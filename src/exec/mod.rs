//! Exec approvals system.
//!
//! This module provides functionality for managing command execution approval requests.
//! When a node wants to execute a command that requires approval, it creates an approval
//! request and waits for it to be resolved (approved or denied) by an operator.

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::oneshot;
use uuid::Uuid;

/// Represents a decision made on an exec approval request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ExecApprovalDecision {
    /// Allow the command to execute this one time.
    AllowOnce,
    /// Allow the command and remember the decision.
    AllowAlways,
    /// Deny the command execution.
    Deny,
}

impl ExecApprovalDecision {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "allow-once" => Some(Self::AllowOnce),
            "allow-always" => Some(Self::AllowAlways),
            "deny" => Some(Self::Deny),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::AllowOnce => "allow-once",
            Self::AllowAlways => "allow-always",
            Self::Deny => "deny",
        }
    }
}

/// Payload for an exec approval request.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExecApprovalRequestPayload {
    /// The command being requested to execute.
    pub command: String,
    /// Current working directory.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    /// The host where the command will run.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// Security classification of the command.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub security: Option<String>,
    /// Human-readable explanation of why this command is being requested.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ask: Option<String>,
    /// The agent ID requesting the command.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    /// The resolved path of the command binary.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolved_path: Option<String>,
    /// The session key associated with this request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_key: Option<String>,
}

/// A record representing an exec approval request.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExecApprovalRecord {
    /// Unique identifier for this approval request.
    pub id: String,
    /// The request payload.
    pub request: ExecApprovalRequestPayload,
    /// When the request was created (Unix timestamp in milliseconds).
    pub created_at_ms: u64,
    /// When the request will expire (Unix timestamp in milliseconds).
    pub expires_at_ms: u64,
    /// When the request was resolved (Unix timestamp in milliseconds).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolved_at_ms: Option<u64>,
    /// The decision made on this request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decision: Option<ExecApprovalDecision>,
    /// Who resolved this request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolved_by: Option<String>,
}

/// Internal entry for a pending approval.
struct PendingEntry {
    record: ExecApprovalRecord,
    #[allow(dead_code)]
    responder: oneshot::Sender<Option<ExecApprovalDecision>>,
    expires_at: Instant,
}

impl std::fmt::Debug for PendingEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingEntry")
            .field("record", &self.record)
            .field("responder", &"<sender>")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// Manager for exec approval requests.
///
/// This manager tracks pending approval requests and allows resolving them
/// with a decision. It provides async waiting for decisions with timeout support.
#[derive(Debug)]
pub struct ExecApprovalManager {
    pending: Mutex<HashMap<String, PendingEntry>>,
}

impl Default for ExecApprovalManager {
    fn default() -> Self {
        Self::new()
    }
}

impl ExecApprovalManager {
    /// Create a new exec approval manager.
    pub fn new() -> Self {
        Self {
            pending: Mutex::new(HashMap::new()),
        }
    }

    /// Create a new approval record without registering it.
    pub fn create_record(
        &self,
        request: ExecApprovalRequestPayload,
        timeout_ms: u64,
        id: Option<&str>,
    ) -> ExecApprovalRecord {
        let now = now_ms();
        let resolved_id = id
            .filter(|s| !s.trim().is_empty())
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|| Uuid::new_v4().to_string());

        ExecApprovalRecord {
            id: resolved_id,
            request,
            created_at_ms: now,
            expires_at_ms: now + timeout_ms,
            resolved_at_ms: None,
            decision: None,
            resolved_by: None,
        }
    }

    /// Register a pending approval and wait for a decision.
    ///
    /// Returns `None` if the request times out without a decision.
    pub async fn wait_for_decision(
        &self,
        record: ExecApprovalRecord,
        timeout_ms: u64,
    ) -> Option<ExecApprovalDecision> {
        let (tx, rx) = oneshot::channel();
        let record_id = record.id.clone();
        let expires_at = Instant::now() + Duration::from_millis(timeout_ms);

        {
            let mut pending = self.pending.lock();
            pending.insert(
                record_id.clone(),
                PendingEntry {
                    record,
                    responder: tx,
                    expires_at,
                },
            );
        }

        // Wait for decision with timeout
        let result = tokio::time::timeout(Duration::from_millis(timeout_ms), rx).await;

        // Clean up if still pending (timeout case)
        {
            let mut pending = self.pending.lock();
            pending.remove(&record_id);
        }

        match result {
            Ok(Ok(decision)) => decision,
            _ => None, // Timeout or channel closed
        }
    }

    /// Resolve a pending approval request.
    ///
    /// Returns `true` if the request was found and resolved, `false` otherwise.
    pub fn resolve(
        &self,
        record_id: &str,
        decision: ExecApprovalDecision,
        _resolved_by: Option<&str>,
    ) -> bool {
        let mut pending = self.pending.lock();
        let Some(entry) = pending.remove(record_id) else {
            return false;
        };

        // Send the decision (ignore if receiver dropped)
        let _ = entry.responder.send(Some(decision));
        true
    }

    /// Get a snapshot of a pending approval record.
    pub fn get_snapshot(&self, record_id: &str) -> Option<ExecApprovalRecord> {
        let pending = self.pending.lock();
        pending.get(record_id).map(|e| e.record.clone())
    }

    /// Check if a record ID is already pending.
    pub fn is_pending(&self, record_id: &str) -> bool {
        let pending = self.pending.lock();
        pending.contains_key(record_id)
    }

    /// Get all pending approval records.
    pub fn list_pending(&self) -> Vec<ExecApprovalRecord> {
        let pending = self.pending.lock();
        pending.values().map(|e| e.record.clone()).collect()
    }

    /// Remove expired entries (called periodically).
    pub fn cleanup_expired(&self) {
        let now = Instant::now();
        let mut pending = self.pending.lock();
        let expired: Vec<String> = pending
            .iter()
            .filter(|(_, entry)| entry.expires_at < now)
            .map(|(id, _)| id.clone())
            .collect();

        for id in expired {
            if let Some(entry) = pending.remove(&id) {
                // Signal timeout
                let _ = entry.responder.send(None);
            }
        }
    }
}

/// Create a shared exec approval manager.
pub fn create_manager() -> Arc<ExecApprovalManager> {
    Arc::new(ExecApprovalManager::new())
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exec_approval_decision_from_str() {
        assert_eq!(
            ExecApprovalDecision::from_str("allow-once"),
            Some(ExecApprovalDecision::AllowOnce)
        );
        assert_eq!(
            ExecApprovalDecision::from_str("allow-always"),
            Some(ExecApprovalDecision::AllowAlways)
        );
        assert_eq!(
            ExecApprovalDecision::from_str("deny"),
            Some(ExecApprovalDecision::Deny)
        );
        assert_eq!(ExecApprovalDecision::from_str("invalid"), None);
    }

    #[test]
    fn test_exec_approval_decision_as_str() {
        assert_eq!(ExecApprovalDecision::AllowOnce.as_str(), "allow-once");
        assert_eq!(ExecApprovalDecision::AllowAlways.as_str(), "allow-always");
        assert_eq!(ExecApprovalDecision::Deny.as_str(), "deny");
    }

    #[test]
    fn test_create_record() {
        let manager = ExecApprovalManager::new();
        let request = ExecApprovalRequestPayload {
            command: "ls -la".to_string(),
            cwd: Some("/home/user".to_string()),
            host: None,
            security: None,
            ask: Some("List directory contents".to_string()),
            agent_id: None,
            resolved_path: Some("/bin/ls".to_string()),
            session_key: None,
        };

        let record = manager.create_record(request.clone(), 60_000, None);
        assert!(!record.id.is_empty());
        assert_eq!(record.request.command, "ls -la");
        assert!(record.created_at_ms > 0);
        assert_eq!(record.expires_at_ms, record.created_at_ms + 60_000);
        assert!(record.resolved_at_ms.is_none());
        assert!(record.decision.is_none());

        // Test with explicit ID
        let record2 = manager.create_record(request, 60_000, Some("custom-id"));
        assert_eq!(record2.id, "custom-id");
    }

    #[test]
    fn test_is_pending() {
        let manager = ExecApprovalManager::new();
        let request = ExecApprovalRequestPayload {
            command: "test".to_string(),
            cwd: None,
            host: None,
            security: None,
            ask: None,
            agent_id: None,
            resolved_path: None,
            session_key: None,
        };
        let _record = manager.create_record(request, 60_000, Some("test-id"));

        assert!(!manager.is_pending("test-id"));

        // We can't easily test wait_for_decision without async, but we can
        // verify the manager starts with no pending requests
        assert_eq!(manager.list_pending().len(), 0);
    }

    #[tokio::test]
    async fn test_resolve_pending_approval() {
        let manager = Arc::new(ExecApprovalManager::new());
        let request = ExecApprovalRequestPayload {
            command: "test".to_string(),
            cwd: None,
            host: None,
            security: None,
            ask: None,
            agent_id: None,
            resolved_path: None,
            session_key: None,
        };
        let record = manager.create_record(request, 60_000, Some("resolve-test"));

        let manager_clone = Arc::clone(&manager);
        let wait_handle =
            tokio::spawn(async move { manager_clone.wait_for_decision(record, 60_000).await });

        // Give the wait task time to register
        tokio::time::sleep(Duration::from_millis(10)).await;

        // Resolve the approval
        assert!(manager.resolve(
            "resolve-test",
            ExecApprovalDecision::AllowOnce,
            Some("tester")
        ));

        // Wait should return the decision
        let decision = wait_handle.await.unwrap();
        assert_eq!(decision, Some(ExecApprovalDecision::AllowOnce));
    }

    #[tokio::test]
    async fn test_approval_timeout() {
        let manager = ExecApprovalManager::new();
        let request = ExecApprovalRequestPayload {
            command: "test".to_string(),
            cwd: None,
            host: None,
            security: None,
            ask: None,
            agent_id: None,
            resolved_path: None,
            session_key: None,
        };
        let record = manager.create_record(request, 50, Some("timeout-test"));

        // Wait with very short timeout
        let decision = manager.wait_for_decision(record, 50).await;
        assert_eq!(decision, None);
    }

    #[test]
    fn test_resolve_unknown_id() {
        let manager = ExecApprovalManager::new();
        assert!(!manager.resolve("unknown-id", ExecApprovalDecision::Deny, None));
    }
}
