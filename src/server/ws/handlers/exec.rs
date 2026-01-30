//! Exec approval handlers.
//!
//! This module implements the exec approval workflow:
//! - exec.approvals.get: Get the global exec approvals configuration
//! - exec.approvals.set: Set the global exec approvals configuration
//! - exec.approvals.node.get: Get exec approvals for a specific node
//! - exec.approvals.node.set: Set exec approvals for a specific node
//! - exec.approval.request: Request approval for a command (async, waits for decision)
//! - exec.approval.resolve: Resolve a pending approval request

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use uuid::Uuid;

use super::super::*;

// Re-export types for use by other modules
pub use crate::exec::{
    ExecApprovalDecision, ExecApprovalManager, ExecApprovalRecord, ExecApprovalRequestPayload,
};

/// Default timeout for approval requests (2 minutes).
const DEFAULT_APPROVAL_TIMEOUT_MS: u64 = 120_000;

/// Return the path to the exec-approvals.json file within the state directory.
fn exec_approvals_path() -> PathBuf {
    resolve_state_dir().join("exec-approvals.json")
}

/// Compute SHA256 hex digest of a string.
fn sha256_hex(value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    format!("{:x}", digest)
}

/// Snapshot of the exec-approvals file on disk.
struct ExecApprovalsSnapshot {
    path: String,
    exists: bool,
    hash: Option<String>,
    file: Value,
}

/// Read the exec-approvals file and return a snapshot.
fn read_exec_approvals_snapshot() -> ExecApprovalsSnapshot {
    let path = exec_approvals_path();
    let path_str = path.display().to_string();

    if !path.exists() {
        return ExecApprovalsSnapshot {
            path: path_str,
            exists: false,
            hash: None,
            file: json!({ "mode": "ask", "rules": [] }),
        };
    }

    match fs::read_to_string(&path) {
        Ok(raw) => {
            let hash = Some(sha256_hex(&raw));
            let file = serde_json::from_str::<Value>(&raw)
                .unwrap_or(json!({ "mode": "ask", "rules": [] }));
            ExecApprovalsSnapshot {
                path: path_str,
                exists: true,
                hash,
                file,
            }
        }
        Err(e) => {
            if e.kind() != std::io::ErrorKind::NotFound {
                tracing::warn!(path = %path_str, error = %e, "failed to read exec approvals file");
            }
            ExecApprovalsSnapshot {
                path: path_str,
                exists: false,
                hash: None,
                file: json!({ "mode": "ask", "rules": [] }),
            }
        }
    }
}

/// Atomically write the exec-approvals file (tmp + rename). Returns the new hash.
fn write_exec_approvals_file(path: &PathBuf, file_value: &Value) -> Result<String, ErrorShape> {
    if let Some(parent) = path.parent() {
        if let Err(err) = fs::create_dir_all(parent) {
            return Err(error_shape(
                ERROR_UNAVAILABLE,
                &format!("failed to create state dir: {}", err),
                None,
            ));
        }
    }

    let content = serde_json::to_string_pretty(file_value)
        .map_err(|err| error_shape(ERROR_UNAVAILABLE, &err.to_string(), None))?;
    let tmp_path = path.with_extension("json.tmp");
    {
        let mut file = fs::File::create(&tmp_path).map_err(|err| {
            error_shape(
                ERROR_UNAVAILABLE,
                &format!("failed to write exec approvals: {}", err),
                None,
            )
        })?;
        file.write_all(content.as_bytes()).map_err(|err| {
            error_shape(
                ERROR_UNAVAILABLE,
                &format!("failed to write exec approvals: {}", err),
                None,
            )
        })?;
        file.write_all(b"\n").map_err(|err| {
            error_shape(
                ERROR_UNAVAILABLE,
                &format!("failed to write exec approvals: {}", err),
                None,
            )
        })?;
        file.sync_all().map_err(|err| {
            error_shape(
                ERROR_UNAVAILABLE,
                &format!("failed to sync exec approvals: {}", err),
                None,
            )
        })?;
    }
    if let Err(err) = fs::rename(&tmp_path, path) {
        return Err(error_shape(
            ERROR_UNAVAILABLE,
            &format!("failed to replace exec approvals: {}", err),
            None,
        ));
    }

    // Hash the content that was actually written (with trailing newline)
    let mut written = content;
    written.push('\n');
    Ok(sha256_hex(&written))
}

/// Get global exec approvals configuration.
///
/// Reads the exec-approvals.json file from the state directory.
/// Returns `{ path, exists, hash, file }`.
pub(super) fn handle_exec_approvals_get() -> Result<Value, ErrorShape> {
    let snapshot = read_exec_approvals_snapshot();
    Ok(json!({
        "path": snapshot.path,
        "exists": snapshot.exists,
        "hash": snapshot.hash,
        "file": snapshot.file
    }))
}

/// Set global exec approvals configuration.
///
/// Writes the exec-approvals.json file atomically.
/// Requires a `baseHash` parameter for optimistic concurrency when the file already exists.
pub(super) fn handle_exec_approvals_set(params: Option<&Value>) -> Result<Value, ErrorShape> {
    let file = params
        .and_then(|v| v.get("file"))
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "file is required", None))?;

    // Validate file structure
    if !file.is_object() {
        return Err(error_shape(
            ERROR_INVALID_REQUEST,
            "file must be an object",
            None,
        ));
    }

    let snapshot = read_exec_approvals_snapshot();

    // Optimistic concurrency: if file exists, baseHash must match
    if snapshot.exists {
        let base_hash = params
            .and_then(|v| v.get("baseHash"))
            .and_then(|v| v.as_str())
            .map(|s| s.trim())
            .filter(|s| !s.is_empty());

        let expected = snapshot.hash.as_deref();
        if expected.is_none() {
            return Err(error_shape(
                ERROR_INVALID_REQUEST,
                "exec approvals hash unavailable; re-run exec.approvals.get and retry",
                None,
            ));
        }
        let Some(base_hash) = base_hash else {
            return Err(error_shape(
                ERROR_INVALID_REQUEST,
                "baseHash required; re-run exec.approvals.get and retry",
                None,
            ));
        };
        if Some(base_hash) != expected {
            return Err(error_shape(
                ERROR_INVALID_REQUEST,
                "exec approvals changed since last load; re-run exec.approvals.get and retry",
                None,
            ));
        }
    }

    let path = exec_approvals_path();
    let new_hash = write_exec_approvals_file(&path, file)?;

    Ok(json!({
        "path": path.display().to_string(),
        "exists": true,
        "hash": new_hash,
        "file": file.clone()
    }))
}

/// Get exec approvals for a specific node.
///
/// This proxies to the node to get its local exec approvals configuration.
/// If the node is not connected or doesn't support the command, returns
/// default placeholder settings.
pub(super) async fn handle_exec_approvals_node_get(
    params: Option<&Value>,
    state: &WsServerState,
) -> Result<Value, ErrorShape> {
    let node_id = params
        .and_then(|v| v.get("nodeId"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "nodeId is required", None))?;

    if node_id.trim().is_empty() {
        return Err(error_shape(
            ERROR_INVALID_REQUEST,
            "nodeId cannot be empty",
            None,
        ));
    }

    // Check if the node is connected and supports the command
    let node_supports_command = {
        let registry = state.node_registry.lock();
        registry
            .get(node_id)
            .is_some_and(|node| node.commands.contains("system.execApprovals.get"))
    };

    if !node_supports_command {
        // Node not connected or doesn't support the command - return default settings
        return Ok(json!({
            "nodeId": node_id,
            "path": null,
            "exists": false,
            "hash": null,
            "file": {
                "mode": "ask",
                "rules": []
            }
        }));
    }

    // Invoke the command on the node
    let invoke_params = json!({
        "nodeId": node_id,
        "command": "system.execApprovals.get",
        "idempotencyKey": Uuid::new_v4().to_string(),
        "timeoutMs": 10000
    });

    match super::node::handle_node_invoke(Some(&invoke_params), state).await {
        Ok(result) => {
            // Extract the payload from the node response
            let payload = result.get("payload").cloned().unwrap_or(Value::Null);

            // Merge nodeId into the response
            if let Some(obj) = payload.as_object() {
                let mut response = obj.clone();
                response.insert("nodeId".to_string(), json!(node_id));
                Ok(Value::Object(response))
            } else {
                Ok(json!({
                    "nodeId": node_id,
                    "path": null,
                    "exists": false,
                    "hash": null,
                    "file": payload
                }))
            }
        }
        Err(_) => {
            // Node invoke failed - return default settings
            Ok(json!({
                "nodeId": node_id,
                "path": null,
                "exists": false,
                "hash": null,
                "file": {
                    "mode": "ask",
                    "rules": []
                }
            }))
        }
    }
}

/// Set exec approvals for a specific node.
///
/// This proxies to the node to update its local exec approvals configuration.
/// If the node is not connected or doesn't support the command, returns an error.
pub(super) async fn handle_exec_approvals_node_set(
    params: Option<&Value>,
    state: &WsServerState,
) -> Result<Value, ErrorShape> {
    let node_id = params
        .and_then(|v| v.get("nodeId"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "nodeId is required", None))?;

    if node_id.trim().is_empty() {
        return Err(error_shape(
            ERROR_INVALID_REQUEST,
            "nodeId cannot be empty",
            None,
        ));
    }

    let file = params
        .and_then(|v| v.get("file"))
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "file is required", None))?;

    if !file.is_object() {
        return Err(error_shape(
            ERROR_INVALID_REQUEST,
            "file must be an object",
            None,
        ));
    }

    // Check if the node is connected and supports the command
    let node_supports_command = {
        let registry = state.node_registry.lock();
        registry
            .get(node_id)
            .is_some_and(|node| node.commands.contains("system.execApprovals.set"))
    };

    if !node_supports_command {
        return Err(error_shape(
            ERROR_UNAVAILABLE,
            "node not connected or does not support exec approvals",
            Some(json!({
                "nodeId": node_id,
                "command": "system.execApprovals.set"
            })),
        ));
    }

    // Invoke the command on the node
    let invoke_params = json!({
        "nodeId": node_id,
        "command": "system.execApprovals.set",
        "idempotencyKey": Uuid::new_v4().to_string(),
        "timeoutMs": 10000,
        "params": {
            "file": file.clone()
        }
    });

    match super::node::handle_node_invoke(Some(&invoke_params), state).await {
        Ok(result) => {
            // Extract the payload from the node response
            let payload = result.get("payload").cloned().unwrap_or(Value::Null);

            // Merge nodeId and ok into the response
            if let Some(obj) = payload.as_object() {
                let mut response = obj.clone();
                response.insert("nodeId".to_string(), json!(node_id));
                if !response.contains_key("ok") {
                    response.insert("ok".to_string(), json!(true));
                }
                Ok(Value::Object(response))
            } else {
                Ok(json!({
                    "ok": true,
                    "nodeId": node_id,
                    "file": file.clone()
                }))
            }
        }
        Err(e) => Err(error_shape(
            ERROR_UNAVAILABLE,
            &format!("failed to set exec approvals on node: {}", e.message),
            Some(json!({
                "nodeId": node_id,
                "error": e.details
            })),
        )),
    }
}

/// Parsed parameters for an exec approval request.
struct ExecApprovalRequestParams {
    command: String,
    explicit_id: Option<String>,
    timeout_ms: u64,
    cwd: Option<String>,
    host: Option<String>,
    security: Option<String>,
    ask: Option<String>,
    agent_id: Option<String>,
    resolved_path: Option<String>,
    session_key: Option<String>,
}

/// Parse and validate parameters for an exec approval request.
fn parse_exec_approval_request_params(
    params: Option<&Value>,
) -> Result<ExecApprovalRequestParams, ErrorShape> {
    let command = params
        .and_then(|v| v.get("command"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "command is required", None))?;

    if command.trim().is_empty() {
        return Err(error_shape(
            ERROR_INVALID_REQUEST,
            "command cannot be empty",
            None,
        ));
    }

    let explicit_id = params
        .and_then(|v| v.get("id"))
        .and_then(|v| v.as_str())
        .filter(|s| !s.trim().is_empty())
        .map(|s| s.trim().to_string());

    let timeout_ms = params
        .and_then(|v| v.get("timeoutMs"))
        .and_then(|v| v.as_u64())
        .unwrap_or(DEFAULT_APPROVAL_TIMEOUT_MS);

    let str_field = |key: &str| -> Option<String> {
        params
            .and_then(|v| v.get(key))
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
    };

    Ok(ExecApprovalRequestParams {
        command: command.to_string(),
        explicit_id,
        timeout_ms,
        cwd: str_field("cwd"),
        host: str_field("host"),
        security: str_field("security"),
        ask: str_field("ask"),
        agent_id: str_field("agentId"),
        resolved_path: str_field("resolvedPath"),
        session_key: str_field("sessionKey"),
    })
}

/// Request approval for a command execution.
///
/// This creates a pending approval request, broadcasts an exec.approval.requested event,
/// then waits for a decision (or timeout). Returns the final status.
///
/// Parameters:
/// - command: The command being requested (required)
/// - id: Optional explicit ID for the request
/// - cwd: Current working directory
/// - host: Host where command will run
/// - security: Security classification
/// - ask: Human-readable explanation
/// - agentId: The requesting agent's ID
/// - resolvedPath: Resolved path to command binary
/// - sessionKey: Associated session key
/// - timeoutMs: How long to wait for decision (default 120000)
pub(super) async fn handle_exec_approval_request(
    params: Option<&Value>,
    state: &WsServerState,
) -> Result<Value, ErrorShape> {
    let parsed = parse_exec_approval_request_params(params)?;

    let payload = ExecApprovalRequestPayload {
        command: parsed.command.clone(),
        cwd: parsed.cwd.clone(),
        host: parsed.host.clone(),
        security: parsed.security.clone(),
        ask: parsed.ask.clone(),
        agent_id: parsed.agent_id.clone(),
        resolved_path: parsed.resolved_path.clone(),
        session_key: parsed.session_key.clone(),
    };

    let record = state.exec_manager().create_record(
        payload,
        parsed.timeout_ms,
        parsed.explicit_id.as_deref(),
    );

    let record_id = record.id.clone();
    let created_at_ms = record.created_at_ms;
    let expires_at_ms = record.expires_at_ms;

    // Broadcast the request event
    broadcast_exec_approval_requested(
        state,
        &record_id,
        &parsed.command,
        vec![],
        parsed.cwd.as_deref(),
        parsed.agent_id.as_deref(),
        parsed.session_key.as_deref(),
    );

    // Wait for a decision (blocks until resolved or timeout)
    let decision = state
        .exec_manager()
        .wait_for_decision(record, parsed.timeout_ms)
        .await;

    let (decision_value, status) = match decision {
        Some(d) => {
            let s = if matches!(d, ExecApprovalDecision::Deny) {
                "denied"
            } else {
                "approved"
            };
            (json!(d.as_str()), s)
        }
        None => (Value::Null, "expired"),
    };

    Ok(json!({
        "id": record_id,
        "command": parsed.command,
        "createdAtMs": created_at_ms,
        "expiresAtMs": expires_at_ms,
        "decision": decision_value,
        "status": status
    }))
}

/// Parsed parameters for resolving an exec approval.
struct ExecApprovalResolveParams {
    request_id: String,
    decision: ExecApprovalDecision,
}

/// Parse and validate parameters for resolving an exec approval.
fn parse_exec_approval_resolve_params(
    params: Option<&Value>,
) -> Result<ExecApprovalResolveParams, ErrorShape> {
    let request_id = params
        .and_then(|v| v.get("id"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "id is required", None))?;

    if request_id.trim().is_empty() {
        return Err(error_shape(
            ERROR_INVALID_REQUEST,
            "id cannot be empty",
            None,
        ));
    }

    let decision_str = params
        .and_then(|v| v.get("decision"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "decision is required", None))?;

    let decision = ExecApprovalDecision::parse_decision(decision_str).ok_or_else(|| {
        error_shape(
            ERROR_INVALID_REQUEST,
            "invalid decision (must be allow-once, allow-always, or deny)",
            None,
        )
    })?;

    Ok(ExecApprovalResolveParams {
        request_id: request_id.to_string(),
        decision,
    })
}

/// Resolve a pending approval request.
///
/// This resolves an existing approval request with a decision.
/// Broadcasts an exec.approval.resolved event.
///
/// Parameters:
/// - id: The approval request ID (required)
/// - decision: The decision - "allow-once", "allow-always", or "deny" (required)
pub(super) fn handle_exec_approval_resolve(
    params: Option<&Value>,
    state: &WsServerState,
) -> Result<Value, ErrorShape> {
    let parsed = parse_exec_approval_resolve_params(params)?;

    let resolved = state
        .exec_manager()
        .resolve(&parsed.request_id, parsed.decision, None);

    if resolved.is_none() {
        return Err(error_shape(
            ERROR_INVALID_REQUEST,
            "approval request not found or already resolved",
            Some(json!({ "id": parsed.request_id })),
        ));
    }

    // Broadcast the resolved event
    broadcast_exec_approval_resolved(state, &parsed.request_id, parsed.decision.as_str());

    Ok(json!({
        "ok": true,
        "id": parsed.request_id,
        "decision": parsed.decision.as_str()
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Mutex to serialize tests that modify global state (env vars).
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn test_handle_exec_approvals_get() {
        let _lock = TEST_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        std::env::set_var("MOLTBOT_STATE_DIR", tmp.path());
        let result = handle_exec_approvals_get();
        assert!(result.is_ok());
        let value = result.unwrap();
        assert_eq!(value["exists"], false);
        assert!(value["path"].is_string(), "path should always be a string");
        assert_eq!(value["hash"], Value::Null);
        assert!(value["file"].is_object());
        std::env::remove_var("MOLTBOT_STATE_DIR");
    }

    #[test]
    fn test_handle_exec_approvals_set_requires_file() {
        let result = handle_exec_approvals_set(None);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code, ERROR_INVALID_REQUEST);

        let params = json!({});
        let result = handle_exec_approvals_set(Some(&params));
        assert!(result.is_err());
    }

    #[test]
    fn test_handle_exec_approvals_set_validates_file() {
        let _lock = TEST_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        std::env::set_var("MOLTBOT_STATE_DIR", tmp.path());

        let params = json!({ "file": "not an object" });
        let result = handle_exec_approvals_set(Some(&params));
        assert!(result.is_err());

        let params = json!({ "file": { "mode": "ask", "rules": [] } });
        let result = handle_exec_approvals_set(Some(&params));
        assert!(result.is_ok());
        let value = result.unwrap();
        assert_eq!(value["exists"], true);
        assert!(value["hash"].is_string());
        assert!(value["path"].is_string());

        std::env::remove_var("MOLTBOT_STATE_DIR");
    }

    #[test]
    fn test_exec_approvals_roundtrip() {
        let _lock = TEST_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        std::env::set_var("MOLTBOT_STATE_DIR", tmp.path());

        // Set approvals
        let file_data = json!({ "mode": "allow", "rules": [{"pattern": "ls"}] });
        let params = json!({ "file": file_data });
        let set_result = handle_exec_approvals_set(Some(&params)).unwrap();
        assert_eq!(set_result["exists"], true);
        let hash = set_result["hash"].as_str().unwrap().to_string();

        // Get approvals — should match what was set
        let get_result = handle_exec_approvals_get().unwrap();
        assert_eq!(get_result["exists"], true);
        assert_eq!(get_result["hash"], hash);
        assert_eq!(get_result["file"]["mode"], "allow");
        assert_eq!(get_result["file"]["rules"][0]["pattern"], "ls");
        assert!(get_result["path"].is_string());

        std::env::remove_var("MOLTBOT_STATE_DIR");
    }

    #[test]
    fn test_exec_approvals_base_hash_concurrency() {
        let _lock = TEST_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        std::env::set_var("MOLTBOT_STATE_DIR", tmp.path());

        // Initial write (no file exists yet, no baseHash required)
        let params = json!({ "file": { "mode": "ask", "rules": [] } });
        let first = handle_exec_approvals_set(Some(&params)).unwrap();
        let correct_hash = first["hash"].as_str().unwrap().to_string();

        // Attempt without baseHash — should fail (file exists now)
        let params = json!({ "file": { "mode": "deny", "rules": [] } });
        let result = handle_exec_approvals_set(Some(&params));
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code, ERROR_INVALID_REQUEST);

        // Attempt with wrong baseHash — should fail
        let params = json!({ "file": { "mode": "deny", "rules": [] }, "baseHash": "wrong" });
        let result = handle_exec_approvals_set(Some(&params));
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code, ERROR_INVALID_REQUEST);

        // Attempt with correct baseHash — should succeed
        let params = json!({ "file": { "mode": "deny", "rules": [] }, "baseHash": correct_hash });
        let result = handle_exec_approvals_set(Some(&params));
        assert!(result.is_ok());
        let value = result.unwrap();
        assert_eq!(value["file"]["mode"], "deny");
        // Hash should have changed
        assert_ne!(value["hash"].as_str().unwrap(), correct_hash);

        std::env::remove_var("MOLTBOT_STATE_DIR");
    }

    #[tokio::test]
    async fn test_handle_exec_approvals_node_get_requires_node_id() {
        let state = WsServerState::new(crate::server::ws::WsServerConfig::default());

        let result = handle_exec_approvals_node_get(None, &state).await;
        assert!(result.is_err());

        let params = json!({ "nodeId": "" });
        let result = handle_exec_approvals_node_get(Some(&params), &state).await;
        assert!(result.is_err());

        // When node is not connected, returns default settings
        let params = json!({ "nodeId": "node-1" });
        let result = handle_exec_approvals_node_get(Some(&params), &state).await;
        assert!(result.is_ok());
        let value = result.unwrap();
        assert_eq!(value["nodeId"], "node-1");
        assert_eq!(value["exists"], false);
    }

    #[tokio::test]
    async fn test_handle_exec_approvals_node_set_requires_params() {
        let state = WsServerState::new(crate::server::ws::WsServerConfig::default());

        let result = handle_exec_approvals_node_set(None, &state).await;
        assert!(result.is_err());

        let params = json!({ "nodeId": "node-1" });
        let result = handle_exec_approvals_node_set(Some(&params), &state).await;
        assert!(result.is_err()); // Missing file

        // When node is not connected, returns error (can't set on disconnected node)
        let params = json!({ "nodeId": "node-1", "file": { "mode": "ask" } });
        let result = handle_exec_approvals_node_set(Some(&params), &state).await;
        assert!(result.is_err()); // Node not connected
        let err = result.unwrap_err();
        assert_eq!(err.code, ERROR_UNAVAILABLE);
    }

    #[test]
    fn test_parse_exec_approval_request_requires_command() {
        let result = parse_exec_approval_request_params(None);
        assert!(result.is_err());

        let params = json!({ "command": "" });
        let result = parse_exec_approval_request_params(Some(&params));
        assert!(result.is_err());

        let params = json!({ "command": "ls -la" });
        let result = parse_exec_approval_request_params(Some(&params));
        assert!(result.is_ok());
        let parsed = result.unwrap();
        assert_eq!(parsed.command, "ls -la");
    }

    #[test]
    fn test_parse_exec_approval_request_uses_explicit_id() {
        let params = json!({ "command": "test", "id": "custom-id-123" });
        let result = parse_exec_approval_request_params(Some(&params));
        assert!(result.is_ok());
        assert_eq!(result.unwrap().explicit_id.unwrap(), "custom-id-123");
    }

    #[test]
    fn test_parse_exec_approval_resolve_requires_params() {
        let result = parse_exec_approval_resolve_params(None);
        assert!(result.is_err());

        let params = json!({ "id": "test-id" });
        let result = parse_exec_approval_resolve_params(Some(&params));
        assert!(result.is_err()); // Missing decision

        let params = json!({ "id": "", "decision": "allow-once" });
        let result = parse_exec_approval_resolve_params(Some(&params));
        assert!(result.is_err()); // Empty id
    }

    #[test]
    fn test_parse_exec_approval_resolve_validates_decision() {
        let params = json!({ "id": "test-id", "decision": "invalid" });
        let result = parse_exec_approval_resolve_params(Some(&params));
        assert!(result.is_err());

        let params = json!({ "id": "test-id", "decision": "allow-once" });
        let result = parse_exec_approval_resolve_params(Some(&params));
        assert!(result.is_ok());
        let parsed = result.unwrap();
        assert_eq!(parsed.decision.as_str(), "allow-once");

        let params = json!({ "id": "test-id", "decision": "allow-always" });
        let result = parse_exec_approval_resolve_params(Some(&params));
        assert!(result.is_ok());

        let params = json!({ "id": "test-id", "decision": "deny" });
        let result = parse_exec_approval_resolve_params(Some(&params));
        assert!(result.is_ok());
    }
}
