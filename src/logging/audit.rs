//! Structured audit logging for security-relevant events.
//!
//! Provides a global, non-blocking audit log that writes JSONL entries to
//! `{state_dir}/audit.jsonl`. Events are sent through a bounded mpsc channel
//! and flushed to disk by a background Tokio task, so callers never block on I/O.
//!
//! # Usage
//!
//! ```no_run
//! use carapace::logging::audit::{self, AuditEvent, AuditLog};
//! use std::path::PathBuf;
//!
//! # async fn example() {
//! // Initialize once at startup
//! AuditLog::init(PathBuf::from("/var/lib/carapace")).await;
//!
//! // Log events from anywhere (no-ops if not initialized)
//! audit::audit(AuditEvent::AuthSuccess {
//!     method: "api_key".into(),
//!     client_id: "cli-abc".into(),
//!     remote_ip: "127.0.0.1".into(),
//!     role: "admin".into(),
//! });
//! # }
//! ```

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::sync::OnceLock;

use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::mpsc;

/// Maximum audit log file size before rotation (50 MB).
const MAX_FILE_SIZE: u64 = 50 * 1024 * 1024;

/// Bounded channel capacity for non-blocking writes.
const CHANNEL_CAPACITY: usize = 10_000;

/// Audit log file name.
const AUDIT_FILE_NAME: &str = "audit.jsonl";

/// Rotated audit log file name.
const AUDIT_ROTATED_NAME: &str = "audit.jsonl.1";

// ---------------------------------------------------------------------------
// AuditEvent
// ---------------------------------------------------------------------------

/// Security-relevant events tracked by the audit log.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AuditEvent {
    AuthSuccess {
        method: String,
        client_id: String,
        remote_ip: String,
        role: String,
    },
    AuthFailure {
        method: String,
        client_id: String,
        remote_ip: String,
        reason: String,
    },
    ConfigChanged {
        key_path: String,
        actor: String,
        method: String,
    },
    DevicePaired {
        device_id: String,
        device_family: String,
        remote_ip: String,
    },
    NodePaired {
        node_id: String,
        remote_ip: String,
    },
    ToolExecuted {
        tool_name: String,
        agent_id: String,
        session_id: String,
    },
    ToolDenied {
        tool_name: String,
        agent_id: String,
        policy: String,
    },
    SessionCreated {
        session_id: String,
        user_id: String,
    },
    SessionDeleted {
        session_id: String,
        actor: String,
    },
    SessionPurged {
        user_id: String,
        deleted_count: usize,
        total_count: usize,
    },
    DataExported {
        user_id: String,
        session_count: usize,
    },
    SkillInstalled {
        skill_id: String,
        source_url: String,
    },
    ApprovalResolved {
        approval_id: String,
        approved: bool,
    },
    BackupCreated {
        path: String,
        sections: Vec<String>,
    },
    RateLimitHit {
        remote_ip: String,
        endpoint: String,
    },
    GatewayConnected {
        gateway_id: String,
    },
    GatewayDisconnected {
        gateway_id: String,
        reason: String,
    },
}

impl AuditEvent {
    /// Return the snake_case event name (matches the serde tag).
    pub fn event_name(&self) -> &'static str {
        match self {
            AuditEvent::AuthSuccess { .. } => "auth_success",
            AuditEvent::AuthFailure { .. } => "auth_failure",
            AuditEvent::ConfigChanged { .. } => "config_changed",
            AuditEvent::DevicePaired { .. } => "device_paired",
            AuditEvent::NodePaired { .. } => "node_paired",
            AuditEvent::ToolExecuted { .. } => "tool_executed",
            AuditEvent::ToolDenied { .. } => "tool_denied",
            AuditEvent::SessionCreated { .. } => "session_created",
            AuditEvent::SessionDeleted { .. } => "session_deleted",
            AuditEvent::SessionPurged { .. } => "session_purged",
            AuditEvent::DataExported { .. } => "data_exported",
            AuditEvent::SkillInstalled { .. } => "skill_installed",
            AuditEvent::ApprovalResolved { .. } => "approval_resolved",
            AuditEvent::BackupCreated { .. } => "backup_created",
            AuditEvent::RateLimitHit { .. } => "rate_limit_hit",
            AuditEvent::GatewayConnected { .. } => "gateway_connected",
            AuditEvent::GatewayDisconnected { .. } => "gateway_disconnected",
        }
    }
}

// ---------------------------------------------------------------------------
// AuditEntry
// ---------------------------------------------------------------------------

/// A single line in the audit JSONL file.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuditEntry {
    /// RFC 3339 timestamp.
    pub ts: String,
    /// Snake-case event name.
    pub event: String,
    /// Event-specific payload.
    pub data: Value,
}

// ---------------------------------------------------------------------------
// AuditLog (global singleton)
// ---------------------------------------------------------------------------

static AUDIT_LOG: OnceLock<AuditLog> = OnceLock::new();

/// Global audit log backed by a bounded mpsc channel and a background writer.
pub struct AuditLog {
    tx: mpsc::Sender<AuditEntry>,
    state_dir: PathBuf,
}

impl AuditLog {
    /// Initialize the global audit log.
    ///
    /// Spawns a background Tokio task that drains the channel and writes JSONL.
    /// Calling this more than once is a no-op (the second call is ignored).
    pub async fn init(state_dir: PathBuf) {
        // Ensure state dir exists.
        if let Err(e) = fs::create_dir_all(&state_dir) {
            tracing::error!("audit: failed to create state dir: {e}");
            return;
        }

        let (tx, rx) = mpsc::channel::<AuditEntry>(CHANNEL_CAPACITY);
        let log_path = state_dir.join(AUDIT_FILE_NAME);
        let rotated_path = state_dir.join(AUDIT_ROTATED_NAME);

        // Spawn background writer.
        tokio::spawn(writer_task(rx, log_path, rotated_path));

        let audit_log = AuditLog {
            tx,
            state_dir: state_dir.clone(),
        };

        // OnceLock::set returns Err if already set; we silently ignore.
        let _ = AUDIT_LOG.set(audit_log);
    }

    /// Send an event to the background writer (non-blocking best-effort).
    pub fn log(&self, event: AuditEvent) {
        let entry = AuditEntry {
            ts: Utc::now().to_rfc3339(),
            event: event.event_name().to_string(),
            data: serde_json::to_value(&event).unwrap_or(Value::Null),
        };

        // try_send so callers never block; drop if the channel is full.
        if let Err(e) = self.tx.try_send(entry) {
            tracing::warn!("audit: channel full or closed, dropping event: {e}");
        }
    }
}

// ---------------------------------------------------------------------------
// Background writer task
// ---------------------------------------------------------------------------

async fn writer_task(mut rx: mpsc::Receiver<AuditEntry>, log_path: PathBuf, rotated_path: PathBuf) {
    while let Some(entry) = rx.recv().await {
        // Serialize entry.
        let line = match serde_json::to_string(&entry) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!("audit: failed to serialize entry: {e}");
                continue;
            }
        };

        // Rotate if necessary (before writing).
        if let Ok(meta) = fs::metadata(&log_path) {
            if meta.len() >= MAX_FILE_SIZE {
                if let Err(e) = fs::rename(&log_path, &rotated_path) {
                    tracing::error!("audit: rotation rename failed: {e}");
                }
            }
        }

        // Append line.
        let result = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
            .and_then(|mut f| {
                writeln!(f, "{line}")?;
                f.sync_all()
            });

        if let Err(e) = result {
            tracing::error!("audit: failed to write entry: {e}");
        }
    }
}

// ---------------------------------------------------------------------------
// Public convenience API
// ---------------------------------------------------------------------------

/// Log an audit event. No-ops silently if [`AuditLog::init`] has not been called.
pub fn audit(event: AuditEvent) {
    if let Some(log) = AUDIT_LOG.get() {
        log.log(event);
    }
}

/// Read the most recent audit entries from the JSONL file (tail-read).
///
/// Returns up to `limit` entries, most-recent last.  Returns an empty vec if
/// the audit log has not been initialized or the file does not exist.
pub fn recent_audit_events(limit: usize) -> Vec<AuditEntry> {
    let log = match AUDIT_LOG.get() {
        Some(l) => l,
        None => return Vec::new(),
    };

    let path = log.state_dir.join(AUDIT_FILE_NAME);
    read_tail_entries(&path, limit)
}

/// Read the last `limit` entries from a JSONL file.
fn read_tail_entries(path: &PathBuf, limit: usize) -> Vec<AuditEntry> {
    let file = match fs::File::open(path) {
        Ok(f) => f,
        Err(_) => return Vec::new(),
    };

    let reader = BufReader::new(file);
    let mut entries: Vec<AuditEntry> = Vec::new();

    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => continue,
        };
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str::<AuditEntry>(&line) {
            Ok(entry) => entries.push(entry),
            Err(_) => continue,
        }
    }

    // Keep only the last `limit` entries.
    if entries.len() > limit {
        entries.split_off(entries.len() - limit)
    } else {
        entries
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    #[test]
    fn test_event_name_auth_success() {
        let ev = AuditEvent::AuthSuccess {
            method: "api_key".into(),
            client_id: "c1".into(),
            remote_ip: "1.2.3.4".into(),
            role: "admin".into(),
        };
        assert_eq!(ev.event_name(), "auth_success");
    }

    #[test]
    fn test_event_name_auth_failure() {
        let ev = AuditEvent::AuthFailure {
            method: "password".into(),
            client_id: "c2".into(),
            remote_ip: "5.6.7.8".into(),
            reason: "bad password".into(),
        };
        assert_eq!(ev.event_name(), "auth_failure");
    }

    #[test]
    fn test_event_name_config_changed() {
        let ev = AuditEvent::ConfigChanged {
            key_path: "auth.token_ttl".into(),
            actor: "admin".into(),
            method: "http".into(),
        };
        assert_eq!(ev.event_name(), "config_changed");
    }

    #[test]
    fn test_event_name_device_paired() {
        let ev = AuditEvent::DevicePaired {
            device_id: "d1".into(),
            device_family: "ios".into(),
            remote_ip: "10.0.0.1".into(),
        };
        assert_eq!(ev.event_name(), "device_paired");
    }

    #[test]
    fn test_event_name_all_variants() {
        let events: Vec<AuditEvent> = vec![
            AuditEvent::AuthSuccess {
                method: "m".into(),
                client_id: "c".into(),
                remote_ip: "i".into(),
                role: "r".into(),
            },
            AuditEvent::AuthFailure {
                method: "m".into(),
                client_id: "c".into(),
                remote_ip: "i".into(),
                reason: "r".into(),
            },
            AuditEvent::ConfigChanged {
                key_path: "k".into(),
                actor: "a".into(),
                method: "m".into(),
            },
            AuditEvent::DevicePaired {
                device_id: "d".into(),
                device_family: "f".into(),
                remote_ip: "i".into(),
            },
            AuditEvent::NodePaired {
                node_id: "n".into(),
                remote_ip: "i".into(),
            },
            AuditEvent::ToolExecuted {
                tool_name: "t".into(),
                agent_id: "a".into(),
                session_id: "s".into(),
            },
            AuditEvent::ToolDenied {
                tool_name: "t".into(),
                agent_id: "a".into(),
                policy: "p".into(),
            },
            AuditEvent::SessionCreated {
                session_id: "s".into(),
                user_id: "u".into(),
            },
            AuditEvent::SessionDeleted {
                session_id: "s".into(),
                actor: "a".into(),
            },
            AuditEvent::SessionPurged {
                user_id: "u".into(),
                deleted_count: 1,
                total_count: 2,
            },
            AuditEvent::DataExported {
                user_id: "u".into(),
                session_count: 5,
            },
            AuditEvent::SkillInstalled {
                skill_id: "s".into(),
                source_url: "https://example.com".into(),
            },
            AuditEvent::ApprovalResolved {
                approval_id: "a".into(),
                approved: true,
            },
            AuditEvent::BackupCreated {
                path: "/tmp/b".into(),
                sections: vec!["config".into()],
            },
            AuditEvent::RateLimitHit {
                remote_ip: "1.2.3.4".into(),
                endpoint: "/api".into(),
            },
            AuditEvent::GatewayConnected {
                gateway_id: "g".into(),
            },
            AuditEvent::GatewayDisconnected {
                gateway_id: "g".into(),
                reason: "timeout".into(),
            },
        ];
        let names: Vec<&str> = events.iter().map(|e| e.event_name()).collect();
        assert!(names.iter().all(|n| !n.is_empty()));
        let mut sorted = names.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), names.len(), "event names must be unique");
    }

    #[test]
    fn test_event_serialization_roundtrip() {
        let ev = AuditEvent::ToolExecuted {
            tool_name: "bash".into(),
            agent_id: "agent-1".into(),
            session_id: "sess-42".into(),
        };
        let json = serde_json::to_string(&ev).unwrap();
        let deserialized: AuditEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(ev, deserialized);
    }

    #[test]
    fn test_event_json_contains_type_tag() {
        let ev = AuditEvent::RateLimitHit {
            remote_ip: "10.0.0.1".into(),
            endpoint: "/ws".into(),
        };
        let json = serde_json::to_string(&ev).unwrap();
        assert!(json.contains("\"type\":\"rate_limit_hit\""));
    }

    #[test]
    fn test_event_backup_created_with_sections() {
        let ev = AuditEvent::BackupCreated {
            path: "/backups/daily.tar.gz".into(),
            sections: vec!["config".into(), "sessions".into()],
        };
        let json = serde_json::to_string(&ev).unwrap();
        assert!(json.contains("\"sections\":[\"config\",\"sessions\"]"));
    }

    #[test]
    fn test_event_approval_resolved_bool() {
        let ev = AuditEvent::ApprovalResolved {
            approval_id: "apr-1".into(),
            approved: false,
        };
        let val = serde_json::to_value(&ev).unwrap();
        assert_eq!(val["approved"], serde_json::json!(false));
    }

    #[test]
    fn test_audit_entry_serialization() {
        let entry = AuditEntry {
            ts: "2025-01-15T10:00:00+00:00".into(),
            event: "auth_success".into(),
            data: serde_json::json!({"type": "auth_success", "method": "api_key"}),
        };
        let json = serde_json::to_string(&entry).unwrap();
        let parsed: AuditEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.ts, entry.ts);
        assert_eq!(parsed.event, entry.event);
    }

    #[test]
    fn test_audit_entry_fields() {
        let ev = AuditEvent::SessionCreated {
            session_id: "s-1".into(),
            user_id: "u-1".into(),
        };
        let entry = AuditEntry {
            ts: Utc::now().to_rfc3339(),
            event: ev.event_name().to_string(),
            data: serde_json::to_value(&ev).unwrap(),
        };
        assert_eq!(entry.event, "session_created");
        assert_eq!(entry.data["session_id"], "s-1");
        assert_eq!(entry.data["user_id"], "u-1");
    }

    #[test]
    fn test_read_tail_entries_empty_file() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join(AUDIT_FILE_NAME);
        fs::write(&path, "").unwrap();
        let entries = read_tail_entries(&path, 10);
        assert!(entries.is_empty());
    }

    #[test]
    fn test_read_tail_entries_returns_last_n() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join(AUDIT_FILE_NAME);
        let mut file = fs::File::create(&path).unwrap();
        for i in 0..10 {
            let entry = AuditEntry {
                ts: format!("2025-01-15T10:{i:02}:00+00:00"),
                event: "auth_success".into(),
                data: serde_json::json!({"type":"auth_success","index": i}),
            };
            writeln!(file, "{}", serde_json::to_string(&entry).unwrap()).unwrap();
        }
        drop(file);
        let entries = read_tail_entries(&path, 3);
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].data["index"], 7);
        assert_eq!(entries[1].data["index"], 8);
        assert_eq!(entries[2].data["index"], 9);
    }

    #[test]
    fn test_read_tail_entries_fewer_than_limit() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join(AUDIT_FILE_NAME);
        let mut file = fs::File::create(&path).unwrap();
        let entry = AuditEntry {
            ts: "2025-01-15T10:00:00+00:00".into(),
            event: "config_changed".into(),
            data: serde_json::json!({"type":"config_changed","key_path":"a"}),
        };
        writeln!(file, "{}", serde_json::to_string(&entry).unwrap()).unwrap();
        drop(file);
        let entries = read_tail_entries(&path, 100);
        assert_eq!(entries.len(), 1);
    }

    #[test]
    fn test_read_tail_entries_skips_bad_lines() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join(AUDIT_FILE_NAME);
        let mut file = fs::File::create(&path).unwrap();
        let good = AuditEntry {
            ts: "2025-01-15T10:00:00+00:00".into(),
            event: "node_paired".into(),
            data: serde_json::json!({"type":"node_paired","node_id":"n1","remote_ip":"1.2.3.4"}),
        };
        writeln!(file, "this is not json").unwrap();
        writeln!(file, "{}", serde_json::to_string(&good).unwrap()).unwrap();
        writeln!(file, "{{invalid json").unwrap();
        drop(file);
        let entries = read_tail_entries(&path, 10);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].event, "node_paired");
    }

    #[test]
    fn test_read_tail_entries_missing_file() {
        let path = PathBuf::from("/tmp/nonexistent_audit_test_file.jsonl");
        let entries = read_tail_entries(&path, 10);
        assert!(entries.is_empty());
    }

    #[test]
    fn test_read_tail_entries_skips_blank_lines() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join(AUDIT_FILE_NAME);
        let mut file = fs::File::create(&path).unwrap();
        let entry = AuditEntry {
            ts: "2025-01-15T10:00:00+00:00".into(),
            event: "gateway_connected".into(),
            data: serde_json::json!({"type":"gateway_connected","gateway_id":"g1"}),
        };
        writeln!(file).unwrap();
        writeln!(file, "{}", serde_json::to_string(&entry).unwrap()).unwrap();
        writeln!(file).unwrap();
        writeln!(file, "   ").unwrap();
        drop(file);
        let entries = read_tail_entries(&path, 10);
        assert_eq!(entries.len(), 1);
    }

    #[tokio::test]
    async fn test_audit_log_init_and_log() {
        let dir = TempDir::new().unwrap();
        let state_dir = dir.path().to_path_buf();
        let (tx, rx) = mpsc::channel::<AuditEntry>(CHANNEL_CAPACITY);
        let log_path = state_dir.join(AUDIT_FILE_NAME);
        let rotated_path = state_dir.join(AUDIT_ROTATED_NAME);
        tokio::spawn(writer_task(rx, log_path.clone(), rotated_path));
        let ev = AuditEvent::AuthSuccess {
            method: "api_key".into(),
            client_id: "c1".into(),
            remote_ip: "127.0.0.1".into(),
            role: "admin".into(),
        };
        let entry = AuditEntry {
            ts: Utc::now().to_rfc3339(),
            event: ev.event_name().to_string(),
            data: serde_json::to_value(&ev).unwrap(),
        };
        tx.send(entry).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let content = fs::read_to_string(&log_path).unwrap();
        assert!(content.contains("auth_success"));
        assert!(content.contains("api_key"));
    }

    #[tokio::test]
    async fn test_writer_task_writes_multiple_entries() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join(AUDIT_FILE_NAME);
        let rotated_path = dir.path().join(AUDIT_ROTATED_NAME);
        let (tx, rx) = mpsc::channel::<AuditEntry>(CHANNEL_CAPACITY);
        tokio::spawn(writer_task(rx, log_path.clone(), rotated_path));
        for i in 0..5 {
            let entry = AuditEntry {
                ts: Utc::now().to_rfc3339(),
                event: "tool_executed".into(),
                data: serde_json::json!({"type":"tool_executed","tool_name":format!("tool_{i}")}),
            };
            tx.send(entry).await.unwrap();
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let content = fs::read_to_string(&log_path).unwrap();
        let lines: Vec<&str> = content.trim().lines().collect();
        assert_eq!(lines.len(), 5);
    }

    #[tokio::test]
    async fn test_writer_task_rotation() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join(AUDIT_FILE_NAME);
        let rotated_path = dir.path().join(AUDIT_ROTATED_NAME);
        {
            let mut f = fs::File::create(&log_path).unwrap();
            let chunk = vec![b'x'; 1024 * 1024];
            for _ in 0..51 {
                f.write_all(&chunk).unwrap();
            }
            f.flush().unwrap();
        }
        let (tx, rx) = mpsc::channel::<AuditEntry>(CHANNEL_CAPACITY);
        tokio::spawn(writer_task(rx, log_path.clone(), rotated_path.clone()));
        let entry = AuditEntry {
            ts: Utc::now().to_rfc3339(),
            event: "gateway_connected".into(),
            data: serde_json::json!({"type":"gateway_connected","gateway_id":"g1"}),
        };
        tx.send(entry).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        assert!(rotated_path.exists(), "rotated file should exist");
        let content = fs::read_to_string(&log_path).unwrap();
        assert!(content.contains("gateway_connected"));
    }

    #[test]
    fn test_audit_noop_without_init() {
        audit(AuditEvent::GatewayConnected {
            gateway_id: "g-test".into(),
        });
    }

    #[tokio::test]
    async fn test_try_send_does_not_block() {
        let (tx, _rx) = mpsc::channel::<AuditEntry>(1);
        let entry = AuditEntry {
            ts: Utc::now().to_rfc3339(),
            event: "rate_limit_hit".into(),
            data: serde_json::json!({"type":"rate_limit_hit"}),
        };
        tx.try_send(entry.clone()).unwrap();
        let result = tx.try_send(entry);
        assert!(result.is_err());
    }

    #[test]
    fn test_event_name_node_paired() {
        assert_eq!(
            AuditEvent::NodePaired {
                node_id: "n".into(),
                remote_ip: "i".into()
            }
            .event_name(),
            "node_paired"
        );
    }

    #[test]
    fn test_event_name_session_purged() {
        assert_eq!(
            AuditEvent::SessionPurged {
                user_id: "u".into(),
                deleted_count: 3,
                total_count: 10
            }
            .event_name(),
            "session_purged"
        );
    }

    #[test]
    fn test_event_name_data_exported() {
        assert_eq!(
            AuditEvent::DataExported {
                user_id: "u".into(),
                session_count: 5
            }
            .event_name(),
            "data_exported"
        );
    }

    #[test]
    fn test_event_name_gateway_disconnected() {
        assert_eq!(
            AuditEvent::GatewayDisconnected {
                gateway_id: "g".into(),
                reason: "timeout".into()
            }
            .event_name(),
            "gateway_disconnected"
        );
    }

    #[test]
    fn test_event_name_skill_installed() {
        assert_eq!(
            AuditEvent::SkillInstalled {
                skill_id: "s".into(),
                source_url: "https://example.com".into()
            }
            .event_name(),
            "skill_installed"
        );
    }

    #[test]
    fn test_event_name_tool_denied() {
        assert_eq!(
            AuditEvent::ToolDenied {
                tool_name: "t".into(),
                agent_id: "a".into(),
                policy: "p".into()
            }
            .event_name(),
            "tool_denied"
        );
    }

    #[test]
    fn test_event_name_session_deleted() {
        assert_eq!(
            AuditEvent::SessionDeleted {
                session_id: "s".into(),
                actor: "a".into()
            }
            .event_name(),
            "session_deleted"
        );
    }
}
