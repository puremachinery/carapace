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
use std::io::{BufRead, BufReader, ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};

use crate::update::UpdatePhase;
use chrono::Utc;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MatrixRecoveryKeyArtifactLabel {
    RotationMarker,
    MintingMarker,
    CurrentKey,
    PendingKey,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MatrixRecoveryKeyRotationStage {
    Started,
    PendingKeyWritten,
    FinalKeyReplaced,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MatrixRecoveryKeyState {
    Missing,
    MatchesPreviousKey,
    MatchesNewKey,
    Mismatch,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MatrixRecoveryKeyPromotionRefusalReason {
    MissingPreviousKeyDigest,
    MissingNewKeyDigest,
    PendingKeyMissing,
    PendingKeyDigestMismatch,
    CurrentKeyMismatch,
    CurrentKeyMissing,
    UnboundStartedPending,
    FinalStagePendingPresent,
    LegacyMarkerMissingPreviousKeyDigest,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MatrixRecoveryKeyRotationMarkerInvalidReason {
    CorruptTypedMarker,
    UnknownLegacyMarker,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MatrixRecoveryKeyRestoreCleanupErrorKind {
    RemoveFailed,
    ParentSyncFailed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MatrixRecoveryKeyRestoreCleanupArtifact {
    pub label: MatrixRecoveryKeyArtifactLabel,
    pub error_kind: MatrixRecoveryKeyRestoreCleanupErrorKind,
}

// ---------------------------------------------------------------------------
// AuditEvent
// ---------------------------------------------------------------------------

/// Security-relevant events tracked by the audit log.
#[non_exhaustive]
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
    TaskMutated {
        task_id: String,
        action: String,
        actor: String,
        resulting_state: String,
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
    PluginInstalled {
        plugin_id: String,
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
    /// Prompt guard blocked a prompt or output.
    PromptGuardBlocked {
        layer: String,
        reason: String,
        run_id: String,
    },
    /// Plugin signature verified successfully.
    PluginSignatureVerified {
        plugin_id: String,
    },
    /// Plugin signature verification failed.
    PluginSignatureFailed {
        plugin_id: String,
        reason: String,
    },
    /// Plugin capability denied by sandbox.
    PluginCapabilityDenied {
        plugin_id: String,
        capabilities: Vec<String>,
    },
    /// Session integrity violation detected.
    SessionIntegrityViolation {
        session_id: String,
        file: String,
        action: String,
    },
    /// Applied update could not be marked healthy during startup.
    UpdateHealthyMarkerFailed {
        #[serde(
            serialize_with = "serialize_update_phase_option_audit_compat",
            deserialize_with = "deserialize_update_phase_option_audit_compat"
        )]
        phase: Option<UpdatePhase>,
        retryable: bool,
        evidence_recorded: bool,
    },
    /// Stale update startup-health evidence could not be cleared.
    UpdateHealthyEvidenceCleanupFailed {
        #[serde(
            serialize_with = "serialize_update_phase_option_audit_compat",
            deserialize_with = "deserialize_update_phase_option_audit_compat"
        )]
        phase: Option<UpdatePhase>,
        retryable: bool,
    },
    /// Startup cleanup reaped a stale rollback backup sibling.
    UpdateRollbackBackupReaped {
        path: String,
    },
    /// Matrix recovery-key restore left stale rotation artifacts behind.
    MatrixRecoveryKeyRestoreCleanupFailed {
        artifacts: Vec<MatrixRecoveryKeyRestoreCleanupArtifact>,
    },
    /// Daemon refused to promote a pending Matrix recovery key.
    MatrixRecoveryKeyPendingPromotionRefused {
        marker_stage: MatrixRecoveryKeyRotationStage,
        reason: MatrixRecoveryKeyPromotionRefusalReason,
        artifacts: Vec<MatrixRecoveryKeyArtifactLabel>,
        current_key: MatrixRecoveryKeyState,
        pending_key: MatrixRecoveryKeyState,
    },
    /// Recovery-key rotation marker bytes could not be parsed safely.
    MatrixRecoveryKeyRotationMarkerInvalid {
        reason: MatrixRecoveryKeyRotationMarkerInvalidReason,
    },
    /// Legacy Matrix inbound DLQ envelopes were processed by the migration path.
    MatrixInboundDlqLegacyEnvelopeProcessed {
        from_version: u8,
        current_version: u8,
        record_count: usize,
        reencoded_count: usize,
        drained_count: usize,
        quarantined_count: usize,
    },
    /// Inbound message classifier blocked a message.
    ClassifierBlocked {
        category: String,
        confidence: f64,
        reasoning: String,
        run_id: String,
    },
    /// Inbound message classifier warned about a message.
    ClassifierWarned {
        category: String,
        confidence: f64,
        reasoning: String,
        run_id: String,
    },
    /// One or more audit events could not be enqueued while the daemon queue was full.
    AuditEventsDropped {
        dropped_count: u64,
    },
}

impl AuditEvent {
    /// Return the snake_case event name (matches the serde tag).
    pub fn event_name(&self) -> &'static str {
        match self {
            AuditEvent::AuthSuccess { .. } => "auth_success",
            AuditEvent::AuthFailure { .. } => "auth_failure",
            AuditEvent::ConfigChanged { .. } => "config_changed",
            AuditEvent::TaskMutated { .. } => "task_mutated",
            AuditEvent::DevicePaired { .. } => "device_paired",
            AuditEvent::NodePaired { .. } => "node_paired",
            AuditEvent::ToolExecuted { .. } => "tool_executed",
            AuditEvent::ToolDenied { .. } => "tool_denied",
            AuditEvent::SessionCreated { .. } => "session_created",
            AuditEvent::SessionDeleted { .. } => "session_deleted",
            AuditEvent::SessionPurged { .. } => "session_purged",
            AuditEvent::DataExported { .. } => "data_exported",
            AuditEvent::PluginInstalled { .. } => "plugin_installed",
            AuditEvent::ApprovalResolved { .. } => "approval_resolved",
            AuditEvent::BackupCreated { .. } => "backup_created",
            AuditEvent::RateLimitHit { .. } => "rate_limit_hit",
            AuditEvent::GatewayConnected { .. } => "gateway_connected",
            AuditEvent::GatewayDisconnected { .. } => "gateway_disconnected",
            AuditEvent::PromptGuardBlocked { .. } => "prompt_guard_blocked",
            AuditEvent::PluginSignatureVerified { .. } => "plugin_signature_verified",
            AuditEvent::PluginSignatureFailed { .. } => "plugin_signature_failed",
            AuditEvent::PluginCapabilityDenied { .. } => "plugin_capability_denied",
            AuditEvent::SessionIntegrityViolation { .. } => "session_integrity_violation",
            AuditEvent::UpdateHealthyMarkerFailed { .. } => "update_healthy_marker_failed",
            AuditEvent::UpdateHealthyEvidenceCleanupFailed { .. } => {
                "update_healthy_evidence_cleanup_failed"
            }
            AuditEvent::UpdateRollbackBackupReaped { .. } => "update_rollback_backup_reaped",
            AuditEvent::MatrixRecoveryKeyRestoreCleanupFailed { .. } => {
                "matrix_recovery_key_restore_cleanup_failed"
            }
            AuditEvent::MatrixRecoveryKeyPendingPromotionRefused { .. } => {
                "matrix_recovery_key_pending_promotion_refused"
            }
            AuditEvent::MatrixRecoveryKeyRotationMarkerInvalid { .. } => {
                "matrix_recovery_key_rotation_marker_invalid"
            }
            AuditEvent::MatrixInboundDlqLegacyEnvelopeProcessed { .. } => {
                "matrix_inbound_dlq_legacy_envelope_processed"
            }
            AuditEvent::ClassifierBlocked { .. } => "classifier_blocked",
            AuditEvent::ClassifierWarned { .. } => "classifier_warned",
            AuditEvent::AuditEventsDropped { .. } => "audit_events_dropped",
        }
    }
}

fn update_phase_audit_wire_name(phase: UpdatePhase) -> &'static str {
    match phase {
        UpdatePhase::Created => "Created",
        UpdatePhase::Downloading => "Downloading",
        UpdatePhase::Downloaded => "Downloaded",
        UpdatePhase::Verified => "Verified",
        UpdatePhase::Applying => "Applying",
        UpdatePhase::Applied => "Applied",
        UpdatePhase::Failed => "Failed",
    }
}

fn parse_update_phase_audit_wire_name(value: &str) -> Option<UpdatePhase> {
    match value {
        "Created" | "created" => Some(UpdatePhase::Created),
        "Downloading" | "downloading" => Some(UpdatePhase::Downloading),
        "Downloaded" | "downloaded" => Some(UpdatePhase::Downloaded),
        "Verified" | "verified" => Some(UpdatePhase::Verified),
        "Applying" | "applying" => Some(UpdatePhase::Applying),
        "Applied" | "applied" => Some(UpdatePhase::Applied),
        "Failed" | "failed" => Some(UpdatePhase::Failed),
        _ => None,
    }
}

fn serialize_update_phase_option_audit_compat<S>(
    phase: &Option<UpdatePhase>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match phase {
        Some(phase) => serializer.serialize_some(update_phase_audit_wire_name(*phase)),
        None => serializer.serialize_none(),
    }
}

fn deserialize_update_phase_option_audit_compat<'de, D>(
    deserializer: D,
) -> Result<Option<UpdatePhase>, D::Error>
where
    D: Deserializer<'de>,
{
    let Some(value) = Option::<String>::deserialize(deserializer)? else {
        return Ok(None);
    };
    parse_update_phase_audit_wire_name(&value)
        .map(Some)
        .ok_or_else(|| serde::de::Error::custom(format!("unknown update phase '{value}'")))
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
    log_path: PathBuf,
    rotated_path: PathBuf,
    dropped_entries: Arc<AtomicU64>,
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

        let dropped_entries = Arc::new(AtomicU64::new(0));

        // Spawn background writer.
        tokio::spawn(writer_task(
            rx,
            log_path.clone(),
            rotated_path.clone(),
            dropped_entries.clone(),
        ));

        let audit_log = AuditLog {
            tx,
            state_dir: state_dir.clone(),
            log_path,
            rotated_path,
            dropped_entries,
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
            self.dropped_entries.fetch_add(1, Ordering::Relaxed);
            tracing::warn!("audit: channel full or closed, dropping event: {e}");
            flush_audit_drop_marker(&self.dropped_entries, &self.log_path, &self.rotated_path);
        }
    }
}

// ---------------------------------------------------------------------------
// Background writer task
// ---------------------------------------------------------------------------

async fn writer_task(
    mut rx: mpsc::Receiver<AuditEntry>,
    log_path: PathBuf,
    rotated_path: PathBuf,
    dropped_entries: Arc<AtomicU64>,
) {
    while let Some(entry) = rx.recv().await {
        // Serialize entry.
        let line = match serde_json::to_string(&entry) {
            Ok(s) => s,
            Err(e) => {
                dropped_entries.fetch_add(1, Ordering::Relaxed);
                tracing::error!("audit: failed to serialize entry: {e}");
                flush_audit_drop_marker(&dropped_entries, &log_path, &rotated_path);
                continue;
            }
        };

        if let Err(e) = write_entry_to_disk(&line, &log_path, &rotated_path) {
            dropped_entries.fetch_add(1, Ordering::Relaxed);
            tracing::error!("audit: failed to write entry: {e}");
            flush_audit_drop_marker(&dropped_entries, &log_path, &rotated_path);
            continue;
        }
        flush_audit_drop_marker(&dropped_entries, &log_path, &rotated_path);
    }
}

fn flush_audit_drop_marker(dropped_entries: &AtomicU64, log_path: &Path, rotated_path: &Path) {
    let dropped_count = dropped_entries.swap(0, Ordering::AcqRel);
    if dropped_count == 0 {
        return;
    }
    let marker = AuditEntry {
        ts: Utc::now().to_rfc3339(),
        event: "audit_events_dropped".to_string(),
        data: serde_json::to_value(AuditEvent::AuditEventsDropped { dropped_count })
            .unwrap_or(Value::Null),
    };
    match serde_json::to_string(&marker)
        .map_err(std::io::Error::other)
        .and_then(|line| write_entry_to_disk(&line, log_path, rotated_path))
    {
        Ok(()) => {}
        Err(e) => {
            dropped_entries.fetch_add(dropped_count, Ordering::Relaxed);
            tracing::error!("audit: failed to write queue drop marker: {e}");
        }
    }
}

/// Rotate the audit log file if needed, then append a serialized entry line.
fn write_entry_to_disk(line: &str, log_path: &Path, rotated_path: &Path) -> std::io::Result<()> {
    write_entry_to_disk_strict(line, log_path, rotated_path)
}

fn write_entry_to_disk_strict(
    line: &str,
    log_path: &Path,
    rotated_path: &Path,
) -> std::io::Result<()> {
    match fs::symlink_metadata(log_path) {
        Ok(meta) => {
            validate_audit_log_metadata(log_path, &meta)?;
            if meta.len() >= MAX_FILE_SIZE {
                reject_existing_audit_reparse_or_symlink(rotated_path)?;
                fs::rename(log_path, rotated_path)?;
                crate::paths::sync_parent_dir_blocking(rotated_path)?;
            }
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(err),
    }

    let mut file = open_audit_log_for_append(log_path)?;
    writeln!(file, "{line}")?;
    file.sync_all()?;
    crate::paths::sync_parent_dir_blocking(log_path)?;
    Ok(())
}

fn audit_metadata_is_reparse_point(metadata: &fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

        metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }
    #[cfg(not(windows))]
    {
        let _ = metadata;
        false
    }
}

fn validate_audit_log_metadata(path: &Path, metadata: &fs::Metadata) -> std::io::Result<()> {
    if metadata.file_type().is_symlink() || audit_metadata_is_reparse_point(metadata) {
        return Err(std::io::Error::new(
            ErrorKind::InvalidInput,
            format!(
                "audit log path '{}' is a symlink or reparse point",
                path.display()
            ),
        ));
    }
    if !metadata.is_file() {
        return Err(std::io::Error::new(
            ErrorKind::InvalidInput,
            format!("audit log path '{}' is not a regular file", path.display()),
        ));
    }
    Ok(())
}

fn reject_existing_audit_reparse_or_symlink(path: &Path) -> std::io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => validate_audit_log_metadata(path, &metadata),
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err),
    }
}

fn open_audit_log_for_append(path: &Path) -> std::io::Result<fs::File> {
    reject_existing_audit_reparse_or_symlink(path)?;
    let mut options = fs::OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
        options.custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    validate_audit_log_metadata(path, &metadata)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o777 != 0o600 {
            file.set_permissions(fs::Permissions::from_mode(0o600))?;
        }
    }
    Ok(file)
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

/// Synchronously append an audit event to a specific state directory.
///
/// CLI commands use this when the process may exit before the background audit
/// writer has a chance to drain. Server paths should continue to use
/// [`audit`] after [`AuditLog::init`] has installed the process-wide writer,
/// but callers that choose this API get a direct write to the supplied
/// `state_dir` even when a daemon writer is initialized for another directory.
///
/// If the process-wide writer already owns the same state directory, this
/// refuses the direct write so two in-process writers cannot race log rotation.
pub fn audit_blocking(state_dir: PathBuf, event: AuditEvent) -> std::io::Result<()> {
    if let Err(e) = fs::create_dir_all(&state_dir) {
        tracing::error!("audit: failed to create state dir for blocking write: {e}");
        return Err(e);
    }
    if let Some(log) = AUDIT_LOG.get() {
        if audit_state_dirs_match(&log.state_dir, &state_dir)? {
            let err = std::io::Error::other(
                "blocking audit write refused because the initialized audit writer owns the same state directory",
            );
            tracing::error!("audit: {err}");
            return Err(err);
        }
    }
    let entry = AuditEntry {
        ts: Utc::now().to_rfc3339(),
        event: event.event_name().to_string(),
        data: serde_json::to_value(&event).unwrap_or(Value::Null),
    };
    let line = match serde_json::to_string(&entry) {
        Ok(line) => line,
        Err(e) => {
            tracing::error!("audit: failed to serialize blocking entry: {e}");
            return Err(std::io::Error::other(e));
        }
    };
    if let Err(e) = write_entry_to_disk_strict(
        &line,
        &state_dir.join(AUDIT_FILE_NAME),
        &state_dir.join(AUDIT_ROTATED_NAME),
    ) {
        tracing::error!("audit: failed to write blocking entry: {e}");
        return Err(e);
    }
    Ok(())
}

/// Write directly when no daemon writer owns `state_dir`; otherwise enqueue on
/// that writer so in-process callers do not race the audit log file.
pub fn audit_blocking_or_enqueue_for_state_dir(
    state_dir: PathBuf,
    event: AuditEvent,
) -> std::io::Result<()> {
    if let Some(log) = AUDIT_LOG.get() {
        if audit_state_dirs_match(&log.state_dir, &state_dir)? {
            log.log(event);
            return Ok(());
        }
    }
    audit_blocking(state_dir, event)
}

fn audit_state_dirs_match(initialized: &Path, requested: &Path) -> std::io::Result<bool> {
    if initialized == requested {
        return Ok(true);
    }
    let Some(initialized) = canonicalize_existing_or_none(initialized)? else {
        return Ok(false);
    };
    let Some(requested) = canonicalize_existing_or_none(requested)? else {
        return Ok(false);
    };
    Ok(initialized == requested)
}

fn canonicalize_existing_or_none(path: &Path) -> std::io::Result<Option<PathBuf>> {
    match path.canonicalize() {
        Ok(path) => Ok(Some(path)),
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err),
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
fn read_tail_entries(path: &Path, limit: usize) -> Vec<AuditEntry> {
    let file = match open_audit_log_for_read(path) {
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

fn open_audit_log_for_read(path: &Path) -> std::io::Result<fs::File> {
    reject_existing_audit_reparse_or_symlink(path)?;
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    validate_audit_log_metadata(path, &metadata)?;
    Ok(file)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    fn exhaustive_event_name_for_test(event: &AuditEvent) -> &'static str {
        match event {
            AuditEvent::AuthSuccess { .. } => "auth_success",
            AuditEvent::AuthFailure { .. } => "auth_failure",
            AuditEvent::ConfigChanged { .. } => "config_changed",
            AuditEvent::TaskMutated { .. } => "task_mutated",
            AuditEvent::DevicePaired { .. } => "device_paired",
            AuditEvent::NodePaired { .. } => "node_paired",
            AuditEvent::ToolExecuted { .. } => "tool_executed",
            AuditEvent::ToolDenied { .. } => "tool_denied",
            AuditEvent::SessionCreated { .. } => "session_created",
            AuditEvent::SessionDeleted { .. } => "session_deleted",
            AuditEvent::SessionPurged { .. } => "session_purged",
            AuditEvent::DataExported { .. } => "data_exported",
            AuditEvent::PluginInstalled { .. } => "plugin_installed",
            AuditEvent::ApprovalResolved { .. } => "approval_resolved",
            AuditEvent::BackupCreated { .. } => "backup_created",
            AuditEvent::RateLimitHit { .. } => "rate_limit_hit",
            AuditEvent::GatewayConnected { .. } => "gateway_connected",
            AuditEvent::GatewayDisconnected { .. } => "gateway_disconnected",
            AuditEvent::PromptGuardBlocked { .. } => "prompt_guard_blocked",
            AuditEvent::PluginSignatureVerified { .. } => "plugin_signature_verified",
            AuditEvent::PluginSignatureFailed { .. } => "plugin_signature_failed",
            AuditEvent::PluginCapabilityDenied { .. } => "plugin_capability_denied",
            AuditEvent::SessionIntegrityViolation { .. } => "session_integrity_violation",
            AuditEvent::UpdateHealthyMarkerFailed { .. } => "update_healthy_marker_failed",
            AuditEvent::UpdateHealthyEvidenceCleanupFailed { .. } => {
                "update_healthy_evidence_cleanup_failed"
            }
            AuditEvent::UpdateRollbackBackupReaped { .. } => "update_rollback_backup_reaped",
            AuditEvent::MatrixRecoveryKeyRestoreCleanupFailed { .. } => {
                "matrix_recovery_key_restore_cleanup_failed"
            }
            AuditEvent::MatrixRecoveryKeyPendingPromotionRefused { .. } => {
                "matrix_recovery_key_pending_promotion_refused"
            }
            AuditEvent::MatrixRecoveryKeyRotationMarkerInvalid { .. } => {
                "matrix_recovery_key_rotation_marker_invalid"
            }
            AuditEvent::MatrixInboundDlqLegacyEnvelopeProcessed { .. } => {
                "matrix_inbound_dlq_legacy_envelope_processed"
            }
            AuditEvent::ClassifierBlocked { .. } => "classifier_blocked",
            AuditEvent::ClassifierWarned { .. } => "classifier_warned",
            AuditEvent::AuditEventsDropped { .. } => "audit_events_dropped",
        }
    }

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
            AuditEvent::TaskMutated {
                task_id: "t".into(),
                action: "retry".into(),
                actor: "a".into(),
                resulting_state: "retry_wait".into(),
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
            AuditEvent::PluginInstalled {
                plugin_id: "s".into(),
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
            AuditEvent::PromptGuardBlocked {
                layer: "l".into(),
                reason: "r".into(),
                run_id: "rid".into(),
            },
            AuditEvent::PluginSignatureVerified {
                plugin_id: "s".into(),
            },
            AuditEvent::PluginSignatureFailed {
                plugin_id: "s".into(),
                reason: "r".into(),
            },
            AuditEvent::PluginCapabilityDenied {
                plugin_id: "s".into(),
                capabilities: vec!["http".into()],
            },
            AuditEvent::SessionIntegrityViolation {
                session_id: "s".into(),
                file: "f".into(),
                action: "a".into(),
            },
            AuditEvent::UpdateHealthyMarkerFailed {
                phase: Some(UpdatePhase::Applied),
                retryable: true,
                evidence_recorded: true,
            },
            AuditEvent::UpdateHealthyEvidenceCleanupFailed {
                phase: Some(UpdatePhase::Applied),
                retryable: true,
            },
            AuditEvent::UpdateRollbackBackupReaped {
                path: "/tmp/cara.bak".into(),
            },
            AuditEvent::MatrixRecoveryKeyRestoreCleanupFailed {
                artifacts: vec![MatrixRecoveryKeyRestoreCleanupArtifact {
                    label: MatrixRecoveryKeyArtifactLabel::PendingKey,
                    error_kind: MatrixRecoveryKeyRestoreCleanupErrorKind::RemoveFailed,
                }],
            },
            AuditEvent::MatrixRecoveryKeyPendingPromotionRefused {
                marker_stage: MatrixRecoveryKeyRotationStage::PendingKeyWritten,
                reason: MatrixRecoveryKeyPromotionRefusalReason::CurrentKeyMismatch,
                artifacts: vec![
                    MatrixRecoveryKeyArtifactLabel::RotationMarker,
                    MatrixRecoveryKeyArtifactLabel::CurrentKey,
                    MatrixRecoveryKeyArtifactLabel::PendingKey,
                ],
                current_key: MatrixRecoveryKeyState::Mismatch,
                pending_key: MatrixRecoveryKeyState::MatchesNewKey,
            },
            AuditEvent::MatrixRecoveryKeyRotationMarkerInvalid {
                reason: MatrixRecoveryKeyRotationMarkerInvalidReason::CorruptTypedMarker,
            },
            AuditEvent::MatrixInboundDlqLegacyEnvelopeProcessed {
                from_version: 1,
                current_version: 2,
                record_count: 3,
                reencoded_count: 1,
                drained_count: 1,
                quarantined_count: 1,
            },
            AuditEvent::ClassifierBlocked {
                category: "prompt_injection".into(),
                confidence: 0.95,
                reasoning: "r".into(),
                run_id: "rid".into(),
            },
            AuditEvent::ClassifierWarned {
                category: "social_engineering".into(),
                confidence: 0.85,
                reasoning: "r".into(),
                run_id: "rid".into(),
            },
            AuditEvent::AuditEventsDropped { dropped_count: 1 },
        ];
        let names: Vec<&str> = events.iter().map(|e| e.event_name()).collect();
        for event in &events {
            assert_eq!(event.event_name(), exhaustive_event_name_for_test(event));
        }
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
    fn test_update_audit_phase_preserves_released_wire_case() {
        let ev = AuditEvent::UpdateHealthyMarkerFailed {
            phase: Some(UpdatePhase::Applied),
            retryable: true,
            evidence_recorded: true,
        };

        let value = serde_json::to_value(&ev).unwrap();
        assert_eq!(value["phase"], serde_json::json!("Applied"));

        let old_case = r#"{
            "type":"update_healthy_marker_failed",
            "phase":"Applied",
            "retryable":true,
            "evidence_recorded":true
        }"#;
        let new_case = r#"{
            "type":"update_healthy_marker_failed",
            "phase":"applied",
            "retryable":true,
            "evidence_recorded":true
        }"#;
        assert_eq!(serde_json::from_str::<AuditEvent>(old_case).unwrap(), ev);
        assert_eq!(serde_json::from_str::<AuditEvent>(new_case).unwrap(), ev);
    }

    #[test]
    fn test_matrix_recovery_pending_refusal_audit_is_typed_and_redacted() {
        let ev = AuditEvent::MatrixRecoveryKeyPendingPromotionRefused {
            marker_stage: MatrixRecoveryKeyRotationStage::PendingKeyWritten,
            reason: MatrixRecoveryKeyPromotionRefusalReason::CurrentKeyMismatch,
            artifacts: vec![
                MatrixRecoveryKeyArtifactLabel::RotationMarker,
                MatrixRecoveryKeyArtifactLabel::CurrentKey,
                MatrixRecoveryKeyArtifactLabel::PendingKey,
            ],
            current_key: MatrixRecoveryKeyState::Mismatch,
            pending_key: MatrixRecoveryKeyState::MatchesNewKey,
        };

        let value = serde_json::to_value(&ev).unwrap();
        assert_eq!(
            value["type"],
            serde_json::json!("matrix_recovery_key_pending_promotion_refused")
        );
        assert_eq!(
            value["marker_stage"],
            serde_json::json!("pending_key_written")
        );
        assert_eq!(value["reason"], serde_json::json!("current_key_mismatch"));
        assert_eq!(value["current_key"], serde_json::json!("mismatch"));
        assert_eq!(value["pending_key"], serde_json::json!("matches_new_key"));
        let serialized = serde_json::to_string(&value).unwrap();
        assert!(!serialized.contains('/'));
        assert!(!serialized.contains("sha256"));
    }

    #[test]
    fn test_matrix_recovery_restore_cleanup_audit_fields_are_snake_case() {
        let ev = AuditEvent::MatrixRecoveryKeyRestoreCleanupFailed {
            artifacts: vec![MatrixRecoveryKeyRestoreCleanupArtifact {
                label: MatrixRecoveryKeyArtifactLabel::MintingMarker,
                error_kind: MatrixRecoveryKeyRestoreCleanupErrorKind::ParentSyncFailed,
            }],
        };

        let value = serde_json::to_value(&ev).unwrap();
        let artifact = value["artifacts"][0].as_object().unwrap();
        assert_eq!(
            artifact.get("error_kind"),
            Some(&serde_json::json!("parent_sync_failed"))
        );
        assert!(
            !artifact.contains_key("errorKind"),
            "recovery audit payloads use snake_case field names consistently"
        );
    }

    #[test]
    fn test_matrix_recovery_rotation_marker_invalid_audit_is_typed_and_redacted() {
        let ev = AuditEvent::MatrixRecoveryKeyRotationMarkerInvalid {
            reason: MatrixRecoveryKeyRotationMarkerInvalidReason::CorruptTypedMarker,
        };

        let value = serde_json::to_value(&ev).unwrap();
        assert_eq!(
            value["type"],
            serde_json::json!("matrix_recovery_key_rotation_marker_invalid")
        );
        assert_eq!(value["reason"], serde_json::json!("corrupt_typed_marker"));
        let serialized = serde_json::to_string(&value).unwrap();
        assert!(!serialized.contains('/'));
        assert!(!serialized.contains("sha256"));
        assert!(!serialized.contains("recovery_key.rotating"));
        assert!(!serialized.contains("recovery_key.pending"));
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
    fn test_audit_blocking_rotates_and_writes_with_strict_path() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join(AUDIT_FILE_NAME);
        fs::File::create(&log_path)
            .unwrap()
            .set_len(MAX_FILE_SIZE)
            .unwrap();

        audit_blocking(
            dir.path().to_path_buf(),
            AuditEvent::GatewayConnected {
                gateway_id: "g1".into(),
            },
        )
        .unwrap();

        assert!(dir.path().join(AUDIT_ROTATED_NAME).exists());
        let content = fs::read_to_string(&log_path).unwrap();
        assert!(content.contains("gateway_connected"));
    }

    #[cfg(unix)]
    #[test]
    fn test_audit_blocking_creates_owner_only_log() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        audit_blocking(
            dir.path().to_path_buf(),
            AuditEvent::GatewayConnected {
                gateway_id: "g1".into(),
            },
        )
        .unwrap();

        let mode = fs::metadata(dir.path().join(AUDIT_FILE_NAME))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn test_audit_blocking_rejects_symlinked_active_log() {
        use std::os::unix::fs::symlink;

        let dir = TempDir::new().unwrap();
        let target = dir.path().join("redirected.jsonl");
        fs::write(&target, "").unwrap();
        symlink(&target, dir.path().join(AUDIT_FILE_NAME)).unwrap();

        let err = audit_blocking(
            dir.path().to_path_buf(),
            AuditEvent::GatewayConnected {
                gateway_id: "g1".into(),
            },
        )
        .expect_err("audit writer must reject symlinked active log paths");

        assert!(err.to_string().contains("symlink"));
    }

    #[tokio::test]
    async fn test_writer_task_emits_audit_events_dropped_marker() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join(AUDIT_FILE_NAME);
        let rotated_path = dir.path().join(AUDIT_ROTATED_NAME);
        let dropped = Arc::new(AtomicU64::new(3));
        let (tx, rx) = mpsc::channel::<AuditEntry>(1);
        tokio::spawn(writer_task(rx, log_path.clone(), rotated_path, dropped));

        let entry = AuditEntry {
            ts: Utc::now().to_rfc3339(),
            event: "gateway_connected".into(),
            data: serde_json::json!({"type":"gateway_connected","gateway_id":"g1"}),
        };
        tx.send(entry).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let content = fs::read_to_string(&log_path).unwrap();
        assert!(content.contains("gateway_connected"));
        assert!(content.contains("audit_events_dropped"));
        assert!(content.contains("\"dropped_count\":3"));
    }

    #[test]
    fn test_audit_log_drop_path_writes_marker_without_later_entry() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join(AUDIT_FILE_NAME);
        let rotated_path = dir.path().join(AUDIT_ROTATED_NAME);
        let (tx, _rx) = mpsc::channel::<AuditEntry>(1);
        tx.try_send(AuditEntry {
            ts: Utc::now().to_rfc3339(),
            event: "gateway_connected".into(),
            data: serde_json::json!({"type":"gateway_connected","gateway_id":"already-full"}),
        })
        .unwrap();
        let log = AuditLog {
            tx,
            state_dir: dir.path().to_path_buf(),
            log_path: log_path.clone(),
            rotated_path,
            dropped_entries: Arc::new(AtomicU64::new(0)),
        };

        log.log(AuditEvent::GatewayConnected {
            gateway_id: "dropped".into(),
        });

        let content = fs::read_to_string(&log_path).unwrap();
        assert!(content.contains("audit_events_dropped"));
        assert!(content.contains("\"dropped_count\":1"));
    }

    #[tokio::test]
    async fn test_audit_blocking_writes_supplied_state_dir_when_writer_initialized_for_different_dir(
    ) {
        let daemon_dir = TempDir::new().unwrap();
        AuditLog::init(daemon_dir.path().to_path_buf()).await;
        assert!(
            AUDIT_LOG.get().is_some(),
            "test requires the process-wide writer to be initialized"
        );

        let blocking_dir = TempDir::new().unwrap();
        audit_blocking(
            blocking_dir.path().to_path_buf(),
            AuditEvent::GatewayConnected {
                gateway_id: "blocking-gateway".into(),
            },
        )
        .unwrap();

        let blocking_log = blocking_dir.path().join(AUDIT_FILE_NAME);
        let content = fs::read_to_string(&blocking_log).unwrap();
        assert!(content.contains("gateway_connected"));
        assert!(content.contains("blocking-gateway"));
    }

    #[tokio::test]
    async fn test_audit_blocking_refuses_state_dir_owned_by_initialized_writer() {
        let daemon_dir = TempDir::new().unwrap();
        AuditLog::init(daemon_dir.path().to_path_buf()).await;
        let initialized_state_dir = AUDIT_LOG
            .get()
            .expect("test requires initialized audit writer")
            .state_dir
            .clone();

        let err = audit_blocking(
            initialized_state_dir,
            AuditEvent::GatewayConnected {
                gateway_id: "same-dir-gateway".into(),
            },
        )
        .expect_err("blocking writer must refuse a state dir owned by the daemon writer");

        assert!(err
            .to_string()
            .contains("initialized audit writer owns the same state directory"));
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

    #[cfg(unix)]
    #[test]
    fn test_read_tail_entries_rejects_symlinked_log() {
        use std::os::unix::fs::symlink;

        let dir = TempDir::new().unwrap();
        let target = dir.path().join("target.jsonl");
        let link = dir.path().join(AUDIT_FILE_NAME);
        fs::write(&target, "").unwrap();
        symlink(&target, &link).unwrap();

        assert!(
            read_tail_entries(&link, 10).is_empty(),
            "tail reads must not follow symlinked audit logs"
        );
    }

    #[test]
    fn test_audit_state_dirs_match_missing_requested_is_false() {
        let dir = TempDir::new().unwrap();
        let missing = dir.path().join("missing");

        let matched = audit_state_dirs_match(dir.path(), &missing).unwrap();

        assert!(!matched);
    }

    #[tokio::test]
    async fn test_audit_log_init_and_log() {
        let dir = TempDir::new().unwrap();
        let state_dir = dir.path().to_path_buf();
        let (tx, rx) = mpsc::channel::<AuditEntry>(CHANNEL_CAPACITY);
        let log_path = state_dir.join(AUDIT_FILE_NAME);
        let rotated_path = state_dir.join(AUDIT_ROTATED_NAME);
        tokio::spawn(writer_task(
            rx,
            log_path.clone(),
            rotated_path,
            Arc::new(AtomicU64::new(0)),
        ));
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
        tokio::spawn(writer_task(
            rx,
            log_path.clone(),
            rotated_path,
            Arc::new(AtomicU64::new(0)),
        ));
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
        tokio::spawn(writer_task(
            rx,
            log_path.clone(),
            rotated_path.clone(),
            Arc::new(AtomicU64::new(0)),
        ));
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
    fn test_event_name_plugin_installed() {
        assert_eq!(
            AuditEvent::PluginInstalled {
                plugin_id: "s".into(),
                source_url: "https://example.com".into()
            }
            .event_name(),
            "plugin_installed"
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
    fn test_event_name_task_mutated() {
        assert_eq!(
            AuditEvent::TaskMutated {
                task_id: "task-1".into(),
                action: "cancel".into(),
                actor: "127.0.0.1".into(),
                resulting_state: "cancelled".into(),
            }
            .event_name(),
            "task_mutated"
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
