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
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::time::Duration;

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

/// Periodic durability interval for accumulated audit drop markers.
const AUDIT_DROP_MARKER_FLUSH_INTERVAL: Duration = Duration::from_secs(30);
/// Independent watchdog cadence for the secondary drop-marker
/// flusher (`drop_marker_watchdog_task`). Runs longer than the
/// writer-task's own flush interval so under healthy conditions
/// the watchdog observes nothing to do; if the writer task dies
/// (panic, kill, hang) the watchdog still surfaces accumulated
/// drop counts to disk every minute.
const AUDIT_DROP_MARKER_WATCHDOG_INTERVAL: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditWriteOutcome {
    Written,
    Enqueued,
    Dropped(AuditDropReason),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditDropReason {
    ChannelFull,
    ChannelClosed,
}

impl std::fmt::Display for AuditDropReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuditDropReason::ChannelFull => f.write_str("audit channel full"),
            AuditDropReason::ChannelClosed => f.write_str("audit channel closed"),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MatrixVerificationAuditAction {
    Start,
    Accept,
    Confirm,
    Cancel,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MatrixVerificationAuditOutcome {
    /// Action succeeded — the runtime accepted and processed it.
    Ok,
    /// Action failed at the runtime (typed kind not included to keep
    /// the wire shape stable and prevent leaking SDK-internal
    /// classification strings).
    Err,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
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

/// Outcome of the first-mint audit event. Distinguishes a fresh
/// mint at startup from a finalize-after-restart of a previously-
/// interrupted mint.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MatrixRecoveryKeyFirstMintOutcome {
    /// First-time mint completed in a single startup pass.
    Minted,
    /// A previously-interrupted mint left a pending-key file on
    /// disk; this startup promoted it to the live recovery-key
    /// path and removed the marker.
    PromotedPendingAfterRestart,
}

/// Outcome of cross-signing bootstrap. Distinguishes the no-UIA
/// branch (server confirmed cross-signing identity without
/// re-authentication) from the after-UIA branch (operator-supplied
/// password re-authenticated to authorize the new keys).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MatrixCrossSigningBootstrapOutcome {
    /// Homeserver accepted the bootstrap without prompting for
    /// User-Interactive Auth — typically because cross-signing
    /// was already in place and we confirmed ownership.
    ConfirmedOrBootstrappedWithoutUia,
    /// Bootstrap required UIA; the operator-supplied password
    /// re-authenticated and the new keys were authorized.
    BootstrappedAfterUia,
}

/// Specific cleanup path taken by
/// `recover_interrupted_recovery_key_rotation`. Used as the
/// `outcome` discriminator on
/// [`AuditEvent::MatrixRecoveryKeyRotateRecovered`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MatrixRecoveryKeyRotateRecoveredOutcome {
    /// A pending recovery-key file was on disk but the current
    /// recovery key already matches the marker's new-key digest.
    /// The pending file is stale; it is removed and the marker
    /// is cleared.
    ClearedStalePending,
    /// A pending recovery-key file was on disk, the marker is at
    /// `PendingKeyWritten`, the current key matches the marker's
    /// `previous_key_sha256`, and the pending file's digest
    /// matches the marker's `key_sha256`. The pending file is
    /// promoted to the live recovery-key path.
    PromotedPending,
    /// The marker was at `FinalKeyReplaced` and the current key
    /// already matches the marker's new-key digest. The marker
    /// is cleared without touching any key file.
    ClearedFinalMarker,
    /// The marker was at `Started`, no pending file existed, and
    /// the current key matched the marker's pre-rotation digest
    /// (the rotation never began on this filesystem). The marker
    /// is cleared.
    ClearedStartedMarker,
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
    /// Managed plugin manifest rollback failed after a partial transaction.
    ManagedPluginManifestRollbackFailed {
        plugin_id: String,
        error: String,
    },
    /// Managed plugin artifact rollback failed after a partial transaction.
    ManagedPluginArtifactRollbackFailed {
        plugin_id: String,
        error: String,
    },
    /// Managed plugin first-install cleanup failed after a partial transaction.
    ManagedPluginFirstInstallCleanupFailed {
        plugin_id: String,
        error: String,
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
        #[serde(serialize_with = "serialize_redacted_update_rollback_backup_path")]
        path: String,
    },
    /// Matrix recovery-key restore left stale rotation artifacts behind.
    MatrixRecoveryKeyRestoreCleanupFailed {
        artifacts: Vec<MatrixRecoveryKeyRestoreCleanupArtifact>,
    },
    /// Matrix recovery-key restore wrote the cleanup journal in Started
    /// phase. Emitted BEFORE the key file is written, so a crash window
    /// between the anchor and the key write still has a durable audit
    /// trail that a restore was initiated.
    MatrixRecoveryKeyRestoreCleanupAnchored {
        artifacts: Vec<MatrixRecoveryKeyArtifactLabel>,
    },
    /// Matrix recovery-key restore detected an outstanding cleanup
    /// journal (key file already on disk) and resumed the cleanup
    /// pass instead of refusing on the existence guard.
    MatrixRecoveryKeyRestoreCleanupResumed {
        artifacts: Vec<MatrixRecoveryKeyArtifactLabel>,
    },
    /// Daemon refused to start because a Matrix recovery-key restore
    /// cleanup journal is still in Started phase. Surfaces the boot
    /// blocker durably so audit consumers can correlate operator
    /// follow-up.
    MatrixRecoveryKeyStartupCleanupRefused {
        artifact_count: usize,
    },
    /// DLQ replay encountered a record whose sender no longer matches
    /// the current `matrix.autoJoin` allowlist. The record was dropped
    /// (treated as successfully dispatched so phase-3 removes it from
    /// the DLQ rather than leaving an un-dispatchable entry that
    /// occupies cap forever). Operator-attended traceback for
    /// allowlist-drift between original receive and replay.
    MatrixInboundDlqRecordDroppedAllowlistDrift {
        sender_id: String,
        event_id: String,
    },
    /// Operator bypassed the Matrix SAS human-comparison gate via
    /// `cara matrix confirm --unsafe-skip-sas-prompt`. The bypass
    /// is an explicit operator decision but defeats the MITM-
    /// resistance of the SAS protocol; this flow's authenticity
    /// now relies entirely on out-of-band verification.
    ///
    /// Promoted from `tracing::warn!(audit_event = "matrix_sas_unsafe_skip", ...)`
    /// so a post-incident investigation (operator copied a
    /// malicious confirm command from a phishing message) can grep
    /// the audit log instead of relying on the surrounding
    /// tracing log having survived rotation.
    MatrixSasUnsafeSkip {
        /// Matrix verification flow id (uuid-shaped string).
        flow_id: String,
        /// CLI target host (typically `127.0.0.1` for local
        /// daemon).
        host: String,
        /// CLI target port as the operator passed it on the
        /// command line. `None` means the operator did not pass
        /// `--port`, in which case the CLI falls back to the
        /// config / default-18789 chain at connect time.
        #[serde(skip_serializing_if = "Option::is_none")]
        port: Option<u16>,
        /// PID of the CLI process issuing the bypass.
        pid: u32,
        /// The match/no-match outcome the operator asserted
        /// without comparing the SAS.
        matches: bool,
    },
    /// Matrix recovery key restored during DAEMON startup (the
    /// post-restart counterpart to the CLI-side
    /// `MatrixRecoveryKeyRestored`). Emitted when
    /// `maybe_restore_matrix_recovery_at_startup` (or its
    /// equivalent) finds a locally-staged recovery key and uses
    /// it to recover the SDK store on boot.
    MatrixRecoveryKeyRestoredAtStartup,
    /// Matrix recovery key successfully rotated. Emitted at the
    /// end of the rotation flow (matrix.rs:rotate_recovery_key
    /// final-stage). Promotes the existing
    /// `tracing::warn!(audit_event = "matrix_recovery_key_rotate", ...)`
    /// so the rotation event is grep-able in audit.jsonl alongside
    /// `MatrixRecoveryKeyFirstMint` and
    /// `MatrixRecoveryKeyRotateRecovered`.
    MatrixRecoveryKeyRotated {
        rotated_at: i64,
    },
    /// Initial mint (or finalize-after-restart) of a Matrix
    /// recovery key. Emitted by `record_recovery_key_first_mint` at
    /// both fresh-mint and promote-pending-after-restart sites.
    /// Was a `tracing::warn!(audit_event = "matrix_recovery_key_first_mint", ...)`;
    /// promoting to durable so the forensic query
    /// "when was this state_dir's recovery key first created?"
    /// has a JSONL-audit answer that survives log rotation.
    MatrixRecoveryKeyFirstMint {
        outcome: MatrixRecoveryKeyFirstMintOutcome,
        minted_at: i64,
    },
    /// Matrix cross-signing identity bootstrapped on the homeserver
    /// and locally. Emitted by `bootstrap_cross_signing_if_needed_with_uia`
    /// at both the no-UIA-needed branch and the after-UIA branch.
    /// Was a `tracing::warn!(audit_event = "matrix_cross_signing_bootstrapped", ...)`;
    /// promoted to durable so an incident-response query can confirm
    /// cross-signing identity ownership on this state_dir.
    MatrixCrossSigningBootstrapped {
        outcome: MatrixCrossSigningBootstrapOutcome,
        /// Sanitized user_id (homeserver-style identifier filtered
        /// through `sanitize_homeserver_identifier`).
        user_id: String,
    },
    /// Successful resolution of an interrupted Matrix recovery-key
    /// rotation at startup. Emitted by
    /// `recover_interrupted_recovery_key_rotation` at every cleanup
    /// path (clearing stale pending file, promoting pending to
    /// current, clearing stale marker). The refusal path is
    /// covered by `MatrixRecoveryKeyPendingPromotionRefused`; this
    /// variant is the successful-recovery companion.
    ///
    /// Was previously a `tracing::warn!(audit_event =
    /// "matrix_recovery_key_rotate_recovered", ...)`. A forensic
    /// query asking "did the daemon promote a pending recovery
    /// key at startup, when, and from which marker stage?" had no
    /// durable answer; this variant closes the gap.
    MatrixRecoveryKeyRotateRecovered {
        /// Stage the marker carried when recovery ran. Useful for
        /// distinguishing post-rotation cleanup (FinalKeyReplaced)
        /// from an actively-completed pending promotion
        /// (PendingKeyWritten) or a Started-stage marker that
        /// turned out not to need a pending key.
        marker_stage: MatrixRecoveryKeyRotationStage,
        /// Tag for the specific cleanup path taken. Distinguishes
        /// "we cleared a stale pending file because current key
        /// already matches the new marker digest" from "we promoted
        /// the pending key to current".
        outcome: MatrixRecoveryKeyRotateRecoveredOutcome,
    },
    /// Matrix recovery key restored from operator-supplied bytes.
    ///
    /// Emitted by `cara matrix recovery-key restore` after the
    /// recovery-key file lands on disk AND the cleanup journal is
    /// anchored (both irreversible state changes). Was previously a
    /// `tracing::warn!(audit_event = "matrix_recovery_key_restore", ...)`
    /// — easy to lose across log rotation. The forensic query
    /// "did anyone restore this state_dir's recovery key, when, and
    /// from which PID?" needs the JSONL audit log, not the tracing
    /// log. Companion to `MatrixRecoveryKeyRestoreCleanupResumed` and
    /// the existing rekey/start/complete audits.
    MatrixRecoveryKeyRestored {
        pid: u32,
    },
    /// Matrix DLQ rekey backup cleanup failed. The OLD-keyed
    /// `inbound-dlq.jsonl.pre-rekey` sibling remains on disk after a
    /// successful rekey. On the next daemon start
    /// `recover_matrix_inbound_dlq_rekey` will observe the backup
    /// and treat the rekey as interrupted, potentially rolling
    /// inbound DLQ contents back to the OLD key — corrupting replay
    /// for any records appended in the meantime. The operator must
    /// remove the backup manually before restart.
    ///
    /// Was previously a `tracing::warn!(audit_event = "...", ...)`.
    /// Promoting to a durable AuditEvent so an operator who missed
    /// the warn-log can still find the signal in the audit log
    /// before restarting.
    MatrixDlqRekeyBackupCleanupFailed {
        /// `Display`-formatted backup path (state_dir-relative when
        /// possible; rooted otherwise).
        backup_path: String,
        /// `Display`-formatted live DLQ path for cross-reference.
        live_path: String,
        /// `Display` of the underlying `std::io::Error`.
        error: String,
    },
    /// Matrix store rekey requested. Emitted by the CLI rekey
    /// orchestrator (`cara matrix rekey-store --new`) BEFORE any
    /// passphrase write so operators have a durable record that a
    /// rekey was initiated against this state_dir, including the PID
    /// of the issuing CLI invocation. Companion to
    /// `MatrixStoreRekeyComplete`; an isolated `start` with no
    /// matching `complete` indicates a crashed / cancelled rekey
    /// that needs the recovery path.
    ///
    /// Was previously a `tracing::warn!(audit_event = "matrix_store_rekey_start", ...)`
    /// which is easy to lose across log rotation. Forensic queries
    /// for "did anyone rekey this store" need the JSONL audit log,
    /// not tracing logs.
    MatrixStoreRekeyStart {
        /// PID of the CLI process issuing the rekey, for cross-
        /// referencing with `auth_failure` / `auth_success` events.
        pid: u32,
    },
    /// Matrix store rekey completed. Emitted by both the normal
    /// orchestrator path (after passphrase promotion) and the
    /// recovery path (`recover_interrupted_matrix_store_rekey`).
    /// `recovered: true` distinguishes the recovery flow.
    MatrixStoreRekeyComplete {
        /// Number of SQLite store databases re-encrypted under the
        /// new passphrase, including stores that were already on
        /// the new passphrase (idempotent advance).
        sqlite_store_count: usize,
        pid: u32,
        /// `true` when emitted from `recover_interrupted_matrix_store_rekey`;
        /// `false` for the normal-flow completion.
        recovered: bool,
    },
    /// State-directory chmod to `0o700` failed at startup. Per the
    /// `prepare_runtime_environment` invariant the daemon's state
    /// subtree must be owner-only; if the OS refuses (EROFS,
    /// EPERM, filesystem without Unix permissions, ACL conflict)
    /// the daemon still starts but the directory may be wider than
    /// 0o700. A bare `tracing::warn!` is easy to miss on the next
    /// log rotation, so this companion durable record gives an
    /// operator a grep-able signal that their state directory may
    /// be world-readable.
    ///
    /// Best-effort durability: if the chmod failed because of EROFS,
    /// the audit log on the same filesystem won't be writable
    /// either. In that case the tracing-warn is still the operator's
    /// only signal. Emit-site uses the non-result `audit_durable_for_state_dir`
    /// call and ignores the result for that reason.
    StateDirChmodFailed {
        /// Subdirectory path RELATIVE to the state_dir root, or "."
        /// for the state_dir root itself. Relative form is preferred
        /// because the audit log already records `state_dir`
        /// (implicitly: it's where the event lives) and the absolute
        /// path adds noise.
        subdir: String,
        /// Mode the daemon attempted to set, as a base-10 integer
        /// of the underlying octal value (e.g., 448 == 0o700).
        intended_mode: u32,
        /// `Display` of the `std::io::Error` returned by `set_permissions`.
        error: String,
    },
    /// Matrix inbound DLQ quarantine file at cap; refused-legacy /
    /// corrupt records were dropped instead of being preserved for
    /// forensic recovery.
    ///
    /// Emitted when an `append_matrix_inbound_dlq_quarantine` batch
    /// would grow the on-disk quarantine past `MATRIX_DLQ_QUARANTINE_MAX_BYTES`.
    /// The companion `tracing::warn!` at the emission site is loud
    /// enough for normal operations but is easy to lose in a log flood
    /// when sustained corruption (envelope-version migration, key-
    /// mismatch wave, or operator policy=Refuse) drives the live DLQ
    /// replay loop. This durable record gives operators a grep-able
    /// signal that the policy decision they made is now silently
    /// losing records because no one rotated the quarantine — same
    /// durability tier as `MatrixInboundDlqRecordDroppedAllowlistDrift`.
    MatrixInboundDlqQuarantineCapDropped {
        dropped_lines: usize,
        incoming_bytes: u64,
        /// File size at the moment of the cap check. 0 indicates the
        /// first-write batch itself exceeded the cap.
        existing_quarantine_bytes: u64,
        cap_bytes: u64,
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
    /// Operator-initiated Matrix device verification action (start /
    /// accept / confirm / cancel). The confirm step with matches=true
    /// is the operator's MITM-decision; emitting this audit event
    /// preserves attribution (actor, source address, flow id) so an
    /// incident responder can correlate a forged SAS comparison to a
    /// specific operator session. SAS digests are intentionally NOT
    /// included: the digest is a one-time-use challenge whose value
    /// is irrelevant after the flow completes and including it would
    /// invite confusion about whether it is sensitive.
    ///
    /// **Emission boundary.** This event is emitted only AFTER the
    /// control auth gate succeeds and after request-shape validation
    /// (size cap, JSON parse, mutual-exclusion checks) passes. Earlier
    /// rejections are covered by the framework-level audit shapes:
    /// `AuthFailure` for failed credentials, and the request-shape
    /// rejections (malformed body / oversized body) don't reach the
    /// runtime and are reflected only in tracing logs since they
    /// represent caller bugs, not state changes. Forensic queries
    /// looking for "did anyone reach the matrix verification runtime"
    /// should grep both `audit_event = "matrix_verification_action"`
    /// AND `audit_event = "auth_failure"` filtered to the matrix
    /// control endpoints.
    MatrixVerificationAction {
        action: MatrixVerificationAuditAction,
        flow_id: String,
        outcome: MatrixVerificationAuditOutcome,
        /// Operator-identifying string from `control_actor` — typically
        /// the source IP (or "unknown" if no SocketAddr was available).
        /// Mirrors the `actor` field on `AuditEvent::TaskMutated` and
        /// matches the same `control_actor()` helper, so audit consumers
        /// can correlate matrix verification confirms with task /
        /// config / approval mutations issued by the same caller.
        actor: String,
        /// Direct TCP peer source address as recorded by `control_actor`.
        /// Always present; `"unknown"` when the request arrived without
        /// a peer address. Carried alongside `actor` for the case where
        /// `actor` is later extended to include a token id / session id
        /// distinct from the IP, so the network-layer attribution is
        /// preserved even when the principal layer changes.
        remote_ip: String,
        /// `Some(true|false)` only on confirm action (the SAS-match
        /// decision). None for start / accept / cancel where the
        /// matches concept does not apply (a cancel is the operator
        /// aborting the flow, not a match-or-no-match outcome).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        matches: Option<bool>,
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
        first_drop_ts: String,
        last_drop_ts: String,
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
            AuditEvent::ManagedPluginManifestRollbackFailed { .. } => {
                "managed_plugin_manifest_rollback_failed"
            }
            AuditEvent::ManagedPluginArtifactRollbackFailed { .. } => {
                "managed_plugin_artifact_rollback_failed"
            }
            AuditEvent::ManagedPluginFirstInstallCleanupFailed { .. } => {
                "managed_plugin_first_install_cleanup_failed"
            }
            AuditEvent::SessionIntegrityViolation { .. } => "session_integrity_violation",
            AuditEvent::UpdateHealthyMarkerFailed { .. } => "update_healthy_marker_failed",
            AuditEvent::UpdateHealthyEvidenceCleanupFailed { .. } => {
                "update_healthy_evidence_cleanup_failed"
            }
            AuditEvent::UpdateRollbackBackupReaped { .. } => "update_rollback_backup_reaped",
            AuditEvent::MatrixRecoveryKeyRestoreCleanupFailed { .. } => {
                "matrix_recovery_key_restore_cleanup_failed"
            }
            AuditEvent::MatrixRecoveryKeyRestoreCleanupAnchored { .. } => {
                "matrix_recovery_key_restore_cleanup_anchored"
            }
            AuditEvent::MatrixRecoveryKeyRestoreCleanupResumed { .. } => {
                "matrix_recovery_key_restore_cleanup_resumed"
            }
            AuditEvent::MatrixRecoveryKeyStartupCleanupRefused { .. } => {
                "matrix_recovery_key_startup_cleanup_refused"
            }
            AuditEvent::MatrixRecoveryKeyPendingPromotionRefused { .. } => {
                "matrix_recovery_key_pending_promotion_refused"
            }
            AuditEvent::MatrixRecoveryKeyRotationMarkerInvalid { .. } => {
                "matrix_recovery_key_rotation_marker_invalid"
            }
            AuditEvent::MatrixVerificationAction { .. } => "matrix_verification_action",
            AuditEvent::MatrixInboundDlqLegacyEnvelopeProcessed { .. } => {
                "matrix_inbound_dlq_legacy_envelope_processed"
            }
            AuditEvent::MatrixInboundDlqRecordDroppedAllowlistDrift { .. } => {
                "matrix_inbound_dlq_record_dropped_allowlist_drift"
            }
            AuditEvent::MatrixInboundDlqQuarantineCapDropped { .. } => {
                "matrix_inbound_dlq_quarantine_cap_dropped"
            }
            AuditEvent::StateDirChmodFailed { .. } => "state_dir_chmod_failed",
            AuditEvent::MatrixStoreRekeyStart { .. } => "matrix_store_rekey_start",
            AuditEvent::MatrixStoreRekeyComplete { .. } => "matrix_store_rekey_complete",
            AuditEvent::MatrixRecoveryKeyRestored { .. } => "matrix_recovery_key_restore",
            AuditEvent::MatrixDlqRekeyBackupCleanupFailed { .. } => {
                "matrix_dlq_rekey_backup_cleanup_failed"
            }
            AuditEvent::MatrixRecoveryKeyRotateRecovered { .. } => {
                "matrix_recovery_key_rotate_recovered"
            }
            AuditEvent::MatrixRecoveryKeyFirstMint { .. } => "matrix_recovery_key_first_mint",
            AuditEvent::MatrixCrossSigningBootstrapped { .. } => {
                "matrix_cross_signing_bootstrapped"
            }
            AuditEvent::MatrixSasUnsafeSkip { .. } => "matrix_sas_unsafe_skip",
            AuditEvent::MatrixRecoveryKeyRestoredAtStartup => {
                "matrix_recovery_key_restored_at_startup"
            }
            AuditEvent::MatrixRecoveryKeyRotated { .. } => "matrix_recovery_key_rotate",
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
    match parse_update_phase_audit_wire_name(&value) {
        Some(phase) => Ok(Some(phase)),
        None => {
            // Forward-compat: an older binary reading an audit log
            // written by a newer daemon (post-migration with an
            // added `UpdatePhase` variant) must NOT hard-error the
            // entire line. The previous `serde::de::Error::custom`
            // failure made `read_tail_entries` drop the whole entry
            // (any other fields, ts, event name, all of it) — silent
            // audit-log corruption on the read side every time a
            // new phase rolled out. Treat unknown phases as `None`
            // and surface a `warn!` so the operator-visible log
            // still shows phase data is missing.
            // Throttle: this deserializer fires once per audit log
            // entry parsed during `read_tail_entries`. If a long-lived
            // audit log contains many `UpdatePhase::FuturePhase`
            // entries (older binary reading a newer log), each call
            // to `recent_audit_events` from a status endpoint would
            // otherwise emit N warns. Cap to one per hour per process.
            if audit_unknown_update_phase_warn_should_fire() {
                tracing::warn!(
                    update_phase = %value,
                    "audit: unrecognized update phase wire name; treating as missing for forward-compat read"
                );
            }
            Ok(None)
        }
    }
}

#[allow(clippy::ptr_arg)]
fn serialize_redacted_update_rollback_backup_path<S>(
    path: &String,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let redacted = Path::new(path)
        .file_name()
        .and_then(|name| name.to_str())
        .map(|name| format!("<update-rollback-backup>/{name}"))
        .unwrap_or_else(|| "<update-rollback-backup>/<unknown>".to_string());
    serializer.serialize_str(&redacted)
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

#[derive(Debug, Clone)]
struct AuditDropSnapshot {
    count: u64,
    first_drop_ts: String,
    last_drop_ts: String,
}

#[derive(Debug, Default)]
struct AuditDropState {
    count: u64,
    first_drop_ts: Option<String>,
    last_drop_ts: Option<String>,
    marker_flush_failure_count: u64,
    terminal_flush_failure: Option<AuditDropSnapshot>,
    /// Snapshot the writer is currently attempting to flush. Set
    /// by `take()` BEFORE the writer can serialize and write to
    /// disk; cleared by `record_marker_flush_success`,
    /// `restore_after_marker_failure`, or
    /// `preserve_terminal_marker_failure`. If the writer panics
    /// between `take()` and the success/failure call (or process is
    /// killed but the in-memory state survives in the tracker's
    /// Arc — e.g., the writer task panicked but the Arc lives on
    /// in the daemon), the next `take()` observes this slot and
    /// recovers the count rather than silently losing it. The
    /// Mutex's poison-on-panic semantics preserve the data; the
    /// existing `unwrap_or_else(|p| p.into_inner())` shape on every
    /// lock acquire here lets us read it back.
    in_flight: Option<AuditDropSnapshot>,
}

#[derive(Debug, Default)]
struct AuditDropTracker {
    state: Mutex<AuditDropState>,
}

impl AuditDropTracker {
    fn record_drop(&self) {
        let now = Utc::now().to_rfc3339();
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if state.count == 0 {
            state.first_drop_ts = Some(now.clone());
        }
        state.count = state.count.saturating_add(1);
        state.last_drop_ts = Some(now);
    }

    fn take(&self) -> Option<AuditDropSnapshot> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        // Pick up any in-flight residue from a prior `take()` whose
        // caller never recorded success or failure (writer task
        // panicked between take and write completion). Without this
        // the count would be silently lost — the prior take()
        // already zeroed state.count.
        let recovered = state.in_flight.take();
        let terminal = state.terminal_flush_failure.take();
        let active = if state.count == 0 {
            None
        } else {
            let snapshot = AuditDropSnapshot {
                count: state.count,
                first_drop_ts: state
                    .first_drop_ts
                    .take()
                    .unwrap_or_else(|| Utc::now().to_rfc3339()),
                last_drop_ts: state
                    .last_drop_ts
                    .take()
                    .unwrap_or_else(|| Utc::now().to_rfc3339()),
            };
            state.count = 0;
            Some(snapshot)
        };
        // Merge in temporal order: recovered (oldest, prior unsealed
        // attempt) → terminal (saved by TerminalDrain) → active
        // (newest, just-captured).
        let merged = combine_drop_snapshots(recovered, terminal, active);
        // Stash the merged snapshot in in_flight so a writer panic
        // between this return and the success/failure call does not
        // lose the count: the next `take()` will recover it.
        state.in_flight = merged.clone();
        merged
    }

    fn restore(&self, snapshot: AuditDropSnapshot) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if state.count == 0 {
            state.count = snapshot.count;
            state.first_drop_ts = Some(snapshot.first_drop_ts);
            state.last_drop_ts = Some(snapshot.last_drop_ts);
            return;
        }
        state.count = state.count.saturating_add(snapshot.count);
        // Use min/max over the existing state and the restored snapshot
        // so the resulting span covers BOTH time ranges regardless of
        // arrival order. Under monotonic clock the snapshot is older
        // than the post-take drops (so min picks the snapshot's first
        // and max picks the state's last), but under NTP backward-step
        // between take() and the failed flush, the snapshot's window
        // can be newer than the post-take drops. The pre-fix code
        // unconditionally overwrote first_drop_ts with the snapshot's
        // first and left last_drop_ts untouched, which under skew
        // produced `first_drop_ts > last_drop_ts` — exactly the
        // monotonic-invariant violation that f445d144 fixed for
        // merge_drop_snapshots. Same shape; same fix.
        state.first_drop_ts = Some(match state.first_drop_ts.take() {
            Some(existing) => std::cmp::min(existing, snapshot.first_drop_ts),
            None => snapshot.first_drop_ts,
        });
        state.last_drop_ts = Some(match state.last_drop_ts.take() {
            Some(existing) => std::cmp::max(existing, snapshot.last_drop_ts),
            None => snapshot.last_drop_ts,
        });
    }

    fn record_marker_flush_success(&self) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.marker_flush_failure_count = 0;
        // The in-flight slot covered the just-written snapshot; the
        // write succeeded so it is safe to clear. Otherwise the
        // next take() would recover this same snapshot and we would
        // double-write the marker.
        state.in_flight = None;
    }

    fn restore_after_marker_failure(&self, snapshot: AuditDropSnapshot) -> u64 {
        self.restore(snapshot);
        // `restore` merged the snapshot back into state.count; clear
        // the in-flight slot to avoid double-counting on next take().
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.in_flight = None;
        state.marker_flush_failure_count = state.marker_flush_failure_count.saturating_add(1);
        state.marker_flush_failure_count
    }

    fn preserve_terminal_marker_failure(&self, snapshot: AuditDropSnapshot) -> u64 {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.terminal_flush_failure = Some(match state.terminal_flush_failure.take() {
            Some(existing) => merge_drop_snapshots(existing, snapshot),
            None => snapshot,
        });
        // Snapshot was moved into terminal_flush_failure; clear
        // in_flight so next take() does not double-count by
        // observing both this slot and terminal_flush_failure.
        state.in_flight = None;
        state.marker_flush_failure_count = state.marker_flush_failure_count.saturating_add(1);
        state.marker_flush_failure_count
    }

    #[cfg(test)]
    fn marker_flush_failure_count_for_test(&self) -> u64 {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .marker_flush_failure_count
    }
}

fn merge_drop_snapshots(first: AuditDropSnapshot, second: AuditDropSnapshot) -> AuditDropSnapshot {
    // RFC 3339 strings produced by `Utc::now().to_rfc3339()` are
    // lexicographically comparable so `min`/`max` on the raw string
    // gives the chronologically earliest / latest timestamp. Without
    // this, a clock-skew event (NTP step, manual adjust) that lets
    // `second.first_drop_ts` precede `first.first_drop_ts` would
    // produce `first_drop_ts > last_drop_ts` — a non-monotonic
    // invariant violation that downstream queries on the audit row
    // can't reason about. Take min/max so the merged span always
    // covers the actual time range of both snapshots regardless of
    // arrival order.
    let first_drop_ts = std::cmp::min(first.first_drop_ts, second.first_drop_ts);
    let last_drop_ts = std::cmp::max(first.last_drop_ts, second.last_drop_ts);
    AuditDropSnapshot {
        count: first.count.saturating_add(second.count),
        first_drop_ts,
        last_drop_ts,
    }
}

fn combine_drop_snapshots(
    recovered: Option<AuditDropSnapshot>,
    terminal: Option<AuditDropSnapshot>,
    active: Option<AuditDropSnapshot>,
) -> Option<AuditDropSnapshot> {
    let mut acc: Option<AuditDropSnapshot> = None;
    for snapshot in [recovered, terminal, active].into_iter().flatten() {
        acc = Some(match acc {
            Some(prev) => merge_drop_snapshots(prev, snapshot),
            None => snapshot,
        });
    }
    acc
}

fn should_log_audit_drop_marker_failure(failure_count: u64) -> bool {
    failure_count == 1 || failure_count.is_power_of_two()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuditDropFlushMode {
    Retryable,
    TerminalDrain,
}

#[derive(Debug, Default)]
struct AuditDiskWriter {
    lock: Mutex<()>,
}

impl AuditDiskWriter {
    fn write_entry(&self, line: &str, log_path: &Path, rotated_path: &Path) -> std::io::Result<()> {
        let _guard = self
            .lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        write_entry_to_disk_strict(line, log_path, rotated_path)
    }

    fn flush_drop_marker(
        &self,
        dropped_events: &AuditDropTracker,
        log_path: &Path,
        rotated_path: &Path,
        mode: AuditDropFlushMode,
    ) {
        let guard = self
            .lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.flush_drop_marker_locked(&guard, dropped_events, log_path, rotated_path, mode);
    }

    /// Channel-closed companion to `flush_drop_marker` for callers
    /// that are running on a Tokio worker thread (currently just
    /// `AuditLog::log`'s channel-closed branch). Uses `try_lock` so a
    /// burst of concurrent async-context callers does not serialize
    /// behind one sync I/O on the std `Mutex`; if the lock is
    /// contended the call returns immediately, leaving the drop
    /// count in the tracker for the in-progress (or next) flush to
    /// pick up. The tracker's `record_drop` already bumped the
    /// counter before we got here, so the eventual flush still
    /// reports cumulative drops; the trade-off is bounded latency on
    /// every closed-channel path rather than worker stalls during
    /// shutdown storms.
    fn try_flush_drop_marker(
        &self,
        dropped_events: &AuditDropTracker,
        log_path: &Path,
        rotated_path: &Path,
        mode: AuditDropFlushMode,
    ) {
        let Ok(guard) = self.lock.try_lock() else {
            return;
        };
        self.flush_drop_marker_locked(&guard, dropped_events, log_path, rotated_path, mode);
    }

    fn flush_drop_marker_locked(
        &self,
        _guard: &MutexGuard<'_, ()>,
        dropped_events: &AuditDropTracker,
        log_path: &Path,
        rotated_path: &Path,
        mode: AuditDropFlushMode,
    ) {
        let Some(snapshot) = dropped_events.take() else {
            return;
        };
        let marker = AuditEntry {
            ts: Utc::now().to_rfc3339(),
            event: "audit_events_dropped".to_string(),
            data: serde_json::to_value(AuditEvent::AuditEventsDropped {
                dropped_count: snapshot.count,
                first_drop_ts: snapshot.first_drop_ts.clone(),
                last_drop_ts: snapshot.last_drop_ts.clone(),
            })
            .unwrap_or(Value::Null),
        };
        // The caller already holds `self.lock`, so go straight to the
        // unsynchronized disk write helper rather than `self.write_entry`
        // (which would attempt to re-acquire the std Mutex and
        // deadlock — std mutexes are not reentrant).
        match serde_json::to_string(&marker)
            .map_err(std::io::Error::other)
            .and_then(|line| write_entry_to_disk_strict(&line, log_path, rotated_path))
        {
            Ok(()) => dropped_events.record_marker_flush_success(),
            Err(e) => {
                let failure_count = match mode {
                    AuditDropFlushMode::Retryable => {
                        dropped_events.restore_after_marker_failure(snapshot)
                    }
                    AuditDropFlushMode::TerminalDrain => {
                        dropped_events.preserve_terminal_marker_failure(snapshot)
                    }
                };
                if should_log_audit_drop_marker_failure(failure_count) {
                    tracing::error!(
                        failure_count,
                        terminal = matches!(mode, AuditDropFlushMode::TerminalDrain),
                        "audit: failed to write queue drop marker: {e}"
                    );
                }
            }
        }
    }
}

/// Global audit log backed by a bounded mpsc channel and a background writer.
pub struct AuditLog {
    tx: mpsc::Sender<AuditEntry>,
    state_dir: PathBuf,
    log_path: PathBuf,
    rotated_path: PathBuf,
    dropped_events: Arc<AuditDropTracker>,
    disk_writer: Arc<AuditDiskWriter>,
}

/// One-per-hour throttle gate for the channel-FULL tracing warn.
/// The `audit_events_dropped` durable marker already records
/// cumulative drop count + first/last timestamps, so the per-call
/// warn is purely operator-facing log signal. Channel-full is the
/// recoverable case (writer is just backpressured); separated from
/// channel-closed so the latter can escalate via a one-shot path.
fn audit_channel_full_warn_should_fire() -> bool {
    static LAST_WARN_AT_SECS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    crate::logging::throttle::throttled_once_per_hour(&LAST_WARN_AT_SECS)
}

/// One-shot escalation gate for the channel-CLOSED tracing event.
/// Channel-closed means the writer task is GONE (panicked or
/// otherwise exited) — strictly more severe than channel-full and
/// sticky for the lifetime of the process. Returns true exactly
/// once per process (the first time it sees the closed condition)
/// so the operator gets a single tracing::error! line at the
/// transition. Subsequent closed-drop events still bump
/// `dropped_events.record_drop()` for the durable marker.
fn audit_channel_closed_escalation_should_fire() -> bool {
    static FIRED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    audit_channel_closed_escalation_should_fire_inner(&FIRED)
}

/// Inner body of `audit_channel_closed_escalation_should_fire`,
/// factored out so the one-shot contract can be unit-tested against
/// an injected `AtomicBool` (the outer fn's static `FIRED` is
/// process-global and would otherwise pollute across tests in the
/// same binary).
fn audit_channel_closed_escalation_should_fire_inner(
    fired: &std::sync::atomic::AtomicBool,
) -> bool {
    !fired.swap(true, std::sync::atomic::Ordering::Relaxed)
}

/// One-per-hour throttle gate for the audit-log forward-compat
/// `unrecognized update phase` warn. Fires from inside the
/// `deserialize_update_phase_option_audit_compat` deserializer; an
/// older binary reading a long-lived audit log with many
/// `UpdatePhase::FuturePhase` entries would otherwise emit N warns
/// per call to `recent_audit_events`.
fn audit_unknown_update_phase_warn_should_fire() -> bool {
    static LAST_WARN_AT_SECS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    crate::logging::throttle::throttled_once_per_hour(&LAST_WARN_AT_SECS)
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

        let dropped_events = Arc::new(AuditDropTracker::default());
        let disk_writer = Arc::new(AuditDiskWriter::default());

        // Spawn background writer.
        tokio::spawn(writer_task(
            rx,
            log_path.clone(),
            rotated_path.clone(),
            dropped_events.clone(),
            disk_writer.clone(),
        ));

        // Spawn an independent watchdog task that periodically
        // flushes the drop marker via a separate clone of the
        // tracker/disk-writer Arcs. If the primary writer task
        // panics or is killed, the watchdog still surfaces
        // accumulated drop counts to disk so operators see the
        // audit subsystem going silent rather than discovering it
        // silently dropped events for minutes. Lock contention with
        // the writer is benign — `try_lock` would be the safer
        // primitive but the watchdog runs every 60s under normal
        // health so blocking on the std `Mutex` here is acceptable.
        tokio::spawn(drop_marker_watchdog_task(
            dropped_events.clone(),
            disk_writer.clone(),
            log_path.clone(),
            rotated_path.clone(),
            AUDIT_DROP_MARKER_WATCHDOG_INTERVAL,
        ));

        let audit_log = AuditLog {
            tx,
            state_dir: state_dir.clone(),
            log_path,
            rotated_path,
            dropped_events,
            disk_writer,
        };

        // OnceLock::set returns Err if already set; we silently ignore.
        let _ = AUDIT_LOG.set(audit_log);
    }

    /// Send an event to the background writer (non-blocking best-effort).
    pub fn log(&self, event: AuditEvent) -> AuditWriteOutcome {
        let entry = AuditEntry {
            ts: Utc::now().to_rfc3339(),
            event: event.event_name().to_string(),
            data: serde_json::to_value(&event).unwrap_or(Value::Null),
        };

        // try_send so callers never block; drop if the channel is full.
        match self.tx.try_send(entry) {
            Ok(()) => AuditWriteOutcome::Enqueued,
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.dropped_events.record_drop();
                // Throttle: under SAS-flood / agent-storm saturation
                // every try_send failure would otherwise emit a warn
                // line. The `audit_events_dropped` marker already
                // preserves cumulative count + first/last timestamps,
                // so per-call warns add log volume without forensic
                // value. Cap to one line per hour per process.
                if audit_channel_full_warn_should_fire() {
                    tracing::warn!("audit: channel full, dropping event");
                }
                AuditWriteOutcome::Dropped(AuditDropReason::ChannelFull)
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                self.dropped_events.record_drop();
                // Channel-closed is strictly more severe than full:
                // the writer task is GONE (panicked or otherwise
                // exited) and the condition is sticky for the lifetime
                // of the process. Escalate to tracing::error! exactly
                // once at the transition so the operator gets a clear
                // "audit subsystem is down" signal not throttled by a
                // recent channel-full warn. Subsequent closed-drop
                // events still bump `dropped_events.record_drop()` so
                // the durable marker count keeps accumulating.
                if audit_channel_closed_escalation_should_fire() {
                    tracing::error!(
                        "audit: channel closed (writer task exited); all subsequent audit \
                         events drop to the durable marker only. Investigate the audit \
                         writer panic; restart of the daemon required to recover."
                    );
                }
                // Channel-full remains nonblocking. Channel-closed is the
                // bounded sync exception because the owned writer is gone;
                // it still uses the same AuditDiskWriter lock so drop-marker
                // writes cannot race a draining writer or rotation.
                //
                // Use the non-blocking `try_flush_drop_marker` variant so
                // a burst of concurrent async-context callers does not
                // serialize behind one sync I/O on the std `Mutex`.
                // The tracker's `record_drop` above already bumped the
                // counter; whoever wins the next uncontended `try_lock`
                // will pick up the cumulative count.
                self.disk_writer.try_flush_drop_marker(
                    &self.dropped_events,
                    &self.log_path,
                    &self.rotated_path,
                    AuditDropFlushMode::Retryable,
                );
                AuditWriteOutcome::Dropped(AuditDropReason::ChannelClosed)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Background writer task
// ---------------------------------------------------------------------------

/// Independent drop-marker flush watchdog.
///
/// Runs on its own Tokio task and periodically calls
/// `flush_drop_marker` on shared `Arc`s of the tracker and disk
/// writer. The primary `writer_task` also flushes periodically
/// (see `AUDIT_DROP_MARKER_FLUSH_INTERVAL`) so under healthy
/// conditions the watchdog observes nothing to flush. The watchdog
/// matters when the writer task panics or otherwise stops — the
/// audit channel goes "closed" or "full" and accumulates drops in
/// the tracker. Without this task those drops would only flush on
/// the next channel-closed `try_flush_drop_marker` invocation,
/// which requires a caller. The watchdog ensures drop markers
/// land on disk on a bounded cadence regardless of caller activity.
async fn drop_marker_watchdog_task(
    dropped_events: Arc<AuditDropTracker>,
    disk_writer: Arc<AuditDiskWriter>,
    log_path: PathBuf,
    rotated_path: PathBuf,
    interval: Duration,
) {
    let mut ticker = tokio::time::interval_at(tokio::time::Instant::now() + interval, interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        ticker.tick().await;
        disk_writer.flush_drop_marker(
            &dropped_events,
            &log_path,
            &rotated_path,
            AuditDropFlushMode::Retryable,
        );
    }
}

async fn writer_task(
    rx: mpsc::Receiver<AuditEntry>,
    log_path: PathBuf,
    rotated_path: PathBuf,
    dropped_events: Arc<AuditDropTracker>,
    disk_writer: Arc<AuditDiskWriter>,
) {
    writer_task_with_drop_flush_interval(
        rx,
        log_path,
        rotated_path,
        dropped_events,
        disk_writer,
        AUDIT_DROP_MARKER_FLUSH_INTERVAL,
    )
    .await;
}

async fn writer_task_with_drop_flush_interval(
    mut rx: mpsc::Receiver<AuditEntry>,
    log_path: PathBuf,
    rotated_path: PathBuf,
    dropped_events: Arc<AuditDropTracker>,
    disk_writer: Arc<AuditDiskWriter>,
    drop_flush_interval: Duration,
) {
    let mut drop_flush_interval = tokio::time::interval_at(
        tokio::time::Instant::now() + drop_flush_interval,
        drop_flush_interval,
    );
    drop_flush_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        let Some(entry) = ({
            tokio::select! {
                entry = rx.recv() => entry,
                _ = drop_flush_interval.tick() => {
                    disk_writer.flush_drop_marker(
                        &dropped_events,
                        &log_path,
                        &rotated_path,
                        AuditDropFlushMode::Retryable,
                    );
                    continue;
                }
            }
        }) else {
            break;
        };
        // Serialize entry.
        let line = match serde_json::to_string(&entry) {
            Ok(s) => s,
            Err(e) => {
                dropped_events.record_drop();
                tracing::error!("audit: failed to serialize entry: {e}");
                disk_writer.flush_drop_marker(
                    &dropped_events,
                    &log_path,
                    &rotated_path,
                    AuditDropFlushMode::Retryable,
                );
                continue;
            }
        };

        if let Err(e) = disk_writer.write_entry(&line, &log_path, &rotated_path) {
            dropped_events.record_drop();
            tracing::error!("audit: failed to write entry: {e}");
            disk_writer.flush_drop_marker(
                &dropped_events,
                &log_path,
                &rotated_path,
                AuditDropFlushMode::Retryable,
            );
            continue;
        }
    }
    disk_writer.flush_drop_marker(
        &dropped_events,
        &log_path,
        &rotated_path,
        AuditDropFlushMode::TerminalDrain,
    );
}

/// Rotate the audit log file if needed, then append a serialized entry line.
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
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        // SAFETY: `geteuid` has no preconditions and does not dereference
        // caller-provided pointers.
        let current_uid = unsafe { libc::geteuid() };
        if metadata.uid() != current_uid {
            return Err(std::io::Error::new(
                ErrorKind::PermissionDenied,
                format!(
                    "audit log path '{}' is not owned by the current user",
                    path.display()
                ),
            ));
        }
        if metadata.nlink() != 1 {
            return Err(std::io::Error::new(
                ErrorKind::InvalidInput,
                format!("audit log path '{}' has hard links", path.display()),
            ));
        }
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
        // O_NOFOLLOW + O_NONBLOCK: the pre-open `symlink_metadata`
        // probe at `reject_existing_audit_reparse_or_symlink` plus
        // the post-open `validate_audit_log_metadata` defend against
        // symlinks/hard-links/wrong-uid. Without O_NONBLOCK a same-
        // uid attacker who swaps the dirent for a FIFO between the
        // pre-check and the open(2) call wins a TOCTOU window where
        // the daemon hangs on `O_WRONLY | O_CREAT | O_APPEND` until
        // the attacker writes EOF. Closing the audit log is high-
        // impact: every state-mutation site that calls
        // `audit_durable_for_state_dir` would block on the audit
        // mutex behind it.
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
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
        let _ = log.log(event);
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
    let disk_writer = AuditDiskWriter::default();
    if let Err(e) = disk_writer.write_entry(
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
) -> std::io::Result<AuditWriteOutcome> {
    if let Some(log) = AUDIT_LOG.get() {
        if audit_state_dirs_match(&log.state_dir, &state_dir)? {
            return Ok(log.log(event));
        }
    }
    audit_blocking(state_dir, event).map(|()| AuditWriteOutcome::Written)
}

/// Synchronously append an audit event to `state_dir`.
///
/// If the process-wide writer owns the same state directory, this writes
/// through that writer's serialized disk primitive instead of racing it.
pub fn audit_durable_for_state_dir(state_dir: PathBuf, event: AuditEvent) -> std::io::Result<()> {
    if let Some(log) = AUDIT_LOG.get() {
        if audit_state_dirs_match(&log.state_dir, &state_dir)? {
            return write_durable_audit_event_with_writer(
                &log.disk_writer,
                &log.log_path,
                &log.rotated_path,
                event,
            );
        }
    }
    audit_blocking(state_dir, event)
}

fn write_durable_audit_event_with_writer(
    disk_writer: &AuditDiskWriter,
    log_path: &Path,
    rotated_path: &Path,
    event: AuditEvent,
) -> std::io::Result<()> {
    let entry = AuditEntry {
        ts: Utc::now().to_rfc3339(),
        event: event.event_name().to_string(),
        data: serde_json::to_value(&event).unwrap_or(Value::Null),
    };
    let line = serde_json::to_string(&entry).map_err(std::io::Error::other)?;
    disk_writer.write_entry(&line, log_path, rotated_path)
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
        // O_NOFOLLOW + O_NONBLOCK: same TOCTOU rationale as
        // `open_audit_log_for_append` above. Rotation/read paths
        // hang otherwise on a planted FIFO at the audit log path.
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
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

    /// Pin the audit-channel-closed escalation one-shot: first call
    /// returns true (the single tracing::error! transition fires);
    /// subsequent calls return false (silent fail-closed, no log
    /// storm). Tests against an injected `AtomicBool` because the
    /// outer fn's static `FIRED` is process-global.
    #[test]
    fn test_audit_channel_closed_escalation_one_shot() {
        let state = std::sync::atomic::AtomicBool::new(false);
        assert!(
            audit_channel_closed_escalation_should_fire_inner(&state),
            "first call must fire (single transition)"
        );
        assert!(
            !audit_channel_closed_escalation_should_fire_inner(&state),
            "second call must suppress"
        );
        assert!(
            !audit_channel_closed_escalation_should_fire_inner(&state),
            "third call must suppress"
        );
    }

    /// Pin that the throttled_once_per_hour helper used by
    /// audit_channel_full_warn_should_fire and
    /// audit_unknown_update_phase_warn_should_fire behaves correctly
    /// at this caller-level binding.
    #[test]
    fn test_throttled_once_per_hour_first_fires_then_suppresses_at_caller_state() {
        let state = std::sync::atomic::AtomicU64::new(0);
        assert!(crate::logging::throttle::throttled_once_per_hour(&state));
        assert!(!crate::logging::throttle::throttled_once_per_hour(&state));
    }

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
            AuditEvent::ManagedPluginManifestRollbackFailed { .. } => {
                "managed_plugin_manifest_rollback_failed"
            }
            AuditEvent::ManagedPluginArtifactRollbackFailed { .. } => {
                "managed_plugin_artifact_rollback_failed"
            }
            AuditEvent::ManagedPluginFirstInstallCleanupFailed { .. } => {
                "managed_plugin_first_install_cleanup_failed"
            }
            AuditEvent::SessionIntegrityViolation { .. } => "session_integrity_violation",
            AuditEvent::UpdateHealthyMarkerFailed { .. } => "update_healthy_marker_failed",
            AuditEvent::UpdateHealthyEvidenceCleanupFailed { .. } => {
                "update_healthy_evidence_cleanup_failed"
            }
            AuditEvent::UpdateRollbackBackupReaped { .. } => "update_rollback_backup_reaped",
            AuditEvent::MatrixRecoveryKeyRestoreCleanupFailed { .. } => {
                "matrix_recovery_key_restore_cleanup_failed"
            }
            AuditEvent::MatrixRecoveryKeyRestoreCleanupAnchored { .. } => {
                "matrix_recovery_key_restore_cleanup_anchored"
            }
            AuditEvent::MatrixRecoveryKeyRestoreCleanupResumed { .. } => {
                "matrix_recovery_key_restore_cleanup_resumed"
            }
            AuditEvent::MatrixRecoveryKeyStartupCleanupRefused { .. } => {
                "matrix_recovery_key_startup_cleanup_refused"
            }
            AuditEvent::MatrixRecoveryKeyPendingPromotionRefused { .. } => {
                "matrix_recovery_key_pending_promotion_refused"
            }
            AuditEvent::MatrixRecoveryKeyRotationMarkerInvalid { .. } => {
                "matrix_recovery_key_rotation_marker_invalid"
            }
            AuditEvent::MatrixVerificationAction { .. } => "matrix_verification_action",
            AuditEvent::MatrixInboundDlqLegacyEnvelopeProcessed { .. } => {
                "matrix_inbound_dlq_legacy_envelope_processed"
            }
            AuditEvent::MatrixInboundDlqRecordDroppedAllowlistDrift { .. } => {
                "matrix_inbound_dlq_record_dropped_allowlist_drift"
            }
            AuditEvent::MatrixInboundDlqQuarantineCapDropped { .. } => {
                "matrix_inbound_dlq_quarantine_cap_dropped"
            }
            AuditEvent::StateDirChmodFailed { .. } => "state_dir_chmod_failed",
            AuditEvent::MatrixStoreRekeyStart { .. } => "matrix_store_rekey_start",
            AuditEvent::MatrixStoreRekeyComplete { .. } => "matrix_store_rekey_complete",
            AuditEvent::MatrixRecoveryKeyRestored { .. } => "matrix_recovery_key_restore",
            AuditEvent::MatrixDlqRekeyBackupCleanupFailed { .. } => {
                "matrix_dlq_rekey_backup_cleanup_failed"
            }
            AuditEvent::MatrixRecoveryKeyRotateRecovered { .. } => {
                "matrix_recovery_key_rotate_recovered"
            }
            AuditEvent::MatrixRecoveryKeyFirstMint { .. } => "matrix_recovery_key_first_mint",
            AuditEvent::MatrixCrossSigningBootstrapped { .. } => {
                "matrix_cross_signing_bootstrapped"
            }
            AuditEvent::MatrixSasUnsafeSkip { .. } => "matrix_sas_unsafe_skip",
            AuditEvent::MatrixRecoveryKeyRestoredAtStartup => {
                "matrix_recovery_key_restored_at_startup"
            }
            AuditEvent::MatrixRecoveryKeyRotated { .. } => "matrix_recovery_key_rotate",
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
            AuditEvent::ManagedPluginManifestRollbackFailed {
                plugin_id: "s".into(),
                error: "restore failed".into(),
            },
            AuditEvent::ManagedPluginArtifactRollbackFailed {
                plugin_id: "s".into(),
                error: "restore failed".into(),
            },
            AuditEvent::ManagedPluginFirstInstallCleanupFailed {
                plugin_id: "s".into(),
                error: "cleanup failed".into(),
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
            AuditEvent::MatrixRecoveryKeyRestoreCleanupAnchored {
                artifacts: vec![
                    MatrixRecoveryKeyArtifactLabel::RotationMarker,
                    MatrixRecoveryKeyArtifactLabel::MintingMarker,
                    MatrixRecoveryKeyArtifactLabel::PendingKey,
                ],
            },
            AuditEvent::MatrixRecoveryKeyRestoreCleanupResumed {
                artifacts: vec![
                    MatrixRecoveryKeyArtifactLabel::RotationMarker,
                    MatrixRecoveryKeyArtifactLabel::PendingKey,
                ],
            },
            AuditEvent::MatrixRecoveryKeyStartupCleanupRefused { artifact_count: 3 },
            AuditEvent::MatrixInboundDlqLegacyEnvelopeProcessed {
                from_version: 1,
                current_version: 2,
                record_count: 3,
                reencoded_count: 1,
                drained_count: 1,
                quarantined_count: 1,
            },
            AuditEvent::MatrixVerificationAction {
                action: MatrixVerificationAuditAction::Confirm,
                flow_id: "mvr_test".into(),
                outcome: MatrixVerificationAuditOutcome::Ok,
                actor: "1.2.3.4".into(),
                remote_ip: "1.2.3.4".into(),
                matches: Some(true),
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
            AuditEvent::AuditEventsDropped {
                dropped_count: 1,
                first_drop_ts: "2026-05-13T00:00:00Z".into(),
                last_drop_ts: "2026-05-13T00:00:00Z".into(),
            },
            AuditEvent::MatrixInboundDlqRecordDroppedAllowlistDrift {
                sender_id: "@alice:example.com".into(),
                event_id: "$evt".into(),
            },
            AuditEvent::MatrixInboundDlqQuarantineCapDropped {
                dropped_lines: 1,
                incoming_bytes: 64,
                existing_quarantine_bytes: 10_485_760,
                cap_bytes: 10_485_760,
            },
            AuditEvent::StateDirChmodFailed {
                subdir: ".".into(),
                intended_mode: 0o700,
                error: "Operation not permitted".into(),
            },
            AuditEvent::MatrixStoreRekeyStart { pid: 42 },
            AuditEvent::MatrixStoreRekeyComplete {
                sqlite_store_count: 3,
                pid: 42,
                recovered: false,
            },
            AuditEvent::MatrixRecoveryKeyRestored { pid: 42 },
            AuditEvent::MatrixDlqRekeyBackupCleanupFailed {
                backup_path: "/state/matrix/inbound-dlq.jsonl.pre-rekey".into(),
                live_path: "/state/matrix/inbound-dlq.jsonl".into(),
                error: "permission denied".into(),
            },
            AuditEvent::MatrixRecoveryKeyRotateRecovered {
                marker_stage: MatrixRecoveryKeyRotationStage::PendingKeyWritten,
                outcome: MatrixRecoveryKeyRotateRecoveredOutcome::PromotedPending,
            },
            AuditEvent::MatrixRecoveryKeyFirstMint {
                outcome: MatrixRecoveryKeyFirstMintOutcome::Minted,
                minted_at: 1_700_000_000_000,
            },
            AuditEvent::MatrixCrossSigningBootstrapped {
                outcome: MatrixCrossSigningBootstrapOutcome::BootstrappedAfterUia,
                user_id: "@alice:example.com".into(),
            },
            AuditEvent::MatrixSasUnsafeSkip {
                flow_id: "mvr_xyz".into(),
                host: "127.0.0.1".into(),
                port: Some(9000),
                pid: 42,
                matches: true,
            },
            AuditEvent::MatrixRecoveryKeyRestoredAtStartup,
            AuditEvent::MatrixRecoveryKeyRotated {
                rotated_at: 1_700_000_000_000,
            },
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
    fn test_event_name_matrix_verification_action() {
        let ev = AuditEvent::MatrixVerificationAction {
            action: MatrixVerificationAuditAction::Confirm,
            flow_id: "mvr_xyz".into(),
            outcome: MatrixVerificationAuditOutcome::Ok,
            actor: "10.0.0.5".into(),
            remote_ip: "10.0.0.5".into(),
            matches: Some(true),
        };
        assert_eq!(ev.event_name(), "matrix_verification_action");
    }

    /// Pins the wire-format contract for `MatrixVerificationAction`:
    /// the snake_case `type` tag, the action / outcome enum renderings,
    /// the attribution fields, and the conditional `matches` field
    /// (Some(true) on confirm-match, Some(false) on confirm-no-match,
    /// absent — not null — on start / accept / cancel). Drift in any of
    /// these breaks downstream audit consumers (operator alerting,
    /// incident response queries grep'ing `audit_event = "matrix_verification_action"`).
    #[test]
    fn test_matrix_verification_action_wire_shape_is_typed_and_attributed() {
        let cases: &[(MatrixVerificationAuditAction, Option<bool>, &str)] = &[
            (MatrixVerificationAuditAction::Start, None, "start"),
            (MatrixVerificationAuditAction::Accept, None, "accept"),
            (
                MatrixVerificationAuditAction::Confirm,
                Some(true),
                "confirm",
            ),
            (
                MatrixVerificationAuditAction::Confirm,
                Some(false),
                "confirm",
            ),
            (MatrixVerificationAuditAction::Cancel, None, "cancel"),
        ];
        for (action, matches, expected_action_str) in cases {
            let ev = AuditEvent::MatrixVerificationAction {
                action: *action,
                flow_id: "mvr_test_flow".into(),
                outcome: MatrixVerificationAuditOutcome::Ok,
                actor: "192.0.2.5".into(),
                remote_ip: "192.0.2.5".into(),
                matches: *matches,
            };
            let json = serde_json::to_value(&ev).unwrap();
            assert_eq!(
                json["type"], "matrix_verification_action",
                "wire type tag must remain snake_case"
            );
            assert_eq!(
                json["action"], *expected_action_str,
                "action enum must serialize as snake_case lower"
            );
            assert_eq!(
                json["outcome"], "ok",
                "outcome enum must serialize as snake_case lower"
            );
            assert_eq!(
                json["flow_id"], "mvr_test_flow",
                "flow_id passes through unchanged"
            );
            assert_eq!(json["actor"], "192.0.2.5", "actor field present");
            assert_eq!(json["remote_ip"], "192.0.2.5", "remote_ip field present");
            match matches {
                Some(expected) => assert_eq!(
                    json["matches"], *expected,
                    "matches must serialize as the expected bool"
                ),
                None => assert!(
                    json.get("matches").is_none(),
                    "matches must be ABSENT (not null) on non-confirm actions; got: {:?}",
                    json.get("matches")
                ),
            }
        }
    }

    /// Pin the dual-form `actor` field: when the caller authenticated
    /// via Tailscale (and did NOT also present a bearer token), the
    /// `principal_aware_control_actor` helper composes
    /// `tailscale:<user>` while `remote_ip` stays the network-layer
    /// IP. External audit consumers documented in docs/security.md
    /// rely on this two-form contract; without a wire-shape pin a
    /// future refactor that changes the separator (e.g. `tailscale=`,
    /// `ts:`, an `actor_kind` sidecar field) would not break any
    /// test even though it would silently break consumer parsers.
    #[test]
    fn test_matrix_verification_action_actor_renders_tailscale_user_form() {
        let ev = AuditEvent::MatrixVerificationAction {
            action: MatrixVerificationAuditAction::Accept,
            flow_id: "mvr_ts_flow".into(),
            outcome: MatrixVerificationAuditOutcome::Ok,
            actor: "tailscale:alice@tailnet.example".into(),
            remote_ip: "127.0.0.1".into(),
            matches: None,
        };
        let json = serde_json::to_value(&ev).unwrap();
        assert_eq!(
            json["actor"], "tailscale:alice@tailnet.example",
            "tailscale-attributed actor must render verbatim with the `tailscale:` prefix; \
             external consumers (see docs/security.md) parse on the first `:`"
        );
        assert_eq!(
            json["remote_ip"], "127.0.0.1",
            "remote_ip stays the network-layer attribution even when actor is tailscale-prefixed"
        );
    }

    /// Outcome::Err must render as "err" (not "error") to keep the
    /// wire shape narrow and avoid drift from a renamed variant.
    #[test]
    fn test_matrix_verification_action_outcome_err_renders_as_err() {
        let ev = AuditEvent::MatrixVerificationAction {
            action: MatrixVerificationAuditAction::Confirm,
            flow_id: "mvr_test".into(),
            outcome: MatrixVerificationAuditOutcome::Err,
            actor: "unknown".into(),
            remote_ip: "unknown".into(),
            matches: Some(false),
        };
        let json = serde_json::to_value(&ev).unwrap();
        assert_eq!(json["outcome"], "err");
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
    fn test_update_rollback_backup_reaped_path_is_redacted() {
        let ev = AuditEvent::UpdateRollbackBackupReaped {
            path: "/private/state/bin/cara.bak".into(),
        };

        let value = serde_json::to_value(&ev).unwrap();

        assert_eq!(
            value["path"],
            serde_json::json!("<update-rollback-backup>/cara.bak")
        );
        let serialized = serde_json::to_string(&value).unwrap();
        assert!(!serialized.contains("/private/state/bin"));
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

    #[cfg(unix)]
    #[test]
    fn test_audit_blocking_rejects_hardlinked_active_log() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join(AUDIT_FILE_NAME);
        let hardlink_path = dir.path().join("audit-hardlink.jsonl");
        fs::write(&log_path, "").unwrap();
        fs::hard_link(&log_path, hardlink_path).unwrap();

        let err = audit_blocking(
            dir.path().to_path_buf(),
            AuditEvent::GatewayConnected {
                gateway_id: "g1".into(),
            },
        )
        .expect_err("audit writer must reject hardlinked active log paths");

        assert!(err.to_string().contains("hard links"));
    }

    #[tokio::test]
    async fn test_writer_task_does_not_flush_drop_marker_after_clean_success() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join(AUDIT_FILE_NAME);
        let rotated_path = dir.path().join(AUDIT_ROTATED_NAME);
        let dropped = Arc::new(AuditDropTracker::default());
        dropped.record_drop();
        dropped.record_drop();
        dropped.record_drop();
        let (tx, rx) = mpsc::channel::<AuditEntry>(1);
        tokio::spawn(writer_task(
            rx,
            log_path.clone(),
            rotated_path,
            dropped,
            Arc::new(AuditDiskWriter::default()),
        ));

        let entry = AuditEntry {
            ts: Utc::now().to_rfc3339(),
            event: "gateway_connected".into(),
            data: serde_json::json!({"type":"gateway_connected","gateway_id":"g1"}),
        };
        tx.send(entry).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let content = fs::read_to_string(&log_path).unwrap();
        assert!(content.contains("gateway_connected"));
        assert!(
            !content.contains("audit_events_dropped"),
            "successful writes must not flush drop markers until failure or shutdown"
        );
    }

    #[tokio::test]
    async fn test_writer_task_periodically_flushes_dropped_marker() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join(AUDIT_FILE_NAME);
        let rotated_path = dir.path().join(AUDIT_ROTATED_NAME);
        let dropped = Arc::new(AuditDropTracker::default());
        dropped.record_drop();
        dropped.record_drop();
        let (tx, rx) = mpsc::channel::<AuditEntry>(1);
        let writer = tokio::spawn(writer_task_with_drop_flush_interval(
            rx,
            log_path.clone(),
            rotated_path,
            dropped,
            Arc::new(AuditDiskWriter::default()),
            Duration::from_millis(10),
        ));

        let mut content = String::new();
        for _ in 0..50 {
            if let Ok(value) = fs::read_to_string(&log_path) {
                content = value;
                if content.contains("audit_events_dropped") {
                    break;
                }
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        drop(tx);
        writer.await.expect("writer task joins");

        assert!(content.contains("audit_events_dropped"));
        assert!(content.contains("\"dropped_count\":2"));
    }

    #[test]
    fn test_audit_drop_marker_failure_is_rate_limited_and_retryable() {
        assert!(should_log_audit_drop_marker_failure(1));
        assert!(should_log_audit_drop_marker_failure(2));
        assert!(!should_log_audit_drop_marker_failure(3));
        assert!(should_log_audit_drop_marker_failure(4));

        let dir = TempDir::new().unwrap();
        let missing_parent_log = dir.path().join("missing").join(AUDIT_FILE_NAME);
        let missing_parent_rotated = dir.path().join("missing").join(AUDIT_ROTATED_NAME);
        let dropped = AuditDropTracker::default();
        let writer = AuditDiskWriter::default();
        dropped.record_drop();

        writer.flush_drop_marker(
            &dropped,
            &missing_parent_log,
            &missing_parent_rotated,
            AuditDropFlushMode::Retryable,
        );
        writer.flush_drop_marker(
            &dropped,
            &missing_parent_log,
            &missing_parent_rotated,
            AuditDropFlushMode::Retryable,
        );

        assert_eq!(dropped.marker_flush_failure_count_for_test(), 2);
        let snapshot = dropped.take().expect("retryable failure preserves drops");
        assert_eq!(snapshot.count, 1);
    }

    #[test]
    fn test_terminal_drop_marker_failure_preserves_snapshot_for_future_flush() {
        let dir = TempDir::new().unwrap();
        let missing_parent_log = dir.path().join("missing").join(AUDIT_FILE_NAME);
        let missing_parent_rotated = dir.path().join("missing").join(AUDIT_ROTATED_NAME);
        let dropped = AuditDropTracker::default();
        let writer = AuditDiskWriter::default();
        dropped.record_drop();

        writer.flush_drop_marker(
            &dropped,
            &missing_parent_log,
            &missing_parent_rotated,
            AuditDropFlushMode::TerminalDrain,
        );

        assert_eq!(dropped.marker_flush_failure_count_for_test(), 1);
        let snapshot = dropped
            .take()
            .expect("terminal flush failure must leave explicit drop evidence");
        assert_eq!(snapshot.count, 1);
    }

    #[tokio::test]
    async fn test_writer_task_flushes_dropped_marker_on_shutdown() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join(AUDIT_FILE_NAME);
        let rotated_path = dir.path().join(AUDIT_ROTATED_NAME);
        let dropped = Arc::new(AuditDropTracker::default());
        dropped.record_drop();
        dropped.record_drop();
        dropped.record_drop();
        let (tx, rx) = mpsc::channel::<AuditEntry>(1);
        let writer = tokio::spawn(writer_task(
            rx,
            log_path.clone(),
            rotated_path,
            dropped,
            Arc::new(AuditDiskWriter::default()),
        ));
        drop(tx);
        writer.await.expect("writer task joins");

        let content = fs::read_to_string(&log_path).unwrap();
        assert!(content.contains("audit_events_dropped"));
        assert!(content.contains("\"dropped_count\":3"));
        assert!(content.contains("\"first_drop_ts\""));
        assert!(content.contains("\"last_drop_ts\""));
    }

    #[test]
    fn test_audit_log_drop_path_reports_drop_without_sync_write() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join(AUDIT_FILE_NAME);
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
            rotated_path: dir.path().join(AUDIT_ROTATED_NAME),
            dropped_events: Arc::new(AuditDropTracker::default()),
            disk_writer: Arc::new(AuditDiskWriter::default()),
        };

        let outcome = log.log(AuditEvent::GatewayConnected {
            gateway_id: "dropped".into(),
        });

        assert_eq!(
            outcome,
            AuditWriteOutcome::Dropped(AuditDropReason::ChannelFull)
        );
        assert!(
            !log_path.exists(),
            "AuditLog::log must not synchronously create or fsync drop markers"
        );
    }

    /// Regression for R58 H-A1: the audit drop-marker watchdog
    /// task must flush accumulated drops to disk even when the
    /// primary writer task is dead. The audit channel saturates
    /// (full/closed) with no draining writer; without the
    /// watchdog, drop markers only flush on caller-driven
    /// `try_flush_drop_marker` invocations from the
    /// channel-closed path — which can be silent for arbitrarily
    /// long if callers stop hitting that path.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_drop_marker_watchdog_flushes_when_writer_is_absent() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join(AUDIT_FILE_NAME);
        let rotated_path = dir.path().join(AUDIT_ROTATED_NAME);
        let dropped_events = Arc::new(AuditDropTracker::default());
        let disk_writer = Arc::new(AuditDiskWriter::default());

        // Accumulate drops without spawning a writer_task —
        // simulates the writer task being dead after a panic.
        dropped_events.record_drop();
        dropped_events.record_drop();
        dropped_events.record_drop();

        // Use a 25ms watchdog interval so the test stays under a
        // few hundred ms.
        let watchdog = tokio::spawn(drop_marker_watchdog_task(
            dropped_events.clone(),
            disk_writer.clone(),
            log_path.clone(),
            rotated_path.clone(),
            Duration::from_millis(25),
        ));

        // Poll for the marker file every 25ms with a generous
        // upper bound — multi_thread runtime + real clock means
        // we can't deterministically pin the watchdog's first
        // tick to a single yield point.
        let mut content = None;
        for _ in 0..40 {
            tokio::time::sleep(Duration::from_millis(25)).await;
            if let Ok(text) = std::fs::read_to_string(&log_path) {
                if text.contains("audit_events_dropped") {
                    content = Some(text);
                    break;
                }
            }
        }
        watchdog.abort();
        let _ = watchdog.await;

        let content =
            content.expect("watchdog must surface drop markers to disk without a writer task");
        assert!(
            content.contains("\"dropped_count\":3"),
            "watchdog marker must report cumulative drop count: {content}"
        );
    }

    /// Regression for R58 H-A2: when `take()` zeroes state.count
    /// and returns a snapshot, the snapshot is also stored in
    /// `in_flight` so a writer panic between take and write
    /// completion does not silently lose the drop count. A
    /// subsequent take() observes the in-flight slot and recovers
    /// the count.
    #[test]
    fn test_audit_drop_tracker_take_preserves_snapshot_for_crash_recovery() {
        let tracker = AuditDropTracker::default();
        tracker.record_drop();
        tracker.record_drop();
        tracker.record_drop();

        // First take(): captures three drops, zeroes state.count,
        // and stashes the snapshot in `in_flight`.
        let first = tracker.take().expect("first take must return a snapshot");
        assert_eq!(first.count, 3);

        // Simulate a writer panic between take() and the
        // success/failure call: no notification reaches the tracker.
        // The next take() must recover the in-flight count rather
        // than returning None or silently losing it.
        let recovered = tracker
            .take()
            .expect("second take must recover the in-flight snapshot");
        assert_eq!(
            recovered.count, 3,
            "in_flight slot must preserve the count across an interrupted flush attempt"
        );
        assert_eq!(recovered.first_drop_ts, first.first_drop_ts);
        assert_eq!(recovered.last_drop_ts, first.last_drop_ts);
    }

    #[test]
    fn test_audit_drop_tracker_take_merges_inflight_with_new_drops() {
        let tracker = AuditDropTracker::default();
        tracker.record_drop();
        let first = tracker.take().expect("first take");
        assert_eq!(first.count, 1);

        // After the first take(), in_flight=Some(first). Two more
        // drops arrive. The next take() merges them.
        tracker.record_drop();
        tracker.record_drop();
        let merged = tracker.take().expect("merged take");
        assert_eq!(
            merged.count, 3,
            "take() must merge in_flight (count=1) with newly accumulated drops (count=2)"
        );
    }

    #[test]
    fn test_audit_drop_tracker_success_clears_inflight() {
        let tracker = AuditDropTracker::default();
        tracker.record_drop();
        let _snapshot = tracker.take();
        tracker.record_marker_flush_success();
        // After success, in_flight is cleared. A subsequent take()
        // with no new drops returns None.
        assert!(
            tracker.take().is_none(),
            "after success the in-flight slot must be cleared so no spurious recovery happens"
        );
    }

    #[test]
    fn test_audit_drop_tracker_failure_clears_inflight_no_double_count() {
        let tracker = AuditDropTracker::default();
        tracker.record_drop();
        tracker.record_drop();
        let snapshot = tracker.take().expect("first take");
        assert_eq!(snapshot.count, 2);

        // On failure, restore_after_marker_failure merges the
        // snapshot back into state.count and clears in_flight. The
        // next take() must NOT double-count by observing both
        // in_flight AND state.count.
        let _failure_count = tracker.restore_after_marker_failure(snapshot);
        let recovered = tracker.take().expect("post-failure take");
        assert_eq!(
            recovered.count, 2,
            "restore + take must yield the original count, not double it"
        );
    }

    #[test]
    fn test_audit_log_channel_closed_flushes_drop_marker_once() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join(AUDIT_FILE_NAME);
        let rotated_path = dir.path().join(AUDIT_ROTATED_NAME);
        let (tx, rx) = mpsc::channel::<AuditEntry>(1);
        drop(rx);
        let log = AuditLog {
            tx,
            state_dir: dir.path().to_path_buf(),
            log_path: log_path.clone(),
            rotated_path,
            dropped_events: Arc::new(AuditDropTracker::default()),
            disk_writer: Arc::new(AuditDiskWriter::default()),
        };

        let outcome = log.log(AuditEvent::GatewayConnected {
            gateway_id: "closed".into(),
        });

        assert_eq!(
            outcome,
            AuditWriteOutcome::Dropped(AuditDropReason::ChannelClosed)
        );
        let content = fs::read_to_string(&log_path).expect("closed channel must flush marker");
        assert!(content.contains("audit_events_dropped"));
        assert!(content.contains("\"dropped_count\":1"));
        assert!(content.contains("\"first_drop_ts\""));
        assert!(content.contains("\"last_drop_ts\""));
    }

    #[test]
    fn test_audit_log_channel_closed_flush_defers_when_disk_writer_lock_is_held() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join(AUDIT_FILE_NAME);
        let rotated_path = dir.path().join(AUDIT_ROTATED_NAME);
        let disk_writer = Arc::new(AuditDiskWriter::default());
        let dropped_events = Arc::new(AuditDropTracker::default());
        let guard = disk_writer
            .lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let (tx, rx) = mpsc::channel::<AuditEntry>(1);
        drop(rx);
        let log = AuditLog {
            tx,
            state_dir: dir.path().to_path_buf(),
            log_path: log_path.clone(),
            rotated_path: rotated_path.clone(),
            dropped_events: dropped_events.clone(),
            disk_writer: disk_writer.clone(),
        };

        // Channel-closed log() must NOT block on a held disk-writer
        // lock. Previously the fallback used `Mutex::lock()` and
        // serialized async-context callers behind one sync I/O on
        // shutdown bursts; the new design uses `try_lock` and defers
        // the marker write to whichever caller holds the lock. The
        // drop counter is preserved in the tracker so no event is
        // silently lost.
        let started = std::time::Instant::now();
        let outcome = log.log(AuditEvent::GatewayConnected {
            gateway_id: "closed".into(),
        });
        let elapsed = started.elapsed();
        assert!(
            elapsed < std::time::Duration::from_millis(50),
            "channel-closed log() must not block on the held disk-writer lock; took {elapsed:?}"
        );
        assert_eq!(
            outcome,
            AuditWriteOutcome::Dropped(AuditDropReason::ChannelClosed)
        );
        assert!(
            !log_path.exists() || fs::read_to_string(&log_path).unwrap_or_default().is_empty(),
            "deferred flush must not write the marker while another caller holds the lock"
        );

        // Releasing the lock + running a flush picks up the deferred
        // drop count — the tracker preserves the cumulative state
        // across the try_lock defer.
        drop(guard);
        disk_writer.flush_drop_marker(
            &dropped_events,
            &log_path,
            &rotated_path,
            AuditDropFlushMode::Retryable,
        );
        let content = fs::read_to_string(&log_path)
            .expect("post-release flush must write the deferred drop marker");
        assert!(content.contains("audit_events_dropped"));
    }

    /// When the disk-writer lock is uncontended, `try_flush_drop_marker`
    /// behaves like the blocking `flush_drop_marker` — it grabs the
    /// lock and writes the marker immediately. This pins the
    /// "happy-path uncontended is no different from blocking flush"
    /// invariant so a future refactor doesn't accidentally make the
    /// defer-on-contention path the only one that ever writes.
    #[test]
    fn test_try_flush_drop_marker_writes_when_uncontended() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join(AUDIT_FILE_NAME);
        let rotated_path = dir.path().join(AUDIT_ROTATED_NAME);
        let disk_writer = AuditDiskWriter::default();
        let dropped_events = AuditDropTracker::default();
        dropped_events.record_drop();

        disk_writer.try_flush_drop_marker(
            &dropped_events,
            &log_path,
            &rotated_path,
            AuditDropFlushMode::Retryable,
        );

        let content = fs::read_to_string(&log_path)
            .expect("uncontended try_flush must write the marker synchronously");
        assert!(content.contains("audit_events_dropped"));
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
            Arc::new(AuditDropTracker::default()),
            Arc::new(AuditDiskWriter::default()),
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
            Arc::new(AuditDropTracker::default()),
            Arc::new(AuditDiskWriter::default()),
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
            Arc::new(AuditDropTracker::default()),
            Arc::new(AuditDiskWriter::default()),
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

    /// Regression for R58 M-A7: `merge_drop_snapshots` must keep
    /// the earliest first_drop_ts and the latest last_drop_ts even
    /// when arrival order is reversed by clock skew (NTP step,
    /// manual time adjust). The pre-fix implementation always took
    /// `first.first_drop_ts` and `second.last_drop_ts`, producing
    /// `first_drop_ts > last_drop_ts` when the "second" snapshot
    /// covered an earlier window.
    #[test]
    fn test_merge_drop_snapshots_preserves_monotonic_invariant_under_clock_skew() {
        let earlier_first = "2020-01-01T00:00:00+00:00".to_string();
        let earlier_last = "2020-01-01T00:01:00+00:00".to_string();
        let later_first = "2025-06-01T00:00:00+00:00".to_string();
        let later_last = "2025-06-01T00:01:00+00:00".to_string();

        // first = newer window, second = older window (clock skew
        // simulation). Pre-fix merge would emit
        // first_drop_ts=later_first and last_drop_ts=earlier_last,
        // making first > last. Post-fix takes min/max.
        let merged = merge_drop_snapshots(
            AuditDropSnapshot {
                count: 3,
                first_drop_ts: later_first.clone(),
                last_drop_ts: later_last.clone(),
            },
            AuditDropSnapshot {
                count: 5,
                first_drop_ts: earlier_first.clone(),
                last_drop_ts: earlier_last.clone(),
            },
        );

        assert_eq!(merged.count, 8);
        assert_eq!(
            merged.first_drop_ts, earlier_first,
            "merged first_drop_ts must be the chronologically earliest"
        );
        assert_eq!(
            merged.last_drop_ts, later_last,
            "merged last_drop_ts must be the chronologically latest"
        );
        assert!(
            merged.first_drop_ts <= merged.last_drop_ts,
            "merged span must satisfy first <= last invariant regardless of arrival order"
        );
    }

    /// Regression: `AuditDropTracker::restore` must apply the same
    /// min/max monotonic-invariant defense that `merge_drop_snapshots`
    /// has. Before the fix, `restore` unconditionally overwrote
    /// `first_drop_ts` with `snapshot.first_drop_ts` and never touched
    /// `last_drop_ts`, so under NTP backward-step between `take()` and
    /// the failed flush the result violated `first <= last` — same
    /// shape as the merge_drop_snapshots bug fixed by f445d144.
    #[test]
    fn test_audit_drop_tracker_restore_preserves_monotonic_invariant_under_clock_skew() {
        let earlier_first = "2020-01-01T00:00:00+00:00".to_string();
        let earlier_last = "2020-01-01T00:01:00+00:00".to_string();
        let later_first = "2025-06-01T00:00:00+00:00".to_string();
        let later_last = "2025-06-01T00:01:00+00:00".to_string();

        let tracker = AuditDropTracker::default();
        // Override state directly via the private Mutex (no-arg
        // record_drop wouldn't let us pin specific timestamps).
        // Simulate state holding the OLDER window — i.e. the writer
        // already accumulated drops at timestamps earlier than the
        // snapshot we're about to restore (clock backward-step).
        {
            let mut s: std::sync::MutexGuard<'_, AuditDropState> =
                tracker.state.lock().unwrap_or_else(|p| p.into_inner());
            s.count = 3;
            s.first_drop_ts = Some(earlier_first.clone());
            s.last_drop_ts = Some(earlier_last.clone());
        }
        // Restore a NEWER snapshot — pre-fix would produce
        // first=later_first, last=earlier_last → first > last.
        tracker.restore(AuditDropSnapshot {
            count: 5,
            first_drop_ts: later_first.clone(),
            last_drop_ts: later_last.clone(),
        });
        let state: std::sync::MutexGuard<'_, AuditDropState> =
            tracker.state.lock().unwrap_or_else(|p| p.into_inner());
        assert_eq!(state.count, 8);
        assert_eq!(
            state.first_drop_ts.as_deref(),
            Some(earlier_first.as_str()),
            "restore must keep the chronologically earliest first_drop_ts"
        );
        assert_eq!(
            state.last_drop_ts.as_deref(),
            Some(later_last.as_str()),
            "restore must keep the chronologically latest last_drop_ts"
        );
        assert!(
            state.first_drop_ts.as_deref() <= state.last_drop_ts.as_deref(),
            "restored span must satisfy first <= last regardless of clock skew direction"
        );
    }

    /// Regression for R58 M-A3: an older binary reading an audit
    /// log written by a newer daemon (with an additional
    /// `UpdatePhase` variant) must NOT hard-error the entire line.
    /// The pre-fix code returned `serde::de::Error::custom` on any
    /// unrecognized phase, causing `read_tail_entries` to drop the
    /// whole entry — silent audit-log corruption on each new phase
    /// rollout. The forward-compat path now returns `None` and
    /// surfaces the value via `tracing::warn!`.
    #[test]
    fn test_deserialize_update_phase_unknown_value_is_treated_as_missing() {
        let line = r#"{
            "type": "update_healthy_marker_failed",
            "phase": "FuturePhase",
            "retryable": true,
            "evidence_recorded": true
        }"#;
        let event: AuditEvent = serde_json::from_str(line)
            .expect("unknown UpdatePhase must NOT hard-error the audit-log read path");
        match event {
            AuditEvent::UpdateHealthyMarkerFailed { phase, .. } => assert!(
                phase.is_none(),
                "unrecognized phase wire name must deserialize as `None` for forward-compat"
            ),
            other => panic!("expected UpdateHealthyMarkerFailed variant, got {other:?}"),
        }
    }

    #[test]
    fn test_deserialize_update_phase_known_value_round_trips() {
        let line = r#"{
            "type": "update_healthy_marker_failed",
            "phase": "applying",
            "retryable": true,
            "evidence_recorded": true
        }"#;
        let event: AuditEvent =
            serde_json::from_str(line).expect("known phase must deserialize cleanly");
        match event {
            AuditEvent::UpdateHealthyMarkerFailed { phase, .. } => {
                assert_eq!(phase, Some(crate::update::UpdatePhase::Applying));
            }
            other => panic!("expected UpdateHealthyMarkerFailed variant, got {other:?}"),
        }
    }
}
