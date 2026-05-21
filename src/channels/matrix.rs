//! Native Matrix / Element channel runtime.
//!
//! Matrix is stateful: the runtime owns the SDK client, encrypted store state,
//! sync loop, invite policy, and the bounded outbound actor used by the
//! synchronous channel plugin contract.

use std::borrow::Cow;
use std::collections::BTreeSet;
use std::fmt;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicBool, AtomicI64, Ordering},
    mpsc as std_mpsc, Arc,
};
use std::time::Duration;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hkdf::Hkdf;
use matrix_sdk::config::{RequestConfig, SyncSettings};
use matrix_sdk::ruma::events::{
    room::message::{MessageType, OriginalSyncRoomMessageEvent, RoomMessageEventContent},
    AnyToDeviceEvent,
};
use matrix_sdk::ruma::{OwnedDeviceId, OwnedUserId, RoomId};
use matrix_sdk::sync::SyncResponse;
use matrix_sdk::{Client, Room, RoomState, SqliteStoreConfig};
use parking_lot::{Mutex as ParkingMutex, RwLock};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::sync::{mpsc, oneshot, watch, Notify};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

mod inbound_dlq;
mod recovery;
mod verification;
pub(crate) use inbound_dlq::{
    matrix_inbound_dlq_path, recover_matrix_inbound_dlq_rekey, restore_matrix_inbound_dlq_backup,
    rotate_matrix_inbound_dlq_for_rekey, MatrixDlqKeys, MatrixDlqRekeyOutcome,
};
pub(crate) use recovery::{
    matrix_recovery_cleanup_journal_path, matrix_recovery_key_path,
    matrix_recovery_minting_marker_path, matrix_recovery_pending_key_path,
    matrix_recovery_rotating_marker_path, rotate_matrix_recovery_key_for_cli,
    MatrixRecoveryCleanupArtifactResult, MatrixRecoveryCleanupArtifactResultState,
    MatrixRecoveryCleanupArtifactRole, MatrixRecoveryCleanupJournal,
    MatrixRecoveryCleanupJournalArtifact, MatrixRecoveryCleanupJournalPhase,
    MatrixRecoveryKeyRotateOutcome, MATRIX_RECOVERY_CLEANUP_JOURNAL_VERSION,
    MATRIX_RECOVERY_KEY_FILE_MAX_BYTES,
};
pub use verification::{
    MatrixSasEmoji, MatrixSasInfo, MatrixVerificationInfo, MatrixVerificationState,
};

use crate::channels::{ChannelMetadata, ChannelRegistry, ChannelStatus};
use crate::plugins::{
    BindingError, ChannelCapabilities, ChannelInfo as PluginChannelInfo, ChannelPluginInstance,
    ChatType, DeliveryResult, OutboundContext, Retryability,
};
use crate::server::ws::WsServerState;

pub const MATRIX_CHANNEL_ID: &str = "matrix";
pub const MATRIX_CHANNEL_NAME: &str = "Matrix";
/// Outbound-pipeline retry count for Matrix delivery. Larger than the
/// generic-channel default (1) because Matrix transient failures
/// (sync timeouts, room-state propagation, encryption-handshake
/// re-keys) typically clear within seconds; the cost of an extra
/// retry is small compared to losing a message.
pub const MATRIX_OUTBOUND_RETRIES: u32 = 3;
/// Cap on the number of unsupported-room IDs surfaced via
/// `MatrixStatusMetadata.unsupported_rooms`. Anything above this is
/// counted in `unsupported_room_count` but not enumerated in the
/// status payload, so a 10k-room bot doesn't inflate the WS /
/// `/control/channels` payload to multi-MB.
const MATRIX_UNSUPPORTED_ROOMS_LIMIT: usize = 100;
/// Cap on `MatrixStatusMetadata.inbound_dlq_lost_event_ids`. Bounded so a
/// catastrophic phase-3 cleanup failure (every record un-persistable)
/// doesn't inflate the channel-status payload. Operators chasing a
/// larger leak should grep journal for `lost_event_ids` directly; this
/// list is the "recent and small enough to glance at" surface.
const MATRIX_INBOUND_DLQ_LOST_IDS_CAP: usize = 32;
pub const MATRIX_STORE_INFO: &[u8] = b"carapace-matrix-store-v1";
const MATRIX_OUTBOUND_QUEUE_CAPACITY: usize = 128;
/// Maximum inbound Matrix message body size (bytes) before the
/// runtime drops the event with a warn. A peer in any joined room
/// can otherwise send a 100 MB body, which gets cloned through the
/// session log, the agent prompt, and (on dispatch failure) the
/// DLQ record. 64 KiB is well above any sane chat usage and below
/// the homeserver's typical event-size limit.
const MATRIX_INBOUND_BODY_MAX_BYTES: usize = 64 * 1024;
/// Per-field length caps applied at config-resolve time. Operator
/// config is largely operator-trusted, but config files crossing
/// into security-relevant code (allowlist matching, store-key
/// derivation, allocator pressure on every error string carrying
/// `homeserver_url`) should validate at the parse boundary. A
/// poisoned shared-Git-repo config could otherwise slip a
/// 50 000-entry allowlist or a multi-megabyte URL through resolve.
const MATRIX_HOMESERVER_URL_MAX_BYTES: usize = 2048;
const MATRIX_USER_ID_MAX_BYTES: usize = 256;
const MATRIX_DEVICE_ID_MAX_BYTES: usize = 255;
const MATRIX_ALLOWLIST_ENTRY_MAX_BYTES: usize = 256;
const MATRIX_ALLOWLIST_MAX_ENTRIES: usize = 1024;
/// Cap on lines in `inbound_dlq.jsonl`. Without this, a sustained
/// dispatch-failure scenario (broken plugin runtime, agent crash on
/// every inbound) lets adversary-controlled inbound rate inflate
/// the file unboundedly. Each replay tick reads the full file into
/// memory and HKDF-derives a key per record; a 100k-record DLQ =
/// hundreds of MB allocation + 100k key derivations + multi-second
/// lock window blocking live appends. 10k records is well above
/// the legitimate "large outage" recovery scenario but bounds the
/// worst-case replay cost.
const MATRIX_INBOUND_DLQ_MAX_RECORDS: usize = 10_000;
/// Cap on the number of concurrently-in-flight Matrix sends. The mpsc
/// queue at `MATRIX_OUTBOUND_QUEUE_CAPACITY` only bounds *queued*
/// commands; without an in-flight cap, the actor would drain a burst of
/// 128 sends into a JoinSet that grows unbounded as the queue refills.
/// Backpressure must be owned at the send boundary: when the JoinSet is
/// at capacity, callers see `BindingError::CallError` so the delivery
/// pipeline retries via its own logic instead of silently piling up
/// concurrent HTTP requests against the homeserver.
const MATRIX_MAX_IN_FLIGHT_SENDS: usize = 16;
/// Cap on devices retained in `MatrixRuntimeState::devices`. The
/// homeserver decides what shows up in `get_user_devices`; without a
/// cap, a hostile homeserver could synthesize a device list large
/// enough to inflate every status broadcast and SAS-prompt
/// enumeration. A real Matrix account rarely exceeds a dozen devices.
const MATRIX_DEVICE_LIST_MAX: usize = 256;
/// Cap on concurrently-tracked verification flows. The peer side
/// (or any allowlisted Matrix user) decides when to initiate a
/// flow; without a cap, a hostile peer can spam fresh
/// `protocol_flow_id`s at line rate. Each flow is ~256 bytes; at
/// 100/s × 1800s (the 30-min TTL) = 180k records ~46MB before the
/// existing TTL pruner trims them. The cap clamps memory regardless
/// of peer behavior — when exceeded, the oldest non-terminal record
/// is dropped to make room.
const MATRIX_VERIFICATION_RECORDS_MAX: usize = 256;
const MATRIX_SYNC_TIMEOUT: Duration = Duration::from_secs(30);
/// Tokio-side watchdog on `sync_once`. The `MATRIX_SYNC_TIMEOUT`
/// above is the Matrix long-poll timeout (server-side: "wait at most
/// 30s for events"), NOT a Tokio cancellation deadline. A wedged
/// SDK future (TLS handshake hang, deadlocked event-handler future)
/// would otherwise stall retry/backoff/give-up indefinitely. Cap at
/// twice the long-poll timeout plus a generous I/O budget so the
/// watchdog only fires on genuine hangs, not on slow-but-progressing
/// syncs.
const MATRIX_SYNC_WATCHDOG: Duration = Duration::from_secs(120);
const MATRIX_SEND_TIMEOUT: Duration = Duration::from_secs(30);
const MATRIX_OUTBOUND_REPLY_TIMEOUT: Duration = Duration::from_secs(35);
const MATRIX_OUTBOUND_ENQUEUE_RETRY_AFTER: Duration = Duration::from_secs(5);
const MATRIX_SEND_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);
const MATRIX_RUNTIME_OPERATION_TIMEOUT: Duration = Duration::from_secs(30);
/// Cap on how long a single verification command (Accept/Confirm/Cancel
/// or StartVerification) is allowed to block the runtime actor before we
/// surface a typed timeout to the caller and return control to the loop.
/// matrix-sdk verification calls go to the homeserver and back, and a
/// stuck SDK request would otherwise freeze SendText, sync, and shutdown
/// because the actor is single-threaded.
const MATRIX_VERIFICATION_COMMAND_TIMEOUT: Duration = Duration::from_secs(30);
const MATRIX_VERIFICATION_CALLER_TIMEOUT: Duration = Duration::from_secs(70);
const MATRIX_VERIFICATION_RECORD_TTL: Duration = Duration::from_secs(30 * 60);
const MATRIX_REFRESH_FAILURE_ERROR_THRESHOLD: u32 = 3;

/// Tracks consecutive-failure counts for a refresh path that should be
/// throttled before flipping the channel into Error. Replaces a
/// previously-copied pattern of four separate `let mut x_failures = 0;`
/// + saturating_add + threshold-check spread across the runtime.
#[derive(Debug)]
struct FailureStreak {
    count: u32,
    threshold: u32,
}

impl FailureStreak {
    fn new(threshold: u32) -> Self {
        // A zero threshold makes `is_sticky()` true on construction
        // (0 >= 0), defeating the contract that a fresh streak hasn't
        // tripped yet. Catch the misuse in debug builds; release
        // builds clamp to 1 to preserve forward progress rather than
        // panic in production.
        debug_assert!(threshold >= 1, "FailureStreak threshold must be >= 1");
        Self {
            count: 0,
            threshold: threshold.max(1),
        }
    }

    /// Record a failure. Returns the new consecutive count so the
    /// caller can include it in the warn-log line.
    fn record_failure(&mut self) -> u32 {
        self.count = self.count.saturating_add(1);
        self.count
    }

    /// Reset the counter on success.
    fn record_success(&mut self) {
        self.count = 0;
    }

    /// Whether the streak has reached the operator-visible threshold
    /// — i.e., the channel should report Error rather than Connected
    /// even on subsequent sync successes.
    fn is_sticky(&self) -> bool {
        self.count >= self.threshold
    }
}
/// Number of consecutive successful sync iterations after which a
/// sticky inbound-dispatch failure is forgiven. Without this decay, a
/// transient inbound-pipeline blip in a low-traffic room would leave
/// the channel pinned in Error indefinitely (the counter only resets
/// on a successful inbound dispatch, which never happens if no new
/// messages arrive).
const MATRIX_INBOUND_DECAY_SYNC_COUNT: u32 = 6;
const MATRIX_BACKOFF_STEPS: [Duration; 7] = [
    Duration::from_secs(1),
    Duration::from_secs(2),
    Duration::from_secs(4),
    Duration::from_secs(8),
    Duration::from_secs(16),
    Duration::from_secs(32),
    Duration::from_secs(60),
];
/// Upper bound on locally-honored `Retry-After`. A homeserver can
/// legally suggest very long delays (hours, days), but parking the
/// sync loop for that long defeats operator visibility and risks
/// `Instant::now() + delay` arithmetic overflow on extreme values.
/// Cap at 1h so the give-up policy still observes idle progress
/// while honoring the homeserver's intent (slow down significantly).
const MATRIX_RETRY_AFTER_MAX: Duration = Duration::from_secs(60 * 60);
/// Sync-loop give-up policy. Without an upper bound on retries,
/// a daemon with a permanently broken homeserver URL (typo,
/// account moved, DNS hijack) wakes every 60s forever — burning
/// CPU + network + log volume + journal pressure indefinitely.
/// After 24 hours of no successful sync, the actor stamps a
/// distinct `last_error_kind = "sync-loop-give-up"` and slows
/// the retry frequency from once-per-60s to once-per-hour. Sync
/// is NOT paused entirely — the operator may have fixed
/// connectivity without restarting the daemon, and the next
/// successful sync clears the give-up state.
const MATRIX_SYNC_GIVE_UP_THRESHOLD_MS: i64 = 24 * 60 * 60 * 1000;
const MATRIX_SYNC_GIVE_UP_RETRY_INTERVAL: Duration = Duration::from_secs(60 * 60);
/// Sentinel value for the last-valid-wall-clock cache. `i64::MIN` is used
/// instead of `0` so that the "we have never seen a valid clock" case is
/// distinguishable from "the clock briefly went bad and the cached value
/// happens to be 0 ms past UNIX_EPOCH" — in the former, falling back to
/// `0` would cause newly-minted verification records to be pruned within
/// 30 minutes once the clock recovers.
const LAST_VALID_WALL_CLOCK_SENTINEL: i64 = i64::MIN;
static LAST_VALID_WALL_CLOCK_MILLIS: AtomicI64 = AtomicI64::new(LAST_VALID_WALL_CLOCK_SENTINEL);

#[derive(Clone, PartialEq, Eq)]
pub struct MatrixConfig {
    pub homeserver_url: String,
    pub user_id: String,
    /// Long-lived Matrix access token. Wrapped in `Zeroizing` so any
    /// `MatrixConfig::clone()` (the runtime spawns task-local copies)
    /// wipes its heap allocation on drop instead of relying on the
    /// allocator. The hand-rolled `Debug` redacts the value separately.
    pub access_token: Option<zeroize::Zeroizing<String>>,
    /// First-login password. Same Zeroizing discipline as
    /// `access_token` — clones must not retain plaintext on the heap
    /// past the field's drop site.
    pub password: Option<zeroize::Zeroizing<String>>,
    pub device_id: Option<String>,
    /// Encryption posture for the SDK store. Replaces the prior
    /// `encrypted: bool` + `store_passphrase: Option<String>` pair —
    /// those let `{ encrypted: true, store_passphrase: None }` slip
    /// through config-resolve, with the runtime-only fallback to
    /// `CARAPACE_CONFIG_PASSWORD` derivation as the implicit (and
    /// failure-prone) safety net. The sum type makes
    /// "encrypted-without-a-key-source" unrepresentable.
    pub security: MatrixSecurity,
    pub auto_join: MatrixAutoJoinConfig,
    pub legacy_dlq_envelope_policy: MatrixLegacyDlqEnvelopePolicy,
}

impl fmt::Debug for MatrixConfig {
    /// Hand-rolled Debug elides `access_token` and `password` so a
    /// future `tracing::debug!(?config, ...)` or `dbg!` doesn't leak
    /// credentials into log sinks. `MatrixSecurity::Encrypted{Explicit}`
    /// also redacts via `PassphraseSource`'s own Debug impl.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MatrixConfig")
            .field("homeserver_url", &self.homeserver_url)
            .field("user_id", &self.user_id)
            .field(
                "access_token",
                &self.access_token.as_ref().map(|_| "<redacted>"),
            )
            .field("password", &self.password.as_ref().map(|_| "<redacted>"))
            .field("device_id", &self.device_id)
            .field("security", &self.security)
            .field("auto_join", &self.auto_join)
            .field(
                "legacy_dlq_envelope_policy",
                &self.legacy_dlq_envelope_policy,
            )
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatrixLegacyDlqEnvelopePolicy {
    Accept,
    Refuse,
}

impl MatrixConfig {
    /// Whether the runtime should treat this channel as Matrix-encrypted
    /// (E2EE rooms supported). Mirrors the historical `encrypted: bool`
    /// for read-side compatibility.
    pub fn encrypted(&self) -> bool {
        matches!(self.security, MatrixSecurity::Encrypted { .. })
    }
}

fn ensure_encrypted_matrix_state_supported(config: &MatrixConfig) -> Result<(), MatrixError> {
    if !config.encrypted() {
        return Ok(());
    }
    ensure_encrypted_matrix_state_supported_on_platform()
}

#[cfg(windows)]
fn ensure_encrypted_matrix_state_supported_on_platform() -> Result<(), MatrixError> {
    Err(MatrixError::StartupFailed(
        "encrypted Matrix state is unsupported on Windows in this release because Carapace \
         cannot yet enforce owner-only ACLs for the Matrix SDK store, recovery key, \
         installation id, store passphrase, and DLQ files. Refusing to start rather than \
         risk local-account disclosure of encrypted Matrix state. Run the Matrix encrypted \
         runtime on Unix/macOS, or set matrix.encrypted=false only for unencrypted-room use."
            .to_string(),
    ))
}

#[cfg(not(windows))]
fn ensure_encrypted_matrix_state_supported_on_platform() -> Result<(), MatrixError> {
    Ok(())
}

/// SDK-store encryption mode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MatrixSecurity {
    /// E2EE disabled. The SDK store is created without a passphrase
    /// and only unencrypted rooms are supported.
    Unencrypted,
    /// E2EE enabled. The store passphrase comes from the configured
    /// source — either an explicit operator-supplied value or an HKDF
    /// derivation over `CARAPACE_CONFIG_PASSWORD`.
    Encrypted { passphrase_source: PassphraseSource },
}

/// Where the encrypted SDK store passphrase comes from.
#[derive(Clone, PartialEq, Eq)]
pub enum PassphraseSource {
    /// Operator-supplied via `matrix.storePassphrase` or
    /// `MATRIX_STORE_PASSPHRASE`. Used directly as the SQLite
    /// passphrase.
    Explicit(NonEmptyPassphrase),
    /// Derive a 32-byte key via HKDF-SHA256 from
    /// `CARAPACE_CONFIG_PASSWORD` + installation_id at runtime.
    /// `derive_matrix_store_key` performs the derivation; if
    /// `CARAPACE_CONFIG_PASSWORD` is unset at startup, the runtime
    /// surfaces `MatrixError::MissingStoreSecret`.
    DeriveFromConfigPassword,
}

impl fmt::Debug for PassphraseSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Explicit(_) => f.write_str("Explicit(<redacted>)"),
            Self::DeriveFromConfigPassword => f.write_str("DeriveFromConfigPassword"),
        }
    }
}

/// Newtype wrapper around a non-empty operator-supplied passphrase.
/// Constructing via `new()` rejects empty/whitespace values so the
/// `Encrypted{Explicit(_)}` variant can never carry "" as the SQLite
/// passphrase. Debug elides the inner string. The inner String is
/// zeroized on drop so a clone-then-drop cycle doesn't leave the
/// passphrase in heap memory; `MatrixConfig` is `Clone` and the
/// runtime clones it freely (login coroutine, event handlers,
/// per-call closures).
#[derive(Clone, PartialEq, Eq, zeroize::ZeroizeOnDrop)]
pub struct NonEmptyPassphrase(String);

impl NonEmptyPassphrase {
    pub fn new(value: impl Into<String>) -> Result<Self, MatrixError> {
        let value = value.into();
        if value.trim().is_empty() {
            return Err(MatrixError::InvalidString {
                field: "storePassphrase",
            });
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for NonEmptyPassphrase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NonEmptyPassphrase")
            .field("len", &self.0.len())
            .finish()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MatrixAutoJoinConfig {
    pub allow_users: BTreeSet<String>,
    pub allow_server_names: BTreeSet<String>,
}

impl MatrixAutoJoinConfig {
    pub fn is_empty(&self) -> bool {
        self.allow_users.is_empty() && self.allow_server_names.is_empty()
    }

    pub fn allows_user(&self, user_id: &str) -> bool {
        if self.allow_users.contains(user_id) {
            return true;
        }
        let Some(server_name) = matrix_server_name(user_id) else {
            return false;
        };
        self.allow_server_names
            .iter()
            .any(|suffix| server_name == suffix || server_name.ends_with(&format!(".{suffix}")))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MatrixConfigResolve {
    Disabled,
    Missing,
    Configured(MatrixConfig),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DlqCryptoFailure {
    ConfigUnavailable { version: u8 },
    Other(String),
}

impl std::fmt::Display for DlqCryptoFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DlqCryptoFailure::ConfigUnavailable { version } => write!(
                f,
                "encrypted v{version} DLQ record encountered but no key cache or \
                 config available — likely a `matrix.encrypted` flag toggle \
                 with stale records on disk; toggle back to true to drain"
            ),
            DlqCryptoFailure::Other(detail) => f.write_str(detail),
        }
    }
}

#[derive(Debug, Clone, Error)]
pub enum MatrixError {
    #[error("matrix config must be an object")]
    InvalidConfigRoot,
    #[error("matrix.{field} must be a string")]
    InvalidString { field: &'static str },
    #[error("matrix.{field} must be a boolean")]
    InvalidBool { field: &'static str },
    #[error("matrix.autoJoin.{field} must be an array of strings")]
    InvalidStringArray { field: &'static str },
    #[error("matrix.{field} exceeds {max} bytes (got {got})")]
    InvalidLength {
        field: &'static str,
        max: usize,
        got: usize,
    },
    #[error("matrix.{field} is not a valid URL: {reason}")]
    InvalidUrl {
        field: &'static str,
        reason: &'static str,
    },
    #[error("matrix.autoJoin.{field} exceeds {max} entries (got {got})")]
    AllowlistTooLarge {
        field: &'static str,
        max: usize,
        got: usize,
    },
    #[error("matrix homeserver URL is required")]
    MissingHomeserverUrl,
    #[error("matrix user ID is required")]
    MissingUserId,
    #[error("matrix accessToken or password is required")]
    MissingCredentials,
    #[error(
        "matrix.deviceId is required when matrix.accessToken is configured; \
         either set matrix.deviceId to the SDK-issued device ID for that token, \
         or remove matrix.accessToken to fall back to password login"
    )]
    MissingDeviceIdForTokenRestore,
    #[error("matrix encrypted store requires CARAPACE_CONFIG_PASSWORD or MATRIX_STORE_PASSPHRASE")]
    MissingStoreSecret,
    #[error("matrix store key derivation failed")]
    StoreKeyDerivation,
    #[error("failed to read or create Matrix installation id: {0}")]
    InstallationId(String),
    #[error("failed to build Matrix client: {0}")]
    ClientBuild(String),
    /// Generic / login-time auth failure — homeserver rejected the
    /// password or the SDK reported a transport error during login.
    /// The string carries the SDK error verbatim. For operator-
    /// actionable cases prefer the more specific session-mismatch
    /// variants below.
    #[error("failed to authenticate Matrix client: {0}")]
    Auth(String),
    /// Bounded auth probing exhausted its retry budget without a terminal
    /// homeserver auth class. This remains retryable at delivery/control
    /// boundaries; token revocation and account-state failures use the typed
    /// terminal auth variants below.
    #[error("transient Matrix auth probe failed: {0}")]
    AuthProbe(String),
    /// Restored access-token's user-id doesn't match `matrix.userId`.
    /// Operator action: re-check `matrix.userId` against the token's
    /// owner; possibly the token was rotated for a different account.
    #[error(
        "restored Matrix token belongs to {actual}, expected {expected} \
         (check matrix.userId or rotate the token)"
    )]
    AuthSessionUserMismatch { actual: String, expected: String },
    /// Restored access-token's device-id doesn't match
    /// `matrix.deviceId`. Operator action: re-check `matrix.deviceId`
    /// against the token's device.
    #[error(
        "restored Matrix token belongs to device {actual}, expected {expected} \
         (check matrix.deviceId)"
    )]
    AuthSessionDeviceMismatch { actual: String, expected: String },
    /// Restored access-token didn't report a device id at all.
    /// Operator action: this should not happen with a working
    /// homeserver — file an issue with the homeserver software /
    /// version.
    #[error(
        "restored Matrix token did not report a device id \
         (homeserver bug — file an issue with your homeserver)"
    )]
    AuthSessionMissingDeviceId,
    /// Homeserver reported the token is revoked / forbidden /
    /// account deactivated / locked / suspended. Recovery depends on
    /// auth mode; there is no `cara matrix login` subcommand.
    #[error(
        "Matrix access token rejected by homeserver: {0} (token revoked, account \
         deactivated/locked, or suspended. accessToken-configured: mint a new token, \
         edit matrix.accessToken and matrix.deviceId in the config file or set \
         MATRIX_ACCESS_TOKEN and MATRIX_DEVICE_ID in the daemon environment, then restart. \
         password-configured: verify the password is correct and restart)"
    )]
    AuthTokenRevoked(String),
    #[error("failed to persist Matrix access token: {0}")]
    TokenPersistence(String),
    #[error("Matrix recovery-key restore failed ({reason}): {detail}")]
    RecoveryKeyRestoreFailed {
        reason: RecoveryRestoreFailureReason,
        detail: String,
    },
    #[error("Matrix cross-signing bootstrap failed: {0}")]
    CrossSigningBootstrapFailed(String),
    #[error("Matrix encrypted-state file operation failed: {0}")]
    EncryptedStateIo(String),
    #[error("Matrix recovery state probe failed: {0}")]
    RecoveryStateProbeFailed(String),
    #[error("Matrix recovery state file operation failed: {0}")]
    RecoveryStateIo(String),
    #[error("Matrix recovery configuration precondition failed: {0}")]
    RecoveryConfigPrecondition(String),
    #[error("Matrix recovery-key promotion refused: {0}")]
    RecoveryKeyPromotionRefused(String),
    #[error("Matrix runtime startup failed: {0}")]
    StartupFailed(String),
    /// Pending or rekeying-marker on disk without the canonical
    /// passphrase file: the previous `cara matrix rekey-store --new`
    /// crashed mid-rotation. Operators see this at daemon startup
    /// and via `cara verify --outcome matrix`. The runtime carries
    /// the message so the operator-facing string can vary, but the
    /// variant itself is what callers (`cli::verify_matrix_outcome`)
    /// pattern-match on to suggest the right recovery command. The
    /// Display prefix is distinct from `StartupFailed` so operators
    /// reading `cara status` can tell the two apart at a glance —
    /// the recovery actions differ.
    #[error("Matrix store rekey interrupted: {0}")]
    InterruptedRekey(String),
    #[error("Matrix clock error: {0}")]
    Clock(String),
    #[error("Matrix runtime is not connected")]
    NotConnected,
    #[error("Matrix room is unsupported: {0}")]
    UnsupportedRoom(String),
    #[error("Matrix room not found: {0}")]
    RoomNotFound(String),
    #[error("Matrix send failed: {message}")]
    SendFailed {
        message: String,
        retry_after_ms: Option<i64>,
    },
    #[error("Matrix sync failed: {0}")]
    SyncFailed(String),
    #[error("Matrix inbound DLQ crypto operation failed: {0}")]
    DlqCrypto(DlqCryptoFailure),
    #[error("Matrix inbound DLQ I/O failed: {0}")]
    DlqIo(String),
    #[error("Matrix inbound DLQ serialization failed: {0}")]
    DlqSerialization(String),
    #[error("Matrix inbound DLQ dispatch failed: {0}")]
    DlqDispatchFailure(String),
    #[error("Matrix inbound DLQ cap saturated: {0}")]
    DlqCapSaturation(String),
    #[error(
        "legacy Matrix inbound DLQ v1 envelope refused by policy \
         matrix.inboundDlq.legacyEnvelopePolicy=refuse: {0}"
    )]
    LegacyDlqEnvelopeRefused(String),
    #[error("Matrix session history is corrupt: {0}")]
    SessionHistoryCorrupt(String),
    /// 24h have elapsed without a successful sync. The daemon
    /// continues retrying (the operator may have fixed
    /// connectivity without restarting), but at a reduced
    /// frequency (~once/hour) instead of the saturated 60s
    /// backoff. Distinct kind so operator dashboards / alerts can
    /// distinguish "broken for hours" from "transient retry in
    /// progress".
    /// Display string deliberately omits `idle_ms` — under give-up,
    /// the actor stamps this variant every retry interval (~1h).
    /// `set_error` is idempotent only when the formatted message is
    /// stable across re-stamps; embedding the growing `idle_ms` here
    /// would defeat that guard and bump `status_changed_at` every
    /// hour. Operators get the live idle delta from the warn-log
    /// (`idle_ms` field), and from
    /// `MatrixStatusMetadata.last_successful_sync_at` (clients
    /// subtract from now).
    #[error(
        "Matrix sync has been unable to complete a successful sync for over 24h; \
         retrying once per hour instead of every 60s. Investigate homeserver \
         reachability (DNS, network, account state) and restart the daemon to \
         resume normal-cadence sync."
    )]
    SyncLoopGaveUp { idle_ms: i64 },
    #[error("Matrix verification flow not found: {0}")]
    VerificationFlowNotFound(String),
    #[error("Matrix user ID is invalid: {0}")]
    InvalidUserId(String),
    #[error("Matrix device not found: {user_id} {device_id}")]
    DeviceNotFound { user_id: String, device_id: String },
    #[error("Matrix user identity not found: {0}")]
    UserIdentityNotFound(String),
    #[error("Matrix verification flow is not ready for {action}: {flow_id}")]
    VerificationFlowNotReady {
        flow_id: String,
        action: &'static str,
    },
    #[error("Matrix verification failed: {0}")]
    Verification(String),
    #[error("Matrix verification action timed out: {0}")]
    VerificationTimeout(String),
    /// Local in-process command queue is full — the runtime actor
    /// has not drained the bounded mpsc fast enough. Distinct from
    /// `VerificationTimeout` (which means an SDK request did not
    /// complete in the homeserver-bound window): backpressure is
    /// transient and operators should retry shortly. HTTP 503 so
    /// retry policies treat this as service-unavailable rather than
    /// gateway-timeout.
    #[error("Matrix runtime command queue is full; retry shortly")]
    CommandQueueFull,
    /// matrix-sdk reported wrong passphrase / cipher / MAC failure
    /// when opening the encrypted SQLite store. Distinct from
    /// `ClientBuild` (generic SDK build failure including filesystem
    /// errors and missing-token problems) so the operator can route
    /// to the rekey-recovery procedure when a rotation went sideways.
    #[error(
        "Matrix encrypted store at {path} rejected the resolved passphrase \
         (check CARAPACE_CONFIG_PASSWORD or look for an interrupted rekey at \
         {path}; see docs/channels.md#matrix-store-rekey-lifecycle): {detail}",
        path = path.display(),
    )]
    EncryptedStorePassphraseMismatch {
        path: std::path::PathBuf,
        detail: String,
    },
    /// Operator attempted Accept/Confirm/etc on a verification flow
    /// that's already in a terminal state (Cancelled, Done, Mismatched).
    /// Distinct from `VerificationFlowNotReady` which means the flow
    /// hasn't advanced FAR ENOUGH yet (transient — retry after the
    /// peer responds). Cancelled is permanent and security-relevant —
    /// the peer either cancelled the flow or completed a different
    /// step out-of-order. Operator should investigate why and start
    /// a new flow if needed.
    #[error("Matrix verification flow is in terminal state {state}; start a new flow: {flow_id}")]
    VerificationCancelled {
        flow_id: String,
        state: MatrixVerificationState,
    },
    /// A `room.send` failed in a way the homeserver tells us is
    /// permanent for this room: M_TOO_LARGE (oversized payload),
    /// M_GUEST_ACCESS_FORBIDDEN, M_BAD_JSON, M_UNRECOGNIZED.
    /// Token-revocation classes (M_FORBIDDEN, M_UNKNOWN_TOKEN,
    /// M_USER_DEACTIVATED, M_USER_LOCKED, M_USER_SUSPENDED) route
    /// to `AuthTokenRevoked` instead — `classify_terminal_kind`
    /// peels them off before this variant is constructed.
    /// Routing these as retryable would burn the dispatch retry
    /// budget on hopeless cases and delay surfacing the real fault
    /// to the operator. Distinct from `SendFailed` (transient/
    /// unknown) so `matrix_send_error_to_binding_result` can map
    /// terminal classes to a non-retryable `BindingError::CallError`.
    #[error("Matrix send failed permanently: {0}")]
    SendTerminal(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryRestoreFailureReason {
    WrongKey,
    EmptyKeyFile,
    ServerNotConfigured,
    TransportError,
    AccountDataInvalid,
    BackupAlreadyExists,
    LocalStore,
    SdkInternal,
    UnpicklingFailed,
}

impl RecoveryRestoreFailureReason {
    pub fn as_str(self) -> &'static str {
        match self {
            RecoveryRestoreFailureReason::WrongKey => "wrong-key",
            RecoveryRestoreFailureReason::EmptyKeyFile => "empty-key-file",
            RecoveryRestoreFailureReason::ServerNotConfigured => "server-not-configured",
            RecoveryRestoreFailureReason::TransportError => "transport-error",
            RecoveryRestoreFailureReason::AccountDataInvalid => "account-data-invalid",
            RecoveryRestoreFailureReason::BackupAlreadyExists => "backup-already-exists",
            RecoveryRestoreFailureReason::LocalStore => "local-store",
            RecoveryRestoreFailureReason::SdkInternal => "sdk-internal",
            RecoveryRestoreFailureReason::UnpicklingFailed => "unpickling-failed",
        }
    }
}

impl std::fmt::Display for RecoveryRestoreFailureReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl MatrixError {
    /// Stable kebab-case discriminator for routing operator hints
    /// across boundaries that lose the typed variant. The
    /// runtime-readiness path stamps the Display string into
    /// `ChannelMetadata.last_error` and the CLI's
    /// `verify_matrix_outcome` would otherwise have to substring-
    /// match the formatted message to pick a remediation. Surfacing
    /// `kind()` alongside `last_error` lets the CLI match on a
    /// stable token; future Display copy-edits don't break the
    /// routing.
    ///
    /// The values are wire-stable: external consumers (CLI, tests,
    /// future control-API readers) match on these. Renaming a
    /// returned token is a breaking change.
    pub fn kind(&self) -> &'static str {
        match self {
            MatrixError::InvalidConfigRoot => "invalid-config-root",
            MatrixError::InvalidString { .. } => "invalid-string",
            MatrixError::InvalidBool { .. } => "invalid-bool",
            MatrixError::InvalidStringArray { .. } => "invalid-string-array",
            MatrixError::InvalidLength { .. } => "invalid-length",
            MatrixError::InvalidUrl { .. } => "invalid-url",
            MatrixError::AllowlistTooLarge { .. } => "allowlist-too-large",
            MatrixError::MissingHomeserverUrl => "missing-homeserver-url",
            MatrixError::MissingUserId => "missing-user-id",
            MatrixError::MissingCredentials => "missing-credentials",
            MatrixError::MissingDeviceIdForTokenRestore => "missing-device-id-for-token-restore",
            MatrixError::MissingStoreSecret => "missing-store-secret",
            MatrixError::StoreKeyDerivation => "store-key-derivation",
            MatrixError::InstallationId(_) => "installation-id",
            MatrixError::ClientBuild(_) => "client-build",
            MatrixError::Auth(_) => "auth",
            MatrixError::AuthProbe(_) => "auth-probe",
            MatrixError::AuthSessionUserMismatch { .. } => "auth-session-user-mismatch",
            MatrixError::AuthSessionDeviceMismatch { .. } => "auth-session-device-mismatch",
            MatrixError::AuthSessionMissingDeviceId => "auth-session-missing-device-id",
            MatrixError::AuthTokenRevoked(_) => "auth-token-revoked",
            MatrixError::TokenPersistence(_) => "token-persistence",
            MatrixError::RecoveryKeyRestoreFailed { .. } => "recovery-key-restore-failed",
            MatrixError::CrossSigningBootstrapFailed(_) => "cross-signing-bootstrap-failed",
            MatrixError::EncryptedStateIo(_) => "encrypted-state-io",
            MatrixError::RecoveryStateProbeFailed(_) => "recovery-state-probe-failed",
            MatrixError::RecoveryStateIo(_) => "recovery-state-io",
            MatrixError::RecoveryConfigPrecondition(_) => "recovery-config-precondition",
            MatrixError::RecoveryKeyPromotionRefused(_) => "recovery-key-promotion-refused",
            MatrixError::StartupFailed(_) => "startup-failed",
            MatrixError::InterruptedRekey(_) => "interrupted-rekey",
            MatrixError::Clock(_) => "clock",
            MatrixError::NotConnected => "not-connected",
            MatrixError::UnsupportedRoom(_) => "unsupported-room",
            MatrixError::RoomNotFound(_) => "room-not-found",
            MatrixError::SendFailed { .. } => "send-failed",
            MatrixError::SyncFailed(_) => "sync-failed",
            MatrixError::DlqCrypto(_) => "dlq-crypto",
            MatrixError::DlqIo(_) => "dlq-io",
            MatrixError::DlqSerialization(_) => "dlq-serialization",
            MatrixError::DlqDispatchFailure(_) => "dlq-dispatch-failure",
            MatrixError::DlqCapSaturation(_) => "dlq-cap-saturation",
            MatrixError::LegacyDlqEnvelopeRefused(_) => "legacy-dlq-envelope-refused",
            MatrixError::SessionHistoryCorrupt(_) => "session-history-corrupt",
            MatrixError::SyncLoopGaveUp { .. } => "sync-loop-give-up",
            MatrixError::VerificationFlowNotFound(_) => "verification-flow-not-found",
            MatrixError::InvalidUserId(_) => "invalid-user-id",
            MatrixError::DeviceNotFound { .. } => "device-not-found",
            MatrixError::UserIdentityNotFound(_) => "user-identity-not-found",
            MatrixError::VerificationFlowNotReady { .. } => "verification-flow-not-ready",
            MatrixError::Verification(_) => "verification",
            MatrixError::VerificationTimeout(_) => "verification-timeout",
            MatrixError::CommandQueueFull => "command-queue-full",
            MatrixError::EncryptedStorePassphraseMismatch { .. } => {
                "encrypted-store-passphrase-mismatch"
            }
            MatrixError::VerificationCancelled { .. } => "verification-cancelled",
            MatrixError::SendTerminal(_) => "send-terminal",
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MatrixStatusMetadata {
    pub joined_room_count: usize,
    pub encrypted_room_count: usize,
    pub unencrypted_room_count: usize,
    pub unsupported_room_count: usize,
    pub pending_verification_count: usize,
    // `last_successful_sync_at` always serializes (even as `null`) and
    // `unsupported_rooms` always serializes (even as `[]`). Both
    // predate the `skip_serializing_if` convention applied to newer
    // fields. Adding `skip_serializing_if` retroactively would be a
    // breaking wire-format change for the v0.8.x clients already in
    // the field. New fields adopt the omit-when-empty convention;
    // these stay always-emit.
    pub last_successful_sync_at: Option<i64>,
    pub unsupported_rooms: Vec<String>,
    /// Cumulative count of inbound Matrix events whose msgtype the
    /// runtime doesn't yet handle (image/file/audio/video/emote/notice
    /// etc). Surfaced via channel metadata so an operator wondering
    /// "why did the bot not reply to my photo?" has a discoverable
    /// answer without grepping logs.
    pub unsupported_inbound_count: u64,
    /// Cumulative count of inbound dispatch failures since runtime
    /// start. Survives the consecutive-failure decay (which only
    /// resets the threshold counter, not this lifetime total) so
    /// operators can audit how many inbound events were dropped over
    /// the daemon's uptime even when `last_error` has since been
    /// cleared by a successful sync.
    pub inbound_dispatch_failure_total: u64,
    /// Cumulative count of cases where an inbound event failed both
    /// dispatch and durable DLQ append. This is a durability failure:
    /// unlike ordinary inbound dispatch streaks, a clean sync must not
    /// clear the operator-visible error because the event has no replay
    /// source left.
    pub inbound_dlq_append_failure_total: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inbound_dlq_durability_error: Option<String>,
    /// Capped list of inbound event IDs that the DLQ replay phase-3
    /// cleanup couldn't persist back to disk (re-read failed, rewrite
    /// failed, or every record's re-encode failed). The journal
    /// already logs these via `log_lost_remaining`, but a journal
    /// rotation between the failure and the operator's page would
    /// lose the recovery list. Surfacing on channel-status keeps the
    /// IDs visible until the next successful replay clears them.
    /// Capped at MATRIX_INBOUND_DLQ_LOST_IDS_CAP entries to bound the
    /// payload — operators chasing a larger leak should grep the
    /// journal for `lost_event_ids` directly.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub inbound_dlq_lost_event_ids: Vec<String>,
    /// Cumulative count of dropped DLQ records that failed to decode
    /// during cap-clamp tail-truncation (almost always store-key
    /// mismatch from a prior CARAPACE_CONFIG_PASSWORD rotation). The
    /// `inbound_dlq_lost_event_ids` list is empty in this case — the
    /// IDs literally couldn't be recovered — so this counter is the
    /// operator-visible signal that records were lost. Distinct from
    /// `inbound_dlq_append_failure_total` (which counts all DLQ
    /// durability failures regardless of decodability).
    #[serde(default)]
    pub inbound_dlq_undecodable_lost_count: u64,
    /// Stable kebab-case discriminator for the most recent
    /// `MatrixError` stamped to the channel registry. Reflects the
    /// typed variant for the same error whose Display string lives
    /// in `ChannelMetadata.last_error`. Surfaces to `cara verify
    /// --outcome matrix` so the CLI can route per-variant operator
    /// hints (rekey-token / rekey-recovery / fix-config / etc.)
    /// without parsing the redacted Display text. Cleared when the
    /// channel transitions back to Connected. See
    /// `MatrixError::kind()` for the value set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error_kind: Option<String>,
    /// Forensic timestamp for the most recent
    /// `inbound_dlq_durability_error` stamp (Unix ms). Operators
    /// chasing "when did the DLQ start failing?" need a timeline
    /// — without this they only see the current error message
    /// and have to grep journald for the corresponding warn-log.
    /// Cleared by `clear_inbound_dlq_durability_error` in lockstep
    /// with the message itself.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inbound_dlq_durability_error_at: Option<i64>,
    /// Forensic timestamp for the most recent
    /// `inbound_dlq_lost_event_ids` append (Unix ms). The list is
    /// append-and-truncate so this records the timestamp of the
    /// LATEST loss, not the oldest. Cleared by
    /// `clear_inbound_dlq_lost_event_ids` in lockstep.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inbound_dlq_lost_event_ids_at: Option<i64>,
    /// Forensic timestamp for the most recent inbound dispatch
    /// failure stamped via `record_inbound_failure_with_error`
    /// (Unix ms). Survives the consecutive-failure decay so an
    /// operator can audit "did inbound break in the last hour?"
    /// even after `last_error` has been cleared by a successful
    /// sync.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_inbound_failure_at: Option<i64>,
    /// Forensic timestamp for the most recent
    /// `inbound_dlq_append_failure_total` increment (Unix ms).
    /// Distinct from `last_inbound_failure_at` because durability
    /// failures (dispatch failed AND DLQ append failed) have
    /// stricter recovery semantics than transient inbound
    /// dispatch failures.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_inbound_dlq_append_failure_at: Option<i64>,
    /// Timestamp for the first recovery-key mint observed in this daemon
    /// process. The recovery key itself is never exposed here; the field is
    /// only an operator-visible signal that a backup secret was created and
    /// must be captured from the owner-only local file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_recovery_key_minted_at: Option<i64>,
    /// Peer-controlled Matrix events dropped before agent dispatch,
    /// grouped by cause. These are cumulative so hostile homeservers
    /// cannot hide a flood behind sampled logs.
    #[serde(default)]
    pub peer_drop_unsupported_msgtype_total: u64,
    #[serde(default)]
    pub peer_drop_allowlist_rejection_total: u64,
    #[serde(default)]
    pub peer_drop_body_too_large_total: u64,
    #[serde(default)]
    pub peer_drop_verification_cap_full_total: u64,
    #[serde(default)]
    pub peer_drop_encrypted_room_total: u64,
    /// Corrupt inbound-event dedupe index lines ignored while
    /// processing Matrix inbound dispatch. A non-zero value means
    /// idempotency stayed available, but operator cleanup is needed.
    #[serde(default)]
    pub inbound_dedupe_corrupt_line_total: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MatrixDeviceInfo {
    /// Matrix user id projected for operator-visible device-list output.
    pub user_id: OwnedUserId,
    pub device_id: OwnedDeviceId,
    /// Sanitized peer-controlled display name, or absent if the device
    /// has no display name. `skip_serializing_if = Option::is_none`
    /// matches the convention on `MatrixVerificationInfo.sas` and on
    /// `device_id`: omit-when-absent rather than emit `null`, since
    /// JS/TS clients treat the two differently in optional chaining.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    pub verified: bool,
    /// Hex-encoded raw (homeserver-original) device_id bytes —
    /// populated only when sanitization changed `device_id`.
    ///
    /// Operator scripts driving `cara matrix verify <user> <device>`
    /// against an adversarial peer device (one whose raw
    /// device_id carries bidi / ZW / TAG / control bytes) need the
    /// byte-exact form for the SDK lookup. Hex is the wire form so
    /// the `/control/matrix/devices` JSON is guaranteed terminal-
    /// safe even on adversarial entries — `serde_json`'s
    /// pretty-printer escapes 0x00–0x1F as `\uXXXX` but emits 0x7F
    /// (DEL) and the C1 range (0x80–0x9F, including the single-byte
    /// CSI 0x9B) as literal UTF-8 bytes. Encoding at the wire
    /// boundary closes the operator-terminal-injection vector.
    ///
    /// Operator scripts that need the byte-exact form decode the
    /// hex back to bytes for the SDK lookup; humans copy-paste the
    /// terminal-safe `device_id` and rely on
    /// `start_matrix_verification`'s sanitization-equivalence
    /// resolver. Omitted (None) when sanitization was a no-op —
    /// the steady state for ASCII-safe device_ids.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw_device_id_hex: Option<String>,
}

#[derive(Debug)]
pub struct MatrixRuntimeState {
    status: MatrixStatusMetadata,
    devices: Vec<MatrixDeviceInfo>,
    verifications: Vec<MatrixVerificationInfo>,
    /// Inbound-dispatch consecutive-failure tracker. Lives on the
    /// state (not as a stack-local `FailureStreak` like the three
    /// sync-arm streaks) because event handlers outside the sync arm
    /// need to record/reset/check it.
    inbound_streak: FailureStreak,
    /// Last error message produced by an inbound dispatch failure.
    /// Stamped by the room-message handler on each failure, consumed
    /// by `apply_post_sync_maintenance` when reconciling channel-
    /// registry status. Owning all registry transitions in maintenance
    /// (rather than letting inbound write directly to the registry)
    /// eliminates the race where a maintenance recovery to Connected
    /// could overwrite an inbound's just-set Error.
    pending_inbound_error: Option<String>,
    /// Typed `MatrixError::kind()` discriminator corresponding to
    /// `pending_inbound_error`.
    pending_inbound_error_kind: Option<String>,
    /// Monotonic owner-side generation for inbound failure state.
    inbound_failure_generation: u64,
    /// Most-recent invite-handling systemic failure (≥ N failures in
    /// one maintenance tick). Distinct from
    /// `MatrixStatusMetadata.inbound_dlq_durability_error`: invite
    /// failures and DLQ durability failures have different recovery
    /// semantics — DLQ durability is cleared by a successful DLQ
    /// op, invite is cleared by a successful invite-handling tick.
    /// Conflating them stuck the channel in Error indefinitely after
    /// any invite outage because the DLQ-clear path never fires for
    /// invite-only failures.
    pending_invite_systemic_error: Option<String>,
    /// Shared lock that serializes Matrix inbound DLQ disk I/O across
    /// the room-message handler (append) and the post-sync maintenance
    /// path (read + dispatch + rewrite). Without it, `append`'s
    /// freshly-written line can be silently overwritten by `rewrite`'s
    /// tmp-file rename, losing exactly the inbound event the DLQ is
    /// supposed to durably retain.
    dlq_io_lock: Arc<tokio::sync::Mutex<()>>,
    /// Daemon-lifetime cache for the v1/v2 DLQ AEAD keys. Each
    /// derivation runs at most once per daemon process via
    /// `OnceLock`. Argon2id is memory-hard (tens of ms per
    /// derivation); without this cache the replay loop paid a
    /// fresh Argon2id on every tick that reached the encrypted
    /// path. Shared via `Arc` so the replay loop can hold a
    /// long-lived handle without keeping the runtime-state lock.
    dlq_keys: Arc<MatrixDlqKeys>,
    /// Set when the actor has stamped a TERMINAL `MatrixError` via
    /// `mark_terminal_runtime_stamped`. After this flag is set,
    /// forensic-wiping maintenance writes (e.g.,
    /// `clear_inbound_dlq_durability_error`) no-op so an in-flight
    /// maintenance task that completes between the terminal stamp
    /// and the JoinSet cancel cannot overwrite the forensic state
    /// the operator needs to diagnose the terminal cause.
    terminal_runtime_stamped: bool,
    /// Monotonic millis (matches `now_millis()`) at which the DLQ was
    /// last OBSERVED to be at the
    /// `MATRIX_INBOUND_DLQ_MAX_RECORDS`-record cap by
    /// `append_matrix_inbound_dlq`'s post-lock count check.
    ///
    /// Acts as a short-TTL "we're at cap" latch so subsequent failing
    /// dispatches can skip the ~MiB-class `tokio::fs::read_to_string`
    /// that `matrix_inbound_dlq_line_count` does once the byte-floor
    /// short-circuit is exceeded — the cap-confirm path is the one
    /// dispatched events were paying for under `dlq_io_lock` on every
    /// drop under sustained inbound-failure flood.
    ///
    /// Cleared (`None`) by the replay-rewrite path whenever it
    /// commits a file under cap, so a legitimate drain unblocks new
    /// appends within one tick. The TTL bounds the worst case where
    /// the replay-drain itself fails between cap-confirm and a fresh
    /// stamp: the next event past the TTL pays one full file read,
    /// re-confirms the cap, re-stamps. 10s is the picked TTL because
    /// a successful replay rewrite of even a saturated DLQ completes
    /// well under that on local disk, so the latch is self-healing
    /// without operator intervention.
    inbound_dlq_at_cap_since_ms: Option<i64>,
}

impl Default for MatrixRuntimeState {
    fn default() -> Self {
        Self {
            status: MatrixStatusMetadata::default(),
            devices: Vec::new(),
            verifications: Vec::new(),
            inbound_streak: FailureStreak::new(MATRIX_REFRESH_FAILURE_ERROR_THRESHOLD),
            pending_inbound_error: None,
            pending_inbound_error_kind: None,
            inbound_failure_generation: 0,
            pending_invite_systemic_error: None,
            dlq_io_lock: Arc::new(tokio::sync::Mutex::new(())),
            dlq_keys: Arc::new(MatrixDlqKeys::empty()),
            terminal_runtime_stamped: false,
            inbound_dlq_at_cap_since_ms: None,
        }
    }
}

/// TTL on the `inbound_dlq_at_cap_since_ms` short-circuit latch.
/// See the field doc on `MatrixRuntimeState::inbound_dlq_at_cap_since_ms`
/// for the rationale.
const MATRIX_INBOUND_DLQ_AT_CAP_LATCH_TTL_MS: i64 = 10_000;

#[derive(Debug, Clone, Copy)]
enum MatrixPeerDropKind {
    UnsupportedMsgtype,
    AllowlistRejection,
    BodyTooLarge,
    VerificationCapFull,
    EncryptedRoom,
}

impl MatrixPeerDropKind {
    fn as_str(self) -> &'static str {
        match self {
            MatrixPeerDropKind::UnsupportedMsgtype => "unsupported-msgtype",
            MatrixPeerDropKind::AllowlistRejection => "allowlist-rejection",
            MatrixPeerDropKind::BodyTooLarge => "body-too-large",
            MatrixPeerDropKind::VerificationCapFull => "verification-cap-full",
            MatrixPeerDropKind::EncryptedRoom => "encrypted-room",
        }
    }
}

impl MatrixRuntimeState {
    /// Snapshot the channel-status metadata.
    ///
    /// `pending_verification_count` is derived from `verifications.len()`
    /// at read time so the field is mechanically consistent with the
    /// underlying vec — eliminating the hand-maintained
    /// `guard.status.pending_verification_count = guard.verifications.len()`
    /// pattern that previously spread across every mutator and was a
    /// recurring source of out-of-sync bugs.
    pub fn status(&self) -> MatrixStatusMetadata {
        MatrixStatusMetadata {
            pending_verification_count: self.verifications.len(),
            ..self.status.clone()
        }
    }

    pub fn devices(&self) -> Vec<MatrixDeviceInfo> {
        self.devices.clone()
    }

    pub fn verifications(&self) -> Vec<MatrixVerificationInfo> {
        self.verifications.clone()
    }

    /// Bare streak bump for tests that exercise the streak threshold
    /// without an associated error message. Production code MUST use
    /// `record_inbound_failure_with_error` so `pending_inbound_error`
    /// stays in lockstep with the streak counter. A bare bump
    /// leaves apply_post_sync_maintenance reading
    /// (sticky=true, pending=None) and falling into Connected, which
    /// is silent ChannelStatus drift on a still-failing channel.
    #[cfg(test)]
    fn record_inbound_failure(&mut self) -> u32 {
        self.inbound_streak.record_failure()
    }

    /// Atomic record-and-stamp: bump the inbound streak AND store the
    /// error message in one mutation, so a maintenance reader can never
    /// observe `(sticky=true, pending=None)`. Without this, the streak
    /// bump and the error stamp were two separate `state.write()`
    /// acquisitions and a maintenance read between them surfaced an
    /// unhelpful generic "consecutive failures threshold reached"
    /// message instead of the actual error string.
    fn record_inbound_failure_with_error(
        &mut self,
        error: String,
        error_kind: &'static str,
    ) -> u32 {
        let count = self.inbound_streak.record_failure();
        self.inbound_failure_generation = self.inbound_failure_generation.saturating_add(1);
        // Always stamp the forensic timestamp so an operator
        // auditing "did inbound break in the last hour?" sees the
        // most recent failure even when sub-threshold (the streak
        // hasn't tripped sticky yet). Cleared in lockstep with
        // `pending_inbound_error` by `reset_inbound_failures`.
        self.status.last_inbound_failure_at = Some(now_millis());
        // Only stamp the error once we're sticky — sub-threshold
        // failures stay in the streak counter (so they decay) but
        // don't surface to the operator yet.
        if self.inbound_streak.is_sticky() {
            self.pending_inbound_error = Some(error);
            self.pending_inbound_error_kind = Some(error_kind.to_string());
        }
        count
    }

    fn reset_inbound_failures(&mut self) {
        // Same forensic-preservation discipline as
        // `clear_inbound_dlq_durability_error`: once the actor has
        // stamped a terminal runtime error, any late-arriving
        // maintenance task (DLQ replay or inbound dispatch that
        // finished between the terminal stamp and the maintenance/send
        // JoinSet cancel) must not wipe the operator-visible inbound
        // forensic counters that were valid at terminal-stamp time.
        // The runtime is winding down; there is no "next sync
        // iteration" to re-discover the error if the operator clears
        // the snapshot.
        if self.terminal_runtime_stamped {
            return;
        }
        self.inbound_streak.record_success();
        self.pending_inbound_error = None;
        self.pending_inbound_error_kind = None;
        self.status.last_inbound_failure_at = None;
        self.inbound_failure_generation = self.inbound_failure_generation.saturating_add(1);
    }

    fn compare_and_reset_inbound_failures(&mut self, observed_generation: u64) -> bool {
        if self.inbound_failure_generation != observed_generation {
            return false;
        }
        self.reset_inbound_failures();
        true
    }

    fn pending_inbound_error(&self) -> Option<&str> {
        self.pending_inbound_error.as_deref()
    }

    fn pending_inbound_error_kind(&self) -> Option<&str> {
        self.pending_inbound_error_kind.as_deref()
    }

    fn record_inbound_dlq_append_failure(&mut self, error: String) {
        let now = now_millis();
        self.status.inbound_dlq_append_failure_total = self
            .status
            .inbound_dlq_append_failure_total
            .saturating_add(1);
        self.status.inbound_dlq_durability_error = Some(error);
        // Stamp both forensic timestamps: durability_error_at
        // tracks the message lifetime (cleared by
        // clear_inbound_dlq_durability_error); the
        // last_inbound_dlq_append_failure_at counter increment
        // is cumulative — it sticks around even after the
        // durability error clears so an operator auditing past
        // failures sees when the most recent one happened.
        self.status.inbound_dlq_durability_error_at = Some(now);
        self.status.last_inbound_dlq_append_failure_at = Some(now);
    }

    /// Stamp a sticky operator-visible error when invite handling sees
    /// many failures in a single maintenance tick. Bypasses the
    /// `FailureStreak`'s 3-tick hysteresis so the channel-status
    /// `last_error` reflects the systemic problem on the next
    /// `cara status` poll, not 3 sync cycles later. Stored in a
    /// dedicated field — NOT in `inbound_dlq_durability_error` —
    /// because the recovery semantics differ: invite errors clear on
    /// a successful invite-handling tick (handled by
    /// `apply_post_sync_maintenance`'s record_phase_recovery path);
    /// DLQ durability errors clear only on a successful DLQ op.
    fn record_invite_systemic_failure(&mut self, error: String) {
        self.pending_invite_systemic_error = Some(error);
    }

    /// Clear the invite systemic-failure marker on a successful tick.
    fn clear_invite_systemic_failure(&mut self) {
        self.pending_invite_systemic_error = None;
    }

    /// Snapshot of the invite-systemic-failure marker. Read by
    /// `apply_post_sync_maintenance` to gate registry transitions.
    fn invite_systemic_error(&self) -> Option<&str> {
        self.pending_invite_systemic_error.as_deref()
    }

    /// Persist a capped list of event IDs that DLQ replay phase-3
    /// couldn't write back to disk. Surfaced via `MatrixStatusMetadata`
    /// so `cara status` shows the recovery list without grepping the
    /// journal. Append-and-truncate so a torrent of failures still
    /// shows the most recent IDs an operator can act on.
    fn record_inbound_dlq_lost_event_ids(&mut self, ids: impl IntoIterator<Item = String>) {
        let before = self.status.inbound_dlq_lost_event_ids.len();
        self.status.inbound_dlq_lost_event_ids.extend(ids);
        let total = self.status.inbound_dlq_lost_event_ids.len();
        // Stamp the forensic timestamp only when the call actually
        // appended at least one ID — a no-op call shouldn't bump
        // the timestamp and mislead operators about when the most
        // recent loss happened.
        if total > before {
            self.status.inbound_dlq_lost_event_ids_at = Some(now_millis());
        }
        if total > MATRIX_INBOUND_DLQ_LOST_IDS_CAP {
            // Keep the most recent N IDs; older entries fall off the
            // tail via drain-from-front.
            self.status
                .inbound_dlq_lost_event_ids
                .drain(0..(total - MATRIX_INBOUND_DLQ_LOST_IDS_CAP));
        }
    }

    /// Clear the lost-event list once a subsequent replay tick fully
    /// succeeds. Without this, a single transient phase-3 hiccup pins
    /// the IDs on `cara status` for the daemon's lifetime.
    ///
    /// Symmetric with `clear_inbound_dlq_durability_error`: the lost-
    /// event IDs and the durability error form a single coherent
    /// forensic surface that is stamped together by
    /// `log_lost_remaining` and `record_inbound_dlq_lost_event_ids`.
    /// Once a terminal runtime cause has been stamped, both must be
    /// preserved — a late-arriving maintenance task (DLQ replay that
    /// finished between the terminal stamp and the maintenance JoinSet
    /// cancel) must not wipe the operator-visible IDs the runtime
    /// recorded right before shutdown. The runtime is winding down;
    /// there is no "next sync iteration" to re-discover them if the
    /// operator clears them.
    fn clear_inbound_dlq_lost_event_ids(&mut self) {
        if self.terminal_runtime_stamped {
            return;
        }
        self.status.inbound_dlq_lost_event_ids.clear();
        self.status.inbound_dlq_lost_event_ids_at = None;
    }

    /// Clear the operator-visible DLQ durability error after a
    /// successful append or replay. Without this, a single transient
    /// disk hiccup pins the channel in Error state for the rest of the
    /// daemon's lifetime even when every subsequent DLQ operation
    /// succeeds. The cumulative `inbound_dlq_append_failure_total`
    /// counter remains so historical durability incidents stay
    /// auditable.
    fn clear_inbound_dlq_durability_error(&mut self) {
        // Once a terminal runtime cause has been stamped, the
        // forensic durability error is operator evidence — a
        // late-arriving maintenance task (DLQ replay that finished
        // between the terminal stamp and the maintenance JoinSet
        // cancel) must not wipe it. The runtime is winding down;
        // there is no "next sync iteration" to re-discover the
        // durability error if the operator clears it. Gate
        // forensic-wiping writes on the terminal flag so the
        // post-mortem snapshot survives.
        if self.terminal_runtime_stamped {
            return;
        }
        self.status.inbound_dlq_durability_error = None;
        self.status.inbound_dlq_durability_error_at = None;
    }

    /// Set the terminal-stamped flag so subsequent forensic-wiping
    /// maintenance writes (`clear_inbound_dlq_durability_error` and
    /// any siblings added later) no-op. Idempotent — calling this
    /// multiple times has no additional effect.
    pub(crate) fn mark_terminal_runtime_stamped(&mut self) {
        self.terminal_runtime_stamped = true;
    }

    #[cfg(test)]
    #[allow(dead_code)]
    pub(crate) fn terminal_runtime_stamped(&self) -> bool {
        self.terminal_runtime_stamped
    }

    /// Convenience predicate retained for the test suite. Production
    /// callers project `inbound_dlq_durability_error.is_some()`
    /// inline via `PostSyncStateSnapshot` to keep the post-sync
    /// dispatch decision atomic against concurrent handler writes.
    #[cfg_attr(not(test), allow(dead_code))]
    fn inbound_durability_error_is_sticky(&self) -> bool {
        self.status.inbound_dlq_durability_error.is_some()
    }

    fn inbound_dlq_durability_error(&self) -> Option<&str> {
        self.status.inbound_dlq_durability_error.as_deref()
    }

    fn record_peer_drop(&mut self, kind: MatrixPeerDropKind) -> u64 {
        match kind {
            MatrixPeerDropKind::UnsupportedMsgtype => {
                self.status.peer_drop_unsupported_msgtype_total = self
                    .status
                    .peer_drop_unsupported_msgtype_total
                    .saturating_add(1);
                self.status.peer_drop_unsupported_msgtype_total
            }
            MatrixPeerDropKind::AllowlistRejection => {
                self.status.peer_drop_allowlist_rejection_total = self
                    .status
                    .peer_drop_allowlist_rejection_total
                    .saturating_add(1);
                self.status.peer_drop_allowlist_rejection_total
            }
            MatrixPeerDropKind::BodyTooLarge => {
                self.status.peer_drop_body_too_large_total =
                    self.status.peer_drop_body_too_large_total.saturating_add(1);
                self.status.peer_drop_body_too_large_total
            }
            MatrixPeerDropKind::VerificationCapFull => {
                self.status.peer_drop_verification_cap_full_total = self
                    .status
                    .peer_drop_verification_cap_full_total
                    .saturating_add(1);
                self.status.peer_drop_verification_cap_full_total
            }
            MatrixPeerDropKind::EncryptedRoom => {
                self.status.peer_drop_encrypted_room_total =
                    self.status.peer_drop_encrypted_room_total.saturating_add(1);
                self.status.peer_drop_encrypted_room_total
            }
        }
    }

    fn record_inbound_dedupe_corrupt_lines(&mut self, count: u64) {
        if count == 0 {
            return;
        }
        self.status.inbound_dedupe_corrupt_line_total = self
            .status
            .inbound_dedupe_corrupt_line_total
            .saturating_add(count);
    }

    /// Get a long-lived handle to the daemon-lifetime DLQ AEAD key
    /// cache. The replay loop calls this once per tick and reuses
    /// the Arc for all per-record decode/encode operations,
    /// avoiding the Argon2id-per-tick cost the previous per-tick
    /// `MatrixDlqKeys::empty()` paid.
    pub(crate) fn dlq_keys(&self) -> Arc<MatrixDlqKeys> {
        Arc::clone(&self.dlq_keys)
    }

    pub(crate) fn dlq_io_lock(&self) -> Arc<tokio::sync::Mutex<()>> {
        Arc::clone(&self.dlq_io_lock)
    }

    /// Whether the inbound-dispatch streak has hit the operator-visible
    /// threshold. Sync-arm gate uses this to keep the channel in Error
    /// across successful syncs while inbound is sticky.
    fn inbound_streak_is_sticky(&self) -> bool {
        self.inbound_streak.is_sticky()
    }
}

pub struct MatrixRuntimeHandle {
    tx: mpsc::Sender<MatrixCommand>,
    state: Arc<RwLock<MatrixRuntimeState>>,
    completed: Arc<AtomicBool>,
    shutdown_complete: Arc<Notify>,
    /// JoinHandle for the runtime actor task. Held in a `Mutex` so
    /// `wait_for_shutdown` can take it for `.await` without keeping
    /// `&self` borrowed past the await. Without this handle, the
    /// runtime task would detach when `wait_for_shutdown` times out
    /// — leaving an orphaned actor running past
    /// `set_matrix_runtime(None)` and racing with the next daemon
    /// start.
    actor_handle: tokio::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl fmt::Debug for MatrixRuntimeHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MatrixRuntimeHandle")
            .finish_non_exhaustive()
    }
}

impl MatrixRuntimeHandle {
    #[cfg(test)]
    pub(crate) fn for_test() -> Arc<Self> {
        let (tx, _rx) = mpsc::channel(MATRIX_OUTBOUND_QUEUE_CAPACITY);
        Arc::new(Self {
            tx,
            state: Arc::new(RwLock::new(MatrixRuntimeState::default())),
            completed: Arc::new(AtomicBool::new(true)),
            shutdown_complete: Arc::new(Notify::new()),
            actor_handle: tokio::sync::Mutex::new(None),
        })
    }

    #[cfg(test)]
    pub(crate) fn set_devices_for_test(&self, devices: Vec<MatrixDeviceInfo>) {
        self.state.write().devices = devices;
    }

    pub fn channel(&self) -> MatrixChannel {
        MatrixChannel {
            tx: self.tx.clone(),
        }
    }

    pub(crate) async fn abort_startup_registration_failure(&self) {
        self.completed.store(true, Ordering::Release);
        self.shutdown_complete.notify_waiters();
        let handle = self.actor_handle.lock().await.take();
        if let Some(handle) = handle {
            handle.abort();
            let _ = handle.await;
        }
    }

    pub fn status(&self) -> MatrixStatusMetadata {
        self.state.read().status()
    }

    pub fn devices(&self) -> Vec<MatrixDeviceInfo> {
        self.state.read().devices()
    }

    pub fn verifications(&self) -> Vec<MatrixVerificationInfo> {
        verification::prune_verification_records(&self.state);
        self.state.read().verifications()
    }

    pub async fn wait_for_shutdown(&self, timeout: Duration) -> bool {
        let completed = self.completed.clone();
        let notify = self.shutdown_complete.clone();
        let timed_out = tokio::time::timeout(timeout, async move {
            loop {
                // Register the waiter BEFORE checking the flag.
                // Constructing `Notified` via `.notified()` and
                // pinning + enabling it places this task on the
                // notify list synchronously. Without this, the
                // sequence `flag.load → notify_waiters → notified()`
                // loses the wakeup: the runtime stores `completed=true`
                // and calls `notify_waiters()` before our `Notified`
                // future is registered, and `notify_waiters()` does
                // not retain permits the way `notify_one()` does.
                // Result was a stuck wait_for_shutdown that timed
                // out even though shutdown had already completed.
                let notified = notify.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();
                if completed.load(Ordering::Acquire) {
                    return;
                }
                notified.await;
            }
        })
        .await
        .is_err();
        // If the wait timed out the actor is still running. Abort it
        // before returning so it cannot leak past
        // `set_matrix_runtime(None)`. Abort cancels the async future;
        // any in-flight `spawn_blocking` task DETACHES rather than
        // terminates (the blocking thread runs the closure to
        // completion on the blocking pool). The dlq_io_lock async
        // guard IS released by the abort. Cross-daemon races against
        // the still-running blocking write are prevented by the
        // daemon's rekey-lock.
        if timed_out {
            warn!(
                timeout_seconds = timeout.as_secs(),
                "Matrix runtime did not finish within shutdown timeout; aborting"
            );
            // Bind the take() result to a local so the temporary
            // MutexGuard drops at end-of-statement instead of being
            // held across the 2s `timeout(handle).await`. With the
            // guard held that long, any future second caller to
            // `actor_handle.lock()` would block on an aborted handle.
            let handle_opt = self.actor_handle.lock().await.take();
            if let Some(handle) = handle_opt {
                handle.abort();
                if tokio::time::timeout(Duration::from_secs(2), handle)
                    .await
                    .is_err()
                {
                    error!(
                        pid = std::process::id(),
                        "Matrix runtime did not honor abort within 2s — actor task \
                         remains attached. Daemon shutdown will release the rekey-lock; \
                         operator action: confirm the carapace process exits, then \
                         `kill -KILL` if needed before launching a new daemon."
                    );
                }
            }
        }
        !timed_out
    }

    pub async fn start_verification(
        &self,
        user_id: String,
        device_id: Option<String>,
    ) -> Result<MatrixVerificationInfo, MatrixError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        let caller_cancel = CancellationToken::new();
        self.tx
            .try_send(MatrixCommand::StartVerification {
                user_id,
                device_id,
                reply_tx,
                caller_cancel: caller_cancel.clone(),
            })
            .map_err(matrix_command_enqueue_error)?;
        await_matrix_command_reply(reply_rx, caller_cancel, "verification start").await?
    }

    pub async fn accept_verification(
        &self,
        flow_id: String,
    ) -> Result<MatrixVerificationInfo, MatrixError> {
        self.verification_action(MatrixVerificationAction::Accept, flow_id)
            .await
    }

    pub async fn confirm_verification(
        &self,
        flow_id: String,
        matches: bool,
    ) -> Result<MatrixVerificationInfo, MatrixError> {
        self.verification_action(MatrixVerificationAction::Confirm { matches }, flow_id)
            .await
    }

    pub async fn cancel_verification(
        &self,
        flow_id: String,
    ) -> Result<MatrixVerificationInfo, MatrixError> {
        self.verification_action(MatrixVerificationAction::Cancel, flow_id)
            .await
    }

    async fn verification_action(
        &self,
        action: MatrixVerificationAction,
        flow_id: String,
    ) -> Result<MatrixVerificationInfo, MatrixError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        let caller_cancel = CancellationToken::new();
        self.tx
            .try_send(MatrixCommand::VerificationAction {
                action,
                flow_id,
                reply_tx,
                caller_cancel: caller_cancel.clone(),
            })
            .map_err(matrix_command_enqueue_error)?;
        await_matrix_command_reply(reply_rx, caller_cancel, "verification action").await?
    }
}

fn matrix_command_enqueue_error<T>(err: mpsc::error::TrySendError<T>) -> MatrixError {
    match err {
        // Distinguish in-process backpressure (transient, retry
        // shortly) from homeserver-bound timeouts (the
        // `VerificationTimeout` variant). The previous semantic
        // pun routed queue-full as 504 GATEWAY_TIMEOUT — wrong
        // status class for what is local backpressure.
        mpsc::error::TrySendError::Full(_) => MatrixError::CommandQueueFull,
        mpsc::error::TrySendError::Closed(_) => MatrixError::NotConnected,
    }
}

async fn await_matrix_command_reply(
    reply_rx: oneshot::Receiver<Result<MatrixVerificationInfo, MatrixError>>,
    caller_cancel: CancellationToken,
    label: &'static str,
) -> Result<Result<MatrixVerificationInfo, MatrixError>, MatrixError> {
    match tokio::time::timeout(MATRIX_VERIFICATION_CALLER_TIMEOUT, reply_rx).await {
        Ok(Ok(result)) => Ok(result),
        Ok(Err(_)) => Err(MatrixError::NotConnected),
        Err(_) => {
            caller_cancel.cancel();
            Err(MatrixError::VerificationTimeout(format!(
                "Matrix {label} did not complete within {} seconds",
                MATRIX_VERIFICATION_CALLER_TIMEOUT.as_secs()
            )))
        }
    }
}

#[derive(Debug, Clone)]
pub struct MatrixChannel {
    tx: mpsc::Sender<MatrixCommand>,
}

impl ChannelPluginInstance for MatrixChannel {
    fn get_info(&self) -> Result<PluginChannelInfo, BindingError> {
        Ok(PluginChannelInfo {
            id: MATRIX_CHANNEL_ID.to_string(),
            label: MATRIX_CHANNEL_NAME.to_string(),
            selection_label: MATRIX_CHANNEL_NAME.to_string(),
            docs_path: "docs/channels.md#matrix".to_string(),
            blurb: "Send and receive Matrix / Element room messages.".to_string(),
            order: 45,
        })
    }

    fn get_capabilities(&self) -> Result<ChannelCapabilities, BindingError> {
        Ok(ChannelCapabilities {
            chat_types: vec![ChatType::Dm, ChatType::Group, ChatType::Channel],
            reply: true,
            threads: false,
            media: false,
            typing_indicators: false,
            read_receipts: false,
            ..Default::default()
        })
    }

    fn send_text(&self, ctx: OutboundContext) -> Result<DeliveryResult, BindingError> {
        let (reply_tx, reply_rx) = std_mpsc::sync_channel(1);
        let caller_cancel = CancellationToken::new();
        let command = MatrixCommand::SendText {
            ctx,
            reply_tx,
            caller_cancel: caller_cancel.clone(),
        };
        match self.tx.try_send(command) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                return Ok(matrix_retryable_delivery_result_with_retry_after(
                    format!(
                        "Matrix outbound queue is full; retrying in {} seconds",
                        MATRIX_OUTBOUND_ENQUEUE_RETRY_AFTER.as_secs()
                    ),
                    Some(MATRIX_OUTBOUND_ENQUEUE_RETRY_AFTER.as_millis() as i64),
                    Some(MatrixError::CommandQueueFull.kind()),
                ));
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                return Err(BindingError::MatrixRuntimeUnavailable(
                    "Matrix runtime is not running".to_string(),
                ));
            }
        }
        match reply_rx.recv_timeout(MATRIX_OUTBOUND_REPLY_TIMEOUT) {
            Ok(Ok(result)) => Ok(result),
            Ok(Err(err)) => matrix_send_error_to_binding_result(err),
            Err(std_mpsc::RecvTimeoutError::Timeout) => {
                caller_cancel.cancel();
                Ok(matrix_retryable_delivery_result(format!(
                    "Matrix send did not complete within {} seconds; cancelled pending Matrix send",
                    MATRIX_OUTBOUND_REPLY_TIMEOUT.as_secs()
                )))
            }
            Err(std_mpsc::RecvTimeoutError::Disconnected) => {
                Err(BindingError::MatrixRuntimeUnavailable(
                    "Matrix runtime stopped before send completed".to_string(),
                ))
            }
        }
    }

    fn send_media(&self, _ctx: OutboundContext) -> Result<DeliveryResult, BindingError> {
        Err(BindingError::CallError(
            "Matrix media delivery is not supported".to_string(),
        ))
    }
}

fn matrix_send_error_to_binding_result(err: MatrixError) -> Result<DeliveryResult, BindingError> {
    // Redact the entire MatrixError before crossing the binding
    // boundary. Variants that interpolate SDK-error strings
    // (`SendFailed { message: matrix_sdk::Error.to_string(), ... }`,
    // `SyncFailed(...)`, `SendTerminal(...)`) carry homeserver-
    // controlled bytes — and the resulting String flows via
    // `BindingError::CallError` into delivery-result error
    // surfaces that don't always pass through `RedactingWriter`.
    // Wrapping at this single chokepoint matches the
    // `matrix_error_for_status` discipline and keeps every send-
    // path consumer terminal-safe.
    let redacted = crate::logging::redact::RedactedDisplay(&err).to_string();
    let kind = err.kind();
    match err {
        MatrixError::SendFailed { retry_after_ms, .. } => Ok(
            matrix_retryable_delivery_result_with_retry_after(redacted, retry_after_ms, Some(kind)),
        ),
        MatrixError::SyncFailed(_) | MatrixError::AuthProbe(_) => Ok(
            matrix_retryable_delivery_result_with_retry_after(redacted, None, Some(kind)),
        ),
        MatrixError::NotConnected => Ok(matrix_retryable_delivery_result_with_retry_after(
            "Matrix runtime is not connected".to_string(),
            None,
            Some(kind),
        )),
        MatrixError::CommandQueueFull => Ok(matrix_retryable_delivery_result_with_retry_after(
            "Matrix runtime command queue is full; retry shortly".to_string(),
            None,
            Some(kind),
        )),
        MatrixError::Auth(_)
        | MatrixError::AuthSessionUserMismatch { .. }
        | MatrixError::AuthSessionDeviceMismatch { .. }
        | MatrixError::AuthSessionMissingDeviceId
        | MatrixError::AuthTokenRevoked(_) => Err(BindingError::MatrixRuntimeUnavailable(redacted)),
        MatrixError::RoomNotFound(_) => Err(BindingError::CallError(redacted)),
        MatrixError::UnsupportedRoom(_) => Err(BindingError::CallError(redacted)),
        // Terminal send classes — homeserver has declared the failure
        // permanent for this token+room. Retrying issues an identical
        // request and earns an identical rejection; route as a
        // non-retryable CallError so the dispatch pipeline records
        // the failure once and stops.
        MatrixError::SendTerminal(_) => Err(BindingError::CallError(redacted)),
        MatrixError::InvalidConfigRoot
        | MatrixError::InvalidString { .. }
        | MatrixError::InvalidBool { .. }
        | MatrixError::InvalidStringArray { .. }
        | MatrixError::InvalidLength { .. }
        | MatrixError::InvalidUrl { .. }
        | MatrixError::AllowlistTooLarge { .. }
        | MatrixError::MissingHomeserverUrl
        | MatrixError::MissingUserId
        | MatrixError::MissingCredentials
        | MatrixError::MissingDeviceIdForTokenRestore
        | MatrixError::ClientBuild(_)
        | MatrixError::StartupFailed(_)
        | MatrixError::InterruptedRekey(_)
        | MatrixError::RecoveryKeyRestoreFailed { .. }
        | MatrixError::CrossSigningBootstrapFailed(_)
        | MatrixError::EncryptedStateIo(_)
        | MatrixError::RecoveryStateProbeFailed(_)
        | MatrixError::RecoveryStateIo(_)
        | MatrixError::RecoveryConfigPrecondition(_)
        | MatrixError::RecoveryKeyPromotionRefused(_)
        | MatrixError::Clock(_)
        | MatrixError::TokenPersistence(_)
        | MatrixError::EncryptedStorePassphraseMismatch { .. }
        | MatrixError::InstallationId(_)
        | MatrixError::DlqCrypto(_)
        | MatrixError::DlqIo(_)
        | MatrixError::DlqSerialization(_)
        | MatrixError::DlqDispatchFailure(_)
        | MatrixError::DlqCapSaturation(_)
        | MatrixError::LegacyDlqEnvelopeRefused(_)
        | MatrixError::SessionHistoryCorrupt(_)
        | MatrixError::StoreKeyDerivation
        | MatrixError::MissingStoreSecret
        | MatrixError::SyncLoopGaveUp { .. }
        | MatrixError::VerificationFlowNotFound(_)
        | MatrixError::InvalidUserId(_)
        | MatrixError::DeviceNotFound { .. }
        | MatrixError::UserIdentityNotFound(_)
        | MatrixError::VerificationFlowNotReady { .. }
        | MatrixError::Verification(_)
        | MatrixError::VerificationTimeout(_)
        | MatrixError::VerificationCancelled { .. } => Err(BindingError::CallError(redacted)),
    }
}

enum MatrixCommand {
    SendText {
        ctx: OutboundContext,
        reply_tx: std_mpsc::SyncSender<Result<DeliveryResult, MatrixError>>,
        caller_cancel: CancellationToken,
    },
    StartVerification {
        user_id: String,
        device_id: Option<String>,
        reply_tx: oneshot::Sender<Result<MatrixVerificationInfo, MatrixError>>,
        caller_cancel: CancellationToken,
    },
    VerificationAction {
        flow_id: String,
        action: MatrixVerificationAction,
        reply_tx: oneshot::Sender<Result<MatrixVerificationInfo, MatrixError>>,
        caller_cancel: CancellationToken,
    },
}

enum MatrixVerificationAction {
    Accept,
    Confirm { matches: bool },
    Cancel,
}

pub fn resolve_matrix_config(cfg: &Value) -> Result<MatrixConfigResolve, MatrixError> {
    let Some(matrix_value) = cfg.get("matrix") else {
        return Ok(MatrixConfigResolve::Missing);
    };
    let matrix = matrix_value
        .as_object()
        .ok_or(MatrixError::InvalidConfigRoot)?;

    if read_bool(matrix, "enabled")? == Some(false) {
        return Ok(MatrixConfigResolve::Disabled);
    }

    // Matrix homeserver URL is operator-controlled protected configuration.
    // We do not DNS-resolve and block private ranges here because self-hosted
    // Matrix deployments commonly live on private or loopback addresses.
    let homeserver_url = read_string(matrix, "homeserverUrl")?
        .or_else(|| crate::config::read_config_env("MATRIX_HOMESERVER_URL"))
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .ok_or(MatrixError::MissingHomeserverUrl)?;
    validate_field_length(
        &homeserver_url,
        "homeserverUrl",
        MATRIX_HOMESERVER_URL_MAX_BYTES,
    )?;
    validate_homeserver_url(&homeserver_url)?;

    let user_id = read_string(matrix, "userId")?
        .or_else(|| crate::config::read_config_env("MATRIX_USER_ID"))
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .ok_or(MatrixError::MissingUserId)?;
    validate_field_length(&user_id, "userId", MATRIX_USER_ID_MAX_BYTES)?;

    // Wrap the raw read in Zeroizing FIRST so the un-trimmed source
    // String is wiped on drop. The trim-via-to_string chain otherwise
    // allocates a fresh String for the trimmed bytes and drops the
    // un-trimmed source UN-zeroized (the token bytes remain in the
    // allocator's freelist until reuse, observable via coredump or
    // post-free heap inspection). When the trim is a no-op (no
    // leading/trailing whitespace, the common case), reuse the
    // original Zeroizing allocation rather than allocating a fresh
    // one. The fresh trimmed allocation IS also Zeroized — both
    // allocations are wrapped before any drop.
    let access_token = read_string(matrix, "accessToken")?
        .or_else(|| crate::config::read_config_env("MATRIX_ACCESS_TOKEN"))
        .map(zeroize::Zeroizing::new)
        .and_then(|raw| {
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                None
            } else if trimmed.len() == raw.len() {
                Some(raw)
            } else {
                Some(zeroize::Zeroizing::new(trimmed.to_string()))
            }
        });
    // Same zeroize-source-then-trim discipline as access_token above.
    // The pre-fix shape didn't trim the value passed downstream at
    // all — only the empty-check trimmed — so a config or env value
    // with trailing whitespace was sent to the homeserver verbatim
    // and "rejected as wrong password" with no operator diagnostic.
    let password = read_string(matrix, "password")?
        .or_else(|| crate::config::read_config_env("MATRIX_PASSWORD"))
        .map(zeroize::Zeroizing::new)
        .and_then(|raw| {
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                None
            } else if trimmed.len() == raw.len() {
                Some(raw)
            } else {
                Some(zeroize::Zeroizing::new(trimmed.to_string()))
            }
        });
    if access_token.is_none() && password.is_none() {
        return Err(MatrixError::MissingCredentials);
    }
    let device_id = read_string(matrix, "deviceId")?
        .or_else(|| crate::config::read_config_env("MATRIX_DEVICE_ID"))
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    if let Some(ref id) = device_id {
        validate_field_length(id, "deviceId", MATRIX_DEVICE_ID_MAX_BYTES)?;
    }
    // Token-restore path requires both accessToken and deviceId. Allowing
    // accessToken without deviceId would silently fall through to the
    // password-login branch (when password is also configured), creating
    // a fresh device on every restart and churning the bot's
    // cross-signing identity. Reject the ambiguous combo at config-resolve
    // time so operators are explicit: either supply both for token
    // restore, or remove accessToken to opt into password login.
    if access_token.is_some() && device_id.is_none() {
        return Err(MatrixError::MissingDeviceIdForTokenRestore);
    }

    let encrypted = read_bool(matrix, "encrypted")?.unwrap_or(true);
    let explicit_passphrase = read_string(matrix, "storePassphrase")?
        .or_else(|| crate::config::read_config_env("MATRIX_STORE_PASSPHRASE"))
        .filter(|value| !value.trim().is_empty());
    if !encrypted && explicit_passphrase.is_some() {
        // The schema validator already issues a Severity::Warning for
        // this combination; emit a startup warn so operators tailing
        // logs notice the value will be silently ignored.
        warn!(
            "matrix.storePassphrase is set but matrix.encrypted=false; \
             the passphrase will be ignored. Set matrix.encrypted=true to use it."
        );
    }
    let security = if encrypted {
        let source = match explicit_passphrase {
            Some(passphrase) => PassphraseSource::Explicit(NonEmptyPassphrase::new(passphrase)?),
            None => PassphraseSource::DeriveFromConfigPassword,
        };
        MatrixSecurity::Encrypted {
            passphrase_source: source,
        }
    } else {
        MatrixSecurity::Unencrypted
    };

    Ok(MatrixConfigResolve::Configured(MatrixConfig {
        homeserver_url,
        user_id,
        access_token,
        password,
        device_id,
        security,
        auto_join: read_auto_join(matrix)?,
        legacy_dlq_envelope_policy: read_legacy_dlq_envelope_policy(matrix)?,
    }))
}

fn read_legacy_dlq_envelope_policy(
    matrix: &serde_json::Map<String, Value>,
) -> Result<MatrixLegacyDlqEnvelopePolicy, MatrixError> {
    let Some(value) = matrix.get("inboundDlq") else {
        return Ok(MatrixLegacyDlqEnvelopePolicy::Accept);
    };
    let object = value.as_object().ok_or(MatrixError::InvalidString {
        field: "inboundDlq",
    })?;
    // SECURITY/COMPAT: do NOT reject unknown keys here. The rest of
    // parse_matrix_config ignores unknown top-level keys; matching
    // that convention is also a forward-compat requirement for a
    // released product. If a future binary adds a sibling option
    // (e.g. `argon2idMemoryKib`, `maxRecords`) and the operator
    // later downgrades for any reason, a strict-keys check would
    // refuse to start with `InvalidString { field: "inboundDlq" }`
    // and no migration path. Log unknown keys at warn so config
    // drift is observable but non-fatal.
    let unknown: Vec<&str> = object
        .keys()
        .filter(|key| key.as_str() != "legacyEnvelopePolicy")
        .map(String::as_str)
        .collect();
    if !unknown.is_empty() {
        tracing::warn!(
            unknown_keys = ?unknown,
            "matrix.inboundDlq: ignoring unknown keys; this binary may be older \
             than the config or the keys are typos. Known: legacyEnvelopePolicy."
        );
    }
    let Some(value) = object.get("legacyEnvelopePolicy") else {
        return Ok(MatrixLegacyDlqEnvelopePolicy::Accept);
    };
    match value.as_str().map(str::trim) {
        Some("accept") => Ok(MatrixLegacyDlqEnvelopePolicy::Accept),
        Some("refuse") => Ok(MatrixLegacyDlqEnvelopePolicy::Refuse),
        _ => Err(MatrixError::InvalidString {
            field: "inboundDlq.legacyEnvelopePolicy",
        }),
    }
}

fn read_string(
    obj: &serde_json::Map<String, Value>,
    field: &'static str,
) -> Result<Option<String>, MatrixError> {
    let Some(value) = obj.get(field) else {
        return Ok(None);
    };
    value
        .as_str()
        .map(|value| Some(value.to_string()))
        .ok_or(MatrixError::InvalidString { field })
}

fn read_bool(
    obj: &serde_json::Map<String, Value>,
    field: &'static str,
) -> Result<Option<bool>, MatrixError> {
    let Some(value) = obj.get(field) else {
        return Ok(None);
    };
    value
        .as_bool()
        .map(Some)
        .ok_or(MatrixError::InvalidBool { field })
}

fn read_auto_join(
    matrix: &serde_json::Map<String, Value>,
) -> Result<MatrixAutoJoinConfig, MatrixError> {
    let Some(auto_join) = matrix.get("autoJoin").and_then(|value| value.as_object()) else {
        return Ok(MatrixAutoJoinConfig::default());
    };
    Ok(MatrixAutoJoinConfig {
        allow_users: read_string_set(auto_join, "allowUsers")?,
        allow_server_names: read_string_set(auto_join, "allowServerNames")?,
    })
}

fn read_string_set(
    obj: &serde_json::Map<String, Value>,
    field: &'static str,
) -> Result<BTreeSet<String>, MatrixError> {
    let Some(value) = obj.get(field) else {
        return Ok(BTreeSet::new());
    };
    let Some(values) = value.as_array() else {
        return Err(MatrixError::InvalidStringArray { field });
    };
    if values.len() > MATRIX_ALLOWLIST_MAX_ENTRIES {
        return Err(MatrixError::AllowlistTooLarge {
            field,
            max: MATRIX_ALLOWLIST_MAX_ENTRIES,
            got: values.len(),
        });
    }
    let mut out = BTreeSet::new();
    for value in values {
        let Some(value) = value.as_str() else {
            return Err(MatrixError::InvalidStringArray { field });
        };
        let trimmed = value.trim();
        if trimmed.is_empty() {
            continue;
        }
        validate_field_length(trimmed, field, MATRIX_ALLOWLIST_ENTRY_MAX_BYTES)?;
        out.insert(trimmed.to_string());
    }
    Ok(out)
}

/// Length cap for an operator-config string field. Bounded to
/// prevent a poisoned shared-Git-repo config from inflating
/// per-error-string allocations or pushing identifier strings
/// past the matrix-sdk's expected upper bounds.
pub(crate) const MATRIX_HOMESERVER_URL_MAX_BYTES_PUB: usize = MATRIX_HOMESERVER_URL_MAX_BYTES;
pub(crate) const MATRIX_USER_ID_MAX_BYTES_PUB: usize = MATRIX_USER_ID_MAX_BYTES;
pub(crate) const MATRIX_DEVICE_ID_MAX_BYTES_PUB: usize = MATRIX_DEVICE_ID_MAX_BYTES;
pub(crate) const MATRIX_ALLOWLIST_MAX_ENTRIES_PUB: usize = MATRIX_ALLOWLIST_MAX_ENTRIES;
pub(crate) const MATRIX_ALLOWLIST_ENTRY_MAX_BYTES_PUB: usize = MATRIX_ALLOWLIST_ENTRY_MAX_BYTES;

pub(crate) fn validate_field_length(
    value: &str,
    field: &'static str,
    max: usize,
) -> Result<(), MatrixError> {
    if value.len() > max {
        return Err(MatrixError::InvalidLength {
            field,
            max,
            got: value.len(),
        });
    }
    Ok(())
}

/// Parse-time validator for `matrix.homeserverUrl`. Rejects:
/// - non-`http` / non-`https` schemes (matrix-sdk only supports HTTP(S))
/// - URLs with embedded `user:pass` (matrix-sdk doesn't use them; the
///   leak path is the URL flowing through tracing into operator logs)
/// - non-empty path / query / fragment (a homeserver is `host:port`;
///   `https://matrix.example.com/foo` is operator-config error)
pub(crate) fn validate_homeserver_url(url: &str) -> Result<(), MatrixError> {
    // SECURITY (B132): reject non-ASCII bytes in the operator-
    // supplied URL string before `url::Url::parse` applies IDNA
    // normalization. `url::Url::parse` accepts Unicode hosts and
    // silently Punycode-encodes them via IDNA. An operator who
    // pastes a phishing-tier homograph URL (`матrix.org` →
    // `xn--xrx-2lcd.org`) produces a valid `MatrixConfig` and the
    // daemon restores a session to the attacker-controlled host.
    // The runtime validator is the last line — schema validation
    // can be bypassed by hand-edited config — so the homograph
    // defense lives here. Operators who legitimately want a
    // non-ASCII homeserver must explicitly Punycode it
    // (`xn--…`); that round-trip makes the choice visible.
    if !url.is_ascii() {
        return Err(MatrixError::InvalidUrl {
            field: "homeserverUrl",
            reason: "non-ASCII hostnames must be supplied as Punycode (xn--...) to avoid IDN homograph attacks",
        });
    }
    let parsed = url::Url::parse(url).map_err(|_| MatrixError::InvalidUrl {
        field: "homeserverUrl",
        reason: "malformed URL",
    })?;
    match parsed.scheme() {
        "http" | "https" => {}
        _ => {
            return Err(MatrixError::InvalidUrl {
                field: "homeserverUrl",
                reason: "scheme must be http or https",
            });
        }
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(MatrixError::InvalidUrl {
            field: "homeserverUrl",
            reason: "embedded user:pass not allowed",
        });
    }
    if parsed.host_str().map(str::is_empty).unwrap_or(true) {
        return Err(MatrixError::InvalidUrl {
            field: "homeserverUrl",
            reason: "host must not be empty",
        });
    }
    if parsed.path() != "/" && !parsed.path().is_empty() {
        return Err(MatrixError::InvalidUrl {
            field: "homeserverUrl",
            reason: "path component must be empty or `/`",
        });
    }
    if parsed.query().is_some() {
        return Err(MatrixError::InvalidUrl {
            field: "homeserverUrl",
            reason: "query component must not be set",
        });
    }
    if parsed.fragment().is_some() {
        return Err(MatrixError::InvalidUrl {
            field: "homeserverUrl",
            reason: "fragment must not be set",
        });
    }
    Ok(())
}

pub fn derive_matrix_store_key(
    config_password: &[u8],
    installation_id: &[u8],
) -> Result<zeroize::Zeroizing<[u8; 32]>, MatrixError> {
    let hk = Hkdf::<Sha256>::new(Some(installation_id), config_password);
    // Wrap immediately so the OKM never exists as an unzeroed
    // stack value. `Zeroizing<[u8; 32]>` zeroes on Drop. Callers
    // that need the raw bytes can `&*key` / `key.as_slice()`.
    let mut okm = zeroize::Zeroizing::new([0u8; 32]);
    hk.expand(MATRIX_STORE_INFO, &mut *okm)
        .map_err(|_| MatrixError::StoreKeyDerivation)?;
    Ok(okm)
}

/// Returns the Matrix SDK store passphrase as `Zeroizing<String>`
/// so callers cannot accidentally leave the value in an un-zeroed
/// heap allocation. The daemon path holds this through
/// `build_authenticated_client` and SQLite store opens; the
/// per-call `Zeroizing` ensures heap inspection / post-drop reuse
/// can't recover the passphrase. `Option<...>` is preserved because
/// `MatrixSecurity::Plain` legitimately has no passphrase.
pub fn resolve_matrix_store_passphrase(
    state_dir: &Path,
    config: &MatrixConfig,
) -> Result<Option<zeroize::Zeroizing<String>>, MatrixError> {
    let MatrixSecurity::Encrypted { passphrase_source } = &config.security else {
        return Ok(None);
    };
    match passphrase_source {
        PassphraseSource::Explicit(passphrase) => Ok(Some(zeroize::Zeroizing::new(
            passphrase.as_str().to_string(),
        ))),
        PassphraseSource::DeriveFromConfigPassword => {
            // Daemon-side detection of an interrupted
            // `cara matrix rekey-store --new`. If the store_passphrase
            // file isn't pinned yet but the rotation marker / pending
            // passphrase exists, the SQLite stores may already hold
            // the new cipher; falling through to the OLD HKDF-derived
            // key would surface a generic "decrypt failed" error
            // without telling the operator how to recover. Surface a
            // typed StartupFailed pointing at the recovery command
            // instead.
            let pending = matrix_store_pending_passphrase_file_path(state_dir);
            let marker = matrix_store_rekey_marker_path(state_dir);
            let final_path = matrix_store_passphrase_file_path(state_dir);
            let final_exists = matrix_rekey_path_exists(
                &final_path,
                "Matrix store passphrase",
                MatrixError::EncryptedStateIo,
            )?;
            let pending_exists = matrix_rekey_path_exists(
                &pending,
                "Matrix store pending passphrase",
                MatrixError::EncryptedStateIo,
            )?;
            let marker_exists = matrix_rekey_path_exists(
                &marker,
                "Matrix store rekey marker",
                MatrixError::RecoveryStateIo,
            )?;
            if !final_exists && (pending_exists || marker_exists) {
                // The Display prefix ("Matrix store rekey interrupted: ")
                // already names the failure class; the constructor
                // message carries the file-path evidence and the
                // operator's recovery command without restating the
                // category.
                return Err(MatrixError::InterruptedRekey(format!(
                    "{} or {} present without {}. Re-run \
                     `cara matrix rekey-store --new` to advance or roll back the in-flight \
                     rotation before starting the daemon.",
                    pending.display(),
                    marker.display(),
                    final_path.display()
                )));
            }
            if let Some(passphrase) = read_matrix_store_passphrase_file(state_dir)? {
                return Ok(Some(passphrase));
            }
            derive_matrix_store_passphrase_from_config_password(state_dir)
                .map(|s| Some(zeroize::Zeroizing::new(s)))
        }
    }
}

/// Pure HKDF derivation of the Matrix store passphrase from
/// `CARAPACE_CONFIG_PASSWORD` + the per-installation salt. Bypasses
/// the interrupted-rekey StartupFailed gate in
/// `resolve_matrix_store_passphrase` so the rekey CLI's recovery path
/// (`recover_interrupted_matrix_store_rekey`) can derive the OLD
/// passphrase even when the on-disk state matches the
/// "interrupted rekey" pattern (which is the entire point of running
/// recovery in the first place). The daemon must NOT call this
/// directly — it goes through `resolve_matrix_store_passphrase` to
/// preserve the fail-closed startup detection.
pub(crate) fn derive_matrix_store_passphrase_from_config_password(
    state_dir: &Path,
) -> Result<String, MatrixError> {
    // Read the password through the Zeroizing helper so the heap
    // allocation is wiped on drop. derive_matrix_store_key only
    // borrows the bytes for HKDF; once it returns, the password
    // wrapper drops and the heap is zeroed.
    let password = crate::config::read_process_env_zeroizing("CARAPACE_CONFIG_PASSWORD")
        .filter(|value| !value.is_empty())
        .ok_or(MatrixError::MissingStoreSecret)?;
    let installation_id = read_or_create_installation_id(state_dir)?;
    derive_matrix_store_key(password.as_bytes(), installation_id.as_bytes()).map(hex::encode)
}

pub(crate) fn matrix_store_pending_passphrase_file_path(state_dir: &Path) -> PathBuf {
    state_dir.join("matrix").join("store_passphrase.pending")
}

pub(crate) fn matrix_store_rekey_marker_path(state_dir: &Path) -> PathBuf {
    state_dir.join("matrix").join("store_passphrase.rekeying")
}

pub(crate) fn matrix_store_passphrase_file_path(state_dir: &Path) -> PathBuf {
    state_dir.join("matrix").join("store_passphrase")
}

/// Maximum bytes the runtime resolver (and the schema validator) will
/// read from `<state_dir>/matrix/store_passphrase`.
///
/// The validator only needs to know whether the file is non-empty
/// after trim; the actual passphrase has no useful upper bound near
/// this cap, so reading more than 64 KiB would be a sign that
/// something is wrong (FIFO streaming, accidental log redirect,
/// hostile attacker placing a multi-GB file). Without a cap the
/// runtime startup path could be DoS'd by anyone who can write
/// inside the matrix state dir.
pub(crate) const MATRIX_STORE_PASSPHRASE_FILE_MAX_BYTES: u64 = 64 * 1024;

fn matrix_rekey_path_exists(
    path: &Path,
    label: &'static str,
    error_kind: impl FnOnce(String) -> MatrixError,
) -> Result<bool, MatrixError> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(error_kind(format!(
            "failed to inspect {label} at {}: {err}",
            path.display()
        ))),
    }
}

fn read_matrix_store_passphrase_file(
    state_dir: &Path,
) -> Result<Option<zeroize::Zeroizing<String>>, MatrixError> {
    use std::io::Read;
    let path = matrix_store_passphrase_file_path(state_dir);
    // Follow symlinks so operators can route the passphrase through
    // a secret-management tool (1Password, `pass`, secret volumes),
    // but verify the final target is a regular file — a FIFO/socket
    // would otherwise hang `File::open` or block on read, locking up
    // daemon startup. Mirrors `inspect_matrix_store_passphrase_file`
    // in `config/schema.rs` so the validator and the resolver agree.
    //
    // SECURITY: open the file FIRST with O_NONBLOCK so the open()
    // itself does NOT hang when a same-uid attacker swaps the dirent
    // to a FIFO with no writer. The prior `File::open(&path)` could
    // block during open(2) for a FIFO; the held-fd file-type check
    // was never reached. After open we fstat the held fd and refuse
    // anything that is not a regular file, then proceed to read.
    // Regular files ignore O_NONBLOCK (no kernel-side blocking
    // semantics) so the subsequent `take().read_to_string()` runs
    // normally on the happy path. Mirrors the equivalent fix at
    // `inspect_matrix_store_passphrase_file` in `config/schema.rs`.
    let file = match crate::paths::open_regular_file_no_hang(&path) {
        Ok(Some(file)) => file,
        Ok(None) => return Ok(None),
        Err(err) => {
            return Err(MatrixError::EncryptedStateIo(format!(
                "failed to open Matrix store passphrase file {}: {err}",
                path.display()
            )));
        }
    };
    let metadata = file.metadata().map_err(|err| {
        MatrixError::EncryptedStateIo(format!(
            "failed to inspect Matrix store passphrase file {}: {err}",
            path.display()
        ))
    })?;
    if !metadata.is_file() {
        return Err(MatrixError::EncryptedStateIo(format!(
            "Matrix store passphrase file {} must be a regular file (symlinks to regular files are allowed)",
            path.display()
        )));
    }
    if metadata.len() > MATRIX_STORE_PASSPHRASE_FILE_MAX_BYTES {
        return Err(MatrixError::EncryptedStateIo(format!(
            "Matrix store passphrase file {} exceeds {} bytes; refuse to read",
            path.display(),
            MATRIX_STORE_PASSPHRASE_FILE_MAX_BYTES
        )));
    }
    let mut buf = zeroize::Zeroizing::new(String::new());
    // `take(cap + 1)` so a same-call truncate-and-rewrite (or a
    // racy writer extending the file between `metadata` and `open`)
    // cannot stream past the budget. The post-read length check
    // surfaces the same `TooLarge` outcome as the metadata
    // pre-check.
    file.take(MATRIX_STORE_PASSPHRASE_FILE_MAX_BYTES + 1)
        .read_to_string(&mut buf)
        .map_err(|err| {
            MatrixError::EncryptedStateIo(format!(
                "failed to read Matrix store passphrase file {}: {err}",
                path.display()
            ))
        })?;
    if buf.len() as u64 > MATRIX_STORE_PASSPHRASE_FILE_MAX_BYTES {
        return Err(MatrixError::EncryptedStateIo(format!(
            "Matrix store passphrase file {} exceeds {} bytes; refuse to read",
            path.display(),
            MATRIX_STORE_PASSPHRASE_FILE_MAX_BYTES
        )));
    }
    let trimmed = buf.trim();
    if trimmed.is_empty() {
        return Err(MatrixError::EncryptedStateIo(format!(
            "Matrix store passphrase file {} is empty",
            path.display()
        )));
    }
    // The trim borrows from `buf`; clone its trimmed bytes into a
    // fresh Zeroizing<String> so the original `buf` (which may
    // contain trailing whitespace from the file) zeroes on drop.
    Ok(Some(zeroize::Zeroizing::new(trimmed.to_string())))
}

pub fn read_or_create_installation_id(state_dir: &Path) -> Result<String, MatrixError> {
    let path = state_dir.join("installation_id");
    if path.exists() {
        return read_existing_installation_id(&path)?
            .ok_or_else(|| MatrixError::InstallationId(format!("{} is empty", path.display())));
    }

    std::fs::create_dir_all(state_dir)
        .map_err(|err| MatrixError::InstallationId(err.to_string()))?;
    let installation_id = generate_installation_id()?;
    // The previous implementation used `tmp + rename` here. Two
    // concurrent first-time startups would BOTH see `path.exists()
    // == false`, BOTH generate fresh installation_ids, and BOTH
    // rename — last writer wins, but the loser had already cached
    // its own (different) value in memory. Subsequent HKDF
    // derivations diverged across instances, opening the SQLite
    // store with the wrong key. `write_owner_only_file` now uses
    // `tmp + hard_link` (atomic no-replace), so the loser surfaces
    // the EEXIST as `MatrixError::InstallationId`; we then fall
    // through to `read_existing_installation_id` which returns the
    // winner's value, restoring single-source-of-truth.
    if let Err(err) = write_owner_only_file(&path, &installation_id) {
        if let Some(existing) = read_existing_installation_id(&path)? {
            return Ok(existing);
        }
        return Err(err);
    }
    Ok(installation_id)
}

/// Open an owner-only secret file with O_NOFOLLOW + fd-revalidate.
/// The companion to `read_recovery_key_file_to_string_bounded_blocking`
/// pattern: open first, validate via held fd. No swap window.
#[cfg(unix)]
fn open_owner_only_secret_file_for_read(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::{FileTypeExt, OpenOptionsExt};
    // O_NOFOLLOW + O_NONBLOCK: this site refuses symlinks (no
    // operator-tooling escape hatch — installation_id is daemon-
    // owned). O_NOFOLLOW alone does NOT close direct-FIFO-at-path
    // hangs: open(2) on a FIFO with no writer blocks indefinitely
    // until the post-open fd checks even run. O_NONBLOCK makes
    // open(2) return immediately so the fstat below correctly
    // refuses FIFO/socket/device.
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;
    let file_type = metadata.file_type();
    if !file_type.is_file()
        || file_type.is_symlink()
        || file_type.is_fifo()
        || file_type.is_socket()
        || file_type.is_block_device()
        || file_type.is_char_device()
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("not a regular file: {}", path.display()),
        ));
    }
    Ok(file)
}

#[cfg(not(unix))]
fn open_owner_only_secret_file_for_read(path: &Path) -> std::io::Result<std::fs::File> {
    if path.exists() {
        let metadata = std::fs::symlink_metadata(path)?;
        if metadata.file_type().is_symlink() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("symlink refused: {}", path.display()),
            ));
        }
    }
    // Path is operator-trusted: derived from `state_dir` config; not
    // user-supplied. Carapace is not an Actix app.
    std::fs::File::open(path) // nosemgrep
}

/// 64 lowercase hex chars (`generate_installation_id` writes 32
/// bytes hex-encoded), plus headroom for whitespace / EOL. 4 KiB
/// is the same cap class as the recovery-key reader; any file
/// larger than this is malformed (operator hand-edit or attacker
/// pre-plant) and should fail-loud rather than fill RAM.
const MATRIX_INSTALLATION_ID_FILE_MAX_BYTES: u64 = 4 * 1024;

fn read_existing_installation_id(path: &Path) -> Result<Option<String>, MatrixError> {
    // SECURITY: open with O_NOFOLLOW + fd-revalidate + bounded
    // read. The prior `std::fs::read_to_string(path)` had no size
    // cap and followed symlinks — a same-uid attacker swapping the
    // installation_id dirent for a symlink to `/dev/zero` or a
    // multi-GB file would OOM the daemon on every startup before
    // the 64-char shape check rejected it. Mirrors the pattern at
    // `read_matrix_store_passphrase_file` and
    // `read_recovery_key_file_to_string_bounded_blocking`.
    use std::io::Read;
    let file = match open_owner_only_secret_file_for_read(path) {
        Ok(file) => file,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => {
            return Err(MatrixError::InstallationId(format!(
                "{}: {err}",
                path.display()
            )));
        }
    };
    let metadata = file
        .metadata()
        .map_err(|err| MatrixError::InstallationId(format!("{}: {err}", path.display())))?;
    if !metadata.is_file() {
        return Err(MatrixError::InstallationId(format!(
            "{} is not a regular file",
            path.display()
        )));
    }
    if metadata.len() > MATRIX_INSTALLATION_ID_FILE_MAX_BYTES {
        return Err(MatrixError::InstallationId(format!(
            "{} exceeds {} bytes",
            path.display(),
            MATRIX_INSTALLATION_ID_FILE_MAX_BYTES
        )));
    }
    let mut value = String::new();
    file.take(MATRIX_INSTALLATION_ID_FILE_MAX_BYTES + 1)
        .read_to_string(&mut value)
        .map_err(|err| MatrixError::InstallationId(format!("{}: {err}", path.display())))?;
    if value.len() as u64 > MATRIX_INSTALLATION_ID_FILE_MAX_BYTES {
        return Err(MatrixError::InstallationId(format!(
            "{} exceeds {} bytes",
            path.display(),
            MATRIX_INSTALLATION_ID_FILE_MAX_BYTES
        )));
    }
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    // Validate the format of the on-disk id matches the one this
    // build emits via `generate_installation_id` (32 bytes →
    // hex-encoded → 64 lowercase ASCII-hex chars). Without this an
    // operator hand-edit (or a partial write that left fewer bytes)
    // would silently flow into HKDF / Argon2id derivations,
    // producing a key that *succeeds* the derive call but no longer
    // matches the previously-rotated-from key. The strict shape
    // check is a fail-loud signal: the operator either restores the
    // original file or accepts the rotation cost (re-encrypted
    // store).
    let valid = trimmed.len() == 64
        && trimmed
            .chars()
            .all(|c| c.is_ascii_hexdigit() && (c.is_ascii_digit() || c.is_ascii_lowercase()));
    if !valid {
        return Err(MatrixError::InstallationId(format!(
            "{} contents are not the expected format (64 lowercase ASCII-hex chars). \
             A hand-edited or partially-written installation_id silently corrupts \
             every store-key derivation. Restore the original file or remove it to \
             let the daemon mint a fresh id (this rotates all derived keys).",
            path.display()
        )));
    }
    Ok(Some(trimmed.to_string()))
}

fn generate_installation_id() -> Result<String, MatrixError> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|err| MatrixError::InstallationId(err.to_string()))?;
    Ok(hex::encode(bytes))
}

fn write_owner_only_file(path: &Path, content: &str) -> Result<(), MatrixError> {
    use std::io::Write;

    // Tmp file + atomic hard-link-no-replace + parent-dir fsync.
    //
    // The installation_id seeds the DLQ encryption key and the
    // Matrix store-key HKDF derivation (and is recreated on read
    // miss); a lost or split installation_id silently corrupts every
    // subsequent encrypted record. Power-loss-safe atomic write is
    // non-negotiable, and the no-replace contract is what keeps two
    // racing first-time startups from each writing distinct ids.
    //
    // `std::fs::hard_link` is portable across Unix and Windows
    // (NTFS) and atomically refuses an existing link target via
    // EEXIST / ERROR_ALREADY_EXISTS. The earlier `tmp + rename`
    // shape silently replaced on Windows (`MoveFileExW` defaults to
    // `MOVEFILE_REPLACE_EXISTING`) — last-writer-wins races landed
    // a partially-cached id in the loser's memory.
    let tmp = installation_id_temp_path(path);
    {
        // Route through the canonical helper for O_NOFOLLOW + O_EXCL +
        // 0o600 defense-in-depth.
        let mut file = crate::paths::create_atomic_tmp_owner_only(&tmp)
            .map_err(|err| MatrixError::InstallationId(err.to_string()))?;
        let result = file
            .write_all(content.as_bytes())
            .and_then(|_| file.write_all(b"\n"))
            .and_then(|_| file.sync_all());
        if let Err(err) = result {
            let _ = std::fs::remove_file(&tmp);
            return Err(MatrixError::InstallationId(err.to_string()));
        }
    }
    let link_result = std::fs::hard_link(&tmp, path);
    let _ = std::fs::remove_file(&tmp);
    if let Err(err) = link_result {
        return Err(MatrixError::InstallationId(format!(
            "link installation_id into place at {}: {err}",
            path.display()
        )));
    }
    crate::paths::sync_parent_dir_blocking(path)
        .map_err(|err| MatrixError::InstallationId(format!("fsync parent dir: {err}")))?;
    Ok(())
}

fn installation_id_temp_path(path: &Path) -> std::path::PathBuf {
    crate::paths::atomic_tmp_path(path, "iid")
}

pub fn spawn_matrix_runtime(
    config: MatrixConfig,
    state_dir: PathBuf,
    ws_state: Arc<WsServerState>,
    channel_registry: Arc<ChannelRegistry>,
    shutdown_rx: watch::Receiver<bool>,
) -> Arc<MatrixRuntimeHandle> {
    let (tx, rx) = mpsc::channel(MATRIX_OUTBOUND_QUEUE_CAPACITY);
    let state = Arc::new(RwLock::new(MatrixRuntimeState::default()));
    let completed = Arc::new(AtomicBool::new(false));
    let shutdown_complete = Arc::new(Notify::new());
    let state_for_handle = state.clone();
    let completed_for_handle = completed.clone();
    let shutdown_complete_for_handle = shutdown_complete.clone();
    let actor_handle = tokio::spawn(async move {
        run_matrix_runtime(
            config,
            state_dir,
            ws_state,
            channel_registry,
            state,
            rx,
            shutdown_rx,
        )
        .await;
        completed.store(true, Ordering::Release);
        shutdown_complete.notify_waiters();
    });
    Arc::new(MatrixRuntimeHandle {
        tx: tx.clone(),
        state: state_for_handle,
        completed: completed_for_handle,
        shutdown_complete: shutdown_complete_for_handle,
        actor_handle: tokio::sync::Mutex::new(Some(actor_handle)),
    })
}

async fn run_matrix_runtime(
    config: MatrixConfig,
    state_dir: PathBuf,
    ws_state: Arc<WsServerState>,
    channel_registry: Arc<ChannelRegistry>,
    state: Arc<RwLock<MatrixRuntimeState>>,
    mut rx: mpsc::Receiver<MatrixCommand>,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    channel_registry.register(
        crate::channels::ChannelInfo::new(MATRIX_CHANNEL_ID, MATRIX_CHANNEL_NAME)
            .with_status(ChannelStatus::Connecting)
            .with_metadata(ChannelMetadata {
                description: Some("Matrix / Element native channel runtime".to_string()),
                ..Default::default()
            }),
    );

    if let Err(err) = try_now_millis() {
        // Operator-actionable: a system clock that won't advance is a
        // host-environment problem. Surface at error-level so journald
        // priority<=err / Loki alerts catch it without scraping
        // last_error from the channel registry.
        tracing::error!(error = %err, "Matrix runtime startup failed: clock unavailable");
        stamp_matrix_runtime_error(&channel_registry, &state, &err);
        drain_pending_commands(&mut rx, err);
        return;
    }

    let client = match build_authenticated_client(&config, &state_dir, &state).await {
        Ok(client) => Arc::new(client),
        Err(err) => {
            // Common shapes: invalid credentials (`Auth`), store-passphrase
            // mismatch (`ClientBuild`), interrupted-rekey detection
            // (`InterruptedRekey`). All require operator action — surface
            // at error-level. The same `err` reaches `last_error`, so the
            // operator can read either the log or the registry, but the
            // log is the only signal for hosts that don't run a control UI.
            tracing::error!(
                error = %err,
                homeserver = %config.homeserver_url,
                user_id = %config.user_id,
                "Matrix runtime startup failed: authentication or store load",
            );
            stamp_matrix_runtime_error(&channel_registry, &state, &err);
            drain_pending_commands(&mut rx, err);
            return;
        }
    };

    register_matrix_event_handlers(
        client.clone(),
        config.clone(),
        state_dir.clone(),
        ws_state.clone(),
        channel_registry.clone(),
        state.clone(),
    );
    mark_matrix_channel_connected(&channel_registry, &state);
    info!(homeserver = %config.homeserver_url, user_id = %config.user_id, "Matrix channel runtime started");

    let mut sync_settings = SyncSettings::default().timeout(MATRIX_SYNC_TIMEOUT);
    let mut backoff = MatrixBackoff::default();
    let mut next_sync_after: Option<tokio::time::Instant> = None;
    // Fallback baseline for `classify_sync_giveup` when the SDK
    // has never produced a successful sync.
    let actor_started_at_ms = now_millis();
    // Bundle the four post-sync maintenance streaks + the
    // inbound-decay counter into a single struct so they're always
    // passed/passed-through as a unit. Without the bundle, swapping
    // two `&mut FailureStreak` of the same type at a call site is
    // silently wrong; with it, the field name pins the phase identity.
    let mut maintenance_streaks = MatrixMaintenanceStreaks::default();
    // Track in-flight outbound send tasks so they're aborted on shutdown
    // and on terminal sync errors. Detached `tokio::spawn` lets tasks run
    // against a client whose token has just been revoked, surfacing
    // `M_UNKNOWN_TOKEN` to callers instead of the typed terminal cause
    // already on the channel registry.
    let mut send_tasks: tokio::task::JoinSet<()> = tokio::task::JoinSet::new();
    // Shared cancellation + terminal-cause cell so an in-flight
    // SendText task can synthesize the typed terminal MatrixError on
    // shutdown — instead of dropping its `reply_tx` and letting the
    // caller see a generic "Matrix runtime stopped" message that hides
    // the actual cause already on the channel registry.
    let send_cancel = CancellationToken::new();
    let send_terminal_cause: Arc<ParkingMutex<Option<MatrixError>>> =
        Arc::new(ParkingMutex::new(None));
    let mut sync_tasks: tokio::task::JoinSet<Result<SyncResponse, matrix_sdk::Error>> =
        tokio::task::JoinSet::new();
    // Maintenance runs in its own JoinSet so the actor's outer select
    // continues to pump commands while invite handling, verification
    // refresh, device refresh, DLQ replay, and runtime status refresh
    // run in the background. A new maintenance cycle spawns only when
    // the JoinSet is empty so concurrent sync completions don't stack
    // multiple refreshes.
    let mut maintenance_tasks: tokio::task::JoinSet<PostSyncMaintenanceOutcomes> =
        tokio::task::JoinSet::new();
    // Post-timeout refresh tasks for `StartVerification` and
    // `VerificationAction`. Each spawn runs up to
    // `MATRIX_VERIFICATION_COMMAND_TIMEOUT` (30s), broadcasting
    // `matrix.verification.updated` WS events into `WsServerState`
    // when verification flows resolve. Without JoinSet membership +
    // shutdown drain, a daemon shutdown that fires while a refresh
    // is mid-flight leaves the spawned task running past
    // `set_matrix_runtime(None)` — the task continues to broadcast
    // for a runtime that's been removed, racing the next daemon
    // start (which would re-bind `WsServerState` and now see stray
    // updates from the prior runtime). Track here, drain on
    // shutdown.
    let mut verification_refresh_tasks: tokio::task::JoinSet<()> = tokio::task::JoinSet::new();

    loop {
        // Reap finished outbound send tasks so the JoinSet doesn't grow
        // unboundedly under steady traffic. A `JoinError` here means the
        // send task panicked; surface it to operators via warn-log so
        // panics don't disappear silently — `reply_tx` is already closed
        // in that case and the caller has only seen a generic
        // channel-closed error.
        while let Some(joined) = send_tasks.try_join_next() {
            if let Err(join_err) = joined {
                warn!(
                    error = %crate::logging::redact::RedactedDisplay(&join_err),
                    "Matrix outbound send task panicked while reaping finished tasks"
                );
            }
        }
        // Reap finished verification-refresh tasks symmetrically so
        // a steady stream of post-timeout refreshes doesn't grow
        // the JoinSet unboundedly. A panic here surfaces via
        // warn-log; the spawned task already produced its own
        // `tracing::warn!` for the failure path, so this is just
        // panic-as-distinct-from-runtime-error.
        while let Some(joined) = verification_refresh_tasks.try_join_next() {
            if let Err(join_err) = joined {
                warn!(
                    error = %crate::logging::redact::RedactedDisplay(&join_err),
                    "Matrix verification-refresh task panicked while reaping finished tasks"
                );
            }
        }
        if sync_tasks.is_empty() {
            let sync_client = client.clone();
            let settings = sync_settings.clone();
            let deadline = next_sync_after.take();
            sync_tasks.spawn(async move {
                if let Some(deadline) = deadline {
                    tokio::time::sleep_until(deadline).await;
                }
                // Wrap sync_once in a Tokio watchdog. SyncSettings'
                // timeout is the Matrix long-poll timeout (server-
                // side); without a Tokio-side deadline, a wedged SDK
                // future hangs retry/backoff/give-up forever.
                match tokio::time::timeout(MATRIX_SYNC_WATCHDOG, sync_client.sync_once(settings))
                    .await
                {
                    Ok(result) => result,
                    Err(_) => Err(matrix_sdk::Error::UnknownError(
                        format!(
                            "Matrix sync_once exceeded {}s Tokio watchdog (SDK future wedged)",
                            MATRIX_SYNC_WATCHDOG.as_secs()
                        )
                        .into(),
                    )),
                }
            });
        }

        tokio::select! {
            biased;
            changed = shutdown_rx.changed() => {
                // Treat sender-dropped (Err) the same as an explicit
                // shutdown signal: no future send can ever arrive, so
                // there is no reason to keep the actor alive. Without
                // this branch the actor would spin on the `rx.recv()`
                // arm until the tokio runtime is dropped, holding the
                // SQLite store FD open past the point where the
                // DaemonPidGuard is released on startup-error paths.
                if changed.is_err() || *shutdown_rx.borrow() {
                    shutdown_matrix_runtime_actor(
                        &channel_registry,
                        &state,
                        &mut sync_tasks,
                        &mut maintenance_tasks,
                        &mut verification_refresh_tasks,
                        &send_cancel,
                        &mut send_tasks,
                        &mut rx,
                    )
                    .await;
                    return;
                }
            }
            command = rx.recv() => {
                match command {
                    Some(MatrixCommand::SendText {
                        ctx,
                        reply_tx,
                        caller_cancel,
                    }) => {
                        if caller_cancel.is_cancelled() {
                            let _ = reply_tx.send(Err(MatrixError::SendFailed {
                                message: "Matrix send caller timed out before dispatch"
                                    .to_string(),
                                retry_after_ms: None,
                            }));
                            continue;
                        }
                        if send_tasks.len() >= MATRIX_MAX_IN_FLIGHT_SENDS {
                            // Backpressure must surface as a retryable
                            // DeliveryResult, not a hard error: returning
                            // `Err(SendFailed)` flows through send_text →
                            // BindingError, which `messages::delivery` then
                            // marks non-retryable, turning a transient cap
                            // into a permanent delivery failure.
                            let _ = reply_tx.send(Ok(matrix_retryable_delivery_result(format!(
                                "too many in-flight Matrix sends (cap {MATRIX_MAX_IN_FLIGHT_SENDS}); retrying shortly"
                            ))));
                        } else {
                            let send_client = client.clone();
                            let send_config = config.clone();
                            let task_cancel = send_cancel.clone();
                            let task_terminal_cause = send_terminal_cause.clone();
                            send_tasks.spawn(async move {
                                // Poll `send_matrix_text` first under
                                // `biased` ordering so a successful SDK
                                // send beats a simultaneously-ready
                                // cancel signal. Once the SDK has
                                // accepted the message, the wire side
                                // effect is already at the homeserver;
                                // discarding the Ok and reporting a
                                // terminal cause to the caller would
                                // trigger a retry and duplicate the
                                // message at the homeserver. While the
                                // send is still Pending, cancels remain
                                // promptly observable because
                                // `tokio::select!` polls every arm on
                                // every wakeup — biased ordering only
                                // affects tie-break.
                                let result = tokio::select! {
                                    biased;
                                    result = send_matrix_text(send_client, &send_config, ctx) => result,
                                    _ = task_cancel.cancelled() => {
                                        let cause = task_terminal_cause
                                            .lock()
                                            .clone()
                                            .unwrap_or(MatrixError::NotConnected);
                                        Err(cause)
                                    }
                                    _ = caller_cancel.cancelled() => {
                                        Err(MatrixError::SendFailed {
                                            message: "Matrix send caller timed out before dispatch"
                                                .to_string(),
                                            retry_after_ms: None,
                                        })
                                    }
                                };
                                let _ = reply_tx.send(result);
                            });
                        }
                    }
                    Some(MatrixCommand::StartVerification { user_id, device_id, reply_tx, caller_cancel }) => {
                        if caller_cancel.is_cancelled() {
                            let _ = reply_tx.send(Err(MatrixError::VerificationTimeout(
                                "verification start caller timed out before dispatch".to_string(),
                            )));
                            continue;
                        }
                        let result = match tokio::time::timeout(
                            MATRIX_VERIFICATION_COMMAND_TIMEOUT,
                            async {
                                tokio::select! {
                                    biased;
                                    _ = caller_cancel.cancelled() => Err(MatrixError::VerificationTimeout(
                                        "verification start caller timed out before dispatch".to_string(),
                                    )),
                                    result = verification::start_matrix_verification(
                                        client.clone(),
                                        &state,
                                        user_id,
                                        device_id,
                                    ) => result,
                                }
                            },
                        )
                        .await
                        {
                            Ok(result) => result,
                            Err(_) => {
                                // Best-effort refresh of existing verification
                                // records so any state changes the SDK already
                                // observed surface to subscribers. We do NOT
                                // attempt to recover the timed-out start as
                                // Ok: `refresh_verification_records` only
                                // updates records already in `state`, never
                                // inserts new ones, and the SDK
                                // `request_verification` call ran ahead of
                                // `upsert_verification_record`, so any record
                                // matching (user_id, device_id) at this point
                                // belongs to a prior flow. Confirming SAS
                                // against that flow would be a security-
                                // relevant mis-attribution. Return the
                                // timeout unconditionally; the to-device
                                // event handler will surface a successful
                                // SDK start on the next sync tick, where it
                                // is upserted as a fresh record under its
                                // own protocol flow id.
                                //
                                // Run the refresh in a detached task so the
                                // actor returns to the loop within the
                                // documented 30s
                                // MATRIX_VERIFICATION_COMMAND_TIMEOUT cap.
                                // Inline-await of a second 30s timeout
                                // doubled the actor-block budget — during
                                // that window SendText/shutdown/other
                                // verification commands all stalled.
                                let refresh_client = client.clone();
                                let refresh_state = state.clone();
                                let refresh_ws_state = ws_state.clone();
                                verification_refresh_tasks.spawn(async move {
                                    let refresh_result = tokio::time::timeout(
                                        MATRIX_VERIFICATION_COMMAND_TIMEOUT,
                                        verification::refresh_verification_records(
                                            refresh_client,
                                            &refresh_state,
                                            &refresh_ws_state,
                                        ),
                                    )
                                    .await;
                                    match refresh_result {
                                        Ok(Ok(())) => {}
                                        Ok(Err(err)) => warn!(
                                            error = %err,
                                            "post-timeout start-verification refresh failed; \
                                             local state may remain stale until next sync"
                                        ),
                                        Err(_) => warn!(
                                            "post-timeout start-verification refresh also timed out; \
                                             local state may remain stale until next sync"
                                        ),
                                    }
                                });
                                Err(MatrixError::VerificationTimeout(
                                    "verification start did not complete within the command \
                                     window. The SDK request may have reached the homeserver \
                                     before the timeout fired; if so, retrying issues a fresh \
                                     flow id and the original orphan ages out internally. \
                                     Check homeserver reachability and outbound network \
                                     connectivity if timeouts persist."
                                        .to_string(),
                                ))
                            }
                        };
                        // Project the outcome to (info, inserted) for
                        // the broadcasts and to `MatrixVerificationInfo`
                        // for the caller's reply_tx. The witness's
                        // `from_upsert(info, inserted)` constructor
                        // gates the `requested` broadcast on actual
                        // insertion; firing unconditionally would
                        // duplicate the inbound handler's broadcast
                        // for a peer-initiated flow that already
                        // upserted before the operator started one.
                        let info_result: Result<MatrixVerificationInfo, MatrixError> =
                            match result {
                                Ok(outcome) => {
                                    crate::server::ws::broadcast_matrix_verification_request(
                                        &ws_state,
                                        crate::server::ws::NewVerificationFlow::from_upsert(
                                            &outcome.info,
                                            outcome.inserted,
                                        ),
                                    );
                                    // Suppress the `updated` broadcast on a
                                    // freshly-inserted flow — the `requested`
                                    // event already carries the same state-
                                    // transition signal. Firing both produces
                                    // a duplicate WS message per state change,
                                    // which under SAS-flood from a hostile
                                    // peer doubles the rate of
                                    // try_send-on-Full evictions of slow
                                    // operator dashboards.
                                    if !outcome.inserted {
                                        crate::server::ws::broadcast_matrix_verification_updated(
                                            &ws_state,
                                            crate::server::ws::UpdatedVerificationFlow::for_state_change(
                                                &outcome.info,
                                            ),
                                        );
                                    }
                                    Ok(outcome.info)
                                }
                                Err(err) => Err(err),
                            };
                        update_channel_registry_metadata(&channel_registry, &state);
                        let _ = reply_tx.send(info_result);
                    }
                    Some(MatrixCommand::VerificationAction { flow_id, action, reply_tx, caller_cancel }) => {
                        if caller_cancel.is_cancelled() {
                            let _ = reply_tx.send(Err(MatrixError::VerificationTimeout(
                                "verification action caller timed out before dispatch".to_string(),
                            )));
                            continue;
                        }
                        let result = match tokio::time::timeout(
                            MATRIX_VERIFICATION_COMMAND_TIMEOUT,
                            async {
                                tokio::select! {
                                    biased;
                                    _ = caller_cancel.cancelled() => Err(MatrixError::VerificationTimeout(
                                        "verification action caller timed out before dispatch".to_string(),
                                    )),
                                    result = verification::apply_verification_action(
                                        client.clone(),
                                        &state,
                                        &flow_id,
                                        action,
                                    ) => result,
                                }
                            },
                        )
                        .await
                        {
                            Ok(result) => result,
                            Err(_) => {
                                // The SDK request was dropped mid-flight by
                                // the timeout. The homeserver may have
                                // received and processed the verification
                                // step before our future was cancelled, so
                                // local state is now potentially stale.
                                // Refresh in a detached task so the actor
                                // returns to the loop within the documented
                                // 30s window — see the StartVerification
                                // arm above for rationale.
                                // The refresh's broadcasts fire inline from
                                // the spawned task; subscribers see the
                                // post-timeout state transition without
                                // waiting for the next sync-loop tick.
                                let refresh_client = client.clone();
                                let refresh_state = state.clone();
                                let refresh_ws_state = ws_state.clone();
                                let refresh_flow_id = flow_id.clone();
                                verification_refresh_tasks.spawn(async move {
                                    if let Err(refresh_err) = verification::bounded_verification_refresh(
                                        refresh_client,
                                        &refresh_state,
                                        &refresh_ws_state,
                                    )
                                    .await
                                    {
                                        warn!(
                                            flow_id = %refresh_flow_id,
                                            error = %refresh_err,
                                            "post-timeout verification refresh failed; local verification \
                                             state may remain stale until next sync"
                                        );
                                    }
                                });
                                Err(MatrixError::VerificationTimeout(
                                    "verification action did not complete within the command \
                                     window. A detached refresh is running in the background; \
                                     re-check the flow with `cara matrix verifications` and \
                                     retry the action. Persistent timeouts indicate \
                                     homeserver reachability or sync-loop pressure."
                                        .to_string(),
                                ))
                            }
                        };
                        if let Ok(verification) = result.as_ref() {
                            crate::server::ws::broadcast_matrix_verification_updated(
                                &ws_state,
                                crate::server::ws::UpdatedVerificationFlow::for_state_change(verification),
                            );
                        }
                        update_channel_registry_metadata(&channel_registry, &state);
                        let _ = reply_tx.send(result);
                    }
                    None => return,
                }
            }
            sync_join = sync_tasks.join_next(), if !sync_tasks.is_empty() => {
                match sync_join {
                    Some(Ok(Ok(response))) => {
                        sync_settings = sync_settings.token(response.next_batch);
                        backoff.reset();
                        // Capture the sync-success timestamp at the
                        // earliest observable moment — before maintenance
                        // is spawned. The maintenance JoinSet can race
                        // with command processing for tens of seconds
                        // (`MATRIX_RUNTIME_OPERATION_TIMEOUT` per phase);
                        // writing this in `refresh_runtime_status`
                        // labelled "time of last successful sync" with the
                        // wall clock when maintenance happened to start,
                        // skewing operator staleness metrics.
                        if let Ok(now) = try_now_millis() {
                            state.write().status.last_successful_sync_at = Some(now);
                        }
                        // Reset the transient-sync streak so a flaky
                        // uplink that recovers within
                        // MATRIX_REFRESH_FAILURE_ERROR_THRESHOLD
                        // failures never escalates to operator-visible
                        // Error. The streak persists across sync ticks
                        // only on actual sustained failure.
                        maintenance_streaks.transient_sync.record_success();
                        // Spawn one maintenance cycle into its own
                        // JoinSet. The actor's outer select continues to
                        // process commands and shutdown signals while
                        // maintenance runs. A subsequent sync completion
                        // does not stack a second cycle — we only spawn
                        // when the JoinSet is empty.
                        if maintenance_tasks.is_empty() {
                            let task_client = client.clone();
                            let task_config = config.clone();
                            let task_state_dir = state_dir.clone();
                            let task_ws_state = ws_state.clone();
                            let task_state = state.clone();
                            maintenance_tasks.spawn(async move {
                                run_post_sync_maintenance(
                                    task_client,
                                    task_config,
                                    task_state_dir,
                                    task_ws_state,
                                    task_state,
                                )
                                .await
                            });
                        }
                    }
                    Some(Ok(Err(err))) => {
                        maintenance_streaks.consecutive_clean_syncs = 0;
                        let sync_decision = advance_and_classify_matrix_sync_failure(
                            MatrixSyncFailure::from_sdk_error(&err),
                            &state,
                            actor_started_at_ms,
                            &mut backoff,
                            &mut maintenance_streaks.transient_sync,
                        );
                        match sync_decision {
                            MatrixSyncFailureDecision::Terminal(permanent) => {
                                // ORDER MATTERS: set the freeze flag FIRST,
                                // THEN stamp. The clear paths
                                // (matrix.rs:1394 / 1418) gate on
                                // `terminal_runtime_stamped`, so a
                                // late-arriving maintenance writer that
                                // interleaved between stamp and mark in
                                // the prior order would clobber the
                                // operator-visible forensic state. With
                                // the flag set first, any interleaved
                                // clear sees the flag and no-ops, so the
                                // stamp lands without race.
                                state.write().mark_terminal_runtime_stamped();
                                stamp_matrix_runtime_error(&channel_registry, &state, &permanent);
                                // Permanent errors stop the runtime — typically
                                // M_UNKNOWN_TOKEN (revoked credential) or
                                // matrix-store decryption failure. Both are
                                // operator-must-act conditions. Error level so
                                // monitoring sees the daemon transition to a
                                // terminal Matrix state.
                                tracing::error!(
                                    error = %crate::logging::redact::RedactedDisplay(&err),
                                    "Matrix sync failed with permanent error; stopping runtime"
                                );
                                // Stash the terminal cause so in-flight
                                // SendText tasks aborted by the JoinSet
                                // shutdown observe the typed error rather
                                // than a generic "runtime stopped" message.
                                *send_terminal_cause.lock() = Some(permanent.clone());
                                send_cancel.cancel();
                                drain_cancelled_send_tasks(&mut send_tasks).await;
                                // Maintenance runs in a JoinSet that can be
                                // in flight at terminal-error time. Without
                                // this explicit shutdown, maintenance writers
                                // continue to mutate `state.write().status`
                                // during the drain window after `set_error`
                                // has already landed, overwriting the
                                // operator-visible terminal cause with stale
                                // counters.
                                drain_ready_maintenance_outcomes(
                                    &mut maintenance_tasks,
                                    &mut maintenance_streaks,
                                    &state,
                                    &channel_registry,
                                    MaintenanceApplyMode::TerminalDrain,
                                );
                                // Use the panic-surfacing helper so a
                                // maintenance task that panics during the
                                // terminal-sync shutdown still emits a
                                // warn-with-backtrace via JoinError, instead
                                // of being silently consumed by
                                // `JoinSet::shutdown().await`. The clean-
                                // shutdown path in
                                // `shutdown_matrix_runtime_actor` already
                                // uses this helper; the two terminal-sync
                                // arms must match so panic context is not
                                // dropped on the failure path either.
                                cancel_and_drain_join_set_with_panic_warn(
                                    &mut maintenance_tasks,
                                    "Matrix maintenance task panicked during terminal sync shutdown",
                                )
                                .await;
                                cancel_and_drain_join_set_with_panic_warn(
                                    &mut verification_refresh_tasks,
                                    "Matrix verification-refresh task panicked during terminal sync shutdown",
                                )
                                .await;
                                // Defense-in-depth drain of sync_tasks: the
                                // spawn-when-empty guard above (line 2665)
                                // means this is normally a no-op (we got
                                // here because the only in-flight sync task
                                // completed via `Some(Ok(Err))`), but the
                                // clean-shutdown path in
                                // `shutdown_matrix_runtime_actor` does drain
                                // it, and a future refactor that relaxes the
                                // spawn-when-empty invariant (e.g.,
                                // concurrent eager-sync) would silently leak
                                // an aborted-future panic from this terminal
                                // arm without this drain.
                                cancel_and_drain_join_set_with_panic_warn(
                                    &mut sync_tasks,
                                    "Matrix sync task panicked during terminal sync shutdown",
                                )
                                .await;
                                drain_pending_commands(&mut rx, permanent);
                                return;
                            }
                            MatrixSyncFailureDecision::Transient(decision) => {
                                next_sync_after =
                                    Some(tokio::time::Instant::now() + decision.delay);
                                if let Some(stamp_error) = decision.stamp_error.as_ref() {
                                    stamp_matrix_runtime_error(
                                        &channel_registry,
                                        &state,
                                        stamp_error,
                                    );
                                }
                                warn!(
                                    error = %crate::logging::redact::RedactedDisplay(&err),
                                    delay_ms = decision.delay.as_millis(),
                                    consecutive_failures = decision.streak,
                                    idle_ms = decision.idle_ms,
                                    gave_up = decision.gave_up,
                                    "Matrix sync failed; backing off"
                                );
                            }
                        }
                    }
                    Some(Err(join_err)) => {
                        maintenance_streaks.consecutive_clean_syncs = 0;
                        let err = matrix_sync_join_error(join_err);
                        let sync_decision = advance_and_classify_matrix_sync_failure(
                            MatrixSyncFailure::from_matrix_error(&err),
                            &state,
                            actor_started_at_ms,
                            &mut backoff,
                            &mut maintenance_streaks.transient_sync,
                        );
                        match sync_decision {
                            MatrixSyncFailureDecision::Terminal(permanent) => {
                                // ORDER MATTERS: set the freeze flag FIRST,
                                // THEN stamp. See the parallel comment in the
                                // Some(Ok(Err)) arm above for the race window
                                // closed by this ordering.
                                state.write().mark_terminal_runtime_stamped();
                                stamp_matrix_runtime_error(&channel_registry, &state, &permanent);
                                tracing::error!(
                                    error = %crate::logging::redact::RedactedDisplay(&err),
                                    "Matrix sync task ended with terminal error; stopping runtime"
                                );
                                *send_terminal_cause.lock() = Some(permanent.clone());
                                send_cancel.cancel();
                                drain_cancelled_send_tasks(&mut send_tasks).await;
                                drain_ready_maintenance_outcomes(
                                    &mut maintenance_tasks,
                                    &mut maintenance_streaks,
                                    &state,
                                    &channel_registry,
                                    MaintenanceApplyMode::TerminalDrain,
                                );
                                // Use the panic-surfacing helper so a
                                // maintenance task that panics during the
                                // terminal-sync shutdown still emits a
                                // warn-with-backtrace via JoinError, instead
                                // of being silently consumed by
                                // `JoinSet::shutdown().await`. The clean-
                                // shutdown path in
                                // `shutdown_matrix_runtime_actor` already
                                // uses this helper; the two terminal-sync
                                // arms must match so panic context is not
                                // dropped on the failure path either.
                                cancel_and_drain_join_set_with_panic_warn(
                                    &mut maintenance_tasks,
                                    "Matrix maintenance task panicked during terminal sync shutdown",
                                )
                                .await;
                                cancel_and_drain_join_set_with_panic_warn(
                                    &mut verification_refresh_tasks,
                                    "Matrix verification-refresh task panicked during terminal sync shutdown",
                                )
                                .await;
                                // Defense-in-depth: see the parallel comment
                                // in the `Some(Ok(Err))` arm above for why
                                // we also drain sync_tasks here.
                                cancel_and_drain_join_set_with_panic_warn(
                                    &mut sync_tasks,
                                    "Matrix sync task panicked during terminal sync shutdown",
                                )
                                .await;
                                drain_pending_commands(&mut rx, permanent);
                                return;
                            }
                            MatrixSyncFailureDecision::Transient(decision) => {
                                next_sync_after =
                                    Some(tokio::time::Instant::now() + decision.delay);
                                if let Some(stamp_error) = decision.stamp_error.as_ref() {
                                    stamp_matrix_runtime_error(
                                        &channel_registry,
                                        &state,
                                        stamp_error,
                                    );
                                }
                                warn!(
                                    error = %crate::logging::redact::RedactedDisplay(&err),
                                    delay_ms = decision.delay.as_millis(),
                                    consecutive_failures = decision.streak,
                                    idle_ms = decision.idle_ms,
                                    gave_up = decision.gave_up,
                                    "Matrix sync task failed; backing off"
                                );
                            }
                        }
                    }
                    None => {}
                }
            }
            maint_join = maintenance_tasks.join_next(), if !maintenance_tasks.is_empty() => {
                match maint_join {
                    Some(Ok(outcomes)) => {
                        apply_post_sync_maintenance(
                            outcomes,
                            &mut maintenance_streaks,
                            &state,
                            &channel_registry,
                        );
                    }
                    Some(Err(join_err)) => {
                        warn!(
                            error = %crate::logging::redact::RedactedDisplay(&join_err),
                            "Matrix maintenance task panicked; streaks left unchanged this cycle"
                        );
                    }
                    None => {}
                }
            }
        }
    }
}

async fn bounded_matrix_result<T>(
    label: &'static str,
    future: impl std::future::Future<Output = Result<T, MatrixError>>,
) -> Result<T, MatrixError> {
    match tokio::time::timeout(MATRIX_RUNTIME_OPERATION_TIMEOUT, future).await {
        Ok(result) => result,
        Err(_) => Err(MatrixError::SyncFailed(format!(
            "{label} timed out after {} seconds",
            MATRIX_RUNTIME_OPERATION_TIMEOUT.as_secs()
        ))),
    }
}

fn drain_ready_maintenance_outcomes(
    maintenance_tasks: &mut tokio::task::JoinSet<PostSyncMaintenanceOutcomes>,
    maintenance_streaks: &mut MatrixMaintenanceStreaks,
    state: &Arc<RwLock<MatrixRuntimeState>>,
    channel_registry: &ChannelRegistry,
    mode: MaintenanceApplyMode,
) {
    while let Some(joined) = maintenance_tasks.try_join_next() {
        match joined {
            Ok(outcomes) => {
                apply_post_sync_maintenance_with_mode(
                    outcomes,
                    maintenance_streaks,
                    state,
                    channel_registry,
                    mode,
                );
            }
            Err(join_err) => {
                warn!(
                    error = %crate::logging::redact::RedactedDisplay(&join_err),
                    "Matrix maintenance task panicked before terminal sync shutdown"
                );
            }
        }
    }
}

/// Bundle of FailureStreak counters and the inbound-decay scalar that
/// the actor maintains across post-sync maintenance cycles. Passing
/// four `&mut FailureStreak` separately to `apply_post_sync_maintenance`
/// would let any swap of two same-typed args go silently wrong;
/// bundling pins the phase identity to the field name.
struct MatrixMaintenanceStreaks {
    invite: FailureStreak,
    verification_refresh: FailureStreak,
    device_refresh: FailureStreak,
    dlq_replay: FailureStreak,
    runtime_status: FailureStreak,
    /// Consecutive non-terminal sync errors. Without hysteresis,
    /// every transient blip (network glitch, homeserver gateway
    /// 502, DNS hiccup) flipped the channel status `Connected →
    /// Error → Connected` and broadcast both transitions to every
    /// WS subscriber. Use the same `MATRIX_REFRESH_FAILURE_ERROR_THRESHOLD`
    /// the maintenance phases use so a flaky uplink only escalates
    /// to operator-visible Error after sustained failure.
    transient_sync: FailureStreak,
    consecutive_clean_syncs: u32,
}

impl Default for MatrixMaintenanceStreaks {
    fn default() -> Self {
        Self {
            invite: FailureStreak::new(MATRIX_REFRESH_FAILURE_ERROR_THRESHOLD),
            verification_refresh: FailureStreak::new(MATRIX_REFRESH_FAILURE_ERROR_THRESHOLD),
            device_refresh: FailureStreak::new(MATRIX_REFRESH_FAILURE_ERROR_THRESHOLD),
            dlq_replay: FailureStreak::new(MATRIX_REFRESH_FAILURE_ERROR_THRESHOLD),
            // runtime_status has its own streak so a permanently-failing
            // status refresh escalates to the channel registry instead
            // of emitting a warn every cycle with no operator-visible
            // state change.
            runtime_status: FailureStreak::new(MATRIX_REFRESH_FAILURE_ERROR_THRESHOLD),
            transient_sync: FailureStreak::new(MATRIX_REFRESH_FAILURE_ERROR_THRESHOLD),
            consecutive_clean_syncs: 0,
        }
    }
}

/// Outcomes for one post-sync maintenance cycle. Each field is the
/// per-phase result that the actor's main loop applies to its
/// stack-local FailureStreak counters.
///
/// Spawning maintenance into a JoinSet (vs running it inline in the
/// sync_join arm) lets the actor's `tokio::select!` continue pumping
/// commands while maintenance runs. Without this, a five-phase 30s
/// cycle could starve commands for up to 150 seconds.
struct PostSyncMaintenanceOutcomes {
    invite: Result<(), MatrixError>,
    verification: Result<(), MatrixError>,
    device: Result<(), MatrixError>,
    dlq_replay: Result<(), MatrixError>,
    runtime_status: Result<(), MatrixError>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MaintenanceApplyMode {
    Normal,
    TerminalDrain,
}

/// Apply per-phase maintenance outcomes to the actor's stack-local
/// FailureStreak counters and decide whether to restore Connected
/// status. Encapsulates the "Restore Connected only if no streak is
/// sticky" logic that was previously inlined in the sync_join arm.
fn apply_post_sync_maintenance(
    outcomes: PostSyncMaintenanceOutcomes,
    streaks: &mut MatrixMaintenanceStreaks,
    state: &Arc<RwLock<MatrixRuntimeState>>,
    channel_registry: &ChannelRegistry,
) {
    apply_post_sync_maintenance_with_mode(
        outcomes,
        streaks,
        state,
        channel_registry,
        MaintenanceApplyMode::Normal,
    );
}

fn apply_post_sync_maintenance_with_mode(
    outcomes: PostSyncMaintenanceOutcomes,
    streaks: &mut MatrixMaintenanceStreaks,
    state: &Arc<RwLock<MatrixRuntimeState>>,
    channel_registry: &ChannelRegistry,
    mode: MaintenanceApplyMode,
) {
    if mode == MaintenanceApplyMode::TerminalDrain {
        let _ = outcomes;
        let _ = streaks;
        let _ = state;
        let _ = channel_registry;
        debug!(
            "Matrix maintenance outcome ignored during terminal drain; terminal runtime state remains authoritative"
        );
        return;
    }
    let PostSyncMaintenanceOutcomes {
        invite,
        verification,
        device,
        dlq_replay: dlq_outcome,
        runtime_status,
    } = outcomes;
    let MatrixMaintenanceStreaks {
        invite: invite_streak,
        verification_refresh,
        device_refresh,
        dlq_replay,
        runtime_status: runtime_status_streak,
        // The transient_sync streak is owned/reset entirely by the
        // sync arms in `run_matrix_runtime` (sync success → reset,
        // non-terminal sync error → record_failure). Post-sync
        // maintenance phases don't touch it but are READ here to
        // gate `mark_matrix_channel_connected` against a stale-
        // maintenance race: a maintenance task spawned at sync N
        // may complete after sync N+1 has failed and stamped a
        // sticky transient error. Without the gate, the
        // maintenance result would clear the just-stamped sticky.
        transient_sync,
        consecutive_clean_syncs,
    } = streaks;
    let sync_sticky = transient_sync.is_sticky();
    // M2: log info on streak transition from sticky → non-sticky.
    // Without this, an operator who saw the channel flip into Error
    // hours ago has no journal entry telling them which phase recovered;
    // the only signal was warns-on-failure. The closure encapsulates
    // the success path so the "was sticky, now isn't" check happens
    // BEFORE record_success() resets the counter.
    let record_phase_recovery = |label: &'static str, streak: &mut FailureStreak| {
        let was_sticky = streak.is_sticky();
        streak.record_success();
        if was_sticky {
            tracing::info!(
                phase = label,
                "Matrix maintenance phase recovered after sticky failure"
            );
        }
    };
    match invite {
        Ok(()) => {
            record_phase_recovery("invite-handling", invite_streak);
            // Clear the systemic-failure marker on a clean tick so a
            // healed invite outage actually unblocks the connected
            // recovery path. Without this, the marker pinned the
            // channel in Error indefinitely until an unrelated DLQ
            // op fired (the previous design wrote into the DLQ
            // durability field, conflating two different recovery
            // semantics).
            state.write().clear_invite_systemic_failure();
        }
        Err(err) => {
            let count = invite_streak.record_failure();
            warn!(error = %err, failures = count, "Matrix invite handling failed");
            // Set Error when EITHER (a) the streak hit threshold via
            // multiple ticks, or (b) `handle_invites` stamped a
            // systemic-failure marker from many failures in this
            // single tick. The systemic marker is the bypass that
            // skips the streak's 3-tick hysteresis when an entire
            // invite phase fails at once. handle_invites is
            // responsible for clearing the marker on sub-threshold
            // ticks; this site only reacts to the post-tick state.
            let invite_systemic = state.read().invite_systemic_error().is_some();
            if mode == MaintenanceApplyMode::Normal
                && (invite_streak.is_sticky() || invite_systemic)
            {
                stamp_matrix_runtime_error(channel_registry, state, &err);
            }
        }
    }
    // Per-phase outcome handler: on Ok, record-and-recover the
    // streak; on Err, record-failure + warn-log + (if sticky)
    // stamp a sticky operator-visible error with the phase label.
    // The four sticky-sites previously copy-pasted the
    // record_failure / warn / stamp_message triplet with only the
    // phase label / log message / streak counter varying.
    let handle_phase_outcome =
        |label: &'static str,
         message_prefix: &'static str,
         warn_message: &'static str,
         streak: &mut FailureStreak,
         outcome: Result<(), MatrixError>| match outcome {
            Ok(()) => record_phase_recovery(label, streak),
            Err(err) => {
                let count = streak.record_failure();
                warn!(error = %err, failures = count, "{}", warn_message);
                if mode == MaintenanceApplyMode::Normal && streak.is_sticky() {
                    stamp_matrix_runtime_error_message(
                        channel_registry,
                        state,
                        format!(
                            "{message_prefix}: {}",
                            crate::logging::redact::RedactedDisplay(&err)
                        ),
                    );
                }
            }
        };
    handle_phase_outcome(
        "verification-refresh",
        "Matrix verification refresh failing",
        "failed to refresh Matrix verification records",
        verification_refresh,
        verification,
    );
    handle_phase_outcome(
        "device-refresh",
        "Matrix device refresh failing",
        "failed to refresh Matrix device state",
        device_refresh,
        device,
    );
    handle_phase_outcome(
        "inbound-dlq-replay",
        "Matrix inbound DLQ replay failing",
        "failed to replay Matrix inbound DLQ",
        dlq_replay,
        dlq_outcome,
    );
    handle_phase_outcome(
        "runtime-status",
        "Matrix runtime status refresh failing",
        "failed to refresh Matrix runtime status",
        runtime_status_streak,
        runtime_status,
    );
    // Project all runtime-state-derived inputs to the dispatch
    // decision under a SINGLE read guard. Without this, a concurrent
    // matrix-sdk event handler (room-message, encryption-state) can
    // stamp `inbound_dlq_durability_error` BETWEEN the
    // `non_inbound_sticky` evaluation and the per-branch follow-up
    // reads. Result: `non_inbound_sticky` was false at evaluation,
    // we fall into the else branch, and the inbound projection sees
    // a freshly-stamped durability error — but the else branch
    // already committed to transitioning to `Connected`. The
    // operator-visible last_error gets cleared even though the
    // durability marker is set, surfacing only at the next tick.
    //
    // One read guard, project everything, then act on the
    // projection. The handler-write races still happen between
    // ticks (which is fine — the next tick projects the new state),
    // but the within-tick decision is now atomic.
    let snapshot = {
        let guard = state.read();
        PostSyncStateSnapshot {
            inbound_durability_message: guard.inbound_dlq_durability_error().map(String::from),
            invite_systemic_message: guard.invite_systemic_error().map(String::from),
            inbound_streak_sticky: guard.inbound_streak_is_sticky(),
            pending_inbound_error: guard.pending_inbound_error().map(String::from),
            pending_inbound_error_kind: guard.pending_inbound_error_kind().map(String::from),
            inbound_failure_generation: guard.inbound_failure_generation,
        }
    };
    let durability_sticky = snapshot.inbound_durability_message.is_some();
    let invite_systemic = snapshot.invite_systemic_message.is_some();
    let non_inbound_sticky = invite_streak.is_sticky()
        || verification_refresh.is_sticky()
        || device_refresh.is_sticky()
        || dlq_replay.is_sticky()
        || runtime_status_streak.is_sticky()
        || durability_sticky
        || invite_systemic;
    if non_inbound_sticky {
        *consecutive_clean_syncs = 0;
        // Off-phase durability stamps (cap-clamp on the dlq_replay
        // success path at ~4101, room-message handler's append-failure
        // path at ~3561, append-path failure at ~3759) set
        // `inbound_dlq_durability_error` without any per-phase Err arm
        // firing this tick. Without this branch, the channel stays at
        // its previous status (typically Connected) while the
        // operator-visible durability error sits in metadata.extra
        // — visible via /control/channels JSON but never reaching
        // last_error / ChannelStatus::Error. Surface it on the same
        // tick the durability becomes sticky, idempotently
        // (set_error is a no-op if the message matches the prior
        // last_error).
        let durability_or_systemic = snapshot
            .inbound_durability_message
            .map(|s| format!("Matrix inbound DLQ durability: {s}"))
            .or_else(|| {
                snapshot
                    .invite_systemic_message
                    .map(|err| format!("Matrix invite systemic failure: {err}"))
            });
        if let Some(message) = durability_or_systemic {
            if mode == MaintenanceApplyMode::Normal {
                stamp_matrix_runtime_error_message(channel_registry, state, message);
            } else {
                debug!(
                    message = %message,
                    "Matrix maintenance status stamp suppressed during terminal drain"
                );
            }
        }
    } else {
        *consecutive_clean_syncs = consecutive_clean_syncs.saturating_add(1);
        // Decay the inbound counter so a sticky inbound failure in a
        // low-traffic room doesn't pin the channel in Error indefinitely.
        // Other counters reset every iteration via their match Ok arms;
        // inbound resets only on inbound success and so needs a separate
        // sync-driven path.
        let inbound_state_reset = if *consecutive_clean_syncs >= MATRIX_INBOUND_DECAY_SYNC_COUNT {
            state
                .write()
                .compare_and_reset_inbound_failures(snapshot.inbound_failure_generation)
        } else {
            false
        };
        // Reconcile inbound state into the registry from the
        // already-projected snapshot. The room-message handler
        // stamps `pending_inbound_error` on sticky failures rather
        // than writing the registry directly — doing so eliminates
        // the race where a maintenance recovery could overwrite an
        // inbound's Error. This is the only site that translates
        // inbound state into channel-registry status.
        // `record_inbound_failure_with_error` is the only writer
        // that sets `pending_inbound_error`, and it stamps
        // Some(error) atomically with the streak bump that flips
        // `is_sticky` true. So `(sticky=true, pending=None)` is
        // unreachable and we can collapse the cases.
        let inbound_snapshot = if !inbound_state_reset && snapshot.inbound_streak_sticky {
            snapshot
                .pending_inbound_error
                .zip(snapshot.pending_inbound_error_kind)
        } else {
            None
        };
        match inbound_snapshot {
            Some((error, error_kind)) => {
                if mode == MaintenanceApplyMode::Normal {
                    stamp_matrix_runtime_error_message_with_kind(
                        channel_registry,
                        state,
                        error,
                        error_kind,
                    );
                } else {
                    debug!(
                        error = %error,
                        "Matrix inbound status stamp suppressed during terminal drain"
                    );
                }
                debug!(
                    clean_syncs = *consecutive_clean_syncs,
                    "Matrix inbound dispatch error remains sticky until decay threshold"
                );
            }
            None => {
                // Don't override a sticky transient-sync error with a
                // stale maintenance Connected stamp. The maintenance
                // outcomes here may have been computed before the
                // current sync failure landed.
                if mode == MaintenanceApplyMode::TerminalDrain {
                    debug!(
                        "Matrix maintenance Connected suppressed during terminal drain; \
                         terminal sync error remains authoritative"
                    );
                } else if !sync_sticky {
                    mark_matrix_channel_connected(channel_registry, state);
                } else {
                    debug!(
                        "Matrix maintenance Connected suppressed: transient sync streak \
                         is sticky; the sync arm has the canonical error stamp"
                    );
                }
            }
        }
    }
    update_channel_registry_metadata(channel_registry, state);
}

/// One-shot projection of every runtime-state field
/// `apply_post_sync_maintenance` consults for the Connected/Error
/// dispatch decision. Built under a single read guard so the
/// dispatch logic is atomic against concurrent matrix-sdk event-
/// handler writes (`record_inbound_dlq_append_failure`,
/// `record_inbound_failure_with_error`, etc.).
struct PostSyncStateSnapshot {
    inbound_durability_message: Option<String>,
    invite_systemic_message: Option<String>,
    inbound_streak_sticky: bool,
    pending_inbound_error: Option<String>,
    pending_inbound_error_kind: Option<String>,
    inbound_failure_generation: u64,
}

async fn run_post_sync_maintenance(
    client: Arc<Client>,
    config: MatrixConfig,
    state_dir: PathBuf,
    ws_state: Arc<WsServerState>,
    state: Arc<RwLock<MatrixRuntimeState>>,
) -> PostSyncMaintenanceOutcomes {
    // Each phase is bounded individually so a wedged SDK call cannot
    // block the maintenance task forever. Shutdown selection moves to
    // the actor's outer loop — the JoinSet shutdown drain will abort
    // this task at process shutdown.
    let invite = bounded_matrix_result(
        "Matrix invite handling",
        handle_invites(client.clone(), &config, &state),
    )
    .await;
    // Broadcasts now fire inline from `refresh_verification_records`
    // immediately after each successful state mutation, so a 30s
    // bounded-timeout cancel mid-iteration cannot strand a state-update
    // without its broadcast.
    let verification = bounded_matrix_result(
        "Matrix verification refresh",
        verification::refresh_verification_records(client.clone(), &state, &ws_state),
    )
    .await;
    let device = bounded_matrix_result(
        "Matrix device refresh",
        refresh_device_state(client.clone(), &config, &state),
    )
    .await;
    let dlq_replay = bounded_matrix_result(
        "Matrix inbound DLQ replay",
        inbound_dlq::replay_matrix_inbound_dlq(
            &state_dir,
            &config,
            ws_state.clone(),
            state.clone(),
        ),
    )
    .await;
    let runtime_status = bounded_matrix_result(
        "Matrix runtime status refresh",
        bounded_runtime_status_refresh(client.clone(), &config, &state),
    )
    .await;
    PostSyncMaintenanceOutcomes {
        invite,
        verification,
        device,
        dlq_replay,
        runtime_status,
    }
}

#[allow(clippy::too_many_arguments)]
async fn shutdown_matrix_runtime_actor(
    channel_registry: &ChannelRegistry,
    state: &Arc<RwLock<MatrixRuntimeState>>,
    sync_tasks: &mut tokio::task::JoinSet<Result<SyncResponse, matrix_sdk::Error>>,
    maintenance_tasks: &mut tokio::task::JoinSet<PostSyncMaintenanceOutcomes>,
    verification_refresh_tasks: &mut tokio::task::JoinSet<()>,
    send_cancel: &CancellationToken,
    send_tasks: &mut tokio::task::JoinSet<()>,
    rx: &mut mpsc::Receiver<MatrixCommand>,
) {
    // Clear the typed-error discriminator and refresh the registry's
    // `extra` JSON before transitioning to Disconnected. Without this,
    // `extra.lastErrorKind` retains the prior runtime's stale kind for
    // any operator inspecting `/control/channels` between shutdown and
    // a subsequent re-registration in the same daemon process.
    state.write().status.last_error_kind = None;
    update_channel_registry_metadata(channel_registry, state);
    channel_registry.update_status(MATRIX_CHANNEL_ID, ChannelStatus::Disconnected);
    // No typed cause for clean shutdown; in-flight tasks resolve as
    // `NotConnected`, matching queued-command drain semantics.
    send_cancel.cancel();
    cancel_and_drain_join_set_with_panic_warn(
        sync_tasks,
        "Matrix sync task panicked during shutdown",
    )
    .await;
    // Maintenance phases hold short-lived locks but no caller-facing
    // reply channels; aborting mid-phase is safe because each phase is
    // a snapshot reconciliation that the next sync iteration can redo.
    // A panic mid-maintenance during shutdown — which could indicate
    // corruption or torn state — must not be silenced; the drain
    // helper surfaces JoinError via `warn!`.
    cancel_and_drain_join_set_with_panic_warn(
        maintenance_tasks,
        "Matrix maintenance task panicked during shutdown",
    )
    .await;
    // Detached verification-refresh tasks (`StartVerification` /
    // `VerificationAction` post-timeout refreshes). Without an
    // explicit shutdown drain, these can run for up to 30s past
    // `set_matrix_runtime(None)`, broadcasting
    // `matrix.verification.updated` WS events for a runtime that
    // no longer exists — racing the next daemon start which would
    // re-bind `WsServerState` and now see stray updates from the
    // prior runtime. Cancel + drain in lockstep with the other
    // JoinSets.
    cancel_and_drain_join_set_with_panic_warn(
        verification_refresh_tasks,
        "Matrix verification-refresh task panicked during shutdown",
    )
    .await;
    drain_cancelled_send_tasks(send_tasks).await;
    drain_pending_commands(rx, MatrixError::NotConnected);
}

/// Cancel every task in `tasks` (`abort_all`) then drain `join_next`
/// to surface JoinError context (panic backtraces, cancellation
/// outcomes). The previous implementation called `tasks.shutdown().await`
/// followed by a separate `join_next()` loop, but `JoinSet::shutdown`
/// already drains every task before returning — the follow-up loop saw
/// `None` immediately and the panic context was silently dropped. With
/// `abort_all` we send the cancellation signal but the tasks remain
/// joinable; the drain loop then iterates each `JoinError` for
/// operator-visible logging. Drain is bounded by a 5s timeout so a
/// hung future cannot block daemon shutdown indefinitely.
async fn cancel_and_drain_join_set_with_panic_warn<T: 'static>(
    tasks: &mut tokio::task::JoinSet<T>,
    label: &'static str,
) {
    let initial_count = tasks.len();
    tasks.abort_all();
    let mut drained_count = 0usize;
    let mut cancelled_count = 0usize;
    let mut panic_count = 0usize;
    let drain = async {
        while let Some(joined) = tasks.join_next().await {
            drained_count = drained_count.saturating_add(1);
            if let Err(join_err) = joined {
                // `is_cancelled` distinguishes the abort_all signal
                // (expected, suppressed at debug) from genuine task
                // panics (warn-log with backtrace context).
                if join_err.is_cancelled() {
                    cancelled_count = cancelled_count.saturating_add(1);
                    debug!(label, "task cancelled during shutdown");
                } else {
                    panic_count = panic_count.saturating_add(1);
                    warn!(
                        error = %crate::logging::redact::RedactedDisplay(&join_err),
                        "{label}"
                    );
                }
            }
        }
    };
    if tokio::time::timeout(Duration::from_secs(5), drain)
        .await
        .is_err()
    {
        let remaining_count = tasks.len();
        warn!(
            label,
            initial_count,
            drained_count,
            cancelled_count,
            panic_count,
            remaining_count,
            "JoinSet drain exceeded 5s shutdown budget; remaining tasks abandoned"
        );
    } else {
        debug!(
            label,
            initial_count,
            drained_count,
            cancelled_count,
            panic_count,
            "JoinSet drained during shutdown"
        );
    }
}

async fn bounded_runtime_status_refresh(
    client: Arc<Client>,
    config: &MatrixConfig,
    state: &Arc<RwLock<MatrixRuntimeState>>,
) -> Result<(), MatrixError> {
    match tokio::time::timeout(
        MATRIX_RUNTIME_OPERATION_TIMEOUT,
        refresh_runtime_status(client, config, state),
    )
    .await
    {
        Ok(result) => result,
        Err(_) => Err(MatrixError::SyncFailed(format!(
            "Matrix runtime status refresh timed out after {} seconds",
            MATRIX_RUNTIME_OPERATION_TIMEOUT.as_secs()
        ))),
    }
}

async fn drain_cancelled_send_tasks(send_tasks: &mut tokio::task::JoinSet<()>) {
    let deadline = tokio::time::sleep(MATRIX_SEND_DRAIN_TIMEOUT);
    tokio::pin!(deadline);
    while !send_tasks.is_empty() {
        tokio::select! {
            _ = &mut deadline => {
                send_tasks.shutdown().await;
                return;
            }
            joined = send_tasks.join_next() => {
                match joined {
                    None => return,
                    Some(Ok(())) => {}
                    Some(Err(join_err)) => {
                        warn!(
                            error = %crate::logging::redact::RedactedDisplay(&join_err),
                            "Matrix outbound send task panicked or was aborted during shutdown drain"
                        );
                    }
                }
            }
        }
    }
}

async fn build_authenticated_client(
    config: &MatrixConfig,
    state_dir: &Path,
    state: &Arc<RwLock<MatrixRuntimeState>>,
) -> Result<Client, MatrixError> {
    ensure_encrypted_matrix_state_supported(config)?;
    let store_dir = state_dir.join("matrix");
    let cache_dir = store_dir.join("cache");
    tokio::fs::create_dir_all(&store_dir)
        .await
        .map_err(|err| MatrixError::ClientBuild(err.to_string()))?;
    recovery::recover_interrupted_recovery_key_rotation(state_dir).await?;
    // Lock the matrix subtree to owner-only on Unix. Encrypted
    // Matrix state (SQLite store, recovery key, installation_id)
    // must NOT be readable by other local accounts — leaking those
    // files allows offline brute-force on CARAPACE_CONFIG_PASSWORD.
    // For encrypted configs this is fail-closed: a chmod that
    // silently failed on a sticky-bit / restrictive parent ACL
    // would leak the secrets across the multi-user boundary the
    // mode bits are designed to enforce. For unencrypted configs
    // (matrix.encrypted=false) the contents are non-secret so
    // best-effort warn is acceptable.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(err) =
            tokio::fs::set_permissions(&store_dir, std::fs::Permissions::from_mode(0o700)).await
        {
            if config.encrypted() {
                return Err(MatrixError::EncryptedStateIo(format!(
                    "failed to set owner-only (0o700) permissions on Matrix encrypted-state \
                     subdirectory {}: {err}. Encrypted Matrix state must not be readable by \
                     other local accounts; refusing to start. Verify the parent directory's \
                     permissions/ACL allow chmod by the daemon user, or move the state \
                     directory to a path the daemon owns.",
                    store_dir.display()
                )));
            }
            tracing::warn!(
                path = %store_dir.display(),
                error = %err,
                "failed to set 0o700 on Matrix state subdirectory; continuing with \
                 default perms (matrix.encrypted=false; contents are non-secret)"
            );
        }
    }
    let store_passphrase = resolve_matrix_store_passphrase(state_dir, config)?;
    // SECURITY: SDK boundary leak — symmetric with the access_token /
    // UIA-password sites further below. The carapace side passes a
    // borrowed `&str` derived from `Zeroizing<String>`, but matrix-sdk's
    // `SqliteStoreConfig` stores the passphrase internally as a plain
    // `String` for SQLCipher key derivation and holds it for the
    // lifetime of the SDK store handle (the longest-lived window of any
    // boundary leak in this file — equal to the actor lifetime).
    // Mitigation would require re-implementing matrix-sdk's
    // SqliteStoreConfig. The `Zeroizing` wrapper on the carapace side
    // only protects the caller's allocation.
    let sqlite_config = SqliteStoreConfig::new(&store_dir)
        .passphrase(store_passphrase.as_deref().map(|p| p.as_str()));
    // Client-wide RequestConfig: cap per-SDK-call duration so a
    // hung TLS handshake on a wedged homeserver cannot wedge daemon
    // startup indefinitely. The SDK's default RequestConfig has no
    // per-call timeout and retries forever. Without this, the eight
    // client.encryption() startup callsites (bootstrap_cross_signing,
    // maybe_restore_recovery_key, recovery().{enable,disable,reset_key},
    // secret_storage().is_enabled), plus login.send / restore_session /
    // whoami, each have no individual deadline; MATRIX_SYNC_WATCHDOG
    // never fires because sync never starts; DaemonPidGuard stays
    // held; the operator sees a stuck process with no diagnostic.
    //
    // 30s per HTTP request matches MATRIX_RUNTIME_OPERATION_TIMEOUT
    // (the runtime-side wrapper for individual SDK calls). short_retry
    // bounds the SDK's internal retry loop to 3 attempts instead of
    // forever — important because the SDK retries transient errors by
    // default, and we want startup to fail-fast on a persistently bad
    // homeserver so the operator gets a quick error rather than a
    // multi-hour silent wedge.
    let request_config = RequestConfig::short_retry().timeout(MATRIX_RUNTIME_OPERATION_TIMEOUT);
    let client = Client::builder()
        .homeserver_url(&config.homeserver_url)
        .sqlite_store_with_config_and_cache_path(sqlite_config, Some(cache_dir))
        .request_config(request_config)
        .build()
        .await
        .map_err(|err| {
            let msg = err.to_string();
            if matrix_open_store_message_indicates_passphrase_mismatch(&msg) {
                MatrixError::EncryptedStorePassphraseMismatch {
                    path: store_dir.clone(),
                    detail: msg,
                }
            } else {
                MatrixError::ClientBuild(msg)
            }
        })?;

    if let (Some(access_token), Some(device_id)) =
        (config.access_token.as_deref(), config.device_id.as_deref())
    {
        restore_matrix_session(&client, config, access_token, device_id).await?;
        let session = validate_restored_matrix_session(&client, config, device_id).await?;
        recovery::maybe_restore_recovery_key(&client, config, state_dir, &session).await?;
        recovery::maybe_bootstrap_cross_signing(
            &client,
            config,
            config.password.as_deref().map(|s| s.as_str()),
            state_dir,
            state,
            &session,
        )
        .await?;
        return Ok(client);
    }

    let password = config
        .password
        .as_deref()
        .ok_or(MatrixError::MissingCredentials)?;
    recovery::preflight_matrix_session_persistence()?;
    // SECURITY: SDK boundary leak — symmetric with the UIA `Password::new`
    // site documented further below and the access_token site at
    // `SessionTokens.access_token`. The carapace side passes a borrowed
    // `&str` from `Zeroizing<String>`, but matrix-sdk's `LoginBuilder`
    // stores the password as a plain `String` in its
    // `LoginMethod::UserPassword { password: String }` variant for the
    // lifetime of the builder + the awaited `login.send()` round-trip.
    // Mitigation would require re-implementing the SDK's LoginBuilder.
    let mut login = client
        .matrix_auth()
        .login_username(&config.user_id, password.as_str())
        .initial_device_display_name("Carapace Matrix");
    if let Some(device_id) = config.device_id.as_deref() {
        login = login.device_id(device_id);
    }
    let response = login.send().await.map_err(|err| {
        // Peel terminal token-revocation classes off into
        // `AuthTokenRevoked` so the operator-facing routing
        // (rekey hint, 503 status) fires instead of a generic
        // `Auth(...)` 503-with-no-hint. Symmetric with
        // `whoami_with_bounded_retry`'s preserved typed variant —
        // both call sites consume the same `matrix_sdk::Error`
        // shape, so they should classify the same way. Without
        // this, an operator whose homeserver has locked or
        // suspended the account between password rotations sees
        // "failed to authenticate Matrix client: …" with no
        // discriminator from "wrong password," which collapses
        // two very different remediations onto one message.
        matrix_auth_error_from_sdk(&err)
    })?;
    if let Err(err) =
        persist_matrix_session(&response.access_token, response.device_id.as_str()).await
    {
        if let Err(logout_err) = client.logout().await {
            warn!(error = %logout_err, "failed to log out Matrix device after session persistence failure");
        }
        return Err(err);
    }
    // A successful password login mints the same witness — the
    // homeserver issued the access token and device ID via the login
    // response, so we don't need a follow-up /whoami to prove identity.
    let user_id: OwnedUserId = config.user_id.parse().map_err(|err| {
        MatrixError::InvalidUserId(format!(
            "Matrix user ID became unparseable after login: {err}"
        ))
    })?;
    let session = ValidatedMatrixSession {
        user_id,
        device_id: response.device_id.clone(),
        _proof: (),
    };
    recovery::maybe_restore_recovery_key(&client, config, state_dir, &session).await?;
    recovery::maybe_bootstrap_cross_signing(
        &client,
        config,
        Some(password),
        state_dir,
        state,
        &session,
    )
    .await?;
    remove_persisted_matrix_password().await?;
    Ok(client)
}

async fn restore_matrix_session(
    client: &Client,
    config: &MatrixConfig,
    access_token: &str,
    device_id: &str,
) -> Result<(), MatrixError> {
    let user_id: OwnedUserId = config
        .user_id
        .parse()
        .map_err(|err| MatrixError::InvalidUserId(format!("invalid Matrix user ID: {err}")))?;
    let device_id: OwnedDeviceId = device_id.into();
    // SECURITY: `access_token.to_string()` materializes a plain (NOT
    // Zeroizing) String that matrix-sdk's `SessionTokens.access_token`
    // holds for the lifetime of the `Client`. This silently breaks
    // the `Zeroizing<String>` discipline that upstream applies to
    // `MatrixConfig.access_token` — the SDK API takes plain String and
    // does not zeroize on drop. Mitigation requires re-implementing
    // matrix-sdk's `SessionTokens` (out of scope here). Mirrors the
    // documented leak at `persist_matrix_session_blocking` (~line
    // 5921). The window is "client process lifetime"; downstream
    // recovery via coredump or post-free heap inspection is
    // theoretically possible until the allocator reuses the buffer.
    let session = matrix_sdk::authentication::matrix::MatrixSession {
        meta: matrix_sdk::SessionMeta { user_id, device_id },
        tokens: matrix_sdk::SessionTokens {
            access_token: access_token.to_string(),
            refresh_token: None,
        },
    };
    client.restore_session(session).await.map_err(|err| {
        // Symmetric with `whoami_with_bounded_retry` and the
        // password-login peel: if the homeserver responds with a
        // terminal token-revocation class (M_UNKNOWN_TOKEN /
        // M_FORBIDDEN / M_USER_DEACTIVATED / M_USER_LOCKED /
        // M_USER_SUSPENDED) during the SDK's restore-session
        // path, preserve the typed `AuthTokenRevoked` variant
        // so `verify_matrix_outcome` can route the rekey-token
        // hint instead of shipping a generic `Auth(...)` 503.
        matrix_auth_error_from_sdk(&err)
    })
}

/// Witness type proving the `Client`'s session was either restored
/// from a token AND validated against the homeserver via `/whoami`, or
/// freshly minted by a successful password login.
///
/// Holding this witness is the only way to call into
/// `maybe_restore_recovery_key` and `maybe_bootstrap_cross_signing` —
/// a future side path that constructs a `Client` without going through
/// either authentication flow CANNOT reach those E2EE-bearing
/// operations because the type cannot be constructed outside this
/// module (the `_proof` field is private). The witness travels with
/// the `Client` from `build_authenticated_client` to its consumers.
#[derive(Debug)]
struct ValidatedMatrixSession {
    user_id: OwnedUserId,
    /// Stored despite being unread today: a future caller (audit
    /// logging, recovery flow) needs the homeserver-confirmed device
    /// id without re-running /whoami. The witness's value is the
    /// "the homeserver confirmed THESE values" guarantee.
    #[allow(dead_code)]
    device_id: OwnedDeviceId,
    /// Private marker preventing construction outside this module.
    /// Without it, `ValidatedMatrixSession { user_id, device_id }`
    /// would be public-constructible from any code that imports the
    /// type — defeating the validation contract.
    _proof: (),
}

async fn validate_restored_matrix_session(
    client: &Client,
    config: &MatrixConfig,
    expected_device_id: &str,
) -> Result<ValidatedMatrixSession, MatrixError> {
    // Bounded retry on transient transport errors before deferring to
    // the sync loop. A short network blip / DNS hiccup at startup
    // shouldn't cause us to skip pre-flight validation entirely (which
    // would let restored-token-mismatch — e.g., operator hand-edited
    // the config — go undetected until first sync). Three attempts
    // with 1s/2s/4s backoff covers the common transient window;
    // anything longer hands off to the sync-loop classifier.
    let response = whoami_with_bounded_retry(client).await?;
    if !matrix_user_ids_equal(&response.user_id, &config.user_id) {
        return Err(MatrixError::AuthSessionUserMismatch {
            actual: response.user_id.to_string(),
            expected: config.user_id.clone(),
        });
    }
    let device_id = match response.device_id.as_ref() {
        Some(device_id) if device_id.as_str() == expected_device_id => device_id.clone(),
        Some(other) => {
            return Err(MatrixError::AuthSessionDeviceMismatch {
                actual: other.to_string(),
                expected: expected_device_id.to_string(),
            });
        }
        None => {
            return Err(MatrixError::AuthSessionMissingDeviceId);
        }
    };
    Ok(ValidatedMatrixSession {
        user_id: response.user_id.clone(),
        device_id,
        _proof: (),
    })
}

async fn persist_matrix_session(access_token: &str, device_id: &str) -> Result<(), MatrixError> {
    // SECURITY: snapshot `config_password()` ONCE here and encrypt the
    // access token in this function's scope, BEFORE handing the
    // candidate config off to `update_config_file` → `seal_config_secrets`.
    //
    // The prior shape did a preflight `config_password().is_none()` check
    // and trusted the seal layer to encrypt. That created a TOCTOU
    // silent-plaintext-leak: between the preflight and
    // `seal_config_secrets`' independent `config_password()` re-read,
    // CARAPACE_CONFIG_PASSWORD could vanish (test pollution, container
    // hot-reload, operator unset) and the seal would early-return
    // `Ok(())`, writing the Matrix access token to disk in plaintext
    // while this caller believed it was encrypted.
    //
    // Encrypt-here-then-seal-as-noop closes the gap: the value flowing
    // into update_config_file is ALREADY enc:v2:, so seal_secrets'
    // is_encrypted() guard skips it whether or not the env var is still
    // set at seal time.
    let Some(password) = crate::config::config_password() else {
        return Err(MatrixError::TokenPersistence(
            "CARAPACE_CONFIG_PASSWORD is required to persist matrix.accessToken as an encrypted config secret".to_string(),
        ));
    };
    let store = crate::config::secrets::SecretStore::new(password.as_ref()).map_err(|err| {
        MatrixError::TokenPersistence(format!("failed to initialize config secret store: {err}"))
    })?;
    let encrypted_access_token =
        zeroize::Zeroizing::new(store.encrypt(access_token).map_err(|err| {
            MatrixError::TokenPersistence(format!("failed to encrypt matrix.accessToken: {err}"))
        })?);
    drop(password); // wipe via Zeroizing Drop before further work
    let device_id = device_id.to_string();
    tokio::task::spawn_blocking(move || {
        persist_matrix_session_blocking(&encrypted_access_token, &device_id)
    })
    .await
    .map_err(|err| MatrixError::TokenPersistence(err.to_string()))?
}

async fn remove_persisted_matrix_password() -> Result<(), MatrixError> {
    tokio::task::spawn_blocking(remove_persisted_matrix_password_blocking)
        .await
        .map_err(|err| MatrixError::TokenPersistence(err.to_string()))?
}

fn remove_persisted_matrix_password_blocking() -> Result<(), MatrixError> {
    let path = crate::config::get_config_path();
    crate::server::ws::update_config_file(&path, |config| {
        let Some(matrix) = config.get_mut("matrix").and_then(Value::as_object_mut) else {
            return Ok(());
        };
        matrix.remove("password");
        Ok(())
    })
    .map_err(MatrixError::TokenPersistence)
}

fn persist_matrix_session_blocking(access_token: &str, device_id: &str) -> Result<(), MatrixError> {
    let path = crate::config::get_config_path();
    crate::server::ws::update_config_file(&path, |config| {
        set_json_path_checked(
            config,
            &["matrix", "accessToken"],
            Value::String(access_token.to_string()),
        )
        .map_err(|err| err.to_string())?;
        set_json_path_checked(
            config,
            &["matrix", "deviceId"],
            Value::String(device_id.to_string()),
        )
        .map_err(|err| err.to_string())
    })
    .map_err(MatrixError::TokenPersistence)
}

fn set_json_path_checked(root: &mut Value, path: &[&str], value: Value) -> Result<(), MatrixError> {
    if path.is_empty() {
        *root = value;
        return Ok(());
    }
    if !root.is_object() {
        return Err(MatrixError::TokenPersistence(
            "config root must be an object to persist Matrix session".to_string(),
        ));
    }
    let mut current = root;
    for key in &path[..path.len() - 1] {
        let obj = current.as_object_mut().ok_or_else(|| {
            MatrixError::TokenPersistence(format!(
                "config path {} is not an object",
                path.join(".")
            ))
        })?;
        current = obj
            .entry((*key).to_string())
            .or_insert_with(|| Value::Object(serde_json::Map::new()));
        if !current.is_object() {
            return Err(MatrixError::TokenPersistence(format!(
                "config path {} is not an object",
                key
            )));
        }
    }
    let obj = current.as_object_mut().ok_or_else(|| {
        MatrixError::TokenPersistence(format!("config path {} is not an object", path.join(".")))
    })?;
    obj.insert(path[path.len() - 1].to_string(), value);
    Ok(())
}

fn register_matrix_event_handlers(
    client: Arc<Client>,
    config: MatrixConfig,
    state_dir: PathBuf,
    ws_state: Arc<WsServerState>,
    channel_registry: Arc<ChannelRegistry>,
    state: Arc<RwLock<MatrixRuntimeState>>,
) {
    // Capture the bool flag up front: `config` is moved into the
    // first closure below, but the encryption-state handler farther
    // down still needs the `encrypted()` discriminator to skip its
    // warn+counter bump when matrix.encrypted=true.
    let encryption_enabled = config.encrypted();
    let room_ws_state = ws_state.clone();
    let room_state = state.clone();
    let room_channel_registry = channel_registry.clone();
    let to_device_config = config.clone();
    client.add_event_handler(move |event: OriginalSyncRoomMessageEvent, room: Room| {
        let ws_state = room_ws_state.clone();
        let config = config.clone();
        let state_dir = state_dir.clone();
        let state = room_state.clone();
        let channel_registry = room_channel_registry.clone();
        async move {
            handle_room_message_event(
                ws_state,
                channel_registry,
                state,
                state_dir,
                config,
                event,
                room,
            )
            .await;
        }
    });
    let to_device_state = state.clone();
    client.add_event_handler(move |event: AnyToDeviceEvent| {
        let ws_state = ws_state.clone();
        let state = to_device_state.clone();
        let config = to_device_config.clone();
        async move {
            verification::handle_to_device_event(ws_state, state, config, event).await;
        }
    });
    // m.room.encryption state-event handler. Without this, a room
    // transitioning from unencrypted → encrypted (operator toggles
    // E2EE on a live room while `matrix.encrypted=false`) would
    // only show up in `MatrixStatusMetadata.unsupported_room_count`
    // at the next post-sync maintenance refresh — potentially
    // minutes later. Operators querying `cara status` in the
    // meantime see a healthy channel that's silently broken for
    // that room. Surface the transition synchronously by bumping
    // the unsupported-inbound counter and logging at warn so the
    // operator gets an immediate journal entry.
    //
    // When `matrix.encrypted=true`, encrypted rooms are SUPPORTED
    // — bumping the unsupported counter would lie. Only the
    // `matrix.encrypted=false` path needs the warn + counter bump.
    let encryption_state = state;
    client.add_event_handler(
        move |event: matrix_sdk::ruma::events::OriginalSyncStateEvent<
            matrix_sdk::ruma::events::room::encryption::RoomEncryptionEventContent,
        >,
              room: Room| {
            let state = encryption_state.clone();
            async move {
                if encryption_enabled {
                    return;
                }
                if room.state() != RoomState::Joined {
                    return;
                }
                let room_id = sanitize_homeserver_identifier(room.room_id().as_str());
                let drop_total = record_matrix_peer_drop(&state, MatrixPeerDropKind::EncryptedRoom);
                if should_log_matrix_peer_drop(drop_total) {
                    warn!(
                        room_id = %room_id,
                        algorithm = ?event.content.algorithm,
                        drop_total,
                        drop_kind = MatrixPeerDropKind::EncryptedRoom.as_str(),
                        "Matrix room transitioned to encrypted state with matrix.encrypted=false; \
                         channel-status will reflect this on the next maintenance refresh"
                    );
                }
                let mut guard = state.write();
                guard.status.unsupported_inbound_count =
                    guard.status.unsupported_inbound_count.saturating_add(1);
            }
        },
    );
}

async fn handle_room_message_event(
    ws_state: Arc<WsServerState>,
    // The room-message handler no longer writes to the channel
    // registry directly — it stamps state and lets
    // `apply_post_sync_maintenance` reconcile the registry. The arg
    // is kept for callers that still pass it (and for symmetry with
    // sibling event handlers); leading underscore silences unused-var.
    _channel_registry: Arc<ChannelRegistry>,
    state: Arc<RwLock<MatrixRuntimeState>>,
    state_dir: PathBuf,
    config: MatrixConfig,
    event: OriginalSyncRoomMessageEvent,
    room: Room,
) {
    if room.state() != RoomState::Joined {
        return;
    }
    let raw_room_id = room.room_id().as_str().to_string();
    let raw_sender_id = event.sender.as_str().to_string();
    let raw_event_id = event.event_id.as_str().to_string();
    // Keep peer-controlled identifiers raw for SDK/runtime/storage identity.
    // Sanitize only the log/display projections below.
    let room_id_log = sanitize_homeserver_identifier(&raw_room_id);
    let sender_id_log = sanitize_homeserver_identifier(&raw_sender_id);
    let event_id_log = sanitize_homeserver_identifier(&raw_event_id);

    if !is_room_supported(&room, config.encrypted()) {
        let drop_total = record_matrix_peer_drop(&state, MatrixPeerDropKind::EncryptedRoom);
        if should_log_matrix_peer_drop(drop_total) {
            warn!(
                room_id = %room_id_log,
                drop_total,
                drop_kind = MatrixPeerDropKind::EncryptedRoom.as_str(),
                "Matrix room became encrypted while matrix.encrypted=false; inbound event ignored"
            );
        }
        // Bump the unsupported-inbound counter here too. Without this,
        // the operator-visible counter on `MatrixStatusMetadata` only
        // reflects the msgtype-not-supported path; an encrypted-room
        // event that's silently dropped would leave the operator
        // wondering why their message produced no agent run, with the
        // "encrypted room marked unsupported" signal only arriving on
        // the next refresh sync (per-room) rather than per-event.
        let mut guard = state.write();
        guard.status.unsupported_inbound_count =
            guard.status.unsupported_inbound_count.saturating_add(1);
        return;
    }

    let MessageType::Text(text_content) = &event.content.msgtype else {
        if let MessageType::VerificationRequest(request) = &event.content.msgtype {
            if !matrix_user_ids_equal(&request.to, &config.user_id) {
                return;
            }
            let sender_str = event.sender.as_str();
            let is_self = matrix_user_ids_equal(&event.sender, &config.user_id);
            if !is_self && !config.auto_join.allows_user(sender_str) {
                let sender_san = sanitize_homeserver_identifier(sender_str);
                let drop_total =
                    record_matrix_peer_drop(&state, MatrixPeerDropKind::AllowlistRejection);
                if should_log_matrix_peer_drop(drop_total) {
                    warn!(
                        sender = %sender_san,
                        drop_total,
                        drop_kind = MatrixPeerDropKind::AllowlistRejection.as_str(),
                        "Matrix room-message verification request dropped: sender is not the configured user nor on the auto-join allowlist"
                    );
                }
                return;
            }
            let verification::VerificationRecordUpsert::Applied {
                info: verification,
                inserted,
            } = verification::upsert_verification_record(
                &state,
                event.event_id.to_string(),
                event.sender.clone(),
                Some(request.from_device.to_string()),
                MatrixVerificationState::Requested,
            )
            else {
                let drop_total =
                    record_matrix_peer_drop(&state, MatrixPeerDropKind::VerificationCapFull);
                if should_log_matrix_peer_drop(drop_total) {
                    warn!(
                        drop_total,
                        drop_kind = MatrixPeerDropKind::VerificationCapFull.as_str(),
                        "Matrix room-message verification request dropped: verification record cap is full of active flows"
                    );
                }
                return;
            };
            crate::server::ws::broadcast_matrix_verification_request(
                &ws_state,
                crate::server::ws::NewVerificationFlow::from_upsert(&verification, inserted),
            );
            // Suppress the `updated` event when this is a fresh
            // insert — `requested` already covers the state
            // transition. Doubling broadcasts on every inbound
            // verification doubles the rate at which slow
            // operator dashboards get evicted via try_send-on-Full
            // under SAS-flood from a hostile peer.
            if !inserted {
                crate::server::ws::broadcast_matrix_verification_updated(
                    &ws_state,
                    crate::server::ws::UpdatedVerificationFlow::for_state_change(&verification),
                );
            }
            return;
        }
        // Self-sent non-text events still bypass the unsupported counter
        // — the bot's own outbound (e.g. an event we just sent) shouldn't
        // count as "the bot ignored an inbound" from the operator's POV.
        if matrix_user_ids_equal(&event.sender, &config.user_id) {
            return;
        }
        // Surface non-text inbound at warn level with an operator-visible
        // counter on channel status. Without this, image/file/audio/video
        // messages reach the homeserver and the bot is mute, with no log
        // and no visible signal explaining why no agent run happened.
        let msgtype = event.content.msgtype.msgtype().to_string();
        let drop_total = record_matrix_peer_drop(&state, MatrixPeerDropKind::UnsupportedMsgtype);
        if should_log_matrix_peer_drop(drop_total) {
            warn!(
                room_id = %room_id_log,
                sender = %sender_id_log,
                event_id = %event_id_log,
                msgtype = %msgtype,
                drop_total,
                drop_kind = MatrixPeerDropKind::UnsupportedMsgtype.as_str(),
                "Matrix inbound event ignored: msgtype not yet supported",
            );
        }
        let mut guard = state.write();
        guard.status.unsupported_inbound_count =
            guard.status.unsupported_inbound_count.saturating_add(1);
        return;
    };
    if matrix_user_ids_equal(&event.sender, &config.user_id) {
        return;
    }
    if !config.auto_join.allows_user(&raw_sender_id) {
        let drop_total = record_matrix_peer_drop(&state, MatrixPeerDropKind::AllowlistRejection);
        if should_log_matrix_peer_drop(drop_total) {
            warn!(
                room_id = %room_id_log,
                sender = %sender_id_log,
                event_id = %event_id_log,
                drop_total,
                drop_kind = MatrixPeerDropKind::AllowlistRejection.as_str(),
                "Matrix inbound text message dropped: sender is not on the auto-join allowlist"
            );
        }
        return;
    }
    if let Some(reason) = matrix_relation_suppression_reason(event.content.relates_to.as_ref()) {
        debug!(event_id = %event_id_log, reason = reason, "Matrix relation suppressed");
        return;
    }
    // Skip whitespace-only messages. A stuck client or a typo could
    // emit an empty body; dispatching `"   "` to the agent runtime
    // wastes an LLM call. The body's idempotency token is still
    // logged so a redelivery loop is observable in the journal.
    //
    // SECURITY: `trim().is_empty()` does NOT catch bodies
    // composed only of bidi/zero-width format chars (U+202E and
    // friends). `'\u{202E}'.is_whitespace()` is false, so a body of
    // exactly "\u{202E}" passed the prior check and got dispatched
    // to the LLM as a 1-char prompt while polluting session history
    // and reset-policy bookkeeping. Reject any body whose every char
    // is whitespace, control, or bidi/zero-width.
    if text_content
        .body
        .chars()
        .all(|c| c.is_whitespace() || c.is_control() || is_bidi_or_zero_width(c))
    {
        debug!(
            event_id = %event_id_log,
            sender = %sender_id_log,
            "Matrix inbound message had empty/whitespace-or-format-only body; skipping dispatch"
        );
        return;
    }
    // SECURITY: cap inbound body size. Without this, a peer in any
    // joined room can send a 100 MB body which flows through the
    // session log, agent prompt, and (on dispatch failure) the DLQ
    // record — N copies of the same memory hog. 64 KiB is well above
    // sane chat usage and well below the homeserver's typical
    // per-event size limit, so legitimate traffic isn't affected.
    // Drop with a warn rather than truncate-with-marker because the
    // truncated version would still let an adversary force the
    // runtime through the rest of the dispatch pipeline.
    if text_content.body.len() > MATRIX_INBOUND_BODY_MAX_BYTES {
        let drop_total = record_matrix_peer_drop(&state, MatrixPeerDropKind::BodyTooLarge);
        if should_log_matrix_peer_drop(drop_total) {
            warn!(
                event_id = %event_id_log,
                sender = %sender_id_log,
                body_bytes = text_content.body.len(),
                limit_bytes = MATRIX_INBOUND_BODY_MAX_BYTES,
                drop_total,
                drop_kind = MatrixPeerDropKind::BodyTooLarge.as_str(),
                "Matrix inbound message body exceeds size cap; dropping event without dispatch"
            );
        }
        let mut guard = state.write();
        guard.status.unsupported_inbound_count =
            guard.status.unsupported_inbound_count.saturating_add(1);
        return;
    }
    debug!(
        room_id = %room_id_log,
        sender = %sender_id_log,
        event_id = %event_id_log,
        "Matrix inbound message"
    );
    let idempotency_key = matrix_event_idempotency_key(&raw_event_id);
    match crate::channels::inbound::dispatch_inbound_text_with_options(
        &ws_state,
        MATRIX_CHANNEL_ID,
        &raw_sender_id,
        &raw_room_id,
        &text_content.body,
        Some(raw_room_id.clone()),
        crate::channels::inbound::InboundDispatchOptions {
            inbound_event_id: idempotency_key,
            delivery_recipient_id: Some(raw_room_id.clone()),
            ..Default::default()
        },
    )
    .await
    {
        Ok(result) => {
            let mut guard = state.write();
            guard.record_inbound_dedupe_corrupt_lines(result.corrupt_dedupe_index_lines);
            guard.reset_inbound_failures();
        }
        Err(err) => {
            let dlq_record = inbound_dlq::MatrixInboundDlqRecord::new(
                &event.event_id,
                room.room_id(),
                &event.sender,
                text_content.body.clone(),
                now_millis(),
            );
            if let Err(dlq_err) = inbound_dlq::append_matrix_inbound_dlq(
                &state_dir,
                &config,
                state.clone(),
                &dlq_record,
            )
            .await
            {
                let message = format!(
                    "Matrix inbound dispatch failed and DLQ append failed for event {event_id_log}: {}",
                    crate::logging::redact::RedactedDisplay(&dlq_err)
                );
                // Stamp on state and let maintenance reconcile the
                // registry. record_inbound_dlq_append_failure already
                // sets `inbound_dlq_durability_error` which maintenance
                // checks via `inbound_durability_error_is_sticky`.
                state.write().record_inbound_dlq_append_failure(message);
            }
            // Atomic bump-and-stamp: `record_inbound_failure_with_error`
            // increments the streak AND stamps the error message in
            // one `state.write()` so a concurrent maintenance read
            // can never observe `(sticky=true, pending=None)`.
            // Maintenance owns the registry transition under its own
            // pass — inbound never writes the registry directly.
            let error_kind = if err.is_session_history_corrupt() {
                MatrixError::SessionHistoryCorrupt(String::new()).kind()
            } else {
                MatrixError::SyncFailed(String::new()).kind()
            };
            let error_msg = format!(
                "Matrix inbound dispatch failing: {}",
                crate::logging::redact::RedactedDisplay(&err)
            );
            let (failures, lifetime_failures) = {
                let mut guard = state.write();
                let count = guard.record_inbound_failure_with_error(error_msg, error_kind);
                // Lifetime counter survives the consecutive-failure
                // decay so operators auditing inbound delivery health
                // can see total drops over the daemon's uptime, even
                // after `last_error` has been cleared by a later
                // successful sync.
                guard.status.inbound_dispatch_failure_total = guard
                    .status
                    .inbound_dispatch_failure_total
                    .saturating_add(1);
                (count, guard.status.inbound_dispatch_failure_total)
            };
            if should_log_matrix_inbound_dispatch_failure(failures, lifetime_failures) {
                warn!(
                    error = %crate::logging::redact::RedactedDisplay(&err),
                    failures,
                    lifetime_failures,
                    "failed to dispatch Matrix inbound message"
                );
            } else {
                debug!(
                    error = %crate::logging::redact::RedactedDisplay(&err),
                    failures,
                    lifetime_failures,
                    "failed to dispatch Matrix inbound message"
                );
            }
        }
    }
}

fn record_matrix_peer_drop(
    state: &Arc<RwLock<MatrixRuntimeState>>,
    kind: MatrixPeerDropKind,
) -> u64 {
    state.write().record_peer_drop(kind)
}

fn should_log_matrix_peer_drop(total: u64) -> bool {
    total <= 10 || total.is_power_of_two()
}

fn should_log_matrix_inbound_dispatch_failure(streak_failures: u32, lifetime_total: u64) -> bool {
    streak_failures == 1 || should_log_matrix_peer_drop(lifetime_total)
}

async fn sync_parent_dir_or_err(path: &Path) -> Result<(), MatrixError> {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || sync_parent_dir_or_err_blocking(&path))
        .await
        .map_err(|err| MatrixError::SyncFailed(format!("Matrix parent-dir fsync task: {err}")))?
}

/// Synchronously fsync the parent directory of `path`, surfacing any
/// failure as `MatrixError::SyncFailed`. Used on success paths that
/// commit a tmp+rename and where the dirent's durability is part of
/// the documented contract. A failure here means the rename hasn't
/// actually landed on disk; the caller must propagate the error
/// rather than report success.
fn sync_parent_dir_or_err_blocking(path: &Path) -> Result<(), MatrixError> {
    crate::paths::sync_parent_dir_blocking(path)
        .map_err(|err| MatrixError::SyncFailed(format!("fsync parent dir: {err}")))
}

async fn send_matrix_text(
    client: Arc<Client>,
    config: &MatrixConfig,
    ctx: OutboundContext,
) -> Result<DeliveryResult, MatrixError> {
    send_matrix_text_from_client(client.as_ref(), config, ctx).await
}

trait MatrixTextSendClient: Sync {
    type Room: MatrixTextSendRoom;

    fn get_text_send_room(&self, room_id: &RoomId) -> Option<Self::Room>;
}

#[async_trait::async_trait]
trait MatrixTextSendRoom: Send + Sync {
    fn room_id_for_delivery(&self) -> String;
    fn supported_for_send(&self, encrypted: bool) -> bool;
    async fn send_text_content(
        &self,
        content: RoomMessageEventContent,
    ) -> Result<String, MatrixTextSendFailure>;
}

#[derive(Debug, Clone)]
enum MatrixTextSendFailure {
    Terminal(MatrixError),
    Transient {
        error: String,
        retry_after_ms: Option<i64>,
    },
}

impl MatrixTextSendClient for Client {
    type Room = Room;

    fn get_text_send_room(&self, room_id: &RoomId) -> Option<Self::Room> {
        self.get_room(room_id)
    }
}

#[async_trait::async_trait]
impl MatrixTextSendRoom for Room {
    fn room_id_for_delivery(&self) -> String {
        self.room_id().to_string()
    }

    fn supported_for_send(&self, encrypted: bool) -> bool {
        is_room_supported(self, encrypted)
    }

    async fn send_text_content(
        &self,
        content: RoomMessageEventContent,
    ) -> Result<String, MatrixTextSendFailure> {
        let send_result = tokio::time::timeout(MATRIX_SEND_TIMEOUT, self.send(content))
            .await
            .map_err(|_| {
                MatrixTextSendFailure::Terminal(MatrixError::SendFailed {
                    message: format!(
                        "Matrix send timed out after {} seconds",
                        MATRIX_SEND_TIMEOUT.as_secs()
                    ),
                    retry_after_ms: None,
                })
            })?;
        match send_result {
            Ok(response) => Ok(response.event_id.to_string()),
            Err(err) => {
                if let Some(terminal) = matrix_send_terminal_error(&err) {
                    return Err(MatrixTextSendFailure::Terminal(terminal));
                }
                let retry_after_ms = matrix_retry_after(&err)
                    .map(|d| d.min(MATRIX_RETRY_AFTER_MAX))
                    .map(|d| d.as_millis() as i64);
                let error = crate::logging::redact::RedactedDisplay(&err).to_string();
                Err(MatrixTextSendFailure::Transient {
                    error,
                    retry_after_ms,
                })
            }
        }
    }
}

async fn send_matrix_text_from_client<C>(
    client: &C,
    config: &MatrixConfig,
    ctx: OutboundContext,
) -> Result<DeliveryResult, MatrixError>
where
    C: MatrixTextSendClient,
{
    let OutboundContext {
        to,
        text,
        media_url: _,
        gif_playback: _,
        reply_to_id,
        thread_id,
        account_id: _,
    } = ctx;
    let room_id = RoomId::parse(to.as_str()).map_err(|_| MatrixError::RoomNotFound(to.clone()))?;
    let room = client
        .get_text_send_room(&room_id)
        .ok_or_else(|| MatrixError::RoomNotFound(to.clone()))?;
    let room_id_for_delivery = room.room_id_for_delivery();
    if !room.supported_for_send(config.encrypted()) {
        return Err(MatrixError::UnsupportedRoom(format!(
            "{room_id_for_delivery} is encrypted but matrix.encrypted=false"
        )));
    }
    let content = matrix_room_message_content(text, reply_to_id.as_deref(), thread_id.as_deref());
    match room.send_text_content(content).await {
        Ok(event_id) => Ok(matrix_successful_delivery_result(
            event_id,
            room_id_for_delivery,
        )),
        Err(MatrixTextSendFailure::Terminal(err)) => Err(err),
        Err(MatrixTextSendFailure::Transient {
            error,
            retry_after_ms,
        }) => Ok(matrix_transient_send_delivery_result(
            error,
            retry_after_ms,
            room_id_for_delivery,
        )),
    }
}

fn matrix_room_message_content(
    text: String,
    reply_to_id: Option<&str>,
    thread_id: Option<&str>,
) -> RoomMessageEventContent {
    // SECURITY: the prior `text_plain(ctx.text)` constructor
    // silently dropped `ctx.reply_to_id` and `ctx.thread_id`. Plugin
    // authors who set these on `OutboundContext` got a top-level
    // message instead of the Matrix `m.relates_to` shape they
    // requested — replies rendered without quoted parents, threads
    // never threaded. Honor the fields by attaching the appropriate
    // `Relation` to the content. Invalid event IDs from the plugin
    // are tracing-warned and ignored rather than erroring the send,
    // so a single bad reply_to_id doesn't take the whole send path
    // down.
    use matrix_sdk::ruma::events::relation::{InReplyTo, Thread};
    use matrix_sdk::ruma::events::room::message::Relation;
    use matrix_sdk::ruma::OwnedEventId;
    let mut content = RoomMessageEventContent::text_plain(text);
    // SECURITY: cap the raw plugin-supplied string before
    // logging so a malicious plugin cannot inject ANSI escapes,
    // newlines, or megabyte payloads into operator logs via the
    // tracing fallback. 256 bytes is comfortably above a legitimate
    // Matrix event id (<128 bytes) and bounds the log-injection
    // surface to whatever the tracing layer's own escape policy is.
    fn bound_plugin_log_field(raw: &str) -> &str {
        const LOG_INJECT_CAP: usize = 256;
        if raw.len() <= LOG_INJECT_CAP {
            return raw;
        }
        let mut boundary = LOG_INJECT_CAP;
        while boundary > 0 && !raw.is_char_boundary(boundary) {
            boundary -= 1;
        }
        &raw[..boundary]
    }
    let reply_to_event_id = reply_to_id.and_then(|raw| match OwnedEventId::try_from(raw) {
        Ok(id) => Some(id),
        Err(err) => {
            tracing::warn!(
                plugin_reply_to_id = bound_plugin_log_field(raw),
                error = %err,
                "matrix outbound: dropping invalid reply_to_id from plugin context",
            );
            None
        }
    });
    let thread_root_event_id = thread_id.and_then(|raw| match OwnedEventId::try_from(raw) {
        Ok(id) => Some(id),
        Err(err) => {
            tracing::warn!(
                plugin_thread_id = bound_plugin_log_field(raw),
                error = %err,
                "matrix outbound: dropping invalid thread_id from plugin context",
            );
            None
        }
    });
    content.relates_to = match (thread_root_event_id, reply_to_event_id) {
        // Thread + reply: use Thread::reply so the in_reply_to inside the
        // thread points at the actual replied-to event and not the thread
        // root.
        (Some(thread_root), Some(reply_event)) => {
            Some(Relation::Thread(Thread::reply(thread_root, reply_event)))
        }
        // Thread only: emit a thread relation without an in_reply_to
        // fallback. Clients that don't render threads will still receive
        // the message at the top level.
        (Some(thread_root), None) => Some(Relation::Thread(Thread::without_fallback(thread_root))),
        // Reply only: plain rich-reply (no thread wrapping).
        (None, Some(reply_event)) => Some(Relation::Reply {
            in_reply_to: InReplyTo::new(reply_event),
        }),
        (None, None) => None,
    };
    content
}

fn matrix_successful_delivery_result(event_id: String, room_id: String) -> DeliveryResult {
    DeliveryResult {
        ok: true,
        message_id: Some(event_id),
        error: None,
        retryability: crate::plugins::Retryability::Terminal,
        conversation_id: Some(room_id),
        to_jid: None,
        poll_id: None,
        error_kind: None,
    }
}

fn matrix_transient_send_delivery_result(
    error: String,
    retry_after_ms: Option<i64>,
    room_id: String,
) -> DeliveryResult {
    DeliveryResult {
        ok: false,
        message_id: None,
        error: Some(format!("Matrix send failed: {error}")),
        retryability: Retryability::Transient { retry_after_ms },
        conversation_id: Some(room_id),
        to_jid: None,
        poll_id: None,
        // SDK-level send failures classify as `send-failed`
        // (matches `MatrixError::SendFailed.kind()`) so the
        // /control/matrix/send-test wire payload surfaces a typed
        // discriminator instead of forcing clients to substring-parse
        // the redacted `error` message.
        error_kind: Some("send-failed".to_string()),
    }
}

fn matrix_retryable_delivery_result(error: String) -> DeliveryResult {
    matrix_retryable_delivery_result_with_retry_after(error, None, None)
}

fn matrix_retryable_delivery_result_with_retry_after(
    error: String,
    retry_after_ms: Option<i64>,
    error_kind: Option<&'static str>,
) -> DeliveryResult {
    DeliveryResult {
        ok: false,
        message_id: None,
        error: Some(error),
        retryability: Retryability::Transient { retry_after_ms },
        conversation_id: None,
        to_jid: None,
        poll_id: None,
        error_kind: error_kind.map(|s| s.to_string()),
    }
}

/// Threshold above which a single tick of invite failures is treated
/// as systemic (homeserver problem, network outage) rather than a
/// transient per-room hiccup. At that level the FailureStreak's 3-tick
/// hysteresis would let `cara status` show `Connected` for ~3 sync
/// cycles while every invite is failing — too long for an operator
/// monitoring fan-out. Bypass the streak when this many failures fire
/// in a single tick.
const MATRIX_INVITE_SYSTEMIC_FAILURE_THRESHOLD: usize = 3;

async fn handle_invites(
    client: Arc<Client>,
    config: &MatrixConfig,
    state: &Arc<RwLock<MatrixRuntimeState>>,
) -> Result<(), MatrixError> {
    handle_invites_from_source(client.as_ref(), config, state).await
}

// Internal test seam: production impls delegate to the Matrix SDK, while unit
// tests provide fakes for invite policy and failure accounting.
trait MatrixInviteSource: Sync {
    type Room: MatrixInviteRoom;

    fn invited_rooms(&self) -> Vec<Self::Room>;
}

#[async_trait::async_trait]
trait MatrixInviteRoom: Send + Sync {
    fn room_id_for_log(&self) -> Cow<'_, str>;
    async fn invite_inviter(&self) -> Result<Option<String>, MatrixInviteFailure>;
    fn definitely_encrypted(&self) -> bool;
    async fn leave_invite(&self) -> Result<(), MatrixInviteFailure>;
    async fn join_invite(&self) -> Result<(), MatrixInviteFailure>;
}

impl MatrixInviteSource for Client {
    type Room = Room;

    fn invited_rooms(&self) -> Vec<Self::Room> {
        Client::invited_rooms(self)
    }
}

#[async_trait::async_trait]
impl MatrixInviteRoom for Room {
    fn room_id_for_log(&self) -> Cow<'_, str> {
        Cow::Borrowed(self.room_id().as_str())
    }

    async fn invite_inviter(&self) -> Result<Option<String>, MatrixInviteFailure> {
        let invite = self
            .invite_details()
            .await
            .map_err(MatrixInviteFailure::from_display)?;
        Ok(invite
            .inviter
            .as_ref()
            .map(|member| member.user_id().to_string()))
    }

    fn definitely_encrypted(&self) -> bool {
        is_invite_room_definitely_encrypted(self)
    }

    async fn leave_invite(&self) -> Result<(), MatrixInviteFailure> {
        self.leave()
            .await
            .map_err(MatrixInviteFailure::from_display)
    }

    async fn join_invite(&self) -> Result<(), MatrixInviteFailure> {
        self.join().await.map_err(MatrixInviteFailure::from_display)
    }
}

#[derive(Debug, Clone)]
struct MatrixInviteFailure {
    message: String,
}

impl MatrixInviteFailure {
    fn from_display(err: impl std::fmt::Display) -> Self {
        Self {
            message: crate::logging::redact::RedactedDisplay(&err).to_string(),
        }
    }

    #[cfg(test)]
    // Intentionally unredacted for scripted fake errors. Production call sites
    // must use from_display so homeserver-controlled errors pass RedactedDisplay.
    fn from_message(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for MatrixInviteFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

async fn handle_invites_from_source<S>(
    source: &S,
    config: &MatrixConfig,
    state: &Arc<RwLock<MatrixRuntimeState>>,
) -> Result<(), MatrixError>
where
    S: MatrixInviteSource,
{
    let mut failures = Vec::new();
    // Per-tick warn-emission cap for SDK call failures inside the
    // invite-handling loop. A hostile homeserver delivering 10K
    // invites would otherwise emit one warn per inspect/leave/join
    // failure per maintenance tick — same flooding shape the DLQ
    // replay loop's per-kind cap defends against. The `failures`
    // Vec still records every event_id-shaped detail via
    // `push_invite_failure`, which feeds the systemic-failure
    // detection and the operator-visible `last_error` JSON; only
    // the per-event tracing warn is capped.
    const INVITE_HANDLER_PER_KIND_WARN_CAP: usize = 10;
    let mut inspect_failure_warn_count = 0usize;
    let mut reject_failure_warn_count = 0usize;
    let mut encrypted_reject_failure_warn_count = 0usize;
    let mut join_failure_warn_count = 0usize;
    let mut suppressed_inspect_failure_count = 0usize;
    let mut suppressed_reject_failure_count = 0usize;
    let mut suppressed_encrypted_reject_failure_count = 0usize;
    let mut suppressed_join_failure_count = 0usize;
    for room in source.invited_rooms() {
        // Sanitize peer-controlled identifiers once per iteration so
        // every log emission and operator-visible failure summary
        // below uses defense-in-depth-cleaned values. ruma's
        // identifier validators don't strip control bytes, so a
        // hostile homeserver delivering an invite from a crafted
        // inviter ID could otherwise inject ANSI escapes into
        // operator scrollback. The raw `inviter` string is still
        // needed for the byte-exact `auto_join.allows_user`
        // allowlist match — sanitizing the allowlist input would
        // make a legitimate operator-configured allowlist entry
        // fail to match its own user.
        let room_id_san = sanitize_homeserver_identifier(room.room_id_for_log().as_ref());
        let inviter = match room.invite_inviter().await {
            Ok(inviter) => inviter,
            Err(err) => {
                if inspect_failure_warn_count < INVITE_HANDLER_PER_KIND_WARN_CAP {
                    inspect_failure_warn_count += 1;
                    warn!(
                        room_id = %room_id_san,
                        error = %crate::logging::redact::RedactedDisplay(&err),
                        "failed to inspect Matrix invite"
                    );
                } else {
                    suppressed_inspect_failure_count += 1;
                }
                // Wrap the SDK error display in `RedactedDisplay` so
                // homeserver-controlled bytes (`error` field of the
                // HTTP response) are stripped before they land in the
                // failures Vec. The summary feeds
                // `record_invite_systemic_failure`, which surfaces at
                // `last_error` JSON — a path that bypasses the
                // tracing-writer-layer redactor entirely.
                push_invite_failure(&mut failures, &room_id_san, "inspect", &err);
                continue;
            }
        };
        let inviter_san = inviter.as_deref().map(sanitize_homeserver_identifier);
        let allowed = inviter
            .as_deref()
            .map(|user_id| config.auto_join.allows_user(user_id))
            .unwrap_or(false);
        if !allowed {
            let drop_total = record_matrix_peer_drop(state, MatrixPeerDropKind::AllowlistRejection);
            // Distinguish two reasons for rejection so an operator
            // checking logs doesn't conclude their allowlist is
            // misconfigured when the homeserver actually withheld the
            // inviter identity. Logged at info-level (not debug) since
            // a one-off allowlist mismatch is the most common operator
            // misconfig and won't fire MATRIX_INVITE_SYSTEMIC_FAILURE_THRESHOLD
            // — the operator needs visibility at default log filter.
            // Includes allowlist cardinality for triage.
            if inviter.is_none() {
                if should_log_matrix_peer_drop(drop_total) {
                    info!(
                        room_id = %room_id_san,
                        allow_users_count = config.auto_join.allow_users.len(),
                        allow_server_names_count = config.auto_join.allow_server_names.len(),
                        drop_total,
                        drop_kind = MatrixPeerDropKind::AllowlistRejection.as_str(),
                        "Matrix invite rejected: homeserver did not provide an inviter identity"
                    );
                }
            } else if should_log_matrix_peer_drop(drop_total) {
                info!(
                    room_id = %room_id_san,
                    inviter = inviter_san.as_deref().unwrap_or("<unknown>"),
                    allow_users_count = config.auto_join.allow_users.len(),
                    allow_server_names_count = config.auto_join.allow_server_names.len(),
                    drop_total,
                    drop_kind = MatrixPeerDropKind::AllowlistRejection.as_str(),
                    "Matrix invite rejected by auto-join allowlist"
                );
            }
            if let Err(err) = room.leave_invite().await {
                if reject_failure_warn_count < INVITE_HANDLER_PER_KIND_WARN_CAP {
                    reject_failure_warn_count += 1;
                    warn!(
                        room_id = %room_id_san,
                        error = %crate::logging::redact::RedactedDisplay(&err),
                        "failed to reject Matrix invite"
                    );
                } else {
                    suppressed_reject_failure_count += 1;
                }
                push_invite_failure(&mut failures, &room_id_san, "reject", &err);
            }
            continue;
        }
        if !config.encrypted() && room.definitely_encrypted() {
            let drop_total = record_matrix_peer_drop(state, MatrixPeerDropKind::EncryptedRoom);
            if should_log_matrix_peer_drop(drop_total) {
                warn!(
                    room_id = %room_id_san,
                    inviter = inviter_san.as_deref().unwrap_or("<unknown>"),
                    drop_total,
                    drop_kind = MatrixPeerDropKind::EncryptedRoom.as_str(),
                    "Matrix invite refused because room is encrypted and matrix.encrypted=false"
                );
            }
            if let Err(err) = room.leave_invite().await {
                if encrypted_reject_failure_warn_count < INVITE_HANDLER_PER_KIND_WARN_CAP {
                    encrypted_reject_failure_warn_count += 1;
                    warn!(
                        room_id = %room_id_san,
                        error = %crate::logging::redact::RedactedDisplay(&err),
                        "failed to reject encrypted Matrix invite"
                    );
                } else {
                    suppressed_encrypted_reject_failure_count += 1;
                }
                push_invite_failure(&mut failures, &room_id_san, "encrypted reject", &err);
            }
            continue;
        }
        if let Err(err) = room.join_invite().await {
            if join_failure_warn_count < INVITE_HANDLER_PER_KIND_WARN_CAP {
                join_failure_warn_count += 1;
                warn!(
                    room_id = %room_id_san,
                    error = %crate::logging::redact::RedactedDisplay(&err),
                    "failed to auto-join Matrix invite"
                );
            } else {
                suppressed_join_failure_count += 1;
            }
            push_invite_failure(&mut failures, &room_id_san, "join", &err);
        } else {
            info!(
                room_id = %room_id_san,
                inviter = inviter_san.as_deref().unwrap_or("<unknown>"),
                "auto-joined Matrix room invite"
            );
        }
    }
    // Per-tick suppressed-warn summary for the invite handler.
    // Cardinality bound: 4 summary warns at most per tick. The
    // channel-status `last_error` is a first-3-of-N preview, NOT a
    // full failure list — the underlying `failures` Vec is consumed
    // into that summary and dropped at function return. An operator
    // diagnosing a specific suppressed room_id beyond the preview
    // window has to either (a) wait for the next maintenance tick
    // (the same rooms will be re-inspected and the first-10 warn
    // budget refills) or (b) increase the homeserver-side audit
    // visibility. The `unsupported_room_count` channel-status field
    // still carries the accurate scale signal.
    if suppressed_inspect_failure_count > 0 {
        warn!(
            suppressed = suppressed_inspect_failure_count,
            logged = inspect_failure_warn_count,
            "Matrix invite inspect failures (suppressed remainder; channel status \
             `last_error` carries a first-3-of-N preview only, suppressed room_ids will \
             re-surface on the next maintenance tick)"
        );
    }
    if suppressed_reject_failure_count > 0 {
        warn!(
            suppressed = suppressed_reject_failure_count,
            logged = reject_failure_warn_count,
            "Matrix invite reject failures (suppressed remainder; channel status \
             `last_error` carries a first-3-of-N preview only)"
        );
    }
    if suppressed_encrypted_reject_failure_count > 0 {
        warn!(
            suppressed = suppressed_encrypted_reject_failure_count,
            logged = encrypted_reject_failure_warn_count,
            "Matrix encrypted-invite reject failures (suppressed remainder; channel status \
             `last_error` carries a first-3-of-N preview only)"
        );
    }
    if suppressed_join_failure_count > 0 {
        warn!(
            suppressed = suppressed_join_failure_count,
            logged = join_failure_warn_count,
            "Matrix invite join failures (suppressed remainder; channel status `last_error` \
             carries a first-3-of-N preview only)"
        );
    }
    if failures.is_empty() {
        Ok(())
    } else {
        // First 3 entries give operators an actionable sample; the
        // count tells them how wide the impact is. journald / log
        // forwarders won't have to truncate it themselves with no
        // preview.
        let total = failures.len();
        let summary = summarize_failures(&failures, 3);
        // Systemic-failure bypass: when many invites fail in one tick
        // (a homeserver outage, network partition), the FailureStreak's
        // 3-tick hysteresis hides the problem from `cara status` for
        // ~3 sync cycles. Stamp a sticky durability error directly so
        // it surfaces immediately. The marker is cleared ONLY on a
        // fully-clean tick (handled by apply_post_sync_maintenance's
        // Ok-arm via clear_invite_systemic_failure) — clearing on a
        // sub-threshold-but-still-failing tick lets the channel flip
        // Error→Connected on a still-failing tick because
        // non_inbound_sticky goes false (marker=None, count below
        // threshold) and the else-branch fires update_status(Connected).
        if let Some(message) = compute_invite_systemic_message(&failures) {
            state.write().record_invite_systemic_failure(message);
        }
        Err(MatrixError::SyncFailed(format!(
            "Matrix invite handling failures ({total}): {summary}"
        )))
    }
}

/// Push an invite-handling failure entry onto the failures Vec
/// with a redacted SDK error display. The SDK error
/// `matrix_sdk::Error` Display can carry homeserver response-body
/// bytes (the `error` field of an HTTP error response is
/// homeserver-controlled), so wrapping in `RedactedDisplay`
/// strips control / Cf chars before the bytes land on
/// `last_error` JSON — a path that bypasses the writer-layer
/// redactor entirely. Centralizing the wrap removes the risk
/// that one of the four call sites forgets the redaction.
fn push_invite_failure(
    failures: &mut Vec<String>,
    room_id_san: &str,
    op_label: &'static str,
    err: &(dyn std::fmt::Display + Sync),
) {
    failures.push(format!(
        "{room_id_san} {op_label} failed: {}",
        crate::logging::redact::RedactedDisplay(err)
    ));
}

/// Operator-visible summary of a failure list: emit the first
/// `preview_len` entries verbatim, then `(N more)` if the list
/// exceeds the preview length. Shared by the invite-systemic and
/// DLQ-replay paths so the journald / log-aggregator preview shape
/// stays consistent across surfaces.
fn summarize_failures(items: &[String], preview_len: usize) -> String {
    let total = items.len();
    let preview: Vec<&str> = items.iter().take(preview_len).map(String::as_str).collect();
    if total <= preview.len() {
        items.join("; ")
    } else {
        format!("{} ({} more)", preview.join("; "), total - preview.len())
    }
}

/// Decision helper extracted from `handle_invites`: when a
/// maintenance tick observes ≥`MATRIX_INVITE_SYSTEMIC_FAILURE_THRESHOLD`
/// invite failures in a single pass, return the operator-facing
/// systemic-error message. Below threshold, return `None` —
/// `FailureStreak`'s 3-tick hysteresis handles the slower escalation
/// path. Pure function (no state reads/writes) so a unit test can
/// drive it directly without constructing an SDK `Client` fixture.
fn compute_invite_systemic_message(failures: &[String]) -> Option<String> {
    let total = failures.len();
    if total < MATRIX_INVITE_SYSTEMIC_FAILURE_THRESHOLD {
        return None;
    }
    let summary = summarize_failures(failures, 3);
    Some(format!(
        "Matrix invite handling: {total} failures in one maintenance tick: {summary} \
         — check homeserver connectivity and matrix.autoJoin allowlist"
    ))
}

async fn refresh_runtime_status(
    client: Arc<Client>,
    config: &MatrixConfig,
    state: &Arc<RwLock<MatrixRuntimeState>>,
) -> Result<(), MatrixError> {
    // Returns `Result<(), MatrixError>` for consistency with the other
    // refresh phases (`refresh_device_state`, `refresh_verification_records`,
    // `replay_matrix_inbound_dlq`, `handle_invites`) which all flow
    // through `bounded_matrix_result` + a per-phase `FailureStreak`.
    // The function body currently has no fallible operations
    // (`client.joined_rooms()` returns an in-memory iterator), but
    // typing the signature as `Result` means future fallible additions
    // surface to the streak counter automatically rather than getting
    // silently absorbed.

    // `last_successful_sync_at` is owned by the sync-success arm of the
    // actor loop (captured at sync_once-return time, not here): writing
    // it in this maintenance path would label "time of last sync" with
    // the wall clock when maintenance happened to start, off by tens of
    // seconds under load.

    // Collect the room-survey fields locally without holding any lock
    // across the SDK iteration.
    let mut joined_room_count: usize = 0;
    let mut encrypted_room_count: usize = 0;
    let mut unencrypted_room_count: usize = 0;
    let mut unsupported_room_count: usize = 0;
    let mut unsupported_rooms: Vec<String> = Vec::new();
    // Cap per-tick warn emissions for unsupported-room logging
    // symmetric with the `unsupported_rooms` JSON-list cap. A
    // federated bot in 10K encrypted rooms with `encrypted=false`
    // would otherwise emit one warn per room per maintenance tick.
    // The `unsupported_room_count` is unaffected so operators see
    // the full scale via channel status.
    const UNSUPPORTED_ROOM_WARN_CAP: usize = 10;
    let mut unsupported_room_warn_count = 0usize;
    let mut suppressed_unsupported_room_warn_count = 0usize;
    // Cap the surfaced room-id list at MATRIX_UNSUPPORTED_ROOMS_LIMIT
    // so a federated bot in 10k encrypted rooms with `encrypted=false`
    // can't inflate `metadata.extra.unsupportedRooms` to multi-MB and
    // flood every `/control/channels` consumer + WS subscriber. The
    // total count stays in `unsupported_room_count` regardless; the
    // truncation is observable via `unsupported_rooms.len()` <
    // `unsupported_room_count`.
    for room in client.joined_rooms() {
        joined_room_count += 1;
        if is_room_encrypted(&room) {
            encrypted_room_count += 1;
            if !config.encrypted() {
                unsupported_room_count += 1;
                // Sanitize before BOTH the JSON-bound `unsupported_rooms`
                // list AND the warn log. The JSON path bypasses the
                // tracing-writer-layer redactor entirely (it goes
                // through `update_channel_registry_metadata` →
                // `info.metadata.extra` → /control/channels JSON
                // response), so a homeserver-controlled room_id with
                // ANSI/bidi codepoints would land verbatim in operator
                // dashboards and CLI consumers without sanitization
                // here.
                let room_id = sanitize_homeserver_identifier(room.room_id().as_str());
                if unsupported_rooms.len() < MATRIX_UNSUPPORTED_ROOMS_LIMIT {
                    unsupported_rooms.push(room_id.clone());
                }
                if unsupported_room_warn_count < UNSUPPORTED_ROOM_WARN_CAP {
                    unsupported_room_warn_count += 1;
                    warn!(
                        room_id = %room_id,
                        "Matrix room became encrypted while matrix.encrypted=false; marking unsupported"
                    );
                } else {
                    suppressed_unsupported_room_warn_count += 1;
                }
            }
        } else {
            unencrypted_room_count += 1;
        }
    }
    if suppressed_unsupported_room_warn_count > 0 {
        warn!(
            suppressed = suppressed_unsupported_room_warn_count,
            logged = unsupported_room_warn_count,
            total_unsupported = unsupported_room_count,
            "Matrix unsupported-room warnings (suppressed remainder; full count in channel \
             status `unsupported_room_count`, first {MATRIX_UNSUPPORTED_ROOMS_LIMIT} ids in \
             `unsupported_rooms`)"
        );
    }

    // Field-level merge under a single write lock: refresh OWNS the
    // room-survey fields and updates only those. Counters mutated by
    // concurrent paths (`unsupported_inbound_count`,
    // `inbound_dispatch_failure_total`, `inbound_dlq_append_failure_total`,
    // `inbound_dlq_durability_error`) are NOT overwritten — maintenance
    // runs in a JoinSet that races with the room-message handler, and
    // a wholesale `state.write().status = status` would lose
    // increments landing between this function's read and write.
    // `pending_verification_count` is derived from `verifications.len()`
    // by `MatrixRuntimeState::status()` at read time, so it is not
    // touched here either. `last_successful_sync_at` is owned by the
    // sync-success arm of the actor loop, not this function.
    let mut guard = state.write();
    guard.status.joined_room_count = joined_room_count;
    guard.status.encrypted_room_count = encrypted_room_count;
    guard.status.unencrypted_room_count = unencrypted_room_count;
    guard.status.unsupported_room_count = unsupported_room_count;
    guard.status.unsupported_rooms = unsupported_rooms;
    Ok(())
}

async fn refresh_device_state(
    client: Arc<Client>,
    config: &MatrixConfig,
    state: &Arc<RwLock<MatrixRuntimeState>>,
) -> Result<(), MatrixError> {
    let user_id: OwnedUserId = config
        .user_id
        .parse::<OwnedUserId>()
        .map_err(|err| MatrixError::InvalidUserId(err.to_string()))?;
    let devices = client
        .encryption()
        .get_user_devices(&user_id)
        .await
        .map_err(|err| MatrixError::Verification(err.to_string()))?;
    // Two-pass build: per-device emit + collision sweep so the
    // `raw_device_id_hex` field disambiguates EVERY ambiguous
    // entry, not just the sanitization-altered one. With only the
    // altered-side populated, an operator running
    // `cara matrix verify @user <sanitized-device-id>` sees the
    // byte-exact device picked first and has no signal that a
    // second device sharing the same sanitized form exists.
    let raw_devices: Vec<(String, String, MatrixDeviceInfo)> = devices
        .devices()
        .take(MATRIX_DEVICE_LIST_MAX)
        .map(|device| {
            // Sanitize peer-controlled identifiers and display name:
            // ruma's `OwnedDeviceId` validator is a no-op so device_id
            // can carry ANSI escapes or bidi codepoints. user_id is
            // projected through the same operator-visible identifier
            // sanitizer so historical Matrix IDs with display-hostile
            // codepoints cannot reach JSON wire or CLI consumers
            // (especially the SAS-confirm prompt).
            let raw_device_id = device.device_id().as_str().to_string();
            let sanitized_device_id = sanitize_homeserver_identifier(&raw_device_id);
            // First-pass `raw_device_id_hex`: populated when
            // sanitization changed something. Collision sweep
            // below fills it on the byte-exact side too.
            let raw_device_id_hex = if sanitized_device_id == raw_device_id {
                None
            } else {
                Some(hex::encode(raw_device_id.as_bytes()))
            };
            (
                raw_device_id,
                sanitized_device_id.clone(),
                MatrixDeviceInfo {
                    user_id: sanitize_matrix_user_id_for_operator(device.user_id().as_str()),
                    device_id: OwnedDeviceId::from(sanitized_device_id),
                    display_name: device
                        .display_name()
                        .map(sanitize_matrix_display_name)
                        .filter(|s| !s.is_empty()),
                    verified: device.is_verified(),
                    raw_device_id_hex,
                },
            )
        })
        .collect();
    // Sanitization-collision sweep: any sanitized device_id that
    // appears more than once across the device list is ambiguous.
    // Populate `raw_device_id_hex` on every entry sharing that key
    // (including the byte-exact-equals-sanitized entries) so the
    // operator can pick the right one by hex when the SDK lookup
    // would otherwise refuse on collision (see resolver in
    // `start_matrix_verification`).
    let mut counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for (_, sanitized, _) in &raw_devices {
        *counts.entry(sanitized.clone()).or_insert(0) += 1;
    }
    let devices: Vec<MatrixDeviceInfo> = raw_devices
        .into_iter()
        .map(|(raw, sanitized, mut info)| {
            if counts.get(&sanitized).copied().unwrap_or(0) > 1 && info.raw_device_id_hex.is_none()
            {
                info.raw_device_id_hex = Some(hex::encode(raw.as_bytes()));
            }
            info
        })
        .collect();
    state.write().devices = devices;
    Ok(())
}

fn update_channel_registry_metadata(
    registry: &ChannelRegistry,
    state: &Arc<RwLock<MatrixRuntimeState>>,
) {
    let status = state.read().status();
    registry.update_metadata_extra(MATRIX_CHANNEL_ID, json!(status));
}

/// Stamp a typed `MatrixError` to the channel registry's
/// `last_error` AND record the typed kind in runtime state's
/// `MatrixStatusMetadata.last_error_kind`, then flush registry
/// metadata so the CLI sees both. The CLI's
/// `verify_matrix_outcome` reads `extra.lastErrorKind` to route
/// per-variant remediation hints (rekey-token / rekey-recovery /
/// fix-config / etc.) without substring-matching the redacted
/// Display string. Without this helper, the runtime-readiness path
/// strips the typed variant: `set_error` only stores the formatted
/// message, so the operator-facing rekey-token hint that
/// `whoami_with_bounded_retry`'s typed-variant preservation
/// enables would never fire.
fn stamp_matrix_runtime_error(
    registry: &ChannelRegistry,
    state: &Arc<RwLock<MatrixRuntimeState>>,
    err: &MatrixError,
) {
    state.write().status.last_error_kind = Some(err.kind().to_string());
    registry.set_error(MATRIX_CHANNEL_ID, matrix_error_for_status(err));
    update_channel_registry_metadata(registry, state);
}

/// Stamp a non-typed `String` error to the channel registry. Clears
/// `last_error_kind` so the CLI does not see a stale kind from a
/// prior typed error route to the wrong remediation hint.
fn stamp_matrix_runtime_error_message(
    registry: &ChannelRegistry,
    state: &Arc<RwLock<MatrixRuntimeState>>,
    message: impl Into<String>,
) {
    state.write().status.last_error_kind = None;
    registry.set_error(MATRIX_CHANNEL_ID, message);
    update_channel_registry_metadata(registry, state);
}

fn stamp_matrix_runtime_error_message_with_kind(
    registry: &ChannelRegistry,
    state: &Arc<RwLock<MatrixRuntimeState>>,
    message: impl Into<String>,
    error_kind: impl Into<String>,
) {
    state.write().status.last_error_kind = Some(error_kind.into());
    registry.set_error(MATRIX_CHANNEL_ID, message);
    update_channel_registry_metadata(registry, state);
}

/// Mark the Matrix channel `Connected`, clearing both the registry's
/// `last_error` (via `update_status`'s prev-Error transition logic)
/// and runtime state's `last_error_kind`. Callers are responsible
/// for ensuring a Connected transition is actually appropriate at
/// the call site — this helper just keeps the kind invariant in
/// lockstep with the status transition.
fn mark_matrix_channel_connected(
    registry: &ChannelRegistry,
    state: &Arc<RwLock<MatrixRuntimeState>>,
) {
    state.write().status.last_error_kind = None;
    registry.update_status(MATRIX_CHANNEL_ID, ChannelStatus::Connected);
    update_channel_registry_metadata(registry, state);
}

fn is_room_supported(room: &Room, encrypted_enabled: bool) -> bool {
    if encrypted_enabled {
        return true;
    }
    // matrix.encrypted=false: only rooms whose encryption state is
    // *known to be unencrypted* are supported. An `Unknown` encryption
    // state (the SDK hasn't determined yet) is treated conservatively
    // as if encrypted — refuse rather than risk sending plaintext into
    // a room that turns out to be encrypted.
    let state = room.encryption_state();
    !state.is_encrypted() && !state.is_unknown()
}

fn is_room_encrypted(room: &Room) -> bool {
    // Mirror `is_room_supported`: anything other than known-unencrypted
    // is treated as encrypted for routing decisions. Callers needing the
    // raw tri-state should consult `room.encryption_state()` directly.
    let state = room.encryption_state();
    state.is_encrypted() || state.is_unknown()
}

fn is_invite_room_definitely_encrypted(room: &Room) -> bool {
    // Invites often arrive before the SDK has enough room state to
    // determine encryption. For joined-room send/inbound paths, Unknown
    // remains fail-closed; for invite auto-join with matrix.encrypted=false,
    // the plan only refuses definitely encrypted rooms. Unknown invites
    // can be joined and will be marked unsupported later if they resolve
    // to encrypted.
    room.encryption_state().is_encrypted()
}

fn retry_after_from_kind(
    kind: &matrix_sdk::ruma::api::client::error::ErrorKind,
) -> Option<Duration> {
    use matrix_sdk::ruma::api::client::error::{ErrorKind, RetryAfter};
    match kind {
        ErrorKind::LimitExceeded {
            retry_after: Some(RetryAfter::Delay(delay)),
        } => Some(*delay),
        ErrorKind::LimitExceeded {
            retry_after: Some(RetryAfter::DateTime(when)),
        } => when.duration_since(std::time::SystemTime::now()).ok(),
        _ => None,
    }
}

fn matrix_retry_after(err: &matrix_sdk::Error) -> Option<Duration> {
    retry_after_from_kind(err.client_api_error_kind()?)
}

/// `HttpError` companion to `matrix_retry_after`. Used by the whoami
/// retry loop so a rate-limited login window is honored end-to-end:
/// without this, the 1/2/4-second local backoff burns the budget in
/// ~7s and the outer retry hammers the homeserver's rate-limit
/// window, deepening the limit.
fn matrix_retry_after_http(err: &matrix_sdk::HttpError) -> Option<Duration> {
    retry_after_from_kind(err.client_api_error_kind()?)
}

/// Pure classifier shared by `matrix_sync_terminal_error` (for
/// `matrix_sdk::Error`) and `matrix_http_terminal_error` (for
/// `matrix_sdk::HttpError`). Returning `Some` means the homeserver has
/// declared the token unusable and the runtime should exit with the
/// supplied display string as the operator-visible cause.
/// Account-state classifier for kinds that unambiguously mean
/// "this client cannot do anything" — token revoked, user
/// deactivated/locked/suspended. Routes to `AuthTokenRevoked` so
/// `cara verify --outcome matrix` can suggest re-minting the
/// token / unlocking the account. M_FORBIDDEN is NOT here because
/// it is path-context-dependent: at the sync level it means the
/// token is no longer authorized for this user's sync; at the
/// send level it means this specific room rejected the send
/// (operator banned, no power level, room policy). The two
/// per-path classifiers handle Forbidden differently.
fn classify_auth_terminal_kind(
    kind: &matrix_sdk::ruma::api::client::error::ErrorKind,
    display: impl FnOnce() -> String,
) -> Option<MatrixError> {
    use matrix_sdk::ruma::api::client::error::ErrorKind;
    match kind {
        ErrorKind::UnknownToken { .. }
        | ErrorKind::UserDeactivated
        | ErrorKind::UserLocked
        | ErrorKind::UserSuspended => Some(MatrixError::AuthTokenRevoked(display())),
        _ => None,
    }
}

fn matrix_sync_terminal_error(err: &matrix_sdk::Error) -> Option<MatrixError> {
    use matrix_sdk::ruma::api::client::error::ErrorKind;
    if let Some(kind) = err.client_api_error_kind() {
        if let Some(terminal) = classify_auth_terminal_kind(kind, || err.to_string()) {
            return Some(terminal);
        }
        // Sync-level M_FORBIDDEN means the token is no longer
        // authorized to sync — token-level concern, route to
        // AuthTokenRevoked so operator hint surfaces re-mint guidance.
        if matches!(kind, ErrorKind::Forbidden { .. }) {
            return Some(MatrixError::AuthTokenRevoked(err.to_string()));
        }
    }
    // Text-match fallback for SDK error kinds that DON'T expose
    // `client_api_error_kind` (refresh-token failures, wrapped
    // auth-state errors, non-HTTP error variants). Without this, a
    // permanently-revoked token whose SDK error happens to be wrapped
    // in such a way would slip past `client_api_error_kind() == None`,
    // be classified as transient by the sync loop, and retry forever
    // (up to the 24h give-up window). The panic-path classifier
    // `matrix_sync_join_error` already applies the same text match
    // on `JoinError::into_panic` payloads; mirroring the fallback
    // here closes the gap on the live SDK error path. The text patterns
    // are the same M_* codes as classify_auth_terminal_kind and are
    // expected to round-trip through `Error::to_string()` even when
    // the structured `client_api_error_kind` accessor is absent.
    matrix_sync_terminal_error_text(&err.to_string())
}

/// Authentication-path companion to `classify_auth_terminal_kind`:
/// peel SDK error kinds that mean "the homeserver returned a typed
/// `M_*` code but the operator's credentials are not (provably)
/// invalid — try again later." Currently the only such kind is
/// `M_LIMIT_EXCEEDED` (rate-limited login), which without this peel
/// would fall through into the terminal `MatrixError::Auth` bucket
/// and convince the dispatch pipeline that the credentials are
/// permanently dead. Routing it through `AuthProbe` keeps the
/// failure retryable and steers operator guidance toward "retry
/// after the homeserver's rate-limit window" instead of "re-mint
/// the access token."
///
/// Returning `None` means the kind belongs in the terminal bucket
/// (or in `classify_auth_terminal_kind`, which the auth pipeline
/// consults first).
fn classify_auth_transient_kind(
    kind: &matrix_sdk::ruma::api::client::error::ErrorKind,
    display: impl FnOnce() -> String,
) -> Option<MatrixError> {
    use matrix_sdk::ruma::api::client::error::ErrorKind;
    match kind {
        ErrorKind::LimitExceeded { .. } => Some(MatrixError::AuthProbe(display())),
        _ => None,
    }
}

fn matrix_auth_error_from_sdk(err: &matrix_sdk::Error) -> MatrixError {
    if let Some(typed) = matrix_sync_terminal_error(err) {
        return typed;
    }
    if let Some(kind) = err.client_api_error_kind() {
        if let Some(transient) = classify_auth_transient_kind(kind, || err.to_string()) {
            return transient;
        }
    }
    if err.client_api_error_kind().is_some() {
        MatrixError::Auth(err.to_string())
    } else {
        MatrixError::AuthProbe(err.to_string())
    }
}

fn matrix_error_terminal_runtime_cause(err: &MatrixError) -> Option<MatrixError> {
    match err {
        MatrixError::Auth(_)
        | MatrixError::AuthSessionUserMismatch { .. }
        | MatrixError::AuthSessionDeviceMismatch { .. }
        | MatrixError::AuthSessionMissingDeviceId
        | MatrixError::AuthTokenRevoked(_) => Some(err.clone()),
        _ => None,
    }
}

fn matrix_sync_terminal_error_text(message: &str) -> Option<MatrixError> {
    let upper = message.to_ascii_uppercase();
    if upper.contains("M_UNKNOWN_TOKEN")
        || upper.contains("M_USER_DEACTIVATED")
        || upper.contains("M_USER_LOCKED")
        || upper.contains("M_USER_SUSPENDED")
        || upper.contains("M_FORBIDDEN")
    {
        return Some(MatrixError::AuthTokenRevoked(message.to_string()));
    }
    None
}

fn matrix_panic_payload_message(payload: &(dyn std::any::Any + Send + 'static)) -> String {
    if let Some(message) = payload.downcast_ref::<&'static str>() {
        return (*message).to_string();
    }
    if let Some(message) = payload.downcast_ref::<String>() {
        return message.clone();
    }
    "non-string panic payload".to_string()
}

fn matrix_sync_join_error(join_err: tokio::task::JoinError) -> MatrixError {
    if join_err.is_panic() {
        return match join_err.try_into_panic() {
            Ok(payload) => {
                let message = matrix_panic_payload_message(payload.as_ref());
                matrix_sync_terminal_error_text(&message).unwrap_or_else(|| {
                    MatrixError::SyncFailed(format!("Matrix sync task panicked: {message}"))
                })
            }
            Err(err) => MatrixError::SyncFailed(format!("Matrix sync task failed: {err}")),
        };
    }
    MatrixError::SyncFailed(format!("Matrix sync task failed: {join_err}"))
}

/// Wider classifier for `room.send` errors. Includes the auth-
/// state terminal kinds plus send-specific permanent failures
/// (oversized payload, guest forbidden, malformed body) and
/// room-level M_FORBIDDEN — which at the send level indicates
/// the specific room rejected the send (not a token problem),
/// so it routes to `SendTerminal` rather than `AuthTokenRevoked`.
fn matrix_send_terminal_error(err: &matrix_sdk::Error) -> Option<MatrixError> {
    use matrix_sdk::ruma::api::client::error::ErrorKind;
    let kind = err.client_api_error_kind()?;
    if let Some(terminal) = classify_auth_terminal_kind(kind, || err.to_string()) {
        return Some(terminal);
    }
    match kind {
        // Room-level M_FORBIDDEN: per-room permission failure
        // (banned, no power level, room policy). Not a token issue.
        ErrorKind::Forbidden { .. }
        | ErrorKind::ThreepidDenied
        | ErrorKind::TooLarge
        | ErrorKind::GuestAccessForbidden
        | ErrorKind::BadJson
        | ErrorKind::Unrecognized => Some(MatrixError::SendTerminal(err.to_string())),
        _ => None,
    }
}

/// Same terminal-vs-transient classification as `matrix_sync_terminal_error`
/// but for `matrix_sdk::HttpError` directly. Used by call sites that hit
/// HTTP endpoints (e.g. `client.whoami()`) without going through
/// `client.sync_once`, which surface the narrower `HttpError` rather
/// than the wrapping `matrix_sdk::Error`. M_FORBIDDEN at this level
/// reflects token-state (the call was authenticated against the
/// homeserver and refused), so it routes to AuthTokenRevoked.
fn matrix_http_terminal_error(err: &matrix_sdk::HttpError) -> Option<MatrixError> {
    use matrix_sdk::ruma::api::client::error::ErrorKind;
    let kind = err.client_api_error_kind()?;
    if let Some(terminal) = classify_auth_terminal_kind(kind, || err.to_string()) {
        return Some(terminal);
    }
    if matches!(kind, ErrorKind::Forbidden { .. }) {
        return Some(MatrixError::AuthTokenRevoked(err.to_string()));
    }
    None
}

fn matrix_error_for_status(err: &MatrixError) -> String {
    crate::logging::redact::RedactedDisplay(err).to_string()
}

/// Heuristic classifier for `matrix-sdk-sqlite::OpenStoreError`'s
/// passphrase-mismatch shape. matrix-sdk's `OpenStoreError` does
/// not expose a typed discriminant for "wrong passphrase" —
/// callers see a generic Display chain. The dominant wrong-
/// passphrase error chains as:
///   `OpenStoreError::InitCipher(Error::Encryption(aead::Error))`
///   → "Failed to initialize the store cipher: Error encrypting
///      or decrypting a value: `aead::Error`"
/// The KdfMismatch path also shows:
///   "Failed to import a store cipher, the export used a
///    passphrase ..."
///
/// Bare `ciphertext` / `kdf` substrings would over-match
/// unrelated version-mismatch / corrupt-store errors
/// (`matrix-sdk-store-encryption` variants `Length`, `Version`).
/// `aead::error` is the canonical lower-bound: AEAD failures are
/// authentication-tag mismatches, almost always wrong key.
///
/// Wire-stable: the CLI's
/// `verify_matrix_outcome` matches `last_error_kind ==
/// "encrypted-store-passphrase-mismatch"` to route the rekey-
/// recovery hint. A matrix-sdk upgrade that rewords any of these
/// strings silently disables the routing — the unit tests below
/// pin every phrase to trip on rewording.
fn matrix_open_store_message_indicates_passphrase_mismatch(message: &str) -> bool {
    let lower = message.to_lowercase();
    lower.contains("failed to initialize the store cipher")
        || lower.contains("error encrypting or decrypting")
        || lower.contains("aead::error")
        || lower.contains("failed to import a store cipher")
        || lower.contains("incorrect passphrase")
}

#[derive(Debug)]
struct MatrixWhoamiTransientError {
    message: String,
    retry_after: Option<Duration>,
}

#[derive(Debug)]
enum MatrixWhoamiProbeError {
    Terminal(MatrixError),
    Transient(MatrixWhoamiTransientError),
}

impl MatrixWhoamiProbeError {
    fn from_http_error(err: matrix_sdk::HttpError) -> Self {
        if let Some(typed) = matrix_http_terminal_error(&err) {
            return Self::Terminal(typed);
        }
        Self::Transient(MatrixWhoamiTransientError {
            message: err.to_string(),
            retry_after: matrix_retry_after_http(&err),
        })
    }
}

#[async_trait::async_trait]
trait MatrixWhoamiProbe: Sync {
    type Response: Send;

    async fn whoami(&self) -> Result<Self::Response, MatrixWhoamiProbeError>;
}

#[async_trait::async_trait]
impl MatrixWhoamiProbe for Client {
    type Response = matrix_sdk::ruma::api::client::account::whoami::v3::Response;

    async fn whoami(&self) -> Result<Self::Response, MatrixWhoamiProbeError> {
        Client::whoami(self)
            .await
            .map_err(MatrixWhoamiProbeError::from_http_error)
    }
}

const WHOAMI_RETRY_DELAYS: [Duration; 3] = [
    Duration::from_secs(1),
    Duration::from_secs(2),
    Duration::from_secs(4),
];

fn duration_millis_for_log(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

/// Run `client.whoami()` with bounded retry across transient transport
/// failures. Returns:
/// - `Ok(response)` on success
/// - `Err(MatrixError::AuthProbe)` when the retry budget is exhausted:
///   restored-token startup must fail closed rather than begin an indefinite
///   sync backoff loop
/// - `Err(MatrixError::AuthTokenRevoked { … })` when the homeserver reports a
///   terminal token error (UnknownToken / Forbidden / UserDeactivated /
///   UserLocked / UserSuspended). Preserving the typed variant lets the CLI's
///   `verify_matrix_outcome` route it to the rekey-token hint path; collapsing
///   it to `Auth` defeats that branch and ships a generic message.
async fn whoami_with_bounded_retry(
    client: &Client,
) -> Result<matrix_sdk::ruma::api::client::account::whoami::v3::Response, MatrixError> {
    whoami_with_bounded_retry_from_probe(client, &WHOAMI_RETRY_DELAYS, tokio::time::sleep).await
}

async fn whoami_with_bounded_retry_from_probe<P, Sleep, SleepFuture>(
    probe: &P,
    retry_delays: &[Duration],
    mut sleep: Sleep,
) -> Result<P::Response, MatrixError>
where
    P: MatrixWhoamiProbe,
    Sleep: FnMut(Duration) -> SleepFuture,
    SleepFuture: std::future::Future<Output = ()>,
{
    debug_assert!(
        retry_delays.iter().all(|delay| *delay > Duration::ZERO),
        "whoami retry delays must be non-zero"
    );
    let mut attempt = 0;
    loop {
        match probe.whoami().await {
            Ok(response) => return Ok(response),
            Err(MatrixWhoamiProbeError::Terminal(typed)) => return Err(typed),
            Err(MatrixWhoamiProbeError::Transient(err)) => {
                if attempt >= retry_delays.len() {
                    return Err(MatrixError::AuthProbe(format!(
                        "restored Matrix token could not be validated after {} whoami() attempts: {}",
                        attempt + 1,
                        err.message
                    )));
                }
                // Honor a homeserver-supplied `Retry-After` (e.g.
                // `M_LIMIT_EXCEEDED`) so a rate-limited login window
                // is observed end-to-end. Take the max with the local
                // floor so a tiny hint cannot starve the retry budget,
                // and cap at MATRIX_RETRY_AFTER_MAX so a pathological
                // hint cannot wedge startup.
                let local_delay = retry_delays[attempt];
                let actual_delay = match err.retry_after {
                    Some(hint) => hint.max(local_delay).min(MATRIX_RETRY_AFTER_MAX),
                    None => local_delay,
                };
                warn!(
                    error_kind = "matrix_whoami_transient",
                    error = %crate::logging::redact::RedactedDisplay(err.message.as_str()),
                    attempt = attempt + 1,
                    homeserver_retry_after_ms = err.retry_after.map(duration_millis_for_log),
                    sleeping_ms = duration_millis_for_log(actual_delay),
                    "Matrix whoami() transient error; retrying"
                );
                sleep(actual_delay).await;
                attempt += 1;
            }
        }
    }
}

/// Drain queued commands and reply with the supplied error to each.
/// Sync because `try_recv` and `oneshot::Sender::send` are both
/// non-blocking; callers don't need `.await`.
///
/// `rx.close()` runs first so any sender holding a `tx` clone gets a
/// `Closed` error on `try_send` instead of silently queueing into a
/// soon-to-be-dropped buffer. Without this, plugins holding a
/// `MatrixChannel { tx }` clone could land commands between the
/// drain and the receiver drop, and those commands' `reply_tx`
/// would be silently dropped.
fn drain_pending_commands(rx: &mut mpsc::Receiver<MatrixCommand>, err: MatrixError) {
    rx.close();
    while let Ok(command) = rx.try_recv() {
        match command {
            MatrixCommand::SendText { reply_tx, .. } => {
                let _ = reply_tx.send(Err(err.clone()));
            }
            MatrixCommand::StartVerification { reply_tx, .. } => {
                let _ = reply_tx.send(Err(err.clone()));
            }
            MatrixCommand::VerificationAction { reply_tx, .. } => {
                let _ = reply_tx.send(Err(err.clone()));
            }
        }
    }
}

#[derive(Debug, Default)]
struct MatrixBackoff {
    index: usize,
}

impl MatrixBackoff {
    fn next_delay(&mut self, retry_after: Option<Duration>) -> Duration {
        if let Some(retry_after) = retry_after {
            return retry_after.min(MATRIX_RETRY_AFTER_MAX);
        }
        let delay = MATRIX_BACKOFF_STEPS
            .get(self.index)
            .copied()
            .unwrap_or_else(|| *MATRIX_BACKOFF_STEPS.last().expect("non-empty backoff"));
        self.index = (self.index + 1).min(MATRIX_BACKOFF_STEPS.len() - 1);
        delay
    }

    fn reset(&mut self) {
        self.index = 0;
    }
}

#[derive(Debug)]
enum MatrixSyncFailure<'a> {
    Terminal(MatrixError),
    Transient {
        stamp_error: MatrixSyncTransientStamp<'a>,
        retry_after: Option<Duration>,
    },
}

#[derive(Debug)]
enum MatrixSyncTransientStamp<'a> {
    Error(&'a MatrixError),
    SdkError(&'a matrix_sdk::Error),
}

impl MatrixSyncTransientStamp<'_> {
    fn into_matrix_error(self) -> MatrixError {
        match self {
            MatrixSyncTransientStamp::Error(err) => err.clone(),
            MatrixSyncTransientStamp::SdkError(err) => {
                MatrixError::SyncFailed(crate::logging::redact::RedactedDisplay(err).to_string())
            }
        }
    }
}

impl<'a> MatrixSyncFailure<'a> {
    fn from_sdk_error(err: &'a matrix_sdk::Error) -> Self {
        if let Some(permanent) = matrix_sync_terminal_error(err) {
            return Self::Terminal(permanent);
        }
        Self::Transient {
            stamp_error: MatrixSyncTransientStamp::SdkError(err),
            retry_after: matrix_retry_after(err),
        }
    }

    fn from_matrix_error(err: &'a MatrixError) -> Self {
        if let Some(permanent) = matrix_error_terminal_runtime_cause(err) {
            return Self::Terminal(permanent);
        }
        Self::Transient {
            stamp_error: MatrixSyncTransientStamp::Error(err),
            retry_after: None,
        }
    }
}

#[derive(Debug)]
struct MatrixTransientSyncDecision {
    delay: Duration,
    streak: u32,
    idle_ms: i64,
    gave_up: bool,
    stamp_error: Option<MatrixError>,
}

#[derive(Debug)]
enum MatrixSyncFailureDecision {
    Terminal(MatrixError),
    Transient(MatrixTransientSyncDecision),
}

/// Advance transient sync retry state for one observed failure and return
/// the runtime action. Terminal failures are classified without consuming
/// transient backoff or failure-streak state.
fn advance_and_classify_matrix_sync_failure(
    failure: MatrixSyncFailure,
    state: &Arc<RwLock<MatrixRuntimeState>>,
    actor_started_at_ms: i64,
    backoff: &mut MatrixBackoff,
    transient_sync: &mut FailureStreak,
) -> MatrixSyncFailureDecision {
    match failure {
        MatrixSyncFailure::Terminal(permanent) => MatrixSyncFailureDecision::Terminal(permanent),
        MatrixSyncFailure::Transient {
            stamp_error: transient_stamp,
            retry_after,
        } => {
            let decision =
                classify_sync_giveup(state, actor_started_at_ms, backoff.next_delay(retry_after));
            let streak = transient_sync.record_failure();
            let stamp_error = match decision {
                SyncBackoffDecision::GaveUp { idle_ms, .. } => {
                    Some(MatrixError::SyncLoopGaveUp { idle_ms })
                }
                SyncBackoffDecision::Backoff { .. } if transient_sync.is_sticky() => {
                    Some(transient_stamp.into_matrix_error())
                }
                SyncBackoffDecision::Backoff { .. } => None,
            };
            MatrixSyncFailureDecision::Transient(MatrixTransientSyncDecision {
                delay: decision.delay(),
                streak,
                idle_ms: decision.idle_ms(),
                gave_up: decision.gave_up(),
                stamp_error,
            })
        }
    }
}

/// Typed outcome of the sync-loop give-up policy. The transient-
/// sync-error and sync-task-panic arms both classify the same way:
/// idle past `MATRIX_SYNC_GIVE_UP_THRESHOLD_MS` → `GaveUp`, else
/// `Backoff`. The arm-local stamp/warn code matches on this.
#[derive(Debug)]
enum SyncBackoffDecision {
    Backoff { delay: Duration, idle_ms: i64 },
    GaveUp { delay: Duration, idle_ms: i64 },
}

impl SyncBackoffDecision {
    fn delay(&self) -> Duration {
        match self {
            Self::Backoff { delay, .. } | Self::GaveUp { delay, .. } => *delay,
        }
    }

    fn idle_ms(&self) -> i64 {
        match self {
            Self::Backoff { idle_ms, .. } | Self::GaveUp { idle_ms, .. } => *idle_ms,
        }
    }

    fn gave_up(&self) -> bool {
        matches!(self, Self::GaveUp { .. })
    }
}

/// Compare wall-clock idle since the last successful sync against
/// `MATRIX_SYNC_GIVE_UP_THRESHOLD_MS`, falling back to
/// `actor_started_at_ms` when the SDK has never produced a
/// successful sync. Returns the delay to apply, the idle duration
/// (for logs), and whether give-up fired.
///
/// Wall-clock dependency: `last_successful_sync_at` is exposed to
/// operators in millis-since-epoch, so the give-up policy uses
/// `now_millis()` (wall clock) — not `tokio::time::Instant` — for
/// consistency. NTP slew can shift `idle_ms` by seconds; a step
/// backward could defer give-up by the step size (mostly harmless),
/// a step forward could trigger give-up early (the daemon recovers
/// on the next successful sync, so the operator-visible cost is a
/// misleading idle_ms in logs and one early give-up tick).
fn classify_sync_giveup(
    state: &Arc<RwLock<MatrixRuntimeState>>,
    actor_started_at_ms: i64,
    backoff_delay: Duration,
) -> SyncBackoffDecision {
    let baseline = state
        .read()
        .status
        .last_successful_sync_at
        .filter(|value| *value >= actor_started_at_ms)
        .unwrap_or(actor_started_at_ms);
    let idle_ms = now_millis().saturating_sub(baseline);
    if idle_ms > MATRIX_SYNC_GIVE_UP_THRESHOLD_MS {
        SyncBackoffDecision::GaveUp {
            delay: MATRIX_SYNC_GIVE_UP_RETRY_INTERVAL,
            idle_ms,
        }
    } else {
        SyncBackoffDecision::Backoff {
            delay: backoff_delay,
            idle_ms,
        }
    }
}

fn matrix_server_name(user_id: &str) -> Option<&str> {
    let user_id = user_id.strip_prefix('@')?;
    let (_, server_name) = user_id.split_once(':')?;
    Some(strip_matrix_server_port(server_name))
}

fn strip_matrix_server_port(server_name: &str) -> &str {
    if let Some((host, port)) = server_name.rsplit_once(':') {
        if !host.is_empty() && port.chars().all(|ch| ch.is_ascii_digit()) {
            return host;
        }
    }
    server_name
}

fn matrix_user_ids_equal(left: &OwnedUserId, right: &str) -> bool {
    right
        .parse::<OwnedUserId>()
        .map(|right| left.as_str() == right.as_str())
        .unwrap_or(false)
}

/// Why an inbound `m.relates_to` should suppress the message from
/// becoming a NEW agent run.
///
/// - `m.replace` (edit): every edit has a fresh `event_id`, so without
///   this suppression the bot would re-respond to every typo correction
///   the user made. The body fallback is `* updated text` — semantically
///   not a new question.
/// - `m.thread` (threaded reply): proper threaded routing needs a
///   per-thread session that the runtime doesn't yet implement; the
///   conservative default is to drop these rather than dispatch them
///   into the parent thread's session.
///
/// Reply-to (`m.in_reply_to`) and other relation types fall through —
/// those are top-level messages that just reference an earlier event,
/// and should still dispatch.
fn matrix_relation_suppression_reason(
    relates_to: Option<
        &matrix_sdk::ruma::events::room::message::Relation<
            matrix_sdk::ruma::events::room::message::RoomMessageEventContentWithoutRelation,
        >,
    >,
) -> Option<&'static str> {
    use matrix_sdk::ruma::events::room::message::Relation;
    match relates_to? {
        Relation::Replacement(_) => Some("m.replace"),
        Relation::Thread(_) => Some("m.thread"),
        _ => None,
    }
}

/// Strip control characters and Unicode bidi/zero-width formatters from a
/// peer-controlled display name. Without this, a hostile Matrix device can
/// inject ANSI escapes into operator output or render as a bidi-overridden
/// look-alike of the operator's own device in the SAS-confirm prompt.
fn sanitize_matrix_display_name(input: &str) -> String {
    const DISPLAY_NAME_MAX_CHARS: usize = 256;
    input
        .chars()
        .filter(|ch| !ch.is_control() && !is_bidi_or_zero_width(*ch))
        .take(DISPLAY_NAME_MAX_CHARS)
        .collect::<String>()
        .trim()
        .to_string()
}

/// Strip Cc + Cf + line/paragraph separators from a homeserver-supplied
/// opaque identifier (event_id, device_id) and length-cap to a value
/// large enough for legitimate Matrix-spec identifiers. Used at every
/// boundary where a peer- or homeserver-controlled string is rendered
/// to an operator (CLI, JSON output, structured logs) so an adversary
/// cannot inject ANSI escapes that paint a fake SAS prompt or bidi
/// codepoints that visually rearrange forensic event IDs. Matrix v11+
/// event IDs are ≤255 bytes; ruma's `compat-arbitrary-length-ids`
/// feature otherwise allows unbounded length.
pub(crate) fn sanitize_homeserver_identifier(input: &str) -> String {
    // Byte-cap, NOT char-cap: Matrix v11+ event_ids are ≤255 BYTES
    // and ruma's `compat-arbitrary-length-ids` feature otherwise
    // accepts unbounded length. 4-byte emoji × 255 chars = 1020
    // bytes if we counted chars, blowing past every byte-bounded
    // downstream.
    const HOMESERVER_ID_MAX_BYTES: usize = 255;
    let mut out = String::with_capacity(input.len().min(HOMESERVER_ID_MAX_BYTES));
    for ch in input.chars() {
        if ch.is_control()
            || is_bidi_or_zero_width(ch)
            || is_combining_or_format_mark(ch)
            || is_tag_or_extended_format(ch)
        {
            continue;
        }
        if out.len() + ch.len_utf8() > HOMESERVER_ID_MAX_BYTES {
            break;
        }
        out.push(ch);
    }
    out
}

fn sanitize_matrix_user_id_for_operator(input: &str) -> OwnedUserId {
    let sanitized = sanitize_homeserver_identifier(input);
    sanitized.parse::<OwnedUserId>().unwrap_or_else(|_| {
        let mut hasher = Sha256::new();
        hasher.update(input.as_bytes());
        let digest = hasher.finalize();
        let fallback = format!("@invalid-{}:carapace.invalid", hex::encode(&digest[..8]));
        warn!(
            sanitized_user_id = %sanitized,
            fallback_user_id = %fallback,
            "Matrix user id sanitized to an invalid operator-visible form; substituting hash-keyed placeholder"
        );
        fallback
            .parse()
            .expect("fallback Matrix user id is valid")
    })
}

pub(crate) fn decode_raw_device_id_hex(raw_device_id_hex: &str) -> Result<String, String> {
    let hex_value = raw_device_id_hex.trim();
    if hex_value.is_empty() {
        return Err("rawDeviceIdHex cannot be empty".to_string());
    }
    if hex_value.len() > 1024 {
        return Err("rawDeviceIdHex is too long".to_string());
    }
    if !hex_value.len().is_multiple_of(2) || !hex_value.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err("rawDeviceIdHex must be even-length hexadecimal".to_string());
    }
    let bytes = hex::decode(hex_value).map_err(|err| format!("decode rawDeviceIdHex: {err}"))?;
    let device_id =
        String::from_utf8(bytes).map_err(|_| "rawDeviceIdHex must decode to UTF-8".to_string())?;
    if device_id.trim().is_empty() {
        return Err("rawDeviceIdHex decoded to an empty Matrix device ID".to_string());
    }
    Ok(device_id)
}

fn matrix_event_idempotency_key(
    raw_event_id: &str,
) -> Option<crate::channels::inbound::IdempotencyKey> {
    if raw_event_id.trim().is_empty() {
        return None;
    }
    let mut hasher = Sha256::new();
    hasher.update(raw_event_id.as_bytes());
    let hashed = format!("matrix-event-v3-sha256:{}", hex::encode(hasher.finalize()));
    crate::channels::inbound::IdempotencyKey::from_str_opt(&hashed)
}

fn is_bidi_or_zero_width(ch: char) -> bool {
    matches!(
        ch as u32,
        0x061C                   // ARABIC LETTER MARK
        | 0x200B..=0x200F        // ZWSP, ZWNJ, ZWJ, LRM, RLM
        | 0x2028..=0x2029        // LINE SEPARATOR, PARAGRAPH SEPARATOR
        | 0x202A..=0x202E        // LRE, RLE, PDF, LRO, RLO
        | 0x2066..=0x2069        // LRI, RLI, FSI, PDI
        | 0xFEFF                 // BOM / zero-width no-break space
    )
}

/// Combining marks (Mn) and enclosing marks (Me) that compose onto
/// the preceding character. A peer-crafted `D` + U+0301 renders as
/// `Ó` — visually distinct yet matchable to operator expectations of
/// `D`, defeating SAS-confirm prompt safety.
fn is_combining_or_format_mark(ch: char) -> bool {
    matches!(
        ch as u32,
        0x0300..=0x036F          // Combining Diacritical Marks
        | 0x0483..=0x0489        // Cyrillic combining marks
        | 0x0591..=0x05BD        // Hebrew points
        | 0x05BF
        | 0x05C1..=0x05C2
        | 0x05C4..=0x05C5
        | 0x05C7
        | 0x0610..=0x061A        // Arabic combining marks
        | 0x064B..=0x065F        // Arabic vowels and marks
        | 0x0670
        | 0x06D6..=0x06DC
        | 0x06DF..=0x06E4
        | 0x06E7..=0x06E8
        | 0x06EA..=0x06ED
        | 0x1AB0..=0x1AFF        // Combining Diacritical Marks Extended
        | 0x1DC0..=0x1DFF        // Combining Diacritical Marks Supplement
        | 0x20D0..=0x20FF        // Combining Diacritical Marks for Symbols
        | 0xFE00..=0xFE0F        // Variation Selectors 1-16 (invisible)
        | 0xFE20..=0xFE2F        // Combining Half Marks
        | 0xE0100..=0xE01EF      // Variation Selectors Supplement
    )
}

/// Cf-class characters beyond the bidi/ZW set — these are rendered
/// invisible (or near-invisible) in most terminals but carry hidden
/// bytes through copy-paste flows. TAG codepoints (U+E0001,
/// U+E0020-U+E007F) are the most dangerous: many terminals render
/// them as nothing at all. SOFT HYPHEN, MONGOLIAN VOWEL SEPARATOR,
/// WORD JOINER, INTERLINEAR ANNOTATION, INHIBIT/ACTIVATE SYMMETRIC
/// SWAPPING are the same class. Plus script-specific format chars
/// (Arabic, Syriac, Egyptian Hieroglyph, Kaithi, musical symbols).
fn is_tag_or_extended_format(ch: char) -> bool {
    matches!(
        ch as u32,
        0x00AD                   // SOFT HYPHEN (invisible)
        | 0x0600..=0x0605        // Arabic number signs
        | 0x06DD                 // Arabic End of Ayah
        | 0x070F                 // Syriac Abbreviation Mark
        | 0x0890..=0x0891
        | 0x08E2
        | 0x180E                 // MONGOLIAN VOWEL SEPARATOR
        | 0x2060..=0x2064        // WORD JOINER, INVISIBLE TIMES/SEPARATOR/PLUS
        | 0x206A..=0x206F        // INHIBIT/ACTIVATE SYMMETRIC SWAPPING
        | 0xFFF9..=0xFFFB        // INTERLINEAR ANNOTATION ANCHOR/SEPARATOR/TERMINATOR
        | 0x110BD | 0x110CD      // Kaithi number signs
        | 0x13430..=0x13455      // Egyptian Hieroglyph format controls
        | 0x1BCA0..=0x1BCA3      // Shorthand format controls
        | 0x1D173..=0x1D17A      // Musical symbol formatters
        | 0xE0001                // LANGUAGE TAG
        | 0xE0020..=0xE007F      // TAG codepoints (invisible in most terminals)
    )
}

/// Throttle the broken-clock warn at most once per hour per process.
/// `now_millis()` is on the per-event hot path (called from
/// `handle_room_message_event`, `append_matrix_inbound_dlq`,
/// `record_inbound_failure_with_error`, and the DLQ append-failure
/// stamps). If the system clock is invalid — possible on
/// container/VM resume, fresh-boot pre-NTP, RTC failure — every
/// inbound message would emit one warn line, defeating the
/// log-volume discipline applied elsewhere on this branch. The
/// fallback values (i64::MAX or last-valid) are themselves the
/// load-bearing correctness signal; the warn is operator-facing
/// diagnostic only.
///
/// CRITICAL: uses `Instant` (monotonic), NOT `SystemTime`. The
/// other throttle gates on this branch use `SystemTime::now()
/// .duration_since(UNIX_EPOCH)` because they fire from paths where
/// the wall clock is presumed valid. This gate is the exception:
/// it is called from the `Err(_)` branch of `try_now_millis()`,
/// which is reached precisely when `SystemTime::now()
/// .duration_since(UNIX_EPOCH)` failed. Using SystemTime here
/// would silently suppress EVERY warn in the broken-clock window
/// (the very condition the throttle exists to gate) because both
/// `last` and `now_secs` would saturate at 0. `Instant` is
/// guaranteed monotonic and unaffected by wall-clock failure.
fn now_millis_broken_clock_warn_should_fire() -> bool {
    use std::sync::atomic::AtomicU64;
    use std::sync::OnceLock;
    use std::time::Instant;

    static PROCESS_START: OnceLock<Instant> = OnceLock::new();
    static LAST_WARN_AT_ELAPSED_SECS: AtomicU64 = AtomicU64::new(u64::MAX);

    let start = *PROCESS_START.get_or_init(Instant::now);
    let elapsed_secs = start.elapsed().as_secs();
    now_millis_broken_clock_warn_should_fire_inner(elapsed_secs, &LAST_WARN_AT_ELAPSED_SECS)
}

/// Inner body of `now_millis_broken_clock_warn_should_fire`, factored
/// out so the sentinel-u64::MAX-then-throttle behavior can be unit-
/// tested against an injected `AtomicU64` (the outer fn's static
/// state is process-global and would otherwise pollute across tests
/// in the same binary). `elapsed_secs` is the monotonic process-
/// lifetime elapsed time in seconds.
fn now_millis_broken_clock_warn_should_fire_inner(
    elapsed_secs: u64,
    last_warn_at_elapsed_secs: &std::sync::atomic::AtomicU64,
) -> bool {
    use std::sync::atomic::Ordering;
    const THROTTLE_SECS: u64 = 3600;
    let last = last_warn_at_elapsed_secs.load(Ordering::Relaxed);
    // Sentinel `u64::MAX` means "never fired" — first call always
    // fires (any elapsed_secs > 0 - 1 wraps to huge gap, but using
    // an explicit sentinel keeps the meaning unambiguous).
    if last != u64::MAX && elapsed_secs.saturating_sub(last) < THROTTLE_SECS {
        return false;
    }
    last_warn_at_elapsed_secs
        .compare_exchange(last, elapsed_secs, Ordering::Relaxed, Ordering::Relaxed)
        .is_ok()
}

fn now_millis() -> i64 {
    match try_now_millis() {
        Ok(now) => now,
        Err(err) => {
            let last = LAST_VALID_WALL_CLOCK_MILLIS.load(Ordering::Relaxed);
            if last == LAST_VALID_WALL_CLOCK_SENTINEL {
                // The clock has never been valid in this process. Returning
                // `0` would let records be silently pruned by a future
                // prune call once the clock recovers; returning `i64::MAX`
                // keeps records alive until the operator restarts the
                // daemon with a fixed clock — the safer failure mode.
                if now_millis_broken_clock_warn_should_fire() {
                    warn!(
                        error = %err,
                        "system clock has never been valid in this process; \
                         using i64::MAX so verification records survive the broken-clock window"
                    );
                }
                return i64::MAX;
            }
            if now_millis_broken_clock_warn_should_fire() {
                warn!(error = %err, last_valid_millis = last, "system clock is invalid; reusing last valid Matrix timestamp");
            }
            last
        }
    }
}

fn try_now_millis() -> Result<i64, MatrixError> {
    match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(duration) => {
            let millis = i64::try_from(duration.as_millis()).map_err(|_| {
                MatrixError::Clock("system timestamp overflowed i64 millis".to_string())
            })?;
            LAST_VALID_WALL_CLOCK_MILLIS.store(millis, Ordering::Relaxed);
            Ok(millis)
        }
        Err(err) => Err(MatrixError::Clock(format!(
            "system clock is before UNIX_EPOCH: {err}"
        ))),
    }
}

#[cfg(test)]
fn matrix_rs_fn_body(fn_signature_prefix: &str) -> String {
    for (label, raw_source) in [
        (
            "matrix/verification.rs",
            include_str!("matrix/verification.rs"),
        ),
        ("matrix/recovery.rs", include_str!("matrix/recovery.rs")),
        (
            "matrix/inbound_dlq.rs",
            include_str!("matrix/inbound_dlq.rs"),
        ),
        ("matrix.rs", include_str!("matrix.rs")),
    ] {
        let source = raw_source.replace("\r\n", "\n");
        if let Some(fn_start) = source.find(fn_signature_prefix) {
            let body_offset = source[fn_start..].find("\n}\n").unwrap_or_else(|| {
                panic!("{fn_signature_prefix} in {label} must have a `\\n}}\\n` closing brace")
            });
            return source[fn_start..fn_start + body_offset].to_string();
        }
    }
    panic!("{fn_signature_prefix} must exist in Matrix module sources");
}

#[cfg(test)]
fn matrix_test_config(encrypted: bool) -> MatrixConfig {
    let passphrase = crate::crypto::generate_hex_secret(32).expect("getrandom passphrase");
    let mut auto_join = MatrixAutoJoinConfig::default();
    auto_join
        .allow_users
        .insert("@alice:example.com".to_string());
    MatrixConfig {
        homeserver_url: "https://matrix.example.com".to_string(),
        user_id: "@cara:example.com".to_string(),
        access_token: Some(zeroize::Zeroizing::new("token".to_string())),
        password: None,
        device_id: Some("DEVICE".to_string()),
        security: if encrypted {
            MatrixSecurity::Encrypted {
                passphrase_source: PassphraseSource::Explicit(
                    NonEmptyPassphrase::new(&passphrase).expect("passphrase"),
                ),
            }
        } else {
            MatrixSecurity::Unencrypted
        },
        auto_join,
        legacy_dlq_envelope_policy: MatrixLegacyDlqEnvelopePolicy::Accept,
    }
}

#[cfg(test)]
fn matrix_test_config_with_passphrase(passphrase: &str) -> MatrixConfig {
    let mut auto_join = MatrixAutoJoinConfig::default();
    auto_join
        .allow_users
        .insert("@alice:example.com".to_string());
    MatrixConfig {
        homeserver_url: "https://matrix.example.com".to_string(),
        user_id: "@cara:example.com".to_string(),
        access_token: Some(zeroize::Zeroizing::new("token".to_string())),
        password: None,
        device_id: Some("DEVICE".to_string()),
        security: MatrixSecurity::Encrypted {
            passphrase_source: PassphraseSource::Explicit(
                NonEmptyPassphrase::new(passphrase).expect("passphrase"),
            ),
        },
        auto_join,
        legacy_dlq_envelope_policy: MatrixLegacyDlqEnvelopePolicy::Accept,
    }
}

#[cfg(test)]
mod tests {
    use super::inbound_dlq::*;
    use super::recovery::*;
    use super::verification::*;
    use super::*;
    use crate::test_support::env::ScopedEnv;
    use serde_json::json;
    use std::path::Path;

    #[test]
    fn test_auto_join_empty_rejects_all() {
        let policy = MatrixAutoJoinConfig::default();
        assert!(policy.is_empty());
        assert!(!policy.allows_user("@alice:example.com"));
    }

    /// Pins the sentinel-then-suppress contract of the
    /// broken-clock warn gate at the `_inner` level: first call (with
    /// the `u64::MAX` sentinel state) always fires; the second call
    /// at any elapsed_secs within the 3600s window is suppressed;
    /// elapsed_secs > 3600s after the recorded last fire re-fires.
    ///
    /// Tests against an injected `AtomicU64` so the outer fn's static
    /// state is untouched across the test binary.
    #[test]
    fn test_now_millis_broken_clock_warn_first_call_fires_then_suppresses() {
        let state = std::sync::atomic::AtomicU64::new(u64::MAX);
        // First call: sentinel state, elapsed=0 → fires
        assert!(now_millis_broken_clock_warn_should_fire_inner(0, &state));
        // Second call within the throttle window: suppressed
        assert!(!now_millis_broken_clock_warn_should_fire_inner(10, &state));
        assert!(!now_millis_broken_clock_warn_should_fire_inner(
            1000, &state
        ));
        assert!(!now_millis_broken_clock_warn_should_fire_inner(
            3599, &state
        ));
        // 3600s after the recorded fire: re-fires
        assert!(now_millis_broken_clock_warn_should_fire_inner(3600, &state));
        // Suppressed again until 7200s
        assert!(!now_millis_broken_clock_warn_should_fire_inner(
            3601, &state
        ));
        assert!(now_millis_broken_clock_warn_should_fire_inner(7200, &state));
    }

    /// Pin the bug Batch 8 fixed: the original implementation used
    /// `0` as the "never fired" sentinel, which inverted to
    /// "always-fire-twice on first invocation" because
    /// `elapsed_secs.saturating_sub(0) < THROTTLE_SECS` is true for
    /// any elapsed under 3600. The current sentinel `u64::MAX` makes
    /// the first call unambiguously the fire-once path.
    #[test]
    fn test_now_millis_broken_clock_warn_sentinel_distinguishes_never_fired_from_fired_at_zero() {
        // A "never fired" state (sentinel u64::MAX) fires on first call:
        let never_fired = std::sync::atomic::AtomicU64::new(u64::MAX);
        assert!(now_millis_broken_clock_warn_should_fire_inner(
            0,
            &never_fired
        ));

        // A "fired at elapsed=0" state (the bug Batch 8 fixed) must
        // suppress the second call, not re-fire:
        let fired_at_zero = std::sync::atomic::AtomicU64::new(0);
        assert!(!now_millis_broken_clock_warn_should_fire_inner(
            10,
            &fired_at_zero
        ));
    }

    /// The inbound-body empty-skip predicate must consider bodies
    /// composed entirely of bidi / zero-width / control / whitespace
    /// chars as "empty for dispatch purposes". `'\u{202E}'.is_whitespace()`
    /// is false, so a body of exactly "\u{202E}" used to dispatch as
    /// a 1-char prompt to the LLM. Test the predicate the inbound
    /// handler now uses, with whitespace + bidi + control mixtures
    /// and a legitimate non-empty body.
    #[test]
    fn test_inbound_body_skip_predicate_catches_bidi_and_control_only_bodies() {
        let is_empty = |body: &str| -> bool {
            body.chars()
                .all(|c| c.is_whitespace() || c.is_control() || is_bidi_or_zero_width(c))
        };

        // Pure whitespace and pure bidi/zero-width must skip.
        assert!(is_empty(""));
        assert!(is_empty("   "));
        assert!(is_empty("\u{202E}"));
        assert!(is_empty("\u{200B}"));
        assert!(is_empty("\u{FEFF}"));
        assert!(is_empty("  \u{202E}  "));
        assert!(is_empty("\t\n\r\u{200B}"));

        // Non-empty bodies must dispatch.
        assert!(!is_empty("ok"));
        assert!(!is_empty("  ok  "));
        // Arabic alphabetic chars are not whitespace/control/bidi.
        assert!(!is_empty(
            "\u{0627}\u{0644}\u{0633}\u{0644}\u{0627}\u{0645}"
        ));
        // RTL mark followed by real letters still has letters.
        assert!(!is_empty("\u{202B}hello"));
    }

    #[test]
    fn test_relation_suppression_reason() {
        use matrix_sdk::ruma::events::room::message::RoomMessageEventContent;

        // No relation: not suppressed.
        assert_eq!(matrix_relation_suppression_reason(None), None);

        // The Thread/InReplyTo inner structs are not publicly
        // constructible, so build relations via JSON deserialization
        // through `RoomMessageEventContent`. The helper itself only
        // needs to discriminate the outer Relation variant, so the
        // exact inner-field shape doesn't matter beyond what serde
        // needs.
        let edit: RoomMessageEventContent = serde_json::from_value(serde_json::json!({
            "msgtype": "m.text",
            "body": "* edited",
            "m.new_content": { "msgtype": "m.text", "body": "edited" },
            "m.relates_to": {
                "rel_type": "m.replace",
                "event_id": "$orig:example.com"
            },
        }))
        .unwrap();
        assert_eq!(
            matrix_relation_suppression_reason(edit.relates_to.as_ref()),
            Some("m.replace")
        );

        let thread: RoomMessageEventContent = serde_json::from_value(serde_json::json!({
            "msgtype": "m.text",
            "body": "threaded",
            "m.relates_to": {
                "rel_type": "m.thread",
                "event_id": "$orig:example.com"
            },
        }))
        .unwrap();
        assert_eq!(
            matrix_relation_suppression_reason(thread.relates_to.as_ref()),
            Some("m.thread")
        );

        // m.in_reply_to falls through — top-level message that just
        // references an earlier event.
        let reply: RoomMessageEventContent = serde_json::from_value(serde_json::json!({
            "msgtype": "m.text",
            "body": "reply",
            "m.relates_to": {
                "m.in_reply_to": { "event_id": "$orig:example.com" }
            },
        }))
        .unwrap();
        assert_eq!(
            matrix_relation_suppression_reason(reply.relates_to.as_ref()),
            None
        );

        // No relation field at all — also falls through.
        let plain: RoomMessageEventContent = serde_json::from_value(serde_json::json!({
            "msgtype": "m.text",
            "body": "plain",
        }))
        .unwrap();
        assert!(plain.relates_to.is_none());
    }

    #[test]
    fn test_sanitize_display_name_strips_ansi_escape_and_bidi() {
        // The ESC byte is stripped (terminal won't interpret it as a CSI),
        // and the bidi-override codepoint is stripped. The literal `[31m`
        // parameters remain as plain text — that's the point: rendered
        // literally, they cannot do anything.
        let input = "Alice\x1b[31m\u{202E}EVIL";
        assert_eq!(sanitize_matrix_display_name(input), "Alice[31mEVIL");
    }

    #[test]
    fn test_sanitize_display_name_strips_null_and_newline() {
        let input = "Alice\0Bob\nCarol";
        assert_eq!(sanitize_matrix_display_name(input), "AliceBobCarol");
    }

    #[test]
    fn test_sanitize_display_name_strips_zero_width_and_bom() {
        let input = "A\u{200B}l\u{200D}i\u{FEFF}ce";
        assert_eq!(sanitize_matrix_display_name(input), "Alice");
    }

    #[test]
    fn test_sanitize_display_name_strips_line_paragraph_separators() {
        // U+2028 (LINE SEPARATOR) and U+2029 (PARAGRAPH SEPARATOR) are
        // NOT caught by char::is_control() — they're in Unicode
        // categories Zl/Zp, not Cc. They split terminal output and
        // break JSON parsers when embedded in script-tag contexts.
        // The sanitizer now strips both.
        let input = "Alice\u{2028}Eve\u{2029}Bob";
        assert_eq!(sanitize_matrix_display_name(input), "AliceEveBob");
    }

    #[test]
    fn test_sanitize_display_name_strips_lrm_rlm_alm() {
        // U+200E (LRM) and U+200F (RLM) are the most common bidi marks
        // used in real attacks (Trojan-Source highlighted U+200F as a
        // common smuggling character). U+061C (ALM) is used in
        // Arabic-script bidi-override attacks. None of these are caught
        // by char::is_control() — they're separate codepoint ranges.
        let input = "\u{200E}A\u{200F}l\u{061C}ice";
        assert_eq!(sanitize_matrix_display_name(input), "Alice");
    }

    #[test]
    fn test_sanitize_display_name_caps_length() {
        let input = "x".repeat(500);
        assert_eq!(sanitize_matrix_display_name(&input).chars().count(), 256);
    }

    #[test]
    fn test_sanitize_display_name_preserves_unicode_letters() {
        let input = "  Алиса 日本 🌸  ";
        assert_eq!(sanitize_matrix_display_name(input), "Алиса 日本 🌸");
    }

    #[test]
    fn test_auto_join_matches_full_mxid() {
        let policy = MatrixAutoJoinConfig {
            allow_users: BTreeSet::from(["@alice:example.com".to_string()]),
            allow_server_names: BTreeSet::new(),
        };
        assert!(policy.allows_user("@alice:example.com"));
        assert!(!policy.allows_user("@alice:evil.example.com"));
    }

    #[test]
    fn test_auto_join_matches_server_suffix() {
        let policy = MatrixAutoJoinConfig {
            allow_users: BTreeSet::new(),
            allow_server_names: BTreeSet::from(["example.com".to_string()]),
        };
        assert!(policy.allows_user("@alice:example.com"));
        assert!(policy.allows_user("@alice:example.com:8448"));
        assert!(policy.allows_user("@alice:corp.example.com"));
        assert!(policy.allows_user("@alice:corp.example.com:8448"));
        assert!(!policy.allows_user("@alice:badexample.com"));
        // Rejection of a similarly-named server with a port — exercises
        // the strip_matrix_server_port + dot-boundary check together.
        // Without the explicit `.{suffix}` boundary in the suffix
        // match, "badexample.com:8448" would strip to "badexample.com"
        // and confusingly slip past a naive ends_with("example.com").
        assert!(!policy.allows_user("@alice:badexample.com:8448"));
    }

    #[test]
    fn test_resolve_matrix_config_from_config_and_env() {
        let _env_state_guard = crate::config::ScopedEnvStateForTest::new();
        let mut env = ScopedEnv::new();
        env.set("MATRIX_ACCESS_TOKEN", "env-token")
            .set("MATRIX_DEVICE_ID", "DEVICE");
        let cfg = json!({
            "matrix": {
                "homeserverUrl": "https://matrix.example.com",
                "userId": "@cara:example.com",
                "encrypted": false,
                "autoJoin": {
                    "allowUsers": ["@alice:example.com"],
                    "allowServerNames": ["example.org"]
                }
            }
        });
        let MatrixConfigResolve::Configured(resolved) = resolve_matrix_config(&cfg).unwrap() else {
            panic!("matrix config should resolve");
        };
        assert_eq!(
            resolved.access_token.as_deref().map(|s| s.as_str()),
            Some("env-token")
        );
        assert_eq!(resolved.device_id.as_deref(), Some("DEVICE"));
        assert!(!resolved.encrypted());
        assert!(resolved.auto_join.allows_user("@alice:example.com"));
        assert!(resolved.auto_join.allows_user("@bob:chat.example.org"));
    }

    #[test]
    fn test_resolve_matrix_config_defaults_legacy_dlq_policy_accept() {
        let _env_state_guard = crate::config::ScopedEnvStateForTest::new();
        let mut env = ScopedEnv::new();
        env.unset("MATRIX_HOMESERVER_URL");
        env.unset("MATRIX_USER_ID");
        env.unset("MATRIX_PASSWORD");
        env.unset("MATRIX_ACCESS_TOKEN");
        env.unset("MATRIX_DEVICE_ID");
        let cfg = json!({
            "matrix": {
                "homeserverUrl": "https://matrix.example.com",
                "userId": "@cara:example.com",
                "password": "secret",
                "encrypted": false
            }
        });

        let MatrixConfigResolve::Configured(resolved) = resolve_matrix_config(&cfg).unwrap() else {
            panic!("matrix config should resolve");
        };

        assert_eq!(
            resolved.legacy_dlq_envelope_policy,
            MatrixLegacyDlqEnvelopePolicy::Accept
        );
    }

    #[test]
    fn test_resolve_matrix_config_parses_legacy_dlq_refuse_policy() {
        let _env_state_guard = crate::config::ScopedEnvStateForTest::new();
        let mut env = ScopedEnv::new();
        env.unset("MATRIX_HOMESERVER_URL");
        env.unset("MATRIX_USER_ID");
        env.unset("MATRIX_PASSWORD");
        env.unset("MATRIX_ACCESS_TOKEN");
        env.unset("MATRIX_DEVICE_ID");
        let cfg = json!({
            "matrix": {
                "homeserverUrl": "https://matrix.example.com",
                "userId": "@cara:example.com",
                "password": "secret",
                "encrypted": false,
                "inboundDlq": {
                    "legacyEnvelopePolicy": "refuse"
                }
            }
        });

        let MatrixConfigResolve::Configured(resolved) = resolve_matrix_config(&cfg).unwrap() else {
            panic!("matrix config should resolve");
        };

        assert_eq!(
            resolved.legacy_dlq_envelope_policy,
            MatrixLegacyDlqEnvelopePolicy::Refuse
        );
    }

    /// Forward-compat: unknown keys under `matrix.inboundDlq` MUST
    /// NOT cause startup to fail. Carapace is a released product;
    /// downgrade scenarios (operator runs newer daemon, adds future
    /// option, downgrades binary) would otherwise refuse to start
    /// with no migration path. Unknown keys are logged at warn and
    /// the known key is honored. Mirrors the convention of the rest
    /// of `parse_matrix_config` which ignores unknown top-level keys.
    #[test]
    fn test_resolve_matrix_config_tolerates_unknown_inbound_dlq_keys() {
        let _env_state_guard = crate::config::ScopedEnvStateForTest::new();
        let mut env = ScopedEnv::new();
        env.unset("MATRIX_HOMESERVER_URL");
        env.unset("MATRIX_USER_ID");
        env.unset("MATRIX_PASSWORD");
        env.unset("MATRIX_ACCESS_TOKEN");
        env.unset("MATRIX_DEVICE_ID");
        let cfg = json!({
            "matrix": {
                "homeserverUrl": "https://matrix.example.com",
                "userId": "@cara:example.com",
                "password": "secret",
                "encrypted": false,
                "inboundDlq": {
                    "legacyEnvelopePolicy": "refuse",
                    "argon2idMemoryKib": 65536,
                    "futureOption": "value"
                }
            }
        });

        let MatrixConfigResolve::Configured(resolved) = resolve_matrix_config(&cfg).unwrap() else {
            panic!("matrix config with unknown inboundDlq keys should resolve");
        };

        // Known key still honored.
        assert_eq!(
            resolved.legacy_dlq_envelope_policy,
            MatrixLegacyDlqEnvelopePolicy::Refuse
        );
    }

    #[test]
    fn test_explicit_matrix_store_passphrase_is_used_directly() {
        let config = MatrixConfig {
            homeserver_url: "https://matrix.example.com".to_string(),
            user_id: "@cara:example.com".to_string(),
            access_token: Some(zeroize::Zeroizing::new("token".to_string())),
            password: None,
            device_id: Some("DEVICE".to_string()),
            security: MatrixSecurity::Encrypted {
                passphrase_source: PassphraseSource::Explicit(
                    NonEmptyPassphrase::new("operator supplied passphrase").expect("non-empty"),
                ),
            },
            auto_join: MatrixAutoJoinConfig::default(),
            legacy_dlq_envelope_policy: MatrixLegacyDlqEnvelopePolicy::Accept,
        };
        let passphrase =
            resolve_matrix_store_passphrase(Path::new("/unused"), &config).expect("passphrase");
        assert_eq!(
            passphrase.as_deref().map(|p| p.as_str()),
            Some("operator supplied passphrase")
        );
    }

    #[test]
    fn test_resolve_matrix_store_passphrase_fails_closed_without_secrets() {
        let _env_state_guard = crate::config::ScopedEnvStateForTest::new();
        let mut env = ScopedEnv::new();
        env.unset("CARAPACE_CONFIG_PASSWORD");
        env.unset("MATRIX_STORE_PASSPHRASE");
        let temp = tempfile::tempdir().expect("tempdir");
        let config = MatrixConfig {
            homeserver_url: "https://matrix.example.com".to_string(),
            user_id: "@cara:example.com".to_string(),
            access_token: Some(zeroize::Zeroizing::new("token".to_string())),
            password: None,
            device_id: Some("DEVICE".to_string()),
            security: MatrixSecurity::Encrypted {
                passphrase_source: PassphraseSource::DeriveFromConfigPassword,
            },
            auto_join: MatrixAutoJoinConfig::default(),
            legacy_dlq_envelope_policy: MatrixLegacyDlqEnvelopePolicy::Accept,
        };

        let err = resolve_matrix_store_passphrase(temp.path(), &config).expect_err("fail closed");
        assert!(matches!(err, MatrixError::MissingStoreSecret));
    }

    /// B132 regression: `validate_homeserver_url` rejects non-ASCII
    /// hostnames to defend against IDN homograph attacks. A
    /// homograph like `матrix.org` would otherwise be silently
    /// Punycode-encoded by `url::Url::parse` (IDNA) and the daemon
    /// would restore a session to the attacker-controlled host.
    /// Operators must Punycode-encode explicitly (`xn--xrx-2lcd.org`)
    /// so the choice is visible at config-edit time.
    #[test]
    fn test_validate_homeserver_url_rejects_idn_homograph() {
        let err = validate_homeserver_url("https://матrix.org")
            .expect_err("non-ASCII hostname must be rejected");
        assert!(matches!(err, MatrixError::InvalidUrl { field, reason }
            if field == "homeserverUrl" && reason.contains("Punycode")));
    }

    /// Punycode-encoded equivalent must be accepted (operator
    /// explicitly chose this host).
    #[test]
    fn test_validate_homeserver_url_accepts_punycode_equivalent() {
        validate_homeserver_url("https://xn--xrx-2lcd.org")
            .expect("explicit Punycode encoding must pass validation");
    }

    /// Plain ASCII hostnames still pass.
    #[test]
    fn test_validate_homeserver_url_accepts_ascii() {
        validate_homeserver_url("https://matrix.example.com").expect("ASCII URL must pass");
        validate_homeserver_url("https://matrix.example.com/").expect("trailing slash must pass");
    }

    #[test]
    fn test_resolve_matrix_config_rejects_token_without_device_id() {
        let _env_state_guard = crate::config::ScopedEnvStateForTest::new();
        let mut env = ScopedEnv::new();
        env.unset("MATRIX_DEVICE_ID");
        env.unset("MATRIX_PASSWORD");
        let cfg = json!({
            "matrix": {
                "homeserverUrl": "https://matrix.example.com",
                "userId": "@cara:example.com",
                "accessToken": "token",
                "encrypted": false
            }
        });

        let err = resolve_matrix_config(&cfg).expect_err("token restore requires device id");
        assert!(matches!(err, MatrixError::MissingDeviceIdForTokenRestore));
    }

    /// `homeserverUrl` over the byte cap must reject at parse time.
    /// Operator config is mostly trusted, but per the typed-boundary
    /// rule, fields crossing into security-relevant code (allocator
    /// pressure on every error string carrying the URL, allowlist
    /// matching, store-key derivation) validate at the boundary.
    #[test]
    fn test_resolve_matrix_config_rejects_oversized_homeserver_url() {
        let _env_state_guard = crate::config::ScopedEnvStateForTest::new();
        let mut env = ScopedEnv::new();
        env.unset("MATRIX_HOMESERVER_URL");
        env.unset("MATRIX_USER_ID");
        env.unset("MATRIX_PASSWORD");
        env.unset("MATRIX_ACCESS_TOKEN");
        env.unset("MATRIX_DEVICE_ID");
        let huge_url = format!("https://matrix.example.com/{}", "a".repeat(3000));
        let cfg = json!({
            "matrix": {
                "homeserverUrl": huge_url,
                "userId": "@cara:example.com",
                "password": "p",
                "encrypted": false
            }
        });
        let err = resolve_matrix_config(&cfg).expect_err("oversized homeserverUrl must reject");
        assert!(matches!(err, MatrixError::InvalidLength { .. }));
    }

    #[test]
    fn test_resolve_matrix_config_rejects_non_https_homeserver_scheme() {
        let _env_state_guard = crate::config::ScopedEnvStateForTest::new();
        let mut env = ScopedEnv::new();
        env.unset("MATRIX_HOMESERVER_URL");
        env.unset("MATRIX_USER_ID");
        env.unset("MATRIX_PASSWORD");
        env.unset("MATRIX_ACCESS_TOKEN");
        env.unset("MATRIX_DEVICE_ID");
        let cfg = json!({
            "matrix": {
                "homeserverUrl": "file:///etc/passwd",
                "userId": "@cara:example.com",
                "password": "p",
                "encrypted": false
            }
        });
        let err = resolve_matrix_config(&cfg).expect_err("non-https scheme must reject");
        assert!(matches!(err, MatrixError::InvalidUrl { .. }));
    }

    #[test]
    fn test_resolve_matrix_config_rejects_homeserver_url_with_credentials() {
        let _env_state_guard = crate::config::ScopedEnvStateForTest::new();
        let mut env = ScopedEnv::new();
        env.unset("MATRIX_HOMESERVER_URL");
        env.unset("MATRIX_USER_ID");
        env.unset("MATRIX_PASSWORD");
        env.unset("MATRIX_ACCESS_TOKEN");
        env.unset("MATRIX_DEVICE_ID");
        let cfg = json!({
            "matrix": {
                "homeserverUrl": "https://user:pass@matrix.example.com",
                "userId": "@cara:example.com",
                "password": "p",
                "encrypted": false
            }
        });
        let err =
            resolve_matrix_config(&cfg).expect_err("URL with embedded credentials must reject");
        assert!(matches!(err, MatrixError::InvalidUrl { .. }));
    }

    #[test]
    fn test_resolve_matrix_config_rejects_empty_homeserver_host() {
        let _env_state_guard = crate::config::ScopedEnvStateForTest::new();
        let mut env = ScopedEnv::new();
        env.unset("MATRIX_HOMESERVER_URL");
        env.unset("MATRIX_USER_ID");
        env.unset("MATRIX_PASSWORD");
        env.unset("MATRIX_ACCESS_TOKEN");
        env.unset("MATRIX_DEVICE_ID");
        let cfg = json!({
            "matrix": {
                "homeserverUrl": "https://",
                "userId": "@cara:example.com",
                "password": "p",
                "encrypted": false
            }
        });
        let err = resolve_matrix_config(&cfg).expect_err("empty host must reject");
        assert!(matches!(err, MatrixError::InvalidUrl { .. }));
    }

    #[test]
    fn test_resolve_matrix_config_rejects_oversized_user_id() {
        let _env_state_guard = crate::config::ScopedEnvStateForTest::new();
        let mut env = ScopedEnv::new();
        env.unset("MATRIX_HOMESERVER_URL");
        env.unset("MATRIX_USER_ID");
        env.unset("MATRIX_PASSWORD");
        env.unset("MATRIX_ACCESS_TOKEN");
        env.unset("MATRIX_DEVICE_ID");
        let huge_user_id = format!("@{}:example.com", "x".repeat(300));
        let cfg = json!({
            "matrix": {
                "homeserverUrl": "https://matrix.example.com",
                "userId": huge_user_id,
                "password": "p",
                "encrypted": false
            }
        });
        let err = resolve_matrix_config(&cfg).expect_err("oversized userId must reject");
        assert!(matches!(err, MatrixError::InvalidLength { .. }));
    }

    #[test]
    fn test_resolve_matrix_config_rejects_oversized_allowlist() {
        let _env_state_guard = crate::config::ScopedEnvStateForTest::new();
        let mut env = ScopedEnv::new();
        env.unset("MATRIX_HOMESERVER_URL");
        env.unset("MATRIX_USER_ID");
        env.unset("MATRIX_PASSWORD");
        env.unset("MATRIX_ACCESS_TOKEN");
        env.unset("MATRIX_DEVICE_ID");
        let entries: Vec<String> = (0..(MATRIX_ALLOWLIST_MAX_ENTRIES + 1))
            .map(|i| format!("@user{i}:example.com"))
            .collect();
        let cfg = json!({
            "matrix": {
                "homeserverUrl": "https://matrix.example.com",
                "userId": "@cara:example.com",
                "password": "p",
                "encrypted": false,
                "autoJoin": { "allowUsers": entries }
            }
        });
        let err = resolve_matrix_config(&cfg).expect_err("oversized allowlist must reject");
        assert!(matches!(err, MatrixError::AllowlistTooLarge { .. }));
    }

    #[test]
    fn test_resolve_matrix_config_rejects_oversized_allowlist_entry() {
        let _env_state_guard = crate::config::ScopedEnvStateForTest::new();
        let mut env = ScopedEnv::new();
        env.unset("MATRIX_HOMESERVER_URL");
        env.unset("MATRIX_USER_ID");
        env.unset("MATRIX_PASSWORD");
        env.unset("MATRIX_ACCESS_TOKEN");
        env.unset("MATRIX_DEVICE_ID");
        let huge_entry = format!("@{}:example.com", "x".repeat(300));
        let cfg = json!({
            "matrix": {
                "homeserverUrl": "https://matrix.example.com",
                "userId": "@cara:example.com",
                "password": "p",
                "encrypted": false,
                "autoJoin": { "allowUsers": [huge_entry] }
            }
        });
        let err = resolve_matrix_config(&cfg).expect_err("oversized allowlist entry must reject");
        assert!(matches!(err, MatrixError::InvalidLength { .. }));
    }

    /// `MatrixSecurity::Encrypted{Explicit}` is produced when the
    /// operator supplies a non-empty `matrix.storePassphrase` with
    /// `encrypted=true`. Explicit takes precedence over the
    /// HKDF-from-config-password fallback.
    #[test]
    fn test_resolve_matrix_config_explicit_passphrase_produces_explicit_variant() {
        let _env_state_guard = crate::config::ScopedEnvStateForTest::new();
        let mut env = ScopedEnv::new();
        env.unset("MATRIX_STORE_PASSPHRASE");
        let cfg = json!({
            "matrix": {
                "homeserverUrl": "https://matrix.example.com",
                "userId": "@cara:example.com",
                "password": "operator-password",
                "storePassphrase": "operator-store-passphrase",
                "encrypted": true,
            }
        });
        let resolve = resolve_matrix_config(&cfg).expect("config resolves");
        let MatrixConfigResolve::Configured(resolved) = resolve else {
            panic!("expected Configured");
        };
        match resolved.security {
            MatrixSecurity::Encrypted {
                passphrase_source: PassphraseSource::Explicit(passphrase),
            } => {
                assert_eq!(passphrase.as_str(), "operator-store-passphrase");
            }
            other => panic!("expected Explicit variant, got {other:?}"),
        }
    }

    /// `MatrixSecurity::Encrypted{DeriveFromConfigPassword}` is the
    /// default when `encrypted=true` but no explicit storePassphrase is
    /// supplied — runtime then derives via HKDF over
    /// `CARAPACE_CONFIG_PASSWORD`.
    #[test]
    fn test_resolve_matrix_config_no_passphrase_produces_derive_variant() {
        let _env_state_guard = crate::config::ScopedEnvStateForTest::new();
        let mut env = ScopedEnv::new();
        env.unset("MATRIX_STORE_PASSPHRASE");
        let cfg = json!({
            "matrix": {
                "homeserverUrl": "https://matrix.example.com",
                "userId": "@cara:example.com",
                "password": "operator-password",
                "encrypted": true,
            }
        });
        let resolve = resolve_matrix_config(&cfg).expect("config resolves");
        let MatrixConfigResolve::Configured(resolved) = resolve else {
            panic!("expected Configured");
        };
        assert!(matches!(
            resolved.security,
            MatrixSecurity::Encrypted {
                passphrase_source: PassphraseSource::DeriveFromConfigPassword
            }
        ));
    }

    /// `encrypted=false` produces `MatrixSecurity::Unencrypted`
    /// regardless of whether `storePassphrase` is set (the explicit
    /// passphrase is ignored, and the schema validator + a startup
    /// `warn!` surface this so operators notice).
    #[test]
    fn test_resolve_matrix_config_encrypted_false_produces_unencrypted_variant() {
        let _env_state_guard = crate::config::ScopedEnvStateForTest::new();
        let mut env = ScopedEnv::new();
        env.unset("MATRIX_STORE_PASSPHRASE");
        let cfg = json!({
            "matrix": {
                "homeserverUrl": "https://matrix.example.com",
                "userId": "@cara:example.com",
                "password": "operator-password",
                "encrypted": false,
                "storePassphrase": "ignored",
            }
        });
        let resolve = resolve_matrix_config(&cfg).expect("config resolves");
        let MatrixConfigResolve::Configured(resolved) = resolve else {
            panic!("expected Configured");
        };
        assert!(matches!(resolved.security, MatrixSecurity::Unencrypted));
        assert!(!resolved.encrypted());
    }

    /// `NonEmptyPassphrase::new("")` and whitespace-only inputs are
    /// rejected so `PassphraseSource::Explicit("")` is unrepresentable.
    #[test]
    fn test_non_empty_passphrase_rejects_empty_or_whitespace() {
        assert!(matches!(
            NonEmptyPassphrase::new(""),
            Err(MatrixError::InvalidString { .. })
        ));
        assert!(matches!(
            NonEmptyPassphrase::new("   "),
            Err(MatrixError::InvalidString { .. })
        ));
        let ok = NonEmptyPassphrase::new("hunter2").expect("non-empty");
        assert_eq!(ok.as_str(), "hunter2");
    }

    /// Even when password is also configured, accessToken without
    /// deviceId must be rejected — silently falling through to
    /// password login would churn the bot's device identity on every
    /// restart.
    #[test]
    fn test_resolve_matrix_config_rejects_token_plus_password_without_device_id() {
        let _env_state_guard = crate::config::ScopedEnvStateForTest::new();
        let mut env = ScopedEnv::new();
        env.unset("MATRIX_DEVICE_ID");
        let cfg = json!({
            "matrix": {
                "homeserverUrl": "https://matrix.example.com",
                "userId": "@cara:example.com",
                "accessToken": "token",
                "password": "shouldnt-rescue",
                "encrypted": false
            }
        });

        let err = resolve_matrix_config(&cfg).expect_err(
            "accessToken without deviceId must be rejected even when password is also set",
        );
        assert!(matches!(err, MatrixError::MissingDeviceIdForTokenRestore));
    }

    /// Read the source body of a function in the Matrix module for static-
    /// analysis pin tests. Normalizes CRLF → LF so the body-end
    /// search works on Windows checkouts (`core.autocrlf`). The
    /// search is fragile (depends on `\n}\n` not appearing inside
    /// the function body) but adequate for the existing static-
    /// analysis pins, none of which contain that sequence in
    /// string literals or nested closures.
    fn matrix_rs_fn_body(fn_signature_prefix: &str) -> String {
        // The `OnceLock` cache pattern would dedupe the
        // `replace` cost across all test calls, but the fixture
        // is per-test and the saving is microseconds — keep
        // the implementation simple.
        for (label, raw_source) in [
            (
                "matrix/verification.rs",
                include_str!("matrix/verification.rs"),
            ),
            ("matrix/recovery.rs", include_str!("matrix/recovery.rs")),
            (
                "matrix/inbound_dlq.rs",
                include_str!("matrix/inbound_dlq.rs"),
            ),
            ("matrix.rs", include_str!("matrix.rs")),
        ] {
            let source = raw_source.replace("\r\n", "\n");
            if let Some(fn_start) = source.find(fn_signature_prefix) {
                let body_offset = source[fn_start..].find("\n}\n").unwrap_or_else(|| {
                    panic!("{fn_signature_prefix} in {label} must have a `\\n}}\\n` closing brace")
                });
                return source[fn_start..fn_start + body_offset].to_string();
            }
        }
        panic!("{fn_signature_prefix} must exist in Matrix module sources");
    }

    fn matrix_test_config(encrypted: bool) -> MatrixConfig {
        // Random hex passphrase (not a literal prefix) avoids CodeQL's
        // `rust/hard-coded-cryptographic-value` rule, which flags
        // any constant flowing into Argon2id derivation. See
        // `crate::server::ws::handlers::config` tests for the same
        // pattern and rationale.
        let passphrase = crate::crypto::generate_hex_secret(32).expect("getrandom passphrase");
        // Pre-allow the standard test sender so DLQ replay tests can
        // synthesize records (which bypass the live-receive allowlist
        // gate at `handle_room_message_event`) and still pass the
        // replay-time allowlist re-check at `dispatch_matrix_dlq_record`.
        let mut auto_join = MatrixAutoJoinConfig::default();
        auto_join
            .allow_users
            .insert("@alice:example.com".to_string());
        MatrixConfig {
            homeserver_url: "https://matrix.example.com".to_string(),
            user_id: "@cara:example.com".to_string(),
            access_token: Some(zeroize::Zeroizing::new("token".to_string())),
            password: None,
            device_id: Some("DEVICE".to_string()),
            security: if encrypted {
                MatrixSecurity::Encrypted {
                    passphrase_source: PassphraseSource::Explicit(
                        NonEmptyPassphrase::new(&passphrase).expect("passphrase"),
                    ),
                }
            } else {
                MatrixSecurity::Unencrypted
            },
            auto_join,
            legacy_dlq_envelope_policy: MatrixLegacyDlqEnvelopePolicy::Accept,
        }
    }

    #[derive(Clone)]
    struct FakeInviteSource {
        rooms: Vec<FakeInviteRoom>,
    }

    impl MatrixInviteSource for FakeInviteSource {
        type Room = FakeInviteRoom;

        fn invited_rooms(&self) -> Vec<Self::Room> {
            self.rooms.clone()
        }
    }

    #[derive(Clone)]
    struct FakeInviteRoom {
        room_id: String,
        inviter: Result<Option<String>, String>,
        definitely_encrypted: bool,
        leave_error: Option<String>,
        join_error: Option<String>,
        leave_count: Arc<std::sync::atomic::AtomicUsize>,
        join_count: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl FakeInviteRoom {
        fn new(room_id: &str, inviter: Option<&str>, definitely_encrypted: bool) -> Self {
            Self {
                room_id: room_id.to_string(),
                inviter: Ok(inviter.map(str::to_string)),
                definitely_encrypted,
                leave_error: None,
                join_error: None,
                leave_count: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
                join_count: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            }
        }

        fn inspect_error(room_id: &str, message: &str) -> Self {
            Self {
                room_id: room_id.to_string(),
                inviter: Err(message.to_string()),
                definitely_encrypted: false,
                leave_error: None,
                join_error: None,
                leave_count: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
                join_count: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            }
        }

        fn with_leave_error(mut self, message: &str) -> Self {
            self.leave_error = Some(message.to_string());
            self
        }

        fn with_join_error(mut self, message: &str) -> Self {
            self.join_error = Some(message.to_string());
            self
        }

        fn leave_count(&self) -> usize {
            self.leave_count.load(std::sync::atomic::Ordering::SeqCst)
        }

        fn join_count(&self) -> usize {
            self.join_count.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    #[async_trait::async_trait]
    impl MatrixInviteRoom for FakeInviteRoom {
        fn room_id_for_log(&self) -> Cow<'_, str> {
            Cow::Borrowed(self.room_id.as_str())
        }

        async fn invite_inviter(&self) -> Result<Option<String>, MatrixInviteFailure> {
            self.inviter
                .clone()
                .map_err(MatrixInviteFailure::from_message)
        }

        fn definitely_encrypted(&self) -> bool {
            self.definitely_encrypted
        }

        async fn leave_invite(&self) -> Result<(), MatrixInviteFailure> {
            self.leave_count
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.leave_error
                .clone()
                .map(MatrixInviteFailure::from_message)
                .map_or(Ok(()), Err)
        }

        async fn join_invite(&self) -> Result<(), MatrixInviteFailure> {
            self.join_count
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.join_error
                .clone()
                .map(MatrixInviteFailure::from_message)
                .map_or(Ok(()), Err)
        }
    }

    #[test]
    fn test_encrypted_matrix_state_platform_support_matches_windows_acl_stance() {
        let config = matrix_test_config(true);
        let result = ensure_encrypted_matrix_state_supported(&config);

        #[cfg(windows)]
        {
            let err = result.expect_err("Windows must fail closed without owner-only ACL support");
            assert!(
                matches!(err, MatrixError::StartupFailed(_)),
                "Windows encrypted-state capability guard must surface startup-failed, got {err:?}"
            );
            let message = err.to_string();
            assert!(message.contains("unsupported on Windows"), "{message}");
            assert!(message.contains("owner-only ACLs"), "{message}");
            assert!(message.contains("matrix.encrypted=false"), "{message}");
        }

        #[cfg(not(windows))]
        {
            result.expect("non-Windows platforms retain encrypted Matrix state support");
        }
    }

    #[test]
    fn test_unencrypted_matrix_state_platform_support_is_allowed() {
        let config = matrix_test_config(false);
        ensure_encrypted_matrix_state_supported(&config)
            .expect("unencrypted Matrix state must not be blocked by the Windows ACL stance");
    }

    /// Test fixture: build a `ChannelRegistry` with the Matrix channel
    /// pre-registered so `apply_post_sync_maintenance` calls
    /// `update_status` / `set_error` against a real entry.
    fn matrix_test_registry() -> ChannelRegistry {
        let registry = ChannelRegistry::new();
        registry.register(
            crate::channels::ChannelInfo::new(MATRIX_CHANNEL_ID, "Matrix")
                .with_status(ChannelStatus::Connecting),
        );
        registry
    }

    fn ok_outcomes() -> PostSyncMaintenanceOutcomes {
        PostSyncMaintenanceOutcomes {
            invite: Ok(()),
            verification: Ok(()),
            device: Ok(()),
            dlq_replay: Ok(()),
            runtime_status: Ok(()),
        }
    }

    /// Pin the all-success path — `apply_post_sync_maintenance`
    /// resets every streak via `record_success`, increments the
    /// inbound-decay scalar, and restores the channel to `Connected`.
    #[test]
    fn test_apply_post_sync_maintenance_all_ok_restores_connected() {
        let mut streaks = MatrixMaintenanceStreaks::default();
        let state = Arc::new(RwLock::new(MatrixRuntimeState::default()));
        let registry = matrix_test_registry();

        // Drive the channel to Error first so the test verifies the
        // restoration, not just the absence of a transition.
        registry.set_error(MATRIX_CHANNEL_ID, "seeded error");

        apply_post_sync_maintenance(ok_outcomes(), &mut streaks, &state, &registry);

        assert_eq!(
            registry.get_status(MATRIX_CHANNEL_ID),
            Some(ChannelStatus::Connected),
            "all-Ok outcomes must restore Connected"
        );
        assert_eq!(streaks.consecutive_clean_syncs, 1);
        assert!(!streaks.invite.is_sticky());
        assert!(!streaks.verification_refresh.is_sticky());
        assert!(!streaks.device_refresh.is_sticky());
        assert!(!streaks.dlq_replay.is_sticky());
        assert!(!streaks.runtime_status.is_sticky());
    }

    /// Regression for R58 H-AC3: a maintenance task that completes
    /// between `stamp_matrix_runtime_error` and the JoinSet cancel
    /// must NOT wipe the forensic durability error.
    /// `clear_inbound_dlq_durability_error` no-ops once the
    /// terminal-runtime flag is set, so a late-arriving DLQ-replay
    /// success cannot overwrite the operator-visible cause.
    #[test]
    fn test_clear_inbound_dlq_durability_error_no_ops_after_terminal_stamp() {
        // Pre-terminal: clear() actually wipes the forensic info.
        let mut pre_terminal = MatrixRuntimeState::default();
        pre_terminal.status.inbound_dlq_durability_error = Some("disk full".to_string());
        pre_terminal.status.inbound_dlq_durability_error_at = Some(now_millis());
        pre_terminal.clear_inbound_dlq_durability_error();
        assert!(
            pre_terminal.status.inbound_dlq_durability_error.is_none(),
            "pre-terminal clear must wipe the durability error so the runtime can recover"
        );

        // Once terminal is stamped, a late-arriving maintenance
        // success must not wipe the durability error — the operator
        // needs that forensic trail to diagnose the terminal cause.
        let mut post_terminal = MatrixRuntimeState::default();
        post_terminal.status.inbound_dlq_durability_error = Some("disk full".to_string());
        post_terminal.status.inbound_dlq_durability_error_at = Some(now_millis());
        post_terminal.mark_terminal_runtime_stamped();
        assert!(post_terminal.terminal_runtime_stamped());
        post_terminal.clear_inbound_dlq_durability_error();
        assert_eq!(
            post_terminal.status.inbound_dlq_durability_error.as_deref(),
            Some("disk full"),
            "post-terminal clear must no-op so forensic durability evidence survives"
        );
        assert!(post_terminal
            .status
            .inbound_dlq_durability_error_at
            .is_some());
    }

    /// Sibling pin of `test_clear_inbound_dlq_durability_error_no_ops_after_terminal_stamp`:
    /// the lost-event-IDs list forms a single coherent forensic
    /// surface with the durability error (they are stamped together
    /// by `log_lost_remaining` and `record_inbound_dlq_lost_event_ids`)
    /// and must be preserved across a late-arriving maintenance task
    /// after the terminal stamp lands.
    #[test]
    fn test_clear_inbound_dlq_lost_event_ids_no_ops_after_terminal_stamp() {
        let mut pre_terminal = MatrixRuntimeState::default();
        pre_terminal
            .status
            .inbound_dlq_lost_event_ids
            .push("$evt-1".to_string());
        pre_terminal.status.inbound_dlq_lost_event_ids_at = Some(now_millis());
        pre_terminal.clear_inbound_dlq_lost_event_ids();
        assert!(
            pre_terminal.status.inbound_dlq_lost_event_ids.is_empty(),
            "pre-terminal clear must wipe the lost IDs so a recovered runtime starts clean"
        );

        let mut post_terminal = MatrixRuntimeState::default();
        post_terminal
            .status
            .inbound_dlq_lost_event_ids
            .push("$evt-1".to_string());
        post_terminal.status.inbound_dlq_lost_event_ids_at = Some(now_millis());
        post_terminal.mark_terminal_runtime_stamped();
        post_terminal.clear_inbound_dlq_lost_event_ids();
        assert_eq!(
            post_terminal.status.inbound_dlq_lost_event_ids.len(),
            1,
            "post-terminal clear must no-op so the operator-visible lost IDs survive"
        );
        assert!(post_terminal.status.inbound_dlq_lost_event_ids_at.is_some());
    }

    #[test]
    fn test_terminal_maintenance_drain_preserves_terminal_forensic_state() {
        let mut streaks = MatrixMaintenanceStreaks::default();
        let state = Arc::new(RwLock::new(MatrixRuntimeState::default()));
        let registry = matrix_test_registry();
        {
            let mut guard = state.write();
            for _ in 0..MATRIX_REFRESH_FAILURE_ERROR_THRESHOLD {
                guard.record_inbound_failure_with_error(
                    "session history corrupt".to_string(),
                    MatrixError::SessionHistoryCorrupt("history corrupt".to_string()).kind(),
                );
            }
            guard.status.last_successful_sync_at = Some(111);
        }
        let terminal = MatrixError::AuthTokenRevoked("M_UNKNOWN_TOKEN".to_string());
        stamp_matrix_runtime_error(&registry, &state, &terminal);
        let before_info = registry
            .get(MATRIX_CHANNEL_ID)
            .expect("matrix registry entry");
        let before_extra = before_info.metadata.extra.clone();
        let before_inbound_generation = state.read().inbound_failure_generation;
        let before_pending_error = state.read().pending_inbound_error().map(str::to_string);
        let before_pending_kind = state
            .read()
            .pending_inbound_error_kind()
            .map(str::to_string);
        streaks.consecutive_clean_syncs = MATRIX_INBOUND_DECAY_SYNC_COUNT.saturating_sub(1);
        state.write().status.last_successful_sync_at = Some(222);

        apply_post_sync_maintenance_with_mode(
            ok_outcomes(),
            &mut streaks,
            &state,
            &registry,
            MaintenanceApplyMode::TerminalDrain,
        );

        let after_info = registry
            .get(MATRIX_CHANNEL_ID)
            .expect("matrix registry entry");
        assert_eq!(
            registry.get_status(MATRIX_CHANNEL_ID),
            Some(ChannelStatus::Error),
            "terminal drain must not publish Connected after permanent sync failure"
        );
        assert_eq!(
            state.read().status.last_error_kind.as_deref(),
            Some("auth-token-revoked"),
            "terminal drain must not clear the typed terminal cause"
        );
        assert_eq!(
            state.read().pending_inbound_error().map(str::to_string),
            before_pending_error,
            "terminal drain must not clear pending inbound forensic error"
        );
        assert_eq!(
            state
                .read()
                .pending_inbound_error_kind()
                .map(str::to_string),
            before_pending_kind,
            "terminal drain must not clear pending inbound forensic kind"
        );
        assert_eq!(
            state.read().inbound_failure_generation,
            before_inbound_generation,
            "terminal drain must not advance inbound failure generation"
        );
        assert_eq!(
            streaks.consecutive_clean_syncs,
            MATRIX_INBOUND_DECAY_SYNC_COUNT.saturating_sub(1),
            "terminal drain must not bump the clean-sync recovery counter"
        );
        assert_eq!(
            after_info.metadata.extra, before_extra,
            "terminal drain must not flush fresher runtime success metadata over the terminal stamp"
        );
    }

    /// A single failure below threshold records the
    /// streak but does NOT pin the channel in Error — the streak is
    /// not yet sticky.
    #[test]
    fn test_apply_post_sync_maintenance_single_failure_below_threshold() {
        let mut streaks = MatrixMaintenanceStreaks::default();
        let state = Arc::new(RwLock::new(MatrixRuntimeState::default()));
        let registry = matrix_test_registry();
        registry.update_status(MATRIX_CHANNEL_ID, ChannelStatus::Connected);

        let outcomes = PostSyncMaintenanceOutcomes {
            invite: Err(MatrixError::SyncFailed("transient".to_string())),
            verification: Ok(()),
            device: Ok(()),
            dlq_replay: Ok(()),
            runtime_status: Ok(()),
        };
        apply_post_sync_maintenance(outcomes, &mut streaks, &state, &registry);
        // Below threshold so not sticky; non-sticky streaks don't gate
        // the Connected restore.
        assert!(!streaks.invite.is_sticky());
        assert_eq!(
            registry.get_status(MATRIX_CHANNEL_ID),
            Some(ChannelStatus::Connected),
            "below-threshold failure must not block Connected restoration"
        );
    }

    /// Failures crossing the streak threshold must pin
    /// the channel in Error AND populate `last_error` with the
    /// phase-tagged message.
    #[test]
    fn test_apply_post_sync_maintenance_sticky_invite_pins_error() {
        let mut streaks = MatrixMaintenanceStreaks::default();
        let state = Arc::new(RwLock::new(MatrixRuntimeState::default()));
        let registry = matrix_test_registry();

        for _ in 0..MATRIX_REFRESH_FAILURE_ERROR_THRESHOLD {
            let outcomes = PostSyncMaintenanceOutcomes {
                invite: Err(MatrixError::SyncFailed("invite oops".to_string())),
                verification: Ok(()),
                device: Ok(()),
                dlq_replay: Ok(()),
                runtime_status: Ok(()),
            };
            apply_post_sync_maintenance(outcomes, &mut streaks, &state, &registry);
        }

        assert!(streaks.invite.is_sticky());
        assert_eq!(
            registry.get_status(MATRIX_CHANNEL_ID),
            Some(ChannelStatus::Error),
            "sticky invite streak must pin channel in Error"
        );
        assert_eq!(streaks.consecutive_clean_syncs, 0);
    }

    /// Invite-systemic + sub-threshold integration. The systemic
    /// marker (set by `handle_invites` when ≥3 invites fail in a
    /// single tick) bypasses the streak's hysteresis and pins
    /// Error. A subsequent sub-threshold tick (invite Err but
    /// without re-stamping the marker) must NOT clear the marker
    /// — only a successful invite tick (Ok) clears it via the
    /// `clear_invite_systemic_failure` call on the Ok arm.
    #[test]
    fn test_apply_post_sync_maintenance_invite_systemic_persists_through_sub_threshold_tick() {
        let mut streaks = MatrixMaintenanceStreaks::default();
        let state = Arc::new(RwLock::new(MatrixRuntimeState::default()));
        let registry = matrix_test_registry();
        registry.update_status(MATRIX_CHANNEL_ID, ChannelStatus::Connected);

        // Tick N: simulate handle_invites's many-failures path —
        // it stamps the systemic marker AND returns Err. The
        // maintenance reducer reads the marker via the per-phase
        // Err arm, fires `stamp_matrix_runtime_error`, and the
        // channel transitions to Error.
        state.write().record_invite_systemic_failure(
            "all 5 invites failed: homeserver returned 502".to_string(),
        );
        let outcomes = PostSyncMaintenanceOutcomes {
            invite: Err(MatrixError::SyncFailed(
                "all 5 invites failed: homeserver returned 502".to_string(),
            )),
            verification: Ok(()),
            device: Ok(()),
            dlq_replay: Ok(()),
            runtime_status: Ok(()),
        };
        apply_post_sync_maintenance(outcomes, &mut streaks, &state, &registry);
        assert_eq!(
            registry.get_status(MATRIX_CHANNEL_ID),
            Some(ChannelStatus::Error),
            "invite-systemic marker + Err invite outcome must transition \
             Connected → Error in tick N"
        );

        // Tick N+1: sub-threshold (1 invite failure, no re-stamp
        // of the systemic marker). The Err arm runs again, which
        // does NOT call `clear_invite_systemic_failure`. Only the
        // Ok arm clears. So the marker persists; the channel
        // stays in Error.
        let outcomes = PostSyncMaintenanceOutcomes {
            invite: Err(MatrixError::SyncFailed(
                "one transient invite failure".to_string(),
            )),
            verification: Ok(()),
            device: Ok(()),
            dlq_replay: Ok(()),
            runtime_status: Ok(()),
        };
        apply_post_sync_maintenance(outcomes, &mut streaks, &state, &registry);
        assert_eq!(
            registry.get_status(MATRIX_CHANNEL_ID),
            Some(ChannelStatus::Error),
            "channel must STAY in Error through a sub-threshold tick — the \
             systemic marker is what handle_invites clears via the Ok arm, \
             NOT the maintenance reducer's Err arm"
        );
        // The marker must still be set after the sub-threshold tick.
        assert!(
            state.read().invite_systemic_error().is_some(),
            "invite_systemic marker must persist through Err arm"
        );
    }

    /// An inbound durability error pins the channel in
    /// Error even when every other phase succeeded — that's the whole
    /// point of `inbound_durability_error_is_sticky`.
    #[test]
    fn test_apply_post_sync_maintenance_inbound_durability_blocks_connected() {
        let mut streaks = MatrixMaintenanceStreaks::default();
        let state = Arc::new(RwLock::new(MatrixRuntimeState::default()));
        let registry = matrix_test_registry();
        // Start from Connected so the test observes the
        // off-phase durability stamp's transition TO Error,
        // distinguishing pre-fix `Connecting → still-Connecting`
        // (which was assertion-equivalent to `Error`) from the
        // post-fix `Connected → Error` transition.
        registry.update_status(MATRIX_CHANNEL_ID, ChannelStatus::Connected);

        state
            .write()
            .record_inbound_dlq_append_failure("EIO".to_string());

        apply_post_sync_maintenance(ok_outcomes(), &mut streaks, &state, &registry);

        assert!(state.read().inbound_durability_error_is_sticky());
        assert_eq!(streaks.consecutive_clean_syncs, 0);
        // Strengthened assertion: the off-phase durability stamp
        // must transition the registry FROM Connected TO Error in
        // a single tick, not silently leave it at the prior
        // status. Pre-fix this assertion would have failed because
        // the transition only triggered on a per-phase Err arm.
        assert_eq!(
            registry.get_status(MATRIX_CHANNEL_ID),
            Some(ChannelStatus::Error),
            "off-phase durability stamp must transition Connected → Error in one tick"
        );
        // last_error must surface the durability message so
        // operators reading `cara status` / `/control/channels`
        // see the cause without grepping logs.
        let info = registry
            .get(MATRIX_CHANNEL_ID)
            .expect("matrix channel registered");
        assert!(
            info.metadata
                .last_error
                .as_deref()
                .is_some_and(|s| s.starts_with("Matrix inbound DLQ durability:")),
            "last_error must carry the operator-greppable durability prefix; got: {:?}",
            info.metadata.last_error
        );
    }

    #[test]
    fn test_apply_post_sync_maintenance_inbound_decay_clears_same_tick() {
        let mut streaks = MatrixMaintenanceStreaks {
            consecutive_clean_syncs: MATRIX_INBOUND_DECAY_SYNC_COUNT - 1,
            ..Default::default()
        };
        let state = Arc::new(RwLock::new(MatrixRuntimeState::default()));
        let registry = matrix_test_registry();
        registry.set_error(MATRIX_CHANNEL_ID, "sticky inbound");

        {
            let mut guard = state.write();
            for _ in 0..MATRIX_REFRESH_FAILURE_ERROR_THRESHOLD {
                guard.record_inbound_failure_with_error(
                    "inbound EIO".to_string(),
                    "session-history-corrupt",
                );
            }
        }

        apply_post_sync_maintenance(ok_outcomes(), &mut streaks, &state, &registry);

        assert_eq!(
            registry.get_status(MATRIX_CHANNEL_ID),
            Some(ChannelStatus::Connected),
            "the clean-sync tick that clears inbound state must not restamp the stale snapshot"
        );
        let status = &state.read().status;
        assert!(
            status.last_error_kind.is_none(),
            "cleared inbound state must clear typed last_error_kind in the same maintenance tick"
        );
    }

    /// A sticky `runtime_status` streak escalates to the channel
    /// registry. Without the fifth streak, a permanently-failing
    /// status refresh would emit warn every cycle with no
    /// operator-visible escalation.
    #[test]
    fn test_apply_post_sync_maintenance_runtime_status_sticky_escalates() {
        let mut streaks = MatrixMaintenanceStreaks::default();
        let state = Arc::new(RwLock::new(MatrixRuntimeState::default()));
        let registry = matrix_test_registry();

        for _ in 0..MATRIX_REFRESH_FAILURE_ERROR_THRESHOLD {
            let outcomes = PostSyncMaintenanceOutcomes {
                invite: Ok(()),
                verification: Ok(()),
                device: Ok(()),
                dlq_replay: Ok(()),
                runtime_status: Err(MatrixError::SyncFailed("status oops".to_string())),
            };
            apply_post_sync_maintenance(outcomes, &mut streaks, &state, &registry);
        }
        assert!(streaks.runtime_status.is_sticky());
        assert_eq!(
            registry.get_status(MATRIX_CHANNEL_ID),
            Some(ChannelStatus::Error),
            "sticky runtime_status streak must escalate to Error"
        );
    }

    /// `verification-refresh` phase escalation. Pre-/simplify each
    /// phase had its own match arm; post-/simplify they all flow
    /// through `handle_phase_outcome`. The 4 phases (verification,
    /// device, dlq-replay, runtime-status) collapse cleanly; pin
    /// the three previously untested phases so a refactor that
    /// drops a phase from the closure invocation doesn't ship.
    #[test]
    fn test_apply_post_sync_maintenance_verification_sticky_escalates() {
        let mut streaks = MatrixMaintenanceStreaks::default();
        let state = Arc::new(RwLock::new(MatrixRuntimeState::default()));
        let registry = matrix_test_registry();
        for _ in 0..MATRIX_REFRESH_FAILURE_ERROR_THRESHOLD {
            let outcomes = PostSyncMaintenanceOutcomes {
                invite: Ok(()),
                verification: Err(MatrixError::SyncFailed("verification oops".to_string())),
                device: Ok(()),
                dlq_replay: Ok(()),
                runtime_status: Ok(()),
            };
            apply_post_sync_maintenance(outcomes, &mut streaks, &state, &registry);
        }
        assert!(streaks.verification_refresh.is_sticky());
        assert_eq!(
            registry.get_status(MATRIX_CHANNEL_ID),
            Some(ChannelStatus::Error),
            "sticky verification-refresh streak must escalate to Error"
        );
        let info = registry.get(MATRIX_CHANNEL_ID).expect("matrix channel");
        assert!(
            info.metadata
                .last_error
                .as_deref()
                .is_some_and(|s| s.starts_with("Matrix verification refresh failing:")),
            "last_error must carry the verification-refresh prefix"
        );
    }

    #[test]
    fn test_apply_post_sync_maintenance_device_sticky_escalates() {
        let mut streaks = MatrixMaintenanceStreaks::default();
        let state = Arc::new(RwLock::new(MatrixRuntimeState::default()));
        let registry = matrix_test_registry();
        for _ in 0..MATRIX_REFRESH_FAILURE_ERROR_THRESHOLD {
            let outcomes = PostSyncMaintenanceOutcomes {
                invite: Ok(()),
                verification: Ok(()),
                device: Err(MatrixError::SyncFailed("device oops".to_string())),
                dlq_replay: Ok(()),
                runtime_status: Ok(()),
            };
            apply_post_sync_maintenance(outcomes, &mut streaks, &state, &registry);
        }
        assert!(streaks.device_refresh.is_sticky());
        assert_eq!(
            registry.get_status(MATRIX_CHANNEL_ID),
            Some(ChannelStatus::Error),
            "sticky device-refresh streak must escalate to Error"
        );
        let info = registry.get(MATRIX_CHANNEL_ID).expect("matrix channel");
        assert!(
            info.metadata
                .last_error
                .as_deref()
                .is_some_and(|s| s.starts_with("Matrix device refresh failing:")),
            "last_error must carry the device-refresh prefix"
        );
    }

    #[test]
    fn test_apply_post_sync_maintenance_dlq_replay_sticky_escalates() {
        let mut streaks = MatrixMaintenanceStreaks::default();
        let state = Arc::new(RwLock::new(MatrixRuntimeState::default()));
        let registry = matrix_test_registry();
        for _ in 0..MATRIX_REFRESH_FAILURE_ERROR_THRESHOLD {
            let outcomes = PostSyncMaintenanceOutcomes {
                invite: Ok(()),
                verification: Ok(()),
                device: Ok(()),
                dlq_replay: Err(MatrixError::SyncFailed("dlq oops".to_string())),
                runtime_status: Ok(()),
            };
            apply_post_sync_maintenance(outcomes, &mut streaks, &state, &registry);
        }
        assert!(streaks.dlq_replay.is_sticky());
        assert_eq!(
            registry.get_status(MATRIX_CHANNEL_ID),
            Some(ChannelStatus::Error),
            "sticky dlq-replay streak must escalate to Error"
        );
        let info = registry.get(MATRIX_CHANNEL_ID).expect("matrix channel");
        assert!(
            info.metadata
                .last_error
                .as_deref()
                .is_some_and(|s| s.starts_with("Matrix inbound DLQ replay failing:")),
            "last_error must carry the dlq-replay prefix"
        );
    }

    #[test]
    fn test_failure_streak_record_failure_returns_count() {
        let mut streak = FailureStreak::new(3);
        assert_eq!(streak.record_failure(), 1);
        assert_eq!(streak.record_failure(), 2);
        assert_eq!(streak.record_failure(), 3);
        assert_eq!(streak.record_failure(), 4);
    }

    #[test]
    fn test_failure_streak_record_success_resets() {
        let mut streak = FailureStreak::new(3);
        streak.record_failure();
        streak.record_failure();
        streak.record_success();
        // Counter back to zero — next failure starts the streak fresh.
        assert_eq!(streak.record_failure(), 1);
        assert!(!streak.is_sticky());
    }

    #[test]
    fn test_failure_streak_is_sticky_at_threshold() {
        let mut streak = FailureStreak::new(3);
        assert!(!streak.is_sticky(), "fresh streak not sticky");
        streak.record_failure();
        streak.record_failure();
        assert!(!streak.is_sticky(), "below threshold not sticky");
        streak.record_failure();
        assert!(streak.is_sticky(), "at threshold sticky");
        streak.record_failure();
        assert!(streak.is_sticky(), "past threshold still sticky");
        streak.record_success();
        assert!(!streak.is_sticky(), "success resets sticky");
    }

    /// `pending_verification_count` is computed by `status()` from
    /// `verifications.len()` at read time — there is no separate
    /// stored field to maintain. This pins the contract against any
    /// future "optimization" that re-introduces a stored value.
    #[test]
    fn test_pending_verification_count_derives_from_verifications_len() {
        let state = Arc::new(RwLock::new(MatrixRuntimeState::default()));
        assert_eq!(state.read().status().pending_verification_count, 0);
        upsert_verification_record(
            &state,
            "flow1".to_string(),
            "@alice:example.com".parse().expect("user id"),
            Some("D1".to_string()),
            MatrixVerificationState::Requested,
        )
        .unwrap_applied();
        upsert_verification_record(
            &state,
            "flow2".to_string(),
            "@bob:example.com".parse().expect("user id"),
            Some("D2".to_string()),
            MatrixVerificationState::Requested,
        )
        .unwrap_applied();
        assert_eq!(state.read().status().pending_verification_count, 2);
        // Direct mutation also reflects via the derived reader.
        state.write().verifications.clear();
        assert_eq!(state.read().status().pending_verification_count, 0);
    }

    /// Inbound failure threshold contract: counter increments per
    /// failure, resets on success, and `inbound_streak_is_sticky()`
    /// only returns true at `MATRIX_REFRESH_FAILURE_ERROR_THRESHOLD`
    /// consecutive failures. The sticky semantics prevent transient
    /// session-store hiccups from flapping channel status.
    #[test]
    fn test_inbound_failure_threshold_only_trips_at_threshold() {
        let mut state = MatrixRuntimeState::default();
        assert!(!state.inbound_streak_is_sticky(), "fresh state not sticky");
        assert_eq!(state.record_inbound_failure(), 1);
        assert_eq!(state.record_inbound_failure(), 2);
        assert!(
            !state.inbound_streak_is_sticky(),
            "below threshold not sticky"
        );
        assert_eq!(state.record_inbound_failure(), 3);
        assert!(
            state.inbound_streak_is_sticky(),
            "at threshold tripped sticky"
        );
        state.reset_inbound_failures();
        assert!(!state.inbound_streak_is_sticky(), "reset clears sticky");
    }

    /// `matrix_http_terminal_error` classifies the three terminal Matrix
    /// errors that should exit the runtime: UnknownToken, Forbidden,
    /// UserDeactivated. A network/transport error returns None so the
    /// caller can defer to retry logic.
    #[test]
    fn test_matrix_http_terminal_error_classifies_terminal_kinds() {
        use matrix_sdk::ruma::api::client::error::ErrorKind;

        // Account-state classifier handles only unambiguous kinds.
        // Forbidden is path-context-dependent: HTTP-layer (whoami,
        // token validation) treats it as token revocation; send-
        // path treats it as room-level rejection.
        for kind in [
            ErrorKind::UnknownToken { soft_logout: false },
            ErrorKind::UserDeactivated,
            ErrorKind::UserLocked,
            ErrorKind::UserSuspended,
        ] {
            let err = classify_auth_terminal_kind(&kind, || "terminal".to_string())
                .expect("account-state terminal kind must classify");
            assert!(matches!(err, MatrixError::AuthTokenRevoked(message) if message == "terminal"));
        }

        // Forbidden is NOT in the account-state classifier; per-path
        // wrappers handle it.
        assert!(
            classify_auth_terminal_kind(&ErrorKind::forbidden(), || "f".to_string()).is_none(),
            "Forbidden is path-context-dependent, not in account-state classifier"
        );
        assert!(
            classify_auth_terminal_kind(&ErrorKind::LimitExceeded { retry_after: None }, || {
                "transient".to_string()
            })
            .is_none(),
            "rate-limit errors remain transient"
        );
    }

    /// Regression for R58 H-ER2: the shared `retry_after_from_kind`
    /// helper must extract a `Delay`-style Retry-After from
    /// `LimitExceeded`, and the whoami retry path (which consults
    /// `matrix_retry_after_http`) honors the homeserver-supplied
    /// backoff window instead of burning the local budget.
    #[test]
    fn test_retry_after_from_kind_extracts_limit_exceeded_delay() {
        use matrix_sdk::ruma::api::client::error::{ErrorKind, RetryAfter};

        let kind = ErrorKind::LimitExceeded {
            retry_after: Some(RetryAfter::Delay(Duration::from_secs(42))),
        };
        let extracted = retry_after_from_kind(&kind)
            .expect("LimitExceeded with Delay must surface a Retry-After");
        assert_eq!(extracted, Duration::from_secs(42));
    }

    #[test]
    fn test_retry_after_from_kind_returns_none_for_missing_hint() {
        use matrix_sdk::ruma::api::client::error::ErrorKind;

        let kind = ErrorKind::LimitExceeded { retry_after: None };
        assert!(retry_after_from_kind(&kind).is_none());
        assert!(retry_after_from_kind(&ErrorKind::forbidden()).is_none());
    }

    /// `LimitExceeded` (M_LIMIT_EXCEEDED, rate-limited login) must
    /// classify as the retryable `AuthProbe` class, not as terminal
    /// `Auth`. Without this peel an operator who hits the homeserver's
    /// login rate limit sees their daemon stick on a terminal-auth
    /// classification and gets steered toward token re-minting (the
    /// `auth` operator hint) when the right action is "retry after the
    /// homeserver's rate-limit window."
    #[test]
    fn test_classify_auth_transient_kind_routes_limit_exceeded_to_retryable() {
        use matrix_sdk::ruma::api::client::error::ErrorKind;

        let mapped =
            classify_auth_transient_kind(&ErrorKind::LimitExceeded { retry_after: None }, || {
                "rate-limited".to_string()
            })
            .expect("rate-limit must classify as transient");
        match mapped {
            MatrixError::AuthProbe(message) => assert_eq!(message, "rate-limited"),
            other => panic!("expected AuthProbe for LimitExceeded, got {other:?}"),
        }

        // Account-state kinds belong to the terminal classifier and
        // must NOT also be claimed by the transient classifier — the
        // two helpers partition the kind space without overlap.
        let terminal_kinds = [
            ErrorKind::UnknownToken { soft_logout: false },
            ErrorKind::UserDeactivated,
            ErrorKind::UserLocked,
            ErrorKind::UserSuspended,
        ];
        for kind in terminal_kinds {
            assert!(
                classify_auth_transient_kind(&kind, || "terminal".to_string()).is_none(),
                "account-state kind {kind:?} must not classify as transient"
            );
        }
        // Forbidden is path-context-dependent at the sync/send layer
        // but it is not in the transient bucket either: at the auth
        // layer it should stay in the terminal classifier's hands (or
        // fall through to MatrixError::Auth) rather than being
        // silently auto-retried.
        assert!(
            classify_auth_transient_kind(&ErrorKind::forbidden(), || "f".to_string()).is_none(),
            "Forbidden must not be classified as transient at the auth layer"
        );
    }

    /// `compute_invite_systemic_message` is the pure-function
    /// extraction of `handle_invites`'s systemic-marker decision.
    /// Below threshold: None (the FailureStreak handles the slower
    /// 3-tick hysteresis). At-or-above threshold: a formatted
    /// operator message that includes total count, a 3-entry
    /// preview, and the truncation suffix when there are more.
    /// `apply_post_sync_maintenance` then surfaces the message
    /// via `last_error`. A regression that drops the threshold
    /// gate or the preview format breaks the operator-facing
    /// shape.
    #[test]
    fn test_compute_invite_systemic_message_below_threshold_is_none() {
        // Empty
        assert_eq!(compute_invite_systemic_message(&[]), None);
        // 1 failure (sub-threshold)
        let one = vec!["!room1 inspect failed: 502".to_string()];
        assert_eq!(compute_invite_systemic_message(&one), None);
        // 2 failures (still sub-threshold)
        let two = vec![
            "!room1 inspect failed: 502".to_string(),
            "!room2 reject failed: 503".to_string(),
        ];
        assert_eq!(compute_invite_systemic_message(&two), None);
    }

    #[test]
    fn test_compute_invite_systemic_message_at_threshold_includes_full_summary() {
        let failures = vec![
            "!room1 inspect failed: 502".to_string(),
            "!room2 reject failed: 503".to_string(),
            "!room3 join failed: 500".to_string(),
        ];
        let msg = compute_invite_systemic_message(&failures)
            .expect("at-threshold must produce a message");
        assert!(
            msg.starts_with("Matrix invite handling: 3 failures"),
            "message must lead with total count: {msg}"
        );
        assert!(msg.contains("!room1 inspect failed: 502"));
        assert!(msg.contains("!room2 reject failed: 503"));
        assert!(msg.contains("!room3 join failed: 500"));
        // Below the truncation threshold (3 ≤ 3), the message
        // includes ALL entries with no `(N more)` suffix.
        assert!(
            !msg.contains("more)"),
            "exactly-threshold should not have truncation suffix: {msg}"
        );
        assert!(
            msg.contains("matrix.autoJoin"),
            "message must point operator to homeserver / allowlist runbook: {msg}"
        );
    }

    #[test]
    fn test_compute_invite_systemic_message_above_threshold_truncates_preview() {
        let failures: Vec<String> = (0..7)
            .map(|i| format!("!room{i} inspect failed: 5{i}{i}"))
            .collect();
        let msg = compute_invite_systemic_message(&failures)
            .expect("above-threshold must produce a message");
        assert!(
            msg.starts_with("Matrix invite handling: 7 failures"),
            "leads with total count: {msg}"
        );
        // First 3 entries shown verbatim.
        for i in 0..3 {
            assert!(
                msg.contains(&format!("!room{i} inspect failed: 5{i}{i}")),
                "preview entry {i} missing from: {msg}"
            );
        }
        // Truncation suffix shows remaining count.
        assert!(
            msg.contains("(4 more)"),
            "expected `(4 more)` truncation suffix in: {msg}"
        );
        // Entries beyond the preview are NOT in the message.
        assert!(
            !msg.contains("!room6 inspect failed"),
            "non-preview entries should not appear in the message: {msg}"
        );
    }

    /// `log_lost_remaining` durability + lost-IDs symmetry. The
    /// phase-3 cleanup helper writes a sticky durability-error
    /// stamp AND populates `inbound_dlq_lost_event_ids` together;
    /// they're a paired surface for operator forensics. A
    /// regression that stamps one without the other (or stamps
    /// both with mismatched IDs) defeats the operator's recovery
    /// path. The full helper is a closure inside
    /// `replay_matrix_inbound_dlq` that takes a `&[String]`-ish
    /// remaining-records list and a path; we pin the contract by
    /// calling the underlying state methods directly with the
    /// same shape, since extracting the closure is invasive.
    #[test]
    fn test_log_lost_remaining_stamps_durability_and_lost_ids_together() {
        let mut state = MatrixRuntimeState::default();
        // Simulate a phase-3 cleanup failure: 3 dispatch-failed
        // records held in memory cannot be persisted back to
        // disk. The helper's contract is to stamp BOTH
        // durability error AND the lost-IDs in a single
        // operator-visible surface.
        state.record_inbound_dlq_append_failure(
            "Matrix inbound DLQ phase-3 cleanup (replace) failed; \
             3 dispatch-failed record(s) held in memory cannot be \
             persisted back to disk: simulated I/O failure"
                .to_string(),
        );
        state.record_inbound_dlq_lost_event_ids(vec![
            "$evt-1:example.com".to_string(),
            "$evt-2:example.com".to_string(),
            "$evt-3:example.com".to_string(),
        ]);

        // Both must be set in lockstep — operators reading
        // /control/channels see a coherent forensic surface.
        assert!(
            state.inbound_durability_error_is_sticky(),
            "log_lost_remaining must stamp the durability error"
        );
        assert_eq!(
            state.status.inbound_dlq_lost_event_ids.len(),
            3,
            "log_lost_remaining must persist the dispatch-failed event IDs"
        );
        // Forensic timestamps must also be in lockstep (per the
        // #439 item 4 fix above).
        assert!(
            state.status.inbound_dlq_durability_error_at.is_some(),
            "durability_error_at must stamp"
        );
        assert!(
            state.status.inbound_dlq_lost_event_ids_at.is_some(),
            "lost_event_ids_at must stamp"
        );
        // The durability message must mention the count for
        // operator triage (matches the production format string).
        assert!(
            state
                .inbound_dlq_durability_error()
                .is_some_and(|s| s.contains("3 dispatch-failed record(s)")),
            "durability message must include the count of held records"
        );
    }

    /// Forensic timestamps must be stamped in lockstep with their
    /// associated state fields and cleared in lockstep with the
    /// corresponding clear method. Without this, the timestamps go
    /// stale: an operator chasing "when did the DLQ start failing?"
    /// would see a timestamp from hours ago even though the
    /// durability error was just cleared.
    #[test]
    fn test_forensic_timestamps_stamp_and_clear_in_lockstep() {
        let mut state = MatrixRuntimeState::default();
        let before = state.status();
        assert!(before.inbound_dlq_durability_error_at.is_none());
        assert!(before.inbound_dlq_lost_event_ids_at.is_none());
        assert!(before.last_inbound_failure_at.is_none());
        assert!(before.last_inbound_dlq_append_failure_at.is_none());

        // Stamp a durability error.
        state.record_inbound_dlq_append_failure("EIO".to_string());
        let after_stamp = state.status();
        assert!(
            after_stamp.inbound_dlq_durability_error_at.is_some(),
            "inbound_dlq_durability_error_at must stamp on append-failure"
        );
        assert!(
            after_stamp.last_inbound_dlq_append_failure_at.is_some(),
            "last_inbound_dlq_append_failure_at must stamp on append-failure"
        );

        // Clear durability — durability_error_at clears in
        // lockstep but last_inbound_dlq_append_failure_at is
        // cumulative and stays.
        state.clear_inbound_dlq_durability_error();
        let after_clear = state.status();
        assert!(
            after_clear.inbound_dlq_durability_error_at.is_none(),
            "clear_inbound_dlq_durability_error must clear inbound_dlq_durability_error_at \
             in lockstep with the message"
        );
        assert!(
            after_clear.last_inbound_dlq_append_failure_at.is_some(),
            "last_inbound_dlq_append_failure_at is cumulative — must NOT clear with the \
             durability error"
        );

        // Stamp a lost-event-ID list, then clear.
        state.record_inbound_dlq_lost_event_ids(vec!["$evt:host".to_string()]);
        assert!(
            state.status().inbound_dlq_lost_event_ids_at.is_some(),
            "inbound_dlq_lost_event_ids_at must stamp on a non-empty append"
        );
        state.clear_inbound_dlq_lost_event_ids();
        assert!(
            state.status().inbound_dlq_lost_event_ids_at.is_none(),
            "clear_inbound_dlq_lost_event_ids must clear the timestamp in lockstep"
        );

        // Stamp an inbound failure, then reset.
        state.record_inbound_failure_with_error("transient".to_string(), "sync-failed");
        assert!(
            state.status().last_inbound_failure_at.is_some(),
            "record_inbound_failure_with_error must always stamp last_inbound_failure_at, \
             even sub-threshold (operator-forensic field)"
        );
        state.reset_inbound_failures();
        assert!(
            state.status().last_inbound_failure_at.is_none(),
            "reset_inbound_failures must clear last_inbound_failure_at in lockstep"
        );
    }

    /// `matrix_send_terminal_error` classifier table. Mirror of
    /// `test_matrix_http_terminal_error_classifies_terminal_kinds`
    /// but for the SDK-error wrapper. Pins:
    /// - Token-revocation classes (M_FORBIDDEN, M_UNKNOWN_TOKEN,
    ///   M_USER_DEACTIVATED, M_USER_LOCKED, M_USER_SUSPENDED) →
    ///   `AuthTokenRevoked` (peeled by `classify_terminal_kind`
    ///   first).
    /// - Send-class permanent rejections (M_TOO_LARGE,
    ///   M_GUEST_ACCESS_FORBIDDEN, M_BAD_JSON, M_UNRECOGNIZED) →
    ///   `SendTerminal`.
    /// - Transient classes (M_LIMIT_EXCEEDED) → `None`, allowing
    ///   the dispatch retry budget to do its work.
    ///
    /// `matrix_send_terminal_error` consumes `&matrix_sdk::Error`
    /// rather than `&ErrorKind`, but the underlying classifier
    /// gates on the kind via `client_api_error_kind()`. Since
    /// constructing a synthetic `matrix_sdk::Error` carrying a
    /// specific kind requires SDK-internal types, this test
    /// exercises the classifier by directly calling
    /// `classify_auth_terminal_kind` (covered separately) plus the
    /// inner `match` body in `matrix_send_terminal_error` —
    /// duplicated here as a pure-function expression that
    /// mirrors the production logic. A drift between the two is
    /// the regression we want to catch; static-analysis verifies
    /// the function body has not been edited away from this shape.
    #[test]
    fn test_matrix_send_terminal_error_kind_routing_table() {
        use matrix_sdk::ruma::api::client::error::ErrorKind;

        // Account-state class — peeled by classify_auth_terminal_kind.
        // Forbidden is NOT here: at the send level it means the
        // specific room rejected the send (room-level permission
        // failure), not a token problem.
        for kind in [
            ErrorKind::UnknownToken { soft_logout: false },
            ErrorKind::UserDeactivated,
            ErrorKind::UserLocked,
            ErrorKind::UserSuspended,
        ] {
            let typed = classify_auth_terminal_kind(&kind, || "x".to_string())
                .expect("account-state class must classify as terminal");
            assert!(
                matches!(typed, MatrixError::AuthTokenRevoked(_)),
                "expected AuthTokenRevoked for {kind:?}, got {typed:?}"
            );
        }
        // Forbidden bypasses the auth-state classifier; the
        // send-path wrapper handles it specifically.
        assert!(
            classify_auth_terminal_kind(&ErrorKind::forbidden(), || "x".to_string()).is_none(),
            "Forbidden must NOT be in the auth-state classifier; \
             it is path-context-dependent"
        );

        // Send-terminal class — auth-state classifier returns None;
        // matrix_send_terminal_error has its own inner match.
        // Mirror the inner match here so a drift in the production
        // routing trips the test. Forbidden is in the send-terminal
        // table now.
        let send_terminal_kinds = [
            ErrorKind::forbidden(),
            ErrorKind::ThreepidDenied,
            ErrorKind::TooLarge,
            ErrorKind::GuestAccessForbidden,
            ErrorKind::BadJson,
            ErrorKind::Unrecognized,
        ];
        for kind in send_terminal_kinds {
            assert!(
                classify_auth_terminal_kind(&kind, || "x".to_string()).is_none(),
                "{kind:?} must NOT classify at the auth-state level"
            );
            // The send-class is matched in the wrapper's body:
            let send_classified = matches!(
                kind,
                ErrorKind::Forbidden { .. }
                    | ErrorKind::ThreepidDenied
                    | ErrorKind::TooLarge
                    | ErrorKind::GuestAccessForbidden
                    | ErrorKind::BadJson
                    | ErrorKind::Unrecognized
            );
            assert!(
                send_classified,
                "{kind:?} must be in the SendTerminal classifier table"
            );
        }

        // Transient class — neither classifier returns Some.
        let transient_kinds = [ErrorKind::LimitExceeded { retry_after: None }];
        for kind in transient_kinds {
            assert!(
                classify_auth_terminal_kind(&kind, || "x".to_string()).is_none(),
                "{kind:?} must remain transient at the auth-state level"
            );
            let send_classified = matches!(
                kind,
                ErrorKind::TooLarge
                    | ErrorKind::GuestAccessForbidden
                    | ErrorKind::BadJson
                    | ErrorKind::Unrecognized
            );
            assert!(
                !send_classified,
                "{kind:?} must remain transient at the send-terminal level too"
            );
        }

        // Pin the source body — drift in the inner match arm
        // would otherwise silently change routing.
        let body = matrix_rs_fn_body("fn matrix_send_terminal_error");
        let body = body.as_str();
        assert!(
            body.contains("ErrorKind::ThreepidDenied"),
            "matrix_send_terminal_error must classify M_THREEPID_DENIED as SendTerminal"
        );
        assert!(
            body.contains("ErrorKind::TooLarge"),
            "matrix_send_terminal_error must classify M_TOO_LARGE as SendTerminal"
        );
        assert!(
            body.contains("ErrorKind::GuestAccessForbidden"),
            "matrix_send_terminal_error must classify M_GUEST_ACCESS_FORBIDDEN as SendTerminal"
        );
        assert!(
            body.contains("ErrorKind::BadJson"),
            "matrix_send_terminal_error must classify M_BAD_JSON as SendTerminal"
        );
        assert!(
            body.contains("ErrorKind::Unrecognized"),
            "matrix_send_terminal_error must classify M_UNRECOGNIZED as SendTerminal"
        );
    }

    /// Pin the five phrases the heuristic at
    /// `matrix_open_store_message_indicates_passphrase_mismatch`
    /// matches. A matrix-sdk upgrade that rewords any of them
    /// silently re-routes a wrong-passphrase startup failure
    /// from `EncryptedStorePassphraseMismatch` (which the CLI
    /// surfaces with the rekey-recovery hint) to `ClientBuild`
    /// (which ships a generic message). This test trips before
    /// shipping so the heuristic stays in lockstep with the SDK.
    #[test]
    fn test_open_store_passphrase_mismatch_phrase_pin() {
        for phrase in [
            "Failed to initialize the store cipher: aead::Error",
            "Error encrypting or decrypting a value",
            "aead::Error wrapped in InitCipher",
            "Failed to import a store cipher, the export used a passphrase",
            "Incorrect passphrase supplied",
        ] {
            assert!(
                matrix_open_store_message_indicates_passphrase_mismatch(phrase),
                "phrase should classify as passphrase mismatch: {phrase}"
            );
        }
        for control in [
            "Database is locked",
            "could not decrypt ciphertext",
            "kdf parameters mismatch",
            "version mismatch on the encrypted store",
            "I/O error reading file",
        ] {
            assert!(
                !matrix_open_store_message_indicates_passphrase_mismatch(control),
                "phrase should NOT classify as passphrase mismatch: {control}"
            );
        }
    }

    #[test]
    fn test_set_json_path_checked_rejects_non_object_intermediates() {
        let mut config = json!({
            "matrix": "not-an-object"
        });

        let err = set_json_path_checked(
            &mut config,
            &["matrix", "accessToken"],
            Value::String("token".to_string()),
        )
        .expect_err("non-object intermediates must not be coerced");
        assert!(matches!(err, MatrixError::TokenPersistence(_)));
        assert_eq!(config["matrix"], "not-an-object");
    }

    #[test]
    fn test_pinned_matrix_store_key_vector() {
        let key = derive_matrix_store_key(
            b"correct horse battery staple",
            b"installation-00000000-0000-0000-0000-000000000000",
        )
        .unwrap();
        assert_eq!(
            hex::encode(key),
            "c812a97783aa8a0256aa4607a57f3652bf183a9eb7fa422cfaf7c19da935b44b"
        );
    }

    /// Pin: per-path Forbidden classification. `matrix_send_terminal_error`
    /// must route Forbidden to `SendTerminal` (room-level
    /// rejection), NOT `AuthTokenRevoked` (which would mislead
    /// operators into rotating their token after a "this room
    /// banned me" or "no power level" error). Sync-path Forbidden
    /// remains routed to AuthTokenRevoked because at the sync
    /// level Forbidden means the token is no longer authorized
    /// for this user's sync (token-state).
    #[test]
    fn test_matrix_send_terminal_error_routes_room_forbidden_to_send_terminal() {
        // Build a forbidden-classed `matrix_sdk::Error` via the
        // `RumaApiError::ClientApi` path so `client_api_error_kind`
        // returns Forbidden. Constructing the exact error type via
        // SDK internals isn't exposed for unit tests; instead pin
        // the per-path branch via static analysis on the function
        // body.
        let body = matrix_rs_fn_body("fn matrix_send_terminal_error");
        let body = body.as_str();
        assert!(
            body.contains("ErrorKind::Forbidden { .. }"),
            "matrix_send_terminal_error must explicitly handle Forbidden"
        );
        assert!(
            body.contains("MatrixError::SendTerminal"),
            "Forbidden in send path must route to SendTerminal, not AuthTokenRevoked"
        );
        // Sync-path Forbidden routes to AuthTokenRevoked.
        let sync_body = matrix_rs_fn_body("fn matrix_sync_terminal_error");
        let sync_body = sync_body.as_str();
        assert!(
            sync_body.contains("MatrixError::AuthTokenRevoked"),
            "matrix_sync_terminal_error Forbidden branch must route to AuthTokenRevoked"
        );
    }

    /// Pin: room-message verification requests must use the same
    /// sender trust gate as to-device requests before they consume
    /// verification-record capacity.
    #[test]
    fn test_handle_room_message_verification_request_uses_sender_trust_gate() {
        let body = matrix_rs_fn_body("async fn handle_room_message_event");
        let body = body.as_str();
        assert!(
            body.contains("MessageType::VerificationRequest"),
            "room-message handler must explicitly handle verification requests"
        );
        assert!(
            body.contains("matrix_user_ids_equal(&event.sender, &config.user_id)"),
            "room-message verification gate must allow self-sent requests"
        );
        assert!(
            body.contains("config.auto_join.allows_user(sender_str)"),
            "room-message verification gate must allow only configured peers"
        );
        assert!(
            body.contains("room-message verification request dropped"),
            "untrusted room-message verification requests must drop before upsert"
        );
    }

    /// `summarize_failures` boundary cases. Pinned directly — the
    /// helper is shared by invite-systemic and DLQ-replay paths,
    /// and `compute_invite_systemic_message` exercises it
    /// indirectly only at threshold and above. The empty-list and
    /// `preview_len > items` branches need their own pins.
    #[test]
    fn test_summarize_failures_boundary_cases() {
        // Empty list.
        assert_eq!(summarize_failures(&[], 3), "");
        // One item, plenty of preview slots.
        let one = vec!["only".to_string()];
        assert_eq!(summarize_failures(&one, 3), "only");
        // Exactly preview_len items: full join, NO truncation suffix.
        let three = vec!["a".to_string(), "b".to_string(), "c".to_string()];
        assert_eq!(summarize_failures(&three, 3), "a; b; c");
        // Above preview_len: truncated form.
        let four = vec![
            "a".to_string(),
            "b".to_string(),
            "c".to_string(),
            "d".to_string(),
        ];
        assert_eq!(summarize_failures(&four, 3), "a; b; c (1 more)");
        // preview_len > items: full join.
        assert_eq!(summarize_failures(&one, 5), "only");
    }

    /// `push_invite_failure` redaction guarantee. The helper
    /// centralizes the `RedactedDisplay` wrap so every site that
    /// pushes an SDK error onto the `failures` Vec gets uniform
    /// treatment. A regression that drops the wrap would let
    /// homeserver-controlled control bytes flow into `last_error`
    /// JSON via the systemic-failure summary path.
    #[test]
    fn test_push_invite_failure_redacts_control_bytes() {
        struct HostileError;
        impl std::fmt::Display for HostileError {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("err with \x1b[31mctrl\u{202E}bytes")
            }
        }
        let mut failures: Vec<String> = Vec::new();
        push_invite_failure(&mut failures, "!room:example.com", "join", &HostileError);
        assert_eq!(failures.len(), 1);
        let msg = &failures[0];
        assert!(
            !msg.contains('\x1b'),
            "ANSI escape must be stripped: {msg:?}"
        );
        assert!(
            !msg.contains('\u{202E}'),
            "Bidi override must be stripped: {msg:?}"
        );
        assert!(
            msg.contains("!room:example.com join failed:"),
            "operator-readable prefix preserved: {msg:?}"
        );
        assert!(
            msg.contains("ctrl"),
            "non-control characters preserved: {msg:?}"
        );
    }

    /// Full HKDF chain: config_password → store_key → hex(store_key)
    /// → DLQ_key. The two pinned vectors above lock the pure HKDF
    /// derivations in isolation, but the chain that joins them — the
    /// `hex::encode` step inside
    /// `derive_matrix_store_passphrase_from_config_password` — is not
    /// exercised by either. Without this test, a switch from
    /// lower-case hex to upper-case (or URL-safe base64) at the
    /// glue layer would break decryption of every on-disk DLQ record
    /// without tripping either pure-function pin.
    #[test]
    fn test_pinned_matrix_store_to_dlq_chain_vector() {
        // Same inputs as the pure-function pins above, so the chain
        // value is reproducible by hand: store_key = c812... → hex =
        // "c812a97783aa8a0256aa4607a57f3652bf183a9eb7fa422cfaf7c19da935b44b"
        // → DLQ_key derived from that hex string + same installation_id.
        let config_password = b"correct horse battery staple";
        let installation_id = b"installation-00000000-0000-0000-0000-000000000000";

        let store_key = derive_matrix_store_key(config_password, installation_id).unwrap();
        let store_passphrase_hex = hex::encode(store_key);
        // Sanity: the hex-encoded store key matches the pinned vector
        // above. If this fails, one of the pins drifted.
        assert_eq!(
            store_passphrase_hex,
            "c812a97783aa8a0256aa4607a57f3652bf183a9eb7fa422cfaf7c19da935b44b"
        );

        let dlq_key =
            derive_matrix_inbound_dlq_key_from(store_passphrase_hex.as_bytes(), installation_id)
                .unwrap();
        // Pinned chain output. Any change to MATRIX_STORE_INFO,
        // MATRIX_INBOUND_DLQ_INFO, the hex encoding step, or the HKDF
        // construction will trip this assertion before shipping.
        assert_eq!(
            hex::encode(dlq_key),
            "771408ff94686fe5a22466fd2b115c298d9091c881af11451edd9989d2e0da2f"
        );
    }

    /// Golden JSON shape for `MatrixStatusMetadata`. The serialized
    /// form is wire format — operators reading `channels.status` and
    /// the Control UI rendering channel metadata both depend on the
    /// camelCase field names. A future `#[serde(rename_all)]` flip or
    /// a field rename would silently break browser clients and any
    /// external consumer polling `/control/channels`. Pin the shape
    /// directly so any drift trips this test before shipping.
    #[test]
    fn test_pinned_matrix_status_metadata_wire_shape() {
        let metadata = MatrixStatusMetadata {
            joined_room_count: 5,
            encrypted_room_count: 3,
            unencrypted_room_count: 2,
            unsupported_room_count: 0,
            pending_verification_count: 1,
            last_successful_sync_at: Some(1700000000000),
            unsupported_rooms: vec!["!room:example.com".to_string()],
            unsupported_inbound_count: 7,
            inbound_dispatch_failure_total: 2,
            inbound_dlq_append_failure_total: 0,
            inbound_dlq_durability_error: None,
            inbound_dlq_lost_event_ids: Vec::new(),
            inbound_dlq_undecodable_lost_count: 0,
            last_error_kind: None,
            inbound_dlq_durability_error_at: None,
            inbound_dlq_lost_event_ids_at: None,
            last_inbound_failure_at: None,
            last_inbound_dlq_append_failure_at: None,
            first_recovery_key_minted_at: None,
            peer_drop_unsupported_msgtype_total: 3,
            peer_drop_allowlist_rejection_total: 4,
            peer_drop_body_too_large_total: 5,
            peer_drop_verification_cap_full_total: 6,
            peer_drop_encrypted_room_total: 8,
            inbound_dedupe_corrupt_line_total: 9,
        };
        let json = serde_json::to_value(&metadata).expect("serialize");
        let expected = serde_json::json!({
            "joinedRoomCount": 5,
            "encryptedRoomCount": 3,
            "unencryptedRoomCount": 2,
            "unsupportedRoomCount": 0,
            "pendingVerificationCount": 1,
            "lastSuccessfulSyncAt": 1700000000000_i64,
            "unsupportedRooms": ["!room:example.com"],
            "unsupportedInboundCount": 7,
            "inboundDispatchFailureTotal": 2,
            "inboundDlqAppendFailureTotal": 0,
            "inboundDlqUndecodableLostCount": 0,
            "peerDropUnsupportedMsgtypeTotal": 3,
            "peerDropAllowlistRejectionTotal": 4,
            "peerDropBodyTooLargeTotal": 5,
            "peerDropVerificationCapFullTotal": 6,
            "peerDropEncryptedRoomTotal": 8,
            "inboundDedupeCorruptLineTotal": 9,
        });
        assert_eq!(
            json, expected,
            "MatrixStatusMetadata wire shape changed; if this is intentional, \
             update the docs at docs/protocol/websocket.md and notify Control \
             UI consumers. inbound_dlq_durability_error is omitted on None per \
             skip_serializing_if."
        );

        // With a durability error present, the field appears.
        let metadata_with_err = MatrixStatusMetadata {
            inbound_dlq_durability_error: Some("disk full".to_string()),
            ..metadata.clone()
        };
        let json = serde_json::to_value(&metadata_with_err).expect("serialize");
        assert_eq!(
            json.get("inboundDlqDurabilityError")
                .and_then(|v| v.as_str()),
            Some("disk full"),
        );

        // With lost event ids present, the field appears as a JSON
        // array under the camelCase rename. Pins both that the field
        // serializes (omit-when-empty was already verified above) AND
        // that the rename is `inboundDlqLostEventIds`. A future
        // inadvertent removal of `#[serde(rename_all = camelCase)]`
        // or a typo in a `#[serde(rename = ...)]` would trip here.
        let metadata_with_lost = MatrixStatusMetadata {
            inbound_dlq_lost_event_ids: vec![
                "$evt1:example.com".to_string(),
                "$evt2:example.com".to_string(),
            ],
            ..metadata
        };
        let json = serde_json::to_value(&metadata_with_lost).expect("serialize");
        let lost = json
            .get("inboundDlqLostEventIds")
            .and_then(|v| v.as_array())
            .expect("inboundDlqLostEventIds must serialize as a JSON array");
        let collected: Vec<&str> = lost.iter().filter_map(|v| v.as_str()).collect();
        assert_eq!(collected, vec!["$evt1:example.com", "$evt2:example.com"]);
        assert!(
            json.get("inbound_dlq_lost_event_ids").is_none(),
            "snake_case form must NOT appear; rename_all=camelCase governs the wire format"
        );

        // With a typed kind present, the field appears as
        // `lastErrorKind` (camelCase rename). The CLI's
        // `verify_matrix_outcome` matches on this exact key/value
        // pair to route per-variant remediation hints; a typo in
        // either side would silently disable the routing.
        let metadata_with_kind = MatrixStatusMetadata {
            last_error_kind: Some("auth-token-revoked".to_string()),
            ..MatrixStatusMetadata::default()
        };
        let json = serde_json::to_value(&metadata_with_kind).expect("serialize");
        assert_eq!(
            json.get("lastErrorKind").and_then(|v| v.as_str()),
            Some("auth-token-revoked"),
            "lastErrorKind must surface the kebab-case kind value when set",
        );
        assert!(
            json.get("last_error_kind").is_none(),
            "snake_case form must NOT appear; rename_all=camelCase governs"
        );

        // Forensic timestamps are optional and usually absent, so
        // the base shape above would not catch a rename regression.
        // Pin the camelCase keys explicitly while populated.
        let metadata_with_forensic_timestamps = MatrixStatusMetadata {
            inbound_dlq_durability_error_at: Some(1_700_000_000_001),
            inbound_dlq_lost_event_ids_at: Some(1_700_000_000_002),
            last_inbound_failure_at: Some(1_700_000_000_003),
            last_inbound_dlq_append_failure_at: Some(1_700_000_000_004),
            first_recovery_key_minted_at: Some(1_700_000_000_005),
            ..MatrixStatusMetadata::default()
        };
        let json = serde_json::to_value(&metadata_with_forensic_timestamps).expect("serialize");
        for (key, expected) in [
            ("inboundDlqDurabilityErrorAt", 1_700_000_000_001_i64),
            ("inboundDlqLostEventIdsAt", 1_700_000_000_002_i64),
            ("lastInboundFailureAt", 1_700_000_000_003_i64),
            ("lastInboundDlqAppendFailureAt", 1_700_000_000_004_i64),
            ("firstRecoveryKeyMintedAt", 1_700_000_000_005_i64),
        ] {
            assert_eq!(
                json.get(key).and_then(|v| v.as_i64()),
                Some(expected),
                "{key} must serialize in camelCase when populated"
            );
        }
        for snake_key in [
            "inbound_dlq_durability_error_at",
            "inbound_dlq_lost_event_ids_at",
            "last_inbound_failure_at",
            "last_inbound_dlq_append_failure_at",
            "first_recovery_key_minted_at",
        ] {
            assert!(
                json.get(snake_key).is_none(),
                "{snake_key} must NOT appear on the MatrixStatusMetadata wire surface"
            );
        }
    }

    #[test]
    fn test_peer_drop_and_corrupt_dedupe_counters_are_operator_visible() {
        let mut state = MatrixRuntimeState::default();
        assert_eq!(
            state.record_peer_drop(MatrixPeerDropKind::AllowlistRejection),
            1
        );
        state.record_inbound_dedupe_corrupt_lines(2);
        let metadata = state.status();
        assert_eq!(metadata.peer_drop_allowlist_rejection_total, 1);
        assert_eq!(metadata.inbound_dedupe_corrupt_line_total, 2);
        assert!(should_log_matrix_peer_drop(1));
        assert!(should_log_matrix_peer_drop(8));
        assert!(!should_log_matrix_peer_drop(11));
        assert!(should_log_matrix_inbound_dispatch_failure(1, 4097));
        assert!(!should_log_matrix_inbound_dispatch_failure(2, 4097));
    }

    /// Pin every `MatrixError::kind()` value. The values are wire-
    /// stable: external consumers (CLI's `verify_matrix_outcome` arms,
    /// future control-API readers, automation scripts) match against
    /// these exact strings. Renaming a returned token here is a
    /// breaking change — without this pin a typo or "let me clean up
    /// the kebab-case" copy edit would compile silently and ship a
    /// regression that only manifests when an operator hits the
    /// affected error path.
    #[test]
    fn test_matrix_error_kind_wire_stable_table() {
        // A small fixture path / detail string for variants that
        // need them; the `kind()` is independent of the payload.
        let p = std::path::PathBuf::from("/tmp/store");
        let cases: &[(MatrixError, &str)] = &[
            (MatrixError::InvalidConfigRoot, "invalid-config-root"),
            (MatrixError::InvalidString { field: "x" }, "invalid-string"),
            (MatrixError::InvalidBool { field: "x" }, "invalid-bool"),
            (
                MatrixError::InvalidStringArray { field: "x" },
                "invalid-string-array",
            ),
            (
                MatrixError::InvalidLength {
                    field: "x",
                    max: 1,
                    got: 2,
                },
                "invalid-length",
            ),
            (
                MatrixError::InvalidUrl {
                    field: "x",
                    reason: "y",
                },
                "invalid-url",
            ),
            (
                MatrixError::AllowlistTooLarge {
                    field: "x",
                    max: 1,
                    got: 2,
                },
                "allowlist-too-large",
            ),
            (MatrixError::MissingHomeserverUrl, "missing-homeserver-url"),
            (MatrixError::MissingUserId, "missing-user-id"),
            (MatrixError::MissingCredentials, "missing-credentials"),
            (
                MatrixError::MissingDeviceIdForTokenRestore,
                "missing-device-id-for-token-restore",
            ),
            (MatrixError::MissingStoreSecret, "missing-store-secret"),
            (MatrixError::StoreKeyDerivation, "store-key-derivation"),
            (MatrixError::InstallationId("x".into()), "installation-id"),
            (MatrixError::ClientBuild("x".into()), "client-build"),
            (MatrixError::Auth("x".into()), "auth"),
            (MatrixError::AuthProbe("x".into()), "auth-probe"),
            (
                MatrixError::AuthSessionUserMismatch {
                    actual: "a".into(),
                    expected: "b".into(),
                },
                "auth-session-user-mismatch",
            ),
            (
                MatrixError::AuthSessionDeviceMismatch {
                    actual: "a".into(),
                    expected: "b".into(),
                },
                "auth-session-device-mismatch",
            ),
            (
                MatrixError::AuthSessionMissingDeviceId,
                "auth-session-missing-device-id",
            ),
            (
                MatrixError::AuthTokenRevoked("x".into()),
                "auth-token-revoked",
            ),
            (
                MatrixError::TokenPersistence("x".into()),
                "token-persistence",
            ),
            (
                MatrixError::RecoveryKeyRestoreFailed {
                    reason: RecoveryRestoreFailureReason::WrongKey,
                    detail: "x".into(),
                },
                "recovery-key-restore-failed",
            ),
            (
                MatrixError::CrossSigningBootstrapFailed("x".into()),
                "cross-signing-bootstrap-failed",
            ),
            (
                MatrixError::EncryptedStateIo("x".into()),
                "encrypted-state-io",
            ),
            (
                MatrixError::RecoveryStateProbeFailed("x".into()),
                "recovery-state-probe-failed",
            ),
            (
                MatrixError::RecoveryStateIo("x".into()),
                "recovery-state-io",
            ),
            (
                MatrixError::RecoveryConfigPrecondition("x".into()),
                "recovery-config-precondition",
            ),
            (
                MatrixError::RecoveryKeyPromotionRefused("x".into()),
                "recovery-key-promotion-refused",
            ),
            (MatrixError::StartupFailed("x".into()), "startup-failed"),
            (
                MatrixError::InterruptedRekey("x".into()),
                "interrupted-rekey",
            ),
            (MatrixError::Clock("x".into()), "clock"),
            (MatrixError::NotConnected, "not-connected"),
            (MatrixError::UnsupportedRoom("x".into()), "unsupported-room"),
            (MatrixError::RoomNotFound("x".into()), "room-not-found"),
            (
                MatrixError::SendFailed {
                    message: "x".into(),
                    retry_after_ms: None,
                },
                "send-failed",
            ),
            (MatrixError::SyncFailed("x".into()), "sync-failed"),
            (
                MatrixError::DlqCrypto(DlqCryptoFailure::Other("x".into())),
                "dlq-crypto",
            ),
            (MatrixError::DlqIo("x".into()), "dlq-io"),
            (
                MatrixError::DlqSerialization("x".into()),
                "dlq-serialization",
            ),
            (
                MatrixError::DlqDispatchFailure("x".into()),
                "dlq-dispatch-failure",
            ),
            (
                MatrixError::DlqCapSaturation("x".into()),
                "dlq-cap-saturation",
            ),
            (
                MatrixError::LegacyDlqEnvelopeRefused("refused".into()),
                "legacy-dlq-envelope-refused",
            ),
            (
                MatrixError::SessionHistoryCorrupt("x".into()),
                "session-history-corrupt",
            ),
            (
                MatrixError::VerificationFlowNotFound("x".into()),
                "verification-flow-not-found",
            ),
            (MatrixError::InvalidUserId("x".into()), "invalid-user-id"),
            (
                MatrixError::DeviceNotFound {
                    user_id: "u".into(),
                    device_id: "d".into(),
                },
                "device-not-found",
            ),
            (
                MatrixError::UserIdentityNotFound("x".into()),
                "user-identity-not-found",
            ),
            (
                MatrixError::VerificationFlowNotReady {
                    flow_id: "f".into(),
                    action: "accept",
                },
                "verification-flow-not-ready",
            ),
            (MatrixError::Verification("x".into()), "verification"),
            (
                MatrixError::VerificationTimeout("x".into()),
                "verification-timeout",
            ),
            (MatrixError::CommandQueueFull, "command-queue-full"),
            (
                MatrixError::EncryptedStorePassphraseMismatch {
                    path: p.clone(),
                    detail: "x".into(),
                },
                "encrypted-store-passphrase-mismatch",
            ),
            (
                MatrixError::VerificationCancelled {
                    flow_id: "f".into(),
                    state: MatrixVerificationState::Cancelled,
                },
                "verification-cancelled",
            ),
            (MatrixError::SendTerminal("x".into()), "send-terminal"),
            (
                MatrixError::SyncLoopGaveUp {
                    idle_ms: 86_400_001,
                },
                "sync-loop-give-up",
            ),
        ];
        for (err, expected_kind) in cases {
            assert_eq!(
                err.kind(),
                *expected_kind,
                "MatrixError::{:?} must return wire-stable kind {:?}",
                err,
                expected_kind
            );
        }
    }

    #[test]
    fn test_sync_loop_gave_up_display_is_idempotent() {
        let first = MatrixError::SyncLoopGaveUp {
            idle_ms: 86_400_001,
        }
        .to_string();
        let later = MatrixError::SyncLoopGaveUp {
            idle_ms: 172_800_002,
        }
        .to_string();

        assert_eq!(
            first, later,
            "SyncLoopGaveUp Display must stay stable across hourly restamps"
        );
        assert!(
            !first.contains("86400001") && !first.contains("172800002"),
            "idle_ms belongs in structured log metadata, not the idempotence key"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_matrix_sync_join_panic_preserves_terminal_auth_kind() {
        let handle = tokio::spawn(async {
            panic!("M_UNKNOWN_TOKEN from sync task");
        });
        let join_err = handle.await.expect_err("sync task should panic");
        let err = matrix_sync_join_error(join_err);

        assert!(
            matches!(err, MatrixError::AuthTokenRevoked(ref message) if message.contains("M_UNKNOWN_TOKEN")),
            "sync task panic carrying terminal auth must stay typed, got {err:?}"
        );
    }

    struct FakeWhoamiProbe {
        attempts: std::sync::atomic::AtomicUsize,
        outcomes: ParkingMutex<std::collections::VecDeque<Result<(), MatrixWhoamiProbeError>>>,
    }

    impl FakeWhoamiProbe {
        fn new(outcomes: impl IntoIterator<Item = Result<(), MatrixWhoamiProbeError>>) -> Self {
            Self {
                attempts: std::sync::atomic::AtomicUsize::new(0),
                outcomes: ParkingMutex::new(outcomes.into_iter().collect()),
            }
        }

        fn attempts(&self) -> usize {
            self.attempts.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    #[async_trait::async_trait]
    impl MatrixWhoamiProbe for FakeWhoamiProbe {
        type Response = ();

        async fn whoami(&self) -> Result<Self::Response, MatrixWhoamiProbeError> {
            self.attempts
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.outcomes
                .lock()
                .pop_front()
                .expect("fake whoami probe exhausted")
        }
    }

    /// Fake-driven pin for `whoami_with_bounded_retry`'s typed-
    /// variant preservation contract. Terminal token-revocation
    /// classes must return immediately as their original `MatrixError`
    /// variant so `verify_matrix_outcome` can route to the rekey-token
    /// hint; retry-budget collapse would degrade the operator path to
    /// the generic auth-probe fallback.
    #[tokio::test(flavor = "current_thread")]
    async fn test_whoami_with_bounded_retry_returns_terminal_without_retry() {
        let probe = FakeWhoamiProbe::new([
            Err(MatrixWhoamiProbeError::Terminal(
                MatrixError::AuthTokenRevoked("M_UNKNOWN_TOKEN".to_string()),
            )),
            Ok(()),
        ]);
        let mut sleeps = Vec::new();

        let err =
            whoami_with_bounded_retry_from_probe(&probe, &[Duration::from_secs(1)], |delay| {
                sleeps.push(delay);
                std::future::ready(())
            })
            .await
            .expect_err("terminal auth must fail immediately");

        assert!(
            matches!(err, MatrixError::AuthTokenRevoked(ref message) if message == "M_UNKNOWN_TOKEN"),
            "terminal auth must preserve typed variant, got {err:?}"
        );
        assert_eq!(probe.attempts(), 1, "terminal auth must not retry");
        assert!(sleeps.is_empty(), "terminal auth must not sleep");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_whoami_with_bounded_retry_retries_transient_then_succeeds() {
        let probe = FakeWhoamiProbe::new([
            Err(MatrixWhoamiProbeError::Transient(
                MatrixWhoamiTransientError {
                    message: "M_LIMIT_EXCEEDED".to_string(),
                    retry_after: Some(Duration::from_secs(42)),
                },
            )),
            Ok(()),
        ]);
        let mut sleeps = Vec::new();

        whoami_with_bounded_retry_from_probe(&probe, &[Duration::from_secs(1)], |delay| {
            sleeps.push(delay);
            std::future::ready(())
        })
        .await
        .expect("transient whoami should retry and then succeed");

        assert_eq!(probe.attempts(), 2);
        assert_eq!(
            sleeps,
            vec![Duration::from_secs(42)],
            "homeserver Retry-After must win over the local retry floor"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_whoami_with_bounded_retry_uses_floor_for_short_retry_after() {
        let probe = FakeWhoamiProbe::new([
            Err(MatrixWhoamiProbeError::Transient(
                MatrixWhoamiTransientError {
                    message: "M_LIMIT_EXCEEDED".to_string(),
                    retry_after: Some(Duration::from_millis(100)),
                },
            )),
            Ok(()),
        ]);
        let mut sleeps = Vec::new();

        whoami_with_bounded_retry_from_probe(&probe, &[Duration::from_secs(1)], |delay| {
            sleeps.push(delay);
            std::future::ready(())
        })
        .await
        .expect("transient whoami should retry and then succeed");

        assert_eq!(
            sleeps,
            vec![Duration::from_secs(1)],
            "local retry floor must win over a tiny homeserver Retry-After"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_whoami_with_bounded_retry_caps_large_retry_after() {
        let probe = FakeWhoamiProbe::new([
            Err(MatrixWhoamiProbeError::Transient(
                MatrixWhoamiTransientError {
                    message: "M_LIMIT_EXCEEDED".to_string(),
                    retry_after: Some(MATRIX_RETRY_AFTER_MAX + Duration::from_secs(1)),
                },
            )),
            Ok(()),
        ]);
        let mut sleeps = Vec::new();

        whoami_with_bounded_retry_from_probe(&probe, &[Duration::from_secs(1)], |delay| {
            sleeps.push(delay);
            std::future::ready(())
        })
        .await
        .expect("transient whoami should retry and then succeed");

        assert_eq!(
            sleeps,
            vec![MATRIX_RETRY_AFTER_MAX],
            "oversized homeserver Retry-After must be capped"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_whoami_with_bounded_retry_exhausts_transient_as_auth_probe() {
        let probe = FakeWhoamiProbe::new([
            Err(MatrixWhoamiProbeError::Transient(
                MatrixWhoamiTransientError {
                    message: "network down".to_string(),
                    retry_after: None,
                },
            )),
            Err(MatrixWhoamiProbeError::Transient(
                MatrixWhoamiTransientError {
                    message: "still down".to_string(),
                    retry_after: None,
                },
            )),
        ]);
        let mut sleeps = Vec::new();

        let err =
            whoami_with_bounded_retry_from_probe(&probe, &[Duration::from_secs(1)], |delay| {
                sleeps.push(delay);
                std::future::ready(())
            })
            .await
            .expect_err("exhausted transient whoami must fail closed");

        assert_eq!(probe.attempts(), 2);
        assert_eq!(sleeps, vec![Duration::from_secs(1)]);
        assert!(
            matches!(err, MatrixError::AuthProbe(ref message)
                if message.contains("after 2 whoami() attempts")
                    && message.contains("still down")),
            "exhausted transient whoami must surface AuthProbe, got {err:?}"
        );
    }

    /// Static-analysis pin for `handle_room_message_event`'s
    /// sanitization-hoist contract. Every operator-visible log
    /// emission inside the function MUST use the sanitized
    /// `room_id` / `sender_id` / `event_id` bindings, not the raw
    /// `room.room_id()` / `event.sender` / `event.event_id` from
    /// the SDK types. A regression that re-inlines any of the raw
    /// references in any of the four early-return branches
    /// (msgtype-not-supported, relation-suppressed, empty-body,
    /// body-size-cap) re-opens the homeserver-controlled ANSI/bidi
    /// injection surface that this PR closed.
    ///
    /// The function consumes ruma SDK types that are awkward to
    /// construct in unit tests, so the pin runs static analysis
    /// against the function source. Combined with
    /// `test_sanitize_homeserver_identifier_strips_dangerous_classes`
    /// which exercises the helper itself, this catches both
    /// sanitizer regressions and call-site re-inlining mistakes.
    #[test]
    fn test_handle_room_message_event_uses_sanitized_identifiers_in_logs() {
        let body = matrix_rs_fn_body("async fn handle_room_message_event");
        let body = body.as_str();

        // Pin: the sanitized triple is bound at function entry.
        for binding in [
            "let room_id_log = sanitize_homeserver_identifier(",
            "let sender_id_log = sanitize_homeserver_identifier(",
            "let event_id_log = sanitize_homeserver_identifier(",
        ] {
            assert!(
                body.contains(binding),
                "handle_room_message_event missing expected sanitization \
                 binding `{binding}`. The hoist must compute the sanitized \
                 triple at function entry so all downstream log emissions \
                 use cleaned identifiers."
            );
        }

        // Pin: NO tracing macro field uses the raw SDK references.
        // `tracing` field syntax is `field = %value` for Display
        // formatting; the regression we want to catch is something
        // like `event_id = %event.event_id` slipping back in.
        for forbidden in [
            "%event.event_id",
            "%event.sender",
            "%room.room_id()",
            "= ?event.event_id",
            "= ?event.sender",
            "= ?room.room_id()",
        ] {
            assert!(
                !body.contains(forbidden),
                "handle_room_message_event contains forbidden raw-identifier \
                 tracing field `{forbidden}`. Use the sanitized `room_id` / \
                 `sender_id` / `event_id` bindings instead — homeserver-\
                 controlled bytes (ANSI escapes, bidi overrides) in raw \
                 identifiers can rewrite operator-visible terminal scrollback."
            );
        }
    }

    /// Pin the camelCase wire shape of `MatrixDeviceInfo`. Browser
    /// UI and external automation that consume `/control/matrix/devices`
    /// depend on `userId` / `deviceId` / `displayName` / `verified`.
    /// A future field rename or `rename_all` flip would silently break
    /// them; trip the test instead.
    #[test]
    fn test_pinned_matrix_device_info_wire_shape() {
        let info = MatrixDeviceInfo {
            user_id: "@alice:example.com".parse().expect("user id"),
            device_id: "DEVICEID".into(),
            display_name: Some("Laptop".to_string()),
            verified: true,
            raw_device_id_hex: None,
        };
        let json = serde_json::to_value(&info).expect("serialize");
        let expected = serde_json::json!({
            "userId": "@alice:example.com",
            "deviceId": "DEVICEID",
            "displayName": "Laptop",
            "verified": true,
        });
        assert_eq!(json, expected, "MatrixDeviceInfo wire shape changed");
        assert!(
            json.get("rawDeviceIdHex").is_none(),
            "rawDeviceIdHex omitted when sanitization is a no-op"
        );

        // With raw_device_id_hex Some, the field surfaces under the
        // camelCase rename so operator scripts can disambiguate
        // adversarial peer devices via hex-decoded byte-exact
        // lookup. Wire form is hex (no raw control bytes in JSON).
        let info = MatrixDeviceInfo {
            user_id: "@alice:example.com".parse().expect("user id"),
            device_id: "DEVICEID".into(),
            display_name: None,
            verified: false,
            raw_device_id_hex: Some(hex::encode(b"\xe2\x80\x8eDEVICEID")),
        };
        let json = serde_json::to_value(&info).expect("serialize");
        let hex_value = json
            .get("rawDeviceIdHex")
            .and_then(|v| v.as_str())
            .expect("rawDeviceIdHex must surface under camelCase rename");
        assert_eq!(
            hex_value, "e2808e4445564943454944",
            "rawDeviceIdHex surfaces as the hex encoding of the homeserver-original UTF-8 bytes"
        );
        // The hex string itself is ASCII-only, so the JSON cannot
        // carry control bytes through this field.
        for ch in hex_value.chars() {
            assert!(
                ch.is_ascii_hexdigit(),
                "rawDeviceIdHex must be all-ASCII-hex, got {ch:?} in {hex_value}"
            );
        }
    }

    #[test]
    fn test_send_text_queue_full_returns_retryable_delivery_result() {
        let (tx, _rx) = mpsc::channel::<MatrixCommand>(1);
        let (reply_tx, _reply_rx) = std_mpsc::sync_channel(1);
        tx.try_send(MatrixCommand::SendText {
            ctx: OutboundContext {
                to: "!held:example.com".to_string(),
                text: "held".to_string(),
                media_url: None,
                gif_playback: false,
                reply_to_id: None,
                thread_id: None,
                account_id: None,
            },
            reply_tx,
            caller_cancel: CancellationToken::new(),
        })
        .expect("seed full outbound queue");

        let channel = MatrixChannel { tx };
        let delivery = channel
            .send_text(OutboundContext {
                to: "!room:example.com".to_string(),
                text: "hello".to_string(),
                media_url: None,
                gif_playback: false,
                reply_to_id: None,
                thread_id: None,
                account_id: None,
            })
            .expect("queue-full should be retryable DeliveryResult");

        assert!(!delivery.ok);
        assert!(delivery.retryable());
        assert_eq!(
            delivery.retry_after_ms(),
            Some(MATRIX_OUTBOUND_ENQUEUE_RETRY_AFTER.as_millis() as i64)
        );
        assert!(delivery
            .error
            .unwrap_or_default()
            .contains("Matrix outbound queue is full"));
    }

    #[derive(Clone)]
    struct FakeTextSendClient {
        room: Option<FakeTextSendRoom>,
    }

    impl MatrixTextSendClient for FakeTextSendClient {
        type Room = FakeTextSendRoom;

        fn get_text_send_room(&self, _room_id: &RoomId) -> Option<Self::Room> {
            self.room.clone()
        }
    }

    #[derive(Clone)]
    struct FakeTextSendRoom {
        room_id: String,
        supported: bool,
        results:
            Arc<ParkingMutex<std::collections::VecDeque<Result<String, MatrixTextSendFailure>>>>,
        sent_content: Arc<ParkingMutex<Vec<RoomMessageEventContent>>>,
    }

    #[async_trait::async_trait]
    impl MatrixTextSendRoom for FakeTextSendRoom {
        fn room_id_for_delivery(&self) -> String {
            self.room_id.clone()
        }

        fn supported_for_send(&self, encrypted: bool) -> bool {
            encrypted || self.supported
        }

        async fn send_text_content(
            &self,
            content: RoomMessageEventContent,
        ) -> Result<String, MatrixTextSendFailure> {
            self.sent_content.lock().push(content);
            let mut results = self.results.lock();
            assert!(
                !results.is_empty(),
                "fake send result queue is empty; script one result per expected send"
            );
            results
                .pop_front()
                .expect("checked fake result queue is non-empty")
        }
    }

    fn outbound_text_context() -> OutboundContext {
        OutboundContext {
            to: "!room:example.com".to_string(),
            text: "hello".to_string(),
            media_url: None,
            gif_playback: false,
            reply_to_id: None,
            thread_id: None,
            account_id: None,
        }
    }

    // Convenience helper for one-send scenarios. Tests that need multiple
    // sequential send outcomes should construct FakeTextSendRoom directly and
    // seed the VecDeque with one result per expected send.
    fn fake_text_send_client(
        supported: bool,
        result: Result<String, MatrixTextSendFailure>,
    ) -> (
        FakeTextSendClient,
        Arc<ParkingMutex<Vec<RoomMessageEventContent>>>,
    ) {
        let sent_content = Arc::new(ParkingMutex::new(Vec::new()));
        let client = FakeTextSendClient {
            room: Some(FakeTextSendRoom {
                room_id: "!room:example.com".to_string(),
                supported,
                results: Arc::new(ParkingMutex::new(std::collections::VecDeque::from([
                    result,
                ]))),
                sent_content: Arc::clone(&sent_content),
            }),
        };
        (client, sent_content)
    }

    #[test]
    fn test_matrix_room_message_content_preserves_reply_and_thread_relations() {
        use matrix_sdk::ruma::events::room::message::Relation;

        let content = matrix_room_message_content(
            "hello".to_string(),
            Some("$reply:example.com"),
            Some("$thread:example.com"),
        );

        let Some(Relation::Thread(thread)) = content.relates_to.as_ref() else {
            panic!("thread + reply send context must produce a Matrix thread relation");
        };
        assert_eq!(thread.event_id.as_str(), "$thread:example.com");
        assert_eq!(
            thread
                .in_reply_to
                .as_ref()
                .expect("thread reply must include in_reply_to")
                .event_id
                .as_str(),
            "$reply:example.com"
        );
        assert!(
            !thread.is_falling_back,
            "thread replies must not mark the reply relation as a legacy fallback"
        );
    }

    #[test]
    fn test_matrix_room_message_content_preserves_single_relation_shapes() {
        use matrix_sdk::ruma::events::room::message::Relation;

        let thread_only =
            matrix_room_message_content("hello".to_string(), None, Some("$thread:example.com"));
        let Some(Relation::Thread(thread)) = thread_only.relates_to.as_ref() else {
            panic!("thread-only send context must produce a Matrix thread relation");
        };
        assert_eq!(thread.event_id.as_str(), "$thread:example.com");
        assert!(
            thread.in_reply_to.is_none(),
            "thread-only sends must not attach an in_reply_to fallback"
        );
        assert!(
            !thread.is_falling_back,
            "thread-only sends must not set is_falling_back"
        );

        let reply_only =
            matrix_room_message_content("hello".to_string(), Some("$reply:example.com"), None);
        let Some(Relation::Reply { in_reply_to }) = reply_only.relates_to.as_ref() else {
            panic!("reply-only send context must produce a Matrix reply relation");
        };
        assert_eq!(in_reply_to.event_id.as_str(), "$reply:example.com");
    }

    #[test]
    fn test_matrix_room_message_content_ignores_invalid_relation_ids() {
        use matrix_sdk::ruma::events::room::message::Relation;

        let content = matrix_room_message_content(
            "hello".to_string(),
            Some("not-an-event-id"),
            Some("also-not-an-event-id"),
        );

        assert!(
            content.relates_to.is_none(),
            "invalid plugin relation ids must be dropped rather than failing the send"
        );

        let valid_thread_invalid_reply = matrix_room_message_content(
            "hello".to_string(),
            Some("not-an-event-id"),
            Some("$thread:example.com"),
        );
        let Some(Relation::Thread(thread)) = valid_thread_invalid_reply.relates_to.as_ref() else {
            panic!("valid thread ids must survive an invalid reply_to_id");
        };
        assert_eq!(thread.event_id.as_str(), "$thread:example.com");
        assert!(
            thread.in_reply_to.is_none(),
            "invalid reply_to_id must not clobber a valid thread relation"
        );

        let invalid_thread_valid_reply = matrix_room_message_content(
            "hello".to_string(),
            Some("$reply:example.com"),
            Some("not-an-event-id"),
        );
        let Some(Relation::Reply { in_reply_to }) = invalid_thread_valid_reply.relates_to.as_ref()
        else {
            panic!("valid reply_to_id must survive an invalid thread_id");
        };
        assert_eq!(in_reply_to.event_id.as_str(), "$reply:example.com");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_send_matrix_text_from_client_success_uses_fake_room() {
        let (client, sent_content) =
            fake_text_send_client(true, Ok("$event:example.com".to_string()));

        let delivery = send_matrix_text_from_client(
            &client,
            &matrix_test_config(false),
            outbound_text_context(),
        )
        .await
        .expect("fake room send succeeds");

        assert!(delivery.ok);
        assert_eq!(delivery.message_id.as_deref(), Some("$event:example.com"));
        assert_eq!(
            delivery.conversation_id.as_deref(),
            Some("!room:example.com")
        );
        assert_eq!(
            sent_content.lock().len(),
            1,
            "fake room must observe exactly one outbound content payload"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_send_matrix_text_from_client_room_not_found_is_typed() {
        let client = FakeTextSendClient { room: None };

        let err = send_matrix_text_from_client(
            &client,
            &matrix_test_config(false),
            outbound_text_context(),
        )
        .await
        .expect_err("missing room must surface as typed RoomNotFound");

        assert!(
            matches!(err, MatrixError::RoomNotFound(room_id) if room_id == "!room:example.com")
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_send_matrix_text_from_client_invalid_room_id_is_typed() {
        let (client, sent_content) =
            fake_text_send_client(true, Ok("$event:example.com".to_string()));
        let mut ctx = outbound_text_context();
        ctx.to = "not-a-room-id".to_string();

        let err = send_matrix_text_from_client(&client, &matrix_test_config(false), ctx)
            .await
            .expect_err("invalid room ids must fail before room lookup or send");

        assert!(matches!(err, MatrixError::RoomNotFound(room_id) if room_id == "not-a-room-id"));
        assert!(
            sent_content.lock().is_empty(),
            "invalid room ids must not reach the SDK send boundary"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_send_matrix_text_from_client_rejects_unsupported_room_before_send() {
        let (client, sent_content) =
            fake_text_send_client(false, Ok("$event:example.com".to_string()));

        let err = send_matrix_text_from_client(
            &client,
            &matrix_test_config(false),
            outbound_text_context(),
        )
        .await
        .expect_err("unsupported room must fail before the fake send runs");

        assert!(
            matches!(err, MatrixError::UnsupportedRoom(message) if message.contains("!room:example.com"))
        );
        assert!(
            sent_content.lock().is_empty(),
            "unsupported rooms must not reach the SDK send boundary"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_send_matrix_text_from_client_encrypted_config_skips_room_support_gate() {
        let (client, sent_content) =
            fake_text_send_client(false, Ok("$event:example.com".to_string()));

        let delivery = send_matrix_text_from_client(
            &client,
            &matrix_test_config(true),
            outbound_text_context(),
        )
        .await
        .expect("encrypted config must allow the room through the support gate");

        assert!(delivery.ok);
        assert_eq!(delivery.message_id.as_deref(), Some("$event:example.com"));
        assert_eq!(
            sent_content.lock().len(),
            1,
            "encrypted config must reach the SDK send boundary"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_send_matrix_text_from_client_transient_failure_is_retryable_delivery() {
        let (client, _sent_content) = fake_text_send_client(
            true,
            Err(MatrixTextSendFailure::Transient {
                error: "homeserver rate limited".to_string(),
                retry_after_ms: Some(2_500),
            }),
        );

        let delivery = send_matrix_text_from_client(
            &client,
            &matrix_test_config(false),
            outbound_text_context(),
        )
        .await
        .expect("transient room-send failure must stay in DeliveryResult");

        assert!(!delivery.ok);
        assert!(delivery.retryable());
        assert_eq!(delivery.retry_after_ms(), Some(2_500));
        assert_eq!(delivery.error_kind.as_deref(), Some("send-failed"));
        assert_eq!(
            delivery.conversation_id.as_deref(),
            Some("!room:example.com")
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_send_matrix_text_from_client_terminal_failure_surfaces_error() {
        let (client, _sent_content) = fake_text_send_client(
            true,
            Err(MatrixTextSendFailure::Terminal(MatrixError::SendTerminal(
                "M_FORBIDDEN".to_string(),
            ))),
        );

        let err = send_matrix_text_from_client(
            &client,
            &matrix_test_config(false),
            outbound_text_context(),
        )
        .await
        .expect_err("terminal room-send failure must surface as MatrixError");

        assert!(matches!(err, MatrixError::SendTerminal(message) if message == "M_FORBIDDEN"));
    }

    #[test]
    fn test_send_matrix_text_redacts_sdk_error_delivery_result() {
        // This source-pin guard intentionally covers both authoritative
        // transient-send construction sites: the production Room impl redacts
        // SDK errors, and the DeliveryResult helper formats only that redacted
        // binding. Extend this assertion if a new MatrixTextSendFailure::Transient
        // construction site is introduced.
        let room_impl = matrix_rs_fn_body("impl MatrixTextSendRoom for Room");
        let room_impl = room_impl.as_str();
        let delivery = matrix_rs_fn_body("fn matrix_transient_send_delivery_result");
        let delivery = delivery.as_str();
        assert!(
            room_impl.contains("RedactedDisplay(&err).to_string()"),
            "production MatrixTextSendRoom must redact SDK errors before returning transient send failures"
        );
        assert!(
            delivery.contains("Matrix send failed: {error}"),
            "DeliveryResult.error must use the redacted error binding"
        );
        assert!(
            !room_impl.contains("Matrix send failed: {err}")
                && !delivery.contains("Matrix send failed: {err}"),
            "DeliveryResult.error must not interpolate the raw SDK error"
        );
    }

    /// Regression for R58 H-AC2: the terminal-sync shutdown path
    /// must drain `maintenance_tasks` through
    /// `cancel_and_drain_join_set_with_panic_warn`, not
    /// `JoinSet::shutdown().await`. The latter silently consumes
    /// panic JoinErrors, leaving operators with no signal that a
    /// maintenance task panicked during a terminal-shutdown cascade.
    #[test]
    fn test_terminal_sync_shutdown_surfaces_maintenance_panics() {
        let body = matrix_rs_fn_body("async fn run_matrix_runtime");
        assert!(
            !body.contains("maintenance_tasks.shutdown().await"),
            "terminal-sync paths must not consume maintenance JoinSet panics via shutdown().await"
        );
        let mut panic_helper_uses = 0;
        let mut rest = body.as_str();
        let await_suffix = ".await;";
        while let Some(index) = rest.find("cancel_and_drain_join_set_with_panic_warn(") {
            let tail = &rest[index..];
            let call_end = tail
                .find(await_suffix)
                .expect("panic-surfacing helper call must be awaited");
            let call = &tail[..call_end];
            if call.contains("&mut maintenance_tasks")
                && call
                    .contains("\"Matrix maintenance task panicked during terminal sync shutdown\"")
            {
                panic_helper_uses += 1;
            }
            rest = &tail[call_end + await_suffix.len()..];
        }
        assert_eq!(
            panic_helper_uses, 2,
            "both terminal-sync arms (Err(err) and Err(join_err)) must drain maintenance_tasks through the panic-surfacing helper; found {panic_helper_uses} sites"
        );
    }

    #[test]
    fn test_join_set_shutdown_drain_logs_counts_on_timeout() {
        let body = matrix_rs_fn_body("async fn cancel_and_drain_join_set_with_panic_warn");
        let body = body.as_str();
        for field in [
            "initial_count",
            "drained_count",
            "cancelled_count",
            "panic_count",
            "remaining_count",
        ] {
            assert!(
                body.contains(field),
                "shutdown drain timeout log must include {field}"
            );
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_write_owner_only_secret_file_refuses_overwrite() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("secret");
        write_owner_only_secret_file(&path, "old")
            .await
            .expect("initial write");

        let err = write_owner_only_secret_file(&path, "new")
            .await
            .expect_err("overwrite must fail");
        assert!(err.contains("refusing to overwrite"));
        let content = std::fs::read_to_string(&path).expect("read secret");
        assert_eq!(content.trim(), "old");
    }

    #[test]
    fn test_read_matrix_store_passphrase_file_accepts_symlink_to_regular_file() {
        let temp = tempfile::tempdir().expect("tempdir");
        let state_dir = temp.path();
        let real_target = state_dir.join("real-passphrase");
        std::fs::write(&real_target, "secret-passphrase\n").expect("write real target");
        let passphrase_path = matrix_store_passphrase_file_path(state_dir);
        std::fs::create_dir_all(passphrase_path.parent().unwrap()).expect("matrix dir");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&real_target, &passphrase_path).expect("symlink");
        #[cfg(not(unix))]
        {
            // On non-Unix platforms we can't easily test symlinks
            // without elevated privileges; fall back to the direct
            // file path to exercise the same non-symlink code path.
            std::fs::copy(&real_target, &passphrase_path).expect("copy stand-in");
        }

        let value = read_matrix_store_passphrase_file(state_dir)
            .expect("symlink to regular file must be accepted")
            .expect("passphrase present");
        assert_eq!(value.as_str(), "secret-passphrase");
    }

    #[test]
    fn test_read_matrix_store_passphrase_file_rejects_oversize() {
        let temp = tempfile::tempdir().expect("tempdir");
        let state_dir = temp.path();
        let passphrase_path = matrix_store_passphrase_file_path(state_dir);
        std::fs::create_dir_all(passphrase_path.parent().unwrap()).expect("matrix dir");
        let oversize = vec![b'x'; (MATRIX_STORE_PASSPHRASE_FILE_MAX_BYTES as usize) + 1];
        std::fs::write(&passphrase_path, &oversize).expect("write oversize");

        let err = read_matrix_store_passphrase_file(state_dir)
            .expect_err("oversize passphrase file must be rejected by the resolver");
        let MatrixError::EncryptedStateIo(msg) = err else {
            panic!("expected MatrixError::EncryptedStateIo");
        };
        assert!(
            msg.contains("exceeds")
                && msg.contains(&MATRIX_STORE_PASSPHRASE_FILE_MAX_BYTES.to_string()),
            "oversize message must surface the cap: {msg}"
        );
    }

    #[test]
    fn test_read_matrix_store_passphrase_file_rejects_non_regular_file() {
        let temp = tempfile::tempdir().expect("tempdir");
        let state_dir = temp.path();
        let passphrase_path = matrix_store_passphrase_file_path(state_dir);
        // Use a directory at the passphrase path as a stand-in for
        // any non-regular file (FIFO, socket, device). The runtime
        // resolver must refuse to open it; previously
        // `std::fs::read_to_string` on a FIFO would block daemon
        // startup forever.
        std::fs::create_dir_all(&passphrase_path).expect("create dir at passphrase path");

        let err = read_matrix_store_passphrase_file(state_dir)
            .expect_err("non-regular passphrase path must be rejected by the resolver");
        let MatrixError::EncryptedStateIo(msg) = err else {
            panic!("expected MatrixError::EncryptedStateIo");
        };
        assert!(
            msg.contains("regular file"),
            "non-regular-file message must surface the contract: {msg}"
        );
    }

    /// Regression for R58 H-AC1: when the SDK's `send_matrix_text`
    /// has just returned Ok AND a terminal-cause cancel fires in the
    /// same poll round, the send-task `tokio::select!` must NOT
    /// discard the Ok. Discarding it would propagate a typed
    /// terminal cause to the caller, which the dispatch pipeline
    /// would retry — duplicating the already-sent message at the
    /// homeserver. Pins the `biased; result = ...; _ = task_cancel.cancelled(); ...`
    /// ordering used in run_matrix_runtime's SendText arm.
    #[tokio::test(flavor = "current_thread")]
    async fn test_send_task_select_prefers_ok_over_task_cancel_on_tie() {
        use tokio_util::sync::CancellationToken;
        let task_cancel = CancellationToken::new();
        let caller_cancel = CancellationToken::new();
        // Pre-cancel both signals so the cancel arms are ready at
        // the moment the select begins. The send future is also
        // immediately Ready (with Ok). With the broken (cancel-first)
        // ordering the select would take the cancel arm; with the
        // correct (result-first) ordering the Ok wins.
        task_cancel.cancel();
        caller_cancel.cancel();
        let send_fut = std::future::ready(Ok::<String, MatrixError>("delivered".to_string()));

        let result: Result<String, MatrixError> = tokio::select! {
            biased;
            result = send_fut => result,
            _ = task_cancel.cancelled() => Err(MatrixError::NotConnected),
            _ = caller_cancel.cancelled() => Err(MatrixError::SendFailed {
                message: "caller timed out".to_string(),
                retry_after_ms: None,
            }),
        };

        assert_eq!(
            result.expect("Ok must win tie with cancel signals"),
            "delivered"
        );
    }

    /// Companion to the Ok-wins-tie test: when `send_matrix_text` is
    /// still Pending and the cancel fires, the select must promptly
    /// surface the terminal cause. Pins that biased ordering does
    /// not starve cancellation responsiveness.
    #[tokio::test(flavor = "current_thread")]
    async fn test_send_task_select_takes_cancel_when_send_is_pending() {
        use tokio_util::sync::CancellationToken;
        let task_cancel = CancellationToken::new();
        let caller_cancel = CancellationToken::new();
        task_cancel.cancel();
        // The send future is Pending forever — mirrors a stuck SDK
        // future after a terminal cause is stashed.
        let send_fut = std::future::pending::<Result<String, MatrixError>>();

        let result: Result<String, MatrixError> = tokio::select! {
            biased;
            result = send_fut => result,
            _ = task_cancel.cancelled() => Err(MatrixError::NotConnected),
            _ = caller_cancel.cancelled() => Err(MatrixError::SendFailed {
                message: "caller timed out".to_string(),
                retry_after_ms: None,
            }),
        };

        assert!(matches!(result, Err(MatrixError::NotConnected)));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_drain_outbound_replies_to_all_pending_commands() {
        let (tx, mut rx) = mpsc::channel(MATRIX_OUTBOUND_QUEUE_CAPACITY);

        let mut send_receivers = Vec::new();
        for idx in 0..3 {
            let (reply_tx, reply_rx) = std_mpsc::sync_channel(1);
            tx.send(MatrixCommand::SendText {
                ctx: OutboundContext {
                    to: format!("!room{idx}:example.com"),
                    text: "hello".to_string(),
                    media_url: None,
                    gif_playback: false,
                    reply_to_id: None,
                    thread_id: None,
                    account_id: None,
                },
                reply_tx,
                caller_cancel: CancellationToken::new(),
            })
            .await
            .expect("queue send command");
            send_receivers.push(reply_rx);
        }
        let (start_reply_tx, start_reply_rx) = oneshot::channel();
        tx.send(MatrixCommand::StartVerification {
            user_id: "@alice:example.com".to_string(),
            device_id: Some("DEVICE".to_string()),
            reply_tx: start_reply_tx,
            caller_cancel: CancellationToken::new(),
        })
        .await
        .expect("queue verification start command");
        let (action_reply_tx, action_reply_rx) = oneshot::channel();
        tx.send(MatrixCommand::VerificationAction {
            flow_id: "flow".to_string(),
            action: MatrixVerificationAction::Cancel,
            reply_tx: action_reply_tx,
            caller_cancel: CancellationToken::new(),
        })
        .await
        .expect("queue verification action command");

        drain_pending_commands(&mut rx, MatrixError::NotConnected);

        for reply_rx in send_receivers {
            let err = reply_rx
                .recv_timeout(Duration::from_secs(1))
                .expect("shutdown drain should reply")
                .expect_err("shutdown drain should fail pending sends");
            assert!(matches!(err, MatrixError::NotConnected));
        }
        let err = start_reply_rx
            .await
            .expect("shutdown drain should reply to verification start")
            .expect_err("shutdown drain should fail pending verification start");
        assert!(matches!(err, MatrixError::NotConnected));
        let err = action_reply_rx
            .await
            .expect("shutdown drain should reply to verification action")
            .expect_err("shutdown drain should fail pending verification action");
        assert!(matches!(err, MatrixError::NotConnected));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_fail_pending_commands_preserves_startup_error_variant() {
        let (tx, mut rx) = mpsc::channel(MATRIX_OUTBOUND_QUEUE_CAPACITY);
        let (reply_tx, reply_rx) = std_mpsc::sync_channel(1);
        tx.send(MatrixCommand::SendText {
            ctx: OutboundContext {
                to: "!room:example.com".to_string(),
                text: "hello".to_string(),
                media_url: None,
                gif_playback: false,
                reply_to_id: None,
                thread_id: None,
                account_id: None,
            },
            reply_tx,
            caller_cancel: CancellationToken::new(),
        })
        .await
        .expect("queue send command");

        drain_pending_commands(&mut rx, MatrixError::Auth("bad token".to_string()));

        let err = reply_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("startup failure should reply")
            .expect_err("startup failure should fail pending sends");
        assert!(matches!(err, MatrixError::Auth(message) if message == "bad token"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_persist_matrix_session_fails_without_config_password() {
        let _env_state_guard = crate::config::ScopedEnvStateForTest::new();
        let mut env = ScopedEnv::new();
        let temp = tempfile::tempdir().expect("tempdir");
        let config_path = temp.path().join("carapace.json5");
        env.set("CARAPACE_CONFIG_PATH", config_path.as_os_str())
            .unset("CARAPACE_CONFIG_PASSWORD");

        let err = persist_matrix_session("access-token", "DEVICE")
            .await
            .expect_err("session persistence must fail closed without config password");

        assert!(matches!(err, MatrixError::TokenPersistence(_)));
        assert!(!config_path.exists());
    }

    /// Batch 111: `persist_matrix_session` must encrypt the access
    /// token IN THE CALLING FUNCTION (using a snapshot of
    /// CARAPACE_CONFIG_PASSWORD) BEFORE handing the candidate config
    /// off to `seal_config_secrets`. The on-disk value at
    /// `matrix.accessToken` must be `enc:v2:`, not plaintext.
    ///
    /// The prior shape did a preflight `config_password().is_none()`
    /// check and trusted the seal layer to encrypt. Between those
    /// two reads of CARAPACE_CONFIG_PASSWORD, the env could vanish
    /// and the seal would silently early-return Ok, writing
    /// plaintext to disk while believing it was encrypted.
    #[tokio::test(flavor = "current_thread")]
    async fn test_persist_matrix_session_writes_encrypted_access_token() {
        let _env_state_guard = crate::config::ScopedEnvStateForTest::new();
        let mut env = ScopedEnv::new();
        let temp = tempfile::tempdir().expect("tempdir");
        let config_path = temp.path().join("carapace.json5");
        env.set("CARAPACE_CONFIG_PATH", config_path.as_os_str())
            .set("CARAPACE_CONFIG_PASSWORD", "snapshot-test-password");
        std::fs::write(
            &config_path,
            r#"{ matrix: { enabled: true, homeserverUrl: "https://m.example.com", userId: "@a:m" } }"#,
        )
        .expect("seed config");
        crate::config::clear_cache();

        persist_matrix_session("plaintext-access-token", "DEVICE")
            .await
            .expect("persist must succeed when password is present");

        let written = std::fs::read_to_string(&config_path).expect("read config");
        // The on-disk accessToken value must be the enc:v2: shape;
        // the literal plaintext must NOT be present anywhere in the
        // file (a serialized leak via comments/wraps).
        assert!(
            written.contains("\"accessToken\": \"enc:v2:"),
            "matrix.accessToken must be enc:v2: encrypted on disk, got: {written}"
        );
        assert!(
            !written.contains("plaintext-access-token"),
            "plaintext access token must not appear in the on-disk config"
        );

        crate::config::clear_cache();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_remove_persisted_matrix_password_after_token_login() {
        let _env_state_guard = crate::config::ScopedEnvStateForTest::new();
        let mut env = ScopedEnv::new();
        let temp = tempfile::tempdir().expect("tempdir");
        let config_path = temp.path().join("carapace.json5");
        env.set("CARAPACE_CONFIG_PATH", config_path.as_os_str())
            .set("CARAPACE_CONFIG_PASSWORD", "config-password");
        std::fs::write(
            &config_path,
            r#"{
                matrix: {
                    enabled: true,
                    homeserverUrl: "https://matrix.example.com",
                    userId: "@cara:example.com",
                    accessToken: "token",
                    deviceId: "DEVICE",
                    password: "first-login-only",
                    encrypted: false
                }
            }"#,
        )
        .expect("write config");

        remove_persisted_matrix_password()
            .await
            .expect("password removal");

        let raw = std::fs::read_to_string(&config_path).expect("read config");
        assert!(
            !raw.contains("\"password\""),
            "password should be removed after successful token persistence"
        );
        let parsed: Value = json5::from_str(&raw).expect("parse config");
        assert_eq!(parsed["matrix"]["deviceId"], "DEVICE");
        assert!(parsed["matrix"]["accessToken"].as_str().is_some());
        crate::config::clear_cache();
    }

    #[test]
    fn test_backoff_sequence_caps_at_sixty_seconds() {
        let mut backoff = MatrixBackoff::default();
        let values: Vec<u64> = (0..9).map(|_| backoff.next_delay(None).as_secs()).collect();
        assert_eq!(values, vec![1, 2, 4, 8, 16, 32, 60, 60, 60]);
        backoff.reset();
        assert_eq!(backoff.next_delay(None), Duration::from_secs(1));
        assert_eq!(
            backoff.next_delay(Some(Duration::from_secs(120))),
            Duration::from_secs(120)
        );
    }

    /// Pin: the `StartVerification` post-timeout branch returns
    /// `Err(VerificationTimeout)` unconditionally and does NOT
    /// upsert a verification record from inside the arm.
    /// Confirming SAS against an orphan record under a mismatched
    /// flow id is a security-relevant mis-attribution (see the
    /// inline rationale comment in the arm).
    #[test]
    fn test_start_verification_post_timeout_returns_timeout_unconditionally() {
        let body = matrix_rs_fn_body("async fn run_matrix_runtime");
        let body = body.as_str();

        // Locate the StartVerification arm body by anchoring on
        // its match-arm header. The arm runs through the next
        // `Some(MatrixCommand::` (start of the next arm) — bound
        // the search there to avoid matching unrelated text.
        let arm_start = body
            .find("Some(MatrixCommand::StartVerification {")
            .expect("StartVerification arm exists");
        let after_arm = &body[arm_start..];
        let arm_end = after_arm[1..]
            .find("Some(MatrixCommand::")
            .map(|i| i + 1)
            .unwrap_or(after_arm.len());
        let arm = &after_arm[..arm_end];

        // The post-timeout branch must construct a
        // VerificationTimeout. Two literal occurrences are expected:
        // the caller-cancel pre-check and the timeout branch itself
        // (plus possibly the inner select-cancel arm). The pin
        // requires at least 2 to catch a refactor that drops the
        // timeout-branch return.
        let occurrences = arm.matches("MatrixError::VerificationTimeout").count();
        assert!(
            occurrences >= 2,
            "StartVerification arm must construct VerificationTimeout in \
             multiple branches (caller cancel + post-timeout); found \
             {occurrences} occurrence(s) — refactor may have collapsed \
             the timeout branch"
        );

        // The post-timeout branch must NOT call into the existing-
        // record machinery to convert a timeout into an Ok. The
        // refresh helper IS allowed (it only updates pre-existing
        // records, never inserts new ones, and runs detached). What
        // is forbidden is `upsert_verification_record` from the
        // timeout branch — that would create a fresh record under a
        // mismatched flow id.
        //
        // Arm-local check: assert no upsert in the timeout branch's
        // CODE (line comments referencing the helper are fine — they
        // anchor the security rationale). Strip `//` line comments
        // first so a doc-string mention doesn't trigger.
        let arm_code: String = arm
            .lines()
            .map(|line| match line.find("//") {
                Some(idx) => &line[..idx],
                None => line,
            })
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            !arm_code.contains("upsert_verification_record"),
            "StartVerification arm code must not call \
             upsert_verification_record from inside the actor arm body \
             — the project-outcome step handles it from the Ok branch only. \
             Comments referencing the helper are fine; this checks code only."
        );
    }

    /// Pin: the `VerificationAction` post-timeout branch returns
    /// `Err(VerificationTimeout)` and does NOT upsert a record from
    /// inside the arm. Symmetric to the `StartVerification` pin —
    /// the same mis-attribution risk applies (a record matching
    /// `(user_id, device_id)` after a slow accept/confirm/cancel
    /// belongs to a prior flow).
    #[test]
    fn test_verification_action_post_timeout_returns_timeout_unconditionally() {
        let body = matrix_rs_fn_body("async fn run_matrix_runtime");
        let body = body.as_str();

        let arm_start = body
            .find("Some(MatrixCommand::VerificationAction {")
            .expect("VerificationAction arm exists");
        let after_arm = &body[arm_start..];
        let arm_end = after_arm[1..]
            .find("Some(MatrixCommand::")
            .map(|i| i + 1)
            .unwrap_or_else(|| {
                after_arm
                    .find("None => {}")
                    .expect("VerificationAction arm must end before the None terminator")
            });
        let arm = &after_arm[..arm_end];

        let occurrences = arm.matches("MatrixError::VerificationTimeout").count();
        assert!(
            occurrences >= 2,
            "VerificationAction arm must construct VerificationTimeout in \
             multiple branches (caller cancel + post-timeout); found \
             {occurrences} occurrence(s)"
        );

        let arm_code: String = arm
            .lines()
            .map(|line| match line.find("//") {
                Some(idx) => &line[..idx],
                None => line,
            })
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            !arm_code.contains("upsert_verification_record"),
            "VerificationAction arm code must not call \
             upsert_verification_record from inside the actor arm body. \
             Comments referencing the helper are fine; this checks code only."
        );
    }

    /// Direct unit test for `matrix_send_error_to_binding_result`'s
    /// dispatch table. The function routes typed `MatrixError`
    /// variants into either retryable `DeliveryResult` (Ok) or
    /// terminal `BindingError::CallError` / typed runtime-unavailable
    /// errors. This pin asserts
    /// each variant lands in the right bucket so a future "let me
    /// reorganize this match" refactor can't silently flip a
    /// terminal class to retryable (causing the pipeline to spin)
    /// or a retryable class to terminal (causing the pipeline to
    /// drop a recoverable failure on the first attempt).
    #[test]
    fn test_matrix_send_error_to_binding_result_routing() {
        // Retryable bucket: pipeline resets to Queued for retry.
        for err in [
            MatrixError::SendFailed {
                message: "transient".to_string(),
                retry_after_ms: None,
            },
            MatrixError::SyncFailed("transient".to_string()),
            MatrixError::AuthProbe("whoami retry budget exhausted".to_string()),
            MatrixError::NotConnected,
            MatrixError::CommandQueueFull,
        ] {
            let kind = err.kind();
            let result = matrix_send_error_to_binding_result(err);
            match result {
                Ok(delivery) => {
                    assert!(
                        delivery.retryable(),
                        "{kind} must route to a retryable DeliveryResult"
                    );
                    assert!(!delivery.ok);
                }
                Err(other) => panic!("{kind} must route to Ok(retryable), got Err({other})"),
            }
        }
        let send_failed_with_retry_after =
            matrix_send_error_to_binding_result(MatrixError::SendFailed {
                message: "rate limited".to_string(),
                retry_after_ms: Some(2_500),
            })
            .expect("send-failed retry hints should remain delivery results");
        assert_eq!(
            send_failed_with_retry_after.retry_after_ms(),
            Some(2_500),
            "typed SendFailed retry_after_ms must survive binding projection"
        );
        // Terminal bucket: pipeline marks Failed permanently.
        for err in [
            MatrixError::RoomNotFound("room".to_string()),
            MatrixError::UnsupportedRoom("room".to_string()),
            MatrixError::SendTerminal("perm".to_string()),
            MatrixError::StartupFailed("startup".to_string()),
            MatrixError::InterruptedRekey("rekey".to_string()),
            MatrixError::RecoveryKeyRestoreFailed {
                reason: RecoveryRestoreFailureReason::WrongKey,
                detail: "wrong recovery key".to_string(),
            },
            MatrixError::CrossSigningBootstrapFailed("bootstrap".to_string()),
            MatrixError::EncryptedStateIo("operator action".to_string()),
            MatrixError::RecoveryStateProbeFailed("probe".to_string()),
            MatrixError::RecoveryStateIo("state io".to_string()),
            MatrixError::RecoveryConfigPrecondition("config precondition".to_string()),
            MatrixError::RecoveryKeyPromotionRefused("promotion refused".to_string()),
            MatrixError::Clock("clock".to_string()),
            MatrixError::TokenPersistence("persist".to_string()),
            MatrixError::DlqCrypto(DlqCryptoFailure::Other("dlq crypto".to_string())),
            MatrixError::DlqIo("dlq io".to_string()),
            MatrixError::DlqSerialization("dlq serialization".to_string()),
            MatrixError::DlqDispatchFailure("dlq dispatch".to_string()),
            MatrixError::DlqCapSaturation("dlq cap".to_string()),
            MatrixError::LegacyDlqEnvelopeRefused("legacy refused".to_string()),
        ] {
            let kind = err.kind();
            let result = matrix_send_error_to_binding_result(err);
            assert!(
                matches!(result, Err(BindingError::CallError(_))),
                "{kind} must route to terminal Err(CallError)"
            );
        }
        for err in [
            MatrixError::Auth("auth".to_string()),
            MatrixError::AuthTokenRevoked("revoked".to_string()),
        ] {
            let kind = err.kind();
            let result = matrix_send_error_to_binding_result(err);
            assert!(
                matches!(result, Err(BindingError::MatrixRuntimeUnavailable(_))),
                "{kind} must route to typed runtime-unavailable handling"
            );
        }
    }

    #[test]
    fn test_advance_and_classify_matrix_sync_failure_terminal_does_not_consume_retry_state() {
        let state = Arc::new(RwLock::new(MatrixRuntimeState::default()));
        let actor_start = now_millis();
        let mut backoff = MatrixBackoff::default();
        let mut streak = FailureStreak::new(MATRIX_REFRESH_FAILURE_ERROR_THRESHOLD);

        let decision = advance_and_classify_matrix_sync_failure(
            MatrixSyncFailure::Terminal(MatrixError::AuthTokenRevoked(
                "M_UNKNOWN_TOKEN".to_string(),
            )),
            &state,
            actor_start,
            &mut backoff,
            &mut streak,
        );

        match decision {
            MatrixSyncFailureDecision::Terminal(MatrixError::AuthTokenRevoked(message)) => {
                assert_eq!(message, "M_UNKNOWN_TOKEN");
            }
            other => panic!("terminal sync failure must preserve typed cause, got {other:?}"),
        }
        assert_eq!(
            backoff.next_delay(None),
            Duration::from_secs(1),
            "terminal failures must not consume the transient backoff step"
        );
        assert_eq!(
            streak.record_failure(),
            1,
            "terminal failures must not increment the transient failure streak"
        );
    }

    #[test]
    fn test_matrix_sync_failure_constructors_preserve_terminal_paths() {
        let matrix_error = MatrixError::AuthTokenRevoked("M_UNKNOWN_TOKEN".to_string());
        match MatrixSyncFailure::from_matrix_error(&matrix_error) {
            MatrixSyncFailure::Terminal(MatrixError::AuthTokenRevoked(message)) => {
                assert_eq!(message, "M_UNKNOWN_TOKEN");
            }
            other => panic!("from_matrix_error must preserve terminal causes, got {other:?}"),
        }

        // `matrix_sync_terminal_error` has an intentional text
        // fallback for SDK error shapes that do not expose
        // `client_api_error_kind()` (wrapped refresh-token/auth-state
        // failures and panic payloads). `UnknownError` is the public,
        // constructible SDK variant that exercises that fallback; the
        // structured kind table is pinned by the terminal-kind tests.
        let sdk_error = matrix_sdk::Error::UnknownError("M_UNKNOWN_TOKEN".into());
        match MatrixSyncFailure::from_sdk_error(&sdk_error) {
            MatrixSyncFailure::Terminal(MatrixError::AuthTokenRevoked(message)) => {
                assert!(
                    message.contains("M_UNKNOWN_TOKEN"),
                    "SDK terminal fallback must preserve the terminal marker, got {message:?}"
                );
            }
            other => panic!("from_sdk_error must preserve terminal SDK causes, got {other:?}"),
        }
    }

    #[test]
    fn test_matrix_sync_failure_from_matrix_error_transient_preserves_error_without_retry_after() {
        let source = MatrixError::SyncFailed("join transient".to_string());

        let failure = MatrixSyncFailure::from_matrix_error(&source);

        match failure {
            MatrixSyncFailure::Transient {
                stamp_error: MatrixSyncTransientStamp::Error(err),
                retry_after,
            } => {
                assert!(
                    std::ptr::eq(err, &source),
                    "from_matrix_error must borrow below-threshold transients until a sticky stamp is needed"
                );
                let MatrixError::SyncFailed(message) = err else {
                    panic!("expected borrowed SyncFailed stamp, got {err:?}");
                };
                assert_eq!(message, "join transient");
                assert!(
                    retry_after.is_none(),
                    "join-derived MatrixError transients must not invent Retry-After"
                );
            }
            other => panic!(
                "transient MatrixError must stay clone-backed for sticky stamping, got {other:?}"
            ),
        }
    }

    #[test]
    fn test_advance_and_classify_matrix_sync_failure_transient_backs_off_before_sticky() {
        let state = Arc::new(RwLock::new(MatrixRuntimeState::default()));
        let actor_start = now_millis();
        let mut backoff = MatrixBackoff::default();
        let mut streak = FailureStreak::new(MATRIX_REFRESH_FAILURE_ERROR_THRESHOLD);
        let stamp = MatrixError::SyncFailed("transient".to_string());

        let decision = advance_and_classify_matrix_sync_failure(
            MatrixSyncFailure::Transient {
                stamp_error: MatrixSyncTransientStamp::Error(&stamp),
                retry_after: None,
            },
            &state,
            actor_start,
            &mut backoff,
            &mut streak,
        );

        let MatrixSyncFailureDecision::Transient(decision) = decision else {
            panic!("transient sync failure must produce a transient decision");
        };
        assert_eq!(decision.delay, Duration::from_secs(1));
        assert_eq!(decision.streak, 1);
        assert!(!decision.gave_up);
        assert!(
            decision.stamp_error.is_none(),
            "below-threshold transient failures must not stamp Error"
        );
    }

    #[test]
    fn test_matrix_sync_failure_sdk_error_backs_off_before_sticky() {
        let state = Arc::new(RwLock::new(MatrixRuntimeState::default()));
        let actor_start = now_millis();
        let mut backoff = MatrixBackoff::default();
        let mut streak = FailureStreak::new(MATRIX_REFRESH_FAILURE_ERROR_THRESHOLD);
        let sdk_err = matrix_sdk::Error::UnknownError("sdk transient".into());

        let decision = advance_and_classify_matrix_sync_failure(
            MatrixSyncFailure::from_sdk_error(&sdk_err),
            &state,
            actor_start,
            &mut backoff,
            &mut streak,
        );

        let MatrixSyncFailureDecision::Transient(decision) = decision else {
            panic!("below-threshold SDK sync failure must produce a transient decision");
        };
        assert_eq!(decision.delay, Duration::from_secs(1));
        assert_eq!(decision.streak, 1);
        assert!(
            decision.stamp_error.is_none(),
            "below-threshold SDK sync failures must not allocate or stamp SyncFailed"
        );
    }

    #[test]
    fn test_advance_and_classify_matrix_sync_failure_transient_retry_after_sticky_stamp() {
        let state = Arc::new(RwLock::new(MatrixRuntimeState::default()));
        let actor_start = now_millis();
        let mut backoff = MatrixBackoff::default();
        let mut streak = FailureStreak::new(MATRIX_REFRESH_FAILURE_ERROR_THRESHOLD);

        let mut latest = None;
        for idx in 0..MATRIX_REFRESH_FAILURE_ERROR_THRESHOLD {
            let stamp = MatrixError::SyncFailed(format!("transient {idx}"));
            latest = Some(advance_and_classify_matrix_sync_failure(
                MatrixSyncFailure::Transient {
                    stamp_error: MatrixSyncTransientStamp::Error(&stamp),
                    retry_after: Some(Duration::from_secs(42)),
                },
                &state,
                actor_start,
                &mut backoff,
                &mut streak,
            ));
        }

        let MatrixSyncFailureDecision::Transient(decision) =
            latest.expect("threshold loop must produce a decision")
        else {
            panic!("transient sync failure must produce a transient decision");
        };
        assert_eq!(
            decision.delay,
            Duration::from_secs(42),
            "homeserver Retry-After must drive transient sync delay"
        );
        assert_eq!(decision.streak, MATRIX_REFRESH_FAILURE_ERROR_THRESHOLD);
        assert!(!decision.gave_up);
        let expected = format!("transient {}", MATRIX_REFRESH_FAILURE_ERROR_THRESHOLD - 1);
        assert!(
            matches!(
                decision.stamp_error,
                Some(MatrixError::SyncFailed(ref message)) if message == &expected
            ),
            "sticky transient sync must stamp the supplied transient error, got {:?}",
            decision.stamp_error
        );
    }

    #[test]
    fn test_matrix_sync_failure_sdk_error_sticky_stamp_is_redacted_sync_failed() {
        let state = Arc::new(RwLock::new(MatrixRuntimeState::default()));
        let actor_start = now_millis();
        let mut backoff = MatrixBackoff::default();
        let mut streak = FailureStreak::new(MATRIX_REFRESH_FAILURE_ERROR_THRESHOLD);
        for _ in 1..MATRIX_REFRESH_FAILURE_ERROR_THRESHOLD {
            streak.record_failure();
        }
        let sdk_err = matrix_sdk::Error::UnknownError("sdk transient".into());

        let decision = advance_and_classify_matrix_sync_failure(
            MatrixSyncFailure::from_sdk_error(&sdk_err),
            &state,
            actor_start,
            &mut backoff,
            &mut streak,
        );

        let MatrixSyncFailureDecision::Transient(decision) = decision else {
            panic!("transient SDK sync failure must produce a transient decision");
        };
        assert_eq!(decision.streak, MATRIX_REFRESH_FAILURE_ERROR_THRESHOLD);
        assert!(
            matches!(
                decision.stamp_error,
                Some(MatrixError::SyncFailed(ref message)) if message.contains("sdk transient")
            ),
            "sticky SDK sync transient must convert through RedactedDisplay into SyncFailed, got {:?}",
            decision.stamp_error
        );
    }

    #[test]
    fn test_advance_and_classify_matrix_sync_failure_give_up_overrides_sticky_stamp() {
        let state = Arc::new(RwLock::new(MatrixRuntimeState::default()));
        let now = now_millis();
        let actor_start = now - MATRIX_SYNC_GIVE_UP_THRESHOLD_MS - 2000;
        state.write().status.last_successful_sync_at =
            Some(now - MATRIX_SYNC_GIVE_UP_THRESHOLD_MS - 1000);
        let mut backoff = MatrixBackoff::default();
        let mut streak = FailureStreak::new(MATRIX_REFRESH_FAILURE_ERROR_THRESHOLD);
        for _ in 1..MATRIX_REFRESH_FAILURE_ERROR_THRESHOLD {
            streak.record_failure();
        }
        let stamp = MatrixError::SyncFailed("sticky should not win".to_string());

        let decision = advance_and_classify_matrix_sync_failure(
            MatrixSyncFailure::Transient {
                stamp_error: MatrixSyncTransientStamp::Error(&stamp),
                retry_after: None,
            },
            &state,
            actor_start,
            &mut backoff,
            &mut streak,
        );

        let MatrixSyncFailureDecision::Transient(decision) = decision else {
            panic!("transient sync failure must produce a transient decision");
        };
        assert_eq!(
            decision.streak, MATRIX_REFRESH_FAILURE_ERROR_THRESHOLD,
            "test setup must make the transient streak sticky before proving give-up wins"
        );
        assert_eq!(decision.delay, MATRIX_SYNC_GIVE_UP_RETRY_INTERVAL);
        assert!(decision.gave_up);
        assert!(
            matches!(
                decision.stamp_error,
                Some(MatrixError::SyncLoopGaveUp { idle_ms })
                    if idle_ms > MATRIX_SYNC_GIVE_UP_THRESHOLD_MS
            ),
            "give-up decision must stamp SyncLoopGaveUp, got {:?}",
            decision.stamp_error
        );
    }

    /// Direct unit test for `classify_sync_giveup` (the actor-loop
    /// helper extracted in commit 86eff85). The static-analysis pin
    /// above asserts the wiring; this test asserts the actual
    /// decision boundaries: idle below threshold → Backoff; idle
    /// above threshold → GaveUp; missing `last_successful_sync_at`
    /// falls back to `actor_started_at_ms`.
    #[test]
    fn test_classify_sync_giveup_decision_boundaries() {
        let runtime_state = Arc::new(parking_lot::RwLock::new(MatrixRuntimeState::default()));
        let backoff_delay = Duration::from_secs(60);

        // Case 1: never synced (`last_successful_sync_at = None`),
        // actor started just now → idle_ms ≈ 0 → Backoff.
        runtime_state.write().status.last_successful_sync_at = None;
        let actor_start = now_millis();
        let decision = classify_sync_giveup(&runtime_state, actor_start, backoff_delay);
        assert!(
            matches!(decision, SyncBackoffDecision::Backoff { .. }),
            "fresh actor start should classify as Backoff"
        );
        assert_eq!(decision.delay(), backoff_delay);
        assert!(!decision.gave_up());

        // Case 2: never synced, actor started long ago → idle past
        // threshold → GaveUp.
        let stale_actor_start = now_millis() - MATRIX_SYNC_GIVE_UP_THRESHOLD_MS - 1000;
        let decision = classify_sync_giveup(&runtime_state, stale_actor_start, backoff_delay);
        assert!(
            matches!(decision, SyncBackoffDecision::GaveUp { .. }),
            "actor started past threshold without successful sync should classify as GaveUp"
        );
        assert_eq!(decision.delay(), MATRIX_SYNC_GIVE_UP_RETRY_INTERVAL);
        assert!(decision.gave_up());

        // Case 3: recent successful sync → idle ≈ 0 even with
        // stale actor_start → Backoff (`last_successful_sync_at`
        // takes precedence over the actor_start fallback).
        runtime_state.write().status.last_successful_sync_at = Some(now_millis() - 1000);
        let decision = classify_sync_giveup(&runtime_state, stale_actor_start, backoff_delay);
        assert!(
            matches!(decision, SyncBackoffDecision::Backoff { .. }),
            "recent successful sync overrides stale actor_start fallback"
        );

        // Case 4: stale `last_successful_sync_at` past threshold →
        // GaveUp.
        let stale_sync_at = now_millis() - MATRIX_SYNC_GIVE_UP_THRESHOLD_MS - 500;
        runtime_state.write().status.last_successful_sync_at = Some(stale_sync_at);
        let decision = classify_sync_giveup(&runtime_state, stale_actor_start, backoff_delay);
        assert!(
            matches!(decision, SyncBackoffDecision::GaveUp { .. }),
            "stale last_successful_sync_at past threshold should classify as GaveUp"
        );

        // Case 5: corrupt or pre-start sentinel timestamps must not
        // give up immediately on a fresh actor. Treat them as absent
        // and use the actor-start baseline instead.
        runtime_state.write().status.last_successful_sync_at = Some(0);
        let actor_start = now_millis();
        let decision = classify_sync_giveup(&runtime_state, actor_start, backoff_delay);
        assert!(
            matches!(decision, SyncBackoffDecision::Backoff { .. }),
            "pre-start sync timestamp sentinel should fall back to actor start"
        );
    }

    /// Pin: both sync-failure arms route through the owned
    /// `advance_and_classify_matrix_sync_failure` seam, and that seam routes
    /// transient failures through `classify_sync_giveup` and stamps
    /// `SyncLoopGaveUp` on the `GaveUp` decision. Catches a refactor
    /// that moves one arm back to ad hoc classification or drops the
    /// typed give-up stamp.
    #[test]
    fn test_run_matrix_runtime_sync_give_up_wiring_pinned() {
        let body = matrix_rs_fn_body("async fn run_matrix_runtime");
        let body = body.as_str();
        let sync_failure_helper = matrix_rs_fn_body("fn advance_and_classify_matrix_sync_failure");
        let sync_failure_helper = sync_failure_helper.as_str();
        let helper = matrix_rs_fn_body("fn classify_sync_giveup");
        let helper = helper.as_str();

        assert!(
            body.contains("actor_started_at_ms = now_millis()"),
            "run_matrix_runtime must capture an actor-start baseline so \
             give-up triggers even when last_successful_sync_at is None"
        );
        let sdk_sync_arm = body
            .split_once("Some(Ok(Err(err))) =>")
            .and_then(|(_, tail)| tail.split_once("Some(Err(join_err)) =>"))
            .map(|(arm, _)| arm)
            .expect("run_matrix_runtime must keep the SDK sync-error arm before join-error arm");
        let join_sync_arm = body
            .split_once("Some(Err(join_err)) =>")
            .and_then(|(_, tail)| tail.split_once("None => {}"))
            .map(|(arm, _)| arm)
            .expect(
                "run_matrix_runtime must keep the join-error arm before the sync select fallback",
            );
        let call_count = body
            .matches("advance_and_classify_matrix_sync_failure(")
            .count();
        assert_eq!(
            call_count, 2,
            "both sync-failure arms must call advance_and_classify_matrix_sync_failure; \
             found {call_count} call(s)"
        );
        assert!(
            sdk_sync_arm.contains("advance_and_classify_matrix_sync_failure(")
                && sdk_sync_arm.contains("MatrixSyncFailure::from_sdk_error(&err)"),
            "SDK sync-error arm must route directly through the advancing classifier"
        );
        assert!(
            join_sync_arm.contains("advance_and_classify_matrix_sync_failure(")
                && join_sync_arm.contains("MatrixSyncFailure::from_matrix_error(&err)"),
            "sync task join-error arm must route directly through the advancing classifier"
        );
        assert!(
            sync_failure_helper.contains("classify_sync_giveup("),
            "advance_and_classify_matrix_sync_failure must own give-up classification"
        );
        assert!(
            sync_failure_helper.contains("MatrixError::SyncLoopGaveUp"),
            "advance_and_classify_matrix_sync_failure must stamp SyncLoopGaveUp on GaveUp"
        );
        assert!(
            helper.contains("MATRIX_SYNC_GIVE_UP_THRESHOLD_MS"),
            "classify_sync_giveup must compare against the 24h threshold"
        );
        assert!(
            helper.contains("MATRIX_SYNC_GIVE_UP_RETRY_INTERVAL"),
            "classify_sync_giveup must override the delay with the give-up interval"
        );
        assert!(
            helper.contains(".filter(|value| *value >= actor_started_at_ms)"),
            "classify_sync_giveup must ignore pre-start sentinel timestamps"
        );
        // Polarity pin: the comparison must be `>` (strict), not
        // `>=`. With `>=`, a sync that succeeds exactly at 24h
        // would still classify as GaveUp on a subsequent failed
        // tick. The strict form means the trigger is "more than
        // 24h", matching the doc comment "After 24 hours."
        assert!(
            helper.contains("idle_ms > MATRIX_SYNC_GIVE_UP_THRESHOLD_MS"),
            "classify_sync_giveup must use strict `>` comparison; a flip to `>=` \
             trips at exactly 24h, breaking the documented contract"
        );
        // Threshold pin: a future refactor that "rounds" to
        // 86_400 (seconds) silently shortens the threshold by 1000x.
        assert_eq!(MATRIX_SYNC_GIVE_UP_THRESHOLD_MS, 24 * 60 * 60 * 1000);
        assert_eq!(
            MATRIX_SYNC_GIVE_UP_RETRY_INTERVAL,
            Duration::from_secs(60 * 60)
        );
    }

    /// `InterruptedRekey` MUST render with its own prefix so operators
    /// can route `cara status` errors to the rekey-recovery procedure
    /// rather than a generic startup retry. The exact-string assertion
    /// also pins the `{0}` formatter — a struct-shaped variant rewrite
    /// would compile-fail at the constructor.
    #[test]
    fn test_matrix_error_interrupted_rekey_display() {
        let interrupted = MatrixError::InterruptedRekey("rekey aborted".into()).to_string();
        assert_eq!(interrupted, "Matrix store rekey interrupted: rekey aborted");
    }

    #[cfg(unix)]
    #[test]
    fn test_matrix_rekey_marker_probe_uses_recovery_state_io_kind() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;

        let invalid_path = Path::new(OsStr::from_bytes(b"bad\0path"));
        let err = matrix_rekey_path_exists(
            invalid_path,
            "Matrix store rekey marker",
            MatrixError::RecoveryStateIo,
        )
        .expect_err("invalid marker path must surface the configured error kind");
        assert!(
            matches!(err, MatrixError::RecoveryStateIo(_)),
            "rekey marker stat failures must route as recovery-state-io, got {err:?}"
        );
    }

    /// `record_inbound_dlq_lost_event_ids` is append-and-truncate-front:
    /// the cap retains the MOST RECENT entries, so a torrent of
    /// failures still leaves the operator with the latest IDs they can
    /// act on. The `drain(0..(total - cap))` direction is exactly the
    /// kind of off-by-one a refactor could silently invert; pin it.
    #[test]
    fn test_record_inbound_dlq_lost_event_ids_keeps_latest_at_cap() {
        let mut state = MatrixRuntimeState::default();
        let ids: Vec<String> = (0..40).map(|i| format!("$evt{i}:example.com")).collect();
        state.record_inbound_dlq_lost_event_ids(ids);
        let kept = &state.status.inbound_dlq_lost_event_ids;
        assert_eq!(kept.len(), MATRIX_INBOUND_DLQ_LOST_IDS_CAP);
        // Cap is 32; with 40 inserts, the oldest 8 are drained from the
        // front. Most recent ID must survive at the tail.
        assert_eq!(
            kept.first().map(String::as_str),
            Some("$evt8:example.com"),
            "drain direction must keep the latest 32 IDs, not the first 32"
        );
        assert_eq!(kept.last().map(String::as_str), Some("$evt39:example.com"));
    }

    /// `clear_inbound_dlq_lost_event_ids` drops the entire list once a
    /// subsequent replay tick succeeds. Without this, a single
    /// transient phase-3 hiccup pins stale IDs on `cara status` for the
    /// daemon's lifetime.
    #[test]
    fn test_clear_inbound_dlq_lost_event_ids_drops_all() {
        let mut state = MatrixRuntimeState::default();
        state.record_inbound_dlq_lost_event_ids(["$a:x".to_string(), "$b:x".to_string()]);
        assert_eq!(state.status.inbound_dlq_lost_event_ids.len(), 2);
        state.clear_inbound_dlq_lost_event_ids();
        assert!(state.status.inbound_dlq_lost_event_ids.is_empty());
    }

    /// The invite-systemic-error marker must round-trip and clear.
    /// `handle_invites` clears it on a sub-threshold tick so the channel
    /// can recover when invite handling partially succeeds; without the
    /// clear path, the channel would stay in Error indefinitely after
    /// `apply_post_sync_maintenance`'s Ok-arm calls
    /// `clear_invite_systemic_failure` on a fully-clean tick;
    /// `handle_invites` no longer clears on sub-threshold ticks (so
    /// the channel correctly stays in Error during partial-recovery
    /// ticks). This unit test pins the state-method round-trip;
    /// integration with `handle_invites` is exercised separately.
    #[test]
    fn test_invite_systemic_record_then_clear_round_trip() {
        let mut state = MatrixRuntimeState::default();
        assert!(state.invite_systemic_error().is_none());
        state.record_invite_systemic_failure("5 of 5 invites failed".into());
        assert_eq!(state.invite_systemic_error(), Some("5 of 5 invites failed"));
        state.clear_invite_systemic_failure();
        assert!(
            state.invite_systemic_error().is_none(),
            "clear must drop the marker so a subsequent fully-clean tick can transition the channel back to Connected"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_handle_invites_fake_sdk_allowlist_and_encryption_paths() {
        let allowed =
            FakeInviteRoom::new("!allowed:example.com", Some("@alice:example.com"), false);
        let rejected = FakeInviteRoom::new(
            "!rejected\x1b[31m:example.com",
            Some("@mallory:evil.com"),
            false,
        );
        let encrypted =
            FakeInviteRoom::new("!encrypted:example.com", Some("@alice:example.com"), true);
        let source = FakeInviteSource {
            rooms: vec![allowed.clone(), rejected.clone(), encrypted.clone()],
        };
        let config = matrix_test_config(false);
        let state = Arc::new(RwLock::new(MatrixRuntimeState::default()));

        handle_invites_from_source(&source, &config, &state)
            .await
            .expect("non-failing fake invite operations must succeed");

        assert_eq!(allowed.join_count(), 1, "allowlisted invite must join");
        assert_eq!(
            allowed.leave_count(),
            0,
            "allowlisted invite must not leave"
        );
        assert_eq!(
            rejected.join_count(),
            0,
            "non-allowlisted invite must not join"
        );
        assert_eq!(
            rejected.leave_count(),
            1,
            "non-allowlisted invite must be rejected"
        );
        assert_eq!(
            encrypted.join_count(),
            0,
            "definitely encrypted invite must not join when matrix.encrypted=false"
        );
        assert_eq!(
            encrypted.leave_count(),
            1,
            "definitely encrypted invite must be rejected when matrix.encrypted=false"
        );

        let status = state.read().status();
        assert_eq!(status.peer_drop_allowlist_rejection_total, 1);
        assert_eq!(status.peer_drop_encrypted_room_total, 1);
        assert!(
            state.read().invite_systemic_error().is_none(),
            "successful leave/join operations must not stamp a systemic invite error"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_handle_invites_fake_sdk_systemic_failures_stamp_state() {
        let source = FakeInviteSource {
            rooms: vec![
                FakeInviteRoom::inspect_error("!one:example.com", "inspect 500"),
                FakeInviteRoom::inspect_error("!two:example.com", "inspect 501"),
                FakeInviteRoom::inspect_error("!three:example.com", "inspect 502"),
            ],
        };
        let config = matrix_test_config(false);
        let state = Arc::new(RwLock::new(MatrixRuntimeState::default()));

        let err = handle_invites_from_source(&source, &config, &state)
            .await
            .expect_err("threshold fake failures must surface as invite handling failure");
        assert!(
            err.to_string()
                .starts_with("Matrix sync failed: Matrix invite handling failures (3):"),
            "invite handler must return the aggregate failure shape: {err}"
        );
        let marker = state
            .read()
            .invite_systemic_error()
            .expect("threshold fake failures must stamp systemic marker")
            .to_string();
        assert!(
            marker.starts_with("Matrix invite handling: 3 failures in one maintenance tick:"),
            "systemic marker must carry the operator-facing failure count: {marker}"
        );
        assert!(
            marker.contains("!one:example.com inspect failed: inspect 500"),
            "systemic marker must include the sanitized first failure preview: {marker}"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_handle_invites_fake_sdk_leave_and_join_failures_stamp_state() {
        let reject_leave = FakeInviteRoom::new(
            "!reject-leave:example.com",
            Some("@mallory:evil.com"),
            false,
        )
        .with_leave_error("reject EIO");
        let encrypted_leave = FakeInviteRoom::new(
            "!encrypted-leave:example.com",
            Some("@alice:example.com"),
            true,
        )
        .with_leave_error("encrypted EIO");
        let join_failure = FakeInviteRoom::new(
            "!join-failure:example.com",
            Some("@alice:example.com"),
            false,
        )
        .with_join_error("join EIO");
        let source = FakeInviteSource {
            rooms: vec![
                reject_leave.clone(),
                encrypted_leave.clone(),
                join_failure.clone(),
            ],
        };
        let config = matrix_test_config(false);
        let state = Arc::new(RwLock::new(MatrixRuntimeState::default()));

        let err = handle_invites_from_source(&source, &config, &state)
            .await
            .expect_err("scripted leave/join failures must surface as invite handling failure");
        assert!(
            err.to_string()
                .starts_with("Matrix sync failed: Matrix invite handling failures (3):"),
            "leave/join failures must return the aggregate failure shape: {err}"
        );
        assert_eq!(reject_leave.leave_count(), 1);
        assert_eq!(encrypted_leave.leave_count(), 1);
        assert_eq!(join_failure.join_count(), 1);

        let marker = state
            .read()
            .invite_systemic_error()
            .expect("threshold leave/join failures must stamp systemic marker")
            .to_string();
        assert!(
            marker.contains("!reject-leave:example.com reject failed: reject EIO"),
            "allowlist leave failure must feed the systemic failure preview: {marker}"
        );
        assert!(
            marker.contains("!encrypted-leave:example.com encrypted reject failed: encrypted EIO"),
            "encrypted-room leave failure must feed the systemic failure preview: {marker}"
        );
        assert!(
            marker.contains("!join-failure:example.com join failed: join EIO"),
            "join failure must feed the systemic failure preview: {marker}"
        );
    }

    /// Sanitizer must strip control bytes, bidi/zero-width
    /// formatting, combining marks (so `D` + U+0301 doesn't visually
    /// duplicate `D`, defeating SAS-confirm), and TAG codepoints
    /// (invisible in most terminals so they carry hidden bytes
    /// through copy-paste). Output is byte-bounded to 255 bytes —
    /// NOT char-bounded — so 4-byte emoji can't yield 1020 bytes.
    #[test]
    fn test_sanitize_homeserver_identifier_strips_dangerous_classes() {
        // ANSI escape + SOFT HYPHEN + bidi override + combining acute
        // + a TAG codepoint (U+E0041 = TAG LATIN SMALL LETTER A) +
        // Variation Selector-16 (U+FE0F, emoji presentation selector
        // — used to disguise ASCII as a different visual glyph) +
        // Variation Selectors Supplement (U+E0100, ideographic
        // variation selector) + legitimate ASCII.
        let input = "Alice\x1b[31m\u{00AD}\u{202E}D\u{0301}\u{E0041}\u{FE0F}X\u{E0100}EVIL";
        let out = sanitize_homeserver_identifier(input);
        // Expected: ESC, SOFT HYPHEN, bidi override, combining acute,
        // TAG codepoint, both Variation Selectors all gone. Plain
        // `D`, `X`, and `EVIL` survive ([31m is rendered literally).
        assert_eq!(out, "Alice[31mDXEVIL");
    }

    #[test]
    fn test_sanitize_matrix_user_id_for_operator_strips_zwsp_spoof() {
        assert_eq!(
            sanitize_matrix_user_id_for_operator("@ali\u{200b}ce:example.com").as_str(),
            "@alice:example.com"
        );
    }

    #[test]
    fn test_sanitize_matrix_user_id_for_operator_hashes_invalid_fallback() {
        let first = sanitize_matrix_user_id_for_operator("\u{200b}");
        let second = sanitize_matrix_user_id_for_operator("\u{200c}");
        assert!(first.as_str().starts_with("@invalid-"));
        assert!(first.as_str().ends_with(":carapace.invalid"));
        assert!(second.as_str().starts_with("@invalid-"));
        assert!(second.as_str().ends_with(":carapace.invalid"));
        assert_ne!(first, second);
    }

    #[test]
    fn test_sanitize_homeserver_identifier_byte_caps_at_255() {
        // 100 4-byte emoji = 400 bytes if char-counted, way past
        // Matrix v11+ event_id 255-byte limit.
        let input: String = std::iter::repeat_n('\u{1F600}', 100).collect();
        let out = sanitize_homeserver_identifier(&input);
        assert!(
            out.len() <= 255,
            "byte length must be ≤ 255, got {}",
            out.len()
        );
        // Output must be a valid UTF-8 prefix (no truncated codepoint).
        assert_eq!(out.chars().count() * 4, out.len());
    }

    #[test]
    fn test_decode_raw_device_id_hex_preserves_control_bytes() {
        let raw = "DEV\u{0007}ICE";
        let encoded = hex::encode(raw.as_bytes());
        assert_eq!(decode_raw_device_id_hex(&encoded).unwrap(), raw);
        assert!(decode_raw_device_id_hex("abc").is_err());
        assert!(decode_raw_device_id_hex("").is_err());
    }

    /// `MatrixError::InterruptedRekey`'s Display starts with a
    /// stable, operator-greppable prefix. Operator runbooks and the
    /// CLI's typed-arm routing are designed around the prefix shape;
    /// a copy-edit of the message that drops the leading
    /// "Matrix store rekey interrupted:" anchor would silently break
    /// those consumers.
    #[test]
    fn test_matrix_error_interrupted_rekey_display_prefix_is_stable() {
        let err = MatrixError::InterruptedRekey(
            "pending-marker on disk without canonical passphrase".to_string(),
        );
        let msg = err.to_string();
        assert!(
            msg.starts_with("Matrix store rekey interrupted:"),
            "InterruptedRekey Display prefix must remain stable for operator runbooks: got `{msg}`"
        );
    }

    /// Drive 3 consecutive bad-event_id failures through the
    /// runtime-state inbound-streak path and assert the streak
    /// becomes sticky AND `pending_inbound_error` carries the
    /// caller's message. This pins the atomic
    /// `record_inbound_failure_with_error` contract: a refactor
    /// that calls bare `record_inbound_failure()` (without stamping
    /// the error message) would let
    /// `apply_post_sync_maintenance` observe (sticky=true,
    /// pending=None) and surface a generic "consecutive failures
    /// threshold reached" message instead of the actual cause.
    #[test]
    fn test_record_inbound_failure_with_error_stamps_error_when_sticky() {
        let state = Arc::new(RwLock::new(MatrixRuntimeState::default()));
        let mut guard = state.write();
        // Each call records a failure; the streak goes sticky at
        // its `MATRIX_INBOUND_FAILURE_STREAK_THRESHOLD` (3).
        guard.record_inbound_failure_with_error(
            "bad event_id #1: empty".to_string(),
            "session-history-corrupt",
        );
        guard.record_inbound_failure_with_error(
            "bad event_id #2: control bytes".to_string(),
            "session-history-corrupt",
        );
        guard.record_inbound_failure_with_error(
            "bad event_id #3: oversized".to_string(),
            "session-history-corrupt",
        );
        assert!(
            guard.inbound_streak_is_sticky(),
            "3 consecutive bad-event_id failures must trip the sticky streak"
        );
        assert_eq!(
            guard.pending_inbound_error(),
            Some("bad event_id #3: oversized"),
            "pending_inbound_error must carry the LATEST error message when sticky; \
             a regression that bare-bumps the streak would leave this None and \
             apply_post_sync_maintenance would surface a generic message"
        );
        assert_eq!(
            guard.pending_inbound_error_kind(),
            Some("session-history-corrupt"),
            "pending inbound failures must retain their typed routing kind"
        );
    }

    /// Static-analysis pin for `handle_invites`: a non-allowlisted
    /// inviter must always leave the invited room and continue the
    /// loop before any join path can run. The SDK-heavy integration
    /// fixture belongs with the fake-client seam; this pin catches
    /// the local refactor class where the gate is loosened or the
    /// `continue` is dropped.
    #[test]
    fn test_handle_invites_gates_on_allowlist_pin() {
        fn matching_closing_brace(source: &str, open_brace_idx: usize) -> usize {
            let mut depth = 0usize;
            for (relative_idx, ch) in source[open_brace_idx..].char_indices() {
                match ch {
                    '{' => depth += 1,
                    '}' => {
                        depth = depth.checked_sub(1).expect("brace depth underflow");
                        if depth == 0 {
                            return open_brace_idx + relative_idx;
                        }
                    }
                    _ => {}
                }
            }
            panic!("allowlist rejection arm must have a matching closing brace");
        }

        let body = matrix_rs_fn_body("async fn handle_invites_from_source");
        let body = body.as_str();
        assert!(
            body.contains("config.auto_join.allows_user(user_id)"),
            "handle_invites_from_source must evaluate the raw inviter against the auto-join allowlist"
        );
        assert!(
            body.contains("if !allowed {"),
            "handle_invites_from_source must branch on the allowlist decision before attempting joins"
        );
        assert!(
            body.contains("Matrix invite rejected by auto-join allowlist"),
            "allowlist rejection must remain operator-visible"
        );
        assert!(
            body.contains("room.leave_invite().await"),
            "non-allowlisted invites must be rejected via room.leave_invite()"
        );
        let allowlist_gate = body
            .find("if !allowed {")
            .expect("allowlist rejection arm must exist");
        let rejection_open = allowlist_gate
            + body[allowlist_gate..]
                .find('{')
                .expect("allowlist rejection arm must open with a brace");
        let rejection_close = matching_closing_brace(body, rejection_open);
        let encrypted_room_gate = body[allowlist_gate..]
            .find("if !config.encrypted()")
            .map(|idx| allowlist_gate + idx)
            .expect("encrypted-room gate must follow allowlist rejection");
        assert!(
            rejection_close < encrypted_room_gate,
            "allowlist rejection arm must close before encrypted-room handling; \
             move this source-shape pin with any refactor that nests config.encrypted() in the arm"
        );
        let rejection_arm = &body[rejection_open..rejection_close];
        let leave_idx = rejection_arm
            .find("room.leave_invite().await")
            .expect("allowlist rejection arm must leave the room");
        let continue_idx = rejection_arm
            .rfind("continue;")
            .expect("allowlist rejection arm must continue before later handling");
        assert!(
            leave_idx < continue_idx,
            "allowlist rejection must leave the room before continuing"
        );
        assert!(
            !rejection_arm.contains("room.join_invite().await"),
            "allowlist rejection arm must not join the room"
        );
    }
}
