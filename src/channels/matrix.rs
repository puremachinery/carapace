//! Native Matrix / Element channel runtime.
//!
//! Matrix is stateful: the runtime owns the SDK client, encrypted store state,
//! sync loop, invite policy, and the bounded outbound actor used by the
//! synchronous channel plugin contract.

use std::collections::BTreeSet;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicBool, AtomicI64, Ordering},
    mpsc as std_mpsc, Arc,
};
use std::time::Duration;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hkdf::Hkdf;
use matrix_sdk::config::SyncSettings;
use matrix_sdk::encryption::verification::{SasState, SasVerification, VerificationRequestState};
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
use sha2::Sha256;
use thiserror::Error;
use tokio::sync::{mpsc, oneshot, watch, Notify};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use crate::channels::{ChannelMetadata, ChannelRegistry, ChannelStatus};
use crate::plugins::{
    BindingError, ChannelCapabilities, ChannelInfo as PluginChannelInfo, ChannelPluginInstance,
    ChatType, DeliveryResult, OutboundContext,
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
const MATRIX_INBOUND_DLQ_INFO: &[u8] = b"carapace-matrix-inbound-dlq-v1";
// AAD for the AES-GCM seal of DLQ records. Note: this string lacks the
// `carapace-` application prefix that `MATRIX_STORE_INFO` and
// `MATRIX_INBOUND_DLQ_INFO` carry. The prefix omission was the original
// shape committed and is now locked in: the AAD is part of the GCM
// authentication tag of every on-disk DLQ record, so changing the
// constant value is a wire-format break that would invalidate every
// existing encrypted DLQ. A future v2 envelope can adopt the
// `carapace-` prefix; until then, this departure is intentional.
const MATRIX_INBOUND_DLQ_AAD: &[u8] = b"matrix-inbound-dlq-v1";
/// On-disk envelope version for `MatrixEncryptedInboundDlqRecord`.
/// Bumping the codec (new field, different encoding, different AAD)
/// requires bumping this AND the decode-time gate together. Pinning a
/// named constant keeps writer and reader in sync — two raw `1` literals
/// at separate sites would let one drift silently and either reject our
/// own DLQ records or silently mis-decode them with stale params.
const MATRIX_INBOUND_DLQ_ENVELOPE_VERSION: u8 = 1;
const MATRIX_OUTBOUND_QUEUE_CAPACITY: usize = 128;
/// Maximum inbound Matrix message body size (bytes) before the
/// runtime drops the event with a warn. A peer in any joined room
/// can otherwise send a 100 MB body, which gets cloned through the
/// session log, the agent prompt, and (on dispatch failure) the
/// DLQ record. 64 KiB is well above any sane chat usage and below
/// the homeserver's typical event-size limit.
const MATRIX_INBOUND_BODY_MAX_BYTES: usize = 64 * 1024;
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
            .finish()
    }
}

impl MatrixConfig {
    /// Whether the runtime should treat this channel as Matrix-encrypted
    /// (E2EE rooms supported). Mirrors the historical `encrypted: bool`
    /// for read-side compatibility.
    pub fn encrypted(&self) -> bool {
        matches!(self.security, MatrixSecurity::Encrypted { .. })
    }
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
         deactivated/locked, or suspended. accessToken-configured: mint a new \
         token, run `cara config set matrix.accessToken <new>` and \
         `cara config set matrix.deviceId <new>`, then restart the daemon. \
         password-configured: verify the password is correct and restart)"
    )]
    AuthTokenRevoked(String),
    #[error("failed to persist Matrix access token: {0}")]
    TokenPersistence(String),
    #[error("Matrix E2EE setup failed: {0}")]
    E2ee(String),
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
    #[error("Matrix send failed: {0}")]
    SendFailed(String),
    #[error("Matrix sync failed: {0}")]
    SyncFailed(String),
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
            MatrixError::MissingHomeserverUrl => "missing-homeserver-url",
            MatrixError::MissingUserId => "missing-user-id",
            MatrixError::MissingCredentials => "missing-credentials",
            MatrixError::MissingDeviceIdForTokenRestore => "missing-device-id-for-token-restore",
            MatrixError::MissingStoreSecret => "missing-store-secret",
            MatrixError::StoreKeyDerivation => "store-key-derivation",
            MatrixError::InstallationId(_) => "installation-id",
            MatrixError::ClientBuild(_) => "client-build",
            MatrixError::Auth(_) => "auth",
            MatrixError::AuthSessionUserMismatch { .. } => "auth-session-user-mismatch",
            MatrixError::AuthSessionDeviceMismatch { .. } => "auth-session-device-mismatch",
            MatrixError::AuthSessionMissingDeviceId => "auth-session-missing-device-id",
            MatrixError::AuthTokenRevoked(_) => "auth-token-revoked",
            MatrixError::TokenPersistence(_) => "token-persistence",
            MatrixError::E2ee(_) => "e2ee",
            MatrixError::StartupFailed(_) => "startup-failed",
            MatrixError::InterruptedRekey(_) => "interrupted-rekey",
            MatrixError::Clock(_) => "clock",
            MatrixError::NotConnected => "not-connected",
            MatrixError::UnsupportedRoom(_) => "unsupported-room",
            MatrixError::RoomNotFound(_) => "room-not-found",
            MatrixError::SendFailed(_) => "send-failed",
            MatrixError::SyncFailed(_) => "sync-failed",
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
}

/// One inbound Matrix event parked on the dead-letter queue after a
/// dispatch failure. The `text` field holds *decrypted* room body text
/// when the source room is encrypted, so:
///
/// 1. `Debug` is hand-rolled to elide the body — a stray
///    `tracing::debug!(?record, ...)` would otherwise print E2EE
///    plaintext into stdout/journal/`RedactingWriter` (which only
///    matches OAuth/bearer/recovery-key shapes, not free-form text).
/// 2. `Drop` zeroizes `text` on the way out so a leaked heap allocation
///    cannot be recovered with a memory inspector.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct MatrixInboundDlqRecord {
    event_id: String,
    room_id: String,
    sender_id: String,
    text: String,
    received_at: i64,
}

impl std::fmt::Debug for MatrixInboundDlqRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MatrixInboundDlqRecord")
            .field("event_id", &self.event_id)
            .field("room_id", &self.room_id)
            .field("sender_id", &self.sender_id)
            .field("text", &format_args!("<elided {} bytes>", self.text.len()))
            .field("received_at", &self.received_at)
            .finish()
    }
}

impl Drop for MatrixInboundDlqRecord {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        // event_id / room_id / sender_id are PII (e.g. `@alice:example.com`,
        // `!room:server.tld`). Zeroize all four fields so a heap inspector or
        // post-free reuse cannot recover them. Defense-in-depth: clones made
        // by the dispatch path do not inherit this Drop, so the heap window
        // is shorter for the record itself than for any in-flight clones.
        self.event_id.zeroize();
        self.room_id.zeroize();
        self.sender_id.zeroize();
        self.text.zeroize();
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct MatrixEncryptedInboundDlqRecord {
    version: u8,
    nonce: String,
    ciphertext: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MatrixDeviceInfo {
    pub user_id: String,
    pub device_id: String,
    /// Sanitized peer-controlled display name, or absent if the device
    /// has no display name. `skip_serializing_if = Option::is_none`
    /// matches the convention on `MatrixVerificationInfo.sas` and on
    /// `device_id`: omit-when-absent rather than emit `null`, since
    /// JS/TS clients treat the two differently in optional chaining.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    pub verified: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MatrixVerificationInfo {
    /// Opaque daemon-owned verification id used by the control API.
    pub flow_id: String,
    /// Matrix protocol flow / transaction id.
    pub protocol_flow_id: String,
    pub user_id: String,
    /// Device id of the peer being verified, or absent when the
    /// protocol flow targets the user without a specific device.
    /// `skip_serializing_if = Option::is_none` matches the convention
    /// on `sas` below: omit-when-absent rather than emit `null`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
    pub state: MatrixVerificationState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sas: Option<MatrixSasInfo>,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MatrixSasInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub emoji: Option<Vec<MatrixSasEmoji>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decimals: Option<[u16; 3]>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MatrixSasEmoji {
    pub symbol: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MatrixVerificationState {
    Created,
    Requested,
    Ready,
    Transitioned,
    Started,
    Accepted,
    KeysExchanged,
    Confirmed,
    Done,
    Cancelled,
    Mismatched,
}

impl MatrixVerificationState {
    fn is_terminal(&self) -> bool {
        matches!(self, Self::Cancelled | Self::Done | Self::Mismatched)
    }

    /// Snake_case form matching the wire `state` field
    /// (`#[serde(rename_all = "snake_case")]`). Use this when
    /// embedding the state in operator-visible error messages so
    /// `cara matrix verifications` JSON values round-trip-grep
    /// against the error string.
    fn as_wire_str(&self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::Requested => "requested",
            Self::Ready => "ready",
            Self::Transitioned => "transitioned",
            Self::Started => "started",
            Self::Accepted => "accepted",
            Self::KeysExchanged => "keys_exchanged",
            Self::Confirmed => "confirmed",
            Self::Done => "done",
            Self::Cancelled => "cancelled",
            Self::Mismatched => "mismatched",
        }
    }
}

impl std::fmt::Display for MatrixVerificationState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_wire_str())
    }
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
}

impl Default for MatrixRuntimeState {
    fn default() -> Self {
        Self {
            status: MatrixStatusMetadata::default(),
            devices: Vec::new(),
            verifications: Vec::new(),
            inbound_streak: FailureStreak::new(MATRIX_REFRESH_FAILURE_ERROR_THRESHOLD),
            pending_inbound_error: None,
            pending_invite_systemic_error: None,
            dlq_io_lock: Arc::new(tokio::sync::Mutex::new(())),
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
    fn record_inbound_failure_with_error(&mut self, error: String) -> u32 {
        let count = self.inbound_streak.record_failure();
        // Only stamp the error once we're sticky — sub-threshold
        // failures stay in the streak counter (so they decay) but
        // don't surface to the operator yet.
        if self.inbound_streak.is_sticky() {
            self.pending_inbound_error = Some(error);
        }
        count
    }

    fn reset_inbound_failures(&mut self) {
        self.inbound_streak.record_success();
        self.pending_inbound_error = None;
    }

    fn pending_inbound_error(&self) -> Option<&str> {
        self.pending_inbound_error.as_deref()
    }

    fn record_inbound_dlq_append_failure(&mut self, error: String) {
        self.status.inbound_dlq_append_failure_total = self
            .status
            .inbound_dlq_append_failure_total
            .saturating_add(1);
        self.status.inbound_dlq_durability_error = Some(error);
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
        self.status.inbound_dlq_lost_event_ids.extend(ids);
        let total = self.status.inbound_dlq_lost_event_ids.len();
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
    fn clear_inbound_dlq_lost_event_ids(&mut self) {
        self.status.inbound_dlq_lost_event_ids.clear();
    }

    /// Clear the operator-visible DLQ durability error after a
    /// successful append or replay. Without this, a single transient
    /// disk hiccup pins the channel in Error state for the rest of the
    /// daemon's lifetime even when every subsequent DLQ operation
    /// succeeds. The cumulative `inbound_dlq_append_failure_total`
    /// counter remains so historical durability incidents stay
    /// auditable.
    fn clear_inbound_dlq_durability_error(&mut self) {
        self.status.inbound_dlq_durability_error = None;
    }

    fn inbound_durability_error_is_sticky(&self) -> bool {
        self.status.inbound_dlq_durability_error.is_some()
    }

    fn inbound_dlq_durability_error(&self) -> Option<&str> {
        self.status.inbound_dlq_durability_error.as_deref()
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
    pub fn channel(&self) -> MatrixChannel {
        MatrixChannel {
            tx: self.tx.clone(),
        }
    }

    pub fn status(&self) -> MatrixStatusMetadata {
        self.state.read().status()
    }

    pub fn devices(&self) -> Vec<MatrixDeviceInfo> {
        self.state.read().devices()
    }

    pub fn verifications(&self) -> Vec<MatrixVerificationInfo> {
        prune_verification_records(&self.state);
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
                return Ok(matrix_retryable_delivery_result(format!(
                    "Matrix outbound queue is full; retrying in {} seconds",
                    MATRIX_OUTBOUND_ENQUEUE_RETRY_AFTER.as_secs()
                )));
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                return Err(BindingError::CallError(
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
            Err(std_mpsc::RecvTimeoutError::Disconnected) => Err(BindingError::CallError(
                "Matrix runtime stopped before send completed".to_string(),
            )),
        }
    }

    fn send_media(&self, _ctx: OutboundContext) -> Result<DeliveryResult, BindingError> {
        Err(BindingError::CallError(
            "Matrix media delivery is not supported".to_string(),
        ))
    }
}

fn matrix_send_error_to_binding_result(err: MatrixError) -> Result<DeliveryResult, BindingError> {
    match err {
        MatrixError::SendFailed(message)
        | MatrixError::SyncFailed(message)
        | MatrixError::StartupFailed(message)
        | MatrixError::InterruptedRekey(message) => Ok(matrix_retryable_delivery_result(message)),
        MatrixError::NotConnected => Ok(matrix_retryable_delivery_result(
            "Matrix runtime is not connected".to_string(),
        )),
        MatrixError::CommandQueueFull => Ok(matrix_retryable_delivery_result(
            "Matrix runtime command queue is full; retry shortly".to_string(),
        )),
        MatrixError::RoomNotFound(room) => Err(BindingError::CallError(format!(
            "Matrix room not found: {room}"
        ))),
        MatrixError::UnsupportedRoom(message) => Err(BindingError::CallError(message)),
        // Terminal send classes — homeserver has declared the failure
        // permanent for this token+room. Retrying issues an identical
        // request and earns an identical rejection; route as a
        // non-retryable CallError so the dispatch pipeline records
        // the failure once and stops.
        MatrixError::SendTerminal(message) => Err(BindingError::CallError(message)),
        other => Err(BindingError::CallError(other.to_string())),
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

    let user_id = read_string(matrix, "userId")?
        .or_else(|| crate::config::read_config_env("MATRIX_USER_ID"))
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .ok_or(MatrixError::MissingUserId)?;

    let access_token = read_string(matrix, "accessToken")?
        .or_else(|| crate::config::read_config_env("MATRIX_ACCESS_TOKEN"))
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .map(zeroize::Zeroizing::new);
    let password = read_string(matrix, "password")?
        .or_else(|| crate::config::read_config_env("MATRIX_PASSWORD"))
        .filter(|value| !value.trim().is_empty())
        .map(zeroize::Zeroizing::new);
    if access_token.is_none() && password.is_none() {
        return Err(MatrixError::MissingCredentials);
    }
    let device_id = read_string(matrix, "deviceId")?
        .or_else(|| crate::config::read_config_env("MATRIX_DEVICE_ID"))
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
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
    }))
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
    let mut out = BTreeSet::new();
    for value in values {
        let Some(value) = value.as_str() else {
            return Err(MatrixError::InvalidStringArray { field });
        };
        let trimmed = value.trim();
        if !trimmed.is_empty() {
            out.insert(trimmed.to_string());
        }
    }
    Ok(out)
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
            if !final_path.exists() && (pending.exists() || marker.exists()) {
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
                return Ok(Some(zeroize::Zeroizing::new(passphrase)));
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

fn read_matrix_store_passphrase_file(state_dir: &Path) -> Result<Option<String>, MatrixError> {
    let path = matrix_store_passphrase_file_path(state_dir);
    let value = match std::fs::read_to_string(&path) {
        Ok(value) => value,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => {
            return Err(MatrixError::E2ee(format!(
                "failed to read Matrix store passphrase file {}: {err}",
                path.display()
            )))
        }
    };
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(MatrixError::E2ee(format!(
            "Matrix store passphrase file {} is empty",
            path.display()
        )));
    }
    Ok(Some(trimmed.to_string()))
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

fn read_existing_installation_id(path: &Path) -> Result<Option<String>, MatrixError> {
    let value = std::fs::read_to_string(path)
        .map_err(|err| MatrixError::InstallationId(err.to_string()))?;
    let trimmed = value.trim();
    if trimmed.is_empty() {
        Ok(None)
    } else {
        Ok(Some(trimmed.to_string()))
    }
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
        let mut options = std::fs::OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(&tmp)
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

    let client = match build_authenticated_client(&config, &state_dir).await {
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
                    error = %join_err,
                    "Matrix outbound send task panicked while reaping finished tasks"
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
                sync_client.sync_once(settings).await
            });
        }

        tokio::select! {
            changed = shutdown_rx.changed() => {
                if changed.is_ok() && *shutdown_rx.borrow() {
                    shutdown_matrix_runtime_actor(
                        &channel_registry,
                        &mut sync_tasks,
                        &mut maintenance_tasks,
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
                            let _ = reply_tx.send(Err(MatrixError::SendFailed(
                                "Matrix send caller timed out before dispatch".to_string(),
                            )));
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
                                let result = tokio::select! {
                                    biased;
                                    _ = caller_cancel.cancelled() => {
                                        Err(MatrixError::SendFailed(
                                            "Matrix send caller timed out before dispatch".to_string(),
                                        ))
                                    }
                                    _ = task_cancel.cancelled() => {
                                        let cause = task_terminal_cause
                                            .lock()
                                            .clone()
                                            .unwrap_or(MatrixError::NotConnected);
                                        Err(cause)
                                    }
                                    result = send_matrix_text(send_client, &send_config, ctx) => result,
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
                                    result = start_matrix_verification(
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
                                tokio::spawn(async move {
                                    let refresh_result = tokio::time::timeout(
                                        MATRIX_VERIFICATION_COMMAND_TIMEOUT,
                                        refresh_verification_records(
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
                                    crate::server::ws::broadcast_matrix_verification_updated(
                                        &ws_state,
                                        crate::server::ws::UpdatedVerificationFlow::for_state_change(
                                            &outcome.info,
                                        ),
                                    );
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
                                    result = apply_verification_action(
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
                                tokio::spawn(async move {
                                    if let Err(refresh_err) = bounded_verification_refresh(
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
                        if let Some(permanent) = matrix_sync_terminal_error(&err) {
                            stamp_matrix_runtime_error(&channel_registry, &state, &permanent);
                            // Permanent errors stop the runtime — typically
                            // M_UNKNOWN_TOKEN (revoked credential) or
                            // matrix-store decryption failure. Both are
                            // operator-must-act conditions. Error level so
                            // monitoring sees the daemon transition to a
                            // terminal Matrix state.
                            tracing::error!(error = %err, "Matrix sync failed with permanent error; stopping runtime");
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
                            maintenance_tasks.shutdown().await;
                            drain_pending_commands(&mut rx, permanent);
                            return;
                        }
                        let retry_after = matrix_retry_after(&err);
                        let delay = backoff.next_delay(retry_after);
                        next_sync_after = Some(tokio::time::Instant::now() + delay);
                        let streak = maintenance_streaks.transient_sync.record_failure();
                        if maintenance_streaks.transient_sync.is_sticky() {
                            stamp_matrix_runtime_error_message(
                                &channel_registry,
                                &state,
                                crate::logging::redact::RedactedDisplay(&err).to_string(),
                            );
                        }
                        warn!(
                            error = %err,
                            delay_ms = delay.as_millis(),
                            consecutive_failures = streak,
                            "Matrix sync failed; backing off"
                        );
                    }
                    Some(Err(err)) => {
                        maintenance_streaks.consecutive_clean_syncs = 0;
                        let delay = backoff.next_delay(None);
                        next_sync_after = Some(tokio::time::Instant::now() + delay);
                        let err = MatrixError::SyncFailed(format!("Matrix sync task failed: {err}"));
                        let streak = maintenance_streaks.transient_sync.record_failure();
                        if maintenance_streaks.transient_sync.is_sticky() {
                            stamp_matrix_runtime_error(&channel_registry, &state, &err);
                        }
                        warn!(
                            error = %err,
                            delay_ms = delay.as_millis(),
                            consecutive_failures = streak,
                            "Matrix sync task failed; backing off"
                        );
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
                            error = %join_err,
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
        // maintenance phases don't touch it; bind via `..` to keep
        // the destructure exhaustive without the ownership shuffle.
        transient_sync: _,
        consecutive_clean_syncs,
    } = streaks;
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
            if invite_streak.is_sticky() || invite_systemic {
                stamp_matrix_runtime_error(channel_registry, state, &err);
            }
        }
    }
    match verification {
        Ok(_) => record_phase_recovery("verification-refresh", verification_refresh),
        Err(err) => {
            let count = verification_refresh.record_failure();
            warn!(
                error = %err,
                failures = count,
                "failed to refresh Matrix verification records"
            );
            if verification_refresh.is_sticky() {
                stamp_matrix_runtime_error_message(
                    channel_registry,
                    state,
                    format!(
                        "Matrix verification refresh failing: {}",
                        crate::logging::redact::RedactedDisplay(&err)
                    ),
                );
            }
        }
    }
    match device {
        Ok(()) => record_phase_recovery("device-refresh", device_refresh),
        Err(err) => {
            let count = device_refresh.record_failure();
            warn!(error = %err, failures = count, "failed to refresh Matrix device state");
            if device_refresh.is_sticky() {
                stamp_matrix_runtime_error_message(
                    channel_registry,
                    state,
                    format!(
                        "Matrix device refresh failing: {}",
                        crate::logging::redact::RedactedDisplay(&err)
                    ),
                );
            }
        }
    }
    match dlq_outcome {
        Ok(()) => record_phase_recovery("inbound-dlq-replay", dlq_replay),
        Err(err) => {
            let count = dlq_replay.record_failure();
            warn!(error = %err, failures = count, "failed to replay Matrix inbound DLQ");
            if dlq_replay.is_sticky() {
                stamp_matrix_runtime_error_message(
                    channel_registry,
                    state,
                    format!(
                        "Matrix inbound DLQ replay failing: {}",
                        crate::logging::redact::RedactedDisplay(&err)
                    ),
                );
            }
        }
    }
    match runtime_status {
        Ok(()) => record_phase_recovery("runtime-status", runtime_status_streak),
        Err(err) => {
            let count = runtime_status_streak.record_failure();
            warn!(error = %err, failures = count, "failed to refresh Matrix runtime status");
            if runtime_status_streak.is_sticky() {
                stamp_matrix_runtime_error_message(
                    channel_registry,
                    state,
                    format!(
                        "Matrix runtime status refresh failing: {}",
                        crate::logging::redact::RedactedDisplay(&err)
                    ),
                );
            }
        }
    }
    let non_inbound_sticky = invite_streak.is_sticky()
        || verification_refresh.is_sticky()
        || device_refresh.is_sticky()
        || dlq_replay.is_sticky()
        || runtime_status_streak.is_sticky()
        || {
            let guard = state.read();
            guard.inbound_durability_error_is_sticky() || guard.invite_systemic_error().is_some()
        };
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
        let durability_or_systemic = {
            let guard = state.read();
            guard
                .inbound_dlq_durability_error()
                .map(|s| format!("Matrix inbound DLQ durability: {s}"))
                .or_else(|| {
                    guard
                        .invite_systemic_error()
                        .map(|err| format!("Matrix invite systemic failure: {err}"))
                })
        };
        if let Some(message) = durability_or_systemic {
            stamp_matrix_runtime_error_message(channel_registry, state, message);
        }
    } else {
        *consecutive_clean_syncs = consecutive_clean_syncs.saturating_add(1);
        // Decay the inbound counter so a sticky inbound failure in a
        // low-traffic room doesn't pin the channel in Error indefinitely.
        // Other counters reset every iteration via their match Ok arms;
        // inbound resets only on inbound success and so needs a separate
        // sync-driven path.
        if *consecutive_clean_syncs >= MATRIX_INBOUND_DECAY_SYNC_COUNT {
            state.write().reset_inbound_failures();
        }
        // Reconcile inbound state into the registry under a single read.
        // The room-message handler stamps `pending_inbound_error` on
        // sticky failures rather than writing the registry directly —
        // doing so eliminates the race where a maintenance recovery
        // could overwrite an inbound's Error. This is the only site
        // that translates inbound state into channel-registry status.
        // `record_inbound_failure_with_error` is the only writer that
        // sets `pending_inbound_error`, and it stamps Some(error)
        // atomically with the streak bump that flips `is_sticky` true.
        // So `(sticky=true, pending=None)` is unreachable and we can
        // collapse the cases.
        let inbound_snapshot = {
            let guard = state.read();
            guard
                .inbound_streak_is_sticky()
                .then(|| guard.pending_inbound_error().map(str::to_string))
                .flatten()
        };
        match inbound_snapshot {
            Some(error) => {
                stamp_matrix_runtime_error_message(channel_registry, state, error);
                debug!(
                    clean_syncs = *consecutive_clean_syncs,
                    "Matrix inbound dispatch error remains sticky until decay threshold"
                );
            }
            None => {
                mark_matrix_channel_connected(channel_registry, state);
            }
        }
    }
    update_channel_registry_metadata(channel_registry, state);
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
        refresh_verification_records(client.clone(), &state, &ws_state),
    )
    .await;
    let device = bounded_matrix_result(
        "Matrix device refresh",
        refresh_device_state(client.clone(), &config, &state),
    )
    .await;
    let dlq_replay = bounded_matrix_result(
        "Matrix inbound DLQ replay",
        replay_matrix_inbound_dlq(&state_dir, &config, ws_state.clone(), state.clone()),
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

async fn shutdown_matrix_runtime_actor(
    channel_registry: &ChannelRegistry,
    sync_tasks: &mut tokio::task::JoinSet<Result<SyncResponse, matrix_sdk::Error>>,
    maintenance_tasks: &mut tokio::task::JoinSet<PostSyncMaintenanceOutcomes>,
    send_cancel: &CancellationToken,
    send_tasks: &mut tokio::task::JoinSet<()>,
    rx: &mut mpsc::Receiver<MatrixCommand>,
) {
    channel_registry.update_status(MATRIX_CHANNEL_ID, ChannelStatus::Disconnected);
    // No typed cause for clean shutdown; in-flight tasks resolve as
    // `NotConnected`, matching queued-command drain semantics.
    send_cancel.cancel();
    sync_tasks.shutdown().await;
    drain_join_set_with_panic_warn(sync_tasks, "Matrix sync task panicked during shutdown").await;
    // Maintenance phases hold short-lived locks but no caller-facing
    // reply channels; aborting mid-phase is safe because each phase is
    // a snapshot reconciliation that the next sync iteration can redo.
    // A panic mid-maintenance during shutdown — which could indicate
    // corruption or torn state — must not be silenced by
    // `JoinSet::shutdown`. Drain join_next afterwards and warn-log
    // any JoinError so the panic shows up in the operator's log.
    maintenance_tasks.shutdown().await;
    drain_join_set_with_panic_warn(
        maintenance_tasks,
        "Matrix maintenance task panicked during shutdown",
    )
    .await;
    drain_cancelled_send_tasks(send_tasks).await;
    drain_pending_commands(rx, MatrixError::NotConnected);
}

/// Drain a `JoinSet` after `shutdown().await` and warn-log any
/// `JoinError` (panic or cancellation surfaced as error). The
/// `shutdown()` call cancels and awaits each task; this loop iterates
/// the resolved results so panic context is operator-visible rather
/// than silently dropped.
async fn drain_join_set_with_panic_warn<T: 'static>(
    tasks: &mut tokio::task::JoinSet<T>,
    label: &'static str,
) {
    while let Some(joined) = tasks.join_next().await {
        if let Err(join_err) = joined {
            // We don't differentiate panic vs cancellation here; the
            // shutdown path that called us already cancelled the
            // tasks, so any non-Ok at this point is panic-flavoured
            // information worth surfacing.
            warn!(error = %join_err, "{label}");
        }
    }
}

async fn bounded_verification_refresh(
    client: Arc<Client>,
    state: &Arc<RwLock<MatrixRuntimeState>>,
    ws_state: &Arc<WsServerState>,
) -> Result<(), MatrixError> {
    bounded_matrix_result(
        "Matrix verification refresh",
        refresh_verification_records(client, state, ws_state),
    )
    .await
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
                            error = %join_err,
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
) -> Result<Client, MatrixError> {
    let store_dir = state_dir.join("matrix");
    let cache_dir = store_dir.join("cache");
    tokio::fs::create_dir_all(&store_dir)
        .await
        .map_err(|err| MatrixError::ClientBuild(err.to_string()))?;
    // Lock the matrix subtree to owner-only on Unix — defense in
    // depth so a multi-user host's other accounts cannot copy the
    // encrypted SQLite blob, recovery key file, or installation_id
    // for offline brute force on CARAPACE_CONFIG_PASSWORD.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(err) =
            tokio::fs::set_permissions(&store_dir, std::fs::Permissions::from_mode(0o700)).await
        {
            tracing::warn!(
                path = %store_dir.display(),
                error = %err,
                "failed to set 0o700 on Matrix state subdirectory; continuing with default perms"
            );
        }
    }
    let store_passphrase = resolve_matrix_store_passphrase(state_dir, config)?;
    // `as_deref()` on `Option<Zeroizing<String>>` yields `Option<&Zeroizing<String>>`;
    // map to `Option<&str>` for the matrix-sdk API. The `Zeroizing` wrapper
    // is held by `store_passphrase` for the duration of this scope.
    let sqlite_config = SqliteStoreConfig::new(&store_dir)
        .passphrase(store_passphrase.as_deref().map(|p| p.as_str()));
    let client = Client::builder()
        .homeserver_url(&config.homeserver_url)
        .sqlite_store_with_config_and_cache_path(sqlite_config, Some(cache_dir))
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
        maybe_restore_recovery_key(&client, config, state_dir, &session).await?;
        maybe_bootstrap_cross_signing(
            &client,
            config,
            config.password.as_deref().map(|s| s.as_str()),
            state_dir,
            &session,
        )
        .await?;
        return Ok(client);
    }

    let password = config
        .password
        .as_deref()
        .ok_or(MatrixError::MissingCredentials)?;
    preflight_matrix_session_persistence()?;
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
        if let Some(typed) = matrix_sync_terminal_error(&err) {
            typed
        } else {
            MatrixError::Auth(err.to_string())
        }
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
        MatrixError::Auth(format!(
            "Matrix user ID became unparseable after login: {err}"
        ))
    })?;
    let session = ValidatedMatrixSession {
        user_id,
        device_id: response.device_id.clone(),
        _proof: (),
    };
    maybe_restore_recovery_key(&client, config, state_dir, &session).await?;
    maybe_bootstrap_cross_signing(&client, config, Some(password), state_dir, &session).await?;
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
        .map_err(|err| MatrixError::Auth(format!("invalid Matrix user ID: {err}")))?;
    let device_id: OwnedDeviceId = device_id.into();
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
        if let Some(typed) = matrix_sync_terminal_error(&err) {
            typed
        } else {
            MatrixError::Auth(err.to_string())
        }
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

async fn maybe_bootstrap_cross_signing(
    client: &Client,
    config: &MatrixConfig,
    password: Option<&str>,
    state_dir: &Path,
    session: &ValidatedMatrixSession,
) -> Result<(), MatrixError> {
    if !config.encrypted() {
        return Ok(());
    }
    let Err(err) = client
        .encryption()
        .bootstrap_cross_signing_if_needed(None)
        .await
    else {
        maybe_enable_recovery(client, config, state_dir, session).await?;
        return Ok(());
    };
    let Some(response) = err.as_uiaa_response() else {
        return Err(MatrixError::E2ee(format!(
            "cross-signing bootstrap failed before UIA: {err}"
        )));
    };
    let Some(password) = password else {
        return Err(MatrixError::E2ee(
            "cross-signing bootstrap requires password UIA; provide matrix.password or MATRIX_PASSWORD once".to_string(),
        ));
    };
    // Use the validated user_id from the witness instead of re-parsing
    // `config.user_id`. Re-reading config between validation and
    // bootstrap is a TOCTOU window where a config mutation mid-flow
    // would let bootstrap run for a different user than was just
    // validated.
    let mut auth = matrix_sdk::ruma::api::client::uiaa::Password::new(
        matrix_sdk::ruma::api::client::uiaa::UserIdentifier::UserIdOrLocalpart(
            session.user_id.to_string(),
        ),
        password.to_string(),
    );
    auth.session = response.session.clone();
    client
        .encryption()
        .bootstrap_cross_signing(Some(
            matrix_sdk::ruma::api::client::uiaa::AuthData::Password(auth),
        ))
        .await
        .map_err(|err| {
            // The post-UIA bootstrap call still hits the homeserver,
            // and a homeserver that revokes / locks the account
            // between password verification and bootstrap returns a
            // typed terminal class. Preserve the typed
            // `AuthTokenRevoked` so the operator-facing rekey hint
            // routes through `verify_matrix_outcome`'s typed arm.
            if let Some(typed) = matrix_sync_terminal_error(&err) {
                typed
            } else {
                MatrixError::E2ee(format!("cross-signing bootstrap failed after UIA: {err}"))
            }
        })?;
    maybe_enable_recovery(client, config, state_dir, session).await
}

async fn maybe_restore_recovery_key(
    client: &Client,
    config: &MatrixConfig,
    state_dir: &Path,
    _session: &ValidatedMatrixSession,
) -> Result<(), MatrixError> {
    // The witness is required to call this function — its presence in
    // the signature is what gates recovery-key restore behind a
    // validated session. The body itself doesn't read the witness's
    // user_id/device_id because the `recover` SDK call doesn't take
    // them; the type-level guard is the entire point.
    if !config.encrypted() {
        return Ok(());
    }
    let path = matrix_recovery_key_path(state_dir);
    // Wrap the raw file read in Zeroizing BEFORE any further processing
    // so the un-trimmed source allocation (which may include trailing
    // newline / whitespace bytes that are NOT in the trimmed slice) is
    // wiped on drop. A plain String would leave the recovery-key bytes
    // in heap memory until the allocator reclaims them — long enough on
    // a daemon-startup path to be observable in a coredump.
    let recovery_key_raw = match tokio::fs::read_to_string(&path).await {
        Ok(recovery_key) => zeroize::Zeroizing::new(recovery_key),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(err) => {
            return Err(MatrixError::E2ee(format!(
                "failed to read Matrix recovery key from {}: {err}",
                path.display()
            )));
        }
    };
    let recovery_key = recovery_key_raw.trim();
    if recovery_key.is_empty() {
        return Err(MatrixError::E2ee(format!(
            "Matrix recovery key file {} is empty",
            path.display()
        )));
    }
    client
        .encryption()
        .recovery()
        .recover(recovery_key)
        .await
        .map_err(|err| {
            // matrix-sdk's `RecoveryError` is a distinct type from
            // `matrix_sdk::Error`, so the symmetric peel pattern used
            // by `whoami_with_bounded_retry`,
            // `restore_matrix_session`, and `build_authenticated_client`
            // does not type-check here: there is no
            // `client_api_error_kind()` on `RecoveryError`. The
            // practical exposure is narrow because this site runs
            // AFTER `validate_restored_matrix_session`'s whoami
            // (which already verified the token), so an
            // `M_UNKNOWN_TOKEN` returned by `recover()` would require
            // a sub-second token revocation between whoami-success
            // and the recover call. Operators who do hit it see a
            // generic E2ee message and fall through to the recover-
            // path docs. If the SDK exposes a typed kind on
            // `RecoveryError` in a future version, route through
            // `AuthTokenRevoked` here for parity.
            MatrixError::E2ee(format!(
                "Matrix recovery-key restore failed from {}: {err}",
                path.display()
            ))
        })
}

async fn maybe_enable_recovery(
    client: &Client,
    config: &MatrixConfig,
    state_dir: &Path,
    _session: &ValidatedMatrixSession,
) -> Result<(), MatrixError> {
    if !config.encrypted() {
        return Ok(());
    }
    let path = matrix_recovery_key_path(state_dir);
    let marker_path = matrix_recovery_minting_marker_path(state_dir);
    let pending_path = matrix_recovery_pending_key_path(state_dir);

    // If a "minting in progress" marker is sitting next to the recovery
    // dir, a previous startup minted a server-side secret but crashed
    // before the local persist landed (see write_owner_only_secret_file
    // failure path below). Treat this as the signal to roll back the
    // orphaned server-side state instead of double-minting.
    if marker_path.exists() && !path.exists() {
        if pending_path.exists() {
            promote_owner_only_secret_file(&pending_path, &path)
                .await
                .map_err(|err| {
                    MatrixError::E2ee(format!(
                        "Matrix recovery key was preserved at {} after a previous interrupted enable, \
                         but finalizing it to {} failed: {err}",
                        pending_path.display(),
                        path.display()
                    ))
                })?;
            remove_recovery_marker_with_log(&marker_path).await;
            return Ok(());
        }
        warn!(
            marker = %marker_path.display(),
            "Matrix recovery minting marker found without a recovery key on disk; \
             a previous run minted a server-side recovery secret that wasn't durably \
             persisted locally. Checking remote recovery state before rollback."
        );
        if matrix_recovery_secret_storage_enabled(client).await? {
            return Err(MatrixError::E2ee(format!(
                "Matrix recovery minting marker exists at {} but no pending/local key was preserved, \
                 and the homeserver already has recovery enabled. Refuse to call disable() because \
                 this may be a valid existing backup; remove the stale marker only after verifying \
                 the recovery key in Element or restoring it with `cara matrix recovery-key restore`.",
                marker_path.display()
            )));
        }
        let rollback = client.encryption().recovery().disable().await;
        rollback.map_err(|err| {
            MatrixError::E2ee(format!(
                "Matrix recovery had a stale minting marker but disable() failed: {err}. \
                 Disable recovery via Element and rerun."
            ))
        })?;
        remove_recovery_marker_with_log(&marker_path).await;
    }

    if path.exists() {
        return Ok(());
    }
    // Refuse to call enable() if the homeserver already has recovery
    // configured for this account. enable() in that state may rotate
    // the secret-storage key, and a follow-on local-persist failure
    // would trigger our rollback (disable()), tearing down a
    // previously functional backup the operator never asked us to
    // touch. Direct the operator to retrieve the existing key via
    // Element / `cara matrix recovery-key restore --key-file ...` or stdin
    // instead.
    if matrix_recovery_secret_storage_enabled(client).await? {
        return Err(MatrixError::E2ee(format!(
            "Matrix recovery is already enabled on the homeserver but no local key file at {} \
             — refuse to mint a new recovery secret (which would invalidate the existing backup). \
             Retrieve the existing key via Element and run `cara matrix recovery-key restore --key-file <file>` \
             or pipe it to `cara matrix recovery-key restore` over stdin.",
            path.display()
        )));
    }

    // Drop a marker file before enable() so a crash between minting and
    // local persist leaves a discoverable "we owe you a rollback"
    // breadcrumb. The marker is removed on successful persist.
    if let Some(parent) = marker_path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|err| MatrixError::E2ee(format!("create matrix state dir: {err}")))?;
    }
    write_recovery_minting_marker_durable(&marker_path).await?;

    let recovery_key = match client.encryption().recovery().enable().await {
        // Wrap in Zeroizing so the freshly-minted backup passphrase is
        // wiped from the heap when this scope exits. The SDK returns
        // a plain `String`; if the persist path below fails or panics
        // before the wrapper drops, a coredump or post-free heap
        // inspection could otherwise recover the key. Symmetric with
        // the discipline applied to `recovery_key_raw` in
        // `maybe_restore_recovery_key`.
        Ok(key) => zeroize::Zeroizing::new(key),
        Err(err) => {
            // Marker no longer represents real server-side state because
            // enable() never produced one. Clean it up — and surface the
            // cleanup error in the operator-visible message if it fails,
            // so a stale marker cannot quietly trigger rollback machinery
            // on the next start.
            let cleanup_note = match tokio::fs::remove_file(&marker_path).await {
                Ok(()) => String::new(),
                Err(cleanup_err) => format!(
                    " (additionally, removing stale minting marker at {} failed: {cleanup_err})",
                    marker_path.display()
                ),
            };
            return Err(MatrixError::E2ee(format!(
                "Matrix recovery enable failed: {err}{cleanup_note}"
            )));
        }
    };
    if let Err(persist_err) = write_owner_only_secret_file(&pending_path, &recovery_key).await {
        // The server-side recovery secret has just been minted, but the
        // generated key could not even be preserved in the local pending
        // slot. Roll back because there is no durable local copy to
        // promote on the next start.
        let rollback_msg = match client.encryption().recovery().disable().await {
            Ok(()) => {
                remove_recovery_marker_with_log(&marker_path).await;
                "server-side recovery disabled".to_string()
            }
            Err(disable_err) => format!(
                "server-side recovery rollback failed: {disable_err}; \
                 minting marker left at {} for next-start rollback retry",
                marker_path.display()
            ),
        };
        return Err(MatrixError::E2ee(format!(
            "failed to preserve Matrix recovery key at {}: {persist_err}; {rollback_msg}",
            pending_path.display()
        )));
    }

    if let Err(promote_err) = promote_owner_only_secret_file(&pending_path, &path).await {
        return Err(MatrixError::E2ee(format!(
            "Matrix recovery key was durably preserved at {}, but finalizing it to {} failed: {promote_err}. \
             The server-side recovery key was left enabled so the preserved pending key remains valid; \
             fix the file conflict and restart so Carapace can promote the pending key.",
            pending_path.display(),
            path.display()
        )));
    }
    // Persist landed: clear the minting marker so next start doesn't
    // try to roll back.
    remove_recovery_marker_with_log(&marker_path).await;
    Ok(())
}

/// Best-effort marker cleanup with a `warn!` on failure.
///
/// A stale recovery-minting marker can re-trigger the rollback branch of
/// `maybe_enable_recovery` on a subsequent start. The cleanup itself is
/// rarely fatal — the rollback branch is idempotent — but a silent
/// `let _ = remove_file(...)` hides the signal that the marker is still
/// on disk. Operators get a `warn!` so a stuck marker shows up in logs.
async fn remove_recovery_marker_with_log(marker_path: &Path) {
    match tokio::fs::remove_file(marker_path).await {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => {
            warn!(
                marker = %marker_path.display(),
                error = %err,
                "Matrix recovery minting marker cleanup failed; remove the file manually if it persists"
            );
        }
    }
}

/// Atomic, fsynced write of the recovery-minting marker file.
///
/// `tokio::fs::write(...)` returns once the kernel has buffered the
/// data; a power loss before the page-cache flush erases the marker.
/// The marker is the *only* breadcrumb that lets the next start roll
/// back an orphaned server-side `recovery().enable()`, so it must be
/// durable before `enable()` runs. Tmp-then-rename + parent-dir fsync
/// matches the discipline used by `write_owner_only_secret_file` for
/// the recovery key itself.
async fn write_recovery_minting_marker_durable(marker_path: &Path) -> Result<(), MatrixError> {
    if let Some(parent) = marker_path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|err| MatrixError::E2ee(format!("create matrix state dir: {err}")))?;
    }
    let marker_path_owned = marker_path.to_path_buf();
    let marker_for_err = marker_path_owned.clone();
    tokio::task::spawn_blocking(move || -> Result<(), String> {
        use std::io::Write;
        let tmp_path = secret_file_temp_path(&marker_path_owned);
        {
            // Use OpenOptions with explicit `mode(0o600)` for
            // consistency with neighbouring secret-file writers, even
            // though the marker itself contains no secret material.
            // This forecloses umask drift if a later contributor
            // copies this code as a template for a real secret writer.
            #[cfg(unix)]
            let create_result = {
                use std::os::unix::fs::OpenOptionsExt;
                std::fs::OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .mode(0o600)
                    .open(&tmp_path)
            };
            #[cfg(not(unix))]
            let create_result = std::fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&tmp_path);
            let mut file = create_result.map_err(|err| format!("create marker tmp: {err}"))?;
            let result = (|| -> std::io::Result<()> {
                file.write_all(b"recovery-minting-in-progress\n")?;
                file.sync_all()
            })();
            if let Err(err) = result {
                let _ = std::fs::remove_file(&tmp_path);
                return Err(format!("write marker tmp: {err}"));
            }
        }
        if let Err(err) = std::fs::rename(&tmp_path, &marker_path_owned) {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(format!("rename marker: {err}"));
        }
        // Parent-dir fsync via shared helper. The marker's whole
        // point is to be the rollback breadcrumb on crash, so a
        // silent fsync would defeat the durable-write contract this
        // function advertises. Routes through the shared helper so
        // Windows takes the documented no-op (NTFS journal handles
        // dirent durability) instead of erroring with
        // ERROR_ACCESS_DENIED.
        crate::paths::sync_parent_dir_blocking(&marker_path_owned)
            .map_err(|err| format!("fsync marker parent dir: {err}"))?;
        Ok(())
    })
    .await
    .map_err(|err| MatrixError::E2ee(format!("marker write join: {err}")))?
    .map_err(|err| {
        MatrixError::E2ee(format!(
            "failed to write recovery-minting marker at {}: {err}",
            marker_for_err.display()
        ))
    })
}

fn matrix_recovery_key_path(state_dir: &Path) -> PathBuf {
    state_dir.join("matrix").join("recovery_key")
}

fn matrix_recovery_minting_marker_path(state_dir: &Path) -> PathBuf {
    state_dir.join("matrix").join("recovery_key.minting")
}

fn matrix_recovery_pending_key_path(state_dir: &Path) -> PathBuf {
    state_dir.join("matrix").join("recovery_key.pending")
}

async fn matrix_recovery_secret_storage_enabled(client: &Client) -> Result<bool, MatrixError> {
    client
        .encryption()
        .secret_storage()
        .is_enabled()
        .await
        .map_err(|err| MatrixError::E2ee(format!("check Matrix recovery state: {err}")))
}

fn preflight_matrix_session_persistence() -> Result<(), MatrixError> {
    if crate::config::config_password().is_none() {
        return Err(MatrixError::TokenPersistence(
            "CARAPACE_CONFIG_PASSWORD is required before Matrix password login so the resulting access token can be persisted as an encrypted config secret".to_string(),
        ));
    }
    Ok(())
}

/// Owner-only secret-file write with atomic semantics.
///
/// Earlier versions wrote directly to the final path with `create_new`,
/// which leaves a partial/empty file on disk if `write_all` or
/// `sync_all` fails midway. A subsequent startup short-circuits
/// `maybe_enable_recovery` (because `path.exists()` is true) but
/// `maybe_restore_recovery_key` then fails reading the partial content,
/// bricking the daemon until manual cleanup. This implementation
/// instead writes a temp file in the same directory, fsyncs, and only
/// then renames into place — so the final path either holds the
/// complete content or doesn't exist.
///
/// Refuses to overwrite a pre-existing file at the final path
/// (matching the prior `create_new` contract). On Unix, finalization
/// uses `link(2)` from the fully-synced temp file to the final path so
/// the kernel performs create-if-absent atomically; `rename(2)` would
/// replace the destination.
#[cfg(unix)]
async fn write_owner_only_secret_file(path: &Path, content: &str) -> Result<(), String> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    if path.exists() {
        return Err(format!(
            "refusing to overwrite existing secret file at {}",
            path.display()
        ));
    }
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|err| err.to_string())?;
    }
    let path = path.to_path_buf();
    // Wrap the spawn_blocking-side clone in Zeroizing so the worker
    // thread's heap copy of the secret payload is wiped on drop. The
    // caller may pass a Zeroizing<String> via &str deref, but that
    // wrapper protects only the caller's copy — `to_string()` here
    // produces a fresh allocation that needs its own zeroize.
    let content = zeroize::Zeroizing::new(content.to_string());
    tokio::task::spawn_blocking(move || -> Result<(), String> {
        let tmp_path = secret_file_temp_path(&path);
        {
            let mut file = std::fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .open(&tmp_path)
                .map_err(|err| format!("create temp secret file: {err}"))?;
            let write_result = file
                .write_all(content.as_bytes())
                .and_then(|_| file.write_all(b"\n"))
                .and_then(|_| file.sync_all());
            if let Err(err) = write_result {
                let _ = std::fs::remove_file(&tmp_path);
                return Err(format!("write temp secret file: {err}"));
            }
        }
        if let Err(err) = link_secret_file_no_replace(&tmp_path, &path) {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(err);
        }
        let _ = std::fs::remove_file(&tmp_path);
        // Fsync the parent dir via the shared helper so the linked
        // final path is durable across power-loss. Without this, the
        // kernel may have written the temp file's contents to disk
        // but not yet flushed the dirent change; a crash here loses
        // the final link and the operator boots with the SDK store
        // referencing a server-side recovery secret that has no
        // local key file. Errors propagate now (previously swallowed).
        crate::paths::sync_parent_dir_blocking(&path)
            .map_err(|err| format!("fsync recovery-key parent dir: {err}"))?;
        Ok(())
    })
    .await
    .map_err(|err| err.to_string())?
}

fn link_secret_file_no_replace(src: &Path, dst: &Path) -> Result<(), String> {
    std::fs::hard_link(src, dst).map_err(|err| {
        if dst.exists() {
            format!(
                "secret file at {} appeared concurrently; refusing to overwrite",
                dst.display()
            )
        } else {
            format!("link secret file into place: {err}")
        }
    })
}

async fn promote_owner_only_secret_file(src: &Path, dst: &Path) -> Result<(), String> {
    // SECURITY: same atomic-no-replace contract as
    // `promote_owner_only_cli_secret_no_replace` in cli/mod.rs. The
    // previous Windows branch used `dst.exists()` + `std::fs::rename`,
    // which silently replaces under `MoveFileExW(MOVEFILE_REPLACE_EXISTING)`.
    // `link_secret_file_no_replace` uses `std::fs::hard_link` which is
    // portable across Unix and Windows (NTFS) and atomically refuses
    // an existing destination via EEXIST / ERROR_ALREADY_EXISTS.
    if dst.exists() {
        return Err(format!(
            "refusing to overwrite existing secret file at {}",
            dst.display()
        ));
    }
    let src = src.to_path_buf();
    let dst = dst.to_path_buf();
    tokio::task::spawn_blocking(move || -> Result<(), String> {
        link_secret_file_no_replace(&src, &dst)?;
        crate::paths::sync_parent_dir_blocking(&dst)
            .map_err(|err| format!("fsync recovery-key parent dir: {err}"))?;
        std::fs::remove_file(&src).map_err(|err| format!("remove pending secret file: {err}"))?;
        Ok(())
    })
    .await
    .map_err(|err| err.to_string())?
}

#[cfg(not(unix))]
async fn write_owner_only_secret_file(path: &Path, content: &str) -> Result<(), String> {
    if path.exists() {
        return Err(format!(
            "refusing to overwrite existing secret file at {}",
            path.display()
        ));
    }
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|err| err.to_string())?;
    }
    let path = path.to_path_buf();
    // Same Zeroize discipline as the unix branch — see comment there.
    let content = zeroize::Zeroizing::new(content.to_string());
    tokio::task::spawn_blocking(move || -> Result<(), String> {
        use std::io::Write;
        let tmp_path = secret_file_temp_path(&path);
        {
            let mut file = std::fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&tmp_path)
                .map_err(|err| format!("create temp secret file: {err}"))?;
            let write_result = file
                .write_all(content.as_bytes())
                .and_then(|_| file.write_all(b"\n"))
                .and_then(|_| file.sync_all());
            if let Err(err) = write_result {
                let _ = std::fs::remove_file(&tmp_path);
                return Err(format!("write temp secret file: {err}"));
            }
        }
        // SECURITY: same atomic-no-replace contract as the Unix
        // branch. `path.exists()` + `std::fs::rename` is TOCTOU-prone
        // on Windows because std-fs-rename maps to
        // `MoveFileExW(MOVEFILE_REPLACE_EXISTING)` and silently
        // overwrites concurrent writers. `link_secret_file_no_replace`
        // is portable (NTFS supports hard links) and atomically
        // refuses an existing destination.
        let link_result = link_secret_file_no_replace(&tmp_path, &path);
        let _ = std::fs::remove_file(&tmp_path);
        if let Err(err) = link_result {
            return Err(err);
        }
        // Fsync the parent dir via the shared helper. On Windows the
        // helper is a no-op (NTFS journal handles dirent durability);
        // on Unix it surfaces fsync failures as Err.
        crate::paths::sync_parent_dir_blocking(&path)
            .map_err(|err| format!("fsync recovery-key parent dir: {err}"))?;
        Ok(())
    })
    .await
    .map_err(|err| err.to_string())?
}

fn secret_file_temp_path(path: &Path) -> PathBuf {
    crate::paths::atomic_tmp_path(path, "secret")
}

async fn persist_matrix_session(access_token: &str, device_id: &str) -> Result<(), MatrixError> {
    if crate::config::config_password().is_none() {
        return Err(MatrixError::TokenPersistence(
            "CARAPACE_CONFIG_PASSWORD is required to persist matrix.accessToken as an encrypted config secret".to_string(),
        ));
    }
    // Wrap the spawn_blocking-side clone of the access token in
    // Zeroizing so the worker thread's input copy is wiped on Drop.
    // Note: this protects ONLY the closure's argument copy.
    // `persist_matrix_session_blocking` itself flows the token
    // through `Value::String(access_token.to_string())` →
    // serde_json buffers → the on-disk write path; those copies
    // are NOT zeroed (they live briefly between serialize and
    // file-write). device_id is not secret material; plain String
    // is fine.
    let access_token = zeroize::Zeroizing::new(access_token.to_string());
    let device_id = device_id.to_string();
    tokio::task::spawn_blocking(move || persist_matrix_session_blocking(&access_token, &device_id))
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
            handle_to_device_event(ws_state, state, config, event).await;
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
    let encryption_state = state;
    client.add_event_handler(
        move |event: matrix_sdk::ruma::events::OriginalSyncStateEvent<
            matrix_sdk::ruma::events::room::encryption::RoomEncryptionEventContent,
        >,
              room: Room| {
            let state = encryption_state.clone();
            async move {
                if room.state() != RoomState::Joined {
                    return;
                }
                let room_id = sanitize_homeserver_identifier(room.room_id().as_str());
                warn!(
                    room_id = %room_id,
                    algorithm = ?event.content.algorithm,
                    "Matrix room transitioned to encrypted state; \
                     channel-status will reflect this on the next maintenance refresh"
                );
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
    // Sanitize peer-controlled identifiers up front so every log
    // emission below — including the early-return branches before
    // dispatch reaches the IdempotencyKey gate — uses defense-in-
    // depth-cleaned values. ruma's identifier validators are
    // permissive (event_id only checks the leading sigil; OwnedDeviceId
    // rejects nothing); without this, four pre-screen warn/debug
    // sites emitted raw homeserver-supplied bytes and a hostile
    // homeserver could rewrite operator-visible terminal output.
    let room_id = sanitize_homeserver_identifier(room.room_id().as_str());
    let sender_id = sanitize_homeserver_identifier(event.sender.as_str());
    let event_id = sanitize_homeserver_identifier(event.event_id.as_str());

    if !is_room_supported(&room, config.encrypted()) {
        warn!(
            room_id = %room_id,
            "Matrix room became encrypted while matrix.encrypted=false; inbound event ignored"
        );
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
            let (verification, inserted) = upsert_verification_record(
                &state,
                event.event_id.to_string(),
                event.sender.to_string(),
                Some(request.from_device.to_string()),
                MatrixVerificationState::Requested,
            );
            crate::server::ws::broadcast_matrix_verification_request(
                &ws_state,
                crate::server::ws::NewVerificationFlow::from_upsert(&verification, inserted),
            );
            crate::server::ws::broadcast_matrix_verification_updated(
                &ws_state,
                crate::server::ws::UpdatedVerificationFlow::for_state_change(&verification),
            );
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
        warn!(
            room_id = %room_id,
            sender = %sender_id,
            event_id = %event_id,
            msgtype = %msgtype,
            "Matrix inbound event ignored: msgtype not yet supported",
        );
        let mut guard = state.write();
        guard.status.unsupported_inbound_count =
            guard.status.unsupported_inbound_count.saturating_add(1);
        return;
    };
    if matrix_user_ids_equal(&event.sender, &config.user_id) {
        return;
    }
    if let Some(reason) = matrix_relation_suppression_reason(event.content.relates_to.as_ref()) {
        debug!(event_id = %event_id, reason = reason, "Matrix relation suppressed");
        return;
    }
    // Skip whitespace-only messages. A stuck client or a typo could
    // emit an empty body; dispatching `"   "` to the agent runtime
    // wastes an LLM call. The body's idempotency token is still
    // logged so a redelivery loop is observable in the journal.
    if text_content.body.trim().is_empty() {
        debug!(
            event_id = %event_id,
            sender = %sender_id,
            "Matrix inbound message had empty/whitespace-only body; skipping dispatch"
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
        warn!(
            event_id = %event_id,
            sender = %sender_id,
            body_bytes = text_content.body.len(),
            limit_bytes = MATRIX_INBOUND_BODY_MAX_BYTES,
            "Matrix inbound message body exceeds size cap; dropping event without dispatch"
        );
        let mut guard = state.write();
        guard.status.unsupported_inbound_count =
            guard.status.unsupported_inbound_count.saturating_add(1);
        return;
    }
    debug!(
        room_id = %room_id,
        sender = %sender_id,
        event_id = %event_id,
        "Matrix inbound message"
    );
    let idempotency_key = crate::channels::inbound::IdempotencyKey::from_str_opt(&event_id);
    if idempotency_key.is_none() && !event_id.is_empty() {
        // SDK delivered a non-empty event_id we can't canonicalize
        // (control bytes, embedded NUL, etc.). Dispatch falls through
        // without dedupe — surface the bypass so a redelivery storm
        // is observable in the operator's journal rather than landing
        // as N indistinguishable user messages.
        warn!(
            event_id = %event_id,
            "Matrix inbound event_id failed IdempotencyKey canonicalization; dispatching without dedupe"
        );
    }
    match crate::channels::inbound::dispatch_inbound_text_with_options(
        &ws_state,
        MATRIX_CHANNEL_ID,
        &sender_id,
        &room_id,
        &text_content.body,
        Some(room_id.clone()),
        crate::channels::inbound::InboundDispatchOptions {
            inbound_event_id: idempotency_key,
            delivery_recipient_id: Some(room_id.clone()),
            ..Default::default()
        },
    )
    .await
    {
        Ok(_) => {
            state.write().reset_inbound_failures();
        }
        Err(err) => {
            // Validate event_id at DLQ-writer time. If the SDK ever
            // hands us an event_id that wouldn't yield a valid
            // `IdempotencyKey` (empty, whitespace, control bytes),
            // landing it on disk produces a permanently-stuck DLQ
            // because `decode_matrix_inbound_dlq_record` will reject
            // it on every replay. Refuse to enqueue and surface the
            // dispatch failure directly.
            if crate::channels::inbound::IdempotencyKey::from_str_opt(&event_id).is_none() {
                warn!(
                    error = %err,
                    event_id = %event_id,
                    "Matrix inbound dispatch failed and event_id is unsuitable for DLQ — \
                     refusing to enqueue an unreplayable record"
                );
                // Stamp `pending_inbound_error` alongside the streak
                // bump so apply_post_sync_maintenance's reconciliation
                // sees the operator-actionable cause and pins the
                // channel into Error once the streak goes sticky. The
                // bare `record_inbound_failure()` would leave
                // `pending_inbound_error=None`, in which case the
                // sticky-streak reconciliation falls into Connected
                // because the error-snapshot is None — adversary-
                // reachable via a homeserver delivering events with
                // control bytes in event_id.
                state.write().record_inbound_failure_with_error(format!(
                    "Matrix inbound dispatch failed for event {event_id} with unsuitable \
                         event_id (refused DLQ enqueue): {}",
                    crate::logging::redact::RedactedDisplay(&err)
                ));
                return;
            }
            let dlq_record = MatrixInboundDlqRecord {
                event_id: event_id.clone(),
                room_id: room_id.clone(),
                sender_id: sender_id.clone(),
                text: text_content.body.clone(),
                received_at: now_millis(),
            };
            if let Err(dlq_err) =
                append_matrix_inbound_dlq(&state_dir, &config, state.clone(), &dlq_record).await
            {
                let message = format!(
                    "Matrix inbound dispatch failed and DLQ append failed for event {event_id}: {}",
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
            let error_msg = format!(
                "Matrix inbound dispatch failing: {}",
                crate::logging::redact::RedactedDisplay(&err)
            );
            let failures = {
                let mut guard = state.write();
                let count = guard.record_inbound_failure_with_error(error_msg);
                // Lifetime counter survives the consecutive-failure
                // decay so operators auditing inbound delivery health
                // can see total drops over the daemon's uptime, even
                // after `last_error` has been cleared by a later
                // successful sync.
                guard.status.inbound_dispatch_failure_total = guard
                    .status
                    .inbound_dispatch_failure_total
                    .saturating_add(1);
                count
            };
            warn!(
                error = %err,
                failures,
                "failed to dispatch Matrix inbound message"
            );
        }
    }
}

async fn handle_to_device_event(
    ws_state: Arc<WsServerState>,
    state: Arc<RwLock<MatrixRuntimeState>>,
    config: MatrixConfig,
    event: AnyToDeviceEvent,
) {
    let AnyToDeviceEvent::KeyVerificationRequest(event) = event else {
        return;
    };
    // Gate to-device verification requests by trust boundary so a
    // hostile peer can't burn through the 256-record verification cap
    // and evict the operator's legitimate flow at index 0 (the cap-
    // eviction policy at `upsert_verification_record` falls back to
    // oldest non-terminal when no terminal records exist). Two
    // accepted classes:
    //
    //   1. `event.sender == config.user_id` — the operator's own
    //      device starting a self-verification flow with another of
    //      their devices. Most common operator path.
    //   2. `auto_join.allows_user(event.sender.as_str())` — a peer
    //      who is already trusted enough to auto-join a room with
    //      the bot is also trusted enough to start a verification
    //      flow.
    //
    // Anything else is dropped silently (warn-logged) — the peer
    // gets no SAS handshake; the operator can still initiate
    // verification toward an unlisted peer via
    // `cara matrix start-verification`, which goes through
    // `start_matrix_verification` and bypasses this handler.
    let sender_str = event.sender.as_str();
    let is_self = matrix_user_ids_equal(&event.sender, &config.user_id);
    if !is_self && !config.auto_join.allows_user(sender_str) {
        let sender_san = sanitize_homeserver_identifier(sender_str);
        warn!(
            sender = %sender_san,
            "Matrix to-device KeyVerificationRequest dropped: sender is not the configured user nor on the auto-join allowlist"
        );
        return;
    }
    let (verification, inserted) = upsert_verification_record(
        &state,
        event.content.transaction_id.to_string(),
        event.sender.to_string(),
        Some(event.content.from_device.to_string()),
        MatrixVerificationState::Requested,
    );
    crate::server::ws::broadcast_matrix_verification_request(
        &ws_state,
        crate::server::ws::NewVerificationFlow::from_upsert(&verification, inserted),
    );
    crate::server::ws::broadcast_matrix_verification_updated(
        &ws_state,
        crate::server::ws::UpdatedVerificationFlow::for_state_change(&verification),
    );
}

fn matrix_inbound_dlq_path(state_dir: &Path) -> PathBuf {
    state_dir.join("matrix").join("inbound_dlq.jsonl")
}

fn matrix_inbound_dlq_quarantine_path(state_dir: &Path) -> PathBuf {
    state_dir.join("matrix").join("inbound_dlq.corrupt.jsonl")
}

/// Cap on the on-disk quarantine file size. Quarantine is for forensic
/// recovery of lines the runtime can't decode (key-mismatch wave,
/// envelope-version drift). Once full, additional corrupt lines are no
/// more recoverable than the ones already there — and an attacker
/// driving sustained corruption (or repeat operator key rotations
/// between DLQ floods) could otherwise fill the disk silently. 10 MB
/// is well above the legitimate post-rotation forensic window for a
/// daemon at typical message rates.
const MATRIX_DLQ_QUARANTINE_MAX_BYTES: u64 = 10 * 1024 * 1024;

/// Append undecodable DLQ lines to a sibling quarantine file
/// (`inbound_dlq.corrupt.jsonl`) so the live DLQ can drain. The lines
/// are preserved verbatim — they failed to decode, so re-encoding
/// would lose the original on-disk form needed for forensic recovery.
async fn append_matrix_inbound_dlq_quarantine(
    state_dir: &Path,
    lines: &[String],
) -> Result<(), MatrixError> {
    let path = matrix_inbound_dlq_quarantine_path(state_dir);
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await.map_err(|err| {
            MatrixError::SyncFailed(format!("create Matrix DLQ quarantine dir: {err}"))
        })?;
    }
    // Refuse to grow the quarantine file past
    // MATRIX_DLQ_QUARANTINE_MAX_BYTES. Drop the new lines with a warn
    // — the on-disk evidence of earlier corruption survives, and the
    // operator can rotate / archive / triage before clearing the cap.
    if let Ok(metadata) = tokio::fs::metadata(&path).await {
        if metadata.len() >= MATRIX_DLQ_QUARANTINE_MAX_BYTES {
            warn!(
                path = %path.display(),
                quarantine_bytes = metadata.len(),
                cap = MATRIX_DLQ_QUARANTINE_MAX_BYTES,
                dropped_lines = lines.len(),
                "Matrix DLQ quarantine file at cap; dropping new corrupt lines. \
                 Archive or rotate the existing quarantine before clearing the cap."
            );
            return Ok(());
        }
    }
    let blob = lines
        .iter()
        .map(|line| format!("{line}\n"))
        .collect::<String>();
    let path_owned = path.clone();
    tokio::task::spawn_blocking(move || -> Result<(), MatrixError> {
        // SECURITY: quarantine carries the same payloads as the live DLQ
        // (encrypted-record envelopes when matrix.encrypted=true, raw event
        // text otherwise). Owner-only mode mirrors the live DLQ writer at
        // `append_matrix_inbound_dlq_line_blocking` so other local users
        // can't read messages that the live DLQ deliberately keeps private.
        // Both first-create and existing-file branches enforce 0o600; if a
        // pre-existing file is wider, force it back.
        let was_first_write = !path_owned.exists();
        let mut file = open_matrix_dlq_quarantine_owner_only(&path_owned)
            .map_err(|err| MatrixError::SyncFailed(format!("open Matrix DLQ quarantine: {err}")))?;
        ensure_matrix_dlq_quarantine_owner_only(&path_owned).map_err(|err| {
            MatrixError::SyncFailed(format!("chmod Matrix DLQ quarantine: {err}"))
        })?;
        use std::io::Write;
        file.write_all(blob.as_bytes())
            .and_then(|_| file.sync_all())
            .map_err(|err| {
                MatrixError::SyncFailed(format!("write Matrix DLQ quarantine: {err}"))
            })?;
        // First-time creation requires a parent-dir fsync so the new dirent
        // survives a power loss. The live DLQ rewrite that follows is
        // already fsynced; without this the quarantine sibling could be
        // lost while the rewrite landed, silently dropping corrupt records
        // we promised to preserve for forensic recovery.
        if was_first_write {
            crate::paths::sync_parent_dir_blocking(&path_owned).map_err(|err| {
                MatrixError::SyncFailed(format!("fsync Matrix DLQ quarantine dir: {err}"))
            })?;
        }
        Ok(())
    })
    .await
    .map_err(|err| MatrixError::SyncFailed(format!("Matrix DLQ quarantine task: {err}")))?
}

#[cfg(unix)]
fn open_matrix_dlq_quarantine_owner_only(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(path)
}

#[cfg(not(unix))]
fn open_matrix_dlq_quarantine_owner_only(path: &Path) -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
}

#[cfg(unix)]
fn ensure_matrix_dlq_quarantine_owner_only(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let metadata = std::fs::metadata(path)?;
    let mut permissions = metadata.permissions();
    if permissions.mode() & 0o777 != 0o600 {
        permissions.set_mode(0o600);
        std::fs::set_permissions(path, permissions)?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn ensure_matrix_dlq_quarantine_owner_only(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

async fn append_matrix_inbound_dlq(
    state_dir: &Path,
    config: &MatrixConfig,
    state: Arc<RwLock<MatrixRuntimeState>>,
    record: &MatrixInboundDlqRecord,
) -> Result<(), MatrixError> {
    let path = matrix_inbound_dlq_path(state_dir);
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await.map_err(|err| {
            MatrixError::SyncFailed(format!("create Matrix inbound DLQ dir: {err}"))
        })?;
    }
    let serialized = encode_matrix_inbound_dlq_record(state_dir, config, record)?;
    let lock = state.read().dlq_io_lock();
    let _guard = lock.lock().await;
    // SECURITY: cap DLQ size before appending. The cheapest line-
    // count check on a JSONL file is reading existing length; we
    // can short-circuit by checking the file size against a
    // conservative per-record floor (records are at minimum a few
    // hundred bytes). Use line count for accuracy under the lock.
    if let Some(count) = matrix_inbound_dlq_line_count(&path).await? {
        if count >= MATRIX_INBOUND_DLQ_MAX_RECORDS {
            warn!(
                path = %path.display(),
                lines = count,
                limit = MATRIX_INBOUND_DLQ_MAX_RECORDS,
                "Matrix inbound DLQ size cap reached; dropping record. \
                 Operator action: fix the underlying inbound dispatch \
                 failure (typically a misconfigured agent or downstream \
                 channel). The DLQ drains automatically on the next \
                 successful post-sync replay tick — no manual file action \
                 is needed in the normal recovery path. If you must discard \
                 records to clear backlog, stop the daemon first, then \
                 truncate or remove inbound_dlq.jsonl; truncating while the \
                 daemon is running races the DLQ rewrite path."
            );
            // Mark this as a durability error so the operator sees
            // the channel-status sticky-Error signal — DLQ
            // saturation IS an unrecoverable durability event from
            // the inbound's perspective.
            state.write().record_inbound_dlq_append_failure(format!(
                "Matrix inbound DLQ at {} reached {MATRIX_INBOUND_DLQ_MAX_RECORDS}-record cap; \
                 dropping new dispatch failures until the queue drains",
                path.display()
            ));
            return Err(MatrixError::SyncFailed(
                "Matrix inbound DLQ at size cap; record dropped".to_string(),
            ));
        }
    }
    let result = append_matrix_inbound_dlq_line(&path, serialized).await;
    if result.is_ok() {
        state.write().clear_inbound_dlq_durability_error();
    }
    result
}

/// Count lines in the DLQ file (best-effort). Returns `Ok(None)` when
/// the file doesn't exist (= queue is empty, no cap risk). Errors
/// otherwise are surfaced so the cap can fail-closed if the queue
/// state can't be determined.
///
/// Two-phase check: (1) `metadata().len()` is a syscall-only size
/// query that does no file content I/O; (2) only when the byte size
/// gets close to the cap (per-record-floor heuristic) do we fall back
/// to reading the file and counting newlines for an exact count. This
/// keeps the common hot-path call O(1) syscall instead of multi-MB of
/// content I/O — without that, every `append_matrix_inbound_dlq` would
/// hold the dlq_io_lock during a full file read for files near cap,
/// blocking concurrent appends for the duration of the read.
async fn matrix_inbound_dlq_line_count(path: &Path) -> Result<Option<usize>, MatrixError> {
    // Conservative per-record floor for the size heuristic. Encrypted
    // DLQ records (the common case for `matrix.encrypted=true`
    // deployments) are at minimum ~270 bytes: 12-byte AES-GCM nonce →
    // 16 base64 chars; plaintext `MatrixInboundDlqRecord` (event_id
    // ~50 chars + room_id ~30 + sender_id ~30 + text ≥1 + received_at
    // ~13 + JSON syntax) is ~150+ bytes; AES-GCM ciphertext + 16-byte
    // tag base64-encoded ≥222 chars; total JSON envelope ≥270 bytes.
    // Plaintext records (encrypted=false) are smaller, ~150 bytes
    // minimum. 250 sits below both minimums and stays safe even if
    // the field encoding gets tighter; the heuristic only crosses
    // into the slow read path at ~93% of cap, which is the intended
    // near-cap behavior.
    const PER_RECORD_FLOOR_BYTES: u64 = 250;
    const CAP_BYTES_FLOOR: u64 =
        (MATRIX_INBOUND_DLQ_MAX_RECORDS as u64).saturating_mul(PER_RECORD_FLOOR_BYTES);
    let metadata = match tokio::fs::metadata(path).await {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => {
            return Err(MatrixError::SyncFailed(format!(
                "stat Matrix inbound DLQ for cap check {}: {err}",
                path.display()
            )))
        }
    };

    // If the file size is well below cap × floor bytes, the cap can't
    // possibly be reached. Skip the content read entirely.
    let cap_bytes_floor = CAP_BYTES_FLOOR;
    if metadata.len() < cap_bytes_floor {
        // Below the floor → cannot exceed the cap. Return a count
        // sentinel of 0 to short-circuit the comparison; the cap path
        // only fires on `>= MATRIX_INBOUND_DLQ_MAX_RECORDS` so a 0
        // count is structurally safe.
        return Ok(Some(0));
    }

    // Possibly at-cap. Pay the full read for an accurate count.
    match tokio::fs::read_to_string(path).await {
        Ok(content) => Ok(Some(content.lines().count())),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(MatrixError::SyncFailed(format!(
            "read Matrix inbound DLQ for cap check {}: {err}",
            path.display()
        ))),
    }
}

/// One classified outcome from the per-record decode in
/// `replay_matrix_inbound_dlq`. Lines that fail to decode are kept
/// verbatim in `Corrupt` so the rewrite path can preserve them on
/// disk for forensic recovery instead of silently dropping them.
enum DlqReplayLine {
    Decoded(MatrixInboundDlqRecord),
    Corrupt { raw: String, error: String },
}

async fn replay_matrix_inbound_dlq(
    state_dir: &Path,
    config: &MatrixConfig,
    ws_state: Arc<WsServerState>,
    state: Arc<RwLock<MatrixRuntimeState>>,
) -> Result<(), MatrixError> {
    let path = matrix_inbound_dlq_path(state_dir);
    let lock = state.read().dlq_io_lock();

    // Phase 1: snapshot the current DLQ contents under the lock and
    // release it. Holding the lock across dispatch (a per-record
    // agent-pipeline call that can block on the LLM) would block every
    // inbound `append_matrix_inbound_dlq` call for as long as replay
    // takes — a single slow LLM round-trip on one DLQ record means new
    // dispatch failures get blocked at the lock, not the cap, dropping
    // them silently on shutdown. We track the original line set so
    // phase 3 can preserve any new appends that arrived during dispatch.
    let original_content = {
        let _guard = lock.lock().await;
        match tokio::fs::read_to_string(&path).await {
            Ok(content) => content,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                state.write().clear_inbound_dlq_durability_error();
                return Ok(());
            }
            Err(err) => {
                return Err(MatrixError::SyncFailed(format!(
                    "read Matrix inbound DLQ {}: {err}",
                    path.display()
                )))
            }
        }
    };
    // Multiset rather than HashSet so byte-identical lines (e.g., the
    // same Matrix event ID delivered twice in a redelivery storm) are
    // tracked with their multiplicity. A plain HashSet would let two
    // concurrent appends of the same encoded record collapse to one,
    // and the phase-3 diff would silently drop the second concurrent
    // append after the first dispatched.
    let mut original_multiset: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();
    for line in original_content
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
    {
        *original_multiset.entry(line.to_string()).or_insert(0) += 1;
    }
    let original_lines: Vec<String> = original_multiset
        .iter()
        .flat_map(|(line, count)| std::iter::repeat_n(line.clone(), *count))
        .collect();

    // Derive the AEAD key once for the whole replay loop. The key is
    // process-deterministic over `(passphrase, installation_id)`,
    // both fixed for a daemon's lifetime barring rekey, so deriving
    // it per record (10k HKDF + 10k filesystem reads of
    // `installation_id` under `dlq_io_lock`) is wasted work that
    // throttles concurrent `append_matrix_inbound_dlq` callers.
    // Plaintext mode skips key derivation entirely.
    let dlq_key = if config.encrypted() {
        Some(derive_matrix_inbound_dlq_key(state_dir, config)?)
    } else {
        None
    };

    // Phase 2: classify and dispatch each record OUTSIDE the lock.
    // Concurrent inbound failures land in the live file via
    // `append_matrix_inbound_dlq`; we'll merge them in during phase 3.
    let mut remaining_records: Vec<MatrixInboundDlqRecord> = Vec::new();
    let mut corrupt_lines: Vec<String> = Vec::new();
    let mut errors: Vec<String> = Vec::new();
    for line in original_lines.iter() {
        let classified = match decode_matrix_inbound_dlq_record_with_key(dlq_key.as_ref(), line) {
            Ok(record) => DlqReplayLine::Decoded(record),
            Err(err) => DlqReplayLine::Corrupt {
                raw: line.clone(),
                error: err.to_string(),
            },
        };
        match classified {
            DlqReplayLine::Decoded(record) => {
                match dispatch_matrix_dlq_record(ws_state.clone(), state.clone(), &record).await {
                    Ok(()) => {
                        state.write().reset_inbound_failures();
                    }
                    Err(err) => {
                        // M7: log per-record dispatch failures at warn so
                        // the trace is queryable per event_id. The
                        // aggregate error returned later only carries
                        // the first 3 of N, hiding the long tail.
                        warn!(
                            event_id = %record.event_id,
                            error = %err,
                            "Matrix DLQ replay dispatch failed"
                        );
                        errors.push(format!("event {}: {err}", record.event_id));
                        remaining_records.push(record);
                    }
                }
            }
            DlqReplayLine::Corrupt { raw, error } => {
                // Move undecodable lines to a sibling quarantine file
                // so the live DLQ can drain. Without this, every
                // replay tick re-classifies them as Corrupt, the
                // dlq_replay streak ticks up monotonically, and the
                // channel stays in Error forever — even after every
                // recoverable record has dispatched. The quarantine
                // file preserves the raw line for forensic recovery.
                warn!(
                    error = %error,
                    "Matrix DLQ replay encountered an undecodable line; moving to quarantine"
                );
                errors.push(format!("undecodable line (quarantined): {error}"));
                corrupt_lines.push(raw);
            }
        }
    }

    // Append corrupt lines to the quarantine file (best-effort).
    // Quarantine writes go to a sibling file that no other DLQ path
    // touches, so they don't need the dlq_io_lock.
    let quarantine_failed_err = if corrupt_lines.is_empty() {
        None
    } else {
        match append_matrix_inbound_dlq_quarantine(state_dir, &corrupt_lines).await {
            Ok(()) => None,
            Err(err) => {
                tracing::error!(
                    error = %err,
                    "failed to write Matrix DLQ quarantine file; corrupt lines remain in live DLQ \
                     — channel will stay in Error until the operator unblocks the quarantine path"
                );
                Some(err)
            }
        }
    };

    // Phase 3: re-acquire the lock briefly to merge any concurrently-
    // appended records back into the live DLQ along with dispatch
    // failures (and corrupt lines if quarantine failed).
    //
    // Helper: log the in-memory remaining_records' event_ids before
    // propagating an error so an operator chasing a "where did my
    // events go?" report has a forensic recovery list. Phase-3 failure
    // means those records will not be persisted back to disk. Also
    // mirror the IDs into channel-status so the recovery list survives
    // a journal rotation between the failure and the operator's page.
    let lost_persist_state = state.clone();
    let log_lost_remaining = |where_label: &str, err: &dyn std::fmt::Display| {
        if !remaining_records.is_empty() {
            let lost_ids: Vec<&str> = remaining_records
                .iter()
                .map(|r| r.event_id.as_str())
                .collect();
            // JSON-encoded so log aggregators can parse the IDs out as
            // an array; see the cap-clamp branch below for the same
            // discipline.
            let lost_event_ids_json =
                serde_json::to_string(&lost_ids).expect("Vec<&str> always serializes to JSON");
            tracing::error!(
                stage = where_label,
                error = %err,
                lost_event_ids = %lost_event_ids_json,
                path = %path.display(),
                "Matrix DLQ phase-3 cleanup failed; dispatch-failed records held in memory \
                 cannot be persisted back to disk and may be lost on shutdown. Operator \
                 may need to manually replay events from session log."
            );
            // Stamp a durability error and the lost-IDs together so a
            // first-time phase-3 failure on a fresh daemon immediately
            // pins the channel into Error via the durability-error
            // path — symmetrical with the cap-clamp branch below,
            // which is the only other path that surfaces lost
            // event_ids without a prior dlq_replay streak.
            let lost_count = remaining_records.len();
            let mut guard = lost_persist_state.write();
            guard.record_inbound_dlq_append_failure(format!(
                "Matrix inbound DLQ phase-3 cleanup ({where_label}) failed; \
                 {lost_count} dispatch-failed record(s) held in memory cannot be \
                 persisted back to disk: {err}"
            ));
            guard.record_inbound_dlq_lost_event_ids(
                remaining_records.iter().map(|r| r.event_id.clone()),
            );
        }
    };

    {
        let _guard = lock.lock().await;
        let new_lines = match tokio::fs::read_to_string(&path).await {
            Ok(content) => {
                let mut snapshot_remaining = original_multiset.clone();
                let mut new_lines = Vec::new();
                for line in content
                    .lines()
                    .map(str::trim)
                    .filter(|line| !line.is_empty())
                {
                    match snapshot_remaining.get_mut(line) {
                        Some(count) if *count > 0 => {
                            // This line was already in phase-1 snapshot;
                            // accounted for. Decrement multiplicity.
                            *count -= 1;
                        }
                        _ => {
                            // Concurrent append since phase 1 — preserve.
                            new_lines.push(line.to_string());
                        }
                    }
                }
                new_lines
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(err) => {
                log_lost_remaining("re-read", &err);
                return Err(MatrixError::SyncFailed(format!(
                    "re-read Matrix inbound DLQ during replay merge {}: {err}",
                    path.display()
                )));
            }
        };

        // Final live-file content: new appends since phase 1, then
        // dispatch failures, then corrupt lines (only if quarantine
        // failed — successful quarantine moves them to the sibling).
        let preserved_corrupt: &[String] = if quarantine_failed_err.is_some() {
            &corrupt_lines
        } else {
            &[]
        };
        let mut merged_lines =
            Vec::with_capacity(new_lines.len() + remaining_records.len() + preserved_corrupt.len());
        // Order matters for the cap-clamp below: dispatch-failed records
        // (`remaining_records`) come FIRST because they have already
        // earned their slot — they survived classification and dispatch
        // in phase 2 and are awaiting retry. Concurrent new appends
        // (`new_lines`) come second; under cap pressure these are the
        // safer drop target since the next replay tick will re-process
        // any new appends written after this rewrite. `truncate` keeps
        // the prefix and drops from the tail, so this ordering yields
        // FIFO eviction (oldest-survives) under load — the correct
        // policy when an adversary-controlled inbound burst races a
        // legitimate dispatch backlog. Track encode failures so we
        // detect the all-fail-edge below.
        let mut encode_failure_count = 0usize;
        for record in &remaining_records {
            // Reuse the per-replay AEAD key derived above — re-deriving
            // for each remaining record under `dlq_io_lock` is wasted
            // work that throttles concurrent `append_matrix_inbound_dlq`.
            match encode_matrix_inbound_dlq_record_with_key(dlq_key.as_ref(), record) {
                Ok(line) => merged_lines.push(line),
                Err(err) => {
                    encode_failure_count += 1;
                    tracing::error!(
                        event_id = %record.event_id,
                        error = %err,
                        "Matrix DLQ replay phase-3 re-encode failed; record dropped from \
                         live DLQ. Operator may need to manually replay this event from \
                         session log."
                    );
                }
            }
        }
        // If EVERY remaining record failed to encode (config corruption,
        // store-key drift, HKDF info mismatch), surface a sticky
        // durability error — silently dropping the entire dispatch-
        // failed batch on the next replay tick is the worst-case for a
        // DLQ. Operator must intervene before the channel is recoverable.
        if !remaining_records.is_empty() && encode_failure_count == remaining_records.len() {
            state.write().record_inbound_dlq_append_failure(format!(
                "Matrix inbound DLQ replay phase-3 re-encoded zero of {} dispatch-failed \
                 records; check store key + HKDF info constants",
                remaining_records.len()
            ));
        }
        merged_lines.extend(new_lines);
        merged_lines.extend(preserved_corrupt.iter().cloned());

        // Cap-clamp the rewrite. The standard `append_matrix_inbound_dlq`
        // path enforces MATRIX_INBOUND_DLQ_MAX_RECORDS but this rewrite
        // bypasses that path; without a clamp, an adversary-controlled
        // inbound rate during phase 2 (concurrent new failures) plus
        // dispatch-failed remaining_records can push the merged file past
        // the cap.
        if merged_lines.len() > MATRIX_INBOUND_DLQ_MAX_RECORDS {
            let dropped = merged_lines.len() - MATRIX_INBOUND_DLQ_MAX_RECORDS;
            // Decode the tail slice we're about to truncate so the
            // dropped event IDs land in `cara status` and the journal,
            // not just the count. Without this, operators get
            // "47 records dropped to fit" with no way to know which
            // Matrix events vanished — they can't ask correspondents
            // to resend or audit lost conversations. Decode failures
            // are tolerable (the line was still going to drop) but we
            // log them for forensic completeness.
            let mut decode_failures: usize = 0;
            let dropped_ids: Vec<String> = merged_lines[MATRIX_INBOUND_DLQ_MAX_RECORDS..]
                .iter()
                .filter_map(|line| {
                    match decode_matrix_inbound_dlq_record_with_key(dlq_key.as_ref(), line) {
                        Ok(record) => Some(record.event_id.clone()),
                        Err(err) => {
                            decode_failures += 1;
                            tracing::debug!(
                                error = %err,
                                "could not decode tail-truncated DLQ record for forensic \
                                 event_id capture; record was already going to be dropped"
                            );
                            None
                        }
                    }
                })
                .collect();
            // Encode the dropped event_ids as a JSON array string so log
            // aggregators (Loki/ELK/Datadog) can parse them as a list.
            // `?dropped_ids` would emit Rust Debug format (e.g.
            // `["a", "b"]` with quoting/spacing not guaranteed to be
            // valid JSON), which forces aggregators to either string-
            // match or fall back to per-line regex extraction.
            let dropped_event_ids_json =
                serde_json::to_string(&dropped_ids).expect("Vec<String> always serializes to JSON");
            warn!(
                kept = MATRIX_INBOUND_DLQ_MAX_RECORDS,
                dropped = dropped,
                dropped_event_ids = %dropped_event_ids_json,
                decode_failures = decode_failures,
                "Matrix DLQ replay merge exceeded record cap; truncating to FIFO oldest \
                 (dropping {dropped} most-recent appends to retain dispatch-failed retries)"
            );
            // A WAVE of decode failures (vs a single corrupt record)
            // is a qualitatively different signal — almost always a
            // store-key mismatch from a previous daemon's
            // CARAPACE_CONFIG_PASSWORD or rekey-store rotation.
            // Surface it separately so the operator's investigation
            // path is "check key rotation history", not "ask peers
            // to resend events". Empty `dropped_ids` with a non-zero
            // decode_failures is the giveaway of this case.
            if decode_failures > 0 {
                warn!(
                    decode_failures,
                    dropped,
                    "Matrix DLQ tail-truncation could not decode {decode_failures} of \
                     {dropped} dropped records — likely store-key mismatch from a \
                     prior daemon's CARAPACE_CONFIG_PASSWORD or rekey-store rotation. \
                     Event IDs cannot be recovered for these records; investigate the \
                     key rotation history before assuming events were never received."
                );
            }
            merged_lines.truncate(MATRIX_INBOUND_DLQ_MAX_RECORDS);
            {
                let mut guard = state.write();
                guard.record_inbound_dlq_append_failure(format!(
                    "Matrix inbound DLQ replay merge exceeded {MATRIX_INBOUND_DLQ_MAX_RECORDS}-record cap; \
                     {dropped} records dropped to fit{}",
                    if decode_failures > 0 {
                        format!(" ({decode_failures} unrecoverable due to key mismatch)")
                    } else {
                        String::new()
                    }
                ));
                if !dropped_ids.is_empty() {
                    guard.record_inbound_dlq_lost_event_ids(dropped_ids);
                }
                // Surface the undecodable-but-lost count as a numeric
                // metadata field so an operator running `cara status`
                // (or alerting on `extra.inboundDlqUndecodableLostCount`)
                // sees a signal even when individual IDs cannot be
                // recovered. Without this the only signal lives inside
                // the durability-error free-form string, which is
                // harder to threshold against.
                if decode_failures > 0 {
                    guard.status.inbound_dlq_undecodable_lost_count = guard
                        .status
                        .inbound_dlq_undecodable_lost_count
                        .saturating_add(decode_failures as u64);
                }
            }
        }

        if merged_lines.is_empty() {
            // Nothing left to retain: remove the file entirely so the
            // next replay tick early-returns at the NotFound branch.
            match tokio::fs::remove_file(&path).await {
                Ok(()) => sync_parent_dir_best_effort(&path).await,
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                Err(err) => {
                    log_lost_remaining("remove", &err);
                    return Err(MatrixError::SyncFailed(format!(
                        "remove drained Matrix inbound DLQ {}: {err}",
                        path.display()
                    )));
                }
            }
        } else if let Err(err) = replace_matrix_inbound_dlq_lines(&path, merged_lines).await {
            log_lost_remaining("replace", &err);
            return Err(err);
        }

        if let Some(err) = quarantine_failed_err {
            return Err(MatrixError::SyncFailed(format!(
                "Matrix DLQ replay quarantine failed: {err}"
            )));
        }
    }

    if errors.is_empty() {
        // Full success: drop both the durability error AND the lost-
        // event-id list. A single transient phase-3 hiccup followed
        // by a clean replay should fully clear the operator-visible
        // surface, not pin stale IDs forever.
        let mut guard = state.write();
        guard.clear_inbound_dlq_durability_error();
        guard.clear_inbound_dlq_lost_event_ids();
        return Ok(());
    }
    let total_failures = errors.len();
    let preview: Vec<&str> = errors.iter().take(3).map(String::as_str).collect();
    Err(MatrixError::SyncFailed(format!(
        "Matrix inbound DLQ replay still has {total_failures} undelivered or undecodable record(s); first {}: {}",
        preview.len(),
        preview.join("; ")
    )))
}

async fn dispatch_matrix_dlq_record(
    ws_state: Arc<WsServerState>,
    state: Arc<RwLock<MatrixRuntimeState>>,
    record: &MatrixInboundDlqRecord,
) -> Result<(), MatrixError> {
    crate::channels::inbound::dispatch_inbound_text_with_options(
        &ws_state,
        MATRIX_CHANNEL_ID,
        &record.sender_id,
        &record.room_id,
        &record.text,
        Some(record.room_id.clone()),
        crate::channels::inbound::InboundDispatchOptions {
            inbound_event_id: crate::channels::inbound::IdempotencyKey::from_str_opt(
                &record.event_id,
            ),
            delivery_recipient_id: Some(record.room_id.clone()),
            ..Default::default()
        },
    )
    .await
    .map(|_| {
        state.write().reset_inbound_failures();
    })
    .map_err(|err| MatrixError::SyncFailed(format!("replay Matrix inbound event: {err}")))
}

fn encode_matrix_inbound_dlq_record(
    state_dir: &Path,
    config: &MatrixConfig,
    record: &MatrixInboundDlqRecord,
) -> Result<String, MatrixError> {
    if !config.encrypted() {
        return encode_matrix_inbound_dlq_record_with_key(None, record);
    }
    let key = derive_matrix_inbound_dlq_key(state_dir, config)?;
    encode_matrix_inbound_dlq_record_with_key(Some(&key), record)
}

/// Encode-with-key variant for hot loops that derive the AEAD key
/// once and process N records. The single-record entry point at
/// `encode_matrix_inbound_dlq_record` re-derives the key on every
/// call (one HKDF + one filesystem read of `installation_id`); for
/// the cap-clamp re-encode loop at ~10k records, that's 10k of each.
/// Callers in the hot path derive once and pass the key reference.
fn encode_matrix_inbound_dlq_record_with_key(
    key: Option<&zeroize::Zeroizing<[u8; crate::crypto::AEAD_KEY_LEN]>>,
    record: &MatrixInboundDlqRecord,
) -> Result<String, MatrixError> {
    // Wrap the serialized plaintext in `Zeroizing<Vec<u8>>` so the
    // intermediate buffer that holds the decrypted message body is
    // wiped before the heap allocation is returned to the allocator.
    // The struct's hand-rolled Drop-zeroize on `text` is undermined
    // without this — same plaintext, separate allocation, no zeroize.
    let plaintext = zeroize::Zeroizing::new(serde_json::to_vec(record).map_err(|err| {
        MatrixError::SyncFailed(format!("serialize Matrix inbound DLQ record: {err}"))
    })?);
    let Some(key) = key else {
        // Plaintext branch: copy the bytes into a `String` for return.
        // The Zeroizing<Vec<u8>> is dropped at scope-end and zeroes
        // its bytes; the returned String contains a fresh allocation
        // that the caller is responsible for.
        return String::from_utf8(plaintext.to_vec())
            .map_err(|err| MatrixError::SyncFailed(format!("encode Matrix inbound DLQ: {err}")));
    };
    let blob = crate::crypto::encrypt_aead_blob(key, &plaintext, MATRIX_INBOUND_DLQ_AAD)
        .map_err(|err| MatrixError::SyncFailed(format!("encrypt Matrix inbound DLQ: {err}")))?;
    serde_json::to_string(&MatrixEncryptedInboundDlqRecord {
        version: MATRIX_INBOUND_DLQ_ENVELOPE_VERSION,
        nonce: URL_SAFE_NO_PAD.encode(blob.nonce),
        ciphertext: URL_SAFE_NO_PAD.encode(blob.ciphertext),
    })
    .map_err(|err| {
        MatrixError::SyncFailed(format!("serialize encrypted Matrix inbound DLQ: {err}"))
    })
}

/// Single-record entry point. Hot-loop callers (replay phase 1,
/// cap-clamp tail decode) MUST call
/// `decode_matrix_inbound_dlq_record_with_key` to avoid re-deriving
/// the AEAD key per record. This single-record entry point derives
/// lazily inside the encrypted branch only and is retained for tests
/// + ad-hoc one-off decodes.
#[cfg_attr(not(test), allow(dead_code))]
fn decode_matrix_inbound_dlq_record(
    state_dir: &Path,
    config: &MatrixConfig,
    line: &str,
) -> Result<MatrixInboundDlqRecord, MatrixError> {
    decode_matrix_inbound_dlq_record_inner(state_dir, Some(config), line, None)
}

/// Decode-with-key variant for hot loops. The AEAD key is process-
/// deterministic over `(passphrase, installation_id)`, both fixed for
/// a daemon's lifetime barring rekey, so deriving it 10k times during
/// a cap-clamp tail-truncate is wasted HKDF + 10k filesystem reads of
/// the installation_id file, all under `dlq_io_lock`. Callers derive
/// once before the loop and reuse.
fn decode_matrix_inbound_dlq_record_with_key(
    key: Option<&zeroize::Zeroizing<[u8; crate::crypto::AEAD_KEY_LEN]>>,
    line: &str,
) -> Result<MatrixInboundDlqRecord, MatrixError> {
    decode_matrix_inbound_dlq_record_inner(Path::new(""), None, line, key)
}

fn decode_matrix_inbound_dlq_record_inner(
    state_dir: &Path,
    config: Option<&MatrixConfig>,
    line: &str,
    cached_key: Option<&zeroize::Zeroizing<[u8; crate::crypto::AEAD_KEY_LEN]>>,
) -> Result<MatrixInboundDlqRecord, MatrixError> {
    // Detect the on-disk format by introspecting the line rather than
    // trusting `config.encrypted()`. An operator who flipped
    // `matrix.encrypted` between runs (true→false, then back) would
    // otherwise leave existing records permanently unreplayable —
    // `serde_json::from_str::<MatrixInboundDlqRecord>` would parse the
    // envelope-shaped JSON as plaintext (and fail on missing fields),
    // and the reverse direction parses plaintext lines as envelopes
    // (and fails on missing version/nonce/ciphertext). The envelope
    // is uniquely identifiable by carrying all three of `version`,
    // `nonce`, `ciphertext` at the top level; `MatrixInboundDlqRecord`
    // has none of those.
    let line_is_encrypted = serde_json::from_str::<serde_json::Value>(line)
        .map(|v| {
            v.get("version").is_some() && v.get("nonce").is_some() && v.get("ciphertext").is_some()
        })
        .unwrap_or(false);
    let record = if !line_is_encrypted {
        serde_json::from_str::<MatrixInboundDlqRecord>(line).map_err(|err| {
            MatrixError::SyncFailed(format!("parse Matrix inbound DLQ record: {err}"))
        })?
    } else {
        let envelope: MatrixEncryptedInboundDlqRecord =
            serde_json::from_str(line).map_err(|err| {
                MatrixError::SyncFailed(format!("parse encrypted Matrix inbound DLQ record: {err}"))
            })?;
        if envelope.version != MATRIX_INBOUND_DLQ_ENVELOPE_VERSION {
            return Err(MatrixError::SyncFailed(format!(
                "unsupported Matrix inbound DLQ version {}",
                envelope.version
            )));
        }
        let nonce = decode_matrix_dlq_b64_fixed::<{ crate::crypto::AEAD_NONCE_LEN }>(
            "nonce",
            &envelope.nonce,
        )?;
        let ciphertext = URL_SAFE_NO_PAD
            .decode(envelope.ciphertext.as_bytes())
            .map_err(|err| {
                MatrixError::SyncFailed(format!(
                    "decode encrypted Matrix inbound DLQ ciphertext: {err}"
                ))
            })?;
        // Hot-path callers pass a pre-derived `cached_key`. The
        // single-record entry point passes `None` and derives lazily
        // here using the supplied `config`. One of the two branches
        // is always taken (the `_with_key` API enforces `cached_key`
        // is Some, the canonical API enforces `config` is Some).
        let derived;
        let key = match cached_key {
            Some(k) => k,
            None => {
                let cfg = config.expect(
                    "decode_matrix_inbound_dlq_record_inner: cached_key is None but config is None too",
                );
                derived = derive_matrix_inbound_dlq_key(state_dir, cfg)?;
                &derived
            }
        };
        let plaintext = zeroize::Zeroizing::new(
            crate::crypto::decrypt_aead_blob(key, &nonce, &ciphertext, MATRIX_INBOUND_DLQ_AAD)
                .map_err(|err| {
                    MatrixError::SyncFailed(format!("decrypt Matrix inbound DLQ: {err}"))
                })?,
        );
        serde_json::from_slice::<MatrixInboundDlqRecord>(&plaintext).map_err(|err| {
            MatrixError::SyncFailed(format!("parse decrypted Matrix inbound DLQ: {err}"))
        })?
    };
    // Reject records whose persisted `event_id` cannot produce a valid
    // `IdempotencyKey` — empty/whitespace/control bytes would otherwise
    // bypass replay-time dedupe and allow a redelivered DLQ record to
    // double-dispatch into the agent (since
    // `IdempotencyKey::from_str_opt` returning `None` falls through
    // to a non-deduped dispatch).
    if crate::channels::inbound::IdempotencyKey::from_str_opt(&record.event_id).is_none() {
        return Err(MatrixError::SyncFailed(
            "Matrix inbound DLQ record has invalid event_id (empty, whitespace, or control bytes); \
             refusing to dispatch without an idempotency key"
                .to_string(),
        ));
    }
    Ok(record)
}

fn decode_matrix_dlq_b64_fixed<const N: usize>(
    field: &'static str,
    value: &str,
) -> Result<[u8; N], MatrixError> {
    let decoded = URL_SAFE_NO_PAD.decode(value.as_bytes()).map_err(|err| {
        MatrixError::SyncFailed(format!(
            "decode encrypted Matrix inbound DLQ {field}: {err}"
        ))
    })?;
    decoded.try_into().map_err(|decoded: Vec<u8>| {
        MatrixError::SyncFailed(format!(
            "encrypted Matrix inbound DLQ {field} has wrong length: expected {N}, got {}",
            decoded.len()
        ))
    })
}

fn derive_matrix_inbound_dlq_key(
    state_dir: &Path,
    config: &MatrixConfig,
) -> Result<zeroize::Zeroizing<[u8; crate::crypto::AEAD_KEY_LEN]>, MatrixError> {
    let passphrase = resolve_matrix_store_passphrase(state_dir, config)?
        .ok_or(MatrixError::MissingStoreSecret)?;
    let installation_id = read_or_create_installation_id(state_dir)?;
    derive_matrix_inbound_dlq_key_from(passphrase.as_bytes(), installation_id.as_bytes())
}

/// Pure HKDF-SHA256 derivation for the Matrix inbound-DLQ encryption
/// key. Extracted so a pinned test vector locks the derivation
/// against silent drift — `MATRIX_INBOUND_DLQ_INFO` is the per-domain
/// info string; rotating it would be a wire-format break (operators
/// would lose access to existing on-disk DLQ records).
fn derive_matrix_inbound_dlq_key_from(
    passphrase: &[u8],
    installation_id: &[u8],
) -> Result<zeroize::Zeroizing<[u8; crate::crypto::AEAD_KEY_LEN]>, MatrixError> {
    let hk = Hkdf::<Sha256>::new(Some(installation_id), passphrase);
    // Same Zeroize discipline as `derive_matrix_store_key` — the
    // AEAD key for DLQ blobs never sits unzeroed on the stack.
    let mut key = zeroize::Zeroizing::new([0u8; crate::crypto::AEAD_KEY_LEN]);
    hk.expand(MATRIX_INBOUND_DLQ_INFO, &mut *key)
        .map_err(|_| MatrixError::StoreKeyDerivation)?;
    Ok(key)
}

async fn append_matrix_inbound_dlq_line(path: &Path, line: String) -> Result<(), MatrixError> {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || append_matrix_inbound_dlq_line_blocking(&path, &line))
        .await
        .map_err(|err| MatrixError::SyncFailed(format!("Matrix inbound DLQ append task: {err}")))?
}

#[cfg(unix)]
fn append_matrix_inbound_dlq_line_blocking(path: &Path, line: &str) -> Result<(), MatrixError> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let existed = path.exists();
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(path)
        .map_err(|err| MatrixError::SyncFailed(format!("open Matrix inbound DLQ: {err}")))?;
    if existed {
        let mut permissions = file
            .metadata()
            .map_err(|err| MatrixError::SyncFailed(format!("stat Matrix inbound DLQ: {err}")))?
            .permissions();
        if permissions.mode() & 0o777 != 0o600 {
            permissions.set_mode(0o600);
            file.set_permissions(permissions).map_err(|err| {
                MatrixError::SyncFailed(format!("chmod Matrix inbound DLQ: {err}"))
            })?;
        }
    }
    file.write_all(line.as_bytes())
        .and_then(|_| file.write_all(b"\n"))
        .and_then(|_| file.sync_all())
        .map_err(|err| MatrixError::SyncFailed(format!("write Matrix inbound DLQ: {err}")))?;
    if !existed {
        sync_parent_dir_best_effort_blocking(path);
    }
    Ok(())
}

#[cfg(not(unix))]
fn append_matrix_inbound_dlq_line_blocking(path: &Path, line: &str) -> Result<(), MatrixError> {
    use std::io::Write;

    let existed = path.exists();
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|err| MatrixError::SyncFailed(format!("open Matrix inbound DLQ: {err}")))?;
    file.write_all(line.as_bytes())
        .and_then(|_| file.write_all(b"\n"))
        .and_then(|_| file.sync_all())
        .map_err(|err| MatrixError::SyncFailed(format!("write Matrix inbound DLQ: {err}")))?;
    if !existed {
        sync_parent_dir_best_effort_blocking(path);
    }
    Ok(())
}

async fn replace_matrix_inbound_dlq_lines(
    path: &Path,
    lines: Vec<String>,
) -> Result<(), MatrixError> {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || replace_matrix_inbound_dlq_lines_blocking(&path, &lines))
        .await
        .map_err(|err| MatrixError::SyncFailed(format!("Matrix inbound DLQ rewrite task: {err}")))?
}

#[cfg(unix)]
fn replace_matrix_inbound_dlq_lines_blocking(
    path: &Path,
    lines: &[String],
) -> Result<(), MatrixError> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let tmp_path = secret_file_temp_path(path);
    let write_result = (|| {
        let mut file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&tmp_path)
            .map_err(|err| {
                MatrixError::SyncFailed(format!("create Matrix inbound DLQ temp: {err}"))
            })?;
        for line in lines {
            file.write_all(line.as_bytes())
                .and_then(|_| file.write_all(b"\n"))
                .map_err(|err| {
                    MatrixError::SyncFailed(format!("write Matrix inbound DLQ temp: {err}"))
                })?;
        }
        file.sync_all().map_err(|err| {
            MatrixError::SyncFailed(format!("sync Matrix inbound DLQ temp: {err}"))
        })?;
        std::fs::rename(&tmp_path, path)
            .map_err(|err| MatrixError::SyncFailed(format!("replace Matrix inbound DLQ: {err}")))?;
        // Propagate fsync errors. A silent failure here would let an
        // empty-on-rename DLQ replay-rewrite revert to the OLD file
        // on power loss, re-dispatching events the session-history
        // dedupe might miss if the session file is also affected.
        sync_parent_dir_or_err_blocking(path)?;
        Ok(())
    })();
    if write_result.is_err() {
        let _ = std::fs::remove_file(&tmp_path);
    }
    write_result
}

#[cfg(not(unix))]
fn replace_matrix_inbound_dlq_lines_blocking(
    path: &Path,
    lines: &[String],
) -> Result<(), MatrixError> {
    use std::io::Write;

    let tmp_path = secret_file_temp_path(path);
    let write_result = (|| {
        let mut file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&tmp_path)
            .map_err(|err| {
                MatrixError::SyncFailed(format!("create Matrix inbound DLQ temp: {err}"))
            })?;
        for line in lines {
            file.write_all(line.as_bytes())
                .and_then(|_| file.write_all(b"\n"))
                .map_err(|err| {
                    MatrixError::SyncFailed(format!("write Matrix inbound DLQ temp: {err}"))
                })?;
        }
        file.sync_all().map_err(|err| {
            MatrixError::SyncFailed(format!("sync Matrix inbound DLQ temp: {err}"))
        })?;
        std::fs::rename(&tmp_path, path)
            .map_err(|err| MatrixError::SyncFailed(format!("replace Matrix inbound DLQ: {err}")))?;
        // Same C4 propagation as the Unix branch — see the explanation
        // there.
        sync_parent_dir_or_err_blocking(path)?;
        Ok(())
    })();
    if write_result.is_err() {
        let _ = std::fs::remove_file(&tmp_path);
    }
    write_result
}

/// Async wrapper around the shared best-effort blocking helper. Used
/// on cleanup paths where a primary error is already in flight and
/// the fsync result is purely defensive.
async fn sync_parent_dir_best_effort(path: &Path) {
    let path = path.to_path_buf();
    let _ = tokio::task::spawn_blocking(move || {
        crate::paths::sync_parent_dir_best_effort_blocking(&path)
    })
    .await;
}

fn sync_parent_dir_best_effort_blocking(path: &Path) {
    crate::paths::sync_parent_dir_best_effort_blocking(path);
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
    let room_id =
        RoomId::parse(ctx.to.as_str()).map_err(|_| MatrixError::RoomNotFound(ctx.to.clone()))?;
    let room = client
        .get_room(&room_id)
        .ok_or_else(|| MatrixError::RoomNotFound(ctx.to.clone()))?;
    if !is_room_supported(&room, config.encrypted()) {
        return Err(MatrixError::UnsupportedRoom(format!(
            "{} is encrypted but matrix.encrypted=false",
            room.room_id()
        )));
    }
    let content = RoomMessageEventContent::text_plain(ctx.text);
    let response = tokio::time::timeout(MATRIX_SEND_TIMEOUT, room.send(content))
        .await
        .map_err(|_| {
            MatrixError::SendFailed(format!(
                "Matrix send timed out after {} seconds",
                MATRIX_SEND_TIMEOUT.as_secs()
            ))
        })?
        // Classify the SDK error: terminal classes (M_FORBIDDEN,
        // M_UNKNOWN_TOKEN, M_TOO_LARGE, M_GUEST_ACCESS_FORBIDDEN,
        // M_BAD_JSON) become `SendTerminal` so the binding router
        // returns a non-retryable failure instead of looping the
        // pipeline through three doomed attempts. Transient or
        // unclassified errors stay `SendFailed` (retryable).
        .map_err(|err| {
            matrix_send_terminal_error(&err)
                .unwrap_or_else(|| MatrixError::SendFailed(err.to_string()))
        })?;
    Ok(DeliveryResult {
        ok: true,
        message_id: Some(response.event_id.to_string()),
        error: None,
        retryable: false,
        conversation_id: Some(room.room_id().to_string()),
        to_jid: None,
        poll_id: None,
    })
}

fn matrix_retryable_delivery_result(error: String) -> DeliveryResult {
    DeliveryResult {
        ok: false,
        message_id: None,
        error: Some(error),
        retryable: true,
        conversation_id: None,
        to_jid: None,
        poll_id: None,
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
    let mut failures = Vec::new();
    for room in client.invited_rooms() {
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
        let room_id_san = sanitize_homeserver_identifier(room.room_id().as_str());
        let invite = match room.invite_details().await {
            Ok(invite) => invite,
            Err(err) => {
                warn!(room_id = %room_id_san, error = %err, "failed to inspect Matrix invite");
                // Wrap the SDK error display in `RedactedDisplay` so
                // homeserver-controlled bytes (`error` field of the
                // HTTP response) are stripped before they land in the
                // failures Vec. The summary feeds
                // `record_invite_systemic_failure`, which surfaces at
                // `last_error` JSON — a path that bypasses the
                // tracing-writer-layer redactor entirely.
                failures.push(format!(
                    "{} inspect failed: {}",
                    room_id_san,
                    crate::logging::redact::RedactedDisplay(&err)
                ));
                continue;
            }
        };
        let inviter = invite
            .inviter
            .as_ref()
            .map(|member| member.user_id().to_string());
        let inviter_san = inviter.as_deref().map(sanitize_homeserver_identifier);
        let allowed = inviter
            .as_deref()
            .map(|user_id| config.auto_join.allows_user(user_id))
            .unwrap_or(false);
        if !allowed {
            // Distinguish two reasons for rejection so an operator
            // checking logs doesn't conclude their allowlist is
            // misconfigured when the homeserver actually withheld the
            // inviter identity. Logged at info-level (not debug) since
            // a one-off allowlist mismatch is the most common operator
            // misconfig and won't fire MATRIX_INVITE_SYSTEMIC_FAILURE_THRESHOLD
            // — the operator needs visibility at default log filter.
            // Includes allowlist cardinality for triage.
            if inviter.is_none() {
                info!(
                    room_id = %room_id_san,
                    allow_users_count = config.auto_join.allow_users.len(),
                    allow_server_names_count = config.auto_join.allow_server_names.len(),
                    "Matrix invite rejected: homeserver did not provide an inviter identity"
                );
            } else {
                info!(
                    room_id = %room_id_san,
                    inviter = inviter_san.as_deref().unwrap_or("<unknown>"),
                    allow_users_count = config.auto_join.allow_users.len(),
                    allow_server_names_count = config.auto_join.allow_server_names.len(),
                    "Matrix invite rejected by auto-join allowlist"
                );
            }
            if let Err(err) = room.leave().await {
                warn!(room_id = %room_id_san, error = %err, "failed to reject Matrix invite");
                failures.push(format!(
                    "{} reject failed: {}",
                    room_id_san,
                    crate::logging::redact::RedactedDisplay(&err)
                ));
            }
            continue;
        }
        if !config.encrypted() && is_invite_room_definitely_encrypted(&room) {
            warn!(
                room_id = %room_id_san,
                inviter = inviter_san.as_deref().unwrap_or("<unknown>"),
                "Matrix invite refused because room is encrypted and matrix.encrypted=false"
            );
            if let Err(err) = room.leave().await {
                warn!(room_id = %room_id_san, error = %err, "failed to reject encrypted Matrix invite");
                failures.push(format!(
                    "{} encrypted reject failed: {}",
                    room_id_san,
                    crate::logging::redact::RedactedDisplay(&err)
                ));
            }
            continue;
        }
        if let Err(err) = room.join().await {
            warn!(room_id = %room_id_san, error = %err, "failed to auto-join Matrix invite");
            failures.push(format!(
                "{} join failed: {}",
                room_id_san,
                crate::logging::redact::RedactedDisplay(&err)
            ));
        } else {
            info!(
                room_id = %room_id_san,
                inviter = inviter_san.as_deref().unwrap_or("<unknown>"),
                "auto-joined Matrix room invite"
            );
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        // Truncate the aggregated message so journald / log forwarders
        // don't truncate it themselves with no preview. First 3 entries
        // give operators an actionable sample; the count tells them how
        // wide the impact is.
        let total = failures.len();
        let preview: Vec<&str> = failures.iter().take(3).map(String::as_str).collect();
        let summary = if total <= preview.len() {
            failures.join("; ")
        } else {
            format!("{} ({} more)", preview.join("; "), total - preview.len())
        };
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
        if total >= MATRIX_INVITE_SYSTEMIC_FAILURE_THRESHOLD {
            state.write().record_invite_systemic_failure(format!(
                "Matrix invite handling: {total} failures in one maintenance tick: {summary} \
                 — check homeserver connectivity and matrix.autoJoin allowlist"
            ));
        }
        Err(MatrixError::SyncFailed(format!(
            "Matrix invite handling failures ({total}): {summary}"
        )))
    }
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
                warn!(
                    room_id = %room_id,
                    "Matrix room became encrypted while matrix.encrypted=false; marking unsupported"
                );
            }
        } else {
            unencrypted_room_count += 1;
        }
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
    let devices = devices
        .devices()
        .take(MATRIX_DEVICE_LIST_MAX)
        .map(|device| MatrixDeviceInfo {
            // Sanitize peer-controlled identifiers and display name:
            // ruma's `OwnedDeviceId` validator is a no-op so device_id
            // can carry ANSI escapes or bidi codepoints. user_id is
            // structurally constrained but defense-in-depth applies
            // the same filter so the JSON wire and CLI consumers
            // (especially the SAS-confirm prompt at cli/mod.rs:1243)
            // see only printable, non-bidi characters.
            user_id: sanitize_homeserver_identifier(device.user_id().as_str()),
            device_id: sanitize_homeserver_identifier(device.device_id().as_str()),
            display_name: device
                .display_name()
                .map(sanitize_matrix_display_name)
                .filter(|s| !s.is_empty()),
            verified: device.is_verified(),
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
    if let Some(mut info) = registry.get(MATRIX_CHANNEL_ID) {
        info.metadata.extra = Some(json!(status));
        registry.register(info);
    }
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

/// Result of starting a Matrix verification flow.
///
/// Carries the upsert insertion flag so the caller can construct
/// `NewVerificationFlow::from_upsert(info, inserted)` and emit the
/// `matrix.verification.requested` event ONLY when the flow is fresh.
/// Without this, an operator-initiated `start-verification` for a peer
/// whose request already arrived inbound would re-broadcast
/// `requested` on top of the inbound-handler's broadcast, duplicating
/// UI notifications.
pub(crate) struct MatrixStartVerificationOutcome {
    pub info: MatrixVerificationInfo,
    pub inserted: bool,
}

async fn start_matrix_verification(
    client: Arc<Client>,
    state: &Arc<RwLock<MatrixRuntimeState>>,
    user_id: String,
    device_id: Option<String>,
) -> Result<MatrixStartVerificationOutcome, MatrixError> {
    let parsed_user_id: OwnedUserId = user_id
        .parse::<OwnedUserId>()
        .map_err(|err| MatrixError::InvalidUserId(err.to_string()))?;
    let request = if let Some(device_id) = device_id.as_deref() {
        let parsed_device_id: OwnedDeviceId = device_id.into();
        let device = client
            .encryption()
            .get_device(&parsed_user_id, &parsed_device_id)
            .await
            .map_err(|err| MatrixError::Verification(err.to_string()))?
            .ok_or_else(|| MatrixError::DeviceNotFound {
                user_id: user_id.clone(),
                device_id: device_id.to_string(),
            })?;
        device
            .request_verification()
            .await
            .map_err(|err| MatrixError::Verification(err.to_string()))?
    } else {
        let identity = client
            .encryption()
            .request_user_identity(&parsed_user_id)
            .await
            .map_err(|err| MatrixError::Verification(err.to_string()))?
            .ok_or_else(|| MatrixError::UserIdentityNotFound(user_id.clone()))?;
        identity
            .request_verification()
            .await
            .map_err(|err| MatrixError::Verification(err.to_string()))?
    };
    let state_label = verification_request_state_label(&request.state());
    let (info, inserted) = upsert_verification_record(
        state,
        request.flow_id().to_string(),
        user_id,
        device_id,
        state_label,
    );
    Ok(MatrixStartVerificationOutcome { info, inserted })
}

fn matrix_verification_control_id(user_id: &str, protocol_flow_id: &str) -> String {
    URL_SAFE_NO_PAD.encode(json!([user_id, protocol_flow_id]).to_string())
}

fn upsert_verification_record(
    state: &Arc<RwLock<MatrixRuntimeState>>,
    protocol_flow_id: String,
    user_id: String,
    device_id: Option<String>,
    flow_state: MatrixVerificationState,
) -> (MatrixVerificationInfo, bool) {
    // Sanitize at the boundary so every consumer (CLI SAS confirm
    // prompt, JSON wire, structured logs, WS broadcasts) sees only
    // printable non-bidi chars. ruma's `OwnedDeviceId` validator is
    // a no-op so without sanitization an adversarial peer can craft
    // a device_id containing ANSI escapes that paint a fake
    // verification prompt. user_id and protocol_flow_id are
    // sanitized for defense-in-depth.
    let user_id = sanitize_homeserver_identifier(&user_id);
    let device_id = device_id.map(|d| sanitize_homeserver_identifier(&d));
    let protocol_flow_id = sanitize_homeserver_identifier(&protocol_flow_id);
    let now = now_millis();
    let flow_id = matrix_verification_control_id(&user_id, &protocol_flow_id);
    let mut guard = state.write();
    if let Some(flow) = guard
        .verifications
        .iter_mut()
        .find(|flow| flow.flow_id == flow_id)
    {
        flow.protocol_flow_id = protocol_flow_id;
        flow.user_id = user_id;
        flow.device_id = device_id;
        flow.state = flow_state;
        // Preserve any previously captured SAS data on re-upsert. A
        // duplicate verification request from the peer (or a refresh
        // racing the upsert) would otherwise clear the emoji/decimals
        // the operator was about to compare. Fresh SAS data flows in
        // via `refresh_verification_records` which calls
        // `update_verification_record_state` with `Some(sas)` whenever
        // the SDK exposes new SAS values.
        flow.updated_at = now;
        let flow = flow.clone();
        return (flow, false);
    }
    // Enforce a hard cap before insert so a flood of fresh flow_ids
    // (allowlisted peer spam, redelivery storm) cannot grow the Vec
    // unbounded between TTL prunes. Eviction priority: drop the
    // oldest TERMINAL record first (Cancelled/Done/Mismatched —
    // these are due for TTL pruning anyway). Only fall back to the
    // oldest non-terminal if no terminal records exist.
    //
    // This protects the operator's pending flow when AT LEAST ONE
    // terminal record is present. The all-non-terminal case (pure
    // peer spam in `Requested` state, no completion in flight) still
    // hits the operator's flow at index 0; TTL pruning is the
    // backstop there.
    if guard.verifications.len() >= MATRIX_VERIFICATION_RECORDS_MAX {
        let drop_index = guard
            .verifications
            .iter()
            .position(|f| f.state.is_terminal())
            .or_else(|| {
                guard
                    .verifications
                    .iter()
                    .position(|f| !f.state.is_terminal())
            })
            .unwrap_or(0);
        let dropped = guard.verifications.remove(drop_index);
        warn!(
            cap = MATRIX_VERIFICATION_RECORDS_MAX,
            dropped_flow_id = %dropped.flow_id,
            dropped_state = %dropped.state,
            dropped_was_terminal = dropped.state.is_terminal(),
            "Matrix verification records hit cap; evicting oldest record \
             (terminal-first) — may indicate a peer flooding fresh flow ids"
        );
    }
    let flow = MatrixVerificationInfo {
        flow_id,
        protocol_flow_id,
        user_id,
        device_id,
        state: flow_state,
        sas: None,
        created_at: now,
        updated_at: now,
    };
    guard.verifications.push(flow.clone());
    (flow, true)
}

async fn apply_verification_action(
    client: Arc<Client>,
    state: &Arc<RwLock<MatrixRuntimeState>>,
    flow_id: &str,
    action: MatrixVerificationAction,
) -> Result<MatrixVerificationInfo, MatrixError> {
    let flow = state
        .read()
        .verifications
        .iter()
        .find(|flow| flow.flow_id == flow_id)
        .cloned()
        .ok_or_else(|| MatrixError::VerificationFlowNotFound(flow_id.to_string()))?;
    // Reject Accept/Confirm against an already-terminal flow with a
    // typed `VerificationCancelled` rather than `VerificationFlowNotReady`.
    // Cancelled/Done/Mismatched are permanent — retrying issues the
    // same SDK request and earns the same SDK rejection. Distinct
    // status code (HTTP 410 vs 409) helps the CLI/operator distinguish
    // "peer cancelled while you were typing" (security-relevant —
    // investigate why) from "you're racing the SDK" (transient —
    // retry). Exhaustive match (not `matches!`) so a future
    // MatrixVerificationAction variant compile-fails here, forcing
    // the contributor to deliberately classify whether the new
    // action needs the terminal-state guard.
    let needs_terminal_guard = match action {
        MatrixVerificationAction::Accept | MatrixVerificationAction::Confirm { .. } => true,
        // Cancel is idempotent on terminal flows.
        MatrixVerificationAction::Cancel => false,
    };
    if needs_terminal_guard && flow.state.is_terminal() {
        return Err(MatrixError::VerificationCancelled {
            flow_id: flow_id.to_string(),
            state: flow.state,
        });
    }
    let parsed_user_id: OwnedUserId = flow
        .user_id
        .parse::<OwnedUserId>()
        .map_err(|err| MatrixError::InvalidUserId(err.to_string()))?;
    let protocol_flow_id = flow.protocol_flow_id.clone();

    let next_state = match action {
        MatrixVerificationAction::Accept => {
            let mut accepted = false;
            let mut next_state = None;
            let mut next_sas = None;
            if let Some(request) = client
                .encryption()
                .get_verification_request(&parsed_user_id, &protocol_flow_id)
                .await
            {
                request
                    .accept()
                    .await
                    .map_err(|err| MatrixError::Verification(err.to_string()))?;
                accepted = true;
                if request.is_ready() {
                    if let Some(sas) = request
                        .start_sas()
                        .await
                        .map_err(|err| MatrixError::Verification(err.to_string()))?
                    {
                        next_sas = matrix_sas_info(&sas);
                        next_state = Some(sas_state_label(&sas.state()));
                    }
                }
                if next_state.is_none() {
                    next_state = Some(verification_request_state_label(&request.state()));
                }
            }
            if !accepted {
                if let Some(sas) = client
                    .encryption()
                    .get_verification(&parsed_user_id, &protocol_flow_id)
                    .await
                    .and_then(|verification| verification.sas())
                {
                    sas.accept()
                        .await
                        .map_err(|err| MatrixError::Verification(err.to_string()))?;
                    accepted = true;
                    next_sas = matrix_sas_info(&sas);
                    next_state = Some(sas_state_label(&sas.state()));
                }
            }
            if !accepted {
                return Err(MatrixError::VerificationFlowNotReady {
                    flow_id: flow_id.to_string(),
                    action: "accept",
                });
            }
            let final_state = next_state.unwrap_or(MatrixVerificationState::Accepted);
            (final_state, next_sas)
        }
        MatrixVerificationAction::Confirm { matches } => {
            // Refuse to call sas.confirm() unless the daemon has
            // previously captured SAS data for this flow. The stored
            // `flow.sas` is populated by `refresh_verification_records`
            // (called on every successful sync) and surfaced via the
            // verifications GET endpoint so the operator can compare
            // emoji/decimals before confirming. Without this guard, an
            // operator who knows a flow_id can confirm a verification
            // they have never seen the SAS for, defeating the entire
            // point of SAS verification (a MITM-resistant manual
            // comparison).
            if flow.sas.is_none() {
                return Err(MatrixError::VerificationFlowNotReady {
                    flow_id: flow_id.to_string(),
                    action: "confirm",
                });
            }
            let Some(sas) = client
                .encryption()
                .get_verification(&parsed_user_id, &protocol_flow_id)
                .await
                .and_then(|verification| verification.sas())
            else {
                return Err(MatrixError::VerificationFlowNotReady {
                    flow_id: flow_id.to_string(),
                    action: "confirm",
                });
            };
            if matches {
                sas.confirm()
                    .await
                    .map_err(|err| MatrixError::Verification(err.to_string()))?;
                (sas_state_label(&sas.state()), matrix_sas_info(&sas))
            } else {
                sas.mismatch()
                    .await
                    .map_err(|err| MatrixError::Verification(err.to_string()))?;
                (MatrixVerificationState::Mismatched, matrix_sas_info(&sas))
            }
        }
        MatrixVerificationAction::Cancel => {
            let mut cancelled = false;
            let mut sas_info: Option<MatrixSasInfo> = None;
            if let Some(request) = client
                .encryption()
                .get_verification_request(&parsed_user_id, &protocol_flow_id)
                .await
            {
                request
                    .cancel()
                    .await
                    .map_err(|err| MatrixError::Verification(err.to_string()))?;
                cancelled = true;
            }
            if let Some(sas) = client
                .encryption()
                .get_verification(&parsed_user_id, &protocol_flow_id)
                .await
                .and_then(|verification| verification.sas())
            {
                sas_info = matrix_sas_info(&sas);
                sas.cancel()
                    .await
                    .map_err(|err| MatrixError::Verification(err.to_string()))?;
                cancelled = true;
            }
            if !cancelled {
                // Cancel is idempotent: if the SDK no longer has either
                // a request or SAS view but our local record is already
                // terminal (e.g. previously cancelled, or the SDK
                // garbage-collected after a peer-side cancel), treat
                // this as a no-op success rather than 409 ConflictNotReady.
                if flow.state.is_terminal() {
                    return Ok(flow);
                }
                return Err(MatrixError::VerificationFlowNotReady {
                    flow_id: flow_id.to_string(),
                    action: "cancel",
                });
            }
            (MatrixVerificationState::Cancelled, sas_info)
        }
    };

    update_verification_record_state(
        state,
        flow_id,
        next_state.0,
        SasUpdate::from_optional(next_state.1),
    )?;
    let info = state
        .read()
        .verifications
        .iter()
        .find(|f| f.flow_id == flow_id)
        .cloned()
        .ok_or_else(|| MatrixError::VerificationFlowNotFound(flow_id.to_string()))?;
    prune_finished_verification_records(state);
    Ok(info)
}

/// How a verification-state update should treat the stored SAS data.
///
/// Earlier the helper accepted `Option<MatrixSasInfo>` where `None`
/// meant "preserve" — the signature read as "no SAS available," which
/// was the opposite of the actual behavior (preserve). Encoding the
/// choice in a sum type makes call sites self-documenting and prevents
/// a contributor from accidentally clobbering SAS by passing `None`
/// when they meant "I have no fresh SAS to install."
#[derive(Debug, Clone)]
enum SasUpdate {
    /// Keep `flow.sas` as-is. Used by the refresh path when the SDK
    /// surfaces only a `VerificationRequest` view (no active SAS) so
    /// the operator's previously captured emoji/decimals don't vanish
    /// across state transitions.
    Preserve,
    /// Replace `flow.sas` with the fresh SAS data captured from the
    /// SDK after a SAS-state-producing transition.
    Set(MatrixSasInfo),
}

impl SasUpdate {
    fn from_optional(sas: Option<MatrixSasInfo>) -> Self {
        match sas {
            Some(sas) => SasUpdate::Set(sas),
            None => SasUpdate::Preserve,
        }
    }
}

fn update_verification_record_state(
    state: &Arc<RwLock<MatrixRuntimeState>>,
    flow_id: &str,
    next_state: MatrixVerificationState,
    sas: SasUpdate,
) -> Result<Option<MatrixVerificationInfo>, MatrixError> {
    let mut guard = state.write();
    let Some(flow) = guard
        .verifications
        .iter_mut()
        .find(|flow| flow.flow_id == flow_id)
    else {
        return Err(MatrixError::VerificationFlowNotFound(flow_id.to_string()));
    };
    let next_sas = match sas {
        SasUpdate::Set(sas) => Some(sas),
        SasUpdate::Preserve => flow.sas.clone(),
    };
    if flow.state == next_state && flow.sas == next_sas {
        return Ok(None);
    }
    flow.updated_at = now_millis();
    flow.sas = next_sas;
    flow.state = next_state;
    Ok(Some(flow.clone()))
}

async fn refresh_verification_records(
    client: Arc<Client>,
    state: &Arc<RwLock<MatrixRuntimeState>>,
    ws_state: &Arc<WsServerState>,
) -> Result<(), MatrixError> {
    prune_verification_records(state);
    let records = state.read().verifications.clone();
    for record in records {
        let parsed_user_id: OwnedUserId = match record.user_id.parse() {
            Ok(user_id) => user_id,
            Err(err) => {
                // Skip the record rather than aborting the loop. With
                // inline broadcasts, an early `return Err` would emit
                // the broadcasts that already landed but skip every
                // remaining record — mid-loop partial progress with
                // no recovery on the next tick. A malformed stored
                // user_id is operator-visible at warn level and the
                // record will be pruned by TTL eventually.
                warn!(
                    flow_id = %record.flow_id,
                    error = %err,
                    "invalid Matrix verification user ID; skipping record this tick",
                );
                continue;
            }
        };
        // Always probe both the request view AND the SAS view. The
        // earlier short-circuit (`if Some(request) -> use request, else if
        // Some(sas) -> use sas`) meant a flow that advanced from
        // request-state into SAS-state without garbage-collecting the
        // request would never refresh its SAS into our local record —
        // and combined with the confirm-requires-flow.sas guard, that
        // could leave a valid SAS-state flow stuck unable to confirm.
        let request = client
            .encryption()
            .get_verification_request(&parsed_user_id, &record.protocol_flow_id)
            .await;
        let sas = client
            .encryption()
            .get_verification(&parsed_user_id, &record.protocol_flow_id)
            .await
            .and_then(|verification| verification.sas());
        let (next_state, next_sas) = match (request, sas) {
            (_, Some(sas)) => (sas_state_label(&sas.state()), matrix_sas_info(&sas)),
            (Some(request), None) => (verification_request_state_label(&request.state()), None),
            (None, None) => {
                debug!(
                    flow_id = %record.flow_id,
                    "Matrix verification record has no SDK view; awaiting prune"
                );
                continue;
            }
        };
        match update_verification_record_state(
            state,
            &record.flow_id,
            next_state,
            SasUpdate::from_optional(next_sas),
        ) {
            Ok(Some(updated)) => {
                // Broadcast immediately after each successful state
                // mutation. The previous shape collected updates into a
                // Vec and broadcast at the end, but the call site wraps
                // this future in a 30-second timeout — a mid-iteration
                // cancel dropped the Vec while the state mutations had
                // already landed, and the next refresh's `Ok(None)`
                // dedupe meant the broadcast was permanently lost.
                // Broadcasting inline guarantees every mutation that
                // commits to state is also delivered to clients.
                crate::server::ws::broadcast_matrix_verification_updated(
                    ws_state,
                    crate::server::ws::UpdatedVerificationFlow::for_state_change(&updated),
                );
            }
            Ok(None) => {}
            Err(err) => {
                debug!(
                    flow_id = %record.flow_id,
                    error = %err,
                    "Matrix verification update skipped (record disappeared mid-refresh)"
                );
                continue;
            }
        }
    }
    prune_finished_verification_records(state);
    Ok(())
}

fn verification_request_state_label(state: &VerificationRequestState) -> MatrixVerificationState {
    match state {
        VerificationRequestState::Created { .. } => MatrixVerificationState::Created,
        VerificationRequestState::Requested { .. } => MatrixVerificationState::Requested,
        VerificationRequestState::Ready { .. } => MatrixVerificationState::Ready,
        VerificationRequestState::Transitioned { .. } => MatrixVerificationState::Transitioned,
        VerificationRequestState::Done => MatrixVerificationState::Done,
        VerificationRequestState::Cancelled(_) => MatrixVerificationState::Cancelled,
    }
}

fn sas_state_label(state: &SasState) -> MatrixVerificationState {
    match state {
        SasState::Created { .. } => MatrixVerificationState::Created,
        SasState::Started { .. } => MatrixVerificationState::Started,
        SasState::Accepted { .. } => MatrixVerificationState::Accepted,
        SasState::KeysExchanged { .. } => MatrixVerificationState::KeysExchanged,
        SasState::Confirmed => MatrixVerificationState::Confirmed,
        SasState::Done { .. } => MatrixVerificationState::Done,
        SasState::Cancelled(_) => MatrixVerificationState::Cancelled,
    }
}

fn matrix_sas_info(sas: &SasVerification) -> Option<MatrixSasInfo> {
    let emoji = sas.emoji().map(|emojis| {
        emojis
            .iter()
            .map(|emoji| MatrixSasEmoji {
                symbol: emoji.symbol.to_string(),
                description: emoji.description.to_string(),
            })
            .collect::<Vec<_>>()
    });
    let decimals = sas
        .decimals()
        .map(|(first, second, third)| [first, second, third]);
    if emoji.is_none() && decimals.is_none() {
        None
    } else {
        Some(MatrixSasInfo { emoji, decimals })
    }
}

fn prune_verification_records(state: &Arc<RwLock<MatrixRuntimeState>>) {
    let now = match try_now_millis() {
        Ok(now) => now,
        Err(err) => {
            warn!(error = %err, "skipping Matrix verification prune because wall clock is invalid");
            return;
        }
    };
    let cutoff = now.saturating_sub(MATRIX_VERIFICATION_RECORD_TTL.as_millis() as i64);
    let mut guard = state.write();
    guard.verifications.retain(|flow| flow.updated_at >= cutoff);
}

fn prune_finished_verification_records(state: &Arc<RwLock<MatrixRuntimeState>>) {
    let mut guard = state.write();
    guard.verifications.retain(|flow| !flow.state.is_terminal());
}

fn matrix_retry_after(err: &matrix_sdk::Error) -> Option<Duration> {
    match err.client_api_error_kind()? {
        matrix_sdk::ruma::api::client::error::ErrorKind::LimitExceeded {
            retry_after: Some(matrix_sdk::ruma::api::client::error::RetryAfter::Delay(delay)),
        } => Some(*delay),
        _ => None,
    }
}

/// Pure classifier shared by `matrix_sync_terminal_error` (for
/// `matrix_sdk::Error`) and `matrix_http_terminal_error` (for
/// `matrix_sdk::HttpError`). Returning `Some` means the homeserver has
/// declared the token unusable and the runtime should exit with the
/// supplied display string as the operator-visible cause.
fn classify_terminal_kind(
    kind: &matrix_sdk::ruma::api::client::error::ErrorKind,
    display: impl FnOnce() -> String,
) -> Option<MatrixError> {
    use matrix_sdk::ruma::api::client::error::ErrorKind;
    match kind {
        // Per Matrix spec, all five of these block ALL client actions
        // — sync, send, verification — so the sync-loop terminal
        // classifier and the send-path terminal classifier should
        // both see them as terminal. Without UserLocked/UserSuspended
        // here, an account locked/suspended mid-sync would keep
        // retrying forever (the send path classifies them via
        // `matrix_send_terminal_error`, but sync uses this fn).
        ErrorKind::UnknownToken { .. }
        | ErrorKind::Forbidden { .. }
        | ErrorKind::UserDeactivated
        | ErrorKind::UserLocked
        | ErrorKind::UserSuspended => Some(MatrixError::AuthTokenRevoked(display())),
        _ => None,
    }
}

fn matrix_sync_terminal_error(err: &matrix_sdk::Error) -> Option<MatrixError> {
    classify_terminal_kind(err.client_api_error_kind()?, || err.to_string())
}

/// Wider classifier for `room.send` errors. Includes the auth-class
/// terminal kinds from `classify_terminal_kind` plus send-specific
/// permanent failures (oversized payload, guest forbidden, malformed
/// body) the homeserver has explicitly rejected. Returning `Some`
/// means the dispatch pipeline should NOT retry — the next attempt
/// would fail identically.
fn matrix_send_terminal_error(err: &matrix_sdk::Error) -> Option<MatrixError> {
    use matrix_sdk::ruma::api::client::error::ErrorKind;
    let kind = err.client_api_error_kind()?;
    if let Some(terminal) = classify_terminal_kind(kind, || err.to_string()) {
        return Some(terminal);
    }
    match kind {
        ErrorKind::TooLarge
        | ErrorKind::GuestAccessForbidden
        | ErrorKind::BadJson
        | ErrorKind::Unrecognized => Some(MatrixError::SendTerminal(err.to_string())),
        // UserLocked / UserSuspended are now handled inside
        // `classify_terminal_kind` so both sync and send paths see
        // them as terminal.
        _ => None,
    }
}

/// Same terminal-vs-transient classification as `matrix_sync_terminal_error`
/// but for `matrix_sdk::HttpError` directly. Used by call sites that hit
/// HTTP endpoints (e.g. `client.whoami()`) without going through
/// `client.sync_once`, which surface the narrower `HttpError` rather
/// than the wrapping `matrix_sdk::Error`.
fn matrix_http_terminal_error(err: &matrix_sdk::HttpError) -> Option<MatrixError> {
    classify_terminal_kind(err.client_api_error_kind()?, || err.to_string())
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

/// Run `client.whoami()` with bounded retry across transient transport
/// failures. Returns:
/// - `Ok(response)` on success
/// - `Err(MatrixError::Auth)` when the retry budget is exhausted: restored-token
///   startup must fail closed rather than begin an indefinite sync backoff loop
/// - `Err(MatrixError::AuthTokenRevoked { … })` when the homeserver reports a
///   terminal token error (UnknownToken / Forbidden / UserDeactivated /
///   UserLocked / UserSuspended). Preserving the typed variant lets the CLI's
///   `verify_matrix_outcome` route it to the rekey-token hint path; collapsing
///   it to `Auth` defeats that branch and ships a generic message.
async fn whoami_with_bounded_retry(
    client: &Client,
) -> Result<matrix_sdk::ruma::api::client::account::whoami::v3::Response, MatrixError> {
    const WHOAMI_RETRY_DELAYS: [Duration; 3] = [
        Duration::from_secs(1),
        Duration::from_secs(2),
        Duration::from_secs(4),
    ];
    let mut attempt = 0;
    loop {
        match client.whoami().await {
            Ok(response) => return Ok(response),
            Err(err) => {
                if let Some(typed) = matrix_http_terminal_error(&err) {
                    return Err(typed);
                }
                if attempt >= WHOAMI_RETRY_DELAYS.len() {
                    return Err(MatrixError::Auth(format!(
                        "restored Matrix token could not be validated after {} whoami() attempts: {err}",
                        attempt + 1
                    )));
                }
                warn!(
                    error = %err,
                    attempt = attempt + 1,
                    "Matrix whoami() transient error; retrying"
                );
                tokio::time::sleep(WHOAMI_RETRY_DELAYS[attempt]).await;
                attempt += 1;
            }
        }
    }
}

/// Drain queued commands and reply with the supplied error to each.
/// Sync because `try_recv` and `oneshot::Sender::send` are both
/// non-blocking; callers don't need `.await`.
fn drain_pending_commands(rx: &mut mpsc::Receiver<MatrixCommand>, err: MatrixError) {
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
            return retry_after;
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
                warn!(
                    error = %err,
                    "system clock has never been valid in this process; \
                     using i64::MAX so verification records survive the broken-clock window"
                );
                return i64::MAX;
            }
            warn!(error = %err, last_valid_millis = last, "system clock is invalid; reusing last valid Matrix timestamp");
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
mod tests {
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
        };

        let err = resolve_matrix_store_passphrase(temp.path(), &config).expect_err("fail closed");
        assert!(matches!(err, MatrixError::MissingStoreSecret));
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

    fn matrix_test_config(encrypted: bool) -> MatrixConfig {
        MatrixConfig {
            homeserver_url: "https://matrix.example.com".to_string(),
            user_id: "@cara:example.com".to_string(),
            access_token: Some(zeroize::Zeroizing::new("token".to_string())),
            password: None,
            device_id: Some("DEVICE".to_string()),
            security: if encrypted {
                MatrixSecurity::Encrypted {
                    passphrase_source: PassphraseSource::Explicit(
                        NonEmptyPassphrase::new("matrix-dlq-test-passphrase").expect("passphrase"),
                    ),
                }
            } else {
                MatrixSecurity::Unencrypted
            },
            auto_join: MatrixAutoJoinConfig::default(),
        }
    }

    fn matrix_test_dlq_record() -> MatrixInboundDlqRecord {
        MatrixInboundDlqRecord {
            event_id: "$event:example.com".to_string(),
            room_id: "!room:example.com".to_string(),
            sender_id: "@alice:example.com".to_string(),
            text: "encrypted room secret".to_string(),
            received_at: 1_700_000_000_000,
        }
    }

    #[test]
    fn test_matrix_inbound_dlq_encrypts_records_when_matrix_encrypted() {
        let temp = tempfile::tempdir().expect("tempdir");
        let config = matrix_test_config(true);
        let record = matrix_test_dlq_record();

        let line = encode_matrix_inbound_dlq_record(temp.path(), &config, &record)
            .expect("encrypted DLQ line");

        assert!(
            !line.contains(&record.text),
            "encrypted Matrix DLQ line must not persist plaintext message body"
        );
        assert!(
            !line.contains(&record.sender_id),
            "encrypted Matrix DLQ line must not persist plaintext sender"
        );
        let decoded = decode_matrix_inbound_dlq_record(temp.path(), &config, &line)
            .expect("encrypted DLQ line should decode");
        assert_eq!(decoded, record);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_append_matrix_inbound_dlq_uses_owner_only_file() {
        let temp = tempfile::tempdir().expect("tempdir");
        let config = matrix_test_config(false);
        let record = matrix_test_dlq_record();

        let state = Arc::new(RwLock::new(MatrixRuntimeState::default()));
        append_matrix_inbound_dlq(temp.path(), &config, state, &record)
            .await
            .expect("append DLQ");

        let path = matrix_inbound_dlq_path(temp.path());
        assert!(path.exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path)
                .expect("metadata")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600);
        }
    }

    /// Successful DLQ append must clear a previously sticky
    /// `inbound_dlq_durability_error`. The pre-fix behavior pinned the
    /// channel in Error for the daemon's lifetime after a single
    /// transient append failure even though every later append
    /// succeeded.
    #[tokio::test(flavor = "current_thread")]
    async fn test_dlq_durability_error_clears_on_successful_append() {
        let temp = tempfile::tempdir().expect("tempdir");
        let config = matrix_test_config(false);
        let record = matrix_test_dlq_record();

        let state = Arc::new(RwLock::new(MatrixRuntimeState::default()));
        state
            .write()
            .record_inbound_dlq_append_failure("transient EIO".to_string());
        assert!(state.read().inbound_durability_error_is_sticky());

        append_matrix_inbound_dlq(temp.path(), &config, state.clone(), &record)
            .await
            .expect("append DLQ");

        assert!(
            !state.read().inbound_durability_error_is_sticky(),
            "successful append must clear sticky durability error"
        );
    }

    /// Replay of an empty/missing DLQ must clear a sticky durability
    /// error, matching the append decay path.
    #[tokio::test(flavor = "current_thread")]
    async fn test_dlq_durability_error_clears_on_empty_replay() {
        let temp = tempfile::tempdir().expect("tempdir");
        let config = matrix_test_config(false);
        let state = Arc::new(RwLock::new(MatrixRuntimeState::default()));
        state
            .write()
            .record_inbound_dlq_append_failure("transient EIO".to_string());
        assert!(state.read().inbound_durability_error_is_sticky());

        let ws_state = Arc::new(crate::server::ws::WsServerState::new(
            crate::server::ws::WsServerConfig::default(),
        ));
        replay_matrix_inbound_dlq(temp.path(), &config, ws_state, state.clone())
            .await
            .expect("empty replay");
        assert!(
            !state.read().inbound_durability_error_is_sticky(),
            "empty replay tick must decay sticky durability error"
        );
    }

    /// A DLQ record whose persisted `event_id` is empty,
    /// whitespace-only, or contains control bytes must be rejected at
    /// decode time so the replay path can't silently dispatch it
    /// without an idempotency key. Combined with the rejection in
    /// `IdempotencyKey::from_str_opt`, this closes the double-dispatch
    /// window for corrupted DLQ lines.
    #[test]
    fn test_decode_matrix_inbound_dlq_record_rejects_empty_event_id() {
        let temp = tempfile::tempdir().expect("tempdir");
        let config = matrix_test_config(false);
        // Plaintext encoding so the line is human-readable and we
        // can hand-craft an "empty event_id" record.
        let line = serde_json::json!({
            "eventId": "",
            "roomId": "!room:example.com",
            "senderId": "@alice:example.com",
            "text": "hello",
            "receivedAt": 1_700_000_000_000_i64,
        })
        .to_string();
        let err = decode_matrix_inbound_dlq_record(temp.path(), &config, &line)
            .expect_err("empty event_id must be rejected");
        let msg = err.to_string();
        assert!(
            msg.contains("invalid event_id"),
            "expected invalid-event_id error, got {msg}"
        );

        // Embedded control bytes also reject.
        let line = serde_json::json!({
            "eventId": "abc\u{0007}def",
            "roomId": "!room:example.com",
            "senderId": "@alice:example.com",
            "text": "hello",
            "receivedAt": 1_700_000_000_000_i64,
        })
        .to_string();
        let err = decode_matrix_inbound_dlq_record(temp.path(), &config, &line)
            .expect_err("control-byte event_id must be rejected");
        assert!(err.to_string().contains("invalid event_id"));
    }

    /// A line that fails to decode must NOT be silently dropped on
    /// the next replay. The current implementation moves corrupt
    /// lines to an `inbound_dlq.corrupt.jsonl` quarantine sibling so
    /// the live DLQ can drain (otherwise every replay tick
    /// re-classifies the same lines as Corrupt and the channel stays
    /// sticky-Error). Both invariants are pinned here:
    /// (a) the corrupt line is preserved verbatim in quarantine,
    /// (b) the live DLQ no longer contains it after replay.
    #[tokio::test(flavor = "current_thread")]
    async fn test_dlq_replay_keeps_corrupt_lines_verbatim() {
        let temp = tempfile::tempdir().expect("tempdir");
        let config = matrix_test_config(false);
        let path = matrix_inbound_dlq_path(temp.path());
        let quarantine_path = matrix_inbound_dlq_quarantine_path(temp.path());
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await.expect("dir");
        }
        // Pre-seed with a line that won't decode (truncated JSON).
        let corrupt_line = "{\"eventId\":\"$abc:example.com\",  // truncated\n";
        tokio::fs::write(&path, corrupt_line)
            .await
            .expect("seed corrupt DLQ");

        let state = Arc::new(RwLock::new(MatrixRuntimeState::default()));
        let ws_state = Arc::new(crate::server::ws::WsServerState::new(
            crate::server::ws::WsServerConfig::default(),
        ));
        let err = replay_matrix_inbound_dlq(temp.path(), &config, ws_state, state.clone())
            .await
            .expect_err("corrupt-only replay must surface error");
        assert!(format!("{err}").contains("undecodable"));

        // (a) The corrupt line must be preserved verbatim in the
        // quarantine file for forensic recovery.
        let quarantined = tokio::fs::read_to_string(&quarantine_path)
            .await
            .expect("read quarantine");
        assert!(
            quarantined.contains("$abc:example.com"),
            "corrupt DLQ line must be quarantined verbatim, got {quarantined:?}"
        );

        // (b) The live DLQ must no longer contain the corrupt line —
        // either the file was rewritten empty (then deleted, hence
        // NotFound), or it exists but contains no records.
        match tokio::fs::read_to_string(&path).await {
            Ok(live) => assert!(
                !live.contains("$abc:example.com"),
                "corrupt line must be removed from live DLQ after quarantine, got {live:?}"
            ),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => panic!("unexpected live DLQ read error: {err}"),
        }
    }

    /// `update_verification_record_state` must preserve previously
    /// captured SAS data when the caller passes `SasUpdate::Preserve`
    /// — regression test pinning that emoji stay visible across state
    /// transitions instead of being clobbered on every refresh
    /// iteration.
    #[test]
    fn test_update_verification_record_state_preserves_sas_when_next_is_none() {
        let state = Arc::new(RwLock::new(MatrixRuntimeState::default()));
        let (info, inserted) = upsert_verification_record(
            &state,
            "abc123".to_string(),
            "@alice:example.com".to_string(),
            Some("DEVICE".to_string()),
            MatrixVerificationState::Requested,
        );
        assert!(inserted);
        let flow_id = info.flow_id.clone();
        let seeded_sas = MatrixSasInfo {
            emoji: Some(vec![MatrixSasEmoji {
                symbol: "🐱".to_string(),
                description: "Cat".to_string(),
            }]),
            decimals: Some([1, 2, 3]),
        };
        update_verification_record_state(
            &state,
            &flow_id,
            MatrixVerificationState::KeysExchanged,
            SasUpdate::Set(seeded_sas.clone()),
        )
        .expect("seed SAS");

        // Preserve must keep the SAS intact even though the state advances.
        update_verification_record_state(
            &state,
            &flow_id,
            MatrixVerificationState::Confirmed,
            SasUpdate::Preserve,
        )
        .expect("preserve");
        let stored = state
            .read()
            .verifications
            .iter()
            .find(|f| f.flow_id == flow_id)
            .cloned()
            .expect("flow exists");
        assert_eq!(stored.state, MatrixVerificationState::Confirmed);
        assert_eq!(stored.sas, Some(seeded_sas.clone()));

        // Set replaces.
        let replacement = MatrixSasInfo {
            emoji: None,
            decimals: Some([9, 8, 7]),
        };
        update_verification_record_state(
            &state,
            &flow_id,
            MatrixVerificationState::Done,
            SasUpdate::Set(replacement.clone()),
        )
        .expect("set");
        let stored = state
            .read()
            .verifications
            .iter()
            .find(|f| f.flow_id == flow_id)
            .cloned()
            .expect("flow exists");
        assert_eq!(stored.sas, Some(replacement));
    }

    /// `update_verification_record_state` returns `Ok(None)` when the
    /// requested next state and SAS are equal to the existing record
    /// (no-op tick) — refresh broadcasts only fire on real change;
    /// this test pins that contract.
    #[test]
    fn test_update_verification_record_state_returns_none_on_noop() {
        let state = Arc::new(RwLock::new(MatrixRuntimeState::default()));
        let (info, inserted) = upsert_verification_record(
            &state,
            "noop-flow".to_string(),
            "@alice:example.com".to_string(),
            Some("DEVICE".to_string()),
            MatrixVerificationState::Requested,
        );
        assert!(inserted);
        let flow_id = info.flow_id.clone();
        // Same state, SasUpdate::Preserve (so SAS stays None) — must
        // return Ok(None) so the broadcast caller knows nothing changed.
        let result = update_verification_record_state(
            &state,
            &flow_id,
            MatrixVerificationState::Requested,
            SasUpdate::Preserve,
        )
        .expect("call");
        assert!(
            result.is_none(),
            "no-op state update must return None so refresh broadcasts only fire on real change"
        );
    }

    /// A real state change must return `Ok(Some(record))` so the
    /// caller can broadcast `matrix.verification.updated` with the
    /// post-state record.
    #[test]
    fn test_update_verification_record_state_returns_some_on_change() {
        let state = Arc::new(RwLock::new(MatrixRuntimeState::default()));
        let (info, _) = upsert_verification_record(
            &state,
            "change-flow".to_string(),
            "@alice:example.com".to_string(),
            Some("DEVICE".to_string()),
            MatrixVerificationState::Requested,
        );
        let flow_id = info.flow_id.clone();
        let result = update_verification_record_state(
            &state,
            &flow_id,
            MatrixVerificationState::KeysExchanged,
            SasUpdate::Preserve,
        )
        .expect("call");
        let updated = result.expect("real change must return Some");
        assert_eq!(updated.state, MatrixVerificationState::KeysExchanged);
    }

    /// A SAS-only change with the same state must still report the
    /// change. Otherwise a refresh that captures fresh SAS data on a
    /// flow that's been in `KeysExchanged` for a while would fail to
    /// broadcast and the operator UI would never see the comparison
    /// emoji.
    #[test]
    fn test_update_verification_record_state_returns_some_when_sas_changes() {
        let state = Arc::new(RwLock::new(MatrixRuntimeState::default()));
        let (info, _) = upsert_verification_record(
            &state,
            "sas-flow".to_string(),
            "@alice:example.com".to_string(),
            Some("DEVICE".to_string()),
            MatrixVerificationState::KeysExchanged,
        );
        let flow_id = info.flow_id.clone();
        let new_sas = MatrixSasInfo {
            emoji: None,
            decimals: Some([1, 2, 3]),
        };
        let result = update_verification_record_state(
            &state,
            &flow_id,
            MatrixVerificationState::KeysExchanged,
            SasUpdate::Set(new_sas.clone()),
        )
        .expect("call");
        let updated = result.expect("SAS change must return Some");
        assert_eq!(updated.sas, Some(new_sas));
    }

    /// DLQ replay-success path: a record that dispatches successfully
    /// must result in the file being removed by `rewrite_matrix_inbound_dlq`
    /// AND the inbound-failure streak reset on the runtime state.
    /// Pins the item-93 promised "successful deletion" + "counter
    /// reset" behaviors. Installs a real session store and activity
    /// service so dispatch reaches the "no-LLM-provider → Ok" path
    /// that legitimately produces a successful drain — without that
    /// setup the test would short-circuit through the not-found branch
    /// and never exercise the rewrite path.
    #[tokio::test(flavor = "current_thread")]
    async fn test_dlq_replay_drains_succeeding_record_and_resets_inbound_streak() {
        use crate::channels::activity::ActivityService;
        use crate::server::ws::WsServerConfig;
        let temp = tempfile::tempdir().expect("tempdir");
        let config = matrix_test_config(false);
        let state = Arc::new(RwLock::new(MatrixRuntimeState::default()));

        // Real WsServerState wired with a tempdir-backed session store
        // and activity service so dispatch_inbound_text_with_options
        // reaches its non-failing terminal branch (no LLM provider →
        // returns Ok with run_spawned=false). Without these, dispatch
        // panics on `state.session_store()`.
        let cfg = serde_json::json!({});
        crate::config::clear_cache();
        crate::config::update_cache(cfg.clone(), cfg.clone());
        let session_dir = tempfile::tempdir().expect("session tempdir");
        let session_store = Arc::new(crate::sessions::SessionStore::with_base_path(
            session_dir.path().to_path_buf(),
        ));
        let activity_service = Arc::new(ActivityService::with_limits_for_test(8, 1));
        let ws_state = Arc::new(
            crate::server::ws::WsServerState::new(WsServerConfig::default())
                .with_session_store(session_store)
                .with_activity_service(activity_service),
        );

        // Drive the inbound streak to a non-zero count and seed a
        // sticky durability error so the test can observe both
        // recoveries.
        state.write().record_inbound_failure();
        state.write().record_inbound_failure();
        state
            .write()
            .record_inbound_dlq_append_failure("transient EIO".to_string());

        let record = matrix_test_dlq_record();
        append_matrix_inbound_dlq(temp.path(), &config, state.clone(), &record)
            .await
            .expect("append DLQ");
        let path = matrix_inbound_dlq_path(temp.path());
        assert!(path.exists(), "DLQ file present before replay");

        replay_matrix_inbound_dlq(temp.path(), &config, ws_state, state.clone())
            .await
            .expect("replay must succeed when dispatch returns Ok");

        // Real drain by `rewrite_matrix_inbound_dlq`: the file must
        // be REMOVED, not just rewritten empty.
        assert!(
            !path.exists(),
            "successfully-replayed DLQ must be drained by rewrite_matrix_inbound_dlq"
        );
        assert!(
            !state.read().inbound_durability_error_is_sticky(),
            "successful drain must clear the sticky durability error"
        );
        assert!(
            !state.read().inbound_streak_is_sticky(),
            "successful dispatch must reset the inbound failure streak"
        );
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

    /// An inbound durability error pins the channel in
    /// Error even when every other phase succeeded — that's the whole
    /// point of `inbound_durability_error_is_sticky`.
    #[test]
    fn test_apply_post_sync_maintenance_inbound_durability_blocks_connected() {
        let mut streaks = MatrixMaintenanceStreaks::default();
        let state = Arc::new(RwLock::new(MatrixRuntimeState::default()));
        let registry = matrix_test_registry();
        // Drive the channel to Connecting so the test observes whether
        // apply_post_sync_maintenance promotes to Connected.
        registry.update_status(MATRIX_CHANNEL_ID, ChannelStatus::Connecting);

        state
            .write()
            .record_inbound_dlq_append_failure("EIO".to_string());

        apply_post_sync_maintenance(ok_outcomes(), &mut streaks, &state, &registry);

        assert!(state.read().inbound_durability_error_is_sticky());
        assert_eq!(streaks.consecutive_clean_syncs, 0);
        // Channel must NOT be Connected while inbound durability is sticky.
        assert_ne!(
            registry.get_status(MATRIX_CHANNEL_ID),
            Some(ChannelStatus::Connected),
            "inbound durability sticky must block Connected restoration"
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

    /// Pin the JSON shape of `MatrixVerificationInfo` against the
    /// schema declared in `tests/golden/ws/events.json`. If the
    /// runtime adds/removes a public field on the verification info,
    /// the golden schema must be updated in lockstep — this test
    /// catches drift before WS clients see it.
    #[test]
    fn test_matrix_verification_info_serializes_required_fields() {
        let info = MatrixVerificationInfo {
            flow_id: "flow-1".to_string(),
            protocol_flow_id: "txn-1".to_string(),
            user_id: "@alice:example.com".to_string(),
            device_id: Some("DEVICE".to_string()),
            state: MatrixVerificationState::Requested,
            sas: None,
            created_at: 1,
            updated_at: 2,
        };
        let json = serde_json::to_value(&info).expect("serialize");
        // Required fields per the WS event schema.
        for field in [
            "flowId",
            "protocolFlowId",
            "userId",
            "state",
            "createdAt",
            "updatedAt",
        ] {
            assert!(
                json.get(field).is_some(),
                "MatrixVerificationInfo must serialize {field}"
            );
        }
        // State must serialize to one of the documented values.
        let state_str = json
            .get("state")
            .and_then(|v| v.as_str())
            .expect("state is string");
        let allowed = [
            "created",
            "requested",
            "ready",
            "transitioned",
            "started",
            "accepted",
            "keys_exchanged",
            "confirmed",
            "done",
            "cancelled",
            "mismatched",
        ];
        assert!(
            allowed.contains(&state_str),
            "MatrixVerificationState '{state_str}' is not in the documented enum"
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
            "@alice:example.com".to_string(),
            Some("D1".to_string()),
            MatrixVerificationState::Requested,
        );
        upsert_verification_record(
            &state,
            "flow2".to_string(),
            "@bob:example.com".to_string(),
            Some("D2".to_string()),
            MatrixVerificationState::Requested,
        );
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

        for kind in [
            ErrorKind::UnknownToken { soft_logout: false },
            ErrorKind::forbidden(),
            ErrorKind::UserDeactivated,
            ErrorKind::UserLocked,
            ErrorKind::UserSuspended,
        ] {
            let err = classify_terminal_kind(&kind, || "terminal".to_string())
                .expect("terminal Matrix auth kind must classify");
            assert!(matches!(err, MatrixError::AuthTokenRevoked(message) if message == "terminal"));
        }

        assert!(
            classify_terminal_kind(&ErrorKind::LimitExceeded { retry_after: None }, || {
                "transient".to_string()
            })
            .is_none(),
            "rate-limit errors remain transient"
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

    /// Pinned vector for the inbound-DLQ HKDF derivation. Drift here
    /// is a silent wire-format break: an operator upgrading carapace
    /// while a non-empty `inbound_dlq.jsonl` is on disk would lose
    /// access to those records (decryption would yield gibberish or
    /// AEAD-tag failures, and the records would land in the
    /// quarantine sibling). Pin against a known input so any rotation
    /// of `MATRIX_INBOUND_DLQ_INFO`, salt formula, or HKDF-construction
    /// detail trips this test before shipping.
    #[test]
    fn test_pinned_matrix_inbound_dlq_key_vector() {
        let key = derive_matrix_inbound_dlq_key_from(
            b"correct horse battery staple",
            b"installation-00000000-0000-0000-0000-000000000000",
        )
        .unwrap();
        assert_eq!(
            hex::encode(key),
            "4f17d4dc2615c81e3e552fe15374de09634d883e4b7835a1d43a04676f5a0ff7"
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
            ..MatrixStatusMetadata {
                joined_room_count: 0,
                encrypted_room_count: 0,
                unencrypted_room_count: 0,
                unsupported_room_count: 0,
                pending_verification_count: 0,
                last_successful_sync_at: None,
                unsupported_rooms: Vec::new(),
                unsupported_inbound_count: 0,
                inbound_dispatch_failure_total: 0,
                inbound_dlq_append_failure_total: 0,
                inbound_dlq_durability_error: None,
                inbound_dlq_lost_event_ids: Vec::new(),
                inbound_dlq_undecodable_lost_count: 0,
                last_error_kind: None,
            }
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
            (MatrixError::E2ee("x".into()), "e2ee"),
            (MatrixError::StartupFailed("x".into()), "startup-failed"),
            (
                MatrixError::InterruptedRekey("x".into()),
                "interrupted-rekey",
            ),
            (MatrixError::Clock("x".into()), "clock"),
            (MatrixError::NotConnected, "not-connected"),
            (MatrixError::UnsupportedRoom("x".into()), "unsupported-room"),
            (MatrixError::RoomNotFound("x".into()), "room-not-found"),
            (MatrixError::SendFailed("x".into()), "send-failed"),
            (MatrixError::SyncFailed("x".into()), "sync-failed"),
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

    /// Pin the camelCase wire shape of `MatrixDeviceInfo`. Browser
    /// UI and external automation that consume `/control/matrix/devices`
    /// depend on `userId` / `deviceId` / `displayName` / `verified`.
    /// A future field rename or `rename_all` flip would silently break
    /// them; trip the test instead.
    #[test]
    fn test_pinned_matrix_device_info_wire_shape() {
        let info = MatrixDeviceInfo {
            user_id: "@alice:example.com".to_string(),
            device_id: "DEVICEID".to_string(),
            display_name: Some("Laptop".to_string()),
            verified: true,
        };
        let json = serde_json::to_value(&info).expect("serialize");
        let expected = serde_json::json!({
            "userId": "@alice:example.com",
            "deviceId": "DEVICEID",
            "displayName": "Laptop",
            "verified": true,
        });
        assert_eq!(json, expected, "MatrixDeviceInfo wire shape changed");
    }

    #[test]
    fn test_verification_record_upsert_and_prune() {
        let state = Arc::new(RwLock::new(MatrixRuntimeState::default()));
        let (first, inserted) = upsert_verification_record(
            &state,
            "protocol-flow-1".to_string(),
            "@alice:example.com".to_string(),
            Some("DEVICE1".to_string()),
            MatrixVerificationState::Requested,
        );
        assert!(inserted);
        assert_eq!(first.protocol_flow_id, "protocol-flow-1");
        assert_eq!(first.state, MatrixVerificationState::Requested);

        let (updated, inserted) = upsert_verification_record(
            &state,
            "protocol-flow-1".to_string(),
            "@alice:example.com".to_string(),
            Some("DEVICE2".to_string()),
            MatrixVerificationState::Ready,
        );
        assert!(!inserted);
        assert_eq!(updated.device_id.as_deref(), Some("DEVICE2"));
        assert_eq!(updated.state, MatrixVerificationState::Ready);

        state.write().verifications[0].updated_at =
            now_millis() - MATRIX_VERIFICATION_RECORD_TTL.as_millis() as i64 - 1;
        prune_verification_records(&state);
        assert!(state.read().verifications.is_empty());
    }

    #[test]
    fn test_verification_control_id_includes_user_and_protocol_flow() {
        let state = Arc::new(RwLock::new(MatrixRuntimeState::default()));
        let (alice, inserted) = upsert_verification_record(
            &state,
            "shared-protocol-flow".to_string(),
            "@alice:example.com".to_string(),
            Some("DEVICE1".to_string()),
            MatrixVerificationState::Requested,
        );
        assert!(inserted);
        let (bob, inserted) = upsert_verification_record(
            &state,
            "shared-protocol-flow".to_string(),
            "@bob:example.com".to_string(),
            Some("DEVICE2".to_string()),
            MatrixVerificationState::Requested,
        );
        assert!(inserted);
        assert_ne!(alice.flow_id, bob.flow_id);
        assert_eq!(state.read().verifications.len(), 2);
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
        assert!(delivery.retryable);
        assert!(delivery
            .error
            .unwrap_or_default()
            .contains("Matrix outbound queue is full"));
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
    fn test_verification_state_serde_round_trip_and_terminal() {
        let encoded = serde_json::to_value(MatrixVerificationState::KeysExchanged).unwrap();
        assert_eq!(encoded, json!("keys_exchanged"));
        let decoded: MatrixVerificationState = serde_json::from_value(encoded).unwrap();
        assert_eq!(decoded, MatrixVerificationState::KeysExchanged);
        assert!(MatrixVerificationState::Done.is_terminal());
        assert!(MatrixVerificationState::Cancelled.is_terminal());
        assert!(MatrixVerificationState::Mismatched.is_terminal());
        assert!(!MatrixVerificationState::Ready.is_terminal());
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

    /// Verification-flow eviction must be terminal-first. Otherwise
    /// a peer flooding fresh protocol_flow_ids fills the cap with
    /// non-terminal records and evicts the operator's pending flow
    /// at index 0 — denying the operator's verification UX.
    #[test]
    fn test_upsert_verification_record_evicts_terminal_first_at_cap() {
        let state = Arc::new(RwLock::new(MatrixRuntimeState::default()));
        // Fill the cap with 1 OPERATOR-PENDING flow (non-terminal)
        // followed by (CAP-1) PEER-INITIATED flows in mixed states,
        // including some terminal so we can verify terminal-first.
        let cap = MATRIX_VERIFICATION_RECORDS_MAX;
        // First record: a non-terminal flow at index 0 (the
        // operator's). It must NOT be evicted on the next overflow.
        let (_, inserted) = upsert_verification_record(
            &state,
            "operator-flow".to_string(),
            "@operator:example.com".to_string(),
            Some("OPERDEV".to_string()),
            MatrixVerificationState::Requested,
        );
        assert!(inserted);
        // Add cap-2 more non-terminals; record at index 1 will be a
        // marker we can later spot when it's NOT evicted.
        for i in 0..(cap - 2) {
            upsert_verification_record(
                &state,
                format!("peer-flow-{i}"),
                format!("@peer{i}:example.com"),
                Some(format!("PEERDEV{i}")),
                MatrixVerificationState::Requested,
            );
        }
        // Add one TERMINAL record at the end (the SECOND-to-last,
        // since we add one more terminal to ensure terminal eviction).
        upsert_verification_record(
            &state,
            "old-terminal".to_string(),
            "@cancelled:example.com".to_string(),
            Some("DEVTERM".to_string()),
            MatrixVerificationState::Cancelled,
        );
        // Cap is now reached. Insert one more — this triggers
        // eviction. The OLDEST-TERMINAL is "old-terminal"; should be
        // dropped. Operator's flow stays.
        let (_, inserted) = upsert_verification_record(
            &state,
            "trigger-evict".to_string(),
            "@new:example.com".to_string(),
            Some("DEVNEW".to_string()),
            MatrixVerificationState::Requested,
        );
        assert!(inserted);
        let guard = state.read();
        let flow_ids: Vec<&str> = guard
            .verifications
            .iter()
            .map(|f| f.protocol_flow_id.as_str())
            .collect();
        assert!(
            flow_ids.contains(&"operator-flow"),
            "operator's pending flow MUST NOT be evicted under peer flood"
        );
        assert!(
            !flow_ids.contains(&"old-terminal"),
            "oldest terminal record MUST be evicted before any non-terminal"
        );
    }
}
