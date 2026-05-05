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
use tracing::{debug, info, warn};

use crate::channels::{ChannelMetadata, ChannelRegistry, ChannelStatus};
use crate::plugins::{
    BindingError, ChannelCapabilities, ChannelInfo as PluginChannelInfo, ChannelPluginInstance,
    ChatType, DeliveryResult, OutboundContext,
};
use crate::server::ws::WsServerState;

pub const MATRIX_CHANNEL_ID: &str = "matrix";
pub const MATRIX_CHANNEL_NAME: &str = "Matrix";
pub const MATRIX_STORE_INFO: &[u8] = b"carapace-matrix-store-v1";
const MATRIX_INBOUND_DLQ_INFO: &[u8] = b"carapace-matrix-inbound-dlq-v1";
const MATRIX_INBOUND_DLQ_AAD: &[u8] = b"matrix-inbound-dlq-v1";
const MATRIX_OUTBOUND_QUEUE_CAPACITY: usize = 128;
/// Cap on the number of concurrently-in-flight Matrix sends. The mpsc
/// queue at `MATRIX_OUTBOUND_QUEUE_CAPACITY` only bounds *queued*
/// commands; without an in-flight cap, the actor would drain a burst of
/// 128 sends into a JoinSet that grows unbounded as the queue refills.
/// Backpressure must be owned at the send boundary: when the JoinSet is
/// at capacity, callers see `BindingError::CallError` so the delivery
/// pipeline retries via its own logic instead of silently piling up
/// concurrent HTTP requests against the homeserver.
const MATRIX_MAX_IN_FLIGHT_SENDS: usize = 16;
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
    pub access_token: Option<String>,
    pub password: Option<String>,
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
/// passphrase. Debug elides the inner string.
#[derive(Clone, PartialEq, Eq)]
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
    #[error("failed to authenticate Matrix client: {0}")]
    Auth(String),
    #[error("failed to persist Matrix access token: {0}")]
    TokenPersistence(String),
    #[error("Matrix E2EE setup failed: {0}")]
    E2ee(String),
    #[error("Matrix runtime startup failed: {0}")]
    StartupFailed(String),
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
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MatrixStatusMetadata {
    pub joined_room_count: usize,
    pub encrypted_room_count: usize,
    pub unencrypted_room_count: usize,
    pub unsupported_room_count: usize,
    pub pending_verification_count: usize,
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

    /// Record an inbound-dispatch failure, returning the new
    /// consecutive count for the warn-log line.
    fn record_inbound_failure(&mut self) -> u32 {
        self.inbound_streak.record_failure()
    }

    fn reset_inbound_failures(&mut self) {
        self.inbound_streak.record_success();
    }

    fn record_inbound_dlq_append_failure(&mut self, error: String) {
        self.status.inbound_dlq_append_failure_total = self
            .status
            .inbound_dlq_append_failure_total
            .saturating_add(1);
        self.status.inbound_dlq_durability_error = Some(error);
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
        let notified = self.shutdown_complete.clone();
        tokio::time::timeout(timeout, async move {
            loop {
                if completed.load(Ordering::Acquire) {
                    return;
                }
                notified.notified().await;
            }
        })
        .await
        .is_ok()
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
        mpsc::error::TrySendError::Full(_) => MatrixError::VerificationTimeout(
            "Matrix runtime command queue is full; retry the verification command shortly"
                .to_string(),
        ),
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
        | MatrixError::StartupFailed(message) => Ok(matrix_retryable_delivery_result(message)),
        MatrixError::NotConnected => Ok(matrix_retryable_delivery_result(
            "Matrix runtime is not connected".to_string(),
        )),
        MatrixError::RoomNotFound(room) => Err(BindingError::CallError(format!(
            "Matrix room not found: {room}"
        ))),
        MatrixError::UnsupportedRoom(message) => Err(BindingError::CallError(message)),
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
        .filter(|value| !value.is_empty());
    let password = read_string(matrix, "password")?
        .or_else(|| crate::config::read_config_env("MATRIX_PASSWORD"))
        .filter(|value| !value.trim().is_empty());
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
) -> Result<[u8; 32], MatrixError> {
    let hk = Hkdf::<Sha256>::new(Some(installation_id), config_password);
    let mut okm = [0u8; 32];
    hk.expand(MATRIX_STORE_INFO, &mut okm)
        .map_err(|_| MatrixError::StoreKeyDerivation)?;
    Ok(okm)
}

pub fn resolve_matrix_store_passphrase(
    state_dir: &Path,
    config: &MatrixConfig,
) -> Result<Option<String>, MatrixError> {
    let MatrixSecurity::Encrypted { passphrase_source } = &config.security else {
        return Ok(None);
    };
    match passphrase_source {
        PassphraseSource::Explicit(passphrase) => Ok(Some(passphrase.as_str().to_string())),
        PassphraseSource::DeriveFromConfigPassword => {
            if let Some(passphrase) = read_matrix_store_passphrase_file(state_dir)? {
                return Ok(Some(passphrase));
            }
            let password = crate::config::read_process_env("CARAPACE_CONFIG_PASSWORD")
                .filter(|value| !value.is_empty())
                .ok_or(MatrixError::MissingStoreSecret)?;
            let installation_id = read_or_create_installation_id(state_dir)?;
            derive_matrix_store_key(password.as_bytes(), installation_id.as_bytes())
                .map(|key| Some(hex::encode(key)))
        }
    }
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

#[cfg(unix)]
fn write_owner_only_file(path: &Path, content: &str) -> Result<(), MatrixError> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .map_err(|err| MatrixError::InstallationId(err.to_string()))?;
    file.write_all(content.as_bytes())
        .and_then(|_| file.write_all(b"\n"))
        .and_then(|_| file.sync_all())
        .map_err(|err| MatrixError::InstallationId(err.to_string()))
}

#[cfg(not(unix))]
fn write_owner_only_file(path: &Path, content: &str) -> Result<(), MatrixError> {
    std::fs::write(path, format!("{content}\n"))
        .map_err(|err| MatrixError::InstallationId(err.to_string()))
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
    let handle = Arc::new(MatrixRuntimeHandle {
        tx: tx.clone(),
        state: state.clone(),
        completed: completed.clone(),
        shutdown_complete: shutdown_complete.clone(),
    });
    tokio::spawn(async move {
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
    handle
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
        channel_registry.set_error(MATRIX_CHANNEL_ID, matrix_error_for_status(&err));
        fail_pending_commands(&mut rx, err).await;
        return;
    }

    let client = match build_authenticated_client(&config, &state_dir).await {
        Ok(client) => Arc::new(client),
        Err(err) => {
            channel_registry.set_error(MATRIX_CHANNEL_ID, matrix_error_for_status(&err));
            fail_pending_commands(&mut rx, err).await;
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
    channel_registry.update_status(MATRIX_CHANNEL_ID, ChannelStatus::Connected);
    update_channel_registry_metadata(&channel_registry, &state);
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
                                let refresh_result = tokio::time::timeout(
                                    MATRIX_VERIFICATION_COMMAND_TIMEOUT,
                                    refresh_verification_records(client.clone(), &state),
                                )
                                .await;
                                match refresh_result {
                                    Ok(Ok(updated)) => {
                                        // Broadcast any updates surfaced by
                                        // the post-timeout refresh; otherwise
                                        // WS-subscribed UIs miss the state
                                        // transition until the next sync.
                                        for verification in updated {
                                            crate::server::ws::broadcast_matrix_verification_updated(
                                                &ws_state,
                                                crate::server::ws::UpdatedVerificationFlow::for_state_change(&verification),
                                            );
                                        }
                                    }
                                    Ok(Err(err)) => {
                                        warn!(
                                            error = %err,
                                            "post-timeout start-verification refresh failed; \
                                             local state may remain stale until next sync"
                                        );
                                    }
                                    Err(_) => {
                                        warn!(
                                            "post-timeout start-verification refresh also timed out; \
                                             local state may remain stale until next sync"
                                        );
                                    }
                                }
                                Err(MatrixError::VerificationTimeout(
                                    "verification start exceeded MATRIX_VERIFICATION_COMMAND_TIMEOUT"
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
                                // Refresh the verification record from the
                                // SDK before returning so the operator's
                                // next call sees the actual server state
                                // (and doesn't hit `VerificationFlowNotReady`
                                // for a flow the server already advanced).
                                //
                                // Capture the changed-records vec returned by
                                // the refresh and broadcast each one so
                                // WS-subscribed UIs see the post-timeout
                                // state transition without waiting for the
                                // next sync-loop tick. Refresh failure is
                                // logged at warn (not debug) — local state
                                // staleness IS operator-visible and
                                // shouldn't be hidden under the default
                                // info-level log filter.
                                match bounded_verification_refresh(client.clone(), &state).await {
                                    Ok(updated) => {
                                        for verification in updated {
                                            crate::server::ws::broadcast_matrix_verification_updated(
                                                &ws_state,
                                                crate::server::ws::UpdatedVerificationFlow::for_state_change(&verification),
                                            );
                                        }
                                    }
                                    Err(refresh_err) => {
                                        warn!(
                                            error = %refresh_err,
                                            "post-timeout verification refresh failed; local verification \
                                             state may remain stale until next sync"
                                        );
                                    }
                                }
                                Err(MatrixError::VerificationTimeout(
                                    "verification action exceeded MATRIX_VERIFICATION_COMMAND_TIMEOUT"
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
                            channel_registry.set_error(
                                MATRIX_CHANNEL_ID,
                                matrix_error_for_status(&permanent),
                            );
                            warn!(error = %err, "Matrix sync failed with permanent error; stopping runtime");
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
                            fail_pending_commands(&mut rx, permanent).await;
                            return;
                        }
                        let retry_after = matrix_retry_after(&err);
                        let delay = backoff.next_delay(retry_after);
                        next_sync_after = Some(tokio::time::Instant::now() + delay);
                        channel_registry.set_error(
                            MATRIX_CHANNEL_ID,
                            crate::logging::redact::RedactedDisplay(&err).to_string(),
                        );
                        warn!(
                            error = %err,
                            delay_ms = delay.as_millis(),
                            "Matrix sync failed; backing off"
                        );
                    }
                    Some(Err(err)) => {
                        maintenance_streaks.consecutive_clean_syncs = 0;
                        let delay = backoff.next_delay(None);
                        next_sync_after = Some(tokio::time::Instant::now() + delay);
                        let err = MatrixError::SyncFailed(format!("Matrix sync task failed: {err}"));
                        channel_registry.set_error(
                            MATRIX_CHANNEL_ID,
                            matrix_error_for_status(&err),
                        );
                        warn!(
                            error = %err,
                            delay_ms = delay.as_millis(),
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
    verification: Result<Vec<MatrixVerificationInfo>, MatrixError>,
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
        Ok(()) => record_phase_recovery("invite-handling", invite_streak),
        Err(err) => {
            let count = invite_streak.record_failure();
            warn!(error = %err, failures = count, "Matrix invite handling failed");
            if invite_streak.is_sticky() {
                channel_registry.set_error(MATRIX_CHANNEL_ID, matrix_error_for_status(&err));
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
                channel_registry.set_error(
                    MATRIX_CHANNEL_ID,
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
                channel_registry.set_error(
                    MATRIX_CHANNEL_ID,
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
                channel_registry.set_error(
                    MATRIX_CHANNEL_ID,
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
                channel_registry.set_error(
                    MATRIX_CHANNEL_ID,
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
        || state.read().inbound_durability_error_is_sticky();
    if non_inbound_sticky {
        *consecutive_clean_syncs = 0;
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
        if state.read().inbound_streak_is_sticky() {
            debug!(
                clean_syncs = *consecutive_clean_syncs,
                "Matrix inbound dispatch error remains sticky until decay threshold"
            );
        } else {
            channel_registry.update_status(MATRIX_CHANNEL_ID, ChannelStatus::Connected);
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
        handle_invites(client.clone(), &config),
    )
    .await;
    let verification = bounded_matrix_result(
        "Matrix verification refresh",
        refresh_verification_records(client.clone(), &state),
    )
    .await;
    if let Ok(updated) = verification.as_ref() {
        for verification in updated {
            crate::server::ws::broadcast_matrix_verification_updated(
                &ws_state,
                crate::server::ws::UpdatedVerificationFlow::for_state_change(verification),
            );
        }
    }
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
    drain_outbound_on_shutdown(rx).await;
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
) -> Result<Vec<MatrixVerificationInfo>, MatrixError> {
    bounded_matrix_result(
        "Matrix verification refresh",
        refresh_verification_records(client, state),
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
        Ok(()) => Ok(()),
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
    let store_passphrase = resolve_matrix_store_passphrase(state_dir, config)?;
    let sqlite_config = SqliteStoreConfig::new(&store_dir).passphrase(store_passphrase.as_deref());
    let client = Client::builder()
        .homeserver_url(&config.homeserver_url)
        .sqlite_store_with_config_and_cache_path(sqlite_config, Some(cache_dir))
        .build()
        .await
        .map_err(|err| MatrixError::ClientBuild(err.to_string()))?;

    if let (Some(access_token), Some(device_id)) =
        (config.access_token.as_deref(), config.device_id.as_deref())
    {
        restore_matrix_session(&client, config, access_token, device_id).await?;
        let session = validate_restored_matrix_session(&client, config, device_id).await?;
        maybe_restore_recovery_key(&client, config, state_dir, &session).await?;
        maybe_bootstrap_cross_signing(
            &client,
            config,
            config.password.as_deref(),
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
        .login_username(&config.user_id, password)
        .initial_device_display_name("Carapace Matrix");
    if let Some(device_id) = config.device_id.as_deref() {
        login = login.device_id(device_id);
    }
    let response = login
        .send()
        .await
        .map_err(|err| MatrixError::Auth(err.to_string()))?;
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
    client
        .restore_session(session)
        .await
        .map_err(|err| MatrixError::Auth(err.to_string()))
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
    device_id: OwnedDeviceId,
    /// Private marker preventing construction outside this module.
    /// Without it, `ValidatedMatrixSession { user_id, device_id }`
    /// would be public-constructible from any code that imports the
    /// type — defeating the validation contract.
    _proof: (),
}

impl ValidatedMatrixSession {
    /// User ID the homeserver confirmed at validation time. Exposed so
    /// future callers (recovery flows, audit logging) can read it
    /// without re-running /whoami.
    #[allow(dead_code)]
    fn user_id(&self) -> &OwnedUserId {
        &self.user_id
    }

    /// Device ID the homeserver confirmed at validation time.
    #[allow(dead_code)]
    fn device_id(&self) -> &OwnedDeviceId {
        &self.device_id
    }
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
        return Err(MatrixError::Auth(format!(
            "restored Matrix token belongs to {}, expected {}",
            response.user_id, config.user_id
        )));
    }
    let device_id = match response.device_id.as_ref() {
        Some(device_id) if device_id.as_str() == expected_device_id => device_id.clone(),
        Some(_) => {
            return Err(MatrixError::Auth(
                "restored Matrix token belongs to a different device than matrix.deviceId"
                    .to_string(),
            ));
        }
        None => {
            return Err(MatrixError::Auth(
                "restored Matrix token did not report a device ID".to_string(),
            ));
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
            session.user_id().to_string(),
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
            MatrixError::E2ee(format!("cross-signing bootstrap failed after UIA: {err}"))
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
    let recovery_key = match tokio::fs::read_to_string(&path).await {
        Ok(recovery_key) => recovery_key,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(err) => {
            return Err(MatrixError::E2ee(format!(
                "failed to read Matrix recovery key from {}: {err}",
                path.display()
            )));
        }
    };
    let recovery_key = recovery_key.trim();
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
        Ok(key) => key,
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
        // Parent-dir fsync: `tokio::fs::write(...)` and `rename(2)`
        // both leave the dirent change in the kernel page cache. The
        // marker's whole point is to be the rollback breadcrumb on
        // crash, so a silent `let _ = dir.sync_all()` would defeat
        // the durable-write contract this function advertises.
        if let Some(parent) = marker_path_owned.parent() {
            let dir = std::fs::File::open(parent)
                .map_err(|err| format!("open marker parent for fsync: {err}"))?;
            dir.sync_all()
                .map_err(|err| format!("fsync marker parent dir: {err}"))?;
        }
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
    let content = content.to_string();
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
        // fsync the parent directory so the linked final path is durable across a
        // power-loss. Without this, the kernel may have written the
        // temp file's contents to disk but not yet flushed the dirent
        // change; a crash here loses the final link and the operator boots
        // with the SDK store referencing a server-side recovery secret
        // that has no local key file.
        if let Some(parent) = path.parent() {
            if let Ok(dir) = std::fs::File::open(parent) {
                let _ = dir.sync_all();
            }
        }
        Ok(())
    })
    .await
    .map_err(|err| err.to_string())?
}

#[cfg(unix)]
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

#[cfg(unix)]
async fn promote_owner_only_secret_file(src: &Path, dst: &Path) -> Result<(), String> {
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
        if let Some(parent) = dst.parent() {
            if let Ok(dir) = std::fs::File::open(parent) {
                let _ = dir.sync_all();
            }
        }
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
    let content = content.to_string();
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
        if path.exists() {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(format!(
                "secret file at {} appeared concurrently; refusing to overwrite",
                path.display()
            ));
        }
        if let Err(err) = std::fs::rename(&tmp_path, &path) {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(format!("rename secret file into place: {err}"));
        }
        // Mirror the Unix branch: fsync the parent directory so the
        // rename is durable. On Windows this is a best-effort no-op
        // when the platform's sync_all on a directory handle isn't
        // supported; the surrounding write+rename ordering is still
        // strictly better than the prior tokio::fs::write that
        // truncated the existing file.
        if let Some(parent) = path.parent() {
            if let Ok(dir) = std::fs::File::open(parent) {
                let _ = dir.sync_all();
            }
        }
        Ok(())
    })
    .await
    .map_err(|err| err.to_string())?
}

#[cfg(not(unix))]
async fn promote_owner_only_secret_file(src: &Path, dst: &Path) -> Result<(), String> {
    if dst.exists() {
        return Err(format!(
            "refusing to overwrite existing secret file at {}",
            dst.display()
        ));
    }
    let src = src.to_path_buf();
    let dst = dst.to_path_buf();
    tokio::task::spawn_blocking(move || -> Result<(), String> {
        if dst.exists() {
            return Err(format!(
                "secret file at {} appeared concurrently; refusing to overwrite",
                dst.display()
            ));
        }
        std::fs::rename(&src, &dst)
            .map_err(|err| format!("rename secret file into place: {err}"))?;
        if let Some(parent) = dst.parent() {
            if let Ok(dir) = std::fs::File::open(parent) {
                let _ = dir.sync_all();
            }
        }
        Ok(())
    })
    .await
    .map_err(|err| err.to_string())?
}

fn secret_file_temp_path(path: &Path) -> PathBuf {
    use std::ffi::OsString;
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut file_name = path
        .file_name()
        .map(OsString::from)
        .unwrap_or_else(|| OsString::from("secret"));
    file_name.push(format!(".tmp.{}.{counter}", std::process::id()));
    path.with_file_name(file_name)
}

async fn persist_matrix_session(access_token: &str, device_id: &str) -> Result<(), MatrixError> {
    if crate::config::config_password().is_none() {
        return Err(MatrixError::TokenPersistence(
            "CARAPACE_CONFIG_PASSWORD is required to persist matrix.accessToken as an encrypted config secret".to_string(),
        ));
    }
    let access_token = access_token.to_string();
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
    client.add_event_handler(move |event: AnyToDeviceEvent| {
        let ws_state = ws_state.clone();
        let state = state.clone();
        async move {
            handle_to_device_event(ws_state, state, event).await;
        }
    });
}

async fn handle_room_message_event(
    ws_state: Arc<WsServerState>,
    channel_registry: Arc<ChannelRegistry>,
    state: Arc<RwLock<MatrixRuntimeState>>,
    state_dir: PathBuf,
    config: MatrixConfig,
    event: OriginalSyncRoomMessageEvent,
    room: Room,
) {
    if room.state() != RoomState::Joined {
        return;
    }
    if !is_room_supported(&room, config.encrypted()) {
        warn!(
            room_id = %room.room_id(),
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
            room_id = %room.room_id(),
            sender = %event.sender,
            event_id = %event.event_id,
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
    let room_id = room.room_id().to_string();
    let sender_id = event.sender.to_string();
    let event_id = event.event_id.to_string();
    debug!(
        room_id = %room_id,
        sender = %sender_id,
        event_id = %event_id,
        "Matrix inbound message"
    );
    match crate::channels::inbound::dispatch_inbound_text_with_options(
        &ws_state,
        MATRIX_CHANNEL_ID,
        &sender_id,
        &room_id,
        &text_content.body,
        Some(room_id.clone()),
        crate::channels::inbound::InboundDispatchOptions {
            inbound_event_id: crate::channels::inbound::IdempotencyKey::from_str_opt(&event_id),
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
                state
                    .write()
                    .record_inbound_dlq_append_failure(message.clone());
                channel_registry.set_error(MATRIX_CHANNEL_ID, message);
            }
            let failures = {
                let mut guard = state.write();
                let count = guard.record_inbound_failure();
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
            if failures >= MATRIX_REFRESH_FAILURE_ERROR_THRESHOLD {
                channel_registry.set_error(
                    MATRIX_CHANNEL_ID,
                    format!(
                        "Matrix inbound dispatch failing ({failures} consecutive failures): {}",
                        crate::logging::redact::RedactedDisplay(&err)
                    ),
                );
            }
        }
    }
}

async fn handle_to_device_event(
    ws_state: Arc<WsServerState>,
    state: Arc<RwLock<MatrixRuntimeState>>,
    event: AnyToDeviceEvent,
) {
    let AnyToDeviceEvent::KeyVerificationRequest(event) = event else {
        return;
    };
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
    let result = append_matrix_inbound_dlq_line(&path, serialized).await;
    if result.is_ok() {
        state.write().clear_inbound_dlq_durability_error();
    }
    result
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
    let _guard = lock.lock().await;

    let content = match tokio::fs::read_to_string(&path).await {
        Ok(content) => content,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            // No queue; treat as a successful replay tick — clear any
            // sticky durability error so a transient append failure
            // followed by a clean drain doesn't pin the channel
            // permanently in Error.
            state.write().clear_inbound_dlq_durability_error();
            return Ok(());
        }
        Err(err) => {
            return Err(MatrixError::SyncFailed(format!(
                "read Matrix inbound DLQ {}: {err}",
                path.display()
            )))
        }
    };

    let mut remaining_records: Vec<MatrixInboundDlqRecord> = Vec::new();
    let mut corrupt_lines: Vec<String> = Vec::new();
    let mut errors: Vec<String> = Vec::new();
    for line in content
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
    {
        let classified = match decode_matrix_inbound_dlq_record(state_dir, config, line) {
            Ok(record) => DlqReplayLine::Decoded(record),
            Err(err) => DlqReplayLine::Corrupt {
                raw: line.to_string(),
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
                // Preserve the raw line on disk so a future operator
                // (or improved decoder) can recover it. Silently
                // dropping corrupt records — as the previous
                // implementation did — turned a single tampered or
                // truncated line into permanent inbound-event loss.
                warn!(
                    error = %error,
                    "Matrix DLQ replay encountered an undecodable line; preserved verbatim for recovery"
                );
                errors.push(format!("undecodable line: {error}"));
                corrupt_lines.push(raw);
            }
        }
    }

    rewrite_matrix_inbound_dlq(state_dir, config, &path, &remaining_records, &corrupt_lines)
        .await?;

    if errors.is_empty() {
        state.write().clear_inbound_dlq_durability_error();
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

async fn rewrite_matrix_inbound_dlq(
    state_dir: &Path,
    config: &MatrixConfig,
    path: &Path,
    remaining: &[MatrixInboundDlqRecord],
    corrupt_lines: &[String],
) -> Result<(), MatrixError> {
    if remaining.is_empty() && corrupt_lines.is_empty() {
        match tokio::fs::remove_file(path).await {
            Ok(()) => {
                sync_parent_dir_best_effort(path).await;
                return Ok(());
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(err) => {
                return Err(MatrixError::SyncFailed(format!(
                    "remove drained Matrix inbound DLQ {}: {err}",
                    path.display()
                )))
            }
        }
    }
    let mut lines = Vec::with_capacity(remaining.len() + corrupt_lines.len());
    for record in remaining {
        lines.push(encode_matrix_inbound_dlq_record(state_dir, config, record)?);
    }
    for raw in corrupt_lines {
        // Preserve the original on-disk encoding verbatim. We can't
        // re-encode because we couldn't decode it in the first place,
        // and we don't want to silently drop it.
        lines.push(raw.clone());
    }
    replace_matrix_inbound_dlq_lines(path, lines).await
}

fn encode_matrix_inbound_dlq_record(
    state_dir: &Path,
    config: &MatrixConfig,
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
    if !config.encrypted() {
        // Plaintext branch: copy the bytes into a `String` for return.
        // The Zeroizing<Vec<u8>> is dropped at scope-end and zeroes
        // its bytes; the returned String contains a fresh allocation
        // that the caller is responsible for.
        return String::from_utf8(plaintext.to_vec())
            .map_err(|err| MatrixError::SyncFailed(format!("encode Matrix inbound DLQ: {err}")));
    }
    let key = derive_matrix_inbound_dlq_key(state_dir, config)?;
    let blob = crate::crypto::encrypt_aead_blob(&key, &plaintext, MATRIX_INBOUND_DLQ_AAD)
        .map_err(|err| MatrixError::SyncFailed(format!("encrypt Matrix inbound DLQ: {err}")))?;
    serde_json::to_string(&MatrixEncryptedInboundDlqRecord {
        version: 1,
        nonce: URL_SAFE_NO_PAD.encode(blob.nonce),
        ciphertext: URL_SAFE_NO_PAD.encode(blob.ciphertext),
    })
    .map_err(|err| {
        MatrixError::SyncFailed(format!("serialize encrypted Matrix inbound DLQ: {err}"))
    })
}

fn decode_matrix_inbound_dlq_record(
    state_dir: &Path,
    config: &MatrixConfig,
    line: &str,
) -> Result<MatrixInboundDlqRecord, MatrixError> {
    let record = if !config.encrypted() {
        serde_json::from_str::<MatrixInboundDlqRecord>(line).map_err(|err| {
            MatrixError::SyncFailed(format!("parse Matrix inbound DLQ record: {err}"))
        })?
    } else {
        let envelope: MatrixEncryptedInboundDlqRecord =
            serde_json::from_str(line).map_err(|err| {
                MatrixError::SyncFailed(format!("parse encrypted Matrix inbound DLQ record: {err}"))
            })?;
        if envelope.version != 1 {
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
        let key = derive_matrix_inbound_dlq_key(state_dir, config)?;
        let plaintext = zeroize::Zeroizing::new(
            crate::crypto::decrypt_aead_blob(&key, &nonce, &ciphertext, MATRIX_INBOUND_DLQ_AAD)
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
) -> Result<[u8; crate::crypto::AEAD_KEY_LEN], MatrixError> {
    let passphrase = resolve_matrix_store_passphrase(state_dir, config)?
        .ok_or(MatrixError::MissingStoreSecret)?;
    let installation_id = read_or_create_installation_id(state_dir)?;
    let hk = Hkdf::<Sha256>::new(Some(installation_id.as_bytes()), passphrase.as_bytes());
    let mut key = [0u8; crate::crypto::AEAD_KEY_LEN];
    hk.expand(MATRIX_INBOUND_DLQ_INFO, &mut key)
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
        .map_err(|err| MatrixError::SendFailed(err.to_string()))?;
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

async fn handle_invites(client: Arc<Client>, config: &MatrixConfig) -> Result<(), MatrixError> {
    let mut failures = Vec::new();
    for room in client.invited_rooms() {
        let invite = match room.invite_details().await {
            Ok(invite) => invite,
            Err(err) => {
                warn!(room_id = %room.room_id(), error = %err, "failed to inspect Matrix invite");
                failures.push(format!("{} inspect failed: {err}", room.room_id()));
                continue;
            }
        };
        let inviter = invite
            .inviter
            .as_ref()
            .map(|member| member.user_id().to_string());
        let allowed = inviter
            .as_deref()
            .map(|user_id| config.auto_join.allows_user(user_id))
            .unwrap_or(false);
        if !allowed {
            // Distinguish two reasons for rejection so an operator
            // checking logs doesn't conclude their allowlist is
            // misconfigured when the homeserver actually withheld the
            // inviter identity.
            if inviter.is_none() {
                debug!(
                    room_id = %room.room_id(),
                    "Matrix invite rejected: homeserver did not provide an inviter identity"
                );
            } else {
                debug!(
                    room_id = %room.room_id(),
                    inviter = inviter.as_deref().unwrap_or("<unknown>"),
                    "Matrix invite rejected by auto-join allowlist"
                );
            }
            if let Err(err) = room.leave().await {
                warn!(room_id = %room.room_id(), error = %err, "failed to reject Matrix invite");
                failures.push(format!("{} reject failed: {err}", room.room_id()));
            }
            continue;
        }
        if !config.encrypted() && is_invite_room_definitely_encrypted(&room) {
            warn!(
                room_id = %room.room_id(),
                inviter = inviter.as_deref().unwrap_or("<unknown>"),
                "Matrix invite refused because room is encrypted and matrix.encrypted=false"
            );
            if let Err(err) = room.leave().await {
                warn!(room_id = %room.room_id(), error = %err, "failed to reject encrypted Matrix invite");
                failures.push(format!("{} encrypted reject failed: {err}", room.room_id()));
            }
            continue;
        }
        if let Err(err) = room.join().await {
            warn!(room_id = %room.room_id(), error = %err, "failed to auto-join Matrix invite");
            failures.push(format!("{} join failed: {err}", room.room_id()));
        } else {
            info!(
                room_id = %room.room_id(),
                inviter = inviter.as_deref().unwrap_or("<unknown>"),
                "auto-joined Matrix room invite"
            );
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(MatrixError::SyncFailed(format!(
            "Matrix invite handling failures: {}",
            failures.join("; ")
        )))
    }
}

async fn refresh_runtime_status(
    client: Arc<Client>,
    config: &MatrixConfig,
    state: &Arc<RwLock<MatrixRuntimeState>>,
) {
    // Use try_now_millis() for the observability path: when the wall
    // clock is invalid we want the field to read as `null`, not as
    // `i64::MAX` (year ~292M). The latter flows through the control
    // API and breaks any client computing a "seconds since last sync"
    // staleness metric.
    let last_successful_sync_at = try_now_millis().ok();

    // Collect the room-survey fields locally without holding any lock
    // across the SDK iteration.
    let mut joined_room_count: usize = 0;
    let mut encrypted_room_count: usize = 0;
    let mut unencrypted_room_count: usize = 0;
    let mut unsupported_room_count: usize = 0;
    let mut unsupported_rooms: Vec<String> = Vec::new();
    for room in client.joined_rooms() {
        joined_room_count += 1;
        if is_room_encrypted(&room) {
            encrypted_room_count += 1;
            if !config.encrypted() {
                unsupported_room_count += 1;
                unsupported_rooms.push(room.room_id().to_string());
                warn!(
                    room_id = %room.room_id(),
                    "Matrix room became encrypted while matrix.encrypted=false; marking unsupported"
                );
            }
        } else {
            unencrypted_room_count += 1;
        }
    }

    // Field-level merge under a single write lock: refresh OWNS the
    // room-survey + last_successful_sync_at fields and updates only
    // those. Counters mutated by concurrent paths
    // (`unsupported_inbound_count`, `inbound_dispatch_failure_total`,
    // `inbound_dlq_append_failure_total`,
    // `inbound_dlq_durability_error`) are NOT overwritten — round 11
    // moved maintenance into a JoinSet that races with the room-message
    // handler, and a wholesale `state.write().status = status` would
    // lose increments landing between this function's read and write.
    // `pending_verification_count` is derived from `verifications.len()`
    // by `MatrixRuntimeState::status()` at read time, so it is not
    // touched here either.
    let mut guard = state.write();
    guard.status.last_successful_sync_at = last_successful_sync_at;
    guard.status.joined_room_count = joined_room_count;
    guard.status.encrypted_room_count = encrypted_room_count;
    guard.status.unencrypted_room_count = unencrypted_room_count;
    guard.status.unsupported_room_count = unsupported_room_count;
    guard.status.unsupported_rooms = unsupported_rooms;
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
        .map(|device| MatrixDeviceInfo {
            user_id: device.user_id().to_string(),
            device_id: device.device_id().to_string(),
            display_name: device.display_name().map(ToOwned::to_owned),
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
) -> Result<Vec<MatrixVerificationInfo>, MatrixError> {
    prune_verification_records(state);
    let records = state.read().verifications.clone();
    let mut changed = Vec::new();
    for record in records {
        let parsed_user_id: OwnedUserId = match record.user_id.parse() {
            Ok(user_id) => user_id,
            Err(err) => {
                warn!(flow_id = %record.flow_id, error = %err, "invalid Matrix verification user ID");
                return Err(MatrixError::InvalidUserId(err.to_string()));
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
            Ok(Some(updated)) => changed.push(updated),
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
    Ok(changed)
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
        ErrorKind::UnknownToken { .. }
        | ErrorKind::Forbidden { .. }
        | ErrorKind::UserDeactivated => Some(MatrixError::Auth(display())),
        _ => None,
    }
}

fn matrix_sync_terminal_error(err: &matrix_sdk::Error) -> Option<MatrixError> {
    classify_terminal_kind(err.client_api_error_kind()?, || err.to_string())
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

/// Run `client.whoami()` with bounded retry across transient transport
/// failures. Returns:
/// - `Ok(response)` on success
/// - `Err(MatrixError::Auth)` when the retry budget is exhausted: restored-token
///   startup must fail closed rather than begin an indefinite sync backoff loop
/// - `Err(MatrixError::Auth)` when the homeserver reports a terminal
///   token error (UnknownToken / Forbidden / UserDeactivated)
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
                if matrix_http_terminal_error(&err).is_some() {
                    return Err(MatrixError::Auth(err.to_string()));
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
/// Replaces the prior `fail_pending_commands` + `drain_outbound_on_shutdown`
/// pair which differed only in the error variant they sent.
async fn drain_pending_commands(rx: &mut mpsc::Receiver<MatrixCommand>, err: MatrixError) {
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

#[inline]
async fn fail_pending_commands(rx: &mut mpsc::Receiver<MatrixCommand>, err: MatrixError) {
    drain_pending_commands(rx, err).await;
}

#[inline]
async fn drain_outbound_on_shutdown(rx: &mut mpsc::Receiver<MatrixCommand>) {
    drain_pending_commands(rx, MatrixError::NotConnected).await;
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
        assert_eq!(resolved.access_token.as_deref(), Some("env-token"));
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
            access_token: Some("token".to_string()),
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
        assert_eq!(passphrase.as_deref(), Some("operator supplied passphrase"));
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
            access_token: Some("token".to_string()),
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
            access_token: Some("token".to_string()),
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

    /// A line that fails to decode must NOT be silently dropped on the
    /// next replay. The previous implementation lost the data; the fix
    /// keeps the raw line in the rewritten file.
    #[tokio::test(flavor = "current_thread")]
    async fn test_dlq_replay_keeps_corrupt_lines_verbatim() {
        let temp = tempfile::tempdir().expect("tempdir");
        let config = matrix_test_config(false);
        let path = matrix_inbound_dlq_path(temp.path());
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

        // The corrupt line must still be on disk for forensic recovery.
        let after = tokio::fs::read_to_string(&path).await.expect("read after");
        assert!(
            after.contains("$abc:example.com"),
            "corrupt DLQ line must be preserved verbatim, got {after:?}"
        );
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
            verification: Ok(Vec::new()),
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
            verification: Ok(Vec::new()),
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
                verification: Ok(Vec::new()),
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
                verification: Ok(Vec::new()),
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
        ] {
            let err = classify_terminal_kind(&kind, || "terminal".to_string())
                .expect("terminal Matrix auth kind must classify");
            assert!(matches!(err, MatrixError::Auth(message) if message == "terminal"));
        }

        assert!(
            classify_terminal_kind(&ErrorKind::LimitExceeded { retry_after: None }, || {
                "transient".to_string()
            })
            .is_none(),
            "rate-limit errors remain transient"
        );
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

        drain_outbound_on_shutdown(&mut rx).await;

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

        fail_pending_commands(&mut rx, MatrixError::Auth("bad token".to_string())).await;

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
}
