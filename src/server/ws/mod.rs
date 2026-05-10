//! WebSocket server implementation
//!
//! Implements the gateway WebSocket protocol (handshake + framing + auth).

use axum::extract::ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade};
use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use base64::Engine as _;
use ed25519_dalek::{Signature, VerifyingKey};
use futures_util::{SinkExt, StreamExt};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, oneshot, watch};
use tracing::warn;
use uuid::Uuid;

use crate::plugins::PluginRuntime;
use crate::server::plugin_bootstrap::PluginActivationReport;
use crate::{
    agent, auth, channels, config, credentials, cron, devices, exec, messages, nodes, plugins,
    sessions, tasks,
};

#[cfg(test)]
mod golden_tests;
mod handlers;
pub(crate) mod limits;
#[cfg(test)]
mod tests;

pub(super) use handlers::*;

// Re-export types used by the agent module
pub use handlers::record_usage;
pub use handlers::AgentRunRegistry;
pub use handlers::AgentRunStatus;

// Re-export AgentRun for use by cron executor and tests
pub use handlers::sessions::AgentRun;

// Re-export config persistence types for use by control endpoint
pub(crate) use handlers::{
    broadcast_config_changed, has_config_errors, map_validation_issues, persist_config_file,
    persist_config_file_with_base_hash, read_config_snapshot, update_config_file,
};

const PROTOCOL_VERSION: u32 = 3;
const MAX_PAYLOAD_BYTES: usize = 512 * 1024;
/// Per-connection outbound channel capacity. See SECURITY comment
/// in `handle_socket` for rationale.
const WS_CONNECTION_CHANNEL_CAPACITY: usize = 256;
const MAX_BUFFERED_BYTES: usize = (1024 * 1024 * 3) / 2;
const TICK_INTERVAL_MS: u64 = 30_000;
const DEFAULT_HEARTBEAT_INTERVAL_MS: u64 = 30_000;
const MIN_HEARTBEAT_INTERVAL_MS: u64 = 1_000;
const MAX_HEARTBEAT_INTERVAL_MS: u64 = 300_000;
const HANDSHAKE_TIMEOUT_MS: u64 = 10_000;
const SIGNATURE_SKEW_MS: i64 = 600_000;
const LOGS_DEFAULT_LIMIT: usize = 500;
const LOGS_DEFAULT_MAX_BYTES: usize = 250_000;
const LOGS_MAX_LIMIT: usize = 5_000;
const LOGS_MAX_BYTES: usize = 1_000_000;
const MAX_JSON_DEPTH: usize = 32;
const WS_BROADCAST_PAYLOAD_MAX_BYTES: usize = 1024 * 1024;
const MATRIX_VERIFICATION_REQUEST_RATE_WINDOW: Duration = Duration::from_secs(60);
const MATRIX_VERIFICATION_REQUEST_RATE_BURST: u32 = 16;
const MATRIX_VERIFICATION_REQUEST_RATE_MAX_KEYS: usize = 512;
const MATRIX_VERIFICATION_REQUEST_RATE_PRUNE_INTERVAL: u64 = 64;

// WS error codes are wire-format strings clients dispatch on. Convention:
// lower_snake_case to match the rest of the JSON wire surface and OpenAI-
// style error families (`invalid_request_error`, etc.). All emit sites
// — including ad-hoc string literals in node.rs, plugin runtime, ratelimit,
// csrf, and integration goldens — must use the lower_snake form. See PR
// renaming this from the prior SCREAMING_SNAKE convention.
const ERROR_INVALID_REQUEST: &str = "invalid_request";
const ERROR_NOT_PAIRED: &str = "not_paired";
const ERROR_UNAVAILABLE: &str = "unavailable";
const ERROR_RATE_LIMITED: &str = "rate_limited";
// Note: Node doesn't use ERROR_FORBIDDEN - use ERROR_INVALID_REQUEST for auth errors

/// Wire codes whose `retryable` field is `true` in the error response.
///
/// Adding a new retryable code requires extending this list — unlisted
/// codes surface as `retryable: false`. The slice is the single source
/// of truth for retryable classification; `error_shape` consults it via
/// `wire_code_is_retryable`. Domain-level codes from
/// `AgentConfigurationError` (e.g. `unknown_route`, `missing_model`)
/// are intentionally absent — config errors require operator
/// intervention, not retry.
///
/// A typed-enum alternative (variants carrying retryability as a method)
/// would compile-time-enforce the classification but require migrating
/// every `error_shape` call site away from `&'static str`. The slice is
/// the smaller, grep-able shape that fits the existing `const ERROR_*`
/// convention.
const RETRYABLE_CODES: &[&str] = &[ERROR_UNAVAILABLE, ERROR_RATE_LIMITED];

/// Returns `true` if a wire code should surface `retryable: true` to clients.
fn wire_code_is_retryable(code: &str) -> bool {
    RETRYABLE_CODES.contains(&code)
}

const ALLOWED_CLIENT_IDS: [&str; 12] = [
    "webchat-ui",
    "carapace-control-ui",
    "webchat",
    "cli",
    "gateway-client",
    "carapace-macos",
    "carapace-ios",
    "carapace-android",
    "node-host",
    "test",
    "fingerprint",
    "carapace-probe",
];

const ALLOWED_CLIENT_MODES: [&str; 7] =
    ["webchat", "cli", "ui", "backend", "node", "probe", "test"];

const GATEWAY_METHODS: [&str; 123] = [
    // Health/status
    "health",
    "status",
    "logs.tail",
    // Channels
    "channels.status",
    "channels.logout",
    // Config
    "config.get",
    "config.set",
    "config.apply",
    "config.patch",
    "config.validate",
    "config.schema",
    "config.reload",
    // Agent
    "agent",
    "agent.identity.get",
    "agent.wait",
    // Chat
    "chat.send",
    "chat.history",
    "chat.abort",
    // Sessions
    "sessions.list",
    "sessions.preview",
    "sessions.create",
    "sessions.load",
    "sessions.fork",
    "sessions.rename",
    "sessions.switch",
    "sessions.patch",
    "sessions.reset",
    "sessions.delete",
    "sessions.compact",
    "sessions.archive",
    "sessions.restore",
    "sessions.archives",
    "sessions.archive.delete",
    "sessions.export_user",
    "sessions.purge_user",
    // TTS
    "tts.status",
    "tts.providers",
    "tts.voices",
    "tts.enable",
    "tts.disable",
    "tts.convert",
    "tts.setProvider",
    "tts.setVoice",
    "tts.configure",
    "tts.speak",
    "tts.stop",
    // Voice wake
    "voicewake.get",
    "voicewake.set",
    "voicewake.enable",
    "voicewake.disable",
    "voicewake.keywords",
    "voicewake.test",
    // Wizard
    "wizard.start",
    "wizard.next",
    "wizard.back",
    "wizard.cancel",
    "wizard.status",
    "wizard.list",
    // Talk mode
    "talk.mode",
    "talk.status",
    "talk.start",
    "talk.stop",
    "talk.configure",
    "talk.devices",
    // Models/agents/plugins
    "models.list",
    "agents.list",
    "plugins.status",
    "plugins.bins",
    "plugins.install",
    "plugins.update",
    // Update
    "update.run",
    "update.status",
    "update.check",
    "update.setChannel",
    "update.configure",
    "update.install",
    "update.dismiss",
    "update.releaseNotes",
    // Cron
    "cron.status",
    "cron.list",
    "cron.add",
    "cron.update",
    "cron.remove",
    "cron.run",
    "cron.runs",
    // Node pairing
    "node.pair.request",
    "node.pair.list",
    "node.pair.approve",
    "node.pair.reject",
    "node.pair.verify",
    "node.rename",
    "node.list",
    "node.describe",
    "node.invoke",
    "node.invoke.result",
    "node.event",
    // Device pairing
    "device.pair.list",
    "device.pair.approve",
    "device.pair.reject",
    "device.token.rotate",
    "device.token.revoke",
    // Exec approvals
    "exec.approvals.get",
    "exec.approvals.set",
    "exec.approvals.node.get",
    "exec.approvals.node.set",
    "exec.approval.request",
    "exec.approval.resolve",
    // Usage
    "usage.status",
    "usage.enable",
    "usage.disable",
    "usage.cost",
    "usage.session",
    "usage.providers",
    "usage.daily",
    "usage.monthly",
    "usage.reset",
    // Misc
    "last-heartbeat",
    "set-heartbeats",
    "wake",
    "send",
    "system-presence",
    "system-event",
    "system.info",
];

const GATEWAY_EVENTS: [&str; 22] = [
    "connect.challenge",
    "agent",
    "chat",
    "presence",
    "tick",
    "talk.mode",
    "shutdown",
    "health",
    "heartbeat",
    "cron",
    "config.changed",
    "node.pair.requested",
    "node.pair.resolved",
    "node.invoke.request",
    "node.event",
    "device.pair.requested",
    "device.pair.resolved",
    "voicewake.changed",
    "exec.approval.requested",
    "exec.approval.resolved",
    "matrix.verification.requested",
    "matrix.verification.updated",
];

#[derive(Clone, Debug, Default)]
pub struct WsAuthConfig {
    pub resolved: auth::ResolvedGatewayAuth,
}

#[derive(Clone, Debug, Default)]
pub struct WsServerConfig {
    pub auth: WsAuthConfig,
    pub policy: WsPolicy,
    pub trusted_proxies: Vec<String>,
    pub control_ui_allow_insecure_auth: bool,
    pub control_ui_disable_device_auth: bool,
    pub node_allow_commands: Vec<String>,
    pub node_deny_commands: Vec<String>,
    /// Optional session retention in days. Sessions not updated within this
    /// period are automatically deleted. `None` means unlimited retention.
    pub session_retention_days: Option<u32>,
    /// Maximum total concurrent WebSocket connections.
    /// `None` means use the default (1024).
    pub max_ws_connections: Option<usize>,
    /// Maximum concurrent WebSocket connections from a single IP.
    /// `None` means use the default (32).
    pub max_ws_per_ip: Option<usize>,
    /// Maximum JSON nesting depth for incoming WS messages.
    /// `None` means use the default (32).
    pub max_json_depth: Option<usize>,
    /// Per-connection WS message rate (messages/sec). Default 60.
    pub ws_message_rate: Option<f64>,
    /// Per-connection WS message burst capacity. Default 120.
    pub ws_message_burst: Option<f64>,
}

#[derive(Clone, Debug, Serialize)]
pub struct WsPolicy {
    pub max_payload: usize,
    pub max_buffered_bytes: usize,
    pub tick_interval_ms: u64,
}

impl Default for WsPolicy {
    fn default() -> Self {
        Self {
            max_payload: MAX_PAYLOAD_BYTES,
            max_buffered_bytes: MAX_BUFFERED_BYTES,
            tick_interval_ms: TICK_INTERVAL_MS,
        }
    }
}

/// Presence entry for a connected client.
/// Matches the Node.js PresenceEntrySchema in src/gateway/protocol/schema/snapshot.ts
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PresenceEntry {
    /// Client hostname or display name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// Client IP address (remote only)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    /// Client version
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Client platform (darwin, linux, win32)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub platform: Option<String>,
    /// Device family (MacBookPro, iPhone, etc)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_family: Option<String>,
    /// Device model identifier
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model_identifier: Option<String>,
    /// Client mode (ui, cli, webchat, etc)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    /// Connection reason (connect or disconnect)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Tags
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
    /// Last update timestamp
    pub ts: u64,
    /// Device identity ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
    /// Roles
    #[serde(skip_serializing_if = "Option::is_none")]
    pub roles: Option<Vec<String>>,
    /// Scopes
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scopes: Option<Vec<String>>,
    /// Instance ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instance_id: Option<String>,
    /// Event text (from system-event)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    /// Seconds since last input (idle time)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_input_seconds: Option<u64>,
    /// Connection ID (internal, not serialized to match Node schema)
    #[serde(skip)]
    pub conn_id: String,
    /// Client ID (internal, not serialized to match Node schema)
    #[serde(skip)]
    pub client_id: Option<String>,
}

fn presence_broadcast_payload(entry: &PresenceEntry, admin_visible: bool) -> Value {
    let mut obj = serde_json::Map::new();
    obj.insert("ts".to_string(), Value::from(entry.ts));
    if let Some(value) = &entry.host {
        obj.insert("host".to_string(), Value::String(value.clone()));
    }
    if admin_visible {
        if let Some(value) = &entry.ip {
            obj.insert("ip".to_string(), Value::String(value.clone()));
        }
    }
    if let Some(value) = &entry.version {
        obj.insert("version".to_string(), Value::String(value.clone()));
    }
    if let Some(value) = &entry.platform {
        obj.insert("platform".to_string(), Value::String(value.clone()));
    }
    if let Some(value) = &entry.mode {
        obj.insert("mode".to_string(), Value::String(value.clone()));
    }
    if let Some(value) = &entry.reason {
        obj.insert("reason".to_string(), Value::String(value.clone()));
    }
    if let Some(value) = &entry.tags {
        obj.insert("tags".to_string(), json!(value));
    }
    if let Some(value) = &entry.text {
        obj.insert("text".to_string(), Value::String(value.clone()));
    }
    if let Some(value) = entry.last_input_seconds {
        obj.insert("lastInputSeconds".to_string(), Value::from(value));
    }
    if admin_visible {
        if let Some(value) = &entry.device_id {
            obj.insert("deviceId".to_string(), Value::String(value.clone()));
        }
        if let Some(value) = &entry.roles {
            obj.insert("roles".to_string(), json!(value));
        }
        if let Some(value) = &entry.scopes {
            obj.insert("scopes".to_string(), json!(value));
        }
        if let Some(value) = &entry.instance_id {
            obj.insert("instanceId".to_string(), Value::String(value.clone()));
        }
    }
    Value::Object(obj)
}

#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WsHealthCounters {
    pub broadcast_drop_total: u64,
    pub matrix_verification_rate_limit_drop_total: u64,
    pub connection_count: usize,
    pub max_buffered_bytes: usize,
}

/// Cached health snapshot
#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HealthSnapshot {
    pub ts: u64,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub channels: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ws: Option<WsHealthCounters>,
}

#[derive(Debug, Clone)]
struct HeartbeatState {
    enabled: bool,
    interval_ms: u64,
    last_heartbeat_ms: Option<u64>,
}

/// System event entry for history
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SystemEvent {
    pub ts: u64,
    pub text: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instance_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Maximum number of system events to keep in history
const SYSTEM_EVENT_HISTORY_MAX: usize = 1000;

/// Tracks presence and health version numbers for stateVersion in events
#[derive(Debug, Default)]
struct StateVersionTracker {
    presence: u64,
    health: u64,
}

impl StateVersionTracker {
    fn increment_presence(&mut self) -> u64 {
        self.presence += 1;
        self.presence
    }

    fn increment_health(&mut self) -> u64 {
        self.health += 1;
        self.health
    }

    fn current(&self) -> StateVersion {
        StateVersion {
            presence: self.presence,
            health: self.health,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct MatrixVerificationRequestRateKey {
    user_id: String,
    device: MatrixVerificationRequestRateDevice,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum MatrixVerificationRequestRateDevice {
    DeviceId { device_id: String },
    MissingDevice { flow_id: String },
    MalformedMissingDevice,
}

#[derive(Debug, Clone)]
struct MatrixVerificationRequestRate {
    tokens: f64,
    last_refill: Instant,
    last_seen: Instant,
    sequence: u64,
    class: MatrixVerificationRequestRateClass,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MatrixVerificationRequestRateClass {
    Normal,
    Malformed,
    Finished,
}

#[derive(Debug, Default)]
struct MatrixVerificationRequestRateTable {
    buckets: HashMap<MatrixVerificationRequestRateKey, MatrixVerificationRequestRate>,
    next_sequence: u64,
    prune_calls: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MatrixVerificationRequestRateDecision {
    Allowed,
    Limited,
}

impl MatrixVerificationRequestRateTable {
    fn allow(
        &mut self,
        key: MatrixVerificationRequestRateKey,
        class: MatrixVerificationRequestRateClass,
        now: Instant,
    ) -> MatrixVerificationRequestRateDecision {
        self.prune_calls = self.prune_calls.saturating_add(1);
        if self
            .prune_calls
            .is_multiple_of(MATRIX_VERIFICATION_REQUEST_RATE_PRUNE_INTERVAL)
            || self.buckets.len() >= MATRIX_VERIFICATION_REQUEST_RATE_MAX_KEYS
        {
            self.prune_expired(now);
        }

        if !self.buckets.contains_key(&key)
            && self.buckets.len() >= MATRIX_VERIFICATION_REQUEST_RATE_MAX_KEYS
        {
            self.evict_low_value_bucket();
            if self.buckets.len() >= MATRIX_VERIFICATION_REQUEST_RATE_MAX_KEYS {
                return MatrixVerificationRequestRateDecision::Limited;
            }
        }

        let sequence = self.next_sequence;
        self.next_sequence = self.next_sequence.saturating_add(1);
        let bucket = self
            .buckets
            .entry(key)
            .or_insert_with(|| MatrixVerificationRequestRate {
                tokens: MATRIX_VERIFICATION_REQUEST_RATE_BURST as f64,
                last_refill: now,
                last_seen: now,
                sequence,
                class,
            });
        bucket.class = class;
        Self::refill_bucket(bucket, now);
        if bucket.tokens < 1.0 {
            bucket.sequence = sequence;
            return MatrixVerificationRequestRateDecision::Limited;
        }
        bucket.tokens -= 1.0;
        bucket.last_seen = now;
        bucket.sequence = sequence;
        MatrixVerificationRequestRateDecision::Allowed
    }

    fn refill_bucket(bucket: &mut MatrixVerificationRequestRate, now: Instant) {
        let elapsed = now.saturating_duration_since(bucket.last_refill);
        if elapsed.is_zero() {
            return;
        }
        let refill = elapsed.as_secs_f64() / MATRIX_VERIFICATION_REQUEST_RATE_WINDOW.as_secs_f64()
            * MATRIX_VERIFICATION_REQUEST_RATE_BURST as f64;
        bucket.tokens = (bucket.tokens + refill).min(MATRIX_VERIFICATION_REQUEST_RATE_BURST as f64);
        bucket.last_refill = now;
    }

    fn prune_expired(&mut self, now: Instant) {
        self.buckets.retain(|_, bucket| {
            now.saturating_duration_since(bucket.last_seen)
                < MATRIX_VERIFICATION_REQUEST_RATE_WINDOW * 2
        });
    }

    fn evict_low_value_bucket(&mut self) {
        let Some(key) = self
            .buckets
            .iter()
            .filter(|(_, bucket)| {
                matches!(
                    bucket.class,
                    MatrixVerificationRequestRateClass::Malformed
                        | MatrixVerificationRequestRateClass::Finished
                )
            })
            .min_by_key(|(_, bucket)| bucket.sequence)
            .map(|(key, _)| key.clone())
        else {
            return;
        };
        self.buckets.remove(&key);
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.buckets.len()
    }
}

pub struct WsServerState {
    config: WsServerConfig,
    start_time: Instant,
    device_registry: Arc<devices::DevicePairingRegistry>,
    node_registry: Mutex<NodeRegistry>,
    node_pairing: Arc<nodes::NodePairingRegistry>,
    connections: Mutex<HashMap<String, ConnectionHandle>>,
    session_defaults: Mutex<HashMap<String, SessionDefaults>>,
    channel_registry: Arc<channels::ChannelRegistry>,
    message_pipeline: Arc<messages::outbound::MessagePipeline>,
    session_store: Arc<sessions::SessionStore>,
    event_seq: Mutex<u64>,
    state_broadcast_ordering: Mutex<()>,
    /// Tracks connected client presence
    presence: Mutex<HashMap<String, PresenceEntry>>,
    /// Cached health snapshot
    health_cache: Mutex<HealthSnapshot>,
    /// Tracks state versions for presence and health
    state_versions: Mutex<StateVersionTracker>,
    /// Heartbeat configuration and last event timestamp
    heartbeat_state: Mutex<HeartbeatState>,
    /// Exec approval manager
    exec_manager: exec::ExecApprovalManager,
    /// Cron job scheduler
    pub cron_scheduler: cron::CronScheduler,
    /// Durable task queue for long-running autonomy workflows.
    pub task_queue: Arc<tasks::TaskQueue>,
    /// Agent run registry for tracking active/completed agent invocations
    pub agent_run_registry: Mutex<handlers::AgentRunRegistry>,
    /// System event history (enqueued via system-event method)
    system_event_history: Mutex<Vec<SystemEvent>>,
    /// Per-peer/device burst guard for Matrix verification-request broadcasts.
    matrix_verification_request_rates: Mutex<MatrixVerificationRequestRateTable>,
    matrix_verification_rate_limit_drop_total: AtomicU64,
    ws_broadcast_drop_total: AtomicU64,
    /// LLM provider for agent execution (hot-swappable via RwLock)
    llm_provider: parking_lot::RwLock<Option<Arc<dyn agent::LlmProvider>>>,
    /// Sender for synchronous reload commands routed to the hot-reload
    /// bridge. Set once after the bridge spawns; left `None` in test setups
    /// that don't run the bridge.
    reload_command_tx: parking_lot::RwLock<
        Option<tokio::sync::mpsc::Sender<crate::server::startup::ReloadCommand>>,
    >,
    /// Tools registry for agent tool dispatch
    tools_registry: Option<Arc<plugins::ToolsRegistry>>,
    /// Plugin registry for channel/tool/webhook plugins
    plugin_registry: Option<Arc<plugins::PluginRegistry>>,
    /// Runtime-owned service for channel activity side effects and warnings.
    activity_service: Arc<channels::activity::ActivityService>,
    /// Runtime-owned Matrix channel state and command actor.
    matrix_runtime: parking_lot::RwLock<Option<Arc<channels::matrix::MatrixRuntimeHandle>>>,
    /// Retained plugin runtime for instantiated plugin lifetimes and epoch ticker.
    plugin_runtime: Option<Arc<PluginRuntime<credentials::DefaultCredentialBackend>>>,
    /// Startup-time plugin activation report
    plugin_activation_report: Option<PluginActivationReport>,
    /// WebSocket connection limiter
    pub(crate) connection_tracker: limits::ConnectionTracker,
}

impl std::fmt::Debug for WsServerState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WsServerState")
            .field("config", &self.config)
            .field("start_time", &self.start_time)
            .field(
                "llm_provider",
                &self.llm_provider.read().as_ref().map(|_| ".."),
            )
            .field(
                "reload_command_tx",
                &self.reload_command_tx.read().as_ref().map(|_| ".."),
            )
            .field(
                "tools_registry",
                &self.tools_registry.as_ref().map(|_| ".."),
            )
            .field(
                "plugin_registry",
                &self.plugin_registry.as_ref().map(|_| ".."),
            )
            .field("activity_service", &"..")
            .field(
                "matrix_runtime",
                &self.matrix_runtime.read().as_ref().map(|_| ".."),
            )
            .field(
                "plugin_runtime",
                &self.plugin_runtime.as_ref().map(|_| ".."),
            )
            .field(
                "plugin_activation_report",
                &self.plugin_activation_report.as_ref().map(|_| ".."),
            )
            .finish_non_exhaustive()
    }
}

impl WsServerState {
    pub fn new(config: WsServerConfig) -> Self {
        Self::try_new(config).expect("failed to initialize in-memory websocket server state")
    }

    pub fn try_new(config: WsServerConfig) -> Result<Self, WsConfigError> {
        Self::build_in_memory_with_activity_service_factory(config, || {
            channels::activity::ActivityService::try_new()
        })
    }

    fn build_in_memory_with_activity_service_factory<F>(
        config: WsServerConfig,
        activity_service_factory: F,
    ) -> Result<Self, WsConfigError>
    where
        F: FnOnce() -> Result<
            channels::activity::ActivityService,
            channels::activity::ActivityStartupError,
        >,
    {
        let connection_tracker = limits::ConnectionTracker::with_limits(
            config
                .max_ws_connections
                .unwrap_or(limits::DEFAULT_MAX_CONNECTIONS),
            config.max_ws_per_ip.unwrap_or(limits::DEFAULT_MAX_PER_IP),
        );
        Ok(Self {
            config,
            start_time: Instant::now(),
            device_registry: Arc::new(devices::DevicePairingRegistry::in_memory()),
            node_registry: Mutex::new(NodeRegistry::default()),
            node_pairing: Arc::new(nodes::NodePairingRegistry::in_memory()),
            connections: Mutex::new(HashMap::new()),
            session_defaults: Mutex::new(HashMap::new()),
            channel_registry: channels::create_registry(),
            message_pipeline: messages::outbound::create_pipeline(),
            session_store: Arc::new(sessions::SessionStore::with_base_path(
                resolve_state_dir().join("sessions"),
            )),
            event_seq: Mutex::new(0),
            state_broadcast_ordering: Mutex::new(()),
            presence: Mutex::new(HashMap::new()),
            health_cache: Mutex::new(HealthSnapshot {
                ts: now_ms(),
                status: "healthy".to_string(),
                channels: None,
                agent: None,
                ws: None,
            }),
            state_versions: Mutex::new(StateVersionTracker::default()),
            heartbeat_state: Mutex::new(HeartbeatState {
                enabled: false,
                interval_ms: DEFAULT_HEARTBEAT_INTERVAL_MS,
                last_heartbeat_ms: None,
            }),
            exec_manager: exec::ExecApprovalManager::new(),
            cron_scheduler: cron::CronScheduler::in_memory(),
            task_queue: Arc::new(tasks::TaskQueue::in_memory()),
            agent_run_registry: Mutex::new(handlers::AgentRunRegistry::new()),
            system_event_history: Mutex::new(Vec::new()),
            matrix_verification_request_rates: Mutex::new(
                MatrixVerificationRequestRateTable::default(),
            ),
            matrix_verification_rate_limit_drop_total: AtomicU64::new(0),
            ws_broadcast_drop_total: AtomicU64::new(0),
            llm_provider: parking_lot::RwLock::new(None),
            reload_command_tx: parking_lot::RwLock::new(None),
            tools_registry: None,
            plugin_registry: None,
            activity_service: Arc::new(activity_service_factory()?),
            matrix_runtime: parking_lot::RwLock::new(None),
            plugin_runtime: None,
            plugin_activation_report: None,
            connection_tracker,
        })
    }

    #[cfg(test)]
    pub(crate) fn try_new_with_activity_service_factory_for_test<F>(
        config: WsServerConfig,
        activity_service_factory: F,
    ) -> Result<Self, WsConfigError>
    where
        F: FnOnce() -> Result<
            channels::activity::ActivityService,
            channels::activity::ActivityStartupError,
        >,
    {
        Self::build_in_memory_with_activity_service_factory(config, activity_service_factory)
    }

    fn build_persistent_unloaded_with_activity_service_factory<F>(
        config: WsServerConfig,
        state_dir: PathBuf,
        activity_service_factory: F,
    ) -> Result<Self, WsConfigError>
    where
        F: FnOnce(
            PathBuf,
        ) -> Result<
            channels::activity::ActivityService,
            channels::activity::ActivityStartupError,
        >,
    {
        let node_pairing = nodes::create_registry(state_dir.clone())?;
        let device_registry = devices::create_registry(state_dir.clone())?;
        let connection_tracker = limits::ConnectionTracker::with_limits(
            config
                .max_ws_connections
                .unwrap_or(limits::DEFAULT_MAX_CONNECTIONS),
            config.max_ws_per_ip.unwrap_or(limits::DEFAULT_MAX_PER_IP),
        );
        let activity_state_dir = state_dir.clone();
        let activity_service = activity_service_factory(activity_state_dir)?;
        Ok(Self {
            config,
            start_time: Instant::now(),
            device_registry,
            node_registry: Mutex::new(NodeRegistry::default()),
            node_pairing,
            connections: Mutex::new(HashMap::new()),
            session_defaults: Mutex::new(HashMap::new()),
            channel_registry: channels::create_registry(),
            message_pipeline: messages::outbound::create_pipeline(),
            session_store: Arc::new(sessions::SessionStore::with_base_path(
                state_dir.join("sessions"),
            )),
            event_seq: Mutex::new(0),
            state_broadcast_ordering: Mutex::new(()),
            presence: Mutex::new(HashMap::new()),
            health_cache: Mutex::new(HealthSnapshot {
                ts: now_ms(),
                status: "healthy".to_string(),
                channels: None,
                agent: None,
                ws: None,
            }),
            state_versions: Mutex::new(StateVersionTracker::default()),
            heartbeat_state: Mutex::new(HeartbeatState {
                enabled: false,
                interval_ms: DEFAULT_HEARTBEAT_INTERVAL_MS,
                last_heartbeat_ms: None,
            }),
            exec_manager: exec::ExecApprovalManager::new(),
            cron_scheduler: {
                cron::CronScheduler::new(true, Some(state_dir.join("cron").join("jobs.json")))
            },
            task_queue: {
                Arc::new(tasks::TaskQueue::new(Some(
                    state_dir.join("tasks").join("queue.json"),
                )))
            },
            agent_run_registry: Mutex::new(handlers::AgentRunRegistry::new()),
            system_event_history: Mutex::new(Vec::new()),
            matrix_verification_request_rates: Mutex::new(
                MatrixVerificationRequestRateTable::default(),
            ),
            matrix_verification_rate_limit_drop_total: AtomicU64::new(0),
            ws_broadcast_drop_total: AtomicU64::new(0),
            llm_provider: parking_lot::RwLock::new(None),
            reload_command_tx: parking_lot::RwLock::new(None),
            tools_registry: None,
            plugin_registry: None,
            activity_service: Arc::new(activity_service),
            matrix_runtime: parking_lot::RwLock::new(None),
            plugin_runtime: None,
            plugin_activation_report: None,
            connection_tracker,
        })
    }

    fn new_persistent_unloaded(
        config: WsServerConfig,
        state_dir: PathBuf,
    ) -> Result<Self, WsConfigError> {
        Self::build_persistent_unloaded_with_activity_service_factory(
            config,
            state_dir,
            channels::activity::ActivityService::try_new_persistent,
        )
    }

    #[cfg(test)]
    pub(crate) fn try_new_persistent_unloaded_with_activity_service_factory_for_test<F>(
        config: WsServerConfig,
        state_dir: PathBuf,
        activity_service_factory: F,
    ) -> Result<Self, WsConfigError>
    where
        F: FnOnce(
            PathBuf,
        ) -> Result<
            channels::activity::ActivityService,
            channels::activity::ActivityStartupError,
        >,
    {
        Self::build_persistent_unloaded_with_activity_service_factory(
            config,
            state_dir,
            activity_service_factory,
        )
    }

    /// Construct persistent WS server state, including async-safe task queue
    /// load/recovery and async-safe cron scheduler load.
    pub async fn new_persistent(
        config: WsServerConfig,
        state_dir: PathBuf,
    ) -> Result<Self, WsConfigError> {
        let cleanup_state_dir = state_dir.clone();
        let state = Self::new_persistent_unloaded(config, state_dir)?;
        let state = tokio::task::spawn_blocking(move || {
            state.cron_scheduler.load();
            state
        })
        .await
        .map_err(|err| {
            let reason = if err.is_panic() {
                "panicked"
            } else if err.is_cancelled() {
                "was cancelled"
            } else {
                "failed"
            };
            WsConfigError::Runtime(format!(
                "cron scheduler load worker {reason} during startup: {err}"
            ))
        })?;
        state
            .task_queue
            .load_async()
            .await
            .map_err(WsConfigError::Runtime)?;
        state
            .activity_service
            .read_receipt_queue()
            .load_async()
            .await
            .map_err(WsConfigError::Runtime)?;
        tokio::task::spawn_blocking(move || {
            crate::update::cleanup_startup_update_state(&cleanup_state_dir)
        })
        .await
        .map_err(|err| {
            let reason = if err.is_panic() {
                "panicked"
            } else if err.is_cancelled() {
                "was cancelled"
            } else {
                "failed"
            };
            WsConfigError::Runtime(format!(
                "update cleanup worker {reason} during startup: {err}"
            ))
        })?;
        Ok(state)
    }

    pub fn with_node_pairing(mut self, registry: Arc<nodes::NodePairingRegistry>) -> Self {
        self.node_pairing = registry;
        self
    }

    pub fn with_device_registry(mut self, registry: Arc<devices::DevicePairingRegistry>) -> Self {
        self.device_registry = registry;
        self
    }

    #[cfg(test)]
    pub(crate) fn with_session_store(mut self, store: Arc<sessions::SessionStore>) -> Self {
        self.session_store = store;
        self
    }

    pub fn with_llm_provider(self, provider: Arc<dyn agent::LlmProvider>) -> Self {
        *self.llm_provider.write() = Some(provider);
        self
    }

    pub fn with_tools_registry(mut self, registry: Arc<plugins::ToolsRegistry>) -> Self {
        self.tools_registry = Some(registry);
        self
    }

    pub fn with_plugin_registry(mut self, registry: Arc<plugins::PluginRegistry>) -> Self {
        self.plugin_registry = Some(registry);
        self
    }

    #[cfg(test)]
    pub(crate) fn with_activity_service(
        mut self,
        activity_service: Arc<channels::activity::ActivityService>,
    ) -> Self {
        self.activity_service = activity_service;
        self
    }

    pub(crate) fn with_plugin_runtime_opt(
        mut self,
        runtime: Option<Arc<PluginRuntime<credentials::DefaultCredentialBackend>>>,
    ) -> Self {
        self.plugin_runtime = runtime;
        self
    }

    pub fn set_matrix_runtime(&self, runtime: Option<Arc<channels::matrix::MatrixRuntimeHandle>>) {
        *self.matrix_runtime.write() = runtime;
    }

    pub(crate) fn with_plugin_activation_report(mut self, report: PluginActivationReport) -> Self {
        self.plugin_activation_report = Some(report);
        self
    }

    /// Get the session store.
    pub fn session_store(&self) -> &Arc<sessions::SessionStore> {
        &self.session_store
    }

    /// Get the configured session retention period in days, if any.
    pub fn session_retention_days(&self) -> Option<u32> {
        self.config.session_retention_days
    }

    pub(crate) fn default_session_key(&self, conn_id: &str) -> Option<String> {
        self.session_defaults
            .lock()
            .get(conn_id)
            .and_then(|defaults| {
                defaults
                    .main_session_key
                    .clone()
                    .or_else(|| defaults.main_key.clone())
            })
    }

    pub(crate) fn update_session_defaults(
        &self,
        conn_id: &str,
        session_key: String,
        agent_id: Option<String>,
        scope: Option<String>,
    ) -> Value {
        let defaults = SessionDefaults {
            default_agent_id: agent_id,
            main_key: Some(session_key.clone()),
            main_session_key: Some(session_key),
            scope,
        };
        self.session_defaults
            .lock()
            .insert(conn_id.to_string(), defaults.clone());
        defaults.to_value()
    }

    /// Get the tools registry, if configured.
    pub fn tools_registry(&self) -> Option<&plugins::ToolsRegistry> {
        self.tools_registry.as_deref()
    }

    /// Get the LLM provider, if configured.
    pub fn llm_provider(&self) -> Option<Arc<dyn agent::LlmProvider>> {
        self.llm_provider.read().clone()
    }

    /// Hot-swap the LLM provider at runtime (e.g. on config reload).
    pub fn set_llm_provider(&self, provider: Option<Arc<dyn agent::LlmProvider>>) {
        *self.llm_provider.write() = provider;
    }

    /// Return a clone of the reload-command sender if the hot-reload bridge
    /// is running. WS handlers use this to route manual reloads through the
    /// bridge for provider validation.
    pub(crate) fn reload_command_tx(
        &self,
    ) -> Option<tokio::sync::mpsc::Sender<crate::server::startup::ReloadCommand>> {
        self.reload_command_tx.read().clone()
    }

    /// Publish the reload-command sender; called once by the hot-reload
    /// bridge after it spawns. `None` clears the slot (e.g. on shutdown).
    pub(crate) fn set_reload_command_tx(
        &self,
        tx: Option<tokio::sync::mpsc::Sender<crate::server::startup::ReloadCommand>>,
    ) {
        *self.reload_command_tx.write() = tx;
    }

    /// Get the plugin registry, if configured.
    pub fn plugin_registry(&self) -> Option<&Arc<plugins::PluginRegistry>> {
        self.plugin_registry.as_ref()
    }

    pub fn activity_service(&self) -> &Arc<channels::activity::ActivityService> {
        &self.activity_service
    }

    pub fn matrix_runtime(&self) -> Option<Arc<channels::matrix::MatrixRuntimeHandle>> {
        self.matrix_runtime.read().clone()
    }

    /// Runtime-owned shutdown entrypoint for Matrix background work.
    ///
    /// The Matrix runtime owns its sync loop, send tasks, and DLQ replay state,
    /// so server shutdown waits for its completion signal after broadcasting the
    /// shared shutdown watch. Dropping only the handle would leave a best-effort
    /// fire-and-forget task with user-visible side effects still in flight.
    pub async fn shutdown_matrix_runtime(&self) {
        let Some(runtime) = self.matrix_runtime() else {
            return;
        };
        if !runtime.wait_for_shutdown(Duration::from_secs(10)).await {
            warn!("Matrix runtime did not finish within 10s shutdown timeout");
        }
        self.set_matrix_runtime(None);
    }

    /// Runtime-owned shutdown entrypoint for channel activity side effects.
    ///
    /// This is the only runtime path that should close intake and drain the
    /// activity subsystem. The activity service owns shutdown coordination.
    pub async fn shutdown_activity_service(&self) {
        self.activity_service.shutdown().await;
    }

    pub(crate) fn plugin_runtime(
        &self,
    ) -> Option<&Arc<PluginRuntime<credentials::DefaultCredentialBackend>>> {
        self.plugin_runtime.as_ref()
    }

    pub(crate) fn plugin_activation_report(&self) -> Option<&PluginActivationReport> {
        self.plugin_activation_report.as_ref()
    }

    /// Get the outbound message pipeline.
    pub fn message_pipeline(&self) -> &Arc<messages::outbound::MessagePipeline> {
        &self.message_pipeline
    }

    /// Get the durable task queue.
    pub fn task_queue(&self) -> &Arc<tasks::TaskQueue> {
        &self.task_queue
    }

    /// Get the channel registry.
    pub fn channel_registry(&self) -> &Arc<channels::ChannelRegistry> {
        &self.channel_registry
    }

    /// Get the exec approval manager.
    pub(crate) fn exec_manager(&self) -> &exec::ExecApprovalManager {
        &self.exec_manager
    }

    fn next_event_seq(&self) -> u64 {
        let mut guard = self.event_seq.lock();
        *guard += 1;
        *guard
    }

    fn next_presence_event_ordering(&self) -> (u64, StateVersion) {
        let mut seq = self.event_seq.lock();
        let mut versions = self.state_versions.lock();
        versions.increment_presence();
        *seq += 1;
        (*seq, versions.current())
    }

    fn next_health_event_ordering(&self) -> (u64, StateVersion) {
        let mut seq = self.event_seq.lock();
        let mut versions = self.state_versions.lock();
        versions.increment_health();
        *seq += 1;
        (*seq, versions.current())
    }

    fn allow_matrix_verification_request_broadcast(&self, event: &str, payload: &Value) -> bool {
        let key = matrix_verification_request_rate_key(event, payload);
        let class = matrix_verification_request_rate_class(payload);
        let now = Instant::now();
        let mut rates = self.matrix_verification_request_rates.lock();
        match rates.allow(key, class, now) {
            MatrixVerificationRequestRateDecision::Allowed => true,
            MatrixVerificationRequestRateDecision::Limited => false,
        }
    }

    fn record_ws_broadcast_drop(&self) -> u64 {
        crate::server::metrics::STD_METRICS
            .ws_broadcast_drops_total
            .inc();
        self.ws_broadcast_drop_total
            .fetch_add(1, Ordering::Relaxed)
            .saturating_add(1)
    }

    fn record_matrix_verification_rate_limit_drop(&self) -> u64 {
        crate::server::metrics::STD_METRICS
            .matrix_verification_rate_limit_drops_total
            .inc();
        self.matrix_verification_rate_limit_drop_total
            .fetch_add(1, Ordering::Relaxed)
            .saturating_add(1)
    }

    /// Get the current state version (presence + health)
    fn current_state_version(&self) -> StateVersion {
        self.state_versions.lock().current()
    }

    /// Register a connection and update presence tracking.
    /// Broadcasts a presence event to all operators.
    fn register_connection<T>(&self, conn: &ConnectionContext, tx: T, remote_ip: Option<String>)
    where
        T: Into<ConnectionTx>,
    {
        // Add to connections map
        {
            let mut conns = self.connections.lock();
            conns.insert(
                conn.conn_id.clone(),
                ConnectionHandle {
                    role: conn.role.clone(),
                    scopes: conn.scopes.clone(),
                    tx: tx.into(),
                },
            );
        }

        // Add to presence tracking
        let entry = PresenceEntry {
            host: conn.client.display_name.clone(),
            ip: remote_ip,
            version: Some(conn.client.version.clone()),
            platform: Some(conn.client.platform.clone()),
            device_family: conn.client.device_family.clone(),
            model_identifier: conn.client.model_identifier.clone(),
            mode: Some(conn.client.mode.clone()),
            reason: Some("connect".to_string()),
            tags: None,
            ts: now_ms(),
            device_id: conn.device_id.clone(),
            conn_id: conn.conn_id.clone(),
            client_id: Some(conn.client.id.clone()),
            roles: Some(vec![conn.role.clone()]),
            scopes: Some(conn.scopes.clone()),
            instance_id: conn.client.instance_id.clone(),
            text: None,
            last_input_seconds: None,
        };

        {
            let mut presence = self.presence.lock();
            presence.insert(conn.conn_id.clone(), entry);
        }

        self.broadcast_next_presence_event();
    }

    /// Unregister a connection and update presence tracking.
    /// Broadcasts a presence event to remaining operators.
    fn unregister_connection(&self, conn_id: &str) {
        if self.remove_connection_state(conn_id) {
            self.broadcast_next_presence_event();
        }
    }

    fn remove_connection_state(&self, conn_id: &str) -> bool {
        let removed = {
            let mut conns = self.connections.lock();
            conns.remove(conn_id).is_some()
        };
        {
            let mut defaults = self.session_defaults.lock();
            defaults.remove(conn_id);
        }
        {
            let mut presence = self.presence.lock();
            if let Some(entry) = presence.get_mut(conn_id) {
                entry.reason = Some("disconnect".to_string());
                entry.ts = now_ms();
            }
            presence.remove(conn_id);
        }
        removed
    }

    fn drop_connection_after_send_failure(&self, conn_id: &str, event: &str) {
        let tx = {
            let conns = self.connections.lock();
            conns.get(conn_id).map(|handle| handle.tx.clone())
        };
        if let Some(tx) = tx {
            tx.close();
        }
        if !self.remove_connection_state(conn_id) {
            return;
        }
        let drop_total = self.record_ws_broadcast_drop();
        warn!(
            conn_id = %conn_id,
            event = %event,
            drop_total,
            "WS client backpressure or close detected during broadcast; unregistering connection"
        );
        if event == "presence" {
            return;
        }
        self.broadcast_next_presence_event();
    }

    /// Get current presence list as JSON values with TTL pruning and ts-desc ordering.
    /// Prunes expired entries (older than 5 minutes) to match Node's listSystemPresence.
    #[cfg(test)]
    fn get_presence_list(&self) -> Vec<Value> {
        self.get_presence_list_for_recipient(false)
    }

    fn get_presence_list_for_conn(&self, conn_id: &str) -> Vec<Value> {
        let admin_visible = {
            let conns = self.connections.lock();
            conns
                .get(conn_id)
                .is_some_and(connection_has_admin_presence_visibility)
        };
        self.get_presence_list_for_recipient(admin_visible)
    }

    fn get_presence_list_for_recipient(&self, admin_visible: bool) -> Vec<Value> {
        const PRESENCE_TTL_MS: u64 = 5 * 60 * 1000; // 5 minutes
        const MAX_PRESENCE_ENTRIES: usize = 200; // Node uses 200
        let now = now_ms();
        let cutoff = now.saturating_sub(PRESENCE_TTL_MS);

        let mut presence = self.presence.lock();

        // Prune expired entries
        presence.retain(|_, entry| entry.ts >= cutoff);

        // Collect, filter disconnects, and sort by ts descending
        let mut entries: Vec<_> = presence
            .values()
            .filter(|e| e.reason.as_deref() != Some("disconnect"))
            .map(|e| (e.ts, presence_broadcast_payload(e, admin_visible)))
            .collect();

        // Sort by ts descending (newest first)
        entries.sort_by(|a, b| b.0.cmp(&a.0));

        // Limit to MAX_PRESENCE_ENTRIES (Node parity)
        entries
            .into_iter()
            .take(MAX_PRESENCE_ENTRIES)
            .map(|(_, v)| v)
            .collect()
    }

    /// Enqueue a system event to history (per Node's enqueueSystemEvent)
    pub fn enqueue_system_event(&self, event: SystemEvent) {
        let mut history = self.system_event_history.lock();
        history.push(event);
        // Trim to max size, keeping newest
        if history.len() > SYSTEM_EVENT_HISTORY_MAX {
            let excess = history.len() - SYSTEM_EVENT_HISTORY_MAX;
            history.drain(0..excess);
        }
    }

    /// Get system event history
    pub fn get_system_event_history(&self) -> Vec<SystemEvent> {
        self.system_event_history.lock().clone()
    }

    /// Get cached health snapshot
    fn get_health_snapshot(&self) -> HealthSnapshot {
        let mut snapshot = self.health_cache.lock().clone();
        snapshot.ws = Some(self.ws_health_counters());
        snapshot
    }

    fn ws_health_counters(&self) -> WsHealthCounters {
        WsHealthCounters {
            broadcast_drop_total: self.ws_broadcast_drop_total.load(Ordering::Relaxed),
            matrix_verification_rate_limit_drop_total: self
                .matrix_verification_rate_limit_drop_total
                .load(Ordering::Relaxed),
            connection_count: self.connections.lock().len(),
            max_buffered_bytes: self.config.policy.max_buffered_bytes,
        }
    }

    /// Get a snapshot of heartbeat state.
    fn heartbeat_snapshot(&self) -> HeartbeatState {
        self.heartbeat_state.lock().clone()
    }

    /// Update heartbeat settings.
    fn set_heartbeat_settings(&self, enabled: bool, interval_ms: u64) -> HeartbeatState {
        let mut state = self.heartbeat_state.lock();
        state.enabled = enabled;
        state.interval_ms = interval_ms.clamp(MIN_HEARTBEAT_INTERVAL_MS, MAX_HEARTBEAT_INTERVAL_MS);
        state.clone()
    }

    /// Record a heartbeat event and return the timestamp.
    fn record_heartbeat(&self) -> u64 {
        let mut state = self.heartbeat_state.lock();
        let ts = now_ms();
        state.last_heartbeat_ms = Some(ts);
        ts
    }

    /// Update health snapshot and broadcast if changed
    pub fn update_health(&self, status: &str, channels: Option<Value>, agent: Option<Value>) {
        let new_snapshot = HealthSnapshot {
            ts: now_ms(),
            status: status.to_string(),
            channels,
            agent,
            ws: Some(self.ws_health_counters()),
        };

        let should_broadcast = {
            let mut cache = self.health_cache.lock();
            let changed = cache.status != new_snapshot.status;
            *cache = new_snapshot.clone();
            changed
        };

        if should_broadcast {
            self.broadcast_next_health_event(new_snapshot);
        }
    }

    fn broadcast_next_presence_event(&self) {
        let dead = {
            let _order = self.state_broadcast_ordering.lock();
            let (seq, state_version) = self.next_presence_event_ordering();
            self.broadcast_presence_event_unlocked(seq, state_version)
        };
        self.drop_dead_broadcast_connections(dead, "presence");
    }

    /// Broadcast presence event to all operator connections
    pub(crate) fn broadcast_presence_event(&self, seq: u64, state_version: StateVersion) {
        let dead = {
            let _order = self.state_broadcast_ordering.lock();
            self.broadcast_presence_event_unlocked(seq, state_version)
        };
        self.drop_dead_broadcast_connections(dead, "presence");
    }

    fn broadcast_presence_event_unlocked(
        &self,
        seq: u64,
        state_version: StateVersion,
    ) -> Vec<String> {
        broadcast_presence_event_per_recipient(self, seq, state_version)
    }

    fn broadcast_next_health_event(&self, snapshot: HealthSnapshot) {
        let dead = {
            let _order = self.state_broadcast_ordering.lock();
            let (seq, state_version) = self.next_health_event_ordering();
            self.broadcast_health_event_unlocked(snapshot, seq, state_version)
        };
        self.drop_dead_broadcast_connections(dead, "health");
    }

    /// Broadcast health event to all operator connections
    #[allow(dead_code)]
    fn broadcast_health_event(
        &self,
        snapshot: HealthSnapshot,
        seq: u64,
        state_version: StateVersion,
    ) {
        let dead = {
            let _order = self.state_broadcast_ordering.lock();
            self.broadcast_health_event_unlocked(snapshot, seq, state_version)
        };
        self.drop_dead_broadcast_connections(dead, "health");
    }

    fn broadcast_health_event_unlocked(
        &self,
        snapshot: HealthSnapshot,
        seq: u64,
        state_version: StateVersion,
    ) -> Vec<String> {
        let Some(serialized) = serialize_event_frame_with_explicit_seq(
            self,
            "health",
            serde_json::to_value(&snapshot).unwrap_or(json!({})),
            seq,
            Some(state_version),
        ) else {
            return Vec::new();
        };
        broadcast_serialized_event_collect_dead(self, "health", serialized, false)
    }

    fn drop_dead_broadcast_connections(&self, dead: Vec<String>, event: &str) {
        for conn_id in dead {
            self.drop_connection_after_send_failure(&conn_id, event);
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum WsConfigError {
    #[error(transparent)]
    Config(#[from] config::ConfigError),
    #[error(transparent)]
    Credentials(#[from] credentials::CredentialError),
    #[error(transparent)]
    Nodes(#[from] nodes::NodePairingError),
    #[error(transparent)]
    Devices(#[from] devices::DevicePairingError),
    #[error("failed to initialize activity service: {0}")]
    ActivityStartup(#[from] channels::activity::ActivityStartupError),
    #[error("{0}")]
    Runtime(String),
}

pub async fn build_ws_state_owned_from_value(cfg: &Value) -> Result<WsServerState, WsConfigError> {
    let state_dir = resolve_state_dir();
    {
        let state_dir = state_dir.clone();
        tokio::task::spawn_blocking(move || {
            credentials::reject_plaintext_credential_files(&state_dir)
        })
        .await
        .map_err(|e| WsConfigError::Runtime(format!("plaintext credential scan join: {e}")))??;
    }
    let config = build_ws_config_from_value(cfg).await?;
    let mut state = WsServerState::new_persistent(config, state_dir).await?;
    let integrity_config = sessions::resolve_session_integrity_config(cfg);
    let encryption_config = sessions::resolve_session_encryption_config(cfg);
    let fallback_integrity_secret = resolve_session_integrity_secret(
        &state.config.auth.resolved,
        config::read_config_env("CARAPACE_SERVER_SECRET"),
    );
    let encryption_password_present = crate::config::config_password().is_some();
    let session_store = sessions::configured_store_with_path(
        state.session_store.base_path().to_path_buf(),
        cfg,
        fallback_integrity_secret.clone(),
    )
    .map_err(|err| WsConfigError::Runtime(format!("failed to configure session store: {err}")))?;
    state.session_store = Arc::new(session_store);

    if encryption_config.mode.uses_encryption() && encryption_password_present {
        tracing::info!(mode = ?encryption_config.mode, "session encryption enabled");
        tracing::info!(
            action = ?integrity_config.action,
            source = "session encryption master key",
            "session integrity verification enabled"
        );
    } else if integrity_config.enabled {
        if let Some((_, source)) = fallback_integrity_secret {
            tracing::info!(
                action = ?integrity_config.action,
                source,
                "session integrity verification enabled"
            );
        } else {
            tracing::warn!(
                "sessions.integrity.enabled is true but no server secret found \
                 (set gateway.auth.token/password or CARAPACE_SERVER_SECRET); \
                 sessions will run without integrity verification"
            );
        }
    }

    Ok(state)
}

fn resolve_session_integrity_secret(
    auth: &auth::ResolvedGatewayAuth,
    env_server_secret: Option<String>,
) -> Option<(String, &'static str)> {
    if let Some(secret) = env_server_secret.filter(|value| !value.is_empty()) {
        return Some((secret, "CARAPACE_SERVER_SECRET"));
    }
    if let Some(secret) = auth
        .token
        .as_ref()
        .filter(|value| !value.is_empty())
        .cloned()
    {
        return Some((secret, "gateway token"));
    }
    if let Some(secret) = auth
        .password
        .as_ref()
        .filter(|value| !value.is_empty())
        .cloned()
    {
        return Some((secret, "gateway password"));
    }
    None
}

pub async fn build_ws_state_owned_from_config() -> Result<WsServerState, WsConfigError> {
    let cfg = config::load_config()?;
    build_ws_state_owned_from_value(&cfg).await
}

pub async fn build_ws_state_from_config() -> Result<Arc<WsServerState>, WsConfigError> {
    Ok(Arc::new(build_ws_state_owned_from_config().await?))
}

pub async fn build_ws_config_from_value(cfg: &Value) -> Result<WsServerConfig, WsConfigError> {
    let gateway = cfg.get("gateway").and_then(|v| v.as_object());

    let resolved_auth = resolve_gateway_auth_config(gateway, cfg).await?;
    let options = parse_ws_server_options(gateway, cfg);

    Ok(WsServerConfig {
        auth: WsAuthConfig {
            resolved: resolved_auth,
        },
        policy: WsPolicy::default(),
        trusted_proxies: options.trusted_proxies,
        control_ui_allow_insecure_auth: options.control_ui_allow_insecure_auth,
        control_ui_disable_device_auth: options.control_ui_disable_device_auth,
        node_allow_commands: options.node_allow_commands,
        node_deny_commands: options.node_deny_commands,
        session_retention_days: options.session_retention_days,
        max_ws_connections: options.max_ws_connections,
        max_ws_per_ip: options.max_ws_per_ip,
        max_json_depth: options.max_json_depth,
        ws_message_rate: options.ws_message_rate,
        ws_message_burst: options.ws_message_burst,
    })
}

pub async fn build_ws_config_from_files() -> Result<WsServerConfig, WsConfigError> {
    let cfg = config::load_config()?;
    build_ws_config_from_value(&cfg).await
}

/// Resolve gateway auth configuration from config objects, environment variables,
/// and stored credentials.
async fn resolve_gateway_auth_config(
    gateway: Option<&serde_json::Map<String, Value>>,
    _cfg: &Value,
) -> Result<auth::ResolvedGatewayAuth, WsConfigError> {
    let auth_obj = gateway
        .and_then(|g| g.get("auth"))
        .and_then(|v| v.as_object());
    let tailscale_obj = gateway
        .and_then(|g| g.get("tailscale"))
        .and_then(|v| v.as_object());

    let mode = auth_obj
        .and_then(|o| o.get("mode"))
        .and_then(|v| v.as_str())
        .unwrap_or_default();

    let token_cfg = auth_obj
        .and_then(|o| o.get("token"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let password_cfg = auth_obj
        .and_then(|o| o.get("password"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let allow_tailscale_cfg = auth_obj
        .and_then(|o| o.get("allowTailscale"))
        .and_then(|v| v.as_bool());

    let tailscale_mode = tailscale_obj
        .and_then(|o| o.get("mode"))
        .and_then(|v| v.as_str())
        .unwrap_or("off");

    let env_token = config::read_config_env("CARAPACE_GATEWAY_TOKEN");
    let env_password = config::read_config_env("CARAPACE_GATEWAY_PASSWORD");

    let state_dir = resolve_state_dir();
    let mut creds = credentials::read_gateway_auth(state_dir).await?;
    let token = env_token.or(token_cfg).or(std::mem::take(&mut creds.token));
    let password = env_password
        .or(password_cfg)
        .or(std::mem::take(&mut creds.password));

    let has_both_credentials = token.is_some() && password.is_some();
    let resolved_mode = match mode {
        "none" | "local" => auth::AuthMode::None,
        "password" => auth::AuthMode::Password,
        "token" => auth::AuthMode::Token,
        "" => {
            if has_both_credentials {
                warn!(
                    "gateway auth mode not set; both token and password configured, defaulting to password auth"
                );
            }
            if password.is_some() {
                auth::AuthMode::Password
            } else {
                auth::AuthMode::Token
            }
        }
        other => {
            return Err(WsConfigError::Config(
                config::ConfigError::ValidationError {
                    path: "gateway.auth.mode".to_string(),
                    message: format!(
                    "unknown gateway auth mode '{}'; expected one of: none, local, token, password",
                    other
                ),
                },
            ));
        }
    };

    let allow_tailscale = allow_tailscale_cfg.unwrap_or_else(|| {
        tailscale_mode == "serve" && !matches!(resolved_mode, auth::AuthMode::Password)
    });

    Ok(auth::ResolvedGatewayAuth {
        mode: resolved_mode,
        token,
        password,
        allow_tailscale,
    })
}

/// Parsed WS server options (non-auth fields).
struct WsServerOptions {
    trusted_proxies: Vec<String>,
    control_ui_allow_insecure_auth: bool,
    control_ui_disable_device_auth: bool,
    node_allow_commands: Vec<String>,
    node_deny_commands: Vec<String>,
    session_retention_days: Option<u32>,
    max_ws_connections: Option<usize>,
    max_ws_per_ip: Option<usize>,
    max_json_depth: Option<usize>,
    ws_message_rate: Option<f64>,
    ws_message_burst: Option<f64>,
}

/// Parse non-auth WS server options from the gateway config section.
fn parse_ws_server_options(
    gateway: Option<&serde_json::Map<String, Value>>,
    cfg: &Value,
) -> WsServerOptions {
    let control_ui_obj = gateway
        .and_then(|g| g.get("controlUi"))
        .and_then(|v| v.as_object());
    let nodes_obj = gateway
        .and_then(|g| g.get("nodes"))
        .and_then(|v| v.as_object());

    let trusted_proxies = gateway
        .and_then(|g| g.get("trustedProxies"))
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    let control_ui_allow_insecure_auth = control_ui_obj
        .and_then(|o| o.get("allowInsecureAuth"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let control_ui_disable_device_auth = control_ui_obj
        .and_then(|o| o.get("dangerouslyDisableDeviceAuth"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let node_allow_commands = nodes_obj
        .and_then(|o| o.get("allowCommands"))
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str())
                .map(|s| s.to_string())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let node_deny_commands = nodes_obj
        .and_then(|o| o.get("denyCommands"))
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str())
                .map(|s| s.to_string())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    let sessions_obj = cfg.get("sessions").and_then(|v| v.as_object());
    let session_retention_days = sessions_obj
        .and_then(|s| s.get("retention"))
        .and_then(|r| r.get("days"))
        .and_then(|v| v.as_u64())
        .map(|d| d as u32);

    let ws_obj = gateway
        .and_then(|g| g.get("ws"))
        .and_then(|v| v.as_object());
    let max_ws_connections = ws_obj
        .and_then(|w| w.get("maxConnections"))
        .and_then(|v| v.as_u64())
        .map(|v| v as usize);
    let max_ws_per_ip = ws_obj
        .and_then(|w| w.get("maxPerIp"))
        .and_then(|v| v.as_u64())
        .map(|v| v as usize);
    let max_json_depth = ws_obj
        .and_then(|w| w.get("maxJsonDepth"))
        .and_then(|v| v.as_u64())
        .map(|v| v as usize);

    let ws_message_rate = ws_obj
        .and_then(|w| w.get("messageRate"))
        .and_then(|v| v.as_f64());
    let ws_message_burst = ws_obj
        .and_then(|w| w.get("messageBurst"))
        .and_then(|v| v.as_f64());

    WsServerOptions {
        trusted_proxies,
        control_ui_allow_insecure_auth,
        control_ui_disable_device_auth,
        node_allow_commands,
        node_deny_commands,
        session_retention_days,
        max_ws_connections,
        max_ws_per_ip,
        max_json_depth,
        ws_message_rate,
        ws_message_burst,
    }
}

#[derive(Debug, Clone)]
struct NodeSession {
    node_id: String,
    conn_id: String,
    display_name: Option<String>,
    platform: Option<String>,
    version: Option<String>,
    device_family: Option<String>,
    model_identifier: Option<String>,
    remote_ip: Option<String>,
    caps: Vec<String>,
    commands: HashSet<String>,
    permissions: Option<HashMap<String, bool>>,
    path_env: Option<String>,
    connected_at_ms: u64,
}

#[derive(Debug)]
struct PendingInvoke {
    node_id: String,
    responder: oneshot::Sender<NodeInvokeResult>,
}

#[derive(Debug, Clone)]
struct NodeInvokeError {
    code: Option<String>,
    message: Option<String>,
}

#[derive(Debug, Clone)]
struct NodeInvokeResult {
    ok: bool,
    payload: Option<Value>,
    payload_json: Option<String>,
    error: Option<NodeInvokeError>,
}

#[derive(Debug, Default)]
struct NodeRegistry {
    nodes_by_id: HashMap<String, NodeSession>,
    nodes_by_conn: HashMap<String, String>,
    pending_invokes: HashMap<String, PendingInvoke>,
}

impl NodeRegistry {
    fn register(&mut self, session: NodeSession) {
        let conn_id = session.conn_id.clone();
        let node_id = session.node_id.clone();
        if let Some(existing) = self.nodes_by_conn.remove(&conn_id) {
            self.nodes_by_id.remove(&existing);
        }
        if let Some(existing_conn) = self.nodes_by_conn.iter().find_map(|(conn, id)| {
            if id == &node_id {
                Some(conn.clone())
            } else {
                None
            }
        }) {
            self.nodes_by_conn.remove(&existing_conn);
        }
        self.nodes_by_id.insert(node_id.clone(), session);
        self.nodes_by_conn.insert(conn_id, node_id);
    }

    fn unregister(&mut self, conn_id: &str) -> Option<String> {
        let node_id = self.nodes_by_conn.remove(conn_id)?;
        self.nodes_by_id.remove(&node_id);
        let pending: Vec<String> = self
            .pending_invokes
            .iter()
            .filter_map(|(invoke_id, pending)| {
                if pending.node_id == node_id {
                    Some(invoke_id.clone())
                } else {
                    None
                }
            })
            .collect();
        for invoke_id in pending {
            if let Some(pending) = self.pending_invokes.remove(&invoke_id) {
                let _ = pending.responder.send(NodeInvokeResult {
                    ok: false,
                    payload: None,
                    payload_json: None,
                    error: Some(NodeInvokeError {
                        code: Some("not_connected".to_string()),
                        message: Some("node disconnected".to_string()),
                    }),
                });
            }
        }
        Some(node_id)
    }

    fn get(&self, node_id: &str) -> Option<&NodeSession> {
        self.nodes_by_id.get(node_id)
    }

    fn list_connected(&self) -> Vec<NodeSession> {
        self.nodes_by_id.values().cloned().collect()
    }

    fn insert_pending_invoke(&mut self, invoke_id: String, pending: PendingInvoke) {
        self.pending_invokes.insert(invoke_id, pending);
    }

    fn remove_pending_invoke(&mut self, invoke_id: &str) -> Option<PendingInvoke> {
        self.pending_invokes.remove(invoke_id)
    }

    fn resolve_invoke(&mut self, invoke_id: &str, node_id: &str, result: NodeInvokeResult) -> bool {
        let Some(pending) = self.pending_invokes.get(invoke_id) else {
            return false;
        };
        if pending.node_id != node_id {
            return false;
        }
        let Some(pending) = self.pending_invokes.remove(invoke_id) else {
            return false;
        };
        let _ = pending.responder.send(result);
        true
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ConnectParams {
    min_protocol: u32,
    max_protocol: u32,
    client: ClientInfo,
    #[serde(default)]
    caps: Option<Vec<String>>,
    #[serde(default)]
    commands: Option<Vec<String>>,
    #[serde(default)]
    permissions: Option<HashMap<String, bool>>,
    #[serde(default)]
    path_env: Option<String>,
    #[serde(default)]
    role: Option<String>,
    #[serde(default)]
    scopes: Option<Vec<String>>,
    #[serde(default)]
    device: Option<DeviceIdentity>,
    #[serde(default)]
    auth: Option<AuthParams>,
    #[serde(default, rename = "locale")]
    _locale: Option<String>,
    #[serde(default, rename = "userAgent")]
    _user_agent: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct ClientInfo {
    id: String,
    version: String,
    platform: String,
    mode: String,
    #[serde(default)]
    display_name: Option<String>,
    #[serde(default)]
    device_family: Option<String>,
    #[serde(default)]
    model_identifier: Option<String>,
    #[serde(default)]
    instance_id: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct DeviceIdentity {
    id: String,
    public_key: String,
    signature: String,
    signed_at: i64,
    #[serde(default)]
    nonce: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct AuthParams {
    #[serde(default)]
    token: Option<String>,
    #[serde(default)]
    password: Option<String>,
}

#[derive(Debug, Serialize, Clone)]
struct ErrorShape {
    code: &'static str,
    message: String,
    retryable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    details: Option<Value>,
}

#[derive(Debug, Serialize)]
struct ResponseFrame<'a> {
    #[serde(rename = "type")]
    frame_type: &'a str,
    id: &'a str,
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    payload: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<ErrorShape>,
}

/// Server-to-client event frame.
///
/// `seq` is allocated before payload serialization and fan-out. Concurrent
/// producers can therefore be observed by a client in a different order than
/// allocation order; clients that need a total order must sort/reconcile by
/// `seq`, not by WebSocket receive order.
#[derive(Debug, Serialize)]
struct EventFrame<'a> {
    #[serde(rename = "type")]
    frame_type: &'a str,
    event: &'a str,
    payload: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    seq: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "stateVersion")]
    state_version: Option<StateVersion>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct StateVersion {
    presence: u64,
    health: u64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct HelloOkPayload {
    #[serde(rename = "type")]
    payload_type: &'static str,
    protocol: u32,
    server: ServerInfo,
    features: Features,
    snapshot: Snapshot,
    #[serde(skip_serializing_if = "Option::is_none")]
    canvas_host_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    auth: Option<DeviceTokenInfo>,
    policy: PolicyInfo,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ServerInfo {
    version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    commit: Option<String>,
    host: String,
    conn_id: String,
}

#[derive(Debug, Serialize)]
struct Features {
    methods: Vec<String>,
    events: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Snapshot {
    presence: Vec<Value>,
    health: Value,
    state_version: StateVersion,
    uptime_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    config_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    state_dir: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    session_defaults: Option<Value>,
}

#[derive(Debug, Serialize)]
struct PolicyInfo {
    #[serde(rename = "maxPayload")]
    max_payload: usize,
    #[serde(rename = "maxBufferedBytes")]
    max_buffered_bytes: usize,
    #[serde(rename = "tickIntervalMs")]
    tick_interval_ms: u64,
}

#[derive(Debug, Serialize)]
struct DeviceTokenInfo {
    #[serde(rename = "deviceToken")]
    device_token: String,
    role: String,
    scopes: Vec<String>,
    #[serde(rename = "issuedAtMs")]
    issued_at_ms: u64,
}

#[derive(Debug, Clone)]
struct ConnectionContext {
    conn_id: String,
    role: String,
    scopes: Vec<String>,
    client: ClientInfo,
    device_id: Option<String>,
}

#[derive(Debug)]
struct QueuedWsMessage {
    message: Message,
    bytes: usize,
}

#[derive(Debug, Clone)]
struct MeteredConnectionTx {
    tx: mpsc::Sender<QueuedWsMessage>,
    queued_bytes: Arc<AtomicUsize>,
    closed: Arc<AtomicBool>,
    close_tx: watch::Sender<bool>,
    max_buffered_bytes: usize,
}

#[derive(Debug, Clone)]
enum ConnectionTx {
    Metered(MeteredConnectionTx),
    Raw(mpsc::Sender<Message>),
}

impl From<MeteredConnectionTx> for ConnectionTx {
    fn from(tx: MeteredConnectionTx) -> Self {
        Self::Metered(tx)
    }
}

impl From<mpsc::Sender<Message>> for ConnectionTx {
    fn from(tx: mpsc::Sender<Message>) -> Self {
        Self::Raw(tx)
    }
}

impl ConnectionTx {
    fn try_send_text(&self, text: String) -> Result<(), ()> {
        let bytes = text.len();
        self.try_send_message(Message::Text(text.into()), bytes)
    }

    fn try_send_message(&self, message: Message, bytes: usize) -> Result<(), ()> {
        match self {
            Self::Raw(tx) => tx.try_send(message).map_err(|_| ()),
            Self::Metered(tx) => tx.try_send_message(message, bytes),
        }
    }

    fn close(&self) {
        if let Self::Metered(tx) = self {
            tx.close();
        }
    }
}

impl MeteredConnectionTx {
    fn try_send_message(&self, message: Message, bytes: usize) -> Result<(), ()> {
        if self.closed.load(Ordering::Acquire) {
            return Err(());
        }
        if !self.reserve_bytes(bytes) {
            self.close();
            return Err(());
        }
        match self.tx.try_send(QueuedWsMessage { message, bytes }) {
            Ok(()) => Ok(()),
            Err(_) => {
                self.release_bytes(bytes);
                self.close();
                Err(())
            }
        }
    }

    fn reserve_bytes(&self, bytes: usize) -> bool {
        if bytes > self.max_buffered_bytes {
            return false;
        }
        let mut current = self.queued_bytes.load(Ordering::Acquire);
        loop {
            let Some(next) = current.checked_add(bytes) else {
                return false;
            };
            if next > self.max_buffered_bytes {
                return false;
            }
            match self.queued_bytes.compare_exchange_weak(
                current,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return true,
                Err(actual) => current = actual,
            }
        }
    }

    fn release_bytes(&self, bytes: usize) {
        self.queued_bytes.fetch_sub(bytes, Ordering::AcqRel);
    }

    fn close(&self) {
        if !self.closed.swap(true, Ordering::AcqRel) {
            let _ = self.close_tx.send(true);
        }
    }
}

#[derive(Clone, Debug)]
struct ConnectionHandle {
    role: String,
    scopes: Vec<String>,
    tx: ConnectionTx,
}

fn connection_has_admin_presence_visibility(conn: &ConnectionHandle) -> bool {
    conn.role == "admin" || scope_satisfies(&conn.scopes, "operator.admin")
}

#[derive(Clone, Debug, Default)]
struct SessionDefaults {
    default_agent_id: Option<String>,
    main_key: Option<String>,
    main_session_key: Option<String>,
    scope: Option<String>,
}

impl SessionDefaults {
    fn to_value(&self) -> Value {
        json!({
            "defaultAgentId": self.default_agent_id,
            "mainKey": self.main_key,
            "mainSessionKey": self.main_session_key,
            "scope": self.scope,
        })
    }
}

pub async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<WsServerState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    let ip = addr.ip();
    let guard = match state.connection_tracker.try_acquire(ip) {
        Ok(guard) => guard,
        Err(_) => {
            return Response::builder()
                .status(StatusCode::SERVICE_UNAVAILABLE)
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    r#"{"error":"connection limit reached"}"#,
                ))
                .unwrap()
                .into_response();
        }
    };
    ws.on_upgrade(move |socket| handle_socket_with_guard(socket, state, addr, headers, guard))
        .into_response()
}

async fn handle_socket_with_guard(
    socket: WebSocket,
    state: Arc<WsServerState>,
    remote_addr: SocketAddr,
    headers: HeaderMap,
    _guard: limits::ConnectionGuard,
) {
    handle_socket(socket, state, remote_addr, headers).await;
    // _guard is dropped here, decrementing the connection count
}

async fn handle_socket(
    socket: WebSocket,
    state: Arc<WsServerState>,
    remote_addr: SocketAddr,
    headers: HeaderMap,
) {
    let (mut sender, mut receiver) = socket.split();
    // SECURITY: bounded channel with backpressure. The previous
    // `mpsc::unbounded_channel` left every connection's outbound
    // queue uncapped — a slow WS client (mobile on bad link, hung
    // browser tab) accumulated frames in memory until the
    // connection eventually disconnected, with no upper bound on
    // memory use per-laggy-client. With a bounded channel, every
    // send-site uses `try_send` and treats `Full` as "client is too
    // slow — drop them" (same as `Closed`). 256 frames is well
    // above any sane burst from event broadcasts; legitimate
    // clients clear their queue between sync ticks. A truly
    // backpressured client gets disconnected and reconnects fresh.
    let (raw_tx, mut rx) = mpsc::channel::<QueuedWsMessage>(WS_CONNECTION_CHANNEL_CAPACITY);
    let queued_bytes = Arc::new(AtomicUsize::new(0));
    let (close_tx, close_rx) = watch::channel(false);
    let tx = ConnectionTx::Metered(MeteredConnectionTx {
        tx: raw_tx,
        queued_bytes: queued_bytes.clone(),
        closed: Arc::new(AtomicBool::new(false)),
        close_tx,
        max_buffered_bytes: state.config.policy.max_buffered_bytes,
    });

    let send_task = tokio::spawn(async move {
        while let Some(queued) = rx.recv().await {
            let bytes = queued.bytes;
            let result = sender.send(queued.message).await;
            queued_bytes.fetch_sub(bytes, Ordering::AcqRel);
            if result.is_err() {
                break;
            }
        }
    });

    let handshake =
        match perform_socket_handshake(&mut receiver, &tx, &state, remote_addr, &headers).await {
            Ok(handshake) => handshake,
            Err(()) => {
                drop(tx);
                let _ = send_task.await;
                return;
            }
        };
    let HandshakeContext {
        conn_id,
        role,
        scopes,
        connect_params,
        device_id,
        remote_ip_for_presence,
        json_depth_limit,
    } = handshake;
    let conn = ConnectionContext {
        conn_id,
        role,
        scopes,
        client: connect_params.client,
        device_id,
    };
    run_connection_lifecycle(
        &mut receiver,
        &tx,
        &state,
        conn,
        remote_ip_for_presence,
        json_depth_limit,
        close_rx,
    )
    .await;

    drop(tx);
    let _ = send_task.await;
}

struct HandshakeContext {
    conn_id: String,
    role: String,
    scopes: Vec<String>,
    connect_params: ConnectParams,
    device_id: Option<String>,
    remote_ip_for_presence: Option<String>,
    json_depth_limit: usize,
}

async fn perform_socket_handshake(
    receiver: &mut futures_util::stream::SplitStream<WebSocket>,
    tx: &ConnectionTx,
    state: &Arc<WsServerState>,
    remote_addr: SocketAddr,
    headers: &HeaderMap,
) -> Result<HandshakeContext, ()> {
    let nonce = Uuid::new_v4().to_string();
    send_challenge(tx, &nonce);

    let json_depth_limit = state.config.max_json_depth.unwrap_or(MAX_JSON_DEPTH);
    let (req_id, mut connect_params) =
        receive_initial_handshake(receiver, tx, json_depth_limit).await?;

    let is_local =
        auth::is_local_direct_request(remote_addr, headers, &state.config.trusted_proxies);
    let (role, scopes) = validate_connect_params(tx, &req_id, &mut connect_params, is_local)?;
    let device_id = authenticate_connection(
        state,
        tx,
        &req_id,
        &connect_params,
        headers,
        remote_addr,
        &nonce,
        is_local,
        &role,
        &scopes,
    )?;

    let conn_id = Uuid::new_v4().to_string();
    let issued_token = issue_device_token_for_connection(
        state,
        tx,
        &req_id,
        device_id.as_deref(),
        &role,
        &scopes,
    )?;

    if role == "node" {
        finalize_node_commands(state, &mut connect_params);
        register_node_session(
            state,
            &connect_params,
            &conn_id,
            device_id.clone(),
            is_local,
            remote_addr,
        );
    }

    let remote_ip_for_presence = if is_local {
        None
    } else {
        Some(remote_addr.ip().to_string())
    };
    let hello = build_hello_response(state, &conn_id, issued_token);
    let _ = send_response(tx, &req_id, true, Some(json!(hello)), None);

    Ok(HandshakeContext {
        conn_id,
        role,
        scopes,
        connect_params,
        device_id,
        remote_ip_for_presence,
        json_depth_limit,
    })
}

fn issue_device_token_for_connection(
    state: &Arc<WsServerState>,
    tx: &ConnectionTx,
    req_id: &str,
    device_id: Option<&str>,
    role: &str,
    scopes: &[String],
) -> Result<Option<devices::IssuedDeviceToken>, ()> {
    match device_id {
        Some(id) => match ensure_device_token(state, id, role, scopes) {
            Ok(token) => Ok(Some(token)),
            Err(err) => {
                warn!("failed to issue device token for {}: {}", id, err);
                let err_resp = error_shape(
                    ERROR_INVALID_REQUEST,
                    &format!("device token issuance failed: {}", err),
                    None,
                );
                let _ = send_response(tx, req_id, false, None, Some(err_resp));
                let _ = send_close(tx, 1008, "device token issuance failed");
                Err(())
            }
        },
        None => Ok(None),
    }
}

async fn run_connection_lifecycle(
    receiver: &mut futures_util::stream::SplitStream<WebSocket>,
    tx: &ConnectionTx,
    state: &Arc<WsServerState>,
    conn: ConnectionContext,
    remote_ip_for_presence: Option<String>,
    json_depth_limit: usize,
    close_rx: watch::Receiver<bool>,
) {
    state.register_connection(&conn, tx.clone(), remote_ip_for_presence);

    let tick_task = spawn_tick_task(tx.clone(), state.clone());
    let mut ws_rate_limiter = create_ws_rate_limiter(state);
    let mut ws_rate_warn_count: u32 = 0;
    run_message_loop(
        receiver,
        tx,
        state,
        &conn,
        json_depth_limit,
        MessageLoopControls {
            ws_rate_limiter: &mut ws_rate_limiter,
            ws_rate_warn_count: &mut ws_rate_warn_count,
            close_rx,
        },
    )
    .await;

    tick_task.abort();
    state.unregister_connection(&conn.conn_id);
    state.node_registry.lock().unregister(&conn.conn_id);
}

/// Send the connect challenge event containing a nonce.
fn send_challenge(tx: &ConnectionTx, nonce: &str) {
    let challenge = EventFrame {
        frame_type: "event",
        event: "connect.challenge",
        payload: json!({ "nonce": nonce, "ts": now_ms() }),
        seq: None,
        state_version: None,
    };
    let _ = send_json(tx, &challenge);
}

/// Filter declared node commands through the configured allowlist.
fn finalize_node_commands(state: &WsServerState, connect_params: &mut ConnectParams) {
    let allowlist = resolve_node_command_allowlist(
        &state.config.node_allow_commands,
        &state.config.node_deny_commands,
        Some(connect_params.client.platform.as_str()),
        connect_params.client.device_family.as_deref(),
    );
    let declared = connect_params.commands.clone().unwrap_or_default();
    let filtered = declared
        .into_iter()
        .map(|cmd| cmd.trim().to_string())
        .filter(|cmd| !cmd.is_empty() && allowlist.contains(cmd))
        .collect::<Vec<_>>();
    connect_params.commands = Some(filtered);
}

/// Spawn the periodic tick event task. Returns the join handle for cleanup.
fn spawn_tick_task(
    tick_tx: ConnectionTx,
    tick_state: Arc<WsServerState>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_millis(TICK_INTERVAL_MS));
        loop {
            ticker.tick().await;
            let event = EventFrame {
                frame_type: "event",
                event: "tick",
                payload: json!({ "ts": now_ms() }),
                seq: Some(tick_state.next_event_seq()),
                state_version: None,
            };
            if send_json(&tick_tx, &event).is_err() {
                break;
            }
        }
    })
}

pub fn spawn_heartbeat_task(state: Arc<WsServerState>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let snapshot = state.heartbeat_snapshot();
            if !snapshot.enabled {
                tokio::time::sleep(Duration::from_secs(1)).await;
                continue;
            }
            let interval_ms = snapshot.interval_ms.max(MIN_HEARTBEAT_INTERVAL_MS);
            tokio::time::sleep(Duration::from_millis(interval_ms)).await;
            if state.heartbeat_snapshot().enabled {
                broadcast_heartbeat(&state);
            }
        }
    })
}

/// Create a per-connection WebSocket rate limiter from server config.
fn create_ws_rate_limiter(state: &WsServerState) -> crate::server::ratelimit::WsRateLimiter {
    let rate = state
        .config
        .ws_message_rate
        .unwrap_or(crate::server::ratelimit::DEFAULT_WS_MESSAGE_RATE);
    let burst = state
        .config
        .ws_message_burst
        .unwrap_or(crate::server::ratelimit::DEFAULT_WS_MESSAGE_BURST);
    crate::server::ratelimit::WsRateLimiter::new(rate, burst)
}

/// Decode a raw WebSocket message into a parsed request frame.
/// Returns `Ok(request)` on success, `Err(LoopSignal::Continue)` to skip this
/// message, or `Err(LoopSignal::Break)` to close the connection.
fn decode_inbound_message(
    msg: Message,
    tx: &ConnectionTx,
    json_depth_limit: usize,
) -> Result<ParsedRequest, LoopSignal> {
    let text = match message_to_text(msg) {
        Ok(InboundText::Text(text)) => text,
        Ok(InboundText::Control) => return Err(LoopSignal::Continue),
        Ok(InboundText::Close) => return Err(LoopSignal::Break),
        Err(reason) => {
            let _ = send_close(tx, 1008, reason);
            return Err(LoopSignal::Break);
        }
    };
    if text.len() > MAX_PAYLOAD_BYTES {
        let _ = send_close(tx, 1008, "payload too large");
        return Err(LoopSignal::Break);
    }
    let parsed = match serde_json::from_str::<Value>(&text) {
        Ok(val) => val,
        Err(_) => {
            let _ = send_close(tx, 1008, "invalid request frame");
            return Err(LoopSignal::Break);
        }
    };
    if let Err(depth_err) = validate_json_depth(&parsed, json_depth_limit) {
        let _ = send_close(tx, 1008, &depth_err);
        return Err(LoopSignal::Break);
    }
    match parse_request_frame(&parsed) {
        Ok(req) => Ok(req),
        Err(err) => {
            if let Some(id) = err.id {
                let _ = send_response(tx, &id, false, None, Some(err.error));
            } else {
                let _ = send_close(tx, 1008, "invalid request frame");
            }
            Err(LoopSignal::Continue)
        }
    }
}

/// Check the per-connection rate limiter before parsing the JSON body.
/// Returns `Ok(())` if the request should proceed,
/// `Err(LoopSignal::Continue)` if rate-limited, or `Err(LoopSignal::Break)`
/// if the warning threshold was exceeded.
fn check_pre_decode_rate_limit(
    tx: &ConnectionTx,
    rate_limiter: &mut crate::server::ratelimit::WsRateLimiter,
    warn_count: &mut u32,
) -> Result<(), LoopSignal> {
    if !rate_limiter.try_consume() {
        *warn_count += 1;
        if *warn_count >= 3 {
            let _ = send_close(tx, 1008, "rate limit exceeded");
            return Err(LoopSignal::Break);
        }
        return Err(LoopSignal::Continue);
    }
    *warn_count = 0;
    Ok(())
}

/// Validate request params depth and reject duplicate connect calls.
/// Returns `Ok(())` if the request should proceed, `Err(LoopSignal::Continue)`
/// to skip this message.
fn validate_request_params(
    tx: &ConnectionTx,
    req_id: &str,
    method: &str,
    params: &Option<Value>,
    json_depth_limit: usize,
) -> Result<(), LoopSignal> {
    if let Some(ref p) = *params {
        if let Err(depth_err) = validate_json_depth(p, json_depth_limit) {
            let err = error_shape(ERROR_INVALID_REQUEST, &depth_err, None);
            let _ = send_response(tx, req_id, false, None, Some(err));
            return Err(LoopSignal::Continue);
        }
    }
    if method == "connect" {
        let err = error_shape(ERROR_INVALID_REQUEST, "connect already completed", None);
        let _ = send_response(tx, req_id, false, None, Some(err));
        return Err(LoopSignal::Continue);
    }
    Ok(())
}

/// Send the result of method dispatch back to the client.
fn send_dispatch_result(
    tx: &ConnectionTx,
    req_id: &str,
    method: &str,
    method_known: bool,
    result: Result<Value, ErrorShape>,
) {
    match result {
        Ok(payload) => {
            let _ = send_response(tx, req_id, true, Some(payload), None);
        }
        Err(err) => {
            if method_known {
                let _ = send_response(tx, req_id, false, None, Some(err));
            } else {
                let _ = send_response(
                    tx,
                    req_id,
                    false,
                    None,
                    Some(error_shape(
                        ERROR_INVALID_REQUEST,
                        "unknown method",
                        Some(json!({ "method": method })),
                    )),
                );
            }
        }
    }
}

/// Signal used to communicate loop control flow from helper functions.
enum LoopSignal {
    Continue,
    Break,
}

struct MessageLoopControls<'a> {
    ws_rate_limiter: &'a mut crate::server::ratelimit::WsRateLimiter,
    ws_rate_warn_count: &'a mut u32,
    close_rx: watch::Receiver<bool>,
}

/// Main message receive loop. Processes inbound WebSocket frames until the
/// connection is closed or an unrecoverable error occurs.
async fn run_message_loop(
    receiver: &mut futures_util::stream::SplitStream<WebSocket>,
    tx: &ConnectionTx,
    state: &Arc<WsServerState>,
    conn: &ConnectionContext,
    json_depth_limit: usize,
    controls: MessageLoopControls<'_>,
) {
    let MessageLoopControls {
        ws_rate_limiter,
        ws_rate_warn_count,
        mut close_rx,
    } = controls;
    loop {
        let next = tokio::select! {
            _ = close_rx.changed() => break,
            next = receiver.next() => next,
        };
        let Some(next) = next else {
            break;
        };
        let msg = match next {
            Ok(msg) => msg,
            Err(_) => break,
        };
        match check_pre_decode_rate_limit(tx, ws_rate_limiter, ws_rate_warn_count) {
            Ok(()) => {}
            Err(LoopSignal::Continue) => continue,
            Err(LoopSignal::Break) => break,
        }
        let request = match decode_inbound_message(msg, tx, json_depth_limit) {
            Ok(req) => req,
            Err(LoopSignal::Continue) => continue,
            Err(LoopSignal::Break) => break,
        };
        let ParsedRequest {
            id: req_id,
            method,
            params,
        } = request;

        if validate_request_params(tx, &req_id, &method, &params, json_depth_limit).is_err() {
            continue;
        }
        let method_known = GATEWAY_METHODS.contains(&method.as_str());
        let result = dispatch_method(&method, params.as_ref(), state, conn).await;
        send_dispatch_result(tx, &req_id, &method, method_known, result);
    }
}

/// Receive the initial handshake message: timeout-bounded first message receive,
/// payload parsing, and connect method validation.
/// Returns (request_id, ConnectParams) on success, Err(()) if the connection should close.
async fn receive_initial_handshake(
    receiver: &mut futures_util::stream::SplitStream<WebSocket>,
    tx: &ConnectionTx,
    json_depth_limit: usize,
) -> Result<(String, ConnectParams), ()> {
    let text = match recv_text_with_timeout(receiver, HANDSHAKE_TIMEOUT_MS).await {
        Ok(Some(text)) => text,
        Ok(None) => return Err(()),
        Err(reason) => {
            if reason == "handshake timeout" {
                let _ = send_close(tx, 1000, "");
            } else {
                let _ = send_close(tx, 1008, reason);
            }
            return Err(());
        }
    };

    if text.len() > MAX_PAYLOAD_BYTES {
        let _ = send_close(tx, 1008, "payload too large");
        return Err(());
    }

    let parsed = match serde_json::from_str::<Value>(&text) {
        Ok(val) => val,
        Err(_) => {
            let _ = send_close(tx, 1008, "invalid request frame");
            return Err(());
        }
    };

    if let Err(depth_err) = validate_json_depth(&parsed, json_depth_limit) {
        let _ = send_close(tx, 1008, &depth_err);
        return Err(());
    }

    let ParsedRequest {
        id: req_id,
        method,
        params,
    } = match parse_request_frame(&parsed) {
        Ok(req) => req,
        Err(err) => {
            let close_reason = err.error.message.clone();
            if let Some(id) = err.id {
                let _ = send_response(tx, &id, false, None, Some(err.error));
            }
            let _ = send_close(tx, 1008, &close_reason);
            return Err(());
        }
    };

    if method != "connect" {
        let err = error_shape(
            ERROR_INVALID_REQUEST,
            "invalid handshake: first request must be connect",
            None,
        );
        let _ = send_response(tx, &req_id, false, None, Some(err));
        let _ = send_close(tx, 1008, "invalid handshake: first request must be connect");
        return Err(());
    }

    let connect_params = match params {
        Some(value) => match serde_json::from_value::<ConnectParams>(value) {
            Ok(val) => val,
            Err(_) => {
                let err = error_shape(ERROR_INVALID_REQUEST, "invalid connect params", None);
                let _ = send_response(tx, &req_id, false, None, Some(err));
                let _ = send_close(tx, 1008, "invalid connect params");
                return Err(());
            }
        },
        None => {
            let err = error_shape(ERROR_INVALID_REQUEST, "invalid connect params", None);
            let _ = send_response(tx, &req_id, false, None, Some(err));
            let _ = send_close(tx, 1008, "invalid connect params");
            return Err(());
        }
    };

    Ok((req_id, connect_params))
}

/// Validate connect parameters: protocol version, client fields, role, and scopes.
/// Updates connect_params.role and connect_params.scopes in place.
/// Returns (role, scopes) on success, Err(()) if the connection should close.
fn validate_connect_params(
    tx: &ConnectionTx,
    req_id: &str,
    connect_params: &mut ConnectParams,
    _is_local: bool,
) -> Result<(String, Vec<String>), ()> {
    if connect_params.min_protocol == 0 || connect_params.max_protocol == 0 {
        let err = error_shape(ERROR_INVALID_REQUEST, "invalid connect params", None);
        let _ = send_response(tx, req_id, false, None, Some(err));
        let _ = send_close(tx, 1008, "invalid connect params");
        return Err(());
    }

    if !ALLOWED_CLIENT_IDS.contains(&connect_params.client.id.as_str())
        || !ALLOWED_CLIENT_MODES.contains(&connect_params.client.mode.as_str())
        || connect_params.client.version.trim().is_empty()
        || connect_params.client.platform.trim().is_empty()
    {
        let err = error_shape(ERROR_INVALID_REQUEST, "invalid connect params", None);
        let _ = send_response(tx, req_id, false, None, Some(err));
        let _ = send_close(tx, 1008, "invalid connect params");
        return Err(());
    }

    if connect_params.max_protocol < PROTOCOL_VERSION
        || connect_params.min_protocol > PROTOCOL_VERSION
    {
        let err = error_shape(
            ERROR_INVALID_REQUEST,
            "protocol mismatch",
            Some(json!({ "expectedProtocol": PROTOCOL_VERSION })),
        );
        let _ = send_response(tx, req_id, false, None, Some(err));
        let _ = send_close(tx, 1002, "protocol mismatch");
        return Err(());
    }

    let role = connect_params
        .role
        .clone()
        .unwrap_or_else(|| "operator".to_string());
    if role != "operator" && role != "node" {
        let err = error_shape(ERROR_INVALID_REQUEST, "invalid role", None);
        let _ = send_response(tx, req_id, false, None, Some(err));
        let _ = send_close(tx, 1008, "invalid role");
        return Err(());
    }
    let requested_scopes = connect_params.scopes.clone().unwrap_or_default();
    let scopes = if requested_scopes.is_empty() && role == "operator" {
        vec!["operator.admin".to_string()]
    } else {
        requested_scopes
    };
    connect_params.role = Some(role.clone());
    connect_params.scopes = Some(scopes.clone());

    Ok((role, scopes))
}

/// Authenticate the connection: token/password auth, local auth, control UI bypass,
/// device identity validation, and device pairing.
/// Returns the device_id (if any) on success, Err(()) if the connection should close.
#[allow(clippy::too_many_arguments)]
fn authenticate_connection(
    state: &WsServerState,
    tx: &ConnectionTx,
    req_id: &str,
    connect_params: &ConnectParams,
    headers: &HeaderMap,
    remote_addr: SocketAddr,
    nonce: &str,
    is_local: bool,
    role: &str,
    scopes: &[String],
) -> Result<Option<String>, ()> {
    let has_token_auth = connect_params
        .auth
        .as_ref()
        .and_then(|a| a.token.as_ref())
        .is_some();
    let has_password_auth = connect_params
        .auth
        .as_ref()
        .and_then(|a| a.password.as_ref())
        .is_some();
    let is_control_ui = connect_params.client.id == "carapace-control-ui";
    let allow_control_ui_bypass = is_control_ui
        && (state.config.control_ui_allow_insecure_auth
            || state.config.control_ui_disable_device_auth);
    let device_required = !(is_control_ui && state.config.control_ui_disable_device_auth);
    if connect_params.device.is_none() && device_required {
        let can_skip_device = if allow_control_ui_bypass {
            has_token_auth || has_password_auth
        } else {
            is_local && has_token_auth
        };
        if !can_skip_device {
            let err = error_shape(ERROR_NOT_PAIRED, "device identity required", None);
            let _ = send_response(tx, req_id, false, None, Some(err));
            let _ = send_close(tx, 1008, "device identity required");
            return Err(());
        }
    }

    let device_opt = if is_control_ui && state.config.control_ui_disable_device_auth {
        None
    } else {
        connect_params.device.as_ref()
    };

    let device_id = match validate_and_pair_device(
        state,
        tx,
        req_id,
        connect_params,
        headers,
        remote_addr,
        nonce,
        is_local,
        role,
        scopes,
        device_opt,
    ) {
        Ok(id) => id,
        Err(()) => return Err(()),
    };

    Ok(device_id)
}

/// Validate device identity and ensure pairing.
/// Returns the device_id (if any) on success, Err(()) if the connection should close.
#[allow(clippy::too_many_arguments)]
fn validate_and_pair_device(
    state: &WsServerState,
    tx: &ConnectionTx,
    req_id: &str,
    connect_params: &ConnectParams,
    headers: &HeaderMap,
    remote_addr: SocketAddr,
    nonce: &str,
    is_local: bool,
    role: &str,
    scopes: &[String],
    device_opt: Option<&DeviceIdentity>,
) -> Result<Option<String>, ()> {
    let device_id = match device_opt {
        Some(device) => {
            if let Err(err) = validate_device_identity(device, connect_params, nonce, is_local) {
                let err_clone = err.clone();
                let _ = send_response(tx, req_id, false, None, Some(err));
                let _ = send_close(tx, 1008, err_clone.message.as_str());
                return Err(());
            }
            Some(device.id.clone())
        }
        None => None,
    };

    if let Err(err) = authorize_connection(
        state,
        connect_params,
        headers,
        remote_addr,
        device_id.as_deref(),
        role,
        scopes,
    ) {
        let _ = send_response(tx, req_id, false, None, Some(err.clone()));
        let _ = send_close(tx, 1008, err.message.as_str());
        return Err(());
    }

    if let Some(device) = device_opt {
        if let Err(err) = ensure_paired(
            state,
            device,
            connect_params,
            role,
            scopes,
            is_local,
            remote_addr,
        ) {
            let _ = send_response(tx, req_id, false, None, Some(err.clone()));
            let _ = send_close(tx, 1008, err.message.as_str());
            return Err(());
        }
    }

    Ok(device_id)
}

/// Register a node session in the node registry.
fn register_node_session(
    state: &WsServerState,
    connect_params: &ConnectParams,
    conn_id: &str,
    device_id: Option<String>,
    is_local: bool,
    remote_addr: SocketAddr,
) {
    let node_id = device_id.unwrap_or_else(|| connect_params.client.id.clone());
    let commands = connect_params
        .commands
        .clone()
        .unwrap_or_default()
        .into_iter()
        .collect::<HashSet<String>>();
    let remote_ip = if is_local {
        None
    } else {
        Some(remote_addr.ip().to_string())
    };
    state.node_registry.lock().register(NodeSession {
        node_id,
        conn_id: conn_id.to_string(),
        display_name: connect_params.client.display_name.clone(),
        platform: Some(connect_params.client.platform.clone()),
        version: Some(connect_params.client.version.clone()),
        device_family: connect_params.client.device_family.clone(),
        model_identifier: connect_params.client.model_identifier.clone(),
        remote_ip,
        caps: connect_params.caps.clone().unwrap_or_default(),
        commands,
        permissions: connect_params.permissions.clone(),
        path_env: connect_params.path_env.clone(),
        connected_at_ms: now_ms(),
    });
}

/// Build the hello-ok response payload.
fn build_hello_response(
    state: &WsServerState,
    conn_id: &str,
    issued_token: Option<devices::IssuedDeviceToken>,
) -> HelloOkPayload {
    let current_state_version = state.current_state_version();
    let presence_list = state.get_presence_list_for_conn(conn_id);
    let health_snapshot = state.get_health_snapshot();

    HelloOkPayload {
        payload_type: "hello-ok",
        protocol: PROTOCOL_VERSION,
        server: ServerInfo {
            version: server_version(),
            commit: server_commit(),
            host: server_hostname(),
            conn_id: conn_id.to_string(),
        },
        features: Features {
            methods: GATEWAY_METHODS.iter().map(|s| s.to_string()).collect(),
            events: GATEWAY_EVENTS.iter().map(|s| s.to_string()).collect(),
        },
        snapshot: Snapshot {
            presence: presence_list,
            health: serde_json::to_value(&health_snapshot).unwrap_or(json!({})),
            state_version: current_state_version,
            uptime_ms: state.start_time.elapsed().as_millis() as u64,
            config_path: None,
            state_dir: None,
            session_defaults: None,
        },
        canvas_host_url: None,
        auth: issued_token.map(|token| DeviceTokenInfo {
            device_token: token.token,
            role: token.role,
            scopes: token.scopes,
            issued_at_ms: token.issued_at_ms,
        }),
        policy: PolicyInfo {
            max_payload: state.config.policy.max_payload,
            max_buffered_bytes: state.config.policy.max_buffered_bytes,
            tick_interval_ms: state.config.policy.tick_interval_ms,
        },
    }
}

struct ParsedRequest {
    id: String,
    method: String,
    params: Option<Value>,
}

struct FrameError {
    id: Option<String>,
    error: ErrorShape,
}

fn parse_request_frame(value: &Value) -> Result<ParsedRequest, FrameError> {
    let obj = value.as_object().ok_or_else(|| FrameError {
        id: None,
        error: error_shape(ERROR_INVALID_REQUEST, "invalid request frame", None),
    })?;
    let frame_type = obj
        .get("type")
        .and_then(|v| v.as_str())
        .ok_or_else(|| FrameError {
            id: None,
            error: error_shape(ERROR_INVALID_REQUEST, "invalid request frame", None),
        })?;
    if frame_type != "req" {
        return Err(FrameError {
            id: None,
            error: error_shape(ERROR_INVALID_REQUEST, "invalid request frame", None),
        });
    }
    let id = obj
        .get("id")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let method = obj
        .get("method")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let Some(id) = id else {
        return Err(FrameError {
            id: None,
            error: error_shape(ERROR_INVALID_REQUEST, "invalid request frame", None),
        });
    };
    if id.trim().is_empty() {
        return Err(FrameError {
            id: None,
            error: error_shape(ERROR_INVALID_REQUEST, "invalid request frame", None),
        });
    }
    let Some(method) = method else {
        return Err(FrameError {
            id: Some(id),
            error: error_shape(ERROR_INVALID_REQUEST, "invalid request frame", None),
        });
    };
    if method.trim().is_empty() {
        return Err(FrameError {
            id: Some(id),
            error: error_shape(ERROR_INVALID_REQUEST, "invalid request frame", None),
        });
    }
    let params = obj.get("params").cloned();
    Ok(ParsedRequest { id, method, params })
}

/// Validates that a JSON value doesn't exceed the maximum nesting depth.
/// Returns Err with a message if the depth limit is exceeded.
fn validate_json_depth(value: &Value, max_depth: usize) -> Result<(), String> {
    check_json_depth(value, 1, max_depth)
}

fn check_json_depth(value: &Value, current_depth: usize, max_depth: usize) -> Result<(), String> {
    if current_depth > max_depth {
        return Err(format!(
            "JSON nesting depth exceeds maximum allowed depth of {max_depth}"
        ));
    }
    match value {
        Value::Array(arr) => {
            for item in arr {
                check_json_depth(item, current_depth + 1, max_depth)?;
            }
        }
        Value::Object(map) => {
            for val in map.values() {
                check_json_depth(val, current_depth + 1, max_depth)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn get_value_at_path(root: &Value, path: &str) -> Option<Value> {
    let mut current = root;
    for part in path.split('.') {
        let obj = current.as_object()?;
        current = obj.get(part)?;
    }
    Some(current.clone())
}

fn validate_device_identity(
    device: &DeviceIdentity,
    connect: &ConnectParams,
    nonce: &str,
    is_local: bool,
) -> Result<(), ErrorShape> {
    let derived_id = derive_device_id_from_public_key(&device.public_key)
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "device public key invalid", None))?;
    if derived_id != device.id {
        return Err(error_shape(
            ERROR_INVALID_REQUEST,
            "device identity mismatch",
            None,
        ));
    }
    let signed_at = device.signed_at;
    let now = now_ms() as i64;
    if (now - signed_at).abs() > SIGNATURE_SKEW_MS {
        return Err(error_shape(
            ERROR_INVALID_REQUEST,
            "device signature expired",
            None,
        ));
    }
    let nonce_required = !is_local;
    let provided_nonce = device.nonce.clone().unwrap_or_default();
    if nonce_required && provided_nonce.is_empty() {
        return Err(error_shape(
            ERROR_INVALID_REQUEST,
            "device nonce required",
            None,
        ));
    }
    if !provided_nonce.is_empty() && provided_nonce != nonce {
        return Err(error_shape(
            ERROR_INVALID_REQUEST,
            "device nonce mismatch",
            None,
        ));
    }
    let payload = build_device_auth_payload(DeviceAuthPayload {
        device_id: device.id.clone(),
        client_id: connect.client.id.clone(),
        client_mode: connect.client.mode.clone(),
        role: connect
            .role
            .clone()
            .unwrap_or_else(|| "operator".to_string()),
        scopes: connect.scopes.clone().unwrap_or_default(),
        signed_at_ms: signed_at,
        token: connect.auth.as_ref().and_then(|a| a.token.clone()),
        nonce: if provided_nonce.is_empty() {
            None
        } else {
            Some(provided_nonce.clone())
        },
    });
    if !verify_device_signature(&device.public_key, &payload, &device.signature) {
        return Err(error_shape(
            ERROR_INVALID_REQUEST,
            "device signature invalid",
            None,
        ));
    }
    Ok(())
}

fn authorize_connection(
    state: &WsServerState,
    connect: &ConnectParams,
    headers: &HeaderMap,
    remote_addr: SocketAddr,
    device_id: Option<&str>,
    role: &str,
    scopes: &[String],
) -> Result<(), ErrorShape> {
    let auth = &state.config.auth.resolved;
    let connect_auth = connect.auth.as_ref();

    let auth_result = auth::authorize_gateway_connect(
        auth,
        connect_auth.and_then(|a| a.token.as_deref()),
        connect_auth.and_then(|a| a.password.as_deref()),
        headers,
        remote_addr,
        &state.config.trusted_proxies,
    );

    if auth_result.ok {
        if matches!(auth_result.method, Some(auth::GatewayAuthMethod::Tailscale)) {
            tracing::debug!(
                user = %auth_result.user.as_deref().unwrap_or("unknown"),
                ip = %remote_addr.ip(),
                "tailscale auth accepted"
            );
        }
        return Ok(());
    }

    if let Some(device_id) = device_id {
        if let Some(token) = connect_auth.and_then(|a| a.token.clone()) {
            if verify_device_token(state, device_id, &token, role, scopes) {
                return Ok(());
            }
        }
    }

    let reason = auth_result
        .reason
        .unwrap_or(auth::GatewayAuthFailure::Unauthorized)
        .message();

    Err(error_shape(ERROR_INVALID_REQUEST, reason, None))
}

fn ensure_paired(
    state: &WsServerState,
    device: &DeviceIdentity,
    connect: &ConnectParams,
    role: &str,
    scopes: &[String],
    is_local: bool,
    remote_addr: SocketAddr,
) -> Result<(), ErrorShape> {
    if let Some(paired) = state.device_registry.get_paired_device(&device.id) {
        if paired.public_key != device.public_key {
            return Err(error_shape(
                ERROR_INVALID_REQUEST,
                "device identity mismatch",
                None,
            ));
        }

        let role_allowed = if paired.roles.is_empty() {
            false
        } else {
            paired.roles.iter().any(|r| r == role)
        };
        if !role_allowed {
            return require_pairing(state, device, connect, role, scopes, is_local, remote_addr);
        }

        if !scopes.is_empty()
            && (paired.scopes.is_empty()
                || !scopes.iter().all(|scope| paired.scopes.contains(scope)))
        {
            return require_pairing(state, device, connect, role, scopes, is_local, remote_addr);
        }

        let remote_ip = if is_local {
            None
        } else {
            Some(remote_addr.ip().to_string())
        };
        if let Err(err) = state.device_registry.update_metadata(
            &device.id,
            devices::DeviceMetadataPatch {
                display_name: connect.client.display_name.clone(),
                platform: Some(connect.client.platform.clone()),
                client_id: Some(connect.client.id.clone()),
                client_mode: Some(connect.client.mode.clone()),
                remote_ip,
                role: Some(role.to_string()),
                scopes: Some(scopes.to_vec()),
            },
        ) {
            warn!(error = %err, device_id = %device.id, "failed to update device metadata");
        }

        return Ok(());
    }

    require_pairing(state, device, connect, role, scopes, is_local, remote_addr)
}

fn require_pairing(
    state: &WsServerState,
    device: &DeviceIdentity,
    connect: &ConnectParams,
    role: &str,
    scopes: &[String],
    is_local: bool,
    remote_addr: SocketAddr,
) -> Result<(), ErrorShape> {
    let remote_ip = if is_local {
        None
    } else {
        Some(remote_addr.ip().to_string())
    };
    let outcome = state
        .device_registry
        .request_pairing_with_status(
            device.id.clone(),
            device.public_key.clone(),
            vec![role.to_string()],
            scopes.to_vec(),
            connect.client.display_name.clone(),
            Some(connect.client.platform.clone()),
            Some(connect.client.id.clone()),
            Some(connect.client.mode.clone()),
            remote_ip,
            Some(is_local),
        )
        .map_err(|e| match e {
            devices::DevicePairingError::PublicKeyMismatch => {
                error_shape(ERROR_INVALID_REQUEST, "device identity mismatch", None)
            }
            devices::DevicePairingError::TooManyPendingRequests => {
                error_shape(ERROR_UNAVAILABLE, "too many pending pairing requests", None)
            }
            _ => error_shape(ERROR_UNAVAILABLE, &e.to_string(), None),
        })?;

    let request = outcome.request;
    let silent = request.silent.unwrap_or(false);
    if outcome.created && !silent {
        broadcast_event(
            state,
            "device.pair.requested",
            json!({
                "requestId": request.request_id,
                "deviceId": request.device_id,
                "publicKey": request.public_key,
                "displayName": request.display_name,
                "platform": request.platform,
                "clientId": request.client_id,
                "clientMode": request.client_mode,
                "role": request.role,
                "roles": request.requested_roles,
                "scopes": request.requested_scopes,
                "remoteIp": request.remote_ip,
                "silent": request.silent,
                "isRepair": request.is_repair,
                "ts": request.created_at_ms
            }),
        );
    }

    if is_local {
        let _ = state
            .device_registry
            .approve_request(
                &request.request_id,
                request.requested_roles,
                request.requested_scopes,
            )
            .map_err(|e| error_shape(ERROR_UNAVAILABLE, &e.to_string(), None))?;

        broadcast_event(
            state,
            "device.pair.resolved",
            json!({
                "requestId": request.request_id,
                "deviceId": request.device_id,
                "decision": "approved",
                "ts": now_ms()
            }),
        );
        return Ok(());
    }

    Err(error_shape(
        ERROR_NOT_PAIRED,
        "pairing required",
        Some(json!({ "details": { "requestId": request.request_id } })),
    ))
}

fn ensure_device_token(
    state: &WsServerState,
    device_id: &str,
    role: &str,
    scopes: &[String],
) -> Result<devices::IssuedDeviceToken, devices::DevicePairingError> {
    state
        .device_registry
        .ensure_token(device_id, role.to_string(), scopes.to_vec())
}

fn verify_device_token(
    state: &WsServerState,
    device_id: &str,
    token: &str,
    role: &str,
    scopes: &[String],
) -> bool {
    state
        .device_registry
        .verify_token(device_id, token, Some(role), scopes)
        .is_ok()
}

fn build_device_auth_payload(params: DeviceAuthPayload) -> String {
    let version = if params.nonce.is_some() { "v2" } else { "v1" };
    let scopes = params.scopes.join(",");
    let token = params.token.unwrap_or_default();
    let mut base = vec![
        version.to_string(),
        params.device_id,
        params.client_id,
        params.client_mode,
        params.role,
        scopes,
        params.signed_at_ms.to_string(),
        token,
    ];
    if let Some(nonce) = params.nonce {
        base.push(nonce);
    }
    base.join("|")
}

#[derive(Debug)]
struct DeviceAuthPayload {
    device_id: String,
    client_id: String,
    client_mode: String,
    role: String,
    scopes: Vec<String>,
    signed_at_ms: i64,
    token: Option<String>,
    nonce: Option<String>,
}

fn verify_device_signature(public_key: &str, payload: &str, signature: &str) -> bool {
    let pubkey_raw = match base64url_decode(public_key) {
        Ok(bytes) => bytes,
        Err(_) => return false,
    };
    let sig_raw = match base64url_decode(signature) {
        Ok(bytes) => bytes,
        Err(_) => return false,
    };
    let Ok(pubkey_bytes) = <[u8; 32]>::try_from(pubkey_raw.as_slice()) else {
        return false;
    };
    let Ok(sig_bytes) = <[u8; 64]>::try_from(sig_raw.as_slice()) else {
        return false;
    };
    let Ok(pubkey) = VerifyingKey::from_bytes(&pubkey_bytes) else {
        return false;
    };
    let sig = Signature::from_bytes(&sig_bytes);
    pubkey.verify_strict(payload.as_bytes(), &sig).is_ok()
}

fn derive_device_id_from_public_key(public_key: &str) -> Option<String> {
    let raw = base64url_decode(public_key).ok()?;
    let digest = Sha256::digest(&raw);
    Some(hex::encode(digest))
}

fn base64url_decode(input: &str) -> Result<Vec<u8>, ()> {
    if let Ok(bytes) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(input.as_bytes()) {
        return Ok(bytes);
    }
    base64::engine::general_purpose::STANDARD
        .decode(input.as_bytes())
        .map_err(|_| ())
}

fn now_ms() -> u64 {
    crate::time::unix_now_ms_u64()
}

fn server_version() -> String {
    config::read_process_env("CARAPACE_VERSION")
        .or_else(|| config::read_process_env("npm_package_version"))
        .unwrap_or_else(|| "dev".to_string())
}

fn server_commit() -> Option<String> {
    config::read_process_env("GIT_COMMIT")
}

fn server_hostname() -> String {
    config::read_process_env("HOSTNAME").unwrap_or_else(|| "unknown".to_string())
}

enum InboundText {
    Text(String),
    Control,
    Close,
}

fn message_to_text(msg: Message) -> Result<InboundText, &'static str> {
    match msg {
        Message::Text(text) => Ok(InboundText::Text(text.to_string())),
        Message::Binary(_) => Err("binary messages not supported"),
        Message::Close(_) => Ok(InboundText::Close),
        Message::Ping(_) | Message::Pong(_) => Ok(InboundText::Control),
    }
}

fn error_shape(code: &'static str, message: &str, details: Option<Value>) -> ErrorShape {
    ErrorShape {
        code,
        message: message.to_string(),
        retryable: wire_code_is_retryable(code),
        details,
    }
}

fn send_json<T: Serialize>(tx: &ConnectionTx, payload: &T) -> Result<(), ()> {
    let text = serde_json::to_string(payload).map_err(|_| ())?;
    // try_send — `Full` (slow client) is treated identically to
    // `Closed` (gone). Both surface as Err(()) here, and the caller
    // (`send_event_to_connection` etc.) removes the connection.
    // This is the bounded-channel backpressure-as-disconnect
    // contract documented at the channel-construction site.
    tx.try_send_text(text)
}

/// Send a pre-serialized JSON string as a WebSocket text message.
/// Used by broadcast paths to avoid re-serializing the same frame per connection.
fn send_text(tx: &ConnectionTx, text: String) -> Result<(), ()> {
    tx.try_send_text(text)
}

fn send_event_to_connection(
    state: &WsServerState,
    conn_id: &str,
    event: &str,
    payload: Value,
) -> bool {
    let frame = EventFrame {
        frame_type: "event",
        event,
        payload,
        seq: Some(state.next_event_seq()),
        state_version: None,
    };
    let tx = {
        let conns = state.connections.lock();
        let Some(conn) = conns.get(conn_id) else {
            return false;
        };
        conn.tx.clone()
    };
    if send_json(&tx, &frame).is_err() {
        state.drop_connection_after_send_failure(conn_id, event);
        return false;
    }
    true
}

fn event_required_scope(event: &str) -> Option<&'static str> {
    match event {
        "device.pair.requested"
        | "device.pair.resolved"
        | "node.pair.requested"
        | "node.pair.resolved" => Some("operator.pairing"),
        "exec.approval.requested" | "exec.approval.resolved" => Some("operator.approvals"),
        "matrix.verification.requested" | "matrix.verification.updated" => Some("operator.admin"),
        // Default-closed for any future `matrix.*` event. The
        // current Matrix events above are admin-scope; new
        // events added without an explicit arm would otherwise
        // default to wide broadcast (None) and silently surface
        // sensitive Matrix peer/device/room state to non-admin
        // operator connections. Force a conscious classification
        // by routing fall-through to admin; if a future event
        // is genuinely safe for wider scope, it must be added
        // to an explicit arm above (and its scope reviewed).
        e if e.starts_with("matrix.") => Some("operator.admin"),
        _ => None,
    }
}

fn matrix_verification_request_rate_key(
    event: &str,
    payload: &Value,
) -> MatrixVerificationRequestRateKey {
    let verification = payload.get("verification").and_then(Value::as_object);
    let flow_id = verification
        .and_then(|v| v.get("flowId"))
        .and_then(Value::as_str)
        .or_else(|| {
            verification
                .and_then(|v| v.get("protocolFlowId"))
                .and_then(Value::as_str)
        });
    let user_id = verification
        .and_then(|v| v.get("userId"))
        .and_then(Value::as_str)
        .map(ToString::to_string)
        .unwrap_or_else(|| {
            let discriminator = flow_id
                .filter(|flow_id| !flow_id.is_empty())
                .map(ToString::to_string)
                .unwrap_or_else(|| verification_payload_hash(payload));
            format!("<missing-user:{discriminator}>")
        });
    let device_id = verification
        .and_then(|v| v.get("deviceId"))
        .and_then(Value::as_str);
    MatrixVerificationRequestRateKey {
        user_id: format!("{event}:{user_id}"),
        device: match device_id {
            Some(device_id) if !device_id.is_empty() => {
                MatrixVerificationRequestRateDevice::DeviceId {
                    device_id: device_id.to_string(),
                }
            }
            _ => flow_id
                .filter(|flow_id| !flow_id.is_empty())
                .map(
                    |flow_id| MatrixVerificationRequestRateDevice::MissingDevice {
                        flow_id: flow_id.to_string(),
                    },
                )
                .unwrap_or(MatrixVerificationRequestRateDevice::MalformedMissingDevice),
        },
    }
}

fn matrix_verification_request_rate_class(payload: &Value) -> MatrixVerificationRequestRateClass {
    let verification = payload.get("verification").and_then(Value::as_object);
    let malformed = verification
        .and_then(|v| v.get("userId"))
        .and_then(Value::as_str)
        .is_none()
        || (verification
            .and_then(|v| v.get("deviceId"))
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .is_none()
            && verification
                .and_then(|v| v.get("flowId"))
                .and_then(Value::as_str)
                .or_else(|| {
                    verification
                        .and_then(|v| v.get("protocolFlowId"))
                        .and_then(Value::as_str)
                })
                .filter(|value| !value.is_empty())
                .is_none());
    if malformed {
        return MatrixVerificationRequestRateClass::Malformed;
    }
    let state = verification
        .and_then(|v| v.get("state"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    if matches!(
        state,
        "done" | "cancelled" | "canceled" | "failed" | "expired" | "timeout" | "timed_out"
    ) {
        MatrixVerificationRequestRateClass::Finished
    } else {
        MatrixVerificationRequestRateClass::Normal
    }
}

fn verification_payload_hash(payload: &Value) -> String {
    let mut hasher = Sha256::new();
    hasher.update(payload.to_string().as_bytes());
    hex::encode(hasher.finalize())
}

fn serialize_event_frame(state: &WsServerState, event: &str, payload: Value) -> Option<String> {
    serialize_event_frame_with_state_version(state, event, payload, None)
}

fn serialize_event_frame_with_state_version(
    state: &WsServerState,
    event: &str,
    payload: Value,
    state_version: Option<StateVersion>,
) -> Option<String> {
    serialize_event_frame_with_explicit_seq(
        state,
        event,
        payload,
        state.next_event_seq(),
        state_version,
    )
}

fn serialize_event_frame_with_explicit_seq(
    state: &WsServerState,
    event: &str,
    payload: Value,
    seq: u64,
    state_version: Option<StateVersion>,
) -> Option<String> {
    let frame = EventFrame {
        frame_type: "event",
        event,
        payload: payload.clone(),
        seq: Some(seq),
        state_version: state_version.clone(),
    };
    match serialize_json_frame_capped(&frame, WS_BROADCAST_PAYLOAD_MAX_BYTES) {
        Ok(s) => Some(s),
        Err(FrameSerializeError::TooLarge { bytes_at_least }) => {
            if event == "agent" {
                let truncated_payload = truncated_agent_broadcast_payload(
                    payload,
                    bytes_at_least,
                    WS_BROADCAST_PAYLOAD_MAX_BYTES,
                );
                let frame = EventFrame {
                    frame_type: "event",
                    event,
                    payload: truncated_payload,
                    seq: Some(seq),
                    state_version: state_version.clone(),
                };
                match serialize_json_frame_capped(&frame, WS_BROADCAST_PAYLOAD_MAX_BYTES) {
                    Ok(truncated) => return Some(truncated),
                    Err(FrameSerializeError::TooLarge { bytes_at_least }) => {
                        let drop_total = state.record_ws_broadcast_drop();
                        log_ws_broadcast_frame_drop(
                            event,
                            drop_total,
                            Some(bytes_at_least),
                            None,
                            "WS broadcast event remains oversized after agent truncation; dropping notification",
                        );
                        return None;
                    }
                    Err(FrameSerializeError::Serialize(err)) => {
                        let drop_total = state.record_ws_broadcast_drop();
                        log_ws_broadcast_frame_drop(
                            event,
                            drop_total,
                            None,
                            Some(&err),
                            "WS truncated agent broadcast failed to serialize; dropping notification",
                        );
                        return None;
                    }
                }
            }
            let drop_total = state.record_ws_broadcast_drop();
            log_ws_broadcast_frame_drop(
                event,
                drop_total,
                Some(bytes_at_least),
                None,
                "WS broadcast event frame exceeds size cap; dropping notification",
            );
            None
        }
        Err(FrameSerializeError::Serialize(err)) => {
            let drop_total = state.record_ws_broadcast_drop();
            log_ws_broadcast_frame_drop(
                event,
                drop_total,
                None,
                Some(&err),
                "WS broadcast event payload failed to serialize; dropping notification",
            );
            None
        }
    }
}

fn log_ws_broadcast_frame_drop(
    event: &str,
    drop_total: u64,
    bytes_at_least: Option<usize>,
    error: Option<&serde_json::Error>,
    message: &'static str,
) {
    if drop_total <= 10 || drop_total.is_power_of_two() {
        tracing::warn!(
            event = %event,
            serialized_frame_bytes_at_least = bytes_at_least,
            max_frame_bytes = WS_BROADCAST_PAYLOAD_MAX_BYTES,
            drop_total,
            error = error.map(ToString::to_string),
            "{message}"
        );
    } else {
        tracing::debug!(
            event = %event,
            drop_total,
            "{message}"
        );
    }
}

#[derive(Debug)]
enum FrameSerializeError {
    TooLarge { bytes_at_least: usize },
    Serialize(serde_json::Error),
}

struct CappedJsonWriter {
    buf: Vec<u8>,
    max: usize,
    overflow: bool,
    bytes_at_least: usize,
}

impl std::io::Write for CappedJsonWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let next_len = self.buf.len().saturating_add(bytes.len());
        if next_len > self.max {
            self.overflow = true;
            self.bytes_at_least = self.max.saturating_add(1);
            return Err(std::io::Error::other("websocket frame cap exceeded"));
        }
        self.buf.extend_from_slice(bytes);
        self.bytes_at_least = self.buf.len();
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn serialize_json_frame_capped<T: Serialize>(
    frame: &T,
    max_bytes: usize,
) -> Result<String, FrameSerializeError> {
    let mut writer = CappedJsonWriter {
        buf: Vec::with_capacity(max_bytes.min(16 * 1024)),
        max: max_bytes,
        overflow: false,
        bytes_at_least: 0,
    };
    let result = {
        let mut serializer = serde_json::Serializer::new(&mut writer);
        frame.serialize(&mut serializer)
    };
    if let Err(err) = result {
        if writer.overflow {
            return Err(FrameSerializeError::TooLarge {
                bytes_at_least: writer.bytes_at_least,
            });
        }
        return Err(FrameSerializeError::Serialize(err));
    }
    Ok(String::from_utf8(writer.buf).expect("serde_json writes UTF-8"))
}

fn truncated_agent_broadcast_payload(
    payload: Value,
    original_frame_bytes_at_least: usize,
    max_frame_bytes: usize,
) -> Value {
    let marker = json!({
        "truncated": true,
        "reason": "agent broadcast payload exceeded websocket frame cap",
        "originalFrameBytesAtLeast": original_frame_bytes_at_least,
        "maxFrameBytes": max_frame_bytes,
    });
    match payload {
        Value::Object(mut map) => {
            map.insert("truncated".to_string(), Value::Bool(true));
            map.insert(
                "reason".to_string(),
                Value::String("agent broadcast payload exceeded websocket frame cap".to_string()),
            );
            map.insert(
                "originalFrameBytesAtLeast".to_string(),
                Value::from(original_frame_bytes_at_least),
            );
            map.insert("maxFrameBytes".to_string(), Value::from(max_frame_bytes));
            map.insert("data".to_string(), marker);
            Value::Object(map)
        }
        _ => marker,
    }
}

fn broadcast_serialized_event(
    state: &WsServerState,
    event: &str,
    serialized: String,
    include_nodes: bool,
) {
    let dead = broadcast_serialized_event_collect_dead(state, event, serialized, include_nodes);
    for conn_id in dead {
        state.drop_connection_after_send_failure(&conn_id, event);
    }
}

fn broadcast_serialized_event_collect_dead(
    state: &WsServerState,
    event: &str,
    serialized: String,
    include_nodes: bool,
) -> Vec<String> {
    let required_scope = event_required_scope(event);
    let snapshot: Vec<(String, ConnectionTx)> = {
        let conns = state.connections.lock();
        conns
            .iter()
            .filter_map(|(conn_id, conn)| {
                if !include_nodes && conn.role == "node" {
                    return None;
                }
                if let Some(required_scope) = required_scope {
                    if conn.role != "admin" && !scope_satisfies(&conn.scopes, required_scope) {
                        return None;
                    }
                }
                Some((conn_id.clone(), conn.tx.clone()))
            })
            .collect()
    };
    let mut dead = Vec::new();
    for (conn_id, tx) in snapshot {
        if send_text(&tx, serialized.clone()).is_err() {
            dead.push(conn_id);
        }
    }
    dead
}

fn broadcast_presence_event_per_recipient(
    state: &WsServerState,
    seq: u64,
    state_version: StateVersion,
) -> Vec<String> {
    let snapshot: Vec<(String, bool, ConnectionTx)> = {
        let conns = state.connections.lock();
        conns
            .iter()
            .filter_map(|(conn_id, conn)| {
                if conn.role == "node" {
                    return None;
                }
                Some((
                    conn_id.clone(),
                    connection_has_admin_presence_visibility(conn),
                    conn.tx.clone(),
                ))
            })
            .collect()
    };
    let mut dead = Vec::new();
    for (conn_id, admin_visible, tx) in snapshot {
        let presence_list = state.get_presence_list_for_recipient(admin_visible);
        let Some(serialized) = serialize_event_frame_with_explicit_seq(
            state,
            "presence",
            json!({ "presence": presence_list }),
            seq,
            Some(state_version.clone()),
        ) else {
            continue;
        };
        if send_text(&tx, serialized).is_err() {
            dead.push(conn_id);
        }
    }
    dead
}

fn broadcast_event(state: &WsServerState, event: &str, payload: Value) {
    if matches!(
        event,
        "matrix.verification.requested" | "matrix.verification.updated"
    ) && !state.allow_matrix_verification_request_broadcast(event, &payload)
    {
        let drop_total = state.record_matrix_verification_rate_limit_drop();
        log_matrix_verification_rate_limit_drop(event, drop_total);
        return;
    }
    let Some(serialized) = serialize_event_frame(state, event, payload) else {
        return;
    };
    broadcast_serialized_event(state, event, serialized, false);
}

fn log_matrix_verification_rate_limit_drop(event: &str, drop_total: u64) {
    if drop_total == 1 || drop_total.is_power_of_two() {
        tracing::warn!(
            event = %event,
            max_burst = MATRIX_VERIFICATION_REQUEST_RATE_BURST,
            window_secs = MATRIX_VERIFICATION_REQUEST_RATE_WINDOW.as_secs(),
            drop_total,
            "WS matrix verification broadcast rate-limited; dropping notification"
        );
    } else {
        tracing::debug!(
            event = %event,
            drop_total,
            "WS matrix verification broadcast rate-limited; dropping notification"
        );
    }
}

// ============================================================================
// Operator Broadcast Helpers
// ============================================================================
// These functions provide typed broadcast helpers for specific event types,
// matching the Node.js gateway's broadcast patterns in src/gateway/server-broadcast.ts

/// Broadcast an agent event to all operator connections.
/// Agent events include: start, delta, tool_use, tool_result, final, error, thinking
///
/// # Arguments
/// * `state` - Server state
/// * `run_id` - Agent run identifier (from idempotencyKey)
/// * `seq` - Event sequence within this run
/// * `stream` - Stream type (text, tool_use, tool_result, final, error, thinking)
/// * `data` - Stream-specific data
pub fn broadcast_agent_event(
    state: &WsServerState,
    run_id: &str,
    seq: u64,
    stream: &str,
    data: Value,
) {
    let payload = json!({
        "runId": run_id,
        "seq": seq,
        "stream": stream,
        "ts": now_ms(),
        "data": data
    });
    broadcast_event(state, "agent", payload);
}

/// Broadcast a chat event to all operator connections.
/// Chat events are used by webchat-ui clients.
///
/// # Arguments
/// * `state` - Server state
/// * `run_id` - Chat run identifier (from idempotencyKey)
/// * `session_key` - Session key
/// * `seq` - Event sequence within this run
/// * `chat_state` - Event state: "delta", "final", "aborted", "error"
/// * `message` - Optional message content
/// * `error_message` - Optional error description (for error state)
/// * `usage` - Optional token usage (for final state)
/// * `stop_reason` - Optional stop reason
#[allow(clippy::too_many_arguments)]
pub fn broadcast_chat_event(
    state: &WsServerState,
    run_id: &str,
    session_key: &str,
    seq: u64,
    chat_state: &str,
    message: Option<Value>,
    error_message: Option<&str>,
    usage: Option<Value>,
    stop_reason: Option<&str>,
) {
    let mut payload = json!({
        "runId": run_id,
        "sessionKey": session_key,
        "seq": seq,
        "state": chat_state
    });
    if let Some(msg) = message {
        payload["message"] = msg;
    }
    if let Some(err) = error_message {
        payload["errorMessage"] = json!(err);
    }
    if let Some(u) = usage {
        payload["usage"] = u;
    }
    if let Some(sr) = stop_reason {
        payload["stopReason"] = json!(sr);
    }
    broadcast_event(state, "chat", payload);
}

/// Broadcast a cron job event to all operator connections.
///
/// # Arguments
/// * `state` - Server state
/// * `job_id` - Cron job identifier
/// * `status` - Job status (e.g., "started", "completed", "failed")
/// * `run_id` - Optional run identifier
/// * `result` - Optional result data
pub fn broadcast_cron_event(
    state: &WsServerState,
    job_id: &str,
    status: &str,
    run_id: Option<&str>,
    result: Option<Value>,
) {
    let mut payload = json!({
        "jobId": job_id,
        "status": status,
        "ts": now_ms()
    });
    if let Some(rid) = run_id {
        payload["runId"] = json!(rid);
    }
    if let Some(r) = result {
        payload["result"] = r;
    }
    broadcast_event(state, "cron", payload);
}

/// Broadcast a voicewake configuration change event.
/// This is sent to node clients when voice wake triggers are updated.
///
/// # Arguments
/// * `state` - Server state
/// * `triggers` - Updated voice wake triggers
pub fn broadcast_voicewake_changed(state: &WsServerState, triggers: Vec<String>) {
    let payload = json!({
        "triggers": triggers,
        "ts": now_ms()
    });
    let Some(serialized) = serialize_event_frame(state, "voicewake.changed", payload) else {
        return;
    };
    // voicewake.changed goes to all connections including nodes.
    broadcast_serialized_event(state, "voicewake.changed", serialized, true);
}

/// Broadcast an exec approval requested event.
/// This is sent to operators with the approvals scope.
///
/// # Arguments
/// * `state` - Server state
/// * `request_id` - Approval request identifier
/// * `command` - Command requesting approval
/// * `args` - Command arguments
/// * `cwd` - Optional working directory
/// * `agent_id` - Optional agent identifier
/// * `session_key` - Optional session key
pub fn broadcast_exec_approval_requested(
    state: &WsServerState,
    request_id: &str,
    command: &str,
    args: Vec<String>,
    cwd: Option<&str>,
    agent_id: Option<&str>,
    session_key: Option<&str>,
) {
    let mut payload = json!({
        "requestId": request_id,
        "command": command,
        "args": args,
        "ts": now_ms()
    });
    if let Some(c) = cwd {
        payload["cwd"] = json!(c);
    }
    if let Some(aid) = agent_id {
        payload["agentId"] = json!(aid);
    }
    if let Some(sk) = session_key {
        payload["sessionKey"] = json!(sk);
    }
    broadcast_event(state, "exec.approval.requested", payload);
}

/// Broadcast an exec approval resolved event.
/// This is sent to operators with the approvals scope.
///
/// # Arguments
/// * `state` - Server state
/// * `request_id` - Approval request identifier
/// * `decision` - Decision: "approved" or "denied"
pub fn broadcast_exec_approval_resolved(state: &WsServerState, request_id: &str, decision: &str) {
    let payload = json!({
        "requestId": request_id,
        "decision": decision,
        "ts": now_ms()
    });
    broadcast_event(state, "exec.approval.resolved", payload);
}

/// Witness type for `matrix.verification.requested`.
///
/// Distinguishes the "a brand-new flow appeared, decide whether to act"
/// signal from the "an in-flight flow's state changed" signal. Both
/// events serialize to the same JSON shape on the wire (a
/// `MatrixVerificationInfo` payload), but the typed witness gates
/// construction on the `inserted: bool` returned by
/// `upsert_verification_record`. The inner field is private and the
/// only constructor (`from_upsert`) returns `Option<Self>` — calling
/// from a non-insert path produces `None`, which the broadcaster
/// helper short-circuits on. A regression where a refresh-tick
/// rebuild of the local record tries to fire `requested` becomes a
/// compile-or-runtime no-op rather than a duplicated UI notification.
pub(crate) struct NewVerificationFlow<'a>(&'a crate::channels::matrix::MatrixVerificationInfo);

impl<'a> NewVerificationFlow<'a> {
    /// Construct a `NewVerificationFlow` witness only when the upsert
    /// actually inserted the record. Returns `None` for an existing
    /// flow that was merely refreshed — the caller's downstream
    /// `broadcast_matrix_verification_request` then quietly skips
    /// emitting `requested`.
    pub(crate) fn from_upsert(
        info: &'a crate::channels::matrix::MatrixVerificationInfo,
        inserted: bool,
    ) -> Option<Self> {
        if inserted {
            Some(Self(info))
        } else {
            None
        }
    }

    pub(crate) fn info(&self) -> &crate::channels::matrix::MatrixVerificationInfo {
        self.0
    }
}

/// Witness type for `matrix.verification.updated`.
///
/// Carries the post-state record for a flow that was already known.
/// Refresh ticks broadcasting unchanged records are suppressed by
/// `update_verification_record_state` returning `Ok(None)`; the
/// witness type pairs that runtime dedupe with a compile-time guard
/// against a future regression that re-broadcasts unchanged records. Construction is via the typed
/// constructor `for_state_change` so the wire-format-broadcaster does
/// not have to take a `pub` field-named instance.
pub(crate) struct UpdatedVerificationFlow<'a>(&'a crate::channels::matrix::MatrixVerificationInfo);

impl<'a> UpdatedVerificationFlow<'a> {
    pub(crate) fn for_state_change(
        info: &'a crate::channels::matrix::MatrixVerificationInfo,
    ) -> Self {
        Self(info)
    }

    pub(crate) fn info(&self) -> &crate::channels::matrix::MatrixVerificationInfo {
        self.0
    }
}

/// Broadcast that a Matrix device verification flow needs operator attention.
///
/// Takes `Option<NewVerificationFlow>` so the call site can pass
/// `NewVerificationFlow::from_upsert(info, inserted)` and have a
/// non-insert (`inserted == false`) automatically suppress the
/// broadcast — the type system enforces "only fire `requested` on a
/// fresh upsert" without each call site needing to inline the check.
pub(crate) fn broadcast_matrix_verification_request(
    state: &WsServerState,
    new_flow: Option<NewVerificationFlow<'_>>,
) {
    let Some(new_flow) = new_flow else {
        return;
    };
    let payload = json!({
        "verification": new_flow.info(),
        "ts": now_ms()
    });
    broadcast_event(state, "matrix.verification.requested", payload);
}

/// Broadcast that a Matrix device verification flow changed state.
pub(crate) fn broadcast_matrix_verification_updated(
    state: &WsServerState,
    updated_flow: UpdatedVerificationFlow<'_>,
) {
    let payload = json!({
        "verification": updated_flow.info(),
        "ts": now_ms()
    });
    broadcast_event(state, "matrix.verification.updated", payload);
}

/// Broadcast a shutdown event to all connections.
/// This notifies clients that the server is shutting down.
///
/// # Arguments
/// * `state` - Server state
/// * `reason` - Shutdown reason
/// * `restart_expected_ms` - Optional expected restart time in milliseconds
pub fn broadcast_shutdown(state: &WsServerState, reason: &str, restart_expected_ms: Option<u64>) {
    let mut payload = json!({
        "reason": reason
    });
    if let Some(ms) = restart_expected_ms {
        payload["restartExpectedMs"] = json!(ms);
    }
    let Some(serialized) = serialize_event_frame(state, "shutdown", payload) else {
        tracing::warn!(
            reason = %reason,
            "WS shutdown event payload failed validation; clients won't receive notification"
        );
        return;
    };
    // Shutdown goes to all connections.
    broadcast_serialized_event(state, "shutdown", serialized, true);
}

/// Broadcast a heartbeat event to all operator connections.
///
/// # Arguments
/// * `state` - Server state
pub fn broadcast_heartbeat(state: &WsServerState) {
    let ts = state.record_heartbeat();
    let payload = json!({
        "ts": ts
    });
    broadcast_event(state, "heartbeat", payload);
}

/// Broadcast a talk mode change event to all operator connections.
///
/// # Arguments
/// * `state` - Server state
/// * `enabled` - Whether talk mode is enabled
/// * `channel` - Optional channel identifier
pub fn broadcast_talk_mode(state: &WsServerState, enabled: bool, channel: Option<&str>) {
    let mut payload = json!({
        "enabled": enabled
    });
    if let Some(ch) = channel {
        payload["channel"] = json!(ch);
    }
    broadcast_event(state, "talk.mode", payload);
}

fn send_response(
    tx: &ConnectionTx,
    id: &str,
    ok: bool,
    payload: Option<Value>,
    error: Option<ErrorShape>,
) -> Result<(), ()> {
    let frame = ResponseFrame {
        frame_type: "res",
        id,
        ok,
        payload,
        error,
    };
    send_json(tx, &frame)
}

fn send_close(tx: &ConnectionTx, code: u16, reason: &str) -> Result<(), ()> {
    // Truncate close reason to 123 bytes to fit WebSocket limit
    let truncated_reason: String = reason.chars().take(123).collect();
    let frame = CloseFrame {
        code,
        reason: truncated_reason.into(),
    };
    let result = tx.try_send_message(Message::Close(Some(frame)), 0);
    tx.close();
    result
}

async fn recv_text_with_timeout(
    receiver: &mut futures_util::stream::SplitStream<WebSocket>,
    timeout_ms: u64,
) -> Result<Option<String>, &'static str> {
    let deadline = Instant::now() + Duration::from_millis(timeout_ms);
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err("handshake timeout");
        }
        let msg = match tokio::time::timeout(remaining, receiver.next()).await {
            Ok(Some(Ok(msg))) => msg,
            Ok(Some(Err(_))) => return Err("socket error"),
            Ok(None) => return Ok(None),
            Err(_) => return Err("handshake timeout"),
        };
        match message_to_text(msg)? {
            InboundText::Text(text) => return Ok(Some(text)),
            InboundText::Control => continue,
            InboundText::Close => return Ok(None),
        }
    }
}

const CANVAS_COMMANDS: [&str; 8] = [
    "canvas.present",
    "canvas.hide",
    "canvas.navigate",
    "canvas.eval",
    "canvas.snapshot",
    "canvas.a2ui.push",
    "canvas.a2ui.pushJSONL",
    "canvas.a2ui.reset",
];
const CAMERA_COMMANDS: [&str; 3] = ["camera.list", "camera.snap", "camera.clip"];
const SCREEN_COMMANDS: [&str; 1] = ["screen.record"];
const LOCATION_COMMANDS: [&str; 1] = ["location.get"];
const SMS_COMMANDS: [&str; 1] = ["sms.send"];
const SYSTEM_COMMANDS: [&str; 6] = [
    "system.run",
    "system.which",
    "system.notify",
    "system.execApprovals.get",
    "system.execApprovals.set",
    "browser.proxy",
];

fn normalize_platform_id(platform: Option<&str>, device_family: Option<&str>) -> &'static str {
    let raw = platform.unwrap_or_default().trim().to_lowercase();
    if raw.starts_with("ios") {
        return "ios";
    }
    if raw.starts_with("android") {
        return "android";
    }
    if raw.starts_with("mac") || raw.starts_with("darwin") {
        return "macos";
    }
    if raw.starts_with("win") {
        return "windows";
    }
    if raw.starts_with("linux") {
        return "linux";
    }
    let family = device_family.unwrap_or_default().trim().to_lowercase();
    if family.contains("iphone") || family.contains("ipad") || family.contains("ios") {
        return "ios";
    }
    if family.contains("android") {
        return "android";
    }
    if family.contains("mac") {
        return "macos";
    }
    if family.contains("windows") {
        return "windows";
    }
    if family.contains("linux") {
        return "linux";
    }
    "unknown"
}

fn default_node_commands(platform_id: &str) -> Vec<&'static str> {
    let mut commands = Vec::new();
    match platform_id {
        "ios" => {
            commands.extend_from_slice(&CANVAS_COMMANDS);
            commands.extend_from_slice(&CAMERA_COMMANDS);
            commands.extend_from_slice(&SCREEN_COMMANDS);
            commands.extend_from_slice(&LOCATION_COMMANDS);
        }
        "android" => {
            commands.extend_from_slice(&CANVAS_COMMANDS);
            commands.extend_from_slice(&CAMERA_COMMANDS);
            commands.extend_from_slice(&SCREEN_COMMANDS);
            commands.extend_from_slice(&LOCATION_COMMANDS);
            commands.extend_from_slice(&SMS_COMMANDS);
        }
        "macos" => {
            commands.extend_from_slice(&CANVAS_COMMANDS);
            commands.extend_from_slice(&CAMERA_COMMANDS);
            commands.extend_from_slice(&SCREEN_COMMANDS);
            commands.extend_from_slice(&LOCATION_COMMANDS);
            commands.extend_from_slice(&SYSTEM_COMMANDS);
        }
        "linux" | "windows" => {
            commands.extend_from_slice(&SYSTEM_COMMANDS);
        }
        _ => {
            commands.extend_from_slice(&CANVAS_COMMANDS);
            commands.extend_from_slice(&CAMERA_COMMANDS);
            commands.extend_from_slice(&SCREEN_COMMANDS);
            commands.extend_from_slice(&LOCATION_COMMANDS);
            commands.extend_from_slice(&SMS_COMMANDS);
            commands.extend_from_slice(&SYSTEM_COMMANDS);
        }
    }
    commands
}

fn resolve_node_command_allowlist(
    allow: &[String],
    deny: &[String],
    platform: Option<&str>,
    device_family: Option<&str>,
) -> HashSet<String> {
    let platform_id = normalize_platform_id(platform, device_family);
    let mut allowlist: HashSet<String> = default_node_commands(platform_id)
        .into_iter()
        .map(|cmd| cmd.to_string())
        .collect();
    for cmd in allow {
        let trimmed = cmd.trim();
        if !trimmed.is_empty() {
            allowlist.insert(trimmed.to_string());
        }
    }
    for cmd in deny {
        let trimmed = cmd.trim();
        if !trimmed.is_empty() {
            allowlist.remove(trimmed);
        }
    }
    allowlist
}

pub(crate) fn resolve_state_dir() -> PathBuf {
    crate::paths::resolve_state_dir()
}
