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
use std::env;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::{mpsc, oneshot};
use tracing::warn;
use uuid::Uuid;

use crate::{
    agent, auth, channels, config, credentials, cron, devices, exec, messages, nodes, plugins,
    sessions,
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

// Re-export update functions for use by CLI
pub(crate) use handlers::{apply_staged_update, cleanup_old_binaries};

// Re-export config persistence types for use by control endpoint
pub(crate) use handlers::{
    broadcast_config_changed, map_validation_issues, persist_config_file, read_config_snapshot,
};

const PROTOCOL_VERSION: u32 = 3;
const MAX_PAYLOAD_BYTES: usize = 512 * 1024;
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

const ERROR_INVALID_REQUEST: &str = "INVALID_REQUEST";
const ERROR_NOT_PAIRED: &str = "NOT_PAIRED";
const ERROR_UNAVAILABLE: &str = "UNAVAILABLE";
const ERROR_RATE_LIMITED: &str = "RATE_LIMITED";
// Note: Node doesn't use ERROR_FORBIDDEN - use ERROR_INVALID_REQUEST for auth errors

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
    // Models/agents/skills
    "models.list",
    "agents.list",
    "skills.status",
    "skills.bins",
    "skills.install",
    "skills.update",
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

const GATEWAY_EVENTS: [&str; 20] = [
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
    /// Agent run registry for tracking active/completed agent invocations
    pub agent_run_registry: Mutex<handlers::AgentRunRegistry>,
    /// System event history (enqueued via system-event method)
    system_event_history: Mutex<Vec<SystemEvent>>,
    /// LLM provider for agent execution (hot-swappable via RwLock)
    llm_provider: parking_lot::RwLock<Option<Arc<dyn agent::LlmProvider>>>,
    /// Tools registry for agent tool dispatch
    tools_registry: Option<Arc<plugins::ToolsRegistry>>,
    /// Plugin registry for channel/tool/webhook plugins
    plugin_registry: Option<Arc<plugins::PluginRegistry>>,
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
                "tools_registry",
                &self.tools_registry.as_ref().map(|_| ".."),
            )
            .field(
                "plugin_registry",
                &self.plugin_registry.as_ref().map(|_| ".."),
            )
            .finish_non_exhaustive()
    }
}

impl WsServerState {
    pub fn new(config: WsServerConfig) -> Self {
        let connection_tracker = limits::ConnectionTracker::with_limits(
            config
                .max_ws_connections
                .unwrap_or(limits::DEFAULT_MAX_CONNECTIONS),
            config.max_ws_per_ip.unwrap_or(limits::DEFAULT_MAX_PER_IP),
        );
        Self {
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
            presence: Mutex::new(HashMap::new()),
            health_cache: Mutex::new(HealthSnapshot {
                ts: now_ms(),
                status: "healthy".to_string(),
                channels: None,
                agent: None,
            }),
            state_versions: Mutex::new(StateVersionTracker::default()),
            heartbeat_state: Mutex::new(HeartbeatState {
                enabled: false,
                interval_ms: DEFAULT_HEARTBEAT_INTERVAL_MS,
                last_heartbeat_ms: None,
            }),
            exec_manager: exec::ExecApprovalManager::new(),
            cron_scheduler: cron::CronScheduler::in_memory(),
            agent_run_registry: Mutex::new(handlers::AgentRunRegistry::new()),
            system_event_history: Mutex::new(Vec::new()),
            llm_provider: parking_lot::RwLock::new(None),
            tools_registry: None,
            plugin_registry: None,
            connection_tracker,
        }
    }

    pub fn new_persistent(
        config: WsServerConfig,
        state_dir: PathBuf,
    ) -> Result<Self, WsConfigError> {
        let node_pairing = nodes::create_registry(state_dir.clone())?;
        let device_registry = devices::create_registry(state_dir.clone())?;
        let connection_tracker = limits::ConnectionTracker::with_limits(
            config
                .max_ws_connections
                .unwrap_or(limits::DEFAULT_MAX_CONNECTIONS),
            config.max_ws_per_ip.unwrap_or(limits::DEFAULT_MAX_PER_IP),
        );
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
            presence: Mutex::new(HashMap::new()),
            health_cache: Mutex::new(HealthSnapshot {
                ts: now_ms(),
                status: "healthy".to_string(),
                channels: None,
                agent: None,
            }),
            state_versions: Mutex::new(StateVersionTracker::default()),
            heartbeat_state: Mutex::new(HeartbeatState {
                enabled: false,
                interval_ms: DEFAULT_HEARTBEAT_INTERVAL_MS,
                last_heartbeat_ms: None,
            }),
            exec_manager: exec::ExecApprovalManager::new(),
            cron_scheduler: {
                let scheduler =
                    cron::CronScheduler::new(true, Some(state_dir.join("cron").join("jobs.json")));
                scheduler.load();
                scheduler
            },
            agent_run_registry: Mutex::new(handlers::AgentRunRegistry::new()),
            system_event_history: Mutex::new(Vec::new()),
            llm_provider: parking_lot::RwLock::new(None),
            tools_registry: None,
            plugin_registry: None,
            connection_tracker,
        })
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

    /// Get the plugin registry, if configured.
    pub fn plugin_registry(&self) -> Option<&Arc<plugins::PluginRegistry>> {
        self.plugin_registry.as_ref()
    }

    /// Get the outbound message pipeline.
    pub fn message_pipeline(&self) -> &Arc<messages::outbound::MessagePipeline> {
        &self.message_pipeline
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

    /// Get the current state version (presence + health)
    fn current_state_version(&self) -> StateVersion {
        self.state_versions.lock().current()
    }

    /// Register a connection and update presence tracking.
    /// Broadcasts a presence event to all operators.
    fn register_connection(
        &self,
        conn: &ConnectionContext,
        tx: mpsc::UnboundedSender<Message>,
        remote_ip: Option<String>,
    ) {
        // Add to connections map
        {
            let mut conns = self.connections.lock();
            conns.insert(
                conn.conn_id.clone(),
                ConnectionHandle {
                    role: conn.role.clone(),
                    scopes: conn.scopes.clone(),
                    tx,
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

        // Increment presence version and broadcast
        let state_version = {
            let mut versions = self.state_versions.lock();
            versions.increment_presence();
            versions.current()
        };

        self.broadcast_presence_event(state_version);
    }

    /// Unregister a connection and update presence tracking.
    /// Broadcasts a presence event to remaining operators.
    fn unregister_connection(&self, conn_id: &str) {
        // Remove from connections
        {
            let mut conns = self.connections.lock();
            conns.remove(conn_id);
        }
        {
            let mut defaults = self.session_defaults.lock();
            defaults.remove(conn_id);
        }

        // Update presence tracking (mark as disconnect, then remove)
        {
            let mut presence = self.presence.lock();
            if let Some(entry) = presence.get_mut(conn_id) {
                entry.reason = Some("disconnect".to_string());
                entry.ts = now_ms();
            }
            presence.remove(conn_id);
        }

        // Increment presence version and broadcast
        let state_version = {
            let mut versions = self.state_versions.lock();
            versions.increment_presence();
            versions.current()
        };

        self.broadcast_presence_event(state_version);
    }

    /// Get current presence list as JSON values with TTL pruning and ts-desc ordering.
    /// Prunes expired entries (older than 5 minutes) to match Node's listSystemPresence.
    fn get_presence_list(&self) -> Vec<Value> {
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
            .map(|e| (e.ts, serde_json::to_value(e).unwrap_or(json!({}))))
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
        self.health_cache.lock().clone()
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
        };

        let should_broadcast = {
            let mut cache = self.health_cache.lock();
            let changed = cache.status != new_snapshot.status;
            *cache = new_snapshot.clone();
            changed
        };

        if should_broadcast {
            let state_version = {
                let mut versions = self.state_versions.lock();
                versions.increment_health();
                versions.current()
            };
            self.broadcast_health_event(new_snapshot, state_version);
        }
    }

    /// Broadcast presence event to all operator connections
    pub(crate) fn broadcast_presence_event(&self, state_version: StateVersion) {
        let presence_list = self.get_presence_list();
        let frame = EventFrame {
            frame_type: "event",
            event: "presence",
            payload: json!({ "presence": presence_list }),
            seq: Some(self.next_event_seq()),
            state_version: Some(state_version),
        };

        let serialized = match serde_json::to_string(&frame) {
            Ok(s) => s,
            Err(_) => return,
        };

        let mut conns = self.connections.lock();
        let mut dead = Vec::new();
        for (conn_id, conn) in conns.iter() {
            // Only send to operators, not nodes
            if conn.role == "node" {
                continue;
            }
            if send_text(&conn.tx, serialized.clone()).is_err() {
                dead.push(conn_id.clone());
            }
        }
        for conn_id in dead {
            conns.remove(&conn_id);
        }
    }

    /// Broadcast health event to all operator connections
    fn broadcast_health_event(&self, snapshot: HealthSnapshot, state_version: StateVersion) {
        let frame = EventFrame {
            frame_type: "event",
            event: "health",
            payload: serde_json::to_value(&snapshot).unwrap_or(json!({})),
            seq: Some(self.next_event_seq()),
            state_version: Some(state_version),
        };

        let serialized = match serde_json::to_string(&frame) {
            Ok(s) => s,
            Err(_) => return,
        };

        let mut conns = self.connections.lock();
        let mut dead = Vec::new();
        for (conn_id, conn) in conns.iter() {
            if conn.role == "node" {
                continue;
            }
            if send_text(&conn.tx, serialized.clone()).is_err() {
                dead.push(conn_id.clone());
            }
        }
        for conn_id in dead {
            conns.remove(&conn_id);
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
}

pub async fn build_ws_state_owned_from_value(cfg: &Value) -> Result<WsServerState, WsConfigError> {
    let state_dir = resolve_state_dir();
    if let Err(err) = credentials::migrate_plaintext_credentials(state_dir.clone()).await {
        tracing::warn!(error = %err, "Credential migration failed");
    }
    let config = build_ws_config_from_value(cfg).await?;
    let mut state = WsServerState::new_persistent(config, state_dir)?;

    // Wire session integrity HMAC key from config
    let sessions_cfg = cfg.get("sessions").and_then(|s| s.get("integrity"));
    let integrity_enabled = sessions_cfg
        .and_then(|i| i.get("enabled"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    if integrity_enabled {
        // Derive HMAC key from the gateway auth token (server secret)
        let server_secret = std::env::var("CARAPACE_GATEWAY_TOKEN")
            .or_else(|_| std::env::var("CARAPACE_SERVER_SECRET"))
            .unwrap_or_default();

        if !server_secret.is_empty() {
            let hmac_key = crate::sessions::integrity::derive_hmac_key(server_secret.as_bytes());

            let integrity_action = sessions_cfg
                .and_then(|i| i.get("action"))
                .and_then(|v| v.as_str())
                .map(|s| match s {
                    "reject" => crate::sessions::integrity::IntegrityAction::Reject,
                    _ => crate::sessions::integrity::IntegrityAction::Warn,
                })
                .unwrap_or(crate::sessions::integrity::IntegrityAction::Warn);

            let session_store = sessions::SessionStore::with_base_path(
                state.session_store.base_path().to_path_buf(),
            )
            .with_hmac_key(hmac_key)
            .with_integrity_action(integrity_action);
            state.session_store = Arc::new(session_store);

            tracing::info!(
                action = ?integrity_action,
                "session integrity verification enabled"
            );
        } else {
            tracing::warn!(
                "sessions.integrity.enabled is true but no server secret found \
                 (set CARAPACE_GATEWAY_TOKEN or CARAPACE_SERVER_SECRET)"
            );
        }
    }

    Ok(state)
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

    let env_token = env::var("CARAPACE_GATEWAY_TOKEN").ok();
    let env_password = env::var("CARAPACE_GATEWAY_PASSWORD").ok();

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
    let legacy_session_obj = cfg.get("session").and_then(|v| v.as_object());
    let session_retention_days = sessions_obj
        .and_then(|s| s.get("retention"))
        .and_then(|r| r.get("days"))
        .and_then(|v| v.as_u64())
        .map(|d| d as u32)
        .or_else(|| {
            sessions_obj
                .and_then(|s| s.get("retentionDays"))
                .and_then(|v| v.as_u64())
                .map(|d| d as u32)
        })
        .or_else(|| {
            legacy_session_obj
                .and_then(|s| s.get("retention"))
                .and_then(|r| r.get("days"))
                .and_then(|v| v.as_u64())
                .map(|d| d as u32)
        });

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
    #[allow(dead_code)] // populated, read later
    command: String,
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
                        code: Some("NOT_CONNECTED".to_string()),
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

    fn conn_id_for_node(&self, node_id: &str) -> Option<String> {
        self.nodes_by_id
            .get(node_id)
            .map(|session| session.conn_id.clone())
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
    #[serde(default)]
    #[allow(dead_code)] // deserialized from client
    locale: Option<String>,
    #[serde(default)]
    #[allow(dead_code)] // deserialized from client
    user_agent: Option<String>,
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

#[derive(Debug, Serialize)]
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

#[derive(Clone, Debug)]
struct ConnectionHandle {
    role: String,
    scopes: Vec<String>,
    tx: mpsc::UnboundedSender<Message>,
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
    let (tx, mut rx) = mpsc::unbounded_channel::<Message>();

    let send_task = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if sender.send(msg).await.is_err() {
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
    let conn = ConnectionContext {
        conn_id: handshake.conn_id,
        role: handshake.role,
        scopes: handshake.scopes,
        client: handshake.connect_params.client,
        device_id: handshake.device_id,
    };
    run_connection_lifecycle(
        &mut receiver,
        &tx,
        &state,
        conn,
        handshake.remote_ip_for_presence,
        handshake.json_depth_limit,
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
    tx: &mpsc::UnboundedSender<Message>,
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
    tx: &mpsc::UnboundedSender<Message>,
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
    tx: &mpsc::UnboundedSender<Message>,
    state: &Arc<WsServerState>,
    conn: ConnectionContext,
    remote_ip_for_presence: Option<String>,
    json_depth_limit: usize,
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
        &mut ws_rate_limiter,
        &mut ws_rate_warn_count,
    )
    .await;

    tick_task.abort();
    state.unregister_connection(&conn.conn_id);
    state.node_registry.lock().unregister(&conn.conn_id);
}

/// Send the connect challenge event containing a nonce.
fn send_challenge(tx: &mpsc::UnboundedSender<Message>, nonce: &str) {
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
    tick_tx: mpsc::UnboundedSender<Message>,
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
    tx: &mpsc::UnboundedSender<Message>,
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

/// Check the per-connection rate limiter. Returns `Ok(())` if the request
/// should proceed, `Err(LoopSignal::Continue)` if rate-limited (warning sent),
/// or `Err(LoopSignal::Break)` if the warning threshold was exceeded.
fn check_rate_limit(
    tx: &mpsc::UnboundedSender<Message>,
    req_id: &str,
    rate_limiter: &mut crate::server::ratelimit::WsRateLimiter,
    warn_count: &mut u32,
) -> Result<(), LoopSignal> {
    if !rate_limiter.try_consume() {
        *warn_count += 1;
        if *warn_count >= 3 {
            let _ = send_close(tx, 1008, "rate limit exceeded");
            return Err(LoopSignal::Break);
        }
        let err = error_shape(ERROR_RATE_LIMITED, "rate limit exceeded", None);
        let _ = send_response(tx, req_id, false, None, Some(err));
        return Err(LoopSignal::Continue);
    }
    *warn_count = 0;
    Ok(())
}

/// Validate request params depth and reject duplicate connect calls.
/// Returns `Ok(())` if the request should proceed, `Err(LoopSignal::Continue)`
/// to skip this message.
fn validate_request_params(
    tx: &mpsc::UnboundedSender<Message>,
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
    tx: &mpsc::UnboundedSender<Message>,
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

/// Main message receive loop. Processes inbound WebSocket frames until the
/// connection is closed or an unrecoverable error occurs.
async fn run_message_loop(
    receiver: &mut futures_util::stream::SplitStream<WebSocket>,
    tx: &mpsc::UnboundedSender<Message>,
    state: &Arc<WsServerState>,
    conn: &ConnectionContext,
    json_depth_limit: usize,
    ws_rate_limiter: &mut crate::server::ratelimit::WsRateLimiter,
    ws_rate_warn_count: &mut u32,
) {
    while let Some(next) = receiver.next().await {
        let msg = match next {
            Ok(msg) => msg,
            Err(_) => break,
        };
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

        match check_rate_limit(tx, &req_id, ws_rate_limiter, ws_rate_warn_count) {
            Ok(()) => {}
            Err(LoopSignal::Continue) => continue,
            Err(LoopSignal::Break) => break,
        }
        if validate_request_params(tx, &req_id, &method, &params, json_depth_limit).is_err() {
            continue;
        }
        let canonical_method = handlers::canonicalize_ws_method_name(&method);
        let method_known = GATEWAY_METHODS.contains(&canonical_method);
        let result = dispatch_method(&method, params.as_ref(), state, conn).await;
        send_dispatch_result(tx, &req_id, &method, method_known, result);
    }
}

/// Receive the initial handshake message: timeout-bounded first message receive,
/// payload parsing, and connect method validation.
/// Returns (request_id, ConnectParams) on success, Err(()) if the connection should close.
async fn receive_initial_handshake(
    receiver: &mut futures_util::stream::SplitStream<WebSocket>,
    tx: &mpsc::UnboundedSender<Message>,
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
    tx: &mpsc::UnboundedSender<Message>,
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
    tx: &mpsc::UnboundedSender<Message>,
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
    tx: &mpsc::UnboundedSender<Message>,
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
    let presence_list = state.get_presence_list();
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
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_millis() as u64
}

fn server_version() -> String {
    std::env::var("CARAPACE_VERSION")
        .or_else(|_| std::env::var("npm_package_version"))
        .unwrap_or_else(|_| "dev".to_string())
}

fn server_commit() -> Option<String> {
    std::env::var("GIT_COMMIT").ok()
}

fn server_hostname() -> String {
    std::env::var("HOSTNAME").unwrap_or_else(|_| "unknown".to_string())
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
        retryable: code == ERROR_UNAVAILABLE,
        details,
    }
}

fn send_json<T: Serialize>(tx: &mpsc::UnboundedSender<Message>, payload: &T) -> Result<(), ()> {
    let text = serde_json::to_string(payload).map_err(|_| ())?;
    tx.send(Message::Text(text.into())).map_err(|_| ())
}

/// Send a pre-serialized JSON string as a WebSocket text message.
/// Used by broadcast paths to avoid re-serializing the same frame per connection.
fn send_text(tx: &mpsc::UnboundedSender<Message>, text: String) -> Result<(), ()> {
    tx.send(Message::Text(text.into())).map_err(|_| ())
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
    let mut conns = state.connections.lock();
    let Some(conn) = conns.get(conn_id) else {
        return false;
    };
    if send_json(&conn.tx, &frame).is_err() {
        conns.remove(conn_id);
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
        _ => None,
    }
}

fn broadcast_event(state: &WsServerState, event: &str, payload: Value) {
    let frame = EventFrame {
        frame_type: "event",
        event,
        payload,
        seq: Some(state.next_event_seq()),
        state_version: None,
    };
    let serialized = match serde_json::to_string(&frame) {
        Ok(s) => s,
        Err(_) => return,
    };
    let required_scope = event_required_scope(event);
    let mut conns = state.connections.lock();
    let mut dead = Vec::new();
    for (conn_id, conn) in conns.iter() {
        if conn.role == "node" {
            continue;
        }
        if let Some(required_scope) = required_scope {
            if conn.role != "admin" && !scope_satisfies(&conn.scopes, required_scope) {
                continue;
            }
        }
        if send_text(&conn.tx, serialized.clone()).is_err() {
            dead.push(conn_id.clone());
        }
    }
    for conn_id in dead {
        conns.remove(&conn_id);
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
    // voicewake.changed goes to all connections including nodes
    let frame = EventFrame {
        frame_type: "event",
        event: "voicewake.changed",
        payload,
        seq: Some(state.next_event_seq()),
        state_version: None,
    };
    let serialized = match serde_json::to_string(&frame) {
        Ok(s) => s,
        Err(_) => return,
    };
    let mut conns = state.connections.lock();
    let mut dead = Vec::new();
    for (conn_id, conn) in conns.iter() {
        if send_text(&conn.tx, serialized.clone()).is_err() {
            dead.push(conn_id.clone());
        }
    }
    for conn_id in dead {
        conns.remove(&conn_id);
    }
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
    let frame = EventFrame {
        frame_type: "event",
        event: "shutdown",
        payload,
        seq: Some(state.next_event_seq()),
        state_version: None,
    };
    let serialized = match serde_json::to_string(&frame) {
        Ok(s) => s,
        Err(_) => return,
    };
    // Shutdown goes to all connections
    let conns = state.connections.lock();
    for conn in conns.values() {
        let _ = send_text(&conn.tx, serialized.clone());
    }
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

/// Send an event to a specific node connection (for node.invoke.request).
/// This is used to request a node to invoke a command.
///
/// # Arguments
/// * `state` - Server state
/// * `node_id` - Target node identifier
/// * `invoke_id` - Invocation identifier
/// * `command` - Command to invoke
/// * `args` - Command arguments
/// * `cwd` - Optional working directory
/// * `env` - Optional environment variables
/// * `timeout_ms` - Optional timeout in milliseconds
///
/// Returns true if the event was sent successfully
#[allow(clippy::too_many_arguments)]
pub fn send_node_invoke_request(
    state: &WsServerState,
    node_id: &str,
    invoke_id: &str,
    command: &str,
    args: Vec<String>,
    cwd: Option<&str>,
    env: Option<HashMap<String, String>>,
    timeout_ms: Option<u64>,
) -> bool {
    let node_registry = state.node_registry.lock();
    let Some(conn_id) = node_registry.conn_id_for_node(node_id) else {
        return false;
    };
    drop(node_registry);

    let mut payload = json!({
        "id": invoke_id,
        "command": command,
        "args": args
    });
    if let Some(c) = cwd {
        payload["cwd"] = json!(c);
    }
    if let Some(e) = env {
        payload["env"] = serde_json::to_value(e).unwrap_or(json!({}));
    }
    if let Some(t) = timeout_ms {
        payload["timeoutMs"] = json!(t);
    }

    send_event_to_connection(state, &conn_id, "node.invoke.request", payload)
}

fn send_response(
    tx: &mpsc::UnboundedSender<Message>,
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

fn send_close(tx: &mpsc::UnboundedSender<Message>, code: u16, reason: &str) -> Result<(), ()> {
    // Truncate close reason to 123 bytes to fit WebSocket limit
    let truncated_reason: String = reason.chars().take(123).collect();
    let frame = CloseFrame {
        code,
        reason: truncated_reason.into(),
    };
    tx.send(Message::Close(Some(frame))).map_err(|_| ())
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
    if let Ok(dir) = env::var("CARAPACE_STATE_DIR") {
        return PathBuf::from(dir);
    }
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from(".config"))
        .join("carapace")
}
