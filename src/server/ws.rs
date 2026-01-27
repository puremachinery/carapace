//! WebSocket server implementation
//!
//! Implements the gateway WebSocket protocol (handshake + framing + auth).

use axum::extract::ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade};
use axum::extract::{ConnectInfo, State};
use axum::http::HeaderMap;
use axum::response::IntoResponse;
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
use tokio::sync::mpsc;
use tracing::warn;
use uuid::Uuid;

use crate::{auth, config, credentials};

const PROTOCOL_VERSION: u32 = 3;
const MAX_PAYLOAD_BYTES: usize = 512 * 1024;
const MAX_BUFFERED_BYTES: usize = (1024 * 1024 * 3) / 2;
const TICK_INTERVAL_MS: u64 = 30_000;
const HANDSHAKE_TIMEOUT_MS: u64 = 10_000;
const SIGNATURE_SKEW_MS: i64 = 600_000;

const ERROR_INVALID_REQUEST: &str = "INVALID_REQUEST";
const ERROR_NOT_PAIRED: &str = "NOT_PAIRED";
const ERROR_UNAVAILABLE: &str = "UNAVAILABLE";
const ERROR_FORBIDDEN: &str = "FORBIDDEN";

const ALLOWED_CLIENT_IDS: [&str; 12] = [
    "webchat-ui",
    "clawdbot-control-ui",
    "webchat",
    "cli",
    "gateway-client",
    "clawdbot-macos",
    "clawdbot-ios",
    "clawdbot-android",
    "node-host",
    "test",
    "fingerprint",
    "clawdbot-probe",
];

const ALLOWED_CLIENT_MODES: [&str; 7] =
    ["webchat", "cli", "ui", "backend", "node", "probe", "test"];

const GATEWAY_METHODS: [&str; 79] = [
    "health",
    "status",
    "logs.tail",
    "channels.status",
    "channels.logout",
    "config.get",
    "config.set",
    "config.apply",
    "config.patch",
    "config.schema",
    "agent",
    "agent.identity.get",
    "agent.wait",
    "chat.send",
    "chat.history",
    "chat.abort",
    "sessions.list",
    "sessions.preview",
    "sessions.patch",
    "sessions.reset",
    "sessions.delete",
    "sessions.compact",
    "tts.status",
    "tts.providers",
    "tts.enable",
    "tts.disable",
    "tts.convert",
    "tts.setProvider",
    "voicewake.get",
    "voicewake.set",
    "wizard.start",
    "wizard.next",
    "wizard.cancel",
    "wizard.status",
    "talk.mode",
    "models.list",
    "agents.list",
    "skills.status",
    "skills.bins",
    "skills.install",
    "skills.update",
    "update.run",
    "cron.status",
    "cron.list",
    "cron.add",
    "cron.update",
    "cron.remove",
    "cron.run",
    "cron.runs",
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
    "device.pair.list",
    "device.pair.approve",
    "device.pair.reject",
    "device.token.rotate",
    "device.token.revoke",
    "exec.approvals.get",
    "exec.approvals.set",
    "exec.approvals.node.get",
    "exec.approvals.node.set",
    "exec.approval.request",
    "exec.approval.resolve",
    "usage.status",
    "usage.cost",
    "last-heartbeat",
    "set-heartbeats",
    "wake",
    "send",
    "system-presence",
    "system-event",
];

const GATEWAY_EVENTS: [&str; 18] = [
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
    "node.pair.requested",
    "node.pair.resolved",
    "node.invoke.request",
    "device.pair.requested",
    "device.pair.resolved",
    "voicewake.changed",
    "exec.approval.requested",
    "exec.approval.resolved",
];

#[derive(Clone, Debug)]
pub struct WsAuthConfig {
    pub resolved: auth::ResolvedGatewayAuth,
}

impl Default for WsAuthConfig {
    fn default() -> Self {
        Self {
            resolved: auth::ResolvedGatewayAuth::default(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct WsServerConfig {
    pub auth: WsAuthConfig,
    pub policy: WsPolicy,
    pub trusted_proxies: Vec<String>,
    pub control_ui_allow_insecure_auth: bool,
    pub control_ui_disable_device_auth: bool,
    pub node_allow_commands: Vec<String>,
    pub node_deny_commands: Vec<String>,
}

impl Default for WsServerConfig {
    fn default() -> Self {
        Self {
            auth: WsAuthConfig::default(),
            policy: WsPolicy::default(),
            trusted_proxies: Vec::new(),
            control_ui_allow_insecure_auth: false,
            control_ui_disable_device_auth: false,
            node_allow_commands: Vec::new(),
            node_deny_commands: Vec::new(),
        }
    }
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

#[derive(Debug)]
pub struct WsServerState {
    config: WsServerConfig,
    start_time: Instant,
    device_store: Mutex<DeviceStore>,
    node_registry: Mutex<NodeRegistry>,
    event_seq: Mutex<u64>,
}

impl WsServerState {
    pub fn new(config: WsServerConfig) -> Self {
        Self {
            config,
            start_time: Instant::now(),
            device_store: Mutex::new(DeviceStore::default()),
            node_registry: Mutex::new(NodeRegistry::default()),
            event_seq: Mutex::new(0),
        }
    }

    fn next_event_seq(&self) -> u64 {
        let mut guard = self.event_seq.lock();
        *guard += 1;
        *guard
    }
}

#[derive(Debug, thiserror::Error)]
pub enum WsConfigError {
    #[error(transparent)]
    Config(#[from] config::ConfigError),
    #[error(transparent)]
    Credentials(#[from] credentials::CredentialError),
}

pub async fn build_ws_state_from_config() -> Result<Arc<WsServerState>, WsConfigError> {
    let config = build_ws_config_from_files().await?;
    Ok(Arc::new(WsServerState::new(config)))
}

pub async fn build_ws_config_from_files() -> Result<WsServerConfig, WsConfigError> {
    let cfg = config::load_config()?;
    let gateway = cfg.get("gateway").and_then(|v| v.as_object());
    let auth_obj = gateway
        .and_then(|g| g.get("auth"))
        .and_then(|v| v.as_object());
    let tailscale_obj = gateway
        .and_then(|g| g.get("tailscale"))
        .and_then(|v| v.as_object());
    let control_ui_obj = gateway
        .and_then(|g| g.get("controlUi"))
        .and_then(|v| v.as_object());
    let nodes_obj = gateway
        .and_then(|g| g.get("nodes"))
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

    let env_token = env::var("CLAWDBOT_GATEWAY_TOKEN").ok();
    let env_password = env::var("CLAWDBOT_GATEWAY_PASSWORD").ok();

    let state_dir = resolve_state_dir();
    let creds = match credentials::read_gateway_auth(state_dir).await {
        Ok(creds) => creds,
        Err(err) => {
            warn!("failed to read gateway credentials: {}", err);
            credentials::GatewayAuthSecrets::default()
        }
    };
    let token = env_token.or(token_cfg).or(creds.token);
    let password = env_password.or(password_cfg).or(creds.password);

    let resolved_mode = match mode {
        "password" => auth::AuthMode::Password,
        "token" => auth::AuthMode::Token,
        _ => {
            if password.is_some() {
                auth::AuthMode::Password
            } else {
                auth::AuthMode::Token
            }
        }
    };

    let allow_tailscale = allow_tailscale_cfg.unwrap_or_else(|| {
        tailscale_mode == "serve" && !matches!(resolved_mode, auth::AuthMode::Password)
    });

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

    Ok(WsServerConfig {
        auth: WsAuthConfig {
            resolved: auth::ResolvedGatewayAuth {
                mode: resolved_mode,
                token,
                password,
                allow_tailscale,
            },
        },
        policy: WsPolicy::default(),
        trusted_proxies,
        control_ui_allow_insecure_auth,
        control_ui_disable_device_auth,
        node_allow_commands,
        node_deny_commands,
    })
}

/// Maximum number of paired devices to prevent unbounded memory growth
const MAX_PAIRED_DEVICES: usize = 100;

/// Maximum number of active tokens (across all devices)
const MAX_DEVICE_TOKENS: usize = 500;

#[derive(Debug, Default)]
struct DeviceStore {
    paired: HashMap<String, PairedDevice>,
    tokens: HashMap<String, DeviceToken>,
}

impl DeviceStore {
    /// Add a paired device, evicting oldest if at capacity
    fn add_paired_device(&mut self, device: PairedDevice) {
        // If already exists (update), just replace
        if self.paired.contains_key(&device.device_id) {
            self.paired.insert(device.device_id.clone(), device);
            return;
        }

        // Evict oldest if at capacity
        if self.paired.len() >= MAX_PAIRED_DEVICES {
            if let Some(oldest_id) = self.find_oldest_paired_device() {
                self.paired.remove(&oldest_id);
                // Also remove tokens for evicted device
                self.tokens.retain(|_, t| t.device_id != oldest_id);
            }
        }

        self.paired.insert(device.device_id.clone(), device);
    }

    /// Add a device token with the given key, evicting oldest if at capacity
    fn add_token(&mut self, key: String, token: DeviceToken) {
        // If already exists, replace
        if self.tokens.contains_key(&key) {
            self.tokens.insert(key, token);
            return;
        }

        // Evict oldest if at capacity
        if self.tokens.len() >= MAX_DEVICE_TOKENS {
            if let Some(oldest_key) = self.find_oldest_token_key() {
                self.tokens.remove(&oldest_key);
            }
        }

        self.tokens.insert(key, token);
    }

    /// Find the oldest paired device (by paired_at_ms)
    fn find_oldest_paired_device(&self) -> Option<String> {
        self.paired
            .values()
            .min_by_key(|d| d.paired_at_ms)
            .map(|d| d.device_id.clone())
    }

    /// Find the key of the oldest token (by issued_at_ms)
    fn find_oldest_token_key(&self) -> Option<String> {
        self.tokens
            .iter()
            .min_by_key(|(_, t)| t.issued_at_ms)
            .map(|(k, _)| k.clone())
    }

    /// Get current counts for diagnostics
    #[allow(dead_code)]
    fn stats(&self) -> (usize, usize) {
        (self.paired.len(), self.tokens.len())
    }
}

#[derive(Debug, Clone)]
struct NodeSession {
    node_id: String,
    commands: HashSet<String>,
}

#[derive(Debug, Default)]
struct NodeRegistry {
    nodes_by_id: HashMap<String, NodeSession>,
    nodes_by_conn: HashMap<String, String>,
}

impl NodeRegistry {
    fn register(&mut self, conn_id: &str, node_id: String, commands: HashSet<String>) {
        if let Some(existing) = self.nodes_by_conn.remove(conn_id) {
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
        self.nodes_by_id.insert(
            node_id.clone(),
            NodeSession {
                node_id: node_id.clone(),
                commands,
            },
        );
        self.nodes_by_conn.insert(conn_id.to_string(), node_id);
    }

    fn unregister(&mut self, conn_id: &str) -> Option<String> {
        let node_id = self.nodes_by_conn.remove(conn_id)?;
        self.nodes_by_id.remove(&node_id);
        Some(node_id)
    }

    fn get(&self, node_id: &str) -> Option<&NodeSession> {
        self.nodes_by_id.get(node_id)
    }
}

#[derive(Debug, Clone)]
struct PairedDevice {
    device_id: String,
    public_key: String,
    roles: Vec<String>,
    scopes: Vec<String>,
    paired_at_ms: u64,
}

#[derive(Debug, Clone)]
struct DeviceToken {
    token: String,
    device_id: String,
    role: String,
    scopes: Vec<String>,
    issued_at_ms: u64,
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
    locale: Option<String>,
    #[serde(default)]
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
struct StateVersion {
    presence: u64,
    health: u64,
}

#[derive(Debug, Serialize)]
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
struct Snapshot {
    presence: Vec<Value>,
    health: Value,
    #[serde(rename = "stateVersion")]
    state_version: StateVersion,
    #[serde(rename = "uptimeMs")]
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

pub async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<WsServerState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_socket(socket, state, addr, headers))
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

    let nonce = Uuid::new_v4().to_string();
    let challenge = EventFrame {
        frame_type: "event",
        event: "connect.challenge",
        payload: json!({ "nonce": nonce, "ts": now_ms() }),
        seq: None,
        state_version: None,
    };
    let _ = send_json(&tx, &challenge);

    let text = match recv_text_with_timeout(&mut receiver, HANDSHAKE_TIMEOUT_MS).await {
        Ok(Some(text)) => text,
        Ok(None) => return,
        Err(reason) => {
            if reason == "handshake timeout" {
                let _ = send_close(&tx, 1000, "");
            } else {
                let _ = send_close(&tx, 1008, reason);
            }
            return;
        }
    };

    if text.as_bytes().len() > MAX_PAYLOAD_BYTES {
        let _ = send_close(&tx, 1008, "payload too large");
        return;
    }

    let parsed = match serde_json::from_str::<Value>(&text) {
        Ok(val) => val,
        Err(_) => {
            let _ = send_close(&tx, 1008, "invalid request frame");
            return;
        }
    };

    let ParsedRequest {
        id: req_id,
        method,
        params,
    } = match parse_request_frame(&parsed) {
        Ok(req) => req,
        Err(err) => {
            let close_reason = err.error.message.clone();
            if let Some(id) = err.id {
                let _ = send_response(&tx, &id, false, None, Some(err.error));
            }
            let _ = send_close(&tx, 1008, &close_reason);
            return;
        }
    };

    if method != "connect" {
        let err = error_shape(
            ERROR_INVALID_REQUEST,
            "invalid handshake: first request must be connect",
            None,
        );
        let _ = send_response(&tx, &req_id, false, None, Some(err));
        let _ = send_close(
            &tx,
            1008,
            "invalid handshake: first request must be connect",
        );
        return;
    }

    let mut connect_params = match params {
        Some(value) => match serde_json::from_value::<ConnectParams>(value) {
            Ok(val) => val,
            Err(_) => {
                let err = error_shape(ERROR_INVALID_REQUEST, "invalid connect params", None);
                let _ = send_response(&tx, &req_id, false, None, Some(err));
                let _ = send_close(&tx, 1008, "invalid connect params");
                return;
            }
        },
        None => {
            let err = error_shape(ERROR_INVALID_REQUEST, "invalid connect params", None);
            let _ = send_response(&tx, &req_id, false, None, Some(err));
            let _ = send_close(&tx, 1008, "invalid connect params");
            return;
        }
    };

    if connect_params.min_protocol == 0 || connect_params.max_protocol == 0 {
        let err = error_shape(ERROR_INVALID_REQUEST, "invalid connect params", None);
        let _ = send_response(&tx, &req_id, false, None, Some(err));
        let _ = send_close(&tx, 1008, "invalid connect params");
        return;
    }

    if !ALLOWED_CLIENT_IDS.contains(&connect_params.client.id.as_str())
        || !ALLOWED_CLIENT_MODES.contains(&connect_params.client.mode.as_str())
        || connect_params.client.version.trim().is_empty()
        || connect_params.client.platform.trim().is_empty()
    {
        let err = error_shape(ERROR_INVALID_REQUEST, "invalid connect params", None);
        let _ = send_response(&tx, &req_id, false, None, Some(err));
        let _ = send_close(&tx, 1008, "invalid connect params");
        return;
    }

    if connect_params.max_protocol < PROTOCOL_VERSION
        || connect_params.min_protocol > PROTOCOL_VERSION
    {
        let err = error_shape(
            ERROR_INVALID_REQUEST,
            "protocol mismatch",
            Some(json!({ "expectedProtocol": PROTOCOL_VERSION })),
        );
        let _ = send_response(&tx, &req_id, false, None, Some(err));
        let _ = send_close(&tx, 1002, "protocol mismatch");
        return;
    }

    let is_local =
        auth::is_local_direct_request(remote_addr, &headers, &state.config.trusted_proxies);
    let role = connect_params
        .role
        .clone()
        .unwrap_or_else(|| "operator".to_string());
    if role != "operator" && role != "node" {
        let err = error_shape(ERROR_INVALID_REQUEST, "invalid role", None);
        let _ = send_response(&tx, &req_id, false, None, Some(err));
        let _ = send_close(&tx, 1008, "invalid role");
        return;
    }
    let requested_scopes = connect_params.scopes.clone().unwrap_or_default();
    let scopes = if requested_scopes.is_empty() && role == "operator" {
        vec!["operator.admin".to_string()]
    } else {
        requested_scopes
    };
    connect_params.role = Some(role.clone());
    connect_params.scopes = Some(scopes.clone());

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
    let is_control_ui = connect_params.client.id == "clawdbot-control-ui";
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
            let _ = send_response(&tx, &req_id, false, None, Some(err));
            let _ = send_close(&tx, 1008, "device identity required");
            return;
        }
    }

    let device_opt = if is_control_ui && state.config.control_ui_disable_device_auth {
        None
    } else {
        connect_params.device.as_ref()
    };

    let device_id = match device_opt {
        Some(device) => {
            if let Err(err) = validate_device_identity(device, &connect_params, &nonce, is_local) {
                let err_clone = err.clone();
                let _ = send_response(&tx, &req_id, false, None, Some(err));
                let _ = send_close(&tx, 1008, err_clone.message.as_str());
                return;
            }
            Some(device.id.clone())
        }
        None => None,
    };

    if let Err(err) = authorize_connection(
        &state,
        &connect_params,
        &headers,
        remote_addr,
        device_id.as_deref(),
        &role,
        &scopes,
    ) {
        let _ = send_response(&tx, &req_id, false, None, Some(err.clone()));
        let _ = send_close(&tx, 1008, err.message.as_str());
        return;
    }

    if let Some(device) = device_opt {
        if let Err(err) = ensure_paired(&state, device, &role, &scopes, is_local) {
            let _ = send_response(&tx, &req_id, false, None, Some(err.clone()));
            let _ = send_close(&tx, 1008, err.message.as_str());
            return;
        }
    }

    let conn_id = Uuid::new_v4().to_string();
    let issued_token = device_id
        .as_ref()
        .map(|id| ensure_device_token(&state, id, &role, &scopes));

    if role == "node" {
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

    if role == "node" {
        let node_id = device_id
            .clone()
            .unwrap_or_else(|| connect_params.client.id.clone());
        let commands = connect_params
            .commands
            .clone()
            .unwrap_or_default()
            .into_iter()
            .collect::<HashSet<String>>();
        state
            .node_registry
            .lock()
            .register(&conn_id, node_id, commands);
    }

    let hello = HelloOkPayload {
        payload_type: "hello-ok",
        protocol: PROTOCOL_VERSION,
        server: ServerInfo {
            version: server_version(),
            commit: server_commit(),
            host: server_hostname(),
            conn_id: conn_id.clone(),
        },
        features: Features {
            methods: GATEWAY_METHODS.iter().map(|s| s.to_string()).collect(),
            events: GATEWAY_EVENTS.iter().map(|s| s.to_string()).collect(),
        },
        snapshot: Snapshot {
            presence: Vec::new(),
            health: json!({}),
            state_version: StateVersion {
                presence: 0,
                health: 0,
            },
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
    };

    let _ = send_response(&tx, &req_id, true, Some(json!(hello)), None);

    let conn = ConnectionContext {
        conn_id: conn_id.clone(),
        role,
        scopes,
        client: connect_params.client.clone(),
        device_id,
    };

    let tick_tx = tx.clone();
    let tick_state = state.clone();
    let tick_task = tokio::spawn(async move {
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
    });

    while let Some(next) = receiver.next().await {
        let msg = match next {
            Ok(msg) => msg,
            Err(_) => break,
        };
        let text = match message_to_text(msg) {
            Ok(InboundText::Text(text)) => text,
            Ok(InboundText::Control) => continue,
            Ok(InboundText::Close) => break,
            Err(reason) => {
                let _ = send_close(&tx, 1008, reason);
                break;
            }
        };
        if text.as_bytes().len() > MAX_PAYLOAD_BYTES {
            let _ = send_close(&tx, 1008, "payload too large");
            break;
        }
        let parsed = match serde_json::from_str::<Value>(&text) {
            Ok(val) => val,
            Err(_) => {
                let _ = send_close(&tx, 1008, "invalid request frame");
                break;
            }
        };
        let ParsedRequest {
            id: req_id,
            method,
            params,
        } = match parse_request_frame(&parsed) {
            Ok(req) => req,
            Err(err) => {
                if let Some(id) = err.id {
                    let _ = send_response(&tx, &id, false, None, Some(err.error));
                } else {
                    let _ = send_close(&tx, 1008, "invalid request frame");
                }
                continue;
            }
        };
        if method == "connect" {
            let err = error_shape(ERROR_INVALID_REQUEST, "connect already completed", None);
            let _ = send_response(&tx, &req_id, false, None, Some(err));
            continue;
        }
        let method_known = GATEWAY_METHODS.contains(&method.as_str());
        let result = dispatch_method(&method, params.as_ref(), &state, &conn);
        match result {
            Ok(payload) => {
                let _ = send_response(&tx, &req_id, true, Some(payload), None);
            }
            Err(err) => {
                if method_known {
                    let _ = send_response(&tx, &req_id, false, None, Some(err));
                } else {
                    let _ = send_response(
                        &tx,
                        &req_id,
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

    tick_task.abort();
    drop(tx);
    let _ = send_task.await;

    state.node_registry.lock().unregister(&conn.conn_id);
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

fn handle_health() -> Value {
    json!({
        "ts": now_ms(),
        "status": "healthy"
    })
}

fn handle_status(state: &WsServerState) -> Value {
    json!({
        "ts": now_ms(),
        "status": "ok",
        "uptimeMs": state.start_time.elapsed().as_millis() as u64
    })
}

/// Methods exclusively for the `node` role
///
/// These methods can ONLY be called by node connections.
/// Non-node roles are explicitly blocked from calling these.
/// This matches Node.js gateway behavior in src/gateway/server-methods.ts.
const NODE_ONLY_METHODS: [&str; 3] = ["node.invoke.result", "node.event", "skills.bins"];

/// Methods that require operator.admin scope for operator role
///
/// Per Node.js gateway: config.*, wizard.*, update.*, skills.install/update,
/// channels.logout, sessions.*, and cron.* require operator.admin for operators.
const OPERATOR_ADMIN_REQUIRED_METHODS: [&str; 20] = [
    "config.get",
    "config.set",
    "config.apply",
    "config.patch",
    "config.schema",
    "sessions.patch",
    "sessions.reset",
    "sessions.delete",
    "sessions.compact",
    "wizard.start",
    "wizard.next",
    "wizard.cancel",
    "update.run",
    "skills.install",
    "skills.update",
    "cron.add",
    "cron.update",
    "cron.remove",
    "cron.run",
    "channels.logout",
];

/// Method authorization levels
///
/// Methods are categorized by the minimum role required to call them:
/// - read: health, status, list operations (any authenticated connection)
/// - write: session modifications, agent invocations
/// - admin: device pairing, exec approvals, sensitive operations
///
/// Note: For operators, additional scope checks are applied separately.
fn get_method_required_role(method: &str) -> &'static str {
    match method {
        // Read-only operations (any authenticated role)
        "health"
        | "status"
        | "last-heartbeat"
        | "config.get"
        | "config.schema"
        | "sessions.list"
        | "sessions.preview"
        | "channels.status"
        | "agent.identity.get"
        | "chat.history"
        | "tts.status"
        | "tts.providers"
        | "voicewake.get"
        | "wizard.status"
        | "models.list"
        | "agents.list"
        | "skills.status"
        | "cron.status"
        | "cron.list"
        | "cron.runs"
        | "node.list"
        | "node.describe"
        | "node.pair.list"
        | "device.pair.list"
        | "exec.approvals.get"
        | "exec.approvals.node.get"
        | "usage.status"
        | "usage.cost"
        | "logs.tail" => "read",

        // Write operations (requires write or admin role)
        "config.set" | "config.apply" | "config.patch" | "sessions.patch" | "sessions.reset"
        | "sessions.delete" | "sessions.compact" | "channels.logout" | "agent" | "agent.wait"
        | "chat.send" | "chat.abort" | "tts.enable" | "tts.disable" | "tts.convert"
        | "tts.setProvider" | "voicewake.set" | "wizard.start" | "wizard.next"
        | "wizard.cancel" | "talk.mode" | "skills.install" | "skills.update" | "update.run"
        | "cron.add" | "cron.update" | "cron.remove" | "cron.run" | "node.invoke"
        | "set-heartbeats" | "wake" | "send" | "system-presence" | "system-event" => "write",

        // Admin operations (requires admin role, or operator with specific scopes)
        "device.pair.approve"
        | "device.pair.reject"
        | "device.token.rotate"
        | "device.token.revoke"
        | "node.pair.request"
        | "node.pair.approve"
        | "node.pair.reject"
        | "node.pair.verify"
        | "node.rename"
        | "exec.approvals.set"
        | "exec.approvals.node.set"
        | "exec.approval.request"
        | "exec.approval.resolve" => "admin",

        // Unknown methods default to admin (fail secure)
        _ => "admin",
    }
}

/// Get the required scope for admin-level methods (for operator role)
///
/// These are methods that require a specific scope beyond operator.admin.
/// Operators can call these with the specific scope without needing full operator.admin.
fn get_method_specific_scope(method: &str) -> Option<&'static str> {
    match method {
        // Pairing operations require operator.pairing scope
        "device.pair.approve"
        | "device.pair.reject"
        | "device.token.rotate"
        | "device.token.revoke"
        | "node.pair.request"
        | "node.pair.approve"
        | "node.pair.reject"
        | "node.pair.verify"
        | "node.rename" => Some("operator.pairing"),

        // Exec approval operations require operator.approvals scope
        "exec.approvals.set"
        | "exec.approvals.node.set"
        | "exec.approval.request"
        | "exec.approval.resolve" => Some("operator.approvals"),

        // All other methods don't have a specific scope override
        _ => None,
    }
}

/// Check if a role satisfies the required role level
///
/// Role hierarchy: admin > operator > write > read
fn role_satisfies(has_role: &str, required_role: &str) -> bool {
    match required_role {
        "read" => true, // Any role satisfies read
        "write" => matches!(has_role, "write" | "admin" | "operator"),
        "admin" => has_role == "admin",
        _ => false,
    }
}

/// Check if scopes satisfy the required scope
fn scope_satisfies(scopes: &[String], required_scope: &str) -> bool {
    for scope in scopes {
        // Exact match
        if scope == required_scope {
            return true;
        }

        // Wildcard: operator.* covers all operator scopes
        if scope == "operator.*" && required_scope.starts_with("operator.") {
            return true;
        }

        // operator.admin covers all operator scopes
        if scope == "operator.admin" && required_scope.starts_with("operator.") {
            return true;
        }

        // operator.write covers operator.read
        if scope == "operator.write" && required_scope == "operator.read" {
            return true;
        }
    }

    false
}

/// Check if the connection is authorized to call a method
///
/// Authorization flow (matching Node.js gateway):
/// 1. Block node-only methods for non-node roles
/// 2. Node role: only allow node-only methods
/// 3. Admin role: full access
/// 4. Operator role: check scopes per method requirements
/// 5. Other roles: check role hierarchy
fn check_method_authorization(method: &str, conn: &ConnectionContext) -> Result<(), ErrorShape> {
    // Block node-only methods for non-node roles
    if NODE_ONLY_METHODS.contains(&method) && conn.role != "node" {
        return Err(error_shape(
            ERROR_FORBIDDEN,
            &format!("method '{}' is only allowed for node role", method),
            Some(json!({
                "method": method,
                "connection_role": conn.role,
                "required_role": "node"
            })),
        ));
    }

    // Node role: only allow node-only methods
    if conn.role == "node" {
        if NODE_ONLY_METHODS.contains(&method) {
            return Ok(());
        }
        return Err(error_shape(
            ERROR_FORBIDDEN,
            &format!(
                "method '{}' not allowed for node role (allowed: {:?})",
                method, NODE_ONLY_METHODS
            ),
            Some(json!({
                "method": method,
                "connection_role": "node",
                "allowed_methods": NODE_ONLY_METHODS
            })),
        ));
    }

    // Admin role: full access
    if conn.role == "admin" {
        return Ok(());
    }

    let required_role = get_method_required_role(method);

    // Operator role: check scopes per Node.js gateway model
    if conn.role == "operator" {
        return check_operator_authorization(method, required_role, conn);
    }

    // Other roles: check role hierarchy
    if !role_satisfies(&conn.role, required_role) {
        return Err(error_shape(
            ERROR_FORBIDDEN,
            &format!(
                "method '{}' requires role '{}', connection has role '{}'",
                method, required_role, conn.role
            ),
            Some(json!({
                "method": method,
                "required_role": required_role,
                "connection_role": conn.role
            })),
        ));
    }

    Ok(())
}

/// Check operator authorization with scope-based access control
///
/// Per Node.js gateway:
/// - operator.admin required for: config.*, wizard.*, update.*, skills.install/update, channels.logout
/// - operator.pairing allows: device pairing methods (without needing operator.admin)
/// - operator.approvals allows: exec approval methods (without needing operator.admin)
/// - operator.write required for write-level methods
/// - operator.read required for read-level methods
fn check_operator_authorization(
    method: &str,
    required_role: &str,
    conn: &ConnectionContext,
) -> Result<(), ErrorShape> {
    // Check if method requires operator.admin (config.*, wizard.*, etc.)
    if OPERATOR_ADMIN_REQUIRED_METHODS.contains(&method) {
        if !scope_satisfies(&conn.scopes, "operator.admin") {
            return Err(error_shape(
                ERROR_FORBIDDEN,
                &format!("method '{}' requires 'operator.admin' scope", method),
                Some(json!({
                    "method": method,
                    "required_scope": "operator.admin",
                    "connection_scopes": conn.scopes
                })),
            ));
        }
        return Ok(());
    }

    // Check if method has a specific scope that can bypass operator.admin
    // E.g., operator.pairing allows device.pair.* without full admin
    if let Some(specific_scope) = get_method_specific_scope(method) {
        if scope_satisfies(&conn.scopes, specific_scope) {
            return Ok(());
        }
        // Also allow if they have operator.admin
        if scope_satisfies(&conn.scopes, "operator.admin") {
            return Ok(());
        }
        return Err(error_shape(
            ERROR_FORBIDDEN,
            &format!(
                "method '{}' requires '{}' or 'operator.admin' scope",
                method, specific_scope
            ),
            Some(json!({
                "method": method,
                "required_scope": specific_scope,
                "connection_scopes": conn.scopes
            })),
        ));
    }

    // Check scope based on required role level
    match required_role {
        "write" => {
            if !scope_satisfies(&conn.scopes, "operator.write") {
                return Err(error_shape(
                    ERROR_FORBIDDEN,
                    &format!("method '{}' requires 'operator.write' scope", method),
                    Some(json!({
                        "method": method,
                        "required_scope": "operator.write",
                        "connection_scopes": conn.scopes
                    })),
                ));
            }
        }
        "read" => {
            if !scope_satisfies(&conn.scopes, "operator.read") {
                return Err(error_shape(
                    ERROR_FORBIDDEN,
                    &format!("method '{}' requires 'operator.read' scope", method),
                    Some(json!({
                        "method": method,
                        "required_scope": "operator.read",
                        "connection_scopes": conn.scopes
                    })),
                ));
            }
        }
        "admin" => {
            // Admin methods that don't have specific scopes require operator.admin
            if !scope_satisfies(&conn.scopes, "operator.admin") {
                return Err(error_shape(
                    ERROR_FORBIDDEN,
                    &format!("method '{}' requires 'operator.admin' scope", method),
                    Some(json!({
                        "method": method,
                        "required_scope": "operator.admin",
                        "connection_scopes": conn.scopes
                    })),
                ));
            }
        }
        _ => {
            // Unknown role level, fail secure
            return Err(error_shape(
                ERROR_FORBIDDEN,
                &format!(
                    "method '{}' has unknown required role '{}'",
                    method, required_role
                ),
                Some(json!({
                    "method": method,
                    "required_role": required_role
                })),
            ));
        }
    }

    Ok(())
}

fn dispatch_method(
    method: &str,
    params: Option<&Value>,
    state: &WsServerState,
    conn: &ConnectionContext,
) -> Result<Value, ErrorShape> {
    // Check authorization before dispatching
    check_method_authorization(method, conn)?;

    match method {
        // Health/status
        "health" => Ok(handle_health()),
        "status" => Ok(handle_status(state)),

        // Config
        "config.get" => handle_config_get(params),
        "config.set" => handle_config_set(params),
        "config.apply" => handle_config_apply(),
        "config.patch" => handle_config_patch(params),
        "config.schema" => handle_config_schema(),

        // Sessions
        "sessions.list" => handle_sessions_list(state),
        "sessions.preview" => handle_sessions_preview(params),
        "sessions.patch" => handle_sessions_patch(params),
        "sessions.reset" => handle_sessions_reset(params),
        "sessions.delete" => handle_sessions_delete(params),
        "sessions.compact" => handle_sessions_compact(params),

        // Channels
        "channels.status" => handle_channels_status(state),
        "channels.logout" => handle_channels_logout(params),

        // Agent
        "agent" => handle_agent(params, conn),
        "agent.identity.get" => handle_agent_identity_get(state),
        "agent.wait" => handle_agent_wait(params),

        // Chat
        "chat.history" => handle_chat_history(params),
        "chat.send" => handle_chat_send(params, conn),
        "chat.abort" => handle_chat_abort(params),

        // TTS
        "tts.status" => handle_tts_status(),
        "tts.providers" => handle_tts_providers(),
        "tts.enable" => handle_tts_enable(),
        "tts.disable" => handle_tts_disable(),
        "tts.convert" => handle_tts_convert(params),
        "tts.setProvider" => handle_tts_set_provider(params),

        // Voice wake
        "voicewake.get" => handle_voicewake_get(),
        "voicewake.set" => handle_voicewake_set(params),

        // Wizard
        "wizard.start" => handle_wizard_start(params),
        "wizard.next" => handle_wizard_next(params),
        "wizard.cancel" => handle_wizard_cancel(),
        "wizard.status" => handle_wizard_status(),

        // Talk mode
        "talk.mode" => handle_talk_mode(params),

        // Models/agents/skills
        "models.list" => handle_models_list(),
        "agents.list" => handle_agents_list(),
        "skills.status" => handle_skills_status(),
        "skills.bins" => handle_skills_bins(),
        "skills.install" => handle_skills_install(params),
        "skills.update" => handle_skills_update(params),
        "update.run" => handle_update_run(),

        // Cron
        "cron.status" => handle_cron_status(),
        "cron.list" => handle_cron_list(),
        "cron.add" => handle_cron_add(params),
        "cron.update" => handle_cron_update(params),
        "cron.remove" => handle_cron_remove(params),
        "cron.run" => handle_cron_run(params),
        "cron.runs" => handle_cron_runs(params),

        // Node pairing
        "node.pair.request" => handle_node_pair_request(params),
        "node.pair.list" => handle_node_pair_list(),
        "node.pair.approve" => handle_node_pair_approve(params),
        "node.pair.reject" => handle_node_pair_reject(params),
        "node.pair.verify" => handle_node_pair_verify(params),
        "node.rename" => handle_node_rename(params),
        "node.list" => handle_node_list(),
        "node.describe" => handle_node_describe(params),
        "node.invoke" => handle_node_invoke(params, state),
        "node.invoke.result" => handle_node_invoke_result(params),
        "node.event" => handle_node_event(params),

        // Device pairing
        "device.pair.list" => handle_device_pair_list(state),
        "device.pair.approve" => handle_device_pair_approve(params, state),
        "device.pair.reject" => handle_device_pair_reject(params, state),
        "device.token.rotate" => handle_device_token_rotate(params, state),
        "device.token.revoke" => handle_device_token_revoke(params, state),

        // Exec approvals
        "exec.approvals.get" => handle_exec_approvals_get(),
        "exec.approvals.set" => handle_exec_approvals_set(params),
        "exec.approvals.node.get" => handle_exec_approvals_node_get(params),
        "exec.approvals.node.set" => handle_exec_approvals_node_set(params),
        "exec.approval.request" => handle_exec_approval_request(params),
        "exec.approval.resolve" => handle_exec_approval_resolve(params),

        // Usage
        "usage.status" => handle_usage_status(),
        "usage.cost" => handle_usage_cost(params),

        // Logs
        "logs.tail" => handle_logs_tail(params),

        // Misc
        "last-heartbeat" => handle_last_heartbeat(),
        "set-heartbeats" => handle_set_heartbeats(params),
        "wake" => handle_wake(params),
        "send" => handle_send(params, conn),
        "system-presence" => handle_system_presence(params),
        "system-event" => handle_system_event(params),

        _ => Err(error_shape(
            ERROR_UNAVAILABLE,
            "method unavailable",
            Some(json!({ "method": method })),
        )),
    }
}

fn handle_config_get(params: Option<&Value>) -> Result<Value, ErrorShape> {
    let cfg = config::load_config()
        .map_err(|_| error_shape(ERROR_UNAVAILABLE, "config load failed", None))?;
    let key = params
        .and_then(|v| v.get("key"))
        .and_then(|v| v.as_str())
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());

    if let Some(key) = key {
        let value = get_value_at_path(&cfg, &key).unwrap_or(Value::Null);
        Ok(json!({ "key": key, "value": value }))
    } else {
        Ok(json!({ "value": cfg }))
    }
}

fn handle_config_set(params: Option<&Value>) -> Result<Value, ErrorShape> {
    let key = params
        .and_then(|v| v.get("key"))
        .and_then(|v| v.as_str())
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "key is required", None))?;
    let value = params
        .and_then(|v| v.get("value"))
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "value is required", None))?;

    // In the Rust gateway, config is immutable at runtime for now
    // This would require file write + reload
    Ok(json!({
        "ok": true,
        "key": key,
        "value": value.clone()
    }))
}

fn handle_config_apply() -> Result<Value, ErrorShape> {
    // Reload config from disk
    config::clear_cache();
    let _ = config::load_config()
        .map_err(|_| error_shape(ERROR_UNAVAILABLE, "config reload failed", None))?;
    Ok(json!({ "ok": true }))
}

fn handle_config_patch(params: Option<&Value>) -> Result<Value, ErrorShape> {
    let patch = params
        .and_then(|v| v.get("patch"))
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "patch is required", None))?;
    // For now, just acknowledge the patch - actual implementation would merge
    Ok(json!({
        "ok": true,
        "applied": patch.clone()
    }))
}

fn handle_config_schema() -> Result<Value, ErrorShape> {
    // Return JSON schema for config
    Ok(json!({
        "$schema": "http://json-schema.org/draft-07/schema#",
        "type": "object",
        "properties": {
            "gateway": { "type": "object" },
            "agent": { "type": "object" },
            "channels": { "type": "object" }
        }
    }))
}

fn handle_sessions_list(_state: &WsServerState) -> Result<Value, ErrorShape> {
    // Return empty sessions list for now - full implementation would read from state dir
    Ok(json!({ "sessions": [] }))
}

fn handle_sessions_preview(params: Option<&Value>) -> Result<Value, ErrorShape> {
    let session_key = params
        .and_then(|v| v.get("sessionKey"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "sessionKey is required", None))?;
    Ok(json!({
        "sessionKey": session_key,
        "preview": null,
        "messageCount": 0
    }))
}

fn handle_sessions_patch(params: Option<&Value>) -> Result<Value, ErrorShape> {
    let session_key = params
        .and_then(|v| v.get("sessionKey"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "sessionKey is required", None))?;
    Ok(json!({
        "ok": true,
        "sessionKey": session_key
    }))
}

fn handle_sessions_reset(params: Option<&Value>) -> Result<Value, ErrorShape> {
    let session_key = params
        .and_then(|v| v.get("sessionKey"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "sessionKey is required", None))?;
    Ok(json!({
        "ok": true,
        "sessionKey": session_key
    }))
}

fn handle_sessions_delete(params: Option<&Value>) -> Result<Value, ErrorShape> {
    let session_key = params
        .and_then(|v| v.get("sessionKey"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "sessionKey is required", None))?;
    Ok(json!({
        "ok": true,
        "sessionKey": session_key,
        "deleted": true
    }))
}

fn handle_sessions_compact(params: Option<&Value>) -> Result<Value, ErrorShape> {
    let session_key = params
        .and_then(|v| v.get("sessionKey"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "sessionKey is required", None))?;
    Ok(json!({
        "ok": true,
        "sessionKey": session_key,
        "compacted": true
    }))
}

fn handle_channels_status(_state: &WsServerState) -> Result<Value, ErrorShape> {
    Ok(json!({
        "channels": [],
        "ts": now_ms()
    }))
}

fn handle_channels_logout(params: Option<&Value>) -> Result<Value, ErrorShape> {
    let channel = params
        .and_then(|v| v.get("channel"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "channel is required", None))?;
    Ok(json!({
        "ok": true,
        "channel": channel
    }))
}

fn handle_agent(params: Option<&Value>, _conn: &ConnectionContext) -> Result<Value, ErrorShape> {
    let message = params
        .and_then(|v| v.get("message"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "message is required", None))?;
    let idempotency_key = params
        .and_then(|v| v.get("idempotencyKey"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "idempotencyKey is required", None))?;

    // In full implementation, this would queue an agent run
    Ok(json!({
        "runId": idempotency_key,
        "status": "started",
        "message": message
    }))
}

fn handle_agent_identity_get(_state: &WsServerState) -> Result<Value, ErrorShape> {
    // Return agent identity (would read from config)
    Ok(json!({
        "agentId": "default",
        "name": "Clawdbot"
    }))
}

fn handle_agent_wait(params: Option<&Value>) -> Result<Value, ErrorShape> {
    let run_id = params
        .and_then(|v| v.get("runId"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "runId is required", None))?;
    // In full implementation, this would wait for an agent run to complete
    Ok(json!({
        "runId": run_id,
        "status": "completed",
        "result": null
    }))
}

fn handle_chat_history(params: Option<&Value>) -> Result<Value, ErrorShape> {
    let session_key = params
        .and_then(|v| v.get("sessionKey"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "sessionKey is required", None))?;
    Ok(json!({
        "sessionKey": session_key,
        "sessionId": null,
        "messages": [],
        "thinkingLevel": "off"
    }))
}

fn handle_chat_send(
    params: Option<&Value>,
    _conn: &ConnectionContext,
) -> Result<Value, ErrorShape> {
    let session_key = params
        .and_then(|v| v.get("sessionKey"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "sessionKey is required", None))?;
    let message = params
        .and_then(|v| v.get("message"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "message is required", None))?;
    let idempotency_key = params
        .and_then(|v| v.get("idempotencyKey"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "idempotencyKey is required", None))?;

    Ok(json!({
        "runId": idempotency_key,
        "status": "started",
        "sessionKey": session_key,
        "message": message
    }))
}

fn handle_chat_abort(params: Option<&Value>) -> Result<Value, ErrorShape> {
    let session_key = params
        .and_then(|v| v.get("sessionKey"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "sessionKey is required", None))?;
    Ok(json!({
        "ok": true,
        "aborted": true,
        "sessionKey": session_key,
        "runIds": []
    }))
}

fn handle_tts_status() -> Result<Value, ErrorShape> {
    Ok(json!({
        "enabled": false,
        "provider": null
    }))
}

fn handle_tts_providers() -> Result<Value, ErrorShape> {
    Ok(json!({
        "providers": ["system", "elevenlabs", "openai"]
    }))
}

fn handle_tts_enable() -> Result<Value, ErrorShape> {
    Ok(json!({ "ok": true, "enabled": true }))
}

fn handle_tts_disable() -> Result<Value, ErrorShape> {
    Ok(json!({ "ok": true, "enabled": false }))
}

fn handle_tts_convert(params: Option<&Value>) -> Result<Value, ErrorShape> {
    let text = params
        .and_then(|v| v.get("text"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "text is required", None))?;
    // In full implementation, would convert text to speech
    Ok(json!({
        "ok": true,
        "text": text,
        "audio": null
    }))
}

fn handle_tts_set_provider(params: Option<&Value>) -> Result<Value, ErrorShape> {
    let provider = params
        .and_then(|v| v.get("provider"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "provider is required", None))?;
    Ok(json!({
        "ok": true,
        "provider": provider
    }))
}

fn handle_voicewake_get() -> Result<Value, ErrorShape> {
    Ok(json!({
        "enabled": false,
        "keyword": null
    }))
}

fn handle_voicewake_set(params: Option<&Value>) -> Result<Value, ErrorShape> {
    let enabled = params
        .and_then(|v| v.get("enabled"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    Ok(json!({
        "ok": true,
        "enabled": enabled
    }))
}

fn handle_wizard_start(params: Option<&Value>) -> Result<Value, ErrorShape> {
    let wizard_type = params
        .and_then(|v| v.get("type"))
        .and_then(|v| v.as_str())
        .unwrap_or("setup");
    Ok(json!({
        "ok": true,
        "wizardId": Uuid::new_v4().to_string(),
        "type": wizard_type,
        "step": 0
    }))
}

fn handle_wizard_next(params: Option<&Value>) -> Result<Value, ErrorShape> {
    let wizard_id = params
        .and_then(|v| v.get("wizardId"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "wizardId is required", None))?;
    Ok(json!({
        "ok": true,
        "wizardId": wizard_id,
        "step": 1,
        "complete": false
    }))
}

fn handle_wizard_cancel() -> Result<Value, ErrorShape> {
    Ok(json!({ "ok": true, "cancelled": true }))
}

fn handle_wizard_status() -> Result<Value, ErrorShape> {
    Ok(json!({
        "active": false,
        "wizardId": null
    }))
}

fn handle_talk_mode(params: Option<&Value>) -> Result<Value, ErrorShape> {
    let mode = params
        .and_then(|v| v.get("mode"))
        .and_then(|v| v.as_str())
        .unwrap_or("off");
    Ok(json!({
        "ok": true,
        "mode": mode
    }))
}

fn handle_models_list() -> Result<Value, ErrorShape> {
    Ok(json!({
        "models": []
    }))
}

fn handle_agents_list() -> Result<Value, ErrorShape> {
    Ok(json!({
        "agents": [{
            "id": "default",
            "name": "Clawdbot"
        }]
    }))
}

fn handle_skills_status() -> Result<Value, ErrorShape> {
    Ok(json!({
        "skills": [],
        "installed": []
    }))
}

fn handle_skills_bins() -> Result<Value, ErrorShape> {
    Ok(json!({
        "bins": []
    }))
}

fn handle_skills_install(params: Option<&Value>) -> Result<Value, ErrorShape> {
    let skill_id = params
        .and_then(|v| v.get("skillId"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "skillId is required", None))?;
    Ok(json!({
        "ok": true,
        "skillId": skill_id,
        "installed": true
    }))
}

fn handle_skills_update(params: Option<&Value>) -> Result<Value, ErrorShape> {
    let skill_id = params
        .and_then(|v| v.get("skillId"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "skillId is required", None))?;
    Ok(json!({
        "ok": true,
        "skillId": skill_id,
        "updated": true
    }))
}

fn handle_update_run() -> Result<Value, ErrorShape> {
    Ok(json!({
        "ok": true,
        "updateAvailable": false
    }))
}

fn handle_cron_status() -> Result<Value, ErrorShape> {
    Ok(json!({
        "enabled": true,
        "jobs": 0
    }))
}

fn handle_cron_list() -> Result<Value, ErrorShape> {
    Ok(json!({
        "jobs": []
    }))
}

fn handle_cron_add(params: Option<&Value>) -> Result<Value, ErrorShape> {
    let schedule = params
        .and_then(|v| v.get("schedule"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "schedule is required", None))?;
    let command = params
        .and_then(|v| v.get("command"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "command is required", None))?;
    Ok(json!({
        "ok": true,
        "jobId": Uuid::new_v4().to_string(),
        "schedule": schedule,
        "command": command
    }))
}

fn handle_cron_update(params: Option<&Value>) -> Result<Value, ErrorShape> {
    let job_id = params
        .and_then(|v| v.get("jobId"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "jobId is required", None))?;
    Ok(json!({
        "ok": true,
        "jobId": job_id,
        "updated": true
    }))
}

fn handle_cron_remove(params: Option<&Value>) -> Result<Value, ErrorShape> {
    let job_id = params
        .and_then(|v| v.get("jobId"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "jobId is required", None))?;
    Ok(json!({
        "ok": true,
        "jobId": job_id,
        "removed": true
    }))
}

fn handle_cron_run(params: Option<&Value>) -> Result<Value, ErrorShape> {
    let job_id = params
        .and_then(|v| v.get("jobId"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "jobId is required", None))?;
    Ok(json!({
        "ok": true,
        "jobId": job_id,
        "runId": Uuid::new_v4().to_string()
    }))
}

fn handle_cron_runs(params: Option<&Value>) -> Result<Value, ErrorShape> {
    let job_id = params.and_then(|v| v.get("jobId")).and_then(|v| v.as_str());
    Ok(json!({
        "runs": [],
        "jobId": job_id
    }))
}

fn handle_node_pair_request(params: Option<&Value>) -> Result<Value, ErrorShape> {
    let node_id = params
        .and_then(|v| v.get("nodeId"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "nodeId is required", None))?;
    Ok(json!({
        "ok": true,
        "requestId": Uuid::new_v4().to_string(),
        "nodeId": node_id,
        "status": "pending"
    }))
}

fn handle_node_pair_list() -> Result<Value, ErrorShape> {
    Ok(json!({
        "nodes": [],
        "pending": []
    }))
}

fn handle_node_pair_approve(params: Option<&Value>) -> Result<Value, ErrorShape> {
    let request_id = params
        .and_then(|v| v.get("requestId"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "requestId is required", None))?;
    Ok(json!({
        "ok": true,
        "requestId": request_id,
        "approved": true
    }))
}

fn handle_node_pair_reject(params: Option<&Value>) -> Result<Value, ErrorShape> {
    let request_id = params
        .and_then(|v| v.get("requestId"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "requestId is required", None))?;
    Ok(json!({
        "ok": true,
        "requestId": request_id,
        "rejected": true
    }))
}

fn handle_node_pair_verify(params: Option<&Value>) -> Result<Value, ErrorShape> {
    let node_id = params
        .and_then(|v| v.get("nodeId"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "nodeId is required", None))?;
    Ok(json!({
        "ok": true,
        "nodeId": node_id,
        "verified": true
    }))
}

fn handle_node_rename(params: Option<&Value>) -> Result<Value, ErrorShape> {
    let node_id = params
        .and_then(|v| v.get("nodeId"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "nodeId is required", None))?;
    let name = params
        .and_then(|v| v.get("name"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "name is required", None))?;
    Ok(json!({
        "ok": true,
        "nodeId": node_id,
        "name": name
    }))
}

fn handle_node_list() -> Result<Value, ErrorShape> {
    Ok(json!({
        "nodes": []
    }))
}

fn handle_node_describe(params: Option<&Value>) -> Result<Value, ErrorShape> {
    let node_id = params
        .and_then(|v| v.get("nodeId"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "nodeId is required", None))?;
    Ok(json!({
        "nodeId": node_id,
        "description": null
    }))
}

fn handle_node_invoke(params: Option<&Value>, state: &WsServerState) -> Result<Value, ErrorShape> {
    let node_id = params
        .and_then(|v| v.get("nodeId"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "nodeId is required", None))?;
    let command = params
        .and_then(|v| v.get("command").or_else(|| v.get("method")))
        .and_then(|v| v.as_str())
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "command is required", None))?;
    let registry = state.node_registry.lock();
    let node = registry
        .get(node_id)
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "unknown nodeId", None))?;
    if node.commands.is_empty() {
        return Err(error_shape(
            ERROR_FORBIDDEN,
            "node did not declare commands",
            Some(json!({ "nodeId": node_id })),
        ));
    }
    if !node.commands.contains(command) {
        return Err(error_shape(
            ERROR_FORBIDDEN,
            "command not allowlisted",
            Some(json!({ "nodeId": node_id, "command": command })),
        ));
    }
    Ok(json!({
        "ok": true,
        "invokeId": Uuid::new_v4().to_string(),
        "nodeId": node_id,
        "command": command
    }))
}

fn handle_node_invoke_result(params: Option<&Value>) -> Result<Value, ErrorShape> {
    let invoke_id = params
        .and_then(|v| v.get("invokeId"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "invokeId is required", None))?;
    Ok(json!({
        "invokeId": invoke_id,
        "result": null,
        "complete": false
    }))
}

fn handle_node_event(params: Option<&Value>) -> Result<Value, ErrorShape> {
    let node_id = params
        .and_then(|v| v.get("nodeId"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "nodeId is required", None))?;
    let event = params
        .and_then(|v| v.get("event"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "event is required", None))?;
    Ok(json!({
        "ok": true,
        "nodeId": node_id,
        "event": event
    }))
}

fn handle_device_pair_list(state: &WsServerState) -> Result<Value, ErrorShape> {
    let store = state.device_store.lock();
    let devices: Vec<_> = store
        .paired
        .values()
        .map(|d| {
            json!({
                "deviceId": d.device_id,
                "roles": d.roles,
                "scopes": d.scopes
            })
        })
        .collect();
    Ok(json!({ "devices": devices }))
}

fn handle_device_pair_approve(
    params: Option<&Value>,
    state: &WsServerState,
) -> Result<Value, ErrorShape> {
    let device_id = params
        .and_then(|v| v.get("deviceId"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "deviceId is required", None))?;
    let public_key = params
        .and_then(|v| v.get("publicKey"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "publicKey is required", None))?;
    let roles = params
        .and_then(|v| v.get("roles"))
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let scopes = params
        .and_then(|v| v.get("scopes"))
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    let paired_at_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);

    let mut store = state.device_store.lock();
    store.add_paired_device(PairedDevice {
        device_id: device_id.to_string(),
        public_key: public_key.to_string(),
        roles,
        scopes,
        paired_at_ms,
    });
    Ok(json!({
        "ok": true,
        "deviceId": device_id,
        "approved": true
    }))
}

fn handle_device_pair_reject(
    params: Option<&Value>,
    _state: &WsServerState,
) -> Result<Value, ErrorShape> {
    let device_id = params
        .and_then(|v| v.get("deviceId"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "deviceId is required", None))?;
    Ok(json!({
        "ok": true,
        "deviceId": device_id,
        "rejected": true
    }))
}

fn handle_device_token_rotate(
    params: Option<&Value>,
    state: &WsServerState,
) -> Result<Value, ErrorShape> {
    let device_id = params
        .and_then(|v| v.get("deviceId"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "deviceId is required", None))?;

    // Remove existing tokens for this device
    let mut store = state.device_store.lock();
    store.tokens.retain(|_, t| t.device_id != device_id);

    Ok(json!({
        "ok": true,
        "deviceId": device_id,
        "rotated": true
    }))
}

fn handle_device_token_revoke(
    params: Option<&Value>,
    state: &WsServerState,
) -> Result<Value, ErrorShape> {
    let device_id = params
        .and_then(|v| v.get("deviceId"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "deviceId is required", None))?;

    let mut store = state.device_store.lock();
    store.tokens.retain(|_, t| t.device_id != device_id);
    store.paired.remove(device_id);

    Ok(json!({
        "ok": true,
        "deviceId": device_id,
        "revoked": true
    }))
}

fn handle_exec_approvals_get() -> Result<Value, ErrorShape> {
    Ok(json!({
        "approvals": []
    }))
}

fn handle_exec_approvals_set(params: Option<&Value>) -> Result<Value, ErrorShape> {
    let approvals = params
        .and_then(|v| v.get("approvals"))
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "approvals is required", None))?;
    Ok(json!({
        "ok": true,
        "approvals": approvals.clone()
    }))
}

fn handle_exec_approvals_node_get(params: Option<&Value>) -> Result<Value, ErrorShape> {
    let node_id = params
        .and_then(|v| v.get("nodeId"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "nodeId is required", None))?;
    Ok(json!({
        "nodeId": node_id,
        "approvals": []
    }))
}

fn handle_exec_approvals_node_set(params: Option<&Value>) -> Result<Value, ErrorShape> {
    let node_id = params
        .and_then(|v| v.get("nodeId"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "nodeId is required", None))?;
    let approvals = params
        .and_then(|v| v.get("approvals"))
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "approvals is required", None))?;
    Ok(json!({
        "ok": true,
        "nodeId": node_id,
        "approvals": approvals.clone()
    }))
}

fn handle_exec_approval_request(params: Option<&Value>) -> Result<Value, ErrorShape> {
    let command = params
        .and_then(|v| v.get("command"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "command is required", None))?;
    Ok(json!({
        "requestId": Uuid::new_v4().to_string(),
        "command": command,
        "status": "pending"
    }))
}

fn handle_exec_approval_resolve(params: Option<&Value>) -> Result<Value, ErrorShape> {
    let request_id = params
        .and_then(|v| v.get("requestId"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "requestId is required", None))?;
    let approved = params
        .and_then(|v| v.get("approved"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    Ok(json!({
        "ok": true,
        "requestId": request_id,
        "approved": approved
    }))
}

fn handle_usage_status() -> Result<Value, ErrorShape> {
    Ok(json!({
        "enabled": true,
        "tracking": true
    }))
}

fn handle_usage_cost(params: Option<&Value>) -> Result<Value, ErrorShape> {
    let session_key = params
        .and_then(|v| v.get("sessionKey"))
        .and_then(|v| v.as_str());
    Ok(json!({
        "sessionKey": session_key,
        "inputTokens": 0,
        "outputTokens": 0,
        "totalCost": 0.0
    }))
}

fn handle_logs_tail(params: Option<&Value>) -> Result<Value, ErrorShape> {
    let lines = params
        .and_then(|v| v.get("lines"))
        .and_then(|v| v.as_i64())
        .unwrap_or(100);
    Ok(json!({
        "lines": [],
        "requested": lines
    }))
}

fn handle_last_heartbeat() -> Result<Value, ErrorShape> {
    Ok(json!({
        "ts": now_ms(),
        "lastHeartbeat": null
    }))
}

fn handle_set_heartbeats(params: Option<&Value>) -> Result<Value, ErrorShape> {
    let enabled = params
        .and_then(|v| v.get("enabled"))
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    Ok(json!({
        "ok": true,
        "enabled": enabled
    }))
}

fn handle_wake(params: Option<&Value>) -> Result<Value, ErrorShape> {
    let target = params
        .and_then(|v| v.get("target"))
        .and_then(|v| v.as_str());
    Ok(json!({
        "ok": true,
        "target": target
    }))
}

fn handle_send(params: Option<&Value>, _conn: &ConnectionContext) -> Result<Value, ErrorShape> {
    let to = params
        .and_then(|v| v.get("to"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "to is required", None))?;
    let message = params
        .and_then(|v| v.get("message"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "message is required", None))?;
    let idempotency_key = params
        .and_then(|v| v.get("idempotencyKey"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "idempotencyKey is required", None))?;

    Ok(json!({
        "ok": true,
        "messageId": idempotency_key,
        "to": to,
        "message": message
    }))
}

fn handle_system_presence(params: Option<&Value>) -> Result<Value, ErrorShape> {
    let presence = params
        .and_then(|v| v.get("presence"))
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "presence is required", None))?;
    Ok(json!({
        "ok": true,
        "presence": presence.clone()
    }))
}

fn handle_system_event(params: Option<&Value>) -> Result<Value, ErrorShape> {
    let event = params
        .and_then(|v| v.get("event"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "event is required", None))?;
    Ok(json!({
        "ok": true,
        "event": event
    }))
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
    role: &str,
    scopes: &[String],
    is_local: bool,
) -> Result<(), ErrorShape> {
    let mut store = state.device_store.lock();
    if let Some(paired) = store.paired.get(&device.id) {
        if paired.public_key != device.public_key {
            return Err(error_shape(
                ERROR_INVALID_REQUEST,
                "device identity mismatch",
                None,
            ));
        }
        if !paired.roles.is_empty() && !paired.roles.contains(&role.to_string()) {
            return Err(error_shape(ERROR_NOT_PAIRED, "pairing required", None));
        }
        if !paired.scopes.is_empty() {
            for scope in scopes {
                if !paired.scopes.contains(scope) {
                    return Err(error_shape(ERROR_NOT_PAIRED, "pairing required", None));
                }
            }
        }
        return Ok(());
    }
    if is_local {
        let paired_at_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        store.add_paired_device(PairedDevice {
            device_id: device.id.clone(),
            public_key: device.public_key.clone(),
            roles: vec![role.to_string()],
            scopes: scopes.to_vec(),
            paired_at_ms,
        });
        return Ok(());
    }
    Err(error_shape(ERROR_NOT_PAIRED, "pairing required", None))
}

fn ensure_device_token(
    state: &WsServerState,
    device_id: &str,
    role: &str,
    scopes: &[String],
) -> DeviceToken {
    let key = device_token_key(device_id, role, scopes);
    let mut store = state.device_store.lock();
    if let Some(existing) = store.tokens.get(&key) {
        return existing.clone();
    }
    let token = DeviceToken {
        token: Uuid::new_v4().to_string(),
        device_id: device_id.to_string(),
        role: role.to_string(),
        scopes: scopes.to_vec(),
        issued_at_ms: now_ms(),
    };
    store.add_token(key, token.clone());
    token
}

fn verify_device_token(
    state: &WsServerState,
    device_id: &str,
    token: &str,
    role: &str,
    scopes: &[String],
) -> bool {
    let store = state.device_store.lock();
    let key = device_token_key(device_id, role, scopes);
    store
        .tokens
        .get(&key)
        .map(|entry| entry.token == token)
        .unwrap_or(false)
}

fn device_token_key(device_id: &str, role: &str, scopes: &[String]) -> String {
    let mut scopes_sorted = scopes.to_vec();
    scopes_sorted.sort();
    format!("{}|{}|{}", device_id, role, scopes_sorted.join(","))
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
    std::env::var("CLAWDBOT_VERSION")
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
        Message::Text(text) => Ok(InboundText::Text(text)),
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
    tx.send(Message::Text(text)).map_err(|_| ())
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
        code: code.into(),
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

fn resolve_state_dir() -> PathBuf {
    if let Ok(dir) = env::var("CLAWDBOT_STATE_DIR") {
        return PathBuf::from(dir);
    }
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".clawdbot")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_shape() {
        let err = error_shape(ERROR_INVALID_REQUEST, "test error", None);
        assert_eq!(err.code, "INVALID_REQUEST");
        assert_eq!(err.message, "test error");
        assert!(!err.retryable);

        let err2 = error_shape(ERROR_UNAVAILABLE, "temp error", Some(json!({"foo": "bar"})));
        assert_eq!(err2.code, "UNAVAILABLE");
        assert!(err2.retryable);
        assert!(err2.details.is_some());
    }

    #[test]
    fn test_get_value_at_path() {
        let root = json!({
            "gateway": {
                "port": 8080,
                "auth": {
                    "mode": "token"
                }
            }
        });

        assert_eq!(get_value_at_path(&root, "gateway.port"), Some(json!(8080)));
        assert_eq!(
            get_value_at_path(&root, "gateway.auth.mode"),
            Some(json!("token"))
        );
        assert_eq!(get_value_at_path(&root, "gateway.missing"), None);
        assert_eq!(get_value_at_path(&root, "unknown"), None);
    }

    #[test]
    fn test_handle_node_invoke_enforces_allowlist() {
        let state = WsServerState::new(WsServerConfig::default());
        let mut registry = state.node_registry.lock();
        registry.register(
            "conn-1",
            "node-1".to_string(),
            HashSet::from(["system.run".to_string()]),
        );
        drop(registry);

        let ok_params = json!({ "nodeId": "node-1", "command": "system.run" });
        assert!(handle_node_invoke(Some(&ok_params), &state).is_ok());

        let bad_params = json!({ "nodeId": "node-1", "command": "sms.send" });
        let err = handle_node_invoke(Some(&bad_params), &state).unwrap_err();
        assert_eq!(err.code, ERROR_FORBIDDEN);
    }

    #[test]
    fn test_normalize_platform_id() {
        assert_eq!(normalize_platform_id(Some("Darwin"), None), "macos");
        assert_eq!(normalize_platform_id(None, Some("iPhone13,3")), "ios");
        assert_eq!(normalize_platform_id(Some("android"), None), "android");
        assert_eq!(normalize_platform_id(None, None), "unknown");
    }

    #[test]
    fn test_resolve_node_command_allowlist() {
        let allow = vec!["custom.command".to_string()];
        let deny = vec!["canvas.present".to_string()];
        let allowlist = resolve_node_command_allowlist(&allow, &deny, Some("darwin"), None);
        assert!(allowlist.contains("system.run"));
        assert!(!allowlist.contains("sms.send"));
        assert!(allowlist.contains("custom.command"));
        assert!(!allowlist.contains("canvas.present"));
    }

    // ============== Method Authorization Tests ==============

    fn make_conn(role: &str) -> ConnectionContext {
        make_conn_with_scopes(role, vec![])
    }

    fn make_conn_with_scopes(role: &str, scopes: Vec<String>) -> ConnectionContext {
        ConnectionContext {
            conn_id: "test-conn".to_string(),
            role: role.to_string(),
            scopes,
            client: ClientInfo {
                id: "test-client".to_string(),
                version: "1.0".to_string(),
                platform: "test".to_string(),
                mode: "test".to_string(),
                display_name: None,
                device_family: None,
                model_identifier: None,
                instance_id: None,
            },
            device_id: None,
        }
    }

    #[test]
    fn test_role_satisfies() {
        // Any role satisfies read
        assert!(role_satisfies("read", "read"));
        assert!(role_satisfies("write", "read"));
        assert!(role_satisfies("admin", "read"));
        assert!(role_satisfies("operator", "read"));

        // Only write, admin, operator satisfy write
        assert!(!role_satisfies("read", "write"));
        assert!(role_satisfies("write", "write"));
        assert!(role_satisfies("admin", "write"));
        assert!(role_satisfies("operator", "write"));

        // Only admin satisfies admin
        assert!(!role_satisfies("read", "admin"));
        assert!(!role_satisfies("write", "admin"));
        assert!(role_satisfies("admin", "admin"));
    }

    #[test]
    fn test_method_authorization_read_methods() {
        // Read-only methods should be allowed by any role
        let read_methods = [
            "health",
            "status",
            "config.get",
            "sessions.list",
            "channels.status",
        ];

        for method in read_methods {
            for role in ["read", "write", "admin"] {
                let conn = make_conn(role);
                let result = check_method_authorization(method, &conn);
                assert!(
                    result.is_ok(),
                    "Method '{}' should be allowed for role '{}'",
                    method,
                    role
                );
            }
        }
    }

    #[test]
    fn test_method_authorization_write_methods() {
        // Write methods should not be allowed by read role
        let write_methods = ["config.set", "agent", "chat.send", "cron.add"];

        for method in write_methods {
            let read_conn = make_conn("read");
            let result = check_method_authorization(method, &read_conn);
            assert!(
                result.is_err(),
                "Method '{}' should NOT be allowed for role 'read'",
                method
            );

            // But allowed for write and admin
            for role in ["write", "admin"] {
                let conn = make_conn(role);
                let result = check_method_authorization(method, &conn);
                assert!(
                    result.is_ok(),
                    "Method '{}' should be allowed for role '{}'",
                    method,
                    role
                );
            }
        }
    }

    #[test]
    fn test_method_authorization_admin_methods() {
        // Admin methods should only be allowed by admin role
        let admin_methods = [
            "device.pair.approve",
            "device.token.rotate",
            "exec.approvals.set",
            "node.pair.approve",
        ];

        for method in admin_methods {
            // Not allowed for read or write
            for role in ["read", "write"] {
                let conn = make_conn(role);
                let result = check_method_authorization(method, &conn);
                assert!(
                    result.is_err(),
                    "Method '{}' should NOT be allowed for role '{}'",
                    method,
                    role
                );
            }

            // Allowed for admin
            let admin_conn = make_conn("admin");
            let result = check_method_authorization(method, &admin_conn);
            assert!(
                result.is_ok(),
                "Method '{}' should be allowed for role 'admin'",
                method
            );
        }
    }

    #[test]
    fn test_method_authorization_unknown_method_requires_admin() {
        // Unknown methods should require admin (fail secure)
        let conn = make_conn("write");
        let result = check_method_authorization("unknown.method.xyz", &conn);
        assert!(result.is_err(), "Unknown method should require admin role");

        let admin_conn = make_conn("admin");
        let result = check_method_authorization("unknown.method.xyz", &admin_conn);
        assert!(result.is_ok(), "Unknown method should be allowed for admin");
    }

    #[test]
    fn test_method_authorization_error_contains_details() {
        let conn = make_conn("read");
        let result = check_method_authorization("config.set", &conn);

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code, "FORBIDDEN");
        assert!(err.message.contains("config.set"));
        assert!(err.message.contains("write"));
        assert!(err.message.contains("read"));
    }

    // ============== Node Role Allowlist Tests ==============

    #[test]
    fn test_node_role_only_allows_specific_methods() {
        let conn = make_conn("node");

        // Allowed methods for node role
        for method in NODE_ONLY_METHODS {
            let result = check_method_authorization(method, &conn);
            assert!(
                result.is_ok(),
                "Method '{}' should be allowed for node role",
                method
            );
        }

        // Read methods should NOT be allowed for node role
        let blocked_methods = ["health", "status", "config.get", "sessions.list"];
        for method in blocked_methods {
            let result = check_method_authorization(method, &conn);
            assert!(
                result.is_err(),
                "Method '{}' should NOT be allowed for node role",
                method
            );
        }
    }

    // ============== Operator Scope Tests ==============

    #[test]
    fn test_operator_without_scopes_cannot_write() {
        // Operator with no scopes should not be able to call write methods
        let conn = make_conn_with_scopes("operator", vec![]);

        let result = check_method_authorization("config.set", &conn);
        assert!(
            result.is_err(),
            "Operator without scopes should not be able to write"
        );
    }

    #[test]
    fn test_operator_with_write_scope_can_write() {
        let conn = make_conn_with_scopes("operator", vec!["operator.write".to_string()]);

        // config.set requires operator.admin (it's in OPERATOR_ADMIN_REQUIRED_METHODS)
        let result = check_method_authorization("config.set", &conn);
        assert!(
            result.is_err(),
            "config.set requires operator.admin, not just write scope"
        );

        // sessions.patch also requires operator.admin
        let result = check_method_authorization("sessions.patch", &conn);
        assert!(
            result.is_err(),
            "sessions.patch requires operator.admin, not just write scope"
        );

        // agent/chat are write-level methods that DO work with operator.write
        let result = check_method_authorization("agent", &conn);
        assert!(
            result.is_ok(),
            "agent is a write-level method that works with operator.write"
        );

        let result = check_method_authorization("chat.send", &conn);
        assert!(
            result.is_ok(),
            "chat.send is a write-level method that works with operator.write"
        );
    }

    #[test]
    fn test_operator_with_read_scope_can_read() {
        let conn = make_conn_with_scopes("operator", vec!["operator.read".to_string()]);

        // Read methods should work
        let result = check_method_authorization("health", &conn);
        assert!(
            result.is_ok(),
            "Operator with read scope should be able to read"
        );

        // Write methods should not work
        let result = check_method_authorization("config.set", &conn);
        assert!(
            result.is_err(),
            "Operator with only read scope should not be able to write"
        );
    }

    #[test]
    fn test_operator_needs_pairing_scope_for_pairing() {
        // Per Node.js gateway: operator.pairing allows pairing methods WITHOUT needing operator.admin
        // This enables granular access control where operators can be granted just pairing rights

        // Operator with admin scope - can pair (admin covers all)
        let conn = make_conn_with_scopes("operator", vec!["operator.admin".to_string()]);
        let result = check_method_authorization("device.pair.approve", &conn);
        assert!(
            result.is_ok(),
            "Operator with admin scope should be able to pair"
        );

        // Operator with only write scope - cannot pair (needs pairing or admin)
        let conn_write = make_conn_with_scopes("operator", vec!["operator.write".to_string()]);
        let result = check_method_authorization("device.pair.approve", &conn_write);
        assert!(
            result.is_err(),
            "Operator with only write scope should not be able to pair"
        );

        // Operator with just pairing scope - CAN pair (per Node.js gateway)
        let conn_pairing = make_conn_with_scopes("operator", vec!["operator.pairing".to_string()]);
        let result = check_method_authorization("device.pair.approve", &conn_pairing);
        assert!(
            result.is_ok(),
            "Operator with pairing scope should be able to pair (Node.js parity)"
        );

        // Operator with read scope only - cannot pair
        let conn_read = make_conn_with_scopes("operator", vec!["operator.read".to_string()]);
        let result = check_method_authorization("device.pair.approve", &conn_read);
        assert!(
            result.is_err(),
            "Operator with only read scope should not be able to pair"
        );
    }

    #[test]
    fn test_operator_needs_approvals_scope_for_exec_approvals() {
        // Per Node.js gateway: operator.approvals allows exec approval methods WITHOUT needing operator.admin

        let conn = make_conn_with_scopes("operator", vec!["operator.write".to_string()]);
        let result = check_method_authorization("exec.approvals.set", &conn);
        assert!(
            result.is_err(),
            "Operator without approvals scope should not set approvals"
        );

        // Admin scope covers all
        let conn_admin = make_conn_with_scopes("operator", vec!["operator.admin".to_string()]);
        let result = check_method_authorization("exec.approvals.set", &conn_admin);
        assert!(
            result.is_ok(),
            "Operator with admin scope should set approvals"
        );

        // Approvals scope alone allows exec approval methods (per Node.js gateway)
        let conn_approvals =
            make_conn_with_scopes("operator", vec!["operator.approvals".to_string()]);
        let result = check_method_authorization("exec.approvals.set", &conn_approvals);
        assert!(
            result.is_ok(),
            "Operator with approvals scope should set approvals (Node.js parity)"
        );
    }

    #[test]
    fn test_operator_wildcard_scope() {
        let conn = make_conn_with_scopes("operator", vec!["operator.*".to_string()]);

        // Wildcard should cover all operations (covers operator.admin, operator.pairing, etc.)
        assert!(
            check_method_authorization("config.set", &conn).is_ok(),
            "wildcard covers operator.admin for config.set"
        );
        assert!(
            check_method_authorization("device.pair.approve", &conn).is_ok(),
            "wildcard covers operator.pairing"
        );
        assert!(
            check_method_authorization("exec.approvals.set", &conn).is_ok(),
            "wildcard covers operator.approvals"
        );
        assert!(
            check_method_authorization("agent", &conn).is_ok(),
            "wildcard covers operator.write"
        );
        assert!(
            check_method_authorization("health", &conn).is_ok(),
            "wildcard covers operator.read"
        );
    }

    #[test]
    fn test_scope_satisfies() {
        // Exact match
        assert!(scope_satisfies(
            &vec!["operator.write".to_string()],
            "operator.write"
        ));
        assert!(!scope_satisfies(
            &vec!["operator.read".to_string()],
            "operator.write"
        ));

        // Wildcard
        assert!(scope_satisfies(
            &vec!["operator.*".to_string()],
            "operator.pairing"
        ));
        assert!(scope_satisfies(
            &vec!["operator.*".to_string()],
            "operator.admin"
        ));

        // Admin covers all
        assert!(scope_satisfies(
            &vec!["operator.admin".to_string()],
            "operator.pairing"
        ));
        assert!(scope_satisfies(
            &vec!["operator.admin".to_string()],
            "operator.approvals"
        ));

        // Write covers read
        assert!(scope_satisfies(
            &vec!["operator.write".to_string()],
            "operator.read"
        ));
    }

    // ============== Device Store Bounds Tests ==============

    #[test]
    fn test_device_store_paired_device_limit() {
        let mut store = DeviceStore::default();

        // Fill up to limit
        for i in 0..MAX_PAIRED_DEVICES {
            store.add_paired_device(PairedDevice {
                device_id: format!("device-{}", i),
                public_key: format!("key-{}", i),
                roles: vec!["write".to_string()],
                scopes: vec![],
                paired_at_ms: i as u64,
            });
        }
        assert_eq!(store.paired.len(), MAX_PAIRED_DEVICES);

        // Add one more - should evict oldest (device-0)
        store.add_paired_device(PairedDevice {
            device_id: "device-new".to_string(),
            public_key: "key-new".to_string(),
            roles: vec!["write".to_string()],
            scopes: vec![],
            paired_at_ms: (MAX_PAIRED_DEVICES + 1) as u64,
        });

        assert_eq!(store.paired.len(), MAX_PAIRED_DEVICES);
        assert!(
            !store.paired.contains_key("device-0"),
            "Oldest device should be evicted"
        );
        assert!(
            store.paired.contains_key("device-new"),
            "New device should be added"
        );
    }

    #[test]
    fn test_device_store_token_limit() {
        let mut store = DeviceStore::default();

        // Fill up to limit
        for i in 0..MAX_DEVICE_TOKENS {
            let key = format!("token-key-{}", i);
            store.add_token(
                key,
                DeviceToken {
                    token: format!("token-{}", i),
                    device_id: format!("device-{}", i % 10),
                    role: "write".to_string(),
                    scopes: vec![],
                    issued_at_ms: i as u64,
                },
            );
        }
        assert_eq!(store.tokens.len(), MAX_DEVICE_TOKENS);

        // Add one more - should evict oldest
        store.add_token(
            "token-key-new".to_string(),
            DeviceToken {
                token: "token-new".to_string(),
                device_id: "device-new".to_string(),
                role: "write".to_string(),
                scopes: vec![],
                issued_at_ms: (MAX_DEVICE_TOKENS + 1) as u64,
            },
        );

        assert_eq!(store.tokens.len(), MAX_DEVICE_TOKENS);
        assert!(
            !store.tokens.contains_key("token-key-0"),
            "Oldest token should be evicted"
        );
        assert!(
            store.tokens.contains_key("token-key-new"),
            "New token should be added"
        );
    }

    #[test]
    fn test_device_store_update_existing_device_no_eviction() {
        let mut store = DeviceStore::default();

        // Add a device
        store.add_paired_device(PairedDevice {
            device_id: "device-1".to_string(),
            public_key: "key-1".to_string(),
            roles: vec!["read".to_string()],
            scopes: vec![],
            paired_at_ms: 100,
        });
        assert_eq!(store.paired.len(), 1);

        // Update the same device
        store.add_paired_device(PairedDevice {
            device_id: "device-1".to_string(),
            public_key: "key-1-updated".to_string(),
            roles: vec!["write".to_string()],
            scopes: vec![],
            paired_at_ms: 200,
        });

        // Should still be 1 device, but updated
        assert_eq!(store.paired.len(), 1);
        assert_eq!(
            store.paired.get("device-1").unwrap().public_key,
            "key-1-updated"
        );
        assert_eq!(
            store.paired.get("device-1").unwrap().roles,
            vec!["write".to_string()]
        );
    }

    #[test]
    fn test_device_store_evict_device_also_removes_tokens() {
        let mut store = DeviceStore::default();

        // Add a device
        store.add_paired_device(PairedDevice {
            device_id: "device-old".to_string(),
            public_key: "key-old".to_string(),
            roles: vec!["write".to_string()],
            scopes: vec![],
            paired_at_ms: 0, // Oldest
        });

        // Add tokens for this device
        store.add_token(
            "token-key-1".to_string(),
            DeviceToken {
                token: "token-1".to_string(),
                device_id: "device-old".to_string(),
                role: "write".to_string(),
                scopes: vec![],
                issued_at_ms: 100,
            },
        );
        store.add_token(
            "token-key-2".to_string(),
            DeviceToken {
                token: "token-2".to_string(),
                device_id: "device-old".to_string(),
                role: "admin".to_string(),
                scopes: vec![],
                issued_at_ms: 101,
            },
        );

        // Add another device's token
        store.add_token(
            "token-key-3".to_string(),
            DeviceToken {
                token: "token-3".to_string(),
                device_id: "device-other".to_string(),
                role: "write".to_string(),
                scopes: vec![],
                issued_at_ms: 102,
            },
        );

        assert_eq!(store.tokens.len(), 3);

        // Fill up to limit with newer devices
        for i in 1..MAX_PAIRED_DEVICES {
            store.add_paired_device(PairedDevice {
                device_id: format!("device-{}", i),
                public_key: format!("key-{}", i),
                roles: vec!["write".to_string()],
                scopes: vec![],
                paired_at_ms: i as u64 + 1, // Newer than device-old
            });
        }

        // Add one more to trigger eviction of device-old
        store.add_paired_device(PairedDevice {
            device_id: "device-new".to_string(),
            public_key: "key-new".to_string(),
            roles: vec!["write".to_string()],
            scopes: vec![],
            paired_at_ms: 1000,
        });

        // device-old should be evicted along with its tokens
        assert!(!store.paired.contains_key("device-old"));
        assert!(
            !store.tokens.contains_key("token-key-1"),
            "Token for evicted device should be removed"
        );
        assert!(
            !store.tokens.contains_key("token-key-2"),
            "Token for evicted device should be removed"
        );
        assert!(
            store.tokens.contains_key("token-key-3"),
            "Token for other device should remain"
        );
    }
}
