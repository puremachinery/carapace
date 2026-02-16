//! Remote gateway connection support
//!
//! Allows a carapace node to connect to a remote carapace gateway that it
//! cannot reach directly. Two transport modes are supported:
//!
//! - **Direct WebSocket** -- outbound WS connection with TLS certificate
//!   fingerprint-based trust-on-first-use (TOFU) verification.
//! - **SSH tunnel** -- SSH tunnel transport for NAT traversal scenarios.
//!
//! Configuration lives under `gateway.remote` in the JSON5 config file.

use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::Write as IoWrite;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::agent::sandbox::{
    default_ssh_tunnel_sandbox_config, ensure_sandbox_supported, spawn_sandboxed_tokio_command,
    SandboxedTokioChild,
};

type WsStream = WebSocketStream<MaybeTlsStream<TcpStream>>;

// ============================================================================
// Constants
// ============================================================================

/// Maximum number of registered remote gateways.
pub const MAX_GATEWAYS: usize = 50;

/// Default reconnect interval in milliseconds (30 seconds).
pub const DEFAULT_RECONNECT_INTERVAL_MS: u64 = 30_000;

/// Default maximum reconnect attempts before giving up.
pub const DEFAULT_MAX_RECONNECT_ATTEMPTS: u32 = 10;

/// Protocol version used in the gateway handshake.
pub const PROTOCOL_VERSION: u32 = 3;

// ============================================================================
// Error types
// ============================================================================

/// Errors that can occur during remote gateway operations.
#[derive(Debug, Clone, PartialEq)]
pub enum GatewayError {
    /// TLS certificate fingerprint mismatch (TOFU violation).
    FingerprintMismatch { expected: String, actual: String },
    /// WebSocket or network connection failed.
    ConnectionFailed(String),
    /// Authentication with the remote gateway failed.
    AuthFailed(String),
    /// SSH tunnel setup or operation failed.
    TunnelFailed(String),
    /// File I/O error.
    IoError(String),
    /// Configuration parsing or validation error.
    ConfigError(String),
    /// The maximum number of gateways has been reached.
    MaxGatewaysExceeded,
    /// The requested gateway was not found.
    NotFound,
    /// mTLS certificate verification failed.
    MtlsCertError(String),
}

impl std::fmt::Display for GatewayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FingerprintMismatch { expected, actual } => write!(
                f,
                "TLS fingerprint mismatch: expected {}, got {}",
                expected, actual
            ),
            Self::ConnectionFailed(msg) => write!(f, "connection failed: {}", msg),
            Self::AuthFailed(msg) => write!(f, "authentication failed: {}", msg),
            Self::TunnelFailed(msg) => write!(f, "tunnel failed: {}", msg),
            Self::IoError(msg) => write!(f, "I/O error: {}", msg),
            Self::ConfigError(msg) => write!(f, "config error: {}", msg),
            Self::MaxGatewaysExceeded => write!(f, "maximum number of gateways exceeded"),
            Self::NotFound => write!(f, "gateway not found"),
            Self::MtlsCertError(msg) => write!(f, "mTLS certificate error: {}", msg),
        }
    }
}

impl std::error::Error for GatewayError {}

// ============================================================================
// Transport types
// ============================================================================

/// Transport mode for connecting to a remote gateway.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum GatewayTransport {
    /// Direct outbound WebSocket connection.
    #[default]
    DirectWs,
    /// SSH tunnel with port forwarding.
    SshTunnel {
        ssh_host: String,
        ssh_port: u16,
        ssh_user: String,
        remote_port: u16,
    },
}

// ============================================================================
// Gateway entry
// ============================================================================

/// A known remote gateway entry stored in the registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GatewayEntry {
    /// Unique identifier (UUID).
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// WebSocket URL, e.g. `wss://host:port/ws`.
    pub url: String,
    /// SHA-256 TLS certificate fingerprint for TOFU verification.
    /// `None` means the fingerprint has not been pinned yet (first connect).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    /// Transport mode.
    #[serde(default)]
    pub transport: GatewayTransport,
    /// Whether to automatically connect on startup.
    #[serde(default)]
    pub auto_connect: bool,
    /// Timestamp when this entry was created (Unix ms).
    pub created_at_ms: u64,
    /// Timestamp of the last successful connection (Unix ms).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_connected_ms: Option<u64>,
}

impl GatewayEntry {
    /// Create a new gateway entry with a generated UUID.
    pub fn new(name: String, url: String) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            name,
            url,
            fingerprint: None,
            transport: GatewayTransport::DirectWs,
            auto_connect: false,
            created_at_ms: now_ms(),
            last_connected_ms: None,
        }
    }
}

// ============================================================================
// Connection state
// ============================================================================

/// Runtime state of a gateway connection.
#[derive(Debug, Clone, PartialEq, Default)]
pub enum GatewayConnectionState {
    /// Not connected.
    #[default]
    Disconnected,
    /// Connection attempt in progress.
    Connecting,
    /// Successfully connected since the given timestamp (Unix ms).
    Connected { since_ms: u64 },
    /// Connection failed with an error; optional retry timestamp.
    Failed {
        error: String,
        retry_at_ms: Option<u64>,
    },
}

// ============================================================================
// Gateway connection handle
// ============================================================================

/// Handle representing an active connection to a remote gateway.
///
/// Holds the WebSocket stream halves behind async mutexes so that reads
/// and writes can proceed independently.
pub struct GatewayConnection {
    /// ID of the gateway this connection belongs to.
    pub gateway_id: String,
    /// Current state.
    pub state: GatewayConnectionState,
    /// Protocol version negotiated with the remote side.
    pub protocol_version: u32,
    /// WebSocket write half (`None` if stub / disconnected).
    ws_writer: Option<Mutex<SplitSink<WsStream, tokio_tungstenite::tungstenite::Message>>>,
    /// WebSocket read half (`None` if stub / disconnected).
    ws_reader: Option<Mutex<SplitStream<WsStream>>>,
}

impl std::fmt::Debug for GatewayConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GatewayConnection")
            .field("gateway_id", &self.gateway_id)
            .field("state", &self.state)
            .field("protocol_version", &self.protocol_version)
            .field("has_ws_writer", &self.ws_writer.is_some())
            .field("has_ws_reader", &self.ws_reader.is_some())
            .finish()
    }
}

impl GatewayConnection {
    /// Create a new connection handle in the `Connected` state (without
    /// a real WebSocket stream — for testing / stub use).
    pub fn new_connected(gateway_id: String) -> Self {
        Self {
            gateway_id,
            state: GatewayConnectionState::Connected { since_ms: now_ms() },
            protocol_version: PROTOCOL_VERSION,
            ws_writer: None,
            ws_reader: None,
        }
    }

    /// Create a connection handle backed by a real WebSocket stream.
    fn new_with_stream(gateway_id: String, stream: WsStream) -> Self {
        let (writer, reader) = stream.split();
        Self {
            gateway_id,
            state: GatewayConnectionState::Connected { since_ms: now_ms() },
            protocol_version: PROTOCOL_VERSION,
            ws_writer: Some(Mutex::new(writer)),
            ws_reader: Some(Mutex::new(reader)),
        }
    }

    /// Check whether the connection is currently in the `Connected` state.
    pub fn is_connected(&self) -> bool {
        matches!(self.state, GatewayConnectionState::Connected { .. })
    }

    /// Whether this connection has a real WebSocket stream attached.
    pub fn has_stream(&self) -> bool {
        self.ws_writer.is_some()
    }

    /// Send a JSON-RPC message over the WebSocket.
    pub async fn send_message(&self, method: &str, params: &Value) -> Result<(), GatewayError> {
        let writer = self
            .ws_writer
            .as_ref()
            .ok_or_else(|| GatewayError::ConnectionFailed("no WebSocket stream".into()))?;

        let msg = serde_json::json!({
            "jsonrpc": "2.0",
            "id": Uuid::new_v4().to_string(),
            "method": method,
            "params": params,
        });
        let text = serde_json::to_string(&msg)
            .map_err(|e| GatewayError::ConnectionFailed(e.to_string()))?;

        writer
            .lock()
            .await
            .send(tokio_tungstenite::tungstenite::Message::Text(text.into()))
            .await
            .map_err(|e| GatewayError::ConnectionFailed(e.to_string()))
    }

    /// Receive the next message from the WebSocket.
    ///
    /// Returns `None` when the stream is closed or no reader is available.
    pub async fn recv_message(
        &self,
    ) -> Option<Result<tokio_tungstenite::tungstenite::Message, GatewayError>> {
        let reader = self.ws_reader.as_ref()?;
        let result = reader.lock().await.next().await?;
        Some(result.map_err(|e| GatewayError::ConnectionFailed(e.to_string())))
    }
}

/// Result of establishing a gateway connection.
#[derive(Debug)]
pub struct GatewayConnectResult {
    pub conn: GatewayConnection,
    pub peer_node_id: Option<String>,
    pub tofu_fingerprint: Option<String>,
    pub tunnel: Option<SshTunnel>,
}

// ============================================================================
// Gateway registry
// ============================================================================

/// Persistent store for gateway entries (serialised to disk).
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GatewayStore {
    /// Schema version for future migrations.
    pub version: u32,
    /// Registered gateway entries.
    #[serde(default)]
    pub gateways: Vec<GatewayEntry>,
}

impl GatewayStore {
    const VERSION: u32 = 1;
}

/// Thread-safe registry of remote gateways with persistence.
pub struct GatewayRegistry {
    /// In-memory gateway entries.
    gateways: RwLock<Vec<GatewayEntry>>,
    /// Runtime connection states keyed by gateway ID.
    connections: RwLock<HashMap<String, GatewayConnectionState>>,
    /// Path to the persisted `gateways.json` file.
    state_path: PathBuf,
}

impl std::fmt::Debug for GatewayRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GatewayRegistry")
            .field("state_path", &self.state_path)
            .finish()
    }
}

impl GatewayRegistry {
    /// Create a new registry. Persisted data is stored in `{state_dir}/gateways.json`.
    pub fn new(state_dir: PathBuf) -> Self {
        let state_path = state_dir.join("gateways.json");
        Self {
            gateways: RwLock::new(Vec::new()),
            connections: RwLock::new(HashMap::new()),
            state_path,
        }
    }

    /// Create an in-memory-only registry (for testing).
    pub fn in_memory() -> Self {
        Self {
            gateways: RwLock::new(Vec::new()),
            connections: RwLock::new(HashMap::new()),
            state_path: PathBuf::new(),
        }
    }

    /// Load gateway entries from the persisted JSON file.
    pub fn load(&self) -> Result<(), GatewayError> {
        if self.state_path.as_os_str().is_empty() {
            return Ok(());
        }

        if !self.state_path.exists() {
            return Ok(());
        }

        let content = fs::read_to_string(&self.state_path)
            .map_err(|e| GatewayError::IoError(e.to_string()))?;

        let store: GatewayStore = serde_json::from_str(&content).map_err(|e| {
            GatewayError::ConfigError(format!("failed to parse gateways.json: {}", e))
        })?;

        let mut gateways = self.gateways.write();
        *gateways = store.gateways;

        Ok(())
    }

    /// Save gateway entries to disk using an atomic write (temp + fsync + rename).
    pub fn save(&self) -> Result<(), GatewayError> {
        if self.state_path.as_os_str().is_empty() {
            return Ok(());
        }

        let gateways = self.gateways.read();
        let store = GatewayStore {
            version: GatewayStore::VERSION,
            gateways: gateways.clone(),
        };
        let content = serde_json::to_string_pretty(&store)
            .map_err(|e| GatewayError::IoError(e.to_string()))?;
        drop(gateways);

        // Ensure parent directory exists
        if let Some(parent) = self.state_path.parent() {
            fs::create_dir_all(parent).map_err(|e| GatewayError::IoError(e.to_string()))?;
        }

        // Atomic write: temp file -> fsync -> rename
        let temp_path = self.state_path.with_extension("tmp");
        let mut file =
            File::create(&temp_path).map_err(|e| GatewayError::IoError(e.to_string()))?;
        IoWrite::write_all(&mut file, content.as_bytes())
            .map_err(|e| GatewayError::IoError(e.to_string()))?;
        file.sync_all()
            .map_err(|e| GatewayError::IoError(e.to_string()))?;
        fs::rename(&temp_path, &self.state_path)
            .map_err(|e| GatewayError::IoError(e.to_string()))?;

        Ok(())
    }

    /// Add a new gateway entry. Enforces the `MAX_GATEWAYS` limit and rejects
    /// duplicate IDs.
    pub fn add(&self, entry: GatewayEntry) -> Result<(), GatewayError> {
        let mut gateways = self.gateways.write();

        if gateways.len() >= MAX_GATEWAYS {
            return Err(GatewayError::MaxGatewaysExceeded);
        }

        // Reject duplicate IDs
        if gateways.iter().any(|g| g.id == entry.id) {
            return Err(GatewayError::ConfigError(format!(
                "gateway with id {} already exists",
                entry.id
            )));
        }

        gateways.push(entry);
        drop(gateways);

        self.save()?;
        Ok(())
    }

    /// Remove a gateway entry by ID. Returns `true` if the entry was found
    /// and removed, `false` if not found.
    pub fn remove(&self, id: &str) -> Result<bool, GatewayError> {
        let mut gateways = self.gateways.write();
        let before = gateways.len();
        gateways.retain(|g| g.id != id);
        let removed = gateways.len() < before;
        drop(gateways);

        if removed {
            // Also clean up connection state
            self.connections.write().remove(id);
            self.save()?;
        }

        Ok(removed)
    }

    /// Return a cloned list of all gateway entries.
    pub fn list(&self) -> Vec<GatewayEntry> {
        self.gateways.read().clone()
    }

    /// Get a single gateway entry by ID.
    pub fn get(&self, id: &str) -> Option<GatewayEntry> {
        self.gateways.read().iter().find(|g| g.id == id).cloned()
    }

    /// Update a gateway entry by ID and persist changes. Returns `true` if updated.
    pub fn update_entry<F>(&self, id: &str, update: F) -> Result<bool, GatewayError>
    where
        F: FnOnce(&mut GatewayEntry),
    {
        let mut gateways = self.gateways.write();
        let mut updated = false;
        for entry in gateways.iter_mut() {
            if entry.id == id {
                update(entry);
                updated = true;
                break;
            }
        }
        drop(gateways);

        if updated {
            self.save()?;
        }

        Ok(updated)
    }

    /// Update the runtime connection state for a gateway.
    pub fn update_connection_state(&self, id: &str, state: GatewayConnectionState) {
        self.connections.write().insert(id.to_string(), state);
    }

    /// Get the runtime connection state for a gateway.
    pub fn get_connection_state(&self, id: &str) -> GatewayConnectionState {
        self.connections.read().get(id).cloned().unwrap_or_default()
    }
}

// ============================================================================
// TOFU fingerprint verification
// ============================================================================

/// Verify a TLS certificate fingerprint against an expected value.
///
/// Implements trust-on-first-use (TOFU) semantics:
/// - If `expected` is `None` (first connection), the actual fingerprint is
///   accepted and returned so the caller can persist it.
/// - If `expected` matches `actual` (case-insensitive), returns `Ok`.
/// - If there is a mismatch, returns `Err(GatewayError::FingerprintMismatch)`.
pub fn verify_fingerprint(expected: Option<&str>, actual: &str) -> Result<String, GatewayError> {
    match expected {
        None => {
            // First connection -- trust on first use
            Ok(actual.to_string())
        }
        Some(exp) => {
            if exp.eq_ignore_ascii_case(actual) {
                Ok(actual.to_string())
            } else {
                Err(GatewayError::FingerprintMismatch {
                    expected: exp.to_string(),
                    actual: actual.to_string(),
                })
            }
        }
    }
}

// ============================================================================
// Gateway client connection (stub)
// ============================================================================

/// Validate gateway connection parameters (URL, auth token, client ID) and
/// URL scheme before attempting a connection.
fn validate_gateway_params(
    entry: &GatewayEntry,
    auth_token: &str,
    client_id: &str,
) -> Result<(), GatewayError> {
    if entry.url.is_empty() {
        return Err(GatewayError::ConnectionFailed(
            "gateway URL is empty".to_string(),
        ));
    }

    if auth_token.is_empty() {
        return Err(GatewayError::AuthFailed("auth token is empty".to_string()));
    }

    if client_id.is_empty() {
        return Err(GatewayError::AuthFailed("client ID is empty".to_string()));
    }

    // Validate URL scheme
    let url = url::Url::parse(&entry.url)
        .map_err(|e| GatewayError::ConnectionFailed(format!("invalid URL: {}", e)))?;
    match url.scheme() {
        "ws" | "wss" => {}
        other => {
            return Err(GatewayError::ConnectionFailed(format!(
                "unsupported URL scheme: {}",
                other
            )));
        }
    }

    Ok(())
}

/// Send the JSON-RPC `gateway.connect` handshake over the WebSocket connection.
async fn send_gateway_handshake(
    conn: &GatewayConnection,
    auth_token: &str,
    client_id: &str,
) -> Result<(), GatewayError> {
    let handshake_id = Uuid::new_v4().to_string();
    let handshake = serde_json::json!({
        "jsonrpc": "2.0",
        "id": handshake_id,
        "method": "gateway.connect",
        "params": {
            "clientId": client_id,
            "token": auth_token,
            "protocolVersion": PROTOCOL_VERSION,
        }
    });
    let handshake_text = serde_json::to_string(&handshake)
        .map_err(|e| GatewayError::ConnectionFailed(e.to_string()))?;

    let writer = conn.ws_writer.as_ref().unwrap();
    writer
        .lock()
        .await
        .send(tokio_tungstenite::tungstenite::Message::Text(
            handshake_text.into(),
        ))
        .await
        .map_err(|e| GatewayError::ConnectionFailed(format!("handshake send failed: {}", e)))
}

/// Receive and validate the handshake response from the remote gateway.
async fn receive_handshake_response(conn: &GatewayConnection) -> Result<(), GatewayError> {
    match conn.recv_message().await {
        Some(Ok(tokio_tungstenite::tungstenite::Message::Text(text))) => {
            let resp: Value = serde_json::from_str(&text).map_err(|e| {
                GatewayError::ConnectionFailed(format!("handshake response parse failed: {}", e))
            })?;
            let ok = resp
                .get("result")
                .and_then(|r| r.get("ok"))
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            if !ok {
                let err_msg = resp
                    .get("error")
                    .and_then(|e| e.get("message"))
                    .and_then(|m| m.as_str())
                    .unwrap_or("handshake rejected");
                return Err(GatewayError::AuthFailed(err_msg.to_string()));
            }
            Ok(())
        }
        Some(Ok(_)) => Err(GatewayError::ConnectionFailed(
            "unexpected non-text handshake response".into(),
        )),
        Some(Err(e)) => Err(GatewayError::ConnectionFailed(format!(
            "handshake receive failed: {}",
            e
        ))),
        None => Err(GatewayError::ConnectionFailed(
            "connection closed during handshake".into(),
        )),
    }
}

/// Verify the TLS fingerprint extracted from the WebSocket stream against
/// the expected fingerprint stored in the gateway entry.
fn verify_stream_fingerprint(
    entry: &GatewayEntry,
    ws_stream: &WsStream,
) -> Result<Option<String>, GatewayError> {
    let actual_fp = extract_tls_fingerprint(ws_stream);
    if let Some(ref fp) = actual_fp {
        let verified = verify_fingerprint(entry.fingerprint.as_deref(), fp)?;
        if entry.fingerprint.is_none() {
            info!(fingerprint = %verified, "TLS fingerprint pinned via TOFU");
            return Ok(Some(verified));
        }
        info!(fingerprint = %verified, "TLS fingerprint verified");
        return Ok(None);
    }

    if entry.fingerprint.is_some() {
        return Err(GatewayError::ConnectionFailed(
            "expected TLS connection for fingerprint verification but got plaintext".into(),
        ));
    }

    Ok(None)
}

fn url_requires_tls(url: &str) -> Result<bool, GatewayError> {
    let parsed = url::Url::parse(url)
        .map_err(|e| GatewayError::ConnectionFailed(format!("invalid URL: {}", e)))?;
    Ok(parsed.scheme() == "wss")
}

async fn connect_ws_with_optional_stream(
    url: &str,
    stream: Option<TcpStream>,
    connector: Option<tokio_tungstenite::Connector>,
) -> Result<WsStream, GatewayError> {
    if let Some(stream) = stream {
        let (ws_stream, _response) =
            tokio_tungstenite::client_async_tls_with_config(url, stream, None, connector)
                .await
                .map_err(|e| {
                    GatewayError::ConnectionFailed(format!("WebSocket connect failed: {}", e))
                })?;
        return Ok(ws_stream);
    }

    if let Some(connector) = connector {
        let (ws_stream, _response) =
            tokio_tungstenite::connect_async_tls_with_config(url, None, false, Some(connector))
                .await
                .map_err(|e| {
                    GatewayError::ConnectionFailed(format!("WebSocket connect failed: {}", e))
                })?;
        return Ok(ws_stream);
    }

    let (ws_stream, _response) = tokio_tungstenite::connect_async(url)
        .await
        .map_err(|e| GatewayError::ConnectionFailed(format!("WebSocket connect failed: {}", e)))?;
    Ok(ws_stream)
}

async fn finalize_gateway_connect(
    entry: &GatewayEntry,
    auth_token: &str,
    client_id: &str,
    ws_stream: WsStream,
    tunnel: Option<SshTunnel>,
) -> Result<GatewayConnectResult, GatewayError> {
    let tofu_fingerprint = verify_stream_fingerprint(entry, &ws_stream)?;
    let peer_node_id = extract_peer_node_identity(&ws_stream);

    let conn = GatewayConnection::new_with_stream(entry.id.clone(), ws_stream);

    send_gateway_handshake(&conn, auth_token, client_id).await?;
    receive_handshake_response(&conn).await?;

    Ok(GatewayConnectResult {
        conn,
        peer_node_id,
        tofu_fingerprint,
        tunnel,
    })
}

/// Connect to a remote gateway via direct WebSocket.
///
/// 1. Validate parameters.
/// 2. Establish a TLS + WebSocket connection to `entry.url` via
///    `tokio-tungstenite`.
/// 3. Extract the TLS certificate fingerprint and verify it via TOFU.
/// 4. Send a JSON-RPC `gateway.connect` handshake.
/// 5. Return a [`GatewayConnection`] with live read/write stream halves.
pub async fn connect_to_gateway(
    entry: &GatewayEntry,
    auth_token: &str,
    client_id: &str,
) -> Result<GatewayConnectResult, GatewayError> {
    validate_gateway_params(entry, auth_token, client_id)?;

    info!(
        gateway_id = %entry.id,
        gateway_name = %entry.name,
        url = %entry.url,
        "connecting to remote gateway"
    );

    // Establish the WebSocket connection (TLS handled by tokio-tungstenite
    // when the URL scheme is wss://).
    let ws_stream = connect_ws_with_optional_stream(&entry.url, None, None).await?;

    let result = finalize_gateway_connect(entry, auth_token, client_id, ws_stream, None).await?;

    info!(
        gateway_id = %entry.id,
        "gateway WebSocket connected and handshake completed"
    );

    Ok(result)
}

/// Connect to a remote gateway using mTLS.
///
/// Similar to [`connect_to_gateway`] but uses the provided
/// `rustls::ClientConfig` to present a client certificate and verify the
/// server certificate against the cluster CA.
pub async fn connect_to_gateway_mtls(
    entry: &GatewayEntry,
    auth_token: &str,
    client_id: &str,
    client_config: std::sync::Arc<rustls::ClientConfig>,
) -> Result<GatewayConnectResult, GatewayError> {
    validate_gateway_params(entry, auth_token, client_id)?;
    if !url_requires_tls(&entry.url)? {
        return Err(GatewayError::ConfigError(
            "mTLS requires a wss:// gateway URL".to_string(),
        ));
    }

    info!(
        gateway_id = %entry.id,
        gateway_name = %entry.name,
        url = %entry.url,
        "connecting to remote gateway with mTLS"
    );

    // Build the TLS connector with our mTLS client config
    let connector = tokio_tungstenite::Connector::Rustls(client_config);

    let ws_stream = connect_ws_with_optional_stream(&entry.url, None, Some(connector))
        .await
        .map_err(|e| {
            GatewayError::ConnectionFailed(format!("mTLS WebSocket connect failed: {}", e))
        })?;

    let result = finalize_gateway_connect(entry, auth_token, client_id, ws_stream, None).await?;

    info!(
        gateway_id = %entry.id,
        "mTLS gateway WebSocket connected and handshake completed"
    );

    Ok(result)
}

async fn connect_to_gateway_via_ssh(
    entry: &GatewayEntry,
    auth_token: &str,
    client_id: &str,
    mtls_client_config: Option<std::sync::Arc<rustls::ClientConfig>>,
) -> Result<GatewayConnectResult, GatewayError> {
    let GatewayTransport::SshTunnel {
        ssh_host,
        ssh_port,
        ssh_user,
        remote_port,
    } = &entry.transport
    else {
        return Err(GatewayError::TunnelFailed(
            "ssh transport required but not configured".to_string(),
        ));
    };

    validate_gateway_params(entry, auth_token, client_id)?;

    let ssh_config = SshTunnelConfig {
        ssh_host: ssh_host.clone(),
        ssh_port: *ssh_port,
        ssh_user: ssh_user.clone(),
        remote_port: *remote_port,
        local_port: 0,
    };

    let tunnel = setup_ssh_tunnel(&ssh_config).await?;
    let stream = TcpStream::connect(("127.0.0.1", tunnel.local_port()))
        .await
        .map_err(|e| {
            GatewayError::TunnelFailed(format!("failed to connect to SSH tunnel: {}", e))
        })?;

    let connector = mtls_client_config.map(tokio_tungstenite::Connector::Rustls);

    let ws_stream = connect_ws_with_optional_stream(&entry.url, Some(stream), connector)
        .await
        .map_err(|e| {
            GatewayError::ConnectionFailed(format!("SSH WebSocket connect failed: {}", e))
        })?;

    info!(
        gateway_id = %entry.id,
        local_port = tunnel.local_port(),
        "gateway SSH tunnel connected"
    );

    let result =
        finalize_gateway_connect(entry, auth_token, client_id, ws_stream, Some(tunnel)).await?;

    info!(
        gateway_id = %entry.id,
        "gateway SSH WebSocket connected and handshake completed"
    );

    Ok(result)
}

async fn connect_to_gateway_with_transport(
    entry: &GatewayEntry,
    auth_token: &str,
    client_id: &str,
    mtls_client_config: Option<std::sync::Arc<rustls::ClientConfig>>,
) -> Result<GatewayConnectResult, GatewayError> {
    if mtls_client_config.is_some() && !url_requires_tls(&entry.url)? {
        return Err(GatewayError::ConfigError(
            "mTLS requires a wss:// gateway URL".to_string(),
        ));
    }

    match &entry.transport {
        GatewayTransport::DirectWs => {
            if let Some(client_config) = mtls_client_config {
                connect_to_gateway_mtls(entry, auth_token, client_id, client_config).await
            } else {
                connect_to_gateway(entry, auth_token, client_id).await
            }
        }
        GatewayTransport::SshTunnel { .. } => {
            connect_to_gateway_via_ssh(entry, auth_token, client_id, mtls_client_config).await
        }
    }
}

/// Extract the peer's node identity from an mTLS WebSocket stream.
///
/// Reads the peer's TLS certificate and extracts the Common Name (CN),
/// which contains the node ID set during certificate issuance.
fn extract_peer_node_identity(stream: &WsStream) -> Option<String> {
    let tls_stream = match stream.get_ref() {
        MaybeTlsStream::Rustls(s) => s,
        _ => return None,
    };

    let (_, conn) = tls_stream.get_ref();
    let certs = conn.peer_certificates()?;
    let cert_der = certs.first()?;

    crate::tls::ca::extract_node_identity(cert_der)
}

/// Extract the SHA-256 fingerprint from a TLS-wrapped WebSocket stream.
///
/// Returns `None` for plaintext (non-TLS) streams or if certificate
/// extraction is not supported by the TLS backend.
fn extract_tls_fingerprint(stream: &WsStream) -> Option<String> {
    let tls_stream = match stream.get_ref() {
        MaybeTlsStream::Rustls(s) => s,
        _ => return None,
    };
    let (_, conn) = tls_stream.get_ref();
    let certs = conn.peer_certificates()?;
    let cert_der = certs.first()?;
    let digest = <sha2::Sha256 as sha2::Digest>::digest(cert_der.as_ref());
    let hex: Vec<String> = digest.iter().map(|b| format!("{:02X}", b)).collect();
    Some(hex.join(":"))
}

// ============================================================================
// SSH tunnel
// ============================================================================

/// Configuration for setting up an SSH tunnel to a remote gateway.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SshTunnelConfig {
    pub ssh_host: String,
    pub ssh_port: u16,
    pub ssh_user: String,
    pub remote_port: u16,
    /// Local port to bind. Use `0` for automatic assignment.
    pub local_port: u16,
}

impl Default for SshTunnelConfig {
    fn default() -> Self {
        Self {
            ssh_host: String::new(),
            ssh_port: 22,
            ssh_user: String::new(),
            remote_port: 0,
            local_port: 0,
        }
    }
}

/// Handle to a running SSH tunnel subprocess.
pub struct SshTunnel {
    child: SandboxedTokioChild,
    local_port: u16,
}

impl std::fmt::Debug for SshTunnel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SshTunnel")
            .field("local_port", &self.local_port)
            .finish()
    }
}

impl SshTunnel {
    /// The local port the tunnel is bound to.
    pub fn local_port(&self) -> u16 {
        self.local_port
    }

    /// Check whether the SSH child process is still running.
    pub fn is_alive(&mut self) -> bool {
        match self.child.try_wait() {
            Ok(Some(_)) => false, // exited
            Ok(None) => true,     // still running
            Err(_) => false,      // error checking -- assume dead
        }
    }

    /// Kill the SSH child process and wait for it to exit.
    pub async fn shutdown(&mut self) -> Result<(), GatewayError> {
        self.child.kill().await.map_err(|e| {
            GatewayError::TunnelFailed(format!("failed to kill ssh process: {}", e))
        })?;
        self.child.wait().await.map_err(|e| {
            GatewayError::TunnelFailed(format!("failed to wait for ssh process: {}", e))
        })?;
        Ok(())
    }
}

fn allocate_local_port() -> Result<u16, GatewayError> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")
        .map_err(|e| GatewayError::TunnelFailed(format!("failed to allocate local port: {}", e)))?;
    let port = listener
        .local_addr()
        .map_err(|e| GatewayError::TunnelFailed(format!("failed to read local port: {}", e)))?;
    Ok(port.port())
}

/// Set up an SSH tunnel to a remote gateway using `ssh -L`.
///
/// Spawns an `ssh` child process that forwards traffic from a local port to the
/// remote gateway port. If `config.local_port` is `0`, a free local port is
/// selected automatically.
pub async fn setup_ssh_tunnel(config: &SshTunnelConfig) -> Result<SshTunnel, GatewayError> {
    if config.ssh_host.is_empty() {
        return Err(GatewayError::TunnelFailed("ssh_host is empty".to_string()));
    }

    if config.ssh_user.is_empty() {
        return Err(GatewayError::TunnelFailed("ssh_user is empty".to_string()));
    }

    if config.remote_port == 0 {
        return Err(GatewayError::TunnelFailed(
            "remote_port must be non-zero".to_string(),
        ));
    }

    let local_port = if config.local_port == 0 {
        allocate_local_port()?
    } else {
        config.local_port
    };

    let forward_spec = format!("{}:127.0.0.1:{}", local_port, config.remote_port);

    info!(
        ssh_host = %config.ssh_host,
        ssh_port = config.ssh_port,
        ssh_user = %config.ssh_user,
        forward = %forward_spec,
        "setting up SSH tunnel"
    );

    let sandbox = default_ssh_tunnel_sandbox_config();
    ensure_sandbox_supported(Some(&sandbox))
        .map_err(|e| GatewayError::TunnelFailed(format!("ssh tunnel sandbox unavailable: {e}")))?;

    let ssh_port = config.ssh_port.to_string();
    let destination = format!("{}@{}", config.ssh_user, config.ssh_host);
    let ssh_args = [
        "-N", // no remote command
        "-L",
        forward_spec.as_str(),
        "-p",
        ssh_port.as_str(),
        "-o",
        "StrictHostKeyChecking=accept-new",
        "-o",
        "ExitOnForwardFailure=yes",
        destination.as_str(),
    ];
    let child = spawn_sandboxed_tokio_command("ssh", &ssh_args, Some(&sandbox), true)
        .await
        .map_err(|e| GatewayError::TunnelFailed(format!("failed to spawn ssh: {}", e)))?;

    Ok(SshTunnel { child, local_port })
}

// ============================================================================
// Configuration
// ============================================================================

/// Parsed remote gateway configuration.
#[derive(Debug, Clone)]
pub struct GatewayConfig {
    /// Whether remote gateway support is enabled.
    pub enabled: bool,
    /// Pre-configured gateway entries from the config file.
    pub gateways: Vec<GatewayEntry>,
    /// Whether to automatically reconnect on connection loss.
    pub auto_reconnect: bool,
    /// Base interval between reconnect attempts in milliseconds.
    pub reconnect_interval_ms: u64,
    /// Maximum number of consecutive reconnect attempts before giving up.
    pub max_reconnect_attempts: u32,
    /// Auth token passed in the `gateway.connect` handshake.
    pub auth_token: String,
    /// mTLS configuration for gateway-to-gateway communication.
    pub mtls: crate::tls::MtlsConfig,
}

impl Default for GatewayConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            gateways: Vec::new(),
            auto_reconnect: true,
            reconnect_interval_ms: DEFAULT_RECONNECT_INTERVAL_MS,
            max_reconnect_attempts: DEFAULT_MAX_RECONNECT_ATTEMPTS,
            auth_token: String::new(),
            mtls: crate::tls::MtlsConfig::default(),
        }
    }
}

/// Parse remote gateway configuration from a JSON config value.
///
/// Config path: `gateway.remote`
///
/// ```json5
/// {
///   gateway: {
///     remote: {
///       enabled: true,
///       autoReconnect: true,
///       reconnectIntervalMs: 30000,
///       maxReconnectAttempts: 10,
///       gateways: [
///         { name: "home", url: "wss://home.example.com:18789/ws", fingerprint: "AB:CD:..." }
///       ]
///     }
///   }
/// }
/// ```
pub fn build_gateway_config(cfg: &Value) -> GatewayConfig {
    let remote = cfg
        .get("gateway")
        .and_then(|g| g.get("remote"))
        .and_then(|v| v.as_object());

    let remote = match remote {
        Some(obj) => obj,
        None => return GatewayConfig::default(),
    };

    let enabled = remote
        .get("enabled")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let auto_reconnect = remote
        .get("autoReconnect")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);

    let reconnect_interval_ms = remote
        .get("reconnectIntervalMs")
        .and_then(|v| v.as_u64())
        .unwrap_or(DEFAULT_RECONNECT_INTERVAL_MS);

    let max_reconnect_attempts = remote
        .get("maxReconnectAttempts")
        .and_then(|v| v.as_u64())
        .map(|v| v as u32)
        .unwrap_or(DEFAULT_MAX_RECONNECT_ATTEMPTS);

    let auth_token = remote
        .get("authToken")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let gateways = remote
        .get("gateways")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|item| {
                    let name = item.get("name")?.as_str()?.to_string();
                    let url = item.get("url")?.as_str()?.to_string();
                    let fingerprint = item
                        .get("fingerprint")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                    let auto_connect = item
                        .get("autoConnect")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(true);

                    let transport = if let Some(ssh) = item.get("ssh").and_then(|v| v.as_object()) {
                        let ssh_host = ssh.get("host")?.as_str()?.to_string();
                        let ssh_port = ssh
                            .get("port")
                            .and_then(|v| v.as_u64())
                            .map(|v| v as u16)
                            .unwrap_or(22);
                        let ssh_user = ssh.get("user")?.as_str()?.to_string();
                        let remote_port = ssh
                            .get("remotePort")
                            .and_then(|v| v.as_u64())
                            .map(|v| v as u16)
                            .unwrap_or(18789);
                        GatewayTransport::SshTunnel {
                            ssh_host,
                            ssh_port,
                            ssh_user,
                            remote_port,
                        }
                    } else {
                        GatewayTransport::DirectWs
                    };

                    Some(GatewayEntry {
                        id: Uuid::new_v4().to_string(),
                        name,
                        url,
                        fingerprint,
                        transport,
                        auto_connect,
                        created_at_ms: now_ms(),
                        last_connected_ms: None,
                    })
                })
                .collect()
        })
        .unwrap_or_default();

    // Parse mTLS config from the same top-level config value
    let mtls = crate::tls::parse_mtls_config(cfg);

    GatewayConfig {
        enabled,
        gateways,
        auto_reconnect,
        reconnect_interval_ms,
        max_reconnect_attempts,
        auth_token,
        mtls,
    }
}

// ============================================================================
// Lifecycle
// ============================================================================

/// Run the message-read loop for an established gateway connection.
///
/// Returns `true` if shutdown was requested, `false` if the connection
/// was lost and a reconnect should be attempted.
async fn run_gateway_read_loop(
    conn: &GatewayConnection,
    gateway_id: &str,
    rx: &mut tokio::sync::watch::Receiver<bool>,
) -> bool {
    loop {
        tokio::select! {
            msg = conn.recv_message() => {
                match msg {
                    Some(Ok(_)) => {
                        // Message received -- could dispatch here
                    }
                    Some(Err(e)) => {
                        warn!(
                            gateway_id = %gateway_id,
                            error = %e,
                            "gateway read error, will reconnect"
                        );
                        break;
                    }
                    None => {
                        info!(
                            gateway_id = %gateway_id,
                            "gateway connection closed by remote"
                        );
                        break;
                    }
                }
            }
            _ = rx.changed() => {
                if *rx.borrow() {
                    return true;
                }
            }
        }
    }
    *rx.borrow()
}

/// Handle a failed gateway connection attempt: update registry state, log,
/// and sleep with exponential backoff.
///
/// Returns `true` if the caller should stop retrying (shutdown requested or
/// max attempts reached), `false` if a retry should be attempted.
async fn handle_connection_failure(
    e: &GatewayError,
    gateway_id: &str,
    attempts: u32,
    reg: &GatewayRegistry,
    cfg: &GatewayConfig,
    rx: &mut tokio::sync::watch::Receiver<bool>,
) -> bool {
    let backoff_ms = cfg.reconnect_interval_ms * 2u64.saturating_pow(attempts.min(6));
    let retry_at = now_ms() + backoff_ms;

    reg.update_connection_state(
        gateway_id,
        GatewayConnectionState::Failed {
            error: e.to_string(),
            retry_at_ms: Some(retry_at),
        },
    );

    if !cfg.auto_reconnect || attempts >= cfg.max_reconnect_attempts {
        error!(
            gateway_id = %gateway_id,
            attempts = attempts,
            "giving up on gateway connection"
        );
        return true;
    }

    warn!(
        gateway_id = %gateway_id,
        error = %e,
        attempt = attempts,
        backoff_ms = backoff_ms,
        "gateway connection failed, will retry"
    );

    tokio::select! {
        _ = tokio::time::sleep(Duration::from_millis(backoff_ms)) => {}
        _ = rx.changed() => {
            if *rx.borrow() {
                return true;
            }
        }
    }

    false
}

/// Per-gateway reconnection loop with exponential backoff.
///
/// Connects to the given gateway entry, monitors the connection, and
/// reconnects on failure until shutdown or max attempts are reached.
async fn run_single_gateway_connection(
    mut entry: GatewayEntry,
    reg: Arc<GatewayRegistry>,
    cfg: GatewayConfig,
    mtls_client_config: Option<Arc<rustls::ClientConfig>>,
    mut rx: tokio::sync::watch::Receiver<bool>,
) {
    let gateway_id = entry.id.clone();
    let mut attempts: u32 = 0;

    loop {
        if *rx.borrow() {
            break;
        }

        reg.update_connection_state(&gateway_id, GatewayConnectionState::Connecting);

        match connect_to_gateway_with_transport(
            &entry,
            &cfg.auth_token,
            &gateway_id,
            mtls_client_config.clone(),
        )
        .await
        {
            Ok(result) => {
                reg.update_connection_state(
                    &gateway_id,
                    GatewayConnectionState::Connected { since_ms: now_ms() },
                );
                attempts = 0;

                let connected_at = now_ms();
                if let Some(fp) = result.tofu_fingerprint.clone() {
                    entry.fingerprint = Some(fp);
                }
                entry.last_connected_ms = Some(connected_at);
                if let Err(e) = reg.update_entry(&gateway_id, |entry| {
                    entry.last_connected_ms = Some(connected_at);
                    if let Some(fp) = result.tofu_fingerprint.clone() {
                        entry.fingerprint = Some(fp);
                    }
                }) {
                    warn!(
                        gateway_id = %gateway_id,
                        error = %e,
                        "failed to persist gateway metadata"
                    );
                }

                let tunnel = result.tunnel;
                let shutdown = run_gateway_read_loop(&result.conn, &gateway_id, &mut rx).await;
                if let Some(mut tunnel) = tunnel {
                    if let Err(e) = tunnel.shutdown().await {
                        warn!(
                            gateway_id = %gateway_id,
                            error = %e,
                            "failed to shut down SSH tunnel"
                        );
                    }
                }
                if shutdown {
                    break;
                }
            }
            Err(e) => {
                attempts += 1;
                let give_up =
                    handle_connection_failure(&e, &gateway_id, attempts, &reg, &cfg, &mut rx).await;
                if give_up {
                    break;
                }
            }
        }
    }

    reg.update_connection_state(&gateway_id, GatewayConnectionState::Disconnected);
}

/// Seed the registry with gateway entries from the configuration file,
/// skipping entries that already exist.
fn seed_registry_from_config(registry: &GatewayRegistry, config: &GatewayConfig) {
    for entry in &config.gateways {
        if registry.get(&entry.id).is_none() {
            if let Err(e) = registry.add(entry.clone()) {
                warn!(
                    gateway_id = %entry.id,
                    error = %e,
                    "failed to add config-defined gateway to registry"
                );
            }
        }
    }
}

/// Spawn a connection task for each auto-connect gateway and return the
/// join handles.
fn spawn_auto_connect_tasks(
    registry: &Arc<GatewayRegistry>,
    config: &GatewayConfig,
    mtls_client_config: Option<Arc<rustls::ClientConfig>>,
    shutdown_rx: &tokio::sync::watch::Receiver<bool>,
) -> Vec<tokio::task::JoinHandle<()>> {
    let auto_connect: Vec<GatewayEntry> = registry
        .list()
        .into_iter()
        .filter(|g| g.auto_connect)
        .collect();

    if auto_connect.is_empty() {
        info!("no auto-connect gateways configured, lifecycle idle");
    } else {
        info!(count = auto_connect.len(), "auto-connect gateways found");
    }

    let mut handles = Vec::new();
    for entry in auto_connect {
        let reg = Arc::clone(registry);
        let cfg = config.clone();
        let mtls = mtls_client_config.clone();
        let rx = shutdown_rx.clone();
        let handle = tokio::spawn(run_single_gateway_connection(entry, reg, cfg, mtls, rx));
        handles.push(handle);
    }
    handles
}

/// Run the remote gateway connection lifecycle.
///
/// For each gateway entry with `auto_connect = true`, spawns a connection task
/// that:
/// 1. Establishes the connection (with optional SSH tunnel).
/// 2. Monitors connection health.
/// 3. Reconnects with exponential backoff on failure.
///
/// The lifecycle respects the `shutdown_rx` signal and cleans up all
/// connections on shutdown.
pub async fn run_gateway_lifecycle(
    registry: Arc<GatewayRegistry>,
    config: GatewayConfig,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) -> Result<(), GatewayError> {
    if !config.enabled {
        return Ok(());
    }

    info!("remote gateway lifecycle starting");

    seed_registry_from_config(&registry, &config);
    let mtls_client_config = if config.mtls.enabled {
        let setup = crate::tls::setup_mtls(&config.mtls).map_err(|e| {
            GatewayError::ConfigError(format!("failed to set up mTLS client config: {}", e))
        })?;
        Some(setup.client_config)
    } else {
        None
    };

    let handles = spawn_auto_connect_tasks(&registry, &config, mtls_client_config, &shutdown_rx);

    // Wait for shutdown
    loop {
        tokio::select! {
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    break;
                }
            }
        }
    }

    // Wait for all connection tasks to finish
    for handle in handles {
        let _ = handle.await;
    }

    info!("remote gateway lifecycle stopped");
    Ok(())
}

// ============================================================================
// Helpers
// ============================================================================

/// Get the current time in milliseconds since the Unix epoch.
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_millis() as u64
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tempfile::TempDir;

    // ====================================================================
    // Registry: add/remove
    // ====================================================================

    #[test]
    fn test_registry_add_remove() {
        let registry = GatewayRegistry::in_memory();
        let entry = GatewayEntry::new("test".to_string(), "wss://example.com/ws".to_string());
        let id = entry.id.clone();

        registry.add(entry).unwrap();
        assert_eq!(registry.list().len(), 1);

        let removed = registry.remove(&id).unwrap();
        assert!(removed);
        assert_eq!(registry.list().len(), 0);
    }

    // ====================================================================
    // Registry: max gateways
    // ====================================================================

    #[test]
    fn test_registry_max_gateways() {
        let registry = GatewayRegistry::in_memory();
        for i in 0..MAX_GATEWAYS {
            let entry = GatewayEntry::new(format!("gw-{}", i), "wss://example.com/ws".to_string());
            registry.add(entry).unwrap();
        }

        let extra = GatewayEntry::new("overflow".to_string(), "wss://example.com/ws".to_string());
        let err = registry.add(extra).unwrap_err();
        assert_eq!(err, GatewayError::MaxGatewaysExceeded);
    }

    // ====================================================================
    // Registry: persistence round-trip
    // ====================================================================

    #[test]
    fn test_registry_persistence() {
        let dir = TempDir::new().unwrap();
        let registry = GatewayRegistry::new(dir.path().to_path_buf());

        let entry = GatewayEntry::new(
            "persist-test".to_string(),
            "wss://example.com/ws".to_string(),
        );
        let id = entry.id.clone();
        registry.add(entry).unwrap();

        // Create a new registry pointing at the same directory and load
        let registry2 = GatewayRegistry::new(dir.path().to_path_buf());
        registry2.load().unwrap();

        let loaded = registry2.get(&id);
        assert!(loaded.is_some());
        assert_eq!(loaded.unwrap().name, "persist-test");
    }

    // ====================================================================
    // Registry: atomic write (temp + rename)
    // ====================================================================

    #[test]
    fn test_registry_atomic_write() {
        let dir = TempDir::new().unwrap();
        let registry = GatewayRegistry::new(dir.path().to_path_buf());

        let entry = GatewayEntry::new("atomic".to_string(), "wss://example.com/ws".to_string());
        registry.add(entry).unwrap();

        // The final file should exist, but the temp file should not
        let final_path = dir.path().join("gateways.json");
        let temp_path = dir.path().join("gateways.tmp");
        assert!(final_path.exists());
        assert!(!temp_path.exists());

        // Content should be valid JSON
        let content = fs::read_to_string(&final_path).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert!(parsed.get("gateways").is_some());
    }

    // ====================================================================
    // Registry: duplicate ID rejection
    // ====================================================================

    #[test]
    fn test_registry_duplicate_id() {
        let registry = GatewayRegistry::in_memory();
        let entry = GatewayEntry::new("dupe".to_string(), "wss://example.com/ws".to_string());
        let id = entry.id.clone();
        registry.add(entry).unwrap();

        let dupe = GatewayEntry {
            id: id.clone(),
            name: "dupe2".to_string(),
            url: "wss://other.com/ws".to_string(),
            fingerprint: None,
            transport: GatewayTransport::DirectWs,
            auto_connect: false,
            created_at_ms: now_ms(),
            last_connected_ms: None,
        };
        let err = registry.add(dupe).unwrap_err();
        assert!(matches!(err, GatewayError::ConfigError(_)));
    }

    // ====================================================================
    // TOFU fingerprint verification
    // ====================================================================

    #[test]
    fn test_fingerprint_tofu_first_connect() {
        let actual = "AB:CD:EF:01:23:45:67:89";
        let result = verify_fingerprint(None, actual);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), actual);
    }

    #[test]
    fn test_fingerprint_tofu_match() {
        let fp = "AB:CD:EF:01:23:45:67:89";
        let result = verify_fingerprint(Some(fp), fp);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), fp);
    }

    #[test]
    fn test_fingerprint_tofu_mismatch() {
        let expected = "AB:CD:EF:01:23:45:67:89";
        let actual = "FF:FF:FF:FF:FF:FF:FF:FF";
        let result = verify_fingerprint(Some(expected), actual);
        assert!(result.is_err());
        match result.unwrap_err() {
            GatewayError::FingerprintMismatch {
                expected: e,
                actual: a,
            } => {
                assert_eq!(e, expected);
                assert_eq!(a, actual);
            }
            other => panic!("expected FingerprintMismatch, got {:?}", other),
        }
    }

    #[test]
    fn test_fingerprint_case_insensitive() {
        let lower = "ab:cd:ef:01:23:45:67:89";
        let upper = "AB:CD:EF:01:23:45:67:89";
        assert!(verify_fingerprint(Some(lower), upper).is_ok());
        assert!(verify_fingerprint(Some(upper), lower).is_ok());
    }

    // ====================================================================
    // Connection state transitions
    // ====================================================================

    #[test]
    fn test_connection_state_transitions() {
        let registry = GatewayRegistry::in_memory();
        let id = "gw-1";

        // Initially Disconnected
        assert_eq!(
            registry.get_connection_state(id),
            GatewayConnectionState::Disconnected
        );

        // Transition to Connecting
        registry.update_connection_state(id, GatewayConnectionState::Connecting);
        assert_eq!(
            registry.get_connection_state(id),
            GatewayConnectionState::Connecting
        );

        // Transition to Connected
        registry.update_connection_state(id, GatewayConnectionState::Connected { since_ms: 12345 });
        assert_eq!(
            registry.get_connection_state(id),
            GatewayConnectionState::Connected { since_ms: 12345 }
        );

        // Transition to Failed
        registry.update_connection_state(
            id,
            GatewayConnectionState::Failed {
                error: "timeout".to_string(),
                retry_at_ms: Some(99999),
            },
        );
        assert_eq!(
            registry.get_connection_state(id),
            GatewayConnectionState::Failed {
                error: "timeout".to_string(),
                retry_at_ms: Some(99999),
            }
        );

        // Back to Disconnected
        registry.update_connection_state(id, GatewayConnectionState::Disconnected);
        assert_eq!(
            registry.get_connection_state(id),
            GatewayConnectionState::Disconnected
        );
    }

    // ====================================================================
    // Gateway config: defaults
    // ====================================================================

    #[test]
    fn test_gateway_config_defaults() {
        let cfg = GatewayConfig::default();
        assert!(!cfg.enabled);
        assert!(cfg.gateways.is_empty());
        assert!(cfg.auto_reconnect);
        assert_eq!(cfg.reconnect_interval_ms, DEFAULT_RECONNECT_INTERVAL_MS);
        assert_eq!(cfg.max_reconnect_attempts, DEFAULT_MAX_RECONNECT_ATTEMPTS);
    }

    // ====================================================================
    // Gateway config: custom values
    // ====================================================================

    #[test]
    fn test_gateway_config_custom() {
        let cfg = json!({
            "gateway": {
                "remote": {
                    "enabled": true,
                    "autoReconnect": false,
                    "reconnectIntervalMs": 5000,
                    "maxReconnectAttempts": 3
                }
            }
        });
        let config = build_gateway_config(&cfg);
        assert!(config.enabled);
        assert!(!config.auto_reconnect);
        assert_eq!(config.reconnect_interval_ms, 5000);
        assert_eq!(config.max_reconnect_attempts, 3);
    }

    // ====================================================================
    // Gateway config: missing section falls back to defaults
    // ====================================================================

    #[test]
    fn test_gateway_config_missing() {
        let cfg = json!({});
        let config = build_gateway_config(&cfg);
        assert!(!config.enabled);
        assert!(config.auto_reconnect);
        assert_eq!(config.reconnect_interval_ms, DEFAULT_RECONNECT_INTERVAL_MS);
        assert_eq!(
            config.max_reconnect_attempts,
            DEFAULT_MAX_RECONNECT_ATTEMPTS
        );
    }

    // ====================================================================
    // Gateway entry serialization round-trip
    // ====================================================================

    #[test]
    fn test_gateway_entry_serialization() {
        let entry = GatewayEntry {
            id: "test-id-123".to_string(),
            name: "my-gateway".to_string(),
            url: "wss://gw.example.com:18789/ws".to_string(),
            fingerprint: Some("AB:CD:EF".to_string()),
            transport: GatewayTransport::DirectWs,
            auto_connect: true,
            created_at_ms: 1700000000000,
            last_connected_ms: Some(1700000001000),
        };

        let json_str = serde_json::to_string(&entry).unwrap();
        let deserialized: GatewayEntry = serde_json::from_str(&json_str).unwrap();

        assert_eq!(deserialized.id, "test-id-123");
        assert_eq!(deserialized.name, "my-gateway");
        assert_eq!(deserialized.url, "wss://gw.example.com:18789/ws");
        assert_eq!(deserialized.fingerprint, Some("AB:CD:EF".to_string()));
        assert_eq!(deserialized.transport, GatewayTransport::DirectWs);
        assert!(deserialized.auto_connect);
        assert_eq!(deserialized.created_at_ms, 1700000000000);
        assert_eq!(deserialized.last_connected_ms, Some(1700000001000));
    }

    // ====================================================================
    // SSH tunnel config defaults
    // ====================================================================

    #[test]
    fn test_ssh_tunnel_config_defaults() {
        let cfg = SshTunnelConfig::default();
        assert!(cfg.ssh_host.is_empty());
        assert_eq!(cfg.ssh_port, 22);
        assert!(cfg.ssh_user.is_empty());
        assert_eq!(cfg.remote_port, 0);
        assert_eq!(cfg.local_port, 0);
    }

    // ====================================================================
    // Transport variants
    // ====================================================================

    #[test]
    fn test_gateway_transport_variants() {
        let direct = GatewayTransport::DirectWs;
        let ssh = GatewayTransport::SshTunnel {
            ssh_host: "host.example.com".to_string(),
            ssh_port: 22,
            ssh_user: "admin".to_string(),
            remote_port: 18789,
        };

        // Verify they are different
        assert_ne!(direct, ssh);

        // Verify default is DirectWs
        assert_eq!(GatewayTransport::default(), GatewayTransport::DirectWs);

        // Verify serde round-trip for DirectWs
        let json = serde_json::to_string(&direct).unwrap();
        let deser: GatewayTransport = serde_json::from_str(&json).unwrap();
        assert_eq!(deser, GatewayTransport::DirectWs);

        // Verify serde round-trip for SshTunnel
        let json = serde_json::to_string(&ssh).unwrap();
        let deser: GatewayTransport = serde_json::from_str(&json).unwrap();
        assert_eq!(deser, ssh);
    }

    // ====================================================================
    // Registry: empty initial state
    // ====================================================================

    #[test]
    fn test_registry_empty_initial() {
        let registry = GatewayRegistry::in_memory();
        assert!(registry.list().is_empty());
    }

    // ====================================================================
    // Registry: get nonexistent
    // ====================================================================

    #[test]
    fn test_registry_get_nonexistent() {
        let registry = GatewayRegistry::in_memory();
        assert!(registry.get("nonexistent-id").is_none());
    }

    // ====================================================================
    // Registry: update/get connection state
    // ====================================================================

    #[test]
    fn test_registry_update_connection_state() {
        let registry = GatewayRegistry::in_memory();
        let id = "gw-state-test";

        registry.update_connection_state(id, GatewayConnectionState::Connected { since_ms: 42000 });
        let state = registry.get_connection_state(id);
        assert_eq!(state, GatewayConnectionState::Connected { since_ms: 42000 });
    }

    // ====================================================================
    // Registry: list returns independent clone
    // ====================================================================

    #[test]
    fn test_registry_list_clones() {
        let registry = GatewayRegistry::in_memory();
        let entry = GatewayEntry::new("clone-test".to_string(), "wss://example.com/ws".to_string());
        registry.add(entry).unwrap();

        let list1 = registry.list();
        let list2 = registry.list();

        assert_eq!(list1.len(), list2.len());
        assert_eq!(list1[0].id, list2[0].id);

        // Modifying list1 should not affect list2 or the registry
        // (they are independent clones)
        drop(list1);
        assert_eq!(registry.list().len(), 1);
    }

    // ====================================================================
    // Error display messages
    // ====================================================================

    #[test]
    fn test_gateway_error_display() {
        let err = GatewayError::FingerprintMismatch {
            expected: "AA:BB".to_string(),
            actual: "CC:DD".to_string(),
        };
        assert_eq!(
            err.to_string(),
            "TLS fingerprint mismatch: expected AA:BB, got CC:DD"
        );

        let err = GatewayError::ConnectionFailed("timeout".to_string());
        assert_eq!(err.to_string(), "connection failed: timeout");

        let err = GatewayError::AuthFailed("bad token".to_string());
        assert_eq!(err.to_string(), "authentication failed: bad token");

        let err = GatewayError::TunnelFailed("port in use".to_string());
        assert_eq!(err.to_string(), "tunnel failed: port in use");

        let err = GatewayError::IoError("permission denied".to_string());
        assert_eq!(err.to_string(), "I/O error: permission denied");

        let err = GatewayError::ConfigError("missing field".to_string());
        assert_eq!(err.to_string(), "config error: missing field");

        let err = GatewayError::MaxGatewaysExceeded;
        assert_eq!(err.to_string(), "maximum number of gateways exceeded");

        let err = GatewayError::NotFound;
        assert_eq!(err.to_string(), "gateway not found");

        let err = GatewayError::MtlsCertError("invalid cert".to_string());
        assert_eq!(err.to_string(), "mTLS certificate error: invalid cert");
    }

    // ====================================================================
    // build_gateway_config: enabled
    // ====================================================================

    #[test]
    fn test_build_gateway_config_enabled() {
        let cfg = json!({
            "gateway": {
                "remote": {
                    "enabled": true
                }
            }
        });
        let config = build_gateway_config(&cfg);
        assert!(config.enabled);
    }

    // ====================================================================
    // build_gateway_config: disabled
    // ====================================================================

    #[test]
    fn test_build_gateway_config_disabled() {
        let cfg = json!({
            "gateway": {
                "remote": {
                    "enabled": false
                }
            }
        });
        let config = build_gateway_config(&cfg);
        assert!(!config.enabled);
    }

    // ====================================================================
    // build_gateway_config: mTLS settings
    // ====================================================================

    #[test]
    fn test_build_gateway_config_mtls() {
        let cfg = json!({
            "gateway": {
                "remote": {
                    "enabled": true
                },
                "mtls": {
                    "enabled": true,
                    "caCert": "/path/to/ca.pem",
                    "crlPath": "/path/to/crl.json",
                    "nodeCert": "/path/to/node-cert.pem",
                    "nodeKey": "/path/to/node-key.pem",
                    "requireClientCert": false
                }
            }
        });
        let config = build_gateway_config(&cfg);
        assert!(config.mtls.enabled);
        assert_eq!(
            config.mtls.ca_cert,
            Some(std::path::PathBuf::from("/path/to/ca.pem"))
        );
        assert_eq!(
            config.mtls.crl_path,
            Some(std::path::PathBuf::from("/path/to/crl.json"))
        );
        assert_eq!(
            config.mtls.node_cert,
            Some(std::path::PathBuf::from("/path/to/node-cert.pem"))
        );
        assert_eq!(
            config.mtls.node_key,
            Some(std::path::PathBuf::from("/path/to/node-key.pem"))
        );
        assert!(!config.mtls.require_client_cert);
    }

    #[test]
    fn test_build_gateway_config_mtls_defaults() {
        let cfg = json!({
            "gateway": {
                "remote": {
                    "enabled": true
                }
            }
        });
        let config = build_gateway_config(&cfg);
        assert!(!config.mtls.enabled);
        assert!(config.mtls.ca_cert.is_none());
        assert!(config.mtls.crl_path.is_none());
        assert!(config.mtls.require_client_cert); // default true
    }

    // ====================================================================
    // build_gateway_config: with gateway entries
    // ====================================================================

    #[test]
    fn test_build_gateway_config_with_gateways() {
        let cfg = json!({
            "gateway": {
                "remote": {
                    "enabled": true,
                    "gateways": [
                        {
                            "name": "home",
                            "url": "wss://home.example.com:18789/ws",
                            "fingerprint": "AB:CD:EF:01"
                        },
                        {
                            "name": "office",
                            "url": "wss://office.example.com/ws"
                        }
                    ]
                }
            }
        });
        let config = build_gateway_config(&cfg);
        assert_eq!(config.gateways.len(), 2);
        assert_eq!(config.gateways[0].name, "home");
        assert_eq!(config.gateways[0].url, "wss://home.example.com:18789/ws");
        assert_eq!(
            config.gateways[0].fingerprint,
            Some("AB:CD:EF:01".to_string())
        );
        assert_eq!(config.gateways[1].name, "office");
        assert_eq!(config.gateways[1].url, "wss://office.example.com/ws");
        assert!(config.gateways[1].fingerprint.is_none());
    }

    // ====================================================================
    // build_gateway_config: reconnect settings
    // ====================================================================

    #[test]
    fn test_build_gateway_config_reconnect_settings() {
        let cfg = json!({
            "gateway": {
                "remote": {
                    "enabled": true,
                    "autoReconnect": true,
                    "reconnectIntervalMs": 60000,
                    "maxReconnectAttempts": 20
                }
            }
        });
        let config = build_gateway_config(&cfg);
        assert!(config.auto_reconnect);
        assert_eq!(config.reconnect_interval_ms, 60000);
        assert_eq!(config.max_reconnect_attempts, 20);
    }

    // ====================================================================
    // GatewayEntry: default auto_connect
    // ====================================================================

    #[test]
    fn test_gateway_entry_default_auto_connect() {
        let entry = GatewayEntry::new("test".to_string(), "wss://example.com/ws".to_string());
        assert!(!entry.auto_connect);
    }

    // ====================================================================
    // Connection state: default
    // ====================================================================

    #[test]
    fn test_connection_state_default() {
        let state = GatewayConnectionState::default();
        assert_eq!(state, GatewayConnectionState::Disconnected);
    }

    // ====================================================================
    // Registry: remove nonexistent returns false
    // ====================================================================

    #[test]
    fn test_registry_remove_nonexistent() {
        let registry = GatewayRegistry::in_memory();
        let result = registry.remove("does-not-exist").unwrap();
        assert!(!result);
    }

    // ====================================================================
    // Fingerprint: empty string edge case
    // ====================================================================

    #[test]
    fn test_fingerprint_empty_string() {
        // Empty expected with non-empty actual: TOFU accepts
        let result = verify_fingerprint(None, "");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "");

        // Empty expected string (Some("")) vs empty actual: match
        let result = verify_fingerprint(Some(""), "");
        assert!(result.is_ok());

        // Empty expected string vs non-empty actual: mismatch
        let result = verify_fingerprint(Some(""), "AB:CD");
        assert!(result.is_err());
    }

    // ====================================================================
    // SSH tunnel: shutdown (validate struct construction)
    // ====================================================================

    #[test]
    fn test_allocate_local_port() {
        let port = allocate_local_port().unwrap();
        assert!(port > 0);
    }

    #[tokio::test]
    async fn test_ssh_tunnel_shutdown() {
        // We test the setup_ssh_tunnel validation without actually spawning ssh
        // by providing invalid config that triggers early validation errors.
        let config = SshTunnelConfig {
            ssh_host: String::new(),
            ssh_port: 22,
            ssh_user: "user".to_string(),
            remote_port: 18789,
            local_port: 0,
        };
        let result = setup_ssh_tunnel(&config).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), GatewayError::TunnelFailed(_)));

        // Empty user
        let config = SshTunnelConfig {
            ssh_host: "host.example.com".to_string(),
            ssh_port: 22,
            ssh_user: String::new(),
            remote_port: 18789,
            local_port: 0,
        };
        let result = setup_ssh_tunnel(&config).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), GatewayError::TunnelFailed(_)));

        // Zero remote port
        let config = SshTunnelConfig {
            ssh_host: "host.example.com".to_string(),
            ssh_port: 22,
            ssh_user: "user".to_string(),
            remote_port: 0,
            local_port: 0,
        };
        let result = setup_ssh_tunnel(&config).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), GatewayError::TunnelFailed(_)));
    }

    // ====================================================================
    // Gateway lifecycle reads config
    // ====================================================================

    #[tokio::test]
    async fn test_gateway_lifecycle_config() {
        // With enabled=false, lifecycle should return immediately
        let registry = Arc::new(GatewayRegistry::in_memory());
        let config = GatewayConfig {
            enabled: false,
            ..GatewayConfig::default()
        };
        let (tx, rx) = tokio::sync::watch::channel(false);

        let result = run_gateway_lifecycle(registry, config, rx).await;
        assert!(result.is_ok());

        // Shut down the sender to avoid leaks
        drop(tx);
    }

    // ====================================================================
    // GatewayConnection: basic functionality
    // ====================================================================

    #[test]
    fn test_gateway_connection_new_connected() {
        let conn = GatewayConnection::new_connected("gw-1".to_string());
        assert!(conn.is_connected());
        assert_eq!(conn.gateway_id, "gw-1");
        assert_eq!(conn.protocol_version, PROTOCOL_VERSION);
    }

    #[tokio::test]
    async fn test_gateway_connection_send_without_stream() {
        // A stub connection (no WS stream) should return an error
        let conn = GatewayConnection::new_connected("gw-2".to_string());
        let result = conn.send_message("test.method", &json!({})).await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            GatewayError::ConnectionFailed(_)
        ));
    }

    #[test]
    fn test_gateway_connection_disconnected_not_connected() {
        let conn = GatewayConnection {
            gateway_id: "gw-3".to_string(),
            state: GatewayConnectionState::Disconnected,
            protocol_version: PROTOCOL_VERSION,
            ws_writer: None,
            ws_reader: None,
        };
        assert!(!conn.is_connected());
    }

    // ====================================================================
    // connect_to_gateway: validation
    // ====================================================================

    #[tokio::test]
    async fn test_connect_to_gateway_empty_url() {
        let entry = GatewayEntry {
            id: "gw-empty-url".to_string(),
            name: "empty".to_string(),
            url: String::new(),
            fingerprint: None,
            transport: GatewayTransport::DirectWs,
            auto_connect: false,
            created_at_ms: 0,
            last_connected_ms: None,
        };
        let result = connect_to_gateway(&entry, "token", "client").await;
        assert!(matches!(
            result.unwrap_err(),
            GatewayError::ConnectionFailed(_)
        ));
    }

    #[tokio::test]
    async fn test_connect_to_gateway_empty_token() {
        let entry = GatewayEntry::new("test".to_string(), "wss://example.com/ws".to_string());
        let result = connect_to_gateway(&entry, "", "client").await;
        assert!(matches!(result.unwrap_err(), GatewayError::AuthFailed(_)));
    }

    #[tokio::test]
    async fn test_connect_to_gateway_empty_client_id() {
        let entry = GatewayEntry::new("test".to_string(), "wss://example.com/ws".to_string());
        let result = connect_to_gateway(&entry, "token", "").await;
        assert!(matches!(result.unwrap_err(), GatewayError::AuthFailed(_)));
    }

    // ====================================================================
    // GatewayEntry serialization with SshTunnel transport
    // ====================================================================

    #[test]
    fn test_gateway_entry_ssh_transport_serialization() {
        let entry = GatewayEntry {
            id: "ssh-test".to_string(),
            name: "ssh-gateway".to_string(),
            url: "wss://via-tunnel.example.com/ws".to_string(),
            fingerprint: None,
            transport: GatewayTransport::SshTunnel {
                ssh_host: "bastion.example.com".to_string(),
                ssh_port: 2222,
                ssh_user: "deployer".to_string(),
                remote_port: 18789,
            },
            auto_connect: true,
            created_at_ms: 1700000000000,
            last_connected_ms: None,
        };

        let json_str = serde_json::to_string(&entry).unwrap();
        let deser: GatewayEntry = serde_json::from_str(&json_str).unwrap();

        assert_eq!(
            deser.transport,
            GatewayTransport::SshTunnel {
                ssh_host: "bastion.example.com".to_string(),
                ssh_port: 2222,
                ssh_user: "deployer".to_string(),
                remote_port: 18789,
            }
        );
    }

    // ====================================================================
    // GatewayStore serialization
    // ====================================================================

    #[test]
    fn test_gateway_store_serialization() {
        let store = GatewayStore {
            version: 1,
            gateways: vec![
                GatewayEntry::new("gw-a".to_string(), "wss://a.example.com/ws".to_string()),
                GatewayEntry::new("gw-b".to_string(), "wss://b.example.com/ws".to_string()),
            ],
        };

        let json_str = serde_json::to_string_pretty(&store).unwrap();
        let deser: GatewayStore = serde_json::from_str(&json_str).unwrap();

        assert_eq!(deser.version, 1);
        assert_eq!(deser.gateways.len(), 2);
    }

    // ====================================================================
    // Registry load from nonexistent file (should be ok / empty)
    // ====================================================================

    #[test]
    fn test_registry_load_nonexistent() {
        let dir = TempDir::new().unwrap();
        let registry = GatewayRegistry::new(dir.path().join("subdir").to_path_buf());
        let result = registry.load();
        assert!(result.is_ok());
        assert!(registry.list().is_empty());
    }

    // ====================================================================
    // build_gateway_config: gateway with SSH transport
    // ====================================================================

    #[test]
    fn test_build_gateway_config_ssh_transport() {
        let cfg = json!({
            "gateway": {
                "remote": {
                    "enabled": true,
                    "gateways": [
                        {
                            "name": "ssh-gw",
                            "url": "wss://localhost:18789/ws",
                            "ssh": {
                                "host": "bastion.example.com",
                                "port": 2222,
                                "user": "admin",
                                "remotePort": 18789
                            }
                        }
                    ]
                }
            }
        });
        let config = build_gateway_config(&cfg);
        assert_eq!(config.gateways.len(), 1);
        assert_eq!(
            config.gateways[0].transport,
            GatewayTransport::SshTunnel {
                ssh_host: "bastion.example.com".to_string(),
                ssh_port: 2222,
                ssh_user: "admin".to_string(),
                remote_port: 18789,
            }
        );
    }

    // ====================================================================
    // SshTunnelConfig serialization
    // ====================================================================

    #[test]
    fn test_ssh_tunnel_config_serialization() {
        let cfg = SshTunnelConfig {
            ssh_host: "bastion.example.com".to_string(),
            ssh_port: 2222,
            ssh_user: "admin".to_string(),
            remote_port: 18789,
            local_port: 19000,
        };

        let json_str = serde_json::to_string(&cfg).unwrap();
        let deser: SshTunnelConfig = serde_json::from_str(&json_str).unwrap();

        assert_eq!(deser.ssh_host, "bastion.example.com");
        assert_eq!(deser.ssh_port, 2222);
        assert_eq!(deser.ssh_user, "admin");
        assert_eq!(deser.remote_port, 18789);
        assert_eq!(deser.local_port, 19000);
    }
}
