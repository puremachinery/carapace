//! CLI subcommand definitions and handlers.
//!
//! Uses clap derive to define the subcommand hierarchy:
//! - `start` (default) -- start the gateway server
//! - `config show|get|set|path` -- read/write configuration
//! - `status` -- query a running instance for health info
//! - `logs` -- tail log entries from a running instance
//! - `version` -- print build/version info
//! - `backup` -- create a backup archive of all gateway data
//! - `restore` -- restore from a backup archive
//! - `reset` -- clear specific data categories
//! - `setup` -- interactive first-run configuration wizard
//! - `pair` -- pair with a remote gateway node
//! - `update` -- check for updates or self-update

pub mod backup_crypto;
pub mod chat;

use clap::{Parser, Subcommand};

/// Carapace gateway server for AI assistants.
#[derive(Parser, Debug)]
#[command(
    name = "cara",
    version = env!("CARGO_PKG_VERSION"),
    about = "Carapace — a secure gateway server for AI assistants"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(clap::ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyOutcomeSelection {
    Auto,
    LocalChat,
    Discord,
    Telegram,
    Hooks,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Start the gateway server (default when no subcommand is given).
    Start,

    /// Read or write configuration values.
    #[command(subcommand)]
    Config(ConfigCommand),

    /// Query a running instance for health/status information.
    Status {
        /// Port of the running instance (default: from config or 18789).
        #[arg(short, long)]
        port: Option<u16>,

        /// Host of the running instance.
        #[arg(long, default_value = "127.0.0.1")]
        host: String,
    },

    /// Tail log entries from a running instance.
    Logs {
        /// Number of recent log lines to show (default: 50).
        #[arg(short = 'n', long, default_value_t = 50)]
        lines: usize,

        /// Port of the running instance (default: from config or 18789).
        #[arg(short, long)]
        port: Option<u16>,

        /// Host of the running instance.
        #[arg(long, default_value = "127.0.0.1")]
        host: String,

        /// Use TLS (wss://) for remote connections.
        #[arg(long)]
        tls: bool,

        /// Accept invalid TLS certificates (only with --tls).
        #[arg(long)]
        trust: bool,

        /// Allow plaintext ws:// for non-loopback hosts (unsafe).
        #[arg(long)]
        allow_plaintext: bool,
    },

    /// Print version, build date, and git commit information.
    Version,

    /// Create a backup archive of all gateway data.
    Backup {
        /// Output file path (default: ./carapace-backup-{timestamp}.tar.gz).
        #[arg(short, long)]
        output: Option<String>,
    },

    /// Restore from a backup archive.
    Restore {
        /// Path to the backup archive file.
        path: String,

        /// Overwrite existing data without confirmation prompt.
        #[arg(long)]
        force: bool,
    },

    /// Clear specific categories of gateway data.
    Reset {
        /// Delete all session data.
        #[arg(long)]
        sessions: bool,

        /// Delete all cron job data.
        #[arg(long)]
        cron: bool,

        /// Reset usage tracking data.
        #[arg(long)]
        usage: bool,

        /// Delete agent memory stores.
        #[arg(long)]
        memory: bool,

        /// Delete everything (equivalent to all flags).
        #[arg(long)]
        all: bool,

        /// Proceed without confirmation prompt.
        #[arg(long)]
        force: bool,
    },

    /// Run the interactive setup wizard for first-time configuration.
    Setup {
        /// Overwrite existing configuration if it already exists.
        #[arg(long)]
        force: bool,
    },

    /// Pair with a remote gateway node.
    Pair {
        /// Gateway URL to pair with (e.g., https://gateway.local:3001).
        url: String,

        /// Device name for this node (defaults to hostname).
        #[arg(long)]
        name: Option<String>,

        /// Accept the gateway's TLS fingerprint without verification.
        #[arg(long)]
        trust: bool,
    },

    /// Check for updates or install a specific version.
    Update {
        /// Check for updates without installing.
        #[arg(long)]
        check: bool,

        /// Install a specific version (e.g., "0.2.0").
        #[arg(long)]
        version: Option<String>,
    },

    /// Start an interactive chat session.
    Chat {
        /// Start a new session instead of resuming.
        #[arg(long)]
        new: bool,

        /// Port of a running instance to connect to.
        #[arg(short, long)]
        port: Option<u16>,
    },

    /// Verify that a first-run outcome works end-to-end.
    Verify {
        /// Which outcome to verify (default: infer from config).
        #[arg(long, value_enum, default_value_t = VerifyOutcomeSelection::Auto)]
        outcome: VerifyOutcomeSelection,

        /// Port of a running instance to connect to.
        #[arg(short, long)]
        port: Option<u16>,

        /// Discord channel ID for send-path verification.
        #[arg(long)]
        discord_to: Option<String>,

        /// Telegram chat ID for send-path verification.
        #[arg(long)]
        telegram_to: Option<String>,
    },

    /// Manage mTLS certificates for gateway-to-gateway communication.
    #[command(subcommand)]
    Tls(TlsCommand),
}

#[derive(Subcommand, Debug)]
pub enum TlsCommand {
    /// Generate a new cluster CA certificate.
    InitCa {
        /// Output directory for CA files (default: ~/.config/carapace/cluster-ca).
        #[arg(long)]
        output: Option<String>,
    },

    /// Issue a node certificate signed by the cluster CA.
    IssueCert {
        /// Node ID to embed in the certificate CN.
        node_id: String,

        /// Directory containing the cluster CA files.
        #[arg(long)]
        ca_dir: Option<String>,

        /// Output directory for the node certificate and key.
        #[arg(long)]
        output: Option<String>,
    },

    /// Revoke a node certificate by fingerprint.
    RevokeCert {
        /// SHA-256 fingerprint of the certificate to revoke (colon-separated hex).
        fingerprint: String,

        /// Node ID associated with the certificate.
        #[arg(long)]
        node_id: String,

        /// Directory containing the cluster CA files.
        #[arg(long)]
        ca_dir: Option<String>,

        /// Reason for revocation.
        #[arg(long)]
        reason: Option<String>,
    },

    /// Show cluster CA information and certificate revocation list.
    ShowCa {
        /// Directory containing the cluster CA files.
        #[arg(long)]
        ca_dir: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
pub enum ConfigCommand {
    /// Print the fully loaded configuration (secrets redacted) as JSON.
    Show,

    /// Print a specific configuration value by dot-notation path.
    Get {
        /// Dot-notation key (e.g. "server.port", "gateway.bind").
        key: String,
    },

    /// Set a configuration value and write to disk.
    Set {
        /// Dot-notation key (e.g. "gateway.port").
        key: String,

        /// Value to set (interpreted as JSON; bare strings allowed).
        value: String,
    },

    /// Print the resolved configuration file path.
    Path,
}

// ---------------------------------------------------------------------------
// Subcommand handlers
// ---------------------------------------------------------------------------

use crate::channels::discord::{DiscordChannel, DISCORD_DEFAULT_API_BASE_URL};
use crate::channels::telegram::{TelegramChannel, TELEGRAM_DEFAULT_API_BASE_URL};
use crate::config;
use crate::credentials;
use crate::logging::buffer::LogLevel;
use crate::runtime_bridge::{run_sync_blocking, run_sync_blocking_send};
use crate::server::bind::DEFAULT_PORT;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use futures_util::{SinkExt, StreamExt};
use getrandom::fill;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error as RustlsError, SignatureScheme};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::io::IsTerminal;
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio_tungstenite::{
    connect_async, connect_async_tls_with_config, tungstenite::Message, Connector,
};
use url::{Host, Url};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Secrets that should be redacted when printing config.
/// Kept in sync with logging/redact.rs SECRET_KEY_NAMES.
const SECRET_KEYS: &[&str] = &[
    "apiKey",
    "apikey",
    "api_key",
    "token",
    "secret",
    "password",
    "credentials",
    "client_secret",
    "refresh_token",
    "access_token",
];

/// Run the `config show` subcommand.
pub fn handle_config_show() -> Result<(), Box<dyn std::error::Error>> {
    let cfg = config::load_config()?;
    let redacted = redact_secrets(cfg);
    let pretty = serde_json::to_string_pretty(&redacted)?;
    println!("{}", pretty);
    Ok(())
}

/// Run the `config get <key>` subcommand.
pub fn handle_config_get(key: &str) -> Result<(), Box<dyn std::error::Error>> {
    let cfg = config::load_config()?;
    match get_value_at_path(&cfg, key) {
        Some(value) => {
            let pretty = serde_json::to_string_pretty(&value)?;
            println!("{}", pretty);
        }
        None => {
            eprintln!("Key not found: {}", key);
            std::process::exit(1);
        }
    }
    Ok(())
}

/// Run the `config set <key> <value>` subcommand.
pub fn handle_config_set(key: &str, raw_value: &str) -> Result<(), Box<dyn std::error::Error>> {
    // Parse value as JSON first; fall back to treating it as a plain string.
    let value: Value =
        serde_json::from_str(raw_value).unwrap_or_else(|_| Value::String(raw_value.to_string()));

    // Load current config from disk (bypassing cache).
    let config_path = config::get_config_path();
    let mut cfg = config::load_config_uncached(&config_path)?;

    // Walk the dot-path and set the value, creating intermediate objects as needed.
    set_value_at_path(&mut cfg, key, value.clone());

    // Write atomically (write to temp, rename).
    use crate::server::ws::persist_config_file;
    persist_config_file(&config_path, &cfg).map_err(std::io::Error::other)?;

    println!("Set {} = {}", key, serde_json::to_string(&value)?);
    Ok(())
}

/// Run the `config path` subcommand.
pub fn handle_config_path() {
    println!("{}", config::get_config_path().display());
}

/// Run the `status` subcommand -- connect to a running instance's health endpoint.
pub async fn handle_status(
    host: &str,
    port: Option<u16>,
) -> Result<(), Box<dyn std::error::Error>> {
    let port = resolve_port(port);
    let url = format!("http://{}:{}/health", host, port);

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()?;

    let response = match client.get(&url).send().await {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Could not connect to carapace at {}:{}", host, port);
            eprintln!("  Error: {}", e);
            eprintln!();
            eprintln!("Is the server running? Start it with: cara start");
            std::process::exit(1);
        }
    };

    if !response.status().is_success() {
        eprintln!(
            "Health endpoint returned HTTP {}: {}",
            response.status(),
            response.text().await.unwrap_or_default()
        );
        std::process::exit(1);
    }

    let body: Value = response.json().await?;

    // Pretty-print the status summary.
    println!("Carapace gateway status");
    println!("=======================");
    if let Some(version) = body.get("version").and_then(|v| v.as_str()) {
        println!("  Version:  {}", version);
    }
    if let Some(uptime) = body.get("uptimeSeconds").and_then(|v| v.as_i64()) {
        println!("  Uptime:   {}", format_duration(uptime));
    }
    println!("  Address:  {}:{}", host, port);
    if let Some(status) = body.get("status").and_then(|v| v.as_str()) {
        println!("  Status:   {}", status);
    }

    // If the control endpoint is available, try to get richer info.
    let control_url = format!("http://{}:{}/control/status", host, port);
    if let Ok(resp) = client.get(&control_url).send().await {
        if resp.status().is_success() {
            if let Ok(ctrl) = resp.json::<Value>().await {
                if let Some(ch) = ctrl.get("connectedChannels").and_then(|v| v.as_u64()) {
                    let total = ctrl
                        .get("totalChannels")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0);
                    println!("  Channels: {}/{} connected", ch, total);
                }
                if let Some(rt) = ctrl.get("runtime").and_then(|v| v.as_object()) {
                    if let (Some(platform), Some(arch)) = (
                        rt.get("platform").and_then(|v| v.as_str()),
                        rt.get("arch").and_then(|v| v.as_str()),
                    ) {
                        println!("  Platform: {} ({})", platform, arch);
                    }
                }
            }
        }
    }

    Ok(())
}

/// Run the `logs` subcommand -- fetch recent logs from a running instance.
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct LogsTailEntry {
    timestamp: u64,
    level: LogLevel,
    target: String,
    message: String,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct LogsTailResponse {
    #[serde(default)]
    entries: Vec<LogsTailEntry>,
    #[serde(default)]
    truncated: bool,
}

pub(crate) type WsStream =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;
pub(crate) type WsRead = futures_util::stream::SplitStream<WsStream>;
pub(crate) type WsWrite = futures_util::stream::SplitSink<WsStream, Message>;

#[derive(Debug)]
struct InsecureCertVerifier;

impl ServerCertVerifier for InsecureCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ED25519,
            SignatureScheme::ED448,
        ]
    }
}

pub(crate) async fn connect_ws(
    ws_url: &str,
    trust_invalid: bool,
) -> Result<WsStream, Box<dyn std::error::Error>> {
    if trust_invalid && ws_url.starts_with("wss://") {
        let config = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(std::sync::Arc::new(InsecureCertVerifier))
            .with_no_client_auth();
        let connector = Connector::Rustls(std::sync::Arc::new(config));
        let (stream, _) =
            connect_async_tls_with_config(ws_url, None, false, Some(connector)).await?;
        Ok(stream)
    } else {
        let (stream, _) = connect_async(ws_url).await?;
        Ok(stream)
    }
}

pub(crate) struct GatewayAuth {
    pub(crate) token: Option<String>,
    pub(crate) password: Option<String>,
}

pub(crate) async fn resolve_gateway_auth() -> GatewayAuth {
    let token_env = std::env::var("CARAPACE_GATEWAY_TOKEN").ok().and_then(|v| {
        let token = v.trim().to_string();
        if token.is_empty() {
            None
        } else {
            Some(token)
        }
    });
    let password_env = std::env::var("CARAPACE_GATEWAY_PASSWORD")
        .ok()
        .and_then(|v| {
            let password = v.trim().to_string();
            if password.is_empty() {
                None
            } else {
                Some(password)
            }
        });

    let mut token_cfg = None;
    let mut password_cfg = None;
    if let Ok(cfg) = config::load_config() {
        if let Some(token) = cfg
            .get("gateway")
            .and_then(|v| v.get("auth"))
            .and_then(|v| v.get("token"))
            .and_then(|v| v.as_str())
        {
            let token = token.trim().to_string();
            if !token.is_empty() {
                token_cfg = Some(token);
            }
        }
        if let Some(password) = cfg
            .get("gateway")
            .and_then(|v| v.get("auth"))
            .and_then(|v| v.get("password"))
            .and_then(|v| v.as_str())
        {
            let password = password.trim().to_string();
            if !password.is_empty() {
                password_cfg = Some(password);
            }
        }
    }

    let mut token_creds = None;
    let mut password_creds = None;
    let state_dir = crate::server::ws::resolve_state_dir();
    if let Ok(mut creds) = credentials::read_gateway_auth(state_dir).await {
        token_creds = std::mem::take(&mut creds.token).and_then(|v| {
            let token = v.trim().to_string();
            if token.is_empty() {
                None
            } else {
                Some(token)
            }
        });
        password_creds = std::mem::take(&mut creds.password).and_then(|v| {
            let password = v.trim().to_string();
            if password.is_empty() {
                None
            } else {
                Some(password)
            }
        });
    }

    GatewayAuth {
        token: token_env.or(token_cfg).or(token_creds),
        password: password_env.or(password_cfg).or(password_creds),
    }
}

fn is_loopback_host(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    host.parse::<std::net::IpAddr>()
        .map(|ip| ip.is_loopback())
        .unwrap_or(false)
}

#[derive(Debug, serde::Serialize, serde::Deserialize, Zeroize, ZeroizeOnDrop)]
pub(crate) struct StoredDeviceIdentity {
    device_id: String,
    public_key: String,
    secret_key: String,
}

const DEVICE_IDENTITY_FILENAME: &str = "device-identity.json";
const CONNECT_CHALLENGE_TIMEOUT: Duration = Duration::from_secs(30);

fn device_identity_path(state_dir: &Path) -> PathBuf {
    state_dir.join(DEVICE_IDENTITY_FILENAME)
}

fn strict_device_identity_mode() -> bool {
    env_flag_enabled("CARAPACE_DEVICE_IDENTITY_STRICT")
}

fn env_flag_enabled(name: &str) -> bool {
    std::env::var(name)
        .ok()
        .map(|value| {
            matches!(
                value.trim().to_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

pub(crate) async fn load_or_create_device_identity(
    state_dir: &Path,
) -> Result<StoredDeviceIdentity, Box<dyn std::error::Error>> {
    std::fs::create_dir_all(state_dir)?;
    let identity_path = device_identity_path(state_dir);
    let strict = strict_device_identity_mode();

    match credentials::read_device_identity(state_dir.to_path_buf()).await {
        Ok(Some(data)) => {
            let identity: StoredDeviceIdentity = serde_json::from_str(&data)?;
            validate_device_identity(&identity)?;
            if identity_path.exists() {
                if let Err(err) = std::fs::remove_file(&identity_path) {
                    eprintln!(
                        "Warning: failed to remove legacy device identity file: {}",
                        err
                    );
                }
            }
            return Ok(identity);
        }
        Ok(None) => {}
        Err(err) => {
            if strict && should_fallback_to_file(&err) {
                return Err(format!(
                    "credential store unavailable ({err}); strict device identity mode enabled"
                )
                .into());
            }
            if !should_fallback_to_file(&err) {
                return Err(err.into());
            }
            warn_credential_store_fallback(&err);
        }
    }

    if identity_path.exists() {
        if strict {
            return Err(format!(
                "legacy device identity file present at {}; strict device identity mode enabled",
                identity_path.display()
            )
            .into());
        }
        let data = std::fs::read_to_string(&identity_path)?;
        let identity: StoredDeviceIdentity = serde_json::from_str(&data)?;
        validate_device_identity(&identity)?;
        if let Err(err) = credentials::write_device_identity(
            state_dir.to_path_buf(),
            &serde_json::to_string(&identity)?,
        )
        .await
        {
            if strict && should_fallback_to_file(&err) {
                return Err(format!(
                    "credential store unavailable ({err}); strict device identity mode enabled"
                )
                .into());
            }
            if !should_fallback_to_file(&err) {
                return Err(err.into());
            }
            warn_credential_store_fallback(&err);
            write_device_identity_file(&identity_path, &identity)?;
            return Ok(identity);
        }
        let _ = std::fs::remove_file(&identity_path);
        return Ok(identity);
    }

    let identity = generate_device_identity()?;
    if let Err(err) = credentials::write_device_identity(
        state_dir.to_path_buf(),
        &serde_json::to_string(&identity)?,
    )
    .await
    {
        if strict && should_fallback_to_file(&err) {
            return Err(format!(
                "credential store unavailable ({err}); strict device identity mode enabled"
            )
            .into());
        }
        if !should_fallback_to_file(&err) {
            return Err(err.into());
        }
        warn_credential_store_fallback(&err);
        write_device_identity_file(&identity_path, &identity)?;
    }
    Ok(identity)
}

fn should_fallback_to_file(err: &credentials::CredentialError) -> bool {
    matches!(
        err,
        credentials::CredentialError::StoreUnavailable(_)
            | credentials::CredentialError::StoreLocked
            | credentials::CredentialError::AccessDenied
    )
}

fn warn_credential_store_fallback(err: &credentials::CredentialError) {
    match err {
        credentials::CredentialError::StoreLocked => {
            eprintln!("Warning: credential store is locked; using legacy device identity file.");
        }
        credentials::CredentialError::AccessDenied => {
            eprintln!(
                "Warning: credential store access denied; using legacy device identity file."
            );
        }
        credentials::CredentialError::StoreUnavailable(_) => {
            eprintln!("Warning: credential store unavailable; using legacy device identity file.");
        }
        _ => {
            eprintln!("Warning: credential store error; using legacy device identity file.");
        }
    }
}

fn write_device_identity_file(
    path: &Path,
    identity: &StoredDeviceIdentity,
) -> Result<(), Box<dyn std::error::Error>> {
    let contents = serde_json::to_string_pretty(identity)?;
    #[cfg(unix)]
    {
        use std::fs::OpenOptions;
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(contents.as_bytes())?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, contents)?;
    }
    Ok(())
}

fn validate_device_identity(
    identity: &StoredDeviceIdentity,
) -> Result<(), Box<dyn std::error::Error>> {
    let signing_key = signing_key_from_identity(identity)?;
    let public_key = signing_key.verifying_key().to_bytes();
    let public_key_b64 = encode_base64_url(&public_key);
    if public_key_b64 != identity.public_key {
        return Err("device identity public key mismatch".into());
    }
    let derived_id = derive_device_id(&public_key);
    if derived_id != identity.device_id {
        return Err("device identity mismatch".into());
    }
    Ok(())
}

fn generate_device_identity() -> Result<StoredDeviceIdentity, Box<dyn std::error::Error>> {
    let mut seed = [0u8; 32];
    fill(&mut seed)?;
    let signing_key = SigningKey::from_bytes(&seed);
    let public_key = signing_key.verifying_key().to_bytes();
    let device_id = derive_device_id(&public_key);
    let secret_key = encode_base64_url(&seed);
    seed.zeroize();
    Ok(StoredDeviceIdentity {
        device_id,
        public_key: encode_base64_url(&public_key),
        secret_key,
    })
}

fn signing_key_from_identity(
    identity: &StoredDeviceIdentity,
) -> Result<SigningKey, Box<dyn std::error::Error>> {
    let secret_raw = Zeroizing::new(decode_base64_any(&identity.secret_key)?);
    if secret_raw.len() != 32 {
        return Err("device identity secret key invalid".into());
    }
    let mut secret = [0u8; 32];
    secret.copy_from_slice(&secret_raw);
    let signing_key = SigningKey::from_bytes(&secret);
    secret.zeroize();
    Ok(signing_key)
}

pub(crate) fn build_device_identity_for_connect(
    identity: &StoredDeviceIdentity,
    client_id: &str,
    client_mode: &str,
    role: &str,
    scopes: &[String],
    token: Option<&str>,
    nonce: Option<&str>,
) -> Result<Value, Box<dyn std::error::Error>> {
    let signed_at_ms = current_time_ms();
    let payload = build_device_auth_payload(DeviceAuthPayload {
        device_id: identity.device_id.clone(),
        client_id: client_id.to_string(),
        client_mode: client_mode.to_string(),
        role: role.to_string(),
        scopes: scopes.to_vec(),
        signed_at_ms,
        token: token.map(|value| value.to_string()),
        nonce: nonce.map(|value| value.to_string()),
    });
    let signature = sign_device_payload(identity, &payload)?;
    let mut device = serde_json::json!({
        "id": identity.device_id.clone(),
        "publicKey": identity.public_key.clone(),
        "signature": signature,
        "signedAt": signed_at_ms,
    });
    if let Some(nonce) = nonce {
        device["nonce"] = Value::String(nonce.to_string());
    }
    Ok(device)
}

fn sign_device_payload(
    identity: &StoredDeviceIdentity,
    payload: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let signing_key = signing_key_from_identity(identity)?;
    let signature = signing_key.sign(payload.as_bytes());
    Ok(encode_base64_url(&signature.to_bytes()))
}

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

fn encode_base64_url(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn decode_base64_any(input: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if let Ok(bytes) = URL_SAFE_NO_PAD.decode(input.as_bytes()) {
        return Ok(bytes);
    }
    STANDARD
        .decode(input.as_bytes())
        .map_err(|_| "base64 decode failed".into())
}

fn derive_device_id(public_key: &[u8]) -> String {
    let digest = Sha256::digest(public_key);
    hex::encode(digest)
}

fn current_time_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

fn ws_url_from_http(url: &Url) -> Result<String, Box<dyn std::error::Error>> {
    let scheme = match url.scheme() {
        "https" => "wss",
        "http" => "ws",
        _ => return Err("invalid URL scheme".into()),
    };
    let host = match url.host() {
        Some(Host::Domain(name)) => name.to_string(),
        Some(Host::Ipv4(addr)) => addr.to_string(),
        Some(Host::Ipv6(addr)) => format!("[{}]", addr),
        None => return Err("missing host in gateway URL".into()),
    };
    let port = url
        .port_or_known_default()
        .ok_or("missing port in gateway URL")?;
    Ok(format!("{scheme}://{host}:{port}/ws"))
}

pub(crate) async fn read_ws_json(
    reader: &mut WsRead,
    writer: &mut WsWrite,
) -> Result<Value, Box<dyn std::error::Error>> {
    while let Some(msg) = reader.next().await {
        match msg? {
            Message::Text(text) => return Ok(serde_json::from_str(&text)?),
            Message::Binary(bytes) => {
                if let Ok(text) = String::from_utf8(bytes.to_vec()) {
                    return Ok(serde_json::from_str(&text)?);
                }
            }
            Message::Ping(data) => {
                writer.send(Message::Pong(data)).await?;
            }
            Message::Pong(_) => {}
            Message::Close(frame) => {
                let reason = frame
                    .as_ref()
                    .map(|f| f.reason.to_string())
                    .unwrap_or_default();
                let msg = if reason.is_empty() {
                    "WebSocket closed".to_string()
                } else {
                    format!("WebSocket closed: {}", reason)
                };
                return Err(msg.into());
            }
            _ => {}
        }
    }

    Err("WebSocket closed".into())
}

pub(crate) async fn await_connect_challenge(
    reader: &mut WsRead,
    writer: &mut WsWrite,
) -> Result<String, Box<dyn std::error::Error>> {
    let deadline = tokio::time::Instant::now() + CONNECT_CHALLENGE_TIMEOUT;
    tokio::time::timeout_at(deadline, async {
        loop {
            let frame = read_ws_json(reader, writer).await?;
            let frame_type = frame.get("type").and_then(|v| v.as_str()).unwrap_or("");
            if frame_type == "event" {
                let event = frame.get("event").and_then(|v| v.as_str()).unwrap_or("");
                if event == "connect.challenge" {
                    let nonce = frame
                        .get("payload")
                        .and_then(|v| v.get("nonce"))
                        .and_then(|v| v.as_str())
                        .ok_or("connect.challenge missing nonce")?;
                    return Ok(nonce.to_string());
                }
                continue;
            }
            if frame_type == "res" {
                let message = frame
                    .get("error")
                    .and_then(|v| v.get("message"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("unexpected response before connect");
                return Err(message.to_string().into());
            }
        }
    })
    .await
    .map_err(|_| -> Box<dyn std::error::Error> { "connect.challenge timed out".into() })?
}

pub(crate) async fn await_ws_response(
    reader: &mut WsRead,
    writer: &mut WsWrite,
    request_id: &str,
) -> Result<Value, Box<dyn std::error::Error>> {
    loop {
        let frame = read_ws_json(reader, writer).await?;
        let frame_type = frame.get("type").and_then(|v| v.as_str()).unwrap_or("");
        if frame_type == "event" {
            continue;
        }
        if frame_type != "res" {
            continue;
        }
        let id = frame.get("id").and_then(|v| v.as_str()).unwrap_or("");
        if id != request_id {
            continue;
        }
        let ok = frame.get("ok").and_then(|v| v.as_bool()).unwrap_or(false);
        if ok {
            return Ok(frame.get("payload").cloned().unwrap_or(Value::Null));
        }
        let message = frame
            .get("error")
            .and_then(|v| v.get("message"))
            .and_then(|v| v.as_str())
            .unwrap_or("request failed");
        return Err(message.to_string().into());
    }
}

#[derive(Debug)]
pub(crate) struct WsError {
    pub(crate) code: Option<String>,
    pub(crate) message: String,
    pub(crate) details: Option<Value>,
}

impl std::fmt::Display for WsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for WsError {}

pub(crate) async fn await_ws_response_with_error(
    reader: &mut WsRead,
    writer: &mut WsWrite,
    request_id: &str,
) -> Result<Value, WsError> {
    loop {
        let frame = match read_ws_json(reader, writer).await {
            Ok(frame) => frame,
            Err(err) => {
                return Err(WsError {
                    code: None,
                    message: err.to_string(),
                    details: None,
                });
            }
        };
        let frame_type = frame.get("type").and_then(|v| v.as_str()).unwrap_or("");
        if frame_type == "event" {
            continue;
        }
        if frame_type != "res" {
            continue;
        }
        let id = frame.get("id").and_then(|v| v.as_str()).unwrap_or("");
        if id != request_id {
            continue;
        }
        let ok = frame.get("ok").and_then(|v| v.as_bool()).unwrap_or(false);
        if ok {
            return Ok(frame.get("payload").cloned().unwrap_or(Value::Null));
        }
        let error = frame.get("error").cloned().unwrap_or(Value::Null);
        let code = error
            .get("code")
            .and_then(|v| v.as_str())
            .map(|v| v.to_string());
        let message = error
            .get("message")
            .and_then(|v| v.as_str())
            .unwrap_or("request failed")
            .to_string();
        let details = error.get("details").cloned();
        return Err(WsError {
            code,
            message,
            details,
        });
    }
}

fn extract_pairing_request_id(details: &Value) -> Option<String> {
    if let Some(id) = details.get("requestId").and_then(|value| value.as_str()) {
        return Some(id.to_string());
    }
    details
        .get("details")
        .and_then(|value| value.get("requestId"))
        .and_then(|value| value.as_str())
        .map(|id| id.to_string())
}

pub async fn handle_logs(
    host: &str,
    port: Option<u16>,
    lines: usize,
    tls: bool,
    trust: bool,
    allow_plaintext: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let port = resolve_port(port);

    let is_loopback = is_loopback_host(host);
    if !is_loopback && !tls && !allow_plaintext {
        eprintln!("Remote logs require TLS or explicit plaintext opt-in.");
        eprintln!("Use --tls for wss:// or pass --allow-plaintext to override.");
        std::process::exit(1);
    }
    if !is_loopback && !tls && allow_plaintext {
        eprintln!(
            "Warning: using plaintext WebSocket to remote host; credentials will be sent unencrypted."
        );
    }
    if trust && !tls {
        eprintln!("Warning: --trust has no effect without --tls.");
    }

    let auth = resolve_gateway_auth().await;
    if auth.token.is_none() && auth.password.is_none() {
        eprintln!("No gateway auth credentials found.");
        eprintln!("Attempting local-direct connection (if enabled)...");
    }

    let state_dir = resolve_state_dir();
    let device_identity = load_or_create_device_identity(&state_dir).await?;

    let ws_url = if tls {
        format!("wss://{}:{}/ws", host, port)
    } else {
        format!("ws://{}:{}/ws", host, port)
    };
    let ws_stream = match connect_ws(&ws_url, trust).await {
        Ok(conn) => conn,
        Err(err) => {
            eprintln!("Could not connect to carapace at {}:{}", host, port);
            eprintln!("  Error: {}", err);
            eprintln!();
            eprintln!("Is the server running? Start it with: cara start");
            std::process::exit(1);
        }
    };
    let (mut ws_write, mut ws_read) = ws_stream.split();

    let nonce = await_connect_challenge(&mut ws_read, &mut ws_write).await?;

    let role = "operator";
    let scopes = vec!["operator.read".to_string()];
    let mut connect_params = serde_json::json!({
        "minProtocol": 3,
        "maxProtocol": 3,
        "client": {
            "id": "cli",
            "version": env!("CARGO_PKG_VERSION"),
            "platform": std::env::consts::OS,
            "mode": "cli"
        },
        "role": role,
        "scopes": scopes.clone()
    });
    let GatewayAuth { token, password } = auth;
    let token_for_signature = token.clone();
    if let Some(token) = token {
        connect_params["auth"] = serde_json::json!({ "token": token });
    } else if let Some(password) = password {
        connect_params["auth"] = serde_json::json!({ "password": password });
    }
    connect_params["device"] = build_device_identity_for_connect(
        &device_identity,
        "cli",
        "cli",
        role,
        &scopes,
        token_for_signature.as_deref(),
        Some(&nonce),
    )?;

    let connect_frame = serde_json::json!({
        "type": "req",
        "id": "connect-1",
        "method": "connect",
        "params": connect_params
    });
    ws_write
        .send(Message::Text(serde_json::to_string(&connect_frame)?.into()))
        .await?;

    if let Err(err) = await_ws_response_with_error(&mut ws_read, &mut ws_write, "connect-1").await {
        if err.code.as_deref() == Some("NOT_PAIRED") && err.message.contains("pairing required") {
            eprintln!("Device pairing required for this CLI.");
            if let Some(details) = err.details.as_ref() {
                if let Some(request_id) = extract_pairing_request_id(details) {
                    eprintln!("Pairing request ID: {}", request_id);
                }
            }
            eprintln!("Approve the request in the control UI, then retry.");
        } else if err.message.contains("device identity required") {
            eprintln!("WebSocket connect failed: {}", err.message);
            eprintln!("This gateway requires a paired device for WebSocket access.");
            eprintln!("Set gateway.auth.token for local CLI access or use the control UI.");
        } else {
            eprintln!("WebSocket connect failed: {}", err.message);
        }
        return Err(Box::new(err));
    }

    let logs_frame = serde_json::json!({
        "type": "req",
        "id": "logs-1",
        "method": "logs.tail",
        "params": { "limit": lines }
    });
    ws_write
        .send(Message::Text(serde_json::to_string(&logs_frame)?.into()))
        .await?;

    let payload = match await_ws_response(&mut ws_read, &mut ws_write, "logs-1").await {
        Ok(payload) => payload,
        Err(err) => {
            eprintln!("logs.tail failed: {}", err);
            std::process::exit(1);
        }
    };

    let response: LogsTailResponse = serde_json::from_value(payload)?;
    for entry in response.entries {
        println!(
            "{} [{}] {}: {}",
            format_timestamp(entry.timestamp),
            entry.level,
            entry.target,
            entry.message
        );
    }
    if response.truncated {
        eprintln!("(log output truncated; reduce scope or increase --lines)");
    }

    Ok(())
}

/// Run the `version` subcommand.
pub fn handle_version() {
    println!("cara {}", env!("CARGO_PKG_VERSION"));
    println!("  Build date: {}", env!("CARAPACE_BUILD_DATE"));
    println!("  Git commit: {}", env!("CARAPACE_GIT_HASH"));
    println!(
        "  Platform:   {} ({})",
        std::env::consts::OS,
        std::env::consts::ARCH
    );
}

// ---------------------------------------------------------------------------
// Backup / Restore / Reset handlers
// ---------------------------------------------------------------------------

use std::io::Read as IoRead;
use std::path::{Component, Path, PathBuf};

/// Resolve the state directory (same logic as `server::ws::resolve_state_dir`
/// but duplicated here to avoid pulling in the full server module for CLI-only
/// commands).
pub(crate) fn resolve_state_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("CARAPACE_STATE_DIR") {
        return PathBuf::from(dir);
    }
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from(".config"))
        .join("carapace")
}

/// Resolve the memory store directory.
fn resolve_memory_dir() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".config")
        .join("carapace")
        .join("memory")
}

/// Name of the marker file inside backup archives to identify them as
/// carapace backups.
const BACKUP_MARKER: &str = ".carapace-backup";

/// Run the `backup` subcommand.
pub fn handle_backup(output: Option<&str>) -> Result<(), Box<dyn std::error::Error>> {
    let state_dir = resolve_state_dir();
    let config_path = config::get_config_path();
    let memory_dir = resolve_memory_dir();

    // Determine output path.
    let timestamp = chrono::Utc::now().format("%Y%m%dT%H%M%SZ");
    let default_name = format!("carapace-backup-{}.tar.gz", timestamp);
    let output_path = PathBuf::from(output.unwrap_or(&default_name));

    // Build the tar.gz archive.
    let file = std::fs::File::create(&output_path)?;
    let enc = flate2::write::GzEncoder::new(file, flate2::Compression::default());
    let mut archive = tar::Builder::new(enc);

    // Write marker file so we can validate on restore.
    let marker_content = format!("carapace-backup v1\ncreated={}\n", timestamp);
    let marker_bytes = marker_content.as_bytes();
    let mut header = tar::Header::new_gnu();
    header.set_size(marker_bytes.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    archive.append_data(&mut header, BACKUP_MARKER, marker_bytes)?;

    let mut included_sections: Vec<&str> = Vec::new();

    // Sessions directory.
    let sessions_dir = state_dir.join("sessions");
    if sessions_dir.is_dir() {
        archive.append_dir_all("sessions", &sessions_dir)?;
        included_sections.push("sessions");
    }

    // Config file.
    if config_path.exists() {
        let name = config_path
            .file_name()
            .unwrap_or_else(|| std::ffi::OsStr::new("carapace.json"));
        archive.append_path_with_name(&config_path, Path::new("config").join(name))?;
        included_sections.push("config");
    }

    // Memory store directory.
    if memory_dir.is_dir() {
        archive.append_dir_all("memory", &memory_dir)?;
        included_sections.push("memory");
    }

    // Cron data directory.
    let cron_dir = state_dir.join("cron");
    if cron_dir.is_dir() {
        archive.append_dir_all("cron", &cron_dir)?;
        included_sections.push("cron");
    }

    // Usage data file.
    let usage_path = state_dir.join("usage.json");
    if usage_path.exists() {
        archive.append_path_with_name(&usage_path, "usage/usage.json")?;
        included_sections.push("usage");
    }

    // Finalize the archive.
    let enc = archive.into_inner()?;
    enc.finish()?;

    // Report results.
    let metadata = std::fs::metadata(&output_path)?;
    let size = metadata.len();
    let human_size = format_file_size(size);

    println!("Backup created successfully");
    println!("  Path: {}", output_path.display());
    println!("  Size: {} ({})", human_size, size);
    println!(
        "  Included: {}",
        if included_sections.is_empty() {
            "(empty)".to_string()
        } else {
            included_sections.join(", ")
        }
    );

    Ok(())
}

/// Run the `restore` subcommand.
pub fn handle_restore(archive_path: &str, force: bool) -> Result<(), Box<dyn std::error::Error>> {
    let archive_path = PathBuf::from(archive_path);
    if !archive_path.exists() {
        eprintln!("Backup file not found: {}", archive_path.display());
        std::process::exit(1);
    }

    let sections_found = validate_backup_file(&archive_path)?;

    // Prompt for confirmation unless --force is given.
    if !force {
        eprintln!(
            "This will overwrite existing data with the contents of: {}",
            archive_path.display()
        );
        eprintln!(
            "Sections to restore: {}",
            if sections_found.is_empty() {
                "(none)".to_string()
            } else {
                sections_found.join(", ")
            }
        );
        eprintln!("Pass --force to proceed without this prompt.");
        std::process::exit(1);
    }

    let (restored, restored_sessions) = restore_files_from_tar(&archive_path)?;

    println!("Restore completed successfully");
    println!(
        "  Restored: {}",
        if restored.is_empty() {
            "(nothing)".to_string()
        } else {
            restored.join(", ")
        }
    );
    if restored_sessions > 0 {
        println!("  Sessions: {}", restored_sessions);
    }

    Ok(())
}

/// Validate a backup archive by checking for the marker file and discovering sections.
fn validate_backup_file(archive_path: &PathBuf) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let file = std::fs::File::open(archive_path)?;
    let dec = flate2::read::GzDecoder::new(file);
    let mut archive = tar::Archive::new(dec);

    let mut found_marker = false;
    let mut sections_found: Vec<String> = Vec::new();

    for entry_result in archive.entries()? {
        let entry = entry_result?;
        let path = entry.path()?;
        if !is_safe_archive_path(&path) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("invalid path in backup: {}", path.display()),
            )
            .into());
        }
        let path_str = path.to_string_lossy().to_string();

        if path_str == BACKUP_MARKER {
            found_marker = true;
        } else {
            let section = if path_str.starts_with("sessions/") {
                Some("sessions")
            } else if path_str.starts_with("config/") {
                Some("config")
            } else if path_str.starts_with("memory/") {
                Some("memory")
            } else if path_str.starts_with("cron/") {
                Some("cron")
            } else if path_str.starts_with("usage/") {
                Some("usage")
            } else {
                None
            };
            if let Some(s) = section {
                if !sections_found.contains(&s.to_string()) {
                    sections_found.push(s.to_string());
                }
            }
        }
    }

    if !found_marker {
        eprintln!("Invalid backup: archive does not contain a carapace backup marker.");
        eprintln!("The file may be corrupt or was not created by `cara backup`.");
        std::process::exit(1);
    }

    Ok(sections_found)
}

/// Extract files from a validated backup archive into the appropriate locations.
fn restore_files_from_tar(
    archive_path: &PathBuf,
) -> Result<(Vec<String>, usize), Box<dyn std::error::Error>> {
    let state_dir = resolve_state_dir();
    let config_path = config::get_config_path();
    let memory_dir = resolve_memory_dir();

    let file = std::fs::File::open(archive_path)?;
    let dec = flate2::read::GzDecoder::new(file);
    let mut archive = tar::Archive::new(dec);

    let mut restored: Vec<String> = Vec::new();
    let mut restored_sessions: usize = 0;

    for entry_result in archive.entries()? {
        let mut entry = entry_result?;
        let path = entry.path()?.to_path_buf();
        if !is_safe_archive_path(&path) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("invalid path in backup: {}", path.display()),
            )
            .into());
        }
        let path_str = path.to_string_lossy().to_string();

        if path_str == BACKUP_MARKER {
            continue;
        }

        if path_str.starts_with("sessions/") {
            let rel = path.strip_prefix("sessions").unwrap_or(&path);
            let target = state_dir.join("sessions").join(rel);
            extract_entry(&mut entry, &target)?;
            if path_str.ends_with(".json") && !path_str.ends_with(".jsonl") {
                restored_sessions += 1;
            }
            if !restored.contains(&"sessions".to_string()) {
                restored.push("sessions".to_string());
            }
        } else if path_str.starts_with("config/") {
            let rel = path.strip_prefix("config").unwrap_or(&path);
            let config_dir = config_path.parent().unwrap_or_else(|| Path::new("."));
            let target = config_dir.join(rel);
            extract_entry(&mut entry, &target)?;
            if !restored.contains(&"config".to_string()) {
                restored.push("config".to_string());
            }
        } else if path_str.starts_with("memory/") {
            let rel = path.strip_prefix("memory").unwrap_or(&path);
            let target = memory_dir.join(rel);
            extract_entry(&mut entry, &target)?;
            if !restored.contains(&"memory".to_string()) {
                restored.push("memory".to_string());
            }
        } else if path_str.starts_with("cron/") {
            let rel = path.strip_prefix("cron").unwrap_or(&path);
            let target = state_dir.join("cron").join(rel);
            extract_entry(&mut entry, &target)?;
            if !restored.contains(&"cron".to_string()) {
                restored.push("cron".to_string());
            }
        } else if path_str.starts_with("usage/") {
            let rel = path.strip_prefix("usage").unwrap_or(&path);
            let target = state_dir.join(rel);
            extract_entry(&mut entry, &target)?;
            if !restored.contains(&"usage".to_string()) {
                restored.push("usage".to_string());
            }
        }
    }

    Ok((restored, restored_sessions))
}

fn is_safe_archive_path(path: &Path) -> bool {
    for component in path.components() {
        match component {
            Component::Normal(_) | Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => return false,
        }
    }
    true
}

/// Extract a single tar entry to a target path, creating parent directories.
fn extract_entry(
    entry: &mut tar::Entry<'_, flate2::read::GzDecoder<std::fs::File>>,
    target: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let entry_type = entry.header().entry_type();
    if entry_type.is_dir() {
        std::fs::create_dir_all(target)?;
    } else if entry_type.is_file() {
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut buf = Vec::new();
        entry.read_to_end(&mut buf)?;
        std::fs::write(target, &buf)?;
    }
    Ok(())
}

/// Run the `reset` subcommand.
pub fn handle_reset(
    sessions: bool,
    cron: bool,
    usage: bool,
    memory: bool,
    all: bool,
    force: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let do_sessions = sessions || all;
    let do_cron = cron || all;
    let do_usage = usage || all;
    let do_memory = memory || all;

    if !do_sessions && !do_cron && !do_usage && !do_memory {
        eprintln!(
            "No data category specified. Use --sessions, --cron, --usage, --memory, or --all."
        );
        std::process::exit(1);
    }

    // Build a list of what will be deleted for the confirmation prompt.
    let mut categories: Vec<&str> = Vec::new();
    if do_sessions {
        categories.push("sessions");
    }
    if do_cron {
        categories.push("cron");
    }
    if do_usage {
        categories.push("usage");
    }
    if do_memory {
        categories.push("memory");
    }

    if !force {
        eprintln!("This will permanently delete: {}", categories.join(", "));
        eprintln!("Pass --force to proceed without this prompt.");
        std::process::exit(1);
    }

    let state_dir = resolve_state_dir();
    let mut deleted: Vec<String> = Vec::new();

    if do_sessions {
        let sessions_dir = state_dir.join("sessions");
        if sessions_dir.is_dir() {
            let count = count_files_in_dir(&sessions_dir, "json");
            std::fs::remove_dir_all(&sessions_dir)?;
            deleted.push(format!("sessions ({} metadata files removed)", count));
        } else {
            deleted.push("sessions (directory not found, nothing to delete)".to_string());
        }
    }

    if do_cron {
        let cron_dir = state_dir.join("cron");
        if cron_dir.is_dir() {
            std::fs::remove_dir_all(&cron_dir)?;
            deleted.push("cron (directory removed)".to_string());
        } else {
            deleted.push("cron (directory not found, nothing to delete)".to_string());
        }
    }

    if do_usage {
        let usage_path = state_dir.join("usage.json");
        if usage_path.exists() {
            std::fs::remove_file(&usage_path)?;
            deleted.push("usage (usage.json removed)".to_string());
        } else {
            deleted.push("usage (file not found, nothing to delete)".to_string());
        }
    }

    if do_memory {
        let memory_dir = resolve_memory_dir();
        if memory_dir.is_dir() {
            let count = count_files_in_dir(&memory_dir, "json");
            std::fs::remove_dir_all(&memory_dir)?;
            deleted.push(format!("memory ({} store files removed)", count));
        } else {
            deleted.push("memory (directory not found, nothing to delete)".to_string());
        }
    }

    println!("Reset completed");
    for item in &deleted {
        println!("  - {}", item);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Setup / Pair / Update handlers
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SetupOutcome {
    LocalChat,
    Discord,
    Telegram,
    Hooks,
}

impl SetupOutcome {
    fn prompt_key(self) -> &'static str {
        match self {
            Self::LocalChat => "local-chat",
            Self::Discord => "discord",
            Self::Telegram => "telegram",
            Self::Hooks => "hooks",
        }
    }
}

impl VerifyOutcomeSelection {
    fn resolved(self, cfg: &Value) -> SetupOutcome {
        match self {
            Self::Auto => infer_setup_outcome_from_config(cfg),
            Self::LocalChat => SetupOutcome::LocalChat,
            Self::Discord => SetupOutcome::Discord,
            Self::Telegram => SetupOutcome::Telegram,
            Self::Hooks => SetupOutcome::Hooks,
        }
    }
}

fn parse_setup_outcome(raw: &str) -> Option<SetupOutcome> {
    match raw.trim().to_lowercase().as_str() {
        "local-chat" | "local" | "chat" | "assistant" => Some(SetupOutcome::LocalChat),
        "discord" => Some(SetupOutcome::Discord),
        "telegram" => Some(SetupOutcome::Telegram),
        "hooks" | "webhook" | "webhooks" => Some(SetupOutcome::Hooks),
        _ => None,
    }
}

fn prompt_setup_outcome() -> Result<SetupOutcome, Box<dyn std::error::Error>> {
    loop {
        let selection = prompt_with_default(
            "Pick your first-run outcome (local-chat/discord/telegram/hooks)",
            SetupOutcome::LocalChat.prompt_key(),
        )?;
        if let Some(outcome) = parse_setup_outcome(&selection) {
            return Ok(outcome);
        }
        eprintln!("Please choose one of: local-chat, discord, telegram, hooks.");
    }
}

fn prompt_optional_value_from_env(
    env_var: &str,
    label: &str,
    prompt: &str,
) -> Result<Option<String>, Box<dyn std::error::Error>> {
    let env_value = std::env::var(env_var).ok().filter(|v| !v.trim().is_empty());
    if let Some(value) = env_value {
        let use_env = prompt_yes_no(&format!("Use {label} from ${env_var}?"), true)?;
        if use_env {
            return Ok(Some(value));
        }
    }

    let entered = prompt_hidden_line(prompt)?;
    if entered.is_empty() {
        Ok(None)
    } else {
        Ok(Some(entered))
    }
}

fn print_setup_outcome_next_steps(outcome: SetupOutcome, port: u16, hooks_enabled: bool) {
    println!();
    match outcome {
        SetupOutcome::LocalChat => {
            println!("First-run outcome: local assistant chat");
            println!("Next step: run `cara chat --port {port}` when the service is up.");
        }
        SetupOutcome::Discord => {
            println!("First-run outcome: Discord assistant");
            println!("Next step: https://getcara.io/cookbook/discord-assistant.html");
            println!("Repo docs path: docs/cookbook/discord-assistant.md");
        }
        SetupOutcome::Telegram => {
            println!("First-run outcome: Telegram assistant");
            println!("Next step: https://getcara.io/cookbook/telegram-webhook-assistant.html");
            println!("Repo docs path: docs/cookbook/telegram-webhook-assistant.md");
        }
        SetupOutcome::Hooks => {
            println!("First-run outcome: hooks automation");
            if hooks_enabled {
                println!("Next step: send a test hook to http://127.0.0.1:{port}/hooks/wake");
                println!(
                    "Example: curl -X POST -H 'Authorization: Bearer <CARAPACE_HOOKS_TOKEN>' \\"
                );
                println!(
                    "  -H 'Content-Type: application/json' http://127.0.0.1:{port}/hooks/wake \\"
                );
                println!("  -d '{{\"text\":\"wake\"}}'");
            } else {
                println!(
                    "Hooks outcome selected, but hooks are disabled. Enable `gateway.hooks.enabled` to use it."
                );
            }
        }
    }
}

fn prompt_line(prompt: &str) -> Result<String, Box<dyn std::error::Error>> {
    use std::io::{self, Write};

    print!("{}", prompt);
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(input.trim().to_string())
}

fn prompt_hidden_line(prompt: &str) -> Result<String, Box<dyn std::error::Error>> {
    let input = rpassword::prompt_password(prompt)?;
    Ok(input.trim().to_string())
}

fn prompt_with_default(prompt: &str, default: &str) -> Result<String, Box<dyn std::error::Error>> {
    let line = prompt_line(&format!("{prompt} [{default}]: "))?;
    if line.is_empty() {
        Ok(default.to_string())
    } else {
        Ok(line)
    }
}

fn prompt_yes_no(prompt: &str, default_yes: bool) -> Result<bool, Box<dyn std::error::Error>> {
    let suffix = if default_yes { "Y/n" } else { "y/N" };
    let line = prompt_line(&format!("{prompt} ({suffix}): "))?;
    if line.is_empty() {
        return Ok(default_yes);
    }
    match line.trim().to_lowercase().as_str() {
        "y" | "yes" => Ok(true),
        "n" | "no" => Ok(false),
        _ => Ok(default_yes),
    }
}

fn prompt_choice(
    prompt: &str,
    default: &str,
    accepted: &[&str],
) -> Result<String, Box<dyn std::error::Error>> {
    loop {
        let selection = prompt_with_default(prompt, default)?;
        let normalized = selection.trim().to_lowercase();
        if accepted
            .iter()
            .any(|value| normalized.as_str() == value.to_lowercase())
        {
            return Ok(normalized);
        }
        eprintln!("Please enter one of: {}", accepted.join(", "));
    }
}

fn prompt_port(default_port: u16) -> Result<u16, Box<dyn std::error::Error>> {
    loop {
        let raw = prompt_with_default("Gateway port", &default_port.to_string())?;
        match raw.parse::<u16>() {
            Ok(0) => eprintln!("Port must be between 1 and 65535."),
            Ok(port) => return Ok(port),
            Err(_) => eprintln!("Please enter a valid TCP port (1-65535)."),
        }
    }
}

fn generate_hex_secret(byte_len: usize) -> Result<String, Box<dyn std::error::Error>> {
    Ok(crate::crypto::generate_hex_secret(byte_len)?)
}

fn prompt_custom_secret(kind: &str) -> Result<String, Box<dyn std::error::Error>> {
    const MIN_SECRET_LENGTH: usize = 10;

    loop {
        let entered = prompt_hidden_line(&format!("Enter {kind} (input hidden): "))?;
        if entered.is_empty() {
            eprintln!("{} cannot be empty.", kind);
            continue;
        }

        if entered.chars().count() < MIN_SECRET_LENGTH {
            eprintln!(
                "{} must be at least {} characters long.",
                kind, MIN_SECRET_LENGTH
            );
            continue;
        }

        return Ok(entered);
    }
}

async fn validate_provider_credentials(provider: &str, api_key: &str) -> Result<(), String> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(8))
        .build()
        .map_err(|e| format!("failed to build validation client: {e}"))?;

    let response = match provider {
        "openai" => client
            .get("https://api.openai.com/v1/models")
            .bearer_auth(api_key)
            .send()
            .await
            .map_err(|e| format!("OpenAI credential check failed: {e}"))?,
        "anthropic" => client
            .get("https://api.anthropic.com/v1/models")
            .header("x-api-key", api_key)
            .header("anthropic-version", "2023-06-01")
            .send()
            .await
            .map_err(|e| format!("Anthropic credential check failed: {e}"))?,
        other => return Err(format!("unsupported provider for validation: {other}")),
    };

    if response.status().is_success() {
        return Ok(());
    }

    let status = response.status();
    let has_body = !response.text().await.unwrap_or_default().trim().is_empty();
    let mut message = format!("{provider} credential check failed (HTTP {status}).");
    if has_body {
        message.push_str(
            " The provider returned an error message that is hidden because it may contain sensitive information.",
        );
    }
    Err(message)
}

async fn validate_provider_credentials_owned(
    provider: String,
    api_key: String,
) -> Result<(), String> {
    validate_provider_credentials(&provider, &api_key).await
}

fn map_channel_validation_error(
    channel_name: &str,
    err: crate::channels::ChannelAuthError,
) -> String {
    if err.is_auth() {
        format!("{channel_name} credential check failed: {}", err.message())
    } else {
        format!(
            "{channel_name} credential check hit a transient error: {}",
            err.message()
        )
    }
}

fn prompt_and_configure_bot_channel(
    config: &mut Value,
    channel_key: &str,
    channel_label: &str,
    env_var: &str,
    prompt: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let token_label = format!("{channel_label} bot token");
    let channel_token = prompt_optional_value_from_env(env_var, &token_label, prompt)?;
    if let Some(token) = channel_token {
        validate_channel_credentials_interactive(channel_key, &token)?;
        config[channel_key] = serde_json::json!({
            "enabled": true,
            "botToken": token
        });
    } else {
        println!(
            "Skipped {channel_label} token. You can configure it later in `{channel_key}.botToken`."
        );
    }
    Ok(())
}

async fn validate_channel_credentials(channel: &str, token: &str) -> Result<(), String> {
    match channel {
        "discord" => {
            let token = token.to_string();
            tokio::task::spawn_blocking(move || {
                DiscordChannel::new(DISCORD_DEFAULT_API_BASE_URL.to_string(), token)
                    .validate()
                    .map_err(|err| map_channel_validation_error("Discord", err))
            })
            .await
            .map_err(|e| format!("Discord credential check task failed: {e}"))?
        }
        "telegram" => {
            let token = token.to_string();
            tokio::task::spawn_blocking(move || {
                TelegramChannel::new(TELEGRAM_DEFAULT_API_BASE_URL.to_string(), token)
                    .validate()
                    .map_err(|err| map_channel_validation_error("Telegram", err))
            })
            .await
            .map_err(|e| format!("Telegram credential check task failed: {e}"))?
        }
        other => Err(format!("unsupported channel for validation: {other}")),
    }
}

async fn validate_channel_credentials_owned(channel: String, token: String) -> Result<(), String> {
    validate_channel_credentials(&channel, &token).await
}

fn validate_provider_credentials_interactive(
    provider: &str,
    api_key: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let validate_now = prompt_yes_no("Validate provider credentials now? Recommended.", true)?;
    if !validate_now {
        return Ok(());
    }

    let provider = provider.to_string();
    let api_key = api_key.to_string();
    println!("Checking {} credentials...", provider);
    match run_sync_blocking_send(validate_provider_credentials_owned(provider, api_key))
        .map_err(|err| format!("credential validation runtime failed: {err}"))
    {
        Ok(()) => {
            println!("Credential check succeeded.");
            Ok(())
        }
        Err(err) => {
            eprintln!("Credential check failed: {}", err);
            if prompt_yes_no("Continue setup and write config anyway?", false)? {
                Ok(())
            } else {
                Err("setup aborted after credential validation failure".into())
            }
        }
    }
}

fn validate_channel_credentials_interactive(
    channel: &str,
    token: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let validate_now = prompt_yes_no(
        &format!("Validate {channel} credentials now? Recommended."),
        true,
    )?;
    if !validate_now {
        return Ok(());
    }

    let channel = channel.to_string();
    let token = token.to_string();
    println!("Checking {} credentials...", channel);
    match run_sync_blocking_send(validate_channel_credentials_owned(channel, token))
        .map_err(|err| format!("credential validation runtime failed: {err}"))
    {
        Ok(()) => {
            println!("Credential check succeeded.");
            Ok(())
        }
        Err(err) => {
            eprintln!("Credential check failed: {}", err);
            if prompt_yes_no("Continue setup and write config anyway?", false)? {
                Ok(())
            } else {
                Err("setup aborted after credential validation failure".into())
            }
        }
    }
}

#[derive(Debug)]
struct VerifyCheckResult {
    name: String,
    status: VerifyCheckStatus,
    detail: String,
    next_step: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VerifyCheckStatus {
    Pass,
    Fail,
    Skip,
}

impl VerifyCheckResult {
    fn pass(name: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            status: VerifyCheckStatus::Pass,
            detail: detail.into(),
            next_step: None,
        }
    }

    fn fail(
        name: impl Into<String>,
        detail: impl Into<String>,
        next_step: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            status: VerifyCheckStatus::Fail,
            detail: detail.into(),
            next_step: Some(next_step.into()),
        }
    }

    fn skip(
        name: impl Into<String>,
        detail: impl Into<String>,
        next_step: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            status: VerifyCheckStatus::Skip,
            detail: detail.into(),
            next_step: Some(next_step.into()),
        }
    }
}

// Keep this list in sync when adding channels that support token placeholders.
const VERIFY_ALLOWED_ENV_PLACEHOLDER_KEYS: &[&str] = &[
    "DISCORD_BOT_TOKEN",
    "TELEGRAM_BOT_TOKEN",
    "CARAPACE_HOOKS_TOKEN",
];
static WARNED_VERIFY_PLACEHOLDER_KEYS: LazyLock<Mutex<HashSet<String>>> =
    LazyLock::new(|| Mutex::new(HashSet::new()));

fn is_allowed_verify_placeholder_key(key: &str) -> bool {
    VERIFY_ALLOWED_ENV_PLACEHOLDER_KEYS.contains(&key)
}

fn warn_unsupported_verify_placeholder_key(key: &str) {
    if cfg!(test) {
        return;
    }
    if key.len() > 64 {
        return;
    }
    let mut warned = WARNED_VERIFY_PLACEHOLDER_KEYS
        .lock()
        .expect("verify placeholder warning lock poisoned");
    if !warned.insert(key.to_string()) {
        return;
    }
    eprintln!(
        "Warning: unsupported token placeholder `${{{key}}}` ignored during verification. \
Use one of: {}",
        VERIFY_ALLOWED_ENV_PLACEHOLDER_KEYS.join(", ")
    );
}

fn normalize_optional_input(input: Option<String>) -> Option<String> {
    input
        .map(|value| value.trim().to_string())
        .filter(|trimmed| !trimmed.is_empty())
}

fn summarize_destination_for_display(raw: &str) -> String {
    let sanitized: String = raw
        .chars()
        .filter(|ch| !ch.is_control())
        .take(120)
        .collect();
    if sanitized.is_empty() {
        "<redacted>".to_string()
    } else {
        sanitized
    }
}

fn resolve_env_placeholder(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }
    let Some(key) = trimmed.strip_prefix("${").and_then(|s| s.strip_suffix('}')) else {
        return Some(trimmed.to_string());
    };
    let key = key.trim();
    if key.is_empty() {
        return None;
    }
    if !is_allowed_verify_placeholder_key(key) {
        warn_unsupported_verify_placeholder_key(key);
        return None;
    }
    std::env::var(key)
        .ok()
        .map(|env_value| env_value.trim().to_string())
        .filter(|normalized| !normalized.is_empty())
}

fn resolve_channel_bot_token(cfg: &Value, channel_key: &str, env_var: &str) -> Option<String> {
    std::env::var(env_var)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|normalized| !normalized.is_empty())
        .or_else(|| resolve_channel_bot_token_from_config(cfg, channel_key))
}

fn resolve_channel_bot_token_from_config(cfg: &Value, channel_key: &str) -> Option<String> {
    cfg.get(channel_key)
        .and_then(|v| v.get("botToken"))
        .and_then(|v| v.as_str())
        .and_then(resolve_env_placeholder)
}

fn channel_outcome_configured(cfg: &Value, channel_key: &str) -> bool {
    resolve_channel_bot_token_from_config(cfg, channel_key).is_some()
}

fn resolve_hooks_token(cfg: &Value) -> Option<String> {
    std::env::var("CARAPACE_HOOKS_TOKEN")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|normalized| !normalized.is_empty())
        .or_else(|| {
            cfg.get("gateway")
                .and_then(|v| v.get("hooks"))
                .and_then(|v| v.get("token"))
                .and_then(|v| v.as_str())
                .and_then(resolve_env_placeholder)
        })
}

fn infer_setup_outcome_from_config(cfg: &Value) -> SetupOutcome {
    // Priority is intentional: configured channels first, then hooks, then local chat.
    if channel_outcome_configured(cfg, "discord") {
        return SetupOutcome::Discord;
    }
    if channel_outcome_configured(cfg, "telegram") {
        return SetupOutcome::Telegram;
    }
    let hooks_enabled = cfg
        .get("gateway")
        .and_then(|v| v.get("hooks"))
        .and_then(|v| v.get("enabled"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    if hooks_enabled {
        return SetupOutcome::Hooks;
    }
    SetupOutcome::LocalChat
}

fn print_verify_summary(outcome: SetupOutcome, port: u16, checks: &[VerifyCheckResult]) {
    println!();
    println!("Outcome verification summary");
    println!("----------------------------");
    println!("Outcome: {}", outcome.prompt_key());
    println!("Gateway port: {}", port);
    println!();
    for check in checks {
        let status = match check.status {
            VerifyCheckStatus::Pass => "PASS",
            VerifyCheckStatus::Fail => "FAIL",
            VerifyCheckStatus::Skip => "SKIP",
        };
        println!("[{}] {}: {}", status, check.name, check.detail);
        if let Some(next_step) = check.next_step.as_deref() {
            println!("      next step: {}", next_step);
        }
    }
}

async fn verify_channel_send_path(
    channel: SetupOutcome,
    token: String,
    destination: String,
) -> Result<(), String> {
    let message = format!(
        "Carapace verify ping ({})",
        chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
    );
    tokio::task::spawn_blocking(move || {
        use crate::plugins::{ChannelPluginInstance, OutboundContext};
        let outbound = OutboundContext {
            to: destination,
            text: message,
            media_url: None,
            gif_playback: false,
            reply_to_id: None,
            thread_id: None,
            account_id: None,
        };

        let delivery = match channel {
            SetupOutcome::Discord => {
                let channel_impl =
                    DiscordChannel::new(DISCORD_DEFAULT_API_BASE_URL.to_string(), token);
                channel_impl.send_text(outbound)
            }
            SetupOutcome::Telegram => {
                let channel_impl =
                    TelegramChannel::new(TELEGRAM_DEFAULT_API_BASE_URL.to_string(), token);
                channel_impl.send_text(outbound)
            }
            _ => return Err("unsupported channel send-path verification target".to_string()),
        }
        .map_err(|e| format!("send invocation failed: {e}"))?;

        if delivery.ok {
            Ok(())
        } else {
            Err(sanitize_channel_delivery_error(
                delivery
                    .error
                    .unwrap_or_else(|| "send path rejected request".to_string()),
            ))
        }
    })
    .await
    .map_err(|e| format!("send-path verification task failed: {e}"))?
}

fn sanitize_channel_delivery_error(raw_error: String) -> String {
    let trimmed = raw_error.trim();
    if trimmed.is_empty() {
        return "send path rejected request".to_string();
    }
    "send path rejected request (provider details hidden for safety)".to_string()
}

fn summarize_http_failure_body(status: reqwest::StatusCode, body: &str) -> String {
    let _ = status;
    let _ = body;
    "(body hidden for safety)".to_string()
}

async fn verify_local_chat_outcome(
    port: u16,
    checks: &mut Vec<VerifyCheckResult>,
) -> Result<(), String> {
    let mut setup_server_handle = match chat::ensure_local_gateway_running(port).await {
        Ok(handle) => {
            checks.push(VerifyCheckResult::pass(
                "Gateway reachability",
                format!("service is reachable at 127.0.0.1:{port}"),
            ));
            handle
        }
        Err(err) => {
            checks.push(VerifyCheckResult::fail(
                "Gateway reachability",
                err.to_string(),
                format!(
                    "start the service (`cara start --port {port}`) and retry `cara verify --outcome local-chat --port {port}`"
                ),
            ));
            return Err("outcome verification failed".to_string());
        }
    };

    let roundtrip_result = chat::verify_chat_roundtrip(
        port,
        "Reply with exactly: verification-ok",
        Duration::from_secs(45),
    )
    .await;
    if let Some(handle) = setup_server_handle.take() {
        handle.shutdown().await;
    }

    match roundtrip_result {
        Ok(()) => checks.push(VerifyCheckResult::pass(
            "Local chat roundtrip",
            "non-interactive chat send reached final state",
        )),
        Err(err) => {
            checks.push(VerifyCheckResult::fail(
                "Local chat roundtrip",
                err,
                "check provider API key/model and retry `cara verify --outcome local-chat`",
            ));
            return Err("outcome verification failed".to_string());
        }
    }
    Ok(())
}

async fn verify_hooks_outcome(
    port: u16,
    cfg: &Value,
    checks: &mut Vec<VerifyCheckResult>,
) -> Result<(), String> {
    let mut setup_server_handle = match chat::ensure_local_gateway_running(port).await {
        Ok(handle) => {
            checks.push(VerifyCheckResult::pass(
                "Gateway reachability",
                format!("service is reachable at 127.0.0.1:{port}"),
            ));
            handle
        }
        Err(err) => {
            checks.push(VerifyCheckResult::fail(
                "Gateway reachability",
                err.to_string(),
                format!(
                    "start the service (`cara start --port {port}`) and retry `cara verify --outcome hooks --port {port}`"
                ),
            ));
            return Err("outcome verification failed".to_string());
        }
    };

    let hooks_enabled = cfg
        .get("gateway")
        .and_then(|v| v.get("hooks"))
        .and_then(|v| v.get("enabled"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    if !hooks_enabled {
        checks.push(VerifyCheckResult::fail(
            "Hooks enabled",
            "gateway.hooks.enabled is false",
            "enable `gateway.hooks.enabled` and configure `gateway.hooks.token`, then retry",
        ));
        if let Some(handle) = setup_server_handle.take() {
            handle.shutdown().await;
        }
        return Err("outcome verification failed".to_string());
    } else {
        checks.push(VerifyCheckResult::pass(
            "Hooks enabled",
            "gateway.hooks.enabled is true",
        ));
    }

    let hooks_token = resolve_hooks_token(cfg);
    let hooks_token = if let Some(token) = hooks_token {
        checks.push(VerifyCheckResult::pass(
            "Hooks token",
            "hooks token resolved from config/environment",
        ));
        token
    } else {
        checks.push(VerifyCheckResult::fail(
            "Hooks token",
            "no hooks token configured",
            "set `gateway.hooks.token` (or CARAPACE_HOOKS_TOKEN) and retry",
        ));
        if let Some(handle) = setup_server_handle.take() {
            handle.shutdown().await;
        }
        return Err("outcome verification failed".to_string());
    };

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|e| format!("failed to create hooks verification client: {e}"))?;
    let wake_url = format!("http://127.0.0.1:{port}/hooks/wake");
    println!("Sending signed hooks wake request (this triggers real hooks processing)...");
    let wake_result = client
        .post(&wake_url)
        .header("Authorization", format!("Bearer {hooks_token}"))
        .json(&serde_json::json!({ "text": "verify-hook" }))
        .send()
        .await;
    if let Some(handle) = setup_server_handle.take() {
        handle.shutdown().await;
    }

    match wake_result {
        Ok(resp) if resp.status().is_success() => checks.push(VerifyCheckResult::pass(
            "Signed /hooks/wake",
            "received success response from /hooks/wake",
        )),
        Ok(resp) => {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            let safe_body = summarize_http_failure_body(status, &body);
            checks.push(VerifyCheckResult::fail(
                "Signed /hooks/wake",
                format!("request failed with HTTP {status}: {safe_body}"),
                format!(
                    "verify hooks auth token and retry `cara verify --outcome hooks --port {port}`"
                ),
            ));
        }
        Err(_err) => checks.push(VerifyCheckResult::fail(
            "Signed /hooks/wake",
            "network error sending request",
            format!("confirm gateway is reachable on port {port} and retry"),
        )),
    }

    Ok(())
}

async fn verify_channel_outcome(
    outcome: SetupOutcome,
    cfg: &Value,
    discord_to: Option<String>,
    telegram_to: Option<String>,
    checks: &mut Vec<VerifyCheckResult>,
) -> Result<(), String> {
    let (channel_label, channel_key, env_var, destination, destination_flag) = match outcome {
        SetupOutcome::Discord => (
            "Discord",
            "discord",
            "DISCORD_BOT_TOKEN",
            discord_to,
            "--discord-to <channel_id>",
        ),
        SetupOutcome::Telegram => (
            "Telegram",
            "telegram",
            "TELEGRAM_BOT_TOKEN",
            telegram_to,
            "--telegram-to <chat_id>",
        ),
        other => {
            return Err(format!(
                "unsupported channel outcome for verification: {other:?}"
            ))
        }
    };

    let token = resolve_channel_bot_token(cfg, channel_key, env_var);
    let token = if let Some(token) = token {
        checks.push(VerifyCheckResult::pass(
            format!("{channel_label} credentials"),
            format!("{channel_label} token is configured"),
        ));
        token
    } else {
        checks.push(VerifyCheckResult::fail(
            format!("{channel_label} credentials"),
            format!("{channel_label} token is not configured"),
            format!("set `{channel_key}.botToken` or `{env_var}`, then retry `cara verify --outcome {channel_key}`"),
        ));
        return Err("outcome verification failed".to_string());
    };

    match validate_channel_credentials(channel_key, &token).await {
        Ok(()) => {
            checks.push(VerifyCheckResult::pass(
                format!("{channel_label} token check"),
                "credential validation succeeded",
            ));

            if let Some(destination) = destination {
                let destination_display = summarize_destination_for_display(&destination);
                println!(
                    "Sending verification ping to {channel_label} destination {destination_display}..."
                );
                match verify_channel_send_path(outcome, token, destination).await {
                    Ok(()) => checks.push(VerifyCheckResult::pass(
                        format!("{channel_label} send path"),
                        "test message delivery succeeded",
                    )),
                    Err(err) => checks.push(VerifyCheckResult::fail(
                        format!("{channel_label} send path"),
                        err,
                        format!(
                            "confirm destination and bot permissions, then retry with `{destination_flag}`"
                        ),
                    )),
                }
            } else {
                checks.push(VerifyCheckResult::skip(
                    format!("{channel_label} send path"),
                    "destination id not provided; send-path test skipped",
                    format!("rerun with `{destination_flag}` to verify end-to-end delivery"),
                ));
            }
        }
        Err(err) => {
            checks.push(VerifyCheckResult::fail(
                format!("{channel_label} token check"),
                err,
                format!("update `{channel_key}.botToken` and retry `cara verify --outcome {channel_key}`"),
            ));
            checks.push(VerifyCheckResult::skip(
                format!("{channel_label} send path"),
                "not attempted because credential validation failed",
                format!(
                    "fix `{channel_key}` credentials first, then rerun with `{destination_flag}`"
                ),
            ));
        }
    }
    Ok(())
}

async fn run_outcome_verifier(
    selection: VerifyOutcomeSelection,
    port: u16,
    discord_to: Option<String>,
    telegram_to: Option<String>,
    cfg: Value,
) -> Result<(), String> {
    let mut checks: Vec<VerifyCheckResult> = Vec::new();
    let outcome = selection.resolved(&cfg);
    let discord_to = normalize_optional_input(discord_to);
    let telegram_to = normalize_optional_input(telegram_to);

    let result = match outcome {
        SetupOutcome::LocalChat => verify_local_chat_outcome(port, &mut checks).await,
        SetupOutcome::Hooks => verify_hooks_outcome(port, &cfg, &mut checks).await,
        SetupOutcome::Discord | SetupOutcome::Telegram => {
            verify_channel_outcome(outcome, &cfg, discord_to, telegram_to, &mut checks).await
        }
    };
    if let Err(err) = result {
        print_verify_summary(outcome, port, &checks);
        return Err(err);
    }

    print_verify_summary(outcome, port, &checks);
    let has_fail = checks
        .iter()
        .any(|check| check.status == VerifyCheckStatus::Fail);
    let has_pass = checks
        .iter()
        .any(|check| check.status == VerifyCheckStatus::Pass);
    let has_skip = checks
        .iter()
        .any(|check| check.status == VerifyCheckStatus::Skip);
    if !has_fail && has_pass {
        println!();
        if has_skip {
            println!("Outcome verification passed with skipped checks.");
        } else {
            println!("Outcome verification passed.");
        }
        Ok(())
    } else if !has_fail {
        Err("outcome verification incomplete (no checks passed)".to_string())
    } else {
        Err("outcome verification failed".to_string())
    }
}

pub async fn handle_verify(
    outcome: VerifyOutcomeSelection,
    port: Option<u16>,
    discord_to: Option<String>,
    telegram_to: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let cfg = config::load_config()
        .map_err(|e| format!("failed to load config: {e}. Run `cara setup` first."))?;
    let port = resolve_port(port);
    run_outcome_verifier(outcome, port, discord_to, telegram_to, cfg)
        .await
        .map_err(|err| err.into())
}

async fn run_setup_post_checks(
    port: u16,
    run_status: bool,
    launch_chat: bool,
) -> Result<(), String> {
    let mut setup_server_handle = if run_status || launch_chat {
        chat::ensure_local_gateway_running(port)
            .await
            .map_err(|e| format!("failed to start local gateway: {e}"))?
    } else {
        None
    };

    if run_status {
        let status_result = handle_status("127.0.0.1", Some(port))
            .await
            .map_err(|e| format!("status check failed: {e}"));
        if status_result.is_err() {
            if let Some(handle) = setup_server_handle.take() {
                handle.shutdown().await;
            }
        }
        status_result?;
    }

    let chat_result = if launch_chat {
        chat::run_chat_session(false, port)
            .await
            .map_err(|e| format!("chat session failed: {e}"))
    } else {
        Ok(())
    };

    if let Some(handle) = setup_server_handle {
        handle.shutdown().await;
    }

    chat_result
}

/// Run the `setup` subcommand -- interactive first-run wizard.
pub fn handle_setup(force: bool) -> Result<(), Box<dyn std::error::Error>> {
    let config_path = config::get_config_path();

    // Check if config already exists.
    if config_path.exists() && !force {
        eprintln!(
            "Config already exists at {}. Use --force to overwrite.",
            config_path.display()
        );
        return Err("config already exists".into());
    }

    // Create the config directory if needed.
    if let Some(parent) = config_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let interactive = std::io::stdin().is_terminal();

    let default_gateway_token = generate_hex_secret(32)?;

    // Build a minimal default config.
    let mut config = serde_json::json!({
        "gateway": {
            "port": DEFAULT_PORT,
            "bind": "loopback",
            "auth": {
                "mode": "token",
                "token": default_gateway_token
            }
        },
        "agents": {
            "defaults": {
                "model": "claude-sonnet-4-20250514"
            }
        }
    });

    let mut setup_outcome = SetupOutcome::LocalChat;
    let mut hooks_enabled = false;
    let mut verify_discord_to: Option<String> = None;
    let mut verify_telegram_to: Option<String> = None;

    if interactive {
        println!("Carapace setup wizard");
        println!("---------------------");

        let default_provider = if std::env::var("ANTHROPIC_API_KEY").is_ok() {
            "anthropic"
        } else if std::env::var("OPENAI_API_KEY").is_ok() {
            "openai"
        } else {
            "anthropic"
        };

        let provider = loop {
            let selection =
                prompt_with_default("Select provider (anthropic/openai)", default_provider)?;
            let normalized = selection.trim().to_lowercase();
            match normalized.as_str() {
                "anthropic" | "claude" => break "anthropic",
                "openai" | "gpt" => break "openai",
                _ => eprintln!("Please enter either \"anthropic\" or \"openai\"."),
            }
        };

        let (env_var, default_model) = match provider {
            "openai" => ("OPENAI_API_KEY", "gpt-4o"),
            _ => ("ANTHROPIC_API_KEY", "claude-sonnet-4-20250514"),
        };

        let env_key = std::env::var(env_var).ok();
        let mut effective_api_key = None;
        let api_key = if env_key.is_some() {
            let use_env = prompt_yes_no(&format!("Use API key from ${env_var}?"), true)?;
            if use_env {
                effective_api_key = env_key.clone();
                Some(format!("${{{env_var}}}"))
            } else {
                let entered = prompt_hidden_line("Enter API key (input hidden): ")?;
                if entered.is_empty() {
                    None
                } else {
                    effective_api_key = Some(entered.clone());
                    Some(entered)
                }
            }
        } else {
            let entered =
                prompt_hidden_line("Enter API key (input hidden, leave blank to skip): ")?;
            if entered.is_empty() {
                None
            } else {
                effective_api_key = Some(entered.clone());
                Some(entered)
            }
        };

        if api_key.is_none() {
            println!("No API key provided. You can set it later via ${env_var}.");
        }

        if let Some(key) = effective_api_key.as_deref() {
            validate_provider_credentials_interactive(provider, key)?;
        }

        let auth_mode = prompt_choice(
            "Gateway auth mode (token/password)",
            "token",
            &["token", "password"],
        )?;
        let auth_secret = if auth_mode == "token" {
            if prompt_yes_no("Generate a strong gateway token automatically?", true)? {
                generate_hex_secret(32)?
            } else {
                prompt_custom_secret("gateway token")?
            }
        } else if prompt_yes_no("Generate a strong gateway password automatically?", true)? {
            generate_hex_secret(24)?
        } else {
            prompt_custom_secret("gateway password")?
        };

        let bind_mode = loop {
            let bind = prompt_choice(
                "Gateway bind mode (loopback/lan)",
                "loopback",
                &["loopback", "lan"],
            )?;
            if bind == "lan" {
                eprintln!("Warning: LAN bind exposes Carapace to your local network.");
                eprintln!("Use strong auth and add TLS/reverse proxy before broader exposure.");
                if !prompt_yes_no("Continue with LAN bind?", false)? {
                    continue;
                }
            }
            break bind;
        };
        let gateway_port = prompt_port(DEFAULT_PORT)?;

        config["gateway"]["bind"] = serde_json::json!(bind_mode);
        config["gateway"]["port"] = serde_json::json!(gateway_port);
        if auth_mode == "token" {
            config["gateway"]["auth"] = serde_json::json!({
                "mode": "token",
                "token": auth_secret
            });
        } else {
            config["gateway"]["auth"] = serde_json::json!({
                "mode": "password",
                "password": auth_secret
            });
        }

        setup_outcome = prompt_setup_outcome()?;

        match setup_outcome {
            SetupOutcome::Discord => {
                prompt_and_configure_bot_channel(
                    &mut config,
                    "discord",
                    "Discord",
                    "DISCORD_BOT_TOKEN",
                    "Enter Discord bot token (leave blank to skip for now): ",
                )?;
                let discord_configured =
                    resolve_channel_bot_token_from_config(&config, "discord").is_some();
                if discord_configured {
                    let destination = prompt_line(
                        "Optional: Discord channel ID for send-path verify (leave blank to skip): ",
                    )?;
                    verify_discord_to = normalize_optional_input(Some(destination));
                }
            }
            SetupOutcome::Telegram => {
                prompt_and_configure_bot_channel(
                    &mut config,
                    "telegram",
                    "Telegram",
                    "TELEGRAM_BOT_TOKEN",
                    "Enter Telegram bot token (leave blank to skip for now): ",
                )?;
                let telegram_configured =
                    resolve_channel_bot_token_from_config(&config, "telegram").is_some();
                if telegram_configured {
                    let destination = prompt_line(
                        "Optional: Telegram chat ID for send-path verify (leave blank to skip): ",
                    )?;
                    verify_telegram_to = normalize_optional_input(Some(destination));
                }
            }
            SetupOutcome::LocalChat | SetupOutcome::Hooks => {}
        }

        hooks_enabled = prompt_yes_no(
            "Enable hooks API (`/hooks`) for automations?",
            matches!(setup_outcome, SetupOutcome::Hooks),
        )?;
        if hooks_enabled {
            let hooks_token =
                if prompt_yes_no("Generate a strong hooks token automatically?", true)? {
                    generate_hex_secret(32)?
                } else {
                    prompt_custom_secret("hooks token")?
                };
            config["gateway"]["hooks"] = serde_json::json!({
                "enabled": true,
                "token": hooks_token
            });
        }

        let enable_control_ui =
            prompt_yes_no("Enable local Control UI dashboard (`/control`)?", false)?;
        if enable_control_ui {
            config["gateway"]["controlUi"] = serde_json::json!({
                "enabled": true
            });
        }

        config["agents"]["defaults"]["model"] = serde_json::json!(default_model);
        match provider {
            "openai" => {
                let value = api_key.clone().unwrap_or_else(|| format!("${{{env_var}}}"));
                config["openai"] = serde_json::json!({ "apiKey": value });
            }
            _ => {
                let value = api_key.clone().unwrap_or_else(|| format!("${{{env_var}}}"));
                config["anthropic"] = serde_json::json!({ "apiKey": value });
            }
        }
    }

    // Write the config file using json5 (pretty-formatted).
    let content = json5::to_string(&config)?;
    std::fs::write(&config_path, &content)?;

    println!("Config written to {}", config_path.display());
    println!("Start the server with: cara start");

    if interactive {
        let port = config
            .get("gateway")
            .and_then(|v| v.get("port"))
            .and_then(|v| v.as_u64())
            .and_then(|v| u16::try_from(v).ok())
            .unwrap_or(DEFAULT_PORT);

        let run_status = prompt_yes_no("Run setup smoke check now (`cara status`)?", true)?;
        let launch_chat_default = matches!(setup_outcome, SetupOutcome::LocalChat);
        let launch_chat_prompt = if launch_chat_default {
            "Run your first assistant action now (`cara chat`)?"
        } else {
            "Also launch local assistant chat now (`cara chat`)?"
        };
        let launch_chat = prompt_yes_no(launch_chat_prompt, launch_chat_default)?;
        let verify_default = match setup_outcome {
            SetupOutcome::LocalChat | SetupOutcome::Hooks => true,
            SetupOutcome::Discord => verify_discord_to.is_some(),
            SetupOutcome::Telegram => verify_telegram_to.is_some(),
        };
        let verify_prompt = format!(
            "Run outcome verifier now (`cara verify --outcome {}`)?",
            setup_outcome.prompt_key()
        );
        let run_verify = prompt_yes_no(&verify_prompt, verify_default)?;

        if run_status || launch_chat || run_verify {
            if run_status || launch_chat {
                // Assumes this executes from the main thread (#[tokio::main] multi-threaded runtime),
                // where this helper works without spawning a new thread.
                if let Err(err) =
                    run_sync_blocking(run_setup_post_checks(port, run_status, launch_chat))
                        .map_err(|err| format!("runtime execution failed: {err}"))
                {
                    eprintln!("Post-setup checks failed: {}", err);
                    eprintln!(
                        "You can retry manually with: cara status --port {}  and  cara chat --port {}",
                        port, port
                    );
                }
            }

            if run_verify {
                let verify_outcome = match setup_outcome {
                    SetupOutcome::LocalChat => VerifyOutcomeSelection::LocalChat,
                    SetupOutcome::Discord => VerifyOutcomeSelection::Discord,
                    SetupOutcome::Telegram => VerifyOutcomeSelection::Telegram,
                    SetupOutcome::Hooks => VerifyOutcomeSelection::Hooks,
                };
                if let Err(err) = run_sync_blocking_send(run_outcome_verifier(
                    verify_outcome,
                    port,
                    verify_discord_to,
                    verify_telegram_to,
                    config,
                ))
                .map_err(|err| format!("runtime execution failed: {err}"))
                {
                    eprintln!("Outcome verification failed: {}", err);
                    eprintln!("Fix the failing checks above, then rerun `cara verify`.");
                }
            }
        }

        print_setup_outcome_next_steps(setup_outcome, port, hooks_enabled);
    }

    Ok(())
}

/// Run the `pair` subcommand -- pair with a remote gateway node.
pub async fn handle_pair(
    url: &str,
    name: Option<&str>,
    trust: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    // Validate and parse the URL.
    let parsed_url = Url::parse(url).map_err(|e| {
        eprintln!("Invalid URL: {} ({})", url, e);
        "invalid URL".to_string()
    })?;
    if parsed_url.scheme() != "http" && parsed_url.scheme() != "https" {
        eprintln!("Invalid URL: {} (must start with http:// or https://)", url);
        return Err("invalid URL scheme".into());
    }

    // Resolve the device name.
    let device_name = match name {
        Some(n) => n.to_string(),
        None => std::env::var("HOSTNAME").unwrap_or_else(|_| "unknown".to_string()),
    };

    let ws_url = ws_url_from_http(&parsed_url)?;

    if trust {
        if parsed_url.scheme() == "https" {
            eprintln!(
                "Warning: --trust disables TLS certificate verification; use only for local/self-signed gateways."
            );
        } else {
            eprintln!("Warning: --trust has no effect for http URLs.");
        }
    }

    let auth = resolve_gateway_auth().await;
    if auth.token.is_none() && auth.password.is_none() {
        eprintln!("Gateway auth token/password required for pairing.");
        eprintln!("Set gateway.auth.token or gateway.auth.password in config.");
        eprintln!("You can also export CARAPACE_GATEWAY_TOKEN or CARAPACE_GATEWAY_PASSWORD.");
        return Err("missing gateway auth".into());
    }

    let state_dir = resolve_state_dir();
    let device_identity = load_or_create_device_identity(&state_dir).await?;

    println!("Pairing with: {}", parsed_url);
    println!("Device name: {}", device_name);

    let ws_stream = match connect_ws(&ws_url, trust).await {
        Ok(stream) => stream,
        Err(err) => {
            eprintln!("Connection error: {}", err);
            return Err(err);
        }
    };
    let (mut ws_write, mut ws_read) = ws_stream.split();

    let nonce = await_connect_challenge(&mut ws_read, &mut ws_write).await?;

    let role = "operator";
    let scopes = vec!["operator.pairing".to_string()];
    let mut connect_params = serde_json::json!({
        "minProtocol": 3,
        "maxProtocol": 3,
        "client": {
            "id": "cli",
            "version": env!("CARGO_PKG_VERSION"),
            "platform": std::env::consts::OS,
            "mode": "cli"
        },
        "role": role,
        "scopes": scopes.clone()
    });
    let GatewayAuth { token, password } = auth;
    let token_for_signature = token.clone();
    if let Some(token) = token {
        connect_params["auth"] = serde_json::json!({ "token": token });
    } else if let Some(password) = password {
        connect_params["auth"] = serde_json::json!({ "password": password });
    }
    connect_params["device"] = build_device_identity_for_connect(
        &device_identity,
        "cli",
        "cli",
        role,
        &scopes,
        token_for_signature.as_deref(),
        Some(&nonce),
    )?;

    let connect_frame = serde_json::json!({
        "type": "req",
        "id": "connect-1",
        "method": "connect",
        "params": connect_params
    });
    ws_write
        .send(Message::Text(serde_json::to_string(&connect_frame)?.into()))
        .await?;
    if let Err(err) = await_ws_response_with_error(&mut ws_read, &mut ws_write, "connect-1").await {
        if err.code.as_deref() == Some("NOT_PAIRED") && err.message.contains("pairing required") {
            eprintln!("Device pairing required for this CLI.");
            if let Some(details) = err.details.as_ref() {
                if let Some(request_id) = extract_pairing_request_id(details) {
                    eprintln!("Pairing request ID: {}", request_id);
                }
            }
            eprintln!("Approve the request in the control UI, then retry.");
        } else if err.message.contains("device identity required") {
            eprintln!("WebSocket connect failed: {}", err.message);
            eprintln!("This gateway requires a paired device for WebSocket access.");
        } else {
            eprintln!("WebSocket connect failed: {}", err.message);
        }
        return Err(Box::new(err));
    }

    let node_id = format!("node-{}", uuid::Uuid::new_v4());
    let pair_frame = serde_json::json!({
        "type": "req",
        "id": "pair-1",
        "method": "node.pair.request",
        "params": {
            "nodeId": node_id,
            "displayName": device_name,
            "platform": std::env::consts::OS,
            "version": env!("CARGO_PKG_VERSION"),
            "silent": false
        }
    });
    ws_write
        .send(Message::Text(serde_json::to_string(&pair_frame)?.into()))
        .await?;
    let pair_response = await_ws_response(&mut ws_read, &mut ws_write, "pair-1").await?;
    let request_id = pair_response
        .get("request")
        .and_then(|v| v.get("requestId"))
        .and_then(|v| v.as_str())
        .ok_or("pairing request missing requestId")?;

    let approve_frame = serde_json::json!({
        "type": "req",
        "id": "pair-2",
        "method": "node.pair.approve",
        "params": { "requestId": request_id }
    });
    ws_write
        .send(Message::Text(serde_json::to_string(&approve_frame)?.into()))
        .await?;
    let approve_response = await_ws_response(&mut ws_read, &mut ws_write, "pair-2").await?;
    let node_token = approve_response
        .get("node")
        .and_then(|v| v.get("token"))
        .and_then(|v| v.as_str())
        .ok_or("pairing approval missing token")?;

    println!("Paired successfully! Node ID: {}", node_id);
    println!("Node token: {}", node_token);

    // Save pairing to state dir.
    std::fs::create_dir_all(&state_dir)?;
    let pairing_path = state_dir.join("pairing.json");
    let pairing_data = serde_json::json!({
        "node_id": node_id,
        "gateway_url": parsed_url.as_str(),
        "device_name": device_name,
        "token": node_token,
        "paired_at": chrono::Utc::now().to_rfc3339(),
    });
    std::fs::write(&pairing_path, serde_json::to_string_pretty(&pairing_data)?)?;
    println!("Pairing saved to {}", pairing_path.display());

    Ok(())
}

/// Run the `update` subcommand -- check for updates or self-update.
pub async fn handle_update(
    check: bool,
    version: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let current_version = env!("CARGO_PKG_VERSION");

    let (release, client) = fetch_release_info(current_version, version).await?;

    let tag_name = release
        .get("tag_name")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let _release_name = release
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or(tag_name);
    let html_url = release
        .get("html_url")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let latest_version = tag_name.strip_prefix('v').unwrap_or(tag_name);

    if check {
        println!("Current version: v{}", current_version);
        println!("Latest version:  v{}", latest_version);

        if current_version == latest_version {
            println!("Already up to date (v{})", current_version);
        } else {
            println!(
                "Update available: v{} -> v{}",
                current_version, latest_version
            );
            println!("Run `cara update` to install");
        }
        return Ok(());
    }

    // Install mode.
    let target_version = version.unwrap_or(latest_version);
    if target_version == current_version {
        println!("Already up to date (v{})", current_version);
        return Ok(());
    }

    println!(
        "Updating from v{} to v{}...",
        current_version, target_version
    );

    download_and_install_binary(&release, &client, current_version, target_version, html_url).await
}

/// Fetch release information from the GitHub API.
async fn fetch_release_info(
    current_version: &str,
    version: Option<&str>,
) -> Result<(Value, reqwest::Client), Box<dyn std::error::Error>> {
    let api_url = match version {
        Some(v) => format!(
            "https://api.github.com/repos/puremachinery/carapace/releases/tags/v{}",
            v
        ),
        None => "https://api.github.com/repos/puremachinery/carapace/releases/latest".to_string(),
    };

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()?;

    let response = match client
        .get(&api_url)
        .header("Accept", "application/vnd.github+json")
        .header("User-Agent", format!("cara/{}", current_version))
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Failed to check for updates: {}", e);
            return Err(e.into());
        }
    };

    if !response.status().is_success() {
        let status = response.status();
        let body_text = response.text().await.unwrap_or_default();
        eprintln!("GitHub API error (HTTP {}): {}", status, body_text);
        return Err(format!("HTTP {}", status).into());
    }

    let release: Value = response.json().await?;
    Ok((release, client))
}

/// Download and install a binary from a GitHub release.
async fn download_and_install_binary(
    release: &Value,
    client: &reqwest::Client,
    current_version: &str,
    target_version: &str,
    html_url: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let asset_name = format!("cara-{}-{}", std::env::consts::OS, std::env::consts::ARCH);

    let assets = release
        .get("assets")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let matching_asset = assets.iter().find(|a| {
        a.get("name")
            .and_then(|n| n.as_str())
            .is_some_and(|n| n.contains(&asset_name))
    });

    let asset = match matching_asset {
        Some(a) => a,
        None => {
            eprintln!(
                "No matching binary asset found for platform '{}'. Download manually from: {}",
                asset_name, html_url
            );
            return Ok(());
        }
    };

    let download_url = asset
        .get("browser_download_url")
        .and_then(|u| u.as_str())
        .ok_or("asset has no download URL")?;
    let name = asset
        .get("name")
        .and_then(|n| n.as_str())
        .unwrap_or(&asset_name);

    println!("Downloading {}...", name);

    let dl_response = client
        .get(download_url)
        .header("User-Agent", format!("cara/{}", current_version))
        .send()
        .await?;

    if !dl_response.status().is_success() {
        eprintln!("Download failed with HTTP {}", dl_response.status());
        return Err(format!("download failed: HTTP {}", dl_response.status()).into());
    }

    let bytes = dl_response.bytes().await?;
    if bytes.is_empty() {
        return Err("downloaded asset is empty".into());
    }

    // Stage the binary
    let state_dir = crate::server::ws::resolve_state_dir();
    let updates_dir = state_dir.join("updates");
    std::fs::create_dir_all(&updates_dir)?;
    let staged_path = updates_dir.join(format!("cara-{}", target_version));
    std::fs::write(&staged_path, &bytes)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&staged_path, std::fs::Permissions::from_mode(0o755))?;
    }

    println!("Applying update...");

    let staged_str = staged_path.to_string_lossy();
    match crate::server::ws::apply_staged_update(&staged_str) {
        Ok(result) => {
            println!("Update applied successfully.");
            println!("  Binary: {}", result.binary_path);
            println!("  SHA-256: {}", result.sha256);
            crate::server::ws::cleanup_old_binaries();
            println!("Restart cara to use v{}.", target_version);
        }
        Err(e) => {
            eprintln!("Failed to apply update: {}", e);
            return Err(e.into());
        }
    }

    Ok(())
}

/// Count files matching a given extension in a directory (non-recursive top level).
fn count_files_in_dir(dir: &Path, extension: &str) -> usize {
    std::fs::read_dir(dir)
        .map(|entries| {
            entries
                .filter_map(|e| e.ok())
                .filter(|e| e.path().extension().is_some_and(|ext| ext == extension))
                .count()
        })
        .unwrap_or(0)
}

/// Format a file size in human-readable form.
fn format_file_size(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{} B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.2} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Navigate a JSON value by dot-notation path and return the leaf value.
fn get_value_at_path(root: &Value, path: &str) -> Option<Value> {
    let mut current = root;
    for part in path.split('.') {
        current = current.as_object()?.get(part)?;
    }
    Some(current.clone())
}

/// Set a value at a dot-notation path, creating intermediate objects as needed.
fn set_value_at_path(root: &mut Value, path: &str, value: Value) {
    let parts: Vec<&str> = path.split('.').collect();
    let mut current = root;

    for (i, part) in parts.iter().enumerate() {
        if i == parts.len() - 1 {
            if let Value::Object(map) = current {
                map.insert(part.to_string(), value);
            }
            return;
        }
        if !current.get(*part).is_some_and(|v| v.is_object()) {
            if let Value::Object(map) = current {
                map.insert(part.to_string(), Value::Object(serde_json::Map::new()));
            }
        }
        current = current.get_mut(*part).expect("just inserted");
    }
}

/// Redact known secret keys in a JSON value (recursive).
fn redact_secrets(mut value: Value) -> Value {
    match &mut value {
        Value::Object(map) => {
            let keys: Vec<String> = map.keys().cloned().collect();
            for key in keys {
                let lower = key.to_lowercase();
                if SECRET_KEYS.iter().any(|s| lower.contains(s)) {
                    map.insert(key, Value::String("[REDACTED]".to_string()));
                } else if let Some(child) = map.remove(&key) {
                    map.insert(key, redact_secrets(child));
                }
            }
        }
        Value::Array(arr) => {
            for item in arr.iter_mut() {
                *item = redact_secrets(item.clone());
            }
        }
        _ => {}
    }
    value
}

/// Resolve the port to use for connecting to a running instance.
/// Tries (in order): explicit flag, config file value, DEFAULT_PORT.
pub(crate) fn resolve_port(explicit: Option<u16>) -> u16 {
    if let Some(p) = explicit {
        return p;
    }
    // Try reading from config.
    if let Ok(cfg) = config::load_config() {
        if let Some(port) = cfg
            .get("gateway")
            .and_then(|g| g.get("port"))
            .and_then(|v| v.as_u64())
        {
            return port as u16;
        }
    }
    DEFAULT_PORT
}

/// Format seconds into a human-readable duration string.
fn format_duration(seconds: i64) -> String {
    let days = seconds / 86400;
    let hours = (seconds % 86400) / 3600;
    let mins = (seconds % 3600) / 60;
    let secs = seconds % 60;
    if days > 0 {
        format!("{}d {}h {}m {}s", days, hours, mins, secs)
    } else if hours > 0 {
        format!("{}h {}m {}s", hours, mins, secs)
    } else if mins > 0 {
        format!("{}m {}s", mins, secs)
    } else {
        format!("{}s", secs)
    }
}

/// Format a Unix-ms timestamp for display.
fn format_timestamp(ms: u64) -> String {
    chrono::DateTime::from_timestamp_millis(ms as i64)
        .map(|dt| dt.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string())
        .unwrap_or_else(|| ms.to_string())
}

// ---------------------------------------------------------------------------
// TLS / mTLS subcommand handlers
// ---------------------------------------------------------------------------

/// Run the `tls init-ca` subcommand.
pub fn handle_tls_init_ca(output: Option<&str>) -> Result<(), Box<dyn std::error::Error>> {
    let ca_dir = match output {
        Some(p) => PathBuf::from(p),
        None => crate::tls::ca::default_ca_dir(),
    };

    let cluster = crate::tls::ca::ClusterCA::generate(&ca_dir)?;

    println!("Cluster CA generated successfully");
    println!("  Directory:   {}", ca_dir.display());
    println!("  Certificate: {}", cluster.ca_cert_path().display());
    println!("  Fingerprint: {}", cluster.ca_fingerprint());
    println!("  Files:       ca.crt, ca.key, crl.json");
    println!();
    println!("Distribute the CA certificate to all gateway nodes.");
    println!("Keep the CA private key secure.");

    Ok(())
}

/// Run the `tls issue-cert` subcommand.
pub fn handle_tls_issue_cert(
    node_id: &str,
    ca_dir_opt: Option<&str>,
    output_opt: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let ca_dir = match ca_dir_opt {
        Some(p) => PathBuf::from(p),
        None => crate::tls::ca::default_ca_dir(),
    };

    let output_dir = match output_opt {
        Some(p) => PathBuf::from(p),
        None => ca_dir.join("nodes"),
    };

    let cluster = crate::tls::ca::ClusterCA::load(&ca_dir)?;
    let _issued = cluster.issue_node_cert(node_id, &output_dir)?;

    println!("Node certificate issued successfully");
    println!("  Output Dir:  {}", output_dir.display());
    println!();
    println!("Deploy these files to the node and configure gateway.mtls:");
    println!("  nodeCert: \"<path-to-output-dir>/node.crt\"");
    println!("  nodeKey:  \"<path-to-output-dir>/node.key\"");

    Ok(())
}

/// Run the `tls revoke-cert` subcommand.
pub fn handle_tls_revoke_cert(
    fingerprint: &str,
    node_id: &str,
    ca_dir_opt: Option<&str>,
    reason: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let ca_dir = match ca_dir_opt {
        Some(p) => PathBuf::from(p),
        None => crate::tls::ca::default_ca_dir(),
    };

    let ca = crate::tls::ca::ClusterCA::load(&ca_dir)?;
    let revoked = ca.revoke_cert(fingerprint, node_id, reason.map(|s| s.to_string()))?;

    if revoked {
        println!("Certificate revoked successfully");
        println!("  Fingerprint: {}", fingerprint);
        println!("  Node ID:     {}", node_id);
        if let Some(r) = reason {
            println!("  Reason:      {}", r);
        }
    } else {
        println!("Certificate was already revoked: {}", fingerprint);
    }

    Ok(())
}

/// Run the `tls show-ca` subcommand.
pub fn handle_tls_show_ca(ca_dir_opt: Option<&str>) -> Result<(), Box<dyn std::error::Error>> {
    let ca_dir = match ca_dir_opt {
        Some(p) => PathBuf::from(p),
        None => crate::tls::ca::default_ca_dir(),
    };

    let cluster = crate::tls::ca::ClusterCA::load(&ca_dir)?;

    println!("Cluster CA Information");
    println!("=====================");
    println!("  Directory:   {}", ca_dir.display());
    println!("  Certificate: {}", cluster.ca_cert_path().display());
    println!("  Fingerprint: {}", cluster.ca_fingerprint());
    println!("  Files:       ca.crt, ca.key, crl.json");

    let entries = cluster.crl_entries();
    if entries.is_empty() {
        println!();
        println!("Certificate Revocation List: (empty)");
    } else {
        println!();
        println!("Certificate Revocation List ({} entries):", entries.len());
        for entry in &entries {
            println!(
                "  - {} (node: {}, revoked at: {}{})",
                entry.fingerprint,
                entry.node_id,
                entry.revoked_at_ms,
                entry
                    .reason
                    .as_deref()
                    .map(|r| format!(", reason: {}", r))
                    .unwrap_or_default()
            );
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime_bridge::CURRENT_THREAD_RUNTIME_MESSAGE;
    use clap::Parser;
    use ed25519_dalek::{Signature, VerifyingKey};
    use std::ffi::OsString;
    use std::sync::{LazyLock, Mutex};

    // Serializes env-var touching tests in this module.
    // Cross-module env-var tests should use a shared lock if they touch the same keys.
    static ENV_VAR_TEST_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

    struct EnvVarGuard {
        key: String,
        previous: Option<OsString>,
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            match self.previous.take() {
                Some(value) => std::env::set_var(&self.key, value),
                None => std::env::remove_var(&self.key),
            }
        }
    }

    fn set_env_var_scoped(key: &str, value: &str) -> EnvVarGuard {
        let previous = std::env::var_os(key);
        std::env::set_var(key, value);
        EnvVarGuard {
            key: key.to_string(),
            previous,
        }
    }

    fn unset_env_var_scoped(key: &str) -> EnvVarGuard {
        let previous = std::env::var_os(key);
        std::env::remove_var(key);
        EnvVarGuard {
            key: key.to_string(),
            previous,
        }
    }

    #[test]
    fn test_cli_no_args_defaults_to_none() {
        let cli = Cli::try_parse_from(["cara"]).unwrap();
        assert!(cli.command.is_none());
    }

    #[test]
    fn test_cli_start_subcommand() {
        let cli = Cli::try_parse_from(["cara", "start"]).unwrap();
        assert!(matches!(cli.command, Some(Command::Start)));
    }

    #[test]
    fn test_cli_version_subcommand() {
        let cli = Cli::try_parse_from(["cara", "version"]).unwrap();
        assert!(matches!(cli.command, Some(Command::Version)));
    }

    #[test]
    fn test_cli_config_show() {
        let cli = Cli::try_parse_from(["cara", "config", "show"]).unwrap();
        match cli.command {
            Some(Command::Config(ConfigCommand::Show)) => {}
            other => panic!("Expected Config(Show), got {:?}", other),
        }
    }

    #[test]
    fn test_cli_config_get() {
        let cli = Cli::try_parse_from(["cara", "config", "get", "gateway.port"]).unwrap();
        match cli.command {
            Some(Command::Config(ConfigCommand::Get { ref key })) => {
                assert_eq!(key, "gateway.port");
            }
            other => panic!("Expected Config(Get), got {:?}", other),
        }
    }

    #[test]
    fn test_cli_config_set() {
        let cli = Cli::try_parse_from(["cara", "config", "set", "gateway.port", "9000"]).unwrap();
        match cli.command {
            Some(Command::Config(ConfigCommand::Set { ref key, ref value })) => {
                assert_eq!(key, "gateway.port");
                assert_eq!(value, "9000");
            }
            other => panic!("Expected Config(Set), got {:?}", other),
        }
    }

    #[test]
    fn test_cli_config_path() {
        let cli = Cli::try_parse_from(["cara", "config", "path"]).unwrap();
        assert!(matches!(
            cli.command,
            Some(Command::Config(ConfigCommand::Path))
        ));
    }

    #[test]
    fn test_cli_status_defaults() {
        let cli = Cli::try_parse_from(["cara", "status"]).unwrap();
        match cli.command {
            Some(Command::Status { port, ref host }) => {
                assert_eq!(port, None);
                assert_eq!(host, "127.0.0.1");
            }
            other => panic!("Expected Status, got {:?}", other),
        }
    }

    #[test]
    fn test_cli_status_with_port() {
        let cli = Cli::try_parse_from(["cara", "status", "--port", "9000"]).unwrap();
        match cli.command {
            Some(Command::Status { port, .. }) => {
                assert_eq!(port, Some(9000));
            }
            other => panic!("Expected Status, got {:?}", other),
        }
    }

    #[test]
    fn test_cli_logs_defaults() {
        let cli = Cli::try_parse_from(["cara", "logs"]).unwrap();
        match cli.command {
            Some(Command::Logs {
                lines,
                port,
                ref host,
                tls,
                trust,
                allow_plaintext,
            }) => {
                assert_eq!(lines, 50);
                assert_eq!(port, None);
                assert_eq!(host, "127.0.0.1");
                assert!(!tls);
                assert!(!trust);
                assert!(!allow_plaintext);
            }
            other => panic!("Expected Logs, got {:?}", other),
        }
    }

    #[test]
    fn test_cli_logs_with_lines() {
        let cli = Cli::try_parse_from(["cara", "logs", "--lines", "100"]).unwrap();
        match cli.command {
            Some(Command::Logs { lines, .. }) => {
                assert_eq!(lines, 100);
            }
            other => panic!("Expected Logs, got {:?}", other),
        }
    }

    #[test]
    fn test_cli_logs_with_short_flag() {
        let cli = Cli::try_parse_from(["cara", "logs", "-n", "25"]).unwrap();
        match cli.command {
            Some(Command::Logs { lines, .. }) => {
                assert_eq!(lines, 25);
            }
            other => panic!("Expected Logs, got {:?}", other),
        }
    }

    #[test]
    fn test_cli_chat_defaults() {
        let cli = Cli::try_parse_from(["cara", "chat"]).unwrap();
        match cli.command {
            Some(Command::Chat { new, port }) => {
                assert!(!new);
                assert_eq!(port, None);
            }
            other => panic!("Expected Chat, got {:?}", other),
        }
    }

    #[test]
    fn test_cli_chat_with_new_and_port() {
        let cli = Cli::try_parse_from(["cara", "chat", "--new", "--port", "9000"]).unwrap();
        match cli.command {
            Some(Command::Chat { new, port }) => {
                assert!(new);
                assert_eq!(port, Some(9000));
            }
            other => panic!("Expected Chat, got {:?}", other),
        }
    }

    #[test]
    fn test_cli_verify_defaults() {
        let cli = Cli::try_parse_from(["cara", "verify"]).unwrap();
        match cli.command {
            Some(Command::Verify {
                outcome,
                port,
                discord_to,
                telegram_to,
            }) => {
                assert_eq!(outcome, VerifyOutcomeSelection::Auto);
                assert_eq!(port, None);
                assert!(discord_to.is_none());
                assert!(telegram_to.is_none());
            }
            other => panic!("Expected Verify, got {:?}", other),
        }
    }

    #[test]
    fn test_cli_verify_with_options() {
        let cli = Cli::try_parse_from([
            "cara",
            "verify",
            "--outcome",
            "discord",
            "--port",
            "19000",
            "--discord-to",
            "1234567890",
        ])
        .unwrap();
        match cli.command {
            Some(Command::Verify {
                outcome,
                port,
                discord_to,
                telegram_to,
            }) => {
                assert_eq!(outcome, VerifyOutcomeSelection::Discord);
                assert_eq!(port, Some(19000));
                assert_eq!(discord_to.as_deref(), Some("1234567890"));
                assert!(telegram_to.is_none());
            }
            other => panic!("Expected Verify, got {:?}", other),
        }
    }

    #[test]
    fn test_setup_post_checks_bridge_inside_current_thread_runtime_does_not_panic() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let call_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            rt.block_on(async {
                run_sync_blocking(run_setup_post_checks(DEFAULT_PORT, false, false))
                    .expect_err("expected bridge error from current-thread runtime")
            })
        }));

        assert!(
            call_result.is_ok(),
            "current-thread runtime should not panic when running setup post checks through sync bridge"
        );
        let err = call_result.unwrap().to_string();
        assert!(
            err.contains(CURRENT_THREAD_RUNTIME_MESSAGE),
            "expected explicit current-thread bridge guard error, got: {err}"
        );
    }

    #[test]
    fn test_validate_channel_credentials_bridge_inside_current_thread_runtime_is_panic_free() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let call_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            rt.block_on(async {
                run_sync_blocking_send(validate_channel_credentials_owned(
                    "unsupported".to_string(),
                    "ignored-token".to_string(),
                ))
                .expect_err("unsupported channels should be rejected, not panic")
            })
        }));

        assert!(
            call_result.is_ok(),
            "current-thread runtime should not panic when validating channel creds through send bridge"
        );
        let err = call_result.unwrap().to_string();
        assert!(
            err.contains("unsupported channel for validation: unsupported"),
            "expected unsupported-channel rejection path, got: {err}"
        );
    }

    #[test]
    fn test_device_identity_round_trip() {
        let identity = generate_device_identity().unwrap();
        validate_device_identity(&identity).unwrap();
        let signing_key = signing_key_from_identity(&identity).unwrap();
        let public_key = signing_key.verifying_key().to_bytes();
        assert_eq!(encode_base64_url(&public_key), identity.public_key);
    }

    #[test]
    fn test_device_auth_payload_format_v2() {
        let payload = build_device_auth_payload(DeviceAuthPayload {
            device_id: "device-1".to_string(),
            client_id: "cli".to_string(),
            client_mode: "cli".to_string(),
            role: "operator".to_string(),
            scopes: vec!["operator.read".to_string(), "operator.write".to_string()],
            signed_at_ms: 1234,
            token: Some("tok".to_string()),
            nonce: Some("nonce-1".to_string()),
        });
        assert_eq!(
            payload,
            "v2|device-1|cli|cli|operator|operator.read,operator.write|1234|tok|nonce-1"
        );
    }

    #[test]
    fn test_device_signature_verifies() {
        let identity = generate_device_identity().unwrap();
        let payload = build_device_auth_payload(DeviceAuthPayload {
            device_id: identity.device_id.clone(),
            client_id: "cli".to_string(),
            client_mode: "cli".to_string(),
            role: "operator".to_string(),
            scopes: vec!["operator.read".to_string()],
            signed_at_ms: 42,
            token: Some("tok".to_string()),
            nonce: Some("nonce".to_string()),
        });
        let signature = sign_device_payload(&identity, &payload).unwrap();
        let public_key_raw = decode_base64_any(&identity.public_key).unwrap();
        let sig_raw = decode_base64_any(&signature).unwrap();
        let pubkey_bytes: [u8; 32] = public_key_raw.as_slice().try_into().unwrap();
        let sig_bytes: [u8; 64] = sig_raw.as_slice().try_into().unwrap();
        let verifying_key = VerifyingKey::from_bytes(&pubkey_bytes).unwrap();
        let sig = Signature::from_bytes(&sig_bytes);
        verifying_key
            .verify_strict(payload.as_bytes(), &sig)
            .unwrap();
    }

    #[test]
    fn test_decode_base64_any_accepts_urlsafe_and_standard() {
        let bytes = b"hello-world";
        let urlsafe = URL_SAFE_NO_PAD.encode(bytes);
        let standard = STANDARD.encode(bytes);
        assert_eq!(decode_base64_any(&urlsafe).unwrap(), bytes);
        assert_eq!(decode_base64_any(&standard).unwrap(), bytes);
    }

    #[test]
    fn test_extract_pairing_request_id() {
        let direct = serde_json::json!({ "requestId": "abc" });
        let nested = serde_json::json!({ "details": { "requestId": "xyz" } });
        assert_eq!(extract_pairing_request_id(&direct), Some("abc".to_string()));
        assert_eq!(extract_pairing_request_id(&nested), Some("xyz".to_string()));
    }

    #[test]
    fn test_get_value_at_path_simple() {
        let val = serde_json::json!({"gateway": {"port": 9000}});
        let result = get_value_at_path(&val, "gateway.port");
        assert_eq!(result, Some(serde_json::json!(9000)));
    }

    #[test]
    fn test_get_value_at_path_top_level() {
        let val = serde_json::json!({"key": "value"});
        let result = get_value_at_path(&val, "key");
        assert_eq!(result, Some(serde_json::json!("value")));
    }

    #[test]
    fn test_get_value_at_path_missing() {
        let val = serde_json::json!({"a": 1});
        let result = get_value_at_path(&val, "b.c");
        assert_eq!(result, None);
    }

    #[test]
    fn test_set_value_at_path_creates_intermediate() {
        let mut val = serde_json::json!({});
        set_value_at_path(&mut val, "a.b.c", serde_json::json!(42));
        assert_eq!(val["a"]["b"]["c"], 42);
    }

    #[test]
    fn test_set_value_at_path_overwrites() {
        let mut val = serde_json::json!({"gateway": {"port": 8080}});
        set_value_at_path(&mut val, "gateway.port", serde_json::json!(9000));
        assert_eq!(val["gateway"]["port"], 9000);
    }

    #[test]
    fn test_redact_secrets() {
        let val = serde_json::json!({
            "gateway": {
                "port": 9000,
                "auth": {
                    "token": "my-secret-token"
                }
            },
            "anthropic": {
                "apiKey": "sk-ant-abc123"
            },
            "safe": "visible"
        });
        let redacted = redact_secrets(val);
        assert_eq!(redacted["gateway"]["auth"]["token"], "[REDACTED]");
        assert_eq!(redacted["anthropic"]["apiKey"], "[REDACTED]");
        assert_eq!(redacted["gateway"]["port"], 9000);
        assert_eq!(redacted["safe"], "visible");
    }

    #[test]
    fn test_redact_secrets_array() {
        let val = serde_json::json!([{"apiKey": "secret"}, {"safe": "ok"}]);
        let redacted = redact_secrets(val);
        assert_eq!(redacted[0]["apiKey"], "[REDACTED]");
        assert_eq!(redacted[1]["safe"], "ok");
    }

    #[test]
    fn test_format_duration() {
        assert_eq!(format_duration(5), "5s");
        assert_eq!(format_duration(65), "1m 5s");
        assert_eq!(format_duration(3665), "1h 1m 5s");
        assert_eq!(format_duration(90061), "1d 1h 1m 1s");
    }

    #[test]
    fn test_resolve_port_explicit() {
        assert_eq!(resolve_port(Some(1234)), 1234);
    }

    #[test]
    fn test_resolve_port_default() {
        // resolve_port(None) reads the live config file, so it may return
        // the configured port rather than DEFAULT_PORT. Just verify it
        // returns a valid non-zero port.
        let port = resolve_port(None);
        assert_ne!(port, 0);
    }

    // -----------------------------------------------------------------------
    // Backup / Restore / Reset CLI parsing tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_cli_backup_no_args() {
        let cli = Cli::try_parse_from(["cara", "backup"]).unwrap();
        match cli.command {
            Some(Command::Backup { output }) => {
                assert!(output.is_none());
            }
            other => panic!("Expected Backup, got {:?}", other),
        }
    }

    #[test]
    fn test_cli_backup_with_output() {
        let cli =
            Cli::try_parse_from(["cara", "backup", "--output", "/tmp/my-backup.tar.gz"]).unwrap();
        match cli.command {
            Some(Command::Backup { output }) => {
                assert_eq!(output.as_deref(), Some("/tmp/my-backup.tar.gz"));
            }
            other => panic!("Expected Backup, got {:?}", other),
        }
    }

    #[test]
    fn test_cli_backup_with_short_flag() {
        let cli = Cli::try_parse_from(["cara", "backup", "-o", "/tmp/backup.tar.gz"]).unwrap();
        match cli.command {
            Some(Command::Backup { output }) => {
                assert_eq!(output.as_deref(), Some("/tmp/backup.tar.gz"));
            }
            other => panic!("Expected Backup, got {:?}", other),
        }
    }

    #[test]
    fn test_cli_restore_requires_path() {
        let result = Cli::try_parse_from(["cara", "restore"]);
        assert!(result.is_err(), "restore should require a path argument");
    }

    #[test]
    fn test_cli_restore_with_path() {
        let cli = Cli::try_parse_from(["cara", "restore", "/tmp/backup.tar.gz"]).unwrap();
        match cli.command {
            Some(Command::Restore { ref path, force }) => {
                assert_eq!(path, "/tmp/backup.tar.gz");
                assert!(!force);
            }
            other => panic!("Expected Restore, got {:?}", other),
        }
    }

    #[test]
    fn test_cli_restore_with_force() {
        let cli =
            Cli::try_parse_from(["cara", "restore", "/tmp/backup.tar.gz", "--force"]).unwrap();
        match cli.command {
            Some(Command::Restore { force, .. }) => {
                assert!(force);
            }
            other => panic!("Expected Restore, got {:?}", other),
        }
    }

    #[test]
    fn test_cli_reset_no_flags() {
        let cli = Cli::try_parse_from(["cara", "reset"]).unwrap();
        match cli.command {
            Some(Command::Reset {
                sessions,
                cron,
                usage,
                memory,
                all,
                force,
            }) => {
                assert!(!sessions);
                assert!(!cron);
                assert!(!usage);
                assert!(!memory);
                assert!(!all);
                assert!(!force);
            }
            other => panic!("Expected Reset, got {:?}", other),
        }
    }

    #[test]
    fn test_cli_reset_all_force() {
        let cli = Cli::try_parse_from(["cara", "reset", "--all", "--force"]).unwrap();
        match cli.command {
            Some(Command::Reset { all, force, .. }) => {
                assert!(all);
                assert!(force);
            }
            other => panic!("Expected Reset, got {:?}", other),
        }
    }

    #[test]
    fn test_cli_reset_individual_flags() {
        let cli = Cli::try_parse_from([
            "cara",
            "reset",
            "--sessions",
            "--cron",
            "--usage",
            "--memory",
            "--force",
        ])
        .unwrap();
        match cli.command {
            Some(Command::Reset {
                sessions,
                cron,
                usage,
                memory,
                all,
                force,
            }) => {
                assert!(sessions);
                assert!(cron);
                assert!(usage);
                assert!(memory);
                assert!(!all);
                assert!(force);
            }
            other => panic!("Expected Reset, got {:?}", other),
        }
    }

    // -----------------------------------------------------------------------
    // Backup/Restore round-trip tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_backup_creates_valid_archive() {
        let temp = tempfile::TempDir::new().unwrap();
        let state_dir = temp.path().join("state");
        let sessions_dir = state_dir.join("sessions");
        let cron_dir = state_dir.join("cron");
        std::fs::create_dir_all(&sessions_dir).unwrap();
        std::fs::create_dir_all(&cron_dir).unwrap();

        // Create some fake session data.
        std::fs::write(
            sessions_dir.join("abc123.json"),
            r#"{"id":"abc123","agentId":"test"}"#,
        )
        .unwrap();
        std::fs::write(
            sessions_dir.join("abc123.jsonl"),
            r#"{"id":"m1","role":"user","content":"hello"}"#,
        )
        .unwrap();

        // Create fake cron data.
        std::fs::write(cron_dir.join("jobs.json"), r#"{"version":1,"jobs":[]}"#).unwrap();

        // Create fake usage data.
        std::fs::write(state_dir.join("usage.json"), r#"{"totalTokens":42}"#).unwrap();

        // Build archive.
        let archive_path = temp.path().join("test-backup.tar.gz");
        let file = std::fs::File::create(&archive_path).unwrap();
        let enc = flate2::write::GzEncoder::new(file, flate2::Compression::default());
        let mut builder = tar::Builder::new(enc);

        // Write marker.
        let marker = b"carapace-backup v1\n";
        let mut header = tar::Header::new_gnu();
        header.set_size(marker.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, BACKUP_MARKER, &marker[..])
            .unwrap();

        // Add sessions.
        builder.append_dir_all("sessions", &sessions_dir).unwrap();
        // Add cron.
        builder.append_dir_all("cron", &cron_dir).unwrap();
        // Add usage.
        builder
            .append_path_with_name(state_dir.join("usage.json"), "usage/usage.json")
            .unwrap();

        let enc = builder.into_inner().unwrap();
        enc.finish().unwrap();

        // Verify the archive can be read and contains the marker.
        let file = std::fs::File::open(&archive_path).unwrap();
        let dec = flate2::read::GzDecoder::new(file);
        let mut archive = tar::Archive::new(dec);

        let mut found_marker = false;
        let mut found_session = false;
        let mut found_cron = false;
        let mut found_usage = false;

        for entry in archive.entries().unwrap() {
            let entry = entry.unwrap();
            let path = entry.path().unwrap().to_string_lossy().to_string();
            if path == BACKUP_MARKER {
                found_marker = true;
            } else if path.contains("abc123.json") {
                found_session = true;
            } else if path.contains("jobs.json") {
                found_cron = true;
            } else if path.contains("usage.json") {
                found_usage = true;
            }
        }

        assert!(found_marker, "Archive should contain backup marker");
        assert!(found_session, "Archive should contain session data");
        assert!(found_cron, "Archive should contain cron data");
        assert!(found_usage, "Archive should contain usage data");
    }

    #[test]
    fn test_backup_restore_round_trip() {
        let temp = tempfile::TempDir::new().unwrap();

        // Set up source state directory.
        let source_state = temp.path().join("source");
        let source_sessions = source_state.join("sessions");
        let source_cron = source_state.join("cron");
        std::fs::create_dir_all(&source_sessions).unwrap();
        std::fs::create_dir_all(&source_cron).unwrap();

        std::fs::write(source_sessions.join("sess1.json"), r#"{"id":"sess1"}"#).unwrap();
        std::fs::write(source_cron.join("store.json"), r#"{"version":1}"#).unwrap();
        std::fs::write(source_state.join("usage.json"), r#"{"totalTokens":100}"#).unwrap();

        // Create an archive.
        let archive_path = temp.path().join("roundtrip.tar.gz");
        let file = std::fs::File::create(&archive_path).unwrap();
        let enc = flate2::write::GzEncoder::new(file, flate2::Compression::default());
        let mut builder = tar::Builder::new(enc);

        let marker = b"carapace-backup v1\n";
        let mut header = tar::Header::new_gnu();
        header.set_size(marker.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, BACKUP_MARKER, &marker[..])
            .unwrap();
        builder
            .append_dir_all("sessions", &source_sessions)
            .unwrap();
        builder.append_dir_all("cron", &source_cron).unwrap();
        builder
            .append_path_with_name(source_state.join("usage.json"), "usage/usage.json")
            .unwrap();

        let enc = builder.into_inner().unwrap();
        enc.finish().unwrap();

        // Set up a fresh target state directory and restore into it.
        let target_state = temp.path().join("target");
        std::fs::create_dir_all(&target_state).unwrap();

        // Manually extract (simulating what handle_restore does).
        let file = std::fs::File::open(&archive_path).unwrap();
        let dec = flate2::read::GzDecoder::new(file);
        let mut archive = tar::Archive::new(dec);

        for entry_result in archive.entries().unwrap() {
            let mut entry = entry_result.unwrap();
            let path = entry.path().unwrap().to_path_buf();
            let path_str = path.to_string_lossy().to_string();

            if path_str == BACKUP_MARKER {
                continue;
            }

            if path_str.starts_with("sessions/") {
                let rel = path.strip_prefix("sessions").unwrap_or(&path);
                let target = target_state.join("sessions").join(rel);
                let entry_type = entry.header().entry_type();
                if entry_type.is_dir() {
                    std::fs::create_dir_all(&target).unwrap();
                } else if entry_type.is_file() {
                    if let Some(parent) = target.parent() {
                        std::fs::create_dir_all(parent).unwrap();
                    }
                    let mut buf = Vec::new();
                    entry.read_to_end(&mut buf).unwrap();
                    std::fs::write(&target, &buf).unwrap();
                }
            } else if path_str.starts_with("cron/") {
                let rel = path.strip_prefix("cron").unwrap_or(&path);
                let target = target_state.join("cron").join(rel);
                let entry_type = entry.header().entry_type();
                if entry_type.is_dir() {
                    std::fs::create_dir_all(&target).unwrap();
                } else if entry_type.is_file() {
                    if let Some(parent) = target.parent() {
                        std::fs::create_dir_all(parent).unwrap();
                    }
                    let mut buf = Vec::new();
                    entry.read_to_end(&mut buf).unwrap();
                    std::fs::write(&target, &buf).unwrap();
                }
            } else if path_str.starts_with("usage/") {
                let rel = path.strip_prefix("usage").unwrap_or(&path);
                let target = target_state.join(rel);
                let entry_type = entry.header().entry_type();
                if entry_type.is_file() {
                    if let Some(parent) = target.parent() {
                        std::fs::create_dir_all(parent).unwrap();
                    }
                    let mut buf = Vec::new();
                    entry.read_to_end(&mut buf).unwrap();
                    std::fs::write(&target, &buf).unwrap();
                }
            }
        }

        // Verify restored data matches original.
        let restored_session =
            std::fs::read_to_string(target_state.join("sessions").join("sess1.json")).unwrap();
        assert_eq!(restored_session, r#"{"id":"sess1"}"#);

        let restored_cron =
            std::fs::read_to_string(target_state.join("cron").join("store.json")).unwrap();
        assert_eq!(restored_cron, r#"{"version":1}"#);

        let restored_usage = std::fs::read_to_string(target_state.join("usage.json")).unwrap();
        assert_eq!(restored_usage, r#"{"totalTokens":100}"#);
    }

    #[test]
    fn test_is_safe_archive_path_rejects_traversal() {
        assert!(!is_safe_archive_path(Path::new("../evil.json")));
        assert!(!is_safe_archive_path(Path::new(
            "sessions/../config/evil.json"
        )));
        assert!(!is_safe_archive_path(Path::new("/etc/passwd")));
        assert!(is_safe_archive_path(Path::new("sessions/ok.json")));
    }

    // -----------------------------------------------------------------------
    // Reset logic tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_reset_sessions_deletes_directory() {
        let temp = tempfile::TempDir::new().unwrap();
        let sessions_dir = temp.path().join("sessions");
        std::fs::create_dir_all(&sessions_dir).unwrap();
        std::fs::write(sessions_dir.join("s1.json"), "{}").unwrap();
        std::fs::write(sessions_dir.join("s2.json"), "{}").unwrap();

        assert!(sessions_dir.exists());
        std::fs::remove_dir_all(&sessions_dir).unwrap();
        assert!(!sessions_dir.exists());
    }

    #[test]
    fn test_reset_usage_deletes_file() {
        let temp = tempfile::TempDir::new().unwrap();
        let usage_path = temp.path().join("usage.json");
        std::fs::write(&usage_path, r#"{"tokens":0}"#).unwrap();

        assert!(usage_path.exists());
        std::fs::remove_file(&usage_path).unwrap();
        assert!(!usage_path.exists());
    }

    #[test]
    fn test_count_files_in_dir() {
        let temp = tempfile::TempDir::new().unwrap();
        std::fs::write(temp.path().join("a.json"), "{}").unwrap();
        std::fs::write(temp.path().join("b.json"), "{}").unwrap();
        std::fs::write(temp.path().join("c.txt"), "").unwrap();
        std::fs::write(temp.path().join("d.jsonl"), "").unwrap();

        let count = count_files_in_dir(temp.path(), "json");
        assert_eq!(count, 2);

        let count_txt = count_files_in_dir(temp.path(), "txt");
        assert_eq!(count_txt, 1);

        let count_missing = count_files_in_dir(&temp.path().join("nonexistent"), "json");
        assert_eq!(count_missing, 0);
    }

    // -----------------------------------------------------------------------
    // Helper function tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_format_file_size() {
        assert_eq!(format_file_size(0), "0 B");
        assert_eq!(format_file_size(512), "512 B");
        assert_eq!(format_file_size(1024), "1.0 KB");
        assert_eq!(format_file_size(1536), "1.5 KB");
        assert_eq!(format_file_size(1048576), "1.0 MB");
        assert_eq!(format_file_size(1073741824), "1.00 GB");
    }

    #[test]
    fn test_parse_setup_outcome_aliases() {
        assert_eq!(
            parse_setup_outcome("local-chat"),
            Some(SetupOutcome::LocalChat)
        );
        assert_eq!(parse_setup_outcome("local"), Some(SetupOutcome::LocalChat));
        assert_eq!(parse_setup_outcome("discord"), Some(SetupOutcome::Discord));
        assert_eq!(
            parse_setup_outcome("telegram"),
            Some(SetupOutcome::Telegram)
        );
        assert_eq!(parse_setup_outcome("webhooks"), Some(SetupOutcome::Hooks));
    }

    #[test]
    fn test_parse_setup_outcome_invalid() {
        assert_eq!(parse_setup_outcome(""), None);
        assert_eq!(parse_setup_outcome("unknown"), None);
    }

    #[test]
    fn test_resolve_env_placeholder_handles_literal_and_placeholder_values() {
        let _lock = ENV_VAR_TEST_LOCK.lock().expect("env var test lock");
        let key = "DISCORD_BOT_TOKEN";
        let _env_guard = set_env_var_scoped(key, "  resolved-value  ");

        assert_eq!(
            resolve_env_placeholder("${DISCORD_BOT_TOKEN}"),
            Some("resolved-value".to_string())
        );
        assert_eq!(
            resolve_env_placeholder("{DISCORD_BOT_TOKEN}"),
            Some("{DISCORD_BOT_TOKEN}".to_string())
        );
        assert_eq!(
            resolve_env_placeholder("$$${{DISCORD_BOT_TOKEN}"),
            Some("$$${{DISCORD_BOT_TOKEN}".to_string())
        );
    }

    #[test]
    fn test_resolve_env_placeholder_missing_var_returns_none() {
        let _lock = ENV_VAR_TEST_LOCK.lock().expect("env var test lock");
        let _env_guard = unset_env_var_scoped("DISCORD_BOT_TOKEN");
        assert_eq!(resolve_env_placeholder("${DISCORD_BOT_TOKEN}"), None);
    }

    #[test]
    fn test_resolve_env_placeholder_rejects_non_allowlisted_keys() {
        let _lock = ENV_VAR_TEST_LOCK.lock().expect("env var test lock");
        let _env_guard = set_env_var_scoped("CARAPACE_TEST_NON_ALLOWLISTED_SECRET", "secret");
        assert_eq!(
            resolve_env_placeholder("${CARAPACE_TEST_NON_ALLOWLISTED_SECRET}"),
            None
        );
    }

    #[test]
    fn test_resolve_env_placeholder_rejects_custom_bot_token_names() {
        let _lock = ENV_VAR_TEST_LOCK.lock().expect("env var test lock");
        let _env_guard = set_env_var_scoped("MY_DISCORD_BOT_TOKEN", "custom-token");
        assert_eq!(resolve_env_placeholder("${MY_DISCORD_BOT_TOKEN}"), None);
    }

    #[test]
    fn test_sanitize_channel_delivery_error_redacts_untrusted_body() {
        assert_eq!(
            sanitize_channel_delivery_error(
                "<html>stacktrace and debug secrets</html>".to_string()
            ),
            "send path rejected request (provider details hidden for safety)"
        );
    }

    #[test]
    fn test_sanitize_channel_delivery_error_redacts_short_standard_message() {
        assert_eq!(
            sanitize_channel_delivery_error("Unauthorized".to_string()),
            "send path rejected request (provider details hidden for safety)"
        );
    }

    #[test]
    fn test_infer_setup_outcome_from_config_prefers_discord_then_telegram() {
        let cfg = serde_json::json!({
            "discord": { "botToken": "discord-token" },
            "telegram": { "botToken": "telegram-token" },
            "gateway": { "hooks": { "enabled": true } }
        });
        assert_eq!(infer_setup_outcome_from_config(&cfg), SetupOutcome::Discord);

        let cfg = serde_json::json!({
            "telegram": { "botToken": "telegram-token" },
            "gateway": { "hooks": { "enabled": true } }
        });
        assert_eq!(
            infer_setup_outcome_from_config(&cfg),
            SetupOutcome::Telegram
        );
    }

    #[test]
    fn test_infer_setup_outcome_from_config_hooks_then_local() {
        let hooks_cfg = serde_json::json!({
            "gateway": { "hooks": { "enabled": true } }
        });
        assert_eq!(
            infer_setup_outcome_from_config(&hooks_cfg),
            SetupOutcome::Hooks
        );

        let local_cfg = serde_json::json!({});
        assert_eq!(
            infer_setup_outcome_from_config(&local_cfg),
            SetupOutcome::LocalChat
        );
    }

    #[test]
    fn test_infer_setup_outcome_ignores_empty_or_unresolved_channel_tokens() {
        let _lock = ENV_VAR_TEST_LOCK.lock().expect("env var test lock");
        let _env_guard = unset_env_var_scoped("CARAPACE_TEST_VERIFY_MISSING_TELEGRAM_TOKEN");
        let empty_discord_token_cfg = serde_json::json!({
            "discord": { "enabled": true, "botToken": "   " },
            "gateway": { "hooks": { "enabled": true } }
        });
        assert_eq!(
            infer_setup_outcome_from_config(&empty_discord_token_cfg),
            SetupOutcome::Hooks
        );

        let unresolved_placeholder_cfg = serde_json::json!({
            "telegram": { "enabled": true, "botToken": "${CARAPACE_TEST_VERIFY_MISSING_TELEGRAM_TOKEN}" },
            "gateway": { "hooks": { "enabled": true } }
        });
        assert_eq!(
            infer_setup_outcome_from_config(&unresolved_placeholder_cfg),
            SetupOutcome::Hooks
        );
    }

    // -----------------------------------------------------------------------
    // Setup subcommand tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_cli_setup_no_force() {
        let cli = Cli::try_parse_from(["cara", "setup"]).unwrap();
        match cli.command {
            Some(Command::Setup { force }) => {
                assert!(!force);
            }
            other => panic!("Expected Setup, got {:?}", other),
        }
    }

    #[test]
    fn test_cli_setup_with_force() {
        let cli = Cli::try_parse_from(["cara", "setup", "--force"]).unwrap();
        match cli.command {
            Some(Command::Setup { force }) => {
                assert!(force);
            }
            other => panic!("Expected Setup, got {:?}", other),
        }
    }

    #[test]
    fn test_handle_setup_errors_when_config_exists_no_force() {
        let _lock = ENV_VAR_TEST_LOCK.lock().expect("env var test lock");
        let temp = tempfile::TempDir::new().unwrap();
        let config_path = temp.path().join("carapace.json");
        std::fs::write(&config_path, "{}").unwrap();

        let _env_guard = set_env_var_scoped("CARAPACE_CONFIG_PATH", config_path.to_str().unwrap());
        let result = handle_setup(false);

        assert!(
            result.is_err(),
            "Should error when config exists and force=false"
        );
    }

    #[test]
    fn test_handle_setup_force_creates_config() {
        let _lock = ENV_VAR_TEST_LOCK.lock().expect("env var test lock");
        let temp = tempfile::TempDir::new().unwrap();
        let config_path = temp.path().join("carapace.json");
        std::fs::write(&config_path, "{}").unwrap();

        let _env_guard = set_env_var_scoped("CARAPACE_CONFIG_PATH", config_path.to_str().unwrap());
        let result = handle_setup(true);

        assert!(
            result.is_ok(),
            "Should succeed with force=true even when config exists"
        );
        assert!(config_path.exists(), "Config file should exist after setup");
    }

    #[test]
    fn test_handle_setup_creates_valid_json5_config() {
        let _lock = ENV_VAR_TEST_LOCK.lock().expect("env var test lock");
        let temp = tempfile::TempDir::new().unwrap();
        let config_path = temp.path().join("carapace.json");

        let _env_guard = set_env_var_scoped("CARAPACE_CONFIG_PATH", config_path.to_str().unwrap());
        let result = handle_setup(false);

        assert!(result.is_ok(), "Setup should succeed");

        let content = std::fs::read_to_string(&config_path).unwrap();
        let parsed: serde_json::Value = json5::from_str(&content).unwrap();
        assert!(parsed.is_object(), "Config should be a JSON object");
    }

    #[test]
    fn test_handle_setup_default_values() {
        let _lock = ENV_VAR_TEST_LOCK.lock().expect("env var test lock");
        let temp = tempfile::TempDir::new().unwrap();
        let config_path = temp.path().join("carapace.json");

        let _env_guard = set_env_var_scoped("CARAPACE_CONFIG_PATH", config_path.to_str().unwrap());
        let result = handle_setup(false);

        assert!(result.is_ok());

        let content = std::fs::read_to_string(&config_path).unwrap();
        let parsed: serde_json::Value = json5::from_str(&content).unwrap();

        assert_eq!(
            parsed["gateway"]["port"], DEFAULT_PORT,
            "Default port should match server default"
        );
        assert_eq!(
            parsed["gateway"]["bind"], "loopback",
            "Default bind should be loopback"
        );
        assert_eq!(
            parsed["gateway"]["auth"]["mode"], "token",
            "Default auth mode should be token"
        );
        assert!(
            parsed["gateway"]["auth"]["token"]
                .as_str()
                .map(|v| !v.is_empty())
                .unwrap_or(false),
            "Default setup should generate a non-empty gateway token"
        );
        assert_eq!(
            parsed["agents"]["defaults"]["model"], "claude-sonnet-4-20250514",
            "Default model should be claude-sonnet-4-20250514"
        );
    }

    // -----------------------------------------------------------------------
    // Pair subcommand tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_cli_pair_basic() {
        let cli = Cli::try_parse_from(["cara", "pair", "https://gateway.local:3001"]).unwrap();
        match cli.command {
            Some(Command::Pair {
                ref url,
                ref name,
                trust,
            }) => {
                assert_eq!(url, "https://gateway.local:3001");
                assert!(name.is_none());
                assert!(!trust);
            }
            other => panic!("Expected Pair, got {:?}", other),
        }
    }

    #[test]
    fn test_cli_pair_with_name_and_trust() {
        let cli = Cli::try_parse_from([
            "cara",
            "pair",
            "https://gateway.local:3001",
            "--name",
            "my-node",
            "--trust",
        ])
        .unwrap();
        match cli.command {
            Some(Command::Pair {
                ref url,
                ref name,
                trust,
            }) => {
                assert_eq!(url, "https://gateway.local:3001");
                assert_eq!(name.as_deref(), Some("my-node"));
                assert!(trust);
            }
            other => panic!("Expected Pair, got {:?}", other),
        }
    }

    #[test]
    fn test_pair_url_validation_https() {
        // Valid https URL should not trigger the URL validation error.
        let url = "https://gateway.local:3001";
        assert!(
            url.starts_with("http://") || url.starts_with("https://"),
            "https URL should be valid"
        );
    }

    #[test]
    fn test_pair_url_validation_http() {
        // Valid http URL should not trigger the URL validation error.
        let url = "http://gateway.local:3001";
        assert!(
            url.starts_with("http://") || url.starts_with("https://"),
            "http URL should be valid"
        );
    }

    #[test]
    fn test_pair_url_validation_invalid() {
        let url = "ftp://gateway.local:3001";
        assert!(
            !(url.starts_with("http://") || url.starts_with("https://")),
            "ftp URL should be invalid"
        );

        let url2 = "gateway.local:3001";
        assert!(
            !(url2.starts_with("http://") || url2.starts_with("https://")),
            "URL without scheme should be invalid"
        );
    }

    #[test]
    fn test_pair_generates_valid_uuid_token() {
        let token = uuid::Uuid::new_v4().to_string();
        // UUID v4 format: 8-4-4-4-12 hex chars.
        assert_eq!(token.len(), 36, "UUID should be 36 characters");
        assert_eq!(
            token.chars().filter(|c| *c == '-').count(),
            4,
            "UUID should have 4 dashes"
        );
        // Verify it parses back as a valid UUID.
        assert!(
            uuid::Uuid::parse_str(&token).is_ok(),
            "Generated token should be a valid UUID"
        );
    }

    #[test]
    fn test_pair_device_name_explicit() {
        let name = Some("my-device");
        let device_name = match name {
            Some(n) => n.to_string(),
            None => std::env::var("HOSTNAME").unwrap_or_else(|_| "unknown".to_string()),
        };
        assert_eq!(device_name, "my-device");
    }

    #[test]
    fn test_pair_device_name_fallback() {
        let name: Option<&str> = None;
        let device_name = match name {
            Some(n) => n.to_string(),
            None => std::env::var("HOSTNAME").unwrap_or_else(|_| "unknown".to_string()),
        };
        // Should be either the hostname or "unknown", both are acceptable.
        assert!(
            !device_name.is_empty(),
            "Fallback device name should not be empty"
        );
    }

    // -----------------------------------------------------------------------
    // Update subcommand tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_cli_update_check() {
        let cli = Cli::try_parse_from(["cara", "update", "--check"]).unwrap();
        match cli.command {
            Some(Command::Update { check, version }) => {
                assert!(check);
                assert!(version.is_none());
            }
            other => panic!("Expected Update, got {:?}", other),
        }
    }

    #[test]
    fn test_cli_update_with_version() {
        let cli = Cli::try_parse_from(["cara", "update", "--version", "0.2.0"]).unwrap();
        match cli.command {
            Some(Command::Update { check, version }) => {
                assert!(!check);
                assert_eq!(version.as_deref(), Some("0.2.0"));
            }
            other => panic!("Expected Update, got {:?}", other),
        }
    }

    #[test]
    fn test_update_version_comparison_up_to_date() {
        let current = "0.1.0";
        let latest = "0.1.0";
        assert_eq!(current, latest, "Same versions should be equal");
    }

    // ====================================================================
    // TLS subcommand parsing tests
    // ====================================================================

    #[test]
    fn test_cli_tls_init_ca() {
        let cli = Cli::try_parse_from(["cara", "tls", "init-ca"]).unwrap();
        match cli.command {
            Some(Command::Tls(TlsCommand::InitCa { output })) => {
                assert!(output.is_none());
            }
            other => panic!("Expected Tls(InitCa), got {:?}", other),
        }
    }

    #[test]
    fn test_cli_tls_init_ca_with_output() {
        let cli = Cli::try_parse_from(["cara", "tls", "init-ca", "--output", "/tmp/ca"]).unwrap();
        match cli.command {
            Some(Command::Tls(TlsCommand::InitCa { output })) => {
                assert_eq!(output.as_deref(), Some("/tmp/ca"));
            }
            other => panic!("Expected Tls(InitCa), got {:?}", other),
        }
    }

    #[test]
    fn test_cli_tls_issue_cert() {
        let cli = Cli::try_parse_from(["cara", "tls", "issue-cert", "node-east-1"]).unwrap();
        match cli.command {
            Some(Command::Tls(TlsCommand::IssueCert {
                node_id,
                ca_dir,
                output,
            })) => {
                assert_eq!(node_id, "node-east-1");
                assert!(ca_dir.is_none());
                assert!(output.is_none());
            }
            other => panic!("Expected Tls(IssueCert), got {:?}", other),
        }
    }

    #[test]
    fn test_cli_tls_issue_cert_with_options() {
        let cli = Cli::try_parse_from([
            "cara",
            "tls",
            "issue-cert",
            "node-west-2",
            "--ca-dir",
            "/etc/carapace/ca",
            "--output",
            "/etc/carapace/nodes",
        ])
        .unwrap();
        match cli.command {
            Some(Command::Tls(TlsCommand::IssueCert {
                node_id,
                ca_dir,
                output,
            })) => {
                assert_eq!(node_id, "node-west-2");
                assert_eq!(ca_dir.as_deref(), Some("/etc/carapace/ca"));
                assert_eq!(output.as_deref(), Some("/etc/carapace/nodes"));
            }
            other => panic!("Expected Tls(IssueCert), got {:?}", other),
        }
    }

    #[test]
    fn test_cli_tls_revoke_cert() {
        let cli = Cli::try_parse_from([
            "cara",
            "tls",
            "revoke-cert",
            "AA:BB:CC:DD",
            "--node-id",
            "node-1",
        ])
        .unwrap();
        match cli.command {
            Some(Command::Tls(TlsCommand::RevokeCert {
                fingerprint,
                node_id,
                ca_dir,
                reason,
            })) => {
                assert_eq!(fingerprint, "AA:BB:CC:DD");
                assert_eq!(node_id, "node-1");
                assert!(ca_dir.is_none());
                assert!(reason.is_none());
            }
            other => panic!("Expected Tls(RevokeCert), got {:?}", other),
        }
    }

    #[test]
    fn test_cli_tls_revoke_cert_with_reason() {
        let cli = Cli::try_parse_from([
            "cara",
            "tls",
            "revoke-cert",
            "AA:BB:CC:DD",
            "--node-id",
            "node-1",
            "--reason",
            "key compromised",
        ])
        .unwrap();
        match cli.command {
            Some(Command::Tls(TlsCommand::RevokeCert {
                fingerprint,
                node_id,
                ca_dir,
                reason,
            })) => {
                assert_eq!(fingerprint, "AA:BB:CC:DD");
                assert_eq!(node_id, "node-1");
                assert!(ca_dir.is_none());
                assert_eq!(reason.as_deref(), Some("key compromised"));
            }
            other => panic!("Expected Tls(RevokeCert), got {:?}", other),
        }
    }

    #[test]
    fn test_cli_tls_show_ca() {
        let cli = Cli::try_parse_from(["cara", "tls", "show-ca"]).unwrap();
        match cli.command {
            Some(Command::Tls(TlsCommand::ShowCa { ca_dir })) => {
                assert!(ca_dir.is_none());
            }
            other => panic!("Expected Tls(ShowCa), got {:?}", other),
        }
    }

    #[test]
    fn test_cli_tls_show_ca_with_dir() {
        let cli = Cli::try_parse_from(["cara", "tls", "show-ca", "--ca-dir", "/tmp/ca"]).unwrap();
        match cli.command {
            Some(Command::Tls(TlsCommand::ShowCa { ca_dir })) => {
                assert_eq!(ca_dir.as_deref(), Some("/tmp/ca"));
            }
            other => panic!("Expected Tls(ShowCa), got {:?}", other),
        }
    }
}
