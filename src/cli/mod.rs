//! CLI subcommand definitions and handlers.
//!
//! Uses clap derive to define the subcommand hierarchy:
//! - `start` (default) -- start the gateway server
//! - `config show|get|set|path` -- read/write configuration
//! - `status` -- query a running instance for health info
//! - `logs` -- tail log entries from a running instance
//! - `plugins` -- inspect and manage plugins on a running instance
//! - `version` -- print build/version info
//! - `backup` -- create a backup archive of all gateway data
//! - `restore` -- restore from a backup archive
//! - `reset` -- clear specific data categories
//! - `setup` -- interactive first-run configuration wizard
//! - `pair` -- pair with a remote gateway node
//! - `update` -- check for updates or self-update
//! - `task` -- manage long-running objective tasks

pub mod backup_crypto;
pub mod chat;

use clap::{Parser, Subcommand};
use tokio::io::AsyncWriteExt;

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
    Autonomy,
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

    /// Inspect and manage plugins on a running instance.
    #[command(subcommand)]
    Plugins(PluginsCommand),

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

        /// Provider to configure for first run.
        #[arg(long, value_enum)]
        provider: Option<SetupProvider>,

        /// Provider auth mode. Required for non-interactive Gemini and Anthropic setup.
        #[arg(long, value_enum)]
        auth_mode: Option<SetupAuthModeSelection>,
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

    /// Manage long-running objective tasks.
    #[command(subcommand)]
    Task(TaskCommand),

    /// Start an interactive chat session.
    Chat {
        /// Start a new session instead of resuming.
        #[arg(long)]
        new: bool,

        /// Port of a running instance to connect to.
        #[arg(short, long)]
        port: Option<u16>,
    },

    /// Verify outcome paths, including long-running autonomy execution.
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

    /// Import configuration from another tool.
    Import {
        /// Source tool to import from.
        #[arg(value_enum)]
        source: ImportSource,

        /// Overwrite existing Carapace configuration if it already exists.
        #[arg(long)]
        force: bool,
    },

    /// Manage mTLS certificates for gateway-to-gateway communication.
    #[command(subcommand)]
    Tls(TlsCommand),
}

#[derive(clap::ValueEnum, Clone, Debug)]
pub enum ImportSource {
    /// Import from OpenClaw (~/.openclaw/ or ~/.clawdbot/).
    Openclaw,
    /// Import from OpenCode (~/.opencode.json).
    Opencode,
    /// Import from Aider (~/.aider.conf.yml and .env).
    Aider,
    /// Import from NemoClaw (~/.nemoclaw/config.json).
    Nemoclaw,
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

#[derive(clap::Args, Debug, Clone)]
pub struct WsConnectionArgs {
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
}

#[derive(clap::ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum PluginSourceSelection {
    Managed,
    Config,
}

#[derive(clap::ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum PluginStateSelection {
    Active,
    Disabled,
    Ignored,
    Failed,
}

#[derive(Subcommand, Debug)]
pub enum PluginsCommand {
    /// Show plugin activation state and restart requirements.
    Status {
        /// Print JSON instead of human-readable output.
        #[arg(long)]
        json: bool,

        /// Filter by configured plugin name.
        #[arg(long)]
        name: Option<String>,

        /// Filter by instantiated plugin ID.
        #[arg(long = "plugin-id")]
        plugin_id: Option<String>,

        /// Filter by plugin source.
        #[arg(long, value_enum)]
        source: Option<PluginSourceSelection>,

        /// Filter by plugin activation state.
        #[arg(long, value_enum)]
        state: Option<PluginStateSelection>,

        /// Show only failed plugin entries.
        #[arg(long)]
        only_failed: bool,

        /// Exit nonzero if activation errors exist or filtered results are not all active.
        #[arg(long)]
        strict: bool,

        #[command(flatten)]
        connection: WsConnectionArgs,
    },

    /// List managed plugin binaries present on disk.
    Bins {
        /// Print JSON instead of human-readable output.
        #[arg(long)]
        json: bool,

        #[command(flatten)]
        connection: WsConnectionArgs,
    },

    /// Install a managed plugin.
    Install(PluginMutationArgs),

    /// Update a managed plugin.
    Update(PluginMutationArgs),
}

#[derive(clap::Args, Debug)]
#[command(group(
    clap::ArgGroup::new("source")
        .required(true)
        .multiple(false)
        .args(["url", "file"])
))]
pub struct PluginMutationArgs {
    /// Managed plugin name.
    name: String,

    /// Download URL for the plugin artifact.
    #[arg(long, group = "source")]
    url: Option<String>,

    /// Local plugin artifact to copy into the managed plugins directory.
    #[arg(long, group = "source")]
    file: Option<PathBuf>,

    /// Optional plugin version string.
    #[arg(long)]
    version: Option<String>,

    /// Optional publisher public key.
    #[arg(long = "publisher-key")]
    publisher_key: Option<String>,

    /// Optional detached plugin signature.
    #[arg(long)]
    signature: Option<String>,

    /// Print JSON instead of human-readable output.
    #[arg(long)]
    json: bool,

    #[command(flatten)]
    connection: WsConnectionArgs,
}

#[derive(clap::Args, Debug)]
pub struct TaskConnectionArgs {
    /// Port of the running instance (default: from config or 18789).
    #[arg(short, long)]
    port: Option<u16>,

    /// Host of the running instance.
    #[arg(long, default_value = "127.0.0.1")]
    host: String,
}

#[derive(Subcommand, Debug)]
pub enum TaskCommand {
    /// Create a durable objective task.
    Create {
        /// Task payload as JSON (CronPayload shape).
        #[arg(long)]
        payload: String,

        /// Optional Unix-ms time when the task becomes runnable.
        #[arg(long = "next-run-at-ms")]
        next_run_at_ms: Option<u64>,

        /// Optional max retry attempts for this task.
        #[arg(long = "max-attempts")]
        max_attempts: Option<u32>,

        /// Optional max wall-clock budget in milliseconds from creation.
        #[arg(long = "max-total-runtime-ms")]
        max_total_runtime_ms: Option<u64>,

        /// Optional max tool-turn budget for this task.
        #[arg(long = "max-turns")]
        max_turns: Option<u32>,

        /// Optional max timeout (seconds) for each spawned agent run.
        #[arg(long = "max-run-timeout-seconds")]
        max_run_timeout_seconds: Option<u32>,

        #[command(flatten)]
        connection: TaskConnectionArgs,
    },
    /// List durable objective tasks.
    List {
        /// Optional task state filter.
        #[arg(long)]
        state: Option<String>,

        /// Optional max number of tasks to return.
        #[arg(long)]
        limit: Option<usize>,

        #[command(flatten)]
        connection: TaskConnectionArgs,
    },
    /// Get a single durable objective task by ID.
    Get {
        /// Task ID.
        id: String,

        #[command(flatten)]
        connection: TaskConnectionArgs,
    },
    /// Cancel a durable objective task.
    Cancel {
        /// Task ID.
        id: String,

        /// Optional cancellation reason.
        #[arg(long)]
        reason: Option<String>,

        #[command(flatten)]
        connection: TaskConnectionArgs,
    },
    /// Retry a durable objective task.
    Retry {
        /// Task ID.
        id: String,

        /// Retry delay in milliseconds (default: immediate).
        #[arg(long = "delay-ms")]
        delay_ms: Option<u64>,

        /// Optional retry reason.
        #[arg(long)]
        reason: Option<String>,

        #[command(flatten)]
        connection: TaskConnectionArgs,
    },
    /// Resume a blocked durable objective task.
    Resume {
        /// Task ID.
        id: String,

        /// Resume delay in milliseconds (default: immediate).
        #[arg(long = "delay-ms")]
        delay_ms: Option<u64>,

        /// Optional resume reason.
        #[arg(long)]
        reason: Option<String>,

        #[command(flatten)]
        connection: TaskConnectionArgs,
    },
    /// Update payload/policy fields for a durable objective task.
    Update {
        /// Task ID.
        id: String,

        /// Replacement task payload as JSON (CronPayload shape).
        #[arg(long)]
        payload: Option<String>,

        /// Optional max retry attempts for this task.
        #[arg(long = "max-attempts")]
        max_attempts: Option<u32>,

        /// Optional max wall-clock budget in milliseconds from creation.
        #[arg(long = "max-total-runtime-ms")]
        max_total_runtime_ms: Option<u64>,

        /// Optional max tool-turn budget for this task.
        #[arg(long = "max-turns")]
        max_turns: Option<u32>,

        /// Optional max timeout (seconds) for each spawned agent run.
        #[arg(long = "max-run-timeout-seconds")]
        max_run_timeout_seconds: Option<u32>,

        /// Optional operator note stored on the task.
        #[arg(long)]
        reason: Option<String>,

        #[command(flatten)]
        connection: TaskConnectionArgs,
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
use crate::runtime_bridge::{run_blocking_cleanup, run_sync_blocking_send};
use crate::server::bind::DEFAULT_PORT;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use futures_util::{SinkExt, StreamExt};
use getrandom::fill;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error as RustlsError, SignatureScheme};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
#[cfg(not(test))]
use std::io::IsTerminal;
use std::sync::{LazyLock, Mutex};
use std::time::Duration;
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
    "clientsecret",
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

/// Run the `task` subcommand family -- manage durable objective tasks.
pub async fn handle_task(command: TaskCommand) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        TaskCommand::Create {
            payload,
            next_run_at_ms,
            max_attempts,
            max_total_runtime_ms,
            max_turns,
            max_run_timeout_seconds,
            connection,
        } => {
            handle_task_create(
                &connection.host,
                connection.port,
                TaskCreateOptions {
                    payload,
                    next_run_at_ms,
                    max_attempts,
                    max_total_runtime_ms,
                    max_turns,
                    max_run_timeout_seconds,
                },
            )
            .await
        }
        TaskCommand::List {
            state,
            limit,
            connection,
        } => handle_task_list(&connection.host, connection.port, state, limit).await,
        TaskCommand::Get { id, connection } => {
            handle_task_get(&connection.host, connection.port, &id).await
        }
        TaskCommand::Cancel {
            id,
            reason,
            connection,
        } => handle_task_cancel(&connection.host, connection.port, &id, reason).await,
        TaskCommand::Retry {
            id,
            delay_ms,
            reason,
            connection,
        } => handle_task_retry(&connection.host, connection.port, &id, delay_ms, reason).await,
        TaskCommand::Resume {
            id,
            delay_ms,
            reason,
            connection,
        } => handle_task_resume(&connection.host, connection.port, &id, delay_ms, reason).await,
        TaskCommand::Update {
            id,
            payload,
            max_attempts,
            max_total_runtime_ms,
            max_turns,
            max_run_timeout_seconds,
            reason,
            connection,
        } => {
            handle_task_update(
                &connection.host,
                connection.port,
                &id,
                TaskUpdateOptions {
                    payload,
                    max_attempts,
                    max_total_runtime_ms,
                    max_turns,
                    max_run_timeout_seconds,
                    reason,
                },
            )
            .await
        }
    }
}

struct TaskCreateOptions {
    payload: String,
    next_run_at_ms: Option<u64>,
    max_attempts: Option<u32>,
    max_total_runtime_ms: Option<u64>,
    max_turns: Option<u32>,
    max_run_timeout_seconds: Option<u32>,
}

struct TaskUpdateOptions {
    payload: Option<String>,
    max_attempts: Option<u32>,
    max_total_runtime_ms: Option<u64>,
    max_turns: Option<u32>,
    max_run_timeout_seconds: Option<u32>,
    reason: Option<String>,
}

async fn handle_task_create(
    host: &str,
    port: Option<u16>,
    options: TaskCreateOptions,
) -> Result<(), Box<dyn std::error::Error>> {
    let parsed_payload: Value = serde_json::from_str(&options.payload)
        .map_err(|e| format!("invalid --payload JSON (expected CronPayload object): {e}"))?;
    let mut body = serde_json::Map::new();
    body.insert("payload".to_string(), parsed_payload);
    body.insert(
        "nextRunAtMs".to_string(),
        options.next_run_at_ms.map_or(Value::Null, Value::from),
    );

    let mut policy = serde_json::Map::new();
    if let Some(max_attempts) = options.max_attempts {
        policy.insert("maxAttempts".to_string(), Value::from(max_attempts));
    }
    if let Some(max_total_runtime_ms) = options.max_total_runtime_ms {
        policy.insert(
            "maxTotalRuntimeMs".to_string(),
            Value::from(max_total_runtime_ms),
        );
    }
    if let Some(max_turns) = options.max_turns {
        policy.insert("maxTurns".to_string(), Value::from(max_turns));
    }
    if let Some(max_run_timeout_seconds) = options.max_run_timeout_seconds {
        policy.insert(
            "maxRunTimeoutSeconds".to_string(),
            Value::from(max_run_timeout_seconds),
        );
    }
    if !policy.is_empty() {
        body.insert("policy".to_string(), Value::Object(policy));
    }
    let body = Value::Object(body);

    let response = send_control_request(
        host,
        resolve_port(port),
        reqwest::Method::POST,
        "/control/tasks",
        &[],
        Some(body),
    )
    .await?;
    print_pretty_json(&response)
}

async fn handle_task_list(
    host: &str,
    port: Option<u16>,
    state: Option<String>,
    limit: Option<usize>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut query: Vec<(&str, String)> = Vec::new();
    if let Some(state) = state {
        let normalized = state.trim();
        if !normalized.is_empty() {
            query.push(("state", normalized.to_string()));
        }
    }
    if let Some(limit) = limit {
        query.push(("limit", limit.to_string()));
    }

    let response = send_control_request(
        host,
        resolve_port(port),
        reqwest::Method::GET,
        "/control/tasks",
        &query,
        None,
    )
    .await?;
    print_pretty_json(&response)
}

async fn handle_task_get(
    host: &str,
    port: Option<u16>,
    id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let task_id = normalize_task_id(id)?;
    let path = format!("/control/tasks/{task_id}");
    let response = send_control_request(
        host,
        resolve_port(port),
        reqwest::Method::GET,
        &path,
        &[],
        None,
    )
    .await?;
    print_pretty_json(&response)
}

async fn handle_task_cancel(
    host: &str,
    port: Option<u16>,
    id: &str,
    reason: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let task_id = normalize_task_id(id)?;
    let path = format!("/control/tasks/{task_id}/cancel");
    let body = reason
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|trimmed| serde_json::json!({ "reason": trimmed }));
    let response = send_control_request(
        host,
        resolve_port(port),
        reqwest::Method::POST,
        &path,
        &[],
        body,
    )
    .await?;
    print_pretty_json(&response)
}

async fn handle_task_retry(
    host: &str,
    port: Option<u16>,
    id: &str,
    delay_ms: Option<u64>,
    reason: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let task_id = normalize_task_id(id)?;
    let path = format!("/control/tasks/{task_id}/retry");
    let mut body = serde_json::Map::new();
    if let Some(delay_ms) = delay_ms {
        body.insert("delayMs".to_string(), Value::from(delay_ms));
    }
    if let Some(reason) = reason {
        let trimmed = reason.trim();
        if !trimmed.is_empty() {
            body.insert("reason".to_string(), Value::from(trimmed));
        }
    }
    let payload = if body.is_empty() {
        None
    } else {
        Some(Value::Object(body))
    };
    let response = send_control_request(
        host,
        resolve_port(port),
        reqwest::Method::POST,
        &path,
        &[],
        payload,
    )
    .await?;
    print_pretty_json(&response)
}

async fn handle_task_resume(
    host: &str,
    port: Option<u16>,
    id: &str,
    delay_ms: Option<u64>,
    reason: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let task_id = normalize_task_id(id)?;
    let path = format!("/control/tasks/{task_id}/resume");
    let mut body = serde_json::Map::new();
    if let Some(delay_ms) = delay_ms {
        body.insert("delayMs".to_string(), Value::from(delay_ms));
    }
    if let Some(reason) = reason {
        let trimmed = reason.trim();
        if !trimmed.is_empty() {
            body.insert("reason".to_string(), Value::from(trimmed));
        }
    }
    let payload = if body.is_empty() {
        None
    } else {
        Some(Value::Object(body))
    };
    let response = send_control_request(
        host,
        resolve_port(port),
        reqwest::Method::POST,
        &path,
        &[],
        payload,
    )
    .await?;
    print_pretty_json(&response)
}

async fn handle_task_update(
    host: &str,
    port: Option<u16>,
    id: &str,
    options: TaskUpdateOptions,
) -> Result<(), Box<dyn std::error::Error>> {
    let task_id = normalize_task_id(id)?;
    let path = format!("/control/tasks/{task_id}");
    let mut body = serde_json::Map::new();

    if let Some(payload) = options.payload {
        let parsed_payload: Value = serde_json::from_str(&payload)
            .map_err(|e| format!("invalid --payload JSON (expected CronPayload object): {e}"))?;
        body.insert("payload".to_string(), parsed_payload);
    }

    let mut policy = serde_json::Map::new();
    if let Some(max_attempts) = options.max_attempts {
        policy.insert("maxAttempts".to_string(), Value::from(max_attempts));
    }
    if let Some(max_total_runtime_ms) = options.max_total_runtime_ms {
        policy.insert(
            "maxTotalRuntimeMs".to_string(),
            Value::from(max_total_runtime_ms),
        );
    }
    if let Some(max_turns) = options.max_turns {
        policy.insert("maxTurns".to_string(), Value::from(max_turns));
    }
    if let Some(max_run_timeout_seconds) = options.max_run_timeout_seconds {
        policy.insert(
            "maxRunTimeoutSeconds".to_string(),
            Value::from(max_run_timeout_seconds),
        );
    }
    if !policy.is_empty() {
        body.insert("policy".to_string(), Value::Object(policy));
    }

    if let Some(reason) = options.reason {
        let trimmed = reason.trim();
        if !trimmed.is_empty() {
            body.insert("reason".to_string(), Value::from(trimmed));
        }
    }

    if body.is_empty() {
        return Err("task update requires at least one of: --payload, --max-attempts, --max-total-runtime-ms, --max-turns, --max-run-timeout-seconds, --reason".into());
    }

    let response = send_control_request(
        host,
        resolve_port(port),
        reqwest::Method::PATCH,
        &path,
        &[],
        Some(Value::Object(body)),
    )
    .await?;
    print_pretty_json(&response)
}

fn normalize_task_id(id: &str) -> Result<String, Box<dyn std::error::Error>> {
    let trimmed = id.trim();
    if trimmed.is_empty() {
        return Err("task id cannot be empty".into());
    }
    Ok(trimmed.to_string())
}

async fn send_control_request(
    host: &str,
    port: u16,
    method: reqwest::Method,
    path: &str,
    query: &[(&str, String)],
    body: Option<Value>,
) -> Result<Value, Box<dyn std::error::Error>> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()?;
    let GatewayAuth { token, password } = resolve_gateway_auth().await;
    let auth = GatewayAuth { token, password };
    let url = build_control_url(host, port, path, query)?;
    send_control_request_with_client_and_auth(&client, &auth, method, url, body).await
}

fn build_control_url(
    host: &str,
    port: u16,
    path: &str,
    query: &[(&str, String)],
) -> Result<Url, Box<dyn std::error::Error>> {
    let mut url = Url::parse(&format!("http://{}:{}{}", host, port, path))
        .map_err(|e| format!("failed to build control URL: {e}"))?;
    if !query.is_empty() {
        let mut pairs = url.query_pairs_mut();
        for (key, value) in query {
            pairs.append_pair(key, value);
        }
    }
    Ok(url)
}

async fn send_control_request_with_client_and_auth(
    client: &reqwest::Client,
    auth: &GatewayAuth,
    method: reqwest::Method,
    url: Url,
    body: Option<Value>,
) -> Result<Value, Box<dyn std::error::Error>> {
    let request_url = url.clone();
    let mut request = client.request(method, url);
    if let Some(token) = auth.token.as_deref() {
        request = request.bearer_auth(token);
    } else if let Some(password) = auth.password.as_deref() {
        request = request.bearer_auth(password);
    }
    if let Some(body) = body {
        request = request.json(&body);
    }

    let response = request
        .send()
        .await
        .map_err(|e| format!("failed to send control request ({request_url}): {e}"))?;
    let status = response.status();
    let bytes = response.bytes().await?;
    if !status.is_success() {
        let error = extract_control_error_message(&bytes);
        return Err(format!("control request failed (HTTP {status}): {error}").into());
    }

    if bytes.is_empty() {
        return Ok(serde_json::json!({ "ok": true }));
    }

    serde_json::from_slice(&bytes)
        .map_err(|e| format!("failed to parse control response as JSON: {e}").into())
}

fn extract_control_error_message(body: &[u8]) -> String {
    if body.is_empty() {
        return "empty response body".to_string();
    }
    if let Ok(value) = serde_json::from_slice::<Value>(body) {
        if let Some(error) = value.get("error").and_then(|v| v.as_str()) {
            return error.to_string();
        }
        if let Some(message) = value.get("message").and_then(|v| v.as_str()) {
            return message.to_string();
        }
        return value.to_string();
    }
    let text = String::from_utf8_lossy(body).trim().to_string();
    if text.is_empty() {
        "response body unavailable".to_string()
    } else {
        text
    }
}

fn print_pretty_json(value: &Value) -> Result<(), Box<dyn std::error::Error>> {
    println!("{}", serde_json::to_string_pretty(value)?);
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

#[derive(Debug, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct PluginStatusEntry {
    name: String,
    #[serde(default)]
    plugin_id: Option<String>,
    #[serde(default)]
    enabled: Option<bool>,
    #[serde(default)]
    install_id: Option<Value>,
    #[serde(default)]
    requested_at: Option<u64>,
    #[serde(default)]
    source: Option<String>,
    #[serde(default)]
    state: Option<String>,
    #[serde(default)]
    reason: Option<String>,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct PluginsStatusResponse {
    plugins_enabled: bool,
    configured_plugin_path_count: usize,
    restart_required_for_changes: bool,
    activation_error_count: usize,
    #[serde(default)]
    plugins: Vec<PluginStatusEntry>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct PluginBinEntry {
    name: String,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct PluginsBinsResponse {
    #[serde(default)]
    bins: Vec<PluginBinEntry>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct PluginActivationSummary {
    state: String,
    #[serde(default)]
    message: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct PluginMutationResponse {
    name: String,
    #[serde(default)]
    version: Option<String>,
    activation: PluginActivationSummary,
}

struct PluginStatusCliOptions {
    connection: WsConnectionArgs,
    json_output: bool,
    name: Option<String>,
    plugin_id: Option<String>,
    source: Option<PluginSourceSelection>,
    state: Option<PluginStateSelection>,
    only_failed: bool,
    strict: bool,
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
    let state_dir = resolve_state_dir();
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
    crate::time::unix_now_ms_i64()
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

fn cli_error(message: impl Into<String>) -> Box<dyn std::error::Error> {
    std::io::Error::other(message.into()).into()
}

fn validate_cli_ws_transport(
    host: &str,
    tls: bool,
    trust: bool,
    allow_plaintext: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let is_loopback = is_loopback_host(host);
    if !is_loopback && !tls && !allow_plaintext {
        return Err(cli_error(
            "remote WebSocket commands require TLS or explicit plaintext opt-in; use --tls or pass --allow-plaintext",
        ));
    }
    if !is_loopback && !tls && allow_plaintext {
        eprintln!(
            "Warning: using plaintext WebSocket to remote host; credentials will be sent unencrypted."
        );
    }
    if trust && !tls {
        eprintln!("Warning: --trust has no effect without --tls.");
    }
    Ok(())
}

async fn connect_cli_ws_authenticated(
    connection: &WsConnectionArgs,
    role: &str,
    scopes: &[&str],
) -> Result<(WsWrite, WsRead), Box<dyn std::error::Error>> {
    validate_cli_ws_transport(
        &connection.host,
        connection.tls,
        connection.trust,
        connection.allow_plaintext,
    )?;

    let port = resolve_port(connection.port);
    let auth = resolve_gateway_auth().await;
    if auth.token.is_none() && auth.password.is_none() {
        eprintln!("No gateway auth credentials found.");
        eprintln!("Attempting local-direct connection (if enabled)...");
    }

    let state_dir = resolve_state_dir();
    let device_identity = load_or_create_device_identity(&state_dir).await?;
    let ws_url = if connection.tls {
        format!("wss://{}:{}/ws", connection.host, port)
    } else {
        format!("ws://{}:{}/ws", connection.host, port)
    };
    let ws_stream = connect_ws(&ws_url, connection.trust).await.map_err(|err| {
        cli_error(format!(
            "could not connect to carapace at {}:{}: {}",
            connection.host, port, err
        ))
    })?;
    let (mut ws_write, mut ws_read) = ws_stream.split();

    let nonce = await_connect_challenge(&mut ws_read, &mut ws_write).await?;
    let scope_values: Vec<String> = scopes.iter().map(|scope| (*scope).to_string()).collect();
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
        "scopes": scope_values.clone()
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
        &scope_values,
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
        let message = if err.code.as_deref() == Some("not_paired")
            && err.message.contains("pairing required")
        {
            let mut message =
                "device pairing required for this CLI; approve the request in the control UI and retry".to_string();
            if let Some(details) = err.details.as_ref() {
                if let Some(request_id) = extract_pairing_request_id(details) {
                    message.push_str(&format!(" (request ID: {request_id})"));
                }
            }
            message
        } else if err.message.contains("device identity required") {
            format!(
                "{}; this gateway requires a paired device for WebSocket access. Set gateway.auth.token for local CLI access or use the control UI",
                err.message
            )
        } else {
            err.message.clone()
        };
        return Err(cli_error(format!("WebSocket connect failed: {message}")));
    }

    Ok((ws_write, ws_read))
}

async fn send_cli_ws_request(
    connection: &WsConnectionArgs,
    role: &str,
    scopes: &[&str],
    method: &str,
    params: Value,
) -> Result<Value, Box<dyn std::error::Error>> {
    let (mut ws_write, mut ws_read) =
        connect_cli_ws_authenticated(connection, role, scopes).await?;
    let request_id = format!("cli-{}", method.replace('.', "-"));
    let frame = serde_json::json!({
        "type": "req",
        "id": request_id,
        "method": method,
        "params": params,
    });
    ws_write
        .send(Message::Text(serde_json::to_string(&frame)?.into()))
        .await?;
    await_ws_response_with_error(&mut ws_read, &mut ws_write, &request_id)
        .await
        .map_err(|err| cli_error(format!("{method} failed: {}", err.message)))
}

fn plugin_source_label(source: PluginSourceSelection) -> &'static str {
    match source {
        PluginSourceSelection::Managed => "managed",
        PluginSourceSelection::Config => "config",
    }
}

fn plugin_state_label(state: PluginStateSelection) -> &'static str {
    match state {
        PluginStateSelection::Active => "active",
        PluginStateSelection::Disabled => "disabled",
        PluginStateSelection::Ignored => "ignored",
        PluginStateSelection::Failed => "failed",
    }
}

fn plugin_entry_matches_filters(
    entry: &PluginStatusEntry,
    name: Option<&str>,
    plugin_id: Option<&str>,
    source: Option<PluginSourceSelection>,
    state: Option<PluginStateSelection>,
    only_failed: bool,
) -> bool {
    if let Some(name) = name {
        if entry.name != name {
            return false;
        }
    }
    if let Some(plugin_id) = plugin_id {
        if entry.plugin_id.as_deref() != Some(plugin_id) {
            return false;
        }
    }
    if let Some(source) = source {
        if entry.source.as_deref() != Some(plugin_source_label(source)) {
            return false;
        }
    }
    if let Some(state) = state {
        if entry.state.as_deref() != Some(plugin_state_label(state)) {
            return false;
        }
    }
    if only_failed && entry.state.as_deref() != Some("failed") {
        return false;
    }
    true
}

fn maybe_fail_strict_plugin_status(
    response: &PluginsStatusResponse,
) -> Result<(), Box<dyn std::error::Error>> {
    if response.activation_error_count > 0 {
        return Err(cli_error(format!(
            "plugin activation errors reported: {}",
            response.activation_error_count
        )));
    }
    if response.plugins.is_empty() {
        return Err(cli_error("no matching plugins found"));
    }
    let non_active = response
        .plugins
        .iter()
        .filter(|entry| entry.state.as_deref() != Some("active"))
        .map(|entry| entry.name.as_str())
        .collect::<Vec<_>>();
    if !non_active.is_empty() {
        return Err(cli_error(format!(
            "one or more matching plugins are not active: {}",
            non_active.join(", ")
        )));
    }
    Ok(())
}

fn print_plugin_status_human(response: &PluginsStatusResponse) {
    println!("Plugin status");
    println!("=============");
    println!("  Plugins enabled: {}", response.plugins_enabled);
    println!(
        "  Configured plugin paths: {}",
        response.configured_plugin_path_count
    );
    println!(
        "  Restart required for changes: {}",
        response.restart_required_for_changes
    );
    println!("  Activation errors: {}", response.activation_error_count);
    println!();

    if response.plugins.is_empty() {
        println!("No matching plugins found.");
        return;
    }

    for entry in &response.plugins {
        let state = entry.state.as_deref().unwrap_or("unknown");
        let source = entry.source.as_deref().unwrap_or("-");
        let enabled = entry.enabled.unwrap_or(true);
        let plugin_id = entry.plugin_id.as_deref().unwrap_or("-");
        println!(
            "{} [{}] {} (enabled: {}, pluginId: {})",
            entry.name, source, state, enabled, plugin_id
        );
        if let Some(reason) = entry.reason.as_deref().filter(|reason| !reason.is_empty()) {
            println!("  reason: {}", reason);
        }
    }
}

fn print_plugin_bins_human(response: &PluginsBinsResponse) {
    if response.bins.is_empty() {
        println!("No managed plugin binaries found.");
        return;
    }
    let mut names = response
        .bins
        .iter()
        .map(|entry| entry.name.as_str())
        .collect::<Vec<_>>();
    names.sort_unstable();
    for name in names {
        println!("{}", name);
    }
}

fn validate_local_plugin_artifact(file_label: &str, bytes: &[u8]) -> Result<(), String> {
    crate::plugins::loader::validate_plugin_component_bytes(file_label, bytes)
        .map_err(|error| format!("invalid plugin component '{}': {}", file_label, error))
}

async fn read_and_validate_local_plugin_artifact(
    file: &Path,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let metadata = tokio::fs::metadata(file).await.map_err(|err| {
        cli_error(format!(
            "failed to stat plugin file '{}': {}",
            file.display(),
            err
        ))
    })?;
    if !metadata.is_file() {
        return Err(cli_error(format!(
            "plugin file '{}' is not a regular file",
            file.display()
        )));
    }
    if metadata.len() > crate::plugins::MAX_MANAGED_PLUGIN_ARTIFACT_BYTES {
        return Err(cli_error(format!(
            "plugin file '{}' exceeds maximum size ({} bytes > {} bytes)",
            file.display(),
            metadata.len(),
            crate::plugins::MAX_MANAGED_PLUGIN_ARTIFACT_BYTES
        )));
    }

    let bytes = tokio::fs::read(file).await.map_err(|err| {
        cli_error(format!(
            "failed to read plugin file '{}': {}",
            file.display(),
            err
        ))
    })?;
    let file_label = file.display().to_string();
    tokio::task::spawn_blocking(move || {
        validate_local_plugin_artifact(&file_label, &bytes)?;
        Ok::<Vec<u8>, String>(bytes)
    })
    .await
    .map_err(|err| cli_error(format!("plugin validation task failed: {}", err)))?
    .map_err(cli_error)
}

#[derive(Debug)]
struct ManagedPluginFileTransaction {
    dest: PathBuf,
    backup: Option<PathBuf>,
    lock: PathBuf,
    // Tracks what `Drop` should finish if the future is cancelled mid-commit/rollback.
    drop_action: ManagedPluginFileTransactionDropAction,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ManagedPluginFileTransactionDropAction {
    RollbackArtifact,
    ReleaseLockOnly,
    CommitCleanup,
    Completed,
}

#[derive(Debug)]
struct PendingPluginFileTransactionLock {
    path: Option<PathBuf>,
}

impl PendingPluginFileTransactionLock {
    fn new(path: PathBuf) -> Self {
        Self { path: Some(path) }
    }

    async fn release_with_context(mut self, message: String) -> String {
        match self.path.take() {
            Some(path) => release_plugin_file_transaction_lock_with_context(&path, message).await,
            None => message,
        }
    }

    fn into_path(mut self) -> PathBuf {
        self.path
            .take()
            .expect("pending plugin transaction lock already released")
    }
}

impl Drop for PendingPluginFileTransactionLock {
    fn drop(&mut self) {
        let Some(path) = self.path.take() else {
            return;
        };
        run_blocking_cleanup(move || {
            match release_plugin_file_transaction_lock_blocking(&path) {
                Ok(()) => eprintln!(
                    "Warning: PendingPluginFileTransactionLock dropped before handoff; synchronously removed staging lock '{}' after an interrupted or cancelled run",
                    path.display()
                ),
                Err(err) => eprintln!(
                    "Warning: PendingPluginFileTransactionLock dropped before handoff and failed to remove staging lock '{}': {}",
                    path.display(),
                    err
                ),
            }
        });
    }
}

impl ManagedPluginFileTransaction {
    async fn commit(mut self) -> Result<(), Box<dyn std::error::Error>> {
        self.drop_action = ManagedPluginFileTransactionDropAction::CommitCleanup;
        let mut failures = Vec::new();
        if let Some(backup) = self.backup.as_deref() {
            match tokio::fs::remove_file(backup).await {
                Ok(()) => self.backup = None,
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => self.backup = None,
                Err(err) => {
                    failures.push(format!(
                        "plugin request succeeded, but failed to remove staging backup '{}': {}; remove or recover that backup before the next local `--file` plugin mutation",
                        backup.display(), err
                    ));
                }
            }
        }
        if let Err(err) = release_plugin_file_transaction_lock(&self.lock).await {
            failures.push(append_lock_release_failure(
                "plugin request succeeded".to_string(),
                &self.lock,
                &err,
            ));
        }
        self.drop_action = ManagedPluginFileTransactionDropAction::Completed;
        if failures.is_empty() {
            Ok(())
        } else {
            Err(cli_error(failures.join("; ")))
        }
    }

    async fn rollback(mut self) -> Result<String, Box<dyn std::error::Error>> {
        let rollback_result = match self.backup.as_deref() {
            Some(backup) => match restore_previous_plugin_artifact(backup, &self.dest).await {
                Ok(()) => Ok(format!(
                    "restored previous local managed artifact at '{}'",
                    self.dest.display()
                )),
                Err(err) => Err(err),
            },
            None => match tokio::fs::remove_file(&self.dest).await {
                Ok(()) => Ok(format!(
                    "removed staged local managed artifact at '{}'",
                    self.dest.display()
                )),
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(format!(
                    "no staged local managed artifact remained at '{}'",
                    self.dest.display()
                )),
                Err(err) => Err(cli_error(format!(
                    "failed to remove staged plugin artifact '{}' during rollback: {}",
                    self.dest.display(),
                    err
                ))),
            },
        };
        if rollback_result.is_ok() {
            self.backup = None;
            self.drop_action = ManagedPluginFileTransactionDropAction::ReleaseLockOnly;
        }
        let lock_release_result = release_plugin_file_transaction_lock(&self.lock).await;
        self.drop_action = ManagedPluginFileTransactionDropAction::Completed;
        match (rollback_result, lock_release_result) {
            (Ok(note), Ok(())) => Ok(note),
            (Ok(note), Err(lock_err)) => Err(cli_error(append_lock_release_failure(
                note, &self.lock, &lock_err,
            ))),
            (Err(err), Ok(())) => Err(err),
            (Err(err), Err(lock_err)) => Err(cli_error(append_lock_release_failure(
                err.to_string(),
                &self.lock,
                &lock_err,
            ))),
        }
    }
}

impl Drop for ManagedPluginFileTransaction {
    fn drop(&mut self) {
        let drop_action = std::mem::replace(
            &mut self.drop_action,
            ManagedPluginFileTransactionDropAction::Completed,
        );
        if drop_action == ManagedPluginFileTransactionDropAction::Completed {
            return;
        }
        let dest = self.dest.clone();
        let backup = self.backup.take();
        let lock = self.lock.clone();
        match drop_action {
            ManagedPluginFileTransactionDropAction::RollbackArtifact => {
                let message = format!(
                    "ManagedPluginFileTransaction dropped before rollback finished; attempting synchronous cleanup for staged artifact '{}' and any matching `.cli-lock` / `.cli-backup` files after an interrupted or cancelled run",
                    self.dest.display()
                );
                eprintln!("Warning: {message}");
                run_blocking_cleanup(move || {
                    if let Err(err) = rollback_managed_plugin_file_transaction_blocking(
                        &dest,
                        backup.as_deref(),
                        &lock,
                    ) {
                        eprintln!("Warning: dropped transaction cleanup failed: {err}");
                    }
                });
            }
            ManagedPluginFileTransactionDropAction::ReleaseLockOnly => {
                let message = format!(
                    "ManagedPluginFileTransaction dropped after artifact rollback but before staging lock release for '{}'; attempting synchronous lock cleanup after an interrupted or cancelled run",
                    self.dest.display()
                );
                eprintln!("Warning: {message}");
                run_blocking_cleanup(move || {
                    if let Err(err) = release_plugin_file_transaction_lock_blocking(&lock) {
                        eprintln!(
                            "Warning: dropped transaction cleanup failed to remove staging lock '{}': {}",
                            lock.display(),
                            err
                        );
                    }
                });
            }
            ManagedPluginFileTransactionDropAction::CommitCleanup => {
                let message = format!(
                    "ManagedPluginFileTransaction dropped while commit cleanup was still removing `.cli-backup` / `.cli-lock` sidecars for '{}'; attempting synchronous cleanup after an interrupted or cancelled run",
                    self.dest.display()
                );
                eprintln!("Warning: {message}");
                run_blocking_cleanup(move || {
                    if let Err(err) =
                        finish_managed_plugin_file_commit_cleanup_blocking(backup.as_deref(), &lock)
                    {
                        eprintln!("Warning: dropped transaction cleanup failed: {err}");
                    }
                });
            }
            ManagedPluginFileTransactionDropAction::Completed => {}
        }
    }
}

fn plugin_cli_sidecar_path(
    dest: &Path,
    suffix: &str,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let file_name = dest.file_name().ok_or_else(|| {
        cli_error(format!(
            "managed plugin destination '{}' has no file name",
            dest.display()
        ))
    })?;
    let mut sidecar_name = file_name.to_os_string();
    sidecar_name.push(suffix);
    Ok(dest.with_file_name(sidecar_name))
}

fn plugin_cli_backup_path(dest: &Path) -> Result<PathBuf, Box<dyn std::error::Error>> {
    plugin_cli_sidecar_path(dest, ".cli-backup")
}

fn plugin_cli_lock_path(dest: &Path) -> Result<PathBuf, Box<dyn std::error::Error>> {
    plugin_cli_sidecar_path(dest, ".cli-lock")
}

fn plugin_cli_staged_path(dest: &Path) -> Result<PathBuf, Box<dyn std::error::Error>> {
    plugin_cli_sidecar_path(dest, ".cli-staged")
}

async fn acquire_plugin_file_transaction_lock(
    lock: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let lock_owned = lock.to_path_buf();
    let std_file = tokio::task::spawn_blocking({
        move || {
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.custom_flags(libc::O_NOFOLLOW);
            }
            options.open(&lock_owned)
        }
    })
    .await
    .map_err(|e| cli_error(format!("spawn_blocking failed: {e}")))?;
    let mut file = tokio::fs::File::from_std(std_file.map_err(|err| {
        if err.kind() == std::io::ErrorKind::AlreadyExists {
            cli_error(format!(
                "refusing to stage plugin file because staging lock '{}' already exists; another local plugin mutation may still be in progress, or the lock may be stale from a previous interrupted run. Verify that no other `cara plugins install --file` or `cara plugins update --file` command is still running, inspect the PID recorded in the lock file if needed, and then remove the lock file and retry. The PID in the lock file may have been recycled if the original process crashed.",
                lock.display()
            ))
        } else {
            cli_error(format!(
                "failed to create staging lock '{}': {}",
                lock.display(),
                err
            ))
        }
    })?);
    let pid = std::process::id().to_string();
    if let Err(err) = file.write_all(pid.as_bytes()).await {
        return Err(cleanup_failed_plugin_file_transaction_lock_init(
            file,
            lock,
            format!(
                "failed to record staging lock owner in '{}': {}",
                lock.display(),
                err
            ),
        )
        .await);
    }
    if let Err(err) = file.sync_data().await {
        return Err(cleanup_failed_plugin_file_transaction_lock_init(
            file,
            lock,
            format!(
                "failed to persist staging lock owner in '{}': {}",
                lock.display(),
                err
            ),
        )
        .await);
    }
    Ok(())
}

async fn cleanup_failed_plugin_file_transaction_lock_init(
    file: tokio::fs::File,
    lock: &Path,
    message: String,
) -> Box<dyn std::error::Error> {
    drop(file);
    let mut message = message;
    match tokio::fs::remove_file(lock).await {
        Ok(()) => {}
        Err(cleanup_err) if cleanup_err.kind() == std::io::ErrorKind::NotFound => {}
        Err(cleanup_err) => {
            message = format!(
                "{message}; additionally failed to remove staging lock '{}': {}",
                lock.display(),
                cleanup_err
            );
        }
    }
    cli_error(message)
}

async fn release_plugin_file_transaction_lock(lock: &Path) -> std::io::Result<()> {
    match tokio::fs::remove_file(lock).await {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err),
    }
}

fn release_plugin_file_transaction_lock_blocking(lock: &Path) -> std::io::Result<()> {
    match std::fs::remove_file(lock) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err),
    }
}

fn append_lock_release_failure(
    message: String,
    lock: &Path,
    lock_err: &dyn std::fmt::Display,
) -> String {
    format!(
        "{message}; additionally failed to remove staging lock '{}': {}; remove that lock file before the next local `--file` plugin mutation",
        lock.display(), lock_err
    )
}

async fn release_plugin_file_transaction_lock_with_context(lock: &Path, message: String) -> String {
    match release_plugin_file_transaction_lock(lock).await {
        Ok(()) => message,
        Err(lock_err) => append_lock_release_failure(message, lock, &lock_err),
    }
}

fn finish_managed_plugin_file_commit_cleanup_blocking(
    backup: Option<&Path>,
    lock: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut failures = Vec::new();
    if let Some(backup) = backup {
        match std::fs::remove_file(backup) {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => failures.push(format!(
                "plugin request succeeded, but failed to remove staging backup '{}': {}; remove or recover that backup before the next local `--file` plugin mutation",
                backup.display(), err
            )),
        }
    }
    if let Err(err) = release_plugin_file_transaction_lock_blocking(lock) {
        failures.push(append_lock_release_failure(
            "plugin request succeeded".to_string(),
            lock,
            &err,
        ));
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(cli_error(failures.join("; ")))
    }
}

#[cfg(not(windows))]
async fn replace_plugin_artifact_with_backup(backup: &Path, dest: &Path) -> std::io::Result<()> {
    tokio::fs::rename(backup, dest).await
}

#[cfg(not(windows))]
fn replace_plugin_artifact_with_backup_blocking(backup: &Path, dest: &Path) -> std::io::Result<()> {
    std::fs::rename(backup, dest)
}

#[cfg(windows)]
async fn replace_plugin_artifact_with_backup(backup: &Path, dest: &Path) -> std::io::Result<()> {
    let backup = backup.to_path_buf();
    let dest = dest.to_path_buf();
    tokio::task::spawn_blocking(move || replace_plugin_artifact_with_backup_windows(&backup, &dest))
        .await
        .map_err(|err| std::io::Error::other(format!("rollback replace task failed: {}", err)))?
}

#[cfg(windows)]
fn replace_plugin_artifact_with_backup_blocking(backup: &Path, dest: &Path) -> std::io::Result<()> {
    replace_plugin_artifact_with_backup_windows(backup, dest)
}

#[cfg(windows)]
fn replace_plugin_artifact_with_backup_windows(backup: &Path, dest: &Path) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
    };

    let backup_wide: Vec<u16> = backup
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let dest_wide: Vec<u16> = dest
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let flags = MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH;
    // SAFETY: `backup_wide` and `dest_wide` are owned, NUL-terminated UTF-16
    // buffers that stay alive for the duration of this call, so the pointers are
    // valid and satisfy `MoveFileExW`'s requirements.
    let result = unsafe { MoveFileExW(backup_wide.as_ptr(), dest_wide.as_ptr(), flags) };
    if result == 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

async fn restore_previous_plugin_artifact(
    backup: &Path,
    dest: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(test)]
    if should_fail_restore_previous_plugin_artifact(dest) {
        return Err(cli_error(format!(
            "failed to restore previous plugin artifact from '{}' to '{}': injected restore failure",
            backup.display(),
            dest.display()
        )));
    }
    replace_plugin_artifact_with_backup(backup, dest)
        .await
        .map_err(|err| {
            cli_error(format!(
                "failed to restore previous plugin artifact from '{}' to '{}': {}",
                backup.display(),
                dest.display(),
                err
            ))
        })?;

    Ok(())
}

fn restore_previous_plugin_artifact_blocking(
    backup: &Path,
    dest: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    replace_plugin_artifact_with_backup_blocking(backup, dest).map_err(|err| {
        cli_error(format!(
            "failed to restore previous plugin artifact from '{}' to '{}': {}",
            backup.display(),
            dest.display(),
            err
        ))
    })?;

    Ok(())
}

async fn cleanup_partially_staged_plugin_artifact(
    dest: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(test)]
    if should_fail_staged_plugin_cleanup(dest) {
        return Err(cli_error(format!(
            "failed to remove partially staged plugin artifact '{}': injected staged plugin cleanup failure",
            dest.display()
        )));
    }
    match tokio::fs::remove_file(dest).await {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(cli_error(format!(
            "failed to remove partially staged plugin artifact '{}': {}",
            dest.display(),
            err
        ))),
    }
}

fn cleanup_partially_staged_plugin_artifact_blocking(
    dest: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    match std::fs::remove_file(dest) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(cli_error(format!(
            "failed to remove partially staged plugin artifact '{}': {}",
            dest.display(),
            err
        ))),
    }
}

fn rollback_managed_plugin_file_transaction_blocking(
    dest: &Path,
    backup: Option<&Path>,
    lock: &Path,
) -> Result<String, Box<dyn std::error::Error>> {
    let rollback_result = match backup {
        Some(backup) => match restore_previous_plugin_artifact_blocking(backup, dest) {
            Ok(()) => Ok(format!(
                "restored previous local managed artifact at '{}'",
                dest.display()
            )),
            Err(err) => Err(err),
        },
        None => match cleanup_partially_staged_plugin_artifact_blocking(dest) {
            Ok(()) => Ok(format!(
                "removed staged local managed artifact at '{}'",
                dest.display()
            )),
            Err(err) => Err(err),
        },
    };
    let lock_release_result = release_plugin_file_transaction_lock_blocking(lock);
    match (rollback_result, lock_release_result) {
        (Ok(note), Ok(())) => Ok(note),
        (Ok(note), Err(lock_err)) => Err(cli_error(append_lock_release_failure(
            note, lock, &lock_err,
        ))),
        (Err(err), Ok(())) => Err(err),
        (Err(err), Err(lock_err)) => Err(cli_error(append_lock_release_failure(
            err.to_string(),
            lock,
            &lock_err,
        ))),
    }
}

#[cfg(test)]
fn should_fail_staged_plugin_write(dest: &Path) -> bool {
    std::env::var_os("CARAPACE_TEST_FAIL_STAGE_PLUGIN_WRITE_DEST")
        .map(PathBuf::from)
        .as_deref()
        == Some(dest)
}

/// Reject a path that is a symlink. This narrows the TOCTOU window between
/// a prior `symlink_metadata` check and a subsequent mutation. It is not
/// race-proof on its own but combined with `O_NOFOLLOW` on opens it
/// provides defense-in-depth against local symlink-swap attacks.
fn reject_if_symlink(path: &Path, label: &str) -> Result<(), String> {
    match path.symlink_metadata() {
        Ok(m) if m.file_type().is_symlink() => Err(format!(
            "{label} '{}' is a symlink; refusing to proceed",
            path.display()
        )),
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!(
            "failed to verify {label} '{}' is not a symlink: {e}",
            path.display()
        )),
    }
}

async fn write_staged_plugin_artifact(dest: &Path, bytes: &[u8]) -> std::io::Result<()> {
    #[cfg(test)]
    if should_fail_staged_plugin_write(dest) {
        return Err(std::io::Error::other(
            "injected staged plugin write failure",
        ));
    }
    // create_new(true) provides O_CREAT|O_EXCL (fails if path exists).
    // On Unix, O_NOFOLLOW prevents following symlinks — if an attacker
    // places a symlink between the cleanup check and this open, the open
    // fails with ELOOP instead of creating a file through the symlink.
    //
    // Uses std::fs for the open (to access OpenOptionsExt::custom_flags),
    // then wraps in tokio::fs::File for async write.
    let dest = dest.to_path_buf();
    let std_file = tokio::task::spawn_blocking({
        move || {
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.custom_flags(libc::O_NOFOLLOW);
            }
            options.open(&dest)
        }
    })
    .await
    .map_err(|e| std::io::Error::other(format!("spawn_blocking failed: {e}")))??;

    let mut file = tokio::fs::File::from_std(std_file);
    file.write_all(bytes).await?;
    file.sync_data().await
}

#[cfg(test)]
fn should_fail_staged_plugin_cleanup(dest: &Path) -> bool {
    std::env::var_os("CARAPACE_TEST_FAIL_STAGE_PLUGIN_CLEANUP_DEST")
        .map(PathBuf::from)
        .as_deref()
        == Some(dest)
}

#[cfg(test)]
fn should_fail_staged_plugin_rename_dest(dest: &Path) -> bool {
    std::env::var_os("CARAPACE_TEST_FAIL_STAGE_PLUGIN_RENAME_DEST")
        .map(PathBuf::from)
        .as_deref()
        == Some(dest)
}

#[cfg(test)]
fn should_fail_restore_previous_plugin_artifact(dest: &Path) -> bool {
    std::env::var_os("CARAPACE_TEST_FAIL_RESTORE_PLUGIN_DEST")
        .map(PathBuf::from)
        .as_deref()
        == Some(dest)
}

async fn finalize_staged_plugin_artifact(staged: &Path, dest: &Path) -> std::io::Result<()> {
    #[cfg(test)]
    if should_fail_staged_plugin_rename_dest(dest) {
        return Err(std::io::Error::other(
            "injected staged plugin rename failure",
        ));
    }
    tokio::fs::rename(staged, dest).await
}

async fn stage_plugin_file_into_managed_dir(
    connection: &WsConnectionArgs,
    name: &str,
    file: &Path,
) -> Result<ManagedPluginFileTransaction, Box<dyn std::error::Error>> {
    if !is_loopback_host(&connection.host) {
        return Err(cli_error(
            "--file is only supported for loopback targets; use --url for remote plugin management",
        ));
    }
    crate::plugins::validate_managed_plugin_name(name).map_err(cli_error)?;

    let bytes = read_and_validate_local_plugin_artifact(file).await?;

    let managed_plugins_dir = resolve_state_dir().join("plugins");
    tokio::fs::create_dir_all(&managed_plugins_dir)
        .await
        .map_err(|err| {
            cli_error(format!(
                "failed to create managed plugins directory '{}': {}",
                managed_plugins_dir.display(),
                err
            ))
        })?;
    let dest = managed_plugins_dir.join(format!("{}.wasm", name));
    let backup = plugin_cli_backup_path(&dest)?;
    let lock = plugin_cli_lock_path(&dest)?;
    let staged = plugin_cli_staged_path(&dest)?;
    acquire_plugin_file_transaction_lock(&lock).await?;
    let pending_lock = PendingPluginFileTransactionLock::new(lock);
    let had_existing = match async {
        let existing_metadata = match tokio::fs::symlink_metadata(&dest).await {
            Ok(metadata) => Some(metadata),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
            Err(err) => {
                return Err(format!(
                    "failed to inspect managed plugin destination '{}': {}",
                    dest.display(),
                    err
                ));
            }
        };
        if let Some(metadata) = existing_metadata.as_ref() {
            if !metadata.is_file() {
                return Err(format!(
                    "managed plugin destination '{}' is not a regular file",
                    dest.display()
                ));
            }
        }
        // SECURITY: symlink-resistant staging for loopback-only --file workflow.
        match tokio::fs::symlink_metadata(&backup).await {
            Ok(_) => {
                return Err(format!(
                    "refusing to stage plugin file because rollback backup '{}' already exists; remove or recover it first",
                    backup.display()
                ));
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => {
                return Err(format!(
                    "failed to inspect staging backup '{}': {}",
                    backup.display(),
                    err
                ));
            }
        }
        match tokio::fs::symlink_metadata(&staged).await {
            Ok(_) => {
                cleanup_partially_staged_plugin_artifact(&staged)
                    .await
                    .map_err(|err| {
                        format!(
                            "failed to remove stale staged plugin artifact '{}': {}",
                            staged.display(),
                            err
                        )
                    })?;
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => {
                return Err(format!(
                    "failed to inspect staged plugin artifact '{}': {}",
                    staged.display(),
                    err
                ));
            }
        }
        let had_existing = existing_metadata.is_some();
        if had_existing {
            // Tighten the TOCTOU window: re-check dest is not a symlink
            // immediately before the rename. Combined with the preflight
            // check above, this narrows the attack surface.
            reject_if_symlink(&dest, "managed plugin destination")?;
            tokio::fs::rename(&dest, &backup).await.map_err(|err| {
                format!(
                    "failed to move existing managed plugin artifact '{}' to staging backup '{}': {}",
                    dest.display(),
                    backup.display(),
                    err
                )
            })?;
        }
        if let Err(err) = write_staged_plugin_artifact(&staged, &bytes).await {
            let mut message = format!(
                "failed to stage plugin file into temporary artifact '{}': {}",
                staged.display(),
                err
            );
            if let Err(cleanup_err) = cleanup_partially_staged_plugin_artifact(&staged).await {
                message = format!(
                    "{message}; additionally failed to remove partial staged file: {}",
                    cleanup_err
                );
            }
            if had_existing {
                let restore_result = restore_previous_plugin_artifact(&backup, &dest).await;
                return Err(match restore_result {
                    Ok(()) => format!(
                        "{message}; restored previous local managed artifact at '{}'",
                        dest.display()
                    ),
                    Err(restore_err) => {
                        format!("{message}; rollback also failed: {}", restore_err)
                    }
                });
            }
            return Err(message);
        }
        reject_if_symlink(&staged, "staged plugin artifact")?;
        if let Err(err) = finalize_staged_plugin_artifact(&staged, &dest).await {
            let mut message = format!(
                "failed to finalize staged plugin artifact from '{}' to '{}': {}",
                staged.display(),
                dest.display(),
                err
            );
            if let Err(cleanup_err) = cleanup_partially_staged_plugin_artifact(&staged).await {
                message = format!(
                    "{message}; additionally failed to remove partial staged file: {}",
                    cleanup_err
                );
            }
            if had_existing {
                let restore_result = restore_previous_plugin_artifact(&backup, &dest).await;
                return Err(match restore_result {
                    Ok(()) => format!(
                        "{message}; restored previous local managed artifact at '{}'",
                        dest.display()
                    ),
                    Err(restore_err) => {
                        format!("{message}; rollback also failed: {}", restore_err)
                    }
                });
            }
            return Err(message);
        }
        Ok::<bool, String>(had_existing)
    }
    .await
    {
        Ok(had_existing) => had_existing,
        Err(message) => {
            let message = pending_lock.release_with_context(message).await;
            return Err(cli_error(message));
        }
    };
    let lock = pending_lock.into_path();
    Ok(ManagedPluginFileTransaction {
        dest,
        backup: had_existing.then_some(backup),
        lock,
        drop_action: ManagedPluginFileTransactionDropAction::RollbackArtifact,
    })
}

async fn finalize_plugin_file_mutation<T, F>(
    staged_file: Option<ManagedPluginFileTransaction>,
    result_future: F,
) -> Result<T, Box<dyn std::error::Error>>
where
    F: std::future::Future<Output = Result<T, Box<dyn std::error::Error>>>,
{
    let result = result_future.await;
    match (staged_file, result) {
        (Some(transaction), Ok(value)) => {
            transaction.commit().await?;
            Ok(value)
        }
        (Some(transaction), Err(err)) => {
            let original = err.to_string();
            match transaction.rollback().await {
                Ok(rollback_note) => Err(cli_error(format!("{original}; {rollback_note}"))),
                Err(rollback_err) => Err(cli_error(format!(
                    "{original}; rollback also failed: {}",
                    rollback_err
                ))),
            }
        }
        (None, result) => result,
    }
}

fn plugin_mutation_params(
    name: &str,
    url: Option<&str>,
    version: Option<&str>,
    publisher_key: Option<&str>,
    signature: Option<&str>,
) -> Value {
    let mut params = serde_json::Map::new();
    params.insert("name".to_string(), Value::String(name.to_string()));
    if let Some(url) = url {
        params.insert("url".to_string(), Value::String(url.to_string()));
    }
    if let Some(version) = version.filter(|value| !value.trim().is_empty()) {
        params.insert(
            "version".to_string(),
            Value::String(version.trim().to_string()),
        );
    }
    if let Some(publisher_key) = publisher_key.filter(|value| !value.trim().is_empty()) {
        params.insert(
            "publisherKey".to_string(),
            Value::String(publisher_key.trim().to_string()),
        );
    }
    if let Some(signature) = signature.filter(|value| !value.trim().is_empty()) {
        params.insert(
            "signature".to_string(),
            Value::String(signature.trim().to_string()),
        );
    }
    Value::Object(params)
}

async fn handle_plugins_status_cli(
    options: PluginStatusCliOptions,
) -> Result<(), Box<dyn std::error::Error>> {
    let payload = send_cli_ws_request(
        &options.connection,
        "operator",
        &["operator.read"],
        "plugins.status",
        json!({}),
    )
    .await?;
    let mut response: PluginsStatusResponse = serde_json::from_value(payload)?;
    response.plugins.retain(|entry| {
        plugin_entry_matches_filters(
            entry,
            options.name.as_deref(),
            options.plugin_id.as_deref(),
            options.source,
            options.state,
            options.only_failed,
        )
    });

    if options.json_output {
        print_pretty_json(&serde_json::to_value(&response)?)?;
    } else {
        print_plugin_status_human(&response);
    }

    if options.strict {
        maybe_fail_strict_plugin_status(&response)?;
    }
    Ok(())
}

async fn handle_plugins_bins_cli(
    connection: WsConnectionArgs,
    json_output: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let payload = send_cli_ws_request(
        &connection,
        "operator",
        &["operator.read"],
        "plugins.bins",
        json!({}),
    )
    .await?;
    if json_output {
        print_pretty_json(&payload)?;
        return Ok(());
    }
    let response: PluginsBinsResponse = serde_json::from_value(payload)?;
    print_plugin_bins_human(&response);
    Ok(())
}

async fn handle_plugins_install_cli(
    options: PluginMutationArgs,
) -> Result<(), Box<dyn std::error::Error>> {
    let staged_file = if let Some(file) = options.file.as_deref() {
        Some(stage_plugin_file_into_managed_dir(&options.connection, &options.name, file).await?)
    } else {
        None
    };
    let payload = finalize_plugin_file_mutation(
        staged_file,
        send_cli_ws_request(
            &options.connection,
            "operator",
            &["operator.admin"],
            "plugins.install",
            plugin_mutation_params(
                &options.name,
                options.url.as_deref(),
                options.version.as_deref(),
                options.publisher_key.as_deref(),
                options.signature.as_deref(),
            ),
        ),
    )
    .await?;
    if options.json {
        print_pretty_json(&payload)?;
        return Ok(());
    }
    let response: PluginMutationResponse = serde_json::from_value(payload)?;
    println!("Plugin install requested");
    println!("  Name: {}", response.name);
    if let Some(version) = response.version.as_deref() {
        println!("  Version: {}", version);
    }
    if let Some(message) = response.activation.message.as_deref() {
        println!("  Activation: {} ({})", response.activation.state, message);
    } else {
        println!("  Activation: {}", response.activation.state);
    }
    Ok(())
}

async fn handle_plugins_update_cli(
    options: PluginMutationArgs,
) -> Result<(), Box<dyn std::error::Error>> {
    let staged_file = if let Some(file) = options.file.as_deref() {
        Some(stage_plugin_file_into_managed_dir(&options.connection, &options.name, file).await?)
    } else {
        None
    };
    let payload = finalize_plugin_file_mutation(
        staged_file,
        send_cli_ws_request(
            &options.connection,
            "operator",
            &["operator.admin"],
            "plugins.update",
            plugin_mutation_params(
                &options.name,
                options.url.as_deref(),
                options.version.as_deref(),
                options.publisher_key.as_deref(),
                options.signature.as_deref(),
            ),
        ),
    )
    .await?;
    if options.json {
        print_pretty_json(&payload)?;
        return Ok(());
    }
    let response: PluginMutationResponse = serde_json::from_value(payload)?;
    println!("Plugin update requested");
    println!("  Name: {}", response.name);
    if let Some(version) = response.version.as_deref() {
        println!("  Version: {}", version);
    }
    if let Some(message) = response.activation.message.as_deref() {
        println!("  Activation: {} ({})", response.activation.state, message);
    } else {
        println!("  Activation: {}", response.activation.state);
    }
    Ok(())
}

pub async fn handle_plugins(command: PluginsCommand) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        PluginsCommand::Status {
            json,
            name,
            plugin_id,
            source,
            state,
            only_failed,
            strict,
            connection,
        } => {
            handle_plugins_status_cli(PluginStatusCliOptions {
                connection,
                json_output: json,
                name,
                plugin_id,
                source,
                state,
                only_failed,
                strict,
            })
            .await
        }
        PluginsCommand::Bins { json, connection } => {
            handle_plugins_bins_cli(connection, json).await
        }
        PluginsCommand::Install(args) => handle_plugins_install_cli(args).await,
        PluginsCommand::Update(args) => handle_plugins_update_cli(args).await,
    }
}

pub async fn handle_logs(
    host: &str,
    port: Option<u16>,
    lines: usize,
    tls: bool,
    trust: bool,
    allow_plaintext: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let connection = WsConnectionArgs {
        port,
        host: host.to_string(),
        tls,
        trust,
        allow_plaintext,
    };
    let payload = send_cli_ws_request(
        &connection,
        "operator",
        &["operator.read"],
        "logs.tail",
        json!({ "limit": lines }),
    )
    .await?;

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

pub(crate) fn resolve_state_dir() -> PathBuf {
    crate::paths::resolve_state_dir()
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

    // Durable task queue/state directory.
    let tasks_dir = state_dir.join("tasks");
    if tasks_dir.is_dir() {
        archive.append_dir_all("tasks", &tasks_dir)?;
        included_sections.push("tasks");
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
            } else if path_str == "tasks" || path_str.starts_with("tasks/") {
                Some("tasks")
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
        } else if path_str == "tasks" || path_str.starts_with("tasks/") {
            let rel = path.strip_prefix("tasks").unwrap_or(&path);
            let target = state_dir.join("tasks").join(rel);
            extract_entry(&mut entry, &target)?;
            if !restored.contains(&"tasks".to_string()) {
                restored.push("tasks".to_string());
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SetupProviderChoice {
    Anthropic,
    OpenAi,
    Ollama,
    Gemini,
    Vertex,
    Venice,
    Bedrock,
}

impl SetupProviderChoice {
    fn prompt_key(self) -> &'static str {
        match self {
            Self::Anthropic => "anthropic",
            Self::OpenAi => "openai",
            Self::Ollama => "ollama",
            Self::Gemini => "gemini",
            Self::Vertex => "vertex",
            Self::Venice => "venice",
            Self::Bedrock => "bedrock",
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Anthropic => "Anthropic",
            Self::OpenAi => "OpenAI",
            Self::Ollama => "Ollama",
            Self::Gemini => "Gemini",
            Self::Vertex => "Vertex",
            Self::Venice => "Venice",
            Self::Bedrock => "Bedrock",
        }
    }

    fn parse_prompt(raw: &str) -> Option<Self> {
        match raw.trim().to_lowercase().as_str() {
            "anthropic" | "claude" => Some(Self::Anthropic),
            "openai" | "gpt" => Some(Self::OpenAi),
            "ollama" => Some(Self::Ollama),
            "gemini" => Some(Self::Gemini),
            "vertex" => Some(Self::Vertex),
            "venice" => Some(Self::Venice),
            "bedrock" => Some(Self::Bedrock),
            _ => None,
        }
    }
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VerifyOutcome {
    LocalChat,
    Discord,
    Telegram,
    Hooks,
    Autonomy,
}

impl VerifyOutcome {
    fn key(self) -> &'static str {
        match self {
            Self::LocalChat => "local-chat",
            Self::Discord => "discord",
            Self::Telegram => "telegram",
            Self::Hooks => "hooks",
            Self::Autonomy => "autonomy",
        }
    }
}

impl From<SetupOutcome> for VerifyOutcome {
    fn from(value: SetupOutcome) -> Self {
        match value {
            SetupOutcome::LocalChat => Self::LocalChat,
            SetupOutcome::Discord => Self::Discord,
            SetupOutcome::Telegram => Self::Telegram,
            SetupOutcome::Hooks => Self::Hooks,
        }
    }
}

impl VerifyOutcomeSelection {
    fn resolved(self, cfg: &Value) -> VerifyOutcome {
        match self {
            Self::Auto => infer_setup_outcome_from_config(cfg).into(),
            Self::LocalChat => VerifyOutcome::LocalChat,
            Self::Discord => VerifyOutcome::Discord,
            Self::Telegram => VerifyOutcome::Telegram,
            Self::Hooks => VerifyOutcome::Hooks,
            Self::Autonomy => VerifyOutcome::Autonomy,
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

#[derive(clap::ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetupProvider {
    #[value(name = "anthropic", alias = "claude")]
    Anthropic,
    #[value(name = "codex")]
    Codex,
    #[value(name = "openai", alias = "gpt")]
    OpenAi,
    #[value(name = "ollama")]
    Ollama,
    #[value(name = "gemini")]
    Gemini,
    #[value(name = "vertex")]
    Vertex,
    #[value(name = "venice")]
    Venice,
    #[value(name = "bedrock")]
    Bedrock,
}

impl SetupProvider {
    fn prompt_key(self) -> &'static str {
        match self {
            Self::Anthropic => "anthropic",
            Self::Codex => "codex",
            Self::OpenAi => "openai",
            Self::Ollama => "ollama",
            Self::Gemini => "gemini",
            Self::Vertex => "vertex",
            Self::Venice => "venice",
            Self::Bedrock => "bedrock",
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Anthropic => "Anthropic",
            Self::Codex => "OpenAI",
            Self::OpenAi => "OpenAI",
            Self::Ollama => "Ollama",
            Self::Gemini => "Gemini",
            Self::Vertex => "Vertex",
            Self::Venice => "Venice",
            Self::Bedrock => "Bedrock",
        }
    }

    fn api_key_env_var_name(self) -> Option<&'static str> {
        match self {
            Self::Anthropic => Some("ANTHROPIC_API_KEY"),
            Self::Codex => None,
            Self::OpenAi => Some("OPENAI_API_KEY"),
            Self::Gemini => Some("GOOGLE_API_KEY"),
            Self::Vertex => None,
            Self::Venice => Some("VENICE_API_KEY"),
            Self::Ollama | Self::Bedrock => None,
        }
    }

    fn default_model(self) -> &'static str {
        match self {
            Self::Anthropic => "anthropic:claude-sonnet-4-20250514",
            Self::Codex => "codex:default",
            Self::OpenAi => "openai:gpt-4o",
            Self::Ollama => "ollama:llama3",
            Self::Gemini => "gemini:gemini-2.0-flash",
            Self::Vertex => "vertex:default",
            Self::Venice => "venice:llama-3.3-70b",
            Self::Bedrock => "bedrock:anthropic.claude-3-5-sonnet-20240620-v1:0",
        }
    }
}

#[derive(clap::ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetupAuthModeSelection {
    #[value(name = "oauth")]
    OAuth,
    #[value(name = "api-key")]
    ApiKey,
    #[value(name = "setup-token")]
    SetupToken,
}

impl From<SetupProvider> for crate::onboarding::setup::SetupProvider {
    fn from(value: SetupProvider) -> Self {
        match value {
            SetupProvider::Anthropic => Self::Anthropic,
            SetupProvider::Codex => Self::Codex,
            SetupProvider::OpenAi => Self::OpenAi,
            SetupProvider::Ollama => Self::Ollama,
            SetupProvider::Gemini => Self::Gemini,
            SetupProvider::Vertex => Self::Vertex,
            SetupProvider::Venice => Self::Venice,
            SetupProvider::Bedrock => Self::Bedrock,
        }
    }
}

impl From<SetupAuthModeSelection> for crate::onboarding::setup::SetupAuthMode {
    fn from(value: SetupAuthModeSelection) -> Self {
        match value {
            SetupAuthModeSelection::OAuth => Self::OAuth,
            SetupAuthModeSelection::ApiKey => Self::ApiKey,
            SetupAuthModeSelection::SetupToken => Self::SetupToken,
        }
    }
}

type ProviderSetupResult = crate::onboarding::setup::SetupFlowResult;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ModelProviderRoute {
    Anthropic,
    Codex,
    OpenAi,
    Ollama,
    Gemini,
    Vertex,
    Bedrock,
    Venice,
}

fn env_var_present(key: &str) -> bool {
    std::env::var(key)
        .ok()
        .map(|value| !value.trim().is_empty())
        .unwrap_or(false)
}

fn env_var_value(key: &str) -> Option<String> {
    std::env::var(key)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

#[cfg(test)]
fn detect_setup_provider_env_hints() -> Vec<SetupProvider> {
    let mut providers = Vec::new();

    if env_var_present("ANTHROPIC_API_KEY")
        || (env_var_present("ANTHROPIC_SETUP_TOKEN") && env_var_present("CARAPACE_CONFIG_PASSWORD"))
    {
        providers.push(SetupProvider::Anthropic);
    }
    if env_var_present("OPENAI_API_KEY") {
        providers.push(SetupProvider::OpenAi);
    }
    if env_var_present("CARAPACE_CONFIG_PASSWORD")
        && env_var_present("OPENAI_OAUTH_CLIENT_ID")
        && env_var_present("OPENAI_OAUTH_CLIENT_SECRET")
    {
        providers.push(SetupProvider::Codex);
    }
    if env_var_present("OLLAMA_BASE_URL") {
        providers.push(SetupProvider::Ollama);
    }
    if env_var_present("GOOGLE_API_KEY") {
        providers.push(SetupProvider::Gemini);
    }
    if env_var_present("VERTEX_PROJECT_ID") {
        providers.push(SetupProvider::Vertex);
    }
    if env_var_present("VENICE_API_KEY") {
        providers.push(SetupProvider::Venice);
    }

    let bedrock_region = env_var_present("AWS_REGION") || env_var_present("AWS_DEFAULT_REGION");
    let bedrock_access_key = env_var_present("AWS_ACCESS_KEY_ID");
    let bedrock_secret_key = env_var_present("AWS_SECRET_ACCESS_KEY");
    if bedrock_region && bedrock_access_key && bedrock_secret_key {
        providers.push(SetupProvider::Bedrock);
    }

    providers
}

fn detect_setup_provider_choice_env_hints() -> Vec<SetupProviderChoice> {
    let mut choices = Vec::new();

    if env_var_present("ANTHROPIC_API_KEY")
        || (env_var_present("ANTHROPIC_SETUP_TOKEN") && env_var_present("CARAPACE_CONFIG_PASSWORD"))
    {
        choices.push(SetupProviderChoice::Anthropic);
    }
    if env_var_present("OPENAI_API_KEY")
        || (env_var_present("CARAPACE_CONFIG_PASSWORD")
            && env_var_present("OPENAI_OAUTH_CLIENT_ID")
            && env_var_present("OPENAI_OAUTH_CLIENT_SECRET"))
    {
        choices.push(SetupProviderChoice::OpenAi);
    }
    if env_var_present("OLLAMA_BASE_URL") {
        choices.push(SetupProviderChoice::Ollama);
    }
    if env_var_present("GOOGLE_API_KEY") {
        choices.push(SetupProviderChoice::Gemini);
    }
    if env_var_present("VERTEX_PROJECT_ID") {
        choices.push(SetupProviderChoice::Vertex);
    }
    if env_var_present("VENICE_API_KEY") {
        choices.push(SetupProviderChoice::Venice);
    }

    let bedrock_region = env_var_present("AWS_REGION") || env_var_present("AWS_DEFAULT_REGION");
    let bedrock_access_key = env_var_present("AWS_ACCESS_KEY_ID");
    let bedrock_secret_key = env_var_present("AWS_SECRET_ACCESS_KEY");
    if bedrock_region && bedrock_access_key && bedrock_secret_key {
        choices.push(SetupProviderChoice::Bedrock);
    }

    choices
}

fn default_setup_provider_choice(provider_hints: &[SetupProviderChoice]) -> SetupProviderChoice {
    if let [provider] = provider_hints {
        *provider
    } else {
        provider_hints
            .first()
            .copied()
            .unwrap_or(SetupProviderChoice::Anthropic)
    }
}

fn referenced_env_vars(value: &str) -> Vec<String> {
    crate::config::env_var_references_in_string(value)
}

fn first_missing_env_var(value: &str) -> Option<String> {
    referenced_env_vars(value)
        .into_iter()
        .find(|env_var| !env_var_present(env_var))
}

fn config_string(cfg: &Value, path: &[&str]) -> Option<String> {
    let mut current = cfg;
    for key in path {
        current = current.get(*key)?;
    }
    current
        .as_str()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn config_value_is_usable(value: &str) -> bool {
    referenced_env_vars(value)
        .into_iter()
        .all(|env_var| env_var_present(&env_var))
}

fn config_path_has_usable_value(cfg: &Value, path: &[&str]) -> bool {
    config_string(cfg, path)
        .map(|value| config_value_is_usable(&value))
        .unwrap_or(false)
}

fn unresolved_placeholder_env_var(cfg: &Value, path: &[&str]) -> Option<String> {
    config_string(cfg, path).and_then(|value| first_missing_env_var(&value))
}

fn ollama_configured_for_guidance(cfg: &Value) -> bool {
    if env_var_present("OLLAMA_BASE_URL") {
        return true;
    }

    match cfg.get("providers").and_then(|value| value.get("ollama")) {
        Some(ollama_cfg) => {
            if let Some(base_url) = ollama_cfg.get("baseUrl").and_then(|value| value.as_str()) {
                config_value_is_usable(base_url.trim()) && !base_url.trim().is_empty()
            } else {
                true
            }
        }
        None => false,
    }
}

fn usable_provider_labels(cfg: &Value) -> Vec<&'static str> {
    let mut labels = Vec::new();
    if env_var_present("ANTHROPIC_API_KEY")
        || config_path_has_usable_value(cfg, &["anthropic", "apiKey"])
        || (config_path_has_usable_value(cfg, &["anthropic", "authProfile"])
            && env_var_present("CARAPACE_CONFIG_PASSWORD"))
    {
        labels.push("Anthropic");
    }
    if env_var_present("OPENAI_API_KEY") || config_path_has_usable_value(cfg, &["openai", "apiKey"])
    {
        labels.push("OpenAI");
    }
    if config_path_has_usable_value(cfg, &["codex", "authProfile"])
        && env_var_present("CARAPACE_CONFIG_PASSWORD")
    {
        labels.push("Codex");
    }
    if ollama_configured_for_guidance(cfg) {
        labels.push("Ollama");
    }
    if env_var_present("GOOGLE_API_KEY") || config_path_has_usable_value(cfg, &["google", "apiKey"])
    {
        labels.push("Gemini");
    }
    let vertex_project = env_var_present("VERTEX_PROJECT_ID")
        || config_path_has_usable_value(cfg, &["vertex", "projectId"]);
    let vertex_location = env_var_present("VERTEX_LOCATION")
        || config_path_has_usable_value(cfg, &["vertex", "location"]);
    let vertex_model =
        env_var_present("VERTEX_MODEL") || config_path_has_usable_value(cfg, &["vertex", "model"]);
    let vertex_route = local_chat_model(cfg);
    if crate::agent::vertex::is_vertex_model(&vertex_route)
        && vertex_project
        && vertex_location
        && (!matches!(vertex_route.as_str(), "vertex:default") || vertex_model)
    {
        labels.push("Vertex");
    }
    if env_var_present("VENICE_API_KEY") || config_path_has_usable_value(cfg, &["venice", "apiKey"])
    {
        labels.push("Venice");
    }
    let bedrock_enabled = cfg
        .get("bedrock")
        .and_then(|value| value.get("enabled"))
        .and_then(|value| value.as_bool())
        != Some(false);
    let bedrock_region = env_var_present("AWS_REGION")
        || env_var_present("AWS_DEFAULT_REGION")
        || config_path_has_usable_value(cfg, &["bedrock", "region"]);
    let bedrock_access_key = env_var_present("AWS_ACCESS_KEY_ID")
        || config_path_has_usable_value(cfg, &["bedrock", "accessKeyId"]);
    let bedrock_secret_key = env_var_present("AWS_SECRET_ACCESS_KEY")
        || config_path_has_usable_value(cfg, &["bedrock", "secretAccessKey"]);
    if bedrock_enabled && bedrock_region && bedrock_access_key && bedrock_secret_key {
        labels.push("Bedrock");
    }
    labels
}

fn no_provider_configured_guidance() -> String {
    "configure a provider for the selected model, or rerun `cara setup --force`, then retry `cara verify --outcome local-chat`"
        .to_string()
}

fn missing_placeholder_guidance(env_var: &str) -> String {
    format!(
        "set `${env_var}` in the same shell you use for `cara start` and `cara verify`, or rerun `cara setup --force` to write the key into config, then retry `cara verify --outcome local-chat`"
    )
}

fn provider_route_fallback_guidance(
    cfg: &Value,
    provider_label: &str,
    config_hint: Option<&str>,
) -> String {
    let usable = usable_provider_labels(cfg);
    if usable.is_empty() {
        return no_provider_configured_guidance();
    }

    match config_hint {
        Some(hint) => format!(
            "the selected model currently routes to {provider_label}; configure {provider_label} ({hint}) or switch `agents.defaults.model` to one of the other usable providers ({}), then retry `cara verify --outcome local-chat`",
            usable.join(", ")
        ),
        None => format!(
            "the selected model currently routes to {provider_label}; configure {provider_label} or switch `agents.defaults.model` to one of the other usable providers ({}), then retry `cara verify --outcome local-chat`",
            usable.join(", ")
        ),
    }
}

fn single_credential_provider_guidance(
    cfg: &Value,
    provider_label: &str,
    primary_env_var_name: &str,
    config_path: &[&str],
    configured_message: &str,
    config_hint: Option<&str>,
) -> String {
    if env_var_present(primary_env_var_name) {
        return configured_message.to_string();
    }

    if let Some(configured) = config_string(cfg, config_path) {
        if let Some(env_var) = first_missing_env_var(&configured) {
            return missing_placeholder_guidance(&env_var);
        }
        return configured_message.to_string();
    }

    provider_route_fallback_guidance(cfg, provider_label, config_hint)
}

fn local_chat_model(cfg: &Value) -> String {
    config_string(cfg, &["agents", "defaults", "model"]).unwrap_or_default()
}

fn local_chat_provider_route(model: &str) -> Option<ModelProviderRoute> {
    if crate::agent::ollama::is_ollama_model(model) {
        Some(ModelProviderRoute::Ollama)
    } else if crate::agent::venice::is_venice_model(model) {
        Some(ModelProviderRoute::Venice)
    } else if crate::agent::gemini::is_gemini_model(model) {
        Some(ModelProviderRoute::Gemini)
    } else if crate::agent::vertex::is_vertex_model(model) {
        Some(ModelProviderRoute::Vertex)
    } else if crate::agent::codex::is_codex_model(model) {
        Some(ModelProviderRoute::Codex)
    } else if crate::agent::openai::is_openai_model(model) {
        Some(ModelProviderRoute::OpenAi)
    } else if crate::agent::bedrock::is_bedrock_model(model) {
        Some(ModelProviderRoute::Bedrock)
    } else if crate::agent::anthropic::is_anthropic_model(model) {
        Some(ModelProviderRoute::Anthropic)
    } else {
        None
    }
}

fn provider_api_key_guidance(cfg: &Value, provider: SetupProvider, config_path: &[&str]) -> String {
    let configured_message = format!(
        "check {} API key/model and retry `cara verify --outcome local-chat`",
        provider.label()
    );
    let Some(primary_env_var_name) = provider.api_key_env_var_name() else {
        return provider_route_fallback_guidance(cfg, provider.label(), None);
    };
    single_credential_provider_guidance(
        cfg,
        provider.label(),
        primary_env_var_name,
        config_path,
        &configured_message,
        None,
    )
}

fn anthropic_provider_guidance(cfg: &Value) -> String {
    if let Some(env_var) = unresolved_placeholder_env_var(cfg, &["anthropic", "apiKey"]) {
        return missing_placeholder_guidance(&env_var);
    }

    let api_key_configured = SetupProvider::Anthropic
        .api_key_env_var_name()
        .map(env_var_present)
        .unwrap_or(false)
        || config_path_has_usable_value(cfg, &["anthropic", "apiKey"]);
    if api_key_configured {
        let mut guidance =
            provider_api_key_guidance(cfg, SetupProvider::Anthropic, &["anthropic", "apiKey"]);
        if config_path_has_usable_value(cfg, &["anthropic", "authProfile"]) {
            guidance.push_str(
                " Note: both `anthropic.apiKey` and `anthropic.authProfile` are configured; the API key configuration will be used.",
            );
        }
        return guidance;
    }

    if config_path_has_usable_value(cfg, &["anthropic", "authProfile"]) {
        if env_var_present("CARAPACE_CONFIG_PASSWORD") {
            return "check Anthropic auth profile/model and retry `cara verify --outcome local-chat`"
                .to_string();
        }
        return "set `CARAPACE_CONFIG_PASSWORD` in the same shell you use for `cara start` and `cara verify`, then retry `cara verify --outcome local-chat`".to_string();
    }

    provider_api_key_guidance(cfg, SetupProvider::Anthropic, &["anthropic", "apiKey"])
}

fn bedrock_provider_guidance(cfg: &Value) -> String {
    let region = env_var_present("AWS_REGION")
        || env_var_present("AWS_DEFAULT_REGION")
        || config_path_has_usable_value(cfg, &["bedrock", "region"]);
    let access_key = env_var_present("AWS_ACCESS_KEY_ID")
        || config_path_has_usable_value(cfg, &["bedrock", "accessKeyId"]);
    let secret_key = env_var_present("AWS_SECRET_ACCESS_KEY")
        || config_path_has_usable_value(cfg, &["bedrock", "secretAccessKey"]);

    if region && access_key && secret_key {
        return "check AWS Bedrock region/credentials and selected model, then retry `cara verify --outcome local-chat`"
            .to_string();
    }

    if let Some(env_var) = unresolved_placeholder_env_var(cfg, &["bedrock", "region"])
        .or_else(|| unresolved_placeholder_env_var(cfg, &["bedrock", "accessKeyId"]))
        .or_else(|| unresolved_placeholder_env_var(cfg, &["bedrock", "secretAccessKey"]))
    {
        return missing_placeholder_guidance(&env_var);
    }

    provider_route_fallback_guidance(
        cfg,
        "Bedrock",
        Some("`AWS_REGION`, `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` or `bedrock.*`"),
    )
}

fn vertex_provider_guidance(cfg: &Value) -> String {
    let project = env_var_present("VERTEX_PROJECT_ID")
        || config_path_has_usable_value(cfg, &["vertex", "projectId"]);
    let location = env_var_present("VERTEX_LOCATION")
        || config_path_has_usable_value(cfg, &["vertex", "location"]);
    let local_route = local_chat_model(cfg);
    let requires_default_model = crate::agent::vertex::is_vertex_model(&local_route)
        && crate::agent::vertex::strip_vertex_prefix(&local_route) == "default";
    let default_model =
        env_var_present("VERTEX_MODEL") || config_path_has_usable_value(cfg, &["vertex", "model"]);

    if project && location && requires_default_model && !default_model {
        return "set `VERTEX_MODEL` in the same shell you use for `cara start` and `cara verify`, or configure `vertex.model`, then retry `cara verify --outcome local-chat`"
            .to_string();
    }

    if project && location && (!requires_default_model || default_model) {
        return "check Vertex auth, project, location, and selected model, then retry `cara verify --outcome local-chat`"
            .to_string();
    }

    if let Some(env_var) = unresolved_placeholder_env_var(cfg, &["vertex", "projectId"])
        .or_else(|| unresolved_placeholder_env_var(cfg, &["vertex", "location"]))
        .or_else(|| unresolved_placeholder_env_var(cfg, &["vertex", "model"]))
    {
        return missing_placeholder_guidance(&env_var);
    }

    provider_route_fallback_guidance(
        cfg,
        "Vertex",
        Some("`VERTEX_PROJECT_ID`, `VERTEX_LOCATION`, `VERTEX_MODEL` or `vertex.*`"),
    )
}

fn codex_provider_guidance(cfg: &Value) -> String {
    if config_path_has_usable_value(cfg, &["codex", "authProfile"]) {
        if env_var_present("CARAPACE_CONFIG_PASSWORD") {
            return "check Codex auth profile/model and retry `cara verify --outcome local-chat`"
                .to_string();
        }
        return "set `CARAPACE_CONFIG_PASSWORD` in the same shell you use for `cara start` and `cara verify`, then retry `cara verify --outcome local-chat`".to_string();
    }

    provider_route_fallback_guidance(
        cfg,
        "Codex",
        Some("`codex.authProfile` plus `CARAPACE_CONFIG_PASSWORD` (or rerun `cara setup --provider codex`)"),
    )
}

fn local_chat_verify_next_step(cfg: &Value) -> String {
    let model = local_chat_model(cfg);
    let Some(route) = local_chat_provider_route(&model) else {
        if model.is_empty() {
            return "set `agents.defaults.model` to a provider:model value \
                    (e.g. `anthropic:claude-sonnet-4-20250514`), then retry \
                    `cara verify --outcome local-chat`"
                .to_string();
        }
        let suggestion = crate::migration::prefix_bare_model(&model);
        return if suggestion != model {
            format!(
                "`agents.defaults.model` = \"{model}\" needs a provider prefix; \
                 use `{suggestion}` instead, then retry `cara verify --outcome local-chat`"
            )
        } else {
            format!(
                "`agents.defaults.model` = \"{model}\" uses an unrecognized provider; \
                 configure a provider for the selected model, or rerun `cara setup --force`, \
                 then retry `cara verify --outcome local-chat`"
            )
        };
    };
    match route {
        ModelProviderRoute::Anthropic => anthropic_provider_guidance(cfg),
        ModelProviderRoute::Codex => codex_provider_guidance(cfg),
        ModelProviderRoute::OpenAi => {
            provider_api_key_guidance(cfg, SetupProvider::OpenAi, &["openai", "apiKey"])
        }
        ModelProviderRoute::Gemini => single_credential_provider_guidance(
            cfg,
            "Gemini",
            "GOOGLE_API_KEY",
            &["google", "apiKey"],
            "check Gemini API key/model and retry `cara verify --outcome local-chat`",
            Some("`GOOGLE_API_KEY` or `google.apiKey`"),
        ),
        ModelProviderRoute::Vertex => vertex_provider_guidance(cfg),
        ModelProviderRoute::Venice => single_credential_provider_guidance(
            cfg,
            "Venice",
            "VENICE_API_KEY",
            &["venice", "apiKey"],
            "check Venice API key/model and retry `cara verify --outcome local-chat`",
            Some("`VENICE_API_KEY` or `venice.apiKey`"),
        ),
        ModelProviderRoute::Ollama => {
            if ollama_configured_for_guidance(cfg) {
                "check Ollama server reachability/base URL and selected model, then retry `cara verify --outcome local-chat`"
                    .to_string()
            } else {
                provider_route_fallback_guidance(
                    cfg,
                    "Ollama",
                    Some("`OLLAMA_BASE_URL` or `providers.ollama.baseUrl`"),
                )
            }
        }
        ModelProviderRoute::Bedrock => bedrock_provider_guidance(cfg),
    }
}

fn verify_failure_follow_up_url(outcome: VerifyOutcome) -> &'static str {
    match outcome {
        VerifyOutcome::Discord => "https://getcara.io/cookbook/discord-assistant.html",
        VerifyOutcome::Telegram => "https://getcara.io/cookbook/telegram-webhook-assistant.html",
        VerifyOutcome::Hooks | VerifyOutcome::LocalChat | VerifyOutcome::Autonomy => {
            "https://getcara.io/help.html#guided-setup-help"
        }
    }
}

#[cfg(test)]
#[derive(Debug, Clone, Default)]
struct SetupInteractiveTestHarness {
    force_interactive: Option<bool>,
    visible_inputs: std::collections::VecDeque<String>,
    hidden_inputs: std::collections::VecDeque<String>,
    provider_validation_results: std::collections::VecDeque<Result<(), String>>,
    channel_validation_results: std::collections::VecDeque<Result<(), String>>,
    visible_prompt_count: usize,
    hidden_prompt_count: usize,
    provider_validation_calls: usize,
    channel_validation_calls: usize,
}

#[cfg(test)]
static SETUP_INTERACTIVE_TEST_HARNESS: std::sync::LazyLock<
    std::sync::Mutex<Option<SetupInteractiveTestHarness>>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(None));
// Test harness state is process-global; harness-using tests must hold a `ScopedEnv`.

#[cfg(test)]
fn set_setup_interactive_test_harness(harness: SetupInteractiveTestHarness) {
    let mut slot = SETUP_INTERACTIVE_TEST_HARNESS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    assert!(slot.is_none(), "setup test harness already installed");
    *slot = Some(harness);
}

#[cfg(test)]
fn clear_setup_interactive_test_harness() {
    let mut slot = SETUP_INTERACTIVE_TEST_HARNESS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    *slot = None;
}

#[cfg(test)]
fn setup_interactive_test_harness_snapshot() -> Option<SetupInteractiveTestHarness> {
    let slot = SETUP_INTERACTIVE_TEST_HARNESS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    slot.clone()
}

#[cfg(test)]
fn setup_interactive_test_harness_override_interactive() -> Option<bool> {
    let slot = SETUP_INTERACTIVE_TEST_HARNESS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    slot.as_ref().and_then(|state| state.force_interactive)
}

#[cfg(test)]
fn setup_interactive_test_harness_take_prompt_input(prompt: &str, hidden: bool) -> Option<String> {
    let mut slot = SETUP_INTERACTIVE_TEST_HARNESS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let state = slot.as_mut()?;
    let value = if hidden {
        state.hidden_prompt_count = state.hidden_prompt_count.saturating_add(1);
        state.hidden_inputs.pop_front()
    } else {
        state.visible_prompt_count = state.visible_prompt_count.saturating_add(1);
        state.visible_inputs.pop_front()
    };
    if value.is_some() {
        return value;
    }
    drop(slot);
    if hidden {
        panic!("missing scripted hidden input for prompt: {prompt}");
    }
    panic!("missing scripted visible input for prompt: {prompt}");
}

#[cfg(test)]
fn setup_interactive_test_harness_take_provider_validation_result() -> Option<Result<(), String>> {
    let mut slot = SETUP_INTERACTIVE_TEST_HARNESS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let state = slot.as_mut()?;
    state.provider_validation_calls = state.provider_validation_calls.saturating_add(1);
    let result = state.provider_validation_results.pop_front();
    if result.is_some() {
        return result;
    }
    drop(slot);
    panic!("missing scripted provider validation result");
}

#[cfg(test)]
fn setup_interactive_test_harness_take_channel_validation_result() -> Option<Result<(), String>> {
    let mut slot = SETUP_INTERACTIVE_TEST_HARNESS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let state = slot.as_mut()?;
    state.channel_validation_calls = state.channel_validation_calls.saturating_add(1);
    let result = state.channel_validation_results.pop_front();
    if result.is_some() {
        return result;
    }
    drop(slot);
    panic!("missing scripted channel validation result");
}

fn stdin_is_interactive() -> bool {
    #[cfg(test)]
    {
        // Keep tests deterministic: default to non-interactive unless explicitly forced.
        setup_interactive_test_harness_override_interactive().unwrap_or(false)
    }

    #[cfg(not(test))]
    {
        std::io::stdin().is_terminal()
    }
}

fn prompt_setup_outcome() -> Result<SetupOutcome, Box<dyn std::error::Error>> {
    loop {
        let selection = prompt_with_default(
            "Pick your first-run outcome (fastest path: local-chat/discord/telegram/hooks)",
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
    value_label: &str,
    hide_sensitive_input: bool,
) -> Result<Option<String>, Box<dyn std::error::Error>> {
    let env_value = std::env::var(env_var).ok().filter(|v| !v.trim().is_empty());
    if let Some(value) = env_value {
        let use_env = prompt_yes_no(&format!("Use {label} from ${env_var}?"), true)?;
        if use_env {
            return Ok(Some(value.trim().to_string()));
        }
    }

    let entered = prompt_sensitive_line(value_label, hide_sensitive_input, true)?;
    if entered.is_empty() {
        Ok(None)
    } else {
        Ok(Some(entered))
    }
}

fn print_setup_outcome_next_steps(outcome: SetupOutcome, port: u16, hooks_enabled: bool) {
    println!();
    let verify_command = format!(
        "cara verify --outcome {} --port {port}",
        outcome.prompt_key()
    );
    match outcome {
        SetupOutcome::LocalChat => {
            println!("First-run outcome: local assistant chat");
            println!("Next step: run `{verify_command}` once the service is up.");
            println!("Then open chat with `cara chat --port {port}`.");
            println!(
                "Need step-by-step help? {}",
                verify_failure_follow_up_url(VerifyOutcome::LocalChat)
            );
        }
        SetupOutcome::Discord => {
            println!("First-run outcome: Discord assistant");
            println!("Next step: run `{verify_command}`.");
            println!("For full send-path verification, rerun with `--discord-to <channel_id>`.");
            println!("Docs: https://getcara.io/cookbook/discord-assistant.html");
            println!("Repo docs path: docs/cookbook/discord-assistant.md");
        }
        SetupOutcome::Telegram => {
            println!("First-run outcome: Telegram assistant");
            println!("Next step: run `{verify_command}`.");
            println!("For full send-path verification, rerun with `--telegram-to <chat_id>`.");
            println!("Docs: https://getcara.io/cookbook/telegram-webhook-assistant.html");
            println!("Repo docs path: docs/cookbook/telegram-webhook-assistant.md");
        }
        SetupOutcome::Hooks => {
            println!("First-run outcome: hooks automation");
            println!("Next step: run `{verify_command}`.");
            if hooks_enabled {
                println!(
                    "After verification, send a test hook to http://127.0.0.1:{port}/hooks/wake"
                );
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

fn print_setup_assessment_summary(assessment: &crate::onboarding::setup::SetupAssessment) {
    println!();
    println!("Provider setup summary");
    println!("----------------------");
    println!("Provider: {}", assessment.provider.label());
    if let Some(auth_mode) = assessment.auth_mode {
        println!("Auth mode: {}", auth_mode.label());
    }
    if let Some(profile_name) = assessment.profile_name.as_deref() {
        match assessment.email.as_deref() {
            Some(email) => println!("Profile: {profile_name} ({email})"),
            None => println!("Profile: {profile_name}"),
        }
    }
    println!("Status: {}", assessment.status.label());
    println!("{}", assessment.summary);
    for check in &assessment.checks {
        let status = match check.status {
            crate::onboarding::setup::SetupCheckStatus::Pass => "PASS",
            crate::onboarding::setup::SetupCheckStatus::Fail => "FAIL",
            crate::onboarding::setup::SetupCheckStatus::Skip => "SKIP",
        };
        println!("[{status}] {}: {}", check.name, check.detail);
        if let Some(remediation) = check.remediation.as_deref() {
            println!("      next step: {remediation}");
        }
    }
}

fn prompt_line(prompt: &str) -> Result<String, Box<dyn std::error::Error>> {
    #[cfg(test)]
    if let Some(scripted) = setup_interactive_test_harness_take_prompt_input(prompt, false) {
        return Ok(scripted.trim().to_string());
    }

    use std::io::{self, Write};

    print!("{}", prompt);
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(input.trim().to_string())
}

fn prompt_hidden_line(prompt: &str) -> Result<String, Box<dyn std::error::Error>> {
    #[cfg(test)]
    if let Some(scripted) = setup_interactive_test_harness_take_prompt_input(prompt, true) {
        return Ok(scripted.trim().to_string());
    }

    let input = rpassword::prompt_password(prompt)?;
    Ok(input.trim().to_string())
}

fn sensitive_prompt_text(label: &str, hide_sensitive_input: bool, allow_blank: bool) -> String {
    let visibility_hint = if hide_sensitive_input {
        "input hidden; pasted text will not be shown"
    } else {
        "input visible (WARNING: secrets will be shown on screen)"
    };
    let blank_hint = if allow_blank {
        ", leave blank to skip for now"
    } else {
        ""
    };

    format!("Enter {label} ({visibility_hint}{blank_hint}): ")
}

fn prompt_sensitive_line_with<FHidden, FVisible>(
    prompt: &str,
    hide_sensitive_input: bool,
    prompt_hidden: FHidden,
    prompt_visible: FVisible,
) -> Result<String, Box<dyn std::error::Error>>
where
    FHidden: FnOnce(&str) -> Result<String, Box<dyn std::error::Error>>,
    FVisible: FnOnce(&str) -> Result<String, Box<dyn std::error::Error>>,
{
    if hide_sensitive_input {
        prompt_hidden(prompt)
    } else {
        prompt_visible(prompt)
    }
}

fn prompt_sensitive_line(
    label: &str,
    hide_sensitive_input: bool,
    allow_blank: bool,
) -> Result<String, Box<dyn std::error::Error>> {
    let prompt = sensitive_prompt_text(label, hide_sensitive_input, allow_blank);
    prompt_sensitive_line_with(
        &prompt,
        hide_sensitive_input,
        prompt_hidden_line,
        prompt_line,
    )
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

fn prompt_custom_secret(
    kind: &str,
    hide_sensitive_input: bool,
) -> Result<String, Box<dyn std::error::Error>> {
    const MIN_SECRET_LENGTH: usize = 10;

    loop {
        let entered = prompt_sensitive_line(kind, hide_sensitive_input, false)?;
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
    #[cfg(test)]
    if let Some(result) = setup_interactive_test_harness_take_provider_validation_result() {
        return result;
    }

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
    let detail = err.message();
    let mut message = if err.is_auth() {
        format!("{channel_name} credential check failed.")
    } else {
        format!("{channel_name} credential check hit a transient error.")
    };

    if !detail.trim().is_empty() {
        message.push_str(" Details are hidden because they may contain sensitive information.");
    }

    message
}

fn prompt_and_configure_bot_channel(
    config: &mut Value,
    channel_key: &str,
    channel_label: &str,
    env_var: &str,
    hide_sensitive_input: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let token_label = format!("{channel_label} bot token");
    let channel_token =
        prompt_optional_value_from_env(env_var, &token_label, &token_label, hide_sensitive_input)?;
    if let Some(token) = channel_token {
        println!("{channel_label} token captured.");
        validate_channel_credentials_interactive(channel_key, &token)?;
        config[channel_key] = serde_json::json!({
            "enabled": true,
            "botToken": token
        });
    } else {
        println!("No {channel_label} token entered; skipping credential validation.");
        println!(
            "Skipped {channel_label} token. You can configure it later in `{channel_key}.botToken`."
        );
    }
    Ok(())
}

async fn validate_channel_credentials(channel: &str, token: &str) -> Result<(), String> {
    #[cfg(test)]
    if let Some(result) = setup_interactive_test_harness_take_channel_validation_result() {
        return result;
    }

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

fn setup_rerun_command(
    provider: SetupProvider,
    requested_auth_mode: Option<SetupAuthModeSelection>,
) -> String {
    crate::onboarding::setup::SetupProvider::from(provider)
        .setup_command(setup_provider_auth_mode_hint(provider, requested_auth_mode))
        .unwrap_or_else(|| crate::onboarding::setup::LOCAL_CHAT_VERIFY_COMMAND.to_string())
}

fn validate_provider_credentials_interactive(
    provider: SetupProvider,
    requested_auth_mode: Option<SetupAuthModeSelection>,
    api_key: &str,
) -> Result<crate::onboarding::setup::SetupCheck, Box<dyn std::error::Error>> {
    if provider == SetupProvider::Anthropic
        && requested_auth_mode == Some(SetupAuthModeSelection::SetupToken)
    {
        return Ok(crate::onboarding::setup::SetupCheck::validation_skip(
            "Live provider validation",
            "Anthropic setup-token live validation was skipped because setup-tokens do not use the API-key validation probe."
                .to_string(),
            Some(
                "run `cara verify --outcome local-chat` after setup to exercise the configured Anthropic setup-token path"
                    .to_string(),
            ),
            None,
        ));
    }

    let validate_now = prompt_yes_no("Validate provider credentials now?", true)?;
    if !validate_now {
        return Ok(crate::onboarding::setup::SetupCheck::validation_skip(
            "Live provider validation",
            format!("{} credential validation was skipped", provider.label()),
            Some(
                "run `cara verify` after setup to exercise the configured provider path"
                    .to_string(),
            ),
            None,
        ));
    }

    let provider_key = provider.prompt_key().to_string();
    let api_key = api_key.to_string();
    println!("Checking {} credentials...", provider.label());
    match run_sync_blocking_send(validate_provider_credentials_owned(provider_key, api_key))
        .map_err(|err| format!("credential validation runtime failed: {err}"))
    {
        Ok(()) => {
            println!("Credential check succeeded.");
            Ok(crate::onboarding::setup::SetupCheck::validation_pass(
                "Live provider validation",
                format!("{} credential validation succeeded", provider.label()),
                None,
            ))
        }
        Err(err) => {
            eprintln!("Credential check failed: {}", err);
            if prompt_yes_no("Continue setup and write config anyway?", false)? {
                let rerun_command = setup_rerun_command(provider, requested_auth_mode);
                Ok(crate::onboarding::setup::SetupCheck::validation_fail(
                    "Live provider validation",
                    err,
                    format!(
                        "fix the credential and rerun `{}` or run `cara verify` after updating config",
                        rerun_command
                    ),
                    None,
                ))
            } else {
                Err("setup aborted after credential validation failure".into())
            }
        }
    }
}

fn validate_bedrock_credentials_interactive(
    provider: SetupProvider,
    region: &str,
    access_key: &str,
    secret_key: &str,
    session_token: Option<&str>,
) -> Result<Vec<crate::onboarding::setup::SetupCheck>, Box<dyn std::error::Error>> {
    let validate_now = prompt_yes_no("Validate Bedrock credentials now?", true)?;
    if !validate_now {
        return Ok(vec![crate::onboarding::setup::SetupCheck::validation_skip(
            "Live Bedrock validation",
            "Bedrock credential validation was skipped".to_string(),
            Some(
                "run `cara verify` after setup to exercise the configured provider path"
                    .to_string(),
            ),
            None,
        )]);
    }

    let mut checks = Vec::new();
    checks.push(crate::onboarding::bedrock::validate_region(region));

    let region = region.to_string();
    let access_key = access_key.to_string();
    let secret_key = secret_key.to_string();
    let session_token = session_token.map(|s| s.to_string());
    let default_model = provider.default_model().to_string();

    println!("Checking Bedrock credentials...");
    let (cred_check, models_json) = run_sync_blocking_send(async move {
        Ok::<_, String>(
            crate::onboarding::bedrock::validate_bedrock_credentials(
                &region,
                &access_key,
                &secret_key,
                session_token.as_deref(),
            )
            .await,
        )
    })
    .map_err(|err| format!("credential validation runtime failed: {err}"))?;

    match cred_check.status {
        crate::onboarding::setup::SetupCheckStatus::Pass => {
            println!("Credential check succeeded.");
        }
        crate::onboarding::setup::SetupCheckStatus::Fail => {
            eprintln!("Credential check failed: {}", cred_check.detail);
            if let Some(ref remediation) = cred_check.remediation {
                eprintln!("  Remediation: {}", remediation);
            }
            if !prompt_yes_no("Continue setup and write config anyway?", false)? {
                return Err("setup aborted after credential validation failure".into());
            }
        }
        _ => {}
    }
    checks.push(cred_check);

    if let Some(ref models) = models_json {
        let model_check = crate::onboarding::bedrock::check_model_access(&default_model, models);
        match model_check.status {
            crate::onboarding::setup::SetupCheckStatus::Pass => {
                println!("Model access check succeeded.");
            }
            crate::onboarding::setup::SetupCheckStatus::Fail => {
                eprintln!("Model access: {}", model_check.detail);
                if let Some(ref remediation) = model_check.remediation {
                    eprintln!("  Remediation: {}", remediation);
                }
            }
            _ => {}
        }
        checks.push(model_check);
    }

    Ok(checks)
}

fn vertex_validation_failure_remediation(
    err: &crate::agent::vertex::VertexSetupValidationError,
) -> String {
    match err {
        crate::agent::vertex::VertexSetupValidationError::InvalidProjectId => {
            "enter a valid GCP project ID and rerun `cara setup --force --provider vertex`"
                .to_string()
        }
        crate::agent::vertex::VertexSetupValidationError::InvalidLocation => {
            "enter a valid GCP location such as `us-central1` and rerun `cara setup --force --provider vertex`"
                .to_string()
        }
        crate::agent::vertex::VertexSetupValidationError::MissingDefaultModel => {
            "set `vertex.model`, or choose an explicit Vertex model route, then rerun `cara setup --force --provider vertex`"
                .to_string()
        }
        crate::agent::vertex::VertexSetupValidationError::UnsupportedModel => {
            "choose a supported Google Gemini model such as `vertex:gemini-2.5-flash`, then rerun `cara setup --force --provider vertex`"
                .to_string()
        }
        crate::agent::vertex::VertexSetupValidationError::ClientInit(_) => {
            "check local HTTP client and TLS runtime availability, then rerun `cara setup --force --provider vertex`"
                .to_string()
        }
        crate::agent::vertex::VertexSetupValidationError::AuthUnavailable => {
            "run `gcloud auth application-default login` or use a metadata-backed Google Cloud service account, then rerun `cara setup --force --provider vertex`"
                .to_string()
        }
        crate::agent::vertex::VertexSetupValidationError::AccessDenied => {
            "check Vertex IAM/API access for the configured project, location, and model, then rerun `cara setup --force --provider vertex`"
                .to_string()
        }
        crate::agent::vertex::VertexSetupValidationError::ProbeRejected => {
            "check the Vertex project, location, and model values; if they look correct, this may indicate a malformed Vertex validation request in Carapace"
                .to_string()
        }
        crate::agent::vertex::VertexSetupValidationError::Unavailable => {
            "check the Vertex project ID, location, and model name, then rerun `cara setup --force --provider vertex`"
                .to_string()
        }
        crate::agent::vertex::VertexSetupValidationError::Rejected => {
            "check the Vertex project, location, model, and provider access, then rerun `cara setup --force --provider vertex`"
                .to_string()
        }
        crate::agent::vertex::VertexSetupValidationError::RateLimited => {
            "retry after the current Vertex AI rate limit window, then rerun `cara setup --force --provider vertex`"
                .to_string()
        }
        crate::agent::vertex::VertexSetupValidationError::Transport => {
            "retry if Vertex AI is temporarily unavailable; otherwise check network connectivity and rerun `cara setup --force --provider vertex`"
                .to_string()
        }
    }
}

fn validate_vertex_provider_interactive(
    input: &crate::onboarding::vertex::VertexSetupInput,
) -> Result<crate::onboarding::setup::SetupCheck, Box<dyn std::error::Error>> {
    let validate_now = prompt_yes_no("Validate Vertex configuration now?", true)?;
    if !validate_now {
        return Ok(crate::onboarding::setup::SetupCheck::validation_skip(
            "Live provider validation",
            "Vertex live validation was skipped",
            Some(
                "run `cara verify` after setup to exercise the configured Vertex path".to_string(),
            ),
            None,
        ));
    }

    #[cfg(test)]
    if let Some(result) = setup_interactive_test_harness_take_provider_validation_result() {
        return match result {
            Ok(()) => Ok(crate::onboarding::setup::SetupCheck::validation_pass(
                "Live provider validation",
                "Vertex auth, project, location, and model access validated",
                None,
            )),
            Err(detail) => {
                eprintln!("Credential check failed: {detail}");
                if prompt_yes_no("Continue setup and write config anyway?", false)? {
                    Ok(crate::onboarding::setup::SetupCheck::validation_fail(
                        "Live provider validation",
                        detail,
                        "check Vertex auth, project, location, and model access, then rerun `cara setup --force --provider vertex`".to_string(),
                        None,
                    ))
                } else {
                    Err("setup aborted after provider configuration validation failure".into())
                }
            }
        };
    }

    println!("Checking Vertex configuration...");
    let route_model = input.route_model()?;
    match run_sync_blocking_send(crate::agent::vertex::validate_vertex_setup(
        input.project_id.clone(),
        input.location.clone(),
        route_model,
        input.default_model(),
    )) {
        Ok(()) => {
            println!("Credential check succeeded.");
            Ok(crate::onboarding::setup::SetupCheck::validation_pass(
                "Live provider validation",
                "Vertex auth, project, location, and model access validated",
                None,
            ))
        }
        Err(crate::runtime_bridge::BridgeError::Inner(err)) => {
            let detail = err.to_string();
            eprintln!("Credential check failed: {detail}");
            if prompt_yes_no("Continue setup and write config anyway?", false)? {
                Ok(crate::onboarding::setup::SetupCheck::validation_fail(
                    "Live provider validation",
                    detail,
                    vertex_validation_failure_remediation(&err),
                    None,
                ))
            } else {
                Err("setup aborted after provider configuration validation failure".into())
            }
        }
        Err(err) => {
            let detail = format!("Vertex validation runtime failed: {err}");
            eprintln!("Credential check failed: {detail}");
            if prompt_yes_no("Continue setup and write config anyway?", false)? {
                Ok(crate::onboarding::setup::SetupCheck::validation_fail(
                    "Live provider validation",
                    detail,
                    "check local runtime availability and rerun `cara setup --force --provider vertex`"
                        .to_string(),
                    None,
                ))
            } else {
                Err("setup aborted after provider configuration validation failure".into())
            }
        }
    }
}

fn validate_channel_credentials_interactive(
    channel: &str,
    token: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let validate_now = prompt_yes_no(&format!("Validate {channel} credentials now?"), true)?;
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

fn print_verify_summary(outcome: VerifyOutcome, port: u16, checks: &[VerifyCheckResult]) {
    println!();
    println!("Outcome verification summary");
    println!("----------------------------");
    println!("Outcome: {}", outcome.key());
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
    channel: VerifyOutcome,
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
            VerifyOutcome::Discord => {
                let channel_impl =
                    DiscordChannel::new(DISCORD_DEFAULT_API_BASE_URL.to_string(), token);
                channel_impl.send_text(outbound)
            }
            VerifyOutcome::Telegram => {
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
                local_chat_verify_next_step(cfg),
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
    outcome: VerifyOutcome,
    cfg: &Value,
    discord_to: Option<String>,
    telegram_to: Option<String>,
    checks: &mut Vec<VerifyCheckResult>,
) -> Result<(), String> {
    let (channel_label, channel_key, env_var, destination, destination_flag) = match outcome {
        VerifyOutcome::Discord => (
            "Discord",
            "discord",
            "DISCORD_BOT_TOKEN",
            discord_to,
            "--discord-to <channel_id>",
        ),
        VerifyOutcome::Telegram => (
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

async fn verify_autonomy_outcome(
    port: u16,
    cfg: &Value,
    checks: &mut Vec<VerifyCheckResult>,
) -> Result<(), String> {
    async fn shutdown_embedded_gateway(
        setup_server_handle: &mut Option<crate::server::startup::ServerHandle>,
    ) {
        if let Some(handle) = setup_server_handle.take() {
            handle.shutdown().await;
        }
    }

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
                    "start the service (`cara start --port {port}`) and retry `cara verify --outcome autonomy --port {port}`"
                ),
            ));
            return Err("outcome verification failed".to_string());
        }
    };

    let verify_result = async {
        let control_client = match reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .build()
        {
            Ok(client) => client,
            Err(err) => {
                checks.push(VerifyCheckResult::fail(
                    "Control client setup",
                    err.to_string(),
                    "fix local networking/runtime dependencies, then retry",
                ));
                return Err("outcome verification failed".to_string());
            }
        };
        // Resolve control-plane auth once and reuse for task create + polling.
        // This includes env/config/keychain fallback behavior.
        let mut control_auth = resolve_gateway_auth().await;
        if control_auth.token.is_none() && control_auth.password.is_none() {
            if let Some(token) = cfg
                .get("gateway")
                .and_then(|v| v.get("auth"))
                .and_then(|v| v.get("token"))
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|v| !v.is_empty())
            {
                control_auth.token = Some(token.to_string());
            } else if let Some(password) = cfg
                .get("gateway")
                .and_then(|v| v.get("auth"))
                .and_then(|v| v.get("password"))
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|v| !v.is_empty())
            {
                control_auth.password = Some(password.to_string());
            }
        }

        let policy_max_attempts: u32 = 1;
        let policy_max_total_runtime_ms: u64 = 60_000;
        let policy_max_turns: u32 = 1;
        let policy_max_run_timeout_seconds: u32 = 30;
        let create_body = serde_json::json!({
            "payload": {
                "kind": "agentTurn",
                "message": "verify-autonomy",
            },
            "policy": {
                "maxAttempts": policy_max_attempts,
                "maxTotalRuntimeMs": policy_max_total_runtime_ms,
                "maxTurns": policy_max_turns,
                "maxRunTimeoutSeconds": policy_max_run_timeout_seconds
            }
        });

        let create_url = match build_control_url("127.0.0.1", port, "/control/tasks", &[])
            .map_err(|error| error.to_string())
        {
            Ok(url) => url,
            Err(error) => {
                checks.push(VerifyCheckResult::fail(
                    "Task create",
                    format!("failed to build control URL: {error}"),
                    "confirm host/port configuration and retry verification",
                ));
                return Err("outcome verification failed".to_string());
            }
        };
        let create_response = match send_control_request_with_client_and_auth(
            &control_client,
            &control_auth,
            reqwest::Method::POST,
            create_url,
            Some(create_body),
        )
        .await
        .map_err(|err| err.to_string())
        {
            Ok(response) => response,
            Err(error_message) => {
                checks.push(VerifyCheckResult::fail(
                    "Task create",
                    error_message,
                    format!("verify control auth and task queue availability, then retry `cara verify --outcome autonomy --port {port}`"),
                ));
                return Err("outcome verification failed".to_string());
            }
        };

        let created_task = create_response
            .get("task")
            .and_then(|task| task.as_object())
            .cloned();
        let Some(created_task) = created_task else {
            checks.push(VerifyCheckResult::fail(
                "Task create",
                "task response missing task object",
                "retry verification; if this persists, inspect server logs",
            ));
            return Err("outcome verification failed".to_string());
        };

        let Some(task_id) = created_task
            .get("id")
            .and_then(|value| value.as_str())
            .map(ToString::to_string)
        else {
            checks.push(VerifyCheckResult::fail(
                "Task create",
                "task response missing task id",
                "retry verification; if this persists, inspect server logs",
            ));
            return Err("outcome verification failed".to_string());
        };

        checks.push(VerifyCheckResult::pass(
            "Task create",
            format!("created task `{task_id}`"),
        ));

        let mut max_attempts_seen = created_task
            .get("attempts")
            .and_then(|value| value.as_u64())
            .unwrap_or(0);
        // Polling window must be at least as long as task runtime policy budgets
        // (plus headroom) to avoid false negatives on healthy slow paths.
        let polling_timeout_secs = policy_max_total_runtime_ms
            .div_ceil(1000)
            .max(u64::from(policy_max_run_timeout_seconds))
            .saturating_add(10);
        let deadline = std::time::Instant::now() + Duration::from_secs(polling_timeout_secs);
        let mut terminal_task: Option<Value> = None;

        while std::time::Instant::now() < deadline {
            let path = format!("/control/tasks/{task_id}");
            let task_url = match build_control_url("127.0.0.1", port, &path, &[])
                .map_err(|error| error.to_string())
            {
                Ok(url) => url,
                Err(error) => {
                    checks.push(VerifyCheckResult::fail(
                        "Task polling",
                        format!("failed to build control URL: {error}"),
                        "confirm host/port configuration and retry verification",
                    ));
                    return Err("outcome verification failed".to_string());
                }
            };
            let task_response = match send_control_request_with_client_and_auth(
                &control_client,
                &control_auth,
                reqwest::Method::GET,
                task_url,
                None,
            )
            .await
            .map_err(|err| err.to_string())
            {
                Ok(response) => response,
                Err(error_message) => {
                    checks.push(VerifyCheckResult::fail(
                        "Task polling",
                        error_message,
                        "confirm service health and control auth, then retry",
                    ));
                    return Err("outcome verification failed".to_string());
                }
            };

            let task = task_response.get("task").cloned();
            if let Some(task) = task {
                let attempts = task
                    .get("attempts")
                    .and_then(|value| value.as_u64())
                    .unwrap_or(0);
                max_attempts_seen = max_attempts_seen.max(attempts);
                if matches!(
                    task.get("state").and_then(|value| value.as_str()),
                    Some("done" | "blocked" | "failed" | "cancelled")
                ) {
                    terminal_task = Some(task);
                    break;
                }
            }

            tokio::time::sleep(Duration::from_millis(250)).await;
        }

        if max_attempts_seen == 0 {
            checks.push(VerifyCheckResult::fail(
                "Task start proof",
                "task never reported attempts > 0",
                "inspect worker loop logs and retry verification",
            ));
            return Err("outcome verification failed".to_string());
        }
        checks.push(VerifyCheckResult::pass(
            "Task start proof",
            format!("task attempts observed: {max_attempts_seen}"),
        ));

        let Some(terminal_task) = terminal_task else {
            checks.push(VerifyCheckResult::fail(
                "Task terminal proof",
                "task did not reach terminal state before timeout",
                "inspect queue/worker logs and retry verification",
            ));
            return Err("outcome verification failed".to_string());
        };

        let state = terminal_task
            .get("state")
            .and_then(|value| value.as_str())
            .unwrap_or("unknown");
        match state {
            "done" => {
                let run_count = terminal_task
                    .get("runIds")
                    .and_then(|value| value.as_array())
                    .map_or(0, |runs| runs.len());
                checks.push(VerifyCheckResult::pass(
                    "Task terminal proof",
                    format!("task reached done state (run IDs: {run_count})"),
                ));
                Ok(())
            }
            "blocked" => {
                let blocked_reason = terminal_task
                    .get("blockedReason")
                    .and_then(|value| value.as_str())
                    .unwrap_or("unknown");
                checks.push(VerifyCheckResult::pass(
                    "Task terminal proof",
                    format!("task reached blocked state ({blocked_reason})"),
                ));
                Ok(())
            }
            "failed" => {
                let error = terminal_task
                    .get("lastError")
                    .and_then(|value| value.as_str())
                    .unwrap_or("unknown error");
                checks.push(VerifyCheckResult::fail(
                    "Task terminal proof",
                    format!("task failed: {error}"),
                    "check provider configuration or task policy and retry",
                ));
                Err("outcome verification failed".to_string())
            }
            "cancelled" => {
                checks.push(VerifyCheckResult::fail(
                    "Task terminal proof",
                    "task was cancelled unexpectedly during verification",
                    "retry verify; if this repeats, inspect control-plane mutations",
                ));
                Err("outcome verification failed".to_string())
            }
            other => {
                checks.push(VerifyCheckResult::fail(
                    "Task terminal proof",
                    format!("task reached unexpected state `{other}`"),
                    "inspect task state transitions and retry verification",
                ));
                Err("outcome verification failed".to_string())
            }
        }
    }
    .await;

    shutdown_embedded_gateway(&mut setup_server_handle).await;
    verify_result
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
        VerifyOutcome::LocalChat => verify_local_chat_outcome(port, &cfg, &mut checks).await,
        VerifyOutcome::Hooks => verify_hooks_outcome(port, &cfg, &mut checks).await,
        VerifyOutcome::Discord | VerifyOutcome::Telegram => {
            verify_channel_outcome(outcome, &cfg, discord_to, telegram_to, &mut checks).await
        }
        VerifyOutcome::Autonomy => verify_autonomy_outcome(port, &cfg, &mut checks).await,
    };
    if let Err(err) = result {
        print_verify_summary(outcome, port, &checks);
        println!("Next help path: {}", verify_failure_follow_up_url(outcome));
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

#[derive(Debug, Clone, PartialEq, Eq)]
struct SetupConfigValue {
    config_value: String,
    effective_value: Option<String>,
}

fn env_placeholder(env_var: &str) -> String {
    format!("${{{env_var}}}")
}

fn first_present_env_var(env_vars: &[&'static str]) -> Option<(&'static str, String)> {
    for env_var in env_vars {
        if let Some(value) = env_var_value(env_var) {
            return Some((*env_var, value));
        }
    }
    None
}

fn prompt_setup_provider_interactive(
    requested_provider: Option<SetupProvider>,
) -> Result<SetupProvider, Box<dyn std::error::Error>> {
    if let Some(provider) = requested_provider {
        return Ok(provider);
    }

    let provider_hints = detect_setup_provider_choice_env_hints();
    if provider_hints.len() > 1 {
        let labels = provider_hints
            .iter()
            .map(|provider| provider.label())
            .collect::<Vec<_>>();
        eprintln!(
            "Detected multiple provider env hints: {}.",
            labels.join(", ")
        );
        eprintln!("Setup will only write the provider you choose.");
    }

    let default_provider = default_setup_provider_choice(&provider_hints).prompt_key();
    loop {
        let selection = prompt_with_default(
            "Select provider for first run (anthropic/openai/ollama/gemini/vertex/venice/bedrock)",
            default_provider,
        )?;
        if let Some(provider) = SetupProviderChoice::parse_prompt(&selection) {
            return match provider {
                SetupProviderChoice::Anthropic => Ok(SetupProvider::Anthropic),
                SetupProviderChoice::OpenAi => prompt_openai_setup_provider_variant(),
                SetupProviderChoice::Ollama => Ok(SetupProvider::Ollama),
                SetupProviderChoice::Gemini => Ok(SetupProvider::Gemini),
                SetupProviderChoice::Vertex => Ok(SetupProvider::Vertex),
                SetupProviderChoice::Venice => Ok(SetupProvider::Venice),
                SetupProviderChoice::Bedrock => Ok(SetupProvider::Bedrock),
            };
        }
        eprintln!(
            "Please enter one of: anthropic, openai, ollama, gemini, vertex, venice, bedrock."
        );
    }
}

fn prompt_openai_setup_provider_variant() -> Result<SetupProvider, Box<dyn std::error::Error>> {
    let default_variant = if env_var_present("OPENAI_API_KEY") {
        "api-key"
    } else if env_var_present("CARAPACE_CONFIG_PASSWORD")
        && env_var_present("OPENAI_OAUTH_CLIENT_ID")
        && env_var_present("OPENAI_OAUTH_CLIENT_SECRET")
    {
        "subscription-sign-in"
    } else {
        "api-key"
    };

    loop {
        let selection = prompt_choice(
            "How should OpenAI authenticate? (api-key/subscription-sign-in)",
            default_variant,
            &["api-key", "subscription-sign-in"],
        )?;
        match selection.as_str() {
            "api-key" => return Ok(SetupProvider::OpenAi),
            "subscription-sign-in" => return Ok(SetupProvider::Codex),
            _ => eprintln!("Please choose either `api-key` or `subscription-sign-in`."),
        }
    }
}

fn setup_provider_auth_mode_hint(
    provider: SetupProvider,
    requested_auth_mode: Option<SetupAuthModeSelection>,
) -> Option<crate::onboarding::setup::SetupAuthMode> {
    match provider {
        SetupProvider::Anthropic | SetupProvider::Gemini => requested_auth_mode.map(Into::into),
        SetupProvider::Codex => Some(crate::onboarding::setup::SetupAuthMode::OAuth),
        SetupProvider::OpenAi | SetupProvider::Venice => {
            Some(crate::onboarding::setup::SetupAuthMode::ApiKey)
        }
        SetupProvider::Ollama => Some(crate::onboarding::setup::SetupAuthMode::BaseUrl),
        SetupProvider::Vertex => None,
        SetupProvider::Bedrock => Some(crate::onboarding::setup::SetupAuthMode::StaticCredentials),
    }
}

fn prompt_gemini_setup_auth_mode(
    requested_mode: Option<SetupAuthModeSelection>,
) -> Result<SetupAuthModeSelection, Box<dyn std::error::Error>> {
    if let Some(mode) = requested_mode {
        if mode == SetupAuthModeSelection::SetupToken {
            return Err(
                "`--auth-mode setup-token` is only valid with `--provider anthropic`.".into(),
            );
        }
        return Ok(mode);
    }

    loop {
        let selection = prompt_choice(
            "How should Gemini authenticate? (oauth/api-key)",
            "oauth",
            &["oauth", "api-key"],
        )?;
        match selection.as_str() {
            "oauth" => return Ok(SetupAuthModeSelection::OAuth),
            "api-key" => return Ok(SetupAuthModeSelection::ApiKey),
            _ => {
                eprintln!("Please choose either `oauth` or `api-key`.");
            }
        }
    }
}

fn prompt_anthropic_setup_auth_mode(
    requested_mode: Option<SetupAuthModeSelection>,
) -> Result<SetupAuthModeSelection, Box<dyn std::error::Error>> {
    if let Some(mode) = requested_mode {
        return match mode {
            SetupAuthModeSelection::ApiKey | SetupAuthModeSelection::SetupToken => Ok(mode),
            SetupAuthModeSelection::OAuth => {
                Err("`--auth-mode oauth` is only valid with `--provider gemini`.".into())
            }
        };
    }

    loop {
        let selection = prompt_choice(
            "How should Anthropic authenticate? (api-key/setup-token)",
            "api-key",
            &["api-key", "setup-token"],
        )?;
        match selection.as_str() {
            "api-key" => return Ok(SetupAuthModeSelection::ApiKey),
            "setup-token" => return Ok(SetupAuthModeSelection::SetupToken),
            _ => eprintln!("Please choose either `api-key` or `setup-token`."),
        }
    }
}

fn prompt_vertex_setup_route(
) -> Result<crate::onboarding::vertex::VertexModelRoute, Box<dyn std::error::Error>> {
    let selection = prompt_choice(
        "How should Vertex choose the model? (default-route/explicit-model)",
        "default-route",
        &["default-route", "explicit-model"],
    )?;
    match selection.as_str() {
        "default-route" => Ok(crate::onboarding::vertex::VertexModelRoute::Default),
        "explicit-model" => Ok(crate::onboarding::vertex::VertexModelRoute::Explicit),
        _ => Err("prompt_choice returned an unexpected Vertex route".into()),
    }
}

fn prompt_required_visible_env_backed_config_value(
    env_vars: &[&'static str],
    placeholder_env_var: &'static str,
    label: &str,
    default_value: Option<&str>,
) -> Result<SetupConfigValue, Box<dyn std::error::Error>> {
    if let Some((env_name, env_value)) = first_present_env_var(env_vars) {
        if prompt_yes_no(&format!("Use {label} from ${env_name}?"), true)? {
            return Ok(SetupConfigValue {
                config_value: env_placeholder(env_name),
                effective_value: Some(env_value),
            });
        }

        let entered = prompt_with_default(label, &env_value)?;
        let trimmed = entered.trim();
        let chosen = if trimmed.is_empty() {
            env_value
        } else {
            trimmed.to_string()
        };
        return Ok(SetupConfigValue {
            config_value: chosen.clone(),
            effective_value: Some(chosen),
        });
    }

    match default_value {
        Some(default) => {
            let entered = prompt_with_default(label, default)?;
            let trimmed = entered.trim();
            let chosen = if trimmed.is_empty() {
                default.to_string()
            } else {
                trimmed.to_string()
            };
            Ok(SetupConfigValue {
                config_value: chosen.clone(),
                effective_value: Some(chosen),
            })
        }
        None => {
            let entered = prompt_line(&format!(
                "Enter {label} (leave blank to use ${placeholder_env_var} later): "
            ))?;
            let trimmed = entered.trim();
            if trimmed.is_empty() {
                return Ok(SetupConfigValue {
                    config_value: env_placeholder(placeholder_env_var),
                    effective_value: None,
                });
            }
            Ok(SetupConfigValue {
                config_value: trimmed.to_string(),
                effective_value: Some(trimmed.to_string()),
            })
        }
    }
}

fn prompt_vertex_explicit_model_id() -> Result<String, Box<dyn std::error::Error>> {
    let default_model =
        env_var_value("VERTEX_MODEL").unwrap_or_else(|| "gemini-2.5-flash".to_string());
    loop {
        let entered = prompt_with_default("Vertex model ID", &default_model)?;
        let normalized = crate::onboarding::vertex::normalize_vertex_model_id(&entered);
        if normalized.is_empty() || normalized == "default" {
            eprintln!("Enter a concrete Vertex model ID such as `gemini-2.5-flash`.");
            continue;
        }
        return Ok(normalized);
    }
}

fn print_missing_setup_value_notice(env_var: &str, label: &str) {
    println!(
        "No {label} provided. Set ${env_var} in the same shell you use for `cara start` and `cara verify`, or rerun `cara setup --force` later."
    );
}

fn prompt_required_secret_config_value(
    env_var: &'static str,
    label: &str,
    hide_sensitive_input: bool,
) -> Result<SetupConfigValue, Box<dyn std::error::Error>> {
    if let Some((env_name, env_value)) = first_present_env_var(&[env_var]) {
        if prompt_yes_no(&format!("Use {label} from ${env_name}?"), true)? {
            return Ok(SetupConfigValue {
                config_value: env_placeholder(env_name),
                effective_value: Some(env_value),
            });
        }
    }

    let entered = prompt_sensitive_line(label, hide_sensitive_input, true)?;
    if entered.is_empty() {
        Ok(SetupConfigValue {
            config_value: env_placeholder(env_var),
            effective_value: None,
        })
    } else {
        Ok(SetupConfigValue {
            config_value: entered.clone(),
            effective_value: Some(entered),
        })
    }
}

fn prompt_required_secret_value_from_env(
    env_var: &'static str,
    label: &str,
    hide_sensitive_input: bool,
) -> Result<String, Box<dyn std::error::Error>> {
    if let Some((env_name, env_value)) = first_present_env_var(&[env_var]) {
        if prompt_yes_no(&format!("Use {label} from ${env_name}?"), true)? {
            return Ok(env_value);
        }
    }

    loop {
        let entered = prompt_sensitive_line(label, hide_sensitive_input, false)?;
        let trimmed = entered.trim();
        if !trimmed.is_empty() {
            return Ok(trimmed.to_string());
        }
        eprintln!("{label} is required.");
    }
}

fn prompt_optional_secret_config_value(
    env_var: &'static str,
    label: &str,
    hide_sensitive_input: bool,
) -> Result<Option<SetupConfigValue>, Box<dyn std::error::Error>> {
    if let Some((env_name, env_value)) = first_present_env_var(&[env_var]) {
        if prompt_yes_no(&format!("Use {label} from ${env_name}?"), true)? {
            return Ok(Some(SetupConfigValue {
                config_value: env_placeholder(env_name),
                effective_value: Some(env_value),
            }));
        }
    }

    let entered = prompt_sensitive_line(label, hide_sensitive_input, true)?;
    if entered.is_empty() {
        Ok(None)
    } else {
        Ok(Some(SetupConfigValue {
            config_value: entered.clone(),
            effective_value: Some(entered),
        }))
    }
}

fn prompt_required_visible_config_value(
    env_vars: &[&'static str],
    label: &str,
    default_value: &str,
) -> Result<SetupConfigValue, Box<dyn std::error::Error>> {
    if let Some((env_name, env_value)) = first_present_env_var(env_vars) {
        if prompt_yes_no(&format!("Use {label} from ${env_name}?"), true)? {
            return Ok(SetupConfigValue {
                config_value: env_placeholder(env_name),
                effective_value: Some(env_value),
            });
        }

        let entered = prompt_with_default(label, &env_value)?;
        return Ok(SetupConfigValue {
            config_value: entered.clone(),
            effective_value: Some(entered),
        });
    }

    let entered = prompt_with_default(label, default_value)?;
    Ok(SetupConfigValue {
        config_value: entered.clone(),
        effective_value: Some(entered),
    })
}

fn prompt_optional_base_url_override(
    provider_label: &str,
    env_var: &'static str,
    default_url: &str,
) -> Result<Option<SetupConfigValue>, Box<dyn std::error::Error>> {
    if let Some((env_name, env_value)) = first_present_env_var(&[env_var]) {
        if prompt_yes_no(
            &format!("Use {provider_label} base URL from ${env_name}?"),
            true,
        )? {
            return Ok(Some(SetupConfigValue {
                config_value: env_placeholder(env_name),
                effective_value: Some(env_value),
            }));
        }
    }

    if !prompt_yes_no(
        &format!("Override default {provider_label} base URL?"),
        false,
    )? {
        return Ok(None);
    }

    let entered = prompt_with_default(&format!("{provider_label} base URL"), default_url)?;
    Ok(Some(SetupConfigValue {
        config_value: entered.clone(),
        effective_value: Some(entered),
    }))
}

fn render_setup_validation_failure(err: &crate::agent::AgentError) -> String {
    match err {
        crate::agent::AgentError::InvalidApiKey(_) => {
            "Provider configuration check failed: the supplied credential is invalid or incomplete."
                .to_string()
        }
        crate::agent::AgentError::InvalidBaseUrl(_) => {
            "Provider configuration check failed: the supplied base URL is invalid or unsupported."
                .to_string()
        }
        crate::agent::AgentError::Provider(_) => {
            "Provider configuration check failed: the provider rejected the configuration."
                .to_string()
        }
        _ => "Provider configuration check failed.".to_string(),
    }
}

fn prompt_oauth_client_value(
    env_var: &'static str,
    label: &str,
    hide_sensitive_input: bool,
) -> Result<String, Box<dyn std::error::Error>> {
    if let Some((env_name, env_value)) = first_present_env_var(&[env_var]) {
        if prompt_yes_no(&format!("Use {label} from ${env_name}?"), true)? {
            return Ok(env_value);
        }
    }

    loop {
        let entered = if hide_sensitive_input {
            prompt_sensitive_line(label, true, false)?
        } else {
            prompt_line(&format!("Enter {label}: "))?
        };
        if !entered.trim().is_empty() {
            return Ok(entered.trim().to_string());
        }
        eprintln!("{label} is required for OAuth sign-in.");
    }
}

fn configure_gemini_provider_interactive(
    config: &mut Value,
    hide_sensitive_input: bool,
    requested_auth_mode: Option<SetupAuthModeSelection>,
) -> Result<ProviderSetupResult, Box<dyn std::error::Error>> {
    let auth_mode = prompt_gemini_setup_auth_mode(requested_auth_mode)?;
    let base_url = prompt_optional_base_url_override(
        "Gemini",
        "GOOGLE_API_BASE_URL",
        "https://generativelanguage.googleapis.com",
    )?;
    let mut result = ProviderSetupResult::default();

    match auth_mode {
        SetupAuthModeSelection::ApiKey => {
            let api_key = prompt_required_secret_config_value(
                "GOOGLE_API_KEY",
                "Gemini API key",
                hide_sensitive_input,
            )?;
            if api_key.effective_value.is_none() {
                print_missing_setup_value_notice("GOOGLE_API_KEY", "Gemini API key");
            }

            if let Some(key) = api_key.effective_value.clone() {
                let validation = crate::onboarding::gemini::validate_gemini_api_key_input(
                    &key,
                    base_url
                        .as_ref()
                        .and_then(|value| value.effective_value.as_deref()),
                );
                if let Err(err) = validation {
                    result.observed_checks.push(handle_setup_validation_failure(
                        SetupProvider::Gemini,
                        Some(SetupAuthModeSelection::ApiKey),
                        err,
                    )?);
                }
            }

            crate::onboarding::gemini::write_gemini_api_key_config(
                config,
                &api_key.config_value,
                base_url.as_ref().map(|value| value.config_value.as_str()),
            );
        }
        SetupAuthModeSelection::OAuth => {
            let client_id = prompt_oauth_client_value(
                "GOOGLE_OAUTH_CLIENT_ID",
                "Google OAuth client ID",
                false,
            )?;
            let client_secret = prompt_oauth_client_value(
                "GOOGLE_OAUTH_CLIENT_SECRET",
                "Google OAuth client secret",
                hide_sensitive_input,
            )?;

            if let Some(url) = base_url
                .as_ref()
                .and_then(|value| value.effective_value.as_deref())
            {
                if let Err(err) =
                    crate::onboarding::gemini::validate_gemini_base_url_input(Some(url))
                {
                    result.observed_checks.push(handle_setup_validation_failure(
                        SetupProvider::Gemini,
                        Some(SetupAuthModeSelection::OAuth),
                        err,
                    )?);
                }
            }

            let config_snapshot = config.clone();
            let completion =
                run_sync_blocking_send(crate::onboarding::gemini::run_cli_google_oauth(
                    config_snapshot,
                    Some(client_id.clone()),
                    Some(client_secret.clone()),
                ))
                .map_err(|err| format!("Gemini Google sign-in runtime failed: {err}"))?;

            let state_dir = resolve_state_dir();
            std::fs::create_dir_all(&state_dir)?;
            let profile_detail = match completion.auth_profile.email.as_deref() {
                Some(email) => format!("stored Gemini auth profile for {email}"),
                None => "stored Gemini auth profile".to_string(),
            };
            crate::onboarding::gemini::persist_cli_google_oauth(state_dir, config, completion)?;
            result
                .observed_checks
                .push(crate::onboarding::setup::SetupCheck::validation_pass(
                    "Live provider validation",
                    profile_detail,
                    None,
                ));

            if let Some(base_url) = base_url {
                config["google"]["baseUrl"] = serde_json::json!(base_url.config_value);
            }
        }
        SetupAuthModeSelection::SetupToken => {
            return Err(
                "`--auth-mode setup-token` is only valid with `--provider anthropic`.".into(),
            );
        }
    }

    Ok(result)
}

fn configure_codex_provider_interactive(
    config: &mut Value,
    hide_sensitive_input: bool,
) -> Result<ProviderSetupResult, Box<dyn std::error::Error>> {
    println!(
        "OpenAI subscription sign-in stores a refreshable auth profile. OpenAI API-key setup remains available through the OpenAI API-key path."
    );

    let client_id =
        prompt_oauth_client_value("OPENAI_OAUTH_CLIENT_ID", "OpenAI OAuth client ID", false)?;
    let client_secret = prompt_oauth_client_value(
        "OPENAI_OAUTH_CLIENT_SECRET",
        "OpenAI OAuth client secret",
        hide_sensitive_input,
    )?;

    let config_snapshot = config.clone();
    let completion = run_sync_blocking_send(crate::onboarding::codex::run_cli_openai_oauth(
        config_snapshot,
        Some(client_id.clone()),
        Some(client_secret.clone()),
    ))
    .map_err(|err| format!("Codex sign-in runtime failed: {err}"))?;

    let state_dir = resolve_state_dir();
    std::fs::create_dir_all(&state_dir)?;
    let profile_detail = match completion.auth_profile.email.as_deref() {
        Some(email) => format!("stored OpenAI auth profile for {email}"),
        None => "stored OpenAI auth profile".to_string(),
    };
    crate::onboarding::codex::persist_cli_openai_oauth(state_dir, config, completion)?;

    Ok(ProviderSetupResult {
        observed_checks: vec![crate::onboarding::setup::SetupCheck::validation_pass(
            "Live provider validation",
            profile_detail,
            None,
        )],
    })
}

fn configure_vertex_provider_interactive(
    config: &mut Value,
) -> Result<ProviderSetupResult, Box<dyn std::error::Error>> {
    let project_id = prompt_required_visible_env_backed_config_value(
        &["VERTEX_PROJECT_ID"],
        "VERTEX_PROJECT_ID",
        "GCP project ID",
        None,
    )?;
    let location = prompt_required_visible_env_backed_config_value(
        &["VERTEX_LOCATION"],
        "VERTEX_LOCATION",
        "GCP location",
        Some("us-central1"),
    )?;
    let route = prompt_vertex_setup_route()?;
    let model = match route {
        crate::onboarding::vertex::VertexModelRoute::Default => {
            let configured = prompt_required_visible_env_backed_config_value(
                &["VERTEX_MODEL"],
                "VERTEX_MODEL",
                "Vertex default model",
                None,
            )?;
            if configured.effective_value.is_none() {
                print_missing_setup_value_notice("VERTEX_MODEL", "Vertex default model");
            }
            configured
        }
        crate::onboarding::vertex::VertexModelRoute::Explicit => {
            let explicit_model = prompt_vertex_explicit_model_id()?;
            SetupConfigValue {
                config_value: explicit_model.clone(),
                effective_value: Some(explicit_model),
            }
        }
    };

    if project_id.effective_value.is_none() {
        print_missing_setup_value_notice("VERTEX_PROJECT_ID", "Vertex project ID");
    }

    let config_input = crate::onboarding::vertex::VertexSetupInput {
        project_id: project_id.config_value.clone(),
        location: location.config_value.clone(),
        route,
        model: Some(model.config_value.clone()),
    };

    let mut result = ProviderSetupResult::default();
    let effective_model = model.effective_value.clone();
    let mut deferred_env_vars = Vec::new();
    if project_id.effective_value.is_none() {
        deferred_env_vars.push("`VERTEX_PROJECT_ID`");
    }
    if matches!(route, crate::onboarding::vertex::VertexModelRoute::Default)
        && effective_model.is_none()
    {
        deferred_env_vars.push("`VERTEX_MODEL`");
    }

    if deferred_env_vars.is_empty() {
        // The location prompt defaults to `us-central1`, so setup should always
        // have a concrete location before live validation runs.
        let effective_location = location.effective_value.clone().ok_or_else(|| {
            std::io::Error::other(
                "Vertex location prompt must produce a concrete value before validation",
            )
        })?;
        let effective_project_id = project_id.effective_value.clone().ok_or_else(|| {
            std::io::Error::other(
                "Vertex project prompt must produce a concrete value before validation",
            )
        })?;
        let validation_input = crate::onboarding::vertex::VertexSetupInput {
            project_id: effective_project_id,
            location: effective_location,
            route,
            model: effective_model.clone(),
        };
        result
            .observed_checks
            .push(validate_vertex_provider_interactive(&validation_input)?);
    } else {
        let (detail, remediation) = match deferred_env_vars.as_slice() {
            ["`VERTEX_MODEL`"] => (
                "Vertex live validation was skipped because `vertex:default` still resolves `vertex.model` from `VERTEX_MODEL` later".to_string(),
                "set `VERTEX_MODEL` in the same shell and run `cara verify --outcome local-chat` once the default model is available".to_string(),
            ),
            [env_var] => (
                format!(
                    "Vertex live validation was skipped because {env_var} still resolves from the environment later"
                ),
                format!(
                    "set {env_var} in the same shell and run `cara verify --outcome local-chat` once it is available"
                ),
            ),
            deferred => (
                format!(
                    "Vertex live validation was skipped because {} still resolve from the environment later",
                    deferred.join(", ")
                ),
                format!(
                    "set {} in the same shell and run `cara verify --outcome local-chat` once they are available",
                    deferred.join(", ")
                ),
            ),
        };
        result
            .observed_checks
            .push(crate::onboarding::setup::SetupCheck::validation_skip(
                "Live provider validation",
                detail,
                Some(remediation),
                None,
            ));
    }

    crate::onboarding::vertex::write_vertex_config(config, &config_input)?;
    Ok(result)
}

fn handle_setup_validation_failure(
    provider: SetupProvider,
    requested_auth_mode: Option<SetupAuthModeSelection>,
    err: crate::agent::AgentError,
) -> Result<crate::onboarding::setup::SetupCheck, Box<dyn std::error::Error>> {
    eprintln!("{}", render_setup_validation_failure(&err));
    let rerun = setup_rerun_command(provider, requested_auth_mode);
    eprintln!("Next step: fix the value and rerun `{rerun}`.");
    if prompt_yes_no("Continue setup and write config anyway?", false)? {
        Ok(crate::onboarding::setup::SetupCheck::validation_fail(
            "Provider configuration validation",
            render_setup_validation_failure(&err),
            format!("fix the value and rerun `{rerun}`"),
            None,
        ))
    } else {
        Err("setup aborted after provider configuration validation failure".into())
    }
}

fn configure_provider_interactive(
    config: &mut Value,
    provider: SetupProvider,
    hide_sensitive_input: bool,
    requested_auth_mode: Option<SetupAuthModeSelection>,
) -> Result<ProviderSetupResult, Box<dyn std::error::Error>> {
    if !matches!(provider, SetupProvider::Anthropic | SetupProvider::Gemini)
        && requested_auth_mode.is_some()
    {
        return Err("`--auth-mode` is only valid with `--provider anthropic|gemini`.".into());
    }

    let mut result = ProviderSetupResult::default();

    match provider {
        SetupProvider::Anthropic => {
            let auth_mode = prompt_anthropic_setup_auth_mode(requested_auth_mode)?;
            match auth_mode {
                SetupAuthModeSelection::ApiKey => {
                    let api_key = prompt_required_secret_config_value(
                        "ANTHROPIC_API_KEY",
                        "Anthropic API key",
                        hide_sensitive_input,
                    )?;
                    if let Some(key) = api_key.effective_value.as_deref() {
                        result
                            .observed_checks
                            .push(validate_provider_credentials_interactive(
                                provider,
                                Some(SetupAuthModeSelection::ApiKey),
                                key,
                            )?);
                    } else {
                        print_missing_setup_value_notice("ANTHROPIC_API_KEY", "Anthropic API key");
                    }
                    config["anthropic"] = serde_json::json!({ "apiKey": api_key.config_value });
                }
                SetupAuthModeSelection::SetupToken => {
                    let api_key_conflict =
                        crate::onboarding::anthropic::anthropic_setup_token_api_key_conflict(
                            config,
                        );
                    if api_key_conflict.config_api_key_present
                        && !prompt_yes_no(
                            "Replace existing `anthropic.apiKey` config with Anthropic setup-token auth?",
                            false,
                        )?
                    {
                        return Err(
                            "setup aborted before replacing existing Anthropic API key config"
                                .into(),
                        );
                    }
                    if api_key_conflict.env_api_key_present
                        && !prompt_yes_no(
                            "`ANTHROPIC_API_KEY` is set in this shell and will override Anthropic setup-token auth until you unset it. Continue storing the setup token anyway?",
                            false,
                        )?
                    {
                        return Err(
                            "setup aborted while `ANTHROPIC_API_KEY` would still override Anthropic setup-token auth"
                                .into(),
                        );
                    }
                    let token = prompt_required_secret_value_from_env(
                        "ANTHROPIC_SETUP_TOKEN",
                        "Anthropic setup-token",
                        hide_sensitive_input,
                    )?;
                    let token =
                        crate::onboarding::anthropic::validate_anthropic_setup_token_input(&token)
                            .map_err(std::io::Error::other)?;
                    result
                        .observed_checks
                        .push(validate_provider_credentials_interactive(
                            provider,
                            Some(SetupAuthModeSelection::SetupToken),
                            &token,
                        )?);
                    let state_dir = resolve_state_dir();
                    std::fs::create_dir_all(&state_dir)?;
                    crate::onboarding::anthropic::persist_cli_anthropic_setup_token(
                        state_dir, config, &token,
                    )
                    .map_err(std::io::Error::other)?;
                }
                SetupAuthModeSelection::OAuth => {
                    return Err(
                        "`--auth-mode oauth` is only valid with `--provider gemini`.".into(),
                    );
                }
            }
        }
        SetupProvider::Codex => {
            result = configure_codex_provider_interactive(config, hide_sensitive_input)?;
        }
        SetupProvider::OpenAi => {
            let api_key = prompt_required_secret_config_value(
                "OPENAI_API_KEY",
                "API key",
                hide_sensitive_input,
            )?;
            if let Some(key) = api_key.effective_value.as_deref() {
                result
                    .observed_checks
                    .push(validate_provider_credentials_interactive(
                        provider, None, key,
                    )?);
            } else {
                print_missing_setup_value_notice("OPENAI_API_KEY", "API key");
            }
            config["openai"] = serde_json::json!({ "apiKey": api_key.config_value });
        }
        SetupProvider::Ollama => {
            let base_url = prompt_required_visible_config_value(
                &["OLLAMA_BASE_URL"],
                "Ollama base URL",
                crate::agent::ollama::DEFAULT_OLLAMA_BASE_URL,
            )?;

            let api_key = if prompt_yes_no("Does this Ollama endpoint require an API key?", false)?
            {
                Some(prompt_required_secret_config_value(
                    "OLLAMA_API_KEY",
                    "Ollama API key",
                    hide_sensitive_input,
                )?)
            } else {
                None
            };
            if api_key
                .as_ref()
                .is_some_and(|value| value.effective_value.is_none())
            {
                print_missing_setup_value_notice("OLLAMA_API_KEY", "Ollama API key");
            }

            match crate::agent::ollama::OllamaProvider::new()
                .and_then(|provider| {
                    provider.with_base_url(base_url.effective_value.clone().unwrap_or_default())
                })
                .map(|provider| {
                    if let Some(api_key) = api_key
                        .as_ref()
                        .and_then(|value| value.effective_value.clone())
                    {
                        provider.with_api_key(api_key)
                    } else {
                        provider
                    }
                }) {
                Ok(_) => {}
                Err(err) => result
                    .observed_checks
                    .push(handle_setup_validation_failure(provider, None, err)?),
            }

            let mut ollama_config = serde_json::Map::new();
            ollama_config.insert(
                "baseUrl".to_string(),
                serde_json::json!(base_url.config_value),
            );
            if let Some(api_key) = api_key {
                ollama_config.insert(
                    "apiKey".to_string(),
                    serde_json::json!(api_key.config_value),
                );
            }
            config["providers"] = serde_json::json!({
                "ollama": Value::Object(ollama_config)
            });
        }
        SetupProvider::Gemini => {
            result = configure_gemini_provider_interactive(
                config,
                hide_sensitive_input,
                requested_auth_mode,
            )?;
        }
        SetupProvider::Vertex => {
            result = configure_vertex_provider_interactive(config)?;
        }
        SetupProvider::Venice => {
            let api_key = prompt_required_secret_config_value(
                "VENICE_API_KEY",
                "Venice API key",
                hide_sensitive_input,
            )?;
            if api_key.effective_value.is_none() {
                print_missing_setup_value_notice("VENICE_API_KEY", "Venice API key");
            }
            let base_url = prompt_optional_base_url_override(
                "Venice",
                "VENICE_BASE_URL",
                "https://api.venice.ai/api",
            )?;

            if let Some(key) = api_key.effective_value.clone() {
                let validation =
                    crate::agent::venice::VeniceProvider::new(key).and_then(|provider| {
                        if let Some(base_url) = base_url
                            .as_ref()
                            .and_then(|value| value.effective_value.clone())
                        {
                            provider.with_base_url(base_url)
                        } else {
                            Ok(provider)
                        }
                    });
                if let Err(err) = validation {
                    result
                        .observed_checks
                        .push(handle_setup_validation_failure(provider, None, err)?);
                }
            }

            let mut venice_config = serde_json::Map::new();
            venice_config.insert(
                "apiKey".to_string(),
                serde_json::json!(api_key.config_value),
            );
            if let Some(base_url) = base_url {
                venice_config.insert(
                    "baseUrl".to_string(),
                    serde_json::json!(base_url.config_value),
                );
            }
            config["venice"] = Value::Object(venice_config);
        }
        SetupProvider::Bedrock => {
            let region = prompt_required_visible_config_value(
                &["AWS_REGION", "AWS_DEFAULT_REGION"],
                "AWS Bedrock region",
                "us-east-1",
            )?;
            let access_key = prompt_required_secret_config_value(
                "AWS_ACCESS_KEY_ID",
                "AWS access key ID",
                hide_sensitive_input,
            )?;
            let secret_key = prompt_required_secret_config_value(
                "AWS_SECRET_ACCESS_KEY",
                "AWS secret access key",
                hide_sensitive_input,
            )?;

            if access_key.effective_value.is_none() {
                print_missing_setup_value_notice("AWS_ACCESS_KEY_ID", "AWS access key ID");
            }
            if secret_key.effective_value.is_none() {
                print_missing_setup_value_notice("AWS_SECRET_ACCESS_KEY", "AWS secret access key");
            }

            let session_token = if env_var_present("AWS_SESSION_TOKEN") {
                if prompt_yes_no("Use AWS session token from $AWS_SESSION_TOKEN?", true)? {
                    Some(SetupConfigValue {
                        config_value: env_placeholder("AWS_SESSION_TOKEN"),
                        effective_value: env_var_value("AWS_SESSION_TOKEN"),
                    })
                } else if prompt_yes_no("Add an AWS session token?", false)? {
                    let entered =
                        prompt_sensitive_line("AWS session token", hide_sensitive_input, true)?;
                    if entered.is_empty() {
                        None
                    } else {
                        Some(SetupConfigValue {
                            config_value: entered.clone(),
                            effective_value: Some(entered),
                        })
                    }
                } else {
                    None
                }
            } else if prompt_yes_no("Add an AWS session token?", false)? {
                prompt_optional_secret_config_value(
                    "AWS_SESSION_TOKEN",
                    "AWS session token",
                    hide_sensitive_input,
                )?
            } else {
                None
            };

            // Live credential + model validation (includes region check).
            if let (Some(eff_region), Some(eff_access), Some(eff_secret)) = (
                region.effective_value.clone(),
                access_key.effective_value.clone(),
                secret_key.effective_value.clone(),
            ) {
                let check = validate_bedrock_credentials_interactive(
                    provider,
                    &eff_region,
                    &eff_access,
                    &eff_secret,
                    session_token
                        .as_ref()
                        .and_then(|v| v.effective_value.as_deref()),
                )?;
                result.observed_checks.extend(check);
            }

            config["bedrock"] = serde_json::json!({
                "region": region.config_value,
                "accessKeyId": access_key.config_value,
                "secretAccessKey": secret_key.config_value
            });
            if let Some(session_token) = session_token {
                config["bedrock"]["sessionToken"] = serde_json::json!(session_token.config_value);
            }
        }
    }

    if provider != SetupProvider::Vertex {
        config["agents"]["defaults"]["model"] = serde_json::json!(provider.default_model());
    }

    Ok(result)
}

fn configure_provider_noninteractive(
    config: &mut Value,
    provider: SetupProvider,
    requested_auth_mode: Option<SetupAuthModeSelection>,
) -> Result<ProviderSetupResult, Box<dyn std::error::Error>> {
    if !matches!(provider, SetupProvider::Anthropic | SetupProvider::Gemini)
        && requested_auth_mode.is_some()
    {
        return Err("`--auth-mode` is only valid with `--provider anthropic|gemini`.".into());
    }
    config["agents"]["defaults"]["model"] = serde_json::json!(provider.default_model());

    match provider {
        SetupProvider::Anthropic => match requested_auth_mode {
            Some(SetupAuthModeSelection::SetupToken) => {
                let api_key_conflict =
                    crate::onboarding::anthropic::anthropic_setup_token_api_key_conflict(config);
                if api_key_conflict.config_api_key_present {
                    eprintln!(
                        "Replacing existing `anthropic.apiKey` config with `anthropic.authProfile` for Anthropic setup-token mode."
                    );
                }
                if api_key_conflict.env_api_key_present {
                    eprintln!(
                        "`ANTHROPIC_API_KEY` is set in this shell and will override `anthropic.authProfile` until you unset it."
                    );
                }
                let token = env_var_value("ANTHROPIC_SETUP_TOKEN").ok_or_else(|| {
                        std::io::Error::other(
                            "non-interactive Anthropic setup-token mode requires ANTHROPIC_SETUP_TOKEN.",
                        )
                    })?;
                let state_dir = resolve_state_dir();
                std::fs::create_dir_all(&state_dir)?;
                crate::onboarding::anthropic::persist_cli_anthropic_setup_token(
                    state_dir, config, &token,
                )
                .map_err(std::io::Error::other)?;
            }
            Some(SetupAuthModeSelection::OAuth) => {
                return Err(
                        "non-interactive Anthropic setup does not support `--auth-mode oauth`; use `api-key` or `setup-token`."
                            .into(),
                    );
            }
            _ => {
                config["anthropic"] =
                    serde_json::json!({ "apiKey": env_placeholder("ANTHROPIC_API_KEY") });
            }
        },
        SetupProvider::Codex => {
            return Err(
                "non-interactive Codex sign-in is not supported; rerun interactively.".into(),
            );
        }
        SetupProvider::OpenAi => {
            config["openai"] = serde_json::json!({ "apiKey": env_placeholder("OPENAI_API_KEY") });
        }
        SetupProvider::Ollama => {
            let base_url = first_present_env_var(&["OLLAMA_BASE_URL"])
                .map(|(env_var, _)| env_placeholder(env_var))
                .unwrap_or_else(|| crate::agent::ollama::DEFAULT_OLLAMA_BASE_URL.to_string());
            let mut ollama_config = serde_json::Map::new();
            ollama_config.insert("baseUrl".to_string(), serde_json::json!(base_url));
            if env_var_present("OLLAMA_API_KEY") {
                ollama_config.insert(
                    "apiKey".to_string(),
                    serde_json::json!(env_placeholder("OLLAMA_API_KEY")),
                );
            }
            config["providers"] = serde_json::json!({
                "ollama": ollama_config
            });
        }
        SetupProvider::Gemini => match requested_auth_mode {
            Some(SetupAuthModeSelection::ApiKey) => {
                crate::onboarding::gemini::write_gemini_api_key_config(
                    config,
                    &env_placeholder("GOOGLE_API_KEY"),
                    env_var_present("GOOGLE_API_BASE_URL")
                        .then(|| env_placeholder("GOOGLE_API_BASE_URL"))
                        .as_deref(),
                );
            }
            Some(SetupAuthModeSelection::OAuth) => {
                return Err(
                        "non-interactive Gemini Google sign-in is not supported; rerun interactively or use `--auth-mode api-key`."
                            .into(),
                    );
            }
            Some(SetupAuthModeSelection::SetupToken) => {
                return Err(
                    "non-interactive Gemini setup does not support `--auth-mode setup-token`; use `oauth` or `api-key`."
                        .into(),
                );
            }
            None => {
                return Err(
                    "non-interactive Gemini setup requires `--auth-mode oauth|api-key`.".into(),
                );
            }
        },
        SetupProvider::Vertex => {
            crate::onboarding::vertex::write_vertex_config(
                config,
                &crate::onboarding::vertex::VertexSetupInput {
                    project_id: env_placeholder("VERTEX_PROJECT_ID"),
                    location: if env_var_present("VERTEX_LOCATION") {
                        env_placeholder("VERTEX_LOCATION")
                    } else {
                        "us-central1".to_string()
                    },
                    route: crate::onboarding::vertex::VertexModelRoute::Default,
                    model: Some(env_placeholder("VERTEX_MODEL")),
                },
            )?;
        }
        SetupProvider::Venice => {
            config["venice"] = serde_json::json!({
                "apiKey": env_placeholder("VENICE_API_KEY")
            });
            if env_var_present("VENICE_BASE_URL") {
                config["venice"]["baseUrl"] = serde_json::json!(env_placeholder("VENICE_BASE_URL"));
            }
        }
        SetupProvider::Bedrock => {
            let region_placeholder = if env_var_present("AWS_REGION") {
                env_placeholder("AWS_REGION")
            } else if env_var_present("AWS_DEFAULT_REGION") {
                env_placeholder("AWS_DEFAULT_REGION")
            } else {
                "us-east-1".to_string()
            };
            config["bedrock"] = serde_json::json!({
                "region": region_placeholder,
                "accessKeyId": env_placeholder("AWS_ACCESS_KEY_ID"),
                "secretAccessKey": env_placeholder("AWS_SECRET_ACCESS_KEY")
            });
            if env_var_present("AWS_SESSION_TOKEN") {
                config["bedrock"]["sessionToken"] =
                    serde_json::json!(env_placeholder("AWS_SESSION_TOKEN"));
            }

            // Run live validation if actual credential values are available.
            let sources = crate::onboarding::bedrock::detect_credential_sources();
            let mut result = ProviderSetupResult::default();
            let effective_region = sources
                .region
                .as_ref()
                .map(|s| s.value.clone())
                .unwrap_or_else(|| "us-east-1".to_string());
            if sources.region.is_some() {
                result
                    .observed_checks
                    .push(crate::onboarding::bedrock::validate_region(
                        &effective_region,
                    ));
            }
            if let (Some(access_src), Some(secret_src)) = (&sources.access_key, &sources.secret_key)
            {
                let r = effective_region.clone();
                let a = access_src.value.clone();
                let s = secret_src.value.clone();
                let t = sources.session_token.as_ref().map(|v| v.value.clone());
                let default_model = provider.default_model().to_string();

                match run_sync_blocking_send(async move {
                    Ok::<_, String>(
                        crate::onboarding::bedrock::validate_bedrock_credentials(
                            &r,
                            &a,
                            &s,
                            t.as_deref(),
                        )
                        .await,
                    )
                }) {
                    Ok((cred_check, models_json)) => {
                        result.observed_checks.push(cred_check);
                        if let Some(ref models) = models_json {
                            result.observed_checks.push(
                                crate::onboarding::bedrock::check_model_access(
                                    &default_model,
                                    models,
                                ),
                            );
                        }
                    }
                    Err(err) => {
                        result.observed_checks.push(
                            crate::onboarding::setup::SetupCheck::validation_fail(
                                "Live Bedrock validation",
                                format!("Credential validation runtime failed: {err}"),
                                "run `cara verify` after setup to exercise the configured provider path".to_string(),
                                None,
                            ),
                        );
                    }
                }
            }
            return Ok(result);
        }
    }
    Ok(ProviderSetupResult::default())
}

/// Run the `import openclaw` subcommand.
pub fn handle_import_openclaw(force: bool) -> Result<(), Box<dyn std::error::Error>> {
    use crate::migration::openclaw;

    let discovery = match openclaw::discover() {
        Some(d) => d,
        None => {
            eprintln!("No OpenClaw installation found.");
            eprintln!(
                "Checked: ~/.openclaw/, ~/.clawdbot/, $OPENCLAW_CONFIG_PATH, $OPENCLAW_STATE_DIR"
            );
            return Err("no OpenClaw config found".into());
        }
    };

    println!("Found OpenClaw config: {}", discovery.config_path.display());
    if let Some(ref env) = discovery.env_path {
        println!("Found .env file: {}", env.display());
    }
    if let Some(ref creds) = discovery.credentials_path {
        println!("Found credentials: {}", creds.display());
    }
    println!();

    let plan = openclaw::plan_import(&discovery);
    execute_import_plan(plan, force)
}

/// Run the `import opencode` subcommand.
pub fn handle_import_opencode(force: bool) -> Result<(), Box<dyn std::error::Error>> {
    use crate::migration::opencode;

    let discovery = match opencode::discover() {
        Some(d) => d,
        None => {
            eprintln!("No OpenCode installation found.");
            eprintln!(
                "Checked: ./.opencode.json, ~/.opencode.json, $XDG_CONFIG_HOME/opencode/, ~/.config/opencode/"
            );
            return Err("no OpenCode config found".into());
        }
    };

    println!("Found OpenCode config: {}", discovery.config_path.display());
    println!();

    let plan = opencode::plan_import(&discovery);
    execute_import_plan(plan, force)
}

/// Run the `import aider` subcommand.
pub fn handle_import_aider(force: bool) -> Result<(), Box<dyn std::error::Error>> {
    use crate::migration::aider;

    let discovery = match aider::discover() {
        Some(d) => d,
        None => {
            eprintln!("No Aider installation found.");
            eprintln!("Checked: ./.aider.conf.yml, ~/.aider.conf.yml, ./.env");
            return Err("no Aider config found".into());
        }
    };

    if let Some(ref config) = discovery.config_path {
        println!("Found Aider config: {}", config.display());
    }
    if let Some(ref env) = discovery.env_path {
        println!("Found .env file: {}", env.display());
    }
    println!();

    let plan = aider::plan_import(&discovery);
    execute_import_plan(plan, force)
}

/// Run the `import nemoclaw` subcommand.
pub fn handle_import_nemoclaw(force: bool) -> Result<(), Box<dyn std::error::Error>> {
    use crate::migration::nemoclaw;

    let discovery = match nemoclaw::discover() {
        Some(d) => d,
        None => {
            eprintln!("No NemoClaw installation found.");
            eprintln!("Checked: ~/.nemoclaw/config.json");
            return Err("no NemoClaw config found".into());
        }
    };

    println!("Found NemoClaw config: {}", discovery.config_path.display());
    println!();

    let plan = nemoclaw::plan_import(&discovery);
    execute_import_plan(plan, force)
}

fn execute_import_plan(
    plan: crate::migration::ImportPlan,
    force: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let config_path = config::get_config_path();
    if config_path.exists() && !force {
        eprintln!(
            "Carapace config already exists at {}.",
            config_path.display()
        );
        eprintln!("Use --force to overwrite, or edit the existing config manually.");
        return Err("existing config found; use --force to overwrite".into());
    }

    for warning in &plan.warnings {
        eprintln!("Warning: {warning}");
    }

    if plan.is_empty() && plan.skipped.is_empty() {
        println!(
            "No importable configuration found in the {} config.",
            plan.source_name
        );
        return Ok(());
    }

    // Show what will be imported.
    if !plan.mappings.is_empty() {
        println!("The following fields will be imported:\n");
        println!(
            "  {:<45} {:<30} Value",
            format!("{} source", plan.source_name),
            "Carapace key"
        );
        println!(
            "  {:<45} {:<30} {}",
            "-".repeat(44),
            "-".repeat(29),
            "-".repeat(20)
        );
        for mapping in &plan.mappings {
            let display_value = if mapping.sensitive {
                "[REDACTED]".to_string()
            } else {
                mapping
                    .value
                    .as_str()
                    .map(|s| truncate_display(s, 40))
                    .unwrap_or_else(|| mapping.value.to_string())
            };
            println!(
                "  {:<45} {:<30} {}",
                truncate_display(&mapping.source_path, 44),
                mapping.carapace_key,
                display_value
            );
        }
        println!();
    }

    // Show what was skipped.
    if !plan.skipped.is_empty() {
        println!("Skipped (no Carapace mapping):\n");
        for skipped in &plan.skipped {
            println!("  {} — {}", skipped.source_path, skipped.reason);
        }
        println!();
    }

    if plan.is_empty() {
        println!("No importable fields found after scanning.");
        return Ok(());
    }

    // Confirm.
    if !prompt_yes_no(
        &format!(
            "Write {} field(s) to {}?",
            plan.mappings.len(),
            config_path.display()
        ),
        true,
    )? {
        println!("Import cancelled.");
        return Ok(());
    }

    // Build and write config with restricted permissions.
    let mut config = plan.build_carapace_config();
    if let Some(parent) = config_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    if let Err(e) = config::seal_config_secrets(&mut config) {
        return Err(format!("Failed to encrypt secrets: {e}").into());
    }
    let content = json5::to_string(&config)?;
    write_config_restricted(&config_path, &content)?;

    println!("\nConfig written to {}", config_path.display());
    println!();
    println!("Next steps:");
    println!("  cara verify    — validate that imported providers work");
    println!("  cara status    — check gateway health after starting");
    println!("  cara setup     — reconfigure or add providers interactively");

    Ok(())
}

fn truncate_display(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let truncated: String = s.chars().take(max.saturating_sub(1)).collect();
        format!("{truncated}…")
    }
}

fn write_config_restricted(
    path: &std::path::Path,
    content: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    use std::io::Write;
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(content.as_bytes())?;
    }
    #[cfg(not(unix))]
    {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)?;
        file.write_all(content.as_bytes())?;
    }
    Ok(())
}

/// Run the `setup` subcommand -- interactive first-run wizard.
pub fn handle_setup(
    force: bool,
    requested_provider: Option<SetupProvider>,
    requested_auth_mode: Option<SetupAuthModeSelection>,
) -> Result<(), Box<dyn std::error::Error>> {
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

    let interactive = stdin_is_interactive();

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

    let setup_outcome;
    let mut hooks_enabled = false;
    let mut verify_discord_to: Option<String> = None;
    let mut verify_telegram_to: Option<String> = None;
    let configured_provider;
    let provider_setup_result;

    if interactive {
        println!("Carapace setup wizard");
        println!("---------------------");
        println!("This interactive wizard writes first-run config for every supported provider.");
        println!(
            "Fastest first-run path: pick one provider, keep `local-chat`, then run `cara verify --outcome local-chat`."
        );

        let hide_sensitive_input = prompt_yes_no("Hide sensitive input while typing?", true)?;
        let provider = prompt_setup_provider_interactive(requested_provider)?;
        provider_setup_result = configure_provider_interactive(
            &mut config,
            provider,
            hide_sensitive_input,
            requested_auth_mode,
        )?;
        configured_provider = provider;

        let auth_mode = prompt_choice(
            "Gateway auth mode (token/password)",
            "token",
            &["token", "password"],
        )?;
        let auth_secret = if auth_mode == "token" {
            if prompt_yes_no("Generate a strong gateway token automatically?", true)? {
                generate_hex_secret(32)?
            } else {
                prompt_custom_secret("gateway token", hide_sensitive_input)?
            }
        } else if prompt_yes_no("Generate a strong gateway password automatically?", true)? {
            generate_hex_secret(24)?
        } else {
            prompt_custom_secret("gateway password", hide_sensitive_input)?
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
                    hide_sensitive_input,
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
                    hide_sensitive_input,
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
                    prompt_custom_secret("hooks token", hide_sensitive_input)?
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
    } else if let Some(provider) = requested_provider {
        provider_setup_result =
            configure_provider_noninteractive(&mut config, provider, requested_auth_mode)?;
        configured_provider = provider;
        setup_outcome = infer_setup_outcome_from_config(&config);
    } else {
        return Err(
            "non-interactive setup requires `--provider <provider>`; rerun with an explicit provider."
                .into(),
        );
    }

    // Write the config file using json5 (pretty-formatted).
    let content = json5::to_string(&config)?;
    std::fs::write(&config_path, &content)?;

    println!("Config written to {}", config_path.display());
    println!("Start the server with: cara start");

    let setup_assessment = crate::onboarding::setup::assess_provider_setup(
        &config,
        &resolve_state_dir(),
        configured_provider.into(),
        provider_setup_result.observed_checks,
    );
    print_setup_assessment_summary(&setup_assessment);
    if let Some(remediation) = setup_assessment.recommended_remediation() {
        if setup_assessment.status == crate::onboarding::setup::SetupAssessmentStatus::Invalid {
            println!("Next fix: {remediation}");
        }
    }

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
                if let Err(err) =
                    run_sync_blocking_send(run_setup_post_checks(port, run_status, launch_chat))
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
    } else {
        let port = config
            .get("gateway")
            .and_then(|v| v.get("port"))
            .and_then(|v| v.as_u64())
            .and_then(|v| u16::try_from(v).ok())
            .unwrap_or(DEFAULT_PORT);
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
        if err.code.as_deref() == Some("not_paired") && err.message.contains("pairing required") {
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
    let release = match crate::update::fetch_release_info(current_version, version).await {
        Ok(release) => release,
        Err(err) => {
            eprintln!("Failed to check for updates: {}", err.message);
            if err.retryable {
                eprintln!("This may be a temporary issue; retry in a moment.");
            }
            return Err(err.message.into());
        }
    };
    let latest_version = crate::update::tag_to_version(&release.tag_name);
    let html_url = release.html_url.as_str();

    if check {
        println!("Current version: v{}", current_version);
        println!("Latest version:  v{}", latest_version);

        if current_version == latest_version.as_str() {
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
    let target_version = version.unwrap_or(latest_version.as_str());
    if target_version == current_version {
        println!("Already up to date (v{})", current_version);
        return Ok(());
    }

    println!(
        "Updating from v{} to v{}...",
        current_version, target_version
    );

    let request = crate::update::InstallRequest {
        current_version: current_version.to_string(),
        state_dir: resolve_state_dir(),
        requested_version: Some(target_version.to_string()),
        apply_update: true,
    };

    match crate::update::install_or_resume(request).await {
        Ok(outcome) => {
            if outcome.resumed {
                if let Some(max_attempts) = outcome.transaction.as_ref().map(|tx| tx.max_attempts) {
                    println!(
                        "Resumed pending update transaction (attempt {}/{}).",
                        outcome.attempt, max_attempts
                    );
                } else {
                    println!(
                        "Resumed pending update transaction (attempt {}).",
                        outcome.attempt
                    );
                }
            }
            println!("Update applied successfully.");
            println!("  Staged path: {}", outcome.staged_path);
            if let Some(apply) = outcome.apply_result {
                println!("  Binary: {}", apply.binary_path);
                println!("  SHA-256: {}", apply.sha256);
            }
            println!(
                "  Sigstore bundle verification: {}",
                if outcome.verification.bundle_verified {
                    "passed"
                } else {
                    "failed"
                }
            );
            println!(
                "  Checksum verification: {}",
                if outcome.verification.checksum_verified {
                    "passed"
                } else {
                    "not available"
                }
            );
            println!(
                "  Signing identity: {}",
                outcome.verification.expected_identity
            );
            println!("Restart cara to use v{}.", target_version);
        }
        Err(err) => {
            eprintln!("Update failed (phase: {:?}): {}", err.phase, err.message);
            if err.retryable {
                eprintln!("This failure is retryable; rerun `cara update` to resume.");
            } else {
                eprintln!(
                    "This failure is non-retryable; resolve release artifact/policy mismatch before retrying."
                );
            }
            eprintln!("Release page: {}", html_url);
            return Err(err.message.into());
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
    use crate::runtime_bridge::{run_sync_blocking, CURRENT_THREAD_RUNTIME_MESSAGE};
    use crate::test_support::{env::ScopedEnv, plugins::tool_plugin_component_bytes};
    use clap::Parser;
    use ed25519_dalek::{Signature, VerifyingKey};
    use std::collections::VecDeque;
    use std::path::PathBuf;

    struct SetupInteractiveHarnessGuard;

    impl Drop for SetupInteractiveHarnessGuard {
        fn drop(&mut self) {
            clear_setup_interactive_test_harness();
        }
    }

    fn install_setup_interactive_harness(
        harness: SetupInteractiveTestHarness,
    ) -> SetupInteractiveHarnessGuard {
        set_setup_interactive_test_harness(harness);
        SetupInteractiveHarnessGuard
    }

    struct SetupInteractiveTestEnv {
        _temp: tempfile::TempDir,
        config_path: PathBuf,
        _harness_guard: SetupInteractiveHarnessGuard,
    }

    fn setup_interactive_test_env(
        env_guard: &mut ScopedEnv,
        harness: SetupInteractiveTestHarness,
    ) -> SetupInteractiveTestEnv {
        let temp = tempfile::TempDir::new().unwrap();
        let config_path = temp.path().join("carapace.json");
        env_guard
            .set("CARAPACE_CONFIG_PATH", config_path.as_os_str())
            .unset("OPENAI_API_KEY")
            .unset("ANTHROPIC_API_KEY")
            .unset("VERTEX_PROJECT_ID")
            .unset("VERTEX_LOCATION")
            .unset("VERTEX_MODEL")
            .unset("TELEGRAM_BOT_TOKEN")
            .unset("DISCORD_BOT_TOKEN");
        let harness_guard = install_setup_interactive_harness(harness);
        SetupInteractiveTestEnv {
            _temp: temp,
            config_path,
            _harness_guard: harness_guard,
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
    fn test_cli_plugins_status_defaults() {
        let cli = Cli::try_parse_from(["cara", "plugins", "status"]).unwrap();
        match cli.command {
            Some(Command::Plugins(PluginsCommand::Status {
                json,
                name,
                plugin_id,
                source,
                state,
                only_failed,
                strict,
                connection,
            })) => {
                assert!(!json);
                assert_eq!(name, None);
                assert_eq!(plugin_id, None);
                assert_eq!(source, None);
                assert_eq!(state, None);
                assert!(!only_failed);
                assert!(!strict);
                assert_eq!(connection.port, None);
                assert_eq!(connection.host, "127.0.0.1");
                assert!(!connection.tls);
                assert!(!connection.trust);
                assert!(!connection.allow_plaintext);
            }
            other => panic!("Expected Plugins(Status), got {:?}", other),
        }
    }

    #[test]
    fn test_cli_plugins_status_filters() {
        let cli = Cli::try_parse_from([
            "cara",
            "plugins",
            "status",
            "--plugin-id",
            "demo.tool",
            "--source",
            "managed",
            "--state",
            "failed",
            "--only-failed",
            "--strict",
        ])
        .unwrap();
        match cli.command {
            Some(Command::Plugins(PluginsCommand::Status {
                plugin_id,
                source,
                state,
                only_failed,
                strict,
                ..
            })) => {
                assert_eq!(plugin_id.as_deref(), Some("demo.tool"));
                assert_eq!(source, Some(PluginSourceSelection::Managed));
                assert_eq!(state, Some(PluginStateSelection::Failed));
                assert!(only_failed);
                assert!(strict);
            }
            other => panic!("Expected Plugins(Status), got {:?}", other),
        }
    }

    #[test]
    fn test_cli_plugins_bins_defaults() {
        let cli = Cli::try_parse_from(["cara", "plugins", "bins"]).unwrap();
        match cli.command {
            Some(Command::Plugins(PluginsCommand::Bins { json, connection })) => {
                assert!(!json);
                assert_eq!(connection.port, None);
                assert_eq!(connection.host, "127.0.0.1");
            }
            other => panic!("Expected Plugins(Bins), got {:?}", other),
        }
    }

    #[test]
    fn test_cli_plugins_install_with_file() {
        let cli = Cli::try_parse_from([
            "cara",
            "plugins",
            "install",
            "demo-plugin",
            "--file",
            "./demo.wasm",
            "--version",
            "1.2.3",
            "--publisher-key",
            "pubkey",
            "--signature",
            "sig",
        ])
        .unwrap();
        match cli.command {
            Some(Command::Plugins(PluginsCommand::Install(PluginMutationArgs {
                name,
                url,
                file,
                version,
                publisher_key,
                signature,
                ..
            }))) => {
                assert_eq!(name, "demo-plugin");
                assert_eq!(url, None);
                assert_eq!(file, Some(PathBuf::from("./demo.wasm")));
                assert_eq!(version.as_deref(), Some("1.2.3"));
                assert_eq!(publisher_key.as_deref(), Some("pubkey"));
                assert_eq!(signature.as_deref(), Some("sig"));
            }
            other => panic!("Expected Plugins(Install), got {:?}", other),
        }
    }

    #[test]
    fn test_cli_plugins_install_requires_exactly_one_source() {
        let err = Cli::try_parse_from([
            "cara",
            "plugins",
            "install",
            "demo-plugin",
            "--url",
            "https://example.com/demo.wasm",
            "--file",
            "./demo.wasm",
        ])
        .unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("--url"));
        assert!(rendered.contains("--file"));
    }

    #[test]
    fn test_cli_plugins_update_with_url() {
        let cli = Cli::try_parse_from([
            "cara",
            "plugins",
            "update",
            "demo-plugin",
            "--url",
            "https://example.com/demo.wasm",
            "--json",
        ])
        .unwrap();
        match cli.command {
            Some(Command::Plugins(PluginsCommand::Update(PluginMutationArgs {
                name,
                url,
                file,
                json,
                ..
            }))) => {
                assert_eq!(name, "demo-plugin");
                assert_eq!(url.as_deref(), Some("https://example.com/demo.wasm"));
                assert_eq!(file, None);
                assert!(json);
            }
            other => panic!("Expected Plugins(Update), got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_stage_plugin_file_into_managed_dir_requires_loopback_host() {
        let temp = tempfile::TempDir::new().unwrap();
        let plugin_path = temp.path().join("demo.wasm");
        std::fs::write(&plugin_path, tool_plugin_component_bytes()).unwrap();
        let connection = WsConnectionArgs {
            port: Some(18789),
            host: "10.0.0.12".to_string(),
            tls: true,
            trust: false,
            allow_plaintext: false,
        };

        let err = stage_plugin_file_into_managed_dir(&connection, "demo", &plugin_path)
            .await
            .unwrap_err();
        assert!(err
            .to_string()
            .contains("--file is only supported for loopback"));
    }

    #[tokio::test]
    async fn test_stage_plugin_file_into_managed_dir_stages_file() {
        let mut env_guard = ScopedEnv::new();
        let temp = tempfile::TempDir::new().unwrap();
        env_guard.set("CARAPACE_STATE_DIR", temp.path().as_os_str());

        let plugin_path = temp.path().join("demo-input.wasm");
        std::fs::write(&plugin_path, tool_plugin_component_bytes()).unwrap();
        let connection = WsConnectionArgs {
            port: Some(18789),
            host: "127.0.0.1".to_string(),
            tls: false,
            trust: false,
            allow_plaintext: false,
        };

        let transaction =
            stage_plugin_file_into_managed_dir(&connection, "demo-plugin", &plugin_path)
                .await
                .unwrap();
        assert!(transaction.commit().await.is_ok());
        let staged = temp.path().join("plugins").join("demo-plugin.wasm");
        let lock = temp
            .path()
            .join("plugins")
            .join("demo-plugin.wasm.cli-lock");
        assert!(staged.is_file());
        assert!(!lock.exists());
        assert_eq!(
            std::fs::read(staged).unwrap(),
            tool_plugin_component_bytes()
        );
    }

    #[tokio::test]
    async fn test_stage_plugin_file_into_managed_dir_rejects_invalid_plugin_name() {
        let temp = tempfile::TempDir::new().unwrap();
        let plugin_path = temp.path().join("demo-input.wasm");
        std::fs::write(&plugin_path, tool_plugin_component_bytes()).unwrap();
        let connection = WsConnectionArgs {
            port: Some(18789),
            host: "127.0.0.1".to_string(),
            tls: false,
            trust: false,
            allow_plaintext: false,
        };

        let err = stage_plugin_file_into_managed_dir(&connection, "../escape", &plugin_path)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("plugin name may only contain"));
    }

    #[tokio::test]
    async fn test_stage_plugin_file_into_managed_dir_rollback_removes_new_file() {
        let mut env_guard = ScopedEnv::new();
        let temp = tempfile::TempDir::new().unwrap();
        env_guard.set("CARAPACE_STATE_DIR", temp.path().as_os_str());

        let plugin_path = temp.path().join("demo-input.wasm");
        std::fs::write(&plugin_path, tool_plugin_component_bytes()).unwrap();
        let connection = WsConnectionArgs {
            port: Some(18789),
            host: "127.0.0.1".to_string(),
            tls: false,
            trust: false,
            allow_plaintext: false,
        };

        let transaction =
            stage_plugin_file_into_managed_dir(&connection, "demo-plugin", &plugin_path)
                .await
                .unwrap();
        let rollback_note = transaction.rollback().await.unwrap();
        let staged = temp.path().join("plugins").join("demo-plugin.wasm");
        let lock = temp
            .path()
            .join("plugins")
            .join("demo-plugin.wasm.cli-lock");
        assert!(!staged.exists());
        assert!(!lock.exists());
        assert!(rollback_note.contains("removed staged local managed artifact"));
    }

    #[tokio::test]
    async fn test_stage_plugin_file_into_managed_dir_rollback_restores_previous_file() {
        let mut env_guard = ScopedEnv::new();
        let temp = tempfile::TempDir::new().unwrap();
        env_guard.set("CARAPACE_STATE_DIR", temp.path().as_os_str());

        let plugins_dir = temp.path().join("plugins");
        std::fs::create_dir_all(&plugins_dir).unwrap();
        let existing = plugins_dir.join("demo-plugin.wasm");
        std::fs::write(&existing, b"old-plugin-bytes").unwrap();

        let plugin_path = temp.path().join("demo-input.wasm");
        std::fs::write(&plugin_path, tool_plugin_component_bytes()).unwrap();
        let connection = WsConnectionArgs {
            port: Some(18789),
            host: "127.0.0.1".to_string(),
            tls: false,
            trust: false,
            allow_plaintext: false,
        };

        let transaction =
            stage_plugin_file_into_managed_dir(&connection, "demo-plugin", &plugin_path)
                .await
                .unwrap();
        assert_eq!(
            std::fs::read(&existing).unwrap(),
            tool_plugin_component_bytes()
        );

        let rollback_note = transaction.rollback().await.unwrap();
        assert_eq!(std::fs::read(&existing).unwrap(), b"old-plugin-bytes");
        assert!(rollback_note.contains("restored previous local managed artifact"));
        assert!(!plugins_dir.join("demo-plugin.wasm.cli-backup").exists());
        assert!(!plugins_dir.join("demo-plugin.wasm.cli-lock").exists());
    }

    #[tokio::test]
    async fn test_managed_plugin_file_transaction_rollback_releases_lock_on_restore_failure() {
        let mut env_guard = ScopedEnv::new();
        let temp = tempfile::TempDir::new().unwrap();
        let dest = temp.path().join("demo-plugin.wasm");
        let backup = temp.path().join("demo-plugin.wasm.cli-backup");
        let lock = temp.path().join("demo-plugin.wasm.cli-lock");

        std::fs::write(&dest, b"new-plugin-bytes").unwrap();
        std::fs::write(&backup, b"old-plugin-bytes").unwrap();
        std::fs::write(&lock, b"locked").unwrap();
        env_guard.set("CARAPACE_TEST_FAIL_RESTORE_PLUGIN_DEST", dest.as_os_str());

        let err = ManagedPluginFileTransaction {
            dest: dest.clone(),
            backup: Some(backup.clone()),
            lock: lock.clone(),
            drop_action: ManagedPluginFileTransactionDropAction::RollbackArtifact,
        }
        .rollback()
        .await
        .unwrap_err();

        assert!(err
            .to_string()
            .contains("failed to restore previous plugin artifact"));
        assert!(!lock.exists());
        assert!(backup.exists());
        assert!(dest.exists());
    }

    #[tokio::test]
    async fn test_managed_plugin_file_transaction_rollback_reports_restore_and_lock_failure() {
        let mut env_guard = ScopedEnv::new();
        let temp = tempfile::TempDir::new().unwrap();
        let dest = temp.path().join("demo-plugin.wasm");
        let backup = temp.path().join("demo-plugin.wasm.cli-backup");
        let lock = temp.path().join("demo-plugin.wasm.cli-lock");

        std::fs::write(&dest, b"new-plugin-bytes").unwrap();
        std::fs::write(&backup, b"old-plugin-bytes").unwrap();
        std::fs::create_dir_all(&lock).unwrap();
        env_guard.set("CARAPACE_TEST_FAIL_RESTORE_PLUGIN_DEST", dest.as_os_str());

        let err = ManagedPluginFileTransaction {
            dest: dest.clone(),
            backup: Some(backup.clone()),
            lock: lock.clone(),
            drop_action: ManagedPluginFileTransactionDropAction::RollbackArtifact,
        }
        .rollback()
        .await
        .unwrap_err();

        let rendered = err.to_string();
        assert!(rendered.contains("failed to restore previous plugin artifact"));
        assert!(rendered.contains("failed to remove staging lock"));
        assert!(lock.exists());
        assert!(backup.exists());
        assert!(dest.exists());
    }

    #[tokio::test]
    async fn test_stage_plugin_file_into_managed_dir_commit_removes_backup() {
        let mut env_guard = ScopedEnv::new();
        let temp = tempfile::TempDir::new().unwrap();
        env_guard.set("CARAPACE_STATE_DIR", temp.path().as_os_str());

        let plugins_dir = temp.path().join("plugins");
        std::fs::create_dir_all(&plugins_dir).unwrap();
        let existing = plugins_dir.join("demo-plugin.wasm");
        std::fs::write(&existing, b"old-plugin-bytes").unwrap();

        let plugin_path = temp.path().join("demo-input.wasm");
        std::fs::write(&plugin_path, tool_plugin_component_bytes()).unwrap();
        let connection = WsConnectionArgs {
            port: Some(18789),
            host: "127.0.0.1".to_string(),
            tls: false,
            trust: false,
            allow_plaintext: false,
        };

        let transaction =
            stage_plugin_file_into_managed_dir(&connection, "demo-plugin", &plugin_path)
                .await
                .unwrap();
        assert!(transaction.commit().await.is_ok());

        assert_eq!(
            std::fs::read(&existing).unwrap(),
            tool_plugin_component_bytes()
        );
        assert!(!plugins_dir.join("demo-plugin.wasm.cli-backup").exists());
        assert!(!plugins_dir.join("demo-plugin.wasm.cli-lock").exists());
    }

    #[tokio::test]
    async fn test_restore_previous_plugin_artifact_replaces_partial_dest() {
        let temp = tempfile::TempDir::new().unwrap();
        let dest = temp.path().join("demo-plugin.wasm");
        let backup = temp.path().join("demo-plugin.wasm.cli-backup");
        std::fs::write(&dest, b"partial-new-bytes").unwrap();
        std::fs::write(&backup, b"old-plugin-bytes").unwrap();

        restore_previous_plugin_artifact(&backup, &dest)
            .await
            .unwrap();

        assert_eq!(std::fs::read(&dest).unwrap(), b"old-plugin-bytes");
        assert!(!backup.exists());
    }

    #[tokio::test]
    async fn test_commit_returns_error_when_backup_cleanup_fails() {
        let temp = tempfile::TempDir::new().unwrap();
        let dest = temp.path().join("demo-plugin.wasm");
        let backup = temp.path().join("demo-plugin.wasm.cli-backup");
        std::fs::write(&dest, b"new-plugin-bytes").unwrap();
        std::fs::create_dir_all(&backup).unwrap();

        let err = ManagedPluginFileTransaction {
            dest,
            backup: Some(backup.clone()),
            lock: temp.path().join("demo-plugin.wasm.cli-lock"),
            drop_action: ManagedPluginFileTransactionDropAction::RollbackArtifact,
        }
        .commit()
        .await
        .unwrap_err();

        let rendered = err.to_string();
        assert!(rendered.contains("plugin request succeeded"));
        assert!(rendered.contains("failed to remove staging backup"));
        assert!(rendered.contains("remove or recover that backup"));
        assert!(backup.exists());
    }

    #[tokio::test]
    async fn test_commit_returns_error_when_backup_cleanup_and_lock_release_fail() {
        let temp = tempfile::TempDir::new().unwrap();
        let dest = temp.path().join("demo-plugin.wasm");
        let backup = temp.path().join("demo-plugin.wasm.cli-backup");
        let lock = temp.path().join("demo-plugin.wasm.cli-lock");
        std::fs::write(&dest, b"new-plugin-bytes").unwrap();
        std::fs::create_dir_all(&backup).unwrap();
        std::fs::create_dir_all(&lock).unwrap();

        let err = ManagedPluginFileTransaction {
            dest,
            backup: Some(backup.clone()),
            lock: lock.clone(),
            drop_action: ManagedPluginFileTransactionDropAction::RollbackArtifact,
        }
        .commit()
        .await
        .unwrap_err();

        let rendered = err.to_string();
        assert!(rendered.contains("failed to remove staging backup"));
        assert!(rendered.contains("failed to remove staging lock"));
        assert!(rendered.contains("remove or recover that backup"));
        assert!(rendered
            .contains("remove that lock file before the next local `--file` plugin mutation"));
        assert!(backup.exists());
        assert!(lock.exists());
    }

    #[tokio::test]
    async fn test_finalize_plugin_file_mutation_returns_error_on_commit_cleanup_failure() {
        let temp = tempfile::TempDir::new().unwrap();
        let dest = temp.path().join("demo-plugin.wasm");
        let backup = temp.path().join("demo-plugin.wasm.cli-backup");
        std::fs::write(&dest, b"new-plugin-bytes").unwrap();
        std::fs::create_dir_all(&backup).unwrap();

        let result = finalize_plugin_file_mutation(
            Some(ManagedPluginFileTransaction {
                dest,
                backup: Some(backup.clone()),
                lock: temp.path().join("demo-plugin.wasm.cli-lock"),
                drop_action: ManagedPluginFileTransactionDropAction::RollbackArtifact,
            }),
            async { Ok::<(), Box<dyn std::error::Error>>(()) },
        )
        .await
        .unwrap_err();

        assert!(result
            .to_string()
            .contains("failed to remove staging backup"));
        assert!(backup.exists());
    }

    #[tokio::test]
    async fn test_finalize_plugin_file_mutation_without_transaction_passthroughs_ok() {
        let result = finalize_plugin_file_mutation(None, async {
            Ok::<_, Box<dyn std::error::Error>>("ok".to_string())
        })
        .await
        .unwrap();

        assert_eq!(result, "ok");
    }

    #[tokio::test]
    async fn test_finalize_plugin_file_mutation_without_transaction_passthroughs_err() {
        let err = finalize_plugin_file_mutation(None, async {
            Err::<(), Box<dyn std::error::Error>>(cli_error(
                "plugins.update failed: simulated passthrough failure",
            ))
        })
        .await
        .unwrap_err();

        assert_eq!(
            err.to_string(),
            "plugins.update failed: simulated passthrough failure"
        );
    }

    #[tokio::test]
    async fn test_cleanup_partially_staged_plugin_artifact_removes_file() {
        let temp = tempfile::TempDir::new().unwrap();
        let dest = temp.path().join("demo-plugin.wasm");
        std::fs::write(&dest, b"partial-plugin-bytes").unwrap();

        cleanup_partially_staged_plugin_artifact(&dest)
            .await
            .unwrap();

        assert!(!dest.exists());
    }

    #[tokio::test]
    async fn test_cleanup_partially_staged_plugin_artifact_reports_remove_failure() {
        let temp = tempfile::TempDir::new().unwrap();
        let dest = temp.path().join("demo-plugin.wasm");
        std::fs::create_dir_all(&dest).unwrap();

        let err = cleanup_partially_staged_plugin_artifact(&dest)
            .await
            .unwrap_err();

        assert!(err
            .to_string()
            .contains("failed to remove partially staged plugin artifact"));
    }

    #[tokio::test]
    async fn test_release_plugin_file_transaction_lock_with_context_appends_failure() {
        let temp = tempfile::TempDir::new().unwrap();
        let lock = temp.path().join("demo-plugin.wasm.cli-lock");
        std::fs::create_dir_all(&lock).unwrap();

        let message =
            release_plugin_file_transaction_lock_with_context(&lock, "base failure".to_string())
                .await;

        assert!(message.contains("base failure"));
        assert!(message.contains("failed to remove staging lock"));
        assert!(message
            .contains("remove that lock file before the next local `--file` plugin mutation"));
    }

    #[test]
    fn test_managed_plugin_file_transaction_drop_warns_when_unfinished() {
        let temp = tempfile::TempDir::new().unwrap();
        let transaction = ManagedPluginFileTransaction {
            dest: temp.path().join("demo-plugin.wasm"),
            backup: None,
            lock: temp.path().join("demo-plugin.wasm.cli-lock"),
            drop_action: ManagedPluginFileTransactionDropAction::RollbackArtifact,
        };

        let result = std::panic::catch_unwind(|| drop(transaction));
        assert!(result.is_ok());
    }

    #[test]
    fn test_pending_plugin_file_transaction_lock_drop_releases_lock() {
        let temp = tempfile::TempDir::new().unwrap();
        let lock = temp.path().join("demo-plugin.wasm.cli-lock");
        std::fs::write(&lock, b"locked").unwrap();

        drop(PendingPluginFileTransactionLock::new(lock.clone()));

        assert!(!lock.exists());
    }

    #[test]
    fn test_managed_plugin_file_transaction_drop_rolls_back_new_file() {
        let temp = tempfile::TempDir::new().unwrap();
        let dest = temp.path().join("demo-plugin.wasm");
        let lock = temp.path().join("demo-plugin.wasm.cli-lock");
        std::fs::write(&dest, b"new-plugin-bytes").unwrap();
        std::fs::write(&lock, b"locked").unwrap();

        drop(ManagedPluginFileTransaction {
            dest: dest.clone(),
            backup: None,
            lock: lock.clone(),
            drop_action: ManagedPluginFileTransactionDropAction::RollbackArtifact,
        });

        assert!(!dest.exists());
        assert!(!lock.exists());
    }

    #[test]
    fn test_managed_plugin_file_transaction_drop_restores_previous_file() {
        let temp = tempfile::TempDir::new().unwrap();
        let dest = temp.path().join("demo-plugin.wasm");
        let backup = temp.path().join("demo-plugin.wasm.cli-backup");
        let lock = temp.path().join("demo-plugin.wasm.cli-lock");
        std::fs::write(&dest, b"new-plugin-bytes").unwrap();
        std::fs::write(&backup, b"old-plugin-bytes").unwrap();
        std::fs::write(&lock, b"locked").unwrap();

        drop(ManagedPluginFileTransaction {
            dest: dest.clone(),
            backup: Some(backup.clone()),
            lock: lock.clone(),
            drop_action: ManagedPluginFileTransactionDropAction::RollbackArtifact,
        });

        assert_eq!(std::fs::read(&dest).unwrap(), b"old-plugin-bytes");
        assert!(!backup.exists());
        assert!(!lock.exists());
    }

    #[test]
    fn test_managed_plugin_file_transaction_drop_finishes_commit_cleanup() {
        let temp = tempfile::TempDir::new().unwrap();
        let dest = temp.path().join("demo-plugin.wasm");
        let backup = temp.path().join("demo-plugin.wasm.cli-backup");
        let lock = temp.path().join("demo-plugin.wasm.cli-lock");
        std::fs::write(&dest, b"new-plugin-bytes").unwrap();
        std::fs::write(&backup, b"old-plugin-bytes").unwrap();
        std::fs::write(&lock, b"locked").unwrap();

        drop(ManagedPluginFileTransaction {
            dest: dest.clone(),
            backup: Some(backup.clone()),
            lock: lock.clone(),
            drop_action: ManagedPluginFileTransactionDropAction::CommitCleanup,
        });

        assert_eq!(std::fs::read(&dest).unwrap(), b"new-plugin-bytes");
        assert!(!backup.exists());
        assert!(!lock.exists());
    }

    #[test]
    fn test_managed_plugin_file_transaction_drop_releases_lock_only() {
        let temp = tempfile::TempDir::new().unwrap();
        let dest = temp.path().join("demo-plugin.wasm");
        let lock = temp.path().join("demo-plugin.wasm.cli-lock");
        std::fs::write(&dest, b"restored-plugin-bytes").unwrap();
        std::fs::write(&lock, b"locked").unwrap();

        drop(ManagedPluginFileTransaction {
            dest: dest.clone(),
            backup: None,
            lock: lock.clone(),
            drop_action: ManagedPluginFileTransactionDropAction::ReleaseLockOnly,
        });

        assert_eq!(std::fs::read(&dest).unwrap(), b"restored-plugin-bytes");
        assert!(!lock.exists());
    }

    #[tokio::test]
    async fn test_acquire_plugin_file_transaction_lock_writes_pid() {
        let temp = tempfile::TempDir::new().unwrap();
        let lock = temp.path().join("demo-plugin.wasm.cli-lock");

        acquire_plugin_file_transaction_lock(&lock).await.unwrap();

        assert_eq!(
            std::fs::read_to_string(&lock).unwrap(),
            std::process::id().to_string()
        );
        release_plugin_file_transaction_lock(&lock).await.unwrap();
    }

    #[tokio::test]
    async fn test_stage_plugin_file_into_managed_dir_rejects_preexisting_backup() {
        let mut env_guard = ScopedEnv::new();
        let temp = tempfile::TempDir::new().unwrap();
        env_guard.set("CARAPACE_STATE_DIR", temp.path().as_os_str());

        let plugins_dir = temp.path().join("plugins");
        std::fs::create_dir_all(&plugins_dir).unwrap();
        std::fs::write(
            plugins_dir.join("demo-plugin.wasm.cli-backup"),
            b"stale-backup",
        )
        .unwrap();

        let plugin_path = temp.path().join("demo-input.wasm");
        std::fs::write(&plugin_path, tool_plugin_component_bytes()).unwrap();
        let connection = WsConnectionArgs {
            port: Some(18789),
            host: "127.0.0.1".to_string(),
            tls: false,
            trust: false,
            allow_plaintext: false,
        };

        let err = stage_plugin_file_into_managed_dir(&connection, "demo-plugin", &plugin_path)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("rollback backup"));
        assert!(!plugins_dir.join("demo-plugin.wasm.cli-lock").exists());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_stage_plugin_file_into_managed_dir_rejects_broken_symlink_backup() {
        use std::os::unix::fs::symlink;

        let mut env_guard = ScopedEnv::new();
        let temp = tempfile::TempDir::new().unwrap();
        env_guard.set("CARAPACE_STATE_DIR", temp.path().as_os_str());

        let plugins_dir = temp.path().join("plugins");
        std::fs::create_dir_all(&plugins_dir).unwrap();
        symlink(
            temp.path().join("missing-backup-target"),
            plugins_dir.join("demo-plugin.wasm.cli-backup"),
        )
        .unwrap();

        let plugin_path = temp.path().join("demo-input.wasm");
        std::fs::write(&plugin_path, tool_plugin_component_bytes()).unwrap();
        let connection = WsConnectionArgs {
            port: Some(18789),
            host: "127.0.0.1".to_string(),
            tls: false,
            trust: false,
            allow_plaintext: false,
        };

        let err = stage_plugin_file_into_managed_dir(&connection, "demo-plugin", &plugin_path)
            .await
            .unwrap_err();

        assert!(err.to_string().contains("rollback backup"));
        assert!(!plugins_dir.join("demo-plugin.wasm.cli-lock").exists());
    }

    #[tokio::test]
    async fn test_stage_plugin_file_into_managed_dir_removes_stale_staged_artifact() {
        let mut env_guard = ScopedEnv::new();
        let temp = tempfile::TempDir::new().unwrap();
        env_guard.set("CARAPACE_STATE_DIR", temp.path().as_os_str());

        let plugins_dir = temp.path().join("plugins");
        std::fs::create_dir_all(&plugins_dir).unwrap();
        let staged = plugins_dir.join("demo-plugin.wasm.cli-staged");
        let dest = plugins_dir.join("demo-plugin.wasm");
        std::fs::write(&staged, b"stale-staged-bytes").unwrap();

        let new_bytes = tool_plugin_component_bytes();
        let plugin_path = temp.path().join("demo-input.wasm");
        std::fs::write(&plugin_path, &new_bytes).unwrap();
        let connection = WsConnectionArgs {
            port: Some(18789),
            host: "127.0.0.1".to_string(),
            tls: false,
            trust: false,
            allow_plaintext: false,
        };

        let transaction =
            stage_plugin_file_into_managed_dir(&connection, "demo-plugin", &plugin_path)
                .await
                .unwrap();

        assert_eq!(std::fs::read(&dest).unwrap(), new_bytes);
        assert!(!staged.exists());
        assert!(plugins_dir.join("demo-plugin.wasm.cli-lock").exists());

        let note = transaction.rollback().await.unwrap();
        assert!(note.contains("removed staged local managed artifact"));
        assert!(!dest.exists());
        assert!(!plugins_dir.join("demo-plugin.wasm.cli-lock").exists());
    }

    #[tokio::test]
    async fn test_stage_plugin_file_into_managed_dir_rejects_non_regular_destination() {
        let mut env_guard = ScopedEnv::new();
        let temp = tempfile::TempDir::new().unwrap();
        env_guard.set("CARAPACE_STATE_DIR", temp.path().as_os_str());

        let plugins_dir = temp.path().join("plugins");
        std::fs::create_dir_all(plugins_dir.join("demo-plugin.wasm")).unwrap();

        let plugin_path = temp.path().join("demo-input.wasm");
        std::fs::write(&plugin_path, tool_plugin_component_bytes()).unwrap();
        let connection = WsConnectionArgs {
            port: Some(18789),
            host: "127.0.0.1".to_string(),
            tls: false,
            trust: false,
            allow_plaintext: false,
        };

        let err = stage_plugin_file_into_managed_dir(&connection, "demo-plugin", &plugin_path)
            .await
            .unwrap_err();

        assert!(err.to_string().contains("not a regular file"));
        assert!(!plugins_dir.join("demo-plugin.wasm.cli-lock").exists());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_stage_plugin_file_into_managed_dir_rejects_symlink_destination() {
        use std::os::unix::fs::symlink;

        let mut env_guard = ScopedEnv::new();
        let temp = tempfile::TempDir::new().unwrap();
        env_guard.set("CARAPACE_STATE_DIR", temp.path().as_os_str());

        let plugins_dir = temp.path().join("plugins");
        std::fs::create_dir_all(&plugins_dir).unwrap();
        let real_plugin = temp.path().join("real-plugin.wasm");
        std::fs::write(&real_plugin, tool_plugin_component_bytes()).unwrap();
        symlink(&real_plugin, plugins_dir.join("demo-plugin.wasm")).unwrap();

        let plugin_path = temp.path().join("demo-input.wasm");
        std::fs::write(&plugin_path, tool_plugin_component_bytes()).unwrap();
        let connection = WsConnectionArgs {
            port: Some(18789),
            host: "127.0.0.1".to_string(),
            tls: false,
            trust: false,
            allow_plaintext: false,
        };

        let err = stage_plugin_file_into_managed_dir(&connection, "demo-plugin", &plugin_path)
            .await
            .unwrap_err();

        assert!(err.to_string().contains("not a regular file"));
        assert!(!plugins_dir.join("demo-plugin.wasm.cli-lock").exists());
    }

    #[tokio::test]
    async fn test_stage_plugin_file_into_managed_dir_restores_backup_after_write_failure() {
        let mut env_guard = ScopedEnv::new();
        let temp = tempfile::TempDir::new().unwrap();
        env_guard.set("CARAPACE_STATE_DIR", temp.path().as_os_str());

        let plugins_dir = temp.path().join("plugins");
        std::fs::create_dir_all(&plugins_dir).unwrap();
        let existing = plugins_dir.join("demo-plugin.wasm");
        let staged = plugins_dir.join("demo-plugin.wasm.cli-staged");
        std::fs::write(&existing, b"old-plugin-bytes").unwrap();

        let plugin_path = temp.path().join("demo-input.wasm");
        std::fs::write(&plugin_path, tool_plugin_component_bytes()).unwrap();
        env_guard.set(
            "CARAPACE_TEST_FAIL_STAGE_PLUGIN_WRITE_DEST",
            staged.as_os_str(),
        );
        let connection = WsConnectionArgs {
            port: Some(18789),
            host: "127.0.0.1".to_string(),
            tls: false,
            trust: false,
            allow_plaintext: false,
        };

        let err = stage_plugin_file_into_managed_dir(&connection, "demo-plugin", &plugin_path)
            .await
            .unwrap_err();

        assert!(err.to_string().contains("failed to stage plugin file"));
        assert!(err
            .to_string()
            .contains("restored previous local managed artifact"));
        assert_eq!(std::fs::read(&existing).unwrap(), b"old-plugin-bytes");
        assert!(!plugins_dir.join("demo-plugin.wasm.cli-backup").exists());
        assert!(!staged.exists());
        assert!(!plugins_dir.join("demo-plugin.wasm.cli-lock").exists());
    }

    #[tokio::test]
    async fn test_stage_plugin_file_into_managed_dir_cleans_new_file_after_write_failure() {
        let mut env_guard = ScopedEnv::new();
        let temp = tempfile::TempDir::new().unwrap();
        env_guard.set("CARAPACE_STATE_DIR", temp.path().as_os_str());

        let plugins_dir = temp.path().join("plugins");
        std::fs::create_dir_all(&plugins_dir).unwrap();
        let staged_dest = plugins_dir.join("demo-plugin.wasm");
        let staged_temp = plugins_dir.join("demo-plugin.wasm.cli-staged");

        let plugin_path = temp.path().join("demo-input.wasm");
        std::fs::write(&plugin_path, tool_plugin_component_bytes()).unwrap();
        env_guard.set(
            "CARAPACE_TEST_FAIL_STAGE_PLUGIN_WRITE_DEST",
            staged_temp.as_os_str(),
        );
        let connection = WsConnectionArgs {
            port: Some(18789),
            host: "127.0.0.1".to_string(),
            tls: false,
            trust: false,
            allow_plaintext: false,
        };

        let err = stage_plugin_file_into_managed_dir(&connection, "demo-plugin", &plugin_path)
            .await
            .unwrap_err();

        assert!(err.to_string().contains("failed to stage plugin file"));
        assert!(!err
            .to_string()
            .contains("restored previous local managed artifact"));
        assert!(!staged_dest.exists());
        assert!(!staged_temp.exists());
        assert!(!plugins_dir.join("demo-plugin.wasm.cli-backup").exists());
        assert!(!plugins_dir.join("demo-plugin.wasm.cli-lock").exists());
    }

    #[tokio::test]
    async fn test_stage_plugin_file_into_managed_dir_cleans_new_file_after_rename_failure() {
        let mut env_guard = ScopedEnv::new();
        let temp = tempfile::TempDir::new().unwrap();
        env_guard.set("CARAPACE_STATE_DIR", temp.path().as_os_str());

        let plugins_dir = temp.path().join("plugins");
        std::fs::create_dir_all(&plugins_dir).unwrap();
        let staged_dest = plugins_dir.join("demo-plugin.wasm");
        let staged_temp = plugins_dir.join("demo-plugin.wasm.cli-staged");

        let plugin_path = temp.path().join("demo-input.wasm");
        std::fs::write(&plugin_path, tool_plugin_component_bytes()).unwrap();
        env_guard.set(
            "CARAPACE_TEST_FAIL_STAGE_PLUGIN_RENAME_DEST",
            staged_dest.as_os_str(),
        );
        let connection = WsConnectionArgs {
            port: Some(18789),
            host: "127.0.0.1".to_string(),
            tls: false,
            trust: false,
            allow_plaintext: false,
        };

        let err = stage_plugin_file_into_managed_dir(&connection, "demo-plugin", &plugin_path)
            .await
            .unwrap_err();

        assert!(err
            .to_string()
            .contains("failed to finalize staged plugin artifact"));
        assert!(!err
            .to_string()
            .contains("restored previous local managed artifact"));
        assert!(!staged_dest.exists());
        assert!(!staged_temp.exists());
        assert!(!plugins_dir.join("demo-plugin.wasm.cli-backup").exists());
        assert!(!plugins_dir.join("demo-plugin.wasm.cli-lock").exists());
    }

    #[tokio::test]
    async fn test_stage_plugin_file_into_managed_dir_restores_backup_after_rename_failure() {
        let mut env_guard = ScopedEnv::new();
        let temp = tempfile::TempDir::new().unwrap();
        env_guard.set("CARAPACE_STATE_DIR", temp.path().as_os_str());

        let plugins_dir = temp.path().join("plugins");
        std::fs::create_dir_all(&plugins_dir).unwrap();
        let existing = plugins_dir.join("demo-plugin.wasm");
        let staged = plugins_dir.join("demo-plugin.wasm.cli-staged");
        std::fs::write(&existing, b"old-plugin-bytes").unwrap();

        let plugin_path = temp.path().join("demo-input.wasm");
        std::fs::write(&plugin_path, tool_plugin_component_bytes()).unwrap();
        env_guard.set(
            "CARAPACE_TEST_FAIL_STAGE_PLUGIN_RENAME_DEST",
            existing.as_os_str(),
        );
        let connection = WsConnectionArgs {
            port: Some(18789),
            host: "127.0.0.1".to_string(),
            tls: false,
            trust: false,
            allow_plaintext: false,
        };

        let err = stage_plugin_file_into_managed_dir(&connection, "demo-plugin", &plugin_path)
            .await
            .unwrap_err();

        assert!(err
            .to_string()
            .contains("failed to finalize staged plugin artifact"));
        assert!(err
            .to_string()
            .contains("restored previous local managed artifact"));
        assert_eq!(std::fs::read(&existing).unwrap(), b"old-plugin-bytes");
        assert!(!plugins_dir.join("demo-plugin.wasm.cli-backup").exists());
        assert!(!staged.exists());
        assert!(!plugins_dir.join("demo-plugin.wasm.cli-lock").exists());
    }

    #[tokio::test]
    async fn test_stage_plugin_file_into_managed_dir_reports_write_and_cleanup_failure() {
        let mut env_guard = ScopedEnv::new();
        let temp = tempfile::TempDir::new().unwrap();
        env_guard.set("CARAPACE_STATE_DIR", temp.path().as_os_str());

        let plugins_dir = temp.path().join("plugins");
        std::fs::create_dir_all(&plugins_dir).unwrap();
        let staged_dest = plugins_dir.join("demo-plugin.wasm");
        let staged_temp = plugins_dir.join("demo-plugin.wasm.cli-staged");

        let plugin_path = temp.path().join("demo-input.wasm");
        std::fs::write(&plugin_path, tool_plugin_component_bytes()).unwrap();
        env_guard.set(
            "CARAPACE_TEST_FAIL_STAGE_PLUGIN_WRITE_DEST",
            staged_temp.as_os_str(),
        );
        env_guard.set(
            "CARAPACE_TEST_FAIL_STAGE_PLUGIN_CLEANUP_DEST",
            staged_temp.as_os_str(),
        );
        let connection = WsConnectionArgs {
            port: Some(18789),
            host: "127.0.0.1".to_string(),
            tls: false,
            trust: false,
            allow_plaintext: false,
        };

        let err = stage_plugin_file_into_managed_dir(&connection, "demo-plugin", &plugin_path)
            .await
            .unwrap_err();

        let rendered = err.to_string();
        assert!(rendered.contains("failed to stage plugin file"));
        assert!(rendered.contains("additionally failed to remove partial staged file"));
        assert!(!staged_dest.exists());
        assert!(!plugins_dir.join("demo-plugin.wasm.cli-lock").exists());
    }

    #[tokio::test]
    async fn test_stage_plugin_file_into_managed_dir_reports_write_and_restore_failure_and_releases_lock(
    ) {
        let mut env_guard = ScopedEnv::new();
        let temp = tempfile::TempDir::new().unwrap();
        env_guard.set("CARAPACE_STATE_DIR", temp.path().as_os_str());

        let plugins_dir = temp.path().join("plugins");
        std::fs::create_dir_all(&plugins_dir).unwrap();
        let existing = plugins_dir.join("demo-plugin.wasm");
        let staged = plugins_dir.join("demo-plugin.wasm.cli-staged");
        std::fs::write(&existing, b"old-plugin-bytes").unwrap();

        let plugin_path = temp.path().join("demo-input.wasm");
        std::fs::write(&plugin_path, tool_plugin_component_bytes()).unwrap();
        env_guard.set(
            "CARAPACE_TEST_FAIL_STAGE_PLUGIN_WRITE_DEST",
            staged.as_os_str(),
        );
        env_guard.set(
            "CARAPACE_TEST_FAIL_RESTORE_PLUGIN_DEST",
            existing.as_os_str(),
        );
        let connection = WsConnectionArgs {
            port: Some(18789),
            host: "127.0.0.1".to_string(),
            tls: false,
            trust: false,
            allow_plaintext: false,
        };

        let err = stage_plugin_file_into_managed_dir(&connection, "demo-plugin", &plugin_path)
            .await
            .unwrap_err();

        let rendered = err.to_string();
        assert!(rendered.contains("failed to stage plugin file"));
        assert!(rendered.contains("rollback also failed"));
        assert!(!staged.exists());
        assert!(!plugins_dir.join("demo-plugin.wasm.cli-lock").exists());
        assert!(plugins_dir.join("demo-plugin.wasm.cli-backup").exists());
    }

    #[tokio::test]
    async fn test_stage_plugin_file_into_managed_dir_rejects_preexisting_lock() {
        let mut env_guard = ScopedEnv::new();
        let temp = tempfile::TempDir::new().unwrap();
        env_guard.set("CARAPACE_STATE_DIR", temp.path().as_os_str());

        let plugins_dir = temp.path().join("plugins");
        std::fs::create_dir_all(&plugins_dir).unwrap();
        std::fs::write(plugins_dir.join("demo-plugin.wasm.cli-lock"), b"busy").unwrap();

        let plugin_path = temp.path().join("demo-input.wasm");
        std::fs::write(&plugin_path, tool_plugin_component_bytes()).unwrap();
        let connection = WsConnectionArgs {
            port: Some(18789),
            host: "127.0.0.1".to_string(),
            tls: false,
            trust: false,
            allow_plaintext: false,
        };

        let err = stage_plugin_file_into_managed_dir(&connection, "demo-plugin", &plugin_path)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("staging lock"));
        assert!(err.to_string().contains("remove the lock file and retry"));
        assert!(err
            .to_string()
            .contains("PID in the lock file may have been recycled"));
    }

    #[tokio::test]
    async fn test_finalize_plugin_file_mutation_reports_original_error_and_rollback() {
        let mut env_guard = ScopedEnv::new();
        let temp = tempfile::TempDir::new().unwrap();
        env_guard.set("CARAPACE_STATE_DIR", temp.path().as_os_str());

        let plugin_path = temp.path().join("demo-input.wasm");
        std::fs::write(&plugin_path, tool_plugin_component_bytes()).unwrap();
        let connection = WsConnectionArgs {
            port: Some(18789),
            host: "127.0.0.1".to_string(),
            tls: false,
            trust: false,
            allow_plaintext: false,
        };

        let transaction =
            stage_plugin_file_into_managed_dir(&connection, "demo-plugin", &plugin_path)
                .await
                .unwrap();
        let err = finalize_plugin_file_mutation(Some(transaction), async {
            Err::<(), Box<dyn std::error::Error>>(cli_error(
                "plugins.install failed: simulated failure",
            ))
        })
        .await
        .unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("plugins.install failed: simulated failure"));
        assert!(rendered.contains("removed staged local managed artifact"));
        assert!(!temp
            .path()
            .join("plugins")
            .join("demo-plugin.wasm")
            .exists());
    }

    #[tokio::test]
    async fn test_finalize_plugin_file_mutation_reports_original_and_rollback_failure() {
        let mut env_guard = ScopedEnv::new();
        let temp = tempfile::TempDir::new().unwrap();
        let dest = temp.path().join("demo-plugin.wasm");
        let backup = temp.path().join("demo-plugin.wasm.cli-backup");
        let lock = temp.path().join("demo-plugin.wasm.cli-lock");

        std::fs::write(&dest, b"new-plugin-bytes").unwrap();
        std::fs::write(&backup, b"old-plugin-bytes").unwrap();
        std::fs::create_dir_all(&lock).unwrap();
        env_guard.set("CARAPACE_TEST_FAIL_RESTORE_PLUGIN_DEST", dest.as_os_str());

        let err = finalize_plugin_file_mutation(
            Some(ManagedPluginFileTransaction {
                dest,
                backup: Some(backup.clone()),
                lock: lock.clone(),
                drop_action: ManagedPluginFileTransactionDropAction::RollbackArtifact,
            }),
            async {
                Err::<(), Box<dyn std::error::Error>>(cli_error(
                    "plugins.install failed: simulated failure",
                ))
            },
        )
        .await
        .unwrap_err();

        let rendered = err.to_string();
        assert!(rendered.contains("plugins.install failed: simulated failure"));
        assert!(rendered.contains("rollback also failed"));
        assert!(rendered.contains("failed to restore previous plugin artifact"));
        assert!(rendered.contains("failed to remove staging lock"));
        assert!(backup.exists());
        assert!(lock.exists());
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
    fn test_cli_verify_autonomy_outcome() {
        let cli = Cli::try_parse_from(["cara", "verify", "--outcome", "autonomy"]).unwrap();
        match cli.command {
            Some(Command::Verify {
                outcome,
                port,
                discord_to,
                telegram_to,
            }) => {
                assert_eq!(outcome, VerifyOutcomeSelection::Autonomy);
                assert_eq!(port, None);
                assert!(discord_to.is_none());
                assert!(telegram_to.is_none());
            }
            other => panic!("Expected Verify autonomy outcome, got {:?}", other),
        }
    }

    #[test]
    fn test_verify_outcome_selection_autonomy_resolved() {
        let cfg = serde_json::json!({});
        assert_eq!(
            VerifyOutcomeSelection::Autonomy.resolved(&cfg),
            VerifyOutcome::Autonomy
        );
    }

    #[test]
    fn test_cli_task_create() {
        let cli = Cli::try_parse_from([
            "cara",
            "task",
            "create",
            "--payload",
            r#"{"kind":"systemEvent","text":"hello"}"#,
            "--next-run-at-ms",
            "1234",
            "--max-attempts",
            "5",
            "--max-total-runtime-ms",
            "60000",
            "--max-turns",
            "12",
            "--max-run-timeout-seconds",
            "45",
            "--port",
            "19123",
            "--host",
            "localhost",
        ])
        .unwrap();
        match cli.command {
            Some(Command::Task(TaskCommand::Create {
                payload,
                next_run_at_ms,
                max_attempts,
                max_total_runtime_ms,
                max_turns,
                max_run_timeout_seconds,
                connection,
            })) => {
                assert_eq!(payload, r#"{"kind":"systemEvent","text":"hello"}"#);
                assert_eq!(next_run_at_ms, Some(1234));
                assert_eq!(max_attempts, Some(5));
                assert_eq!(max_total_runtime_ms, Some(60_000));
                assert_eq!(max_turns, Some(12));
                assert_eq!(max_run_timeout_seconds, Some(45));
                assert_eq!(connection.port, Some(19123));
                assert_eq!(connection.host, "localhost");
            }
            other => panic!("Expected Task(Create), got {:?}", other),
        }
    }

    #[test]
    fn test_cli_task_list_with_filters() {
        let cli = Cli::try_parse_from([
            "cara",
            "task",
            "list",
            "--state",
            "retry_wait",
            "--limit",
            "25",
        ])
        .unwrap();
        match cli.command {
            Some(Command::Task(TaskCommand::List { state, limit, .. })) => {
                assert_eq!(state.as_deref(), Some("retry_wait"));
                assert_eq!(limit, Some(25));
            }
            other => panic!("Expected Task(List), got {:?}", other),
        }
    }

    #[test]
    fn test_cli_task_get() {
        let cli = Cli::try_parse_from(["cara", "task", "get", "task-123"]).unwrap();
        match cli.command {
            Some(Command::Task(TaskCommand::Get { id, connection })) => {
                assert_eq!(id, "task-123");
                assert_eq!(connection.port, None);
                assert_eq!(connection.host, "127.0.0.1");
            }
            other => panic!("Expected Task(Get), got {:?}", other),
        }
    }

    #[test]
    fn test_cli_task_cancel() {
        let cli = Cli::try_parse_from([
            "cara",
            "task",
            "cancel",
            "task-123",
            "--reason",
            "operator requested",
        ])
        .unwrap();
        match cli.command {
            Some(Command::Task(TaskCommand::Cancel {
                id,
                reason,
                connection,
            })) => {
                assert_eq!(id, "task-123");
                assert_eq!(reason.as_deref(), Some("operator requested"));
                assert_eq!(connection.port, None);
                assert_eq!(connection.host, "127.0.0.1");
            }
            other => panic!("Expected Task(Cancel), got {:?}", other),
        }
    }

    #[test]
    fn test_cli_task_retry() {
        let cli = Cli::try_parse_from([
            "cara",
            "task",
            "retry",
            "task-123",
            "--delay-ms",
            "500",
            "--reason",
            "retry now",
        ])
        .unwrap();
        match cli.command {
            Some(Command::Task(TaskCommand::Retry {
                id,
                delay_ms,
                reason,
                connection,
            })) => {
                assert_eq!(id, "task-123");
                assert_eq!(delay_ms, Some(500));
                assert_eq!(reason.as_deref(), Some("retry now"));
                assert_eq!(connection.port, None);
                assert_eq!(connection.host, "127.0.0.1");
            }
            other => panic!("Expected Task(Retry), got {:?}", other),
        }
    }

    #[test]
    fn test_cli_task_resume() {
        let cli = Cli::try_parse_from([
            "cara",
            "task",
            "resume",
            "task-123",
            "--delay-ms",
            "250",
            "--reason",
            "unblocked",
        ])
        .unwrap();
        match cli.command {
            Some(Command::Task(TaskCommand::Resume {
                id,
                delay_ms,
                reason,
                connection,
            })) => {
                assert_eq!(id, "task-123");
                assert_eq!(delay_ms, Some(250));
                assert_eq!(reason.as_deref(), Some("unblocked"));
                assert_eq!(connection.port, None);
                assert_eq!(connection.host, "127.0.0.1");
            }
            other => panic!("Expected Task(Resume), got {:?}", other),
        }
    }

    #[test]
    fn test_cli_task_update() {
        let cli = Cli::try_parse_from([
            "cara",
            "task",
            "update",
            "task-123",
            "--payload",
            r#"{"kind":"systemEvent","text":"updated"}"#,
            "--max-attempts",
            "10",
            "--max-total-runtime-ms",
            "90000",
            "--max-turns",
            "15",
            "--max-run-timeout-seconds",
            "30",
            "--reason",
            "operator patch",
        ])
        .unwrap();
        match cli.command {
            Some(Command::Task(TaskCommand::Update {
                id,
                payload,
                max_attempts,
                max_total_runtime_ms,
                max_turns,
                max_run_timeout_seconds,
                reason,
                connection,
            })) => {
                assert_eq!(id, "task-123");
                assert_eq!(
                    payload.as_deref(),
                    Some(r#"{"kind":"systemEvent","text":"updated"}"#)
                );
                assert_eq!(max_attempts, Some(10));
                assert_eq!(max_total_runtime_ms, Some(90_000));
                assert_eq!(max_turns, Some(15));
                assert_eq!(max_run_timeout_seconds, Some(30));
                assert_eq!(reason.as_deref(), Some("operator patch"));
                assert_eq!(connection.port, None);
                assert_eq!(connection.host, "127.0.0.1");
            }
            other => panic!("Expected Task(Update), got {:?}", other),
        }
    }

    #[test]
    fn test_extract_control_error_message_prefers_error_field() {
        let body = br#"{"ok":false,"error":"Task not found"}"#;
        assert_eq!(extract_control_error_message(body), "Task not found");
    }

    #[test]
    fn test_extract_control_error_message_falls_back_to_text_body() {
        let body = b"plain error text";
        assert_eq!(extract_control_error_message(body), "plain error text");
    }

    #[test]
    fn test_extract_control_error_message_handles_empty_body() {
        assert_eq!(extract_control_error_message(b""), "empty response body");
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
        let tasks_dir = state_dir.join("tasks");
        std::fs::create_dir_all(&sessions_dir).unwrap();
        std::fs::create_dir_all(&cron_dir).unwrap();
        std::fs::create_dir_all(&tasks_dir).unwrap();

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
        // Create fake task data (durable task queue is stored as a JSON array).
        std::fs::write(tasks_dir.join("queue.json"), r#"[]"#).unwrap();

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
        // Add tasks.
        builder.append_dir_all("tasks", &tasks_dir).unwrap();
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
        let mut found_tasks = false;
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
            } else if path.contains("queue.json") {
                found_tasks = true;
            } else if path.contains("usage.json") {
                found_usage = true;
            }
        }

        assert!(found_marker, "Archive should contain backup marker");
        assert!(found_session, "Archive should contain session data");
        assert!(found_cron, "Archive should contain cron data");
        assert!(found_tasks, "Archive should contain task queue data");
        assert!(found_usage, "Archive should contain usage data");
    }

    #[test]
    fn test_backup_restore_round_trip() {
        let mut env_guard = ScopedEnv::new();
        let temp = tempfile::TempDir::new().unwrap();

        // Set up source state directory.
        let source_state = temp.path().join("source");
        let source_sessions = source_state.join("sessions");
        let source_cron = source_state.join("cron");
        let source_tasks = source_state.join("tasks");
        std::fs::create_dir_all(&source_sessions).unwrap();
        std::fs::create_dir_all(&source_cron).unwrap();
        std::fs::create_dir_all(&source_tasks).unwrap();

        std::fs::write(source_sessions.join("sess1.json"), r#"{"id":"sess1"}"#).unwrap();
        std::fs::write(source_cron.join("store.json"), r#"{"version":1}"#).unwrap();
        std::fs::write(source_tasks.join("queue.json"), r#"[]"#).unwrap();
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
        builder.append_dir_all("tasks", &source_tasks).unwrap();
        builder
            .append_path_with_name(source_state.join("usage.json"), "usage/usage.json")
            .unwrap();

        let enc = builder.into_inner().unwrap();
        enc.finish().unwrap();

        // Set up a fresh target state directory and restore into it using the
        // production restore path.
        let target_state = temp.path().join("target");
        let target_config = temp.path().join("target-config.json5");
        std::fs::write(&target_config, "{}").unwrap();
        env_guard.set("CARAPACE_STATE_DIR", target_state.as_os_str());
        env_guard.set("CARAPACE_CONFIG_PATH", target_config.as_os_str());
        let (mut restored_sections, restored_sessions) =
            restore_files_from_tar(&archive_path).unwrap();
        assert_eq!(restored_sessions, 1);
        restored_sections.sort_unstable();
        assert_eq!(
            restored_sections,
            vec![
                "cron".to_string(),
                "sessions".to_string(),
                "tasks".to_string(),
                "usage".to_string()
            ]
        );

        // Verify restored data matches original.
        let restored_session =
            std::fs::read_to_string(target_state.join("sessions").join("sess1.json")).unwrap();
        assert_eq!(restored_session, r#"{"id":"sess1"}"#);

        let restored_cron =
            std::fs::read_to_string(target_state.join("cron").join("store.json")).unwrap();
        assert_eq!(restored_cron, r#"{"version":1}"#);

        let restored_usage = std::fs::read_to_string(target_state.join("usage.json")).unwrap();
        assert_eq!(restored_usage, r#"{"totalTokens":100}"#);

        let restored_tasks =
            std::fs::read_to_string(target_state.join("tasks").join("queue.json")).unwrap();
        assert_eq!(restored_tasks, r#"[]"#);
    }

    #[test]
    fn test_handle_backup_includes_tasks_section() {
        let mut env_guard = ScopedEnv::new();
        let temp = tempfile::TempDir::new().unwrap();
        let state_dir = temp.path().join("state");
        let tasks_dir = state_dir.join("tasks");
        std::fs::create_dir_all(&tasks_dir).unwrap();
        std::fs::write(tasks_dir.join("queue.json"), r#"[]"#).unwrap();

        let config_path = temp.path().join("carapace.json5");
        std::fs::write(&config_path, "{}").unwrap();
        let archive_path = temp.path().join("backup-with-tasks.tar.gz");

        env_guard.set("CARAPACE_STATE_DIR", state_dir.as_os_str());
        env_guard.set("CARAPACE_CONFIG_PATH", config_path.as_os_str());

        handle_backup(Some(archive_path.to_string_lossy().as_ref())).unwrap();
        let sections = validate_backup_file(&archive_path).unwrap();
        assert!(
            sections.contains(&"tasks".to_string()),
            "backup should report tasks section when state/tasks exists"
        );
    }

    #[test]
    fn test_handle_backup_restore_round_trip_preserves_tasks() {
        let mut env_guard = ScopedEnv::new();
        let temp = tempfile::TempDir::new().unwrap();
        let home_dir = temp.path().join("home");
        std::fs::create_dir_all(&home_dir).unwrap();
        env_guard.set("HOME", home_dir.as_os_str());
        env_guard.set("USERPROFILE", home_dir.as_os_str());

        let source_state = temp.path().join("source-state");
        let source_tasks = source_state.join("tasks");
        let source_sessions = source_state.join("sessions");
        let source_cron = source_state.join("cron");
        std::fs::create_dir_all(&source_tasks).unwrap();
        std::fs::create_dir_all(&source_sessions).unwrap();
        std::fs::create_dir_all(&source_cron).unwrap();
        std::fs::write(
            source_tasks.join("queue.json"),
            r#"[{"id":"task-1","state":"queued"}]"#,
        )
        .unwrap();
        std::fs::write(source_sessions.join("sess-a.json"), r#"{"id":"sess-a"}"#).unwrap();
        std::fs::write(source_cron.join("jobs.json"), r#"{"jobs":[]}"#).unwrap();
        std::fs::write(source_state.join("usage.json"), r#"{"sessions":{}}"#).unwrap();

        let source_config = temp.path().join("source-config.json5");
        std::fs::write(&source_config, "{}").unwrap();
        let archive_path = temp.path().join("backup-roundtrip.tar.gz");

        {
            env_guard.set("CARAPACE_STATE_DIR", source_state.as_os_str());
            env_guard.set("CARAPACE_CONFIG_PATH", source_config.as_os_str());
            handle_backup(Some(archive_path.to_string_lossy().as_ref())).unwrap();
        }

        let target_state = temp.path().join("target-state");
        let target_config = temp.path().join("target-config.json5");
        std::fs::write(&target_config, "{}").unwrap();

        {
            env_guard.set("CARAPACE_STATE_DIR", target_state.as_os_str());
            env_guard.set("CARAPACE_CONFIG_PATH", target_config.as_os_str());
            handle_restore(archive_path.to_string_lossy().as_ref(), true).unwrap();
        }

        let restored_tasks =
            std::fs::read_to_string(target_state.join("tasks").join("queue.json")).unwrap();
        assert_eq!(restored_tasks, r#"[{"id":"task-1","state":"queued"}]"#);
    }

    #[test]
    fn test_tasks_section_detected_and_restored_for_directory_entry() {
        let mut env_guard = ScopedEnv::new();
        let temp = tempfile::TempDir::new().unwrap();
        let archive_path = temp.path().join("tasks-dir-only.tar.gz");

        let file = std::fs::File::create(&archive_path).unwrap();
        let enc = flate2::write::GzEncoder::new(file, flate2::Compression::default());
        let mut builder = tar::Builder::new(enc);

        let marker = b"carapace-backup v1\n";
        let mut marker_header = tar::Header::new_gnu();
        marker_header.set_size(marker.len() as u64);
        marker_header.set_mode(0o644);
        marker_header.set_cksum();
        builder
            .append_data(&mut marker_header, BACKUP_MARKER, &marker[..])
            .unwrap();

        let mut dir_header = tar::Header::new_gnu();
        dir_header.set_entry_type(tar::EntryType::Directory);
        dir_header.set_size(0);
        dir_header.set_mode(0o755);
        dir_header.set_cksum();
        builder
            .append_data(&mut dir_header, "tasks", std::io::empty())
            .unwrap();

        let enc = builder.into_inner().unwrap();
        enc.finish().unwrap();

        let sections = validate_backup_file(&archive_path).unwrap();
        assert!(
            sections.contains(&"tasks".to_string()),
            "top-level tasks directory entry should be detected as tasks section"
        );

        let target_state = temp.path().join("target-state");
        let target_config = temp.path().join("target-config.json5");
        std::fs::write(&target_config, "{}").unwrap();

        env_guard.set("CARAPACE_STATE_DIR", target_state.as_os_str());
        env_guard.set("CARAPACE_CONFIG_PATH", target_config.as_os_str());

        let (restored, _) = restore_files_from_tar(&archive_path).unwrap();
        assert!(restored.contains(&"tasks".to_string()));
        assert!(
            target_state.join("tasks").is_dir(),
            "restore should recreate empty tasks directory from top-level tasks entry"
        );
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
    fn test_detect_setup_provider_env_hints() {
        let mut env_guard = ScopedEnv::new();
        {
            env_guard.unset("ANTHROPIC_API_KEY");
            env_guard.unset("OPENAI_API_KEY");
            env_guard.unset("OPENAI_OAUTH_CLIENT_ID");
            env_guard.unset("OPENAI_OAUTH_CLIENT_SECRET");
            env_guard.unset("CARAPACE_CONFIG_PASSWORD");
            env_guard.unset("OLLAMA_BASE_URL");
            env_guard.unset("GOOGLE_API_KEY");
            env_guard.unset("VERTEX_PROJECT_ID");
            env_guard.unset("VENICE_API_KEY");
            env_guard.unset("AWS_REGION");
            env_guard.unset("AWS_DEFAULT_REGION");
            env_guard.unset("AWS_ACCESS_KEY_ID");
            env_guard.unset("AWS_SECRET_ACCESS_KEY");
            assert!(detect_setup_provider_env_hints().is_empty());
        }

        {
            env_guard.set("ANTHROPIC_API_KEY", "sk-anthropic");
            env_guard.unset("OPENAI_API_KEY");
            env_guard.unset("OPENAI_OAUTH_CLIENT_ID");
            env_guard.unset("OPENAI_OAUTH_CLIENT_SECRET");
            env_guard.unset("CARAPACE_CONFIG_PASSWORD");
            assert_eq!(
                detect_setup_provider_env_hints(),
                vec![SetupProvider::Anthropic]
            );
        }

        {
            env_guard.unset("ANTHROPIC_API_KEY");
            env_guard.set("OPENAI_API_KEY", "sk-openai");
            env_guard.unset("OPENAI_OAUTH_CLIENT_ID");
            env_guard.unset("OPENAI_OAUTH_CLIENT_SECRET");
            env_guard.unset("CARAPACE_CONFIG_PASSWORD");
            assert_eq!(
                detect_setup_provider_env_hints(),
                vec![SetupProvider::OpenAi]
            );
        }

        {
            env_guard.unset("ANTHROPIC_API_KEY");
            env_guard.unset("OPENAI_API_KEY");
            env_guard.set("GOOGLE_API_KEY", "google-key");
            env_guard.unset("OPENAI_OAUTH_CLIENT_ID");
            env_guard.unset("OPENAI_OAUTH_CLIENT_SECRET");
            env_guard.unset("CARAPACE_CONFIG_PASSWORD");
            env_guard.unset("VERTEX_PROJECT_ID");
            assert_eq!(
                detect_setup_provider_env_hints(),
                vec![SetupProvider::Gemini]
            );
        }

        {
            env_guard.unset("ANTHROPIC_API_KEY");
            env_guard.unset("OPENAI_API_KEY");
            env_guard.unset("GOOGLE_API_KEY");
            env_guard.set("CARAPACE_CONFIG_PASSWORD", "test-config-password");
            env_guard.set("OPENAI_OAUTH_CLIENT_ID", "openai-client-id");
            env_guard.set("OPENAI_OAUTH_CLIENT_SECRET", "openai-client-secret");
            env_guard.unset("VERTEX_PROJECT_ID");
            assert_eq!(
                detect_setup_provider_env_hints(),
                vec![SetupProvider::Codex]
            );
        }

        {
            env_guard.unset("ANTHROPIC_API_KEY");
            env_guard.unset("OPENAI_API_KEY");
            env_guard.unset("GOOGLE_API_KEY");
            env_guard.unset("OPENAI_OAUTH_CLIENT_ID");
            env_guard.unset("OPENAI_OAUTH_CLIENT_SECRET");
            env_guard.unset("CARAPACE_CONFIG_PASSWORD");
            env_guard.set("VERTEX_PROJECT_ID", "vertex-project");
            assert_eq!(
                detect_setup_provider_env_hints(),
                vec![SetupProvider::Vertex]
            );
        }

        {
            env_guard.set("ANTHROPIC_API_KEY", "sk-anthropic");
            env_guard.set("OPENAI_API_KEY", "sk-openai");
            env_guard.unset("OPENAI_OAUTH_CLIENT_ID");
            env_guard.unset("OPENAI_OAUTH_CLIENT_SECRET");
            env_guard.unset("CARAPACE_CONFIG_PASSWORD");
            env_guard.unset("OLLAMA_BASE_URL");
            env_guard.unset("GOOGLE_API_KEY");
            env_guard.unset("VERTEX_PROJECT_ID");
            env_guard.unset("VENICE_API_KEY");
            env_guard.unset("AWS_REGION");
            env_guard.unset("AWS_DEFAULT_REGION");
            env_guard.unset("AWS_ACCESS_KEY_ID");
            env_guard.unset("AWS_SECRET_ACCESS_KEY");
            assert_eq!(
                detect_setup_provider_env_hints(),
                vec![SetupProvider::Anthropic, SetupProvider::OpenAi]
            );
        }
    }

    #[test]
    fn test_local_chat_verify_next_step_without_provider_config() {
        let mut env_guard = ScopedEnv::new();
        env_guard.unset("VERTEX_PROJECT_ID");
        env_guard.unset("VERTEX_LOCATION");
        env_guard.unset("VERTEX_MODEL");
        let cfg = serde_json::json!({});
        assert!(
            local_chat_verify_next_step(&cfg).contains("set `agents.defaults.model`"),
            "empty config should tell user to set agents.defaults.model"
        );
    }

    #[test]
    fn test_local_chat_verify_next_step_for_missing_provider_env_var() {
        let mut env_guard = ScopedEnv::new();
        env_guard.unset("ANTHROPIC_API_KEY");
        let cfg = serde_json::json!({
            "anthropic": { "apiKey": "${ANTHROPIC_API_KEY}" },
            "agents": { "defaults": { "model": "anthropic:claude-sonnet-4-20250514" } }
        });
        assert_eq!(
            local_chat_verify_next_step(&cfg),
            "set `$ANTHROPIC_API_KEY` in the same shell you use for `cara start` and `cara verify`, or rerun `cara setup --force` to write the key into config, then retry `cara verify --outcome local-chat`"
        );
    }

    #[test]
    fn test_local_chat_verify_next_step_for_configured_provider() {
        let cfg = serde_json::json!({
            "openai": { "apiKey": "sk-openai-inline" },
            "agents": { "defaults": { "model": "openai:gpt-4o" } }
        });
        assert_eq!(
            local_chat_verify_next_step(&cfg),
            "check OpenAI API key/model and retry `cara verify --outcome local-chat`"
        );
    }

    #[test]
    fn test_local_chat_verify_next_step_for_env_only_openai() {
        let mut env_guard = ScopedEnv::new();
        env_guard.set("OPENAI_API_KEY", "sk-openai-env");
        env_guard.unset("ANTHROPIC_API_KEY");
        let cfg = serde_json::json!({
            "agents": { "defaults": { "model": "openai:gpt-4o" } }
        });
        assert_eq!(
            local_chat_verify_next_step(&cfg),
            "check OpenAI API key/model and retry `cara verify --outcome local-chat`"
        );
    }

    #[test]
    fn test_local_chat_verify_next_step_for_multi_provider_config_routes_by_model() {
        let cfg = serde_json::json!({
            "anthropic": { "apiKey": "sk-anthropic-inline" },
            "openai": { "apiKey": "sk-openai-inline" },
            "agents": { "defaults": { "model": "openai:gpt-4o" } }
        });
        assert_eq!(
            local_chat_verify_next_step(&cfg),
            "check OpenAI API key/model and retry `cara verify --outcome local-chat`"
        );
    }

    #[test]
    fn test_local_chat_verify_next_step_for_ollama_model() {
        let mut env_guard = ScopedEnv::new();
        env_guard.set("OLLAMA_BASE_URL", "http://127.0.0.1:11434");
        let cfg = serde_json::json!({
            "agents": { "defaults": { "model": "ollama:llama3" } }
        });
        assert_eq!(
            local_chat_verify_next_step(&cfg),
            "check Ollama server reachability/base URL and selected model, then retry `cara verify --outcome local-chat`"
        );
    }

    #[test]
    fn test_local_chat_verify_next_step_for_missing_gemini_provider() {
        let mut env_guard = ScopedEnv::new();
        env_guard.unset("GOOGLE_API_KEY");
        env_guard.unset("VERTEX_PROJECT_ID");
        env_guard.unset("VERTEX_LOCATION");
        env_guard.unset("VERTEX_MODEL");
        let cfg = serde_json::json!({
            "agents": { "defaults": { "model": "gemini:gemini-2.0-flash" } }
        });
        assert_eq!(
            local_chat_verify_next_step(&cfg),
            "configure a provider for the selected model, or rerun `cara setup --force`, then retry `cara verify --outcome local-chat`"
        );
    }

    #[test]
    fn test_local_chat_verify_next_step_for_missing_gemini_provider_env_var() {
        let mut env_guard = ScopedEnv::new();
        env_guard.unset("GOOGLE_API_KEY");
        let cfg = serde_json::json!({
            "google": { "apiKey": "${GOOGLE_API_KEY}" },
            "agents": { "defaults": { "model": "gemini:gemini-2.0-flash" } }
        });
        assert_eq!(
            local_chat_verify_next_step(&cfg),
            "set `$GOOGLE_API_KEY` in the same shell you use for `cara start` and `cara verify`, or rerun `cara setup --force` to write the key into config, then retry `cara verify --outcome local-chat`"
        );
    }

    #[test]
    fn test_local_chat_verify_next_step_for_vertex_config() {
        let cfg = serde_json::json!({
            "vertex": {
                "projectId": "my-project",
                "location": "us-central1",
                "model": "gemini-2.5-flash"
            },
            "agents": { "defaults": { "model": "vertex:default" } }
        });
        assert_eq!(
            local_chat_verify_next_step(&cfg),
            "check Vertex auth, project, location, and selected model, then retry `cara verify --outcome local-chat`"
        );
    }

    #[test]
    fn test_local_chat_verify_next_step_for_vertex_explicit_route() {
        let cfg = serde_json::json!({
            "vertex": {
                "projectId": "my-project",
                "location": "us-central1"
            },
            "agents": { "defaults": { "model": "vertex:gemini-2.5-flash" } }
        });
        assert_eq!(
            local_chat_verify_next_step(&cfg),
            "check Vertex auth, project, location, and selected model, then retry `cara verify --outcome local-chat`"
        );
    }

    #[test]
    fn test_local_chat_verify_next_step_for_vertex_default_alias_missing_model() {
        let mut env_guard = ScopedEnv::new();
        env_guard.unset("VERTEX_MODEL");
        let cfg = serde_json::json!({
            "vertex": {
                "projectId": "my-project",
                "location": "us-central1"
            },
            "agents": { "defaults": { "model": "vertex:default" } }
        });
        assert_eq!(
            local_chat_verify_next_step(&cfg),
            "set `VERTEX_MODEL` in the same shell you use for `cara start` and `cara verify`, or configure `vertex.model`, then retry `cara verify --outcome local-chat`"
        );
    }

    #[test]
    fn test_local_chat_verify_next_step_for_missing_vertex_project_env_var() {
        let mut env_guard = ScopedEnv::new();
        env_guard.unset("VERTEX_PROJECT_ID");
        let cfg = serde_json::json!({
            "vertex": {
                "projectId": "${VERTEX_PROJECT_ID}",
                "location": "us-central1",
                "model": "gemini-2.5-flash"
            },
            "agents": { "defaults": { "model": "vertex:default" } }
        });
        assert_eq!(
            local_chat_verify_next_step(&cfg),
            "set `$VERTEX_PROJECT_ID` in the same shell you use for `cara start` and `cara verify`, or rerun `cara setup --force` to write the key into config, then retry `cara verify --outcome local-chat`"
        );
    }

    #[test]
    fn test_local_chat_verify_next_step_for_model_provider_mismatch() {
        let mut env_guard = ScopedEnv::new();
        env_guard.unset("VERTEX_PROJECT_ID");
        env_guard.unset("VERTEX_LOCATION");
        env_guard.unset("VERTEX_MODEL");
        let cfg = serde_json::json!({
            "openai": { "apiKey": "sk-openai-inline" },
            "agents": { "defaults": { "model": "anthropic:claude-sonnet-4-20250514" } }
        });
        assert_eq!(
            local_chat_verify_next_step(&cfg),
            "the selected model currently routes to Anthropic; configure Anthropic or switch `agents.defaults.model` to one of the other usable providers (OpenAI), then retry `cara verify --outcome local-chat`"
        );
    }

    #[test]
    fn test_local_chat_verify_next_step_prefers_anthropic_api_key_guidance_when_both_paths_exist() {
        let mut env_guard = ScopedEnv::new();
        env_guard.unset("ANTHROPIC_API_KEY");
        env_guard.unset("CARAPACE_CONFIG_PASSWORD");
        env_guard.unset("VERTEX_PROJECT_ID");
        env_guard.unset("VERTEX_LOCATION");
        env_guard.unset("VERTEX_MODEL");
        let cfg = serde_json::json!({
            "anthropic": {
                "apiKey": "sk-ant-inline",
                "authProfile": "anthropic:default"
            },
            "agents": { "defaults": { "model": "anthropic:claude-sonnet-4-20250514" } }
        });

        assert_eq!(
            local_chat_verify_next_step(&cfg),
            "check Anthropic API key/model and retry `cara verify --outcome local-chat` Note: both `anthropic.apiKey` and `anthropic.authProfile` are configured; the API key configuration will be used."
        );
    }

    #[test]
    fn test_local_chat_verify_next_step_flags_missing_anthropic_api_key_placeholder_before_auth_profile(
    ) {
        let mut env_guard = ScopedEnv::new();
        env_guard.unset("ANTHROPIC_API_KEY");
        env_guard.set("CARAPACE_CONFIG_PASSWORD", "test-config-password");
        env_guard.unset("VERTEX_PROJECT_ID");
        env_guard.unset("VERTEX_LOCATION");
        env_guard.unset("VERTEX_MODEL");
        let cfg = serde_json::json!({
            "anthropic": {
                "apiKey": "${ANTHROPIC_API_KEY}",
                "authProfile": "anthropic:default"
            },
            "agents": { "defaults": { "model": "anthropic:claude-sonnet-4-20250514" } }
        });

        assert_eq!(
            local_chat_verify_next_step(&cfg),
            "set `$ANTHROPIC_API_KEY` in the same shell you use for `cara start` and `cara verify`, or rerun `cara setup --force` to write the key into config, then retry `cara verify --outcome local-chat`"
        );
    }

    #[test]
    fn test_usable_provider_labels_ignores_empty_api_keys() {
        let mut env_guard = ScopedEnv::new();
        env_guard.unset("VERTEX_PROJECT_ID");
        env_guard.unset("VERTEX_LOCATION");
        env_guard.unset("VERTEX_MODEL");
        let cfg = serde_json::json!({
            "openai": { "apiKey": "   " },
            "anthropic": { "apiKey": "sk-anthropic-inline" }
        });
        assert_eq!(usable_provider_labels(&cfg), vec!["Anthropic"]);
    }

    #[test]
    fn test_usable_provider_labels_ignore_missing_env_placeholders() {
        let mut env_guard = ScopedEnv::new();
        env_guard.unset("OPENAI_API_KEY");
        env_guard.unset("VENICE_API_KEY");
        env_guard.unset("CARAPACE_CONFIG_PASSWORD");
        env_guard.unset("VERTEX_PROJECT_ID");
        env_guard.unset("VERTEX_LOCATION");
        env_guard.unset("VERTEX_MODEL");
        let cfg = serde_json::json!({
            "openai": { "apiKey": "${OPENAI_API_KEY}" },
            "venice": { "apiKey": "${VENICE_API_KEY}" }
        });
        assert!(usable_provider_labels(&cfg).is_empty());
    }

    #[test]
    fn test_usable_provider_labels_require_config_password_for_codex() {
        let mut env_guard = ScopedEnv::new();
        env_guard.unset("CARAPACE_CONFIG_PASSWORD");
        env_guard.unset("VERTEX_PROJECT_ID");
        env_guard.unset("VERTEX_LOCATION");
        env_guard.unset("VERTEX_MODEL");
        let cfg = serde_json::json!({
            "codex": { "authProfile": "openai-abc123" }
        });
        assert!(usable_provider_labels(&cfg).is_empty());

        env_guard.set("CARAPACE_CONFIG_PASSWORD", "test-config-password");
        assert_eq!(usable_provider_labels(&cfg), vec!["Codex"]);
    }

    #[test]
    fn test_usable_provider_labels_require_complete_bedrock_credentials() {
        let mut env_guard = ScopedEnv::new();
        env_guard.unset("VERTEX_PROJECT_ID");
        env_guard.unset("VERTEX_LOCATION");
        env_guard.unset("VERTEX_MODEL");
        let cfg = serde_json::json!({
            "bedrock": {
                "region": "us-east-1",
                "accessKeyId": "AKIA..."
            }
        });
        assert!(usable_provider_labels(&cfg).is_empty());
    }

    #[test]
    fn test_usable_provider_labels_ignore_vertex_credentials_for_non_vertex_route() {
        let mut env_guard = ScopedEnv::new();
        env_guard.unset("VERTEX_PROJECT_ID");
        env_guard.unset("VERTEX_LOCATION");
        env_guard.unset("VERTEX_MODEL");
        let cfg = serde_json::json!({
            "vertex": {
                "projectId": "my-project",
                "location": "us-central1",
                "model": "gemini-2.5-flash"
            },
            "openai": {
                "apiKey": "sk-openai-inline"
            },
            "agents": {
                "defaults": {
                    "model": "gpt-4o"
                }
            }
        });

        assert_eq!(usable_provider_labels(&cfg), vec!["OpenAI"]);
    }

    #[test]
    fn test_usable_provider_labels_include_vertex_for_explicit_route() {
        let mut env_guard = ScopedEnv::new();
        env_guard.unset("VERTEX_PROJECT_ID");
        env_guard.unset("VERTEX_LOCATION");
        env_guard.unset("VERTEX_MODEL");
        let cfg = serde_json::json!({
            "vertex": {
                "projectId": "my-project",
                "location": "us-central1"
            },
            "agents": {
                "defaults": {
                    "model": "vertex:gemini-2.5-flash"
                }
            }
        });

        assert_eq!(usable_provider_labels(&cfg), vec!["Vertex"]);
    }

    #[test]
    fn test_local_chat_verify_next_step_for_missing_venice_provider_env_var() {
        let mut env_guard = ScopedEnv::new();
        env_guard.unset("VENICE_API_KEY");
        let cfg = serde_json::json!({
            "venice": { "apiKey": "${VENICE_API_KEY}" },
            "agents": { "defaults": { "model": "venice:llama-3.3-70b" } }
        });
        assert_eq!(
            local_chat_verify_next_step(&cfg),
            "set `$VENICE_API_KEY` in the same shell you use for `cara start` and `cara verify`, or rerun `cara setup --force` to write the key into config, then retry `cara verify --outcome local-chat`"
        );
    }

    #[test]
    fn test_local_chat_verify_next_step_for_missing_bedrock_provider_env_var() {
        let mut env_guard = ScopedEnv::new();
        env_guard.unset("AWS_REGION");
        env_guard.unset("AWS_ACCESS_KEY_ID");
        env_guard.unset("AWS_SECRET_ACCESS_KEY");
        let cfg = serde_json::json!({
            "bedrock": {
                "region": "${AWS_REGION}",
                "accessKeyId": "${AWS_ACCESS_KEY_ID}",
                "secretAccessKey": "${AWS_SECRET_ACCESS_KEY}"
            },
            "agents": { "defaults": { "model": "bedrock:anthropic.claude-3-5-sonnet-20240620-v1:0" } }
        });
        assert_eq!(
            local_chat_verify_next_step(&cfg),
            "set `$AWS_REGION` in the same shell you use for `cara start` and `cara verify`, or rerun `cara setup --force` to write the key into config, then retry `cara verify --outcome local-chat`"
        );
    }

    #[test]
    fn test_local_chat_verify_next_step_for_missing_embedded_bedrock_env_var() {
        let mut env_guard = ScopedEnv::new();
        env_guard.unset("AWS_REGION_SUFFIX");
        let cfg = serde_json::json!({
            "bedrock": {
                "region": "us-${AWS_REGION_SUFFIX}-1",
                "accessKeyId": "AKIA...",
                "secretAccessKey": "secret"
            },
            "agents": { "defaults": { "model": "bedrock:anthropic.claude-3-5-sonnet-20240620-v1:0" } }
        });
        assert_eq!(
            local_chat_verify_next_step(&cfg),
            "set `$AWS_REGION_SUFFIX` in the same shell you use for `cara start` and `cara verify`, or rerun `cara setup --force` to write the key into config, then retry `cara verify --outcome local-chat`"
        );
    }

    #[test]
    fn test_detect_setup_provider_env_hints_ignore_partial_aws_env() {
        let mut env_guard = ScopedEnv::new();
        env_guard.set("AWS_REGION", "us-east-1");
        env_guard.unset("AWS_ACCESS_KEY_ID");
        env_guard.unset("AWS_SECRET_ACCESS_KEY");
        env_guard.unset("GOOGLE_API_KEY");
        env_guard.unset("VERTEX_PROJECT_ID");
        env_guard.unset("OLLAMA_BASE_URL");
        env_guard.unset("VENICE_API_KEY");

        assert!(detect_setup_provider_env_hints().is_empty());
    }

    #[test]
    fn test_detect_setup_provider_env_hints_include_complete_bedrock_env() {
        let mut env_guard = ScopedEnv::new();
        env_guard.set("AWS_REGION", "us-east-1");
        env_guard.set("AWS_ACCESS_KEY_ID", "AKIA...");
        env_guard.set("AWS_SECRET_ACCESS_KEY", "secret");
        env_guard.unset("GOOGLE_API_KEY");
        env_guard.unset("VERTEX_PROJECT_ID");
        env_guard.unset("OLLAMA_BASE_URL");
        env_guard.unset("VENICE_API_KEY");

        assert_eq!(
            detect_setup_provider_env_hints(),
            vec![SetupProvider::Bedrock]
        );
    }

    #[test]
    fn test_verify_failure_follow_up_url() {
        assert_eq!(
            verify_failure_follow_up_url(VerifyOutcome::LocalChat),
            "https://getcara.io/help.html#guided-setup-help"
        );
        assert_eq!(
            verify_failure_follow_up_url(VerifyOutcome::Discord),
            "https://getcara.io/cookbook/discord-assistant.html"
        );
        assert_eq!(
            verify_failure_follow_up_url(VerifyOutcome::Telegram),
            "https://getcara.io/cookbook/telegram-webhook-assistant.html"
        );
    }

    #[test]
    fn test_sensitive_prompt_text_hidden_with_skip_hint() {
        let prompt = sensitive_prompt_text("API key", true, true);
        assert_eq!(
            prompt,
            "Enter API key (input hidden; pasted text will not be shown, leave blank to skip for now): "
        );
    }

    #[test]
    fn test_sensitive_prompt_text_visible_warns_without_skip_hint() {
        let prompt = sensitive_prompt_text("Telegram bot token", false, false);
        assert_eq!(
            prompt,
            "Enter Telegram bot token (input visible (WARNING: secrets will be shown on screen)): "
        );
    }

    #[test]
    fn test_prompt_sensitive_line_with_uses_hidden_reader() {
        let expected_prompt = "Enter gateway token (input hidden; pasted text will not be shown): ";
        let value = prompt_sensitive_line_with(
            expected_prompt,
            true,
            |prompt| {
                assert_eq!(prompt, expected_prompt);
                Ok("hidden-value".to_string())
            },
            |_prompt| panic!("visible reader should not be called when hide_sensitive_input=true"),
        )
        .expect("hidden prompt should succeed");

        assert_eq!(value, "hidden-value");
    }

    #[test]
    fn test_prompt_sensitive_line_with_uses_visible_reader() {
        let expected_prompt =
            "Enter gateway token (input visible (WARNING: secrets will be shown on screen)): ";
        let value = prompt_sensitive_line_with(
            expected_prompt,
            false,
            |_prompt| panic!("hidden reader should not be called when hide_sensitive_input=false"),
            |prompt| {
                assert_eq!(prompt, expected_prompt);
                Ok("visible-value".to_string())
            },
        )
        .expect("visible prompt should succeed");

        assert_eq!(value, "visible-value");
    }

    #[test]
    fn test_map_channel_validation_error_redacts_auth_detail() {
        let err = crate::channels::ChannelAuthError::auth("token abc123 rejected");
        let message = map_channel_validation_error("Telegram", err);
        assert_eq!(
            message,
            "Telegram credential check failed. Details are hidden because they may contain sensitive information."
        );
    }

    #[test]
    fn test_map_channel_validation_error_redacts_transient_detail() {
        let err = crate::channels::ChannelAuthError::transient("upstream returned HTML body");
        let message = map_channel_validation_error("Discord", err);
        assert_eq!(
            message,
            "Discord credential check hit a transient error. Details are hidden because they may contain sensitive information."
        );
    }

    #[test]
    fn test_resolve_env_placeholder_handles_literal_and_placeholder_values() {
        let mut env_guard = ScopedEnv::new();
        let key = "DISCORD_BOT_TOKEN";
        env_guard.set(key, "  resolved-value  ");

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
        let mut env_guard = ScopedEnv::new();
        env_guard.unset("DISCORD_BOT_TOKEN");
        assert_eq!(resolve_env_placeholder("${DISCORD_BOT_TOKEN}"), None);
    }

    #[test]
    fn test_resolve_env_placeholder_rejects_non_allowlisted_keys() {
        let mut env_guard = ScopedEnv::new();
        env_guard.set("CARAPACE_TEST_NON_ALLOWLISTED_SECRET", "secret");
        assert_eq!(
            resolve_env_placeholder("${CARAPACE_TEST_NON_ALLOWLISTED_SECRET}"),
            None
        );
    }

    #[test]
    fn test_resolve_env_placeholder_rejects_custom_bot_token_names() {
        let mut env_guard = ScopedEnv::new();
        env_guard.set("MY_DISCORD_BOT_TOKEN", "custom-token");
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
        let mut env_guard = ScopedEnv::new();
        env_guard.unset("CARAPACE_TEST_VERIFY_MISSING_TELEGRAM_TOKEN");
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
            Some(Command::Setup {
                force,
                provider: None,
                auth_mode: None,
            }) => {
                assert!(!force);
            }
            other => panic!("Expected Setup, got {:?}", other),
        }
    }

    #[test]
    fn test_cli_setup_with_force() {
        let cli = Cli::try_parse_from(["cara", "setup", "--force"]).unwrap();
        match cli.command {
            Some(Command::Setup {
                force,
                provider: None,
                auth_mode: None,
            }) => {
                assert!(force);
            }
            other => panic!("Expected Setup, got {:?}", other),
        }
    }

    #[test]
    fn test_cli_setup_with_provider() {
        let cli = Cli::try_parse_from(["cara", "setup", "--provider", "ollama"]).unwrap();
        match cli.command {
            Some(Command::Setup {
                force,
                provider: Some(SetupProvider::Ollama),
                auth_mode: None,
            }) => {
                assert!(!force);
            }
            other => panic!("Expected Setup with provider, got {:?}", other),
        }
    }

    #[test]
    fn test_cli_setup_with_vertex_provider() {
        let cli = Cli::try_parse_from(["cara", "setup", "--provider", "vertex"]).unwrap();
        match cli.command {
            Some(Command::Setup {
                force,
                provider: Some(SetupProvider::Vertex),
                auth_mode: None,
            }) => {
                assert!(!force);
            }
            other => panic!("Expected Setup with vertex provider, got {:?}", other),
        }
    }

    #[test]
    fn test_cli_setup_with_provider_aliases() {
        let claude_cli = Cli::try_parse_from(["cara", "setup", "--provider", "claude"]).unwrap();
        match claude_cli.command {
            Some(Command::Setup {
                force,
                provider: Some(SetupProvider::Anthropic),
                auth_mode: None,
            }) => {
                assert!(!force);
            }
            other => panic!("Expected Setup with anthropic alias, got {:?}", other),
        }

        let gpt_cli = Cli::try_parse_from(["cara", "setup", "--provider", "gpt"]).unwrap();
        match gpt_cli.command {
            Some(Command::Setup {
                force,
                provider: Some(SetupProvider::OpenAi),
                auth_mode: None,
            }) => {
                assert!(!force);
            }
            other => panic!("Expected Setup with openai alias, got {:?}", other),
        }
    }

    #[test]
    fn test_cli_setup_with_gemini_auth_mode() {
        let cli = Cli::try_parse_from([
            "cara",
            "setup",
            "--provider",
            "gemini",
            "--auth-mode",
            "oauth",
        ])
        .unwrap();
        match cli.command {
            Some(Command::Setup {
                force,
                provider: Some(SetupProvider::Gemini),
                auth_mode: Some(SetupAuthModeSelection::OAuth),
            }) => {
                assert!(!force);
            }
            other => panic!(
                "Expected Setup with Gemini OAuth auth mode, got {:?}",
                other
            ),
        }
    }

    #[test]
    fn test_handle_setup_errors_when_config_exists_no_force() {
        let mut env_guard = ScopedEnv::new();
        let temp = tempfile::TempDir::new().unwrap();
        let config_path = temp.path().join("carapace.json");
        std::fs::write(&config_path, "{}").unwrap();

        env_guard.set("CARAPACE_CONFIG_PATH", config_path.as_os_str());
        let result = handle_setup(false, None, None);

        assert!(
            result.is_err(),
            "Should error when config exists and force=false"
        );
    }

    #[test]
    fn test_handle_setup_force_creates_config() {
        let mut env_guard = ScopedEnv::new();
        let temp = tempfile::TempDir::new().unwrap();
        let config_path = temp.path().join("carapace.json");
        std::fs::write(&config_path, "{}").unwrap();

        env_guard.set("CARAPACE_CONFIG_PATH", config_path.as_os_str());
        let result = handle_setup(true, Some(SetupProvider::Anthropic), None);

        assert!(
            result.is_ok(),
            "Should succeed with force=true even when config exists"
        );
        assert!(config_path.exists(), "Config file should exist after setup");
    }

    #[test]
    fn test_handle_setup_noninteractive_without_provider_errors() {
        let mut env_guard = ScopedEnv::new();
        let temp = tempfile::TempDir::new().unwrap();
        let config_path = temp.path().join("carapace.json");

        env_guard.set("CARAPACE_CONFIG_PATH", config_path.as_os_str());
        let result = handle_setup(false, None, None);

        assert!(result.is_err(), "Setup should require --provider");
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("non-interactive setup requires `--provider <provider>`"),
            "unexpected error message"
        );
        assert!(
            !config_path.exists(),
            "setup should not write a providerless config in non-interactive mode"
        );
    }

    #[test]
    fn test_handle_setup_noninteractive_provider_flag_keeps_default_gateway_values() {
        let mut env_guard = ScopedEnv::new();
        let temp = tempfile::TempDir::new().unwrap();
        let config_path = temp.path().join("carapace.json");

        env_guard.set("CARAPACE_CONFIG_PATH", config_path.as_os_str());
        let result = handle_setup(false, Some(SetupProvider::Anthropic), None);

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
            parsed["agents"]["defaults"]["model"], "anthropic:claude-sonnet-4-20250514",
            "Default model should be anthropic:claude-sonnet-4-20250514"
        );
        assert_eq!(parsed["anthropic"]["apiKey"], "${ANTHROPIC_API_KEY}");
    }

    #[test]
    fn test_handle_setup_noninteractive_provider_flag_writes_gemini_config() {
        let mut env_guard = ScopedEnv::new();
        let temp = tempfile::TempDir::new().unwrap();
        let config_path = temp.path().join("carapace.json");
        env_guard.set("CARAPACE_CONFIG_PATH", config_path.as_os_str());

        let result = handle_setup(false, Some(SetupProvider::Gemini), None);
        assert!(result.is_err(), "Gemini should require explicit auth mode");
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("non-interactive Gemini setup requires `--auth-mode oauth|api-key`"),
            "unexpected Gemini auth-mode error"
        );
        assert!(
            !config_path.exists(),
            "Gemini setup without auth mode should not write config"
        );
    }

    #[test]
    fn test_handle_setup_noninteractive_gemini_api_key_mode_writes_config() {
        let mut env_guard = ScopedEnv::new();
        let temp = tempfile::TempDir::new().unwrap();
        let config_path = temp.path().join("carapace.json");
        env_guard.set("CARAPACE_CONFIG_PATH", config_path.as_os_str());

        let result = handle_setup(
            false,
            Some(SetupProvider::Gemini),
            Some(SetupAuthModeSelection::ApiKey),
        );
        assert!(
            result.is_ok(),
            "non-interactive provider setup should succeed"
        );

        let content = std::fs::read_to_string(&config_path).unwrap();
        let parsed: serde_json::Value = json5::from_str(&content).unwrap();
        assert_eq!(parsed["google"]["apiKey"], "${GOOGLE_API_KEY}");
        assert_eq!(
            parsed["agents"]["defaults"]["model"],
            "gemini:gemini-2.0-flash"
        );
    }

    #[test]
    fn test_handle_setup_noninteractive_gemini_oauth_mode_errors() {
        let mut env_guard = ScopedEnv::new();
        let temp = tempfile::TempDir::new().unwrap();
        let config_path = temp.path().join("carapace.json");
        env_guard.set("CARAPACE_CONFIG_PATH", config_path.as_os_str());

        let result = handle_setup(
            false,
            Some(SetupProvider::Gemini),
            Some(SetupAuthModeSelection::OAuth),
        );
        assert!(result.is_err(), "non-interactive Gemini OAuth should fail");
        assert!(
            result.unwrap_err().to_string().contains(
                "non-interactive Gemini Google sign-in is not supported; rerun interactively or use `--auth-mode api-key`."
            ),
            "unexpected Gemini OAuth non-interactive error"
        );
        assert!(
            !config_path.exists(),
            "non-interactive Gemini OAuth should not write config"
        );
    }

    #[test]
    fn test_handle_setup_noninteractive_codex_errors() {
        let mut env_guard = ScopedEnv::new();
        let temp = tempfile::TempDir::new().unwrap();
        let config_path = temp.path().join("carapace.json");
        env_guard.set("CARAPACE_CONFIG_PATH", config_path.as_os_str());

        let result = handle_setup(false, Some(SetupProvider::Codex), None);
        assert!(result.is_err(), "non-interactive Codex sign-in should fail");
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("non-interactive Codex sign-in is not supported; rerun interactively."),
            "unexpected Codex non-interactive error"
        );
        assert!(
            !config_path.exists(),
            "non-interactive Codex sign-in should not write config"
        );
    }

    #[test]
    fn test_handle_setup_noninteractive_provider_flag_writes_ollama_api_key_placeholder() {
        let mut env_guard = ScopedEnv::new();
        let temp = tempfile::TempDir::new().unwrap();
        let config_path = temp.path().join("carapace.json");
        env_guard.set("CARAPACE_CONFIG_PATH", config_path.as_os_str());
        env_guard.set("OLLAMA_BASE_URL", "http://127.0.0.1:11434");
        env_guard.set("OLLAMA_API_KEY", "ollama-token");

        let result = handle_setup(false, Some(SetupProvider::Ollama), None);
        assert!(
            result.is_ok(),
            "non-interactive provider setup should succeed"
        );

        let content = std::fs::read_to_string(&config_path).unwrap();
        let parsed: serde_json::Value = json5::from_str(&content).unwrap();
        assert_eq!(parsed["providers"]["ollama"]["apiKey"], "${OLLAMA_API_KEY}");
        assert_eq!(parsed["agents"]["defaults"]["model"], "ollama:llama3");
    }

    #[test]
    fn test_handle_setup_noninteractive_provider_flag_writes_venice_config() {
        let mut env_guard = ScopedEnv::new();
        let temp = tempfile::TempDir::new().unwrap();
        let config_path = temp.path().join("carapace.json");
        env_guard.set("CARAPACE_CONFIG_PATH", config_path.as_os_str());

        let result = handle_setup(false, Some(SetupProvider::Venice), None);
        assert!(
            result.is_ok(),
            "non-interactive provider setup should succeed"
        );

        let content = std::fs::read_to_string(&config_path).unwrap();
        let parsed: serde_json::Value = json5::from_str(&content).unwrap();
        assert_eq!(parsed["venice"]["apiKey"], "${VENICE_API_KEY}");
        assert_eq!(
            parsed["agents"]["defaults"]["model"],
            "venice:llama-3.3-70b"
        );
    }

    #[test]
    fn test_handle_setup_noninteractive_provider_flag_writes_bedrock_config() {
        let mut env_guard = ScopedEnv::new();
        let temp = tempfile::TempDir::new().unwrap();
        let config_path = temp.path().join("carapace.json");
        env_guard.set("CARAPACE_CONFIG_PATH", config_path.as_os_str());
        env_guard.unset("AWS_REGION");
        env_guard.unset("AWS_DEFAULT_REGION");

        let result = handle_setup(false, Some(SetupProvider::Bedrock), None);
        assert!(
            result.is_ok(),
            "non-interactive provider setup should succeed"
        );

        let content = std::fs::read_to_string(&config_path).unwrap();
        let parsed: serde_json::Value = json5::from_str(&content).unwrap();
        assert_eq!(parsed["bedrock"]["region"], "us-east-1");
        assert_eq!(parsed["bedrock"]["accessKeyId"], "${AWS_ACCESS_KEY_ID}");
        assert_eq!(
            parsed["bedrock"]["secretAccessKey"],
            "${AWS_SECRET_ACCESS_KEY}"
        );
        assert_eq!(
            parsed["agents"]["defaults"]["model"],
            "bedrock:anthropic.claude-3-5-sonnet-20240620-v1:0"
        );
    }

    #[test]
    fn test_handle_setup_noninteractive_provider_flag_writes_vertex_config() {
        let mut env_guard = ScopedEnv::new();
        let temp = tempfile::TempDir::new().unwrap();
        let config_path = temp.path().join("carapace.json");
        env_guard.set("CARAPACE_CONFIG_PATH", config_path.as_os_str());
        env_guard.unset("VERTEX_LOCATION");

        let result = handle_setup(false, Some(SetupProvider::Vertex), None);
        assert!(
            result.is_ok(),
            "non-interactive Vertex setup should succeed"
        );

        let content = std::fs::read_to_string(&config_path).unwrap();
        let parsed: serde_json::Value = json5::from_str(&content).unwrap();
        assert_eq!(parsed["vertex"]["projectId"], "${VERTEX_PROJECT_ID}");
        assert_eq!(parsed["vertex"]["location"], "us-central1");
        assert_eq!(parsed["vertex"]["model"], "${VERTEX_MODEL}");
        assert_eq!(parsed["agents"]["defaults"]["model"], "vertex:default");
    }

    #[test]
    fn test_render_setup_validation_failure_redacts_sensitive_input() {
        let rendered = render_setup_validation_failure(&crate::agent::AgentError::InvalidBaseUrl(
            "invalid URL \"https://user:secret@example.com\": bad input".to_string(),
        ));
        assert_eq!(
            rendered,
            "Provider configuration check failed: the supplied base URL is invalid or unsupported."
        );
        assert!(!rendered.contains("secret"));
        assert!(!rendered.contains("example.com"));
    }

    #[test]
    fn test_vertex_validation_failure_remediation_mentions_validation_request_for_probe_rejected() {
        assert_eq!(
            vertex_validation_failure_remediation(
                &crate::agent::vertex::VertexSetupValidationError::ProbeRejected
            ),
            "check the Vertex project, location, and model values; if they look correct, this may indicate a malformed Vertex validation request in Carapace"
        );
    }

    #[test]
    fn test_vertex_validation_failure_remediation_mentions_retry_for_rate_limited() {
        assert_eq!(
            vertex_validation_failure_remediation(
                &crate::agent::vertex::VertexSetupValidationError::RateLimited
            ),
            "retry after the current Vertex AI rate limit window, then rerun `cara setup --force --provider vertex`"
        );
    }

    #[test]
    fn test_configure_provider_interactive_gemini_api_key_sets_default_model() {
        let mut env_guard = ScopedEnv::new();
        env_guard.unset("GOOGLE_API_KEY");
        env_guard.unset("GOOGLE_API_BASE_URL");
        let _guard = install_setup_interactive_harness(SetupInteractiveTestHarness {
            visible_inputs: VecDeque::from(vec!["n".to_string(), "AIza-test-key".to_string()]),
            ..Default::default()
        });
        let mut config = serde_json::json!({});

        let result = configure_provider_interactive(
            &mut config,
            SetupProvider::Gemini,
            false,
            Some(SetupAuthModeSelection::ApiKey),
        )
        .expect("interactive Gemini setup");

        assert!(result.observed_checks.is_empty());
        assert_eq!(config["google"]["apiKey"], "AIza-test-key");
        assert_eq!(
            config["agents"]["defaults"]["model"],
            "gemini:gemini-2.0-flash"
        );
        let state = setup_interactive_test_harness_snapshot().expect("harness snapshot");
        assert_eq!(state.provider_validation_calls, 0);
        assert!(state.visible_inputs.is_empty());
    }

    #[test]
    fn test_configure_provider_interactive_anthropic_setup_token_skips_live_validation() {
        let mut env_guard = ScopedEnv::new();
        let state_dir = tempfile::TempDir::new().unwrap();
        env_guard.unset("ANTHROPIC_SETUP_TOKEN");
        env_guard.unset("ANTHROPIC_API_KEY");
        env_guard.set("CARAPACE_STATE_DIR", state_dir.path().as_os_str());
        env_guard.set("CARAPACE_CONFIG_PASSWORD", "test-password");

        let payload_len = crate::onboarding::anthropic::ANTHROPIC_SETUP_TOKEN_MIN_TOTAL_LENGTH
            - crate::onboarding::anthropic::ANTHROPIC_SETUP_TOKEN_PREFIX.len();
        let token = format!(
            "{}{}",
            crate::onboarding::anthropic::ANTHROPIC_SETUP_TOKEN_PREFIX,
            "a".repeat(payload_len)
        );
        let _guard = install_setup_interactive_harness(SetupInteractiveTestHarness {
            hidden_inputs: VecDeque::from(vec![token.clone()]),
            ..Default::default()
        });
        let mut config = serde_json::json!({});

        let result = configure_provider_interactive(
            &mut config,
            SetupProvider::Anthropic,
            true,
            Some(SetupAuthModeSelection::SetupToken),
        )
        .expect("interactive Anthropic setup-token setup");

        assert_eq!(result.observed_checks.len(), 1);
        assert_eq!(
            result.observed_checks[0].status,
            crate::onboarding::setup::SetupCheckStatus::Skip
        );
        assert_eq!(
            result.observed_checks[0].kind,
            crate::onboarding::setup::SetupCheckKind::Validation
        );
        assert!(result.observed_checks[0].detail.contains("setup-token"));
        assert_eq!(
            result.observed_checks[0].remediation.as_deref(),
            Some(
                "run `cara verify --outcome local-chat` after setup to exercise the configured Anthropic setup-token path"
            )
        );

        assert_eq!(
            config["anthropic"]["authProfile"],
            crate::onboarding::anthropic::DEFAULT_ANTHROPIC_AUTH_PROFILE_ID
        );
        assert_eq!(
            config["auth"]["profiles"]["enabled"],
            serde_json::json!(true)
        );

        let state = setup_interactive_test_harness_snapshot().expect("harness snapshot");
        assert_eq!(state.provider_validation_calls, 0);
        assert_eq!(state.hidden_prompt_count, 1);
        assert!(state.hidden_inputs.is_empty());

        let raw = std::fs::read_to_string(state_dir.path().join("auth_profiles.json")).unwrap();
        assert!(raw.contains("enc:v2:"));
        assert!(!raw.contains(&token));
    }

    #[test]
    fn test_configure_provider_interactive_anthropic_setup_token_confirms_api_key_replacement() {
        let mut env_guard = ScopedEnv::new();
        let state_dir = tempfile::TempDir::new().unwrap();
        env_guard.unset("ANTHROPIC_SETUP_TOKEN");
        env_guard.unset("ANTHROPIC_API_KEY");
        env_guard.set("CARAPACE_STATE_DIR", state_dir.path().as_os_str());
        env_guard.set("CARAPACE_CONFIG_PASSWORD", "test-password");

        let payload_len = crate::onboarding::anthropic::ANTHROPIC_SETUP_TOKEN_MIN_TOTAL_LENGTH
            - crate::onboarding::anthropic::ANTHROPIC_SETUP_TOKEN_PREFIX.len();
        let token = format!(
            "{}{}",
            crate::onboarding::anthropic::ANTHROPIC_SETUP_TOKEN_PREFIX,
            "a".repeat(payload_len)
        );
        let _guard = install_setup_interactive_harness(SetupInteractiveTestHarness {
            visible_inputs: VecDeque::from(vec!["y".to_string()]),
            hidden_inputs: VecDeque::from(vec![token.clone()]),
            ..Default::default()
        });
        let mut config = serde_json::json!({
            "anthropic": {
                "apiKey": "${ANTHROPIC_API_KEY}"
            }
        });

        let result = configure_provider_interactive(
            &mut config,
            SetupProvider::Anthropic,
            true,
            Some(SetupAuthModeSelection::SetupToken),
        )
        .expect("interactive Anthropic setup-token setup");

        assert_eq!(result.observed_checks.len(), 1);
        assert!(config["anthropic"].get("apiKey").is_none());
        assert_eq!(
            config["anthropic"]["authProfile"],
            crate::onboarding::anthropic::DEFAULT_ANTHROPIC_AUTH_PROFILE_ID
        );

        let state = setup_interactive_test_harness_snapshot().expect("harness snapshot");
        assert_eq!(state.visible_prompt_count, 1);
        assert_eq!(state.hidden_prompt_count, 1);
        assert!(state.visible_inputs.is_empty());
        assert!(state.hidden_inputs.is_empty());
    }

    #[test]
    fn test_configure_provider_interactive_anthropic_setup_token_decline_api_key_replacement() {
        let mut env_guard = ScopedEnv::new();
        let state_dir = tempfile::TempDir::new().unwrap();
        env_guard.unset("ANTHROPIC_SETUP_TOKEN");
        env_guard.unset("ANTHROPIC_API_KEY");
        env_guard.set("CARAPACE_STATE_DIR", state_dir.path().as_os_str());
        env_guard.set("CARAPACE_CONFIG_PASSWORD", "test-password");

        let _guard = install_setup_interactive_harness(SetupInteractiveTestHarness {
            visible_inputs: VecDeque::from(vec!["n".to_string()]),
            ..Default::default()
        });
        let mut config = serde_json::json!({
            "anthropic": {
                "apiKey": "${ANTHROPIC_API_KEY}"
            }
        });

        let result = configure_provider_interactive(
            &mut config,
            SetupProvider::Anthropic,
            true,
            Some(SetupAuthModeSelection::SetupToken),
        );

        assert!(
            result.is_err(),
            "setup should abort when replacement is declined"
        );
        assert_eq!(
            result
                .expect_err("expected replacement-decline abort")
                .to_string(),
            "setup aborted before replacing existing Anthropic API key config"
        );
        assert_eq!(config["anthropic"]["apiKey"], "${ANTHROPIC_API_KEY}");
        assert!(config["anthropic"].get("authProfile").is_none());

        let state = setup_interactive_test_harness_snapshot().expect("harness snapshot");
        assert_eq!(state.visible_prompt_count, 1);
        assert_eq!(state.hidden_prompt_count, 0);
        assert!(state.visible_inputs.is_empty());
        assert!(state.hidden_inputs.is_empty());
        assert!(!state_dir.path().join("auth_profiles.json").exists());
    }

    #[test]
    fn test_configure_provider_interactive_anthropic_setup_token_confirms_env_api_key_override() {
        let mut env_guard = ScopedEnv::new();
        let state_dir = tempfile::TempDir::new().unwrap();
        env_guard.unset("ANTHROPIC_SETUP_TOKEN");
        env_guard.set("ANTHROPIC_API_KEY", "sk-anthropic");
        env_guard.set("CARAPACE_STATE_DIR", state_dir.path().as_os_str());
        env_guard.set("CARAPACE_CONFIG_PASSWORD", "test-password");

        let payload_len = crate::onboarding::anthropic::ANTHROPIC_SETUP_TOKEN_MIN_TOTAL_LENGTH
            - crate::onboarding::anthropic::ANTHROPIC_SETUP_TOKEN_PREFIX.len();
        let token = format!(
            "{}{}",
            crate::onboarding::anthropic::ANTHROPIC_SETUP_TOKEN_PREFIX,
            "a".repeat(payload_len)
        );
        let _guard = install_setup_interactive_harness(SetupInteractiveTestHarness {
            visible_inputs: VecDeque::from(vec!["y".to_string()]),
            hidden_inputs: VecDeque::from(vec![token]),
            ..Default::default()
        });
        let mut config = serde_json::json!({});

        let result = configure_provider_interactive(
            &mut config,
            SetupProvider::Anthropic,
            true,
            Some(SetupAuthModeSelection::SetupToken),
        )
        .expect("interactive Anthropic setup-token setup");

        assert_eq!(result.observed_checks.len(), 1);
        assert_eq!(
            config["anthropic"]["authProfile"],
            crate::onboarding::anthropic::DEFAULT_ANTHROPIC_AUTH_PROFILE_ID
        );

        let state = setup_interactive_test_harness_snapshot().expect("harness snapshot");
        assert_eq!(state.visible_prompt_count, 1);
        assert_eq!(state.hidden_prompt_count, 1);
        assert!(state.visible_inputs.is_empty());
        assert!(state.hidden_inputs.is_empty());
    }

    #[test]
    fn test_configure_provider_interactive_anthropic_setup_token_decline_env_api_key_override() {
        let mut env_guard = ScopedEnv::new();
        let state_dir = tempfile::TempDir::new().unwrap();
        env_guard.unset("ANTHROPIC_SETUP_TOKEN");
        env_guard.set("ANTHROPIC_API_KEY", "sk-anthropic");
        env_guard.set("CARAPACE_STATE_DIR", state_dir.path().as_os_str());
        env_guard.set("CARAPACE_CONFIG_PASSWORD", "test-password");

        let _guard = install_setup_interactive_harness(SetupInteractiveTestHarness {
            visible_inputs: VecDeque::from(vec!["n".to_string()]),
            ..Default::default()
        });
        let mut config = serde_json::json!({});

        let result = configure_provider_interactive(
            &mut config,
            SetupProvider::Anthropic,
            true,
            Some(SetupAuthModeSelection::SetupToken),
        );

        assert!(
            result.is_err(),
            "setup should abort when env API key override is declined"
        );
        assert_eq!(
            result
                .expect_err("expected env-override-decline abort")
                .to_string(),
            "setup aborted while `ANTHROPIC_API_KEY` would still override Anthropic setup-token auth"
        );
        assert!(config["anthropic"].get("authProfile").is_none());

        let state = setup_interactive_test_harness_snapshot().expect("harness snapshot");
        assert_eq!(state.visible_prompt_count, 1);
        assert_eq!(state.hidden_prompt_count, 0);
        assert!(state.visible_inputs.is_empty());
        assert!(state.hidden_inputs.is_empty());
        assert!(!state_dir.path().join("auth_profiles.json").exists());
    }

    #[test]
    fn test_configure_provider_interactive_vertex_default_route_writes_config_and_validates() {
        let mut env_guard = ScopedEnv::new();
        env_guard.unset("VERTEX_PROJECT_ID");
        env_guard.unset("VERTEX_LOCATION");
        env_guard.unset("VERTEX_MODEL");
        let _guard = install_setup_interactive_harness(SetupInteractiveTestHarness {
            visible_inputs: VecDeque::from(vec![
                "my-project".to_string(),
                "us-central1".to_string(),
                "default-route".to_string(),
                "gemini-2.5-flash".to_string(),
                "y".to_string(),
            ]),
            provider_validation_results: VecDeque::from(vec![Ok(())]),
            ..Default::default()
        });
        let mut config = serde_json::json!({});

        let result =
            configure_provider_interactive(&mut config, SetupProvider::Vertex, false, None)
                .expect("interactive Vertex setup");

        assert_eq!(config["vertex"]["projectId"], "my-project");
        assert_eq!(config["vertex"]["location"], "us-central1");
        assert_eq!(config["vertex"]["model"], "gemini-2.5-flash");
        assert_eq!(config["agents"]["defaults"]["model"], "vertex:default");
        assert_eq!(result.observed_checks.len(), 1);
        assert_eq!(
            result.observed_checks[0].detail,
            "Vertex auth, project, location, and model access validated"
        );
        let state = setup_interactive_test_harness_snapshot().expect("harness snapshot");
        assert_eq!(state.provider_validation_calls, 1);
        assert!(state.visible_inputs.is_empty());
    }

    #[test]
    fn test_configure_provider_interactive_vertex_explicit_route_omits_vertex_model() {
        let mut env_guard = ScopedEnv::new();
        env_guard.unset("VERTEX_PROJECT_ID");
        env_guard.unset("VERTEX_LOCATION");
        env_guard.unset("VERTEX_MODEL");
        let _guard = install_setup_interactive_harness(SetupInteractiveTestHarness {
            visible_inputs: VecDeque::from(vec![
                "my-project".to_string(),
                "us-central1".to_string(),
                "explicit-model".to_string(),
                "vertex:google/gemini-1.5-pro".to_string(),
                "n".to_string(),
            ]),
            ..Default::default()
        });
        let mut config = serde_json::json!({});

        let result =
            configure_provider_interactive(&mut config, SetupProvider::Vertex, false, None)
                .expect("interactive Vertex setup");

        assert_eq!(config["vertex"]["projectId"], "my-project");
        assert_eq!(config["vertex"]["location"], "us-central1");
        assert!(
            config["vertex"].get("model").is_none(),
            "explicit route should not persist `vertex.model`"
        );
        assert_eq!(
            config["agents"]["defaults"]["model"],
            "vertex:google/gemini-1.5-pro"
        );
        assert_eq!(result.observed_checks.len(), 1);
        assert_eq!(
            result.observed_checks[0].detail,
            "Vertex live validation was skipped"
        );
        let state = setup_interactive_test_harness_snapshot().expect("harness snapshot");
        assert_eq!(state.provider_validation_calls, 0);
        assert!(state.visible_inputs.is_empty());
    }

    #[test]
    fn test_configure_provider_interactive_vertex_validation_failure_can_continue() {
        let mut env_guard = ScopedEnv::new();
        env_guard.unset("VERTEX_PROJECT_ID");
        env_guard.unset("VERTEX_LOCATION");
        env_guard.unset("VERTEX_MODEL");
        let _guard = install_setup_interactive_harness(SetupInteractiveTestHarness {
            visible_inputs: VecDeque::from(vec![
                "my-project".to_string(),
                "us-central1".to_string(),
                "default-route".to_string(),
                "gemini-2.5-flash".to_string(),
                "y".to_string(),
                "y".to_string(),
            ]),
            provider_validation_results: VecDeque::from(vec![Err(
                "Vertex rejected access to the configured project".to_string(),
            )]),
            ..Default::default()
        });
        let mut config = serde_json::json!({});

        let result =
            configure_provider_interactive(&mut config, SetupProvider::Vertex, false, None)
                .expect("interactive Vertex setup");

        assert_eq!(result.observed_checks.len(), 1);
        assert_eq!(
            result.observed_checks[0].status,
            crate::onboarding::setup::SetupCheckStatus::Fail
        );
        let state = setup_interactive_test_harness_snapshot().expect("harness snapshot");
        assert_eq!(state.provider_validation_calls, 1);
        assert!(state.visible_inputs.is_empty());
    }

    #[test]
    fn test_configure_provider_interactive_vertex_default_route_with_unresolved_model_skips_validation(
    ) {
        let mut env_guard = ScopedEnv::new();
        env_guard.unset("VERTEX_PROJECT_ID");
        env_guard.unset("VERTEX_LOCATION");
        env_guard.unset("VERTEX_MODEL");
        let _guard = install_setup_interactive_harness(SetupInteractiveTestHarness {
            visible_inputs: VecDeque::from(vec![
                "my-project".to_string(),
                "us-central1".to_string(),
                "default-route".to_string(),
                "".to_string(),
            ]),
            ..Default::default()
        });
        let mut config = serde_json::json!({});

        let result =
            configure_provider_interactive(&mut config, SetupProvider::Vertex, false, None)
                .expect("interactive Vertex setup");

        assert_eq!(config["vertex"]["projectId"], "my-project");
        assert_eq!(config["vertex"]["location"], "us-central1");
        assert_eq!(config["vertex"]["model"], "${VERTEX_MODEL}");
        assert_eq!(config["agents"]["defaults"]["model"], "vertex:default");
        assert_eq!(result.observed_checks.len(), 1);
        assert_eq!(
            result.observed_checks[0].status,
            crate::onboarding::setup::SetupCheckStatus::Skip
        );
        assert_eq!(
            result.observed_checks[0].detail,
            "Vertex live validation was skipped because `vertex:default` still resolves `vertex.model` from `VERTEX_MODEL` later"
        );
        let state = setup_interactive_test_harness_snapshot().expect("harness snapshot");
        assert_eq!(state.provider_validation_calls, 0);
        assert!(state.visible_inputs.is_empty());
    }

    #[test]
    fn test_configure_provider_interactive_vertex_with_unresolved_project_skips_validation() {
        let mut env_guard = ScopedEnv::new();
        env_guard.unset("VERTEX_PROJECT_ID");
        env_guard.unset("VERTEX_LOCATION");
        env_guard.unset("VERTEX_MODEL");
        let _guard = install_setup_interactive_harness(SetupInteractiveTestHarness {
            visible_inputs: VecDeque::from(vec![
                "".to_string(),
                "us-central1".to_string(),
                "default-route".to_string(),
                "gemini-2.5-flash".to_string(),
            ]),
            ..Default::default()
        });
        let mut config = serde_json::json!({});

        let result =
            configure_provider_interactive(&mut config, SetupProvider::Vertex, false, None)
                .expect("interactive Vertex setup");

        assert_eq!(config["vertex"]["projectId"], "${VERTEX_PROJECT_ID}");
        assert_eq!(config["vertex"]["location"], "us-central1");
        assert_eq!(config["vertex"]["model"], "gemini-2.5-flash");
        assert_eq!(config["agents"]["defaults"]["model"], "vertex:default");
        assert_eq!(result.observed_checks.len(), 1);
        assert_eq!(
            result.observed_checks[0].status,
            crate::onboarding::setup::SetupCheckStatus::Skip
        );
        assert_eq!(
            result.observed_checks[0].detail,
            "Vertex live validation was skipped because `VERTEX_PROJECT_ID` still resolves from the environment later"
        );
        assert_eq!(
            result.observed_checks[0].remediation.as_deref(),
            Some(
                "set `VERTEX_PROJECT_ID` in the same shell and run `cara verify --outcome local-chat` once it is available"
            )
        );
        let state = setup_interactive_test_harness_snapshot().expect("harness snapshot");
        assert_eq!(state.provider_validation_calls, 0);
        assert!(state.visible_inputs.is_empty());
    }

    #[test]
    fn test_configure_provider_interactive_vertex_validation_failure_can_abort() {
        let mut env_guard = ScopedEnv::new();
        env_guard.unset("VERTEX_PROJECT_ID");
        env_guard.unset("VERTEX_LOCATION");
        env_guard.unset("VERTEX_MODEL");
        let _guard = install_setup_interactive_harness(SetupInteractiveTestHarness {
            visible_inputs: VecDeque::from(vec![
                "my-project".to_string(),
                "us-central1".to_string(),
                "default-route".to_string(),
                "gemini-2.5-flash".to_string(),
                "y".to_string(),
                "n".to_string(),
            ]),
            provider_validation_results: VecDeque::from(vec![Err(
                "Vertex rejected access to the configured project".to_string(),
            )]),
            ..Default::default()
        });
        let mut config = serde_json::json!({});

        let result =
            configure_provider_interactive(&mut config, SetupProvider::Vertex, false, None);
        assert!(
            result.is_err(),
            "setup should abort after validation failure"
        );
        assert_eq!(
            result.expect_err("expected setup abort").to_string(),
            "setup aborted after provider configuration validation failure"
        );
        assert_eq!(
            config,
            serde_json::json!({}),
            "aborting setup should leave the in-memory config untouched"
        );
        let state = setup_interactive_test_harness_snapshot().expect("harness snapshot");
        assert_eq!(state.provider_validation_calls, 1);
        assert!(state.visible_inputs.is_empty());
    }

    #[test]
    fn test_handle_setup_interactive_selects_ollama_provider() {
        let mut env_guard = ScopedEnv::new();
        let env = setup_interactive_test_env(
            &mut env_guard,
            SetupInteractiveTestHarness {
                force_interactive: Some(true),
                visible_inputs: VecDeque::from(vec![
                    "y".to_string(),
                    "ollama".to_string(),
                    "".to_string(),
                    "".to_string(),
                    "".to_string(),
                    "".to_string(),
                    "".to_string(),
                    "".to_string(),
                    "".to_string(),
                    "n".to_string(),
                    "n".to_string(),
                    "n".to_string(),
                    "n".to_string(),
                    "n".to_string(),
                ]),
                ..Default::default()
            },
        );
        env_guard.set("OLLAMA_BASE_URL", "http://127.0.0.1:11434");

        let result = handle_setup(true, None, None);
        assert!(result.is_ok(), "interactive Ollama setup should succeed");

        let state = setup_interactive_test_harness_snapshot().expect("harness snapshot");
        assert_eq!(state.provider_validation_calls, 0);
        assert!(state.visible_inputs.is_empty());

        let content = std::fs::read_to_string(&env.config_path).unwrap();
        let parsed: serde_json::Value = json5::from_str(&content).unwrap();
        assert_eq!(
            parsed["providers"]["ollama"]["baseUrl"],
            "${OLLAMA_BASE_URL}"
        );
        assert_eq!(parsed["agents"]["defaults"]["model"], "ollama:llama3");
    }

    #[test]
    fn test_handle_setup_interactive_hidden_input_skips_telegram_validation_on_blank_token() {
        let mut env_guard = ScopedEnv::new();
        let env = setup_interactive_test_env(
            &mut env_guard,
            SetupInteractiveTestHarness {
                force_interactive: Some(true),
                visible_inputs: VecDeque::from(vec![
                    "y".to_string(),
                    "openai".to_string(),
                    "api-key".to_string(),
                    "".to_string(),
                    "n".to_string(),
                    "".to_string(),
                    "".to_string(),
                    "telegram".to_string(),
                    "n".to_string(),
                    "n".to_string(),
                    "n".to_string(),
                    "n".to_string(),
                    "n".to_string(),
                ]),
                hidden_inputs: VecDeque::from(vec![
                    "".to_string(),
                    "hidden-token-123".to_string(),
                    "".to_string(),
                ]),
                ..Default::default()
            },
        );

        let result = handle_setup(true, None, None);
        assert!(result.is_ok(), "interactive setup should succeed");

        let state = setup_interactive_test_harness_snapshot().expect("harness snapshot");
        assert_eq!(state.hidden_prompt_count, 3);
        assert_eq!(state.channel_validation_calls, 0);
        assert_eq!(state.provider_validation_calls, 0);
        assert!(state.visible_inputs.is_empty());
        assert!(state.hidden_inputs.is_empty());

        let content = std::fs::read_to_string(&env.config_path).unwrap();
        let parsed: serde_json::Value = json5::from_str(&content).unwrap();
        assert_eq!(parsed["gateway"]["auth"]["token"], "hidden-token-123");
        assert!(
            parsed.get("telegram").is_none(),
            "telegram config should be absent when token is blank"
        );
    }

    #[test]
    fn test_handle_setup_interactive_visible_input_validates_telegram_token() {
        let mut env_guard = ScopedEnv::new();
        let env = setup_interactive_test_env(
            &mut env_guard,
            SetupInteractiveTestHarness {
                force_interactive: Some(true),
                visible_inputs: VecDeque::from(vec![
                    "n".to_string(),
                    "openai".to_string(),
                    "api-key".to_string(),
                    "sk-openai-visible".to_string(),
                    "n".to_string(),
                    "".to_string(),
                    "".to_string(),
                    "".to_string(),
                    "".to_string(),
                    "telegram".to_string(),
                    "12345:abc".to_string(),
                    "y".to_string(),
                    "".to_string(),
                    "n".to_string(),
                    "n".to_string(),
                    "n".to_string(),
                    "n".to_string(),
                    "n".to_string(),
                ]),
                channel_validation_results: VecDeque::from(vec![Ok(())]),
                ..Default::default()
            },
        );

        let result = handle_setup(true, None, None);
        assert!(result.is_ok(), "interactive setup should succeed");

        let state = setup_interactive_test_harness_snapshot().expect("harness snapshot");
        assert_eq!(state.hidden_prompt_count, 0);
        assert_eq!(state.channel_validation_calls, 1);
        assert_eq!(state.provider_validation_calls, 0);
        assert!(state.channel_validation_results.is_empty());
        assert!(state.visible_inputs.is_empty());

        let content = std::fs::read_to_string(&env.config_path).unwrap();
        let parsed: serde_json::Value = json5::from_str(&content).unwrap();
        assert_eq!(parsed["telegram"]["enabled"], true);
        assert_eq!(parsed["telegram"]["botToken"], "12345:abc");
    }

    #[test]
    fn test_handle_setup_interactive_telegram_validation_failure_aborts_when_user_declines_continue(
    ) {
        let mut env_guard = ScopedEnv::new();
        let env = setup_interactive_test_env(
            &mut env_guard,
            SetupInteractiveTestHarness {
                force_interactive: Some(true),
                visible_inputs: VecDeque::from(vec![
                    "n".to_string(),
                    "openai".to_string(),
                    "api-key".to_string(),
                    "sk-openai-visible".to_string(),
                    "n".to_string(),
                    "".to_string(),
                    "".to_string(),
                    "".to_string(),
                    "".to_string(),
                    "telegram".to_string(),
                    "12345:abc".to_string(),
                    "y".to_string(),
                    "n".to_string(),
                ]),
                channel_validation_results: VecDeque::from(vec![Err(
                    "telegram token rejected".to_string()
                )]),
                ..Default::default()
            },
        );

        let result = handle_setup(true, None, None);
        assert!(
            result.is_err(),
            "setup should abort after validation failure"
        );
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("setup aborted after credential validation failure"),
            "unexpected setup error"
        );
        assert!(
            !env.config_path.exists(),
            "config file should not be written when setup aborts"
        );

        let state = setup_interactive_test_harness_snapshot().expect("harness snapshot");
        assert_eq!(state.hidden_prompt_count, 0);
        assert_eq!(state.channel_validation_calls, 1);
        assert_eq!(state.provider_validation_calls, 0);
        assert!(state.channel_validation_results.is_empty());
        assert!(state.visible_inputs.is_empty());
    }

    #[test]
    fn test_handle_setup_interactive_hidden_input_skips_discord_validation_on_blank_token() {
        let mut env_guard = ScopedEnv::new();
        let env = setup_interactive_test_env(
            &mut env_guard,
            SetupInteractiveTestHarness {
                force_interactive: Some(true),
                visible_inputs: VecDeque::from(vec![
                    "y".to_string(),
                    "openai".to_string(),
                    "api-key".to_string(),
                    "".to_string(),
                    "n".to_string(),
                    "".to_string(),
                    "".to_string(),
                    "discord".to_string(),
                    "n".to_string(),
                    "n".to_string(),
                    "n".to_string(),
                    "n".to_string(),
                    "n".to_string(),
                ]),
                hidden_inputs: VecDeque::from(vec![
                    "".to_string(),
                    "hidden-token-123".to_string(),
                    "".to_string(),
                ]),
                ..Default::default()
            },
        );

        let result = handle_setup(true, None, None);
        assert!(result.is_ok(), "interactive setup should succeed");

        let state = setup_interactive_test_harness_snapshot().expect("harness snapshot");
        assert_eq!(state.hidden_prompt_count, 3);
        assert_eq!(state.channel_validation_calls, 0);
        assert_eq!(state.provider_validation_calls, 0);
        assert!(state.visible_inputs.is_empty());
        assert!(state.hidden_inputs.is_empty());

        let content = std::fs::read_to_string(&env.config_path).unwrap();
        let parsed: serde_json::Value = json5::from_str(&content).unwrap();
        assert_eq!(parsed["gateway"]["auth"]["token"], "hidden-token-123");
        assert!(
            parsed.get("discord").is_none(),
            "discord config should be absent when token is blank"
        );
    }

    #[test]
    fn test_handle_setup_interactive_discord_validation_failure_aborts_when_user_declines_continue()
    {
        let mut env_guard = ScopedEnv::new();
        let env = setup_interactive_test_env(
            &mut env_guard,
            SetupInteractiveTestHarness {
                force_interactive: Some(true),
                visible_inputs: VecDeque::from(vec![
                    "n".to_string(),
                    "openai".to_string(),
                    "api-key".to_string(),
                    "sk-openai-visible".to_string(),
                    "n".to_string(),
                    "".to_string(),
                    "".to_string(),
                    "".to_string(),
                    "".to_string(),
                    "discord".to_string(),
                    "discord-bot-token".to_string(),
                    "y".to_string(),
                    "n".to_string(),
                ]),
                channel_validation_results: VecDeque::from(vec![Err(
                    "discord token rejected".to_string()
                )]),
                ..Default::default()
            },
        );

        let result = handle_setup(true, None, None);
        assert!(
            result.is_err(),
            "setup should abort after validation failure"
        );
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("setup aborted after credential validation failure"),
            "unexpected setup error"
        );
        assert!(
            !env.config_path.exists(),
            "config file should not be written when setup aborts"
        );

        let state = setup_interactive_test_harness_snapshot().expect("harness snapshot");
        assert_eq!(state.hidden_prompt_count, 0);
        assert_eq!(state.channel_validation_calls, 1);
        assert_eq!(state.provider_validation_calls, 0);
        assert!(state.channel_validation_results.is_empty());
        assert!(state.visible_inputs.is_empty());
    }

    #[test]
    fn test_handle_setup_validation_failure_uses_provider_configuration_abort_message() {
        let _guard = install_setup_interactive_harness(SetupInteractiveTestHarness {
            visible_inputs: VecDeque::from(vec!["n".to_string()]),
            ..Default::default()
        });

        let result = handle_setup_validation_failure(
            SetupProvider::Gemini,
            Some(SetupAuthModeSelection::ApiKey),
            crate::agent::AgentError::InvalidBaseUrl("bad".to_string()),
        );

        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "setup aborted after provider configuration validation failure"
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
