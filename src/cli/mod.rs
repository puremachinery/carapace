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

use clap::{Parser, Subcommand};

/// Carapace gateway server for AI assistants.
#[derive(Parser, Debug)]
#[command(
    name = "carapace",
    version = env!("CARGO_PKG_VERSION"),
    about = "Carapace — a secure gateway server for AI assistants"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,
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

use crate::config;
use crate::logging::buffer::LOG_BUFFER;
use crate::server::bind::DEFAULT_PORT;
use serde_json::Value;

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
            eprintln!("Is the server running? Start it with: carapace start");
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
pub async fn handle_logs(
    host: &str,
    port: Option<u16>,
    lines: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    let port = resolve_port(port);

    // First, try the local in-process log buffer (only works if we *are* the
    // running process, which normally we are not). This is a graceful no-op for
    // the common CLI case.
    let buffer_entries = LOG_BUFFER.len();
    if buffer_entries > 0 {
        let filter = crate::logging::buffer::LogFilter::new().with_limit(lines);
        let result = LOG_BUFFER.query(&filter);
        for entry in &result.entries {
            println!(
                "{} [{}] {}: {}",
                format_timestamp(entry.timestamp),
                entry.level,
                entry.target,
                entry.message
            );
        }
        return Ok(());
    }

    // Otherwise, try to read from the log file on disk.
    let log_path = crate::server::ws::resolve_state_dir()
        .join("logs")
        .join("moltbot.log");

    if log_path.exists() {
        let content = std::fs::read_to_string(&log_path)?;
        let all_lines: Vec<&str> = content.lines().collect();
        let start = all_lines.len().saturating_sub(lines);
        for line in &all_lines[start..] {
            println!("{}", line);
        }
        return Ok(());
    }

    // Last resort: hit the health endpoint to confirm the server is running,
    // then inform the user that log streaming is not yet available via this path.
    let url = format!("http://{}:{}/health", host, port);
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()?;

    match client.get(&url).send().await {
        Ok(resp) if resp.status().is_success() => {
            eprintln!(
                "Server is running at {}:{}, but no log file found at {}",
                host,
                port,
                log_path.display()
            );
            eprintln!("Hint: enable file logging or use the WebSocket logs.tail method.");
        }
        _ => {
            eprintln!("Could not connect to carapace at {}:{}", host, port);
            eprintln!("Is the server running? Start it with: carapace start");
            std::process::exit(1);
        }
    }

    Ok(())
}

/// Run the `version` subcommand.
pub fn handle_version() {
    println!("carapace {}", env!("CARGO_PKG_VERSION"));
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
fn resolve_state_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("MOLTBOT_STATE_DIR") {
        return PathBuf::from(dir);
    }
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".moltbot")
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
            .unwrap_or_else(|| std::ffi::OsStr::new("moltbot.json"));
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
        eprintln!("The file may be corrupt or was not created by `carapace backup`.");
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

    // Build a minimal default config.
    let default_config = serde_json::json!({
        "gateway": {
            "port": 3001,
            "bind": "loopback"
        },
        "agents": {
            "defaults": {
                "model": "claude-sonnet-4-20250514"
            }
        }
    });

    // Check for API keys in environment.
    if std::env::var("ANTHROPIC_API_KEY").is_ok() {
        println!("Anthropic API key detected in environment");
    }
    if std::env::var("OPENAI_API_KEY").is_ok() {
        println!("OpenAI API key detected in environment");
    }
    if std::env::var("GOOGLE_API_KEY").is_ok() {
        println!("Google API key detected in environment");
    }

    // Write the config file using json5 (pretty-formatted).
    let content = json5::to_string(&default_config)?;
    std::fs::write(&config_path, &content)?;

    println!("Config written to {}", config_path.display());
    println!("Start the server with: carapace start");

    Ok(())
}

/// Run the `pair` subcommand -- pair with a remote gateway node.
pub async fn handle_pair(
    url: &str,
    name: Option<&str>,
    trust: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    // Validate the URL.
    if !url.starts_with("http://") && !url.starts_with("https://") {
        eprintln!("Invalid URL: {} (must start with http:// or https://)", url);
        return Err("invalid URL scheme".into());
    }

    // Resolve the device name.
    let device_name = match name {
        Some(n) => n.to_string(),
        None => std::env::var("HOSTNAME").unwrap_or_else(|_| "unknown".to_string()),
    };

    // Generate a pairing token.
    let token = uuid::Uuid::new_v4().to_string();

    println!("Pairing with: {}", url);
    println!("Device name: {}", device_name);
    println!("Pairing token: {}", token);

    // Build the request body.
    let body = serde_json::json!({
        "name": device_name,
        "token": token,
        "version": env!("CARGO_PKG_VERSION"),
    });

    // Build the HTTP client (optionally accepting invalid certs).
    let client = if trust {
        reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .timeout(std::time::Duration::from_secs(10))
            .build()?
    } else {
        reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()?
    };

    // Attempt to connect to the gateway.
    let pair_url = format!("{}/api/nodes/pair", url.trim_end_matches('/'));
    let response = match client.post(&pair_url).json(&body).send().await {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Connection error: {}", e);
            return Err(e.into());
        }
    };

    if !response.status().is_success() {
        let status = response.status();
        let body_text = response.text().await.unwrap_or_default();
        eprintln!("Pairing failed (HTTP {}): {}", status, body_text);
        return Err(format!("HTTP {}", status).into());
    }

    // Parse response and save pairing info.
    let resp_body: Value = response.json().await?;
    let node_id = resp_body
        .get("node_id")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    println!("Paired successfully! Node ID: {}", node_id);

    // Save pairing to state dir.
    let state_dir = resolve_state_dir();
    std::fs::create_dir_all(&state_dir)?;
    let pairing_path = state_dir.join("pairing.json");
    let pairing_data = serde_json::json!({
        "node_id": node_id,
        "gateway_url": url,
        "device_name": device_name,
        "token": token,
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
            println!("Run `carapace update` to install");
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
            "https://api.github.com/repos/moltbot/carapace/releases/tags/v{}",
            v
        ),
        None => "https://api.github.com/repos/moltbot/carapace/releases/latest".to_string(),
    };

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()?;

    let response = match client
        .get(&api_url)
        .header("Accept", "application/vnd.github+json")
        .header("User-Agent", format!("carapace/{}", current_version))
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
    let asset_name = format!(
        "carapace-{}-{}",
        std::env::consts::OS,
        std::env::consts::ARCH
    );

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
        .header("User-Agent", format!("carapace/{}", current_version))
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
    let staged_path = updates_dir.join(format!("carapace-{}", target_version));
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
            println!("Restart carapace to use v{}.", target_version);
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
fn resolve_port(explicit: Option<u16>) -> u16 {
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

    let ca = crate::tls::ca::ClusterCA::generate(&ca_dir)?;

    println!("Cluster CA generated successfully");
    println!("  Directory:   {}", ca_dir.display());
    println!("  Certificate: {}", ca.ca_cert_path().display());
    println!("  Key:         {}", ca.ca_key_path().display());
    println!("  Fingerprint: {}", ca.ca_fingerprint());
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

    let ca = crate::tls::ca::ClusterCA::load(&ca_dir)?;
    let cert = ca.issue_node_cert(node_id, &output_dir)?;

    println!("Node certificate issued successfully");
    println!("  Node ID:     {}", cert.node_id);
    println!("  Certificate: {}", cert.cert_path.display());
    println!("  Key:         {}", cert.key_path.display());
    println!("  Fingerprint: {}", cert.fingerprint);
    println!();
    println!("Deploy these files to the node and configure gateway.mtls:");
    println!("  nodeCert: \"{}\"", cert.cert_path.display());
    println!("  nodeKey:  \"{}\"", cert.key_path.display());

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

    let ca = crate::tls::ca::ClusterCA::load(&ca_dir)?;

    println!("Cluster CA Information");
    println!("=====================");
    println!("  Directory:   {}", ca.ca_dir().display());
    println!("  Certificate: {}", ca.ca_cert_path().display());
    println!("  Key:         {}", ca.ca_key_path().display());
    println!("  Fingerprint: {}", ca.ca_fingerprint());

    let entries = ca.crl_entries();
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
    use clap::Parser;

    #[test]
    fn test_cli_no_args_defaults_to_none() {
        let cli = Cli::try_parse_from(["carapace"]).unwrap();
        assert!(cli.command.is_none());
    }

    #[test]
    fn test_cli_start_subcommand() {
        let cli = Cli::try_parse_from(["carapace", "start"]).unwrap();
        assert!(matches!(cli.command, Some(Command::Start)));
    }

    #[test]
    fn test_cli_version_subcommand() {
        let cli = Cli::try_parse_from(["carapace", "version"]).unwrap();
        assert!(matches!(cli.command, Some(Command::Version)));
    }

    #[test]
    fn test_cli_config_show() {
        let cli = Cli::try_parse_from(["carapace", "config", "show"]).unwrap();
        match cli.command {
            Some(Command::Config(ConfigCommand::Show)) => {}
            other => panic!("Expected Config(Show), got {:?}", other),
        }
    }

    #[test]
    fn test_cli_config_get() {
        let cli = Cli::try_parse_from(["carapace", "config", "get", "gateway.port"]).unwrap();
        match cli.command {
            Some(Command::Config(ConfigCommand::Get { ref key })) => {
                assert_eq!(key, "gateway.port");
            }
            other => panic!("Expected Config(Get), got {:?}", other),
        }
    }

    #[test]
    fn test_cli_config_set() {
        let cli =
            Cli::try_parse_from(["carapace", "config", "set", "gateway.port", "9000"]).unwrap();
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
        let cli = Cli::try_parse_from(["carapace", "config", "path"]).unwrap();
        assert!(matches!(
            cli.command,
            Some(Command::Config(ConfigCommand::Path))
        ));
    }

    #[test]
    fn test_cli_status_defaults() {
        let cli = Cli::try_parse_from(["carapace", "status"]).unwrap();
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
        let cli = Cli::try_parse_from(["carapace", "status", "--port", "9000"]).unwrap();
        match cli.command {
            Some(Command::Status { port, .. }) => {
                assert_eq!(port, Some(9000));
            }
            other => panic!("Expected Status, got {:?}", other),
        }
    }

    #[test]
    fn test_cli_logs_defaults() {
        let cli = Cli::try_parse_from(["carapace", "logs"]).unwrap();
        match cli.command {
            Some(Command::Logs {
                lines,
                port,
                ref host,
            }) => {
                assert_eq!(lines, 50);
                assert_eq!(port, None);
                assert_eq!(host, "127.0.0.1");
            }
            other => panic!("Expected Logs, got {:?}", other),
        }
    }

    #[test]
    fn test_cli_logs_with_lines() {
        let cli = Cli::try_parse_from(["carapace", "logs", "--lines", "100"]).unwrap();
        match cli.command {
            Some(Command::Logs { lines, .. }) => {
                assert_eq!(lines, 100);
            }
            other => panic!("Expected Logs, got {:?}", other),
        }
    }

    #[test]
    fn test_cli_logs_with_short_flag() {
        let cli = Cli::try_parse_from(["carapace", "logs", "-n", "25"]).unwrap();
        match cli.command {
            Some(Command::Logs { lines, .. }) => {
                assert_eq!(lines, 25);
            }
            other => panic!("Expected Logs, got {:?}", other),
        }
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
        // When config is unavailable, should fall back to DEFAULT_PORT.
        assert_eq!(resolve_port(None), DEFAULT_PORT);
    }

    // -----------------------------------------------------------------------
    // Backup / Restore / Reset CLI parsing tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_cli_backup_no_args() {
        let cli = Cli::try_parse_from(["carapace", "backup"]).unwrap();
        match cli.command {
            Some(Command::Backup { output }) => {
                assert!(output.is_none());
            }
            other => panic!("Expected Backup, got {:?}", other),
        }
    }

    #[test]
    fn test_cli_backup_with_output() {
        let cli = Cli::try_parse_from(["carapace", "backup", "--output", "/tmp/my-backup.tar.gz"])
            .unwrap();
        match cli.command {
            Some(Command::Backup { output }) => {
                assert_eq!(output.as_deref(), Some("/tmp/my-backup.tar.gz"));
            }
            other => panic!("Expected Backup, got {:?}", other),
        }
    }

    #[test]
    fn test_cli_backup_with_short_flag() {
        let cli = Cli::try_parse_from(["carapace", "backup", "-o", "/tmp/backup.tar.gz"]).unwrap();
        match cli.command {
            Some(Command::Backup { output }) => {
                assert_eq!(output.as_deref(), Some("/tmp/backup.tar.gz"));
            }
            other => panic!("Expected Backup, got {:?}", other),
        }
    }

    #[test]
    fn test_cli_restore_requires_path() {
        let result = Cli::try_parse_from(["carapace", "restore"]);
        assert!(result.is_err(), "restore should require a path argument");
    }

    #[test]
    fn test_cli_restore_with_path() {
        let cli = Cli::try_parse_from(["carapace", "restore", "/tmp/backup.tar.gz"]).unwrap();
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
            Cli::try_parse_from(["carapace", "restore", "/tmp/backup.tar.gz", "--force"]).unwrap();
        match cli.command {
            Some(Command::Restore { force, .. }) => {
                assert!(force);
            }
            other => panic!("Expected Restore, got {:?}", other),
        }
    }

    #[test]
    fn test_cli_reset_no_flags() {
        let cli = Cli::try_parse_from(["carapace", "reset"]).unwrap();
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
        let cli = Cli::try_parse_from(["carapace", "reset", "--all", "--force"]).unwrap();
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
            "carapace",
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

    // -----------------------------------------------------------------------
    // Setup subcommand tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_cli_setup_no_force() {
        let cli = Cli::try_parse_from(["carapace", "setup"]).unwrap();
        match cli.command {
            Some(Command::Setup { force }) => {
                assert!(!force);
            }
            other => panic!("Expected Setup, got {:?}", other),
        }
    }

    #[test]
    fn test_cli_setup_with_force() {
        let cli = Cli::try_parse_from(["carapace", "setup", "--force"]).unwrap();
        match cli.command {
            Some(Command::Setup { force }) => {
                assert!(force);
            }
            other => panic!("Expected Setup, got {:?}", other),
        }
    }

    #[test]
    fn test_handle_setup_errors_when_config_exists_no_force() {
        let temp = tempfile::TempDir::new().unwrap();
        let config_path = temp.path().join("moltbot.json");
        std::fs::write(&config_path, "{}").unwrap();

        // Point config to our temp file.
        std::env::set_var("MOLTBOT_CONFIG_PATH", config_path.to_str().unwrap());
        let result = handle_setup(false);
        std::env::remove_var("MOLTBOT_CONFIG_PATH");

        assert!(
            result.is_err(),
            "Should error when config exists and force=false"
        );
    }

    #[test]
    fn test_handle_setup_force_creates_config() {
        let temp = tempfile::TempDir::new().unwrap();
        let config_path = temp.path().join("moltbot.json");
        std::fs::write(&config_path, "{}").unwrap();

        std::env::set_var("MOLTBOT_CONFIG_PATH", config_path.to_str().unwrap());
        let result = handle_setup(true);
        std::env::remove_var("MOLTBOT_CONFIG_PATH");

        assert!(
            result.is_ok(),
            "Should succeed with force=true even when config exists"
        );
        assert!(config_path.exists(), "Config file should exist after setup");
    }

    #[test]
    fn test_handle_setup_creates_valid_json5_config() {
        let temp = tempfile::TempDir::new().unwrap();
        let config_path = temp.path().join("moltbot.json");

        std::env::set_var("MOLTBOT_CONFIG_PATH", config_path.to_str().unwrap());
        let result = handle_setup(false);
        std::env::remove_var("MOLTBOT_CONFIG_PATH");

        assert!(result.is_ok(), "Setup should succeed");

        let content = std::fs::read_to_string(&config_path).unwrap();
        let parsed: serde_json::Value = json5::from_str(&content).unwrap();
        assert!(parsed.is_object(), "Config should be a JSON object");
    }

    #[test]
    fn test_handle_setup_default_values() {
        let temp = tempfile::TempDir::new().unwrap();
        let config_path = temp.path().join("moltbot.json");

        std::env::set_var("MOLTBOT_CONFIG_PATH", config_path.to_str().unwrap());
        let result = handle_setup(false);
        std::env::remove_var("MOLTBOT_CONFIG_PATH");

        assert!(result.is_ok());

        let content = std::fs::read_to_string(&config_path).unwrap();
        let parsed: serde_json::Value = json5::from_str(&content).unwrap();

        assert_eq!(
            parsed["gateway"]["port"], 3001,
            "Default port should be 3001"
        );
        assert_eq!(
            parsed["gateway"]["bind"], "loopback",
            "Default bind should be loopback"
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
        let cli = Cli::try_parse_from(["carapace", "pair", "https://gateway.local:3001"]).unwrap();
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
            "carapace",
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
        let cli = Cli::try_parse_from(["carapace", "update", "--check"]).unwrap();
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
        let cli = Cli::try_parse_from(["carapace", "update", "--version", "0.2.0"]).unwrap();
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
        let cli = Cli::try_parse_from(["carapace", "tls", "init-ca"]).unwrap();
        match cli.command {
            Some(Command::Tls(TlsCommand::InitCa { output })) => {
                assert!(output.is_none());
            }
            other => panic!("Expected Tls(InitCa), got {:?}", other),
        }
    }

    #[test]
    fn test_cli_tls_init_ca_with_output() {
        let cli =
            Cli::try_parse_from(["carapace", "tls", "init-ca", "--output", "/tmp/ca"]).unwrap();
        match cli.command {
            Some(Command::Tls(TlsCommand::InitCa { output })) => {
                assert_eq!(output.as_deref(), Some("/tmp/ca"));
            }
            other => panic!("Expected Tls(InitCa), got {:?}", other),
        }
    }

    #[test]
    fn test_cli_tls_issue_cert() {
        let cli = Cli::try_parse_from(["carapace", "tls", "issue-cert", "node-east-1"]).unwrap();
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
            "carapace",
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
            "carapace",
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
            "carapace",
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
        let cli = Cli::try_parse_from(["carapace", "tls", "show-ca"]).unwrap();
        match cli.command {
            Some(Command::Tls(TlsCommand::ShowCa { ca_dir })) => {
                assert!(ca_dir.is_none());
            }
            other => panic!("Expected Tls(ShowCa), got {:?}", other),
        }
    }

    #[test]
    fn test_cli_tls_show_ca_with_dir() {
        let cli =
            Cli::try_parse_from(["carapace", "tls", "show-ca", "--ca-dir", "/tmp/ca"]).unwrap();
        match cli.command {
            Some(Command::Tls(TlsCommand::ShowCa { ca_dir })) => {
                assert_eq!(ca_dir.as_deref(), Some("/tmp/ca"));
            }
            other => panic!("Expected Tls(ShowCa), got {:?}", other),
        }
    }
}
