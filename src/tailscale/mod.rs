//! Tailscale serve and funnel integration
//!
//! Auto-configures HTTPS exposure via the Tailscale CLI. Two modes are
//! supported:
//! - `serve`: proxy a local port via Tailscale HTTPS (LAN-accessible via tailnet)
//! - `funnel`: expose to the public internet via Tailscale
//!
//! Configuration lives under `gateway.tailscale` in the JSON5 config file.

use serde_json::Value;
use tracing::{debug, info, warn};

use crate::agent::sandbox::{
    build_sandboxed_tokio_command, default_tailscale_cli_sandbox_config, ensure_sandbox_supported,
};

// ============================================================================
// Core types
// ============================================================================

/// Tailscale integration mode
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum TailscaleMode {
    /// No Tailscale integration
    #[default]
    Off,
    /// Tailscale serve: proxy local port via Tailscale HTTPS (LAN accessible via tailnet)
    Serve,
    /// Tailscale funnel: expose to public internet via Tailscale
    Funnel,
}

impl TailscaleMode {
    /// Parse a mode string from config.
    /// Returns `None` for unrecognized values.
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_lowercase().as_str() {
            "off" | "disabled" | "none" => Some(TailscaleMode::Off),
            "serve" => Some(TailscaleMode::Serve),
            "funnel" => Some(TailscaleMode::Funnel),
            _ => None,
        }
    }

    /// Whether Tailscale integration is enabled (serve or funnel).
    pub fn is_enabled(&self) -> bool {
        !matches!(self, TailscaleMode::Off)
    }
}

/// Configuration for Tailscale integration
#[derive(Debug, Clone)]
pub struct TailscaleConfig {
    pub mode: TailscaleMode,
    /// Local port to proxy (filled from gateway.port)
    pub local_port: u16,
    /// External port to serve on (default: 443)
    pub external_port: u16,
    /// Path to tailscale CLI binary (default: "tailscale")
    pub cli_path: String,
    /// Whether to reset serve/funnel config on shutdown
    pub reset_on_shutdown: bool,
}

impl Default for TailscaleConfig {
    fn default() -> Self {
        TailscaleConfig {
            mode: TailscaleMode::Off,
            local_port: 0,
            external_port: 443,
            cli_path: "tailscale".to_string(),
            reset_on_shutdown: true,
        }
    }
}

// ============================================================================
// Status and result types
// ============================================================================

/// Tailscale daemon status information.
#[derive(Debug, Clone)]
pub struct TailscaleStatus {
    pub is_up: bool,
    pub hostname: Option<String>,
    pub tailnet: Option<String>,
    pub ip: Option<String>,
}

/// Result of a successful serve/funnel setup.
#[derive(Debug, Clone)]
pub struct TailscaleSetupResult {
    pub mode: TailscaleMode,
    pub url: String,
    pub local_port: u16,
    pub external_port: u16,
}

// ============================================================================
// Errors
// ============================================================================

/// Errors that can occur during Tailscale integration.
#[derive(Debug, thiserror::Error)]
pub enum TailscaleError {
    #[error("tailscale CLI not found at '{0}'")]
    CliNotFound(String),
    #[error("tailscale is not running")]
    NotRunning,
    #[error("tailscale command failed: {0}")]
    CommandFailed(String),
    #[error("failed to parse tailscale output: {0}")]
    ParseError(String),
}

// ============================================================================
// Config parsing
// ============================================================================

/// Build TailscaleConfig from the JSON config.
///
/// Config path: `gateway.tailscale`
/// ```json5
/// {
///   gateway: {
///     tailscale: {
///       mode: "serve",      // "off" | "serve" | "funnel"
///       externalPort: 443,
///       cliPath: "tailscale",
///       resetOnShutdown: true
///     }
///   }
/// }
/// ```
pub fn build_tailscale_config(config: &Value, local_port: u16) -> TailscaleConfig {
    let ts = config
        .get("gateway")
        .and_then(|g| g.get("tailscale"))
        .and_then(|v| v.as_object());

    let mode = ts
        .and_then(|t| t.get("mode"))
        .and_then(|v| v.as_str())
        .and_then(TailscaleMode::parse)
        .unwrap_or_default();

    let external_port = ts
        .and_then(|t| t.get("externalPort"))
        .and_then(|v| v.as_u64())
        .map(|p| p as u16)
        .unwrap_or(443);

    let cli_path = ts
        .and_then(|t| t.get("cliPath"))
        .and_then(|v| v.as_str())
        .unwrap_or("tailscale")
        .to_string();

    let reset_on_shutdown = ts
        .and_then(|t| t.get("resetOnShutdown"))
        .and_then(|v| v.as_bool())
        .unwrap_or(true);

    TailscaleConfig {
        mode,
        local_port,
        external_port,
        cli_path,
        reset_on_shutdown,
    }
}

// ============================================================================
// CLI wrapper helpers
// ============================================================================

/// Execute a tailscale CLI command and return its output.
async fn run_command(
    cli_path: &str,
    args: &[&str],
) -> Result<std::process::Output, TailscaleError> {
    let sandbox = default_tailscale_cli_sandbox_config();
    ensure_sandbox_supported(Some(&sandbox))
        .map_err(|e| TailscaleError::CommandFailed(format!("sandbox unavailable: {e}")))?;
    build_sandboxed_tokio_command(cli_path, args, Some(&sandbox))
        .output()
        .await
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                TailscaleError::CliNotFound(cli_path.to_string())
            } else {
                TailscaleError::CommandFailed(format!("failed to execute: {e}"))
            }
        })
}

/// Build the argument list for a `tailscale serve` command.
pub fn build_serve_args(config: &TailscaleConfig) -> Vec<String> {
    vec![
        "serve".to_string(),
        "--bg".to_string(),
        format!("--https={}", config.external_port),
        format!("http://localhost:{}", config.local_port),
    ]
}

/// Build the argument list for a `tailscale funnel` command.
pub fn build_funnel_args(config: &TailscaleConfig) -> Vec<String> {
    vec![
        "funnel".to_string(),
        "--bg".to_string(),
        format!("--https={}", config.external_port),
        format!("http://localhost:{}", config.local_port),
    ]
}

/// Build the argument list for tearing down a serve/funnel configuration.
pub fn build_teardown_args(config: &TailscaleConfig) -> Vec<String> {
    vec![
        "serve".to_string(),
        format!("--https={}", config.external_port),
        "off".to_string(),
    ]
}

/// Construct the public HTTPS URL from a hostname and external port.
pub fn build_url(hostname: &str, external_port: u16) -> String {
    if external_port == 443 {
        format!("https://{hostname}")
    } else {
        format!("https://{hostname}:{external_port}")
    }
}

// ============================================================================
// CLI commands
// ============================================================================

/// Check if Tailscale CLI is available and return its version.
pub async fn check_tailscale(cli_path: &str) -> Result<String, TailscaleError> {
    let output = run_command(cli_path, &["version"]).await?;
    if !output.status.success() {
        return Err(TailscaleError::CommandFailed(
            String::from_utf8_lossy(&output.stderr).to_string(),
        ));
    }
    let version = String::from_utf8_lossy(&output.stdout).trim().to_string();
    Ok(version)
}

/// Parse `tailscale status --json` output into a `TailscaleStatus`.
pub fn parse_status(json: &Value) -> TailscaleStatus {
    let backend_state = json
        .get("BackendState")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    let is_up = backend_state == "Running";

    let hostname = json
        .get("Self")
        .and_then(|s| s.get("HostName"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let tailnet = json
        .get("CurrentTailnet")
        .and_then(|t| t.get("MagicDNSSuffix"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let ip = json
        .get("TailscaleIPs")
        .and_then(|v| v.as_array())
        .and_then(|arr| arr.first())
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    TailscaleStatus {
        is_up,
        hostname,
        tailnet,
        ip,
    }
}

/// Get the current Tailscale status (up/down, hostname, tailnet name).
pub async fn get_status(cli_path: &str) -> Result<TailscaleStatus, TailscaleError> {
    let output = run_command(cli_path, &["status", "--json"]).await?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("not running") || stderr.contains("not logged in") {
            return Err(TailscaleError::NotRunning);
        }
        return Err(TailscaleError::CommandFailed(stderr.to_string()));
    }

    let json: Value = serde_json::from_slice(&output.stdout)
        .map_err(|e| TailscaleError::ParseError(format!("failed to parse status JSON: {e}")))?;

    Ok(parse_status(&json))
}

/// Configure Tailscale serve to proxy local_port.
/// Runs: tailscale serve --bg --https={external_port} http://localhost:{local_port}
pub async fn setup_serve(config: &TailscaleConfig) -> Result<TailscaleSetupResult, TailscaleError> {
    let args = build_serve_args(config);
    let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    let output = run_command(&config.cli_path, &arg_refs).await?;

    if !output.status.success() {
        return Err(TailscaleError::CommandFailed(
            String::from_utf8_lossy(&output.stderr).to_string(),
        ));
    }

    // Fetch status to get hostname for URL construction
    let status = get_status(&config.cli_path).await?;
    let hostname = status.hostname.unwrap_or_else(|| "unknown".to_string());
    let tailnet = status.tailnet.unwrap_or_else(|| "ts.net".to_string());

    let fqdn = format!("{hostname}.{tailnet}");
    let url = build_url(&fqdn, config.external_port);

    Ok(TailscaleSetupResult {
        mode: TailscaleMode::Serve,
        url,
        local_port: config.local_port,
        external_port: config.external_port,
    })
}

/// Configure Tailscale funnel to expose via public internet.
/// Runs: tailscale funnel --bg --https={external_port} http://localhost:{local_port}
pub async fn setup_funnel(
    config: &TailscaleConfig,
) -> Result<TailscaleSetupResult, TailscaleError> {
    let args = build_funnel_args(config);
    let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    let output = run_command(&config.cli_path, &arg_refs).await?;

    if !output.status.success() {
        return Err(TailscaleError::CommandFailed(
            String::from_utf8_lossy(&output.stderr).to_string(),
        ));
    }

    // Fetch status to get hostname for URL construction
    let status = get_status(&config.cli_path).await?;
    let hostname = status.hostname.unwrap_or_else(|| "unknown".to_string());
    let tailnet = status.tailnet.unwrap_or_else(|| "ts.net".to_string());

    let fqdn = format!("{hostname}.{tailnet}");
    let url = build_url(&fqdn, config.external_port);

    Ok(TailscaleSetupResult {
        mode: TailscaleMode::Funnel,
        url,
        local_port: config.local_port,
        external_port: config.external_port,
    })
}

/// Remove the serve/funnel configuration.
/// Runs: tailscale serve --https={external_port} off
pub async fn teardown(config: &TailscaleConfig) -> Result<(), TailscaleError> {
    let args = build_teardown_args(config);
    let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    let output = run_command(&config.cli_path, &arg_refs).await?;

    if !output.status.success() {
        return Err(TailscaleError::CommandFailed(
            String::from_utf8_lossy(&output.stderr).to_string(),
        ));
    }

    Ok(())
}

// ============================================================================
// Lifecycle management
// ============================================================================

/// Validate that the Tailscale CLI is accessible and the daemon is running.
///
/// Returns the daemon status on success.
async fn validate_tailscale_environment(cli_path: &str) -> Result<TailscaleStatus, TailscaleError> {
    let version = check_tailscale(cli_path).await?;
    info!("Tailscale CLI version: {}", version);

    let status = get_status(cli_path).await?;
    if !status.is_up {
        return Err(TailscaleError::NotRunning);
    }
    debug!(
        "Tailscale is running: hostname={:?}, tailnet={:?}, ip={:?}",
        status.hostname, status.tailnet, status.ip
    );

    Ok(status)
}

/// Execute the mode-specific serve or funnel setup.
async fn execute_tailscale_setup(
    config: &TailscaleConfig,
) -> Result<TailscaleSetupResult, TailscaleError> {
    match config.mode {
        TailscaleMode::Serve => {
            info!(
                "Setting up Tailscale serve: localhost:{} -> https port {}",
                config.local_port, config.external_port
            );
            setup_serve(config).await
        }
        TailscaleMode::Funnel => {
            info!(
                "Setting up Tailscale funnel: localhost:{} -> https port {} (public)",
                config.local_port, config.external_port
            );
            setup_funnel(config).await
        }
        TailscaleMode::Off => unreachable!(),
    }
}

/// Run the Tailscale serve/funnel lifecycle.
///
/// - Checks the CLI is available and Tailscale is running
/// - Sets up serve or funnel based on config
/// - Waits for shutdown signal
/// - Tears down on shutdown (if reset_on_shutdown is true)
pub async fn run_tailscale_lifecycle(
    config: TailscaleConfig,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) -> Result<(), TailscaleError> {
    if !config.mode.is_enabled() {
        return Ok(());
    }

    validate_tailscale_environment(&config.cli_path).await?;

    let result = execute_tailscale_setup(&config).await?;

    info!(
        "Tailscale {:?} active: {} (local:{} -> external:{})",
        result.mode, result.url, result.local_port, result.external_port
    );

    await_shutdown_signal(&mut shutdown_rx).await;

    perform_teardown_if_configured(&config).await;

    Ok(())
}

/// Block until the shutdown watch channel signals `true`.
async fn await_shutdown_signal(shutdown_rx: &mut tokio::sync::watch::Receiver<bool>) {
    loop {
        tokio::select! {
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    break;
                }
            }
        }
    }
}

/// Tear down the Tailscale serve/funnel configuration if `reset_on_shutdown`
/// is enabled.
async fn perform_teardown_if_configured(config: &TailscaleConfig) {
    if config.reset_on_shutdown {
        info!("Tearing down Tailscale serve/funnel configuration");
        if let Err(e) = teardown(config).await {
            warn!("Failed to tear down Tailscale config: {}", e);
        }
    } else {
        debug!("Tailscale reset_on_shutdown is false, leaving configuration in place");
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ========================================================================
    // TailscaleMode tests
    // ========================================================================

    #[test]
    fn test_tailscale_mode_default_is_off() {
        assert_eq!(TailscaleMode::default(), TailscaleMode::Off);
    }

    #[test]
    fn test_tailscale_mode_parse_off() {
        assert_eq!(TailscaleMode::parse("off"), Some(TailscaleMode::Off));
        assert_eq!(TailscaleMode::parse("OFF"), Some(TailscaleMode::Off));
        assert_eq!(TailscaleMode::parse("disabled"), Some(TailscaleMode::Off));
        assert_eq!(TailscaleMode::parse("none"), Some(TailscaleMode::Off));
    }

    #[test]
    fn test_tailscale_mode_parse_serve() {
        assert_eq!(TailscaleMode::parse("serve"), Some(TailscaleMode::Serve));
        assert_eq!(TailscaleMode::parse("SERVE"), Some(TailscaleMode::Serve));
        assert_eq!(TailscaleMode::parse("Serve"), Some(TailscaleMode::Serve));
    }

    #[test]
    fn test_tailscale_mode_parse_funnel() {
        assert_eq!(TailscaleMode::parse("funnel"), Some(TailscaleMode::Funnel));
        assert_eq!(TailscaleMode::parse("FUNNEL"), Some(TailscaleMode::Funnel));
        assert_eq!(TailscaleMode::parse("Funnel"), Some(TailscaleMode::Funnel));
    }

    #[test]
    fn test_tailscale_mode_parse_invalid() {
        assert_eq!(TailscaleMode::parse("invalid"), None);
        assert_eq!(TailscaleMode::parse(""), None);
        assert_eq!(TailscaleMode::parse("yes"), None);
        assert_eq!(TailscaleMode::parse("proxy"), None);
    }

    #[test]
    fn test_tailscale_mode_parse_trims_whitespace() {
        assert_eq!(
            TailscaleMode::parse("  serve  "),
            Some(TailscaleMode::Serve)
        );
        assert_eq!(
            TailscaleMode::parse("\tfunnel\n"),
            Some(TailscaleMode::Funnel)
        );
    }

    #[test]
    fn test_tailscale_mode_is_enabled() {
        assert!(!TailscaleMode::Off.is_enabled());
        assert!(TailscaleMode::Serve.is_enabled());
        assert!(TailscaleMode::Funnel.is_enabled());
    }

    #[test]
    fn test_tailscale_mode_equality() {
        assert_eq!(TailscaleMode::Off, TailscaleMode::Off);
        assert_eq!(TailscaleMode::Serve, TailscaleMode::Serve);
        assert_eq!(TailscaleMode::Funnel, TailscaleMode::Funnel);
        assert_ne!(TailscaleMode::Off, TailscaleMode::Serve);
        assert_ne!(TailscaleMode::Serve, TailscaleMode::Funnel);
        assert_ne!(TailscaleMode::Funnel, TailscaleMode::Off);
    }

    // ========================================================================
    // TailscaleConfig tests
    // ========================================================================

    #[test]
    fn test_tailscale_config_default() {
        let config = TailscaleConfig::default();
        assert_eq!(config.mode, TailscaleMode::Off);
        assert_eq!(config.local_port, 0);
        assert_eq!(config.external_port, 443);
        assert_eq!(config.cli_path, "tailscale");
        assert!(config.reset_on_shutdown);
    }

    // ========================================================================
    // build_tailscale_config tests
    // ========================================================================

    #[test]
    fn test_build_config_missing_section_defaults_to_off() {
        let cfg = json!({});
        let config = build_tailscale_config(&cfg, 18789);
        assert_eq!(config.mode, TailscaleMode::Off);
        assert_eq!(config.local_port, 18789);
        assert_eq!(config.external_port, 443);
        assert_eq!(config.cli_path, "tailscale");
        assert!(config.reset_on_shutdown);
    }

    #[test]
    fn test_build_config_mode_serve() {
        let cfg = json!({
            "gateway": {
                "tailscale": {
                    "mode": "serve"
                }
            }
        });
        let config = build_tailscale_config(&cfg, 8080);
        assert_eq!(config.mode, TailscaleMode::Serve);
        assert_eq!(config.local_port, 8080);
    }

    #[test]
    fn test_build_config_mode_funnel() {
        let cfg = json!({
            "gateway": {
                "tailscale": {
                    "mode": "funnel"
                }
            }
        });
        let config = build_tailscale_config(&cfg, 3000);
        assert_eq!(config.mode, TailscaleMode::Funnel);
        assert_eq!(config.local_port, 3000);
    }

    #[test]
    fn test_build_config_mode_off() {
        let cfg = json!({
            "gateway": {
                "tailscale": {
                    "mode": "off"
                }
            }
        });
        let config = build_tailscale_config(&cfg, 18789);
        assert_eq!(config.mode, TailscaleMode::Off);
    }

    #[test]
    fn test_build_config_invalid_mode_defaults_to_off() {
        let cfg = json!({
            "gateway": {
                "tailscale": {
                    "mode": "garbage"
                }
            }
        });
        let config = build_tailscale_config(&cfg, 18789);
        assert_eq!(config.mode, TailscaleMode::Off);
    }

    #[test]
    fn test_build_config_custom_cli_path() {
        let cfg = json!({
            "gateway": {
                "tailscale": {
                    "mode": "serve",
                    "cliPath": "/usr/local/bin/tailscale"
                }
            }
        });
        let config = build_tailscale_config(&cfg, 18789);
        assert_eq!(config.cli_path, "/usr/local/bin/tailscale");
    }

    #[test]
    fn test_build_config_custom_external_port() {
        let cfg = json!({
            "gateway": {
                "tailscale": {
                    "mode": "serve",
                    "externalPort": 8443
                }
            }
        });
        let config = build_tailscale_config(&cfg, 18789);
        assert_eq!(config.external_port, 8443);
    }

    #[test]
    fn test_build_config_reset_on_shutdown_false() {
        let cfg = json!({
            "gateway": {
                "tailscale": {
                    "mode": "serve",
                    "resetOnShutdown": false
                }
            }
        });
        let config = build_tailscale_config(&cfg, 18789);
        assert!(!config.reset_on_shutdown);
    }

    #[test]
    fn test_build_config_all_fields() {
        let cfg = json!({
            "gateway": {
                "tailscale": {
                    "mode": "funnel",
                    "externalPort": 8443,
                    "cliPath": "/opt/bin/tailscale",
                    "resetOnShutdown": false
                }
            }
        });
        let config = build_tailscale_config(&cfg, 9000);
        assert_eq!(config.mode, TailscaleMode::Funnel);
        assert_eq!(config.local_port, 9000);
        assert_eq!(config.external_port, 8443);
        assert_eq!(config.cli_path, "/opt/bin/tailscale");
        assert!(!config.reset_on_shutdown);
    }

    #[test]
    fn test_build_config_gateway_without_tailscale() {
        let cfg = json!({
            "gateway": {
                "port": 18789
            }
        });
        let config = build_tailscale_config(&cfg, 18789);
        assert_eq!(config.mode, TailscaleMode::Off);
    }

    // ========================================================================
    // TailscaleStatus parsing tests
    // ========================================================================

    #[test]
    fn test_parse_status_running() {
        let json = json!({
            "BackendState": "Running",
            "Self": {
                "HostName": "myhost"
            },
            "CurrentTailnet": {
                "MagicDNSSuffix": "tailnet-name.ts.net"
            },
            "TailscaleIPs": ["100.100.50.25", "fd7a:115c:a1e0::1"]
        });
        let status = parse_status(&json);
        assert!(status.is_up);
        assert_eq!(status.hostname, Some("myhost".to_string()));
        assert_eq!(status.tailnet, Some("tailnet-name.ts.net".to_string()));
        assert_eq!(status.ip, Some("100.100.50.25".to_string()));
    }

    #[test]
    fn test_parse_status_stopped() {
        let json = json!({
            "BackendState": "Stopped"
        });
        let status = parse_status(&json);
        assert!(!status.is_up);
        assert!(status.hostname.is_none());
        assert!(status.tailnet.is_none());
        assert!(status.ip.is_none());
    }

    #[test]
    fn test_parse_status_empty_json() {
        let json = json!({});
        let status = parse_status(&json);
        assert!(!status.is_up);
        assert!(status.hostname.is_none());
        assert!(status.tailnet.is_none());
        assert!(status.ip.is_none());
    }

    // ========================================================================
    // TailscaleError display tests
    // ========================================================================

    #[test]
    fn test_error_cli_not_found_display() {
        let err = TailscaleError::CliNotFound("/usr/bin/tailscale".to_string());
        let msg = format!("{err}");
        assert_eq!(msg, "tailscale CLI not found at '/usr/bin/tailscale'");
    }

    #[test]
    fn test_error_not_running_display() {
        let err = TailscaleError::NotRunning;
        let msg = format!("{err}");
        assert_eq!(msg, "tailscale is not running");
    }

    #[test]
    fn test_error_command_failed_display() {
        let err = TailscaleError::CommandFailed("exit code 1".to_string());
        let msg = format!("{err}");
        assert_eq!(msg, "tailscale command failed: exit code 1");
    }

    #[test]
    fn test_error_parse_error_display() {
        let err = TailscaleError::ParseError("invalid json".to_string());
        let msg = format!("{err}");
        assert_eq!(msg, "failed to parse tailscale output: invalid json");
    }

    // ========================================================================
    // URL construction tests
    // ========================================================================

    #[test]
    fn test_build_url_default_port() {
        let url = build_url("myhost.tailnet-name.ts.net", 443);
        assert_eq!(url, "https://myhost.tailnet-name.ts.net");
    }

    #[test]
    fn test_build_url_custom_port() {
        let url = build_url("myhost.tailnet-name.ts.net", 8443);
        assert_eq!(url, "https://myhost.tailnet-name.ts.net:8443");
    }

    // ========================================================================
    // Command argument construction tests
    // ========================================================================

    #[test]
    fn test_build_serve_args() {
        let config = TailscaleConfig {
            mode: TailscaleMode::Serve,
            local_port: 18789,
            external_port: 443,
            cli_path: "tailscale".to_string(),
            reset_on_shutdown: true,
        };
        let args = build_serve_args(&config);
        assert_eq!(
            args,
            vec!["serve", "--bg", "--https=443", "http://localhost:18789"]
        );
    }

    #[test]
    fn test_build_serve_args_custom_ports() {
        let config = TailscaleConfig {
            mode: TailscaleMode::Serve,
            local_port: 3000,
            external_port: 8443,
            cli_path: "tailscale".to_string(),
            reset_on_shutdown: true,
        };
        let args = build_serve_args(&config);
        assert_eq!(
            args,
            vec!["serve", "--bg", "--https=8443", "http://localhost:3000"]
        );
    }

    #[test]
    fn test_build_funnel_args() {
        let config = TailscaleConfig {
            mode: TailscaleMode::Funnel,
            local_port: 18789,
            external_port: 443,
            cli_path: "tailscale".to_string(),
            reset_on_shutdown: true,
        };
        let args = build_funnel_args(&config);
        assert_eq!(
            args,
            vec!["funnel", "--bg", "--https=443", "http://localhost:18789"]
        );
    }

    #[test]
    fn test_build_funnel_args_custom_ports() {
        let config = TailscaleConfig {
            mode: TailscaleMode::Funnel,
            local_port: 9000,
            external_port: 8443,
            cli_path: "tailscale".to_string(),
            reset_on_shutdown: true,
        };
        let args = build_funnel_args(&config);
        assert_eq!(
            args,
            vec!["funnel", "--bg", "--https=8443", "http://localhost:9000"]
        );
    }

    #[test]
    fn test_build_teardown_args() {
        let config = TailscaleConfig {
            mode: TailscaleMode::Serve,
            local_port: 18789,
            external_port: 443,
            cli_path: "tailscale".to_string(),
            reset_on_shutdown: true,
        };
        let args = build_teardown_args(&config);
        assert_eq!(args, vec!["serve", "--https=443", "off"]);
    }

    #[test]
    fn test_build_teardown_args_custom_port() {
        let config = TailscaleConfig {
            mode: TailscaleMode::Funnel,
            local_port: 9000,
            external_port: 8443,
            cli_path: "tailscale".to_string(),
            reset_on_shutdown: true,
        };
        let args = build_teardown_args(&config);
        assert_eq!(args, vec!["serve", "--https=8443", "off"]);
    }

    // ========================================================================
    // Setup result construction test
    // ========================================================================

    #[test]
    fn test_setup_result_fields() {
        let result = TailscaleSetupResult {
            mode: TailscaleMode::Serve,
            url: "https://myhost.tailnet-name.ts.net".to_string(),
            local_port: 18789,
            external_port: 443,
        };
        assert_eq!(result.mode, TailscaleMode::Serve);
        assert_eq!(result.url, "https://myhost.tailnet-name.ts.net");
        assert_eq!(result.local_port, 18789);
        assert_eq!(result.external_port, 443);
    }

    #[test]
    fn test_setup_result_funnel_fields() {
        let result = TailscaleSetupResult {
            mode: TailscaleMode::Funnel,
            url: "https://myhost.tailnet-name.ts.net:8443".to_string(),
            local_port: 3000,
            external_port: 8443,
        };
        assert_eq!(result.mode, TailscaleMode::Funnel);
        assert_eq!(result.url, "https://myhost.tailnet-name.ts.net:8443");
        assert_eq!(result.local_port, 3000);
        assert_eq!(result.external_port, 8443);
    }
}
