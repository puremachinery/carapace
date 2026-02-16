//! mDNS service discovery module
//!
//! Advertises the gateway on the local network via mDNS/DNS-SD (Bonjour)
//! so that clients can discover it automatically. Uses the `_carapace._tcp.local.`
//! service type.
//!
//! Three discovery modes are supported:
//! - `off`: no mDNS broadcast (default)
//! - `minimal`: broadcast service with minimal TXT records (version only)
//! - `full`: broadcast service with all TXT records (version, fingerprint, device name)

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{debug, error, info, warn};

/// mDNS service type for the gateway
pub const SERVICE_TYPE: &str = "_carapace._tcp.local.";

/// Discovery mode
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum DiscoveryMode {
    /// No mDNS broadcast
    #[default]
    Off,
    /// Broadcast service with minimal TXT records
    Minimal,
    /// Broadcast service with all TXT records
    Full,
}

impl DiscoveryMode {
    /// Parse a discovery mode from a string value.
    /// Returns `None` for unrecognized values.
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_lowercase().as_str() {
            "off" | "disabled" | "none" => Some(DiscoveryMode::Off),
            "minimal" | "min" => Some(DiscoveryMode::Minimal),
            "full" | "all" => Some(DiscoveryMode::Full),
            _ => None,
        }
    }

    /// Whether mDNS broadcasting is enabled
    pub fn is_enabled(&self) -> bool {
        !matches!(self, DiscoveryMode::Off)
    }
}

/// Discovery configuration parsed from the config file
#[derive(Debug, Clone)]
pub struct DiscoveryConfig {
    /// Discovery mode
    pub mode: DiscoveryMode,
    /// Custom service name (defaults to hostname)
    pub service_name: Option<String>,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        DiscoveryConfig {
            mode: DiscoveryMode::Off,
            service_name: None,
        }
    }
}

/// Build a DiscoveryConfig from the loaded JSON configuration.
///
/// Reads from the `discovery` section:
/// ```json5
/// {
///   discovery: {
///     mode: "off",        // "off" | "minimal" | "full"
///     serviceName: "my-gateway"  // optional, defaults to hostname
///   }
/// }
/// ```
pub fn build_discovery_config(cfg: &serde_json::Value) -> DiscoveryConfig {
    let discovery = cfg.get("discovery").and_then(|v| v.as_object());

    let mode = discovery
        .and_then(|d| d.get("mode"))
        .and_then(|v| v.as_str())
        .and_then(DiscoveryMode::parse)
        .unwrap_or_default();

    let service_name = discovery
        .and_then(|d| d.get("serviceName"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .filter(|s| !s.trim().is_empty());

    DiscoveryConfig { mode, service_name }
}

/// Properties to include in the mDNS TXT records
#[derive(Debug, Clone)]
pub struct ServiceProperties {
    /// Gateway version
    pub version: String,
    /// TLS certificate SHA-256 fingerprint (hex-encoded), if TLS is enabled
    pub fingerprint: Option<String>,
    /// Device/host display name
    pub device_name: String,
}

/// Build TXT record properties based on the discovery mode.
///
/// - `minimal`: only includes `version`
/// - `full`: includes `version`, `fingerprint` (if present), and `device`
pub fn build_txt_properties(
    mode: &DiscoveryMode,
    props: &ServiceProperties,
) -> HashMap<String, String> {
    let mut txt = HashMap::new();

    match mode {
        DiscoveryMode::Off => {
            // Should not be called for off mode, but return empty just in case
        }
        DiscoveryMode::Minimal => {
            txt.insert("version".to_string(), props.version.clone());
        }
        DiscoveryMode::Full => {
            txt.insert("version".to_string(), props.version.clone());
            if let Some(ref fp) = props.fingerprint {
                txt.insert("fingerprint".to_string(), fp.clone());
            }
            txt.insert("device".to_string(), props.device_name.clone());
        }
    }

    txt
}

/// Resolve the service instance name.
///
/// Uses the configured service name if provided, otherwise falls back to the
/// system hostname.
pub fn resolve_service_name(config: &DiscoveryConfig) -> String {
    if let Some(ref name) = config.service_name {
        return name.clone();
    }

    // Fall back to hostname
    hostname::get()
        .ok()
        .and_then(|h| h.into_string().ok())
        .unwrap_or_else(|| "carapace-gateway".to_string())
}

/// Handle for a running mDNS service daemon.
///
/// Holds the `ServiceDaemon` and the fullname of the registered service,
/// allowing clean unregistration on shutdown.
pub struct MdnsHandle {
    daemon: mdns_sd::ServiceDaemon,
    fullname: String,
}

impl MdnsHandle {
    /// Shut down the mDNS daemon cleanly by unregistering the service
    /// and shutting down the daemon.
    pub fn shutdown(self) {
        info!("Shutting down mDNS discovery");
        if let Err(e) = self.daemon.unregister(&self.fullname) {
            warn!("Failed to unregister mDNS service: {}", e);
        }
        if let Err(e) = self.daemon.shutdown() {
            warn!("Failed to shut down mDNS daemon: {}", e);
        }
    }
}

/// Build the TXT record key-value pairs as a `Vec` of `(&str, &str)` slices
/// ready for `ServiceInfo::new`.
fn prepare_txt_records(txt_records: &HashMap<String, String>) -> Vec<(&str, &str)> {
    let mut properties: Vec<(&str, &str)> = Vec::new();
    for (k, v) in txt_records {
        properties.push((k.as_str(), v.as_str()));
    }
    properties
}

/// Resolve the system hostname and format it with a `.local.` suffix as
/// required by `mdns-sd`.
fn resolve_hostname() -> String {
    let hostname = hostname::get()
        .ok()
        .and_then(|h| h.into_string().ok())
        .unwrap_or_else(|| "localhost".to_string());

    if hostname.ends_with(".local.") {
        hostname
    } else if hostname.ends_with(".local") {
        format!("{}.", hostname)
    } else {
        format!("{}.local.", hostname)
    }
}

/// Create the mDNS daemon, build the `ServiceInfo`, and register it.
///
/// Returns the daemon and the registered service fullname.
fn register_mdns_service(
    instance_name: &str,
    port: u16,
    txt_records: &HashMap<String, String>,
) -> Result<(mdns_sd::ServiceDaemon, String), mdns_sd::Error> {
    let daemon = mdns_sd::ServiceDaemon::new()?;

    let properties = prepare_txt_records(txt_records);
    let host_label = resolve_hostname();

    let service_info = mdns_sd::ServiceInfo::new(
        SERVICE_TYPE,
        instance_name,
        &host_label,
        "", // empty IP -- let mdns-sd use the host's addresses
        port,
        properties.as_slice(),
    )?;

    let fullname = service_info.get_fullname().to_string();
    daemon.register(service_info)?;

    Ok((daemon, fullname))
}

/// Log the successful mDNS service registration along with TXT record details.
fn log_mdns_registration(
    fullname: &str,
    port: u16,
    mode: &DiscoveryMode,
    txt_records: &HashMap<String, String>,
) {
    info!(
        "mDNS service registered: {} on port {} ({})",
        fullname,
        port,
        match mode {
            DiscoveryMode::Minimal => "minimal TXT records",
            DiscoveryMode::Full => "full TXT records",
            DiscoveryMode::Off => unreachable!(),
        }
    );

    for (k, v) in txt_records {
        debug!("  TXT: {}={}", k, v);
    }
}

/// Start the mDNS service daemon and register the gateway service.
///
/// Returns an `MdnsHandle` on success that must be shut down on exit,
/// or `None` if discovery mode is `off`.
///
/// # Arguments
/// * `config` - Discovery configuration
/// * `port` - The port the HTTP server is bound to
/// * `props` - Service properties for TXT records
pub fn start_mdns(
    config: &DiscoveryConfig,
    port: u16,
    props: &ServiceProperties,
) -> Result<Option<MdnsHandle>, mdns_sd::Error> {
    if !config.mode.is_enabled() {
        debug!("mDNS discovery is disabled");
        return Ok(None);
    }

    let instance_name = resolve_service_name(config);
    let txt_records = build_txt_properties(&config.mode, props);

    info!(
        "Starting mDNS discovery: service='{}', mode={:?}, port={}",
        instance_name, config.mode, port
    );

    let (daemon, fullname) = register_mdns_service(&instance_name, port, &txt_records)?;

    log_mdns_registration(&fullname, port, &config.mode, &txt_records);

    Ok(Some(MdnsHandle { daemon, fullname }))
}

/// Spawn the mDNS lifecycle as a background tokio task.
///
/// Starts the mDNS daemon and waits for the shutdown signal, then cleans up.
/// This function is meant to be called from `tokio::spawn`.
///
/// Returns immediately if discovery mode is `off`.
pub async fn run_mdns_lifecycle(
    config: DiscoveryConfig,
    port: u16,
    props: ServiceProperties,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    if !config.mode.is_enabled() {
        return;
    }

    let handle = match start_mdns(&config, port, &props) {
        Ok(Some(h)) => h,
        Ok(None) => return,
        Err(e) => {
            error!("Failed to start mDNS discovery: {}", e);
            return;
        }
    };

    // Wait for shutdown signal
    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    break;
                }
            }
        }
    }

    // Clean shutdown
    handle.shutdown();
}

// ============================================================================
// Hostname helper (inline, no extra crate)
// ============================================================================

mod hostname {
    use std::ffi::OsString;

    use crate::agent::sandbox::{
        build_sandboxed_std_command, default_probe_sandbox_config, ensure_sandbox_supported,
    };

    fn run_hostname_command() -> Result<std::process::Output, std::io::Error> {
        let sandbox = default_probe_sandbox_config();
        ensure_sandbox_supported(Some(&sandbox))
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Unsupported, e.to_string()))?;
        build_sandboxed_std_command("hostname", &[], Some(&sandbox)).output()
    }

    /// Get the system hostname via the `hostname` command.
    /// Falls back to environment variables if the command is not available.
    pub fn get() -> Result<OsString, std::io::Error> {
        // Try `hostname` command (available on macOS, Linux, and most Unix systems)
        if let Ok(output) = run_hostname_command() {
            if output.status.success() {
                let name = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if !name.is_empty() {
                    return Ok(OsString::from(name));
                }
            }
        }

        // Fallback to environment variables
        if let Some(name) = std::env::var_os("HOSTNAME") {
            return Ok(name);
        }
        if let Some(name) = std::env::var_os("COMPUTERNAME") {
            return Ok(name);
        }

        Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "hostname not available",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ========================================================================
    // DiscoveryMode tests
    // ========================================================================

    #[test]
    fn test_discovery_mode_default_is_off() {
        assert_eq!(DiscoveryMode::default(), DiscoveryMode::Off);
    }

    #[test]
    fn test_discovery_mode_parse_off() {
        assert_eq!(DiscoveryMode::parse("off"), Some(DiscoveryMode::Off));
        assert_eq!(DiscoveryMode::parse("OFF"), Some(DiscoveryMode::Off));
        assert_eq!(DiscoveryMode::parse("disabled"), Some(DiscoveryMode::Off));
        assert_eq!(DiscoveryMode::parse("none"), Some(DiscoveryMode::Off));
    }

    #[test]
    fn test_discovery_mode_parse_minimal() {
        assert_eq!(
            DiscoveryMode::parse("minimal"),
            Some(DiscoveryMode::Minimal)
        );
        assert_eq!(
            DiscoveryMode::parse("MINIMAL"),
            Some(DiscoveryMode::Minimal)
        );
        assert_eq!(DiscoveryMode::parse("min"), Some(DiscoveryMode::Minimal));
    }

    #[test]
    fn test_discovery_mode_parse_full() {
        assert_eq!(DiscoveryMode::parse("full"), Some(DiscoveryMode::Full));
        assert_eq!(DiscoveryMode::parse("FULL"), Some(DiscoveryMode::Full));
        assert_eq!(DiscoveryMode::parse("all"), Some(DiscoveryMode::Full));
    }

    #[test]
    fn test_discovery_mode_parse_invalid() {
        assert_eq!(DiscoveryMode::parse("invalid"), None);
        assert_eq!(DiscoveryMode::parse(""), None);
        assert_eq!(DiscoveryMode::parse("yes"), None);
    }

    #[test]
    fn test_discovery_mode_parse_trims_whitespace() {
        assert_eq!(DiscoveryMode::parse("  full  "), Some(DiscoveryMode::Full));
    }

    #[test]
    fn test_discovery_mode_is_enabled() {
        assert!(!DiscoveryMode::Off.is_enabled());
        assert!(DiscoveryMode::Minimal.is_enabled());
        assert!(DiscoveryMode::Full.is_enabled());
    }

    // ========================================================================
    // DiscoveryConfig / build_discovery_config tests
    // ========================================================================

    #[test]
    fn test_discovery_config_default() {
        let config = DiscoveryConfig::default();
        assert_eq!(config.mode, DiscoveryMode::Off);
        assert!(config.service_name.is_none());
    }

    #[test]
    fn test_build_discovery_config_empty() {
        let cfg = json!({});
        let config = build_discovery_config(&cfg);
        assert_eq!(config.mode, DiscoveryMode::Off);
        assert!(config.service_name.is_none());
    }

    #[test]
    fn test_build_discovery_config_mode_off() {
        let cfg = json!({
            "discovery": {
                "mode": "off"
            }
        });
        let config = build_discovery_config(&cfg);
        assert_eq!(config.mode, DiscoveryMode::Off);
    }

    #[test]
    fn test_build_discovery_config_mode_minimal() {
        let cfg = json!({
            "discovery": {
                "mode": "minimal"
            }
        });
        let config = build_discovery_config(&cfg);
        assert_eq!(config.mode, DiscoveryMode::Minimal);
    }

    #[test]
    fn test_build_discovery_config_mode_full() {
        let cfg = json!({
            "discovery": {
                "mode": "full"
            }
        });
        let config = build_discovery_config(&cfg);
        assert_eq!(config.mode, DiscoveryMode::Full);
    }

    #[test]
    fn test_build_discovery_config_invalid_mode_defaults_to_off() {
        let cfg = json!({
            "discovery": {
                "mode": "garbage"
            }
        });
        let config = build_discovery_config(&cfg);
        assert_eq!(config.mode, DiscoveryMode::Off);
    }

    #[test]
    fn test_build_discovery_config_with_service_name() {
        let cfg = json!({
            "discovery": {
                "mode": "full",
                "serviceName": "my-gateway"
            }
        });
        let config = build_discovery_config(&cfg);
        assert_eq!(config.mode, DiscoveryMode::Full);
        assert_eq!(config.service_name, Some("my-gateway".to_string()));
    }

    #[test]
    fn test_build_discovery_config_empty_service_name_ignored() {
        let cfg = json!({
            "discovery": {
                "mode": "minimal",
                "serviceName": ""
            }
        });
        let config = build_discovery_config(&cfg);
        assert!(config.service_name.is_none());
    }

    #[test]
    fn test_build_discovery_config_whitespace_service_name_ignored() {
        let cfg = json!({
            "discovery": {
                "mode": "minimal",
                "serviceName": "   "
            }
        });
        let config = build_discovery_config(&cfg);
        assert!(config.service_name.is_none());
    }

    // ========================================================================
    // TXT property building tests
    // ========================================================================

    fn test_props() -> ServiceProperties {
        ServiceProperties {
            version: "0.1.0".to_string(),
            fingerprint: Some("abcdef1234567890".to_string()),
            device_name: "test-device".to_string(),
        }
    }

    #[test]
    fn test_build_txt_properties_off_returns_empty() {
        let txt = build_txt_properties(&DiscoveryMode::Off, &test_props());
        assert!(txt.is_empty());
    }

    #[test]
    fn test_build_txt_properties_minimal() {
        let txt = build_txt_properties(&DiscoveryMode::Minimal, &test_props());
        assert_eq!(txt.len(), 1);
        assert_eq!(txt.get("version"), Some(&"0.1.0".to_string()));
        assert!(!txt.contains_key("fingerprint"));
        assert!(!txt.contains_key("device"));
    }

    #[test]
    fn test_build_txt_properties_full() {
        let txt = build_txt_properties(&DiscoveryMode::Full, &test_props());
        assert_eq!(txt.len(), 3);
        assert_eq!(txt.get("version"), Some(&"0.1.0".to_string()));
        assert_eq!(
            txt.get("fingerprint"),
            Some(&"abcdef1234567890".to_string())
        );
        assert_eq!(txt.get("device"), Some(&"test-device".to_string()));
    }

    #[test]
    fn test_build_txt_properties_full_no_fingerprint() {
        let props = ServiceProperties {
            version: "1.2.3".to_string(),
            fingerprint: None,
            device_name: "myhost".to_string(),
        };
        let txt = build_txt_properties(&DiscoveryMode::Full, &props);
        assert_eq!(txt.len(), 2);
        assert_eq!(txt.get("version"), Some(&"1.2.3".to_string()));
        assert!(!txt.contains_key("fingerprint"));
        assert_eq!(txt.get("device"), Some(&"myhost".to_string()));
    }

    // ========================================================================
    // Service name resolution tests
    // ========================================================================

    #[test]
    fn test_resolve_service_name_with_config() {
        let config = DiscoveryConfig {
            mode: DiscoveryMode::Full,
            service_name: Some("my-custom-name".to_string()),
        };
        assert_eq!(resolve_service_name(&config), "my-custom-name");
    }

    #[test]
    fn test_resolve_service_name_falls_back_to_hostname() {
        let config = DiscoveryConfig {
            mode: DiscoveryMode::Full,
            service_name: None,
        };
        let name = resolve_service_name(&config);
        // Should be a non-empty string (the hostname)
        assert!(!name.is_empty());
    }

    // ========================================================================
    // Serde round-trip tests for DiscoveryMode
    // ========================================================================

    #[test]
    fn test_discovery_mode_serde_roundtrip() {
        let modes = vec![
            DiscoveryMode::Off,
            DiscoveryMode::Minimal,
            DiscoveryMode::Full,
        ];
        for mode in modes {
            let json = serde_json::to_string(&mode).unwrap();
            let parsed: DiscoveryMode = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, mode);
        }
    }

    #[test]
    fn test_discovery_mode_serializes_lowercase() {
        assert_eq!(
            serde_json::to_string(&DiscoveryMode::Off).unwrap(),
            "\"off\""
        );
        assert_eq!(
            serde_json::to_string(&DiscoveryMode::Minimal).unwrap(),
            "\"minimal\""
        );
        assert_eq!(
            serde_json::to_string(&DiscoveryMode::Full).unwrap(),
            "\"full\""
        );
    }

    // ========================================================================
    // Service constant test
    // ========================================================================

    #[test]
    fn test_service_type_constant() {
        assert_eq!(SERVICE_TYPE, "_carapace._tcp.local.");
        assert!(SERVICE_TYPE.starts_with("_"));
        assert!(SERVICE_TYPE.ends_with(".local."));
    }

    // ========================================================================
    // start_mdns disabled mode test
    // ========================================================================

    #[test]
    fn test_start_mdns_off_returns_none() {
        let config = DiscoveryConfig::default();
        let props = test_props();
        let result = start_mdns(&config, 18789, &props).unwrap();
        assert!(result.is_none());
    }
}
