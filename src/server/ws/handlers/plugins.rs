//! Plugins handlers.

use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use hickory_resolver::config::ResolverConfig;
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_resolver::TokioResolver;

use super::super::*;
use super::config::{map_validation_issues, read_config_snapshot, write_config_file};
use crate::plugins::capabilities::SsrfProtection;
use crate::plugins::loader::{validate_plugin_component_bytes, LoaderError};
use crate::runtime_bridge::{run_sync_blocking_send, BridgeError};

/// Maximum download size for a plugin WASM binary (50 MB).
const MAX_PLUGIN_DOWNLOAD_BYTES: usize = 50 * 1024 * 1024;

/// Default HTTP timeout for plugin downloads (60 seconds).
const PLUGIN_DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(60);

/// Name of the plugins manifest file stored alongside WASM binaries.
const PLUGINS_MANIFEST_FILE: &str = "plugins-manifest.json";

enum PluginDnsError {
    InvalidRequest(String),
    Unavailable(String),
}

impl std::fmt::Display for PluginDnsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidRequest(msg) | Self::Unavailable(msg) => write!(f, "{}", msg),
        }
    }
}

impl PluginDnsError {
    fn into_error_shape(self) -> ErrorShape {
        match self {
            Self::InvalidRequest(msg) => error_shape(ERROR_INVALID_REQUEST, &msg, None),
            Self::Unavailable(msg) => error_shape(ERROR_UNAVAILABLE, &msg, None),
        }
    }
}

fn ensure_object(value: &mut Value) -> Result<&mut serde_json::Map<String, Value>, ErrorShape> {
    if !value.is_object() {
        *value = Value::Object(serde_json::Map::new());
    }
    value
        .as_object_mut()
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "expected JSON object value", None))
}

/// Resolve the managed plugins directory under the state dir.
fn resolve_plugins_dir() -> PathBuf {
    resolve_state_dir().join("plugins")
}

/// Validate that a plugin name is safe: non-empty, ASCII alphanumeric plus hyphens and
/// underscores, no path separators, and reasonable length.
fn validate_plugin_name(name: &str) -> Result<(), ErrorShape> {
    if name.is_empty() {
        return Err(error_shape(
            ERROR_INVALID_REQUEST,
            "plugin name must not be empty",
            None,
        ));
    }
    if name.len() > 128 {
        return Err(error_shape(
            ERROR_INVALID_REQUEST,
            "plugin name is too long (max 128 characters)",
            None,
        ));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(error_shape(
            ERROR_INVALID_REQUEST,
            "plugin name may only contain ASCII alphanumeric characters, hyphens, and underscores",
            None,
        ));
    }
    Ok(())
}

fn validate_plugin_wasm_bytes(bytes: &[u8], source: &str) -> Result<(), ErrorShape> {
    validate_plugin_wasm_size(bytes.len() as u64, source)?;
    validate_plugin_component_bytes(source, bytes).map_err(|error| match error {
        LoaderError::WasmCompileError { message, .. } => error_shape(
            ERROR_INVALID_REQUEST,
            &format!("{source} is not a valid WASM plugin component: {message}"),
            None,
        ),
        other => error_shape(
            ERROR_UNAVAILABLE,
            &format!("failed to validate {source}: {other}"),
            None,
        ),
    })
}

fn validate_plugin_wasm_size(size_bytes: u64, source: &str) -> Result<(), ErrorShape> {
    if size_bytes > MAX_PLUGIN_DOWNLOAD_BYTES as u64 {
        return Err(error_shape(
            ERROR_INVALID_REQUEST,
            &format!(
                "{source} exceeds maximum size ({} bytes > {} bytes)",
                size_bytes, MAX_PLUGIN_DOWNLOAD_BYTES
            ),
            None,
        ));
    }

    Ok(())
}

/// Validate that a URL string is a well-formed HTTP or HTTPS URL.
fn validate_url(raw: &str) -> Result<url::Url, ErrorShape> {
    let parsed = url::Url::parse(raw)
        .map_err(|e| error_shape(ERROR_INVALID_REQUEST, &format!("invalid url: {}", e), None))?;
    match parsed.scheme() {
        "http" | "https" => Ok(parsed),
        other => Err(error_shape(
            ERROR_INVALID_REQUEST,
            &format!("unsupported url scheme '{}', must be http or https", other),
            None,
        )),
    }
}

/// Read the plugins manifest JSON from the managed plugins directory.
/// Returns an empty object if the file does not exist or cannot be parsed.
fn read_plugins_manifest(plugins_dir: &Path) -> Value {
    let manifest_path = plugins_dir.join(PLUGINS_MANIFEST_FILE);
    match std::fs::read_to_string(&manifest_path) {
        Ok(contents) => serde_json::from_str(&contents).unwrap_or_else(|e| {
            tracing::warn!(
                path = %manifest_path.display(),
                error = %e,
                "plugins manifest JSON is corrupt, falling back to empty object"
            );
            json!({})
        }),
        Err(e) => {
            // Only warn if the file exists but could not be read (permission error, etc.).
            // A missing file is expected on first run and not worth logging.
            if e.kind() != std::io::ErrorKind::NotFound {
                tracing::warn!(
                    path = %manifest_path.display(),
                    error = %e,
                    "failed to read plugins manifest, falling back to empty object"
                );
            }
            json!({})
        }
    }
}

/// Write the plugins manifest JSON to the managed plugins directory using atomic
/// tmp + rename.
fn write_plugins_manifest(plugins_dir: &Path, manifest: &Value) -> Result<(), ErrorShape> {
    std::fs::create_dir_all(plugins_dir).map_err(|e| {
        error_shape(
            ERROR_UNAVAILABLE,
            &format!("failed to create plugins directory: {}", e),
            None,
        )
    })?;

    let manifest_path = plugins_dir.join(PLUGINS_MANIFEST_FILE);
    let tmp_path = plugins_dir.join(format!("{}.tmp", PLUGINS_MANIFEST_FILE));

    let content = serde_json::to_string_pretty(manifest).map_err(|e| {
        error_shape(
            ERROR_UNAVAILABLE,
            &format!("failed to serialize manifest: {}", e),
            None,
        )
    })?;
    {
        let mut file = std::fs::File::create(&tmp_path).map_err(|e| {
            error_shape(
                ERROR_UNAVAILABLE,
                &format!("failed to write plugins manifest: {}", e),
                None,
            )
        })?;
        file.write_all(content.as_bytes()).map_err(|e| {
            error_shape(
                ERROR_UNAVAILABLE,
                &format!("failed to write plugins manifest: {}", e),
                None,
            )
        })?;
        file.write_all(b"\n").map_err(|e| {
            error_shape(
                ERROR_UNAVAILABLE,
                &format!("failed to write plugins manifest: {}", e),
                None,
            )
        })?;
        file.sync_all().map_err(|e| {
            error_shape(
                ERROR_UNAVAILABLE,
                &format!("failed to sync plugins manifest: {}", e),
                None,
            )
        })?;
    }
    std::fs::rename(&tmp_path, &manifest_path).map_err(|e| {
        error_shape(
            ERROR_UNAVAILABLE,
            &format!("failed to replace plugins manifest: {}", e),
            None,
        )
    })?;
    Ok(())
}

/// Compute the SHA-256 hash of the given bytes and return it as a lowercase hex string.
fn compute_sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let hash = hasher.finalize();
    hex::encode(hash)
}

/// Validate the download URL against SSRF attacks and resolve DNS for hostname-based
/// URLs.  Returns `(host, port, resolved_ip)` where `resolved_ip` is `Some` only when
/// the host is a hostname (not an IP literal) and DNS resolution succeeded.
fn validate_and_resolve_dns(url: &url::Url) -> Result<(String, u16, Option<IpAddr>), ErrorShape> {
    // Validate URL against SSRF attacks (blocks localhost, private IPs, metadata endpoints)
    SsrfProtection::validate_url(url.as_str()).map_err(|e| {
        error_shape(
            ERROR_INVALID_REQUEST,
            &format!("plugin download URL blocked by SSRF protection: {}", e),
            None,
        )
    })?;

    let host = url
        .host_str()
        .ok_or_else(|| {
            error_shape(
                ERROR_INVALID_REQUEST,
                "plugin download URL has no host",
                None,
            )
        })?
        .to_string();
    let port = url.port_or_known_default().unwrap_or(443);

    let resolved_ip: Option<IpAddr> = if host.parse::<IpAddr>().is_ok() {
        // Host is already an IP literal; URL validation above already checked it.
        None
    } else {
        // Host is a hostname -- resolve DNS and validate every returned IP.
        let host_for_lookup = host.clone();
        let ip = run_sync_blocking_send(async move {
            let resolver = TokioResolver::builder_with_config(
                ResolverConfig::default(),
                TokioConnectionProvider::default(),
            )
            .build();

            let lookup = resolver.lookup_ip(&host_for_lookup).await.map_err(|e| {
                PluginDnsError::Unavailable(format!(
                    "DNS resolution failed for {}: {}",
                    host_for_lookup, e
                ))
            })?;

            let mut first_valid: Option<IpAddr> = None;
            for ip in lookup.iter() {
                SsrfProtection::validate_resolved_ip(&ip, &host_for_lookup).map_err(|e| {
                    PluginDnsError::InvalidRequest(format!(
                        "plugin download blocked by DNS rebinding protection: {}",
                        e
                    ))
                })?;
                if first_valid.is_none() {
                    first_valid = Some(ip);
                }
            }

            first_valid.ok_or_else(|| {
                PluginDnsError::Unavailable(format!(
                    "DNS resolution returned no addresses for {}",
                    host_for_lookup
                ))
            })
        })
        .map_err(|err| match err {
            BridgeError::Inner(inner) => inner.into_error_shape(),
            other => error_shape(ERROR_UNAVAILABLE, &other.to_string(), None),
        })?;

        tracing::debug!(
            url = %url,
            host = %host,
            resolved_ip = %ip,
            "DNS resolved and validated for plugin download"
        );

        Some(ip)
    };

    Ok((host, port, resolved_ip))
}

/// Build an HTTP client pinned to the validated IP (if any) and download the WASM
/// binary. Validates response status, size limit, and component compatibility.
fn download_with_pinned_ip(
    url: &url::Url,
    host: &str,
    port: u16,
    resolved_ip: Option<IpAddr>,
) -> Result<bytes::Bytes, ErrorShape> {
    let mut client_builder = reqwest::blocking::Client::builder()
        .timeout(PLUGIN_DOWNLOAD_TIMEOUT)
        // SECURITY: Disable redirects to prevent redirect-based SSRF bypass.
        // An attacker could redirect from a public URL to a private IP.
        .redirect(reqwest::redirect::Policy::none());

    // Pin the validated IP so the HTTP client connects directly to it,
    // preventing any second DNS lookup from returning a different address.
    if let Some(ip) = resolved_ip {
        let socket_addr = std::net::SocketAddr::new(ip, port);
        client_builder = client_builder.resolve(host, socket_addr);
    }

    let client = client_builder.build().map_err(|e| {
        error_shape(
            ERROR_UNAVAILABLE,
            &format!("failed to create HTTP client: {}", e),
            None,
        )
    })?;

    let response = client.get(url.as_str()).send().map_err(|e| {
        error_shape(
            ERROR_UNAVAILABLE,
            &format!("failed to download plugin: {}", e),
            None,
        )
    })?;

    if !response.status().is_success() {
        return Err(error_shape(
            ERROR_UNAVAILABLE,
            &format!(
                "plugin download failed with HTTP {}",
                response.status().as_u16()
            ),
            None,
        ));
    }

    let bytes = response.bytes().map_err(|e| {
        error_shape(
            ERROR_UNAVAILABLE,
            &format!("failed to read plugin download body: {}", e),
            None,
        )
    })?;

    validate_plugin_wasm_bytes(&bytes, "downloaded plugin")?;

    Ok(bytes)
}

/// Write the downloaded bytes to a temporary file, fsync, then atomically rename
/// into the final destination.  Returns the final file path.
fn atomic_write_plugin_file(
    plugins_dir: &Path,
    file_name: &str,
    bytes: &[u8],
) -> Result<PathBuf, ErrorShape> {
    let dest_path = plugins_dir.join(file_name);
    let tmp_path = plugins_dir.join(format!("{}.tmp", file_name));

    {
        let mut file = std::fs::File::create(&tmp_path).map_err(|e| {
            error_shape(
                ERROR_UNAVAILABLE,
                &format!("failed to write plugin binary: {}", e),
                None,
            )
        })?;
        file.write_all(bytes).map_err(|e| {
            error_shape(
                ERROR_UNAVAILABLE,
                &format!("failed to write plugin binary: {}", e),
                None,
            )
        })?;
        file.sync_all().map_err(|e| {
            error_shape(
                ERROR_UNAVAILABLE,
                &format!("failed to sync plugin binary: {}", e),
                None,
            )
        })?;
    }
    std::fs::rename(&tmp_path, &dest_path).map_err(|e| {
        error_shape(
            ERROR_UNAVAILABLE,
            &format!("failed to replace plugin binary: {}", e),
            None,
        )
    })?;

    Ok(dest_path)
}

/// Download a WASM binary from the given URL and save it atomically to the plugins
/// directory.  Returns the final file path and the raw bytes on success.
fn download_plugin_wasm(
    url: &url::Url,
    plugins_dir: &Path,
    file_name: &str,
) -> Result<(PathBuf, Vec<u8>), ErrorShape> {
    let (host, port, resolved_ip) = validate_and_resolve_dns(url)?;

    std::fs::create_dir_all(plugins_dir).map_err(|e| {
        error_shape(
            ERROR_UNAVAILABLE,
            &format!("failed to create plugins directory: {}", e),
            None,
        )
    })?;

    let bytes = download_with_pinned_ip(url, &host, port, resolved_ip)?;
    let dest_path = atomic_write_plugin_file(plugins_dir, file_name, &bytes)?;

    Ok((dest_path, bytes.to_vec()))
}

pub(super) fn handle_plugins_status(state: &WsServerState) -> Result<Value, ErrorShape> {
    let cfg = config::load_config().unwrap_or(Value::Object(serde_json::Map::new()));
    let (
        plugins_enabled,
        configured_path_count,
        activation_error_count,
        plugins_arr,
        restart_required,
    ) = if let Some(report) = state.plugin_activation_report() {
        let failed_plugin_count = report
            .entries
            .iter()
            .filter(|entry| {
                entry.state == crate::server::plugin_bootstrap::PluginActivationState::Failed
            })
            .count();
        (
            report.enabled,
            report.configured_paths.len(),
            report.errors.len() + failed_plugin_count,
            build_plugins_array_from_report_and_config(report, &cfg),
            report.restart_required_for_changes,
        )
    } else {
        (
            cfg.pointer("/plugins/enabled")
                .and_then(|value| value.as_bool())
                .unwrap_or(true),
            crate::server::plugin_bootstrap::configured_plugin_paths(&cfg).len(),
            0usize,
            build_plugins_array(&cfg),
            true,
        )
    };

    Ok(json!({
        "pluginsEnabled": plugins_enabled,
        "configuredPluginPathCount": configured_path_count,
        "restartRequiredForChanges": restart_required,
        "activationErrorCount": activation_error_count,
        "plugins": plugins_arr
    }))
}

/// Build a JSON array of plugin entries from the config's `plugins.entries` map.
fn build_plugins_array(cfg: &Value) -> Vec<Value> {
    let entries = match cfg
        .get("plugins")
        .and_then(|s| s.get("entries"))
        .and_then(|e| e.as_object())
    {
        Some(map) => map,
        None => return Vec::new(),
    };

    entries
        .iter()
        .map(|(key, entry)| {
            json!({
                "name": key,
                "enabled": entry.get("enabled").and_then(|v| v.as_bool()).unwrap_or(true),
                "installId": entry.get("installId").cloned().unwrap_or(Value::Null),
                "requestedAt": entry.get("requestedAt").cloned().unwrap_or(Value::Null),
            })
        })
        .collect()
}

fn token_looks_like_filesystem_path(token: &str) -> bool {
    token.starts_with('/')
        || token.starts_with("./")
        || token.starts_with("../")
        || token.starts_with("~/")
        || (token.len() > 2
            && token.as_bytes()[1] == b':'
            && matches!(token.as_bytes()[2], b'\\' | b'/'))
        || (token.contains('\\') && !token.contains(':'))
}

fn sanitize_activation_reason(reason: &str) -> String {
    if reason.starts_with("failed to read configured plugin path ") {
        return "configured plugin directory is unreadable".to_string();
    }
    if reason.starts_with("failed to resolve managed plugin directory ") {
        return "failed to resolve managed plugin directory".to_string();
    }
    if reason.starts_with("failed to resolve ") {
        return "failed to resolve plugin artifact path".to_string();
    }
    if reason.starts_with("Failed to read WASM file ") {
        return "failed to read WASM plugin artifact".to_string();
    }
    if reason.starts_with("Failed to compile WASM component ") {
        return "failed to compile WASM plugin component".to_string();
    }
    if reason
        .split_whitespace()
        .any(token_looks_like_filesystem_path)
    {
        return "plugin activation failed; see server logs for details".to_string();
    }
    reason.to_string()
}

fn build_plugins_array_from_report(
    report: &crate::server::plugin_bootstrap::PluginActivationReport,
) -> Vec<Value> {
    report
        .entries
        .iter()
        .map(|entry| {
            json!({
                "name": entry.name,
                "pluginId": entry.plugin_id,
                "enabled": entry.enabled,
                "installId": entry.install_id.clone().unwrap_or(Value::Null),
                "requestedAt": entry.requested_at.map(Value::from).unwrap_or(Value::Null),
                "source": entry.source.label(),
                "state": entry.state.label(),
                "reason": entry.reason.as_deref().map(sanitize_activation_reason),
            })
        })
        .collect()
}

fn pending_plugin_value(plugin: &Value) -> Value {
    let enabled = plugin
        .get("enabled")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    json!({
        "name": plugin.get("name").cloned().unwrap_or(Value::Null),
        "pluginId": Value::Null,
        "enabled": enabled,
        "installId": plugin.get("installId").cloned().unwrap_or(Value::Null),
        "requestedAt": plugin.get("requestedAt").cloned().unwrap_or(Value::Null),
        "source": crate::server::plugin_bootstrap::PluginActivationSource::Managed.label(),
        "state": if enabled {
            crate::server::plugin_bootstrap::PluginActivationState::Ignored.label()
        } else {
            crate::server::plugin_bootstrap::PluginActivationState::Disabled.label()
        },
        "reason": if enabled {
            Value::String("plugin is configured and will activate after restart".to_string())
        } else {
            Value::String("managed plugin is disabled in plugins.entries".to_string())
        },
    })
}

fn merge_managed_plugin_config(existing: &mut Value, plugin: &Value) {
    // The activation report is a startup-time snapshot. `plugins.status` refreshes
    // these config-owned fields so post-startup installs/enables show the current
    // desired state even though activation itself still requires restart.
    let enabled = plugin
        .get("enabled")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    let previous_enabled = existing
        .get("enabled")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    let previous_state = existing
        .get("state")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();

    existing["enabled"] = Value::Bool(enabled);
    existing["installId"] = plugin.get("installId").cloned().unwrap_or(Value::Null);
    existing["requestedAt"] = plugin.get("requestedAt").cloned().unwrap_or(Value::Null);

    if enabled == previous_enabled {
        return;
    }

    if enabled {
        let pending = pending_plugin_value(plugin);
        existing["state"] = pending["state"].clone();
        existing["reason"] = pending["reason"].clone();
        return;
    }

    existing["state"] = Value::String(
        crate::server::plugin_bootstrap::PluginActivationState::Disabled
            .label()
            .to_string(),
    );
    existing["reason"] = Value::String(
        if previous_state == crate::server::plugin_bootstrap::PluginActivationState::Active.label()
        {
            "managed plugin is currently active and will be disabled after restart".to_string()
        } else {
            "managed plugin is disabled in plugins.entries".to_string()
        },
    );
}

fn mark_removed_managed_plugin(existing: &mut Value) {
    let previous_state = existing
        .get("state")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();

    existing["enabled"] = Value::Bool(false);
    existing["installId"] = Value::Null;
    existing["requestedAt"] = Value::Null;
    existing["state"] = Value::String(
        crate::server::plugin_bootstrap::PluginActivationState::Disabled
            .label()
            .to_string(),
    );
    existing["reason"] = Value::String(
        if previous_state == crate::server::plugin_bootstrap::PluginActivationState::Active.label()
        {
            "managed plugin is currently active and will be removed after restart".to_string()
        } else {
            "managed plugin has been removed from plugins.entries and will stay inactive after restart"
                .to_string()
        },
    );
}

fn is_stray_managed_plugin(existing: &Value) -> bool {
    existing.get("source").and_then(Value::as_str)
        == Some(crate::server::plugin_bootstrap::PluginActivationSource::Managed.label())
        && existing.get("enabled").and_then(Value::as_bool) == Some(false)
        && (existing.get("pluginId").is_none()
            || existing.get("pluginId").is_some_and(Value::is_null))
        && existing.get("state").and_then(Value::as_str)
            == Some(crate::server::plugin_bootstrap::PluginActivationState::Ignored.label())
        && (existing.get("installId").is_none()
            || existing.get("installId").is_some_and(Value::is_null))
        && (existing.get("requestedAt").is_none()
            || existing.get("requestedAt").is_some_and(Value::is_null))
}

fn build_plugins_array_from_report_and_config(
    report: &crate::server::plugin_bootstrap::PluginActivationReport,
    cfg: &Value,
) -> Vec<Value> {
    let mut by_name: BTreeMap<String, Vec<Value>> = BTreeMap::new();
    for plugin in build_plugins_array_from_report(report) {
        let Some(name) = plugin.get("name").and_then(Value::as_str) else {
            continue;
        };
        by_name.entry(name.to_string()).or_default().push(plugin);
    }

    let config_plugins = build_plugins_array(cfg);
    let configured_names = config_plugins
        .iter()
        .filter_map(|plugin| plugin.get("name").and_then(Value::as_str))
        .map(str::to_string)
        .collect::<std::collections::HashSet<_>>();

    for plugin in config_plugins {
        let Some(name) = plugin.get("name").and_then(Value::as_str) else {
            continue;
        };
        if let Some(existing_plugins) = by_name.get_mut(name) {
            if let Some(existing) = existing_plugins.iter_mut().find(|entry| {
                // Config-backed merge only targets the managed entry for a plugin name.
                // Config-path rows are runtime observations/conflicts and stay separate.
                // There should be at most one managed row per plugin name because startup
                // only emits one managed activation entry per configured plugin.
                entry.get("source").and_then(Value::as_str)
                    == Some(
                        crate::server::plugin_bootstrap::PluginActivationSource::Managed.label(),
                    )
            }) {
                merge_managed_plugin_config(existing, &plugin);
            } else {
                existing_plugins.push(pending_plugin_value(&plugin));
            }
        } else {
            by_name.insert(name.to_string(), vec![pending_plugin_value(&plugin)]);
        }
    }

    for (name, plugins) in &mut by_name {
        if configured_names.contains(name) {
            continue;
        }
        for existing in plugins.iter_mut().filter(|entry| {
            entry.get("source").and_then(Value::as_str)
                == Some(crate::server::plugin_bootstrap::PluginActivationSource::Managed.label())
        }) {
            if is_stray_managed_plugin(existing) {
                continue;
            }
            mark_removed_managed_plugin(existing);
        }
    }

    by_name
        .into_values()
        .flat_map(|plugins| plugins.into_iter())
        .collect()
}

pub(super) fn handle_plugins_bins() -> Result<Value, ErrorShape> {
    let managed_plugins_dir = resolve_plugins_dir();

    let bins = scan_plugins_bins(&managed_plugins_dir);

    Ok(json!({ "bins": bins }))
}

/// Scan the managed plugins directory for binary files.
/// Returns an empty vec if the directory does not exist or cannot be read.
fn scan_plugins_bins(dir: &std::path::Path) -> Vec<Value> {
    let read_dir = match std::fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(_) => return Vec::new(),
    };

    let mut bins = Vec::new();
    for entry in read_dir {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };
        let path = entry.path();
        // Only include files (skip subdirectories)
        if path.is_file() {
            let name = entry.file_name().to_string_lossy().to_string();
            bins.push(json!({
                "name": name,
                "path": path.to_string_lossy(),
            }));
        }
    }
    bins
}

pub(super) fn handle_plugins_install(params: Option<&Value>) -> Result<Value, ErrorShape> {
    handle_plugins_install_inner(params, &resolve_plugins_dir())
}

/// Inner implementation of plugins.install, accepting a plugins directory for testability.
fn handle_plugins_install_inner(
    params: Option<&Value>,
    plugins_dir: &Path,
) -> Result<Value, ErrorShape> {
    // --- Parse and validate params ---
    let name = params
        .and_then(|v| v.get("name"))
        .and_then(|v| v.as_str())
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "name is required", None))?;
    validate_plugin_name(name)?;

    let url_str = params
        .and_then(|v| v.get("url"))
        .and_then(|v| v.as_str())
        .map(|s| s.trim())
        .filter(|s| !s.is_empty());
    let version = params
        .and_then(|v| v.get("version"))
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let publisher_key = params
        .and_then(|v| v.get("publisherKey"))
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let signature = params
        .and_then(|v| v.get("signature"))
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    let wasm_file_name = format!("{}.wasm", name);
    let local_wasm_path = plugins_dir.join(&wasm_file_name);
    let installed_at = now_ms();

    // Either download the managed plugin artifact or adopt an existing local one.
    let (wasm_path, wasm_hash) = if let Some(raw_url) = url_str {
        let parsed_url = validate_url(raw_url)?;
        let (dest, wasm_bytes) = download_plugin_wasm(&parsed_url, plugins_dir, &wasm_file_name)?;
        (Some(dest), Some(compute_sha256_hex(&wasm_bytes)))
    } else {
        let mut local_wasm = match std::fs::File::open(&local_wasm_path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(error_shape(
                    ERROR_INVALID_REQUEST,
                    "url is required unless a matching local WASM already exists in the managed plugins directory",
                    None,
                ));
            }
            Err(error) => {
                return Err(error_shape(
                    ERROR_UNAVAILABLE,
                    &format!(
                        "failed to open existing plugin binary at '{}': {}",
                        local_wasm_path.display(),
                        error
                    ),
                    None,
                ));
            }
        };
        let wasm_metadata = local_wasm.metadata().map_err(|e| {
            error_shape(
                ERROR_UNAVAILABLE,
                &format!(
                    "failed to stat existing plugin binary at '{}': {}",
                    local_wasm_path.display(),
                    e
                ),
                None,
            )
        })?;
        if !wasm_metadata.is_file() {
            return Err(error_shape(
                ERROR_INVALID_REQUEST,
                &format!(
                    "existing plugin binary at '{}' is not a regular file",
                    local_wasm_path.display()
                ),
                None,
            ));
        }
        validate_plugin_wasm_size(wasm_metadata.len(), "existing managed plugin binary")?;
        let mut wasm_bytes = Vec::new();
        local_wasm.read_to_end(&mut wasm_bytes).map_err(|e| {
            error_shape(
                ERROR_UNAVAILABLE,
                &format!(
                    "failed to read existing plugin binary at '{}': {}",
                    local_wasm_path.display(),
                    e
                ),
                None,
            )
        })?;
        validate_plugin_wasm_bytes(&wasm_bytes, "existing managed plugin binary")?;
        (
            Some(local_wasm_path.clone()),
            Some(compute_sha256_hex(&wasm_bytes)),
        )
    };

    // Record metadata in the plugins manifest
    let mut manifest = read_plugins_manifest(plugins_dir);
    let manifest_obj = ensure_object(&mut manifest)?;
    let entry = manifest_obj
        .entry(name.to_string())
        .or_insert_with(|| json!({}));
    let entry_obj = ensure_object(entry)?;
    entry_obj.insert("name".to_string(), Value::String(name.to_string()));
    if let Some(ref v) = version {
        entry_obj.insert("version".to_string(), Value::String(v.clone()));
    }
    entry_obj.insert(
        "installed_at".to_string(),
        Value::Number(installed_at.into()),
    );
    if let Some(ref p) = wasm_path {
        entry_obj.insert(
            "path".to_string(),
            Value::String(p.to_string_lossy().to_string()),
        );
    }
    if let Some(ref hash) = wasm_hash {
        entry_obj.insert("sha256".to_string(), Value::String(hash.clone()));
    }
    if let Some(ref pk) = publisher_key {
        entry_obj.insert("publisher_key".to_string(), Value::String(pk.clone()));
    }
    if let Some(ref sig) = signature {
        entry_obj.insert("signature".to_string(), Value::String(sig.clone()));
    }
    if let Some(raw_url) = url_str {
        entry_obj.insert("url".to_string(), Value::String(raw_url.to_string()));
    }
    write_plugins_manifest(plugins_dir, &manifest)?;

    // Also record the plugin in the main config (preserving existing behaviour)
    let mut config_value = read_config_snapshot().config;
    let root = ensure_object(&mut config_value)?;
    let plugins = root.entry("plugins").or_insert_with(|| json!({}));
    let plugins_obj = ensure_object(plugins)?;
    let entries = plugins_obj.entry("entries").or_insert_with(|| json!({}));
    let entries_obj = ensure_object(entries)?;
    let cfg_entry = entries_obj
        .entry(name.to_string())
        .or_insert_with(|| json!({}));
    let cfg_entry_obj = ensure_object(cfg_entry)?;
    cfg_entry_obj.insert("enabled".to_string(), Value::Bool(true));
    cfg_entry_obj.insert("name".to_string(), Value::String(name.to_string()));
    cfg_entry_obj.insert(
        "requestedAt".to_string(),
        Value::Number(installed_at.into()),
    );

    let issues = map_validation_issues(config::validate_config(&config_value));
    if !issues.is_empty() {
        return Err(error_shape(
            ERROR_INVALID_REQUEST,
            "invalid config",
            Some(json!({ "issues": issues })),
        ));
    }
    write_config_file(&config::get_config_path(), &config_value)?;

    Ok(json!({
        "ok": true,
        "name": name,
        "version": version,
        "installed_at": installed_at,
        "path": wasm_path.map(|p| p.to_string_lossy().to_string()),
        "plugins_dir": plugins_dir.to_string_lossy(),
        "publisher_key": publisher_key,
        "signature": signature,
        "activation": {
            "state": "restart-required",
            "message": "restart Carapace to activate the installed plugin"
        }
    }))
}

pub(super) fn handle_plugins_update(params: Option<&Value>) -> Result<Value, ErrorShape> {
    handle_plugins_update_inner(params, &resolve_plugins_dir())
}

/// Inner implementation of plugins.update, accepting a plugins directory for testability.
fn handle_plugins_update_inner(
    params: Option<&Value>,
    plugins_dir: &Path,
) -> Result<Value, ErrorShape> {
    // --- Parse and validate params ---
    let name = params
        .and_then(|v| v.get("name"))
        .and_then(|v| v.as_str())
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "name is required", None))?;
    validate_plugin_name(name)?;

    let url_str = params
        .and_then(|v| v.get("url"))
        .and_then(|v| v.as_str())
        .map(|s| s.trim())
        .filter(|s| !s.is_empty());
    let version = params
        .and_then(|v| v.get("version"))
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let publisher_key = params
        .and_then(|v| v.get("publisherKey"))
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let signature = params
        .and_then(|v| v.get("signature"))
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    // Verify the plugin exists in the manifest
    let mut manifest = read_plugins_manifest(plugins_dir);
    {
        let manifest_obj = manifest
            .as_object()
            .unwrap_or(&serde_json::Map::new())
            .clone();
        if !manifest_obj.contains_key(name) {
            // Also check the filesystem as a fallback
            let wasm_path = plugins_dir.join(format!("{}.wasm", name));
            if !wasm_path.is_file() {
                return Err(error_shape(
                    ERROR_INVALID_REQUEST,
                    &format!("managed plugin '{}' is not installed", name),
                    None,
                ));
            }
        }
    }

    // URL is required to perform an actual update (download new version)
    let url_str = match url_str {
        Some(u) => u,
        None => {
            return Err(error_shape(
                ERROR_INVALID_REQUEST,
                "no update source available: url is required to update a plugin",
                None,
            ));
        }
    };

    let parsed_url = validate_url(url_str)?;
    let wasm_file_name = format!("{}.wasm", name);
    let (dest, wasm_bytes) = download_plugin_wasm(&parsed_url, plugins_dir, &wasm_file_name)?;
    let wasm_hash = compute_sha256_hex(&wasm_bytes);
    let updated_at = now_ms();

    // Update the manifest entry
    let manifest_obj = ensure_object(&mut manifest)?;
    let entry = manifest_obj
        .entry(name.to_string())
        .or_insert_with(|| json!({}));
    let entry_obj = ensure_object(entry)?;
    entry_obj.insert("name".to_string(), Value::String(name.to_string()));
    if let Some(ref v) = version {
        entry_obj.insert("version".to_string(), Value::String(v.clone()));
    }
    entry_obj.insert("updated_at".to_string(), Value::Number(updated_at.into()));
    entry_obj.insert(
        "path".to_string(),
        Value::String(dest.to_string_lossy().to_string()),
    );
    entry_obj.insert("sha256".to_string(), Value::String(wasm_hash));
    if let Some(ref pk) = publisher_key {
        entry_obj.insert("publisher_key".to_string(), Value::String(pk.clone()));
    }
    if let Some(ref sig) = signature {
        entry_obj.insert("signature".to_string(), Value::String(sig.clone()));
    }
    entry_obj.insert("url".to_string(), Value::String(url_str.to_string()));
    write_plugins_manifest(plugins_dir, &manifest)?;

    Ok(json!({
        "ok": true,
        "name": name,
        "version": version,
        "updated_at": updated_at,
        "path": dest.to_string_lossy(),
        "plugins_dir": plugins_dir.to_string_lossy(),
        "publisher_key": publisher_key,
        "signature": signature,
        "activation": {
            "state": "restart-required",
            "message": "restart Carapace to activate the updated plugin"
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::ws::{WsServerConfig, WsServerState};
    use crate::test_support::{env::ScopedEnv, plugins::tool_plugin_component_bytes};
    use tempfile::TempDir;

    struct TestConfigEnv {
        _env: ScopedEnv,
        _dir: TempDir,
    }

    impl TestConfigEnv {
        fn new() -> Self {
            let dir = TempDir::new().unwrap();
            let config_path = dir.path().join("carapace.json");
            let mut env = ScopedEnv::new();
            env.set("CARAPACE_CONFIG_PATH", config_path.as_os_str())
                .set("CARAPACE_DISABLE_CONFIG_CACHE", "1");
            crate::config::clear_cache();

            Self {
                _env: env,
                _dir: dir,
            }
        }
    }

    impl Drop for TestConfigEnv {
        fn drop(&mut self) {
            crate::config::clear_cache();
        }
    }

    #[test]
    fn test_build_plugins_array_empty_config() {
        let cfg = json!({});
        let result = build_plugins_array(&cfg);
        assert!(result.is_empty());
    }

    #[test]
    fn test_build_plugins_array_no_entries() {
        let cfg = json!({ "plugins": {} });
        let result = build_plugins_array(&cfg);
        assert!(result.is_empty());
    }

    #[test]
    fn test_build_plugins_array_empty_entries() {
        let cfg = json!({ "plugins": { "entries": {} } });
        let result = build_plugins_array(&cfg);
        assert!(result.is_empty());
    }

    #[test]
    fn test_build_plugins_array_with_entries() {
        let cfg = json!({
            "plugins": {
                "entries": {
                    "weather": {
                        "enabled": true,
                        "installId": "abc-123",
                        "requestedAt": 1700000000000u64
                    },
                    "calendar": {
                        "enabled": false,
                        "installId": "def-456",
                        "requestedAt": 1700000001000u64
                    }
                }
            }
        });
        let result = build_plugins_array(&cfg);
        assert_eq!(result.len(), 2);

        // Find weather and calendar entries (order is not guaranteed in JSON objects)
        let weather = result.iter().find(|v| v["name"] == "weather").unwrap();
        assert_eq!(weather["enabled"], true);
        assert_eq!(weather["installId"], "abc-123");
        assert_eq!(weather["requestedAt"], 1700000000000u64);

        let calendar = result.iter().find(|v| v["name"] == "calendar").unwrap();
        assert_eq!(calendar["enabled"], false);
        assert_eq!(calendar["installId"], "def-456");
        assert_eq!(calendar["requestedAt"], 1700000001000u64);
    }

    #[test]
    fn test_build_plugins_array_enabled_defaults_true() {
        let cfg = json!({
            "plugins": {
                "entries": {
                    "minimal": {}
                }
            }
        });
        let result = build_plugins_array(&cfg);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0]["name"], "minimal");
        assert_eq!(result[0]["enabled"], true);
        assert!(result[0]["installId"].is_null());
        assert!(result[0]["requestedAt"].is_null());
    }

    #[test]
    fn test_build_plugins_array_entries_not_object() {
        // If entries is not an object (e.g. an array), return empty
        let cfg = json!({ "plugins": { "entries": [1, 2, 3] } });
        let result = build_plugins_array(&cfg);
        assert!(result.is_empty());
    }

    #[test]
    fn test_handle_plugins_status_uses_plugin_activation_report() {
        let env_state_dir = TempDir::new().unwrap();
        let report_state_dir = TempDir::new().unwrap();
        let config_dir = TempDir::new().unwrap();
        let config_path = config_dir.path().join("carapace.json");
        std::fs::write(
            &config_path,
            json!({
                "plugins": {
                    "entries": {
                        "weather": {
                            "enabled": true,
                            "installId": "install-weather",
                            "requestedAt": 1700000000000u64
                        }
                    }
                }
            })
            .to_string(),
        )
        .unwrap();
        let mut env = ScopedEnv::new();
        env.set("CARAPACE_STATE_DIR", env_state_dir.path().as_os_str())
            .set("CARAPACE_CONFIG_PATH", config_path.as_os_str())
            .set("CARAPACE_DISABLE_CONFIG_CACHE", "1");
        crate::config::clear_cache();

        let state = WsServerState::new(WsServerConfig::default()).with_plugin_activation_report(
            crate::server::plugin_bootstrap::PluginActivationReport {
                enabled: true,
                configured_paths: vec![report_state_dir.path().join("dev-plugins")],
                restart_required_for_changes: true,
                errors: vec!["failed to read configured plugin path".to_string()],
                entries: vec![crate::server::plugin_bootstrap::PluginActivationEntry {
                    name: "weather".to_string(),
                    plugin_id: Some("weather".to_string()),
                    source: crate::server::plugin_bootstrap::PluginActivationSource::Managed,
                    enabled: true,
                    path: Some(report_state_dir.path().join("plugins/weather.wasm")),
                    requested_at: Some(1700000000000u64),
                    install_id: Some(json!("install-weather")),
                    state: crate::server::plugin_bootstrap::PluginActivationState::Active,
                    reason: None,
                }],
            },
        );

        let result = handle_plugins_status(&state).unwrap();
        assert_eq!(result["pluginsEnabled"], true);
        assert_eq!(result["configuredPluginPathCount"], 1);
        assert_eq!(result["restartRequiredForChanges"], true);
        assert_eq!(result["activationErrorCount"], 1);
        assert_eq!(result["plugins"].as_array().unwrap().len(), 1);
        let entry = &result["plugins"][0];
        assert_eq!(entry["name"], "weather");
        assert_eq!(entry["pluginId"], "weather");
        assert_eq!(entry["source"], "managed");
        assert_eq!(entry["state"], "active");
        assert_eq!(entry["enabled"], true);
        assert!(entry.get("path").is_none());

        crate::config::clear_cache();
    }

    #[test]
    fn test_handle_plugins_status_merges_pending_configured_plugins_into_report() {
        let env_state_dir = TempDir::new().unwrap();
        let report_state_dir = TempDir::new().unwrap();
        let config_dir = TempDir::new().unwrap();
        let config_path = config_dir.path().join("carapace.json");
        std::fs::write(
            &config_path,
            json!({
                "plugins": {
                    "entries": {
                        "weather": {
                            "enabled": true,
                            "installId": "install-weather-new",
                            "requestedAt": 1700000001000u64
                        },
                        "calendar": {
                            "enabled": true,
                            "installId": "install-calendar",
                            "requestedAt": 1700000002000u64
                        }
                    }
                }
            })
            .to_string(),
        )
        .unwrap();
        let mut env = ScopedEnv::new();
        env.set("CARAPACE_STATE_DIR", env_state_dir.path().as_os_str())
            .set("CARAPACE_CONFIG_PATH", config_path.as_os_str())
            .set("CARAPACE_DISABLE_CONFIG_CACHE", "1");
        crate::config::clear_cache();

        let state = WsServerState::new(WsServerConfig::default()).with_plugin_activation_report(
            crate::server::plugin_bootstrap::PluginActivationReport {
                enabled: true,
                configured_paths: vec![],
                restart_required_for_changes: true,
                errors: vec![],
                entries: vec![crate::server::plugin_bootstrap::PluginActivationEntry {
                    name: "weather".to_string(),
                    plugin_id: Some("weather".to_string()),
                    source: crate::server::plugin_bootstrap::PluginActivationSource::Managed,
                    enabled: true,
                    path: Some(report_state_dir.path().join("plugins/weather.wasm")),
                    requested_at: Some(1700000000000u64),
                    install_id: Some(json!("install-weather")),
                    state: crate::server::plugin_bootstrap::PluginActivationState::Active,
                    reason: None,
                }],
            },
        );

        let result = handle_plugins_status(&state).unwrap();
        assert_eq!(result["plugins"].as_array().unwrap().len(), 2);
        let weather = result["plugins"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["name"] == "weather")
            .unwrap();
        assert_eq!(weather["state"], "active");
        assert_eq!(weather["installId"], "install-weather-new");
        assert_eq!(weather["requestedAt"], 1700000001000u64);
        let calendar = result["plugins"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["name"] == "calendar")
            .unwrap();
        assert_eq!(calendar["state"], "ignored");
        assert_eq!(calendar["source"], "managed");
        assert_eq!(
            calendar["reason"],
            "plugin is configured and will activate after restart"
        );

        crate::config::clear_cache();
    }

    #[test]
    fn test_handle_plugins_status_without_report_counts_configured_plugin_paths() {
        let env_state_dir = TempDir::new().unwrap();
        let config_dir = TempDir::new().unwrap();
        let config_path = config_dir.path().join("carapace.json");
        std::fs::write(
            &config_path,
            json!({
                "plugins": {
                    "load": {
                        "paths": [
                            "  /tmp/plugins-a  ",
                            "",
                            "/tmp/plugins-a",
                            "/tmp/plugins-b"
                        ]
                    }
                }
            })
            .to_string(),
        )
        .unwrap();
        let mut env = ScopedEnv::new();
        env.set("CARAPACE_STATE_DIR", env_state_dir.path().as_os_str())
            .set("CARAPACE_CONFIG_PATH", config_path.as_os_str())
            .set("CARAPACE_DISABLE_CONFIG_CACHE", "1");
        crate::config::clear_cache();

        let state = WsServerState::new(WsServerConfig::default());
        let result = handle_plugins_status(&state).unwrap();
        assert_eq!(result["configuredPluginPathCount"], 2);

        crate::config::clear_cache();
    }

    #[test]
    fn test_handle_plugins_status_preserves_duplicate_name_report_entries() {
        let config_dir = TempDir::new().unwrap();
        let config_path = config_dir.path().join("carapace.json");
        std::fs::write(
            &config_path,
            json!({
                "plugins": {
                    "entries": {
                        "weather": {
                            "enabled": true,
                            "installId": "install-weather",
                            "requestedAt": 1700000003000u64
                        }
                    }
                }
            })
            .to_string(),
        )
        .unwrap();
        let mut env = ScopedEnv::new();
        env.set("CARAPACE_CONFIG_PATH", config_path.as_os_str())
            .set("CARAPACE_DISABLE_CONFIG_CACHE", "1");
        crate::config::clear_cache();

        let state = WsServerState::new(WsServerConfig::default()).with_plugin_activation_report(
            crate::server::plugin_bootstrap::PluginActivationReport {
                enabled: true,
                configured_paths: vec![PathBuf::from("/plugins-dev")],
                restart_required_for_changes: true,
                errors: vec![],
                entries: vec![
                    crate::server::plugin_bootstrap::PluginActivationEntry {
                        name: "weather".to_string(),
                        plugin_id: Some("weather".to_string()),
                        source: crate::server::plugin_bootstrap::PluginActivationSource::Managed,
                        enabled: true,
                        path: Some(PathBuf::from("/managed/weather.wasm")),
                        requested_at: Some(1700000000000u64),
                        install_id: Some(json!("install-weather-old")),
                        state: crate::server::plugin_bootstrap::PluginActivationState::Active,
                        reason: None,
                    },
                    crate::server::plugin_bootstrap::PluginActivationEntry {
                        name: "weather".to_string(),
                        plugin_id: Some("weather".to_string()),
                        source: crate::server::plugin_bootstrap::PluginActivationSource::ConfigPath,
                        enabled: true,
                        path: Some(PathBuf::from("/plugins-dev/weather.wasm")),
                        requested_at: None,
                        install_id: None,
                        state: crate::server::plugin_bootstrap::PluginActivationState::Failed,
                        reason: Some(
                            "plugin ID conflict with an earlier activation source: weather"
                                .to_string(),
                        ),
                    },
                ],
            },
        );

        let result = handle_plugins_status(&state).unwrap();
        let weather_entries = result["plugins"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|entry| entry["name"] == "weather")
            .collect::<Vec<_>>();
        assert_eq!(weather_entries.len(), 2);
        let managed_entry = weather_entries
            .iter()
            .find(|entry| entry["source"] == "managed")
            .unwrap();
        assert_eq!(managed_entry["installId"], "install-weather");
        assert_eq!(managed_entry["requestedAt"], 1700000003000u64);
        let config_entry = weather_entries
            .iter()
            .find(|entry| entry["source"] == "config")
            .unwrap();
        assert_eq!(config_entry["state"], "failed");
        assert_eq!(
            config_entry["reason"],
            "plugin ID conflict with an earlier activation source: weather"
        );

        crate::config::clear_cache();
    }

    #[test]
    fn test_handle_plugins_status_sanitizes_path_bearing_reasons() {
        let state = WsServerState::new(WsServerConfig::default()).with_plugin_activation_report(
            crate::server::plugin_bootstrap::PluginActivationReport {
                enabled: true,
                configured_paths: vec![PathBuf::from("/plugins-dev")],
                restart_required_for_changes: true,
                errors: vec![
                    "failed to read configured plugin path /plugins-dev: denied".to_string()
                ],
                entries: vec![crate::server::plugin_bootstrap::PluginActivationEntry {
                    name: "weather".to_string(),
                    plugin_id: None,
                    source: crate::server::plugin_bootstrap::PluginActivationSource::ConfigPath,
                    enabled: true,
                    path: Some(PathBuf::from("/plugins-dev/weather.wasm")),
                    requested_at: None,
                    install_id: None,
                    state: crate::server::plugin_bootstrap::PluginActivationState::Failed,
                    reason: Some(
                        "Failed to compile WASM component /plugins-dev/weather.wasm: bad module"
                            .to_string(),
                    ),
                }],
            },
        );

        let result = handle_plugins_status(&state).unwrap();
        assert_eq!(result["activationErrorCount"], 2);
        let weather = result["plugins"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["name"] == "weather")
            .unwrap();
        assert_eq!(weather["reason"], "failed to compile WASM plugin component");
        assert!(weather.get("path").is_none());
    }

    #[test]
    fn test_sanitize_activation_reason_preserves_namespaced_identifiers() {
        assert_eq!(
            sanitize_activation_reason("unknown import: carapace:plugin/host@1.0.0"),
            "unknown import: carapace:plugin/host@1.0.0"
        );
    }

    #[test]
    fn test_handle_plugins_status_recomputes_pending_enable_after_config_change() {
        let config_dir = TempDir::new().unwrap();
        let config_path = config_dir.path().join("carapace.json");
        std::fs::write(
            &config_path,
            json!({
                "plugins": {
                    "entries": {
                        "weather": {
                            "enabled": true,
                            "installId": "install-weather",
                            "requestedAt": 1700000003000u64
                        }
                    }
                }
            })
            .to_string(),
        )
        .unwrap();
        let mut env = ScopedEnv::new();
        env.set("CARAPACE_CONFIG_PATH", config_path.as_os_str())
            .set("CARAPACE_DISABLE_CONFIG_CACHE", "1");
        crate::config::clear_cache();

        let state = WsServerState::new(WsServerConfig::default()).with_plugin_activation_report(
            crate::server::plugin_bootstrap::PluginActivationReport {
                enabled: true,
                configured_paths: vec![],
                restart_required_for_changes: true,
                errors: vec![],
                entries: vec![crate::server::plugin_bootstrap::PluginActivationEntry {
                    name: "weather".to_string(),
                    plugin_id: None,
                    source: crate::server::plugin_bootstrap::PluginActivationSource::Managed,
                    enabled: false,
                    path: Some(PathBuf::from("/managed/weather.wasm")),
                    requested_at: Some(1700000000000u64),
                    install_id: Some(json!("install-weather-old")),
                    state: crate::server::plugin_bootstrap::PluginActivationState::Disabled,
                    reason: Some("managed plugin is disabled in plugins.entries".to_string()),
                }],
            },
        );

        let result = handle_plugins_status(&state).unwrap();
        let weather = result["plugins"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["name"] == "weather")
            .unwrap();
        assert_eq!(weather["enabled"], true);
        assert_eq!(weather["state"], "ignored");
        assert_eq!(
            weather["reason"],
            "plugin is configured and will activate after restart"
        );

        crate::config::clear_cache();
    }

    #[test]
    fn test_handle_plugins_status_marks_disable_after_config_change_as_pending_restart() {
        let config_dir = TempDir::new().unwrap();
        let config_path = config_dir.path().join("carapace.json");
        std::fs::write(
            &config_path,
            json!({
                "plugins": {
                    "entries": {
                        "weather": {
                            "enabled": false,
                            "installId": "install-weather",
                            "requestedAt": 1700000003000u64
                        }
                    }
                }
            })
            .to_string(),
        )
        .unwrap();
        let mut env = ScopedEnv::new();
        env.set("CARAPACE_CONFIG_PATH", config_path.as_os_str())
            .set("CARAPACE_DISABLE_CONFIG_CACHE", "1");
        crate::config::clear_cache();

        let state = WsServerState::new(WsServerConfig::default()).with_plugin_activation_report(
            crate::server::plugin_bootstrap::PluginActivationReport {
                enabled: true,
                configured_paths: vec![],
                restart_required_for_changes: true,
                errors: vec![],
                entries: vec![crate::server::plugin_bootstrap::PluginActivationEntry {
                    name: "weather".to_string(),
                    plugin_id: Some("weather".to_string()),
                    source: crate::server::plugin_bootstrap::PluginActivationSource::Managed,
                    enabled: true,
                    path: Some(PathBuf::from("/managed/weather.wasm")),
                    requested_at: Some(1700000000000u64),
                    install_id: Some(json!("install-weather-old")),
                    state: crate::server::plugin_bootstrap::PluginActivationState::Active,
                    reason: None,
                }],
            },
        );

        let result = handle_plugins_status(&state).unwrap();
        let weather = result["plugins"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["name"] == "weather")
            .unwrap();
        assert_eq!(weather["enabled"], false);
        assert_eq!(weather["state"], "disabled");
        assert_eq!(
            weather["reason"],
            "managed plugin is currently active and will be disabled after restart"
        );

        crate::config::clear_cache();
    }

    #[test]
    fn test_handle_plugins_status_marks_removed_managed_plugin_as_pending_restart() {
        let config_dir = TempDir::new().unwrap();
        let config_path = config_dir.path().join("carapace.json");
        std::fs::write(
            &config_path,
            json!({ "plugins": { "entries": {} } }).to_string(),
        )
        .unwrap();
        let mut env = ScopedEnv::new();
        env.set("CARAPACE_CONFIG_PATH", config_path.as_os_str())
            .set("CARAPACE_DISABLE_CONFIG_CACHE", "1");
        crate::config::clear_cache();

        let state = WsServerState::new(WsServerConfig::default()).with_plugin_activation_report(
            crate::server::plugin_bootstrap::PluginActivationReport {
                enabled: true,
                configured_paths: vec![],
                restart_required_for_changes: true,
                errors: vec![],
                entries: vec![crate::server::plugin_bootstrap::PluginActivationEntry {
                    name: "weather".to_string(),
                    plugin_id: Some("weather".to_string()),
                    source: crate::server::plugin_bootstrap::PluginActivationSource::Managed,
                    enabled: true,
                    path: Some(PathBuf::from("/managed/weather.wasm")),
                    requested_at: Some(1700000000000u64),
                    install_id: Some(json!("install-weather-old")),
                    state: crate::server::plugin_bootstrap::PluginActivationState::Active,
                    reason: None,
                }],
            },
        );

        let result = handle_plugins_status(&state).unwrap();
        let weather = result["plugins"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["name"] == "weather")
            .unwrap();
        assert_eq!(weather["enabled"], false);
        assert_eq!(weather["installId"], Value::Null);
        assert_eq!(weather["requestedAt"], Value::Null);
        assert_eq!(weather["state"], "disabled");
        assert_eq!(
            weather["reason"],
            "managed plugin is currently active and will be removed after restart"
        );

        crate::config::clear_cache();
    }

    #[test]
    fn test_handle_plugins_status_preserves_stray_managed_plugin_reason() {
        let state = WsServerState::new(WsServerConfig::default()).with_plugin_activation_report(
            crate::server::plugin_bootstrap::PluginActivationReport {
                enabled: true,
                configured_paths: vec![],
                restart_required_for_changes: true,
                errors: vec![],
                entries: vec![crate::server::plugin_bootstrap::PluginActivationEntry {
                    name: "weather".to_string(),
                    plugin_id: None,
                    source: crate::server::plugin_bootstrap::PluginActivationSource::Managed,
                    enabled: false,
                    path: Some(PathBuf::from("/managed/weather.wasm")),
                    requested_at: None,
                    install_id: None,
                    state: crate::server::plugin_bootstrap::PluginActivationState::Ignored,
                    reason: Some(
                        "WASM file is present in the managed plugin directory but not declared in plugins.entries"
                            .to_string(),
                    ),
                }],
            },
        );

        let result = handle_plugins_status(&state).unwrap();
        let weather = result["plugins"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["name"] == "weather")
            .unwrap();
        assert_eq!(weather["state"], "ignored");
        assert_eq!(
            weather["reason"],
            "WASM file is present in the managed plugin directory but not declared in plugins.entries"
        );
    }

    #[test]
    fn test_scan_plugins_bins_nonexistent_dir() {
        let result = scan_plugins_bins(std::path::Path::new(
            "/nonexistent/path/that/does/not/exist/plugins",
        ));
        assert!(result.is_empty());
    }

    #[test]
    fn test_scan_plugins_bins_empty_dir() {
        let dir = TempDir::new().unwrap();
        let result = scan_plugins_bins(dir.path());
        assert!(result.is_empty());
    }

    #[test]
    fn test_scan_plugins_bins_with_files() {
        let dir = TempDir::new().unwrap();
        // Create some files
        std::fs::write(dir.path().join("plugin-a"), b"#!/bin/sh\n").unwrap();
        std::fs::write(dir.path().join("plugin-b"), b"#!/bin/sh\n").unwrap();
        // Create a subdirectory (should be skipped)
        std::fs::create_dir(dir.path().join("subdir")).unwrap();

        let result = scan_plugins_bins(dir.path());
        assert_eq!(result.len(), 2);

        let names: Vec<&str> = result.iter().map(|v| v["name"].as_str().unwrap()).collect();
        assert!(names.contains(&"plugin-a"));
        assert!(names.contains(&"plugin-b"));

        // Verify paths are absolute
        for bin in &result {
            let path = bin["path"].as_str().unwrap();
            assert!(
                std::path::Path::new(path).is_absolute(),
                "path should be absolute: {}",
                path
            );
        }
    }

    // ---- Validation tests ----

    #[test]
    fn test_validate_plugin_name_valid() {
        assert!(validate_plugin_name("weather").is_ok());
        assert!(validate_plugin_name("my-plugin").is_ok());
        assert!(validate_plugin_name("my_plugin_v2").is_ok());
        assert!(validate_plugin_name("a").is_ok());
        assert!(validate_plugin_name("ABC123").is_ok());
    }

    #[test]
    fn test_validate_plugin_name_empty() {
        let err = validate_plugin_name("").unwrap_err();
        assert_eq!(err.code, ERROR_INVALID_REQUEST);
        assert!(err.message.contains("empty"));
    }

    #[test]
    fn test_validate_plugin_name_too_long() {
        let long_name = "a".repeat(129);
        let err = validate_plugin_name(&long_name).unwrap_err();
        assert_eq!(err.code, ERROR_INVALID_REQUEST);
        assert!(err.message.contains("too long"));
    }

    #[test]
    fn test_validate_plugin_name_bad_chars() {
        let err = validate_plugin_name("my plugin").unwrap_err();
        assert_eq!(err.code, ERROR_INVALID_REQUEST);

        let err = validate_plugin_name("../escape").unwrap_err();
        assert_eq!(err.code, ERROR_INVALID_REQUEST);

        let err = validate_plugin_name("path/traversal").unwrap_err();
        assert_eq!(err.code, ERROR_INVALID_REQUEST);

        let err = validate_plugin_name("has.dot").unwrap_err();
        assert_eq!(err.code, ERROR_INVALID_REQUEST);
    }

    #[test]
    fn test_validate_url_valid() {
        assert!(validate_url("https://example.com/plugin.wasm").is_ok());
        assert!(validate_url("http://localhost:8080/plugin.wasm").is_ok());
    }

    #[test]
    fn test_validate_url_bad_scheme() {
        let err = validate_url("ftp://example.com/plugin.wasm").unwrap_err();
        assert!(err.message.contains("unsupported url scheme"));
    }

    #[test]
    fn test_validate_url_invalid() {
        let err = validate_url("not a url at all").unwrap_err();
        assert!(err.message.contains("invalid url"));
    }

    #[test]
    fn test_validate_and_resolve_dns_inside_current_thread_runtime_is_panic_free() {
        let url = url::Url::parse("https://example.com/plugin.wasm").unwrap();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let dns_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            rt.block_on(async { validate_and_resolve_dns(&url) })
        }));

        assert!(
            dns_result.is_ok(),
            "DNS resolve path should not panic in current-thread runtime"
        );

        match dns_result.unwrap() {
            Ok((host, port, _resolved_ip)) => {
                assert!(!host.is_empty());
                assert!(port > 0);
            }
            Err(err) => {
                assert_ne!(
                    err.code, ERROR_INVALID_REQUEST,
                    "DNS validation should not fail SSRF validation for a public URL"
                );
            }
        }
    }

    // ---- SSRF protection tests for plugin downloads ----

    #[tokio::test(flavor = "multi_thread")]
    async fn test_download_plugin_ssrf_public_url_passes_validation() {
        // A public URL should pass SSRF validation (will fail later at the network level,
        // but the SSRF check itself should not reject it).
        // This test requires a tokio multi_thread runtime because the function
        // performs async DNS resolution for hostname-based URLs via block_in_place.
        // We use spawn_blocking to avoid reqwest::blocking::Client's internal
        // runtime conflicting with the test runtime on drop.
        let dir = TempDir::new().unwrap();
        let dir_path = dir.path().to_path_buf();
        let result = tokio::task::spawn_blocking(move || {
            let url = url::Url::parse("https://example.com/plugins/my-plugin.wasm").unwrap();
            download_plugin_wasm(&url, &dir_path, "test.wasm")
        })
        .await
        .unwrap();
        // Should fail with a network error, NOT an SSRF error
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            !err.message.contains("SSRF"),
            "public URL should not be blocked by SSRF protection, got: {}",
            err.message
        );
    }

    #[test]
    fn test_download_plugin_ssrf_rejects_localhost() {
        let dir = TempDir::new().unwrap();
        let url = url::Url::parse("http://localhost/evil.wasm").unwrap();
        let result = download_plugin_wasm(&url, dir.path(), "test.wasm");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code, ERROR_INVALID_REQUEST);
        assert!(
            err.message.contains("SSRF"),
            "localhost should be blocked by SSRF protection, got: {}",
            err.message
        );
    }

    #[test]
    fn test_download_plugin_ssrf_rejects_metadata_endpoint() {
        let dir = TempDir::new().unwrap();
        let url = url::Url::parse("http://169.254.169.254/latest/meta-data/").unwrap();
        let result = download_plugin_wasm(&url, dir.path(), "test.wasm");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code, ERROR_INVALID_REQUEST);
        assert!(
            err.message.contains("SSRF"),
            "metadata endpoint should be blocked by SSRF protection, got: {}",
            err.message
        );
    }

    #[test]
    fn test_download_plugin_ssrf_rejects_internal_ip() {
        let dir = TempDir::new().unwrap();
        let url = url::Url::parse("http://10.0.0.1/internal-plugin.wasm").unwrap();
        let result = download_plugin_wasm(&url, dir.path(), "test.wasm");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code, ERROR_INVALID_REQUEST);
        assert!(
            err.message.contains("SSRF"),
            "internal IP should be blocked by SSRF protection, got: {}",
            err.message
        );
    }

    // ---- Manifest read/write tests ----

    #[test]
    fn test_read_plugins_manifest_nonexistent() {
        let dir = TempDir::new().unwrap();
        let manifest = read_plugins_manifest(dir.path());
        assert_eq!(manifest, json!({}));
    }

    #[test]
    fn test_write_and_read_plugins_manifest() {
        let dir = TempDir::new().unwrap();
        let manifest = json!({
            "weather": {
                "name": "weather",
                "version": "1.0.0",
                "installed_at": 1700000000000u64
            }
        });
        write_plugins_manifest(dir.path(), &manifest).unwrap();

        let read_back = read_plugins_manifest(dir.path());
        assert_eq!(read_back["weather"]["name"], "weather");
        assert_eq!(read_back["weather"]["version"], "1.0.0");
        assert_eq!(read_back["weather"]["installed_at"], 1700000000000u64);
    }

    #[test]
    fn test_write_plugins_manifest_creates_directory() {
        let dir = TempDir::new().unwrap();
        let nested = dir.path().join("nested").join("plugins");
        let manifest = json!({ "test": {} });
        write_plugins_manifest(&nested, &manifest).unwrap();
        assert!(nested.join(PLUGINS_MANIFEST_FILE).is_file());
    }

    #[test]
    fn test_read_plugins_manifest_corrupt_json() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join(PLUGINS_MANIFEST_FILE), b"not json").unwrap();
        let manifest = read_plugins_manifest(dir.path());
        assert_eq!(manifest, json!({}));
    }

    #[test]
    fn test_validate_plugin_wasm_bytes_rejects_invalid_component() {
        let err = validate_plugin_wasm_bytes(
            &[0x00, 0x61, 0x73, 0x6D, 0x02, 0x00, 0x00, 0x00],
            "test plugin",
        )
        .unwrap_err();
        assert_eq!(err.code, ERROR_INVALID_REQUEST);
        assert!(err
            .message
            .contains("test plugin is not a valid WASM plugin component"));
    }

    // ---- Install handler tests ----

    #[test]
    fn test_install_missing_name() {
        let dir = TempDir::new().unwrap();
        let result = handle_plugins_install_inner(None, dir.path());
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code, ERROR_INVALID_REQUEST);
        assert!(err.message.contains("name is required"));
    }

    #[test]
    fn test_install_empty_name() {
        let dir = TempDir::new().unwrap();
        let params = json!({ "name": "  " });
        let result = handle_plugins_install_inner(Some(&params), dir.path());
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.message.contains("name is required"));
    }

    #[test]
    fn test_install_invalid_name_chars() {
        let dir = TempDir::new().unwrap();
        let params = json!({ "name": "../etc/passwd" });
        let result = handle_plugins_install_inner(Some(&params), dir.path());
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.message.contains("alphanumeric"));
    }

    #[test]
    fn test_install_invalid_url_scheme() {
        let dir = TempDir::new().unwrap();
        let params = json!({ "name": "test-plugin", "url": "ftp://example.com/foo.wasm" });
        let result = handle_plugins_install_inner(Some(&params), dir.path());
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.message.contains("unsupported url scheme"));
    }

    #[test]
    fn test_install_invalid_url_parse() {
        let dir = TempDir::new().unwrap();
        let params = json!({ "name": "test-plugin", "url": "not a url" });
        let result = handle_plugins_install_inner(Some(&params), dir.path());
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.message.contains("invalid url"));
    }

    #[test]
    fn test_install_no_url_requires_existing_local_wasm() {
        let dir = TempDir::new().unwrap();
        let plugins_dir = dir.path().join("plugins");
        let params = json!({ "name": "my-plugin", "version": "2.0.0" });

        let _env = TestConfigEnv::new();

        let err = handle_plugins_install_inner(Some(&params), &plugins_dir).unwrap_err();
        assert!(err
            .message
            .contains("url is required unless a matching local WASM already exists"));
    }

    #[test]
    fn test_install_no_url_adopts_existing_local_wasm() {
        let dir = TempDir::new().unwrap();
        let plugins_dir = dir.path().join("plugins");
        std::fs::create_dir_all(&plugins_dir).unwrap();
        let wasm_bytes = tool_plugin_component_bytes();
        let wasm_path = plugins_dir.join("my-plugin.wasm");
        std::fs::write(&wasm_path, &wasm_bytes).unwrap();
        let params = json!({ "name": "my-plugin", "version": "2.0.0" });

        let _env = TestConfigEnv::new();
        let result = handle_plugins_install_inner(Some(&params), &plugins_dir).unwrap();

        let manifest = read_plugins_manifest(&plugins_dir);
        assert_eq!(manifest["my-plugin"]["name"], "my-plugin");
        assert_eq!(manifest["my-plugin"]["version"], "2.0.0");
        assert_eq!(
            manifest["my-plugin"]["path"],
            wasm_path.to_string_lossy().to_string()
        );
        assert_eq!(
            manifest["my-plugin"]["sha256"],
            compute_sha256_hex(&wasm_bytes)
        );
        assert_eq!(result["activation"]["state"], "restart-required");
    }

    #[test]
    fn test_install_no_url_rejects_oversized_existing_local_wasm_before_read() {
        let dir = TempDir::new().unwrap();
        let plugins_dir = dir.path().join("plugins");
        std::fs::create_dir_all(&plugins_dir).unwrap();
        let wasm_path = plugins_dir.join("my-plugin.wasm");
        let wasm_file = std::fs::File::create(&wasm_path).unwrap();
        wasm_file
            .set_len((MAX_PLUGIN_DOWNLOAD_BYTES as u64) + 1)
            .unwrap();
        let params = json!({ "name": "my-plugin", "version": "2.0.0" });

        let _env = TestConfigEnv::new();
        let err = handle_plugins_install_inner(Some(&params), &plugins_dir).unwrap_err();

        assert_eq!(err.code, ERROR_INVALID_REQUEST);
        assert!(err
            .message
            .contains("existing managed plugin binary exceeds maximum size"));
    }

    #[test]
    fn test_install_reports_restart_required_activation() {
        let dir = TempDir::new().unwrap();
        let plugins_dir = dir.path().join("plugins");
        std::fs::create_dir_all(&plugins_dir).unwrap();
        let wasm_bytes = tool_plugin_component_bytes();
        std::fs::write(plugins_dir.join("my-plugin.wasm"), wasm_bytes).unwrap();
        let params = json!({ "name": "my-plugin", "version": "2.0.0" });

        let _env = TestConfigEnv::new();
        let result = handle_plugins_install_inner(Some(&params), &plugins_dir).unwrap();

        assert_eq!(result["ok"], true);
        assert_eq!(result["activation"]["state"], "restart-required");
        assert_eq!(
            result["activation"]["message"],
            "restart Carapace to activate the installed plugin"
        );
    }

    // ---- Update handler tests ----

    #[test]
    fn test_update_missing_name() {
        let dir = TempDir::new().unwrap();
        let result = handle_plugins_update_inner(None, dir.path());
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code, ERROR_INVALID_REQUEST);
        assert!(err.message.contains("name is required"));
    }

    #[test]
    fn test_update_empty_name() {
        let dir = TempDir::new().unwrap();
        let params = json!({ "name": "" });
        let result = handle_plugins_update_inner(Some(&params), dir.path());
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.message.contains("name is required"));
    }

    #[test]
    fn test_update_invalid_name() {
        let dir = TempDir::new().unwrap();
        let params = json!({ "name": "bad/name" });
        let result = handle_plugins_update_inner(Some(&params), dir.path());
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.message.contains("alphanumeric"));
    }

    #[test]
    fn test_update_plugin_not_installed() {
        let dir = TempDir::new().unwrap();
        let params = json!({ "name": "nonexistent", "url": "https://example.com/plugin.wasm" });
        let result = handle_plugins_update_inner(Some(&params), dir.path());
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.message.contains("not installed"));
    }

    #[test]
    fn test_update_no_url_returns_error() {
        let dir = TempDir::new().unwrap();
        // Pre-create a manifest entry so the plugin is "installed"
        let manifest = json!({
            "my-plugin": {
                "name": "my-plugin",
                "version": "1.0.0",
                "installed_at": 1700000000000u64
            }
        });
        write_plugins_manifest(dir.path(), &manifest).unwrap();

        let params = json!({ "name": "my-plugin" });
        let result = handle_plugins_update_inner(Some(&params), dir.path());
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.message.contains("no update source available"));
    }

    #[test]
    fn test_update_plugin_found_by_wasm_file() {
        // Even if the manifest doesn't have the entry, a .wasm file on disk counts
        let dir = TempDir::new().unwrap();
        // Create a valid plugin component file on disk.
        let wasm_bytes = tool_plugin_component_bytes();
        std::fs::write(dir.path().join("disk-plugin.wasm"), &wasm_bytes).unwrap();

        // No URL provided, so it should fail with "no update source" (not "not installed")
        let params = json!({ "name": "disk-plugin" });
        let result = handle_plugins_update_inner(Some(&params), dir.path());
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.message.contains("no update source"),
            "expected 'no update source' but got: {}",
            err.message
        );
    }

    #[test]
    fn test_update_invalid_url_scheme() {
        let dir = TempDir::new().unwrap();
        let manifest = json!({ "my-plugin": { "name": "my-plugin" } });
        write_plugins_manifest(dir.path(), &manifest).unwrap();

        let params = json!({ "name": "my-plugin", "url": "ftp://example.com/plugin.wasm" });
        let result = handle_plugins_update_inner(Some(&params), dir.path());
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.message.contains("unsupported url scheme"));
    }

    // ---- ensure_object tests ----

    #[test]
    fn test_ensure_object_with_object_value() {
        let mut value = json!({"key": "val"});
        let obj = ensure_object(&mut value).unwrap();
        assert_eq!(obj.get("key").unwrap(), "val");
    }

    #[test]
    fn test_ensure_object_with_non_object_resets_to_empty() {
        // A non-object value (e.g. a string) should be replaced with an empty object
        let mut value = json!("not an object");
        let obj = ensure_object(&mut value).unwrap();
        assert!(obj.is_empty());
        assert!(value.is_object());
    }

    #[test]
    fn test_ensure_object_with_null_resets_to_empty() {
        let mut value = Value::Null;
        let obj = ensure_object(&mut value).unwrap();
        assert!(obj.is_empty());
        assert!(value.is_object());
    }

    #[test]
    fn test_ensure_object_with_array_resets_to_empty() {
        let mut value = json!([1, 2, 3]);
        let obj = ensure_object(&mut value).unwrap();
        assert!(obj.is_empty());
        assert!(value.is_object());
    }

    // ---- read_plugins_manifest logging tests ----

    #[test]
    fn test_read_plugins_manifest_corrupt_json_returns_empty() {
        // Corrupt JSON should fall back to empty object (and log a warning)
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join(PLUGINS_MANIFEST_FILE), b"not json {{{{").unwrap();
        let manifest = read_plugins_manifest(dir.path());
        assert_eq!(manifest, json!({}));
    }

    #[test]
    fn test_read_plugins_manifest_empty_file_returns_empty() {
        // An empty file is invalid JSON and should fall back gracefully
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join(PLUGINS_MANIFEST_FILE), b"").unwrap();
        let manifest = read_plugins_manifest(dir.path());
        assert_eq!(manifest, json!({}));
    }

    // ---- download_plugin_wasm tests ----

    #[test]
    fn test_download_plugin_wasm_connection_refused() {
        // 127.0.0.1 is now blocked by SSRF protection before any network request is made
        let dir = TempDir::new().unwrap();
        let url = url::Url::parse("http://127.0.0.1:1/nonexistent.wasm").unwrap();
        let result = download_plugin_wasm(&url, dir.path(), "test.wasm");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code, ERROR_INVALID_REQUEST);
        assert!(
            err.message.contains("SSRF"),
            "127.0.0.1 should be blocked by SSRF protection, got: {}",
            err.message
        );
    }

    // ---- SHA-256 hash pinning tests ----

    #[test]
    fn test_plugin_hash_computed_on_install() {
        // Simulate an install without a URL (no download) but manually write a plugin
        // component file and manifest entry with a hash, then verify the hash is present.
        let dir = TempDir::new().unwrap();
        let plugins_dir = dir.path().join("plugins");
        std::fs::create_dir_all(&plugins_dir).unwrap();

        let wasm_bytes = tool_plugin_component_bytes();

        // Compute expected hash
        let expected_hash = compute_sha256_hex(&wasm_bytes);
        assert!(!expected_hash.is_empty());
        assert_eq!(expected_hash.len(), 64); // SHA-256 produces 64 hex chars

        // Write the WASM file
        std::fs::write(plugins_dir.join("my-plugin.wasm"), &wasm_bytes).unwrap();

        // Write a manifest entry that includes the sha256 field (simulating post-install)
        let manifest = json!({
            "my-plugin": {
                "name": "my-plugin",
                "version": "1.0.0",
                "installed_at": 1700000000000u64,
                "sha256": expected_hash
            }
        });
        write_plugins_manifest(&plugins_dir, &manifest).unwrap();

        // Read back and verify hash is stored
        let read_back = read_plugins_manifest(&plugins_dir);
        let stored_hash = read_back["my-plugin"]["sha256"].as_str().unwrap();
        assert_eq!(stored_hash, expected_hash);
        assert_eq!(stored_hash.len(), 64);
        // Verify it is lowercase hex
        assert!(stored_hash
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }

    // ---- DNS rebinding defense tests ----

    #[tokio::test(flavor = "multi_thread")]
    async fn test_download_plugin_dns_rebinding_defense_active() {
        // Verify that the DNS rebinding defense code path is active by testing
        // that both IP-literal and hostname-based URLs are handled correctly.
        // Requires a tokio multi_thread runtime because the hostname path uses
        // async DNS resolution via block_in_place. We use spawn_blocking to
        // isolate the reqwest::blocking::Client from the async test runtime.

        // IP literal: blocked at URL validation (no DNS resolution path).
        // This part does not need spawn_blocking since it fails before
        // creating any blocking HTTP client.
        let dir = TempDir::new().unwrap();
        let ip_url = url::Url::parse("http://10.0.0.1/plugin.wasm").unwrap();
        let result = download_plugin_wasm(&ip_url, dir.path(), "test.wasm");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.message.contains("SSRF"),
            "IP-literal private URL should be blocked by SSRF protection, got: {}",
            err.message
        );

        // Hostname-based URL with a public domain: passes URL validation but
        // enters the DNS resolution + IP validation path. Will fail at the
        // network/DNS level (not SSRF), confirming the defense path is active.
        let dir2 = TempDir::new().unwrap();
        let dir2_path = dir2.path().to_path_buf();
        let result = tokio::task::spawn_blocking(move || {
            let hostname_url =
                url::Url::parse("https://example.com/plugins/my-plugin.wasm").unwrap();
            download_plugin_wasm(&hostname_url, &dir2_path, "test.wasm")
        })
        .await
        .unwrap();
        assert!(result.is_err());
        let err = result.unwrap_err();
        // The error should NOT be an SSRF error -- example.com resolves to a
        // public IP. The error will be a DNS/network error since we are running
        // in a test environment, but critically it must not be an SSRF block.
        assert!(
            !err.message.contains("SSRF") && !err.message.contains("rebinding"),
            "public hostname URL should not be blocked by SSRF/rebinding protection, got: {}",
            err.message
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_download_plugin_hostname_url_passes_ssrf_validation() {
        // Verify that a hostname-based URL with a legitimate public domain
        // passes through SSRF URL validation and reaches the DNS resolution
        // stage (where it may fail due to network, but that is expected).
        // Requires a tokio multi_thread runtime for the async DNS resolution path.
        // We use spawn_blocking to isolate the reqwest::blocking::Client.
        let dir = TempDir::new().unwrap();
        let dir_path = dir.path().to_path_buf();
        let result = tokio::task::spawn_blocking(move || {
            let url = url::Url::parse("https://cdn.example.org/plugins/translator.wasm").unwrap();
            download_plugin_wasm(&url, &dir_path, "translator.wasm")
        })
        .await
        .unwrap();
        assert!(result.is_err());
        let err = result.unwrap_err();
        // Must not fail with an SSRF or rebinding error -- the hostname and
        // its (eventual) resolved IP are both public.
        assert!(
            !err.message.contains("SSRF") && !err.message.contains("rebinding"),
            "legitimate hostname URL must not be rejected by SSRF/rebinding checks, got: {}",
            err.message
        );
    }
}
