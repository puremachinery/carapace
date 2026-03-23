use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde_json::Value;

use crate::credentials;
use crate::plugins::loader::{is_reserved_plugin_id, load_plugins_manifest, LoaderError};
use crate::plugins::permissions::PermissionConfig;
use crate::plugins::sandbox::SandboxConfig;
use crate::plugins::signature::SignatureConfig;
use crate::plugins::{PluginLoader, PluginRegistry, PluginRuntime};
use crate::server::ws::WsServerState;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PluginActivationSource {
    Managed,
    ConfigPath,
}

impl PluginActivationSource {
    pub fn label(self) -> &'static str {
        match self {
            Self::Managed => "managed",
            Self::ConfigPath => "config",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PluginActivationState {
    Active,
    Disabled,
    Ignored,
    Failed,
}

impl PluginActivationState {
    pub fn label(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Disabled => "disabled",
            Self::Ignored => "ignored",
            Self::Failed => "failed",
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct PluginActivationEntry {
    pub name: String,
    pub plugin_id: Option<String>,
    pub source: PluginActivationSource,
    pub enabled: bool,
    pub path: Option<PathBuf>,
    pub requested_at: Option<u64>,
    pub install_id: Option<Value>,
    pub state: PluginActivationState,
    pub reason: Option<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct PluginActivationReport {
    pub enabled: bool,
    pub configured_paths: Vec<PathBuf>,
    /// Startup activation changes require restart in the current model.
    pub restart_required_for_changes: bool,
    pub entries: Vec<PluginActivationEntry>,
    pub errors: Vec<String>,
}

impl PluginActivationReport {
    pub(crate) fn empty(configured_paths: Vec<PathBuf>, enabled: bool) -> Self {
        Self {
            enabled,
            configured_paths,
            restart_required_for_changes: true,
            entries: Vec::new(),
            errors: Vec::new(),
        }
    }
}

pub(crate) struct PluginBootstrapResult {
    pub registry: Arc<PluginRegistry>,
    pub runtime: Option<Arc<PluginRuntime<credentials::DefaultCredentialBackend>>>,
    pub activation_report: PluginActivationReport,
}

#[derive(Debug, Clone)]
struct ManagedPluginConfigEntry {
    name: String,
    enabled: bool,
    requested_at: Option<u64>,
    install_id: Option<Value>,
}

fn plugins_globally_enabled(cfg: &Value) -> bool {
    cfg.pointer("/plugins/enabled")
        .and_then(|value| value.as_bool())
        .unwrap_or(true)
}

pub(crate) fn configured_plugin_paths(cfg: &Value) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    let mut seen = HashSet::new();

    let Some(array) = cfg
        .pointer("/plugins/load/paths")
        .and_then(|value| value.as_array())
    else {
        return paths;
    };

    for value in array {
        let Some(path) = value
            .as_str()
            .map(str::trim)
            .filter(|path| !path.is_empty())
        else {
            continue;
        };
        let path_buf = Path::new(path).components().collect::<PathBuf>();
        if seen.insert(path_buf.clone()) {
            paths.push(path_buf);
        }
    }

    paths
}

fn plugin_signature_config_from_config(cfg: &Value) -> SignatureConfig {
    cfg.pointer("/plugins/signature")
        .cloned()
        .and_then(|value| serde_json::from_value(value).ok())
        .unwrap_or_default()
}

fn plugin_sandbox_config_from_config(cfg: &Value) -> SandboxConfig {
    cfg.pointer("/plugins/sandbox")
        .cloned()
        .and_then(|value| serde_json::from_value(value).ok())
        .unwrap_or_default()
}

fn managed_plugin_config_entries(cfg: &Value) -> Vec<ManagedPluginConfigEntry> {
    let Some(entries) = cfg
        .pointer("/plugins/entries")
        .and_then(|value| value.as_object())
    else {
        return Vec::new();
    };

    let mut managed = entries
        .iter()
        .filter_map(|(name, entry)| {
            if is_reserved_plugin_id(name) {
                return None;
            }
            let entry = entry.as_object()?;
            let unexpected_fields = entry
                .keys()
                .filter(|field| !matches!(field.as_str(), "enabled" | "installId" | "requestedAt"))
                .cloned()
                .collect::<Vec<_>>();
            if !unexpected_fields.is_empty() {
                tracing::warn!(
                    name = %name,
                    unexpected_fields = ?unexpected_fields,
                    "skipping plugins.entries entry with unexpected fields"
                );
                return None;
            }
            Some(ManagedPluginConfigEntry {
                name: name.clone(),
                enabled: entry
                    .get("enabled")
                    .and_then(|value| value.as_bool())
                    .unwrap_or(true),
                requested_at: entry.get("requestedAt").and_then(|value| value.as_u64()),
                install_id: entry.get("installId").cloned(),
            })
        })
        .collect::<Vec<_>>();
    managed.sort_by(|left, right| left.name.cmp(&right.name));
    managed
}

fn manifest_entry_path(entry: &serde_json::Value, managed_dir: &Path, name: &str) -> PathBuf {
    let path = entry
        .get("path")
        .and_then(|value| value.as_str())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(format!("{name}.wasm")));
    if path.is_relative() {
        managed_dir.join(path)
    } else {
        path
    }
}

fn canonical_prefix(path: &Path) -> Result<PathBuf, String> {
    match path.canonicalize() {
        Ok(canonical) => Ok(canonical),
        // If the managed directory does not exist yet, fail closed by comparing against
        // the raw path. Any candidate under that directory still has to canonicalize
        // successfully in `resolve_managed_plugin_path`, which cannot happen while the
        // parent directory is absent.
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(path.to_path_buf()),
        Err(error) => Err(format!(
            "failed to resolve managed plugin directory {}: {error}",
            path.display()
        )),
    }
}

fn canonicalize_existing_path(path: &Path) -> Result<PathBuf, String> {
    path.canonicalize()
        .map_err(|error| format!("failed to resolve {}: {error}", path.display()))
}

fn resolve_managed_plugin_path(
    managed_dir: &Path,
    manifest: &Value,
    entry: &ManagedPluginConfigEntry,
) -> Result<PathBuf, String> {
    let manifest_entry = manifest
        .get(&entry.name)
        .ok_or_else(|| "missing manifest entry in plugins-manifest.json".to_string())?;

    if manifest_entry
        .get("sha256")
        .and_then(|value| value.as_str())
        .is_none()
    {
        return Err(
            "managed plugin is missing a pinned sha256 in plugins-manifest.json".to_string(),
        );
    }

    let path = manifest_entry_path(manifest_entry, managed_dir, &entry.name);
    let canonical_managed_dir = canonical_prefix(managed_dir)?;
    let canonical_path = canonicalize_existing_path(&path)?;
    if !canonical_path.starts_with(&canonical_managed_dir) {
        return Err("managed plugin path escapes the managed plugin directory".to_string());
    }

    let stem = canonical_path
        .file_stem()
        .and_then(|value| value.to_str())
        .ok_or_else(|| "managed plugin path has no valid UTF-8 file stem".to_string())?;
    if stem != entry.name {
        return Err("managed plugin artifact name does not match the configured entry".to_string());
    }

    Ok(canonical_path)
}

fn discover_config_path_plugins(path: &Path) -> Result<Vec<PathBuf>, String> {
    // Config-path loading is an explicit trusted-local-input escape hatch. We scan the
    // directory as configured and intentionally do not apply managed-dir containment or pinning.
    let read_dir = std::fs::read_dir(path).map_err(|error| {
        format!(
            "failed to read configured plugin path {}: {error}",
            path.display()
        )
    })?;

    let mut wasm_paths = Vec::new();
    for entry in read_dir {
        let entry = entry.map_err(|error| {
            format!(
                "failed to read configured plugin path {}: {error}",
                path.display()
            )
        })?;
        let candidate = entry.path();
        if candidate.is_file()
            && candidate
                .extension()
                .and_then(|value| value.to_str())
                .is_some_and(|ext| ext.eq_ignore_ascii_case("wasm"))
        {
            wasm_paths.push(candidate);
        }
    }
    wasm_paths.sort();
    Ok(wasm_paths)
}

pub(crate) fn load_plugin_candidate(
    loader: &PluginLoader,
    report: &mut PluginActivationReport,
    mut entry: PluginActivationEntry,
    wasm_path: &Path,
    report_index_by_plugin_id: &mut HashMap<String, usize>,
) {
    entry.path = Some(wasm_path.to_path_buf());
    match loader.load_plugin(wasm_path) {
        Ok(plugin_id) => {
            entry.plugin_id = Some(plugin_id.clone());
            let index = report.entries.len();
            report_index_by_plugin_id.insert(plugin_id, index);
            report.entries.push(entry);
        }
        Err(error) => {
            entry.state = PluginActivationState::Failed;
            entry.reason = Some(match error {
                LoaderError::DuplicatePluginId(plugin_id) => {
                    entry.plugin_id = Some(plugin_id.clone());
                    format!("plugin ID conflict with an earlier activation source: {plugin_id}")
                }
                other => other.to_string(),
            });
            report.entries.push(entry);
        }
    }
}

pub(crate) fn start_plugin_services(
    shared_registry: &Arc<PluginRegistry>,
    instantiated_service_ids: &[String],
    report: &mut PluginActivationReport,
    report_index_by_plugin_id: &HashMap<String, usize>,
) -> Vec<String> {
    let services_by_id = shared_registry
        .get_services()
        .into_iter()
        .collect::<HashMap<_, _>>();
    let mut unload_plugin_ids = Vec::new();

    for plugin_id in instantiated_service_ids {
        let Some(service) = services_by_id.get(plugin_id) else {
            continue;
        };
        if let Err(error) = service.start() {
            if let Some(index) = report_index_by_plugin_id.get(plugin_id).copied() {
                report.entries[index].state = PluginActivationState::Failed;
                report.entries[index].reason =
                    Some(format!("service plugin failed to start: {error}"));
            }
            unload_plugin_ids.push(plugin_id.clone());
        }
    }

    unload_plugin_ids
}

struct BlockingPluginBootstrapResult {
    report: PluginActivationReport,
    loader: Option<Arc<PluginLoader>>,
    loaded_plugin_ids: Vec<String>,
    report_index_by_plugin_id: HashMap<String, usize>,
    sandbox_config: SandboxConfig,
    permission_config: PermissionConfig,
}

fn discover_and_load_plugins(cfg: Value, state_dir: PathBuf) -> BlockingPluginBootstrapResult {
    let managed_dir = state_dir.join("plugins");
    let configured_paths = configured_plugin_paths(&cfg);
    let plugins_enabled = plugins_globally_enabled(&cfg);
    let mut report = PluginActivationReport::empty(configured_paths.clone(), plugins_enabled);
    let managed_entries = managed_plugin_config_entries(&cfg);

    if !plugins_enabled {
        for entry in managed_entries {
            report.entries.push(PluginActivationEntry {
                name: entry.name,
                plugin_id: None,
                source: PluginActivationSource::Managed,
                enabled: entry.enabled,
                path: None,
                requested_at: entry.requested_at,
                install_id: entry.install_id,
                state: if entry.enabled {
                    PluginActivationState::Ignored
                } else {
                    PluginActivationState::Disabled
                },
                reason: Some("plugin loading is disabled by plugins.enabled=false".to_string()),
            });
        }
        return BlockingPluginBootstrapResult {
            report,
            loader: None,
            loaded_plugin_ids: Vec::new(),
            report_index_by_plugin_id: HashMap::new(),
            sandbox_config: plugin_sandbox_config_from_config(&cfg),
            permission_config: PermissionConfig::default(),
        };
    }

    let signature_config = plugin_signature_config_from_config(&cfg);
    let sandbox_config = plugin_sandbox_config_from_config(&cfg);
    let permission_config = PermissionConfig::default();
    let loader = match PluginLoader::with_signature_config(managed_dir.clone(), signature_config) {
        Ok(loader) => Arc::new(loader),
        Err(error) => {
            report
                .errors
                .push(format!("failed to initialize plugin loader: {error}"));
            return BlockingPluginBootstrapResult {
                report,
                loader: None,
                loaded_plugin_ids: Vec::new(),
                report_index_by_plugin_id: HashMap::new(),
                sandbox_config,
                permission_config,
            };
        }
    };
    let mut report_index_by_plugin_id = HashMap::new();

    if !configured_paths.is_empty() {
        tracing::warn!(
            configured_path_count = configured_paths.len(),
            "plugins.load.paths trusts local filesystem directories; managed sha256 pinning and containment checks are not applied"
        );
    }

    let (manifest, manifest_error) = match load_plugins_manifest(&managed_dir) {
        Ok(Some(manifest)) => (manifest, None),
        Ok(None) => (Value::Object(Default::default()), None),
        Err(error) => {
            report.errors.push(error);
            (
                Value::Object(Default::default()),
                Some(
                    "managed plugins manifest is invalid; fix plugins-manifest.json and restart"
                        .to_string(),
                ),
            )
        }
    };
    let managed_entry_names = managed_entries
        .iter()
        .map(|entry| entry.name.clone())
        .collect::<HashSet<_>>();

    for entry in managed_entries {
        let mut activation_entry = PluginActivationEntry {
            name: entry.name.clone(),
            plugin_id: None,
            source: PluginActivationSource::Managed,
            enabled: entry.enabled,
            path: None,
            requested_at: entry.requested_at,
            install_id: entry.install_id.clone(),
            state: PluginActivationState::Ignored,
            reason: None,
        };

        if !entry.enabled {
            activation_entry.state = PluginActivationState::Disabled;
            activation_entry.reason =
                Some("managed plugin is disabled in plugins.entries".to_string());
            report.entries.push(activation_entry);
            continue;
        }

        if let Some(reason) = manifest_error.as_ref() {
            activation_entry.state = PluginActivationState::Failed;
            activation_entry.reason = Some(reason.clone());
            report.entries.push(activation_entry);
            continue;
        }

        let wasm_path = match resolve_managed_plugin_path(&managed_dir, &manifest, &entry) {
            Ok(path) => path,
            Err(reason) => {
                activation_entry.state = PluginActivationState::Failed;
                activation_entry.reason = Some(reason);
                report.entries.push(activation_entry);
                continue;
            }
        };

        load_plugin_candidate(
            loader.as_ref(),
            &mut report,
            activation_entry,
            &wasm_path,
            &mut report_index_by_plugin_id,
        );
    }

    if let Ok(read_dir) = std::fs::read_dir(&managed_dir) {
        let mut stray_paths = read_dir
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| {
                path.is_file()
                    && path
                        .extension()
                        .and_then(|value| value.to_str())
                        .is_some_and(|ext| ext.eq_ignore_ascii_case("wasm"))
            })
            .collect::<Vec<_>>();
        stray_paths.sort();

        for path in stray_paths {
            let Some(stem) = path.file_stem().and_then(|value| value.to_str()) else {
                continue;
            };
            if managed_entry_names.contains(stem) {
                continue;
            }
            report.entries.push(PluginActivationEntry {
                name: stem.to_string(),
                plugin_id: None,
                source: PluginActivationSource::Managed,
                enabled: false,
                path: Some(path),
                requested_at: None,
                install_id: None,
                state: PluginActivationState::Ignored,
                reason: Some(
                    "WASM file is present in the managed plugin directory but not declared in plugins.entries"
                        .to_string(),
                ),
            });
        }
    }

    for plugin_path in &configured_paths {
        let wasm_paths = match discover_config_path_plugins(plugin_path) {
            Ok(paths) => paths,
            Err(error) => {
                report.errors.push(error);
                continue;
            }
        };

        for wasm_path in wasm_paths {
            let name = wasm_path
                .file_stem()
                .and_then(|value| value.to_str())
                .unwrap_or("unknown-plugin")
                .to_string();
            let activation_entry = PluginActivationEntry {
                name,
                plugin_id: None,
                source: PluginActivationSource::ConfigPath,
                enabled: true,
                path: Some(wasm_path.clone()),
                requested_at: None,
                install_id: None,
                state: PluginActivationState::Ignored,
                reason: None,
            };
            load_plugin_candidate(
                loader.as_ref(),
                &mut report,
                activation_entry,
                &wasm_path,
                &mut report_index_by_plugin_id,
            );
        }
    }

    let loaded_plugin_ids = loader.list_plugins();
    BlockingPluginBootstrapResult {
        report,
        loader: Some(loader),
        loaded_plugin_ids,
        report_index_by_plugin_id,
        sandbox_config,
        permission_config,
    }
}

pub(crate) async fn bootstrap_plugin_runtime(
    cfg: &Value,
    state_dir: &Path,
) -> PluginBootstrapResult {
    let registry = Arc::new(PluginRegistry::new());
    let fallback_report =
        PluginActivationReport::empty(configured_plugin_paths(cfg), plugins_globally_enabled(cfg));
    let blocking = match tokio::task::spawn_blocking({
        let cfg = cfg.clone();
        let state_dir = state_dir.to_path_buf();
        move || discover_and_load_plugins(cfg, state_dir)
    })
    .await
    {
        Ok(result) => result,
        Err(error) => {
            let mut report = fallback_report;
            report
                .errors
                .push(format!("plugin bootstrap worker failed: {error}"));
            return PluginBootstrapResult {
                registry,
                runtime: None,
                activation_report: report,
            };
        }
    };

    let BlockingPluginBootstrapResult {
        mut report,
        loader,
        loaded_plugin_ids,
        report_index_by_plugin_id,
        sandbox_config,
        permission_config,
    } = blocking;

    let Some(loader) = loader else {
        return PluginBootstrapResult {
            registry,
            runtime: None,
            activation_report: report,
        };
    };

    if loaded_plugin_ids.is_empty() {
        return PluginBootstrapResult {
            registry,
            runtime: None,
            activation_report: report,
        };
    }

    let credential_store = match credentials::create_default_store(state_dir.to_path_buf()).await {
        Ok(store) => store,
        Err(error) => {
            report.errors.push(format!(
                "failed to initialize plugin credential store: {error}"
            ));
            for plugin_id in loaded_plugin_ids {
                if let Some(index) = report_index_by_plugin_id.get(&plugin_id).copied() {
                    report.entries[index].state = PluginActivationState::Failed;
                    report.entries[index].reason =
                        Some(format!("plugin runtime unavailable: {error}"));
                }
            }
            return PluginBootstrapResult {
                registry,
                runtime: None,
                activation_report: report,
            };
        }
    };

    let runtime = match PluginRuntime::with_permissions_config(
        loader.clone(),
        credential_store,
        Arc::new(crate::plugins::RateLimiterRegistry::new()),
        crate::plugins::capabilities::SsrfConfig::default(),
        sandbox_config,
        permission_config,
    ) {
        Ok(runtime) => Arc::new(runtime),
        Err(error) => {
            report
                .errors
                .push(format!("failed to initialize plugin runtime: {error}"));
            for plugin_id in loaded_plugin_ids {
                if let Some(index) = report_index_by_plugin_id.get(&plugin_id).copied() {
                    report.entries[index].state = PluginActivationState::Failed;
                    report.entries[index].reason =
                        Some(format!("plugin runtime unavailable: {error}"));
                }
            }
            return PluginBootstrapResult {
                registry,
                runtime: None,
                activation_report: report,
            };
        }
    };
    let shared_registry = runtime.registry();

    let mut instantiated_service_ids = Vec::new();
    for plugin_id in loaded_plugin_ids {
        if let Some(index) = report_index_by_plugin_id.get(&plugin_id).copied() {
            let entry = &mut report.entries[index];
            match runtime.instantiate_plugin(&plugin_id).await {
                Ok(()) => {
                    entry.state = PluginActivationState::Active;
                    entry.plugin_id = Some(plugin_id.clone());
                    if let Some(loaded) = loader.get_plugin(&plugin_id) {
                        if loaded.manifest.kind == crate::plugins::PluginKind::Service {
                            instantiated_service_ids.push(plugin_id.clone());
                        }
                    }
                }
                Err(error) => {
                    entry.state = PluginActivationState::Failed;
                    entry.plugin_id = Some(plugin_id.clone());
                    entry.reason = Some(error.to_string());
                }
            }
        }
    }

    for plugin_id in start_plugin_services(
        &shared_registry,
        &instantiated_service_ids,
        &mut report,
        &report_index_by_plugin_id,
    ) {
        runtime.unload_plugin(&plugin_id).ok();
    }

    PluginBootstrapResult {
        registry: shared_registry,
        runtime: Some(runtime),
        activation_report: report,
    }
}

pub(crate) fn stop_plugin_services(ws_state: &WsServerState) {
    let runtime = ws_state.plugin_runtime().cloned();
    let Some(registry) = runtime
        .as_ref()
        .map(|runtime| runtime.registry())
        .or_else(|| ws_state.plugin_registry().cloned())
    else {
        return;
    };

    for (plugin_id, service) in registry.get_services() {
        if let Err(error) = service.stop() {
            tracing::warn!(plugin_id = %plugin_id, error = %error, "failed to stop service plugin");
        }
        if let Some(runtime) = runtime.as_ref() {
            if let Err(error) = runtime.unload_plugin(&plugin_id) {
                tracing::warn!(plugin_id = %plugin_id, error = %error, "failed to unload service plugin");
            }
        }
    }
}
