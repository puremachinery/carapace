//! Testable server startup logic.
//!
//! Provides [`ServerConfig`] and [`ServerHandle`] to allow integration tests
//! to spin up a real (non-TLS) Carapace server on an ephemeral port, exercise
//! its HTTP and WebSocket endpoints, and shut it down cleanly.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use axum::routing::get;
use axum::Router;
use serde_json::Value;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tracing::{error, info, warn};

use crate::config;
use crate::credentials;
use crate::cron;
use crate::hooks::registry::HookRegistry;
use crate::messages;
use crate::plugins::loader::{load_skills_manifest, LoaderError};
use crate::plugins::permissions::PermissionConfig;
use crate::plugins::sandbox::SandboxConfig;
use crate::plugins::signature::SignatureConfig;
use crate::plugins::tools::ToolsRegistry;
use crate::plugins::{PluginLoader, PluginRegistry, PluginRuntime};
use crate::server::http::{HttpConfig, MiddlewareConfig};
use crate::server::ws::WsServerState;
use crate::sessions;
use crate::tasks::{DurableTask, TaskBlockedReason, TaskExecutionOutcome, TaskExecutor};

struct RuntimeTaskExecutor {
    state: Arc<WsServerState>,
}

const NO_PROVIDER_RETRY_DELAY_MS: u64 = 60_000;
const NO_PROVIDER_LEGACY_MAX_RETRY_ATTEMPTS: u32 = 3_600;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PluginActivationSource {
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
pub enum PluginActivationState {
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
pub struct PluginActivationEntry {
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
pub struct PluginActivationReport {
    pub enabled: bool,
    pub managed_dir: PathBuf,
    pub configured_paths: Vec<PathBuf>,
    /// Startup activation changes require restart in the current model.
    pub restart_required_for_changes: bool,
    pub entries: Vec<PluginActivationEntry>,
    pub errors: Vec<String>,
}

impl PluginActivationReport {
    fn empty(managed_dir: PathBuf, configured_paths: Vec<PathBuf>, enabled: bool) -> Self {
        Self {
            enabled,
            managed_dir,
            configured_paths,
            restart_required_for_changes: true,
            entries: Vec::new(),
            errors: Vec::new(),
        }
    }
}

struct PluginBootstrapResult {
    registry: Arc<PluginRegistry>,
    runtime: Option<Arc<PluginRuntime<credentials::DefaultCredentialBackend>>>,
    activation_report: PluginActivationReport,
}

#[derive(Debug, Clone)]
struct ManagedSkillConfigEntry {
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
        let path_buf = PathBuf::from(path);
        if seen.insert(path_buf.clone()) {
            paths.push(path_buf);
        }
    }

    paths
}

fn plugin_signature_config_from_config(cfg: &Value) -> SignatureConfig {
    cfg.pointer("/skills/signature")
        .cloned()
        .and_then(|value| serde_json::from_value(value).ok())
        .unwrap_or_default()
}

fn plugin_sandbox_config_from_config(cfg: &Value) -> SandboxConfig {
    cfg.pointer("/skills/sandbox")
        .cloned()
        .and_then(|value| serde_json::from_value(value).ok())
        .unwrap_or_default()
}

fn managed_skill_config_entries(cfg: &Value) -> Vec<ManagedSkillConfigEntry> {
    let Some(entries) = cfg
        .pointer("/skills/entries")
        .and_then(|value| value.as_object())
    else {
        return Vec::new();
    };

    let mut managed = entries
        .iter()
        .map(|(name, entry)| ManagedSkillConfigEntry {
            name: name.clone(),
            enabled: entry
                .get("enabled")
                .and_then(|value| value.as_bool())
                .unwrap_or(true),
            requested_at: entry.get("requestedAt").and_then(|value| value.as_u64()),
            install_id: entry.get("installId").cloned(),
        })
        .collect::<Vec<_>>();
    // Managed activation uses alphabetical order as the deterministic load order
    // within this source. The API layer may sort again for presentation.
    managed.sort_by(|left, right| left.name.cmp(&right.name));
    managed
}

fn manifest_entry_path(entry: &serde_json::Value, managed_dir: &Path, name: &str) -> PathBuf {
    entry
        .get("path")
        .and_then(|value| value.as_str())
        .map(PathBuf::from)
        .unwrap_or_else(|| managed_dir.join(format!("{name}.wasm")))
}

fn canonical_prefix(path: &Path) -> PathBuf {
    // Fall back to the declared path when canonicalization fails so callers can
    // still perform a deterministic prefix check and report the real missing-path
    // error from canonicalizing the candidate itself.
    path.canonicalize().unwrap_or_else(|_| path.to_path_buf())
}

fn canonicalize_existing_path(path: &Path) -> Result<PathBuf, String> {
    path.canonicalize()
        .map_err(|error| format!("failed to resolve {}: {error}", path.display()))
}

fn resolve_managed_skill_path(
    managed_dir: &Path,
    manifest: &Value,
    entry: &ManagedSkillConfigEntry,
) -> Result<PathBuf, String> {
    let manifest_entry = manifest
        .get(&entry.name)
        .ok_or_else(|| "missing manifest entry in skills-manifest.json".to_string())?;

    // This presence check is only the managed-policy gate. The actual byte-level
    // SHA-256 verification still happens inside `PluginLoader::load_plugin`.
    if manifest_entry
        .get("sha256")
        .and_then(|value| value.as_str())
        .is_none()
    {
        return Err("managed skill is missing a pinned sha256 in skills-manifest.json".to_string());
    }

    let path = manifest_entry_path(manifest_entry, managed_dir, &entry.name);
    let canonical_managed_dir = canonical_prefix(managed_dir);
    let canonical_path = canonicalize_existing_path(&path)?;
    if !canonical_path.starts_with(&canonical_managed_dir) {
        return Err(format!(
            "managed skill path {} escapes {}",
            canonical_path.display(),
            canonical_managed_dir.display()
        ));
    }

    let stem = canonical_path
        .file_stem()
        .and_then(|value| value.to_str())
        .ok_or_else(|| "managed skill path has no valid UTF-8 file stem".to_string())?;
    if stem != entry.name {
        return Err(format!(
            "managed skill path {} does not match configured entry {}",
            canonical_path.display(),
            entry.name
        ));
    }

    Ok(canonical_path)
}

fn discover_config_path_plugins(path: &Path) -> Result<Vec<PathBuf>, String> {
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
        if candidate
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

fn load_plugin_candidate(
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

struct BlockingPluginBootstrapResult {
    report: PluginActivationReport,
    loader: Option<Arc<PluginLoader>>,
    loaded_plugin_ids: Vec<String>,
    report_index_by_plugin_id: HashMap<String, usize>,
    sandbox_config: SandboxConfig,
    permission_config: PermissionConfig,
}

fn discover_and_load_plugins(cfg: Value, state_dir: PathBuf) -> BlockingPluginBootstrapResult {
    let managed_dir = state_dir.join("skills");
    let configured_paths = configured_plugin_paths(&cfg);
    let plugins_enabled = plugins_globally_enabled(&cfg);
    let mut report = PluginActivationReport::empty(
        managed_dir.clone(),
        configured_paths.clone(),
        plugins_enabled,
    );
    let managed_entries = managed_skill_config_entries(&cfg);

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

    let (manifest, manifest_error) = match load_skills_manifest(&managed_dir) {
        Ok(Some(manifest)) => (manifest, None),
        Ok(None) => (Value::Object(Default::default()), None),
        Err(error) => {
            report.errors.push(error);
            (
                Value::Object(Default::default()),
                Some(
                    "managed skills manifest is invalid; fix skills-manifest.json and restart"
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
                Some("managed skill is disabled in skills.entries".to_string());
            report.entries.push(activation_entry);
            continue;
        }

        if let Some(reason) = manifest_error.as_ref() {
            activation_entry.state = PluginActivationState::Failed;
            activation_entry.reason = Some(reason.clone());
            report.entries.push(activation_entry);
            continue;
        }

        let wasm_path = match resolve_managed_skill_path(&managed_dir, &manifest, &entry) {
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
                path.extension()
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
                    "WASM file is present in the managed skills directory but not declared in skills.entries"
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

async fn bootstrap_plugin_runtime(cfg: &Value, state_dir: &Path) -> PluginBootstrapResult {
    let registry = Arc::new(PluginRegistry::new());
    let fallback_report = PluginActivationReport::empty(
        state_dir.join("skills"),
        configured_plugin_paths(cfg),
        plugins_globally_enabled(cfg),
    );
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

    for plugin_id in instantiated_service_ids {
        let Some(service) = shared_registry
            .get_services()
            .into_iter()
            .find_map(
                |(id, service)| {
                    if id == plugin_id {
                        Some(service)
                    } else {
                        None
                    }
                },
            )
        else {
            continue;
        };
        if let Err(error) = service.start() {
            if let Some(index) = report_index_by_plugin_id.get(&plugin_id).copied() {
                report.entries[index].state = PluginActivationState::Failed;
                report.entries[index].reason =
                    Some(format!("service plugin failed to start: {error}"));
            }
            runtime.unload_plugin(&plugin_id).ok();
        }
    }

    PluginBootstrapResult {
        registry: shared_registry,
        runtime: Some(runtime),
        activation_report: report,
    }
}

fn invalid_policy_budget_error(policy: &crate::tasks::TaskPolicy) -> Option<&'static str> {
    if policy.max_attempts == 0 {
        Some("maxAttempts must be greater than 0")
    } else if policy.max_total_runtime_ms == 0 {
        Some("maxTotalRuntimeMs must be greater than 0")
    } else if policy.max_turns == 0 {
        Some("maxTurns must be greater than 0")
    } else if policy.max_run_timeout_seconds == 0 {
        Some("maxRunTimeoutSeconds must be greater than 0")
    } else {
        None
    }
}

#[async_trait]
impl TaskExecutor for RuntimeTaskExecutor {
    async fn execute(&self, task: DurableTask) -> TaskExecutionOutcome {
        // Policy budgets are enforced only for tasks created with explicit
        // policy metadata. Legacy tasks loaded from pre-policy queue files
        // deserialize with policy_explicit=false and retain prior behavior.
        if task.policy_explicit {
            // Belt-and-suspenders fail-closed guard: control API validation
            // rejects zero budgets, but persisted/manual task mutations should
            // still fail safely at execution time.
            if let Some(error) = invalid_policy_budget_error(&task.policy) {
                return TaskExecutionOutcome::Failed {
                    error: format!("objective policy violation: {error}"),
                };
            }

            if task.attempts > task.policy.max_attempts {
                return TaskExecutionOutcome::Failed {
                    error: format!(
                        "objective policy violation: attempts {} exceeded maxAttempts {}",
                        task.attempts, task.policy.max_attempts
                    ),
                };
            }

            let now_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64;
            let task_age_ms = now_ms.saturating_sub(task.created_at_ms);
            if task_age_ms > task.policy.max_total_runtime_ms {
                return TaskExecutionOutcome::Failed {
                    error: format!(
                        "objective policy violation: task age {}ms exceeded maxTotalRuntimeMs {}",
                        task_age_ms, task.policy.max_total_runtime_ms
                    ),
                };
            }
        }

        let payload = match serde_json::from_value::<crate::cron::CronPayload>(task.payload) {
            Ok(payload) => payload,
            Err(err) => {
                return TaskExecutionOutcome::Failed {
                    error: format!("invalid task payload: {err}"),
                };
            }
        };

        let execution_limits = if task.policy_explicit {
            crate::cron::executor::ExecutionLimits {
                max_turns: Some(task.policy.max_turns),
                max_timeout_seconds: Some(task.policy.max_run_timeout_seconds),
            }
        } else {
            crate::cron::executor::ExecutionLimits::default()
        };

        match crate::cron::executor::execute_payload(
            &task.id,
            &payload,
            &self.state,
            execution_limits,
        )
        .await
        {
            Ok(crate::cron::executor::CronRunOutcome::Broadcast) => {
                TaskExecutionOutcome::Done { run_id: None }
            }
            Ok(crate::cron::executor::CronRunOutcome::Spawned { run_id }) => {
                TaskExecutionOutcome::Done {
                    run_id: Some(run_id),
                }
            }
            Err(crate::cron::executor::CronExecuteError::LlmNotConfigured) => {
                // At budget boundary, fail immediately instead of enqueuing a
                // retry that cannot run due to maxAttempts preflight checks.
                if task.policy_explicit && task.attempts >= task.policy.max_attempts {
                    TaskExecutionOutcome::Blocked {
                        category: TaskBlockedReason::ConfigMissing,
                        reason: format!(
                            "{} (retry limit reached: {})",
                            crate::cron::executor::NO_LLM_PROVIDER_CONFIGURED_ERROR,
                            task.policy.max_attempts
                        ),
                    }
                } else if !task.policy_explicit
                    && task.attempts >= NO_PROVIDER_LEGACY_MAX_RETRY_ATTEMPTS
                {
                    TaskExecutionOutcome::Blocked {
                        category: TaskBlockedReason::ConfigMissing,
                        reason: format!(
                            "{} (retry limit reached: {})",
                            crate::cron::executor::NO_LLM_PROVIDER_CONFIGURED_ERROR,
                            NO_PROVIDER_LEGACY_MAX_RETRY_ATTEMPTS
                        ),
                    }
                } else {
                    TaskExecutionOutcome::RetryWait {
                        delay_ms: NO_PROVIDER_RETRY_DELAY_MS,
                        error: crate::cron::executor::NO_LLM_PROVIDER_CONFIGURED_ERROR.to_string(),
                    }
                }
            }
            Err(crate::cron::executor::CronExecuteError::Other(error)) => {
                TaskExecutionOutcome::Failed { error }
            }
        }
    }
}

/// Everything needed to start a non-TLS Carapace server.
pub struct ServerConfig {
    pub ws_state: Arc<WsServerState>,
    pub http_config: HttpConfig,
    pub middleware_config: MiddlewareConfig,
    pub hook_registry: Arc<HookRegistry>,
    pub tools_registry: Arc<ToolsRegistry>,
    pub bind_address: SocketAddr,
    pub raw_config: Value,
    /// When `false` (e.g. in tests), background tasks like the delivery loop,
    /// cron tick, config watcher, SIGHUP handler, and retention cleanup are
    /// **not** spawned.
    pub spawn_background_tasks: bool,
}

impl ServerConfig {
    /// Minimal config suitable for integration tests.
    ///
    /// Binds to `127.0.0.1:0` (OS-assigned port), disables all middleware and
    /// background tasks, and uses empty registries.
    pub fn for_testing(ws_state: Arc<WsServerState>) -> Self {
        ServerConfig {
            ws_state,
            http_config: HttpConfig::default(),
            middleware_config: MiddlewareConfig::none(),
            hook_registry: Arc::new(HookRegistry::new()),
            tools_registry: Arc::new(ToolsRegistry::new()),
            bind_address: SocketAddr::from(([127, 0, 0, 1], 0)),
            raw_config: Value::Object(serde_json::Map::new()),
            spawn_background_tasks: false,
        }
    }
}

/// Build the runtime `WsServerState` used by server startup paths.
///
/// Shared by `main.rs` and embedded CLI startup to avoid drift in provider and
/// registry wiring.
pub async fn build_ws_state_with_runtime_dependencies(
    cfg: &Value,
    state_dir: &Path,
    tools_registry: Arc<ToolsRegistry>,
) -> Result<Arc<WsServerState>, Box<dyn std::error::Error>> {
    let ws_state = crate::server::ws::build_ws_state_owned_from_value(cfg).await?;
    let ws_state = match crate::agent::factory::build_providers(cfg)? {
        Some(multi_provider) => ws_state.with_llm_provider(Arc::new(multi_provider)),
        None => {
            info!(
                "No LLM provider configured (set ANTHROPIC_API_KEY, OPENAI_API_KEY, GOOGLE_API_KEY, VENICE_API_KEY, configure Ollama, configure google.authProfile, or configure codex.authProfile)"
            );
            ws_state
        }
    };

    let plugin_bootstrap = bootstrap_plugin_runtime(cfg, state_dir).await;
    tools_registry.set_plugin_registry(plugin_bootstrap.registry.clone());
    Ok(Arc::new(
        ws_state
            .with_tools_registry(tools_registry)
            .with_plugin_registry(plugin_bootstrap.registry)
            .with_plugin_runtime_opt(plugin_bootstrap.runtime)
            .with_plugin_activation_report(plugin_bootstrap.activation_report),
    ))
}

/// Prepare runtime state storage and shared local startup services.
///
/// Shared by normal server startup and embedded chat startup to keep state
/// directory creation, audit initialization, and media cleanup wiring in one
/// place.
pub async fn prepare_runtime_environment() -> Result<std::path::PathBuf, Box<dyn std::error::Error>>
{
    let state_dir = crate::server::ws::resolve_state_dir();
    tokio::fs::create_dir_all(&state_dir).await?;
    tokio::fs::create_dir_all(state_dir.join("sessions")).await?;
    tokio::fs::create_dir_all(state_dir.join("cron")).await?;
    tokio::fs::create_dir_all(state_dir.join("tasks")).await?;
    crate::logging::audit::AuditLog::init(state_dir.clone()).await;
    init_media_store_cleanup().await;
    Ok(state_dir)
}

async fn init_media_store_cleanup() {
    let store = match crate::media::MediaStore::new(crate::media::StoreConfig::default()).await {
        Ok(store) => store,
        Err(e) => {
            warn!(error = %e, "failed to initialize media store");
            return;
        }
    };
    let store = Arc::new(store);
    let _cleanup = store.clone().start_cleanup_task();
    info!("media store cleanup task started");
}

/// Handle to a running server.  Returned by [`run_server_with_config`].
pub struct ServerHandle {
    local_addr: SocketAddr,
    shutdown_tx: watch::Sender<bool>,
    ws_state: Arc<WsServerState>,
    server_task: JoinHandle<Result<(), std::io::Error>>,
}

impl ServerHandle {
    /// The port the server actually bound to (useful when binding to port 0).
    pub fn port(&self) -> u16 {
        self.local_addr.port()
    }

    /// The full local address (ip + port).
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// `http://ip:port` base URL for the running server.
    pub fn base_url(&self) -> String {
        format!("http://{}", self.local_addr)
    }

    /// Trigger graceful shutdown: notify background tasks, broadcast to WS
    /// clients, flush sessions, then await the server task.
    #[allow(clippy::cognitive_complexity)]
    pub async fn shutdown(self) {
        // Signal background tasks to stop
        let _ = self.shutdown_tx.send(true);

        // Broadcast shutdown event to connected WebSocket clients
        crate::server::ws::broadcast_shutdown(&self.ws_state, "test-shutdown", None);

        // Flush dirty sessions
        if let Err(e) = self.ws_state.session_store().flush_all() {
            error!("Failed to flush session store during shutdown: {}", e);
        }

        stop_plugin_services(&self.ws_state);

        // Brief grace period for in-flight operations
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Wait for the server task to finish (with a timeout to avoid hanging)
        match tokio::time::timeout(Duration::from_secs(5), self.server_task).await {
            Ok(Ok(Ok(()))) => {}
            Ok(Ok(Err(e))) => error!("Server task returned error: {}", e),
            Ok(Err(e)) => error!("Server task panicked: {}", e),
            Err(_) => warn!("Server task did not finish within 5s timeout"),
        }
    }
}

pub fn stop_plugin_services(ws_state: &WsServerState) {
    let Some(plugin_registry) = ws_state
        .plugin_runtime()
        .map(|runtime| runtime.registry())
        .or_else(|| ws_state.plugin_registry().cloned())
    else {
        return;
    };

    for (plugin_id, service) in plugin_registry.get_services() {
        if let Err(error) = service.stop() {
            warn!(plugin_id = %plugin_id, error = %error, "error stopping service plugin");
        } else {
            info!(plugin_id = %plugin_id, "service plugin stopped");
        }
    }
}

/// Spawn the SIGHUP handler that triggers config reload on Unix systems.
#[cfg(unix)]
fn spawn_sighup_handler(
    ws_state: &Arc<WsServerState>,
    config_watcher: &config::watcher::ConfigWatcher,
    shutdown_rx: &watch::Receiver<bool>,
) {
    let ws_state_for_sighup = ws_state.clone();
    let config_event_tx = config_watcher.event_sender();
    let mut sighup_shutdown_rx = shutdown_rx.clone();
    tokio::spawn(async move {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sighup = match signal(SignalKind::hangup()) {
            Ok(s) => s,
            Err(e) => {
                error!("Failed to install SIGHUP handler: {}", e);
                return;
            }
        };
        loop {
            tokio::select! {
                _ = sighup.recv() => {
                    info!("SIGHUP received, triggering config reload");
                    let current_cfg = config::load_config()
                        .unwrap_or_else(|_| serde_json::Value::Object(serde_json::Map::new()));
                    let mode_str = current_cfg
                        .get("gateway")
                        .and_then(|g| g.get("reload"))
                        .and_then(|r| r.get("mode"))
                        .and_then(|m| m.as_str())
                        .unwrap_or("hot");
                    let mode = match config::watcher::ReloadMode::parse_mode(mode_str) {
                        config::watcher::ReloadMode::Off => config::watcher::ReloadMode::Hot,
                        other => other,
                    };
                    let result = config::watcher::perform_reload_async(&mode).await;
                    if result.success {
                        crate::server::ws::broadcast_config_changed(
                            &ws_state_for_sighup,
                            &result.mode,
                        );
                        let _ = config_event_tx.send(
                            config::watcher::ConfigEvent::Reloaded(result),
                        );
                    } else {
                        let _ = config_event_tx.send(
                            config::watcher::ConfigEvent::ReloadFailed(result),
                        );
                    }
                }
                _ = sighup_shutdown_rx.changed() => {
                    if *sighup_shutdown_rx.borrow() {
                        break;
                    }
                }
            }
        }
    });
}

/// Spawn the resource monitor and session retention cleanup tasks.
fn spawn_monitoring_and_retention(
    ws_state: &Arc<WsServerState>,
    raw_config: &Value,
    shutdown_rx: &watch::Receiver<bool>,
) {
    // Resource monitor (60s sampling interval)
    let state_dir = crate::server::ws::resolve_state_dir();
    let health_checker = Arc::new(crate::server::health::HealthChecker::new(state_dir));
    let monitor = Arc::new(crate::server::resource_monitor::ResourceMonitor::new(
        health_checker,
    ));
    let monitor_rx = shutdown_rx.clone();
    tokio::spawn(crate::server::resource_monitor::run_resource_monitor(
        monitor,
        Duration::from_secs(60),
        crate::server::resource_monitor::ResourceThresholds::default(),
        monitor_rx,
    ));

    // Session retention cleanup loop
    let retention_config = sessions::retention::build_retention_config(raw_config);
    if retention_config.enabled {
        tokio::spawn(sessions::retention::retention_cleanup_loop(
            ws_state.session_store().clone(),
            retention_config,
            shutdown_rx.clone(),
        ));
    }
}

fn spawn_update_resume_task(shutdown_rx: &watch::Receiver<bool>) {
    let mut update_shutdown_rx = shutdown_rx.clone();
    tokio::spawn(async move {
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(1)) => {}
            result = update_shutdown_rx.changed() => {
                if result.is_err() || *update_shutdown_rx.borrow() {
                    return;
                }
            }
        }

        let state_dir = crate::server::ws::resolve_state_dir();
        match crate::update::auto_resume_with_backoff(
            state_dir,
            env!("CARGO_PKG_VERSION").to_string(),
            true,
            Some(update_shutdown_rx),
        )
        .await
        {
            Ok(Some(outcome)) => {
                info!(
                    version = %outcome.version,
                    staged_path = %outcome.staged_path,
                    applied = outcome.applied,
                    "resumed pending update transaction"
                );
            }
            Ok(None) => {}
            Err(err) => {
                warn!(
                    phase = ?err.phase,
                    retryable = err.retryable,
                    error = %err.message,
                    "failed to resume pending update transaction"
                );
            }
        }
    });
}

/// Spawn background tasks (delivery loop, cron, config watcher, SIGHUP,
/// retention cleanup).  Shared between `run_server_with_config` and the
/// production TLS path in `main.rs`.
pub fn spawn_background_tasks(
    ws_state: &Arc<WsServerState>,
    raw_config: &Value,
    shutdown_rx: &watch::Receiver<bool>,
) {
    // Durable task worker loop
    let task_executor = Arc::new(RuntimeTaskExecutor {
        state: ws_state.clone(),
    });
    tokio::spawn(crate::tasks::task_worker_loop(
        ws_state.task_queue().clone(),
        task_executor,
        Duration::from_secs(1),
        shutdown_rx.clone(),
    ));

    // One-shot updater resume pass for interrupted updates.
    spawn_update_resume_task(shutdown_rx);

    // Delivery loop
    if let Some(plugin_reg) = ws_state.plugin_registry().cloned() {
        let pipeline = ws_state.message_pipeline().clone();
        let channels = ws_state.channel_registry().clone();
        let state = ws_state.clone();
        let rx = shutdown_rx.clone();
        tokio::spawn(messages::delivery::delivery_loop(
            pipeline, plugin_reg, channels, state, rx,
        ));
    }

    // Cron tick loop
    tokio::spawn(cron::tick::cron_tick_loop(
        ws_state.clone(),
        Duration::from_secs(10),
        shutdown_rx.clone(),
    ));

    // Config file watcher (hot/hybrid reload)
    let config_watcher = config::watcher::ConfigWatcher::from_config(raw_config);
    {
        let config_path = config::get_config_path();
        info!("Config reload mode: {:?}", config_watcher.mode());
        config_watcher.start(config_path, shutdown_rx.clone());
    }

    // Bridge config watcher events to WS broadcasts + provider hot-swap
    spawn_config_watcher_bridge(&config_watcher, ws_state, raw_config, shutdown_rx);

    // SIGHUP handler for manual config reload (Unix only)
    #[cfg(unix)]
    spawn_sighup_handler(ws_state, &config_watcher, shutdown_rx);

    // Resource monitor and session retention cleanup
    spawn_monitoring_and_retention(ws_state, raw_config, shutdown_rx);
}

/// Spawn a task that bridges config watcher reload events to WebSocket broadcasts
/// and performs LLM provider hot-swap when the provider fingerprint changes.
fn spawn_config_watcher_bridge(
    config_watcher: &config::watcher::ConfigWatcher,
    ws_state: &Arc<WsServerState>,
    raw_config: &Value,
    shutdown_rx: &watch::Receiver<bool>,
) {
    let mut config_rx = config_watcher.subscribe();
    let ws_state_for_config = ws_state.clone();
    let mut config_shutdown_rx = shutdown_rx.clone();
    // Track current provider fingerprint for change detection
    let mut current_fingerprint = crate::agent::factory::fingerprint_providers(raw_config);
    tokio::spawn(async move {
        loop {
            tokio::select! {
                event = config_rx.recv() => {
                    match event {
                        Ok(config::watcher::ConfigEvent::Reloaded(result)) => {
                            crate::server::ws::broadcast_config_changed(
                                &ws_state_for_config,
                                &result.mode,
                            );
                            // Hot-swap LLM providers if config changed
                            if let Ok(new_cfg) = config::load_config() {
                                let new_fingerprint =
                                    crate::agent::factory::fingerprint_providers(&new_cfg);
                                if new_fingerprint != current_fingerprint {
                                    info!("LLM provider configuration changed, rebuilding providers");
                                    match crate::agent::factory::build_providers(&new_cfg) {
                                        Ok(Some(mp)) => {
                                            ws_state_for_config
                                                .set_llm_provider(Some(std::sync::Arc::new(mp)));
                                            info!("LLM providers hot-swapped successfully");
                                        }
                                        Ok(None) => {
                                            ws_state_for_config.set_llm_provider(None);
                                            info!("LLM providers removed (none configured)");
                                        }
                                        Err(e) => {
                                            warn!(
                                                "Failed to rebuild LLM providers: {} (keeping previous)",
                                                e
                                            );
                                            // Don't update fingerprint on failure
                                            continue;
                                        }
                                    }
                                    current_fingerprint = new_fingerprint;
                                }
                            }
                        }
                        Ok(config::watcher::ConfigEvent::ReloadFailed(_)) => {}
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                            warn!("Config event receiver lagged by {} events", n);
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                            break;
                        }
                    }
                }
                _ = config_shutdown_rx.changed() => {
                    if *config_shutdown_rx.borrow() {
                        break;
                    }
                }
            }
        }
    });
}

/// Start a non-TLS server from a fully-assembled [`ServerConfig`].
///
/// Returns a [`ServerHandle`] that exposes the actual bound address and
/// provides a [`ServerHandle::shutdown`] method for clean teardown.
pub async fn run_server_with_config(
    config: ServerConfig,
) -> Result<ServerHandle, Box<dyn std::error::Error>> {
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    // Build HTTP router
    let http_router = crate::server::http::create_router_with_state(
        config.http_config,
        config.middleware_config,
        config.hook_registry,
        config.tools_registry,
        config.ws_state.channel_registry().clone(),
        Some(config.ws_state.clone()),
        false,
    );

    // Build WS router and merge
    let ws_router = Router::new()
        .route("/ws", get(crate::server::ws::ws_handler))
        .with_state(config.ws_state.clone());

    let app = http_router.merge(ws_router);

    // Optionally spawn background tasks
    if config.spawn_background_tasks {
        spawn_background_tasks(&config.ws_state, &config.raw_config, &shutdown_rx);
    }

    // Bind TCP listener (supports port 0 for ephemeral port assignment)
    let listener = tokio::net::TcpListener::bind(config.bind_address).await?;
    let local_addr = listener.local_addr()?;

    // Spawn axum::serve as a background tokio task with graceful shutdown
    let mut shutdown_watch = shutdown_rx.clone();
    let server_task = tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(async move {
            // Wait until the shutdown channel is set to true
            loop {
                if *shutdown_watch.borrow() {
                    break;
                }
                if shutdown_watch.changed().await.is_err() {
                    break;
                }
            }
        })
        .await
    });

    Ok(ServerHandle {
        local_addr,
        shutdown_tx,
        ws_state: config.ws_state,
        server_task,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cron::CronPayload;
    use crate::plugins::tools::ToolsRegistry;
    use crate::plugins::{BindingError, ServicePluginInstance};
    use crate::server::ws::WsServerConfig;
    use crate::test_support::env::ScopedEnv;
    use serde_json::json;
    use sha2::{Digest, Sha256};
    use std::ffi::OsString;
    use std::path::Path;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{LazyLock, Mutex, MutexGuard};

    static TEST_ENV_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

    struct EnvVarGuard {
        key: &'static str,
        prev: Option<OsString>,
        _lock: MutexGuard<'static, ()>,
    }

    impl EnvVarGuard {
        fn set(key: &'static str, value: &std::ffi::OsStr) -> Self {
            let lock = TEST_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            let prev = std::env::var_os(key);
            // SAFETY: env mutation in this test module is serialized by TEST_ENV_LOCK.
            unsafe { std::env::set_var(key, value) };
            Self {
                key,
                prev,
                _lock: lock,
            }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            match &self.prev {
                // SAFETY: restoring test-scoped env var state.
                Some(value) => unsafe { std::env::set_var(self.key, value) },
                // SAFETY: restoring test-scoped env var state.
                None => unsafe { std::env::remove_var(self.key) },
            }
        }
    }

    fn runtime_task_executor_with_temp_state(
    ) -> (tempfile::TempDir, EnvVarGuard, RuntimeTaskExecutor) {
        let temp = tempfile::tempdir().expect("create temp dir");
        let state_dir = temp.path().join("state");
        let guard = EnvVarGuard::set("CARAPACE_STATE_DIR", state_dir.as_os_str());
        let state = Arc::new(WsServerState::new(WsServerConfig::default()));
        let executor = RuntimeTaskExecutor { state };
        (temp, guard, executor)
    }

    fn durable_task_with_payload(payload: serde_json::Value, attempts: u32) -> DurableTask {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        DurableTask {
            id: "task-1".to_string(),
            state: crate::tasks::TaskState::Queued,
            attempts,
            next_run_at_ms: None,
            last_error: None,
            payload,
            created_at_ms: now_ms,
            updated_at_ms: now_ms,
            run_ids: Vec::new(),
            policy: crate::tasks::TaskPolicy::default(),
            blocked_reason: None,
            policy_explicit: true,
        }
    }

    fn durable_task_with_policy(
        payload: serde_json::Value,
        attempts: u32,
        policy: crate::tasks::TaskPolicy,
    ) -> DurableTask {
        let mut task = durable_task_with_payload(payload, attempts);
        task.policy = policy;
        task
    }

    fn minimal_wasm_bytes() -> Vec<u8> {
        vec![0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00]
    }

    fn sha256_hex(bytes: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        hex::encode(hasher.finalize())
    }

    fn write_minimal_wasm(dir: &Path, name: &str) -> PathBuf {
        let path = dir.join(format!("{name}.wasm"));
        std::fs::create_dir_all(dir).expect("create wasm dir");
        std::fs::write(&path, minimal_wasm_bytes()).expect("write wasm");
        path
    }

    struct MockServicePlugin {
        stop_calls: AtomicUsize,
        fail_stop: bool,
    }

    impl MockServicePlugin {
        fn new(fail_stop: bool) -> Self {
            Self {
                stop_calls: AtomicUsize::new(0),
                fail_stop,
            }
        }
    }

    impl ServicePluginInstance for MockServicePlugin {
        fn start(&self) -> Result<(), BindingError> {
            Ok(())
        }

        fn stop(&self) -> Result<(), BindingError> {
            self.stop_calls.fetch_add(1, Ordering::SeqCst);
            if self.fail_stop {
                Err(BindingError::CallError("stop failed".to_string()))
            } else {
                Ok(())
            }
        }

        fn health(&self) -> Result<bool, BindingError> {
            Ok(true)
        }
    }

    #[tokio::test]
    async fn runtime_task_executor_retries_when_provider_missing() {
        let (_temp, _state_dir_guard, executor) = runtime_task_executor_with_temp_state();
        let payload = serde_json::to_value(CronPayload::AgentTurn {
            message: "hello".to_string(),
            model: None,
            thinking: None,
            timeout_seconds: None,
            allow_unsafe_external_content: None,
            deliver: None,
            channel: None,
            to: None,
            best_effort_deliver: None,
        })
        .expect("payload serializes");

        let outcome = executor
            .execute(durable_task_with_payload(payload, 1))
            .await;
        assert_eq!(
            outcome,
            TaskExecutionOutcome::RetryWait {
                delay_ms: NO_PROVIDER_RETRY_DELAY_MS,
                error: crate::cron::executor::NO_LLM_PROVIDER_CONFIGURED_ERROR.to_string(),
            }
        );
    }

    #[tokio::test]
    async fn runtime_task_executor_blocks_when_policy_max_attempts_reached() {
        let (_temp, _state_dir_guard, executor) = runtime_task_executor_with_temp_state();
        let payload = serde_json::to_value(CronPayload::AgentTurn {
            message: "hello".to_string(),
            model: None,
            thinking: None,
            timeout_seconds: None,
            allow_unsafe_external_content: None,
            deliver: None,
            channel: None,
            to: None,
            best_effort_deliver: None,
        })
        .expect("payload serializes");

        let outcome = executor
            .execute(durable_task_with_payload(
                payload,
                crate::tasks::TaskPolicy::default().max_attempts,
            ))
            .await;
        assert_eq!(
            outcome,
            TaskExecutionOutcome::Blocked {
                category: TaskBlockedReason::ConfigMissing,
                reason: format!(
                    "{} (retry limit reached: {})",
                    crate::cron::executor::NO_LLM_PROVIDER_CONFIGURED_ERROR,
                    crate::tasks::TaskPolicy::default().max_attempts
                ),
            }
        );
    }

    #[tokio::test]
    async fn runtime_task_executor_rejects_attempts_over_policy_budget() {
        let (_temp, _state_dir_guard, executor) = runtime_task_executor_with_temp_state();
        let policy = crate::tasks::TaskPolicy {
            max_attempts: 1,
            ..Default::default()
        };
        let payload = serde_json::to_value(CronPayload::SystemEvent {
            text: "hello".to_string(),
        })
        .expect("payload serializes");

        let outcome = executor
            .execute(durable_task_with_policy(payload, 2, policy))
            .await;
        assert_eq!(
            outcome,
            TaskExecutionOutcome::Failed {
                error: "objective policy violation: attempts 2 exceeded maxAttempts 1".to_string(),
            }
        );
    }

    #[tokio::test]
    async fn runtime_task_executor_rejects_task_age_over_policy_budget() {
        let (_temp, _state_dir_guard, executor) = runtime_task_executor_with_temp_state();
        let policy = crate::tasks::TaskPolicy {
            max_total_runtime_ms: 1,
            ..Default::default()
        };
        let payload = serde_json::to_value(CronPayload::SystemEvent {
            text: "hello".to_string(),
        })
        .expect("payload serializes");
        let mut task = durable_task_with_policy(payload, 1, policy);
        task.created_at_ms = 0;

        let outcome = executor.execute(task).await;
        assert!(matches!(
            outcome,
            TaskExecutionOutcome::Failed { error }
            if error.contains("objective policy violation: task age")
                && error.contains("exceeded maxTotalRuntimeMs 1")
        ));
    }

    #[tokio::test]
    async fn runtime_task_executor_rejects_run_timeout_over_policy_budget() {
        let (_temp, _state_dir_guard, executor) = runtime_task_executor_with_temp_state();
        let policy = crate::tasks::TaskPolicy {
            max_run_timeout_seconds: 10,
            ..Default::default()
        };
        let payload = serde_json::to_value(CronPayload::AgentTurn {
            message: "hello".to_string(),
            model: None,
            thinking: None,
            timeout_seconds: Some(30),
            allow_unsafe_external_content: None,
            deliver: None,
            channel: None,
            to: None,
            best_effort_deliver: None,
        })
        .expect("payload serializes");

        let outcome = executor
            .execute(durable_task_with_policy(payload, 1, policy))
            .await;
        assert_eq!(
            outcome,
            TaskExecutionOutcome::Failed {
                error:
                    "objective policy violation: timeoutSeconds 30 exceeds maxRunTimeoutSeconds 10"
                        .to_string(),
            }
        );
    }

    #[tokio::test]
    async fn runtime_task_executor_preserves_legacy_task_behavior_for_old_age() {
        let (_temp, _state_dir_guard, executor) = runtime_task_executor_with_temp_state();
        let payload = serde_json::to_value(CronPayload::SystemEvent {
            text: "hello".to_string(),
        })
        .expect("payload serializes");
        let mut task = durable_task_with_payload(payload, 1);
        task.policy_explicit = false;
        task.created_at_ms = 0;

        let outcome = executor.execute(task).await;
        assert_eq!(outcome, TaskExecutionOutcome::Done { run_id: None });
    }

    #[tokio::test]
    async fn runtime_task_executor_preserves_legacy_task_behavior_for_attempt_budget() {
        let (_temp, _state_dir_guard, executor) = runtime_task_executor_with_temp_state();
        let payload = serde_json::to_value(CronPayload::SystemEvent {
            text: "hello".to_string(),
        })
        .expect("payload serializes");
        let mut task =
            durable_task_with_payload(payload, crate::tasks::DEFAULT_TASK_MAX_ATTEMPTS + 1);
        task.policy_explicit = false;

        let outcome = executor.execute(task).await;
        assert_eq!(outcome, TaskExecutionOutcome::Done { run_id: None });
    }

    #[tokio::test]
    async fn runtime_task_executor_legacy_provider_missing_retries_below_legacy_limit() {
        let (_temp, _state_dir_guard, executor) = runtime_task_executor_with_temp_state();
        let payload = serde_json::to_value(CronPayload::AgentTurn {
            message: "hello".to_string(),
            model: None,
            thinking: None,
            timeout_seconds: None,
            allow_unsafe_external_content: None,
            deliver: None,
            channel: None,
            to: None,
            best_effort_deliver: None,
        })
        .expect("payload serializes");
        let mut task =
            durable_task_with_payload(payload, NO_PROVIDER_LEGACY_MAX_RETRY_ATTEMPTS - 1);
        task.policy_explicit = false;

        let outcome = executor.execute(task).await;
        assert_eq!(
            outcome,
            TaskExecutionOutcome::RetryWait {
                delay_ms: NO_PROVIDER_RETRY_DELAY_MS,
                error: crate::cron::executor::NO_LLM_PROVIDER_CONFIGURED_ERROR.to_string(),
            }
        );
    }

    #[tokio::test]
    async fn runtime_task_executor_legacy_provider_missing_blocks_at_legacy_limit() {
        let (_temp, _state_dir_guard, executor) = runtime_task_executor_with_temp_state();
        let payload = serde_json::to_value(CronPayload::AgentTurn {
            message: "hello".to_string(),
            model: None,
            thinking: None,
            timeout_seconds: None,
            allow_unsafe_external_content: None,
            deliver: None,
            channel: None,
            to: None,
            best_effort_deliver: None,
        })
        .expect("payload serializes");
        let mut task = durable_task_with_payload(payload, NO_PROVIDER_LEGACY_MAX_RETRY_ATTEMPTS);
        task.policy_explicit = false;

        let outcome = executor.execute(task).await;
        assert_eq!(
            outcome,
            TaskExecutionOutcome::Blocked {
                category: TaskBlockedReason::ConfigMissing,
                reason: format!(
                    "{} (retry limit reached: {})",
                    crate::cron::executor::NO_LLM_PROVIDER_CONFIGURED_ERROR,
                    NO_PROVIDER_LEGACY_MAX_RETRY_ATTEMPTS
                ),
            }
        );
    }

    #[tokio::test]
    async fn bootstrap_plugin_runtime_respects_plugins_enabled_false() {
        let temp = tempfile::tempdir().expect("temp dir");
        let cfg = json!({
            "plugins": { "enabled": false, "load": { "paths": [temp.path().join("dev").to_string_lossy()] } },
            "skills": {
                "entries": {
                    "alpha": {
                        "enabled": true,
                        "installId": "install-alpha",
                        "requestedAt": 1700000000000u64
                    },
                    "beta": {
                        "enabled": false
                    }
                }
            }
        });

        let result = bootstrap_plugin_runtime(&cfg, temp.path()).await;
        let report = result.activation_report;

        assert!(!report.enabled);
        assert_eq!(report.entries.len(), 2);
        let alpha = report
            .entries
            .iter()
            .find(|entry| entry.name == "alpha")
            .expect("alpha entry");
        assert_eq!(alpha.source, PluginActivationSource::Managed);
        assert_eq!(alpha.state, PluginActivationState::Ignored);
        assert_eq!(
            alpha.reason.as_deref(),
            Some("plugin loading is disabled by plugins.enabled=false")
        );

        let beta = report
            .entries
            .iter()
            .find(|entry| entry.name == "beta")
            .expect("beta entry");
        assert_eq!(beta.state, PluginActivationState::Disabled);
        assert_eq!(
            beta.reason.as_deref(),
            Some("plugin loading is disabled by plugins.enabled=false")
        );
    }

    #[tokio::test]
    async fn bootstrap_plugin_runtime_reports_missing_manifest_for_managed_skill() {
        let temp = tempfile::tempdir().expect("temp dir");
        let cfg = json!({
            "skills": {
                "entries": {
                    "alpha": { "enabled": true }
                }
            }
        });

        let result = bootstrap_plugin_runtime(&cfg, temp.path()).await;
        let report = result.activation_report;

        assert_eq!(report.entries.len(), 1);
        let alpha = &report.entries[0];
        assert_eq!(alpha.name, "alpha");
        assert_eq!(alpha.state, PluginActivationState::Failed);
        assert_eq!(
            alpha.reason.as_deref(),
            Some("missing manifest entry in skills-manifest.json")
        );
    }

    #[tokio::test]
    async fn bootstrap_plugin_runtime_reports_invalid_manifest_parse_error() {
        let temp = tempfile::tempdir().expect("temp dir");
        let managed_dir = temp.path().join("skills");
        std::fs::create_dir_all(&managed_dir).expect("create managed dir");
        std::fs::write(managed_dir.join("skills-manifest.json"), "{invalid-json").unwrap();
        let cfg = json!({
            "skills": {
                "entries": {
                    "alpha": { "enabled": true }
                }
            }
        });

        let result = bootstrap_plugin_runtime(&cfg, temp.path()).await;
        let report = result.activation_report;

        assert_eq!(report.entries.len(), 1);
        assert_eq!(report.errors.len(), 1);
        assert!(report.errors[0].contains("failed to parse"));
        let alpha = &report.entries[0];
        assert_eq!(alpha.state, PluginActivationState::Failed);
        assert_eq!(
            alpha.reason.as_deref(),
            Some("managed skills manifest is invalid; fix skills-manifest.json and restart")
        );
    }

    #[tokio::test]
    async fn bootstrap_plugin_runtime_ignores_stray_managed_wasm_files() {
        let temp = tempfile::tempdir().expect("temp dir");
        write_minimal_wasm(&temp.path().join("skills"), "rogue");

        let result = bootstrap_plugin_runtime(&json!({}), temp.path()).await;
        let report = result.activation_report;

        assert_eq!(report.entries.len(), 1);
        let entry = &report.entries[0];
        assert_eq!(entry.name, "rogue");
        assert_eq!(entry.source, PluginActivationSource::Managed);
        assert_eq!(entry.state, PluginActivationState::Ignored);
        assert!(entry
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("not declared in skills.entries")));
    }

    #[tokio::test]
    async fn bootstrap_plugin_runtime_reports_config_path_read_errors() {
        let temp = tempfile::tempdir().expect("temp dir");
        let missing = temp.path().join("missing-plugins");
        let cfg = json!({
            "plugins": {
                "load": {
                    "paths": [missing.to_string_lossy().to_string()]
                }
            }
        });

        let result = bootstrap_plugin_runtime(&cfg, temp.path()).await;
        let report = result.activation_report;

        assert_eq!(report.entries.len(), 0);
        assert_eq!(report.errors.len(), 1);
        assert!(report.errors[0].contains("failed to read configured plugin path"));
    }

    #[tokio::test]
    async fn bootstrap_plugin_runtime_skips_unpinned_managed_manifest_entries() {
        let temp = tempfile::tempdir().expect("temp dir");
        let managed_dir = temp.path().join("skills");
        write_minimal_wasm(&managed_dir, "alpha");
        std::fs::write(
            managed_dir.join("skills-manifest.json"),
            json!({
                "alpha": {
                    "path": managed_dir.join("alpha.wasm").to_string_lossy().to_string()
                }
            })
            .to_string(),
        )
        .expect("write manifest");
        let cfg = json!({
            "skills": {
                "entries": {
                    "alpha": { "enabled": true }
                }
            }
        });

        let result = bootstrap_plugin_runtime(&cfg, temp.path()).await;
        let report = result.activation_report;

        assert_eq!(report.entries.len(), 1);
        let entry = &report.entries[0];
        assert_eq!(entry.name, "alpha");
        assert_eq!(entry.state, PluginActivationState::Failed);
        assert_eq!(
            entry.reason.as_deref(),
            Some("managed skill is missing a pinned sha256 in skills-manifest.json")
        );
    }

    #[tokio::test]
    async fn bootstrap_plugin_runtime_rejects_managed_paths_outside_managed_dir() {
        let temp = tempfile::tempdir().expect("temp dir");
        let managed_dir = temp.path().join("skills");
        let outside_dir = temp.path().join("outside");
        let outside_path = write_minimal_wasm(&outside_dir, "alpha");
        std::fs::create_dir_all(&managed_dir).expect("create managed dir");
        std::fs::write(
            managed_dir.join("skills-manifest.json"),
            json!({
                "alpha": {
                    "path": outside_path.to_string_lossy().to_string(),
                    "sha256": sha256_hex(&minimal_wasm_bytes())
                }
            })
            .to_string(),
        )
        .expect("write manifest");
        let cfg = json!({
            "skills": {
                "entries": {
                    "alpha": { "enabled": true }
                }
            }
        });

        let result = bootstrap_plugin_runtime(&cfg, temp.path()).await;
        let report = result.activation_report;

        assert_eq!(report.entries.len(), 1);
        let entry = &report.entries[0];
        assert_eq!(entry.name, "alpha");
        assert_eq!(entry.state, PluginActivationState::Failed);
        assert!(entry
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("escapes")));
    }

    #[test]
    fn load_plugin_candidate_reports_duplicate_plugin_ids_across_sources() {
        let temp = tempfile::tempdir().expect("temp dir");
        let managed_dir = temp.path().join("skills");
        let config_dir = temp.path().join("config-plugins");
        let managed_bytes = minimal_wasm_bytes();
        let managed_path = write_minimal_wasm(&managed_dir, "alpha");
        let config_path = write_minimal_wasm(&config_dir, "alpha");
        std::fs::write(
            managed_dir.join("skills-manifest.json"),
            json!({
                "alpha": {
                    "path": managed_path.to_string_lossy().to_string(),
                    "sha256": sha256_hex(&managed_bytes)
                }
            })
            .to_string(),
        )
        .expect("write manifest");

        let loader = crate::plugins::PluginLoader::with_signature_config(
            managed_dir.clone(),
            crate::plugins::signature::SignatureConfig {
                enabled: false,
                require_signature: false,
                trusted_publishers: Vec::new(),
            },
        )
        .expect("create plugin loader");
        let mut report = PluginActivationReport::empty(managed_dir, vec![config_dir], true);
        let mut report_index_by_plugin_id = HashMap::new();

        load_plugin_candidate(
            &loader,
            &mut report,
            PluginActivationEntry {
                name: "alpha".to_string(),
                plugin_id: None,
                source: PluginActivationSource::Managed,
                enabled: true,
                path: None,
                requested_at: None,
                install_id: None,
                state: PluginActivationState::Ignored,
                reason: None,
            },
            &managed_path,
            &mut report_index_by_plugin_id,
        );
        load_plugin_candidate(
            &loader,
            &mut report,
            PluginActivationEntry {
                name: "alpha".to_string(),
                plugin_id: None,
                source: PluginActivationSource::ConfigPath,
                enabled: true,
                path: None,
                requested_at: None,
                install_id: None,
                state: PluginActivationState::Ignored,
                reason: None,
            },
            &config_path,
            &mut report_index_by_plugin_id,
        );

        let duplicate = report
            .entries
            .iter()
            .find(|entry| entry.source == PluginActivationSource::ConfigPath)
            .expect("config-path entry");
        assert_eq!(duplicate.name, "alpha");
        assert_eq!(duplicate.plugin_id.as_deref(), Some("alpha"));
        assert_eq!(duplicate.state, PluginActivationState::Failed);
        assert!(duplicate
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("plugin ID conflict")));
    }

    #[tokio::test]
    async fn build_ws_state_with_runtime_dependencies_attaches_plugin_activation_report() {
        let temp = tempfile::tempdir().expect("temp dir");
        let state_dir = temp.path().join("state");
        let config_path = temp.path().join("carapace.json5");
        let mut env = ScopedEnv::new();
        env.set("CARAPACE_STATE_DIR", state_dir.as_os_str())
            .set("CARAPACE_CONFIG_PATH", config_path.as_os_str())
            .set("CARAPACE_DISABLE_CONFIG_CACHE", "1");
        crate::config::clear_cache();

        let tools_registry = Arc::new(ToolsRegistry::new());
        let ws_state =
            build_ws_state_with_runtime_dependencies(&json!({}), &state_dir, tools_registry)
                .await
                .expect("build ws state");

        let report = ws_state
            .plugin_activation_report()
            .expect("plugin activation report");
        assert_eq!(report.managed_dir, state_dir.join("skills"));
        assert!(report.entries.is_empty());

        crate::config::clear_cache();
    }

    #[test]
    fn stop_plugin_services_stops_all_services_and_ignores_stop_errors() {
        let ok_service = Arc::new(MockServicePlugin::new(false));
        let failing_service = Arc::new(MockServicePlugin::new(true));
        let registry = Arc::new(PluginRegistry::new());
        registry.register_service("ok".to_string(), ok_service.clone());
        registry.register_service("failing".to_string(), failing_service.clone());
        let state = WsServerState::new(WsServerConfig::default()).with_plugin_registry(registry);

        stop_plugin_services(&state);

        assert_eq!(ok_service.stop_calls.load(Ordering::SeqCst), 1);
        assert_eq!(failing_service.stop_calls.load(Ordering::SeqCst), 1);
    }
}
