//! Testable server startup logic.
//!
//! Provides [`ServerConfig`] and [`ServerHandle`] to allow integration tests
//! to spin up a real (non-TLS) Carapace server on an ephemeral port, exercise
//! its HTTP and WebSocket endpoints, and shut it down cleanly.

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
use crate::cron;
use crate::hooks::registry::HookRegistry;
use crate::messages;
use crate::plugins::tools::ToolsRegistry;
use crate::server::http::{HttpConfig, MiddlewareConfig};
use crate::server::plugin_bootstrap::{bootstrap_plugin_runtime, stop_plugin_services};
use crate::server::ws::WsServerState;
use crate::sessions;
use crate::tasks::{DurableTask, TaskBlockedReason, TaskExecutionOutcome, TaskExecutor};

struct RuntimeTaskExecutor {
    state: Arc<WsServerState>,
}

const NO_PROVIDER_RETRY_DELAY_MS: u64 = 60_000;
const NO_PROVIDER_EXISTING_TASK_MAX_RETRY_ATTEMPTS: u32 = 3_600;

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
                    && task.attempts >= NO_PROVIDER_EXISTING_TASK_MAX_RETRY_ATTEMPTS
                {
                    TaskExecutionOutcome::Blocked {
                        category: TaskBlockedReason::ConfigMissing,
                        reason: format!(
                            "{} (retry limit reached: {})",
                            crate::cron::executor::NO_LLM_PROVIDER_CONFIGURED_ERROR,
                            NO_PROVIDER_EXISTING_TASK_MAX_RETRY_ATTEMPTS
                        ),
                    }
                } else {
                    TaskExecutionOutcome::RetryWait {
                        delay_ms: NO_PROVIDER_RETRY_DELAY_MS,
                        error: crate::cron::executor::NO_LLM_PROVIDER_CONFIGURED_ERROR.to_string(),
                    }
                }
            }
            Err(crate::cron::executor::CronExecuteError::Configuration(error)) => {
                TaskExecutionOutcome::Blocked {
                    category: TaskBlockedReason::ConfigMissing,
                    reason: error.to_string(),
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
    /// Runtime state directory used for native stateful channel runtimes.
    ///
    /// `None` means the caller has already registered stateful channels or
    /// intentionally wants to skip them, as tests often do.
    pub state_dir: Option<PathBuf>,
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
            state_dir: None,
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
            return Err(
                "No LLM provider configured. Configure at least one supported \
                 provider before starting Carapace — examples include setting \
                 ANTHROPIC_API_KEY, OPENAI_API_KEY, GOOGLE_API_KEY, or VENICE_API_KEY; \
                 configuring Ollama; configuring an authProfile (anthropic.authProfile, \
                 google.authProfile, codex.authProfile); or configuring AWS Bedrock \
                 (AWS_REGION + credentials), Vertex AI (VERTEX_PROJECT_ID), or the \
                 Claude CLI provider. Other supported provider configurations may \
                 also be valid; see the project documentation for the full list."
                    .into(),
            );
        }
    };

    let plugin_bootstrap = bootstrap_plugin_runtime(cfg, state_dir).await?;
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
    tokio::fs::create_dir_all(state_dir.join("activity")).await?;
    crate::logging::audit::AuditLog::init(state_dir.clone()).await;
    init_media_store_cleanup().await;
    Ok(state_dir)
}

/// Optionally register the Matrix channel runtime if configured.
pub fn register_matrix_channel_if_configured(
    ws_state: Arc<WsServerState>,
    cfg: &Value,
    state_dir: &Path,
    shutdown_rx: &watch::Receiver<bool>,
) -> Result<Arc<WsServerState>, Box<dyn std::error::Error>> {
    let matrix_config = match crate::channels::matrix::resolve_matrix_config(cfg) {
        Ok(crate::channels::matrix::MatrixConfigResolve::Configured(config)) => config,
        Ok(
            crate::channels::matrix::MatrixConfigResolve::Disabled
            | crate::channels::matrix::MatrixConfigResolve::Missing,
        ) => {
            return Ok(ws_state);
        }
        Err(err) => return Err(Box::new(err)),
    };

    let runtime = crate::channels::matrix::spawn_matrix_runtime(
        matrix_config,
        state_dir.to_path_buf(),
        ws_state.clone(),
        ws_state.channel_registry().clone(),
        shutdown_rx.clone(),
    );

    if let Some(registry) = ws_state.plugin_registry() {
        registry.register_channel(
            crate::channels::matrix::MATRIX_CHANNEL_ID.to_string(),
            Arc::new(runtime.channel()),
        );
    }

    ws_state.set_matrix_runtime(Some(runtime));
    info!("Matrix channel registered");
    Ok(ws_state)
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
///
/// `ServerHandle` carries the [`DaemonPidGuard`] for the daemon's
/// lifetime so embedded gateways (`cara chat`, `cara verify --outcome
/// matrix`) ALSO hold the Matrix rekey lock — closing the round-23
/// hole where embedded paths bypassed the lock entirely. The TLS
/// launch path that uses `axum_server::bind_rustls` directly
/// (instead of `run_server_with_config`) must install its own guard
/// separately; see `launch_tls_server` in `main.rs`.
pub struct ServerHandle {
    local_addr: SocketAddr,
    shutdown_tx: watch::Sender<bool>,
    ws_state: Arc<WsServerState>,
    server_task: JoinHandle<Result<(), std::io::Error>>,
    // Held alongside `server_task` for the daemon's full lifetime.
    // Drops on `ServerHandle::shutdown` (which moves `self`) — after
    // the server task is awaited, before the function returns.
    _daemon_pid_guard: Option<DaemonPidGuard>,
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

        self.ws_state.shutdown_matrix_runtime().await;

        // Flush dirty sessions
        if let Err(e) = self.ws_state.session_store().flush_all() {
            error!("Failed to flush session store during shutdown: {}", e);
        }

        stop_plugin_services(&self.ws_state);

        // Brief grace period for in-flight operations
        tokio::time::sleep(Duration::from_millis(100)).await;

        self.ws_state.shutdown_activity_service().await;

        // Wait for the server task to finish. If the graceful timeout
        // fires we abort and re-await with a short bounded wait —
        // dropping the JoinHandle does NOT cancel the task, so without
        // the abort the server could keep running after the function
        // returns and `_daemon_pid_guard` releases, briefly racing a
        // freshly-started daemon for the Matrix rekey lock.
        let mut server_task = self.server_task;
        match tokio::time::timeout(Duration::from_secs(5), &mut server_task).await {
            Ok(Ok(Ok(()))) => {}
            Ok(Ok(Err(e))) => error!("Server task returned error: {}", e),
            Ok(Err(e)) => error!("Server task panicked: {}", e),
            Err(_) => {
                warn!("Server task did not finish within 5s timeout; aborting");
                server_task.abort();
                if tokio::time::timeout(Duration::from_secs(2), &mut server_task)
                    .await
                    .is_err()
                {
                    error!("Server task did not honor abort within 2s — leaking");
                }
            }
        }
    }
}

/// Spawn the SIGHUP handler that triggers config reload on Unix systems.
///
/// The handler loads the payload via `perform_reload_async` and forwards
/// it as a `ConfigEvent`; the hot-reload bridge owns the cache install and
/// the WS broadcast on validation success, so SIGHUP no longer touches the
/// cache or the WS broadcast directly.
#[cfg(unix)]
fn spawn_sighup_handler(
    config_watcher: &config::watcher::ConfigWatcher,
    shutdown_rx: &watch::Receiver<bool>,
) {
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
                    let mode = config::watcher::manual_reload_mode();
                    // perform_reload_async loads the payload but doesn't install
                    // it — the bridge owns cache install + WS broadcast after
                    // provider validation. SIGHUP just routes the event.
                    let event = config::watcher::perform_reload_async(&mode).await;
                    let _ = config_event_tx.send(event);
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
    ws_state
        .activity_service()
        .spawn_read_receipt_worker(ws_state.clone(), shutdown_rx.clone());

    // One-shot updater resume pass for interrupted updates.
    spawn_update_resume_task(shutdown_rx);

    // Delivery loop
    if let Some(plugin_reg) = ws_state.plugin_registry().cloned() {
        let pipeline = ws_state.message_pipeline().clone();
        let channels = ws_state.channel_registry().clone();
        let rx = shutdown_rx.clone();
        tokio::spawn(messages::delivery::delivery_loop(
            pipeline, plugin_reg, channels, rx,
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
    spawn_activity_feature_support_warnings(ws_state, shutdown_rx);

    // SIGHUP handler for manual config reload (Unix only)
    #[cfg(unix)]
    spawn_sighup_handler(&config_watcher, shutdown_rx);

    // Resource monitor and session retention cleanup
    spawn_monitoring_and_retention(ws_state, raw_config, shutdown_rx);
}

fn spawn_activity_feature_support_warnings(
    ws_state: &Arc<WsServerState>,
    shutdown_rx: &watch::Receiver<bool>,
) {
    let Some(plugin_registry) = ws_state.plugin_registry().cloned() else {
        return;
    };
    let activity_service = ws_state.activity_service().clone();
    let mut config_rx = crate::config::subscribe_config_changes();
    config_rx.borrow_and_update();
    let mut shutdown_rx = shutdown_rx.clone();
    tokio::spawn(async move {
        activity_service
            .warn_configured_unsupported_features_for_registered_channels(plugin_registry.clone())
            .await;

        loop {
            tokio::select! {
                changed = config_rx.changed() => {
                    if changed.is_err() {
                        break;
                    }
                    activity_service
                        .warn_configured_unsupported_features_for_registered_channels(
                            plugin_registry.clone(),
                        )
                        .await;
                }
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        break;
                    }
                }
            }
        }
    });
}

/// Cross-event state for env-rollback and provider-fingerprint comparison.
struct ReloadState {
    /// Pre-load env snapshot used to revert `CONFIG_ENV_STATE` on a rejected
    /// reload (the loader injects `${VAR}` env before later validation can
    /// fail).
    last_good_env: config::InjectedConfigEnvState,
    /// Fingerprint of the currently-installed provider; short-circuits
    /// `build_providers` when the new config doesn't change provider shape.
    current_fingerprint: crate::agent::factory::ProviderFingerprint,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReloadOutcome {
    /// New config validated and installed in the cache. Broadcast to
    /// downstream subscribers.
    Apply,
    /// Reload rejected; cache was never written, env restored to last good.
    /// Suppress the downstream broadcast.
    Reverted,
}

/// A command sent to the hot-reload bridge requesting a manual reload.
///
/// Used by callers that need a synchronous response (notably the WS
/// `config.reload` admin RPC). Fire-and-forget callers (file watcher,
/// SIGHUP) use the broadcast `ConfigEvent` channel instead.
///
/// The bridge does the load itself when handling the command — the caller
/// does not pre-load — so the validated payload is always against current
/// on-disk state, avoiding a TOCTOU between the WS handler's load and the
/// bridge's processing.
pub(crate) struct ReloadCommand {
    /// Reload mode requested by the caller; converted to a label only when
    /// the bridge fires `broadcast_config_changed` on `Apply`.
    pub mode: config::watcher::ReloadMode,
    /// One-shot channel the bridge uses to report back the outcome.
    pub respond_to: tokio::sync::oneshot::Sender<ReloadCommandResult>,
}

/// Mode label for a `config.changed` broadcast emitted from the
/// lag-recovery path (no `ReloadMode` corresponds — the bridge converged
/// to disk after dropping events).
const LAG_RECOVERY_MODE_LABEL: &str = "lag-recovery";

/// Bridge-side result of processing a [`ReloadCommand`].
#[derive(Debug)]
pub(crate) enum ReloadCommandResult {
    /// New config validated and installed; WS broadcast fired. Carries any
    /// non-fatal validation warnings collected during the load so the WS
    /// handler can forward them to the requesting client.
    Applied { warnings: Vec<String> },
    /// Reload rejected on provider validation (no provider, build failure).
    /// Cache and env have been kept at / restored to last good.
    Reverted,
    /// The disk load itself failed (parse error, missing file, etc.).
    LoadError(String),
}

/// Validate `(raw, normalized)` against provider invariants. On `Apply`,
/// install the payload in `CONFIG_CACHE` and refresh `state`'s env snapshot
/// + fingerprint. On `Reverted`, the caller is responsible for env restore.
///
/// Disabled-cache caveat: with `CARAPACE_DISABLE_CONFIG_CACHE=1`, direct
/// disk readers continue to read the operator's bad save until the file is
/// repaired — the warn-log in `revert_pending_env` announces this.
async fn handle_provider_reload(
    ws_state: &Arc<WsServerState>,
    state: &mut ReloadState,
    raw: Arc<Value>,
    normalized: Arc<Value>,
) -> ReloadOutcome {
    let new_fingerprint = crate::agent::factory::fingerprint_providers(&normalized);
    if new_fingerprint == state.current_fingerprint {
        config::update_cache_arc(raw, normalized);
        state.last_good_env = config::snapshot_env_state();
        return ReloadOutcome::Apply;
    }

    info!("LLM provider configuration changed, rebuilding providers");
    // `build_providers` does blocking I/O (auth-profile-store load, key
    // material decryption when CARAPACE_CONFIG_PASSWORD is set, HTTP-client
    // construction). Run it on the blocking pool so the bridge's tokio
    // worker stays free; the unchanged-fingerprint fast path above stays
    // sync and pays no spawn-blocking cost for no-op reloads.
    // `build_providers` returns `Box<dyn std::error::Error>`, which is not
    // `Send`; stringify the error inside the blocking closure so the
    // spawn_blocking output type is Send.
    let normalized_for_build = Arc::clone(&normalized);
    let build_result = tokio::task::spawn_blocking(move || {
        crate::agent::factory::build_providers(&normalized_for_build).map_err(|e| e.to_string())
    })
    .await;
    let mp = match build_result {
        Ok(Ok(Some(mp))) => mp,
        Ok(Ok(None)) => {
            warn!(
                "Reloaded config has no LLM provider; rejecting reload to keep the \
                 previous provider active. Restore a provider config to apply \
                 further changes."
            );
            // current_fingerprint intentionally unchanged: a re-save of the
            // same config retriggers build_providers, letting a transient
            // build error recover on the next attempt.
            revert_pending_env(state);
            return ReloadOutcome::Reverted;
        }
        Ok(Err(message)) => {
            warn!(
                "Failed to rebuild LLM providers: {} (rejecting reload to keep previous provider)",
                message
            );
            revert_pending_env(state);
            return ReloadOutcome::Reverted;
        }
        Err(e) => {
            error!(
                "build_providers blocking task panicked: {} (rejecting reload)",
                e
            );
            revert_pending_env(state);
            return ReloadOutcome::Reverted;
        }
    };
    ws_state.set_llm_provider(Some(Arc::new(mp)));
    info!("LLM providers hot-swapped successfully");
    config::update_cache_arc(raw, normalized);
    state.last_good_env = config::snapshot_env_state();
    state.current_fingerprint = new_fingerprint;
    ReloadOutcome::Apply
}

/// Discard everything currently buffered in the bridge's broadcast receiver.
/// Called after a lag-recovery has already converged the bridge to the
/// latest on-disk state — the still-buffered events are now stale and would
/// cause provider thrashing if replayed.
fn drain_pending_events(rx: &mut tokio::sync::broadcast::Receiver<config::watcher::ConfigEvent>) {
    use tokio::sync::broadcast::error::TryRecvError;
    // Discard buffered events (Ok) and any further lag notifications until
    // we hit Empty or Closed. Empty body — the discard *is* the work.
    while let Ok(_) | Err(TryRecvError::Lagged(_)) = rx.try_recv() {}
}

/// Run a fresh load + provider validation + cache install. Returns the
/// outcome without broadcasting; the caller chooses the broadcast label so
/// the lag-recovery path can label its tick distinctly from a normal reload.
///
/// `perform_reload_async` already handles `spawn_blocking` + JoinError. On
/// `ReloadFailed` the loader may have partially mutated `CONFIG_ENV_STATE`
/// before failing (env injection runs before secrets resolution); we
/// `revert_pending_env` to put env back to last good. The cache itself
/// never moved on a load failure.
async fn dispatch_bridge_reload(
    ws_state: &Arc<WsServerState>,
    state: &mut ReloadState,
    mode: &config::watcher::ReloadMode,
) -> ReloadCommandResult {
    use config::watcher::{perform_reload_async, ConfigEvent};
    match perform_reload_async(mode).await {
        ConfigEvent::Reloaded(success) => {
            let outcome = handle_provider_reload(
                ws_state,
                state,
                success.payload.raw,
                success.payload.normalized,
            )
            .await;
            match outcome {
                ReloadOutcome::Apply => ReloadCommandResult::Applied {
                    warnings: success.warnings,
                },
                ReloadOutcome::Reverted => ReloadCommandResult::Reverted,
            }
        }
        ConfigEvent::ReloadFailed(failure) => {
            revert_pending_env(state);
            ReloadCommandResult::LoadError(failure.error)
        }
    }
}

/// Undo the pending reload's env mutations and warn the operator if direct
/// disk readers are still exposed (cache-disabled mode). The cache itself
/// has nothing to undo: the bridge only writes on `Apply`.
fn revert_pending_env(state: &ReloadState) {
    config::restore_env_state(&state.last_good_env);
    if crate::config::read_process_env("CARAPACE_DISABLE_CONFIG_CACHE").is_some() {
        warn!(
            "Hot-reload rejected with CARAPACE_DISABLE_CONFIG_CACHE=1; \
             on-disk config still reflects the rejected save. Subscribers \
             that re-read from disk on each change notification will see \
             the bad config until the file is repaired."
        );
    }
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
    // `raw_config` is the normalized startup config (parameter name is a
    // historical misnomer) — the server is already running with it, so it's
    // the right fingerprint baseline.
    let current_fingerprint = crate::agent::factory::fingerprint_providers(raw_config);
    let mut reload_state = ReloadState {
        last_good_env: config::snapshot_env_state(),
        current_fingerprint,
    };

    // Command inbox for synchronous reload requests (WS `config.reload`).
    // Capacity 8: enough headroom for an admin reload burst without
    // blocking WS handler threads.
    let (command_tx, mut command_rx) = tokio::sync::mpsc::channel::<ReloadCommand>(8);
    ws_state.set_reload_command_tx(Some(command_tx));

    tokio::spawn(async move {
        loop {
            tokio::select! {
                event = config_rx.recv() => {
                    match event {
                        Ok(config::watcher::ConfigEvent::Reloaded(success)) => {
                            let outcome = handle_provider_reload(
                                &ws_state_for_config,
                                &mut reload_state,
                                success.payload.raw,
                                success.payload.normalized,
                            )
                            .await;
                            match outcome {
                                ReloadOutcome::Apply => {
                                    crate::server::ws::broadcast_config_changed(
                                        &ws_state_for_config,
                                        &success.mode,
                                    );
                                }
                                ReloadOutcome::Reverted => {
                                    // Reload rejected before the cache was
                                    // touched; suppress the WS broadcast so
                                    // clients don't observe a transient
                                    // invalid state.
                                }
                            }
                        }
                        Ok(config::watcher::ConfigEvent::ReloadFailed(_)) => {}
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                            // Buffered events are stale; reload from disk to
                            // converge to current on-disk state, then drain
                            // the buffer so the next recv() blocks on a fresh
                            // event rather than replaying superseded ones.
                            warn!(
                                "Config event receiver lagged by {} events; reloading from disk to converge",
                                n
                            );
                            let outcome = dispatch_bridge_reload(
                                &ws_state_for_config,
                                &mut reload_state,
                                &config::watcher::ReloadMode::Hot,
                            )
                            .await;
                            // Drain the buffered events that prompted the
                            // lag iff the disk recovery actually converged.
                            // On a transient `LoadError` (file being written,
                            // I/O glitch) the buffered events may carry valid
                            // payloads from completed earlier saves; let the
                            // next `recv()` iteration process them in order
                            // so we don't lose state until the next watcher
                            // event.
                            match outcome {
                                ReloadCommandResult::Applied { .. } => {
                                    crate::server::ws::broadcast_config_changed(
                                        &ws_state_for_config,
                                        LAG_RECOVERY_MODE_LABEL,
                                    );
                                    drain_pending_events(&mut config_rx);
                                }
                                ReloadCommandResult::Reverted => {
                                    drain_pending_events(&mut config_rx);
                                }
                                ReloadCommandResult::LoadError(ref e) => {
                                    error!(
                                        "Lag-recovery load failed: {} (keeping buffered events for next iteration)",
                                        e
                                    );
                                }
                            }
                            continue;
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                            break;
                        }
                    }
                }
                Some(command) = command_rx.recv() => {
                    let outcome = dispatch_bridge_reload(
                        &ws_state_for_config,
                        &mut reload_state,
                        &command.mode,
                    )
                    .await;
                    if matches!(outcome, ReloadCommandResult::Applied { .. }) {
                        crate::server::ws::broadcast_config_changed(
                            &ws_state_for_config,
                            config::watcher::mode_label(&command.mode),
                        );
                    }
                    let _ = command.respond_to.send(outcome);
                }
                _ = config_shutdown_rx.changed() => {
                    if *config_shutdown_rx.borrow() {
                        break;
                    }
                }
            }
        }
        // Clear the command sender so callers checking
        // `reload_command_tx().is_some()` as a liveness gate see the
        // bridge as gone rather than stuck-Some with a closed receiver.
        ws_state_for_config.set_reload_command_tx(None);
    });
}

/// Start a non-TLS server from a fully-assembled [`ServerConfig`].
///
/// Returns a [`ServerHandle`] that exposes the actual bound address and
/// provides a [`ServerHandle::shutdown`] method for clean teardown.
pub async fn run_server_with_config(
    config: ServerConfig,
) -> Result<ServerHandle, Box<dyn std::error::Error>> {
    let ServerConfig {
        ws_state,
        http_config,
        middleware_config,
        hook_registry,
        tools_registry,
        bind_address,
        raw_config,
        state_dir,
        spawn_background_tasks: should_spawn_background_tasks,
    } = config;
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    // Install the daemon PID + rekey lock guard inside
    // `run_server_with_config` so every caller (production daemon,
    // embedded `cara chat`, embedded `cara verify --outcome matrix`)
    // contends on the same `state_dir/.matrix-rekey.lock`. Round 22
    // installed only at `main.rs::run_server`, leaving embedded
    // paths free to open Matrix SQLite stores without holding the
    // lock — round 23 found that hole. Tests that pass
    // `state_dir: None` (`ServerConfig::for_testing`) skip the
    // install, matching the prior contract.
    let daemon_pid_guard = state_dir
        .as_deref()
        .map(|dir| DaemonPidGuard::install(dir.to_path_buf()))
        .transpose()?;

    let ws_state = if let Some(state_dir) = state_dir.as_deref() {
        register_matrix_channel_if_configured(ws_state, &raw_config, state_dir, &shutdown_rx)?
    } else {
        ws_state
    };

    // Build HTTP router
    let http_router = crate::server::http::create_router_with_state(
        http_config,
        middleware_config,
        hook_registry,
        tools_registry,
        ws_state.channel_registry().clone(),
        Some(ws_state.clone()),
        false,
    );

    // Build WS router and merge
    let ws_router = Router::new()
        .route("/ws", get(crate::server::ws::ws_handler))
        .with_state(ws_state.clone());

    let app = http_router.merge(ws_router);

    // Optionally spawn background tasks
    if should_spawn_background_tasks {
        spawn_background_tasks(&ws_state, &raw_config, &shutdown_rx);
    }

    // Bind TCP listener (supports port 0 for ephemeral port assignment)
    let listener = tokio::net::TcpListener::bind(bind_address).await?;
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
        ws_state,
        server_task,
        _daemon_pid_guard: daemon_pid_guard,
    })
}

/// Removes the daemon PID file when dropped. Held by the `run_server`
/// caller for the lifetime of the daemon so the file persists across
/// the TLS / non-TLS launch fork and is cleaned up when the server
/// task exits. A daemon panic skips Drop and leaves the file behind
/// — acceptable because the rekey-side `rekey_pid_is_alive` returns
/// false on ESRCH (the process is gone) and unblocks the next rekey.
///
/// Also holds an exclusive flock on `state_dir/.matrix-rekey.lock`
/// for the daemon's lifetime. The Matrix rekey CLI tries to acquire
/// the same lock and fails fast when the daemon holds it — closing
/// the round-21 TOCTOU window where a daemon launched between the
/// CLI's PID-file probe and its first SQLite write would race the
/// rotation and leave stores in a mixed-cipher state. Failure to
/// acquire the lock at startup is fail-closed: a typed error from
/// `install()` rather than a "best-effort" downgrade, because if
/// another carapace process already holds it (typically a
/// previously-launched daemon, possibly a stuck rekey CLI) starting
/// this daemon would create exactly the concurrent-mutation
/// scenario the lock exists to prevent.
pub struct DaemonPidGuard {
    path: PathBuf,
    _rekey_lock: crate::sessions::file_lock::FileLock,
}

impl DaemonPidGuard {
    pub fn install(state_dir: PathBuf) -> Result<Self, Box<dyn std::error::Error>> {
        if let Err(err) = std::fs::create_dir_all(&state_dir) {
            return Err(format!(
                "failed to create state dir for daemon PID file at {}: {err}",
                state_dir.display()
            )
            .into());
        }

        // Acquire the rekey lock first so the failure mode is
        // "another carapace process is here" rather than "we
        // wrote a PID file then errored out". Path matches the
        // CLI side at `cli/mod.rs::matrix_rekey_lock_path`.
        let rekey_lock_path = state_dir.join(".matrix-rekey.lock");
        let rekey_lock = match crate::sessions::file_lock::FileLock::try_acquire(&rekey_lock_path) {
            Ok(Some(lock)) => lock,
            Ok(None) => {
                return Err(format!(
                    "Matrix rekey lock at {} is already held — another carapace daemon is \
                     running, or `cara matrix rekey-store` is in progress. Stop the other \
                     process before launching this daemon to avoid mixed-cipher Matrix \
                     SQLite state.",
                    rekey_lock_path.display()
                )
                .into());
            }
            Err(err) => {
                return Err(format!(
                    "failed to acquire Matrix rekey lock at {}: {err}",
                    rekey_lock_path.display()
                )
                .into());
            }
        };

        let path = state_dir.join("daemon.pid");
        write_daemon_pid_file(&path, std::process::id())?;
        Ok(Self {
            path,
            _rekey_lock: rekey_lock,
        })
    }
}

impl Drop for DaemonPidGuard {
    fn drop(&mut self) {
        // Best-effort: if the file is gone (e.g. operator manually
        // cleared it) treat that as success rather than panicking from
        // Drop.
        if let Err(err) = std::fs::remove_file(&self.path) {
            if err.kind() != std::io::ErrorKind::NotFound {
                tracing::warn!(
                    error = %err,
                    path = %self.path.display(),
                    "failed to remove daemon PID file on shutdown",
                );
            }
        }
    }
}

fn write_daemon_pid_file(path: &Path, pid: u32) -> Result<(), Box<dyn std::error::Error>> {
    use std::io::Write;
    let mut tmp_path = path.to_path_buf();
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("daemon.pid");
    tmp_path.set_file_name(format!("{file_name}.tmp.{}", std::process::id()));

    let mut file = open_daemon_pid_tmp(&tmp_path).map_err(|err| {
        format!(
            "failed to create daemon PID tmp file at {}: {err}",
            tmp_path.display()
        )
    })?;
    file.write_all(format!("{pid}\n").as_bytes())
        .and_then(|_| file.sync_all())
        .map_err(|err| format!("failed to write daemon PID file: {err}"))?;
    drop(file);

    if let Err(err) = std::fs::rename(&tmp_path, path) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(format!(
            "failed to install daemon PID file at {}: {err}",
            path.display()
        )
        .into());
    }
    crate::paths::sync_parent_dir_blocking(path).map_err(|err| {
        format!(
            "failed to fsync parent dir of {} after PID write: {err}",
            path.display()
        )
    })?;
    Ok(())
}

#[cfg(unix)]
fn open_daemon_pid_tmp(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(path)
}

#[cfg(not(unix))]
fn open_daemon_pid_tmp(path: &Path) -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cron::CronPayload;
    use crate::plugins::signature::sign_wasm_bytes;
    use crate::plugins::tools::ToolsRegistry;
    use crate::plugins::{BindingError, PluginKind, PluginRegistry, ServicePluginInstance};
    use crate::server::plugin_bootstrap::{
        bootstrap_plugin_runtime, load_plugin_candidate, start_plugin_services,
        stop_plugin_services, PluginActivationEntry, PluginActivationReport,
        PluginActivationSource, PluginActivationState, TEST_FORCE_PLUGIN_ENGINE_INIT_FAILURE_ENV,
    };
    use crate::server::ws::WsServerConfig;
    use crate::test_support::{env::ScopedEnv, plugins::tool_plugin_component_bytes};
    use ed25519_dalek::SigningKey;
    use serde_json::json;
    use sha2::{Digest, Sha256};
    use std::collections::HashMap;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn runtime_task_executor_with_temp_state() -> (tempfile::TempDir, ScopedEnv, RuntimeTaskExecutor)
    {
        let temp = tempfile::tempdir().expect("create temp dir");
        let state_dir = temp.path().join("state");
        let mut env = ScopedEnv::new();
        env.set("CARAPACE_STATE_DIR", state_dir);
        let state = Arc::new(WsServerState::new(WsServerConfig::default()));
        let executor = RuntimeTaskExecutor { state };
        (temp, env, executor)
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

    fn test_signing_key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    fn write_wasm_bytes(dir: &Path, name: &str, bytes: &[u8]) -> PathBuf {
        let path = dir.join(format!("{name}.wasm"));
        std::fs::create_dir_all(dir).expect("create wasm dir");
        std::fs::write(&path, bytes).expect("write wasm");
        path
    }

    fn write_minimal_wasm(dir: &Path, name: &str) -> PathBuf {
        write_wasm_bytes(dir, name, &minimal_wasm_bytes())
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

    struct MockFailingStartServicePlugin;

    impl ServicePluginInstance for MockFailingStartServicePlugin {
        fn start(&self) -> Result<(), BindingError> {
            Err(BindingError::CallError("start failed".to_string()))
        }

        fn stop(&self) -> Result<(), BindingError> {
            Ok(())
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
            route: None,
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
            route: None,
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
    async fn runtime_task_executor_preserves_existing_task_behavior_for_old_age() {
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
    async fn runtime_task_executor_preserves_existing_task_behavior_for_attempt_budget() {
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
    async fn runtime_task_executor_existing_provider_missing_retries_below_task_limit() {
        let (_temp, _state_dir_guard, executor) = runtime_task_executor_with_temp_state();
        let payload = serde_json::to_value(CronPayload::AgentTurn {
            message: "hello".to_string(),
            model: None,
            route: None,
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
            durable_task_with_payload(payload, NO_PROVIDER_EXISTING_TASK_MAX_RETRY_ATTEMPTS - 1);
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
    async fn runtime_task_executor_existing_provider_missing_blocks_at_task_limit() {
        let (_temp, _state_dir_guard, executor) = runtime_task_executor_with_temp_state();
        let payload = serde_json::to_value(CronPayload::AgentTurn {
            message: "hello".to_string(),
            model: None,
            route: None,
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
            durable_task_with_payload(payload, NO_PROVIDER_EXISTING_TASK_MAX_RETRY_ATTEMPTS);
        task.policy_explicit = false;

        let outcome = executor.execute(task).await;
        assert_eq!(
            outcome,
            TaskExecutionOutcome::Blocked {
                category: TaskBlockedReason::ConfigMissing,
                reason: format!(
                    "{} (retry limit reached: {})",
                    crate::cron::executor::NO_LLM_PROVIDER_CONFIGURED_ERROR,
                    NO_PROVIDER_EXISTING_TASK_MAX_RETRY_ATTEMPTS
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
            route: None,
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
    async fn bootstrap_plugin_runtime_respects_plugins_enabled_false() {
        let temp = tempfile::tempdir().expect("temp dir");
        let cfg = json!({
            "plugins": {
                "enabled": false,
                "load": { "paths": [temp.path().join("dev").to_string_lossy()] },
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

        let result = bootstrap_plugin_runtime(&cfg, temp.path())
            .await
            .expect("plugin bootstrap should not fatally fail");
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
    async fn bootstrap_plugin_runtime_reports_missing_manifest_for_managed_plugin() {
        let temp = tempfile::tempdir().expect("temp dir");
        let cfg = json!({
            "plugins": {
                "entries": {
                    "alpha": { "enabled": true }
                }
            }
        });

        let result = bootstrap_plugin_runtime(&cfg, temp.path())
            .await
            .expect("plugin bootstrap should not fatally fail");
        let report = result.activation_report;

        assert_eq!(report.entries.len(), 1);
        let alpha = &report.entries[0];
        assert_eq!(alpha.name, "alpha");
        assert_eq!(alpha.state, PluginActivationState::Failed);
        assert_eq!(
            alpha.reason.as_deref(),
            Some("missing manifest entry in plugins-manifest.json")
        );
    }

    #[tokio::test]
    async fn bootstrap_plugin_runtime_ignores_invalid_managed_entry_shapes() {
        let temp = tempfile::tempdir().expect("temp dir");
        let cfg = json!({
            "plugins": {
                "entries": {
                    "alpha": {
                        "apiKey": "${ALPHA_API_KEY}"
                    }
                }
            }
        });

        let result = bootstrap_plugin_runtime(&cfg, temp.path())
            .await
            .expect("plugin bootstrap should not fatally fail");
        let report = result.activation_report;

        assert!(report.entries.is_empty());
        assert!(report.errors.is_empty());
    }

    #[tokio::test]
    async fn bootstrap_plugin_runtime_reports_invalid_manifest_parse_error() {
        let temp = tempfile::tempdir().expect("temp dir");
        let managed_dir = temp.path().join("plugins");
        std::fs::create_dir_all(&managed_dir).expect("create managed dir");
        std::fs::write(managed_dir.join("plugins-manifest.json"), "{invalid-json").unwrap();
        let cfg = json!({
            "plugins": {
                "entries": {
                    "alpha": { "enabled": true }
                }
            }
        });

        let result = bootstrap_plugin_runtime(&cfg, temp.path())
            .await
            .expect("plugin bootstrap should not fatally fail");
        let report = result.activation_report;

        assert_eq!(report.entries.len(), 1);
        assert_eq!(report.errors.len(), 1);
        assert!(report.errors[0].contains("failed to parse"));
        let alpha = &report.entries[0];
        assert_eq!(alpha.state, PluginActivationState::Failed);
        assert_eq!(
            alpha.reason.as_deref(),
            Some("managed plugins manifest is invalid; fix plugins-manifest.json and restart")
        );
    }

    #[tokio::test]
    async fn bootstrap_plugin_runtime_reports_engine_init_failure_per_managed_plugin() {
        let temp = tempfile::tempdir().expect("temp dir");
        let mut env = ScopedEnv::new();
        env.set(
            TEST_FORCE_PLUGIN_ENGINE_INIT_FAILURE_ENV,
            "forced engine init failure",
        );
        let cfg = json!({
            "plugins": {
                "entries": {
                    "alpha": {
                        "enabled": true,
                        "installId": "install-alpha",
                        "requestedAt": 1700000001000u64
                    },
                    "beta": {
                        "enabled": false,
                        "installId": "install-beta",
                        "requestedAt": 1700000002000u64
                    }
                }
            }
        });

        let result = bootstrap_plugin_runtime(&cfg, temp.path())
            .await
            .expect("plugin bootstrap should not fatally fail");
        let report = result.activation_report;

        assert!(result.runtime.is_none());
        assert_eq!(report.errors.len(), 1);
        assert_eq!(
            report.errors[0],
            "failed to initialize plugin engine: Wasmtime engine error: forced engine init failure"
        );
        assert_eq!(report.entries.len(), 2);

        let alpha = report
            .entries
            .iter()
            .find(|entry| entry.name == "alpha")
            .expect("alpha entry");
        assert!(alpha.enabled);
        assert_eq!(alpha.state, PluginActivationState::Failed);
        assert_eq!(
            alpha.reason.as_deref(),
            Some(
                "failed to initialize plugin engine: Wasmtime engine error: forced engine init failure"
            )
        );
        assert_eq!(alpha.install_id.as_ref(), Some(&json!("install-alpha")));
        assert_eq!(alpha.requested_at, Some(1700000001000u64));

        let beta = report
            .entries
            .iter()
            .find(|entry| entry.name == "beta")
            .expect("beta entry");
        assert!(!beta.enabled);
        assert_eq!(beta.state, PluginActivationState::Disabled);
        assert_eq!(
            beta.reason.as_deref(),
            Some("managed plugin is disabled in plugins.entries")
        );
        assert_eq!(beta.install_id.as_ref(), Some(&json!("install-beta")));
        assert_eq!(beta.requested_at, Some(1700000002000u64));
    }

    #[tokio::test]
    async fn bootstrap_plugin_runtime_reports_loader_init_failure_per_managed_plugin() {
        let temp = tempfile::tempdir().expect("temp dir");
        let mut env = ScopedEnv::new();
        env.set(
            crate::server::plugin_bootstrap::TEST_FORCE_PLUGIN_LOADER_INIT_FAILURE_ENV,
            "forced loader init failure",
        );
        let cfg = json!({
            "plugins": {
                "entries": {
                    "alpha": {
                        "enabled": true,
                        "installId": "install-alpha",
                        "requestedAt": 1700000001000u64
                    },
                    "beta": {
                        "enabled": false,
                        "installId": "install-beta",
                        "requestedAt": 1700000002000u64
                    }
                }
            }
        });

        let result = bootstrap_plugin_runtime(&cfg, temp.path())
            .await
            .expect("plugin bootstrap should not fatally fail");
        let report = result.activation_report;

        assert!(result.runtime.is_none());
        assert_eq!(report.errors.len(), 1);
        assert_eq!(
            report.errors[0],
            "failed to initialize plugin loader: Wasmtime engine error: forced loader init failure"
        );
        assert_eq!(report.entries.len(), 2);

        let alpha = report
            .entries
            .iter()
            .find(|entry| entry.name == "alpha")
            .expect("alpha entry");
        assert!(alpha.enabled);
        assert_eq!(alpha.state, PluginActivationState::Failed);
        assert_eq!(
            alpha.reason.as_deref(),
            Some(
                "failed to initialize plugin loader: Wasmtime engine error: forced loader init failure"
            )
        );
        assert_eq!(alpha.install_id.as_ref(), Some(&json!("install-alpha")));
        assert_eq!(alpha.requested_at, Some(1700000001000u64));

        let beta = report
            .entries
            .iter()
            .find(|entry| entry.name == "beta")
            .expect("beta entry");
        assert!(!beta.enabled);
        assert_eq!(beta.state, PluginActivationState::Disabled);
        assert_eq!(
            beta.reason.as_deref(),
            Some("managed plugin is disabled in plugins.entries")
        );
        assert_eq!(beta.install_id.as_ref(), Some(&json!("install-beta")));
        assert_eq!(beta.requested_at, Some(1700000002000u64));
    }

    #[tokio::test]
    async fn bootstrap_plugin_runtime_ignores_stray_managed_wasm_files() {
        let temp = tempfile::tempdir().expect("temp dir");
        write_minimal_wasm(&temp.path().join("plugins"), "rogue");

        let result = bootstrap_plugin_runtime(&json!({}), temp.path())
            .await
            .expect("plugin bootstrap should not fatally fail");
        let report = result.activation_report;

        assert_eq!(report.entries.len(), 1);
        let entry = &report.entries[0];
        assert_eq!(entry.name, "rogue");
        assert_eq!(entry.source, PluginActivationSource::Managed);
        assert_eq!(entry.state, PluginActivationState::Ignored);
        assert!(entry
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("not declared in plugins.entries")));
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

        let result = bootstrap_plugin_runtime(&cfg, temp.path())
            .await
            .expect("plugin bootstrap should not fatally fail");
        let report = result.activation_report;

        assert_eq!(report.entries.len(), 0);
        assert_eq!(report.errors.len(), 1);
        assert!(report.errors[0].contains("failed to read configured plugin path"));
    }

    #[tokio::test]
    async fn bootstrap_plugin_runtime_skips_unpinned_managed_manifest_entries() {
        let temp = tempfile::tempdir().expect("temp dir");
        let managed_dir = temp.path().join("plugins");
        write_minimal_wasm(&managed_dir, "alpha");
        std::fs::write(
            managed_dir.join("plugins-manifest.json"),
            json!({
                "alpha": {
                    "path": managed_dir.join("alpha.wasm").to_string_lossy().to_string()
                }
            })
            .to_string(),
        )
        .expect("write manifest");
        let cfg = json!({
            "plugins": {
                "entries": {
                    "alpha": { "enabled": true }
                }
            }
        });

        let result = bootstrap_plugin_runtime(&cfg, temp.path())
            .await
            .expect("plugin bootstrap should not fatally fail");
        let report = result.activation_report;

        assert_eq!(report.entries.len(), 1);
        let entry = &report.entries[0];
        assert_eq!(entry.name, "alpha");
        assert_eq!(entry.state, PluginActivationState::Failed);
        assert_eq!(
            entry.reason.as_deref(),
            Some("managed plugin is missing a pinned sha256 in plugins-manifest.json")
        );
    }

    #[tokio::test]
    async fn bootstrap_plugin_runtime_rejects_managed_paths_outside_managed_dir() {
        let temp = tempfile::tempdir().expect("temp dir");
        let managed_dir = temp.path().join("plugins");
        let outside_dir = temp.path().join("outside");
        let outside_path = write_minimal_wasm(&outside_dir, "alpha");
        std::fs::create_dir_all(&managed_dir).expect("create managed dir");
        std::fs::write(
            managed_dir.join("plugins-manifest.json"),
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
            "plugins": {
                "entries": {
                    "alpha": { "enabled": true }
                }
            }
        });

        let result = bootstrap_plugin_runtime(&cfg, temp.path())
            .await
            .expect("plugin bootstrap should not fatally fail");
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

    #[tokio::test]
    async fn bootstrap_plugin_runtime_resolves_relative_manifest_paths_under_managed_dir() {
        let temp = tempfile::tempdir().expect("temp dir");
        let managed_dir = temp.path().join("plugins");
        let component_bytes = tool_plugin_component_bytes();
        let wasm_path = write_wasm_bytes(&managed_dir, "alpha", &component_bytes);
        std::fs::write(
            managed_dir.join("plugins-manifest.json"),
            json!({
                "alpha": {
                    "path": "alpha.wasm",
                    "sha256": sha256_hex(&component_bytes)
                }
            })
            .to_string(),
        )
        .expect("write manifest");
        let cfg = json!({
            "plugins": {
                "signature": {
                    "enabled": false,
                    "requireSignature": false
                },
                "sandbox": { "enabled": false },
                "entries": {
                    "alpha": { "enabled": true }
                }
            }
        });

        let result = bootstrap_plugin_runtime(&cfg, temp.path())
            .await
            .expect("plugin bootstrap should not fatally fail");
        let report = result.activation_report;
        let expected_path = std::fs::canonicalize(&wasm_path).expect("canonicalize wasm path");

        assert!(result.runtime.is_some(), "activation report: {report:#?}");
        assert_eq!(report.entries.len(), 1);
        let entry = &report.entries[0];
        assert_eq!(entry.state, PluginActivationState::Active);
        assert_eq!(
            entry
                .path
                .as_ref()
                .map(|path| std::fs::canonicalize(path).expect("canonicalize report path"))
                .as_deref(),
            Some(expected_path.as_path())
        );
    }

    #[tokio::test]
    async fn bootstrap_plugin_runtime_activates_valid_managed_tool_component() {
        let temp = tempfile::tempdir().expect("temp dir");
        let managed_dir = temp.path().join("plugins");
        let component_bytes = tool_plugin_component_bytes();
        let wasm_path = write_wasm_bytes(&managed_dir, "alpha", &component_bytes);
        let signing_key = test_signing_key();
        let signature = sign_wasm_bytes(&component_bytes, &signing_key);
        std::fs::write(
            managed_dir.join("plugins-manifest.json"),
            json!({
                "alpha": {
                    "path": wasm_path.to_string_lossy().to_string(),
                    "sha256": sha256_hex(&component_bytes),
                    "publisher_key": hex::encode(signing_key.verifying_key().as_bytes()),
                    "signature": hex::encode(signature.to_bytes())
                }
            })
            .to_string(),
        )
        .expect("write manifest");
        let loader = crate::plugins::PluginLoader::with_signature_config(
            managed_dir.clone(),
            crate::plugins::signature::SignatureConfig::default(),
        )
        .expect("create plugin loader");
        let plugin_id = loader
            .load_plugin(&wasm_path)
            .expect("load signed component");
        let loaded = loader
            .get_plugin(&plugin_id)
            .expect("retrieve loaded signed component");
        assert_eq!(loaded.manifest.kind, PluginKind::Tool);

        let cfg = json!({
            "plugins": {
                "sandbox": { "enabled": false },
                "entries": {
                    "alpha": { "enabled": true }
                }
            }
        });

        let result = bootstrap_plugin_runtime(&cfg, temp.path())
            .await
            .expect("plugin bootstrap should not fatally fail");
        let report = result.activation_report;
        let expected_path = std::fs::canonicalize(&wasm_path).expect("canonicalize wasm path");

        assert!(result.runtime.is_some(), "activation report: {report:#?}");
        let tools = result.registry.get_tools();
        assert_eq!(tools.len(), 1, "activation report: {report:#?}");
        assert_eq!(tools[0].0, "alpha");

        assert_eq!(report.entries.len(), 1);
        let entry = &report.entries[0];
        assert_eq!(entry.name, "alpha");
        assert_eq!(entry.plugin_id.as_deref(), Some("alpha"));
        assert_eq!(entry.source, PluginActivationSource::Managed);
        assert_eq!(entry.state, PluginActivationState::Active);
        assert_eq!(
            entry
                .path
                .as_ref()
                .map(|path| std::fs::canonicalize(path).expect("canonicalize report path"))
                .as_deref(),
            Some(expected_path.as_path())
        );
        assert_eq!(entry.reason, None);

        let runtime = result.runtime.expect("runtime retained");
        runtime.unload_plugin("alpha").expect("unload plugin");
    }

    #[tokio::test]
    async fn bootstrap_plugin_runtime_reports_managed_sha256_mismatch() {
        let temp = tempfile::tempdir().expect("temp dir");
        let managed_dir = temp.path().join("plugins");
        let component_bytes = tool_plugin_component_bytes();
        let wasm_path = write_wasm_bytes(&managed_dir, "alpha", &component_bytes);
        std::fs::write(
            managed_dir.join("plugins-manifest.json"),
            json!({
                "alpha": {
                    "path": wasm_path.to_string_lossy().to_string(),
                    "sha256": sha256_hex(b"wrong-bytes")
                }
            })
            .to_string(),
        )
        .expect("write manifest");

        let cfg = json!({
            "plugins": {
                "sandbox": { "enabled": false },
                "entries": {
                    "alpha": { "enabled": true }
                }
            }
        });

        let result = bootstrap_plugin_runtime(&cfg, temp.path())
            .await
            .expect("plugin bootstrap should not fatally fail");
        let report = result.activation_report;

        assert!(
            result.runtime.is_none(),
            "runtime should not be created when no plugins load: {report:#?}"
        );
        assert!(
            result.registry.get_tools().is_empty(),
            "activation report: {report:#?}"
        );
        assert_eq!(report.entries.len(), 1);
        let entry = &report.entries[0];
        assert_eq!(entry.name, "alpha");
        assert_eq!(entry.source, PluginActivationSource::Managed);
        assert_eq!(entry.state, PluginActivationState::Failed);
        assert!(entry
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("Plugin hash verification failed")));
    }

    #[tokio::test]
    async fn bootstrap_plugin_runtime_activates_valid_config_path_tool_component() {
        let temp = tempfile::tempdir().expect("temp dir");
        let config_dir = temp.path().join("config-plugins");
        let component_bytes = tool_plugin_component_bytes();
        let wasm_path = write_wasm_bytes(&config_dir, "alpha", &component_bytes);
        let cfg = json!({
            "plugins": {
                "load": {
                    "paths": [config_dir.to_string_lossy().to_string()]
                },
                "signature": {
                    "enabled": false,
                    "requireSignature": false
                },
                "sandbox": { "enabled": false }
            }
        });

        let result = bootstrap_plugin_runtime(&cfg, temp.path())
            .await
            .expect("plugin bootstrap should not fatally fail");
        let report = result.activation_report;
        let expected_path = std::fs::canonicalize(&wasm_path).expect("canonicalize wasm path");

        assert!(result.runtime.is_some(), "activation report: {report:#?}");
        let tools = result.registry.get_tools();
        assert_eq!(tools.len(), 1, "activation report: {report:#?}");
        assert_eq!(tools[0].0, "alpha");

        assert_eq!(report.entries.len(), 1);
        let entry = &report.entries[0];
        assert_eq!(entry.name, "alpha");
        assert_eq!(entry.plugin_id.as_deref(), Some("alpha"));
        assert_eq!(entry.source, PluginActivationSource::ConfigPath);
        assert_eq!(entry.state, PluginActivationState::Active);
        assert_eq!(
            entry
                .path
                .as_ref()
                .map(|path| std::fs::canonicalize(path).expect("canonicalize report path"))
                .as_deref(),
            Some(expected_path.as_path())
        );
        assert_eq!(entry.reason, None);

        let runtime = result.runtime.expect("runtime retained");
        runtime.unload_plugin("alpha").expect("unload plugin");
    }

    #[tokio::test]
    async fn bootstrap_plugin_runtime_ignores_wasm_named_directories_in_config_paths() {
        let temp = tempfile::tempdir().expect("temp dir");
        let config_dir = temp.path().join("config-plugins");
        let component_bytes = tool_plugin_component_bytes();
        write_wasm_bytes(&config_dir, "alpha", &component_bytes);
        std::fs::create_dir_all(config_dir.join("fake.wasm")).expect("create fake wasm directory");
        let cfg = json!({
            "plugins": {
                "load": {
                    "paths": [config_dir.to_string_lossy().to_string()]
                },
                "signature": {
                    "enabled": false,
                    "requireSignature": false
                },
                "sandbox": { "enabled": false }
            }
        });

        let result = bootstrap_plugin_runtime(&cfg, temp.path())
            .await
            .expect("plugin bootstrap should not fatally fail");
        let report = result.activation_report;

        assert!(result.runtime.is_some(), "activation report: {report:#?}");
        assert_eq!(
            result.registry.get_tools().len(),
            1,
            "activation report: {report:#?}"
        );
        assert_eq!(report.entries.len(), 1);
        assert_eq!(report.entries[0].name, "alpha");
        assert_eq!(report.entries[0].state, PluginActivationState::Active);
    }

    #[tokio::test]
    async fn bootstrap_plugin_runtime_ignores_wasm_named_directories_in_managed_dir() {
        let temp = tempfile::tempdir().expect("temp dir");
        let managed_dir = temp.path().join("plugins");
        let component_bytes = tool_plugin_component_bytes();
        let wasm_path = write_wasm_bytes(&managed_dir, "alpha", &component_bytes);
        std::fs::create_dir_all(managed_dir.join("fake.wasm")).expect("create fake wasm directory");
        std::fs::write(
            managed_dir.join("plugins-manifest.json"),
            json!({
                "alpha": {
                    "path": wasm_path.to_string_lossy().to_string(),
                    "sha256": sha256_hex(&component_bytes)
                }
            })
            .to_string(),
        )
        .expect("write manifest");
        let cfg = json!({
            "plugins": {
                "signature": {
                    "enabled": false,
                    "requireSignature": false
                },
                "sandbox": { "enabled": false },
                "entries": {
                    "alpha": { "enabled": true }
                }
            }
        });

        let result = bootstrap_plugin_runtime(&cfg, temp.path())
            .await
            .expect("plugin bootstrap should not fatally fail");
        let report = result.activation_report;

        assert!(result.runtime.is_some(), "activation report: {report:#?}");
        assert_eq!(report.entries.len(), 1);
        assert_eq!(report.entries[0].name, "alpha");
        assert_eq!(report.entries[0].state, PluginActivationState::Active);
    }

    #[test]
    fn load_plugin_candidate_reports_duplicate_plugin_ids_across_sources() {
        let temp = tempfile::tempdir().expect("temp dir");
        let managed_dir = temp.path().join("plugins");
        let config_dir = temp.path().join("config-plugins");
        let managed_bytes = tool_plugin_component_bytes();
        let managed_path = write_wasm_bytes(&managed_dir, "alpha", &managed_bytes);
        let config_path = write_wasm_bytes(&config_dir, "alpha", &managed_bytes);
        std::fs::write(
            managed_dir.join("plugins-manifest.json"),
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
        let mut report = PluginActivationReport::empty(vec![config_dir], true);
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

    #[test]
    fn configured_plugin_paths_normalizes_equivalent_paths() {
        let cfg = json!({
            "plugins": {
                "load": {
                    "paths": [
                        "plugins/tooling",
                        "plugins/./tooling",
                        "plugins//tooling"
                    ]
                }
            }
        });

        let paths = crate::server::plugin_bootstrap::configured_plugin_paths(&cfg);
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0], PathBuf::from("plugins/tooling"));
    }

    #[tokio::test]
    async fn build_ws_state_with_runtime_dependencies_attaches_plugin_activation_report() {
        let temp = tempfile::tempdir().expect("temp dir");
        let state_dir = temp.path().join("state");
        let config_path = temp.path().join("carapace.json5");
        let mut env = ScopedEnv::new();
        env.set("CARAPACE_STATE_DIR", state_dir.as_os_str())
            .set("CARAPACE_CONFIG_PATH", config_path.as_os_str())
            .set("CARAPACE_DISABLE_CONFIG_CACHE", "1")
            // Provide a minimal LLM provider so build_ws_state_with_runtime_dependencies
            // doesn't fail-fast on missing-provider — this test is exercising the plugin
            // activation report, not provider configuration.
            .set("ANTHROPIC_API_KEY", "test-key");
        crate::config::clear_cache();

        let tools_registry = Arc::new(ToolsRegistry::new());
        let ws_state =
            build_ws_state_with_runtime_dependencies(&json!({}), &state_dir, tools_registry)
                .await
                .expect("build ws state");

        let report = ws_state
            .plugin_activation_report()
            .expect("plugin activation report");
        assert!(report.entries.is_empty());

        crate::config::clear_cache();
    }

    /// `build_ws_state_with_runtime_dependencies` must error out when no LLM
    /// provider is configured, and the message must name at least one
    /// supported env var so an operator can fix the misconfiguration without
    /// consulting docs.
    #[tokio::test]
    async fn build_ws_state_with_runtime_dependencies_errors_when_no_provider() {
        let temp = tempfile::tempdir().expect("temp dir");
        let state_dir = temp.path().join("state");
        let config_path = temp.path().join("carapace.json5");
        // Start from `provider_env_cleared()` to unset every provider-relevant
        // env var (covers Bedrock, Vertex, Claude CLI in addition to the four
        // API keys), then layer the test-specific paths on top.
        let mut env = crate::test_support::env::provider_env_cleared();
        env.set("CARAPACE_STATE_DIR", state_dir.as_os_str())
            .set("CARAPACE_CONFIG_PATH", config_path.as_os_str())
            .set("CARAPACE_DISABLE_CONFIG_CACHE", "1");
        crate::config::clear_cache();

        let tools_registry = Arc::new(ToolsRegistry::new());
        let result =
            build_ws_state_with_runtime_dependencies(&json!({}), &state_dir, tools_registry).await;

        let err = result.expect_err("startup must error when no provider configured");
        let msg = err.to_string();
        assert!(
            msg.contains("No LLM provider configured"),
            "error must name the failure: {msg}"
        );
        assert!(
            msg.contains("ANTHROPIC_API_KEY") && msg.contains("authProfile"),
            "error must list at least one env var and the authProfile path: {msg}"
        );

        crate::config::clear_cache();
    }

    /// Build a config-cache-locked, env-cleared test scope plus a starting
    /// `ReloadState` whose `last_good_*` mirror an `ANTHROPIC_API_KEY` setup.
    /// The initial cache holds **distinct** raw and normalized values so a
    /// rollback-mixup that wrote one into the other's slot would surface in
    /// the assertions, and `CONFIG_ENV_STATE` is pre-populated via
    /// `apply_config_env_for_test` so `last_good_env` snapshots have
    /// non-empty content — that lets the rollback tests actually exercise
    /// `restore_env_state` rather than treating it as a no-op. The
    /// returned `ScopedEnvStateForTest` resets the env tracker on drop so
    /// concurrent tests don't observe each other's `active_values`.
    fn make_reload_state_with_anthropic_provider() -> (
        crate::test_support::config::ScopedConfigCache,
        ScopedEnv,
        crate::config::ScopedEnvStateForTest,
        Arc<WsServerState>,
        ReloadState,
    ) {
        use crate::config::ScopedEnvStateForTest;
        use crate::test_support::config::ScopedConfigCache;

        let cache_guard = ScopedConfigCache::new();
        crate::config::clear_cache();
        let env_state_guard = ScopedEnvStateForTest::new();
        let mut env = crate::test_support::env::provider_env_cleared();
        env.set(TEST_PROVIDER_KEY, "test-initial-key");

        // Mirror the env into CONFIG_ENV_STATE so the snapshot below
        // captures a non-empty tracker.
        crate::config::apply_config_env_for_test(HashMap::from([(
            TEST_PROVIDER_KEY.to_string(),
            "test-initial-key".to_string(),
        )]));

        let initial_raw = json!({ "marker": "raw-initial" });
        let initial_normalized = json!({ "marker": "normalized-initial" });
        crate::config::update_cache(initial_raw.clone(), initial_normalized.clone());

        let ws_state = Arc::new(WsServerState::new(WsServerConfig::default()));
        let reload_state = ReloadState {
            last_good_env: crate::config::snapshot_env_state(),
            current_fingerprint: crate::agent::factory::fingerprint_providers(&initial_normalized),
        };
        (cache_guard, env, env_state_guard, ws_state, reload_state)
    }

    const TEST_PROVIDER_KEY: &str = "ANTHROPIC_API_KEY";

    fn install_reloaded_config_without_provider_env(env: &mut ScopedEnv) {
        crate::config::apply_config_env_for_test(HashMap::new());
        env.unset(TEST_PROVIDER_KEY);
    }

    #[tokio::test]
    async fn handle_provider_reload_reverts_when_new_config_has_no_provider() {
        let (_cache, mut env, _env_state, ws_state, mut state) =
            make_reload_state_with_anthropic_provider();
        let prior_fingerprint = state.current_fingerprint.clone();
        let initial_raw = json!({ "marker": "raw-initial" });
        let initial_normalized = json!({ "marker": "normalized-initial" });

        install_reloaded_config_without_provider_env(&mut env);
        let new_raw = json!({ "marker": "raw-new", "agents": { "defaults": { "route": "fast" } } });
        let new_normalized =
            json!({ "marker": "normalized-new", "agents": { "defaults": { "route": "fast" } } });

        let outcome = handle_provider_reload(
            &ws_state,
            &mut state,
            Arc::new(new_raw),
            Arc::new(new_normalized),
        )
        .await;

        assert_eq!(outcome, ReloadOutcome::Reverted);
        // Cache must be untouched — the bridge never installed the bad
        // payload, so the fixture's initial `(raw, normalized)` still wins.
        let normalized_after = crate::config::load_config_shared().expect("normalized populated");
        assert_eq!(*normalized_after, initial_normalized);
        let raw_after = crate::config::load_raw_config_shared().expect("raw populated");
        assert_eq!(*raw_after, initial_raw);
        assert_eq!(state.current_fingerprint, prior_fingerprint);
        assert_eq!(
            crate::config::read_process_env(TEST_PROVIDER_KEY),
            Some("test-initial-key".to_string()),
            "rollback must restore the env-injected provider var"
        );
    }

    #[tokio::test]
    async fn handle_provider_reload_swaps_provider_and_applies_on_valid_change() {
        let (_cache, mut env, _env_state, ws_state, mut state) =
            make_reload_state_with_anthropic_provider();

        crate::config::apply_config_env_for_test(HashMap::from([(
            TEST_PROVIDER_KEY.to_string(),
            "test-rotated-key".to_string(),
        )]));
        env.set(TEST_PROVIDER_KEY, "test-rotated-key");
        let new_raw = json!({ "marker": "raw-rotated" });
        let new_normalized = json!({ "marker": "normalized-rotated" });

        let outcome = handle_provider_reload(
            &ws_state,
            &mut state,
            Arc::new(new_raw.clone()),
            Arc::new(new_normalized.clone()),
        )
        .await;

        assert_eq!(outcome, ReloadOutcome::Apply);
        assert!(ws_state.llm_provider().is_some());
        // The bridge writes the new payload into CONFIG_CACHE on Apply.
        let normalized_after = crate::config::load_config_shared().expect("normalized populated");
        assert_eq!(*normalized_after, new_normalized);
        let raw_after = crate::config::load_raw_config_shared().expect("raw populated");
        assert_eq!(*raw_after, new_raw);
        // Re-applying the captured snapshot must restore the rotated value,
        // not the initial one — pins last_good_env advancement on swap.
        crate::config::restore_env_state(&state.last_good_env);
        assert_eq!(
            crate::config::read_process_env(TEST_PROVIDER_KEY),
            Some("test-rotated-key".to_string()),
        );
    }

    #[tokio::test]
    async fn handle_provider_reload_captures_new_last_good_when_provider_unchanged() {
        let (_cache, _env, _env_state, ws_state, mut state) =
            make_reload_state_with_anthropic_provider();
        let prior_fingerprint = state.current_fingerprint.clone();

        // Add a non-provider env entry between fixture init and the reload
        // so the unchanged-provider arm has a distinguishable post-snapshot
        // to verify against without perturbing the provider fingerprint.
        const PROBE_VAR: &str = "CARAPACE_TEST_PROBE_VAR";
        crate::config::apply_config_env_for_test(HashMap::from([
            (
                TEST_PROVIDER_KEY.to_string(),
                "test-initial-key".to_string(),
            ),
            (PROBE_VAR.to_string(), "probe-value".to_string()),
        ]));
        let new_raw = json!({ "marker": "raw-edited" });
        let new_normalized = json!({ "marker": "normalized-edited" });

        let outcome = handle_provider_reload(
            &ws_state,
            &mut state,
            Arc::new(new_raw.clone()),
            Arc::new(new_normalized.clone()),
        )
        .await;

        assert_eq!(outcome, ReloadOutcome::Apply);
        assert_eq!(state.current_fingerprint, prior_fingerprint);
        // Bridge writes the new payload into CONFIG_CACHE on Apply, even
        // when the provider fingerprint is unchanged.
        let normalized_after = crate::config::load_config_shared().expect("normalized populated");
        assert_eq!(*normalized_after, new_normalized);
        let raw_after = crate::config::load_raw_config_shared().expect("raw populated");
        assert_eq!(*raw_after, new_raw);
        // Restoring the captured snapshot must keep the probe set — pins
        // last_good_env advancement on the unchanged-provider arm. Without
        // the snapshot_env_state call, last_good_env would still be the
        // fixture's pre-probe state and restore would unset the probe.
        crate::config::restore_env_state(&state.last_good_env);
        assert_eq!(
            crate::config::read_process_env(PROBE_VAR),
            Some("probe-value".to_string())
        );
        // Explicit cleanup is unnecessary: ScopedEnvStateForTest's Drop
        // resets CONFIG_ENV_STATE to empty, which unsets PROBE_VAR from
        // process env via restore_config_env_state.
    }

    /// When the bridge starts from a clean state (cache empty after a
    /// startup-time initial-load failure), the first valid provider reload
    /// must install the provider AND write the new payload into
    /// `CONFIG_CACHE`. A regression that skips `update_cache_arc` on this
    /// path would leave the cache empty, breaking every downstream reader
    /// until a later successful reload arrived.
    #[tokio::test]
    async fn handle_provider_reload_installs_cache_and_provider_on_first_valid_swap_from_clean_state(
    ) {
        use crate::config::ScopedEnvStateForTest;
        use crate::test_support::config::ScopedConfigCache;

        let _cache_guard = ScopedConfigCache::new();
        crate::config::clear_cache();
        let _env_state_guard = ScopedEnvStateForTest::new();
        // Start with no provider env set so the initial fingerprint has
        // no anthropic entry; the later API-key install creates a real
        // fingerprint change that drives the provider-swap branch.
        let mut env = crate::test_support::env::provider_env_cleared();

        let mut state = ReloadState {
            last_good_env: crate::config::snapshot_env_state(),
            current_fingerprint: crate::agent::factory::fingerprint_providers(&json!({})),
        };

        // Now install the API key — fingerprint mismatch on the next reload
        // will drive build_providers and the Apply arm's update_cache_arc
        // write.
        env.set(TEST_PROVIDER_KEY, "test-degraded-key");
        crate::config::apply_config_env_for_test(HashMap::from([(
            TEST_PROVIDER_KEY.to_string(),
            "test-degraded-key".to_string(),
        )]));
        let new_raw = json!({ "marker": "raw-from-degraded" });
        let new_normalized = json!({ "marker": "normalized-from-degraded" });
        let ws_state = Arc::new(WsServerState::new(WsServerConfig::default()));

        let outcome = handle_provider_reload(
            &ws_state,
            &mut state,
            Arc::new(new_raw.clone()),
            Arc::new(new_normalized.clone()),
        )
        .await;

        assert_eq!(outcome, ReloadOutcome::Apply);
        assert!(
            ws_state.llm_provider().is_some(),
            "valid provider swap from clean state must install the provider"
        );
        // Bridge must populate CONFIG_CACHE so downstream readers see the
        // freshly-installed config (not the empty cache the test started
        // with).
        let normalized_after = crate::config::load_config_shared().expect("normalized populated");
        assert_eq!(*normalized_after, new_normalized);
        let raw_after = crate::config::load_raw_config_shared().expect("raw populated");
        assert_eq!(*raw_after, new_raw);
    }

    /// `drain_pending_events` must empty the broadcast receiver so the next
    /// `recv()` blocks on a fresh event rather than replaying buffered
    /// (stale) ones. Critical for the lag-recovery branch — without the
    /// drain, `tokio::sync::broadcast::Receiver` advances its cursor to the
    /// oldest still-buffered message after a `Lagged`, which would replay
    /// E3..En in order and could thrash the live provider through stale
    /// intermediate fingerprints.
    #[tokio::test]
    async fn drain_pending_events_empties_buffer_so_next_recv_blocks_on_fresh() {
        use config::watcher::{ConfigEvent, FailedReload};

        let (event_tx, mut rx) = tokio::sync::broadcast::channel::<ConfigEvent>(4);
        // Fill past capacity to force a Lagged on next recv.
        for i in 0..6 {
            event_tx
                .send(ConfigEvent::ReloadFailed(FailedReload {
                    mode: format!("test-{i}"),
                    error: "synthetic".into(),
                }))
                .expect("send into broadcast");
        }
        // Confirm the receiver lags as expected.
        match rx.try_recv() {
            Err(tokio::sync::broadcast::error::TryRecvError::Lagged(_)) => {}
            other => panic!("expected Lagged before drain, got {other:?}"),
        }

        drain_pending_events(&mut rx);

        // Receiver must report Empty now — drain consumed every buffered event.
        match rx.try_recv() {
            Err(tokio::sync::broadcast::error::TryRecvError::Empty) => {}
            other => panic!("expected Empty after drain, got {other:?}"),
        }

        // A fresh send is observable on the next try_recv (i.e. drain didn't
        // consume from a closed channel or otherwise break the receiver).
        event_tx
            .send(ConfigEvent::ReloadFailed(FailedReload {
                mode: "post-drain".into(),
                error: "synthetic".into(),
            }))
            .expect("send post-drain");
        match rx.try_recv() {
            Ok(ConfigEvent::ReloadFailed(failure)) => {
                assert_eq!(failure.mode, "post-drain");
            }
            other => panic!("expected fresh event after drain, got {other:?}"),
        }
    }

    /// A rejected reload fires zero ticks on `CONFIG_CHANGE_TX`: the bridge
    /// owns the cache write, so when `handle_provider_reload` returns
    /// `Reverted` it never calls `update_cache_arc`. The cache stays at
    /// whatever the previous validated reload installed — there is no
    /// transient bad-state observable to subscribers.
    #[tokio::test]
    async fn rejected_reload_fires_zero_change_ticks_and_keeps_cache_unchanged() {
        let (_cache, mut env, _env_state, ws_state, mut state) =
            make_reload_state_with_anthropic_provider();
        let initial_raw = json!({ "marker": "raw-initial" });
        let initial_normalized = json!({ "marker": "normalized-initial" });

        let mut rx = crate::config::subscribe_config_changes();
        let counter_before = *rx.borrow_and_update();

        // Bridge sees a no-provider reload payload directly; no pre-call
        // `update_cache` simulates a bad install — that's the whole point.
        install_reloaded_config_without_provider_env(&mut env);
        let bad_raw = json!({ "marker": "bad-raw" });
        let bad_normalized = json!({ "marker": "bad-normalized" });

        let outcome = handle_provider_reload(
            &ws_state,
            &mut state,
            Arc::new(bad_raw),
            Arc::new(bad_normalized),
        )
        .await;

        assert_eq!(outcome, ReloadOutcome::Reverted);
        let counter_after = *rx.borrow_and_update();
        assert_eq!(
            counter_after, counter_before,
            "rejected reload must fire zero ticks — the bridge writes nothing on Reverted"
        );

        // Cache still holds the fixture's initial values: the bridge never
        // installed the bad payload.
        let normalized_after = crate::config::load_config_shared().expect("cache populated");
        assert_eq!(*normalized_after, initial_normalized);
        let raw_after = crate::config::load_raw_config_shared().expect("cache populated");
        assert_eq!(*raw_after, initial_raw);
    }

    /// `Err(_)` arm of `build_providers` must roll back the same way
    /// `Ok(None)` does — guards against the two arms diverging.
    #[tokio::test]
    async fn handle_provider_reload_reverts_when_build_providers_errors() {
        let (_cache, mut env, _env_state, ws_state, mut state) =
            make_reload_state_with_anthropic_provider();
        let initial_raw = json!({ "marker": "raw-initial" });
        let initial_normalized = json!({ "marker": "normalized-initial" });
        let prior_fingerprint = state.current_fingerprint.clone();

        // The encryption-guard inside `build_anthropic_provider` returns
        // `Err(_)` when an `authProfile` is configured but
        // `CARAPACE_CONFIG_PASSWORD` is unset (the default in test envs).
        // The `/nonexistent` path itself is never read — the guard fires
        // before the profile-store lookup.
        install_reloaded_config_without_provider_env(&mut env);
        env.unset("CARAPACE_CONFIG_PASSWORD");
        let new_raw = json!({
            "anthropic": { "authProfile": "/nonexistent/path/that/does/not/resolve" }
        });
        let new_normalized = new_raw.clone();
        // Pre-assert that this config truly reaches the `Err` arm of
        // `build_providers` (not `Ok(None)`). If a future refactor of
        // `build_anthropic_provider`'s guard ordering makes the same input
        // return `Ok(None)` instead, this assertion fails loudly — without
        // it, the test would silently exercise the no-provider arm and the
        // doc comment above would rot. `build_providers` is non-`Send`, so
        // we must call it on the current thread.
        assert!(
            crate::agent::factory::build_providers(&new_normalized).is_err(),
            "test config must reach the Err arm of build_providers"
        );

        let outcome = handle_provider_reload(
            &ws_state,
            &mut state,
            Arc::new(new_raw),
            Arc::new(new_normalized),
        )
        .await;

        assert_eq!(outcome, ReloadOutcome::Reverted);
        // Bridge wrote nothing on the Err arm: cache stays at fixture state.
        let raw_after = crate::config::load_raw_config_shared().expect("raw populated");
        assert_eq!(*raw_after, initial_raw);
        let normalized_after = crate::config::load_config_shared().expect("normalized populated");
        assert_eq!(*normalized_after, initial_normalized);
        assert_eq!(state.current_fingerprint, prior_fingerprint);
        assert_eq!(
            crate::config::read_process_env(TEST_PROVIDER_KEY),
            Some("test-initial-key".to_string()),
            "rollback must restore the env-injected provider var on the Err arm too"
        );
    }

    /// In `CARAPACE_DISABLE_CONFIG_CACHE` mode, `revert_pending_env` still
    /// restores env (`CONFIG_ENV_STATE` is independent of `CONFIG_CACHE`)
    /// but cannot protect direct disk readers — `load_config_shared`
    /// bypasses the cache in this mode and re-reads the operator's bad
    /// file. This pins the documented partial-rollback contract.
    #[test]
    fn revert_pending_env_in_cache_disabled_mode_restores_env_but_disk_readers_see_bad_file() {
        use crate::config::ScopedEnvStateForTest;
        use crate::test_support::config::ScopedConfigCache;

        let _cache_guard = ScopedConfigCache::new();
        crate::config::clear_cache();
        let _env_state_guard = ScopedEnvStateForTest::new();
        let temp = tempfile::tempdir().expect("tempdir");
        let bad_path = temp.path().join("config.json5");
        std::fs::write(&bad_path, r#"{"marker": "bad-on-disk"}"#).expect("write bad config");
        let mut env = crate::test_support::env::provider_env_cleared();
        env.set("CARAPACE_CONFIG_PATH", bad_path.as_os_str())
            .set("CARAPACE_DISABLE_CONFIG_CACHE", "1")
            .set(TEST_PROVIDER_KEY, "test-initial-key");
        crate::config::apply_config_env_for_test(HashMap::from([(
            TEST_PROVIDER_KEY.to_string(),
            "test-initial-key".to_string(),
        )]));

        let state = ReloadState {
            last_good_env: crate::config::snapshot_env_state(),
            current_fingerprint: crate::agent::factory::fingerprint_providers(&json!({})),
        };

        // Mutate the env so restore_env_state has observable work.
        env.unset(TEST_PROVIDER_KEY);

        revert_pending_env(&state);

        // Env restoration works regardless of cache mode.
        assert_eq!(
            crate::config::read_process_env(TEST_PROVIDER_KEY),
            Some("test-initial-key".to_string()),
            "env restoration must work in disabled-cache mode"
        );

        // load_config_shared bypasses CONFIG_CACHE in disabled mode and
        // returns the on-disk bad content — the documented limitation that
        // the warning log in revert_pending_env announces to operators.
        let on_disk = crate::config::load_config_shared().expect("disk read");
        assert_eq!(
            on_disk["marker"],
            json!("bad-on-disk"),
            "disabled-cache load must keep returning the bad disk file post-rollback"
        );
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

    #[test]
    fn start_plugin_services_marks_failures_for_unload() {
        let registry = Arc::new(PluginRegistry::new());
        registry.register_service(
            "weather".to_string(),
            Arc::new(MockFailingStartServicePlugin),
        );
        let mut report = PluginActivationReport::empty(vec![], true);
        report.entries.push(PluginActivationEntry {
            name: "weather".to_string(),
            plugin_id: Some("weather".to_string()),
            source: PluginActivationSource::Managed,
            enabled: true,
            path: Some(PathBuf::from("/managed/weather.wasm")),
            requested_at: None,
            install_id: None,
            state: PluginActivationState::Active,
            reason: None,
        });
        let report_index_by_plugin_id = HashMap::from([(String::from("weather"), 0usize)]);

        let unload_ids = start_plugin_services(
            &registry,
            &[String::from("weather")],
            &mut report,
            &report_index_by_plugin_id,
        );

        assert_eq!(unload_ids, vec![String::from("weather")]);
        assert_eq!(report.entries[0].state, PluginActivationState::Failed);
        assert_eq!(
            report.entries[0].reason.as_deref(),
            Some("service plugin failed to start: Function call error: start failed")
        );
    }

    #[test]
    fn test_daemon_pid_guard_writes_and_removes_pid_file() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let state_dir = temp.path().to_path_buf();
        let pid_path = state_dir.join("daemon.pid");

        let guard = DaemonPidGuard::install(state_dir.clone()).expect("install pid guard");
        assert!(pid_path.exists(), "PID file should exist after install");
        let content = std::fs::read_to_string(&pid_path).expect("read pid file");
        let pid: u32 = content.trim().parse().expect("pid file is decimal");
        assert_eq!(pid, std::process::id());

        drop(guard);
        assert!(
            !pid_path.exists(),
            "PID file should be removed when guard is dropped"
        );
    }

    #[test]
    fn test_daemon_pid_guard_rejects_concurrent_install() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let state_dir = temp.path().to_path_buf();

        let _first = DaemonPidGuard::install(state_dir.clone()).expect("first install");
        let err = match DaemonPidGuard::install(state_dir.clone()) {
            Ok(_) => panic!("second install should fail while the first holds the rekey lock"),
            Err(e) => e,
        };
        let msg = err.to_string();
        assert!(
            msg.contains("Matrix rekey lock"),
            "error should mention rekey lock contention: {msg}"
        );
    }

    #[test]
    fn test_daemon_pid_guard_release_allows_reinstall() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let state_dir = temp.path().to_path_buf();

        {
            let _first = DaemonPidGuard::install(state_dir.clone()).expect("first install");
        }
        let _second = DaemonPidGuard::install(state_dir.clone())
            .expect("second install after the first was dropped");
    }

    #[test]
    fn test_daemon_pid_guard_recovers_when_pid_file_was_removed_externally() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let state_dir = temp.path().to_path_buf();
        let pid_path = state_dir.join("daemon.pid");

        let guard = DaemonPidGuard::install(state_dir).expect("install pid guard");
        std::fs::remove_file(&pid_path).expect("operator clears pid file out from under us");
        // Drop must not panic when the file is already gone.
        drop(guard);
    }
}
