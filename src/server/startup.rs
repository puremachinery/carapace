//! Testable server startup logic.
//!
//! Provides [`ServerConfig`] and [`ServerHandle`] to allow integration tests
//! to spin up a real (non-TLS) Carapace server on an ephemeral port, exercise
//! its HTTP and WebSocket endpoints, and shut it down cleanly.

use std::net::SocketAddr;
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
use crate::plugins::PluginRegistry;
use crate::server::http::{HttpConfig, MiddlewareConfig};
use crate::server::ws::WsServerState;
use crate::sessions;
use crate::tasks::{DurableTask, TaskBlockedReason, TaskExecutionOutcome, TaskExecutor};

struct RuntimeTaskExecutor {
    state: Arc<WsServerState>,
}

const NO_PROVIDER_RETRY_DELAY_MS: u64 = 60_000;
const NO_PROVIDER_LEGACY_MAX_RETRY_ATTEMPTS: u32 = 3_600;

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
    tools_registry: Arc<ToolsRegistry>,
    plugin_registry: Arc<PluginRegistry>,
) -> Result<Arc<WsServerState>, Box<dyn std::error::Error>> {
    let ws_state = crate::server::ws::build_ws_state_owned_from_value(cfg).await?;
    let ws_state = match crate::agent::factory::build_providers(cfg)? {
        Some(multi_provider) => ws_state.with_llm_provider(Arc::new(multi_provider)),
        None => {
            info!(
                "No LLM provider configured (set ANTHROPIC_API_KEY, OPENAI_API_KEY, GOOGLE_API_KEY, and/or configure Ollama to enable)"
            );
            ws_state
        }
    };

    tools_registry.set_plugin_registry(plugin_registry.clone());
    Ok(Arc::new(
        ws_state
            .with_tools_registry(tools_registry)
            .with_plugin_registry(plugin_registry),
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
    use crate::server::ws::WsServerConfig;

    struct EnvVarGuard {
        key: &'static str,
        prev: Option<String>,
    }

    impl EnvVarGuard {
        fn set(key: &'static str, value: &str) -> Self {
            let prev = std::env::var(key).ok();
            // SAFETY: tests scope env var mutation to a short-lived guard.
            unsafe { std::env::set_var(key, value) };
            Self { key, prev }
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
        let state_dir_str = state_dir.to_str().expect("state dir utf8");
        let guard = EnvVarGuard::set("CARAPACE_STATE_DIR", state_dir_str);
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
}
