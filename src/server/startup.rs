//! Testable server startup logic.
//!
//! Provides [`ServerConfig`] and [`ServerHandle`] to allow integration tests
//! to spin up a real (non-TLS) Carapace server on an ephemeral port, exercise
//! its HTTP and WebSocket endpoints, and shut it down cleanly.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

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
use crate::server::ws::WsServerState;
use crate::sessions;

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
                    let result = config::watcher::perform_reload(&mode);
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

/// Spawn background tasks (delivery loop, cron, config watcher, SIGHUP,
/// retention cleanup).  Shared between `run_server_with_config` and the
/// production TLS path in `main.rs`.
pub fn spawn_background_tasks(
    ws_state: &Arc<WsServerState>,
    raw_config: &Value,
    shutdown_rx: &watch::Receiver<bool>,
) {
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
