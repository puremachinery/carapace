#![allow(dead_code)]
#![allow(unused_imports)]

mod agent;
mod auth;
mod channels;
mod cli;
mod config;
mod credentials;
mod cron;
mod devices;
mod discovery;
mod exec;
mod hooks;
mod logging;
mod media;
mod messages;
mod nodes;
mod plugins;
mod server;
mod sessions;
mod tailscale;
mod tls;
mod usage;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::routing::get;
use axum::Router;
use clap::Parser;
use serde_json::Value;
use tracing::{error, info, warn};

use cli::{Cli, Command, ConfigCommand};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        // No subcommand or explicit `start` both launch the server.
        None | Some(Command::Start) => run_server().await,

        Some(Command::Config(sub)) => {
            match sub {
                ConfigCommand::Show => cli::handle_config_show()?,
                ConfigCommand::Get { key } => cli::handle_config_get(&key)?,
                ConfigCommand::Set { key, value } => cli::handle_config_set(&key, &value)?,
                ConfigCommand::Path => cli::handle_config_path(),
            }
            Ok(())
        }

        Some(Command::Status { port, host }) => cli::handle_status(&host, port).await,

        Some(Command::Logs { lines, port, host }) => cli::handle_logs(&host, port, lines).await,

        Some(Command::Version) => {
            cli::handle_version();
            Ok(())
        }

        Some(Command::Backup { output }) => cli::handle_backup(output.as_deref()),

        Some(Command::Restore { path, force }) => cli::handle_restore(&path, force),

        Some(Command::Reset {
            sessions,
            cron,
            usage,
            memory,
            all,
            force,
        }) => cli::handle_reset(sessions, cron, usage, memory, all, force),

        Some(Command::Setup { force }) => cli::handle_setup(force),

        Some(Command::Pair { url, name, trust }) => {
            cli::handle_pair(&url, name.as_deref(), trust).await
        }

        Some(Command::Update { check, version }) => {
            cli::handle_update(check, version.as_deref()).await
        }
    }
}

/// Run the gateway server (the original `main` logic).
async fn run_server() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Initialize logging
    let log_config = if std::env::var("MOLTBOT_DEV")
        .map(|v| !v.is_empty() && v != "0" && v.to_lowercase() != "false")
        .unwrap_or(false)
    {
        logging::LogConfig::development()
    } else {
        logging::LogConfig::production()
    };
    logging::init_logging(log_config)?;

    // 2. Load config
    let cfg = config::load_config().unwrap_or_else(|e| {
        warn!("Failed to load config: {}, using defaults", e);
        Value::Object(serde_json::Map::new())
    });

    // 3. Ensure state directories exist
    let state_dir = server::ws::resolve_state_dir();
    std::fs::create_dir_all(&state_dir)?;
    std::fs::create_dir_all(state_dir.join("sessions"))?;

    // 4. Resolve bind address
    let gateway = cfg.get("gateway").and_then(|v| v.as_object());
    let bind_str = gateway
        .and_then(|g| g.get("bind"))
        .and_then(|v| v.as_str())
        .unwrap_or("loopback");
    let port = gateway
        .and_then(|g| g.get("port"))
        .and_then(|v| v.as_u64())
        .map(|p| p as u16)
        .unwrap_or(server::bind::DEFAULT_PORT);

    let bind_mode = server::bind::parse_bind_mode(bind_str);
    let resolved = server::bind::resolve_bind_with_metadata(&bind_mode, port)?;

    // 5. Build WsServerState (persistent, with device/node registries)
    let ws_state = server::ws::build_ws_state_from_config().await?;

    // 6. Configure LLM providers (Anthropic + OpenAI + Ollama)
    // 6a. Anthropic provider
    let anthropic_api_key = std::env::var("ANTHROPIC_API_KEY").ok().or_else(|| {
        cfg.get("anthropic")
            .and_then(|v| v.get("apiKey"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    });

    let anthropic_base_url = std::env::var("ANTHROPIC_BASE_URL").ok().or_else(|| {
        cfg.get("anthropic")
            .and_then(|v| v.get("baseUrl"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    });

    let anthropic_provider: Option<Arc<dyn agent::LlmProvider>> =
        if let Some(key) = anthropic_api_key {
            match agent::anthropic::AnthropicProvider::new(key) {
                Ok(provider) => {
                    let provider = if let Some(url) = anthropic_base_url {
                        match provider.with_base_url(url) {
                            Ok(p) => p,
                            Err(e) => {
                                warn!("Invalid ANTHROPIC_BASE_URL: {}", e);
                                return Err(e.into());
                            }
                        }
                    } else {
                        provider
                    };
                    info!("LLM provider configured: Anthropic");
                    Some(Arc::new(provider))
                }
                Err(e) => {
                    warn!("Failed to configure Anthropic provider: {}", e);
                    None
                }
            }
        } else {
            None
        };

    // 6b. OpenAI provider
    let openai_api_key = std::env::var("OPENAI_API_KEY").ok().or_else(|| {
        cfg.get("openai")
            .and_then(|v| v.get("apiKey"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    });

    let openai_base_url = std::env::var("OPENAI_BASE_URL").ok().or_else(|| {
        cfg.get("openai")
            .and_then(|v| v.get("baseUrl"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    });

    let openai_provider: Option<Arc<dyn agent::LlmProvider>> = if let Some(key) = openai_api_key {
        match agent::openai::OpenAiProvider::new(key) {
            Ok(provider) => {
                let provider = if let Some(url) = openai_base_url {
                    match provider.with_base_url(url) {
                        Ok(p) => p,
                        Err(e) => {
                            warn!("Invalid OPENAI_BASE_URL: {}", e);
                            return Err(e.into());
                        }
                    }
                } else {
                    provider
                };
                info!("LLM provider configured: OpenAI");
                Some(Arc::new(provider))
            }
            Err(e) => {
                warn!("Failed to configure OpenAI provider: {}", e);
                None
            }
        }
    } else {
        None
    };

    // 6c. Ollama provider (local inference)
    let ollama_providers_cfg = cfg.get("providers").and_then(|v| v.get("ollama"));
    let ollama_base_url = std::env::var("OLLAMA_BASE_URL").ok().or_else(|| {
        ollama_providers_cfg
            .and_then(|v| v.get("baseUrl"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    });
    let ollama_api_key = ollama_providers_cfg
        .and_then(|v| v.get("apiKey"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    // Ollama is configured if a base URL is explicitly set, or if the
    // providers.ollama section exists in the config, or if the
    // OLLAMA_BASE_URL env var is present. We always attempt creation
    // since no API key is required for local Ollama.
    let ollama_explicitly_configured = ollama_base_url.is_some() || ollama_providers_cfg.is_some();
    let ollama_provider: Option<Arc<dyn agent::LlmProvider>> = if ollama_explicitly_configured {
        match agent::ollama::OllamaProvider::new() {
            Ok(provider) => {
                let provider = if let Some(url) = ollama_base_url {
                    match provider.with_base_url(url) {
                        Ok(p) => p,
                        Err(e) => {
                            warn!("Invalid OLLAMA_BASE_URL: {}", e);
                            return Err(e.into());
                        }
                    }
                } else {
                    provider
                };
                let provider = if let Some(key) = ollama_api_key {
                    provider.with_api_key(key)
                } else {
                    provider
                };
                info!("LLM provider configured: Ollama ({})", provider.base_url());
                // Connectivity check (non-blocking, best-effort)
                let provider = Arc::new(provider);
                let provider_clone = Arc::clone(&provider);
                tokio::spawn(async move {
                    match provider_clone.check_connectivity().await {
                        Ok(models) => {
                            if models.is_empty() {
                                info!("Ollama connected (no models pulled yet)");
                            } else {
                                info!("Ollama connected, available models: {}", models.join(", "));
                            }
                        }
                        Err(e) => {
                            warn!("Ollama connectivity check failed: {} (provider will remain configured, requests may fail until Ollama is reachable)", e);
                        }
                    }
                });
                Some(provider)
            }
            Err(e) => {
                warn!("Failed to configure Ollama provider: {}", e);
                None
            }
        }
    } else {
        None
    };

    // 6d. Gemini provider
    let google_api_key = std::env::var("GOOGLE_API_KEY").ok().or_else(|| {
        cfg.get("google")
            .and_then(|v| v.get("apiKey"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    });

    let google_base_url = std::env::var("GOOGLE_API_BASE_URL").ok().or_else(|| {
        cfg.get("google")
            .and_then(|v| v.get("baseUrl"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    });

    let gemini_provider: Option<Arc<dyn agent::LlmProvider>> = if let Some(key) = google_api_key {
        match agent::gemini::GeminiProvider::new(key) {
            Ok(provider) => {
                let provider = if let Some(url) = google_base_url {
                    match provider.with_base_url(url) {
                        Ok(p) => p,
                        Err(e) => {
                            warn!("Invalid GOOGLE_API_BASE_URL: {}", e);
                            return Err(e.into());
                        }
                    }
                } else {
                    provider
                };
                info!("LLM provider configured: Gemini");
                Some(Arc::new(provider))
            }
            Err(e) => {
                warn!("Failed to configure Gemini provider: {}", e);
                None
            }
        }
    } else {
        None
    };

    // 6e. Build multi-provider dispatcher
    let multi_provider = agent::provider::MultiProvider::new(anthropic_provider, openai_provider)
        .with_ollama(ollama_provider)
        .with_gemini(gemini_provider);

    let ws_state = if multi_provider.has_any_provider() {
        let inner = Arc::try_unwrap(ws_state)
            .map_err(|_| "WsServerState Arc should have single owner at startup")?;
        Arc::new(inner.with_llm_provider(Arc::new(multi_provider)))
    } else {
        info!("No LLM provider configured (set ANTHROPIC_API_KEY, OPENAI_API_KEY, GOOGLE_API_KEY, and/or configure Ollama to enable)");
        ws_state
    };

    // 6f. Register built-in console channel (for testing/demo)
    let ws_state = {
        let plugin_reg = Arc::new(plugins::PluginRegistry::new());
        plugin_reg.register_channel(
            "console".to_string(),
            Arc::new(channels::console::ConsoleChannel::new()),
        );
        ws_state.channel_registry().register(
            channels::ChannelInfo::new("console", "Console")
                .with_status(channels::ChannelStatus::Connected),
        );
        let inner = Arc::try_unwrap(ws_state)
            .map_err(|_| "WsServerState Arc should have single owner at startup")?;
        Arc::new(inner.with_plugin_registry(plugin_reg))
    };
    info!("Console channel registered");

    // 7. Build HTTP config and router
    let http_config = server::http::build_http_config(&cfg);
    let http_router = server::http::create_router_with_state(
        http_config,
        server::http::MiddlewareConfig::default(),
        Arc::new(hooks::registry::HookRegistry::new()),
        Arc::new(plugins::tools::ToolsRegistry::new()),
        ws_state.channel_registry().clone(),
        Some(ws_state.clone()),
    );

    // 8. Merge HTTP + WS into a single router
    let ws_router = Router::new()
        .route("/ws", get(server::ws::ws_handler))
        .with_state(ws_state.clone());

    let app = http_router.merge(ws_router);

    // 9. Create shutdown channel
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    // 10. Spawn background tasks

    // Delivery loop (if plugin registry is available)
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
    let config_watcher = config::watcher::ConfigWatcher::from_config(&cfg);
    {
        let config_path = config::get_config_path();
        info!("Config reload mode: {:?}", config_watcher.mode());
        config_watcher.start(config_path, shutdown_rx.clone());
    }

    // Bridge config watcher events to WS broadcasts
    {
        let mut config_rx = config_watcher.subscribe();
        let ws_state_for_config = ws_state.clone();
        let mut config_shutdown_rx = shutdown_rx.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    event = config_rx.recv() => {
                        match event {
                            Ok(config::watcher::ConfigEvent::Reloaded(result)) => {
                                server::ws::broadcast_config_changed(
                                    &ws_state_for_config,
                                    &result.mode,
                                );
                            }
                            Ok(config::watcher::ConfigEvent::ReloadFailed(_)) => {
                                // Failed reloads are already logged by the watcher;
                                // no broadcast needed (previous config stays active).
                            }
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

    // SIGHUP handler for manual config reload (Unix only)
    #[cfg(unix)]
    {
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
                        // Determine reload mode from current config
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
                            server::ws::broadcast_config_changed(
                                &ws_state_for_sighup,
                                &result.mode,
                            );
                            // Also notify any config event subscribers
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

    // Session retention cleanup loop
    let retention_config = sessions::retention::build_retention_config(&cfg);
    if retention_config.enabled {
        tokio::spawn(sessions::retention::retention_cleanup_loop(
            ws_state.session_store().clone(),
            retention_config,
            shutdown_rx.clone(),
        ));
    }

    // 11. Parse TLS configuration
    let tls_config = tls::parse_tls_config(&cfg);
    let tls_setup = if tls_config.enabled {
        match tls::setup_tls(&tls_config) {
            Ok(result) => {
                info!("TLS enabled");
                info!("TLS certificate: {}", result.cert_path.display());
                info!("TLS fingerprint (SHA-256): {}", result.fingerprint);
                Some(result)
            }
            Err(e) => {
                error!("Failed to set up TLS: {}", e);
                return Err(e.into());
            }
        }
    } else {
        None
    };

    // 12. Start mDNS discovery (after we know the port and TLS state)
    let discovery_config = discovery::build_discovery_config(&cfg);
    if discovery_config.mode.is_enabled() {
        let tls_fingerprint = tls_setup.as_ref().map(|t| t.fingerprint.clone());
        let device_name = discovery::resolve_service_name(&discovery_config);
        let discovery_props = discovery::ServiceProperties {
            version: env!("CARGO_PKG_VERSION").to_string(),
            fingerprint: tls_fingerprint,
            device_name,
        };
        tokio::spawn(discovery::run_mdns_lifecycle(
            discovery_config.clone(),
            port,
            discovery_props,
            shutdown_rx.clone(),
        ));
    }

    // 12b. Start Tailscale serve/funnel (if configured)
    let tailscale_config = tailscale::build_tailscale_config(&cfg, port);
    if tailscale_config.mode != tailscale::TailscaleMode::Off {
        let ts_shutdown_rx = shutdown_rx.clone();
        tokio::spawn(async move {
            match tailscale::run_tailscale_lifecycle(tailscale_config, ts_shutdown_rx).await {
                Ok(()) => info!("Tailscale lifecycle completed"),
                Err(e) => warn!("Tailscale lifecycle error: {}", e),
            }
        });
    }

    // 13. Startup banner
    info!("Carapace gateway v{}", env!("CARGO_PKG_VERSION"));
    let protocol = if tls_setup.is_some() { "https" } else { "http" };
    info!(
        "Bind mode: {} -> {protocol}://{}",
        server::bind::bind_mode_display_name(&resolved.mode),
        resolved.address
    );
    info!("Listening on {}", resolved.description);
    info!("State directory: {}", state_dir.display());
    if ws_state.llm_provider().is_some() {
        info!("LLM: enabled");
    } else {
        info!("LLM: disabled");
    }
    let cron_count = ws_state.cron_scheduler.list(true).len();
    if cron_count > 0 {
        info!("Cron jobs loaded: {}", cron_count);
    }
    if discovery_config.mode.is_enabled() {
        info!("mDNS discovery: {:?}", discovery_config.mode);
    }

    // 14. Start server with graceful shutdown
    if let Some(tls_result) = tls_setup {
        // TLS-enabled server using axum-server with rustls
        let rustls_config =
            axum_server::tls_rustls::RustlsConfig::from_config(tls_result.server_config);
        let addr = resolved.address;

        let handle = axum_server::Handle::new();
        let shutdown_handle = handle.clone();

        // Spawn a task that awaits the shutdown signal, performs cleanup,
        // then tells axum_server to gracefully shut down via its Handle API.
        tokio::spawn(async move {
            shutdown_signal(shutdown_tx, ws_state.clone()).await;
            shutdown_handle.graceful_shutdown(Some(Duration::from_secs(30)));
        });

        axum_server::bind_rustls(addr, rustls_config)
            .handle(handle)
            .serve(app.into_make_service_with_connect_info::<SocketAddr>())
            .await?;
    } else {
        // Plain TCP server (no TLS)
        let listener = tokio::net::TcpListener::bind(resolved.address).await?;

        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(shutdown_signal(shutdown_tx, ws_state.clone()))
        .await?;
    }

    info!("Gateway shut down");
    Ok(())
}

async fn shutdown_signal(
    tx: tokio::sync::watch::Sender<bool>,
    ws_state: Arc<server::ws::WsServerState>,
) {
    let reason = await_shutdown_trigger().await;
    info!("Shutdown signal received ({})", reason);

    // Notify background tasks to stop
    let _ = tx.send(true);

    // Broadcast shutdown event to all connected WebSocket clients
    server::ws::broadcast_shutdown(&ws_state, reason, None);

    // Flush dirty sessions to disk
    if let Err(e) = ws_state.session_store().flush_all() {
        error!("Failed to flush session store during shutdown: {}", e);
    }

    // Brief grace period for in-flight operations to complete
    tokio::time::sleep(Duration::from_millis(250)).await;
    info!("Graceful shutdown complete");
}

/// Wait for either Ctrl+C or SIGTERM (Unix only) and return a label for logging.
#[cfg(unix)]
async fn await_shutdown_trigger() -> &'static str {
    use tokio::signal::unix::{signal, SignalKind};

    match signal(SignalKind::terminate()) {
        Ok(mut sigterm) => {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => "ctrl-c",
                _ = sigterm.recv() => "SIGTERM",
            }
        }
        Err(e) => {
            warn!(
                "Failed to install SIGTERM handler: {}; falling back to Ctrl+C only",
                e
            );
            match tokio::signal::ctrl_c().await {
                Ok(()) => "ctrl-c",
                Err(e) => {
                    panic!("Failed to install Ctrl+C handler: {}", e);
                }
            }
        }
    }
}

/// On non-Unix platforms, only Ctrl+C is available.
#[cfg(not(unix))]
async fn await_shutdown_trigger() -> &'static str {
    match tokio::signal::ctrl_c().await {
        Ok(()) => "ctrl-c",
        Err(e) => {
            panic!("Failed to install Ctrl+C handler: {}", e);
        }
    }
}
