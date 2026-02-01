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

use cli::{Cli, Command, ConfigCommand, TlsCommand};

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

        Some(Command::Logs {
            lines,
            port,
            host,
            tls,
            trust,
            allow_plaintext,
        }) => cli::handle_logs(&host, port, lines, tls, trust, allow_plaintext).await,

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

        Some(Command::Tls(sub)) => {
            match sub {
                TlsCommand::InitCa { output } => {
                    cli::handle_tls_init_ca(output.as_deref())?;
                }
                TlsCommand::IssueCert {
                    node_id,
                    ca_dir,
                    output,
                } => {
                    cli::handle_tls_issue_cert(&node_id, ca_dir.as_deref(), output.as_deref())?;
                }
                TlsCommand::RevokeCert {
                    fingerprint,
                    node_id,
                    ca_dir,
                    reason,
                } => {
                    cli::handle_tls_revoke_cert(
                        &fingerprint,
                        &node_id,
                        ca_dir.as_deref(),
                        reason.as_deref(),
                    )?;
                }
                TlsCommand::ShowCa { ca_dir } => {
                    cli::handle_tls_show_ca(ca_dir.as_deref())?;
                }
            }
            Ok(())
        }
    }
}

/// Run the gateway server (the original `main` logic).
async fn run_server() -> Result<(), Box<dyn std::error::Error>> {
    init_logging_from_env()?;
    let cfg = load_and_validate_config()?;

    let state_dir = server::ws::resolve_state_dir();
    std::fs::create_dir_all(&state_dir)?;
    std::fs::create_dir_all(state_dir.join("sessions"))?;
    std::fs::create_dir_all(state_dir.join("cron"))?;
    logging::audit::AuditLog::init(state_dir.clone()).await;

    let resolved = resolve_bind_config(&cfg)?;
    let ws_state = server::ws::build_ws_state_from_config().await?;
    let ws_state = configure_ws_with_llm(ws_state, &cfg)?;
    let ws_state = register_console_channel(ws_state)?;
    let ws_state = register_signal_channel_if_configured(ws_state, &cfg)?;

    let http_config = server::http::build_http_config(&cfg)?;
    let tls_setup = setup_optional_tls(&cfg)?;

    log_startup_banner(&tls_setup, &resolved, &state_dir, &ws_state);

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    spawn_network_services(&cfg, &tls_setup, resolved.address.port(), &shutdown_rx);
    spawn_signal_receive_loop_if_configured(&cfg, &ws_state, &shutdown_rx);

    if let Some(tls_result) = tls_setup {
        launch_tls_server(
            tls_result,
            http_config,
            &ws_state,
            &cfg,
            &shutdown_rx,
            shutdown_tx,
            resolved.address,
        )
        .await?;
    } else {
        launch_non_tls_server(ws_state, http_config, cfg, resolved.address).await?;
    }

    info!("Gateway shut down");
    Ok(())
}

/// Initialize logging based on the MOLTBOT_DEV environment variable.
fn init_logging_from_env() -> Result<(), Box<dyn std::error::Error>> {
    let log_config = if std::env::var("MOLTBOT_DEV")
        .map(|v| !v.is_empty() && v != "0" && v.to_lowercase() != "false")
        .unwrap_or(false)
    {
        logging::LogConfig::development()
    } else {
        logging::LogConfig::production()
    };
    logging::init_logging(log_config)?;
    Ok(())
}

/// Parse the bind address and port from the gateway configuration section.
fn resolve_bind_config(
    cfg: &Value,
) -> Result<server::bind::ResolvedBind, Box<dyn std::error::Error>> {
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
    Ok(server::bind::resolve_bind_with_metadata(&bind_mode, port)?)
}

/// Configure LLM providers on the WsServerState via the provider factory.
fn configure_ws_with_llm(
    ws_state: Arc<server::ws::WsServerState>,
    cfg: &Value,
) -> Result<Arc<server::ws::WsServerState>, Box<dyn std::error::Error>> {
    match agent::factory::build_providers(cfg)? {
        Some(multi_provider) => {
            let inner = Arc::try_unwrap(ws_state)
                .map_err(|_| "WsServerState Arc should have single owner at startup")?;
            Ok(Arc::new(inner.with_llm_provider(Arc::new(multi_provider))))
        }
        None => {
            info!("No LLM provider configured (set ANTHROPIC_API_KEY, OPENAI_API_KEY, GOOGLE_API_KEY, and/or configure Ollama to enable)");
            Ok(ws_state)
        }
    }
}

/// Register the built-in console channel (for testing/demo) on the WsServerState.
fn register_console_channel(
    ws_state: Arc<server::ws::WsServerState>,
) -> Result<Arc<server::ws::WsServerState>, Box<dyn std::error::Error>> {
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
    info!("Console channel registered");
    Ok(Arc::new(inner.with_plugin_registry(plugin_reg)))
}

/// Resolved Signal configuration (shared between registration and receive loop).
struct SignalConfig {
    base_url: String,
    phone_number: String,
}

/// Resolve Signal configuration from config file and/or environment variables.
/// Returns `None` if Signal is not configured or is explicitly disabled.
///
/// Activates when both a base URL and phone number are provided (via config or
/// env vars). The `enabled: false` field is an explicit kill switch to disable
/// without removing config.
fn resolve_signal_config(cfg: &Value) -> Option<SignalConfig> {
    let signal_cfg = cfg.get("signal");

    // Explicit kill switch
    if signal_cfg
        .and_then(|s| s.get("enabled"))
        .and_then(|v| v.as_bool())
        == Some(false)
    {
        return None;
    }

    let base_url = signal_cfg
        .and_then(|s| s.get("baseUrl"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .or_else(|| std::env::var("SIGNAL_CLI_URL").ok())?;

    let phone_number = signal_cfg
        .and_then(|s| s.get("phoneNumber"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .or_else(|| std::env::var("SIGNAL_PHONE_NUMBER").ok())?;

    Some(SignalConfig {
        base_url,
        phone_number,
    })
}

/// Optionally register the Signal channel plugin if configured.
///
/// If configured, creates a `SignalChannel` and registers it in both the plugin registry
/// and channel registry.
fn register_signal_channel_if_configured(
    ws_state: Arc<server::ws::WsServerState>,
    cfg: &Value,
) -> Result<Arc<server::ws::WsServerState>, Box<dyn std::error::Error>> {
    let sc = match resolve_signal_config(cfg) {
        Some(c) => c,
        None => return Ok(ws_state),
    };

    if let Some(registry) = ws_state.plugin_registry() {
        registry.register_channel(
            "signal".to_string(),
            Arc::new(channels::signal::SignalChannel::new(
                sc.base_url.clone(),
                sc.phone_number.clone(),
            )),
        );
    }

    ws_state.channel_registry().register(
        channels::ChannelInfo::new("signal", "Signal")
            .with_status(channels::ChannelStatus::Connecting),
    );

    info!(
        base_url = %sc.base_url,
        phone = %sc.phone_number,
        "Signal channel registered"
    );

    Ok(ws_state)
}

/// Spawn the Signal receive loop if the channel is configured.
fn spawn_signal_receive_loop_if_configured(
    cfg: &Value,
    ws_state: &Arc<server::ws::WsServerState>,
    shutdown_rx: &tokio::sync::watch::Receiver<bool>,
) {
    let sc = match resolve_signal_config(cfg) {
        Some(c) => c,
        None => return,
    };

    tokio::spawn(channels::signal_receive::signal_receive_loop(
        sc.base_url,
        sc.phone_number,
        ws_state.clone(),
        ws_state.channel_registry().clone(),
        shutdown_rx.clone(),
    ));
}

/// Parse TLS configuration and set up certificates if enabled.
#[allow(clippy::cognitive_complexity)]
fn setup_optional_tls(
    cfg: &Value,
) -> Result<Option<tls::TlsSetupResult>, Box<dyn std::error::Error>> {
    let tls_config = tls::parse_tls_config(cfg);
    if !tls_config.enabled {
        return Ok(None);
    }
    match tls::setup_tls(&tls_config) {
        Ok(result) => {
            info!("TLS enabled");
            info!("TLS certificate: {}", result.cert_path.display());
            info!("TLS fingerprint (SHA-256): {}", result.fingerprint);
            Ok(Some(result))
        }
        Err(e) => {
            error!("Failed to set up TLS: {}", e);
            Err(e.into())
        }
    }
}

/// Launch the non-TLS server path via run_server_with_config.
async fn launch_non_tls_server(
    ws_state: Arc<server::ws::WsServerState>,
    http_config: server::http::HttpConfig,
    cfg: Value,
    bind_address: SocketAddr,
) -> Result<(), Box<dyn std::error::Error>> {
    let server_config = server::startup::ServerConfig {
        ws_state: ws_state.clone(),
        http_config,
        middleware_config: server::http::MiddlewareConfig::default(),
        hook_registry: Arc::new(hooks::registry::HookRegistry::new()),
        tools_registry: Arc::new(plugins::tools::ToolsRegistry::new()),
        bind_address,
        raw_config: cfg,
        spawn_background_tasks: true,
    };

    let handle = server::startup::run_server_with_config(server_config).await?;

    let reason = await_shutdown_trigger().await;
    info!("Shutdown signal received ({})", reason);
    handle.shutdown().await;
    Ok(())
}

/// Load configuration from disk and validate it against the schema.
/// Returns the config on success, or an error if schema validation finds errors.
fn load_and_validate_config() -> Result<Value, Box<dyn std::error::Error>> {
    let cfg = config::load_config().unwrap_or_else(|e| {
        warn!("Failed to load config: {}, using defaults", e);
        Value::Object(serde_json::Map::new())
    });

    let schema_issues = config::schema::validate_schema(&cfg);
    let mut has_errors = false;
    for issue in &schema_issues {
        match issue.severity {
            config::schema::Severity::Error => {
                error!("Config error at {}: {}", issue.path, issue.message);
                has_errors = true;
            }
            config::schema::Severity::Warning => {
                warn!("Config warning at {}: {}", issue.path, issue.message);
            }
        }
    }
    if has_errors {
        return Err("Configuration contains errors — aborting startup".into());
    }

    Ok(cfg)
}

/// Log the startup banner with version, bind info, state dir, and LLM/cron status.
#[allow(clippy::cognitive_complexity)]
fn log_startup_banner(
    tls_setup: &Option<tls::TlsSetupResult>,
    resolved: &server::bind::ResolvedBind,
    state_dir: &std::path::Path,
    ws_state: &Arc<server::ws::WsServerState>,
) {
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
}

/// Spawn mDNS discovery and Tailscale serve/funnel background tasks.
fn spawn_network_services(
    cfg: &Value,
    tls_setup: &Option<tls::TlsSetupResult>,
    port: u16,
    shutdown_rx: &tokio::sync::watch::Receiver<bool>,
) {
    let discovery_config = discovery::build_discovery_config(cfg);
    if discovery_config.mode.is_enabled() {
        let tls_fingerprint = tls_setup.as_ref().map(|t| t.fingerprint.clone());
        let device_name = discovery::resolve_service_name(&discovery_config);
        let discovery_props = discovery::ServiceProperties {
            version: env!("CARGO_PKG_VERSION").to_string(),
            fingerprint: tls_fingerprint,
            device_name,
        };
        info!("mDNS discovery: {:?}", discovery_config.mode);
        tokio::spawn(discovery::run_mdns_lifecycle(
            discovery_config,
            port,
            discovery_props,
            shutdown_rx.clone(),
        ));
    }

    let tailscale_config = tailscale::build_tailscale_config(cfg, port);
    if tailscale_config.mode != tailscale::TailscaleMode::Off {
        let ts_shutdown_rx = shutdown_rx.clone();
        tokio::spawn(async move {
            match tailscale::run_tailscale_lifecycle(tailscale_config, ts_shutdown_rx).await {
                Ok(()) => info!("Tailscale lifecycle completed"),
                Err(e) => warn!("Tailscale lifecycle error: {}", e),
            }
        });
    }
}

/// Assemble and serve the TLS-enabled server path.
async fn launch_tls_server(
    tls_result: tls::TlsSetupResult,
    http_config: server::http::HttpConfig,
    ws_state: &Arc<server::ws::WsServerState>,
    cfg: &Value,
    shutdown_rx: &tokio::sync::watch::Receiver<bool>,
    shutdown_tx: tokio::sync::watch::Sender<bool>,
    addr: SocketAddr,
) -> Result<(), Box<dyn std::error::Error>> {
    let http_router = server::http::create_router_with_state(
        http_config,
        server::http::MiddlewareConfig::default(),
        Arc::new(hooks::registry::HookRegistry::new()),
        Arc::new(plugins::tools::ToolsRegistry::new()),
        ws_state.channel_registry().clone(),
        Some(ws_state.clone()),
        true,
    );

    let ws_router = Router::new()
        .route("/ws", get(server::ws::ws_handler))
        .with_state(ws_state.clone());

    let app = http_router.merge(ws_router);

    // Spawn background tasks
    server::startup::spawn_background_tasks(ws_state, cfg, shutdown_rx);

    let rustls_config =
        axum_server::tls_rustls::RustlsConfig::from_config(tls_result.server_config);

    let handle = axum_server::Handle::new();
    let shutdown_handle = handle.clone();
    let ws_state_clone = ws_state.clone();

    tokio::spawn(async move {
        shutdown_signal(shutdown_tx, ws_state_clone).await;
        shutdown_handle.graceful_shutdown(Some(Duration::from_secs(30)));
    });

    axum_server::bind_rustls(addr, rustls_config)
        .handle(handle)
        .serve(app.into_make_service_with_connect_info::<SocketAddr>())
        .await?;

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
