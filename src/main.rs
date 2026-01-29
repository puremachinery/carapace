#![allow(dead_code)]
#![allow(unused_imports)]

mod agent;
mod auth;
mod channels;
mod config;
mod credentials;
mod cron;
mod devices;
mod exec;
mod hooks;
mod logging;
mod media;
mod messages;
mod nodes;
mod plugins;
mod server;
mod sessions;
mod usage;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::routing::get;
use axum::Router;
use serde_json::Value;
use tracing::{info, warn};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Initialize logging
    let log_config = if std::env::var("MOLTBOT_DEV").is_ok() {
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

    // 6. Configure LLM provider
    let api_key = std::env::var("ANTHROPIC_API_KEY").ok().or_else(|| {
        cfg.get("anthropic")
            .and_then(|v| v.get("apiKey"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    });

    let base_url = std::env::var("ANTHROPIC_BASE_URL").ok().or_else(|| {
        cfg.get("anthropic")
            .and_then(|v| v.get("baseUrl"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    });

    let ws_state = if let Some(key) = api_key {
        match agent::anthropic::AnthropicProvider::new(key) {
            Ok(mut provider) => {
                if let Some(url) = base_url {
                    provider = provider.with_base_url(url);
                }
                info!("LLM provider configured (Anthropic)");
                let inner = Arc::try_unwrap(ws_state)
                    .expect("WsServerState Arc should have single owner at startup");
                Arc::new(inner.with_llm_provider(Arc::new(provider)))
            }
            Err(e) => {
                warn!("Failed to configure LLM provider: {}", e);
                ws_state
            }
        }
    } else {
        info!("No LLM provider configured (set ANTHROPIC_API_KEY to enable)");
        ws_state
    };

    // 6b. Register built-in console channel (for testing/demo)
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
            .expect("WsServerState Arc should have single owner at startup");
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

    // 11. Startup banner
    info!("Carapace gateway v{}", env!("CARGO_PKG_VERSION"));
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

    // 12. Start server with graceful shutdown
    let listener = tokio::net::TcpListener::bind(resolved.address).await?;

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal(shutdown_tx))
    .await?;

    info!("Gateway shut down");
    Ok(())
}

async fn shutdown_signal(tx: tokio::sync::watch::Sender<bool>) {
    tokio::signal::ctrl_c().await.ok();
    info!("Shutdown signal received");
    let _ = tx.send(true);
}
