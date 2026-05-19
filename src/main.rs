#![deny(clippy::disallowed_methods)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::routing::get;
use axum::Router;
use carapace::{
    channels, cli, config, discovery, gateway, hooks, logging, plugins, server, tailscale, tls,
    update,
};
use clap::Parser;
use serde::Deserialize;
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

        Some(Command::Plugins(sub)) => cli::handle_plugins(sub).await,

        Some(Command::Version) => {
            cli::handle_version();
            Ok(())
        }

        Some(Command::Backup { output, force }) => cli::handle_backup(output.as_deref(), force),

        Some(Command::Restore { path, force }) => cli::handle_restore(&path, force),

        Some(Command::Reset {
            sessions,
            cron,
            usage,
            memory,
            all,
            force,
        }) => cli::handle_reset(sessions, cron, usage, memory, all, force),

        Some(Command::Setup {
            force,
            provider,
            auth_mode,
        }) => cli::handle_setup(force, provider, auth_mode),

        Some(Command::Import { source, force }) => match source {
            cli::ImportSource::Openclaw => cli::handle_import_openclaw(force),
            cli::ImportSource::Opencode => cli::handle_import_opencode(force),
            cli::ImportSource::Aider => cli::handle_import_aider(force),
            cli::ImportSource::Nemoclaw => cli::handle_import_nemoclaw(force),
        },

        Some(Command::Pair { url, name, trust }) => {
            cli::handle_pair(&url, name.as_deref(), trust).await
        }

        Some(Command::Update { check, version }) => {
            cli::handle_update(check, version.as_deref()).await
        }

        Some(Command::Task(sub)) => {
            init_logging_from_env()?;
            cli::handle_task(sub).await
        }

        Some(Command::Matrix(sub)) => {
            init_logging_from_env()?;
            cli::handle_matrix(sub).await
        }

        Some(Command::Chat { new, port }) => {
            init_logging_from_env()?;
            cli::chat::handle_chat(new, port).await
        }

        Some(Command::Verify {
            outcome,
            port,
            discord_to,
            telegram_to,
            matrix_to,
        }) => cli::handle_verify(outcome, port, discord_to, telegram_to, matrix_to).await,

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

    let state_dir = server::startup::prepare_runtime_environment().await?;

    // Daemon PID + rekey-lock guard install used to live here so it
    // covered both TLS and non-TLS launch paths. Round 23 moved the
    // install into `run_server_with_config` (covers non-TLS daemon +
    // embedded chat + embedded verify) and `launch_tls_server`
    // (covers TLS daemon). Installing here would conflict with the
    // `run_server_with_config` install on the non-TLS path because
    // `flock(2)` on Linux treats two FDs from the same process as
    // independent locks (deadlock). The TLS path installs internally
    // before `axum_server::bind_rustls` returns.

    let gateway_registry = Arc::new(gateway::GatewayRegistry::new(state_dir.clone()));
    if let Err(e) = gateway_registry.load() {
        warn!(error = %e, "failed to load gateway registry");
    }
    let gateway_config = gateway::build_gateway_config(&cfg);

    let resolved = resolve_bind_config(&cfg)?;
    let tools_registry = Arc::new(plugins::tools::ToolsRegistry::with_config(&cfg));
    let hook_registry = Arc::new(hooks::registry::HookRegistry::new());

    let ws_state = server::startup::build_ws_state_with_runtime_dependencies(
        &cfg,
        &state_dir,
        tools_registry.clone(),
    )
    .await?;
    let ws_state = register_console_channel(ws_state)?;
    let ws_state = register_signal_channel_if_configured(ws_state, &cfg)?;
    let ws_state = register_telegram_channel_if_configured(ws_state, &cfg)?;
    let ws_state = register_discord_channel_if_configured(ws_state, &cfg)?;
    let ws_state = register_slack_channel_if_configured(ws_state, &cfg)?;

    server::ws::spawn_heartbeat_task(ws_state.clone());

    let http_config = server::http::build_http_config(&cfg)?;
    let tls_setup = setup_optional_tls(&cfg)?;

    log_startup_banner(&tls_setup, &resolved, &state_dir, &ws_state);

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    server::startup::spawn_background_tasks(&ws_state, &cfg, &shutdown_rx);
    spawn_network_services(&cfg, &tls_setup, resolved.address.port(), &shutdown_rx);
    spawn_signal_receive_loop_if_configured(&cfg, &ws_state, &shutdown_rx);
    spawn_telegram_receive_loop_if_configured(&cfg, &ws_state, &shutdown_rx);
    spawn_discord_gateway_loop_if_configured(&cfg, &ws_state, &shutdown_rx);
    spawn_gateway_lifecycle(gateway_registry.clone(), gateway_config, &shutdown_rx);

    if let Some(tls_result) = tls_setup {
        launch_tls_server(
            tls_result,
            http_config,
            &ws_state,
            shutdown_tx,
            resolved.address,
            hook_registry.clone(),
            tools_registry.clone(),
            state_dir.clone(),
            cfg.clone(),
        )
        .await?;
    } else {
        launch_non_tls_server(
            ws_state.clone(),
            http_config,
            cfg,
            resolved.address,
            shutdown_tx,
            hook_registry.clone(),
            tools_registry.clone(),
            state_dir.clone(),
        )
        .await?;
    }

    info!("Gateway shut down");
    Ok(())
}

/// Initialize logging based on the CARAPACE_DEV environment variable.
fn init_logging_from_env() -> Result<(), Box<dyn std::error::Error>> {
    let dev_mode = config::read_process_env("CARAPACE_DEV")
        .map(|v| !v.is_empty() && v != "0" && v.to_lowercase() != "false")
        .unwrap_or(false);
    let log_config = if dev_mode {
        logging::LogConfig::development()
    } else {
        logging::LogConfig::production()
    };
    logging::init_logging(log_config)?;
    if dev_mode {
        warn!("CARAPACE_DEV is enabled; using development logging");
    }
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

/// Register the built-in console channel (for testing/demo) on the WsServerState.
fn register_console_channel(
    ws_state: Arc<server::ws::WsServerState>,
) -> Result<Arc<server::ws::WsServerState>, Box<dyn std::error::Error>> {
    let Some(plugin_reg) = ws_state.plugin_registry() else {
        warn!("Plugin registry not configured; skipping console channel registration");
        return Ok(ws_state);
    };
    plugin_reg.try_register_channel(
        "console".to_string(),
        Arc::new(channels::console::ConsoleChannel::new()),
    )?;
    ws_state.channel_registry().register(
        channels::ChannelInfo::new("console", "Console")
            .with_status(channels::ChannelStatus::Connected),
    );
    info!("Console channel registered");
    Ok(ws_state)
}

/// Resolved Signal configuration (shared between registration and receive loop).
struct SignalConfig {
    base_url: String,
    phone_number: String,
}

/// Resolved Telegram configuration (shared between registration and dispatch).
struct TelegramConfig {
    base_url: String,
    bot_token: String,
}

/// Resolved Discord configuration (shared between registration and dispatch).
struct DiscordConfig {
    base_url: String,
    bot_token: String,
    gateway_url: String,
    gateway_intents: u64,
    gateway_enabled: bool,
}

/// Resolved Slack configuration (shared between registration and dispatch).
struct SlackConfig {
    base_url: String,
    bot_token: String,
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
        .or_else(|| config::read_config_env("SIGNAL_CLI_URL"))?;

    let phone_number = signal_cfg
        .and_then(|s| s.get("phoneNumber"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .or_else(|| config::read_config_env("SIGNAL_PHONE_NUMBER"))?;

    Some(SignalConfig {
        base_url,
        phone_number,
    })
}

/// Resolve Telegram configuration from config file and/or environment variables.
/// Returns `None` if Telegram is not configured or is explicitly disabled.
fn resolve_telegram_config(cfg: &Value) -> Option<TelegramConfig> {
    let telegram_cfg = cfg.get("telegram");

    // Explicit kill switch
    if telegram_cfg
        .and_then(|s| s.get("enabled"))
        .and_then(|v| v.as_bool())
        == Some(false)
    {
        return None;
    }

    let bot_token = telegram_cfg
        .and_then(|s| s.get("botToken"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .or_else(|| config::read_config_env("TELEGRAM_BOT_TOKEN"))?;

    let base_url = telegram_cfg
        .and_then(|s| s.get("baseUrl"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .or_else(|| config::read_config_env("TELEGRAM_BASE_URL"))
        .unwrap_or_else(|| channels::telegram::TELEGRAM_DEFAULT_API_BASE_URL.to_string());

    Some(TelegramConfig {
        base_url,
        bot_token,
    })
}

/// Resolve Discord configuration from config file and/or environment variables.
/// Returns `None` if Discord is not configured or is explicitly disabled.
fn resolve_discord_config(cfg: &Value) -> Option<DiscordConfig> {
    let discord_cfg = cfg.get("discord");

    // Explicit kill switch
    if discord_cfg
        .and_then(|s| s.get("enabled"))
        .and_then(|v| v.as_bool())
        == Some(false)
    {
        return None;
    }

    let bot_token = discord_cfg
        .and_then(|s| s.get("botToken"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .or_else(|| config::read_config_env("DISCORD_BOT_TOKEN"))?;

    let base_url = discord_cfg
        .and_then(|s| s.get("baseUrl"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .or_else(|| config::read_config_env("DISCORD_BASE_URL"))
        .unwrap_or_else(|| channels::discord::DISCORD_DEFAULT_API_BASE_URL.to_string());

    let gateway_url = discord_cfg
        .and_then(|s| s.get("gatewayUrl"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .or_else(|| config::read_config_env("DISCORD_GATEWAY_URL"))
        .unwrap_or_else(|| channels::discord_gateway::DEFAULT_DISCORD_GATEWAY_URL.to_string());

    let gateway_intents = discord_cfg
        .and_then(|s| s.get("gatewayIntents"))
        .and_then(|v| v.as_u64())
        .or_else(|| config::read_config_env("DISCORD_GATEWAY_INTENTS").and_then(|v| v.parse().ok()))
        .unwrap_or(37377);

    let gateway_enabled = discord_cfg
        .and_then(|s| s.get("gatewayEnabled"))
        .and_then(|v| v.as_bool())
        .unwrap_or(true);

    Some(DiscordConfig {
        base_url,
        bot_token,
        gateway_url,
        gateway_intents,
        gateway_enabled,
    })
}

/// Resolve Slack configuration from config file and/or environment variables.
/// Returns `None` if Slack is not configured or is explicitly disabled.
fn resolve_slack_config(cfg: &Value) -> Option<SlackConfig> {
    let slack_cfg = cfg.get("slack");

    // Explicit kill switch
    if slack_cfg
        .and_then(|s| s.get("enabled"))
        .and_then(|v| v.as_bool())
        == Some(false)
    {
        return None;
    }

    let bot_token = slack_cfg
        .and_then(|s| s.get("botToken"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .or_else(|| config::read_config_env("SLACK_BOT_TOKEN"))?;

    let base_url = slack_cfg
        .and_then(|s| s.get("baseUrl"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .or_else(|| config::read_config_env("SLACK_BASE_URL"))
        .unwrap_or_else(|| "https://slack.com/api".to_string());

    Some(SlackConfig {
        base_url,
        bot_token,
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
        registry.try_register_channel(
            "signal".to_string(),
            Arc::new(channels::signal::SignalChannel::new(
                sc.base_url.clone(),
                sc.phone_number.clone(),
            )),
        )?;
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

fn operator_ssrf_config_from_config(cfg: &Value) -> plugins::capabilities::SsrfConfig {
    plugins::capabilities::SsrfConfig {
        allow_tailscale: cfg
            .pointer("/plugins/sandbox/allow_tailscale")
            .and_then(Value::as_bool)
            .unwrap_or(false),
    }
}

/// Optionally register the Telegram channel plugin if configured.
fn register_telegram_channel_if_configured(
    ws_state: Arc<server::ws::WsServerState>,
    cfg: &Value,
) -> Result<Arc<server::ws::WsServerState>, Box<dyn std::error::Error>> {
    let tc = match resolve_telegram_config(cfg) {
        Some(c) => c,
        None => return Ok(ws_state),
    };

    let channel = channels::telegram::TelegramChannel::new(
        tc.base_url.clone(),
        tc.bot_token,
        operator_ssrf_config_from_config(cfg),
    );
    let validation = channel.validate();

    if let Some(registry) = ws_state.plugin_registry() {
        registry.try_register_channel("telegram".to_string(), Arc::new(channel))?;
    }

    ws_state.channel_registry().register(
        channels::ChannelInfo::new("telegram", "Telegram")
            .with_status(channels::ChannelStatus::Connected),
    );

    apply_channel_validation(ws_state.channel_registry(), "telegram", validation);

    info!(base_url = %tc.base_url, "Telegram channel registered");

    Ok(ws_state)
}

/// Optionally register the Discord channel plugin if configured.
fn register_discord_channel_if_configured(
    ws_state: Arc<server::ws::WsServerState>,
    cfg: &Value,
) -> Result<Arc<server::ws::WsServerState>, Box<dyn std::error::Error>> {
    let dc = match resolve_discord_config(cfg) {
        Some(c) => c,
        None => return Ok(ws_state),
    };

    let channel = channels::discord::DiscordChannel::new(
        dc.base_url.clone(),
        dc.bot_token,
        operator_ssrf_config_from_config(cfg),
    );
    let validation = channel.validate();

    if let Some(registry) = ws_state.plugin_registry() {
        registry.try_register_channel("discord".to_string(), Arc::new(channel))?;
    }

    ws_state.channel_registry().register(
        channels::ChannelInfo::new("discord", "Discord")
            .with_status(channels::ChannelStatus::Connected),
    );

    apply_channel_validation(ws_state.channel_registry(), "discord", validation);

    info!(base_url = %dc.base_url, "Discord channel registered");

    Ok(ws_state)
}

/// Optionally register the Slack channel plugin if configured.
fn register_slack_channel_if_configured(
    ws_state: Arc<server::ws::WsServerState>,
    cfg: &Value,
) -> Result<Arc<server::ws::WsServerState>, Box<dyn std::error::Error>> {
    let sc = match resolve_slack_config(cfg) {
        Some(c) => c,
        None => return Ok(ws_state),
    };

    let channel = channels::slack::SlackChannel::new(
        sc.base_url.clone(),
        sc.bot_token,
        operator_ssrf_config_from_config(cfg),
    );
    let validation = channel.validate();

    if let Some(registry) = ws_state.plugin_registry() {
        registry.try_register_channel("slack".to_string(), Arc::new(channel))?;
    }

    ws_state.channel_registry().register(
        channels::ChannelInfo::new("slack", "Slack")
            .with_status(channels::ChannelStatus::Connected),
    );

    apply_channel_validation(ws_state.channel_registry(), "slack", validation);

    info!(base_url = %sc.base_url, "Slack channel registered");

    Ok(ws_state)
}

fn apply_channel_validation(
    registry: &channels::ChannelRegistry,
    channel_id: &str,
    validation: channels::ChannelAuthResult,
) {
    let Err(error) = validation else {
        return;
    };

    let message = error.message().to_string();
    registry.set_error(channel_id, message.clone());

    if !error.is_auth() {
        registry.update_status(channel_id, channels::ChannelStatus::Connected);
    }

    warn!(channel = %channel_id, error = %message, "Channel validation failed");
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

const TELEGRAM_DELETE_WEBHOOK_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Deserialize)]
struct TelegramDeleteWebhookResponse {
    ok: bool,
    #[serde(default)]
    description: Option<String>,
}

fn build_telegram_delete_webhook_url(base_url: &str, bot_token: &str) -> String {
    let base = base_url.trim_end_matches('/');
    format!("{base}/bot{bot_token}/deleteWebhook?drop_pending_updates=false")
}

async fn clear_telegram_webhook_before_polling(base_url: &str, bot_token: &str) {
    let delete_url = build_telegram_delete_webhook_url(base_url, bot_token);
    let client = match reqwest::Client::builder()
        .timeout(TELEGRAM_DELETE_WEBHOOK_TIMEOUT)
        .build()
    {
        Ok(client) => client,
        Err(err) => {
            warn!(
                error = %err,
                "Failed to build Telegram deleteWebhook client; polling may not receive updates if a webhook is still registered"
            );
            return;
        }
    };

    match client.post(&delete_url).send().await {
        Ok(resp) => {
            let status = resp.status();
            // Cap the response body — the deleteWebhook response is a
            // tiny `{"ok": bool, "description": str}` payload; 32 KiB
            // is generous and bounds a hostile / MITM-attacked bot
            // endpoint from streaming unbounded bytes into RAM.
            let body_text =
                carapace::net_util::read_response_body_text_capped(resp, 32 * 1024).await;
            match body_text.and_then(|text| {
                serde_json::from_str::<TelegramDeleteWebhookResponse>(&text)
                    .map_err(std::io::Error::other)
            }) {
                Ok(payload) if status.is_success() && payload.ok => {
                    info!("Telegram deleteWebhook succeeded before enabling polling");
                }
                Ok(payload) => {
                    let description = payload
                        .description
                        .unwrap_or_else(|| "unknown Telegram API error".to_string());
                    warn!(
                        status = %status,
                        error = %description,
                        "Telegram deleteWebhook failed; polling may not receive updates if a webhook is still registered"
                    );
                }
                Err(err) => {
                    // SECURITY: the read_response_body_text_capped
                    // helper already strips URLs from any reqwest
                    // error before this point. Telegram bot URLs embed
                    // the bot TOKEN, so the URL must never leak.
                    warn!(
                        status = %status,
                        error = %err,
                        "Failed to parse Telegram deleteWebhook response; polling may not receive updates if a webhook is still registered"
                    );
                }
            }
        }
        Err(err) => {
            // SECURITY: scrub URL — bot token in URL.
            warn!(
                error = %err.without_url(),
                "Telegram deleteWebhook request failed; polling may not receive updates if a webhook is still registered"
            );
        }
    }
}

/// Spawn the Telegram long-polling receive loop when webhook auth is not configured.
fn spawn_telegram_receive_loop_if_configured(
    cfg: &Value,
    ws_state: &Arc<server::ws::WsServerState>,
    shutdown_rx: &tokio::sync::watch::Receiver<bool>,
) {
    let tc = match resolve_telegram_config(cfg) {
        Some(c) => c,
        None => return,
    };

    if channels::telegram_inbound::resolve_webhook_secret(cfg).is_some() {
        info!("Telegram webhook secret configured; inbound webhook mode enabled");
        return;
    }

    info!("Telegram webhook secret not configured; enabling long-polling fallback");
    let ws_state = ws_state.clone();
    let shutdown_rx = shutdown_rx.clone();
    tokio::spawn(async move {
        clear_telegram_webhook_before_polling(&tc.base_url, &tc.bot_token).await;
        channels::telegram_receive::telegram_receive_loop(
            tc.base_url,
            tc.bot_token,
            ws_state.clone(),
            ws_state.channel_registry().clone(),
            shutdown_rx,
        )
        .await;
    });
}

/// Spawn the Discord gateway loop if configured.
fn spawn_discord_gateway_loop_if_configured(
    cfg: &Value,
    ws_state: &Arc<server::ws::WsServerState>,
    shutdown_rx: &tokio::sync::watch::Receiver<bool>,
) {
    let dc = match resolve_discord_config(cfg) {
        Some(c) => c,
        None => return,
    };

    if !dc.gateway_enabled {
        return;
    }

    tokio::spawn(channels::discord_gateway::discord_gateway_loop(
        dc.gateway_url,
        dc.bot_token,
        dc.gateway_intents,
        ws_state.clone(),
        ws_state.channel_registry().clone(),
        shutdown_rx.clone(),
    ));
}

fn spawn_gateway_lifecycle(
    registry: Arc<gateway::GatewayRegistry>,
    config: gateway::GatewayConfig,
    shutdown_rx: &tokio::sync::watch::Receiver<bool>,
) {
    if !config.enabled {
        return;
    }

    let rx = shutdown_rx.clone();
    tokio::spawn(async move {
        if let Err(e) = gateway::run_gateway_lifecycle(registry, config, rx).await {
            warn!(error = %e, "remote gateway lifecycle exited with error");
        }
    });
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
#[allow(clippy::too_many_arguments)]
async fn launch_non_tls_server(
    ws_state: Arc<server::ws::WsServerState>,
    http_config: server::http::HttpConfig,
    cfg: Value,
    bind_address: SocketAddr,
    shutdown_tx: tokio::sync::watch::Sender<bool>,
    hook_registry: Arc<hooks::registry::HookRegistry>,
    tools_registry: Arc<plugins::tools::ToolsRegistry>,
    state_dir: std::path::PathBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    let server_config = server::startup::ServerConfig {
        ws_state: ws_state.clone(),
        http_config,
        middleware_config: server::http::MiddlewareConfig::default(),
        hook_registry,
        tools_registry,
        bind_address,
        raw_config: cfg,
        // Pass `state_dir` so `run_server_with_config` installs
        // `DaemonPidGuard` (acquires `state_dir/.matrix-rekey.lock`
        // and writes `daemon.pid`). Round 23's hoist documented this
        // path as covered, but `launch_non_tls_server` was still
        // passing `None` — the production non-TLS daemon (the
        // default deployment) ran without the lock, leaving the
        // round-21 TOCTOU window open against `cara matrix
        // rekey-store --new`.
        state_dir: Some(state_dir),
        spawn_background_tasks: false,
    };

    let handle = server::startup::run_server_with_config(server_config).await?;

    let reason = await_shutdown_trigger().await;
    info!("Shutdown signal received ({})", reason);
    let _ = shutdown_tx.send(true);
    handle.shutdown(reason).await;
    Ok(())
}

/// Load configuration from disk and validate it against the schema.
/// Returns the config on success, or an error if schema validation finds errors.
fn load_and_validate_config() -> Result<Value, Box<dyn std::error::Error>> {
    let cfg = match config::load_config() {
        Ok(cfg) => cfg,
        Err(err @ config::ConfigError::ValidationError { .. }) => return Err(Box::new(err)),
        Err(err) => {
            warn!("Failed to load config: {}, using defaults", err);
            Value::Object(serde_json::Map::new())
        }
    };

    let schema_issues = config::schema::validate_schema_for_runtime(&cfg);
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
#[allow(clippy::too_many_arguments)]
async fn launch_tls_server(
    tls_result: tls::TlsSetupResult,
    http_config: server::http::HttpConfig,
    ws_state: &Arc<server::ws::WsServerState>,
    shutdown_tx: tokio::sync::watch::Sender<bool>,
    addr: SocketAddr,
    hook_registry: Arc<hooks::registry::HookRegistry>,
    tools_registry: Arc<plugins::tools::ToolsRegistry>,
    state_dir: std::path::PathBuf,
    raw_config: Value,
) -> Result<(), Box<dyn std::error::Error>> {
    // Install the daemon PID + rekey-lock guard. The non-TLS path
    // gets this via `run_server_with_config`; the TLS path bypasses
    // that helper to use `axum_server::bind_rustls` directly, so we
    // install here. The guard drops when this function returns —
    // covers normal-shutdown, panic-unwind, and `?` early returns.
    let _daemon_pid_guard = server::startup::DaemonPidGuard::install(state_dir.clone())?;
    let shutdown_rx = shutdown_tx.subscribe();
    let ws_state = server::startup::register_matrix_channel_if_configured(
        ws_state.clone(),
        &raw_config,
        &state_dir,
        &shutdown_rx,
    )
    .await?;

    let http_router = server::http::create_router_with_state(
        http_config,
        server::http::MiddlewareConfig::default(),
        hook_registry,
        tools_registry,
        ws_state.channel_registry().clone(),
        Some(ws_state.clone()),
        true,
    );

    let ws_router = Router::new()
        .route("/ws", get(server::ws::ws_handler))
        .with_state(ws_state.clone());

    let app = http_router.merge(ws_router);

    let rustls_config =
        axum_server::tls_rustls::RustlsConfig::from_config(tls_result.server_config);

    let handle = axum_server::Handle::new();
    let shutdown_handle = handle.clone();
    let ws_state_clone = ws_state.clone();

    tokio::spawn(async move {
        shutdown_signal(shutdown_tx, ws_state_clone).await;
        shutdown_handle.graceful_shutdown(Some(Duration::from_secs(30)));
    });

    if let Err(err) = update::mark_pending_update_healthy(&state_dir) {
        match err {
            update::UpdateHealthyMarkerError::Marker { error, evidence } => {
                tracing::error!(
                    audit_event = "update_healthy_marker_failed",
                    phase = ?error.phase,
                    retryable = error.retryable,
                    evidence_recorded = evidence.is_some(),
                    error = %error.message,
                    "failed to mark pending update healthy after TLS server startup; rollback may run on next restart"
                );
            }
            update::UpdateHealthyMarkerError::EvidenceCleanup(error) => {
                tracing::warn!(
                    phase = ?error.phase,
                    retryable = error.retryable,
                    error = %error.message,
                    "pending update was marked healthy after TLS server startup, but stale update.status evidence could not be cleared"
                );
            }
        }
    }

    // On serve failure the DaemonPidGuard (and its rekey-lock) drops
    // via RAII while the Matrix actor is still live (shutdown_tx lives
    // in the spawned shutdown-signal task, not this stack frame, so the
    // actor's watch channel stays open). Explicitly shut it down so the
    // actor cannot hold the SQLite store FD open past the point where
    // the lock is released.
    //
    // Partial slowloris defense (header-dribble only): axum-server 0.8's
    // `bind_rustls` does NOT auto-apply the hyper `header_read_timeout`
    // that `axum::serve` installs in axum 0.8.8+. Without an explicit
    // timer + `header_read_timeout`, a hostile client can hold the TLS
    // listener's accepted connection open by dribbling header bytes
    // indefinitely, exhausting file descriptors and starving legitimate
    // handshakes.
    //
    // `header_read_timeout` is an HTTP/1-only Builder method; hyper's
    // HTTP/2 Builder has no equivalent and its `keep_alive_interval` is
    // disabled by default. axum-server's auto Builder classifies a
    // connection as HTTP/2 by reading the preface directly off the
    // wire (independent of TLS ALPN), so without `http1_only(true)` a
    // hostile client could shift the slowloris to a partial-preface
    // dribble that is not bounded by the HTTP/1 header timeout. Pin
    // HTTP/1 only — the WS control surface and JSON-RPC endpoints
    // carapace exposes are HTTP/1.1 by design. `Builder::http1()`
    // requires a `Timer` to be configured first; `hyper_util::rt::
    // TokioTimer` is the standard choice.
    //
    // RESIDUAL: hyper's HTTP/1 server has no body_read_timeout (open
    // upstream hyperium/hyper#2864) and no idle-keep-alive timeout.
    // After header_read_timeout is satisfied, a hostile peer can
    // (a) advertise `Content-Length: <large>` and dribble body bytes,
    // or (b) complete one valid request and hold the keep-alive
    // connection idle indefinitely. Neither is bounded by the knobs
    // above. The dominant carapace deployment binds to loopback /
    // tailscale-serve, so the practical exposure is narrow, but
    // public-internet deployments behind a forwarding proxy SHOULD
    // also set a reverse-proxy-level body timeout and an explicit
    // tcp_keepalive on the listener as backstops.
    let mut server = axum_server::bind_rustls(addr, rustls_config).http1_only();
    server
        .http_builder()
        .http1()
        .timer(hyper_util::rt::TokioTimer::new())
        .header_read_timeout(Duration::from_secs(30));
    if let Err(e) = server
        .handle(handle)
        .serve(app.into_make_service_with_connect_info::<SocketAddr>())
        .await
    {
        ws_state.shutdown_matrix_runtime().await;
        return Err(e.into());
    }

    Ok(())
}

async fn shutdown_signal(
    tx: tokio::sync::watch::Sender<bool>,
    ws_state: Arc<server::ws::WsServerState>,
) {
    let reason = await_shutdown_trigger().await;
    info!("Shutdown signal received ({})", reason);

    // SECURITY (R15 MEDIUM + R17 HIGH): once the first shutdown
    // signal lands, the graceful sequence can take ~20s worst case
    // (matrix 10s + activity 250ms + audit 5s + server 5s grace + 2s
    // drain). An impatient operator who hits Ctrl+C again to abort
    // cleanup had no escalation path because the signal handler
    // future already completed. Detach a watcher for the SECOND
    // signal that exits with code 130 (the conventional
    // SIGINT-aborted code).
    //
    // `std::process::exit` calls `libc::exit()` which does NOT run
    // Drop for the tokio runtime / mpsc senders / AuditDiskWriter /
    // BufWriter, so any in-flight audit fsync is aborted. Before
    // exit, run a bounded `AuditLog::shutdown_and_drain` (1.5s — well
    // below the operator's third-Ctrl+C threshold and inside the
    // channel-bounded write path) so the events buffered up to the
    // second signal still reach disk.
    tokio::spawn(async {
        let _ = await_shutdown_trigger().await;
        warn!("Second shutdown signal received; aborting graceful cleanup");
        let _ =
            crate::logging::audit::AuditLog::shutdown_and_drain(Duration::from_millis(1500)).await;
        std::process::exit(130);
    });

    // Notify background tasks to stop
    let _ = tx.send(true);

    // Broadcast shutdown event to all connected WebSocket clients
    server::ws::broadcast_shutdown(&ws_state, reason, None);

    ws_state.shutdown_matrix_runtime().await;

    // Flush dirty sessions to disk
    if let Err(e) = ws_state.session_store().flush_all() {
        error!("Failed to flush session store during shutdown: {}", e);
    }

    server::stop_plugin_services(&ws_state);

    // Brief grace period for in-flight operations to complete
    tokio::time::sleep(Duration::from_millis(250)).await;
    ws_state.shutdown_activity_service().await;

    // Round-9 shutdown-audit HIGH 1: drain the audit writer task so
    // pending entries reach disk before the tokio runtime drop
    // aborts the writer. The non-TLS path goes through
    // `ServerHandle::shutdown` which calls this; the TLS path drives
    // shutdown inline here and needs the same drain. Must run AFTER
    // every other shutdown step above so the events those steps
    // emit are still persisted.
    if !crate::logging::audit::AuditLog::shutdown_and_drain(Duration::from_secs(5)).await {
        warn!("audit writer did not drain within 5s; in-channel entries may be lost");
    }
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
