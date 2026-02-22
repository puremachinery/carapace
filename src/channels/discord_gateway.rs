//! Discord Gateway inbound message loop.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::sync::Mutex;
use tokio_tungstenite::tungstenite::Message;
use tracing::{debug, error, info, warn};

use crate::channels::inbound::dispatch_inbound_text;
use crate::channels::{ChannelRegistry, ChannelStatus};
use crate::server::ws::WsServerState;

type WsStream =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;
type WsWrite = futures_util::stream::SplitSink<WsStream, Message>;

#[derive(Debug, Deserialize)]
struct GatewayPayload {
    op: u64,
    #[serde(default)]
    d: Option<Value>,
    #[serde(default)]
    s: Option<u64>,
    #[serde(default)]
    t: Option<String>,
}

/// Default Discord gateway URL.
pub const DEFAULT_DISCORD_GATEWAY_URL: &str = "wss://gateway.discord.gg/?v=10&encoding=json";

/// Run the Discord gateway loop (reconnects with backoff).
pub async fn discord_gateway_loop(
    gateway_url: String,
    bot_token: String,
    intents: u64,
    state: Arc<WsServerState>,
    channel_registry: Arc<ChannelRegistry>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    let mut backoff = Duration::from_secs(1);

    loop {
        if *shutdown.borrow() {
            break;
        }

        channel_registry.update_status("discord", ChannelStatus::Connecting);
        match tokio_tungstenite::connect_async(&gateway_url).await {
            Ok((ws_stream, _)) => {
                backoff = Duration::from_secs(1);
                if let Err(err) = run_discord_session(
                    ws_stream,
                    bot_token.clone(),
                    intents,
                    state.clone(),
                    channel_registry.clone(),
                    &mut shutdown,
                )
                .await
                {
                    channel_registry.set_error("discord", err);
                }
            }
            Err(e) => {
                channel_registry.set_error("discord", format!("gateway connect failed: {e}"));
            }
        }

        if *shutdown.borrow() {
            break;
        }

        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(Duration::from_secs(30));
    }

    channel_registry.update_status("discord", ChannelStatus::Disconnected);
    info!("Discord gateway loop exited");
}

async fn run_discord_session(
    ws_stream: WsStream,
    bot_token: String,
    intents: u64,
    state: Arc<WsServerState>,
    channel_registry: Arc<ChannelRegistry>,
    shutdown: &mut tokio::sync::watch::Receiver<bool>,
) -> Result<(), String> {
    let (write, mut read) = ws_stream.split();
    let write = Arc::new(Mutex::new(write));
    let seq = Arc::new(AtomicU64::new(0));
    let seq_set = Arc::new(AtomicBool::new(false));

    let mut heartbeat_task: Option<tokio::task::JoinHandle<()>> = None;
    let mut identified = false;
    let mut bot_user_id: Option<String> = None;

    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    break;
                }
            }
            msg = read.next() => {
                let msg = match msg {
                    Some(Ok(msg)) => msg,
                    Some(Err(e)) => return Err(format!("gateway read failed: {e}")),
                    None => break,
                };

                let text = match msg {
                    Message::Text(text) => text,
                    Message::Close(_) => break,
                    _ => continue,
                };

                let payload: GatewayPayload = match serde_json::from_str(&text) {
                    Ok(payload) => payload,
                    Err(e) => {
                        debug!("Discord gateway payload parse error: {}", e);
                        continue;
                    }
                };

                if let Some(s) = payload.s {
                    seq.store(s, Ordering::Relaxed);
                    seq_set.store(true, Ordering::Relaxed);
                }

                match payload.op {
                    10 => {
                        let interval_ms = payload
                            .d
                            .as_ref()
                            .and_then(|d| d.get("heartbeat_interval"))
                            .and_then(|v| v.as_u64())
                            .unwrap_or(45000);
                        if heartbeat_task.is_none() {
                            heartbeat_task = Some(spawn_heartbeat_task(
                                write.clone(),
                                seq.clone(),
                                seq_set.clone(),
                                Duration::from_millis(interval_ms),
                            ));
                        }
                        if !identified {
                            send_identify(&write, &bot_token, intents).await?;
                            identified = true;
                        }
                    }
                    0 => {
                        if let Some(ref t) = payload.t {
                            if t == "READY" {
                                bot_user_id = payload
                                    .d
                                    .as_ref()
                                    .and_then(|d| d.get("user"))
                                    .and_then(|u| u.get("id"))
                                    .and_then(|v| v.as_str())
                                    .map(|s| s.to_string());
                                channel_registry.update_status("discord", ChannelStatus::Connected);
                                info!("Discord gateway READY");
                            } else if t == "MESSAGE_CREATE" {
                                if let Some(ref d) = payload.d {
                                    handle_message_create(&state, d, bot_user_id.as_deref()).await;
                                }
                            }
                        }
                    }
                    1 => {
                        let current_seq = current_seq(seq.as_ref(), seq_set.as_ref());
                        send_heartbeat(&write, current_seq).await?;
                    }
                    7 => {
                        warn!("Discord gateway requested reconnect");
                        break;
                    }
                    9 => {
                        warn!("Discord gateway invalid session");
                        identified = false;
                        tokio::time::sleep(Duration::from_secs(5)).await;
                        send_identify(&write, &bot_token, intents).await?;
                    }
                    11 => {
                        // Heartbeat ACK
                    }
                    _ => {}
                }
            }
        }
    }

    if let Some(task) = heartbeat_task.take() {
        task.abort();
    }

    Ok(())
}

fn current_seq(seq: &AtomicU64, seq_set: &AtomicBool) -> Option<u64> {
    if seq_set.load(Ordering::Relaxed) {
        Some(seq.load(Ordering::Relaxed))
    } else {
        None
    }
}

fn spawn_heartbeat_task(
    write: Arc<Mutex<WsWrite>>,
    seq: Arc<AtomicU64>,
    seq_set: Arc<AtomicBool>,
    interval: Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        // Skip the immediate tick to align with the advertised heartbeat interval.
        ticker.tick().await;
        loop {
            ticker.tick().await;
            let current = current_seq(seq.as_ref(), seq_set.as_ref());
            if send_heartbeat(&write, current).await.is_err() {
                break;
            }
        }
    })
}

async fn send_identify(
    write: &Arc<Mutex<WsWrite>>,
    bot_token: &str,
    intents: u64,
) -> Result<(), String> {
    let token = format_bot_token(bot_token);
    let payload = json!({
        "op": 2,
        "d": {
            "token": token,
            "intents": intents,
            "properties": {
                "$os": std::env::consts::OS,
                "$browser": "carapace",
                "$device": "carapace"
            }
        }
    });
    send_json(write, &payload).await
}

async fn send_heartbeat(write: &Arc<Mutex<WsWrite>>, seq: Option<u64>) -> Result<(), String> {
    let payload = json!({
        "op": 1,
        "d": seq
    });
    send_json(write, &payload).await
}

async fn send_json(write: &Arc<Mutex<WsWrite>>, payload: &Value) -> Result<(), String> {
    let text = serde_json::to_string(payload).map_err(|e| e.to_string())?;
    let mut writer = write.lock().await;
    writer
        .send(Message::Text(text.into()))
        .await
        .map_err(|e| e.to_string())
}

async fn handle_message_create(
    state: &Arc<WsServerState>,
    data: &Value,
    bot_user_id: Option<&str>,
) {
    let author = match data.get("author") {
        Some(a) => a,
        None => return,
    };

    if author.get("bot").and_then(|v| v.as_bool()) == Some(true) {
        return;
    }

    let sender_id = match author.get("id").and_then(|v| v.as_str()) {
        Some(id) => id,
        None => return,
    };

    if bot_user_id == Some(sender_id) {
        return;
    }

    let channel_id = match data.get("channel_id").and_then(|v| v.as_str()) {
        Some(id) => id,
        None => return,
    };

    let content = match data.get("content").and_then(|v| v.as_str()) {
        Some(text) if !text.is_empty() => text,
        _ => return,
    };

    if let Err(err) = dispatch_inbound_text(
        state,
        "discord",
        sender_id,
        channel_id,
        content,
        Some(channel_id.to_string()),
    )
    .await
    {
        error!("Discord inbound dispatch failed: {}", err);
    }
}

fn format_bot_token(token: &str) -> String {
    if token.trim_start().starts_with("Bot ") {
        token.to_string()
    } else {
        format!("Bot {}", token)
    }
}
