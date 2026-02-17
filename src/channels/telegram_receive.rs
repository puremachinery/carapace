//! Telegram inbound receive loop.
//!
//! Uses Telegram Bot API long polling (`getUpdates`) as an inbound fallback
//! when webhook secret configuration is absent.

use std::sync::Arc;
use std::time::Duration;

use serde::Deserialize;
use tracing::{debug, info, warn};

use crate::channels::{inbound, telegram_inbound, ChannelRegistry, ChannelStatus};
use crate::server::ws::WsServerState;

/// Long-poll timeout passed to Telegram getUpdates.
const POLL_TIMEOUT_SECS: u64 = 30;
/// Client-side request timeout (must exceed poll timeout).
const REQUEST_TIMEOUT: Duration = Duration::from_secs(POLL_TIMEOUT_SECS + 10);
/// Backoff between failed poll attempts.
const ERROR_BACKOFF: Duration = Duration::from_secs(3);

#[derive(Debug, Deserialize)]
struct TelegramGetUpdatesResponse {
    ok: bool,
    #[serde(default)]
    result: Vec<telegram_inbound::TelegramUpdate>,
    #[serde(default)]
    description: Option<String>,
}

/// Run Telegram long-polling receive loop.
pub async fn telegram_receive_loop(
    base_url: String,
    bot_token: String,
    state: Arc<WsServerState>,
    channel_registry: Arc<ChannelRegistry>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    let client = reqwest::Client::builder()
        .timeout(REQUEST_TIMEOUT)
        .build()
        .expect("failed to build Telegram receive HTTP client");
    let updates_url = build_get_updates_url(&base_url, &bot_token);

    info!(
        base_url = %base_url,
        "Telegram receive loop started (long-polling fallback)"
    );

    let mut offset: Option<i64> = None;
    let mut consecutive_errors: u32 = 0;

    loop {
        if *shutdown.borrow() {
            info!("Telegram receive loop shutting down");
            break;
        }

        let mut had_error = false;
        let request_url = build_poll_request_url(&updates_url, offset);
        match client.get(&request_url).send().await {
            Ok(resp) if resp.status().is_success() => {
                match resp.json::<TelegramGetUpdatesResponse>().await {
                    Ok(payload) => {
                        if !payload.ok {
                            had_error = true;
                            consecutive_errors += 1;
                            let description = payload.description.unwrap_or_else(|| {
                                "telegram getUpdates returned ok=false".to_string()
                            });
                            if consecutive_errors <= 3 {
                                warn!("Telegram getUpdates returned error: {}", description);
                            }
                            channel_registry.set_error("telegram", description);
                        } else {
                            if consecutive_errors > 0 {
                                info!(
                                    "Telegram receive loop recovered after {} errors",
                                    consecutive_errors
                                );
                                consecutive_errors = 0;
                            }
                            channel_registry.update_status("telegram", ChannelStatus::Connected);

                            for update in payload.result {
                                offset = next_offset_after_update(offset, update.update_id);
                                let Some(inbound_message) =
                                    telegram_inbound::extract_inbound(&update)
                                else {
                                    continue;
                                };
                                if let Err(err) = inbound::dispatch_inbound_text(
                                    &state,
                                    "telegram",
                                    &inbound_message.sender_id,
                                    &inbound_message.chat_id,
                                    &inbound_message.text,
                                    Some(inbound_message.chat_id.clone()),
                                ) {
                                    warn!("Telegram inbound dispatch failed: {}", err);
                                }
                            }
                        }
                    }
                    Err(err) => {
                        had_error = true;
                        consecutive_errors += 1;
                        if consecutive_errors <= 3 {
                            warn!("Telegram getUpdates response parse failed: {}", err);
                        }
                        channel_registry.set_error(
                            "telegram",
                            "failed to parse getUpdates response".to_string(),
                        );
                    }
                }
            }
            Ok(resp) => {
                had_error = true;
                consecutive_errors += 1;
                let status = resp.status();
                if consecutive_errors <= 3 {
                    warn!("Telegram getUpdates HTTP {}", status);
                }
                channel_registry.set_error("telegram", format!("HTTP {}", status));
            }
            Err(err) => {
                had_error = true;
                consecutive_errors += 1;
                let message = classify_transport_error(&err).to_string();
                if consecutive_errors <= 3 {
                    warn!("Telegram getUpdates request failed: {}", message);
                } else if consecutive_errors == 4 {
                    warn!(
                        "Telegram receive errors continuing (suppressing further logs until recovery)"
                    );
                }
                channel_registry.set_error("telegram", message);
            }
        }

        if had_error {
            tokio::select! {
                _ = tokio::time::sleep(ERROR_BACKOFF) => {}
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        info!("Telegram receive loop shutting down");
                        break;
                    }
                }
            }
        } else {
            debug!("Telegram long-poll request completed successfully");
        }
    }
}

fn build_get_updates_url(base_url: &str, bot_token: &str) -> String {
    let base = base_url.trim_end_matches('/');
    format!("{base}/bot{bot_token}/getUpdates")
}

fn build_poll_request_url(base_url: &str, offset: Option<i64>) -> String {
    let mut url = format!("{base_url}?timeout={POLL_TIMEOUT_SECS}");
    if let Some(offset) = offset {
        url.push_str("&offset=");
        url.push_str(&offset.to_string());
    }
    url
}

fn next_offset_after_update(current: Option<i64>, update_id: Option<i64>) -> Option<i64> {
    let Some(update_id) = update_id else {
        return current;
    };
    let next = update_id.saturating_add(1);
    Some(current.map_or(next, |current_value| current_value.max(next)))
}

fn classify_transport_error(err: &reqwest::Error) -> &'static str {
    if err.is_timeout() {
        "request timeout"
    } else if err.is_connect() {
        "connection error"
    } else {
        "request failed"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_get_updates_url_trims_trailing_slash() {
        let url = build_get_updates_url("https://api.telegram.org/", "token");
        assert_eq!(url, "https://api.telegram.org/bottoken/getUpdates");
    }

    #[test]
    fn test_build_poll_request_url_with_offset() {
        let url = build_poll_request_url("https://api.telegram.org/bot123/getUpdates", Some(77));
        assert_eq!(
            url,
            "https://api.telegram.org/bot123/getUpdates?timeout=30&offset=77"
        );
    }

    #[test]
    fn test_build_poll_request_url_without_offset() {
        let url = build_poll_request_url("https://api.telegram.org/bot123/getUpdates", None);
        assert_eq!(url, "https://api.telegram.org/bot123/getUpdates?timeout=30");
    }

    #[test]
    fn test_next_offset_after_update_monotonic() {
        let mut offset = None;
        offset = next_offset_after_update(offset, Some(10));
        assert_eq!(offset, Some(11));
        offset = next_offset_after_update(offset, Some(9));
        assert_eq!(offset, Some(11));
        offset = next_offset_after_update(offset, Some(15));
        assert_eq!(offset, Some(16));
    }

    #[test]
    fn test_next_offset_after_update_ignores_missing_update_id() {
        assert_eq!(next_offset_after_update(None, None), None);
        assert_eq!(next_offset_after_update(Some(7), None), Some(7));
    }
}
