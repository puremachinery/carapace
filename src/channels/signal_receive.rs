//! Signal inbound receive loop.
//!
//! Connects to the signal-cli-rest-api WebSocket stream at `{base_url}/v1/receive/{number}`
//! (rewriting `http`→`ws` and `https`→`wss`) and routes inbound messages in real time into the chat pipeline.
//! Requires `signal-cli-rest-api` running in JSON-RPC mode (`MODE=json-rpc-native` or `MODE=json-rpc`).

use std::sync::Arc;
use std::time::{Duration, Instant};

use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use serde_json::Value;
use tokio_tungstenite::tungstenite::Message;
use tracing::{debug, error, info, warn};

use crate::channels::signal::validate_signal_url;
use crate::channels::{ChannelRegistry, ChannelStatus};
use crate::plugins::{ChannelPluginInstance, ReadReceiptContext, TypingContext};
use crate::server::ws::WsServerState;

/// Initial reconnect backoff delay.
const INITIAL_RECONNECT_BACKOFF: Duration = Duration::from_secs(1);
/// Maximum reconnect backoff delay.
const MAX_RECONNECT_BACKOFF: Duration = Duration::from_secs(30);
const SIGNAL_RECEIPT_CAPABILITY_RETRY_BACKOFF: Duration = Duration::from_secs(30);
/// Timeout for WebSocket connection attempt.
const SIGNAL_WS_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// An envelope returned by `GET /v1/receive/{number}`.
#[derive(Debug, Deserialize)]
pub struct SignalEnvelope {
    /// Source phone number (e.g. "+15559876543").
    #[serde(default, rename = "sourceNumber")]
    pub source_number: Option<String>,

    /// Source UUID (used when phone number privacy is enabled).
    #[serde(default, rename = "sourceUuid")]
    pub source_uuid: Option<String>,

    /// Timestamp of the message.
    #[serde(default)]
    pub timestamp: Option<u64>,

    /// The data message payload (present for normal text messages).
    #[serde(default, rename = "dataMessage")]
    pub data_message: Option<SignalDataMessage>,
}

/// The `dataMessage` payload inside an envelope.
#[derive(Debug, Deserialize)]
pub struct SignalDataMessage {
    /// Text body of the message.
    #[serde(default)]
    pub message: Option<String>,

    /// Timestamp of the message.
    #[serde(default)]
    pub timestamp: Option<u64>,

    /// Group info, if this is a group message.
    #[serde(default, rename = "groupInfo")]
    pub group_info: Option<SignalGroupInfo>,
}

impl SignalEnvelope {
    /// Returns the effective source identifier for the envelope.
    ///
    /// Returns `sourceNumber` or `sourceUuid`, so the result is not guaranteed
    /// to be a phone number.
    pub fn effective_source_number(&self) -> Option<&str> {
        self.source_number
            .as_deref()
            .filter(|s| !s.trim().is_empty())
            .or_else(|| self.source_uuid.as_deref().filter(|s| !s.trim().is_empty()))
    }
}

/// Group metadata on a Signal message.
#[derive(Debug, Deserialize)]
pub struct SignalGroupInfo {
    /// Group identifier (base64).
    #[serde(default, rename = "groupId")]
    pub group_id: Option<String>,
}

fn deserialize_signal_envelope_item(item: Value) -> Result<SignalEnvelope, serde_json::Error> {
    let envelope_value = item.get("envelope").unwrap_or(&item);
    SignalEnvelope::deserialize(envelope_value)
}

fn resolve_signal_sender_and_peer(
    sender: &str,
    data_message: &SignalDataMessage,
) -> Option<(String, String)> {
    let sender = sender.trim();
    if sender.is_empty() {
        return None;
    }
    let group_id = data_message
        .group_info
        .as_ref()
        .and_then(|group| group.group_id.as_deref())
        .map(str::trim)
        .filter(|id| !id.is_empty());
    // Signal outbound currently supports direct messages only; reject any
    // group recipient until the send path grows real group-send support.
    if group_id.is_some() {
        return None;
    }
    Some((sender.to_string(), sender.to_string()))
}

fn signal_group_id(data_message: &SignalDataMessage) -> Option<&str> {
    data_message
        .group_info
        .as_ref()
        .and_then(|group| group.group_id.as_deref())
        .map(str::trim)
        .filter(|id| !id.is_empty())
}

fn build_signal_read_receipt_context(
    envelope: &SignalEnvelope,
    data_message: &SignalDataMessage,
    sender: &str,
) -> Option<ReadReceiptContext> {
    // Signal read receipts identify the original message by its data-message
    // timestamp. Fall back to the outer envelope timestamp only for message
    // shapes where the data-message timestamp is absent.
    data_message
        .timestamp
        .or(envelope.timestamp)
        .map(|timestamp| ReadReceiptContext {
            recipient: sender.to_string(),
            timestamp: Some(timestamp),
            ..Default::default()
        })
}

fn read_receipt_context_for_signal_run(
    envelope: &SignalEnvelope,
    data_message: &SignalDataMessage,
    sender: &str,
    carapace_manages_read_receipts: bool,
) -> Option<ReadReceiptContext> {
    if !carapace_manages_read_receipts {
        return None;
    }

    build_signal_read_receipt_context(envelope, data_message, sender)
}

fn sanitize_signal_receive_transport_error(error: &dyn std::fmt::Display) -> String {
    let raw = error.to_string();
    static URL_RE: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
        regex::Regex::new(r#"(?i)\b(?:https?|wss?)://[^\s<>()"']*[^\s<>()"':,.;]"#)
            .expect("valid URL regex")
    });
    static SENSITIVE_RE: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
        regex::Regex::new(r"(%2B|\+)\d{5,}").expect("valid sensitive phone regex")
    });
    let without_url = URL_RE.replace_all(&raw, "[redacted]");
    SENSITIVE_RE
        .replace_all(&without_url, "[redacted]")
        .to_string()
}

fn build_receive_url(
    base_url: &url::Url,
    phone_number: &str,
    carapace_manages_read_receipts: bool,
) -> url::Url {
    let mut url = base_url.clone();
    let ws_scheme = match url.scheme() {
        "http" | "ws" => "ws",
        "https" | "wss" => "wss",
        _ => "ws",
    };
    url.set_scheme(ws_scheme).expect("valid WebSocket scheme");
    let encoded_phone_number = urlencoding::encode(phone_number);
    let path_prefix = url.path().trim_end_matches('/');
    let receive_path = if path_prefix.is_empty() {
        format!("/v1/receive/{}", encoded_phone_number)
    } else {
        format!("{}/v1/receive/{}", path_prefix, encoded_phone_number)
    };
    url.set_path(&receive_path);
    let filtered_query_pairs = url
        .query_pairs()
        .into_owned()
        .filter(|(key, _)| key != "send_read_receipts" && key != "max_messages")
        .collect::<Vec<_>>();
    url.set_query(None);
    if !filtered_query_pairs.is_empty() || carapace_manages_read_receipts {
        let mut query_pairs = url.query_pairs_mut();
        for (key, value) in filtered_query_pairs {
            query_pairs.append_pair(&key, &value);
        }
        if carapace_manages_read_receipts {
            query_pairs.append_pair("send_read_receipts", "false");
        }
    }
    url
}

struct SignalReceivePollSnapshot {
    receive_url: url::Url,
    suppressed_upstream_auto_receipts: bool,
}

impl SignalReceivePollSnapshot {
    fn carapace_manages_read_receipts(&self) -> bool {
        self.suppressed_upstream_auto_receipts
    }
}

#[derive(Debug, Default)]
struct SignalReadReceiptCapabilityCache {
    plugin_key: Option<usize>,
    read_receipts_supported: Option<bool>,
    retry_after: Option<Instant>,
}

impl SignalReadReceiptCapabilityCache {
    fn clear(&mut self) {
        *self = Self::default();
    }

    fn update_plugin(&mut self, plugin_key: usize) {
        if self.plugin_key != Some(plugin_key) {
            self.plugin_key = Some(plugin_key);
            self.read_receipts_supported = None;
            self.retry_after = None;
        }
    }
}

fn signal_plugin_cache_key(plugin: &Arc<dyn ChannelPluginInstance>) -> usize {
    Arc::as_ptr(plugin) as *const () as usize
}

async fn can_manage_signal_read_receipts(
    activity_policy: &crate::channels::activity::ChannelActivityPolicy,
    activity_service: &crate::channels::activity::ActivityService,
    state: &WsServerState,
    capability_cache: &mut SignalReadReceiptCapabilityCache,
) -> bool {
    if !activity_policy.read_receipts.enabled {
        return false;
    }

    let Some(plugin_registry) = state.plugin_registry() else {
        capability_cache.clear();
        return false;
    };
    let Some(plugin) = plugin_registry.get_channel("signal") else {
        capability_cache.clear();
        return false;
    };
    capability_cache.update_plugin(signal_plugin_cache_key(&plugin));

    let supported = if let Some(supported) = capability_cache.read_receipts_supported {
        supported
    } else {
        if capability_cache
            .retry_after
            .is_some_and(|retry_after| Instant::now() < retry_after)
        {
            return false;
        }

        match tokio::task::spawn_blocking(move || plugin.get_capabilities()).await {
            Ok(Ok(capabilities)) => {
                capability_cache.read_receipts_supported = Some(capabilities.read_receipts);
                capability_cache.retry_after = None;
                if !capabilities.read_receipts {
                    activity_service.warn_unsupported_feature("signal", "read_receipts");
                }
                capabilities.read_receipts
            }
            Ok(Err(err)) => {
                capability_cache.retry_after =
                    Some(Instant::now() + SIGNAL_RECEIPT_CAPABILITY_RETRY_BACKOFF);
                warn!(
                    error = %err,
                    "failed to load Signal capabilities while deciding whether to suppress upstream auto-read-receipts"
                );
                false
            }
            Err(err) => {
                capability_cache.retry_after =
                    Some(Instant::now() + SIGNAL_RECEIPT_CAPABILITY_RETRY_BACKOFF);
                warn!(
                    error = %err,
                    "Signal capability worker failed while deciding whether to suppress upstream auto-read-receipts"
                );
                false
            }
        }
    };

    supported && activity_service.can_accept_read_receipt_ownership("signal")
}

async fn snapshot_signal_receive_poll(
    base_url: &url::Url,
    phone_number: &str,
    activity_policy: &crate::channels::activity::ChannelActivityPolicy,
    state: &WsServerState,
    activity_service: &crate::channels::activity::ActivityService,
    capability_cache: &mut SignalReadReceiptCapabilityCache,
) -> SignalReceivePollSnapshot {
    let carapace_manages_read_receipts =
        can_manage_signal_read_receipts(activity_policy, activity_service, state, capability_cache)
            .await;
    SignalReceivePollSnapshot {
        receive_url: build_receive_url(base_url, phone_number, carapace_manages_read_receipts),
        suppressed_upstream_auto_receipts: carapace_manages_read_receipts,
    }
}

fn record_signal_parse_failure<E: std::fmt::Display>(
    context: &str,
    err: E,
    consecutive_parse_errors: &mut u32,
) {
    *consecutive_parse_errors += 1;
    if *consecutive_parse_errors <= 3 {
        warn!("Failed to parse Signal {}: {}", context, err);
    } else if *consecutive_parse_errors == 4 {
        warn!("Signal receive parse errors continuing (suppressing further logs until recovery)");
    }
}

/// Run the Signal receive loop.
///
/// Connects to the signal-cli-rest-api WebSocket stream at `ws://{base_url}/v1/receive/{number}`
/// (or `wss://...`), receives pushed inbound message envelopes in real time, and routes
/// them into the chat pipeline. Updates channel registry status on success/failure and
/// reconnects with exponential backoff on disconnect. Exits when the shutdown signal fires.
///
/// Requires `signal-cli-rest-api` running in JSON-RPC mode (`MODE=json-rpc-native` or `MODE=json-rpc`).
pub async fn signal_receive_loop(
    base_url: String,
    phone_number: String,
    state: Arc<WsServerState>,
    channel_registry: Arc<ChannelRegistry>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    let base_url = match validate_signal_url(&base_url, "signal receive", true) {
        Ok(url) => url,
        Err(err) => {
            error!(phone_number = %phone_number, error = %err, "Signal receive loop configuration is invalid");
            channel_registry.set_error("signal", err);
            channel_registry.update_status("signal", ChannelStatus::Error);
            return;
        }
    };

    info!(phone_number = %phone_number, "Signal receive loop started");
    let mut config_rx = crate::config::subscribe_config_changes();
    config_rx.borrow_and_update();
    let mut config_closed = false;
    let mut activity_policy =
        crate::channels::activity::load_channel_activity_policy_async("signal").await;
    let mut capability_cache = SignalReadReceiptCapabilityCache::default();

    let mut backoff = INITIAL_RECONNECT_BACKOFF;
    let mut consecutive_errors: u32 = 0;
    let mut consecutive_parse_errors: u32 = 0;

    loop {
        if *shutdown.borrow() {
            info!("Signal receive loop shutting down");
            break;
        }

        let mut poll_snapshot = snapshot_signal_receive_poll(
            &base_url,
            &phone_number,
            &activity_policy,
            state.as_ref(),
            state.activity_service(),
            &mut capability_cache,
        )
        .await;

        let ws_url_str = poll_snapshot.receive_url.as_str();
        channel_registry.update_status("signal", ChannelStatus::Connecting);

        let mut ws_config = tokio_tungstenite::tungstenite::protocol::WebSocketConfig::default();
        ws_config.max_message_size = Some(16 * 1024 * 1024);
        ws_config.max_frame_size = Some(16 * 1024 * 1024);

        let maybe_ws_stream = tokio::select! {
            biased;
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    info!("Signal receive loop shutting down");
                    break;
                }
                continue;
            }
            changed = config_rx.changed(), if !config_closed => {
                if changed.is_err() {
                    warn!("Signal receive loop config subscription closed unexpectedly");
                    config_closed = true;
                } else {
                    activity_policy =
                        crate::channels::activity::load_channel_activity_policy_async("signal").await;
                    capability_cache.clear();
                }
                continue;
            }
            connect_res = tokio::time::timeout(
                SIGNAL_WS_CONNECT_TIMEOUT,
                tokio_tungstenite::connect_async_with_config(ws_url_str, Some(ws_config), false),
            ) => {
                match connect_res {
                    Ok(Ok((ws_stream, _response))) => {
                        if consecutive_errors > 0 {
                            info!(
                                "Signal receive loop recovered after {} errors",
                                consecutive_errors
                            );
                            consecutive_errors = 0;
                        }
                        backoff = INITIAL_RECONNECT_BACKOFF;
                        channel_registry.update_status("signal", ChannelStatus::Connected);
                        Some(ws_stream)
                    }
                    Ok(Err(err)) => {
                        consecutive_errors += 1;
                        let sanitized = sanitize_signal_receive_transport_error(&err);
                        if consecutive_errors <= 3 {
                            warn!(error = %sanitized, "Signal WebSocket connect failed");
                        } else if consecutive_errors == 4 {
                            warn!(
                                "Signal WebSocket connect errors continuing (suppressing further logs until recovery)"
                            );
                        }
                        channel_registry.set_error("signal", sanitized);
                        None
                    }
                    Err(_) => {
                        consecutive_errors += 1;
                        let err_msg = format!(
                            "Signal WebSocket connect timed out after {:?}",
                            SIGNAL_WS_CONNECT_TIMEOUT
                        );
                        let sanitized = sanitize_signal_receive_transport_error(&err_msg);
                        if consecutive_errors <= 3 {
                            warn!(error = %sanitized, "Signal WebSocket connect failed");
                        } else if consecutive_errors == 4 {
                            warn!(
                                "Signal WebSocket connect errors continuing (suppressing further logs until recovery)"
                            );
                        }
                        channel_registry.set_error("signal", sanitized);
                        None
                    }
                }
            }
        };

        if let Some(ws_stream) = maybe_ws_stream {
            let (mut ws_writer, mut ws_reader) = ws_stream.split();

            loop {
                tokio::select! {
                    biased;
                    _ = shutdown.changed() => {
                        if *shutdown.borrow() {
                            info!("Signal receive loop shutting down");
                            let _ = ws_writer.send(Message::Close(None)).await;
                            channel_registry.update_status("signal", ChannelStatus::Disconnected);
                            return;
                        }
                    }
                    changed = config_rx.changed(), if !config_closed => {
                        if changed.is_err() {
                            warn!("Signal receive loop config subscription closed unexpectedly");
                            config_closed = true;
                            continue;
                        }
                        activity_policy =
                            crate::channels::activity::load_channel_activity_policy_async("signal").await;
                        capability_cache.clear();
                        let new_snapshot = snapshot_signal_receive_poll(
                            &base_url,
                            &phone_number,
                            &activity_policy,
                            state.as_ref(),
                            state.activity_service(),
                            &mut capability_cache,
                        )
                        .await;
                        if new_snapshot.suppressed_upstream_auto_receipts != poll_snapshot.suppressed_upstream_auto_receipts {
                            info!("Signal read receipt suppression policy changed; reconnecting WebSocket stream");
                            let _ = ws_writer.send(Message::Close(None)).await;
                            break;
                        } else {
                            poll_snapshot = new_snapshot;
                        }
                    }
                    msg = ws_reader.next() => {
                        match msg {
                            Some(Ok(Message::Text(text))) => {
                                match serde_json::from_str::<Value>(&text) {
                                    Ok(Value::Array(items)) => {
                                        let mut had_parse_error = false;
                                        for item in items {
                                            match deserialize_signal_envelope_item(item) {
                                                Ok(envelope) => {
                                                    let carapace_manages_read_receipts =
                                                        poll_snapshot.carapace_manages_read_receipts();
                                                    process_envelope(
                                                        &envelope,
                                                        &state,
                                                        carapace_manages_read_receipts,
                                                    )
                                                    .await;
                                                }
                                                Err(e) => {
                                                    had_parse_error = true;
                                                    record_signal_parse_failure(
                                                        "envelope item",
                                                        &e,
                                                        &mut consecutive_parse_errors,
                                                    );
                                                }
                                            }
                                        }
                                        if !had_parse_error && consecutive_parse_errors > 0 {
                                            info!(
                                                "Signal receive parse handling recovered after {} errors",
                                                consecutive_parse_errors
                                            );
                                            consecutive_parse_errors = 0;
                                        }
                                    }
                                    Ok(item @ Value::Object(_)) => {
                                        match deserialize_signal_envelope_item(item) {
                                            Ok(envelope) => {
                                                if consecutive_parse_errors > 0 {
                                                    info!(
                                                        "Signal receive parse handling recovered after {} errors",
                                                        consecutive_parse_errors
                                                    );
                                                    consecutive_parse_errors = 0;
                                                }
                                                let carapace_manages_read_receipts =
                                                    poll_snapshot.carapace_manages_read_receipts();
                                                process_envelope(
                                                    &envelope,
                                                    &state,
                                                    carapace_manages_read_receipts,
                                                )
                                                .await;
                                            }
                                            Err(e) => {
                                                record_signal_parse_failure(
                                                    "envelope item",
                                                    &e,
                                                    &mut consecutive_parse_errors,
                                                );
                                            }
                                        }
                                    }
                                    Ok(_) => {
                                        debug!("Ignoring non-object non-array Signal WebSocket payload");
                                    }
                                    Err(e) => {
                                        record_signal_parse_failure(
                                            "receive payload JSON",
                                            &e,
                                            &mut consecutive_parse_errors,
                                        );
                                    }
                                }
                            }
                            Some(Ok(Message::Ping(payload))) => {
                                if let Err(e) = ws_writer.send(Message::Pong(payload)).await {
                                    warn!(error = %e, "Failed to respond to Signal WebSocket ping with pong");
                                }
                            }
                            Some(Ok(Message::Pong(_))) => {}
                            Some(Ok(Message::Close(frame))) => {
                                info!(frame = ?frame, "Signal WebSocket stream closed by remote");
                                break;
                            }
                            Some(Ok(Message::Binary(_))) => {
                                debug!("Ignoring binary Signal WebSocket message");
                            }
                            Some(Ok(Message::Frame(_))) => {}
                            Some(Err(err)) => {
                                let sanitized = sanitize_signal_receive_transport_error(&err);
                                warn!(error = %sanitized, "Signal WebSocket stream error");
                                channel_registry.set_error("signal", sanitized);
                                break;
                            }
                            None => {
                                info!("Signal WebSocket stream ended");
                                break;
                            }
                        }
                    }
                }
            }
            if channel_registry.get_status("signal") != Some(ChannelStatus::Error) {
                channel_registry.update_status("signal", ChannelStatus::Disconnected);
            }
        }

        if *shutdown.borrow() {
            break;
        }

        tokio::select! {
            _ = tokio::time::sleep(backoff) => {
                backoff = (backoff * 2).min(MAX_RECONNECT_BACKOFF);
            }
            changed = config_rx.changed(), if !config_closed => {
                if changed.is_err() {
                    config_closed = true;
                } else {
                    activity_policy =
                        crate::channels::activity::load_channel_activity_policy_async("signal").await;
                    capability_cache.clear();
                }
            }
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    break;
                }
            }
        }
    }

    channel_registry.update_status("signal", ChannelStatus::Disconnected);
    info!("Signal receive loop shutting down");
}

/// Process a single inbound Signal envelope by routing it into the chat pipeline.
async fn process_envelope(
    envelope: &SignalEnvelope,
    state: &Arc<WsServerState>,
    carapace_manages_read_receipts: bool,
) {
    let data_message = match &envelope.data_message {
        Some(dm) => dm,
        None => return, // Not a data message (e.g., receipt, typing indicator)
    };

    let sender = envelope
        .effective_source_number()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let read_receipt_context = sender.and_then(|sender| {
        read_receipt_context_for_signal_run(
            envelope,
            data_message,
            sender,
            carapace_manages_read_receipts,
        )
    });

    let text = match &data_message.message {
        Some(t) if !t.is_empty() => t,
        _ => return, // No text content
    };

    if signal_group_id(data_message).is_some() {
        warn!("Ignoring Signal group message: Signal outbound currently supports direct messages only");
        return;
    }

    let sender = match sender {
        Some(sender) => sender.to_string(),
        None => {
            warn!("Ignoring Signal envelope with empty sender ID");
            return;
        }
    };
    let Some((sender, peer_id)) = resolve_signal_sender_and_peer(&sender, data_message) else {
        warn!("Ignoring Signal envelope because sender normalization failed");
        return;
    };
    let had_read_receipt_context = read_receipt_context.is_some();
    let read_receipt = read_receipt_context.and_then(|ctx| {
        state
            .activity_service()
            .try_claim_read_receipt("signal", ctx)
    });

    debug!(
        sender = %sender,
        text_len = text.len(),
        "Signal inbound message"
    );
    if carapace_manages_read_receipts && !had_read_receipt_context {
        warn!(
            sender = %sender,
            "Signal read receipts are enabled but this message did not include a timestamp; Carapace cannot acknowledge it explicitly"
        );
    } else if carapace_manages_read_receipts && read_receipt.is_none() {
        warn!(
            sender = %sender,
            "Signal read receipts are enabled but Carapace could not claim bounded receipt ownership for this message; leaving it unread"
        );
    }

    let options = crate::channels::inbound::InboundDispatchOptions {
        typing_context: Some(TypingContext {
            to: peer_id.clone(),
            ..Default::default()
        }),
        claimed_read_receipt: read_receipt,
        ..Default::default()
    };

    match crate::channels::inbound::dispatch_inbound_text_with_options(
        state,
        "signal",
        &sender,
        &peer_id,
        text,
        Some(peer_id.clone()),
        options,
    )
    .await
    {
        Ok(result) => {
            debug!(
                run_id = %result.run_id,
                sender = %sender,
                "Signal agent run dispatched"
            );
        }
        Err(err) => {
            error!(sender = %sender, error = %err, "Failed to dispatch Signal message");
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    use axum::extract::{OriginalUri, Path, State};
    use axum::routing::get;
    use axum::Router;
    use parking_lot::Mutex;
    use tokio::sync::Notify;

    use super::*;
    use crate::plugins::{
        BindingError, ChannelCapabilities, ChannelInfo, ChannelPluginInstance, PluginRegistry,
    };
    use crate::server::ws::WsServerConfig;
    use crate::tasks::TaskQueue;
    use crate::test_support::agent::StaticTestProvider;

    fn test_state_with_provider(enabled: bool) -> Arc<WsServerState> {
        let state = WsServerState::new(WsServerConfig::default());
        if enabled {
            Arc::new(state.with_llm_provider(Arc::new(StaticTestProvider)))
        } else {
            Arc::new(state)
        }
    }

    struct MockSignalReadReceiptChannel {
        mark_read_count: AtomicU32,
        mark_read_notify: Arc<Notify>,
    }

    impl MockSignalReadReceiptChannel {
        fn new(mark_read_notify: Arc<Notify>) -> Self {
            Self {
                mark_read_count: AtomicU32::new(0),
                mark_read_notify,
            }
        }
    }

    impl ChannelPluginInstance for MockSignalReadReceiptChannel {
        fn get_info(&self) -> Result<ChannelInfo, BindingError> {
            Ok(ChannelInfo {
                id: "signal".to_string(),
                label: "Signal".to_string(),
                selection_label: "Signal".to_string(),
                docs_path: String::new(),
                blurb: String::new(),
                order: 0,
            })
        }

        fn get_capabilities(&self) -> Result<ChannelCapabilities, BindingError> {
            Ok(ChannelCapabilities {
                read_receipts: true,
                ..Default::default()
            })
        }

        fn send_text(
            &self,
            _ctx: crate::plugins::OutboundContext,
        ) -> Result<crate::plugins::DeliveryResult, BindingError> {
            Ok(crate::plugins::DeliveryResult {
                ok: true,
                message_id: None,
                error: None,
                retryability: crate::plugins::Retryability::Terminal,
                conversation_id: None,
                to_jid: None,
                poll_id: None,
                error_kind: None,
            })
        }

        fn send_media(
            &self,
            _ctx: crate::plugins::OutboundContext,
        ) -> Result<crate::plugins::DeliveryResult, BindingError> {
            Ok(crate::plugins::DeliveryResult {
                ok: true,
                message_id: None,
                error: None,
                retryability: crate::plugins::Retryability::Terminal,
                conversation_id: None,
                to_jid: None,
                poll_id: None,
                error_kind: None,
            })
        }

        fn mark_read(&self, _ctx: ReadReceiptContext) -> Result<(), BindingError> {
            self.mark_read_count.fetch_add(1, Ordering::Relaxed);
            self.mark_read_notify.notify_one();
            Ok(())
        }
    }

    fn test_state_with_provider_and_signal_plugin() -> Arc<WsServerState> {
        let plugin_registry = Arc::new(PluginRegistry::new());
        plugin_registry.register_channel(
            "signal".to_string(),
            Arc::new(MockSignalReadReceiptChannel::new(Arc::new(Notify::new()))),
        );
        Arc::new(
            WsServerState::new(WsServerConfig::default())
                .with_llm_provider(Arc::new(StaticTestProvider))
                .with_plugin_registry(plugin_registry),
        )
    }

    struct MockSignalNoReadReceiptChannel;

    impl ChannelPluginInstance for MockSignalNoReadReceiptChannel {
        fn get_info(&self) -> Result<ChannelInfo, BindingError> {
            Ok(ChannelInfo {
                id: "signal".to_string(),
                label: "Signal".to_string(),
                selection_label: "Signal".to_string(),
                docs_path: String::new(),
                blurb: String::new(),
                order: 0,
            })
        }

        fn get_capabilities(&self) -> Result<ChannelCapabilities, BindingError> {
            Ok(ChannelCapabilities::default())
        }

        fn send_text(
            &self,
            _ctx: crate::plugins::OutboundContext,
        ) -> Result<crate::plugins::DeliveryResult, BindingError> {
            Ok(crate::plugins::DeliveryResult {
                ok: true,
                message_id: None,
                error: None,
                retryability: crate::plugins::Retryability::Terminal,
                conversation_id: None,
                to_jid: None,
                poll_id: None,
                error_kind: None,
            })
        }

        fn send_media(
            &self,
            _ctx: crate::plugins::OutboundContext,
        ) -> Result<crate::plugins::DeliveryResult, BindingError> {
            Ok(crate::plugins::DeliveryResult {
                ok: true,
                message_id: None,
                error: None,
                retryability: crate::plugins::Retryability::Terminal,
                conversation_id: None,
                to_jid: None,
                poll_id: None,
                error_kind: None,
            })
        }
    }

    fn test_state_with_provider_and_signal_plugin_without_receipts() -> Arc<WsServerState> {
        let plugin_registry = Arc::new(PluginRegistry::new());
        plugin_registry.register_channel(
            "signal".to_string(),
            Arc::new(MockSignalNoReadReceiptChannel),
        );
        Arc::new(
            WsServerState::new(WsServerConfig::default())
                .with_llm_provider(Arc::new(StaticTestProvider))
                .with_plugin_registry(plugin_registry),
        )
    }

    #[derive(Clone)]
    struct SignalReceiveTestServerState {
        requests: Arc<Mutex<Vec<String>>>,
        responses: Arc<Mutex<VecDeque<Value>>>,
    }

    async fn signal_receive_test_ws_handler(
        ws: axum::extract::ws::WebSocketUpgrade,
        State(state): State<SignalReceiveTestServerState>,
        OriginalUri(uri): OriginalUri,
        Path(_number): Path<String>,
    ) -> axum::response::Response {
        let uri_str = uri
            .path_and_query()
            .map(|value| value.as_str().to_string())
            .unwrap_or_else(|| uri.path().to_string());
        state.requests.lock().push(uri_str);
        let next_msg = state.responses.lock().pop_front();
        ws.on_upgrade(move |mut socket| async move {
            if let Some(payload) = next_msg {
                let text = serde_json::to_string(&payload).unwrap();
                let _ = socket
                    .send(axum::extract::ws::Message::Text(text.into()))
                    .await;
            }
            while let Some(Ok(msg)) = socket.recv().await {
                if let axum::extract::ws::Message::Close(_) = msg {
                    break;
                }
            }
        })
    }

    async fn wait_for_condition<F>(timeout: Duration, mut condition: F)
    where
        F: FnMut() -> bool,
    {
        let started = tokio::time::Instant::now();
        loop {
            if condition() {
                return;
            }
            assert!(
                started.elapsed() < timeout,
                "condition was not satisfied within {:?}",
                timeout
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    #[test]
    fn test_parse_inbound_message() {
        let json = r#"[
            {
                "sourceNumber": "+15559876543",
                "timestamp": 1706745600000,
                "dataMessage": {
                    "message": "Hello from Signal!",
                    "timestamp": 1706745600000
                }
            }
        ]"#;

        let envelopes: Vec<SignalEnvelope> = serde_json::from_str(json).unwrap();
        assert_eq!(envelopes.len(), 1);
        assert_eq!(envelopes[0].effective_source_number(), Some("+15559876543"));
        let dm = envelopes[0].data_message.as_ref().unwrap();
        assert_eq!(dm.message.as_deref(), Some("Hello from Signal!"));
        assert_eq!(dm.timestamp, Some(1706745600000));
    }

    #[test]
    fn test_parse_group_message() {
        let json = r#"[
            {
                "sourceNumber": "+15559876543",
                "dataMessage": {
                    "message": "Group hello",
                    "groupInfo": {
                        "groupId": "dGVzdGdyb3VwaWQ="
                    }
                }
            }
        ]"#;

        let envelopes: Vec<SignalEnvelope> = serde_json::from_str(json).unwrap();
        assert_eq!(envelopes.len(), 1);
        let dm = envelopes[0].data_message.as_ref().unwrap();
        assert_eq!(dm.message.as_deref(), Some("Group hello"));
        let group = dm.group_info.as_ref().unwrap();
        assert_eq!(group.group_id.as_deref(), Some("dGVzdGdyb3VwaWQ="));
    }

    #[test]
    fn test_parse_empty_response() {
        let json = "[]";
        let envelopes: Vec<SignalEnvelope> = serde_json::from_str(json).unwrap();
        assert!(envelopes.is_empty());
    }

    #[test]
    fn test_parse_receipt_envelope() {
        // Receipt envelopes have no dataMessage — should deserialize fine
        let json = r#"[
            {
                "sourceNumber": "+15559876543",
                "timestamp": 1706745600000
            }
        ]"#;

        let envelopes: Vec<SignalEnvelope> = serde_json::from_str(json).unwrap();
        assert_eq!(envelopes.len(), 1);
        assert!(envelopes[0].data_message.is_none());
    }

    #[test]
    fn test_parse_envelope_with_source_number_field() {
        let json = r#"[
            {
                "sourceNumber": "+15559876543",
                "dataMessage": {
                    "message": "Hello"
                }
            }
        ]"#;

        let envelopes: Vec<SignalEnvelope> = serde_json::from_str(json).unwrap();
        assert_eq!(envelopes[0].effective_source_number(), Some("+15559876543"));
    }

    #[test]
    fn test_effective_source_number_uuid_fallback() {
        let envelope = SignalEnvelope {
            source_uuid: Some("bc10cb01-949e-4c75-8eb6-04dbdbda16e0".to_string()),
            source_number: None,
            timestamp: None,
            data_message: None,
        };
        assert_eq!(
            envelope.effective_source_number(),
            Some("bc10cb01-949e-4c75-8eb6-04dbdbda16e0")
        );
    }

    #[test]
    fn test_effective_source_number_both_absent() {
        let envelope = SignalEnvelope {
            source_uuid: None,
            source_number: None,
            timestamp: None,
            data_message: None,
        };
        assert_eq!(envelope.effective_source_number(), None);
    }

    #[test]
    fn test_effective_source_number_both_empty() {
        let envelope = SignalEnvelope {
            source_uuid: Some("   ".to_string()),
            source_number: Some("   ".to_string()),
            timestamp: None,
            data_message: None,
        };
        assert_eq!(envelope.effective_source_number(), None);
    }

    #[test]
    fn test_parse_envelope_with_source_number() {
        let json = r#"[
            {
                "sourceNumber": "+15559876543",
                "dataMessage": {
                    "message": "Hello from sourceNumber!"
                }
            }
        ]"#;

        let envelopes: Vec<SignalEnvelope> = serde_json::from_str(json).unwrap();
        assert_eq!(envelopes.len(), 1);
        assert_eq!(envelopes[0].effective_source_number(), Some("+15559876543"));
    }

    #[test]
    fn test_parse_missing_text() {
        let json = r#"[
            {
                "sourceNumber": "+15559876543",
                "dataMessage": {}
            }
        ]"#;

        let envelopes: Vec<SignalEnvelope> = serde_json::from_str(json).unwrap();
        assert_eq!(envelopes.len(), 1);
        let dm = envelopes[0].data_message.as_ref().unwrap();
        assert!(dm.message.is_none());
    }

    #[test]
    fn test_parse_wrapped_envelope_item() {
        let item = serde_json::json!({
            "envelope": {
                "sourceNumber": "+15559876543",
                "dataMessage": {
                    "message": "Hello from wrapped Signal"
                }
            }
        });

        let envelope = deserialize_signal_envelope_item(item).unwrap();
        assert_eq!(envelope.effective_source_number(), Some("+15559876543"));
        assert_eq!(
            envelope
                .data_message
                .as_ref()
                .and_then(|dm| dm.message.as_deref()),
            Some("Hello from wrapped Signal")
        );
    }

    #[test]
    fn test_parse_unwrapped_envelope_item() {
        let item = serde_json::json!({
            "sourceNumber": "+15559876543",
            "dataMessage": {
                "message": "Hello direct"
            }
        });

        let envelope = deserialize_signal_envelope_item(item).unwrap();
        assert_eq!(envelope.effective_source_number(), Some("+15559876543"));
        assert_eq!(
            envelope
                .data_message
                .as_ref()
                .and_then(|dm| dm.message.as_deref()),
            Some("Hello direct")
        );
    }

    #[test]
    fn test_parse_wrapped_group_envelope_item() {
        let item = serde_json::json!({
            "envelope": {
                "sourceNumber": "+15559876543",
                "dataMessage": {
                    "message": "Group hello",
                    "groupInfo": {
                        "groupId": "dGVzdGdyb3VwaWQ="
                    }
                }
            }
        });

        let envelope = deserialize_signal_envelope_item(item).unwrap();
        let group = envelope
            .data_message
            .as_ref()
            .and_then(|dm| dm.group_info.as_ref())
            .and_then(|group| group.group_id.as_deref());
        assert_eq!(group, Some("dGVzdGdyb3VwaWQ="));
        assert_eq!(envelope.effective_source_number(), Some("+15559876543"));
    }

    #[test]
    fn test_build_receive_url_preserves_signal_auto_receipts_by_default() {
        assert_eq!(
            build_receive_url(
                &url::Url::parse("http://localhost:8080").unwrap(),
                "+15551234567",
                false
            )
            .as_str(),
            "ws://localhost:8080/v1/receive/%2B15551234567"
        );
    }

    #[test]
    fn test_build_receive_url_disables_signal_auto_receipts_when_feature_enabled() {
        assert_eq!(
            build_receive_url(
                &url::Url::parse("http://localhost:8080").unwrap(),
                "+15551234567",
                true
            )
            .as_str(),
            "ws://localhost:8080/v1/receive/%2B15551234567?send_read_receipts=false"
        );
    }

    #[test]
    fn test_build_receive_url_preserves_existing_query_parameters() {
        assert_eq!(
            build_receive_url(
                &url::Url::parse("http://localhost:8080?debug=1").unwrap(),
                "+15551234567",
                true
            )
            .as_str(),
            "ws://localhost:8080/v1/receive/%2B15551234567?debug=1&send_read_receipts=false"
        );
    }

    #[test]
    fn test_build_receive_url_replaces_existing_receipt_control_parameters() {
        assert_eq!(
            build_receive_url(
                &url::Url::parse(
                    "http://localhost:8080?debug=1&max_messages=99&send_read_receipts=true",
                )
                .unwrap(),
                "+15551234567",
                true
            )
            .as_str(),
            "ws://localhost:8080/v1/receive/%2B15551234567?debug=1&send_read_receipts=false"
        );
    }

    #[test]
    fn test_build_receive_url_strips_existing_receipt_control_parameters_when_not_managing_receipts(
    ) {
        assert_eq!(
            build_receive_url(
                &url::Url::parse(
                    "http://localhost:8080?debug=1&max_messages=99&send_read_receipts=false",
                )
                .unwrap(),
                "+15551234567",
                false
            )
            .as_str(),
            "ws://localhost:8080/v1/receive/%2B15551234567?debug=1"
        );
    }

    #[test]
    fn test_build_receive_url_preserves_non_root_path_prefix() {
        assert_eq!(
            build_receive_url(
                &url::Url::parse("http://localhost:8080/api").unwrap(),
                "+15551234567",
                false
            )
            .as_str(),
            "ws://localhost:8080/api/v1/receive/%2B15551234567"
        );
    }

    #[test]
    fn test_build_receive_url_preserves_non_root_path_prefix_and_query() {
        assert_eq!(
            build_receive_url(
                &url::Url::parse("http://localhost:8080/api?debug=1").unwrap(),
                "+15551234567",
                true
            )
            .as_str(),
            "ws://localhost:8080/api/v1/receive/%2B15551234567?debug=1&send_read_receipts=false"
        );
    }

    #[test]
    fn test_build_receive_url_converts_https_to_wss() {
        assert_eq!(
            build_receive_url(
                &url::Url::parse("https://signal.example.com/api").unwrap(),
                "+15551234567",
                true
            )
            .as_str(),
            "wss://signal.example.com/api/v1/receive/%2B15551234567?send_read_receipts=false"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_snapshot_signal_receive_poll_leaves_auto_receipts_enabled_without_signal_plugin()
    {
        let state = test_state_with_provider(true);
        let activity_service = crate::channels::activity::ActivityService::new();
        let activity_policy = crate::channels::activity::ChannelActivityPolicy {
            read_receipts: crate::channels::activity::ReadReceiptFeaturePolicy { enabled: true },
            ..Default::default()
        };
        let mut capability_cache = SignalReadReceiptCapabilityCache::default();

        let snapshot = snapshot_signal_receive_poll(
            &url::Url::parse("http://localhost:8080").unwrap(),
            "+15551234567",
            &activity_policy,
            state.as_ref(),
            &activity_service,
            &mut capability_cache,
        )
        .await;

        assert!(!snapshot.carapace_manages_read_receipts());
        assert_eq!(
            snapshot.receive_url.as_str(),
            "ws://localhost:8080/v1/receive/%2B15551234567"
        );
        drop(snapshot);
        state.shutdown_activity_service().await;
        activity_service.shutdown().await;
    }

    #[tokio::test]
    async fn test_sanitize_signal_receive_transport_error_strips_phone_number_from_url() {
        let err = reqwest::Client::new()
            .get(
                "http://127.0.0.1:1/v1/receive/%2B15551234567?max_messages=7&send_read_receipts=false",
            )
            .send()
            .await
            .expect_err("transport request should fail against unreachable port");
        let sanitized = sanitize_signal_receive_transport_error(&err);
        assert!(!sanitized.contains("%2B15551234567"));
        assert!(!sanitized.contains("+15551234567"));
        assert!(!sanitized.contains("127.0.0.1:1"));
        assert!(!sanitized.contains("send_read_receipts=false"));
        assert!(!sanitized.contains("max_messages=7"));
        assert!(!sanitized.contains("/v1/receive"));
    }

    #[test]
    fn test_sanitize_signal_receive_transport_error_scrubs_ws_urls_and_credentials() {
        struct MockError(&'static str);
        impl std::fmt::Display for MockError {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}", self.0)
            }
        }

        let err = MockError(
            "WebSocket connect error for ws://user:secretpass@127.0.0.1:8080/v1/receive/%2B15551234567?token=xyz123: Connection refused",
        );
        let sanitized = sanitize_signal_receive_transport_error(&err);
        assert!(!sanitized.contains("user:secretpass"));
        assert!(!sanitized.contains("127.0.0.1:8080"));
        assert!(!sanitized.contains("%2B15551234567"));
        assert!(!sanitized.contains("+15551234567"));
        assert!(!sanitized.contains("token=xyz123"));
        assert_eq!(
            sanitized,
            "WebSocket connect error for [redacted]: Connection refused"
        );

        let err2 = MockError(
            "Connection to wss://example.com/v1/receive/+15559876543 closed unexpectedly (status: +15559876543 error)",
        );
        let sanitized2 = sanitize_signal_receive_transport_error(&err2);
        assert_eq!(
            sanitized2,
            "Connection to [redacted] closed unexpectedly (status: [redacted] error)"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_snapshot_signal_receive_poll_uses_single_policy_view() {
        let activity_service =
            crate::channels::activity::ActivityService::with_limits_for_test(8, 3);
        let state = test_state_with_provider_and_signal_plugin();
        let activity_policy = crate::channels::activity::ChannelActivityPolicy {
            read_receipts: crate::channels::activity::ReadReceiptFeaturePolicy { enabled: true },
            ..Default::default()
        };
        let mut capability_cache = SignalReadReceiptCapabilityCache::default();

        let snapshot = snapshot_signal_receive_poll(
            &url::Url::parse("http://localhost:8080/api?debug=1").unwrap(),
            "+15551234567",
            &activity_policy,
            state.as_ref(),
            &activity_service,
            &mut capability_cache,
        )
        .await;

        assert!(snapshot.carapace_manages_read_receipts());
        assert_eq!(
            snapshot.receive_url.as_str(),
            "ws://localhost:8080/api/v1/receive/%2B15551234567?debug=1&send_read_receipts=false"
        );
        drop(snapshot);
        state.shutdown_activity_service().await;
        activity_service.shutdown().await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_snapshot_signal_receive_poll_leaves_auto_receipts_enabled_when_backlog_is_high() {
        let activity_service =
            crate::channels::activity::ActivityService::with_limits_for_test(8, 1);
        let state = test_state_with_provider_and_signal_plugin();
        activity_service
            .enqueue_ready_read_receipt(
                "signal",
                ReadReceiptContext {
                    recipient: "+15551234567".to_string(),
                    timestamp: Some(123),
                    ..Default::default()
                },
            )
            .await
            .expect("backlog setup should persist a durable read receipt obligation");
        let activity_policy = crate::channels::activity::ChannelActivityPolicy {
            read_receipts: crate::channels::activity::ReadReceiptFeaturePolicy { enabled: true },
            ..Default::default()
        };
        let mut capability_cache = SignalReadReceiptCapabilityCache::default();

        let snapshot = snapshot_signal_receive_poll(
            &url::Url::parse("http://localhost:8080/api?debug=1").unwrap(),
            "+15551234567",
            &activity_policy,
            state.as_ref(),
            &activity_service,
            &mut capability_cache,
        )
        .await;

        assert!(!snapshot.carapace_manages_read_receipts());
        assert_eq!(
            snapshot.receive_url.as_str(),
            "ws://localhost:8080/api/v1/receive/%2B15551234567?debug=1"
        );
        drop(snapshot);
        state.shutdown_activity_service().await;
        activity_service.shutdown().await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_snapshot_signal_receive_poll_suppresses_auto_receipts_without_provider() {
        let activity_service = crate::channels::activity::ActivityService::new();
        let plugin_registry = Arc::new(PluginRegistry::new());
        plugin_registry.register_channel(
            "signal".to_string(),
            Arc::new(MockSignalReadReceiptChannel::new(Arc::new(Notify::new()))),
        );
        let state = Arc::new(
            WsServerState::new(WsServerConfig::default()).with_plugin_registry(plugin_registry),
        );
        let activity_policy = crate::channels::activity::ChannelActivityPolicy {
            read_receipts: crate::channels::activity::ReadReceiptFeaturePolicy { enabled: true },
            ..Default::default()
        };
        let mut capability_cache = SignalReadReceiptCapabilityCache::default();

        let snapshot = snapshot_signal_receive_poll(
            &url::Url::parse("http://localhost:8080/api?debug=1").unwrap(),
            "+15551234567",
            &activity_policy,
            state.as_ref(),
            &activity_service,
            &mut capability_cache,
        )
        .await;

        assert!(snapshot.carapace_manages_read_receipts());
        assert_eq!(
            snapshot.receive_url.as_str(),
            "ws://localhost:8080/api/v1/receive/%2B15551234567?debug=1&send_read_receipts=false"
        );
        drop(snapshot);
        state.shutdown_activity_service().await;
        activity_service.shutdown().await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_snapshot_signal_receive_poll_leaves_auto_receipts_enabled_without_receipt_capability(
    ) {
        let activity_service = crate::channels::activity::ActivityService::new();
        let state = test_state_with_provider_and_signal_plugin_without_receipts();
        let activity_policy = crate::channels::activity::ChannelActivityPolicy {
            read_receipts: crate::channels::activity::ReadReceiptFeaturePolicy { enabled: true },
            ..Default::default()
        };
        let mut capability_cache = SignalReadReceiptCapabilityCache::default();

        let snapshot = snapshot_signal_receive_poll(
            &url::Url::parse("http://localhost:8080/api?debug=1").unwrap(),
            "+15551234567",
            &activity_policy,
            state.as_ref(),
            &activity_service,
            &mut capability_cache,
        )
        .await;

        assert!(!snapshot.carapace_manages_read_receipts());
        assert_eq!(
            snapshot.receive_url.as_str(),
            "ws://localhost:8080/api/v1/receive/%2B15551234567?debug=1"
        );
        drop(snapshot);
        state.shutdown_activity_service().await;
        activity_service.shutdown().await;
    }

    #[test]
    fn test_validate_signal_receive_url_rejects_non_https_non_loopback_base_url() {
        let err = validate_signal_url("http://example.com:8080", "signal receive", true)
            .expect_err("non-loopback receive URL should be rejected");
        assert!(err.contains("signal receive URL must use https"));
    }

    #[test]
    fn test_build_signal_read_receipt_context_uses_available_timestamp() {
        let envelope = SignalEnvelope {
            source_uuid: None,
            source_number: Some("+15559876543".to_string()),
            timestamp: None,
            data_message: Some(SignalDataMessage {
                message: Some("Hello".to_string()),
                timestamp: Some(1706745600000),
                group_info: None,
            }),
        };

        let ctx = build_signal_read_receipt_context(
            &envelope,
            envelope.data_message.as_ref().unwrap(),
            "+15559876543",
        )
        .expect("timestamp should produce read receipt context");
        assert_eq!(ctx.recipient, "+15559876543");
        assert_eq!(ctx.timestamp, Some(1706745600000));
    }

    #[test]
    fn test_build_signal_read_receipt_context_prefers_data_message_timestamp() {
        let envelope = SignalEnvelope {
            source_uuid: None,
            source_number: Some("+15559876543".to_string()),
            timestamp: Some(1706745600999),
            data_message: Some(SignalDataMessage {
                message: Some("Hello".to_string()),
                timestamp: Some(1706745600000),
                group_info: None,
            }),
        };

        let ctx = build_signal_read_receipt_context(
            &envelope,
            envelope.data_message.as_ref().unwrap(),
            "+15559876543",
        )
        .expect("timestamp should produce read receipt context");
        assert_eq!(ctx.timestamp, Some(1706745600000));
    }

    #[test]
    fn test_build_signal_read_receipt_context_skips_missing_timestamp() {
        let envelope = SignalEnvelope {
            source_uuid: None,
            source_number: Some("+15559876543".to_string()),
            timestamp: None,
            data_message: Some(SignalDataMessage {
                message: Some("Hello".to_string()),
                timestamp: None,
                group_info: None,
            }),
        };

        let ctx = build_signal_read_receipt_context(
            &envelope,
            envelope.data_message.as_ref().unwrap(),
            "+15559876543",
        );
        assert!(ctx.is_none());
    }

    #[test]
    fn test_read_receipt_context_for_signal_run_skips_context_when_feature_disabled() {
        let envelope = SignalEnvelope {
            source_uuid: None,
            source_number: Some("+15559876543".to_string()),
            timestamp: Some(1706745600000),
            data_message: Some(SignalDataMessage {
                message: Some("Hello".to_string()),
                timestamp: Some(1706745600000),
                group_info: None,
            }),
        };

        let ctx = read_receipt_context_for_signal_run(
            &envelope,
            envelope.data_message.as_ref().unwrap(),
            "+15559876543",
            false,
        );
        assert!(ctx.is_none());
    }

    #[test]
    fn test_read_receipt_context_for_signal_run_returns_context_when_feature_enabled() {
        let envelope = SignalEnvelope {
            source_uuid: None,
            source_number: Some("+15559876543".to_string()),
            timestamp: Some(1706745600999),
            data_message: Some(SignalDataMessage {
                message: Some("Hello".to_string()),
                timestamp: Some(1706745600000),
                group_info: None,
            }),
        };

        let ctx = read_receipt_context_for_signal_run(
            &envelope,
            envelope.data_message.as_ref().unwrap(),
            "+15559876543",
            true,
        )
        .expect("enabled path should delegate to receipt-context builder");
        assert_eq!(ctx.recipient, "+15559876543");
        assert_eq!(ctx.timestamp, Some(1706745600000));
    }

    #[test]
    fn test_resolve_sender_and_peer_rejects_empty_sender() {
        let data_message = SignalDataMessage {
            message: Some("Hello".to_string()),
            timestamp: None,
            group_info: None,
        };
        let ids = resolve_signal_sender_and_peer("   ", &data_message);
        assert!(ids.is_none());
    }

    #[test]
    fn test_resolve_sender_and_peer_ignores_empty_group_id() {
        let envelope = SignalEnvelope {
            source_uuid: None,
            source_number: Some("+15559876543".to_string()),
            timestamp: None,
            data_message: Some(SignalDataMessage {
                message: Some("Hello".to_string()),
                timestamp: None,
                group_info: Some(SignalGroupInfo {
                    group_id: Some("   ".to_string()),
                }),
            }),
        };

        let ids = resolve_signal_sender_and_peer(
            envelope.effective_source_number().unwrap(),
            envelope.data_message.as_ref().unwrap(),
        );
        assert_eq!(
            ids,
            Some(("+15559876543".to_string(), "+15559876543".to_string()))
        );
    }

    #[test]
    fn test_resolve_sender_and_peer_rejects_group_message_with_phone_number_like_id() {
        let envelope = SignalEnvelope {
            source_uuid: None,
            source_number: Some("+15559876543".to_string()),
            timestamp: None,
            data_message: Some(SignalDataMessage {
                message: Some("Hello".to_string()),
                timestamp: None,
                group_info: Some(SignalGroupInfo {
                    group_id: Some("+15551234567".to_string()),
                }),
            }),
        };

        let ids = resolve_signal_sender_and_peer(
            envelope.effective_source_number().unwrap(),
            envelope.data_message.as_ref().unwrap(),
        );
        assert!(ids.is_none());
    }

    #[test]
    fn test_resolve_sender_and_peer_rejects_group_messages() {
        let envelope = SignalEnvelope {
            source_uuid: None,
            source_number: Some("+15559876543".to_string()),
            timestamp: None,
            data_message: Some(SignalDataMessage {
                message: Some("Hello".to_string()),
                timestamp: None,
                group_info: Some(SignalGroupInfo {
                    group_id: Some("dGVzdGdyb3VwaWQ=".to_string()),
                }),
            }),
        };

        let ids = resolve_signal_sender_and_peer(
            envelope.effective_source_number().unwrap(),
            envelope.data_message.as_ref().unwrap(),
        );
        assert!(ids.is_none());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_signal_receive_loop_reload_affects_future_polls_and_messages_only() {
        let initial_config = serde_json::json!({
            "channels": {
                "signal": {
                    "features": {
                        "readReceipts": {
                            "enabled": false
                        }
                    }
                }
            }
        });
        let fixture = crate::test_support::config::StableConfigFixture::new(initial_config);

        let requests = Arc::new(Mutex::new(Vec::new()));
        let responses = Arc::new(Mutex::new(VecDeque::from(vec![
            serde_json::json!([
                {
                    "sourceNumber": "+15559876543",
                    "timestamp": 1706745600000_u64,
                    "dataMessage": {
                        "message": "first",
                        "timestamp": 1706745600000_u64
                    }
                }
            ]),
            serde_json::json!([
                {
                    "sourceNumber": "+15559876543",
                    "timestamp": 1706745601000_u64,
                    "dataMessage": {
                        "message": "second",
                        "timestamp": 1706745601000_u64
                    }
                }
            ]),
        ])));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test Signal receive server");
        let addr = listener.local_addr().expect("local addr");
        let (server_shutdown_tx, server_shutdown_rx) = tokio::sync::watch::channel(false);
        let app = Router::new()
            .route(
                "/api/v1/receive/{number}",
                get(signal_receive_test_ws_handler),
            )
            .with_state(SignalReceiveTestServerState {
                requests: requests.clone(),
                responses: responses.clone(),
            });
        let server_task = tokio::spawn(async move {
            let server = axum::serve(listener, app).with_graceful_shutdown(async move {
                let mut shutdown = server_shutdown_rx;
                let _ = shutdown.changed().await;
            });
            server.await.expect("serve test Signal receive server");
        });

        let state = test_state_with_provider_and_signal_plugin();
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let receive_task = tokio::spawn(signal_receive_loop(
            format!("http://127.0.0.1:{}/api", addr.port()),
            "+15551234567".to_string(),
            state.clone(),
            state.channel_registry().clone(),
            shutdown_rx,
        ));

        wait_for_condition(Duration::from_secs(2), || {
            state
                .agent_run_registry
                .lock()
                .snapshot_runs()
                .iter()
                .any(|run| run.message == "first")
        })
        .await;

        let reloaded_config = serde_json::json!({
            "channels": {
                "signal": {
                    "features": {
                        "readReceipts": {
                            "enabled": true
                        }
                    }
                }
            }
        });
        fixture.update(reloaded_config);

        wait_for_condition(Duration::from_secs(2), || {
            state
                .activity_service()
                .read_receipt_queue()
                .list()
                .iter()
                .any(|task| {
                    task.payload["context"]["timestamp"].as_u64() == Some(1706745601000_u64)
                })
        })
        .await;

        let _ = shutdown_tx.send(true);
        let _ = server_shutdown_tx.send(true);
        tokio::time::timeout(Duration::from_secs(5), receive_task)
            .await
            .expect("receive loop should exit")
            .expect("receive loop task should succeed");
        tokio::time::timeout(Duration::from_secs(5), server_task)
            .await
            .expect("server should exit")
            .expect("server task should succeed");

        let requests = requests.lock().clone();
        assert!(requests
            .first()
            .is_some_and(|request| !request.contains("send_read_receipts=false")));
        assert!(requests
            .get(1)
            .is_some_and(|request| request.contains("send_read_receipts=false")));

        let runs = state.agent_run_registry.lock().snapshot_runs();
        assert!(runs.iter().any(|run| run.message == "first"));
        assert!(runs.iter().any(|run| run.message == "second"));
        let receipt_tasks = state.activity_service().read_receipt_queue().list();
        assert_eq!(receipt_tasks.len(), 1);
        assert_eq!(
            receipt_tasks[0].payload["context"]["timestamp"].as_u64(),
            Some(1706745601000_u64)
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_signal_receive_loop_handles_ping_pong_and_clean_close() {
        let (ping_received_tx, ping_received_rx) = tokio::sync::watch::channel(false);
        let ping_received_tx = Arc::new(ping_received_tx);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test Signal receive server");
        let addr = listener.local_addr().expect("local addr");
        let (server_shutdown_tx, server_shutdown_rx) = tokio::sync::watch::channel(false);

        let tx_for_ws = ping_received_tx.clone();
        let app = Router::new().route(
            "/v1/receive/{number}",
            get(move |ws: axum::extract::ws::WebSocketUpgrade| {
                let tx = tx_for_ws.clone();
                async move {
                    ws.on_upgrade(move |mut socket| async move {
                        let _ = socket
                            .send(axum::extract::ws::Message::Ping(vec![1, 2, 3, 4].into()))
                            .await;
                        while let Some(Ok(msg)) = socket.recv().await {
                            match msg {
                                axum::extract::ws::Message::Pong(payload) => {
                                    if payload.as_ref() == [1, 2, 3, 4] {
                                        let _ = tx.send(true);
                                    }
                                }
                                axum::extract::ws::Message::Close(_) => {
                                    break;
                                }
                                _ => {}
                            }
                        }
                    })
                }
            }),
        );

        let server_task = tokio::spawn(async move {
            let server = axum::serve(listener, app).with_graceful_shutdown(async move {
                let mut shutdown = server_shutdown_rx;
                let _ = shutdown.changed().await;
            });
            server.await.expect("serve test Signal receive server");
        });

        let state = test_state_with_provider_and_signal_plugin();
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let receive_task = tokio::spawn(signal_receive_loop(
            format!("http://127.0.0.1:{}", addr.port()),
            "+15551234567".to_string(),
            state.clone(),
            state.channel_registry().clone(),
            shutdown_rx,
        ));

        let mut ping_rx = ping_received_rx;
        let pong_received = tokio::time::timeout(Duration::from_secs(2), async {
            while !*ping_rx.borrow() {
                if ping_rx.changed().await.is_err() {
                    break;
                }
            }
        })
        .await;
        assert!(
            pong_received.is_ok(),
            "receive loop should answer ping with pong"
        );

        let _ = shutdown_tx.send(true);
        let _ = server_shutdown_tx.send(true);
        tokio::time::timeout(Duration::from_secs(5), receive_task)
            .await
            .expect("receive loop should exit")
            .expect("receive loop task should succeed");
        tokio::time::timeout(Duration::from_secs(5), server_task)
            .await
            .expect("server should exit")
            .expect("server task should succeed");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_signal_receive_loop_preserves_error_status_on_stream_error() {
        use tokio::io::AsyncWriteExt;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test Signal receive server");
        let addr = listener.local_addr().expect("local addr");
        let (server_shutdown_tx, server_shutdown_rx) = tokio::sync::watch::channel(false);

        let server_task = tokio::spawn(async move {
            let mut shutdown = server_shutdown_rx;
            tokio::select! {
                _ = shutdown.changed() => {}
                res = listener.accept() => {
                    if let Ok((stream, _)) = res {
                        if let Ok(ws_stream) = tokio_tungstenite::accept_async(stream).await {
                            let mut raw_stream = ws_stream.into_inner();
                            let _ = raw_stream.flush().await;
                            // Send partial frame header declaring 1024 bytes payload, then drop stream
                            // to force an unexpected EOF stream read error on the client.
                            let _ = raw_stream.write_all(&[0x81, 0x7E, 0x04, 0x00]).await;
                            let _ = raw_stream.flush().await;
                            drop(raw_stream);
                        }
                    }
                }
            }
        });

        let state = test_state_with_provider_and_signal_plugin();
        let channel_registry = state.channel_registry().clone();
        channel_registry.register(crate::channels::ChannelInfo::new("signal", "Signal"));
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let receive_task = tokio::spawn(signal_receive_loop(
            format!("http://127.0.0.1:{}", addr.port()),
            "+15551234567".to_string(),
            state.clone(),
            channel_registry.clone(),
            shutdown_rx,
        ));

        wait_for_condition(Duration::from_secs(2), || {
            channel_registry.get_status("signal") == Some(ChannelStatus::Error)
        })
        .await;

        let channel_info = channel_registry.get("signal").expect("channel info");
        assert_eq!(channel_info.status, ChannelStatus::Error);
        assert!(
            channel_info.metadata.last_error.is_some(),
            "last_error must be preserved on stream read error"
        );

        let _ = shutdown_tx.send(true);
        let _ = server_shutdown_tx.send(true);
        tokio::time::timeout(Duration::from_secs(5), receive_task)
            .await
            .expect("receive loop should exit")
            .expect("receive loop task should succeed");
        tokio::time::timeout(Duration::from_secs(5), server_task)
            .await
            .expect("server should exit")
            .expect("server task should succeed");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_signal_receive_loop_sets_disconnected_on_clean_remote_close() {
        let (close_sent_tx, close_sent_rx) = tokio::sync::watch::channel(false);
        let close_sent_tx = Arc::new(close_sent_tx);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test Signal receive server");
        let addr = listener.local_addr().expect("local addr");
        let (server_shutdown_tx, server_shutdown_rx) = tokio::sync::watch::channel(false);

        let tx = close_sent_tx.clone();
        let app = Router::new().route(
            "/v1/receive/{number}",
            get(move |ws: axum::extract::ws::WebSocketUpgrade| {
                let tx = tx.clone();
                async move {
                    ws.on_upgrade(move |mut socket| async move {
                        let _ = socket.send(axum::extract::ws::Message::Close(None)).await;
                        let _ = tx.send(true);
                    })
                }
            }),
        );

        let server_task = tokio::spawn(async move {
            let server = axum::serve(listener, app).with_graceful_shutdown(async move {
                let mut shutdown = server_shutdown_rx;
                let _ = shutdown.changed().await;
            });
            server.await.expect("serve test Signal receive server");
        });

        let state = test_state_with_provider_and_signal_plugin();
        let channel_registry = state.channel_registry().clone();
        channel_registry.register(crate::channels::ChannelInfo::new("signal", "Signal"));
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let receive_task = tokio::spawn(signal_receive_loop(
            format!("http://127.0.0.1:{}", addr.port()),
            "+15551234567".to_string(),
            state.clone(),
            channel_registry.clone(),
            shutdown_rx,
        ));

        let mut rx = close_sent_rx;
        let sent = tokio::time::timeout(Duration::from_secs(2), async {
            while !*rx.borrow() {
                if rx.changed().await.is_err() {
                    break;
                }
            }
        })
        .await;
        assert!(sent.is_ok(), "server should send clean close frame");

        wait_for_condition(Duration::from_secs(2), || {
            channel_registry.get_status("signal") == Some(ChannelStatus::Disconnected)
        })
        .await;

        let channel_info = channel_registry.get("signal").expect("channel info");
        assert_eq!(channel_info.status, ChannelStatus::Disconnected);
        assert!(channel_info.metadata.last_error.is_none());

        let _ = shutdown_tx.send(true);
        let _ = server_shutdown_tx.send(true);
        tokio::time::timeout(Duration::from_secs(5), receive_task)
            .await
            .expect("receive loop should exit")
            .expect("receive loop task should succeed");
        tokio::time::timeout(Duration::from_secs(5), server_task)
            .await
            .expect("server should exit")
            .expect("server task should succeed");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_signal_receive_loop_shuts_down_promptly_during_stalled_connect() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind stalled TCP listener");
        let addr = listener.local_addr().expect("local addr");

        let (connected_tx, connected_rx) = tokio::sync::watch::channel(false);
        let server_task = tokio::spawn(async move {
            if let Ok((_socket, _)) = listener.accept().await {
                let _ = connected_tx.send(true);
                // Keep socket alive without completing WebSocket handshake until task dropped
                std::future::pending::<()>().await;
            }
        });

        let state = test_state_with_provider_and_signal_plugin();
        let channel_registry = state.channel_registry().clone();
        channel_registry.register(crate::channels::ChannelInfo::new("signal", "Signal"));
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let receive_task = tokio::spawn(signal_receive_loop(
            format!("http://127.0.0.1:{}", addr.port()),
            "+15551234567".to_string(),
            state.clone(),
            channel_registry.clone(),
            shutdown_rx,
        ));

        let mut connected_rx = connected_rx;
        let connected = tokio::time::timeout(Duration::from_secs(2), async {
            while !*connected_rx.borrow() {
                if connected_rx.changed().await.is_err() {
                    break;
                }
            }
        })
        .await;
        assert!(
            connected.is_ok(),
            "receive loop should have opened TCP connection"
        );

        assert_eq!(
            channel_registry.get_status("signal"),
            Some(ChannelStatus::Connecting)
        );

        let _ = shutdown_tx.send(true);
        tokio::time::timeout(Duration::from_secs(1), receive_task)
            .await
            .expect("receive loop should promptly exit on shutdown during stalled connect")
            .expect("receive loop task should succeed");

        assert_eq!(
            channel_registry.get_status("signal"),
            Some(ChannelStatus::Disconnected)
        );

        server_task.abort();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_signal_receive_loop_reloads_config_during_stalled_connect() {
        let initial_config = serde_json::json!({
            "channels": {
                "signal": {
                    "features": {
                        "readReceipts": {
                            "enabled": false
                        }
                    }
                }
            }
        });
        let fixture = crate::test_support::config::StableConfigFixture::new(initial_config);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind stalled TCP listener");
        let addr = listener.local_addr().expect("local addr");

        let (first_connected_tx, first_connected_rx) = tokio::sync::watch::channel(false);
        let (second_connected_tx, second_connected_rx) = tokio::sync::watch::channel(false);

        let server_task = tokio::spawn(async move {
            // First stalled connection
            if let Ok((_socket1, _)) = listener.accept().await {
                let _ = first_connected_tx.send(true);
            }
            // Second connection after config reload reconnect
            if let Ok((_socket2, _)) = listener.accept().await {
                let _ = second_connected_tx.send(true);
            }
            std::future::pending::<()>().await;
        });

        let state = test_state_with_provider_and_signal_plugin();
        let channel_registry = state.channel_registry().clone();
        channel_registry.register(crate::channels::ChannelInfo::new("signal", "Signal"));
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let receive_task = tokio::spawn(signal_receive_loop(
            format!("http://127.0.0.1:{}", addr.port()),
            "+15551234567".to_string(),
            state.clone(),
            channel_registry.clone(),
            shutdown_rx,
        ));

        let mut first_rx = first_connected_rx;
        let first_connected = tokio::time::timeout(Duration::from_secs(2), async {
            while !*first_rx.borrow() {
                if first_rx.changed().await.is_err() {
                    break;
                }
            }
        })
        .await;
        assert!(
            first_connected.is_ok(),
            "receive loop should connect first time"
        );

        // Update configuration while stalled in connect
        let reloaded_config = serde_json::json!({
            "channels": {
                "signal": {
                    "features": {
                        "readReceipts": {
                            "enabled": true
                        }
                    }
                }
            }
        });
        fixture.update(reloaded_config);

        let mut second_rx = second_connected_rx;
        let second_connected = tokio::time::timeout(Duration::from_secs(2), async {
            while !*second_rx.borrow() {
                if second_rx.changed().await.is_err() {
                    break;
                }
            }
        })
        .await;
        assert!(
            second_connected.is_ok(),
            "receive loop should reload config and initiate a new connect attempt"
        );

        let _ = shutdown_tx.send(true);
        tokio::time::timeout(Duration::from_secs(1), receive_task)
            .await
            .expect("receive loop should exit on shutdown")
            .expect("receive loop task should succeed");

        server_task.abort();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_process_envelope_does_not_acknowledge_ignored_non_text_message() {
        let notify = Arc::new(Notify::new());
        let signal_channel = Arc::new(MockSignalReadReceiptChannel::new(notify.clone()));
        let plugin_registry = Arc::new(PluginRegistry::new());
        plugin_registry.register_channel("signal".to_string(), signal_channel.clone());
        let state = Arc::new(
            WsServerState::new(WsServerConfig::default()).with_plugin_registry(plugin_registry),
        );
        let envelope = SignalEnvelope {
            source_uuid: None,
            source_number: Some("+15559876543".to_string()),
            timestamp: Some(1706745600000),
            data_message: Some(SignalDataMessage {
                message: None,
                timestamp: Some(1706745600000),
                group_info: None,
            }),
        };

        process_envelope(&envelope, &state, true).await;

        assert_eq!(signal_channel.mark_read_count.load(Ordering::Relaxed), 0);
        assert!(state
            .activity_service()
            .read_receipt_queue()
            .list()
            .is_empty());
        assert!(
            state.agent_run_registry.lock().snapshot_runs().is_empty(),
            "ignored non-text messages should not create agent runs"
        );
        state.shutdown_activity_service().await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_process_envelope_does_not_acknowledge_ignored_group_message() {
        let notify = Arc::new(Notify::new());
        let signal_channel = Arc::new(MockSignalReadReceiptChannel::new(notify.clone()));
        let plugin_registry = Arc::new(PluginRegistry::new());
        plugin_registry.register_channel("signal".to_string(), signal_channel.clone());
        let state = Arc::new(
            WsServerState::new(WsServerConfig::default()).with_plugin_registry(plugin_registry),
        );
        let envelope = SignalEnvelope {
            source_uuid: None,
            source_number: Some("+15559876543".to_string()),
            timestamp: Some(1706745600000),
            data_message: Some(SignalDataMessage {
                message: Some("hello".to_string()),
                timestamp: Some(1706745600000),
                group_info: Some(SignalGroupInfo {
                    group_id: Some("dGVzdGdyb3VwaWQ=".to_string()),
                }),
            }),
        };

        process_envelope(&envelope, &state, true).await;

        assert_eq!(signal_channel.mark_read_count.load(Ordering::Relaxed), 0);
        assert!(state
            .activity_service()
            .read_receipt_queue()
            .list()
            .is_empty());
        assert!(
            state.agent_run_registry.lock().snapshot_runs().is_empty(),
            "ignored group messages should not create agent runs"
        );
        state.shutdown_activity_service().await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_process_envelope_claims_receipt_dynamically_and_respects_backpressure() {
        let activity_service =
            Arc::new(crate::channels::activity::ActivityService::with_limits_for_test(8, 1));
        let plugin_registry = Arc::new(PluginRegistry::new());
        plugin_registry.register_channel(
            "signal".to_string(),
            Arc::new(MockSignalReadReceiptChannel::new(Arc::new(Notify::new()))),
        );
        let state = Arc::new(
            WsServerState::new(WsServerConfig::default())
                .with_llm_provider(Arc::new(StaticTestProvider))
                .with_plugin_registry(plugin_registry)
                .with_activity_service(activity_service.clone()),
        );
        let activity_policy = crate::channels::activity::ChannelActivityPolicy {
            read_receipts: crate::channels::activity::ReadReceiptFeaturePolicy { enabled: true },
            ..Default::default()
        };
        let mut capability_cache = SignalReadReceiptCapabilityCache::default();
        let poll_snapshot = snapshot_signal_receive_poll(
            &url::Url::parse("http://localhost:8080").unwrap(),
            "+15551234567",
            &activity_policy,
            state.as_ref(),
            activity_service.as_ref(),
            &mut capability_cache,
        )
        .await;
        assert!(
            poll_snapshot.carapace_manages_read_receipts(),
            "poll snapshot should enable read receipt management without blocking other claims"
        );
        assert!(
            activity_service.can_accept_read_receipt_ownership("signal"),
            "snapshot should not hold a static batch reservation while the stream is idle"
        );

        // Simulate backpressure by claiming the 1 available slot.
        let held_claim = activity_service
            .try_claim_read_receipt(
                "signal",
                ReadReceiptContext {
                    recipient: "+15550000000".to_string(),
                    timestamp: Some(100),
                    ..Default::default()
                },
            )
            .expect("should claim the only available slot");

        assert!(
            !activity_service.can_accept_read_receipt_ownership("signal"),
            "backlog should reach high-water mark when capacity is held"
        );

        // An envelope arriving while capacity is exhausted is dispatched without claiming a receipt.
        let envelope1 = SignalEnvelope {
            source_uuid: None,
            source_number: Some("+15559876543".to_string()),
            timestamp: Some(1706745600000),
            data_message: Some(SignalDataMessage {
                message: Some("hello 1".to_string()),
                timestamp: Some(1706745600000),
                group_info: None,
            }),
        };

        let carapace_manages_read_receipts = poll_snapshot.carapace_manages_read_receipts();
        process_envelope(&envelope1, &state, carapace_manages_read_receipts).await;

        let runs = state.agent_run_registry.lock().snapshot_runs();
        assert!(runs.iter().any(|run| run.message == "hello 1"));
        // No receipt was claimed because of backpressure.
        assert!(state
            .activity_service()
            .read_receipt_queue()
            .list()
            .is_empty());

        // Now release the held claim so capacity opens up.
        assert!(activity_service.withhold_claimed_read_receipt(&held_claim));
        assert!(
            activity_service.can_accept_read_receipt_ownership("signal"),
            "capacity should be available again after releasing held claim"
        );

        // A second envelope now claims and completes receipt ownership dynamically.
        let envelope2 = SignalEnvelope {
            source_uuid: None,
            source_number: Some("+15559876543".to_string()),
            timestamp: Some(1706745600001),
            data_message: Some(SignalDataMessage {
                message: Some("hello 2".to_string()),
                timestamp: Some(1706745600001),
                group_info: None,
            }),
        };
        process_envelope(&envelope2, &state, carapace_manages_read_receipts).await;

        let runs = state.agent_run_registry.lock().snapshot_runs();
        assert!(runs.iter().any(|run| run.message == "hello 2"));
        let receipt_tasks = state.activity_service().read_receipt_queue().list();
        assert_eq!(receipt_tasks.len(), 1);
        assert_eq!(
            receipt_tasks[0].payload["context"]["timestamp"].as_u64(),
            Some(1706745600001)
        );

        state.shutdown_activity_service().await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_process_envelope_processes_unbounded_stream_messages_without_capacity_exhaustion()
    {
        let notify = Arc::new(Notify::new());
        let signal_channel = Arc::new(MockSignalReadReceiptChannel::new(notify.clone()));
        let plugin_registry = Arc::new(PluginRegistry::new());
        plugin_registry.register_channel("signal".to_string(), signal_channel.clone());
        // Configure watermark limit of 1
        let activity_service =
            Arc::new(crate::channels::activity::ActivityService::with_limits_for_test(8, 1));
        let state = Arc::new(
            WsServerState::new(WsServerConfig::default())
                .with_llm_provider(Arc::new(StaticTestProvider))
                .with_plugin_registry(plugin_registry)
                .with_activity_service(activity_service.clone()),
        );

        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        state
            .activity_service()
            .spawn_read_receipt_worker(state.clone(), shutdown_rx);

        // Send 5 messages sequentially across the same stream session.
        // Each message claims a receipt, worker completes it, releasing capacity for the next message.
        for i in 0..5 {
            let timestamp = 1706745600000 + i;
            let envelope = SignalEnvelope {
                source_uuid: None,
                source_number: Some("+15559876543".to_string()),
                timestamp: Some(timestamp),
                data_message: Some(SignalDataMessage {
                    message: Some(format!("message {}", i)),
                    timestamp: Some(timestamp),
                    group_info: None,
                }),
            };

            process_envelope(&envelope, &state, true).await;

            tokio::time::timeout(Duration::from_secs(1), notify.notified())
                .await
                .expect("receipt should be sent by worker for message");
            assert_eq!(
                signal_channel.mark_read_count.load(Ordering::Relaxed),
                (i + 1) as u32
            );
        }

        shutdown_tx.send(true).unwrap();
        state.shutdown_activity_service().await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_process_envelope_sends_immediate_receipt_when_durable_queue_is_unavailable() {
        let notify = Arc::new(Notify::new());
        let signal_channel = Arc::new(MockSignalReadReceiptChannel::new(notify.clone()));
        let plugin_registry = Arc::new(PluginRegistry::new());
        plugin_registry.register_channel("signal".to_string(), signal_channel.clone());
        let activity_service = Arc::new(
            crate::channels::activity::ActivityService::with_read_receipt_queue_for_test(Arc::new(
                TaskQueue::with_capacity_limit(None, Some(0)),
            )),
        );
        let state = Arc::new(
            WsServerState::new(WsServerConfig::default())
                .with_plugin_registry(plugin_registry)
                .with_activity_service(activity_service),
        );
        let envelope = SignalEnvelope {
            source_uuid: None,
            source_number: Some("+15559876543".to_string()),
            timestamp: Some(1706745600000),
            data_message: Some(SignalDataMessage {
                message: Some("hello".to_string()),
                timestamp: Some(1706745600000),
                group_info: None,
            }),
        };

        process_envelope(&envelope, &state, true).await;

        tokio::time::timeout(Duration::from_secs(1), notify.notified())
            .await
            .expect("failed durable receipt ownership should fall back to an immediate receipt");
        assert_eq!(signal_channel.mark_read_count.load(Ordering::Relaxed), 1);
        assert!(
            state
                .activity_service()
                .read_receipt_queue()
                .list()
                .is_empty(),
            "immediate fallback should not leave a synthetic receipt task behind"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_process_envelope_completes_claimed_receipt_when_llm_provider_disappears_after_poll(
    ) {
        let notify = Arc::new(Notify::new());
        let signal_channel = Arc::new(MockSignalReadReceiptChannel::new(notify.clone()));
        let plugin_registry = Arc::new(PluginRegistry::new());
        plugin_registry.register_channel("signal".to_string(), signal_channel.clone());
        let state = Arc::new(
            WsServerState::new(WsServerConfig::default())
                .with_llm_provider(Arc::new(StaticTestProvider))
                .with_plugin_registry(plugin_registry),
        );
        let activity_policy = crate::channels::activity::ChannelActivityPolicy {
            read_receipts: crate::channels::activity::ReadReceiptFeaturePolicy { enabled: true },
            ..Default::default()
        };
        let mut capability_cache = SignalReadReceiptCapabilityCache::default();
        let carapace_manages_read_receipts = can_manage_signal_read_receipts(
            &activity_policy,
            state.activity_service(),
            state.as_ref(),
            &mut capability_cache,
        )
        .await;
        assert!(
            carapace_manages_read_receipts,
            "LLM provider presence should not affect receipt ownership at connect time"
        );

        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        state
            .activity_service()
            .spawn_read_receipt_worker(state.clone(), shutdown_rx);
        state.set_llm_provider(None);

        let envelope = SignalEnvelope {
            source_uuid: None,
            source_number: Some("+15559876543".to_string()),
            timestamp: Some(1706745600000),
            data_message: Some(SignalDataMessage {
                message: Some("hello".to_string()),
                timestamp: Some(1706745600000),
                group_info: None,
            }),
        };

        process_envelope(&envelope, &state, carapace_manages_read_receipts).await;

        tokio::time::timeout(Duration::from_secs(1), notify.notified())
            .await
            .expect(
                "claimed receipts should be completed when the provider disappears before dispatch",
            );
        assert_eq!(signal_channel.mark_read_count.load(Ordering::Relaxed), 1);
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                let tasks = state.activity_service().read_receipt_queue().list();
                if tasks.len() == 1 && tasks[0].state == crate::tasks::TaskState::Done {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("immediate no-run receipt task should settle to done");

        // Receipt completion + session-message persistence happen above
        // (asserted via mark_read_count and the queue task); the run-tracking
        // entry is gated on provider availability and must not be orphaned
        // when the provider is absent at dispatch time.
        assert!(
            state.agent_run_registry.lock().snapshot_runs().is_empty(),
            "no provider at dispatch time should not orphan a run-registry entry"
        );
        shutdown_tx
            .send(true)
            .expect("read receipt worker shutdown signal should send");
        state.shutdown_activity_service().await;
    }
}
