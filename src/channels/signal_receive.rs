//! Signal inbound receive loop.
//!
//! Polls the signal-cli-rest-api `GET /v1/receive/{number}` endpoint every
//! 2 seconds and routes inbound messages into the chat pipeline.

use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::Deserialize;
use serde_json::Value;
use tracing::{debug, error, info, warn};

use crate::channels::signal::validate_signal_url;
use crate::channels::{ChannelRegistry, ChannelStatus};
use crate::plugins::{ChannelPluginInstance, ReadReceiptContext, TypingContext};
use crate::server::ws::WsServerState;

/// Interval between receive polls.
const POLL_INTERVAL: Duration = Duration::from_secs(2);

/// Timeout for each receive HTTP request.
const RECEIVE_TIMEOUT: Duration = Duration::from_secs(10);
const SIGNAL_RECEIPT_CAPABILITY_RETRY_BACKOFF: Duration = Duration::from_secs(30);

/// An envelope returned by `GET /v1/receive/{number}`.
#[derive(Debug, Deserialize)]
pub struct SignalEnvelope {
    /// Source phone number (e.g. "+15559876543").
    #[serde(default, rename = "sourceNumber")]
    pub source_number: Option<String>,

    /// Source UUID (used when phone number privacy is enabled).
    #[serde(default, rename = "sourceUuid")]
    pub source_uuid: Option<String>,

    /// Source field emitted by some signal-cli-rest-api versions.
    #[serde(default)]
    pub source: Option<String>,

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
    #[serde(default, alias = "groupInfo")]
    pub group_info: Option<SignalGroupInfo>,
}

impl SignalEnvelope {
    /// Returns the effective source identifier for the envelope.
    ///
    /// Returns `sourceNumber`, `sourceUuid`, or `source`, so the result is not
    /// guaranteed to be a phone number.
    pub fn effective_source_number(&self) -> Option<&str> {
        self.source_number
            .as_deref()
            .filter(|s| !s.trim().is_empty())
            .or_else(|| self.source_uuid.as_deref().filter(|s| !s.trim().is_empty()))
            .or_else(|| self.source.as_deref().filter(|s| !s.trim().is_empty()))
    }
}

/// Group metadata on a Signal message.
#[derive(Debug, Deserialize)]
pub struct SignalGroupInfo {
    /// Group identifier (base64).
    #[serde(default, alias = "groupId")]
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

fn summarize_signal_receive_response_error(error: &reqwest::Error) -> &'static str {
    if error.is_decode() {
        "invalid Signal receive response body"
    } else if error.is_timeout() {
        "timed out reading Signal receive response body"
    } else if error.is_body() {
        "failed to read Signal receive response body"
    } else {
        "failed to receive Signal response body"
    }
}

fn sanitize_signal_receive_transport_error(error: reqwest::Error) -> String {
    error.without_url().to_string()
}

fn build_signal_receive_http_client(
    builder: reqwest::ClientBuilder,
) -> Result<reqwest::Client, String> {
    builder
        .timeout(RECEIVE_TIMEOUT)
        .build()
        .map_err(|err| format!("failed to build Signal receive HTTP client: {err}"))
}

fn build_receive_url(
    base_url: &url::Url,
    phone_number: &str,
    managed_read_receipt_capacity: usize,
) -> url::Url {
    let mut url = base_url.clone();
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
    if !filtered_query_pairs.is_empty() || managed_read_receipt_capacity > 0 {
        let mut query_pairs = url.query_pairs_mut();
        for (key, value) in filtered_query_pairs {
            query_pairs.append_pair(&key, &value);
        }
        if managed_read_receipt_capacity > 0 {
            query_pairs.append_pair("max_messages", &managed_read_receipt_capacity.to_string());
            query_pairs.append_pair("send_read_receipts", "false");
        }
    }
    url
}

struct SignalReceivePollSnapshot {
    receive_url: url::Url,
    suppressed_upstream_auto_receipts: bool,
    read_receipt_reservation: Option<crate::channels::activity::ReadReceiptOwnershipReservation>,
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
) -> Option<crate::channels::activity::ReadReceiptOwnershipReservation> {
    if !activity_policy.read_receipts.enabled {
        return None;
    }

    let Some(plugin_registry) = state.plugin_registry() else {
        capability_cache.clear();
        return None;
    };
    let Some(plugin) = plugin_registry.get_channel("signal") else {
        capability_cache.clear();
        return None;
    };
    capability_cache.update_plugin(signal_plugin_cache_key(&plugin));

    if let Some(supported) = capability_cache.read_receipts_supported {
        return if supported {
            activity_service.reserve_available_read_receipt_ownership("signal")
        } else {
            None
        };
    }
    if capability_cache
        .retry_after
        .is_some_and(|retry_after| Instant::now() < retry_after)
    {
        return None;
    }

    match tokio::task::spawn_blocking(move || plugin.get_capabilities()).await {
        Ok(Ok(capabilities)) => {
            capability_cache.read_receipts_supported = Some(capabilities.read_receipts);
            capability_cache.retry_after = None;
            if capabilities.read_receipts {
                activity_service.reserve_available_read_receipt_ownership("signal")
            } else {
                activity_service.warn_unsupported_feature("signal", "read_receipts");
                None
            }
        }
        Ok(Err(err)) => {
            capability_cache.retry_after =
                Some(Instant::now() + SIGNAL_RECEIPT_CAPABILITY_RETRY_BACKOFF);
            warn!(
                error = %err,
                "failed to load Signal capabilities while deciding whether to suppress upstream auto-read-receipts"
            );
            None
        }
        Err(err) => {
            capability_cache.retry_after =
                Some(Instant::now() + SIGNAL_RECEIPT_CAPABILITY_RETRY_BACKOFF);
            warn!(
                error = %err,
                "Signal capability worker failed while deciding whether to suppress upstream auto-read-receipts"
            );
            None
        }
    }
}

async fn snapshot_signal_receive_poll(
    base_url: &url::Url,
    phone_number: &str,
    activity_policy: &crate::channels::activity::ChannelActivityPolicy,
    state: &WsServerState,
    activity_service: &crate::channels::activity::ActivityService,
    capability_cache: &mut SignalReadReceiptCapabilityCache,
) -> SignalReceivePollSnapshot {
    let read_receipt_reservation =
        can_manage_signal_read_receipts(activity_policy, activity_service, state, capability_cache)
            .await;
    let managed_read_receipt_capacity = read_receipt_reservation
        .as_ref()
        .map_or(0, |reservation| reservation.reserved_capacity());
    SignalReceivePollSnapshot {
        receive_url: build_receive_url(base_url, phone_number, managed_read_receipt_capacity),
        suppressed_upstream_auto_receipts: read_receipt_reservation.is_some(),
        read_receipt_reservation,
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
/// Polls `GET {base_url}/v1/receive/{number}` every 2 seconds, parses inbound
/// messages, and routes them into the chat pipeline. Updates channel registry
/// status on success/failure. Exits when the shutdown signal fires.
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

    let client = match build_signal_receive_http_client(reqwest::Client::builder()) {
        Ok(client) => client,
        Err(err) => {
            error!(
                phone_number = %phone_number,
                error = %err,
                "Signal receive loop HTTP client initialization failed"
            );
            channel_registry.set_error("signal", err);
            channel_registry.update_status("signal", ChannelStatus::Error);
            return;
        }
    };
    info!(phone_number = %phone_number, "Signal receive loop started");
    let mut config_rx = crate::config::subscribe_config_changes();
    config_rx.borrow_and_update();
    let mut activity_policy =
        crate::channels::activity::load_channel_activity_policy_async("signal").await;
    let mut capability_cache = SignalReadReceiptCapabilityCache::default();

    // Track consecutive transport and parse errors to avoid spamming logs.
    let mut consecutive_errors: u32 = 0;
    let mut consecutive_parse_errors: u32 = 0;

    loop {
        // Check shutdown before polling
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

        match client.get(poll_snapshot.receive_url.clone()).send().await {
            Ok(resp) if resp.status().is_success() => {
                if consecutive_errors > 0 {
                    info!(
                        "Signal receive loop recovered after {} errors",
                        consecutive_errors
                    );
                    consecutive_errors = 0;
                }

                match resp.json::<Vec<Value>>().await {
                    Ok(items) => {
                        channel_registry.update_status("signal", ChannelStatus::Connected);
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
                                        &mut poll_snapshot.read_receipt_reservation,
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
                    Err(e) => {
                        let sanitized_error = e.without_url();
                        let error_summary =
                            summarize_signal_receive_response_error(&sanitized_error);
                        let error_detail = sanitized_error.to_string();
                        let error_message = format!("{}: {}", error_summary, error_detail);
                        record_signal_parse_failure(
                            "receive response",
                            &error_message,
                            &mut consecutive_parse_errors,
                        );
                        channel_registry.set_error(
                            "signal",
                            format!("receive parse failed: {}", error_message),
                        );
                    }
                }
            }
            Ok(resp) => {
                consecutive_errors += 1;
                let status = resp.status();
                if consecutive_errors <= 3 {
                    warn!("Signal receive HTTP {}", status);
                }
                channel_registry.set_error("signal", format!("HTTP {}", status));
            }
            Err(e) => {
                consecutive_errors += 1;
                let sanitized_error = sanitize_signal_receive_transport_error(e);
                if consecutive_errors <= 3 {
                    warn!("Signal receive error: {}", sanitized_error);
                } else if consecutive_errors == 4 {
                    warn!(
                        "Signal receive errors continuing (suppressing further logs until recovery)"
                    );
                }
                channel_registry.set_error("signal", sanitized_error);
            }
        }

        // Wait for poll interval or shutdown
        tokio::select! {
            _ = tokio::time::sleep(POLL_INTERVAL) => {}
            changed = config_rx.changed() => {
                if changed.is_err() {
                    warn!("Signal receive loop config subscription closed unexpectedly");
                    continue;
                }
                activity_policy =
                    crate::channels::activity::load_channel_activity_policy_async("signal").await;
                capability_cache.clear();
            }
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    info!("Signal receive loop shutting down");
                    break;
                }
            }
        }
    }
}

/// Process a single inbound Signal envelope by routing it into the chat pipeline.
async fn process_envelope(
    envelope: &SignalEnvelope,
    state: &Arc<WsServerState>,
    carapace_manages_read_receipts: bool,
    read_receipt_reservation: &mut Option<
        crate::channels::activity::ReadReceiptOwnershipReservation,
    >,
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
        read_receipt_reservation
            .as_mut()
            .and_then(|reservation| reservation.claim(ctx))
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
    use axum::{Json, Router};
    use parking_lot::Mutex;
    use tokio::sync::mpsc;
    use tokio::sync::Notify;
    use tokio_util::sync::CancellationToken;

    use super::*;
    use crate::agent::provider::CompletionRequest;
    use crate::agent::{AgentError, LlmProvider, StreamEvent};
    use crate::plugins::{
        BindingError, ChannelCapabilities, ChannelInfo, ChannelPluginInstance, PluginRegistry,
    };
    use crate::server::ws::WsServerConfig;
    use crate::tasks::TaskQueue;

    struct StaticTestProvider;

    #[async_trait::async_trait]
    impl LlmProvider for StaticTestProvider {
        async fn complete(
            &self,
            _request: CompletionRequest,
            _cancel_token: CancellationToken,
        ) -> Result<mpsc::Receiver<StreamEvent>, AgentError> {
            let (_tx, rx) = mpsc::channel(1);
            Ok(rx)
        }
    }

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
                retryable: false,
                conversation_id: None,
                to_jid: None,
                poll_id: None,
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
                retryable: false,
                conversation_id: None,
                to_jid: None,
                poll_id: None,
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
                retryable: false,
                conversation_id: None,
                to_jid: None,
                poll_id: None,
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
                retryable: false,
                conversation_id: None,
                to_jid: None,
                poll_id: None,
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

    async fn signal_receive_test_handler(
        State(state): State<SignalReceiveTestServerState>,
        OriginalUri(uri): OriginalUri,
        Path(_number): Path<String>,
    ) -> Json<Value> {
        state.requests.lock().push(
            uri.path_and_query()
                .map(|value| value.as_str().to_string())
                .unwrap_or_else(|| uri.path().to_string()),
        );
        Json(
            state
                .responses
                .lock()
                .pop_front()
                .unwrap_or_else(|| serde_json::json!([])),
        )
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
    fn test_parse_group_message_with_snake_case_fields() {
        let json = r#"[
            {
                "sourceNumber": "+15559876543",
                "dataMessage": {
                    "message": "Group hello",
                    "group_info": {
                        "group_id": "dGVzdGdyb3VwaWQ="
                    }
                }
            }
        ]"#;

        let envelopes: Vec<SignalEnvelope> = serde_json::from_str(json).unwrap();
        let dm = envelopes[0].data_message.as_ref().unwrap();
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
    fn test_parse_envelope_with_source_field() {
        let json = r#"[
            {
                "source": "+15559876543",
                "dataMessage": {
                    "message": "Hello"
                }
            }
        ]"#;

        let envelopes: Vec<SignalEnvelope> = serde_json::from_str(json).unwrap();
        assert_eq!(envelopes[0].effective_source_number(), Some("+15559876543"));
    }

    #[test]
    fn test_effective_source_number_empty_source_number_fallback() {
        let envelope = SignalEnvelope {
            source_uuid: None,
            source_number: Some("   ".to_string()),
            source: Some("+15559876543".to_string()),
            timestamp: None,
            data_message: None,
        };
        assert_eq!(envelope.effective_source_number(), Some("+15559876543"));
    }

    #[test]
    fn test_effective_source_number_uuid_fallback() {
        let envelope = SignalEnvelope {
            source_uuid: Some("bc10cb01-949e-4c75-8eb6-04dbdbda16e0".to_string()),
            source_number: None,
            source: None,
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
            source: None,
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
            source: Some("+15559876543".to_string()),
            timestamp: None,
            data_message: None,
        };
        assert_eq!(envelope.effective_source_number(), Some("+15559876543"));
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
                0
            )
            .as_str(),
            "http://localhost:8080/v1/receive/%2B15551234567"
        );
    }

    #[test]
    fn test_build_receive_url_disables_signal_auto_receipts_when_feature_enabled() {
        assert_eq!(
            build_receive_url(
                &url::Url::parse("http://localhost:8080").unwrap(),
                "+15551234567",
                7
            )
            .as_str(),
            "http://localhost:8080/v1/receive/%2B15551234567?max_messages=7&send_read_receipts=false"
        );
    }

    #[test]
    fn test_build_receive_url_preserves_existing_query_parameters() {
        assert_eq!(
            build_receive_url(
                &url::Url::parse("http://localhost:8080?debug=1").unwrap(),
                "+15551234567",
                7
            )
            .as_str(),
            "http://localhost:8080/v1/receive/%2B15551234567?debug=1&max_messages=7&send_read_receipts=false"
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
                7
            )
            .as_str(),
            "http://localhost:8080/v1/receive/%2B15551234567?debug=1&max_messages=7&send_read_receipts=false"
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
                0,
            )
            .as_str(),
            "http://localhost:8080/v1/receive/%2B15551234567?debug=1"
        );
    }

    #[test]
    fn test_build_receive_url_preserves_non_root_path_prefix() {
        assert_eq!(
            build_receive_url(
                &url::Url::parse("http://localhost:8080/api").unwrap(),
                "+15551234567",
                0
            )
            .as_str(),
            "http://localhost:8080/api/v1/receive/%2B15551234567"
        );
    }

    #[test]
    fn test_build_receive_url_preserves_non_root_path_prefix_and_query() {
        assert_eq!(
            build_receive_url(
                &url::Url::parse("http://localhost:8080/api?debug=1").unwrap(),
                "+15551234567",
                7
            )
            .as_str(),
            "http://localhost:8080/api/v1/receive/%2B15551234567?debug=1&max_messages=7&send_read_receipts=false"
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
            "http://localhost:8080/v1/receive/%2B15551234567"
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
        let sanitized = sanitize_signal_receive_transport_error(err);
        assert!(!sanitized.contains("%2B15551234567"));
        assert!(!sanitized.contains("+15551234567"));
        assert!(!sanitized.contains("send_read_receipts=false"));
    }

    #[test]
    fn test_build_signal_receive_http_client_reports_builder_errors() {
        let err = build_signal_receive_http_client(reqwest::Client::builder().user_agent("\n"))
            .expect_err("invalid user agent should fail client construction");
        assert!(err.contains("failed to build Signal receive HTTP client"));
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
            "http://localhost:8080/api/v1/receive/%2B15551234567?debug=1&max_messages=3&send_read_receipts=false"
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
            "http://localhost:8080/api/v1/receive/%2B15551234567?debug=1"
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
            "http://localhost:8080/api/v1/receive/%2B15551234567?debug=1&max_messages=10000&send_read_receipts=false"
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
            "http://localhost:8080/api/v1/receive/%2B15551234567?debug=1"
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
            source: None,
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
            source: None,
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
            source: None,
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
            source: None,
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
            source: None,
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
            source: None,
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
            source: None,
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
            source: None,
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
            .route("/api/v1/receive/{number}", get(signal_receive_test_handler))
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
        let first = runs
            .iter()
            .find(|run| run.message == "first")
            .expect("first inbound run");
        assert_eq!(first.status, crate::server::ws::AgentRunStatus::Queued);

        let second = runs
            .iter()
            .find(|run| run.message == "second")
            .expect("second inbound run");
        assert_eq!(second.status, crate::server::ws::AgentRunStatus::Queued);
        let receipt_tasks = state.activity_service().read_receipt_queue().list();
        assert_eq!(receipt_tasks.len(), 1);
        assert_eq!(
            receipt_tasks[0].payload["context"]["timestamp"].as_u64(),
            Some(1706745601000_u64)
        );
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
            source: None,
            timestamp: Some(1706745600000),
            data_message: Some(SignalDataMessage {
                message: None,
                timestamp: Some(1706745600000),
                group_info: None,
            }),
        };

        let mut read_receipt_reservation = state
            .activity_service()
            .reserve_available_read_receipt_ownership("signal");
        process_envelope(&envelope, &state, true, &mut read_receipt_reservation).await;

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
            source: None,
            timestamp: Some(1706745600000),
            data_message: Some(SignalDataMessage {
                message: Some("hello".to_string()),
                timestamp: Some(1706745600000),
                group_info: Some(SignalGroupInfo {
                    group_id: Some("dGVzdGdyb3VwaWQ=".to_string()),
                }),
            }),
        };

        let mut read_receipt_reservation = state
            .activity_service()
            .reserve_available_read_receipt_ownership("signal");
        process_envelope(&envelope, &state, true, &mut read_receipt_reservation).await;

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
    async fn test_process_envelope_uses_reserved_poll_capacity_when_other_claims_are_blocked() {
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
        let mut poll_snapshot = snapshot_signal_receive_poll(
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
            "poll snapshot should reserve the only available ownership slot"
        );
        assert!(
            activity_service
                .try_claim_read_receipt(
                    "signal",
                    ReadReceiptContext {
                        recipient: "+15551230000".to_string(),
                        timestamp: Some(1),
                        ..Default::default()
                    },
                )
                .is_none(),
            "other claims should be blocked while the poll reservation owns the slot"
        );
        let envelope = SignalEnvelope {
            source_uuid: None,
            source_number: Some("+15559876543".to_string()),
            source: None,
            timestamp: Some(1706745600000),
            data_message: Some(SignalDataMessage {
                message: Some("hello".to_string()),
                timestamp: Some(1706745600000),
                group_info: None,
            }),
        };

        let carapace_manages_read_receipts = poll_snapshot.carapace_manages_read_receipts();
        process_envelope(
            &envelope,
            &state,
            carapace_manages_read_receipts,
            &mut poll_snapshot.read_receipt_reservation,
        )
        .await;

        let runs = state.agent_run_registry.lock().snapshot_runs();
        assert!(runs.iter().any(|run| run.message == "hello"));
        let receipt_tasks = state.activity_service().read_receipt_queue().list();
        assert_eq!(receipt_tasks.len(), 1);
        assert_eq!(
            receipt_tasks[0].payload["context"]["timestamp"].as_u64(),
            Some(1706745600000)
        );
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
            source: None,
            timestamp: Some(1706745600000),
            data_message: Some(SignalDataMessage {
                message: Some("hello".to_string()),
                timestamp: Some(1706745600000),
                group_info: None,
            }),
        };

        let mut read_receipt_reservation = state
            .activity_service()
            .reserve_available_read_receipt_ownership("signal");
        process_envelope(&envelope, &state, true, &mut read_receipt_reservation).await;

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
        let mut read_receipt_reservation = can_manage_signal_read_receipts(
            &activity_policy,
            state.activity_service(),
            state.as_ref(),
            &mut capability_cache,
        )
        .await;
        assert!(
            read_receipt_reservation.is_some(),
            "LLM provider presence should not affect receipt ownership at poll time"
        );

        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        state
            .activity_service()
            .spawn_read_receipt_worker(state.clone(), shutdown_rx);
        state.set_llm_provider(None);

        let envelope = SignalEnvelope {
            source_uuid: None,
            source_number: Some("+15559876543".to_string()),
            source: None,
            timestamp: Some(1706745600000),
            data_message: Some(SignalDataMessage {
                message: Some("hello".to_string()),
                timestamp: Some(1706745600000),
                group_info: None,
            }),
        };

        let carapace_manages_read_receipts = read_receipt_reservation.is_some();
        process_envelope(
            &envelope,
            &state,
            carapace_manages_read_receipts,
            &mut read_receipt_reservation,
        )
        .await;

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

        let runs = state.agent_run_registry.lock().snapshot_runs();
        let run = runs
            .iter()
            .find(|run| run.message == "hello")
            .expect("dispatch should still register the inbound run context");
        assert_eq!(run.status, crate::server::ws::AgentRunStatus::Queued);
        shutdown_tx
            .send(true)
            .expect("read receipt worker shutdown signal should send");
        state.shutdown_activity_service().await;
    }
}
