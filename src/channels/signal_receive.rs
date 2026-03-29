//! Signal inbound receive loop.
//!
//! Polls the signal-cli-rest-api `GET /v1/receive/{number}` endpoint every
//! 2 seconds and routes inbound messages into the chat pipeline.

use std::sync::Arc;
use std::time::Duration;

use serde::Deserialize;
use serde_json::Value;
use tracing::{debug, error, info, warn};

use crate::channels::signal::validate_signal_url;
use crate::channels::{ChannelRegistry, ChannelStatus};
use crate::plugins::{ReadReceiptContext, TypingContext};
use crate::server::ws::WsServerState;

/// Interval between receive polls.
const POLL_INTERVAL: Duration = Duration::from_secs(2);

/// Timeout for each receive HTTP request.
const RECEIVE_TIMEOUT: Duration = Duration::from_secs(10);

/// An envelope returned by `GET /v1/receive/{number}`.
#[derive(Debug, Deserialize)]
pub struct SignalEnvelope {
    /// Source phone number (e.g. "+15559876543").
    #[serde(default, rename = "sourceNumber")]
    pub source_number: Option<String>,

    /// Legacy source field.
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
    /// Returns the effective source number, preferring `sourceNumber` over `source`.
    pub fn effective_source_number(&self) -> Option<&str> {
        self.source_number
            .as_deref()
            .filter(|s| !s.trim().is_empty())
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
    envelope: &SignalEnvelope,
    data_message: &SignalDataMessage,
) -> Option<(String, String)> {
    let sender = envelope
        .effective_source_number()
        .map(str::trim)
        .filter(|s| !s.is_empty())?;
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

async fn maybe_dispatch_read_receipt_for_ignored_signal_message(
    state: &Arc<WsServerState>,
    sender: Option<&str>,
    read_receipt_context: Option<ReadReceiptContext>,
    carapace_manages_read_receipts: bool,
    reason: &str,
) {
    if !carapace_manages_read_receipts {
        return;
    }

    let Some(sender) = sender else {
        warn!(
            ignored_reason = reason,
            "Signal read receipts are enabled but an ignored message had no sender; Carapace cannot acknowledge it explicitly"
        );
        return;
    };

    let Some(read_receipt_context) = read_receipt_context else {
        warn!(
            sender = %sender,
            ignored_reason = reason,
            "Signal read receipts are enabled but an ignored message did not include a timestamp; Carapace cannot acknowledge it explicitly"
        );
        return;
    };

    if state
        .activity_service()
        .enqueue_ready_read_receipt("signal", read_receipt_context.clone())
        .await
        .is_none()
    {
        warn!(
            sender = %sender,
            ignored_reason = reason,
            "Signal read receipts are enabled but Carapace could not persist the explicit acknowledgment obligation; attempting direct receipt send"
        );
        if let Err(err) = crate::channels::activity::send_read_receipt_immediately(
            state.as_ref(),
            "signal",
            read_receipt_context,
        )
        .await
        {
            error!(
                sender = %sender,
                ignored_reason = reason,
                error = %err,
                "Signal read receipts are enabled but Carapace could not persist or send the explicit acknowledgment"
            );
        }
    }
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

fn build_receive_url(
    base_url: &url::Url,
    phone_number: &str,
    carapace_manages_read_receipts: bool,
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
        .filter(|(key, _)| key != "send_read_receipts")
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

#[derive(Debug, Clone)]
struct SignalReceivePollSnapshot {
    receive_url: url::Url,
    carapace_manages_read_receipts: bool,
}

fn can_manage_signal_read_receipts(
    activity_policy: &crate::channels::activity::ChannelActivityPolicy,
    activity_service: &crate::channels::activity::ActivityService,
    state: &WsServerState,
) -> bool {
    activity_policy.read_receipts.enabled
        && state.llm_provider().is_some()
        && state
            .plugin_registry()
            .and_then(|registry| registry.get_channel("signal"))
            .is_some()
        && activity_service.can_accept_read_receipt_ownership("signal")
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum SignalReadReceiptOwnership {
    Deferred(String),
    SentImmediately,
    Unavailable,
}

async fn acquire_signal_read_receipt_ownership(
    state: &Arc<WsServerState>,
    sender: &str,
    ctx: ReadReceiptContext,
) -> SignalReadReceiptOwnership {
    if let Some(task_id) = state
        .activity_service()
        .enqueue_after_response_read_receipt("signal", ctx.clone())
        .await
    {
        return SignalReadReceiptOwnership::Deferred(task_id);
    }

    warn!(
        sender = %sender,
        "Signal read receipts are enabled but Carapace could not persist the after-response acknowledgment obligation; falling back to an immediate retryable receipt task"
    );

    if let Some(task_id) = state
        .activity_service()
        .enqueue_ready_read_receipt("signal", ctx.clone())
        .await
    {
        return SignalReadReceiptOwnership::Deferred(task_id);
    }

    warn!(
        sender = %sender,
        "Signal read receipts are enabled but Carapace could not persist any durable acknowledgment obligation; attempting direct receipt send"
    );

    match crate::channels::activity::send_read_receipt_immediately(state.as_ref(), "signal", ctx)
        .await
    {
        Ok(()) => SignalReadReceiptOwnership::SentImmediately,
        Err(err) => {
            error!(
                sender = %sender,
                error = %err,
                "Signal read receipts were claimed for this message but Carapace could not persist or send the explicit acknowledgment"
            );
            SignalReadReceiptOwnership::Unavailable
        }
    }
}

fn snapshot_signal_receive_poll(
    base_url: &url::Url,
    phone_number: &str,
    activity_policy: &crate::channels::activity::ChannelActivityPolicy,
    state: &WsServerState,
    activity_service: &crate::channels::activity::ActivityService,
) -> SignalReceivePollSnapshot {
    let carapace_manages_read_receipts =
        can_manage_signal_read_receipts(activity_policy, activity_service, state);
    SignalReceivePollSnapshot {
        receive_url: build_receive_url(base_url, phone_number, carapace_manages_read_receipts),
        carapace_manages_read_receipts,
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

    let client = reqwest::Client::builder()
        .timeout(RECEIVE_TIMEOUT)
        .build()
        .expect("failed to build Signal receive HTTP client");
    info!(phone_number = %phone_number, "Signal receive loop started");
    let mut config_rx = crate::config::subscribe_config_changes();
    config_rx.borrow_and_update();
    let mut activity_policy =
        crate::channels::activity::load_channel_activity_policy_async("signal").await;

    // Track consecutive transport and parse errors to avoid spamming logs.
    let mut consecutive_errors: u32 = 0;
    let mut consecutive_parse_errors: u32 = 0;

    loop {
        // Check shutdown before polling
        if *shutdown.borrow() {
            info!("Signal receive loop shutting down");
            break;
        }

        let poll_snapshot = snapshot_signal_receive_poll(
            &base_url,
            &phone_number,
            &activity_policy,
            state.as_ref(),
            state.activity_service(),
        );

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
                                    process_envelope(
                                        &envelope,
                                        &state,
                                        poll_snapshot.carapace_manages_read_receipts,
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
        _ => {
            maybe_dispatch_read_receipt_for_ignored_signal_message(
                state,
                sender,
                read_receipt_context,
                carapace_manages_read_receipts,
                "ignored non-text Signal message",
            )
            .await;
            return;
        } // No text content
    };

    if signal_group_id(data_message).is_some() {
        maybe_dispatch_read_receipt_for_ignored_signal_message(
            state,
            sender,
            read_receipt_context,
            carapace_manages_read_receipts,
            "ignored unsupported Signal group message",
        )
        .await;
        warn!("Ignoring Signal group message: Signal outbound currently supports direct messages only");
        return;
    }

    let (sender, peer_id) = match resolve_signal_sender_and_peer(envelope, data_message) {
        Some(ids) => ids,
        None => {
            warn!("Ignoring Signal envelope with empty sender ID");
            return;
        }
    };
    let (read_receipt_context, read_receipt_task_id) = match read_receipt_context {
        Some(ctx) => match acquire_signal_read_receipt_ownership(state, &sender, ctx.clone()).await
        {
            SignalReadReceiptOwnership::Deferred(task_id) => (Some(ctx), Some(task_id)),
            SignalReadReceiptOwnership::SentImmediately => (None, None),
            SignalReadReceiptOwnership::Unavailable => (None, None),
        },
        None => (None, None),
    };

    debug!(
        sender = %sender,
        text_len = text.len(),
        "Signal inbound message"
    );
    if carapace_manages_read_receipts && read_receipt_context.is_none() {
        warn!(
            sender = %sender,
            "Signal read receipts are enabled but this message did not include a timestamp; Carapace cannot acknowledge it explicitly"
        );
    }

    let options = crate::channels::inbound::InboundDispatchOptions {
        typing_context: Some(TypingContext {
            to: peer_id.clone(),
            ..Default::default()
        }),
        read_receipt_context,
        read_receipt_task_id: read_receipt_task_id.clone(),
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
            if !result.run_spawned {
                if let Some(task_id) = read_receipt_task_id.as_deref() {
                    state
                        .activity_service()
                        .activate_read_receipt(task_id)
                        .await;
                }
                warn!(
                    sender = %sender,
                    "Signal read receipts were claimed for this message but no LLM provider was available at dispatch time; sending the explicit receipt immediately"
                );
            }
            debug!(
                run_id = %result.run_id,
                sender = %sender,
                "Signal agent run dispatched"
            );
        }
        Err(err) => {
            if let Some(task_id) = read_receipt_task_id.as_deref() {
                state
                    .activity_service()
                    .withhold_read_receipt(
                        task_id,
                        crate::channels::activity::READ_RECEIPT_WITHHELD_REASON,
                    )
                    .await;
            }
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
                "source": "+15559876543",
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
                "source": "+15559876543",
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
                "source": "+15559876543",
                "timestamp": 1706745600000
            }
        ]"#;

        let envelopes: Vec<SignalEnvelope> = serde_json::from_str(json).unwrap();
        assert_eq!(envelopes.len(), 1);
        assert!(envelopes[0].data_message.is_none());
    }

    #[test]
    fn test_parse_envelope_with_source_number_field() {
        // signal-cli-rest-api may return `sourceNumber` instead of `source`
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
    fn test_effective_source_number_empty_source_number_fallback() {
        let envelope = SignalEnvelope {
            source_number: Some("   ".to_string()),
            source: Some("+15559876543".to_string()),
            timestamp: None,
            data_message: None,
        };
        assert_eq!(envelope.effective_source_number(), Some("+15559876543"));
    }

    #[test]
    fn test_parse_envelope_with_duplicate_source_fields() {
        let json = r#"[
            {
                "source": "+15559876543",
                "sourceNumber": "+15559876543",
                "dataMessage": {
                    "message": "Hello from duplicate fields!"
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
                "source": "+15559876543",
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
                "source": "+15559876543",
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
            "http://localhost:8080/v1/receive/%2B15551234567"
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
            "http://localhost:8080/v1/receive/%2B15551234567?send_read_receipts=false"
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
            "http://localhost:8080/v1/receive/%2B15551234567?debug=1&send_read_receipts=false"
        );
    }

    #[test]
    fn test_build_receive_url_replaces_existing_send_read_receipts_parameter() {
        assert_eq!(
            build_receive_url(
                &url::Url::parse("http://localhost:8080?debug=1&send_read_receipts=true",).unwrap(),
                "+15551234567",
                true
            )
            .as_str(),
            "http://localhost:8080/v1/receive/%2B15551234567?debug=1&send_read_receipts=false"
        );
    }

    #[test]
    fn test_build_receive_url_strips_existing_send_read_receipts_parameter_when_not_managing_receipts(
    ) {
        assert_eq!(
            build_receive_url(
                &url::Url::parse("http://localhost:8080?debug=1&send_read_receipts=false").unwrap(),
                "+15551234567",
                false,
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
                false
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
                true
            )
            .as_str(),
            "http://localhost:8080/api/v1/receive/%2B15551234567?debug=1&send_read_receipts=false"
        );
    }

    #[test]
    fn test_snapshot_signal_receive_poll_leaves_auto_receipts_enabled_without_signal_plugin() {
        let state = test_state_with_provider(true);
        let activity_service = crate::channels::activity::ActivityService::new();
        let activity_policy = crate::channels::activity::ChannelActivityPolicy {
            read_receipts: crate::channels::activity::ReadReceiptFeaturePolicy {
                enabled: true,
                ..Default::default()
            },
            ..Default::default()
        };

        let snapshot = snapshot_signal_receive_poll(
            &url::Url::parse("http://localhost:8080").unwrap(),
            "+15551234567",
            &activity_policy,
            state.as_ref(),
            &activity_service,
        );

        assert!(!snapshot.carapace_manages_read_receipts);
        assert_eq!(
            snapshot.receive_url.as_str(),
            "http://localhost:8080/v1/receive/%2B15551234567"
        );
    }

    #[tokio::test]
    async fn test_sanitize_signal_receive_transport_error_strips_phone_number_from_url() {
        let err = reqwest::Client::new()
            .get("http://127.0.0.1:1/v1/receive/%2B15551234567?send_read_receipts=false")
            .send()
            .await
            .expect_err("transport request should fail against unreachable port");
        let sanitized = sanitize_signal_receive_transport_error(err);
        assert!(!sanitized.contains("%2B15551234567"));
        assert!(!sanitized.contains("+15551234567"));
        assert!(!sanitized.contains("send_read_receipts=false"));
    }

    #[test]
    fn test_snapshot_signal_receive_poll_uses_single_policy_view() {
        let activity_service = crate::channels::activity::ActivityService::new();
        let state = test_state_with_provider_and_signal_plugin();
        let activity_policy = crate::channels::activity::ChannelActivityPolicy {
            read_receipts: crate::channels::activity::ReadReceiptFeaturePolicy {
                enabled: true,
                ..Default::default()
            },
            ..Default::default()
        };

        let snapshot = snapshot_signal_receive_poll(
            &url::Url::parse("http://localhost:8080/api?debug=1").unwrap(),
            "+15551234567",
            &activity_policy,
            state.as_ref(),
            &activity_service,
        );

        assert!(snapshot.carapace_manages_read_receipts);
        assert_eq!(
            snapshot.receive_url.as_str(),
            "http://localhost:8080/api/v1/receive/%2B15551234567?debug=1&send_read_receipts=false"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_snapshot_signal_receive_poll_leaves_auto_receipts_enabled_when_backlog_is_high() {
        let activity_service =
            crate::channels::activity::ActivityService::with_limits_for_test(8, 1);
        let state = test_state_with_provider_and_signal_plugin();
        activity_service
            .enqueue_after_response_read_receipt(
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
            read_receipts: crate::channels::activity::ReadReceiptFeaturePolicy {
                enabled: true,
                ..Default::default()
            },
            ..Default::default()
        };

        let snapshot = snapshot_signal_receive_poll(
            &url::Url::parse("http://localhost:8080/api?debug=1").unwrap(),
            "+15551234567",
            &activity_policy,
            state.as_ref(),
            &activity_service,
        );

        assert!(!snapshot.carapace_manages_read_receipts);
        assert_eq!(
            snapshot.receive_url.as_str(),
            "http://localhost:8080/api/v1/receive/%2B15551234567?debug=1"
        );
    }

    #[test]
    fn test_snapshot_signal_receive_poll_leaves_auto_receipts_enabled_without_provider() {
        let activity_service = crate::channels::activity::ActivityService::new();
        let state = test_state_with_provider(false);
        let activity_policy = crate::channels::activity::ChannelActivityPolicy {
            read_receipts: crate::channels::activity::ReadReceiptFeaturePolicy {
                enabled: true,
                ..Default::default()
            },
            ..Default::default()
        };

        let snapshot = snapshot_signal_receive_poll(
            &url::Url::parse("http://localhost:8080/api?debug=1").unwrap(),
            "+15551234567",
            &activity_policy,
            state.as_ref(),
            &activity_service,
        );

        assert!(!snapshot.carapace_manages_read_receipts);
        assert_eq!(
            snapshot.receive_url.as_str(),
            "http://localhost:8080/api/v1/receive/%2B15551234567?debug=1"
        );
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
        let envelope = SignalEnvelope {
            source_number: Some("   ".to_string()),
            source: None,
            timestamp: None,
            data_message: Some(SignalDataMessage {
                message: Some("Hello".to_string()),
                timestamp: None,
                group_info: None,
            }),
        };

        let ids =
            resolve_signal_sender_and_peer(&envelope, envelope.data_message.as_ref().unwrap());
        assert!(ids.is_none());
    }

    #[test]
    fn test_resolve_sender_and_peer_ignores_empty_group_id() {
        let envelope = SignalEnvelope {
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

        let ids =
            resolve_signal_sender_and_peer(&envelope, envelope.data_message.as_ref().unwrap());
        assert_eq!(
            ids,
            Some(("+15559876543".to_string(), "+15559876543".to_string()))
        );
    }

    #[test]
    fn test_resolve_sender_and_peer_rejects_group_message_with_phone_number_like_id() {
        let envelope = SignalEnvelope {
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

        let ids =
            resolve_signal_sender_and_peer(&envelope, envelope.data_message.as_ref().unwrap());
        assert!(ids.is_none());
    }

    #[test]
    fn test_resolve_sender_and_peer_rejects_group_messages() {
        let envelope = SignalEnvelope {
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

        let ids =
            resolve_signal_sender_and_peer(&envelope, envelope.data_message.as_ref().unwrap());
        assert!(ids.is_none());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_signal_receive_loop_reload_affects_future_polls_and_messages_only() {
        crate::config::clear_cache();

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
        crate::config::update_cache(initial_config.clone(), initial_config);

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
                .any(|run| run.message == "first" && run.read_receipt_context.is_none())
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
        crate::config::update_cache(reloaded_config.clone(), reloaded_config);

        wait_for_condition(Duration::from_secs(2), || {
            state
                .agent_run_registry
                .lock()
                .snapshot_runs()
                .iter()
                .any(|run| {
                    run.message == "second"
                        && run
                            .read_receipt_context
                            .as_ref()
                            .and_then(|ctx| ctx.timestamp)
                            == Some(1706745601000_u64)
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
        assert!(first.read_receipt_context.is_none());

        let second = runs
            .iter()
            .find(|run| run.message == "second")
            .expect("second inbound run");
        assert_eq!(
            second
                .read_receipt_context
                .as_ref()
                .and_then(|ctx| ctx.timestamp),
            Some(1706745601000_u64)
        );

        crate::config::clear_cache();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_process_envelope_acknowledges_ignored_non_text_message_when_managed() {
        let notify = Arc::new(Notify::new());
        let signal_channel = Arc::new(MockSignalReadReceiptChannel::new(notify.clone()));
        let plugin_registry = Arc::new(PluginRegistry::new());
        plugin_registry.register_channel("signal".to_string(), signal_channel.clone());
        let state = Arc::new(
            WsServerState::new(WsServerConfig::default()).with_plugin_registry(plugin_registry),
        );
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        state
            .activity_service()
            .spawn_read_receipt_worker(state.clone(), shutdown_rx);
        let envelope = SignalEnvelope {
            source_number: Some("+15559876543".to_string()),
            source: None,
            timestamp: Some(1706745600000),
            data_message: Some(SignalDataMessage {
                message: None,
                timestamp: Some(1706745600000),
                group_info: None,
            }),
        };

        process_envelope(&envelope, &state, true).await;

        tokio::time::timeout(Duration::from_secs(1), notify.notified())
            .await
            .expect("ignored non-text messages should still be acknowledged");
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
        .expect("ignored-envelope receipt task should settle to done");
        assert!(
            state.agent_run_registry.lock().snapshot_runs().is_empty(),
            "ignored non-text messages should not create agent runs"
        );
        shutdown_tx
            .send(true)
            .expect("read receipt worker shutdown signal should send");
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
            source_number: Some("+15559876543".to_string()),
            source: None,
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
}
