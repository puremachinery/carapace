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

fn build_receive_url(
    base_url: &str,
    phone_number: &str,
    disable_auto_read_receipts: bool,
) -> String {
    let encoded_phone_number = urlencoding::encode(phone_number);
    if disable_auto_read_receipts {
        format!(
            "{}/v1/receive/{}?send_read_receipts=false",
            base_url, encoded_phone_number
        )
    } else {
        format!("{}/v1/receive/{}", base_url, encoded_phone_number)
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
        Ok(url) => url.to_string().trim_end_matches('/').to_string(),
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
    let mut activity_policy = crate::channels::activity::load_channel_activity_policy("signal");

    // Track consecutive transport and parse errors to avoid spamming logs.
    let mut consecutive_errors: u32 = 0;
    let mut consecutive_parse_errors: u32 = 0;

    loop {
        // Check shutdown before polling
        if *shutdown.borrow() {
            info!("Signal receive loop shutting down");
            break;
        }

        let receive_url = build_receive_url(
            &base_url,
            &phone_number,
            activity_policy.read_receipts.enabled,
        );

        match client.get(&receive_url).send().await {
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
                                    process_envelope(&envelope, &state).await;
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
                if consecutive_errors <= 3 {
                    warn!("Signal receive error: {}", e);
                } else if consecutive_errors == 4 {
                    warn!(
                        "Signal receive errors continuing (suppressing further logs until recovery)"
                    );
                }
                channel_registry.set_error("signal", e.to_string());
            }
        }

        // Wait for poll interval or shutdown
        tokio::select! {
            _ = tokio::time::sleep(POLL_INTERVAL) => {}
            changed = config_rx.changed() => {
                if changed.is_err() {
                    info!("Signal receive loop config subscription closed");
                    break;
                }
                activity_policy = crate::channels::activity::load_channel_activity_policy("signal");
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
async fn process_envelope(envelope: &SignalEnvelope, state: &Arc<WsServerState>) {
    let data_message = match &envelope.data_message {
        Some(dm) => dm,
        None => return, // Not a data message (e.g., receipt, typing indicator)
    };

    let text = match &data_message.message {
        Some(t) if !t.is_empty() => t,
        _ => return, // No text content
    };

    if signal_group_id(data_message).is_some() {
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

    debug!(
        sender = %sender,
        text_len = text.len(),
        "Signal inbound message"
    );

    let options = crate::channels::inbound::InboundDispatchOptions {
        typing_context: Some(TypingContext {
            to: peer_id.clone(),
            ..Default::default()
        }),
        read_receipt_context: build_signal_read_receipt_context(envelope, data_message, &sender),
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
        Ok(run_id) => {
            debug!(
                run_id = %run_id,
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
    use super::*;

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
            build_receive_url("http://localhost:8080", "+15551234567", false),
            "http://localhost:8080/v1/receive/%2B15551234567"
        );
    }

    #[test]
    fn test_build_receive_url_disables_signal_auto_receipts_when_feature_enabled() {
        assert_eq!(
            build_receive_url("http://localhost:8080", "+15551234567", true),
            "http://localhost:8080/v1/receive/%2B15551234567?send_read_receipts=false"
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
}
