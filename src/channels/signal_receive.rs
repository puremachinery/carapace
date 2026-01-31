//! Signal inbound receive loop.
//!
//! Polls the signal-cli-rest-api `GET /v1/receive/{number}` endpoint every
//! 2 seconds and routes inbound messages into the chat pipeline.

use std::sync::Arc;
use std::time::Duration;

use serde::Deserialize;
use tracing::{debug, error, info, warn};

use crate::channels::{ChannelRegistry, ChannelStatus};
use crate::server::ws::WsServerState;

/// Interval between receive polls.
const POLL_INTERVAL: Duration = Duration::from_secs(2);

/// Timeout for each receive HTTP request.
const RECEIVE_TIMEOUT: Duration = Duration::from_secs(10);

/// An envelope returned by `GET /v1/receive/{number}`.
#[derive(Debug, Deserialize)]
pub struct SignalEnvelope {
    /// Source phone number (e.g. "+15559876543").
    #[serde(default, rename = "sourceNumber", alias = "source")]
    pub source_number: Option<String>,

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

/// Group metadata on a Signal message.
#[derive(Debug, Deserialize)]
pub struct SignalGroupInfo {
    /// Group identifier (base64).
    #[serde(default, alias = "groupId")]
    pub group_id: Option<String>,
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
    let client = reqwest::Client::builder()
        .timeout(RECEIVE_TIMEOUT)
        .build()
        .expect("failed to build Signal receive HTTP client");
    let receive_url = format!(
        "{}/v1/receive/{}",
        base_url,
        urlencoding::encode(&phone_number)
    );

    info!(
        url = %receive_url,
        "Signal receive loop started"
    );

    // Track consecutive errors to avoid spamming logs
    let mut consecutive_errors: u32 = 0;

    loop {
        // Check shutdown before polling
        if *shutdown.borrow() {
            info!("Signal receive loop shutting down");
            break;
        }

        match client.get(&receive_url).send().await {
            Ok(resp) if resp.status().is_success() => {
                if consecutive_errors > 0 {
                    info!(
                        "Signal receive loop recovered after {} errors",
                        consecutive_errors
                    );
                    consecutive_errors = 0;
                }
                channel_registry.update_status("signal", ChannelStatus::Connected);

                match resp.json::<Vec<SignalEnvelope>>().await {
                    Ok(envelopes) => {
                        for envelope in envelopes {
                            process_envelope(&envelope, &state);
                        }
                    }
                    Err(e) => {
                        debug!("Failed to parse Signal receive response: {}", e);
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
fn process_envelope(envelope: &SignalEnvelope, state: &Arc<WsServerState>) {
    let data_message = match &envelope.data_message {
        Some(dm) => dm,
        None => return, // Not a data message (e.g., receipt, typing indicator)
    };

    let text = match &data_message.message {
        Some(t) if !t.is_empty() => t,
        _ => return, // No text content
    };

    let sender = match &envelope.source_number {
        Some(s) => s,
        None => return, // No sender info
    };

    debug!(
        sender = %sender,
        text_len = text.len(),
        "Signal inbound message"
    );

    // Build a session key scoped to Signal + sender
    let session_key = format!("signal:{}", sender);

    let metadata = crate::sessions::SessionMetadata {
        channel: Some("signal".to_string()),
        ..Default::default()
    };

    // Get or create the session
    let session = match state
        .session_store()
        .get_or_create_session(&session_key, metadata)
    {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to get/create Signal session for {}: {}", sender, e);
            return;
        }
    };

    // Append the user message
    if let Err(e) = state
        .session_store()
        .append_message(crate::sessions::ChatMessage::user(session.id.clone(), text))
    {
        error!("Failed to append Signal message: {}", e);
        return;
    }

    // Register and spawn agent run
    let run_id = uuid::Uuid::new_v4().to_string();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    let cancel_token = tokio_util::sync::CancellationToken::new();
    let run = crate::server::ws::AgentRun {
        run_id: run_id.clone(),
        session_key: session.session_key.clone(),
        status: crate::server::ws::AgentRunStatus::Queued,
        message: text.to_string(),
        response: String::new(),
        error: None,
        created_at: now,
        started_at: None,
        completed_at: None,
        cancel_token: cancel_token.clone(),
        waiters: Vec::new(),
    };

    {
        let mut registry = state.agent_run_registry.lock();
        registry.register(run);
    }

    if let Some(provider) = state.llm_provider() {
        let config = crate::agent::AgentConfig {
            deliver: true,
            ..Default::default()
        };
        crate::agent::spawn_run(
            run_id.clone(),
            session.session_key.clone(),
            config,
            state.clone(),
            provider,
            cancel_token,
        );
        debug!(
            run_id = %run_id,
            sender = %sender,
            "Signal agent run dispatched"
        );
    } else {
        debug!(
            run_id = %run_id,
            "Signal message queued (no LLM provider)"
        );
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
        assert_eq!(envelopes[0].source_number.as_deref(), Some("+15559876543"));
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
        assert_eq!(envelopes[0].source_number.as_deref(), Some("+15559876543"));
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
}
