//! Signal inbound receive loop.
//!
//! Polls the signal-cli-rest-api `GET /v1/receive/{number}` endpoint every
//! 2 seconds and routes inbound messages into the chat pipeline.

use std::sync::Arc;
use std::time::Duration;

use serde::Deserialize;
use serde_json::Value;
use tracing::{debug, error, info, warn};

use crate::channels::{ChannelRegistry, ChannelStatus};
use crate::server::ws::WsServerState;
use crate::sessions::{get_or_create_scoped_session, SessionMetadata};

/// Backoff between failed receive polls.
const ERROR_BACKOFF: Duration = Duration::from_secs(2);

/// Timeout for each receive HTTP request.
const RECEIVE_TIMEOUT: Duration = Duration::from_secs(30);

/// An envelope returned by `GET /v1/receive/{number}`.
#[derive(Debug, Deserialize)]
pub struct SignalEnvelope {
    /// Source phone number (e.g. "+15559876543").
    #[serde(default)]
    pub source: Option<String>,

    /// Source phone number (newer key).
    #[serde(default, rename = "sourceNumber")]
    pub source_number: Option<String>,

    /// Source UUID.
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

/// Builds the receive URL for the signal-cli-rest-api with the read receipts flag.
pub fn build_receive_url(base_url: &str, phone_number: &str) -> String {
    format!(
        "{}/v1/receive/{}?timeout=20&i=true",
        base_url,
        urlencoding::encode(phone_number)
    )
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

    let receive_url = build_receive_url(&base_url, &phone_number);

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

        let mut had_error = false;

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

                match resp.json::<Vec<serde_json::Value>>().await {
                    Ok(items) => {
                        for item in items {
                            info!("Raw JSON item received: {}", item);
                            let env_val = item.get("envelope").unwrap_or(&item);
                            match serde_json::from_value::<SignalEnvelope>(env_val.clone()) {
                                Ok(envelope) => {
                                    process_envelope(
                                        &envelope,
                                        &state,
                                        client.clone(),
                                        &base_url,
                                        &phone_number,
                                    )
                                    .await;
                                }
                                Err(err) => {
                                    warn!("Failed to cleanly deserialize envelope: {} - JSON: {}", err, env_val);
                                }
                            }
                        }
                    }
                    Err(e) => {
                        error!("Failed to read Signal receive response: {}", e);
                    }
                }
            }
            Ok(resp) => {
                had_error = true;
                consecutive_errors += 1;
                let status = resp.status();
                if consecutive_errors <= 3 {
                    warn!("Signal receive HTTP {}", status);
                }
                channel_registry.set_error("signal", format!("HTTP {}", status));
            }
            Err(e) => {
                had_error = true;
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

        if had_error {
            // Wait for backoff interval or shutdown
            tokio::select! {
                _ = tokio::time::sleep(ERROR_BACKOFF) => {}
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        info!("Signal receive loop shutting down");
                        break;
                    }
                }
            }
        }
    }
}



/// Builds the JSON payload for a Signal read receipt.
fn build_read_receipt_payload(sender: &str, timestamp: u64) -> serde_json::Value {
    serde_json::json!({
        "receipt_type": "read",
        "recipient": sender,
        "timestamp": timestamp,
    })
}

/// Process a single inbound Signal envelope by routing it into the chat pipeline.
async fn process_envelope(
    envelope: &SignalEnvelope,
    state: &Arc<WsServerState>,
    client: reqwest::Client,
    base_url: &str,
    phone_number: &str,
) {
    let data_message = match &envelope.data_message {
        Some(dm) => dm,
        None => {
            info!("Dropped envelope without dataMessage (could be syncMessage/receipt): {:?}", envelope);
            return;
        }
    };

    let text = match &data_message.message {
        Some(t) if !t.is_empty() => t,
        _ => return, // No text content
    };

    let sender = match envelope
        .source_uuid
        .as_ref()
        .or(envelope.source_number.as_ref())
        .or(envelope.source.as_ref())
    {
        Some(s) => s,
        None => return, // No sender info
    };

    let receipt_recipient = match envelope
        .source_number
        .as_ref()
        .or(envelope.source.as_ref())
        .or(envelope.source_uuid.as_ref())
    {
        Some(s) => s.to_string(),
        None => sender.to_string(), // Fallback
    };

    info!(
        sender = %sender,
        text_len = text.len(),
        "Signal inbound message"
    );

    let cfg = crate::config::load_config_shared()
        .unwrap_or_else(|_| Arc::new(Value::Object(serde_json::Map::new())));
    let group_id = data_message
        .group_info
        .as_ref()
        .and_then(|group| group.group_id.clone());
    let peer_id = group_id.as_deref().unwrap_or(sender).to_string();

    let metadata = SessionMetadata {
        channel: Some("signal".to_string()),
        user_id: Some(sender.to_string()),
        chat_id: Some(peer_id.clone()),
        ..Default::default()
    };

    let session_store = state.session_store();
    let session = match get_or_create_scoped_session(
        session_store,
        cfg.as_ref(),
        "signal",
        sender,
        peer_id.as_str(),
        None,
        metadata,
    ) {
        Ok(session) => session,
        Err(e) => {
            error!("Failed to get/create Signal session for {}: {}", sender, e);
            return;
        }
    };

    // Append the user message
    if let Err(e) = crate::sessions::append_message_blocking(
        state.session_store().clone(),
        crate::sessions::ChatMessage::user(session.id.clone(), text),
    )
    .await
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
        let mut config = crate::agent::AgentConfig::default();
        crate::agent::apply_agent_config_from_settings(&mut config, &cfg, None);
        config.deliver = true;
        crate::agent::spawn_run(
            run_id.clone(),
            session.session_key.clone(),
            config,
            state.clone(),
            provider,
            cancel_token,
        );
        info!(
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

    // Fire off a read receipt asynchronously
    let receipt_url = format!(
        "{}/v1/receipts/{}",
        base_url,
        urlencoding::encode(phone_number)
    );
    let sender_clone = sender.to_string();
    let timestamp = data_message.timestamp.or(envelope.timestamp).unwrap_or_else(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
    });

    let payload = build_read_receipt_payload(&receipt_recipient, timestamp);

    // Spawn read receipt
    let client_clone = client.clone();
    tokio::spawn(async move {
        match client_clone.post(&receipt_url).json(&payload).send().await {
            Ok(resp) if resp.status().is_success() => {
                debug!(
                    sender = %sender_clone,
                    timestamp = timestamp,
                    "Signal read receipt sent successfully"
                );
            }
            Ok(resp) => {
                warn!(
                    status = %resp.status(),
                    sender = %sender_clone,
                    "Failed to send Signal read receipt (HTTP Error)"
                );
            }
            Err(e) => {
                warn!(
                    error = %e,
                    sender = %sender_clone,
                    "Failed to send Signal read receipt (Network Error)"
                );
            }
        }
    });

    // Start typing indicator loop
    let typing_url = format!(
        "{}/v1/typing-indicator/{}",
        base_url,
        urlencoding::encode(phone_number)
    );

    // Fallback to 3 seconds if not present
    let typing_interval = Duration::from_secs(
        cfg.get("session")
            .and_then(|s| s.get("typing_interval_seconds"))
            .and_then(|t| t.as_u64())
            .unwrap_or(3) as u64,
    );

    let typing_payload = serde_json::json!({
        "recipient": peer_id
    });

    let run_id_clone = run_id.clone();
    let state_clone = Arc::clone(state);

    tokio::spawn(async move {
        info!(run_id = %run_id_clone, peer_id = %peer_id, "Signal typing indicator started");
        let mut loop_interval = tokio::time::interval(typing_interval);

        loop {
            loop_interval.tick().await;

            let status = {
                let registry = state_clone.agent_run_registry.lock();
                registry.get(&run_id_clone).map(|r| r.status)
            };

            match status {
                Some(crate::server::ws::AgentRunStatus::Completed)
                | Some(crate::server::ws::AgentRunStatus::Failed)
                | Some(crate::server::ws::AgentRunStatus::Cancelled)
                | None => {
                    // Stop typing indicator
                    let stop_payload = serde_json::json!({
                        "recipient": peer_id
                    });

                    if let Err(e) = client.delete(&typing_url).json(&stop_payload).send().await {
                        debug!("Failed to stop Signal typing indicator: {}", e);
                    } else {
                        info!(run_id = %run_id_clone, peer_id = %peer_id, "Signal typing indicator stopped");
                    }
                    break;
                }
                _ => {
                    // Send typing indicator pulse
                    if let Err(e) = client.put(&typing_url).json(&typing_payload).send().await {
                        debug!("Failed to send Signal typing indicator pulse: {}", e);
                    }
                }
            }
        }
    });
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
        assert_eq!(envelopes[0].source.as_deref().or(envelopes[0].source_number.as_deref()), Some("+15559876543"));
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

    #[test]
    fn test_parse_envelope_with_source_uuid_field() {
        let json = r#"[
            {
                "sourceUuid": "8fe77508-3017-48de-82ed-5722f4b48625",
                "sourceNumber": "+15559876543",
                "dataMessage": {
                    "message": "Hello"
                }
            }
        ]"#;

        let envelopes: Vec<SignalEnvelope> = serde_json::from_str(json).unwrap();
        assert_eq!(envelopes.len(), 1);
        assert_eq!(
            envelopes[0].source_uuid.as_deref(),
            Some("8fe77508-3017-48de-82ed-5722f4b48625")
        );
        assert_eq!(
            envelopes[0]
                .source_uuid
                .as_ref()
                .or(envelopes[0].source_number.as_ref())
                .or(envelopes[0].source.as_ref())
                .map(|s| s.as_str()),
            Some("8fe77508-3017-48de-82ed-5722f4b48625")
        );
    }

    #[test]
    fn test_build_read_receipt_payload() {
        let payload = super::build_read_receipt_payload("8fe77508-3017-48de-82ed-5722f4b48625", 1706745600000);
        assert_eq!(payload["receipt_type"], "read");
        assert_eq!(payload["recipient"], "8fe77508-3017-48de-82ed-5722f4b48625");
        assert_eq!(payload["timestamp"], 1706745600000_u64);
    }

    #[test]
    fn test_build_receive_url() {
        let base_url = "http://loopback:8080";
        let phone_number = "+12506417114";

        let url = super::build_receive_url(base_url, phone_number);

        // Ensure + gets url-encoded
        assert!(url.contains("%2B12506417114"));
        assert!(url.starts_with("http://loopback:8080/v1/receive/"));
        // Ensure read receipts feature flag is enabled
        assert!(url.contains("i=true"));
        assert_eq!(url, "http://loopback:8080/v1/receive/%2B12506417114?timeout=20&i=true");
    }

    #[tokio::test]
    async fn test_signal_typing_indicator_flow() {
        use axum::{routing::{post, put}, Router, extract::Path};
        use std::sync::{Arc, Mutex};
        use std::time::Duration;
        use tokio::net::TcpListener;

        let requests = Arc::new(Mutex::new(Vec::new()));

        let app = Router::new()
            .route(
                "/v1/receipts/{number}",
                post({
                    let reqs = requests.clone();
                    move |Path(number): Path<String>| async move {
                        reqs.lock().unwrap().push(format!("POST_RECEIPT_{}", number));
                        axum::http::StatusCode::OK
                    }
                })
            )
            .route(
                "/v1/typing-indicator/{number}",
                put({
                    let reqs = requests.clone();
                    move |Path(number): Path<String>| async move {
                        reqs.lock().unwrap().push(format!("PUT_TYPING_{}", number));
                        axum::http::StatusCode::OK
                    }
                })
                .delete({
                    let reqs = requests.clone();
                    move |Path(number): Path<String>| async move {
                        reqs.lock().unwrap().push(format!("DELETE_TYPING_{}", number));
                        axum::http::StatusCode::OK
                    }
                })
            );

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let base_url = format!("http://{}", addr);
        let phone_number = "+15551234567";
        let sender = "+15559876543";

        let tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(crate::sessions::SessionStore::with_base_path(
            tmp.path().join("sessions"),
        ));
        let state = Arc::new(crate::server::ws::WsServerState::new(crate::server::ws::WsServerConfig::default()).with_session_store(store));

        let json = format!(r#"{{
            "source": "{}",
            "timestamp": 1706745600000,
            "dataMessage": {{
                "message": "Hello from Signal test!",
                "timestamp": 1706745600000
            }}
        }}"#, sender);

        let envelope: SignalEnvelope = serde_json::from_str(&json).unwrap();
        let client = reqwest::Client::new();

        super::process_envelope(&envelope, &state, client, &base_url, phone_number).await;

        // Give it a moment for the typing loop to run
        tokio::time::sleep(Duration::from_millis(1500)).await;

        {
            let reqs = requests.lock().unwrap();
            assert!(reqs.contains(&format!("POST_RECEIPT_{}", phone_number)), "Requests: {:?}", reqs);
            assert!(reqs.contains(&format!("PUT_TYPING_{}", phone_number)), "Requests: {:?}", reqs);
            assert!(!reqs.contains(&format!("DELETE_TYPING_{}", phone_number)), "Requests: {:?}", reqs);
        }

        // Find the active run and mark it completed to trigger DELETE
        let session_key = format!("signal:{}", sender);
        let run_id = {
            let registry = state.agent_run_registry.lock();
            let runs = registry.get_active_runs_for_session(&session_key);
            assert_eq!(runs.len(), 1, "Should have exactly one active run");
            runs[0].clone()
        };

        {
            let mut registry = state.agent_run_registry.lock();
            registry.mark_completed(&run_id, "Done".to_string());
        }

        // Wait a bit for the next interval to notice the status change (default is 3s)
        tokio::time::sleep(Duration::from_millis(3500)).await;

        {
            let reqs = requests.lock().unwrap();
            assert!(reqs.contains(&format!("DELETE_TYPING_{}", phone_number)), "Requests: {:?}", reqs);
        }
    }

    #[tokio::test]
    async fn test_signal_receive_to_response_latency() {
        use axum::{routing::{get, post, put}, Router, extract::Path};
        use std::sync::{Arc, Mutex};
        use std::time::{Duration, Instant};
        use tokio::net::TcpListener;

        let timestamps = Arc::new(Mutex::new(Vec::new()));

        let app = Router::new()
            .route(
                "/v1/receive/{number}",
                get({
                    let ts = timestamps.clone();
                    move |Path(_number): Path<String>| async move {
                        let mut locked = ts.lock().unwrap();
                        if locked.is_empty() {
                            // First poll: record receive time and send a message
                            locked.push(Instant::now());
                            let json = serde_json::json!([{
                                "source": "+15559876543",
                                "timestamp": 1706745600000_u64,
                                "dataMessage": {
                                    "message": "Latency test",
                                    "timestamp": 1706745600000_u64
                                }
                            }]);
                            axum::Json(json)
                        } else {
                            // Subsequent polls: return empty immediately
                            axum::Json(serde_json::json!([]))
                        }
                    }
                })
            )
            .route(
                "/v1/receipts/{number}",
                post({
                    let ts = timestamps.clone();
                    move |Path(_number): Path<String>| async move {
                        let mut locked = ts.lock().unwrap();
                        if locked.len() == 1 {
                             locked.push(Instant::now()); // Record response time
                        }
                        axum::http::StatusCode::OK
                    }
                })
            )
            .route(
                "/v1/typing-indicator/{number}",
                put(|| async move { axum::http::StatusCode::OK })
                .delete(|| async move { axum::http::StatusCode::OK })
            );

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let base_url = format!("http://{}", addr);
        let phone_number = "+15551234567";

        let tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(crate::sessions::SessionStore::with_base_path(
            tmp.path().join("sessions"),
        ));
        let state = Arc::new(crate::server::ws::WsServerState::new(crate::server::ws::WsServerConfig::default()).with_session_store(store));

        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let channel_registry = Arc::new(crate::channels::ChannelRegistry::new());

        let loop_handle = tokio::spawn(super::signal_receive_loop(
            base_url,
            phone_number.to_string(),
            state,
            channel_registry,
            shutdown_rx,
        ));

        // Wait a tiny bit for the loop to fetch and process the message containing the fake timestamp
        tokio::time::sleep(Duration::from_millis(150)).await;

        shutdown_tx.send(true).unwrap();
        let _ = loop_handle.await;

        let locked_ts = timestamps.lock().unwrap();

        // Output detailed timing if it failed
        assert!(locked_ts.len() >= 2, "Test failed: mock server was not hit enough times. Got {} hits", locked_ts.len());

        let receive_time = locked_ts[0];
        let receipt_time = locked_ts[1];
        let latency = receipt_time.duration_since(receive_time);

        // Assert latency is extremely small (sub 50ms)
        assert!(latency < Duration::from_millis(50), "Latency was too high: {latency:?}");
    }
}
