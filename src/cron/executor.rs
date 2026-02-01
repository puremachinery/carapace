//! Cron payload executor.
//!
//! Executes the payload of a cron job after `run()` marks it as started.
//! Supports `SystemEvent` (broadcast) and `AgentTurn` (spawn agent run).

use std::sync::Arc;

use crate::cron::CronPayload;
use crate::messages::outbound::{
    MessageContent, MessageMetadata, OutboundContext, OutboundMessage,
};
use crate::server::ws::{SystemEvent, WsServerState};
use serde_json::Value;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

/// Outcome of executing a cron payload.
#[derive(Debug)]
pub enum CronRunOutcome {
    /// A SystemEvent was enqueued and broadcast.
    Broadcast,
    /// An AgentTurn was spawned.
    Spawned { run_id: String },
}

/// Execute a cron job payload.
///
/// For `SystemEvent`: enqueues the event into system event history.
/// For `AgentTurn`: creates a session, registers an agent run, and spawns execution.
pub async fn execute_payload(
    job_id: &str,
    payload: &CronPayload,
    state: &Arc<WsServerState>,
) -> Result<CronRunOutcome, String> {
    match payload {
        CronPayload::SystemEvent { text } => {
            let now = crate::cron::now_ms();
            state.enqueue_system_event(SystemEvent {
                ts: now,
                text: text.clone(),
                host: None,
                ip: None,
                device_id: None,
                instance_id: Some(format!("cron:{}", job_id)),
                reason: Some("cron".to_string()),
            });
            Ok(CronRunOutcome::Broadcast)
        }
        CronPayload::AgentTurn {
            message,
            model,
            thinking,
            timeout_seconds,
            allow_unsafe_external_content,
            deliver,
            channel,
            to,
            best_effort_deliver,
        } => {
            let session_key = format!("cron:{}", job_id);
            let run_id = uuid::Uuid::new_v4().to_string();

            let normalized_channel = channel
                .as_ref()
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .map(|s| s.to_ascii_lowercase());
            let normalized_to = to
                .as_ref()
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string());

            let mut metadata = crate::sessions::SessionMetadata::default();
            if let Some(ref value) = normalized_channel {
                metadata.channel = Some(value.clone());
            }
            if let Some(ref value) = normalized_to {
                metadata.chat_id = Some(value.clone());
            }
            if let Some(ref value) = thinking {
                metadata.thinking_level = Some(value.clone());
            }
            if let Some(ref value) = model {
                metadata.model = Some(value.clone());
            }

            // Ensure session exists
            let session = state
                .session_store()
                .get_or_create_session(&session_key, metadata)
                .map_err(|e| format!("failed to create session: {}", e))?;

            // Append user message
            let msg = crate::sessions::ChatMessage::user(&session.id, message);
            state
                .session_store()
                .append_message(msg)
                .map_err(|e| format!("failed to append message: {}", e))?;

            // Build agent config
            let cfg = crate::config::load_config().unwrap_or(Value::Object(serde_json::Map::new()));
            let mut config = crate::agent::AgentConfig::default();
            crate::agent::apply_agent_config_from_settings(&mut config, &cfg, None);
            config.model = model
                .clone()
                .unwrap_or_else(|| crate::agent::DEFAULT_MODEL.to_string());
            if let Some(&allow) = allow_unsafe_external_content.as_ref() {
                config.exfiltration_guard = !allow;
            }
            if let Some(&deliver) = deliver.as_ref() {
                config.deliver = deliver;
            }

            // Register the agent run
            let cancel_token = CancellationToken::new();
            {
                use crate::server::ws::AgentRunStatus;
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as u64;
                let mut registry = state.agent_run_registry.lock();
                registry.register(crate::server::ws::AgentRun {
                    run_id: run_id.clone(),
                    session_key: session_key.clone(),
                    status: AgentRunStatus::Queued,
                    message: message.clone(),
                    response: String::new(),
                    error: None,
                    created_at: now,
                    started_at: None,
                    completed_at: None,
                    cancel_token: cancel_token.clone(),
                    waiters: Vec::new(),
                });
            }

            if let Some(&timeout) = timeout_seconds.as_ref() {
                if timeout > 0 {
                    let run_id = run_id.clone();
                    let cancel_token = cancel_token.clone();
                    tokio::spawn(async move {
                        tokio::time::sleep(Duration::from_secs(timeout as u64)).await;
                        tracing::warn!(
                            run_id = %run_id,
                            timeout_seconds = timeout,
                            "cron agent run exceeded timeout; cancelling"
                        );
                        cancel_token.cancel();
                    });
                }
            }

            let provider = state
                .llm_provider()
                .ok_or_else(|| "no LLM provider configured".to_string())?;

            if deliver.unwrap_or(false) {
                match (normalized_channel.clone(), normalized_to.clone()) {
                    (Some(channel_id), Some(recipient_id)) => {
                        let delivery_pipeline = Arc::clone(state.message_pipeline());
                        let delivery_run_id = run_id.clone();
                        let delivery_message_id = format!("cron-deliver:{delivery_run_id}");
                        let retry_enabled = best_effort_deliver.unwrap_or(false);
                        let waiter = {
                            let mut registry = state.agent_run_registry.lock();
                            registry.add_waiter(&run_id)
                        };
                        if let Some(waiter) = waiter {
                            tokio::spawn(async move {
                                let result = match waiter.await {
                                    Ok(result) => result,
                                    Err(_) => {
                                        tracing::warn!(
                                            run_id = %delivery_run_id,
                                            "cron delivery waiter dropped before completion"
                                        );
                                        return;
                                    }
                                };
                                if result.status != crate::server::ws::AgentRunStatus::Completed {
                                    return;
                                }
                                let Some(content) = result.response else {
                                    return;
                                };
                                let metadata = MessageMetadata {
                                    recipient_id: Some(recipient_id),
                                    ..Default::default()
                                };
                                let outbound =
                                    OutboundMessage::new(channel_id, MessageContent::text(content))
                                        .with_metadata(metadata);
                                let mut ctx =
                                    OutboundContext::new().with_trace_id(&delivery_message_id);
                                if retry_enabled {
                                    ctx = ctx.with_retries(3);
                                }
                                if let Err(err) = delivery_pipeline.queue_with_idempotency(
                                    outbound,
                                    ctx,
                                    Some(&delivery_message_id),
                                ) {
                                    tracing::warn!(
                                        run_id = %delivery_run_id,
                                        error = %err,
                                        "failed to queue cron delivery message"
                                    );
                                }
                            });
                        }
                    }
                    (None, _) => {
                        tracing::warn!(
                            job_id = %job_id,
                            "cron delivery requested without channel; skipping"
                        );
                    }
                    (_, None) => {
                        tracing::warn!(
                            job_id = %job_id,
                            "cron delivery requested without recipient; skipping"
                        );
                    }
                }
            }

            // Spawn agent execution
            crate::agent::spawn_run(
                run_id.clone(),
                session_key,
                config,
                state.clone(),
                provider,
                cancel_token,
            );

            Ok(CronRunOutcome::Spawned { run_id })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cron::CronPayload;
    use crate::server::ws::{WsServerConfig, WsServerState};
    use crate::sessions;
    use std::sync::Arc;

    /// Create a WsServerState backed by a temp directory so tests work on all
    /// platforms (including Windows CI where writing to ~/.moltbot may fail).
    fn make_test_state() -> (Arc<WsServerState>, tempfile::TempDir) {
        let tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(sessions::SessionStore::with_base_path(
            tmp.path().join("sessions"),
        ));
        let state = WsServerState::new(WsServerConfig::default()).with_session_store(store);
        (Arc::new(state), tmp)
    }

    #[tokio::test]
    async fn test_execute_system_event() {
        let (state, _tmp) = make_test_state();

        let payload = CronPayload::SystemEvent {
            text: "test cron event".to_string(),
        };

        let result = execute_payload("job-1", &payload, &state).await;
        assert!(result.is_ok());
        assert!(matches!(result.unwrap(), CronRunOutcome::Broadcast));
    }

    #[tokio::test]
    async fn test_execute_agent_turn_no_provider() {
        // Without an LLM provider, agent turn should fail
        let (state, _tmp) = make_test_state();

        let payload = CronPayload::AgentTurn {
            message: "do something".to_string(),
            model: None,
            thinking: None,
            timeout_seconds: None,
            allow_unsafe_external_content: None,
            deliver: None,
            channel: None,
            to: None,
            best_effort_deliver: None,
        };

        let result = execute_payload("job-2", &payload, &state).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("no LLM provider"));
    }

    #[tokio::test]
    async fn test_agent_turn_applies_session_metadata() {
        let (state, _tmp) = make_test_state();

        let payload = CronPayload::AgentTurn {
            message: "hello".to_string(),
            model: Some("model-x".to_string()),
            thinking: Some("deep".to_string()),
            timeout_seconds: Some(10),
            allow_unsafe_external_content: Some(false),
            deliver: Some(true),
            channel: Some("Signal".to_string()),
            to: Some("123".to_string()),
            best_effort_deliver: Some(true),
        };

        let result = execute_payload("job-meta", &payload, &state).await;
        assert!(result.is_err());

        let session = state
            .session_store()
            .get_session_by_key("cron:job-meta")
            .unwrap();
        assert_eq!(session.metadata.channel, Some("signal".to_string()));
        assert_eq!(session.metadata.chat_id, Some("123".to_string()));
        assert_eq!(session.metadata.thinking_level, Some("deep".to_string()));
        assert_eq!(session.metadata.model, Some("model-x".to_string()));
    }
}
