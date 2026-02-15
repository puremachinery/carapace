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
        CronPayload::SystemEvent { text } => execute_system_event(job_id, text, state),
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
            execute_agent_turn(
                job_id,
                state,
                AgentTurnParams {
                    message,
                    model,
                    thinking,
                    timeout_seconds: *timeout_seconds,
                    allow_unsafe_external_content: *allow_unsafe_external_content,
                    deliver: *deliver,
                    channel,
                    to,
                    best_effort_deliver: *best_effort_deliver,
                },
            )
            .await
        }
    }
}

struct AgentTurnParams<'a> {
    message: &'a str,
    model: &'a Option<String>,
    thinking: &'a Option<String>,
    timeout_seconds: Option<u32>,
    allow_unsafe_external_content: Option<bool>,
    deliver: Option<bool>,
    channel: &'a Option<String>,
    to: &'a Option<String>,
    best_effort_deliver: Option<bool>,
}

fn execute_system_event(
    job_id: &str,
    text: &str,
    state: &Arc<WsServerState>,
) -> Result<CronRunOutcome, String> {
    let now = crate::cron::now_ms();
    state.enqueue_system_event(SystemEvent {
        ts: now,
        text: text.to_string(),
        host: None,
        ip: None,
        device_id: None,
        instance_id: Some(format!("cron:{}", job_id)),
        reason: Some("cron".to_string()),
    });
    Ok(CronRunOutcome::Broadcast)
}

async fn execute_agent_turn(
    job_id: &str,
    state: &Arc<WsServerState>,
    params: AgentTurnParams<'_>,
) -> Result<CronRunOutcome, String> {
    let session_key = format!("cron:{}", job_id);
    let run_id = uuid::Uuid::new_v4().to_string();
    let normalized_channel = normalize_channel(params.channel);
    let normalized_to = normalize_recipient(params.to);

    let metadata = build_session_metadata(
        &normalized_channel,
        &normalized_to,
        params.thinking,
        params.model,
    );
    let has_metadata_updates = has_metadata_updates(
        &normalized_channel,
        &normalized_to,
        params.thinking,
        params.model,
    );

    let session = load_or_create_cron_session(state, &session_key, metadata, has_metadata_updates)?;
    append_user_message(state, &session.id, params.message)?;

    let config = build_agent_config(
        params.model,
        params.allow_unsafe_external_content,
        params.deliver,
    );

    let cancel_token = CancellationToken::new();
    register_agent_run(state, &run_id, &session_key, params.message, &cancel_token);
    spawn_timeout_cancellation(state, &run_id, params.timeout_seconds, cancel_token.clone());

    let provider = state
        .llm_provider()
        .ok_or_else(|| "no LLM provider configured".to_string())?;

    spawn_delivery_waiter_if_enabled(
        state,
        &run_id,
        job_id,
        params.deliver.unwrap_or(false),
        params.best_effort_deliver.unwrap_or(false),
        normalized_channel,
        normalized_to,
    );

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

fn normalize_channel(channel: &Option<String>) -> Option<String> {
    channel
        .as_ref()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_ascii_lowercase())
}

fn normalize_recipient(to: &Option<String>) -> Option<String> {
    to.as_ref()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
}

fn build_session_metadata(
    normalized_channel: &Option<String>,
    normalized_to: &Option<String>,
    thinking: &Option<String>,
    model: &Option<String>,
) -> crate::sessions::SessionMetadata {
    crate::sessions::SessionMetadata {
        channel: normalized_channel.clone(),
        chat_id: normalized_to.clone(),
        thinking_level: thinking.clone(),
        model: model.clone(),
        ..Default::default()
    }
}

fn has_metadata_updates(
    normalized_channel: &Option<String>,
    normalized_to: &Option<String>,
    thinking: &Option<String>,
    model: &Option<String>,
) -> bool {
    normalized_channel.is_some() || normalized_to.is_some() || thinking.is_some() || model.is_some()
}

fn load_or_create_cron_session(
    state: &Arc<WsServerState>,
    session_key: &str,
    metadata: crate::sessions::SessionMetadata,
    has_metadata_updates: bool,
) -> Result<crate::sessions::Session, String> {
    match state.session_store().get_session_by_key(session_key) {
        Ok(existing) => {
            if has_metadata_updates {
                state
                    .session_store()
                    .patch_session(&existing.id, metadata)
                    .map_err(|e| format!("failed to update session: {}", e))
            } else {
                Ok(existing)
            }
        }
        Err(crate::sessions::SessionStoreError::NotFound(_)) => state
            .session_store()
            .get_or_create_session(session_key, metadata)
            .map_err(|e| format!("failed to create session: {}", e)),
        Err(err) => Err(format!("failed to load session: {}", err)),
    }
}

fn append_user_message(
    state: &Arc<WsServerState>,
    session_id: &str,
    message: &str,
) -> Result<(), String> {
    let msg = crate::sessions::ChatMessage::user(session_id, message);
    state
        .session_store()
        .append_message(msg)
        .map_err(|e| format!("failed to append message: {}", e))
}

fn build_agent_config(
    model: &Option<String>,
    allow_unsafe_external_content: Option<bool>,
    deliver: Option<bool>,
) -> crate::agent::AgentConfig {
    let cfg = crate::config::load_config().unwrap_or(Value::Object(serde_json::Map::new()));
    let mut config = crate::agent::AgentConfig::default();
    crate::agent::apply_agent_config_from_settings(&mut config, &cfg, None);
    config.model = model
        .clone()
        .unwrap_or_else(|| crate::agent::DEFAULT_MODEL.to_string());
    if let Some(allow) = allow_unsafe_external_content {
        config.exfiltration_guard = !allow;
    }
    if let Some(deliver) = deliver {
        // Delivery for cron runs is handled via a completion waiter below.
        config.deliver = deliver;
    }
    config
}

fn register_agent_run(
    state: &Arc<WsServerState>,
    run_id: &str,
    session_key: &str,
    message: &str,
    cancel_token: &CancellationToken,
) {
    use crate::server::ws::AgentRunStatus;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let mut registry = state.agent_run_registry.lock();
    registry.register(crate::server::ws::AgentRun {
        run_id: run_id.to_string(),
        session_key: session_key.to_string(),
        status: AgentRunStatus::Queued,
        message: message.to_string(),
        response: String::new(),
        error: None,
        created_at: now,
        started_at: None,
        completed_at: None,
        cancel_token: cancel_token.clone(),
        waiters: Vec::new(),
    });
}

fn spawn_timeout_cancellation(
    state: &Arc<WsServerState>,
    run_id: &str,
    timeout_seconds: Option<u32>,
    cancel_token: CancellationToken,
) {
    let Some(timeout) = timeout_seconds.filter(|timeout| *timeout > 0) else {
        return;
    };
    let run_id = run_id.to_string();
    let waiter = {
        let mut registry = state.agent_run_registry.lock();
        registry.add_waiter(&run_id)
    };
    if let Some(waiter) = waiter {
        tokio::spawn(async move {
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(timeout as u64)) => {
                    tracing::warn!(
                        run_id = %run_id,
                        timeout_seconds = timeout,
                        "cron agent run exceeded timeout; cancelling"
                    );
                    cancel_token.cancel();
                }
                _ = waiter => {}
            }
        });
    }
}

fn spawn_delivery_waiter_if_enabled(
    state: &Arc<WsServerState>,
    run_id: &str,
    job_id: &str,
    deliver: bool,
    retry_enabled: bool,
    normalized_channel: Option<String>,
    normalized_to: Option<String>,
) {
    if !deliver {
        return;
    }

    match (normalized_channel, normalized_to) {
        (Some(channel_id), Some(recipient_id)) => {
            let delivery_pipeline = Arc::clone(state.message_pipeline());
            let delivery_run_id = run_id.to_string();
            let delivery_message_id = format!("cron-deliver:{delivery_run_id}");
            let waiter = {
                let mut registry = state.agent_run_registry.lock();
                registry.add_waiter(run_id)
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
                    let outbound = OutboundMessage::new(channel_id, MessageContent::text(content))
                        .with_metadata(metadata);
                    let mut ctx = OutboundContext::new().with_trace_id(&delivery_message_id);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cron::CronPayload;
    use crate::server::ws::{WsServerConfig, WsServerState};
    use crate::sessions;
    use std::sync::Arc;

    /// Create a WsServerState backed by a temp directory so tests work on all
    /// platforms (including Windows CI where writing to ~/.config/carapace may fail).
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

    #[tokio::test]
    async fn test_agent_turn_updates_existing_metadata() {
        let (state, _tmp) = make_test_state();

        let initial = sessions::SessionMetadata {
            channel: Some("signal".to_string()),
            chat_id: Some("111".to_string()),
            thinking_level: Some("shallow".to_string()),
            model: Some("old-model".to_string()),
            ..Default::default()
        };
        state
            .session_store()
            .get_or_create_session("cron:job-update", initial)
            .unwrap();

        let payload = CronPayload::AgentTurn {
            message: "hello".to_string(),
            model: Some("new-model".to_string()),
            thinking: Some("deep".to_string()),
            timeout_seconds: Some(10),
            allow_unsafe_external_content: Some(false),
            deliver: Some(true),
            channel: Some("Discord".to_string()),
            to: Some("999".to_string()),
            best_effort_deliver: Some(true),
        };

        let result = execute_payload("job-update", &payload, &state).await;
        assert!(result.is_err());

        let session = state
            .session_store()
            .get_session_by_key("cron:job-update")
            .unwrap();
        assert_eq!(session.metadata.channel, Some("discord".to_string()));
        assert_eq!(session.metadata.chat_id, Some("999".to_string()));
        assert_eq!(session.metadata.thinking_level, Some("deep".to_string()));
        assert_eq!(session.metadata.model, Some("new-model".to_string()));
    }
}
