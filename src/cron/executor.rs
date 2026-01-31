//! Cron payload executor.
//!
//! Executes the payload of a cron job after `run()` marks it as started.
//! Supports `SystemEvent` (broadcast) and `AgentTurn` (spawn agent run).

use std::sync::Arc;

use crate::cron::CronPayload;
use crate::server::ws::{SystemEvent, WsServerState};
use serde_json::Value;
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
            if thinking.is_some() {
                tracing::warn!(job_id = %job_id, "AgentTurn 'thinking' field is accepted but not yet acted on");
            }
            if timeout_seconds.is_some() {
                tracing::warn!(job_id = %job_id, "AgentTurn 'timeout_seconds' field is accepted but not yet acted on");
            }
            if allow_unsafe_external_content.is_some() {
                tracing::warn!(job_id = %job_id, "AgentTurn 'allow_unsafe_external_content' field is accepted but not yet acted on");
            }
            if deliver.is_some() {
                tracing::warn!(job_id = %job_id, "AgentTurn 'deliver' field is accepted but not yet acted on");
            }
            if channel.is_some() {
                tracing::warn!(job_id = %job_id, "AgentTurn 'channel' field is accepted but not yet acted on");
            }
            if to.is_some() {
                tracing::warn!(job_id = %job_id, "AgentTurn 'to' field is accepted but not yet acted on");
            }
            if best_effort_deliver.is_some() {
                tracing::warn!(job_id = %job_id, "AgentTurn 'best_effort_deliver' field is accepted but not yet acted on");
            }
            let session_key = format!("cron:{}", job_id);
            let run_id = uuid::Uuid::new_v4().to_string();

            // Ensure session exists
            let session = state
                .session_store()
                .get_or_create_session(&session_key, crate::sessions::SessionMetadata::default())
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

            // Spawn agent execution
            if let Some(provider) = state.llm_provider() {
                crate::agent::spawn_run(
                    run_id.clone(),
                    session_key,
                    config,
                    state.clone(),
                    provider.clone(),
                    cancel_token,
                );
            } else {
                return Err("no LLM provider configured".to_string());
            }

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
}
