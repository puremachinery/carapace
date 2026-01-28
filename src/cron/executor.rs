//! Cron payload executor.
//!
//! Executes the payload of a cron job after `run()` marks it as started.
//! Supports `SystemEvent` (broadcast) and `AgentTurn` (spawn agent run).

use std::sync::Arc;

use crate::cron::CronPayload;
use crate::server::ws::{SystemEvent, WsServerState};

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
            timeout_seconds: _,
            ..
        } => {
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
            let config = crate::agent::AgentConfig {
                model: model
                    .clone()
                    .unwrap_or_else(|| crate::agent::DEFAULT_MODEL.to_string()),
                ..Default::default()
            };

            // Register the agent run
            {
                use crate::server::ws::{AgentRunRegistry, AgentRunStatus};
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
    use std::sync::Arc;

    #[tokio::test]
    async fn test_execute_system_event() {
        let state = Arc::new(WsServerState::new(WsServerConfig::default()));

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
        let state = Arc::new(WsServerState::new(WsServerConfig::default()));

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
