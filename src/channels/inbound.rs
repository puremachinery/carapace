//! Shared inbound channel dispatch helpers.
//!
//! Routes inbound text messages into the session + agent pipeline.

use std::sync::Arc;

use serde_json::Value;
use tracing::debug;

use crate::server::ws::{AgentRun, AgentRunStatus, WsServerState};
use crate::sessions::{get_or_create_scoped_session, ChatMessage, SessionMetadata};

/// Dispatch an inbound text message into the agent pipeline.
///
/// Returns the run ID if queued successfully.
pub fn dispatch_inbound_text(
    state: &Arc<WsServerState>,
    channel: &str,
    sender_id: &str,
    peer_id: &str,
    text: &str,
    chat_id: Option<String>,
) -> Result<String, String> {
    let cfg = crate::config::load_config_shared()
        .unwrap_or_else(|_| Arc::new(Value::Object(serde_json::Map::new())));
    let effective_peer_id = if peer_id.is_empty() {
        sender_id
    } else {
        peer_id
    };

    let metadata = SessionMetadata {
        channel: Some(channel.to_string()),
        user_id: Some(sender_id.to_string()),
        chat_id,
        ..Default::default()
    };

    let session_store = state.session_store();
    let session = get_or_create_scoped_session(
        session_store,
        cfg.as_ref(),
        channel,
        sender_id,
        effective_peer_id,
        None,
        metadata,
    )
    .map_err(|e| format!("failed to get/create session: {}", e))?;

    if let Err(e) = state
        .session_store()
        .append_message(ChatMessage::user(session.id.clone(), text))
    {
        return Err(format!("failed to append message: {}", e));
    }

    let run_id = uuid::Uuid::new_v4().to_string();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    let cancel_token = tokio_util::sync::CancellationToken::new();
    let run = AgentRun {
        run_id: run_id.clone(),
        session_key: session.session_key.clone(),
        status: AgentRunStatus::Queued,
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
        crate::agent::apply_agent_config_from_settings(&mut config, cfg.as_ref(), None);
        config.deliver = true;
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
            channel = %channel,
            sender = %sender_id,
            "Inbound agent run dispatched"
        );
    } else {
        debug!(
            run_id = %run_id,
            channel = %channel,
            "Inbound message queued (no LLM provider)"
        );
    }

    Ok(run_id)
}
