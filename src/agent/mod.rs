//! Agent execution engine.
//!
//! Provides the LLM provider abstraction, context building, tool dispatch,
//! and the core agent run loop that ties everything together.

pub mod anthropic;
pub mod context;
pub mod executor;
pub mod provider;
pub mod tools;

use std::sync::Arc;

use futures_util::FutureExt;

use crate::server::ws::{AgentRunStatus, WsServerState};
pub use executor::execute_run;
pub use provider::{LlmProvider, StreamEvent};
use tokio_util::sync::CancellationToken;

/// Default LLM model used when none is specified.
pub const DEFAULT_MODEL: &str = "claude-sonnet-4-20250514";

/// Errors that can occur during agent execution.
#[derive(Debug, thiserror::Error)]
pub enum AgentError {
    #[error("LLM provider error: {0}")]
    Provider(String),

    #[error("session not found: {0}")]
    SessionNotFound(String),

    #[error("session store error: {0}")]
    SessionStore(String),

    #[error("tool execution error: {0}")]
    ToolExecution(String),

    #[error("invalid API key: {0}")]
    InvalidApiKey(String),

    #[error("run cancelled")]
    Cancelled,

    #[error("max turns exceeded ({0})")]
    MaxTurns(u32),

    #[error("streaming error: {0}")]
    Stream(String),
}

/// Configuration for an agent run.
#[derive(Debug, Clone)]
pub struct AgentConfig {
    /// LLM model identifier (e.g., "claude-sonnet-4-20250514").
    pub model: String,
    /// Optional system prompt prepended to context.
    pub system: Option<String>,
    /// Maximum agentic turns (LLM round-trips). Default 25.
    pub max_turns: u32,
    /// Maximum output tokens per LLM call. Default 8192.
    pub max_tokens: u32,
    /// Sampling temperature. None means provider default.
    pub temperature: Option<f64>,
    /// Whether to deliver the final message via the channel pipeline.
    pub deliver: bool,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            model: DEFAULT_MODEL.to_string(),
            system: None,
            max_turns: 25,
            max_tokens: 8192,
            temperature: None,
            deliver: false,
        }
    }
}

/// Spawn an agent run as a background tokio task.
///
/// Called from `handle_agent` and `handle_chat_send` after creating the `AgentRun`.
/// The task runs `execute_run()` and handles errors/panics.
pub fn spawn_run(
    run_id: String,
    session_key: String,
    config: AgentConfig,
    state: Arc<WsServerState>,
    provider: Arc<dyn LlmProvider>,
    cancel_token: CancellationToken,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let result: Result<Result<(), AgentError>, _> = std::panic::AssertUnwindSafe(execute_run(
            run_id.clone(),
            session_key,
            config,
            state.clone(),
            provider,
            cancel_token,
        ))
        .catch_unwind()
        .await;

        match result {
            Ok(Ok(())) => { /* marked completed inside execute_run */ }
            Ok(Err(AgentError::Cancelled)) => {
                // Ensure marked as cancelled (may already be set by chat.abort)
                let mut registry = state.agent_run_registry.lock();
                if !registry
                    .get(&run_id)
                    .is_some_and(|r| r.status == AgentRunStatus::Cancelled)
                {
                    registry.mark_cancelled(&run_id);
                }
            }
            Ok(Err(e)) => {
                tracing::error!(run_id = %run_id, error = %e, "agent run failed");
                let mut registry = state.agent_run_registry.lock();
                registry.mark_failed(&run_id, e.to_string());
            }
            Err(panic_payload) => {
                let msg = if let Some(s) = panic_payload.downcast_ref::<&str>() {
                    (*s).to_string()
                } else if let Some(s) = panic_payload.downcast_ref::<String>() {
                    s.clone()
                } else {
                    "unknown panic".to_string()
                };
                tracing::error!(run_id = %run_id, panic = %msg, "agent run panicked");
                let mut registry = state.agent_run_registry.lock();
                registry.mark_failed(&run_id, format!("panic: {msg}"));
            }
        }
    })
}
