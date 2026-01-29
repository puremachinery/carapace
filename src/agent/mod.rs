//! Agent execution engine.
//!
//! Provides the LLM provider abstraction, context building, tool dispatch,
//! and the core agent run loop that ties everything together.

pub mod anthropic;
pub mod builtin_tools;
pub mod context;
pub mod executor;
pub mod openai;
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

    #[error("invalid base URL: {0}")]
    InvalidBaseUrl(String),

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
///
/// A secondary supervisor task monitors the `JoinHandle` so that even if the
/// inner task panics in a way that `catch_unwind` does not capture (e.g. a
/// double-panic or a panic in the error-handling code itself), the run is
/// still marked as failed instead of staying in `Running` state forever.
pub fn spawn_run(
    run_id: String,
    session_key: String,
    config: AgentConfig,
    state: Arc<WsServerState>,
    provider: Arc<dyn LlmProvider>,
    cancel_token: CancellationToken,
) -> tokio::task::JoinHandle<()> {
    let supervisor_state = Arc::clone(&state);
    let supervisor_run_id = run_id.clone();

    let handle = tokio::spawn(async move {
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
    });

    // Supervisor task: if the inner task panics in a way that bypasses
    // catch_unwind (e.g. the match/error-handling code itself panics),
    // the JoinHandle will return Err(JoinError). We catch that here as
    // a last-resort safety net so the run never stays stuck in Running.
    tokio::spawn(async move {
        if let Err(join_err) = handle.await {
            let msg = if join_err.is_panic() {
                let panic_payload = join_err.into_panic();
                if let Some(s) = panic_payload.downcast_ref::<&str>() {
                    format!("task panic: {s}")
                } else if let Some(s) = panic_payload.downcast_ref::<String>() {
                    format!("task panic: {s}")
                } else {
                    "task panic: unknown payload".to_string()
                }
            } else {
                format!("task failed: {join_err}")
            };

            tracing::error!(
                run_id = %supervisor_run_id,
                error = %msg,
                "agent task terminated unexpectedly — marking run as failed"
            );

            let mut registry = supervisor_state.agent_run_registry.lock();
            // Only mark failed if the run is still in a non-terminal state
            // (the inner handler may have already marked it).
            if registry.get(&supervisor_run_id).is_some_and(|r| {
                r.status == AgentRunStatus::Running || r.status == AgentRunStatus::Queued
            }) {
                registry.mark_failed(&supervisor_run_id, msg);
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::provider::{CompletionRequest, LlmProvider, StreamEvent};
    use crate::server::ws::{AgentRun, AgentRunStatus, WsServerConfig, WsServerState};
    use crate::sessions;
    use async_trait::async_trait;
    use std::sync::Arc;
    use tokio::sync::mpsc;
    use tokio_util::sync::CancellationToken;

    /// Mock provider whose `complete` method panics with a `&str` message.
    struct PanickingProvider {
        message: &'static str,
    }

    #[async_trait]
    impl LlmProvider for PanickingProvider {
        async fn complete(
            &self,
            _request: CompletionRequest,
        ) -> Result<mpsc::Receiver<StreamEvent>, AgentError> {
            panic!("{}", self.message);
        }
    }

    /// Mock provider whose `complete` method panics with a `String` message.
    struct PanickingStringProvider {
        message: String,
    }

    #[async_trait]
    impl LlmProvider for PanickingStringProvider {
        async fn complete(
            &self,
            _request: CompletionRequest,
        ) -> Result<mpsc::Receiver<StreamEvent>, AgentError> {
            panic!("{}", self.message);
        }
    }

    /// Helper to set up test state with a temp session store.
    fn make_test_state() -> (Arc<WsServerState>, tempfile::TempDir) {
        let tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(sessions::SessionStore::with_base_path(
            tmp.path().join("sessions"),
        ));
        let state = WsServerState::new(WsServerConfig::default()).with_session_store(store);
        (Arc::new(state), tmp)
    }

    /// Helper to set up a session and register an agent run.
    fn setup_session_and_run(state: &WsServerState, session_key: &str, run_id: &str) {
        let session = state
            .session_store()
            .get_or_create_session(session_key, sessions::SessionMetadata::default())
            .unwrap();
        state
            .session_store()
            .append_message(sessions::ChatMessage::user(&session.id, "Hello"))
            .unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let mut registry = state.agent_run_registry.lock();
        registry.register(AgentRun {
            run_id: run_id.to_string(),
            session_key: session_key.to_string(),
            status: AgentRunStatus::Queued,
            message: "Hello".to_string(),
            response: String::new(),
            error: None,
            created_at: now,
            started_at: None,
            completed_at: None,
            cancel_token: CancellationToken::new(),
            waiters: Vec::new(),
        });
    }

    #[tokio::test]
    async fn test_spawn_run_panic_marks_run_failed() {
        let (state, _tmp) = make_test_state();
        let run_id = "run-panic-str";
        let session_key = "session-panic-str";
        setup_session_and_run(&state, session_key, run_id);

        let provider: Arc<dyn LlmProvider> = Arc::new(PanickingProvider {
            message: "provider exploded",
        });
        let config = AgentConfig {
            max_turns: 1,
            ..Default::default()
        };

        let supervisor_handle = spawn_run(
            run_id.to_string(),
            session_key.to_string(),
            config,
            state.clone(),
            provider,
            CancellationToken::new(),
        );

        // Wait for the supervisor task to complete
        supervisor_handle.await.unwrap();

        // The run should be marked as failed with a panic message
        let registry = state.agent_run_registry.lock();
        let run = registry.get(run_id).expect("run should exist in registry");
        assert_eq!(
            run.status,
            AgentRunStatus::Failed,
            "run should be Failed, got: {:?}",
            run.status
        );
        let error = run.error.as_deref().expect("run should have an error");
        assert!(
            error.contains("panic"),
            "error should mention panic, got: {error}"
        );
        assert!(
            error.contains("provider exploded"),
            "error should contain panic message, got: {error}"
        );
    }

    #[tokio::test]
    async fn test_spawn_run_panic_string_payload_marks_run_failed() {
        let (state, _tmp) = make_test_state();
        let run_id = "run-panic-string";
        let session_key = "session-panic-string";
        setup_session_and_run(&state, session_key, run_id);

        let provider: Arc<dyn LlmProvider> = Arc::new(PanickingStringProvider {
            message: "string panic payload".to_string(),
        });
        let config = AgentConfig {
            max_turns: 1,
            ..Default::default()
        };

        let supervisor_handle = spawn_run(
            run_id.to_string(),
            session_key.to_string(),
            config,
            state.clone(),
            provider,
            CancellationToken::new(),
        );

        supervisor_handle.await.unwrap();

        let registry = state.agent_run_registry.lock();
        let run = registry.get(run_id).expect("run should exist in registry");
        assert_eq!(run.status, AgentRunStatus::Failed);
        let error = run.error.as_deref().expect("run should have an error");
        assert!(
            error.contains("panic"),
            "error should mention panic, got: {error}"
        );
        assert!(
            error.contains("string panic payload"),
            "error should contain panic message, got: {error}"
        );
    }

    #[tokio::test]
    async fn test_spawn_run_panic_does_not_leave_run_in_running_state() {
        let (state, _tmp) = make_test_state();
        let run_id = "run-not-stuck";
        let session_key = "session-not-stuck";
        setup_session_and_run(&state, session_key, run_id);

        let provider: Arc<dyn LlmProvider> = Arc::new(PanickingProvider { message: "boom" });
        let config = AgentConfig::default();

        let supervisor_handle = spawn_run(
            run_id.to_string(),
            session_key.to_string(),
            config,
            state.clone(),
            provider,
            CancellationToken::new(),
        );

        supervisor_handle.await.unwrap();

        let registry = state.agent_run_registry.lock();
        let run = registry.get(run_id).expect("run should exist");
        // The key invariant: the run must NOT be in Running or Queued state
        assert_ne!(
            run.status,
            AgentRunStatus::Running,
            "run must not be stuck in Running after panic"
        );
        assert_ne!(
            run.status,
            AgentRunStatus::Queued,
            "run must not be stuck in Queued after panic"
        );
    }
}
