//! Agent executor: core run loop.
//!
//! Loads session history, calls the LLM, streams results, handles tool calls,
//! appends messages to history, and marks the run complete.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};

use crate::agent::context::build_context;
use crate::agent::provider::*;
use crate::agent::tools::{self, ToolCallResult};
use crate::agent::{AgentConfig, AgentError};
use crate::server::ws::{broadcast_agent_event, broadcast_chat_event, WsServerState};

/// Maximum wall-clock time for a single LLM turn (call + stream processing).
/// This is a safety net above the reqwest-level timeout (300s) to catch hangs
/// in stream processing or channel backpressure.
const TURN_TIMEOUT: Duration = Duration::from_secs(600);
use crate::sessions::{ChatMessage, MessageRole};
use tokio_util::sync::CancellationToken;

/// Execute an agent run to completion.
///
/// This is the core loop: load history → call LLM → stream results →
/// handle tool calls → append to history → mark complete.
pub async fn execute_run(
    run_id: String,
    session_key: String,
    config: AgentConfig,
    state: Arc<WsServerState>,
    provider: Arc<dyn LlmProvider>,
    cancel_token: CancellationToken,
) -> Result<(), AgentError> {
    // Sequence counter for broadcast events
    let seq = AtomicU64::new(0);
    let next_seq = || seq.fetch_add(1, Ordering::Relaxed);

    // 1. Mark run as Running (returns false if already cancelled)
    {
        let mut registry = state.agent_run_registry.lock();
        if !registry.mark_started(&run_id) {
            return Err(AgentError::Cancelled);
        }
    }

    // Broadcast started event
    broadcast_agent_event(
        &state,
        &run_id,
        next_seq(),
        "started",
        json!({ "sessionKey": &session_key, "model": &config.model }),
    );

    // 2. Load or create session
    let session = state
        .session_store()
        .get_session_by_key(&session_key)
        .map_err(|e| AgentError::SessionNotFound(format!("{session_key}: {e}")))?;

    // 3. Main agentic loop
    let mut accumulated_text = String::new();
    let mut total_input_tokens: u64 = 0;
    let mut total_output_tokens: u64 = 0;
    let mut final_stop_reason = StopReason::EndTurn;

    // Load history once before the loop to avoid O(turns × history_size) disk I/O
    let mut history = state
        .session_store()
        .get_history(&session.id, None, None)
        .map_err(|e| AgentError::SessionStore(e.to_string()))?;

    for _turn in 0..config.max_turns {
        // Check cancellation
        if cancel_token.is_cancelled() {
            broadcast_agent_event(&state, &run_id, next_seq(), "cancelled", json!({}));
            return Err(AgentError::Cancelled);
        }

        // Build LLM context from in-memory history
        let (system, messages) = build_context(&history, config.system.as_deref());

        // Get available tools
        let tools = if let Some(tools_registry) = state.tools_registry() {
            tools::list_provider_tools(tools_registry)
        } else {
            vec![]
        };

        // Build completion request
        let request = CompletionRequest {
            model: config.model.clone(),
            messages,
            system,
            tools,
            max_tokens: config.max_tokens,
            temperature: config.temperature,
        };

        // Call LLM (with per-turn timeout)
        let mut rx = match tokio::time::timeout(TURN_TIMEOUT, provider.complete(request)).await {
            Ok(result) => result.map_err(|e| AgentError::Provider(e.to_string()))?,
            Err(_) => {
                return Err(AgentError::Provider(format!(
                    "LLM turn timed out after {}s",
                    TURN_TIMEOUT.as_secs()
                )));
            }
        };

        // Process the stream
        let mut turn_text = String::new();
        let mut pending_tool_calls: Vec<(String, String, Value)> = Vec::new(); // (id, name, input)
        let mut stop_reason = StopReason::EndTurn;
        let mut turn_usage = TokenUsage::default();
        let mut got_stop = false;

        loop {
            let event = tokio::select! {
                _ = cancel_token.cancelled() => {
                    broadcast_agent_event(&state, &run_id, next_seq(), "cancelled", json!({}));
                    return Err(AgentError::Cancelled);
                }
                event = rx.recv() => {
                    match event {
                        Some(e) => e,
                        None => break,
                    }
                }
            };

            match event {
                StreamEvent::TextDelta { text } => {
                    turn_text.push_str(&text);

                    // Broadcast text delta
                    broadcast_agent_event(
                        &state,
                        &run_id,
                        next_seq(),
                        "text",
                        json!({ "delta": &text }),
                    );

                    // Also broadcast chat event for webchat-ui
                    broadcast_chat_event(
                        &state,
                        &run_id,
                        &session_key,
                        next_seq(),
                        "delta",
                        Some(json!({ "content": &text })),
                        None,
                        None,
                        None,
                    );
                }

                StreamEvent::ToolUse { id, name, input } => {
                    // Broadcast tool_use event
                    broadcast_agent_event(
                        &state,
                        &run_id,
                        next_seq(),
                        "tool_use",
                        json!({
                            "toolUseId": &id,
                            "name": &name,
                            "input": &input,
                        }),
                    );
                    pending_tool_calls.push((id, name, input));
                }

                StreamEvent::Stop { reason, usage } => {
                    stop_reason = reason;
                    turn_usage = usage;
                    got_stop = true;
                    break;
                }

                StreamEvent::Error { message } => {
                    // Sanitize error before broadcasting — strip potential secrets
                    let safe_message = sanitize_provider_error(&message);
                    broadcast_agent_event(
                        &state,
                        &run_id,
                        next_seq(),
                        "error",
                        json!({ "message": &safe_message }),
                    );
                    broadcast_chat_event(
                        &state,
                        &run_id,
                        &session_key,
                        next_seq(),
                        "error",
                        None,
                        Some(&safe_message),
                        None,
                        None,
                    );
                    // Log the full unsanitized error server-side
                    tracing::error!(run_id = %run_id, error = %message, "LLM provider error");
                    return Err(AgentError::Provider(safe_message));
                }
            }
        }

        // Detect premature stream end (network interruption, upstream error)
        if !got_stop {
            return Err(AgentError::Stream(
                "stream ended without stop event".to_string(),
            ));
        }

        // Track usage
        total_input_tokens += turn_usage.input_tokens;
        total_output_tokens += turn_usage.output_tokens;

        // Record usage via the usage tracker
        crate::server::ws::record_usage(
            &session_key,
            "anthropic",
            turn_usage.input_tokens,
            turn_usage.output_tokens,
            estimate_cost(
                &config.model,
                turn_usage.input_tokens,
                turn_usage.output_tokens,
            ),
        );

        // Append assistant message to history
        if !turn_text.is_empty() || !pending_tool_calls.is_empty() {
            let content = if pending_tool_calls.is_empty() {
                turn_text.clone()
            } else {
                // Store tool_use blocks as JSON for context reconstruction
                let mut blocks: Vec<Value> = Vec::new();
                if !turn_text.is_empty() {
                    blocks.push(json!({"type": "text", "text": &turn_text}));
                }
                for (id, name, input) in &pending_tool_calls {
                    blocks.push(json!({
                        "type": "tool_use",
                        "id": id,
                        "name": name,
                        "input": input,
                    }));
                }
                serde_json::to_string(&blocks).unwrap_or_else(|_| turn_text.clone())
            };

            let msg =
                ChatMessage::assistant(&session.id, &content).with_tokens(turn_usage.output_tokens);
            state
                .session_store()
                .append_message(msg.clone())
                .map_err(|e| AgentError::SessionStore(e.to_string()))?;
            history.push(msg);
        }

        accumulated_text.push_str(&turn_text);
        final_stop_reason = stop_reason;

        // If there are tool calls, execute them and continue the loop
        if !pending_tool_calls.is_empty() && stop_reason == StopReason::ToolUse {
            let mut tool_msgs = Vec::with_capacity(pending_tool_calls.len());

            for (tool_id, tool_name, tool_input) in &pending_tool_calls {
                // Execute the tool
                let tool_result = if let Some(tools_registry) = state.tools_registry() {
                    tools::execute_tool_call(
                        tool_name,
                        tool_input.clone(),
                        tools_registry,
                        &session_key,
                        None,
                    )
                } else {
                    ToolCallResult::Error {
                        message: "no tools registry available".to_string(),
                    }
                };

                let (result_content, is_error) = match &tool_result {
                    ToolCallResult::Ok { output } => (output.clone(), false),
                    ToolCallResult::Error { message } => (message.clone(), true),
                };

                // Broadcast tool_result event
                broadcast_agent_event(
                    &state,
                    &run_id,
                    next_seq(),
                    "tool_result",
                    json!({
                        "toolUseId": tool_id,
                        "name": tool_name,
                        "result": &result_content,
                        "isError": is_error,
                    }),
                );

                let mut tool_msg =
                    ChatMessage::tool(&session.id, tool_name, tool_id, &result_content);
                if is_error {
                    tool_msg.metadata = Some(json!({"is_error": true}));
                }
                tool_msgs.push(tool_msg);
            }

            // Batch-append all tool results in a single file write
            state
                .session_store()
                .append_messages(&tool_msgs)
                .map_err(|e| AgentError::SessionStore(e.to_string()))?;
            history.extend(tool_msgs);

            // Continue loop — tool results will be sent back to LLM on next turn
            continue;
        }

        // No tool calls or EndTurn/MaxTokens → done
        break;
    }

    // 6. Broadcast completion
    let stop_reason_str = match final_stop_reason {
        StopReason::EndTurn => "end_turn",
        StopReason::MaxTokens => "max_tokens",
        StopReason::ToolUse => "tool_use",
    };

    broadcast_agent_event(
        &state,
        &run_id,
        next_seq(),
        "complete",
        json!({
            "stopReason": stop_reason_str,
            "usage": {
                "inputTokens": total_input_tokens,
                "outputTokens": total_output_tokens,
            }
        }),
    );

    broadcast_chat_event(
        &state,
        &run_id,
        &session_key,
        next_seq(),
        "final",
        Some(json!({ "content": &accumulated_text })),
        None,
        Some(json!({
            "inputTokens": total_input_tokens,
            "outputTokens": total_output_tokens,
        })),
        Some(stop_reason_str),
    );

    // 7. Mark run as completed
    {
        let mut registry = state.agent_run_registry.lock();
        registry.mark_completed(&run_id, accumulated_text);
    }

    Ok(())
}

/// Sanitize a provider error message before sending to clients.
///
/// Strips potential secrets (API keys, internal URLs with auth) from error
/// messages while preserving the error type and human-readable portion.
fn sanitize_provider_error(message: &str) -> String {
    // Strip anything that looks like an API key (sk-ant-..., sk-..., key-...)
    let sanitized = regex::Regex::new(r"(sk-ant-|sk-|key-)[A-Za-z0-9_-]{10,}")
        .map(|re| re.replace_all(message, "[REDACTED]").to_string())
        .unwrap_or_else(|_| message.to_string());

    // Strip Authorization header values
    let sanitized = regex::Regex::new(r"(?i)(authorization:\s*)(bearer\s+)?\S+")
        .map(|re| re.replace_all(&sanitized, "$1[REDACTED]").to_string())
        .unwrap_or(sanitized);

    // Cap length to prevent huge error payloads
    if sanitized.len() > 500 {
        format!("{}... (truncated)", &sanitized[..500])
    } else {
        sanitized
    }
}

/// Cost estimate per model using the shared pricing table. Returns USD.
fn estimate_cost(model: &str, input_tokens: u64, output_tokens: u64) -> f64 {
    use crate::usage::{get_model_pricing, ModelPricing};

    let pricing = get_model_pricing(model).unwrap_or(ModelPricing {
        // Default to sonnet pricing for unknown models
        input_cost_per_mtok: 3.0,
        output_cost_per_mtok: 15.0,
    });
    pricing.calculate_cost(input_tokens, output_tokens)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::provider::{LlmProvider, StopReason, StreamEvent, TokenUsage};
    use crate::agent::AgentConfig;
    use crate::server::ws::{WsServerConfig, WsServerState};
    use crate::sessions;
    use async_trait::async_trait;
    use std::sync::Arc;
    use tokio::sync::mpsc;
    use tokio_util::sync::CancellationToken;

    /// Mock LLM provider that returns canned responses.
    struct MockProvider {
        /// Each call to `complete` pops the next response sequence.
        responses: parking_lot::Mutex<Vec<Vec<StreamEvent>>>,
    }

    impl MockProvider {
        /// Create a provider that returns the given sequences in order.
        fn new(responses: Vec<Vec<StreamEvent>>) -> Self {
            // Reverse so we can pop from the back (FIFO via pop from reversed vec)
            let mut reversed = responses;
            reversed.reverse();
            Self {
                responses: parking_lot::Mutex::new(reversed),
            }
        }

        /// Convenience: single-turn text response.
        fn text(text: &str) -> Self {
            Self::new(vec![vec![
                StreamEvent::TextDelta {
                    text: text.to_string(),
                },
                StreamEvent::Stop {
                    reason: StopReason::EndTurn,
                    usage: TokenUsage {
                        input_tokens: 10,
                        output_tokens: 5,
                    },
                },
            ]])
        }

        /// Always returns a tool_use, useful for testing max_turns.
        fn always_tool_use(turns: usize) -> Self {
            let mut responses = Vec::new();
            for _ in 0..turns {
                responses.push(vec![
                    StreamEvent::ToolUse {
                        id: "tool_1".to_string(),
                        name: "time".to_string(),
                        input: serde_json::json!({}),
                    },
                    StreamEvent::Stop {
                        reason: StopReason::ToolUse,
                        usage: TokenUsage {
                            input_tokens: 10,
                            output_tokens: 5,
                        },
                    },
                ]);
            }
            Self::new(responses)
        }
    }

    #[async_trait]
    impl LlmProvider for MockProvider {
        async fn complete(
            &self,
            _request: crate::agent::provider::CompletionRequest,
        ) -> Result<mpsc::Receiver<StreamEvent>, crate::agent::AgentError> {
            let events = {
                let mut responses = self.responses.lock();
                responses.pop().unwrap_or_default()
            };
            let (tx, rx) = mpsc::channel(64);
            tokio::spawn(async move {
                for event in events {
                    let _ = tx.send(event).await;
                }
            });
            Ok(rx)
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

    /// Helper to set up test state with a tools registry.
    fn make_test_state_with_tools() -> (Arc<WsServerState>, tempfile::TempDir) {
        let tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(sessions::SessionStore::with_base_path(
            tmp.path().join("sessions"),
        ));
        let tools_registry = Arc::new(crate::plugins::tools::ToolsRegistry::new());
        let state = WsServerState::new(WsServerConfig::default())
            .with_session_store(store)
            .with_tools_registry(tools_registry);
        (Arc::new(state), tmp)
    }

    /// Helper to set up a session and register an agent run.
    fn setup_session_and_run(
        state: &WsServerState,
        session_key: &str,
        run_id: &str,
    ) -> sessions::Session {
        let session = state
            .session_store()
            .get_or_create_session(session_key, sessions::SessionMetadata::default())
            .unwrap();
        // Append a user message so the executor has context
        state
            .session_store()
            .append_message(sessions::ChatMessage::user(&session.id, "Hello"))
            .unwrap();
        // Register the run
        {
            use crate::server::ws::{AgentRun, AgentRunStatus};
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
        session
    }

    #[tokio::test]
    async fn test_single_turn_text_response() {
        let (state, _tmp) = make_test_state();
        let run_id = "run-text-1";
        let session_key = "test-session-1";
        setup_session_and_run(&state, session_key, run_id);

        let provider = Arc::new(MockProvider::text("Hello world!"));
        let config = AgentConfig {
            max_turns: 5,
            ..Default::default()
        };

        let result = execute_run(
            run_id.to_string(),
            session_key.to_string(),
            config,
            state.clone(),
            provider,
            CancellationToken::new(),
        )
        .await;
        assert!(result.is_ok(), "execute_run failed: {:?}", result.err());

        // Verify the run is marked completed
        let registry = state.agent_run_registry.lock();
        let run = registry.get(run_id).unwrap();
        assert_eq!(run.status, crate::server::ws::AgentRunStatus::Completed);
        assert_eq!(run.response, "Hello world!");
    }

    #[tokio::test]
    async fn test_max_turns_reached() {
        let (state, _tmp) = make_test_state_with_tools();
        let run_id = "run-max-turns";
        let session_key = "test-session-max";
        setup_session_and_run(&state, session_key, run_id);

        let max_turns = 3;
        let provider = Arc::new(MockProvider::always_tool_use(max_turns as usize + 1));
        let config = AgentConfig {
            max_turns,
            ..Default::default()
        };

        let result = execute_run(
            run_id.to_string(),
            session_key.to_string(),
            config,
            state.clone(),
            provider,
            CancellationToken::new(),
        )
        .await;
        // Should complete without error — the loop simply exits after max_turns
        assert!(result.is_ok(), "execute_run failed: {:?}", result.err());
    }

    #[tokio::test]
    async fn test_tool_use_loop() {
        let (state, _tmp) = make_test_state_with_tools();
        let run_id = "run-tool-loop";
        let session_key = "test-session-tool";
        setup_session_and_run(&state, session_key, run_id);

        // Turn 1: tool use (time), Turn 2: text response
        let provider = Arc::new(MockProvider::new(vec![
            // Turn 1: tool use
            vec![
                StreamEvent::ToolUse {
                    id: "tool_1".to_string(),
                    name: "time".to_string(),
                    input: serde_json::json!({}),
                },
                StreamEvent::Stop {
                    reason: StopReason::ToolUse,
                    usage: TokenUsage {
                        input_tokens: 10,
                        output_tokens: 5,
                    },
                },
            ],
            // Turn 2: text response
            vec![
                StreamEvent::TextDelta {
                    text: "The time is now.".to_string(),
                },
                StreamEvent::Stop {
                    reason: StopReason::EndTurn,
                    usage: TokenUsage {
                        input_tokens: 20,
                        output_tokens: 10,
                    },
                },
            ],
        ]));
        let config = AgentConfig {
            max_turns: 5,
            ..Default::default()
        };

        let result = execute_run(
            run_id.to_string(),
            session_key.to_string(),
            config,
            state.clone(),
            provider,
            CancellationToken::new(),
        )
        .await;
        assert!(result.is_ok(), "execute_run failed: {:?}", result.err());

        let registry = state.agent_run_registry.lock();
        let run = registry.get(run_id).unwrap();
        assert_eq!(run.status, crate::server::ws::AgentRunStatus::Completed);
        assert_eq!(run.response, "The time is now.");
    }

    #[tokio::test]
    async fn test_empty_response_handling() {
        let (state, _tmp) = make_test_state();
        let run_id = "run-empty";
        let session_key = "test-session-empty";
        setup_session_and_run(&state, session_key, run_id);

        // Provider returns stop immediately with no text
        let provider = Arc::new(MockProvider::new(vec![vec![StreamEvent::Stop {
            reason: StopReason::EndTurn,
            usage: TokenUsage {
                input_tokens: 5,
                output_tokens: 0,
            },
        }]]));
        let config = AgentConfig {
            max_turns: 5,
            ..Default::default()
        };

        let result = execute_run(
            run_id.to_string(),
            session_key.to_string(),
            config,
            state.clone(),
            provider,
            CancellationToken::new(),
        )
        .await;
        assert!(result.is_ok(), "execute_run failed: {:?}", result.err());

        let registry = state.agent_run_registry.lock();
        let run = registry.get(run_id).unwrap();
        assert_eq!(run.status, crate::server::ws::AgentRunStatus::Completed);
        assert!(run.response.is_empty(), "response should be empty");
    }

    /// Helper: register a run with a specific cancel token so tests can control it.
    fn setup_session_and_run_with_token(
        state: &WsServerState,
        session_key: &str,
        run_id: &str,
        cancel_token: CancellationToken,
    ) -> sessions::Session {
        let session = state
            .session_store()
            .get_or_create_session(session_key, sessions::SessionMetadata::default())
            .unwrap();
        state
            .session_store()
            .append_message(sessions::ChatMessage::user(&session.id, "Hello"))
            .unwrap();
        {
            use crate::server::ws::{AgentRun, AgentRunStatus};
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
                cancel_token,
                waiters: Vec::new(),
            });
        }
        session
    }

    /// Mock provider that pauses before sending events, giving time to cancel.
    struct SlowMockProvider {
        delay_ms: u64,
        events: parking_lot::Mutex<Vec<Vec<StreamEvent>>>,
    }

    impl SlowMockProvider {
        fn new(delay_ms: u64, events: Vec<Vec<StreamEvent>>) -> Self {
            let mut reversed = events;
            reversed.reverse();
            Self {
                delay_ms,
                events: parking_lot::Mutex::new(reversed),
            }
        }
    }

    #[async_trait]
    impl LlmProvider for SlowMockProvider {
        async fn complete(
            &self,
            _request: crate::agent::provider::CompletionRequest,
        ) -> Result<mpsc::Receiver<StreamEvent>, crate::agent::AgentError> {
            let events = {
                let mut responses = self.events.lock();
                responses.pop().unwrap_or_default()
            };
            let delay = self.delay_ms;
            let (tx, rx) = mpsc::channel(64);
            tokio::spawn(async move {
                for event in events {
                    tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
                    let _ = tx.send(event).await;
                }
            });
            Ok(rx)
        }
    }

    #[tokio::test]
    async fn test_cancellation_before_start() {
        // Cancel the token before execute_run is called — mark_started should
        // return false, and execute_run should return Cancelled immediately.
        let (state, _tmp) = make_test_state();
        let run_id = "run-cancel-before";
        let session_key = "test-cancel-before";
        let token = CancellationToken::new();
        setup_session_and_run_with_token(&state, session_key, run_id, token.clone());

        // Cancel before running
        token.cancel();

        let provider = Arc::new(MockProvider::text("should not appear"));
        let config = AgentConfig {
            max_turns: 5,
            ..Default::default()
        };

        let result = execute_run(
            run_id.to_string(),
            session_key.to_string(),
            config,
            state.clone(),
            provider,
            token,
        )
        .await;

        assert!(
            matches!(result, Err(crate::agent::AgentError::Cancelled)),
            "expected Cancelled, got: {:?}",
            result
        );
    }

    #[tokio::test]
    async fn test_cancellation_mid_stream() {
        // Cancel the token while the stream is being consumed — the select!
        // branch should fire and return Cancelled.
        let (state, _tmp) = make_test_state();
        let run_id = "run-cancel-stream";
        let session_key = "test-cancel-stream";
        let token = CancellationToken::new();
        setup_session_and_run_with_token(&state, session_key, run_id, token.clone());

        // Slow provider: sends events with 200ms delay each
        let provider = Arc::new(SlowMockProvider::new(
            200,
            vec![vec![
                StreamEvent::TextDelta {
                    text: "chunk1".to_string(),
                },
                StreamEvent::TextDelta {
                    text: "chunk2".to_string(),
                },
                StreamEvent::TextDelta {
                    text: "chunk3".to_string(),
                },
                StreamEvent::Stop {
                    reason: StopReason::EndTurn,
                    usage: TokenUsage {
                        input_tokens: 10,
                        output_tokens: 5,
                    },
                },
            ]],
        ));

        let cancel_token = token.clone();
        // Cancel after 300ms — should interrupt mid-stream
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(300)).await;
            cancel_token.cancel();
        });

        let config = AgentConfig {
            max_turns: 5,
            ..Default::default()
        };

        let result = execute_run(
            run_id.to_string(),
            session_key.to_string(),
            config,
            state.clone(),
            provider,
            token,
        )
        .await;

        assert!(
            matches!(result, Err(crate::agent::AgentError::Cancelled)),
            "expected Cancelled, got: {:?}",
            result
        );
    }

    #[tokio::test]
    async fn test_cancellation_during_second_turn_stream() {
        // Cancel the token during the second turn's streaming.
        // Turn 1 completes fast (tool use), turn 2 streams slowly so the cancel fires mid-stream.
        let (state, _tmp) = make_test_state_with_tools();
        let run_id = "run-cancel-turn2";
        let session_key = "test-cancel-turn2";
        let token = CancellationToken::new();
        setup_session_and_run_with_token(&state, session_key, run_id, token.clone());

        // Turn 1 is fast (tool use), turn 2 is slow (300ms per event).
        // We cancel at 100ms into turn 2, which should catch it in the select! branch.
        let provider = Arc::new(SlowMockProvider::new(
            300,
            vec![
                // Turn 1
                vec![
                    StreamEvent::ToolUse {
                        id: "tool_1".to_string(),
                        name: "time".to_string(),
                        input: serde_json::json!({}),
                    },
                    StreamEvent::Stop {
                        reason: StopReason::ToolUse,
                        usage: TokenUsage {
                            input_tokens: 10,
                            output_tokens: 5,
                        },
                    },
                ],
                // Turn 2 (slow — events arrive at 300ms intervals)
                vec![
                    StreamEvent::TextDelta {
                        text: "unreachable".to_string(),
                    },
                    StreamEvent::Stop {
                        reason: StopReason::EndTurn,
                        usage: TokenUsage {
                            input_tokens: 10,
                            output_tokens: 5,
                        },
                    },
                ],
            ],
        ));

        let cancel_token = token.clone();
        // Cancel at 800ms — after turn 1 completes (~600ms) but before turn 2 finishes (~1200ms)
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(800)).await;
            cancel_token.cancel();
        });

        let config = AgentConfig {
            max_turns: 5,
            ..Default::default()
        };

        let result = execute_run(
            run_id.to_string(),
            session_key.to_string(),
            config,
            state.clone(),
            provider,
            token,
        )
        .await;

        assert!(
            matches!(result, Err(crate::agent::AgentError::Cancelled)),
            "expected Cancelled, got: {:?}",
            result
        );
    }

    #[test]
    fn test_estimate_cost_sonnet() {
        let cost = estimate_cost("claude-sonnet-4-20250514", 1000, 500);
        // 1000 * 3/1M + 500 * 15/1M = 0.003 + 0.0075 = 0.0105
        assert!((cost - 0.0105).abs() < 0.0001);
    }

    #[test]
    fn test_estimate_cost_opus() {
        let cost = estimate_cost("claude-opus-4-20250514", 1000, 500);
        // 1000 * 15/1M + 500 * 75/1M = 0.015 + 0.0375 = 0.0525
        assert!((cost - 0.0525).abs() < 0.0001);
    }

    #[test]
    fn test_estimate_cost_haiku() {
        let cost = estimate_cost("claude-haiku-3-20250514", 1000, 500);
        // 1000 * 0.25/1M + 500 * 1.25/1M = 0.00025 + 0.000625 = 0.000875
        assert!((cost - 0.000875).abs() < 0.00001);
    }
}
