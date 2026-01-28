//! Agent executor: core run loop.
//!
//! Loads session history, calls the LLM, streams results, handles tool calls,
//! appends messages to history, and marks the run complete.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use serde_json::{json, Value};

use crate::agent::context::build_context;
use crate::agent::provider::*;
use crate::agent::tools::{self, ToolCallResult};
use crate::agent::{AgentConfig, AgentError};
use crate::server::ws::{broadcast_agent_event, broadcast_chat_event, WsServerState};
use crate::sessions::{ChatMessage, MessageRole};

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
) -> Result<(), AgentError> {
    // Sequence counter for broadcast events
    let seq = AtomicU64::new(0);
    let next_seq = || seq.fetch_add(1, Ordering::Relaxed);

    // 1. Mark run as Running
    {
        let mut registry = state.agent_run_registry.lock();
        registry.mark_started(&run_id);
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

    // Load history once before the loop to avoid O(turns × history_size) disk I/O
    let mut history = state
        .session_store()
        .get_history(&session.id, None, None)
        .map_err(|e| AgentError::SessionStore(e.to_string()))?;

    for _turn in 0..config.max_turns {
        // Check cancellation
        if is_cancelled(&state, &run_id) {
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

        // Call LLM
        let mut rx = provider
            .complete(request)
            .await
            .map_err(|e| AgentError::Provider(e.to_string()))?;

        // Process the stream
        let mut turn_text = String::new();
        let mut pending_tool_calls: Vec<(String, String, Value)> = Vec::new(); // (id, name, input)
        let mut stop_reason = StopReason::EndTurn;
        let mut turn_usage = TokenUsage::default();

        while let Some(event) = rx.recv().await {
            // Check cancellation during streaming
            if is_cancelled(&state, &run_id) {
                broadcast_agent_event(&state, &run_id, next_seq(), "cancelled", json!({}));
                return Err(AgentError::Cancelled);
            }

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
                    break;
                }

                StreamEvent::Error { message } => {
                    // Broadcast error
                    broadcast_agent_event(
                        &state,
                        &run_id,
                        next_seq(),
                        "error",
                        json!({ "message": &message }),
                    );
                    broadcast_chat_event(
                        &state,
                        &run_id,
                        &session_key,
                        next_seq(),
                        "error",
                        None,
                        Some(&message),
                        None,
                        None,
                    );
                    return Err(AgentError::Provider(message));
                }
            }
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

            let msg = ChatMessage::assistant(&session.id, &content)
                .with_tokens(turn_usage.output_tokens as u32);
            state
                .session_store()
                .append_message(msg.clone())
                .map_err(|e| AgentError::SessionStore(e.to_string()))?;
            history.push(msg);
        }

        accumulated_text.push_str(&turn_text);

        // If there are tool calls, execute them and continue the loop
        if !pending_tool_calls.is_empty() && stop_reason == StopReason::ToolUse {
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

                // Append tool result to session history
                let mut tool_msg =
                    ChatMessage::tool(&session.id, tool_name, tool_id, &result_content);
                if is_error {
                    tool_msg.metadata = Some(json!({"is_error": true}));
                }
                state
                    .session_store()
                    .append_message(tool_msg.clone())
                    .map_err(|e| AgentError::SessionStore(e.to_string()))?;
                history.push(tool_msg);
            }

            // Continue loop — tool results will be sent back to LLM on next turn
            continue;
        }

        // No tool calls or EndTurn/MaxTokens → done
        break;
    }

    // 6. Broadcast completion
    let stop_reason_str = if accumulated_text.is_empty() {
        "max_tokens"
    } else {
        "end_turn"
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

/// Check if a run has been cancelled.
fn is_cancelled(state: &WsServerState, run_id: &str) -> bool {
    let registry = state.agent_run_registry.lock();
    registry
        .get(run_id)
        .map(|run| run.status == crate::server::ws::AgentRunStatus::Cancelled)
        .unwrap_or(false)
}

/// Rough cost estimate per model. Returns USD.
fn estimate_cost(model: &str, input_tokens: u64, output_tokens: u64) -> f64 {
    let (input_rate, output_rate) = if model.contains("opus") {
        (15.0 / 1_000_000.0, 75.0 / 1_000_000.0)
    } else if model.contains("sonnet") {
        (3.0 / 1_000_000.0, 15.0 / 1_000_000.0)
    } else if model.contains("haiku") {
        (0.25 / 1_000_000.0, 1.25 / 1_000_000.0)
    } else {
        // Default to sonnet pricing
        (3.0 / 1_000_000.0, 15.0 / 1_000_000.0)
    };
    input_tokens as f64 * input_rate + output_tokens as f64 * output_rate
}

#[cfg(test)]
mod tests {
    use super::*;

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
