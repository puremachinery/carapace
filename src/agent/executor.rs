//! Agent executor: core run loop.
//!
//! Loads session history, calls the LLM, streams results, handles tool calls,
//! appends messages to history, and marks the run complete.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};

use crate::agent::context::{build_context, build_context_with_tagging};
use crate::agent::prompt_guard::{postflight, preflight};
use crate::agent::provider::*;
use crate::agent::tools::{self, ToolCallResult};
use crate::agent::{AgentConfig, AgentError};
use crate::plugins::hook_utils;
use crate::plugins::HookDispatchResult;
use crate::server::ws::{broadcast_agent_event, broadcast_chat_event, WsServerState};

/// Maximum wall-clock time for a single LLM turn (call + stream processing).
/// This is a safety net above the reqwest-level timeout (300s) to catch hangs
/// in stream processing or channel backpressure.
const TURN_TIMEOUT: Duration = Duration::from_secs(600);

/// Maximum time to wait for the next chunk in the SSE stream.
/// If the provider stalls without sending any data for this long,
/// we treat it as a timeout and abort the turn.
const STREAM_CHUNK_TIMEOUT: Duration = Duration::from_secs(90);
use crate::sessions::{ChatMessage, MessageRole};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

/// Result of processing an LLM stream for a single turn.
struct StreamResult {
    turn_text: String,
    pending_tool_calls: Vec<(String, String, Value)>,
    stop_reason: StopReason,
    turn_usage: TokenUsage,
}

fn dispatch_plugin_hook(
    state: &Arc<WsServerState>,
    hook_name: &str,
    payload: &Value,
) -> Option<HookDispatchResult> {
    let plugin_registry = state.plugin_registry()?.clone();
    hook_utils::dispatch_hook(plugin_registry, hook_name, payload)
}

fn parse_hook_payload(result: &HookDispatchResult, hook_name: &str) -> Option<Value> {
    hook_utils::parse_hook_payload(result, hook_name)
}

fn apply_agent_hook_overrides(config: &mut AgentConfig, payload: &Value) {
    let Some(obj) = payload.as_object() else {
        return;
    };

    if let Some(system) = obj.get("system") {
        match system {
            Value::String(value) => config.system = Some(value.clone()),
            Value::Null => config.system = None,
            _ => {}
        }
    }

    if let Some(model) = obj.get("model").and_then(|value| value.as_str()) {
        config.model = model.to_string();
    }

    if let Some(max_tokens) = obj.get("maxTokens").and_then(|value| value.as_u64()) {
        config.max_tokens = max_tokens.min(u32::MAX as u64) as u32;
    }

    if let Some(temperature) = obj.get("temperature").and_then(|value| value.as_f64()) {
        config.temperature = Some(temperature);
    }

    if let Some(extra) = obj.get("extra") {
        if extra.is_null() {
            config.extra = None;
        } else {
            config.extra = Some(extra.clone());
        }
    }
}

fn apply_tool_input_override(tool_input: &mut Value, payload: &Value) {
    let Some(obj) = payload.as_object() else {
        return;
    };
    if let Some(input) = obj.get("input") {
        *tool_input = input.clone();
    }
}

fn apply_tool_result_override(result_content: &mut String, is_error: &mut bool, payload: &Value) {
    let Some(obj) = payload.as_object() else {
        return;
    };

    if let Some(result) = obj.get("result") {
        match result {
            Value::String(value) => *result_content = value.clone(),
            Value::Null => {}
            _ => {
                if let Ok(serialized) = serde_json::to_string(result) {
                    *result_content = serialized;
                }
            }
        }
    }

    if let Some(flag) = obj.get("isError").and_then(|value| value.as_bool()) {
        *is_error = flag;
    }
}

/// Dispatch a single stream event, updating turn accumulators.
///
/// Returns `Ok(true)` if the event was a `Stop` (caller should break),
/// `Ok(false)` to continue reading, or `Err` on a provider error event.
fn handle_stream_event(
    event: StreamEvent,
    result: &mut StreamResult,
    state: &Arc<WsServerState>,
    run_id: &str,
    session_key: &str,
    seq: &AtomicU64,
) -> Result<bool, AgentError> {
    match event {
        StreamEvent::TextDelta { text } => {
            result.turn_text.push_str(&text);

            broadcast_agent_event(
                state,
                run_id,
                seq.fetch_add(1, Ordering::Relaxed),
                "text",
                json!({ "delta": &text }),
            );

            broadcast_chat_event(
                state,
                run_id,
                session_key,
                seq.fetch_add(1, Ordering::Relaxed),
                "delta",
                Some(json!({ "content": &text })),
                None,
                None,
                None,
            );
            Ok(false)
        }

        StreamEvent::ToolUse { id, name, input } => {
            broadcast_agent_event(
                state,
                run_id,
                seq.fetch_add(1, Ordering::Relaxed),
                "tool_use",
                json!({
                    "toolUseId": &id,
                    "name": &name,
                    "input": &input,
                }),
            );
            result.pending_tool_calls.push((id, name, input));
            Ok(false)
        }

        StreamEvent::Stop { reason, usage } => {
            result.stop_reason = reason;
            result.turn_usage = usage;
            Ok(true)
        }

        StreamEvent::Error { message } => {
            let safe_message = sanitize_provider_error(&message);
            broadcast_agent_event(
                state,
                run_id,
                seq.fetch_add(1, Ordering::Relaxed),
                "error",
                json!({ "message": &safe_message }),
            );
            broadcast_chat_event(
                state,
                run_id,
                session_key,
                seq.fetch_add(1, Ordering::Relaxed),
                "error",
                None,
                Some(&safe_message),
                None,
                None,
            );
            tracing::error!(run_id = %run_id, error = %safe_message, "LLM provider error");
            Err(AgentError::Provider(safe_message))
        }
    }
}

/// Process the LLM event stream for a single turn.
///
/// Reads events from `rx`, accumulates text deltas and tool-use blocks,
/// broadcasts events to clients, and checks for cancellation. Returns the
/// accumulated turn data or an error on cancellation / stream failure.
async fn process_llm_stream(
    rx: &mut mpsc::Receiver<StreamEvent>,
    state: &Arc<WsServerState>,
    run_id: &str,
    session_key: &str,
    seq: &AtomicU64,
    cancel_token: &CancellationToken,
) -> Result<StreamResult, AgentError> {
    let mut result = StreamResult {
        turn_text: String::new(),
        pending_tool_calls: Vec::new(),
        stop_reason: StopReason::EndTurn,
        turn_usage: TokenUsage::default(),
    };
    let mut got_stop = false;

    loop {
        let event = tokio::select! {
            _ = cancel_token.cancelled() => {
                broadcast_agent_event(state, run_id, seq.fetch_add(1, Ordering::Relaxed), "cancelled", json!({}));
                return Err(AgentError::Cancelled);
            }
            result = tokio::time::timeout(STREAM_CHUNK_TIMEOUT, rx.recv()) => {
                match result {
                    Ok(Some(e)) => e,
                    Ok(None) => break, // stream ended
                    Err(_) => {
                        tracing::error!(
                            run_id = %run_id,
                            timeout_secs = STREAM_CHUNK_TIMEOUT.as_secs(),
                            "LLM stream stalled — no data received within chunk timeout"
                        );
                        return Err(AgentError::Provider(format!(
                            "LLM stream stalled — no data received for {}s",
                            STREAM_CHUNK_TIMEOUT.as_secs()
                        )));
                    }
                }
            }
        };

        got_stop = handle_stream_event(event, &mut result, state, run_id, session_key, seq)?;
        if got_stop {
            break;
        }
    }

    // Detect premature stream end (network interruption, upstream error)
    if !got_stop {
        return Err(AgentError::Stream(
            "stream ended without stop event".to_string(),
        ));
    }

    Ok(result)
}

/// Build an assistant history message from accumulated turn text and tool-use blocks.
///
/// Returns the `ChatMessage` ready for persistence, or `None` if there is
/// nothing to record (empty text and no tool calls).
fn build_assistant_message(
    session_id: &str,
    turn_text: &str,
    pending_tool_calls: &[(String, String, Value)],
    output_tokens: u64,
) -> Option<ChatMessage> {
    if turn_text.is_empty() && pending_tool_calls.is_empty() {
        return None;
    }

    let content = if pending_tool_calls.is_empty() {
        turn_text.to_string()
    } else {
        // Store tool_use blocks as JSON for context reconstruction
        let mut blocks: Vec<Value> = Vec::new();
        if !turn_text.is_empty() {
            blocks.push(json!({"type": "text", "text": turn_text}));
        }
        for (id, name, input) in pending_tool_calls {
            blocks.push(json!({
                "type": "tool_use",
                "id": id,
                "name": name,
                "input": input,
            }));
        }
        serde_json::to_string(&blocks).unwrap_or_else(|_| turn_text.to_string())
    };

    Some(ChatMessage::assistant(session_id, &content).with_tokens(output_tokens))
}

/// Execute pending tool calls with exfiltration guard and tool-policy checks,
/// broadcast results, and return the corresponding history messages.
#[allow(clippy::too_many_arguments)]
fn execute_tools_with_guards(
    pending_tool_calls: &[(String, String, Value)],
    config: &AgentConfig,
    state: &Arc<WsServerState>,
    session_id: &str,
    session_key: &str,
    message_channel: Option<&str>,
    run_id: &str,
    seq: &AtomicU64,
) -> Vec<ChatMessage> {
    let mut tool_msgs = Vec::with_capacity(pending_tool_calls.len());

    for (tool_id, tool_name, tool_input) in pending_tool_calls {
        let mut tool_input = tool_input.clone();
        let original_tool_input = tool_input.clone();

        // Check exfiltration guard before tool policy (defence-in-depth)
        let tool_result = if config.exfiltration_guard
            && crate::agent::exfiltration::is_exfiltration_sensitive(tool_name)
        {
            ToolCallResult::Error {
                message: format!(
                    "Tool \"{}\" is blocked by the exfiltration guard. \
                     This tool sends data externally and requires explicit approval. \
                     Set exfiltration_guard: false in agent config to allow.",
                    tool_name
                ),
            }
        } else if !config.tool_policy.is_allowed(tool_name) {
            ToolCallResult::Error {
                message: format!("Tool \"{}\" is not available for this agent", tool_name),
            }
        } else if let Some(result) = dispatch_plugin_hook(
            state,
            "before_tool_call",
            &json!({
                "runId": run_id,
                "sessionKey": session_key,
                "toolUseId": tool_id,
                "name": tool_name,
                "input": &tool_input,
                "messageChannel": message_channel,
            }),
        ) {
            if result.cancelled {
                ToolCallResult::Error {
                    message: format!("Tool \"{}\" cancelled by hook", tool_name),
                }
            } else {
                if let Some(payload) = parse_hook_payload(&result, "before_tool_call") {
                    apply_tool_input_override(&mut tool_input, &payload);
                    if tool_input != original_tool_input {
                        tracing::info!(
                            run_id = %run_id,
                            tool = %tool_name,
                            tool_use_id = %tool_id,
                            "tool input modified by hook"
                        );
                    }
                }

                if let Some(tools_registry) = state.tools_registry() {
                    let sandbox = if config.process_sandbox.enabled {
                        Some(&config.process_sandbox)
                    } else {
                        None
                    };
                    tools::execute_tool_call_with_sandbox(
                        tool_name,
                        tool_input.clone(),
                        tools_registry,
                        session_key,
                        None,
                        message_channel,
                        sandbox,
                    )
                } else {
                    ToolCallResult::Error {
                        message: "no tools registry available".to_string(),
                    }
                }
            }
        } else if let Some(tools_registry) = state.tools_registry() {
            let sandbox = if config.process_sandbox.enabled {
                Some(&config.process_sandbox)
            } else {
                None
            };
            tools::execute_tool_call_with_sandbox(
                tool_name,
                tool_input.clone(),
                tools_registry,
                session_key,
                None,
                message_channel,
                sandbox,
            )
        } else {
            ToolCallResult::Error {
                message: "no tools registry available".to_string(),
            }
        };

        let (mut result_content, mut is_error) = match &tool_result {
            ToolCallResult::Ok { output } => (output.clone(), false),
            ToolCallResult::Error { message } => (message.clone(), true),
        };

        let _ = dispatch_plugin_hook(
            state,
            "after_tool_call",
            &json!({
                "runId": run_id,
                "sessionKey": session_key,
                "toolUseId": tool_id,
                "name": tool_name,
                "originalInput": &original_tool_input,
                "input": &tool_input,
                "result": &result_content,
                "isError": is_error,
                "messageChannel": message_channel,
            }),
        );

        if let Some(result) = dispatch_plugin_hook(
            state,
            "tool_result_persist",
            &json!({
                "runId": run_id,
                "sessionKey": session_key,
                "toolUseId": tool_id,
                "name": tool_name,
                "originalInput": &original_tool_input,
                "input": &tool_input,
                "result": &result_content,
                "isError": is_error,
                "messageChannel": message_channel,
            }),
        ) {
            if result.cancelled {
                result_content = format!("Tool \"{}\" result suppressed by hook", tool_name);
                is_error = true;
            } else if let Some(payload) = parse_hook_payload(&result, "tool_result_persist") {
                apply_tool_result_override(&mut result_content, &mut is_error, &payload);
            }
        }

        // Broadcast tool_result event
        broadcast_agent_event(
            state,
            run_id,
            seq.fetch_add(1, Ordering::Relaxed),
            "tool_result",
            json!({
                "toolUseId": tool_id,
                "name": tool_name,
                "result": &result_content,
                "isError": is_error,
            }),
        );

        let mut tool_msg = ChatMessage::tool(session_id, tool_name, tool_id, &result_content);
        if is_error {
            tool_msg.metadata = Some(json!({"is_error": true}));
        }
        tool_msgs.push(tool_msg);
    }

    tool_msgs
}

/// Record token usage for a single turn via the usage tracker.
fn record_turn_usage(session_key: &str, model: &str, usage: &TokenUsage) {
    let provider_name = if crate::agent::venice::is_venice_model(model) {
        "venice"
    } else if crate::agent::openai::is_openai_model(model) {
        "openai"
    } else {
        "anthropic"
    };
    crate::server::ws::record_usage(
        session_key,
        provider_name,
        model,
        usage.input_tokens,
        usage.output_tokens,
    );
}

/// Build the `CompletionRequest` for a single turn from in-memory history.
fn build_turn_request(
    history: &[ChatMessage],
    config: &AgentConfig,
    state: &Arc<WsServerState>,
    message_channel: Option<&str>,
) -> CompletionRequest {
    let (system, messages) = if config.prompt_guard.enabled && config.prompt_guard.tagging.enabled {
        build_context_with_tagging(
            history,
            config.system.as_deref(),
            &config.prompt_guard.tagging,
        )
    } else {
        build_context(history, config.system.as_deref())
    };

    let tools = if let Some(tools_registry) = state.tools_registry() {
        let all_tools = tools::list_provider_tools(tools_registry, message_channel);
        config
            .tool_policy
            .filter_tools_with_guard(all_tools, config.exfiltration_guard)
    } else {
        vec![]
    };

    CompletionRequest {
        model: config.model.clone(),
        messages,
        system,
        tools,
        max_tokens: config.max_tokens,
        temperature: config.temperature,
        extra: config.extra.clone(),
    }
}

/// Broadcast run-completion events and mark the run as completed in the registry.
#[allow(clippy::too_many_arguments)]
fn finalize_run(
    state: &Arc<WsServerState>,
    run_id: &str,
    session_key: &str,
    seq: &AtomicU64,
    final_stop_reason: StopReason,
    total_input_tokens: u64,
    total_output_tokens: u64,
    accumulated_text: String,
    csp_policy: &str,
) {
    let stop_reason_str = match final_stop_reason {
        StopReason::EndTurn => "end_turn",
        StopReason::MaxTokens => "max_tokens",
        StopReason::ToolUse => "tool_use",
    };

    broadcast_agent_event(
        state,
        run_id,
        seq.fetch_add(1, Ordering::Relaxed),
        "complete",
        json!({
            "stopReason": stop_reason_str,
            "usage": {
                "inputTokens": total_input_tokens,
                "outputTokens": total_output_tokens,
            },
            "contentPolicy": {
                "csp": csp_policy,
            }
        }),
    );

    broadcast_chat_event(
        state,
        run_id,
        session_key,
        seq.fetch_add(1, Ordering::Relaxed),
        "final",
        Some(json!({
            "content": &accumulated_text,
            "contentPolicy": {
                "csp": csp_policy,
            }
        })),
        None,
        Some(json!({
            "inputTokens": total_input_tokens,
            "outputTokens": total_output_tokens,
        })),
        Some(stop_reason_str),
    );

    let mut registry = state.agent_run_registry.lock();
    registry.mark_completed(run_id, accumulated_text);
}

/// Execute a single LLM turn: call the provider, stream the response,
/// record usage, persist the assistant message, and optionally execute tools.
///
/// Returns `Ok(true)` if the loop should continue (tool calls pending),
/// `Ok(false)` if the run is done (end-turn / max-tokens).
#[allow(clippy::too_many_arguments)]
async fn execute_single_turn(
    config: &AgentConfig,
    state: &Arc<WsServerState>,
    provider: &Arc<dyn LlmProvider>,
    cancel_token: &CancellationToken,
    run_id: &str,
    session_key: &str,
    session_id: &str,
    message_channel: Option<&str>,
    seq: &AtomicU64,
    history: &mut Vec<ChatMessage>,
    accumulated_text: &mut String,
    total_input_tokens: &mut u64,
    total_output_tokens: &mut u64,
    final_stop_reason: &mut StopReason,
) -> Result<bool, AgentError> {
    // Check cancellation
    if cancel_token.is_cancelled() {
        broadcast_agent_event(
            state,
            run_id,
            seq.fetch_add(1, Ordering::Relaxed),
            "cancelled",
            json!({}),
        );
        return Err(AgentError::Cancelled);
    }

    let request = build_turn_request(history, config, state, message_channel);

    // Call LLM (with per-turn timeout)
    let mut rx = match tokio::time::timeout(
        TURN_TIMEOUT,
        provider.complete(request, cancel_token.clone()),
    )
    .await
    {
        Ok(Ok(rx)) => rx,
        Ok(Err(AgentError::Cancelled)) => return Err(AgentError::Cancelled),
        Ok(Err(e)) => return Err(AgentError::Provider(e.to_string())),
        Err(_) => {
            return Err(AgentError::Provider(format!(
                "LLM turn timed out after {}s",
                TURN_TIMEOUT.as_secs()
            )));
        }
    };

    let StreamResult {
        turn_text,
        pending_tool_calls,
        stop_reason,
        turn_usage,
    } = process_llm_stream(&mut rx, state, run_id, session_key, seq, cancel_token).await?;

    // Track usage
    *total_input_tokens += turn_usage.input_tokens;
    *total_output_tokens += turn_usage.output_tokens;
    record_turn_usage(session_key, &config.model, &turn_usage);

    // Post-flight filtering — MUST run before persistence to avoid storing
    // unfiltered PII/credentials in session history.
    let turn_text = if config.prompt_guard.enabled && config.prompt_guard.postflight.enabled {
        let postflight_result =
            postflight::filter_output(&turn_text, &config.prompt_guard.postflight);
        if !postflight_result.is_clean() {
            let finding_count = postflight_result.findings.len();
            tracing::warn!(
                run_id = %run_id,
                findings = finding_count,
                blocked = postflight_result.blocked,
                "prompt guard post-flight detected sensitive content in output"
            );
            if postflight_result.blocked {
                crate::logging::audit::audit(
                    crate::logging::audit::AuditEvent::PromptGuardBlocked {
                        layer: "postflight".to_string(),
                        reason: format!("{finding_count} findings (output sanitized)"),
                        run_id: run_id.to_string(),
                    },
                );
            }
        }
        postflight_result.sanitized
    } else {
        turn_text
    };

    // Output sanitization — strip dangerous HTML/Markdown constructs so that
    // agent output is safe for web UI rendering.  Runs after post-flight (PII
    // redaction) and before persistence.
    let turn_text = if config.output_sanitizer.sanitize_html {
        let sanitized =
            crate::agent::output_sanitizer::sanitize_output(&turn_text, &config.output_sanitizer);
        if sanitized.was_modified {
            tracing::info!(
                run_id = %run_id,
                "output sanitizer modified agent response for safe rendering"
            );
        }
        sanitized.content
    } else {
        turn_text
    };

    // Append assistant message to history (after post-flight filtering)
    if let Some(msg) = build_assistant_message(
        session_id,
        &turn_text,
        &pending_tool_calls,
        turn_usage.output_tokens,
    ) {
        state
            .session_store()
            .append_message(msg.clone())
            .map_err(|e| AgentError::SessionStore(e.to_string()))?;
        history.push(msg);
    }

    accumulated_text.push_str(&turn_text);
    *final_stop_reason = stop_reason;

    // If there are tool calls, execute them and signal continuation
    if !pending_tool_calls.is_empty() && stop_reason == StopReason::ToolUse {
        let tool_msgs = execute_tools_with_guards(
            &pending_tool_calls,
            config,
            state,
            session_id,
            session_key,
            message_channel,
            run_id,
            seq,
        );
        state
            .session_store()
            .append_messages(&tool_msgs)
            .map_err(|e| AgentError::SessionStore(e.to_string()))?;
        history.extend(tool_msgs);
        return Ok(true);
    }

    Ok(false)
}

/// Execute an agent run to completion.
///
/// This is the core loop: load history → call LLM → stream results →
/// handle tool calls → append to history → mark complete.
pub async fn execute_run(
    run_id: String,
    session_key: String,
    mut config: AgentConfig,
    state: Arc<WsServerState>,
    provider: Arc<dyn LlmProvider>,
    cancel_token: CancellationToken,
) -> Result<(), AgentError> {
    let seq = AtomicU64::new(0);

    // 1. Mark run as Running (returns false if already cancelled)
    {
        let mut registry = state.agent_run_registry.lock();
        if !registry.mark_started(&run_id) {
            return Err(AgentError::Cancelled);
        }
    }

    broadcast_agent_event(
        &state,
        &run_id,
        seq.fetch_add(1, Ordering::Relaxed),
        "started",
        json!({ "sessionKey": &session_key, "model": &config.model }),
    );

    // 2. Load or create session
    let session = state
        .session_store()
        .get_session_by_key(&session_key)
        .map_err(|e| AgentError::SessionNotFound(format!("{session_key}: {e}")))?;
    let message_channel = session.metadata.channel.clone();

    if let Some(result) = dispatch_plugin_hook(
        &state,
        "before_agent_start",
        &json!({
            "runId": run_id,
            "sessionKey": session_key,
            "model": &config.model,
            "system": &config.system,
            "maxTokens": config.max_tokens,
            "temperature": config.temperature,
            "deliver": config.deliver,
            "messageChannel": &message_channel,
            "extra": &config.extra,
        }),
    ) {
        if result.cancelled {
            return Err(AgentError::Cancelled);
        }
        if let Some(payload) = parse_hook_payload(&result, "before_agent_start") {
            apply_agent_hook_overrides(&mut config, &payload);
        }
    }

    // 2b. Pre-flight system prompt check
    if config.prompt_guard.enabled && config.prompt_guard.preflight.enabled {
        if let Some(ref system) = config.system {
            let preflight_result =
                preflight::analyze_system_prompt(system, &config.prompt_guard.preflight);
            if preflight_result.has_critical() {
                let reasons: Vec<String> = preflight_result
                    .findings
                    .iter()
                    .map(|f| f.description.clone())
                    .collect();
                let reason = reasons.join("; ");
                tracing::warn!(
                    run_id = %run_id,
                    findings = %reason,
                    "prompt guard pre-flight blocked system prompt"
                );
                crate::logging::audit::audit(
                    crate::logging::audit::AuditEvent::PromptGuardBlocked {
                        layer: "preflight".to_string(),
                        reason: reason.clone(),
                        run_id: run_id.clone(),
                    },
                );
                return Err(AgentError::Provider(format!(
                    "Prompt guard pre-flight blocked: {reason}"
                )));
            }
        }
    }

    // 2c. Classifier (optional, fail-open)
    if let Some(ref clf_config) = config.classifier {
        if clf_config.enabled && clf_config.mode != crate::agent::classifier::ClassifierMode::Off {
            // Get the last user message from session history for classification
            let last_user_msg = state
                .session_store()
                .get_history(&session.id, None, None)
                .ok()
                .and_then(|history| {
                    history
                        .iter()
                        .rev()
                        .find(|m| m.role == MessageRole::User)
                        .map(|m| m.content.clone())
                });

            if let Some(user_message) = last_user_msg {
                match crate::agent::classifier::classify_message(
                    &user_message,
                    clf_config,
                    provider.as_ref(),
                )
                .await
                {
                    Ok(verdict) if verdict.should_block(clf_config) => {
                        crate::logging::audit::audit(
                            crate::logging::audit::AuditEvent::ClassifierBlocked {
                                category: verdict.category.to_string(),
                                confidence: verdict.confidence as f64,
                                reasoning: verdict.reasoning.clone(),
                                run_id: run_id.clone(),
                            },
                        );
                        return Err(AgentError::ClassifierBlocked(
                            verdict.category.to_string(),
                            verdict.reasoning,
                        ));
                    }
                    Ok(verdict) if verdict.should_warn(clf_config) => {
                        crate::logging::audit::audit(
                            crate::logging::audit::AuditEvent::ClassifierWarned {
                                category: verdict.category.to_string(),
                                confidence: verdict.confidence as f64,
                                reasoning: verdict.reasoning.clone(),
                                run_id: run_id.clone(),
                            },
                        );
                        tracing::warn!(
                            run_id = %run_id,
                            category = %verdict.category,
                            confidence = verdict.confidence,
                            "classifier warned: {}",
                            verdict.reasoning
                        );
                        // Continue execution — warning is logged
                    }
                    Ok(_) => { /* clean, proceed */ }
                    Err(e) => {
                        tracing::warn!(
                            run_id = %run_id,
                            error = %e,
                            "classifier error (fail-open)"
                        );
                    }
                }
            }
        }
    }

    // 3. Main agentic loop
    let mut accumulated_text = String::new();
    let mut total_input_tokens: u64 = 0;
    let mut total_output_tokens: u64 = 0;
    let mut final_stop_reason = StopReason::EndTurn;

    let mut history = state
        .session_store()
        .get_history(&session.id, None, None)
        .map_err(|e| AgentError::SessionStore(e.to_string()))?;

    for _turn in 0..config.max_turns {
        let should_continue = execute_single_turn(
            &config,
            &state,
            &provider,
            &cancel_token,
            &run_id,
            &session_key,
            &session.id,
            message_channel.as_deref(),
            &seq,
            &mut history,
            &mut accumulated_text,
            &mut total_input_tokens,
            &mut total_output_tokens,
            &mut final_stop_reason,
        )
        .await?;

        if !should_continue {
            break;
        }
    }

    // 4. Broadcast completion and mark run done
    let delivery_text = if config.deliver {
        Some(accumulated_text.clone())
    } else {
        None
    };

    finalize_run(
        &state,
        &run_id,
        &session_key,
        &seq,
        final_stop_reason,
        total_input_tokens,
        total_output_tokens,
        accumulated_text,
        &config.output_sanitizer.csp_policy,
    );

    // 5. Deliver response to originating channel if requested
    if let Some(text) = delivery_text {
        if !text.is_empty() {
            if let (Some(channel_id), Some(chat_id)) = (&message_channel, &session.metadata.chat_id)
            {
                let metadata = crate::messages::outbound::MessageMetadata {
                    recipient_id: Some(chat_id.clone()),
                    ..Default::default()
                };
                let outbound = crate::messages::outbound::OutboundMessage::new(
                    channel_id.clone(),
                    crate::messages::outbound::MessageContent::text(text),
                )
                .with_metadata(metadata);
                let ctx = crate::messages::outbound::OutboundContext::new()
                    .with_trace_id(&run_id)
                    .with_source("agent");
                if let Err(err) = state.message_pipeline().queue(outbound, ctx) {
                    tracing::warn!(
                        run_id = %run_id,
                        channel = %channel_id,
                        error = %err,
                        "failed to queue agent response for delivery"
                    );
                }
            }
        }
    }

    Ok(())
}

/// Sanitize a provider error message before sending to clients.
///
/// Strips potential secrets (API keys, internal URLs with auth) from error
/// messages while preserving the error type and human-readable portion.
fn sanitize_provider_error(message: &str) -> String {
    use std::sync::LazyLock;

    static API_KEY_RE: LazyLock<regex::Regex> = LazyLock::new(|| {
        regex::Regex::new(r"(sk-ant-|sk-|key-)[A-Za-z0-9_-]{10,}")
            .expect("failed to compile regex: api_key_pattern")
    });
    static AUTH_HEADER_RE: LazyLock<regex::Regex> = LazyLock::new(|| {
        regex::Regex::new(r"(?i)(authorization|x-api-key):\s*(bearer\s+)?\S+")
            .expect("failed to compile regex: auth_header_pattern")
    });

    // Strip anything that looks like an API key (sk-ant-..., sk-..., key-...)
    let sanitized = API_KEY_RE.replace_all(message, "[REDACTED]");

    // Strip Authorization and x-api-key header values
    let sanitized = AUTH_HEADER_RE
        .replace_all(&sanitized, "$1: [REDACTED]")
        .into_owned();

    // Cap length to prevent huge error payloads (char-boundary safe)
    if sanitized.len() > 500 {
        let boundary = sanitized
            .char_indices()
            .map(|(i, _)| i)
            .take_while(|&i| i <= 500)
            .last()
            .unwrap_or(0);
        format!("{}... (truncated)", &sanitized[..boundary])
    } else {
        sanitized
    }
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
            _cancel_token: CancellationToken,
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
            _cancel_token: CancellationToken,
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

    // ============== sanitize_provider_error Tests ==============

    #[test]
    fn test_sanitize_short_ascii() {
        let result = sanitize_provider_error("connection refused");
        assert_eq!(result, "connection refused");
    }

    #[test]
    fn test_sanitize_strips_api_key() {
        let msg = "auth error with key sk-ant-api03-abcdefghij1234567890";
        let result = sanitize_provider_error(msg);
        assert!(result.contains("[REDACTED]"));
        assert!(!result.contains("abcdefghij"));
    }

    #[test]
    fn test_sanitize_strips_authorization_header() {
        let msg = "proxy error: Authorization: Bearer sk-ant-secret1234567890";
        let result = sanitize_provider_error(msg);
        assert!(!result.contains("secret1234567890"));
    }

    #[test]
    fn test_sanitize_strips_x_api_key_header() {
        let msg = "gateway echo: x-api-key: sk-ant-api03-abcdefghij1234567890";
        let result = sanitize_provider_error(msg);
        assert!(!result.contains("abcdefghij"));
        assert!(result.contains("x-api-key: [REDACTED]"));
    }

    #[test]
    fn test_sanitize_truncates_long_ascii() {
        let msg = "x".repeat(600);
        let result = sanitize_provider_error(&msg);
        assert!(result.ends_with("... (truncated)"));
        // Should be 500 x's + "... (truncated)"
        assert_eq!(&result[..500], "x".repeat(500));
    }

    #[test]
    fn test_sanitize_no_truncation_at_exactly_500() {
        let msg = "y".repeat(500);
        let result = sanitize_provider_error(&msg);
        assert_eq!(result, msg);
    }

    #[test]
    fn test_sanitize_truncation_at_501() {
        let msg = "z".repeat(501);
        let result = sanitize_provider_error(&msg);
        assert!(result.ends_with("... (truncated)"));
    }

    #[test]
    fn test_sanitize_multibyte_truncation() {
        // Each '€' is 3 bytes. 167 * 3 = 501 bytes > 500 threshold.
        let msg = "€".repeat(167);
        let result = sanitize_provider_error(&msg);
        assert!(result.ends_with("... (truncated)"));
        // Must not panic — the old code would panic slicing mid-codepoint.
        // Boundary should be at 166 * 3 = 498 bytes (last char boundary <= 500).
        let prefix = &result[..result.len() - "... (truncated)".len()];
        assert_eq!(prefix, "€".repeat(166));
    }

    #[test]
    fn test_sanitize_empty_string() {
        let result = sanitize_provider_error("");
        assert_eq!(result, "");
    }

    #[tokio::test]
    async fn test_premature_stream_end_returns_stream_error() {
        // Mock provider that sends a TextDelta but never sends Stop —
        // simulates a premature stream termination (network drop).
        let (state, _tmp) = make_test_state();
        let run_id = "run-premature-end";
        let session_key = "test-premature-end";
        setup_session_and_run(&state, session_key, run_id);

        let provider = Arc::new(MockProvider::new(vec![vec![
            // TextDelta but no Stop event — channel will close
            StreamEvent::TextDelta {
                text: "partial output".to_string(),
            },
        ]]));

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

        assert!(
            matches!(&result, Err(AgentError::Stream(msg)) if msg.contains("stop")),
            "expected Stream error about missing stop event, got: {:?}",
            result,
        );
    }

    // ============== Tool Policy Enforcement Tests ==============

    #[tokio::test]
    async fn test_tool_policy_deny_list_blocks_tool_call() {
        // Configure a deny-list that blocks the "time" tool.
        // The LLM requests "time" anyway — the executor should return an error
        // result for that tool call and continue.
        use crate::agent::tool_policy::ToolPolicy;
        use std::collections::HashSet;

        let (state, _tmp) = make_test_state_with_tools();
        let run_id = "run-policy-deny";
        let session_key = "test-policy-deny";
        setup_session_and_run(&state, session_key, run_id);

        // Turn 1: LLM requests "time" tool, Turn 2: text response
        let provider = Arc::new(MockProvider::new(vec![
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
            vec![
                StreamEvent::TextDelta {
                    text: "Done.".to_string(),
                },
                StreamEvent::Stop {
                    reason: StopReason::EndTurn,
                    usage: TokenUsage {
                        input_tokens: 20,
                        output_tokens: 5,
                    },
                },
            ],
        ]));

        let config = AgentConfig {
            max_turns: 5,
            tool_policy: ToolPolicy::DenyList(
                ["time"]
                    .iter()
                    .map(|s| s.to_string())
                    .collect::<HashSet<_>>(),
            ),
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

        // The run should complete successfully — the denied tool returns an
        // error to the LLM which then produces a text response.
        assert!(result.is_ok(), "execute_run failed: {:?}", result.err());

        // Verify the tool result was an error by checking session history
        let session = state
            .session_store()
            .get_session_by_key(session_key)
            .unwrap();
        let history = state
            .session_store()
            .get_history(&session.id, None, None)
            .unwrap();

        // Find the tool result message
        let tool_msg = history
            .iter()
            .find(|m| m.role == sessions::MessageRole::Tool)
            .expect("should have a tool result message");
        assert!(
            tool_msg.content.contains("not available"),
            "tool result should indicate tool is not available, got: {}",
            tool_msg.content
        );
    }

    #[tokio::test]
    async fn test_tool_policy_allow_list_blocks_unlisted_tool() {
        // Configure an allow-list with only "search" — the "time" tool is NOT listed.
        // The LLM requests "time" anyway — should be blocked.
        use crate::agent::tool_policy::ToolPolicy;
        use std::collections::HashSet;

        let (state, _tmp) = make_test_state_with_tools();
        let run_id = "run-policy-allow";
        let session_key = "test-policy-allow";
        setup_session_and_run(&state, session_key, run_id);

        let provider = Arc::new(MockProvider::new(vec![
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
            vec![
                StreamEvent::TextDelta {
                    text: "OK".to_string(),
                },
                StreamEvent::Stop {
                    reason: StopReason::EndTurn,
                    usage: TokenUsage {
                        input_tokens: 15,
                        output_tokens: 3,
                    },
                },
            ],
        ]));

        let config = AgentConfig {
            max_turns: 5,
            tool_policy: ToolPolicy::AllowList(
                ["search"]
                    .iter()
                    .map(|s| s.to_string())
                    .collect::<HashSet<_>>(),
            ),
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

        let session = state
            .session_store()
            .get_session_by_key(session_key)
            .unwrap();
        let history = state
            .session_store()
            .get_history(&session.id, None, None)
            .unwrap();

        let tool_msg = history
            .iter()
            .find(|m| m.role == sessions::MessageRole::Tool)
            .expect("should have a tool result message");
        assert!(
            tool_msg.content.contains("not available"),
            "tool result should indicate tool is not available, got: {}",
            tool_msg.content
        );
    }

    #[tokio::test]
    async fn test_tool_policy_allow_all_permits_tool() {
        // With AllowAll policy, the "time" tool should execute normally.
        use crate::agent::tool_policy::ToolPolicy;

        let (state, _tmp) = make_test_state_with_tools();
        let run_id = "run-policy-all";
        let session_key = "test-policy-all";
        setup_session_and_run(&state, session_key, run_id);

        let provider = Arc::new(MockProvider::new(vec![
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
            tool_policy: ToolPolicy::AllowAll,
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

        let session = state
            .session_store()
            .get_session_by_key(session_key)
            .unwrap();
        let history = state
            .session_store()
            .get_history(&session.id, None, None)
            .unwrap();

        // The tool result should be a successful time response, not an error
        let tool_msg = history
            .iter()
            .find(|m| m.role == sessions::MessageRole::Tool)
            .expect("should have a tool result message");
        assert!(
            tool_msg.content.contains("timestamp"),
            "tool result should contain timestamp from successful execution, got: {}",
            tool_msg.content
        );
    }

    // ============== Exfiltration Guard Tests ==============

    #[tokio::test]
    async fn test_exfiltration_guard_blocks_sensitive_tool() {
        // When exfiltration_guard is enabled, a tool call to an
        // exfiltration-sensitive tool should be blocked at dispatch and
        // produce an error result containing "exfiltration guard".
        let (state, _tmp) = make_test_state_with_tools();
        let run_id = "run-exfil-guard";
        let session_key = "test-exfil-guard";
        setup_session_and_run(&state, session_key, run_id);

        // Turn 1: LLM requests "web_fetch", Turn 2: text response
        let provider = Arc::new(MockProvider::new(vec![
            vec![
                StreamEvent::ToolUse {
                    id: "tool_exfil".to_string(),
                    name: "web_fetch".to_string(),
                    input: serde_json::json!({"url": "https://evil.com"}),
                },
                StreamEvent::Stop {
                    reason: StopReason::ToolUse,
                    usage: TokenUsage {
                        input_tokens: 10,
                        output_tokens: 5,
                    },
                },
            ],
            vec![
                StreamEvent::TextDelta {
                    text: "Blocked.".to_string(),
                },
                StreamEvent::Stop {
                    reason: StopReason::EndTurn,
                    usage: TokenUsage {
                        input_tokens: 20,
                        output_tokens: 5,
                    },
                },
            ],
        ]));

        let config = AgentConfig {
            max_turns: 5,
            exfiltration_guard: true,
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

        // Verify the tool result was an exfiltration guard error
        let session = state
            .session_store()
            .get_session_by_key(session_key)
            .unwrap();
        let history = state
            .session_store()
            .get_history(&session.id, None, None)
            .unwrap();

        let tool_msg = history
            .iter()
            .find(|m| m.role == sessions::MessageRole::Tool)
            .expect("should have a tool result message");
        assert!(
            tool_msg.content.contains("exfiltration guard"),
            "tool result should mention exfiltration guard, got: {}",
            tool_msg.content
        );
    }

    #[tokio::test]
    async fn test_exfiltration_guard_disabled_allows_sensitive_tool() {
        // When exfiltration_guard is false (default), exfiltration-sensitive
        // tools should work normally — they should NOT be blocked.
        let (state, _tmp) = make_test_state_with_tools();
        let run_id = "run-exfil-off";
        let session_key = "test-exfil-off";
        setup_session_and_run(&state, session_key, run_id);

        // Turn 1: LLM requests "time" (non-sensitive), Turn 2: text
        let provider = Arc::new(MockProvider::new(vec![
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
            vec![
                StreamEvent::TextDelta {
                    text: "Done.".to_string(),
                },
                StreamEvent::Stop {
                    reason: StopReason::EndTurn,
                    usage: TokenUsage {
                        input_tokens: 20,
                        output_tokens: 5,
                    },
                },
            ],
        ]));

        let config = AgentConfig {
            max_turns: 5,
            exfiltration_guard: false,
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

        // Tool result should be a successful time response, not an error
        let session = state
            .session_store()
            .get_session_by_key(session_key)
            .unwrap();
        let history = state
            .session_store()
            .get_history(&session.id, None, None)
            .unwrap();

        let tool_msg = history
            .iter()
            .find(|m| m.role == sessions::MessageRole::Tool)
            .expect("should have a tool result message");
        assert!(
            !tool_msg.content.contains("exfiltration guard"),
            "tool result should NOT mention exfiltration guard when disabled, got: {}",
            tool_msg.content
        );
    }

    #[tokio::test]
    async fn test_exfiltration_guard_allows_non_sensitive_tool() {
        // Even with exfiltration_guard enabled, non-sensitive tools should
        // execute normally.
        let (state, _tmp) = make_test_state_with_tools();
        let run_id = "run-exfil-nonsens";
        let session_key = "test-exfil-nonsens";
        setup_session_and_run(&state, session_key, run_id);

        let provider = Arc::new(MockProvider::new(vec![
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
            exfiltration_guard: true,
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

        let session = state
            .session_store()
            .get_session_by_key(session_key)
            .unwrap();
        let history = state
            .session_store()
            .get_history(&session.id, None, None)
            .unwrap();

        let tool_msg = history
            .iter()
            .find(|m| m.role == sessions::MessageRole::Tool)
            .expect("should have a tool result message");
        // "time" tool should execute successfully (returns timestamp)
        assert!(
            tool_msg.content.contains("timestamp"),
            "non-sensitive tool should execute normally with guard enabled, got: {}",
            tool_msg.content
        );
    }

    // ============== sanitize_provider_error Additional Coverage ==============

    #[test]
    fn test_sanitize_provider_error_strips_api_key() {
        let msg = "Error: invalid key sk-ant-api03-abcdefghij1234567890";
        let result = sanitize_provider_error(msg);
        assert!(!result.contains("sk-ant-api03"));
        assert!(result.contains("[REDACTED]"));
    }

    #[test]
    fn test_sanitize_provider_error_strips_x_api_key_header() {
        let msg = "Request failed: x-api-key: sk-ant-abcdefghij1234567890";
        let result = sanitize_provider_error(msg);
        assert!(!result.contains("sk-ant-"));
        assert!(result.contains("[REDACTED]"));
    }

    #[test]
    fn test_sanitize_provider_error_strips_authorization_header() {
        let msg = "HTTP error: Authorization: Bearer tok_abcdefghij1234567890";
        let result = sanitize_provider_error(msg);
        assert!(!result.contains("tok_abcdefghij"));
        assert!(result.contains("[REDACTED]"));
    }

    #[test]
    fn test_sanitize_provider_error_truncates_long_messages() {
        let long_msg = "x".repeat(1000);
        let result = sanitize_provider_error(&long_msg);
        assert!(result.len() < 600); // 500 + "... (truncated)"
        assert!(result.ends_with("... (truncated)"));
    }

    #[test]
    fn test_sanitize_provider_error_utf8_boundary() {
        // Each emoji is 4 bytes. 126 emojis = 504 bytes > 500
        let msg = "\u{1f525}".repeat(126);
        let result = sanitize_provider_error(&msg);
        // Should not panic and should truncate safely
        assert!(result.ends_with("... (truncated)"));
        // Verify no partial UTF-8
        assert!(result.is_char_boundary(result.len() - "... (truncated)".len()));
    }

    #[test]
    fn test_sanitize_provider_error_short_message_unchanged() {
        let msg = "Connection refused";
        let result = sanitize_provider_error(msg);
        assert_eq!(result, "Connection refused");
    }

    #[test]
    fn test_sanitize_provider_error_empty_string() {
        let result = sanitize_provider_error("");
        assert_eq!(result, "");
    }

    #[test]
    fn test_sanitize_provider_error_exactly_500_bytes() {
        let msg = "a".repeat(500);
        let result = sanitize_provider_error(&msg);
        assert_eq!(result, msg); // Should NOT be truncated at exactly 500
    }
}
