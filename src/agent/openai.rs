//! OpenAI Chat Completions API provider.
//!
//! Streams completions from the OpenAI `/v1/chat/completions` endpoint using
//! Server-Sent Events (SSE).

use async_trait::async_trait;
use futures_util::StreamExt;
use serde_json::{json, Value};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::agent::provider::*;
use crate::agent::AgentError;

/// OpenAI Chat Completions API provider.
#[derive(Debug)]
pub struct OpenAiProvider {
    client: reqwest::Client,
    api_key: String,
    base_url: String,
}

impl OpenAiProvider {
    pub fn new(api_key: String) -> Result<Self, AgentError> {
        if api_key.trim().is_empty() {
            return Err(AgentError::InvalidApiKey(
                "API key must not be empty".to_string(),
            ));
        }
        let client = reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(10))
            .timeout(std::time::Duration::from_secs(300))
            .build()
            .map_err(|e| AgentError::Provider(format!("failed to build HTTP client: {e}")))?;
        Ok(Self {
            client,
            api_key,
            base_url: "https://api.openai.com".to_string(),
        })
    }

    pub fn with_base_url(mut self, url: String) -> Result<Self, AgentError> {
        let parsed = url::Url::parse(&url)
            .map_err(|e| AgentError::InvalidBaseUrl(format!("invalid URL \"{url}\": {e}")))?;
        let host = parsed.host_str().unwrap_or("");
        let is_loopback =
            host == "localhost" || host == "127.0.0.1" || host == "::1" || host == "[::1]";
        if parsed.scheme() != "https" && !is_loopback {
            return Err(AgentError::InvalidBaseUrl(format!(
                "base URL must use https scheme (or http for localhost), got \"{}\"",
                parsed.scheme()
            )));
        }
        // Strip trailing slash for consistent path joining
        self.base_url = url.trim_end_matches('/').to_string();
        Ok(self)
    }

    /// Build the JSON body for the OpenAI Chat Completions API.
    ///
    /// Exposed as `pub(crate)` so that providers using composition (e.g. Venice)
    /// can build the body and inject extra parameters before sending.
    pub(crate) fn build_body(&self, request: &CompletionRequest) -> Value {
        let mut messages: Vec<Value> = Vec::new();

        if let Some(ref system) = request.system {
            messages.push(json!({
                "role": "system",
                "content": system,
            }));
        }

        for msg in &request.messages {
            match msg.role {
                LlmRole::User => convert_user_message_openai(msg, &mut messages),
                LlmRole::Assistant => convert_assistant_message_openai(msg, &mut messages),
            }
        }

        let mut body = json!({
            "model": request.model,
            "messages": messages,
            "max_completion_tokens": request.max_tokens,
            "stream": true,
            "stream_options": { "include_usage": true },
        });

        if let Some(temp) = request.temperature {
            body["temperature"] = json!(temp);
        }

        append_tools_openai(&request.tools, &mut body);

        body
    }

    /// Send a pre-built JSON body to the Chat Completions endpoint and stream
    /// the response.
    ///
    /// This is separated from `complete()` so that composition-based providers
    /// (e.g. Venice) can modify the body (inject extra parameters) before
    /// sending.
    pub(crate) async fn complete_with_body(
        &self,
        body: Value,
        cancel_token: CancellationToken,
    ) -> Result<mpsc::Receiver<StreamEvent>, AgentError> {
        if cancel_token.is_cancelled() {
            return Err(AgentError::Cancelled);
        }
        let url = format!("{}/v1/chat/completions", self.base_url);

        let response = tokio::select! {
            _ = cancel_token.cancelled() => {
                return Err(AgentError::Cancelled);
            }
            response = self
                .client
                .post(&url)
                .header("authorization", format!("Bearer {}", self.api_key))
                .header("content-type", "application/json")
                .header("accept", "text/event-stream")
                .json(&body)
                .send() => {
                    response.map_err(|e| AgentError::Provider(format!("HTTP request failed: {e}")))?
                }
        };

        if !response.status().is_success() {
            let status = response.status();
            let body = response
                .text()
                .await
                .unwrap_or_else(|_| "<unreadable>".to_string());
            return Err(AgentError::Provider(format!(
                "API returned {status}: {body}"
            )));
        }

        let (tx, rx) = mpsc::channel(64);

        // Spawn a task to read the SSE stream and forward events
        let stream = response.bytes_stream();
        let cancel = cancel_token.clone();
        tokio::spawn(async move {
            if let Err(e) = process_sse_stream(stream, &tx, &cancel).await {
                let _ = tx
                    .send(StreamEvent::Error {
                        message: e.to_string(),
                    })
                    .await;
            }
        });

        Ok(rx)
    }
}

/// Convert a user-role `LlmMessage` into one or more OpenAI-format messages.
fn convert_user_message_openai(msg: &LlmMessage, messages: &mut Vec<Value>) {
    let has_tool_result = msg
        .content
        .iter()
        .any(|b| matches!(b, ContentBlock::ToolResult { .. }));

    if has_tool_result {
        for block in &msg.content {
            match block {
                ContentBlock::ToolResult {
                    tool_use_id,
                    content,
                    ..
                } => {
                    messages.push(json!({
                        "role": "tool",
                        "tool_call_id": tool_use_id,
                        "content": content,
                    }));
                }
                ContentBlock::Text { text } => {
                    messages.push(json!({
                        "role": "user",
                        "content": text,
                    }));
                }
                _ => {}
            }
        }
    } else {
        let text = collect_text_blocks(&msg.content);
        if !text.is_empty() {
            messages.push(json!({
                "role": "user",
                "content": text,
            }));
        }
    }
}

/// Convert an assistant-role `LlmMessage` into an OpenAI-format message.
fn convert_assistant_message_openai(msg: &LlmMessage, messages: &mut Vec<Value>) {
    let has_tool_use = msg
        .content
        .iter()
        .any(|b| matches!(b, ContentBlock::ToolUse { .. }));

    if has_tool_use {
        let text_content = collect_text_blocks(&msg.content);

        let tool_calls: Vec<Value> = msg
            .content
            .iter()
            .filter_map(|b| match b {
                ContentBlock::ToolUse { id, name, input } => Some(json!({
                    "id": id,
                    "type": "function",
                    "function": {
                        "name": name,
                        "arguments": input.to_string(),
                    }
                })),
                _ => None,
            })
            .collect();

        let mut msg_obj = json!({
            "role": "assistant",
            "tool_calls": tool_calls,
        });
        if !text_content.is_empty() {
            msg_obj["content"] = json!(text_content);
        }
        messages.push(msg_obj);
    } else {
        let text = collect_text_blocks(&msg.content);
        messages.push(json!({
            "role": "assistant",
            "content": text,
        }));
    }
}

/// Concatenate all `Text` blocks in a content slice into a single string.
fn collect_text_blocks(content: &[ContentBlock]) -> String {
    content
        .iter()
        .filter_map(|b| match b {
            ContentBlock::Text { text } => Some(text.as_str()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("")
}

/// Append tool definitions to the body if any are present.
fn append_tools_openai(tools: &[ToolDefinition], body: &mut Value) {
    if !tools.is_empty() {
        let tool_values: Vec<Value> = tools
            .iter()
            .map(|t| {
                json!({
                    "type": "function",
                    "function": {
                        "name": t.name,
                        "description": t.description,
                        "parameters": t.input_schema,
                    }
                })
            })
            .collect();
        body["tools"] = json!(tool_values);
    }
}

#[async_trait]
impl LlmProvider for OpenAiProvider {
    async fn complete(
        &self,
        request: CompletionRequest,
        cancel_token: CancellationToken,
    ) -> Result<mpsc::Receiver<StreamEvent>, AgentError> {
        let body = self.build_body(&request);
        self.complete_with_body(body, cancel_token).await
    }
}

/// Maximum SSE line buffer size (1 MB). If a single SSE line exceeds this,
/// the stream is treated as corrupted to prevent unbounded memory growth.
const MAX_SSE_BUFFER_BYTES: usize = 1_048_576;

/// Process an OpenAI-compatible SSE byte stream into StreamEvents.
///
/// This is a public wrapper used by the Ollama provider, which uses the same
/// SSE format via Ollama's `/v1/chat/completions` OpenAI-compatible endpoint.
pub async fn process_ollama_sse_stream<S>(
    stream: S,
    tx: &mpsc::Sender<StreamEvent>,
    cancel_token: &CancellationToken,
) -> Result<(), String>
where
    S: futures_util::Stream<Item = Result<bytes::Bytes, reqwest::Error>> + Unpin,
{
    process_sse_stream(stream, tx, cancel_token).await
}

/// Process an OpenAI SSE byte stream into StreamEvents.
async fn process_sse_stream<S>(
    mut stream: S,
    tx: &mpsc::Sender<StreamEvent>,
    cancel_token: &CancellationToken,
) -> Result<(), String>
where
    S: futures_util::Stream<Item = Result<bytes::Bytes, reqwest::Error>> + Unpin,
{
    let mut buffer = String::new();
    // Accumulated tool call state: index → (id, name, arguments_json_string)
    let mut tool_calls: std::collections::HashMap<u64, (String, String, String)> =
        std::collections::HashMap::new();
    let mut accumulated_usage = TokenUsage::default();
    let mut got_done = false;

    loop {
        let chunk = tokio::select! {
            _ = cancel_token.cancelled() => return Ok(()),
            chunk = stream.next() => chunk,
        };
        let Some(chunk) = chunk else {
            break;
        };
        let chunk = chunk.map_err(|e| format!("stream read error: {e}"))?;
        buffer.push_str(&String::from_utf8_lossy(&chunk));

        if buffer.len() > MAX_SSE_BUFFER_BYTES {
            return Err(format!(
                "SSE buffer exceeded {} bytes, aborting stream",
                MAX_SSE_BUFFER_BYTES
            ));
        }

        // Process complete lines
        let mut consumed = 0;
        while let Some(rel_pos) = buffer[consumed..].find('\n') {
            let newline_pos = consumed + rel_pos;
            let line = buffer[consumed..newline_pos]
                .trim_end_matches('\r')
                .to_string();
            consumed = newline_pos + 1;

            if let Some(data) = line.strip_prefix("data: ") {
                // Check for the [DONE] sentinel
                if data.trim() == "[DONE]" {
                    got_done = true;
                    // Flush any remaining tool calls
                    let stop_event =
                        flush_tool_calls_and_stop(&mut tool_calls, &accumulated_usage, tx).await;
                    if let Some(event) = stop_event {
                        let is_stop = matches!(event, StreamEvent::Stop { .. });
                        if tx.send(event).await.is_err() {
                            return Ok(());
                        }
                        if is_stop {
                            return Ok(());
                        }
                    }
                    continue;
                }

                if let Some(event) = parse_sse_data(data, &mut tool_calls, &mut accumulated_usage) {
                    let is_stop = matches!(event, StreamEvent::Stop { .. });
                    let is_error = matches!(event, StreamEvent::Error { .. });
                    if tx.send(event).await.is_err() {
                        return Ok(()); // Receiver dropped
                    }
                    if is_stop || is_error {
                        return Ok(());
                    }
                }
            }
            // Ignore empty lines, comments, and event: lines
        }
        // Remove consumed bytes in one operation
        if consumed > 0 {
            buffer.drain(..consumed);
        }
    }

    if got_done {
        Ok(())
    } else {
        Err("stream ended without [DONE] sentinel (premature termination)".to_string())
    }
}

/// Parse a single SSE data payload from OpenAI's streaming format.
///
/// OpenAI streaming chunks look like:
/// ```json
/// {"id":"chatcmpl-...","choices":[{"index":0,"delta":{"content":"Hello"},"finish_reason":null}]}
/// ```
fn parse_sse_data(
    data: &str,
    tool_calls: &mut std::collections::HashMap<u64, (String, String, String)>,
    accumulated_usage: &mut TokenUsage,
) -> Option<StreamEvent> {
    let parsed: Value = serde_json::from_str(data).ok()?;

    // Check for error response
    if let Some(error) = parsed.get("error") {
        let message = error
            .get("message")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown API error")
            .to_string();
        return Some(StreamEvent::Error { message });
    }

    // Extract usage if present (OpenAI sends usage in the final chunk when
    // stream_options.include_usage is true)
    if let Some(usage) = parsed.get("usage") {
        if let Some(prompt_tokens) = usage.get("prompt_tokens").and_then(|v| v.as_u64()) {
            accumulated_usage.input_tokens = prompt_tokens;
        }
        if let Some(completion_tokens) = usage.get("completion_tokens").and_then(|v| v.as_u64()) {
            accumulated_usage.output_tokens = completion_tokens;
        }
    }

    // Process choices
    let choices = parsed.get("choices")?.as_array()?;
    if choices.is_empty() {
        return None;
    }

    let choice = &choices[0];

    // Check for finish_reason
    if let Some(finish_reason) = choice.get("finish_reason").and_then(|v| v.as_str()) {
        let reason = match finish_reason {
            "stop" => StopReason::EndTurn,
            "tool_calls" => StopReason::ToolUse,
            "length" => StopReason::MaxTokens,
            _ => StopReason::EndTurn,
        };

        // If the stop reason is tool_use, we need to flush pending tool calls.
        // The caller (process_sse_stream) handles this when it sees [DONE].
        // For now, just record the stop reason — the Stop event is emitted by
        // flush_tool_calls_and_stop when [DONE] arrives.
        if reason == StopReason::ToolUse {
            // Don't emit Stop yet — tool_calls may still be accumulating.
            // Store the finish reason for later.
            return None;
        }

        return Some(StreamEvent::Stop {
            reason,
            usage: *accumulated_usage,
        });
    }

    // Process delta
    let delta = choice.get("delta")?;

    // Text content
    if let Some(content) = delta.get("content").and_then(|v| v.as_str()) {
        if !content.is_empty() {
            return Some(StreamEvent::TextDelta {
                text: content.to_string(),
            });
        }
    }

    // Tool calls in delta
    if let Some(tc_array) = delta.get("tool_calls").and_then(|v| v.as_array()) {
        for tc in tc_array {
            let index = tc.get("index").and_then(|v| v.as_u64()).unwrap_or(0);

            // If there's an id, this is the start of a new tool call
            if let Some(id) = tc.get("id").and_then(|v| v.as_str()) {
                let name = tc
                    .get("function")
                    .and_then(|f| f.get("name"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let args = tc
                    .get("function")
                    .and_then(|f| f.get("arguments"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                tool_calls.insert(index, (id.to_string(), name, args));
            } else {
                // Partial argument delta — append to existing entry
                if let Some(entry) = tool_calls.get_mut(&index) {
                    if let Some(args_chunk) = tc
                        .get("function")
                        .and_then(|f| f.get("arguments"))
                        .and_then(|v| v.as_str())
                    {
                        entry.2.push_str(args_chunk);
                    }
                }
            }
        }
    }

    None
}

/// Flush accumulated tool calls as StreamEvents and emit a Stop event.
///
/// Called when we receive `[DONE]` from OpenAI to emit any pending tool calls
/// and the final Stop event.
async fn flush_tool_calls_and_stop(
    tool_calls: &mut std::collections::HashMap<u64, (String, String, String)>,
    usage: &TokenUsage,
    tx: &mpsc::Sender<StreamEvent>,
) -> Option<StreamEvent> {
    if tool_calls.is_empty() {
        // No pending tool calls — this was a normal text completion.
        // The Stop event was already emitted by parse_sse_data when
        // finish_reason was "stop".
        return None;
    }

    // Sort by index for deterministic ordering
    let mut sorted: Vec<(u64, (String, String, String))> = tool_calls.drain().collect();
    sorted.sort_by_key(|(idx, _)| *idx);

    for (_index, (id, name, args_json)) in sorted {
        let input: Value = serde_json::from_str(&args_json).unwrap_or(json!({}));
        let event = StreamEvent::ToolUse { id, name, input };
        if tx.send(event).await.is_err() {
            return None; // Receiver dropped
        }
    }

    // Emit stop with ToolUse reason
    Some(StreamEvent::Stop {
        reason: StopReason::ToolUse,
        usage: *usage,
    })
}

/// Determine whether a model identifier should route to the OpenAI provider.
pub fn is_openai_model(model: &str) -> bool {
    let lower = model.to_lowercase();
    lower.starts_with("gpt-")
        || lower.starts_with("o1-")
        || lower.starts_with("o3-")
        || lower.starts_with("o1")
        || lower.starts_with("o3")
        || lower.starts_with("chatgpt-")
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== build_body tests ====================

    #[test]
    fn test_build_body_basic() {
        let provider = OpenAiProvider::new("test-key".to_string()).unwrap();
        let request = CompletionRequest {
            model: "gpt-4o".to_string(),
            messages: vec![LlmMessage {
                role: LlmRole::User,
                content: vec![ContentBlock::Text {
                    text: "Hello".to_string(),
                }],
            }],
            system: Some("You are helpful.".to_string()),
            tools: vec![],
            max_tokens: 1024,
            temperature: Some(0.7),
            extra: None,
        };
        let body = provider.build_body(&request);
        assert_eq!(body["model"], "gpt-4o");
        assert_eq!(body["max_completion_tokens"], 1024);
        assert_eq!(body["stream"], true);
        assert_eq!(body["temperature"], 0.7);
        // System message should be the first message
        let messages = body["messages"].as_array().unwrap();
        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0]["role"], "system");
        assert_eq!(messages[0]["content"], "You are helpful.");
        assert_eq!(messages[1]["role"], "user");
        assert_eq!(messages[1]["content"], "Hello");
        // No tools key when tools is empty
        assert!(body.get("tools").is_none());
    }

    #[test]
    fn test_build_body_with_tools() {
        let provider = OpenAiProvider::new("test-key".to_string()).unwrap();
        let request = CompletionRequest {
            model: "gpt-4o".to_string(),
            messages: vec![],
            system: None,
            tools: vec![ToolDefinition {
                name: "get_weather".to_string(),
                description: "Get weather for a city".to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "city": { "type": "string" }
                    }
                }),
            }],
            max_tokens: 4096,
            temperature: None,
            extra: None,
        };
        let body = provider.build_body(&request);
        assert!(body["tools"].is_array());
        let tools = body["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0]["type"], "function");
        assert_eq!(tools[0]["function"]["name"], "get_weather");
        assert_eq!(
            tools[0]["function"]["description"],
            "Get weather for a city"
        );
        assert!(body.get("temperature").is_none());
    }

    #[test]
    fn test_build_body_assistant_with_tool_calls() {
        let provider = OpenAiProvider::new("test-key".to_string()).unwrap();
        let request = CompletionRequest {
            model: "gpt-4o".to_string(),
            messages: vec![
                LlmMessage {
                    role: LlmRole::User,
                    content: vec![ContentBlock::Text {
                        text: "What's the weather?".to_string(),
                    }],
                },
                LlmMessage {
                    role: LlmRole::Assistant,
                    content: vec![
                        ContentBlock::Text {
                            text: "Let me check.".to_string(),
                        },
                        ContentBlock::ToolUse {
                            id: "call_abc123".to_string(),
                            name: "get_weather".to_string(),
                            input: json!({"city": "SF"}),
                        },
                    ],
                },
                LlmMessage {
                    role: LlmRole::User,
                    content: vec![ContentBlock::ToolResult {
                        tool_use_id: "call_abc123".to_string(),
                        content: "72F and sunny".to_string(),
                        is_error: false,
                    }],
                },
            ],
            system: None,
            tools: vec![],
            max_tokens: 1024,
            temperature: None,
            extra: None,
        };
        let body = provider.build_body(&request);
        let messages = body["messages"].as_array().unwrap();
        assert_eq!(messages.len(), 3);

        // User message
        assert_eq!(messages[0]["role"], "user");
        assert_eq!(messages[0]["content"], "What's the weather?");

        // Assistant message with tool_calls
        assert_eq!(messages[1]["role"], "assistant");
        assert_eq!(messages[1]["content"], "Let me check.");
        let tool_calls = messages[1]["tool_calls"].as_array().unwrap();
        assert_eq!(tool_calls.len(), 1);
        assert_eq!(tool_calls[0]["id"], "call_abc123");
        assert_eq!(tool_calls[0]["type"], "function");
        assert_eq!(tool_calls[0]["function"]["name"], "get_weather");

        // Tool result as role: "tool"
        assert_eq!(messages[2]["role"], "tool");
        assert_eq!(messages[2]["tool_call_id"], "call_abc123");
        assert_eq!(messages[2]["content"], "72F and sunny");
    }

    #[test]
    fn test_build_body_no_system() {
        let provider = OpenAiProvider::new("test-key".to_string()).unwrap();
        let request = CompletionRequest {
            model: "gpt-4o".to_string(),
            messages: vec![LlmMessage {
                role: LlmRole::User,
                content: vec![ContentBlock::Text {
                    text: "Hi".to_string(),
                }],
            }],
            system: None,
            tools: vec![],
            max_tokens: 1024,
            temperature: None,
            extra: None,
        };
        let body = provider.build_body(&request);
        let messages = body["messages"].as_array().unwrap();
        // No system message
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0]["role"], "user");
    }

    // ==================== SSE parsing tests ====================

    #[test]
    fn test_parse_text_delta() {
        let mut tool_calls = std::collections::HashMap::new();
        let mut usage = TokenUsage::default();
        let event = parse_sse_data(
            r#"{"id":"chatcmpl-123","choices":[{"index":0,"delta":{"content":"Hello"},"finish_reason":null}]}"#,
            &mut tool_calls,
            &mut usage,
        );
        match event {
            Some(StreamEvent::TextDelta { text }) => assert_eq!(text, "Hello"),
            other => panic!("expected TextDelta, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_stop_reason_end_turn() {
        let mut tool_calls = std::collections::HashMap::new();
        let mut usage = TokenUsage {
            input_tokens: 100,
            output_tokens: 42,
        };
        let event = parse_sse_data(
            r#"{"id":"chatcmpl-123","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}"#,
            &mut tool_calls,
            &mut usage,
        );
        match event {
            Some(StreamEvent::Stop { reason, usage }) => {
                assert_eq!(reason, StopReason::EndTurn);
                assert_eq!(usage.input_tokens, 100);
                assert_eq!(usage.output_tokens, 42);
            }
            other => panic!("expected Stop, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_stop_reason_length() {
        let mut tool_calls = std::collections::HashMap::new();
        let mut usage = TokenUsage::default();
        let event = parse_sse_data(
            r#"{"id":"chatcmpl-123","choices":[{"index":0,"delta":{},"finish_reason":"length"}]}"#,
            &mut tool_calls,
            &mut usage,
        );
        match event {
            Some(StreamEvent::Stop { reason, .. }) => {
                assert_eq!(reason, StopReason::MaxTokens);
            }
            other => panic!("expected Stop with MaxTokens, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_tool_calls_finish_reason_returns_none() {
        // tool_calls finish_reason should NOT emit a Stop event immediately —
        // the Stop is deferred until [DONE] arrives and tool calls are flushed.
        let mut tool_calls = std::collections::HashMap::new();
        let mut usage = TokenUsage::default();
        let event = parse_sse_data(
            r#"{"id":"chatcmpl-123","choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}"#,
            &mut tool_calls,
            &mut usage,
        );
        assert!(
            event.is_none(),
            "tool_calls finish_reason should not emit Stop, got {event:?}"
        );
    }

    #[test]
    fn test_parse_tool_call_accumulation() {
        let mut tool_calls = std::collections::HashMap::new();
        let mut usage = TokenUsage::default();

        // First chunk: tool call start with id and function name
        parse_sse_data(
            r#"{"id":"chatcmpl-123","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_abc","type":"function","function":{"name":"get_weather","arguments":""}}]},"finish_reason":null}]}"#,
            &mut tool_calls,
            &mut usage,
        );
        assert!(tool_calls.contains_key(&0));
        assert_eq!(tool_calls[&0].0, "call_abc");
        assert_eq!(tool_calls[&0].1, "get_weather");

        // Second chunk: partial arguments
        parse_sse_data(
            r#"{"id":"chatcmpl-123","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\"city\":"}}]},"finish_reason":null}]}"#,
            &mut tool_calls,
            &mut usage,
        );
        assert_eq!(tool_calls[&0].2, r#"{"city":"#);

        // Third chunk: more arguments
        parse_sse_data(
            r#"{"id":"chatcmpl-123","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"\"SF\"}"}}]},"finish_reason":null}]}"#,
            &mut tool_calls,
            &mut usage,
        );
        assert_eq!(tool_calls[&0].2, r#"{"city":"SF"}"#);
    }

    #[test]
    fn test_parse_usage_from_final_chunk() {
        let mut tool_calls = std::collections::HashMap::new();
        let mut usage = TokenUsage::default();
        // OpenAI sends usage in the final chunk (with include_usage option)
        parse_sse_data(
            r#"{"id":"chatcmpl-123","choices":[],"usage":{"prompt_tokens":150,"completion_tokens":42,"total_tokens":192}}"#,
            &mut tool_calls,
            &mut usage,
        );
        assert_eq!(usage.input_tokens, 150);
        assert_eq!(usage.output_tokens, 42);
    }

    #[test]
    fn test_parse_error_response() {
        let mut tool_calls = std::collections::HashMap::new();
        let mut usage = TokenUsage::default();
        let event = parse_sse_data(
            r#"{"error":{"message":"Rate limit exceeded","type":"rate_limit_error","code":"rate_limit_exceeded"}}"#,
            &mut tool_calls,
            &mut usage,
        );
        match event {
            Some(StreamEvent::Error { message }) => {
                assert_eq!(message, "Rate limit exceeded");
            }
            other => panic!("expected Error, got {other:?}"),
        }
    }

    // ==================== flush_tool_calls_and_stop tests ====================

    #[tokio::test]
    async fn test_flush_tool_calls_emits_tool_use_then_stop() {
        let (tx, mut rx) = mpsc::channel(64);
        let mut tool_calls = std::collections::HashMap::new();
        tool_calls.insert(
            0,
            (
                "call_1".to_string(),
                "get_weather".to_string(),
                r#"{"city":"SF"}"#.to_string(),
            ),
        );
        let usage = TokenUsage {
            input_tokens: 100,
            output_tokens: 50,
        };

        let stop_event = flush_tool_calls_and_stop(&mut tool_calls, &usage, &tx).await;
        assert!(stop_event.is_some());

        // Should have sent ToolUse via the channel
        let event = rx.try_recv().unwrap();
        match event {
            StreamEvent::ToolUse { id, name, input } => {
                assert_eq!(id, "call_1");
                assert_eq!(name, "get_weather");
                assert_eq!(input["city"], "SF");
            }
            other => panic!("expected ToolUse, got {other:?}"),
        }

        // The Stop event is returned (not sent via channel)
        match stop_event.unwrap() {
            StreamEvent::Stop { reason, usage } => {
                assert_eq!(reason, StopReason::ToolUse);
                assert_eq!(usage.input_tokens, 100);
                assert_eq!(usage.output_tokens, 50);
            }
            other => panic!("expected Stop, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_flush_empty_tool_calls_returns_none() {
        let (tx, _rx) = mpsc::channel(64);
        let mut tool_calls = std::collections::HashMap::new();
        let usage = TokenUsage::default();

        let result = flush_tool_calls_and_stop(&mut tool_calls, &usage, &tx).await;
        assert!(result.is_none());
    }

    // ==================== process_sse_stream integration tests ====================

    /// Helper: build a mock byte stream from raw SSE text chunks.
    fn mock_sse_stream(
        chunks: Vec<&str>,
    ) -> futures_util::stream::Iter<std::vec::IntoIter<Result<bytes::Bytes, reqwest::Error>>> {
        let items: Vec<Result<bytes::Bytes, reqwest::Error>> = chunks
            .into_iter()
            .map(|s| Ok(bytes::Bytes::from(s.to_owned())))
            .collect();
        futures_util::stream::iter(items)
    }

    #[tokio::test]
    async fn test_complete_text_stream() {
        let sse_data = concat!(
            "data: {\"id\":\"chatcmpl-1\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"\"},\"finish_reason\":null}]}\n\n",
            "data: {\"id\":\"chatcmpl-1\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"Hello\"},\"finish_reason\":null}]}\n\n",
            "data: {\"id\":\"chatcmpl-1\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\" world\"},\"finish_reason\":null}]}\n\n",
            "data: {\"id\":\"chatcmpl-1\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n",
            "data: {\"id\":\"chatcmpl-1\",\"choices\":[],\"usage\":{\"prompt_tokens\":10,\"completion_tokens\":5,\"total_tokens\":15}}\n\n",
            "data: [DONE]\n\n",
        );

        let stream = mock_sse_stream(vec![sse_data]);
        let (tx, mut rx) = mpsc::channel(64);

        let result = process_sse_stream(stream, &tx, &CancellationToken::new()).await;
        assert!(result.is_ok(), "expected Ok, got: {:?}", result);

        let mut events = Vec::new();
        while let Ok(event) = rx.try_recv() {
            events.push(event);
        }

        // Should have TextDelta events and Stop
        assert!(
            events
                .iter()
                .any(|e| matches!(e, StreamEvent::TextDelta { text } if text == "Hello")),
            "expected TextDelta 'Hello', got: {:?}",
            events,
        );
        assert!(
            events
                .iter()
                .any(|e| matches!(e, StreamEvent::TextDelta { text } if text == " world")),
            "expected TextDelta ' world', got: {:?}",
            events,
        );
        assert!(
            events.iter().any(|e| matches!(
                e,
                StreamEvent::Stop {
                    reason: StopReason::EndTurn,
                    ..
                }
            )),
            "expected Stop with EndTurn, got: {:?}",
            events,
        );
    }

    #[tokio::test]
    async fn test_complete_tool_call_stream() {
        let sse_data = concat!(
            "data: {\"id\":\"chatcmpl-1\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":null,\"tool_calls\":[{\"index\":0,\"id\":\"call_abc\",\"type\":\"function\",\"function\":{\"name\":\"get_weather\",\"arguments\":\"\"}}]},\"finish_reason\":null}]}\n\n",
            "data: {\"id\":\"chatcmpl-1\",\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"{\\\"city\\\":\\\"SF\\\"}\"}}]},\"finish_reason\":null}]}\n\n",
            "data: {\"id\":\"chatcmpl-1\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"tool_calls\"}]}\n\n",
            "data: {\"id\":\"chatcmpl-1\",\"choices\":[],\"usage\":{\"prompt_tokens\":20,\"completion_tokens\":10,\"total_tokens\":30}}\n\n",
            "data: [DONE]\n\n",
        );

        let stream = mock_sse_stream(vec![sse_data]);
        let (tx, mut rx) = mpsc::channel(64);

        let result = process_sse_stream(stream, &tx, &CancellationToken::new()).await;
        assert!(result.is_ok(), "expected Ok, got: {:?}", result);

        let mut events = Vec::new();
        while let Ok(event) = rx.try_recv() {
            events.push(event);
        }

        // Should have ToolUse and Stop
        assert!(
            events.iter().any(|e| matches!(
                e,
                StreamEvent::ToolUse { id, name, .. }
                if id == "call_abc" && name == "get_weather"
            )),
            "expected ToolUse for get_weather, got: {:?}",
            events,
        );
        assert!(
            events.iter().any(|e| matches!(
                e,
                StreamEvent::Stop {
                    reason: StopReason::ToolUse,
                    ..
                }
            )),
            "expected Stop with ToolUse, got: {:?}",
            events,
        );
    }

    #[tokio::test]
    async fn test_truncated_stream_without_done_returns_error() {
        // Stream ends abruptly — no [DONE]
        let sse_data = "data: {\"id\":\"chatcmpl-1\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"Hello\"},\"finish_reason\":null}]}\n\n";

        let stream = mock_sse_stream(vec![sse_data]);
        let (tx, _rx) = mpsc::channel(64);

        let result = process_sse_stream(stream, &tx, &CancellationToken::new()).await;
        assert!(result.is_err(), "expected Err for truncated stream, got Ok");
        let err_msg = result.unwrap_err();
        assert!(
            err_msg.contains("[DONE]"),
            "error should mention [DONE]: {err_msg}",
        );
    }

    // ==================== Provider construction tests ====================

    #[test]
    fn test_new_rejects_empty_api_key() {
        let result = OpenAiProvider::new("".to_string());
        assert!(result.is_err(), "expected empty API key to fail");
        let err = result.unwrap_err().to_string();
        assert!(err.contains("empty"));
    }

    #[test]
    fn test_new_rejects_whitespace_api_key() {
        let result = OpenAiProvider::new("   ".to_string());
        assert!(result.is_err(), "expected whitespace API key to fail");
    }

    #[test]
    fn test_new_accepts_valid_api_key() {
        let result = OpenAiProvider::new("sk-valid-key-1234567890".to_string());
        assert!(result.is_ok(), "expected valid API key to pass");
    }

    #[test]
    fn test_default_base_url() {
        let provider = OpenAiProvider::new("test-key".to_string()).unwrap();
        assert_eq!(provider.base_url, "https://api.openai.com");
    }

    #[test]
    fn test_custom_base_url_accepted() {
        let provider = OpenAiProvider::new("test-key".to_string())
            .unwrap()
            .with_base_url("https://proxy.example.com".to_string())
            .unwrap();
        assert_eq!(provider.base_url, "https://proxy.example.com");
    }

    #[test]
    fn test_custom_base_url_trailing_slash_stripped() {
        let provider = OpenAiProvider::new("test-key".to_string())
            .unwrap()
            .with_base_url("https://proxy.example.com/".to_string())
            .unwrap();
        assert_eq!(provider.base_url, "https://proxy.example.com");
    }

    #[test]
    fn test_base_url_rejects_http() {
        let result = OpenAiProvider::new("test-key".to_string())
            .unwrap()
            .with_base_url("http://insecure.example.com".to_string());
        assert!(result.is_err(), "expected http base URL to fail");
        let err = result.unwrap_err().to_string();
        assert!(err.contains("https"), "got: {err}");
        assert!(err.contains("or http for localhost"), "got: {err}");
    }

    #[test]
    fn test_base_url_allows_http_localhost() {
        let provider = OpenAiProvider::new("test-key".to_string())
            .unwrap()
            .with_base_url("http://localhost:8000/v1".to_string())
            .unwrap();
        assert_eq!(provider.base_url, "http://localhost:8000/v1");
    }

    #[test]
    fn test_base_url_allows_http_127() {
        let provider = OpenAiProvider::new("test-key".to_string())
            .unwrap()
            .with_base_url("http://127.0.0.1:8000/v1".to_string())
            .unwrap();
        assert_eq!(provider.base_url, "http://127.0.0.1:8000/v1");
    }

    #[test]
    fn test_base_url_rejects_http_remote() {
        let result = OpenAiProvider::new("test-key".to_string())
            .unwrap()
            .with_base_url("http://192.168.1.100:8000".to_string());
        assert!(result.is_err(), "expected remote http base URL to fail");
        let err = result.unwrap_err().to_string();
        assert!(err.contains("https"), "got: {err}");
    }

    #[test]
    fn test_base_url_rejects_invalid_url() {
        let result = OpenAiProvider::new("test-key".to_string())
            .unwrap()
            .with_base_url("not-a-url".to_string());
        assert!(result.is_err(), "expected malformed base URL to fail");
    }

    // ==================== is_openai_model tests ====================

    #[test]
    fn test_is_openai_model() {
        assert!(is_openai_model("gpt-4o"));
        assert!(is_openai_model("gpt-4-turbo"));
        assert!(is_openai_model("gpt-3.5-turbo"));
        assert!(is_openai_model("GPT-4o")); // case insensitive
        assert!(is_openai_model("o1-preview"));
        assert!(is_openai_model("o1-mini"));
        assert!(is_openai_model("o3-mini"));
        assert!(is_openai_model("chatgpt-4o-latest"));

        assert!(!is_openai_model("claude-sonnet-4-20250514"));
        assert!(!is_openai_model("claude-3-opus"));
        assert!(!is_openai_model("some-other-model"));
    }
}
