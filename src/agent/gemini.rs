//! Google Gemini API provider.
//!
//! Streams completions from the Gemini `v1beta/models/{model}:streamGenerateContent`
//! endpoint using Server-Sent Events (SSE).

use async_trait::async_trait;
use futures_util::StreamExt;
use serde_json::{json, Value};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::agent::provider::*;
use crate::agent::AgentError;

/// Google Gemini API provider.
#[derive(Debug)]
pub struct GeminiProvider {
    client: reqwest::Client,
    api_key: String,
    base_url: String,
}

impl GeminiProvider {
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
            base_url: "https://generativelanguage.googleapis.com".to_string(),
        })
    }

    pub fn with_base_url(mut self, url: String) -> Result<Self, AgentError> {
        let parsed = url::Url::parse(&url)
            .map_err(|e| AgentError::InvalidBaseUrl(format!("invalid URL \"{url}\": {e}")))?;
        if parsed.scheme() != "https" {
            return Err(AgentError::InvalidBaseUrl(format!(
                "base URL must use https scheme, got \"{}\"",
                parsed.scheme()
            )));
        }
        // Strip trailing slash for consistent path joining
        self.base_url = url.trim_end_matches('/').to_string();
        Ok(self)
    }

    /// Build the JSON body for the Gemini streamGenerateContent API.
    fn build_body(&self, request: &CompletionRequest) -> Value {
        let mut body = json!({});

        // System instruction
        if let Some(ref system) = request.system {
            body["system_instruction"] = json!({
                "parts": [{ "text": system }]
            });
        }

        // Convert LlmMessages to Gemini contents format
        let mut contents: Vec<Value> = Vec::new();

        for msg in &request.messages {
            let role = match msg.role {
                LlmRole::User => "user",
                LlmRole::Assistant => "model",
            };

            let mut parts: Vec<Value> = Vec::new();

            for block in &msg.content {
                match block {
                    ContentBlock::Text { text } => {
                        parts.push(json!({ "text": text }));
                    }
                    ContentBlock::ToolUse { id: _, name, input } => {
                        parts.push(json!({
                            "functionCall": {
                                "name": name,
                                "args": input,
                            }
                        }));
                    }
                    ContentBlock::ToolResult {
                        tool_use_id: _,
                        content,
                        is_error: _,
                    } => {
                        // For tool results, we need to look up the tool name.
                        // Gemini uses functionResponse with name and response.
                        // We look backwards through messages to find the matching tool use name.
                        let tool_name = find_tool_name_for_result(&request.messages, block);
                        parts.push(json!({
                            "functionResponse": {
                                "name": tool_name,
                                "response": {
                                    "result": content,
                                }
                            }
                        }));
                    }
                }
            }

            if !parts.is_empty() {
                contents.push(json!({
                    "role": role,
                    "parts": parts,
                }));
            }
        }

        body["contents"] = json!(contents);

        // Tools (function declarations)
        if !request.tools.is_empty() {
            let function_declarations: Vec<Value> = request
                .tools
                .iter()
                .map(|t| {
                    json!({
                        "name": t.name,
                        "description": t.description,
                        "parameters": t.input_schema,
                    })
                })
                .collect();
            body["tools"] = json!([{
                "function_declarations": function_declarations,
            }]);
        }

        // Generation config
        let mut generation_config = json!({
            "maxOutputTokens": request.max_tokens,
        });
        if let Some(temp) = request.temperature {
            generation_config["temperature"] = json!(temp);
        }
        body["generationConfig"] = generation_config;

        body
    }
}

/// Find the tool name that corresponds to a ToolResult block by searching
/// backwards through the messages for a matching ToolUse with the same ID.
fn find_tool_name_for_result(messages: &[LlmMessage], block: &ContentBlock) -> String {
    let target_id = match block {
        ContentBlock::ToolResult { tool_use_id, .. } => tool_use_id,
        _ => return "unknown".to_string(),
    };

    for msg in messages.iter().rev() {
        for b in &msg.content {
            if let ContentBlock::ToolUse { id, name, .. } = b {
                if id == target_id {
                    return name.clone();
                }
            }
        }
    }

    "unknown".to_string()
}

#[async_trait]
impl LlmProvider for GeminiProvider {
    async fn complete(
        &self,
        request: CompletionRequest,
        cancel_token: CancellationToken,
    ) -> Result<mpsc::Receiver<StreamEvent>, AgentError> {
        if cancel_token.is_cancelled() {
            return Err(AgentError::Cancelled);
        }
        let body = self.build_body(&request);

        // Strip any prefix (gemini/, models/) to get the bare model name for the URL
        let model_name = strip_gemini_prefix(&request.model);
        let url = format!(
            "{}/v1beta/models/{}:streamGenerateContent?alt=sse",
            self.base_url, model_name
        );

        let response = tokio::select! {
            _ = cancel_token.cancelled() => {
                return Err(AgentError::Cancelled);
            }
            response = self
                .client
                .post(&url)
                .header("x-goog-api-key", &self.api_key)
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
            if let Err(e) = process_gemini_sse_stream(stream, &tx, &cancel).await {
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

/// Maximum SSE line buffer size (1 MB). If a single SSE line exceeds this,
/// the stream is treated as corrupted to prevent unbounded memory growth.
const MAX_SSE_BUFFER_BYTES: usize = 1_048_576;

/// Process a Gemini SSE byte stream into StreamEvents.
async fn process_gemini_sse_stream<S>(
    mut stream: S,
    tx: &mpsc::Sender<StreamEvent>,
    cancel_token: &CancellationToken,
) -> Result<(), String>
where
    S: futures_util::Stream<Item = Result<bytes::Bytes, reqwest::Error>> + Unpin,
{
    let mut buffer = String::new();
    let mut accumulated_usage = TokenUsage::default();
    let mut last_finish_reason: Option<String> = None;

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
                if let Some(events) =
                    parse_gemini_sse_data(data, &mut accumulated_usage, &mut last_finish_reason)
                {
                    for event in events {
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
            }
            // Ignore empty lines, comments, and event: lines
        }
        // Remove consumed bytes in one operation
        if consumed > 0 {
            buffer.drain(..consumed);
        }
    }

    // Gemini streams don't use a [DONE] sentinel; the stream simply ends.
    // If we haven't sent a Stop event yet, send one now.
    let reason = match last_finish_reason.as_deref() {
        Some("MAX_TOKENS") => StopReason::MaxTokens,
        Some("STOP") => StopReason::EndTurn,
        _ => StopReason::EndTurn,
    };

    let _ = tx
        .send(StreamEvent::Stop {
            reason,
            usage: accumulated_usage,
        })
        .await;

    Ok(())
}

/// Parse a single SSE data payload from Gemini's streaming format.
///
/// Gemini streaming chunks look like:
/// ```json
/// {"candidates":[{"content":{"parts":[{"text":"Hello"}],"role":"model"},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":10,"candidatesTokenCount":5}}
/// ```
///
/// Returns a Vec of StreamEvents since a single chunk can contain both text
/// and function calls in the parts array.
fn parse_gemini_sse_data(
    data: &str,
    accumulated_usage: &mut TokenUsage,
    last_finish_reason: &mut Option<String>,
) -> Option<Vec<StreamEvent>> {
    let parsed: Value = serde_json::from_str(data).ok()?;

    // Check for error response
    if let Some(error) = parsed.get("error") {
        let message = error
            .get("message")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown API error")
            .to_string();
        return Some(vec![StreamEvent::Error { message }]);
    }

    // Extract usage metadata if present
    extract_gemini_usage(&parsed, accumulated_usage);

    // Process candidates
    let candidates = parsed.get("candidates")?.as_array()?;
    if candidates.is_empty() {
        return None;
    }

    let candidate = &candidates[0];

    // Check for finish reason
    if let Some(finish_reason) = candidate.get("finishReason").and_then(|v| v.as_str()) {
        *last_finish_reason = Some(finish_reason.to_string());
        return Some(parse_gemini_finish_chunk(
            candidate,
            finish_reason,
            accumulated_usage,
        ));
    }

    // No finish reason — process content parts
    let parts = candidate
        .get("content")
        .and_then(|c| c.get("parts"))
        .and_then(|p| p.as_array())?;

    let events = collect_gemini_part_events(parts);
    if events.is_empty() {
        None
    } else {
        Some(events)
    }
}

/// Extract usage metadata from a Gemini SSE chunk.
fn extract_gemini_usage(parsed: &Value, accumulated_usage: &mut TokenUsage) {
    if let Some(usage_meta) = parsed.get("usageMetadata") {
        if let Some(prompt_tokens) = usage_meta.get("promptTokenCount").and_then(|v| v.as_u64()) {
            accumulated_usage.input_tokens = prompt_tokens;
        }
        if let Some(candidates_tokens) = usage_meta
            .get("candidatesTokenCount")
            .and_then(|v| v.as_u64())
        {
            accumulated_usage.output_tokens = candidates_tokens;
        }
    }
}

/// Parse a Gemini chunk that includes a finish reason.
fn parse_gemini_finish_chunk(
    candidate: &Value,
    finish_reason: &str,
    accumulated_usage: &TokenUsage,
) -> Vec<StreamEvent> {
    let reason = match finish_reason {
        "STOP" => StopReason::EndTurn,
        "MAX_TOKENS" => StopReason::MaxTokens,
        "SAFETY" => StopReason::EndTurn,
        _ => StopReason::EndTurn,
    };

    let parts = candidate
        .get("content")
        .and_then(|c| c.get("parts"))
        .and_then(|p| p.as_array());

    let mut events = Vec::new();

    if let Some(parts) = parts {
        let has_function_call = parts.iter().any(|p| p.get("functionCall").is_some());
        events.extend(collect_gemini_part_events(parts));

        let stop_reason = if has_function_call {
            StopReason::ToolUse
        } else {
            reason
        };
        events.push(StreamEvent::Stop {
            reason: stop_reason,
            usage: *accumulated_usage,
        });
    } else {
        events.push(StreamEvent::Stop {
            reason,
            usage: *accumulated_usage,
        });
    }

    events
}

/// Collect stream events from Gemini content parts (text deltas and function calls).
fn collect_gemini_part_events(parts: &[Value]) -> Vec<StreamEvent> {
    let mut events = Vec::new();
    for part in parts {
        if let Some(text) = part.get("text").and_then(|v| v.as_str()) {
            if !text.is_empty() {
                events.push(StreamEvent::TextDelta {
                    text: text.to_string(),
                });
            }
        }
        if let Some(fc) = part.get("functionCall") {
            let name = fc
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let args = fc.get("args").cloned().unwrap_or(json!({}));
            let id = uuid::Uuid::new_v4().to_string();
            events.push(StreamEvent::ToolUse {
                id,
                name,
                input: args,
            });
        }
    }
    events
}

/// Determine whether a model identifier should route to the Gemini provider.
pub fn is_gemini_model(model: &str) -> bool {
    let lower = model.to_lowercase();
    lower.starts_with("gemini-")
        || lower.starts_with("gemini/")
        || lower.starts_with("models/gemini-")
}

/// Strip the `gemini/` or `models/gemini-` prefix from a model name.
///
/// Returns the bare model name suitable for passing to the Gemini API.
/// The API expects model names like `gemini-2.0-flash` (without `models/` prefix).
/// If the model doesn't have a prefix, it is returned unchanged.
pub fn strip_gemini_prefix(model: &str) -> &str {
    if let Some(rest) = model.strip_prefix("gemini/") {
        rest
    } else if let Some(rest) = model.strip_prefix("Gemini/") {
        rest
    } else if let Some(rest) = model.strip_prefix("models/") {
        rest
    } else {
        model
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== Provider construction tests ====================

    #[test]
    fn test_new_rejects_empty_api_key() {
        let result = GeminiProvider::new("".to_string());
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("empty"));
    }

    #[test]
    fn test_new_rejects_whitespace_api_key() {
        let result = GeminiProvider::new("   ".to_string());
        assert!(result.is_err());
    }

    #[test]
    fn test_new_accepts_valid_api_key() {
        let result = GeminiProvider::new("AIzaSyA-valid-key-1234567890".to_string());
        assert!(result.is_ok());
    }

    #[test]
    fn test_default_base_url() {
        let provider = GeminiProvider::new("test-key".to_string()).unwrap();
        assert_eq!(
            provider.base_url,
            "https://generativelanguage.googleapis.com"
        );
    }

    #[test]
    fn test_custom_base_url_accepted() {
        let provider = GeminiProvider::new("test-key".to_string())
            .unwrap()
            .with_base_url("https://proxy.example.com".to_string())
            .unwrap();
        assert_eq!(provider.base_url, "https://proxy.example.com");
    }

    #[test]
    fn test_custom_base_url_trailing_slash_stripped() {
        let provider = GeminiProvider::new("test-key".to_string())
            .unwrap()
            .with_base_url("https://proxy.example.com/".to_string())
            .unwrap();
        assert_eq!(provider.base_url, "https://proxy.example.com");
    }

    #[test]
    fn test_base_url_rejects_http() {
        let result = GeminiProvider::new("test-key".to_string())
            .unwrap()
            .with_base_url("http://insecure.example.com".to_string());
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("https"));
    }

    #[test]
    fn test_base_url_rejects_invalid_url() {
        let result = GeminiProvider::new("test-key".to_string())
            .unwrap()
            .with_base_url("not-a-url".to_string());
        assert!(result.is_err());
    }

    // ==================== build_body tests ====================

    #[test]
    fn test_build_body_basic() {
        let provider = GeminiProvider::new("test-key".to_string()).unwrap();
        let request = CompletionRequest {
            model: "gemini-2.0-flash".to_string(),
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

        // System instruction
        assert_eq!(
            body["system_instruction"]["parts"][0]["text"],
            "You are helpful."
        );

        // Contents
        let contents = body["contents"].as_array().unwrap();
        assert_eq!(contents.len(), 1);
        assert_eq!(contents[0]["role"], "user");
        assert_eq!(contents[0]["parts"][0]["text"], "Hello");

        // Generation config
        assert_eq!(body["generationConfig"]["maxOutputTokens"], 1024);
        assert_eq!(body["generationConfig"]["temperature"], 0.7);

        // No tools key when tools is empty
        assert!(body.get("tools").is_none());
    }

    #[test]
    fn test_build_body_no_system() {
        let provider = GeminiProvider::new("test-key".to_string()).unwrap();
        let request = CompletionRequest {
            model: "gemini-2.0-flash".to_string(),
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

        // No system_instruction
        assert!(body.get("system_instruction").is_none());

        // Contents
        let contents = body["contents"].as_array().unwrap();
        assert_eq!(contents.len(), 1);
        assert_eq!(contents[0]["role"], "user");

        // No temperature in generation config
        assert!(body["generationConfig"].get("temperature").is_none());
    }

    #[test]
    fn test_build_body_with_tools() {
        let provider = GeminiProvider::new("test-key".to_string()).unwrap();
        let request = CompletionRequest {
            model: "gemini-2.0-flash".to_string(),
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
        let func_decls = tools[0]["function_declarations"].as_array().unwrap();
        assert_eq!(func_decls.len(), 1);
        assert_eq!(func_decls[0]["name"], "get_weather");
        assert_eq!(func_decls[0]["description"], "Get weather for a city");
        assert!(func_decls[0]["parameters"]["properties"]["city"].is_object());
    }

    #[test]
    fn test_build_body_with_tool_results() {
        let provider = GeminiProvider::new("test-key".to_string()).unwrap();
        let request = CompletionRequest {
            model: "gemini-2.0-flash".to_string(),
            messages: vec![
                LlmMessage {
                    role: LlmRole::User,
                    content: vec![ContentBlock::Text {
                        text: "What's the weather?".to_string(),
                    }],
                },
                LlmMessage {
                    role: LlmRole::Assistant,
                    content: vec![ContentBlock::ToolUse {
                        id: "call_abc123".to_string(),
                        name: "get_weather".to_string(),
                        input: json!({"city": "SF"}),
                    }],
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
        let contents = body["contents"].as_array().unwrap();
        assert_eq!(contents.len(), 3);

        // User message
        assert_eq!(contents[0]["role"], "user");
        assert_eq!(contents[0]["parts"][0]["text"], "What's the weather?");

        // Model message with functionCall
        assert_eq!(contents[1]["role"], "model");
        assert_eq!(
            contents[1]["parts"][0]["functionCall"]["name"],
            "get_weather"
        );
        assert_eq!(
            contents[1]["parts"][0]["functionCall"]["args"]["city"],
            "SF"
        );

        // User message with functionResponse
        assert_eq!(contents[2]["role"], "user");
        assert_eq!(
            contents[2]["parts"][0]["functionResponse"]["name"],
            "get_weather"
        );
        assert_eq!(
            contents[2]["parts"][0]["functionResponse"]["response"]["result"],
            "72F and sunny"
        );
    }

    #[test]
    fn test_build_body_multi_turn() {
        let provider = GeminiProvider::new("test-key".to_string()).unwrap();
        let request = CompletionRequest {
            model: "gemini-2.0-flash".to_string(),
            messages: vec![
                LlmMessage {
                    role: LlmRole::User,
                    content: vec![ContentBlock::Text {
                        text: "Hello".to_string(),
                    }],
                },
                LlmMessage {
                    role: LlmRole::Assistant,
                    content: vec![ContentBlock::Text {
                        text: "Hi there!".to_string(),
                    }],
                },
                LlmMessage {
                    role: LlmRole::User,
                    content: vec![ContentBlock::Text {
                        text: "How are you?".to_string(),
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
        let contents = body["contents"].as_array().unwrap();
        assert_eq!(contents.len(), 3);
        assert_eq!(contents[0]["role"], "user");
        assert_eq!(contents[0]["parts"][0]["text"], "Hello");
        assert_eq!(contents[1]["role"], "model");
        assert_eq!(contents[1]["parts"][0]["text"], "Hi there!");
        assert_eq!(contents[2]["role"], "user");
        assert_eq!(contents[2]["parts"][0]["text"], "How are you?");
    }

    #[test]
    fn test_build_body_assistant_role_mapped_to_model() {
        let provider = GeminiProvider::new("test-key".to_string()).unwrap();
        let request = CompletionRequest {
            model: "gemini-2.0-flash".to_string(),
            messages: vec![LlmMessage {
                role: LlmRole::Assistant,
                content: vec![ContentBlock::Text {
                    text: "I am a model response.".to_string(),
                }],
            }],
            system: None,
            tools: vec![],
            max_tokens: 1024,
            temperature: None,
            extra: None,
        };
        let body = provider.build_body(&request);
        let contents = body["contents"].as_array().unwrap();
        assert_eq!(contents[0]["role"], "model");
    }

    // ==================== SSE parsing tests ====================

    #[test]
    fn test_parse_text_delta() {
        let mut usage = TokenUsage::default();
        let mut finish_reason = None;
        let events = parse_gemini_sse_data(
            r#"{"candidates":[{"content":{"parts":[{"text":"Hello"}],"role":"model"}}]}"#,
            &mut usage,
            &mut finish_reason,
        );
        let events = events.unwrap();
        assert_eq!(events.len(), 1);
        match &events[0] {
            StreamEvent::TextDelta { text } => assert_eq!(text, "Hello"),
            other => panic!("expected TextDelta, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_tool_call() {
        let mut usage = TokenUsage::default();
        let mut finish_reason = None;
        let events = parse_gemini_sse_data(
            r#"{"candidates":[{"content":{"parts":[{"functionCall":{"name":"get_weather","args":{"city":"SF"}}}],"role":"model"}}]}"#,
            &mut usage,
            &mut finish_reason,
        );
        let events = events.unwrap();
        assert_eq!(events.len(), 1);
        match &events[0] {
            StreamEvent::ToolUse { name, input, id } => {
                assert_eq!(name, "get_weather");
                assert_eq!(input["city"], "SF");
                // ID should be a valid UUID
                assert!(!id.is_empty());
                assert!(uuid::Uuid::parse_str(id).is_ok());
            }
            other => panic!("expected ToolUse, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_stop_reason_end_turn() {
        let mut usage = TokenUsage {
            input_tokens: 100,
            output_tokens: 42,
        };
        let mut finish_reason = None;
        let events = parse_gemini_sse_data(
            r#"{"candidates":[{"content":{"parts":[{"text":"Done."}],"role":"model"},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":100,"candidatesTokenCount":42}}"#,
            &mut usage,
            &mut finish_reason,
        );
        let events = events.unwrap();
        // Should have TextDelta + Stop
        assert!(events.len() >= 2);
        match &events[events.len() - 1] {
            StreamEvent::Stop { reason, usage } => {
                assert_eq!(*reason, StopReason::EndTurn);
                assert_eq!(usage.input_tokens, 100);
                assert_eq!(usage.output_tokens, 42);
            }
            other => panic!("expected Stop, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_stop_reason_max_tokens() {
        let mut usage = TokenUsage::default();
        let mut finish_reason = None;
        let events = parse_gemini_sse_data(
            r#"{"candidates":[{"content":{"parts":[{"text":"truncated"}],"role":"model"},"finishReason":"MAX_TOKENS"}]}"#,
            &mut usage,
            &mut finish_reason,
        );
        let events = events.unwrap();
        let stop = events
            .iter()
            .find(|e| matches!(e, StreamEvent::Stop { .. }));
        match stop {
            Some(StreamEvent::Stop { reason, .. }) => {
                assert_eq!(*reason, StopReason::MaxTokens);
            }
            other => panic!("expected Stop with MaxTokens, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_stop_reason_safety() {
        let mut usage = TokenUsage::default();
        let mut finish_reason = None;
        let events = parse_gemini_sse_data(
            r#"{"candidates":[{"finishReason":"SAFETY"}]}"#,
            &mut usage,
            &mut finish_reason,
        );
        let events = events.unwrap();
        match &events[0] {
            StreamEvent::Stop { reason, .. } => {
                assert_eq!(*reason, StopReason::EndTurn);
            }
            other => panic!("expected Stop, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_usage_extraction() {
        let mut usage = TokenUsage::default();
        let mut finish_reason = None;
        parse_gemini_sse_data(
            r#"{"candidates":[{"content":{"parts":[{"text":"Hi"}],"role":"model"}}],"usageMetadata":{"promptTokenCount":150,"candidatesTokenCount":42,"totalTokenCount":192}}"#,
            &mut usage,
            &mut finish_reason,
        );
        assert_eq!(usage.input_tokens, 150);
        assert_eq!(usage.output_tokens, 42);
    }

    #[test]
    fn test_parse_error_response() {
        let mut usage = TokenUsage::default();
        let mut finish_reason = None;
        let events = parse_gemini_sse_data(
            r#"{"error":{"message":"API key not valid","status":"INVALID_ARGUMENT","code":400}}"#,
            &mut usage,
            &mut finish_reason,
        );
        let events = events.unwrap();
        assert_eq!(events.len(), 1);
        match &events[0] {
            StreamEvent::Error { message } => {
                assert_eq!(message, "API key not valid");
            }
            other => panic!("expected Error, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_invalid_json_returns_none() {
        let mut usage = TokenUsage::default();
        let mut finish_reason = None;
        let events = parse_gemini_sse_data("not valid json", &mut usage, &mut finish_reason);
        assert!(events.is_none());
    }

    #[test]
    fn test_parse_empty_candidates_returns_none() {
        let mut usage = TokenUsage::default();
        let mut finish_reason = None;
        let events = parse_gemini_sse_data(r#"{"candidates":[]}"#, &mut usage, &mut finish_reason);
        assert!(events.is_none());
    }

    #[test]
    fn test_parse_function_call_with_finish_reason() {
        let mut usage = TokenUsage::default();
        let mut finish_reason = None;
        let events = parse_gemini_sse_data(
            r#"{"candidates":[{"content":{"parts":[{"functionCall":{"name":"search","args":{"q":"test"}}}],"role":"model"},"finishReason":"STOP"}]}"#,
            &mut usage,
            &mut finish_reason,
        );
        let events = events.unwrap();
        // Should have ToolUse + Stop (with ToolUse reason since there are function calls)
        assert!(events.len() >= 2);
        match &events[0] {
            StreamEvent::ToolUse { name, input, .. } => {
                assert_eq!(name, "search");
                assert_eq!(input["q"], "test");
            }
            other => panic!("expected ToolUse, got {other:?}"),
        }
        match &events[events.len() - 1] {
            StreamEvent::Stop { reason, .. } => {
                assert_eq!(*reason, StopReason::ToolUse);
            }
            other => panic!("expected Stop with ToolUse reason, got {other:?}"),
        }
    }

    // ==================== is_gemini_model tests ====================

    #[test]
    fn test_is_gemini_model() {
        assert!(is_gemini_model("gemini-2.0-flash"));
        assert!(is_gemini_model("gemini-1.5-pro"));
        assert!(is_gemini_model("gemini-1.5-flash"));
        assert!(is_gemini_model("Gemini-2.0-flash")); // case insensitive
        assert!(is_gemini_model("GEMINI-2.0-FLASH")); // case insensitive

        assert!(is_gemini_model("gemini/gemini-2.0-flash"));
        assert!(is_gemini_model("models/gemini-2.0-flash"));

        assert!(!is_gemini_model("gpt-4o"));
        assert!(!is_gemini_model("claude-sonnet-4-20250514"));
        assert!(!is_gemini_model("some-other-model"));
        assert!(!is_gemini_model("ollama:llama3"));
    }

    // ==================== strip_gemini_prefix tests ====================

    #[test]
    fn test_strip_gemini_slash_prefix() {
        assert_eq!(
            strip_gemini_prefix("gemini/gemini-2.0-flash"),
            "gemini-2.0-flash"
        );
    }

    #[test]
    fn test_strip_models_prefix() {
        assert_eq!(
            strip_gemini_prefix("models/gemini-2.0-flash"),
            "gemini-2.0-flash"
        );
    }

    #[test]
    fn test_strip_no_prefix_returns_unchanged() {
        assert_eq!(strip_gemini_prefix("gemini-2.0-flash"), "gemini-2.0-flash");
    }

    #[test]
    fn test_strip_case_variant() {
        assert_eq!(
            strip_gemini_prefix("Gemini/gemini-2.0-flash"),
            "gemini-2.0-flash"
        );
    }

    // ==================== Integration-style stream processing tests ====================

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
            "data: {\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"Hello\"}],\"role\":\"model\"}}]}\n\n",
            "data: {\"candidates\":[{\"content\":{\"parts\":[{\"text\":\" world\"}],\"role\":\"model\"}}]}\n\n",
            "data: {\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"!\"}],\"role\":\"model\"},\"finishReason\":\"STOP\"}],\"usageMetadata\":{\"promptTokenCount\":10,\"candidatesTokenCount\":5}}\n\n",
        );

        let stream = mock_sse_stream(vec![sse_data]);
        let (tx, mut rx) = mpsc::channel(64);

        let result = process_gemini_sse_stream(stream, &tx, &CancellationToken::new()).await;
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
        let sse_data = "data: {\"candidates\":[{\"content\":{\"parts\":[{\"functionCall\":{\"name\":\"get_weather\",\"args\":{\"city\":\"SF\"}}}],\"role\":\"model\"},\"finishReason\":\"STOP\"}],\"usageMetadata\":{\"promptTokenCount\":20,\"candidatesTokenCount\":10}}\n\n";

        let stream = mock_sse_stream(vec![sse_data]);
        let (tx, mut rx) = mpsc::channel(64);

        let result = process_gemini_sse_stream(stream, &tx, &CancellationToken::new()).await;
        assert!(result.is_ok(), "expected Ok, got: {:?}", result);

        let mut events = Vec::new();
        while let Ok(event) = rx.try_recv() {
            events.push(event);
        }

        // Should have ToolUse and Stop
        assert!(
            events.iter().any(|e| matches!(
                e,
                StreamEvent::ToolUse { name, .. }
                if name == "get_weather"
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
    async fn test_stream_ends_without_finish_reason_sends_stop() {
        // Stream ends without a finishReason in any chunk — should still emit Stop
        let sse_data = "data: {\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"Hello\"}],\"role\":\"model\"}}]}\n\n";

        let stream = mock_sse_stream(vec![sse_data]);
        let (tx, mut rx) = mpsc::channel(64);

        let result = process_gemini_sse_stream(stream, &tx, &CancellationToken::new()).await;
        assert!(result.is_ok(), "expected Ok, got: {:?}", result);

        let mut events = Vec::new();
        while let Ok(event) = rx.try_recv() {
            events.push(event);
        }

        // Should have TextDelta and a Stop event added by the stream end handler
        assert!(
            events
                .iter()
                .any(|e| matches!(e, StreamEvent::TextDelta { text } if text == "Hello")),
            "expected TextDelta 'Hello', got: {:?}",
            events,
        );
        assert!(
            events.iter().any(|e| matches!(e, StreamEvent::Stop { .. })),
            "expected Stop event, got: {:?}",
            events,
        );
    }

    #[tokio::test]
    async fn test_error_in_stream_sends_error_event() {
        let sse_data = "data: {\"error\":{\"message\":\"Quota exceeded\",\"status\":\"RESOURCE_EXHAUSTED\",\"code\":429}}\n\n";

        let stream = mock_sse_stream(vec![sse_data]);
        let (tx, mut rx) = mpsc::channel(64);

        let result = process_gemini_sse_stream(stream, &tx, &CancellationToken::new()).await;
        assert!(result.is_ok());

        let mut events = Vec::new();
        while let Ok(event) = rx.try_recv() {
            events.push(event);
        }

        assert!(
            events.iter().any(|e| matches!(
                e,
                StreamEvent::Error { message }
                if message == "Quota exceeded"
            )),
            "expected Error event, got: {:?}",
            events,
        );
    }
}
