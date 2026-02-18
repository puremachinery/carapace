//! Anthropic Messages API provider.
//!
//! Streams completions from the Anthropic `/v1/messages` endpoint using
//! Server-Sent Events (SSE).

use async_trait::async_trait;
use futures_util::StreamExt;
use serde_json::{json, Value};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::agent::provider::*;
use crate::agent::AgentError;

/// Anthropic Messages API provider.
#[derive(Debug)]
pub struct AnthropicProvider {
    client: reqwest::Client,
    api_key: String,
    base_url: String,
}

impl AnthropicProvider {
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
            base_url: "https://api.anthropic.com".to_string(),
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

    /// Build the JSON body for the Anthropic Messages API.
    fn build_body(&self, request: &CompletionRequest) -> Value {
        let messages: Vec<Value> = request
            .messages
            .iter()
            .map(|msg| {
                let role = match msg.role {
                    LlmRole::User => "user",
                    LlmRole::Assistant => "assistant",
                };
                let content: Vec<Value> = msg
                    .content
                    .iter()
                    .map(|block| match block {
                        ContentBlock::Text { text } => json!({
                            "type": "text",
                            "text": text,
                        }),
                        ContentBlock::ToolUse { id, name, input } => json!({
                            "type": "tool_use",
                            "id": id,
                            "name": name,
                            "input": input,
                        }),
                        ContentBlock::ToolResult {
                            tool_use_id,
                            content,
                            is_error,
                        } => json!({
                            "type": "tool_result",
                            "tool_use_id": tool_use_id,
                            "content": content,
                            "is_error": is_error,
                        }),
                    })
                    .collect();
                json!({
                    "role": role,
                    "content": content,
                })
            })
            .collect();

        let mut body = json!({
            "model": request.model,
            "messages": messages,
            "max_tokens": request.max_tokens,
            "stream": true,
        });

        if let Some(ref system) = request.system {
            body["system"] = json!(system);
        }

        if let Some(temp) = request.temperature {
            body["temperature"] = json!(temp);
        }

        if !request.tools.is_empty() {
            let tools: Vec<Value> = request
                .tools
                .iter()
                .map(|t| {
                    json!({
                        "name": t.name,
                        "description": t.description,
                        "input_schema": t.input_schema,
                    })
                })
                .collect();
            body["tools"] = json!(tools);
        }

        body
    }
}

#[async_trait]
impl LlmProvider for AnthropicProvider {
    async fn complete(
        &self,
        request: CompletionRequest,
        cancel_token: CancellationToken,
    ) -> Result<mpsc::Receiver<StreamEvent>, AgentError> {
        if cancel_token.is_cancelled() {
            return Err(AgentError::Cancelled);
        }
        let body = self.build_body(&request);
        let url = format!("{}/v1/messages", self.base_url);

        let response = tokio::select! {
            _ = cancel_token.cancelled() => {
                return Err(AgentError::Cancelled);
            }
            response = self
                .client
                .post(&url)
                .header("x-api-key", &self.api_key)
                .header("anthropic-version", "2023-06-01")
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

/// Maximum SSE line buffer size (1 MB). If a single SSE line exceeds this,
/// the stream is treated as corrupted to prevent unbounded memory growth.
const MAX_SSE_BUFFER_BYTES: usize = 1_048_576;

/// Process an SSE byte stream into StreamEvents.
async fn process_sse_stream<S>(
    mut stream: S,
    tx: &mpsc::Sender<StreamEvent>,
    cancel_token: &CancellationToken,
) -> Result<(), String>
where
    S: futures_util::Stream<Item = Result<bytes::Bytes, reqwest::Error>> + Unpin,
{
    let mut buffer = String::new();
    let mut event_type = String::new();
    // Accumulated tool call state: index → (id, name, input_json_string)
    let mut tool_calls: std::collections::HashMap<u64, (String, String, String)> =
        std::collections::HashMap::new();
    let mut accumulated_usage = TokenUsage::default();

    let mut got_message_stop = false;

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

        // Process complete lines.
        // We track how far we've consumed to avoid O(n²) re-copying.
        let mut consumed = 0;
        while let Some(rel_pos) = buffer[consumed..].find('\n') {
            let newline_pos = consumed + rel_pos;
            let line = buffer[consumed..newline_pos]
                .trim_end_matches('\r')
                .to_string();
            consumed = newline_pos + 1;

            if let Some(evt) = line.strip_prefix("event: ") {
                event_type = evt.to_string();
            } else if let Some(data) = line.strip_prefix("data: ") {
                if event_type == "message_stop" {
                    got_message_stop = true;
                }
                if let Some(event) =
                    parse_sse_event(&event_type, data, &mut tool_calls, &mut accumulated_usage)
                {
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
            // Ignore empty lines and comments
        }
        // Remove consumed bytes in one operation
        if consumed > 0 {
            buffer.drain(..consumed);
        }
    }

    if got_message_stop {
        Ok(())
    } else {
        Err("stream ended without message_stop event (premature termination)".to_string())
    }
}

/// Parse a single SSE event into a StreamEvent.
fn parse_sse_event(
    event_type: &str,
    data: &str,
    tool_calls: &mut std::collections::HashMap<u64, (String, String, String)>,
    accumulated_usage: &mut TokenUsage,
) -> Option<StreamEvent> {
    let parsed: Value = serde_json::from_str(data).ok()?;

    match event_type {
        "content_block_start" => {
            let index = parsed["index"].as_u64()?;
            let block = &parsed["content_block"];
            if block["type"].as_str() == Some("tool_use") {
                let id = block["id"].as_str().unwrap_or("").to_string();
                let name = block["name"].as_str().unwrap_or("").to_string();
                tool_calls.insert(index, (id, name, String::new()));
            }
            None
        }

        "content_block_delta" => handle_content_block_delta(&parsed, tool_calls),

        "content_block_stop" => handle_content_block_stop(&parsed, tool_calls),

        "message_start" => {
            // Extract input token count from the initial message
            if let Some(input_tokens) = parsed["message"]["usage"]["input_tokens"].as_u64() {
                accumulated_usage.input_tokens = input_tokens;
            }
            None
        }

        "message_delta" => {
            let delta = &parsed["delta"];
            let usage = &parsed["usage"];

            let stop_reason = match delta["stop_reason"].as_str() {
                Some("end_turn") => StopReason::EndTurn,
                Some("tool_use") => StopReason::ToolUse,
                Some("max_tokens") => StopReason::MaxTokens,
                _ => StopReason::EndTurn,
            };

            if let Some(output_tokens) = usage["output_tokens"].as_u64() {
                accumulated_usage.output_tokens = output_tokens;
            }

            Some(StreamEvent::Stop {
                reason: stop_reason,
                usage: *accumulated_usage,
            })
        }

        "error" => {
            let message = parsed["error"]["message"]
                .as_str()
                .or_else(|| parsed["message"].as_str())
                .unwrap_or("unknown API error")
                .to_string();
            Some(StreamEvent::Error { message })
        }

        _ => None,
    }
}

/// Handle a `content_block_delta` SSE event from the Anthropic API.
fn handle_content_block_delta(
    parsed: &Value,
    tool_calls: &mut std::collections::HashMap<u64, (String, String, String)>,
) -> Option<StreamEvent> {
    let index = match parsed["index"].as_u64() {
        Some(i) => i,
        None => {
            tracing::warn!("content_block_delta missing index field, defaulting to 0");
            0
        }
    };
    let delta = &parsed["delta"];

    match delta["type"].as_str() {
        Some("text_delta") => {
            let text = delta["text"].as_str().unwrap_or("").to_string();
            if text.is_empty() {
                None
            } else {
                Some(StreamEvent::TextDelta { text })
            }
        }
        Some("input_json_delta") => {
            if let Some(entry) = tool_calls.get_mut(&index) {
                if let Some(partial) = delta["partial_json"].as_str() {
                    entry.2.push_str(partial);
                }
            }
            None
        }
        _ => None,
    }
}

/// Handle a `content_block_stop` SSE event from the Anthropic API.
fn handle_content_block_stop(
    parsed: &Value,
    tool_calls: &mut std::collections::HashMap<u64, (String, String, String)>,
) -> Option<StreamEvent> {
    let index = match parsed["index"].as_u64() {
        Some(i) => i,
        None => {
            tracing::warn!("content_block_stop missing index field, defaulting to 0");
            0
        }
    };
    if let Some((id, name, input_json)) = tool_calls.remove(&index) {
        let input: Value = serde_json::from_str(&input_json).unwrap_or(json!({}));
        Some(StreamEvent::ToolUse { id, name, input })
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_body_basic() {
        let provider = AnthropicProvider::new("test-key".to_string()).unwrap();
        let request = CompletionRequest {
            model: "claude-sonnet-4-20250514".to_string(),
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
        assert_eq!(body["model"], "claude-sonnet-4-20250514");
        assert_eq!(body["max_tokens"], 1024);
        assert_eq!(body["stream"], true);
        assert_eq!(body["system"], "You are helpful.");
        assert_eq!(body["temperature"], 0.7);
        assert!(body.get("tools").is_none());
    }

    #[test]
    fn test_build_body_with_tools() {
        let provider = AnthropicProvider::new("test-key".to_string()).unwrap();
        let request = CompletionRequest {
            model: "claude-sonnet-4-20250514".to_string(),
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
        assert_eq!(body["tools"][0]["name"], "get_weather");
        assert!(body.get("temperature").is_none());
        assert!(body.get("system").is_none());
    }

    #[test]
    fn test_parse_text_delta() {
        let mut tool_calls = std::collections::HashMap::new();
        let mut usage = TokenUsage::default();
        let event = parse_sse_event(
            "content_block_delta",
            r#"{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hello"}}"#,
            &mut tool_calls,
            &mut usage,
        );
        match event {
            Some(StreamEvent::TextDelta { text }) => assert_eq!(text, "Hello"),
            other => panic!("expected TextDelta, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_tool_use_sequence() {
        let mut tool_calls = std::collections::HashMap::new();
        let mut usage = TokenUsage::default();

        // content_block_start with tool_use
        parse_sse_event(
            "content_block_start",
            r#"{"index":0,"content_block":{"type":"tool_use","id":"toolu_123","name":"get_weather"}}"#,
            &mut tool_calls,
            &mut usage,
        );
        assert!(tool_calls.contains_key(&0));

        // input_json_delta
        parse_sse_event(
            "content_block_delta",
            r#"{"index":0,"delta":{"type":"input_json_delta","partial_json":"{\"city\":\"SF\"}"}}"#,
            &mut tool_calls,
            &mut usage,
        );

        // content_block_stop emits ToolUse
        let event = parse_sse_event(
            "content_block_stop",
            r#"{"index":0}"#,
            &mut tool_calls,
            &mut usage,
        );
        match event {
            Some(StreamEvent::ToolUse { id, name, input }) => {
                assert_eq!(id, "toolu_123");
                assert_eq!(name, "get_weather");
                assert_eq!(input["city"], "SF");
            }
            other => panic!("expected ToolUse, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_message_delta_stop() {
        let mut tool_calls = std::collections::HashMap::new();
        let mut usage = TokenUsage {
            input_tokens: 100,
            output_tokens: 0,
        };
        let event = parse_sse_event(
            "message_delta",
            r#"{"delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":42}}"#,
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
    fn test_parse_error_event() {
        let mut tool_calls = std::collections::HashMap::new();
        let mut usage = TokenUsage::default();
        let event = parse_sse_event(
            "error",
            r#"{"error":{"type":"overloaded_error","message":"Overloaded"}}"#,
            &mut tool_calls,
            &mut usage,
        );
        match event {
            Some(StreamEvent::Error { message }) => assert_eq!(message, "Overloaded"),
            other => panic!("expected Error, got {other:?}"),
        }
    }

    #[test]
    fn test_new_rejects_empty_api_key() {
        let result = AnthropicProvider::new("".to_string());
        assert!(result.is_err(), "expected empty API key to fail");
        let err = result.unwrap_err().to_string();
        assert!(err.contains("empty"), "got: {err}");
    }

    #[test]
    fn test_new_rejects_whitespace_api_key() {
        let result = AnthropicProvider::new("   ".to_string());
        assert!(result.is_err(), "expected whitespace API key to fail");
    }

    #[test]
    fn test_new_accepts_valid_api_key() {
        let result = AnthropicProvider::new("sk-ant-valid-key".to_string());
        assert!(result.is_ok(), "expected valid API key to pass");
    }

    #[test]
    fn test_parse_message_start_captures_input_tokens() {
        let mut tool_calls = std::collections::HashMap::new();
        let mut usage = TokenUsage::default();
        parse_sse_event(
            "message_start",
            r#"{"message":{"id":"msg_1","type":"message","role":"assistant","content":[],"model":"claude-sonnet-4-20250514","usage":{"input_tokens":250}}}"#,
            &mut tool_calls,
            &mut usage,
        );
        assert_eq!(usage.input_tokens, 250);
    }

    #[test]
    fn test_default_base_url() {
        let provider = AnthropicProvider::new("test-key".to_string()).unwrap();
        assert_eq!(provider.base_url, "https://api.anthropic.com");
    }

    #[test]
    fn test_custom_base_url_accepted() {
        let provider = AnthropicProvider::new("test-key".to_string())
            .unwrap()
            .with_base_url("https://proxy.example.com".to_string())
            .unwrap();
        assert_eq!(provider.base_url, "https://proxy.example.com");
    }

    #[test]
    fn test_custom_base_url_trailing_slash_stripped() {
        let provider = AnthropicProvider::new("test-key".to_string())
            .unwrap()
            .with_base_url("https://proxy.example.com/".to_string())
            .unwrap();
        assert_eq!(provider.base_url, "https://proxy.example.com");
    }

    #[test]
    fn test_base_url_rejects_http() {
        let result = AnthropicProvider::new("test-key".to_string())
            .unwrap()
            .with_base_url("http://insecure.example.com".to_string());
        assert!(result.is_err(), "expected http base URL to fail");
        let err = result.unwrap_err().to_string();
        assert!(err.contains("https"), "got: {err}");
    }

    #[test]
    fn test_base_url_rejects_invalid_url() {
        let result = AnthropicProvider::new("test-key".to_string())
            .unwrap()
            .with_base_url("not-a-url".to_string());
        assert!(result.is_err(), "expected malformed base URL to fail");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("invalid URL"),
            "error should mention invalid URL: {err}"
        );
    }

    #[test]
    fn test_base_url_with_path() {
        let provider = AnthropicProvider::new("test-key".to_string())
            .unwrap()
            .with_base_url("https://proxy.example.com/v1/anthropic".to_string())
            .unwrap();
        assert_eq!(provider.base_url, "https://proxy.example.com/v1/anthropic");
    }

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
    async fn test_complete_stream_with_message_stop_returns_ok() {
        // A complete Anthropic SSE stream: message_start, content deltas,
        // message_delta (with stop), and message_stop.
        let sse_data = concat!(
            "event: message_start\n",
            "data: {\"message\":{\"id\":\"msg_1\",\"type\":\"message\",\"role\":\"assistant\",\"content\":[],\"model\":\"claude-sonnet-4-20250514\",\"usage\":{\"input_tokens\":10}}}\n\n",
            "event: content_block_start\n",
            "data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n",
            "event: content_block_delta\n",
            "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"Hello\"}}\n\n",
            "event: content_block_stop\n",
            "data: {\"type\":\"content_block_stop\",\"index\":0}\n\n",
            "event: message_delta\n",
            "data: {\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":5}}\n\n",
            "event: message_stop\n",
            "data: {}\n\n",
        );

        let stream = mock_sse_stream(vec![sse_data]);
        let (tx, mut rx) = mpsc::channel(64);

        let result = process_sse_stream(stream, &tx, &CancellationToken::new()).await;
        assert!(result.is_ok(), "expected Ok, got: {:?}", result);

        // Verify we received the expected events
        let mut events = Vec::new();
        while let Ok(event) = rx.try_recv() {
            events.push(event);
        }
        // Should have TextDelta and Stop
        assert!(
            events
                .iter()
                .any(|e| matches!(e, StreamEvent::TextDelta { text } if text == "Hello")),
            "expected TextDelta with 'Hello', got: {:?}",
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
    async fn test_truncated_stream_without_message_stop_returns_error() {
        // A truncated stream: message_start and a text delta, but no
        // message_delta or message_stop (simulating network interruption).
        let sse_data = concat!(
            "event: message_start\n",
            "data: {\"message\":{\"id\":\"msg_1\",\"type\":\"message\",\"role\":\"assistant\",\"content\":[],\"model\":\"claude-sonnet-4-20250514\",\"usage\":{\"input_tokens\":10}}}\n\n",
            "event: content_block_start\n",
            "data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n",
            "event: content_block_delta\n",
            "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"Hello\"}}\n\n",
            // Stream ends abruptly here — no message_delta, no message_stop
        );

        let stream = mock_sse_stream(vec![sse_data]);
        let (tx, _rx) = mpsc::channel(64);

        let result = process_sse_stream(stream, &tx, &CancellationToken::new()).await;
        assert!(result.is_err(), "expected Err for truncated stream, got Ok");
        let err_msg = result.unwrap_err();
        assert!(
            err_msg.contains("message_stop"),
            "error should mention message_stop: {err_msg}",
        );
    }
}
