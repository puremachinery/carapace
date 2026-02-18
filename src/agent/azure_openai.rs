//! Azure OpenAI API provider.
//!
//! Streams completions from Azure OpenAI's `/chat/completions` endpoint using
//! Server-Sent Events (SSE). Azure OpenAI uses a different URL format than
//! standard OpenAI:
//!   https://{resource}.openai.azure.com/openai/deployments/{deployment}/chat/completions?api-version={version}
//!
//! The "deployment" name is used instead of the model name, and can be
//! configured separately from the model identifier.

use async_trait::async_trait;
use futures_util::StreamExt;
use serde_json::{json, Value};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::agent::provider::*;
use crate::agent::AgentError;

/// Default Azure OpenAI API version.
const DEFAULT_AZURE_API_VERSION: &str = "2024-02-15-preview";

/// Azure OpenAI Chat Completions API provider.
#[derive(Debug)]
pub struct AzureOpenAiProvider {
    client: reqwest::Client,
    api_key: String,
    base_url: String,
    deployment: String,
    api_version: String,
}

impl AzureOpenAiProvider {
    /// Create a new Azure OpenAI provider.
    ///
    /// - `api_key`: Azure OpenAI API key
    /// - `resource`: Azure resource name (e.g., "my-resource" from "my-resource.openai.azure.com")
    /// - `deployment`: Deployment name (the model deployment in Azure)
    pub fn new(api_key: String, resource: String, deployment: String) -> Result<Self, AgentError> {
        if api_key.trim().is_empty() {
            return Err(AgentError::InvalidApiKey(
                "API key must not be empty".to_string(),
            ));
        }
        if resource.trim().is_empty() {
            return Err(AgentError::Provider(
                "Azure resource name must not be empty".to_string(),
            ));
        }
        if deployment.trim().is_empty() {
            return Err(AgentError::Provider(
                "Azure deployment name must not be empty".to_string(),
            ));
        }

        let client = reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(10))
            .timeout(std::time::Duration::from_secs(300))
            .build()
            .map_err(|e| AgentError::Provider(format!("failed to build HTTP client: {e}")))?;

        let base_url = format!("https://{}.openai.azure.com", resource.trim());

        Ok(Self {
            client,
            api_key,
            base_url,
            deployment: deployment.trim().to_string(),
            api_version: DEFAULT_AZURE_API_VERSION.to_string(),
        })
    }

    /// Set a custom API version (default: "2024-02-15-preview").
    pub fn with_api_version(mut self, version: String) -> Self {
        if !version.trim().is_empty() {
            self.api_version = version.trim().to_string();
        }
        self
    }

    /// Build the JSON body for the Azure OpenAI Chat Completions API.
    ///
    /// Note: Azure OpenAI uses the same message format as OpenAI.
    fn build_body(&self, request: &CompletionRequest) -> Value {
        let mut messages: Vec<Value> = Vec::new();

        if let Some(ref system) = request.system {
            messages.push(json!({
                "role": "system",
                "content": system,
            }));
        }

        for msg in &request.messages {
            match msg.role {
                LlmRole::User => convert_user_message_azure(msg, &mut messages),
                LlmRole::Assistant => convert_assistant_message_azure(msg, &mut messages),
            }
        }

        let mut body = json!({
            "messages": messages,
            "max_completion_tokens": request.max_tokens,
            "stream": true,
            "stream_options": { "include_usage": true },
        });

        if let Some(temp) = request.temperature {
            body["temperature"] = json!(temp);
        }

        append_tools_azure(&request.tools, &mut body);

        body
    }
}

/// Convert a user-role `LlmMessage` into one or more Azure OpenAI-format messages.
fn convert_user_message_azure(msg: &LlmMessage, messages: &mut Vec<Value>) {
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
        let text = collect_text_blocks_azure(&msg.content);
        if !text.is_empty() {
            messages.push(json!({
                "role": "user",
                "content": text,
            }));
        }
    }
}

/// Convert an assistant-role `LlmMessage` into an Azure OpenAI-format message.
fn convert_assistant_message_azure(msg: &LlmMessage, messages: &mut Vec<Value>) {
    let has_tool_use = msg
        .content
        .iter()
        .any(|b| matches!(b, ContentBlock::ToolUse { .. }));

    if has_tool_use {
        let text_content = collect_text_blocks_azure(&msg.content);

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
        let text = collect_text_blocks_azure(&msg.content);
        messages.push(json!({
            "role": "assistant",
            "content": text,
        }));
    }
}

/// Concatenate all `Text` blocks in a content slice into a single string.
fn collect_text_blocks_azure(content: &[ContentBlock]) -> String {
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
fn append_tools_azure(tools: &[ToolDefinition], body: &mut Value) {
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
impl LlmProvider for AzureOpenAiProvider {
    async fn complete(
        &self,
        request: CompletionRequest,
        cancel_token: CancellationToken,
    ) -> Result<mpsc::Receiver<StreamEvent>, AgentError> {
        if cancel_token.is_cancelled() {
            return Err(AgentError::Cancelled);
        }

        let body = self.build_body(&request);

        // Azure OpenAI URL format:
        // https://{resource}.openai.azure.com/openai/deployments/{deployment}/chat/completions?api-version={version}
        let url = format!(
            "{}/openai/deployments/{}/chat/completions?api-version={}",
            self.base_url, self.deployment, self.api_version
        );

        let response = tokio::select! {
            _ = cancel_token.cancelled() => {
                return Err(AgentError::Cancelled);
            }
            response = self
                .client
                .post(&url)
                .header("api-key", &self.api_key)
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
                "Azure OpenAI API returned {status}: {body}"
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

/// Maximum SSE line buffer size (1 MB).
const MAX_SSE_BUFFER_BYTES: usize = 1_048_576;

/// Process an Azure OpenAI SSE byte stream into StreamEvents.
///
/// Azure OpenAI uses the same SSE format as OpenAI.
async fn process_sse_stream<S>(
    mut stream: S,
    tx: &mpsc::Sender<StreamEvent>,
    cancel_token: &CancellationToken,
) -> Result<(), String>
where
    S: futures_util::Stream<Item = Result<bytes::Bytes, reqwest::Error>> + Unpin,
{
    let mut buffer = String::new();
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

        let mut consumed = 0;
        while let Some(rel_pos) = buffer[consumed..].find('\n') {
            let newline_pos = consumed + rel_pos;
            let line = buffer[consumed..newline_pos]
                .trim_end_matches('\r')
                .to_string();
            consumed = newline_pos + 1;

            if let Some(data) = line.strip_prefix("data: ") {
                if data.trim() == "[DONE]" {
                    got_done = true;
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

                if let Some(event) =
                    parse_sse_data(data, &mut tool_calls, &mut accumulated_usage)
                {
                    let is_stop = matches!(event, StreamEvent::Stop { .. });
                    let is_error = matches!(event, StreamEvent::Error { .. });
                    if tx.send(event).await.is_err() {
                        return Ok(());
                    }
                    if is_stop || is_error {
                        return Ok(());
                    }
                }
            }
        }
        if consumed > 0 {
            buffer.drain(..consumed);
        }
    }

    if got_done {
        Ok(())
    } else {
        Err("stream ended without [DONE] sentinel".to_string())
    }
}

/// Parse a single SSE data payload from Azure OpenAI's streaming format.
fn parse_sse_data(
    data: &str,
    tool_calls: &mut std::collections::HashMap<u64, (String, String, String)>,
    accumulated_usage: &mut TokenUsage,
) -> Option<StreamEvent> {
    let parsed: Value = serde_json::from_str(data).ok()?;

    if let Some(error) = parsed.get("error") {
        let message = error
            .get("message")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown API error")
            .to_string();
        return Some(StreamEvent::Error { message });
    }

    if let Some(usage) = parsed.get("usage") {
        if let Some(prompt_tokens) = usage.get("prompt_tokens").and_then(|v| v.as_u64()) {
            accumulated_usage.input_tokens = prompt_tokens;
        }
        if let Some(completion_tokens) = usage.get("completion_tokens").and_then(|v| v.as_u64())
        {
            accumulated_usage.output_tokens = completion_tokens;
        }
    }

    let choices = parsed.get("choices")?.as_array()?;
    if choices.is_empty() {
        return None;
    }

    let choice = &choices[0];

    if let Some(finish_reason) = choice.get("finish_reason").and_then(|v| v.as_str()) {
        let reason = match finish_reason {
            "stop" => StopReason::EndTurn,
            "tool_calls" => StopReason::ToolUse,
            "length" => StopReason::MaxTokens,
            _ => StopReason::EndTurn,
        };

        if reason == StopReason::ToolUse {
            return None;
        }

        return Some(StreamEvent::Stop {
            reason,
            usage: *accumulated_usage,
        });
    }

    let delta = choice.get("delta")?;

    if let Some(content) = delta.get("content").and_then(|v| v.as_str()) {
        if !content.is_empty() {
            return Some(StreamEvent::TextDelta {
                text: content.to_string(),
            });
        }
    }

    if let Some(tc_array) = delta.get("tool_calls").and_then(|v| v.as_array()) {
        for tc in tc_array {
            let index = tc.get("index").and_then(|v| v.as_u64()).unwrap_or(0);

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
async fn flush_tool_calls_and_stop(
    tool_calls: &mut std::collections::HashMap<u64, (String, String, String)>,
    usage: &TokenUsage,
    tx: &mpsc::Sender<StreamEvent>,
) -> Option<StreamEvent> {
    if tool_calls.is_empty() {
        return None;
    }

    let mut sorted: Vec<(u64, (String, String, String))> = tool_calls.drain().collect();
    sorted.sort_by_key(|(idx, _)| *idx);

    for (_index, (id, name, args_json)) in sorted {
        let input: Value = serde_json::from_str(&args_json).unwrap_or(json!({}));
        let event = StreamEvent::ToolUse { id, name, input };
        if tx.send(event).await.is_err() {
            return None;
        }
    }

    Some(StreamEvent::Stop {
        reason: StopReason::ToolUse,
        usage: *usage,
    })
}

/// Determine whether a model identifier should route to the Azure OpenAI provider.
///
/// Models prefixed with `azure:` are routed to Azure OpenAI.
pub fn is_azure_openai_model(model: &str) -> bool {
    let lower = model.to_lowercase();
    lower.starts_with("azure:")
}

/// Strip the `azure:` prefix from a model identifier.
///
/// Returns the bare deployment name for the Azure OpenAI API.
pub fn strip_azure_prefix(model: &str) -> &str {
    if let Some(rest) = model.strip_prefix("azure:") {
        rest
    } else if let Some(rest) = model.strip_prefix("Azure:") {
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
        let result = AzureOpenAiProvider::new(
            "".to_string(),
            "my-resource".to_string(),
            "gpt-4".to_string(),
        );
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("API key"), "error should mention API key: {err}");
    }

    #[test]
    fn test_new_rejects_empty_resource() {
        let result = AzureOpenAiProvider::new(
            "sk-key".to_string(),
            "".to_string(),
            "gpt-4".to_string(),
        );
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("resource"), "error should mention resource: {err}");
    }

    #[test]
    fn test_new_rejects_empty_deployment() {
        let result = AzureOpenAiProvider::new(
            "sk-key".to_string(),
            "my-resource".to_string(),
            "".to_string(),
        );
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("deployment"), "error should mention deployment: {err}");
    }

    #[test]
    fn test_new_accepts_valid_params() {
        let result = AzureOpenAiProvider::new(
            "sk-key".to_string(),
            "my-resource".to_string(),
            "gpt-4".to_string(),
        );
        assert!(result.is_ok());
        let provider = result.unwrap();
        assert_eq!(provider.base_url, "https://my-resource.openai.azure.com");
        assert_eq!(provider.deployment, "gpt-4");
        assert_eq!(provider.api_version, DEFAULT_AZURE_API_VERSION);
    }

    #[test]
    fn test_with_api_version() {
        let provider = AzureOpenAiProvider::new(
            "sk-key".to_string(),
            "my-resource".to_string(),
            "gpt-4".to_string(),
        )
        .unwrap()
        .with_api_version("2024-06-01".to_string());
        assert_eq!(provider.api_version, "2024-06-01");
    }

    #[test]
    fn test_with_api_version_empty_ignores() {
        let provider = AzureOpenAiProvider::new(
            "sk-key".to_string(),
            "my-resource".to_string(),
            "gpt-4".to_string(),
        )
        .unwrap()
        .with_api_version("".to_string());
        assert_eq!(provider.api_version, DEFAULT_AZURE_API_VERSION);
    }

    // ==================== Model detection tests ====================

    #[test]
    fn test_is_azure_openai_model() {
        assert!(is_azure_openai_model("azure:gpt-4"));
        assert!(is_azure_openai_model("azure:gpt-4o"));
        assert!(is_azure_openai_model("Azure:gpt-4"));
        assert!(is_azure_openai_model("AZURE:gpt-4"));

        assert!(!is_azure_openai_model("gpt-4o"));
        assert!(!is_azure_openai_model("claude-sonnet-4"));
    }

    #[test]
    fn test_strip_azure_prefix() {
        assert_eq!(strip_azure_prefix("azure:gpt-4"), "gpt-4");
        assert_eq!(strip_azure_prefix("Azure:gpt-4"), "gpt-4");
        assert_eq!(strip_azure_prefix("gpt-4"), "gpt-4");
    }

    // ==================== build_body tests ====================

    #[test]
    fn test_build_body_basic() {
        let provider = AzureOpenAiProvider::new(
            "sk-key".to_string(),
            "my-resource".to_string(),
            "gpt-4".to_string(),
        )
        .unwrap();
        let request = CompletionRequest {
            model: "gpt-4".to_string(),
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
        assert_eq!(body["max_completion_tokens"], 1024);
        assert_eq!(body["stream"], true);
        assert_eq!(body["temperature"], 0.7);
        let messages = body["messages"].as_array().unwrap();
        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0]["role"], "system");
        assert_eq!(messages[1]["role"], "user");
    }

    #[test]
    fn test_build_body_with_tools() {
        let provider = AzureOpenAiProvider::new(
            "sk-key".to_string(),
            "my-resource".to_string(),
            "gpt-4".to_string(),
        )
        .unwrap();
        let request = CompletionRequest {
            model: "gpt-4".to_string(),
            messages: vec![],
            system: None,
            tools: vec![ToolDefinition {
                name: "get_weather".to_string(),
                description: "Get weather".to_string(),
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
        assert_eq!(tools[0]["function"]["name"], "get_weather");
    }

    #[test]
    fn test_build_body_assistant_with_tool_calls() {
        let provider = AzureOpenAiProvider::new(
            "sk-key".to_string(),
            "my-resource".to_string(),
            "gpt-4".to_string(),
        )
        .unwrap();
        let request = CompletionRequest {
            model: "gpt-4".to_string(),
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
            ],
            system: None,
            tools: vec![],
            max_tokens: 1024,
            temperature: None,
            extra: None,
        };
        let body = provider.build_body(&request);
        let messages = body["messages"].as_array().unwrap();
        assert_eq!(messages.len(), 2);
        // Assistant message with tool_calls
        assert_eq!(messages[1]["role"], "assistant");
        let tool_calls = messages[1]["tool_calls"].as_array().unwrap();
        assert_eq!(tool_calls[0]["id"], "call_abc123");
    }

    #[test]
    fn test_build_body_with_tool_results() {
        let provider = AzureOpenAiProvider::new(
            "sk-key".to_string(),
            "my-resource".to_string(),
            "gpt-4".to_string(),
        )
        .unwrap();
        let request = CompletionRequest {
            model: "gpt-4".to_string(),
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
                        id: "call_abc".to_string(),
                        name: "get_weather".to_string(),
                        input: json!({"city": "SF"}),
                    }],
                },
                LlmMessage {
                    role: LlmRole::User,
                    content: vec![ContentBlock::ToolResult {
                        tool_use_id: "call_abc".to_string(),
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
        // Tool result should be converted to role: "tool"
        assert_eq!(messages[2]["role"], "tool");
        assert_eq!(messages[2]["tool_call_id"], "call_abc");
        assert_eq!(messages[2]["content"], "72F and sunny");
    }
}
