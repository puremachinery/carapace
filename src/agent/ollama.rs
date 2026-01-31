//! Ollama LLM provider for local model inference.
//!
//! Uses Ollama's OpenAI-compatible `/v1/chat/completions` endpoint, which means
//! we can reuse the existing OpenAI streaming and message-format logic. The main
//! differences from the OpenAI provider are:
//!
//! - Default base URL is `http://localhost:11434` (local Ollama server)
//! - No API key is required by default (local inference)
//! - HTTP (not just HTTPS) is allowed for base URLs
//! - Model names are passed through after stripping the `ollama:` or `ollama/` prefix

use async_trait::async_trait;
use serde_json::Value;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::agent::provider::*;
use crate::agent::AgentError;

/// Default Ollama base URL (local server).
pub const DEFAULT_OLLAMA_BASE_URL: &str = "http://localhost:11434";

/// Ollama LLM provider.
///
/// Internally wraps an HTTP client and reuses the OpenAI-compatible endpoint
/// (`/v1/chat/completions`) that Ollama exposes. This avoids duplicating the
/// SSE streaming and message-format conversion logic already in `openai.rs`.
#[derive(Debug)]
pub struct OllamaProvider {
    client: reqwest::Client,
    base_url: String,
    api_key: Option<String>,
}

impl OllamaProvider {
    /// Create a new Ollama provider with the default base URL.
    ///
    /// Unlike the OpenAI provider, no API key is required by default since
    /// Ollama typically runs locally without authentication.
    pub fn new() -> Result<Self, AgentError> {
        let client = reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(10))
            .timeout(std::time::Duration::from_secs(600)) // longer timeout for local inference
            .build()
            .map_err(|e| AgentError::Provider(format!("failed to build HTTP client: {e}")))?;
        Ok(Self {
            client,
            base_url: DEFAULT_OLLAMA_BASE_URL.to_string(),
            api_key: None,
        })
    }

    /// Set a custom base URL for the Ollama server.
    ///
    /// Unlike OpenAI/Anthropic providers, both `http` and `https` schemes are
    /// accepted since Ollama is typically run locally over plain HTTP.
    pub fn with_base_url(mut self, url: String) -> Result<Self, AgentError> {
        let parsed = url::Url::parse(&url)
            .map_err(|e| AgentError::InvalidBaseUrl(format!("invalid URL \"{url}\": {e}")))?;
        let scheme = parsed.scheme();
        if scheme != "http" && scheme != "https" {
            return Err(AgentError::InvalidBaseUrl(format!(
                "base URL must use http or https scheme, got \"{scheme}\""
            )));
        }
        // Strip trailing slash for consistent path joining
        self.base_url = url.trim_end_matches('/').to_string();
        Ok(self)
    }

    /// Set an optional API key for remote Ollama instances that require auth.
    pub fn with_api_key(mut self, api_key: String) -> Self {
        if api_key.trim().is_empty() {
            self.api_key = None;
        } else {
            self.api_key = Some(api_key);
        }
        self
    }

    /// Build the JSON body for the OpenAI-compatible chat completions endpoint.
    ///
    /// This reuses the same message format as `OpenAiProvider::build_body` since
    /// Ollama's `/v1/chat/completions` is OpenAI-compatible.
    fn build_body(&self, request: &CompletionRequest) -> Value {
        use serde_json::json;

        let mut messages: Vec<Value> = Vec::new();

        if let Some(ref system) = request.system {
            messages.push(json!({
                "role": "system",
                "content": system,
            }));
        }

        for msg in &request.messages {
            match msg.role {
                LlmRole::User => convert_user_message_ollama(msg, &mut messages),
                LlmRole::Assistant => convert_assistant_message_ollama(msg, &mut messages),
            }
        }

        let mut body = json!({
            "model": request.model,
            "messages": messages,
            "stream": true,
            "stream_options": { "include_usage": true },
        });

        // Ollama uses "max_completion_tokens" in OpenAI-compat mode
        body["max_completion_tokens"] = json!(request.max_tokens);

        if let Some(temp) = request.temperature {
            body["temperature"] = json!(temp);
        }

        append_tools_ollama(&request.tools, &mut body);

        body
    }

    /// Returns the configured base URL.
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Check connectivity to the Ollama server and return available models.
    ///
    /// Calls `GET /api/tags` which lists all locally available models.
    /// Returns the list of model names on success, or an error on failure.
    pub async fn check_connectivity(&self) -> Result<Vec<String>, AgentError> {
        let url = format!("{}/api/tags", self.base_url);

        let mut request = self.client.get(&url);
        if let Some(ref key) = self.api_key {
            request = request.header("authorization", format!("Bearer {key}"));
        }

        let response = request
            .send()
            .await
            .map_err(|e| AgentError::Provider(format!("Ollama connectivity check failed: {e}")))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response
                .text()
                .await
                .unwrap_or_else(|_| "<unreadable>".to_string());
            return Err(AgentError::Provider(format!(
                "Ollama /api/tags returned {status}: {body}"
            )));
        }

        let body: Value = response
            .json()
            .await
            .map_err(|e| AgentError::Provider(format!("failed to parse Ollama response: {e}")))?;

        let models = body
            .get("models")
            .and_then(|m| m.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|m| m.get("name").and_then(|n| n.as_str()).map(String::from))
                    .collect()
            })
            .unwrap_or_default();

        Ok(models)
    }
}

/// Convert a user-role `LlmMessage` into one or more OpenAI-compat messages.
fn convert_user_message_ollama(msg: &LlmMessage, messages: &mut Vec<Value>) {
    use serde_json::json;

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
        let text = collect_text_blocks_ollama(&msg.content);
        if !text.is_empty() {
            messages.push(json!({
                "role": "user",
                "content": text,
            }));
        }
    }
}

/// Convert an assistant-role `LlmMessage` into an OpenAI-compat message.
fn convert_assistant_message_ollama(msg: &LlmMessage, messages: &mut Vec<Value>) {
    use serde_json::json;

    let has_tool_use = msg
        .content
        .iter()
        .any(|b| matches!(b, ContentBlock::ToolUse { .. }));

    if has_tool_use {
        let text_content = collect_text_blocks_ollama(&msg.content);

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
        let text = collect_text_blocks_ollama(&msg.content);
        messages.push(json!({
            "role": "assistant",
            "content": text,
        }));
    }
}

/// Concatenate all `Text` blocks in a content slice into a single string.
fn collect_text_blocks_ollama(content: &[ContentBlock]) -> String {
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
fn append_tools_ollama(tools: &[ToolDefinition], body: &mut Value) {
    use serde_json::json;

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
impl LlmProvider for OllamaProvider {
    async fn complete(
        &self,
        request: CompletionRequest,
        cancel_token: CancellationToken,
    ) -> Result<mpsc::Receiver<StreamEvent>, AgentError> {
        if cancel_token.is_cancelled() {
            return Err(AgentError::Cancelled);
        }
        let body = self.build_body(&request);
        let url = format!("{}/v1/chat/completions", self.base_url);

        let mut http_request = self
            .client
            .post(&url)
            .header("content-type", "application/json")
            .header("accept", "text/event-stream");

        // Add authorization header only if an API key is configured
        if let Some(ref key) = self.api_key {
            http_request = http_request.header("authorization", format!("Bearer {key}"));
        }

        let response = tokio::select! {
            _ = cancel_token.cancelled() => {
                return Err(AgentError::Cancelled);
            }
            response = http_request
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
                "Ollama API returned {status}: {body}"
            )));
        }

        let (tx, rx) = mpsc::channel(64);

        // Spawn a task to read the SSE stream and forward events.
        // Reuses the OpenAI SSE stream processor since Ollama's
        // /v1/chat/completions returns the same SSE format.
        let stream = response.bytes_stream();
        let cancel = cancel_token.clone();
        tokio::spawn(async move {
            if let Err(e) =
                crate::agent::openai::process_ollama_sse_stream(stream, &tx, &cancel).await
            {
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

/// Determine whether a model identifier should route to the Ollama provider.
///
/// Models starting with `ollama:` or `ollama/` are routed to Ollama.
pub fn is_ollama_model(model: &str) -> bool {
    let lower = model.to_lowercase();
    lower.starts_with("ollama:") || lower.starts_with("ollama/")
}

/// Strip the `ollama:` or `ollama/` prefix from a model name.
///
/// Returns the bare model name suitable for passing to the Ollama API.
/// If the model doesn't have the prefix, it is returned unchanged.
pub fn strip_ollama_prefix(model: &str) -> &str {
    if let Some(rest) = model.strip_prefix("ollama:") {
        rest
    } else if let Some(rest) = model.strip_prefix("ollama/") {
        rest
    } else if let Some(rest) = model.strip_prefix("Ollama:") {
        rest
    } else if let Some(rest) = model.strip_prefix("Ollama/") {
        rest
    } else {
        model
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ==================== is_ollama_model tests ====================

    #[test]
    fn test_is_ollama_model_with_colon_prefix() {
        assert!(is_ollama_model("ollama:llama3"));
        assert!(is_ollama_model("ollama:codellama"));
        assert!(is_ollama_model("ollama:mistral"));
        assert!(is_ollama_model("ollama:phi3:mini"));
    }

    #[test]
    fn test_is_ollama_model_with_slash_prefix() {
        assert!(is_ollama_model("ollama/llama3"));
        assert!(is_ollama_model("ollama/codellama"));
        assert!(is_ollama_model("ollama/mixtral:8x7b"));
    }

    #[test]
    fn test_is_ollama_model_case_insensitive() {
        assert!(is_ollama_model("Ollama:llama3"));
        assert!(is_ollama_model("OLLAMA:llama3"));
        assert!(is_ollama_model("Ollama/llama3"));
        assert!(is_ollama_model("OLLAMA/llama3"));
    }

    #[test]
    fn test_is_not_ollama_model() {
        assert!(!is_ollama_model("gpt-4o"));
        assert!(!is_ollama_model("claude-sonnet-4-20250514"));
        assert!(!is_ollama_model("llama3"));
        assert!(!is_ollama_model("mistral"));
    }

    // ==================== strip_ollama_prefix tests ====================

    #[test]
    fn test_strip_colon_prefix() {
        assert_eq!(strip_ollama_prefix("ollama:llama3"), "llama3");
        assert_eq!(strip_ollama_prefix("ollama:codellama:7b"), "codellama:7b");
    }

    #[test]
    fn test_strip_slash_prefix() {
        assert_eq!(strip_ollama_prefix("ollama/llama3"), "llama3");
        assert_eq!(strip_ollama_prefix("ollama/mixtral:8x7b"), "mixtral:8x7b");
    }

    #[test]
    fn test_strip_case_variants() {
        assert_eq!(strip_ollama_prefix("Ollama:llama3"), "llama3");
        assert_eq!(strip_ollama_prefix("Ollama/llama3"), "llama3");
    }

    #[test]
    fn test_strip_no_prefix_returns_unchanged() {
        assert_eq!(strip_ollama_prefix("llama3"), "llama3");
        assert_eq!(strip_ollama_prefix("gpt-4o"), "gpt-4o");
    }

    // ==================== Provider construction tests ====================

    #[test]
    fn test_new_provider_default_base_url() {
        let provider = OllamaProvider::new().unwrap();
        assert_eq!(provider.base_url(), DEFAULT_OLLAMA_BASE_URL);
    }

    #[test]
    fn test_custom_base_url_http_accepted() {
        let provider = OllamaProvider::new()
            .unwrap()
            .with_base_url("http://192.168.1.100:11434".to_string())
            .unwrap();
        assert_eq!(provider.base_url(), "http://192.168.1.100:11434");
    }

    #[test]
    fn test_custom_base_url_https_accepted() {
        let provider = OllamaProvider::new()
            .unwrap()
            .with_base_url("https://ollama.example.com".to_string())
            .unwrap();
        assert_eq!(provider.base_url(), "https://ollama.example.com");
    }

    #[test]
    fn test_custom_base_url_trailing_slash_stripped() {
        let provider = OllamaProvider::new()
            .unwrap()
            .with_base_url("http://localhost:11434/".to_string())
            .unwrap();
        assert_eq!(provider.base_url(), "http://localhost:11434");
    }

    #[test]
    fn test_base_url_rejects_invalid_scheme() {
        let result = OllamaProvider::new()
            .unwrap()
            .with_base_url("ftp://localhost:11434".to_string());
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("http or https"),
            "error should mention http or https: {err}"
        );
    }

    #[test]
    fn test_base_url_rejects_invalid_url() {
        let result = OllamaProvider::new()
            .unwrap()
            .with_base_url("not-a-url".to_string());
        assert!(result.is_err());
    }

    #[test]
    fn test_api_key_set_and_clear() {
        let provider = OllamaProvider::new()
            .unwrap()
            .with_api_key("my-secret-key".to_string());
        assert_eq!(provider.api_key.as_deref(), Some("my-secret-key"));

        // Empty key should clear it
        let provider = OllamaProvider::new().unwrap().with_api_key("".to_string());
        assert!(provider.api_key.is_none());

        // Whitespace-only key should clear it
        let provider = OllamaProvider::new()
            .unwrap()
            .with_api_key("   ".to_string());
        assert!(provider.api_key.is_none());
    }

    #[test]
    fn test_no_api_key_by_default() {
        let provider = OllamaProvider::new().unwrap();
        assert!(provider.api_key.is_none());
    }

    // ==================== build_body tests ====================

    #[test]
    fn test_build_body_basic() {
        let provider = OllamaProvider::new().unwrap();
        let request = CompletionRequest {
            model: "llama3".to_string(),
            messages: vec![LlmMessage {
                role: LlmRole::User,
                content: vec![ContentBlock::Text {
                    text: "Hello".to_string(),
                }],
            }],
            system: Some("You are helpful.".to_string()),
            tools: vec![],
            max_tokens: 2048,
            temperature: Some(0.7),
            extra: None,
        };
        let body = provider.build_body(&request);
        assert_eq!(body["model"], "llama3");
        assert_eq!(body["max_completion_tokens"], 2048);
        assert_eq!(body["stream"], true);
        assert_eq!(body["temperature"], 0.7);

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
        let provider = OllamaProvider::new().unwrap();
        let request = CompletionRequest {
            model: "llama3".to_string(),
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
        assert!(body.get("temperature").is_none());
    }

    #[test]
    fn test_build_body_assistant_with_tool_calls() {
        let provider = OllamaProvider::new().unwrap();
        let request = CompletionRequest {
            model: "llama3".to_string(),
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
        let provider = OllamaProvider::new().unwrap();
        let request = CompletionRequest {
            model: "llama3".to_string(),
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
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0]["role"], "user");
    }

    #[test]
    fn test_build_body_stream_options_present() {
        let provider = OllamaProvider::new().unwrap();
        let request = CompletionRequest {
            model: "llama3".to_string(),
            messages: vec![],
            system: None,
            tools: vec![],
            max_tokens: 1024,
            temperature: None,
            extra: None,
        };
        let body = provider.build_body(&request);
        assert_eq!(body["stream"], true);
        assert!(body["stream_options"]["include_usage"].as_bool().unwrap());
    }
}
