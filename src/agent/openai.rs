//! OpenAI Chat Completions API provider.
//!
//! Streams completions from the OpenAI `/v1/chat/completions` endpoint using
//! Server-Sent Events (SSE).

use async_trait::async_trait;
use reqwest::header::HeaderValue;
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
    http_referer: Option<String>,
    title: Option<String>,
}

impl OpenAiProvider {
    pub fn new(api_key: String) -> Result<Self, AgentError> {
        let client = Self::build_http_client()?;
        Self::with_client(api_key, client)
    }

    pub(crate) fn with_client(
        api_key: String,
        client: reqwest::Client,
    ) -> Result<Self, AgentError> {
        if api_key.trim().is_empty() {
            return Err(AgentError::InvalidApiKey(
                "API key must not be empty".to_string(),
            ));
        }
        Ok(Self {
            client,
            api_key,
            base_url: "https://api.openai.com".to_string(),
            http_referer: None,
            title: None,
        })
    }

    pub(crate) fn build_http_client() -> Result<reqwest::Client, AgentError> {
        reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(10))
            .timeout(std::time::Duration::from_secs(300))
            .build()
            .map_err(|e| AgentError::Provider(format!("failed to build HTTP client: {e}")))
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

    pub fn with_http_referer(mut self, value: String) -> Result<Self, AgentError> {
        let value = value.trim();
        if value.is_empty() {
            return Err(AgentError::Provider(
                "OpenAI HTTP-Referer header must not be empty".to_string(),
            ));
        }
        HeaderValue::from_str(value).map_err(|e| {
            AgentError::Provider(format!(
                "OpenAI HTTP-Referer header must be a valid HTTP header value: {e}"
            ))
        })?;
        self.http_referer = Some(value.to_string());
        Ok(self)
    }

    pub fn with_title(mut self, value: String) -> Result<Self, AgentError> {
        let value = value.trim();
        if value.is_empty() {
            return Err(AgentError::Provider(
                "OpenAI X-Title header must not be empty".to_string(),
            ));
        }
        HeaderValue::from_str(value).map_err(|e| {
            AgentError::Provider(format!(
                "OpenAI X-Title header must be a valid HTTP header value: {e}"
            ))
        })?;
        self.title = Some(value.to_string());
        Ok(self)
    }

    /// Build the JSON body for the OpenAI Chat Completions API.
    ///
    /// Exposed as `pub(crate)` so that providers using composition (e.g. Venice)
    /// can build the body and inject extra parameters before sending.
    pub(crate) fn build_body(&self, request: &CompletionRequest) -> Value {
        let mut body = crate::agent::openai_wire::build_openai_messages_body(request);
        body["model"] = json!(request.model);
        body["max_completion_tokens"] = json!(request.max_tokens);
        body["stream_options"] = json!({ "include_usage": true });
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

        let mut request_builder = self
            .client
            .post(&url)
            .header("authorization", format!("Bearer {}", self.api_key))
            .header("content-type", "application/json")
            .header("accept", "text/event-stream");
        if let Some(ref value) = self.http_referer {
            request_builder = request_builder.header("HTTP-Referer", value);
        }
        if let Some(ref value) = self.title {
            request_builder = request_builder.header("X-Title", value);
        }

        let response = tokio::select! {
            _ = cancel_token.cancelled() => {
                return Err(AgentError::Cancelled);
            }
            response = request_builder.json(&body).send() => {
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
            if let Err(e) =
                crate::agent::openai_wire::process_openai_sse_stream(stream, &tx, &cancel).await
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
    crate::agent::openai_wire::process_openai_sse_stream(stream, tx, cancel_token).await
}

/// Determine whether a model identifier should route to the OpenAI provider.
///
/// Requires the canonical `openai:` prefix (e.g. `openai:gpt-4o`).
pub fn is_openai_model(model: &str) -> bool {
    model.len() > 7
        && model.as_bytes()[..6].eq_ignore_ascii_case(b"openai")
        && model.as_bytes()[6] == b':'
}

/// Strip the `openai:` prefix from a model identifier.
///
/// Returns the bare model name for the OpenAI API (e.g. `gpt-4o`).
pub fn strip_openai_prefix(model: &str) -> &str {
    if is_openai_model(model) {
        &model[7..]
    } else {
        model
    }
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
                    metadata: None,
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
                        metadata: None,
                    }],
                },
                LlmMessage {
                    role: LlmRole::Assistant,
                    content: vec![
                        ContentBlock::Text {
                            text: "Let me check.".to_string(),
                            metadata: None,
                        },
                        ContentBlock::ToolUse {
                            id: "call_abc123".to_string(),
                            name: "get_weather".to_string(),
                            input: json!({"city": "SF"}),
                            metadata: None,
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
                    metadata: None,
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

    #[test]
    fn test_build_body_ignores_signatures_from_structured_assistant_history() {
        let provider = OpenAiProvider::new("test-key".to_string()).unwrap();
        let assistant_content =
            crate::agent::context::serialize_assistant_blocks(&[ContentBlock::Text {
                text: "Hello".to_string(),
                metadata: ContentBlockMetadata::with_gemini_thought_signature(Some(
                    "sig-text".to_string(),
                )),
            }])
            .unwrap();
        let history = vec![crate::sessions::ChatMessage::assistant(
            "sess-openai-history",
            &assistant_content,
        )];
        let (_system, messages) = crate::agent::context::build_context(&history, None);
        let request = CompletionRequest {
            model: "gpt-4o".to_string(),
            messages,
            system: None,
            tools: vec![],
            max_tokens: 1024,
            temperature: None,
            extra: None,
        };

        let body = provider.build_body(&request);
        let messages = body["messages"].as_array().unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0]["role"], "assistant");
        assert_eq!(messages[0]["content"], "Hello");
        assert!(
            !body.to_string().contains("thoughtSignature"),
            "non-Gemini providers should not forward stored Gemini thought signatures"
        );
    }

    // ==================== Provider construction tests ====================

    #[test]
    fn test_new_rejects_empty_api_key() {
        let result = OpenAiProvider::new("".to_string());
        assert!(result.is_err(), "expected empty API key to fail");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("empty"),
            "expected 'empty' in error, got redacted"
        );
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
    fn test_http_referer_rejects_invalid_header_value() {
        let result = OpenAiProvider::new("test-key".to_string())
            .unwrap()
            .with_http_referer("https://example.com/\napp".to_string());
        assert!(result.is_err(), "expected invalid header value to fail");
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("valid HTTP header value"));
    }

    #[test]
    fn test_title_rejects_invalid_header_value() {
        let result = OpenAiProvider::new("test-key".to_string())
            .unwrap()
            .with_title("Carapace\nInjected".to_string());
        assert!(result.is_err(), "expected invalid header value to fail");
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("valid HTTP header value"));
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
        assert!(is_openai_model("openai:gpt-4o"));
        assert!(is_openai_model("openai:gpt-4-turbo"));
        assert!(is_openai_model("openai:o1-preview"));
        assert!(is_openai_model("OpenAI:gpt-4o")); // case insensitive
        assert!(is_openai_model("OPENAI:chatgpt-4o-latest"));

        assert!(!is_openai_model("gpt-4o")); // bare model names no longer match
        assert!(!is_openai_model("o1-preview"));
        assert!(!is_openai_model("claude-sonnet-4-20250514"));
        assert!(!is_openai_model("some-other-model"));
    }

    #[test]
    fn test_strip_openai_prefix() {
        assert_eq!(strip_openai_prefix("openai:gpt-4o"), "gpt-4o");
        assert_eq!(strip_openai_prefix("OpenAI:o1-preview"), "o1-preview");
        assert_eq!(strip_openai_prefix("gpt-4o"), "gpt-4o"); // no prefix
    }
}
