//! NEAR AI Cloud provider.
//!
//! NEAR AI Cloud exposes an OpenAI-compatible TEE inference API at
//! `https://cloud-api.near.ai/v1`, so this provider reuses the shared
//! OpenAI-compatible SSE parser while sending the broader `max_tokens`
//! completion field expected by NEAR's compatibility layer.

use async_trait::async_trait;
use serde_json::json;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::agent::openai::OpenAiProvider;
use crate::agent::provider::*;
use crate::agent::AgentError;

/// Default NEAR AI Cloud OpenAI-compatible base URL.
const NEARAI_DEFAULT_BASE_URL: &str = "https://cloud-api.near.ai/v1";

/// NEAR AI Cloud TEE inference provider.
#[derive(Debug)]
pub struct NearAiProvider {
    inner: OpenAiProvider,
}

impl NearAiProvider {
    /// Create a new NEAR AI Cloud provider with the default base URL.
    pub fn new(api_key: String) -> Result<Self, AgentError> {
        let inner =
            OpenAiProvider::new(api_key)?.with_base_url(NEARAI_DEFAULT_BASE_URL.to_string())?;
        Ok(Self { inner })
    }

    /// Override the base URL for proxies or tests.
    pub fn with_base_url(self, url: String) -> Result<Self, AgentError> {
        Ok(Self {
            inner: self.inner.with_base_url(url)?,
        })
    }

    fn build_nearai_body(&self, request: &CompletionRequest) -> serde_json::Value {
        let mut body = crate::agent::openai_wire::build_openai_messages_body(request);
        body["model"] = json!(request.model);
        body["max_tokens"] = json!(request.max_tokens);
        body["stream_options"] = json!({ "include_usage": true });
        body
    }
}

#[async_trait]
impl LlmProvider for NearAiProvider {
    async fn complete(
        &self,
        request: CompletionRequest,
        cancel_token: CancellationToken,
    ) -> Result<mpsc::Receiver<StreamEvent>, AgentError> {
        let body = self.build_nearai_body(&request);
        self.inner.complete_with_body(body, cancel_token).await
    }
}

/// Determine whether a model identifier should route to the NEAR AI provider.
///
/// Requires the canonical `nearai:` prefix (e.g. `nearai:google/gemma-4-31B-it`).
pub fn is_nearai_model(model: &str) -> bool {
    model.len() > 7
        && model.as_bytes()[..6].eq_ignore_ascii_case(b"nearai")
        && model.as_bytes()[6] == b':'
}

/// Strip the `nearai:` prefix from a model identifier.
pub fn strip_nearai_prefix(model: &str) -> &str {
    if is_nearai_model(model) {
        &model[7..]
    } else {
        model
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_new_rejects_empty_api_key() {
        let result = NearAiProvider::new("".to_string());
        assert!(result.is_err());
    }

    #[test]
    fn test_new_accepts_valid_api_key() {
        let result = NearAiProvider::new("nearai-test-key-123".to_string());
        assert!(result.is_ok());
    }

    #[test]
    fn test_custom_base_url() {
        let provider = NearAiProvider::new("test-key".to_string())
            .unwrap()
            .with_base_url("https://proxy.example.com/v1".to_string())
            .unwrap();
        assert!(format!("{:?}", provider).contains("NearAiProvider"));
    }

    #[test]
    fn test_base_url_rejects_http() {
        let result = NearAiProvider::new("test-key".to_string())
            .unwrap()
            .with_base_url("http://insecure.example.com/v1".to_string());
        assert!(result.is_err());
    }

    #[test]
    fn test_is_nearai_model() {
        assert!(is_nearai_model("nearai:google/gemma-4-31B-it"));
        assert!(is_nearai_model("nearai:Qwen/Qwen3.6-35B-A3B-FP8"));
        assert!(is_nearai_model("nearai:anything"));

        assert!(!is_nearai_model("google/gemma-4-31B-it"));
        assert!(!is_nearai_model("venice:deepseek-r1"));
        assert!(!is_nearai_model("openai:gpt-5.5"));
    }

    #[test]
    fn test_is_nearai_model_case_insensitive() {
        assert!(is_nearai_model("NEARAI:google/gemma-4-31B-it"));
        assert!(is_nearai_model("NearAI:Qwen/Qwen3.6-35B-A3B-FP8"));
    }

    #[test]
    fn test_strip_nearai_prefix() {
        assert_eq!(
            strip_nearai_prefix("nearai:google/gemma-4-31B-it"),
            "google/gemma-4-31B-it"
        );
        assert_eq!(
            strip_nearai_prefix("NEARAI:Qwen/Qwen3.6-35B-A3B-FP8"),
            "Qwen/Qwen3.6-35B-A3B-FP8"
        );
        assert_eq!(strip_nearai_prefix("gpt-5.5"), "gpt-5.5");
    }

    #[test]
    fn test_build_body_uses_max_tokens() {
        let provider = NearAiProvider::new("test-key".to_string()).unwrap();
        let request = CompletionRequest {
            model: "google/gemma-4-31B-it".to_string(),
            messages: vec![LlmMessage {
                role: LlmRole::User,
                content: vec![ContentBlock::Text {
                    text: "Hello".to_string(),
                    metadata: None,
                }],
            }],
            system: None,
            tools: vec![],
            max_tokens: 1024,
            temperature: None,
            extra: None,
        };
        let body = provider.build_nearai_body(&request);
        assert_eq!(body["model"], "google/gemma-4-31B-it");
        assert_eq!(body["max_tokens"], 1024);
        assert!(body.get("max_completion_tokens").is_none());
        assert_eq!(body["stream"], true);
    }

    #[test]
    fn test_build_body_with_system_temperature_and_tools() {
        let provider = NearAiProvider::new("test-key".to_string()).unwrap();
        let request = CompletionRequest {
            model: "Qwen/Qwen3.6-35B-A3B-FP8".to_string(),
            messages: vec![LlmMessage {
                role: LlmRole::User,
                content: vec![ContentBlock::Text {
                    text: "Explain rust.".to_string(),
                    metadata: None,
                }],
            }],
            system: Some("You are a Rust expert.".to_string()),
            tools: vec![ToolDefinition {
                name: "search".to_string(),
                description: "Search the web".to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "query": { "type": "string" }
                    }
                }),
            }],
            max_tokens: 2048,
            temperature: Some(0.2),
            extra: None,
        };
        let body = provider.build_nearai_body(&request);
        assert_eq!(body["temperature"], 0.2);
        let messages = body["messages"].as_array().unwrap();
        assert_eq!(messages[0]["role"], "system");
        assert_eq!(messages[0]["content"], "You are a Rust expert.");
        let tools = body["tools"].as_array().unwrap();
        assert_eq!(tools[0]["function"]["name"], "search");
    }
}
