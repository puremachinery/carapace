//! Venice AI provider.
//!
//! Wraps `OpenAiProvider` via composition — Venice exposes an OpenAI-compatible
//! API at `https://api.venice.ai/api/v1`, so we reuse all SSE parsing, body
//! construction, and streaming logic.  The only addition is optional
//! `venice_parameters` injection into the request body.

use async_trait::async_trait;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::agent::openai::OpenAiProvider;
use crate::agent::provider::*;
use crate::agent::AgentError;

/// Default Venice API base URL.
const VENICE_DEFAULT_BASE_URL: &str = "https://api.venice.ai/api";

/// Venice AI provider (OpenAI-compatible with `venice_parameters` extension).
#[derive(Debug)]
pub struct VeniceProvider {
    inner: OpenAiProvider,
}

impl VeniceProvider {
    /// Create a new Venice provider with the default base URL.
    pub fn new(api_key: String) -> Result<Self, AgentError> {
        let inner =
            OpenAiProvider::new(api_key)?.with_base_url(VENICE_DEFAULT_BASE_URL.to_string())?;
        Ok(Self { inner })
    }

    /// Override the base URL (for testing or self-hosted endpoints).
    pub fn with_base_url(self, url: String) -> Result<Self, AgentError> {
        Ok(Self {
            inner: self.inner.with_base_url(url)?,
        })
    }

    /// Build the OpenAI-format request body, injecting `venice_parameters`
    /// from `request.extra` when present.
    fn build_venice_body(&self, request: &CompletionRequest) -> serde_json::Value {
        let mut body = self.inner.build_body(request);
        if let Some(ref venice_params) = request.extra {
            body["venice_parameters"] = venice_params.clone();
        }
        body
    }
}

#[async_trait]
impl LlmProvider for VeniceProvider {
    async fn complete(
        &self,
        request: CompletionRequest,
        cancel_token: CancellationToken,
    ) -> Result<mpsc::Receiver<StreamEvent>, AgentError> {
        let body = self.build_venice_body(&request);
        self.inner.complete_with_body(body, cancel_token).await
    }
}

/// Determine whether a model identifier should route to the Venice provider.
///
/// Venice models use the `venice:` prefix (e.g. `venice:llama-3.3-70b`).
pub fn is_venice_model(model: &str) -> bool {
    let lower = model.to_lowercase();
    lower.starts_with("venice:")
}

/// Strip the `venice:` prefix from a model identifier.
///
/// Returns the bare model name for the Venice API (e.g. `llama-3.3-70b`).
pub fn strip_venice_prefix(model: &str) -> &str {
    if let Some(rest) = model.strip_prefix("venice:") {
        rest
    } else if let Some(rest) = model.strip_prefix("Venice:") {
        rest
    } else {
        model
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ==================== Provider construction tests ====================

    #[test]
    fn test_new_rejects_empty_api_key() {
        let result = VeniceProvider::new("".to_string());
        assert!(result.is_err());
    }

    #[test]
    fn test_new_accepts_valid_api_key() {
        let result = VeniceProvider::new("venice-test-key-123".to_string());
        assert!(result.is_ok());
    }

    #[test]
    fn test_custom_base_url() {
        let provider = VeniceProvider::new("test-key".to_string())
            .unwrap()
            .with_base_url("https://custom.venice.ai/api".to_string())
            .unwrap();
        // Provider should be created successfully
        assert!(format!("{:?}", provider).contains("VeniceProvider"));
    }

    #[test]
    fn test_base_url_rejects_http() {
        let result = VeniceProvider::new("test-key".to_string())
            .unwrap()
            .with_base_url("http://insecure.example.com".to_string());
        assert!(result.is_err());
    }

    // ==================== Model routing tests ====================

    #[test]
    fn test_is_venice_model() {
        assert!(is_venice_model("venice:llama-3.3-70b"));
        assert!(is_venice_model("venice:deepseek-r1-671b"));
        assert!(is_venice_model("venice:anything"));

        assert!(!is_venice_model("gpt-4o"));
        assert!(!is_venice_model("claude-sonnet-4-20250514"));
        assert!(!is_venice_model("ollama:llama3"));
    }

    #[test]
    fn test_strip_venice_prefix() {
        assert_eq!(strip_venice_prefix("venice:llama-3.3-70b"), "llama-3.3-70b");
        assert_eq!(strip_venice_prefix("Venice:deepseek-r1"), "deepseek-r1");
        assert_eq!(strip_venice_prefix("gpt-4o"), "gpt-4o"); // no prefix
    }

    // ==================== Body construction tests ====================

    #[test]
    fn test_build_body_uses_stripped_model() {
        let provider = VeniceProvider::new("test-key".to_string()).unwrap();
        let request = CompletionRequest {
            model: "llama-3.3-70b".to_string(), // already stripped by MultiProvider
            messages: vec![LlmMessage {
                role: LlmRole::User,
                content: vec![ContentBlock::Text {
                    text: "Hello".to_string(),
                }],
            }],
            system: None,
            tools: vec![],
            max_tokens: 1024,
            temperature: None,
            extra: None,
        };
        let body = provider.inner.build_body(&request);
        assert_eq!(body["model"], "llama-3.3-70b");
        assert_eq!(body["stream"], true);
    }

    #[test]
    fn test_build_body_with_system_and_temperature() {
        let provider = VeniceProvider::new("test-key".to_string()).unwrap();
        let request = CompletionRequest {
            model: "deepseek-r1-671b".to_string(),
            messages: vec![LlmMessage {
                role: LlmRole::User,
                content: vec![ContentBlock::Text {
                    text: "Explain rust.".to_string(),
                }],
            }],
            system: Some("You are a Rust expert.".to_string()),
            tools: vec![],
            max_tokens: 4096,
            temperature: Some(0.3),
            extra: None,
        };
        let body = provider.inner.build_body(&request);
        assert_eq!(body["model"], "deepseek-r1-671b");
        assert_eq!(body["temperature"], 0.3);
        let messages = body["messages"].as_array().unwrap();
        assert_eq!(messages[0]["role"], "system");
        assert_eq!(messages[0]["content"], "You are a Rust expert.");
    }

    #[test]
    fn test_build_body_with_tools() {
        let provider = VeniceProvider::new("test-key".to_string()).unwrap();
        let request = CompletionRequest {
            model: "llama-3.3-70b".to_string(),
            messages: vec![],
            system: None,
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
            temperature: None,
            extra: None,
        };
        let body = provider.inner.build_body(&request);
        let tools = body["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0]["function"]["name"], "search");
    }

    #[test]
    fn test_venice_parameters_injected_into_body() {
        let provider = VeniceProvider::new("test-key".to_string()).unwrap();
        let venice_params = json!({
            "enable_web_search": "on",
            "include_venice_system_prompt": false
        });
        let request = CompletionRequest {
            model: "llama-3.3-70b".to_string(),
            messages: vec![LlmMessage {
                role: LlmRole::User,
                content: vec![ContentBlock::Text {
                    text: "Hello".to_string(),
                }],
            }],
            system: None,
            tools: vec![],
            max_tokens: 1024,
            temperature: None,
            extra: Some(venice_params.clone()),
        };
        let body = provider.build_venice_body(&request);
        assert_eq!(body["venice_parameters"], venice_params);
        assert_eq!(body["venice_parameters"]["enable_web_search"], "on");
        assert_eq!(
            body["venice_parameters"]["include_venice_system_prompt"],
            false
        );
    }

    #[test]
    fn test_venice_parameters_absent_when_extra_is_none() {
        let provider = VeniceProvider::new("test-key".to_string()).unwrap();
        let request = CompletionRequest {
            model: "llama-3.3-70b".to_string(),
            messages: vec![LlmMessage {
                role: LlmRole::User,
                content: vec![ContentBlock::Text {
                    text: "Hello".to_string(),
                }],
            }],
            system: None,
            tools: vec![],
            max_tokens: 1024,
            temperature: None,
            extra: None,
        };
        let body = provider.build_venice_body(&request);
        assert!(body.get("venice_parameters").is_none());
    }
}
