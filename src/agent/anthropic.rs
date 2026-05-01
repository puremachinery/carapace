//! Anthropic Messages API provider.
//!
//! Streams completions from the Anthropic `/v1/messages` endpoint using
//! Server-Sent Events (SSE).

use async_trait::async_trait;
use serde_json::{json, Value};
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::agent::provider::*;
use crate::agent::AgentError;
use crate::auth::profiles::{resolve_anthropic_profile_token, ProfileStore};

enum AnthropicAuth {
    ApiKey(String),
    AuthProfileToken {
        profile_store: Arc<ProfileStore>,
        profile_id: String,
    },
}

impl std::fmt::Debug for AnthropicAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApiKey(_) => f.debug_tuple("ApiKey").field(&"<redacted>").finish(),
            Self::AuthProfileToken { profile_id, .. } => f
                .debug_struct("AuthProfileToken")
                .field("profile_id", profile_id)
                .finish_non_exhaustive(),
        }
    }
}

/// Anthropic Messages API provider.
pub struct AnthropicProvider {
    client: reqwest::Client,
    auth: AnthropicAuth,
    base_url: String,
}

impl std::fmt::Debug for AnthropicProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AnthropicProvider")
            .field("auth", &self.auth)
            .field("base_url", &self.base_url)
            .finish()
    }
}

impl AnthropicProvider {
    fn build_client() -> Result<reqwest::Client, AgentError> {
        reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(10))
            .timeout(std::time::Duration::from_secs(300))
            .build()
            .map_err(|e| AgentError::Provider(format!("failed to build HTTP client: {e}")))
    }

    pub fn new(api_key: String) -> Result<Self, AgentError> {
        if api_key.trim().is_empty() {
            return Err(AgentError::InvalidApiKey(
                "API key must not be empty".to_string(),
            ));
        }
        let client = Self::build_client()?;
        Ok(Self {
            client,
            auth: AnthropicAuth::ApiKey(api_key),
            base_url: "https://api.anthropic.com".to_string(),
        })
    }

    pub fn with_auth_profile_token(
        profile_store: Arc<ProfileStore>,
        profile_id: String,
    ) -> Result<Self, AgentError> {
        if profile_id.trim().is_empty() {
            return Err(AgentError::Provider(
                "Anthropic auth profile ID must not be empty".to_string(),
            ));
        }
        let client = Self::build_client()?;
        Ok(Self {
            client,
            auth: AnthropicAuth::AuthProfileToken {
                profile_store,
                profile_id,
            },
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
        let mut body = crate::agent::anthropic_wire::build_messages_body(request);
        body["model"] = json!(request.model);
        body
    }

    async fn api_key(&self) -> Result<String, AgentError> {
        match &self.auth {
            AnthropicAuth::ApiKey(api_key) => Ok(api_key.clone()),
            AnthropicAuth::AuthProfileToken {
                profile_store,
                profile_id,
            } => {
                let token = resolve_anthropic_profile_token(profile_store, profile_id)
                    .map_err(AgentError::Provider)?;
                profile_store.update_last_used(profile_id);
                Ok(token)
            }
        }
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
        let api_key = self.api_key().await?;

        let response = tokio::select! {
            _ = cancel_token.cancelled() => {
                return Err(AgentError::Cancelled);
            }
            response = self
                .client
                .post(&url)
                .header("x-api-key", api_key)
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
            if let Err(e) =
                crate::agent::anthropic_wire::process_anthropic_sse_stream(stream, &tx, &cancel)
                    .await
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

/// Determine whether a model identifier should route to the Anthropic provider.
///
/// Requires the canonical `anthropic:` prefix (e.g. `anthropic:claude-sonnet-4-6`).
pub fn is_anthropic_model(model: &str) -> bool {
    model.len() > 10
        && model.as_bytes()[..9].eq_ignore_ascii_case(b"anthropic")
        && model.as_bytes()[9] == b':'
}

/// Strip the `anthropic:` prefix from a model identifier.
///
/// Returns the bare model name for the Anthropic API
/// (e.g. `claude-sonnet-4-6`).
pub fn strip_anthropic_prefix(model: &str) -> &str {
    if is_anthropic_model(model) {
        &model[10..]
    } else {
        model
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::profiles::{
        AuthProfile, AuthProfileCredentialKind, OAuthProvider, ProfileStore,
    };
    use std::sync::Arc;

    #[test]
    fn test_build_body_basic() {
        let provider = AnthropicProvider::new("test-key".to_string()).unwrap();
        let request = CompletionRequest {
            model: "claude-sonnet-4-6".to_string(),
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
        assert_eq!(body["model"], "claude-sonnet-4-6");
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
            model: "claude-sonnet-4-6".to_string(),
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
    fn test_build_body_ignores_signatures_from_structured_assistant_history() {
        let provider = AnthropicProvider::new("test-key".to_string()).unwrap();
        let assistant_content =
            crate::agent::context::serialize_assistant_blocks(&[ContentBlock::Text {
                text: "Hello".to_string(),
                metadata: ContentBlockMetadata::with_gemini_thought_signature(Some(
                    "sig-text".to_string(),
                )),
            }])
            .unwrap();
        let history = vec![crate::sessions::ChatMessage::assistant(
            "sess-anthropic-history",
            &assistant_content,
        )];
        let (_system, messages) = crate::agent::context::build_context(&history, None);
        let request = CompletionRequest {
            model: "claude-sonnet-4-6".to_string(),
            messages,
            system: None,
            tools: vec![],
            max_tokens: 1024,
            temperature: None,
            extra: None,
        };

        let body = provider.build_body(&request);
        assert!(
            !body.to_string().contains("thoughtSignature"),
            "Anthropic requests should not forward stored Gemini thought signatures"
        );
    }

    #[test]
    fn test_new_rejects_empty_api_key() {
        let result = AnthropicProvider::new("".to_string());
        assert!(result.is_err(), "expected empty API key to fail");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("empty"),
            "expected 'empty' in error, got redacted"
        );
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

    #[tokio::test]
    async fn test_with_auth_profile_token_uses_stored_token() {
        let temp = tempfile::tempdir().expect("tempdir");
        let store = Arc::new(ProfileStore::new(temp.path().to_path_buf()));
        store
            .add(AuthProfile {
                id: "anthropic:default".to_string(),
                name: "Anthropic setup token".to_string(),
                provider: OAuthProvider::Anthropic,
                user_id: None,
                email: None,
                display_name: None,
                avatar_url: None,
                created_at_ms: 1,
                last_used_ms: None,
                credential_kind: AuthProfileCredentialKind::Token,
                tokens: None,
                token: Some("sk-ant-oat01-test-token".to_string()),
                oauth_provider_config: None,
            })
            .expect("store profile");

        let provider = AnthropicProvider::with_auth_profile_token(
            store.clone(),
            "anthropic:default".to_string(),
        )
        .expect("provider");

        let token = provider.api_key().await.expect("token");
        assert_eq!(token, "sk-ant-oat01-test-token");
        assert!(
            store
                .get("anthropic:default")
                .expect("stored profile")
                .last_used_ms
                .is_some(),
            "last_used_ms should update after successful Anthropic token resolution"
        );
    }

    #[tokio::test]
    async fn test_with_auth_profile_token_rejects_wrong_credential_kind() {
        let temp = tempfile::tempdir().expect("tempdir");
        let store = ProfileStore::new(temp.path().to_path_buf());
        store
            .add(AuthProfile {
                id: "anthropic:default".to_string(),
                name: "Wrong profile".to_string(),
                provider: OAuthProvider::Anthropic,
                user_id: None,
                email: None,
                display_name: None,
                avatar_url: None,
                created_at_ms: 1,
                last_used_ms: None,
                credential_kind: AuthProfileCredentialKind::OAuth,
                tokens: Some(crate::auth::profiles::OAuthTokens {
                    access_token: "oauth-access".to_string(),
                    refresh_token: None,
                    token_type: "Bearer".to_string(),
                    expires_at_ms: None,
                    scope: None,
                }),
                token: None,
                oauth_provider_config: None,
            })
            .expect("store profile");

        let provider = AnthropicProvider::with_auth_profile_token(
            Arc::new(store),
            "anthropic:default".to_string(),
        )
        .expect("provider");

        let err = provider.api_key().await.expect_err("wrong credential kind");
        assert!(err.to_string().contains("not token-backed"));
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

    // ==================== is_anthropic_model / strip_anthropic_prefix tests ====================

    #[test]
    fn test_is_anthropic_model() {
        assert!(is_anthropic_model("anthropic:claude-sonnet-4-6"));
        assert!(is_anthropic_model("Anthropic:claude-opus-4-20250514"));
        assert!(is_anthropic_model("ANTHROPIC:claude-3-haiku"));
    }

    #[test]
    fn test_is_not_anthropic_model() {
        assert!(!is_anthropic_model("claude-sonnet-4-6")); // bare
        assert!(!is_anthropic_model("openai:gpt-5.5"));
        assert!(!is_anthropic_model("anthropic:")); // prefix only, no model
        assert!(!is_anthropic_model("anthropic")); // bare word
    }

    #[test]
    fn test_strip_anthropic_prefix() {
        assert_eq!(
            strip_anthropic_prefix("anthropic:claude-sonnet-4-6"),
            "claude-sonnet-4-6"
        );
        assert_eq!(
            strip_anthropic_prefix("Anthropic:claude-opus-4-20250514"),
            "claude-opus-4-20250514"
        );
        assert_eq!(
            strip_anthropic_prefix("openai:gpt-5.5"),
            "openai:gpt-5.5" // not anthropic, passes through
        );
    }
}
