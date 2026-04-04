//! LLM provider trait and common types.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::agent::AgentError;
use crate::auth::profiles::{AuthProfile, AuthProfileCredentialKind};

/// A streaming event from the LLM.
#[derive(Debug, Clone)]
pub enum StreamEvent {
    /// Incremental text output.
    TextDelta {
        text: String,
        metadata: Option<ContentBlockMetadata>,
    },

    /// The model wants to call a tool.
    ToolUse {
        id: String,
        name: String,
        input: serde_json::Value,
        metadata: Option<ContentBlockMetadata>,
    },

    /// The model finished its turn.
    Stop {
        reason: StopReason,
        usage: TokenUsage,
    },

    /// Unrecoverable error from the provider.
    Error { message: String },
}

/// Why the model stopped generating.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StopReason {
    EndTurn,
    ToolUse,
    MaxTokens,
}

/// Token counts for a single LLM response.
#[derive(Debug, Clone, Copy, Default)]
pub struct TokenUsage {
    pub input_tokens: u64,
    pub output_tokens: u64,
}

/// A request to the LLM.
#[derive(Debug, Clone)]
pub struct CompletionRequest {
    pub model: String,
    pub messages: Vec<LlmMessage>,
    pub system: Option<String>,
    pub tools: Vec<ToolDefinition>,
    pub max_tokens: u32,
    pub temperature: Option<f64>,
    /// Provider-specific extension payload (e.g. Venice's `venice_parameters`).
    /// Providers that don't recognise it simply ignore it.
    pub extra: Option<serde_json::Value>,
}

/// A message in the LLM conversation.
#[derive(Debug, Clone)]
pub struct LlmMessage {
    pub role: LlmRole,
    pub content: Vec<ContentBlock>,
}

/// Role of a message in the LLM conversation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LlmRole {
    User,
    Assistant,
}

/// A content block within a message.
#[derive(Debug, Clone)]
pub enum ContentBlock {
    Text {
        text: String,
        metadata: Option<ContentBlockMetadata>,
    },
    ToolUse {
        id: String,
        name: String,
        input: serde_json::Value,
        metadata: Option<ContentBlockMetadata>,
    },
    ToolResult {
        tool_use_id: String,
        content: String,
        is_error: bool,
    },
}

/// Provider-specific metadata associated with a content part.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContentBlockMetadata {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gemini: Option<GeminiPartMetadata>,
}

/// Gemini/Vertex-specific metadata carried on content parts.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GeminiPartMetadata {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thought_signature: Option<String>,
}

const MAX_GEMINI_THOUGHT_SIGNATURE_BYTES: usize = 64 * 1024;

pub(crate) fn ensure_oauth_profile_kind(
    profile: &AuthProfile,
    profile_id: &str,
    provider_name: &str,
) -> Result<(), AgentError> {
    if profile.credential_kind != AuthProfileCredentialKind::OAuth {
        return Err(AgentError::Provider(format!(
            "{provider_name} auth profile \"{profile_id}\" uses {} credentials, not oauth",
            profile.credential_kind
        )));
    }
    Ok(())
}

impl ContentBlockMetadata {
    pub fn with_gemini_thought_signature(thought_signature: Option<String>) -> Option<Self> {
        thought_signature.map(|thought_signature| Self {
            gemini: Some(GeminiPartMetadata {
                thought_signature: Some(thought_signature),
            }),
        })
    }

    pub fn gemini_thought_signature(&self) -> Option<&str> {
        self.gemini
            .as_ref()
            .and_then(|gemini| gemini.thought_signature.as_deref())
    }

    pub fn has_effective_provider_metadata(&self) -> bool {
        self.gemini_thought_signature().is_some()
    }
}

pub(crate) fn apply_gemini_thought_signature(
    part: &mut Value,
    metadata: &Option<ContentBlockMetadata>,
) {
    if let Some(thought_signature) = metadata
        .as_ref()
        .and_then(ContentBlockMetadata::gemini_thought_signature)
    {
        part["thoughtSignature"] = json!(thought_signature);
    }
}

pub(crate) fn gemini_part_metadata(part: &Value) -> Option<ContentBlockMetadata> {
    let thought_signature = part
        .get("thoughtSignature")
        .and_then(|value| value.as_str())
        .and_then(|value| {
            if value.len() > MAX_GEMINI_THOUGHT_SIGNATURE_BYTES {
                tracing::warn!(
                    signature_bytes = value.len(),
                    max_signature_bytes = MAX_GEMINI_THOUGHT_SIGNATURE_BYTES,
                    "dropping oversized Gemini thoughtSignature"
                );
                None
            } else {
                Some(value.to_owned())
            }
        });
    ContentBlockMetadata::with_gemini_thought_signature(thought_signature)
}

impl ContentBlock {
    pub fn metadata(&self) -> Option<&ContentBlockMetadata> {
        match self {
            Self::Text { metadata, .. } | Self::ToolUse { metadata, .. } => metadata.as_ref(),
            Self::ToolResult { .. } => None,
        }
    }

    pub fn has_provider_metadata(&self) -> bool {
        self.metadata()
            .is_some_and(ContentBlockMetadata::has_effective_provider_metadata)
    }
}

/// A tool definition for the LLM.
#[derive(Debug, Clone)]
pub struct ToolDefinition {
    pub name: String,
    pub description: String,
    pub input_schema: serde_json::Value,
}

/// Trait for LLM providers (Anthropic, OpenAI, etc.).
///
/// Implementations send a completion request and return a channel that
/// yields streaming events until the model stops or errors.
#[async_trait]
pub trait LlmProvider: Send + Sync {
    async fn complete(
        &self,
        request: CompletionRequest,
        cancel_token: CancellationToken,
    ) -> Result<mpsc::Receiver<StreamEvent>, AgentError>;
}

pub(crate) fn summarize_http_failure_body(body: &str) -> String {
    let trimmed = body.trim();
    if trimmed.is_empty() {
        return "(empty response body)".to_string();
    }

    let summary = serde_json::from_str::<serde_json::Value>(trimmed)
        .ok()
        .and_then(|parsed| {
            parsed
                .pointer("/error/message")
                .and_then(|v| v.as_str())
                .or_else(|| parsed.get("message").and_then(|v| v.as_str()))
                .map(str::to_owned)
        })
        .unwrap_or_else(|| trimmed.to_string());

    let collapsed = summary.split_whitespace().collect::<Vec<_>>().join(" ");
    const MAX_CHARS: usize = 200;
    if collapsed.chars().count() > MAX_CHARS {
        format!(
            "{}...",
            collapsed.chars().take(MAX_CHARS).collect::<String>()
        )
    } else {
        collapsed
    }
}

/// Strip the canonical `provider:` prefix from a model identifier.
///
/// Checks each known provider prefix in turn and returns the bare model name.
/// If no prefix matches, returns the input unchanged (Anthropic fallback models).
pub(crate) fn strip_provider_prefix(model: &str) -> &str {
    if crate::agent::claude_cli::is_claude_cli_model(model) {
        crate::agent::claude_cli::strip_claude_cli_prefix(model)
    } else if crate::agent::ollama::is_ollama_model(model) {
        crate::agent::ollama::strip_ollama_prefix(model)
    } else if crate::agent::venice::is_venice_model(model) {
        crate::agent::venice::strip_venice_prefix(model)
    } else if crate::agent::vertex::is_vertex_model(model) {
        crate::agent::vertex::strip_vertex_prefix(model)
    } else if crate::agent::gemini::is_gemini_model(model) {
        crate::agent::gemini::strip_gemini_prefix(model)
    } else if crate::agent::codex::is_codex_model(model) {
        crate::agent::codex::strip_codex_prefix(model)
    } else if crate::agent::openai::is_openai_model(model) {
        crate::agent::openai::strip_openai_prefix(model)
    } else if crate::agent::bedrock::is_bedrock_model(model) {
        crate::agent::bedrock::strip_bedrock_prefix(model)
    } else if crate::agent::anthropic::is_anthropic_model(model) {
        crate::agent::anthropic::strip_anthropic_prefix(model)
    } else {
        model
    }
}

/// A provider that dispatches to Anthropic, OpenAI, Ollama, Gemini, or Bedrock
/// based on the model identifier in the request.
///
/// This allows the system to hold a single `Arc<dyn LlmProvider>` while
/// supporting multiple backend providers transparently.
pub struct MultiProvider {
    anthropic: Option<std::sync::Arc<dyn LlmProvider>>,
    openai: Option<std::sync::Arc<dyn LlmProvider>>,
    codex: Option<std::sync::Arc<dyn LlmProvider>>,
    ollama: Option<std::sync::Arc<dyn LlmProvider>>,
    gemini: Option<std::sync::Arc<dyn LlmProvider>>,
    bedrock: Option<std::sync::Arc<dyn LlmProvider>>,
    venice: Option<std::sync::Arc<dyn LlmProvider>>,
    vertex: Option<std::sync::Arc<dyn LlmProvider>>,
    claude_cli: Option<std::sync::Arc<dyn LlmProvider>>,
}

impl std::fmt::Debug for MultiProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MultiProvider")
            .field("anthropic", &self.anthropic.is_some())
            .field("openai", &self.openai.is_some())
            .field("codex", &self.codex.is_some())
            .field("ollama", &self.ollama.is_some())
            .field("gemini", &self.gemini.is_some())
            .field("bedrock", &self.bedrock.is_some())
            .field("venice", &self.venice.is_some())
            .field("vertex", &self.vertex.is_some())
            .field("claude_cli", &self.claude_cli.is_some())
            .finish()
    }
}

impl MultiProvider {
    /// Create a new multi-provider dispatcher.
    ///
    /// At least one provider should be configured; otherwise all requests
    /// will fail.
    pub fn new(
        anthropic: Option<std::sync::Arc<dyn LlmProvider>>,
        openai: Option<std::sync::Arc<dyn LlmProvider>>,
    ) -> Self {
        Self {
            anthropic,
            openai,
            codex: None,
            ollama: None,
            gemini: None,
            bedrock: None,
            venice: None,
            vertex: None,
            claude_cli: None,
        }
    }

    /// Set the Codex provider for subscription-backed OpenAI routing.
    pub fn with_codex(mut self, codex: Option<std::sync::Arc<dyn LlmProvider>>) -> Self {
        self.codex = codex;
        self
    }

    /// Set the Ollama provider for local model inference.
    pub fn with_ollama(mut self, ollama: Option<std::sync::Arc<dyn LlmProvider>>) -> Self {
        self.ollama = ollama;
        self
    }

    /// Set the Gemini provider for Google Gemini models.
    pub fn with_gemini(mut self, gemini: Option<std::sync::Arc<dyn LlmProvider>>) -> Self {
        self.gemini = gemini;
        self
    }

    /// Set the Bedrock provider for AWS Bedrock models.
    pub fn with_bedrock(mut self, bedrock: Option<std::sync::Arc<dyn LlmProvider>>) -> Self {
        self.bedrock = bedrock;
        self
    }

    /// Set the Venice provider for Venice AI models.
    pub fn with_venice(mut self, venice: Option<std::sync::Arc<dyn LlmProvider>>) -> Self {
        self.venice = venice;
        self
    }

    /// Set the Vertex provider for Google Vertex AI models.
    pub fn with_vertex(mut self, vertex: Option<std::sync::Arc<dyn LlmProvider>>) -> Self {
        self.vertex = vertex;
        self
    }

    /// Set the Claude CLI backend provider for local CLI-based inference.
    pub fn with_claude_cli(mut self, claude_cli: Option<std::sync::Arc<dyn LlmProvider>>) -> Self {
        self.claude_cli = claude_cli;
        self
    }

    /// Returns `true` if at least one provider is configured.
    pub fn has_any_provider(&self) -> bool {
        self.anthropic.is_some()
            || self.openai.is_some()
            || self.codex.is_some()
            || self.ollama.is_some()
            || self.gemini.is_some()
            || self.bedrock.is_some()
            || self.venice.is_some()
            || self.vertex.is_some()
            || self.claude_cli.is_some()
    }

    /// Select the appropriate backend provider for the given model.
    ///
    /// All providers require the canonical `provider:model` colon prefix.
    /// Bare models without a prefix are rejected.
    fn select_provider(&self, model: &str) -> Result<&dyn LlmProvider, AgentError> {
        if model.is_empty() {
            return Err(AgentError::Provider(
                "no model configured; set `agents.defaults.model` in your config \
                 (e.g. `anthropic:claude-sonnet-4-20250514`)"
                    .to_string(),
            ));
        }

        if crate::agent::claude_cli::is_claude_cli_model(model) {
            self.claude_cli.as_deref().ok_or_else(|| {
                AgentError::Provider(format!(
                    "model \"{model}\" requires Claude CLI backend, but it is not configured; \
                     set claudeCli.enabled: true in config or CLAUDE_CLI_ENABLED=1 in env"
                ))
            })
        } else if crate::agent::ollama::is_ollama_model(model) {
            self.ollama.as_deref().ok_or_else(|| {
                AgentError::Provider(format!(
                    "model \"{model}\" requires Ollama provider, but Ollama is not configured"
                ))
            })
        } else if crate::agent::venice::is_venice_model(model) {
            self.venice.as_deref().ok_or_else(|| {
                AgentError::Provider(format!(
                    "model \"{model}\" requires Venice provider, but no VENICE_API_KEY is configured"
                ))
            })
        } else if crate::agent::vertex::is_vertex_model(model) {
            self.vertex.as_deref().ok_or_else(|| {
                AgentError::Provider(format!(
                    "model \"{model}\" requires Vertex provider, but it is not configured"
                ))
            })
        } else if crate::agent::gemini::is_gemini_model(model) {
            if let Some(provider) = self.gemini.as_deref() {
                Ok(provider)
            } else if let Some(provider) = self.vertex.as_deref() {
                Ok(provider)
            } else {
                Err(AgentError::Provider(format!(
                    "model \"{model}\" requires Gemini provider, but no GOOGLE_API_KEY is configured"
                )))
            }
        } else if crate::agent::codex::is_codex_model(model) {
            self.codex.as_deref().ok_or_else(|| {
                AgentError::Provider(format!(
                    "model \"{model}\" requires Codex provider, but the Codex provider is unavailable; ensure codex.authProfile is configured, CARAPACE_CONFIG_PASSWORD is set, and the referenced OpenAI auth profile/provider config can be loaded"
                ))
            })
        } else if crate::agent::openai::is_openai_model(model) {
            self.openai.as_deref().ok_or_else(|| {
                AgentError::Provider(format!(
                    "model \"{model}\" requires OpenAI provider, but no OPENAI_API_KEY is configured"
                ))
            })
        } else if crate::agent::bedrock::is_bedrock_model(model) {
            self.bedrock.as_deref().ok_or_else(|| {
                AgentError::Provider(format!(
                    "model \"{model}\" requires Bedrock provider, but no AWS credentials are configured"
                ))
            })
        } else if crate::agent::anthropic::is_anthropic_model(model) {
            self.anthropic.as_deref().ok_or_else(|| {
                AgentError::Provider(format!(
                    "model \"{model}\" requires Anthropic provider, but neither an API key \
                     (ANTHROPIC_API_KEY env var or anthropic.apiKey config) nor \
                     anthropic.authProfile is configured"
                ))
            })
        } else {
            let hint = match model.split_once(':') {
                Some((prefix, _)) if !prefix.contains('.') => {
                    // Looks like a provider:model pattern (no dots in prefix).
                    // Bedrock native IDs like `anthropic.claude-v1:0` contain dots
                    // before the colon, so they fall to the else branch.
                    format!(
                        "model \"{model}\" uses unrecognized provider prefix \"{prefix}:\"; \
                         known prefixes are anthropic:, openai:, gemini:, vertex:, bedrock:, \
                         ollama:, codex:, venice:, claude-cli:"
                    )
                }
                _ => {
                    let suggestion = crate::migration::prefix_bare_model(model);
                    if suggestion != model {
                        format!(
                            "model \"{model}\" is missing a provider prefix; \
                             use `{suggestion}` instead"
                        )
                    } else {
                        format!(
                            "model \"{model}\" is missing a provider prefix; \
                             use the provider:model format (e.g. `anthropic:{model}`)"
                        )
                    }
                }
            };
            Err(AgentError::Provider(hint))
        }
    }
}

#[async_trait]
impl LlmProvider for MultiProvider {
    async fn complete(
        &self,
        mut request: CompletionRequest,
        cancel_token: CancellationToken,
    ) -> Result<mpsc::Receiver<StreamEvent>, AgentError> {
        let provider = self.select_provider(&request.model)?;

        // Strip the provider prefix before forwarding to the backend,
        // so each API receives the bare model name/ID.
        request.model = strip_provider_prefix(&request.model).to_string();

        provider.complete(request, cancel_token).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_multi_provider_has_any_provider() {
        let empty = MultiProvider::new(None, None);
        assert!(!empty.has_any_provider());
    }

    #[test]
    fn test_multi_provider_has_any_provider_with_ollama() {
        let provider = MultiProvider::new(None, None);
        assert!(!provider.has_any_provider());

        let ollama = crate::agent::ollama::OllamaProvider::new().unwrap();
        let provider =
            MultiProvider::new(None, None).with_ollama(Some(std::sync::Arc::new(ollama)));
        assert!(provider.has_any_provider());
    }

    #[test]
    fn test_multi_provider_select_anthropic_model() {
        let provider = MultiProvider::new(None, None);
        let err = provider.select_provider("anthropic:claude-sonnet-4-20250514");
        assert!(err.is_err());
        let msg = match err {
            Err(e) => e.to_string(),
            Ok(_) => panic!("expected error"),
        };
        assert!(
            msg.contains("Anthropic"),
            "expected Anthropic in error: {msg}"
        );
        assert!(
            msg.contains("anthropic.apiKey"),
            "expected anthropic.apiKey guidance in error: {msg}"
        );
        assert!(
            msg.contains("anthropic.authProfile"),
            "expected anthropic.authProfile guidance in error: {msg}"
        );
    }

    #[test]
    fn test_multi_provider_select_openai_model() {
        let provider = MultiProvider::new(None, None);
        let err = provider.select_provider("openai:gpt-4o");
        assert!(err.is_err());
        let msg = match err {
            Err(e) => e.to_string(),
            Ok(_) => panic!("expected error"),
        };
        assert!(msg.contains("OpenAI"), "expected OpenAI in error: {msg}");
    }

    #[test]
    fn test_bare_model_rejected_with_prefix_hint() {
        let provider = MultiProvider::new(None, None);
        let err = provider.select_provider("gpt-4o");
        assert!(err.is_err());
        let msg = match err {
            Err(e) => e.to_string(),
            Ok(_) => panic!("expected error"),
        };
        assert!(
            msg.contains("missing a provider prefix"),
            "bare model should suggest adding prefix: {msg}"
        );
    }

    #[test]
    fn test_multi_provider_select_codex_model() {
        let provider = MultiProvider::new(None, None);
        let err = provider.select_provider("codex:gpt-5.4");
        assert!(err.is_err());
        let msg = match err {
            Err(e) => e.to_string(),
            Ok(_) => panic!("expected error"),
        };
        assert!(msg.contains("Codex"), "expected Codex in error: {msg}");
    }

    #[test]
    fn test_multi_provider_select_ollama_model_colon() {
        let provider = MultiProvider::new(None, None);
        let err = provider.select_provider("ollama:llama3");
        assert!(err.is_err());
        let msg = match err {
            Err(e) => e.to_string(),
            Ok(_) => panic!("expected error"),
        };
        assert!(msg.contains("Ollama"), "expected Ollama in error: {msg}");
    }

    #[test]
    fn test_slash_prefix_rejected_as_bare_model() {
        let provider = MultiProvider::new(None, None);
        let err = provider.select_provider("ollama/mistral");
        assert!(err.is_err());
        let msg = match err {
            Err(e) => e.to_string(),
            Ok(_) => panic!("expected error"),
        };
        assert!(
            msg.contains("missing a provider prefix"),
            "slash form should be rejected as bare model: {msg}"
        );
    }

    #[test]
    fn test_multi_provider_ollama_dispatch_succeeds_when_configured() {
        let ollama = crate::agent::ollama::OllamaProvider::new().unwrap();
        let provider =
            MultiProvider::new(None, None).with_ollama(Some(std::sync::Arc::new(ollama)));
        let result = provider.select_provider("ollama:llama3");
        assert!(result.is_ok(), "expected Ok when Ollama is configured");
    }

    #[test]
    fn test_multi_provider_debug_includes_ollama() {
        let provider = MultiProvider::new(None, None);
        let debug = format!("{:?}", provider);
        assert!(
            debug.contains("ollama"),
            "debug output should include ollama: {debug}"
        );
    }

    #[test]
    fn test_multi_provider_select_gemini_model() {
        let provider = MultiProvider::new(None, None);
        let err = provider.select_provider("gemini:gemini-2.0-flash");
        assert!(err.is_err());
        let msg = match err {
            Err(e) => e.to_string(),
            Ok(_) => panic!("expected error"),
        };
        assert!(msg.contains("Gemini"), "expected Gemini in error: {msg}");
    }

    #[test]
    fn test_multi_provider_gemini_dispatch_succeeds_when_configured() {
        let gemini = crate::agent::gemini::GeminiProvider::new("test-key".to_string()).unwrap();
        let provider =
            MultiProvider::new(None, None).with_gemini(Some(std::sync::Arc::new(gemini)));
        let result = provider.select_provider("gemini:gemini-2.0-flash");
        assert!(result.is_ok(), "expected Ok when Gemini is configured");
    }

    #[test]
    fn test_multi_provider_has_any_provider_with_gemini() {
        let gemini = crate::agent::gemini::GeminiProvider::new("test-key".to_string()).unwrap();
        let provider =
            MultiProvider::new(None, None).with_gemini(Some(std::sync::Arc::new(gemini)));
        assert!(provider.has_any_provider());
    }

    #[test]
    fn test_multi_provider_has_any_provider_with_codex() {
        let temp = tempfile::tempdir().unwrap();
        let profile_store = std::sync::Arc::new(
            crate::auth::profiles::ProfileStore::from_env(temp.path().to_path_buf()).unwrap(),
        );
        let provider = crate::agent::codex::CodexProvider::with_oauth_profile(
            profile_store,
            "openai-abc123".to_string(),
            crate::auth::profiles::OAuthProvider::OpenAI
                .default_config(
                    "client-id",
                    "client-secret",
                    "http://127.0.0.1:3000/auth/callback",
                )
                .unwrap(),
        )
        .unwrap();
        let multi = MultiProvider::new(None, None).with_codex(Some(std::sync::Arc::new(provider)));
        assert!(multi.has_any_provider());
    }

    #[test]
    fn test_multi_provider_debug_includes_gemini() {
        let provider = MultiProvider::new(None, None);
        let debug = format!("{:?}", provider);
        assert!(
            debug.contains("gemini"),
            "debug output should include gemini: {debug}"
        );
    }

    // ==================== Bedrock routing tests ====================

    #[test]
    fn test_multi_provider_select_bedrock_model_colon_prefix() {
        let provider = MultiProvider::new(None, None);
        let err = provider.select_provider("bedrock:anthropic.claude-3-sonnet");
        assert!(err.is_err());
        let msg = match err {
            Err(e) => e.to_string(),
            Ok(_) => panic!("expected error"),
        };
        assert!(msg.contains("Bedrock"), "expected Bedrock in error: {msg}");
    }

    #[test]
    fn test_bare_bedrock_native_id_gets_missing_prefix_hint() {
        let provider = MultiProvider::new(None, None);
        let err = provider.select_provider("anthropic.claude-3-sonnet-20240229-v1:0");
        assert!(err.is_err());
        let msg = match err {
            Err(e) => e.to_string(),
            Ok(_) => panic!("expected error"),
        };
        // The colon is embedded in the version suffix, not a provider prefix.
        // Error should suggest bedrock: prefix, not anthropic:.
        assert!(
            msg.contains("missing a provider prefix"),
            "Bedrock native ID should get missing-prefix hint: {msg}"
        );
        assert!(
            msg.contains("bedrock:"),
            "hint should suggest bedrock: prefix: {msg}"
        );
    }

    #[test]
    fn test_unrecognized_provider_prefix_gives_clear_error() {
        let provider = MultiProvider::new(None, None);
        let err = provider.select_provider("mistral:mixtral");
        assert!(err.is_err());
        let msg = match err {
            Err(e) => e.to_string(),
            Ok(_) => panic!("expected error"),
        };
        assert!(
            msg.contains("unrecognized provider prefix"),
            "unknown prefix should give clear error: {msg}"
        );
        assert!(
            msg.contains("known prefixes"),
            "error should list known prefixes: {msg}"
        );

        // Long prefix (>10 chars) should also get "unrecognized prefix", not "missing prefix"
        let err = provider.select_provider("claude-code:opus");
        let msg = match err {
            Err(e) => e.to_string(),
            Ok(_) => panic!("expected error"),
        };
        assert!(
            msg.contains("unrecognized provider prefix"),
            "long unrecognized prefix should still say 'unrecognized': {msg}"
        );
    }

    #[test]
    fn test_multi_provider_bedrock_dispatch_succeeds_when_configured() {
        let bedrock = crate::agent::bedrock::BedrockProvider::new(
            "us-east-1".to_string(),
            "AKID".to_string(),
            "secret".to_string(),
        )
        .unwrap();
        let provider =
            MultiProvider::new(None, None).with_bedrock(Some(std::sync::Arc::new(bedrock)));
        let result = provider.select_provider("bedrock:anthropic.claude-3-sonnet");
        assert!(result.is_ok(), "expected Ok when Bedrock is configured");
    }

    #[test]
    fn test_multi_provider_debug_includes_bedrock() {
        let provider = MultiProvider::new(None, None);
        let debug = format!("{:?}", provider);
        assert!(
            debug.contains("bedrock"),
            "debug output should include bedrock: {debug}"
        );
    }

    #[test]
    fn test_multi_provider_has_any_provider_with_bedrock() {
        let bedrock = crate::agent::bedrock::BedrockProvider::new(
            "us-east-1".to_string(),
            "AKID".to_string(),
            "secret".to_string(),
        )
        .unwrap();
        let provider =
            MultiProvider::new(None, None).with_bedrock(Some(std::sync::Arc::new(bedrock)));
        assert!(provider.has_any_provider());
    }

    #[test]
    fn test_multi_provider_vertex_dispatch_succeeds_when_configured() {
        let vertex = crate::agent::vertex::VertexProvider::new(
            "my-project".to_string(),
            "us-central1".to_string(),
            None,
        )
        .unwrap();
        let provider =
            MultiProvider::new(None, None).with_vertex(Some(std::sync::Arc::new(vertex)));
        let result = provider.select_provider("vertex:gemini-2.0-flash");
        assert!(result.is_ok(), "expected Ok when Vertex is configured");
    }

    #[test]
    fn test_empty_model_gives_clear_error() {
        let provider = MultiProvider::new(None, None);
        let err = provider.select_provider("");
        assert!(err.is_err());
        let msg = match err {
            Err(e) => e.to_string(),
            Ok(_) => panic!("expected error"),
        };
        assert!(
            msg.contains("no model configured"),
            "empty model should give configuration guidance: {msg}"
        );
    }

    #[test]
    fn test_bare_model_without_prefix_rejected() {
        let provider = MultiProvider::new(None, None);
        let err = provider.select_provider("claude-sonnet-4-20250514");
        assert!(err.is_err());
        let msg = match err {
            Err(e) => e.to_string(),
            Ok(_) => panic!("expected error"),
        };
        assert!(
            msg.contains("missing a provider prefix"),
            "bare model should suggest adding prefix: {msg}"
        );
    }

    #[test]
    fn test_summarize_http_failure_body_prefers_structured_message() {
        let summary = summarize_http_failure_body(
            r#"{"error":{"message":"quota exceeded for project my-project","status":"RESOURCE_EXHAUSTED"}}"#,
        );
        assert_eq!(summary, "quota exceeded for project my-project");
    }

    #[test]
    fn test_summarize_http_failure_body_truncates_long_plaintext() {
        let summary = summarize_http_failure_body(&"x".repeat(300));
        assert!(
            summary.len() <= 203,
            "summary should be truncated: {}",
            summary.len()
        );
        assert!(summary.ends_with("..."));
    }

    #[test]
    fn test_strip_provider_prefix() {
        assert_eq!(strip_provider_prefix("openai:gpt-4o"), "gpt-4o");
        assert_eq!(strip_provider_prefix("ollama:llama3"), "llama3");
        assert_eq!(strip_provider_prefix("venice:deepseek-r1"), "deepseek-r1");
        assert_eq!(
            strip_provider_prefix("bedrock:anthropic.claude-3-sonnet"),
            "anthropic.claude-3-sonnet"
        );
        assert_eq!(
            strip_provider_prefix("vertex:gemini-2.0-flash"),
            "gemini-2.0-flash"
        );
        assert_eq!(
            strip_provider_prefix("gemini:gemini-2.0-flash"),
            "gemini-2.0-flash"
        );
        assert_eq!(strip_provider_prefix("codex:gpt-5.4"), "gpt-5.4");
        assert_eq!(
            strip_provider_prefix("anthropic:claude-sonnet-4-20250514"),
            "claude-sonnet-4-20250514"
        );
        assert_eq!(strip_provider_prefix("claude-cli:opus"), "opus");
        // Unrecognized input passes through unchanged
        assert_eq!(strip_provider_prefix("unknown"), "unknown");
    }

    #[test]
    fn test_gemini_part_metadata_drops_oversized_thought_signature() {
        let oversized = "a".repeat(MAX_GEMINI_THOUGHT_SIGNATURE_BYTES + 1);
        let part = json!({
            "text": "Hello",
            "thoughtSignature": oversized,
        });

        assert!(
            gemini_part_metadata(&part).is_none(),
            "oversized thought signatures should be dropped instead of persisted"
        );
    }
}
