//! LLM provider trait and common types.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::agent::AgentError;

/// A streaming event from the LLM.
#[derive(Debug, Clone)]
pub enum StreamEvent {
    /// Incremental text output.
    TextDelta { text: String },

    /// The model wants to call a tool.
    ToolUse {
        id: String,
        name: String,
        input: serde_json::Value,
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
    },
    ToolUse {
        id: String,
        name: String,
        input: serde_json::Value,
    },
    ToolResult {
        tool_use_id: String,
        content: String,
        is_error: bool,
    },
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

/// A provider that dispatches to Anthropic, OpenAI, Ollama, Gemini, Bedrock, Azure OpenAI, Vertex AI,
/// or OpenAI-compatible providers (DeepSeek, Qwen, Moonshot, Minimax, GLM, xAI) based on the model identifier in the request.
///
/// This allows the system to hold a single `Arc<dyn LlmProvider>` while
/// supporting multiple backend providers transparently.
pub struct MultiProvider {
    anthropic: Option<std::sync::Arc<dyn LlmProvider>>,
    openai: Option<std::sync::Arc<dyn LlmProvider>>,
    ollama: Option<std::sync::Arc<dyn LlmProvider>>,
    gemini: Option<std::sync::Arc<dyn LlmProvider>>,
    bedrock: Option<std::sync::Arc<dyn LlmProvider>>,
    venice: Option<std::sync::Arc<dyn LlmProvider>>,
    azure: Option<std::sync::Arc<dyn LlmProvider>>,
    vertex: Option<std::sync::Arc<dyn LlmProvider>>,
    // OpenAI-compatible providers: deepseek, qwen, moonshot, minimax, glm, xai
    openai_compatible: Option<std::sync::Arc<dyn LlmProvider>>,
}

impl std::fmt::Debug for MultiProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MultiProvider")
            .field("anthropic", &self.anthropic.is_some())
            .field("openai", &self.openai.is_some())
            .field("ollama", &self.ollama.is_some())
            .field("gemini", &self.gemini.is_some())
            .field("bedrock", &self.bedrock.is_some())
            .field("venice", &self.venice.is_some())
            .field("azure", &self.azure.is_some())
            .field("vertex", &self.vertex.is_some())
            .field("openai_compatible", &self.openai_compatible.is_some())
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
            ollama: None,
            gemini: None,
            bedrock: None,
            venice: None,
            azure: None,
            vertex: None,
            openai_compatible: None,
        }
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

    /// Set the Azure OpenAI provider for Azure-deployed models.
    pub fn with_azure(mut self, azure: Option<std::sync::Arc<dyn LlmProvider>>) -> Self {
        self.azure = azure;
        self
    }

    /// Set the Vertex AI provider for Google Cloud Vertex AI models.
    pub fn with_vertex(mut self, vertex: Option<std::sync::Arc<dyn LlmProvider>>) -> Self {
        self.vertex = vertex;
        self
    }

    /// Set the OpenAI-compatible provider for DeepSeek, Qwen, Moonshot, Minimax, GLM, xAI models.
    pub fn with_openai_compatible(mut self, openai_compatible: Option<std::sync::Arc<dyn LlmProvider>>) -> Self {
        self.openai_compatible = openai_compatible;
        self
    }

    /// Returns `true` if at least one provider is configured.
    pub fn has_any_provider(&self) -> bool {
        self.anthropic.is_some()
            || self.openai.is_some()
            || self.ollama.is_some()
            || self.gemini.is_some()
            || self.bedrock.is_some()
            || self.venice.is_some()
            || self.azure.is_some()
            || self.vertex.is_some()
            || self.openai_compatible.is_some()
    }

    /// Select the appropriate backend provider for the given model.
    ///
    /// Dispatch order:
    /// 1. Models prefixed with `ollama:` or `ollama/` -> Ollama
    /// 2. Models prefixed with `venice:` -> Venice
    /// 3. Models matching Gemini patterns (gemini-*, gemini/*, models/gemini-*) -> Gemini
    /// 4. Models matching OpenAI patterns (gpt-*, o1-*, etc.) -> OpenAI
    /// 5. Models matching Bedrock patterns (bedrock:*, anthropic.claude-*, etc.) -> Bedrock
    /// 6. Models prefixed with `azure:` -> Azure OpenAI
    /// 7. Models prefixed with `vertex:` -> Vertex AI
    /// 8. OpenAI-compatible providers (deepseek:, qwen:, moonshot:, kimi:, minimax:, glm:, z.ai:, xai:, grok:) -> OpenAI-Compatible
    /// 9. Everything else -> Anthropic (default)
    fn select_provider(&self, model: &str) -> Result<&dyn LlmProvider, AgentError> {
        if crate::agent::ollama::is_ollama_model(model) {
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
        } else if crate::agent::gemini::is_gemini_model(model) {
            self.gemini.as_deref().ok_or_else(|| {
                AgentError::Provider(format!(
                    "model \"{model}\" requires Gemini provider, but no GOOGLE_API_KEY is configured"
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
        } else if crate::agent::azure_openai::is_azure_openai_model(model) {
            self.azure.as_deref().ok_or_else(|| {
                AgentError::Provider(format!(
                    "model \"{model}\" requires Azure OpenAI provider, but no AZURE_OPENAI_API_KEY is configured"
                ))
            })
        } else if crate::agent::vertex::is_vertex_model(model) {
            self.vertex.as_deref().ok_or_else(|| {
                AgentError::Provider(format!(
                    "model \"{model}\" requires Vertex AI provider, but no GCP credentials are configured"
                ))
            })
        } else if is_openai_compatible_model(model) {
            self.openai_compatible.as_deref().ok_or_else(|| {
                AgentError::Provider(format!(
                    "model \"{model}\" requires an OpenAI-compatible provider (DeepSeek, Qwen, Moonshot, Minimax, GLM, xAI), but none is configured"
                ))
            })
        } else {
            // Default to Anthropic for claude-* and unknown models
            self.anthropic.as_deref().ok_or_else(|| {
                AgentError::Provider(format!(
                    "model \"{model}\" requires Anthropic provider, but no ANTHROPIC_API_KEY is configured"
                ))
            })
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

        // Strip the ollama: or ollama/ prefix before forwarding to the provider,
        // so the Ollama server receives the bare model name (e.g. "llama3").
        if crate::agent::ollama::is_ollama_model(&request.model) {
            request.model = crate::agent::ollama::strip_ollama_prefix(&request.model).to_string();
        }

        // Strip the venice: prefix before forwarding to the provider,
        // so the Venice API receives the bare model name (e.g. "llama-3.3-70b").
        if crate::agent::venice::is_venice_model(&request.model) {
            request.model = crate::agent::venice::strip_venice_prefix(&request.model).to_string();
        }

        // Strip the gemini/ or models/ prefix before forwarding to the provider,
        // so the Gemini API receives the bare model name (e.g. "gemini-2.0-flash").
        if crate::agent::gemini::is_gemini_model(&request.model) {
            request.model = crate::agent::gemini::strip_gemini_prefix(&request.model).to_string();
        }

        // Strip the bedrock: or bedrock/ prefix before forwarding to the provider,
        // so the Bedrock API receives the bare model ID (e.g. "anthropic.claude-3-sonnet-20240229-v1:0").
        if crate::agent::bedrock::is_bedrock_model(&request.model) {
            request.model = crate::agent::bedrock::strip_bedrock_prefix(&request.model).to_string();
        }

        // Strip the azure: prefix before forwarding to the provider,
        // so the Azure API receives the bare deployment name (e.g. "gpt-4").
        if crate::agent::azure_openai::is_azure_openai_model(&request.model) {
            request.model = crate::agent::azure_openai::strip_azure_prefix(&request.model).to_string();
        }

        // Strip the vertex: prefix before forwarding to the provider,
        // so the Vertex API receives the bare model name (e.g. "gemini-2.0-flash").
        if crate::agent::vertex::is_vertex_model(&request.model) {
            request.model = crate::agent::vertex::strip_vertex_prefix(&request.model).to_string();
        }

        // Strip OpenAI-compatible prefixes (deepseek:, qwen:, moonshot:, minimax:, glm:, xai:, grok:)
        if is_openai_compatible_model(&request.model) {
            request.model = strip_openai_compatible_prefix(&request.model).to_string();
        }

        provider.complete(request, cancel_token).await
    }
}

/// Check if a model should be routed to an OpenAI-compatible provider.
/// Matches: deepseek:, qwen:, moonshot:, kimi:, minimax:, glm:, z.ai:, zai:, xai:, grok:, openrouter:
fn is_openai_compatible_model(model: &str) -> bool {
    crate::agent::openai_compatible::is_deepseek_model(model)
        || crate::agent::openai_compatible::is_qwen_model(model)
        || crate::agent::openai_compatible::is_moonshot_model(model)
        || crate::agent::openai_compatible::is_minimax_model(model)
        || crate::agent::openai_compatible::is_glm_model(model)
        || crate::agent::openai_compatible::is_xai_model(model)
        || crate::agent::openai_compatible::is_openrouter_model(model)
}

/// Strip the provider-specific prefix from an OpenAI-compatible model.
fn strip_openai_compatible_prefix(model: &str) -> &str {
    if crate::agent::openai_compatible::is_deepseek_model(model) {
        crate::agent::openai_compatible::strip_deepseek_prefix(model)
    } else if crate::agent::openai_compatible::is_qwen_model(model) {
        crate::agent::openai_compatible::strip_qwen_prefix(model)
    } else if crate::agent::openai_compatible::is_moonshot_model(model) {
        crate::agent::openai_compatible::strip_moonshot_prefix(model)
    } else if crate::agent::openai_compatible::is_minimax_model(model) {
        crate::agent::openai_compatible::strip_minimax_prefix(model)
    } else if crate::agent::openai_compatible::is_glm_model(model) {
        crate::agent::openai_compatible::strip_glm_prefix(model)
    } else if crate::agent::openai_compatible::is_xai_model(model) {
        crate::agent::openai_compatible::strip_xai_prefix(model)
    } else if crate::agent::openai_compatible::is_openrouter_model(model) {
        crate::agent::openai_compatible::strip_openrouter_prefix(model)
    } else {
        model
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
        let err = provider.select_provider("claude-sonnet-4-20250514");
        assert!(err.is_err());
        let msg = match err {
            Err(e) => e.to_string(),
            Ok(_) => panic!("expected error"),
        };
        assert!(
            msg.contains("Anthropic"),
            "expected Anthropic in error: {msg}"
        );
    }

    #[test]
    fn test_multi_provider_select_openai_model() {
        let provider = MultiProvider::new(None, None);
        let err = provider.select_provider("gpt-4o");
        assert!(err.is_err());
        let msg = match err {
            Err(e) => e.to_string(),
            Ok(_) => panic!("expected error"),
        };
        assert!(msg.contains("OpenAI"), "expected OpenAI in error: {msg}");
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
    fn test_multi_provider_select_ollama_model_slash() {
        let provider = MultiProvider::new(None, None);
        let err = provider.select_provider("ollama/mistral");
        assert!(err.is_err());
        let msg = match err {
            Err(e) => e.to_string(),
            Ok(_) => panic!("expected error"),
        };
        assert!(msg.contains("Ollama"), "expected Ollama in error: {msg}");
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
        let err = provider.select_provider("gemini-2.0-flash");
        assert!(err.is_err());
        let msg = match err {
            Err(e) => e.to_string(),
            Ok(_) => panic!("expected error"),
        };
        assert!(msg.contains("Gemini"), "expected Gemini in error: {msg}");
    }

    #[test]
    fn test_multi_provider_select_gemini_slash_model() {
        let provider = MultiProvider::new(None, None);
        let err = provider.select_provider("gemini/gemini-2.0-flash");
        assert!(err.is_err());
        let msg = match err {
            Err(e) => e.to_string(),
            Ok(_) => panic!("expected error"),
        };
        assert!(msg.contains("Gemini"), "expected Gemini in error: {msg}");
    }

    #[test]
    fn test_multi_provider_select_models_gemini_prefix() {
        let provider = MultiProvider::new(None, None);
        let err = provider.select_provider("models/gemini-1.5-pro");
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
        let result = provider.select_provider("gemini-2.0-flash");
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
    fn test_multi_provider_select_bedrock_model_native_id() {
        let provider = MultiProvider::new(None, None);
        let err = provider.select_provider("anthropic.claude-3-sonnet-20240229-v1:0");
        assert!(err.is_err());
        let msg = match err {
            Err(e) => e.to_string(),
            Ok(_) => panic!("expected error"),
        };
        assert!(msg.contains("Bedrock"), "expected Bedrock in error: {msg}");
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
}
