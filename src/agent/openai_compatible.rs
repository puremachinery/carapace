//! OpenAI Compatible Provider
//!
//! A generic provider for any OpenAI-compatible API. This wraps the OpenAI provider
//! with a custom base URL, allowing support for many providers like DeepSeek, Qwen,
//! Moonshot, Minimax, GLM, xAI, and others.
//!
//! Uses the same `/v1/chat/completions` endpoint and SSE format as OpenAI.

use async_trait::async_trait;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::agent::openai::OpenAiProvider;
use crate::agent::provider::*;
use crate::agent::AgentError;

/// OpenAI Compatible Provider.
///
/// Wraps the OpenAI provider with a custom base URL to support any
/// OpenAI-compatible API (DeepSeek, Qwen, Moonshot, Minimax, GLM, xAI, etc.).
#[derive(Debug)]
pub struct OpenAiCompatibleProvider {
    inner: OpenAiProvider,
    provider_name: String,
}

impl OpenAiCompatibleProvider {
    /// Create a new OpenAI-compatible provider.
    ///
    /// - `api_key`: API key for the provider
    /// - `base_url`: Base URL for the OpenAI-compatible API
    /// - `provider_name`: Display name for the provider (e.g., "DeepSeek", "Qwen")
    pub fn new(
        api_key: String,
        base_url: String,
        provider_name: String,
    ) -> Result<Self, AgentError> {
        if api_key.trim().is_empty() {
            return Err(AgentError::InvalidApiKey(
                "API key must not be empty".to_string(),
            ));
        }
        if base_url.trim().is_empty() {
            return Err(AgentError::InvalidBaseUrl(
                "Base URL must not be empty".to_string(),
            ));
        }

        let inner = OpenAiProvider::new(api_key)?
            .with_base_url(base_url)?;

        Ok(Self {
            inner,
            provider_name,
        })
    }

    /// Returns the provider name.
    pub fn provider_name(&self) -> &str {
        &self.provider_name
    }
}

#[async_trait]
impl LlmProvider for OpenAiCompatibleProvider {
    async fn complete(
        &self,
        request: CompletionRequest,
        cancel_token: CancellationToken,
    ) -> Result<mpsc::Receiver<StreamEvent>, AgentError> {
        self.inner.complete(request, cancel_token).await
    }
}

/// Determine whether a model identifier should route to DeepSeek.
pub fn is_deepseek_model(model: &str) -> bool {
    let lower = model.to_lowercase();
    lower.starts_with("deepseek:")
}

/// Strip the `deepseek:` prefix from a model identifier.
pub fn strip_deepseek_prefix(model: &str) -> &str {
    if let Some(rest) = model.strip_prefix("deepseek:") {
        rest
    } else if let Some(rest) = model.strip_prefix("Deepseek:") {
        rest
    } else {
        model
    }
}

/// Determine whether a model identifier should route to Qwen (Alibaba).
pub fn is_qwen_model(model: &str) -> bool {
    let lower = model.to_lowercase();
    lower.starts_with("qwen:")
}

/// Strip the `qwen:` prefix from a model identifier.
pub fn strip_qwen_prefix(model: &str) -> &str {
    if let Some(rest) = model.strip_prefix("qwen:") {
        rest
    } else if let Some(rest) = model.strip_prefix("Qwen:") {
        rest
    } else {
        model
    }
}

/// Determine whether a model identifier should route to Moonshot (Kimi).
pub fn is_moonshot_model(model: &str) -> bool {
    let lower = model.to_lowercase();
    lower.starts_with("moonshot:") || lower.starts_with("kimi:")
}

/// Strip the `moonshot:` or `kimi:` prefix from a model identifier.
pub fn strip_moonshot_prefix(model: &str) -> &str {
    if let Some(rest) = model.strip_prefix("moonshot:") {
        rest
    } else if let Some(rest) = model.strip_prefix("moonshot:") {
        rest
    } else if let Some(rest) = model.strip_prefix("kimi:") {
        rest
    } else if let Some(rest) = model.strip_prefix("Kimi:") {
        rest
    } else {
        model
    }
}

/// Determine whether a model identifier should route to Minimax.
pub fn is_minimax_model(model: &str) -> bool {
    let lower = model.to_lowercase();
    lower.starts_with("minimax:")
}

/// Strip the `minimax:` prefix from a model identifier.
pub fn strip_minimax_prefix(model: &str) -> &str {
    if let Some(rest) = model.strip_prefix("minimax:") {
        rest
    } else if let Some(rest) = model.strip_prefix("Minimax:") {
        rest
    } else {
        model
    }
}

/// Determine whether a model identifier should route to GLM (Z.ai - zhipu.ai).
pub fn is_glm_model(model: &str) -> bool {
    let lower = model.to_lowercase();
    lower.starts_with("glm:") || lower.starts_with("z.ai:") || lower.starts_with("zai:")
}

/// Strip the `glm:`, `z.ai:`, or `zai:` prefix from a model identifier.
pub fn strip_glm_prefix(model: &str) -> &str {
    if let Some(rest) = model.strip_prefix("glm:") {
        rest
    } else if let Some(rest) = model.strip_prefix("GLM:") {
        rest
    } else if let Some(rest) = model.strip_prefix("z.ai:") {
        rest
    } else if let Some(rest) = model.strip_prefix("zai:") {
        rest
    } else {
        model
    }
}

/// Determine whether a model identifier should route to xAI (Grok).
pub fn is_xai_model(model: &str) -> bool {
    let lower = model.to_lowercase();
    lower.starts_with("xai:") || lower.starts_with("grok:")
}

/// Strip the `xai:` or `grok:` prefix from a model identifier.
pub fn strip_xai_prefix(model: &str) -> &str {
    if let Some(rest) = model.strip_prefix("xai:") {
        rest
    } else if let Some(rest) = model.strip_prefix("Xai:") {
        rest
    } else if let Some(rest) = model.strip_prefix("grok:") {
        rest
    } else if let Some(rest) = model.strip_prefix("Grok:") {
        rest
    } else {
        model
    }
}

/// Determine whether a model identifier should route to OpenRouter.
pub fn is_openrouter_model(model: &str) -> bool {
    let lower = model.to_lowercase();
    lower.starts_with("openrouter:")
}

/// Strip the `openrouter:` prefix from a model identifier.
pub fn strip_openrouter_prefix(model: &str) -> &str {
    if let Some(rest) = model.strip_prefix("openrouter:") {
        rest
    } else if let Some(rest) = model.strip_prefix("OpenRouter:") {
        rest
    } else {
        model
    }
}
pub fn strip_xai_prefix(model: &str) -> &str {
    if let Some(rest) = model.strip_prefix("xai:") {
        rest
    } else if let Some(rest) = model.strip_prefix("Xai:") {
        rest
    } else if let Some(rest) = model.strip_prefix("grok:") {
        rest
    } else if let Some(rest) = model.strip_prefix("Grok:") {
        rest
    } else {
        model
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_deepseek_model() {
        assert!(is_deepseek_model("deepseek:deepseek-chat"));
        assert!(is_deepseek_model("deepseek:deepseek-coder"));
        assert!(is_deepseek_model("Deepseek:deepseek-chat"));
        assert!(!is_deepseek_model("gpt-4o"));
    }

    #[test]
    fn test_strip_deepseek_prefix() {
        assert_eq!(strip_deepseek_prefix("deepseek:deepseek-chat"), "deepseek-chat");
        assert_eq!(strip_deepseek_prefix("deepseek-chat"), "deepseek-chat");
    }

    #[test]
    fn test_is_qwen_model() {
        assert!(is_qwen_model("qwen:qwen-turbo"));
        assert!(is_qwen_model("qwen:qwen-plus"));
        assert!(!is_qwen_model("gpt-4o"));
    }

    #[test]
    fn test_is_moonshot_model() {
        assert!(is_moonshot_model("moonshot:kimi-k2.5"));
        assert!(is_moonshot_model("kimi:kimi-k2-thinking"));
        assert!(!is_moonshot_model("gpt-4o"));
    }

    #[test]
    fn test_is_minimax_model() {
        assert!(is_minimax_model("minimax:minimax-m2"));
        assert!(!is_minimax_model("gpt-4o"));
    }

    #[test]
    fn test_is_glm_model() {
        assert!(is_glm_model("glm:glm-4"));
        assert!(is_glm_model("glm:glm-5"));
        assert!(is_glm_model("z.ai:glm-4"));
        assert!(is_glm_model("zai:glm-4"));
        assert!(!is_glm_model("gpt-4o"));
    }

    #[test]
    fn test_is_xai_model() {
        assert!(is_xai_model("xai:grok-2"));
        assert!(is_xai_model("grok:grok-2"));
        assert!(!is_xai_model("gpt-4o"));
    }

    #[test]
    fn test_is_openrouter_model() {
        assert!(is_openrouter_model("openrouter:anthropic/claude-3.5-sonnet"));
        assert!(is_openrouter_model("openrouter:google/gemini-pro"));
        assert!(is_openrouter_model("OpenRouter:meta/llama-3"));
        assert!(!is_openrouter_model("gpt-4o"));
    }

    #[test]
    fn test_strip_openrouter_prefix() {
        assert_eq!(strip_openrouter_prefix("openrouter:anthropic/claude-3.5-sonnet"), "anthropic/claude-3.5-sonnet");
        assert_eq!(strip_openrouter_prefix("anthropic/claude-3.5-sonnet"), "anthropic/claude-3.5-sonnet");
    }
}
