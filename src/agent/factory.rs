//! Provider construction factory.
//!
//! Extracts the ~200 lines of provider setup from `main.rs` into a reusable
//! function, and provides fingerprinting for change detection during hot-reload.

use std::sync::Arc;

use serde_json::Value;
use sha2::{Digest, Sha256};
use tracing::{info, warn};

use crate::agent;
use crate::agent::provider::MultiProvider;

/// Try to build a provider from an API key + optional base URL.
///
/// This is the shared pattern for Anthropic, OpenAI, and Gemini providers:
/// resolve an API key (env var or config), optionally apply a base URL,
/// and wrap in `Arc<dyn LlmProvider>`.
fn try_build_provider<P: agent::LlmProvider + 'static>(
    api_key: Option<String>,
    base_url: Option<String>,
    provider_name: &str,
    make: impl FnOnce(String) -> Result<P, agent::AgentError>,
    set_base_url: impl FnOnce(P, String) -> Result<P, agent::AgentError>,
) -> Result<Option<Arc<dyn agent::LlmProvider>>, Box<dyn std::error::Error>> {
    let key = match api_key {
        Some(k) => k,
        None => return Ok(None),
    };
    match make(key) {
        Ok(provider) => {
            let provider = if let Some(url) = base_url {
                match set_base_url(provider, url) {
                    Ok(p) => p,
                    Err(e) => {
                        warn!("Invalid {}_BASE_URL: {}", provider_name.to_uppercase(), e);
                        return Err(e.into());
                    }
                }
            } else {
                provider
            };
            info!("LLM provider configured: {}", provider_name);
            Ok(Some(Arc::new(provider)))
        }
        Err(e) => {
            warn!("Failed to configure {} provider: {}", provider_name, e);
            Ok(None)
        }
    }
}

/// Try to build the Ollama provider with optional base URL, API key, and
/// a non-blocking connectivity check.
fn try_build_ollama_provider(
    cfg: &Value,
) -> Result<Option<Arc<dyn agent::LlmProvider>>, Box<dyn std::error::Error>> {
    let ollama_providers_cfg = cfg.get("providers").and_then(|v| v.get("ollama"));
    let ollama_base_url = std::env::var("OLLAMA_BASE_URL").ok().or_else(|| {
        ollama_providers_cfg
            .and_then(|v| v.get("baseUrl"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    });
    let ollama_api_key = ollama_providers_cfg
        .and_then(|v| v.get("apiKey"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let ollama_explicitly_configured = ollama_base_url.is_some() || ollama_providers_cfg.is_some();
    if !ollama_explicitly_configured {
        return Ok(None);
    }

    match agent::ollama::OllamaProvider::new() {
        Ok(provider) => {
            let provider = if let Some(url) = ollama_base_url {
                match provider.with_base_url(url) {
                    Ok(p) => p,
                    Err(e) => {
                        warn!("Invalid OLLAMA_BASE_URL: {}", e);
                        return Err(e.into());
                    }
                }
            } else {
                provider
            };
            let provider = if let Some(key) = ollama_api_key {
                provider.with_api_key(key)
            } else {
                provider
            };
            info!("LLM provider configured: Ollama ({})", provider.base_url());
            // Connectivity check (non-blocking, best-effort)
            let provider = Arc::new(provider);
            let provider_clone = Arc::clone(&provider);
            tokio::spawn(async move {
                match provider_clone.check_connectivity().await {
                    Ok(models) => {
                        if models.is_empty() {
                            info!("Ollama connected (no models pulled yet)");
                        } else {
                            info!("Ollama connected, available models: {}", models.join(", "));
                        }
                    }
                    Err(e) => {
                        warn!(
                            "Ollama connectivity check failed: {} (provider will remain configured, requests may fail until Ollama is reachable)",
                            e
                        );
                    }
                }
            });
            Ok(Some(provider))
        }
        Err(e) => {
            warn!("Failed to configure Ollama provider: {}", e);
            Ok(None)
        }
    }
}

/// Build all configured LLM providers from the config and environment.
///
/// Returns `None` if no providers are configured.
pub fn build_providers(cfg: &Value) -> Result<Option<MultiProvider>, Box<dyn std::error::Error>> {
    // Anthropic
    let anthropic_api_key = std::env::var("ANTHROPIC_API_KEY").ok().or_else(|| {
        cfg.get("anthropic")
            .and_then(|v| v.get("apiKey"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    });
    let anthropic_base_url = std::env::var("ANTHROPIC_BASE_URL").ok().or_else(|| {
        cfg.get("anthropic")
            .and_then(|v| v.get("baseUrl"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    });
    let anthropic_provider = try_build_provider(
        anthropic_api_key,
        anthropic_base_url,
        "Anthropic",
        agent::anthropic::AnthropicProvider::new,
        |p, url| p.with_base_url(url),
    )?;

    // OpenAI
    let openai_api_key = std::env::var("OPENAI_API_KEY").ok().or_else(|| {
        cfg.get("openai")
            .and_then(|v| v.get("apiKey"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    });
    let openai_base_url = std::env::var("OPENAI_BASE_URL").ok().or_else(|| {
        cfg.get("openai")
            .and_then(|v| v.get("baseUrl"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    });
    let openai_provider = try_build_provider(
        openai_api_key,
        openai_base_url,
        "OpenAI",
        agent::openai::OpenAiProvider::new,
        |p, url| p.with_base_url(url),
    )?;

    // Ollama
    let ollama_provider = try_build_ollama_provider(cfg)?;

    // Gemini
    let google_api_key = std::env::var("GOOGLE_API_KEY").ok().or_else(|| {
        cfg.get("google")
            .and_then(|v| v.get("apiKey"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    });
    let google_base_url = std::env::var("GOOGLE_API_BASE_URL").ok().or_else(|| {
        cfg.get("google")
            .and_then(|v| v.get("baseUrl"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    });
    let gemini_provider = try_build_provider(
        google_api_key,
        google_base_url,
        "Gemini",
        agent::gemini::GeminiProvider::new,
        |p, url| p.with_base_url(url),
    )?;

    // Venice
    let venice_api_key = std::env::var("VENICE_API_KEY").ok().or_else(|| {
        cfg.get("venice")
            .and_then(|v| v.get("apiKey"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    });
    let venice_base_url = std::env::var("VENICE_BASE_URL").ok().or_else(|| {
        cfg.get("venice")
            .and_then(|v| v.get("baseUrl"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    });
    let venice_provider = try_build_provider(
        venice_api_key,
        venice_base_url,
        "Venice",
        agent::venice::VeniceProvider::new,
        |p, url| p.with_base_url(url),
    )?;

    // Bedrock
    let bedrock = {
        let bedrock_cfg = cfg.get("bedrock");
        // Check explicit disable
        if bedrock_cfg
            .and_then(|b| b.get("enabled"))
            .and_then(|v| v.as_bool())
            != Some(false)
        {
            let region = std::env::var("AWS_REGION")
                .ok()
                .or_else(|| std::env::var("AWS_DEFAULT_REGION").ok())
                .or_else(|| {
                    bedrock_cfg
                        .and_then(|b| b.get("region"))
                        .and_then(|v| v.as_str())
                        .map(String::from)
                });

            let access_key = std::env::var("AWS_ACCESS_KEY_ID").ok().or_else(|| {
                bedrock_cfg
                    .and_then(|b| b.get("accessKeyId"))
                    .and_then(|v| v.as_str())
                    .map(String::from)
            });

            let secret_key = std::env::var("AWS_SECRET_ACCESS_KEY").ok().or_else(|| {
                bedrock_cfg
                    .and_then(|b| b.get("secretAccessKey"))
                    .and_then(|v| v.as_str())
                    .map(String::from)
            });

            let session_token = std::env::var("AWS_SESSION_TOKEN").ok().or_else(|| {
                bedrock_cfg
                    .and_then(|b| b.get("sessionToken"))
                    .and_then(|v| v.as_str())
                    .map(String::from)
            });

            match (region, access_key, secret_key) {
                (Some(r), Some(ak), Some(sk)) => {
                    match agent::bedrock::BedrockProvider::new(r, ak, sk) {
                        Ok(mut p) => {
                            if let Some(tok) = session_token {
                                p = p.with_session_token(tok);
                            }
                            info!("Bedrock provider configured");
                            Some(Arc::new(p) as Arc<dyn agent::LlmProvider>)
                        }
                        Err(e) => {
                            warn!("Bedrock provider init failed: {}", e);
                            None
                        }
                    }
                }
                _ => None,
            }
        } else {
            None
        }
    };

    // Azure OpenAI
    let azure_api_key = std::env::var("AZURE_OPENAI_API_KEY").ok().or_else(|| {
        cfg.get("azure")
            .and_then(|v| v.get("apiKey"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    });
    let azure_resource = std::env::var("AZURE_OPENAI_RESOURCE").ok().or_else(|| {
        cfg.get("azure")
            .and_then(|v| v.get("resource"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    });
    let azure_deployment = std::env::var("AZURE_OPENAI_DEPLOYMENT").ok().or_else(|| {
        cfg.get("azure")
            .and_then(|v| v.get("deployment"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    });
    let azure_api_version = std::env::var("AZURE_OPENAI_API_VERSION").ok().or_else(|| {
        cfg.get("azure")
            .and_then(|v| v.get("apiVersion"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    });

    let azure_provider = match (azure_api_key, azure_resource, azure_deployment) {
        (Some(key), Some(resource), Some(deployment)) => {
            match agent::azure_openai::AzureOpenAiProvider::new(key, resource, deployment) {
                Ok(mut p) => {
                    if let Some(version) = azure_api_version {
                        p = p.with_api_version(version);
                    }
                    info!("Azure OpenAI provider configured");
                    Some(Arc::new(p) as Arc<dyn agent::LlmProvider>)
                }
                Err(e) => {
                    warn!("Azure OpenAI provider init failed: {}", e);
                    None
                }
            }
        }
        _ => None,
    };

    // Vertex AI
    let vertex_project_id = std::env::var("GCP_PROJECT_ID").ok().or_else(|| {
        cfg.get("vertex")
            .and_then(|v| v.get("projectId"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    });
    let vertex_region = std::env::var("GCP_REGION").ok().or_else(|| {
        cfg.get("vertex")
            .and_then(|v| v.get("region"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    });
    let vertex_access_token = std::env::var("GCP_ACCESS_TOKEN").ok().or_else(|| {
        cfg.get("vertex")
            .and_then(|v| v.get("accessToken"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    });

    let vertex_provider = match (vertex_project_id, vertex_region, vertex_access_token) {
        (Some(project_id), Some(region), Some(access_token)) => {
            match agent::vertex::VertexProvider::new(project_id, region, access_token) {
                Ok(p) => {
                    info!("Vertex AI provider configured");
                    Some(Arc::new(p) as Arc<dyn agent::LlmProvider>)
                }
                Err(e) => {
                    warn!("Vertex AI provider init failed: {}", e);
                    None
                }
            }
        }
        _ => None,
    };

    // OpenAI-compatible providers (DeepSeek, Qwen, Moonshot, Minimax, GLM/Z.ai, xAI/Grok)
    // Check for any configured OpenAI-compatible provider
    let openai_compatible_cfg = cfg.get("openaiCompatible").or_else(|| cfg.get("openai_compatible"));
    let deepseek_key = std::env::var("DEEPSEEK_API_KEY").ok()
        .or_else(|| openai_compatible_cfg.and_then(|v| v.get("deepseek")).and_then(|v| v.get("apiKey")).and_then(|v| v.as_str()).map(|s| s.to_string()));
    let deepseek_url = std::env::var("DEEPSEEK_BASE_URL").ok()
        .or_else(|| openai_compatible_cfg.and_then(|v| v.get("deepseek")).and_then(|v| v.get("baseUrl")).and_then(|v| v.as_str()).map(|s| s.to_string()));

    let qwen_key = std::env::var("QWEN_API_KEY").ok()
        .or_else(|| openai_compatible_cfg.and_then(|v| v.get("qwen")).and_then(|v| v.get("apiKey")).and_then(|v| v.as_str()).map(|s| s.to_string()));
    let qwen_url = std::env::var("QWEN_BASE_URL").ok()
        .or_else(|| openai_compatible_cfg.and_then(|v| v.get("qwen")).and_then(|v| v.get("baseUrl")).and_then(|v| v.as_str()).map(|s| s.to_string()));

    let moonshot_key = std::env::var("MOONSHOT_API_KEY").ok()
        .or_else(|| openai_compatible_cfg.and_then(|v| v.get("moonshot")).and_then(|v| v.get("apiKey")).and_then(|v| v.as_str()).map(|s| s.to_string()));
    let moonshot_url = std::env::var("MOONSHOT_BASE_URL").ok()
        .or_else(|| openai_compatible_cfg.and_then(|v| v.get("moonshot")).and_then(|v| v.get("baseUrl")).and_then(|v| v.as_str()).map(|s| s.to_string()));

    let minimax_key = std::env::var("MINIMAX_API_KEY").ok()
        .or_else(|| openai_compatible_cfg.and_then(|v| v.get("minimax")).and_then(|v| v.get("apiKey")).and_then(|v| v.as_str()).map(|s| s.to_string()));
    let minimax_url = std::env::var("MINIMAX_BASE_URL").ok()
        .or_else(|| openai_compatible_cfg.and_then(|v| v.get("minimax")).and_then(|v| v.get("baseUrl")).and_then(|v| v.as_str()).map(|s| s.to_string()));

    let glm_key = std::env::var("GLM_API_KEY").ok()
        .or_else(|| openai_compatible_cfg.and_then(|v| v.get("glm")).and_then(|v| v.get("apiKey")).and_then(|v| v.as_str()).map(|s| s.to_string()));
    let glm_url = std::env::var("GLM_BASE_URL").ok()
        .or_else(|| openai_compatible_cfg.and_then(|v| v.get("glm")).and_then(|v| v.get("baseUrl")).and_then(|v| v.as_str()).map(|s| s.to_string()));

    let xai_key = std::env::var("XAI_API_KEY").ok()
        .or_else(|| openai_compatible_cfg.and_then(|v| v.get("xai")).and_then(|v| v.get("apiKey")).and_then(|v| v.as_str()).map(|s| s.to_string()));
    let xai_url = std::env::var("XAI_BASE_URL").ok()
        .or_else(|| openai_compatible_cfg.and_then(|v| v.get("xai")).and_then(|v| v.get("baseUrl")).and_then(|v| v.as_str()).map(|s| s.to_string()));

    let openrouter_key = std::env::var("OPENROUTER_API_KEY").ok()
        .or_else(|| openai_compatible_cfg.and_then(|v| v.get("openrouter")).and_then(|v| v.get("apiKey")).and_then(|v| v.as_str()).map(|s| s.to_string()));
    let openrouter_url = std::env::var("OPENROUTER_BASE_URL").ok()
        .or_else(|| openai_compatible_cfg.and_then(|v| v.get("openrouter")).and_then(|v| v.get("baseUrl")).and_then(|v| v.as_str()).map(|s| s.to_string()));

    // Build the first configured OpenAI-compatible provider
    let openai_compatible_provider = if let Some((key, base_url, name)) = deepseek_key.zip(deepseek_url).map(|(k, u)| (k, u, "DeepSeek".to_string())) {
        match agent::openai_compatible::OpenAiCompatibleProvider::new(key, base_url, name) {
            Ok(p) => {
                info!("OpenAI-compatible provider configured: DeepSeek");
                Some(Arc::new(p) as Arc<dyn agent::LlmProvider>)
            }
            Err(e) => {
                warn!("DeepSeek provider init failed: {}", e);
                None
            }
        }
    } else if let Some((key, base_url, name)) = qwen_key.zip(qwen_url).map(|(k, u)| (k, u, "Qwen".to_string())) {
        match agent::openai_compatible::OpenAiCompatibleProvider::new(key, base_url, name) {
            Ok(p) => {
                info!("OpenAI-compatible provider configured: Qwen");
                Some(Arc::new(p) as Arc<dyn agent::LlmProvider>)
            }
            Err(e) => {
                warn!("Qwen provider init failed: {}", e);
                None
            }
        }
    } else if let Some((key, base_url, name)) = moonshot_key.zip(moonshot_url).map(|(k, u)| (k, u, "Moonshot".to_string())) {
        match agent::openai_compatible::OpenAiCompatibleProvider::new(key, base_url, name) {
            Ok(p) => {
                info!("OpenAI-compatible provider configured: Moonshot");
                Some(Arc::new(p) as Arc<dyn agent::LlmProvider>)
            }
            Err(e) => {
                warn!("Moonshot provider init failed: {}", e);
                None
            }
        }
    } else if let Some((key, base_url, name)) = minimax_key.zip(minimax_url).map(|(k, u)| (k, u, "Minimax".to_string())) {
        match agent::openai_compatible::OpenAiCompatibleProvider::new(key, base_url, name) {
            Ok(p) => {
                info!("OpenAI-compatible provider configured: Minimax");
                Some(Arc::new(p) as Arc<dyn agent::LlmProvider>)
            }
            Err(e) => {
                warn!("Minimax provider init failed: {}", e);
                None
            }
        }
    } else if let Some((key, base_url, name)) = glm_key.zip(glm_url).map(|(k, u)| (k, u, "GLM".to_string())) {
        match agent::openai_compatible::OpenAiCompatibleProvider::new(key, base_url, name) {
            Ok(p) => {
                info!("OpenAI-compatible provider configured: GLM");
                Some(Arc::new(p) as Arc<dyn agent::LlmProvider>)
            }
            Err(e) => {
                warn!("GLM provider init failed: {}", e);
                None
            }
        }
    } else if let Some((key, base_url, name)) = xai_key.zip(xai_url).map(|(k, u)| (k, u, "xAI".to_string())) {
        match agent::openai_compatible::OpenAiCompatibleProvider::new(key, base_url, name) {
            Ok(p) => {
                info!("OpenAI-compatible provider configured: xAI");
                Some(Arc::new(p) as Arc<dyn agent::LlmProvider>)
            }
            Err(e) => {
                warn!("xAI provider init failed: {}", e);
                None
            }
        }
    } else {
        None
    };

    // Build multi-provider dispatcher
    let multi_provider = MultiProvider::new(anthropic_provider, openai_provider)
        .with_ollama(ollama_provider)
        .with_gemini(gemini_provider)
        .with_venice(venice_provider)
        .with_bedrock(bedrock)
        .with_azure(azure_provider)
        .with_vertex(vertex_provider)
        .with_openai_compatible(openai_compatible_provider);

    if multi_provider.has_any_provider() {
        Ok(Some(multi_provider))
    } else {
        Ok(None)
    }
}

/// A fingerprint of the provider configuration, used for change detection.
///
/// API keys are hashed (SHA-256 prefix) rather than stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderFingerprint {
    pub anthropic: Option<(String, Option<String>)>,
    pub openai: Option<(String, Option<String>)>,
    pub ollama: Option<(bool, Option<String>)>,
    pub gemini: Option<(String, Option<String>)>,
    pub venice: Option<(String, Option<String>)>,
    pub bedrock: Option<String>,
    pub azure: Option<(String, Option<String>)>,
    pub vertex: Option<(String, String)>,
}

/// Compute a fingerprint of the provider configuration from config + env vars.
pub fn fingerprint_providers(cfg: &Value) -> ProviderFingerprint {
    let anthropic_key = std::env::var("ANTHROPIC_API_KEY").ok().or_else(|| {
        cfg.get("anthropic")
            .and_then(|v| v.get("apiKey"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    });
    let anthropic_url = std::env::var("ANTHROPIC_BASE_URL").ok().or_else(|| {
        cfg.get("anthropic")
            .and_then(|v| v.get("baseUrl"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    });

    let openai_key = std::env::var("OPENAI_API_KEY").ok().or_else(|| {
        cfg.get("openai")
            .and_then(|v| v.get("apiKey"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    });
    let openai_url = std::env::var("OPENAI_BASE_URL").ok().or_else(|| {
        cfg.get("openai")
            .and_then(|v| v.get("baseUrl"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    });

    let ollama_cfg = cfg.get("providers").and_then(|v| v.get("ollama"));
    let ollama_url = std::env::var("OLLAMA_BASE_URL").ok().or_else(|| {
        ollama_cfg
            .and_then(|v| v.get("baseUrl"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    });
    let ollama_configured = ollama_url.is_some() || ollama_cfg.is_some();

    let google_key = std::env::var("GOOGLE_API_KEY").ok().or_else(|| {
        cfg.get("google")
            .and_then(|v| v.get("apiKey"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    });
    let google_url = std::env::var("GOOGLE_API_BASE_URL").ok().or_else(|| {
        cfg.get("google")
            .and_then(|v| v.get("baseUrl"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    });

    let venice_key = std::env::var("VENICE_API_KEY").ok().or_else(|| {
        cfg.get("venice")
            .and_then(|v| v.get("apiKey"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    });
    let venice_url = std::env::var("VENICE_BASE_URL").ok().or_else(|| {
        cfg.get("venice")
            .and_then(|v| v.get("baseUrl"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    });

    let bedrock_cfg = cfg.get("bedrock");
    let bedrock_enabled = bedrock_cfg
        .and_then(|b| b.get("enabled"))
        .and_then(|v| v.as_bool())
        != Some(false);
    let bedrock_region = std::env::var("AWS_REGION")
        .ok()
        .or_else(|| std::env::var("AWS_DEFAULT_REGION").ok())
        .or_else(|| {
            bedrock_cfg
                .and_then(|b| b.get("region"))
                .and_then(|v| v.as_str())
                .map(String::from)
        });
    let bedrock_access_key = std::env::var("AWS_ACCESS_KEY_ID").ok().or_else(|| {
        bedrock_cfg
            .and_then(|b| b.get("accessKeyId"))
            .and_then(|v| v.as_str())
            .map(String::from)
    });

    // Azure OpenAI fingerprint
    let azure_key = std::env::var("AZURE_OPENAI_API_KEY").ok().or_else(|| {
        cfg.get("azure")
            .and_then(|v| v.get("apiKey"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    });
    let azure_resource = std::env::var("AZURE_OPENAI_RESOURCE").ok().or_else(|| {
        cfg.get("azure")
            .and_then(|v| v.get("resource"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    });

    // Vertex AI fingerprint
    let vertex_project = std::env::var("GCP_PROJECT_ID").ok().or_else(|| {
        cfg.get("vertex")
            .and_then(|v| v.get("projectId"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    });
    let vertex_region = std::env::var("GCP_REGION").ok().or_else(|| {
        cfg.get("vertex")
            .and_then(|v| v.get("region"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    });

    ProviderFingerprint {
        anthropic: anthropic_key.map(|k| (hash_key_prefix(&k), anthropic_url)),
        openai: openai_key.map(|k| (hash_key_prefix(&k), openai_url)),
        ollama: if ollama_configured {
            Some((true, ollama_url))
        } else {
            None
        },
        gemini: google_key.map(|k| (hash_key_prefix(&k), google_url)),
        venice: venice_key.map(|k| (hash_key_prefix(&k), venice_url)),
        bedrock: if bedrock_enabled {
            match (bedrock_region, bedrock_access_key) {
                (Some(r), Some(ak)) => {
                    let combined = format!("{}{}", r, ak);
                    Some(hash_key_prefix(&combined))
                }
                _ => None,
            }
        } else {
            None
        },
        azure: azure_key.map(|k| (hash_key_prefix(&k), azure_resource)),
        vertex: vertex_project.map(|p| (hash_key_prefix(&p), vertex_region.unwrap_or_default())),
    }
}

/// Hash a key to a short prefix for safe comparison.
fn hash_key_prefix(key: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(key.as_bytes());
    let result = hasher.finalize();
    hex::encode(&result[..8])
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_fingerprint_empty_config() {
        // With no env vars and no config, all providers should be None
        let cfg = json!({});
        let fp = fingerprint_providers(&cfg);
        assert!(fp.anthropic.is_none());
        assert!(fp.openai.is_none());
        assert!(fp.ollama.is_none());
        assert!(fp.gemini.is_none());
        assert!(fp.venice.is_none());
        assert!(fp.bedrock.is_none());
    }

    #[test]
    fn test_fingerprint_with_config_keys() {
        let cfg = json!({
            "anthropic": { "apiKey": "sk-ant-test123" },
            "openai": { "apiKey": "sk-openai-test456" },
            "google": { "apiKey": "AIza-test789" }
        });
        let fp = fingerprint_providers(&cfg);
        assert!(fp.anthropic.is_some());
        assert!(fp.openai.is_some());
        assert!(fp.gemini.is_some());
        assert!(fp.ollama.is_none());
    }

    #[test]
    fn test_fingerprint_detects_key_change() {
        let cfg1 = json!({ "anthropic": { "apiKey": "key-a" } });
        let cfg2 = json!({ "anthropic": { "apiKey": "key-b" } });
        let fp1 = fingerprint_providers(&cfg1);
        let fp2 = fingerprint_providers(&cfg2);
        assert_ne!(fp1, fp2);
    }

    #[test]
    fn test_fingerprint_same_key_same_hash() {
        let cfg = json!({ "anthropic": { "apiKey": "key-same" } });
        let fp1 = fingerprint_providers(&cfg);
        let fp2 = fingerprint_providers(&cfg);
        assert_eq!(fp1, fp2);
    }

    #[test]
    fn test_fingerprint_ollama_configured() {
        let cfg = json!({ "providers": { "ollama": { "baseUrl": "http://localhost:11434" } } });
        let fp = fingerprint_providers(&cfg);
        assert!(fp.ollama.is_some());
        let (configured, url) = fp.ollama.unwrap();
        assert!(configured);
        assert_eq!(url.as_deref(), Some("http://localhost:11434"));
    }

    #[test]
    fn test_fingerprint_bedrock_configured() {
        let cfg = json!({
            "bedrock": {
                "region": "us-east-1",
                "accessKeyId": "AKIAIOSFODNN7EXAMPLE",
                "secretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
            }
        });
        let fp = fingerprint_providers(&cfg);
        assert!(fp.bedrock.is_some());
        assert_eq!(fp.bedrock.as_ref().unwrap().len(), 16); // 8 bytes = 16 hex chars
    }

    #[test]
    fn test_fingerprint_bedrock_detects_change() {
        let cfg1 = json!({
            "bedrock": {
                "region": "us-east-1",
                "accessKeyId": "AKIAIOSFODNN7EXAMPLE",
                "secretAccessKey": "secret1"
            }
        });
        let cfg2 = json!({
            "bedrock": {
                "region": "us-west-2",
                "accessKeyId": "AKIAIOSFODNN7EXAMPLE",
                "secretAccessKey": "secret1"
            }
        });
        let fp1 = fingerprint_providers(&cfg1);
        let fp2 = fingerprint_providers(&cfg2);
        assert_ne!(fp1.bedrock, fp2.bedrock);
    }

    #[test]
    fn test_fingerprint_bedrock_disabled() {
        let cfg = json!({
            "bedrock": {
                "region": "us-east-1",
                "accessKeyId": "AKIAIOSFODNN7EXAMPLE",
                "secretAccessKey": "secret",
                "enabled": false
            }
        });
        let fp = fingerprint_providers(&cfg);
        assert!(fp.bedrock.is_none());
    }

    #[test]
    fn test_fingerprint_bedrock_partial_creds() {
        // Only region, missing access key — should be None
        let cfg = json!({
            "bedrock": { "region": "us-east-1" }
        });
        let fp = fingerprint_providers(&cfg);
        assert!(fp.bedrock.is_none());
    }

    #[test]
    fn test_hash_key_prefix_deterministic() {
        let a = hash_key_prefix("my-secret-key");
        let b = hash_key_prefix("my-secret-key");
        assert_eq!(a, b);
        assert_eq!(a.len(), 16); // 8 bytes = 16 hex chars
    }

    #[test]
    fn test_hash_key_prefix_different_keys() {
        let a = hash_key_prefix("key-1");
        let b = hash_key_prefix("key-2");
        assert_ne!(a, b);
    }
}
