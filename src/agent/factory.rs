//! Provider construction factory.
//!
//! Extracts the ~200 lines of provider setup from `main.rs` into a reusable
//! function, and provides fingerprinting for change detection during hot-reload.

use std::path::Path;
use std::sync::Arc;

use serde_json::Value;
use sha2::{Digest, Sha256};
use tracing::{info, warn};

use crate::agent;
use crate::agent::provider::MultiProvider;
use crate::auth::profiles::{
    profile_store_encryption_enabled_from_env, resolve_anthropic_profile_token,
    AuthProfileCredentialKind, OAuthProvider, ProfileStore,
};

/// Open and load the profile store, logging a warning on failure.
///
/// Returns `None` if the store cannot be opened or loaded, with a structured
/// warning that includes the provider name, profile ID, and error. This
/// replaces the previous silent `.ok()?` pattern that erased failures into
/// the same state as "no auth profile configured."
fn open_and_load_profile_store(
    state_dir: std::path::PathBuf,
    provider: &str,
    profile_id: &str,
) -> Option<ProfileStore> {
    let store = match ProfileStore::from_env(state_dir) {
        Ok(s) => s,
        Err(e) => {
            warn!(
                provider = provider,
                profile_id = profile_id,
                error = %e,
                "failed to open auth-profile store; check CARAPACE_CONFIG_PASSWORD"
            );
            return None;
        }
    };
    if let Err(e) = store.load() {
        warn!(
            provider = provider,
            profile_id = profile_id,
            error = %e,
            "failed to load auth-profile store"
        );
        return None;
    }
    Some(store)
}

fn resolve_anthropic_auth_profile_id(cfg: &Value) -> Option<String> {
    cfg.get("anthropic")
        .and_then(|v| v.get("authProfile"))
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn resolve_anthropic_api_key(cfg: &Value) -> Option<String> {
    std::env::var("ANTHROPIC_API_KEY")
        .ok()
        .or_else(|| {
            cfg.get("anthropic")
                .and_then(|v| v.get("apiKey"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
        })
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn resolve_google_auth_profile_id(cfg: &Value) -> Option<String> {
    cfg.get("google")
        .and_then(|v| v.get("authProfile"))
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn resolve_openai_auth_profile_id(cfg: &Value) -> Option<String> {
    cfg.get("codex")
        .and_then(|v| v.get("authProfile"))
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn resolve_google_oauth_runtime_config(
    cfg: &Value,
    state_dir: &Path,
    profile_id: &str,
) -> Option<crate::auth::profiles::OAuthProviderConfig> {
    let profile_store = open_and_load_profile_store(state_dir.to_path_buf(), "google", profile_id)?;
    let profile = profile_store.get(profile_id)?;
    if profile.provider != OAuthProvider::Google
        || profile.credential_kind != AuthProfileCredentialKind::OAuth
    {
        return None;
    }
    if let Some(stored) = profile.oauth_provider_config {
        let redirect_uri = cfg
            .pointer("/auth/profiles/providers/google/redirectUri")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or(&stored.redirect_uri)
            .to_string();
        return Some(crate::auth::profiles::OAuthProviderConfig {
            client_id: stored.client_id,
            client_secret: stored.client_secret,
            redirect_uri,
            auth_url: stored.auth_url,
            token_url: stored.token_url,
            userinfo_url: stored.userinfo_url,
            scopes: stored.scopes,
        });
    }
    None
}

fn resolve_anthropic_auth_profile_fingerprint(cfg: &Value) -> Option<String> {
    let profile_id = resolve_anthropic_auth_profile_id(cfg)?;
    let state_dir = crate::paths::resolve_state_dir();
    let profile_store = open_and_load_profile_store(state_dir, "anthropic", &profile_id)?;
    let profile = profile_store.get(&profile_id)?;
    if profile.provider != OAuthProvider::Anthropic
        || profile.credential_kind != AuthProfileCredentialKind::Token
    {
        return None;
    }

    let material =
        serde_json::to_string(&(&profile_id, &profile.credential_kind, &profile.token)).ok()?;
    Some(format!(
        "auth-profile:{}:{}",
        profile_id,
        hash_key_prefix(&material)
    ))
}

fn resolve_openai_oauth_runtime_config(
    cfg: &Value,
    state_dir: &Path,
    profile_id: &str,
) -> Option<crate::auth::profiles::OAuthProviderConfig> {
    let profile_store = open_and_load_profile_store(state_dir.to_path_buf(), "openai", profile_id)?;
    let profile = profile_store.get(profile_id)?;
    if profile.provider != OAuthProvider::OpenAI
        || profile.credential_kind != AuthProfileCredentialKind::OAuth
    {
        return None;
    }
    if let Some(stored) = profile.oauth_provider_config {
        let redirect_uri = cfg
            .pointer("/auth/profiles/providers/openai/redirectUri")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or(&stored.redirect_uri)
            .to_string();
        return Some(crate::auth::profiles::OAuthProviderConfig {
            client_id: stored.client_id,
            client_secret: stored.client_secret,
            redirect_uri,
            auth_url: stored.auth_url,
            token_url: stored.token_url,
            userinfo_url: stored.userinfo_url,
            scopes: stored.scopes,
        });
    }
    None
}

fn resolve_google_auth_profile_fingerprint(cfg: &Value) -> Option<String> {
    let profile_id = resolve_google_auth_profile_id(cfg)?;
    let state_dir = crate::paths::resolve_state_dir();
    let profile_store = open_and_load_profile_store(state_dir, "google", &profile_id)?;
    let profile = profile_store.get(&profile_id)?;
    if profile.provider != OAuthProvider::Google
        || profile.credential_kind != AuthProfileCredentialKind::OAuth
    {
        return None;
    }

    let material =
        serde_json::to_string(&(&profile_id, &profile.tokens, &profile.oauth_provider_config))
            .ok()?;
    Some(format!(
        "auth-profile:{}:{}",
        profile_id,
        hash_key_prefix(&material)
    ))
}

fn resolve_openai_auth_profile_fingerprint(cfg: &Value) -> Option<String> {
    let profile_id = resolve_openai_auth_profile_id(cfg)?;
    let state_dir = crate::paths::resolve_state_dir();
    let profile_store = open_and_load_profile_store(state_dir, "openai", &profile_id)?;
    let profile = profile_store.get(&profile_id)?;
    if profile.provider != OAuthProvider::OpenAI
        || profile.credential_kind != AuthProfileCredentialKind::OAuth
    {
        return None;
    }

    let material =
        serde_json::to_string(&(&profile_id, &profile.tokens, &profile.oauth_provider_config))
            .ok()?;
    Some(format!(
        "auth-profile:{}:{}",
        profile_id,
        hash_key_prefix(&material)
    ))
}

fn build_gemini_provider(
    cfg: &Value,
    google_api_key: Option<String>,
    google_auth_profile: Option<String>,
    google_base_url: Option<String>,
) -> Result<Option<Arc<dyn agent::LlmProvider>>, Box<dyn std::error::Error>> {
    if google_api_key.is_some() {
        return try_build_provider(
            google_api_key,
            google_base_url,
            "Gemini",
            agent::gemini::GeminiProvider::new,
            |p, url| p.with_base_url(url),
        );
    }

    let Some(profile_id) = google_auth_profile else {
        return Ok(None);
    };

    if !profile_store_encryption_enabled_from_env() {
        warn!(
            "Gemini auth profile requires CARAPACE_CONFIG_PASSWORD so auth profile tokens and OAuth client secrets stay encrypted at rest"
        );
        return Ok(None);
    }

    let state_dir = crate::paths::resolve_state_dir();
    let provider_config = resolve_google_oauth_runtime_config(cfg, &state_dir, &profile_id);
    if let Some(provider_config) = provider_config {
        let profile_store = ProfileStore::from_env(state_dir)?;
        profile_store.load()?;
        let mut provider = agent::gemini::GeminiProvider::with_oauth_profile(
            Arc::new(profile_store),
            profile_id,
            provider_config,
        )?;
        if let Some(url) = google_base_url {
            provider = provider.with_base_url(url)?;
        }
        info!("LLM provider configured: Gemini (Google auth profile)");
        Ok(Some(Arc::new(provider) as Arc<dyn agent::LlmProvider>))
    } else {
        warn!(
            "Gemini auth profile is configured, but the stored Google OAuth provider settings are missing"
        );
        Ok(None)
    }
}

fn build_codex_provider(
    cfg: &Value,
    openai_auth_profile: Option<String>,
) -> Result<Option<Arc<dyn agent::LlmProvider>>, Box<dyn std::error::Error>> {
    let Some(profile_id) = openai_auth_profile else {
        return Ok(None);
    };

    if !profile_store_encryption_enabled_from_env() {
        warn!(
            "Codex auth profile requires CARAPACE_CONFIG_PASSWORD so auth profile tokens and OAuth client secrets stay encrypted at rest"
        );
        return Ok(None);
    }

    let state_dir = crate::paths::resolve_state_dir();
    let provider_config = resolve_openai_oauth_runtime_config(cfg, &state_dir, &profile_id);
    if let Some(provider_config) = provider_config {
        let profile_store = ProfileStore::from_env(state_dir)?;
        profile_store.load()?;
        let provider = agent::codex::CodexProvider::with_oauth_profile(
            Arc::new(profile_store),
            profile_id,
            provider_config,
        )?;
        info!("LLM provider configured: Codex (OpenAI auth profile)");
        Ok(Some(Arc::new(provider) as Arc<dyn agent::LlmProvider>))
    } else {
        warn!(
            "Codex auth profile is configured, but the stored OpenAI OAuth provider settings are missing"
        );
        Ok(None)
    }
}

fn build_anthropic_provider(
    anthropic_api_key: Option<String>,
    anthropic_auth_profile: Option<String>,
    anthropic_base_url: Option<String>,
) -> Result<Option<Arc<dyn agent::LlmProvider>>, Box<dyn std::error::Error>> {
    if let Some(api_key) = anthropic_api_key {
        if anthropic_auth_profile.is_some() {
            warn!(
                "Both anthropic.apiKey and anthropic.authProfile are configured; preferring the direct API key path"
            );
        }
        return try_build_provider(
            Some(api_key),
            anthropic_base_url,
            "Anthropic",
            agent::anthropic::AnthropicProvider::new,
            |p, url| p.with_base_url(url),
        );
    }

    let Some(profile_id) = anthropic_auth_profile else {
        return Ok(None);
    };

    if !profile_store_encryption_enabled_from_env() {
        return Err(std::io::Error::other(
            "Anthropic auth profile requires CARAPACE_CONFIG_PASSWORD so setup-token credentials stay encrypted at rest",
        )
        .into());
    }

    let state_dir = crate::paths::resolve_state_dir();
    let profile_store = ProfileStore::from_env(state_dir)?;
    profile_store.load()?;
    resolve_anthropic_profile_token(&profile_store, &profile_id).map_err(std::io::Error::other)?;

    let mut provider = agent::anthropic::AnthropicProvider::with_auth_profile_token(
        Arc::new(profile_store),
        profile_id,
    )?;
    if let Some(url) = anthropic_base_url {
        provider = provider.with_base_url(url)?;
    }
    info!("LLM provider configured: Anthropic (auth profile)");
    Ok(Some(Arc::new(provider) as Arc<dyn agent::LlmProvider>))
}

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

struct VertexConfig {
    project_id: Option<String>,
    location: Option<String>,
    model: Option<String>,
}

fn get_vertex_config(cfg: &Value) -> VertexConfig {
    let vertex_cfg = cfg.get("vertex");
    let project_id = std::env::var("VERTEX_PROJECT_ID").ok().or_else(|| {
        vertex_cfg
            .and_then(|v| v.get("projectId"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    });
    let location = std::env::var("VERTEX_LOCATION").ok().or_else(|| {
        vertex_cfg
            .and_then(|v| v.get("location"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    });
    let model = std::env::var("VERTEX_MODEL").ok().or_else(|| {
        vertex_cfg
            .and_then(|v| v.get("model"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    });

    VertexConfig {
        project_id,
        location,
        model,
    }
}

struct OpenAiConfig {
    api_key: Option<String>,
    base_url: Option<String>,
    http_referer: Option<String>,
    title: Option<String>,
}

fn normalize_optional_trimmed(value: Option<String>) -> Option<String> {
    value
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn normalize_optional_base_url(value: Option<String>) -> Option<String> {
    normalize_optional_trimmed(value).map(|s| s.trim_end_matches('/').to_string())
}

fn get_openai_config(cfg: &Value) -> OpenAiConfig {
    let openai_cfg = cfg.get("openai");
    let get_optional_string = |env_keys: &[&str], cfg_key: &str| {
        env_keys
            .iter()
            .find_map(|key| std::env::var(key).ok())
            .or_else(|| {
                openai_cfg
                    .and_then(|v| v.get(cfg_key))
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
            })
    };

    let api_key = get_optional_string(&["OPENAI_API_KEY"], "apiKey");
    let base_url =
        normalize_optional_base_url(get_optional_string(&["OPENAI_BASE_URL"], "baseUrl"));
    let http_referer =
        normalize_optional_trimmed(get_optional_string(&["OPENAI_HTTP_REFERER"], "httpReferer"));
    let title = normalize_optional_trimmed(get_optional_string(
        &["OPENAI_X_TITLE", "OPENAI_TITLE"],
        "title",
    ));

    OpenAiConfig {
        api_key,
        base_url,
        http_referer,
        title,
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
    let anthropic_api_key = resolve_anthropic_api_key(cfg);
    let anthropic_auth_profile = resolve_anthropic_auth_profile_id(cfg);
    let anthropic_base_url = std::env::var("ANTHROPIC_BASE_URL").ok().or_else(|| {
        cfg.get("anthropic")
            .and_then(|v| v.get("baseUrl"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    });
    let anthropic_provider = build_anthropic_provider(
        anthropic_api_key,
        anthropic_auth_profile,
        anthropic_base_url,
    )?;

    // OpenAI
    let openai_cfg = get_openai_config(cfg);
    let openai_provider = match openai_cfg.api_key {
        Some(key) => match agent::openai::OpenAiProvider::new(key) {
            Ok(provider) => {
                let provider = if let Some(url) = openai_cfg.base_url {
                    provider.with_base_url(url)?
                } else {
                    provider
                };
                let provider = if let Some(value) = openai_cfg.http_referer {
                    provider.with_http_referer(value)?
                } else {
                    provider
                };
                let provider = if let Some(value) = openai_cfg.title {
                    provider.with_title(value)?
                } else {
                    provider
                };
                info!("LLM provider configured: OpenAI");
                Some(Arc::new(provider) as Arc<dyn agent::LlmProvider>)
            }
            Err(e) => {
                warn!("Failed to configure OpenAI provider: {}", e);
                None
            }
        },
        None => None,
    };

    // Codex
    let codex_auth_profile = resolve_openai_auth_profile_id(cfg);
    let codex_provider = build_codex_provider(cfg, codex_auth_profile)?;

    // Ollama
    let ollama_provider = try_build_ollama_provider(cfg)?;

    // Gemini
    let google_api_key = std::env::var("GOOGLE_API_KEY")
        .ok()
        .or_else(|| {
            cfg.get("google")
                .and_then(|v| v.get("apiKey"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
        })
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let google_auth_profile = resolve_google_auth_profile_id(cfg);
    let google_base_url = std::env::var("GOOGLE_API_BASE_URL").ok().or_else(|| {
        cfg.get("google")
            .and_then(|v| v.get("baseUrl"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    });
    let gemini_provider =
        build_gemini_provider(cfg, google_api_key, google_auth_profile, google_base_url)?;

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

    // Vertex
    let vertex_config = get_vertex_config(cfg);

    let vertex_provider = if let Some(project_id) = vertex_config.project_id {
        let location = vertex_config
            .location
            .unwrap_or_else(|| "us-central1".to_string());
        info!(
            "LLM provider configured: Vertex (project: {}, location: {}, model: {:?})",
            project_id, location, vertex_config.model
        );
        match agent::vertex::VertexProvider::new(project_id, location, vertex_config.model) {
            Ok(provider) => Some(Arc::new(provider) as Arc<dyn agent::LlmProvider>),
            Err(e) => {
                warn!("Failed to configure Vertex provider: {}", e);
                None
            }
        }
    } else {
        None
    };

    // Build multi-provider dispatcher
    let multi_provider = MultiProvider::new(anthropic_provider, openai_provider)
        .with_codex(codex_provider)
        .with_ollama(ollama_provider)
        .with_gemini(gemini_provider)
        .with_venice(venice_provider)
        .with_bedrock(bedrock)
        .with_vertex(vertex_provider);

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
    pub codex: Option<String>,
    pub ollama: Option<(bool, Option<String>)>,
    pub gemini: Option<(String, Option<String>)>,
    pub venice: Option<(String, Option<String>)>,
    pub bedrock: Option<String>,
    pub vertex: Option<(String, String, Option<String>)>,
}

/// Compute a fingerprint of the provider configuration from config + env vars.
pub fn fingerprint_providers(cfg: &Value) -> ProviderFingerprint {
    let anthropic_key = resolve_anthropic_api_key(cfg);
    let anthropic_auth_profile_fingerprint = resolve_anthropic_auth_profile_fingerprint(cfg);
    let anthropic_url = std::env::var("ANTHROPIC_BASE_URL").ok().or_else(|| {
        cfg.get("anthropic")
            .and_then(|v| v.get("baseUrl"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    });

    let OpenAiConfig {
        api_key: openai_api_key,
        base_url: openai_base_url,
        http_referer: openai_http_referer,
        title: openai_title,
    } = get_openai_config(cfg);
    let codex_profile_fingerprint = resolve_openai_auth_profile_fingerprint(cfg);

    let ollama_cfg = cfg.get("providers").and_then(|v| v.get("ollama"));
    let ollama_url = std::env::var("OLLAMA_BASE_URL").ok().or_else(|| {
        ollama_cfg
            .and_then(|v| v.get("baseUrl"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    });
    let ollama_configured = ollama_url.is_some() || ollama_cfg.is_some();

    let google_key = std::env::var("GOOGLE_API_KEY")
        .ok()
        .or_else(|| {
            cfg.get("google")
                .and_then(|v| v.get("apiKey"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
        })
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
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
    let vertex_config = get_vertex_config(cfg);

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

    ProviderFingerprint {
        anthropic: anthropic_key
            .map(|k| {
                (
                    format!("api-key:{}", hash_key_prefix(&k)),
                    anthropic_url.clone(),
                )
            })
            .or_else(|| {
                anthropic_auth_profile_fingerprint.map(|fingerprint| (fingerprint, anthropic_url))
            }),
        openai: openai_api_key.as_ref().map(|api_key| {
            let api_key_hash = if openai_http_referer.is_none() && openai_title.is_none() {
                hash_key_prefix(api_key)
            } else {
                let mut material = String::with_capacity(
                    api_key.len()
                        + openai_http_referer.as_deref().map_or(0, str::len)
                        + openai_title.as_deref().map_or(0, str::len)
                        + 2,
                );
                material.push_str(api_key);
                material.push('\n');
                if let Some(value) = openai_http_referer.as_deref() {
                    material.push_str(value);
                }
                material.push('\n');
                if let Some(value) = openai_title.as_deref() {
                    material.push_str(value);
                }
                hash_key_prefix(&material)
            };
            (api_key_hash, openai_base_url.clone())
        }),
        codex: codex_profile_fingerprint,
        ollama: if ollama_configured {
            Some((true, ollama_url))
        } else {
            None
        },
        gemini: google_key
            .map(|k| {
                (
                    format!("api-key:{}", hash_key_prefix(&k)),
                    google_url.clone(),
                )
            })
            .or_else(|| {
                resolve_google_auth_profile_fingerprint(cfg)
                    .map(|profile_fingerprint| (profile_fingerprint, google_url))
            }),
        venice: venice_key.map(|k| (hash_key_prefix(&k), venice_url)),
        bedrock: if bedrock_enabled {
            match (bedrock_region, bedrock_access_key) {
                (Some(r), Some(k)) => Some(hash_key_prefix(&format!("{}{}", r, k))),
                _ => None,
            }
        } else {
            None
        },
        vertex: vertex_config.project_id.map(|p| {
            (
                hash_key_prefix(&p),
                vertex_config
                    .location
                    .unwrap_or_else(|| "us-central1".to_string()),
                vertex_config.model,
            )
        }),
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
    use std::ffi::OsString;
    use std::sync::{LazyLock, Mutex};

    // Serializes env-var touching tests in this module.
    static ENV_VAR_TEST_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

    const PROVIDER_ENV_KEYS: &[&str] = &[
        "ANTHROPIC_API_KEY",
        "ANTHROPIC_BASE_URL",
        "CARAPACE_CONFIG_PASSWORD",
        "CARAPACE_STATE_DIR",
        "OPENAI_API_KEY",
        "OPENAI_BASE_URL",
        "OPENAI_OAUTH_CLIENT_ID",
        "OPENAI_OAUTH_CLIENT_SECRET",
        "OPENAI_HTTP_REFERER",
        "OPENAI_X_TITLE",
        "OPENAI_TITLE",
        "OLLAMA_BASE_URL",
        "GOOGLE_API_KEY",
        "GOOGLE_API_BASE_URL",
        "VENICE_API_KEY",
        "VENICE_BASE_URL",
        "AWS_REGION",
        "AWS_DEFAULT_REGION",
        "AWS_ACCESS_KEY_ID",
        "VERTEX_PROJECT_ID",
        "VERTEX_LOCATION",
        "VERTEX_MODEL",
    ];

    struct EnvVarGuard {
        key: &'static str,
        previous: Option<OsString>,
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            match self.previous.take() {
                Some(value) => std::env::set_var(self.key, value),
                None => std::env::remove_var(self.key),
            }
        }
    }

    fn unset_env_var_scoped(key: &'static str) -> EnvVarGuard {
        let previous = std::env::var_os(key);
        std::env::remove_var(key);
        EnvVarGuard { key, previous }
    }

    fn set_env_var_scoped(key: &'static str, value: &str) -> EnvVarGuard {
        let previous = std::env::var_os(key);
        std::env::set_var(key, value);
        EnvVarGuard { key, previous }
    }

    fn with_clean_provider_env<T>(f: impl FnOnce() -> T) -> T {
        let _lock = ENV_VAR_TEST_LOCK.lock().expect("env var test lock");
        let _guards: Vec<EnvVarGuard> = PROVIDER_ENV_KEYS
            .iter()
            .map(|key| unset_env_var_scoped(key))
            .collect();
        f()
    }

    #[test]
    fn test_fingerprint_empty_config() {
        with_clean_provider_env(|| {
            // With no env vars and no config, all providers should be None
            let cfg = json!({});
            let fp = fingerprint_providers(&cfg);
            assert!(fp.anthropic.is_none());
            assert!(fp.openai.is_none());
            assert!(fp.codex.is_none());
            assert!(fp.ollama.is_none());
            assert!(fp.gemini.is_none());
            assert!(fp.venice.is_none());
            assert!(fp.bedrock.is_none());
            assert!(fp.vertex.is_none());
        });
    }

    #[test]
    fn test_fingerprint_with_config_keys() {
        with_clean_provider_env(|| {
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
        });
    }

    #[test]
    fn test_fingerprint_with_gemini_auth_profile() {
        with_clean_provider_env(|| {
            let temp = tempfile::tempdir().expect("tempdir");
            let _state_dir = set_env_var_scoped(
                "CARAPACE_STATE_DIR",
                temp.path().to_str().expect("state dir path"),
            );
            let provider_config = OAuthProvider::Google
                .default_config(
                    "google-client-id",
                    "google-client-secret",
                    "https://gateway.example.com/control/onboarding/gemini/callback",
                )
                .unwrap();
            let profile = crate::auth::profiles::AuthProfile {
                id: "google-abc123".to_string(),
                name: "Google user@example.com".to_string(),
                provider: OAuthProvider::Google,
                user_id: Some("user-123".to_string()),
                email: Some("user@example.com".to_string()),
                display_name: Some("Example User".to_string()),
                avatar_url: None,
                created_at_ms: 0,
                last_used_ms: None,
                credential_kind: AuthProfileCredentialKind::OAuth,
                tokens: Some(crate::auth::profiles::OAuthTokens {
                    access_token: "access-token".to_string(),
                    refresh_token: Some("refresh-token".to_string()),
                    token_type: "Bearer".to_string(),
                    expires_at_ms: Some(u64::MAX),
                    scope: Some("openid email profile".to_string()),
                }),
                token: None,
                oauth_provider_config: Some(
                    crate::auth::profiles::StoredOAuthProviderConfig::from(&provider_config),
                ),
            };
            let store = ProfileStore::from_env(temp.path().to_path_buf()).expect("profile store");
            store.add(profile).expect("store profile");
            let cfg = json!({
                "google": { "authProfile": "google-abc123" }
            });
            let fp = fingerprint_providers(&cfg);
            let fingerprint = fp.gemini.expect("gemini fingerprint");
            assert!(fingerprint.0.starts_with("auth-profile:google-abc123:"));
            assert_eq!(fingerprint.1, None);
        });
    }

    #[test]
    fn test_fingerprint_with_anthropic_auth_profile() {
        with_clean_provider_env(|| {
            let temp = tempfile::tempdir().expect("tempdir");
            let _password = set_env_var_scoped("CARAPACE_CONFIG_PASSWORD", "test-config-password");
            let _state_dir = set_env_var_scoped(
                "CARAPACE_STATE_DIR",
                temp.path().to_str().expect("state dir path"),
            );
            let profile = crate::auth::profiles::AuthProfile {
                id: "anthropic:default".to_string(),
                name: "Anthropic setup token".to_string(),
                provider: OAuthProvider::Anthropic,
                user_id: None,
                email: None,
                display_name: None,
                avatar_url: None,
                created_at_ms: 0,
                last_used_ms: None,
                credential_kind: AuthProfileCredentialKind::Token,
                tokens: None,
                token: Some("sk-ant-oat01-test-token".to_string()),
                oauth_provider_config: None,
            };
            let store = ProfileStore::from_env(temp.path().to_path_buf()).expect("profile store");
            store.add(profile).expect("store profile");
            let cfg = json!({
                "anthropic": { "authProfile": "anthropic:default" }
            });
            let fp = fingerprint_providers(&cfg);
            let fingerprint = fp.anthropic.expect("anthropic fingerprint");
            assert!(fingerprint.0.starts_with("auth-profile:anthropic:default:"));
            assert_eq!(fingerprint.1, None);
        });
    }

    #[test]
    fn test_fingerprint_with_codex_auth_profile() {
        with_clean_provider_env(|| {
            let temp = tempfile::tempdir().expect("tempdir");
            let _state_dir = set_env_var_scoped(
                "CARAPACE_STATE_DIR",
                temp.path().to_str().expect("state dir path"),
            );
            let provider_config = OAuthProvider::OpenAI
                .default_config(
                    "openai-client-id",
                    "openai-client-secret",
                    "https://gateway.example.com/control/onboarding/codex/callback",
                )
                .unwrap();
            let profile = crate::auth::profiles::AuthProfile {
                id: "openai-abc123".to_string(),
                name: "Codex user@example.com".to_string(),
                provider: OAuthProvider::OpenAI,
                user_id: Some("user-123".to_string()),
                email: Some("user@example.com".to_string()),
                display_name: Some("Example User".to_string()),
                avatar_url: None,
                created_at_ms: 0,
                last_used_ms: None,
                credential_kind: AuthProfileCredentialKind::OAuth,
                tokens: Some(crate::auth::profiles::OAuthTokens {
                    access_token: "access-token".to_string(),
                    refresh_token: Some("refresh-token".to_string()),
                    token_type: "Bearer".to_string(),
                    expires_at_ms: Some(u64::MAX),
                    scope: Some("openid email profile offline_access".to_string()),
                }),
                token: None,
                oauth_provider_config: Some(
                    crate::auth::profiles::StoredOAuthProviderConfig::from(&provider_config),
                ),
            };
            let store = ProfileStore::from_env(temp.path().to_path_buf()).expect("profile store");
            store.add(profile).expect("store profile");
            let cfg = json!({
                "codex": { "authProfile": "openai-abc123" }
            });
            let fp = fingerprint_providers(&cfg);
            let fingerprint = fp.codex.expect("codex fingerprint");
            assert!(fingerprint.starts_with("auth-profile:openai-abc123:"));
        });
    }

    #[test]
    fn test_fingerprint_ignores_blank_gemini_api_key_when_auth_profile_present() {
        with_clean_provider_env(|| {
            let temp = tempfile::tempdir().expect("tempdir");
            let _state_dir = set_env_var_scoped(
                "CARAPACE_STATE_DIR",
                temp.path().to_str().expect("state dir path"),
            );
            let _blank_key = set_env_var_scoped("GOOGLE_API_KEY", "   ");
            let provider_config = OAuthProvider::Google
                .default_config(
                    "google-client-id",
                    "google-client-secret",
                    "https://gateway.example.com/control/onboarding/gemini/callback",
                )
                .unwrap();
            let profile = crate::auth::profiles::AuthProfile {
                id: "google-abc123".to_string(),
                name: "Google user@example.com".to_string(),
                provider: OAuthProvider::Google,
                user_id: Some("user-123".to_string()),
                email: Some("user@example.com".to_string()),
                display_name: Some("Example User".to_string()),
                avatar_url: None,
                created_at_ms: 0,
                last_used_ms: None,
                credential_kind: AuthProfileCredentialKind::OAuth,
                tokens: Some(crate::auth::profiles::OAuthTokens {
                    access_token: "access-token".to_string(),
                    refresh_token: Some("refresh-token".to_string()),
                    token_type: "Bearer".to_string(),
                    expires_at_ms: Some(u64::MAX),
                    scope: Some("openid email profile".to_string()),
                }),
                token: None,
                oauth_provider_config: Some(
                    crate::auth::profiles::StoredOAuthProviderConfig::from(&provider_config),
                ),
            };
            let store = ProfileStore::from_env(temp.path().to_path_buf()).expect("profile store");
            store.add(profile).expect("store profile");
            let cfg = json!({
                "google": { "authProfile": "google-abc123" }
            });
            let fp = fingerprint_providers(&cfg);
            let fingerprint = fp.gemini.expect("gemini fingerprint");
            assert!(fingerprint.0.starts_with("auth-profile:google-abc123:"));
            assert_eq!(fingerprint.1, None);
        });
    }

    #[test]
    fn test_fingerprint_ignores_blank_gemini_auth_profile() {
        with_clean_provider_env(|| {
            let cfg = json!({
                "google": { "authProfile": "   " }
            });
            let fp = fingerprint_providers(&cfg);
            assert!(fp.gemini.is_none());
        });
    }

    #[test]
    fn test_openai_fingerprint_changes_when_extra_headers_change() {
        with_clean_provider_env(|| {
            let cfg_a = json!({
                "openai": {
                    "apiKey": "sk-openai-test456",
                    "httpReferer": "https://example.com/app-a",
                    "title": "Carapace A"
                }
            });
            let cfg_b = json!({
                "openai": {
                    "apiKey": "sk-openai-test456",
                    "httpReferer": "https://example.com/app-b",
                    "title": "Carapace B"
                }
            });

            let fp_a = fingerprint_providers(&cfg_a);
            let fp_b = fingerprint_providers(&cfg_b);

            assert_ne!(fp_a.openai, fp_b.openai);
        });
    }

    #[test]
    fn test_openai_fingerprint_normalizes_header_whitespace() {
        with_clean_provider_env(|| {
            let cfg_a = json!({
                "openai": {
                    "apiKey": "sk-openai-test456",
                    "httpReferer": "https://example.com/app",
                    "title": "Carapace"
                }
            });
            let cfg_b = json!({
                "openai": {
                    "apiKey": "sk-openai-test456",
                    "httpReferer": "  https://example.com/app  ",
                    "title": "  Carapace  "
                }
            });

            let fp_a = fingerprint_providers(&cfg_a);
            let fp_b = fingerprint_providers(&cfg_b);

            assert_eq!(fp_a.openai, fp_b.openai);
        });
    }

    #[test]
    fn test_openai_fingerprint_normalizes_base_url_trailing_slash() {
        with_clean_provider_env(|| {
            let cfg_a = json!({
                "openai": {
                    "apiKey": "sk-openai-test456",
                    "baseUrl": "https://proxy.example.com/v1"
                }
            });
            let cfg_b = json!({
                "openai": {
                    "apiKey": "sk-openai-test456",
                    "baseUrl": "https://proxy.example.com/v1/"
                }
            });

            let fp_a = fingerprint_providers(&cfg_a);
            let fp_b = fingerprint_providers(&cfg_b);

            assert_eq!(fp_a.openai, fp_b.openai);
        });
    }

    #[test]
    fn test_fingerprint_changes_when_gemini_auth_profile_tokens_change() {
        with_clean_provider_env(|| {
            let temp = tempfile::tempdir().expect("tempdir");
            let _state_dir = set_env_var_scoped(
                "CARAPACE_STATE_DIR",
                temp.path().to_str().expect("state dir path"),
            );
            let provider_config = OAuthProvider::Google
                .default_config(
                    "google-client-id",
                    "google-client-secret",
                    "https://gateway.example.com/control/onboarding/gemini/callback",
                )
                .unwrap();
            let profile = crate::auth::profiles::AuthProfile {
                id: "google-abc123".to_string(),
                name: "Google user@example.com".to_string(),
                provider: OAuthProvider::Google,
                user_id: Some("user-123".to_string()),
                email: Some("user@example.com".to_string()),
                display_name: Some("Example User".to_string()),
                avatar_url: None,
                created_at_ms: 0,
                last_used_ms: None,
                credential_kind: AuthProfileCredentialKind::OAuth,
                tokens: Some(crate::auth::profiles::OAuthTokens {
                    access_token: "access-token-a".to_string(),
                    refresh_token: Some("refresh-token-a".to_string()),
                    token_type: "Bearer".to_string(),
                    expires_at_ms: Some(1_000),
                    scope: Some("openid email profile".to_string()),
                }),
                token: None,
                oauth_provider_config: Some(
                    crate::auth::profiles::StoredOAuthProviderConfig::from(&provider_config),
                ),
            };
            let store = ProfileStore::from_env(temp.path().to_path_buf()).expect("profile store");
            store.add(profile).expect("store profile");

            let cfg = json!({
                "google": { "authProfile": "google-abc123" }
            });
            let fp1 = fingerprint_providers(&cfg);

            store
                .update_tokens(
                    "google-abc123",
                    crate::auth::profiles::OAuthTokens {
                        access_token: "access-token-b".to_string(),
                        refresh_token: Some("refresh-token-b".to_string()),
                        token_type: "Bearer".to_string(),
                        expires_at_ms: Some(2_000),
                        scope: Some("openid email profile".to_string()),
                    },
                )
                .expect("update tokens");

            let fp2 = fingerprint_providers(&cfg);
            assert_ne!(fp1.gemini, fp2.gemini);
        });
    }

    #[test]
    fn test_build_providers_ignores_blank_gemini_api_key_when_auth_profile_present() {
        with_clean_provider_env(|| {
            let temp = tempfile::tempdir().expect("tempdir");
            let _password = set_env_var_scoped("CARAPACE_CONFIG_PASSWORD", "test-config-password");
            let _state_dir = set_env_var_scoped(
                "CARAPACE_STATE_DIR",
                temp.path().to_str().expect("state dir path"),
            );
            let _blank_key = set_env_var_scoped("GOOGLE_API_KEY", "   ");

            let provider_config = OAuthProvider::Google
                .default_config(
                    "google-client-id",
                    "google-client-secret",
                    "https://gateway.example.com/control/onboarding/gemini/callback",
                )
                .unwrap();
            let profile = crate::auth::profiles::AuthProfile {
                id: "google-abc123".to_string(),
                name: "Google user@example.com".to_string(),
                provider: OAuthProvider::Google,
                user_id: Some("user-123".to_string()),
                email: Some("user@example.com".to_string()),
                display_name: Some("Example User".to_string()),
                avatar_url: None,
                created_at_ms: 0,
                last_used_ms: None,
                credential_kind: AuthProfileCredentialKind::OAuth,
                tokens: Some(crate::auth::profiles::OAuthTokens {
                    access_token: "access-token".to_string(),
                    refresh_token: Some("refresh-token".to_string()),
                    token_type: "Bearer".to_string(),
                    expires_at_ms: Some(u64::MAX),
                    scope: Some("openid email profile".to_string()),
                }),
                token: None,
                oauth_provider_config: Some(
                    crate::auth::profiles::StoredOAuthProviderConfig::from(&provider_config),
                ),
            };
            let store = ProfileStore::from_env(temp.path().to_path_buf()).expect("profile store");
            store.add(profile).expect("store profile");

            let cfg = json!({
                "google": { "authProfile": "google-abc123" }
            });
            let providers = build_providers(&cfg).expect("build providers");
            assert!(
                providers.is_some(),
                "blank GOOGLE_API_KEY should not mask auth-profile Gemini setup"
            );
        });
    }

    #[test]
    fn test_build_providers_with_codex_auth_profile() {
        with_clean_provider_env(|| {
            let temp = tempfile::tempdir().expect("tempdir");
            let _password = set_env_var_scoped("CARAPACE_CONFIG_PASSWORD", "test-config-password");
            let _state_dir = set_env_var_scoped(
                "CARAPACE_STATE_DIR",
                temp.path().to_str().expect("state dir path"),
            );

            let provider_config = OAuthProvider::OpenAI
                .default_config(
                    "openai-client-id",
                    "openai-client-secret",
                    "https://gateway.example.com/control/onboarding/codex/callback",
                )
                .unwrap();
            let profile = crate::auth::profiles::AuthProfile {
                id: "openai-abc123".to_string(),
                name: "Codex user@example.com".to_string(),
                provider: OAuthProvider::OpenAI,
                user_id: Some("user-123".to_string()),
                email: Some("user@example.com".to_string()),
                display_name: Some("Example User".to_string()),
                avatar_url: None,
                created_at_ms: 0,
                last_used_ms: None,
                credential_kind: AuthProfileCredentialKind::OAuth,
                tokens: Some(crate::auth::profiles::OAuthTokens {
                    access_token: "access-token".to_string(),
                    refresh_token: Some("refresh-token".to_string()),
                    token_type: "Bearer".to_string(),
                    expires_at_ms: Some(u64::MAX),
                    scope: Some("openid email profile offline_access".to_string()),
                }),
                token: None,
                oauth_provider_config: Some(
                    crate::auth::profiles::StoredOAuthProviderConfig::from(&provider_config),
                ),
            };
            let store = ProfileStore::from_env(temp.path().to_path_buf()).expect("profile store");
            store.add(profile).expect("store profile");

            let cfg = json!({
                "codex": { "authProfile": "openai-abc123" }
            });
            let providers = build_providers(&cfg).expect("build providers");
            assert!(
                providers.is_some(),
                "Codex auth profile should build a usable provider set"
            );
        });
    }

    #[test]
    fn test_build_providers_with_anthropic_auth_profile() {
        with_clean_provider_env(|| {
            let temp = tempfile::tempdir().expect("tempdir");
            let _password = set_env_var_scoped("CARAPACE_CONFIG_PASSWORD", "test-config-password");
            let _state_dir = set_env_var_scoped(
                "CARAPACE_STATE_DIR",
                temp.path().to_str().expect("state dir path"),
            );

            let profile = crate::auth::profiles::AuthProfile {
                id: "anthropic:default".to_string(),
                name: "Anthropic setup token".to_string(),
                provider: OAuthProvider::Anthropic,
                user_id: None,
                email: None,
                display_name: None,
                avatar_url: None,
                created_at_ms: 0,
                last_used_ms: None,
                credential_kind: AuthProfileCredentialKind::Token,
                tokens: None,
                token: Some("sk-ant-oat01-test-token".to_string()),
                oauth_provider_config: None,
            };
            let store = ProfileStore::from_env(temp.path().to_path_buf()).expect("profile store");
            store.add(profile).expect("store profile");

            let cfg = json!({
                "anthropic": { "authProfile": "anthropic:default" }
            });
            let providers = build_providers(&cfg).expect("build providers");
            assert!(
                providers.is_some(),
                "Anthropic auth profile should build a usable provider set"
            );
        });
    }

    #[test]
    fn test_build_providers_ignores_blank_anthropic_api_key_when_auth_profile_present() {
        with_clean_provider_env(|| {
            let temp = tempfile::tempdir().expect("tempdir");
            let _password = set_env_var_scoped("CARAPACE_CONFIG_PASSWORD", "test-config-password");
            let _state_dir = set_env_var_scoped(
                "CARAPACE_STATE_DIR",
                temp.path().to_str().expect("state dir path"),
            );
            let _blank_key = set_env_var_scoped("ANTHROPIC_API_KEY", "   ");

            let profile = crate::auth::profiles::AuthProfile {
                id: "anthropic:default".to_string(),
                name: "Anthropic setup token".to_string(),
                provider: OAuthProvider::Anthropic,
                user_id: None,
                email: None,
                display_name: None,
                avatar_url: None,
                created_at_ms: 0,
                last_used_ms: None,
                credential_kind: AuthProfileCredentialKind::Token,
                tokens: None,
                token: Some("sk-ant-oat01-test-token".to_string()),
                oauth_provider_config: None,
            };
            let store = ProfileStore::from_env(temp.path().to_path_buf()).expect("profile store");
            store.add(profile).expect("store profile");

            let cfg = json!({
                "anthropic": { "authProfile": "anthropic:default" }
            });
            let providers = build_providers(&cfg).expect("build providers");
            assert!(
                providers.is_some(),
                "blank ANTHROPIC_API_KEY should not mask auth-profile Anthropic setup"
            );
        });
    }

    #[test]
    fn test_build_providers_rejects_anthropic_auth_profile_without_token() {
        with_clean_provider_env(|| {
            let temp = tempfile::tempdir().expect("tempdir");
            let _password = set_env_var_scoped("CARAPACE_CONFIG_PASSWORD", "test-config-password");
            let _state_dir = set_env_var_scoped(
                "CARAPACE_STATE_DIR",
                temp.path().to_str().expect("state dir path"),
            );

            let profile = crate::auth::profiles::AuthProfile {
                id: "anthropic:default".to_string(),
                name: "Anthropic setup token".to_string(),
                provider: OAuthProvider::Anthropic,
                user_id: None,
                email: None,
                display_name: None,
                avatar_url: None,
                created_at_ms: 0,
                last_used_ms: None,
                credential_kind: AuthProfileCredentialKind::Token,
                tokens: None,
                token: Some("   ".to_string()),
                oauth_provider_config: None,
            };
            let store = ProfileStore::from_env(temp.path().to_path_buf()).expect("profile store");
            store.add(profile).expect("store profile");

            let cfg = json!({
                "anthropic": { "authProfile": "anthropic:default" }
            });
            let err = build_providers(&cfg).expect_err("missing token should fail fast");
            assert!(err.to_string().contains("has no usable token"));
        });
    }

    #[test]
    fn test_build_providers_rejects_missing_anthropic_auth_profile() {
        with_clean_provider_env(|| {
            let temp = tempfile::tempdir().expect("tempdir");
            let _password = set_env_var_scoped("CARAPACE_CONFIG_PASSWORD", "test-config-password");
            let _state_dir = set_env_var_scoped(
                "CARAPACE_STATE_DIR",
                temp.path().to_str().expect("state dir path"),
            );

            let store = ProfileStore::from_env(temp.path().to_path_buf()).expect("profile store");
            store.load().expect("load empty profile store");

            let cfg = json!({
                "anthropic": { "authProfile": "anthropic:missing" }
            });
            let err = build_providers(&cfg).expect_err("missing profile should fail fast");
            assert!(err
                .to_string()
                .contains("configured Anthropic auth profile \"anthropic:missing\" was not found"));
        });
    }

    #[test]
    fn test_build_providers_rejects_anthropic_auth_profile_without_password() {
        with_clean_provider_env(|| {
            let temp = tempfile::tempdir().expect("tempdir");
            let _state_dir = set_env_var_scoped(
                "CARAPACE_STATE_DIR",
                temp.path().to_str().expect("state dir path"),
            );

            let profile = crate::auth::profiles::AuthProfile {
                id: "anthropic:default".to_string(),
                name: "Anthropic setup token".to_string(),
                provider: OAuthProvider::Anthropic,
                user_id: None,
                email: None,
                display_name: None,
                avatar_url: None,
                created_at_ms: 0,
                last_used_ms: None,
                credential_kind: AuthProfileCredentialKind::Token,
                tokens: None,
                token: Some("sk-ant-oat01-test-token".to_string()),
                oauth_provider_config: None,
            };
            let store = ProfileStore::new(temp.path().to_path_buf());
            store.add(profile).expect("store profile");

            let cfg = json!({
                "anthropic": { "authProfile": "anthropic:default" }
            });
            let err = build_providers(&cfg).expect_err("missing password should fail fast");
            assert!(err.to_string().contains("CARAPACE_CONFIG_PASSWORD"));
        });
    }

    #[test]
    fn test_build_providers_rejects_anthropic_auth_profile_with_wrong_provider() {
        with_clean_provider_env(|| {
            let temp = tempfile::tempdir().expect("tempdir");
            let _password = set_env_var_scoped("CARAPACE_CONFIG_PASSWORD", "test-config-password");
            let _state_dir = set_env_var_scoped(
                "CARAPACE_STATE_DIR",
                temp.path().to_str().expect("state dir path"),
            );

            let profile = crate::auth::profiles::AuthProfile {
                id: "anthropic:default".to_string(),
                name: "Wrong profile".to_string(),
                provider: OAuthProvider::Google,
                user_id: Some("user-123".to_string()),
                email: Some("user@example.com".to_string()),
                display_name: Some("Example User".to_string()),
                avatar_url: None,
                created_at_ms: 0,
                last_used_ms: None,
                credential_kind: AuthProfileCredentialKind::Token,
                tokens: None,
                token: Some("sk-ant-oat01-test-token".to_string()),
                oauth_provider_config: None,
            };
            let store = ProfileStore::from_env(temp.path().to_path_buf()).expect("profile store");
            store.add(profile).expect("store profile");

            let cfg = json!({
                "anthropic": { "authProfile": "anthropic:default" }
            });
            let err = build_providers(&cfg).expect_err("wrong provider should fail fast");
            assert!(err.to_string().contains("belongs to google, not anthropic"));
        });
    }

    #[test]
    fn test_build_providers_rejects_anthropic_auth_profile_with_oauth_credential_kind() {
        with_clean_provider_env(|| {
            let temp = tempfile::tempdir().expect("tempdir");
            let _password = set_env_var_scoped("CARAPACE_CONFIG_PASSWORD", "test-config-password");
            let _state_dir = set_env_var_scoped(
                "CARAPACE_STATE_DIR",
                temp.path().to_str().expect("state dir path"),
            );

            let profile = crate::auth::profiles::AuthProfile {
                id: "anthropic:default".to_string(),
                name: "Anthropic oauth profile".to_string(),
                provider: OAuthProvider::Anthropic,
                user_id: Some("user-123".to_string()),
                email: Some("user@example.com".to_string()),
                display_name: Some("Example User".to_string()),
                avatar_url: None,
                created_at_ms: 0,
                last_used_ms: None,
                credential_kind: AuthProfileCredentialKind::OAuth,
                tokens: Some(crate::auth::profiles::OAuthTokens {
                    access_token: "access-token".to_string(),
                    refresh_token: Some("refresh-token".to_string()),
                    token_type: "Bearer".to_string(),
                    expires_at_ms: Some(u64::MAX),
                    scope: None,
                }),
                token: None,
                oauth_provider_config: None,
            };
            let store = ProfileStore::from_env(temp.path().to_path_buf()).expect("profile store");
            store.add(profile).expect("store profile");

            let cfg = json!({
                "anthropic": { "authProfile": "anthropic:default" }
            });
            let err = build_providers(&cfg).expect_err("oauth-backed profile should fail fast");
            assert!(err.to_string().contains("is not token-backed"));
        });
    }

    #[test]
    fn test_resolve_google_oauth_runtime_config_uses_stored_redirect_uri_when_missing() {
        with_clean_provider_env(|| {
            let temp = tempfile::tempdir().expect("tempdir");
            let provider_config = OAuthProvider::Google
                .default_config(
                    "google-client-id",
                    "google-client-secret",
                    "https://gateway.example.com/control/onboarding/gemini/callback",
                )
                .unwrap();
            let profile = crate::auth::profiles::AuthProfile {
                id: "google-abc123".to_string(),
                name: "Google user@example.com".to_string(),
                provider: OAuthProvider::Google,
                user_id: Some("user-123".to_string()),
                email: Some("user@example.com".to_string()),
                display_name: Some("Example User".to_string()),
                avatar_url: None,
                created_at_ms: 0,
                last_used_ms: None,
                credential_kind: AuthProfileCredentialKind::OAuth,
                tokens: Some(crate::auth::profiles::OAuthTokens {
                    access_token: "access-token".to_string(),
                    refresh_token: Some("refresh-token".to_string()),
                    token_type: "Bearer".to_string(),
                    expires_at_ms: Some(u64::MAX),
                    scope: Some("openid email profile".to_string()),
                }),
                token: None,
                oauth_provider_config: Some(
                    crate::auth::profiles::StoredOAuthProviderConfig::from(&provider_config),
                ),
            };
            let store = ProfileStore::from_env(temp.path().to_path_buf()).expect("profile store");
            store.add(profile).expect("store profile");

            let cfg = json!({
                "google": { "authProfile": "google-abc123" }
            });
            let resolved = resolve_google_oauth_runtime_config(&cfg, temp.path(), "google-abc123")
                .expect("runtime config");

            assert_eq!(
                resolved.redirect_uri,
                "https://gateway.example.com/control/onboarding/gemini/callback"
            );
        });
    }

    #[test]
    fn test_fingerprint_detects_key_change() {
        with_clean_provider_env(|| {
            let cfg1 = json!({ "anthropic": { "apiKey": "key-a" } });
            let cfg2 = json!({ "anthropic": { "apiKey": "key-b" } });
            let fp1 = fingerprint_providers(&cfg1);
            let fp2 = fingerprint_providers(&cfg2);
            assert_ne!(fp1, fp2);
        });
    }

    #[test]
    fn test_fingerprint_same_key_same_hash() {
        with_clean_provider_env(|| {
            let cfg = json!({ "anthropic": { "apiKey": "key-same" } });
            let fp1 = fingerprint_providers(&cfg);
            let fp2 = fingerprint_providers(&cfg);
            assert_eq!(fp1, fp2);
        });
    }

    #[test]
    fn test_fingerprint_ollama_configured() {
        with_clean_provider_env(|| {
            let cfg = json!({ "providers": { "ollama": { "baseUrl": "http://localhost:11434" } } });
            let fp = fingerprint_providers(&cfg);
            assert!(fp.ollama.is_some());
            let (configured, url) = fp.ollama.unwrap();
            assert!(configured);
            assert_eq!(url.as_deref(), Some("http://localhost:11434"));
        });
    }

    #[test]
    fn test_fingerprint_bedrock_configured() {
        with_clean_provider_env(|| {
            let cfg = json!({
                "bedrock": {
                    "region": "us-east-1",
                    "accessKeyId": "AKIAIOSFODNN7EXAMPLE",
                    "secretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
                }
            });
            let fp = fingerprint_providers(&cfg);
            assert!(fp.bedrock.is_some());
            let combined = format!("{}{}", "us-east-1", "AKIAIOSFODNN7EXAMPLE");
            let expected_hash = hash_key_prefix(&combined);
            assert_eq!(fp.bedrock, Some(expected_hash));
        });
    }

    #[test]
    fn test_fingerprint_bedrock_detects_change() {
        with_clean_provider_env(|| {
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
        });
    }

    #[test]
    fn test_fingerprint_bedrock_disabled() {
        with_clean_provider_env(|| {
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
        });
    }

    #[test]
    fn test_fingerprint_bedrock_partial_creds() {
        with_clean_provider_env(|| {
            // Only region, missing access key — should be None
            let cfg = json!({
                "bedrock": { "region": "us-east-1" }
            });
            let fp = fingerprint_providers(&cfg);
            assert!(fp.bedrock.is_none());
        });
    }

    #[test]
    fn test_fingerprint_vertex_hashes_project_id() {
        with_clean_provider_env(|| {
            let cfg = json!({
                "vertex": {
                    "projectId": "my-project",
                    "location": "us-central1",
                    "model": "gemini-2.0-flash"
                }
            });
            let fp = fingerprint_providers(&cfg);
            assert_eq!(
                fp.vertex,
                Some((
                    hash_key_prefix("my-project"),
                    "us-central1".to_string(),
                    Some("gemini-2.0-flash".to_string())
                ))
            );
        });
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

    fn sample_anthropic_token_profile() -> crate::auth::profiles::AuthProfile {
        crate::auth::profiles::AuthProfile {
            id: "anthropic:default".to_string(),
            name: "Test".to_string(),
            provider: OAuthProvider::Anthropic,
            user_id: None,
            email: None,
            display_name: None,
            avatar_url: None,
            created_at_ms: 0,
            last_used_ms: None,
            credential_kind: AuthProfileCredentialKind::Token,
            tokens: None,
            token: Some("sk-ant-oat01-test-token".to_string()),
            oauth_provider_config: None,
        }
    }

    fn random_test_password() -> String {
        let mut bytes = [0u8; 24];
        getrandom::fill(&mut bytes).expect("random test password bytes");
        hex::encode(bytes)
    }

    #[test]
    fn anthropic_auth_profile_fingerprint_with_correct_password() {
        with_clean_provider_env(|| {
            let dir = tempfile::tempdir().unwrap();
            let password = random_test_password();
            let _pw = set_env_var_scoped("CARAPACE_CONFIG_PASSWORD", &password);
            let _sd = set_env_var_scoped("CARAPACE_STATE_DIR", dir.path().to_str().unwrap());

            let store =
                ProfileStore::with_encryption(dir.path().to_path_buf(), password.as_bytes())
                    .unwrap();
            store.add(sample_anthropic_token_profile()).unwrap();

            let cfg = json!({ "anthropic": { "authProfile": "anthropic:default" } });
            let fp = resolve_anthropic_auth_profile_fingerprint(&cfg);

            assert!(
                fp.is_some(),
                "fingerprint should resolve with correct password"
            );
            assert!(fp.unwrap().starts_with("auth-profile:anthropic:default:"));
        });
    }

    #[test]
    fn anthropic_auth_profile_fingerprint_differs_with_wrong_password() {
        with_clean_provider_env(|| {
            let dir = tempfile::tempdir().unwrap();
            let password = random_test_password();
            let wrong_password = random_test_password();

            let store =
                ProfileStore::with_encryption(dir.path().to_path_buf(), password.as_bytes())
                    .unwrap();
            store.add(sample_anthropic_token_profile()).unwrap();

            let cfg = json!({ "anthropic": { "authProfile": "anthropic:default" } });

            // Fingerprint with correct password.
            let _pw = set_env_var_scoped("CARAPACE_CONFIG_PASSWORD", &password);
            let _sd = set_env_var_scoped("CARAPACE_STATE_DIR", dir.path().to_str().unwrap());
            let fp_correct = resolve_anthropic_auth_profile_fingerprint(&cfg);
            drop(_pw);
            drop(_sd);

            // Fingerprint with wrong password — store loads but token stays
            // encrypted, producing a different fingerprint hash.
            let _pw2 = set_env_var_scoped("CARAPACE_CONFIG_PASSWORD", &wrong_password);
            let _sd2 = set_env_var_scoped("CARAPACE_STATE_DIR", dir.path().to_str().unwrap());
            let fp_wrong = resolve_anthropic_auth_profile_fingerprint(&cfg);

            assert!(fp_correct.is_some());
            assert!(fp_wrong.is_some());
            assert_ne!(
                fp_correct, fp_wrong,
                "fingerprint should differ when password is wrong (token stays encrypted)"
            );
        });
    }

    #[test]
    fn anthropic_auth_profile_fingerprint_no_profile_configured() {
        with_clean_provider_env(|| {
            let cfg = json!({ "anthropic": { "apiKey": "sk-ant-test" } });
            let fp = resolve_anthropic_auth_profile_fingerprint(&cfg);
            assert!(fp.is_none());
        });
    }
}
