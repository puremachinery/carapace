//! OpenAI Codex subscription provider.
//!
//! Uses a stored OpenAI OAuth profile to call the OpenAI Chat Completions API
//! with a refreshed bearer token under explicit `codex:` / `codex/` routing.

use async_trait::async_trait;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

use crate::agent::openai::OpenAiProvider;
use crate::agent::provider::*;
use crate::agent::AgentError;
use crate::auth::profiles::{refresh_token, OAuthProviderConfig, ProfileStore};

const TOKEN_REFRESH_MARGIN_MS: u64 = 60_000;
pub const DEFAULT_CODEX_MODEL: &str = "gpt-5.4";

/// OpenAI Codex provider backed by a stored OAuth auth profile.
pub struct CodexProvider {
    profile_store: Arc<ProfileStore>,
    profile_id: String,
    provider_config: OAuthProviderConfig,
    refresh_lock: Arc<Mutex<()>>,
}

impl std::fmt::Debug for CodexProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CodexProvider")
            .field("profile_id", &self.profile_id)
            .finish_non_exhaustive()
    }
}

impl CodexProvider {
    pub fn with_oauth_profile(
        profile_store: Arc<ProfileStore>,
        profile_id: String,
        provider_config: OAuthProviderConfig,
    ) -> Result<Self, AgentError> {
        if profile_id.trim().is_empty() {
            return Err(AgentError::Provider(
                "Codex auth profile ID must not be empty".to_string(),
            ));
        }
        Ok(Self {
            profile_store,
            profile_id,
            provider_config,
            refresh_lock: Arc::new(Mutex::new(())),
        })
    }

    async fn access_token(&self) -> Result<String, AgentError> {
        let mut profile = self.profile_store.get(&self.profile_id).ok_or_else(|| {
            AgentError::Provider(format!(
                "configured Codex auth profile \"{}\" was not found",
                self.profile_id
            ))
        })?;
        let now_ms = current_time_ms();
        if profile
            .tokens
            .expires_at_ms
            .is_some_and(|expires_at| expires_at <= now_ms + TOKEN_REFRESH_MARGIN_MS)
        {
            let _refresh_guard = self.refresh_lock.lock().await;
            let refreshed_profile = self.profile_store.get(&self.profile_id).ok_or_else(|| {
                AgentError::Provider(format!(
                    "configured Codex auth profile \"{}\" was not found",
                    self.profile_id
                ))
            })?;
            let now_ms_after_lock = current_time_ms();
            if refreshed_profile
                .tokens
                .expires_at_ms
                .is_none_or(|expires_at| expires_at > now_ms_after_lock + TOKEN_REFRESH_MARGIN_MS)
            {
                profile = refreshed_profile;
            } else {
                let refresh_token_value = refreshed_profile
                    .tokens
                    .refresh_token
                    .clone()
                    .filter(|token| !token.trim().is_empty())
                    .ok_or_else(|| {
                        AgentError::Provider(format!(
                            "Codex auth profile \"{}\" is expired and cannot be refreshed",
                            self.profile_id
                        ))
                    })?;
                let refreshed = refresh_token(&self.provider_config, &refresh_token_value)
                    .await
                    .map_err(|err| {
                        AgentError::Provider(format!(
                            "failed to refresh Codex auth profile \"{}\": {err}",
                            self.profile_id
                        ))
                    })?;
                self.profile_store
                    .update_tokens(&self.profile_id, refreshed.clone())
                    .map_err(|err| {
                        AgentError::Provider(format!(
                            "failed to persist refreshed Codex auth profile \"{}\": {err}",
                            self.profile_id
                        ))
                    })?;
                profile = refreshed_profile;
                profile.tokens = refreshed;
            }
        }

        let access_token = profile.tokens.access_token.trim();
        if access_token.is_empty() {
            return Err(AgentError::Provider(format!(
                "Codex auth profile \"{}\" has no usable access token",
                self.profile_id
            )));
        }
        Ok(access_token.to_string())
    }

    fn effective_model(model: &str) -> &str {
        if model.eq_ignore_ascii_case("default") {
            DEFAULT_CODEX_MODEL
        } else {
            model
        }
    }
}

#[async_trait]
impl LlmProvider for CodexProvider {
    async fn complete(
        &self,
        mut request: CompletionRequest,
        cancel_token: CancellationToken,
    ) -> Result<tokio::sync::mpsc::Receiver<StreamEvent>, AgentError> {
        let access_token = self.access_token().await?;
        request.model = Self::effective_model(&request.model).to_string();
        let provider = OpenAiProvider::new(access_token)?;
        provider.complete(request, cancel_token).await
    }
}

pub fn is_codex_model(model: &str) -> bool {
    let lower = model.to_lowercase();
    lower.starts_with("codex:") || lower.starts_with("codex/")
}

pub fn strip_codex_prefix(model: &str) -> &str {
    if let Some(rest) = model.strip_prefix("codex:") {
        rest
    } else if let Some(rest) = model.strip_prefix("codex/") {
        rest
    } else if let Some(rest) = model.strip_prefix("Codex:") {
        rest
    } else if let Some(rest) = model.strip_prefix("Codex/") {
        rest
    } else {
        model
    }
}

fn current_time_ms() -> u64 {
    crate::time::unix_now_ms_u64()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::profiles::{
        AuthProfile, OAuthProvider, OAuthTokens, StoredOAuthProviderConfig,
    };

    fn sample_tokens() -> OAuthTokens {
        OAuthTokens {
            access_token: "access-token".to_string(),
            refresh_token: Some("refresh-token".to_string()),
            token_type: "Bearer".to_string(),
            expires_at_ms: Some(current_time_ms() + 3_600_000),
            scope: Some("openid profile email offline_access".to_string()),
        }
    }

    fn sample_profile(id: &str) -> AuthProfile {
        let provider_config = OAuthProvider::OpenAI.default_config(
            "client-id",
            "client-secret",
            "http://127.0.0.1:3000/auth/callback",
        );
        AuthProfile {
            id: id.to_string(),
            name: "Codex (user@example.com)".to_string(),
            provider: OAuthProvider::OpenAI,
            user_id: Some("user-123".to_string()),
            email: Some("user@example.com".to_string()),
            display_name: Some("user@example.com".to_string()),
            avatar_url: None,
            created_at_ms: current_time_ms(),
            last_used_ms: Some(current_time_ms()),
            tokens: sample_tokens(),
            oauth_provider_config: Some(StoredOAuthProviderConfig::from(&provider_config)),
        }
    }

    #[test]
    fn test_is_codex_model() {
        assert!(is_codex_model("codex:gpt-5.4"));
        assert!(is_codex_model("codex/default"));
        assert!(is_codex_model("Codex:gpt-5.4"));
        assert!(!is_codex_model("gpt-5.4"));
        assert!(!is_codex_model("openai:gpt-5.4"));
    }

    #[test]
    fn test_strip_codex_prefix() {
        assert_eq!(strip_codex_prefix("codex:gpt-5.4"), "gpt-5.4");
        assert_eq!(strip_codex_prefix("codex/default"), "default");
        assert_eq!(strip_codex_prefix("Codex:gpt-5.4"), "gpt-5.4");
        assert_eq!(strip_codex_prefix("gpt-5.4"), "gpt-5.4");
    }

    #[test]
    fn test_effective_model_uses_default_mapping() {
        assert_eq!(
            CodexProvider::effective_model("default"),
            DEFAULT_CODEX_MODEL
        );
        assert_eq!(
            CodexProvider::effective_model("DEFAULT"),
            DEFAULT_CODEX_MODEL
        );
        assert_eq!(
            CodexProvider::effective_model("gpt-5.3-codex"),
            "gpt-5.3-codex"
        );
    }

    #[tokio::test]
    async fn test_codex_provider_missing_profile_errors() {
        let temp = tempfile::tempdir().expect("tempdir");
        let store = Arc::new(ProfileStore::from_env(temp.path().to_path_buf()).expect("store"));
        let provider = CodexProvider::with_oauth_profile(
            store,
            "missing-profile".to_string(),
            OAuthProvider::OpenAI.default_config(
                "client-id",
                "client-secret",
                "http://127.0.0.1:3000/auth/callback",
            ),
        )
        .expect("provider");

        let err = provider
            .access_token()
            .await
            .expect_err("missing profile should fail");
        assert!(err
            .to_string()
            .contains("configured Codex auth profile \"missing-profile\" was not found"));
    }

    #[tokio::test]
    async fn test_codex_provider_empty_token_errors() {
        let temp = tempfile::tempdir().expect("tempdir");
        let provider_config = OAuthProvider::OpenAI.default_config(
            "client-id",
            "client-secret",
            "http://127.0.0.1:3000/auth/callback",
        );
        let profile = AuthProfile {
            tokens: OAuthTokens {
                access_token: "   ".to_string(),
                ..sample_tokens()
            },
            ..sample_profile("openai-empty-token")
        };
        let store = Arc::new(ProfileStore::from_env(temp.path().to_path_buf()).expect("store"));
        store.add(profile).expect("store profile");
        let provider = CodexProvider::with_oauth_profile(
            store,
            "openai-empty-token".to_string(),
            provider_config,
        )
        .expect("provider");

        let err = provider
            .access_token()
            .await
            .expect_err("empty token should fail");
        assert!(err
            .to_string()
            .contains("Codex auth profile \"openai-empty-token\" has no usable access token"));
    }
}
