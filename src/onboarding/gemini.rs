use serde::Serialize;
use serde_json::{json, Value};
use sha2::Digest;
use std::path::{Path, PathBuf};

use crate::auth::profiles::{
    AuthProfile, AuthProfileCredentialKind, OAuthProvider, OAuthProviderConfig, OAuthTokens,
    ProfileStore, StoredOAuthProviderConfig, UserInfo,
};
use crate::onboarding::oauth::{self, OAuthCompletion, OAuthOnboardingSpec, OAuthStatusResult};
#[cfg(test)]
use crate::onboarding::oauth::{OAuthFlowState, PendingOAuthFlow};
use crate::server::ws::read_config_snapshot;

// ---------------------------------------------------------------------------
// Gemini spec
// ---------------------------------------------------------------------------

pub(crate) static GEMINI_SPEC: OAuthOnboardingSpec = OAuthOnboardingSpec {
    oauth_provider: OAuthProvider::Google,
    display_name: "Gemini",
    idp_display_name: "Google",
    provider_label: "gemini",
    client_id_env: "GOOGLE_OAUTH_CLIENT_ID",
    client_secret_env: "GOOGLE_OAUTH_CLIENT_SECRET",
    max_pending_flows: 20,
    flow_ttl_secs: 30 * 60,
    resolve_provider_config: resolve_google_oauth_provider_config,
    build_auth_profile: build_gemini_auth_profile,
    write_provider_config: write_gemini_provider_config,
};

// ---------------------------------------------------------------------------
// Public types (stable API surface for control.rs and cli/mod.rs)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GeminiOAuthStart {
    pub flow_id: String,
    pub auth_url: String,
    pub redirect_uri: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GeminiOAuthStatus {
    pub flow_id: String,
    pub status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Clone)]
pub struct GeminiOAuthCompletion {
    pub client_id: String,
    pub auth_profile: AuthProfile,
}

#[derive(Clone)]
pub struct GeminiApiKeyInput {
    pub api_key: String,
    pub base_url: Option<String>,
}

// ---------------------------------------------------------------------------
// Hook: resolve_provider_config
// ---------------------------------------------------------------------------

pub fn resolve_google_oauth_provider_config(
    cfg: &Value,
    client_id_override: Option<String>,
    client_secret_override: Option<String>,
    redirect_uri: String,
    state_dir: &Path,
) -> Result<OAuthProviderConfig, String> {
    let stored_provider_config = load_stored_google_provider_config(cfg, state_dir);

    let client_id = client_id_override
        .or_else(|| std::env::var(GEMINI_SPEC.client_id_env).ok())
        .or_else(|| configured_google_oauth_client_id(cfg))
        .or_else(|| {
            stored_provider_config
                .as_ref()
                .map(|cfg| cfg.client_id.clone())
        })
        .unwrap_or_default();
    let client_secret = client_secret_override
        .or_else(|| std::env::var(GEMINI_SPEC.client_secret_env).ok())
        .or_else(|| {
            stored_provider_config
                .as_ref()
                .map(|cfg| cfg.client_secret.clone())
        })
        .unwrap_or_default();

    if client_id.trim().is_empty() || client_secret.trim().is_empty() {
        return Err(
            "Gemini Google sign-in requires Google OAuth clientId and clientSecret.".to_string(),
        );
    }

    let mut provider_config = OAuthProvider::Google
        .default_config(client_id.trim(), client_secret.trim(), &redirect_uri)
        .expect("Google is an OAuth provider");
    if let Some(stored) = stored_provider_config {
        provider_config.auth_url = stored.auth_url;
        provider_config.token_url = stored.token_url;
        provider_config.userinfo_url = stored.userinfo_url;
        provider_config.scopes = stored.scopes;
    }
    Ok(provider_config)
}

// ---------------------------------------------------------------------------
// Hook: build_auth_profile
// ---------------------------------------------------------------------------

fn build_gemini_auth_profile(
    tokens: OAuthTokens,
    provider_config: &OAuthProviderConfig,
    userinfo: UserInfo,
) -> AuthProfile {
    let now_ms = oauth::now_ms();
    let id_seed = userinfo
        .email
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or(&userinfo.user_id);
    let mut hasher = sha2::Sha256::new();
    hasher.update(id_seed.as_bytes());
    let digest = hasher.finalize();
    let short = hex::encode(&digest[..6]);
    let display = userinfo
        .display_name
        .clone()
        .or_else(|| userinfo.email.clone())
        .unwrap_or_else(|| "Google account".to_string());

    AuthProfile {
        id: format!("google-{short}"),
        name: format!("Gemini ({display})"),
        provider: OAuthProvider::Google,
        user_id: Some(userinfo.user_id),
        email: userinfo.email,
        display_name: userinfo.display_name,
        avatar_url: userinfo.avatar_url,
        created_at_ms: now_ms,
        last_used_ms: Some(now_ms),
        credential_kind: AuthProfileCredentialKind::OAuth,
        tokens: Some(tokens),
        token: None,
        oauth_provider_config: Some(StoredOAuthProviderConfig::from(provider_config)),
    }
}

// ---------------------------------------------------------------------------
// Hook: write_provider_config
// ---------------------------------------------------------------------------

fn write_gemini_provider_config(cfg: &mut Value, profile_id: &str, client_id: &str) {
    if !cfg.get("auth").is_some_and(Value::is_object) {
        cfg["auth"] = json!({});
    }
    if !cfg["auth"].get("profiles").is_some_and(Value::is_object) {
        cfg["auth"]["profiles"] = json!({});
    }
    cfg["auth"]["profiles"]["enabled"] = json!(true);
    if !cfg["auth"]["profiles"]
        .get("providers")
        .is_some_and(Value::is_object)
    {
        cfg["auth"]["profiles"]["providers"] = json!({});
    }
    if !cfg["auth"]["profiles"]["providers"]
        .get("google")
        .is_some_and(Value::is_object)
    {
        cfg["auth"]["profiles"]["providers"]["google"] = json!({});
    }
    cfg["auth"]["profiles"]["providers"]["google"]["clientId"] = json!(client_id);
    if let Some(google_provider) = cfg["auth"]["profiles"]["providers"]
        .get_mut("google")
        .and_then(Value::as_object_mut)
    {
        google_provider.remove("clientSecret");
    }

    if !cfg.get("google").is_some_and(Value::is_object) {
        cfg["google"] = json!({});
    }
    if let Some(google) = cfg.get_mut("google").and_then(Value::as_object_mut) {
        google.remove("apiKey");
        google.insert("authProfile".to_string(), json!(profile_id));
    }
}

// ---------------------------------------------------------------------------
// Public API: Control-facing delegates
// ---------------------------------------------------------------------------

pub fn start_control_google_oauth(
    cfg: &Value,
    client_id_override: Option<String>,
    client_secret_override: Option<String>,
    redirect_base_url: &str,
) -> Result<GeminiOAuthStart, String> {
    let result = oauth::start_oauth_flow(
        &GEMINI_SPEC,
        cfg,
        client_id_override,
        client_secret_override,
        redirect_base_url,
    )?;
    Ok(GeminiOAuthStart {
        flow_id: result.flow_id,
        auth_url: result.auth_url,
        redirect_uri: result.redirect_uri,
    })
}

pub async fn complete_control_google_oauth_callback(
    state_param: &str,
    code: Option<&str>,
    error: Option<&str>,
    error_description: Option<&str>,
) -> Result<(), String> {
    oauth::complete_oauth_callback(&GEMINI_SPEC, state_param, code, error, error_description).await
}

pub fn control_google_oauth_status(flow_id: &str) -> Result<GeminiOAuthStatus, String> {
    match oauth::oauth_flow_status(&GEMINI_SPEC, flow_id) {
        OAuthStatusResult::InProgress => Ok(GeminiOAuthStatus {
            flow_id: flow_id.to_string(),
            status: "pending",
            profile_name: None,
            email: None,
            error: None,
        }),
        OAuthStatusResult::Completed {
            profile_name,
            email,
        } => Ok(GeminiOAuthStatus {
            flow_id: flow_id.to_string(),
            status: "completed",
            profile_name: Some(profile_name),
            email,
            error: None,
        }),
        OAuthStatusResult::Failed { error } => Ok(GeminiOAuthStatus {
            flow_id: flow_id.to_string(),
            status: "failed",
            profile_name: None,
            email: None,
            error: Some(error),
        }),
        OAuthStatusResult::NotFound => Err("Unknown or expired Gemini OAuth flow".to_string()),
    }
}

pub fn apply_control_google_oauth(flow_id: &str, state_dir: PathBuf) -> Result<Value, String> {
    oauth::require_encrypted_profile_store(&GEMINI_SPEC)?;
    let mut snapshot = read_config_snapshot();
    let result = oauth::apply_oauth_flow(&GEMINI_SPEC, flow_id, &state_dir, &mut snapshot.config)?;

    Ok(json!({
        "profileId": result.profile_id,
        "mode": "oauth",
    }))
}

pub fn apply_control_gemini_api_key(input: GeminiApiKeyInput) -> Result<Value, String> {
    let mut config = read_config_snapshot().config;
    validate_gemini_api_key_input(&input.api_key, input.base_url.as_deref())
        .map_err(|err| err.to_string())?;
    write_gemini_api_key_config(&mut config, &input.api_key, input.base_url.as_deref());
    oauth::validate_and_persist_config(&config)?;
    Ok(json!({
        "mode": "apiKey"
    }))
}

// ---------------------------------------------------------------------------
// Public API: CLI-facing delegates
// ---------------------------------------------------------------------------

pub async fn run_cli_google_oauth(
    cfg: Value,
    client_id_override: Option<String>,
    client_secret_override: Option<String>,
) -> Result<GeminiOAuthCompletion, String> {
    let completion = oauth::run_cli_oauth(
        &GEMINI_SPEC,
        &cfg,
        client_id_override,
        client_secret_override,
    )
    .await?;
    Ok(GeminiOAuthCompletion {
        client_id: completion.client_id,
        auth_profile: completion.auth_profile,
    })
}

pub fn persist_cli_google_oauth(
    state_dir: PathBuf,
    config: &mut Value,
    completion: GeminiOAuthCompletion,
) -> Result<String, String> {
    oauth::require_encrypted_profile_store(&GEMINI_SPEC)?;
    let oauth_completion = OAuthCompletion {
        client_id: completion.client_id,
        auth_profile: completion.auth_profile,
    };
    oauth::persist_cli_oauth(&GEMINI_SPEC, oauth_completion, &state_dir, config)
}

// Re-export callback_html from the shared module.
pub(crate) fn callback_html(title: &str, body: &str) -> String {
    oauth::callback_html(title, body)
}

// ---------------------------------------------------------------------------
// Public API: API-key path (unchanged)
// ---------------------------------------------------------------------------

pub fn validate_gemini_api_key_input(
    api_key: &str,
    base_url: Option<&str>,
) -> Result<(), crate::agent::AgentError> {
    if api_key.trim().is_empty() {
        return Err(crate::agent::AgentError::InvalidApiKey(
            "API key must not be empty".to_string(),
        ));
    }
    if let Some(url) = base_url.filter(|value| !value.trim().is_empty()) {
        validate_gemini_base_url(url.trim())?;
    }
    Ok(())
}

pub fn validate_gemini_base_url_input(
    base_url: Option<&str>,
) -> Result<(), crate::agent::AgentError> {
    if let Some(url) = base_url.filter(|value| !value.trim().is_empty()) {
        validate_gemini_base_url(url.trim())?;
    }
    Ok(())
}

pub fn write_gemini_api_key_config(config: &mut Value, api_key: &str, base_url: Option<&str>) {
    if !config.get("google").is_some_and(Value::is_object) {
        config["google"] = json!({});
    }
    config["google"]["apiKey"] = json!(api_key);
    if let Some(google) = config.get_mut("google").and_then(Value::as_object_mut) {
        match base_url.filter(|value| !value.trim().is_empty()) {
            Some(url) => {
                google.insert("baseUrl".to_string(), json!(url.trim()));
            }
            None => {
                google.remove("baseUrl");
            }
        }
        google.remove("authProfile");
    }
}

// ---------------------------------------------------------------------------
// Private helpers (Google-specific config resolution)
// ---------------------------------------------------------------------------

fn configured_google_oauth_client_id(cfg: &Value) -> Option<String> {
    cfg.pointer("/auth/profiles/providers/google/clientId")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
}

fn load_stored_google_provider_config(
    cfg: &Value,
    state_dir: &Path,
) -> Option<StoredOAuthProviderConfig> {
    let profile_id = cfg
        .get("google")
        .and_then(|value| value.get("authProfile"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())?;
    let store = ProfileStore::from_env(state_dir.to_path_buf()).ok()?;
    store.load().ok()?;
    let profile = store.get(profile_id)?;
    if profile.provider != OAuthProvider::Google {
        return None;
    }
    profile.oauth_provider_config
}

fn validate_gemini_base_url(url: &str) -> Result<(), crate::agent::AgentError> {
    let parsed = url::Url::parse(url).map_err(|err| {
        crate::agent::AgentError::InvalidBaseUrl(format!("invalid URL \"{url}\": {err}"))
    })?;
    if parsed.scheme() != "https" {
        return Err(crate::agent::AgentError::InvalidBaseUrl(format!(
            "base URL must use https scheme, got \"{}\"",
            parsed.scheme()
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Test helper (used by src/server/http.rs integration tests)
// ---------------------------------------------------------------------------

#[cfg(test)]
pub(crate) fn insert_completed_control_google_oauth_flow_for_test() -> String {
    let flow_id = format!("gemini-test-flow-{}", uuid::Uuid::new_v4());
    let provider_config = OAuthProvider::Google
        .default_config(
            "google-client-id",
            "google-client-secret",
            "https://gateway.example.com/control/onboarding/gemini/callback",
        )
        .unwrap();
    let tokens = OAuthTokens {
        access_token: "google-access-token".to_string(),
        refresh_token: Some("google-refresh-token".to_string()),
        token_type: "Bearer".to_string(),
        expires_at_ms: Some(oauth::now_ms() + 3_600_000),
        scope: Some("openid email profile".to_string()),
    };
    let userinfo = UserInfo {
        user_id: "user-123".to_string(),
        email: Some("user@example.com".to_string()),
        display_name: Some("Example User".to_string()),
        avatar_url: None,
    };
    let flow = PendingOAuthFlow {
        id: flow_id.clone(),
        state: format!("state-{flow_id}"),
        code_verifier: "verifier".to_string(),
        provider_config: provider_config.clone(),
        created_at_ms: oauth::now_ms(),
        flow_state: OAuthFlowState::Completed(Box::new(OAuthCompletion {
            client_id: "google-client-id".to_string(),
            auth_profile: build_gemini_auth_profile(tokens, &provider_config, userinfo),
        })),
        spec: &GEMINI_SPEC,
    };
    oauth::insert_oauth_flow(flow).expect("insert test flow");
    flow_id
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::profiles::OAuthTokens;
    use crate::test_support::env::ScopedEnv;
    use serde_json::json;

    fn sample_tokens() -> OAuthTokens {
        OAuthTokens {
            access_token: "google-access-token".to_string(),
            refresh_token: Some("google-refresh-token".to_string()),
            token_type: "Bearer".to_string(),
            expires_at_ms: Some(oauth::now_ms() + 3_600_000),
            scope: Some("openid email profile".to_string()),
        }
    }

    fn sample_user_info() -> UserInfo {
        UserInfo {
            user_id: "user-123".to_string(),
            email: Some("user@example.com".to_string()),
            display_name: Some("Example User".to_string()),
            avatar_url: None,
        }
    }

    #[test]
    fn test_resolve_google_oauth_provider_config_uses_configured_client_id_and_env_secret() {
        let mut env_guard = ScopedEnv::new();
        env_guard.set(GEMINI_SPEC.client_secret_env, "env-client-secret");
        let cfg = json!({
            "auth": {
                "profiles": {
                    "enabled": true,
                    "providers": {
                        "google": {
                            "clientId": "existing-client-id"
                        }
                    }
                }
            }
        });
        let temp = tempfile::tempdir().expect("tempdir");

        let provider = resolve_google_oauth_provider_config(
            &cfg,
            None,
            None,
            "http://127.0.0.1:3000/auth/callback".to_string(),
            temp.path(),
        )
        .expect("provider config");

        assert!(provider.client_id == "existing-client-id");
        assert!(provider.client_secret == "env-client-secret");
    }

    #[test]
    fn test_resolve_google_oauth_provider_config_uses_stored_profile_provider_config() {
        let mut env_guard = ScopedEnv::new();
        env_guard.set("CARAPACE_CONFIG_PASSWORD", "test-config-password");
        let temp = tempfile::tempdir().expect("tempdir");
        let state_dir = temp.path().to_path_buf();
        let provider_config = OAuthProvider::Google
            .default_config(
                "stored-client-id",
                "stored-client-secret",
                "http://127.0.0.1:3000/auth/callback",
            )
            .unwrap();
        let profile =
            build_gemini_auth_profile(sample_tokens(), &provider_config, sample_user_info());
        let profile_id = profile.id.clone();
        let store = ProfileStore::from_env(state_dir.clone()).expect("profile store from env");
        store.add(profile).expect("store profile");

        let cfg = json!({
            "google": {
                "authProfile": profile_id
            }
        });

        let provider = resolve_google_oauth_provider_config(
            &cfg,
            None,
            None,
            "http://127.0.0.1:3000/auth/callback".to_string(),
            &state_dir,
        )
        .expect("provider config");

        assert!(provider.client_id == "stored-client-id");
        assert!(provider.client_secret == "stored-client-secret");
    }

    #[test]
    fn test_resolve_google_oauth_provider_config_prefers_explicit_credentials_over_stored_profile()
    {
        let mut env_guard = ScopedEnv::new();
        env_guard.set("CARAPACE_CONFIG_PASSWORD", "test-config-password");
        let temp = tempfile::tempdir().expect("tempdir");
        let state_dir = temp.path().to_path_buf();
        let provider_config = OAuthProvider::Google
            .default_config(
                "stored-client-id",
                "stored-client-secret",
                "http://127.0.0.1:3000/auth/callback",
            )
            .unwrap();
        let profile =
            build_gemini_auth_profile(sample_tokens(), &provider_config, sample_user_info());
        let profile_id = profile.id.clone();
        let store = ProfileStore::from_env(state_dir.clone()).expect("profile store from env");
        store.add(profile).expect("store profile");

        let cfg = json!({
            "google": {
                "authProfile": profile_id
            }
        });

        let provider = resolve_google_oauth_provider_config(
            &cfg,
            Some("override-client-id".to_string()),
            Some("override-client-secret".to_string()),
            "http://127.0.0.1:3555/auth/callback".to_string(),
            &state_dir,
        )
        .expect("provider config");

        assert!(provider.client_id == "override-client-id");
        assert!(provider.client_secret == "override-client-secret");
        assert_eq!(provider.redirect_uri, "http://127.0.0.1:3555/auth/callback");
    }

    #[test]
    fn test_persist_cli_google_oauth_stores_profile_and_updates_config() {
        let mut env_guard = ScopedEnv::new();
        env_guard.set("CARAPACE_CONFIG_PASSWORD", "test-config-password");
        let temp = tempfile::tempdir().expect("tempdir");
        let mut config = json!({});
        let provider_config = OAuthProvider::Google
            .default_config(
                "google-client-id",
                "google-client-secret",
                "http://127.0.0.1:3000/auth/callback",
            )
            .unwrap();
        let completion = GeminiOAuthCompletion {
            client_id: "google-client-id".to_string(),
            auth_profile: build_gemini_auth_profile(
                sample_tokens(),
                &provider_config,
                sample_user_info(),
            ),
        };

        let profile_id =
            persist_cli_google_oauth(temp.path().to_path_buf(), &mut config, completion)
                .expect("persist cli oauth");

        assert_eq!(config["auth"]["profiles"]["enabled"], true);
        assert_eq!(
            config["auth"]["profiles"]["providers"]["google"]["clientId"],
            "google-client-id"
        );
        assert!(config["auth"]["profiles"]["providers"]["google"]
            .get("clientSecret")
            .is_none());
        assert_eq!(config["google"]["authProfile"], profile_id);
        assert!(config["google"].get("apiKey").is_none());

        let store =
            ProfileStore::from_env(temp.path().to_path_buf()).expect("profile store from env");
        store.load().expect("load stored profiles");
        let profile = store.get(&profile_id).expect("stored profile");
        assert_eq!(profile.provider, OAuthProvider::Google);
        assert_eq!(profile.email.as_deref(), Some("user@example.com"));
        let stored_cfg = profile
            .oauth_provider_config
            .expect("stored Google OAuth provider config");
        assert!(stored_cfg.client_id == "google-client-id");
        assert!(stored_cfg.client_secret == "google-client-secret");
    }

    #[test]
    fn test_start_control_google_oauth_requires_encrypted_profile_store() {
        let mut env_guard = ScopedEnv::new();
        env_guard.unset("CARAPACE_CONFIG_PASSWORD");
        let err = start_control_google_oauth(
            &json!({}),
            Some("google-client-id".to_string()),
            Some("google-client-secret".to_string()),
            "https://gateway.example.com",
        )
        .expect_err("missing config password should fail");

        assert!(err.contains("CARAPACE_CONFIG_PASSWORD"));
    }

    #[test]
    fn test_start_control_google_oauth_returns_control_callback() {
        let mut env_guard = ScopedEnv::new();
        env_guard.set("CARAPACE_CONFIG_PASSWORD", "test-config-password");
        let started = start_control_google_oauth(
            &json!({}),
            Some("google-client-id".to_string()),
            Some("google-client-secret".to_string()),
            "https://gateway.example.com",
        )
        .expect("start oauth");

        assert!(started.auth_url.contains("accounts.google.com"));
        assert_eq!(
            started.redirect_uri,
            "https://gateway.example.com/control/onboarding/gemini/callback"
        );
        assert!(!started.flow_id.is_empty());
    }

    #[tokio::test]
    async fn test_complete_control_google_oauth_callback_returns_provider_error_with_description() {
        let mut env_guard = ScopedEnv::new();
        env_guard.set("CARAPACE_CONFIG_PASSWORD", "test-config-password");
        let started = start_control_google_oauth(
            &json!({}),
            Some("google-client-id".to_string()),
            Some("google-client-secret".to_string()),
            "https://gateway.example.com",
        )
        .expect("start oauth");

        let state = {
            let flow = oauth::get_flow(&started.flow_id).expect("stored flow");
            flow.state.clone()
        };

        let err = complete_control_google_oauth_callback(
            &state,
            None,
            Some("access_denied"),
            Some("User denied access"),
        )
        .await
        .expect_err("provider error should fail");
        assert!(err.contains("access_denied"));
        assert!(err.contains("User denied access"));

        let status = control_google_oauth_status(&started.flow_id).expect("flow status");
        assert_eq!(status.status, "failed");
    }

    #[test]
    fn test_completed_gemini_oauth_flow_is_readable_after_insert() {
        let flow_id = insert_completed_control_google_oauth_flow_for_test();
        let flow = oauth::get_flow(&flow_id).expect("completed flow should exist");
        assert!(
            matches!(flow.flow_state, OAuthFlowState::Completed(_)),
            "flow should be in Completed state"
        );
        let status = control_google_oauth_status(&flow_id).expect("status");
        assert_eq!(status.status, "completed");
    }

    #[tokio::test]
    async fn test_complete_control_google_oauth_callback_rejects_in_progress_flow() {
        let mut env_guard = ScopedEnv::new();
        env_guard.set("CARAPACE_CONFIG_PASSWORD", "test-config-password");
        let started = start_control_google_oauth(
            &json!({}),
            Some("google-client-id".to_string()),
            Some("google-client-secret".to_string()),
            "https://gateway.example.com",
        )
        .expect("start oauth");

        let state = {
            let flow = oauth::get_flow(&started.flow_id).expect("stored flow");
            flow.state.clone()
        };

        // Mark the flow as InProgress.
        oauth::update_flow_state(&started.flow_id, OAuthFlowState::InProgress);

        let err = complete_control_google_oauth_callback(&state, Some("code"), None, None)
            .await
            .expect_err("in-progress flow should not start another exchange");
        assert!(err.contains("already being processed"));

        let status = control_google_oauth_status(&started.flow_id).expect("flow status");
        assert_eq!(status.status, "pending");
    }

    #[test]
    fn test_start_control_google_oauth_evicts_stale_in_progress_flow() {
        let mut env_guard = ScopedEnv::new();
        env_guard.set("CARAPACE_CONFIG_PASSWORD", "test-config-password");

        // Insert a flow with a creation time older than the TTL.
        let stale_flow_id = format!("gemini-stale-{}", uuid::Uuid::new_v4());
        let provider_config = OAuthProvider::Google
            .default_config(
                "client-id",
                "client-secret",
                "https://gateway.example.com/control/onboarding/gemini/callback",
            )
            .unwrap();
        let flow = PendingOAuthFlow {
            id: stale_flow_id.clone(),
            state: "gemini-stale-state".to_string(),
            code_verifier: "verifier".to_string(),
            provider_config,
            created_at_ms: oauth::now_ms() - (GEMINI_SPEC.flow_ttl_secs * 1000) - 1,
            flow_state: OAuthFlowState::InProgress,
            spec: &GEMINI_SPEC,
        };
        oauth::insert_oauth_flow(flow).expect("insert stale flow");

        let started = start_control_google_oauth(
            &json!({}),
            Some("google-client-id".to_string()),
            Some("google-client-secret".to_string()),
            "https://gateway.example.com",
        )
        .expect("stale in-progress flow should be evicted");

        assert_ne!(started.flow_id, stale_flow_id);
        assert!(oauth::get_flow(&stale_flow_id).is_none());
    }

    #[test]
    fn test_start_control_google_oauth_rejects_when_pending_flow_limit_reached() {
        let mut env_guard = ScopedEnv::new();
        env_guard.set("CARAPACE_CONFIG_PASSWORD", "test-config-password");

        // Fill up flow slots for the Gemini spec.
        let mut inserted_ids = Vec::new();
        for i in 0..GEMINI_SPEC.max_pending_flows {
            let id = format!("gemini-limit-flow-{i}-{}", uuid::Uuid::new_v4());
            let provider_config = OAuthProvider::Google
                .default_config(
                    "client-id",
                    "client-secret",
                    "https://gateway.example.com/control/onboarding/gemini/callback",
                )
                .unwrap();
            let flow = PendingOAuthFlow {
                id: id.clone(),
                state: format!("gemini-state-{i}"),
                code_verifier: "verifier".to_string(),
                provider_config,
                created_at_ms: oauth::now_ms(),
                flow_state: OAuthFlowState::Pending,
                spec: &GEMINI_SPEC,
            };
            oauth::insert_oauth_flow(flow).expect("insert flow");
            inserted_ids.push(id);
        }

        let err = start_control_google_oauth(
            &json!({}),
            Some("google-client-id".to_string()),
            Some("google-client-secret".to_string()),
            "https://gateway.example.com",
        )
        .expect_err("flow limit should reject new sign-in starts");
        assert!(err.contains("Too many active Gemini sign-in flows"));

        // Clean up the flows we inserted.
        for id in &inserted_ids {
            oauth::remove_flow_for_test(id);
        }
    }

    #[test]
    fn test_write_gemini_api_key_config_replaces_auth_profile() {
        let mut config = json!({
            "google": {
                "authProfile": "google-old"
            }
        });

        validate_gemini_api_key_input("AIza-test-key", Some("https://proxy.example.com"))
            .expect("api key validation");
        write_gemini_api_key_config(
            &mut config,
            "AIza-test-key",
            Some("https://proxy.example.com"),
        );

        assert_eq!(config["google"]["apiKey"], "AIza-test-key");
        assert_eq!(config["google"]["baseUrl"], "https://proxy.example.com");
        assert!(config["google"].get("authProfile").is_none());
    }

    #[test]
    fn test_write_gemini_api_key_config_clears_empty_base_url() {
        let mut config = json!({
            "google": {
                "baseUrl": "https://proxy.example.com"
            }
        });

        validate_gemini_api_key_input("AIza-test-key", None).expect("api key validation");
        write_gemini_api_key_config(&mut config, "AIza-test-key", None);

        assert!(config["google"].get("baseUrl").is_none());
    }

    #[test]
    fn test_validate_gemini_api_key_input_rejects_non_https_base_url() {
        let err = validate_gemini_api_key_input("AIza-test-key", Some("http://proxy.example.com"))
            .expect_err("non-https base URL should fail");
        assert!(err.to_string().contains("https scheme"));
    }

    #[test]
    fn test_validate_gemini_base_url_input_rejects_non_https_base_url() {
        let err = validate_gemini_base_url_input(Some("http://proxy.example.com"))
            .expect_err("non-https base URL should fail");
        assert!(err.to_string().contains("https scheme"));
    }

    #[test]
    fn test_callback_html_escapes_html() {
        let html = callback_html("<Gemini>", "\"bad\" & <script>");
        assert!(html.contains("&lt;Gemini&gt;"));
        assert!(html.contains("&quot;bad&quot; &amp; &lt;script&gt;"));
    }
}
