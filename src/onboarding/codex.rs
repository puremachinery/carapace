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
// Codex spec
// ---------------------------------------------------------------------------

pub(crate) static CODEX_SPEC: OAuthOnboardingSpec = OAuthOnboardingSpec {
    oauth_provider: OAuthProvider::OpenAI,
    display_name: "Codex",
    idp_display_name: "OpenAI",
    provider_label: "codex",
    client_id_env: "OPENAI_OAUTH_CLIENT_ID",
    client_secret_env: "OPENAI_OAUTH_CLIENT_SECRET",
    cli_loopback_error_extra: "",
    max_pending_flows: 20,
    flow_ttl_secs: 30 * 60,
    resolve_provider_config: resolve_openai_oauth_provider_config,
    build_auth_profile: build_codex_auth_profile,
    write_provider_config: write_codex_provider_config,
};

// ---------------------------------------------------------------------------
// Public types (stable API surface for control.rs and cli/mod.rs)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CodexOAuthStart {
    pub flow_id: String,
    pub auth_url: String,
    pub redirect_uri: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CodexOAuthStatus {
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
pub struct CodexOAuthCompletion {
    pub client_id: String,
    pub auth_profile: AuthProfile,
}

// ---------------------------------------------------------------------------
// Hook: resolve_provider_config
// ---------------------------------------------------------------------------

pub fn resolve_openai_oauth_provider_config(
    cfg: &Value,
    client_id_override: Option<String>,
    client_secret_override: Option<String>,
    redirect_uri: String,
    state_dir: &Path,
) -> Result<OAuthProviderConfig, String> {
    let stored_provider_config = load_stored_openai_provider_config(cfg, state_dir);

    let client_id = client_id_override
        .or_else(|| crate::config::read_config_env(CODEX_SPEC.client_id_env))
        .or_else(|| configured_openai_oauth_client_id(cfg))
        .or_else(|| {
            stored_provider_config
                .as_ref()
                .map(|cfg| cfg.client_id.clone())
        })
        .unwrap_or_default();
    let client_secret = client_secret_override
        .or_else(|| crate::config::read_config_env(CODEX_SPEC.client_secret_env))
        .or_else(|| {
            stored_provider_config
                .as_ref()
                .map(|cfg| cfg.client_secret.clone())
        })
        .unwrap_or_default();

    if client_id.trim().is_empty() || client_secret.trim().is_empty() {
        return Err("Codex sign-in requires OpenAI OAuth clientId and clientSecret.".to_string());
    }

    let mut provider_config = OAuthProvider::OpenAI
        .default_config(client_id.trim(), client_secret.trim(), &redirect_uri)
        .expect("OpenAI is an OAuth provider");
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

fn build_codex_auth_profile(
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
        .unwrap_or_else(|| "OpenAI account".to_string());

    AuthProfile {
        id: format!("openai-{short}"),
        name: format!("Codex ({display})"),
        provider: OAuthProvider::OpenAI,
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

fn write_codex_provider_config(cfg: &mut Value, profile_id: &str, client_id: &str) {
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
        .get("openai")
        .is_some_and(Value::is_object)
    {
        cfg["auth"]["profiles"]["providers"]["openai"] = json!({});
    }
    cfg["auth"]["profiles"]["providers"]["openai"]["clientId"] = json!(client_id);
    if let Some(openai_provider) = cfg["auth"]["profiles"]["providers"]
        .get_mut("openai")
        .and_then(Value::as_object_mut)
    {
        openai_provider.remove("clientSecret");
    }

    if !cfg.get("codex").is_some_and(Value::is_object) {
        cfg["codex"] = json!({});
    }
    if let Some(codex) = cfg.get_mut("codex").and_then(Value::as_object_mut) {
        codex.insert("authProfile".to_string(), json!(profile_id));
    }
}

// ---------------------------------------------------------------------------
// Public API: Control-facing delegates
// ---------------------------------------------------------------------------

pub fn start_control_openai_oauth(
    cfg: &Value,
    client_id_override: Option<String>,
    client_secret_override: Option<String>,
    redirect_base_url: &str,
) -> Result<CodexOAuthStart, String> {
    let result = oauth::start_oauth_flow(
        &CODEX_SPEC,
        cfg,
        client_id_override,
        client_secret_override,
        redirect_base_url,
    )?;
    Ok(CodexOAuthStart {
        flow_id: result.flow_id,
        auth_url: result.auth_url,
        redirect_uri: result.redirect_uri,
    })
}

pub async fn complete_control_openai_oauth_callback(
    state_param: &str,
    code: Option<&str>,
    error: Option<&str>,
    error_description: Option<&str>,
) -> Result<(), String> {
    oauth::complete_oauth_callback(&CODEX_SPEC, state_param, code, error, error_description).await
}

pub fn control_openai_oauth_status(flow_id: &str) -> Result<CodexOAuthStatus, String> {
    match oauth::oauth_flow_status(&CODEX_SPEC, flow_id) {
        OAuthStatusResult::InProgress => Ok(CodexOAuthStatus {
            flow_id: flow_id.to_string(),
            status: "pending",
            profile_name: None,
            email: None,
            error: None,
        }),
        OAuthStatusResult::Completed {
            profile_name,
            email,
        } => Ok(CodexOAuthStatus {
            flow_id: flow_id.to_string(),
            status: "completed",
            profile_name: Some(profile_name),
            email,
            error: None,
        }),
        OAuthStatusResult::Failed { error } => Ok(CodexOAuthStatus {
            flow_id: flow_id.to_string(),
            status: "failed",
            profile_name: None,
            email: None,
            error: Some(error),
        }),
        OAuthStatusResult::NotFound => Err("Unknown or expired Codex OAuth flow".to_string()),
    }
}

pub fn apply_control_openai_oauth(flow_id: &str, state_dir: PathBuf) -> Result<Value, String> {
    oauth::require_encrypted_profile_store(&CODEX_SPEC)?;
    let mut snapshot = read_config_snapshot();
    let result = oauth::apply_oauth_flow(&CODEX_SPEC, flow_id, &state_dir, &mut snapshot.config)?;

    Ok(json!({
        "authProfile": result.profile_id,
        "mode": "oauth",
        "provider": "codex",
        "model": crate::agent::codex::DEFAULT_CODEX_MODEL,
    }))
}

// ---------------------------------------------------------------------------
// Public API: CLI-facing delegates
// ---------------------------------------------------------------------------

pub async fn run_cli_openai_oauth(
    cfg: Value,
    client_id_override: Option<String>,
    client_secret_override: Option<String>,
) -> Result<CodexOAuthCompletion, String> {
    let completion = oauth::run_cli_oauth(
        &CODEX_SPEC,
        &cfg,
        client_id_override,
        client_secret_override,
    )
    .await?;
    Ok(CodexOAuthCompletion {
        client_id: completion.client_id,
        auth_profile: completion.auth_profile,
    })
}

pub fn persist_cli_openai_oauth(
    state_dir: PathBuf,
    config: &mut Value,
    completion: CodexOAuthCompletion,
) -> Result<String, String> {
    oauth::require_encrypted_profile_store(&CODEX_SPEC)?;
    let oauth_completion = OAuthCompletion {
        client_id: completion.client_id,
        auth_profile: completion.auth_profile,
    };
    oauth::persist_cli_oauth(&CODEX_SPEC, oauth_completion, &state_dir, config)
}

// ---------------------------------------------------------------------------
// Private helpers (OpenAI-specific config resolution)
// ---------------------------------------------------------------------------

fn configured_openai_oauth_client_id(cfg: &Value) -> Option<String> {
    cfg.pointer("/auth/profiles/providers/openai/clientId")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
}

fn load_stored_openai_provider_config(
    cfg: &Value,
    state_dir: &Path,
) -> Option<StoredOAuthProviderConfig> {
    let profile_id = cfg
        .get("codex")
        .and_then(|value| value.get("authProfile"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())?;
    let store = ProfileStore::from_env(state_dir.to_path_buf()).ok()?;
    store.load().ok()?;
    let profile = store.get(profile_id)?;
    if profile.provider != OAuthProvider::OpenAI {
        return None;
    }
    profile.oauth_provider_config
}

// ---------------------------------------------------------------------------
// Test helper (used by src/server/http.rs integration tests)
// ---------------------------------------------------------------------------

#[cfg(test)]
pub(crate) fn insert_completed_control_openai_oauth_flow_for_test() -> String {
    let flow_id = format!("codex-test-flow-{}", uuid::Uuid::new_v4());
    let provider_config = OAuthProvider::OpenAI
        .default_config(
            "openai-client-id",
            "openai-client-secret",
            "https://gateway.example.com/control/onboarding/codex/callback",
        )
        .unwrap();
    let tokens = OAuthTokens {
        access_token: "header.eyJzdWIiOiJ1c2VyLTEyMyJ9.sig".to_string(),
        refresh_token: Some("refresh-token".to_string()),
        token_type: "Bearer".to_string(),
        expires_at_ms: Some(oauth::now_ms() + 3_600_000),
        scope: Some("openid profile email offline_access".to_string()),
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
            client_id: "openai-client-id".to_string(),
            auth_profile: build_codex_auth_profile(tokens, &provider_config, userinfo),
        })),
        spec: &CODEX_SPEC,
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
            access_token: "header.eyJzdWIiOiJ1c2VyLTEyMyIsImh0dHBzOi8vYXBpLm9wZW5haS5jb20vcHJvZmlsZSI6eyJlbWFpbCI6InVzZXJAZXhhbXBsZS5jb20ifX0.sig".to_string(),
            refresh_token: Some("refresh-token".to_string()),
            token_type: "Bearer".to_string(),
            expires_at_ms: Some(oauth::now_ms() + 3_600_000),
            scope: Some("openid profile email offline_access".to_string()),
        }
    }

    fn sample_user_info() -> UserInfo {
        UserInfo {
            user_id: "user-123".to_string(),
            email: Some("user@example.com".to_string()),
            display_name: Some("user@example.com".to_string()),
            avatar_url: None,
        }
    }

    #[test]
    fn test_resolve_openai_oauth_provider_config_uses_configured_client_id_and_env_secret() {
        let mut env_guard = ScopedEnv::new();
        env_guard.set(CODEX_SPEC.client_secret_env, "env-client-secret");
        let cfg = json!({
            "auth": {
                "profiles": {
                    "enabled": true,
                    "providers": {
                        "openai": {
                            "clientId": "existing-client-id"
                        }
                    }
                }
            }
        });
        let temp = tempfile::tempdir().expect("tempdir");

        let provider = resolve_openai_oauth_provider_config(
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
    fn test_persist_cli_openai_oauth_stores_profile_and_updates_config() {
        let mut env_guard = ScopedEnv::new();
        env_guard.set("CARAPACE_CONFIG_PASSWORD", "test-config-password");
        let temp = tempfile::tempdir().expect("tempdir");
        let config_path = temp.path().join("carapace.json");
        env_guard.set("CARAPACE_CONFIG_PATH", config_path.as_os_str());
        let mut config = json!({});
        let provider_config = OAuthProvider::OpenAI
            .default_config(
                "openai-client-id",
                "openai-client-secret",
                "http://127.0.0.1:3000/auth/callback",
            )
            .unwrap();
        let completion = CodexOAuthCompletion {
            client_id: "openai-client-id".to_string(),
            auth_profile: build_codex_auth_profile(
                sample_tokens(),
                &provider_config,
                sample_user_info(),
            ),
        };

        let profile_id =
            persist_cli_openai_oauth(temp.path().to_path_buf(), &mut config, completion)
                .expect("persist cli oauth");

        assert_eq!(config["auth"]["profiles"]["enabled"], true);
        assert_eq!(
            config["auth"]["profiles"]["providers"]["openai"]["clientId"],
            "openai-client-id"
        );
        assert!(config["auth"]["profiles"]["providers"]["openai"]
            .get("clientSecret")
            .is_none());
        assert_eq!(config["codex"]["authProfile"], profile_id);

        let store =
            ProfileStore::from_env(temp.path().to_path_buf()).expect("profile store from env");
        store.load().expect("load stored profiles");
        let profile = store.get(&profile_id).expect("stored profile");
        assert_eq!(profile.provider, OAuthProvider::OpenAI);
        assert_eq!(profile.email.as_deref(), Some("user@example.com"));
    }

    #[test]
    fn test_start_control_openai_oauth_requires_encrypted_profile_store() {
        let mut env_guard = ScopedEnv::new();
        env_guard.unset("CARAPACE_CONFIG_PASSWORD");
        let err = start_control_openai_oauth(
            &json!({}),
            Some("openai-client-id".to_string()),
            Some("openai-client-secret".to_string()),
            "https://gateway.example.com",
        )
        .expect_err("missing config password should fail");

        assert!(err.contains("CARAPACE_CONFIG_PASSWORD"));
    }

    #[test]
    fn test_start_control_openai_oauth_returns_control_callback() {
        let mut env_guard = ScopedEnv::new();
        env_guard.set("CARAPACE_CONFIG_PASSWORD", "test-config-password");
        let started = start_control_openai_oauth(
            &json!({}),
            Some("openai-client-id".to_string()),
            Some("openai-client-secret".to_string()),
            "https://gateway.example.com",
        )
        .expect("start oauth");

        assert!(started.auth_url.contains("auth.openai.com/oauth/authorize"));
        assert_eq!(
            started.redirect_uri,
            "https://gateway.example.com/control/onboarding/codex/callback"
        );
        assert!(!started.flow_id.is_empty());
    }

    #[tokio::test]
    async fn test_complete_control_openai_oauth_callback_returns_provider_error_with_description() {
        let mut env_guard = ScopedEnv::new();
        env_guard.set("CARAPACE_CONFIG_PASSWORD", "test-config-password");
        let started = start_control_openai_oauth(
            &json!({}),
            Some("openai-client-id".to_string()),
            Some("openai-client-secret".to_string()),
            "https://gateway.example.com",
        )
        .expect("start oauth");

        let state = {
            let flow = oauth::get_flow(&started.flow_id).expect("stored flow");
            flow.state.clone()
        };

        let err = complete_control_openai_oauth_callback(
            &state,
            None,
            Some("access_denied"),
            Some("User denied access"),
        )
        .await
        .expect_err("provider error should fail");
        assert!(err.contains("access_denied"));
        assert!(err.contains("User denied access"));

        let status = control_openai_oauth_status(&started.flow_id).expect("flow status");
        assert_eq!(status.status, "failed");
    }

    #[test]
    fn test_completed_codex_oauth_flow_is_readable_after_insert() {
        let flow_id = insert_completed_control_openai_oauth_flow_for_test();
        let flow = oauth::get_flow(&flow_id).expect("completed flow should exist");
        assert!(
            matches!(flow.flow_state, OAuthFlowState::Completed(_)),
            "flow should be in Completed state"
        );
        let status = control_openai_oauth_status(&flow_id).expect("status");
        assert_eq!(status.status, "completed");
        oauth::remove_flow_for_test(&flow_id);
    }

    #[tokio::test]
    async fn test_complete_control_openai_oauth_callback_rejects_in_progress_flow() {
        let mut env_guard = ScopedEnv::new();
        env_guard.set("CARAPACE_CONFIG_PASSWORD", "test-config-password");
        let started = start_control_openai_oauth(
            &json!({}),
            Some("openai-client-id".to_string()),
            Some("openai-client-secret".to_string()),
            "https://gateway.example.com",
        )
        .expect("start oauth");

        let state = {
            let flow = oauth::get_flow(&started.flow_id).expect("stored flow");
            flow.state.clone()
        };

        // Mark the flow as InProgress.
        oauth::update_flow_state(&started.flow_id, OAuthFlowState::InProgress);

        let err = complete_control_openai_oauth_callback(&state, Some("code"), None, None)
            .await
            .expect_err("in-progress flow should not start another exchange");
        assert!(err.contains("already being processed"));

        let status = control_openai_oauth_status(&started.flow_id).expect("flow status");
        assert_eq!(status.status, "pending");
    }

    #[test]
    fn test_start_control_openai_oauth_evicts_stale_in_progress_flow() {
        let mut env_guard = ScopedEnv::new();
        env_guard.set("CARAPACE_CONFIG_PASSWORD", "test-config-password");

        // Insert a flow with a creation time older than the TTL.
        let stale_flow_id = format!("codex-stale-{}", uuid::Uuid::new_v4());
        let provider_config = OAuthProvider::OpenAI
            .default_config(
                "client-id",
                "client-secret",
                "https://gateway.example.com/control/onboarding/codex/callback",
            )
            .unwrap();
        let flow = PendingOAuthFlow {
            id: stale_flow_id.clone(),
            state: "codex-stale-state".to_string(),
            code_verifier: "verifier".to_string(),
            provider_config,
            created_at_ms: oauth::now_ms() - (CODEX_SPEC.flow_ttl_secs * 1000) - 1,
            flow_state: OAuthFlowState::InProgress,
            spec: &CODEX_SPEC,
        };
        oauth::insert_oauth_flow(flow).expect("insert stale flow");

        let started = start_control_openai_oauth(
            &json!({}),
            Some("openai-client-id".to_string()),
            Some("openai-client-secret".to_string()),
            "https://gateway.example.com",
        )
        .expect("stale in-progress flow should be evicted");

        assert_ne!(started.flow_id, stale_flow_id);
        assert!(oauth::get_flow(&stale_flow_id).is_none());
    }

    #[test]
    fn test_start_control_openai_oauth_rejects_when_pending_flow_limit_reached() {
        let mut env_guard = ScopedEnv::new();
        env_guard.set("CARAPACE_CONFIG_PASSWORD", "test-config-password");

        // Fill up flow slots for the Codex spec.
        let mut inserted_ids = Vec::new();
        for i in 0..CODEX_SPEC.max_pending_flows {
            let id = format!("codex-limit-flow-{i}-{}", uuid::Uuid::new_v4());
            let provider_config = OAuthProvider::OpenAI
                .default_config(
                    "client-id",
                    "client-secret",
                    "https://gateway.example.com/control/onboarding/codex/callback",
                )
                .unwrap();
            let flow = PendingOAuthFlow {
                id: id.clone(),
                state: format!("codex-state-{i}"),
                code_verifier: "verifier".to_string(),
                provider_config,
                created_at_ms: oauth::now_ms(),
                flow_state: OAuthFlowState::Pending,
                spec: &CODEX_SPEC,
            };
            oauth::insert_oauth_flow(flow).expect("insert flow");
            inserted_ids.push(id);
        }

        let err = start_control_openai_oauth(
            &json!({}),
            Some("openai-client-id".to_string()),
            Some("openai-client-secret".to_string()),
            "https://gateway.example.com",
        )
        .expect_err("flow limit should reject new sign-in starts");
        assert!(err.contains("Too many active Codex sign-in flows"));

        // Clean up the flows we inserted.
        for id in &inserted_ids {
            oauth::remove_flow_for_test(id);
        }
    }

    #[test]
    fn test_callback_html_escapes_html() {
        let html = oauth::callback_html("<Codex>", "\"bad\" & <script>");
        assert!(html.contains("&lt;Codex&gt;"));
        assert!(html.contains("&quot;bad&quot; &amp; &lt;script&gt;"));
    }
}
