use parking_lot::RwLock;
use serde::Serialize;
use serde_json::{json, Value};
use sha2::Digest;
use std::collections::HashMap;
use std::path::Path;
use std::path::PathBuf;
use std::sync::LazyLock;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::auth::profiles::{
    build_auth_profiles_config, exchange_code, fetch_user_info, generate_auth_url, AuthProfile,
    OAuthProvider, OAuthProviderConfig, OAuthTokens, ProfileStore,
};
use crate::server::ws::{map_validation_issues, persist_config_file, read_config_snapshot};

const FLOW_TTL: Duration = Duration::from_secs(30 * 60);

static GEMINI_OAUTH_FLOWS: LazyLock<RwLock<HashMap<String, PendingGeminiOAuthFlow>>> =
    LazyLock::new(|| RwLock::new(HashMap::new()));

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

#[derive(Debug, Clone)]
enum GeminiOAuthFlowState {
    Pending,
    Completed(Box<GeminiOAuthCompletion>),
    Failed(String),
}

#[derive(Debug, Clone)]
struct PendingGeminiOAuthFlow {
    id: String,
    state: String,
    code_verifier: String,
    provider_config: OAuthProviderConfig,
    created_at_ms: u64,
    flow_state: GeminiOAuthFlowState,
}

#[derive(Debug, Clone)]
pub struct GeminiOAuthCompletion {
    pub client_id: String,
    pub client_secret: String,
    pub auth_profile: AuthProfile,
}

#[derive(Debug, Clone)]
pub struct GeminiApiKeyInput {
    pub api_key: String,
    pub base_url: Option<String>,
}

type CliOAuthSender = std::sync::Arc<
    std::sync::Mutex<Option<tokio::sync::oneshot::Sender<Result<GeminiOAuthCompletion, String>>>>,
>;

pub fn resolve_google_oauth_provider_config(
    cfg: &Value,
    client_id_override: Option<String>,
    client_secret_override: Option<String>,
    redirect_uri: String,
) -> Result<OAuthProviderConfig, String> {
    let auth_profiles_cfg = build_auth_profiles_config(cfg);
    let existing = auth_profiles_cfg.providers.get(&OAuthProvider::Google);

    let client_id = client_id_override
        .or_else(|| existing.map(|cfg| cfg.client_id.clone()))
        .unwrap_or_default();
    let client_secret = client_secret_override
        .or_else(|| existing.map(|cfg| cfg.client_secret.clone()))
        .unwrap_or_default();

    if client_id.trim().is_empty() || client_secret.trim().is_empty() {
        return Err(
            "Gemini Google sign-in requires Google OAuth clientId and clientSecret.".to_string(),
        );
    }

    let mut provider_cfg =
        OAuthProvider::Google.default_config(client_id.trim(), client_secret.trim(), &redirect_uri);
    if let Some(existing) = existing {
        provider_cfg.scopes = existing.scopes.clone();
        provider_cfg.auth_url = existing.auth_url.clone();
        provider_cfg.token_url = existing.token_url.clone();
        provider_cfg.userinfo_url = existing.userinfo_url.clone();
    }
    Ok(provider_cfg)
}

pub fn start_control_google_oauth(
    cfg: &Value,
    client_id_override: Option<String>,
    client_secret_override: Option<String>,
    redirect_base_url: &str,
) -> Result<GeminiOAuthStart, String> {
    cleanup_expired_flows();

    let redirect_uri = format!(
        "{}/control/onboarding/gemini/callback",
        redirect_base_url.trim_end_matches('/')
    );
    let provider_config = resolve_google_oauth_provider_config(
        cfg,
        client_id_override,
        client_secret_override,
        redirect_uri.clone(),
    )?;

    let state = format!("gemini-{}", uuid::Uuid::new_v4());
    let flow_id = uuid::Uuid::new_v4().to_string();
    let (auth_url, code_verifier) =
        generate_auth_url(&provider_config, &state).map_err(|err| err.to_string())?;

    let flow = PendingGeminiOAuthFlow {
        id: flow_id.clone(),
        state,
        code_verifier,
        provider_config,
        created_at_ms: now_ms(),
        flow_state: GeminiOAuthFlowState::Pending,
    };
    GEMINI_OAUTH_FLOWS.write().insert(flow_id.clone(), flow);

    Ok(GeminiOAuthStart {
        flow_id,
        auth_url,
        redirect_uri,
    })
}

pub async fn complete_control_google_oauth_callback(
    state_param: &str,
    code: Option<&str>,
    error: Option<&str>,
) -> Result<(), String> {
    let flow_id = {
        let flows = GEMINI_OAUTH_FLOWS.read();
        flows
            .values()
            .find(|flow| flow.state == state_param)
            .map(|flow| flow.id.clone())
            .ok_or_else(|| "Unknown or expired Gemini OAuth flow".to_string())?
    };

    if let Some(err) = error.filter(|value| !value.trim().is_empty()) {
        let mut flows = GEMINI_OAUTH_FLOWS.write();
        if let Some(flow) = flows.get_mut(&flow_id) {
            flow.flow_state = GeminiOAuthFlowState::Failed(format!("OAuth provider error: {err}"));
        }
        return Ok(());
    }

    let code = code
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "Missing OAuth authorization code".to_string())?;

    let (provider_config, verifier) = {
        let flows = GEMINI_OAUTH_FLOWS.read();
        let flow = flows
            .get(&flow_id)
            .ok_or_else(|| "Unknown or expired Gemini OAuth flow".to_string())?;
        (flow.provider_config.clone(), flow.code_verifier.clone())
    };

    let result = async {
        let tokens = exchange_code(&provider_config, code, &verifier)
            .await
            .map_err(|err| err.to_string())?;
        let userinfo = fetch_user_info(
            OAuthProvider::Google,
            &provider_config,
            &tokens.access_token,
        )
        .await
        .map_err(|err| err.to_string())?;
        Ok::<GeminiOAuthCompletion, String>(GeminiOAuthCompletion {
            client_id: provider_config.client_id.clone(),
            client_secret: provider_config.client_secret.clone(),
            auth_profile: build_google_auth_profile(tokens, userinfo),
        })
    }
    .await;

    let mut flows = GEMINI_OAUTH_FLOWS.write();
    if let Some(flow) = flows.get_mut(&flow_id) {
        flow.flow_state = match result {
            Ok(completion) => GeminiOAuthFlowState::Completed(Box::new(completion)),
            Err(err) => GeminiOAuthFlowState::Failed(err),
        };
    }

    Ok(())
}

pub fn control_google_oauth_status(flow_id: &str) -> Result<GeminiOAuthStatus, String> {
    cleanup_expired_flows();
    let flows = GEMINI_OAUTH_FLOWS.read();
    let flow = flows
        .get(flow_id)
        .ok_or_else(|| "Unknown or expired Gemini OAuth flow".to_string())?;
    Ok(match &flow.flow_state {
        GeminiOAuthFlowState::Pending => GeminiOAuthStatus {
            flow_id: flow.id.clone(),
            status: "pending",
            profile_name: None,
            email: None,
            error: None,
        },
        GeminiOAuthFlowState::Completed(completion) => GeminiOAuthStatus {
            flow_id: flow.id.clone(),
            status: "completed",
            profile_name: Some(completion.auth_profile.name.clone()),
            email: completion.auth_profile.email.clone(),
            error: None,
        },
        GeminiOAuthFlowState::Failed(err) => GeminiOAuthStatus {
            flow_id: flow.id.clone(),
            status: "failed",
            profile_name: None,
            email: None,
            error: Some(err.clone()),
        },
    })
}

pub fn apply_control_google_oauth(flow_id: &str, state_dir: PathBuf) -> Result<Value, String> {
    let completion = {
        let flows = GEMINI_OAUTH_FLOWS.read();
        let flow = flows
            .get(flow_id)
            .ok_or_else(|| "Unknown or expired Gemini OAuth flow".to_string())?;
        match &flow.flow_state {
            GeminiOAuthFlowState::Completed(completion) => completion.as_ref().clone(),
            GeminiOAuthFlowState::Pending => {
                return Err("Gemini Google sign-in is still pending".to_string())
            }
            GeminiOAuthFlowState::Failed(err) => return Err(err.clone()),
        }
    };

    let profile_id = upsert_google_profile(&state_dir, completion.auth_profile)?;

    let snapshot = read_config_snapshot();
    let mut config = snapshot.config.clone();
    ensure_google_oauth_config(
        &mut config,
        &completion.client_id,
        &completion.client_secret,
        &profile_id,
    );
    validate_and_persist_config(&config)?;
    GEMINI_OAUTH_FLOWS.write().remove(flow_id);

    Ok(json!({
        "profileId": profile_id,
        "mode": "oauth",
    }))
}

pub fn apply_control_gemini_api_key(input: GeminiApiKeyInput) -> Result<Value, String> {
    let mut config = read_config_snapshot().config;
    apply_gemini_api_key_config(&mut config, &input.api_key, input.base_url.as_deref())?;
    validate_and_persist_config(&config)?;
    Ok(json!({
        "mode": "apiKey"
    }))
}

pub async fn run_cli_google_oauth(
    cfg: Value,
    client_id_override: Option<String>,
    client_secret_override: Option<String>,
) -> Result<GeminiOAuthCompletion, String> {
    let redirect_uri = "http://127.0.0.1:3000/auth/callback".to_string();
    let provider_config = resolve_google_oauth_provider_config(
        &cfg,
        client_id_override,
        client_secret_override,
        redirect_uri.clone(),
    )?;

    let parsed_redirect = url::Url::parse(&provider_config.redirect_uri)
        .map_err(|err| format!("invalid Gemini OAuth redirect URI: {err}"))?;
    let host = parsed_redirect.host_str().unwrap_or_default();
    if host != "127.0.0.1" && host != "localhost" {
        return Err(
            "CLI Google sign-in requires a loopback redirect URI; use Control UI sign-in or Gemini API key mode."
                .to_string(),
        );
    }

    let path = parsed_redirect.path().to_string();
    let bind_addr = format!(
        "{}:{}",
        if host == "localhost" {
            "127.0.0.1"
        } else {
            host
        },
        parsed_redirect
            .port_or_known_default()
            .ok_or_else(|| "redirect URI must include a port".to_string())?
    );

    let state = format!("gemini-cli-{}", uuid::Uuid::new_v4());
    let (auth_url, verifier) =
        generate_auth_url(&provider_config, &state).map_err(|err| err.to_string())?;

    let listener = tokio::net::TcpListener::bind(&bind_addr)
        .await
        .map_err(|err| {
            format!("failed to bind local OAuth callback listener on {bind_addr}: {err}")
        })?;

    println!();
    println!("Open this URL to sign in with Google for Gemini:");
    println!("{auth_url}");
    println!();
    println!("Waiting for OAuth callback on {}{} ...", bind_addr, path);

    let provider_config_for_server = provider_config.clone();
    let state_for_server = state.clone();
    let verifier_for_server = verifier.clone();
    let path_for_server = path.clone();
    let (result_tx, result_rx) = tokio::sync::oneshot::channel();
    let result_tx = std::sync::Arc::new(std::sync::Mutex::new(Some(result_tx)));
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    tokio::spawn(async move {
        use axum::extract::{Query, State};
        use axum::response::Html;
        use axum::routing::get;
        use axum::Router;

        #[derive(Clone)]
        struct CliOAuthState {
            expected_state: String,
            code_verifier: String,
            provider_config: OAuthProviderConfig,
            sender: CliOAuthSender,
            shutdown_tx: tokio::sync::watch::Sender<bool>,
        }

        #[derive(serde::Deserialize)]
        struct CallbackQuery {
            code: Option<String>,
            state: Option<String>,
            error: Option<String>,
        }

        async fn callback_handler(
            State(state): State<CliOAuthState>,
            Query(query): Query<CallbackQuery>,
        ) -> Html<String> {
            let result = match query.error.filter(|value| !value.trim().is_empty()) {
                Some(err) => Err(format!("OAuth provider error: {err}")),
                None => {
                    let returned_state = query.state.unwrap_or_default();
                    let code = query.code.unwrap_or_default();
                    if returned_state != state.expected_state {
                        Err("OAuth callback state mismatch".to_string())
                    } else if code.trim().is_empty() {
                        Err("OAuth callback missing authorization code".to_string())
                    } else {
                        let tokens = match exchange_code(
                            &state.provider_config,
                            code.trim(),
                            &state.code_verifier,
                        )
                        .await
                        {
                            Ok(tokens) => tokens,
                            Err(err) => {
                                return Html(callback_html(
                                    "Gemini sign-in failed",
                                    &err.to_string(),
                                ))
                            }
                        };
                        let userinfo = match fetch_user_info(
                            OAuthProvider::Google,
                            &state.provider_config,
                            &tokens.access_token,
                        )
                        .await
                        {
                            Ok(userinfo) => userinfo,
                            Err(err) => {
                                return Html(callback_html(
                                    "Gemini sign-in failed",
                                    &err.to_string(),
                                ))
                            }
                        };
                        Ok(GeminiOAuthCompletion {
                            client_id: state.provider_config.client_id.clone(),
                            client_secret: state.provider_config.client_secret.clone(),
                            auth_profile: build_google_auth_profile(tokens, userinfo),
                        })
                    }
                }
            };

            if let Some(sender) = state
                .sender
                .lock()
                .expect("CLI OAuth sender mutex poisoned")
                .take()
            {
                let _ = sender.send(result.clone());
            }
            let _ = state.shutdown_tx.send(true);

            match result {
                Ok(_) => Html(callback_html(
                    "Gemini sign-in complete",
                    "You can return to Carapace and finish setup.",
                )),
                Err(err) => Html(callback_html("Gemini sign-in failed", &err)),
            }
        }

        let app = Router::new()
            .route(&path_for_server, get(callback_handler))
            .with_state(CliOAuthState {
                expected_state: state_for_server,
                code_verifier: verifier_for_server,
                provider_config: provider_config_for_server,
                sender: result_tx.clone(),
                shutdown_tx: shutdown_tx.clone(),
            });

        let server = axum::serve(listener, app).with_graceful_shutdown(async move {
            let mut shutdown_rx = shutdown_rx;
            let _ = shutdown_rx.changed().await;
        });

        if let Err(err) = server.await {
            if let Some(sender) = result_tx
                .lock()
                .expect("CLI OAuth sender mutex poisoned")
                .take()
            {
                let _ = sender.send(Err(format!("OAuth callback server error: {err}")));
            }
        }
    });

    match tokio::time::timeout(Duration::from_secs(300), result_rx).await {
        Ok(Ok(Ok(completion))) => Ok(completion),
        Ok(Ok(Err(err))) => Err(err),
        Ok(Err(_)) => Err("Gemini OAuth callback channel closed unexpectedly".to_string()),
        Err(_) => Err("Timed out waiting for Gemini Google sign-in callback".to_string()),
    }
}

pub fn persist_cli_google_oauth(
    state_dir: PathBuf,
    config: &mut Value,
    completion: GeminiOAuthCompletion,
) -> Result<String, String> {
    let profile_id = upsert_google_profile(&state_dir, completion.auth_profile)?;
    ensure_google_oauth_config(
        config,
        &completion.client_id,
        &completion.client_secret,
        &profile_id,
    );
    Ok(profile_id)
}

fn build_google_auth_profile(
    tokens: OAuthTokens,
    userinfo: crate::auth::profiles::UserInfo,
) -> AuthProfile {
    let now_ms = now_ms();
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
        tokens,
    }
}

fn upsert_google_profile(state_dir: &Path, profile: AuthProfile) -> Result<String, String> {
    let store = ProfileStore::from_env(state_dir.to_path_buf()).map_err(|err| err.to_string())?;
    store.load().map_err(|err| err.to_string())?;

    let existing = store.find_matching(
        OAuthProvider::Google,
        profile.user_id.as_deref(),
        profile.email.as_deref(),
    );
    let profile = if let Some(existing) = existing {
        AuthProfile {
            id: existing.id,
            created_at_ms: existing.created_at_ms,
            ..profile
        }
    } else {
        profile
    };
    let id = profile.id.clone();
    store.upsert(profile).map_err(|err| err.to_string())?;
    Ok(id)
}

fn ensure_google_oauth_config(
    config: &mut Value,
    client_id: &str,
    client_secret: &str,
    profile_id: &str,
) {
    if !config.get("auth").is_some_and(Value::is_object) {
        config["auth"] = json!({});
    }
    if !config["auth"].get("profiles").is_some_and(Value::is_object) {
        config["auth"]["profiles"] = json!({});
    }
    config["auth"]["profiles"]["enabled"] = json!(true);
    if !config["auth"]["profiles"]
        .get("providers")
        .is_some_and(Value::is_object)
    {
        config["auth"]["profiles"]["providers"] = json!({});
    }
    config["auth"]["profiles"]["providers"]["google"] = json!({
        "clientId": client_id,
        "clientSecret": client_secret
    });

    if !config.get("google").is_some_and(Value::is_object) {
        config["google"] = json!({});
    }
    if let Some(google) = config.get_mut("google").and_then(Value::as_object_mut) {
        google.remove("apiKey");
        google.insert("authProfile".to_string(), json!(profile_id));
    }
}

fn apply_gemini_api_key_config(
    config: &mut Value,
    api_key: &str,
    base_url: Option<&str>,
) -> Result<(), String> {
    let provider = crate::agent::gemini::GeminiProvider::new(api_key.to_string())
        .map_err(|err| err.to_string())?;
    if let Some(url) = base_url.filter(|value| !value.trim().is_empty()) {
        provider
            .with_base_url(url.trim().to_string())
            .map_err(|err| err.to_string())?;
    }

    if !config.get("google").is_some_and(Value::is_object) {
        config["google"] = json!({});
    }
    config["google"]["apiKey"] = json!(api_key);
    if let Some(url) = base_url.filter(|value| !value.trim().is_empty()) {
        config["google"]["baseUrl"] = json!(url.trim());
    }
    if let Some(google) = config.get_mut("google").and_then(Value::as_object_mut) {
        google.remove("authProfile");
    }
    Ok(())
}

fn validate_and_persist_config(config: &Value) -> Result<(), String> {
    let issues = map_validation_issues(crate::config::validate_config(config));
    if !issues.is_empty() {
        let summary = issues
            .into_iter()
            .map(|issue| format!("{}: {}", issue.path, issue.message))
            .collect::<Vec<_>>()
            .join("; ");
        return Err(format!("Invalid configuration: {summary}"));
    }
    let config_path = crate::config::get_config_path();
    persist_config_file(&config_path, config).map_err(|err| err.to_string())
}

fn cleanup_expired_flows() {
    let cutoff = now_ms().saturating_sub(FLOW_TTL.as_millis() as u64);
    GEMINI_OAUTH_FLOWS
        .write()
        .retain(|_, flow| flow.created_at_ms >= cutoff);
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

fn callback_html(title: &str, body: &str) -> String {
    format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>{}</title></head><body><h1>{}</h1><p>{}</p></body></html>",
        title, title, body
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::profiles::OAuthTokens;
    use crate::auth::profiles::UserInfo;
    use serde_json::json;

    fn sample_tokens() -> OAuthTokens {
        OAuthTokens {
            access_token: "google-access-token".to_string(),
            refresh_token: Some("google-refresh-token".to_string()),
            token_type: "Bearer".to_string(),
            expires_at_ms: Some(now_ms() + 3_600_000),
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
    fn test_resolve_google_oauth_provider_config_uses_existing_config() {
        let cfg = json!({
            "auth": {
                "profiles": {
                    "enabled": true,
                    "providers": {
                        "google": {
                            "clientId": "existing-client-id",
                            "clientSecret": "existing-client-secret"
                        }
                    }
                }
            }
        });

        let provider = resolve_google_oauth_provider_config(
            &cfg,
            None,
            None,
            "http://127.0.0.1:3000/auth/callback".to_string(),
        )
        .expect("provider config");

        assert_eq!(provider.client_id, "existing-client-id");
        assert_eq!(provider.client_secret, "existing-client-secret");
    }

    #[test]
    fn test_apply_gemini_api_key_config_replaces_auth_profile() {
        let mut config = json!({
            "google": {
                "authProfile": "google-old"
            }
        });

        apply_gemini_api_key_config(
            &mut config,
            "AIza-test-key",
            Some("https://proxy.example.com"),
        )
        .expect("api key config");

        assert_eq!(config["google"]["apiKey"], "AIza-test-key");
        assert_eq!(config["google"]["baseUrl"], "https://proxy.example.com");
        assert!(config["google"].get("authProfile").is_none());
    }

    #[test]
    fn test_persist_cli_google_oauth_stores_profile_and_updates_config() {
        let temp = tempfile::tempdir().expect("tempdir");
        let mut config = json!({});
        let completion = GeminiOAuthCompletion {
            client_id: "google-client-id".to_string(),
            client_secret: "google-client-secret".to_string(),
            auth_profile: build_google_auth_profile(sample_tokens(), sample_user_info()),
        };

        let profile_id =
            persist_cli_google_oauth(temp.path().to_path_buf(), &mut config, completion)
                .expect("persist cli oauth");

        assert_eq!(config["auth"]["profiles"]["enabled"], true);
        assert_eq!(
            config["auth"]["profiles"]["providers"]["google"]["clientId"],
            "google-client-id"
        );
        assert_eq!(
            config["auth"]["profiles"]["providers"]["google"]["clientSecret"],
            "google-client-secret"
        );
        assert_eq!(config["google"]["authProfile"], profile_id);
        assert!(config["google"].get("apiKey").is_none());

        let store =
            ProfileStore::from_env(temp.path().to_path_buf()).expect("profile store from env");
        store.load().expect("load stored profiles");
        let profile = store.get(&profile_id).expect("stored profile");
        assert_eq!(profile.provider, OAuthProvider::Google);
        assert_eq!(profile.email.as_deref(), Some("user@example.com"));
    }

    #[test]
    fn test_start_control_google_oauth_returns_control_callback() {
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
}
