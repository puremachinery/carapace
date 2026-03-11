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
    exchange_code, fetch_user_info, generate_auth_url, profile_store_encryption_enabled_from_env,
    AuthProfile, OAuthProvider, OAuthProviderConfig, OAuthTokens, ProfileStore,
    StoredOAuthProviderConfig,
};
use crate::server::ws::{map_validation_issues, persist_config_file, read_config_snapshot};

const FLOW_TTL: Duration = Duration::from_secs(30 * 60);

static GEMINI_OAUTH_FLOWS: LazyLock<RwLock<HashMap<String, PendingGeminiOAuthFlow>>> =
    LazyLock::new(|| RwLock::new(HashMap::new()));
// Pending Gemini OAuth state is intentionally process-local for the current
// single-gateway deployment model. Callback completion is not shared across
// restarts or multiple replicas.

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
    state_dir: &Path,
) -> Result<OAuthProviderConfig, String> {
    let stored_provider_config = load_stored_google_provider_config(cfg, state_dir);

    let client_id = client_id_override
        .or_else(|| std::env::var("GOOGLE_OAUTH_CLIENT_ID").ok())
        .or_else(|| configured_google_oauth_client_id(cfg))
        .or_else(|| {
            stored_provider_config
                .as_ref()
                .map(|cfg| cfg.client_id.clone())
        })
        .unwrap_or_default();
    let client_secret = client_secret_override
        .or_else(|| std::env::var("GOOGLE_OAUTH_CLIENT_SECRET").ok())
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

    let mut provider_config =
        OAuthProvider::Google.default_config(client_id.trim(), client_secret.trim(), &redirect_uri);
    if let Some(stored) = stored_provider_config {
        provider_config.auth_url = stored.auth_url;
        provider_config.token_url = stored.token_url;
        provider_config.userinfo_url = stored.userinfo_url;
        provider_config.scopes = stored.scopes;
    }
    Ok(provider_config)
}

pub fn start_control_google_oauth(
    cfg: &Value,
    client_id_override: Option<String>,
    client_secret_override: Option<String>,
    redirect_base_url: &str,
) -> Result<GeminiOAuthStart, String> {
    require_encrypted_profile_store_for_google_oauth()?;
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
        &crate::paths::resolve_state_dir(),
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
        return Err(format!("OAuth provider error: {err}"));
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
            auth_profile: build_google_auth_profile(&provider_config, tokens, userinfo),
        })
    }
    .await;

    finish_control_google_oauth_flow(&flow_id, result)
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
    require_encrypted_profile_store_for_google_oauth()?;
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
    ensure_google_oauth_config(&mut config, &completion.client_id, &profile_id);
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
    require_encrypted_profile_store_for_google_oauth()?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|err| format!("failed to bind local OAuth callback listener: {err}"))?;
    let bind_addr = listener
        .local_addr()
        .map_err(|err| format!("failed to determine local OAuth callback port: {err}"))?;
    let redirect_uri = format!("http://127.0.0.1:{}/auth/callback", bind_addr.port());
    let provider_config = resolve_google_oauth_provider_config(
        &cfg,
        client_id_override,
        client_secret_override,
        redirect_uri.clone(),
        &crate::paths::resolve_state_dir(),
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
    let state = format!("gemini-cli-{}", uuid::Uuid::new_v4());
    let (auth_url, verifier) =
        generate_auth_url(&provider_config, &state).map_err(|err| err.to_string())?;

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
                    complete_cli_oauth_callback(
                        &state.provider_config,
                        &state.expected_state,
                        &state.code_verifier,
                        query.state.as_deref(),
                        query.code.as_deref(),
                    )
                    .await
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
    require_encrypted_profile_store_for_google_oauth()?;
    let profile_id = upsert_google_profile(&state_dir, completion.auth_profile)?;
    ensure_google_oauth_config(config, &completion.client_id, &profile_id);
    Ok(profile_id)
}

fn build_google_auth_profile(
    provider_config: &OAuthProviderConfig,
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
        oauth_provider_config: Some(StoredOAuthProviderConfig::from(provider_config)),
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

fn ensure_google_oauth_config(config: &mut Value, client_id: &str, profile_id: &str) {
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
    if !config["auth"]["profiles"]["providers"]
        .get("google")
        .is_some_and(Value::is_object)
    {
        config["auth"]["profiles"]["providers"]["google"] = json!({});
    }
    config["auth"]["profiles"]["providers"]["google"]["clientId"] = json!(client_id);
    if let Some(google_provider) = config["auth"]["profiles"]["providers"]
        .get_mut("google")
        .and_then(Value::as_object_mut)
    {
        google_provider.remove("clientSecret");
    }

    if !config.get("google").is_some_and(Value::is_object) {
        config["google"] = json!({});
    }
    if let Some(google) = config.get_mut("google").and_then(Value::as_object_mut) {
        google.remove("apiKey");
        google.insert("authProfile".to_string(), json!(profile_id));
    }
}

fn finish_control_google_oauth_flow(
    flow_id: &str,
    result: Result<GeminiOAuthCompletion, String>,
) -> Result<(), String> {
    let mut flows = GEMINI_OAUTH_FLOWS.write();
    if let Some(flow) = flows.get_mut(flow_id) {
        flow.flow_state = match &result {
            Ok(completion) => GeminiOAuthFlowState::Completed(Box::new(completion.clone())),
            Err(err) => GeminiOAuthFlowState::Failed(err.clone()),
        };
    }
    result.map(|_| ())
}

fn require_encrypted_profile_store_for_google_oauth() -> Result<(), String> {
    if profile_store_encryption_enabled_from_env() {
        return Ok(());
    }
    Err(
        "Gemini Google sign-in requires CARAPACE_CONFIG_PASSWORD so auth profile tokens and OAuth client secrets are encrypted at rest."
            .to_string(),
    )
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

pub(crate) fn callback_html(title: &str, body: &str) -> String {
    let title = escape_html(title);
    let body = escape_html(body);
    format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>{}</title></head><body><h1>{}</h1><p>{}</p></body></html>",
        title, title, body
    )
}

fn escape_html(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

async fn complete_cli_oauth_callback(
    provider_config: &OAuthProviderConfig,
    expected_state: &str,
    code_verifier: &str,
    returned_state: Option<&str>,
    code: Option<&str>,
) -> Result<GeminiOAuthCompletion, String> {
    let returned_state = returned_state.unwrap_or_default();
    let code = code.unwrap_or_default();
    if returned_state != expected_state {
        return Err("OAuth callback state mismatch".to_string());
    }
    if code.trim().is_empty() {
        return Err("OAuth callback missing authorization code".to_string());
    }

    let tokens = exchange_code(provider_config, code.trim(), code_verifier)
        .await
        .map_err(|err| err.to_string())?;
    let userinfo = fetch_user_info(OAuthProvider::Google, provider_config, &tokens.access_token)
        .await
        .map_err(|err| err.to_string())?;
    Ok(GeminiOAuthCompletion {
        client_id: provider_config.client_id.clone(),
        auth_profile: build_google_auth_profile(provider_config, tokens, userinfo),
    })
}

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::profiles::OAuthTokens;
    use crate::auth::profiles::UserInfo;
    use serde_json::json;
    use std::sync::Mutex;

    static ENV_VAR_TEST_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

    struct EnvVarGuard {
        key: &'static str,
        previous: Option<String>,
        _lock: std::sync::MutexGuard<'static, ()>,
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            if let Some(value) = &self.previous {
                unsafe { std::env::set_var(self.key, value) };
            } else {
                unsafe { std::env::remove_var(self.key) };
            }
        }
    }

    fn set_temp_env_var(key: &'static str, value: &str) -> EnvVarGuard {
        let lock = ENV_VAR_TEST_LOCK.lock().expect("env var test lock");
        let previous = std::env::var(key).ok();
        unsafe { std::env::set_var(key, value) };
        EnvVarGuard {
            key,
            previous,
            _lock: lock,
        }
    }

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
    fn test_resolve_google_oauth_provider_config_uses_configured_client_id_and_env_secret() {
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
        let _secret_guard = set_temp_env_var("GOOGLE_OAUTH_CLIENT_SECRET", "env-client-secret");
        let temp = tempfile::tempdir().expect("tempdir");

        let provider = resolve_google_oauth_provider_config(
            &cfg,
            None,
            None,
            "http://127.0.0.1:3000/auth/callback".to_string(),
            temp.path(),
        )
        .expect("provider config");

        assert_eq!(provider.client_id, "existing-client-id");
        assert_eq!(provider.client_secret, "env-client-secret");
    }

    #[test]
    fn test_resolve_google_oauth_provider_config_uses_stored_profile_provider_config() {
        let temp = tempfile::tempdir().expect("tempdir");
        let state_dir = temp.path().to_path_buf();
        let _password_guard = set_temp_env_var("CARAPACE_CONFIG_PASSWORD", "test-config-password");
        let profile = build_google_auth_profile(
            &OAuthProvider::Google.default_config(
                "stored-client-id",
                "stored-client-secret",
                "http://127.0.0.1:3000/auth/callback",
            ),
            sample_tokens(),
            sample_user_info(),
        );
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

        assert_eq!(provider.client_id, "stored-client-id");
        assert_eq!(provider.client_secret, "stored-client-secret");
    }

    #[test]
    fn test_resolve_google_oauth_provider_config_prefers_explicit_credentials_over_stored_profile()
    {
        let temp = tempfile::tempdir().expect("tempdir");
        let state_dir = temp.path().to_path_buf();
        let _password_guard = set_temp_env_var("CARAPACE_CONFIG_PASSWORD", "test-config-password");
        let profile = build_google_auth_profile(
            &OAuthProvider::Google.default_config(
                "stored-client-id",
                "stored-client-secret",
                "http://127.0.0.1:3000/auth/callback",
            ),
            sample_tokens(),
            sample_user_info(),
        );
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

        assert_eq!(provider.client_id, "override-client-id");
        assert_eq!(provider.client_secret, "override-client-secret");
        assert_eq!(provider.redirect_uri, "http://127.0.0.1:3555/auth/callback");
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
    fn test_apply_gemini_api_key_config_clears_empty_base_url() {
        let mut config = json!({
            "google": {
                "baseUrl": "https://proxy.example.com"
            }
        });

        apply_gemini_api_key_config(&mut config, "AIza-test-key", None).expect("api key config");

        assert!(config["google"].get("baseUrl").is_none());
    }

    #[test]
    fn test_persist_cli_google_oauth_stores_profile_and_updates_config() {
        let temp = tempfile::tempdir().expect("tempdir");
        let _password_guard = set_temp_env_var("CARAPACE_CONFIG_PASSWORD", "test-config-password");
        let mut config = json!({});
        let completion = GeminiOAuthCompletion {
            client_id: "google-client-id".to_string(),
            auth_profile: build_google_auth_profile(
                &OAuthProvider::Google.default_config(
                    "google-client-id",
                    "google-client-secret",
                    "http://127.0.0.1:3000/auth/callback",
                ),
                sample_tokens(),
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
        assert_eq!(stored_cfg.client_id, "google-client-id");
        assert_eq!(stored_cfg.client_secret, "google-client-secret");
    }

    #[test]
    fn test_start_control_google_oauth_requires_encrypted_profile_store() {
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
        let _password_guard = set_temp_env_var("CARAPACE_CONFIG_PASSWORD", "test-config-password");
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
    async fn test_complete_control_google_oauth_callback_returns_provider_error() {
        let _password_guard = set_temp_env_var("CARAPACE_CONFIG_PASSWORD", "test-config-password");
        let started = start_control_google_oauth(
            &json!({}),
            Some("google-client-id".to_string()),
            Some("google-client-secret".to_string()),
            "https://gateway.example.com",
        )
        .expect("start oauth");

        let state = {
            let flows = GEMINI_OAUTH_FLOWS.read();
            flows
                .get(&started.flow_id)
                .expect("stored flow")
                .state
                .clone()
        };

        let err = complete_control_google_oauth_callback(&state, None, Some("access_denied"))
            .await
            .expect_err("provider error should fail");
        assert!(err.contains("OAuth provider error"));
        let status = control_google_oauth_status(&started.flow_id).expect("flow status");
        assert_eq!(status.status, "failed");
    }

    #[test]
    fn test_finish_control_google_oauth_flow_returns_err_and_marks_failed() {
        let flow_id = "flow-failure".to_string();
        GEMINI_OAUTH_FLOWS.write().insert(
            flow_id.clone(),
            PendingGeminiOAuthFlow {
                id: flow_id.clone(),
                state: "state-failure".to_string(),
                code_verifier: "verifier".to_string(),
                provider_config: OAuthProvider::Google.default_config(
                    "client-id",
                    "client-secret",
                    "http://127.0.0.1:3000/auth/callback",
                ),
                created_at_ms: now_ms(),
                flow_state: GeminiOAuthFlowState::Pending,
            },
        );

        let err = finish_control_google_oauth_flow(&flow_id, Err("exchange failed".to_string()))
            .expect_err("result should propagate failure");
        assert_eq!(err, "exchange failed");

        let status = control_google_oauth_status(&flow_id).expect("flow status");
        assert_eq!(status.status, "failed");
        assert_eq!(status.error.as_deref(), Some("exchange failed"));

        GEMINI_OAUTH_FLOWS.write().remove(&flow_id);
    }

    #[test]
    fn test_callback_html_escapes_dynamic_content() {
        let html = callback_html("<Gemini>", "\"bad\" & <script>");
        assert!(html.contains("&lt;Gemini&gt;"));
        assert!(html.contains("&quot;bad&quot; &amp; &lt;script&gt;"));
        assert!(!html.contains("<script>"));
    }
}
