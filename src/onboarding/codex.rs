use parking_lot::RwLock;
use serde::Serialize;
use serde_json::{json, Value};
use sha2::Digest;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;
use std::time::Duration;

use crate::auth::profiles::{
    exchange_code, fetch_user_info, generate_auth_url, profile_store_encryption_enabled_from_env,
    AuthProfile, OAuthProvider, OAuthProviderConfig, OAuthTokens, ProfileStore,
    StoredOAuthProviderConfig,
};
use crate::server::ws::{map_validation_issues, persist_config_file, read_config_snapshot};

const FLOW_TTL: Duration = Duration::from_secs(30 * 60);
const MAX_PENDING_OAUTH_FLOWS: usize = 20;
const OPENAI_CLIENT_ID_ENV: &str = "OPENAI_OAUTH_CLIENT_ID";
const OPENAI_CLIENT_SECRET_ENV: &str = "OPENAI_OAUTH_CLIENT_SECRET";

static CODEX_OAUTH_FLOWS: LazyLock<RwLock<HashMap<String, PendingCodexOAuthFlow>>> =
    LazyLock::new(|| RwLock::new(HashMap::new()));

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
enum CodexOAuthFlowState {
    Pending,
    InProgress,
    Completed(Box<CodexOAuthCompletion>),
    Failed(String),
}

#[derive(Clone)]
struct PendingCodexOAuthFlow {
    id: String,
    state: String,
    code_verifier: String,
    provider_config: OAuthProviderConfig,
    created_at_ms: u64,
    flow_state: CodexOAuthFlowState,
}

#[derive(Clone)]
pub struct CodexOAuthCompletion {
    pub client_id: String,
    pub auth_profile: AuthProfile,
}

type CliOAuthSender = std::sync::Arc<
    std::sync::Mutex<Option<tokio::sync::oneshot::Sender<Result<CodexOAuthCompletion, String>>>>,
>;

enum ControlOpenAiOAuthAction {
    AlreadyCompleted,
    AlreadyFailed(String),
    AlreadyProcessing,
    Start {
        flow_id: String,
        provider_config: OAuthProviderConfig,
        verifier: String,
    },
}

pub fn resolve_openai_oauth_provider_config(
    cfg: &Value,
    client_id_override: Option<String>,
    client_secret_override: Option<String>,
    redirect_uri: String,
    state_dir: &Path,
) -> Result<OAuthProviderConfig, String> {
    let stored_provider_config = load_stored_openai_provider_config(cfg, state_dir);

    let client_id = client_id_override
        .or_else(|| std::env::var(OPENAI_CLIENT_ID_ENV).ok())
        .or_else(|| configured_openai_oauth_client_id(cfg))
        .or_else(|| {
            stored_provider_config
                .as_ref()
                .map(|cfg| cfg.client_id.clone())
        })
        .unwrap_or_default();
    let client_secret = client_secret_override
        .or_else(|| std::env::var(OPENAI_CLIENT_SECRET_ENV).ok())
        .or_else(|| {
            stored_provider_config
                .as_ref()
                .map(|cfg| cfg.client_secret.clone())
        })
        .unwrap_or_default();

    if client_id.trim().is_empty() || client_secret.trim().is_empty() {
        return Err("Codex sign-in requires OpenAI OAuth clientId and clientSecret.".to_string());
    }

    let mut provider_config =
        OAuthProvider::OpenAI.default_config(client_id.trim(), client_secret.trim(), &redirect_uri);
    if let Some(stored) = stored_provider_config {
        provider_config.auth_url = stored.auth_url;
        provider_config.token_url = stored.token_url;
        provider_config.userinfo_url = stored.userinfo_url;
        provider_config.scopes = stored.scopes;
    }
    Ok(provider_config)
}

pub fn start_control_openai_oauth(
    cfg: &Value,
    client_id_override: Option<String>,
    client_secret_override: Option<String>,
    redirect_base_url: &str,
) -> Result<CodexOAuthStart, String> {
    require_encrypted_profile_store_for_openai_oauth()?;

    let redirect_uri = format!(
        "{}/control/onboarding/codex/callback",
        redirect_base_url.trim_end_matches('/')
    );
    let provider_config = resolve_openai_oauth_provider_config(
        cfg,
        client_id_override,
        client_secret_override,
        redirect_uri.clone(),
        &crate::paths::resolve_state_dir(),
    )?;

    let state = format!("codex-{}", uuid::Uuid::new_v4());
    let flow_id = uuid::Uuid::new_v4().to_string();
    let (auth_url, code_verifier) =
        generate_auth_url(&provider_config, &state).map_err(|err| err.to_string())?;

    let flow = PendingCodexOAuthFlow {
        id: flow_id.clone(),
        state,
        code_verifier,
        provider_config,
        created_at_ms: now_ms(),
        flow_state: CodexOAuthFlowState::Pending,
    };
    insert_openai_oauth_flow(flow)?;

    Ok(CodexOAuthStart {
        flow_id,
        auth_url,
        redirect_uri,
    })
}

pub async fn complete_control_openai_oauth_callback(
    state_param: &str,
    code: Option<&str>,
    error: Option<&str>,
    error_description: Option<&str>,
) -> Result<(), String> {
    cleanup_expired_flows();
    let (flow_id, provider_config, verifier) = match begin_control_openai_oauth_completion(
        state_param,
    )? {
        ControlOpenAiOAuthAction::AlreadyCompleted => return Ok(()),
        ControlOpenAiOAuthAction::AlreadyFailed(err) => return Err(err),
        ControlOpenAiOAuthAction::AlreadyProcessing => {
            return Err(
                "Codex sign-in callback is already being processed. Return to the Control UI and refresh status."
                    .to_string(),
            )
        }
        ControlOpenAiOAuthAction::Start {
            flow_id,
            provider_config,
            verifier,
        } => (flow_id, provider_config, verifier),
    };

    if let Some(err) = error.filter(|value| !value.trim().is_empty()) {
        return finish_control_openai_oauth_flow(
            &flow_id,
            Err(format_oauth_provider_error(err, error_description)),
        );
    }

    let code = match code.map(str::trim).filter(|value| !value.is_empty()) {
        Some(code) => code,
        None => {
            return finish_control_openai_oauth_flow(
                &flow_id,
                Err("Missing OAuth authorization code".to_string()),
            );
        }
    };

    let result = async {
        let tokens = exchange_code(&provider_config, code, &verifier)
            .await
            .map_err(|err| err.to_string())?;
        let userinfo = fetch_user_info(
            OAuthProvider::OpenAI,
            &provider_config,
            &tokens.access_token,
        )
        .await
        .map_err(|err| err.to_string())?;
        Ok::<CodexOAuthCompletion, String>(CodexOAuthCompletion {
            client_id: provider_config.client_id.clone(),
            auth_profile: build_openai_auth_profile(&provider_config, tokens, userinfo),
        })
    }
    .await;

    finish_control_openai_oauth_flow(&flow_id, result)
}

pub fn control_openai_oauth_status(flow_id: &str) -> Result<CodexOAuthStatus, String> {
    cleanup_expired_flows();
    let flows = CODEX_OAUTH_FLOWS.read();
    let flow = flows
        .get(flow_id)
        .ok_or_else(|| "Unknown or expired Codex OAuth flow".to_string())?;
    Ok(match &flow.flow_state {
        CodexOAuthFlowState::Pending | CodexOAuthFlowState::InProgress => CodexOAuthStatus {
            flow_id: flow.id.clone(),
            status: "pending",
            profile_name: None,
            email: None,
            error: None,
        },
        CodexOAuthFlowState::Completed(completion) => CodexOAuthStatus {
            flow_id: flow.id.clone(),
            status: "completed",
            profile_name: Some(completion.auth_profile.name.clone()),
            email: completion.auth_profile.email.clone(),
            error: None,
        },
        CodexOAuthFlowState::Failed(err) => CodexOAuthStatus {
            flow_id: flow.id.clone(),
            status: "failed",
            profile_name: None,
            email: None,
            error: Some(err.clone()),
        },
    })
}

pub fn apply_control_openai_oauth(flow_id: &str, state_dir: PathBuf) -> Result<Value, String> {
    require_encrypted_profile_store_for_openai_oauth()?;
    cleanup_expired_flows();
    let completion = {
        let flows = CODEX_OAUTH_FLOWS.read();
        let flow = flows
            .get(flow_id)
            .ok_or_else(|| "Unknown or expired Codex OAuth flow".to_string())?;
        match &flow.flow_state {
            CodexOAuthFlowState::Completed(completion) => completion.as_ref().clone(),
            CodexOAuthFlowState::Pending | CodexOAuthFlowState::InProgress => {
                return Err("Codex sign-in is still pending".to_string());
            }
            CodexOAuthFlowState::Failed(err) => return Err(err.clone()),
        }
    };

    let mut snapshot = read_config_snapshot();
    let profile_id = persist_cli_openai_oauth(state_dir, &mut snapshot.config, completion)?;
    validate_and_persist_config(&snapshot.config)?;
    CODEX_OAUTH_FLOWS.write().remove(flow_id);

    Ok(json!({
        "authProfile": profile_id,
        "provider": "codex",
        "model": crate::agent::codex::DEFAULT_CODEX_MODEL,
    }))
}

pub async fn run_cli_openai_oauth(
    cfg: Value,
    client_id_override: Option<String>,
    client_secret_override: Option<String>,
) -> Result<CodexOAuthCompletion, String> {
    run_cli_openai_oauth_with_timeout(
        cfg,
        client_id_override,
        client_secret_override,
        Duration::from_secs(300),
    )
    .await
}

async fn run_cli_openai_oauth_with_timeout(
    cfg: Value,
    client_id_override: Option<String>,
    client_secret_override: Option<String>,
    timeout: Duration,
) -> Result<CodexOAuthCompletion, String> {
    require_encrypted_profile_store_for_openai_oauth()?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|err| format!("failed to bind local OAuth callback listener: {err}"))?;
    let bind_addr = listener
        .local_addr()
        .map_err(|err| format!("failed to determine local OAuth callback port: {err}"))?;
    let redirect_uri = format!("http://127.0.0.1:{}/auth/callback", bind_addr.port());
    let provider_config = resolve_openai_oauth_provider_config(
        &cfg,
        client_id_override,
        client_secret_override,
        redirect_uri.clone(),
        &crate::paths::resolve_state_dir(),
    )?;

    let parsed_redirect = url::Url::parse(&provider_config.redirect_uri)
        .map_err(|err| format!("invalid Codex OAuth redirect URI: {err}"))?;
    let host = parsed_redirect.host_str().unwrap_or_default();
    if host != "127.0.0.1" && host != "localhost" {
        return Err(
            "CLI Codex sign-in requires a loopback redirect URI; use Control UI sign-in."
                .to_string(),
        );
    }

    let path = parsed_redirect.path().to_string();
    let state = format!("codex-cli-{}", uuid::Uuid::new_v4());
    let (auth_url, verifier) =
        generate_auth_url(&provider_config, &state).map_err(|err| err.to_string())?;

    println!();
    println!("Open this URL to sign in with OpenAI for Codex:");
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
    let shutdown_tx_for_server = shutdown_tx.clone();

    let server_task = tokio::spawn(async move {
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
            error_description: Option<String>,
        }

        async fn callback_handler(
            State(state): State<CliOAuthState>,
            Query(query): Query<CallbackQuery>,
        ) -> Html<String> {
            if !cli_oauth_callback_matches_expected_state(
                &state.expected_state,
                query.state.as_deref(),
            ) {
                return Html(callback_html(
                    "Still waiting for Codex sign-in",
                    "Ignored an unrelated OAuth callback. Return to the active sign-in flow and continue.",
                ));
            }

            let result = match query.error.filter(|value| !value.trim().is_empty()) {
                Some(err) => Err(format_oauth_provider_error(
                    &err,
                    query.error_description.as_deref(),
                )),
                None => {
                    complete_cli_oauth_callback(
                        &state.provider_config,
                        &state.code_verifier,
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
                    "Codex sign-in complete",
                    "You can return to Carapace and finish setup.",
                )),
                Err(err) => Html(callback_html("Codex sign-in failed", &err)),
            }
        }

        let app = Router::new()
            .route(&path_for_server, get(callback_handler))
            .with_state(CliOAuthState {
                expected_state: state_for_server,
                code_verifier: verifier_for_server,
                provider_config: provider_config_for_server,
                sender: result_tx.clone(),
                shutdown_tx: shutdown_tx_for_server,
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

    let result = match tokio::time::timeout(timeout, result_rx).await {
        Ok(Ok(Ok(completion))) => Ok(completion),
        Ok(Ok(Err(err))) => Err(err),
        Ok(Err(_)) => Err("Codex OAuth callback channel closed unexpectedly".to_string()),
        Err(_) => Err("Timed out waiting for Codex sign-in callback".to_string()),
    };

    let _ = shutdown_tx.send(true);
    let _ = tokio::time::timeout(Duration::from_secs(5), server_task).await;

    result
}

pub fn persist_cli_openai_oauth(
    state_dir: PathBuf,
    config: &mut Value,
    completion: CodexOAuthCompletion,
) -> Result<String, String> {
    require_encrypted_profile_store_for_openai_oauth()?;
    let profile_id = upsert_openai_profile(&state_dir, completion.auth_profile)?;
    ensure_openai_oauth_config(config, &completion.client_id, &profile_id);
    Ok(profile_id)
}

fn build_openai_auth_profile(
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
        tokens,
        oauth_provider_config: Some(StoredOAuthProviderConfig::from(provider_config)),
    }
}

fn upsert_openai_profile(state_dir: &Path, profile: AuthProfile) -> Result<String, String> {
    let store = ProfileStore::from_env(state_dir.to_path_buf()).map_err(|err| err.to_string())?;
    store.load().map_err(|err| err.to_string())?;

    let existing = store.find_matching(
        OAuthProvider::OpenAI,
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

fn ensure_openai_oauth_config(config: &mut Value, client_id: &str, profile_id: &str) {
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
        .get("openai")
        .is_some_and(Value::is_object)
    {
        config["auth"]["profiles"]["providers"]["openai"] = json!({});
    }
    config["auth"]["profiles"]["providers"]["openai"]["clientId"] = json!(client_id);
    if let Some(openai_provider) = config["auth"]["profiles"]["providers"]
        .get_mut("openai")
        .and_then(Value::as_object_mut)
    {
        openai_provider.remove("clientSecret");
    }

    if !config.get("codex").is_some_and(Value::is_object) {
        config["codex"] = json!({});
    }
    if let Some(codex) = config.get_mut("codex").and_then(Value::as_object_mut) {
        codex.insert("authProfile".to_string(), json!(profile_id));
    }
}

fn finish_control_openai_oauth_flow(
    flow_id: &str,
    result: Result<CodexOAuthCompletion, String>,
) -> Result<(), String> {
    let mut flows = CODEX_OAUTH_FLOWS.write();
    if let Some(flow) = flows.get_mut(flow_id) {
        match &flow.flow_state {
            CodexOAuthFlowState::Completed(_) => return Ok(()),
            CodexOAuthFlowState::Failed(err) => return Err(err.clone()),
            CodexOAuthFlowState::Pending | CodexOAuthFlowState::InProgress => {
                flow.flow_state = match &result {
                    Ok(completion) => CodexOAuthFlowState::Completed(Box::new(completion.clone())),
                    Err(err) => CodexOAuthFlowState::Failed(err.clone()),
                };
            }
        }
    }
    result.map(|_| ())
}

fn begin_control_openai_oauth_completion(
    state_param: &str,
) -> Result<ControlOpenAiOAuthAction, String> {
    let mut flows = CODEX_OAUTH_FLOWS.write();
    let flow = flows
        .values_mut()
        .find(|flow| flow.state == state_param)
        .ok_or_else(|| "Unknown or expired Codex OAuth flow".to_string())?;

    match &flow.flow_state {
        CodexOAuthFlowState::Completed(_) => Ok(ControlOpenAiOAuthAction::AlreadyCompleted),
        CodexOAuthFlowState::Failed(err) => {
            Ok(ControlOpenAiOAuthAction::AlreadyFailed(err.clone()))
        }
        CodexOAuthFlowState::InProgress => Ok(ControlOpenAiOAuthAction::AlreadyProcessing),
        CodexOAuthFlowState::Pending => {
            flow.flow_state = CodexOAuthFlowState::InProgress;
            flow.created_at_ms = now_ms();
            Ok(ControlOpenAiOAuthAction::Start {
                flow_id: flow.id.clone(),
                provider_config: flow.provider_config.clone(),
                verifier: flow.code_verifier.clone(),
            })
        }
    }
}

fn insert_openai_oauth_flow(flow: PendingCodexOAuthFlow) -> Result<(), String> {
    let cutoff = now_ms().saturating_sub(FLOW_TTL.as_millis() as u64);
    let mut flows = CODEX_OAUTH_FLOWS.write();
    flows.retain(|_, flow| flow.created_at_ms >= cutoff);
    if flows.len() >= MAX_PENDING_OAUTH_FLOWS {
        return Err("Too many active Codex sign-in flows. Wait for an existing flow to finish or expire and retry.".to_string());
    }
    flows.insert(flow.id.clone(), flow);
    Ok(())
}

fn require_encrypted_profile_store_for_openai_oauth() -> Result<(), String> {
    if profile_store_encryption_enabled_from_env() {
        return Ok(());
    }
    Err(
        "Codex sign-in requires CARAPACE_CONFIG_PASSWORD so auth profile tokens and OAuth client secrets are encrypted at rest."
            .to_string(),
    )
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
    CODEX_OAUTH_FLOWS
        .write()
        .retain(|_, flow| flow.created_at_ms >= cutoff);
}

fn now_ms() -> u64 {
    crate::time::unix_now_ms_u64()
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

fn format_oauth_provider_error(error: &str, error_description: Option<&str>) -> String {
    let description = error_description
        .map(str::trim)
        .filter(|value| !value.is_empty());
    match description {
        Some(description) => format!("OAuth provider error: {error} ({description})"),
        None => format!("OAuth provider error: {error}"),
    }
}

fn cli_oauth_callback_matches_expected_state(
    expected_state: &str,
    returned_state: Option<&str>,
) -> bool {
    returned_state
        .map(str::trim)
        .filter(|value| !value.is_empty())
        == Some(expected_state)
}

async fn complete_cli_oauth_callback(
    provider_config: &OAuthProviderConfig,
    code_verifier: &str,
    code: Option<&str>,
) -> Result<CodexOAuthCompletion, String> {
    let code = code.unwrap_or_default();
    if code.trim().is_empty() {
        return Err("OAuth callback missing authorization code".to_string());
    }

    let tokens = exchange_code(provider_config, code.trim(), code_verifier)
        .await
        .map_err(|err| err.to_string())?;
    let userinfo = fetch_user_info(OAuthProvider::OpenAI, provider_config, &tokens.access_token)
        .await
        .map_err(|err| err.to_string())?;
    Ok(CodexOAuthCompletion {
        client_id: provider_config.client_id.clone(),
        auth_profile: build_openai_auth_profile(provider_config, tokens, userinfo),
    })
}

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::profiles::{OAuthTokens, UserInfo};
    use crate::test_support::env::ScopedEnv;
    use serde_json::json;

    fn sample_tokens() -> OAuthTokens {
        OAuthTokens {
            access_token: "header.eyJzdWIiOiJ1c2VyLTEyMyIsImh0dHBzOi8vYXBpLm9wZW5haS5jb20vcHJvZmlsZSI6eyJlbWFpbCI6InVzZXJAZXhhbXBsZS5jb20ifX0.sig".to_string(),
            refresh_token: Some("refresh-token".to_string()),
            token_type: "Bearer".to_string(),
            expires_at_ms: Some(now_ms() + 3_600_000),
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
        env_guard.set(OPENAI_CLIENT_SECRET_ENV, "env-client-secret");
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
        let mut config = json!({});
        let completion = CodexOAuthCompletion {
            client_id: "openai-client-id".to_string(),
            auth_profile: build_openai_auth_profile(
                &OAuthProvider::OpenAI.default_config(
                    "openai-client-id",
                    "openai-client-secret",
                    "http://127.0.0.1:3000/auth/callback",
                ),
                sample_tokens(),
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
            let flows = CODEX_OAUTH_FLOWS.read();
            flows
                .get(&started.flow_id)
                .expect("stored flow")
                .state
                .clone()
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
    fn test_finish_control_openai_oauth_flow_preserves_completed_flow() {
        let flow_id = "codex-flow-completed".to_string();
        CODEX_OAUTH_FLOWS.write().insert(
            flow_id.clone(),
            PendingCodexOAuthFlow {
                id: flow_id.clone(),
                state: "codex-state-completed".to_string(),
                code_verifier: "verifier".to_string(),
                provider_config: OAuthProvider::OpenAI.default_config(
                    "client-id",
                    "client-secret",
                    "https://gateway.example.com/control/onboarding/codex/callback",
                ),
                created_at_ms: now_ms(),
                flow_state: CodexOAuthFlowState::Completed(Box::new(CodexOAuthCompletion {
                    client_id: "client-id".to_string(),
                    auth_profile: build_openai_auth_profile(
                        &OAuthProvider::OpenAI.default_config(
                            "client-id",
                            "client-secret",
                            "https://gateway.example.com/control/onboarding/codex/callback",
                        ),
                        sample_tokens(),
                        sample_user_info(),
                    ),
                })),
            },
        );

        let result = finish_control_openai_oauth_flow(&flow_id, Err("late failure".to_string()));
        assert!(result.is_ok(), "completed flow should stay successful");

        let status = control_openai_oauth_status(&flow_id).expect("flow status");
        assert_eq!(status.status, "completed");

        CODEX_OAUTH_FLOWS.write().remove(&flow_id);
    }

    #[tokio::test]
    async fn test_complete_control_openai_oauth_callback_rejects_in_progress_flow() {
        let flow_id = "codex-flow-in-progress".to_string();
        let state = "codex-state-in-progress".to_string();
        CODEX_OAUTH_FLOWS.write().insert(
            flow_id.clone(),
            PendingCodexOAuthFlow {
                id: flow_id.clone(),
                state: state.clone(),
                code_verifier: "verifier".to_string(),
                provider_config: OAuthProvider::OpenAI.default_config(
                    "client-id",
                    "client-secret",
                    "https://gateway.example.com/control/onboarding/codex/callback",
                ),
                created_at_ms: now_ms(),
                flow_state: CodexOAuthFlowState::InProgress,
            },
        );

        let err = complete_control_openai_oauth_callback(&state, Some("code"), None, None)
            .await
            .expect_err("in-progress flow should not start another exchange");
        assert!(err.contains("already being processed"));

        let status = control_openai_oauth_status(&flow_id).expect("flow status");
        assert_eq!(status.status, "pending");

        CODEX_OAUTH_FLOWS.write().remove(&flow_id);
    }

    #[test]
    fn test_start_control_openai_oauth_evicts_stale_in_progress_flow() {
        let mut env_guard = ScopedEnv::new();
        env_guard.set("CARAPACE_CONFIG_PASSWORD", "test-config-password");
        let flow_id = "codex-stale-in-progress".to_string();
        CODEX_OAUTH_FLOWS.write().insert(
            flow_id.clone(),
            PendingCodexOAuthFlow {
                id: flow_id.clone(),
                state: "codex-stale-state".to_string(),
                code_verifier: "verifier".to_string(),
                provider_config: OAuthProvider::OpenAI.default_config(
                    "client-id",
                    "client-secret",
                    "https://gateway.example.com/control/onboarding/codex/callback",
                ),
                created_at_ms: now_ms() - FLOW_TTL.as_millis() as u64 - 1,
                flow_state: CodexOAuthFlowState::InProgress,
            },
        );

        let started = start_control_openai_oauth(
            &json!({}),
            Some("openai-client-id".to_string()),
            Some("openai-client-secret".to_string()),
            "https://gateway.example.com",
        )
        .expect("stale in-progress flow should be evicted");

        assert_ne!(started.flow_id, flow_id);
        assert!(CODEX_OAUTH_FLOWS.read().get(&flow_id).is_none());

        CODEX_OAUTH_FLOWS.write().remove(&started.flow_id);
    }

    #[test]
    fn test_start_control_openai_oauth_rejects_when_pending_flow_limit_reached() {
        let mut env_guard = ScopedEnv::new();
        env_guard.set("CARAPACE_CONFIG_PASSWORD", "test-config-password");
        let mut flows = CODEX_OAUTH_FLOWS.write();
        flows.clear();
        for i in 0..MAX_PENDING_OAUTH_FLOWS {
            let id = format!("codex-flow-{i}");
            flows.insert(
                id.clone(),
                PendingCodexOAuthFlow {
                    id: id.clone(),
                    state: format!("codex-state-{i}"),
                    code_verifier: "verifier".to_string(),
                    provider_config: OAuthProvider::OpenAI.default_config(
                        "client-id",
                        "client-secret",
                        "https://gateway.example.com/control/onboarding/codex/callback",
                    ),
                    created_at_ms: now_ms(),
                    flow_state: CodexOAuthFlowState::Pending,
                },
            );
        }
        drop(flows);

        let err = start_control_openai_oauth(
            &json!({}),
            Some("openai-client-id".to_string()),
            Some("openai-client-secret".to_string()),
            "https://gateway.example.com",
        )
        .expect_err("flow limit should reject new sign-in starts");
        assert!(err.contains("Too many active Codex sign-in flows"));

        CODEX_OAUTH_FLOWS.write().clear();
    }

    #[test]
    fn test_callback_html_escapes_html() {
        let html = callback_html("<Codex>", "\"bad\" & <script>");
        assert!(html.contains("&lt;Codex&gt;"));
        assert!(html.contains("&quot;bad&quot; &amp; &lt;script&gt;"));
    }
}
