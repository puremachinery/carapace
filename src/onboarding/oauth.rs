//! Shared types and helpers for OAuth onboarding flows.
//!
//! This module extracts the common structure shared by the Codex (OpenAI) and
//! Gemini (Google) OAuth onboarding implementations. Provider-specific behaviour
//! is captured via function pointers in [`OAuthOnboardingSpec`]; everything else
//! (flow state, result types, HTML helpers, config persistence) lives here once.

use parking_lot::RwLock;
use serde_json::Value;
use std::collections::HashMap;
use std::path::Path;
use std::sync::LazyLock;
use std::time::Duration;

use crate::auth::profiles::{
    exchange_code, fetch_user_info, generate_auth_url, profile_store_encryption_enabled_from_env,
    AuthProfile, OAuthProvider, OAuthProviderConfig, OAuthTokens, ProfileStore, UserInfo,
};
use crate::server::ws::{map_validation_issues, persist_config_file};

/// Oneshot sender used by the CLI OAuth callback server to deliver the result.
type CliOAuthSender = std::sync::Arc<
    std::sync::Mutex<Option<tokio::sync::oneshot::Sender<Result<OAuthCompletion, String>>>>,
>;

/// Function pointer that resolves provider-specific OAuth configuration.
type ResolveProviderConfigFn = fn(
    cfg: &Value,
    client_id_override: Option<String>,
    client_secret_override: Option<String>,
    redirect_uri: String,
    state_dir: &Path,
) -> Result<OAuthProviderConfig, String>;

// ---------------------------------------------------------------------------
// Provider spec
// ---------------------------------------------------------------------------

/// Static, per-provider configuration that parameterises the generic OAuth
/// onboarding flow engine.
pub(crate) struct OAuthOnboardingSpec {
    pub oauth_provider: OAuthProvider,
    /// Human-readable provider name shown in UI, e.g. "Codex" / "Gemini".
    pub display_name: &'static str,
    /// Human-readable identity-provider name, e.g. "OpenAI" / "Google".
    pub idp_display_name: &'static str,
    /// Short label used to derive the callback path, e.g. "codex" / "gemini".
    pub provider_label: &'static str,

    pub client_id_env: &'static str,
    pub client_secret_env: &'static str,

    /// Extra hint appended to the CLI loopback-redirect error, e.g.
    /// " or Gemini API key mode" for Gemini. Empty string for providers
    /// without an alternative auth path.
    pub cli_loopback_error_extra: &'static str,

    /// Maximum number of concurrent pending flows per provider.
    pub max_pending_flows: usize,
    /// Time-to-live for a pending flow, in seconds.
    pub flow_ttl_secs: u64,

    /// Resolve provider-specific OAuth configuration from the merged config
    /// value, optional client-id/secret overrides, the redirect URI, and the
    /// state directory.
    pub resolve_provider_config: ResolveProviderConfigFn,

    /// Build an [`AuthProfile`] from the tokens, provider config and user info
    /// returned after a successful token exchange.
    pub build_auth_profile: fn(
        tokens: OAuthTokens,
        provider_config: &OAuthProviderConfig,
        user_info: UserInfo,
    ) -> AuthProfile,

    /// Persist provider-specific fields into the config value after a profile
    /// has been created (e.g. writing `codex.profile` or `gemini.profile`).
    pub write_provider_config: fn(cfg: &mut Value, profile_id: &str, client_id: &str),
}

// ---------------------------------------------------------------------------
// Flow state
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub(crate) struct OAuthCompletion {
    pub client_id: String,
    pub auth_profile: AuthProfile,
}

#[derive(Clone)]
pub(crate) enum OAuthFlowState {
    Pending,
    InProgress,
    Completed(Box<OAuthCompletion>),
    Failed(String),
}

#[derive(Clone)]
pub(crate) struct PendingOAuthFlow {
    pub id: String,
    pub state: String,
    pub code_verifier: String,
    pub provider_config: OAuthProviderConfig,
    pub created_at_ms: u64,
    pub flow_state: OAuthFlowState,
    pub spec: &'static OAuthOnboardingSpec,
}

// ---------------------------------------------------------------------------
// Typed results
// ---------------------------------------------------------------------------

pub(crate) struct OAuthStartResult {
    pub flow_id: String,
    pub auth_url: String,
    pub redirect_uri: String,
}

pub(crate) enum OAuthStatusResult {
    InProgress,
    Completed {
        profile_name: String,
        email: Option<String>,
    },
    Failed {
        error: String,
    },
    NotFound,
}

pub(crate) struct OAuthApplyResult {
    pub profile_id: String,
}

// ---------------------------------------------------------------------------
// Shared helpers (previously duplicated in codex.rs and gemini.rs)
// ---------------------------------------------------------------------------

pub(crate) fn now_ms() -> u64 {
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

pub(crate) fn format_oauth_provider_error(error: &str, error_description: Option<&str>) -> String {
    let description = error_description
        .map(str::trim)
        .filter(|value| !value.is_empty());
    match description {
        Some(description) => format!("OAuth provider error: {error} ({description})"),
        None => format!("OAuth provider error: {error}"),
    }
}

pub(crate) fn validate_and_persist_config(config: &Value) -> Result<(), String> {
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

/// Shared match-and-upsert: loads the profile store from state_dir, finds an
/// existing profile by provider/user_id/email to preserve its id and created_at_ms,
/// then upserts.
pub(crate) fn upsert_oauth_profile(
    state_dir: &Path,
    profile: AuthProfile,
) -> Result<String, String> {
    let store = ProfileStore::from_env(state_dir.to_path_buf()).map_err(|err| err.to_string())?;
    store.load().map_err(|err| err.to_string())?;

    let existing = store.find_matching(
        profile.provider,
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

// ---------------------------------------------------------------------------
// Shared flow storage
// ---------------------------------------------------------------------------

static OAUTH_FLOWS: LazyLock<RwLock<HashMap<String, PendingOAuthFlow>>> =
    LazyLock::new(|| RwLock::new(HashMap::new()));

/// Insert a flow into the shared store, enforcing per-provider limits.
///
/// Expired flows for the same provider are pruned first. If the provider
/// still has `>= spec.max_pending_flows` entries, the insert is rejected.
pub(crate) fn insert_oauth_flow(flow: PendingOAuthFlow) -> Result<(), String> {
    let spec = flow.spec;
    let cutoff = now_ms().saturating_sub(spec.flow_ttl_secs * 1000);
    let mut flows = OAUTH_FLOWS.write();

    // Evict expired flows for this provider before counting.
    flows.retain(|_, f| !std::ptr::eq(f.spec, spec) || f.created_at_ms >= cutoff);

    let provider_count = flows
        .values()
        .filter(|f| std::ptr::eq(f.spec, spec))
        .count();
    if provider_count >= spec.max_pending_flows {
        return Err(format!(
            "Too many active {} sign-in flows. \
             Wait for an existing flow to finish or expire and retry.",
            spec.display_name
        ));
    }

    flows.insert(flow.id.clone(), flow);
    Ok(())
}

/// Look up a flow by its unique flow ID.
pub(crate) fn get_flow(flow_id: &str) -> Option<PendingOAuthFlow> {
    OAUTH_FLOWS.read().get(flow_id).cloned()
}

/// Mutate a flow's state in place (test-only helper).
#[cfg(test)]
pub(crate) fn update_flow_state(flow_id: &str, new_state: OAuthFlowState) {
    if let Some(flow) = OAUTH_FLOWS.write().get_mut(flow_id) {
        flow.flow_state = new_state;
    }
}

/// Remove all flows whose TTL has elapsed.
pub(crate) fn cleanup_expired_flows() {
    let now = now_ms();
    OAUTH_FLOWS
        .write()
        .retain(|_, flow| now.saturating_sub(flow.created_at_ms) < flow.spec.flow_ttl_secs * 1000);
}

/// Remove a flow from the shared store by ID.
fn remove_flow(flow_id: &str) {
    OAUTH_FLOWS.write().remove(flow_id);
}

/// Remove a flow from the shared store by ID (test-only).
#[cfg(test)]
pub(crate) fn remove_flow_for_test(flow_id: &str) {
    remove_flow(flow_id);
}

// ---------------------------------------------------------------------------
// Flow engine — Control-facing functions
// ---------------------------------------------------------------------------

/// Checks that CARAPACE_CONFIG_PASSWORD is set so profile tokens and OAuth
/// client secrets are encrypted at rest.
pub(crate) fn require_encrypted_profile_store(spec: &OAuthOnboardingSpec) -> Result<(), String> {
    if profile_store_encryption_enabled_from_env() {
        return Ok(());
    }
    Err(format!(
        "{} sign-in requires CARAPACE_CONFIG_PASSWORD so auth profile tokens \
         and OAuth client secrets are encrypted at rest.",
        spec.display_name
    ))
}

/// Start a new Control-UI OAuth flow.
///
/// Validates encryption, resolves provider config, generates the authorization
/// URL, and stores the pending flow.
pub(crate) fn start_oauth_flow(
    spec: &'static OAuthOnboardingSpec,
    cfg: &Value,
    client_id_override: Option<String>,
    client_secret_override: Option<String>,
    redirect_base_url: &str,
) -> Result<OAuthStartResult, String> {
    require_encrypted_profile_store(spec)?;

    let redirect_uri = format!(
        "{}/control/onboarding/{}/callback",
        redirect_base_url.trim_end_matches('/'),
        spec.provider_label
    );
    let provider_config = (spec.resolve_provider_config)(
        cfg,
        client_id_override,
        client_secret_override,
        redirect_uri.clone(),
        &crate::paths::resolve_state_dir(),
    )?;

    let state = format!("{}-{}", spec.provider_label, uuid::Uuid::new_v4());
    let flow_id = uuid::Uuid::new_v4().to_string();
    let (auth_url, code_verifier) =
        generate_auth_url(&provider_config, &state).map_err(|err| err.to_string())?;

    let flow = PendingOAuthFlow {
        id: flow_id.clone(),
        state,
        code_verifier,
        provider_config,
        created_at_ms: now_ms(),
        flow_state: OAuthFlowState::Pending,
        spec,
    };
    insert_oauth_flow(flow)?;

    Ok(OAuthStartResult {
        flow_id,
        auth_url,
        redirect_uri,
    })
}

/// Handle the OAuth callback from the identity provider.
///
/// Looks up the pending flow by state, transitions through InProgress,
/// exchanges the authorization code for tokens, fetches user info, and builds
/// the auth profile. The flow ends in Completed or Failed state.
pub(crate) async fn complete_oauth_callback(
    spec: &'static OAuthOnboardingSpec,
    state_param: &str,
    code: Option<&str>,
    error: Option<&str>,
    error_description: Option<&str>,
) -> Result<(), String> {
    cleanup_expired_flows();

    // --- Begin: look up flow and transition to InProgress (atomically) ---
    let (flow_id, provider_config, verifier) = {
        let mut flows = OAUTH_FLOWS.write();
        let flow = flows
            .values_mut()
            .find(|f| std::ptr::eq(f.spec, spec) && f.state == state_param)
            .ok_or_else(|| format!("Unknown or expired {} OAuth flow", spec.display_name))?;

        match &flow.flow_state {
            OAuthFlowState::Completed(_) => return Ok(()),
            OAuthFlowState::Failed(err) => return Err(err.clone()),
            OAuthFlowState::InProgress => {
                return Err(format!(
                    "{} sign-in callback is already being processed. \
                     Return to the Control UI and refresh status.",
                    spec.display_name
                ));
            }
            OAuthFlowState::Pending => {
                flow.flow_state = OAuthFlowState::InProgress;
                (
                    flow.id.clone(),
                    flow.provider_config.clone(),
                    flow.code_verifier.clone(),
                )
            }
        }
    };
    // --- End: lock released ---

    // Check for provider-side error.
    if let Some(err) = error.filter(|value| !value.trim().is_empty()) {
        return finish_oauth_flow(
            &flow_id,
            Err(format_oauth_provider_error(err, error_description)),
        );
    }

    // Extract authorization code.
    let code = match code.map(str::trim).filter(|value| !value.is_empty()) {
        Some(code) => code,
        None => {
            return finish_oauth_flow(
                &flow_id,
                Err("Missing OAuth authorization code".to_string()),
            );
        }
    };

    // Exchange code for tokens and fetch user info.
    let result = async {
        let tokens = exchange_code(&provider_config, code, &verifier)
            .await
            .map_err(|err| err.to_string())?;
        let userinfo = fetch_user_info(spec.oauth_provider, &provider_config, &tokens.access_token)
            .await
            .map_err(|err| err.to_string())?;
        Ok::<OAuthCompletion, String>(OAuthCompletion {
            client_id: provider_config.client_id.clone(),
            auth_profile: (spec.build_auth_profile)(tokens, &provider_config, userinfo),
        })
    }
    .await;

    finish_oauth_flow(&flow_id, result)
}

/// Transition a flow to its terminal state (Completed or Failed).
///
/// Mirrors the idempotency behaviour of the original per-provider
/// `finish_control_*_oauth_flow` helpers: if the flow has already reached a
/// terminal state, that state is returned without modification.
fn finish_oauth_flow(flow_id: &str, result: Result<OAuthCompletion, String>) -> Result<(), String> {
    let mut flows = OAUTH_FLOWS.write();
    if let Some(flow) = flows.get_mut(flow_id) {
        match &flow.flow_state {
            OAuthFlowState::Completed(_) => return Ok(()),
            OAuthFlowState::Failed(err) => return Err(err.clone()),
            OAuthFlowState::Pending | OAuthFlowState::InProgress => {
                flow.flow_state = match &result {
                    Ok(completion) => OAuthFlowState::Completed(Box::new(completion.clone())),
                    Err(err) => OAuthFlowState::Failed(err.clone()),
                };
            }
        }
    }
    result.map(|_| ())
}

/// Poll the status of an OAuth flow by its flow ID.
/// Only returns results for flows matching the given spec (prevents cross-provider leaks).
pub(crate) fn oauth_flow_status(
    spec: &'static OAuthOnboardingSpec,
    flow_id: &str,
) -> OAuthStatusResult {
    cleanup_expired_flows();
    let flows = OAUTH_FLOWS.read();
    match flows.get(flow_id).filter(|f| std::ptr::eq(f.spec, spec)) {
        None => OAuthStatusResult::NotFound,
        Some(flow) => match &flow.flow_state {
            OAuthFlowState::Pending | OAuthFlowState::InProgress => OAuthStatusResult::InProgress,
            OAuthFlowState::Completed(completion) => OAuthStatusResult::Completed {
                profile_name: completion.auth_profile.name.clone(),
                email: completion.auth_profile.email.clone(),
            },
            OAuthFlowState::Failed(err) => OAuthStatusResult::Failed { error: err.clone() },
        },
    }
}

/// Apply a completed OAuth flow: persist the profile, update config, and
/// remove the flow from the in-memory store.
pub(crate) fn apply_oauth_flow(
    spec: &'static OAuthOnboardingSpec,
    flow_id: &str,
    state_dir: &Path,
    cfg: &mut Value,
) -> Result<OAuthApplyResult, String> {
    cleanup_expired_flows();
    let flow = get_flow(flow_id)
        .filter(|f| std::ptr::eq(f.spec, spec))
        .ok_or_else(|| "Unknown or expired OAuth flow".to_string())?;

    let completion = match &flow.flow_state {
        OAuthFlowState::Completed(completion) => completion.as_ref().clone(),
        OAuthFlowState::Pending | OAuthFlowState::InProgress => {
            return Err(format!(
                "{} sign-in is still pending",
                flow.spec.display_name
            ));
        }
        OAuthFlowState::Failed(err) => return Err(err.clone()),
    };

    let profile_id = upsert_oauth_profile(state_dir, completion.auth_profile)?;
    (flow.spec.write_provider_config)(cfg, &profile_id, &completion.client_id);
    validate_and_persist_config(cfg)?;
    remove_flow(flow_id);

    Ok(OAuthApplyResult { profile_id })
}

// ---------------------------------------------------------------------------
// CLI OAuth flow
// ---------------------------------------------------------------------------

/// Persist a CLI OAuth completion: upsert the profile, write provider config,
/// validate and save.  Returns the profile ID on success.
pub(crate) fn persist_cli_oauth(
    spec: &'static OAuthOnboardingSpec,
    completion: OAuthCompletion,
    state_dir: &Path,
    config: &mut Value,
) -> Result<String, String> {
    let profile_id = upsert_oauth_profile(state_dir, completion.auth_profile)?;
    (spec.write_provider_config)(config, &profile_id, &completion.client_id);
    validate_and_persist_config(config)?;
    Ok(profile_id)
}

/// Run the CLI OAuth flow with the default 300-second timeout.
pub(crate) async fn run_cli_oauth(
    spec: &'static OAuthOnboardingSpec,
    cfg: &Value,
    client_id_override: Option<String>,
    client_secret_override: Option<String>,
) -> Result<OAuthCompletion, String> {
    run_cli_oauth_with_timeout(
        spec,
        cfg,
        client_id_override,
        client_secret_override,
        Duration::from_secs(300),
    )
    .await
}

/// Core CLI OAuth flow: binds a local listener, prints the auth URL, waits
/// for the identity-provider callback, exchanges the code, and returns the
/// completion.
async fn run_cli_oauth_with_timeout(
    spec: &'static OAuthOnboardingSpec,
    cfg: &Value,
    client_id_override: Option<String>,
    client_secret_override: Option<String>,
    timeout: Duration,
) -> Result<OAuthCompletion, String> {
    require_encrypted_profile_store(spec)?;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|err| format!("failed to bind local OAuth callback listener: {err}"))?;
    let bind_addr = listener
        .local_addr()
        .map_err(|err| format!("failed to determine local OAuth callback port: {err}"))?;
    let redirect_uri = format!("http://127.0.0.1:{}/auth/callback", bind_addr.port());

    let provider_config = (spec.resolve_provider_config)(
        cfg,
        client_id_override,
        client_secret_override,
        redirect_uri.clone(),
        &crate::paths::resolve_state_dir(),
    )?;

    let parsed_redirect = url::Url::parse(&provider_config.redirect_uri).map_err(|err| {
        format!(
            "invalid {} OAuth redirect URI: {err}",
            spec.idp_display_name
        )
    })?;
    let host = parsed_redirect.host_str().unwrap_or_default();
    if host != "127.0.0.1" && host != "localhost" {
        return Err(format!(
            "CLI {} sign-in requires a loopback redirect URI; use Control UI sign-in{}.",
            spec.idp_display_name, spec.cli_loopback_error_extra,
        ));
    }

    let path = parsed_redirect.path().to_string();
    let state = format!("{}-cli-{}", spec.provider_label, uuid::Uuid::new_v4());
    let (auth_url, verifier) =
        generate_auth_url(&provider_config, &state).map_err(|err| err.to_string())?;

    println!();
    println!(
        "Open this URL to sign in with {} for {}:",
        spec.idp_display_name, spec.display_name
    );
    println!("{auth_url}");
    println!();
    println!("Waiting for OAuth callback on {}{} ...", bind_addr, path);

    let provider_config_for_server = provider_config.clone();
    let state_for_server = state.clone();
    let verifier_for_server = verifier.clone();
    let path_for_server = path.clone();
    let (result_tx, result_rx) = tokio::sync::oneshot::channel();
    let result_tx: CliOAuthSender = std::sync::Arc::new(std::sync::Mutex::new(Some(result_tx)));
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
            spec: &'static OAuthOnboardingSpec,
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
                    &format!("Still waiting for {} sign-in", state.spec.display_name),
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
                        state.spec,
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
                    &format!("{} sign-in complete", state.spec.display_name),
                    "You can return to Carapace and finish setup.",
                )),
                Err(err) => Html(callback_html(
                    &format!("{} sign-in failed", state.spec.display_name),
                    &err,
                )),
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
                spec,
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
        Ok(Err(_)) => Err(format!(
            "{} OAuth callback channel closed unexpectedly",
            spec.display_name,
        )),
        Err(_) => Err(format!(
            "Timed out waiting for {} sign-in callback",
            spec.display_name,
        )),
    };

    let _ = shutdown_tx.send(true);
    let _ = tokio::time::timeout(Duration::from_secs(5), server_task).await;

    result
}

/// Complete a CLI OAuth callback: exchange the authorization code for tokens,
/// fetch user info, and build the completion via the spec's profile builder.
async fn complete_cli_oauth_callback(
    spec: &'static OAuthOnboardingSpec,
    provider_config: &OAuthProviderConfig,
    code_verifier: &str,
    code: Option<&str>,
) -> Result<OAuthCompletion, String> {
    let code = code.unwrap_or_default();
    if code.trim().is_empty() {
        return Err("OAuth callback missing authorization code".to_string());
    }

    let tokens = exchange_code(provider_config, code.trim(), code_verifier)
        .await
        .map_err(|err| err.to_string())?;
    let userinfo = fetch_user_info(spec.oauth_provider, provider_config, &tokens.access_token)
        .await
        .map_err(|err| err.to_string())?;

    Ok(OAuthCompletion {
        client_id: provider_config.client_id.clone(),
        auth_profile: (spec.build_auth_profile)(tokens, provider_config, userinfo),
    })
}

/// Returns `true` if the returned OAuth state parameter matches the expected value.
pub(crate) fn cli_oauth_callback_matches_expected_state(
    expected_state: &str,
    returned_state: Option<&str>,
) -> bool {
    returned_state
        .map(str::trim)
        .filter(|value| !value.is_empty())
        == Some(expected_state)
}
