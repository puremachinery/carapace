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

use crate::auth::profiles::{
    exchange_code, fetch_user_info, generate_auth_url, profile_store_encryption_enabled_from_env,
    AuthProfile, OAuthProvider, OAuthProviderConfig, OAuthTokens, ProfileStore, UserInfo,
};
use crate::server::ws::{map_validation_issues, persist_config_file};

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

    /// Maximum number of concurrent pending flows per provider.
    pub max_pending_flows: usize,
    /// Time-to-live for a pending flow, in seconds.
    pub flow_ttl_secs: u64,

    /// Resolve provider-specific OAuth configuration from the merged config
    /// value, optional client-id/secret overrides, the redirect URI, and the
    /// state directory.
    pub resolve_provider_config: fn(
        cfg: &Value,
        client_id_override: Option<String>,
        client_secret_override: Option<String>,
        redirect_uri: String,
        state_dir: &Path,
    ) -> Result<OAuthProviderConfig, String>,

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
    Pending,
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
    pub client_id: String,
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
    let store =
        ProfileStore::from_env(state_dir.to_path_buf()).map_err(|err| err.to_string())?;
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
    flows.retain(|_, f| {
        !std::ptr::eq(f.spec, spec) || f.created_at_ms >= cutoff
    });

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

/// Look up a pending flow by its OAuth `state` parameter, scoped to a spec.
pub(crate) fn find_flow_by_state(
    spec: &'static OAuthOnboardingSpec,
    state_param: &str,
) -> Option<PendingOAuthFlow> {
    OAUTH_FLOWS
        .read()
        .values()
        .find(|f| std::ptr::eq(f.spec, spec) && f.state == state_param)
        .cloned()
}

/// Look up a flow by its unique flow ID.
pub(crate) fn get_flow(flow_id: &str) -> Option<PendingOAuthFlow> {
    OAUTH_FLOWS.read().get(flow_id).cloned()
}

/// Mutate a flow's state in place.
pub(crate) fn update_flow_state(flow_id: &str, new_state: OAuthFlowState) {
    if let Some(flow) = OAUTH_FLOWS.write().get_mut(flow_id) {
        flow.flow_state = new_state;
    }
}

/// Remove all flows whose TTL has elapsed.
pub(crate) fn cleanup_expired_flows() {
    let now = now_ms();
    OAUTH_FLOWS.write().retain(|_, flow| {
        now.saturating_sub(flow.created_at_ms) < flow.spec.flow_ttl_secs * 1000
    });
}

/// Remove a flow from the shared store by ID.
fn remove_flow(flow_id: &str) {
    OAUTH_FLOWS.write().remove(flow_id);
}

// ---------------------------------------------------------------------------
// Flow engine — Control-facing functions
// ---------------------------------------------------------------------------

/// Checks that CARAPACE_CONFIG_PASSWORD is set so profile tokens and OAuth
/// client secrets are encrypted at rest.
pub(crate) fn require_encrypted_profile_store(
    spec: &OAuthOnboardingSpec,
) -> Result<(), String> {
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
            .ok_or_else(|| {
                format!("Unknown or expired {} OAuth flow", spec.display_name)
            })?;

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
                flow.created_at_ms = now_ms();
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
            &provider_config,
            Err(format_oauth_provider_error(err, error_description)),
        );
    }

    // Extract authorization code.
    let code = match code.map(str::trim).filter(|value| !value.is_empty()) {
        Some(code) => code,
        None => {
            return finish_oauth_flow(
                &flow_id,
                &provider_config,
                Err("Missing OAuth authorization code".to_string()),
            );
        }
    };

    // Exchange code for tokens and fetch user info.
    let result = async {
        let tokens = exchange_code(&provider_config, code, &verifier)
            .await
            .map_err(|err| err.to_string())?;
        let userinfo = fetch_user_info(
            spec.oauth_provider,
            &provider_config,
            &tokens.access_token,
        )
        .await
        .map_err(|err| err.to_string())?;
        Ok::<OAuthCompletion, String>(OAuthCompletion {
            client_id: provider_config.client_id.clone(),
            auth_profile: (spec.build_auth_profile)(tokens, &provider_config, userinfo),
        })
    }
    .await;

    finish_oauth_flow(&flow_id, &provider_config, result)
}

/// Transition a flow to its terminal state (Completed or Failed).
///
/// Mirrors the idempotency behaviour of the original per-provider
/// `finish_control_*_oauth_flow` helpers: if the flow has already reached a
/// terminal state, that state is returned without modification.
fn finish_oauth_flow(
    flow_id: &str,
    _provider_config: &OAuthProviderConfig,
    result: Result<OAuthCompletion, String>,
) -> Result<(), String> {
    let mut flows = OAUTH_FLOWS.write();
    if let Some(flow) = flows.get_mut(flow_id) {
        match &flow.flow_state {
            OAuthFlowState::Completed(_) => return Ok(()),
            OAuthFlowState::Failed(err) => return Err(err.clone()),
            OAuthFlowState::Pending | OAuthFlowState::InProgress => {
                flow.flow_state = match &result {
                    Ok(completion) => {
                        OAuthFlowState::Completed(Box::new(completion.clone()))
                    }
                    Err(err) => OAuthFlowState::Failed(err.clone()),
                };
            }
        }
    }
    result.map(|_| ())
}

/// Poll the status of an OAuth flow by its flow ID.
pub(crate) fn oauth_flow_status(flow_id: &str) -> OAuthStatusResult {
    cleanup_expired_flows();
    let flows = OAUTH_FLOWS.read();
    match flows.get(flow_id) {
        None => OAuthStatusResult::NotFound,
        Some(flow) => match &flow.flow_state {
            OAuthFlowState::Pending | OAuthFlowState::InProgress => {
                OAuthStatusResult::InProgress
            }
            OAuthFlowState::Completed(completion) => OAuthStatusResult::Completed {
                profile_name: completion.auth_profile.name.clone(),
                email: completion.auth_profile.email.clone(),
            },
            OAuthFlowState::Failed(err) => OAuthStatusResult::Failed {
                error: err.clone(),
            },
        },
    }
}

/// Apply a completed OAuth flow: persist the profile, update config, and
/// remove the flow from the in-memory store.
pub(crate) fn apply_oauth_flow(
    flow_id: &str,
    state_dir: &Path,
    cfg: &mut Value,
) -> Result<OAuthApplyResult, String> {
    let flow = get_flow(flow_id)
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

    Ok(OAuthApplyResult {
        profile_id,
        client_id: completion.client_id,
    })
}
