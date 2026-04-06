//! Shared types and helpers for OAuth onboarding flows.
//!
//! This module extracts the common structure shared by the Codex (OpenAI) and
//! Gemini (Google) OAuth onboarding implementations. Provider-specific behaviour
//! is captured via function pointers in [`OAuthOnboardingSpec`]; everything else
//! (flow state, result types, HTML helpers, config persistence) lives here once.

use serde_json::Value;
use std::path::Path;

use crate::auth::profiles::{
    AuthProfile, OAuthProvider, OAuthProviderConfig, OAuthTokens, UserInfo,
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
