//! Shared provider onboarding contract for `cara setup` and future Control UI
//! parity work.
//!
//! Owning abstraction:
//! - provider-specific setup flows write provider-owned config/auth-profile
//!   state and return live observations through [`SetupFlowResult`]
//! - [`assess_provider_setup`] is the only layer that converts persisted config
//!   plus observed checks into final ready/partial/invalid status
//! - remediation text must be a concrete next step an operator can take without
//!   reverse-engineering the code path
//!
//! Write targets that upcoming guided-provider work must preserve:
//! - Bedrock: `bedrock.region`, `bedrock.accessKeyId`,
//!   `bedrock.secretAccessKey`, optional `bedrock.sessionToken`, and
//!   `agents.defaults.model`
//! - Vertex: `vertex.projectId`, `vertex.location`, and `agents.defaults.model`;
//!   `vertex.model` is required when the route is `vertex:default` and optional
//!   when `agents.defaults.model` names an explicit Vertex model
//!
//! Status contract:
//! - "written" means the flow persisted its config/auth-profile changes and can
//!   hand them to [`assess_provider_setup`]
//! - [`SetupAssessmentStatus::Ready`] requires no failing checks and at least
//!   one validation pass
//! - [`SetupAssessmentStatus::Partial`] means config was written but live
//!   validation was skipped or unavailable
//! - [`SetupAssessmentStatus::Invalid`] means any requirement or validation
//!   failed and remediation must be surfaced directly

use std::path::Path;

use serde::Serialize;
use serde_json::Value;
use strum::IntoEnumIterator;

use crate::agent;
use crate::auth::profiles::{
    AuthProfileCredentialKind, AuthProfileSummary, OAuthProvider, ProfileStore,
};
use crate::config::secrets::is_encrypted;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, strum::EnumIter)]
pub enum SetupProvider {
    #[serde(rename = "anthropic")]
    Anthropic,
    #[serde(rename = "codex")]
    Codex,
    #[serde(rename = "openai")]
    OpenAi,
    #[serde(rename = "ollama")]
    Ollama,
    #[serde(rename = "gemini")]
    Gemini,
    #[serde(rename = "vertex")]
    Vertex,
    #[serde(rename = "venice")]
    Venice,
    #[serde(rename = "bedrock")]
    Bedrock,
}

impl SetupProvider {
    pub fn all() -> &'static [Self] {
        static PROVIDERS: std::sync::LazyLock<Vec<SetupProvider>> =
            std::sync::LazyLock::new(|| SetupProvider::iter().collect());
        PROVIDERS.as_slice()
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Anthropic => "Anthropic",
            Self::Codex => "Codex",
            Self::OpenAi => "OpenAI",
            Self::Ollama => "Ollama",
            Self::Gemini => "Gemini",
            Self::Vertex => "Vertex",
            Self::Venice => "Venice",
            Self::Bedrock => "Bedrock",
        }
    }

    pub fn prompt_key(self) -> &'static str {
        match self {
            Self::Anthropic => "anthropic",
            Self::Codex => "codex",
            Self::OpenAi => "openai",
            Self::Ollama => "ollama",
            Self::Gemini => "gemini",
            Self::Vertex => "vertex",
            Self::Venice => "venice",
            Self::Bedrock => "bedrock",
        }
    }

    pub fn default_model(self) -> &'static str {
        match self {
            Self::Anthropic => "anthropic:claude-sonnet-4-20250514",
            Self::Codex => "codex:default",
            Self::OpenAi => "openai:gpt-4o",
            Self::Ollama => "ollama:llama3",
            Self::Gemini => "gemini:gemini-2.0-flash",
            Self::Vertex => "vertex:default",
            Self::Venice => "venice:llama-3.3-70b",
            Self::Bedrock => "bedrock:anthropic.claude-3-5-sonnet-20240620-v1:0",
        }
    }

    pub fn setup_command(self, auth_mode: Option<SetupAuthMode>) -> Option<String> {
        match (self, auth_mode) {
            (Self::Anthropic, Some(SetupAuthMode::SetupToken)) => {
                Some("cara setup --force --provider anthropic --auth-mode setup-token".to_string())
            }
            (Self::Anthropic, Some(SetupAuthMode::ApiKey)) => {
                Some("cara setup --force --provider anthropic --auth-mode api-key".to_string())
            }
            (Self::Gemini, Some(SetupAuthMode::OAuth)) => {
                Some("cara setup --force --provider gemini --auth-mode oauth".to_string())
            }
            (Self::Gemini, Some(SetupAuthMode::ApiKey)) => {
                Some("cara setup --force --provider gemini --auth-mode api-key".to_string())
            }
            _ => Some(format!(
                "cara setup --force --provider {}",
                self.prompt_key()
            )),
        }
    }

    pub fn supported_auth_modes(self) -> &'static [SetupAuthMode] {
        const NO_AUTH_MODES: [SetupAuthMode; 0] = [];
        const ANTHROPIC_AUTH_MODES: [SetupAuthMode; 2] =
            [SetupAuthMode::ApiKey, SetupAuthMode::SetupToken];
        const CODEX_AUTH_MODES: [SetupAuthMode; 1] = [SetupAuthMode::OAuth];
        const API_KEY_AUTH_MODES: [SetupAuthMode; 1] = [SetupAuthMode::ApiKey];
        const OLLAMA_AUTH_MODES: [SetupAuthMode; 1] = [SetupAuthMode::BaseUrl];
        const GEMINI_AUTH_MODES: [SetupAuthMode; 2] = [SetupAuthMode::OAuth, SetupAuthMode::ApiKey];
        const BEDROCK_AUTH_MODES: [SetupAuthMode; 1] = [SetupAuthMode::StaticCredentials];

        match self {
            Self::Anthropic => &ANTHROPIC_AUTH_MODES,
            Self::Codex => &CODEX_AUTH_MODES,
            Self::OpenAi => &API_KEY_AUTH_MODES,
            Self::Ollama => &OLLAMA_AUTH_MODES,
            Self::Gemini => &GEMINI_AUTH_MODES,
            // Vertex setup is currently CLI-first and credential-source-agnostic
            // (ADC vs service account), so the shared status API exposes guidance
            // via CLI entrypoints rather than a misleading auth-mode enum value.
            Self::Vertex => &NO_AUTH_MODES,
            Self::Venice => &API_KEY_AUTH_MODES,
            Self::Bedrock => &BEDROCK_AUTH_MODES,
        }
    }

    pub fn is_configured(self, cfg: &Value) -> bool {
        match self {
            Self::Anthropic => {
                config_string(cfg, &["anthropic", "apiKey"]).is_some()
                    || config_string(cfg, &["anthropic", "authProfile"]).is_some()
                    || config_string(cfg, &["anthropic", "baseUrl"]).is_some()
            }
            Self::Codex => config_string(cfg, &["codex", "authProfile"]).is_some(),
            Self::OpenAi => {
                config_string(cfg, &["openai", "apiKey"]).is_some()
                    || config_string(cfg, &["openai", "baseUrl"]).is_some()
            }
            Self::Ollama => {
                config_string(cfg, &["providers", "ollama", "baseUrl"]).is_some()
                    || config_string(cfg, &["providers", "ollama", "apiKey"]).is_some()
            }
            Self::Gemini => {
                config_string(cfg, &["google", "authProfile"]).is_some()
                    || config_string(cfg, &["google", "apiKey"]).is_some()
                    || config_string(cfg, &["google", "baseUrl"]).is_some()
            }
            Self::Vertex => {
                config_string(cfg, &["vertex", "projectId"]).is_some()
                    || config_string(cfg, &["vertex", "location"]).is_some()
            }
            Self::Venice => {
                config_string(cfg, &["venice", "apiKey"]).is_some()
                    || config_string(cfg, &["venice", "baseUrl"]).is_some()
            }
            Self::Bedrock => {
                config_string(cfg, &["bedrock", "region"]).is_some()
                    || config_string(cfg, &["bedrock", "accessKeyId"]).is_some()
                    || config_string(cfg, &["bedrock", "secretAccessKey"]).is_some()
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum SetupAuthMode {
    #[serde(rename = "apiKey")]
    ApiKey,
    #[serde(rename = "setupToken")]
    SetupToken,
    #[serde(rename = "oauth")]
    OAuth,
    #[serde(rename = "staticCredentials")]
    StaticCredentials,
    #[serde(rename = "baseUrl")]
    BaseUrl,
}

impl SetupAuthMode {
    pub fn label(self) -> &'static str {
        match self {
            Self::ApiKey => "API key",
            Self::SetupToken => "setup token",
            Self::OAuth => "OAuth sign-in",
            Self::StaticCredentials => "static credentials",
            Self::BaseUrl => "base URL",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SetupCheckStatus {
    Pass,
    Fail,
    Skip,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SetupCheckKind {
    Requirement,
    Validation,
}

/// Internal setup-to-control diagnostic code.
///
/// These codes are stamped at the source when a setup check's browser-visible
/// projection needs an explicit control-owned message instead of relying on
/// generic status/kind fallback.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetupCheckCode {
    /// Config points at an auth profile ID for this provider.
    AuthProfileConfigured,
    /// Config does not contain an auth profile ID for this provider.
    AuthProfileNotConfigured,
    /// The referenced auth profile loaded successfully from the profile store.
    AuthProfileLoaded,
    /// The referenced auth profile belongs to a different provider.
    AuthProfileWrongProvider,
    /// The referenced auth profile uses the wrong credential kind.
    AuthProfileWrongCredentialType,
    /// The referenced token profile stayed encrypted even though a password is present.
    AuthProfileTokenDecryptFailed,
    /// The referenced token profile has no usable token material.
    AuthProfileTokenMissing,
    /// Config references an auth profile ID that is not present in the store.
    AuthProfileMissing,
    /// The encrypted profile store could not be read.
    AuthProfileStoreReadFailed,
    /// A provider-specific local validation check failed.
    LocalValidationFailed,
}

/// Browser-visible projection policy for a setup check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetupCheckProjection {
    /// Control should emit a generic status/kind-derived detail message.
    GenericStatus,
    /// Control should map the check through an explicit internal code.
    Code(SetupCheckCode),
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SetupCheck {
    pub name: String,
    pub status: SetupCheckStatus,
    pub kind: SetupCheckKind,
    pub detail: String,
    pub remediation: Option<String>,
    /// Internal setup-to-control projection policy.
    ///
    /// This is deliberately omitted from `SetupCheck` JSON because browser-
    /// visible responses are emitted through control-owned DTOs instead.
    #[serde(skip)]
    pub projection: SetupCheckProjection,
}

fn projection_from(code: Option<SetupCheckCode>) -> SetupCheckProjection {
    match code {
        Some(c) => SetupCheckProjection::Code(c),
        None => SetupCheckProjection::GenericStatus,
    }
}

impl SetupCheck {
    fn new(
        name: impl Into<String>,
        status: SetupCheckStatus,
        kind: SetupCheckKind,
        detail: impl Into<String>,
        remediation: Option<String>,
        projection: SetupCheckProjection,
    ) -> Self {
        Self {
            name: name.into(),
            status,
            kind,
            detail: detail.into(),
            remediation,
            projection,
        }
    }

    pub fn pass(
        name: impl Into<String>,
        detail: impl Into<String>,
        code: Option<SetupCheckCode>,
    ) -> Self {
        Self::new(
            name,
            SetupCheckStatus::Pass,
            SetupCheckKind::Requirement,
            detail,
            None,
            projection_from(code),
        )
    }

    pub fn validation_pass(
        name: impl Into<String>,
        detail: impl Into<String>,
        code: Option<SetupCheckCode>,
    ) -> Self {
        Self::new(
            name,
            SetupCheckStatus::Pass,
            SetupCheckKind::Validation,
            detail,
            None,
            projection_from(code),
        )
    }

    pub fn fail(
        name: impl Into<String>,
        detail: impl Into<String>,
        remediation: impl Into<String>,
        code: Option<SetupCheckCode>,
    ) -> Self {
        Self::new(
            name,
            SetupCheckStatus::Fail,
            SetupCheckKind::Requirement,
            detail,
            Some(remediation.into()),
            projection_from(code),
        )
    }

    pub fn skip(
        name: impl Into<String>,
        detail: impl Into<String>,
        remediation: Option<String>,
        code: Option<SetupCheckCode>,
    ) -> Self {
        Self::new(
            name,
            SetupCheckStatus::Skip,
            SetupCheckKind::Requirement,
            detail,
            remediation,
            projection_from(code),
        )
    }

    pub fn validation_skip(
        name: impl Into<String>,
        detail: impl Into<String>,
        remediation: Option<String>,
        code: Option<SetupCheckCode>,
    ) -> Self {
        Self::new(
            name,
            SetupCheckStatus::Skip,
            SetupCheckKind::Validation,
            detail,
            remediation,
            projection_from(code),
        )
    }

    pub fn validation_fail(
        name: impl Into<String>,
        detail: impl Into<String>,
        remediation: impl Into<String>,
        code: Option<SetupCheckCode>,
    ) -> Self {
        Self::new(
            name,
            SetupCheckStatus::Fail,
            SetupCheckKind::Validation,
            detail,
            Some(remediation.into()),
            projection_from(code),
        )
    }

    #[cfg(test)]
    pub(crate) fn code(&self) -> Option<SetupCheckCode> {
        match self.projection {
            SetupCheckProjection::GenericStatus => None,
            SetupCheckProjection::Code(code) => Some(code),
        }
    }
}

/// Provider-specific setup flow output that cannot be reconstructed purely
/// from persisted config.
///
/// Setup flows should record live/provider-side observations here, such as
/// auth exchange success, model access verification, or provider-specific input
/// validation that happened before config was written. Static config presence,
/// env-placeholder resolution, and final status classification belong in
/// [`assess_provider_setup`].
#[derive(Debug, Clone, Default)]
pub struct SetupFlowResult {
    pub observed_checks: Vec<SetupCheck>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SetupAssessmentStatus {
    Ready,
    Partial,
    Invalid,
}

impl SetupAssessmentStatus {
    pub fn label(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::Partial => "partial",
            Self::Invalid => "invalid",
        }
    }
}

#[derive(Debug, Clone)]
pub struct SetupAssessment {
    pub provider: SetupProvider,
    pub auth_mode: Option<SetupAuthMode>,
    pub status: SetupAssessmentStatus,
    pub summary: String,
    pub checks: Vec<SetupCheck>,
    pub profile_name: Option<String>,
    pub email: Option<String>,
}

impl SetupAssessment {
    pub fn recommended_remediation(&self) -> Option<&str> {
        self.checks
            .iter()
            .find(|check| check.status == SetupCheckStatus::Fail)
            .and_then(|check| check.remediation.as_deref())
            .or_else(|| {
                self.checks
                    .iter()
                    .find(|check| {
                        check.status == SetupCheckStatus::Skip && check.remediation.is_some()
                    })
                    .and_then(|check| check.remediation.as_deref())
            })
    }
}

pub fn assess_provider_setup(
    cfg: &Value,
    state_dir: &Path,
    provider: SetupProvider,
    observed_validations: Vec<SetupCheck>,
) -> SetupAssessment {
    let auth_mode = detect_auth_mode(cfg, provider);
    let setup_command = provider.setup_command(auth_mode);
    let mut checks = vec![model_route_check(cfg, provider, setup_command.as_deref())];
    let mut profile_name = None;
    let mut email = None;

    match provider {
        SetupProvider::Anthropic => {
            let api_key = config_string(cfg, &["anthropic", "apiKey"]);
            let profile_id = config_string(cfg, &["anthropic", "authProfile"]);
            match (api_key, profile_id) {
                (Some(_), Some(profile_id)) => {
                    checks.push(SetupCheck::skip(
                        "Anthropic auth path",
                        format!(
                            "both `anthropic.apiKey` and `anthropic.authProfile` (`{profile_id}`) are configured; runtime will prefer `anthropic.apiKey`"
                        ),
                        Some(
                            "remove one of `anthropic.apiKey` or `anthropic.authProfile` to keep the Anthropic auth path explicit"
                                .to_string(),
                        ),
                        None,
                    ));
                    checks.push(configured_value_check(
                        cfg,
                        &["anthropic", "apiKey"],
                        "Anthropic API key",
                        provider
                            .setup_command(Some(SetupAuthMode::ApiKey))
                            .as_deref(),
                    ));
                }
                (Some(_), None) => {
                    checks.push(configured_value_check(
                        cfg,
                        &["anthropic", "apiKey"],
                        "Anthropic API key",
                        provider
                            .setup_command(Some(SetupAuthMode::ApiKey))
                            .as_deref(),
                    ));
                }
                (None, Some(profile_id)) => {
                    checks.push(auth_profiles_enabled_check(cfg, setup_command.as_deref()));
                    checks.push(auth_profile_id_check(
                        cfg,
                        &["anthropic", "authProfile"],
                        "Anthropic auth profile",
                        provider
                            .setup_command(Some(SetupAuthMode::SetupToken))
                            .as_deref(),
                    ));
                    let password_present = profile_store_password_present();
                    checks.push(config_password_check(
                        provider
                            .setup_command(Some(SetupAuthMode::SetupToken))
                            .as_deref(),
                    ));
                    if password_present {
                        let (check, summary) = auth_profile_summary_check(
                            state_dir,
                            &profile_id,
                            OAuthProvider::Anthropic,
                            AuthProfileCredentialKind::Token,
                            "Anthropic auth profile",
                            provider
                                .setup_command(Some(SetupAuthMode::SetupToken))
                                .as_deref(),
                        );
                        if let Some(summary) = summary {
                            profile_name = Some(summary.name.clone());
                            email = summary.email.clone();
                        }
                        checks.push(check);
                    }
                }
                (None, None) => checks.push(SetupCheck::fail(
                    "Anthropic credential",
                    "Neither `anthropic.apiKey` nor `anthropic.authProfile` is configured",
                    setup_follow_up(provider_setup_follow_up(
                        setup_command.as_deref(),
                        "to choose Anthropic API-key or setup-token auth".to_string(),
                        "write `anthropic.apiKey` or `anthropic.authProfile` into config"
                            .to_string(),
                    )),
                    None,
                )),
            }
        }
        SetupProvider::Codex => {
            checks.push(auth_profiles_enabled_check(cfg, setup_command.as_deref()));
            let profile_check = auth_profile_id_check(
                cfg,
                &["codex", "authProfile"],
                "OpenAI auth profile",
                setup_command.as_deref(),
            );
            let profile_id = config_string(cfg, &["codex", "authProfile"]);
            checks.push(profile_check);
            let password_present = profile_store_password_present();
            checks.push(config_password_check(setup_command.as_deref()));
            if password_present {
                if let Some(profile_id) = profile_id {
                    let (check, summary) = auth_profile_summary_check(
                        state_dir,
                        &profile_id,
                        OAuthProvider::OpenAI,
                        AuthProfileCredentialKind::OAuth,
                        "OpenAI auth profile",
                        setup_command.as_deref(),
                    );
                    if let Some(summary) = summary {
                        profile_name = Some(summary.name.clone());
                        email = summary.email.clone();
                    }
                    checks.push(check);
                }
            }
        }
        SetupProvider::OpenAi => {
            checks.push(configured_value_check(
                cfg,
                &["openai", "apiKey"],
                "OpenAI API key",
                setup_command.as_deref(),
            ));
        }
        SetupProvider::Ollama => {
            checks.push(configured_value_check(
                cfg,
                &["providers", "ollama", "baseUrl"],
                "Ollama base URL",
                setup_command.as_deref(),
            ));
            checks.push(base_url_validation_check(
                cfg,
                &["providers", "ollama", "baseUrl"],
                "Ollama base URL validation",
                setup_command.as_deref(),
                |url| {
                    agent::ollama::OllamaProvider::new()
                        .and_then(|provider| provider.with_base_url(url.to_string()))
                        .map_err(|err| err.to_string())
                        .map(|_| ())
                },
            ));
            checks.push(optional_configured_value_check(
                cfg,
                &["providers", "ollama", "apiKey"],
                "Ollama API key",
            ));
        }
        SetupProvider::Gemini => match auth_mode {
            Some(SetupAuthMode::OAuth) => {
                checks.push(auth_profiles_enabled_check(cfg, setup_command.as_deref()));
                let profile_check = auth_profile_id_check(
                    cfg,
                    &["google", "authProfile"],
                    "Gemini auth profile",
                    setup_command.as_deref(),
                );
                let profile_id = config_string(cfg, &["google", "authProfile"]);
                checks.push(profile_check);
                let password_present = profile_store_password_present();
                checks.push(config_password_check(setup_command.as_deref()));
                if password_present {
                    if let Some(profile_id) = profile_id {
                        let (check, summary) = auth_profile_summary_check(
                            state_dir,
                            &profile_id,
                            OAuthProvider::Google,
                            AuthProfileCredentialKind::OAuth,
                            "Gemini auth profile",
                            setup_command.as_deref(),
                        );
                        if let Some(summary) = summary {
                            profile_name = Some(summary.name.clone());
                            email = summary.email.clone();
                        }
                        checks.push(check);
                    }
                }
                if config_string(cfg, &["google", "baseUrl"]).is_some() {
                    checks.push(base_url_validation_check(
                        cfg,
                        &["google", "baseUrl"],
                        "Gemini base URL validation",
                        setup_command.as_deref(),
                        |url| {
                            crate::onboarding::gemini::validate_gemini_base_url_input(Some(url))
                                .map_err(|err| err.to_string())
                        },
                    ));
                }
            }
            _ => {
                checks.push(configured_value_check(
                    cfg,
                    &["google", "apiKey"],
                    "Gemini API key",
                    provider
                        .setup_command(Some(SetupAuthMode::ApiKey))
                        .as_deref(),
                ));
                if config_string(cfg, &["google", "baseUrl"]).is_some() {
                    checks.push(base_url_validation_check(
                        cfg,
                        &["google", "baseUrl"],
                        "Gemini base URL validation",
                        provider
                            .setup_command(Some(SetupAuthMode::ApiKey))
                            .as_deref(),
                        |url| {
                            crate::onboarding::gemini::validate_gemini_base_url_input(Some(url))
                                .map_err(|err| err.to_string())
                        },
                    ));
                }
            }
        },
        SetupProvider::Vertex => {
            checks.push(configured_value_check(
                cfg,
                &["vertex", "projectId"],
                "Vertex project ID",
                setup_command.as_deref(),
            ));
            checks.push(configured_value_check(
                cfg,
                &["vertex", "location"],
                "Vertex location",
                setup_command.as_deref(),
            ));
            if vertex_route_requires_default_model(cfg) {
                checks.push(vertex_default_model_check(cfg, setup_command.as_deref()));
            } else {
                checks.push(optional_configured_value_check(
                    cfg,
                    &["vertex", "model"],
                    "Vertex default model",
                ));
            }
        }
        SetupProvider::Venice => {
            checks.push(configured_value_check(
                cfg,
                &["venice", "apiKey"],
                "Venice API key",
                setup_command.as_deref(),
            ));
            if config_string(cfg, &["venice", "baseUrl"]).is_some() {
                checks.push(base_url_validation_check(
                    cfg,
                    &["venice", "baseUrl"],
                    "Venice base URL validation",
                    setup_command.as_deref(),
                    |url| {
                        agent::venice::VeniceProvider::new("test-key".to_string())
                            .and_then(|provider| provider.with_base_url(url.to_string()))
                            .map_err(|err| err.to_string())
                            .map(|_| ())
                    },
                ));
            }
        }
        SetupProvider::Bedrock => {
            checks.push(configured_value_check(
                cfg,
                &["bedrock", "region"],
                "AWS Bedrock region",
                setup_command.as_deref(),
            ));
            checks.push(configured_value_check(
                cfg,
                &["bedrock", "accessKeyId"],
                "AWS access key ID",
                setup_command.as_deref(),
            ));
            checks.push(configured_value_check(
                cfg,
                &["bedrock", "secretAccessKey"],
                "AWS secret access key",
                setup_command.as_deref(),
            ));
            checks.push(optional_configured_value_check(
                cfg,
                &["bedrock", "sessionToken"],
                "AWS session token",
            ));
        }
    }

    checks.extend(observed_validations);

    let has_fail = checks
        .iter()
        .any(|check| check.status == SetupCheckStatus::Fail);
    let has_validation_check = checks
        .iter()
        .any(|check| check.kind == SetupCheckKind::Validation);
    let has_validation_pass = checks.iter().any(|check| {
        check.status == SetupCheckStatus::Pass && check.kind == SetupCheckKind::Validation
    });
    if !has_fail && !has_validation_check {
        checks.push(SetupCheck::validation_skip(
            "Live provider validation",
            "setup completed without a live provider-side validation step",
            None,
            None,
        ));
    }

    let status = if has_fail {
        SetupAssessmentStatus::Invalid
    } else if has_validation_pass {
        SetupAssessmentStatus::Ready
    } else {
        SetupAssessmentStatus::Partial
    };

    let summary = match status {
        SetupAssessmentStatus::Ready => {
            format!("{} setup looks ready for verification.", provider.label())
        }
        SetupAssessmentStatus::Partial => format!(
            "{} setup is written, but some live validation was skipped or not available.",
            provider.label()
        ),
        SetupAssessmentStatus::Invalid => {
            format!("{} setup is incomplete or invalid.", provider.label())
        }
    };

    SetupAssessment {
        provider,
        auth_mode,
        status,
        summary,
        checks,
        profile_name,
        email,
    }
}

fn detect_auth_mode(cfg: &Value, provider: SetupProvider) -> Option<SetupAuthMode> {
    match provider {
        SetupProvider::Anthropic => {
            let has_api_key = config_string(cfg, &["anthropic", "apiKey"]).is_some();
            let has_auth_profile = config_string(cfg, &["anthropic", "authProfile"]).is_some();
            match (has_api_key, has_auth_profile) {
                (true, false) | (true, true) => Some(SetupAuthMode::ApiKey),
                (false, true) => Some(SetupAuthMode::SetupToken),
                _ => None,
            }
        }
        SetupProvider::OpenAi | SetupProvider::Venice => Some(SetupAuthMode::ApiKey),
        SetupProvider::Codex => Some(SetupAuthMode::OAuth),
        SetupProvider::Ollama => Some(SetupAuthMode::BaseUrl),
        SetupProvider::Gemini => {
            if config_string(cfg, &["google", "authProfile"]).is_some() {
                Some(SetupAuthMode::OAuth)
            } else if config_string(cfg, &["google", "apiKey"]).is_some() {
                Some(SetupAuthMode::ApiKey)
            } else {
                None
            }
        }
        SetupProvider::Vertex => None,
        SetupProvider::Bedrock => Some(SetupAuthMode::StaticCredentials),
    }
}

pub(crate) const LOCAL_CHAT_VERIFY_COMMAND: &str = "cara verify --outcome local-chat";

enum SetupFollowUp<'a> {
    Rerun { command: &'a str, action: String },
    Manual { action: String },
}

fn provider_setup_follow_up<'a>(
    setup_command: Option<&'a str>,
    rerun_action: impl Into<String>,
    manual_action: impl Into<String>,
) -> SetupFollowUp<'a> {
    match setup_command {
        Some(command) => SetupFollowUp::Rerun {
            command,
            action: rerun_action.into(),
        },
        None => SetupFollowUp::Manual {
            action: manual_action.into(),
        },
    }
}

fn setup_follow_up(follow_up: SetupFollowUp<'_>) -> String {
    match follow_up {
        SetupFollowUp::Rerun { command, action } => format!("rerun `{command}` {action}"),
        SetupFollowUp::Manual { action } => {
            format!("{action}, then rerun `{LOCAL_CHAT_VERIFY_COMMAND}`")
        }
    }
}

fn default_model_route_follow_up(provider: SetupProvider, setup_command: Option<&str>) -> String {
    let follow_up = match provider {
        SetupProvider::Vertex => provider_setup_follow_up(
            setup_command,
            "to choose `vertex:default` plus `vertex.model`, or an explicit Vertex model such as `vertex:gemini-2.5-flash`".to_string(),
            "set `agents.defaults.model` to `vertex:default` plus `vertex.model`, or to an explicit Vertex model such as `vertex:gemini-2.5-flash`".to_string(),
        ),
        _ => provider_setup_follow_up(
            setup_command,
            format!(
                "to set `agents.defaults.model` to `{}`",
                provider.default_model()
            ),
            format!(
                "set `agents.defaults.model` to `{}`",
                provider.default_model()
            ),
        ),
    };
    setup_follow_up(follow_up)
}

fn vertex_route_requires_default_model(cfg: &Value) -> bool {
    config_string(cfg, &["agents", "defaults", "model"]).is_some_and(|m| m == "vertex:default")
}

fn vertex_default_model_check(cfg: &Value, setup_command: Option<&str>) -> SetupCheck {
    match config_string(cfg, &["vertex", "model"]) {
        Some(value) => {
            let references = env_var_references(&value);
            let missing = missing_env_var_references(&references);
            if !missing.is_empty() {
                let env_vars = format_env_var_list(&missing);
                SetupCheck::fail(
                    "Vertex default model",
                    format!("Vertex default model references {env_vars}, but they are not set"),
                    setup_follow_up(provider_setup_follow_up(
                        setup_command,
                        format!("after setting {env_vars} or rewriting `vertex.model`"),
                        format!("set {env_vars} in the same shell or write `vertex.model` into config"),
                    )),
                    None,
                )
            } else if !references.is_empty() {
                SetupCheck::pass(
                    "Vertex default model",
                    format!(
                        "Vertex default model resolves from {}",
                        format_env_var_list(&references)
                    ),
                    None,
                )
            } else {
                SetupCheck::pass(
                    "Vertex default model",
                    "Vertex default model is written in config",
                    None,
                )
            }
        }
        None => SetupCheck::fail(
            "Vertex default model",
            "`agents.defaults.model` routes to `vertex:default`, but `vertex.model` is not configured",
            setup_follow_up(provider_setup_follow_up(
                setup_command,
                "after setting `vertex.model` or choosing an explicit Vertex model route".to_string(),
                "set `vertex.model`, or switch `agents.defaults.model` to an explicit Vertex model such as `vertex:gemini-2.5-flash`".to_string(),
            )),
            None,
        ),
    }
}

fn model_route_check(
    cfg: &Value,
    provider: SetupProvider,
    setup_command: Option<&str>,
) -> SetupCheck {
    let Some(model) = config_string(cfg, &["agents", "defaults", "model"]) else {
        return SetupCheck::fail(
            "Default model route",
            "`agents.defaults.model` is not configured".to_string(),
            default_model_route_follow_up(provider, setup_command),
            None,
        );
    };
    match model_provider_for_local_chat(&model) {
        Some(actual_provider) if actual_provider == provider => SetupCheck::pass(
            "Default model route",
            format!("`agents.defaults.model` routes to {}", provider.label()),
            None,
        ),
        Some(actual_provider) => SetupCheck::fail(
            "Default model route",
            format!(
                "`agents.defaults.model` currently routes to {}, not {}",
                actual_provider.label(),
                provider.label()
            ),
            default_model_route_follow_up(provider, setup_command),
            None,
        ),
        None => SetupCheck::fail(
            "Default model route",
            format!("`agents.defaults.model` uses an unrecognized provider route: `{model}`"),
            default_model_route_follow_up(provider, setup_command),
            None,
        ),
    }
}

fn auth_profiles_enabled_check(cfg: &Value, setup_command: Option<&str>) -> SetupCheck {
    let enabled = cfg
        .pointer("/auth/profiles/enabled")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if enabled {
        SetupCheck::pass("Auth profiles", "`auth.profiles.enabled` is true", None)
    } else {
        SetupCheck::fail(
            "Auth profiles",
            "`auth.profiles.enabled` is false",
            setup_follow_up(provider_setup_follow_up(
                setup_command,
                "to enable auth profiles",
                "enable `auth.profiles.enabled` in config",
            )),
            None,
        )
    }
}

fn auth_profile_id_check(
    cfg: &Value,
    path: &[&str],
    label: &str,
    setup_command: Option<&str>,
) -> SetupCheck {
    match config_string(cfg, path) {
        Some(profile_id) => SetupCheck::pass(
            label,
            format!("configured profile id: `{profile_id}`"),
            Some(SetupCheckCode::AuthProfileConfigured),
        ),
        None => SetupCheck::fail(
            label,
            format!("{label} is not configured"),
            setup_follow_up(provider_setup_follow_up(
                setup_command,
                "to store a sign-in profile",
                format!("write {label} into config"),
            )),
            Some(SetupCheckCode::AuthProfileNotConfigured),
        ),
    }
}

fn config_password_check(setup_command: Option<&str>) -> SetupCheck {
    if env_var_present("CARAPACE_CONFIG_PASSWORD") {
        SetupCheck::pass(
            "Encrypted profile store",
            "`CARAPACE_CONFIG_PASSWORD` is set in the current shell",
            None,
        )
    } else {
        let remediation = match setup_command {
            Some(command) => format!(
                "set `CARAPACE_CONFIG_PASSWORD` before running Carapace, or rerun `{command}` after exporting it"
            ),
            None => format!(
                "set `CARAPACE_CONFIG_PASSWORD` before running Carapace, then rerun `{LOCAL_CHAT_VERIFY_COMMAND}`"
            ),
        };
        SetupCheck::fail(
            "Encrypted profile store",
            "`CARAPACE_CONFIG_PASSWORD` is not set in the current shell",
            remediation,
            None,
        )
    }
}

fn auth_profile_summary_check(
    state_dir: &Path,
    profile_id: &str,
    expected_provider: OAuthProvider,
    expected_credential_kind: AuthProfileCredentialKind,
    label: &str,
    setup_command: Option<&str>,
) -> (SetupCheck, Option<AuthProfileSummary>) {
    match load_profile_summary(state_dir, profile_id) {
        Ok(Some(loaded)) => {
            if loaded.summary.provider != expected_provider {
                (
                    SetupCheck::fail(
                        label,
                        format!(
                            "stored profile `{profile_id}` belongs to {}, not {}",
                            loaded.summary.provider, expected_provider
                        ),
                        setup_follow_up(provider_setup_follow_up(
                            setup_command,
                            "to store the correct auth profile",
                            format!("write the correct {label} into config"),
                        )),
                        Some(SetupCheckCode::AuthProfileWrongProvider),
                    ),
                    None,
                )
            } else if loaded.summary.credential_kind != expected_credential_kind {
                (
                    SetupCheck::fail(
                        label,
                        format!(
                            "stored profile `{profile_id}` uses {} credentials, not {}",
                            loaded.summary.credential_kind, expected_credential_kind
                        ),
                        setup_follow_up(provider_setup_follow_up(
                            setup_command,
                            "to store the correct auth profile credential type",
                            format!("write the correct {label} into config"),
                        )),
                        Some(SetupCheckCode::AuthProfileWrongCredentialType),
                    ),
                    None,
                )
            } else if loaded.summary.credential_kind == AuthProfileCredentialKind::Token
                && !loaded.summary.token_valid
            {
                let detail = if loaded.token_still_encrypted && profile_store_password_present() {
                    format!(
                        "stored profile `{profile_id}` could not decrypt the stored token; check CARAPACE_CONFIG_PASSWORD"
                    )
                } else {
                    format!("stored profile `{profile_id}` has no usable token")
                };
                (
                    SetupCheck::fail(
                        label,
                        detail,
                        setup_follow_up(provider_setup_follow_up(
                            setup_command,
                            "to store a fresh auth profile token",
                            format!("write a fresh {label} into config"),
                        )),
                        Some(
                            if loaded.token_still_encrypted && profile_store_password_present() {
                                SetupCheckCode::AuthProfileTokenDecryptFailed
                            } else {
                                SetupCheckCode::AuthProfileTokenMissing
                            },
                        ),
                    ),
                    None,
                )
            } else {
                let detail = match loaded.summary.email.as_deref() {
                    Some(email) => format!("loaded `{}` ({email})", loaded.summary.name),
                    None => format!("loaded `{}`", loaded.summary.name),
                };
                (
                    SetupCheck::validation_pass(
                        label,
                        detail,
                        Some(SetupCheckCode::AuthProfileLoaded),
                    ),
                    Some(loaded.summary),
                )
            }
        }
        Ok(None) => (
            SetupCheck::fail(
                label,
                format!("stored profile `{profile_id}` was not found in the profile store"),
                setup_follow_up(provider_setup_follow_up(
                    setup_command,
                    "to store a fresh auth profile",
                    format!("write a fresh {label} into config"),
                )),
                Some(SetupCheckCode::AuthProfileMissing),
            ),
            None,
        ),
        Err(err) => {
            let remediation = match setup_command {
                Some(command) => format!("check the profile store and rerun `{command}`"),
                None => format!("check the profile store and rerun `{LOCAL_CHAT_VERIFY_COMMAND}`"),
            };
            (
                SetupCheck::fail(
                    label,
                    format!("failed to read the profile store: {err}"),
                    remediation,
                    Some(SetupCheckCode::AuthProfileStoreReadFailed),
                ),
                None,
            )
        }
    }
}

struct LoadedProfileSummary {
    summary: AuthProfileSummary,
    token_still_encrypted: bool,
}

/// Result of resolving a config value and its env-var references.
enum ConfigValueResolution {
    /// Value not configured at the given path.
    Missing,
    /// Value references env vars that are not set.
    UnresolvedEnvVars { env_vars: String },
    /// Value is configured and fully resolved.
    Resolved {
        detail: String,
        effective_value: String,
    },
}

/// Resolve a config value at `path`, checking env-var references.
fn resolve_config_value(cfg: &Value, path: &[&str], label: &str) -> ConfigValueResolution {
    let Some(value) = config_string(cfg, path) else {
        return ConfigValueResolution::Missing;
    };
    let references = env_var_references(&value);
    let missing = missing_env_var_references(&references);
    if !missing.is_empty() {
        return ConfigValueResolution::UnresolvedEnvVars {
            env_vars: format_env_var_list(&missing),
        };
    }
    // Env vars are already confirmed present — substitute directly instead of
    // calling effective_config_value (which would re-parse references).
    let (detail, effective) = if !references.is_empty() {
        let resolved = crate::config::substitute_env_in_string(&value)
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or(value);
        (
            format!("{label} resolves from {}", format_env_var_list(&references)),
            resolved,
        )
    } else {
        (format!("{label} is written in config"), value)
    };
    ConfigValueResolution::Resolved {
        detail,
        effective_value: effective,
    }
}

fn configured_value_check(
    cfg: &Value,
    path: &[&str],
    label: &str,
    setup_command: Option<&str>,
) -> SetupCheck {
    match resolve_config_value(cfg, path, label) {
        ConfigValueResolution::Missing => SetupCheck::fail(
            label,
            format!("{label} is not configured"),
            setup_follow_up(provider_setup_follow_up(
                setup_command,
                format!("to configure {label}"),
                format!("write {label} into config"),
            )),
            None,
        ),
        ConfigValueResolution::UnresolvedEnvVars { env_vars } => {
            let remediation = match setup_command {
                Some(command) => format!(
                    "set {env_vars} in the same shell or rerun `{command}` to rewrite the value"
                ),
                None => format!(
                    "set {env_vars} in the same shell or write {label} into config, then rerun `{LOCAL_CHAT_VERIFY_COMMAND}`"
                ),
            };
            SetupCheck::fail(
                label,
                format!("{label} references {env_vars}, but they are not set"),
                remediation,
                None,
            )
        }
        ConfigValueResolution::Resolved { detail, .. } => SetupCheck::pass(label, detail, None),
    }
}

fn optional_configured_value_check(cfg: &Value, path: &[&str], label: &str) -> SetupCheck {
    match resolve_config_value(cfg, path, label) {
        ConfigValueResolution::Missing => {
            SetupCheck::skip(label, format!("{label} is not configured"), None, None)
        }
        ConfigValueResolution::UnresolvedEnvVars { env_vars } => SetupCheck::fail(
            label,
            format!("{label} references {env_vars}, but they are not set"),
            format!("set {env_vars} before starting Carapace"),
            None,
        ),
        ConfigValueResolution::Resolved { detail, .. } => SetupCheck::pass(label, detail, None),
    }
}

fn base_url_validation_check<F>(
    cfg: &Value,
    path: &[&str],
    label: &str,
    setup_command: Option<&str>,
    validator: F,
) -> SetupCheck
where
    F: FnOnce(&str) -> Result<(), String>,
{
    match resolve_config_value(cfg, path, label) {
        ConfigValueResolution::Missing => {
            SetupCheck::skip(label, "no custom base URL configured", None, None)
        }
        ConfigValueResolution::UnresolvedEnvVars { env_vars } => {
            let remediation = match setup_command {
                Some(command) => format!(
                    "set {env_vars} in the same shell or rerun `{command}` to rewrite the base URL"
                ),
                None => format!(
                    "set {env_vars} in the same shell or write a valid {label} into config, then rerun `{LOCAL_CHAT_VERIFY_COMMAND}`"
                ),
            };
            SetupCheck::fail(
                label,
                format!("{label} references {env_vars}, but they are not set"),
                remediation,
                None,
            )
        }
        ConfigValueResolution::Resolved {
            effective_value, ..
        } => match validator(&effective_value) {
            Ok(()) => SetupCheck::pass(label, format!("{label} passed local validation"), None),
            Err(err) => SetupCheck::validation_fail(
                label,
                format!("{label} failed local validation: {err}"),
                setup_follow_up(provider_setup_follow_up(
                    setup_command,
                    "and correct the base URL",
                    format!("write a valid {label} into config"),
                )),
                Some(SetupCheckCode::LocalValidationFailed),
            ),
        },
    }
}

fn load_profile_summary(
    state_dir: &Path,
    profile_id: &str,
) -> Result<Option<LoadedProfileSummary>, String> {
    let store = if profile_store_password_present() {
        ProfileStore::from_env(state_dir.to_path_buf()).map_err(|err| err.to_string())?
    } else {
        ProfileStore::new(state_dir.to_path_buf())
    };
    store.load().map_err(|err| err.to_string())?;
    Ok(store.get(profile_id).map(|profile| LoadedProfileSummary {
        token_still_encrypted: profile
            .token
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .is_some_and(is_encrypted),
        summary: profile.to_summary(),
    }))
}

fn profile_store_password_present() -> bool {
    std::env::var("CARAPACE_CONFIG_PASSWORD")
        .ok()
        .map(|value| !value.trim().is_empty())
        .unwrap_or(false)
}

fn env_var_present(key: &str) -> bool {
    std::env::var(key)
        .ok()
        .map(|value| !value.trim().is_empty())
        .unwrap_or(false)
}

fn config_string(cfg: &Value, path: &[&str]) -> Option<String> {
    let mut current = cfg;
    for key in path {
        current = current.get(*key)?;
    }
    current
        .as_str()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn env_var_references(value: &str) -> Vec<String> {
    crate::config::env_var_references_in_string(value)
}

fn missing_env_var_references(env_vars: &[String]) -> Vec<String> {
    env_vars
        .iter()
        .filter(|env_var| !env_var_present(env_var))
        .cloned()
        .collect()
}

fn format_env_var_list(env_vars: &[String]) -> String {
    env_vars
        .iter()
        .map(|env_var| format!("`${env_var}`"))
        .collect::<Vec<_>>()
        .join(", ")
}

fn model_provider_for_local_chat(model: &str) -> Option<SetupProvider> {
    if agent::ollama::is_ollama_model(model) {
        Some(SetupProvider::Ollama)
    } else if agent::venice::is_venice_model(model) {
        Some(SetupProvider::Venice)
    } else if agent::gemini::is_gemini_model(model) {
        Some(SetupProvider::Gemini)
    } else if agent::vertex::is_vertex_model(model) {
        Some(SetupProvider::Vertex)
    } else if agent::codex::is_codex_model(model) {
        Some(SetupProvider::Codex)
    } else if agent::openai::is_openai_model(model) {
        Some(SetupProvider::OpenAi)
    } else if agent::bedrock::is_bedrock_model(model) {
        Some(SetupProvider::Bedrock)
    } else if agent::anthropic::is_anthropic_model(model) {
        Some(SetupProvider::Anthropic)
    } else {
        // Bare model or unrecognized prefix — not a known provider.
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::profiles::{AuthProfile, AuthProfileCredentialKind, OAuthTokens};
    use crate::test_support::env::ScopedEnv;
    use serde_json::json;
    use tempfile::TempDir;

    fn sample_profile(id: &str, provider: OAuthProvider) -> AuthProfile {
        AuthProfile {
            id: id.to_string(),
            name: "Sample Profile".to_string(),
            provider,
            user_id: Some("user-1".to_string()),
            email: Some("user@example.com".to_string()),
            display_name: Some("User Example".to_string()),
            avatar_url: None,
            created_at_ms: 1,
            last_used_ms: Some(1),
            credential_kind: AuthProfileCredentialKind::OAuth,
            tokens: Some(OAuthTokens {
                access_token: "token".to_string(),
                refresh_token: Some("refresh".to_string()),
                token_type: "Bearer".to_string(),
                expires_at_ms: None,
                scope: None,
            }),
            token: None,
            oauth_provider_config: None,
        }
    }

    fn sample_token_profile(id: &str, provider: OAuthProvider, token: &str) -> AuthProfile {
        AuthProfile {
            id: id.to_string(),
            name: "Sample Token Profile".to_string(),
            provider,
            user_id: None,
            email: None,
            display_name: None,
            avatar_url: None,
            created_at_ms: 1,
            last_used_ms: Some(1),
            credential_kind: AuthProfileCredentialKind::Token,
            tokens: None,
            token: Some(token.to_string()),
            oauth_provider_config: None,
        }
    }

    #[test]
    fn test_assess_provider_setup_flags_missing_placeholder() {
        let temp = TempDir::new().unwrap();
        let cfg = json!({
            "agents": { "defaults": { "model": "anthropic:claude-sonnet-4-20250514" } },
            "anthropic": { "apiKey": "${ANTHROPIC_API_KEY}" }
        });
        let mut env = ScopedEnv::new();
        env.unset("ANTHROPIC_API_KEY");

        let assessment = assess_provider_setup(&cfg, temp.path(), SetupProvider::Anthropic, vec![]);

        assert_eq!(assessment.status, SetupAssessmentStatus::Invalid);
        assert!(assessment
            .recommended_remediation()
            .expect("remediation")
            .contains("ANTHROPIC_API_KEY"));
    }

    #[test]
    fn test_assess_provider_setup_loads_anthropic_token_profile_summary() {
        let temp = TempDir::new().unwrap();
        let store = ProfileStore::new(temp.path().to_path_buf());
        store
            .add(AuthProfile {
                id: "anthropic:default".to_string(),
                name: "Anthropic setup token".to_string(),
                provider: OAuthProvider::Anthropic,
                user_id: None,
                email: None,
                display_name: None,
                avatar_url: None,
                created_at_ms: 1,
                last_used_ms: Some(1),
                credential_kind: AuthProfileCredentialKind::Token,
                tokens: None,
                token: Some("sk-ant-oat01-token".to_string()),
                oauth_provider_config: None,
            })
            .unwrap();

        let cfg = json!({
            "agents": { "defaults": { "model": "anthropic:claude-sonnet-4-20250514" } },
            "auth": { "profiles": { "enabled": true } },
            "anthropic": { "authProfile": "anthropic:default" }
        });
        let mut env = ScopedEnv::new();
        env.set("CARAPACE_CONFIG_PASSWORD", "test-password");

        let assessment = assess_provider_setup(&cfg, temp.path(), SetupProvider::Anthropic, vec![]);

        assert_eq!(assessment.status, SetupAssessmentStatus::Ready);
        assert_eq!(
            assessment.profile_name.as_deref(),
            Some("Anthropic setup token")
        );
    }

    #[test]
    fn test_assess_provider_setup_rejects_anthropic_token_profile_without_token() {
        let temp = TempDir::new().unwrap();
        let store = ProfileStore::new(temp.path().to_path_buf());
        store
            .add(AuthProfile {
                id: "anthropic:default".to_string(),
                name: "Anthropic setup token".to_string(),
                provider: OAuthProvider::Anthropic,
                user_id: None,
                email: None,
                display_name: None,
                avatar_url: None,
                created_at_ms: 1,
                last_used_ms: Some(1),
                credential_kind: AuthProfileCredentialKind::Token,
                tokens: None,
                token: Some("   ".to_string()),
                oauth_provider_config: None,
            })
            .unwrap();

        let cfg = json!({
            "agents": { "defaults": { "model": "anthropic:claude-sonnet-4-20250514" } },
            "auth": { "profiles": { "enabled": true } },
            "anthropic": { "authProfile": "anthropic:default" }
        });
        let mut env = ScopedEnv::new();
        env.set("CARAPACE_CONFIG_PASSWORD", "test-password");

        let assessment = assess_provider_setup(&cfg, temp.path(), SetupProvider::Anthropic, vec![]);

        assert_eq!(assessment.status, SetupAssessmentStatus::Invalid);
        assert!(assessment
            .checks
            .iter()
            .any(|check| check.name == "Anthropic auth profile"
                && check.status == SetupCheckStatus::Fail
                && check.detail.contains("has no usable token")));
    }

    #[test]
    fn test_assess_provider_setup_surfaces_wrong_password_for_anthropic_token_profile() {
        let temp = TempDir::new().unwrap();
        let mut env = ScopedEnv::new();
        env.set("CARAPACE_CONFIG_PASSWORD", "correct-password");

        {
            let store = ProfileStore::from_env(temp.path().to_path_buf()).unwrap();
            store
                .add(AuthProfile {
                    id: "anthropic:default".to_string(),
                    name: "Anthropic setup token".to_string(),
                    provider: OAuthProvider::Anthropic,
                    user_id: None,
                    email: None,
                    display_name: None,
                    avatar_url: None,
                    created_at_ms: 1,
                    last_used_ms: Some(1),
                    credential_kind: AuthProfileCredentialKind::Token,
                    tokens: None,
                    token: Some("sk-ant-oat01-token".to_string()),
                    oauth_provider_config: None,
                })
                .unwrap();
        }

        env.set("CARAPACE_CONFIG_PASSWORD", "wrong-password");

        let cfg = json!({
            "agents": { "defaults": { "model": "anthropic:claude-sonnet-4-20250514" } },
            "auth": { "profiles": { "enabled": true } },
            "anthropic": { "authProfile": "anthropic:default" }
        });

        let assessment = assess_provider_setup(&cfg, temp.path(), SetupProvider::Anthropic, vec![]);

        assert_eq!(assessment.status, SetupAssessmentStatus::Invalid);
        assert!(assessment
            .checks
            .iter()
            .any(|check| check.name == "Anthropic auth profile"
                && check.status == SetupCheckStatus::Fail
                && check.detail.contains("could not decrypt the stored token")
                && check.detail.contains("CARAPACE_CONFIG_PASSWORD")));
    }

    #[test]
    fn test_assess_provider_setup_surfaces_dual_anthropic_auth_paths() {
        let temp = TempDir::new().unwrap();
        let cfg = json!({
            "agents": { "defaults": { "model": "anthropic:claude-sonnet-4-20250514" } },
            "auth": { "profiles": { "enabled": true } },
            "anthropic": {
                "apiKey": "${ANTHROPIC_API_KEY}",
                "authProfile": "anthropic:default"
            }
        });
        let mut env = ScopedEnv::new();
        env.set("ANTHROPIC_API_KEY", "sk-ant-test");

        let assessment = assess_provider_setup(&cfg, temp.path(), SetupProvider::Anthropic, vec![]);

        assert!(assessment
            .checks
            .iter()
            .any(|check| check.name == "Anthropic auth path"
                && check.status == SetupCheckStatus::Skip
                && check
                    .detail
                    .contains("runtime will prefer `anthropic.apiKey`")));
    }

    #[test]
    fn test_detect_auth_mode_prefers_anthropic_api_key_when_both_paths_configured() {
        let cfg = json!({
            "anthropic": {
                "apiKey": "${ANTHROPIC_API_KEY}",
                "authProfile": "anthropic:default"
            }
        });

        assert_eq!(
            detect_auth_mode(&cfg, SetupProvider::Anthropic),
            Some(SetupAuthMode::ApiKey)
        );
    }

    #[test]
    fn test_base_url_validation_check_resolves_embedded_env_placeholders() {
        let cfg = json!({
            "venice": { "baseUrl": "https://${SETUP_TEST_HOST}/v1" }
        });
        let mut env = ScopedEnv::new();
        env.set("SETUP_TEST_HOST", "api.example.com");

        let check = base_url_validation_check(
            &cfg,
            &["venice", "baseUrl"],
            "Venice base URL validation",
            Some("cara setup --provider venice"),
            |url| {
                assert_eq!(url, "https://api.example.com/v1");
                Ok(())
            },
        );

        assert_eq!(check.status, SetupCheckStatus::Pass);
    }

    #[test]
    fn test_base_url_validation_check_reports_missing_embedded_env_placeholders() {
        let cfg = json!({
            "venice": { "baseUrl": "https://${SETUP_TEST_HOST}/v1" }
        });
        let mut env = ScopedEnv::new();
        env.unset("SETUP_TEST_HOST");

        let check = base_url_validation_check(
            &cfg,
            &["venice", "baseUrl"],
            "Venice base URL validation",
            Some("cara setup --provider venice"),
            |_| Ok(()),
        );

        assert_eq!(check.status, SetupCheckStatus::Fail);
        assert!(check.detail.contains("SETUP_TEST_HOST"));
    }

    #[test]
    fn test_base_url_validation_check_sets_local_validation_failed_code() {
        let cfg = json!({
            "venice": { "baseUrl": "https://proxy.example.com/v1" }
        });

        let check = base_url_validation_check(
            &cfg,
            &["venice", "baseUrl"],
            "Venice base URL validation",
            Some("cara setup --provider venice"),
            |_| Err("invalid URL with embedded credentials".to_string()),
        );

        assert_eq!(check.status, SetupCheckStatus::Fail);
        assert_eq!(check.kind, SetupCheckKind::Validation);
        assert_eq!(check.code(), Some(SetupCheckCode::LocalValidationFailed));
    }

    #[test]
    fn test_setup_check_code_constructors_preserve_kind_and_code() {
        let requirement_skip = SetupCheck::skip(
            "Req skip",
            "detail",
            Some("fix it".to_string()),
            Some(SetupCheckCode::AuthProfileMissing),
        );
        assert_eq!(requirement_skip.status, SetupCheckStatus::Skip);
        assert_eq!(requirement_skip.kind, SetupCheckKind::Requirement);
        assert_eq!(
            requirement_skip.code(),
            Some(SetupCheckCode::AuthProfileMissing)
        );

        let validation_skip = SetupCheck::validation_skip(
            "Val skip",
            "detail",
            Some("fix it".to_string()),
            Some(SetupCheckCode::AuthProfileStoreReadFailed),
        );
        assert_eq!(validation_skip.status, SetupCheckStatus::Skip);
        assert_eq!(validation_skip.kind, SetupCheckKind::Validation);
        assert_eq!(
            validation_skip.code(),
            Some(SetupCheckCode::AuthProfileStoreReadFailed)
        );

        let validation_fail = SetupCheck::validation_fail(
            "Val fail",
            "detail",
            "fix it",
            Some(SetupCheckCode::LocalValidationFailed),
        );
        assert_eq!(validation_fail.status, SetupCheckStatus::Fail);
        assert_eq!(validation_fail.kind, SetupCheckKind::Validation);
        assert_eq!(
            validation_fail.code(),
            Some(SetupCheckCode::LocalValidationFailed)
        );
    }

    #[test]
    fn test_auth_profile_id_check_sets_auth_profile_configured_code() {
        let cfg = json!({
            "google": { "authProfile": "google-123" }
        });

        let check = auth_profile_id_check(
            &cfg,
            &["google", "authProfile"],
            "Gemini auth profile",
            Some("cara setup --provider gemini --auth-mode oauth"),
        );

        assert_eq!(check.status, SetupCheckStatus::Pass);
        assert_eq!(check.code(), Some(SetupCheckCode::AuthProfileConfigured));
    }

    #[test]
    fn test_auth_profile_id_check_sets_auth_profile_not_configured_code() {
        let cfg = json!({
            "google": {}
        });

        let check = auth_profile_id_check(
            &cfg,
            &["google", "authProfile"],
            "Gemini auth profile",
            Some("cara setup --provider gemini --auth-mode oauth"),
        );

        assert_eq!(check.status, SetupCheckStatus::Fail);
        assert_eq!(check.code(), Some(SetupCheckCode::AuthProfileNotConfigured));
    }

    #[test]
    fn test_auth_profile_summary_check_sets_wrong_provider_code() {
        let temp = TempDir::new().unwrap();
        let store = ProfileStore::new(temp.path().to_path_buf());
        store
            .add(sample_profile("google-123", OAuthProvider::Google))
            .unwrap();

        let (check, summary) = auth_profile_summary_check(
            temp.path(),
            "google-123",
            OAuthProvider::OpenAI,
            AuthProfileCredentialKind::OAuth,
            "Codex auth profile",
            Some("cara setup --provider codex"),
        );

        assert_eq!(check.status, SetupCheckStatus::Fail);
        assert_eq!(check.code(), Some(SetupCheckCode::AuthProfileWrongProvider));
        assert!(summary.is_none());
    }

    #[test]
    fn test_auth_profile_summary_check_sets_wrong_credential_type_code() {
        let temp = TempDir::new().unwrap();
        let store = ProfileStore::new(temp.path().to_path_buf());
        store
            .add(sample_token_profile(
                "anthropic:default",
                OAuthProvider::Anthropic,
                "sk-ant-oat01-token",
            ))
            .unwrap();

        let (check, summary) = auth_profile_summary_check(
            temp.path(),
            "anthropic:default",
            OAuthProvider::Anthropic,
            AuthProfileCredentialKind::OAuth,
            "Anthropic auth profile",
            Some("cara setup --provider anthropic --auth-mode setup-token"),
        );

        assert_eq!(check.status, SetupCheckStatus::Fail);
        assert_eq!(
            check.code(),
            Some(SetupCheckCode::AuthProfileWrongCredentialType)
        );
        assert!(summary.is_none());
    }

    #[test]
    fn test_auth_profile_summary_check_sets_auth_profile_missing_code() {
        let temp = TempDir::new().unwrap();

        let (check, summary) = auth_profile_summary_check(
            temp.path(),
            "missing-profile",
            OAuthProvider::Google,
            AuthProfileCredentialKind::OAuth,
            "Gemini auth profile",
            Some("cara setup --provider gemini --auth-mode oauth"),
        );

        assert_eq!(check.status, SetupCheckStatus::Fail);
        assert_eq!(check.code(), Some(SetupCheckCode::AuthProfileMissing));
        assert!(summary.is_none());
    }

    #[test]
    fn test_auth_profile_summary_check_sets_auth_profile_store_read_failed_code() {
        let temp = TempDir::new().unwrap();
        std::fs::write(temp.path().join("auth_profiles.json"), "not valid json").unwrap();

        let (check, summary) = auth_profile_summary_check(
            temp.path(),
            "google-123",
            OAuthProvider::Google,
            AuthProfileCredentialKind::OAuth,
            "Gemini auth profile",
            Some("cara setup --provider gemini --auth-mode oauth"),
        );

        assert_eq!(check.status, SetupCheckStatus::Fail);
        assert_eq!(
            check.code(),
            Some(SetupCheckCode::AuthProfileStoreReadFailed)
        );
        assert!(summary.is_none());
    }

    #[test]
    fn test_auth_profile_summary_check_sets_token_missing_code() {
        let temp = TempDir::new().unwrap();
        let store = ProfileStore::new(temp.path().to_path_buf());
        store
            .add(sample_token_profile(
                "anthropic:default",
                OAuthProvider::Anthropic,
                "   ",
            ))
            .unwrap();

        let (check, summary) = auth_profile_summary_check(
            temp.path(),
            "anthropic:default",
            OAuthProvider::Anthropic,
            AuthProfileCredentialKind::Token,
            "Anthropic auth profile",
            Some("cara setup --provider anthropic --auth-mode setup-token"),
        );

        assert_eq!(check.status, SetupCheckStatus::Fail);
        assert_eq!(check.code(), Some(SetupCheckCode::AuthProfileTokenMissing));
        assert!(summary.is_none());
    }

    #[test]
    fn test_auth_profile_summary_check_sets_token_decrypt_failed_code() {
        let temp = TempDir::new().unwrap();
        let mut env = ScopedEnv::new();
        env.set("CARAPACE_CONFIG_PASSWORD", "correct-password");

        {
            let store = ProfileStore::from_env(temp.path().to_path_buf()).unwrap();
            store
                .add(sample_token_profile(
                    "anthropic:default",
                    OAuthProvider::Anthropic,
                    "sk-ant-oat01-token",
                ))
                .unwrap();
        }

        env.set("CARAPACE_CONFIG_PASSWORD", "wrong-password");

        let (check, summary) = auth_profile_summary_check(
            temp.path(),
            "anthropic:default",
            OAuthProvider::Anthropic,
            AuthProfileCredentialKind::Token,
            "Anthropic auth profile",
            Some("cara setup --provider anthropic --auth-mode setup-token"),
        );

        assert_eq!(check.status, SetupCheckStatus::Fail);
        assert_eq!(
            check.code(),
            Some(SetupCheckCode::AuthProfileTokenDecryptFailed)
        );
        assert!(summary.is_none());
    }

    #[test]
    fn test_assess_provider_setup_requires_config_password_for_codex() {
        let temp = TempDir::new().unwrap();
        let cfg = json!({
            "agents": { "defaults": { "model": "codex:default" } },
            "auth": { "profiles": { "enabled": true } },
            "codex": { "authProfile": "openai-123" }
        });
        let mut env = ScopedEnv::new();
        env.unset("CARAPACE_CONFIG_PASSWORD");

        let assessment = assess_provider_setup(&cfg, temp.path(), SetupProvider::Codex, vec![]);

        assert_eq!(assessment.status, SetupAssessmentStatus::Invalid);
        assert!(assessment
            .checks
            .iter()
            .any(|check| check.name == "Encrypted profile store"
                && check.status == SetupCheckStatus::Fail));
    }

    #[test]
    fn test_assess_provider_setup_skips_profile_store_load_when_password_missing() {
        let temp = TempDir::new().unwrap();
        let store = ProfileStore::new(temp.path().to_path_buf());
        store
            .add(sample_profile("openai-123", OAuthProvider::OpenAI))
            .unwrap();

        let cfg = json!({
            "agents": { "defaults": { "model": "codex:default" } },
            "auth": { "profiles": { "enabled": true } },
            "codex": { "authProfile": "openai-123" }
        });
        let mut env = ScopedEnv::new();
        env.unset("CARAPACE_CONFIG_PASSWORD");

        let assessment = assess_provider_setup(&cfg, temp.path(), SetupProvider::Codex, vec![]);

        assert_eq!(assessment.status, SetupAssessmentStatus::Invalid);
        assert!(assessment
            .checks
            .iter()
            .any(|check| check.name == "Encrypted profile store"
                && check.status == SetupCheckStatus::Fail));
        assert!(!assessment
            .checks
            .iter()
            .any(|check| check.detail.contains("failed to read the profile store")));
    }

    #[test]
    fn test_assess_provider_setup_loads_gemini_oauth_profile_summary() {
        let temp = TempDir::new().unwrap();
        let store = ProfileStore::new(temp.path().to_path_buf());
        store
            .add(sample_profile("google-123", OAuthProvider::Google))
            .unwrap();

        let cfg = json!({
            "agents": { "defaults": { "model": "gemini:gemini-2.0-flash" } },
            "auth": { "profiles": { "enabled": true } },
            "google": { "authProfile": "google-123" }
        });
        let mut env = ScopedEnv::new();
        env.set("CARAPACE_CONFIG_PASSWORD", "test-password");

        let assessment = assess_provider_setup(&cfg, temp.path(), SetupProvider::Gemini, vec![]);

        assert_eq!(assessment.status, SetupAssessmentStatus::Ready);
        assert_eq!(assessment.profile_name.as_deref(), Some("Sample Profile"));
        assert_eq!(assessment.email.as_deref(), Some("user@example.com"));
        assert!(assessment.checks.iter().any(|check| {
            check.name == "Gemini auth profile"
                && check.code() == Some(SetupCheckCode::AuthProfileConfigured)
        }));
        assert!(assessment.checks.iter().any(|check| {
            check.name == "Gemini auth profile"
                && check.code() == Some(SetupCheckCode::AuthProfileLoaded)
        }));
    }

    #[test]
    fn test_assess_provider_setup_vertex_requires_explicit_location() {
        let temp = TempDir::new().unwrap();
        let cfg = json!({
            "agents": { "defaults": { "model": "vertex:default" } },
            "vertex": { "projectId": "my-project" }
        });

        let assessment = assess_provider_setup(&cfg, temp.path(), SetupProvider::Vertex, vec![]);

        assert_eq!(assessment.status, SetupAssessmentStatus::Invalid);
        assert!(assessment.checks.iter().any(|check| {
            check.name == "Vertex location" && check.status == SetupCheckStatus::Fail
        }));
    }

    #[test]
    fn test_assess_provider_setup_vertex_requires_explicit_project_id() {
        let temp = TempDir::new().unwrap();
        let cfg = json!({
            "agents": { "defaults": { "model": "vertex:default" } },
            "vertex": { "location": "us-central1" }
        });

        let assessment = assess_provider_setup(&cfg, temp.path(), SetupProvider::Vertex, vec![]);

        assert_eq!(assessment.status, SetupAssessmentStatus::Invalid);
        assert!(assessment.checks.iter().any(|check| {
            check.name == "Vertex project ID" && check.status == SetupCheckStatus::Fail
        }));
    }

    #[test]
    fn test_assess_provider_setup_vertex_default_route_requires_default_model() {
        let temp = TempDir::new().unwrap();
        let cfg = json!({
            "agents": { "defaults": { "model": "vertex:default" } },
            "vertex": {
                "projectId": "my-project",
                "location": "us-central1"
            }
        });

        let assessment = assess_provider_setup(&cfg, temp.path(), SetupProvider::Vertex, vec![]);

        assert_eq!(assessment.status, SetupAssessmentStatus::Invalid);
        assert!(assessment.checks.iter().any(|check| {
            check.name == "Vertex default model" && check.status == SetupCheckStatus::Fail
        }));
    }

    #[test]
    fn test_assess_provider_setup_vertex_default_model_reports_missing_env_placeholder() {
        let temp = TempDir::new().unwrap();
        let cfg = json!({
            "agents": { "defaults": { "model": "vertex:default" } },
            "vertex": {
                "projectId": "my-project",
                "location": "us-central1",
                "model": "${VERTEX_DEFAULT_MODEL}"
            }
        });
        let mut env = ScopedEnv::new();
        env.unset("VERTEX_DEFAULT_MODEL");

        let assessment = assess_provider_setup(&cfg, temp.path(), SetupProvider::Vertex, vec![]);

        assert_eq!(assessment.status, SetupAssessmentStatus::Invalid);
        let check = assessment
            .checks
            .iter()
            .find(|check| check.name == "Vertex default model")
            .expect("vertex default model check");
        assert_eq!(check.status, SetupCheckStatus::Fail);
        assert!(check.detail.contains("VERTEX_DEFAULT_MODEL"));
        assert!(check
            .remediation
            .as_deref()
            .expect("vertex default model remediation")
            .contains("VERTEX_DEFAULT_MODEL"));
    }

    #[test]
    fn test_assess_provider_setup_vertex_ready_with_validation_pass() {
        let temp = TempDir::new().unwrap();
        let cfg = json!({
            "agents": { "defaults": { "model": "vertex:default" } },
            "vertex": {
                "projectId": "my-project",
                "location": "us-central1",
                "model": "gemini-2.5-flash"
            }
        });

        let assessment = assess_provider_setup(
            &cfg,
            temp.path(),
            SetupProvider::Vertex,
            vec![SetupCheck::validation_pass(
                "Vertex model access",
                "validated access to `gemini-2.5-flash`",
                None,
            )],
        );

        assert_eq!(assessment.status, SetupAssessmentStatus::Ready);
        assert!(assessment.checks.iter().any(|check| {
            check.name == "Vertex model access" && check.status == SetupCheckStatus::Pass
        }));
    }

    #[test]
    fn test_assess_provider_setup_vertex_explicit_route_without_validation_is_partial() {
        let temp = TempDir::new().unwrap();
        let cfg = json!({
            "agents": { "defaults": { "model": "vertex:gemini-2.5-flash" } },
            "vertex": {
                "projectId": "my-project",
                "location": "us-central1"
            }
        });

        let assessment = assess_provider_setup(&cfg, temp.path(), SetupProvider::Vertex, vec![]);

        assert_eq!(assessment.status, SetupAssessmentStatus::Partial);
        assert!(assessment.checks.iter().any(|check| {
            check.name == "Live provider validation" && check.status == SetupCheckStatus::Skip
        }));
        assert!(assessment.checks.iter().any(|check| {
            check.name == "Vertex default model" && check.status == SetupCheckStatus::Skip
        }));
    }

    #[test]
    fn test_assess_provider_setup_marks_skipped_live_validation_as_partial() {
        let temp = TempDir::new().unwrap();
        let cfg = json!({
            "agents": { "defaults": { "model": "openai:gpt-4o" } },
            "openai": { "apiKey": "sk-test-value" }
        });

        let assessment = assess_provider_setup(&cfg, temp.path(), SetupProvider::OpenAi, vec![]);

        assert_eq!(assessment.status, SetupAssessmentStatus::Partial);
        assert!(assessment.checks.iter().any(|check| {
            check.name == "Live provider validation" && check.status == SetupCheckStatus::Skip
        }));
    }

    #[test]
    fn test_assess_provider_setup_keeps_failed_validation_invalid() {
        let temp = TempDir::new().unwrap();
        let cfg = json!({
            "agents": { "defaults": { "model": "openai:gpt-4o" } },
            "openai": { "apiKey": "sk-test-value" }
        });

        let assessment = assess_provider_setup(
            &cfg,
            temp.path(),
            SetupProvider::OpenAi,
            vec![SetupCheck::validation_fail(
                "Provider configuration validation",
                "provider config failed local validation",
                "fix the value and rerun setup",
                None,
            )],
        );

        assert_eq!(assessment.status, SetupAssessmentStatus::Invalid);
        assert_eq!(
            assessment
                .checks
                .iter()
                .filter(|check| check.name == "Live provider validation")
                .count(),
            0
        );
    }

    #[test]
    fn test_assess_provider_setup_does_not_duplicate_skipped_validation() {
        let temp = TempDir::new().unwrap();
        let cfg = json!({
            "agents": { "defaults": { "model": "openai:gpt-4o" } },
            "openai": { "apiKey": "sk-test-value" }
        });

        let assessment = assess_provider_setup(
            &cfg,
            temp.path(),
            SetupProvider::OpenAi,
            vec![SetupCheck::validation_skip(
                "Live provider validation",
                "OpenAI credential validation was skipped",
                Some("run `cara verify` after setup".to_string()),
                None,
            )],
        );

        assert_eq!(assessment.status, SetupAssessmentStatus::Partial);
        assert_eq!(
            assessment
                .checks
                .iter()
                .filter(|check| check.name == "Live provider validation")
                .count(),
            1
        );
    }

    #[test]
    fn test_assess_provider_setup_adds_live_validation_skip_after_optional_requirement_skip() {
        let temp = TempDir::new().unwrap();
        let cfg = json!({
            "agents": { "defaults": { "model": "ollama:llama3.2" } },
            "providers": { "ollama": { "baseUrl": "http://127.0.0.1:11434" } }
        });

        let assessment = assess_provider_setup(&cfg, temp.path(), SetupProvider::Ollama, vec![]);

        assert_eq!(assessment.status, SetupAssessmentStatus::Partial);
        assert!(assessment.checks.iter().any(|check| {
            check.name == "Ollama API key"
                && check.status == SetupCheckStatus::Skip
                && check.kind == SetupCheckKind::Requirement
        }));
        assert_eq!(
            assessment
                .checks
                .iter()
                .filter(|check| {
                    check.name == "Live provider validation"
                        && check.status == SetupCheckStatus::Skip
                        && check.kind == SetupCheckKind::Validation
                })
                .count(),
            1
        );
    }

    #[test]
    fn test_assess_provider_setup_reports_unrecognized_provider_prefix() {
        let temp = TempDir::new().unwrap();
        let cfg = json!({
            "agents": { "defaults": { "model": "mistral:mixtral" } },
            "openai": { "apiKey": "sk-test-value" }
        });

        let assessment = assess_provider_setup(&cfg, temp.path(), SetupProvider::OpenAi, vec![]);

        assert_eq!(assessment.status, SetupAssessmentStatus::Invalid);
        assert!(assessment.checks.iter().any(|check| {
            check.name == "Default model route"
                && check.status == SetupCheckStatus::Fail
                && check.detail.contains("unrecognized provider route")
        }));
    }

    #[test]
    fn test_setup_check_serializes_with_control_facing_field_names() {
        let check = SetupCheck::validation_skip(
            "Live provider validation",
            "setup completed without a live provider-side validation step",
            Some("run `cara verify --outcome local-chat`".to_string()),
            None,
        );

        let value = serde_json::to_value(&check).expect("check should serialize");

        assert_eq!(value["status"], "skip");
        assert_eq!(value["kind"], "validation");
        assert_eq!(value["name"], "Live provider validation");
        assert_eq!(
            value["detail"],
            "setup completed without a live provider-side validation step"
        );
    }

    #[test]
    fn test_setup_provider_is_configured_tracks_provider_owned_state() {
        assert!(SetupProvider::Anthropic.is_configured(&json!({
            "anthropic": { "baseUrl": "https://anthropic-proxy.example.com" }
        })));
        assert!(SetupProvider::Codex.is_configured(&json!({
            "codex": { "authProfile": "openai-default" }
        })));
        assert!(SetupProvider::OpenAi.is_configured(&json!({
            "openai": { "apiKey": "sk-test" }
        })));
        assert!(SetupProvider::Ollama.is_configured(&json!({
            "providers": { "ollama": { "baseUrl": "http://127.0.0.1:11434" } }
        })));
        assert!(SetupProvider::Gemini.is_configured(&json!({
            "google": { "authProfile": "google-default" }
        })));
        assert!(SetupProvider::Vertex.is_configured(&json!({
            "vertex": { "projectId": "test-project" }
        })));
        assert!(SetupProvider::Venice.is_configured(&json!({
            "venice": { "baseUrl": "https://venice.example.com/v1" }
        })));
        assert!(SetupProvider::Bedrock.is_configured(&json!({
            "bedrock": { "region": "us-east-1" }
        })));

        assert!(!SetupProvider::Anthropic.is_configured(&json!({})));
        assert!(!SetupProvider::Codex.is_configured(&json!({})));
        assert!(!SetupProvider::OpenAi.is_configured(&json!({})));
        assert!(!SetupProvider::Ollama.is_configured(&json!({})));
        assert!(!SetupProvider::Gemini.is_configured(&json!({})));
        assert!(!SetupProvider::Vertex.is_configured(&json!({
            "vertex": { "model": "gemini-2.5-flash" }
        })));
        assert!(!SetupProvider::Bedrock.is_configured(&json!({
            "bedrock": { "sessionToken": "sts-token" }
        })));
    }

    #[test]
    fn test_setup_provider_labels_distinguish_codex_from_openai() {
        assert_eq!(SetupProvider::Codex.label(), "Codex");
        assert_eq!(SetupProvider::OpenAi.label(), "OpenAI");
    }

    #[test]
    fn test_setup_provider_all_lists_expected_variants() {
        let providers = SetupProvider::all();
        assert_eq!(providers.len(), 8);
        let keys: Vec<&str> = providers
            .iter()
            .map(|provider| provider.prompt_key())
            .collect();
        assert_eq!(
            keys,
            vec![
                "anthropic",
                "codex",
                "openai",
                "ollama",
                "gemini",
                "vertex",
                "venice",
                "bedrock",
            ]
        );
    }
}
