use std::path::Path;

use serde_json::Value;

use crate::agent;
use crate::auth::profiles::{AuthProfileSummary, OAuthProvider, ProfileStore};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetupProvider {
    Anthropic,
    Codex,
    OpenAi,
    Ollama,
    Gemini,
    Venice,
    Bedrock,
}

impl SetupProvider {
    pub fn label(self) -> &'static str {
        match self {
            Self::Anthropic => "Anthropic",
            Self::Codex => "OpenAI",
            Self::OpenAi => "OpenAI",
            Self::Ollama => "Ollama",
            Self::Gemini => "Gemini",
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
            Self::Venice => "venice",
            Self::Bedrock => "bedrock",
        }
    }

    pub fn default_model(self) -> &'static str {
        match self {
            Self::Anthropic => "claude-sonnet-4-20250514",
            Self::Codex => "codex:default",
            Self::OpenAi => "gpt-4o",
            Self::Ollama => "ollama:llama3",
            Self::Gemini => "gemini-2.0-flash",
            Self::Venice => "venice:llama-3.3-70b",
            Self::Bedrock => "bedrock:anthropic.claude-3-5-sonnet-20240620-v1:0",
        }
    }

    pub fn rerun_command(self, auth_mode: Option<SetupAuthMode>) -> String {
        match (self, auth_mode) {
            (Self::Gemini, Some(SetupAuthMode::OAuth)) => {
                "cara setup --force --provider gemini --auth-mode oauth".to_string()
            }
            (Self::Gemini, Some(SetupAuthMode::ApiKey)) => {
                "cara setup --force --provider gemini --auth-mode api-key".to_string()
            }
            _ => format!("cara setup --force --provider {}", self.prompt_key()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetupAuthMode {
    ApiKey,
    OAuth,
    StaticCredentials,
    BaseUrl,
}

impl SetupAuthMode {
    pub fn label(self) -> &'static str {
        match self {
            Self::ApiKey => "API key",
            Self::OAuth => "OAuth sign-in",
            Self::StaticCredentials => "static credentials",
            Self::BaseUrl => "base URL",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetupCheckStatus {
    Pass,
    Fail,
    Skip,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetupCheckKind {
    Requirement,
    Validation,
}

#[derive(Debug, Clone)]
pub struct SetupCheck {
    pub name: String,
    pub status: SetupCheckStatus,
    pub kind: SetupCheckKind,
    pub detail: String,
    pub remediation: Option<String>,
}

impl SetupCheck {
    pub fn pass(name: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            status: SetupCheckStatus::Pass,
            kind: SetupCheckKind::Requirement,
            detail: detail.into(),
            remediation: None,
        }
    }

    pub fn validation_pass(name: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            status: SetupCheckStatus::Pass,
            kind: SetupCheckKind::Validation,
            detail: detail.into(),
            remediation: None,
        }
    }

    pub fn fail(
        name: impl Into<String>,
        detail: impl Into<String>,
        remediation: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            status: SetupCheckStatus::Fail,
            kind: SetupCheckKind::Requirement,
            detail: detail.into(),
            remediation: Some(remediation.into()),
        }
    }

    pub fn skip(
        name: impl Into<String>,
        detail: impl Into<String>,
        remediation: Option<String>,
    ) -> Self {
        Self {
            name: name.into(),
            status: SetupCheckStatus::Skip,
            kind: SetupCheckKind::Validation,
            detail: detail.into(),
            remediation,
        }
    }

    pub fn validation_fail(
        name: impl Into<String>,
        detail: impl Into<String>,
        remediation: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            status: SetupCheckStatus::Fail,
            kind: SetupCheckKind::Validation,
            detail: detail.into(),
            remediation: Some(remediation.into()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
    let rerun_command = provider.rerun_command(auth_mode);
    let mut checks = vec![model_route_check(cfg, provider, &rerun_command)];
    let mut profile_name = None;
    let mut email = None;

    match provider {
        SetupProvider::Anthropic => {
            checks.push(configured_value_check(
                cfg,
                &["anthropic", "apiKey"],
                "Anthropic API key",
                &rerun_command,
            ));
        }
        SetupProvider::Codex => {
            checks.push(auth_profiles_enabled_check(cfg, &rerun_command));
            let profile_check = oauth_profile_id_check(
                cfg,
                &["codex", "authProfile"],
                "OpenAI auth profile",
                &rerun_command,
            );
            let profile_id = config_string(cfg, &["codex", "authProfile"]);
            checks.push(profile_check);
            let password_present = profile_store_password_present();
            checks.push(config_password_check(&rerun_command));
            if password_present {
                if let Some(profile_id) = profile_id {
                    let (check, summary) = auth_profile_summary_check(
                        state_dir,
                        &profile_id,
                        OAuthProvider::OpenAI,
                        "OpenAI auth profile",
                        &rerun_command,
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
                &rerun_command,
            ));
        }
        SetupProvider::Ollama => {
            checks.push(configured_value_check(
                cfg,
                &["providers", "ollama", "baseUrl"],
                "Ollama base URL",
                &rerun_command,
            ));
            checks.push(base_url_validation_check(
                cfg,
                &["providers", "ollama", "baseUrl"],
                "Ollama base URL validation",
                &rerun_command,
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
                checks.push(auth_profiles_enabled_check(cfg, &rerun_command));
                let profile_check = oauth_profile_id_check(
                    cfg,
                    &["google", "authProfile"],
                    "Gemini auth profile",
                    &rerun_command,
                );
                let profile_id = config_string(cfg, &["google", "authProfile"]);
                checks.push(profile_check);
                let password_present = profile_store_password_present();
                checks.push(config_password_check(&rerun_command));
                if password_present {
                    if let Some(profile_id) = profile_id {
                        let (check, summary) = auth_profile_summary_check(
                            state_dir,
                            &profile_id,
                            OAuthProvider::Google,
                            "Gemini auth profile",
                            &rerun_command,
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
                        &rerun_command,
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
                    &provider.rerun_command(Some(SetupAuthMode::ApiKey)),
                ));
                if config_string(cfg, &["google", "baseUrl"]).is_some() {
                    checks.push(base_url_validation_check(
                        cfg,
                        &["google", "baseUrl"],
                        "Gemini base URL validation",
                        &provider.rerun_command(Some(SetupAuthMode::ApiKey)),
                        |url| {
                            crate::onboarding::gemini::validate_gemini_base_url_input(Some(url))
                                .map_err(|err| err.to_string())
                        },
                    ));
                }
            }
        },
        SetupProvider::Venice => {
            checks.push(configured_value_check(
                cfg,
                &["venice", "apiKey"],
                "Venice API key",
                &rerun_command,
            ));
            if config_string(cfg, &["venice", "baseUrl"]).is_some() {
                checks.push(base_url_validation_check(
                    cfg,
                    &["venice", "baseUrl"],
                    "Venice base URL validation",
                    &rerun_command,
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
                &rerun_command,
            ));
            checks.push(configured_value_check(
                cfg,
                &["bedrock", "accessKeyId"],
                "AWS access key ID",
                &rerun_command,
            ));
            checks.push(configured_value_check(
                cfg,
                &["bedrock", "secretAccessKey"],
                "AWS secret access key",
                &rerun_command,
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
        checks.push(SetupCheck::skip(
            "Live provider validation",
            "setup completed without a live provider-side validation step",
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
        SetupProvider::Anthropic | SetupProvider::OpenAi | SetupProvider::Venice => {
            Some(SetupAuthMode::ApiKey)
        }
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
        SetupProvider::Bedrock => Some(SetupAuthMode::StaticCredentials),
    }
}

fn model_route_check(cfg: &Value, provider: SetupProvider, rerun_command: &str) -> SetupCheck {
    let model = config_string(cfg, &["agents", "defaults", "model"])
        .unwrap_or_else(|| provider.default_model().to_string());
    match model_provider_for_local_chat(&model) {
        Some(actual_provider) if actual_provider == provider => SetupCheck::pass(
            "Default model route",
            format!("`agents.defaults.model` routes to {}", provider.label()),
        ),
        Some(actual_provider) => SetupCheck::fail(
            "Default model route",
            format!(
                "`agents.defaults.model` currently routes to {}, not {}",
                actual_provider.label(),
                provider.label()
            ),
            format!(
                "set `agents.defaults.model` to `{}` or rerun `{}`",
                provider.default_model(),
                rerun_command
            ),
        ),
        None => SetupCheck::fail(
            "Default model route",
            format!("`agents.defaults.model` uses an unrecognized provider route: `{model}`"),
            format!(
                "set `agents.defaults.model` to `{}` or rerun `{}`",
                provider.default_model(),
                rerun_command
            ),
        ),
    }
}

fn auth_profiles_enabled_check(cfg: &Value, rerun_command: &str) -> SetupCheck {
    let enabled = cfg
        .pointer("/auth/profiles/enabled")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if enabled {
        SetupCheck::pass("Auth profiles", "`auth.profiles.enabled` is true")
    } else {
        SetupCheck::fail(
            "Auth profiles",
            "`auth.profiles.enabled` is false",
            format!("rerun `{rerun_command}` to enable auth profiles"),
        )
    }
}

fn oauth_profile_id_check(
    cfg: &Value,
    path: &[&str],
    label: &str,
    rerun_command: &str,
) -> SetupCheck {
    match config_string(cfg, path) {
        Some(profile_id) => {
            SetupCheck::pass(label, format!("configured profile id: `{profile_id}`"))
        }
        None => SetupCheck::fail(
            label,
            format!("{label} is not configured"),
            format!("rerun `{rerun_command}` to store a sign-in profile"),
        ),
    }
}

fn config_password_check(rerun_command: &str) -> SetupCheck {
    if env_var_present("CARAPACE_CONFIG_PASSWORD") {
        SetupCheck::pass(
            "Encrypted profile store",
            "`CARAPACE_CONFIG_PASSWORD` is set in the current shell",
        )
    } else {
        SetupCheck::fail(
            "Encrypted profile store",
            "`CARAPACE_CONFIG_PASSWORD` is not set in the current shell",
            format!(
                "set `CARAPACE_CONFIG_PASSWORD` before running Carapace, or rerun `{rerun_command}` after exporting it"
            ),
        )
    }
}

fn auth_profile_summary_check(
    state_dir: &Path,
    profile_id: &str,
    expected_provider: OAuthProvider,
    label: &str,
    rerun_command: &str,
) -> (SetupCheck, Option<AuthProfileSummary>) {
    match load_profile_summary(state_dir, profile_id) {
        Ok(Some(summary)) => {
            if summary.provider != expected_provider {
                (
                    SetupCheck::fail(
                        label,
                        format!(
                            "stored profile `{profile_id}` belongs to {}, not {}",
                            summary.provider, expected_provider
                        ),
                        format!("rerun `{rerun_command}` to store the correct auth profile"),
                    ),
                    None,
                )
            } else {
                let detail = match summary.email.as_deref() {
                    Some(email) => format!("loaded `{}` ({email})", summary.name),
                    None => format!("loaded `{}`", summary.name),
                };
                (SetupCheck::validation_pass(label, detail), Some(summary))
            }
        }
        Ok(None) => (
            SetupCheck::fail(
                label,
                format!("stored profile `{profile_id}` was not found in the profile store"),
                format!("rerun `{rerun_command}` to store a fresh auth profile"),
            ),
            None,
        ),
        Err(err) => (
            SetupCheck::fail(
                label,
                format!("failed to read the profile store: {err}"),
                format!("check the profile store and rerun `{rerun_command}`"),
            ),
            None,
        ),
    }
}

fn configured_value_check(
    cfg: &Value,
    path: &[&str],
    label: &str,
    rerun_command: &str,
) -> SetupCheck {
    match config_string(cfg, path) {
        Some(value) => match extract_env_placeholder_key(&value) {
            Some(env_var) if !env_var_present(&env_var) => SetupCheck::fail(
                label,
                format!("{label} references `${env_var}`, but it is not set"),
                format!(
                    "set `${env_var}` in the same shell or rerun `{rerun_command}` to rewrite the value"
                ),
            ),
            Some(env_var) => {
                SetupCheck::pass(label, format!("{label} resolves from `${env_var}`"))
            }
            None => SetupCheck::pass(label, format!("{label} is written in config")),
        },
        None => SetupCheck::fail(
            label,
            format!("{label} is not configured"),
            format!("rerun `{rerun_command}` to configure {label}"),
        ),
    }
}

fn optional_configured_value_check(cfg: &Value, path: &[&str], label: &str) -> SetupCheck {
    match config_string(cfg, path) {
        Some(value) => match extract_env_placeholder_key(&value) {
            Some(env_var) if !env_var_present(&env_var) => SetupCheck::fail(
                label,
                format!("{label} references `${env_var}`, but it is not set"),
                format!("set `${env_var}` before starting Carapace"),
            ),
            Some(env_var) => SetupCheck::pass(label, format!("{label} resolves from `${env_var}`")),
            None => SetupCheck::pass(label, format!("{label} is written in config")),
        },
        None => SetupCheck::skip(label, format!("{label} is not configured"), None),
    }
}

fn base_url_validation_check<F>(
    cfg: &Value,
    path: &[&str],
    label: &str,
    rerun_command: &str,
    validator: F,
) -> SetupCheck
where
    F: FnOnce(&str) -> Result<(), String>,
{
    let Some(value) = config_string(cfg, path) else {
        return SetupCheck::skip(label, "no custom base URL configured", None);
    };
    if let Some(env_var) = extract_env_placeholder_key(&value) {
        if !env_var_present(&env_var) {
            return SetupCheck::fail(
                label,
                format!("{label} references `${env_var}`, but it is not set"),
                format!(
                    "set `${env_var}` in the same shell or rerun `{rerun_command}` to rewrite the base URL"
                ),
            );
        }
    }

    let effective = effective_config_value(&value).unwrap_or_else(|| value.clone());
    match validator(&effective) {
        Ok(()) => SetupCheck::pass(label, format!("{label} passed local validation")),
        Err(_) => SetupCheck::fail(
            label,
            format!("{label} failed local validation"),
            format!("rerun `{rerun_command}` and correct the base URL"),
        ),
    }
}

fn load_profile_summary(
    state_dir: &Path,
    profile_id: &str,
) -> Result<Option<AuthProfileSummary>, String> {
    let store = if profile_store_password_present() {
        ProfileStore::from_env(state_dir.to_path_buf()).map_err(|err| err.to_string())?
    } else {
        ProfileStore::new(state_dir.to_path_buf())
    };
    store.load().map_err(|err| err.to_string())?;
    Ok(store.get(profile_id).map(|profile| profile.to_summary()))
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

fn effective_config_value(value: &str) -> Option<String> {
    extract_env_placeholder_key(value)
        .and_then(|env_var| std::env::var(env_var).ok())
        .map(|resolved| resolved.trim().to_string())
        .filter(|resolved| !resolved.is_empty())
        .or_else(|| {
            let trimmed = value.trim();
            (!trimmed.is_empty()).then(|| trimmed.to_string())
        })
}

fn extract_env_placeholder_key(value: &str) -> Option<String> {
    value
        .trim()
        .strip_prefix("${")
        .and_then(|trimmed| trimmed.strip_suffix('}'))
        .map(str::trim)
        .filter(|key| !key.is_empty())
        .map(ToOwned::to_owned)
}

fn model_provider_for_local_chat(model: &str) -> Option<SetupProvider> {
    if agent::ollama::is_ollama_model(model) {
        Some(SetupProvider::Ollama)
    } else if agent::venice::is_venice_model(model) {
        Some(SetupProvider::Venice)
    } else if agent::gemini::is_gemini_model(model) {
        Some(SetupProvider::Gemini)
    } else if agent::codex::is_codex_model(model) {
        Some(SetupProvider::Codex)
    } else if agent::openai::is_openai_model(model) {
        Some(SetupProvider::OpenAi)
    } else if agent::bedrock::is_bedrock_model(model) {
        Some(SetupProvider::Bedrock)
    } else if model.trim_start().starts_with("claude") {
        Some(SetupProvider::Anthropic)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::profiles::{AuthProfile, OAuthTokens};
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
            tokens: OAuthTokens {
                access_token: "token".to_string(),
                refresh_token: Some("refresh".to_string()),
                token_type: "Bearer".to_string(),
                expires_at_ms: None,
                scope: None,
            },
            oauth_provider_config: None,
        }
    }

    #[test]
    fn test_assess_provider_setup_flags_missing_placeholder() {
        let temp = TempDir::new().unwrap();
        let cfg = json!({
            "agents": { "defaults": { "model": "claude-sonnet-4-20250514" } },
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
            "agents": { "defaults": { "model": "gemini-2.0-flash" } },
            "auth": { "profiles": { "enabled": true } },
            "google": { "authProfile": "google-123" }
        });
        let mut env = ScopedEnv::new();
        env.set("CARAPACE_CONFIG_PASSWORD", "test-password");

        let assessment = assess_provider_setup(&cfg, temp.path(), SetupProvider::Gemini, vec![]);

        assert_eq!(assessment.status, SetupAssessmentStatus::Ready);
        assert_eq!(assessment.profile_name.as_deref(), Some("Sample Profile"));
        assert_eq!(assessment.email.as_deref(), Some("user@example.com"));
    }

    #[test]
    fn test_assess_provider_setup_marks_skipped_live_validation_as_partial() {
        let temp = TempDir::new().unwrap();
        let cfg = json!({
            "agents": { "defaults": { "model": "gpt-4o" } },
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
            "agents": { "defaults": { "model": "gpt-4o" } },
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
            "agents": { "defaults": { "model": "gpt-4o" } },
            "openai": { "apiKey": "sk-test-value" }
        });

        let assessment = assess_provider_setup(
            &cfg,
            temp.path(),
            SetupProvider::OpenAi,
            vec![SetupCheck::skip(
                "Live provider validation",
                "OpenAI credential validation was skipped",
                Some("run `cara verify` after setup".to_string()),
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
    fn test_assess_provider_setup_reports_unknown_model_route() {
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
}
