use serde_json::{json, Value};
use std::path::{Path, PathBuf};

use crate::auth::profiles::{
    profile_store_encryption_enabled_from_env, AuthProfile, AuthProfileCredentialKind,
    OAuthProvider, ProfileStore,
};

pub const ANTHROPIC_SETUP_TOKEN_PREFIX: &str = "sk-ant-oat01-";
pub const ANTHROPIC_SETUP_TOKEN_MIN_TOTAL_LENGTH: usize = 80;
pub const DEFAULT_ANTHROPIC_AUTH_PROFILE_ID: &str = "anthropic:default";

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AnthropicSetupTokenApiKeyConflict {
    pub env_api_key_present: bool,
    pub config_api_key_present: bool,
}

pub fn require_encrypted_profile_store_for_anthropic_setup_token() -> Result<(), String> {
    if profile_store_encryption_enabled_from_env() {
        Ok(())
    } else {
        Err(
            "Anthropic setup-token auth requires CARAPACE_CONFIG_PASSWORD so the stored token stays encrypted at rest."
                .to_string(),
        )
    }
}

pub fn validate_anthropic_setup_token_input(raw: &str) -> Result<String, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("Anthropic setup-token is required.".to_string());
    }
    if !trimmed.starts_with(ANTHROPIC_SETUP_TOKEN_PREFIX) {
        return Err(format!(
            "Anthropic setup-token must start with `{ANTHROPIC_SETUP_TOKEN_PREFIX}`."
        ));
    }
    if trimmed.len() < ANTHROPIC_SETUP_TOKEN_MIN_TOTAL_LENGTH {
        return Err("Anthropic setup-token looks too short; paste the full token.".to_string());
    }
    Ok(trimmed.to_string())
}

pub fn persist_cli_anthropic_setup_token(
    state_dir: PathBuf,
    config: &mut Value,
    token: &str,
) -> Result<String, String> {
    require_encrypted_profile_store_for_anthropic_setup_token()?;
    let normalized = validate_anthropic_setup_token_input(token)?;
    let profile_id = upsert_anthropic_setup_token_profile(&state_dir, &normalized)?;
    ensure_anthropic_setup_token_config(config, &profile_id);
    Ok(profile_id)
}

pub fn anthropic_setup_token_api_key_conflict(config: &Value) -> AnthropicSetupTokenApiKeyConflict {
    AnthropicSetupTokenApiKeyConflict {
        env_api_key_present: std::env::var("ANTHROPIC_API_KEY")
            .ok()
            .map(|value| !value.trim().is_empty())
            .unwrap_or(false),
        config_api_key_present: config
            .get("anthropic")
            .and_then(|anthropic| anthropic.get("apiKey"))
            .and_then(Value::as_str)
            .map(str::trim)
            .is_some_and(|value| !value.is_empty()),
    }
}

fn upsert_anthropic_setup_token_profile(state_dir: &Path, token: &str) -> Result<String, String> {
    let store = ProfileStore::from_env(state_dir.to_path_buf()).map_err(|err| err.to_string())?;
    store.load().map_err(|err| err.to_string())?;

    let profile_id = DEFAULT_ANTHROPIC_AUTH_PROFILE_ID.to_string();
    let existing = store.get(&profile_id);
    let now_ms = crate::time::unix_now_ms_u64();
    let profile = AuthProfile {
        id: profile_id.clone(),
        name: "Anthropic setup token".to_string(),
        provider: OAuthProvider::Anthropic,
        user_id: existing
            .as_ref()
            .and_then(|profile| profile.user_id.clone()),
        email: existing.as_ref().and_then(|profile| profile.email.clone()),
        display_name: existing
            .as_ref()
            .and_then(|profile| profile.display_name.clone()),
        avatar_url: existing
            .as_ref()
            .and_then(|profile| profile.avatar_url.clone()),
        created_at_ms: existing
            .as_ref()
            .map(|profile| profile.created_at_ms)
            .unwrap_or(now_ms),
        last_used_ms: Some(now_ms),
        credential_kind: AuthProfileCredentialKind::Token,
        tokens: None,
        token: Some(token.to_string()),
        oauth_provider_config: None,
    };
    store.upsert(profile).map_err(|err| err.to_string())?;
    Ok(profile_id)
}

pub fn ensure_anthropic_setup_token_config(config: &mut Value, profile_id: &str) {
    if !config.get("auth").is_some_and(Value::is_object) {
        config["auth"] = json!({});
    }
    if !config["auth"].get("profiles").is_some_and(Value::is_object) {
        config["auth"]["profiles"] = json!({});
    }
    config["auth"]["profiles"]["enabled"] = json!(true);

    if !config.get("anthropic").is_some_and(Value::is_object) {
        config["anthropic"] = json!({});
    }
    if let Some(anthropic) = config.get_mut("anthropic").and_then(Value::as_object_mut) {
        anthropic.insert("authProfile".to_string(), json!(profile_id));
        anthropic.remove("apiKey");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::env::ScopedEnv;
    use serde_json::json;
    use tempfile::tempdir;

    #[test]
    fn test_validate_anthropic_setup_token_input_accepts_expected_shape() {
        let payload_len =
            ANTHROPIC_SETUP_TOKEN_MIN_TOTAL_LENGTH - ANTHROPIC_SETUP_TOKEN_PREFIX.len();
        let token = format!(
            "{}{}",
            ANTHROPIC_SETUP_TOKEN_PREFIX,
            "a".repeat(payload_len)
        );
        let validated = validate_anthropic_setup_token_input(&token).unwrap();
        assert_eq!(validated, token);
    }

    #[test]
    fn test_validate_anthropic_setup_token_input_rejects_wrong_prefix() {
        let err = validate_anthropic_setup_token_input("sk-ant-test").unwrap_err();
        assert!(err.contains(ANTHROPIC_SETUP_TOKEN_PREFIX));
    }

    #[test]
    fn test_validate_anthropic_setup_token_input_rejects_too_short_token() {
        let payload_len =
            ANTHROPIC_SETUP_TOKEN_MIN_TOTAL_LENGTH - ANTHROPIC_SETUP_TOKEN_PREFIX.len() - 1;
        let token = format!(
            "{}{}",
            ANTHROPIC_SETUP_TOKEN_PREFIX,
            "a".repeat(payload_len)
        );
        let err = validate_anthropic_setup_token_input(&token).unwrap_err();
        assert!(err.contains("looks too short"));
    }

    #[test]
    fn test_ensure_anthropic_setup_token_config_replaces_api_key() {
        let mut config = json!({
            "anthropic": {
                "apiKey": "${ANTHROPIC_API_KEY}"
            }
        });
        ensure_anthropic_setup_token_config(&mut config, DEFAULT_ANTHROPIC_AUTH_PROFILE_ID);

        assert!(config["anthropic"].get("apiKey").is_none());
        assert_eq!(
            config["anthropic"]["authProfile"],
            DEFAULT_ANTHROPIC_AUTH_PROFILE_ID
        );
        assert_eq!(config["auth"]["profiles"]["enabled"], json!(true));
    }

    #[test]
    fn test_anthropic_setup_token_api_key_conflict_detects_existing_value() {
        let mut env = ScopedEnv::new();
        env.unset("ANTHROPIC_API_KEY");
        let config = json!({
            "anthropic": {
                "apiKey": "${ANTHROPIC_API_KEY}"
            }
        });
        assert_eq!(
            anthropic_setup_token_api_key_conflict(&config),
            AnthropicSetupTokenApiKeyConflict {
                env_api_key_present: false,
                config_api_key_present: true,
            }
        );

        let blank = json!({
            "anthropic": {
                "apiKey": "   "
            }
        });
        assert_eq!(
            anthropic_setup_token_api_key_conflict(&blank),
            AnthropicSetupTokenApiKeyConflict::default()
        );
    }

    #[test]
    fn test_anthropic_setup_token_api_key_conflict_detects_env_api_key() {
        let mut env = ScopedEnv::new();
        env.set("ANTHROPIC_API_KEY", "sk-anthropic");

        assert_eq!(
            anthropic_setup_token_api_key_conflict(&json!({})),
            AnthropicSetupTokenApiKeyConflict {
                env_api_key_present: true,
                config_api_key_present: false,
            }
        );
    }

    #[test]
    fn test_persist_cli_anthropic_setup_token_stores_token_profile_and_updates_config() {
        let temp = tempdir().unwrap();
        let mut env = ScopedEnv::new();
        env.set("CARAPACE_CONFIG_PASSWORD", "test-password");

        let payload_len =
            ANTHROPIC_SETUP_TOKEN_MIN_TOTAL_LENGTH - ANTHROPIC_SETUP_TOKEN_PREFIX.len();
        let token = format!(
            "{}{}",
            ANTHROPIC_SETUP_TOKEN_PREFIX,
            "a".repeat(payload_len)
        );
        let mut config = json!({});
        let profile_id =
            persist_cli_anthropic_setup_token(temp.path().to_path_buf(), &mut config, &token)
                .unwrap();

        assert_eq!(profile_id, DEFAULT_ANTHROPIC_AUTH_PROFILE_ID);
        assert_eq!(config["anthropic"]["authProfile"], profile_id);

        let store = ProfileStore::from_env(temp.path().to_path_buf()).unwrap();
        store.load().unwrap();
        let profile = store.get(DEFAULT_ANTHROPIC_AUTH_PROFILE_ID).unwrap();
        assert_eq!(profile.provider, OAuthProvider::Anthropic);
        assert_eq!(profile.credential_kind, AuthProfileCredentialKind::Token);
        assert_eq!(profile.provider_token(), Some(token.as_str()));
    }
}
