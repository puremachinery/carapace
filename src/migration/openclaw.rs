use std::path::{Path, PathBuf};

use serde_json::Value;

use super::{push_mapping, ImportPlan, SkippedField};

/// Known OpenClaw config locations, checked in priority order.
const OPENCLAW_STATE_DIRS: &[&str] = &["~/.openclaw", "~/.clawdbot"];
const OPENCLAW_CONFIG_NAMES: &[&str] = &["openclaw.json", "clawdbot.json"];
const OPENCLAW_ENV_FILE: &str = ".env";
const OPENCLAW_CREDENTIALS_DIR: &str = "credentials";
const OPENCLAW_OAUTH_FILE: &str = "oauth.json";

/// Discovered OpenClaw installation on disk.
#[derive(Debug)]
pub struct OpenClawDiscovery {
    pub state_dir: PathBuf,
    pub config_path: PathBuf,
    pub env_path: Option<PathBuf>,
    pub credentials_path: Option<PathBuf>,
}

/// Scan standard locations for an OpenClaw installation.
pub fn discover() -> Option<OpenClawDiscovery> {
    // Check env override first.
    if let Some(path) = crate::config::read_process_env("OPENCLAW_CONFIG_PATH") {
        let config_path = PathBuf::from(path);
        if config_path.is_file() {
            let state_dir = config_path.parent().unwrap_or(Path::new(".")).to_path_buf();
            return Some(build_discovery(state_dir, config_path));
        }
    }

    if let Some(dir) = crate::config::read_process_env("OPENCLAW_STATE_DIR") {
        let state_dir = PathBuf::from(dir);
        if let Some(config_path) = find_config_in_dir(&state_dir) {
            return Some(build_discovery(state_dir, config_path));
        }
    }

    let home = dirs::home_dir()?;
    for dir_name in OPENCLAW_STATE_DIRS {
        let state_dir = home.join(dir_name.trim_start_matches("~/"));
        if let Some(config_path) = find_config_in_dir(&state_dir) {
            return Some(build_discovery(state_dir, config_path));
        }
    }

    None
}

/// Parse an OpenClaw config file and produce an import plan.
pub fn plan_import(discovery: &OpenClawDiscovery) -> ImportPlan {
    let mut plan = ImportPlan {
        source_name: "OpenClaw",
        config_path: Some(discovery.config_path.clone()),
        ..Default::default()
    };

    let config: Option<Value> = match std::fs::read_to_string(&discovery.config_path) {
        Ok(content) => match json5::from_str(&content) {
            Ok(v) => Some(v),
            Err(e) => {
                plan.warnings
                    .push(format!("Failed to parse config as JSON5: {e}"));
                None
            }
        },
        Err(e) => {
            plan.warnings.push(format!("Failed to read config: {e}"));
            None
        }
    };

    if let Some(ref config) = config {
        extract_provider_keys(config, &mut plan);
        extract_agent_defaults(config, &mut plan);
        extract_channel_tokens(config, &mut plan);
        extract_gateway_auth(config, &mut plan);
        extract_env_block(config, &mut plan);
        note_skipped_surfaces(config, &mut plan);
    }

    if let Some(ref env_path) = discovery.env_path {
        extract_dotenv_keys(env_path, &mut plan);
    }

    plan
}

// ---------------------------------------------------------------------------
// Extraction helpers
// ---------------------------------------------------------------------------

fn extract_provider_keys(config: &Value, plan: &mut ImportPlan) {
    // Direct top-level provider keys (OpenClaw sometimes stores these inline).
    try_map_secret(config, &["anthropic", "apiKey"], "anthropic.apiKey", plan);
    try_map_secret(config, &["openai", "apiKey"], "openai.apiKey", plan);
    try_map_secret(config, &["google", "apiKey"], "google.apiKey", plan);

    // models.providers section — OpenClaw's primary provider config surface.
    let providers = match config.pointer("/models/providers") {
        Some(Value::Object(map)) => map,
        _ => return,
    };

    for (name, provider_config) in providers {
        let base_url = provider_config
            .get("baseUrl")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let api_key = provider_config.get("apiKey");
        let auth = provider_config
            .get("auth")
            .and_then(|v| v.as_str())
            .unwrap_or("api-key");

        match map_provider_name(name, base_url, auth) {
            ProviderMapping::Anthropic => {
                if let Some(key) = api_key {
                    push_mapping(
                        plan,
                        format!("models.providers.{name}.apiKey"),
                        "anthropic.apiKey",
                        key.clone(),
                        true,
                    );
                }
            }
            ProviderMapping::OpenAi => {
                if let Some(key) = api_key {
                    push_mapping(
                        plan,
                        format!("models.providers.{name}.apiKey"),
                        "openai.apiKey",
                        key.clone(),
                        true,
                    );
                }
            }
            ProviderMapping::Google => {
                if let Some(key) = api_key {
                    push_mapping(
                        plan,
                        format!("models.providers.{name}.apiKey"),
                        "google.apiKey",
                        key.clone(),
                        true,
                    );
                }
            }
            ProviderMapping::Bedrock => {
                plan.skipped.push(SkippedField {
                    source_path: format!("models.providers.{name}"),
                    reason: "Bedrock credentials use env vars or cara setup; cannot import from OpenClaw provider config",
                });
            }
            ProviderMapping::Venice => {
                if let Some(key) = api_key {
                    push_mapping(
                        plan,
                        format!("models.providers.{name}.apiKey"),
                        "venice.apiKey",
                        key.clone(),
                        true,
                    );
                }
            }
            ProviderMapping::Ollama => {
                if !base_url.is_empty() {
                    push_mapping(
                        plan,
                        format!("models.providers.{name}.baseUrl"),
                        "providers.ollama.baseUrl",
                        Value::String(base_url.to_string()),
                        false,
                    );
                }
                if let Some(key) = api_key {
                    push_mapping(
                        plan,
                        format!("models.providers.{name}.apiKey"),
                        "providers.ollama.apiKey",
                        key.clone(),
                        true,
                    );
                }
            }
            ProviderMapping::Unknown => {
                plan.skipped.push(SkippedField {
                    source_path: format!("models.providers.{name}"),
                    reason: "Custom provider; no automatic Carapace mapping",
                });
            }
        }
    }
}

fn extract_agent_defaults(config: &Value, plan: &mut ImportPlan) {
    if let Some(model) = config
        .pointer("/agents/defaults/model")
        .and_then(|v| v.as_str())
    {
        let remapped = remap_model_id(model);
        push_mapping(
            plan,
            "agents.defaults.model".to_string(),
            "agents.defaults.model",
            Value::String(remapped),
            false,
        );
    }
}

fn extract_channel_tokens(config: &Value, plan: &mut ImportPlan) {
    let channel_mappings: &[(&[&str], &str)] = &[
        (&["channels", "telegram", "botToken"], "telegram.botToken"),
        (&["channels", "discord", "token"], "discord.botToken"),
        (&["channels", "slack", "botToken"], "slack.botToken"),
    ];

    for (path, carapace_key) in channel_mappings {
        try_map_secret(config, path, carapace_key, plan);
    }
}

fn extract_gateway_auth(config: &Value, plan: &mut ImportPlan) {
    try_map_secret(
        config,
        &["gateway", "auth", "token"],
        "gateway.auth.token",
        plan,
    );
    try_map_secret(
        config,
        &["gateway", "auth", "password"],
        "gateway.auth.password",
        plan,
    );
}

fn extract_env_block(config: &Value, plan: &mut ImportPlan) {
    let env = match config.get("env") {
        Some(Value::Object(map)) => map,
        _ => return,
    };

    // Skip non-string entries (shellEnv config object, vars sub-object).
    for (key, value) in env {
        if key == "shellEnv" || key == "vars" {
            continue;
        }
        if let Some(s) = value.as_str() {
            // Only import API key env vars — skip arbitrary env.
            if is_importable_env_key(key) {
                let carapace_key = env_key_to_carapace_config(key);
                if let Some(ck) = carapace_key {
                    push_mapping(
                        plan,
                        format!("env.{key}"),
                        ck,
                        Value::String(s.to_string()),
                        is_sensitive_config_key(ck),
                    );
                }
            }
        }
    }
}

fn extract_dotenv_keys(env_path: &Path, plan: &mut ImportPlan) {
    let content = match std::fs::read_to_string(env_path) {
        Ok(c) => c,
        Err(e) => {
            plan.warnings
                .push(format!("Failed to read {}: {e}", env_path.display()));
            return;
        }
    };

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            let key = key.trim();
            let value = value.trim();
            let value = value
                .strip_prefix('"')
                .and_then(|v| v.strip_suffix('"'))
                .or_else(|| value.strip_prefix('\'').and_then(|v| v.strip_suffix('\'')))
                .unwrap_or(value);
            if value.is_empty() || value.starts_with("change-me") {
                continue;
            }
            // Only import if not already mapped from the JSON config.
            if is_importable_env_key(key) {
                let carapace_key = env_key_to_carapace_config(key);
                if let Some(ck) = carapace_key {
                    if !plan.mappings.iter().any(|m| m.carapace_key == ck) {
                        push_mapping(
                            plan,
                            format!(".env:{key}"),
                            ck,
                            Value::String(value.to_string()),
                            is_sensitive_config_key(ck),
                        );
                    }
                }
            }
        }
    }
}

fn note_skipped_surfaces(config: &Value, plan: &mut ImportPlan) {
    let skippable: &[(&str, &str)] = &[
        (
            "acp",
            "Agent Control Plane config has no Carapace equivalent",
        ),
        (
            "skills",
            "Skills config format differs; use cara's plugin system",
        ),
        (
            "plugins",
            "Plugin config format differs; use cara's plugin system",
        ),
        ("session", "Session config semantics differ"),
        ("commands", "Command config semantics differ"),
        ("approvals", "Approval config semantics differ"),
        (
            "browser",
            "Browser automation config has no Carapace equivalent",
        ),
        ("mcp", "MCP server config format differs"),
        ("memory", "Memory config format differs"),
        ("cron", "Cron config format differs; use cara's task system"),
    ];

    for (key, reason) in skippable {
        if config.get(key).is_some() {
            plan.skipped.push(SkippedField {
                source_path: key.to_string(),
                reason,
            });
        }
    }
}

// ---------------------------------------------------------------------------
// Provider classification
// ---------------------------------------------------------------------------

enum ProviderMapping {
    Anthropic,
    OpenAi,
    Google,
    Bedrock,
    Venice,
    Ollama,
    Unknown,
}

fn map_provider_name(name: &str, base_url: &str, auth: &str) -> ProviderMapping {
    let name_lower = name.to_lowercase();

    if auth == "aws-sdk" || name_lower.contains("bedrock") {
        return ProviderMapping::Bedrock;
    }

    if name_lower.contains("anthropic") || base_url.contains("anthropic.com") {
        return ProviderMapping::Anthropic;
    }
    if name_lower.contains("openai") || base_url.contains("openai.com") {
        return ProviderMapping::OpenAi;
    }
    if name_lower.contains("google")
        || name_lower.contains("gemini")
        || base_url.contains("generativelanguage.googleapis.com")
    {
        return ProviderMapping::Google;
    }
    if name_lower.contains("venice") || base_url.contains("venice.ai") {
        return ProviderMapping::Venice;
    }
    if name_lower.contains("ollama") || base_url.contains("localhost:11434") {
        return ProviderMapping::Ollama;
    }

    ProviderMapping::Unknown
}

// ---------------------------------------------------------------------------
// Model ID remapping
// ---------------------------------------------------------------------------

/// Remap an OpenClaw model ID (provider/model format) to Carapace's prefix:model format.
pub fn remap_model_id(openclaw_model: &str) -> String {
    // OpenClaw uses "provider/model" format; Carapace uses "provider:model".
    if let Some((provider, model)) = openclaw_model.split_once('/') {
        let provider_lower = provider.to_lowercase();
        match provider_lower.as_str() {
            "anthropic" => format!("anthropic:{model}"),
            "openai" => format!("openai:{model}"),
            "google" | "gemini" => format!("gemini:{model}"),
            "bedrock" => format!("bedrock:{model}"),
            "vertex" => format!("vertex:{model}"),
            "ollama" => format!("ollama:{model}"),
            "venice" => format!("venice:{model}"),
            _ => openclaw_model.to_string(), // Unknown provider, keep as-is
        }
    } else {
        // No provider prefix — apply well-known model family prefixes.
        crate::migration::prefix_imported_model(openclaw_model)
    }
}

// ---------------------------------------------------------------------------
// Env var mapping
// ---------------------------------------------------------------------------

fn is_importable_env_key(key: &str) -> bool {
    matches!(
        key,
        "ANTHROPIC_API_KEY"
            | "OPENAI_API_KEY"
            | "GOOGLE_API_KEY"
            | "GEMINI_API_KEY"
            | "VENICE_API_KEY"
            | "OLLAMA_BASE_URL"
            | "OLLAMA_API_KEY"
            | "TELEGRAM_BOT_TOKEN"
            | "DISCORD_BOT_TOKEN"
            | "SLACK_BOT_TOKEN"
    )
}

fn is_sensitive_config_key(key: &str) -> bool {
    !key.contains("baseUrl") && !key.contains("base_url")
}

fn env_key_to_carapace_config(key: &str) -> Option<&'static str> {
    match key {
        "ANTHROPIC_API_KEY" => Some("anthropic.apiKey"),
        "OPENAI_API_KEY" => Some("openai.apiKey"),
        "GOOGLE_API_KEY" | "GEMINI_API_KEY" => Some("google.apiKey"),
        "VENICE_API_KEY" => Some("venice.apiKey"),
        "OLLAMA_BASE_URL" => Some("providers.ollama.baseUrl"),
        "OLLAMA_API_KEY" => Some("providers.ollama.apiKey"),
        "TELEGRAM_BOT_TOKEN" => Some("telegram.botToken"),
        "DISCORD_BOT_TOKEN" => Some("discord.botToken"),
        "SLACK_BOT_TOKEN" => Some("slack.botToken"),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Utility helpers
// ---------------------------------------------------------------------------

fn find_config_in_dir(state_dir: &Path) -> Option<PathBuf> {
    for name in OPENCLAW_CONFIG_NAMES {
        let path = state_dir.join(name);
        if path.is_file() {
            return Some(path);
        }
    }
    None
}

fn build_discovery(state_dir: PathBuf, config_path: PathBuf) -> OpenClawDiscovery {
    let env_path = state_dir.join(OPENCLAW_ENV_FILE);
    let creds_path = state_dir
        .join(OPENCLAW_CREDENTIALS_DIR)
        .join(OPENCLAW_OAUTH_FILE);
    OpenClawDiscovery {
        config_path,
        env_path: env_path.is_file().then_some(env_path),
        credentials_path: creds_path.is_file().then_some(creds_path),
        state_dir,
    }
}

fn try_map_secret(config: &Value, json_path: &[&str], carapace_key: &str, plan: &mut ImportPlan) {
    let mut current = config;
    let mut path_str = String::new();
    for (i, segment) in json_path.iter().enumerate() {
        if i > 0 {
            path_str.push('.');
        }
        path_str.push_str(segment);
        match current.get(segment) {
            Some(v) => current = v,
            None => return,
        }
    }

    if let Some(s) = current.as_str() {
        if !s.is_empty() {
            push_mapping(
                plan,
                path_str,
                carapace_key,
                Value::String(s.to_string()),
                true,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migration::ImportMapping;
    use serde_json::json;

    #[test]
    fn remap_model_anthropic() {
        assert_eq!(
            remap_model_id("anthropic/claude-opus-4-20250514"),
            "anthropic:claude-opus-4-20250514"
        );
    }

    #[test]
    fn remap_model_openai() {
        assert_eq!(remap_model_id("openai/gpt-5.5"), "openai:gpt-5.5");
    }

    #[test]
    fn remap_model_gemini() {
        assert_eq!(
            remap_model_id("gemini/gemini-2.5-flash"),
            "gemini:gemini-2.5-flash"
        );
        assert_eq!(
            remap_model_id("google/gemini-2.5-pro"),
            "gemini:gemini-2.5-pro"
        );
    }

    #[test]
    fn remap_model_bedrock() {
        assert_eq!(
            remap_model_id("bedrock/anthropic.claude-sonnet-4-6"),
            "bedrock:anthropic.claude-sonnet-4-6"
        );
    }

    #[test]
    fn remap_model_vertex() {
        assert_eq!(
            remap_model_id("vertex/gemini-2.5-flash"),
            "vertex:gemini-2.5-flash"
        );
    }

    #[test]
    fn remap_model_ollama() {
        assert_eq!(remap_model_id("ollama/llama3.2"), "ollama:llama3.2");
    }

    #[test]
    fn remap_model_bare() {
        assert_eq!(
            remap_model_id("claude-sonnet-4-6"),
            "anthropic:claude-sonnet-4-6"
        );
    }

    #[test]
    fn remap_model_unknown_provider() {
        assert_eq!(remap_model_id("custom/my-model"), "custom/my-model");
    }

    #[test]
    fn plan_import_extracts_api_keys() {
        let config = json!({
            "models": {
                "providers": {
                    "anthropic": {
                        "baseUrl": "https://api.anthropic.com",
                        "apiKey": "sk-ant-test123",
                        "models": []
                    },
                    "openai": {
                        "baseUrl": "https://api.openai.com",
                        "apiKey": "sk-test456",
                        "models": []
                    }
                }
            },
            "agents": {
                "defaults": {
                    "model": "anthropic/claude-sonnet-4-6"
                }
            }
        });

        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("openclaw.json");
        std::fs::write(&config_path, serde_json::to_string_pretty(&config).unwrap()).unwrap();

        let discovery = OpenClawDiscovery {
            state_dir: dir.path().to_path_buf(),
            config_path,
            env_path: None,
            credentials_path: None,
        };

        let plan = plan_import(&discovery);

        assert!(!plan.is_empty());
        let keys: Vec<&str> = plan
            .mappings
            .iter()
            .map(|m| m.carapace_key.as_str())
            .collect();
        assert!(keys.contains(&"anthropic.apiKey"));
        assert!(keys.contains(&"openai.apiKey"));
        assert!(keys.contains(&"agents.defaults.model"));

        let model_mapping = plan
            .mappings
            .iter()
            .find(|m| m.carapace_key == "agents.defaults.model")
            .unwrap();
        assert_eq!(model_mapping.value, json!("anthropic:claude-sonnet-4-6"));
    }

    #[test]
    fn plan_import_skips_unsupported_surfaces() {
        let config = json!({
            "acp": { "some": "config" },
            "skills": { "list": [] },
            "browser": { "headless": true }
        });

        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("openclaw.json");
        std::fs::write(&config_path, serde_json::to_string_pretty(&config).unwrap()).unwrap();

        let discovery = OpenClawDiscovery {
            state_dir: dir.path().to_path_buf(),
            config_path,
            env_path: None,
            credentials_path: None,
        };

        let plan = plan_import(&discovery);

        assert!(plan.is_empty());
        let skipped_paths: Vec<&str> = plan
            .skipped
            .iter()
            .map(|s| s.source_path.as_str())
            .collect();
        assert!(skipped_paths.contains(&"acp"));
        assert!(skipped_paths.contains(&"skills"));
        assert!(skipped_paths.contains(&"browser"));
    }

    #[test]
    fn plan_import_extracts_channel_tokens() {
        let config = json!({
            "channels": {
                "telegram": { "botToken": "123456:ABCDEF" },
                "discord": { "token": "discord-bot-token" }
            }
        });

        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("openclaw.json");
        std::fs::write(&config_path, serde_json::to_string_pretty(&config).unwrap()).unwrap();

        let discovery = OpenClawDiscovery {
            state_dir: dir.path().to_path_buf(),
            config_path,
            env_path: None,
            credentials_path: None,
        };

        let plan = plan_import(&discovery);
        let keys: Vec<&str> = plan
            .mappings
            .iter()
            .map(|m| m.carapace_key.as_str())
            .collect();
        assert!(keys.contains(&"telegram.botToken"));
        assert!(keys.contains(&"discord.botToken"));
    }

    #[test]
    fn plan_import_reads_dotenv() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("openclaw.json");
        std::fs::write(&config_path, "{}").unwrap();

        let env_path = dir.path().join(".env");
        std::fs::write(
            &env_path,
            "# comment\nANTHROPIC_API_KEY=sk-ant-from-env\nIRRELEVANT_VAR=skip\n",
        )
        .unwrap();

        let discovery = OpenClawDiscovery {
            state_dir: dir.path().to_path_buf(),
            config_path,
            env_path: Some(env_path),
            credentials_path: None,
        };

        let plan = plan_import(&discovery);
        assert_eq!(plan.mappings.len(), 1);
        assert_eq!(plan.mappings[0].carapace_key, "anthropic.apiKey");
        assert_eq!(plan.mappings[0].value, json!("sk-ant-from-env"));
    }

    #[test]
    fn plan_import_json_config_takes_precedence_over_dotenv() {
        let config = json!({
            "anthropic": { "apiKey": "from-json" }
        });

        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("openclaw.json");
        std::fs::write(&config_path, serde_json::to_string_pretty(&config).unwrap()).unwrap();

        let env_path = dir.path().join(".env");
        std::fs::write(&env_path, "ANTHROPIC_API_KEY=from-env\n").unwrap();

        let discovery = OpenClawDiscovery {
            state_dir: dir.path().to_path_buf(),
            config_path,
            env_path: Some(env_path),
            credentials_path: None,
        };

        let plan = plan_import(&discovery);
        let anthropic = plan
            .mappings
            .iter()
            .find(|m| m.carapace_key == "anthropic.apiKey")
            .unwrap();
        assert_eq!(anthropic.value, json!("from-json"));
        // Should not have a duplicate from .env
        assert_eq!(
            plan.mappings
                .iter()
                .filter(|m| m.carapace_key == "anthropic.apiKey")
                .count(),
            1
        );
    }

    #[test]
    fn plan_import_bedrock_provider_skipped() {
        let config = json!({
            "models": {
                "providers": {
                    "my-bedrock": {
                        "baseUrl": "https://bedrock-runtime.us-east-1.amazonaws.com",
                        "auth": "aws-sdk",
                        "models": []
                    }
                }
            }
        });

        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("openclaw.json");
        std::fs::write(&config_path, serde_json::to_string_pretty(&config).unwrap()).unwrap();

        let discovery = OpenClawDiscovery {
            state_dir: dir.path().to_path_buf(),
            config_path,
            env_path: None,
            credentials_path: None,
        };

        let plan = plan_import(&discovery);
        assert!(plan.is_empty());
        assert!(plan
            .skipped
            .iter()
            .any(|s| s.source_path.contains("my-bedrock")));
    }

    #[test]
    fn build_carapace_config_nests_correctly() {
        let plan = ImportPlan {
            mappings: vec![
                ImportMapping {
                    source_path: "test".to_string(),
                    carapace_key: "anthropic.apiKey".to_string(),
                    value: json!("sk-test"),
                    sensitive: true,
                },
                ImportMapping {
                    source_path: "test".to_string(),
                    carapace_key: "agents.defaults.model".to_string(),
                    value: json!("claude-sonnet-4-6"),
                    sensitive: false,
                },
            ],
            ..Default::default()
        };

        let config = plan.build_carapace_config();
        assert_eq!(config["anthropic"]["apiKey"], "sk-test");
        assert_eq!(config["agents"]["defaults"]["model"], "claude-sonnet-4-6");
    }

    #[test]
    fn set_nested_creates_intermediate_objects() {
        use crate::migration::set_nested;
        let mut config = json!({});
        set_nested(&mut config, "a.b.c", json!("deep"));
        assert_eq!(config["a"]["b"]["c"], "deep");
    }

    #[test]
    fn provider_mapping_by_base_url() {
        assert!(matches!(
            map_provider_name("my-llm", "https://api.anthropic.com/v1", "api-key"),
            ProviderMapping::Anthropic
        ));
        assert!(matches!(
            map_provider_name("my-llm", "https://api.openai.com/v1", "api-key"),
            ProviderMapping::OpenAi
        ));
        assert!(matches!(
            map_provider_name(
                "my-llm",
                "https://generativelanguage.googleapis.com",
                "api-key"
            ),
            ProviderMapping::Google
        ));
        assert!(matches!(
            map_provider_name("my-llm", "http://localhost:11434", "api-key"),
            ProviderMapping::Ollama
        ));
    }

    #[test]
    fn provider_mapping_by_name() {
        assert!(matches!(
            map_provider_name("anthropic", "", "api-key"),
            ProviderMapping::Anthropic
        ));
        assert!(matches!(
            map_provider_name("openai-custom", "", "api-key"),
            ProviderMapping::OpenAi
        ));
        assert!(matches!(
            map_provider_name("gemini", "", "api-key"),
            ProviderMapping::Google
        ));
        assert!(matches!(
            map_provider_name("my-bedrock", "", "aws-sdk"),
            ProviderMapping::Bedrock
        ));
    }

    #[test]
    fn provider_mapping_unknown() {
        assert!(matches!(
            map_provider_name("custom-thing", "https://custom.ai/v1", "api-key"),
            ProviderMapping::Unknown
        ));
    }
}
