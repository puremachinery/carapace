use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde_json::Value;

use super::{push_mapping, ImportPlan, SkippedField};

const AIDER_CONFIG_NAME: &str = ".aider.conf.yml";
const AIDER_ENV_NAME: &str = ".env";

/// Discovered Aider installation on disk.
#[derive(Debug)]
pub struct AiderDiscovery {
    pub config_path: Option<PathBuf>,
    pub env_path: Option<PathBuf>,
}

/// Scan standard locations for Aider config files.
pub fn discover() -> Option<AiderDiscovery> {
    let home = dirs::home_dir();

    let home_config = home.as_ref().map(|h| h.join(AIDER_CONFIG_NAME));
    let local_config = PathBuf::from(AIDER_CONFIG_NAME);

    // Prefer local project config over home config.
    let config_path = if local_config.is_file() {
        Some(local_config)
    } else if home_config.as_ref().is_some_and(|p| p.is_file()) {
        home_config
    } else {
        None
    };

    // Aider reads .env from the git root; check current dir.
    let env_path = PathBuf::from(AIDER_ENV_NAME);
    let env_path = env_path.is_file().then_some(env_path);

    if config_path.is_none() && env_path.is_none() {
        return None;
    }

    Some(AiderDiscovery {
        config_path,
        env_path,
    })
}

/// Parse Aider config files and produce an import plan.
pub fn plan_import(discovery: &AiderDiscovery) -> ImportPlan {
    let mut plan = ImportPlan {
        source_name: "Aider",
        config_path: discovery.config_path.clone(),
        ..Default::default()
    };

    if let Some(ref config_path) = discovery.config_path {
        extract_yaml_config(config_path, &mut plan);
    }

    if let Some(ref env_path) = discovery.env_path {
        extract_dotenv(env_path, &mut plan);
    }

    plan
}

// ---------------------------------------------------------------------------
// YAML extraction
// ---------------------------------------------------------------------------

fn extract_yaml_config(path: &Path, plan: &mut ImportPlan) {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => {
            plan.warnings
                .push(format!("Failed to read {}: {e}", path.display()));
            return;
        }
    };

    let entries = parse_flat_yaml(&content);

    if let Some(key) = entries.get("openai-api-key").filter(|v| !v.is_empty()) {
        push_mapping(
            plan,
            "openai-api-key".to_string(),
            "openai.apiKey",
            Value::String(key.clone()),
            true,
        );
    }

    if let Some(key) = entries.get("anthropic-api-key").filter(|v| !v.is_empty()) {
        push_mapping(
            plan,
            "anthropic-api-key".to_string(),
            "anthropic.apiKey",
            Value::String(key.clone()),
            true,
        );
    }

    if let Some(model) = entries.get("model").filter(|v| !v.is_empty()) {
        let remapped = remap_model_id(model);
        push_mapping(
            plan,
            "model".to_string(),
            "agents.defaults.model",
            Value::String(remapped),
            false,
        );
    }

    let skippable: &[(&str, &str)] = &[
        ("auto-commits", "Git commit settings differ"),
        ("lint-cmd", "Lint config has no Carapace equivalent"),
        ("test-cmd", "Test config has no Carapace equivalent"),
        ("dark-mode", "Display settings have no Carapace equivalent"),
        ("light-mode", "Display settings have no Carapace equivalent"),
        ("voice-format", "Voice settings have no Carapace equivalent"),
        (
            "map-tokens",
            "Repo map settings have no Carapace equivalent",
        ),
        ("edit-format", "Edit format has no Carapace equivalent"),
        ("architect", "Architect mode has no Carapace equivalent"),
    ];
    for (key, reason) in skippable {
        if entries.contains_key(*key) {
            plan.skipped.push(SkippedField {
                source_path: key.to_string(),
                reason,
            });
        }
    }
}

/// Parse a flat YAML file into key-value string pairs.
/// Only handles top-level `key: value` lines (sufficient for Aider's config).
fn parse_flat_yaml(content: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((key, value)) = line.split_once(':') {
            let key = key.trim();
            let value = value.trim();
            if value.starts_with('-') || value.starts_with('[') || value.starts_with('{') {
                // Skip list/object values.
                map.insert(key.to_string(), String::new());
                continue;
            }
            let value = value
                .strip_prefix('"')
                .and_then(|v| v.strip_suffix('"'))
                .or_else(|| value.strip_prefix('\'').and_then(|v| v.strip_suffix('\'')))
                .unwrap_or(value);
            map.insert(key.to_string(), value.to_string());
        }
    }
    map
}

// ---------------------------------------------------------------------------
// .env extraction
// ---------------------------------------------------------------------------

fn extract_dotenv(path: &Path, plan: &mut ImportPlan) {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => {
            plan.warnings
                .push(format!("Failed to read {}: {e}", path.display()));
            return;
        }
    };

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        let value = value.trim();
        let value = value
            .strip_prefix('"')
            .and_then(|v| v.strip_suffix('"'))
            .or_else(|| value.strip_prefix('\'').and_then(|v| v.strip_suffix('\'')))
            .unwrap_or(value);

        if value.is_empty() {
            continue;
        }

        let (carapace_key, sensitive) = match key {
            "OPENAI_API_KEY" | "AIDER_OPENAI_API_KEY" => ("openai.apiKey", true),
            "ANTHROPIC_API_KEY" | "AIDER_ANTHROPIC_API_KEY" => ("anthropic.apiKey", true),
            "GEMINI_API_KEY" => ("google.apiKey", true),
            "AIDER_MODEL" => ("agents.defaults.model", false),
            _ => continue,
        };

        if carapace_key == "agents.defaults.model" {
            let remapped = remap_model_id(value);
            push_mapping(
                plan,
                format!(".env:{key}"),
                carapace_key,
                Value::String(remapped),
                sensitive,
            );
        } else {
            push_mapping(
                plan,
                format!(".env:{key}"),
                carapace_key,
                Value::String(value.to_string()),
                sensitive,
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Model ID remapping
// ---------------------------------------------------------------------------

/// Remap an Aider model ID to Carapace format.
///
/// Aider uses litellm-style model identifiers. Most are bare names that
/// Carapace understands directly. Provider-prefixed ones need translation.
pub fn remap_model_id(aider_model: &str) -> String {
    // Aider uses litellm prefixes like "openrouter/...", "bedrock/...", "vertex_ai/..."
    if let Some(rest) = aider_model.strip_prefix("bedrock/") {
        return format!("bedrock:{rest}");
    }
    if let Some(rest) = aider_model.strip_prefix("vertex_ai/") {
        return format!("vertex:{rest}");
    }
    if let Some(rest) = aider_model.strip_prefix("ollama/") {
        return format!("ollama:{rest}");
    }
    // openrouter/, azure/, groq/ prefixes have no Carapace equivalent — pass through.
    // Bare well-known model families need a provider prefix for Carapace routing.
    crate::migration::prefix_bare_model(aider_model)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn remap_model_bare_claude() {
        assert_eq!(
            remap_model_id("claude-3-5-sonnet-20241022"),
            "claude-3-5-sonnet-20241022"
        );
    }

    #[test]
    fn remap_model_bare_gpt() {
        assert_eq!(remap_model_id("gpt-4o"), "openai:gpt-4o");
    }

    #[test]
    fn remap_model_bedrock() {
        assert_eq!(
            remap_model_id("bedrock/anthropic.claude-3-5-sonnet-20241022-v2:0"),
            "bedrock:anthropic.claude-3-5-sonnet-20241022-v2:0"
        );
    }

    #[test]
    fn remap_model_vertex() {
        assert_eq!(
            remap_model_id("vertex_ai/gemini-2.5-flash"),
            "vertex:gemini-2.5-flash"
        );
    }

    #[test]
    fn remap_model_ollama() {
        assert_eq!(remap_model_id("ollama/llama3"), "ollama:llama3");
    }

    #[test]
    fn remap_model_openrouter_passthrough() {
        assert_eq!(
            remap_model_id("openrouter/anthropic/claude-3-opus"),
            "openrouter/anthropic/claude-3-opus"
        );
    }

    #[test]
    fn plan_extracts_yaml_keys() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join(".aider.conf.yml");
        std::fs::write(
            &config_path,
            "openai-api-key: sk-test\nanthropic-api-key: sk-ant-test\nmodel: claude-3-5-sonnet-20241022\nauto-commits: true\n",
        )
        .unwrap();

        let discovery = AiderDiscovery {
            config_path: Some(config_path),
            env_path: None,
        };

        let plan = plan_import(&discovery);
        let keys: Vec<&str> = plan
            .mappings
            .iter()
            .map(|m| m.carapace_key.as_str())
            .collect();
        assert!(keys.contains(&"openai.apiKey"));
        assert!(keys.contains(&"anthropic.apiKey"));
        assert!(keys.contains(&"agents.defaults.model"));
        assert!(plan.skipped.iter().any(|s| s.source_path == "auto-commits"));
    }

    #[test]
    fn plan_extracts_dotenv_keys() {
        let dir = tempfile::tempdir().unwrap();
        let env_path = dir.path().join(".env");
        std::fs::write(
            &env_path,
            "ANTHROPIC_API_KEY=sk-ant-from-env\nGEMINI_API_KEY=gem-key\nAIDER_MODEL=gpt-4o\nAIDER_DARK_MODE=true\n",
        )
        .unwrap();

        let discovery = AiderDiscovery {
            config_path: None,
            env_path: Some(env_path),
        };

        let plan = plan_import(&discovery);
        let keys: Vec<&str> = plan
            .mappings
            .iter()
            .map(|m| m.carapace_key.as_str())
            .collect();
        assert!(keys.contains(&"anthropic.apiKey"));
        assert!(keys.contains(&"google.apiKey"));
        assert!(keys.contains(&"agents.defaults.model"));
        // AIDER_DARK_MODE should not be imported
        assert!(!keys.iter().any(|k| k.contains("dark")));
    }

    #[test]
    fn yaml_takes_precedence_over_dotenv() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join(".aider.conf.yml");
        std::fs::write(&config_path, "anthropic-api-key: from-yaml\n").unwrap();

        let env_path = dir.path().join(".env");
        std::fs::write(&env_path, "ANTHROPIC_API_KEY=from-env\n").unwrap();

        let discovery = AiderDiscovery {
            config_path: Some(config_path),
            env_path: Some(env_path),
        };

        let plan = plan_import(&discovery);
        let anthropic = plan
            .mappings
            .iter()
            .find(|m| m.carapace_key == "anthropic.apiKey")
            .unwrap();
        assert_eq!(anthropic.value, json!("from-yaml"));
        assert_eq!(
            plan.mappings
                .iter()
                .filter(|m| m.carapace_key == "anthropic.apiKey")
                .count(),
            1
        );
    }

    #[test]
    fn plan_handles_empty_config() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join(".aider.conf.yml");
        std::fs::write(&config_path, "# empty config\n").unwrap();

        let discovery = AiderDiscovery {
            config_path: Some(config_path),
            env_path: None,
        };

        let plan = plan_import(&discovery);
        assert!(plan.is_empty());
    }

    #[test]
    fn dotenv_model_remapped() {
        let dir = tempfile::tempdir().unwrap();
        let env_path = dir.path().join(".env");
        std::fs::write(
            &env_path,
            "AIDER_MODEL=bedrock/anthropic.claude-3-5-sonnet-20241022-v2:0\n",
        )
        .unwrap();

        let discovery = AiderDiscovery {
            config_path: None,
            env_path: Some(env_path),
        };

        let plan = plan_import(&discovery);
        let model = plan
            .mappings
            .iter()
            .find(|m| m.carapace_key == "agents.defaults.model")
            .unwrap();
        assert_eq!(
            model.value,
            json!("bedrock:anthropic.claude-3-5-sonnet-20241022-v2:0")
        );
    }
}
