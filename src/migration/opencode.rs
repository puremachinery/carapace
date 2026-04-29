use std::path::{Path, PathBuf};

use serde_json::Value;

use super::{push_mapping, ImportPlan, SkippedField};

const OPENCODE_CONFIG_NAMES: &[&str] = &[".opencode.json"];

/// Discovered OpenCode installation on disk.
#[derive(Debug)]
pub struct OpenCodeDiscovery {
    pub config_path: PathBuf,
}

/// Scan standard locations for an OpenCode config file.
pub fn discover() -> Option<OpenCodeDiscovery> {
    // Check local directory first (OpenCode project-level config).
    for name in OPENCODE_CONFIG_NAMES {
        let local = PathBuf::from(name);
        if local.is_file() {
            return Some(OpenCodeDiscovery { config_path: local });
        }
    }

    // XDG config.
    if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME") {
        let path = Path::new(&xdg).join("opencode").join(".opencode.json");
        if path.is_file() {
            return Some(OpenCodeDiscovery { config_path: path });
        }
    }

    // Home directory.
    let home = dirs::home_dir()?;
    let path = home.join(".opencode.json");
    if path.is_file() {
        return Some(OpenCodeDiscovery { config_path: path });
    }

    // XDG fallback (~/.config/opencode/).
    let xdg_default = home.join(".config").join("opencode").join(".opencode.json");
    if xdg_default.is_file() {
        return Some(OpenCodeDiscovery {
            config_path: xdg_default,
        });
    }

    None
}

/// Parse an OpenCode config file and produce an import plan.
pub fn plan_import(discovery: &OpenCodeDiscovery) -> ImportPlan {
    let mut plan = ImportPlan {
        source_name: "OpenCode",
        config_path: Some(discovery.config_path.clone()),
        ..Default::default()
    };

    let content = match std::fs::read_to_string(&discovery.config_path) {
        Ok(c) => c,
        Err(e) => {
            plan.warnings.push(format!("Failed to read config: {e}"));
            return plan;
        }
    };

    let config: Value = match serde_json::from_str(&content) {
        Ok(v) => v,
        Err(e) => {
            plan.warnings
                .push(format!("Failed to parse config as JSON: {e}"));
            return plan;
        }
    };

    extract_providers(&config, &mut plan);
    extract_agent_model(&config, &mut plan);
    note_skipped_surfaces(&config, &mut plan);

    plan
}

// ---------------------------------------------------------------------------
// Extraction helpers
// ---------------------------------------------------------------------------

fn extract_providers(config: &Value, plan: &mut ImportPlan) {
    let providers = match config.get("providers") {
        Some(Value::Object(map)) => map,
        _ => return,
    };

    for (name, provider_config) in providers {
        let disabled = provider_config
            .get("disabled")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if disabled {
            continue;
        }

        let api_key = match provider_config.get("apiKey").and_then(|v| v.as_str()) {
            Some(k) if !k.is_empty() => k,
            _ => continue,
        };

        match map_provider(name) {
            Some(carapace_key) => {
                push_mapping(
                    plan,
                    format!("providers.{name}.apiKey"),
                    carapace_key,
                    Value::String(api_key.to_string()),
                    true,
                );
            }
            None => {
                plan.skipped.push(SkippedField {
                    source_path: format!("providers.{name}"),
                    reason: provider_skip_reason(name),
                });
            }
        }
    }
}

fn extract_agent_model(config: &Value, plan: &mut ImportPlan) {
    // The "coder" agent is the primary agent, equivalent to Carapace's default model.
    let model = config
        .pointer("/agents/coder/model")
        .and_then(|v| v.as_str());

    if let Some(model_id) = model {
        let remapped = remap_model_id(model_id);
        push_mapping(
            plan,
            "agents.coder.model".to_string(),
            "agents.defaults.model",
            Value::String(remapped),
            false,
        );
    }
}

fn note_skipped_surfaces(config: &Value, plan: &mut ImportPlan) {
    let skippable: &[(&str, &str)] = &[
        ("mcpServers", "MCP server config format differs"),
        ("lsp", "LSP config has no Carapace equivalent"),
        ("tui", "TUI config has no Carapace equivalent"),
        ("contextPaths", "Context paths semantics differ"),
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
// Provider mapping
// ---------------------------------------------------------------------------

fn map_provider(name: &str) -> Option<&'static str> {
    match name {
        "anthropic" => Some("anthropic.apiKey"),
        "openai" => Some("openai.apiKey"),
        "gemini" => Some("google.apiKey"),
        "venice" => Some("venice.apiKey"),
        _ => None,
    }
}

fn provider_skip_reason(name: &str) -> &'static str {
    match name {
        "groq" => "Groq provider has no Carapace equivalent",
        "openrouter" => "OpenRouter provider has no Carapace equivalent",
        "azure" => {
            "Azure OpenAI has no direct Carapace mapping; use cara setup with a supported provider"
        }
        "copilot" => "GitHub Copilot auth uses OAuth; not importable as a static key",
        "bedrock" => "Bedrock credentials use env vars or cara setup; cannot import a static key",
        "vertexai" => "VertexAI uses ADC/config; cannot import a static key",
        "xai" => "xAI provider has no Carapace equivalent",
        _ => "Unknown provider; no Carapace mapping",
    }
}

// ---------------------------------------------------------------------------
// Model ID remapping
// ---------------------------------------------------------------------------

/// Remap an OpenCode model ID to Carapace format.
///
/// OpenCode uses bare model IDs (e.g., `claude-4-sonnet-20250514`) or
/// dotted provider prefixes for Bedrock (e.g., `bedrock.claude-3.7-sonnet`).
pub fn remap_model_id(opencode_model: &str) -> String {
    // OpenCode Bedrock models use "bedrock." prefix with dots.
    if let Some(rest) = opencode_model.strip_prefix("bedrock.") {
        return format!("bedrock:{rest}");
    }

    // Bare well-known model families need a provider prefix for Carapace routing.
    crate::migration::prefix_imported_model(opencode_model)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn remap_model_bare() {
        assert_eq!(
            remap_model_id("claude-4-sonnet-20250514"),
            "anthropic:claude-4-sonnet-20250514"
        );
    }

    #[test]
    fn remap_model_bedrock() {
        assert_eq!(
            remap_model_id("bedrock.claude-3.7-sonnet"),
            "bedrock:claude-3.7-sonnet"
        );
    }

    #[test]
    fn remap_model_gpt() {
        assert_eq!(remap_model_id("gpt-4o"), "openai:gpt-4o");
    }

    #[test]
    fn remap_model_gemini() {
        assert_eq!(
            remap_model_id("gemini-2.5-pro-preview"),
            "gemini:gemini-2.5-pro-preview"
        );
    }

    #[test]
    fn plan_extracts_provider_keys() {
        let config = json!({
            "providers": {
                "anthropic": { "apiKey": "sk-ant-test" },
                "openai": { "apiKey": "sk-test" },
                "groq": { "apiKey": "gsk-test" }
            },
            "agents": {
                "coder": { "model": "claude-4-sonnet-20250514", "maxTokens": 16000 }
            }
        });

        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join(".opencode.json");
        std::fs::write(&config_path, serde_json::to_string_pretty(&config).unwrap()).unwrap();

        let discovery = OpenCodeDiscovery { config_path };
        let plan = plan_import(&discovery);

        let keys: Vec<&str> = plan
            .mappings
            .iter()
            .map(|m| m.carapace_key.as_str())
            .collect();
        assert!(keys.contains(&"anthropic.apiKey"));
        assert!(keys.contains(&"openai.apiKey"));
        assert!(keys.contains(&"agents.defaults.model"));
        // groq should be skipped
        assert!(!keys.contains(&"groq.apiKey"));
        assert!(plan.skipped.iter().any(|s| s.source_path.contains("groq")));
    }

    #[test]
    fn plan_skips_disabled_providers() {
        let config = json!({
            "providers": {
                "anthropic": { "apiKey": "sk-ant-test", "disabled": true }
            }
        });

        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join(".opencode.json");
        std::fs::write(&config_path, serde_json::to_string_pretty(&config).unwrap()).unwrap();

        let discovery = OpenCodeDiscovery { config_path };
        let plan = plan_import(&discovery);
        assert!(plan.is_empty());
    }

    #[test]
    fn plan_skips_unsupported_surfaces() {
        let config = json!({
            "mcpServers": { "some": {} },
            "lsp": { "go": {} },
            "tui": { "theme": "dark" }
        });

        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join(".opencode.json");
        std::fs::write(&config_path, serde_json::to_string_pretty(&config).unwrap()).unwrap();

        let discovery = OpenCodeDiscovery { config_path };
        let plan = plan_import(&discovery);

        assert!(plan.is_empty());
        let skipped: Vec<&str> = plan
            .skipped
            .iter()
            .map(|s| s.source_path.as_str())
            .collect();
        assert!(skipped.contains(&"mcpServers"));
        assert!(skipped.contains(&"lsp"));
        assert!(skipped.contains(&"tui"));
    }

    #[test]
    fn plan_skips_empty_api_keys() {
        let config = json!({
            "providers": {
                "anthropic": { "apiKey": "" },
                "openai": { "apiKey": "sk-real" }
            }
        });

        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join(".opencode.json");
        std::fs::write(&config_path, serde_json::to_string_pretty(&config).unwrap()).unwrap();

        let discovery = OpenCodeDiscovery { config_path };
        let plan = plan_import(&discovery);

        assert_eq!(plan.mappings.len(), 1);
        assert_eq!(plan.mappings[0].carapace_key, "openai.apiKey");
    }

    #[test]
    fn plan_extracts_coder_model() {
        let config = json!({
            "agents": {
                "coder": { "model": "bedrock.claude-3.7-sonnet" }
            }
        });

        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join(".opencode.json");
        std::fs::write(&config_path, serde_json::to_string_pretty(&config).unwrap()).unwrap();

        let discovery = OpenCodeDiscovery { config_path };
        let plan = plan_import(&discovery);

        let model = plan
            .mappings
            .iter()
            .find(|m| m.carapace_key == "agents.defaults.model")
            .unwrap();
        assert_eq!(model.value, json!("bedrock:claude-3.7-sonnet"));
    }
}
