use std::path::PathBuf;

use serde_json::Value;

use super::{push_mapping, ImportPlan, SkippedField};

/// Discovered NemoClaw installation on disk.
#[derive(Debug)]
pub struct NemoClawDiscovery {
    pub config_path: PathBuf,
}

/// Scan standard locations for a NemoClaw config.
pub fn discover() -> Option<NemoClawDiscovery> {
    let home = dirs::home_dir()?;
    let path = home.join(".nemoclaw").join("config.json");
    if path.is_file() {
        return Some(NemoClawDiscovery { config_path: path });
    }

    None
}

/// Parse a NemoClaw config and produce an import plan.
pub fn plan_import(discovery: &NemoClawDiscovery) -> ImportPlan {
    let mut plan = ImportPlan {
        source_name: "NemoClaw",
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

    extract_inference_config(&config, &mut plan);

    plan
}

fn extract_inference_config(config: &Value, plan: &mut ImportPlan) {
    let endpoint_type = config
        .get("endpointType")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    let endpoint_url = config
        .get("endpointUrl")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    let credential_env = config
        .get("credentialEnv")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    let model = config.get("model").and_then(|v| v.as_str()).unwrap_or("");

    // NemoClaw stores the env var name, not the credential itself.
    // Resolve the actual value from the environment.
    let credential_value = if !credential_env.is_empty() {
        crate::config::read_process_env(credential_env).filter(|v| !v.is_empty())
    } else {
        None
    };

    match endpoint_type {
        "anthropic" => {
            if let Some(ref key) = credential_value {
                push_mapping(
                    plan,
                    format!("credentialEnv ({credential_env})"),
                    "anthropic.apiKey",
                    Value::String(key.clone()),
                    true,
                );
            } else if !credential_env.is_empty() {
                plan.warnings.push(format!(
                    "NemoClaw references ${credential_env} for Anthropic but it is not set"
                ));
            }
        }
        "openai" | "openai-compatible" => {
            if let Some(ref key) = credential_value {
                push_mapping(
                    plan,
                    format!("credentialEnv ({credential_env})"),
                    "openai.apiKey",
                    Value::String(key.clone()),
                    true,
                );
            } else if !credential_env.is_empty() {
                plan.warnings.push(format!(
                    "NemoClaw references ${credential_env} for OpenAI but it is not set"
                ));
            }
            if !endpoint_url.is_empty() {
                push_mapping(
                    plan,
                    "endpointUrl".to_string(),
                    "openai.baseUrl",
                    Value::String(endpoint_url.to_string()),
                    false,
                );
            }
        }
        "gemini" => {
            if let Some(ref key) = credential_value {
                push_mapping(
                    plan,
                    format!("credentialEnv ({credential_env})"),
                    "google.apiKey",
                    Value::String(key.clone()),
                    true,
                );
            } else if !credential_env.is_empty() {
                plan.warnings.push(format!(
                    "NemoClaw references ${credential_env} for Gemini but it is not set"
                ));
            }
        }
        "ollama" => {
            if !endpoint_url.is_empty() {
                push_mapping(
                    plan,
                    "endpointUrl".to_string(),
                    "providers.ollama.baseUrl",
                    Value::String(endpoint_url.to_string()),
                    false,
                );
            }
        }
        "ncp" | "nim-local" | "vllm" | "build" | "custom" => {
            plan.skipped.push(SkippedField {
                source_path: format!("endpointType: {endpoint_type}"),
                reason: "NVIDIA/custom inference endpoint has no Carapace equivalent",
            });
        }
        _ => {}
    }

    if !model.is_empty() {
        let remapped = match endpoint_type {
            "ollama" if !model.starts_with("ollama:") => format!("ollama:{model}"),
            _ => model.to_string(),
        };
        push_mapping(
            plan,
            "model".to_string(),
            "agents.defaults.model",
            Value::String(remapped),
            false,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::env::ScopedEnv;
    use serde_json::json;

    #[test]
    fn plan_extracts_anthropic() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.json");
        std::fs::write(
            &config_path,
            serde_json::to_string_pretty(&json!({
                "endpointType": "anthropic",
                "credentialEnv": "ANTHROPIC_API_KEY",
                "model": "claude-3-5-sonnet-20241022"
            }))
            .unwrap(),
        )
        .unwrap();

        // Set the env var so the credential resolves.
        let mut env = ScopedEnv::new();
        env.set("ANTHROPIC_API_KEY", "sk-ant-test");

        let discovery = NemoClawDiscovery { config_path };
        let plan = plan_import(&discovery);

        let keys: Vec<&str> = plan
            .mappings
            .iter()
            .map(|m| m.carapace_key.as_str())
            .collect();
        assert!(keys.contains(&"anthropic.apiKey"));
        assert!(keys.contains(&"agents.defaults.model"));
    }

    #[test]
    fn plan_extracts_openai_with_url() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.json");
        std::fs::write(
            &config_path,
            serde_json::to_string_pretty(&json!({
                "endpointType": "openai",
                "endpointUrl": "https://api.openai.com/v1",
                "credentialEnv": "OPENAI_API_KEY",
                "model": "gpt-5.5"
            }))
            .unwrap(),
        )
        .unwrap();

        let mut env = ScopedEnv::new();
        env.set("OPENAI_API_KEY", "sk-test");

        let discovery = NemoClawDiscovery { config_path };
        let plan = plan_import(&discovery);

        let keys: Vec<&str> = plan
            .mappings
            .iter()
            .map(|m| m.carapace_key.as_str())
            .collect();
        assert!(keys.contains(&"openai.apiKey"));
        assert!(keys.contains(&"openai.baseUrl"));
        assert!(keys.contains(&"agents.defaults.model"));
    }

    #[test]
    fn plan_extracts_ollama() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.json");
        std::fs::write(
            &config_path,
            serde_json::to_string_pretty(&json!({
                "endpointType": "ollama",
                "endpointUrl": "http://localhost:11434",
                "model": "llama3.2"
            }))
            .unwrap(),
        )
        .unwrap();

        let discovery = NemoClawDiscovery { config_path };
        let plan = plan_import(&discovery);

        let keys: Vec<&str> = plan
            .mappings
            .iter()
            .map(|m| m.carapace_key.as_str())
            .collect();
        assert!(keys.contains(&"providers.ollama.baseUrl"));
        assert!(keys.contains(&"agents.defaults.model"));
        let model = plan
            .mappings
            .iter()
            .find(|m| m.carapace_key == "agents.defaults.model")
            .unwrap();
        assert_eq!(model.value, json!("ollama:llama3.2"));
    }

    #[test]
    fn plan_skips_nvidia_endpoints() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.json");
        std::fs::write(
            &config_path,
            serde_json::to_string_pretty(&json!({
                "endpointType": "nim-local",
                "endpointUrl": "http://localhost:8000",
                "model": "meta/llama3-70b"
            }))
            .unwrap(),
        )
        .unwrap();

        let discovery = NemoClawDiscovery { config_path };
        let plan = plan_import(&discovery);

        // Model is still imported even if endpoint type is skipped.
        assert!(plan
            .mappings
            .iter()
            .any(|m| m.carapace_key == "agents.defaults.model"));
        assert!(plan
            .skipped
            .iter()
            .any(|s| s.source_path.contains("nim-local")));
    }

    #[test]
    fn plan_warns_on_missing_credential_env() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.json");
        std::fs::write(
            &config_path,
            serde_json::to_string_pretty(&json!({
                "endpointType": "anthropic",
                "credentialEnv": "NEMOCLAW_TEST_MISSING_KEY_12345"
            }))
            .unwrap(),
        )
        .unwrap();

        let discovery = NemoClawDiscovery { config_path };
        let plan = plan_import(&discovery);

        assert!(plan.is_empty());
        assert!(plan
            .warnings
            .iter()
            .any(|w| w.contains("NEMOCLAW_TEST_MISSING_KEY_12345")));
    }

    #[test]
    fn plan_handles_empty_config() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.json");
        std::fs::write(&config_path, "{}").unwrap();

        let discovery = NemoClawDiscovery { config_path };
        let plan = plan_import(&discovery);
        assert!(plan.is_empty());
    }
}
