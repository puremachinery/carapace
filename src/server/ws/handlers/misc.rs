//! Miscellaneous handlers (models, agents).
//!
//! This module contains handlers for models and agents list operations.
//! TTS, voicewake, wizard, talk, update, and usage handlers have been
//! moved to their own dedicated modules.

use serde_json::{json, Value};

use super::super::*;
use crate::agent::DEFAULT_MODEL;

/// List available models
pub(super) fn handle_models_list() -> Result<Value, ErrorShape> {
    let cfg = config::load_config().unwrap_or(Value::Object(serde_json::Map::new()));
    let mut models = Vec::new();

    // Check for models in agents.defaults.models
    if let Some(map) = cfg
        .get("agents")
        .and_then(|v| v.get("defaults"))
        .and_then(|v| v.get("models"))
        .and_then(|v| v.as_object())
    {
        for (id, entry) in map {
            let alias = entry
                .get("alias")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let label = entry
                .get("label")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let provider = entry
                .get("provider")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let model_id = entry
                .get("model")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());

            models.push(json!({
                "id": id,
                "alias": alias,
                "label": label,
                "provider": provider,
                "model": model_id
            }));
        }
    }

    // Check for models in top-level models.providers
    if let Some(providers) = cfg
        .get("models")
        .and_then(|v| v.get("providers"))
        .and_then(|v| v.as_object())
    {
        for (provider_id, provider_config) in providers {
            if let Some(provider_models) = provider_config.get("models").and_then(|v| v.as_object())
            {
                for (model_id, model_config) in provider_models {
                    let full_id = format!("{}:{}", provider_id, model_id);
                    // Skip if already added
                    if models.iter().any(|m| m.get("id") == Some(&json!(full_id))) {
                        continue;
                    }
                    let label = model_config
                        .get("label")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                    models.push(json!({
                        "id": full_id,
                        "alias": null,
                        "label": label,
                        "provider": provider_id,
                        "model": model_id
                    }));
                }
            }
        }
    }

    // Add default models if none configured
    if models.is_empty() {
        models.push(json!({
            "id": format!("anthropic:{DEFAULT_MODEL}"),
            "alias": "sonnet",
            "label": "Claude Sonnet 4",
            "provider": "anthropic",
            "model": DEFAULT_MODEL
        }));
        models.push(json!({
            "id": "anthropic:claude-opus-4-20250514",
            "alias": "opus",
            "label": "Claude Opus 4",
            "provider": "anthropic",
            "model": "claude-opus-4-20250514"
        }));
    }

    Ok(json!({ "models": models }))
}

/// List available agents
pub(super) fn handle_agents_list() -> Result<Value, ErrorShape> {
    let cfg = config::load_config().unwrap_or(Value::Object(serde_json::Map::new()));
    let mut agents = Vec::new();
    let mut default_id: Option<String> = None;
    let mut main_key: Option<String> = None;
    let mut scope: Option<String> = None;

    // Read session configuration
    if let Some(session_obj) = cfg.get("session").and_then(|v| v.as_object()) {
        if let Some(main_key_value) = session_obj.get("mainKey").and_then(|v| v.as_str()) {
            if !main_key_value.trim().is_empty() {
                main_key = Some(main_key_value.trim().to_string());
            }
        }
        if let Some(scope_value) = session_obj.get("scope").and_then(|v| v.as_str()) {
            if !scope_value.trim().is_empty() {
                scope = Some(scope_value.trim().to_string());
            }
        }
    }

    // Read agents list
    if let Some(list) = cfg
        .get("agents")
        .and_then(|v| v.get("list"))
        .and_then(|v| v.as_array())
    {
        for entry in list {
            if let Some(id) = entry.get("id").and_then(|v| v.as_str()) {
                // Check if this is the default agent
                if entry
                    .get("default")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false)
                {
                    default_id = Some(id.to_string());
                }

                let identity = entry.get("identity").cloned().unwrap_or(Value::Null);
                let name = identity
                    .get("name")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                let description = identity
                    .get("description")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                let enabled = entry
                    .get("enabled")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(true);
                let model = entry
                    .get("model")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                let workspace = entry
                    .get("workspace")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());

                agents.push(json!({
                    "id": id,
                    "name": name,
                    "description": description,
                    "identity": identity,
                    "enabled": enabled,
                    "model": model,
                    "workspace": workspace,
                    "default": entry.get("default").and_then(|v| v.as_bool()).unwrap_or(false)
                }));
            }
        }
    }

    // Add default agent if none configured
    if agents.is_empty() {
        agents.push(json!({
            "id": "default",
            "name": "Moltbot",
            "description": "Default assistant",
            "identity": {
                "name": "Moltbot"
            },
            "enabled": true,
            "default": true
        }));
        default_id = Some("default".to_string());
    }

    // Set default_id to first agent if not explicitly set
    if default_id.is_none() {
        if let Some(first) = agents.first() {
            if let Some(id) = first.get("id").and_then(|v| v.as_str()) {
                default_id = Some(id.to_string());
            }
        }
    }

    Ok(json!({
        "defaultId": default_id.unwrap_or_else(|| "default".to_string()),
        "mainKey": main_key.unwrap_or_else(|| "main".to_string()),
        "scope": scope.unwrap_or_else(|| "per-sender".to_string()),
        "agents": agents,
        "count": agents.len()
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_models_list() {
        let result = handle_models_list().unwrap();
        assert!(result.get("models").is_some());
        let models = result["models"].as_array().unwrap();
        assert!(!models.is_empty());
    }

    #[test]
    fn test_agents_list() {
        let result = handle_agents_list().unwrap();
        assert!(result.get("agents").is_some());
        assert!(result.get("defaultId").is_some());
        assert!(result.get("mainKey").is_some());
        assert!(result.get("scope").is_some());

        let agents = result["agents"].as_array().unwrap();
        assert!(!agents.is_empty());
    }

    #[test]
    fn test_agents_list_has_default() {
        let result = handle_agents_list().unwrap();
        let default_id = result["defaultId"].as_str().unwrap();
        assert!(!default_id.is_empty());
    }
}
