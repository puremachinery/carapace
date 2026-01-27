//! Skills handlers.

use serde_json::{json, Value};
use std::path::PathBuf;

use super::super::*;
use super::config::{map_validation_issues, read_config_snapshot, write_config_file};

fn ensure_object(value: &mut Value) -> &mut serde_json::Map<String, Value> {
    if !value.is_object() {
        *value = Value::Object(serde_json::Map::new());
    }
    value.as_object_mut().expect("value is object")
}

fn resolve_workspace_dir(cfg: &Value) -> PathBuf {
    if let Ok(dir) = env::var("MOLTBOT_WORKSPACE_DIR") {
        if !dir.trim().is_empty() {
            return PathBuf::from(dir);
        }
    }
    if let Some(workspace) = cfg
        .get("agents")
        .and_then(|v| v.get("defaults"))
        .and_then(|v| v.get("workspace"))
        .and_then(|v| v.as_str())
    {
        if !workspace.trim().is_empty() {
            return PathBuf::from(workspace);
        }
    }
    if let Some(list) = cfg
        .get("agents")
        .and_then(|v| v.get("list"))
        .and_then(|v| v.as_array())
    {
        for entry in list {
            if entry
                .get("default")
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
            {
                if let Some(workspace) = entry.get("workspace").and_then(|v| v.as_str()) {
                    if !workspace.trim().is_empty() {
                        return PathBuf::from(workspace);
                    }
                }
            }
        }
        if let Some(first) = list.first() {
            if let Some(workspace) = first.get("workspace").and_then(|v| v.as_str()) {
                if !workspace.trim().is_empty() {
                    return PathBuf::from(workspace);
                }
            }
        }
    }
    std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
}

pub(super) fn handle_skills_status() -> Result<Value, ErrorShape> {
    let cfg = config::load_config().unwrap_or(Value::Object(serde_json::Map::new()));
    let workspace_dir = resolve_workspace_dir(&cfg);
    let managed_skills_dir = workspace_dir.join("skills");
    Ok(json!({
        "workspaceDir": workspace_dir.to_string_lossy(),
        "managedSkillsDir": managed_skills_dir.to_string_lossy(),
        "skills": []
    }))
}

pub(super) fn handle_skills_bins() -> Result<Value, ErrorShape> {
    Ok(json!({ "bins": [] }))
}

pub(super) fn handle_skills_install(params: Option<&Value>) -> Result<Value, ErrorShape> {
    let name = params
        .and_then(|v| v.get("name"))
        .and_then(|v| v.as_str())
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "name is required", None))?;
    let install_id = params
        .and_then(|v| v.get("installId"))
        .and_then(|v| v.as_str())
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "installId is required", None))?;
    let timeout_ms = params
        .and_then(|v| v.get("timeoutMs"))
        .and_then(|v| v.as_i64())
        .map(|v| v.max(1000) as u64);

    let mut config_value = read_config_snapshot().config;
    let root = ensure_object(&mut config_value);
    let skills = root.entry("skills").or_insert_with(|| json!({}));
    let skills_obj = ensure_object(skills);
    let entries = skills_obj.entry("entries").or_insert_with(|| json!({}));
    let entries_obj = ensure_object(entries);
    let entry = entries_obj
        .entry(name.to_string())
        .or_insert_with(|| json!({}));
    let entry_obj = ensure_object(entry);
    entry_obj.insert("enabled".to_string(), Value::Bool(true));
    entry_obj.insert("name".to_string(), Value::String(name.to_string()));
    entry_obj.insert(
        "installId".to_string(),
        Value::String(install_id.to_string()),
    );
    entry_obj.insert("requestedAt".to_string(), Value::Number(now_ms().into()));

    let issues = map_validation_issues(config::validate_config(&config_value));
    if !issues.is_empty() {
        return Err(error_shape(
            ERROR_INVALID_REQUEST,
            "invalid config",
            Some(json!({ "issues": issues })),
        ));
    }
    write_config_file(&config::get_config_path(), &config_value)?;

    Ok(json!({
        "ok": true,
        "name": name,
        "installId": install_id,
        "timeoutMs": timeout_ms,
        "queued": true
    }))
}

pub(super) fn handle_skills_update(params: Option<&Value>) -> Result<Value, ErrorShape> {
    let skill_key = params
        .and_then(|v| v.get("skillKey"))
        .and_then(|v| v.as_str())
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "skillKey is required", None))?;
    let enabled = params
        .and_then(|v| v.get("enabled"))
        .and_then(|v| v.as_bool());
    let api_key = params
        .and_then(|v| v.get("apiKey"))
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_string());
    let env_map = params
        .and_then(|v| v.get("env"))
        .and_then(|v| v.as_object())
        .cloned();

    let mut config_value = read_config_snapshot().config;
    let root = ensure_object(&mut config_value);
    let skills = root.entry("skills").or_insert_with(|| json!({}));
    let skills_obj = ensure_object(skills);
    let entries = skills_obj.entry("entries").or_insert_with(|| json!({}));
    let entries_obj = ensure_object(entries);
    let entry = entries_obj
        .entry(skill_key.to_string())
        .or_insert_with(|| json!({}));
    let entry_obj = ensure_object(entry);

    if let Some(enabled) = enabled {
        entry_obj.insert("enabled".to_string(), Value::Bool(enabled));
    }
    if let Some(api_key) = api_key {
        if api_key.trim().is_empty() {
            entry_obj.remove("apiKey");
        } else {
            entry_obj.insert("apiKey".to_string(), Value::String(api_key));
        }
    }
    if let Some(env_map) = env_map {
        let env_value = entry_obj
            .entry("env".to_string())
            .or_insert_with(|| json!({}));
        let env_obj = ensure_object(env_value);
        for (key, value) in env_map {
            let k = key.trim().to_string();
            if k.is_empty() {
                continue;
            }
            if let Some(v) = value.as_str() {
                let trimmed = v.trim();
                if trimmed.is_empty() {
                    env_obj.remove(&k);
                } else {
                    env_obj.insert(k, Value::String(trimmed.to_string()));
                }
            }
        }
    }

    let issues = map_validation_issues(config::validate_config(&config_value));
    if !issues.is_empty() {
        return Err(error_shape(
            ERROR_INVALID_REQUEST,
            "invalid config",
            Some(json!({ "issues": issues })),
        ));
    }
    write_config_file(&config::get_config_path(), &config_value)?;

    Ok(json!({
        "ok": true,
        "skillKey": skill_key,
        "updated": true
    }))
}
