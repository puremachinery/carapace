//! Config handlers.

use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Write;
use std::path::PathBuf;

use super::super::*;

#[derive(Debug, Serialize)]
pub(crate) struct ConfigIssue {
    pub(crate) path: String,
    pub(crate) message: String,
}

#[derive(Debug)]
pub(crate) struct ConfigSnapshot {
    pub(crate) path: String,
    pub(crate) exists: bool,
    pub(crate) raw: Option<String>,
    pub(crate) parsed: Value,
    pub(crate) valid: bool,
    pub(crate) config: Value,
    pub(crate) hash: Option<String>,
    pub(crate) issues: Vec<ConfigIssue>,
}

pub(crate) fn map_validation_issues(issues: Vec<config::ValidationIssue>) -> Vec<ConfigIssue> {
    issues
        .into_iter()
        .map(|issue| ConfigIssue {
            path: issue.path,
            message: issue.message,
        })
        .collect()
}

pub(crate) fn sha256_hex(value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    format!("{:x}", digest)
}

pub(crate) fn read_config_snapshot() -> ConfigSnapshot {
    let path = config::get_config_path();
    let path_str = path.display().to_string();
    if !path.exists() {
        return ConfigSnapshot {
            path: path_str,
            exists: false,
            raw: None,
            parsed: Value::Object(serde_json::Map::new()),
            valid: true,
            config: Value::Object(serde_json::Map::new()),
            hash: None,
            issues: Vec::new(),
        };
    }

    let raw = match fs::read_to_string(&path) {
        Ok(raw) => raw,
        Err(err) => {
            return ConfigSnapshot {
                path: path_str,
                exists: true,
                raw: None,
                parsed: Value::Object(serde_json::Map::new()),
                valid: false,
                config: Value::Object(serde_json::Map::new()),
                hash: None,
                issues: vec![ConfigIssue {
                    path: "".to_string(),
                    message: format!("read failed: {}", err),
                }],
            }
        }
    };

    let hash = Some(sha256_hex(&raw));
    let parsed = json5::from_str::<Value>(&raw).unwrap_or(Value::Null);

    let (config_value, mut issues, valid) = match config::load_config_uncached(&path) {
        Ok(cfg) => {
            let issues = map_validation_issues(config::validate_config(&cfg));
            let valid = issues.is_empty();
            (cfg, issues, valid)
        }
        Err(err) => {
            let issues = vec![ConfigIssue {
                path: "".to_string(),
                message: err.to_string(),
            }];
            (parsed.clone(), issues, false)
        }
    };

    if !valid && issues.is_empty() {
        issues.push(ConfigIssue {
            path: "".to_string(),
            message: "invalid config".to_string(),
        });
    }

    ConfigSnapshot {
        path: path_str,
        exists: true,
        raw: Some(raw),
        parsed,
        valid,
        config: config_value,
        hash,
        issues,
    }
}

fn require_config_base_hash(
    params: Option<&Value>,
    snapshot: &ConfigSnapshot,
) -> Result<(), ErrorShape> {
    if !snapshot.exists {
        return Ok(());
    }
    let base_hash = params
        .and_then(|v| v.get("baseHash"))
        .and_then(|v| v.as_str())
        .map(|s| s.trim())
        .filter(|s| !s.is_empty());
    let expected = snapshot.hash.as_deref();
    if expected.is_none() {
        return Err(error_shape(
            ERROR_INVALID_REQUEST,
            "config base hash unavailable; re-run config.get and retry",
            None,
        ));
    }
    let Some(base_hash) = base_hash else {
        return Err(error_shape(
            ERROR_INVALID_REQUEST,
            "config base hash required; re-run config.get and retry",
            None,
        ));
    };
    if Some(base_hash) != expected {
        return Err(error_shape(
            ERROR_INVALID_REQUEST,
            "config changed since last load; re-run config.get and retry",
            None,
        ));
    }
    Ok(())
}

/// Write a config value to disk atomically. Returns `Err(message)` on failure.
/// This is the `pub(crate)` helper so non-WS code (e.g. the control HTTP
/// endpoint) can persist config without depending on `ErrorShape`.
pub(crate) fn persist_config_file(path: &PathBuf, config_value: &Value) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|err| format!("failed to create config dir: {}", err))?;
    }

    let mut config_value = config_value.clone();
    config::seal_config_secrets(&mut config_value)?;
    let content = serde_json::to_string_pretty(&config_value)
        .map_err(|err| format!("failed to serialize config: {}", err))?;
    let tmp_path = path.with_extension("json.tmp");
    {
        let mut file = fs::File::create(&tmp_path)
            .map_err(|err| format!("failed to write config: {}", err))?;
        file.write_all(content.as_bytes())
            .map_err(|err| format!("failed to write config: {}", err))?;
        file.write_all(b"\n")
            .map_err(|err| format!("failed to write config: {}", err))?;
        file.sync_all()
            .map_err(|err| format!("failed to sync config: {}", err))?;
    }
    fs::rename(&tmp_path, path).map_err(|err| format!("failed to replace config: {}", err))?;

    config::clear_cache();
    Ok(())
}

pub(super) fn write_config_file(path: &PathBuf, config_value: &Value) -> Result<(), ErrorShape> {
    persist_config_file(path, config_value)
        .map_err(|msg| error_shape(ERROR_UNAVAILABLE, &msg, None))
}

fn merge_patch(base: Value, patch: Value) -> Value {
    match (base, patch) {
        (_, Value::Null) => Value::Null,
        (Value::Object(mut base_map), Value::Object(patch_map)) => {
            for (key, patch_value) in patch_map {
                if patch_value.is_null() {
                    base_map.remove(&key);
                } else {
                    let base_value = base_map.remove(&key).unwrap_or(Value::Null);
                    let merged = merge_patch(base_value, patch_value);
                    base_map.insert(key, merged);
                }
            }
            Value::Object(base_map)
        }
        (_, patch_value) => patch_value,
    }
}

pub(super) fn handle_config_get(params: Option<&Value>) -> Result<Value, ErrorShape> {
    let snapshot = read_config_snapshot();
    let key = params
        .and_then(|v| v.get("key"))
        .and_then(|v| v.as_str())
        .map(|s| s.trim())
        .filter(|s| !s.is_empty());

    if let Some(key) = key {
        let value = get_value_at_path(&snapshot.config, key).unwrap_or(Value::Null);
        return Ok(json!({
            "key": key,
            "value": value
        }));
    }

    Ok(json!({
        "path": snapshot.path,
        "exists": snapshot.exists,
        "raw": snapshot.raw,
        "parsed": snapshot.parsed,
        "valid": snapshot.valid,
        "config": snapshot.config,
        "hash": snapshot.hash,
        "issues": snapshot.issues,
        "warnings": [],
        "legacyIssues": []
    }))
}

pub(super) fn handle_config_set(params: Option<&Value>) -> Result<Value, ErrorShape> {
    let snapshot = read_config_snapshot();
    require_config_base_hash(params, &snapshot)?;

    let raw = params
        .and_then(|v| v.get("raw"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "raw is required", None))?;
    let parsed = json5::from_str::<Value>(raw)
        .map_err(|err| error_shape(ERROR_INVALID_REQUEST, &err.to_string(), None))?;
    if !parsed.is_object() {
        return Err(error_shape(
            ERROR_INVALID_REQUEST,
            "config.set raw must be an object",
            None,
        ));
    }
    let issues = map_validation_issues(config::validate_config(&parsed));
    if !issues.is_empty() {
        return Err(error_shape(
            ERROR_INVALID_REQUEST,
            "invalid config",
            Some(json!({ "issues": issues })),
        ));
    }
    write_config_file(&config::get_config_path(), &parsed)?;
    Ok(json!({
        "ok": true,
        "path": config::get_config_path().display().to_string(),
        "config": parsed
    }))
}

pub(super) fn handle_config_apply(params: Option<&Value>) -> Result<Value, ErrorShape> {
    let snapshot = read_config_snapshot();
    require_config_base_hash(params, &snapshot)?;

    let raw = params
        .and_then(|v| v.get("raw"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "raw is required", None))?;
    let parsed = json5::from_str::<Value>(raw)
        .map_err(|err| error_shape(ERROR_INVALID_REQUEST, &err.to_string(), None))?;
    if !parsed.is_object() {
        return Err(error_shape(
            ERROR_INVALID_REQUEST,
            "config.apply raw must be an object",
            None,
        ));
    }
    let issues = map_validation_issues(config::validate_config(&parsed));
    if !issues.is_empty() {
        return Err(error_shape(
            ERROR_INVALID_REQUEST,
            "invalid config",
            Some(json!({ "issues": issues })),
        ));
    }
    write_config_file(&config::get_config_path(), &parsed)?;
    Ok(json!({
        "ok": true,
        "path": config::get_config_path().display().to_string(),
        "config": parsed
    }))
}

pub(super) fn handle_config_patch(params: Option<&Value>) -> Result<Value, ErrorShape> {
    let snapshot = read_config_snapshot();
    require_config_base_hash(params, &snapshot)?;

    let raw = params
        .and_then(|v| v.get("raw"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "raw is required", None))?;
    let patch_value = json5::from_str::<Value>(raw)
        .map_err(|err| error_shape(ERROR_INVALID_REQUEST, &err.to_string(), None))?;
    if !patch_value.is_object() {
        return Err(error_shape(
            ERROR_INVALID_REQUEST,
            "config.patch raw must be an object",
            None,
        ));
    }

    let merged = merge_patch(snapshot.config.clone(), patch_value);
    let issues = map_validation_issues(config::validate_config(&merged));
    if !issues.is_empty() {
        return Err(error_shape(
            ERROR_INVALID_REQUEST,
            "invalid config",
            Some(json!({ "issues": issues })),
        ));
    }

    write_config_file(&config::get_config_path(), &merged)?;
    Ok(json!({
        "ok": true,
        "path": config::get_config_path().display().to_string(),
        "config": merged
    }))
}

pub(super) fn handle_config_validate(params: Option<&Value>) -> Result<Value, ErrorShape> {
    let raw = params.and_then(|v| v.get("raw")).and_then(|v| v.as_str());

    let parsed = if let Some(raw) = raw {
        json5::from_str::<Value>(raw)
            .map_err(|err| error_shape(ERROR_INVALID_REQUEST, &err.to_string(), None))?
    } else {
        params
            .and_then(|v| v.get("config"))
            .cloned()
            .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "raw or config is required", None))?
    };

    if !parsed.is_object() {
        return Err(error_shape(
            ERROR_INVALID_REQUEST,
            "config.validate value must be an object",
            None,
        ));
    }

    let issues = map_validation_issues(config::validate_config(&parsed));
    if !issues.is_empty() {
        return Err(error_shape(
            ERROR_INVALID_REQUEST,
            "invalid config",
            Some(json!({ "issues": issues })),
        ));
    }

    Ok(json!({
        "ok": true,
        "valid": true,
        "issues": []
    }))
}

pub(super) fn handle_config_schema() -> Result<Value, ErrorShape> {
    let keys = config::schema::known_top_level_keys();
    let mut properties = serde_json::Map::new();
    for key in keys {
        properties.insert(key.to_string(), json!({ "type": "object" }));
    }

    Ok(json!({
        "$schema": "http://json-schema.org/draft-07/schema#",
        "type": "object",
        "additionalProperties": false,
        "properties": properties,
        "knownKeys": keys
    }))
}

/// Handle the `config.reload` WS method (admin-only).
///
/// Triggers a manual config reload, re-reading the config file from disk,
/// validating it, and updating the config cache. The reload mode used is
/// read from the current config's `gateway.reload.mode` (defaulting to "hot"
/// for manual reloads).
pub(super) async fn handle_config_reload(state: &WsServerState) -> Result<Value, ErrorShape> {
    use crate::config::watcher::{perform_reload_async, ReloadMode};

    // Determine reload mode from current config
    let current_config =
        config::load_config().unwrap_or_else(|_| Value::Object(serde_json::Map::new()));
    let mode_str = current_config
        .get("gateway")
        .and_then(|g| g.get("reload"))
        .and_then(|r| r.get("mode"))
        .and_then(|m| m.as_str())
        .unwrap_or("hot");

    // For manual reload, use the configured mode (or "hot" if "off")
    let mode = match ReloadMode::parse_mode(mode_str) {
        ReloadMode::Off => ReloadMode::Hot, // Manual reload always does at least hot
        other => other,
    };

    let result = perform_reload_async(&mode).await;

    if result.success {
        // Broadcast config.changed event to all WS clients
        broadcast_config_changed(state, &result.mode);

        Ok(json!({
            "ok": true,
            "mode": result.mode,
            "warnings": result.warnings
        }))
    } else {
        Err(error_shape(
            ERROR_UNAVAILABLE,
            &result.error.unwrap_or_else(|| "reload failed".to_string()),
            None,
        ))
    }
}

/// Broadcast a `config.changed` event to all connected WS clients.
///
/// This is called after a successful config reload (from file watcher, SIGHUP,
/// or the `config.reload` WS method).
pub fn broadcast_config_changed(state: &WsServerState, mode: &str) {
    let payload = json!({
        "mode": mode,
        "ts": now_ms()
    });
    broadcast_event(state, "config.changed", payload);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handle_config_validate_accepts_object() {
        let params = json!({ "config": {} });
        let result = handle_config_validate(Some(&params));
        assert!(result.is_ok());
        let value = result.unwrap();
        assert_eq!(value["ok"], true);
        assert_eq!(value["valid"], true);
    }
}
