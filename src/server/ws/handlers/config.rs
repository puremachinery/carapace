//! Config handlers.

use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::ffi::OsString;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use super::super::*;

static CONFIG_WRITE_TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

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
    pub(crate) raw_config: Value,
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
    hex::encode(digest)
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
            raw_config: Value::Object(serde_json::Map::new()),
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
                raw_config: Value::Object(serde_json::Map::new()),
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
    let (raw_config, config_value, mut issues, valid) =
        match config::load_config_pair_uncached(&path) {
            Ok((raw_cfg, cfg)) => {
                let issues = map_validation_issues(config::validate_config(&cfg));
                let valid = issues.is_empty();
                (raw_cfg, cfg, issues, valid)
            }
            Err(err) => {
                let issues = vec![ConfigIssue {
                    path: "".to_string(),
                    message: err.to_string(),
                }];
                (parsed.clone(), parsed.clone(), issues, false)
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
        raw_config,
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
    let tmp_path = config_write_temp_path(path);
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
    if let Err(err) = fs::rename(&tmp_path, path) {
        let _ = fs::remove_file(&tmp_path);
        return Err(format!("failed to replace config: {}", err));
    }

    config::clear_cache();
    Ok(())
}

fn config_write_temp_path(path: &Path) -> PathBuf {
    let counter = CONFIG_WRITE_TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut file_name = path
        .file_name()
        .map(OsString::from)
        .unwrap_or_else(|| OsString::from("carapace.json"));
    file_name.push(format!(".tmp.{}.{counter}", std::process::id()));
    path.with_file_name(file_name)
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
        "warnings": []
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
/// Routes the reload through the hot-reload bridge: the bridge owns the
/// load + provider validation + cache install + WS broadcast, identical to
/// the file-watcher and SIGHUP paths. A reload that drops the LLM provider
/// (or otherwise fails validation) is rejected before the cache is touched
/// and the client receives an error response.
pub(super) async fn handle_config_reload(state: &WsServerState) -> Result<Value, ErrorShape> {
    use crate::config::watcher::ReloadMode;
    use crate::server::startup::{ReloadCommand, ReloadCommandResult};

    // Determine reload mode from current config (default "hot" for manual
    // reloads; never "off" since the operator explicitly asked to reload).
    let current_config =
        config::load_config().unwrap_or_else(|_| Value::Object(serde_json::Map::new()));
    let mode_str = current_config
        .get("gateway")
        .and_then(|g| g.get("reload"))
        .and_then(|r| r.get("mode"))
        .and_then(|m| m.as_str())
        .unwrap_or("hot");
    let mode = match ReloadMode::parse_mode(mode_str) {
        ReloadMode::Off => "hot".to_string(),
        ReloadMode::Hot => "hot".to_string(),
        ReloadMode::Hybrid => "hybrid".to_string(),
    };

    let Some(command_tx) = state.reload_command_tx() else {
        return Err(error_shape(
            ERROR_UNAVAILABLE,
            "config-reload bridge is not running; reload requests cannot be processed",
            None,
        ));
    };
    let (respond_to, response_rx) = tokio::sync::oneshot::channel();
    if command_tx
        .send(ReloadCommand {
            mode: mode.clone(),
            respond_to,
        })
        .await
        .is_err()
    {
        return Err(error_shape(
            ERROR_UNAVAILABLE,
            "config-reload bridge has shut down; reload not delivered",
            None,
        ));
    }
    match response_rx.await {
        Ok(ReloadCommandResult::Applied { warnings }) => Ok(json!({
            "ok": true,
            "mode": mode,
            "warnings": warnings,
        })),
        Ok(ReloadCommandResult::Reverted) => Err(error_shape(
            ERROR_UNAVAILABLE,
            "reload rejected: the new config has no LLM provider configured (or build_providers \
             failed). The previous config is still active.",
            None,
        )),
        Ok(ReloadCommandResult::LoadError(message)) => {
            Err(error_shape(ERROR_UNAVAILABLE, &message, None))
        }
        Err(_) => Err(error_shape(
            ERROR_UNAVAILABLE,
            "config-reload bridge dropped the response without replying",
            None,
        )),
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
    fn test_config_write_temp_path_is_unique_in_target_dir() {
        let path = PathBuf::from("config-dir").join("carapace.json");
        let first = config_write_temp_path(&path);
        let second = config_write_temp_path(&path);

        assert_ne!(first, second);
        assert_eq!(first.parent(), path.parent());
        assert!(first
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with("carapace.json.tmp.")));
    }

    #[test]
    fn test_handle_config_validate_accepts_object() {
        let params = json!({ "config": {} });
        let result = handle_config_validate(Some(&params));
        assert!(result.is_ok());
        let value = result.unwrap();
        assert_eq!(value["ok"], true);
        assert_eq!(value["valid"], true);
    }

    /// `config.reload` returns ERROR_UNAVAILABLE when the hot-reload bridge
    /// is not running. The bridge sets `reload_command_tx` on
    /// `WsServerState` once it spawns; without it, the handler refuses to
    /// process the request rather than installing a payload directly (which
    /// would skip provider validation).
    #[tokio::test]
    async fn test_handle_config_reload_errors_when_bridge_not_running() {
        let state = WsServerState::new(WsServerConfig::default());
        // No `set_reload_command_tx(Some(...))` here — bridge never spawned.

        let result = handle_config_reload(&state).await;

        let err = result.expect_err("must fail without a bridge");
        assert!(
            err.message.contains("config-reload bridge is not running"),
            "got: {}",
            err.message
        );
    }

    /// `config.reload` reports a load error via ERROR_UNAVAILABLE when the
    /// bridge's load fails (bad on-disk config). Pins that the WS handler
    /// surfaces the bridge's `LoadError` outcome rather than installing a
    /// stale cache or returning ok.
    #[tokio::test]
    async fn test_handle_config_reload_surfaces_bridge_load_error() {
        use crate::server::startup::{ReloadCommand, ReloadCommandResult};

        let state = WsServerState::new(WsServerConfig::default());
        let (command_tx, mut command_rx) = tokio::sync::mpsc::channel::<ReloadCommand>(1);
        state.set_reload_command_tx(Some(command_tx));

        // Stand-in bridge: respond to the command with a synthetic LoadError.
        let bridge = tokio::spawn(async move {
            let cmd = command_rx.recv().await.expect("bridge receives command");
            let _ = cmd.respond_to.send(ReloadCommandResult::LoadError(
                "config.json5: parse failed at line 1".to_string(),
            ));
        });

        let result = handle_config_reload(&state).await;
        bridge.await.expect("bridge task joins");

        let err = result.expect_err("LoadError must surface as Err");
        assert!(
            err.message.contains("config.json5"),
            "load-error message must propagate: {}",
            err.message
        );
    }

    /// `config.reload` returns ok+ERROR_UNAVAILABLE based on the bridge's
    /// outcome. `Reverted` (no provider in new config) maps to an error
    /// response that names the rejection reason; `Applied` maps to ok with
    /// the mode field populated from whatever the handler resolved.
    #[tokio::test]
    async fn test_handle_config_reload_maps_bridge_outcomes_to_responses() {
        use crate::server::startup::{ReloadCommand, ReloadCommandResult};

        // Applied path → Ok response with mode field set.
        {
            let state = WsServerState::new(WsServerConfig::default());
            let (command_tx, mut command_rx) = tokio::sync::mpsc::channel::<ReloadCommand>(1);
            state.set_reload_command_tx(Some(command_tx));
            let bridge = tokio::spawn(async move {
                let cmd = command_rx.recv().await.expect("command received");
                // Echo back the mode the handler resolved so the assertion
                // pins the round-trip without depending on whatever
                // gateway.reload.mode the ambient on-disk config carries.
                let mode = cmd.mode.clone();
                let _ = cmd.respond_to.send(ReloadCommandResult::Applied {
                    warnings: vec!["a: warn-one".to_string()],
                });
                mode
            });
            let result = handle_config_reload(&state).await;
            let resolved_mode = bridge.await.unwrap();
            let value = result.expect("Applied → Ok");
            assert_eq!(value["ok"], true);
            assert_eq!(value["mode"], serde_json::Value::String(resolved_mode));
            // Warnings from the bridge must round-trip into the response so
            // clients can surface non-fatal validation issues to the operator.
            assert_eq!(
                value["warnings"],
                serde_json::json!(["a: warn-one"]),
                "Applied warnings must be forwarded to the WS response"
            );
        }

        // Reverted path → Err with provider-rejection message.
        {
            let state = WsServerState::new(WsServerConfig::default());
            let (command_tx, mut command_rx) = tokio::sync::mpsc::channel::<ReloadCommand>(1);
            state.set_reload_command_tx(Some(command_tx));
            let bridge = tokio::spawn(async move {
                let cmd = command_rx.recv().await.expect("command received");
                let _ = cmd.respond_to.send(ReloadCommandResult::Reverted);
            });
            let result = handle_config_reload(&state).await;
            bridge.await.unwrap();
            let err = result.expect_err("Reverted → Err");
            assert!(
                err.message.contains("no LLM provider"),
                "Reverted reason must surface: {}",
                err.message
            );
        }
    }
}
