//! Control UI HTTP endpoints
//!
//! Implements:
//! - GET /control/status - Gateway status
//! - GET /control/channels - Channel status
//! - POST /control/config - Config updates

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::Arc;

use crate::auth;
use crate::channels::{ChannelInfo, ChannelRegistry, ChannelStatus};
use crate::config;
use crate::server::ws::{map_validation_issues, persist_config_file, read_config_snapshot};

/// Control endpoint state
#[derive(Clone)]
pub struct ControlState {
    /// Gateway auth token
    pub gateway_token: Option<String>,
    /// Gateway auth password
    pub gateway_password: Option<String>,
    /// Channel registry
    pub channel_registry: Arc<ChannelRegistry>,
    /// Gateway version
    pub version: String,
    /// Gateway start time (Unix timestamp)
    pub start_time: i64,
}

impl Default for ControlState {
    fn default() -> Self {
        ControlState {
            gateway_token: None,
            gateway_password: None,
            channel_registry: Arc::new(ChannelRegistry::new()),
            version: env!("CARGO_PKG_VERSION").to_string(),
            start_time: chrono::Utc::now().timestamp(),
        }
    }
}

/// Gateway status response
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GatewayStatusResponse {
    /// Gateway is running
    pub ok: bool,
    /// Gateway version
    pub version: String,
    /// Gateway start time (ISO 8601)
    pub started_at: String,
    /// Uptime in seconds
    pub uptime_seconds: i64,
    /// Number of connected channels
    pub connected_channels: usize,
    /// Total registered channels
    pub total_channels: usize,
    /// Runtime information
    pub runtime: RuntimeInfo,
}

/// Runtime information
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeInfo {
    /// Runtime name
    pub name: String,
    /// Runtime version
    pub version: String,
    /// Platform
    pub platform: String,
    /// Architecture
    pub arch: String,
}

/// Channel status response
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChannelsStatusResponse {
    /// Total number of channels
    pub total: usize,
    /// Number of connected channels
    pub connected: usize,
    /// Channel details
    pub channels: Vec<ChannelStatusItem>,
}

/// Individual channel status
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChannelStatusItem {
    /// Channel ID
    pub id: String,
    /// Channel name
    pub name: String,
    /// Connection status
    pub status: String,
    /// Last connected timestamp (ISO 8601)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_connected_at: Option<String>,
    /// Last error message
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

/// Config update request
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfigUpdateRequest {
    /// Configuration path (dot notation)
    pub path: String,
    /// New value
    pub value: Value,
    /// SHA256 hash of current config for optimistic concurrency
    #[serde(default)]
    pub base_hash: Option<String>,
}

/// Config update response
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfigUpdateResponse {
    /// Success flag
    pub ok: bool,
    /// Error message if failed
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Applied configuration
    #[serde(skip_serializing_if = "Option::is_none")]
    pub applied: Option<Value>,
    /// SHA256 hash of the persisted config (for subsequent optimistic concurrency)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
}

/// Control API error
#[derive(Debug, Serialize)]
pub struct ControlError {
    pub ok: bool,
    pub error: String,
}

impl ControlError {
    pub fn new(message: impl Into<String>) -> Self {
        ControlError {
            ok: false,
            error: message.into(),
        }
    }

    pub fn unauthorized() -> Self {
        ControlError::new("Unauthorized")
    }
}

/// GET /control/status - Gateway status
pub async fn status_handler(State(state): State<ControlState>, headers: HeaderMap) -> Response {
    // Check auth
    if let Some(err) = check_control_auth(&state, &headers) {
        return err;
    }

    let now = chrono::Utc::now().timestamp();
    let uptime_seconds = now - state.start_time;

    let connected_count = state
        .channel_registry
        .count_by_status(ChannelStatus::Connected);
    let total_count = state.channel_registry.len();

    let started_at = chrono::DateTime::from_timestamp(state.start_time, 0)
        .map(|dt| dt.format("%Y-%m-%dT%H:%M:%SZ").to_string())
        .unwrap_or_default();

    let response = GatewayStatusResponse {
        ok: true,
        version: state.version.clone(),
        started_at,
        uptime_seconds,
        connected_channels: connected_count,
        total_channels: total_count,
        runtime: RuntimeInfo {
            name: "carapace".to_string(),
            version: state.version.clone(),
            platform: std::env::consts::OS.to_string(),
            arch: std::env::consts::ARCH.to_string(),
        },
    };

    (StatusCode::OK, Json(response)).into_response()
}

/// GET /control/channels - Channel status
pub async fn channels_handler(State(state): State<ControlState>, headers: HeaderMap) -> Response {
    // Check auth
    if let Some(err) = check_control_auth(&state, &headers) {
        return err;
    }

    let channels = state.channel_registry.list();
    let connected_count = channels
        .iter()
        .filter(|c| c.status == ChannelStatus::Connected)
        .count();

    let channel_items: Vec<ChannelStatusItem> = channels
        .into_iter()
        .map(|c| ChannelStatusItem {
            id: c.id,
            name: c.name,
            status: c.status.to_string(),
            last_connected_at: c.metadata.last_connected_at.and_then(|ts| {
                chrono::DateTime::from_timestamp(ts / 1000, 0)
                    .map(|dt| dt.format("%Y-%m-%dT%H:%M:%SZ").to_string())
            }),
            last_error: c.metadata.last_error,
        })
        .collect();

    let response = ChannelsStatusResponse {
        total: channel_items.len(),
        connected: connected_count,
        channels: channel_items,
    };

    (StatusCode::OK, Json(response)).into_response()
}

/// POST /control/config - Update configuration
pub async fn config_handler(
    State(state): State<ControlState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    // Check auth
    if let Some(err) = check_control_auth(&state, &headers) {
        return err;
    }

    // Parse request
    let req: ConfigUpdateRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ControlError::new(format!("Invalid JSON: {}", e))),
            )
                .into_response();
        }
    };

    // Validate path
    if req.path.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ControlError::new("Configuration path is required")),
        )
            .into_response();
    }

    // Block sensitive paths
    let blocked_prefixes = ["gateway.auth", "hooks.token", "credentials", "secrets"];

    for prefix in blocked_prefixes {
        if req.path.starts_with(prefix) {
            return (
                StatusCode::FORBIDDEN,
                Json(ControlError::new(format!(
                    "Cannot modify protected configuration: {}",
                    prefix
                ))),
            )
                .into_response();
        }
    }

    // Read current config snapshot (with hash for optimistic concurrency)
    let snapshot = read_config_snapshot();

    // Check optimistic concurrency if the config file exists
    if snapshot.exists {
        match (&req.base_hash, &snapshot.hash) {
            (Some(provided), Some(expected)) => {
                let provided = provided.trim();
                if !provided.is_empty() && provided != expected {
                    return (
                        StatusCode::CONFLICT,
                        Json(ControlError::new(
                            "Config changed since last load; re-read config and retry",
                        )),
                    )
                        .into_response();
                }
            }
            (None, Some(_)) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(ControlError::new(
                        "baseHash is required when config file exists; read config first to obtain the hash",
                    )),
                )
                    .into_response();
            }
            _ => {} // No hash available or file doesn't exist - allow
        }
    }

    // Apply the path-based update to the current config
    let mut updated_config = snapshot.config.clone();
    set_value_at_path(&mut updated_config, &req.path, req.value.clone());

    // Validate the updated config
    let issues = map_validation_issues(config::validate_config(&updated_config));
    if !issues.is_empty() {
        let issue_details: Vec<Value> = issues
            .iter()
            .map(|i| json!({ "path": i.path, "message": i.message }))
            .collect();
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({
                "ok": false,
                "error": "Invalid configuration",
                "issues": issue_details,
            })),
        )
            .into_response();
    }

    // Persist the updated config atomically
    let config_path = config::get_config_path();
    if let Err(msg) = persist_config_file(&config_path, &updated_config) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ControlError::new(msg)),
        )
            .into_response();
    }

    // Re-read to get the new hash
    let new_snapshot = read_config_snapshot();

    let response = ConfigUpdateResponse {
        ok: true,
        error: None,
        applied: Some(json!({
            "path": req.path,
            "value": req.value,
            "config": new_snapshot.config,
        })),
        hash: new_snapshot.hash,
    };

    (StatusCode::OK, Json(response)).into_response()
}

/// Set a value at a dot-notation path in a JSON object.
/// Creates intermediate objects as needed.
fn set_value_at_path(root: &mut Value, path: &str, value: Value) {
    let parts: Vec<&str> = path.split('.').collect();
    let mut current = root;

    for (i, part) in parts.iter().enumerate() {
        if i == parts.len() - 1 {
            // Last segment: set the value
            if let Value::Object(map) = current {
                map.insert(part.to_string(), value);
            }
            return;
        }
        // Intermediate segment: ensure it's an object
        if !current.get(*part).is_some_and(|v| v.is_object()) {
            if let Value::Object(map) = current {
                map.insert(part.to_string(), Value::Object(serde_json::Map::new()));
            }
        }
        current = current.get_mut(*part).expect("just inserted");
    }
}

/// Check control endpoint authentication
fn check_control_auth(state: &ControlState, headers: &HeaderMap) -> Option<Response> {
    // Extract bearer token
    let provided = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(|s| s.trim());

    // Check token auth
    if let Some(token) = &state.gateway_token {
        if !token.is_empty() {
            if let Some(provided) = provided {
                if auth::timing_safe_eq(provided, token) {
                    return None;
                }
            }
            return Some(
                (StatusCode::UNAUTHORIZED, Json(ControlError::unauthorized())).into_response(),
            );
        }
    }

    // Check password auth
    if let Some(password) = &state.gateway_password {
        if !password.is_empty() {
            if let Some(provided) = provided {
                if auth::timing_safe_eq(provided, password) {
                    return None;
                }
            }
            return Some(
                (StatusCode::UNAUTHORIZED, Json(ControlError::unauthorized())).into_response(),
            );
        }
    }

    // No auth configured - allow control endpoints (they're internal)
    // In production, you should configure gateway auth
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gateway_status_response_serialization() {
        let response = GatewayStatusResponse {
            ok: true,
            version: "0.1.0".to_string(),
            started_at: "2024-01-01T00:00:00Z".to_string(),
            uptime_seconds: 3600,
            connected_channels: 2,
            total_channels: 3,
            runtime: RuntimeInfo {
                name: "carapace".to_string(),
                version: "0.1.0".to_string(),
                platform: "linux".to_string(),
                arch: "x86_64".to_string(),
            },
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"ok\":true"));
        assert!(json.contains("\"uptimeSeconds\":3600"));
    }

    #[test]
    fn test_channels_status_response_serialization() {
        let response = ChannelsStatusResponse {
            total: 2,
            connected: 1,
            channels: vec![
                ChannelStatusItem {
                    id: "telegram".to_string(),
                    name: "Telegram".to_string(),
                    status: "connected".to_string(),
                    last_connected_at: Some("2024-01-01T12:00:00Z".to_string()),
                    last_error: None,
                },
                ChannelStatusItem {
                    id: "discord".to_string(),
                    name: "Discord".to_string(),
                    status: "disconnected".to_string(),
                    last_connected_at: None,
                    last_error: Some("Auth failed".to_string()),
                },
            ],
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"total\":2"));
        assert!(json.contains("\"connected\":1"));
    }

    #[test]
    fn test_config_update_request_parsing() {
        let json = r#"{"path": "agent.model", "value": "claude-3"}"#;
        let req: ConfigUpdateRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.path, "agent.model");
        assert_eq!(req.value, "claude-3");
        assert!(req.base_hash.is_none());
    }

    #[test]
    fn test_config_update_request_with_base_hash() {
        let json = r#"{"path": "agent.model", "value": "claude-3", "baseHash": "abc123"}"#;
        let req: ConfigUpdateRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.path, "agent.model");
        assert_eq!(req.value, "claude-3");
        assert_eq!(req.base_hash.as_deref(), Some("abc123"));
    }

    #[test]
    fn test_config_update_response_serialization() {
        let response = ConfigUpdateResponse {
            ok: true,
            error: None,
            applied: Some(json!({"path": "gateway.port", "value": 9000})),
            hash: Some("deadbeef".to_string()),
        };
        let json_str = serde_json::to_string(&response).unwrap();
        assert!(json_str.contains("\"ok\":true"));
        assert!(json_str.contains("\"hash\":\"deadbeef\""));
        assert!(!json_str.contains("\"error\""));
    }

    #[test]
    fn test_config_update_response_without_hash() {
        let response = ConfigUpdateResponse {
            ok: true,
            error: None,
            applied: None,
            hash: None,
        };
        let json_str = serde_json::to_string(&response).unwrap();
        assert!(json_str.contains("\"ok\":true"));
        assert!(!json_str.contains("\"hash\""));
        assert!(!json_str.contains("\"applied\""));
    }

    #[test]
    fn test_control_error_serialization() {
        let error = ControlError::unauthorized();
        let json = serde_json::to_string(&error).unwrap();
        assert!(json.contains("\"ok\":false"));
        assert!(json.contains("Unauthorized"));
    }

    #[test]
    fn test_set_value_at_path_simple() {
        let mut root = json!({"gateway": {"port": 8080}});
        set_value_at_path(&mut root, "gateway.port", json!(9000));
        assert_eq!(root["gateway"]["port"], 9000);
    }

    #[test]
    fn test_set_value_at_path_creates_intermediates() {
        let mut root = json!({});
        set_value_at_path(&mut root, "gateway.auth.mode", json!("token"));
        assert_eq!(root["gateway"]["auth"]["mode"], "token");
    }

    #[test]
    fn test_set_value_at_path_top_level() {
        let mut root = json!({"existing": true});
        set_value_at_path(&mut root, "newKey", json!("newValue"));
        assert_eq!(root["newKey"], "newValue");
        assert_eq!(root["existing"], true);
    }

    #[test]
    fn test_set_value_at_path_overwrites_non_object() {
        let mut root = json!({"gateway": "string_value"});
        set_value_at_path(&mut root, "gateway.port", json!(9000));
        // The string value is replaced with an object containing port
        assert_eq!(root["gateway"]["port"], 9000);
    }

    #[test]
    fn test_set_value_at_path_complex_value() {
        let mut root = json!({"channels": {}});
        set_value_at_path(
            &mut root,
            "channels.telegram",
            json!({"enabled": true, "token": "abc"}),
        );
        assert_eq!(root["channels"]["telegram"]["enabled"], true);
        assert_eq!(root["channels"]["telegram"]["token"], "abc");
    }
}
