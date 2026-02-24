//! Control UI HTTP endpoints
//!
//! Implements:
//! - GET /control/status - Gateway status
//! - GET /control/channels - Channel status
//! - POST /control/config - Config updates
//! - POST /control/tasks - Create objective task
//! - GET /control/tasks - List objective tasks
//! - GET /control/tasks/{id} - Get task by ID
//! - PATCH /control/tasks/{id} - Update task payload/policy
//! - POST /control/tasks/{id}/cancel - Cancel task
//! - POST /control/tasks/{id}/retry - Retry task
//! - POST /control/tasks/{id}/resume - Resume blocked task

use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::sync::Arc;

use crate::auth;
use crate::channels::{ChannelRegistry, ChannelStatus};
use crate::config;
use crate::cron::CronPayload;
use crate::logging::audit::{audit, AuditEvent};
use crate::server::connect_info::MaybeConnectInfo;
use crate::server::ws::{map_validation_issues, persist_config_file, read_config_snapshot};
use crate::tasks::{DurableTask, TaskPolicy, TaskPolicyPatch, TaskQueue, TaskState};

const PROTECTED_CONFIG_PREFIXES: &[&str] = &[
    "gateway.auth",
    "gateway.hooks.token",
    "credentials",
    "secrets",
    "anthropic.apiKey",
    "openai.apiKey",
    "google.apiKey",
    "venice.apiKey",
    "ollama.apiKey",
    "providers.ollama.apiKey",
    "bedrock.accessKeyId",
    "bedrock.secretAccessKey",
    "bedrock.sessionToken",
    "models.providers.openai.apiKey",
    "telegram.botToken",
    "telegram.webhookSecret",
    "discord.botToken",
    "slack.botToken",
    "slack.signingSecret",
    "anthropic.baseUrl",
    "openai.baseUrl",
    "google.baseUrl",
    "venice.baseUrl",
    "ollama.baseUrl",
    "providers.ollama.baseUrl",
    "models.providers.openai.baseUrl",
];

/// Control endpoint state
#[derive(Clone)]
pub struct ControlState {
    /// Gateway auth token
    pub gateway_token: Option<String>,
    /// Gateway auth password
    pub gateway_password: Option<String>,
    /// Gateway auth mode
    pub gateway_auth_mode: auth::AuthMode,
    /// Whether Tailscale auth is allowed for gateway endpoints
    pub gateway_allow_tailscale: bool,
    /// Trusted proxy IPs for local-direct detection
    pub trusted_proxies: Vec<String>,
    /// Channel registry
    pub channel_registry: Arc<ChannelRegistry>,
    /// Gateway version
    pub version: String,
    /// Gateway start time (Unix timestamp)
    pub start_time: i64,
    /// Durable task queue (available only when runtime state is attached).
    pub task_queue: Option<Arc<TaskQueue>>,
}

impl Default for ControlState {
    fn default() -> Self {
        ControlState {
            gateway_token: None,
            gateway_password: None,
            gateway_auth_mode: auth::AuthMode::Token,
            gateway_allow_tailscale: false,
            trusted_proxies: Vec::new(),
            channel_registry: Arc::new(ChannelRegistry::new()),
            version: env!("CARGO_PKG_VERSION").to_string(),
            start_time: chrono::Utc::now().timestamp(),
            task_queue: None,
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
    /// System diagnostics (disk, memory, fds, LLM reachability)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub diagnostics: Option<crate::server::health::SystemDiagnostics>,
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

/// Task create request.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TaskCreateRequest {
    pub payload: CronPayload,
    #[serde(default)]
    pub next_run_at_ms: Option<u64>,
    #[serde(default)]
    pub policy: Option<TaskPolicyRequest>,
}

/// Optional per-task continuation policy overrides.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TaskPolicyRequest {
    #[serde(default)]
    pub max_attempts: Option<u32>,
    #[serde(default)]
    pub max_total_runtime_ms: Option<u64>,
    #[serde(default)]
    pub max_turns: Option<u32>,
    #[serde(default)]
    pub max_run_timeout_seconds: Option<u32>,
}

/// Task list query parameters.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TaskListQuery {
    #[serde(default)]
    pub state: Option<String>,
    #[serde(default)]
    pub limit: Option<usize>,
}

/// Task cancel request.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TaskCancelRequest {
    #[serde(default)]
    pub reason: Option<String>,
}

/// Task retry request.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TaskRetryRequest {
    #[serde(default)]
    pub delay_ms: Option<u64>,
    #[serde(default)]
    pub reason: Option<String>,
}

/// Task resume request.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TaskResumeRequest {
    #[serde(default)]
    pub delay_ms: Option<u64>,
    #[serde(default)]
    pub reason: Option<String>,
}

/// Task update request.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TaskUpdateRequest {
    #[serde(default)]
    pub payload: Option<Value>,
    #[serde(default)]
    pub policy: Option<TaskPolicyRequest>,
    #[serde(default)]
    pub reason: Option<String>,
}

const MAX_TASK_REASON_LEN: usize = 1024;
const MAX_TASK_ATTEMPTS_LIMIT: u32 = 10_000;
const MAX_TASK_TOTAL_RUNTIME_MS_LIMIT: u64 = 30 * 24 * 60 * 60 * 1000;
const MAX_TASK_TURNS_LIMIT: u32 = 1_000;
const MAX_TASK_RUN_TIMEOUT_SECONDS_LIMIT: u32 = 24 * 60 * 60;

fn resolve_policy_bound<T>(value: T, max: T, field: &str) -> Result<T, String>
where
    T: Copy + PartialOrd + From<u8> + std::fmt::Display,
{
    if value < T::from(1) || value > max {
        Err(format!(
            "invalid policy.{field}: must be between 1 and {max}"
        ))
    } else {
        Ok(value)
    }
}

fn resolve_task_policy(input: Option<TaskPolicyRequest>) -> Result<TaskPolicy, String> {
    let mut policy = TaskPolicy::default();
    let Some(input) = input else {
        return Ok(policy);
    };

    if let Some(max_attempts) = input.max_attempts {
        policy.max_attempts =
            resolve_policy_bound(max_attempts, MAX_TASK_ATTEMPTS_LIMIT, "maxAttempts")?;
    }

    if let Some(max_total_runtime_ms) = input.max_total_runtime_ms {
        policy.max_total_runtime_ms = resolve_policy_bound(
            max_total_runtime_ms,
            MAX_TASK_TOTAL_RUNTIME_MS_LIMIT,
            "maxTotalRuntimeMs",
        )?;
    }

    if let Some(max_turns) = input.max_turns {
        policy.max_turns = resolve_policy_bound(max_turns, MAX_TASK_TURNS_LIMIT, "maxTurns")?;
    }

    if let Some(max_run_timeout_seconds) = input.max_run_timeout_seconds {
        policy.max_run_timeout_seconds = resolve_policy_bound(
            max_run_timeout_seconds,
            MAX_TASK_RUN_TIMEOUT_SECONDS_LIMIT,
            "maxRunTimeoutSeconds",
        )?;
    }

    Ok(policy)
}

fn resolve_task_policy_patch(input: TaskPolicyRequest) -> Result<TaskPolicyPatch, String> {
    let mut patch = TaskPolicyPatch::default();
    if let Some(max_attempts) = input.max_attempts {
        patch.max_attempts = Some(resolve_policy_bound(
            max_attempts,
            MAX_TASK_ATTEMPTS_LIMIT,
            "maxAttempts",
        )?);
    }
    if let Some(max_total_runtime_ms) = input.max_total_runtime_ms {
        patch.max_total_runtime_ms = Some(resolve_policy_bound(
            max_total_runtime_ms,
            MAX_TASK_TOTAL_RUNTIME_MS_LIMIT,
            "maxTotalRuntimeMs",
        )?);
    }
    if let Some(max_turns) = input.max_turns {
        patch.max_turns = Some(resolve_policy_bound(
            max_turns,
            MAX_TASK_TURNS_LIMIT,
            "maxTurns",
        )?);
    }
    if let Some(max_run_timeout_seconds) = input.max_run_timeout_seconds {
        patch.max_run_timeout_seconds = Some(resolve_policy_bound(
            max_run_timeout_seconds,
            MAX_TASK_RUN_TIMEOUT_SECONDS_LIMIT,
            "maxRunTimeoutSeconds",
        )?);
    }
    Ok(patch)
}

/// Single-task response.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TaskResponse {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub task: Option<DurableTask>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl TaskResponse {
    fn success(task: DurableTask) -> Self {
        TaskResponse {
            ok: true,
            task: Some(task),
            error: None,
        }
    }
}

/// Task list response.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TaskListResponse {
    pub ok: bool,
    pub total: usize,
    pub tasks: Vec<DurableTask>,
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
pub async fn status_handler(
    State(state): State<ControlState>,
    connect_info: MaybeConnectInfo,
    headers: HeaderMap,
) -> Response {
    // Check auth
    let remote_addr = connect_info.0;
    if let Some(err) = check_control_auth(&state, &headers, remote_addr) {
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

    // Gather system diagnostics
    let diagnostics = {
        let state_dir = crate::server::ws::resolve_state_dir();
        let checker = crate::server::health::HealthChecker::new(state_dir);
        Some(checker.gather_diagnostics(false))
    };

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
        diagnostics,
    };

    (StatusCode::OK, Json(response)).into_response()
}

/// GET /control/channels - Channel status
pub async fn channels_handler(
    State(state): State<ControlState>,
    connect_info: MaybeConnectInfo,
    headers: HeaderMap,
) -> Response {
    // Check auth
    let remote_addr = connect_info.0;
    if let Some(err) = check_control_auth(&state, &headers, remote_addr) {
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
    connect_info: MaybeConnectInfo,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    // Check auth
    let remote_addr = connect_info.0;
    if let Some(err) = check_control_auth(&state, &headers, remote_addr) {
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
    for prefix in PROTECTED_CONFIG_PREFIXES {
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

    let actor = remote_addr
        .map(|addr| addr.ip().to_string())
        .unwrap_or_else(|| "unknown".to_string());
    audit(AuditEvent::ConfigChanged {
        key_path: req.path.clone(),
        actor,
        method: "control_api".to_string(),
    });

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

/// POST /control/tasks - Create a durable task.
pub async fn tasks_create_handler(
    State(state): State<ControlState>,
    connect_info: MaybeConnectInfo,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let remote_addr = connect_info.0;
    if let Some(err) = check_control_auth(&state, &headers, remote_addr) {
        return err;
    }
    let Some(queue) = task_queue_or_unavailable(&state) else {
        return task_queue_unavailable_response();
    };

    let req: TaskCreateRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ControlError::new(format!("Invalid JSON: {}", e))),
            )
                .into_response();
        }
    };
    let TaskCreateRequest {
        payload: req_payload,
        next_run_at_ms,
        policy: policy_request,
    } = req;

    let payload = match serde_json::to_value(req_payload) {
        Ok(value) => value,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ControlError::new(format!("Invalid task payload: {}", e))),
            )
                .into_response();
        }
    };

    let policy = match resolve_task_policy(policy_request) {
        Ok(policy) => policy,
        Err(msg) => {
            return (StatusCode::BAD_REQUEST, Json(ControlError::new(msg))).into_response();
        }
    };

    let task = queue
        .enqueue_async_with_policy(payload, next_run_at_ms, policy)
        .await;
    if task.state == TaskState::Failed {
        let message = task.last_error.as_deref().unwrap_or("task queue full");
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ControlError::new(message)),
        )
            .into_response();
    }
    (StatusCode::CREATED, Json(TaskResponse::success(task))).into_response()
}

/// GET /control/tasks - List durable tasks.
pub async fn tasks_list_handler(
    State(state): State<ControlState>,
    connect_info: MaybeConnectInfo,
    headers: HeaderMap,
    Query(query): Query<TaskListQuery>,
) -> Response {
    let remote_addr = connect_info.0;
    if let Some(err) = check_control_auth(&state, &headers, remote_addr) {
        return err;
    }
    let Some(queue) = task_queue_or_unavailable(&state) else {
        return task_queue_unavailable_response();
    };

    let filter_state = if let Some(raw_state) = query.state.as_deref() {
        match parse_task_state(raw_state) {
            Some(state) => Some(state),
            None => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(ControlError::new("invalid task state filter")),
                )
                    .into_response();
            }
        }
    } else {
        None
    };

    let (total, tasks) = queue.list_filtered(filter_state, query.limit);

    (
        StatusCode::OK,
        Json(TaskListResponse {
            ok: true,
            total,
            tasks,
        }),
    )
        .into_response()
}

/// GET /control/tasks/{id} - Get a single durable task.
pub async fn tasks_get_handler(
    Path(task_id): Path<String>,
    State(state): State<ControlState>,
    connect_info: MaybeConnectInfo,
    headers: HeaderMap,
) -> Response {
    let remote_addr = connect_info.0;
    if let Some(err) = check_control_auth(&state, &headers, remote_addr) {
        return err;
    }
    let Some(queue) = task_queue_or_unavailable(&state) else {
        return task_queue_unavailable_response();
    };

    match queue.get(task_id.trim()) {
        Some(task) => (StatusCode::OK, Json(TaskResponse::success(task))).into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(ControlError::new("Task not found")),
        )
            .into_response(),
    }
}

/// POST /control/tasks/{id}/cancel - Cancel a durable task.
pub async fn tasks_cancel_handler(
    Path(task_id): Path<String>,
    State(state): State<ControlState>,
    connect_info: MaybeConnectInfo,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let remote_addr = connect_info.0;
    if let Some(err) = check_control_auth(&state, &headers, remote_addr) {
        return err;
    }
    let Some(queue) = task_queue_or_unavailable(&state) else {
        return task_queue_unavailable_response();
    };
    let req: TaskCancelRequest = match parse_optional_json(&body) {
        Ok(req) => req,
        Err(msg) => {
            return (StatusCode::BAD_REQUEST, Json(ControlError::new(msg))).into_response();
        }
    };
    let task_id = task_id.trim();
    let reason = match parse_optional_reason(req.reason) {
        Ok(reason) => reason,
        Err(msg) => {
            return (StatusCode::BAD_REQUEST, Json(ControlError::new(msg))).into_response();
        }
    };

    let Some(task) = queue.get(task_id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(ControlError::new("Task not found")),
        )
            .into_response();
    };
    if task.state.is_terminal() {
        return (
            StatusCode::CONFLICT,
            Json(ControlError::new("Task is already in a terminal state")),
        )
            .into_response();
    }

    if !queue.mark_cancelled(task_id, reason.as_deref()) {
        return (
            StatusCode::CONFLICT,
            Json(ControlError::new("Task state changed; cancel rejected")),
        )
            .into_response();
    }
    match queue.get(task_id) {
        Some(task) => (StatusCode::OK, Json(TaskResponse::success(task))).into_response(),
        None => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ControlError::new("Task updated but unavailable")),
        )
            .into_response(),
    }
}

/// PATCH /control/tasks/{id} - Update mutable task fields.
pub async fn tasks_patch_handler(
    Path(task_id): Path<String>,
    State(state): State<ControlState>,
    connect_info: MaybeConnectInfo,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let remote_addr = connect_info.0;
    if let Some(err) = check_control_auth(&state, &headers, remote_addr) {
        return err;
    }
    let Some(queue) = task_queue_or_unavailable(&state) else {
        return task_queue_unavailable_response();
    };
    let req: TaskUpdateRequest = match parse_optional_json(&body) {
        Ok(req) => req,
        Err(msg) => {
            return (StatusCode::BAD_REQUEST, Json(ControlError::new(msg))).into_response();
        }
    };
    let task_id = task_id.trim();
    let reason = match parse_optional_reason(req.reason) {
        Ok(reason) => reason,
        Err(msg) => {
            return (StatusCode::BAD_REQUEST, Json(ControlError::new(msg))).into_response();
        }
    };

    let Some(_task) = queue.get(task_id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(ControlError::new("Task not found")),
        )
            .into_response();
    };

    let payload = match req.payload {
        Some(payload) => {
            match serde_json::from_value::<CronPayload>(payload).and_then(serde_json::to_value) {
                Ok(normalized) => Some(normalized),
                Err(err) => {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(ControlError::new(format!("Invalid payload JSON: {err}"))),
                    )
                        .into_response();
                }
            }
        }
        None => None,
    };

    let policy_patch = match req.policy {
        Some(patch) => match resolve_task_policy_patch(patch) {
            Ok(patch) => Some(patch),
            Err(msg) => {
                return (StatusCode::BAD_REQUEST, Json(ControlError::new(msg))).into_response();
            }
        },
        None => None,
    };

    if payload.is_none()
        && reason.is_none()
        && policy_patch
            .as_ref()
            .is_none_or(|patch| !patch.has_updates())
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(ControlError::new(
                "Task patch requires payload, policy, or reason",
            )),
        )
            .into_response();
    }

    if !queue.patch_task(task_id, payload, policy_patch, reason.as_deref()) {
        return (
            StatusCode::CONFLICT,
            Json(ControlError::new("Task state changed; patch rejected")),
        )
            .into_response();
    }

    match queue.get(task_id) {
        Some(task) => (StatusCode::OK, Json(TaskResponse::success(task))).into_response(),
        None => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ControlError::new("Task updated but unavailable")),
        )
            .into_response(),
    }
}

/// POST /control/tasks/{id}/retry - Retry a durable task.
pub async fn tasks_retry_handler(
    Path(task_id): Path<String>,
    State(state): State<ControlState>,
    connect_info: MaybeConnectInfo,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let remote_addr = connect_info.0;
    if let Some(err) = check_control_auth(&state, &headers, remote_addr) {
        return err;
    }
    let Some(queue) = task_queue_or_unavailable(&state) else {
        return task_queue_unavailable_response();
    };
    let req: TaskRetryRequest = match parse_optional_json(&body) {
        Ok(req) => req,
        Err(msg) => {
            return (StatusCode::BAD_REQUEST, Json(ControlError::new(msg))).into_response();
        }
    };
    let task_id = task_id.trim();
    let reason = match parse_optional_reason(req.reason) {
        Ok(reason) => reason.unwrap_or_else(|| "retried by operator".to_string()),
        Err(msg) => {
            return (StatusCode::BAD_REQUEST, Json(ControlError::new(msg))).into_response();
        }
    };
    let delay_ms = req.delay_ms.unwrap_or(0);

    let Some(task) = queue.get(task_id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(ControlError::new("Task not found")),
        )
            .into_response();
    };
    // Operator retry is intentionally allowed for failed/blocked/cancelled tasks.
    if matches!(
        task.state,
        TaskState::Queued | TaskState::Running | TaskState::Done
    ) {
        return (
            StatusCode::CONFLICT,
            Json(ControlError::new(
                "Task is not retryable in its current state",
            )),
        )
            .into_response();
    }

    if !queue.mark_retry_wait(task_id, delay_ms, &reason) {
        return (
            StatusCode::CONFLICT,
            Json(ControlError::new("Task state changed; retry rejected")),
        )
            .into_response();
    }
    match queue.get(task_id) {
        Some(task) => (StatusCode::OK, Json(TaskResponse::success(task))).into_response(),
        None => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ControlError::new("Task updated but unavailable")),
        )
            .into_response(),
    }
}

/// POST /control/tasks/{id}/resume - Resume a blocked task.
pub async fn tasks_resume_handler(
    Path(task_id): Path<String>,
    State(state): State<ControlState>,
    connect_info: MaybeConnectInfo,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let remote_addr = connect_info.0;
    if let Some(err) = check_control_auth(&state, &headers, remote_addr) {
        return err;
    }
    let Some(queue) = task_queue_or_unavailable(&state) else {
        return task_queue_unavailable_response();
    };
    let req: TaskResumeRequest = match parse_optional_json(&body) {
        Ok(req) => req,
        Err(msg) => {
            return (StatusCode::BAD_REQUEST, Json(ControlError::new(msg))).into_response();
        }
    };
    let task_id = task_id.trim();
    let reason = match parse_optional_reason(req.reason) {
        Ok(reason) => reason.unwrap_or_else(|| "resumed by operator".to_string()),
        Err(msg) => {
            return (StatusCode::BAD_REQUEST, Json(ControlError::new(msg))).into_response();
        }
    };
    let delay_ms = req.delay_ms.unwrap_or(0);

    if !queue.resume_blocked_task(task_id, delay_ms, &reason) {
        if queue.get(task_id).is_none() {
            return (
                StatusCode::NOT_FOUND,
                Json(ControlError::new("Task not found")),
            )
                .into_response();
        }
        return (
            StatusCode::CONFLICT,
            Json(ControlError::new("Task is not blocked")),
        )
            .into_response();
    }

    match queue.get(task_id) {
        Some(task) => (StatusCode::OK, Json(TaskResponse::success(task))).into_response(),
        None => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ControlError::new("Task updated but unavailable")),
        )
            .into_response(),
    }
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

fn task_queue_or_unavailable(state: &ControlState) -> Option<Arc<TaskQueue>> {
    state.task_queue.clone()
}

fn task_queue_unavailable_response() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(ControlError::new("Task queue unavailable")),
    )
        .into_response()
}

fn parse_task_state(value: &str) -> Option<TaskState> {
    match value.trim().to_ascii_lowercase().as_str() {
        "queued" => Some(TaskState::Queued),
        "running" => Some(TaskState::Running),
        "blocked" => Some(TaskState::Blocked),
        "retry_wait" | "retry-wait" | "retrywait" => Some(TaskState::RetryWait),
        "done" => Some(TaskState::Done),
        "failed" => Some(TaskState::Failed),
        "cancelled" | "canceled" => Some(TaskState::Cancelled),
        _ => None,
    }
}

fn parse_optional_json<T>(body: &axum::body::Bytes) -> Result<T, String>
where
    T: DeserializeOwned + Default,
{
    if body.is_empty() || body.iter().all(|byte| byte.is_ascii_whitespace()) {
        return Ok(T::default());
    }
    serde_json::from_slice(body).map_err(|e| format!("Invalid JSON: {}", e))
}

fn parse_optional_reason(reason: Option<String>) -> Result<Option<String>, String> {
    let reason = reason
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string);
    if let Some(value) = &reason {
        if value.chars().count() > MAX_TASK_REASON_LEN {
            return Err(format!("reason exceeds {} characters", MAX_TASK_REASON_LEN));
        }
    }
    Ok(reason)
}

/// Check control endpoint authentication
fn check_control_auth(
    state: &ControlState,
    headers: &HeaderMap,
    remote_addr: Option<SocketAddr>,
) -> Option<Response> {
    // Extract bearer token
    let provided = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(|s| s.trim());

    let resolved = auth::ResolvedGatewayAuth {
        mode: state.gateway_auth_mode.clone(),
        token: state.gateway_token.clone(),
        password: state.gateway_password.clone(),
        allow_tailscale: state.gateway_allow_tailscale,
    };
    // HTTP bearer header is used for either token or password auth.
    let auth_result = auth::authorize_gateway_request(
        &resolved,
        provided,
        provided,
        headers,
        remote_addr,
        &state.trusted_proxies,
    );
    if auth_result.ok {
        return None;
    }
    Some((StatusCode::UNAUTHORIZED, Json(ControlError::unauthorized())).into_response())
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
            diagnostics: None,
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

    #[test]
    fn test_parse_optional_json_whitespace_body_defaults() {
        let body = axum::body::Bytes::from_static(b" \n\t ");
        let parsed: TaskCancelRequest =
            parse_optional_json(&body).expect("should parse as default");
        assert!(parsed.reason.is_none());
    }

    #[test]
    fn test_parse_optional_reason_enforces_max_length() {
        let long_reason = "a".repeat(MAX_TASK_REASON_LEN + 1);
        let err = parse_optional_reason(Some(long_reason)).expect_err("expected bound error");
        assert!(err.contains("reason exceeds"));
    }
}
