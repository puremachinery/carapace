//! Control UI HTTP endpoints
//!
//! Implements:
//! - GET /control/status - Gateway status
//! - GET /control/channels - Channel status
//! - GET /control/config - Redacted config snapshot + optimistic concurrency hash
//! - GET /control/onboarding/status - Shared provider onboarding/status snapshot
//! - PATCH /control/config - Safe config updates (controlUi subtree)
//! - POST /control/tasks - Create objective task
//! - GET /control/tasks - List objective tasks
//! - GET /control/tasks/{id} - Get task by ID
//! - PATCH /control/tasks/{id} - Update task payload/policy
//! - POST /control/tasks/{id}/cancel - Cancel task
//! - POST /control/tasks/{id}/retry - Retry task
//! - POST /control/tasks/{id}/resume - Resume blocked task

use axum::{
    extract::{Path, Query, State},
    http::{uri::Authority, HeaderMap, StatusCode, Uri},
    response::{IntoResponse, Response},
    Json,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::path::{Path as FsPath, PathBuf};
use std::sync::Arc;

use crate::auth;
use crate::auth::profiles::build_auth_profiles_config;
use crate::channels::matrix::{
    MatrixDeviceInfo, MatrixError, MatrixRuntimeHandle, MatrixVerificationInfo,
};
use crate::channels::{ChannelRegistry, ChannelStatus};
use crate::config;
use crate::cron::CronPayload;
use crate::logging::audit::{audit, AuditEvent};
use crate::onboarding;
use crate::plugins::{ChannelPluginInstance, DeliveryResult, OutboundContext};
use crate::server::connect_info::MaybeConnectInfo;
use crate::server::ws::{
    map_validation_issues, persist_config_file_with_base_hash, read_config_snapshot,
};
use crate::tasks::{DurableTask, TaskPolicy, TaskPolicyPatch, TaskQueue, TaskState};

const CONTROL_UI_MUTABLE_PREFIX: &str = "gateway.controlUi";

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
    /// Matrix runtime handle for daemon-owned device verification state.
    pub matrix_runtime: Option<Arc<MatrixRuntimeHandle>>,
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
            matrix_runtime: None,
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

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MatrixDevicesResponse {
    pub ok: bool,
    pub devices: Vec<MatrixDeviceInfo>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MatrixVerificationsResponse {
    pub ok: bool,
    pub verifications: Vec<MatrixVerificationInfo>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MatrixVerificationResponse {
    pub ok: bool,
    pub verification: MatrixVerificationInfo,
}

/// Wire request for `POST /control/matrix/send-test`.
///
/// `room_id` deserializes directly into `matrix_sdk::ruma::OwnedRoomId`
/// instead of `String` so a malformed Matrix room ID (zero-width
/// whitespace, missing `!` sigil, missing server suffix) is rejected
/// at the JSON-parse boundary with a clear "invalid Matrix room ID"
/// error — instead of being routed all the way through the actor
/// before failing at SDK send time with an opaque `BindingError`.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MatrixSendTestRequest {
    pub room_id: matrix_sdk::ruma::OwnedRoomId,
    #[serde(default)]
    pub text: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MatrixSendTestResponse {
    pub ok: bool,
    pub delivery: MatrixSendTestDelivery,
}

/// Wire-format outcome for `POST /control/matrix/send-test`.
///
/// Tagged sum (`outcome` discriminator) instead of a flat
/// `{ok, error?, messageId?, retryable}` shape so the type system
/// can't produce nonsense combinations like `ok: true, error:
/// Some(...)` or `ok: false, message_id: Some(...)`. The flat shape's
/// invariants depended on the producer keeping
/// `(ok, error.is_some(), message_id.is_some())` in sync — and there's
/// nothing that catches a future producer drift. The sum encodes the
/// invariant in the schema.
#[derive(Debug, Serialize)]
#[serde(tag = "outcome", rename_all = "camelCase")]
pub enum MatrixSendTestDelivery {
    #[serde(rename_all = "camelCase")]
    Sent {
        message_id: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        conversation_id: Option<String>,
    },
    #[serde(rename_all = "camelCase")]
    Failed {
        error: String,
        retryable: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        conversation_id: Option<String>,
    },
}

impl From<DeliveryResult> for MatrixSendTestDelivery {
    fn from(value: DeliveryResult) -> Self {
        let DeliveryResult {
            ok,
            message_id,
            error,
            retryable,
            conversation_id,
            ..
        } = value;
        // Fail closed when `ok=true` is reported without a
        // `message_id`. Emitting `Sent { message_id: "" }` would
        // silently produce an empty-string event id that's
        // indistinguishable from a real ID for downstream automation.
        // Treat it as `Failed` with an explicit "no event id" message
        // so callers stay deterministic.
        match (ok, message_id) {
            (true, Some(message_id)) => Self::Sent {
                message_id,
                conversation_id,
            },
            (true, None) => Self::Failed {
                error: "Matrix send reported success but the runtime did not return a Matrix \
                       event ID; treating as failure to avoid emitting an empty messageId"
                    .to_string(),
                retryable: false,
                conversation_id,
            },
            (false, _) => Self::Failed {
                error: error.unwrap_or_else(|| "send failed without an error message".to_string()),
                retryable,
                conversation_id,
            },
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MatrixActionResponse {
    pub ok: bool,
    /// Updated verification flow record reflecting the action's effect.
    /// Carries SAS data (emoji + decimals) when the SDK has reached a SAS
    /// state — operators read the response to `accept` directly to see
    /// the comparison values, instead of issuing a follow-up
    /// `verifications` GET that may race against record pruning.
    /// Required (not `Option`): the success branch always populates
    /// this field; failures take a separate response shape via
    /// `matrix_runtime_error_response`.
    pub verification: MatrixVerificationInfo,
}

/// `user_id` and `device_id` deserialize directly into the matrix-sdk
/// canonical types so malformed identifiers are rejected at the JSON
/// boundary with the same `400 Bad Request` shape `MatrixSendTestRequest`
/// already uses for `room_id`. Otherwise the runtime's
/// `MatrixError::InvalidUserId` would surface as a 422 after
/// traversing the actor — same outcome, more inertia.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MatrixVerificationStartRequest {
    pub user_id: matrix_sdk::ruma::OwnedUserId,
    #[serde(default)]
    pub device_id: Option<matrix_sdk::ruma::OwnedDeviceId>,
}

#[derive(Debug, Deserialize)]
pub struct MatrixVerificationConfirmRequest {
    #[serde(rename = "match")]
    pub matches: bool,
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
    pub status: ChannelStatus,
    /// Last connected timestamp (ISO 8601)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_connected_at: Option<String>,
    /// Last error message
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    /// Channel-specific runtime metadata.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extra: Option<Value>,
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

/// Config update response. Errors flow via `ControlError` rather
/// than an inline field — the producer always passes `error: None`
/// because failures are surfaced through the HTTP status path. The
/// field was removed in round 16; wire format unchanged because the
/// previous declaration carried `skip_serializing_if = "Option::is_none"`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfigUpdateResponse {
    /// Success flag
    pub ok: bool,
    /// Applied configuration
    #[serde(skip_serializing_if = "Option::is_none")]
    pub applied: Option<Value>,
    /// SHA256 hash of the persisted config (for subsequent optimistic concurrency)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
}

/// Config read response.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfigReadResponse {
    /// Success flag
    pub ok: bool,
    /// Redacted config snapshot
    pub config: Value,
    /// SHA256 hash of current config file (if present)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
}

/// Shared Control API onboarding status response.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ControlOnboardingStatusResponse {
    pub ok: bool,
    pub providers: Vec<ControlProviderOnboardingStatus>,
}

/// Control-facing onboarding status for a single provider.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ControlProviderOnboardingStatus {
    pub provider: onboarding::setup::SetupProvider,
    pub label: String,
    pub configured: bool,
    pub supported_auth_modes: Vec<onboarding::setup::SetupAuthMode>,
    /// Full set of browser/CLI entrypoints the UI may surface for this
    /// provider.
    pub available_entrypoints: Vec<ControlOnboardingEntrypoint>,
    /// Recommended CLI action for the provider's current state. When a UI
    /// wants a single default command, prefer this over enumerating the CLI
    /// entries in `available_entrypoints`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cli_setup_command: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assessment: Option<ControlSetupAssessment>,
}

/// A browser or CLI entrypoint the Control UI can surface for onboarding.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ControlOnboardingEntrypoint {
    pub kind: ControlOnboardingEntrypointKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_mode: Option<onboarding::setup::SetupAuthMode>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ControlOnboardingEntrypointKind {
    Browser,
    Cli,
}

/// Control-facing provider assessment. Intentionally omits auth-profile
/// identity details so the Control API does not expose raw profile names or
/// emails in browser-visible payloads.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ControlSetupAssessment {
    pub provider: onboarding::setup::SetupProvider,
    pub auth_mode: Option<onboarding::setup::SetupAuthMode>,
    pub status: onboarding::setup::SetupAssessmentStatus,
    pub summary: String,
    pub checks: Vec<ControlSetupCheck>,
}

/// Control-facing setup check. This strips auth-profile identifiers and loaded
/// identity strings before browser serialization.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ControlSetupCheck {
    pub name: String,
    pub status: onboarding::setup::SetupCheckStatus,
    pub kind: onboarding::setup::SetupCheckKind,
    pub detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
}

fn control_setup_summary(
    provider: onboarding::setup::SetupProvider,
    status: onboarding::setup::SetupAssessmentStatus,
) -> String {
    match status {
        onboarding::setup::SetupAssessmentStatus::Ready => {
            format!("{} setup looks ready for verification.", provider.label())
        }
        onboarding::setup::SetupAssessmentStatus::Partial => format!(
            "{} setup is written, but some live validation was skipped or not available.",
            provider.label()
        ),
        onboarding::setup::SetupAssessmentStatus::Invalid => {
            format!("{} setup is incomplete or invalid.", provider.label())
        }
    }
}

fn project_control_setup_check(check: onboarding::setup::SetupCheck) -> ControlSetupCheck {
    let onboarding::setup::SetupCheck {
        name,
        status,
        kind,
        detail: _,
        remediation,
        projection,
    } = check;

    let generic_detail = match (status, kind) {
        (
            onboarding::setup::SetupCheckStatus::Pass,
            onboarding::setup::SetupCheckKind::Requirement,
        ) => {
            format!("{name} is configured")
        }
        (
            onboarding::setup::SetupCheckStatus::Pass,
            onboarding::setup::SetupCheckKind::Validation,
        ) => {
            format!("{name} passed validation")
        }
        (
            onboarding::setup::SetupCheckStatus::Fail,
            onboarding::setup::SetupCheckKind::Requirement,
        ) => {
            format!("{name} requires attention")
        }
        (
            onboarding::setup::SetupCheckStatus::Fail,
            onboarding::setup::SetupCheckKind::Validation,
        ) => {
            format!("{name} failed validation")
        }
        (
            onboarding::setup::SetupCheckStatus::Skip,
            onboarding::setup::SetupCheckKind::Requirement,
        ) => {
            format!("{name} was skipped")
        }
        (
            onboarding::setup::SetupCheckStatus::Skip,
            onboarding::setup::SetupCheckKind::Validation,
        ) => {
            format!("{name} validation was skipped")
        }
    };

    let detail = match projection {
        onboarding::setup::SetupCheckProjection::GenericStatus => generic_detail,
        onboarding::setup::SetupCheckProjection::Code(
            onboarding::setup::SetupCheckCode::AuthProfileConfigured,
        ) => {
            format!("{name} is configured")
        }
        onboarding::setup::SetupCheckProjection::Code(
            onboarding::setup::SetupCheckCode::AuthProfileNotConfigured,
        ) => {
            format!("{name} is not configured")
        }
        onboarding::setup::SetupCheckProjection::Code(
            onboarding::setup::SetupCheckCode::AuthProfileLoaded,
        ) => {
            format!("{name} loaded from encrypted profile store")
        }
        onboarding::setup::SetupCheckProjection::Code(
            onboarding::setup::SetupCheckCode::AuthProfileWrongProvider,
        ) => {
            format!("{name} belongs to a different provider")
        }
        onboarding::setup::SetupCheckProjection::Code(
            onboarding::setup::SetupCheckCode::AuthProfileWrongCredentialType,
        ) => {
            format!("{name} uses the wrong credential type")
        }
        onboarding::setup::SetupCheckProjection::Code(
            onboarding::setup::SetupCheckCode::AuthProfileTokenDecryptFailed,
        ) => {
            format!("{name} token could not be decrypted; check CARAPACE_CONFIG_PASSWORD")
        }
        onboarding::setup::SetupCheckProjection::Code(
            onboarding::setup::SetupCheckCode::AuthProfileTokenMissing,
        ) => {
            format!("{name} has no usable token")
        }
        onboarding::setup::SetupCheckProjection::Code(
            onboarding::setup::SetupCheckCode::AuthProfileMissing,
        ) => {
            format!("{name} was not found in the encrypted profile store")
        }
        onboarding::setup::SetupCheckProjection::Code(
            onboarding::setup::SetupCheckCode::AuthProfileStoreReadFailed,
        ) => "failed to read the encrypted profile store".to_string(),
        onboarding::setup::SetupCheckProjection::Code(
            onboarding::setup::SetupCheckCode::LocalValidationFailed,
        ) => {
            format!("{name} failed local validation")
        }
    };

    ControlSetupCheck {
        name,
        status,
        kind,
        detail,
        remediation,
    }
}

impl From<onboarding::setup::SetupAssessment> for ControlSetupAssessment {
    fn from(value: onboarding::setup::SetupAssessment) -> Self {
        Self {
            provider: value.provider,
            auth_mode: value.auth_mode,
            status: value.status,
            summary: control_setup_summary(value.provider, value.status),
            checks: value
                .checks
                .into_iter()
                .map(project_control_setup_check)
                .collect(),
        }
    }
}

/// Shared shape returned by onboarding apply/save handlers.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ControlOnboardingApplyResponse {
    pub ok: bool,
    /// Control-owned browser-visible apply payload. This intentionally exposes
    /// only the applied auth path instead of forwarding provider-internal
    /// onboarding details.
    pub applied: ControlOnboardingApplied,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
    pub provider_status: ControlProviderOnboardingStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ControlOnboardingAppliedMode {
    #[serde(rename = "apiKey")]
    ApiKey,
    #[serde(rename = "oauth")]
    OAuth,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ControlOnboardingApplied {
    pub mode: ControlOnboardingAppliedMode,
}

impl ControlOnboardingAppliedMode {
    fn applied(self) -> ControlOnboardingApplied {
        ControlOnboardingApplied { mode: self }
    }
}

fn serialize_control_onboarding_applied_mode(mode: ControlOnboardingAppliedMode) -> Option<String> {
    serde_json::to_value(mode)
        .ok()
        .and_then(|value| value.as_str().map(ToOwned::to_owned))
}

fn invalid_control_onboarding_apply_result_message() -> String {
    "Provider onboarding apply result was invalid; check server logs.".to_string()
}

fn validate_control_onboarding_applied_mode(
    applied: &Value,
    expected_mode: ControlOnboardingAppliedMode,
) -> Result<ControlOnboardingApplied, String> {
    let expected_mode_name = serialize_control_onboarding_applied_mode(expected_mode)
        .unwrap_or_else(|| "<unknown expected mode>".to_string());
    let reported_mode_value = applied.get("mode").cloned().ok_or_else(|| {
        let applied_keys = applied
            .as_object()
            .map(|entries| entries.keys().cloned().collect::<Vec<_>>())
            .unwrap_or_default();
        tracing::warn!(
            expected_mode = %expected_mode_name,
            applied_keys = ?applied_keys,
            "control onboarding apply result missing mode"
        );
        invalid_control_onboarding_apply_result_message()
    })?;
    let reported_mode =
        serde_json::from_value::<ControlOnboardingAppliedMode>(reported_mode_value.clone())
            .map_err(|_| {
                tracing::warn!(
                    expected_mode = %expected_mode_name,
                    reported_mode = ?reported_mode_value,
                    "control onboarding apply result reported invalid mode"
                );
                invalid_control_onboarding_apply_result_message()
            })?;

    if reported_mode != expected_mode {
        let reported_mode_name = serialize_control_onboarding_applied_mode(reported_mode)
            .unwrap_or_else(|| "<unknown reported mode>".to_string());
        tracing::warn!(
            expected_mode = %expected_mode_name,
            reported_mode = %reported_mode_name,
            "control onboarding apply result reported unexpected mode"
        );
        return Err(invalid_control_onboarding_apply_result_message());
    }

    Ok(expected_mode.applied())
}

#[derive(Default)]
struct OAuthStartInputs {
    client_id_override: Option<String>,
    client_secret_override: Option<String>,
    redirect_base_url: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GeminiApiKeyRequest {
    pub api_key: String,
    #[serde(default)]
    pub base_url: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GeminiOAuthCallbackQuery {
    #[serde(default)]
    pub code: Option<String>,
    #[serde(default)]
    pub state: Option<String>,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub error_description: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CodexOAuthCallbackQuery {
    #[serde(default)]
    pub code: Option<String>,
    #[serde(default)]
    pub state: Option<String>,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub error_description: Option<String>,
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
            status: c.status,
            last_connected_at: c.metadata.last_connected_at.and_then(|ts| {
                chrono::DateTime::from_timestamp(ts / 1000, 0)
                    .map(|dt| dt.format("%Y-%m-%dT%H:%M:%SZ").to_string())
            }),
            last_error: c.metadata.last_error,
            extra: c.metadata.extra,
        })
        .collect();

    let response = ChannelsStatusResponse {
        total: channel_items.len(),
        connected: connected_count,
        channels: channel_items,
    };

    (StatusCode::OK, Json(response)).into_response()
}

/// GET /control/matrix/devices - list Matrix devices known to the daemon.
pub async fn matrix_devices_handler(
    State(state): State<ControlState>,
    connect_info: MaybeConnectInfo,
    headers: HeaderMap,
) -> Response {
    let remote_addr = connect_info.0;
    if let Some(err) = check_control_auth(&state, &headers, remote_addr) {
        return err;
    }
    let Some(runtime) = matrix_runtime_or_unavailable(&state) else {
        return matrix_runtime_unavailable_response();
    };

    (
        StatusCode::OK,
        Json(MatrixDevicesResponse {
            ok: true,
            devices: runtime.devices(),
        }),
    )
        .into_response()
}

/// GET /control/matrix/verifications - list pending Matrix verification flows.
pub async fn matrix_verifications_handler(
    State(state): State<ControlState>,
    connect_info: MaybeConnectInfo,
    headers: HeaderMap,
) -> Response {
    let remote_addr = connect_info.0;
    if let Some(err) = check_control_auth(&state, &headers, remote_addr) {
        return err;
    }
    let Some(runtime) = matrix_runtime_or_unavailable(&state) else {
        return matrix_runtime_unavailable_response();
    };

    (
        StatusCode::OK,
        Json(MatrixVerificationsResponse {
            ok: true,
            verifications: runtime.verifications(),
        }),
    )
        .into_response()
}

/// POST /control/matrix/send-test - send a Matrix verification test message.
pub async fn matrix_send_test_handler(
    State(state): State<ControlState>,
    connect_info: MaybeConnectInfo,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let remote_addr = connect_info.0;
    if let Some(err) = check_control_auth(&state, &headers, remote_addr) {
        return err;
    }
    let Some(runtime) = matrix_runtime_or_unavailable(&state) else {
        return matrix_runtime_unavailable_response();
    };
    let req: MatrixSendTestRequest = match serde_json::from_slice(&body) {
        Ok(req) => req,
        Err(err) => {
            // Either non-JSON body OR malformed Matrix room ID — both
            // are caller-actionable. The serde error message includes
            // the field name, so a malformed room_id surfaces as
            // "invalid Matrix room ID" without leaking
            // server-internal context.
            return (
                StatusCode::BAD_REQUEST,
                Json(ControlError::new(format!("Invalid request: {err}"))),
            )
                .into_response();
        }
    };
    let room_id = req.room_id.to_string();
    let text = req.text.unwrap_or_else(|| {
        format!(
            "Carapace Matrix verification ping at {}",
            chrono::Utc::now().to_rfc3339()
        )
    });
    let channel = runtime.channel();
    let ctx = OutboundContext {
        to: room_id,
        text,
        media_url: None,
        gif_playback: false,
        reply_to_id: None,
        thread_id: None,
        account_id: None,
    };
    match tokio::task::spawn_blocking(move || channel.send_text(ctx)).await {
        Ok(Ok(delivery)) => {
            let ok = delivery.ok;
            (
                StatusCode::OK,
                Json(MatrixSendTestResponse {
                    ok,
                    delivery: delivery.into(),
                }),
            )
                .into_response()
        }
        Ok(Err(err)) => (
            StatusCode::BAD_GATEWAY,
            Json(ControlError::new(
                crate::logging::redact::RedactedDisplay(&err).to_string(),
            )),
        )
            .into_response(),
        Err(err) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ControlError::new(format!(
                "Matrix send-test task failed: {err}"
            ))),
        )
            .into_response(),
    }
}

/// POST /control/matrix/verifications - start a Matrix device verification.
pub async fn matrix_verification_start_handler(
    State(state): State<ControlState>,
    connect_info: MaybeConnectInfo,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let remote_addr = connect_info.0;
    if let Some(err) = check_control_auth(&state, &headers, remote_addr) {
        return err;
    }
    let Some(runtime) = matrix_runtime_or_unavailable(&state) else {
        return matrix_runtime_unavailable_response();
    };

    let req: MatrixVerificationStartRequest = match serde_json::from_slice(&body) {
        Ok(req) => req,
        Err(err) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ControlError::new(format!("Invalid JSON: {err}"))),
            )
                .into_response();
        }
    };
    // Empty-string filtering is no longer needed: serde now rejects an
    // empty/whitespace `user_id` at the JSON boundary, and `device_id`
    // is `Option<OwnedDeviceId>` — an absent or empty deviceId still
    // arrives as `None` after deserialize, but a non-empty deviceId is
    // already validated.
    let user_id = req.user_id.to_string();
    let device_id = req.device_id.map(|value| value.to_string());

    match runtime.start_verification(user_id, device_id).await {
        Ok(verification) => (
            StatusCode::CREATED,
            Json(MatrixVerificationResponse {
                ok: true,
                verification,
            }),
        )
            .into_response(),
        Err(err) => matrix_runtime_error_response(err),
    }
}

/// POST /control/matrix/verifications/{flow_id}/accept - accept a verification flow.
pub async fn matrix_verification_accept_handler(
    Path(flow_id): Path<String>,
    State(state): State<ControlState>,
    connect_info: MaybeConnectInfo,
    headers: HeaderMap,
) -> Response {
    matrix_verification_action_handler(
        flow_id,
        state,
        connect_info,
        headers,
        MatrixControlVerificationAction::Accept,
    )
    .await
}

/// POST /control/matrix/verifications/{flow_id}/confirm - confirm or reject SAS.
pub async fn matrix_verification_confirm_handler(
    Path(flow_id): Path<String>,
    State(state): State<ControlState>,
    connect_info: MaybeConnectInfo,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let remote_addr = connect_info.0;
    if let Some(err) = check_control_auth(&state, &headers, remote_addr) {
        return err;
    }
    let req: MatrixVerificationConfirmRequest = match serde_json::from_slice(&body) {
        Ok(req) => req,
        Err(err) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ControlError::new(format!("Invalid JSON: {err}"))),
            )
                .into_response();
        }
    };
    matrix_verification_action_handler(
        flow_id,
        state,
        connect_info,
        headers,
        MatrixControlVerificationAction::Confirm {
            matches: req.matches,
        },
    )
    .await
}

/// POST /control/matrix/verifications/{flow_id}/cancel - cancel a verification flow.
pub async fn matrix_verification_cancel_handler(
    Path(flow_id): Path<String>,
    State(state): State<ControlState>,
    connect_info: MaybeConnectInfo,
    headers: HeaderMap,
) -> Response {
    matrix_verification_action_handler(
        flow_id,
        state,
        connect_info,
        headers,
        MatrixControlVerificationAction::Cancel,
    )
    .await
}

/// PATCH /control/config - Update configuration for safe allowlisted paths.
pub async fn config_patch_handler(
    state: State<ControlState>,
    connect_info: MaybeConnectInfo,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    config_update_handler(state, connect_info, headers, body).await
}

async fn config_update_handler(
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

    let path = req.path.trim();
    if path.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ControlError::new("Configuration path is required")),
        )
            .into_response();
    }

    // Block sensitive paths first.
    if let Some(prefix) = config::protected_config_prefix(path) {
        return (
            StatusCode::FORBIDDEN,
            Json(ControlError::new(format!(
                "Cannot modify protected configuration: {}",
                prefix
            ))),
        )
            .into_response();
    }

    // Restrict PATCH writes to the explicit controlUi subtree.
    if !is_allowed_control_ui_config_path(path) {
        return (
            StatusCode::FORBIDDEN,
            Json(ControlError::new(
                "Control API config writes are limited to gateway.controlUi.*",
            )),
        )
            .into_response();
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

    // Apply the path-based update to `snapshot.parsed` — the pure
    // JSON5 parse of the on-disk file with `${VAR}` placeholders and
    // `enc:v2:` ciphertexts preserved verbatim. `snapshot.raw_config`
    // is the env-substituted + secret-decrypted view, so persisting
    // it would silently materialize operator secrets into the config
    // file (the `seal_config_secrets` re-encrypt pass is a no-op when
    // `CARAPACE_CONFIG_PASSWORD` is unset). The corrupt-base guard in
    // `persist_config_file_with_base_hash` rejects writes when
    // `parsed` is `Null` from a parse failure, so we never operate on
    // a corrupted base here.
    let mut updated_config = snapshot.parsed.clone();
    set_value_at_path(&mut updated_config, path, req.value.clone());

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

    // Persist the updated config atomically. The optimistic-concurrency
    // conflict (on-disk hash drifted between snapshot and lock) is a
    // client-side race, not a server fault — surface it as 409 Conflict
    // so callers can re-read and retry. Other failures stay 500.
    let config_path = config::get_config_path();
    if let Err(err) =
        persist_config_file_with_base_hash(&config_path, &updated_config, snapshot.hash.as_deref())
    {
        let status = err.http_status();
        return (status, Json(ControlError::new(err.into_message()))).into_response();
    }

    audit(AuditEvent::ConfigChanged {
        key_path: path.to_string(),
        actor: control_actor(remote_addr),
        method: "control_api".to_string(),
    });

    // Re-read to get the new hash
    let new_snapshot = read_config_snapshot();

    let mut redacted_config = new_snapshot.config;
    crate::logging::redact::redact_json_value(&mut redacted_config);

    let response = ConfigUpdateResponse {
        ok: true,
        applied: Some(json!({
            "path": path,
            "value": req.value,
            "config": redacted_config,
        })),
        hash: new_snapshot.hash,
    };

    (StatusCode::OK, Json(response)).into_response()
}

/// GET /control/config - Read redacted config + hash for optimistic concurrency.
pub async fn config_read_handler(
    State(state): State<ControlState>,
    connect_info: MaybeConnectInfo,
    headers: HeaderMap,
) -> Response {
    let remote_addr = connect_info.0;
    if let Some(err) = check_control_auth(&state, &headers, remote_addr) {
        return err;
    }

    let snapshot = read_config_snapshot();
    let mut redacted = snapshot.config;
    crate::logging::redact::redact_json_value(&mut redacted);

    (
        StatusCode::OK,
        Json(ConfigReadResponse {
            ok: true,
            config: redacted,
            hash: snapshot.hash,
        }),
    )
        .into_response()
}

fn browser_onboarding_entrypoints(
    provider: onboarding::setup::SetupProvider,
) -> Vec<ControlOnboardingEntrypoint> {
    use onboarding::setup::{SetupAuthMode, SetupProvider};

    match provider {
        SetupProvider::Gemini => vec![
            ControlOnboardingEntrypoint {
                kind: ControlOnboardingEntrypointKind::Browser,
                auth_mode: Some(SetupAuthMode::OAuth),
                path: Some("/control/onboarding/gemini/oauth/start".to_string()),
                command: None,
            },
            ControlOnboardingEntrypoint {
                kind: ControlOnboardingEntrypointKind::Browser,
                auth_mode: Some(SetupAuthMode::ApiKey),
                path: Some("/control/onboarding/gemini/api-key".to_string()),
                command: None,
            },
        ],
        SetupProvider::Codex => vec![ControlOnboardingEntrypoint {
            kind: ControlOnboardingEntrypointKind::Browser,
            auth_mode: Some(SetupAuthMode::OAuth),
            path: Some("/control/onboarding/codex/oauth/start".to_string()),
            command: None,
        }],
        _ => Vec::new(),
    }
}

fn cli_onboarding_entrypoints(
    provider: onboarding::setup::SetupProvider,
) -> Vec<ControlOnboardingEntrypoint> {
    let supported_auth_modes = provider.supported_auth_modes();
    if supported_auth_modes.is_empty() {
        return provider
            .setup_command(None)
            .map(|command| {
                vec![ControlOnboardingEntrypoint {
                    kind: ControlOnboardingEntrypointKind::Cli,
                    auth_mode: None,
                    path: None,
                    command: Some(command),
                }]
            })
            .unwrap_or_default();
    }

    supported_auth_modes
        .iter()
        .filter_map(|auth_mode| {
            provider
                .setup_command(Some(*auth_mode))
                .map(|command| ControlOnboardingEntrypoint {
                    kind: ControlOnboardingEntrypointKind::Cli,
                    auth_mode: Some(*auth_mode),
                    path: None,
                    command: Some(command),
                })
        })
        .collect()
}

fn control_onboarding_entrypoints(
    provider: onboarding::setup::SetupProvider,
) -> Vec<ControlOnboardingEntrypoint> {
    let mut entrypoints = browser_onboarding_entrypoints(provider);
    entrypoints.extend(cli_onboarding_entrypoints(provider));
    entrypoints
}

fn build_control_provider_onboarding_status(
    configured_cfg: &Value,
    assessment_cfg: &Value,
    state_dir: &FsPath,
    provider: onboarding::setup::SetupProvider,
) -> ControlProviderOnboardingStatus {
    let configured = provider.is_configured(configured_cfg);
    let assessment = configured.then(|| {
        onboarding::setup::assess_provider_setup(assessment_cfg, state_dir, provider, vec![])
    });
    let cli_setup_command = provider.setup_command(assessment.as_ref().and_then(|it| it.auth_mode));

    ControlProviderOnboardingStatus {
        provider,
        label: provider.label().to_string(),
        configured,
        supported_auth_modes: provider.supported_auth_modes().to_vec(),
        available_entrypoints: control_onboarding_entrypoints(provider),
        cli_setup_command,
        assessment: assessment.map(ControlSetupAssessment::from),
    }
}

fn build_control_onboarding_statuses(
    configured_cfg: &Value,
    assessment_cfg: &Value,
    state_dir: &FsPath,
) -> Vec<ControlProviderOnboardingStatus> {
    onboarding::setup::SetupProvider::all()
        .iter()
        .copied()
        .map(|provider| {
            build_control_provider_onboarding_status(
                configured_cfg,
                assessment_cfg,
                state_dir,
                provider,
            )
        })
        .collect()
}

async fn build_control_provider_onboarding_status_async(
    configured_cfg: Value,
    assessment_cfg: Value,
    state_dir: PathBuf,
    provider: onboarding::setup::SetupProvider,
) -> Result<ControlProviderOnboardingStatus, String> {
    tokio::task::spawn_blocking(move || {
        build_control_provider_onboarding_status(
            &configured_cfg,
            &assessment_cfg,
            &state_dir,
            provider,
        )
    })
    .await
    .map_err(|err| format!("failed to build provider onboarding status: {err}"))
}

async fn build_control_onboarding_statuses_async(
    configured_cfg: Value,
    assessment_cfg: Value,
    state_dir: PathBuf,
) -> Result<Vec<ControlProviderOnboardingStatus>, String> {
    tokio::task::spawn_blocking(move || {
        build_control_onboarding_statuses(&configured_cfg, &assessment_cfg, &state_dir)
    })
    .await
    .map_err(|err| format!("failed to build onboarding statuses: {err}"))
}

/// GET /control/onboarding/status - Shared provider onboarding/status snapshot.
pub async fn onboarding_status_handler(
    State(state): State<ControlState>,
    connect_info: MaybeConnectInfo,
    headers: HeaderMap,
) -> Response {
    let remote_addr = connect_info.0;
    if let Some(err) = check_control_auth(&state, &headers, remote_addr) {
        return err;
    }

    let snapshot = read_config_snapshot();
    let state_dir = crate::server::ws::resolve_state_dir();
    let providers = match build_control_onboarding_statuses_async(
        snapshot.raw_config,
        snapshot.config,
        state_dir,
    )
    .await
    {
        Ok(providers) => providers,
        Err(err) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ControlError::new(err)),
            )
                .into_response();
        }
    };
    (
        StatusCode::OK,
        Json(ControlOnboardingStatusResponse {
            ok: true,
            providers,
        }),
    )
        .into_response()
}

/// POST /control/onboarding/gemini/oauth/start - Begin Gemini Google sign-in.
pub async fn gemini_oauth_start_handler(
    State(state): State<ControlState>,
    connect_info: MaybeConnectInfo,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let remote_addr = connect_info.0;
    if let Some(err) = check_control_auth(&state, &headers, remote_addr) {
        return err;
    }

    let inputs = match parse_oauth_start_inputs(&body) {
        Ok(inputs) => inputs,
        Err(msg) => {
            return (StatusCode::BAD_REQUEST, Json(ControlError::new(msg))).into_response();
        }
    };

    let snapshot = read_config_snapshot();
    let redirect_base_url = match inputs
        .redirect_base_url
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        Some(value) => match sanitize_control_redirect_base_url(value) {
            Ok(validated) => Some(validated),
            Err(msg) => {
                return (StatusCode::BAD_REQUEST, Json(ControlError::new(msg))).into_response();
            }
        },
        None => configured_control_redirect_base_url(&snapshot.config)
            .or_else(|| control_request_base_url(&headers)),
    };

    let Some(redirect_base_url) = redirect_base_url else {
        return (
            StatusCode::BAD_REQUEST,
            Json(ControlError::new(
                "Unable to determine Control UI base URL for Gemini callback",
            )),
        )
            .into_response();
    };

    match onboarding::gemini::start_control_google_oauth(
        &snapshot.config,
        inputs.client_id_override,
        inputs.client_secret_override,
        &redirect_base_url,
    ) {
        Ok(started) => (
            StatusCode::OK,
            Json(json!({
                "ok": true,
                "flowId": started.flow_id,
                "authUrl": started.auth_url,
                "redirectUri": started.redirect_uri,
            })),
        )
            .into_response(),
        Err(err) => (StatusCode::BAD_REQUEST, Json(ControlError::new(err))).into_response(),
    }
}

/// GET /control/onboarding/gemini/oauth/{id} - Poll Gemini Google sign-in status.
pub async fn gemini_oauth_status_handler(
    Path(flow_id): Path<String>,
    State(state): State<ControlState>,
    connect_info: MaybeConnectInfo,
    headers: HeaderMap,
) -> Response {
    let remote_addr = connect_info.0;
    if let Some(err) = check_control_auth(&state, &headers, remote_addr) {
        return err;
    }

    match onboarding::gemini::control_google_oauth_status(flow_id.trim()) {
        Ok(status) => (
            StatusCode::OK,
            Json(json!({ "ok": true, "status": status })),
        )
            .into_response(),
        Err(err) => (StatusCode::NOT_FOUND, Json(ControlError::new(err))).into_response(),
    }
}

/// POST /control/onboarding/gemini/oauth/{id}/apply - Persist Gemini Google sign-in config.
pub async fn gemini_oauth_apply_handler(
    Path(flow_id): Path<String>,
    State(state): State<ControlState>,
    connect_info: MaybeConnectInfo,
    headers: HeaderMap,
) -> Response {
    let remote_addr = connect_info.0;
    if let Some(err) = check_control_auth(&state, &headers, remote_addr) {
        return err;
    }

    let state_dir = crate::server::ws::resolve_state_dir();
    match onboarding::gemini::apply_control_google_oauth(flow_id.trim(), state_dir.clone()) {
        Ok(applied) => {
            let applied = match validate_control_onboarding_applied_mode(
                &applied,
                ControlOnboardingAppliedMode::OAuth,
            ) {
                Ok(applied) => applied,
                Err(err) => {
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(ControlError::new(err)),
                    )
                        .into_response();
                }
            };
            let snapshot = read_config_snapshot();
            let hash = snapshot.hash;
            let provider_status = match build_control_provider_onboarding_status_async(
                snapshot.raw_config,
                snapshot.config,
                state_dir,
                onboarding::setup::SetupProvider::Gemini,
            )
            .await
            {
                Ok(provider_status) => provider_status,
                Err(err) => {
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(ControlError::new(err)),
                    )
                        .into_response();
                }
            };
            (
                StatusCode::OK,
                Json(ControlOnboardingApplyResponse {
                    ok: true,
                    applied,
                    hash,
                    provider_status,
                }),
            )
                .into_response()
        }
        Err(err) => (StatusCode::BAD_REQUEST, Json(ControlError::new(err))).into_response(),
    }
}

/// POST /control/onboarding/codex/oauth/start - Begin Codex OpenAI sign-in.
pub async fn codex_oauth_start_handler(
    State(state): State<ControlState>,
    connect_info: MaybeConnectInfo,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let remote_addr = connect_info.0;
    if let Some(err) = check_control_auth(&state, &headers, remote_addr) {
        return err;
    }

    let inputs = match parse_oauth_start_inputs(&body) {
        Ok(inputs) => inputs,
        Err(msg) => {
            return (StatusCode::BAD_REQUEST, Json(ControlError::new(msg))).into_response();
        }
    };

    let snapshot = read_config_snapshot();
    let redirect_base_url = match inputs
        .redirect_base_url
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        Some(value) => match sanitize_control_redirect_base_url(value) {
            Ok(validated) => Some(validated),
            Err(msg) => {
                return (StatusCode::BAD_REQUEST, Json(ControlError::new(msg))).into_response();
            }
        },
        None => configured_control_redirect_base_url(&snapshot.config)
            .or_else(|| control_request_base_url(&headers)),
    };

    let Some(redirect_base_url) = redirect_base_url else {
        return (
            StatusCode::BAD_REQUEST,
            Json(ControlError::new(
                "Unable to determine Control UI base URL for Codex callback",
            )),
        )
            .into_response();
    };

    match onboarding::codex::start_control_openai_oauth(
        &snapshot.config,
        inputs.client_id_override,
        inputs.client_secret_override,
        &redirect_base_url,
    ) {
        Ok(started) => (
            StatusCode::OK,
            Json(json!({
                "ok": true,
                "flowId": started.flow_id,
                "authUrl": started.auth_url,
                "redirectUri": started.redirect_uri,
            })),
        )
            .into_response(),
        Err(err) => (StatusCode::BAD_REQUEST, Json(ControlError::new(err))).into_response(),
    }
}

/// GET /control/onboarding/codex/oauth/{id} - Poll Codex OpenAI sign-in status.
pub async fn codex_oauth_status_handler(
    Path(flow_id): Path<String>,
    State(state): State<ControlState>,
    connect_info: MaybeConnectInfo,
    headers: HeaderMap,
) -> Response {
    let remote_addr = connect_info.0;
    if let Some(err) = check_control_auth(&state, &headers, remote_addr) {
        return err;
    }

    match onboarding::codex::control_openai_oauth_status(flow_id.trim()) {
        Ok(status) => (
            StatusCode::OK,
            Json(json!({ "ok": true, "status": status })),
        )
            .into_response(),
        Err(err) => (StatusCode::NOT_FOUND, Json(ControlError::new(err))).into_response(),
    }
}

/// POST /control/onboarding/codex/oauth/{id}/apply - Persist Codex sign-in config.
pub async fn codex_oauth_apply_handler(
    Path(flow_id): Path<String>,
    State(state): State<ControlState>,
    connect_info: MaybeConnectInfo,
    headers: HeaderMap,
) -> Response {
    let remote_addr = connect_info.0;
    if let Some(err) = check_control_auth(&state, &headers, remote_addr) {
        return err;
    }

    let state_dir = crate::server::ws::resolve_state_dir();
    match onboarding::codex::apply_control_openai_oauth(flow_id.trim(), state_dir.clone()) {
        Ok(applied) => {
            let applied = match validate_control_onboarding_applied_mode(
                &applied,
                ControlOnboardingAppliedMode::OAuth,
            ) {
                Ok(applied) => applied,
                Err(err) => {
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(ControlError::new(err)),
                    )
                        .into_response();
                }
            };
            let snapshot = read_config_snapshot();
            let hash = snapshot.hash;
            let provider_status = match build_control_provider_onboarding_status_async(
                snapshot.raw_config,
                snapshot.config,
                state_dir,
                onboarding::setup::SetupProvider::Codex,
            )
            .await
            {
                Ok(provider_status) => provider_status,
                Err(err) => {
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(ControlError::new(err)),
                    )
                        .into_response();
                }
            };
            (
                StatusCode::OK,
                Json(ControlOnboardingApplyResponse {
                    ok: true,
                    applied,
                    hash,
                    provider_status,
                }),
            )
                .into_response()
        }
        Err(err) => (StatusCode::BAD_REQUEST, Json(ControlError::new(err))).into_response(),
    }
}

/// GET /control/onboarding/gemini/callback - OAuth callback landing page.
pub async fn gemini_oauth_callback_handler(
    Query(query): Query<GeminiOAuthCallbackQuery>,
) -> Response {
    let state = query.state.as_deref().unwrap_or_default();
    let result: Result<(), String> = onboarding::gemini::complete_control_google_oauth_callback(
        state,
        query.code.as_deref(),
        query.error.as_deref(),
        query.error_description.as_deref(),
    )
    .await;

    let (status, title, message): (StatusCode, &str, String) = match result {
        Ok(()) => (
            StatusCode::OK,
            "Gemini sign-in complete",
            "You can return to the Control UI and finish applying the Gemini config.".to_string(),
        ),
        Err(err) => (StatusCode::BAD_REQUEST, "Gemini sign-in failed", err),
    };

    (
        status,
        axum::response::Html(onboarding::oauth::callback_html(title, &message)),
    )
        .into_response()
}

/// GET /control/onboarding/codex/callback - OAuth callback landing page.
pub async fn codex_oauth_callback_handler(
    Query(query): Query<CodexOAuthCallbackQuery>,
) -> Response {
    let state = query.state.as_deref().unwrap_or_default();
    let result: Result<(), String> = onboarding::codex::complete_control_openai_oauth_callback(
        state,
        query.code.as_deref(),
        query.error.as_deref(),
        query.error_description.as_deref(),
    )
    .await;

    let (status, title, message): (StatusCode, &str, String) = match result {
        Ok(()) => (
            StatusCode::OK,
            "Codex sign-in complete",
            "You can return to the Control UI and finish applying the Codex config.".to_string(),
        ),
        Err(err) => (StatusCode::BAD_REQUEST, "Codex sign-in failed", err),
    };

    (
        status,
        axum::response::Html(onboarding::oauth::callback_html(title, &message)),
    )
        .into_response()
}

/// POST /control/onboarding/gemini/api-key - Persist Gemini API key config.
pub async fn gemini_api_key_handler(
    State(state): State<ControlState>,
    connect_info: MaybeConnectInfo,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let remote_addr = connect_info.0;
    if let Some(err) = check_control_auth(&state, &headers, remote_addr) {
        return err;
    }

    let req: GeminiApiKeyRequest = match serde_json::from_slice(&body) {
        Ok(req) => req,
        Err(err) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ControlError::new(format!("Invalid JSON: {}", err))),
            )
                .into_response();
        }
    };

    match onboarding::gemini::apply_control_gemini_api_key(onboarding::gemini::GeminiApiKeyInput {
        api_key: req.api_key,
        base_url: req.base_url,
    }) {
        Ok(applied) => {
            let applied = match validate_control_onboarding_applied_mode(
                &applied,
                ControlOnboardingAppliedMode::ApiKey,
            ) {
                Ok(applied) => applied,
                Err(err) => {
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(ControlError::new(err)),
                    )
                        .into_response();
                }
            };
            let snapshot = read_config_snapshot();
            let hash = snapshot.hash;
            let provider_status = match build_control_provider_onboarding_status_async(
                snapshot.raw_config,
                snapshot.config,
                crate::server::ws::resolve_state_dir(),
                onboarding::setup::SetupProvider::Gemini,
            )
            .await
            {
                Ok(provider_status) => provider_status,
                Err(err) => {
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(ControlError::new(err)),
                    )
                        .into_response();
                }
            };
            (
                StatusCode::OK,
                Json(ControlOnboardingApplyResponse {
                    ok: true,
                    applied,
                    hash,
                    provider_status,
                }),
            )
                .into_response()
        }
        Err(err) => (StatusCode::BAD_REQUEST, Json(ControlError::new(err))).into_response(),
    }
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
        Some(task) => {
            audit_task_mutation("cancel", &task, remote_addr);
            (StatusCode::OK, Json(TaskResponse::success(task))).into_response()
        }
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

    if queue.get(task_id).is_none() {
        return (
            StatusCode::NOT_FOUND,
            Json(ControlError::new("Task not found")),
        )
            .into_response();
    }
    // Cancellation is intentionally non-terminal for operator remediation:
    // cancelled tasks may be patched and then retried/resumed as needed.
    // Done remains terminal and is rejected by `patch_task`.

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
        Some(task) => {
            audit_task_mutation("patch", &task, remote_addr);
            (StatusCode::OK, Json(TaskResponse::success(task))).into_response()
        }
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
        Some(task) => {
            audit_task_mutation("retry", &task, remote_addr);
            (StatusCode::OK, Json(TaskResponse::success(task))).into_response()
        }
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
        Some(task) => {
            audit_task_mutation("resume", &task, remote_addr);
            (StatusCode::OK, Json(TaskResponse::success(task))).into_response()
        }
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

fn is_allowed_control_ui_config_path(path: &str) -> bool {
    path == CONTROL_UI_MUTABLE_PREFIX || path.starts_with("gateway.controlUi.")
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

enum MatrixControlVerificationAction {
    Accept,
    Confirm { matches: bool },
    Cancel,
}

async fn matrix_verification_action_handler(
    flow_id: String,
    state: ControlState,
    connect_info: MaybeConnectInfo,
    headers: HeaderMap,
    action: MatrixControlVerificationAction,
) -> Response {
    let remote_addr = connect_info.0;
    if let Some(err) = check_control_auth(&state, &headers, remote_addr) {
        return err;
    }
    let Some(runtime) = matrix_runtime_or_unavailable(&state) else {
        return matrix_runtime_unavailable_response();
    };
    let flow_id = flow_id.trim().to_string();
    if flow_id.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ControlError::new("flow id is required")),
        )
            .into_response();
    }

    let result = match action {
        MatrixControlVerificationAction::Accept => runtime.accept_verification(flow_id).await,
        MatrixControlVerificationAction::Confirm { matches } => {
            runtime.confirm_verification(flow_id, matches).await
        }
        MatrixControlVerificationAction::Cancel => runtime.cancel_verification(flow_id).await,
    };
    match result {
        Ok(info) => (
            StatusCode::OK,
            Json(MatrixActionResponse {
                ok: true,
                verification: info,
            }),
        )
            .into_response(),
        Err(err) => matrix_runtime_error_response(err),
    }
}

fn matrix_runtime_or_unavailable(state: &ControlState) -> Option<Arc<MatrixRuntimeHandle>> {
    state.matrix_runtime.clone()
}

fn matrix_runtime_unavailable_response() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(ControlError::new("Matrix runtime unavailable")),
    )
        .into_response()
}

fn matrix_runtime_error_response(err: MatrixError) -> Response {
    // Exhaustive match — no wildcard — so adding a new MatrixError
    // variant is a compile error here, forcing the contributor to
    // assign a deliberate HTTP status. Wildcards previously hid
    // server-side issues like StartupFailed/Clock/InstallationId
    // behind 400 BAD_REQUEST.
    let status = match &err {
        // Server-state issues — service unavailable from the client's
        // POV.
        MatrixError::NotConnected
        | MatrixError::Auth(_)
        | MatrixError::StartupFailed(_)
        | MatrixError::Clock(_)
        | MatrixError::E2ee(_)
        | MatrixError::ClientBuild(_)
        | MatrixError::TokenPersistence(_)
        | MatrixError::InstallationId(_)
        | MatrixError::StoreKeyDerivation
        | MatrixError::MissingStoreSecret => StatusCode::SERVICE_UNAVAILABLE,
        // Resource lookups.
        MatrixError::VerificationFlowNotFound(_)
        | MatrixError::DeviceNotFound { .. }
        | MatrixError::UserIdentityNotFound(_)
        | MatrixError::RoomNotFound(_) => StatusCode::NOT_FOUND,
        // Conflict — caller's action doesn't fit the current state.
        MatrixError::VerificationFlowNotReady { .. } => StatusCode::CONFLICT,
        // Semantic-validity errors on a well-formed request.
        MatrixError::UnsupportedRoom(_) | MatrixError::InvalidUserId(_) => {
            StatusCode::UNPROCESSABLE_ENTITY
        }
        // Upstream gateway/server-side issues.
        MatrixError::SendFailed(_) | MatrixError::SyncFailed(_) | MatrixError::Verification(_) => {
            StatusCode::BAD_GATEWAY
        }
        // Verification SDK timeouts — `MatrixError::VerificationTimeout`
        // is now its own typed variant rather than a string-match on
        // Verification's message.
        MatrixError::VerificationTimeout(_) => StatusCode::GATEWAY_TIMEOUT,
        // Request-shape errors — the operator (or schema validator)
        // sent us a config we can't interpret.
        MatrixError::InvalidConfigRoot
        | MatrixError::InvalidString { .. }
        | MatrixError::InvalidBool { .. }
        | MatrixError::InvalidStringArray { .. }
        | MatrixError::MissingHomeserverUrl
        | MatrixError::MissingUserId
        | MatrixError::MissingCredentials
        | MatrixError::MissingDeviceIdForTokenRestore => StatusCode::BAD_REQUEST,
    };
    (
        status,
        Json(ControlError::new(
            crate::logging::redact::RedactedDisplay(&err).to_string(),
        )),
    )
        .into_response()
}

// Actor attribution is based on the direct TCP peer. If control is behind a
// reverse proxy, this will record the proxy IP unless trusted-forwarded-header
// handling is introduced.
fn control_actor(remote_addr: Option<SocketAddr>) -> String {
    remote_addr
        .map(|addr| addr.ip().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

fn audit_task_mutation(action: &str, task: &DurableTask, remote_addr: Option<SocketAddr>) {
    audit(AuditEvent::TaskMutated {
        task_id: task.id.clone(),
        action: action.to_string(),
        actor: control_actor(remote_addr),
        resulting_state: format!("{:?}", task.state).to_ascii_lowercase(),
    });
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

fn parse_oauth_start_inputs(body: &axum::body::Bytes) -> Result<OAuthStartInputs, String> {
    if body.is_empty() || body.iter().all(|byte| byte.is_ascii_whitespace()) {
        return Ok(OAuthStartInputs::default());
    }

    let value: Value = serde_json::from_slice(body).map_err(|e| format!("Invalid JSON: {}", e))?;
    let Some(object) = value.as_object() else {
        return Err("Invalid JSON: expected object".to_string());
    };

    Ok(OAuthStartInputs {
        client_id_override: parse_optional_trimmed_string_field(object, "clientId")?,
        client_secret_override: parse_optional_trimmed_string_field(object, "clientSecret")?,
        redirect_base_url: parse_optional_trimmed_string_field(object, "redirectBaseUrl")?,
    })
}

fn parse_optional_trimmed_string_field(
    object: &serde_json::Map<String, Value>,
    key: &str,
) -> Result<Option<String>, String> {
    match object.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                Ok(None)
            } else {
                Ok(Some(trimmed.to_string()))
            }
        }
        Some(_) => Err(format!("Invalid JSON: field '{key}' must be a string")),
    }
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

fn configured_control_redirect_base_url(cfg: &Value) -> Option<String> {
    build_auth_profiles_config(cfg)
        .redirect_base_url
        .and_then(|value| sanitize_control_redirect_base_url(&value).ok())
}

fn control_request_base_url(headers: &HeaderMap) -> Option<String> {
    let origin_base_url = headers
        .get("origin")
        .and_then(|value| value.to_str().ok())
        .and_then(sanitize_origin_base_url);
    let host = headers
        .get("x-forwarded-host")
        .or_else(|| headers.get("host"))
        .and_then(|value| value.to_str().ok())
        .and_then(sanitize_forwarded_host)?;

    let proto = match headers.get("x-forwarded-proto") {
        Some(value) => sanitize_forwarded_proto(value.to_str().ok()?)?,
        None => origin_base_url
            .as_deref()
            .and_then(|value| value.split("://").next())
            .map(ToString::to_string)?,
    };

    Some(format!("{proto}://{host}"))
}

fn sanitize_origin_base_url(raw: &str) -> Option<String> {
    let candidate = raw.split(',').next()?.trim();
    sanitize_control_redirect_base_url(candidate).ok()
}

fn sanitize_control_redirect_base_url(raw: &str) -> Result<String, &'static str> {
    let candidate = raw.trim();
    if candidate.is_empty() || candidate.chars().any(char::is_whitespace) {
        return Err("Invalid redirectBaseUrl: malformed URL");
    }

    let uri = candidate
        .parse::<Uri>()
        .map_err(|_| "Invalid redirectBaseUrl: malformed URL")?;
    let scheme = uri
        .scheme_str()
        .ok_or("Invalid redirectBaseUrl: missing scheme")?
        .to_ascii_lowercase();
    if scheme != "http" && scheme != "https" {
        return Err("Invalid redirectBaseUrl: unsupported scheme (must be http or https)");
    }

    let authority = uri
        .authority()
        .map(|value| value.as_str())
        .filter(|value| !value.is_empty() && !value.chars().any(char::is_whitespace))
        .ok_or("Invalid redirectBaseUrl: missing authority")?;

    let path_and_query = uri
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or("/");
    if path_and_query != "/" {
        return Err("Invalid redirectBaseUrl: must not include a path or query");
    }

    Ok(format!("{scheme}://{authority}"))
}

fn sanitize_forwarded_host(raw: &str) -> Option<String> {
    let candidate = raw.split(',').next()?.trim();
    if candidate.is_empty() || candidate.chars().any(char::is_whitespace) {
        return None;
    }
    candidate
        .parse::<Authority>()
        .ok()
        .map(|value| value.to_string())
}

fn sanitize_forwarded_proto(raw: &str) -> Option<String> {
    let candidate = raw.split(',').next()?.trim().to_ascii_lowercase();
    match candidate.as_str() {
        "http" | "https" => Some(candidate),
        _ => None,
    }
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
    use tempfile::TempDir;

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
                    status: ChannelStatus::Connected,
                    last_connected_at: Some("2024-01-01T12:00:00Z".to_string()),
                    last_error: None,
                    extra: None,
                },
                ChannelStatusItem {
                    id: "discord".to_string(),
                    name: "Discord".to_string(),
                    status: ChannelStatus::Disconnected,
                    last_connected_at: None,
                    last_error: Some("Auth failed".to_string()),
                    extra: None,
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
    fn test_config_update_rejects_protected_matrix_paths() {
        for path in [
            "matrix.homeserverUrl",
            "matrix.userId",
            "matrix.accessToken",
            "matrix.password",
            "matrix.deviceId",
            "matrix.storePassphrase",
        ] {
            assert_eq!(config::protected_config_prefix(path), Some(path));
            assert_eq!(
                config::protected_config_prefix(&format!("{path}.nested")),
                Some(path)
            );
        }
        assert_eq!(
            config::protected_config_prefix("matrix.passwordRotation"),
            None
        );
    }

    #[test]
    fn test_matrix_runtime_error_response_status_mapping() {
        assert_eq!(
            matrix_runtime_unavailable_response().status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            matrix_runtime_error_response(MatrixError::RoomNotFound(
                "!missing:example.com".to_string()
            ))
            .status(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            matrix_runtime_error_response(MatrixError::UnsupportedRoom(
                "encrypted room unsupported".to_string()
            ))
            .status(),
            StatusCode::UNPROCESSABLE_ENTITY
        );
        assert_eq!(
            matrix_runtime_error_response(MatrixError::VerificationTimeout(
                "timed out".to_string()
            ))
            .status(),
            StatusCode::GATEWAY_TIMEOUT
        );
    }

    /// Loop-driven coverage of every `MatrixError` variant -> `StatusCode`
    /// mapping. The `matrix_runtime_error_response` match is compile-time
    /// exhaustive so a new variant forces the author to choose a status,
    /// but spot-checks miss accidental-relaxation regressions (e.g. a
    /// future PR collapsing `StartupFailed` to 400). This test asserts
    /// every variant produces an HTTP status in the expected family —
    /// 4xx for client-actionable, 5xx for server-side — and that no
    /// variant returns an unexpected default status.
    /// Loop-driven coverage of every `MatrixError` variant ->
    /// `StatusCode` mapping. The match is compile-time exhaustive so a
    /// new variant forces the author to choose a status, but
    /// spot-checks miss accidental-relaxation regressions (e.g. a
    /// future PR collapsing `StartupFailed` from 503 to 400, hiding a
    /// server-state issue behind a client-error code). Pinning every
    /// variant explicitly catches that.
    #[test]
    fn test_matrix_runtime_error_response_per_variant_class() {
        use crate::channels::matrix::MatrixError;
        let cases: Vec<(MatrixError, StatusCode)> = vec![
            (MatrixError::InvalidConfigRoot, StatusCode::BAD_REQUEST),
            (
                MatrixError::InvalidString { field: "userId" },
                StatusCode::BAD_REQUEST,
            ),
            (
                MatrixError::InvalidBool { field: "encrypted" },
                StatusCode::BAD_REQUEST,
            ),
            (
                MatrixError::InvalidStringArray {
                    field: "allowUsers",
                },
                StatusCode::BAD_REQUEST,
            ),
            (MatrixError::MissingHomeserverUrl, StatusCode::BAD_REQUEST),
            (MatrixError::MissingUserId, StatusCode::BAD_REQUEST),
            (MatrixError::MissingCredentials, StatusCode::BAD_REQUEST),
            (
                MatrixError::MissingDeviceIdForTokenRestore,
                StatusCode::BAD_REQUEST,
            ),
            (
                MatrixError::MissingStoreSecret,
                StatusCode::SERVICE_UNAVAILABLE,
            ),
            (
                MatrixError::StoreKeyDerivation,
                StatusCode::SERVICE_UNAVAILABLE,
            ),
            (
                MatrixError::InstallationId("io".to_string()),
                StatusCode::SERVICE_UNAVAILABLE,
            ),
            (
                MatrixError::ClientBuild("build".to_string()),
                StatusCode::SERVICE_UNAVAILABLE,
            ),
            (
                MatrixError::Auth("auth".to_string()),
                StatusCode::SERVICE_UNAVAILABLE,
            ),
            (
                MatrixError::TokenPersistence("persist".to_string()),
                StatusCode::SERVICE_UNAVAILABLE,
            ),
            (
                MatrixError::SyncFailed("sync".to_string()),
                StatusCode::BAD_GATEWAY,
            ),
            (
                MatrixError::SendFailed("send".to_string()),
                StatusCode::BAD_GATEWAY,
            ),
            (MatrixError::NotConnected, StatusCode::SERVICE_UNAVAILABLE),
            (
                MatrixError::E2ee("e2ee".to_string()),
                StatusCode::SERVICE_UNAVAILABLE,
            ),
            (
                MatrixError::StartupFailed("startup".to_string()),
                StatusCode::SERVICE_UNAVAILABLE,
            ),
            (
                MatrixError::Clock("clock".to_string()),
                StatusCode::SERVICE_UNAVAILABLE,
            ),
            (
                MatrixError::Verification("verification".to_string()),
                StatusCode::BAD_GATEWAY,
            ),
            (
                MatrixError::VerificationFlowNotReady {
                    flow_id: "flow".to_string(),
                    action: "confirm",
                },
                StatusCode::CONFLICT,
            ),
            (
                MatrixError::VerificationFlowNotFound("missing".to_string()),
                StatusCode::NOT_FOUND,
            ),
            (
                MatrixError::VerificationTimeout("timeout".to_string()),
                StatusCode::GATEWAY_TIMEOUT,
            ),
            (
                MatrixError::InvalidUserId("@bad".to_string()),
                StatusCode::UNPROCESSABLE_ENTITY,
            ),
            (
                MatrixError::DeviceNotFound {
                    user_id: "@a:x".to_string(),
                    device_id: "D".to_string(),
                },
                StatusCode::NOT_FOUND,
            ),
            (
                MatrixError::UserIdentityNotFound("@a:x".to_string()),
                StatusCode::NOT_FOUND,
            ),
            (
                MatrixError::RoomNotFound("missing".to_string()),
                StatusCode::NOT_FOUND,
            ),
            (
                MatrixError::UnsupportedRoom("encrypted".to_string()),
                StatusCode::UNPROCESSABLE_ENTITY,
            ),
        ];
        for (variant, expected) in cases {
            let actual = matrix_runtime_error_response(variant.clone()).status();
            assert_eq!(
                actual, expected,
                "MatrixError::{variant:?} mapped to {actual:?}, expected {expected:?}",
            );
        }
    }

    /// Handler-level coverage for the runtime-unavailable branch of
    /// `matrix_send_test_handler`. With `matrix_runtime: None`, the
    /// auth check passes (no token configured by default), and the
    /// handler must return `503 Service Unavailable`. Without this
    /// test, a regression that swapped the unavailable response with
    /// e.g. `404 Not Found` would slip past CI.
    /// Test fixture for handler-level coverage: AuthMode::None +
    /// loopback `SocketAddr` + loopback `Host` header, which is what
    /// the auth layer requires to classify a request as
    /// "local-direct" (per `is_local_direct_request`). Without these
    /// the request is rejected with 401 before reaching the handler's
    /// runtime / shape checks.
    fn loopback_test_state_no_auth() -> (ControlState, HeaderMap, SocketAddr) {
        let state = ControlState {
            gateway_auth_mode: crate::auth::AuthMode::None,
            ..ControlState::default()
        };
        let addr: SocketAddr = "127.0.0.1:54321".parse().expect("loopback");
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::HOST,
            axum::http::HeaderValue::from_static("127.0.0.1:18789"),
        );
        (state, headers, addr)
    }

    /// Handler-level coverage for the runtime-unavailable branch of
    /// `matrix_send_test_handler`. With `matrix_runtime: None`, the
    /// auth check passes (loopback + AuthMode::None) and the handler
    /// must return `503 Service Unavailable`.
    #[tokio::test(flavor = "current_thread")]
    async fn test_matrix_send_test_handler_returns_503_when_runtime_unavailable() {
        use crate::server::connect_info::MaybeConnectInfo;
        let (state, headers, addr) = loopback_test_state_no_auth();
        let body = axum::body::Bytes::from(
            serde_json::to_vec(&serde_json::json!({
                "roomId": "!room:example.com",
                "text": "ping",
            }))
            .expect("serialize"),
        );
        let response = super::matrix_send_test_handler(
            axum::extract::State(state),
            MaybeConnectInfo(Some(addr)),
            headers,
            body,
        )
        .await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    /// `MatrixSendTestRequest.room_id` deserializes into `OwnedRoomId`,
    /// so a malformed Matrix room ID is rejected at the JSON-parse
    /// boundary — the typed deserializer rejects strings that don't
    /// match the Matrix room-ID grammar. Pins the typed-boundary
    /// behavior: with `String` an invalid input
    /// would only fail later at the SDK boundary with a vague
    /// `BindingError`. (Tested at the deserializer level, not the
    /// handler, because the handler's auth+runtime checks fire before
    /// JSON parsing — wiring up a stub runtime to reach the parse
    /// boundary is more setup than the test needs.)
    #[test]
    fn test_matrix_send_test_request_rejects_malformed_room_id() {
        let body = serde_json::to_vec(&serde_json::json!({
            "roomId": "not-a-room-id",
        }))
        .expect("serialize");
        let result: Result<super::MatrixSendTestRequest, _> = serde_json::from_slice(&body);
        assert!(
            result.is_err(),
            "MatrixSendTestRequest must reject malformed Matrix room IDs at deserialize time"
        );
    }

    /// Well-formed Matrix room IDs must round-trip through the
    /// typed-boundary deserializer.
    #[test]
    fn test_matrix_send_test_request_accepts_well_formed_room_id() {
        let body = serde_json::to_vec(&serde_json::json!({
            "roomId": "!abcdef:matrix.example.com",
            "text": "ping",
        }))
        .expect("serialize");
        let req: super::MatrixSendTestRequest = serde_json::from_slice(&body).expect("parse");
        assert_eq!(req.room_id.as_str(), "!abcdef:matrix.example.com");
        assert_eq!(req.text.as_deref(), Some("ping"));
    }

    /// `matrix_verification_action_handler` short-circuits to
    /// `503 Service Unavailable` when no runtime is attached. Pins
    /// the documented order: runtime check happens BEFORE flow_id
    /// validation. A future PR that reorders these checks will fail
    /// this test and the author can decide whether the new order is
    /// intentional.
    #[tokio::test(flavor = "current_thread")]
    async fn test_matrix_verification_action_handler_returns_503_when_runtime_unavailable() {
        use crate::server::connect_info::MaybeConnectInfo;
        let (state, headers, addr) = loopback_test_state_no_auth();
        let response = super::matrix_verification_action_handler(
            "   ".to_string(),
            state,
            MaybeConnectInfo(Some(addr)),
            headers,
            super::MatrixControlVerificationAction::Accept,
        )
        .await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    /// Without auth credentials and with token-mode (the daemon's
    /// default), `matrix_send_test_handler` must reject with
    /// `401 Unauthorized` BEFORE reaching the runtime check. Catches
    /// a regression where a future PR accidentally moves the auth
    /// check after the runtime check (which would leak runtime state
    /// to unauthenticated callers).
    #[tokio::test(flavor = "current_thread")]
    async fn test_matrix_send_test_handler_rejects_unauthenticated_in_token_mode() {
        use crate::server::connect_info::MaybeConnectInfo;
        let state = ControlState::default(); // Token mode, no token configured
        let body = axum::body::Bytes::from(
            serde_json::to_vec(&serde_json::json!({"roomId": "!room:example.com"}))
                .expect("serialize"),
        );
        let response = super::matrix_send_test_handler(
            axum::extract::State(state),
            MaybeConnectInfo(None),
            HeaderMap::new(),
            body,
        )
        .await;
        // Either 401 (auth rejected) or some 4xx — must NOT be 503,
        // because that would mean we skipped auth.
        assert!(
            response.status().is_client_error(),
            "missing auth must produce 4xx, got {}",
            response.status()
        );
        assert_ne!(
            response.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "auth must be checked BEFORE runtime availability"
        );
    }

    /// `MatrixSendTestDelivery` is a tagged sum so its construction
    /// cannot produce nonsense like `ok: true, error: Some(...)` or
    /// `ok: false, message_id: Some(...)`. This pins the `From<DeliveryResult>`
    /// projection at the wire boundary.
    #[test]
    fn test_matrix_send_test_delivery_sum_invariants() {
        use serde_json::Value;

        let sent: MatrixSendTestDelivery = DeliveryResult {
            ok: true,
            message_id: Some("$abc:matrix.org".to_string()),
            error: None,
            retryable: false,
            conversation_id: Some("!room:matrix.org".to_string()),
            to_jid: None,
            poll_id: None,
        }
        .into();
        let json: Value = serde_json::to_value(&sent).expect("serialize sent");
        assert_eq!(json.get("outcome").and_then(Value::as_str), Some("sent"));
        assert_eq!(
            json.get("messageId").and_then(Value::as_str),
            Some("$abc:matrix.org")
        );
        assert!(json.get("error").is_none(), "sent must not carry error");

        let failed: MatrixSendTestDelivery = DeliveryResult {
            ok: false,
            message_id: None,
            error: Some("rate limited".to_string()),
            retryable: true,
            conversation_id: Some("!room:matrix.org".to_string()),
            to_jid: None,
            poll_id: None,
        }
        .into();
        let json: Value = serde_json::to_value(&failed).expect("serialize failed");
        assert_eq!(json.get("outcome").and_then(Value::as_str), Some("failed"));
        assert_eq!(
            json.get("error").and_then(Value::as_str),
            Some("rate limited")
        );
        assert_eq!(json.get("retryable").and_then(Value::as_bool), Some(true));
        assert!(
            json.get("messageId").is_none(),
            "failed must not carry messageId"
        );
    }

    #[test]
    fn test_config_update_response_serialization() {
        let response = ConfigUpdateResponse {
            ok: true,
            applied: Some(json!({"path": "gateway.port", "value": 9000})),
            hash: Some("deadbeef".to_string()),
        };
        let json_str = serde_json::to_string(&response).unwrap();
        assert!(json_str.contains("\"ok\":true"));
        assert!(json_str.contains("\"hash\":\"deadbeef\""));
        assert!(!json_str.contains("\"error\""));
    }

    /// `MatrixActionResponse.verification` carries SAS data inline so
    /// the operator can confirm without racing a `verifications` GET
    /// against record pruning. The success branch always populates the
    /// field — there is no `None` representation; failures take a
    /// different response shape via `matrix_runtime_error_response`.
    #[test]
    fn test_matrix_action_response_serializes_verification_inline() {
        use crate::channels::matrix::{
            MatrixSasEmoji, MatrixSasInfo, MatrixVerificationInfo, MatrixVerificationState,
        };

        let info = MatrixVerificationInfo {
            flow_id: "flow-1".to_string(),
            protocol_flow_id: "txn-1".to_string(),
            user_id: "@alice:example.com".to_string(),
            device_id: Some("DEVICE".to_string()),
            state: MatrixVerificationState::KeysExchanged,
            sas: Some(MatrixSasInfo {
                emoji: Some(vec![MatrixSasEmoji {
                    symbol: "🐱".to_string(),
                    description: "Cat".to_string(),
                }]),
                decimals: Some([1, 2, 3]),
            }),
            created_at: 1,
            updated_at: 2,
        };

        let response = MatrixActionResponse {
            ok: true,
            verification: info,
        };
        let json_str = serde_json::to_string(&response).expect("serialize");
        assert!(json_str.contains("\"ok\":true"));
        assert!(json_str.contains("\"verification\""));
        assert!(json_str.contains("\"emoji\""));
        assert!(json_str.contains("\"decimals\":[1,2,3]"));
        assert!(json_str.contains("\"state\":\"keys_exchanged\""));
    }

    #[test]
    fn test_config_update_response_without_hash() {
        let response = ConfigUpdateResponse {
            ok: true,
            applied: None,
            hash: None,
        };
        let json_str = serde_json::to_string(&response).unwrap();
        assert!(json_str.contains("\"ok\":true"));
        assert!(!json_str.contains("\"hash\""));
        assert!(!json_str.contains("\"applied\""));
    }

    #[test]
    fn test_control_onboarding_status_response_serialization() {
        let response = ControlOnboardingStatusResponse {
            ok: true,
            providers: vec![ControlProviderOnboardingStatus {
                provider: onboarding::setup::SetupProvider::Gemini,
                label: "Gemini".to_string(),
                configured: true,
                supported_auth_modes: vec![
                    onboarding::setup::SetupAuthMode::OAuth,
                    onboarding::setup::SetupAuthMode::ApiKey,
                ],
                available_entrypoints: vec![ControlOnboardingEntrypoint {
                    kind: ControlOnboardingEntrypointKind::Browser,
                    auth_mode: Some(onboarding::setup::SetupAuthMode::OAuth),
                    path: Some("/control/onboarding/gemini/oauth/start".to_string()),
                    command: None,
                }],
                cli_setup_command: Some(
                    "cara setup --force --provider gemini --auth-mode oauth".to_string(),
                ),
                assessment: Some(ControlSetupAssessment {
                    provider: onboarding::setup::SetupProvider::Gemini,
                    auth_mode: Some(onboarding::setup::SetupAuthMode::OAuth),
                    status: onboarding::setup::SetupAssessmentStatus::Partial,
                    summary: "Gemini setup is written, but validation was skipped.".to_string(),
                    checks: vec![ControlSetupCheck {
                        name: "Live provider validation".to_string(),
                        status: onboarding::setup::SetupCheckStatus::Skip,
                        kind: onboarding::setup::SetupCheckKind::Validation,
                        detail: "setup completed without a live provider-side validation step"
                            .to_string(),
                        remediation: None,
                    }],
                }),
            }],
        };

        let json = serde_json::to_value(&response).expect("status response should serialize");
        assert_eq!(json["providers"][0]["provider"], "gemini");
        assert_eq!(json["providers"][0]["supportedAuthModes"][0], "oauth");
        assert_eq!(
            json["providers"][0]["availableEntrypoints"][0]["kind"],
            "browser"
        );
        assert_eq!(json["providers"][0]["assessment"]["status"], "partial");
        assert!(json["providers"][0]["assessment"]
            .get("profileName")
            .is_none());
        assert!(json["providers"][0]["assessment"].get("email").is_none());
    }

    #[test]
    fn test_control_onboarding_apply_response_serialization() {
        let response = ControlOnboardingApplyResponse {
            ok: true,
            applied: ControlOnboardingAppliedMode::OAuth.applied(),
            hash: Some("deadbeef".to_string()),
            provider_status: ControlProviderOnboardingStatus {
                provider: onboarding::setup::SetupProvider::Codex,
                label: "Codex".to_string(),
                configured: true,
                supported_auth_modes: vec![onboarding::setup::SetupAuthMode::OAuth],
                available_entrypoints: vec![],
                cli_setup_command: Some("cara setup --force --provider codex".to_string()),
                assessment: None,
            },
        };

        let json = serde_json::to_value(&response).expect("apply response should serialize");
        assert_eq!(json["ok"], true);
        let applied = json
            .get("applied")
            .and_then(|value| value.as_object())
            .expect("applied should be an object");
        assert_eq!(applied.get("mode"), Some(&serde_json::json!("oauth")));
        // The applied wire shape should be narrowed to only { mode: ... }.
        assert_eq!(
            applied.len(),
            1,
            "applied should only contain the `mode` key"
        );
        assert_eq!(json["providerStatus"]["provider"], "codex");
        assert!(applied.get("profileId").is_none());
        assert!(applied.get("authProfile").is_none());
        assert!(applied.get("provider").is_none());
        assert!(applied.get("model").is_none());
    }

    #[test]
    fn test_control_onboarding_applied_round_trips() {
        let applied = ControlOnboardingAppliedMode::ApiKey.applied();
        let json = serde_json::to_string(&applied).expect("applied payload should serialize");
        let round_trip: ControlOnboardingApplied =
            serde_json::from_str(&json).expect("applied payload should deserialize");
        assert_eq!(round_trip.mode, ControlOnboardingAppliedMode::ApiKey);
    }

    #[test]
    fn test_serialize_control_onboarding_applied_mode_uses_serde_wire_names() {
        assert_eq!(
            serialize_control_onboarding_applied_mode(ControlOnboardingAppliedMode::ApiKey)
                .as_deref(),
            Some("apiKey")
        );
        assert_eq!(
            serialize_control_onboarding_applied_mode(ControlOnboardingAppliedMode::OAuth)
                .as_deref(),
            Some("oauth")
        );
    }

    #[test]
    fn test_validate_control_onboarding_applied_mode_accepts_expected_mode() {
        let applied = json!({ "mode": "oauth", "profileId": "google-123" });
        let projected =
            validate_control_onboarding_applied_mode(&applied, ControlOnboardingAppliedMode::OAuth)
                .expect("matching mode should be accepted");
        assert_eq!(projected, ControlOnboardingAppliedMode::OAuth.applied());
    }

    #[test]
    fn test_validate_control_onboarding_applied_mode_rejects_missing_mode() {
        let err = validate_control_onboarding_applied_mode(
            &json!({"authProfile": "openai-123"}),
            ControlOnboardingAppliedMode::OAuth,
        )
        .expect_err("missing mode should be rejected");
        assert_eq!(
            err,
            "Provider onboarding apply result was invalid; check server logs."
        );
    }

    #[test]
    fn test_validate_control_onboarding_applied_mode_rejects_invalid_non_string_mode() {
        let err = validate_control_onboarding_applied_mode(
            &json!({"mode": {"kind": "oauth"}}),
            ControlOnboardingAppliedMode::OAuth,
        )
        .expect_err("non-string mode should be rejected");
        assert_eq!(
            err,
            "Provider onboarding apply result was invalid; check server logs."
        );
    }

    #[test]
    fn test_validate_control_onboarding_applied_mode_rejects_unexpected_mode() {
        let err = validate_control_onboarding_applied_mode(
            &json!({"mode": "apiKey"}),
            ControlOnboardingAppliedMode::OAuth,
        )
        .expect_err("unexpected mode should be rejected");
        assert_eq!(
            err,
            "Provider onboarding apply result was invalid; check server logs."
        );
        assert!(!err.contains("apiKey"));
        assert!(!err.contains("oauth"));
    }

    #[test]
    fn test_control_setup_assessment_sanitizes_auth_profile_check_details() {
        let assessment = onboarding::setup::SetupAssessment {
            provider: onboarding::setup::SetupProvider::Gemini,
            auth_mode: Some(onboarding::setup::SetupAuthMode::OAuth),
            status: onboarding::setup::SetupAssessmentStatus::Ready,
            summary: "loaded `Google Profile` (user@example.com)".to_string(),
            checks: vec![
                onboarding::setup::SetupCheck::pass(
                    "Gemini auth profile",
                    "opaque internal configured profile detail",
                    Some(onboarding::setup::SetupCheckCode::AuthProfileConfigured),
                ),
                onboarding::setup::SetupCheck::validation_pass(
                    "Gemini account identity",
                    "opaque internal loaded profile detail",
                    Some(onboarding::setup::SetupCheckCode::AuthProfileLoaded),
                ),
                onboarding::setup::SetupCheck::validation_fail(
                    "Gemini credential validation",
                    "stored profile `google-123` future auth detail with `internal-profile-id`",
                    "Re-run setup for Gemini credential validation.",
                    None,
                ),
                onboarding::setup::SetupCheck::validation_fail(
                    "Gemini base URL validation",
                    "opaque invalid URL detail with https://user:secret@proxy.example.com/",
                    "Write a valid Gemini base URL into config.",
                    Some(onboarding::setup::SetupCheckCode::LocalValidationFailed),
                ),
            ],
            profile_name: Some("Google Profile".to_string()),
            email: Some("user@example.com".to_string()),
        };

        let control = ControlSetupAssessment::from(assessment);
        let json = serde_json::to_value(&control).expect("control assessment should serialize");

        assert_eq!(
            json["checks"][0]["detail"],
            "Gemini auth profile is configured"
        );
        assert_eq!(
            json["summary"],
            "Gemini setup looks ready for verification."
        );
        assert_eq!(
            json["checks"][1]["detail"],
            "Gemini account identity loaded from encrypted profile store"
        );
        assert_eq!(
            json["checks"][2]["detail"],
            "Gemini credential validation failed validation"
        );
        assert_eq!(
            json["checks"][3]["detail"],
            "Gemini base URL validation failed local validation"
        );
        assert!(!json.to_string().contains("google-123"));
        assert!(!json.to_string().contains("Google Profile"));
        assert!(!json.to_string().contains("user@example.com"));
        assert!(!json.to_string().contains("internal-profile-id"));
        assert!(!json.to_string().contains("user:secret@proxy.example.com"));
    }

    #[test]
    fn test_control_setup_assessment_fails_closed_for_uncoded_sensitive_detail() {
        let assessment = onboarding::setup::SetupAssessment {
            provider: onboarding::setup::SetupProvider::Gemini,
            auth_mode: Some(onboarding::setup::SetupAuthMode::OAuth),
            status: onboarding::setup::SetupAssessmentStatus::Invalid,
            summary: "opaque setup summary".to_string(),
            checks: vec![onboarding::setup::SetupCheck::fail(
                "Gemini auth profile",
                "stored profile `google-123` future sensitive detail",
                "Re-run setup for Gemini.",
                None,
            )],
            profile_name: None,
            email: None,
        };

        let control = ControlSetupAssessment::from(assessment);
        let json = serde_json::to_value(&control).expect("control assessment should serialize");

        assert_eq!(
            json["checks"][0]["detail"],
            "Gemini auth profile requires attention"
        );
        assert!(!json.to_string().contains("google-123"));
    }

    #[test]
    fn test_build_control_provider_onboarding_status_omits_assessment_when_unconfigured() {
        let temp = TempDir::new().unwrap();
        let cfg = json!({});

        let status = build_control_provider_onboarding_status(
            &cfg,
            &cfg,
            temp.path(),
            onboarding::setup::SetupProvider::Anthropic,
        );

        assert!(!status.configured);
        assert!(status.assessment.is_none());
        assert_eq!(status.provider, onboarding::setup::SetupProvider::Anthropic);
        assert_eq!(status.available_entrypoints.len(), 2);
        assert_eq!(
            status.available_entrypoints[0].kind,
            ControlOnboardingEntrypointKind::Cli
        );
        assert_eq!(
            status.available_entrypoints[0].auth_mode,
            Some(onboarding::setup::SetupAuthMode::ApiKey)
        );
        assert_eq!(status.available_entrypoints[0].path, None);
        assert_eq!(
            status.available_entrypoints[0].command.as_deref(),
            Some("cara setup --force --provider anthropic --auth-mode api-key")
        );
        assert_eq!(
            status.available_entrypoints[1].kind,
            ControlOnboardingEntrypointKind::Cli
        );
        assert_eq!(
            status.available_entrypoints[1].auth_mode,
            Some(onboarding::setup::SetupAuthMode::SetupToken)
        );
        assert_eq!(status.available_entrypoints[1].path, None);
        assert_eq!(
            status.available_entrypoints[1].command.as_deref(),
            Some("cara setup --force --provider anthropic --auth-mode setup-token")
        );
    }

    #[test]
    fn test_build_control_provider_onboarding_status_uses_raw_config_for_configured_detection() {
        let temp = TempDir::new().unwrap();
        let raw_cfg = json!({});
        let effective_cfg = json!({
            "vertex": { "location": "us-central1" }
        });

        let status = build_control_provider_onboarding_status(
            &raw_cfg,
            &effective_cfg,
            temp.path(),
            onboarding::setup::SetupProvider::Vertex,
        );

        assert!(!status.configured);
        assert!(status.assessment.is_none());
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
    fn test_parse_oauth_start_inputs_trims_nonempty_values() {
        let body = axum::body::Bytes::from_static(
            br#"{"clientId":"  openai-client-id  ","clientSecret":"  openai-client-secret  "}"#,
        );
        let inputs = parse_oauth_start_inputs(&body).expect("should parse json");

        assert!(inputs.client_id_override.as_deref() == Some("openai-client-id"));
        assert!(inputs.client_secret_override.as_deref() == Some("openai-client-secret"));
    }

    #[test]
    fn test_parse_oauth_start_inputs_rejects_non_string_values() {
        let body = axum::body::Bytes::from_static(br#"{"clientId":123}"#);
        let err = match parse_oauth_start_inputs(&body) {
            Ok(_) => panic!("non-string clientId should fail"),
            Err(err) => err,
        };
        assert!(err.contains("field 'clientId' must be a string"));
    }

    #[test]
    fn test_parse_optional_reason_enforces_max_length() {
        let long_reason = "a".repeat(MAX_TASK_REASON_LEN + 1);
        let err = parse_optional_reason(Some(long_reason)).expect_err("expected bound error");
        assert!(err.contains("reason exceeds"));
    }

    #[test]
    fn test_control_request_base_url_uses_sanitized_forwarded_headers() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-host", "gateway.example.com".parse().unwrap());
        headers.insert("x-forwarded-proto", "https".parse().unwrap());
        assert_eq!(
            control_request_base_url(&headers).as_deref(),
            Some("https://gateway.example.com")
        );
    }

    #[test]
    fn test_control_request_base_url_rejects_invalid_forwarded_host() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-host", "bad host".parse().unwrap());
        assert!(control_request_base_url(&headers).is_none());
    }

    #[test]
    fn test_control_request_base_url_rejects_invalid_forwarded_proto() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-host", "gateway.example.com".parse().unwrap());
        headers.insert("x-forwarded-proto", "javascript".parse().unwrap());
        assert!(control_request_base_url(&headers).is_none());
    }

    #[test]
    fn test_control_request_base_url_uses_origin_when_forwarded_proto_missing() {
        let mut headers = HeaderMap::new();
        headers.insert("host", "gateway.example.com".parse().unwrap());
        headers.insert("origin", "https://gateway.example.com".parse().unwrap());
        assert_eq!(
            control_request_base_url(&headers).as_deref(),
            Some("https://gateway.example.com")
        );
    }

    #[test]
    fn test_control_request_base_url_rejects_missing_proto_without_origin() {
        let mut headers = HeaderMap::new();
        headers.insert("host", "gateway.example.com".parse().unwrap());
        assert!(control_request_base_url(&headers).is_none());
    }

    #[test]
    fn test_configured_control_redirect_base_url_reads_auth_profiles_config() {
        let cfg = json!({
            "auth": {
                "profiles": {
                    "redirectBaseUrl": "https://gateway.example.com"
                }
            }
        });
        assert_eq!(
            configured_control_redirect_base_url(&cfg).as_deref(),
            Some("https://gateway.example.com")
        );
    }

    #[test]
    fn test_configured_control_redirect_base_url_rejects_invalid_auth_profiles_config() {
        let cfg = json!({
            "auth": {
                "profiles": {
                    "redirectBaseUrl": "null"
                }
            }
        });
        assert!(configured_control_redirect_base_url(&cfg).is_none());
    }

    #[test]
    fn test_sanitize_control_redirect_base_url_rejects_path_and_query() {
        assert!(
            sanitize_control_redirect_base_url("https://gateway.example.com/oauth?x=1").is_err()
        );
    }

    #[test]
    fn test_sanitize_control_redirect_base_url_rejects_non_http_scheme() {
        assert!(sanitize_control_redirect_base_url("null").is_err());
        assert!(sanitize_control_redirect_base_url("file:///tmp/ui").is_err());
    }
}
