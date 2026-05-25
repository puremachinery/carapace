//! Google Vertex AI provider.
//!
//! Streams completions from the Vertex AI `v1beta1/projects/{project}/locations/{location}/publishers/google/models/{model}:streamGenerateContent`
//! endpoint using Server-Sent Events (SSE).
//!
//! Uses `gcloud` CLI or Metadata Server for authentication.

use async_trait::async_trait;
use futures_util::StreamExt;
use reqwest::StatusCode;
use serde_json::{json, Value};
use std::ffi::OsString;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, RwLock};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::agent::provider::*;
use crate::agent::AgentError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VertexSetupValidationError {
    InvalidProjectId,
    InvalidLocation,
    MissingDefaultModel,
    UnsupportedModel,
    ClientInit(String),
    AuthUnavailable,
    AccessDenied,
    ProbeRejected,
    Unavailable,
    Rejected,
    RateLimited,
    Transport,
}

impl std::fmt::Display for VertexSetupValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidProjectId => write!(f, "Vertex project ID is invalid."),
            Self::InvalidLocation => write!(f, "Vertex location is invalid."),
            Self::MissingDefaultModel => write!(
                f,
                "Missing required model parameter and no default model is configured."
            ),
            Self::UnsupportedModel => write!(
                f,
                "Unsupported Vertex model. Use vertex:gemini-2.5-flash for Gemini \
                 or vertex:publishers/<publisher>/models/<model-id> for third-party models \
                 (supported publishers: anthropic, meta, mistral, nvidia)."
            ),
            Self::ClientInit(detail) => {
                if detail.is_empty() {
                    write!(
                        f,
                        "Vertex validation could not initialize the local HTTP client."
                    )
                } else {
                    write!(
                        f,
                        "Vertex validation could not initialize the local HTTP client: {detail}"
                    )
                }
            }
            Self::AuthUnavailable => write!(
                f,
                "Vertex authentication is unavailable from both gcloud and the metadata server."
            ),
            Self::AccessDenied => write!(
                f,
                "Vertex rejected access to the configured project, location, or model."
            ),
            Self::ProbeRejected => write!(
                f,
                "Vertex rejected the validation request before model lookup completed."
            ),
            Self::Unavailable => write!(
                f,
                "Vertex could not find the configured project, location, or model."
            ),
            Self::Rejected => write!(f, "Vertex rejected the configuration."),
            Self::RateLimited => write!(f, "Vertex validation is being rate limited."),
            Self::Transport => write!(f, "Vertex validation could not reach the provider."),
        }
    }
}

impl std::error::Error for VertexSetupValidationError {}

#[derive(Debug, Clone, PartialEq, Eq)]
enum VertexProviderInitError {
    InvalidProjectId,
    InvalidLocation,
    ClientInit(String),
}

impl From<VertexProviderInitError> for AgentError {
    fn from(err: VertexProviderInitError) -> Self {
        AgentError::Provider(VertexSetupValidationError::from(err).to_string())
    }
}

impl From<VertexProviderInitError> for VertexSetupValidationError {
    fn from(err: VertexProviderInitError) -> Self {
        match err {
            VertexProviderInitError::InvalidProjectId => Self::InvalidProjectId,
            VertexProviderInitError::InvalidLocation => Self::InvalidLocation,
            VertexProviderInitError::ClientInit(detail) => Self::ClientInit(detail),
        }
    }
}

// =================================================================================================
// Authentication
// =================================================================================================

#[derive(Debug, Clone)]
struct CachedToken {
    token: String,
    expires_at: Instant,
}

#[async_trait]
trait TokenProvider: Send + Sync + std::fmt::Debug {
    async fn fetch_token(&self) -> Result<String, AgentError>;
}

/// Default timeout for the gcloud auth command (10 seconds).
pub(crate) const DEFAULT_GCLOUD_TOKEN_TIMEOUT_MS: u64 = 10_000;
pub(crate) const MIN_GCLOUD_TOKEN_TIMEOUT_MS: u64 = 500;
pub(crate) const MAX_GCLOUD_TOKEN_TIMEOUT_MS: u64 = 60_000;

const GCLOUD_STDERR_ERROR_MAX_BYTES: usize = 256;
const METADATA_BASE_URL: &str = "http://169.254.169.254";
const METADATA_TOKEN_PATH: &str = "/computeMetadata/v1/instance/service-accounts/default/token";
static METADATA_BYPASS_LOGGED: AtomicBool = AtomicBool::new(false);

pub(crate) fn normalize_gcloud_token_timeout_ms(value: u64, source: &str) -> u64 {
    let clamped = value.clamp(MIN_GCLOUD_TOKEN_TIMEOUT_MS, MAX_GCLOUD_TOKEN_TIMEOUT_MS);
    if clamped != value {
        warn!(
            source,
            requested_ms = value,
            effective_ms = clamped,
            min_ms = MIN_GCLOUD_TOKEN_TIMEOUT_MS,
            max_ms = MAX_GCLOUD_TOKEN_TIMEOUT_MS,
            "clamping Vertex gcloud token timeout"
        );
    }
    clamped
}

pub(crate) fn parse_gcloud_token_timeout_ms_env(raw: &str) -> Option<u64> {
    match raw.trim().parse::<u64>() {
        Ok(value) => Some(normalize_gcloud_token_timeout_ms(
            value,
            "CARAPACE_GCLOUD_TOKEN_TIMEOUT_MS",
        )),
        Err(_) => {
            warn!(
                env_var = "CARAPACE_GCLOUD_TOKEN_TIMEOUT_MS",
                value = %crate::logging::redact::redact_string(raw),
                "ignoring invalid Vertex gcloud token timeout"
            );
            None
        }
    }
}

pub(crate) fn resolve_gcloud_token_timeout_ms_from_config(cfg: &Value) -> u64 {
    let vertex_cfg = cfg.get("vertex");
    crate::config::read_config_env("CARAPACE_GCLOUD_TOKEN_TIMEOUT_MS")
        .and_then(|s| parse_gcloud_token_timeout_ms_env(&s))
        .or_else(|| {
            vertex_cfg
                .and_then(|v| v.get("gcloudTokenTimeoutMs"))
                .and_then(|v| v.as_u64())
                .map(|value| {
                    normalize_gcloud_token_timeout_ms(value, "vertex.gcloudTokenTimeoutMs")
                })
        })
        .unwrap_or(DEFAULT_GCLOUD_TOKEN_TIMEOUT_MS)
}

#[derive(Debug)]
struct GCloudCliProvider {
    timeout_ms: u64,
    command: OsString,
}

impl GCloudCliProvider {
    fn new(timeout_ms: Option<u64>) -> Self {
        Self {
            timeout_ms: normalize_gcloud_token_timeout_ms(
                timeout_ms.unwrap_or(DEFAULT_GCLOUD_TOKEN_TIMEOUT_MS),
                "vertex.gcloudTokenTimeoutMs",
            ),
            command: OsString::from("gcloud"),
        }
    }

    #[cfg(test)]
    fn for_command(command: impl Into<OsString>, timeout_ms: u64) -> Self {
        Self {
            timeout_ms: normalize_gcloud_token_timeout_ms(timeout_ms, "test"),
            command: command.into(),
        }
    }
}

#[async_trait]
impl TokenProvider for GCloudCliProvider {
    async fn fetch_token(&self) -> Result<String, AgentError> {
        debug!("fetching access token via gcloud cli");
        let mut cmd = tokio::process::Command::new(&self.command);
        cmd.kill_on_drop(true);
        // Strip Carapace-internal secrets so gcloud's child env
        // can't carry CARAPACE_CONFIG_PASSWORD. See
        // strip_carapace_secret_env doc.
        crate::agent::sandbox::strip_carapace_secret_env(cmd.as_std_mut());

        cmd.arg("auth")
            .arg("print-access-token")
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .stdin(std::process::Stdio::null());

        let mut child = cmd
            .spawn()
            .map_err(|e| AgentError::Provider(format!("failed to spawn gcloud: {e}")))?;

        let mut stdout = match child.stdout.take() {
            Some(s) => s,
            None => {
                let _ = child.start_kill();
                return Err(AgentError::Provider(
                    "failed to capture gcloud stdout".to_string(),
                ));
            }
        };
        let mut stderr = match child.stderr.take() {
            Some(s) => s,
            None => {
                let _ = child.start_kill();
                return Err(AgentError::Provider(
                    "failed to capture gcloud stderr".to_string(),
                ));
            }
        };

        let mut stdout_bytes = Vec::new();
        let mut stderr_bytes = Vec::new();

        let read_and_wait = async {
            use tokio::io::AsyncReadExt;
            let (status, stdout_res, stderr_res) = tokio::join!(
                child.wait(),
                stdout.read_to_end(&mut stdout_bytes),
                stderr.read_to_end(&mut stderr_bytes),
            );
            let status = status?;
            stdout_res?;
            stderr_res?;
            Ok::<_, std::io::Error>(std::process::Output {
                status,
                stdout: stdout_bytes,
                stderr: stderr_bytes,
            })
        };

        let timeout_ms = self.timeout_ms;

        let output =
            match tokio::time::timeout(Duration::from_millis(timeout_ms), read_and_wait).await {
                Ok(res) => {
                    res.map_err(|e| AgentError::Provider(format!("failed to run gcloud: {e}")))?
                }
                Err(_) => {
                    let _ = child.start_kill();
                    return Err(AgentError::Provider(format!(
                        "gcloud command timed out after {timeout_ms} ms"
                    )));
                }
            };

        if !output.status.success() {
            let stderr_str = sanitized_gcloud_stderr(&output.stderr);
            let message = if stderr_str.is_empty() {
                "gcloud auth print-access-token failed".to_string()
            } else {
                format!("gcloud auth print-access-token failed: {stderr_str}")
            };
            return Err(AgentError::Provider(message));
        }

        let token = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if token.is_empty() {
            return Err(AgentError::Provider(
                "gcloud returned empty token".to_string(),
            ));
        }
        Ok(token)
    }
}

fn sanitized_gcloud_stderr(stderr: &[u8]) -> String {
    let stderr = String::from_utf8_lossy(stderr);
    let redacted = crate::logging::redact::redact_string(stderr.trim());
    crate::logging::audit::truncate_audit_free_text_field(&redacted, GCLOUD_STDERR_ERROR_MAX_BYTES)
}

#[derive(Debug)]
struct MetadataProvider {
    client: reqwest::Client,
    base_url: String,
}

impl MetadataProvider {
    fn new() -> Result<Self, VertexProviderInitError> {
        Self::new_with_base_url(METADATA_BASE_URL)
    }

    fn new_with_base_url(base_url: impl Into<String>) -> Result<Self, VertexProviderInitError> {
        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(2))
            .timeout(Duration::from_secs(5))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| VertexProviderInitError::ClientInit(e.to_string()))?;
        Ok(Self {
            client,
            base_url: base_url.into().trim_end_matches('/').to_string(),
        })
    }

    fn token_url(&self) -> String {
        format!("{}{}", self.base_url, METADATA_TOKEN_PATH)
    }
}

#[async_trait]
impl TokenProvider for MetadataProvider {
    async fn fetch_token(&self) -> Result<String, AgentError> {
        debug!("fetching access token via metadata server");
        // SAFETY: the GCP metadata server only serves HTTP on the fixed
        // link-local IP. The URL is not user controlled, redirects are
        // disabled on the client, and the response must carry Google's
        // Metadata-Flavor header before we trust the body.
        let url = self.token_url();
        let response = self
            .client
            .get(url)
            .header("Metadata-Flavor", "Google")
            .send()
            .await
            .map_err(|e| {
                AgentError::Provider(format!("metadata request failed: {}", e.without_url()))
            })?;

        if !response.status().is_success() {
            return Err(AgentError::Provider(format!(
                "metadata server returned {}",
                response.status()
            )));
        }

        let metadata_flavor = response
            .headers()
            .get("Metadata-Flavor")
            .and_then(|value| value.to_str().ok());
        if !metadata_flavor.is_some_and(|value| value.eq_ignore_ascii_case("Google")) {
            return Err(AgentError::Provider(
                "metadata response missing Metadata-Flavor: Google".to_string(),
            ));
        }

        let body_text = crate::net_util::read_response_body_text_capped(
            response,
            crate::net_util::MAX_RESPONSE_BODY_BYTES,
        )
        .await
        .map_err(|e| AgentError::Provider(format!("failed to read metadata response: {e}")))?;
        let body: Value = serde_json::from_str(&body_text)
            .map_err(|e| AgentError::Provider(format!("failed to parse metadata response: {e}")))?;

        body.get("access_token")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| {
                AgentError::Provider("metadata response missing access_token".to_string())
            })
    }
}

// =================================================================================================
// Request / Response Helpers
// =================================================================================================

pub(crate) fn build_gemini_body(request: &CompletionRequest) -> Value {
    let mut body = json!({});

    // System instruction
    if let Some(ref system) = request.system {
        body["system_instruction"] = json!({
            "parts": [{ "text": system }]
        });
    }

    // Convert LlmMessages to Gemini contents format
    body["contents"] = json!(crate::agent::gemini::build_gemini_contents(
        &request.messages
    ));

    // Tools
    if !request.tools.is_empty() {
        let function_declarations: Vec<Value> = request
            .tools
            .iter()
            .map(|t| {
                json!({
                    "name": t.name,
                    "description": t.description,
                    "parameters": t.input_schema,
                })
            })
            .collect();
        body["tools"] = json!([{
            "function_declarations": function_declarations,
        }]);
    }

    // Generation config
    let mut generation_config = json!({
        "maxOutputTokens": request.max_tokens,
    });
    if let Some(temp) = request.temperature {
        generation_config["temperature"] = json!(temp);
    }
    body["generationConfig"] = generation_config;

    body
}

fn parse_gemini_chunk(
    data: &str,
    accumulated_usage: &mut TokenUsage,
) -> Result<Vec<StreamEvent>, String> {
    let mut events = Vec::new();
    // Parse the JSON data
    let parsed: Value = match serde_json::from_str(data) {
        Ok(v) => v,
        Err(e) => return Err(format!("failed to parse JSON chunk: {}", e)),
    };

    if let Some(error) = parsed.get("error") {
        let message = error
            .get("message")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown API error")
            .to_string();
        return Ok(vec![StreamEvent::Error { message }]);
    }

    // Extract usage if present
    extract_vertex_usage(&parsed, accumulated_usage);

    // Extract candidates
    let candidates = match parsed.get("candidates").and_then(|v| v.as_array()) {
        Some(c) => c,
        None => return Ok(events),
    };

    if candidates.is_empty() {
        return Ok(events);
    }

    let candidate = &candidates[0];
    let finish_reason = candidate.get("finishReason").and_then(|v| v.as_str());

    // Extract content parts
    let parts = candidate
        .get("content")
        .and_then(|c| c.get("parts"))
        .and_then(|p| p.as_array());

    if let Some(parts) = parts {
        events.extend(collect_vertex_part_events(parts));
    }

    // Handle finish reason
    if let Some(reason_str) = finish_reason {
        let reason = match reason_str {
            "STOP" => StopReason::EndTurn,
            "MAX_TOKENS" => StopReason::MaxTokens,
            "SAFETY" => StopReason::EndTurn,
            _ => StopReason::EndTurn,
        };

        // Check if tool use happened
        let has_tool_use = parts.is_some_and(|p| p.iter().any(|x| x.get("functionCall").is_some()));
        let stop_reason = if has_tool_use {
            StopReason::ToolUse
        } else {
            reason
        };

        events.push(StreamEvent::Stop {
            reason: stop_reason,
            usage: *accumulated_usage,
        });
    }

    Ok(events)
}

// =================================================================================================
// Vertex Provider
// =================================================================================================

/// Google Vertex AI provider.
pub struct VertexProvider {
    client: reqwest::Client,
    project_id: String,
    location: String,
    token_manager: Arc<dyn TokenProvider>,
    token_cache: Arc<RwLock<Option<CachedToken>>>,
    default_model: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VertexPublisher {
    Google,
    Anthropic,
    Meta,
    Mistral,
    Nvidia,
}

impl VertexPublisher {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Google => "google",
            Self::Anthropic => "anthropic",
            Self::Meta => "meta",
            Self::Mistral => "mistral",
            Self::Nvidia => "nvidia",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ResolvedVertexModel {
    endpoint_location: String,
    publisher: VertexPublisher,
    model_id: String,
}

impl ResolvedVertexModel {
    fn service_endpoint(&self) -> String {
        if self.endpoint_location == "global" {
            "https://aiplatform.googleapis.com".to_string()
        } else {
            format!(
                "https://{}-aiplatform.googleapis.com",
                self.endpoint_location
            )
        }
    }

    fn stream_generate_url(&self, project_id: &str) -> String {
        format!(
            "{}/v1beta1/projects/{}/locations/{}/publishers/google/models/{}:streamGenerateContent?alt=sse",
            self.service_endpoint(),
            project_id,
            self.endpoint_location,
            self.model_id
        )
    }

    fn stream_raw_predict_url(&self, project_id: &str) -> String {
        format!(
            "{}/v1/projects/{}/locations/{}/publishers/{}/models/{}:streamRawPredict",
            self.service_endpoint(),
            project_id,
            self.endpoint_location,
            self.publisher.as_str(),
            self.model_id
        )
    }

    fn streaming_url(&self, project_id: &str) -> String {
        match self.publisher {
            VertexPublisher::Google => self.stream_generate_url(project_id),
            // All third-party publishers use streamRawPredict.
            VertexPublisher::Anthropic
            | VertexPublisher::Meta
            | VertexPublisher::Mistral
            | VertexPublisher::Nvidia => self.stream_raw_predict_url(project_id),
        }
    }

    fn publisher_model_config_url(&self, project_id: &str) -> String {
        format!(
            "{}/v1beta1/projects/{}/locations/{}/publishers/{}/models/{}:fetchPublisherModelConfig",
            self.service_endpoint(),
            project_id,
            self.endpoint_location,
            self.publisher.as_str(),
            self.model_id
        )
    }
}

impl std::fmt::Debug for VertexProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VertexProvider")
            .field("project_id", &self.project_id)
            .field("location", &self.location)
            .finish()
    }
}
impl VertexProvider {
    fn try_new(
        project_id: String,
        location: String,
        default_model: Option<String>,
    ) -> Result<Self, VertexProviderInitError> {
        Self::try_new_with_timeout(project_id, location, default_model, None)
    }

    fn try_new_with_timeout(
        project_id: String,
        location: String,
        default_model: Option<String>,
        gcloud_timeout_ms: Option<u64>,
    ) -> Result<Self, VertexProviderInitError> {
        validate_project_id(&project_id).map_err(|_| VertexProviderInitError::InvalidProjectId)?;
        validate_location(&location).map_err(|_| VertexProviderInitError::InvalidLocation)?;

        // Uses FallbackTokenProvider: tries gcloud CLI first and falls back to the metadata server.
        let token_manager: Arc<dyn TokenProvider> =
            Arc::new(FallbackTokenProvider::new(gcloud_timeout_ms)?);

        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(300))
            .build()
            .map_err(|e| VertexProviderInitError::ClientInit(e.to_string()))?;

        Ok(Self {
            client,
            project_id,
            location,
            token_manager,
            token_cache: Arc::new(RwLock::new(None)),
            default_model,
        })
    }

    pub fn new(
        project_id: String,
        location: String,
        default_model: Option<String>,
    ) -> Result<Self, AgentError> {
        Self::try_new(project_id, location, default_model).map_err(AgentError::from)
    }

    pub fn new_with_timeout(
        project_id: String,
        location: String,
        default_model: Option<String>,
        gcloud_timeout_ms: Option<u64>,
    ) -> Result<Self, AgentError> {
        Self::try_new_with_timeout(project_id, location, default_model, gcloud_timeout_ms)
            .map_err(AgentError::from)
    }

    pub async fn get_token(&self) -> Result<String, AgentError> {
        // Read path
        {
            let cache = self.token_cache.read().await;
            if let Some(cached) = cache.as_ref() {
                if cached.expires_at > Instant::now() + Duration::from_secs(60) {
                    return Ok(cached.token.clone());
                }
            }
        }

        // Write path
        let mut cache = self.token_cache.write().await;
        // Double check
        if let Some(cached) = cache.as_ref() {
            if cached.expires_at > Instant::now() + Duration::from_secs(60) {
                return Ok(cached.token.clone());
            }
        }

        let token = self.token_manager.fetch_token().await?;
        *cache = Some(CachedToken {
            token: token.clone(),
            // Keep token reuse short and conservative across both gcloud and metadata-server sources.
            // With the 60-second freshness check above, cached tokens are reused for at most ~3 minutes.
            expires_at: Instant::now() + Duration::from_secs(240),
        });

        Ok(token)
    }

    /// Resolves a Vertex AI model target to a typed publisher + model ID.
    ///
    /// Rules:
    /// - `vertex:gemini-1.5-pro` -> Google publisher, gemini-1.5-pro
    /// - `vertex:google/gemini-1.5-pro` -> Google publisher, gemini-1.5-pro
    /// - `vertex:publishers/anthropic/models/claude-sonnet-4-6` -> Anthropic publisher
    /// - `vertex:default` -> use `default_model`
    fn resolve_model_target(
        &self,
        model_name: &str,
    ) -> Result<ResolvedVertexModel, VertexSetupValidationError> {
        let clean_model = strip_vertex_prefix(model_name);

        // Handle generic fallback
        let effective_model = if clean_model.is_empty() || clean_model == "default" {
            if let Some(ref default) = self.default_model {
                strip_vertex_prefix(default)
            } else {
                return Err(VertexSetupValidationError::MissingDefaultModel);
            }
        } else {
            clean_model
        };

        // Explicit publisher path: publishers/<publisher>/models/<model_id>
        if let Some(rest) = effective_model.strip_prefix("publishers/") {
            return self.resolve_publisher_model(rest);
        }

        // Google Gemini shorthand
        let model_id: &str = if let Some(model_id) = effective_model.strip_prefix("google/") {
            if !model_id.starts_with("gemini-") {
                return Err(VertexSetupValidationError::UnsupportedModel);
            }
            model_id
        } else if effective_model.contains('/') || !effective_model.starts_with("gemini-") {
            return Err(VertexSetupValidationError::UnsupportedModel);
        } else {
            // Bare Gemini model IDs are treated as Google-published models on Vertex AI.
            effective_model
        };

        validate_model_id(model_id)?;

        // Global endpoints for Gemini 3
        if model_id.starts_with("gemini-3") {
            return Ok(ResolvedVertexModel {
                endpoint_location: "global".to_string(),
                publisher: VertexPublisher::Google,
                model_id: model_id.to_string(),
            });
        }

        Ok(ResolvedVertexModel {
            endpoint_location: self.location.clone(),
            publisher: VertexPublisher::Google,
            model_id: model_id.to_string(),
        })
    }

    /// Resolve an explicit `publishers/<publisher>/models/<model_id>` path.
    fn resolve_publisher_model(
        &self,
        path: &str,
    ) -> Result<ResolvedVertexModel, VertexSetupValidationError> {
        let (publisher_str, rest) = path
            .split_once('/')
            .ok_or(VertexSetupValidationError::UnsupportedModel)?;
        let model_id = rest
            .strip_prefix("models/")
            .ok_or(VertexSetupValidationError::UnsupportedModel)?;

        let publisher = match publisher_str {
            "anthropic" => VertexPublisher::Anthropic,
            "meta" => VertexPublisher::Meta,
            "mistral" => VertexPublisher::Mistral,
            "nvidia" => VertexPublisher::Nvidia,
            _ => return Err(VertexSetupValidationError::UnsupportedModel),
        };

        validate_model_id(model_id)?;

        Ok(ResolvedVertexModel {
            endpoint_location: self.location.clone(),
            publisher,
            model_id: model_id.to_string(),
        })
    }

    #[cfg(test)]
    fn resolve_request_config(&self, model_name: &str) -> Result<String, AgentError> {
        self.resolve_model_target(model_name)
            .map(|resolved| resolved.streaming_url(&self.project_id))
            .map_err(|err| AgentError::Provider(err.to_string()))
    }
}

/// SSRF / Path Traversal validation for model IDs embedded in URLs.
///
/// Requires the first character to be alphanumeric to reject dot-segment
/// sequences (`.`, `..`) that RFC 3986 normalization could resolve as
/// parent-directory references in the URL path.
fn validate_model_id(model_id: &str) -> Result<(), VertexSetupValidationError> {
    if model_id.is_empty()
        || !model_id.as_bytes()[0].is_ascii_alphanumeric()
        || !model_id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
    {
        return Err(VertexSetupValidationError::UnsupportedModel);
    }
    Ok(())
}

fn validate_project_id(project_id: &str) -> Result<(), VertexSetupValidationError> {
    static PROJECT_ID_REGEX: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let project_id_re = PROJECT_ID_REGEX
        .get_or_init(|| regex::Regex::new(r"^[a-z][a-z0-9-]{4,28}[a-z0-9]$").unwrap());
    if project_id_re.is_match(project_id) {
        Ok(())
    } else {
        Err(VertexSetupValidationError::InvalidProjectId)
    }
}

fn validate_location(location: &str) -> Result<(), VertexSetupValidationError> {
    static LOCATION_REGEX: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let location_re =
        LOCATION_REGEX.get_or_init(|| regex::Regex::new(r"^[a-z]+(?:-[a-z]+)+\d+$").unwrap());
    if location == "global" || location_re.is_match(location) {
        Ok(())
    } else {
        Err(VertexSetupValidationError::InvalidLocation)
    }
}

pub async fn validate_vertex_setup(
    project_id: String,
    location: String,
    route_model: String,
    default_model: Option<String>,
) -> Result<(), VertexSetupValidationError> {
    validate_vertex_setup_with_timeout(project_id, location, route_model, default_model, None).await
}

pub async fn validate_vertex_setup_with_timeout(
    project_id: String,
    location: String,
    route_model: String,
    default_model: Option<String>,
    gcloud_timeout_ms: Option<u64>,
) -> Result<(), VertexSetupValidationError> {
    let provider = VertexProvider::try_new_with_timeout(
        project_id,
        location,
        default_model,
        gcloud_timeout_ms,
    )
    .map_err(VertexSetupValidationError::from)?;
    let target = provider.resolve_model_target(&route_model)?;

    // For non-Google publishers, validation only confirms that the model target
    // parses/resolves and that a local access token can be acquired. It does NOT
    // verify that the token has IAM permissions for the requested publisher/model
    // or that the model exists in Vertex; those failures surface at first request.
    // fetchPublisherModelConfig is a Google-specific v1beta1 endpoint that does
    // not exist for third-party publishers (Anthropic uses v1/streamRawPredict).
    if target.publisher != VertexPublisher::Google {
        provider
            .get_token()
            .await
            .map_err(|_| VertexSetupValidationError::AuthUnavailable)?;
        return Ok(());
    }

    let token = provider
        .get_token()
        .await
        .map_err(|_| VertexSetupValidationError::AuthUnavailable)?;
    let response = provider
        .client
        .get(target.publisher_model_config_url(&provider.project_id))
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
        .map_err(|_| VertexSetupValidationError::Transport)?;
    let status = response.status();
    // Drain at most 4 KiB to free the connection — the body is
    // discarded either way, so a tiny cap is sufficient and bounds a
    // hostile / MITM-attacked validation probe from streaming
    // unbounded bytes just to OOM us.
    if let Err(err) = crate::net_util::read_response_body_bytes_capped(response, 4 * 1024).await {
        debug!("failed to drain Vertex validation probe response body: {err}");
    }

    classify_vertex_validation_probe_status(status)
}

fn classify_vertex_validation_probe_status(
    status: StatusCode,
) -> Result<(), VertexSetupValidationError> {
    match status {
        status if status.is_success() => Ok(()),
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => {
            Err(VertexSetupValidationError::AccessDenied)
        }
        StatusCode::BAD_REQUEST => Err(VertexSetupValidationError::ProbeRejected),
        StatusCode::NOT_FOUND => Err(VertexSetupValidationError::Unavailable),
        StatusCode::TOO_MANY_REQUESTS => Err(VertexSetupValidationError::RateLimited),
        status if status.is_redirection() => Err(VertexSetupValidationError::Transport),
        status if status.is_server_error() => Err(VertexSetupValidationError::Transport),
        _ => Err(VertexSetupValidationError::Rejected),
    }
}

#[derive(Debug)]
struct FallbackTokenProvider {
    primary: Arc<dyn TokenProvider>,
    fallback: Arc<dyn TokenProvider>,
}

impl FallbackTokenProvider {
    fn new(gcloud_timeout_ms: Option<u64>) -> Result<Self, VertexProviderInitError> {
        Ok(Self::with_providers(
            Arc::new(GCloudCliProvider::new(gcloud_timeout_ms)),
            Arc::new(MetadataProvider::new()?),
        ))
    }

    fn with_providers(primary: Arc<dyn TokenProvider>, fallback: Arc<dyn TokenProvider>) -> Self {
        Self { primary, fallback }
    }
}

#[async_trait]
impl TokenProvider for FallbackTokenProvider {
    async fn fetch_token(&self) -> Result<String, AgentError> {
        if let Some(reason) = metadata_bypass_reason_from_process_env() {
            if !METADATA_BYPASS_LOGGED.swap(true, Ordering::Relaxed) {
                info!(
                    reason,
                    "gcloud CLI bypass triggered; querying metadata server directly"
                );
            } else {
                debug!(
                    reason,
                    "gcloud CLI bypass triggered; querying metadata server directly"
                );
            }
            return self.fallback.fetch_token().await;
        }

        match self.primary.fetch_token().await {
            Ok(t) => Ok(t),
            Err(e) => {
                debug!("primary token provider failed, trying fallback: {e}");
                // In a real implementation we might check if 'e' is specific to "not found"
                // But generally trying fallback is safe if primary failed.
                self.fallback.fetch_token().await
            }
        }
    }
}

fn metadata_bypass_reason_from_process_env() -> Option<&'static str> {
    metadata_bypass_reason_from_env(|key| crate::config::read_process_env(key).is_some())
}

fn metadata_bypass_reason_from_env(has_env: impl Fn(&str) -> bool) -> Option<&'static str> {
    if has_env("K_SERVICE") && has_env("K_REVISION") && has_env("K_CONFIGURATION") {
        return Some("cloud_run_service");
    }
    if has_env("CLOUD_RUN_JOB") {
        return Some("cloud_run_job");
    }
    if has_env("CLOUD_RUN_WORKER_POOL") {
        return Some("cloud_run_worker_pool");
    }
    None
}

/// Strip the `vertex:` prefix from a model identifier.
///
/// Returns the bare model name suitable for passing to the Vertex API
/// (e.g. `gemini-2.5-flash`).
pub fn strip_vertex_prefix(model: &str) -> &str {
    if is_vertex_model(model) {
        &model[7..]
    } else {
        model
    }
}

/// Determine whether a model identifier should route to the Vertex provider.
///
/// Requires the canonical `vertex:` prefix (e.g. `vertex:gemini-2.5-flash`).
pub fn is_vertex_model(model: &str) -> bool {
    model.len() > 7
        && model.as_bytes()[..6].eq_ignore_ascii_case(b"vertex")
        && model.as_bytes()[6] == b':'
}

impl VertexProvider {
    async fn complete_gemini(
        &self,
        request: CompletionRequest,
        token: String,
        url: String,
        cancel_token: CancellationToken,
    ) -> Result<mpsc::Receiver<StreamEvent>, AgentError> {
        let body = build_gemini_body(&request);

        let response = tokio::select! {
            _ = cancel_token.cancelled() => {
                return Err(AgentError::Cancelled);
            }
            response = self
                .client
                .post(&url)
                .header("Authorization", format!("Bearer {}", token))
                .header("content-type", "application/json")
                .json(&body)
                .send() => {
                    response.map_err(|e| AgentError::Provider(format!("HTTP request failed: {}", e.without_url())))?
                }
        };

        if !response.status().is_success() {
            let status = response.status();
            let body = crate::net_util::read_response_body_text_capped(
                response,
                crate::net_util::MAX_RESPONSE_BODY_BYTES,
            )
            .await
            .unwrap_or_else(|_| "<unreadable>".to_string());
            let safe_body = summarize_http_failure_body(&body);
            return Err(AgentError::Provider(format!(
                "Vertex API returned {status}: {safe_body}"
            )));
        }

        let (tx, rx) = mpsc::channel(64);
        let stream = response.bytes_stream();
        let cancel = cancel_token.clone();

        tokio::spawn(async move {
            if let Err(e) = process_vertex_sse_stream(stream, &tx, &cancel).await {
                let _ = tx
                    .send(StreamEvent::Error {
                        message: e.to_string(),
                    })
                    .await;
            }
        });

        Ok(rx)
    }

    async fn complete_anthropic(
        &self,
        request: CompletionRequest,
        token: String,
        url: String,
        cancel_token: CancellationToken,
    ) -> Result<mpsc::Receiver<StreamEvent>, AgentError> {
        let mut body = crate::agent::anthropic_wire::build_messages_body(&request);
        body["anthropic_version"] = json!("vertex-2023-10-16");

        let response = tokio::select! {
            _ = cancel_token.cancelled() => {
                return Err(AgentError::Cancelled);
            }
            response = self
                .client
                .post(&url)
                .header("Authorization", format!("Bearer {}", token))
                .header("content-type", "application/json")
                .header("accept", "text/event-stream")
                .json(&body)
                .send() => {
                    response.map_err(|e| AgentError::Provider(format!("HTTP request failed: {}", e.without_url())))?
                }
        };

        if !response.status().is_success() {
            let status = response.status();
            let body = crate::net_util::read_response_body_text_capped(
                response,
                crate::net_util::MAX_RESPONSE_BODY_BYTES,
            )
            .await
            .unwrap_or_else(|_| "<unreadable>".to_string());
            let safe_body = summarize_http_failure_body(&body);
            return Err(AgentError::Provider(format!(
                "Vertex API returned {status}: {safe_body}"
            )));
        }

        let (tx, rx) = mpsc::channel(64);
        let stream = response.bytes_stream();
        let cancel = cancel_token.clone();

        tokio::spawn(async move {
            if let Err(e) =
                crate::agent::anthropic_wire::process_anthropic_sse_stream(stream, &tx, &cancel)
                    .await
            {
                let _ = tx
                    .send(StreamEvent::Error {
                        message: e.to_string(),
                    })
                    .await;
            }
        });

        Ok(rx)
    }

    async fn complete_openai_compat(
        &self,
        request: CompletionRequest,
        resolved: &ResolvedVertexModel,
        token: String,
        url: String,
        cancel_token: CancellationToken,
    ) -> Result<mpsc::Receiver<StreamEvent>, AgentError> {
        let mut body = crate::agent::openai_wire::build_openai_messages_body(&request);
        body["model"] = json!(resolved.model_id);
        body["max_tokens"] = json!(request.max_tokens);
        body["stream_options"] = json!({ "include_usage": true });

        let response = tokio::select! {
            _ = cancel_token.cancelled() => {
                return Err(AgentError::Cancelled);
            }
            response = self
                .client
                .post(&url)
                .header("Authorization", format!("Bearer {}", token))
                .header("content-type", "application/json")
                .header("accept", "text/event-stream")
                .json(&body)
                .send() => {
                    response.map_err(|e| AgentError::Provider(format!("HTTP request failed: {}", e.without_url())))?
                }
        };

        if !response.status().is_success() {
            let status = response.status();
            let body = crate::net_util::read_response_body_text_capped(
                response,
                crate::net_util::MAX_RESPONSE_BODY_BYTES,
            )
            .await
            .unwrap_or_else(|_| "<unreadable>".to_string());
            let safe_body = summarize_http_failure_body(&body);
            return Err(AgentError::Provider(format!(
                "Vertex API returned {status}: {safe_body}"
            )));
        }

        let (tx, rx) = mpsc::channel(64);
        let stream = response.bytes_stream();
        let cancel = cancel_token.clone();

        tokio::spawn(async move {
            if let Err(e) =
                crate::agent::openai_wire::process_openai_sse_stream(stream, &tx, &cancel).await
            {
                let _ = tx
                    .send(StreamEvent::Error {
                        message: e.to_string(),
                    })
                    .await;
            }
        });

        Ok(rx)
    }
}

#[async_trait]
impl LlmProvider for VertexProvider {
    async fn complete(
        &self,
        request: CompletionRequest,
        cancel_token: CancellationToken,
    ) -> Result<mpsc::Receiver<StreamEvent>, AgentError> {
        if cancel_token.is_cancelled() {
            return Err(AgentError::Cancelled);
        }

        let resolved = self
            .resolve_model_target(&request.model)
            .map_err(|err| AgentError::Provider(err.to_string()))?;
        let token = self.get_token().await?;
        let url = resolved.streaming_url(&self.project_id);

        match resolved.publisher {
            VertexPublisher::Google => {
                self.complete_gemini(request, token, url, cancel_token)
                    .await
            }
            VertexPublisher::Anthropic => {
                self.complete_anthropic(request, token, url, cancel_token)
                    .await
            }
            VertexPublisher::Meta | VertexPublisher::Mistral | VertexPublisher::Nvidia => {
                self.complete_openai_compat(request, &resolved, token, url, cancel_token)
                    .await
            }
        }
    }
}

use crate::agent::provider::MAX_SSE_BUFFER_BYTES;

/// Process a Vertex SSE byte stream into StreamEvents.
async fn process_vertex_sse_stream<S>(
    mut stream: S,
    tx: &mpsc::Sender<StreamEvent>,
    cancel_token: &CancellationToken,
) -> Result<(), String>
where
    S: futures_util::Stream<Item = Result<bytes::Bytes, reqwest::Error>> + Unpin,
{
    let mut buffer = String::new();
    let mut accumulated_usage = TokenUsage::default();
    let mut last_finish_reason: Option<String> = None;

    loop {
        let chunk = tokio::select! {
             _ = cancel_token.cancelled() => return Ok(()),
            chunk = stream.next() => chunk,
        };
        let Some(chunk) = chunk else {
            break;
        };
        let chunk = chunk.map_err(|e| format!("stream read error: {}", e.without_url()))?;
        buffer.push_str(&String::from_utf8_lossy(&chunk));

        if buffer.len() > MAX_SSE_BUFFER_BYTES {
            return Err(format!(
                "SSE buffer exceeded {} bytes, aborting stream",
                MAX_SSE_BUFFER_BYTES
            ));
        }

        let mut consumed = 0;
        while let Some(rel_pos) = buffer[consumed..].find('\n') {
            let newline_pos = consumed + rel_pos;
            let line = buffer[consumed..newline_pos]
                .trim_end_matches('\r')
                .to_string();
            consumed = newline_pos + 1;

            if let Some(data) = line.strip_prefix("data: ") {
                match parse_gemini_chunk(data, &mut accumulated_usage) {
                    Ok(events) => {
                        for event in events {
                            if let StreamEvent::Stop { reason, .. } = &event {
                                last_finish_reason = Some(match reason {
                                    StopReason::MaxTokens => "MAX_TOKENS".to_string(),
                                    StopReason::ToolUse | StopReason::EndTurn => "STOP".to_string(),
                                });
                            }
                            let is_stop = matches!(event, StreamEvent::Stop { .. });
                            let is_error = matches!(event, StreamEvent::Error { .. });
                            if tx.send(event).await.is_err() {
                                return Ok(());
                            }
                            if is_stop || is_error {
                                return Ok(());
                            }
                        }
                    }
                    Err(e) => {
                        // Log parse error but maybe continue?
                        // For now, treat as stream error
                        let _ = tx.send(StreamEvent::Error { message: e }).await;
                        return Ok(());
                    }
                }
            }
        }
        if consumed > 0 {
            buffer.drain(..consumed);
        }
    }

    let reason = match last_finish_reason.as_deref() {
        Some("MAX_TOKENS") => StopReason::MaxTokens,
        _ => StopReason::EndTurn,
    };
    let _ = tx
        .send(StreamEvent::Stop {
            reason,
            usage: accumulated_usage,
        })
        .await;

    Ok(())
}

fn extract_vertex_usage(parsed: &Value, accumulated_usage: &mut TokenUsage) {
    if let Some(usage_meta) = parsed.get("usageMetadata") {
        if let Some(prompt_tokens) = usage_meta.get("promptTokenCount").and_then(|v| v.as_u64()) {
            accumulated_usage.input_tokens = prompt_tokens;
        }
        if let Some(candidates_tokens) = usage_meta
            .get("candidatesTokenCount")
            .and_then(|v| v.as_u64())
        {
            accumulated_usage.output_tokens = candidates_tokens;
        }
    }
}

fn collect_vertex_part_events(parts: &[Value]) -> Vec<StreamEvent> {
    let mut events = Vec::new();
    for part in parts {
        let metadata = gemini_part_metadata(part);
        if let Some(text) = part.get("text").and_then(|v| v.as_str()) {
            if !text.is_empty() || metadata.is_some() {
                events.push(StreamEvent::TextDelta {
                    text: text.to_string(),
                    metadata: metadata.clone(),
                });
            }
        }
        if let Some(fc) = part.get("functionCall") {
            let name = fc
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let args = fc.get("args").cloned().unwrap_or(json!({}));
            let id = uuid::Uuid::new_v4().to_string();
            events.push(StreamEvent::ToolUse {
                id,
                name,
                input: args,
                metadata,
            });
        }
    }
    events
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::provider::{
        CompletionRequest, ContentBlock, LlmMessage, LlmRole, ToolDefinition,
    };
    use crate::test_support::env::ScopedEnv;
    use serde_json::json;
    use std::collections::HashSet;
    use std::sync::atomic::AtomicUsize;

    #[derive(Debug, Clone, Copy)]
    enum MockTokenResult {
        Token(&'static str),
        Error(&'static str),
    }

    #[derive(Debug)]
    struct MockTokenProvider {
        result: MockTokenResult,
        calls: Arc<AtomicUsize>,
    }

    impl MockTokenProvider {
        fn new(result: MockTokenResult, calls: Arc<AtomicUsize>) -> Self {
            Self { result, calls }
        }
    }

    #[async_trait::async_trait]
    impl TokenProvider for MockTokenProvider {
        async fn fetch_token(&self) -> Result<String, AgentError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            match self.result {
                MockTokenResult::Token(token) => Ok(token.to_string()),
                MockTokenResult::Error(message) => Err(AgentError::Provider(message.to_string())),
            }
        }
    }

    fn env_set(keys: &[&str]) -> HashSet<String> {
        keys.iter().map(|key| key.to_string()).collect()
    }

    fn mock_provider(result: MockTokenResult) -> (Arc<dyn TokenProvider>, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        (
            Arc::new(MockTokenProvider::new(result, calls.clone())),
            calls,
        )
    }

    #[test]
    fn test_model_utilities() {
        assert_eq!(
            strip_vertex_prefix("vertex:gemini-1.5-pro"),
            "gemini-1.5-pro"
        );
        assert_eq!(
            strip_vertex_prefix("Vertex:gemini-1.5-pro"),
            "gemini-1.5-pro"
        );
        assert_eq!(strip_vertex_prefix("gemini-1.5-pro"), "gemini-1.5-pro");

        assert!(is_vertex_model("vertex:gemini-1.5-pro"));
        assert!(is_vertex_model("Vertex:gemini-1.5-pro"));
        assert!(!is_vertex_model("vertex/gemini-1.5-pro")); // slash no longer accepted
        assert!(!is_vertex_model("gemini-1.5-pro"));
    }

    #[test]
    fn test_gcloud_token_timeout_normalization_clamps_bounds() {
        assert_eq!(
            normalize_gcloud_token_timeout_ms(0, "test"),
            MIN_GCLOUD_TOKEN_TIMEOUT_MS
        );
        assert_eq!(
            normalize_gcloud_token_timeout_ms(MIN_GCLOUD_TOKEN_TIMEOUT_MS - 1, "test"),
            MIN_GCLOUD_TOKEN_TIMEOUT_MS
        );
        assert_eq!(
            normalize_gcloud_token_timeout_ms(MAX_GCLOUD_TOKEN_TIMEOUT_MS + 1, "test"),
            MAX_GCLOUD_TOKEN_TIMEOUT_MS
        );
        assert_eq!(
            normalize_gcloud_token_timeout_ms(u64::MAX, "test"),
            MAX_GCLOUD_TOKEN_TIMEOUT_MS
        );
        assert_eq!(normalize_gcloud_token_timeout_ms(10_000, "test"), 10_000);
    }

    #[test]
    fn test_parse_gcloud_token_timeout_ms_env() {
        assert_eq!(parse_gcloud_token_timeout_ms_env("2500"), Some(2_500));
        assert_eq!(
            parse_gcloud_token_timeout_ms_env("0"),
            Some(MIN_GCLOUD_TOKEN_TIMEOUT_MS)
        );
        assert_eq!(parse_gcloud_token_timeout_ms_env("10s"), None);
        assert_eq!(parse_gcloud_token_timeout_ms_env(""), None);
    }

    #[test]
    fn test_metadata_base_url_uses_link_local_ip() {
        assert_eq!(METADATA_BASE_URL, "http://169.254.169.254");
    }

    #[test]
    fn test_metadata_bypass_reason_requires_explicit_serverless_signal() {
        let service = env_set(&["K_SERVICE", "K_REVISION", "K_CONFIGURATION"]);
        assert_eq!(
            metadata_bypass_reason_from_env(|key| service.contains(key)),
            Some("cloud_run_service")
        );

        let partial_service = env_set(&["K_SERVICE"]);
        assert_eq!(
            metadata_bypass_reason_from_env(|key| partial_service.contains(key)),
            None
        );

        let job = env_set(&["CLOUD_RUN_JOB"]);
        assert_eq!(
            metadata_bypass_reason_from_env(|key| job.contains(key)),
            Some("cloud_run_job")
        );

        let worker_pool = env_set(&["CLOUD_RUN_WORKER_POOL"]);
        assert_eq!(
            metadata_bypass_reason_from_env(|key| worker_pool.contains(key)),
            Some("cloud_run_worker_pool")
        );

        let no_serverless_env = env_set(&[]);
        assert_eq!(
            metadata_bypass_reason_from_env(|key| no_serverless_env.contains(key)),
            None
        );
    }

    #[tokio::test]
    async fn test_fallback_uses_primary_without_serverless_env() {
        let mut env = ScopedEnv::new();
        env.unset("K_SERVICE")
            .unset("K_REVISION")
            .unset("K_CONFIGURATION")
            .unset("CLOUD_RUN_JOB")
            .unset("CLOUD_RUN_WORKER_POOL");

        let (primary, primary_calls) = mock_provider(MockTokenResult::Token("primary-token"));
        let (fallback, fallback_calls) = mock_provider(MockTokenResult::Token("metadata-token"));
        let provider = FallbackTokenProvider::with_providers(primary, fallback);

        let token = provider.fetch_token().await.expect("token");
        assert_eq!(token, "primary-token");
        assert_eq!(primary_calls.load(Ordering::SeqCst), 1);
        assert_eq!(fallback_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn test_fallback_uses_metadata_for_cloud_run_service() {
        let mut env = ScopedEnv::new();
        env.set("K_SERVICE", "svc")
            .set("K_REVISION", "rev")
            .set("K_CONFIGURATION", "cfg")
            .unset("CLOUD_RUN_JOB")
            .unset("CLOUD_RUN_WORKER_POOL");

        let (primary, primary_calls) = mock_provider(MockTokenResult::Error("no gcloud"));
        let (fallback, fallback_calls) = mock_provider(MockTokenResult::Token("metadata-token"));
        let provider = FallbackTokenProvider::with_providers(primary, fallback);

        let token = provider.fetch_token().await.expect("token");
        assert_eq!(token, "metadata-token");
        assert_eq!(primary_calls.load(Ordering::SeqCst), 0);
        assert_eq!(fallback_calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn test_sanitized_gcloud_stderr_redacts_and_truncates() {
        let stderr = format!(
            "account=user@example.com Authorization: Bearer {} {}",
            "a".repeat(300),
            "x".repeat(300)
        );
        let sanitized = sanitized_gcloud_stderr(stderr.as_bytes());
        assert!(!sanitized.contains("Bearer aaaa"));
        assert!(sanitized.len() <= GCLOUD_STDERR_ERROR_MAX_BYTES);
        assert!(sanitized.contains("[REDACTED]"));
    }

    #[cfg(unix)]
    fn write_unix_script(contents: &str) -> (tempfile::TempDir, std::path::PathBuf) {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("gcloud");
        std::fs::write(&path, contents).expect("write script");
        let mut permissions = std::fs::metadata(&path).expect("metadata").permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&path, permissions).expect("chmod");
        (dir, path)
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_gcloud_cli_timeout_fires() {
        let (_dir, path) = write_unix_script("#!/bin/sh\nsleep 2\nprintf token\n");
        let provider = GCloudCliProvider::for_command(path.into_os_string(), 500);
        let err = provider.fetch_token().await.expect_err("must time out");
        assert!(
            err.to_string()
                .contains("gcloud command timed out after 500 ms"),
            "{err}"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_gcloud_cli_empty_stdout_errors() {
        let (_dir, path) = write_unix_script("#!/bin/sh\nexit 0\n");
        let provider = GCloudCliProvider::for_command(path.into_os_string(), 1_000);
        let err = provider
            .fetch_token()
            .await
            .expect_err("empty stdout must fail");
        assert!(err.to_string().contains("gcloud returned empty token"));
    }

    async fn spawn_metadata_fixture(
        response: String,
    ) -> (String, tokio::sync::oneshot::Receiver<String>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind fixture");
        let addr = listener.local_addr().expect("local addr");
        let (request_tx, request_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};

            let (mut stream, _) = listener.accept().await.expect("accept");
            let mut buf = vec![0u8; 4096];
            let n = stream.read(&mut buf).await.expect("read request");
            let request = String::from_utf8_lossy(&buf[..n]).to_string();
            let _ = request_tx.send(request);
            stream
                .write_all(response.as_bytes())
                .await
                .expect("write response");
        });
        (format!("http://{addr}"), request_rx)
    }

    fn http_response(status: &str, headers: &[(&str, &str)], body: &str) -> String {
        let mut response = format!("HTTP/1.1 {status}\r\nContent-Length: {}\r\n", body.len());
        for (name, value) in headers {
            response.push_str(name);
            response.push_str(": ");
            response.push_str(value);
            response.push_str("\r\n");
        }
        response.push_str("\r\n");
        response.push_str(body);
        response
    }

    #[tokio::test]
    async fn test_metadata_provider_requires_metadata_flavor_response_header() {
        let body = r#"{"access_token":"metadata-token"}"#;
        let (base_url, _request_rx) =
            spawn_metadata_fixture(http_response("200 OK", &[], body)).await;
        let provider = MetadataProvider::new_with_base_url(base_url).expect("provider");

        let err = provider
            .fetch_token()
            .await
            .expect_err("missing metadata flavor must fail");
        assert!(
            err.to_string()
                .contains("metadata response missing Metadata-Flavor: Google"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn test_metadata_provider_rejects_wrong_metadata_flavor_response_header() {
        let body = r#"{"access_token":"metadata-token"}"#;
        let (base_url, _request_rx) = spawn_metadata_fixture(http_response(
            "200 OK",
            &[("Metadata-Flavor", "Amazon")],
            body,
        ))
        .await;
        let provider = MetadataProvider::new_with_base_url(base_url).expect("provider");

        let err = provider
            .fetch_token()
            .await
            .expect_err("wrong metadata flavor must fail");
        assert!(
            err.to_string()
                .contains("metadata response missing Metadata-Flavor: Google"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn test_metadata_provider_sends_metadata_flavor_header_and_reads_token() {
        let body = r#"{"access_token":"metadata-token"}"#;
        let (base_url, request_rx) = spawn_metadata_fixture(http_response(
            "200 OK",
            &[
                ("Metadata-Flavor", "Google"),
                ("Content-Type", "application/json"),
            ],
            body,
        ))
        .await;
        let provider = MetadataProvider::new_with_base_url(base_url).expect("provider");

        let token = provider.fetch_token().await.expect("token");
        let request = request_rx.await.expect("request");
        let request_lower = request.to_ascii_lowercase();
        assert_eq!(token, "metadata-token");
        assert!(request
            .contains("GET /computeMetadata/v1/instance/service-accounts/default/token HTTP/1.1"));
        assert!(request_lower.contains("metadata-flavor: google"));
    }

    #[tokio::test]
    async fn test_metadata_provider_does_not_follow_redirects() {
        let (base_url, _request_rx) = spawn_metadata_fixture(http_response(
            "302 Found",
            &[("Location", "/redirected")],
            "",
        ))
        .await;
        let provider = MetadataProvider::new_with_base_url(base_url).expect("provider");

        let err = provider
            .fetch_token()
            .await
            .expect_err("redirect must not be followed");
        assert!(
            err.to_string().contains("metadata server returned 302"),
            "{err}"
        );
    }

    #[test]
    fn test_gemini_adapter_build_body() {
        let request = CompletionRequest {
            model: "gemini-1.5-pro".to_string(),
            messages: vec![LlmMessage {
                role: LlmRole::User,
                content: vec![ContentBlock::Text {
                    text: "Hello".to_string(),
                    metadata: None,
                }],
            }],
            system: Some("You are a helpful assistant.".to_string()),
            temperature: Some(0.7),
            max_tokens: 100,
            tools: vec![ToolDefinition {
                name: "get_weather".to_string(),
                description: "Get weather".to_string(),
                input_schema: json!({ "type": "object", "properties": {} }),
            }],
            extra: None,
        };

        let body = build_gemini_body(&request);

        assert_eq!(
            body["system_instruction"]["parts"][0]["text"],
            "You are a helpful assistant."
        );
        assert_eq!(body["contents"][0]["role"], "user");
        assert_eq!(body["contents"][0]["parts"][0]["text"], "Hello");
        assert_eq!(body["generationConfig"]["temperature"], 0.7);
        assert_eq!(body["generationConfig"]["maxOutputTokens"], 100);
        assert_eq!(
            body["tools"][0]["function_declarations"][0]["name"],
            "get_weather"
        );
    }

    #[test]
    fn test_gemini_adapter_build_body_preserves_text_thought_signature() {
        let request = CompletionRequest {
            model: "gemini-1.5-pro".to_string(),
            messages: vec![LlmMessage {
                role: LlmRole::Assistant,
                content: vec![ContentBlock::Text {
                    text: "Hello".to_string(),
                    metadata: ContentBlockMetadata::with_gemini_thought_signature(Some(
                        "sig-text".to_string(),
                    )),
                }],
            }],
            system: None,
            temperature: None,
            max_tokens: 100,
            tools: vec![],
            extra: None,
        };

        let body = build_gemini_body(&request);
        assert_eq!(body["contents"][0]["parts"][0]["text"], "Hello");
        assert_eq!(
            body["contents"][0]["parts"][0]["thoughtSignature"],
            "sig-text"
        );
    }

    #[test]
    fn test_gemini_adapter_build_body_preserves_tool_call_thought_signature() {
        let request = CompletionRequest {
            model: "gemini-1.5-pro".to_string(),
            messages: vec![
                LlmMessage {
                    role: LlmRole::Assistant,
                    content: vec![ContentBlock::ToolUse {
                        id: "call_abc123".to_string(),
                        name: "get_weather".to_string(),
                        input: json!({"city": "SF"}),
                        metadata: ContentBlockMetadata::with_gemini_thought_signature(Some(
                            "sig-tool".to_string(),
                        )),
                    }],
                },
                LlmMessage {
                    role: LlmRole::User,
                    content: vec![ContentBlock::ToolResult {
                        tool_use_id: "call_abc123".to_string(),
                        content: "72F and sunny".to_string(),
                        is_error: false,
                    }],
                },
            ],
            system: None,
            temperature: None,
            max_tokens: 100,
            tools: vec![],
            extra: None,
        };

        let body = build_gemini_body(&request);
        assert_eq!(
            body["contents"][0]["parts"][0]["functionCall"]["name"],
            "get_weather"
        );
        assert_eq!(
            body["contents"][0]["parts"][0]["thoughtSignature"],
            "sig-tool"
        );
    }

    #[test]
    fn test_gemini_adapter_build_body_batches_consecutive_roles() {
        let request = CompletionRequest {
            model: "gemini-1.5-pro".to_string(),
            messages: vec![
                LlmMessage {
                    role: LlmRole::User,
                    content: vec![ContentBlock::Text {
                        text: "First user message".to_string(),
                        metadata: None,
                    }],
                },
                LlmMessage {
                    role: LlmRole::Assistant,
                    content: vec![ContentBlock::ToolUse {
                        id: "call_1".to_string(),
                        name: "get_weather".to_string(),
                        input: json!({"city": "SF"}),
                        metadata: None,
                    }],
                },
                LlmMessage {
                    role: LlmRole::Assistant,
                    content: vec![ContentBlock::ToolUse {
                        id: "call_2".to_string(),
                        name: "get_time".to_string(),
                        input: json!({"tz": "UTC"}),
                        metadata: None,
                    }],
                },
                LlmMessage {
                    role: LlmRole::User,
                    content: vec![ContentBlock::ToolResult {
                        tool_use_id: "call_1".to_string(),
                        content: "72F".to_string(),
                        is_error: false,
                    }],
                },
                LlmMessage {
                    role: LlmRole::User,
                    content: vec![ContentBlock::ToolResult {
                        tool_use_id: "call_2".to_string(),
                        content: "12:00".to_string(),
                        is_error: false,
                    }],
                },
            ],
            system: None,
            temperature: None,
            max_tokens: 100,
            tools: vec![],
            extra: None,
        };

        let body = build_gemini_body(&request);
        let contents = body["contents"].as_array().unwrap();

        // Should be 3 content entries: user, model (batched 2), user (batched 2)
        assert_eq!(contents.len(), 3);

        assert_eq!(contents[0]["role"], "user");
        assert_eq!(contents[0]["parts"].as_array().unwrap().len(), 1);
        assert_eq!(contents[0]["parts"][0]["text"], "First user message");

        assert_eq!(contents[1]["role"], "model");
        assert_eq!(contents[1]["parts"].as_array().unwrap().len(), 2);
        assert_eq!(
            contents[1]["parts"][0]["functionCall"]["name"],
            "get_weather"
        );
        assert_eq!(contents[1]["parts"][1]["functionCall"]["name"], "get_time");

        assert_eq!(contents[2]["role"], "user");
        assert_eq!(contents[2]["parts"].as_array().unwrap().len(), 2);
        assert_eq!(
            contents[2]["parts"][0]["functionResponse"]["name"],
            "get_weather"
        );
        assert_eq!(
            contents[2]["parts"][0]["functionResponse"]["response"]["result"],
            "72F"
        );
        assert_eq!(
            contents[2]["parts"][1]["functionResponse"]["name"],
            "get_time"
        );
        assert_eq!(
            contents[2]["parts"][1]["functionResponse"]["response"]["result"],
            "12:00"
        );
    }

    #[test]
    fn test_resolve_request_config() {
        let provider = VertexProvider::new(
            "my-project".to_string(),
            "us-central1".to_string(),
            Some("gemini-1.5-flash".to_string()),
        )
        .unwrap();

        // Gemini generic fallback
        let url = provider.resolve_request_config("vertex:default").unwrap();
        assert!(url.contains("publishers/google/models/gemini-1.5-flash"));
        assert!(url.contains("us-central1"));

        // Gemini 1.5 specific
        let url = provider
            .resolve_request_config("vertex:gemini-1.5-pro")
            .unwrap();
        assert!(url.contains("publishers/google/models/gemini-1.5-pro"));
        assert!(url.contains("us-central1"));

        // Gemini 3 (Global endpoint fallback test)
        let url = provider
            .resolve_request_config("vertex:gemini-3.0-flash")
            .unwrap();
        assert!(url.contains("locations/global"));
        assert!(url.contains("publishers/google/models/gemini-3.0-flash"));

        // SSRF Path Traversal test cases
        assert!(provider
            .resolve_request_config("vertex:gemini-1.5-pro/../../something")
            .is_err());
        assert!(provider
            .resolve_request_config("gemini-1.5-pro%2f%2e%2e%2f")
            .is_err());

        // Missing default model test
        let provider_no_default =
            VertexProvider::new("my-project".to_string(), "us-central1".to_string(), None).unwrap();
        assert!(provider_no_default
            .resolve_request_config("vertex:default")
            .is_err());
    }

    #[test]
    fn test_vertex_provider_validation() {
        // Valid params
        assert!(
            VertexProvider::new("my-project".to_string(), "us-central1".to_string(), None).is_ok()
        );
        assert!(VertexProvider::new("my-project".to_string(), "global".to_string(), None).is_ok());

        // Invalid project ID (too short)
        assert!(VertexProvider::new("my-p".to_string(), "us-central1".to_string(), None).is_err());

        // Invalid project ID (invalid characters)
        assert!(
            VertexProvider::new("my_project".to_string(), "us-central1".to_string(), None).is_err()
        );

        // Valid location (multi-hyphen region)
        assert!(VertexProvider::new(
            "my-project".to_string(),
            "northamerica-northeast1".to_string(),
            None
        )
        .is_ok());

        // Valid location (another multi-hyphen region name)
        assert!(VertexProvider::new(
            "my-project".to_string(),
            "southamerica-east1".to_string(),
            None
        )
        .is_ok());

        // Invalid location (no numbers)
        assert!(
            VertexProvider::new("my-project".to_string(), "us-central".to_string(), None).is_err()
        );

        // Invalid location (invalid characters)
        assert!(
            VertexProvider::new("my-project".to_string(), "us_central1".to_string(), None).is_err()
        );
    }

    #[test]
    fn test_vertex_provider_init_error_maps_to_setup_validation_error() {
        assert_eq!(
            VertexSetupValidationError::from(VertexProviderInitError::InvalidProjectId),
            VertexSetupValidationError::InvalidProjectId
        );
        assert_eq!(
            VertexSetupValidationError::from(VertexProviderInitError::InvalidLocation),
            VertexSetupValidationError::InvalidLocation
        );
        assert_eq!(
            VertexSetupValidationError::from(VertexProviderInitError::ClientInit(
                "builder failed".to_string()
            )),
            VertexSetupValidationError::ClientInit("builder failed".to_string())
        );
    }

    #[test]
    fn test_vertex_setup_validation_client_init_preserves_detail() {
        let err = VertexSetupValidationError::from(VertexProviderInitError::ClientInit(
            "tls backend unavailable".to_string(),
        ));
        assert_eq!(
            err.to_string(),
            "Vertex validation could not initialize the local HTTP client: tls backend unavailable"
        );
    }

    #[test]
    fn test_vertex_provider_rejects_unsupported_namespace() {
        let provider =
            VertexProvider::new("my-project".to_string(), "us-central1".to_string(), None).unwrap();
        let err = provider
            .resolve_request_config("anthropic/claude-3-opus")
            .expect_err("unsupported publisher namespace should fail");
        assert!(
            err.to_string().contains("Unsupported Vertex model"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_vertex_provider_rejects_unsupported_bare_model() {
        let provider =
            VertexProvider::new("my-project".to_string(), "us-central1".to_string(), None).unwrap();
        let err = provider
            .resolve_request_config("claude-3-opus")
            .expect_err("unsupported bare model should fail");
        assert!(
            err.to_string().contains("Unsupported Vertex model"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_classify_vertex_validation_probe_status() {
        assert_eq!(
            classify_vertex_validation_probe_status(StatusCode::OK),
            Ok(())
        );
        assert_eq!(
            classify_vertex_validation_probe_status(StatusCode::UNAUTHORIZED),
            Err(VertexSetupValidationError::AccessDenied)
        );
        assert_eq!(
            classify_vertex_validation_probe_status(StatusCode::FORBIDDEN),
            Err(VertexSetupValidationError::AccessDenied)
        );
        assert_eq!(
            classify_vertex_validation_probe_status(StatusCode::TOO_MANY_REQUESTS),
            Err(VertexSetupValidationError::RateLimited)
        );
        assert_eq!(
            classify_vertex_validation_probe_status(StatusCode::SERVICE_UNAVAILABLE),
            Err(VertexSetupValidationError::Transport)
        );
        assert_eq!(
            classify_vertex_validation_probe_status(StatusCode::TEMPORARY_REDIRECT),
            Err(VertexSetupValidationError::Transport)
        );
        assert_eq!(
            classify_vertex_validation_probe_status(StatusCode::BAD_REQUEST),
            Err(VertexSetupValidationError::ProbeRejected)
        );
        assert_eq!(
            classify_vertex_validation_probe_status(StatusCode::NOT_FOUND),
            Err(VertexSetupValidationError::Unavailable)
        );
        assert_eq!(
            classify_vertex_validation_probe_status(StatusCode::UNPROCESSABLE_ENTITY),
            Err(VertexSetupValidationError::Rejected)
        );
    }

    #[test]
    fn test_resolve_model_target_builds_publisher_config_url() {
        let provider =
            VertexProvider::new("my-project".to_string(), "us-central1".to_string(), None).unwrap();
        let target = provider
            .resolve_model_target("vertex:gemini-1.5-pro")
            .expect("model target");
        assert_eq!(
            target.publisher_model_config_url("my-project"),
            "https://us-central1-aiplatform.googleapis.com/v1beta1/projects/my-project/locations/us-central1/publishers/google/models/gemini-1.5-pro:fetchPublisherModelConfig"
        );
    }

    #[test]
    fn test_gemini_adapter_parsing() {
        let mut usage = TokenUsage::default();

        // chunk with text
        let data = json!({
            "candidates": [{
                "content": {
                    "parts": [{ "text": "Hello" }]
                }
            }]
        })
        .to_string();

        let events = parse_gemini_chunk(&data, &mut usage).unwrap();
        assert_eq!(events.len(), 1);
        match &events[0] {
            StreamEvent::TextDelta { text, .. } => assert_eq!(text, "Hello"),
            _ => panic!("Expected TextDelta"),
        }

        let data = json!({
            "candidates": [{
                "content": {
                    "parts": [{ "text": "Hello", "thoughtSignature": "sig-text" }]
                }
            }]
        })
        .to_string();

        let events = parse_gemini_chunk(&data, &mut usage).unwrap();
        match &events[0] {
            StreamEvent::TextDelta { text, metadata } => {
                assert_eq!(text, "Hello");
                assert_eq!(
                    metadata
                        .as_ref()
                        .and_then(ContentBlockMetadata::gemini_thought_signature),
                    Some("sig-text")
                );
            }
            _ => panic!("Expected TextDelta"),
        }

        let data = json!({
            "candidates": [{
                "content": {
                    "parts": [{ "text": "", "thoughtSignature": "sig-empty" }]
                }
            }]
        })
        .to_string();

        let events = parse_gemini_chunk(&data, &mut usage).unwrap();
        match &events[0] {
            StreamEvent::TextDelta { text, metadata } => {
                assert_eq!(text, "");
                assert_eq!(
                    metadata
                        .as_ref()
                        .and_then(ContentBlockMetadata::gemini_thought_signature),
                    Some("sig-empty")
                );
            }
            _ => panic!("Expected TextDelta"),
        }

        let data = json!({
            "candidates": [{
                "content": {
                    "parts": [{
                        "functionCall": {
                            "name": "get_weather",
                            "args": { "city": "SF" }
                        },
                        "thoughtSignature": "sig-tool"
                    }]
                }
            }]
        })
        .to_string();

        let events = parse_gemini_chunk(&data, &mut usage).unwrap();
        match &events[0] {
            StreamEvent::ToolUse {
                name,
                input,
                metadata,
                ..
            } => {
                assert_eq!(name, "get_weather");
                assert_eq!(input["city"], "SF");
                assert_eq!(
                    metadata
                        .as_ref()
                        .and_then(ContentBlockMetadata::gemini_thought_signature),
                    Some("sig-tool")
                );
            }
            _ => panic!("Expected ToolUse"),
        }

        // chunk with usage and finish reason
        let data = json!({
            "candidates": [{
                "finishReason": "STOP",
                "content": { "parts": [] } // or missing?
            }],
            "usageMetadata": {
                "promptTokenCount": 10,
                "candidatesTokenCount": 20
            }
        })
        .to_string();
        let events = parse_gemini_chunk(&data, &mut usage).unwrap();
        // Should have Stop event
        assert!(events.iter().any(|e| matches!(e, StreamEvent::Stop { .. })));
        assert_eq!(usage.input_tokens, 10);
        assert_eq!(usage.output_tokens, 20);
    }

    // ==================== Anthropic-on-Vertex tests ====================

    #[test]
    fn test_resolve_anthropic_publisher_model() {
        let provider =
            VertexProvider::new("my-project".to_string(), "us-central1".to_string(), None).unwrap();
        let target = provider
            .resolve_model_target("publishers/anthropic/models/claude-sonnet-4-6")
            .expect("anthropic model target");
        assert_eq!(target.publisher, VertexPublisher::Anthropic);
        assert_eq!(target.model_id, "claude-sonnet-4-6");
        assert_eq!(target.endpoint_location, "us-central1");
    }

    #[test]
    fn test_resolve_anthropic_publisher_model_with_vertex_prefix() {
        let provider =
            VertexProvider::new("my-project".to_string(), "us-central1".to_string(), None).unwrap();
        let target = provider
            .resolve_model_target("vertex:publishers/anthropic/models/claude-sonnet-4-6")
            .expect("anthropic model target with vertex prefix");
        assert_eq!(target.publisher, VertexPublisher::Anthropic);
        assert_eq!(target.model_id, "claude-sonnet-4-6");
    }

    #[test]
    fn test_anthropic_stream_raw_predict_url() {
        let provider =
            VertexProvider::new("my-project".to_string(), "us-central1".to_string(), None).unwrap();
        let target = provider
            .resolve_model_target("publishers/anthropic/models/claude-sonnet-4-6")
            .unwrap();
        assert_eq!(
            target.stream_raw_predict_url("my-project"),
            "https://us-central1-aiplatform.googleapis.com/v1/projects/my-project/locations/us-central1/publishers/anthropic/models/claude-sonnet-4-6:streamRawPredict"
        );
    }

    #[test]
    fn test_anthropic_streaming_url_uses_raw_predict() {
        let provider =
            VertexProvider::new("my-project".to_string(), "us-central1".to_string(), None).unwrap();
        let url = provider
            .resolve_request_config("publishers/anthropic/models/claude-sonnet-4-6")
            .unwrap();
        assert!(
            url.contains("streamRawPredict"),
            "Anthropic publisher should use streamRawPredict: {url}"
        );
        assert!(
            !url.contains("streamGenerateContent"),
            "Anthropic publisher should not use streamGenerateContent: {url}"
        );
    }

    #[test]
    fn test_gemini_streaming_url_uses_generate_content() {
        let provider =
            VertexProvider::new("my-project".to_string(), "us-central1".to_string(), None).unwrap();
        let url = provider.resolve_request_config("gemini-2.5-flash").unwrap();
        assert!(
            url.contains("streamGenerateContent"),
            "Google publisher should use streamGenerateContent: {url}"
        );
    }

    #[test]
    fn test_anthropic_publisher_model_config_url() {
        let provider =
            VertexProvider::new("my-project".to_string(), "us-central1".to_string(), None).unwrap();
        let target = provider
            .resolve_model_target("publishers/anthropic/models/claude-sonnet-4-6")
            .unwrap();
        let config_url = target.publisher_model_config_url("my-project");
        assert!(
            config_url.contains("publishers/anthropic/"),
            "config URL should reference anthropic publisher: {config_url}"
        );
        assert!(
            config_url.contains("fetchPublisherModelConfig"),
            "config URL should use fetchPublisherModelConfig: {config_url}"
        );
    }

    #[test]
    fn test_reject_unknown_publisher() {
        let provider =
            VertexProvider::new("my-project".to_string(), "us-central1".to_string(), None).unwrap();
        let err = provider
            .resolve_model_target("publishers/openai/models/gpt-5.5")
            .expect_err("unknown publisher should fail");
        assert_eq!(err, VertexSetupValidationError::UnsupportedModel);
    }

    #[test]
    fn test_reject_dot_segment_model_ids() {
        let provider =
            VertexProvider::new("my-project".to_string(), "us-central1".to_string(), None).unwrap();
        // Dot-only sequences are path traversal vectors (RFC 3986 dot-segment normalization)
        assert!(provider
            .resolve_model_target("publishers/anthropic/models/..")
            .is_err());
        assert!(provider
            .resolve_model_target("publishers/anthropic/models/.")
            .is_err());
        assert!(provider
            .resolve_model_target("publishers/anthropic/models/...")
            .is_err());
        // Leading dot rejected even with trailing alphanumeric
        assert!(provider
            .resolve_model_target("publishers/anthropic/models/.hidden")
            .is_err());
        // Dots in the middle are fine (e.g. version separators)
        assert!(provider
            .resolve_model_target("publishers/anthropic/models/claude-3.5-sonnet")
            .is_ok());
    }

    #[test]
    fn test_reject_malformed_publisher_path() {
        let provider =
            VertexProvider::new("my-project".to_string(), "us-central1".to_string(), None).unwrap();
        // Missing models/ segment
        assert!(provider
            .resolve_model_target("publishers/anthropic/claude-3")
            .is_err());
        // Empty model ID
        assert!(provider
            .resolve_model_target("publishers/anthropic/models/")
            .is_err());
        // Path traversal in model ID
        assert!(provider
            .resolve_model_target("publishers/anthropic/models/../../etc/passwd")
            .is_err());
    }

    #[test]
    fn test_anthropic_body_has_anthropic_version_no_model() {
        let request = CompletionRequest {
            model: "publishers/anthropic/models/claude-sonnet-4-6".to_string(),
            messages: vec![LlmMessage {
                role: LlmRole::User,
                content: vec![ContentBlock::Text {
                    text: "Hello".to_string(),
                    metadata: None,
                }],
            }],
            system: Some("You are helpful.".to_string()),
            tools: vec![],
            max_tokens: 1024,
            temperature: Some(0.7),
            extra: None,
        };

        let mut body = crate::agent::anthropic_wire::build_messages_body(&request);
        body["anthropic_version"] = json!("vertex-2023-10-16");

        assert_eq!(body["anthropic_version"], "vertex-2023-10-16");
        assert!(
            body.get("model").is_none(),
            "Vertex Anthropic body should not include model field"
        );
        assert_eq!(body["max_tokens"], 1024);
        assert_eq!(body["stream"], true);
        assert_eq!(body["system"], "You are helpful.");
    }

    #[test]
    fn test_vertex_publisher_as_str() {
        assert_eq!(VertexPublisher::Google.as_str(), "google");
        assert_eq!(VertexPublisher::Anthropic.as_str(), "anthropic");
        assert_eq!(VertexPublisher::Meta.as_str(), "meta");
        assert_eq!(VertexPublisher::Mistral.as_str(), "mistral");
        assert_eq!(VertexPublisher::Nvidia.as_str(), "nvidia");
    }

    // ==================== OpenAI-compat publishers (Meta/Mistral/Nvidia) ====================

    #[test]
    fn test_resolve_meta_publisher_model() {
        let provider =
            VertexProvider::new("my-project".to_string(), "us-central1".to_string(), None).unwrap();
        let target = provider
            .resolve_model_target("publishers/meta/models/llama-3.1-405b-instruct-maas")
            .expect("meta model target");
        assert_eq!(target.publisher, VertexPublisher::Meta);
        assert_eq!(target.model_id, "llama-3.1-405b-instruct-maas");
        assert_eq!(target.endpoint_location, "us-central1");
    }

    #[test]
    fn test_resolve_mistral_publisher_model() {
        let provider =
            VertexProvider::new("my-project".to_string(), "us-central1".to_string(), None).unwrap();
        let target = provider
            .resolve_model_target("publishers/mistral/models/mistral-large-2411")
            .expect("mistral model target");
        assert_eq!(target.publisher, VertexPublisher::Mistral);
        assert_eq!(target.model_id, "mistral-large-2411");
    }

    #[test]
    fn test_resolve_nvidia_publisher_model() {
        let provider =
            VertexProvider::new("my-project".to_string(), "us-central1".to_string(), None).unwrap();
        let target = provider
            .resolve_model_target("publishers/nvidia/models/llama-3.1-nemotron-70b-instruct")
            .expect("nvidia model target");
        assert_eq!(target.publisher, VertexPublisher::Nvidia);
        assert_eq!(target.model_id, "llama-3.1-nemotron-70b-instruct");
    }

    #[test]
    fn test_openai_compat_publishers_use_stream_raw_predict() {
        let provider =
            VertexProvider::new("my-project".to_string(), "us-central1".to_string(), None).unwrap();
        for path in [
            "publishers/meta/models/llama-3.1-405b-instruct-maas",
            "publishers/mistral/models/mistral-large-2411",
            "publishers/nvidia/models/llama-3.1-nemotron-70b-instruct",
        ] {
            let url = provider.resolve_request_config(path).unwrap();
            assert!(
                url.contains("streamRawPredict"),
                "third-party publisher should use streamRawPredict: {url}"
            );
            assert!(
                !url.contains("streamGenerateContent"),
                "third-party publisher should not use streamGenerateContent: {url}"
            );
        }
    }

    #[test]
    fn test_openai_compat_body_has_model_and_max_tokens() {
        let request = CompletionRequest {
            model: "publishers/meta/models/llama-3.1-405b-instruct-maas".to_string(),
            messages: vec![LlmMessage {
                role: LlmRole::User,
                content: vec![ContentBlock::Text {
                    text: "Hello".to_string(),
                    metadata: None,
                }],
            }],
            system: Some("You are helpful.".to_string()),
            tools: vec![],
            max_tokens: 2048,
            temperature: Some(0.7),
            extra: None,
        };

        let mut body = crate::agent::openai_wire::build_openai_messages_body(&request);
        body["model"] = json!("llama-3.1-405b-instruct-maas");
        body["max_tokens"] = json!(request.max_tokens);

        body["stream_options"] = json!({ "include_usage": true });

        assert_eq!(body["model"], "llama-3.1-405b-instruct-maas");
        assert_eq!(body["max_tokens"], 2048);
        assert_eq!(body["stream"], true);
        assert_eq!(body["temperature"], 0.7);
        assert_eq!(
            body["stream_options"]["include_usage"], true,
            "stream_options should request usage data"
        );
        // No max_completion_tokens (OpenAI-specific field name)
        assert!(body.get("max_completion_tokens").is_none());
    }
}
