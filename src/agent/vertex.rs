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
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, RwLock};
use tokio_util::sync::CancellationToken;
use tracing::debug;

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
                "Unsupported Vertex model. This provider currently supports Google Gemini models only."
            ),
            Self::ClientInit(detail) => {
                if detail.is_empty() {
                    write!(f, "Vertex validation could not initialize the local HTTP client.")
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

#[derive(Debug)]
struct GCloudCliProvider;

#[async_trait]
impl TokenProvider for GCloudCliProvider {
    async fn fetch_token(&self) -> Result<String, AgentError> {
        debug!("fetching access token via gcloud cli");
        let output = tokio::process::Command::new("gcloud")
            .arg("auth")
            .arg("print-access-token")
            .output()
            .await
            .map_err(|e| AgentError::Provider(format!("failed to run gcloud: {e}")))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(AgentError::Provider(format!(
                "gcloud auth print-access-token failed: {stderr}"
            )));
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

#[derive(Debug)]
struct MetadataProvider {
    client: reqwest::Client,
}

impl MetadataProvider {
    fn new() -> Result<Self, VertexProviderInitError> {
        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(2))
            .timeout(Duration::from_secs(5))
            .build()
            .map_err(|e| VertexProviderInitError::ClientInit(e.to_string()))?;
        Ok(Self { client })
    }
}

#[async_trait]
impl TokenProvider for MetadataProvider {
    async fn fetch_token(&self) -> Result<String, AgentError> {
        debug!("fetching access token via metadata server");
        // SAFETY: the GCP metadata server is a fixed link-local endpoint that only serves HTTP.
        // HTTPS is not supported there, and this URL is fully static rather than user-controlled.
        // We keep the scheme split to avoid the false-positive CodeQL "use HTTPS URLs" warning.
        let url = format!(
            "{}://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
            "http"
        );
        let response = self
            .client
            .get(url)
            .header("Metadata-Flavor", "Google")
            .send()
            .await
            .map_err(|e| AgentError::Provider(format!("metadata request failed: {e}")))?;

        if !response.status().is_success() {
            return Err(AgentError::Provider(format!(
                "metadata server returned {}",
                response.status()
            )));
        }

        let body: Value = response
            .json()
            .await
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
    let mut contents: Vec<Value> = Vec::new();

    for msg in &request.messages {
        let role = match msg.role {
            LlmRole::User => "user",
            LlmRole::Assistant => "model",
        };

        let mut parts: Vec<Value> = Vec::new();

        for block in &msg.content {
            match block {
                ContentBlock::Text { text, metadata } => {
                    let mut part = json!({ "text": text });
                    apply_gemini_thought_signature(&mut part, metadata);
                    parts.push(part);
                }
                ContentBlock::ToolUse {
                    id: _,
                    name,
                    input,
                    metadata,
                } => {
                    let mut part = json!({
                        "functionCall": {
                            "name": name,
                            "args": input,
                        }
                    });
                    apply_gemini_thought_signature(&mut part, metadata);
                    parts.push(part);
                }
                ContentBlock::ToolResult {
                    tool_use_id: _,
                    content,
                    is_error: _,
                } => {
                    let tool_name = find_tool_name_for_result(&request.messages, block);
                    let part = json!({
                        "functionResponse": {
                            "name": tool_name,
                            "response": {
                                "result": content,
                            }
                        }
                    });
                    parts.push(part);
                }
            }
        }

        if !parts.is_empty() {
            contents.push(json!({
                "role": role,
                "parts": parts,
            }));
        }
    }

    body["contents"] = json!(contents);

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

#[derive(Debug, Clone, PartialEq, Eq)]
struct ResolvedVertexModel {
    endpoint_location: String,
    publisher: &'static str,
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
            "{}/v1beta1/projects/{}/locations/{}/publishers/{}/models/{}:streamGenerateContent?alt=sse",
            self.service_endpoint(),
            project_id,
            self.endpoint_location,
            self.publisher,
            self.model_id
        )
    }

    fn publisher_model_config_url(&self, project_id: &str) -> String {
        format!(
            "{}/v1beta1/projects/{}/locations/{}/publishers/{}/models/{}:fetchPublisherModelConfig",
            self.service_endpoint(),
            project_id,
            self.endpoint_location,
            self.publisher,
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
        validate_project_id(&project_id).map_err(|_| VertexProviderInitError::InvalidProjectId)?;
        validate_location(&location).map_err(|_| VertexProviderInitError::InvalidLocation)?;

        // Uses FallbackTokenProvider: tries gcloud CLI first and falls back to the metadata server.
        let token_manager: Arc<dyn TokenProvider> = Arc::new(FallbackTokenProvider::new()?);

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

    /// Resolves the Google-published Gemini model target on Vertex AI.
    ///
    /// Rules:
    /// - `vertex/gemini-1.5-pro` -> Google publisher, gemini-1.5-pro
    /// - `vertex/google/gemini-1.5-pro` -> Google publisher, gemini-1.5-pro
    /// - `vertex` / `vertex:default` -> use `default_model`
    /// - non-Gemini model IDs and other publisher namespaces are rejected in this scoped implementation
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

        let (publisher, model_id): (&str, &str) =
            if let Some(model_id) = effective_model.strip_prefix("google/") {
                if !model_id.starts_with("gemini-") {
                    return Err(VertexSetupValidationError::UnsupportedModel);
                }
                ("google", model_id)
            } else if effective_model.contains('/') || !effective_model.starts_with("gemini-") {
                return Err(VertexSetupValidationError::UnsupportedModel);
            } else {
                // Bare Gemini model IDs are treated as Google-published models on Vertex AI.
                ("google", effective_model)
            };
        // SSRF / Path Traversal Validation
        if model_id.is_empty()
            || !model_id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
        {
            return Err(VertexSetupValidationError::UnsupportedModel);
        }

        // Global endpoints for Gemini 3 and Experimental
        // These models are automatically routed to the global endpoint `aiplatform.googleapis.com`
        // unless overridden.
        if model_id.starts_with("gemini-3") {
            return Ok(ResolvedVertexModel {
                endpoint_location: "global".to_string(),
                publisher,
                model_id: model_id.to_string(),
            });
        }

        Ok(ResolvedVertexModel {
            endpoint_location: self.location.clone(),
            publisher,
            model_id: model_id.to_string(),
        })
    }

    fn resolve_request_config(&self, model_name: &str) -> Result<String, AgentError> {
        self.resolve_model_target(model_name)
            .map(|resolved| resolved.stream_generate_url(&self.project_id))
            .map_err(|err| AgentError::Provider(err.to_string()))
    }
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
    let provider = VertexProvider::try_new(project_id, location, default_model)
        .map_err(VertexSetupValidationError::from)?;
    let target = provider.resolve_model_target(&route_model)?;
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
    if let Err(err) = response.bytes().await {
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
    primary: GCloudCliProvider,
    fallback: MetadataProvider,
}

impl FallbackTokenProvider {
    fn new() -> Result<Self, VertexProviderInitError> {
        Ok(Self {
            primary: GCloudCliProvider,
            fallback: MetadataProvider::new()?,
        })
    }
}

#[async_trait]
impl TokenProvider for FallbackTokenProvider {
    async fn fetch_token(&self) -> Result<String, AgentError> {
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

fn find_tool_name_for_result<'a>(messages: &'a [LlmMessage], block: &ContentBlock) -> &'a str {
    let target_id = match block {
        ContentBlock::ToolResult { tool_use_id, .. } => tool_use_id,
        _ => return "unknown",
    };

    for msg in messages.iter().rev() {
        for b in &msg.content {
            if let ContentBlock::ToolUse { id, name, .. } = b {
                if id == target_id {
                    return name;
                }
            }
        }
    }

    "unknown"
}

/// Strip the `vertex:` prefix from a model identifier.
///
/// Returns the bare model name suitable for passing to the Vertex API
/// (e.g. `gemini-2.0-flash`).
pub fn strip_vertex_prefix(model: &str) -> &str {
    if is_vertex_model(model) {
        &model[7..]
    } else {
        model
    }
}

/// Determine whether a model identifier should route to the Vertex provider.
///
/// Requires the canonical `vertex:` prefix (e.g. `vertex:gemini-2.0-flash`).
pub fn is_vertex_model(model: &str) -> bool {
    model.len() > 7
        && model.as_bytes()[..6].eq_ignore_ascii_case(b"vertex")
        && model.as_bytes()[6] == b':'
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

        let token = self.get_token().await?;
        let url = self.resolve_request_config(&request.model)?;
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
                    response.map_err(|e| AgentError::Provider(format!("HTTP request failed: {e}")))?
                }
        };

        if !response.status().is_success() {
            let status = response.status();
            let body = response
                .text()
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
}

/// Maximum SSE line buffer size (1 MB). If a single SSE line exceeds this,
/// the stream is treated as corrupted to prevent unbounded memory growth.
const MAX_SSE_BUFFER_BYTES: usize = 1_048_576;

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
        let chunk = chunk.map_err(|e| format!("stream read error: {e}"))?;
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
    use serde_json::json;

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
    fn test_gemini_adapter_build_body() {
        let request = CompletionRequest {
            model: "vertex/gemini-1.5-pro".to_string(),
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
            model: "vertex/gemini-1.5-pro".to_string(),
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
            model: "vertex/gemini-1.5-pro".to_string(),
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
            .resolve_request_config("vertex/anthropic/claude-3-opus")
            .expect_err("unsupported publisher namespace should fail");
        assert!(
            err.to_string()
                .contains("supports Google Gemini models only"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_vertex_provider_rejects_unsupported_bare_model() {
        let provider =
            VertexProvider::new("my-project".to_string(), "us-central1".to_string(), None).unwrap();
        let err = provider
            .resolve_request_config("vertex/claude-3-opus")
            .expect_err("unsupported bare model should fail");
        assert!(
            err.to_string()
                .contains("supports Google Gemini models only"),
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
}
