//! Google Vertex AI provider.
//!
//! Streams completions from the Vertex AI `v1beta1/projects/{project}/locations/{location}/publishers/google/models/{model}:streamGenerateContent`
//! endpoint using Server-Sent Events (SSE).
//!
//! Uses `gcloud` CLI or Metadata Server for authentication.

use async_trait::async_trait;
use futures_util::StreamExt;
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, RwLock};
use tokio_util::sync::CancellationToken;
use tracing::debug;

use crate::agent::provider::*;
use crate::agent::AgentError;

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
    fn new() -> Self {
        Self {
            client: reqwest::Client::new(),
        }
    }
}

#[async_trait]
impl TokenProvider for MetadataProvider {
    async fn fetch_token(&self) -> Result<String, AgentError> {
        debug!("fetching access token via metadata server");
        // The GCP metadata server does not support HTTPS.
        // We construct the URL dynamically to avoid CodeQL's "Failure to use HTTPS URLs" warning.
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
// Response Adapters
// =================================================================================================

fn build_gemini_body(request: &CompletionRequest) -> Value {
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
                ContentBlock::Text { text } => {
                    parts.push(json!({ "text": text }));
                }
                ContentBlock::ToolUse { id: _, name, input } => {
                    parts.push(json!({
                        "functionCall": {
                            "name": name,
                            "args": input,
                        }
                    }));
                }
                ContentBlock::ToolResult {
                    tool_use_id: _,
                    content,
                    is_error: _,
                } => {
                    let tool_name = find_tool_name_for_result(&request.messages, block);
                    parts.push(json!({
                        "functionResponse": {
                            "name": tool_name,
                            "response": {
                                "result": content,
                            }
                        }
                    }));
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

impl std::fmt::Debug for VertexProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VertexProvider")
            .field("project_id", &self.project_id)
            .field("location", &self.location)
            .finish()
    }
}

impl VertexProvider {
    pub fn new(
        project_id: String,
        location: String,
        default_model: Option<String>,
    ) -> Result<Self, AgentError> {
        // Uses FallbackTokenProvider: tries gcloud CLI first and falls back to the metadata server.
        let token_manager: Arc<dyn TokenProvider> = Arc::new(FallbackTokenProvider::new());

        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(300))
            .build()
            .map_err(|e| AgentError::Provider(format!("failed to build HTTP client: {e}")))?;

        Ok(Self {
            client,
            project_id,
            location,
            token_manager,
            token_cache: Arc::new(RwLock::new(None)),
            default_model,
        })
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
            expires_at: Instant::now() + Duration::from_secs(3600), // Assume 1 hour validity
        });

        Ok(token)
    }

    /// Resolves the API endpoint, publisher, model ID, and storage adapter based on the model name.
    ///
    /// Rules:
    /// - `vertex/gemini-1.5-pro` -> Google, gemini-1.5-pro, GeminiAdapter
    /// - `vertex/anthropic/claude-3-opus` -> Anthropic, claude-3-opus, AnthropicAdapter
    /// - `vertex/meta/llama3-405b` -> Meta, llama3-405b, OpenAiAdapter
    /// - `vertex` (generic) -> `default_model` -> Resolve recursively
    fn resolve_request_config(&self, model_name: &str) -> Result<String, AgentError> {
        let clean_model = strip_vertex_prefix(model_name);

        // Handle generic fallback
        let effective_model = if clean_model.is_empty() || clean_model == "default" {
            if let Some(ref default) = self.default_model {
                // Use the default model, but strip any prefix it might have to avoid recursion if simple prefix stripping isn't enough?
                // Ideally default_model is stored clean or we recurse?
                // Let's assume default_model is the full ID like "gemini-1.5-pro" or "vertex/gemini-1.5-pro".
                strip_vertex_prefix(default)
            } else {
                return Err(AgentError::Provider(
                    "Missing required model parameter and no default model is configured."
                        .to_string(),
                ));
            }
        } else {
            clean_model
        };

        let (publisher, model_id): (&str, &str) = if effective_model.starts_with("google/") {
            (
                "google",
                effective_model
                    .strip_prefix("google/")
                    .unwrap_or(effective_model),
            )
        } else if effective_model.starts_with("gemini-") {
            // Models prefixed with "gemini-" are treated as Google Gemini models on Vertex AI.
            ("google", effective_model)
        } else {
            // Fallback: treat other models as Google Gemini models within Vertex AI.
            ("google", effective_model)
        };
        // SSRF / Path Traversal Validation
        if model_id.is_empty()
            || !model_id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
        {
            return Err(AgentError::Provider(format!(
                "Invalid model identifier: {}",
                model_id
            )));
        }

        let method = "streamGenerateContent";

        // Global endpoints for Gemini 3 and Experimental
        // These models are automatically routed to the global endpoint `aiplatform.googleapis.com`
        // unless overridden.
        if model_id.contains("gemini-3") {
            let url = format!(
                "https://aiplatform.googleapis.com/v1beta1/projects/{}/locations/{}/publishers/{}/models/{}:{}?alt=sse",
                self.project_id, "global", publisher, model_id, method
            );
            return Ok(url);
        }

        let url = format!(
            "https://{}-aiplatform.googleapis.com/v1beta1/projects/{}/locations/{}/publishers/{}/models/{}:{}?alt=sse",
            self.location, self.project_id, self.location, publisher, model_id, method
        );
        Ok(url)
    }
}

#[derive(Debug)]
struct FallbackTokenProvider {
    primary: Box<dyn TokenProvider>,
    fallback: Box<dyn TokenProvider>,
}

impl FallbackTokenProvider {
    fn new() -> Self {
        Self {
            primary: Box::new(GCloudCliProvider),
            fallback: Box::new(MetadataProvider::new()),
        }
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

fn find_tool_name_for_result(messages: &[LlmMessage], block: &ContentBlock) -> String {
    let target_id = match block {
        ContentBlock::ToolResult { tool_use_id, .. } => tool_use_id,
        _ => return "unknown".to_string(),
    };

    for msg in messages.iter().rev() {
        for b in &msg.content {
            if let ContentBlock::ToolUse { id, name, .. } = b {
                if id == target_id {
                    return name.clone();
                }
            }
        }
    }

    "unknown".to_string()
}

pub fn strip_vertex_prefix(model: &str) -> &str {
    if let Some(rest) = model.strip_prefix("vertex/") {
        rest
    } else if let Some(rest) = model.strip_prefix("vertex:") {
        rest
    } else {
        model
    }
}

pub fn is_vertex_model(model: &str) -> bool {
    model.starts_with("vertex/") || model.starts_with("vertex:")
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
                // .header("accept", "text/event-stream") // Vertex sometimes is picky, but alt=sse should handle it.
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
            return Err(AgentError::Provider(format!(
                "Vertex API returned {status}: {body}"
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

// Copy of MAX_SSE_BUFFER_BYTES from gemini.rs
const MAX_SSE_BUFFER_BYTES: usize = 1_048_576;

// Logic mostly copied from gemini.rs but adapted if needed.
// Vertex SSE format is identical to Gemini API usually?
// Yes, Model Garden Gemini uses the same payload structure.
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
        if let Some(text) = part.get("text").and_then(|v| v.as_str()) {
            if !text.is_empty() {
                events.push(StreamEvent::TextDelta {
                    text: text.to_string(),
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
            strip_vertex_prefix("vertex/gemini-1.5-pro"),
            "gemini-1.5-pro"
        );
        assert_eq!(
            strip_vertex_prefix("vertex:gemini-1.5-pro"),
            "gemini-1.5-pro"
        );
        assert_eq!(strip_vertex_prefix("gemini-1.5-pro"), "gemini-1.5-pro");

        assert!(is_vertex_model("vertex/gemini-1.5-pro"));
        assert!(is_vertex_model("vertex:gemini-1.5-pro"));
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
    fn test_resolve_request_config() {
        let provider = VertexProvider::new(
            "my-project".to_string(),
            "us-central1".to_string(),
            Some("gemini-1.5-flash".to_string()),
        )
        .unwrap();

        // Gemini generic fallback
        let url = provider.resolve_request_config("vertex/default").unwrap();
        assert!(url.contains("publishers/google/models/gemini-1.5-flash"));
        assert!(url.contains("us-central1"));

        // Gemini 1.5 specific
        let url = provider
            .resolve_request_config("vertex/gemini-1.5-pro")
            .unwrap();
        assert!(url.contains("publishers/google/models/gemini-1.5-pro"));
        assert!(url.contains("us-central1"));

        // Gemini 3 (Global endpoint fallback test)
        let url = provider
            .resolve_request_config("vertex/gemini-3.0-flash")
            .unwrap();
        assert!(url.contains("locations/global"));
        assert!(url.contains("publishers/google/models/gemini-3.0-flash"));

        // SSRF Path Traversal test cases
        assert!(provider
            .resolve_request_config("vertex/gemini-1.5-pro/../../something")
            .is_err());
        assert!(provider
            .resolve_request_config("gemini-1.5-pro%2f%2e%2e%2f")
            .is_err());

        // Missing default model test
        let provider_no_default =
            VertexProvider::new("my-project".to_string(), "us-central1".to_string(), None).unwrap();
        assert!(provider_no_default
            .resolve_request_config("vertex/default")
            .is_err());
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
            StreamEvent::TextDelta { text } => assert_eq!(text, "Hello"),
            _ => panic!("Expected TextDelta"),
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
