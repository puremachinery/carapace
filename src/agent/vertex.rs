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
            return Err(AgentError::Provider("gcloud returned empty token".to_string()));
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
        let url = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token";
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
            .ok_or_else(|| AgentError::Provider("metadata response missing access_token".to_string()))
    }
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
    pub fn new(project_id: String, location: String) -> Self {
        // Determine auth strategy: check if gcloud is available, otherwise assume metadata
        // For simplicity and robustness, we can try to detect or just default to a composite strategy.
        // But per plan: "The provider will attempt to use GCloudCliProvider first. If gcloud is not found (NotFound), it falls back to MetadataProvider."
        // We can't easily detect "NotFound" without running it.
        // So we'll wrap a composite provider? Or just pick one?
        // Let's implement a composite strategy inside `get_token` or use a trait object that does fallback.
        // Actually, checking for gcloud existence is a bit racy or slow to do in `new`.
        // Let's just default to GCloudCli for now as most users are local, AND verify if we are in cloud?
        // The plan said: "If gcloud is not found (NotFound), it falls back".
        // Let's make a `CompositeTokenProvider`.

        let token_manager: Arc<dyn TokenProvider> = Arc::new(FallbackTokenProvider {
            primary: Box::new(GCloudCliProvider),
            fallback: Box::new(MetadataProvider::new()),
        });

        Self {
            client: reqwest::Client::builder()
                .connect_timeout(Duration::from_secs(10))
                .timeout(Duration::from_secs(300))
                .build()
                .expect("failed to build reqwest client"),
            project_id,
            location,
            token_manager,
            token_cache: Arc::new(RwLock::new(None)),
        }
    }

    async fn get_token(&self) -> Result<String, AgentError> {
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

    /// Build the JSON body for the Vertex AI streamGenerateContent API.
    /// This is largely identical to GeminiProvider::build_body.
    fn build_body(&self, request: &CompletionRequest) -> Value {
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
}

#[derive(Debug)]
struct FallbackTokenProvider {
    primary: Box<dyn TokenProvider>,
    fallback: Box<dyn TokenProvider>,
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
        let body = self.build_body(&request);
        let model_name = strip_vertex_prefix(&request.model);

        let url = format!(
            "https://{}-aiplatform.googleapis.com/v1beta1/projects/{}/locations/{}/publishers/google/models/{}:streamGenerateContent?alt=sse",
            self.location, self.project_id, self.location, model_name
        );

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
                if let Some(events) =
                    parse_vertex_sse_data(data, &mut accumulated_usage, &mut last_finish_reason)
                {
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
            }
        }
        if consumed > 0 {
            buffer.drain(..consumed);
        }
    }

    // Vertex also doesn't use [DONE] sentinel
    let reason = match last_finish_reason.as_deref() {
        Some("MAX_TOKENS") => StopReason::MaxTokens,
        Some("STOP") => StopReason::EndTurn,
        _ => StopReason::EndTurn,
    };

    // Only send stop if we haven't already (though logic above breaks on Stop event,
    // so this is for cases where stream ends without explicit stop event?)
    // Actually the logic above loops until stream ends.
    // If last event was STOP, we essentially double send?
    // In gemini.rs, it sends StopReason::EndTurn if loop finishes.
    // Let's safe guard.
    // But since we can't easily check what was sent last without tracking,
    // we'll just follow gemini.rs pattern: "Gemini streams don't use a [DONE] sentinel... If we haven't sent a Stop event yet, send one now."
    // Wait, gemini.rs breaks on Stop event?
    // "if is_stop || is_error { return Ok(()); }"
    // So if we received a STOP event, we returned early.
    // If we reach here, it means the stream ended WITHOUT a stop event (maybe network close?).
    // In that case, we synthesize a Stop event.

    let _ = tx
        .send(StreamEvent::Stop {
            reason,
            usage: accumulated_usage,
        })
        .await;

    Ok(())
}

fn parse_vertex_sse_data(
    data: &str,
    accumulated_usage: &mut TokenUsage,
    last_finish_reason: &mut Option<String>,
) -> Option<Vec<StreamEvent>> {
    let parsed: Value = serde_json::from_str(data).ok()?;

    if let Some(error) = parsed.get("error") {
        let message = error
            .get("message")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown API error")
            .to_string();
        return Some(vec![StreamEvent::Error { message }]);
    }

    extract_vertex_usage(&parsed, accumulated_usage);

    let candidates = parsed.get("candidates")?.as_array()?;
    if candidates.is_empty() {
        return None;
    }

    let candidate = &candidates[0];

    if let Some(finish_reason) = candidate.get("finishReason").and_then(|v| v.as_str()) {
        *last_finish_reason = Some(finish_reason.to_string());
        return Some(parse_vertex_finish_chunk(
            candidate,
            finish_reason,
            accumulated_usage,
        ));
    }

    let parts = candidate
        .get("content")
        .and_then(|c| c.get("parts"))
        .and_then(|p| p.as_array())?;

    let events = collect_vertex_part_events(parts);
    if events.is_empty() {
        None
    } else {
        Some(events)
    }
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

fn parse_vertex_finish_chunk(
    candidate: &Value,
    finish_reason: &str,
    accumulated_usage: &TokenUsage,
) -> Vec<StreamEvent> {
    let reason = match finish_reason {
        "STOP" => StopReason::EndTurn,
        "MAX_TOKENS" => StopReason::MaxTokens,
        "SAFETY" => StopReason::EndTurn,
        _ => StopReason::EndTurn,
    };

    let parts = candidate
        .get("content")
        .and_then(|c| c.get("parts"))
        .and_then(|p| p.as_array());

    let mut events = Vec::new();

    if let Some(parts) = parts {
        let has_function_call = parts.iter().any(|p| p.get("functionCall").is_some());
        events.extend(collect_vertex_part_events(parts));

        let stop_reason = if has_function_call {
            StopReason::ToolUse
        } else {
            reason
        };
        events.push(StreamEvent::Stop {
            reason: stop_reason,
            usage: *accumulated_usage,
        });
    } else {
        events.push(StreamEvent::Stop {
            reason,
            usage: *accumulated_usage,
        });
    }

    events
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
