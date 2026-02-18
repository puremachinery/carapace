//! Google Cloud Vertex AI provider.
//!
//! Streams completions from Vertex AI's `/predict` endpoint using Server-Sent Events (SSE).
//! Vertex AI uses a different authentication method than the standard Gemini API - it uses
//! Google Cloud OAuth2 with service account credentials.
//!
//! Endpoint format:
//!   https://{region}-aiplatform.googleapis.com/v1/projects/{project}/locations/{region}/publishers/google/models/{model}:streamPredict

use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use futures_util::StreamExt;
use serde_json::{json, Value};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::agent::provider::*;
use crate::agent::AgentError;

/// Google Cloud Vertex AI provider.
#[derive(Debug)]
pub struct VertexProvider {
    client: reqwest::Client,
    project_id: String,
    region: String,
    access_token: Option<String>,
    base_url: String,
}

impl VertexProvider {
    /// Create a new Vertex AI provider.
    ///
    /// - `project_id`: GCP project ID
    /// - `region`: GCP region (e.g., "us-central1")
    /// - `access_token`: OAuth2 access token (can be obtained from service account or workload identity)
    pub fn new(
        project_id: String,
        region: String,
        access_token: String,
    ) -> Result<Self, AgentError> {
        if project_id.trim().is_empty() {
            return Err(AgentError::Provider(
                "GCP project ID must not be empty".to_string(),
            ));
        }
        if region.trim().is_empty() {
            return Err(AgentError::Provider(
                "GCP region must not be empty".to_string(),
            ));
        }
        if access_token.trim().is_empty() {
            return Err(AgentError::InvalidApiKey(
                "Access token must not be empty".to_string(),
            ));
        }

        let client = reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(10))
            .timeout(std::time::Duration::from_secs(300))
            .build()
            .map_err(|e| AgentError::Provider(format!("failed to build HTTP client: {e}")))?;

        let base_url = format!(
            "https://{}-aiplatform.googleapis.com",
            region.trim()
        );

        Ok(Self {
            client,
            project_id: project_id.trim().to_string(),
            region: region.trim().to_string(),
            access_token: Some(access_token.trim().to_string()),
            base_url,
        })
    }

    /// Build the JSON body for the Vertex AI streaming predict API.
    fn build_body(&self, request: &CompletionRequest) -> Value {
        // Convert system to Vertex AI's systemInstruction format
        let system_instruction = if let Some(ref system) = request.system {
            json!({
                "role": "system",
                "parts": [{ "text": system }]
            })
        } else {
            json!(null)
        };

        // Convert messages to Vertex AI contents format
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
                        // For tool results, find the tool name
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

        // Tools (function declarations)
        let tools = if !request.tools.is_empty() {
            let declarations: Vec<Value> = request
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
            json!([{
                "functionDeclarations": declarations,
            }])
        } else {
            json!([])
        };

        // Generation config
        let mut generation_config = json!({
            "maxOutputTokens": request.max_tokens,
        });
        if let Some(temp) = request.temperature {
            generation_config["temperature"] = json!(temp);
        }

        json!({
            "systemInstruction": system_instruction,
            "contents": contents,
            "tools": tools,
            "generationConfig": generation_config,
        })
    }

    /// Returns the configured region.
    pub fn region(&self) -> &str {
        &self.region
    }

    /// Refresh the access token (for long-running operations).
    pub fn with_access_token(mut self, token: String) -> Self {
        if !token.trim().is_empty() {
            self.access_token = Some(token.trim().to_string());
        }
        self
    }
}

/// Find the tool name that corresponds to a ToolResult block.
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

        // Strip any prefix to get the bare model name
        let model_name = strip_vertex_prefix(&request.model);
        let body = self.build_body(&request);

        // Vertex AI endpoint format:
        // /v1/projects/{project}/locations/{region}/publishers/google/models/{model}:streamPredict
        let url = format!(
            "{}/v1/projects/{}/locations/{}/publishers/google/models/{}:streamPredict",
            self.base_url, self.project_id, self.region, model_name
        );

        let access_token = self.access_token.as_ref().ok_or_else(|| {
            AgentError::Provider("No access token configured".to_string())
        })?;

        let response = tokio::select! {
            _ = cancel_token.cancelled() => {
                return Err(AgentError::Cancelled);
            }
            response = self
                .client
                .post(&url)
                .header("Authorization", format!("Bearer {}", access_token))
                .header("Content-Type", "application/json")
                .header("Accept", "text/event-stream")
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
                "Vertex AI API returned {status}: {body}"
            )));
        }

        let (tx, rx) = mpsc::channel(64);

        // Spawn a task to read the SSE stream and forward events
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

/// Maximum SSE line buffer size (1 MB).
const MAX_SSE_BUFFER_BYTES: usize = 1_048_576;

/// Process a Vertex AI SSE byte stream into StreamEvents.
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
        let chunk = chunk.map_err(|e| format!("stream read error: {}", e))?;
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
                if let Some(events) = parse_vertex_sse_data(data, &mut accumulated_usage, &mut last_finish_reason) {
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

    // Emit stop if we haven't already
    let reason = match last_finish_reason.as_deref() {
        Some("MAX_TOKENS") => StopReason::MaxTokens,
        Some("STOP") => StopReason::EndTurn,
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

/// Parse a single SSE data payload from Vertex AI's streaming format.
fn parse_vertex_sse_data(
    data: &str,
    accumulated_usage: &mut TokenUsage,
    last_finish_reason: &mut Option<String>,
) -> Option<Vec<StreamEvent>> {
    // Vertex AI sends data as base64-encoded JSON
    let decoded = match BASE64.decode(data.trim()) {
        Ok(bytes) => bytes,
        Err(_) => {
            // Try parsing as plain JSON if base64 fails
            return parse_vertex_json_data(data, accumulated_usage, last_finish_reason);
        }
    };

    let json_str = match String::from_utf8(decoded) {
        Ok(s) => s,
        Err(_) => return None,
    };

    parse_vertex_json_data(&json_str, accumulated_usage, last_finish_reason)
}

fn parse_vertex_json_data(
    data: &str,
    accumulated_usage: &mut TokenUsage,
    last_finish_reason: &mut Option<String>,
) -> Option<Vec<StreamEvent>> {
    let parsed: Value = serde_json::from_str(data).ok()?;

    // Check for error response
    if let Some(error) = parsed.get("error") {
        let message = error
            .get("message")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown API error")
            .to_string();
        return Some(vec![StreamEvent::Error { message }]);
    }

    // Extract usage metadata if present
    if let Some(usage_metadata) = parsed.get("usageMetadata") {
        if let Some(prompt_tokens) = usage_metadata
            .get("promptTokenCount")
            .and_then(|v| v.as_u64())
        {
            accumulated_usage.input_tokens = prompt_tokens;
        }
        if let Some(candidates_tokens) = usage_metadata
            .get("candidatesTokenCount")
            .and_then(|v| v.as_u64())
        {
            accumulated_usage.output_tokens = candidates_tokens;
        }
    }

    // Process candidates
    let candidates = parsed.get("candidates")?.as_array()?;
    if candidates.is_empty() {
        return None;
    }

    let candidate = &candidates[0];

    // Check for finish reason
    if let Some(finish_reason) = candidate.get("finishReason").and_then(|v| v.as_str()) {
        *last_finish_reason = Some(finish_reason.to_string());
        return Some(parse_vertex_finish_chunk(candidate, finish_reason, accumulated_usage));
    }

    // No finish reason - process content parts
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
            events.push(StreamEvent::ToolUse { id, name, input: args });
        }
    }
    events
}

/// Determine whether a model identifier should route to the Vertex AI provider.
pub fn is_vertex_model(model: &str) -> bool {
    let lower = model.to_lowercase();
    lower.starts_with("vertex:")
}

/// Strip the `vertex:` prefix from a model identifier.
pub fn strip_vertex_prefix(model: &str) -> &str {
    if let Some(rest) = model.strip_prefix("vertex:") {
        rest
    } else if let Some(rest) = model.strip_prefix("Vertex:") {
        rest
    } else {
        model
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== Provider construction tests ====================

    #[test]
    fn test_new_rejects_empty_project_id() {
        let result = VertexProvider::new(
            "".to_string(),
            "us-central1".to_string(),
            "access-token".to_string(),
        );
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("project"), "error should mention project: {err}");
    }

    #[test]
    fn test_new_rejects_empty_region() {
        let result = VertexProvider::new(
            "my-project".to_string(),
            "".to_string(),
            "access-token".to_string(),
        );
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("region"), "error should mention region: {err}");
    }

    #[test]
    fn test_new_rejects_empty_access_token() {
        let result = VertexProvider::new(
            "my-project".to_string(),
            "us-central1".to_string(),
            "".to_string(),
        );
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("token"), "error should mention token: {err}");
    }

    #[test]
    fn test_new_accepts_valid_params() {
        let result = VertexProvider::new(
            "my-project".to_string(),
            "us-central1".to_string(),
            "access-token".to_string(),
        );
        assert!(result.is_ok());
        let provider = result.unwrap();
        assert_eq!(provider.region(), "us-central1");
    }

    #[test]
    fn test_with_access_token() {
        let provider = VertexProvider::new(
            "my-project".to_string(),
            "us-central1".to_string(),
            "token1".to_string(),
        )
        .unwrap()
        .with_access_token("token2".to_string());
        assert!(provider.access_token.is_some());
    }

    // ==================== Model detection tests ====================

    #[test]
    fn test_is_vertex_model() {
        assert!(is_vertex_model("vertex:gemini-2.0-flash"));
        assert!(is_vertex_model("vertex:gemini-1.5-pro"));
        assert!(is_vertex_model("Vertex:gemini-2.0-flash"));

        assert!(!is_vertex_model("gemini-2.0-flash"));
        assert!(!is_vertex_model("gpt-4o"));
    }

    #[test]
    fn test_strip_vertex_prefix() {
        assert_eq!(strip_vertex_prefix("vertex:gemini-2.0-flash"), "gemini-2.0-flash");
        assert_eq!(strip_vertex_prefix("Vertex:gemini-2.0-flash"), "gemini-2.0-flash");
        assert_eq!(strip_vertex_prefix("gemini-2.0-flash"), "gemini-2.0-flash");
    }

    // ==================== build_body tests ====================

    #[test]
    fn test_build_body_basic() {
        let provider = VertexProvider::new(
            "my-project".to_string(),
            "us-central1".to_string(),
            "access-token".to_string(),
        ).unwrap();
        let request = CompletionRequest {
            model: "gemini-2.0-flash".to_string(),
            messages: vec![LlmMessage {
                role: LlmRole::User,
                content: vec![ContentBlock::Text {
                    text: "Hello".to_string(),
                }],
            }],
            system: Some("You are helpful.".to_string()),
            tools: vec![],
            max_tokens: 1024,
            temperature: Some(0.7),
            extra: None,
        };
        let body = provider.build_body(&request);

        // System instruction
        assert_eq!(
            body["systemInstruction"]["parts"][0]["text"],
            "You are helpful."
        );

        // Contents
        let contents = body["contents"].as_array().unwrap();
        assert_eq!(contents.len(), 1);
        assert_eq!(contents[0]["role"], "user");
        assert_eq!(contents[0]["parts"][0]["text"], "Hello");

        // Generation config
        assert_eq!(body["generationConfig"]["maxOutputTokens"], 1024);
        assert_eq!(body["generationConfig"]["temperature"], 0.7);
    }

    #[test]
    fn test_build_body_with_tools() {
        let provider = VertexProvider::new(
            "my-project".to_string(),
            "us-central1".to_string(),
            "access-token".to_string(),
        ).unwrap();
        let request = CompletionRequest {
            model: "gemini-2.0-flash".to_string(),
            messages: vec![],
            system: None,
            tools: vec![ToolDefinition {
                name: "get_weather".to_string(),
                description: "Get weather".to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "city": { "type": "string" }
                    }
                }),
            }],
            max_tokens: 4096,
            temperature: None,
            extra: None,
        };
        let body = provider.build_body(&request);

        assert!(body["tools"].is_array());
        let tools = body["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 1);
        let func_decls = tools[0]["functionDeclarations"].as_array().unwrap();
        assert_eq!(func_decls[0]["name"], "get_weather");
    }
}
