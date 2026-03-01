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
// Response Adapters
// =================================================================================================

/// Trait for adapting Vertex AI streaming responses from different model publishers.
pub trait ResponseAdapter: Send + Sync + std::fmt::Debug {
    /// Parse a raw SSE data chunk into a list of stream events.
    fn parse_chunk(
        &self,
        data: &str,
        accumulated_usage: &mut TokenUsage,
    ) -> Result<Vec<StreamEvent>, String>;

    /// Returns the API method to use (e.g. "streamGenerateContent" or "streamRawPredict").
    fn api_method(&self) -> &'static str;

    /// Build the JSON body for the request.
    fn build_body(&self, request: &CompletionRequest) -> Value;
}

#[derive(Debug, Default)]
pub struct GeminiAdapter;

impl ResponseAdapter for GeminiAdapter {
    fn api_method(&self) -> &'static str {
        "streamGenerateContent"
    }

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

    fn parse_chunk(
        &self,
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
            let has_tool_use = parts.map_or(false, |p| {
                p.iter().any(|x| x.get("functionCall").is_some())
            });
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
}

#[derive(Debug, Default)]
pub struct AnthropicAdapter;

impl ResponseAdapter for AnthropicAdapter {
    fn api_method(&self) -> &'static str {
        "streamRawPredict"
    }

    fn build_body(&self, request: &CompletionRequest) -> Value {
        // Construct Anthropic Messages API body
        // https://docs.anthropic.com/en/api/messages
        let mut body = json!({
            "anthropic_version": "vertex-2023-10-16", // Vertex specific version
            "messages": [],
            "max_tokens": request.max_tokens,
            "stream": true,
        });

        if let Some(system) = &request.system {
            body["system"] = json!(system);
        }

        let mut messages = Vec::new();
        for msg in &request.messages {
            let role = match msg.role {
                LlmRole::User => "user",
                LlmRole::Assistant => "assistant",
            };

            let mut content = Vec::new();
            for block in &msg.content {
                match block {
                    ContentBlock::Text { text } => {
                       content.push(json!({ "type": "text", "text": text }));
                    }
                    ContentBlock::ToolUse { id, name, input } => {
                        content.push(json!({
                            "type": "tool_use",
                            "id": id,
                            "name": name,
                            "input": input
                        }));
                    }
                    ContentBlock::ToolResult { tool_use_id, content: result_content, is_error } => {
                         content.push(json!({
                            "type": "tool_result",
                            "tool_use_id": tool_use_id,
                            "content": result_content,
                            "is_error": is_error
                        }));
                    }
                }
            }
            messages.push(json!({ "role": role, "content": content }));
        }
        body["messages"] = json!(messages);

        if !request.tools.is_empty() {
             let tools: Vec<Value> = request.tools.iter().map(|t| {
                json!({
                    "name": t.name,
                    "description": t.description,
                    "input_schema": t.input_schema
                })
            }).collect();
            body["tools"] = json!(tools);
        }

        if let Some(temp) = request.temperature {
            body["temperature"] = json!(temp);
        }

        body
    }

    fn parse_chunk(
        &self,
        data: &str,
        accumulated_usage: &mut TokenUsage,
    ) -> Result<Vec<StreamEvent>, String> {
        let mut events = Vec::new();
        // Anthropic responses via Vertex might be standard SSE from Anthropic
        // parsed: { type: "...", ... }
        let parsed: Value = match serde_json::from_str(data) {
            Ok(v) => v,
            Err(e) => return Err(format!("failed to parse JSON chunk: {}", e)),
        };

        let type_ = parsed.get("type").and_then(|v| v.as_str()).unwrap_or("");
        match type_ {
            "content_block_delta" => {
                if let Some(delta) = parsed.get("delta") {
                    if let Some(text) = delta.get("text").and_then(|v| v.as_str()) {
                        events.push(StreamEvent::TextDelta {
                            text: text.to_string(),
                        });
                    }
                }
            }
            "message_start" => {
                if let Some(message) = parsed.get("message") {
                    if let Some(usage) = message.get("usage") {
                        if let Some(input) = usage.get("input_tokens").and_then(|v| v.as_u64()) {
                            accumulated_usage.input_tokens = input;
                        }
                    }
                }
            }
            "message_delta" => {
                if let Some(usage) = parsed.get("usage") {
                    if let Some(output) = usage.get("output_tokens").and_then(|v| v.as_u64()) {
                        accumulated_usage.output_tokens = output;
                    }
                }
                if let Some(delta) = parsed.get("delta") {
                    if let Some(stop_reason) = delta.get("stop_reason").and_then(|v| v.as_str()) {
                        let reason = match stop_reason {
                            "end_turn" => StopReason::EndTurn,
                            "max_tokens" => StopReason::MaxTokens,
                            "tool_use" => StopReason::ToolUse,
                            _ => StopReason::EndTurn,
                        };
                        events.push(StreamEvent::Stop {
                            reason,
                            usage: *accumulated_usage,
                        });
                    }
                }
            }
            "error" => {
                let msg = parsed
                    .get("error")
                    .and_then(|e| e.get("message"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown error");
                events.push(StreamEvent::Error {
                    message: msg.to_string(),
                });
            }
            _ => {}
        }

        Ok(events)
    }
}

#[derive(Debug, Default)]
pub struct OpenAiAdapter;

impl ResponseAdapter for OpenAiAdapter {
    fn api_method(&self) -> &'static str {
        "streamRawPredict"
    }

    fn build_body(&self, request: &CompletionRequest) -> Value {
        // OpenAI Chat Completions body
        let mut body = json!({
            "model": request.model, // vLLM often ignores this or needs it matching
            "messages": [],
            "stream": true,
            "max_tokens": request.max_tokens,
        });

        let mut messages = Vec::new();
        if let Some(system) = &request.system {
             messages.push(json!({ "role": "system", "content": system }));
        }

        for msg in &request.messages {
             let role = match msg.role {
                LlmRole::User => "user",
                LlmRole::Assistant => "assistant",
            };
            // OpenAI content is usually string, but can be array for multimodal.
            // Simplified handling here:
            // Combine text blocks.
            // Tool calls are separate field in OpenAI message?
            // Yes, "tool_calls".

            let mut text_parts = Vec::new();
            let mut tool_calls = Vec::new();
            let mut tool_result: Option<Value> = None;

            for block in &msg.content {
                match block {
                    ContentBlock::Text { text } => text_parts.push(text.clone()),
                    ContentBlock::ToolUse { id, name, input } => {
                        tool_calls.push(json!({
                            "id": id,
                            "type": "function",
                            "function": {
                                "name": name,
                                "arguments": input.to_string() // OpenAI expects string for args
                            }
                        }));
                    }
                    ContentBlock::ToolResult { tool_use_id, content, .. } => {
                        // Tool results are separate messages in OpenAI with role "tool"
                        tool_result = Some(json!({
                            "role": "tool",
                            "tool_call_id": tool_use_id,
                            "content": content
                        }));
                    }
                }
            }

            if let Some(tr) = tool_result {
                 messages.push(tr);
            } else {
                 let content_str = text_parts.join("\n");
                 let mut msg_obj = json!({ "role": role, "content": content_str });
                 if !tool_calls.is_empty() {
                     msg_obj["tool_calls"] = json!(tool_calls);
                 }
                 messages.push(msg_obj);
            }
        }
        body["messages"] = json!(messages);

        if !request.tools.is_empty() {
             let tools: Vec<Value> = request.tools.iter().map(|t| {
                json!({
                    "type": "function",
                    "function": {
                        "name": t.name,
                        "description": t.description,
                        "parameters": t.input_schema
                    }
                })
            }).collect();
            body["tools"] = json!(tools);
        }

        if let Some(temp) = request.temperature {
            body["temperature"] = json!(temp);
        }

        if let Some(_extra) = &request.extra {
            // merge extra params?
        }

        body
    }

    fn parse_chunk(
        &self,
        data: &str,
        accumulated_usage: &mut TokenUsage,
    ) -> Result<Vec<StreamEvent>, String> {
        let mut events = Vec::new();
        if data.trim() == "[DONE]" {
            return Ok(events);
        }

        let parsed: Value = match serde_json::from_str(data) {
            Ok(v) => v,
            Err(e) => return Err(format!("failed to parse JSON chunk: {}", e)),
        };

        if let Some(choices) = parsed.get("choices").and_then(|v| v.as_array()) {
            if let Some(choice) = choices.first() {
                if let Some(delta) = choice.get("delta") {
                    if let Some(content) = delta.get("content").and_then(|v| v.as_str()) {
                        if !content.is_empty() {
                            events.push(StreamEvent::TextDelta {
                                text: content.to_string(),
                            });
                        }
                    }
                }

                if let Some(finish_reason) = choice.get("finish_reason").and_then(|v| v.as_str()) {
                    let reason = match finish_reason {
                        "stop" => StopReason::EndTurn,
                        "length" => StopReason::MaxTokens,
                        "tool_calls" => StopReason::ToolUse,
                        _ => StopReason::EndTurn,
                    };
                    events.push(StreamEvent::Stop {
                        reason,
                        usage: *accumulated_usage,
                    });
                }
            }
        }

        // Check usage in the chunk (OpenAI stream_options: {include_usage: true})
        if let Some(usage) = parsed.get("usage") {
            if let Some(prompt) = usage.get("prompt_tokens").and_then(|v| v.as_u64()) {
                accumulated_usage.input_tokens = prompt;
            }
             if let Some(completion) = usage.get("completion_tokens").and_then(|v| v.as_u64()) {
                accumulated_usage.output_tokens = completion;
            }
        }

        Ok(events)
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
    pub fn new(project_id: String, location: String, default_model: Option<String>) -> Self {
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
        let token_manager: Arc<dyn TokenProvider> = if std::env::var("UseGCloudCli").is_ok() {
            Arc::new(GCloudCliProvider)
        } else {
            // Default to MetadataProvider, fallback to GCloudCliProvider if it fails?
            // For now, let's implement a FallbackTokenProvider that tries both.
            Arc::new(FallbackTokenProvider::new())
        };

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
            default_model,
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

    /// Resolves the API endpoint, publisher, model ID, and storage adapter based on the model name.
    ///
    /// Rules:
    /// - `vertex/gemini-1.5-pro` -> Google, gemini-1.5-pro, GeminiAdapter
    /// - `vertex/anthropic/claude-3-opus` -> Anthropic, claude-3-opus, AnthropicAdapter
    /// - `vertex/meta/llama3-405b` -> Meta, llama3-405b, OpenAiAdapter
    /// - `vertex` (generic) -> `default_model` -> Resolve recursively
    fn resolve_request_config(
        &self,
        model_name: &str,
    ) -> (Box<dyn ResponseAdapter>, String) {
        let clean_model = strip_vertex_prefix(model_name);

        // Handle generic fallback
        let effective_model = if clean_model.is_empty() || clean_model == "default" {
             if let Some(ref default) = self.default_model {
                 // Use the default model, but strip any prefix it might have to avoid recursion if simple prefix stripping isn't enough?
                 // Ideally default_model is stored clean or we recurse?
                 // Let's assume default_model is the full ID like "gemini-1.5-pro" or "vertex/gemini-1.5-pro".
                 strip_vertex_prefix(default)
             } else {
                 // Fallback if no default configured?
                 "gemini-1.5-flash-001"
             }
        } else {
            clean_model
        };

        // ... rest of logic uses effective_model

        let (publisher, model_id, adapter): (&str, &str, Box<dyn ResponseAdapter>) =
            if effective_model.starts_with("anthropic/") {
                (
                    "anthropic",
                    effective_model.strip_prefix("anthropic/").unwrap_or(effective_model),
                    Box::new(AnthropicAdapter),
                )
            } else if effective_model.starts_with("meta/") {
                (
                    "meta",
                    effective_model.strip_prefix("meta/").unwrap_or(effective_model),
                    Box::new(OpenAiAdapter),
                )
            } else if effective_model.starts_with("google/") {
                (
                    "google",
                    effective_model.strip_prefix("google/").unwrap_or(effective_model),
                    Box::new(GeminiAdapter),
                )
            } else if effective_model.starts_with("gemini-") {
                // Determine if it's gemini (google)
                 ("google", effective_model, Box::new(GeminiAdapter))
            } else {
                // Default to Google/Gemini for unknown, or maybe OpenAI if likely 3rd party?
                // Let's default to Google for now as it's "Vertex AI".
                 ("google", effective_model, Box::new(GeminiAdapter))
            };

        let method = adapter.api_method();

        // Global endpoints for Gemini 3 and Experimental
        // These models are automatically routed to the global endpoint `aiplatform.googleapis.com`
        // unless overridden.
        if model_id.contains("gemini-3") {
             let url = format!(
                "https://aiplatform.googleapis.com/v1beta1/projects/{}/locations/{}/publishers/{}/models/{}:{}?alt=sse",
                self.project_id, "global", publisher, model_id, method
            );
            return (adapter, url);
        }

        let url = format!(
            "https://{}-aiplatform.googleapis.com/v1beta1/projects/{}/locations/{}/publishers/{}/models/{}:{}?alt=sse",
            self.location, self.project_id, self.location, publisher, model_id, method
        );
        (adapter, url)
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
        let (adapter, url) = self.resolve_request_config(&request.model);
        let body = adapter.build_body(&request);

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
            if let Err(e) = process_vertex_sse_stream(stream, &tx, &cancel, adapter.as_ref()).await {
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
    adapter: &dyn ResponseAdapter,
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
                match adapter.parse_chunk(data, &mut accumulated_usage) {
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

/// List available models from Vertex AI publishers.
pub async fn list_models(
    project_id: &str,
    location: &str,
    token: &str,
) -> Result<Vec<String>, AgentError> {
    let client = reqwest::Client::new();
    let publishers = ["google", "anthropic", "meta"];
    let mut all_models = Vec::new();

    for publisher in publishers {
        let url = format!(
            "https://{}-aiplatform.googleapis.com/v1beta1/projects/{}/locations/{}/publishers/{}/models",
            location, project_id, location, publisher
        );

        let response = client
            .get(&url)
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await
            .map_err(|e| AgentError::Provider(format!("failed to list models for {publisher}: {e}")))?;

        if !response.status().is_success() {
             // Log warning but continue?
             // eprintln!("Failed to list models for {publisher}: {}", response.status());
             continue;
        }

        let body: Value = response
            .json()
            .await
            .map_err(|e| AgentError::Provider(format!("failed to parse model list for {publisher}: {e}")))?;

        if let Some(models) = body.get("models").and_then(|v| v.as_array()) {
            for model in models {
                 if let Some(name) = model.get("name").and_then(|v| v.as_str()) {
                     let parts: Vec<&str> = name.split('/').collect();
                     if let Some(model_id) = parts.last() {
                         if publisher == "google" {
                             all_models.push(format!("vertex/{}", model_id));
                         } else {
                             all_models.push(format!("vertex/{}/{}", publisher, model_id));
                         }
                     }
                 }
            }
        }
    }

    Ok(all_models)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_gemini_adapter_parsing() {
        let adapter = GeminiAdapter;
        let mut usage = TokenUsage::default();

        // chunk with text
        let data = json!({
            "candidates": [{
                "content": {
                    "parts": [{ "text": "Hello" }]
                }
            }]
        }).to_string();

        let events = adapter.parse_chunk(&data, &mut usage).unwrap();
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
        }).to_string();
         let events = adapter.parse_chunk(&data, &mut usage).unwrap();
         // Should have Stop event
         assert!(events.iter().any(|e| matches!(e, StreamEvent::Stop { .. })));
         assert_eq!(usage.input_tokens, 10);
         assert_eq!(usage.output_tokens, 20);
    }

    #[test]
    fn test_anthropic_adapter_parsing() {
        let adapter = AnthropicAdapter;
        let mut usage = TokenUsage::default();

        // content block delta
        let data = json!({
            "type": "content_block_delta",
            "index": 0,
            "delta": { "type": "text_delta", "text": "Hello" }
        }).to_string();

        let events = adapter.parse_chunk(&data, &mut usage).unwrap();
        assert_eq!(events.len(), 1);
        match &events[0] {
            StreamEvent::TextDelta { text } => assert_eq!(text, "Hello"),
            _ => panic!("Expected TextDelta"),
        }

        // message delta with usage
        let data = json!({
            "type": "message_delta",
            "delta": { "stop_reason": "end_turn", "stop_sequence": null },
            "usage": { "output_tokens": 15 }
        }).to_string();

        let events = adapter.parse_chunk(&data, &mut usage).unwrap();
        assert!(events.iter().any(|e| matches!(e, StreamEvent::Stop { .. })));
        assert_eq!(usage.output_tokens, 15);
    }
}

