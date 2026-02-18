//! AWS Bedrock Converse API provider.
//!
//! Sends completion requests to the AWS Bedrock Converse endpoint and returns
//! results through the same streaming channel interface used by other providers.
//! Uses the streaming Converse API and decodes AWS event-stream framing into
//! incremental StreamEvent messages to match the provider trait.

use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use futures_util::StreamExt;
use hmac::{Hmac, Mac};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::agent::provider::*;
use crate::agent::AgentError;

type HmacSha256 = Hmac<Sha256>;

/// AWS Bedrock Converse API provider.
pub struct BedrockProvider {
    client: reqwest::Client,
    region: String,
    access_key_id: String,
    secret_access_key: String,
    session_token: Option<String>,
    base_url: String,
}

impl std::fmt::Debug for BedrockProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BedrockProvider")
            .field("region", &self.region)
            .field("base_url", &self.base_url)
            .field("access_key_id", &"***")
            .field("session_token", &self.session_token.is_some())
            .finish()
    }
}

impl BedrockProvider {
    /// Create a new Bedrock provider for the given AWS region and credentials.
    ///
    /// Validates that region, access key ID, and secret access key are non-empty.
    pub fn new(
        region: String,
        access_key_id: String,
        secret_access_key: String,
    ) -> Result<Self, AgentError> {
        if region.trim().is_empty() {
            return Err(AgentError::Provider(
                "AWS region must not be empty".to_string(),
            ));
        }
        if access_key_id.trim().is_empty() {
            return Err(AgentError::Provider(
                "AWS access key ID must not be empty".to_string(),
            ));
        }
        if secret_access_key.trim().is_empty() {
            return Err(AgentError::Provider(
                "AWS secret access key must not be empty".to_string(),
            ));
        }
        let client = reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(10))
            .timeout(std::time::Duration::from_secs(300))
            .build()
            .map_err(|e| AgentError::Provider(format!("failed to build HTTP client: {e}")))?;
        let base_url = format!("https://bedrock-runtime.{region}.amazonaws.com");
        Ok(Self {
            client,
            region,
            access_key_id,
            secret_access_key,
            session_token: None,
            base_url,
        })
    }

    /// Attach an optional AWS session token (for temporary credentials / STS).
    pub fn with_session_token(mut self, token: String) -> Self {
        if token.trim().is_empty() {
            self.session_token = None;
        } else {
            self.session_token = Some(token);
        }
        self
    }

    /// Build the JSON request body for the Bedrock Converse API.
    fn build_body(&self, request: &CompletionRequest) -> Value {
        let mut body = json!({});

        // System prompt
        if let Some(ref system) = request.system {
            body["system"] = json!([{"text": system}]);
        }

        // Messages
        let messages: Vec<Value> = request
            .messages
            .iter()
            .map(|msg| {
                let role = match msg.role {
                    LlmRole::User => "user",
                    LlmRole::Assistant => "assistant",
                };
                let content: Vec<Value> = msg
                    .content
                    .iter()
                    .map(|block| match block {
                        ContentBlock::Text { text } => json!({"text": text}),
                        ContentBlock::ToolUse { id, name, input } => json!({
                            "toolUse": {
                                "toolUseId": id,
                                "name": name,
                                "input": input,
                            }
                        }),
                        ContentBlock::ToolResult {
                            tool_use_id,
                            content,
                            is_error,
                        } => json!({
                            "toolResult": {
                                "toolUseId": tool_use_id,
                                "content": [{"text": content}],
                                "status": if *is_error { "error" } else { "success" },
                            }
                        }),
                    })
                    .collect();
                json!({
                    "role": role,
                    "content": content,
                })
            })
            .collect();
        body["messages"] = json!(messages);

        // Inference configuration
        let mut inference_config = json!({
            "maxTokens": request.max_tokens,
        });
        if let Some(temp) = request.temperature {
            inference_config["temperature"] = json!(temp);
        }
        body["inferenceConfig"] = inference_config;

        // Tool configuration
        if !request.tools.is_empty() {
            let tools: Vec<Value> = request
                .tools
                .iter()
                .map(|t| {
                    json!({
                        "toolSpec": {
                            "name": t.name,
                            "description": t.description,
                            "inputSchema": {
                                "json": t.input_schema,
                            }
                        }
                    })
                })
                .collect();
            body["toolConfig"] = json!({"tools": tools});
        }

        body
    }

    /// Sign the request using AWS Signature Version 4.
    fn sign_request(
        &self,
        method: &str,
        uri_path: &str,
        body: &[u8],
        datetime: &str,
    ) -> Vec<(String, String)> {
        let date = &datetime[..8]; // YYYYMMDD
        let host = format!("bedrock-runtime.{}.amazonaws.com", self.region);
        let payload_hash = hex_sha256(body);

        // Determine signed headers and canonical headers
        let mut signed_header_names = vec!["host", "x-amz-content-sha256", "x-amz-date"];
        let mut canonical_headers = format!(
            "host:{}\nx-amz-content-sha256:{}\nx-amz-date:{}\n",
            host, payload_hash, datetime
        );

        if self.session_token.is_some() {
            signed_header_names.push("x-amz-security-token");
        }
        signed_header_names.sort();

        // Rebuild canonical headers in sorted order
        canonical_headers = String::new();
        for name in &signed_header_names {
            let value = match *name {
                "host" => host.clone(),
                "x-amz-content-sha256" => payload_hash.clone(),
                "x-amz-date" => datetime.to_string(),
                "x-amz-security-token" => self.session_token.as_deref().unwrap_or("").to_string(),
                _ => String::new(),
            };
            canonical_headers.push_str(&format!("{}:{}\n", name, value));
        }

        let signed_headers = signed_header_names.join(";");

        // Canonical request
        let canonical_request = format!(
            "{}\n{}\n\n{}\n{}\n{}",
            method, uri_path, canonical_headers, signed_headers, payload_hash
        );

        let credential_scope = format!("{}/{}/bedrock/aws4_request", date, self.region);

        // String to sign
        let string_to_sign = format!(
            "AWS4-HMAC-SHA256\n{}\n{}\n{}",
            datetime,
            credential_scope,
            hex_sha256(canonical_request.as_bytes())
        );

        // Signing key
        let signing_key = derive_signing_key(&self.secret_access_key, date, &self.region);

        // Signature
        let signature = hex::encode(hmac_sha256(&signing_key, string_to_sign.as_bytes()));

        // Authorization header
        let authorization = format!(
            "AWS4-HMAC-SHA256 Credential={}/{}, SignedHeaders={}, Signature={}",
            self.access_key_id, credential_scope, signed_headers, signature
        );

        let mut headers = vec![
            ("host".to_string(), host),
            ("x-amz-date".to_string(), datetime.to_string()),
            ("x-amz-content-sha256".to_string(), payload_hash),
            ("authorization".to_string(), authorization),
        ];

        if let Some(ref token) = self.session_token {
            headers.push(("x-amz-security-token".to_string(), token.clone()));
        }

        headers
    }
}

#[async_trait]
impl LlmProvider for BedrockProvider {
    async fn complete(
        &self,
        request: CompletionRequest,
        cancel_token: CancellationToken,
    ) -> Result<mpsc::Receiver<StreamEvent>, AgentError> {
        if cancel_token.is_cancelled() {
            return Err(AgentError::Cancelled);
        }
        let body_value = self.build_body(&request);
        let body_bytes = serde_json::to_vec(&body_value)
            .map_err(|e| AgentError::Provider(format!("failed to serialize request body: {e}")))?;

        // URL-encode the model ID for the path
        let model_id = &request.model;
        let uri_path = format!(
            "/model/{}/converse-stream",
            percent_encode_path_segment(model_id)
        );
        let url = format!("{}{}", self.base_url, uri_path);

        // Generate timestamp for signing
        let now = chrono::Utc::now();
        let datetime = now.format("%Y%m%dT%H%M%SZ").to_string();

        // Sign the request
        let sig_headers = self.sign_request("POST", &uri_path, &body_bytes, &datetime);

        let mut http_request = self
            .client
            .post(&url)
            .header("content-type", "application/json")
            .header("accept", "application/vnd.amazon.eventstream");

        for (name, value) in &sig_headers {
            http_request = http_request.header(name.as_str(), value.as_str());
        }

        let response = tokio::select! {
            _ = cancel_token.cancelled() => {
                return Err(AgentError::Cancelled);
            }
            response = http_request
                .body(body_bytes)
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
                "Bedrock API returned {status}: {body}"
            )));
        }

        let (tx, rx) = mpsc::channel(64);

        // Parse the streaming response and emit events through the channel.
        let mut stream = response.bytes_stream();
        let cancel_token = cancel_token.clone();
        tokio::spawn(async move {
            let mut buffer = BytesMut::new();
            let mut state = BedrockStreamState::default();

            loop {
                let chunk = tokio::select! {
                    _ = cancel_token.cancelled() => {
                        return;
                    }
                    chunk = stream.next() => chunk,
                };

                match chunk {
                    Some(Ok(bytes)) => {
                        buffer.extend_from_slice(&bytes);
                        loop {
                            match try_decode_event_frame(&mut buffer) {
                                Ok(Some(frame)) => {
                                    if let Err(err) =
                                        handle_bedrock_frame(frame, &mut state, &tx).await
                                    {
                                        let _ = tx.send(StreamEvent::Error { message: err }).await;
                                        return;
                                    }
                                }
                                Ok(None) => break,
                                Err(err) => {
                                    let _ = tx.send(StreamEvent::Error { message: err }).await;
                                    return;
                                }
                            }
                        }
                    }
                    Some(Err(err)) => {
                        let _ = tx
                            .send(StreamEvent::Error {
                                message: format!("Bedrock stream error: {err}"),
                            })
                            .await;
                        return;
                    }
                    None => break,
                }
            }

            if cancel_token.is_cancelled() {
                return;
            }

            if let Err(err) = finalize_bedrock_stream(&state, &tx).await {
                let _ = tx.send(StreamEvent::Error { message: err }).await;
            }
        });

        Ok(rx)
    }
}

struct BedrockEventFrame {
    headers: HashMap<String, String>,
    payload: Bytes,
}

#[derive(Default)]
struct BedrockStreamState {
    pending_tool_uses: HashMap<String, PendingToolUse>,
    pending_tool_uses_by_index: HashMap<u64, String>,
    stop_reason: Option<StopReason>,
    usage: TokenUsage,
    saw_usage: bool,
    saw_message_stop: bool,
}

#[derive(Default)]
struct PendingToolUse {
    name: Option<String>,
    input_value: Option<Value>,
    input_text: String,
    index: Option<u64>,
}

fn try_decode_event_frame(buffer: &mut BytesMut) -> Result<Option<BedrockEventFrame>, String> {
    const PRELUDE_LEN: usize = 12;
    const MESSAGE_CRC_LEN: usize = 4;
    const MAX_FRAME_LEN: usize = 8 * 1024 * 1024;

    if buffer.len() < PRELUDE_LEN {
        return Ok(None);
    }

    let total_len = u32::from_be_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]) as usize;
    let headers_len = u32::from_be_bytes([buffer[4], buffer[5], buffer[6], buffer[7]]) as usize;

    if total_len > MAX_FRAME_LEN {
        return Err("Bedrock event-stream frame exceeds max size".to_string());
    }
    if total_len < PRELUDE_LEN + MESSAGE_CRC_LEN {
        return Err("invalid Bedrock event-stream frame length".to_string());
    }
    if total_len < PRELUDE_LEN + headers_len + MESSAGE_CRC_LEN {
        return Err("invalid Bedrock event-stream header length".to_string());
    }
    if buffer.len() < total_len {
        return Ok(None);
    }

    let frame = buffer.split_to(total_len).freeze();
    let headers_end = PRELUDE_LEN + headers_len;
    let payload_end = total_len - MESSAGE_CRC_LEN;

    if headers_end > payload_end || payload_end > frame.len() {
        return Err("invalid Bedrock event-stream frame bounds".to_string());
    }

    let prelude_crc = u32::from_be_bytes([frame[8], frame[9], frame[10], frame[11]]);
    let computed_prelude_crc = crc32(&frame[0..8]);
    if prelude_crc != computed_prelude_crc {
        return Err("invalid Bedrock event-stream prelude CRC".to_string());
    }

    let message_crc = u32::from_be_bytes([
        frame[payload_end],
        frame[payload_end + 1],
        frame[payload_end + 2],
        frame[payload_end + 3],
    ]);
    let computed_message_crc = crc32(&frame[0..payload_end]);
    if message_crc != computed_message_crc {
        return Err("invalid Bedrock event-stream message CRC".to_string());
    }

    let headers = parse_event_stream_headers(&frame[PRELUDE_LEN..headers_end])?;
    let payload = frame.slice(headers_end..payload_end);

    Ok(Some(BedrockEventFrame { headers, payload }))
}

fn parse_event_stream_headers(headers: &[u8]) -> Result<HashMap<String, String>, String> {
    let mut index = 0;
    let mut result = HashMap::new();

    while index < headers.len() {
        let name_len = headers[index] as usize;
        index += 1;
        if index + name_len > headers.len() {
            return Err("invalid Bedrock event-stream header name length".to_string());
        }
        let name = std::str::from_utf8(&headers[index..index + name_len])
            .map_err(|e| format!("invalid Bedrock header name encoding: {e}"))?
            .to_string();
        index += name_len;
        if index >= headers.len() {
            return Err("invalid Bedrock event-stream header value".to_string());
        }
        let value_type = headers[index];
        index += 1;

        match value_type {
            0 | 1 => {
                // boolean true/false: no payload
            }
            2 => {
                if index + 1 > headers.len() {
                    return Err("invalid Bedrock event-stream header value length".to_string());
                }
                index += 1;
            }
            3 => {
                if index + 2 > headers.len() {
                    return Err("invalid Bedrock event-stream header value length".to_string());
                }
                index += 2;
            }
            4 => {
                if index + 4 > headers.len() {
                    return Err("invalid Bedrock event-stream header value length".to_string());
                }
                index += 4;
            }
            5 => {
                if index + 8 > headers.len() {
                    return Err("invalid Bedrock event-stream header value length".to_string());
                }
                index += 8;
            }
            6 | 7 => {
                if index + 2 > headers.len() {
                    return Err("invalid Bedrock event-stream header length".to_string());
                }
                let len = u16::from_be_bytes([headers[index], headers[index + 1]]) as usize;
                index += 2;
                if index + len > headers.len() {
                    return Err("invalid Bedrock event-stream header value length".to_string());
                }
                if value_type == 7 {
                    if let Ok(value) = std::str::from_utf8(&headers[index..index + len]) {
                        result.insert(name.clone(), value.to_string());
                    }
                }
                index += len;
            }
            8 => {
                if index + 8 > headers.len() {
                    return Err("invalid Bedrock event-stream header value length".to_string());
                }
                index += 8;
            }
            9 => {
                if index + 16 > headers.len() {
                    return Err("invalid Bedrock event-stream header value length".to_string());
                }
                index += 16;
            }
            _ => {
                return Err(format!(
                    "unknown Bedrock event-stream header type: {value_type}"
                ));
            }
        }
    }

    Ok(result)
}

fn header_value(headers: &HashMap<String, String>, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| headers.get(*key).cloned())
}

async fn handle_bedrock_frame(
    frame: BedrockEventFrame,
    state: &mut BedrockStreamState,
    tx: &mpsc::Sender<StreamEvent>,
) -> Result<(), String> {
    let message_type = header_value(&frame.headers, &[":message-type", "message-type"]);
    let event_type = header_value(&frame.headers, &[":event-type", "event-type"]);

    let payload = if frame.payload.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&frame.payload)
            .map_err(|e| format!("failed to parse Bedrock stream payload: {e}"))?
    };

    if matches!(message_type.as_deref(), Some("error") | Some("exception"))
        || matches!(event_type.as_deref(), Some("error") | Some("exception"))
    {
        let message = payload
            .get("message")
            .and_then(|v| v.as_str())
            .or_else(|| payload.get("errorMessage").and_then(|v| v.as_str()))
            .map(|s| s.to_string())
            .unwrap_or_else(|| payload.to_string());
        return Err(format!("Bedrock stream error: {message}"));
    }

    let content_block_index = payload.get("contentBlockIndex").and_then(|v| v.as_u64());

    match event_type.as_deref() {
        Some("contentBlockDelta") => {
            if let Some(text) = payload
                .get("delta")
                .and_then(|d| d.get("text"))
                .and_then(|t| t.as_str())
            {
                if !text.is_empty() {
                    tx.send(StreamEvent::TextDelta {
                        text: text.to_string(),
                    })
                    .await
                    .map_err(|_| "stream receiver dropped".to_string())?;
                }
            }
            if let Some(tool_use) = payload.get("delta").and_then(|d| d.get("toolUse")) {
                handle_tool_use(tool_use, content_block_index, state).await?;
            }
        }
        Some("contentBlockStart") => {
            if let Some(tool_use) = payload.get("start").and_then(|s| s.get("toolUse")) {
                handle_tool_use(tool_use, content_block_index, state).await?;
            } else if let Some(tool_use) = payload.get("toolUse") {
                handle_tool_use(tool_use, content_block_index, state).await?;
            }
        }
        Some("contentBlockStop") => {
            let tool_use_id = payload
                .get("toolUseId")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
                .or_else(|| {
                    content_block_index
                        .and_then(|index| state.pending_tool_uses_by_index.get(&index).cloned())
                });
            if let Some(tool_use_id) = tool_use_id {
                finalize_tool_use(&tool_use_id, state, tx).await?;
            }
        }
        Some("messageStop") => {
            state.saw_message_stop = true;
            if let Some(reason) = payload.get("stopReason").and_then(|v| v.as_str()) {
                state.stop_reason = Some(parse_stop_reason(reason));
            }
            flush_pending_tool_uses(state, tx).await?;
        }
        Some("metadata") => {
            if let Some(usage) = parse_stream_usage(&payload) {
                state.usage = usage;
                state.saw_usage = true;
            }
        }
        _ => {}
    }

    Ok(())
}

async fn handle_tool_use(
    tool_use: &Value,
    content_block_index: Option<u64>,
    state: &mut BedrockStreamState,
) -> Result<(), String> {
    let id = tool_use
        .get("toolUseId")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    if id.is_empty() {
        return Ok(());
    }

    let entry = state.pending_tool_uses.entry(id.clone()).or_default();
    if let Some(index) = content_block_index {
        entry.index = Some(index);
        state.pending_tool_uses_by_index.insert(index, id.clone());
    }
    if let Some(name) = tool_use.get("name").and_then(|v| v.as_str()) {
        entry.name = Some(name.to_string());
    }
    if let Some(input) = tool_use.get("input") {
        if let Some(fragment) = input.as_str() {
            entry.input_text.push_str(fragment);
        } else {
            entry.input_value = Some(input.clone());
        }
    }

    Ok(())
}

async fn finalize_tool_use(
    tool_use_id: &str,
    state: &mut BedrockStreamState,
    tx: &mpsc::Sender<StreamEvent>,
) -> Result<(), String> {
    let pending = match state.pending_tool_uses.remove(tool_use_id) {
        Some(pending) => pending,
        None => return Ok(()),
    };
    if let Some(index) = pending.index {
        state.pending_tool_uses_by_index.remove(&index);
    }

    let name = pending
        .name
        .ok_or_else(|| "Bedrock stream missing tool name".to_string())?;
    let input = if let Some(value) = pending.input_value {
        value
    } else if !pending.input_text.trim().is_empty() {
        serde_json::from_str(&pending.input_text)
            .map_err(|e| format!("Bedrock stream tool input is not valid JSON: {e}"))?
    } else {
        json!({})
    };

    tx.send(StreamEvent::ToolUse {
        id: tool_use_id.to_string(),
        name,
        input,
    })
    .await
    .map_err(|_| "stream receiver dropped".to_string())?;
    Ok(())
}

async fn flush_pending_tool_uses(
    state: &mut BedrockStreamState,
    tx: &mpsc::Sender<StreamEvent>,
) -> Result<(), String> {
    let pending_ids: Vec<String> = state.pending_tool_uses.keys().cloned().collect();
    for tool_use_id in pending_ids {
        finalize_tool_use(&tool_use_id, state, tx).await?;
    }
    Ok(())
}

fn parse_stream_usage(payload: &Value) -> Option<TokenUsage> {
    let usage = payload
        .get("usage")
        .or_else(|| payload.get("usageMetadata"))?;
    let input_tokens = usage
        .get("inputTokens")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let output_tokens = usage
        .get("outputTokens")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    Some(TokenUsage {
        input_tokens,
        output_tokens,
    })
}

async fn finalize_bedrock_stream(
    state: &BedrockStreamState,
    tx: &mpsc::Sender<StreamEvent>,
) -> Result<(), String> {
    if !state.saw_message_stop {
        return Err("Bedrock stream ended without messageStop event".to_string());
    }

    let usage = if state.saw_usage {
        state.usage
    } else {
        TokenUsage::default()
    };
    let reason = state.stop_reason.unwrap_or(StopReason::EndTurn);

    tx.send(StreamEvent::Stop { reason, usage })
        .await
        .map_err(|_| "stream receiver dropped".to_string())?;

    Ok(())
}

fn crc32(data: &[u8]) -> u32 {
    let mut hasher = crc32fast::Hasher::new();
    hasher.update(data);
    hasher.finalize()
}

/// Map Bedrock stop reason strings to our StopReason enum.
fn parse_stop_reason(reason: &str) -> StopReason {
    match reason {
        "end_turn" => StopReason::EndTurn,
        "tool_use" => StopReason::ToolUse,
        "max_tokens" => StopReason::MaxTokens,
        _ => StopReason::EndTurn,
    }
}

/// Determine whether a model identifier should route to the Bedrock provider.
///
/// Matches models with the `bedrock:` or `bedrock/` prefix, as well as native
/// Bedrock model ID patterns like `anthropic.claude-*`, `amazon.titan-*`, and
/// `meta.llama*`.
pub fn is_bedrock_model(model: &str) -> bool {
    let lower = model.to_lowercase();
    lower.starts_with("bedrock:")
        || lower.starts_with("bedrock/")
        || lower.starts_with("anthropic.claude-")
        || lower.starts_with("amazon.titan-")
        || lower.starts_with("meta.llama")
}

/// Strip the `bedrock:` or `bedrock/` prefix from a model identifier.
///
/// Returns the bare model ID suitable for passing to the Bedrock API.
/// If the model doesn't have the prefix, it is returned unchanged.
pub fn strip_bedrock_prefix(model: &str) -> &str {
    if let Some(rest) = model.strip_prefix("bedrock:") {
        rest
    } else if let Some(rest) = model.strip_prefix("bedrock/") {
        rest
    } else if let Some(rest) = model.strip_prefix("Bedrock:") {
        rest
    } else if let Some(rest) = model.strip_prefix("Bedrock/") {
        rest
    } else {
        model
    }
}

// ==================== AWS SigV4 helpers ====================

/// Compute the hex-encoded SHA-256 digest of `data`.
fn hex_sha256(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// Compute HMAC-SHA256 of `data` with the given `key`.
fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC-SHA256 accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

/// Derive the SigV4 signing key:
///   kDate    = HMAC("AWS4" + secret, date)
///   kRegion  = HMAC(kDate, region)
///   kService = HMAC(kRegion, "bedrock")
///   kSigning = HMAC(kService, "aws4_request")
fn derive_signing_key(secret_access_key: &str, date: &str, region: &str) -> Vec<u8> {
    let k_secret = format!("AWS4{}", secret_access_key);
    let k_date = hmac_sha256(k_secret.as_bytes(), date.as_bytes());
    let k_region = hmac_sha256(&k_date, region.as_bytes());
    let k_service = hmac_sha256(&k_region, b"bedrock");
    hmac_sha256(&k_service, b"aws4_request")
}

/// Percent-encode a URI path segment (for model IDs containing dots, etc.).
fn percent_encode_path_segment(s: &str) -> String {
    let mut result = String::with_capacity(s.len() * 2);
    for byte in s.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                result.push(byte as char)
            }
            _ => {
                result.push('%');
                result.push_str(&format!("{:02X}", byte));
            }
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn random_hex(bytes_len: usize) -> String {
        let mut bytes = vec![0u8; bytes_len];
        getrandom::fill(&mut bytes).expect("random test bytes");
        hex::encode(bytes)
    }

    fn test_access_key() -> String {
        format!("TESTACCESS{}", random_hex(8).to_uppercase())
    }

    fn test_secret_key() -> String {
        format!("test-secret-{}", random_hex(16))
    }

    fn test_provider(region: &str) -> BedrockProvider {
        BedrockProvider::new(region.to_string(), test_access_key(), test_secret_key()).unwrap()
    }

    // ==================== Provider construction tests ====================

    #[test]
    fn test_new_rejects_empty_region() {
        let result = BedrockProvider::new("".to_string(), test_access_key(), test_secret_key());
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("region"), "error should mention region: {err}");
    }

    #[test]
    fn test_new_rejects_empty_access_key() {
        let result =
            BedrockProvider::new("us-east-1".to_string(), "".to_string(), test_secret_key());
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("access key"),
            "error should mention access key: {err}"
        );
    }

    #[test]
    fn test_new_rejects_empty_secret_key() {
        let result =
            BedrockProvider::new("us-east-1".to_string(), test_access_key(), "".to_string());
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("secret access key"),
            "error should mention secret access key: {err}"
        );
    }

    #[test]
    fn test_new_accepts_valid_credentials() {
        let access_key = test_access_key();
        let secret_key = test_secret_key();
        let result = BedrockProvider::new("us-east-1".to_string(), access_key, secret_key);
        assert!(result.is_ok());
        let provider = result.unwrap();
        assert_eq!(provider.region, "us-east-1");
        assert_eq!(
            provider.base_url,
            "https://bedrock-runtime.us-east-1.amazonaws.com"
        );
    }

    #[test]
    fn test_with_session_token() {
        let provider = test_provider("us-west-2").with_session_token("FwoGZX...".to_string());
        assert!(provider.session_token.is_some());
        assert_eq!(provider.session_token.as_deref(), Some("FwoGZX..."));
    }

    #[test]
    fn test_with_empty_session_token_clears() {
        let provider = test_provider("us-west-2").with_session_token("".to_string());
        assert!(provider.session_token.is_none());
    }

    #[test]
    fn test_base_url_derived_from_region() {
        let provider = test_provider("eu-west-1");
        assert_eq!(
            provider.base_url,
            "https://bedrock-runtime.eu-west-1.amazonaws.com"
        );
    }

    // ==================== Request body building tests ====================

    #[test]
    fn test_build_body_basic() {
        let provider = test_provider("us-east-1");
        let request = CompletionRequest {
            model: "anthropic.claude-3-sonnet-20240229-v1:0".to_string(),
            messages: vec![LlmMessage {
                role: LlmRole::User,
                content: vec![ContentBlock::Text {
                    text: "Hello".to_string(),
                }],
            }],
            system: None,
            tools: vec![],
            max_tokens: 1024,
            temperature: Some(0.7),
            extra: None,
        };
        let body = provider.build_body(&request);

        // Messages
        let messages = body["messages"].as_array().unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0]["role"], "user");
        assert_eq!(messages[0]["content"][0]["text"], "Hello");

        // Inference config
        assert_eq!(body["inferenceConfig"]["maxTokens"], 1024);
        assert_eq!(body["inferenceConfig"]["temperature"], 0.7);

        // No system, no tools
        assert!(body.get("system").is_none());
        assert!(body.get("toolConfig").is_none());
    }

    #[test]
    fn test_build_body_with_system() {
        let provider = test_provider("us-east-1");
        let request = CompletionRequest {
            model: "anthropic.claude-3-sonnet-20240229-v1:0".to_string(),
            messages: vec![],
            system: Some("You are helpful.".to_string()),
            tools: vec![],
            max_tokens: 1024,
            temperature: None,
            extra: None,
        };
        let body = provider.build_body(&request);

        let system = body["system"].as_array().unwrap();
        assert_eq!(system.len(), 1);
        assert_eq!(system[0]["text"], "You are helpful.");

        // No temperature when None
        assert!(body["inferenceConfig"].get("temperature").is_none());
    }

    #[test]
    fn test_build_body_with_tools() {
        let provider = test_provider("us-east-1");
        let request = CompletionRequest {
            model: "anthropic.claude-3-sonnet-20240229-v1:0".to_string(),
            messages: vec![],
            system: None,
            tools: vec![ToolDefinition {
                name: "get_weather".to_string(),
                description: "Get weather for a city".to_string(),
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

        let tools = body["toolConfig"]["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0]["toolSpec"]["name"], "get_weather");
        assert_eq!(
            tools[0]["toolSpec"]["description"],
            "Get weather for a city"
        );
        assert!(tools[0]["toolSpec"]["inputSchema"]["json"].is_object());
    }

    #[test]
    fn test_build_body_with_tool_results() {
        let provider = test_provider("us-east-1");
        let request = CompletionRequest {
            model: "anthropic.claude-3-sonnet-20240229-v1:0".to_string(),
            messages: vec![LlmMessage {
                role: LlmRole::User,
                content: vec![ContentBlock::ToolResult {
                    tool_use_id: "toolu_123".to_string(),
                    content: "72F and sunny".to_string(),
                    is_error: false,
                }],
            }],
            system: None,
            tools: vec![],
            max_tokens: 1024,
            temperature: None,
            extra: None,
        };
        let body = provider.build_body(&request);

        let messages = body["messages"].as_array().unwrap();
        assert_eq!(messages.len(), 1);
        let content = &messages[0]["content"][0];
        assert_eq!(content["toolResult"]["toolUseId"], "toolu_123");
        assert_eq!(content["toolResult"]["content"][0]["text"], "72F and sunny");
        assert_eq!(content["toolResult"]["status"], "success");
    }

    #[test]
    fn test_build_body_with_error_tool_result() {
        let provider = test_provider("us-east-1");
        let request = CompletionRequest {
            model: "anthropic.claude-3-sonnet-20240229-v1:0".to_string(),
            messages: vec![LlmMessage {
                role: LlmRole::User,
                content: vec![ContentBlock::ToolResult {
                    tool_use_id: "toolu_456".to_string(),
                    content: "Something went wrong".to_string(),
                    is_error: true,
                }],
            }],
            system: None,
            tools: vec![],
            max_tokens: 1024,
            temperature: None,
            extra: None,
        };
        let body = provider.build_body(&request);

        let content = &body["messages"][0]["content"][0];
        assert_eq!(content["toolResult"]["status"], "error");
    }

    #[test]
    fn test_build_body_multi_turn() {
        let provider = test_provider("us-east-1");
        let request = CompletionRequest {
            model: "anthropic.claude-3-sonnet-20240229-v1:0".to_string(),
            messages: vec![
                LlmMessage {
                    role: LlmRole::User,
                    content: vec![ContentBlock::Text {
                        text: "What's the weather?".to_string(),
                    }],
                },
                LlmMessage {
                    role: LlmRole::Assistant,
                    content: vec![
                        ContentBlock::Text {
                            text: "Let me check.".to_string(),
                        },
                        ContentBlock::ToolUse {
                            id: "toolu_abc".to_string(),
                            name: "get_weather".to_string(),
                            input: json!({"city": "SF"}),
                        },
                    ],
                },
                LlmMessage {
                    role: LlmRole::User,
                    content: vec![ContentBlock::ToolResult {
                        tool_use_id: "toolu_abc".to_string(),
                        content: "72F and sunny".to_string(),
                        is_error: false,
                    }],
                },
            ],
            system: None,
            tools: vec![],
            max_tokens: 1024,
            temperature: None,
            extra: None,
        };
        let body = provider.build_body(&request);
        let messages = body["messages"].as_array().unwrap();
        assert_eq!(messages.len(), 3);

        // User
        assert_eq!(messages[0]["role"], "user");
        assert_eq!(messages[0]["content"][0]["text"], "What's the weather?");

        // Assistant with text + tool_use
        assert_eq!(messages[1]["role"], "assistant");
        assert_eq!(messages[1]["content"][0]["text"], "Let me check.");
        assert_eq!(messages[1]["content"][1]["toolUse"]["name"], "get_weather");

        // Tool result
        assert_eq!(messages[2]["role"], "user");
        assert_eq!(
            messages[2]["content"][0]["toolResult"]["toolUseId"],
            "toolu_abc"
        );
    }

    // ==================== SigV4 signing tests ====================

    #[test]
    fn test_signing_key_derivation() {
        fn hmac_once(key: &[u8], data: &[u8]) -> Vec<u8> {
            let mut hmac = HmacSha256::new_from_slice(key).unwrap();
            hmac.update(data);
            hmac.finalize().into_bytes().to_vec()
        }

        let secret = test_secret_key();
        let date = "20240101";
        let region = "us-east-1";

        // Compute expected key via explicit SigV4 key-schedule chaining.
        let k_secret = format!("AWS4{secret}");
        let k_date = hmac_once(k_secret.as_bytes(), date.as_bytes());
        let k_region = hmac_once(&k_date, region.as_bytes());
        let k_service = hmac_once(&k_region, b"bedrock");
        let expected = hmac_once(&k_service, b"aws4_request");

        let derived = derive_signing_key(&secret, date, region);
        assert_eq!(derived, expected);
    }

    #[test]
    fn test_sign_request_produces_required_headers() {
        let access_key = test_access_key();
        let secret_key = test_secret_key();
        let provider =
            BedrockProvider::new("us-east-1".to_string(), access_key, secret_key).unwrap();

        let body = b"{}";
        let datetime = "20240101T120000Z";
        let headers = provider.sign_request("POST", "/model/test/converse", body, datetime);

        let header_names: Vec<&str> = headers.iter().map(|(n, _)| n.as_str()).collect();
        assert!(header_names.contains(&"host"), "must include host header");
        assert!(
            header_names.contains(&"x-amz-date"),
            "must include x-amz-date header"
        );
        assert!(
            header_names.contains(&"x-amz-content-sha256"),
            "must include x-amz-content-sha256 header"
        );
        assert!(
            header_names.contains(&"authorization"),
            "must include authorization header"
        );
    }

    #[test]
    fn test_sign_request_authorization_format() {
        let access_key = test_access_key();
        let secret_key = test_secret_key();
        let provider =
            BedrockProvider::new("us-east-1".to_string(), access_key.clone(), secret_key).unwrap();

        let body = b"{\"test\": true}";
        let datetime = "20240315T093000Z";
        let headers = provider.sign_request("POST", "/model/test/converse", body, datetime);

        let auth = headers
            .iter()
            .find(|(n, _)| n == "authorization")
            .map(|(_, v)| v.as_str())
            .unwrap();

        assert!(
            auth.starts_with("AWS4-HMAC-SHA256"),
            "auth should start with algorithm: {auth}"
        );
        assert!(
            auth.contains(&format!(
                "Credential={access_key}/20240315/us-east-1/bedrock/aws4_request"
            )),
            "auth should contain credential scope: {auth}"
        );
        assert!(
            auth.contains("SignedHeaders="),
            "auth should contain signed headers: {auth}"
        );
        assert!(
            auth.contains("Signature="),
            "auth should contain signature: {auth}"
        );
    }

    #[test]
    fn test_sign_request_with_session_token() {
        let provider =
            test_provider("us-east-1").with_session_token("my-session-token".to_string());

        let body = b"{}";
        let datetime = "20240101T120000Z";
        let headers = provider.sign_request("POST", "/model/test/converse", body, datetime);

        let header_names: Vec<&str> = headers.iter().map(|(n, _)| n.as_str()).collect();
        assert!(
            header_names.contains(&"x-amz-security-token"),
            "must include security token header when session token is set"
        );

        let token_value = headers
            .iter()
            .find(|(n, _)| n == "x-amz-security-token")
            .map(|(_, v)| v.as_str())
            .unwrap();
        assert_eq!(token_value, "my-session-token");

        // Signed headers should include x-amz-security-token
        let auth = headers
            .iter()
            .find(|(n, _)| n == "authorization")
            .map(|(_, v)| v.as_str())
            .unwrap();
        assert!(
            auth.contains("x-amz-security-token"),
            "signed headers should include security token: {auth}"
        );
    }

    // ==================== Streaming response parsing tests ====================

    fn encode_string_header(name: &str, value: &str) -> Vec<u8> {
        let mut header = Vec::new();
        header.push(name.len() as u8);
        header.extend_from_slice(name.as_bytes());
        header.push(7);
        header.extend_from_slice(&(value.len() as u16).to_be_bytes());
        header.extend_from_slice(value.as_bytes());
        header
    }

    fn build_event_stream_frame(event_type: &str, payload: Value) -> Vec<u8> {
        let mut headers = Vec::new();
        headers.extend(encode_string_header(":message-type", "event"));
        headers.extend(encode_string_header(":event-type", event_type));

        let payload_bytes = serde_json::to_vec(&payload).unwrap();
        let total_len = 12 + headers.len() + payload_bytes.len() + 4;

        let mut frame = Vec::with_capacity(total_len);
        frame.extend_from_slice(&(total_len as u32).to_be_bytes());
        frame.extend_from_slice(&(headers.len() as u32).to_be_bytes());
        frame.extend_from_slice(&0u32.to_be_bytes());
        frame.extend_from_slice(&headers);
        frame.extend_from_slice(&payload_bytes);
        frame.extend_from_slice(&0u32.to_be_bytes());

        let prelude_crc = crc32(&frame[0..8]);
        frame[8..12].copy_from_slice(&prelude_crc.to_be_bytes());
        let message_crc = crc32(&frame[0..(frame.len() - 4)]);
        let crc_start = frame.len() - 4;
        frame[crc_start..].copy_from_slice(&message_crc.to_be_bytes());
        frame
    }

    async fn collect_stream_events(frames: Vec<Vec<u8>>) -> Vec<StreamEvent> {
        let (tx, mut rx) = mpsc::channel(64);
        let mut buffer = BytesMut::new();
        let mut state = BedrockStreamState::default();

        for frame in frames {
            buffer.extend_from_slice(&frame);
            while let Some(frame) = try_decode_event_frame(&mut buffer).unwrap() {
                handle_bedrock_frame(frame, &mut state, &tx).await.unwrap();
            }
        }

        finalize_bedrock_stream(&state, &tx).await.unwrap();
        drop(tx);

        let mut events = Vec::new();
        while let Some(event) = rx.recv().await {
            events.push(event);
        }
        events
    }

    #[tokio::test]
    async fn test_parse_stream_text_response() {
        let frames = vec![
            build_event_stream_frame(
                "contentBlockDelta",
                json!({"delta": {"text": "Hello, world!"}}),
            ),
            build_event_stream_frame(
                "metadata",
                json!({"usage": {"inputTokens": 10, "outputTokens": 5}}),
            ),
            build_event_stream_frame("messageStop", json!({"stopReason": "end_turn"})),
        ];

        let events = collect_stream_events(frames).await;
        assert_eq!(events.len(), 2);
        match &events[0] {
            StreamEvent::TextDelta { text } => assert_eq!(text, "Hello, world!"),
            other => panic!("expected TextDelta, got {other:?}"),
        }
        match &events[1] {
            StreamEvent::Stop { reason, usage } => {
                assert_eq!(*reason, StopReason::EndTurn);
                assert_eq!(usage.input_tokens, 10);
                assert_eq!(usage.output_tokens, 5);
            }
            other => panic!("expected Stop, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_parse_stream_tool_use_response() {
        let frames = vec![
            build_event_stream_frame(
                "contentBlockStart",
                json!({"start": {"toolUse": {"toolUseId": "toolu_abc", "name": "get_weather"}}}),
            ),
            build_event_stream_frame(
                "contentBlockDelta",
                json!({"delta": {"toolUse": {"toolUseId": "toolu_abc", "input": {"city": "SF"}}}}),
            ),
            build_event_stream_frame(
                "metadata",
                json!({"usage": {"inputTokens": 20, "outputTokens": 15}}),
            ),
            build_event_stream_frame("messageStop", json!({"stopReason": "tool_use"})),
        ];

        let events = collect_stream_events(frames).await;
        assert_eq!(events.len(), 2);
        match &events[0] {
            StreamEvent::ToolUse { id, name, input } => {
                assert_eq!(id, "toolu_abc");
                assert_eq!(name, "get_weather");
                assert_eq!(input["city"], "SF");
            }
            other => panic!("expected ToolUse, got {other:?}"),
        }
        match &events[1] {
            StreamEvent::Stop { reason, usage } => {
                assert_eq!(*reason, StopReason::ToolUse);
                assert_eq!(usage.input_tokens, 20);
                assert_eq!(usage.output_tokens, 15);
            }
            other => panic!("expected Stop, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_parse_stream_stop_reason_max_tokens() {
        let frames = vec![
            build_event_stream_frame(
                "contentBlockDelta",
                json!({"delta": {"text": "truncated..."}}),
            ),
            build_event_stream_frame(
                "metadata",
                json!({"usage": {"inputTokens": 50, "outputTokens": 4096}}),
            ),
            build_event_stream_frame("messageStop", json!({"stopReason": "max_tokens"})),
        ];

        let events = collect_stream_events(frames).await;
        match &events[1] {
            StreamEvent::Stop { reason, usage } => {
                assert_eq!(*reason, StopReason::MaxTokens);
                assert_eq!(usage.output_tokens, 4096);
            }
            other => panic!("expected Stop with MaxTokens, got {other:?}"),
        }
    }

    // ==================== Model detection tests ====================

    #[test]
    fn test_is_bedrock_model_colon_prefix() {
        assert!(is_bedrock_model("bedrock:anthropic.claude-3-sonnet"));
        assert!(is_bedrock_model("bedrock:amazon.titan-text-express-v1"));
    }

    #[test]
    fn test_is_bedrock_model_slash_prefix() {
        assert!(is_bedrock_model("bedrock/anthropic.claude-3-sonnet"));
        assert!(is_bedrock_model("bedrock/meta.llama3-70b-instruct-v1:0"));
    }

    #[test]
    fn test_is_bedrock_model_anthropic_pattern() {
        assert!(is_bedrock_model("anthropic.claude-3-sonnet-20240229-v1:0"));
        assert!(is_bedrock_model("anthropic.claude-3-haiku-20240307-v1:0"));
        assert!(is_bedrock_model("anthropic.claude-v2"));
    }

    #[test]
    fn test_is_bedrock_model_amazon_titan_pattern() {
        assert!(is_bedrock_model("amazon.titan-text-express-v1"));
        assert!(is_bedrock_model("amazon.titan-text-lite-v1"));
    }

    #[test]
    fn test_is_bedrock_model_meta_llama_pattern() {
        assert!(is_bedrock_model("meta.llama3-70b-instruct-v1:0"));
        assert!(is_bedrock_model("meta.llama2-13b-chat-v1"));
    }

    #[test]
    fn test_is_not_bedrock_model() {
        assert!(!is_bedrock_model("gpt-4o"));
        assert!(!is_bedrock_model("claude-sonnet-4-20250514"));
        assert!(!is_bedrock_model("ollama:llama3"));
        assert!(!is_bedrock_model("o1-preview"));
    }

    #[test]
    fn test_strip_bedrock_prefix_colon() {
        assert_eq!(
            strip_bedrock_prefix("bedrock:anthropic.claude-3-sonnet"),
            "anthropic.claude-3-sonnet"
        );
    }

    #[test]
    fn test_strip_bedrock_prefix_slash() {
        assert_eq!(
            strip_bedrock_prefix("bedrock/anthropic.claude-3-sonnet"),
            "anthropic.claude-3-sonnet"
        );
    }

    #[test]
    fn test_strip_bedrock_prefix_case_variants() {
        assert_eq!(
            strip_bedrock_prefix("Bedrock:anthropic.claude-3-sonnet"),
            "anthropic.claude-3-sonnet"
        );
        assert_eq!(
            strip_bedrock_prefix("Bedrock/anthropic.claude-3-sonnet"),
            "anthropic.claude-3-sonnet"
        );
    }

    #[test]
    fn test_strip_bedrock_prefix_no_prefix() {
        assert_eq!(
            strip_bedrock_prefix("anthropic.claude-3-sonnet"),
            "anthropic.claude-3-sonnet"
        );
        assert_eq!(strip_bedrock_prefix("gpt-4o"), "gpt-4o");
    }

    // ==================== Utility tests ====================

    #[test]
    fn test_hex_sha256() {
        let hash = hex_sha256(b"");
        assert_eq!(
            hash,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn test_percent_encode_preserves_safe_chars() {
        assert_eq!(
            percent_encode_path_segment("anthropic.claude-3-sonnet"),
            "anthropic.claude-3-sonnet"
        );
    }

    #[test]
    fn test_percent_encode_encodes_colon() {
        let encoded = percent_encode_path_segment("model:version");
        assert_eq!(encoded, "model%3Aversion");
    }

    #[test]
    fn test_parse_stop_reason_variants() {
        assert_eq!(parse_stop_reason("end_turn"), StopReason::EndTurn);
        assert_eq!(parse_stop_reason("tool_use"), StopReason::ToolUse);
        assert_eq!(parse_stop_reason("max_tokens"), StopReason::MaxTokens);
        assert_eq!(parse_stop_reason("unknown"), StopReason::EndTurn);
    }
}
