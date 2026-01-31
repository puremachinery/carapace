//! AWS Bedrock Converse API provider.
//!
//! Sends completion requests to the AWS Bedrock Converse endpoint and returns
//! results through the same streaming channel interface used by other providers.
//! Uses the non-streaming Converse API to avoid AWS event-stream binary framing
//! complexity, and emits events through the mpsc channel to match the trait.

use async_trait::async_trait;
use hmac::{Hmac, Mac};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
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
        let uri_path = format!("/model/{}/converse", percent_encode_path_segment(model_id));
        let url = format!("{}{}", self.base_url, uri_path);

        // Generate timestamp for signing
        let now = chrono::Utc::now();
        let datetime = now.format("%Y%m%dT%H%M%SZ").to_string();

        // Sign the request
        let sig_headers = self.sign_request("POST", &uri_path, &body_bytes, &datetime);

        let mut http_request = self
            .client
            .post(&url)
            .header("content-type", "application/json");

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

        let response_body: Value = tokio::select! {
            _ = cancel_token.cancelled() => {
                return Err(AgentError::Cancelled);
            }
            body = response.json() => {
                body.map_err(|e| AgentError::Provider(format!("failed to parse Bedrock response: {e}")))?
            }
        };

        let (tx, rx) = mpsc::channel(64);

        // Parse the response and emit events through the channel
        tokio::spawn(async move {
            if let Err(e) = emit_converse_events(&response_body, &tx).await {
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

/// Parse a Bedrock Converse response and emit events through the channel.
async fn emit_converse_events(
    response: &Value,
    tx: &mpsc::Sender<StreamEvent>,
) -> Result<(), String> {
    // Extract content blocks from output.message.content
    if let Some(content) = response
        .get("output")
        .and_then(|o| o.get("message"))
        .and_then(|m| m.get("content"))
        .and_then(|c| c.as_array())
    {
        for block in content {
            if let Some(text) = block.get("text").and_then(|t| t.as_str()) {
                if !text.is_empty() {
                    let event = StreamEvent::TextDelta {
                        text: text.to_string(),
                    };
                    if tx.send(event).await.is_err() {
                        return Ok(()); // Receiver dropped
                    }
                }
            } else if let Some(tool_use) = block.get("toolUse") {
                let id = tool_use
                    .get("toolUseId")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let name = tool_use
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let input = tool_use.get("input").cloned().unwrap_or_else(|| json!({}));
                let event = StreamEvent::ToolUse { id, name, input };
                if tx.send(event).await.is_err() {
                    return Ok(());
                }
            }
        }
    }

    // Extract stop reason
    let stop_reason = response
        .get("stopReason")
        .and_then(|v| v.as_str())
        .map(parse_stop_reason)
        .unwrap_or(StopReason::EndTurn);

    // Extract usage
    let usage = TokenUsage {
        input_tokens: response
            .get("usage")
            .and_then(|u| u.get("inputTokens"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0),
        output_tokens: response
            .get("usage")
            .and_then(|u| u.get("outputTokens"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0),
    };

    let _ = tx
        .send(StreamEvent::Stop {
            reason: stop_reason,
            usage,
        })
        .await;

    Ok(())
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

    // ==================== Provider construction tests ====================

    #[test]
    fn test_new_rejects_empty_region() {
        let result = BedrockProvider::new("".to_string(), "AKID".to_string(), "secret".to_string());
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("region"), "error should mention region: {err}");
    }

    #[test]
    fn test_new_rejects_empty_access_key() {
        let result = BedrockProvider::new(
            "us-east-1".to_string(),
            "".to_string(),
            "secret".to_string(),
        );
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
            BedrockProvider::new("us-east-1".to_string(), "AKID".to_string(), "".to_string());
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("secret access key"),
            "error should mention secret access key: {err}"
        );
    }

    #[test]
    fn test_new_accepts_valid_credentials() {
        let result = BedrockProvider::new(
            "us-east-1".to_string(),
            "AKIAIOSFODNN7EXAMPLE".to_string(),
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".to_string(),
        );
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
        let provider = BedrockProvider::new(
            "us-west-2".to_string(),
            "AKID".to_string(),
            "secret".to_string(),
        )
        .unwrap()
        .with_session_token("FwoGZX...".to_string());
        assert!(provider.session_token.is_some());
        assert_eq!(provider.session_token.as_deref(), Some("FwoGZX..."));
    }

    #[test]
    fn test_with_empty_session_token_clears() {
        let provider = BedrockProvider::new(
            "us-west-2".to_string(),
            "AKID".to_string(),
            "secret".to_string(),
        )
        .unwrap()
        .with_session_token("".to_string());
        assert!(provider.session_token.is_none());
    }

    #[test]
    fn test_base_url_derived_from_region() {
        let provider = BedrockProvider::new(
            "eu-west-1".to_string(),
            "AKID".to_string(),
            "secret".to_string(),
        )
        .unwrap();
        assert_eq!(
            provider.base_url,
            "https://bedrock-runtime.eu-west-1.amazonaws.com"
        );
    }

    // ==================== Request body building tests ====================

    #[test]
    fn test_build_body_basic() {
        let provider = BedrockProvider::new(
            "us-east-1".to_string(),
            "AKID".to_string(),
            "secret".to_string(),
        )
        .unwrap();
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
        let provider = BedrockProvider::new(
            "us-east-1".to_string(),
            "AKID".to_string(),
            "secret".to_string(),
        )
        .unwrap();
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
        let provider = BedrockProvider::new(
            "us-east-1".to_string(),
            "AKID".to_string(),
            "secret".to_string(),
        )
        .unwrap();
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
        let provider = BedrockProvider::new(
            "us-east-1".to_string(),
            "AKID".to_string(),
            "secret".to_string(),
        )
        .unwrap();
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
        let provider = BedrockProvider::new(
            "us-east-1".to_string(),
            "AKID".to_string(),
            "secret".to_string(),
        )
        .unwrap();
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
        let provider = BedrockProvider::new(
            "us-east-1".to_string(),
            "AKID".to_string(),
            "secret".to_string(),
        )
        .unwrap();
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
        let key = derive_signing_key(
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "20240101",
            "us-east-1",
        );
        // Should produce a 32-byte key (SHA-256 output)
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_sign_request_produces_required_headers() {
        let provider = BedrockProvider::new(
            "us-east-1".to_string(),
            "AKIAIOSFODNN7EXAMPLE".to_string(),
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".to_string(),
        )
        .unwrap();

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
        let provider = BedrockProvider::new(
            "us-east-1".to_string(),
            "AKIAIOSFODNN7EXAMPLE".to_string(),
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".to_string(),
        )
        .unwrap();

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
            auth.contains(
                "Credential=AKIAIOSFODNN7EXAMPLE/20240315/us-east-1/bedrock/aws4_request"
            ),
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
        let provider = BedrockProvider::new(
            "us-east-1".to_string(),
            "AKID".to_string(),
            "secret".to_string(),
        )
        .unwrap()
        .with_session_token("my-session-token".to_string());

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

    // ==================== Response parsing tests ====================

    #[tokio::test]
    async fn test_parse_text_response() {
        let response = json!({
            "output": {
                "message": {
                    "role": "assistant",
                    "content": [{"text": "Hello, world!"}]
                }
            },
            "stopReason": "end_turn",
            "usage": {
                "inputTokens": 10,
                "outputTokens": 5
            }
        });

        let (tx, mut rx) = mpsc::channel(64);
        emit_converse_events(&response, &tx).await.unwrap();
        drop(tx);

        let mut events = Vec::new();
        while let Some(event) = rx.recv().await {
            events.push(event);
        }

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
    async fn test_parse_tool_use_response() {
        let response = json!({
            "output": {
                "message": {
                    "role": "assistant",
                    "content": [
                        {"text": "Let me check."},
                        {
                            "toolUse": {
                                "toolUseId": "toolu_abc",
                                "name": "get_weather",
                                "input": {"city": "SF"}
                            }
                        }
                    ]
                }
            },
            "stopReason": "tool_use",
            "usage": {
                "inputTokens": 20,
                "outputTokens": 15
            }
        });

        let (tx, mut rx) = mpsc::channel(64);
        emit_converse_events(&response, &tx).await.unwrap();
        drop(tx);

        let mut events = Vec::new();
        while let Some(event) = rx.recv().await {
            events.push(event);
        }

        assert_eq!(events.len(), 3);
        match &events[0] {
            StreamEvent::TextDelta { text } => assert_eq!(text, "Let me check."),
            other => panic!("expected TextDelta, got {other:?}"),
        }
        match &events[1] {
            StreamEvent::ToolUse { id, name, input } => {
                assert_eq!(id, "toolu_abc");
                assert_eq!(name, "get_weather");
                assert_eq!(input["city"], "SF");
            }
            other => panic!("expected ToolUse, got {other:?}"),
        }
        match &events[2] {
            StreamEvent::Stop { reason, usage } => {
                assert_eq!(*reason, StopReason::ToolUse);
                assert_eq!(usage.input_tokens, 20);
                assert_eq!(usage.output_tokens, 15);
            }
            other => panic!("expected Stop, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_parse_stop_reason_max_tokens() {
        let response = json!({
            "output": {
                "message": {
                    "role": "assistant",
                    "content": [{"text": "truncated..."}]
                }
            },
            "stopReason": "max_tokens",
            "usage": {
                "inputTokens": 50,
                "outputTokens": 4096
            }
        });

        let (tx, mut rx) = mpsc::channel(64);
        emit_converse_events(&response, &tx).await.unwrap();
        drop(tx);

        let mut events = Vec::new();
        while let Some(event) = rx.recv().await {
            events.push(event);
        }

        match &events[1] {
            StreamEvent::Stop { reason, usage } => {
                assert_eq!(*reason, StopReason::MaxTokens);
                assert_eq!(usage.output_tokens, 4096);
            }
            other => panic!("expected Stop with MaxTokens, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_parse_usage_extraction() {
        let response = json!({
            "output": {
                "message": {
                    "role": "assistant",
                    "content": [{"text": "ok"}]
                }
            },
            "stopReason": "end_turn",
            "usage": {
                "inputTokens": 150,
                "outputTokens": 42
            }
        });

        let (tx, mut rx) = mpsc::channel(64);
        emit_converse_events(&response, &tx).await.unwrap();
        drop(tx);

        let mut events = Vec::new();
        while let Some(event) = rx.recv().await {
            events.push(event);
        }

        match &events[1] {
            StreamEvent::Stop { usage, .. } => {
                assert_eq!(usage.input_tokens, 150);
                assert_eq!(usage.output_tokens, 42);
            }
            other => panic!("expected Stop, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_parse_empty_content() {
        let response = json!({
            "output": {
                "message": {
                    "role": "assistant",
                    "content": []
                }
            },
            "stopReason": "end_turn",
            "usage": {
                "inputTokens": 5,
                "outputTokens": 0
            }
        });

        let (tx, mut rx) = mpsc::channel(64);
        emit_converse_events(&response, &tx).await.unwrap();
        drop(tx);

        let mut events = Vec::new();
        while let Some(event) = rx.recv().await {
            events.push(event);
        }

        // Only the Stop event, no text or tool events
        assert_eq!(events.len(), 1);
        assert!(matches!(&events[0], StreamEvent::Stop { .. }));
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
