//! OpenAI-compatible HTTP endpoints
//!
//! Implements:
//! - POST /v1/chat/completions - Chat completions API
//! - POST /v1/responses - OpenResponses API

use axum::{
    body::Body,
    extract::State,
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response, Sse},
    Json,
};
use futures_util::stream::{self, Stream};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::convert::Infallible;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use uuid::Uuid;

/// OpenAI chat completions request
#[derive(Debug, Deserialize)]
pub struct ChatCompletionsRequest {
    /// Model identifier (e.g., "clawdbot", "clawdbot:agent-id")
    #[serde(default = "default_model")]
    pub model: String,
    /// Array of conversation messages
    pub messages: Vec<ChatMessage>,
    /// Enable streaming responses
    #[serde(default)]
    pub stream: bool,
    /// Optional user identifier
    pub user: Option<String>,
}

fn default_model() -> String {
    "clawdbot".to_string()
}

/// Chat message in OpenAI format
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ChatMessage {
    /// Message role
    pub role: String,
    /// Message content (string or array of parts)
    #[serde(default)]
    pub content: ChatContent,
    /// Optional name for tool messages
    pub name: Option<String>,
}

/// Chat content can be a string or array of content parts
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum ChatContent {
    Text(String),
    Parts(Vec<ContentPart>),
}

impl Default for ChatContent {
    fn default() -> Self {
        ChatContent::Text(String::new())
    }
}

impl ChatContent {
    /// Convert to plain text (concatenating parts if needed)
    pub fn to_text(&self) -> String {
        match self {
            ChatContent::Text(s) => s.clone(),
            ChatContent::Parts(parts) => parts
                .iter()
                .map(|p| match p {
                    ContentPart::Text { text, .. } => text.clone(),
                    ContentPart::InputText { input_text, .. } => input_text.clone(),
                })
                .collect::<Vec<_>>()
                .join("\n"),
        }
    }
}

/// Content part in message content array
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type")]
pub enum ContentPart {
    #[serde(rename = "text")]
    Text { text: String },
    #[serde(rename = "input_text")]
    InputText { input_text: String },
}

/// OpenAI chat completion response (non-streaming)
#[derive(Debug, Serialize)]
pub struct ChatCompletionResponse {
    pub id: String,
    pub object: String,
    pub created: i64,
    pub model: String,
    pub choices: Vec<ChatChoice>,
    pub usage: ChatUsage,
}

/// Choice in chat completion response
#[derive(Debug, Serialize)]
pub struct ChatChoice {
    pub index: i32,
    pub message: ChatMessage,
    pub finish_reason: String,
}

/// Token usage statistics
#[derive(Debug, Serialize)]
pub struct ChatUsage {
    pub prompt_tokens: i32,
    pub completion_tokens: i32,
    pub total_tokens: i32,
}

/// Chat completion chunk for streaming
#[derive(Debug, Serialize)]
pub struct ChatCompletionChunk {
    pub id: String,
    pub object: String,
    pub created: i64,
    pub model: String,
    pub choices: Vec<ChunkChoice>,
}

/// Choice in streaming chunk
#[derive(Debug, Serialize)]
pub struct ChunkChoice {
    pub index: i32,
    pub delta: ChunkDelta,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finish_reason: Option<String>,
}

/// Delta content in streaming chunk
#[derive(Debug, Serialize)]
pub struct ChunkDelta {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
}

/// OpenAI API error response
#[derive(Debug, Serialize)]
pub struct OpenAiError {
    pub error: OpenAiErrorBody,
}

/// OpenAI error body
#[derive(Debug, Serialize)]
pub struct OpenAiErrorBody {
    pub message: String,
    pub r#type: String,
}

impl OpenAiError {
    pub fn invalid_request(message: impl Into<String>) -> Self {
        OpenAiError {
            error: OpenAiErrorBody {
                message: message.into(),
                r#type: "invalid_request_error".to_string(),
            },
        }
    }

    pub fn unauthorized() -> Self {
        OpenAiError {
            error: OpenAiErrorBody {
                message: "Unauthorized".to_string(),
                r#type: "unauthorized".to_string(),
            },
        }
    }

    pub fn api_error(message: impl Into<String>) -> Self {
        OpenAiError {
            error: OpenAiErrorBody {
                message: message.into(),
                r#type: "api_error".to_string(),
            },
        }
    }
}

/// State for OpenAI endpoints
#[derive(Clone, Default)]
pub struct OpenAiState {
    /// Whether chat completions endpoint is enabled
    pub chat_completions_enabled: bool,
    /// Whether responses endpoint is enabled
    pub responses_enabled: bool,
    /// Gateway auth token
    pub gateway_token: Option<String>,
    /// Gateway auth password
    pub gateway_password: Option<String>,
}

/// Parse agent ID from model string
/// Supports: "clawdbot", "clawdbot:agent-id", "agent:agent-id"
pub fn parse_agent_id(model: &str) -> Option<String> {
    if model.starts_with("clawdbot:") {
        Some(model.strip_prefix("clawdbot:").unwrap().to_string())
    } else if model.starts_with("agent:") {
        Some(model.strip_prefix("agent:").unwrap().to_string())
    } else {
        None
    }
}

/// Extract user message from messages array
fn extract_user_message(messages: &[ChatMessage]) -> Option<String> {
    messages
        .iter()
        .rev()
        .find(|m| m.role == "user")
        .map(|m| m.content.to_text())
}

/// Extract system messages from messages array
fn extract_system_messages(messages: &[ChatMessage]) -> Vec<String> {
    messages
        .iter()
        .filter(|m| m.role == "system" || m.role == "developer")
        .map(|m| m.content.to_text())
        .collect()
}

/// POST /v1/chat/completions handler
pub async fn chat_completions_handler(
    State(state): State<OpenAiState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    // Check if endpoint is enabled
    if !state.chat_completions_enabled {
        return (StatusCode::NOT_FOUND, "Not Found").into_response();
    }

    // Check auth
    if let Some(err) = check_openai_auth(&state, &headers) {
        return err;
    }

    // Parse request
    let req: ChatCompletionsRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(OpenAiError::invalid_request(format!("Invalid JSON: {}", e))),
            )
                .into_response();
        }
    };

    // Validate: must have at least one user message
    if extract_user_message(&req.messages).is_none() {
        return (
            StatusCode::BAD_REQUEST,
            Json(OpenAiError::invalid_request(
                "Missing user message in `messages`.",
            )),
        )
            .into_response();
    }

    // Parse agent ID from model or headers
    let _agent_id = headers
        .get("x-clawdbot-agent-id")
        .or_else(|| headers.get("x-clawdbot-agent"))
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .or_else(|| parse_agent_id(&req.model));

    // Generate response ID and timestamp
    let response_id = format!("chatcmpl_{}", Uuid::new_v4().simple());
    let created = chrono::Utc::now().timestamp();

    if req.stream {
        // Streaming response
        return streaming_chat_response(response_id, created, req.model).await;
    }

    // Non-streaming response
    // In a real implementation, this would call the agent and get a real response
    let mock_response = "I'm Clawdbot, your AI assistant. How can I help you today?";

    let response = ChatCompletionResponse {
        id: response_id,
        object: "chat.completion".to_string(),
        created,
        model: req.model,
        choices: vec![ChatChoice {
            index: 0,
            message: ChatMessage {
                role: "assistant".to_string(),
                content: ChatContent::Text(mock_response.to_string()),
                name: None,
            },
            finish_reason: "stop".to_string(),
        }],
        usage: ChatUsage {
            prompt_tokens: 0,
            completion_tokens: 0,
            total_tokens: 0,
        },
    };

    (StatusCode::OK, Json(response)).into_response()
}

/// Generate streaming chat response
async fn streaming_chat_response(response_id: String, created: i64, model: String) -> Response {
    let mock_response = "I'm Clawdbot, your AI assistant. How can I help you today?";
    let words: Vec<&str> = mock_response.split(' ').collect();

    let stream = async_stream::stream! {
        // First chunk: role
        let first_chunk = ChatCompletionChunk {
            id: response_id.clone(),
            object: "chat.completion.chunk".to_string(),
            created,
            model: model.clone(),
            choices: vec![ChunkChoice {
                index: 0,
                delta: ChunkDelta {
                    role: Some("assistant".to_string()),
                    content: None,
                },
                finish_reason: None,
            }],
        };
        yield Ok::<_, Infallible>(format!("data: {}\n\n", serde_json::to_string(&first_chunk).unwrap()));

        // Content chunks
        for (i, word) in words.iter().enumerate() {
            let content = if i == 0 {
                word.to_string()
            } else {
                format!(" {}", word)
            };

            let chunk = ChatCompletionChunk {
                id: response_id.clone(),
                object: "chat.completion.chunk".to_string(),
                created,
                model: model.clone(),
                choices: vec![ChunkChoice {
                    index: 0,
                    delta: ChunkDelta {
                        role: None,
                        content: Some(content),
                    },
                    finish_reason: None,
                }],
            };
            yield Ok::<_, Infallible>(format!("data: {}\n\n", serde_json::to_string(&chunk).unwrap()));

            // Small delay to simulate streaming
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        // Final chunk with finish_reason
        let final_chunk = ChatCompletionChunk {
            id: response_id.clone(),
            object: "chat.completion.chunk".to_string(),
            created,
            model: model.clone(),
            choices: vec![ChunkChoice {
                index: 0,
                delta: ChunkDelta {
                    role: None,
                    content: None,
                },
                finish_reason: Some("stop".to_string()),
            }],
        };
        yield Ok::<_, Infallible>(format!("data: {}\n\n", serde_json::to_string(&final_chunk).unwrap()));

        // Done marker
        yield Ok::<_, Infallible>("data: [DONE]\n\n".to_string());
    };

    let body = Body::from_stream(stream);

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/event-stream; charset=utf-8")
        .header(header::CACHE_CONTROL, "no-cache")
        .header("connection", "keep-alive")
        .body(body)
        .unwrap()
}

/// Check OpenAI endpoint authentication
fn check_openai_auth(state: &OpenAiState, headers: &HeaderMap) -> Option<Response> {
    // Extract bearer token
    let provided = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(|s| s.trim());

    // Check token auth
    if let Some(token) = &state.gateway_token {
        if !token.is_empty() {
            if let Some(provided) = provided {
                if crate::auth::timing_safe_eq(provided, token) {
                    return None;
                }
            }
            return Some(
                (StatusCode::UNAUTHORIZED, Json(OpenAiError::unauthorized())).into_response(),
            );
        }
    }

    // Check password auth
    if let Some(password) = &state.gateway_password {
        if !password.is_empty() {
            if let Some(provided) = provided {
                if crate::auth::timing_safe_eq(provided, password) {
                    return None;
                }
            }
            return Some(
                (StatusCode::UNAUTHORIZED, Json(OpenAiError::unauthorized())).into_response(),
            );
        }
    }

    // No auth configured - require token for OpenAI endpoints (unlike tools/invoke which allows loopback)
    Some((StatusCode::UNAUTHORIZED, Json(OpenAiError::unauthorized())).into_response())
}

// ============================================================================
// OpenResponses API
// ============================================================================

/// OpenResponses request
#[derive(Debug, Deserialize)]
pub struct ResponsesRequest {
    /// Model identifier
    pub model: String,
    /// Input (string or array of items)
    pub input: ResponsesInput,
    /// System instructions
    pub instructions: Option<String>,
    /// Client tools
    pub tools: Option<Vec<ResponsesTool>>,
    /// Tool choice strategy
    pub tool_choice: Option<Value>,
    /// Enable streaming
    #[serde(default)]
    pub stream: bool,
    /// Max output tokens
    pub max_output_tokens: Option<i32>,
    /// Max tool calls
    pub max_tool_calls: Option<i32>,
    /// User identifier
    pub user: Option<String>,
    /// Reasoning configuration
    pub reasoning: Option<ReasoningConfig>,
}

/// Reasoning configuration
#[derive(Debug, Deserialize)]
pub struct ReasoningConfig {
    pub effort: Option<String>,
    pub summary: Option<String>,
}

/// OpenResponses input (string or array)
#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum ResponsesInput {
    Text(String),
    Items(Vec<ResponsesInputItem>),
}

/// Input item for OpenResponses
#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
pub enum ResponsesInputItem {
    #[serde(rename = "message")]
    Message { role: String, content: ChatContent },
    #[serde(rename = "function_call")]
    FunctionCall { name: String, arguments: String },
    #[serde(rename = "function_call_output")]
    FunctionCallOutput { call_id: String, output: String },
}

/// Tool definition for OpenResponses
#[derive(Debug, Deserialize)]
pub struct ResponsesTool {
    pub r#type: String,
    pub function: Option<ResponsesFunction>,
}

/// Function definition in tool
#[derive(Debug, Deserialize)]
pub struct ResponsesFunction {
    pub name: String,
    pub description: Option<String>,
    pub parameters: Option<Value>,
}

/// OpenResponses response
#[derive(Debug, Serialize)]
pub struct ResponsesResponse {
    pub id: String,
    pub object: String,
    pub created_at: i64,
    pub status: String,
    pub model: String,
    pub output: Vec<ResponsesOutputItem>,
    pub usage: ResponsesUsage,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ResponsesError>,
}

/// Output item in OpenResponses
#[derive(Debug, Serialize)]
#[serde(tag = "type")]
pub enum ResponsesOutputItem {
    #[serde(rename = "message")]
    Message {
        id: String,
        role: String,
        content: Vec<OutputContent>,
        status: String,
    },
    #[serde(rename = "function_call")]
    FunctionCall {
        id: String,
        call_id: String,
        name: String,
        arguments: String,
    },
}

/// Output content part
#[derive(Debug, Serialize)]
pub struct OutputContent {
    pub r#type: String,
    pub text: String,
}

/// Usage for OpenResponses
#[derive(Debug, Serialize)]
pub struct ResponsesUsage {
    pub input_tokens: i32,
    pub output_tokens: i32,
    pub total_tokens: i32,
}

/// Error in OpenResponses
#[derive(Debug, Serialize)]
pub struct ResponsesError {
    pub code: String,
    pub message: String,
}

/// Check if input has a user message
fn has_user_message(input: &ResponsesInput) -> bool {
    match input {
        ResponsesInput::Text(_) => true,
        ResponsesInput::Items(items) => items
            .iter()
            .any(|item| matches!(item, ResponsesInputItem::Message { role, .. } if role == "user")),
    }
}

/// POST /v1/responses handler
pub async fn responses_handler(
    State(state): State<OpenAiState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    // Check if endpoint is enabled
    if !state.responses_enabled {
        return (StatusCode::NOT_FOUND, "Not Found").into_response();
    }

    // Check auth
    if let Some(err) = check_openai_auth(&state, &headers) {
        return err;
    }

    // Parse request
    let req: ResponsesRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(OpenAiError::invalid_request(format!("Invalid JSON: {}", e))),
            )
                .into_response();
        }
    };

    // Validate: must have user message
    if !has_user_message(&req.input) {
        return (
            StatusCode::BAD_REQUEST,
            Json(OpenAiError::invalid_request(
                "Missing user message in `input`.",
            )),
        )
            .into_response();
    }

    // Validate tool_choice
    if let Some(ref tool_choice) = req.tool_choice {
        if let Some(s) = tool_choice.as_str() {
            if s == "required" && req.tools.as_ref().map(|t| t.is_empty()).unwrap_or(true) {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(OpenAiError::invalid_request(
                        "tool_choice=required but no tools were provided",
                    )),
                )
                    .into_response();
            }
        }
        if let Some(obj) = tool_choice.as_object() {
            if obj.get("type").and_then(|v| v.as_str()) == Some("function") {
                if let Some(func) = obj.get("function") {
                    if let Some(name) = func.get("name").and_then(|v| v.as_str()) {
                        let has_tool = req
                            .tools
                            .as_ref()
                            .map(|tools| {
                                tools.iter().any(|t| {
                                    t.function.as_ref().map(|f| f.name == name).unwrap_or(false)
                                })
                            })
                            .unwrap_or(false);
                        if !has_tool {
                            return (
                                StatusCode::BAD_REQUEST,
                                Json(OpenAiError::invalid_request(format!(
                                    "tool_choice requested unknown tool: {}",
                                    name
                                ))),
                            )
                                .into_response();
                        }
                    }
                }
            }
        }
    }

    // Generate response
    let response_id = format!("resp_{}", Uuid::new_v4().simple());
    let msg_id = format!("msg_{}", Uuid::new_v4().simple());
    let created_at = chrono::Utc::now().timestamp();

    // Mock response
    let mock_response = "I'm Clawdbot, your AI assistant.";

    if req.stream {
        // Streaming would be implemented here
        // For now, return non-streaming
    }

    let response = ResponsesResponse {
        id: response_id,
        object: "response".to_string(),
        created_at,
        status: "completed".to_string(),
        model: req.model,
        output: vec![ResponsesOutputItem::Message {
            id: msg_id,
            role: "assistant".to_string(),
            content: vec![OutputContent {
                r#type: "output_text".to_string(),
                text: mock_response.to_string(),
            }],
            status: "completed".to_string(),
        }],
        usage: ResponsesUsage {
            input_tokens: 0,
            output_tokens: 0,
            total_tokens: 0,
        },
        error: None,
    };

    (StatusCode::OK, Json(response)).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_agent_id() {
        assert_eq!(parse_agent_id("clawdbot"), None);
        assert_eq!(
            parse_agent_id("clawdbot:email-agent"),
            Some("email-agent".to_string())
        );
        assert_eq!(parse_agent_id("agent:main"), Some("main".to_string()));
        assert_eq!(parse_agent_id("gpt-4"), None);
    }

    #[test]
    fn test_chat_content_to_text() {
        let text = ChatContent::Text("Hello world".to_string());
        assert_eq!(text.to_text(), "Hello world");

        let parts = ChatContent::Parts(vec![
            ContentPart::Text {
                text: "Hello".to_string(),
            },
            ContentPart::Text {
                text: "World".to_string(),
            },
        ]);
        assert_eq!(parts.to_text(), "Hello\nWorld");
    }

    #[test]
    fn test_extract_user_message() {
        let messages = vec![
            ChatMessage {
                role: "system".to_string(),
                content: ChatContent::Text("You are helpful".to_string()),
                name: None,
            },
            ChatMessage {
                role: "user".to_string(),
                content: ChatContent::Text("Hello".to_string()),
                name: None,
            },
        ];

        let user_msg = extract_user_message(&messages);
        assert_eq!(user_msg, Some("Hello".to_string()));

        let no_user = vec![ChatMessage {
            role: "system".to_string(),
            content: ChatContent::Text("System".to_string()),
            name: None,
        }];
        assert_eq!(extract_user_message(&no_user), None);
    }

    #[test]
    fn test_openai_error_serialization() {
        let error = OpenAiError::invalid_request("Bad request");
        let json = serde_json::to_string(&error).unwrap();
        assert!(json.contains("invalid_request_error"));
        assert!(json.contains("Bad request"));
    }

    #[test]
    fn test_chat_completion_response_serialization() {
        let response = ChatCompletionResponse {
            id: "chatcmpl_test".to_string(),
            object: "chat.completion".to_string(),
            created: 1700000000,
            model: "clawdbot".to_string(),
            choices: vec![ChatChoice {
                index: 0,
                message: ChatMessage {
                    role: "assistant".to_string(),
                    content: ChatContent::Text("Hello".to_string()),
                    name: None,
                },
                finish_reason: "stop".to_string(),
            }],
            usage: ChatUsage {
                prompt_tokens: 10,
                completion_tokens: 5,
                total_tokens: 15,
            },
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("chat.completion"));
        assert!(json.contains("chatcmpl_test"));
    }

    #[test]
    fn test_has_user_message() {
        assert!(has_user_message(&ResponsesInput::Text("hello".to_string())));

        let items_with_user = ResponsesInput::Items(vec![ResponsesInputItem::Message {
            role: "user".to_string(),
            content: ChatContent::Text("hello".to_string()),
        }]);
        assert!(has_user_message(&items_with_user));

        let items_no_user = ResponsesInput::Items(vec![ResponsesInputItem::Message {
            role: "system".to_string(),
            content: ChatContent::Text("system".to_string()),
        }]);
        assert!(!has_user_message(&items_no_user));
    }
}
