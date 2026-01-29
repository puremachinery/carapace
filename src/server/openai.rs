//! OpenAI-compatible HTTP endpoints
//!
//! Implements:
//! - POST /v1/chat/completions - Chat completions API
//! - POST /v1/responses - OpenResponses API

use axum::{
    body::Body,
    extract::State,
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::convert::Infallible;
use std::sync::Arc;
use uuid::Uuid;

use crate::agent::provider::{
    CompletionRequest, ContentBlock, LlmMessage, LlmRole, StopReason, StreamEvent, TokenUsage,
};
use crate::agent::LlmProvider;

/// OpenAI chat completions request
#[derive(Debug, Deserialize)]
pub struct ChatCompletionsRequest {
    /// Model identifier (e.g., "moltbot", "moltbot:agent-id")
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
    "moltbot".to_string()
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
    /// LLM provider for making actual API calls
    pub llm_provider: Option<Arc<dyn LlmProvider>>,
}

/// Parse agent ID from model string
/// Supports: "moltbot", "moltbot:agent-id", "agent:agent-id"
pub fn parse_agent_id(model: &str) -> Option<String> {
    if model.starts_with("moltbot:") {
        Some(model.strip_prefix("moltbot:").unwrap().to_string())
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

/// Convert OpenAI-format chat messages to LLM provider messages.
///
/// Returns `(system_prompt, messages)`. System/developer messages are merged
/// into a single system prompt; user and assistant messages are mapped to
/// `LlmMessage` entries.
fn convert_to_llm_messages(messages: &[ChatMessage]) -> (Option<String>, Vec<LlmMessage>) {
    let system_parts = extract_system_messages(messages);
    let system = if system_parts.is_empty() {
        None
    } else {
        Some(system_parts.join("\n\n"))
    };

    let llm_messages: Vec<LlmMessage> = messages
        .iter()
        .filter(|m| m.role == "user" || m.role == "assistant")
        .map(|m| {
            let role = if m.role == "user" {
                LlmRole::User
            } else {
                LlmRole::Assistant
            };
            LlmMessage {
                role,
                content: vec![ContentBlock::Text {
                    text: m.content.to_text(),
                }],
            }
        })
        .collect();

    (system, llm_messages)
}

/// Call the LLM provider and collect the full response (non-streaming collection).
///
/// Returns `(response_text, usage)` on success.
async fn call_llm_provider(
    provider: &dyn LlmProvider,
    model: &str,
    system: Option<String>,
    messages: Vec<LlmMessage>,
) -> Result<(String, TokenUsage), String> {
    let request = CompletionRequest {
        model: model.to_string(),
        messages,
        system,
        tools: vec![],
        max_tokens: 8192,
        temperature: None,
    };

    let mut rx = provider
        .complete(request)
        .await
        .map_err(|e| format!("LLM provider error: {}", e))?;

    let mut text = String::new();
    let mut usage = TokenUsage::default();

    while let Some(event) = rx.recv().await {
        match event {
            StreamEvent::TextDelta { text: delta } => {
                text.push_str(&delta);
            }
            StreamEvent::Stop { usage: u, .. } => {
                usage = u;
                break;
            }
            StreamEvent::Error { message } => {
                return Err(message);
            }
            StreamEvent::ToolUse { .. } => {
                // Tool calls are not supported in the OpenAI chat endpoint;
                // treat as end of response.
            }
        }
    }

    Ok((text, usage))
}

/// Stream LLM provider events as OpenAI-format SSE chunks.
async fn stream_llm_provider(
    provider: Arc<dyn LlmProvider>,
    model: String,
    system: Option<String>,
    messages: Vec<LlmMessage>,
    response_id: String,
    created: i64,
) -> Response {
    // Start the LLM call. If it fails, return an error SSE stream.
    let request = CompletionRequest {
        model: model.clone(),
        messages,
        system,
        tools: vec![],
        max_tokens: 8192,
        temperature: None,
    };

    let rx = match provider.complete(request).await {
        Ok(rx) => rx,
        Err(e) => {
            // Return an error as a single SSE event
            let error_stream = async_stream::stream! {
                let error_data = serde_json::to_string(&OpenAiError::api_error(e.to_string())).unwrap_or_default();
                yield Ok::<_, Infallible>(format!("data: {}\n\ndata: [DONE]\n\n", error_data));
            };
            let body = Body::from_stream(error_stream);
            return Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "text/event-stream; charset=utf-8")
                .header(header::CACHE_CONTROL, "no-cache")
                .header("connection", "keep-alive")
                .body(body)
                .unwrap();
        }
    };

    let stream = async_stream::stream! {
        let mut rx = rx;

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
        yield Ok::<_, Infallible>(format!(
            "data: {}\n\n",
            serde_json::to_string(&first_chunk).unwrap()
        ));

        // Stream content from the LLM provider
        while let Some(event) = rx.recv().await {
            match event {
                StreamEvent::TextDelta { text } => {
                    let chunk = ChatCompletionChunk {
                        id: response_id.clone(),
                        object: "chat.completion.chunk".to_string(),
                        created,
                        model: model.clone(),
                        choices: vec![ChunkChoice {
                            index: 0,
                            delta: ChunkDelta {
                                role: None,
                                content: Some(text),
                            },
                            finish_reason: None,
                        }],
                    };
                    yield Ok::<_, Infallible>(format!(
                        "data: {}\n\n",
                        serde_json::to_string(&chunk).unwrap()
                    ));
                }
                StreamEvent::Stop { reason, .. } => {
                    let finish_reason = match reason {
                        StopReason::EndTurn => "stop",
                        StopReason::MaxTokens => "length",
                        StopReason::ToolUse => "stop",
                    };
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
                            finish_reason: Some(finish_reason.to_string()),
                        }],
                    };
                    yield Ok::<_, Infallible>(format!(
                        "data: {}\n\n",
                        serde_json::to_string(&final_chunk).unwrap()
                    ));
                    break;
                }
                StreamEvent::Error { message } => {
                    // Send error as a chunk with content, then stop
                    let error_chunk = ChatCompletionChunk {
                        id: response_id.clone(),
                        object: "chat.completion.chunk".to_string(),
                        created,
                        model: model.clone(),
                        choices: vec![ChunkChoice {
                            index: 0,
                            delta: ChunkDelta {
                                role: None,
                                content: Some(format!("[Error: {}]", message)),
                            },
                            finish_reason: Some("stop".to_string()),
                        }],
                    };
                    yield Ok::<_, Infallible>(format!(
                        "data: {}\n\n",
                        serde_json::to_string(&error_chunk).unwrap()
                    ));
                    break;
                }
                StreamEvent::ToolUse { .. } => {
                    // Skip tool calls in OpenAI chat mode
                }
            }
        }

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
        .get("x-moltbot-agent-id")
        .or_else(|| headers.get("x-moltbot-agent"))
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .or_else(|| parse_agent_id(&req.model));

    // Generate response ID and timestamp
    let response_id = format!("chatcmpl_{}", Uuid::new_v4().simple());
    let created = chrono::Utc::now().timestamp();

    // Check if we have an LLM provider
    let provider = match &state.llm_provider {
        Some(p) => p.clone(),
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(OpenAiError::api_error(
                    "No LLM provider configured. Set ANTHROPIC_API_KEY to enable.",
                )),
            )
                .into_response();
        }
    };

    // Convert OpenAI messages to LLM provider format
    let (system, llm_messages) = convert_to_llm_messages(&req.messages);

    if llm_messages.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(OpenAiError::invalid_request(
                "No user or assistant messages found after filtering system messages.",
            )),
        )
            .into_response();
    }

    // Use the requested model, falling back to the default
    let model = if req.model == "moltbot"
        || req.model.starts_with("moltbot:")
        || req.model.starts_with("agent:")
    {
        crate::agent::DEFAULT_MODEL.to_string()
    } else {
        req.model.clone()
    };

    if req.stream {
        // Streaming response via the LLM provider
        return stream_llm_provider(provider, model, system, llm_messages, response_id, created)
            .await;
    }

    // Non-streaming response: call the LLM provider and collect the result
    match call_llm_provider(&*provider, &model, system, llm_messages).await {
        Ok((text, usage)) => {
            let response = ChatCompletionResponse {
                id: response_id,
                object: "chat.completion".to_string(),
                created,
                model,
                choices: vec![ChatChoice {
                    index: 0,
                    message: ChatMessage {
                        role: "assistant".to_string(),
                        content: ChatContent::Text(text),
                        name: None,
                    },
                    finish_reason: "stop".to_string(),
                }],
                usage: ChatUsage {
                    prompt_tokens: usage.input_tokens as i32,
                    completion_tokens: usage.output_tokens as i32,
                    total_tokens: (usage.input_tokens + usage.output_tokens) as i32,
                },
            };
            (StatusCode::OK, Json(response)).into_response()
        }
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(OpenAiError::api_error(err)),
        )
            .into_response(),
    }
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
    let mock_response = "I'm Moltbot, your AI assistant.";

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
        assert_eq!(parse_agent_id("moltbot"), None);
        assert_eq!(
            parse_agent_id("moltbot:email-agent"),
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
            model: "moltbot".to_string(),
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

    // ============== convert_to_llm_messages Tests ==============

    #[test]
    fn test_convert_to_llm_messages_basic() {
        let messages = vec![ChatMessage {
            role: "user".to_string(),
            content: ChatContent::Text("Hello".to_string()),
            name: None,
        }];

        let (system, llm_msgs) = convert_to_llm_messages(&messages);
        assert!(system.is_none());
        assert_eq!(llm_msgs.len(), 1);
        assert_eq!(llm_msgs[0].role, LlmRole::User);
        match &llm_msgs[0].content[0] {
            ContentBlock::Text { text } => assert_eq!(text, "Hello"),
            _ => panic!("expected Text block"),
        }
    }

    #[test]
    fn test_convert_to_llm_messages_with_system() {
        let messages = vec![
            ChatMessage {
                role: "system".to_string(),
                content: ChatContent::Text("You are a helpful assistant".to_string()),
                name: None,
            },
            ChatMessage {
                role: "user".to_string(),
                content: ChatContent::Text("Hi".to_string()),
                name: None,
            },
        ];

        let (system, llm_msgs) = convert_to_llm_messages(&messages);
        assert_eq!(system.unwrap(), "You are a helpful assistant");
        assert_eq!(llm_msgs.len(), 1);
        assert_eq!(llm_msgs[0].role, LlmRole::User);
    }

    #[test]
    fn test_convert_to_llm_messages_with_developer_role() {
        let messages = vec![
            ChatMessage {
                role: "developer".to_string(),
                content: ChatContent::Text("System instruction".to_string()),
                name: None,
            },
            ChatMessage {
                role: "user".to_string(),
                content: ChatContent::Text("Hello".to_string()),
                name: None,
            },
        ];

        let (system, llm_msgs) = convert_to_llm_messages(&messages);
        assert_eq!(system.unwrap(), "System instruction");
        assert_eq!(llm_msgs.len(), 1);
    }

    #[test]
    fn test_convert_to_llm_messages_multi_system() {
        let messages = vec![
            ChatMessage {
                role: "system".to_string(),
                content: ChatContent::Text("Be helpful".to_string()),
                name: None,
            },
            ChatMessage {
                role: "developer".to_string(),
                content: ChatContent::Text("Be concise".to_string()),
                name: None,
            },
            ChatMessage {
                role: "user".to_string(),
                content: ChatContent::Text("Hi".to_string()),
                name: None,
            },
        ];

        let (system, llm_msgs) = convert_to_llm_messages(&messages);
        assert_eq!(system.unwrap(), "Be helpful\n\nBe concise");
        assert_eq!(llm_msgs.len(), 1);
    }

    #[test]
    fn test_convert_to_llm_messages_conversation() {
        let messages = vec![
            ChatMessage {
                role: "system".to_string(),
                content: ChatContent::Text("You are a bot".to_string()),
                name: None,
            },
            ChatMessage {
                role: "user".to_string(),
                content: ChatContent::Text("Hello".to_string()),
                name: None,
            },
            ChatMessage {
                role: "assistant".to_string(),
                content: ChatContent::Text("Hi there!".to_string()),
                name: None,
            },
            ChatMessage {
                role: "user".to_string(),
                content: ChatContent::Text("How are you?".to_string()),
                name: None,
            },
        ];

        let (system, llm_msgs) = convert_to_llm_messages(&messages);
        assert_eq!(system.unwrap(), "You are a bot");
        assert_eq!(llm_msgs.len(), 3);
        assert_eq!(llm_msgs[0].role, LlmRole::User);
        assert_eq!(llm_msgs[1].role, LlmRole::Assistant);
        assert_eq!(llm_msgs[2].role, LlmRole::User);
    }

    #[test]
    fn test_convert_to_llm_messages_system_only_returns_empty() {
        let messages = vec![ChatMessage {
            role: "system".to_string(),
            content: ChatContent::Text("You are a bot".to_string()),
            name: None,
        }];

        let (system, llm_msgs) = convert_to_llm_messages(&messages);
        assert!(system.is_some());
        assert!(llm_msgs.is_empty());
    }

    // ============== call_llm_provider Tests ==============

    use crate::agent::AgentError;
    use async_trait::async_trait;
    use tokio::sync::mpsc;

    /// Mock LLM provider for OpenAI endpoint tests.
    struct MockLlmProvider {
        events: parking_lot::Mutex<Vec<StreamEvent>>,
    }

    impl MockLlmProvider {
        fn with_events(events: Vec<StreamEvent>) -> Self {
            Self {
                events: parking_lot::Mutex::new(events),
            }
        }

        fn text_response(text: &str, input_tokens: u64, output_tokens: u64) -> Self {
            Self::with_events(vec![
                StreamEvent::TextDelta {
                    text: text.to_string(),
                },
                StreamEvent::Stop {
                    reason: StopReason::EndTurn,
                    usage: TokenUsage {
                        input_tokens,
                        output_tokens,
                    },
                },
            ])
        }

        fn error_response(message: &str) -> Self {
            Self::with_events(vec![StreamEvent::Error {
                message: message.to_string(),
            }])
        }
    }

    #[async_trait]
    impl LlmProvider for MockLlmProvider {
        async fn complete(
            &self,
            _request: CompletionRequest,
        ) -> Result<mpsc::Receiver<StreamEvent>, AgentError> {
            let events = {
                let lock = self.events.lock();
                lock.clone()
            };
            let (tx, rx) = mpsc::channel(64);
            tokio::spawn(async move {
                for event in events {
                    let _ = tx.send(event).await;
                }
            });
            Ok(rx)
        }
    }

    #[tokio::test]
    async fn test_call_llm_provider_text_response() {
        let provider = MockLlmProvider::text_response("Hello from LLM!", 50, 10);
        let messages = vec![LlmMessage {
            role: LlmRole::User,
            content: vec![ContentBlock::Text {
                text: "Hi".to_string(),
            }],
        }];

        let result = call_llm_provider(&provider, "claude-sonnet-4-20250514", None, messages).await;
        assert!(result.is_ok());
        let (text, usage) = result.unwrap();
        assert_eq!(text, "Hello from LLM!");
        assert_eq!(usage.input_tokens, 50);
        assert_eq!(usage.output_tokens, 10);
    }

    #[tokio::test]
    async fn test_call_llm_provider_error_response() {
        let provider = MockLlmProvider::error_response("Rate limited");
        let messages = vec![LlmMessage {
            role: LlmRole::User,
            content: vec![ContentBlock::Text {
                text: "Hi".to_string(),
            }],
        }];

        let result = call_llm_provider(&provider, "claude-sonnet-4-20250514", None, messages).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Rate limited");
    }

    #[tokio::test]
    async fn test_call_llm_provider_multi_delta() {
        let provider = MockLlmProvider::with_events(vec![
            StreamEvent::TextDelta {
                text: "Hello ".to_string(),
            },
            StreamEvent::TextDelta {
                text: "world!".to_string(),
            },
            StreamEvent::Stop {
                reason: StopReason::EndTurn,
                usage: TokenUsage {
                    input_tokens: 20,
                    output_tokens: 5,
                },
            },
        ]);
        let messages = vec![LlmMessage {
            role: LlmRole::User,
            content: vec![ContentBlock::Text {
                text: "Test".to_string(),
            }],
        }];

        let result = call_llm_provider(&provider, "claude-sonnet-4-20250514", None, messages).await;
        assert!(result.is_ok());
        let (text, _) = result.unwrap();
        assert_eq!(text, "Hello world!");
    }

    #[tokio::test]
    async fn test_call_llm_provider_with_system() {
        let provider = MockLlmProvider::text_response("I'm helpful!", 30, 5);
        let messages = vec![LlmMessage {
            role: LlmRole::User,
            content: vec![ContentBlock::Text {
                text: "Hi".to_string(),
            }],
        }];

        let result = call_llm_provider(
            &provider,
            "claude-sonnet-4-20250514",
            Some("You are helpful".to_string()),
            messages,
        )
        .await;
        assert!(result.is_ok());
        let (text, _) = result.unwrap();
        assert_eq!(text, "I'm helpful!");
    }

    // ============== Handler integration tests ==============

    #[tokio::test]
    async fn test_chat_completions_no_provider_returns_503() {
        let state = OpenAiState {
            chat_completions_enabled: true,
            llm_provider: None,
            gateway_token: Some("test-token".to_string()),
            ..Default::default()
        };

        let body = serde_json::to_vec(&serde_json::json!({
            "messages": [{"role": "user", "content": "Hello"}]
        }))
        .unwrap();

        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Bearer test-token".parse().unwrap());

        let response =
            chat_completions_handler(State(state), headers, axum::body::Bytes::from(body)).await;

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn test_chat_completions_non_streaming_with_provider() {
        let provider = Arc::new(MockLlmProvider::text_response("LLM response", 100, 25));
        let state = OpenAiState {
            chat_completions_enabled: true,
            llm_provider: Some(provider),
            gateway_token: Some("test-token".to_string()),
            ..Default::default()
        };

        let body = serde_json::to_vec(&serde_json::json!({
            "messages": [
                {"role": "system", "content": "Be helpful"},
                {"role": "user", "content": "Hello"}
            ]
        }))
        .unwrap();

        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Bearer test-token".parse().unwrap());

        let response =
            chat_completions_handler(State(state), headers, axum::body::Bytes::from(body)).await;

        assert_eq!(response.status(), StatusCode::OK);

        // Parse response body
        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

        assert_eq!(parsed["object"], "chat.completion");
        assert!(parsed["id"].as_str().unwrap().starts_with("chatcmpl_"));
        assert_eq!(parsed["choices"][0]["message"]["role"], "assistant");
        assert_eq!(parsed["choices"][0]["message"]["content"], "LLM response");
        assert_eq!(parsed["choices"][0]["finish_reason"], "stop");
        assert_eq!(parsed["usage"]["prompt_tokens"], 100);
        assert_eq!(parsed["usage"]["completion_tokens"], 25);
        assert_eq!(parsed["usage"]["total_tokens"], 125);
    }

    #[tokio::test]
    async fn test_chat_completions_moltbot_model_maps_to_default() {
        let provider = Arc::new(MockLlmProvider::text_response("ok", 10, 5));
        let state = OpenAiState {
            chat_completions_enabled: true,
            llm_provider: Some(provider),
            gateway_token: Some("test-token".to_string()),
            ..Default::default()
        };

        let body = serde_json::to_vec(&serde_json::json!({
            "model": "moltbot",
            "messages": [{"role": "user", "content": "test"}]
        }))
        .unwrap();

        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Bearer test-token".parse().unwrap());

        let response =
            chat_completions_handler(State(state), headers, axum::body::Bytes::from(body)).await;

        assert_eq!(response.status(), StatusCode::OK);

        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

        // Model should be mapped from "moltbot" to the default model
        assert_eq!(parsed["model"], crate::agent::DEFAULT_MODEL);
    }

    #[tokio::test]
    async fn test_chat_completions_provider_error_returns_500() {
        let provider = Arc::new(MockLlmProvider::error_response("API overloaded"));
        let state = OpenAiState {
            chat_completions_enabled: true,
            llm_provider: Some(provider),
            gateway_token: Some("test-token".to_string()),
            ..Default::default()
        };

        let body = serde_json::to_vec(&serde_json::json!({
            "messages": [{"role": "user", "content": "Hello"}]
        }))
        .unwrap();

        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Bearer test-token".parse().unwrap());

        let response =
            chat_completions_handler(State(state), headers, axum::body::Bytes::from(body)).await;

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);

        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(parsed["error"]["type"], "api_error");
        assert!(parsed["error"]["message"]
            .as_str()
            .unwrap()
            .contains("API overloaded"));
    }

    #[tokio::test]
    async fn test_chat_completions_streaming_with_provider() {
        let provider = Arc::new(MockLlmProvider::with_events(vec![
            StreamEvent::TextDelta {
                text: "Hello ".to_string(),
            },
            StreamEvent::TextDelta {
                text: "world!".to_string(),
            },
            StreamEvent::Stop {
                reason: StopReason::EndTurn,
                usage: TokenUsage {
                    input_tokens: 10,
                    output_tokens: 5,
                },
            },
        ]));
        let state = OpenAiState {
            chat_completions_enabled: true,
            llm_provider: Some(provider),
            gateway_token: Some("test-token".to_string()),
            ..Default::default()
        };

        let body = serde_json::to_vec(&serde_json::json!({
            "messages": [{"role": "user", "content": "Hello"}],
            "stream": true
        }))
        .unwrap();

        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Bearer test-token".parse().unwrap());

        let response =
            chat_completions_handler(State(state), headers, axum::body::Bytes::from(body)).await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get("content-type").unwrap(),
            "text/event-stream; charset=utf-8"
        );

        // Read all stream data
        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body_str = String::from_utf8(body_bytes.to_vec()).unwrap();

        // Should have role chunk, text chunks, stop chunk, and [DONE]
        assert!(body_str.contains("\"role\":\"assistant\""));
        assert!(body_str.contains("Hello "));
        assert!(body_str.contains("world!"));
        assert!(body_str.contains("\"finish_reason\":\"stop\""));
        assert!(body_str.contains("data: [DONE]"));
    }

    #[tokio::test]
    async fn test_chat_completions_only_system_messages_returns_400() {
        let provider = Arc::new(MockLlmProvider::text_response("should not reach", 0, 0));
        let state = OpenAiState {
            chat_completions_enabled: true,
            llm_provider: Some(provider),
            gateway_token: Some("test-token".to_string()),
            ..Default::default()
        };

        // Only system message, no user message
        let body = serde_json::to_vec(&serde_json::json!({
            "messages": [{"role": "system", "content": "Be helpful"}]
        }))
        .unwrap();

        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Bearer test-token".parse().unwrap());

        let response =
            chat_completions_handler(State(state), headers, axum::body::Bytes::from(body)).await;

        // Should fail because there's no user message
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}
