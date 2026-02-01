//! HTTP endpoints integration tests
//!
//! Tests for the HTTP gateway endpoints including:
//! - Hook mappings and dispatch
//! - Tools invoke endpoint
//! - OpenAI compatibility endpoints
//! - Control endpoints

use axum::extract::ConnectInfo;
use carapace::auth::AuthMode;
use carapace::channels::{ChannelInfo, ChannelRegistry, ChannelStatus};
use carapace::hooks::{
    HookAction, HookMapping, HookMappingContext, HookMappingResult, HookRegistry,
};
use carapace::plugins::{ToolInvokeContext, ToolInvokeResult, ToolsRegistry};
use serde_json::json;
use std::collections::HashMap;
use std::net::SocketAddr;

fn loopback_connect_info() -> Option<ConnectInfo<SocketAddr>> {
    Some(ConnectInfo("127.0.0.1:1234".parse().unwrap()))
}

// ============================================================================
// Hook Registry Tests
// ============================================================================

#[test]
fn test_hook_registry_register_and_find() {
    let registry = HookRegistry::new();

    registry.register(HookMapping::new("github").with_path("github"));
    registry.register(HookMapping::new("gitlab").with_path("gitlab"));

    assert_eq!(registry.len(), 2);

    let ctx = HookMappingContext {
        path: "github".to_string(),
        headers: HashMap::new(),
        payload: json!({}),
        query: None,
        now: "2024-01-01T00:00:00Z".to_string(),
    };

    let matched = registry.find_match(&ctx);
    assert!(matched.is_some());
    assert_eq!(matched.unwrap().id, Some("github".to_string()));
}

#[test]
fn test_hook_registry_source_matching() {
    let registry = HookRegistry::new();

    registry.register(
        HookMapping::new("stripe")
            .with_path("events")
            .with_source("stripe"),
    );
    registry.register(
        HookMapping::new("github")
            .with_path("events")
            .with_source("github"),
    );

    // Stripe event
    let ctx = HookMappingContext {
        path: "events".to_string(),
        headers: HashMap::new(),
        payload: json!({ "source": "stripe", "type": "payment.succeeded" }),
        query: None,
        now: "2024-01-01T00:00:00Z".to_string(),
    };
    let matched = registry.find_match(&ctx);
    assert_eq!(matched.unwrap().id, Some("stripe".to_string()));

    // GitHub event
    let ctx2 = HookMappingContext {
        path: "events".to_string(),
        headers: HashMap::new(),
        payload: json!({ "source": "github", "action": "push" }),
        query: None,
        now: "2024-01-01T00:00:00Z".to_string(),
    };
    let matched2 = registry.find_match(&ctx2);
    assert_eq!(matched2.unwrap().id, Some("github".to_string()));
}

#[test]
fn test_hook_registry_evaluate_agent() {
    let registry = HookRegistry::new();

    let mapping = HookMapping::new("github")
        .with_path("github")
        .with_action(HookAction::Agent)
        .with_message_template("GitHub {{action}}: {{repository.full_name}}");

    let ctx = HookMappingContext {
        path: "github".to_string(),
        headers: HashMap::new(),
        payload: json!({
            "action": "push",
            "repository": { "full_name": "user/repo" }
        }),
        query: None,
        now: "2024-01-01T00:00:00Z".to_string(),
    };

    let result = registry.evaluate(&mapping, &ctx).unwrap();
    match result {
        HookMappingResult::Agent { message, .. } => {
            assert_eq!(message, "GitHub push: user/repo");
        }
        _ => panic!("Expected Agent result"),
    }
}

#[test]
fn test_hook_registry_evaluate_wake() {
    let registry = HookRegistry::new();

    let mapping = HookMapping::new("trigger")
        .with_path("trigger")
        .with_action(HookAction::Wake)
        .with_text_template("Wake: {{reason}}");

    let ctx = HookMappingContext {
        path: "trigger".to_string(),
        headers: HashMap::new(),
        payload: json!({ "reason": "scheduled task" }),
        query: None,
        now: "2024-01-01T00:00:00Z".to_string(),
    };

    let result = registry.evaluate(&mapping, &ctx).unwrap();
    match result {
        HookMappingResult::Wake { text, mode } => {
            assert_eq!(text, "Wake: scheduled task");
            assert_eq!(mode, "now");
        }
        _ => panic!("Expected Wake result"),
    }
}

#[test]
fn test_hook_registry_template_array_access() {
    let registry = HookRegistry::new();

    let mapping = HookMapping::new("batch")
        .with_message_template("First: {{items[0].name}}, Second: {{items[1].name}}");

    let ctx = HookMappingContext {
        path: "batch".to_string(),
        headers: HashMap::new(),
        payload: json!({
            "items": [
                { "name": "Alpha" },
                { "name": "Beta" }
            ]
        }),
        query: None,
        now: "2024-01-01T00:00:00Z".to_string(),
    };

    let result = registry.evaluate(&mapping, &ctx).unwrap();
    match result {
        HookMappingResult::Agent { message, .. } => {
            assert_eq!(message, "First: Alpha, Second: Beta");
        }
        _ => panic!("Expected Agent result"),
    }
}

#[test]
fn test_hook_registry_template_header_access() {
    let registry = HookRegistry::new();

    let mapping = HookMapping::new("notify")
        .with_message_template("From: {{headers.x-source}} - {{message}}");

    let mut headers = HashMap::new();
    headers.insert("x-source".to_string(), "monitoring-system".to_string());

    let ctx = HookMappingContext {
        path: "notify".to_string(),
        headers,
        payload: json!({ "message": "Alert triggered" }),
        query: None,
        now: "2024-01-01T00:00:00Z".to_string(),
    };

    let result = registry.evaluate(&mapping, &ctx).unwrap();
    match result {
        HookMappingResult::Agent { message, .. } => {
            assert_eq!(message, "From: monitoring-system - Alert triggered");
        }
        _ => panic!("Expected Agent result"),
    }
}

#[test]
fn test_hook_registry_preset() {
    let registry = HookRegistry::new();
    assert!(registry.is_empty());

    assert!(registry.enable_preset("gmail"));
    assert_eq!(registry.len(), 1);

    let ctx = HookMappingContext {
        path: "gmail".to_string(),
        headers: HashMap::new(),
        payload: json!({}),
        query: None,
        now: "2024-01-01T00:00:00Z".to_string(),
    };

    let matched = registry.find_match(&ctx);
    assert!(matched.is_some());
    assert_eq!(matched.unwrap().id, Some("preset:gmail".to_string()));
}

// ============================================================================
// Tools Registry Tests
// ============================================================================

#[test]
fn test_tools_registry_builtin_time() {
    let registry = ToolsRegistry::new();

    assert!(registry.has_tool("time"));

    let ctx = ToolInvokeContext::default();
    let result = registry.invoke("time", json!({}), &ctx);

    match result {
        ToolInvokeResult::Success { ok, result } => {
            assert!(ok);
            assert!(result.get("timestamp").is_some());
            assert!(result.get("timezone").is_some());
            assert_eq!(result["timezone"], "UTC");
        }
        _ => panic!("Expected success result"),
    }
}

#[test]
fn test_tools_registry_not_found() {
    let registry = ToolsRegistry::new();
    let ctx = ToolInvokeContext::default();

    let result = registry.invoke("nonexistent_tool", json!({}), &ctx);

    match result {
        ToolInvokeResult::Error { ok, error } => {
            assert!(!ok);
            assert_eq!(error.r#type, "not_found");
            assert!(error.message.contains("nonexistent_tool"));
        }
        _ => panic!("Expected error result"),
    }
}

#[test]
fn test_tools_registry_allowlist() {
    let registry = ToolsRegistry::new();

    // All tools allowed by default
    assert!(registry.has_tool("time"));

    // Set allowlist to exclude time
    registry.set_allowlist(vec!["other_tool".to_string()]);
    assert!(!registry.has_tool("time"));

    // Add time to allowlist
    registry.set_allowlist(vec!["time".to_string()]);
    assert!(registry.has_tool("time"));
}

#[test]
fn test_tools_registry_list() {
    let registry = ToolsRegistry::new();
    let tools = registry.list_tools();

    assert!(!tools.is_empty());
    assert!(tools.iter().any(|t| t.name == "time"));
}

// ============================================================================
// Channel Registry Tests
// ============================================================================

#[test]
fn test_channel_registry_register() {
    let registry = ChannelRegistry::new();
    assert!(registry.is_empty());

    registry.register(ChannelInfo::new("telegram", "Telegram"));
    registry.register(ChannelInfo::new("discord", "Discord"));

    assert_eq!(registry.len(), 2);
    assert!(registry.get("telegram").is_some());
    assert!(registry.get("discord").is_some());
}

#[test]
fn test_channel_registry_status_update() {
    let registry = ChannelRegistry::new();
    registry.register(ChannelInfo::new("telegram", "Telegram"));

    assert_eq!(
        registry.get_status("telegram"),
        Some(ChannelStatus::Disconnected)
    );

    registry.update_status("telegram", ChannelStatus::Connected);
    assert_eq!(
        registry.get_status("telegram"),
        Some(ChannelStatus::Connected)
    );
    assert!(registry.is_connected("telegram"));
}

#[test]
fn test_channel_registry_snapshot() {
    let registry = ChannelRegistry::new();
    registry
        .register(ChannelInfo::new("telegram", "Telegram").with_status(ChannelStatus::Connected));
    registry.register(ChannelInfo::new("discord", "Discord"));

    let snapshot = registry.snapshot();
    assert_eq!(snapshot.channels.len(), 2);
    assert!(snapshot.timestamp > 0);
}

#[test]
fn test_channel_registry_count_by_status() {
    let registry = ChannelRegistry::new();
    registry
        .register(ChannelInfo::new("telegram", "Telegram").with_status(ChannelStatus::Connected));
    registry.register(ChannelInfo::new("discord", "Discord").with_status(ChannelStatus::Connected));
    registry.register(ChannelInfo::new("slack", "Slack").with_status(ChannelStatus::Error));

    assert_eq!(registry.count_by_status(ChannelStatus::Connected), 2);
    assert_eq!(registry.count_by_status(ChannelStatus::Error), 1);
    assert_eq!(registry.count_by_status(ChannelStatus::Disconnected), 0);
}

// ============================================================================
// OpenResponses /v1/responses Integration Tests
// ============================================================================

use async_trait::async_trait;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use carapace::agent::provider::{CompletionRequest, StopReason, StreamEvent, TokenUsage};
use carapace::agent::{AgentError, LlmProvider};
use carapace::server::openai::{responses_handler, OpenAiState};

/// A mock LLM provider that returns a fixed text response.
struct MockLlmProvider;

#[async_trait]
impl LlmProvider for MockLlmProvider {
    async fn complete(
        &self,
        _request: CompletionRequest,
        _cancel_token: CancellationToken,
    ) -> Result<mpsc::Receiver<StreamEvent>, AgentError> {
        let (tx, rx) = mpsc::channel(8);
        tokio::spawn(async move {
            let _ = tx
                .send(StreamEvent::TextDelta {
                    text: "Mock response from LLM.".to_string(),
                })
                .await;
            let _ = tx
                .send(StreamEvent::Stop {
                    reason: StopReason::EndTurn,
                    usage: TokenUsage {
                        input_tokens: 10,
                        output_tokens: 5,
                    },
                })
                .await;
        });
        Ok(rx)
    }
}

/// Helper: build an `OpenAiState` with the responses endpoint enabled, a
/// gateway token configured for authentication, and a mock LLM provider.
fn responses_state_enabled() -> OpenAiState {
    OpenAiState {
        responses_enabled: true,
        gateway_token: Some("test-token".to_string()),
        llm_provider: Some(Arc::new(MockLlmProvider)),
        ..Default::default()
    }
}

/// Helper: build an `OpenAiState` with the responses endpoint enabled and a
/// gateway token but NO LLM provider (for testing validation paths that fail
/// before the provider is needed).
fn responses_state_enabled_no_provider() -> OpenAiState {
    OpenAiState {
        responses_enabled: true,
        gateway_token: Some("test-token".to_string()),
        ..Default::default()
    }
}

/// Helper: build an `OpenAiState` with the responses endpoint disabled.
fn responses_state_disabled() -> OpenAiState {
    OpenAiState {
        responses_enabled: false,
        gateway_token: Some("test-token".to_string()),
        ..Default::default()
    }
}

/// Helper: create a `HeaderMap` with a valid Bearer auth header.
fn auth_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert("authorization", "Bearer test-token".parse().unwrap());
    headers
}

// --- Disabled endpoint returns 404 ---

#[tokio::test]
async fn test_responses_disabled_returns_404() {
    let state = responses_state_disabled();
    let body = serde_json::to_vec(&json!({
        "model": "carapace",
        "input": "Hello"
    }))
    .unwrap();

    let response = responses_handler(
        State(state),
        loopback_connect_info(),
        auth_headers(),
        axum::body::Bytes::from(body),
    )
    .await;

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

// --- Authentication required (401 without token) ---

#[tokio::test]
async fn test_responses_no_auth_returns_401() {
    let state = responses_state_enabled();
    let body = serde_json::to_vec(&json!({
        "model": "carapace",
        "input": "Hello"
    }))
    .unwrap();

    // No Authorization header
    let headers = HeaderMap::new();
    let response = responses_handler(
        State(state),
        loopback_connect_info(),
        headers,
        axum::body::Bytes::from(body),
    )
    .await;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let parsed: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(parsed["error"]["type"], "unauthorized");
}

#[tokio::test]
async fn test_responses_wrong_token_returns_401() {
    let state = responses_state_enabled();
    let body = serde_json::to_vec(&json!({
        "model": "carapace",
        "input": "Hello"
    }))
    .unwrap();

    let mut headers = HeaderMap::new();
    headers.insert("authorization", "Bearer wrong-token".parse().unwrap());

    let response = responses_handler(
        State(state),
        loopback_connect_info(),
        headers,
        axum::body::Bytes::from(body),
    )
    .await;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

// --- Basic request/response cycle (text input) ---

#[tokio::test]
async fn test_responses_basic_text_input() {
    let state = responses_state_enabled();
    let body = serde_json::to_vec(&json!({
        "model": "carapace",
        "input": "Hello, how are you?"
    }))
    .unwrap();

    let response = responses_handler(
        State(state),
        loopback_connect_info(),
        auth_headers(),
        axum::body::Bytes::from(body),
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);

    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let parsed: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

    // Verify response shape
    assert_eq!(parsed["object"], "response");
    assert_eq!(parsed["status"], "completed");
    // "carapace" is mapped to the default model by the handler
    assert!(parsed["model"].as_str().is_some());
    assert!(parsed["id"].as_str().unwrap().starts_with("resp_"));
    assert!(parsed["created_at"].as_i64().is_some());

    // Verify output array has a message
    let output = parsed["output"].as_array().unwrap();
    assert!(!output.is_empty());
    assert_eq!(output[0]["type"], "message");
    assert_eq!(output[0]["role"], "assistant");
    assert_eq!(output[0]["status"], "completed");
    assert!(output[0]["id"].as_str().unwrap().starts_with("msg_"));

    // Verify content array has output_text
    let content = output[0]["content"].as_array().unwrap();
    assert!(!content.is_empty());
    assert_eq!(content[0]["type"], "output_text");
    assert!(!content[0]["text"].as_str().unwrap().is_empty());

    // Verify usage fields are present
    assert!(parsed["usage"]["input_tokens"].as_i64().is_some());
    assert!(parsed["usage"]["output_tokens"].as_i64().is_some());
    assert!(parsed["usage"]["total_tokens"].as_i64().is_some());

    // Verify error is absent
    assert!(parsed["error"].is_null() || parsed.get("error").is_none());
}

// --- Basic request/response cycle (items input with user message) ---

#[tokio::test]
async fn test_responses_items_input_with_user_message() {
    let state = responses_state_enabled();
    let body = serde_json::to_vec(&json!({
        "model": "carapace",
        "input": [
            { "type": "message", "role": "user", "content": "What is 2+2?" }
        ]
    }))
    .unwrap();

    let response = responses_handler(
        State(state),
        loopback_connect_info(),
        auth_headers(),
        axum::body::Bytes::from(body),
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);

    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let parsed: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

    assert_eq!(parsed["object"], "response");
    assert_eq!(parsed["status"], "completed");
    assert!(!parsed["output"].as_array().unwrap().is_empty());
}

// --- Request validation: missing required fields returns 400 ---

#[tokio::test]
async fn test_responses_missing_model_returns_400() {
    let state = responses_state_enabled_no_provider();
    // Missing "model" field entirely
    let body = serde_json::to_vec(&json!({
        "input": "Hello"
    }))
    .unwrap();

    let response = responses_handler(
        State(state),
        loopback_connect_info(),
        auth_headers(),
        axum::body::Bytes::from(body),
    )
    .await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let parsed: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(parsed["error"]["type"], "invalid_request_error");
}

#[tokio::test]
async fn test_responses_missing_input_returns_400() {
    let state = responses_state_enabled_no_provider();
    // Missing "input" field entirely
    let body = serde_json::to_vec(&json!({
        "model": "carapace"
    }))
    .unwrap();

    let response = responses_handler(
        State(state),
        loopback_connect_info(),
        auth_headers(),
        axum::body::Bytes::from(body),
    )
    .await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let parsed: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(parsed["error"]["type"], "invalid_request_error");
}

#[tokio::test]
async fn test_responses_invalid_json_returns_400() {
    let state = responses_state_enabled_no_provider();
    let body = b"not valid json at all".to_vec();

    let response = responses_handler(
        State(state),
        loopback_connect_info(),
        auth_headers(),
        axum::body::Bytes::from(body),
    )
    .await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let parsed: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(parsed["error"]["type"], "invalid_request_error");
    assert!(parsed["error"]["message"]
        .as_str()
        .unwrap()
        .contains("Invalid JSON"));
}

#[tokio::test]
async fn test_responses_empty_body_returns_400() {
    let state = responses_state_enabled_no_provider();
    let body = Vec::new();

    let response = responses_handler(
        State(state),
        loopback_connect_info(),
        auth_headers(),
        axum::body::Bytes::from(body),
    )
    .await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

// --- Items input without user message returns 400 ---

#[tokio::test]
async fn test_responses_items_no_user_message_returns_400() {
    let state = responses_state_enabled_no_provider();
    // Items array with only a system message, no user message
    let body = serde_json::to_vec(&json!({
        "model": "carapace",
        "input": [
            { "type": "message", "role": "system", "content": "Be concise" }
        ]
    }))
    .unwrap();

    let response = responses_handler(
        State(state),
        loopback_connect_info(),
        auth_headers(),
        axum::body::Bytes::from(body),
    )
    .await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let parsed: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(parsed["error"]["type"], "invalid_request_error");
    assert!(parsed["error"]["message"]
        .as_str()
        .unwrap()
        .contains("user message"));
}

// --- tool_choice validation ---

#[tokio::test]
async fn test_responses_tool_choice_required_without_tools_returns_400() {
    let state = responses_state_enabled_no_provider();
    let body = serde_json::to_vec(&json!({
        "model": "carapace",
        "input": "Hello",
        "tool_choice": "required"
    }))
    .unwrap();

    let response = responses_handler(
        State(state),
        loopback_connect_info(),
        auth_headers(),
        axum::body::Bytes::from(body),
    )
    .await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let parsed: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(parsed["error"]["type"], "invalid_request_error");
    assert!(parsed["error"]["message"]
        .as_str()
        .unwrap()
        .contains("tool_choice"));
}

#[tokio::test]
async fn test_responses_tool_choice_unknown_function_returns_400() {
    let state = responses_state_enabled_no_provider();
    let body = serde_json::to_vec(&json!({
        "model": "carapace",
        "input": "Hello",
        "tools": [
            {
                "type": "function",
                "function": {
                    "name": "get_weather",
                    "description": "Get weather"
                }
            }
        ],
        "tool_choice": {
            "type": "function",
            "function": { "name": "nonexistent_tool" }
        }
    }))
    .unwrap();

    let response = responses_handler(
        State(state),
        loopback_connect_info(),
        auth_headers(),
        axum::body::Bytes::from(body),
    )
    .await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let parsed: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(parsed["error"]["type"], "invalid_request_error");
    assert!(parsed["error"]["message"]
        .as_str()
        .unwrap()
        .contains("nonexistent_tool"));
}

// --- Password-based auth works ---

#[tokio::test]
async fn test_responses_password_auth_accepted() {
    let state = OpenAiState {
        responses_enabled: true,
        gateway_auth_mode: AuthMode::Password,
        gateway_password: Some("my-secret".to_string()),
        llm_provider: Some(Arc::new(MockLlmProvider)),
        ..Default::default()
    };
    let body = serde_json::to_vec(&json!({
        "model": "carapace",
        "input": "Hello"
    }))
    .unwrap();

    let mut headers = HeaderMap::new();
    headers.insert("authorization", "Bearer my-secret".parse().unwrap());

    let response = responses_handler(
        State(state),
        loopback_connect_info(),
        headers,
        axum::body::Bytes::from(body),
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);
}

// --- Model passthrough ---

#[tokio::test]
async fn test_responses_model_echoed_in_response() {
    let state = responses_state_enabled();
    let body = serde_json::to_vec(&json!({
        "model": "custom-model-name",
        "input": "Hello"
    }))
    .unwrap();

    let response = responses_handler(
        State(state),
        loopback_connect_info(),
        auth_headers(),
        axum::body::Bytes::from(body),
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);

    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let parsed: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(parsed["model"], "custom-model-name");
}
