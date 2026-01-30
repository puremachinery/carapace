//! HTTP server implementation
//!
//! Implements:
//! - Hooks API (POST /hooks/wake, /hooks/agent, /hooks/<mapping>)
//! - Tools API (POST /tools/invoke)
//! - OpenAI compatibility (POST /v1/chat/completions, /v1/responses)
//! - Control endpoints (GET /control/status, /control/channels, POST /control/config)
//! - Control UI (static files + SPA fallback + avatar endpoint)
//! - Auth middleware (hooks token, gateway auth, loopback bypass)
//! - Security middleware (headers, CSRF, rate limiting)

use axum::{
    extract::{ConnectInfo, Path, Query, State},
    http::{header, HeaderMap, StatusCode, Uri},
    middleware,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::fs;
use tracing::debug;
use uuid::Uuid;

use crate::server::control::{self, ControlState};
use crate::server::csrf::{csrf_middleware, CsrfConfig, CsrfTokenStore};
use crate::server::headers::{security_headers_middleware, SecurityHeadersConfig};
use crate::server::openai::{self, OpenAiState};
use crate::server::ratelimit::{rate_limit_middleware, RateLimitConfig, RateLimiter};

use crate::auth;
use crate::channels::ChannelRegistry;
use crate::hooks::auth::{extract_hooks_token, validate_hooks_token};
use crate::hooks::handler::{
    validate_agent_request, validate_wake_request, AgentRequest, AgentResponse, HooksErrorResponse,
    WakeRequest, WakeResponse,
};
use crate::hooks::registry::{HookMappingContext, HookMappingResult, HookRegistry};
use crate::plugins::tools::{ToolInvokeContext, ToolInvokeResult, ToolsRegistry};
use crate::server::ws::WsServerState;

/// Default max body size for hooks (256KB)
pub const DEFAULT_MAX_BODY_BYTES: usize = 262144;

/// Default hooks base path
pub const DEFAULT_HOOKS_PATH: &str = "/hooks";

/// HTTP server configuration
#[derive(Debug, Clone)]
pub struct HttpConfig {
    /// Hooks token for authentication
    pub hooks_token: Option<String>,
    /// Whether hooks are enabled
    pub hooks_enabled: bool,
    /// Hooks base path (e.g., "/hooks")
    pub hooks_path: String,
    /// Max body size for hooks in bytes
    pub hooks_max_body_bytes: usize,
    /// Gateway auth token
    pub gateway_token: Option<String>,
    /// Gateway auth password
    pub gateway_password: Option<String>,
    /// Control UI base path (empty string or "/path")
    pub control_ui_base_path: String,
    /// Control UI enabled
    pub control_ui_enabled: bool,
    /// Path to control-ui dist directory
    pub control_ui_dist_path: PathBuf,
    /// Valid channels for agent requests
    pub valid_channels: Vec<String>,
    /// Agents directory for avatar resolution
    pub agents_dir: PathBuf,
    /// Whether OpenAI chat completions endpoint is enabled
    pub openai_chat_completions_enabled: bool,
    /// Whether OpenResponses endpoint is enabled
    pub openai_responses_enabled: bool,
    /// Whether control endpoints are enabled
    pub control_endpoints_enabled: bool,
}

impl Default for HttpConfig {
    fn default() -> Self {
        HttpConfig {
            hooks_token: None,
            hooks_enabled: false,
            hooks_path: DEFAULT_HOOKS_PATH.to_string(),
            hooks_max_body_bytes: DEFAULT_MAX_BODY_BYTES,
            gateway_token: None,
            gateway_password: None,
            control_ui_base_path: String::new(),
            control_ui_enabled: false,
            control_ui_dist_path: PathBuf::from("dist/control-ui"),
            valid_channels: Vec::new(),
            agents_dir: dirs::home_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join(".moltbot/agents"),
            openai_chat_completions_enabled: false,
            openai_responses_enabled: false,
            control_endpoints_enabled: false,
        }
    }
}

/// Build an `HttpConfig` from the loaded JSON configuration.
///
/// Maps gateway.* keys from config and checks environment variables
/// (MOLTBOT_GATEWAY_TOKEN, MOLTBOT_GATEWAY_PASSWORD) with env taking precedence.
pub fn build_http_config(cfg: &Value) -> HttpConfig {
    let gateway = cfg.get("gateway").and_then(|v| v.as_object());

    let hooks_obj = gateway
        .and_then(|g| g.get("hooks"))
        .and_then(|v| v.as_object());
    let auth_obj = gateway
        .and_then(|g| g.get("auth"))
        .and_then(|v| v.as_object());
    let control_ui_obj = gateway
        .and_then(|g| g.get("controlUi"))
        .and_then(|v| v.as_object());
    let openai_obj = gateway
        .and_then(|g| g.get("openai"))
        .and_then(|v| v.as_object());
    let control_obj = gateway
        .and_then(|g| g.get("control"))
        .and_then(|v| v.as_object());

    let hooks_enabled = hooks_obj
        .and_then(|h| h.get("enabled"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let hooks_token = hooks_obj
        .and_then(|h| h.get("token"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    // Auth: env vars take precedence over config
    let cfg_token = auth_obj
        .and_then(|a| a.get("token"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let cfg_password = auth_obj
        .and_then(|a| a.get("password"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let gateway_token = std::env::var("MOLTBOT_GATEWAY_TOKEN").ok().or(cfg_token);
    let gateway_password = std::env::var("MOLTBOT_GATEWAY_PASSWORD")
        .ok()
        .or(cfg_password);

    let control_ui_enabled = control_ui_obj
        .and_then(|c| c.get("enabled"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let control_ui_dist_path = control_ui_obj
        .and_then(|c| c.get("path"))
        .and_then(|v| v.as_str())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("dist/control-ui"));

    let openai_chat_completions_enabled = openai_obj
        .and_then(|o| o.get("chatCompletions"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let openai_responses_enabled = openai_obj
        .and_then(|o| o.get("responses"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let control_endpoints_enabled = control_obj
        .and_then(|c| c.get("enabled"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    HttpConfig {
        hooks_token,
        hooks_enabled,
        gateway_token,
        gateway_password,
        control_ui_enabled,
        control_ui_dist_path,
        openai_chat_completions_enabled,
        openai_responses_enabled,
        control_endpoints_enabled,
        ..Default::default()
    }
}

/// Shared state for HTTP handlers
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<HttpConfig>,
    /// Hook mappings registry
    pub hook_registry: Arc<HookRegistry>,
    /// Tools registry
    pub tools_registry: Arc<ToolsRegistry>,
    /// Channel registry
    pub channel_registry: Arc<ChannelRegistry>,
    /// Gateway start time (Unix timestamp)
    pub start_time: i64,
    /// WebSocket server state (for agent dispatch from hooks)
    pub ws_state: Option<Arc<WsServerState>>,
    /// Health checker for deep diagnostics
    pub health_checker: Option<Arc<crate::server::health::HealthChecker>>,
}

/// Middleware configuration for the HTTP server
#[derive(Debug, Clone)]
pub struct MiddlewareConfig {
    /// Security headers configuration
    pub security_headers: SecurityHeadersConfig,
    /// CSRF protection configuration
    pub csrf: CsrfConfig,
    /// Rate limiting configuration
    pub rate_limit: RateLimitConfig,
    /// Whether to enable security headers middleware
    pub enable_security_headers: bool,
    /// Whether to enable CSRF middleware
    pub enable_csrf: bool,
    /// Whether to enable rate limiting middleware
    pub enable_rate_limit: bool,
}

impl Default for MiddlewareConfig {
    fn default() -> Self {
        MiddlewareConfig {
            security_headers: SecurityHeadersConfig::default(),
            csrf: CsrfConfig::default(),
            rate_limit: RateLimitConfig::default(),
            enable_security_headers: true,
            enable_csrf: false, // Disabled by default for API compatibility
            enable_rate_limit: true,
        }
    }
}

impl MiddlewareConfig {
    /// Create a configuration with all middleware disabled (for testing)
    pub fn none() -> Self {
        MiddlewareConfig {
            security_headers: SecurityHeadersConfig::default(),
            csrf: CsrfConfig::default(),
            rate_limit: RateLimitConfig::default(),
            enable_security_headers: false,
            enable_csrf: false,
            enable_rate_limit: false,
        }
    }

    /// Create a configuration with all security middleware enabled
    pub fn full() -> Self {
        MiddlewareConfig {
            security_headers: SecurityHeadersConfig::default(),
            csrf: CsrfConfig::default(),
            rate_limit: RateLimitConfig::default(),
            enable_security_headers: true,
            enable_csrf: true,
            enable_rate_limit: true,
        }
    }
}

/// Create the HTTP router with all endpoints (without middleware)
pub fn create_router(config: HttpConfig) -> Router {
    create_router_with_middleware(config, MiddlewareConfig::none())
}

/// Create the HTTP router with all endpoints and middleware
pub fn create_router_with_middleware(
    config: HttpConfig,
    middleware_config: MiddlewareConfig,
) -> Router {
    create_router_with_state(
        config,
        middleware_config,
        Arc::new(HookRegistry::new()),
        Arc::new(ToolsRegistry::new()),
        Arc::new(ChannelRegistry::new()),
        None,
    )
}

/// Create the HTTP router with custom registries
pub fn create_router_with_state(
    config: HttpConfig,
    middleware_config: MiddlewareConfig,
    hook_registry: Arc<HookRegistry>,
    tools_registry: Arc<ToolsRegistry>,
    channel_registry: Arc<ChannelRegistry>,
    ws_state: Option<Arc<WsServerState>>,
) -> Router {
    let start_time = chrono::Utc::now().timestamp();

    // Extract LLM provider before moving ws_state into AppState
    let llm_provider = ws_state.as_ref().and_then(|ws| ws.llm_provider());

    // Build health checker if ws_state provides a state directory
    let health_checker = ws_state.as_ref().map(|_| {
        Arc::new(crate::server::health::HealthChecker::new(
            crate::server::ws::resolve_state_dir(),
        ))
    });

    let state = AppState {
        config: Arc::new(config.clone()),
        hook_registry,
        tools_registry,
        channel_registry: channel_registry.clone(),
        start_time,
        ws_state,
        health_checker,
    };

    let mut router: Router<AppState> = Router::new();

    // Hooks routes (when enabled)
    if config.hooks_enabled {
        let hooks_path = normalize_hooks_path(&config.hooks_path);
        router = router
            .route(&format!("{}/wake", hooks_path), post(hooks_wake_handler))
            .route(&format!("{}/agent", hooks_path), post(hooks_agent_handler))
            .route(
                &format!("{}/*path", hooks_path),
                post(hooks_mapping_handler),
            );
    }

    // Health checks (unauthenticated, always enabled)
    router = router
        .route("/health", get(health_handler))
        .route("/health/live", get(health_handler))
        .route("/health/ready", get(health_ready_handler));

    // Metrics (Prometheus scrape endpoint, unauthenticated)
    router = router.route("/metrics", get(crate::server::metrics::metrics_handler));

    // Tools API
    router = router.route("/tools/invoke", post(tools_invoke_handler));

    // OpenAI compatibility endpoints
    if config.openai_chat_completions_enabled || config.openai_responses_enabled {
        let openai_state = OpenAiState {
            chat_completions_enabled: config.openai_chat_completions_enabled,
            responses_enabled: config.openai_responses_enabled,
            gateway_token: config.gateway_token.clone(),
            gateway_password: config.gateway_password.clone(),
            llm_provider: llm_provider.clone(),
        };

        if config.openai_chat_completions_enabled {
            router =
                router.route(
                    "/v1/chat/completions",
                    post(move |headers, body| {
                        let state = openai_state.clone();
                        async move {
                            openai::chat_completions_handler(State(state), headers, body).await
                        }
                    }),
                );
        }

        let openai_state2 = OpenAiState {
            chat_completions_enabled: config.openai_chat_completions_enabled,
            responses_enabled: config.openai_responses_enabled,
            gateway_token: config.gateway_token.clone(),
            gateway_password: config.gateway_password.clone(),
            llm_provider,
        };

        if config.openai_responses_enabled {
            router = router.route(
                "/v1/responses",
                post(move |headers, body| {
                    let state = openai_state2.clone();
                    async move { openai::responses_handler(State(state), headers, body).await }
                }),
            );
        }
    }

    // Control endpoints
    if config.control_endpoints_enabled {
        let control_state = ControlState {
            gateway_token: config.gateway_token.clone(),
            gateway_password: config.gateway_password.clone(),
            channel_registry: channel_registry.clone(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            start_time,
        };

        let control_state_status = control_state.clone();
        let control_state_channels = control_state.clone();
        let control_state_config = control_state.clone();

        router = router
            .route(
                "/control/status",
                get(move |headers| {
                    let state = control_state_status.clone();
                    async move { control::status_handler(State(state), headers).await }
                }),
            )
            .route(
                "/control/channels",
                get(move |headers| {
                    let state = control_state_channels.clone();
                    async move { control::channels_handler(State(state), headers).await }
                }),
            )
            .route(
                "/control/config",
                post(move |headers, body| {
                    let state = control_state_config.clone();
                    async move { control::config_handler(State(state), headers, body).await }
                }),
            );
    }

    // Control UI routes (when enabled)
    if config.control_ui_enabled {
        let base = if config.control_ui_base_path.is_empty() {
            "/ui".to_string()
        } else {
            config.control_ui_base_path.clone()
        };

        router = router
            .route(&base, get(control_ui_redirect))
            .route(&format!("{}/", base), get(control_ui_index))
            .route(
                &format!("{}/__moltbot_avatar__/:agent_id", base),
                get(avatar_handler),
            )
            .route(&format!("{}/*path", base), get(control_ui_static));
    }

    // Convert to stateless Router and apply middleware layers
    // Order matters: last added = first executed
    // The order here is: rate_limit -> csrf -> security_headers -> handler
    let mut stateless_router: Router = router.with_state(state);

    // Rate limiting middleware (applied first to reject overloaded requests early)
    if middleware_config.enable_rate_limit {
        let limiter = RateLimiter::new(middleware_config.rate_limit);
        stateless_router = stateless_router.layer(middleware::from_fn_with_state(
            limiter,
            rate_limit_middleware,
        ));
    }

    // CSRF protection middleware
    if middleware_config.enable_csrf {
        let csrf_store = CsrfTokenStore::new(middleware_config.csrf);
        stateless_router =
            stateless_router.layer(middleware::from_fn_with_state(csrf_store, csrf_middleware));
    }

    // Security headers middleware (applied last, runs after handler)
    if middleware_config.enable_security_headers {
        let headers_config = Arc::new(middleware_config.security_headers);
        stateless_router = stateless_router.layer(middleware::from_fn_with_state(
            headers_config,
            security_headers_middleware,
        ));
    }

    stateless_router
}

/// Normalize hooks path (ensure leading slash, no trailing slash)
fn normalize_hooks_path(path: &str) -> String {
    let trimmed = path.trim();
    if trimmed.is_empty() || trimmed == "/" {
        return "/hooks".to_string();
    }
    let mut result = trimmed.to_string();
    if !result.starts_with('/') {
        result = format!("/{}", result);
    }
    if result.ends_with('/') {
        result.pop();
    }
    result
}

// ============================================================================
// Health Check
// ============================================================================

/// GET /health - Lightweight liveness probe for container orchestrators.
async fn health_handler(State(state): State<AppState>) -> Response {
    let uptime = chrono::Utc::now().timestamp() - state.start_time;
    (
        StatusCode::OK,
        Json(json!({
            "status": "ok",
            "version": env!("CARGO_PKG_VERSION"),
            "uptimeSeconds": uptime,
        })),
    )
        .into_response()
}

/// GET /health/ready - Readiness probe.
///
/// Checks that storage is writable and (if configured) LLM is reachable.
/// Returns 200 if ready, 503 if not.
async fn health_ready_handler(State(state): State<AppState>) -> Response {
    let uptime = chrono::Utc::now().timestamp() - state.start_time;
    let has_llm = state
        .ws_state
        .as_ref()
        .map(|ws| ws.llm_provider().is_some())
        .unwrap_or(false);

    let ready = state
        .health_checker
        .as_ref()
        .map(|hc| hc.is_ready(has_llm))
        .unwrap_or(true);

    let status_code = if ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };

    (
        status_code,
        Json(json!({
            "status": if ready { "ready" } else { "not_ready" },
            "version": env!("CARGO_PKG_VERSION"),
            "uptimeSeconds": uptime,
        })),
    )
        .into_response()
}

// ============================================================================
// Hooks Handlers
// ============================================================================

/// POST /hooks/wake - Wake event trigger
async fn hooks_wake_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    uri: Uri,
    body: axum::body::Bytes,
) -> Response {
    // Check auth
    if let Some(err) = check_hooks_auth(&state.config, &headers, &uri) {
        return err;
    }

    // Check body size
    if body.len() > state.config.hooks_max_body_bytes {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(HooksErrorResponse::new("payload too large")),
        )
            .into_response();
    }

    // Parse JSON body (empty body = empty object)
    let req: WakeRequest = if body.is_empty() {
        WakeRequest {
            text: None,
            mode: None,
        }
    } else {
        match serde_json::from_slice(&body) {
            Ok(r) => r,
            Err(e) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(HooksErrorResponse::new(&format!("SyntaxError: {}", e))),
                )
                    .into_response();
            }
        }
    };

    // Validate request
    match validate_wake_request(&req) {
        Ok(validated) => {
            // In real implementation, dispatch wake event here
            debug!(
                "Wake event: text='{}', mode={:?}",
                validated.text, validated.mode
            );
            (StatusCode::OK, Json(WakeResponse::success(validated.mode))).into_response()
        }
        Err(e) => (StatusCode::BAD_REQUEST, Json(WakeResponse::error(&e))).into_response(),
    }
}

/// POST /hooks/agent - Dispatch message to agent
async fn hooks_agent_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    uri: Uri,
    body: axum::body::Bytes,
) -> Response {
    // Check auth
    if let Some(err) = check_hooks_auth(&state.config, &headers, &uri) {
        return err;
    }

    // Check body size
    if body.len() > state.config.hooks_max_body_bytes {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(HooksErrorResponse::new("payload too large")),
        )
            .into_response();
    }

    // Parse JSON body
    let req: AgentRequest = if body.is_empty() {
        AgentRequest {
            message: None,
            name: None,
            channel: None,
            to: None,
            model: None,
            thinking: None,
            deliver: None,
            wake_mode: None,
            session_key: None,
            timeout_seconds: None,
            allow_unsafe_external_content: None,
        }
    } else {
        match serde_json::from_slice(&body) {
            Ok(r) => r,
            Err(e) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(HooksErrorResponse::new(&format!("SyntaxError: {}", e))),
                )
                    .into_response();
            }
        }
    };

    // Validate request
    let validated = match validate_agent_request(&req, &state.config.valid_channels) {
        Ok(v) => v,
        Err(e) => {
            return (StatusCode::BAD_REQUEST, Json(AgentResponse::error(&e))).into_response();
        }
    };

    let run_id = Uuid::new_v4().to_string();

    // Dispatch agent run if WsServerState is available
    let ws = match &state.ws_state {
        Some(ws) => ws.clone(),
        None => {
            debug!(
                "Agent job accepted (no runtime): message='{}', channel='{}', runId='{}'",
                validated.message, validated.channel, run_id
            );
            return (StatusCode::ACCEPTED, Json(AgentResponse::success(run_id))).into_response();
        }
    };

    // Append user message to session
    let session_key = &validated.session_key;
    let metadata = crate::sessions::SessionMetadata {
        channel: Some(validated.channel.clone()),
        ..Default::default()
    };
    let session = match ws
        .session_store()
        .get_or_create_session(session_key, metadata)
    {
        Ok(s) => s,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(AgentResponse::error(&format!("session error: {}", e))),
            )
                .into_response();
        }
    };

    if let Err(e) = ws
        .session_store()
        .append_message(crate::sessions::ChatMessage::user(
            session.id.clone(),
            &validated.message,
        ))
    {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(AgentResponse::error(&format!("session write error: {}", e))),
        )
            .into_response();
    }

    // Register the agent run
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    let cancel_token = tokio_util::sync::CancellationToken::new();
    let run = crate::server::ws::AgentRun {
        run_id: run_id.clone(),
        session_key: session.session_key.clone(),
        status: crate::server::ws::AgentRunStatus::Queued,
        message: validated.message.clone(),
        response: String::new(),
        error: None,
        created_at: now,
        started_at: None,
        completed_at: None,
        cancel_token: cancel_token.clone(),
        waiters: Vec::new(),
    };

    {
        let mut registry = ws.agent_run_registry.lock();
        registry.register(run);
    }

    // Spawn agent executor if LLM provider is configured
    if let Some(provider) = ws.llm_provider() {
        let config = crate::agent::AgentConfig {
            model: validated
                .model
                .clone()
                .unwrap_or_else(|| crate::agent::DEFAULT_MODEL.to_string()),
            deliver: validated.deliver,
            ..Default::default()
        };
        crate::agent::spawn_run(
            run_id.clone(),
            session.session_key.clone(),
            config,
            ws,
            provider,
            cancel_token,
        );
        debug!(
            "Agent job dispatched: message='{}', channel='{}', runId='{}'",
            validated.message, validated.channel, run_id
        );
    } else {
        debug!("Agent job queued (no LLM provider): runId='{}'", run_id);
    }

    (StatusCode::ACCEPTED, Json(AgentResponse::success(run_id))).into_response()
}

/// POST /hooks/<mapping> - Custom hook mappings
async fn hooks_mapping_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    uri: Uri,
    Path(path): Path<String>,
    body: axum::body::Bytes,
) -> Response {
    // Check auth
    if let Some(err) = check_hooks_auth(&state.config, &headers, &uri) {
        return err;
    }

    // Check body size
    if body.len() > state.config.hooks_max_body_bytes {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(HooksErrorResponse::new("payload too large")),
        )
            .into_response();
    }

    // Parse payload
    let payload: Value = if body.is_empty() {
        json!({})
    } else {
        match serde_json::from_slice(&body) {
            Ok(p) => p,
            Err(e) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(HooksErrorResponse::new(&format!("SyntaxError: {}", e))),
                )
                    .into_response();
            }
        }
    };

    // Build hook context
    let mut header_map: HashMap<String, String> = HashMap::new();
    for (key, value) in headers.iter() {
        if let Ok(v) = value.to_str() {
            header_map.insert(key.as_str().to_lowercase(), v.to_string());
        }
    }

    let ctx = HookMappingContext {
        path: path.clone(),
        headers: header_map,
        payload,
        query: uri.query().map(|s| s.to_string()),
        now: chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
    };

    // Look up matching mapping
    let mapping = match state.hook_registry.find_match(&ctx) {
        Some(m) => m,
        None => {
            debug!("No hook mapping found for path: {}", path);
            return (StatusCode::NOT_FOUND, "Not Found").into_response();
        }
    };

    debug!("Hook mapping found for path '{}': {:?}", path, mapping.id);

    // Evaluate the mapping
    match state.hook_registry.evaluate(&mapping, &ctx) {
        Ok(HookMappingResult::Skip) => {
            // Transform returned null - skip this webhook
            (StatusCode::NO_CONTENT, "").into_response()
        }
        Ok(HookMappingResult::Wake { text, mode }) => {
            debug!("Hook triggered wake: text='{}', mode='{}'", text, mode);
            (StatusCode::OK, Json(json!({ "ok": true, "mode": mode }))).into_response()
        }
        Ok(HookMappingResult::Agent {
            message,
            session_key,
            ..
        }) => {
            let run_id = Uuid::new_v4().to_string();
            debug!(
                "Hook triggered agent: message='{}', session_key='{}', runId='{}'",
                message, session_key, run_id
            );
            (
                StatusCode::ACCEPTED,
                Json(json!({ "ok": true, "runId": run_id })),
            )
                .into_response()
        }
        Err(e) => {
            let status = match &e {
                crate::hooks::HookMappingError::TransformError(_) => {
                    StatusCode::INTERNAL_SERVER_ERROR
                }
                _ => StatusCode::BAD_REQUEST,
            };
            (status, Json(json!({ "ok": false, "error": e.to_string() }))).into_response()
        }
    }
}

/// Check hooks authentication
fn check_hooks_auth(config: &HttpConfig, headers: &HeaderMap, uri: &Uri) -> Option<Response> {
    let configured_token = match &config.hooks_token {
        Some(t) if !t.is_empty() => t,
        _ => return Some(unauthorized_response()),
    };

    match extract_hooks_token(headers, uri) {
        Some((token, _deprecated)) => {
            if !validate_hooks_token(&token, configured_token) {
                Some(unauthorized_response())
            } else {
                None
            }
        }
        None => Some(unauthorized_response()),
    }
}

// ============================================================================
// Tools API
// ============================================================================

/// Request body for POST /tools/invoke
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolsInvokeRequest {
    pub tool: Option<String>,
    pub action: Option<String>,
    pub args: Option<Value>,
    pub session_key: Option<String>,
    pub dry_run: Option<bool>,
}

/// Response body for POST /tools/invoke
#[derive(Debug, Serialize)]
pub struct ToolsInvokeResponse {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ToolsError>,
}

/// Error details for tools API
#[derive(Debug, Serialize)]
pub struct ToolsError {
    pub r#type: String,
    pub message: String,
}

/// POST /tools/invoke - Tool invocation endpoint
async fn tools_invoke_handler(
    State(state): State<AppState>,
    connect_info: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    // Check gateway auth (requires loopback if no auth configured)
    // If ConnectInfo is unavailable (e.g., in tests), treat as non-loopback
    let remote_addr = connect_info.map(|ci| ci.0.ip());
    if let Some(err) = check_gateway_auth(&state.config, &headers, remote_addr) {
        return err;
    }

    // Parse JSON body
    let req: ToolsInvokeRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": {
                        "message": format!("Invalid JSON: {}", e),
                        "type": "invalid_request_error"
                    }
                })),
            )
                .into_response();
        }
    };

    // Validate tool name
    let tool_name = match &req.tool {
        Some(t) if !t.trim().is_empty() => t.trim().to_string(),
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": {
                        "message": "tools.invoke requires body.tool",
                        "type": "invalid_request_error"
                    }
                })),
            )
                .into_response();
        }
    };

    // Normalize args (non-object/array becomes empty object)
    let mut args = match &req.args {
        Some(Value::Object(obj)) => Value::Object(obj.clone()),
        _ => Value::Object(serde_json::Map::new()),
    };

    // If action is provided, merge it into args (if args has 'action' property in schema)
    if let Some(action) = &req.action {
        if let Value::Object(ref mut obj) = args {
            obj.insert("action".to_string(), Value::String(action.clone()));
        }
    }

    // Extract context from headers
    let message_channel = headers
        .get("x-moltbot-message-channel")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let account_id = headers
        .get("x-moltbot-account-id")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    // Build tool invoke context
    let ctx = ToolInvokeContext {
        agent_id: None,
        session_key: req.session_key.unwrap_or_else(|| "main".to_string()),
        message_channel,
        account_id,
        sandboxed: false,
        dry_run: req.dry_run.unwrap_or(false),
    };

    // Invoke the tool via the registry
    let result = state.tools_registry.invoke(&tool_name, args, &ctx);

    match result {
        ToolInvokeResult::Success { ok, result } => (
            StatusCode::OK,
            Json(ToolsInvokeResponse {
                ok,
                result: Some(result),
                error: None,
            }),
        )
            .into_response(),
        ToolInvokeResult::Error { ok, error } => {
            let status = if error.r#type == "not_found" {
                StatusCode::NOT_FOUND
            } else {
                StatusCode::BAD_REQUEST
            };
            (
                status,
                Json(ToolsInvokeResponse {
                    ok,
                    result: None,
                    error: Some(ToolsError {
                        r#type: error.r#type,
                        message: error.message,
                    }),
                }),
            )
                .into_response()
        }
    }
}

/// Get current UTC timestamp in ISO 8601 format
fn utc_now_iso8601() -> String {
    chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

/// Check gateway authentication
///
/// When token/password auth is configured, validates the provided credentials.
/// When no auth is configured, only allows requests from loopback addresses
/// (localhost) to prevent accidental exposure when binding to 0.0.0.0.
fn check_gateway_auth(
    config: &HttpConfig,
    headers: &HeaderMap,
    remote_addr: Option<IpAddr>,
) -> Option<Response> {
    // Extract bearer token
    let provided = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(|s| s.trim());

    // Check token auth
    if let Some(token) = &config.gateway_token {
        if !token.is_empty() {
            if let Some(provided) = provided {
                if auth::timing_safe_eq(provided, token) {
                    return None;
                }
            }
            return Some(unauthorized_response());
        }
    }

    // Check password auth
    if let Some(password) = &config.gateway_password {
        if !password.is_empty() {
            if let Some(provided) = provided {
                if auth::timing_safe_eq(provided, password) {
                    return None;
                }
            }
            return Some(unauthorized_response());
        }
    }

    // No auth configured - only allow loopback requests
    // This prevents accidental exposure when binding to 0.0.0.0
    if auth::is_loopback_request(remote_addr, headers) {
        return None;
    }

    // Non-loopback request without auth configured - reject
    Some(unauthorized_response())
}

/// Generate unauthorized response
fn unauthorized_response() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(json!({
            "error": {
                "message": "Unauthorized",
                "type": "unauthorized"
            }
        })),
    )
        .into_response()
}

// ============================================================================
// Control UI
// ============================================================================

/// Redirect from /ui to /ui/
async fn control_ui_redirect(State(state): State<AppState>) -> Response {
    let base = if state.config.control_ui_base_path.is_empty() {
        "/ui".to_string()
    } else {
        state.config.control_ui_base_path.clone()
    };
    (
        StatusCode::FOUND,
        [(header::LOCATION, format!("{}/", base))],
    )
        .into_response()
}

/// Serve index.html for /ui/
async fn control_ui_index(State(state): State<AppState>) -> Response {
    serve_index_html(&state).await
}

/// Serve static files or fallback to index.html
async fn control_ui_static(State(state): State<AppState>, Path(path): Path<String>) -> Response {
    let dist_path = &state.config.control_ui_dist_path;

    // Security: prevent path traversal
    let safe_path = path.trim_start_matches('/');
    if safe_path.contains("..") {
        return (StatusCode::NOT_FOUND, "Not Found").into_response();
    }

    let file_path = dist_path.join(safe_path);

    // Check if it's the avatar endpoint
    if safe_path.starts_with("__moltbot_avatar__/") {
        let agent_id = safe_path.trim_start_matches("__moltbot_avatar__/");
        return serve_avatar(&state, agent_id).await;
    }

    // Try to serve the file directly
    if file_path.is_file() {
        return serve_file(&file_path).await;
    }

    // SPA fallback: serve index.html for unknown paths
    serve_index_html(&state).await
}

/// Serve index.html with injected configuration
async fn serve_index_html(state: &AppState) -> Response {
    let dist_path = &state.config.control_ui_dist_path;
    let index_path = dist_path.join("index.html");

    if !index_path.is_file() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "Control UI assets not found. Run 'pnpm ui:build' to build the control UI.",
        )
            .into_response();
    }

    match fs::read_to_string(&index_path).await {
        Ok(content) => {
            // Inject runtime configuration
            let base_path = if state.config.control_ui_base_path.is_empty() {
                "/ui".to_string()
            } else {
                state.config.control_ui_base_path.clone()
            };

            let injected = content
                .replace("__MOLTBOT_CONTROL_UI_BASE_PATH__", &base_path)
                .replace("__MOLTBOT_ASSISTANT_NAME__", "Moltbot")
                .replace("__MOLTBOT_ASSISTANT_AVATAR__", "");

            (
                StatusCode::OK,
                [
                    (header::CONTENT_TYPE, "text/html; charset=utf-8"),
                    (header::CACHE_CONTROL, "no-cache"),
                ],
                injected,
            )
                .into_response()
        }
        Err(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            "Control UI assets not found",
        )
            .into_response(),
    }
}

/// Serve a static file
async fn serve_file(path: &std::path::Path) -> Response {
    let content_type = get_content_type(path);

    match fs::read(path).await {
        Ok(content) => (
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, content_type),
                (header::CACHE_CONTROL, "no-cache"),
            ],
            content,
        )
            .into_response(),
        Err(_) => (StatusCode::NOT_FOUND, "Not Found").into_response(),
    }
}

/// Get content type based on file extension
fn get_content_type(path: &std::path::Path) -> &'static str {
    match path.extension().and_then(|e| e.to_str()) {
        Some("html") => "text/html; charset=utf-8",
        Some("js") => "application/javascript; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("json") => "application/json; charset=utf-8",
        Some("map") => "application/json; charset=utf-8",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("jpg") | Some("jpeg") => "image/jpeg",
        Some("gif") => "image/gif",
        Some("webp") => "image/webp",
        Some("ico") => "image/x-icon",
        Some("txt") => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    }
}

/// Avatar query parameters
#[derive(Debug, Deserialize)]
pub struct AvatarQuery {
    pub meta: Option<String>,
}

/// GET /__moltbot_avatar__/:agent_id - Serve agent avatar
async fn avatar_handler(
    State(state): State<AppState>,
    Path(agent_id): Path<String>,
    Query(query): Query<AvatarQuery>,
) -> Response {
    // Validate agent ID format
    if !is_valid_agent_id(&agent_id) {
        return (StatusCode::NOT_FOUND, "Not Found").into_response();
    }

    // Check if requesting metadata
    if query.meta.as_deref() == Some("1") {
        return serve_avatar_metadata(&state, &agent_id).await;
    }

    serve_avatar(&state, &agent_id).await
}

/// Validate agent ID format: /^[a-z0-9][a-z0-9_-]{0,63}$/i
fn is_valid_agent_id(id: &str) -> bool {
    if id.is_empty() || id.len() > 64 {
        return false;
    }

    let mut chars = id.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphanumeric() => {}
        _ => return false,
    }

    chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

/// Serve avatar image
async fn serve_avatar(state: &AppState, agent_id: &str) -> Response {
    let agents_dir = &state.config.agents_dir;

    // Look for avatar files with common extensions
    for ext in &["png", "jpg", "jpeg", "gif", "webp"] {
        let avatar_path = agents_dir.join(agent_id).join(format!("avatar.{}", ext));
        if avatar_path.is_file() {
            return serve_file(&avatar_path).await;
        }
    }

    // Also check for avatar without extension (data: URIs are stored in config)
    (StatusCode::NOT_FOUND, "Not Found").into_response()
}

/// Serve avatar metadata
async fn serve_avatar_metadata(state: &AppState, agent_id: &str) -> Response {
    let agents_dir = &state.config.agents_dir;

    // Look for avatar files
    for ext in &["png", "jpg", "jpeg", "gif", "webp"] {
        let avatar_path = agents_dir.join(agent_id).join(format!("avatar.{}", ext));
        if avatar_path.is_file() {
            let base = if state.config.control_ui_base_path.is_empty() {
                "/ui".to_string()
            } else {
                state.config.control_ui_base_path.clone()
            };
            let url = format!("{}/__moltbot_avatar__/{}", base, agent_id);
            return (
                StatusCode::OK,
                [
                    (header::CONTENT_TYPE, "application/json; charset=utf-8"),
                    (header::CACHE_CONTROL, "no-cache"),
                ],
                Json(json!({ "avatarUrl": url })),
            )
                .into_response();
        }
    }

    // No avatar found
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/json; charset=utf-8"),
            (header::CACHE_CONTROL, "no-cache"),
        ],
        Json(json!({ "avatarUrl": null })),
    )
        .into_response()
}

// ============================================================================
// Loopback Detection
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    fn test_config() -> HttpConfig {
        HttpConfig {
            hooks_token: Some("test-hooks-token".to_string()),
            hooks_enabled: true,
            gateway_token: Some("test-gateway-token".to_string()),
            control_ui_enabled: true,
            ..Default::default()
        }
    }

    /// Create a test router that can be used with oneshot()
    fn test_router(config: HttpConfig) -> Router {
        create_router(config)
    }

    #[tokio::test]
    async fn test_hooks_wake_success() {
        let router = test_router(test_config());

        let req = Request::builder()
            .method("POST")
            .uri("/hooks/wake")
            .header("authorization", "Bearer test-hooks-token")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"text": "hello world"}"#))
            .unwrap();

        let response = router.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["ok"], true);
        assert_eq!(json["mode"], "now");
    }

    #[tokio::test]
    async fn test_hooks_wake_missing_text() {
        let router = test_router(test_config());

        let req = Request::builder()
            .method("POST")
            .uri("/hooks/wake")
            .header("authorization", "Bearer test-hooks-token")
            .header("content-type", "application/json")
            .body(Body::from(r#"{}"#))
            .unwrap();

        let response = router.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["ok"], false);
        assert_eq!(json["error"], "text required");
    }

    #[tokio::test]
    async fn test_hooks_wake_unauthorized() {
        let router = test_router(test_config());

        let req = Request::builder()
            .method("POST")
            .uri("/hooks/wake")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"text": "hello"}"#))
            .unwrap();

        let response = router.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_hooks_wake_wrong_token() {
        let router = test_router(test_config());

        let req = Request::builder()
            .method("POST")
            .uri("/hooks/wake")
            .header("authorization", "Bearer wrong-token")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"text": "hello"}"#))
            .unwrap();

        let response = router.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_hooks_agent_success() {
        let router = test_router(test_config());

        let req = Request::builder()
            .method("POST")
            .uri("/hooks/agent")
            .header("authorization", "Bearer test-hooks-token")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"message": "Do something"}"#))
            .unwrap();

        let response = router.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::ACCEPTED);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["ok"], true);
        assert!(json["runId"].as_str().is_some());
    }

    #[tokio::test]
    async fn test_hooks_agent_missing_message() {
        let router = test_router(test_config());

        let req = Request::builder()
            .method("POST")
            .uri("/hooks/agent")
            .header("authorization", "Bearer test-hooks-token")
            .header("content-type", "application/json")
            .body(Body::from(r#"{}"#))
            .unwrap();

        let response = router.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["ok"], false);
        assert_eq!(json["error"], "message required");
    }

    #[tokio::test]
    async fn test_tools_invoke_success() {
        let router = test_router(test_config());

        let req = Request::builder()
            .method("POST")
            .uri("/tools/invoke")
            .header("authorization", "Bearer test-gateway-token")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"tool": "time"}"#))
            .unwrap();

        let response = router.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["ok"], true);
        assert!(json["result"].is_object());
    }

    #[tokio::test]
    async fn test_tools_invoke_not_found() {
        let router = test_router(test_config());

        let req = Request::builder()
            .method("POST")
            .uri("/tools/invoke")
            .header("authorization", "Bearer test-gateway-token")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"tool": "nonexistent"}"#))
            .unwrap();

        let response = router.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["ok"], false);
        assert_eq!(json["error"]["type"], "not_found");
    }

    #[tokio::test]
    async fn test_tools_invoke_missing_tool() {
        let router = test_router(test_config());

        let req = Request::builder()
            .method("POST")
            .uri("/tools/invoke")
            .header("authorization", "Bearer test-gateway-token")
            .header("content-type", "application/json")
            .body(Body::from(r#"{}"#))
            .unwrap();

        let response = router.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_tools_invoke_unauthorized() {
        let router = test_router(test_config());

        let req = Request::builder()
            .method("POST")
            .uri("/tools/invoke")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"tool": "time"}"#))
            .unwrap();

        let response = router.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn test_normalize_hooks_path() {
        assert_eq!(normalize_hooks_path("/hooks"), "/hooks");
        assert_eq!(normalize_hooks_path("hooks"), "/hooks");
        assert_eq!(normalize_hooks_path("/hooks/"), "/hooks");
        assert_eq!(normalize_hooks_path("/custom"), "/custom");
        assert_eq!(normalize_hooks_path(""), "/hooks");
        assert_eq!(normalize_hooks_path("/"), "/hooks");
        assert_eq!(normalize_hooks_path("  /api  "), "/api");
    }

    #[test]
    fn test_is_valid_agent_id() {
        assert!(is_valid_agent_id("main"));
        assert!(is_valid_agent_id("agent1"));
        assert!(is_valid_agent_id("my-agent"));
        assert!(is_valid_agent_id("my_agent"));
        assert!(is_valid_agent_id("Agent123"));
        assert!(!is_valid_agent_id(""));
        assert!(!is_valid_agent_id("-agent"));
        assert!(!is_valid_agent_id("_agent"));
        assert!(!is_valid_agent_id("agent..name"));
        assert!(!is_valid_agent_id(&"a".repeat(65)));
    }

    #[test]
    fn test_is_loopback_addr() {
        use std::net::{Ipv4Addr, Ipv6Addr};

        assert!(auth::is_loopback_addr(IpAddr::V4(Ipv4Addr::new(
            127, 0, 0, 1
        ))));
        assert!(auth::is_loopback_addr(IpAddr::V4(Ipv4Addr::new(
            127, 1, 2, 3
        ))));
        assert!(!auth::is_loopback_addr(IpAddr::V4(Ipv4Addr::new(
            192, 168, 1, 1
        ))));
        assert!(auth::is_loopback_addr(IpAddr::V6(Ipv6Addr::LOCALHOST)));
    }

    #[test]
    fn test_get_content_type() {
        use std::path::Path;

        assert_eq!(
            get_content_type(Path::new("index.html")),
            "text/html; charset=utf-8"
        );
        assert_eq!(
            get_content_type(Path::new("app.js")),
            "application/javascript; charset=utf-8"
        );
        assert_eq!(
            get_content_type(Path::new("style.css")),
            "text/css; charset=utf-8"
        );
        assert_eq!(get_content_type(Path::new("image.png")), "image/png");
        assert_eq!(get_content_type(Path::new("photo.jpg")), "image/jpeg");
        assert_eq!(
            get_content_type(Path::new("unknown.xyz")),
            "application/octet-stream"
        );
    }

    #[test]
    fn test_gateway_auth_no_config_loopback_allowed() {
        use std::net::Ipv4Addr;

        let config = HttpConfig {
            gateway_token: None,
            gateway_password: None,
            ..Default::default()
        };
        let headers = HeaderMap::new();

        // Loopback address should be allowed
        let result = check_gateway_auth(
            &config,
            &headers,
            Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
        );
        assert!(
            result.is_none(),
            "Loopback should be allowed when no auth configured"
        );
    }

    #[test]
    fn test_gateway_auth_no_config_non_loopback_rejected() {
        use std::net::Ipv4Addr;

        let config = HttpConfig {
            gateway_token: None,
            gateway_password: None,
            ..Default::default()
        };
        let headers = HeaderMap::new();

        // Non-loopback address should be rejected
        let result = check_gateway_auth(
            &config,
            &headers,
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))),
        );
        assert!(
            result.is_some(),
            "Non-loopback should be rejected when no auth configured"
        );
    }

    #[test]
    fn test_gateway_auth_no_config_no_addr_rejected() {
        let config = HttpConfig {
            gateway_token: None,
            gateway_password: None,
            ..Default::default()
        };
        let headers = HeaderMap::new();

        // Unknown address (None) should be rejected for safety
        let result = check_gateway_auth(&config, &headers, None);
        assert!(
            result.is_some(),
            "Unknown address should be rejected when no auth configured"
        );
    }

    #[test]
    fn test_gateway_auth_with_token_allows_any_address() {
        use std::net::Ipv4Addr;

        let config = HttpConfig {
            gateway_token: Some("valid-token".to_string()),
            gateway_password: None,
            ..Default::default()
        };

        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            "Bearer valid-token".parse().unwrap(),
        );

        // Non-loopback address with valid token should be allowed
        let result = check_gateway_auth(
            &config,
            &headers,
            Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
        );
        assert!(result.is_none(), "Valid token should allow any address");
    }

    #[test]
    fn test_gateway_auth_no_config_loopback_with_proxy_headers_rejected() {
        use std::net::Ipv4Addr;

        let config = HttpConfig {
            gateway_token: None,
            gateway_password: None,
            ..Default::default()
        };

        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "203.0.113.50".parse().unwrap());

        // Loopback with proxy headers should be rejected (could be spoofed)
        let result = check_gateway_auth(
            &config,
            &headers,
            Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
        );
        assert!(
            result.is_some(),
            "Loopback with proxy headers should be rejected"
        );
    }

    #[tokio::test]
    async fn test_health_endpoint() {
        let router = test_router(test_config());

        let req = Request::builder()
            .method("GET")
            .uri("/health")
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["status"], "ok");
        assert!(json["version"].as_str().is_some());
        assert!(json["uptimeSeconds"].as_i64().is_some());
    }
}
