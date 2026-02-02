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
    body::Bytes,
    extract::{ConnectInfo, DefaultBodyLimit, Path, Query, State},
    http::{header, HeaderMap, HeaderValue, Method, StatusCode, Uri},
    middleware,
    response::{IntoResponse, Response},
    routing::{any, get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::fs;
use tracing::{debug, warn};
use uuid::Uuid;

use crate::server::control::{self, ControlState};
use crate::server::csrf::{
    csrf_cookie_name, csrf_middleware, ensure_csrf_cookies, CsrfConfig, CsrfTokenStore,
};
use crate::server::headers::{security_headers_middleware, SecurityHeadersConfig};
use crate::server::openai::{self, OpenAiState};
use crate::server::ratelimit::{rate_limit_middleware, RateLimitConfig, RateLimiter};

use crate::auth;
use crate::channels::{inbound, slack_inbound, telegram_inbound, ChannelRegistry};
use crate::hooks::auth::{extract_hooks_token, validate_hooks_token};
use crate::hooks::handler::{
    validate_agent_request, validate_wake_request, AgentRequest, AgentResponse, HooksErrorResponse,
    WakeRequest, WakeResponse,
};
use crate::hooks::registry::{HookMappingContext, HookMappingResult, HookRegistry};
use crate::plugins::tools::{ToolInvokeContext, ToolInvokeResult, ToolsRegistry};
use crate::plugins::{DispatchError, WebhookDispatcher, WebhookRequest};
use crate::server::ws::WsServerState;

/// Default max body size for hooks (256KB)
pub const DEFAULT_MAX_BODY_BYTES: usize = 262144;

/// Default hooks base path
pub const DEFAULT_HOOKS_PATH: &str = "/hooks";

/// HTTP server configuration
#[non_exhaustive]
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
    /// Gateway auth mode
    pub gateway_auth_mode: auth::AuthMode,
    /// Whether Tailscale auth is allowed for gateway endpoints
    pub gateway_allow_tailscale: bool,
    /// Trusted proxy IPs for local-direct detection
    pub trusted_proxies: Vec<String>,
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
            gateway_auth_mode: auth::AuthMode::Token,
            gateway_allow_tailscale: false,
            trusted_proxies: Vec::new(),
            control_ui_base_path: String::new(),
            control_ui_enabled: false,
            control_ui_dist_path: PathBuf::from("dist/control-ui"),
            valid_channels: Vec::new(),
            agents_dir: crate::server::ws::resolve_state_dir().join("agents"),
            openai_chat_completions_enabled: false,
            openai_responses_enabled: false,
            control_endpoints_enabled: false,
        }
    }
}

/// Build an `HttpConfig` from the loaded JSON configuration.
///
/// Maps gateway.* keys from config and checks environment variables
/// (CARAPACE_GATEWAY_TOKEN, CARAPACE_GATEWAY_PASSWORD) with env taking precedence.
pub fn build_http_config(cfg: &Value) -> Result<HttpConfig, String> {
    let gateway = cfg.get("gateway").and_then(|v| v.as_object());

    let hooks_obj = gateway
        .and_then(|g| g.get("hooks"))
        .and_then(|v| v.as_object());
    let auth_obj = gateway
        .and_then(|g| g.get("auth"))
        .and_then(|v| v.as_object());
    let trusted_proxies = gateway
        .and_then(|g| g.get("trustedProxies"))
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
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

    let gateway_token = std::env::var("CARAPACE_GATEWAY_TOKEN").ok().or(cfg_token);
    let gateway_password = std::env::var("CARAPACE_GATEWAY_PASSWORD")
        .ok()
        .or(cfg_password);
    let auth_mode = auth_obj
        .and_then(|a| a.get("mode"))
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    let allow_tailscale = auth_obj
        .and_then(|a| a.get("allowTailscale"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let has_both_gateway_credentials = gateway_password.is_some() && gateway_token.is_some();
    let resolved_auth_mode = match auth_mode {
        "none" | "local" => auth::AuthMode::None,
        "password" => auth::AuthMode::Password,
        "token" => auth::AuthMode::Token,
        "" => {
            if has_both_gateway_credentials {
                warn!(
                    "gateway auth mode not set; both token and password configured, defaulting to password auth"
                );
            }
            if gateway_password.is_some() {
                auth::AuthMode::Password
            } else {
                auth::AuthMode::Token
            }
        }
        other => {
            return Err(format!(
                "unknown gateway auth mode '{}'; expected one of: none, local, token, password",
                other
            ));
        }
    };

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

    Ok(HttpConfig {
        hooks_token,
        hooks_enabled,
        gateway_token,
        gateway_password,
        gateway_auth_mode: resolved_auth_mode,
        gateway_allow_tailscale: allow_tailscale,
        trusted_proxies,
        control_ui_enabled,
        control_ui_dist_path,
        openai_chat_completions_enabled,
        openai_responses_enabled,
        control_endpoints_enabled,
        ..Default::default()
    })
}

/// Shared state for HTTP handlers
#[non_exhaustive]
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<HttpConfig>,
    /// Hook mappings registry
    pub hook_registry: Arc<HookRegistry>,
    /// Tools registry
    pub tools_registry: Arc<ToolsRegistry>,
    /// Channel registry
    pub channel_registry: Arc<ChannelRegistry>,
    /// Cached plugin webhook dispatcher
    pub plugin_webhook_dispatcher: Option<Arc<WebhookDispatcher>>,
    /// Gateway start time (Unix timestamp)
    pub start_time: i64,
    /// WebSocket server state (for agent dispatch from hooks)
    pub ws_state: Option<Arc<WsServerState>>,
    /// Health checker for deep diagnostics
    pub health_checker: Option<Arc<crate::server::health::HealthChecker>>,
    /// CSRF token store for control UI
    pub csrf_store: Option<CsrfTokenStore>,
    /// Whether the HTTP server is running with TLS enabled
    pub tls_enabled: bool,
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
            enable_csrf: true,
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
    create_router_with_middleware(config, MiddlewareConfig::none(), false)
}

/// Create the HTTP router with all endpoints and middleware
pub fn create_router_with_middleware(
    config: HttpConfig,
    middleware_config: MiddlewareConfig,
    tls_enabled: bool,
) -> Router {
    create_router_with_state(
        config,
        middleware_config,
        Arc::new(HookRegistry::new()),
        Arc::new(ToolsRegistry::new()),
        Arc::new(ChannelRegistry::new()),
        None,
        tls_enabled,
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
    tls_enabled: bool,
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

    let plugin_webhook_dispatcher = ws_state
        .as_ref()
        .and_then(|ws| ws.plugin_registry().cloned())
        .map(|registry| Arc::new(WebhookDispatcher::new(registry)));

    let csrf_store = if middleware_config.enable_csrf {
        Some(CsrfTokenStore::new(middleware_config.csrf.clone()))
    } else {
        None
    };

    let state = AppState {
        config: Arc::new(config.clone()),
        hook_registry,
        tools_registry,
        channel_registry: channel_registry.clone(),
        plugin_webhook_dispatcher,
        start_time,
        ws_state,
        health_checker,
        csrf_store: csrf_store.clone(),
        tls_enabled,
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

    let channel_router = Router::new()
        .route("/channels/telegram/webhook", post(telegram_webhook_handler))
        .route("/channels/slack/events", post(slack_events_handler))
        .layer(DefaultBodyLimit::max(config.hooks_max_body_bytes));
    router = router.merge(channel_router);

    // Plugin webhook routes (always enabled when plugins are registered)
    let plugin_router = Router::new()
        .route("/plugins/*path", any(plugins_webhook_handler))
        .layer(DefaultBodyLimit::max(config.hooks_max_body_bytes));
    router = router.merge(plugin_router);

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
            gateway_auth_mode: config.gateway_auth_mode.clone(),
            gateway_allow_tailscale: config.gateway_allow_tailscale,
            trusted_proxies: config.trusted_proxies.clone(),
            llm_provider: llm_provider.clone(),
        };

        if config.openai_chat_completions_enabled {
            router = router.route(
                "/v1/chat/completions",
                post(move |connect_info, headers, body| {
                    let state = openai_state.clone();
                    async move {
                        openai::chat_completions_handler(State(state), connect_info, headers, body)
                            .await
                    }
                }),
            );
        }

        let openai_state2 = OpenAiState {
            chat_completions_enabled: config.openai_chat_completions_enabled,
            responses_enabled: config.openai_responses_enabled,
            gateway_token: config.gateway_token.clone(),
            gateway_password: config.gateway_password.clone(),
            gateway_auth_mode: config.gateway_auth_mode.clone(),
            gateway_allow_tailscale: config.gateway_allow_tailscale,
            trusted_proxies: config.trusted_proxies.clone(),
            llm_provider,
        };

        if config.openai_responses_enabled {
            router = router.route(
                "/v1/responses",
                post(move |connect_info, headers, body| {
                    let state = openai_state2.clone();
                    async move {
                        openai::responses_handler(State(state), connect_info, headers, body).await
                    }
                }),
            );
        }
    }

    // Control endpoints
    if config.control_endpoints_enabled {
        router = register_session_routes(router, &config, &channel_registry, start_time);
    }

    // Control UI routes (when enabled)
    if config.control_ui_enabled {
        router = register_admin_routes(router, &config);
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
    if let Some(csrf_store) = csrf_store {
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

/// Register control session endpoints (status, channels, config).
fn register_session_routes(
    router: Router<AppState>,
    config: &HttpConfig,
    channel_registry: &Arc<ChannelRegistry>,
    start_time: i64,
) -> Router<AppState> {
    let control_state = ControlState {
        gateway_token: config.gateway_token.clone(),
        gateway_password: config.gateway_password.clone(),
        gateway_auth_mode: config.gateway_auth_mode.clone(),
        gateway_allow_tailscale: config.gateway_allow_tailscale,
        trusted_proxies: config.trusted_proxies.clone(),
        channel_registry: channel_registry.clone(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        start_time,
    };

    let control_state_status = control_state.clone();
    let control_state_channels = control_state.clone();
    let control_state_config = control_state.clone();

    router
        .route(
            "/control/status",
            get(move |connect_info, headers| {
                let state = control_state_status.clone();
                async move {
                    control::status_handler(State(state), connect_info, headers).await
                }
            }),
        )
        .route(
            "/control/channels",
            get(move |connect_info, headers| {
                let state = control_state_channels.clone();
                async move {
                    control::channels_handler(State(state), connect_info, headers).await
                }
            }),
        )
        .route(
            "/control/config",
            post(move |connect_info, headers, body| {
                let state = control_state_config.clone();
                async move {
                    control::config_handler(State(state), connect_info, headers, body).await
                }
            }),
        )
}

/// Register control UI routes (static files, SPA fallback, avatar endpoint).
fn register_admin_routes(router: Router<AppState>, config: &HttpConfig) -> Router<AppState> {
    let base = if config.control_ui_base_path.is_empty() {
        "/ui".to_string()
    } else {
        config.control_ui_base_path.clone()
    };

    router
        .route(&base, get(control_ui_redirect))
        .route(&format!("{}/", base), get(control_ui_index))
        .route(
            &format!("{}/__carapace_avatar__/:agent_id", base),
            get(avatar_handler),
        )
        .route(&format!("{}/*path", base), get(control_ui_static))
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

fn resolve_telegram_webhook_secret(cfg: &Value) -> Option<String> {
    cfg.get("telegram")
        .and_then(|t| t.get("webhookSecret"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .or_else(|| std::env::var("TELEGRAM_WEBHOOK_SECRET").ok())
}

fn resolve_slack_signing_secret(cfg: &Value) -> Option<String> {
    cfg.get("slack")
        .and_then(|s| s.get("signingSecret"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .or_else(|| std::env::var("SLACK_SIGNING_SECRET").ok())
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

/// Parse and validate an agent request body, returning the validated request
/// or an HTTP error response.
#[allow(clippy::result_large_err)]
fn parse_agent_request(
    body: &axum::body::Bytes,
    valid_channels: &[String],
) -> Result<crate::hooks::handler::ValidatedAgentRequest, Response> {
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
            venice_parameters: None,
        }
    } else {
        match serde_json::from_slice(body) {
            Ok(r) => r,
            Err(e) => {
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(HooksErrorResponse::new(&format!("SyntaxError: {}", e))),
                )
                    .into_response());
            }
        }
    };

    validate_agent_request(&req, valid_channels)
        .map_err(|e| (StatusCode::BAD_REQUEST, Json(AgentResponse::error(&e))).into_response())
}

/// Dispatch a validated agent request through the WebSocket runtime, creating
/// a session, registering the run, and optionally spawning the LLM executor.
#[allow(clippy::result_large_err)]
fn dispatch_agent_run(
    ws: &Arc<WsServerState>,
    validated: &crate::hooks::handler::ValidatedAgentRequest,
    run_id: &str,
    sender_id: &str,
) -> Result<(), Response> {
    let cfg = crate::config::load_config().unwrap_or(Value::Object(serde_json::Map::new()));
    let channel = if validated.channel == "last" {
        "default"
    } else {
        validated.channel.as_str()
    };
    let peer_id = validated
        .to
        .as_deref()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .unwrap_or(sender_id);
    let metadata = crate::sessions::SessionMetadata {
        channel: Some(channel.to_string()),
        user_id: Some(sender_id.to_string()),
        ..Default::default()
    };
    let session = crate::sessions::get_or_create_scoped_session(
        ws.session_store(),
        &cfg,
        channel,
        sender_id,
        peer_id,
        validated.session_key.as_deref(),
        metadata,
    )
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(AgentResponse::error(&format!("session error: {}", e))),
        )
            .into_response()
    })?;

    ws.session_store()
        .append_message(crate::sessions::ChatMessage::user(
            session.id.clone(),
            &validated.message,
        ))
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(AgentResponse::error(&format!("session write error: {}", e))),
            )
                .into_response()
        })?;

    // Register the agent run
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    let cancel_token = tokio_util::sync::CancellationToken::new();
    let run = crate::server::ws::AgentRun {
        run_id: run_id.to_string(),
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
        let cfg = crate::config::load_config().unwrap_or(Value::Object(serde_json::Map::new()));
        let mut config = crate::agent::AgentConfig::default();
        crate::agent::apply_agent_config_from_settings(&mut config, &cfg, None);
        config.model = validated
            .model
            .clone()
            .unwrap_or_else(|| crate::agent::DEFAULT_MODEL.to_string());
        config.deliver = validated.deliver;
        config.extra = validated.venice_parameters.clone();
        crate::agent::spawn_run(
            run_id.to_string(),
            session.session_key.clone(),
            config,
            ws.clone(),
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

    Ok(())
}

/// POST /hooks/agent - Dispatch message to agent
async fn hooks_agent_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    uri: Uri,
    connect_info: Option<ConnectInfo<SocketAddr>>,
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

    let validated = match parse_agent_request(&body, &state.config.valid_channels) {
        Ok(v) => v,
        Err(resp) => return resp,
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

    let sender_id = connect_info
        .map(|info| info.0.ip().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    if let Err(resp) = dispatch_agent_run(&ws, &validated, &run_id, &sender_id) {
        return resp;
    }

    (StatusCode::ACCEPTED, Json(AgentResponse::success(run_id))).into_response()
}

// ============================================================================
// Channel Webhook Handlers
// ============================================================================

async fn telegram_webhook_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let ws = match &state.ws_state {
        Some(ws) => ws.clone(),
        None => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };

    let cfg = crate::config::load_config().unwrap_or(Value::Object(serde_json::Map::new()));
    if cfg
        .get("telegram")
        .and_then(|v| v.get("enabled"))
        .and_then(|v| v.as_bool())
        == Some(false)
    {
        return StatusCode::NOT_FOUND.into_response();
    }

    if let Some(secret) = resolve_telegram_webhook_secret(&cfg) {
        let provided = headers
            .get("X-Telegram-Bot-Api-Secret-Token")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if !crate::auth::timing_safe_eq(&secret, provided) {
            return StatusCode::UNAUTHORIZED.into_response();
        }
    }

    let update: telegram_inbound::TelegramUpdate = match serde_json::from_slice(&body) {
        Ok(update) => update,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };

    let inbound = match telegram_inbound::extract_inbound(&update) {
        Some(inbound) => inbound,
        None => return StatusCode::OK.into_response(),
    };

    if let Err(err) = inbound::dispatch_inbound_text(
        &ws,
        "telegram",
        &inbound.sender_id,
        &inbound.chat_id,
        &inbound.text,
        Some(inbound.chat_id.clone()),
    ) {
        warn!("Telegram inbound dispatch failed: {}", err);
    }

    StatusCode::OK.into_response()
}

async fn slack_events_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let ws = match &state.ws_state {
        Some(ws) => ws.clone(),
        None => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };

    let cfg = crate::config::load_config().unwrap_or(Value::Object(serde_json::Map::new()));
    if cfg
        .get("slack")
        .and_then(|v| v.get("enabled"))
        .and_then(|v| v.as_bool())
        == Some(false)
    {
        return StatusCode::NOT_FOUND.into_response();
    }

    let signing_secret = match resolve_slack_signing_secret(&cfg) {
        Some(secret) => secret,
        None => return StatusCode::UNAUTHORIZED.into_response(),
    };

    let timestamp = match headers
        .get("X-Slack-Request-Timestamp")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<i64>().ok())
    {
        Some(ts) => ts,
        None => return StatusCode::UNAUTHORIZED.into_response(),
    };

    let signature = match headers
        .get("X-Slack-Signature")
        .and_then(|v| v.to_str().ok())
    {
        Some(sig) => sig,
        None => return StatusCode::UNAUTHORIZED.into_response(),
    };

    let now = chrono::Utc::now().timestamp();
    if (now - timestamp).abs() > slack_inbound::SLACK_SIGNATURE_TOLERANCE_SECS {
        return StatusCode::UNAUTHORIZED.into_response();
    }

    if !slack_inbound::verify_slack_signature(&signing_secret, timestamp, signature, &body) {
        return StatusCode::UNAUTHORIZED.into_response();
    }

    let payload: Value = match serde_json::from_slice(&body) {
        Ok(payload) => payload,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };

    if payload.get("type").and_then(|v| v.as_str()) == Some("url_verification") {
        if let Some(challenge) = payload.get("challenge").and_then(|v| v.as_str()) {
            return (StatusCode::OK, Json(json!({ "challenge": challenge }))).into_response();
        }
    }

    if payload.get("type").and_then(|v| v.as_str()) == Some("event_callback") {
        if let Some(event) = payload.get("event") {
            if let Some(inbound) = slack_inbound::extract_inbound_event(event) {
                if let Err(err) = inbound::dispatch_inbound_text(
                    &ws,
                    "slack",
                    &inbound.sender_id,
                    &inbound.channel_id,
                    &inbound.text,
                    Some(inbound.channel_id.clone()),
                ) {
                    warn!("Slack inbound dispatch failed: {}", err);
                }
            }
        }
    }

    StatusCode::OK.into_response()
}

/// Build the hook execution context from request headers, URI, path, and payload.
fn build_hook_context(
    headers: &HeaderMap,
    uri: &Uri,
    path: &str,
    payload: Value,
) -> HookMappingContext {
    let mut header_map: HashMap<String, String> = HashMap::new();
    for (key, value) in headers.iter() {
        if let Ok(v) = value.to_str() {
            header_map.insert(key.as_str().to_lowercase(), v.to_string());
        }
    }

    HookMappingContext {
        path: path.to_string(),
        headers: header_map,
        payload,
        query: uri.query().map(|s| s.to_string()),
        now: chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
    }
}

/// Convert a hook mapping evaluation result into an HTTP response.
fn hook_result_to_response(
    result: Result<HookMappingResult, crate::hooks::HookMappingError>,
) -> Response {
    match result {
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

/// Look up a matching hook mapping and evaluate it, returning an HTTP response.
fn execute_hook_mapping(state: &AppState, path: &str, ctx: &HookMappingContext) -> Response {
    let mapping = match state.hook_registry.find_match(ctx) {
        Some(m) => m,
        None => {
            debug!("No hook mapping found for path: {}", path);
            return (StatusCode::NOT_FOUND, "Not Found").into_response();
        }
    };

    debug!("Hook mapping found for path '{}': {:?}", path, mapping.id);

    let result = state.hook_registry.evaluate(&mapping, ctx);
    hook_result_to_response(result)
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

    let ctx = build_hook_context(&headers, &uri, &path, payload);
    execute_hook_mapping(&state, &path, &ctx)
}

/// Plugin webhook handler: forwards `/plugins/<plugin-id>/<path>` to plugin instances.
async fn plugins_webhook_handler(
    State(state): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    Path(path): Path<String>,
    body: Bytes,
) -> Response {
    if let Some(err) = check_hooks_auth(&state.config, &headers, &uri) {
        return err;
    }

    if body.len() > state.config.hooks_max_body_bytes {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(HooksErrorResponse::new("payload too large")),
        )
            .into_response();
    }

    let dispatcher = match &state.plugin_webhook_dispatcher {
        Some(dispatcher) => dispatcher.clone(),
        None => {
            return (StatusCode::NOT_FOUND, "Not Found").into_response();
        }
    };

    let full_path = if path.is_empty() {
        "/plugins".to_string()
    } else {
        format!("/plugins/{}", path)
    };

    let req_headers = headers
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|v| (name.as_str().to_string(), v.to_string()))
        })
        .collect::<Vec<_>>();

    let request = WebhookRequest {
        method: method.to_string(),
        path: full_path.clone(),
        headers: req_headers,
        body: if body.is_empty() {
            None
        } else {
            Some(body.to_vec())
        },
        query: uri.query().map(|q| q.to_string()),
    };

    if let Err(err) = dispatcher.refresh_path_map_if_stale() {
        warn!(error = %err, "Failed to refresh plugin webhook paths");
    }

    match dispatcher.handle(&full_path, request) {
        Ok(response) => webhook_response_to_http(response),
        Err(DispatchError::WebhookPathNotFound(_)) | Err(DispatchError::PluginNotFound(_)) => {
            (StatusCode::NOT_FOUND, "Not Found").into_response()
        }
        Err(err) => {
            warn!(error = %err, path = %full_path, "Plugin webhook dispatch failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "Webhook handler error").into_response()
        }
    }
}

fn webhook_response_to_http(response: crate::plugins::WebhookResponse) -> Response {
    let status = StatusCode::from_u16(response.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let mut builder = Response::builder().status(status);

    for (name, value) in response.headers {
        let header_name = match header::HeaderName::from_bytes(name.as_bytes()) {
            Ok(name) => name,
            Err(_) => {
                warn!(header = %name, "Invalid webhook response header name");
                continue;
            }
        };
        let header_value = match HeaderValue::from_str(&value) {
            Ok(value) => value,
            Err(_) => {
                warn!(header = %name, "Invalid webhook response header value");
                continue;
            }
        };
        builder = builder.header(header_name, header_value);
    }

    let body = response.body.unwrap_or_default();
    builder
        .body(axum::body::Body::from(body))
        .unwrap_or_else(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Invalid webhook response",
            )
                .into_response()
        })
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
    let remote_addr = connect_info.map(|ci| ci.0);
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
        .get("x-carapace-message-channel")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let account_id = headers
        .get("x-carapace-account-id")
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

/// Check gateway authentication
///
/// When token/password auth is configured, validates the provided credentials.
/// When no auth is configured, only allows requests from loopback addresses
/// (localhost) to prevent accidental exposure when binding to 0.0.0.0.
fn check_gateway_auth(
    config: &HttpConfig,
    headers: &HeaderMap,
    remote_addr: Option<SocketAddr>,
) -> Option<Response> {
    // Extract bearer token
    let provided = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(|s| s.trim());

    let resolved = auth::ResolvedGatewayAuth {
        mode: config.gateway_auth_mode.clone(),
        token: config.gateway_token.clone(),
        password: config.gateway_password.clone(),
        allow_tailscale: config.gateway_allow_tailscale,
    };
    // HTTP bearer header is used for either token or password auth.
    let auth_result = auth::authorize_gateway_request(
        &resolved,
        provided,
        provided,
        headers,
        remote_addr,
        &config.trusted_proxies,
    );
    if auth_result.ok {
        return None;
    }
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
async fn control_ui_index(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Some(response) = control_ui_tls_guard(&state) {
        return response;
    }
    serve_index_html(&state, &headers).await
}

/// Serve static files or fallback to index.html
async fn control_ui_static(
    State(state): State<AppState>,
    Path(path): Path<String>,
    headers: HeaderMap,
) -> Response {
    if let Some(response) = control_ui_tls_guard(&state) {
        return response;
    }
    let dist_path = &state.config.control_ui_dist_path;

    // Security: prevent path traversal
    let safe_path = path.trim_start_matches('/');
    if safe_path.contains("..") {
        return (StatusCode::NOT_FOUND, "Not Found").into_response();
    }

    let file_path = dist_path.join(safe_path);

    // Check if it's the avatar endpoint
    if safe_path.starts_with("__carapace_avatar__/") {
        let agent_id = safe_path.trim_start_matches("__carapace_avatar__/");
        return serve_avatar(&state, agent_id).await;
    }

    // Try to serve the file directly
    if file_path.is_file() {
        return serve_file(&file_path).await;
    }

    // SPA fallback: serve index.html for unknown paths
    serve_index_html(&state, &headers).await
}

/// Serve index.html with injected configuration
async fn serve_index_html(state: &AppState, headers: &HeaderMap) -> Response {
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

            let mut injected = content
                .replace("__CARAPACE_CONTROL_UI_BASE_PATH__", &base_path)
                .replace("__CARAPACE_ASSISTANT_NAME__", "Carapace")
                .replace("__CARAPACE_ASSISTANT_AVATAR__", "");

            if let Some(store) = &state.csrf_store {
                let config = store.config();
                if config.enabled {
                    let script = csrf_bootstrap_script(config);
                    injected = inject_html_script(&injected, &script);
                }
            }

            let mut response = (
                StatusCode::OK,
                [
                    (header::CONTENT_TYPE, "text/html; charset=utf-8"),
                    (header::CACHE_CONTROL, "no-cache"),
                ],
                injected,
            )
                .into_response();

            if let Some(store) = &state.csrf_store {
                match ensure_csrf_cookies(headers, store) {
                    Ok(cookies) => {
                        let response_headers = response.headers_mut();
                        for cookie in cookies {
                            if let Ok(value) = HeaderValue::from_str(&cookie) {
                                response_headers.append(header::SET_COOKIE, value);
                            }
                        }
                    }
                    Err(err) => {
                        warn!("Failed to set CSRF cookies: {}", err);
                    }
                }
            }

            response
        }
        Err(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            "Control UI assets not found",
        )
            .into_response(),
    }
}

fn control_ui_tls_guard(state: &AppState) -> Option<Response> {
    let store = state.csrf_store.as_ref()?;
    let config = store.config();
    if config.enabled && config.secure_cookie && !state.tls_enabled {
        return Some(
            (
                StatusCode::FORBIDDEN,
                "Control UI requires TLS when CSRF secure cookies are enabled.",
            )
                .into_response(),
        );
    }
    None
}

fn csrf_bootstrap_script(config: &CsrfConfig) -> String {
    let cookie_name = csrf_cookie_name(config);
    format!(
        r#"<script>(function(){{var cookieName='{cookie}';var headerName='{header}';function readCookie(name){{var parts=document.cookie?document.cookie.split(';'):[];for(var i=0;i<parts.length;i++){{var part=parts[i].trim();if(part.indexOf(name+'=')===0){{return part.substring(name.length+1);}}}}return '';}}function getToken(){{return readCookie(cookieName);}}function addHeader(headers,token){{if(!token){{return headers;}}var lower=headerName.toLowerCase();if(headers instanceof Headers){{if(!headers.has(headerName)){{headers.set(headerName,token);}}return headers;}}if(Array.isArray(headers)){{for(var i=0;i<headers.length;i++){{if(String(headers[i][0]).toLowerCase()===lower){{return headers;}}}}headers.push([headerName,token]);return headers;}}headers=headers||{{}};for(var key in headers){{if(Object.prototype.hasOwnProperty.call(headers,key)&&String(key).toLowerCase()===lower){{return headers;}}}}headers[headerName]=token;return headers;}}if(window.fetch){{var origFetch=window.fetch.bind(window);window.fetch=function(input,init){{var token=getToken();if(token){{init=init||{{}};if(input instanceof Request){{var baseHeaders=new Headers(input.headers);init.headers=addHeader(baseHeaders,token);var req=new Request(input,init);return origFetch(req);}}init.headers=addHeader(init.headers,token);}}return origFetch(input,init);}};}}if(window.XMLHttpRequest){{var origOpen=XMLHttpRequest.prototype.open;var origSend=XMLHttpRequest.prototype.send;XMLHttpRequest.prototype.open=function(){{this.__csrfToken=getToken();return origOpen.apply(this,arguments);}};XMLHttpRequest.prototype.send=function(){{if(this.__csrfToken){{try{{this.setRequestHeader(headerName,this.__csrfToken);}}catch(e){{}}}}return origSend.apply(this,arguments);}};}}}})();</script>"#,
        cookie = cookie_name,
        header = config.header_name
    )
}

fn inject_html_script(html: &str, script: &str) -> String {
    if html.contains("</head>") {
        return html.replace("</head>", &format!("{}</head>", script));
    }
    if html.contains("</body>") {
        return html.replace("</body>", &format!("{}</body>", script));
    }
    format!("{}{}", html, script)
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

/// GET /__carapace_avatar__/:agent_id - Serve agent avatar
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
            let url = format!("{}/__carapace_avatar__/{}", base, agent_id);
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
        use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

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
    fn test_gateway_auth_no_config_loopback_rejected() {
        let config = HttpConfig {
            gateway_token: None,
            gateway_password: None,
            ..Default::default()
        };
        let headers = HeaderMap::new();

        // Loopback address should be rejected by default (fail-closed).
        let result = check_gateway_auth(&config, &headers, Some("127.0.0.1:1234".parse().unwrap()));
        assert!(
            result.is_some(),
            "Loopback should be rejected when no auth configured"
        );
    }

    #[test]
    fn test_gateway_auth_no_config_non_loopback_rejected() {
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
            Some("192.168.1.100:5555".parse().unwrap()),
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
        let result = check_gateway_auth(&config, &headers, Some("8.8.8.8:443".parse().unwrap()));
        assert!(result.is_none(), "Valid token should allow any address");
    }

    #[test]
    fn test_gateway_auth_mode_none_allows_loopback() {
        let config = HttpConfig {
            gateway_token: None,
            gateway_password: None,
            gateway_auth_mode: auth::AuthMode::None,
            ..Default::default()
        };

        let mut headers = HeaderMap::new();
        headers.insert("host", "localhost".parse().unwrap());

        let result = check_gateway_auth(&config, &headers, Some("127.0.0.1:4321".parse().unwrap()));
        assert!(
            result.is_none(),
            "Loopback should be allowed in auth mode none"
        );
    }

    #[test]
    fn test_gateway_auth_mode_none_loopback_requires_local_host() {
        let config = HttpConfig {
            gateway_token: None,
            gateway_password: None,
            gateway_auth_mode: auth::AuthMode::None,
            ..Default::default()
        };

        let mut headers = HeaderMap::new();
        headers.insert("host", "example.com".parse().unwrap());

        let result = check_gateway_auth(&config, &headers, Some("127.0.0.1:4321".parse().unwrap()));
        assert!(
            result.is_some(),
            "Loopback without a local Host header should be rejected"
        );
    }

    #[test]
    fn test_gateway_auth_mode_none_loopback_with_proxy_headers_rejected() {
        let config = HttpConfig {
            gateway_token: None,
            gateway_password: None,
            gateway_auth_mode: auth::AuthMode::None,
            ..Default::default()
        };

        let mut headers = HeaderMap::new();
        headers.insert("host", "localhost".parse().unwrap());
        headers.insert("x-forwarded-for", "203.0.113.50".parse().unwrap());

        // Loopback with proxy headers should be rejected (could be spoofed)
        let result = check_gateway_auth(&config, &headers, Some("127.0.0.1:9000".parse().unwrap()));
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
