//! HTTP server implementation
//!
//! Implements:
//! - Hooks API (POST /hooks/wake, /hooks/agent, /hooks/<mapping>)
//! - Tools API (POST /tools/invoke)
//! - OpenAI compatibility (POST /v1/chat/completions, /v1/responses)
//! - Control endpoints (status/channels/config/tasks)
//! - Control UI (static files + SPA fallback + avatar endpoint)
//! - Auth middleware (hooks token, gateway auth, loopback bypass)
//! - Security middleware (headers, CSRF, rate limiting)

use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, Path, Query, State},
    http::{header, HeaderMap, HeaderValue, Method, StatusCode, Uri},
    middleware,
    response::{IntoResponse, Response},
    routing::{any, get, patch, post},
    Json, Router,
};
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::Sha256;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::fs;
use tracing::{debug, warn};
use uuid::Uuid;

use crate::server::connect_info::MaybeConnectInfo;
use crate::server::control::{self, ControlState};
use crate::server::csrf::{
    csrf_cookie_name, csrf_middleware, ensure_csrf_cookies, CsrfConfig, CsrfTokenStore,
};
use crate::server::headers::{security_headers_middleware, SecurityHeadersConfig};
use crate::server::openai::{self, OpenAiState};
use crate::server::ratelimit::{rate_limit_middleware, RateLimitConfig, RateLimiter};

use crate::agent::{AgentConfigurationError, AgentError, LlmProvider};
use crate::auth;
use crate::channels::{inbound, slack_inbound, telegram_inbound, ChannelRegistry};
use crate::hooks::auth::{extract_hooks_token, validate_hooks_token};
use crate::hooks::handler::{
    validate_agent_request, validate_wake_request, AgentRequest, AgentResponse, HooksErrorResponse,
    WakeMode, WakeRequest, WakeResponse,
};
use crate::hooks::registry::{HookMappingContext, HookMappingResult, HookRegistry};
use crate::plugins::tools::{ToolInvokeContext, ToolInvokeResult, ToolsRegistry};
use crate::plugins::{DispatchError, WebhookDispatcher, WebhookRequest};
use crate::server::ws::{SystemEvent, WsServerState};

/// Default max body size for hooks (256KB)
pub const DEFAULT_MAX_BODY_BYTES: usize = 262144;

/// Default hooks base path
pub const DEFAULT_HOOKS_PATH: &str = "/hooks";
const HOOK_SENDER_SCOPE_KDF_TAG: &[u8] = b"hooks-sender-scope-v1";
const HOOK_SENDER_SCOPE_KDF_FALLBACK_KEY: &str = "carapace-hooks-sender-scope-fallback";
type HmacSha256 = Hmac<Sha256>;

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
    /// Secret used for keyed hook sender derivation.
    pub sender_scope_secret: Option<String>,
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
            sender_scope_secret: None,
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
    if cfg.get("hooks").is_some() {
        return Err("hooks must be configured under gateway.hooks".to_string());
    }

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

    let hooks_path = hooks_obj
        .and_then(|h| h.get("path"))
        .and_then(|v| v.as_str())
        .map(normalize_hooks_path)
        .unwrap_or_else(|| DEFAULT_HOOKS_PATH.to_string());

    let hooks_max_body_bytes = hooks_obj
        .and_then(|h| h.get("maxBodyBytes"))
        .and_then(|v| v.as_u64())
        .and_then(|v| usize::try_from(v).ok())
        .filter(|v| *v > 0)
        .unwrap_or(DEFAULT_MAX_BODY_BYTES);

    // Auth: env vars take precedence over config
    let cfg_token = auth_obj
        .and_then(|a| a.get("token"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let cfg_password = auth_obj
        .and_then(|a| a.get("password"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let gateway_token = crate::config::read_config_env("CARAPACE_GATEWAY_TOKEN").or(cfg_token);
    let gateway_password =
        crate::config::read_config_env("CARAPACE_GATEWAY_PASSWORD").or(cfg_password);
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

    let sender_scope_secret = crate::config::read_config_env("CARAPACE_SERVER_SECRET")
        .filter(|value| !value.is_empty())
        .or_else(|| gateway_token.clone().filter(|value| !value.is_empty()))
        .or_else(|| gateway_password.clone().filter(|value| !value.is_empty()))
        .or_else(|| hooks_token.clone().filter(|value| !value.is_empty()));

    let control_ui_enabled = control_ui_obj
        .and_then(|c| c.get("enabled"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let control_ui_dist_path = control_ui_obj
        .and_then(|c| c.get("path"))
        .and_then(|v| v.as_str())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("dist/control-ui"));
    let control_ui_base_path = control_ui_obj
        .and_then(|c| c.get("basePath"))
        .and_then(|v| v.as_str())
        .map(normalize_control_ui_base_path)
        .unwrap_or_default();

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
        hooks_path,
        hooks_max_body_bytes,
        gateway_token,
        gateway_password,
        gateway_auth_mode: resolved_auth_mode,
        gateway_allow_tailscale: allow_tailscale,
        trusted_proxies,
        control_ui_base_path,
        control_ui_enabled,
        control_ui_dist_path,
        sender_scope_secret,
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
    mut middleware_config: MiddlewareConfig,
    hook_registry: Arc<HookRegistry>,
    tools_registry: Arc<ToolsRegistry>,
    channel_registry: Arc<ChannelRegistry>,
    ws_state: Option<Arc<WsServerState>>,
    tls_enabled: bool,
) -> Router {
    let start_time = chrono::Utc::now().timestamp();
    remap_default_hooks_rate_limit_prefix(&config, &mut middleware_config);

    let llm_provider = ws_state.as_ref().and_then(|ws| ws.llm_provider());
    let csrf_store = if middleware_config.enable_csrf {
        Some(CsrfTokenStore::new(middleware_config.csrf.clone()))
    } else {
        None
    };
    let control_ws_state = ws_state.clone();
    let state = build_app_state(
        &config,
        start_time,
        tls_enabled,
        AppStateComponents {
            hook_registry,
            tools_registry,
            channel_registry: channel_registry.clone(),
            ws_state,
            csrf_store: csrf_store.clone(),
        },
    );

    let mut router: Router<AppState> = Router::new();
    router = register_hooks_routes(router, &config);
    router = register_channel_webhook_routes(router, &config);
    router = register_plugin_webhook_routes(router, &config);
    router = register_core_routes(router);
    router = register_openai_routes(router, &config, llm_provider);

    // Control endpoints
    if config.control_endpoints_enabled {
        router = register_session_routes(
            router,
            &config,
            &channel_registry,
            control_ws_state,
            start_time,
        );
    }

    // Control UI routes (when enabled)
    if config.control_ui_enabled {
        router = register_admin_routes(router, &config);
    }

    apply_http_middleware_layers(router, state, middleware_config, csrf_store)
}

fn remap_default_hooks_rate_limit_prefix(
    config: &HttpConfig,
    middleware_config: &mut MiddlewareConfig,
) {
    let hooks_prefix = format!("{}/", normalize_hooks_path(&config.hooks_path));
    let default_hooks_prefix = format!("{}/", DEFAULT_HOOKS_PATH);
    if hooks_prefix != default_hooks_prefix {
        for limit in &mut middleware_config.rate_limit.route_limits {
            if limit.prefix == default_hooks_prefix {
                limit.prefix = hooks_prefix.clone();
            }
        }
    }
}

struct AppStateComponents {
    hook_registry: Arc<HookRegistry>,
    tools_registry: Arc<ToolsRegistry>,
    channel_registry: Arc<ChannelRegistry>,
    ws_state: Option<Arc<WsServerState>>,
    csrf_store: Option<CsrfTokenStore>,
}

fn build_app_state(
    config: &HttpConfig,
    start_time: i64,
    tls_enabled: bool,
    components: AppStateComponents,
) -> AppState {
    let AppStateComponents {
        hook_registry,
        tools_registry,
        channel_registry,
        ws_state,
        csrf_store,
    } = components;
    let health_checker = ws_state.as_ref().map(|_| {
        Arc::new(crate::server::health::HealthChecker::new(
            crate::server::ws::resolve_state_dir(),
        ))
    });
    let plugin_webhook_dispatcher = ws_state
        .as_ref()
        .and_then(|ws| ws.plugin_registry().cloned())
        .map(|registry| Arc::new(WebhookDispatcher::new(registry)));

    AppState {
        config: Arc::new(config.clone()),
        hook_registry,
        tools_registry,
        channel_registry,
        plugin_webhook_dispatcher,
        start_time,
        ws_state,
        health_checker,
        csrf_store,
        tls_enabled,
    }
}

fn register_hooks_routes(router: Router<AppState>, config: &HttpConfig) -> Router<AppState> {
    if !config.hooks_enabled {
        return router;
    }
    let hooks_path = normalize_hooks_path(&config.hooks_path);
    router
        .route(&format!("{}/wake", hooks_path), post(hooks_wake_handler))
        .route(&format!("{}/agent", hooks_path), post(hooks_agent_handler))
        .route(
            &format!("{}/{{*path}}", hooks_path),
            post(hooks_mapping_handler),
        )
}

fn register_channel_webhook_routes(
    router: Router<AppState>,
    config: &HttpConfig,
) -> Router<AppState> {
    let channel_router = Router::new()
        .route("/channels/telegram/webhook", post(telegram_webhook_handler))
        .route("/channels/slack/events", post(slack_events_handler))
        .layer(DefaultBodyLimit::max(config.hooks_max_body_bytes));
    router.merge(channel_router)
}

fn register_plugin_webhook_routes(
    router: Router<AppState>,
    config: &HttpConfig,
) -> Router<AppState> {
    let plugin_router = Router::new()
        .route("/plugins/{*path}", any(plugins_webhook_handler))
        .layer(DefaultBodyLimit::max(config.hooks_max_body_bytes));
    router.merge(plugin_router)
}

fn register_core_routes(router: Router<AppState>) -> Router<AppState> {
    router
        .route("/health", get(health_handler))
        .route("/health/live", get(health_handler))
        .route("/health/ready", get(health_ready_handler))
        .route("/metrics", get(crate::server::metrics::metrics_handler))
        .route("/tools/invoke", post(tools_invoke_handler))
}

fn build_openai_state(
    config: &HttpConfig,
    llm_provider: Option<Arc<dyn LlmProvider>>,
) -> OpenAiState {
    OpenAiState {
        chat_completions_enabled: config.openai_chat_completions_enabled,
        responses_enabled: config.openai_responses_enabled,
        gateway_token: config.gateway_token.clone(),
        gateway_password: config.gateway_password.clone(),
        gateway_auth_mode: config.gateway_auth_mode.clone(),
        gateway_allow_tailscale: config.gateway_allow_tailscale,
        trusted_proxies: config.trusted_proxies.clone(),
        llm_provider,
    }
}

fn register_openai_routes(
    mut router: Router<AppState>,
    config: &HttpConfig,
    llm_provider: Option<Arc<dyn LlmProvider>>,
) -> Router<AppState> {
    if !config.openai_chat_completions_enabled && !config.openai_responses_enabled {
        return router;
    }

    let openai_state = build_openai_state(config, llm_provider);
    if config.openai_chat_completions_enabled {
        let chat_state = openai_state.clone();
        router = router.route(
            "/v1/chat/completions",
            post(
                move |connect_info: MaybeConnectInfo, headers: HeaderMap, body: Bytes| {
                    let state = chat_state.clone();
                    async move {
                        openai::chat_completions_handler(State(state), connect_info, headers, body)
                            .await
                    }
                },
            ),
        );
    }

    if config.openai_responses_enabled {
        let responses_state = openai_state.clone();
        router = router.route(
            "/v1/responses",
            post(
                move |connect_info: MaybeConnectInfo, headers: HeaderMap, body: Bytes| {
                    let state = responses_state.clone();
                    async move {
                        openai::responses_handler(State(state), connect_info, headers, body).await
                    }
                },
            ),
        );
    }

    router
}

fn apply_http_middleware_layers(
    router: Router<AppState>,
    state: AppState,
    middleware_config: MiddlewareConfig,
    csrf_store: Option<CsrfTokenStore>,
) -> Router {
    // Order matters: last added = first executed
    // The order here is: rate_limit -> csrf -> security_headers -> handler
    let mut stateless_router: Router = router.with_state(state);

    if middleware_config.enable_rate_limit {
        let limiter = RateLimiter::new(middleware_config.rate_limit);
        stateless_router = stateless_router.layer(middleware::from_fn_with_state(
            limiter,
            rate_limit_middleware,
        ));
    }
    if let Some(csrf_store) = csrf_store {
        stateless_router =
            stateless_router.layer(middleware::from_fn_with_state(csrf_store, csrf_middleware));
    }
    if middleware_config.enable_security_headers {
        let headers_config = Arc::new(middleware_config.security_headers);
        stateless_router = stateless_router.layer(middleware::from_fn_with_state(
            headers_config,
            security_headers_middleware,
        ));
    }

    stateless_router
}

/// Register control session endpoints (status, channels, config, onboarding).
fn register_session_routes(
    router: Router<AppState>,
    config: &HttpConfig,
    channel_registry: &Arc<ChannelRegistry>,
    ws_state: Option<Arc<WsServerState>>,
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
        task_queue: ws_state.as_ref().map(|state| state.task_queue().clone()),
    };

    let control_state_status = control_state.clone();
    let control_state_channels = control_state.clone();
    let control_state_config_read = control_state.clone();
    let control_state_config_patch = control_state.clone();
    let control_state_onboarding_status = control_state.clone();
    let control_state_gemini_oauth_start = control_state.clone();
    let control_state_gemini_oauth_status = control_state.clone();
    let control_state_gemini_oauth_apply = control_state.clone();
    let control_state_gemini_api_key = control_state.clone();
    let control_state_codex_oauth_start = control_state.clone();
    let control_state_codex_oauth_status = control_state.clone();
    let control_state_codex_oauth_apply = control_state.clone();
    let control_state_tasks_create = control_state.clone();
    let control_state_tasks_list = control_state.clone();
    let control_state_tasks_get = control_state.clone();
    let control_state_tasks_patch = control_state.clone();
    let control_state_tasks_cancel = control_state.clone();
    let control_state_tasks_retry = control_state.clone();
    let control_state_tasks_resume = control_state.clone();

    router
        .route(
            "/control/status",
            get(move |connect_info: MaybeConnectInfo, headers: HeaderMap| {
                let state = control_state_status.clone();
                async move { control::status_handler(State(state), connect_info, headers).await }
            }),
        )
        .route(
            "/control/channels",
            get(move |connect_info: MaybeConnectInfo, headers: HeaderMap| {
                let state = control_state_channels.clone();
                async move { control::channels_handler(State(state), connect_info, headers).await }
            }),
        )
        .route(
            "/control/config",
            get(move |connect_info: MaybeConnectInfo, headers: HeaderMap| {
                let state = control_state_config_read.clone();
                async move { control::config_read_handler(State(state), connect_info, headers).await }
            })
            .patch(
                move |connect_info: MaybeConnectInfo, headers: HeaderMap, body: Bytes| {
                    let state = control_state_config_patch.clone();
                    async move {
                        control::config_patch_handler(State(state), connect_info, headers, body)
                            .await
                    }
                },
            ),
        )
        .route(
            "/control/onboarding/status",
            get(move |connect_info: MaybeConnectInfo, headers: HeaderMap| {
                let state = control_state_onboarding_status.clone();
                async move {
                    control::onboarding_status_handler(State(state), connect_info, headers).await
                }
            }),
        )
        .route(
            "/control/onboarding/gemini/oauth/start",
            post(
                move |connect_info: MaybeConnectInfo, headers: HeaderMap, body: Bytes| {
                    let state = control_state_gemini_oauth_start.clone();
                    async move {
                        control::gemini_oauth_start_handler(
                            State(state),
                            connect_info,
                            headers,
                            body,
                        )
                        .await
                    }
                },
            ),
        )
        .route(
            "/control/onboarding/gemini/oauth/{id}",
            get(
                move |Path(id): Path<String>, connect_info: MaybeConnectInfo, headers: HeaderMap| {
                    let state = control_state_gemini_oauth_status.clone();
                    async move {
                        control::gemini_oauth_status_handler(
                            Path(id),
                            State(state),
                            connect_info,
                            headers,
                        )
                        .await
                    }
                },
            ),
        )
        .route(
            "/control/onboarding/gemini/oauth/{id}/apply",
            post(
                move |Path(id): Path<String>, connect_info: MaybeConnectInfo, headers: HeaderMap| {
                    let state = control_state_gemini_oauth_apply.clone();
                    async move {
                        control::gemini_oauth_apply_handler(
                            Path(id),
                            State(state),
                            connect_info,
                            headers,
                        )
                        .await
                    }
                },
            ),
        )
        .route(
            "/control/onboarding/gemini/api-key",
            post(
                move |connect_info: MaybeConnectInfo, headers: HeaderMap, body: Bytes| {
                    let state = control_state_gemini_api_key.clone();
                    async move {
                        control::gemini_api_key_handler(
                            State(state),
                            connect_info,
                            headers,
                            body,
                        )
                        .await
                    }
                },
            ),
        )
        .route(
            "/control/onboarding/gemini/callback",
            get(move |query: Query<control::GeminiOAuthCallbackQuery>| async move {
                control::gemini_oauth_callback_handler(query).await
            }),
        )
        .route(
            "/control/onboarding/codex/oauth/start",
            post(
                move |connect_info: MaybeConnectInfo, headers: HeaderMap, body: Bytes| {
                    let state = control_state_codex_oauth_start.clone();
                    async move {
                        control::codex_oauth_start_handler(State(state), connect_info, headers, body)
                            .await
                    }
                },
            ),
        )
        .route(
            "/control/onboarding/codex/oauth/{id}",
            get(
                move |Path(id): Path<String>, connect_info: MaybeConnectInfo, headers: HeaderMap| {
                    let state = control_state_codex_oauth_status.clone();
                    async move {
                        control::codex_oauth_status_handler(
                            Path(id),
                            State(state),
                            connect_info,
                            headers,
                        )
                        .await
                    }
                },
            ),
        )
        .route(
            "/control/onboarding/codex/oauth/{id}/apply",
            post(
                move |Path(id): Path<String>, connect_info: MaybeConnectInfo, headers: HeaderMap| {
                    let state = control_state_codex_oauth_apply.clone();
                    async move {
                        control::codex_oauth_apply_handler(
                            Path(id),
                            State(state),
                            connect_info,
                            headers,
                        )
                        .await
                    }
                },
            ),
        )
        .route(
            "/control/onboarding/codex/callback",
            get(move |query: Query<control::CodexOAuthCallbackQuery>| async move {
                control::codex_oauth_callback_handler(query).await
            }),
        )
        .route(
            "/control/tasks",
            post(
                move |connect_info: MaybeConnectInfo, headers: HeaderMap, body: Bytes| {
                    let state = control_state_tasks_create.clone();
                    async move {
                        control::tasks_create_handler(State(state), connect_info, headers, body)
                            .await
                    }
                },
            ),
        )
        .route(
            "/control/tasks",
            get(
                move |connect_info: MaybeConnectInfo,
                      headers: HeaderMap,
                      query: Query<control::TaskListQuery>| {
                    let state = control_state_tasks_list.clone();
                    async move {
                        control::tasks_list_handler(State(state), connect_info, headers, query)
                            .await
                    }
                },
            ),
        )
        .route(
            "/control/tasks/{id}",
            get(
                move |Path(id): Path<String>,
                      connect_info: MaybeConnectInfo,
                      headers: HeaderMap| {
                    let state = control_state_tasks_get.clone();
                    async move {
                        control::tasks_get_handler(Path(id), State(state), connect_info, headers)
                            .await
                    }
                },
            ),
        )
        .route(
            "/control/tasks/{id}",
            patch(
                move |Path(id): Path<String>,
                      connect_info: MaybeConnectInfo,
                      headers: HeaderMap,
                      body: Bytes| {
                    let state = control_state_tasks_patch.clone();
                    async move {
                        control::tasks_patch_handler(
                            Path(id),
                            State(state),
                            connect_info,
                            headers,
                            body,
                        )
                        .await
                    }
                },
            ),
        )
        .route(
            "/control/tasks/{id}/cancel",
            post(
                move |Path(id): Path<String>,
                      connect_info: MaybeConnectInfo,
                      headers: HeaderMap,
                      body: Bytes| {
                    let state = control_state_tasks_cancel.clone();
                    async move {
                        control::tasks_cancel_handler(
                            Path(id),
                            State(state),
                            connect_info,
                            headers,
                            body,
                        )
                        .await
                    }
                },
            ),
        )
        .route(
            "/control/tasks/{id}/retry",
            post(
                move |Path(id): Path<String>,
                      connect_info: MaybeConnectInfo,
                      headers: HeaderMap,
                      body: Bytes| {
                    let state = control_state_tasks_retry.clone();
                    async move {
                        control::tasks_retry_handler(
                            Path(id),
                            State(state),
                            connect_info,
                            headers,
                            body,
                        )
                        .await
                    }
                },
            ),
        )
        .route(
            "/control/tasks/{id}/resume",
            post(
                move |Path(id): Path<String>,
                      connect_info: MaybeConnectInfo,
                      headers: HeaderMap,
                      body: Bytes| {
                    let state = control_state_tasks_resume.clone();
                    async move {
                        control::tasks_resume_handler(
                            Path(id),
                            State(state),
                            connect_info,
                            headers,
                            body,
                        )
                        .await
                    }
                },
            ),
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
            &format!("{}/__carapace_avatar__/{{agent_id}}", base),
            get(avatar_handler),
        )
        .route(&format!("{}/{{*path}}", base), get(control_ui_static))
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

/// Normalize control UI base path (empty string uses default /ui).
fn normalize_control_ui_base_path(path: &str) -> String {
    let trimmed = path.trim();
    if trimmed.is_empty() || trimmed == "/" {
        return String::new();
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

fn resolve_slack_signing_secret(cfg: &Value) -> Option<String> {
    cfg.get("slack")
        .and_then(|s| s.get("signingSecret"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .or_else(|| crate::config::read_config_env("SLACK_SIGNING_SECRET"))
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

fn unix_now_ms() -> u64 {
    crate::time::unix_now_ms_u64()
}

fn enqueue_hook_wake_event(ws: &Arc<WsServerState>, text: &str, mode: WakeMode) {
    let reason = match mode {
        WakeMode::Now => "hook-wake-now",
        WakeMode::NextHeartbeat => "hook-wake-next-heartbeat",
    };
    // Hook wake events track intent + mode and intentionally omit source-network
    // attribution fields. Sender scoping is applied on run dispatch paths.
    ws.enqueue_system_event(SystemEvent {
        ts: unix_now_ms(),
        text: text.to_string(),
        host: None,
        ip: None,
        device_id: None,
        instance_id: None,
        reason: Some(reason.to_string()),
    });
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
            if let Some(ws) = &state.ws_state {
                enqueue_hook_wake_event(ws, &validated.text, validated.mode);
                debug!(
                    "Wake event dispatched: mode={:?}, text_len={}",
                    validated.mode,
                    validated.text.len()
                );
            } else {
                debug!(
                    "Wake event accepted (no runtime): mode={:?}, text_len={}",
                    validated.mode,
                    validated.text.len()
                );
            }
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
            route: None,
            thinking: None,
            deliver: None,
            wake_mode: None,
            session_scope: None,
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
async fn dispatch_agent_run(
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
        validated.session_scope.as_deref(),
        metadata,
    )
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(AgentResponse::error(&format!("session error: {}", e))),
        )
            .into_response()
    })?;

    crate::sessions::append_message_blocking(
        ws.session_store().clone(),
        crate::sessions::ChatMessage::user(session.id.clone(), &validated.message),
    )
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(AgentResponse::error(&format!("session write error: {}", e))),
        )
            .into_response()
    })?;

    // Validate model before registering the run to avoid orphan entries.
    let mut config = crate::agent::AgentConfig::default();
    // Resolve model through route resolver; request-level model/route param
    // takes highest precedence, then session-level route/model.
    if let Err(e) = crate::agent::resolve_agent_model(
        &mut config,
        &cfg,
        None,
        &crate::agent::ModelResolutionOverrides {
            request_route: validated.route.as_deref(),
            request_model: validated.model.as_deref(),
            session_route: session.metadata.route.as_deref(),
            session_model: session.metadata.model.as_deref(),
        },
    ) {
        e.log_configuration_hint();
        return Err((StatusCode::BAD_REQUEST, Json(AgentResponse::from(&e))).into_response());
    }
    crate::agent::apply_agent_config_from_settings(&mut config, &cfg, None);
    if config.model.trim().is_empty() {
        let error = AgentError::Configuration(AgentConfigurationError::missing_model());
        error.log_configuration_hint();
        return Err((StatusCode::BAD_REQUEST, Json(AgentResponse::from(&error))).into_response());
    }

    // Provider availability is a precondition for queueing a run; check it
    // before `registry.register` so a missing provider can't orphan an entry.
    // Returns 503 (server-side misconfiguration), matching the OpenAI-compat
    // path's status for the same condition.
    let Some(provider) = ws.llm_provider() else {
        let error = AgentError::Configuration(AgentConfigurationError::provider_not_configured());
        error.log_configuration_hint();
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(AgentResponse::from(&error)),
        )
            .into_response());
    };

    // Register the agent run
    let cancel_token = tokio_util::sync::CancellationToken::new();
    let run = crate::server::ws::AgentRun {
        run_id: run_id.to_string(),
        session_key: session.session_key.clone(),
        delivery_recipient_id: None,
        typing_context: None,
        status: crate::server::ws::AgentRunStatus::Queued,
        message: validated.message.clone(),
        response: String::new(),
        error: None,
        created_at: unix_now_ms(),
        started_at: None,
        completed_at: None,
        cancel_token: cancel_token.clone(),
        waiters: Vec::new(),
    };

    {
        let mut registry = ws.agent_run_registry.lock();
        registry.register(run);
    }

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
    debug!("Agent job dispatched: runId='{}'", run_id);

    Ok(())
}

fn sender_scope_for_hook_request(
    remote_addr: Option<SocketAddr>,
    headers: &HeaderMap,
    trusted_proxies: &[String],
    sender_scope_secret: Option<&str>,
) -> String {
    let Some(remote_ip) = auth::resolve_request_client_ip(remote_addr, headers, trusted_proxies)
    else {
        return "unknown".to_string();
    };

    let secret = sender_scope_secret
        .filter(|value| !value.is_empty())
        .unwrap_or(HOOK_SENDER_SCOPE_KDF_FALLBACK_KEY);
    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key length");
    mac.update(HOOK_SENDER_SCOPE_KDF_TAG);
    mac.update(remote_ip.to_string().as_bytes());
    let digest = mac.finalize().into_bytes();
    format!("sender_{}", hex::encode(digest))
}

/// POST /hooks/agent - Dispatch message to agent
async fn hooks_agent_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    uri: Uri,
    connect_info: MaybeConnectInfo,
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
            debug!("Agent job accepted (no runtime): runId='{}'", run_id);
            return (StatusCode::ACCEPTED, Json(AgentResponse::success(run_id))).into_response();
        }
    };

    let sender_id = sender_scope_for_hook_request(
        connect_info.0,
        &headers,
        &state.config.trusted_proxies,
        state.config.sender_scope_secret.as_deref(),
    );

    if let Err(resp) = dispatch_agent_run(&ws, &validated, &run_id, &sender_id).await {
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

    let secret = match telegram_inbound::resolve_webhook_secret(&cfg) {
        Some(secret) => secret,
        None => {
            warn!("Telegram webhook secret not configured; rejecting inbound request");
            return StatusCode::UNAUTHORIZED.into_response();
        }
    };

    let provided = headers
        .get("X-Telegram-Bot-Api-Secret-Token")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !crate::auth::timing_safe_eq(&secret, provided) {
        return StatusCode::UNAUTHORIZED.into_response();
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
    )
    .await
    {
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
                )
                .await
                {
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
async fn hook_result_to_response(
    state: &AppState,
    headers: &HeaderMap,
    connect_info: MaybeConnectInfo,
    result: Result<HookMappingResult, crate::hooks::HookMappingError>,
) -> Response {
    match result {
        Ok(HookMappingResult::Skip) => {
            // Transform returned null - skip this webhook
            (StatusCode::NO_CONTENT, "").into_response()
        }
        Ok(HookMappingResult::Wake { text, mode }) => {
            let wake_mode = WakeMode::from_str_lenient(&mode);
            if let Some(ws) = &state.ws_state {
                enqueue_hook_wake_event(ws, &text, wake_mode);
                debug!(
                    "Hook triggered wake dispatch: mode='{}', text_len={}",
                    mode,
                    text.len()
                );
            } else {
                debug!(
                    "Hook triggered wake accepted (no runtime): mode='{}', text_len={}",
                    mode,
                    text.len()
                );
            }
            (StatusCode::OK, Json(WakeResponse::success(wake_mode))).into_response()
        }
        Ok(HookMappingResult::Agent {
            message,
            name,
            channel,
            to,
            model,
            route,
            thinking,
            deliver,
            wake_mode,
            session_scope,
            timeout_seconds,
            allow_unsafe_external_content,
        }) => {
            let run_id = Uuid::new_v4().to_string();

            let req = AgentRequest {
                message: Some(message),
                name: Some(name),
                channel: Some(channel),
                to,
                model,
                route,
                thinking,
                deliver: Some(deliver),
                wake_mode: Some(wake_mode),
                // Keep mapped session scoping out of AgentRequest to avoid
                // treating it as a sensitive field flow in CodeQL's
                // cleartext-logging heuristic.
                session_scope: None,
                timeout_seconds: timeout_seconds.map(|s| s as f64),
                allow_unsafe_external_content: Some(allow_unsafe_external_content),
                venice_parameters: None,
            };
            let mut validated = match validate_agent_request(&req, &state.config.valid_channels) {
                Ok(v) => v,
                Err(e) => {
                    return (StatusCode::BAD_REQUEST, Json(AgentResponse::error(&e)))
                        .into_response();
                }
            };
            validated.session_scope = Some(session_scope);

            let ws = match &state.ws_state {
                Some(ws) => ws.clone(),
                None => {
                    debug!(
                        "Hook triggered agent accepted (no runtime): runId='{}'",
                        run_id
                    );
                    return (StatusCode::ACCEPTED, Json(AgentResponse::success(run_id)))
                        .into_response();
                }
            };

            let sender_id = sender_scope_for_hook_request(
                connect_info.0,
                headers,
                &state.config.trusted_proxies,
                state.config.sender_scope_secret.as_deref(),
            );
            if let Err(resp) = dispatch_agent_run(&ws, &validated, &run_id, &sender_id).await {
                return resp;
            }

            debug!("Hook triggered agent dispatch: runId='{}'", run_id);
            (StatusCode::ACCEPTED, Json(AgentResponse::success(run_id))).into_response()
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
async fn execute_hook_mapping(
    state: &AppState,
    headers: &HeaderMap,
    connect_info: MaybeConnectInfo,
    path: &str,
    ctx: &HookMappingContext,
) -> Response {
    let mapping = match state.hook_registry.find_match(ctx) {
        Some(m) => m,
        None => {
            debug!("No hook mapping found for path: {}", path);
            return (StatusCode::NOT_FOUND, "Not Found").into_response();
        }
    };

    debug!("Hook mapping found for path '{}': {:?}", path, mapping.id);

    let result = state.hook_registry.evaluate(&mapping, ctx);
    hook_result_to_response(state, headers, connect_info, result).await
}

/// POST /hooks/<mapping> - Custom hook mappings
async fn hooks_mapping_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    uri: Uri,
    connect_info: MaybeConnectInfo,
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
    execute_hook_mapping(&state, &headers, connect_info, &path, &ctx).await
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
        Some(token) => {
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
    connect_info: MaybeConnectInfo,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    // Check gateway auth (requires loopback if no auth configured)
    // If ConnectInfo is unavailable (e.g., in tests), treat as non-loopback
    let remote_addr = connect_info.0;
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

            let (csrf_cookie_name, csrf_header_name) = if let Some(store) = &state.csrf_store {
                let config = store.config();
                if config.enabled {
                    (
                        csrf_cookie_name(config).to_string(),
                        config.header_name.clone(),
                    )
                } else {
                    (String::new(), String::new())
                }
            } else {
                (String::new(), String::new())
            };

            let injected = content
                .replace(
                    "__CARAPACE_CONTROL_UI_BASE_PATH__",
                    &html_attr_escape(&base_path),
                )
                .replace("__CARAPACE_ASSISTANT_NAME__", &html_attr_escape("Carapace"))
                .replace("__CARAPACE_ASSISTANT_AVATAR__", &html_attr_escape(""))
                .replace(
                    "__CARAPACE_CSRF_COOKIE__",
                    &html_attr_escape(&csrf_cookie_name),
                )
                .replace(
                    "__CARAPACE_CSRF_HEADER__",
                    &html_attr_escape(&csrf_header_name),
                );

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

fn html_attr_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
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

/// GET /__carapace_avatar__/{agent_id} - Serve agent avatar
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
    use crate::hooks::registry::{HookAction, HookMapping};
    use crate::server::ws::{WsServerConfig, WsServerState};
    use crate::sessions;
    use crate::test_support::env::ScopedEnv;
    use axum::body::Body;
    use axum::http::Request;
    use std::sync::Arc;
    use tower::ServiceExt;

    fn set_temp_config_path() -> (tempfile::TempDir, ScopedEnv) {
        let temp = tempfile::tempdir().unwrap();
        let config_path = temp.path().join("carapace-test-config.json5");
        let mut env_guard = ScopedEnv::new();
        env_guard.set("CARAPACE_CONFIG_PATH", config_path.as_os_str());
        (temp, env_guard)
    }

    fn make_headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for (name, value) in pairs {
            headers.insert(
                axum::http::header::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                axum::http::HeaderValue::from_str(value).unwrap(),
            );
        }
        headers
    }

    fn test_config() -> HttpConfig {
        HttpConfig {
            hooks_token: Some("test-hooks-token".to_string()),
            hooks_enabled: true,
            gateway_token: Some("test-gateway-token".to_string()),
            sender_scope_secret: None,
            control_endpoints_enabled: true,
            control_ui_enabled: true,
            ..Default::default()
        }
    }

    /// Create a test router that can be used with oneshot()
    fn test_router(config: HttpConfig) -> Router {
        create_router(config)
    }

    fn test_router_with_hook_registry(
        config: HttpConfig,
        hook_registry: Arc<HookRegistry>,
        ws_state: Arc<WsServerState>,
    ) -> Router {
        create_router_with_state(
            config,
            MiddlewareConfig::none(),
            hook_registry,
            Arc::new(ToolsRegistry::new()),
            Arc::new(ChannelRegistry::new()),
            Some(ws_state),
            false,
        )
    }

    fn test_router_with_hook_registry_no_runtime(
        config: HttpConfig,
        hook_registry: Arc<HookRegistry>,
    ) -> Router {
        create_router_with_state(
            config,
            MiddlewareConfig::none(),
            hook_registry,
            Arc::new(ToolsRegistry::new()),
            Arc::new(ChannelRegistry::new()),
            None,
            false,
        )
    }

    async fn read_control_config_snapshot(router: Router) -> Value {
        let req = Request::builder()
            .method("GET")
            .uri("/control/config")
            .header("authorization", "Bearer test-gateway-token")
            .body(Body::empty())
            .unwrap();
        let response = router.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice(&body).unwrap()
    }

    fn make_test_ws_state() -> (Arc<WsServerState>, tempfile::TempDir) {
        let tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(sessions::SessionStore::with_base_path(
            tmp.path().join("sessions"),
        ));
        let state = WsServerState::new(WsServerConfig::default()).with_session_store(store);
        (Arc::new(state), tmp)
    }

    fn make_test_ws_state_with_provider() -> (Arc<WsServerState>, tempfile::TempDir) {
        let tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(sessions::SessionStore::with_base_path(
            tmp.path().join("sessions"),
        ));
        let state = WsServerState::new(WsServerConfig::default())
            .with_session_store(store)
            .with_llm_provider(Arc::new(crate::test_support::agent::StaticTestProvider));
        (Arc::new(state), tmp)
    }

    #[test]
    fn test_sender_scope_for_hook_request_with_ipv4_remote_addr() {
        let headers = HeaderMap::new();
        let sender = sender_scope_for_hook_request(
            Some(SocketAddr::from(([127, 0, 0, 1], 43123))),
            &headers,
            &[],
            None,
        );
        assert!(sender.starts_with("sender_"));
        assert_eq!(sender.len(), 71);
    }

    #[test]
    fn test_sender_scope_for_hook_request_without_remote_addr() {
        let headers = HeaderMap::new();
        let sender = sender_scope_for_hook_request(None, &headers, &[], None);
        assert_eq!(sender, "unknown");
    }

    #[test]
    fn test_sender_scope_for_hook_request_with_ipv6_remote_addr() {
        let headers = HeaderMap::new();
        let sender = sender_scope_for_hook_request(
            Some(SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 1], 43123))),
            &headers,
            &[],
            None,
        );
        assert!(sender.starts_with("sender_"));
        assert_eq!(sender.len(), 71);
    }

    #[test]
    fn test_sender_scope_for_hook_request_uses_forwarded_for_for_trusted_proxy() {
        let trusted = vec!["203.0.113.5".to_string()];
        let headers = make_headers(&[
            ("x-forwarded-for", "198.51.100.9"),
            ("x-real-ip", "198.51.100.10"),
        ]);
        let trusted_sender = sender_scope_for_hook_request(
            Some("203.0.113.5:1234".parse().unwrap()),
            &headers,
            &trusted,
            None,
        );
        let direct_sender = sender_scope_for_hook_request(
            Some("203.0.113.5:1234".parse().unwrap()),
            &headers,
            &[],
            None,
        );
        let fallback_sender = sender_scope_for_hook_request(
            Some("198.51.100.9:1234".parse().unwrap()),
            &HeaderMap::new(),
            &[],
            None,
        );

        assert_eq!(trusted_sender, fallback_sender);
        assert_ne!(trusted_sender, direct_sender);
    }

    #[test]
    fn test_sender_scope_for_hook_request_normalizes_ipv4_mapped_v6() {
        let headers = HeaderMap::new();
        let mapped = sender_scope_for_hook_request(
            Some("[::ffff:127.0.0.1]:8080".parse().unwrap()),
            &headers,
            &[],
            None,
        );
        let ipv4 = sender_scope_for_hook_request(
            Some("127.0.0.1:8080".parse().unwrap()),
            &headers,
            &[],
            None,
        );
        assert_eq!(mapped, ipv4);
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
    async fn test_hooks_wake_dispatches_system_event_with_runtime() {
        let (ws_state, _tmp) = make_test_ws_state();
        let router = test_router_with_hook_registry(
            test_config(),
            Arc::new(HookRegistry::new()),
            ws_state.clone(),
        );

        let req = Request::builder()
            .method("POST")
            .uri("/hooks/wake")
            .header("authorization", "Bearer test-hooks-token")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"text":"wake now","mode":"next-heartbeat"}"#))
            .unwrap();

        let response = router.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["ok"], true);
        assert_eq!(json["mode"], "next-heartbeat");

        let history = ws_state.get_system_event_history();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].text, "wake now");
        assert_eq!(
            history[0].reason.as_deref(),
            Some("hook-wake-next-heartbeat")
        );
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

    /// Integration test for issue #398: when route resolution fails, the
    /// HTTP `/hooks/agent` response body must carry the stable wire-format
    /// `errorCode` and the human-readable `error` message must NOT contain
    /// any of the internal config-key paths the leaky pre-#398 messages
    /// did. Exercises the actual axum handler via `oneshot` (with a real
    /// `ws_state` so `dispatch_agent_run` actually runs), not just the
    /// `AgentResponse` constructor in isolation.
    #[tokio::test]
    async fn test_hooks_agent_unknown_route_emits_typed_error_code() {
        let (temp, _guard) = set_temp_config_path();
        // Empty config — no routes map, no agents.defaults.model. The
        // request below specifies an unknown route name, which forces
        // `resolve_execution_target` into the `UnknownRoute` arm.
        std::fs::write(temp.path().join("carapace-test-config.json5"), "{}").unwrap();
        let (ws_state, _tmp) = make_test_ws_state();
        let router =
            test_router_with_hook_registry(test_config(), Arc::new(HookRegistry::new()), ws_state);

        let req = Request::builder()
            .method("POST")
            .uri("/hooks/agent")
            .header("authorization", "Bearer test-hooks-token")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"message":"hello","route":"nonexistent-route-name"}"#,
            ))
            .unwrap();

        let response = router.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(json["ok"], false);
        assert_eq!(json["errorCode"], "unknown_route");

        let error_msg = json["error"].as_str().expect("error message");
        assert!(
            !error_msg.contains("`routes`")
                && !error_msg.contains("top-level")
                && !error_msg.contains("agents.defaults"),
            "human-readable error must not leak internal config-key paths: {error_msg}"
        );
    }

    /// Companion to the unknown-route test: with no route or model
    /// configured anywhere, `resolve_execution_target` returns
    /// `MissingModel`, which surfaces as `errorCode: "missing_model"`
    /// on the HTTP wire.
    #[tokio::test]
    async fn test_hooks_agent_missing_model_emits_typed_error_code() {
        let (temp, _guard) = set_temp_config_path();
        std::fs::write(temp.path().join("carapace-test-config.json5"), "{}").unwrap();
        let (ws_state, _tmp) = make_test_ws_state();
        let router =
            test_router_with_hook_registry(test_config(), Arc::new(HookRegistry::new()), ws_state);

        let req = Request::builder()
            .method("POST")
            .uri("/hooks/agent")
            .header("authorization", "Bearer test-hooks-token")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"message":"hello"}"#))
            .unwrap();

        let response = router.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(json["ok"], false);
        assert_eq!(json["errorCode"], "missing_model");

        let error_msg = json["error"].as_str().expect("error message");
        assert!(
            !error_msg.contains("`route`")
                && !error_msg.contains("`model`")
                && !error_msg.contains("agents.defaults"),
            "human-readable error must not leak internal config-key paths: {error_msg}"
        );
    }

    /// `/hooks/agent` surfaces `provider_not_configured` with `ok: false`
    /// when the request resolves to a valid model but no LLM provider is
    /// attached to the runtime. Pins that the path doesn't silently queue.
    #[tokio::test]
    async fn test_hooks_agent_provider_not_configured_emits_typed_error_code() {
        let (temp, _guard) = set_temp_config_path();
        std::fs::write(
            temp.path().join("carapace-test-config.json5"),
            r#"{ agents: { defaults: { model: "anthropic:test-model" } } }"#,
        )
        .unwrap();
        // make_test_ws_state has no provider; that's the misconfigured path.
        let (ws_state, _tmp) = make_test_ws_state();
        let router =
            test_router_with_hook_registry(test_config(), Arc::new(HookRegistry::new()), ws_state);

        let req = Request::builder()
            .method("POST")
            .uri("/hooks/agent")
            .header("authorization", "Bearer test-hooks-token")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"message":"hello"}"#))
            .unwrap();

        let response = router.oneshot(req).await.unwrap();
        // 503 SERVICE_UNAVAILABLE matches the existing OpenAI-compat path
        // for the identical server-side misconfiguration; 400 would
        // mis-signal a client-side problem.
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(json["ok"], false);
        assert_eq!(json["errorCode"], "provider_not_configured");

        let error_msg = json["error"].as_str().expect("error message");
        assert!(
            !error_msg.contains("ANTHROPIC_API_KEY") && !error_msg.contains("authProfile"),
            "wire-facing message must not leak operator-only env-var hints: {error_msg}"
        );
    }

    #[tokio::test]
    async fn test_hooks_mapping_agent_dispatches_real_run() {
        let (temp, _guard) = set_temp_config_path();
        std::fs::write(
            temp.path().join("carapace-test-config.json5"),
            r#"{ agents: { defaults: { model: "anthropic:test-model" } } }"#,
        )
        .unwrap();
        let (ws_state, _tmp) = make_test_ws_state_with_provider();
        let hook_registry = Arc::new(HookRegistry::new());
        let mut mapping = HookMapping::new("agent-map")
            .with_path("agent-map")
            .with_action(HookAction::Agent)
            .with_message_template("Mapped {{message}}");
        mapping.session_scope = Some("hook:mapped".to_string());
        hook_registry.register(mapping);

        let router = test_router_with_hook_registry(test_config(), hook_registry, ws_state.clone());

        let req = Request::builder()
            .method("POST")
            .uri("/hooks/agent-map")
            .header("authorization", "Bearer test-hooks-token")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"message":"run this"}"#))
            .unwrap();

        let response = router.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::ACCEPTED);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["ok"], true);
        let run_id = json["runId"].as_str().expect("runId must be returned");

        let registry = ws_state.agent_run_registry.lock();
        let run = registry
            .get(run_id)
            .expect("hook mapping agent action must register a real run");
        assert_eq!(run.message, "Mapped run this");
        assert!(!run.session_key.is_empty());
    }

    #[tokio::test]
    async fn test_hooks_mapping_agent_accepts_when_runtime_missing() {
        let hook_registry = Arc::new(HookRegistry::new());
        let mapping = HookMapping::new("agent-map-no-runtime")
            .with_path("agent-map-no-runtime")
            .with_action(HookAction::Agent)
            .with_message_template("Mapped {{message}}");
        hook_registry.register(mapping);

        let router = test_router_with_hook_registry_no_runtime(test_config(), hook_registry);

        let req = Request::builder()
            .method("POST")
            .uri("/hooks/agent-map-no-runtime")
            .header("authorization", "Bearer test-hooks-token")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"message":"run this"}"#))
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
    async fn test_hooks_mapping_wake_dispatches_system_event_with_runtime() {
        let (ws_state, _tmp) = make_test_ws_state();
        let hook_registry = Arc::new(HookRegistry::new());
        let mut mapping = HookMapping::new("wake-map")
            .with_path("wake-map")
            .with_action(HookAction::Wake)
            .with_text_template("Wake {{reason}}");
        mapping.wake_mode = Some("next-heartbeat".to_string());
        hook_registry.register(mapping);

        let router = test_router_with_hook_registry(test_config(), hook_registry, ws_state.clone());

        let req = Request::builder()
            .method("POST")
            .uri("/hooks/wake-map")
            .header("authorization", "Bearer test-hooks-token")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"reason":"mapped"}"#))
            .unwrap();

        let response = router.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["ok"], true);
        assert_eq!(json["mode"], "next-heartbeat");

        let history = ws_state.get_system_event_history();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].text, "Wake mapped");
        assert_eq!(
            history[0].reason.as_deref(),
            Some("hook-wake-next-heartbeat")
        );
    }

    #[tokio::test]
    async fn test_hooks_mapping_wake_accepts_when_runtime_missing() {
        let hook_registry = Arc::new(HookRegistry::new());
        let mapping = HookMapping::new("wake-map-no-runtime")
            .with_path("wake-map-no-runtime")
            .with_action(HookAction::Wake)
            .with_text_template("Wake {{reason}}");
        hook_registry.register(mapping);

        let router = test_router_with_hook_registry_no_runtime(test_config(), hook_registry);

        let req = Request::builder()
            .method("POST")
            .uri("/hooks/wake-map-no-runtime")
            .header("authorization", "Bearer test-hooks-token")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"reason":"fallback"}"#))
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
    async fn test_control_config_read_requires_auth() {
        let router = test_router(test_config());
        let req = Request::builder()
            .method("GET")
            .uri("/control/config")
            .body(Body::empty())
            .unwrap();
        let response = router.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_control_config_read_returns_snapshot() {
        let (temp, _guard) = set_temp_config_path();
        std::fs::write(
            temp.path().join("carapace-test-config.json5"),
            r#"{
  "gateway": {
    "controlUi": { "enabled": true }
  },
  "anthropic": {
    "apiKey": "test-secret-anthropic-key"
  },
  "bedrock": {
    "accessKeyId": "AKIA_TEST_ACCESS_KEY"
  }
}"#,
        )
        .unwrap();

        let router = test_router(test_config());
        let req = Request::builder()
            .method("GET")
            .uri("/control/config")
            .header("authorization", "Bearer test-gateway-token")
            .body(Body::empty())
            .unwrap();
        let response = router.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["ok"], true);
        assert!(json["config"].is_object());
        assert_eq!(json["config"]["anthropic"]["apiKey"], "[REDACTED]");
        assert_eq!(json["config"]["bedrock"]["accessKeyId"], "[REDACTED]");
    }

    #[tokio::test]
    async fn test_control_config_patch_updates_allowed_path() {
        let (_temp, _guard) = set_temp_config_path();
        let router = test_router(test_config());
        let snapshot = read_control_config_snapshot(router.clone()).await;
        let mut req_body = json!({
            "path": "gateway.controlUi.enabled",
            "value": true,
        });
        if let Some(hash) = snapshot["hash"].as_str() {
            req_body["baseHash"] = json!(hash);
        }

        let req = Request::builder()
            .method("PATCH")
            .uri("/control/config")
            .header("authorization", "Bearer test-gateway-token")
            .header("content-type", "application/json")
            .body(Body::from(req_body.to_string()))
            .unwrap();
        let response = router.clone().oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["ok"], true);
        assert_eq!(json["applied"]["path"], "gateway.controlUi.enabled");
        assert_eq!(json["applied"]["value"], true);
    }

    #[tokio::test]
    async fn test_control_config_patch_rejects_non_allowlisted_path() {
        let (_temp, _guard) = set_temp_config_path();
        let router = test_router(test_config());
        let snapshot = read_control_config_snapshot(router.clone()).await;
        let mut req_body = json!({
            "path": "gateway.mode",
            "value": "lan",
        });
        if let Some(hash) = snapshot["hash"].as_str() {
            req_body["baseHash"] = json!(hash);
        }

        let req = Request::builder()
            .method("PATCH")
            .uri("/control/config")
            .header("authorization", "Bearer test-gateway-token")
            .header("content-type", "application/json")
            .body(Body::from(req_body.to_string()))
            .unwrap();
        let response = router.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_control_gemini_oauth_start_returns_flow() {
        let (_temp, mut env_guard) = set_temp_config_path();
        env_guard.set("CARAPACE_CONFIG_PASSWORD", "test-config-password");
        let router = test_router(test_config());

        let req = Request::builder()
            .method("POST")
            .uri("/control/onboarding/gemini/oauth/start")
            .header("authorization", "Bearer test-gateway-token")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"clientId":"google-client-id","clientSecret":"google-client-secret","redirectBaseUrl":"https://gateway.example.com"}"#,
            ))
            .unwrap();
        let response = router.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["ok"], true);
        assert!(json["flowId"].as_str().is_some());
        assert!(json["authUrl"]
            .as_str()
            .unwrap_or_default()
            .contains("accounts.google.com"));
        assert_eq!(
            json["redirectUri"],
            "https://gateway.example.com/control/onboarding/gemini/callback"
        );
    }

    #[tokio::test]
    async fn test_control_onboarding_status_lists_all_providers() {
        let (_temp, _guard) = set_temp_config_path();
        let router = test_router(test_config());

        let req = Request::builder()
            .method("GET")
            .uri("/control/onboarding/status")
            .header("authorization", "Bearer test-gateway-token")
            .body(Body::empty())
            .unwrap();
        let response = router.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["ok"], true);
        let providers = json["providers"]
            .as_array()
            .expect("providers should be an array");
        assert_eq!(
            providers.len(),
            crate::onboarding::setup::SetupProvider::all().len()
        );
        let anthropic = providers
            .iter()
            .find(|provider| provider["provider"] == "anthropic")
            .expect("anthropic status should be present");
        assert_eq!(anthropic["configured"], false);
        assert!(anthropic["assessment"].is_null());
        assert_eq!(anthropic["supportedAuthModes"][0], "apiKey");
        assert_eq!(anthropic["supportedAuthModes"][1], "setupToken");
        let codex = providers
            .iter()
            .find(|provider| provider["provider"] == "codex")
            .expect("codex status should be present");
        assert_eq!(codex["label"], "Codex");
    }

    #[tokio::test]
    async fn test_control_onboarding_status_requires_auth() {
        let (_temp, _guard) = set_temp_config_path();
        let router = test_router(test_config());

        let req = Request::builder()
            .method("GET")
            .uri("/control/onboarding/status")
            .body(Body::empty())
            .unwrap();
        let response = router.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_control_onboarding_status_reports_configured_provider_assessment() {
        let (temp, _guard) = set_temp_config_path();
        let config_path = temp.path().join("carapace-test-config.json5");
        std::fs::write(
            &config_path,
            r#"{
                agents: { defaults: { model: "gemini:gemini-2.5-flash" } },
                google: { apiKey: "AIza-test-key", baseUrl: "https://proxy.example.com" }
            }"#,
        )
        .unwrap();

        let router = test_router(test_config());
        let req = Request::builder()
            .method("GET")
            .uri("/control/onboarding/status")
            .header("authorization", "Bearer test-gateway-token")
            .body(Body::empty())
            .unwrap();
        let response = router.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        let providers = json["providers"]
            .as_array()
            .expect("providers should be an array");
        let gemini = providers
            .iter()
            .find(|provider| provider["provider"] == "gemini")
            .expect("gemini status should be present");
        assert_eq!(gemini["configured"], true);
        assert_eq!(gemini["assessment"]["provider"], "gemini");
        assert_eq!(gemini["assessment"]["status"], "partial");
        assert_eq!(gemini["assessment"]["authMode"], "apiKey");
    }

    #[tokio::test]
    async fn test_control_onboarding_status_ignores_defaulted_vertex_location() {
        let (temp, _guard) = set_temp_config_path();
        let config_path = temp.path().join("carapace-test-config.json5");
        std::fs::write(
            &config_path,
            r#"{
                agents: { defaults: { model: "openai:gpt-5.5" } }
            }"#,
        )
        .unwrap();

        let router = test_router(test_config());
        let req = Request::builder()
            .method("GET")
            .uri("/control/onboarding/status")
            .header("authorization", "Bearer test-gateway-token")
            .body(Body::empty())
            .unwrap();
        let response = router.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        let providers = json["providers"]
            .as_array()
            .expect("providers should be an array");
        let vertex = providers
            .iter()
            .find(|provider| provider["provider"] == "vertex")
            .expect("vertex status should be present");
        assert_eq!(vertex["configured"], false);
        assert!(vertex["assessment"].is_null());
    }

    #[tokio::test]
    async fn test_control_gemini_api_key_writes_config() {
        let (temp, _guard) = set_temp_config_path();
        let config_path = temp.path().join("carapace-test-config.json5");
        let router = test_router(test_config());

        let req = Request::builder()
            .method("POST")
            .uri("/control/onboarding/gemini/api-key")
            .header("authorization", "Bearer test-gateway-token")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"apiKey":"AIza-test-key","baseUrl":"https://proxy.example.com"}"#,
            ))
            .unwrap();
        let response = router.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["ok"], true);
        assert_eq!(json["applied"]["mode"], "apiKey");
        assert_eq!(json["applied"].as_object().map(|it| it.len()), Some(1));
        assert_eq!(json["providerStatus"]["provider"], "gemini");
        assert_eq!(json["providerStatus"]["configured"], true);
        assert_eq!(json["providerStatus"]["assessment"]["status"], "invalid");
        assert!(json["providerStatus"]["assessment"]
            .get("profileName")
            .is_none());
        assert!(json["providerStatus"]["assessment"].get("email").is_none());

        let content = std::fs::read_to_string(config_path).expect("written config");
        let parsed: Value = json5::from_str(&content).expect("valid json5 config");
        assert_eq!(parsed["google"]["apiKey"], "AIza-test-key");
        assert_eq!(parsed["google"]["baseUrl"], "https://proxy.example.com");
        assert!(parsed["google"].get("authProfile").is_none());
    }

    #[tokio::test]
    async fn test_control_gemini_oauth_apply_returns_provider_status() {
        let (temp, mut env_guard) = set_temp_config_path();
        env_guard.set("CARAPACE_CONFIG_PASSWORD", "test-config-password");
        env_guard.set("CARAPACE_STATE_DIR", temp.path().as_os_str());
        let flow_id =
            crate::onboarding::gemini::insert_completed_control_google_oauth_flow_for_test();
        let router = test_router(test_config());

        let req = Request::builder()
            .method("POST")
            .uri(format!("/control/onboarding/gemini/oauth/{flow_id}/apply"))
            .header("authorization", "Bearer test-gateway-token")
            .body(Body::empty())
            .unwrap();
        let response = router.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["ok"], true);
        assert_eq!(json["applied"]["mode"], "oauth");
        assert_eq!(json["applied"].as_object().map(|it| it.len()), Some(1));
        assert_eq!(json["providerStatus"]["provider"], "gemini");
        assert_eq!(json["providerStatus"]["configured"], true);
        assert_eq!(json["providerStatus"]["assessment"]["provider"], "gemini");
        assert_eq!(json["providerStatus"]["assessment"]["authMode"], "oauth");
        assert!(json["providerStatus"]["assessment"]
            .get("profileName")
            .is_none());
        assert!(json["providerStatus"]["assessment"].get("email").is_none());
    }

    #[tokio::test]
    async fn test_control_codex_oauth_start_returns_flow() {
        let (_temp, mut env_guard) = set_temp_config_path();
        env_guard.set("CARAPACE_CONFIG_PASSWORD", "test-config-password");
        let router = test_router(test_config());

        let req = Request::builder()
            .method("POST")
            .uri("/control/onboarding/codex/oauth/start")
            .header("authorization", "Bearer test-gateway-token")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"clientId":"openai-client-id","clientSecret":"openai-client-secret","redirectBaseUrl":"https://gateway.example.com"}"#,
            ))
            .unwrap();
        let response = router.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["ok"], true);
        assert!(json["flowId"].as_str().is_some());
        assert!(json["authUrl"]
            .as_str()
            .unwrap_or_default()
            .contains("auth.openai.com"));
        assert_eq!(
            json["redirectUri"],
            "https://gateway.example.com/control/onboarding/codex/callback"
        );
    }

    #[tokio::test]
    async fn test_control_codex_oauth_apply_returns_provider_status() {
        let (temp, mut env_guard) = set_temp_config_path();
        env_guard.set("CARAPACE_CONFIG_PASSWORD", "test-config-password");
        env_guard.set("CARAPACE_STATE_DIR", temp.path().as_os_str());
        let flow_id =
            crate::onboarding::codex::insert_completed_control_openai_oauth_flow_for_test();
        let router = test_router(test_config());

        let req = Request::builder()
            .method("POST")
            .uri(format!("/control/onboarding/codex/oauth/{flow_id}/apply"))
            .header("authorization", "Bearer test-gateway-token")
            .body(Body::empty())
            .unwrap();
        let response = router.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["ok"], true);
        assert_eq!(json["applied"]["mode"], "oauth");
        assert_eq!(json["applied"].as_object().map(|it| it.len()), Some(1));
        assert_eq!(json["providerStatus"]["provider"], "codex");
        assert_eq!(json["providerStatus"]["configured"], true);
        assert_eq!(json["providerStatus"]["assessment"]["provider"], "codex");
        assert_eq!(json["providerStatus"]["assessment"]["authMode"], "oauth");
        assert!(json["providerStatus"]["assessment"]
            .get("profileName")
            .is_none());
        assert!(json["providerStatus"]["assessment"].get("email").is_none());
    }

    #[tokio::test]
    async fn test_control_tasks_create_list_and_get() {
        let (ws_state, _tmp) = make_test_ws_state();
        let router = test_router_with_hook_registry(
            test_config(),
            Arc::new(HookRegistry::new()),
            ws_state.clone(),
        );

        let create_req = Request::builder()
            .method("POST")
            .uri("/control/tasks")
            .header("authorization", "Bearer test-gateway-token")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"payload":{"kind":"systemEvent","text":"task wake"}}"#,
            ))
            .unwrap();
        let create_response = router.clone().oneshot(create_req).await.unwrap();
        assert_eq!(create_response.status(), StatusCode::CREATED);
        let create_body = axum::body::to_bytes(create_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let create_json: Value = serde_json::from_slice(&create_body).unwrap();
        assert_eq!(create_json["ok"], true);
        assert_eq!(
            create_json["task"]["policy"]["maxAttempts"],
            crate::tasks::DEFAULT_TASK_MAX_ATTEMPTS
        );
        assert_eq!(
            create_json["task"]["policy"]["maxTotalRuntimeMs"],
            crate::tasks::DEFAULT_TASK_MAX_TOTAL_RUNTIME_MS
        );
        assert_eq!(
            create_json["task"]["policy"]["maxTurns"],
            crate::tasks::DEFAULT_TASK_MAX_TURNS
        );
        assert_eq!(
            create_json["task"]["policy"]["maxRunTimeoutSeconds"],
            crate::tasks::DEFAULT_TASK_MAX_RUN_TIMEOUT_SECONDS
        );
        let task_id = create_json["task"]["id"]
            .as_str()
            .expect("task id should be present")
            .to_string();

        let list_req = Request::builder()
            .method("GET")
            .uri("/control/tasks")
            .header("authorization", "Bearer test-gateway-token")
            .body(Body::empty())
            .unwrap();
        let list_response = router.clone().oneshot(list_req).await.unwrap();
        assert_eq!(list_response.status(), StatusCode::OK);
        let list_body = axum::body::to_bytes(list_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let list_json: Value = serde_json::from_slice(&list_body).unwrap();
        assert_eq!(list_json["ok"], true);
        let listed_tasks = list_json["tasks"]
            .as_array()
            .expect("tasks should be an array");
        assert!(listed_tasks
            .iter()
            .any(|task| task.get("id").and_then(|id| id.as_str()) == Some(task_id.as_str())));

        let get_req = Request::builder()
            .method("GET")
            .uri(format!("/control/tasks/{task_id}"))
            .header("authorization", "Bearer test-gateway-token")
            .body(Body::empty())
            .unwrap();
        let get_response = router.oneshot(get_req).await.unwrap();
        assert_eq!(get_response.status(), StatusCode::OK);
        let get_body = axum::body::to_bytes(get_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let get_json: Value = serde_json::from_slice(&get_body).unwrap();
        assert_eq!(get_json["ok"], true);
        assert_eq!(get_json["task"]["id"], task_id);
    }

    #[tokio::test]
    async fn test_control_tasks_create_rejects_invalid_policy_budget() {
        let (ws_state, _tmp) = make_test_ws_state();
        let router = test_router_with_hook_registry(
            test_config(),
            Arc::new(HookRegistry::new()),
            ws_state.clone(),
        );

        let create_req = Request::builder()
            .method("POST")
            .uri("/control/tasks")
            .header("authorization", "Bearer test-gateway-token")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"payload":{"kind":"systemEvent","text":"task wake"},"policy":{"maxAttempts":0}}"#,
            ))
            .unwrap();
        let create_response = router.clone().oneshot(create_req).await.unwrap();
        assert_eq!(create_response.status(), StatusCode::BAD_REQUEST);
        let create_body = axum::body::to_bytes(create_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let create_json: Value = serde_json::from_slice(&create_body).unwrap();
        assert_eq!(create_json["ok"], false);
        assert!(create_json["error"]
            .as_str()
            .expect("error should be present")
            .contains("policy.maxAttempts"));
    }

    #[tokio::test]
    async fn test_control_tasks_cancel_and_retry() {
        let (ws_state, _tmp) = make_test_ws_state();
        let router = test_router_with_hook_registry(
            test_config(),
            Arc::new(HookRegistry::new()),
            ws_state.clone(),
        );

        let create_req = Request::builder()
            .method("POST")
            .uri("/control/tasks")
            .header("authorization", "Bearer test-gateway-token")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"payload":{"kind":"systemEvent","text":"task cancel retry"}}"#,
            ))
            .unwrap();
        let create_response = router.clone().oneshot(create_req).await.unwrap();
        assert_eq!(create_response.status(), StatusCode::CREATED);
        let create_body = axum::body::to_bytes(create_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let create_json: Value = serde_json::from_slice(&create_body).unwrap();
        let task_id = create_json["task"]["id"]
            .as_str()
            .expect("task id should be present")
            .to_string();

        let cancel_req = Request::builder()
            .method("POST")
            .uri(format!("/control/tasks/{task_id}/cancel"))
            .header("authorization", "Bearer test-gateway-token")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"reason":"operator stop"}"#))
            .unwrap();
        let cancel_response = router.clone().oneshot(cancel_req).await.unwrap();
        assert_eq!(cancel_response.status(), StatusCode::OK);
        let cancel_body = axum::body::to_bytes(cancel_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let cancel_json: Value = serde_json::from_slice(&cancel_body).unwrap();
        assert_eq!(cancel_json["ok"], true);
        assert_eq!(cancel_json["task"]["state"], "cancelled");

        let retry_req = Request::builder()
            .method("POST")
            .uri(format!("/control/tasks/{task_id}/retry"))
            .header("authorization", "Bearer test-gateway-token")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"delayMs":500,"reason":"operator retry"}"#))
            .unwrap();
        let retry_response = router.oneshot(retry_req).await.unwrap();
        assert_eq!(retry_response.status(), StatusCode::OK);
        let retry_body = axum::body::to_bytes(retry_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let retry_json: Value = serde_json::from_slice(&retry_body).unwrap();
        assert_eq!(retry_json["ok"], true);
        assert_eq!(retry_json["task"]["state"], "retry_wait");
        assert_eq!(retry_json["task"]["lastError"], "operator retry");
    }

    #[tokio::test]
    async fn test_control_tasks_resume_blocked_task() {
        let (ws_state, _tmp) = make_test_ws_state();
        let router = test_router_with_hook_registry(
            test_config(),
            Arc::new(HookRegistry::new()),
            ws_state.clone(),
        );

        let create_req = Request::builder()
            .method("POST")
            .uri("/control/tasks")
            .header("authorization", "Bearer test-gateway-token")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"payload":{"kind":"systemEvent","text":"task resume blocked"}}"#,
            ))
            .unwrap();
        let create_response = router.clone().oneshot(create_req).await.unwrap();
        assert_eq!(create_response.status(), StatusCode::CREATED);
        let create_body = axum::body::to_bytes(create_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let create_json: Value = serde_json::from_slice(&create_body).unwrap();
        let task_id = create_json["task"]["id"]
            .as_str()
            .expect("task id should be present")
            .to_string();

        let queue = ws_state.task_queue();
        let _ = queue.claim_due(u64::MAX, 32);
        assert!(queue.mark_blocked(
            &task_id,
            "missing provider config",
            crate::tasks::TaskBlockedReason::ConfigMissing
        ));

        let resume_req = Request::builder()
            .method("POST")
            .uri(format!("/control/tasks/{task_id}/resume"))
            .header("authorization", "Bearer test-gateway-token")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"delayMs":1000,"reason":"operator resume"}"#))
            .unwrap();
        let resume_response = router.oneshot(resume_req).await.unwrap();
        assert_eq!(resume_response.status(), StatusCode::OK);
        let resume_body = axum::body::to_bytes(resume_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let resume_json: Value = serde_json::from_slice(&resume_body).unwrap();
        assert_eq!(resume_json["ok"], true);
        assert_eq!(resume_json["task"]["state"], "retry_wait");
        assert_eq!(resume_json["task"]["lastError"], "operator resume");
        assert!(resume_json["task"]["blockedReason"].is_null());
    }

    #[tokio::test]
    async fn test_control_tasks_patch_updates_payload_and_policy() {
        let (ws_state, _tmp) = make_test_ws_state();
        let router = test_router_with_hook_registry(
            test_config(),
            Arc::new(HookRegistry::new()),
            ws_state.clone(),
        );

        let create_req = Request::builder()
            .method("POST")
            .uri("/control/tasks")
            .header("authorization", "Bearer test-gateway-token")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"payload":{"kind":"systemEvent","text":"task patch old"}}"#,
            ))
            .unwrap();
        let create_response = router.clone().oneshot(create_req).await.unwrap();
        assert_eq!(create_response.status(), StatusCode::CREATED);
        let create_body = axum::body::to_bytes(create_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let create_json: Value = serde_json::from_slice(&create_body).unwrap();
        let task_id = create_json["task"]["id"]
            .as_str()
            .expect("task id should be present")
            .to_string();

        let patch_req = Request::builder()
            .method("PATCH")
            .uri(format!("/control/tasks/{task_id}"))
            .header("authorization", "Bearer test-gateway-token")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"payload":{"kind":"systemEvent","text":"task patch new"},"policy":{"maxRunTimeoutSeconds":42},"reason":"operator patch"}"#,
            ))
            .unwrap();
        let patch_response = router.oneshot(patch_req).await.unwrap();
        assert_eq!(patch_response.status(), StatusCode::OK);
        let patch_body = axum::body::to_bytes(patch_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let patch_json: Value = serde_json::from_slice(&patch_body).unwrap();
        assert_eq!(patch_json["ok"], true);
        assert_eq!(patch_json["task"]["payload"]["text"], "task patch new");
        assert_eq!(patch_json["task"]["policy"]["maxRunTimeoutSeconds"], 42);
        assert_eq!(
            patch_json["task"]["policy"]["maxAttempts"],
            crate::tasks::DEFAULT_TASK_MAX_ATTEMPTS
        );
        assert_eq!(patch_json["task"]["lastError"], "operator patch");
    }

    #[tokio::test]
    async fn test_control_tasks_patch_empty_body_rejected() {
        let (ws_state, _tmp) = make_test_ws_state();
        let router = test_router_with_hook_registry(
            test_config(),
            Arc::new(HookRegistry::new()),
            ws_state.clone(),
        );

        let create_req = Request::builder()
            .method("POST")
            .uri("/control/tasks")
            .header("authorization", "Bearer test-gateway-token")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"payload":{"kind":"systemEvent","text":"task patch empty body"}}"#,
            ))
            .unwrap();
        let create_response = router.clone().oneshot(create_req).await.unwrap();
        assert_eq!(create_response.status(), StatusCode::CREATED);
        let create_body = axum::body::to_bytes(create_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let create_json: Value = serde_json::from_slice(&create_body).unwrap();
        let task_id = create_json["task"]["id"]
            .as_str()
            .expect("task id should be present")
            .to_string();

        let patch_req = Request::builder()
            .method("PATCH")
            .uri(format!("/control/tasks/{task_id}"))
            .header("authorization", "Bearer test-gateway-token")
            .header("content-type", "application/json")
            .body(Body::from(r#"{}"#))
            .unwrap();
        let patch_response = router.oneshot(patch_req).await.unwrap();
        assert_eq!(patch_response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_control_tasks_patch_running_conflict() {
        let (ws_state, _tmp) = make_test_ws_state();
        let router = test_router_with_hook_registry(
            test_config(),
            Arc::new(HookRegistry::new()),
            ws_state.clone(),
        );

        let create_req = Request::builder()
            .method("POST")
            .uri("/control/tasks")
            .header("authorization", "Bearer test-gateway-token")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"payload":{"kind":"systemEvent","text":"task patch running"}}"#,
            ))
            .unwrap();
        let create_response = router.clone().oneshot(create_req).await.unwrap();
        assert_eq!(create_response.status(), StatusCode::CREATED);
        let create_body = axum::body::to_bytes(create_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let create_json: Value = serde_json::from_slice(&create_body).unwrap();
        let task_id = create_json["task"]["id"]
            .as_str()
            .expect("task id should be present")
            .to_string();

        let queue = ws_state.task_queue();
        let _ = queue.claim_due(u64::MAX, 32);

        let patch_req = Request::builder()
            .method("PATCH")
            .uri(format!("/control/tasks/{task_id}"))
            .header("authorization", "Bearer test-gateway-token")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"reason":"operator patch"}"#))
            .unwrap();
        let patch_response = router.oneshot(patch_req).await.unwrap();
        assert_eq!(patch_response.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn test_control_tasks_patch_not_found_returns_404() {
        let (ws_state, _tmp) = make_test_ws_state();
        let router = test_router_with_hook_registry(
            test_config(),
            Arc::new(HookRegistry::new()),
            ws_state.clone(),
        );

        let patch_req = Request::builder()
            .method("PATCH")
            .uri("/control/tasks/task-does-not-exist")
            .header("authorization", "Bearer test-gateway-token")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"reason":"operator patch"}"#))
            .unwrap();
        let patch_response = router.oneshot(patch_req).await.unwrap();
        assert_eq!(patch_response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_control_tasks_resume_non_blocked_conflict() {
        let (ws_state, _tmp) = make_test_ws_state();
        let router = test_router_with_hook_registry(
            test_config(),
            Arc::new(HookRegistry::new()),
            ws_state.clone(),
        );

        let create_req = Request::builder()
            .method("POST")
            .uri("/control/tasks")
            .header("authorization", "Bearer test-gateway-token")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"payload":{"kind":"systemEvent","text":"task resume not blocked"}}"#,
            ))
            .unwrap();
        let create_response = router.clone().oneshot(create_req).await.unwrap();
        assert_eq!(create_response.status(), StatusCode::CREATED);
        let create_body = axum::body::to_bytes(create_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let create_json: Value = serde_json::from_slice(&create_body).unwrap();
        let task_id = create_json["task"]["id"]
            .as_str()
            .expect("task id should be present")
            .to_string();

        let resume_req = Request::builder()
            .method("POST")
            .uri(format!("/control/tasks/{task_id}/resume"))
            .header("authorization", "Bearer test-gateway-token")
            .header("content-type", "application/json")
            .body(Body::from(r#"{}"#))
            .unwrap();
        let resume_response = router.oneshot(resume_req).await.unwrap();
        assert_eq!(resume_response.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn test_control_tasks_resume_not_found_returns_404() {
        let (ws_state, _tmp) = make_test_ws_state();
        let router = test_router_with_hook_registry(
            test_config(),
            Arc::new(HookRegistry::new()),
            ws_state.clone(),
        );

        let resume_req = Request::builder()
            .method("POST")
            .uri("/control/tasks/task-does-not-exist/resume")
            .header("authorization", "Bearer test-gateway-token")
            .header("content-type", "application/json")
            .body(Body::from(r#"{}"#))
            .unwrap();
        let resume_response = router.oneshot(resume_req).await.unwrap();
        assert_eq!(resume_response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_control_tasks_cancel_done_conflict() {
        let (ws_state, _tmp) = make_test_ws_state();
        let router = test_router_with_hook_registry(
            test_config(),
            Arc::new(HookRegistry::new()),
            ws_state.clone(),
        );

        let create_req = Request::builder()
            .method("POST")
            .uri("/control/tasks")
            .header("authorization", "Bearer test-gateway-token")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"payload":{"kind":"systemEvent","text":"task done conflict"}}"#,
            ))
            .unwrap();
        let create_response = router.clone().oneshot(create_req).await.unwrap();
        assert_eq!(create_response.status(), StatusCode::CREATED);
        let create_body = axum::body::to_bytes(create_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let create_json: Value = serde_json::from_slice(&create_body).unwrap();
        let task_id = create_json["task"]["id"]
            .as_str()
            .expect("task id should be present")
            .to_string();

        let queue = ws_state.task_queue();
        let _ = queue.claim_due(u64::MAX, 32);
        assert!(queue.mark_done(&task_id, Some("run-test")));

        let cancel_req = Request::builder()
            .method("POST")
            .uri(format!("/control/tasks/{task_id}/cancel"))
            .header("authorization", "Bearer test-gateway-token")
            .header("content-type", "application/json")
            .body(Body::empty())
            .unwrap();
        let cancel_response = router.oneshot(cancel_req).await.unwrap();
        assert_eq!(cancel_response.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn test_control_tasks_retry_done_conflict() {
        let (ws_state, _tmp) = make_test_ws_state();
        let router = test_router_with_hook_registry(
            test_config(),
            Arc::new(HookRegistry::new()),
            ws_state.clone(),
        );

        let create_req = Request::builder()
            .method("POST")
            .uri("/control/tasks")
            .header("authorization", "Bearer test-gateway-token")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"payload":{"kind":"systemEvent","text":"task retry conflict"}}"#,
            ))
            .unwrap();
        let create_response = router.clone().oneshot(create_req).await.unwrap();
        assert_eq!(create_response.status(), StatusCode::CREATED);
        let create_body = axum::body::to_bytes(create_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let create_json: Value = serde_json::from_slice(&create_body).unwrap();
        let task_id = create_json["task"]["id"]
            .as_str()
            .expect("task id should be present")
            .to_string();

        let queue = ws_state.task_queue();
        let _ = queue.claim_due(u64::MAX, 32);
        assert!(queue.mark_done(&task_id, Some("run-test")));

        let retry_req = Request::builder()
            .method("POST")
            .uri(format!("/control/tasks/{task_id}/retry"))
            .header("authorization", "Bearer test-gateway-token")
            .header("content-type", "application/json")
            .body(Body::empty())
            .unwrap();
        let retry_response = router.oneshot(retry_req).await.unwrap();
        assert_eq!(retry_response.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn test_control_tasks_retry_queued_conflict() {
        let (ws_state, _tmp) = make_test_ws_state();
        let router = test_router_with_hook_registry(
            test_config(),
            Arc::new(HookRegistry::new()),
            ws_state.clone(),
        );

        let create_req = Request::builder()
            .method("POST")
            .uri("/control/tasks")
            .header("authorization", "Bearer test-gateway-token")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"payload":{"kind":"systemEvent","text":"task queued retry conflict"}}"#,
            ))
            .unwrap();
        let create_response = router.clone().oneshot(create_req).await.unwrap();
        assert_eq!(create_response.status(), StatusCode::CREATED);
        let create_body = axum::body::to_bytes(create_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let create_json: Value = serde_json::from_slice(&create_body).unwrap();
        let task_id = create_json["task"]["id"]
            .as_str()
            .expect("task id should be present")
            .to_string();

        let retry_req = Request::builder()
            .method("POST")
            .uri(format!("/control/tasks/{task_id}/retry"))
            .header("authorization", "Bearer test-gateway-token")
            .header("content-type", "application/json")
            .body(Body::empty())
            .unwrap();
        let retry_response = router.oneshot(retry_req).await.unwrap();
        assert_eq!(retry_response.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn test_control_tasks_rejects_overlong_reason() {
        let (ws_state, _tmp) = make_test_ws_state();
        let router = test_router_with_hook_registry(
            test_config(),
            Arc::new(HookRegistry::new()),
            ws_state.clone(),
        );

        let create_req = Request::builder()
            .method("POST")
            .uri("/control/tasks")
            .header("authorization", "Bearer test-gateway-token")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"payload":{"kind":"systemEvent","text":"task long reason"}}"#,
            ))
            .unwrap();
        let create_response = router.clone().oneshot(create_req).await.unwrap();
        assert_eq!(create_response.status(), StatusCode::CREATED);
        let create_body = axum::body::to_bytes(create_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let create_json: Value = serde_json::from_slice(&create_body).unwrap();
        let task_id = create_json["task"]["id"]
            .as_str()
            .expect("task id should be present")
            .to_string();

        let long_reason = "a".repeat(1025);

        let cancel_req = Request::builder()
            .method("POST")
            .uri(format!("/control/tasks/{task_id}/cancel"))
            .header("authorization", "Bearer test-gateway-token")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::json!({ "reason": long_reason })
                    .to_string()
                    .into_bytes(),
            ))
            .unwrap();
        let cancel_response = router.clone().oneshot(cancel_req).await.unwrap();
        assert_eq!(cancel_response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_control_tasks_retry_accepts_whitespace_body() {
        let (ws_state, _tmp) = make_test_ws_state();
        let router = test_router_with_hook_registry(
            test_config(),
            Arc::new(HookRegistry::new()),
            ws_state.clone(),
        );

        let create_req = Request::builder()
            .method("POST")
            .uri("/control/tasks")
            .header("authorization", "Bearer test-gateway-token")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"payload":{"kind":"systemEvent","text":"task retry whitespace"}}"#,
            ))
            .unwrap();
        let create_response = router.clone().oneshot(create_req).await.unwrap();
        assert_eq!(create_response.status(), StatusCode::CREATED);
        let create_body = axum::body::to_bytes(create_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let create_json: Value = serde_json::from_slice(&create_body).unwrap();
        let task_id = create_json["task"]["id"]
            .as_str()
            .expect("task id should be present")
            .to_string();

        let cancel_req = Request::builder()
            .method("POST")
            .uri(format!("/control/tasks/{task_id}/cancel"))
            .header("authorization", "Bearer test-gateway-token")
            .header("content-type", "application/json")
            .body(Body::empty())
            .unwrap();
        let cancel_response = router.clone().oneshot(cancel_req).await.unwrap();
        assert_eq!(cancel_response.status(), StatusCode::OK);

        let retry_req = Request::builder()
            .method("POST")
            .uri(format!("/control/tasks/{task_id}/retry"))
            .header("authorization", "Bearer test-gateway-token")
            .header("content-type", "application/json")
            .body(Body::from(" \n\t "))
            .unwrap();
        let retry_response = router.oneshot(retry_req).await.unwrap();
        assert_eq!(retry_response.status(), StatusCode::OK);
        let retry_body = axum::body::to_bytes(retry_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let retry_json: Value = serde_json::from_slice(&retry_body).unwrap();
        assert_eq!(retry_json["task"]["state"], "retry_wait");
        assert_eq!(retry_json["task"]["lastError"], "retried by operator");
    }

    #[tokio::test]
    async fn test_control_tasks_queue_unavailable_without_runtime() {
        let router = test_router(test_config());

        let req = Request::builder()
            .method("POST")
            .uri("/control/tasks")
            .header("authorization", "Bearer test-gateway-token")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"payload":{"kind":"systemEvent","text":"task unavailable"}}"#,
            ))
            .unwrap();

        let response = router.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
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
    fn test_normalize_control_ui_base_path() {
        assert_eq!(normalize_control_ui_base_path(""), "");
        assert_eq!(normalize_control_ui_base_path("/"), "");
        assert_eq!(normalize_control_ui_base_path("ui"), "/ui");
        assert_eq!(normalize_control_ui_base_path("/ui/"), "/ui");
        assert_eq!(normalize_control_ui_base_path("/admin/ui"), "/admin/ui");
        assert_eq!(normalize_control_ui_base_path("  /admin  "), "/admin");
    }

    #[test]
    fn test_html_attr_escape() {
        let value = html_attr_escape(r#"</script><b test='x' "y">&"#);
        assert_eq!(
            value,
            "&lt;/script&gt;&lt;b test=&#39;x&#39; &quot;y&quot;&gt;&amp;"
        );
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
