//! WASM plugin system
//!
//! wasmtime-based plugin host with capability enforcement.
//!
//! This module provides:
//! - Plugin loading from .wasm files
//! - Host function implementations for plugins
//! - Capability enforcement (credential isolation, SSRF protection, rate limiting)
//! - Plugin registry for tracking loaded instances
//!
//! # Security Model
//!
//! Plugins run in sandboxed WASM environments with capability-based access:
//!
//! 1. **Credential Isolation**: All credential keys are automatically prefixed with
//!    the plugin ID. A plugin calling `credential_get("token")` reads
//!    `<plugin-id>:token`. Plugins cannot access other plugins' credentials.
//!
//! 2. **SSRF Protection**: Both `media_fetch` and `http_fetch` block requests to:
//!    - IPv4 private ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
//!    - IPv4 link-local (169.254.0.0/16)
//!    - IPv4/IPv6 localhost (127.0.0.0/8, ::1)
//!    - IPv6 private ranges (fc00::/7, fe80::/10)
//!    - Cloud metadata endpoints (169.254.169.254, fd00:ec2::254)
//!    - Only HTTP/HTTPS protocols are allowed
//!
//! 3. **Config Access**: Plugins can only read keys under `plugins.<plugin-id>.*`.
//!    Gateway-level config (tokens, auth) is not accessible.
//!
//! 4. **Resource Limits**:
//!    - Memory: 64MB per plugin instance
//!    - Execution: 30s timeout per function call
//!    - HTTP requests: 100/minute rate limit per plugin
//!    - Logging: 1000 messages/minute rate limit per plugin
//!    - Body size: 10MB max for HTTP request/response bodies

pub mod bindings;
pub mod capabilities;
pub mod host;
pub mod loader;

pub mod caps;

// Re-export commonly used types
pub use bindings::{
    BindingError, ChannelCapabilities, ChannelInfo, ChannelPluginInstance, ChatType,
    DeliveryResult, HookEvent, HookPluginInstance, HookResult, OutboundContext, PluginError,
    PluginRegistry, ServicePluginInstance, ToolContext, ToolDefinition, ToolPluginInstance,
    ToolResult, WebhookPluginInstance, WebhookRequest, WebhookResponse,
};
pub use capabilities::{
    CapabilityError, ConfigEnforcer, CredentialEnforcer, RateLimiterRegistry, SsrfProtection,
    HTTP_RATE_LIMIT_PER_MINUTE, LOG_RATE_LIMIT_PER_MINUTE,
};
pub use host::{
    HostError, HttpRequest, HttpResponse, MediaFetchResult, PluginHostContext,
    PluginHostContextBuilder, MAX_HTTP_BODY_SIZE, MAX_LOG_MESSAGE_SIZE, MAX_URL_LENGTH,
};
pub use loader::{LoadedPlugin, LoaderError, PluginKind, PluginLoader, PluginManifest};
