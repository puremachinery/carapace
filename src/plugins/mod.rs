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

/// Maximum managed plugin artifact size accepted by install/update paths.
pub(crate) const MAX_MANAGED_PLUGIN_ARTIFACT_BYTES: u64 = 50 * 1024 * 1024;

/// Validate a managed plugin name used for `plugins.install` / `plugins.update`.
pub(crate) fn validate_managed_plugin_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("plugin name must not be empty".to_string());
    }
    if name.len() > 128 {
        return Err("plugin name is too long (max 128 characters)".to_string());
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(
            "plugin name may only contain ASCII alphanumeric characters, hyphens, and underscores"
                .to_string(),
        );
    }
    if crate::plugins::loader::is_reserved_plugin_id(name) {
        return Err(format!(
            "plugin name '{}' is reserved for plugin configuration",
            name
        ));
    }
    Ok(())
}

pub mod bindings;
pub mod capabilities;
pub mod dispatch;
pub mod hook_utils;
pub mod host;
pub mod loader;
pub mod permissions;
pub mod runtime;
pub mod sandbox;
pub mod signature;
pub mod tools;

pub mod caps;

#[cfg(test)]
mod tests;

// Re-export commonly used types
pub use bindings::{
    BindingError, ChannelCapabilities, ChannelInfo, ChannelPluginInstance, ChatType,
    DeliveryResult, HookEvent, HookPluginInstance, HookResult, OutboundContext, PluginError,
    PluginRegistry, ReadReceiptContext, ServicePluginInstance, ToolContext, ToolDefinition,
    ToolPluginInstance, ToolResult, TypingContext, WebhookPluginInstance, WebhookRequest,
    WebhookResponse,
};
pub use capabilities::{
    CapabilityError, ConfigEnforcer, CredentialEnforcer, RateLimiterRegistry, SsrfProtection,
    HTTP_RATE_LIMIT_PER_MINUTE, LOG_RATE_LIMIT_PER_MINUTE,
};
pub use dispatch::{
    is_modifiable_hook, DispatchError, HookDispatchResult, HookDispatcher, ToolDispatcher,
    WebhookDispatcher, MODIFIABLE_HOOKS,
};
pub use host::{
    HostError, HttpRequest, HttpResponse, MediaFetchResult, PluginHostContext,
    PluginHostContextBuilder, MAX_HTTP_BODY_SIZE, MAX_LOG_MESSAGE_SIZE, MAX_URL_LENGTH,
};
pub use loader::{LoadedPlugin, LoaderError, PluginKind, PluginLoader, PluginManifest};
pub use permissions::{
    compute_effective_permissions, validate_declared_permissions, DeclaredPermissions,
    EffectivePermissions, PermissionConfig, PermissionEnforcer, PermissionError,
    PermissionOverride,
};
pub use runtime::{
    HostState, PluginInstanceHandle, PluginRuntime, RuntimeError, DEFAULT_EXECUTION_TIMEOUT,
    DEFAULT_FUEL_BUDGET, MAX_PLUGIN_MEMORY_BYTES,
};
pub use tools::{
    create_registry as create_tools_registry, BuiltinTool, ToolInvokeContext, ToolInvokeError,
    ToolInvokeResult, ToolsRegistry,
};
