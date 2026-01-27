//! WIT bindgen integration
//!
//! Generates and implements bindings from the WIT interface definition
//! in wit/plugin.wit. This module provides the bridge between the host
//! (Rust gateway) and guest (WASM plugins).

use std::sync::Arc;
use parking_lot::Mutex;
use thiserror::Error;

use crate::credentials::CredentialBackend;

use super::host::{
    HostError, HttpRequest, HttpResponse, MediaFetchResult, PluginHostContext,
};

/// Binding errors
#[derive(Error, Debug)]
pub enum BindingError {
    #[error("Plugin not found: {0}")]
    PluginNotFound(String),

    #[error("Plugin kind mismatch: expected {expected}, got {actual}")]
    KindMismatch { expected: String, actual: String },

    #[error("Instantiation error: {0}")]
    InstantiationError(String),

    #[error("Function call error: {0}")]
    CallError(String),

    #[error("Host error: {0}")]
    HostError(#[from] HostError),

    #[error("Wasmtime error: {0}")]
    WasmtimeError(String),
}

/// Plugin error returned from WASM functions
#[derive(Debug, Clone)]
pub struct PluginError {
    pub code: String,
    pub message: String,
    pub retryable: bool,
}

impl std::fmt::Display for PluginError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] {}", self.code, self.message)
    }
}

impl std::error::Error for PluginError {}

/// Message delivery result from channel plugins
#[derive(Debug, Clone)]
pub struct DeliveryResult {
    pub ok: bool,
    pub message_id: Option<String>,
    pub error: Option<String>,
    pub retryable: bool,
}

/// Chat type supported by channels
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChatType {
    Dm,
    Group,
    Channel,
    Thread,
}

/// Channel information
#[derive(Debug, Clone)]
pub struct ChannelInfo {
    pub id: String,
    pub label: String,
    pub selection_label: String,
    pub docs_path: String,
    pub blurb: String,
    pub order: u32,
}

/// Channel capabilities
#[derive(Debug, Clone, Default)]
pub struct ChannelCapabilities {
    pub chat_types: Vec<ChatType>,
    pub polls: bool,
    pub reactions: bool,
    pub edit: bool,
    pub unsend: bool,
    pub reply: bool,
    pub effects: bool,
    pub group_management: bool,
    pub threads: bool,
    pub media: bool,
    pub native_commands: bool,
    pub block_streaming: bool,
}

/// Outbound message context
#[derive(Debug, Clone)]
pub struct OutboundContext {
    pub to: String,
    pub text: String,
    pub media_url: Option<String>,
    pub gif_playback: bool,
    pub reply_to_id: Option<String>,
    pub thread_id: Option<String>,
    pub account_id: Option<String>,
}

/// Tool definition
#[derive(Debug, Clone)]
pub struct ToolDefinition {
    pub name: String,
    pub description: String,
    pub input_schema: String,
}

/// Tool context
#[derive(Debug, Clone)]
pub struct ToolContext {
    pub agent_id: Option<String>,
    pub session_key: Option<String>,
    pub message_channel: Option<String>,
    pub sandboxed: bool,
}

/// Tool result
#[derive(Debug, Clone)]
pub struct ToolResult {
    pub success: bool,
    pub result: Option<String>,
    pub error: Option<String>,
}

/// Webhook request
#[derive(Debug, Clone)]
pub struct WebhookRequest {
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<Vec<u8>>,
    pub query: Option<String>,
}

/// Webhook response
#[derive(Debug, Clone)]
pub struct WebhookResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Option<Vec<u8>>,
}

/// Hook event
#[derive(Debug, Clone)]
pub struct HookEvent {
    pub hook_name: String,
    pub payload: String,
}

/// Hook result
#[derive(Debug, Clone)]
pub struct HookResult {
    pub handled: bool,
    pub cancel: bool,
    pub modified_payload: Option<String>,
}

/// Plugin instance trait for channel plugins
pub trait ChannelPluginInstance: Send + Sync {
    /// Get channel info
    fn get_info(&self) -> Result<ChannelInfo, BindingError>;

    /// Get channel capabilities
    fn get_capabilities(&self) -> Result<ChannelCapabilities, BindingError>;

    /// Send a text message
    fn send_text(&self, ctx: OutboundContext) -> Result<DeliveryResult, BindingError>;

    /// Send a media message
    fn send_media(&self, ctx: OutboundContext) -> Result<DeliveryResult, BindingError>;
}

/// Plugin instance trait for tool plugins
pub trait ToolPluginInstance: Send + Sync {
    /// Get tool definitions
    fn get_definitions(&self) -> Result<Vec<ToolDefinition>, BindingError>;

    /// Invoke a tool
    fn invoke(
        &self,
        name: &str,
        params: &str,
        ctx: ToolContext,
    ) -> Result<ToolResult, BindingError>;
}

/// Plugin instance trait for webhook plugins
pub trait WebhookPluginInstance: Send + Sync {
    /// Get webhook paths
    fn get_paths(&self) -> Result<Vec<String>, BindingError>;

    /// Handle a webhook request
    fn handle(&self, req: WebhookRequest) -> Result<WebhookResponse, BindingError>;
}

/// Plugin instance trait for service plugins
pub trait ServicePluginInstance: Send + Sync {
    /// Start the service
    fn start(&self) -> Result<(), BindingError>;

    /// Stop the service
    fn stop(&self) -> Result<(), BindingError>;

    /// Health check
    fn health(&self) -> Result<bool, BindingError>;
}

/// Plugin instance trait for hook plugins
pub trait HookPluginInstance: Send + Sync {
    /// Get hooks this plugin handles
    fn get_hooks(&self) -> Result<Vec<String>, BindingError>;

    /// Handle a hook event
    fn handle(&self, event: HookEvent) -> Result<HookResult, BindingError>;
}

/// Host implementation for WIT bindings
///
/// This struct implements the host interface that plugins call into.
/// It wraps a PluginHostContext and provides the actual implementations
/// of the host functions defined in wit/plugin.wit.
pub struct WitHost<B: CredentialBackend + 'static> {
    ctx: Arc<PluginHostContext<B>>,
}

impl<B: CredentialBackend + 'static> WitHost<B> {
    pub fn new(ctx: Arc<PluginHostContext<B>>) -> Self {
        Self { ctx }
    }

    // ============== Logging ==============

    pub fn log_debug(&self, message: &str) {
        if let Err(e) = self.ctx.log_debug(message) {
            tracing::trace!(error = %e, "Failed to log debug message from plugin");
        }
    }

    pub fn log_info(&self, message: &str) {
        if let Err(e) = self.ctx.log_info(message) {
            tracing::trace!(error = %e, "Failed to log info message from plugin");
        }
    }

    pub fn log_warn(&self, message: &str) {
        if let Err(e) = self.ctx.log_warn(message) {
            tracing::trace!(error = %e, "Failed to log warn message from plugin");
        }
    }

    pub fn log_error(&self, message: &str) {
        if let Err(e) = self.ctx.log_error(message) {
            tracing::trace!(error = %e, "Failed to log error message from plugin");
        }
    }

    // ============== Config ==============

    pub fn config_get(&self, key: &str) -> Option<String> {
        match self.ctx.config_get(key) {
            Ok(value) => value,
            Err(e) => {
                tracing::debug!(
                    plugin_id = %self.ctx.plugin_id(),
                    key = %key,
                    error = %e,
                    "Config get failed"
                );
                None
            }
        }
    }

    // ============== Credentials ==============

    pub async fn credential_get(&self, key: &str) -> Option<String> {
        match self.ctx.credential_get(key).await {
            Ok(value) => value,
            Err(e) => {
                tracing::debug!(
                    plugin_id = %self.ctx.plugin_id(),
                    key = %key,
                    error = %e,
                    "Credential get failed"
                );
                None
            }
        }
    }

    pub async fn credential_set(&self, key: &str, value: &str) -> bool {
        match self.ctx.credential_set(key, value).await {
            Ok(success) => success,
            Err(e) => {
                tracing::debug!(
                    plugin_id = %self.ctx.plugin_id(),
                    key = %key,
                    error = %e,
                    "Credential set failed"
                );
                false
            }
        }
    }

    // ============== HTTP ==============

    pub async fn http_fetch(&self, req: HttpRequest) -> Result<HttpResponse, String> {
        self.ctx
            .http_fetch(req)
            .await
            .map_err(|e| e.to_string())
    }

    // ============== Media ==============

    pub async fn media_fetch(
        &self,
        url: &str,
        max_bytes: Option<u64>,
        timeout_ms: Option<u32>,
    ) -> MediaFetchResult {
        match self.ctx.media_fetch(url, max_bytes, timeout_ms).await {
            Ok(result) => result,
            Err(e) => MediaFetchResult {
                ok: false,
                local_path: None,
                mime_type: None,
                size: None,
                error: Some(e.to_string()),
            },
        }
    }
}

/// Plugin registry tracks all loaded plugin instances
pub struct PluginRegistry {
    /// Channel plugin instances
    channel_plugins: Mutex<Vec<(String, Arc<dyn ChannelPluginInstance>)>>,
    /// Tool plugin instances
    tool_plugins: Mutex<Vec<(String, Arc<dyn ToolPluginInstance>)>>,
    /// Webhook plugin instances
    webhook_plugins: Mutex<Vec<(String, Arc<dyn WebhookPluginInstance>)>>,
    /// Service plugin instances
    service_plugins: Mutex<Vec<(String, Arc<dyn ServicePluginInstance>)>>,
    /// Hook plugin instances
    hook_plugins: Mutex<Vec<(String, Arc<dyn HookPluginInstance>)>>,
}

impl Default for PluginRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl PluginRegistry {
    pub fn new() -> Self {
        Self {
            channel_plugins: Mutex::new(Vec::new()),
            tool_plugins: Mutex::new(Vec::new()),
            webhook_plugins: Mutex::new(Vec::new()),
            service_plugins: Mutex::new(Vec::new()),
            hook_plugins: Mutex::new(Vec::new()),
        }
    }

    /// Register a channel plugin
    pub fn register_channel(&self, id: String, instance: Arc<dyn ChannelPluginInstance>) {
        let mut plugins = self.channel_plugins.lock();
        plugins.push((id, instance));
    }

    /// Register a tool plugin
    pub fn register_tool(&self, id: String, instance: Arc<dyn ToolPluginInstance>) {
        let mut plugins = self.tool_plugins.lock();
        plugins.push((id, instance));
    }

    /// Register a webhook plugin
    pub fn register_webhook(&self, id: String, instance: Arc<dyn WebhookPluginInstance>) {
        let mut plugins = self.webhook_plugins.lock();
        plugins.push((id, instance));
    }

    /// Register a service plugin
    pub fn register_service(&self, id: String, instance: Arc<dyn ServicePluginInstance>) {
        let mut plugins = self.service_plugins.lock();
        plugins.push((id, instance));
    }

    /// Register a hook plugin
    pub fn register_hook(&self, id: String, instance: Arc<dyn HookPluginInstance>) {
        let mut plugins = self.hook_plugins.lock();
        plugins.push((id, instance));
    }

    /// Get all channel plugins
    pub fn get_channels(&self) -> Vec<(String, Arc<dyn ChannelPluginInstance>)> {
        self.channel_plugins.lock().clone()
    }

    /// Get a channel plugin by ID
    pub fn get_channel(&self, id: &str) -> Option<Arc<dyn ChannelPluginInstance>> {
        let plugins = self.channel_plugins.lock();
        plugins.iter().find(|(pid, _)| pid == id).map(|(_, p)| p.clone())
    }

    /// Get all tool plugins
    pub fn get_tools(&self) -> Vec<(String, Arc<dyn ToolPluginInstance>)> {
        self.tool_plugins.lock().clone()
    }

    /// Get a tool plugin by ID
    pub fn get_tool(&self, id: &str) -> Option<Arc<dyn ToolPluginInstance>> {
        let plugins = self.tool_plugins.lock();
        plugins.iter().find(|(pid, _)| pid == id).map(|(_, p)| p.clone())
    }

    /// Get all webhook plugins
    pub fn get_webhooks(&self) -> Vec<(String, Arc<dyn WebhookPluginInstance>)> {
        self.webhook_plugins.lock().clone()
    }

    /// Get a webhook plugin by ID
    pub fn get_webhook(&self, id: &str) -> Option<Arc<dyn WebhookPluginInstance>> {
        let plugins = self.webhook_plugins.lock();
        plugins.iter().find(|(pid, _)| pid == id).map(|(_, p)| p.clone())
    }

    /// Get all service plugins
    pub fn get_services(&self) -> Vec<(String, Arc<dyn ServicePluginInstance>)> {
        self.service_plugins.lock().clone()
    }

    /// Get all hook plugins
    pub fn get_hooks(&self) -> Vec<(String, Arc<dyn HookPluginInstance>)> {
        self.hook_plugins.lock().clone()
    }

    /// Unregister a plugin by ID
    pub fn unregister(&self, id: &str) {
        {
            let mut plugins = self.channel_plugins.lock();
            plugins.retain(|(pid, _)| pid != id);
        }
        {
            let mut plugins = self.tool_plugins.lock();
            plugins.retain(|(pid, _)| pid != id);
        }
        {
            let mut plugins = self.webhook_plugins.lock();
            plugins.retain(|(pid, _)| pid != id);
        }
        {
            let mut plugins = self.service_plugins.lock();
            plugins.retain(|(pid, _)| pid != id);
        }
        {
            let mut plugins = self.hook_plugins.lock();
            plugins.retain(|(pid, _)| pid != id);
        }
    }

    /// Get count of all registered plugins
    pub fn count(&self) -> usize {
        self.channel_plugins.lock().len()
            + self.tool_plugins.lock().len()
            + self.webhook_plugins.lock().len()
            + self.service_plugins.lock().len()
            + self.hook_plugins.lock().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plugin_error_display() {
        let err = PluginError {
            code: "INVALID_INPUT".to_string(),
            message: "Missing required field".to_string(),
            retryable: false,
        };
        assert_eq!(err.to_string(), "[INVALID_INPUT] Missing required field");
    }

    #[test]
    fn test_delivery_result() {
        let result = DeliveryResult {
            ok: true,
            message_id: Some("msg-123".to_string()),
            error: None,
            retryable: false,
        };
        assert!(result.ok);
        assert_eq!(result.message_id, Some("msg-123".to_string()));
    }

    #[test]
    fn test_plugin_registry() {
        let registry = PluginRegistry::new();
        assert_eq!(registry.count(), 0);
    }

    #[test]
    fn test_chat_type() {
        assert_ne!(ChatType::Dm, ChatType::Group);
        assert_ne!(ChatType::Channel, ChatType::Thread);
    }

    #[test]
    fn test_channel_capabilities_default() {
        let caps = ChannelCapabilities::default();
        assert!(!caps.polls);
        assert!(!caps.reactions);
        assert!(!caps.edit);
    }

    #[test]
    fn test_tool_definition() {
        let def = ToolDefinition {
            name: "search".to_string(),
            description: "Search the web".to_string(),
            input_schema: r#"{"type": "object"}"#.to_string(),
        };
        assert_eq!(def.name, "search");
    }

    #[test]
    fn test_hook_result() {
        let result = HookResult {
            handled: true,
            cancel: false,
            modified_payload: None,
        };
        assert!(result.handled);
        assert!(!result.cancel);
    }
}
