//! Plugin capability dispatch
//!
//! Wires plugin capabilities (tools, webhooks, hooks, channels) into the gateway's
//! WebSocket and HTTP dispatch systems.
//!
//! # Webhook Routing
//!
//! Plugin webhooks are served under `/plugins/<plugin-id>/<path>` to ensure isolation.
//! This is a breaking change from the Node gateway which allowed arbitrary paths.
//!
//! # Hook Dispatch
//!
//! Hooks are dispatched to all registered hook plugins in registration order.
//! Modifiable hooks (before_agent_start, message_sending, before_tool_call,
//! tool_result_persist) can return modified payloads; other hooks are read-only.
//!
//! # Tool Dispatch
//!
//! Tools are dispatched by name. Plugin tools are namespaced as `<plugin-id>_<tool-name>`
//! to avoid collisions with built-in tools.

use std::collections::HashMap;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::bindings::{
    BindingError, HookEvent, HookPluginInstance, HookResult, PluginRegistry, ToolContext,
    ToolDefinition, ToolPluginInstance, ToolResult, WebhookPluginInstance, WebhookRequest,
    WebhookResponse,
};

/// Dispatch errors
#[derive(Error, Debug)]
pub enum DispatchError {
    #[error("Plugin not found: {0}")]
    PluginNotFound(String),

    #[error("Tool not found: {0}")]
    ToolNotFound(String),

    #[error("Webhook path not found: {0}")]
    WebhookPathNotFound(String),

    #[error("Hook dispatch failed: {0}")]
    HookDispatchFailed(String),

    #[error("Binding error: {0}")]
    BindingError(#[from] BindingError),
}

/// List of hooks that allow payload modification
pub const MODIFIABLE_HOOKS: &[&str] = &[
    "before_agent_start",
    "message_sending",
    "before_tool_call",
    "tool_result_persist",
];

/// Check if a hook allows payload modification
pub fn is_modifiable_hook(hook_name: &str) -> bool {
    MODIFIABLE_HOOKS.contains(&hook_name)
}

/// Tool dispatcher that routes tool invocations to plugins
pub struct ToolDispatcher {
    registry: Arc<PluginRegistry>,
    /// Cache of tool name -> plugin ID mapping
    tool_map: parking_lot::RwLock<HashMap<String, String>>,
}

impl ToolDispatcher {
    /// Create a new tool dispatcher
    pub fn new(registry: Arc<PluginRegistry>) -> Self {
        Self {
            registry,
            tool_map: parking_lot::RwLock::new(HashMap::new()),
        }
    }

    /// Refresh the tool mapping from the registry
    pub fn refresh_tool_map(&self) -> Result<(), DispatchError> {
        let mut map = self.tool_map.write();
        map.clear();

        for (plugin_id, instance) in self.registry.get_tools() {
            let definitions = instance.get_definitions()?;
            for def in definitions {
                // Namespace tool names to avoid collisions
                let namespaced_name = format!("{}_{}", plugin_id, def.name);
                map.insert(namespaced_name, plugin_id.clone());
                // Also store the original name for plugins that want shorter names
                map.insert(def.name.clone(), plugin_id.clone());
            }
        }

        Ok(())
    }

    /// List all available tools from plugins
    pub fn list_tools(&self) -> Result<Vec<ToolDefinition>, DispatchError> {
        let mut tools = Vec::new();

        for (plugin_id, instance) in self.registry.get_tools() {
            let definitions = instance.get_definitions()?;
            for mut def in definitions {
                // Namespace the tool name
                def.name = format!("{}_{}", plugin_id, def.name);
                tools.push(def);
            }
        }

        Ok(tools)
    }

    /// Invoke a tool by name
    pub fn invoke(
        &self,
        tool_name: &str,
        params: &str,
        ctx: ToolContext,
    ) -> Result<ToolResult, DispatchError> {
        // Look up the plugin that provides this tool
        let plugin_id = {
            let map = self.tool_map.read();
            map.get(tool_name).cloned()
        };

        let plugin_id = match plugin_id {
            Some(id) => id,
            None => {
                // Try to find by checking each plugin's definitions
                let mut found_id = None;
                for (id, instance) in self.registry.get_tools() {
                    if let Ok(defs) = instance.get_definitions() {
                        for def in defs {
                            if def.name == tool_name || format!("{}_{}", id, def.name) == tool_name
                            {
                                found_id = Some(id.clone());
                                break;
                            }
                        }
                    }
                    if found_id.is_some() {
                        break;
                    }
                }
                found_id.ok_or_else(|| DispatchError::ToolNotFound(tool_name.to_string()))?
            }
        };

        // Get the plugin instance
        let instance = self
            .registry
            .get_tool(&plugin_id)
            .ok_or_else(|| DispatchError::PluginNotFound(plugin_id.clone()))?;

        // Extract the actual tool name (remove plugin prefix if present)
        let actual_name = tool_name
            .strip_prefix(&format!("{}_", plugin_id))
            .unwrap_or(tool_name);

        // Invoke the tool
        instance
            .invoke(actual_name, params, ctx)
            .map_err(Into::into)
    }
}

/// Webhook dispatcher that routes HTTP requests to plugins
pub struct WebhookDispatcher {
    registry: Arc<PluginRegistry>,
    /// Cache of path -> plugin ID mapping
    path_map: parking_lot::RwLock<HashMap<String, String>>,
}

impl WebhookDispatcher {
    /// Create a new webhook dispatcher
    pub fn new(registry: Arc<PluginRegistry>) -> Self {
        Self {
            registry,
            path_map: parking_lot::RwLock::new(HashMap::new()),
        }
    }

    /// Refresh the path mapping from the registry
    pub fn refresh_path_map(&self) -> Result<(), DispatchError> {
        let mut map = self.path_map.write();
        map.clear();

        for (plugin_id, instance) in self.registry.get_webhooks() {
            let paths = instance.get_paths()?;
            for path in paths {
                // Namespace paths under /plugins/<plugin-id>/
                let full_path = format!("/plugins/{}{}", plugin_id, path);
                map.insert(full_path, plugin_id.clone());
            }
        }

        Ok(())
    }

    /// List all registered webhook paths
    pub fn list_paths(&self) -> Result<Vec<String>, DispatchError> {
        let mut paths = Vec::new();

        for (plugin_id, instance) in self.registry.get_webhooks() {
            let plugin_paths = instance.get_paths()?;
            for path in plugin_paths {
                paths.push(format!("/plugins/{}{}", plugin_id, path));
            }
        }

        Ok(paths)
    }

    /// Handle a webhook request
    ///
    /// The path should be the full path including the `/plugins/<plugin-id>/` prefix.
    pub fn handle(
        &self,
        path: &str,
        request: WebhookRequest,
    ) -> Result<WebhookResponse, DispatchError> {
        // Look up the plugin that handles this path
        let plugin_id = {
            let map = self.path_map.read();

            // Try exact match first
            if let Some(id) = map.get(path) {
                Some(id.clone())
            } else {
                // Try prefix match for paths with parameters
                map.iter()
                    .find(|(p, _)| path.starts_with(p.as_str()))
                    .map(|(_, id)| id.clone())
            }
        };

        let plugin_id = match plugin_id {
            Some(id) => id,
            None => {
                // Try to extract plugin ID from path and check directly
                if let Some(id) = extract_plugin_id_from_path(path) {
                    if self.registry.get_webhook(&id).is_some() {
                        id
                    } else {
                        return Err(DispatchError::WebhookPathNotFound(path.to_string()));
                    }
                } else {
                    return Err(DispatchError::WebhookPathNotFound(path.to_string()));
                }
            }
        };

        // Get the plugin instance
        let instance = self
            .registry
            .get_webhook(&plugin_id)
            .ok_or_else(|| DispatchError::PluginNotFound(plugin_id.clone()))?;

        // Strip the /plugins/<plugin-id> prefix from the path for the plugin
        let plugin_path = strip_plugin_prefix(path, &plugin_id);

        // Create a modified request with the stripped path
        let plugin_request = WebhookRequest {
            path: plugin_path,
            ..request
        };

        // Handle the request
        instance.handle(plugin_request).map_err(Into::into)
    }
}

/// Extract plugin ID from a path like /plugins/<plugin-id>/...
fn extract_plugin_id_from_path(path: &str) -> Option<String> {
    let path = path.strip_prefix("/plugins/")?;
    let end = path.find('/').unwrap_or(path.len());
    Some(path[..end].to_string())
}

/// Strip the /plugins/<plugin-id> prefix from a path
fn strip_plugin_prefix(path: &str, plugin_id: &str) -> String {
    let prefix = format!("/plugins/{}", plugin_id);
    path.strip_prefix(&prefix).unwrap_or(path).to_string()
}

/// Hook dispatcher that routes hook events to plugins
pub struct HookDispatcher {
    registry: Arc<PluginRegistry>,
}

/// Result of dispatching a hook to all handlers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HookDispatchResult {
    /// Whether any handler handled the event
    pub handled: bool,
    /// Whether any handler requested cancellation (only for cancellable hooks)
    pub cancelled: bool,
    /// The final payload after all modifications (only for modifiable hooks)
    pub final_payload: Option<String>,
    /// Number of handlers that processed the event
    pub handler_count: usize,
}

impl HookDispatcher {
    /// Create a new hook dispatcher
    pub fn new(registry: Arc<PluginRegistry>) -> Self {
        Self { registry }
    }

    /// Dispatch a hook event to all registered handlers
    ///
    /// Hooks are called in registration order. For modifiable hooks, each handler
    /// receives the payload as modified by the previous handler.
    pub fn dispatch(
        &self,
        hook_name: &str,
        payload: &str,
    ) -> Result<HookDispatchResult, DispatchError> {
        let is_modifiable = is_modifiable_hook(hook_name);
        let mut current_payload = payload.to_string();
        let mut handled = false;
        let mut cancelled = false;
        let mut handler_count = 0;

        // Get all hook plugins
        let hooks = self.registry.get_hooks();

        for (plugin_id, instance) in hooks {
            // Check if this plugin handles this hook
            let registered_hooks = match instance.get_hooks() {
                Ok(hooks) => hooks,
                Err(e) => {
                    tracing::warn!(
                        plugin_id = %plugin_id,
                        error = %e,
                        "Failed to get hooks from plugin"
                    );
                    continue;
                }
            };

            if !registered_hooks.contains(&hook_name.to_string()) {
                continue;
            }

            // Create the event
            let event = HookEvent {
                hook_name: hook_name.to_string(),
                payload: current_payload.clone(),
            };

            // Call the handler
            let result = match instance.handle(event) {
                Ok(result) => result,
                Err(e) => {
                    tracing::warn!(
                        plugin_id = %plugin_id,
                        hook = %hook_name,
                        error = %e,
                        "Hook handler failed"
                    );
                    continue;
                }
            };

            handler_count += 1;

            if result.handled {
                handled = true;
            }

            if result.cancel {
                cancelled = true;
            }

            // Update payload if modified (only for modifiable hooks)
            if is_modifiable {
                if let Some(modified) = result.modified_payload {
                    current_payload = modified;
                }
            }
        }

        Ok(HookDispatchResult {
            handled,
            cancelled,
            final_payload: if is_modifiable {
                Some(current_payload)
            } else {
                None
            },
            handler_count,
        })
    }

    /// List all registered hooks across all plugins
    pub fn list_hooks(&self) -> Result<Vec<(String, Vec<String>)>, DispatchError> {
        let mut result = Vec::new();

        for (plugin_id, instance) in self.registry.get_hooks() {
            let hooks = instance.get_hooks()?;
            result.push((plugin_id, hooks));
        }

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_modifiable_hooks() {
        assert!(is_modifiable_hook("before_agent_start"));
        assert!(is_modifiable_hook("message_sending"));
        assert!(is_modifiable_hook("before_tool_call"));
        assert!(is_modifiable_hook("tool_result_persist"));

        assert!(!is_modifiable_hook("agent_end"));
        assert!(!is_modifiable_hook("session_start"));
        assert!(!is_modifiable_hook("gateway_start"));
    }

    #[test]
    fn test_extract_plugin_id_from_path() {
        assert_eq!(
            extract_plugin_id_from_path("/plugins/msteams/webhook"),
            Some("msteams".to_string())
        );
        assert_eq!(
            extract_plugin_id_from_path("/plugins/my-plugin/callback/123"),
            Some("my-plugin".to_string())
        );
        assert_eq!(extract_plugin_id_from_path("/other/path"), None);
        assert_eq!(
            extract_plugin_id_from_path("/plugins/"),
            Some("".to_string())
        );
    }

    #[test]
    fn test_strip_plugin_prefix() {
        assert_eq!(
            strip_plugin_prefix("/plugins/msteams/webhook", "msteams"),
            "/webhook"
        );
        assert_eq!(
            strip_plugin_prefix("/plugins/my-plugin/callback/123", "my-plugin"),
            "/callback/123"
        );
        assert_eq!(strip_plugin_prefix("/other/path", "msteams"), "/other/path");
    }

    #[test]
    fn test_hook_dispatch_result() {
        let result = HookDispatchResult {
            handled: true,
            cancelled: false,
            final_payload: Some(r#"{"modified": true}"#.to_string()),
            handler_count: 2,
        };
        assert!(result.handled);
        assert!(!result.cancelled);
        assert_eq!(result.handler_count, 2);
    }

    #[test]
    fn test_tool_dispatcher_creation() {
        let registry = Arc::new(PluginRegistry::new());
        let dispatcher = ToolDispatcher::new(registry);
        let tools = dispatcher.list_tools().unwrap();
        assert!(tools.is_empty());
    }

    #[test]
    fn test_webhook_dispatcher_creation() {
        let registry = Arc::new(PluginRegistry::new());
        let dispatcher = WebhookDispatcher::new(registry);
        let paths = dispatcher.list_paths().unwrap();
        assert!(paths.is_empty());
    }

    #[test]
    fn test_hook_dispatcher_creation() {
        let registry = Arc::new(PluginRegistry::new());
        let dispatcher = HookDispatcher::new(registry);
        let hooks = dispatcher.list_hooks().unwrap();
        assert!(hooks.is_empty());
    }
}
