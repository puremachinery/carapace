//! Tools registry for tool dispatch
//!
//! Provides a registry for tools that can be invoked via the /tools/invoke endpoint.
//! Supports both built-in tools and plugin-provided tools.

use parking_lot::RwLock;
use serde::Serialize;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::bindings::{ToolContext, ToolDefinition, ToolPluginInstance};
use super::{DispatchError, PluginRegistry, ToolDispatcher};

/// Tool invocation context
#[derive(Debug, Clone)]
pub struct ToolInvokeContext {
    /// Agent ID (if specified)
    pub agent_id: Option<String>,
    /// Session key
    pub session_key: String,
    /// Message channel (for policy inheritance)
    pub message_channel: Option<String>,
    /// Account ID (for group-based policy)
    pub account_id: Option<String>,
    /// Whether running in sandboxed mode
    pub sandboxed: bool,
    /// Dry run mode (reserved for future use)
    pub dry_run: bool,
}

impl Default for ToolInvokeContext {
    fn default() -> Self {
        Self {
            agent_id: None,
            session_key: "main".to_string(),
            message_channel: None,
            account_id: None,
            sandboxed: false,
            dry_run: false,
        }
    }
}

/// Tool invocation result
#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
pub enum ToolInvokeResult {
    Success { ok: bool, result: Value },
    Error { ok: bool, error: ToolInvokeError },
}

/// Tool invocation error details
#[derive(Debug, Clone, Serialize)]
pub struct ToolInvokeError {
    pub r#type: String,
    pub message: String,
}

impl ToolInvokeResult {
    pub fn success(result: Value) -> Self {
        ToolInvokeResult::Success { ok: true, result }
    }

    pub fn not_found(tool_name: &str) -> Self {
        ToolInvokeResult::Error {
            ok: false,
            error: ToolInvokeError {
                r#type: "not_found".to_string(),
                message: format!("Tool not available: {}", tool_name),
            },
        }
    }

    pub fn tool_error(message: impl Into<String>) -> Self {
        ToolInvokeResult::Error {
            ok: false,
            error: ToolInvokeError {
                r#type: "tool_error".to_string(),
                message: message.into(),
            },
        }
    }
}

/// Built-in tool handler function type
pub type BuiltinToolHandler =
    Box<dyn Fn(Value, &ToolInvokeContext) -> ToolInvokeResult + Send + Sync>;

/// Built-in tool definition
pub struct BuiltinTool {
    pub name: String,
    pub description: String,
    pub input_schema: Value,
    pub handler: BuiltinToolHandler,
}

/// Tools registry
pub struct ToolsRegistry {
    /// Built-in tools
    builtin_tools: RwLock<HashMap<String, BuiltinTool>>,
    /// Plugin tools by plugin ID
    plugin_tools: RwLock<HashMap<String, Arc<dyn ToolPluginInstance>>>,
    /// Shared plugin registry for dispatch (preferred over plugin_tools)
    plugin_registry: RwLock<Option<Arc<PluginRegistry>>>,
    /// Cached plugin tool dispatcher
    plugin_dispatcher: RwLock<Option<Arc<ToolDispatcher>>>,
    /// Last time we refreshed the tool map
    plugin_dispatcher_last_refresh: RwLock<Option<Instant>>,
    /// Tool allowlist (empty = all allowed)
    allowlist: RwLock<Vec<String>>,
}

impl Default for ToolsRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ToolsRegistry {
    /// Create a new tools registry with default built-in tools
    pub fn new() -> Self {
        let registry = Self {
            builtin_tools: RwLock::new(HashMap::new()),
            plugin_tools: RwLock::new(HashMap::new()),
            plugin_registry: RwLock::new(None),
            plugin_dispatcher: RwLock::new(None),
            plugin_dispatcher_last_refresh: RwLock::new(None),
            allowlist: RwLock::new(Vec::new()),
        };

        // Register default built-in tools
        registry.register_builtin_tool(BuiltinTool {
            name: "time".to_string(),
            description: "Get the current time".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {},
                "additionalProperties": false
            }),
            handler: Box::new(|_args, _ctx| {
                let now = chrono::Utc::now();
                ToolInvokeResult::success(serde_json::json!({
                    "timestamp": now.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
                    "timezone": "UTC",
                    "unix": now.timestamp()
                }))
            }),
        });

        // Register core built-in agent tools
        for tool in crate::agent::builtin_tools::builtin_tools() {
            registry.register_builtin_tool(tool);
        }

        registry
    }

    /// Register a built-in tool
    pub fn register_builtin_tool(&self, tool: BuiltinTool) {
        let mut tools = self.builtin_tools.write();
        tools.insert(tool.name.clone(), tool);
    }

    /// Register a plugin tool provider
    pub fn register_plugin(&self, plugin_id: String, instance: Arc<dyn ToolPluginInstance>) {
        let mut plugins = self.plugin_tools.write();
        plugins.insert(plugin_id, instance);
    }

    /// Unregister a plugin
    pub fn unregister_plugin(&self, plugin_id: &str) {
        let mut plugins = self.plugin_tools.write();
        plugins.remove(plugin_id);
    }

    /// Set the tool allowlist
    pub fn set_allowlist(&self, list: Vec<String>) {
        let mut allowlist = self.allowlist.write();
        *allowlist = list;
    }

    /// Set the shared plugin registry for tool dispatch.
    pub fn set_plugin_registry(&self, registry: Arc<PluginRegistry>) {
        let dispatcher = Arc::new(ToolDispatcher::new(registry.clone()));
        {
            let mut guard = self.plugin_registry.write();
            *guard = Some(registry);
        }
        {
            let mut dispatcher_guard = self.plugin_dispatcher.write();
            *dispatcher_guard = Some(dispatcher.clone());
        }
        {
            let mut last_refresh = self.plugin_dispatcher_last_refresh.write();
            *last_refresh = None;
        }
        self.refresh_plugin_dispatcher(&dispatcher);
    }

    fn plugin_dispatcher(&self) -> Option<Arc<ToolDispatcher>> {
        let registry = self.plugin_registry.read().clone()?;
        let dispatcher = self.plugin_dispatcher.read().clone().unwrap_or_else(|| {
            let dispatcher = Arc::new(ToolDispatcher::new(registry));
            let mut guard = self.plugin_dispatcher.write();
            *guard = Some(dispatcher.clone());
            dispatcher
        });
        self.refresh_plugin_dispatcher(&dispatcher);
        Some(dispatcher)
    }

    fn refresh_plugin_dispatcher(&self, dispatcher: &ToolDispatcher) {
        const TOOL_MAP_TTL: Duration = Duration::from_secs(5);

        let should_refresh = {
            let last_refresh = self.plugin_dispatcher_last_refresh.read();
            match *last_refresh {
                Some(ts) => ts.elapsed() >= TOOL_MAP_TTL,
                None => true,
            }
        };

        if !should_refresh {
            return;
        }

        if let Err(err) = dispatcher.refresh_tool_map() {
            tracing::warn!(error = %err, "failed to refresh plugin tool map");
            return;
        }

        let mut last_refresh = self.plugin_dispatcher_last_refresh.write();
        *last_refresh = Some(Instant::now());
    }

    /// Check if a tool is allowed
    fn is_allowed(&self, tool_name: &str) -> bool {
        let allowlist = self.allowlist.read();
        if allowlist.is_empty() {
            return true;
        }
        allowlist
            .iter()
            .any(|name| name.eq_ignore_ascii_case(tool_name))
    }

    /// Get all available tool definitions
    pub fn list_tools(&self) -> Vec<ToolDefinition> {
        let mut definitions = Vec::new();

        // Built-in tools
        {
            let tools = self.builtin_tools.read();
            for tool in tools.values() {
                if self.is_allowed(&tool.name) {
                    definitions.push(ToolDefinition {
                        name: tool.name.clone(),
                        description: tool.description.clone(),
                        input_schema: serde_json::to_string(&tool.input_schema)
                            .unwrap_or_else(|_| "{}".to_string()),
                    });
                }
            }
        }

        // Plugin tools
        if let Some(dispatcher) = self.plugin_dispatcher() {
            match dispatcher.list_tools() {
                Ok(tool_defs) => {
                    for def in tool_defs {
                        if self.is_allowed(&def.name) {
                            definitions.push(def);
                        }
                    }
                }
                Err(err) => {
                    tracing::warn!(error = %err, "plugin tool definitions unavailable");
                }
            }
        } else {
            let plugins = self.plugin_tools.read();
            for (plugin_id, instance) in plugins.iter() {
                match instance.get_definitions() {
                    Ok(tool_defs) => {
                        for def in tool_defs {
                            if self.is_allowed(&def.name) {
                                definitions.push(def);
                            }
                        }
                    }
                    Err(err) => {
                        tracing::warn!(
                            plugin_id = %plugin_id,
                            error = %err,
                            "tool definitions unavailable"
                        );
                    }
                }
            }
        }

        definitions
    }

    /// Get available tool definitions for a specific message channel.
    ///
    /// Channel-specific built-ins are only included when a channel is provided.
    /// Channel tools take precedence over other definitions with the same name.
    pub fn list_tools_for_channel(&self, message_channel: Option<&str>) -> Vec<ToolDefinition> {
        let mut definitions = Vec::new();
        let mut seen: HashSet<String> = HashSet::new();

        if let Some(channel) = message_channel {
            for tool in crate::agent::builtin_tools::channel_specific_tools(Some(channel)) {
                if self.is_allowed(&tool.name) {
                    let key = tool.name.to_lowercase();
                    if seen.insert(key) {
                        definitions.push(ToolDefinition {
                            name: tool.name,
                            description: tool.description,
                            input_schema: serde_json::to_string(&tool.input_schema)
                                .unwrap_or_else(|_| "{}".to_string()),
                        });
                    }
                }
            }
        }

        for def in self.list_tools() {
            let key = def.name.to_lowercase();
            if seen.contains(&key) {
                tracing::warn!(
                    tool = %def.name,
                    "tool definition skipped because channel tool with same name takes precedence"
                );
                continue;
            }
            seen.insert(key);
            definitions.push(def);
        }

        definitions
    }

    /// Invoke a tool by name.
    ///
    /// Channel-specific tools take precedence when a message channel is set.
    pub fn invoke(
        &self,
        tool_name: &str,
        args: Value,
        ctx: &ToolInvokeContext,
    ) -> ToolInvokeResult {
        // Check allowlist
        if !self.is_allowed(tool_name) {
            return ToolInvokeResult::not_found(tool_name);
        }

        // Check channel-specific built-in tools first
        if let Some(channel) = ctx.message_channel.as_deref() {
            for tool in crate::agent::builtin_tools::channel_specific_tools(Some(channel)) {
                if tool.name.eq_ignore_ascii_case(tool_name) {
                    return (tool.handler)(args, ctx);
                }
            }
        }

        // Check built-in tools next
        {
            let tools = self.builtin_tools.read();
            if let Some(tool) = tools.get(tool_name) {
                return (tool.handler)(args, ctx);
            }
            if let Some((_name, tool)) = tools
                .iter()
                .find(|(name, _)| name.eq_ignore_ascii_case(tool_name))
            {
                return (tool.handler)(args, ctx);
            }
        }

        // Check plugin tools
        if let Some(dispatcher) = self.plugin_dispatcher() {
            let tool_ctx = ToolContext {
                agent_id: ctx.agent_id.clone(),
                session_key: Some(ctx.session_key.clone()),
                message_channel: ctx.message_channel.clone(),
                sandboxed: ctx.sandboxed,
            };
            let params = serde_json::to_string(&args).unwrap_or_else(|_| "{}".to_string());
            match dispatcher.invoke(tool_name, &params, tool_ctx) {
                Ok(result) => {
                    if result.success {
                        let result_value = result
                            .result
                            .as_ref()
                            .and_then(|s| serde_json::from_str(s).ok())
                            .unwrap_or(Value::Null);
                        return ToolInvokeResult::success(result_value);
                    }
                    return ToolInvokeResult::tool_error(
                        result.error.unwrap_or_else(|| "Unknown error".to_string()),
                    );
                }
                Err(DispatchError::ToolNotFound(_)) => {}
                Err(e) => {
                    return ToolInvokeResult::tool_error(e.to_string());
                }
            }
        } else {
            let plugins = self.plugin_tools.read();
            for (plugin_id, instance) in plugins.iter() {
                match instance.get_definitions() {
                    Ok(definitions) => {
                        if let Some(def) = definitions
                            .iter()
                            .find(|d| d.name.eq_ignore_ascii_case(tool_name))
                        {
                            let tool_ctx = ToolContext {
                                agent_id: ctx.agent_id.clone(),
                                session_key: Some(ctx.session_key.clone()),
                                message_channel: ctx.message_channel.clone(),
                                sandboxed: ctx.sandboxed,
                            };

                            let params =
                                serde_json::to_string(&args).unwrap_or_else(|_| "{}".to_string());
                            match instance.invoke(&def.name, &params, tool_ctx) {
                                Ok(result) => {
                                    if result.success {
                                        let result_value = result
                                            .result
                                            .as_ref()
                                            .and_then(|s| serde_json::from_str(s).ok())
                                            .unwrap_or(Value::Null);
                                        return ToolInvokeResult::success(result_value);
                                    } else {
                                        return ToolInvokeResult::tool_error(
                                            result
                                                .error
                                                .unwrap_or_else(|| "Unknown error".to_string()),
                                        );
                                    }
                                }
                                Err(e) => {
                                    return ToolInvokeResult::tool_error(e.to_string());
                                }
                            }
                        }
                    }
                    Err(err) => {
                        tracing::warn!(
                            plugin_id = %plugin_id,
                            error = %err,
                            "tool definitions unavailable"
                        );
                    }
                }
            }
        }

        // Tool not found
        ToolInvokeResult::not_found(tool_name)
    }

    /// Check if a tool exists (and is allowed).
    ///
    /// Channel-specific tools are excluded; use `has_tool_for_channel` when
    /// availability depends on a message channel.
    pub fn has_tool(&self, tool_name: &str) -> bool {
        if !self.is_allowed(tool_name) {
            return false;
        }

        // Check built-in tools
        {
            let tools = self.builtin_tools.read();
            if tools.contains_key(tool_name) {
                return true;
            }
            if tools
                .keys()
                .any(|name| name.eq_ignore_ascii_case(tool_name))
            {
                return true;
            }
        }

        // Check plugin tools
        if let Some(dispatcher) = self.plugin_dispatcher() {
            if let Ok(defs) = dispatcher.list_tools() {
                if defs.iter().any(|d| d.name.eq_ignore_ascii_case(tool_name)) {
                    return true;
                }
            }
        } else {
            let plugins = self.plugin_tools.read();
            for (plugin_id, instance) in plugins.iter() {
                match instance.get_definitions() {
                    Ok(definitions) => {
                        if definitions
                            .iter()
                            .any(|d| d.name.eq_ignore_ascii_case(tool_name))
                        {
                            return true;
                        }
                    }
                    Err(err) => {
                        tracing::warn!(
                            plugin_id = %plugin_id,
                            error = %err,
                            "tool definitions unavailable"
                        );
                    }
                }
            }
        }

        false
    }

    /// Check if a tool exists (and is allowed) for a specific message channel.
    pub fn has_tool_for_channel(&self, tool_name: &str, message_channel: Option<&str>) -> bool {
        if !self.is_allowed(tool_name) {
            return false;
        }

        if let Some(channel) = message_channel {
            for tool in crate::agent::builtin_tools::channel_specific_tools(Some(channel)) {
                if tool.name.eq_ignore_ascii_case(tool_name) {
                    return true;
                }
            }
        }

        self.has_tool(tool_name)
    }

    /// Get the count of registered tools
    pub fn len(&self) -> usize {
        let builtin_count = self.builtin_tools.read().len();
        let plugin_count: usize = if let Some(dispatcher) = self.plugin_dispatcher() {
            dispatcher.list_tools().map(|defs| defs.len()).unwrap_or(0)
        } else {
            self.plugin_tools
                .read()
                .values()
                .filter_map(|instance| instance.get_definitions().ok())
                .map(|defs| defs.len())
                .sum()
        };
        builtin_count + plugin_count
    }

    /// Check if registry is empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Create a shared tools registry
pub fn create_registry() -> Arc<ToolsRegistry> {
    Arc::new(ToolsRegistry::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tools_registry_default_tools() {
        let registry = ToolsRegistry::new();
        assert!(registry.has_tool("time"));
    }

    #[test]
    fn test_invoke_time_tool() {
        let registry = ToolsRegistry::new();
        let ctx = ToolInvokeContext::default();

        let result = registry.invoke("time", serde_json::json!({}), &ctx);
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
    fn test_invoke_nonexistent_tool() {
        let registry = ToolsRegistry::new();
        let ctx = ToolInvokeContext::default();

        let result = registry.invoke("nonexistent", serde_json::json!({}), &ctx);
        match result {
            ToolInvokeResult::Error { ok, error } => {
                assert!(!ok);
                assert_eq!(error.r#type, "not_found");
                assert!(error.message.contains("nonexistent"));
            }
            _ => panic!("Expected error result"),
        }
    }

    #[test]
    fn test_register_builtin_tool() {
        let registry = ToolsRegistry::new();

        registry.register_builtin_tool(BuiltinTool {
            name: "echo".to_string(),
            description: "Echo the input".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "message": { "type": "string" }
                }
            }),
            handler: Box::new(|args, _ctx| {
                let message = args
                    .get("message")
                    .and_then(|v| v.as_str())
                    .unwrap_or("(empty)");
                ToolInvokeResult::success(serde_json::json!({ "echo": message }))
            }),
        });

        assert!(registry.has_tool("echo"));

        let ctx = ToolInvokeContext::default();
        let result = registry.invoke("echo", serde_json::json!({ "message": "hello" }), &ctx);
        match result {
            ToolInvokeResult::Success { result, .. } => {
                assert_eq!(result["echo"], "hello");
            }
            _ => panic!("Expected success result"),
        }
    }

    #[test]
    fn test_allowlist() {
        let registry = ToolsRegistry::new();

        // All tools allowed by default
        assert!(registry.has_tool("time"));

        // Set allowlist to empty list (nothing allowed)
        registry.set_allowlist(vec!["other".to_string()]);
        assert!(!registry.has_tool("time"));

        // Add time to allowlist
        registry.set_allowlist(vec!["time".to_string()]);
        assert!(registry.has_tool("time"));
    }

    #[test]
    fn test_list_tools() {
        let registry = ToolsRegistry::new();
        let tools = registry.list_tools();

        assert!(!tools.is_empty());
        assert!(tools.iter().any(|t| t.name == "time"));
    }

    #[test]
    fn test_has_tool_for_channel() {
        let registry = ToolsRegistry::new();
        assert!(!registry.has_tool("telegram_edit_message"));
        assert!(!registry.has_tool_for_channel("telegram_edit_message", None));
        assert!(registry.has_tool_for_channel("telegram_edit_message", Some("telegram")));
    }

    #[test]
    fn test_channel_tool_precedence_over_builtin() {
        let registry = ToolsRegistry::new();

        registry.register_builtin_tool(BuiltinTool {
            name: "telegram_edit_message".to_string(),
            description: "Shadow tool".to_string(),
            input_schema: serde_json::json!({"type": "object", "properties": {}}),
            handler: Box::new(|_args, _ctx| {
                ToolInvokeResult::success(serde_json::json!({ "source": "builtin" }))
            }),
        });

        let tools = registry.list_tools_for_channel(Some("telegram"));
        let matching: Vec<_> = tools
            .iter()
            .filter(|t| t.name == "telegram_edit_message")
            .collect();
        assert_eq!(matching.len(), 1, "expected deduped tool definitions");

        let ctx = ToolInvokeContext {
            message_channel: Some("telegram".to_string()),
            ..ToolInvokeContext::default()
        };
        let result = registry.invoke(
            "telegram_edit_message",
            serde_json::json!({"message_id": "1", "text": "hi"}),
            &ctx,
        );
        match result {
            ToolInvokeResult::Success { result, .. } => {
                assert!(
                    result.get("message_id").is_some(),
                    "expected channel tool result"
                );
                assert!(result.get("source").is_none(), "builtin should not run");
            }
            _ => panic!("Expected success result"),
        }
    }

    #[test]
    fn test_tool_invoke_result_serialization() {
        let success = ToolInvokeResult::success(serde_json::json!({ "data": 42 }));
        let json = serde_json::to_string(&success).unwrap();
        assert!(json.contains("\"ok\":true"));
        assert!(json.contains("\"result\""));

        let error = ToolInvokeResult::not_found("missing");
        let json = serde_json::to_string(&error).unwrap();
        assert!(json.contains("\"ok\":false"));
        assert!(json.contains("\"type\":\"not_found\""));
    }
}
