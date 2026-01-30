//! Tool dispatch with exec approval integration.

use serde_json::Value;

use crate::agent::provider::ToolDefinition;
use crate::agent::sandbox::ProcessSandboxConfig;
use crate::plugins::tools::{ToolInvokeContext, ToolInvokeResult, ToolsRegistry};

/// Result of a tool execution.
#[derive(Debug)]
pub enum ToolCallResult {
    /// Tool executed successfully.
    Ok { output: String },
    /// Tool execution failed.
    Error { message: String },
}

/// Execute a tool call via the tools registry.
///
/// When `sandbox_config` is provided and enabled, the `sandboxed` flag is set
/// on the `ToolInvokeContext` so that tool handlers can apply OS-level
/// sandboxing to spawned subprocesses.
pub fn execute_tool_call(
    tool_name: &str,
    tool_input: Value,
    tools_registry: &ToolsRegistry,
    session_key: &str,
    agent_id: Option<&str>,
) -> ToolCallResult {
    execute_tool_call_with_sandbox(
        tool_name,
        tool_input,
        tools_registry,
        session_key,
        agent_id,
        None,
    )
}

/// Execute a tool call with optional sandbox configuration.
///
/// This is the full-featured entry point that accepts an optional
/// `ProcessSandboxConfig`. The `sandboxed` flag on the invoke context
/// reflects whether sandboxing is active.
pub fn execute_tool_call_with_sandbox(
    tool_name: &str,
    tool_input: Value,
    tools_registry: &ToolsRegistry,
    session_key: &str,
    agent_id: Option<&str>,
    sandbox_config: Option<&ProcessSandboxConfig>,
) -> ToolCallResult {
    let sandboxed = sandbox_config.is_some_and(|c| c.enabled);

    if sandboxed {
        tracing::debug!(
            tool = %tool_name,
            max_cpu = sandbox_config.unwrap().max_cpu_seconds,
            max_mem_mb = sandbox_config.unwrap().max_memory_mb,
            max_fds = sandbox_config.unwrap().max_fds,
            "executing tool with process sandbox enabled"
        );
    }

    let ctx = ToolInvokeContext {
        agent_id: agent_id.map(|s| s.to_string()),
        session_key: session_key.to_string(),
        message_channel: None,
        account_id: None,
        sandboxed,
        dry_run: false,
    };

    let result = tools_registry.invoke(tool_name, tool_input, &ctx);

    match result {
        ToolInvokeResult::Success { result, .. } => ToolCallResult::Ok {
            output: serde_json::to_string(&result).unwrap_or_else(|_| "null".to_string()),
        },
        ToolInvokeResult::Error { error, .. } => ToolCallResult::Error {
            message: error.message,
        },
    }
}

/// Convert plugin tool definitions to LLM provider tool definitions.
pub fn list_provider_tools(tools_registry: &ToolsRegistry) -> Vec<ToolDefinition> {
    tools_registry
        .list_tools()
        .into_iter()
        .map(|t| ToolDefinition {
            name: t.name,
            description: t.description,
            input_schema: serde_json::from_str(&t.input_schema).unwrap_or(serde_json::json!({})),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_execute_unknown_tool() {
        let registry = ToolsRegistry::new();
        let result = execute_tool_call("nonexistent_tool", json!({}), &registry, "sess-1", None);
        match result {
            ToolCallResult::Error { message } => {
                assert!(
                    message.contains("nonexistent_tool"),
                    "error should name the tool: {message}"
                );
            }
            ToolCallResult::Ok { .. } => panic!("expected error for unknown tool"),
        }
    }

    #[test]
    fn test_execute_builtin_tool() {
        // The default registry ships with a "time" builtin
        let registry = ToolsRegistry::new();
        let result = execute_tool_call("time", json!({}), &registry, "sess-1", None);
        match result {
            ToolCallResult::Ok { output } => {
                assert!(!output.is_empty(), "time tool should return output");
                assert!(
                    output.contains("timestamp"),
                    "time output should contain timestamp: {output}"
                );
            }
            ToolCallResult::Error { message } => panic!("expected success, got error: {message}"),
        }
    }

    #[test]
    fn test_list_provider_tools_empty() {
        // Create a registry with no tools via allowlist that blocks everything
        let registry = ToolsRegistry::new();
        registry.set_allowlist(vec!["__nonexistent__".to_string()]);
        let tools = list_provider_tools(&registry);
        assert!(tools.is_empty(), "expected no tools, got {}", tools.len());
    }

    #[test]
    fn test_list_provider_tools_with_entries() {
        let registry = ToolsRegistry::new();
        let tools = list_provider_tools(&registry);
        assert!(!tools.is_empty(), "default registry should have tools");
        // Should contain the "time" builtin
        assert!(
            tools.iter().any(|t| t.name == "time"),
            "should include 'time' tool"
        );
    }

    #[test]
    fn test_execute_with_empty_name() {
        let registry = ToolsRegistry::new();
        let result = execute_tool_call("", json!({}), &registry, "sess-1", None);
        match result {
            ToolCallResult::Error { .. } => {} // expected
            ToolCallResult::Ok { .. } => panic!("expected error for empty tool name"),
        }
    }

    #[test]
    fn test_execute_with_valid_json_args() {
        let registry = ToolsRegistry::new();
        // "time" tool ignores its args, but it should still succeed with arbitrary JSON
        let result = execute_tool_call(
            "time",
            json!({"timezone": "America/New_York", "extra": 42}),
            &registry,
            "sess-1",
            Some("agent-1"),
        );
        match result {
            ToolCallResult::Ok { output } => {
                assert!(output.contains("UTC"), "time tool returns UTC: {output}");
            }
            ToolCallResult::Error { message } => panic!("expected success, got error: {message}"),
        }
    }
}
