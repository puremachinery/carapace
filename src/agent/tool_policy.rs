//! Agent-level tool allowlists and denylists.
//!
//! Each agent can be configured with a [`ToolPolicy`] that controls which tools
//! it is allowed to invoke. The policy is checked at two enforcement points:
//!
//! 1. **Definition filtering** — before sending tool definitions to the LLM,
//!    so the model only sees tools it is allowed to use.
//! 2. **Dispatch gating** — before executing a tool call, as a defence-in-depth
//!    measure in case the model hallucinates a tool name not in its definitions.
//!
//! # Config format
//!
//! ```json5
//! {
//!   agents: {
//!     defaults: {
//!       tools: {
//!         policy: "allow-all",  // "allow-all" | "allow-list" | "deny-list"
//!         list: []              // tool names for allow-list / deny-list
//!       }
//!     },
//!     list: [
//!       {
//!         id: "my-agent",
//!         tools: { policy: "allow-list", list: ["time", "search"] }
//!       }
//!     ]
//!   }
//! }
//! ```

use std::collections::HashSet;

use serde_json::Value;

use crate::agent::provider::ToolDefinition;

/// Policy governing which tools an agent may invoke.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum ToolPolicy {
    /// All tools are available (current default behaviour).
    #[default]
    AllowAll,

    /// Only the listed tools are available; everything else is denied.
    AllowList(HashSet<String>),

    /// All tools are available *except* the listed ones.
    DenyList(HashSet<String>),
}

impl ToolPolicy {
    /// Returns `true` if `tool_name` is permitted by this policy.
    pub fn is_allowed(&self, tool_name: &str) -> bool {
        match self {
            ToolPolicy::AllowAll => true,
            ToolPolicy::AllowList(set) => set.contains(tool_name),
            ToolPolicy::DenyList(set) => !set.contains(tool_name),
        }
    }

    /// Filter a list of tool definitions, keeping only those permitted by the
    /// policy. This is used to build the set of tools exposed to the LLM.
    pub fn filter_tools(&self, tools: Vec<ToolDefinition>) -> Vec<ToolDefinition> {
        match self {
            ToolPolicy::AllowAll => tools,
            _ => tools
                .into_iter()
                .filter(|t| self.is_allowed(&t.name))
                .collect(),
        }
    }

    /// Filter a list of tool definitions, optionally excluding
    /// exfiltration-sensitive tools when the guard is enabled.
    ///
    /// This combines the standard policy filter with the exfiltration guard
    /// so the LLM never even sees blocked tools (defence-in-depth).
    pub fn filter_tools_with_guard(
        &self,
        tools: Vec<ToolDefinition>,
        exfiltration_guard: bool,
    ) -> Vec<ToolDefinition> {
        let filtered = self.filter_tools(tools);
        if exfiltration_guard {
            filtered
                .into_iter()
                .filter(|t| !crate::agent::exfiltration::is_exfiltration_sensitive(&t.name))
                .collect()
        } else {
            filtered
        }
    }

    /// Parse a `ToolPolicy` from a JSON config value.
    ///
    /// Expects an object shaped like:
    /// ```json
    /// { "policy": "allow-list", "list": ["time", "search"] }
    /// ```
    ///
    /// Returns `ToolPolicy::AllowAll` for `None`, missing keys, or
    /// `"allow-all"`.
    ///
    /// Unknown policy values fail closed as `AllowList(empty)` (deny all tools).
    pub fn from_config(value: Option<&Value>) -> Self {
        let obj = match value.and_then(|v| v.as_object()) {
            Some(o) => o,
            None => return ToolPolicy::AllowAll,
        };

        let policy_str = obj
            .get("policy")
            .and_then(|v| v.as_str())
            .unwrap_or("allow-all");

        let list: HashSet<String> = obj
            .get("list")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();

        match policy_str {
            "allow-list" => ToolPolicy::AllowList(list),
            "deny-list" => ToolPolicy::DenyList(list),
            "allow-all" => ToolPolicy::AllowAll,
            other => {
                tracing::warn!(
                    policy = %other,
                    "unrecognized tool policy value, failing closed (deny all tools)"
                );
                ToolPolicy::AllowList(HashSet::new())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ===== is_allowed =====

    #[test]
    fn test_allow_all_permits_everything() {
        let policy = ToolPolicy::AllowAll;
        assert!(policy.is_allowed("time"));
        assert!(policy.is_allowed("search"));
        assert!(policy.is_allowed("anything"));
    }

    #[test]
    fn test_allow_list_permits_only_listed() {
        let policy =
            ToolPolicy::AllowList(["time", "search"].iter().map(|s| s.to_string()).collect());
        assert!(policy.is_allowed("time"));
        assert!(policy.is_allowed("search"));
        assert!(!policy.is_allowed("exec"));
        assert!(!policy.is_allowed("delete"));
    }

    #[test]
    fn test_allow_list_empty_denies_all() {
        let policy = ToolPolicy::AllowList(HashSet::new());
        assert!(!policy.is_allowed("time"));
        assert!(!policy.is_allowed("anything"));
    }

    #[test]
    fn test_deny_list_blocks_only_listed() {
        let policy =
            ToolPolicy::DenyList(["exec", "delete"].iter().map(|s| s.to_string()).collect());
        assert!(policy.is_allowed("time"));
        assert!(policy.is_allowed("search"));
        assert!(!policy.is_allowed("exec"));
        assert!(!policy.is_allowed("delete"));
    }

    #[test]
    fn test_deny_list_empty_permits_all() {
        let policy = ToolPolicy::DenyList(HashSet::new());
        assert!(policy.is_allowed("time"));
        assert!(policy.is_allowed("anything"));
    }

    // ===== filter_tools =====

    fn make_tool(name: &str) -> ToolDefinition {
        ToolDefinition {
            name: name.to_string(),
            description: format!("{name} tool"),
            input_schema: json!({}),
        }
    }

    #[test]
    fn test_filter_tools_allow_all() {
        let policy = ToolPolicy::AllowAll;
        let tools = vec![make_tool("time"), make_tool("search"), make_tool("exec")];
        let filtered = policy.filter_tools(tools);
        assert_eq!(filtered.len(), 3);
    }

    #[test]
    fn test_filter_tools_allow_list() {
        let policy =
            ToolPolicy::AllowList(["time", "search"].iter().map(|s| s.to_string()).collect());
        let tools = vec![make_tool("time"), make_tool("search"), make_tool("exec")];
        let filtered = policy.filter_tools(tools);
        assert_eq!(filtered.len(), 2);
        let names: Vec<&str> = filtered.iter().map(|t| t.name.as_str()).collect();
        assert!(names.contains(&"time"));
        assert!(names.contains(&"search"));
        assert!(!names.contains(&"exec"));
    }

    #[test]
    fn test_filter_tools_deny_list() {
        let policy = ToolPolicy::DenyList(["exec"].iter().map(|s| s.to_string()).collect());
        let tools = vec![make_tool("time"), make_tool("search"), make_tool("exec")];
        let filtered = policy.filter_tools(tools);
        assert_eq!(filtered.len(), 2);
        let names: Vec<&str> = filtered.iter().map(|t| t.name.as_str()).collect();
        assert!(names.contains(&"time"));
        assert!(names.contains(&"search"));
        assert!(!names.contains(&"exec"));
    }

    #[test]
    fn test_filter_tools_empty_input() {
        let policy = ToolPolicy::AllowList(["time"].iter().map(|s| s.to_string()).collect());
        let filtered = policy.filter_tools(vec![]);
        assert!(filtered.is_empty());
    }

    // ===== from_config =====

    #[test]
    fn test_from_config_none() {
        let policy = ToolPolicy::from_config(None);
        assert_eq!(policy, ToolPolicy::AllowAll);
    }

    #[test]
    fn test_from_config_null_value() {
        let val = json!(null);
        let policy = ToolPolicy::from_config(Some(&val));
        assert_eq!(policy, ToolPolicy::AllowAll);
    }

    #[test]
    fn test_from_config_empty_object() {
        let val = json!({});
        let policy = ToolPolicy::from_config(Some(&val));
        assert_eq!(policy, ToolPolicy::AllowAll);
    }

    #[test]
    fn test_from_config_allow_all_explicit() {
        let val = json!({ "policy": "allow-all" });
        let policy = ToolPolicy::from_config(Some(&val));
        assert_eq!(policy, ToolPolicy::AllowAll);
    }

    #[test]
    fn test_from_config_allow_list() {
        let val = json!({
            "policy": "allow-list",
            "list": ["time", "search"]
        });
        let policy = ToolPolicy::from_config(Some(&val));
        let expected: HashSet<String> = ["time", "search"].iter().map(|s| s.to_string()).collect();
        assert_eq!(policy, ToolPolicy::AllowList(expected));
    }

    #[test]
    fn test_from_config_deny_list() {
        let val = json!({
            "policy": "deny-list",
            "list": ["exec", "delete"]
        });
        let policy = ToolPolicy::from_config(Some(&val));
        let expected: HashSet<String> = ["exec", "delete"].iter().map(|s| s.to_string()).collect();
        assert_eq!(policy, ToolPolicy::DenyList(expected));
    }

    #[test]
    fn test_from_config_allow_list_no_list_key() {
        let val = json!({ "policy": "allow-list" });
        let policy = ToolPolicy::from_config(Some(&val));
        assert_eq!(policy, ToolPolicy::AllowList(HashSet::new()));
    }

    #[test]
    fn test_from_config_deny_list_empty_list() {
        let val = json!({
            "policy": "deny-list",
            "list": []
        });
        let policy = ToolPolicy::from_config(Some(&val));
        assert_eq!(policy, ToolPolicy::DenyList(HashSet::new()));
    }

    #[test]
    fn test_from_config_unknown_policy_fails_closed() {
        let val = json!({
            "policy": "unknown-mode",
            "list": ["time"]
        });
        let policy = ToolPolicy::from_config(Some(&val));
        assert_eq!(policy, ToolPolicy::AllowList(HashSet::new()));
        assert!(!policy.is_allowed("time"));
    }

    #[test]
    fn test_from_config_non_string_list_items_ignored() {
        let val = json!({
            "policy": "allow-list",
            "list": ["time", 42, null, "search", true]
        });
        let policy = ToolPolicy::from_config(Some(&val));
        let expected: HashSet<String> = ["time", "search"].iter().map(|s| s.to_string()).collect();
        assert_eq!(policy, ToolPolicy::AllowList(expected));
    }

    // ===== filter_tools_with_guard =====

    #[test]
    fn test_filter_tools_with_guard_disabled_passes_all() {
        let policy = ToolPolicy::AllowAll;
        let tools = vec![
            make_tool("time"),
            make_tool("web_fetch"),
            make_tool("message_send"),
        ];
        let filtered = policy.filter_tools_with_guard(tools, false);
        assert_eq!(filtered.len(), 3);
    }

    #[test]
    fn test_filter_tools_with_guard_enabled_removes_sensitive() {
        let policy = ToolPolicy::AllowAll;
        let tools = vec![
            make_tool("time"),
            make_tool("web_fetch"),
            make_tool("message_send"),
            make_tool("telegram_edit_message"),
            make_tool("search"),
        ];
        let filtered = policy.filter_tools_with_guard(tools, true);
        let names: Vec<&str> = filtered.iter().map(|t| t.name.as_str()).collect();
        assert_eq!(names, vec!["time", "search"]);
    }

    #[test]
    fn test_filter_tools_with_guard_combines_with_policy() {
        // Allow-list only permits "time" and "web_fetch".
        // Exfiltration guard removes "web_fetch".
        // Result: only "time" survives.
        let policy = ToolPolicy::AllowList(
            ["time", "web_fetch"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
        );
        let tools = vec![
            make_tool("time"),
            make_tool("web_fetch"),
            make_tool("search"),
        ];
        let filtered = policy.filter_tools_with_guard(tools, true);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].name, "time");
    }

    #[test]
    fn test_filter_tools_with_guard_enabled_no_sensitive_tools() {
        let policy = ToolPolicy::AllowAll;
        let tools = vec![make_tool("time"), make_tool("search")];
        let filtered = policy.filter_tools_with_guard(tools, true);
        assert_eq!(filtered.len(), 2);
    }

    #[test]
    fn test_filter_tools_with_guard_enabled_empty_input() {
        let policy = ToolPolicy::AllowAll;
        let filtered = policy.filter_tools_with_guard(vec![], true);
        assert!(filtered.is_empty());
    }

    #[test]
    fn test_filter_tools_with_guard_all_channel_tools_removed() {
        let policy = ToolPolicy::AllowAll;
        let tools = vec![
            make_tool("time"),
            make_tool("telegram_edit_message"),
            make_tool("telegram_delete_message"),
            make_tool("telegram_pin_message"),
            make_tool("telegram_reply_markup"),
            make_tool("telegram_send_photo"),
            make_tool("discord_add_reaction"),
            make_tool("discord_send_embed"),
            make_tool("discord_create_thread"),
            make_tool("discord_edit_message"),
            make_tool("discord_delete_message"),
            make_tool("slack_send_blocks"),
            make_tool("slack_send_ephemeral"),
            make_tool("slack_add_reaction"),
            make_tool("slack_update_message"),
            make_tool("slack_delete_message"),
            make_tool("web_fetch"),
            make_tool("message_send"),
        ];
        let filtered = policy.filter_tools_with_guard(tools, true);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].name, "time");
    }

    // ===== Default =====

    #[test]
    fn test_default_is_allow_all() {
        assert_eq!(ToolPolicy::default(), ToolPolicy::AllowAll);
    }
}
