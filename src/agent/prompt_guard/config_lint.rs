//! Agent configuration lint checks.
//!
//! Detects risky patterns in agent configuration such as overly permissive
//! tool policies, missing safety features, and oversized system prompts.

use serde_json::Value;

use crate::config::schema::{SchemaIssue, Severity};

use super::ConfigLintConfig;

/// Lint agent configurations for risky patterns.
///
/// Called during schema validation to produce warnings for potentially
/// unsafe agent configurations.
pub fn lint_agent_configs(agents: &Value, config: &ConfigLintConfig) -> Vec<SchemaIssue> {
    let mut issues = Vec::new();

    if !config.enabled {
        return issues;
    }

    let list = match agents.get("list").and_then(|v| v.as_array()) {
        Some(l) => l,
        None => return issues,
    };

    for (i, agent) in list.iter().enumerate() {
        let agent_obj = match agent.as_object() {
            Some(o) => o,
            None => continue,
        };

        let path_prefix = format!(".agents.list[{}]", i);

        // Warn: toolPolicy AllowAll without exfiltrationGuard
        if let Some(policy) = agent_obj.get("toolPolicy").and_then(|v| v.as_str()) {
            if policy == "AllowAll" || policy == "allowAll" || policy == "allow_all" {
                let has_guard = agent_obj
                    .get("exfiltrationGuard")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);

                if !has_guard {
                    issues.push(SchemaIssue {
                        severity: Severity::Warning,
                        path: format!("{}.toolPolicy", path_prefix),
                        message: "toolPolicy is AllowAll without exfiltrationGuard enabled; \
                                  consider enabling exfiltrationGuard for defense-in-depth"
                            .to_string(),
                    });
                }
            }
        }

        // Warn: missing maxTokens
        if !agent_obj.contains_key("maxTokens") {
            issues.push(SchemaIssue {
                severity: Severity::Warning,
                path: format!("{}.maxTokens", path_prefix),
                message: "no maxTokens configured — the agent will use the default (8192); \
                          consider setting an explicit limit"
                    .to_string(),
            });
        }

        // Warn: system prompt > 10K chars
        if let Some(system) = agent_obj.get("system").and_then(|v| v.as_str()) {
            if system.len() > 10_000 {
                issues.push(SchemaIssue {
                    severity: Severity::Warning,
                    path: format!("{}.system", path_prefix),
                    message: format!(
                        "system prompt is {} chars (> 10K) — large prompts increase \
                         injection surface and token cost",
                        system.len()
                    ),
                });
            }
        }

        // Warn: missing model specification
        if !agent_obj.contains_key("model") {
            issues.push(SchemaIssue {
                severity: Severity::Warning,
                path: format!("{}.model", path_prefix),
                message: "no model specified — the agent will use the default model; \
                          consider specifying an explicit model for reproducibility"
                    .to_string(),
            });
        }
    }

    issues
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn default_config() -> ConfigLintConfig {
        ConfigLintConfig { enabled: true }
    }

    fn disabled_config() -> ConfigLintConfig {
        ConfigLintConfig { enabled: false }
    }

    // ==================== Clean Config ====================

    #[test]
    fn test_well_configured_agent_no_issues() {
        let agents = json!({
            "list": [{
                "model": "claude-sonnet-4-20250514",
                "maxTokens": 4096,
                "toolPolicy": "DenyList",
                "exfiltrationGuard": true,
                "system": "You are a helpful assistant."
            }]
        });
        let issues = lint_agent_configs(&agents, &default_config());
        assert!(issues.is_empty(), "expected no issues, got: {:?}", issues);
    }

    // ==================== AllowAll Without Guard ====================

    #[test]
    fn test_allow_all_without_guard_warns() {
        let agents = json!({
            "list": [{
                "model": "claude-sonnet-4-20250514",
                "maxTokens": 4096,
                "toolPolicy": "AllowAll"
            }]
        });
        let issues = lint_agent_configs(&agents, &default_config());
        assert!(issues.iter().any(|i| i.path.contains("toolPolicy")));
    }

    #[test]
    fn test_allow_all_with_guard_no_warning() {
        let agents = json!({
            "list": [{
                "model": "claude-sonnet-4-20250514",
                "maxTokens": 4096,
                "toolPolicy": "AllowAll",
                "exfiltrationGuard": true
            }]
        });
        let issues = lint_agent_configs(&agents, &default_config());
        assert!(!issues.iter().any(|i| i.path.contains("toolPolicy")));
    }

    // ==================== Missing maxTokens ====================

    #[test]
    fn test_missing_max_tokens_warns() {
        let agents = json!({
            "list": [{
                "model": "claude-sonnet-4-20250514"
            }]
        });
        let issues = lint_agent_configs(&agents, &default_config());
        assert!(issues.iter().any(|i| i.path.contains("maxTokens")));
    }

    #[test]
    fn test_has_max_tokens_no_warning() {
        let agents = json!({
            "list": [{
                "model": "claude-sonnet-4-20250514",
                "maxTokens": 2048
            }]
        });
        let issues = lint_agent_configs(&agents, &default_config());
        assert!(!issues.iter().any(|i| i.path.contains("maxTokens")));
    }

    // ==================== Long System Prompt ====================

    #[test]
    fn test_long_system_prompt_warns() {
        let long_prompt = "x".repeat(15_000);
        let agents = json!({
            "list": [{
                "model": "claude-sonnet-4-20250514",
                "maxTokens": 4096,
                "system": long_prompt
            }]
        });
        let issues = lint_agent_configs(&agents, &default_config());
        assert!(issues.iter().any(|i| i.path.contains("system")));
    }

    #[test]
    fn test_normal_system_prompt_no_warning() {
        let agents = json!({
            "list": [{
                "model": "claude-sonnet-4-20250514",
                "maxTokens": 4096,
                "system": "You are a helpful assistant."
            }]
        });
        let issues = lint_agent_configs(&agents, &default_config());
        assert!(!issues.iter().any(|i| i.path.contains("system")));
    }

    // ==================== Missing Model ====================

    #[test]
    fn test_missing_model_warns() {
        let agents = json!({
            "list": [{
                "maxTokens": 4096
            }]
        });
        let issues = lint_agent_configs(&agents, &default_config());
        assert!(issues.iter().any(|i| i.path.contains("model")));
    }

    // ==================== Disabled Config ====================

    #[test]
    fn test_disabled_lint_produces_no_issues() {
        let agents = json!({
            "list": [{ "toolPolicy": "AllowAll" }]
        });
        let issues = lint_agent_configs(&agents, &disabled_config());
        assert!(issues.is_empty());
    }

    // ==================== Edge Cases ====================

    #[test]
    fn test_no_list_key() {
        let agents = json!({});
        let issues = lint_agent_configs(&agents, &default_config());
        assert!(issues.is_empty());
    }

    #[test]
    fn test_empty_list() {
        let agents = json!({ "list": [] });
        let issues = lint_agent_configs(&agents, &default_config());
        assert!(issues.is_empty());
    }

    #[test]
    fn test_non_object_list_entries_skipped() {
        let agents = json!({ "list": ["not-an-object", 42] });
        let issues = lint_agent_configs(&agents, &default_config());
        assert!(issues.is_empty());
    }

    #[test]
    fn test_multiple_agents_multiple_issues() {
        let agents = json!({
            "list": [
                { "toolPolicy": "AllowAll" },
                { "system": "x".repeat(15_000) }
            ]
        });
        let issues = lint_agent_configs(&agents, &default_config());
        // First agent: AllowAll without guard + missing maxTokens + missing model
        // Second agent: missing maxTokens + missing model + long system
        assert!(issues.len() >= 5);
    }

    #[test]
    fn test_allow_all_snake_case() {
        let agents = json!({
            "list": [{
                "model": "gpt-4",
                "maxTokens": 4096,
                "toolPolicy": "allow_all"
            }]
        });
        let issues = lint_agent_configs(&agents, &default_config());
        assert!(issues.iter().any(|i| i.path.contains("toolPolicy")));
    }

    #[test]
    fn test_exfiltration_guard_snake_case_does_not_suppress_warning() {
        let agents = json!({
            "list": [{
                "model": "gpt-4",
                "maxTokens": 4096,
                "toolPolicy": "AllowAll",
                "exfiltration_guard": true
            }]
        });
        let issues = lint_agent_configs(&agents, &default_config());
        assert!(issues.iter().any(|i| i.path.contains("toolPolicy")));
    }
}
