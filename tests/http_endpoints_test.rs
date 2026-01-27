//! HTTP endpoints integration tests
//!
//! Tests for the HTTP gateway endpoints including:
//! - Hook mappings and dispatch
//! - Tools invoke endpoint
//! - OpenAI compatibility endpoints
//! - Control endpoints

use carapace::channels::{ChannelInfo, ChannelRegistry, ChannelStatus};
use carapace::hooks::{
    HookAction, HookMapping, HookMappingContext, HookMappingResult, HookRegistry,
};
use carapace::plugins::{ToolInvokeContext, ToolInvokeResult, ToolsRegistry};
use serde_json::json;
use std::collections::HashMap;

// ============================================================================
// Hook Registry Tests
// ============================================================================

#[test]
fn test_hook_registry_register_and_find() {
    let registry = HookRegistry::new();

    registry.register(HookMapping::new("github").with_path("github"));
    registry.register(HookMapping::new("gitlab").with_path("gitlab"));

    assert_eq!(registry.len(), 2);

    let ctx = HookMappingContext {
        path: "github".to_string(),
        headers: HashMap::new(),
        payload: json!({}),
        query: None,
        now: "2024-01-01T00:00:00Z".to_string(),
    };

    let matched = registry.find_match(&ctx);
    assert!(matched.is_some());
    assert_eq!(matched.unwrap().id, Some("github".to_string()));
}

#[test]
fn test_hook_registry_source_matching() {
    let registry = HookRegistry::new();

    registry.register(
        HookMapping::new("stripe")
            .with_path("events")
            .with_source("stripe"),
    );
    registry.register(
        HookMapping::new("github")
            .with_path("events")
            .with_source("github"),
    );

    // Stripe event
    let ctx = HookMappingContext {
        path: "events".to_string(),
        headers: HashMap::new(),
        payload: json!({ "source": "stripe", "type": "payment.succeeded" }),
        query: None,
        now: "2024-01-01T00:00:00Z".to_string(),
    };
    let matched = registry.find_match(&ctx);
    assert_eq!(matched.unwrap().id, Some("stripe".to_string()));

    // GitHub event
    let ctx2 = HookMappingContext {
        path: "events".to_string(),
        headers: HashMap::new(),
        payload: json!({ "source": "github", "action": "push" }),
        query: None,
        now: "2024-01-01T00:00:00Z".to_string(),
    };
    let matched2 = registry.find_match(&ctx2);
    assert_eq!(matched2.unwrap().id, Some("github".to_string()));
}

#[test]
fn test_hook_registry_evaluate_agent() {
    let registry = HookRegistry::new();

    let mapping = HookMapping::new("github")
        .with_path("github")
        .with_action(HookAction::Agent)
        .with_message_template("GitHub {{action}}: {{repository.full_name}}");

    let ctx = HookMappingContext {
        path: "github".to_string(),
        headers: HashMap::new(),
        payload: json!({
            "action": "push",
            "repository": { "full_name": "user/repo" }
        }),
        query: None,
        now: "2024-01-01T00:00:00Z".to_string(),
    };

    let result = registry.evaluate(&mapping, &ctx).unwrap();
    match result {
        HookMappingResult::Agent { message, .. } => {
            assert_eq!(message, "GitHub push: user/repo");
        }
        _ => panic!("Expected Agent result"),
    }
}

#[test]
fn test_hook_registry_evaluate_wake() {
    let registry = HookRegistry::new();

    let mapping = HookMapping::new("trigger")
        .with_path("trigger")
        .with_action(HookAction::Wake)
        .with_text_template("Wake: {{reason}}");

    let ctx = HookMappingContext {
        path: "trigger".to_string(),
        headers: HashMap::new(),
        payload: json!({ "reason": "scheduled task" }),
        query: None,
        now: "2024-01-01T00:00:00Z".to_string(),
    };

    let result = registry.evaluate(&mapping, &ctx).unwrap();
    match result {
        HookMappingResult::Wake { text, mode } => {
            assert_eq!(text, "Wake: scheduled task");
            assert_eq!(mode, "now");
        }
        _ => panic!("Expected Wake result"),
    }
}

#[test]
fn test_hook_registry_template_array_access() {
    let registry = HookRegistry::new();

    let mapping = HookMapping::new("batch")
        .with_message_template("First: {{items[0].name}}, Second: {{items[1].name}}");

    let ctx = HookMappingContext {
        path: "batch".to_string(),
        headers: HashMap::new(),
        payload: json!({
            "items": [
                { "name": "Alpha" },
                { "name": "Beta" }
            ]
        }),
        query: None,
        now: "2024-01-01T00:00:00Z".to_string(),
    };

    let result = registry.evaluate(&mapping, &ctx).unwrap();
    match result {
        HookMappingResult::Agent { message, .. } => {
            assert_eq!(message, "First: Alpha, Second: Beta");
        }
        _ => panic!("Expected Agent result"),
    }
}

#[test]
fn test_hook_registry_template_header_access() {
    let registry = HookRegistry::new();

    let mapping = HookMapping::new("notify")
        .with_message_template("From: {{headers.x-source}} - {{message}}");

    let mut headers = HashMap::new();
    headers.insert("x-source".to_string(), "monitoring-system".to_string());

    let ctx = HookMappingContext {
        path: "notify".to_string(),
        headers,
        payload: json!({ "message": "Alert triggered" }),
        query: None,
        now: "2024-01-01T00:00:00Z".to_string(),
    };

    let result = registry.evaluate(&mapping, &ctx).unwrap();
    match result {
        HookMappingResult::Agent { message, .. } => {
            assert_eq!(message, "From: monitoring-system - Alert triggered");
        }
        _ => panic!("Expected Agent result"),
    }
}

#[test]
fn test_hook_registry_preset() {
    let registry = HookRegistry::new();
    assert!(registry.is_empty());

    assert!(registry.enable_preset("gmail"));
    assert_eq!(registry.len(), 1);

    let ctx = HookMappingContext {
        path: "gmail".to_string(),
        headers: HashMap::new(),
        payload: json!({}),
        query: None,
        now: "2024-01-01T00:00:00Z".to_string(),
    };

    let matched = registry.find_match(&ctx);
    assert!(matched.is_some());
    assert_eq!(matched.unwrap().id, Some("preset:gmail".to_string()));
}

// ============================================================================
// Tools Registry Tests
// ============================================================================

#[test]
fn test_tools_registry_builtin_time() {
    let registry = ToolsRegistry::new();

    assert!(registry.has_tool("time"));

    let ctx = ToolInvokeContext::default();
    let result = registry.invoke("time", json!({}), &ctx);

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
fn test_tools_registry_not_found() {
    let registry = ToolsRegistry::new();
    let ctx = ToolInvokeContext::default();

    let result = registry.invoke("nonexistent_tool", json!({}), &ctx);

    match result {
        ToolInvokeResult::Error { ok, error } => {
            assert!(!ok);
            assert_eq!(error.r#type, "not_found");
            assert!(error.message.contains("nonexistent_tool"));
        }
        _ => panic!("Expected error result"),
    }
}

#[test]
fn test_tools_registry_allowlist() {
    let registry = ToolsRegistry::new();

    // All tools allowed by default
    assert!(registry.has_tool("time"));

    // Set allowlist to exclude time
    registry.set_allowlist(vec!["other_tool".to_string()]);
    assert!(!registry.has_tool("time"));

    // Add time to allowlist
    registry.set_allowlist(vec!["time".to_string()]);
    assert!(registry.has_tool("time"));
}

#[test]
fn test_tools_registry_list() {
    let registry = ToolsRegistry::new();
    let tools = registry.list_tools();

    assert!(!tools.is_empty());
    assert!(tools.iter().any(|t| t.name == "time"));
}

// ============================================================================
// Channel Registry Tests
// ============================================================================

#[test]
fn test_channel_registry_register() {
    let registry = ChannelRegistry::new();
    assert!(registry.is_empty());

    registry.register(ChannelInfo::new("telegram", "Telegram"));
    registry.register(ChannelInfo::new("discord", "Discord"));

    assert_eq!(registry.len(), 2);
    assert!(registry.get("telegram").is_some());
    assert!(registry.get("discord").is_some());
}

#[test]
fn test_channel_registry_status_update() {
    let registry = ChannelRegistry::new();
    registry.register(ChannelInfo::new("telegram", "Telegram"));

    assert_eq!(
        registry.get_status("telegram"),
        Some(ChannelStatus::Disconnected)
    );

    registry.update_status("telegram", ChannelStatus::Connected);
    assert_eq!(
        registry.get_status("telegram"),
        Some(ChannelStatus::Connected)
    );
    assert!(registry.is_connected("telegram"));
}

#[test]
fn test_channel_registry_snapshot() {
    let registry = ChannelRegistry::new();
    registry
        .register(ChannelInfo::new("telegram", "Telegram").with_status(ChannelStatus::Connected));
    registry.register(ChannelInfo::new("discord", "Discord"));

    let snapshot = registry.snapshot();
    assert_eq!(snapshot.channels.len(), 2);
    assert!(snapshot.timestamp > 0);
}

#[test]
fn test_channel_registry_count_by_status() {
    let registry = ChannelRegistry::new();
    registry
        .register(ChannelInfo::new("telegram", "Telegram").with_status(ChannelStatus::Connected));
    registry.register(ChannelInfo::new("discord", "Discord").with_status(ChannelStatus::Connected));
    registry.register(ChannelInfo::new("slack", "Slack").with_status(ChannelStatus::Error));

    assert_eq!(registry.count_by_status(ChannelStatus::Connected), 2);
    assert_eq!(registry.count_by_status(ChannelStatus::Error), 1);
    assert_eq!(registry.count_by_status(ChannelStatus::Disconnected), 0);
}
