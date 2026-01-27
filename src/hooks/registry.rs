//! Hook mappings registry
//!
//! Provides storage and lookup for custom hook mappings that transform
//! webhook requests into wake or agent actions.

use parking_lot::RwLock;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

/// Hook mapping action type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum HookAction {
    /// Wake action - triggers a wake event
    Wake,
    /// Agent action - dispatches to the agent
    #[default]
    Agent,
}

/// Match criteria for a hook mapping
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HookMatch {
    /// Path to match (without /hooks/ prefix)
    pub path: Option<String>,
    /// Match payload.source field value
    pub source: Option<String>,
}

/// Transform module configuration
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HookTransform {
    /// Path to transform module (relative to transforms dir)
    pub module: Option<String>,
    /// Export name (default: 'default' or 'transform')
    pub export: Option<String>,
}

/// Hook mapping configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HookMapping {
    /// Unique identifier for the mapping
    pub id: Option<String>,
    /// Match criteria
    #[serde(default)]
    pub r#match: HookMatch,
    /// Action type (wake or agent)
    #[serde(default)]
    pub action: HookAction,
    /// Wake mode for scheduling
    #[serde(default)]
    pub wake_mode: Option<String>,
    /// Display name (supports templates)
    pub name: Option<String>,
    /// Session key (supports templates)
    pub session_key: Option<String>,
    /// Message template for agent action
    pub message_template: Option<String>,
    /// Text template for wake action
    pub text_template: Option<String>,
    /// Whether to deliver the message
    pub deliver: Option<bool>,
    /// Allow unsafe external content
    pub allow_unsafe_external_content: Option<bool>,
    /// Target channel
    pub channel: Option<String>,
    /// Recipient (supports templates)
    pub to: Option<String>,
    /// Model override (supports templates)
    pub model: Option<String>,
    /// Thinking level (supports templates)
    pub thinking: Option<String>,
    /// Timeout in seconds
    pub timeout_seconds: Option<u32>,
    /// Transform module configuration
    pub transform: Option<HookTransform>,
}

impl HookMapping {
    /// Create a new hook mapping with the given ID
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: Some(id.into()),
            r#match: HookMatch::default(),
            action: HookAction::Agent,
            wake_mode: None,
            name: None,
            session_key: None,
            message_template: None,
            text_template: None,
            deliver: None,
            allow_unsafe_external_content: None,
            channel: None,
            to: None,
            model: None,
            thinking: None,
            timeout_seconds: None,
            transform: None,
        }
    }

    /// Set the path to match
    pub fn with_path(mut self, path: impl Into<String>) -> Self {
        self.r#match.path = Some(path.into());
        self
    }

    /// Set the source to match
    pub fn with_source(mut self, source: impl Into<String>) -> Self {
        self.r#match.source = Some(source.into());
        self
    }

    /// Set the action type
    pub fn with_action(mut self, action: HookAction) -> Self {
        self.action = action;
        self
    }

    /// Set the message template
    pub fn with_message_template(mut self, template: impl Into<String>) -> Self {
        self.message_template = Some(template.into());
        self
    }

    /// Set the text template
    pub fn with_text_template(mut self, template: impl Into<String>) -> Self {
        self.text_template = Some(template.into());
        self
    }
}

/// Result of evaluating a hook mapping
#[derive(Debug, Clone)]
pub enum HookMappingResult {
    /// Wake action
    Wake { text: String, mode: String },
    /// Agent action
    Agent {
        message: String,
        name: String,
        channel: String,
        to: Option<String>,
        model: Option<String>,
        thinking: Option<String>,
        deliver: bool,
        wake_mode: String,
        session_key: String,
        timeout_seconds: Option<u32>,
        allow_unsafe_external_content: bool,
    },
    /// Skip this webhook (transform returned null)
    Skip,
}

/// Context for hook mapping evaluation
#[derive(Debug, Clone)]
pub struct HookMappingContext {
    /// Request path (without /hooks/ prefix)
    pub path: String,
    /// Request headers (lowercase keys)
    pub headers: HashMap<String, String>,
    /// Request body as parsed JSON
    pub payload: serde_json::Value,
    /// Query string
    pub query: Option<String>,
    /// Current timestamp ISO 8601
    pub now: String,
}

/// Hook mappings registry
pub struct HookRegistry {
    /// Registered hook mappings (in order)
    mappings: RwLock<Vec<HookMapping>>,
    /// Preset mappings by name
    presets: RwLock<HashMap<String, HookMapping>>,
}

impl Default for HookRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl HookRegistry {
    /// Create a new empty hook registry
    pub fn new() -> Self {
        let mut presets = HashMap::new();

        // Gmail preset
        presets.insert(
            "gmail".to_string(),
            HookMapping {
                id: Some("preset:gmail".to_string()),
                r#match: HookMatch {
                    path: Some("gmail".to_string()),
                    source: None,
                },
                action: HookAction::Agent,
                wake_mode: None,
                name: Some("Gmail".to_string()),
                session_key: Some("hook:gmail:{{messages[0].id}}".to_string()),
                message_template: Some(
                    "New email from {{messages[0].from}}\nSubject: {{messages[0].subject}}\n{{messages[0].snippet}}\n{{messages[0].body}}".to_string()
                ),
                text_template: None,
                deliver: None,
                allow_unsafe_external_content: None,
                channel: None,
                to: None,
                model: None,
                thinking: None,
                timeout_seconds: None,
                transform: None,
            },
        );

        Self {
            mappings: RwLock::new(Vec::new()),
            presets: RwLock::new(presets),
        }
    }

    /// Register a hook mapping
    pub fn register(&self, mapping: HookMapping) {
        let mut mappings = self.mappings.write();
        mappings.push(mapping);
    }

    /// Register multiple hook mappings
    pub fn register_all(&self, new_mappings: Vec<HookMapping>) {
        let mut mappings = self.mappings.write();
        mappings.extend(new_mappings);
    }

    /// Enable a preset by name
    pub fn enable_preset(&self, name: &str) -> bool {
        let presets = self.presets.read();
        if let Some(preset) = presets.get(name) {
            let mut mappings = self.mappings.write();
            mappings.push(preset.clone());
            true
        } else {
            false
        }
    }

    /// Clear all registered mappings
    pub fn clear(&self) {
        let mut mappings = self.mappings.write();
        mappings.clear();
    }

    /// Get all registered mappings
    pub fn list(&self) -> Vec<HookMapping> {
        self.mappings.read().clone()
    }

    /// Find a matching mapping for the given context
    pub fn find_match(&self, ctx: &HookMappingContext) -> Option<HookMapping> {
        let mappings = self.mappings.read();
        let normalized_path = normalize_path(&ctx.path);

        for mapping in mappings.iter() {
            if matches_mapping(mapping, &normalized_path, &ctx.payload) {
                return Some(mapping.clone());
            }
        }

        None
    }

    /// Evaluate a hook mapping against a context
    pub fn evaluate(
        &self,
        mapping: &HookMapping,
        ctx: &HookMappingContext,
    ) -> Result<HookMappingResult, HookMappingError> {
        match mapping.action {
            HookAction::Wake => {
                let text = if let Some(template) = &mapping.text_template {
                    evaluate_template(template, ctx)?
                } else {
                    // Default: stringify payload
                    serde_json::to_string(&ctx.payload).unwrap_or_else(|_| "{}".to_string())
                };

                if text.trim().is_empty() {
                    return Err(HookMappingError::EmptyText);
                }

                Ok(HookMappingResult::Wake {
                    text,
                    mode: mapping
                        .wake_mode
                        .clone()
                        .unwrap_or_else(|| "now".to_string()),
                })
            }
            HookAction::Agent => {
                let message = if let Some(template) = &mapping.message_template {
                    evaluate_template(template, ctx)?
                } else {
                    return Err(HookMappingError::MissingMessageTemplate);
                };

                if message.trim().is_empty() {
                    return Err(HookMappingError::EmptyMessage);
                }

                let session_key = if let Some(template) = &mapping.session_key {
                    evaluate_template(template, ctx)?
                } else {
                    format!("hook:{}:{}", ctx.path, uuid::Uuid::new_v4())
                };

                Ok(HookMappingResult::Agent {
                    message,
                    name: mapping.name.clone().unwrap_or_else(|| "Hook".to_string()),
                    channel: mapping
                        .channel
                        .clone()
                        .unwrap_or_else(|| "last".to_string()),
                    to: mapping.to.clone(),
                    model: mapping.model.clone(),
                    thinking: mapping.thinking.clone(),
                    deliver: mapping.deliver.unwrap_or(true),
                    wake_mode: mapping
                        .wake_mode
                        .clone()
                        .unwrap_or_else(|| "now".to_string()),
                    session_key,
                    timeout_seconds: mapping.timeout_seconds,
                    allow_unsafe_external_content: mapping
                        .allow_unsafe_external_content
                        .unwrap_or(false),
                })
            }
        }
    }

    /// Get the number of registered mappings
    pub fn len(&self) -> usize {
        self.mappings.read().len()
    }

    /// Check if the registry is empty
    pub fn is_empty(&self) -> bool {
        self.mappings.read().is_empty()
    }
}

/// Hook mapping error
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HookMappingError {
    /// Message template is missing
    MissingMessageTemplate,
    /// Evaluated message is empty
    EmptyMessage,
    /// Evaluated text is empty
    EmptyText,
    /// Template evaluation failed
    TemplateError(String),
    /// Transform error
    TransformError(String),
}

impl std::fmt::Display for HookMappingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HookMappingError::MissingMessageTemplate => write!(f, "hook mapping requires message"),
            HookMappingError::EmptyMessage => write!(f, "hook mapping requires message"),
            HookMappingError::EmptyText => write!(f, "hook mapping requires text"),
            HookMappingError::TemplateError(msg) => write!(f, "template error: {}", msg),
            HookMappingError::TransformError(msg) => write!(f, "hook mapping failed: {}", msg),
        }
    }
}

impl std::error::Error for HookMappingError {}

/// Normalize a path for matching (remove leading/trailing slashes, trim)
fn normalize_path(path: &str) -> String {
    let trimmed = path.trim();
    if trimmed.is_empty() || trimmed == "/" {
        return String::new();
    }
    trimmed
        .trim_start_matches('/')
        .trim_end_matches('/')
        .to_string()
}

/// Check if a mapping matches the given path and payload
fn matches_mapping(
    mapping: &HookMapping,
    normalized_path: &str,
    payload: &serde_json::Value,
) -> bool {
    // Check path match
    if let Some(match_path) = &mapping.r#match.path {
        let normalized_match = normalize_path(match_path);
        if !normalized_match.is_empty() && normalized_match != normalized_path {
            return false;
        }
    }

    // Check source match
    if let Some(match_source) = &mapping.r#match.source {
        let payload_source = payload.get("source").and_then(|v| v.as_str()).unwrap_or("");
        if !match_source.eq_ignore_ascii_case(payload_source) {
            return false;
        }
    }

    true
}

/// Evaluate a template string against a context
fn evaluate_template(template: &str, ctx: &HookMappingContext) -> Result<String, HookMappingError> {
    // Simple template engine: replace {{path}} with context values
    let re = Regex::new(r"\{\{([^}]+)\}\}").unwrap();
    let mut result = template.to_string();

    for cap in re.captures_iter(template) {
        let full_match = &cap[0];
        let expr = cap[1].trim();

        let value = resolve_template_expr(expr, ctx);
        result = result.replace(full_match, &value);
    }

    Ok(result)
}

/// Resolve a template expression
fn resolve_template_expr(expr: &str, ctx: &HookMappingContext) -> String {
    // Built-in variables
    if expr == "path" {
        return ctx.path.clone();
    }
    if expr == "now" {
        return ctx.now.clone();
    }

    // Header access: headers.<name>
    if let Some(header_name) = expr.strip_prefix("headers.") {
        return ctx
            .headers
            .get(&header_name.to_lowercase())
            .cloned()
            .unwrap_or_default();
    }

    // Query access: query.<name>
    if let Some(query_name) = expr.strip_prefix("query.") {
        if let Some(query) = &ctx.query {
            for param in query.split('&') {
                if let Some((key, value)) = param.split_once('=') {
                    if key == query_name {
                        return value.to_string();
                    }
                }
            }
        }
        return String::new();
    }

    // Payload access: payload.<path> or just <path>
    let payload_path = expr.strip_prefix("payload.").unwrap_or(expr);

    resolve_json_path(&ctx.payload, payload_path)
}

/// Resolve a JSON path expression (supports dot notation and array indexing)
fn resolve_json_path(value: &serde_json::Value, path: &str) -> String {
    let mut current = value;

    for part in split_path(path) {
        current = match part {
            PathPart::Key(ref key) => {
                if let Some(v) = current.get(key.as_str()) {
                    v
                } else {
                    return String::new();
                }
            }
            PathPart::Index(idx) => {
                if let Some(arr) = current.as_array() {
                    if let Some(v) = arr.get(idx) {
                        v
                    } else {
                        return String::new();
                    }
                } else {
                    return String::new();
                }
            }
        };
    }

    match current {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::Bool(b) => b.to_string(),
        serde_json::Value::Null => String::new(),
        _ => serde_json::to_string(current).unwrap_or_default(),
    }
}

enum PathPart {
    Key(String),
    Index(usize),
}

/// Split a path into parts (handles dot notation and array indexing)
fn split_path(path: &str) -> Vec<PathPart> {
    let mut parts = Vec::new();
    let mut current = String::new();

    let chars: Vec<char> = path.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        match chars[i] {
            '.' => {
                if !current.is_empty() {
                    parts.push(PathPart::Key(std::mem::take(&mut current)));
                }
            }
            '[' => {
                if !current.is_empty() {
                    parts.push(PathPart::Key(std::mem::take(&mut current)));
                }
                // Parse index
                i += 1;
                let mut idx_str = String::new();
                while i < chars.len() && chars[i] != ']' {
                    idx_str.push(chars[i]);
                    i += 1;
                }
                if let Ok(idx) = idx_str.parse::<usize>() {
                    parts.push(PathPart::Index(idx));
                }
            }
            ']' => {}
            c => {
                current.push(c);
            }
        }
        i += 1;
    }

    if !current.is_empty() {
        parts.push(PathPart::Key(current));
    }

    parts
}

/// Create a shared hook registry
pub fn create_registry() -> Arc<HookRegistry> {
    Arc::new(HookRegistry::new())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_normalize_path() {
        assert_eq!(normalize_path("github"), "github");
        assert_eq!(normalize_path("/github"), "github");
        assert_eq!(normalize_path("github/"), "github");
        assert_eq!(normalize_path("/github/"), "github");
        assert_eq!(normalize_path("  /github/  "), "github");
        assert_eq!(normalize_path(""), "");
        assert_eq!(normalize_path("/"), "");
    }

    #[test]
    fn test_hook_registry_register() {
        let registry = HookRegistry::new();
        assert!(registry.is_empty());

        registry.register(HookMapping::new("test").with_path("webhook"));
        assert_eq!(registry.len(), 1);

        let mappings = registry.list();
        assert_eq!(mappings.len(), 1);
        assert_eq!(mappings[0].id, Some("test".to_string()));
    }

    #[test]
    fn test_hook_registry_find_match() {
        let registry = HookRegistry::new();
        registry.register(HookMapping::new("github").with_path("github"));
        registry.register(
            HookMapping::new("stripe")
                .with_path("events")
                .with_source("stripe"),
        );

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
    fn test_hook_registry_find_match_with_source() {
        let registry = HookRegistry::new();
        registry.register(
            HookMapping::new("stripe")
                .with_path("events")
                .with_source("stripe"),
        );

        let ctx = HookMappingContext {
            path: "events".to_string(),
            headers: HashMap::new(),
            payload: json!({ "source": "stripe", "type": "payment.succeeded" }),
            query: None,
            now: "2024-01-01T00:00:00Z".to_string(),
        };

        let matched = registry.find_match(&ctx);
        assert!(matched.is_some());
        assert_eq!(matched.unwrap().id, Some("stripe".to_string()));

        // Non-matching source
        let ctx2 = HookMappingContext {
            path: "events".to_string(),
            headers: HashMap::new(),
            payload: json!({ "source": "github", "type": "push" }),
            query: None,
            now: "2024-01-01T00:00:00Z".to_string(),
        };

        assert!(registry.find_match(&ctx2).is_none());
    }

    #[test]
    fn test_hook_registry_no_match() {
        let registry = HookRegistry::new();
        registry.register(HookMapping::new("github").with_path("github"));

        let ctx = HookMappingContext {
            path: "unknown".to_string(),
            headers: HashMap::new(),
            payload: json!({}),
            query: None,
            now: "2024-01-01T00:00:00Z".to_string(),
        };

        assert!(registry.find_match(&ctx).is_none());
    }

    #[test]
    fn test_evaluate_agent_mapping() {
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
    fn test_evaluate_wake_mapping() {
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
            HookMappingResult::Wake { text, .. } => {
                assert_eq!(text, "Wake: scheduled task");
            }
            _ => panic!("Expected Wake result"),
        }
    }

    #[test]
    fn test_evaluate_template_array_access() {
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
    fn test_evaluate_template_header_access() {
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
    fn test_evaluate_missing_message_template() {
        let registry = HookRegistry::new();
        let mapping = HookMapping::new("test").with_action(HookAction::Agent);

        let ctx = HookMappingContext {
            path: "test".to_string(),
            headers: HashMap::new(),
            payload: json!({}),
            query: None,
            now: "2024-01-01T00:00:00Z".to_string(),
        };

        let result = registry.evaluate(&mapping, &ctx);
        assert!(matches!(
            result,
            Err(HookMappingError::MissingMessageTemplate)
        ));
    }

    #[test]
    fn test_evaluate_empty_message() {
        let registry = HookRegistry::new();
        let mapping = HookMapping::new("test")
            .with_action(HookAction::Agent)
            .with_message_template("{{nonexistent}}");

        let ctx = HookMappingContext {
            path: "test".to_string(),
            headers: HashMap::new(),
            payload: json!({}),
            query: None,
            now: "2024-01-01T00:00:00Z".to_string(),
        };

        let result = registry.evaluate(&mapping, &ctx);
        assert!(matches!(result, Err(HookMappingError::EmptyMessage)));
    }

    #[test]
    fn test_enable_preset() {
        let registry = HookRegistry::new();
        assert!(registry.is_empty());

        assert!(registry.enable_preset("gmail"));
        assert_eq!(registry.len(), 1);

        let mappings = registry.list();
        assert_eq!(mappings[0].id, Some("preset:gmail".to_string()));
    }

    #[test]
    fn test_enable_unknown_preset() {
        let registry = HookRegistry::new();
        assert!(!registry.enable_preset("unknown"));
        assert!(registry.is_empty());
    }

    #[test]
    fn test_template_builtins() {
        let registry = HookRegistry::new();
        let mapping =
            HookMapping::new("test").with_message_template("Path: {{path}}, Now: {{now}}");

        let ctx = HookMappingContext {
            path: "webhook".to_string(),
            headers: HashMap::new(),
            payload: json!({}),
            query: None,
            now: "2024-01-15T12:00:00Z".to_string(),
        };

        let result = registry.evaluate(&mapping, &ctx).unwrap();
        match result {
            HookMappingResult::Agent { message, .. } => {
                assert_eq!(message, "Path: webhook, Now: 2024-01-15T12:00:00Z");
            }
            _ => panic!("Expected Agent result"),
        }
    }
}
