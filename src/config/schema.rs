//! Config schema validation with typed checks and range enforcement.

use serde_json::Value;

/// Severity of a schema validation issue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    /// Hard error — startup must abort.
    Error,
    /// Advisory — logged but does not prevent startup.
    Warning,
}

/// A single schema validation finding.
#[derive(Debug, Clone)]
pub struct SchemaIssue {
    pub severity: Severity,
    pub path: String,
    pub message: String,
}

/// Return the list of known top-level configuration keys.
pub fn known_top_level_keys() -> &'static [&'static str] {
    KNOWN_TOP_LEVEL_KEYS
}

/// Known top-level configuration keys.
const KNOWN_TOP_LEVEL_KEYS: &[&str] = &[
    "meta",
    "env",
    "wizard",
    "diagnostics",
    "logging",
    "update",
    "browser",
    "ui",
    "auth",
    "models",
    "nodeHost",
    "agents",
    "tools",
    "bindings",
    "broadcast",
    "audio",
    "media",
    "messages",
    "commands",
    "approvals",
    "session",
    "cron",
    "hooks",
    "web",
    "channels",
    "discovery",
    "canvasHost",
    "talk",
    "gateway",
    "usage",
    "skills",
    "plugins",
    "anthropic",
    "sessions",
    "openai",
    "google",
    "providers",
    "bedrock",
    "venice",
    "signal",
    "telegram",
    "discord",
    "slack",
    "classifier",
];

/// Validate a config value against the full schema.
///
/// Returns a (possibly empty) list of issues. Callers should inspect each
/// issue's `severity` to decide whether to abort or merely warn.
pub fn validate_schema(config: &Value) -> Vec<SchemaIssue> {
    let mut issues = Vec::new();

    let obj = match config.as_object() {
        Some(o) => o,
        None => {
            issues.push(SchemaIssue {
                severity: Severity::Error,
                path: ".".to_string(),
                message: "Config root must be an object".to_string(),
            });
            return issues;
        }
    };

    // Unknown top-level keys
    for key in obj.keys() {
        if !KNOWN_TOP_LEVEL_KEYS.contains(&key.as_str()) {
            issues.push(SchemaIssue {
                severity: Severity::Warning,
                path: format!(".{}", key),
                message: format!("Unknown configuration key: {}", key),
            });
        }
    }

    validate_gateway(obj, &mut issues);
    validate_hooks(obj, &mut issues);
    validate_logging(obj, &mut issues);
    validate_agents(obj, &mut issues);
    validate_session(obj, &mut issues);
    validate_cron(obj, &mut issues);
    validate_prompt_guard(obj, &mut issues);
    validate_output_sanitizer(obj, &mut issues);
    validate_skills_signature(obj, &mut issues);
    validate_skills_sandbox(obj, &mut issues);
    validate_session_integrity(obj, &mut issues);
    validate_usage(obj, &mut issues);

    // Run agent config lint if prompt guard config lint is enabled
    if let Some(agents) = obj.get("agents") {
        let lint_enabled = obj
            .get("agents")
            .and_then(|a| a.get("promptGuard"))
            .and_then(|pg| pg.get("configLint"))
            .and_then(|cl| cl.get("enabled"))
            .and_then(|e| e.as_bool())
            .unwrap_or(false);

        if lint_enabled {
            let lint_config = crate::agent::prompt_guard::ConfigLintConfig { enabled: true };
            let lint_issues =
                crate::agent::prompt_guard::config_lint::lint_agent_configs(agents, &lint_config);
            issues.extend(lint_issues);
        }
    }

    issues
}

// ---------------------------------------------------------------------------
// Per-section validators
// ---------------------------------------------------------------------------

fn validate_gateway(obj: &serde_json::Map<String, Value>, issues: &mut Vec<SchemaIssue>) {
    let gateway = match obj.get("gateway").and_then(|v| v.as_object()) {
        Some(g) => g,
        None => return,
    };

    // .gateway.port — integer, 1..=65535
    if let Some(port) = gateway.get("port") {
        match port.as_u64() {
            Some(p) if (1..=65535).contains(&p) => {}
            Some(p) => {
                issues.push(SchemaIssue {
                    severity: Severity::Error,
                    path: ".gateway.port".to_string(),
                    message: format!("port must be between 1 and 65535, got {}", p),
                });
            }
            None => {
                issues.push(SchemaIssue {
                    severity: Severity::Error,
                    path: ".gateway.port".to_string(),
                    message: "port must be a positive integer".to_string(),
                });
            }
        }
    }

    // .gateway.bind — string, known value or valid IP
    if let Some(bind) = gateway.get("bind") {
        if let Some(s) = bind.as_str() {
            let known = ["loopback", "lan", "auto", "tailnet"];
            if !known.contains(&s) && s.parse::<std::net::IpAddr>().is_err() {
                issues.push(SchemaIssue {
                    severity: Severity::Warning,
                    path: ".gateway.bind".to_string(),
                    message: format!(
                        "bind should be one of loopback/lan/auto/tailnet or a valid IP address, got \"{}\"",
                        s
                    ),
                });
            }
        }
    }

    // .gateway.reload sub-section
    if let Some(reload) = gateway.get("reload").and_then(|v| v.as_object()) {
        if let Some(mode) = reload.get("mode") {
            if let Some(s) = mode.as_str() {
                let valid = ["hot", "hybrid", "off"];
                if !valid.contains(&s) {
                    issues.push(SchemaIssue {
                        severity: Severity::Warning,
                        path: ".gateway.reload.mode".to_string(),
                        message: format!(
                            "reload mode should be one of hot/hybrid/off, got \"{}\"",
                            s
                        ),
                    });
                }
            }
        }
        if let Some(debounce) = reload.get("debounceMs") {
            check_positive_integer(debounce, ".gateway.reload.debounceMs", issues);
        }
    }

    // .gateway.ws sub-section (for WS rate limit config)
    if let Some(ws) = gateway.get("ws").and_then(|v| v.as_object()) {
        if let Some(rate) = ws.get("messageRate") {
            check_positive_number(rate, ".gateway.ws.messageRate", issues);
        }
        if let Some(burst) = ws.get("messageBurst") {
            check_positive_number(burst, ".gateway.ws.messageBurst", issues);
        }
    }
}

fn validate_hooks(obj: &serde_json::Map<String, Value>, issues: &mut Vec<SchemaIssue>) {
    let hooks = match obj.get("hooks").and_then(|v| v.as_object()) {
        Some(h) => h,
        None => return,
    };

    if let Some(max_bytes) = hooks.get("maxBodyBytes") {
        check_positive_integer(max_bytes, ".hooks.maxBodyBytes", issues);
    }

    if let Some(enabled) = hooks.get("enabled") {
        if !enabled.is_boolean() {
            issues.push(SchemaIssue {
                severity: Severity::Warning,
                path: ".hooks.enabled".to_string(),
                message: "enabled must be a boolean".to_string(),
            });
        }
    }
}

fn validate_logging(obj: &serde_json::Map<String, Value>, issues: &mut Vec<SchemaIssue>) {
    let logging = match obj.get("logging").and_then(|v| v.as_object()) {
        Some(l) => l,
        None => return,
    };

    if let Some(level) = logging.get("level") {
        if let Some(s) = level.as_str() {
            let valid = ["trace", "debug", "info", "warn", "error"];
            if !valid.contains(&s) {
                issues.push(SchemaIssue {
                    severity: Severity::Warning,
                    path: ".logging.level".to_string(),
                    message: format!(
                        "level should be one of trace/debug/info/warn/error, got \"{}\"",
                        s
                    ),
                });
            }
        }
    }

    if let Some(format) = logging.get("format") {
        if let Some(s) = format.as_str() {
            let valid = ["json", "text"];
            if !valid.contains(&s) {
                issues.push(SchemaIssue {
                    severity: Severity::Warning,
                    path: ".logging.format".to_string(),
                    message: format!("format should be one of json/text, got \"{}\"", s),
                });
            }
        }
    }
}

fn validate_agents(obj: &serde_json::Map<String, Value>, issues: &mut Vec<SchemaIssue>) {
    let agents = match obj.get("agents").and_then(|v| v.as_object()) {
        Some(a) => a,
        None => return,
    };

    let defaults = match agents.get("defaults").and_then(|v| v.as_object()) {
        Some(d) => d,
        None => return,
    };

    if let Some(v) = defaults.get("maxConcurrent") {
        check_positive_integer(v, ".agents.defaults.maxConcurrent", issues);
    }
    if let Some(v) = defaults.get("timeout") {
        check_positive_integer(v, ".agents.defaults.timeout", issues);
    }
    if let Some(v) = defaults.get("contextTokens") {
        check_positive_integer(v, ".agents.defaults.contextTokens", issues);
    }
}

fn validate_session(obj: &serde_json::Map<String, Value>, issues: &mut Vec<SchemaIssue>) {
    let sessions = obj.get("sessions").and_then(|v| v.as_object());
    let legacy_session = obj.get("session").and_then(|v| v.as_object());

    if let Some(retention) = sessions
        .and_then(|s| s.get("retention"))
        .and_then(|v| v.as_object())
    {
        if let Some(days) = retention.get("days") {
            check_positive_integer(days, ".sessions.retention.days", issues);
        }
        if let Some(enabled) = retention.get("enabled") {
            if !enabled.is_boolean() {
                issues.push(SchemaIssue {
                    severity: Severity::Warning,
                    path: ".sessions.retention.enabled".to_string(),
                    message: "enabled must be a boolean".to_string(),
                });
            }
        }
    }

    if let Some(days) = sessions.and_then(|s| s.get("retentionDays")) {
        check_positive_integer(days, ".sessions.retentionDays", issues);
    }

    if let Some(retention) = legacy_session
        .and_then(|s| s.get("retention"))
        .and_then(|v| v.as_object())
    {
        if let Some(days) = retention.get("days") {
            check_positive_integer(days, ".session.retention.days", issues);
        }
        if let Some(enabled) = retention.get("enabled") {
            if !enabled.is_boolean() {
                issues.push(SchemaIssue {
                    severity: Severity::Warning,
                    path: ".session.retention.enabled".to_string(),
                    message: "enabled must be a boolean".to_string(),
                });
            }
        }
    }
}

fn validate_cron(obj: &serde_json::Map<String, Value>, issues: &mut Vec<SchemaIssue>) {
    let cron = match obj.get("cron").and_then(|v| v.as_object()) {
        Some(c) => c,
        None => return,
    };

    let entries = match cron.get("entries").and_then(|v| v.as_array()) {
        Some(a) => a,
        None => return,
    };

    for (i, entry) in entries.iter().enumerate() {
        let entry_obj = match entry.as_object() {
            Some(o) => o,
            None => {
                issues.push(SchemaIssue {
                    severity: Severity::Warning,
                    path: format!(".cron.entries[{}]", i),
                    message: "cron entry must be an object".to_string(),
                });
                continue;
            }
        };

        // Validate schedule (basic regex: should have 5 or 6 cron fields)
        if let Some(schedule) = entry_obj.get("schedule") {
            if let Some(s) = schedule.as_str() {
                if !is_plausible_cron(s) {
                    issues.push(SchemaIssue {
                        severity: Severity::Warning,
                        path: format!(".cron.entries[{}].schedule", i),
                        message: format!(
                            "schedule does not look like a valid cron expression: \"{}\"",
                            s
                        ),
                    });
                }
            }
        }

        // Validate payload is an object
        if let Some(payload) = entry_obj.get("payload") {
            if !payload.is_object() {
                issues.push(SchemaIssue {
                    severity: Severity::Warning,
                    path: format!(".cron.entries[{}].payload", i),
                    message: "payload must be an object".to_string(),
                });
            }
        }
    }
}

fn validate_prompt_guard(obj: &serde_json::Map<String, Value>, issues: &mut Vec<SchemaIssue>) {
    let pg = match obj
        .get("agents")
        .and_then(|a| a.get("promptGuard"))
        .and_then(|v| v.as_object())
    {
        Some(pg) => pg,
        None => return,
    };

    if let Some(enabled) = pg.get("enabled") {
        if !enabled.is_boolean() {
            issues.push(SchemaIssue {
                severity: Severity::Warning,
                path: ".agents.promptGuard.enabled".to_string(),
                message: "enabled must be a boolean".to_string(),
            });
        }
    }

    // Validate sub-sections have boolean enabled fields
    for section in &["preflight", "tagging", "postflight", "configLint"] {
        if let Some(sub) = pg.get(*section).and_then(|v| v.as_object()) {
            if let Some(enabled) = sub.get("enabled") {
                if !enabled.is_boolean() {
                    issues.push(SchemaIssue {
                        severity: Severity::Warning,
                        path: format!(".agents.promptGuard.{}.enabled", section),
                        message: "enabled must be a boolean".to_string(),
                    });
                }
            }
        }
    }
}

fn validate_output_sanitizer(obj: &serde_json::Map<String, Value>, issues: &mut Vec<SchemaIssue>) {
    let agents = match obj.get("agents").and_then(|v| v.as_object()) {
        Some(a) => a,
        None => return,
    };

    let output = agents
        .get("outputSanitizer")
        .or_else(|| agents.get("output_sanitizer"))
        .and_then(|v| v.as_object());
    let output = match output {
        Some(o) => o,
        None => return,
    };

    if let Some(enabled) = output
        .get("sanitizeHtml")
        .or_else(|| output.get("sanitize_html"))
    {
        if !enabled.is_boolean() {
            issues.push(SchemaIssue {
                severity: Severity::Warning,
                path: ".agents.outputSanitizer.sanitizeHtml".to_string(),
                message: "sanitizeHtml must be a boolean".to_string(),
            });
        }
    }

    if let Some(policy) = output.get("cspPolicy").or_else(|| output.get("csp_policy")) {
        if !policy.is_string() {
            issues.push(SchemaIssue {
                severity: Severity::Warning,
                path: ".agents.outputSanitizer.cspPolicy".to_string(),
                message: "cspPolicy must be a string".to_string(),
            });
        }
    }
}

fn validate_skills_signature(obj: &serde_json::Map<String, Value>, issues: &mut Vec<SchemaIssue>) {
    let sig = match obj
        .get("skills")
        .and_then(|s| s.get("signature"))
        .and_then(|v| v.as_object())
    {
        Some(s) => s,
        None => return,
    };

    if let Some(enabled) = sig.get("enabled") {
        if !enabled.is_boolean() {
            issues.push(SchemaIssue {
                severity: Severity::Warning,
                path: ".skills.signature.enabled".to_string(),
                message: "enabled must be a boolean".to_string(),
            });
        }
    }

    if let Some(require) = sig.get("requireSignature") {
        if !require.is_boolean() {
            issues.push(SchemaIssue {
                severity: Severity::Warning,
                path: ".skills.signature.requireSignature".to_string(),
                message: "requireSignature must be a boolean".to_string(),
            });
        }
    }

    if let Some(publishers) = sig.get("trustedPublishers") {
        if !publishers.is_array() {
            issues.push(SchemaIssue {
                severity: Severity::Warning,
                path: ".skills.signature.trustedPublishers".to_string(),
                message: "trustedPublishers must be an array".to_string(),
            });
        }
    }
}

fn validate_skills_sandbox(obj: &serde_json::Map<String, Value>, issues: &mut Vec<SchemaIssue>) {
    let sandbox = match obj
        .get("skills")
        .and_then(|s| s.get("sandbox"))
        .and_then(|v| v.as_object())
    {
        Some(s) => s,
        None => return,
    };

    if let Some(enabled) = sandbox.get("enabled") {
        if !enabled.is_boolean() {
            issues.push(SchemaIssue {
                severity: Severity::Warning,
                path: ".skills.sandbox.enabled".to_string(),
                message: "enabled must be a boolean".to_string(),
            });
        }
    }

    if let Some(defaults) = sandbox.get("defaults").and_then(|v| v.as_object()) {
        for key in &["allowHttp", "allowCredentials", "allowMedia"] {
            if let Some(val) = defaults.get(*key) {
                if !val.is_boolean() {
                    issues.push(SchemaIssue {
                        severity: Severity::Warning,
                        path: format!(".skills.sandbox.defaults.{}", key),
                        message: format!("{} must be a boolean", key),
                    });
                }
            }
        }
    }
}

fn validate_session_integrity(obj: &serde_json::Map<String, Value>, issues: &mut Vec<SchemaIssue>) {
    let integrity = match obj
        .get("sessions")
        .and_then(|s| s.get("integrity"))
        .and_then(|v| v.as_object())
    {
        Some(i) => i,
        None => return,
    };

    if let Some(enabled) = integrity.get("enabled") {
        if !enabled.is_boolean() {
            issues.push(SchemaIssue {
                severity: Severity::Warning,
                path: ".sessions.integrity.enabled".to_string(),
                message: "enabled must be a boolean".to_string(),
            });
        }
    }

    if let Some(action) = integrity.get("action").and_then(|v| v.as_str()) {
        let valid = ["warn", "reject"];
        if !valid.contains(&action) {
            issues.push(SchemaIssue {
                severity: Severity::Warning,
                path: ".sessions.integrity.action".to_string(),
                message: format!("action should be one of warn/reject, got \"{}\"", action),
            });
        }
    }
}

fn validate_usage(obj: &serde_json::Map<String, Value>, issues: &mut Vec<SchemaIssue>) {
    let usage = match obj.get("usage").and_then(|v| v.as_object()) {
        Some(u) => u,
        None => return,
    };

    let pricing = match usage.get("pricing") {
        Some(value) => match value.as_object() {
            Some(p) => p,
            None => {
                issues.push(SchemaIssue {
                    severity: Severity::Warning,
                    path: ".usage.pricing".to_string(),
                    message: "pricing must be an object".to_string(),
                });
                return;
            }
        },
        None => return,
    };

    if let Some(default) = pricing.get("default") {
        match default.as_object() {
            Some(obj) => {
                if let Some(input) = obj.get("inputCostPerMTok") {
                    check_non_negative_number(
                        input,
                        ".usage.pricing.default.inputCostPerMTok",
                        issues,
                    );
                }
                if let Some(output) = obj.get("outputCostPerMTok") {
                    check_non_negative_number(
                        output,
                        ".usage.pricing.default.outputCostPerMTok",
                        issues,
                    );
                }
            }
            None => issues.push(SchemaIssue {
                severity: Severity::Warning,
                path: ".usage.pricing.default".to_string(),
                message: "default must be an object".to_string(),
            }),
        }
    }

    if let Some(overrides) = pricing.get("overrides") {
        let list = match overrides.as_array() {
            Some(list) => list,
            None => {
                issues.push(SchemaIssue {
                    severity: Severity::Warning,
                    path: ".usage.pricing.overrides".to_string(),
                    message: "overrides must be an array".to_string(),
                });
                return;
            }
        };

        for (idx, entry) in list.iter().enumerate() {
            let entry_obj = match entry.as_object() {
                Some(obj) => obj,
                None => {
                    issues.push(SchemaIssue {
                        severity: Severity::Warning,
                        path: format!(".usage.pricing.overrides[{}]", idx),
                        message: "override entry must be an object".to_string(),
                    });
                    continue;
                }
            };

            match entry_obj.get("match").and_then(|v| v.as_str()) {
                Some(value) if !value.trim().is_empty() => {}
                _ => issues.push(SchemaIssue {
                    severity: Severity::Warning,
                    path: format!(".usage.pricing.overrides[{}].match", idx),
                    message: "match must be a non-empty string".to_string(),
                }),
            }

            if let Some(match_type) = entry_obj.get("matchType").and_then(|v| v.as_str()) {
                if !matches!(match_type, "contains" | "exact") {
                    issues.push(SchemaIssue {
                        severity: Severity::Warning,
                        path: format!(".usage.pricing.overrides[{}].matchType", idx),
                        message: "matchType should be \"contains\" or \"exact\"".to_string(),
                    });
                }
            }

            if let Some(input) = entry_obj.get("inputCostPerMTok") {
                check_non_negative_number(
                    input,
                    &format!(".usage.pricing.overrides[{}].inputCostPerMTok", idx),
                    issues,
                );
            }

            if let Some(output) = entry_obj.get("outputCostPerMTok") {
                check_non_negative_number(
                    output,
                    &format!(".usage.pricing.overrides[{}].outputCostPerMTok", idx),
                    issues,
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Check that a value is a positive integer (> 0).
fn check_positive_integer(value: &Value, path: &str, issues: &mut Vec<SchemaIssue>) {
    match value.as_u64() {
        Some(n) if n > 0 => {}
        Some(0) => {
            issues.push(SchemaIssue {
                severity: Severity::Warning,
                path: path.to_string(),
                message: "value must be a positive integer (> 0)".to_string(),
            });
        }
        _ => {
            issues.push(SchemaIssue {
                severity: Severity::Warning,
                path: path.to_string(),
                message: "value must be a positive integer".to_string(),
            });
        }
    }
}

/// Check that a value is a positive number (> 0).
fn check_positive_number(value: &Value, path: &str, issues: &mut Vec<SchemaIssue>) {
    match value.as_f64() {
        Some(n) if n > 0.0 => {}
        Some(_) => {
            issues.push(SchemaIssue {
                severity: Severity::Warning,
                path: path.to_string(),
                message: "value must be a positive number (> 0)".to_string(),
            });
        }
        None => {
            issues.push(SchemaIssue {
                severity: Severity::Warning,
                path: path.to_string(),
                message: "value must be a number".to_string(),
            });
        }
    }
}

/// Check that a value is a non-negative number (>= 0).
fn check_non_negative_number(value: &Value, path: &str, issues: &mut Vec<SchemaIssue>) {
    match value.as_f64() {
        Some(n) if n >= 0.0 => {}
        Some(_) => {
            issues.push(SchemaIssue {
                severity: Severity::Warning,
                path: path.to_string(),
                message: "value must be a non-negative number (>= 0)".to_string(),
            });
        }
        None => {
            issues.push(SchemaIssue {
                severity: Severity::Warning,
                path: path.to_string(),
                message: "value must be a number".to_string(),
            });
        }
    }
}

/// Basic plausibility check for cron expressions.
/// Accepts 5-field (standard) or 6-field (with seconds) expressions.
/// Each field should be `*`, a number, or a more complex expression.
fn is_plausible_cron(s: &str) -> bool {
    let fields: Vec<&str> = s.split_whitespace().collect();
    if !(5..=6).contains(&fields.len()) {
        return false;
    }
    // Each field must be non-empty and contain only valid cron characters
    fields.iter().all(|f| {
        !f.is_empty()
            && f.chars().all(|c| {
                c.is_ascii_digit() || matches!(c, '*' | ',' | '-' | '/' | '?' | '#' | 'L' | 'W')
            })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // --- valid config passes ---

    #[test]
    fn test_valid_config_no_issues() {
        let cfg = json!({
            "gateway": { "port": 18789, "bind": "loopback" },
            "logging": { "level": "info", "format": "json" },
            "hooks": { "enabled": true, "maxBodyBytes": 262144 }
        });
        let issues = validate_schema(&cfg);
        assert!(issues.is_empty(), "expected no issues, got: {:?}", issues);
    }

    // --- port validation ---

    #[test]
    fn test_invalid_port_string() {
        let cfg = json!({ "gateway": { "port": "not-a-number" } });
        let issues = validate_schema(&cfg);
        assert!(issues
            .iter()
            .any(|i| i.path == ".gateway.port" && i.severity == Severity::Error));
    }

    #[test]
    fn test_port_zero_rejected() {
        let cfg = json!({ "gateway": { "port": 0 } });
        let issues = validate_schema(&cfg);
        assert!(issues
            .iter()
            .any(|i| i.path == ".gateway.port" && i.severity == Severity::Error));
    }

    #[test]
    fn test_port_too_high() {
        let cfg = json!({ "gateway": { "port": 70000 } });
        let issues = validate_schema(&cfg);
        assert!(issues
            .iter()
            .any(|i| i.path == ".gateway.port" && i.severity == Severity::Error));
    }

    #[test]
    fn test_port_valid_boundary() {
        let cfg = json!({ "gateway": { "port": 1 } });
        let issues = validate_schema(&cfg);
        assert!(!issues.iter().any(|i| i.path == ".gateway.port"));

        let cfg = json!({ "gateway": { "port": 65535 } });
        let issues = validate_schema(&cfg);
        assert!(!issues.iter().any(|i| i.path == ".gateway.port"));
    }

    // --- bind validation ---

    #[test]
    fn test_bind_valid_known_values() {
        for val in &["loopback", "lan", "auto", "tailnet"] {
            let cfg = json!({ "gateway": { "bind": val } });
            let issues = validate_schema(&cfg);
            assert!(
                !issues.iter().any(|i| i.path == ".gateway.bind"),
                "bind={} should be valid",
                val
            );
        }
    }

    #[test]
    fn test_bind_valid_ip() {
        let cfg = json!({ "gateway": { "bind": "192.168.1.1" } });
        let issues = validate_schema(&cfg);
        assert!(!issues.iter().any(|i| i.path == ".gateway.bind"));
    }

    #[test]
    fn test_bind_invalid() {
        let cfg = json!({ "gateway": { "bind": "banana" } });
        let issues = validate_schema(&cfg);
        assert!(issues.iter().any(|i| i.path == ".gateway.bind"));
    }

    // --- reload mode ---

    #[test]
    fn test_reload_mode_valid() {
        for mode in &["hot", "hybrid", "off"] {
            let cfg = json!({ "gateway": { "reload": { "mode": mode } } });
            let issues = validate_schema(&cfg);
            assert!(!issues.iter().any(|i| i.path == ".gateway.reload.mode"));
        }
    }

    #[test]
    fn test_reload_mode_invalid() {
        let cfg = json!({ "gateway": { "reload": { "mode": "invalid" } } });
        let issues = validate_schema(&cfg);
        assert!(issues.iter().any(|i| i.path == ".gateway.reload.mode"));
    }

    // --- debounce ---

    #[test]
    fn test_debounce_valid() {
        let cfg = json!({ "gateway": { "reload": { "debounceMs": 300 } } });
        let issues = validate_schema(&cfg);
        assert!(!issues.iter().any(|i| i.path.contains("debounceMs")));
    }

    #[test]
    fn test_debounce_zero_warns() {
        let cfg = json!({ "gateway": { "reload": { "debounceMs": 0 } } });
        let issues = validate_schema(&cfg);
        assert!(issues.iter().any(|i| i.path.contains("debounceMs")));
    }

    // --- hooks ---

    #[test]
    fn test_hooks_enabled_non_bool() {
        let cfg = json!({ "hooks": { "enabled": "yes" } });
        let issues = validate_schema(&cfg);
        assert!(issues.iter().any(|i| i.path == ".hooks.enabled"));
    }

    #[test]
    fn test_hooks_max_body_bytes_string() {
        let cfg = json!({ "hooks": { "maxBodyBytes": "big" } });
        let issues = validate_schema(&cfg);
        assert!(issues.iter().any(|i| i.path == ".hooks.maxBodyBytes"));
    }

    // --- logging ---

    #[test]
    fn test_logging_level_invalid() {
        let cfg = json!({ "logging": { "level": "verbose" } });
        let issues = validate_schema(&cfg);
        assert!(issues.iter().any(|i| i.path == ".logging.level"));
    }

    #[test]
    fn test_logging_format_invalid() {
        let cfg = json!({ "logging": { "format": "yaml" } });
        let issues = validate_schema(&cfg);
        assert!(issues.iter().any(|i| i.path == ".logging.format"));
    }

    #[test]
    fn test_logging_valid() {
        let cfg = json!({ "logging": { "level": "debug", "format": "text" } });
        let issues = validate_schema(&cfg);
        assert!(!issues.iter().any(|i| i.path.starts_with(".logging")));
    }

    // --- agents defaults ---

    #[test]
    fn test_agents_defaults_valid() {
        let cfg = json!({ "agents": { "defaults": { "maxConcurrent": 5, "timeout": 60, "contextTokens": 8000 } } });
        let issues = validate_schema(&cfg);
        assert!(!issues.iter().any(|i| i.path.starts_with(".agents")));
    }

    #[test]
    fn test_agents_defaults_zero_warns() {
        let cfg = json!({ "agents": { "defaults": { "maxConcurrent": 0 } } });
        let issues = validate_schema(&cfg);
        assert!(issues
            .iter()
            .any(|i| i.path == ".agents.defaults.maxConcurrent"));
    }

    #[test]
    fn test_agents_output_sanitizer_valid() {
        let cfg = json!({
            "agents": {
                "outputSanitizer": {
                    "sanitizeHtml": false,
                    "cspPolicy": "default-src 'self'"
                }
            }
        });
        let issues = validate_schema(&cfg);
        assert!(!issues
            .iter()
            .any(|i| i.path.starts_with(".agents.outputSanitizer")));
    }

    #[test]
    fn test_agents_output_sanitizer_invalid_types() {
        let cfg = json!({
            "agents": {
                "outputSanitizer": {
                    "sanitizeHtml": "false",
                    "cspPolicy": 123
                }
            }
        });
        let issues = validate_schema(&cfg);
        assert!(issues
            .iter()
            .any(|i| i.path == ".agents.outputSanitizer.sanitizeHtml"));
        assert!(issues
            .iter()
            .any(|i| i.path == ".agents.outputSanitizer.cspPolicy"));
    }

    // --- session retention ---

    #[test]
    fn test_session_retention_valid() {
        let cfg = json!({ "sessions": { "retention": { "days": 30, "enabled": true } } });
        let issues = validate_schema(&cfg);
        assert!(!issues.iter().any(|i| i.path.starts_with(".sessions")));
    }

    #[test]
    fn test_session_retention_enabled_non_bool() {
        let cfg = json!({ "sessions": { "retention": { "enabled": "true" } } });
        let issues = validate_schema(&cfg);
        assert!(issues
            .iter()
            .any(|i| i.path == ".sessions.retention.enabled"));
    }

    #[test]
    fn test_sessions_retention_days_legacy() {
        let cfg = json!({ "sessions": { "retentionDays": 45 } });
        let issues = validate_schema(&cfg);
        assert!(!issues
            .iter()
            .any(|i| i.path.starts_with(".sessions.retentionDays")));
    }

    // --- cron ---

    #[test]
    fn test_cron_valid_entry() {
        let cfg = json!({ "cron": { "entries": [{ "schedule": "0 * * * *", "payload": {} }] } });
        let issues = validate_schema(&cfg);
        assert!(!issues.iter().any(|i| i.path.starts_with(".cron")));
    }

    #[test]
    fn test_cron_bad_schedule() {
        let cfg = json!({ "cron": { "entries": [{ "schedule": "not a cron" }] } });
        let issues = validate_schema(&cfg);
        assert!(issues.iter().any(|i| i.path.contains("schedule")));
    }

    #[test]
    fn test_cron_payload_not_object() {
        let cfg =
            json!({ "cron": { "entries": [{ "schedule": "0 * * * *", "payload": "string" }] } });
        let issues = validate_schema(&cfg);
        assert!(issues.iter().any(|i| i.path.contains("payload")));
    }

    #[test]
    fn test_cron_entry_not_object() {
        let cfg = json!({ "cron": { "entries": ["bad"] } });
        let issues = validate_schema(&cfg);
        assert!(issues.iter().any(|i| i.path.contains("entries[0]")));
    }

    // --- unknown keys ---

    #[test]
    fn test_unknown_top_level_key() {
        let cfg = json!({ "gateway": {}, "somethingWeird": true });
        let issues = validate_schema(&cfg);
        assert!(issues
            .iter()
            .any(|i| i.path == ".somethingWeird" && i.severity == Severity::Warning));
    }

    // --- root not object ---

    #[test]
    fn test_root_not_object() {
        let cfg = json!("just a string");
        let issues = validate_schema(&cfg);
        assert!(issues
            .iter()
            .any(|i| i.severity == Severity::Error && i.path == "."));
    }

    // --- WS rate limit config ---

    #[test]
    fn test_ws_message_rate_valid() {
        let cfg = json!({ "gateway": { "ws": { "messageRate": 60.0, "messageBurst": 120.0 } } });
        let issues = validate_schema(&cfg);
        assert!(!issues.iter().any(|i| i.path.contains("messageRate")));
    }

    #[test]
    fn test_ws_message_rate_invalid() {
        let cfg = json!({ "gateway": { "ws": { "messageRate": -1 } } });
        let issues = validate_schema(&cfg);
        assert!(issues.iter().any(|i| i.path.contains("messageRate")));
    }

    // --- is_plausible_cron ---

    #[test]
    fn test_cron_plausibility() {
        assert!(is_plausible_cron("* * * * *"));
        assert!(is_plausible_cron("0 0 * * *"));
        assert!(is_plausible_cron("*/5 * * * *"));
        assert!(is_plausible_cron("0 0 1 1 *"));
        assert!(is_plausible_cron("0 0 * * 1-5"));
        assert!(is_plausible_cron("0 0 0 * * *")); // 6-field
        assert!(!is_plausible_cron("not a cron"));
        assert!(!is_plausible_cron("* * *")); // too few fields
        assert!(!is_plausible_cron(""));
    }
}
