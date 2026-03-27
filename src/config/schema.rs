//! Config schema validation with typed checks and range enforcement.

use serde_json::Value;

use crate::plugins::loader::{is_reserved_plugin_id, RESERVED_PLUGIN_CONFIG_KEYS};

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
    "plugins",
    "anthropic",
    "sessions",
    "openai",
    "codex",
    "google",
    "providers",
    "bedrock",
    "venice",
    "signal",
    "telegram",
    "discord",
    "slack",
    "classifier",
    "vertex",
    "filesystem",
];

/// Built-in channel IDs that currently accept `channels.<id>.features.*`.
///
/// Unknown channel IDs remain allowed for forward compatibility, but we use
/// this set to catch obvious typos in built-in names.
const BUILTIN_CHANNEL_CONFIG_IDS: &[&str] = &[
    "console", "signal", "telegram", "discord", "slack", "webhook",
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
    validate_auth(obj, &mut issues);
    validate_google(obj, &mut issues);
    validate_codex(obj, &mut issues);
    validate_agents(obj, &mut issues);
    validate_session(obj, &mut issues);
    validate_channels(obj, &mut issues);
    validate_cron(obj, &mut issues);
    validate_prompt_guard(obj, &mut issues);
    validate_output_sanitizer(obj, &mut issues);
    validate_plugins_signature(obj, &mut issues);
    validate_plugins_sandbox(obj, &mut issues);
    validate_plugins(obj, &mut issues);
    validate_session_integrity(obj, &mut issues);
    validate_usage(obj, &mut issues);
    validate_vertex(obj, &mut issues);
    validate_filesystem(obj, &mut issues);

    // Run agent config lint if prompt guard config lint is enabled
    if let Some(agents) = obj.get("agents") {
        let lint_enabled = prompt_guard_obj(agents)
            .and_then(prompt_guard_config_lint_obj)
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

    // .gateway.hooks sub-section
    if let Some(hooks) = gateway.get("hooks").and_then(|v| v.as_object()) {
        if let Some(max_bytes) = hooks.get("maxBodyBytes") {
            check_positive_integer(max_bytes, ".gateway.hooks.maxBodyBytes", issues);
        }

        if let Some(enabled) = hooks.get("enabled") {
            if !enabled.is_boolean() {
                issues.push(SchemaIssue {
                    severity: Severity::Warning,
                    path: ".gateway.hooks.enabled".to_string(),
                    message: "enabled must be a boolean".to_string(),
                });
            }
        }

        if let Some(path) = hooks.get("path") {
            if !path.is_string() {
                issues.push(SchemaIssue {
                    severity: Severity::Warning,
                    path: ".gateway.hooks.path".to_string(),
                    message: "path must be a string".to_string(),
                });
            }
        }

        if let Some(token) = hooks.get("token") {
            if !token.is_string() {
                issues.push(SchemaIssue {
                    severity: Severity::Warning,
                    path: ".gateway.hooks.token".to_string(),
                    message: "token must be a string".to_string(),
                });
            }
        }
    }

    // .gateway.controlUi sub-section
    if let Some(control_ui) = gateway.get("controlUi").and_then(|v| v.as_object()) {
        if let Some(enabled) = control_ui.get("enabled") {
            if !enabled.is_boolean() {
                issues.push(SchemaIssue {
                    severity: Severity::Warning,
                    path: ".gateway.controlUi.enabled".to_string(),
                    message: "enabled must be a boolean".to_string(),
                });
            }
        }

        if let Some(path) = control_ui.get("path") {
            if !path.is_string() {
                issues.push(SchemaIssue {
                    severity: Severity::Warning,
                    path: ".gateway.controlUi.path".to_string(),
                    message: "path must be a string".to_string(),
                });
            }
        }

        if let Some(base_path) = control_ui.get("basePath") {
            if !base_path.is_string() {
                issues.push(SchemaIssue {
                    severity: Severity::Warning,
                    path: ".gateway.controlUi.basePath".to_string(),
                    message: "basePath must be a string".to_string(),
                });
            }
        }
    }
}

fn validate_channels(obj: &serde_json::Map<String, Value>, issues: &mut Vec<SchemaIssue>) {
    let Some(channels_value) = obj.get("channels") else {
        return;
    };
    let Some(channels) = channels_value.as_object() else {
        issues.push(SchemaIssue {
            severity: Severity::Warning,
            path: ".channels".to_string(),
            message: format!(
                "channels must be an object, got {}",
                json_type_label(channels_value)
            ),
        });
        return;
    };

    for (channel_name, entry) in channels {
        let Some(entry_obj) = entry.as_object() else {
            issues.push(SchemaIssue {
                severity: Severity::Warning,
                path: format!(".channels.{}", channel_name),
                message: format!(
                    "channel config entry must be an object, got {}",
                    json_type_label(entry)
                ),
            });
            continue;
        };

        if let Some(suggested) = suggest_builtin_channel_id(channel_name) {
            issues.push(SchemaIssue {
                severity: Severity::Warning,
                path: format!(".channels.{}", channel_name),
                message: format!(
                    "unknown built-in channel id '{}'; did you mean '{}'?",
                    channel_name, suggested
                ),
            });
        }

        for key in entry_obj.keys() {
            if key != "features" {
                issues.push(SchemaIssue {
                    severity: Severity::Warning,
                    path: format!(".channels.{}.{}", channel_name, key),
                    message: format!(
                        "unknown channel config key '{}'; channel activity settings belong under .channels.{}.features",
                        key, channel_name
                    ),
                });
            }
        }

        if let Some(features) = entry_obj.get("features") {
            validate_channel_features(
                features,
                &format!(".channels.{}.features", channel_name),
                issues,
            );
        }
    }
}

fn suggest_builtin_channel_id(channel_name: &str) -> Option<&'static str> {
    BUILTIN_CHANNEL_CONFIG_IDS.iter().copied().find(|builtin| {
        *builtin != channel_name && bounded_levenshtein(channel_name, builtin, 2) <= 2
    })
}

fn bounded_levenshtein(a: &str, b: &str, max_distance: usize) -> usize {
    let a = a.as_bytes();
    let b = b.as_bytes();
    if a == b {
        return 0;
    }
    if a.len().abs_diff(b.len()) > max_distance {
        return max_distance + 1;
    }

    let mut prev: Vec<usize> = (0..=b.len()).collect();
    let mut curr = vec![0; b.len() + 1];

    for (i, a_byte) in a.iter().enumerate() {
        curr[0] = i + 1;
        let mut row_min = curr[0];
        for (j, b_byte) in b.iter().enumerate() {
            let cost = usize::from(a_byte != b_byte);
            curr[j + 1] = (prev[j + 1] + 1).min(curr[j] + 1).min(prev[j] + cost);
            row_min = row_min.min(curr[j + 1]);
        }
        if row_min > max_distance {
            return max_distance + 1;
        }
        std::mem::swap(&mut prev, &mut curr);
    }

    prev[b.len()]
}

fn validate_channel_features(features: &Value, path: &str, issues: &mut Vec<SchemaIssue>) {
    let Some(features_obj) = features.as_object() else {
        issues.push(SchemaIssue {
            severity: Severity::Warning,
            path: path.to_string(),
            message: format!(
                "features must be an object, got {}",
                json_type_label(features)
            ),
        });
        return;
    };

    for key in features_obj.keys() {
        if !matches!(key.as_str(), "typing" | "readReceipts") {
            issues.push(SchemaIssue {
                severity: Severity::Warning,
                path: format!("{}.{}", path, key),
                message: format!("unknown channel feature '{}'", key),
            });
        }
    }

    if let Some(typing) = features_obj.get("typing") {
        let typing_path = format!("{}.typing", path);
        if let Some(typing_obj) = typing.as_object() {
            for key in typing_obj.keys() {
                if !matches!(key.as_str(), "enabled" | "mode" | "intervalSeconds") {
                    issues.push(SchemaIssue {
                        severity: Severity::Warning,
                        path: format!("{}.{}", typing_path, key),
                        message: format!("unknown typing feature key '{}'", key),
                    });
                }
            }
            if let Some(enabled) = typing_obj.get("enabled") {
                if !enabled.is_boolean() {
                    issues.push(SchemaIssue {
                        severity: Severity::Warning,
                        path: format!("{}.enabled", typing_path),
                        message: "typing enabled must be a boolean".to_string(),
                    });
                }
            }

            if let Some(mode) = typing_obj.get("mode").and_then(|value| value.as_str()) {
                if mode != "thinking" {
                    issues.push(SchemaIssue {
                        severity: Severity::Warning,
                        path: format!("{}.mode", typing_path),
                        message: format!("typing mode should be \"thinking\", got \"{}\"", mode),
                    });
                }
            } else if let Some(mode) = typing_obj.get("mode") {
                issues.push(SchemaIssue {
                    severity: Severity::Warning,
                    path: format!("{}.mode", typing_path),
                    message: format!(
                        "typing mode must be a string, got {}",
                        json_type_label(mode)
                    ),
                });
            }

            if let Some(interval) = typing_obj.get("intervalSeconds") {
                check_positive_integer(
                    interval,
                    &format!("{}.intervalSeconds", typing_path),
                    issues,
                );
            }
        } else {
            issues.push(SchemaIssue {
                severity: Severity::Warning,
                path: typing_path,
                message: format!(
                    "typing feature config must be an object, got {}",
                    json_type_label(typing)
                ),
            });
        }
    }

    if let Some(read_receipts) = features_obj.get("readReceipts") {
        let read_receipts_path = format!("{}.readReceipts", path);
        if let Some(read_receipts_obj) = read_receipts.as_object() {
            for key in read_receipts_obj.keys() {
                if !matches!(key.as_str(), "enabled" | "mode") {
                    issues.push(SchemaIssue {
                        severity: Severity::Warning,
                        path: format!("{}.{}", read_receipts_path, key),
                        message: format!("unknown readReceipts feature key '{}'", key),
                    });
                }
            }
            if let Some(enabled) = read_receipts_obj.get("enabled") {
                if !enabled.is_boolean() {
                    issues.push(SchemaIssue {
                        severity: Severity::Warning,
                        path: format!("{}.enabled", read_receipts_path),
                        message: "readReceipts enabled must be a boolean".to_string(),
                    });
                }
            }

            if let Some(mode) = read_receipts_obj
                .get("mode")
                .and_then(|value| value.as_str())
            {
                if mode != "after-response" {
                    issues.push(SchemaIssue {
                        severity: Severity::Warning,
                        path: format!("{}.mode", read_receipts_path),
                        message: format!(
                            "readReceipts mode should be \"after-response\", got \"{}\"",
                            mode
                        ),
                    });
                }
            } else if let Some(mode) = read_receipts_obj.get("mode") {
                issues.push(SchemaIssue {
                    severity: Severity::Warning,
                    path: format!("{}.mode", read_receipts_path),
                    message: format!(
                        "readReceipts mode must be a string, got {}",
                        json_type_label(mode)
                    ),
                });
            }
        } else {
            issues.push(SchemaIssue {
                severity: Severity::Warning,
                path: read_receipts_path,
                message: format!(
                    "readReceipts feature config must be an object, got {}",
                    json_type_label(read_receipts)
                ),
            });
        }
    }
}

fn validate_hooks(obj: &serde_json::Map<String, Value>, issues: &mut Vec<SchemaIssue>) {
    if obj.get("hooks").is_some() {
        issues.push(SchemaIssue {
            severity: Severity::Error,
            path: ".hooks".to_string(),
            message: "hooks must be configured under gateway.hooks".to_string(),
        });
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

fn validate_auth(obj: &serde_json::Map<String, Value>, issues: &mut Vec<SchemaIssue>) {
    let auth = match obj.get("auth").and_then(|v| v.as_object()) {
        Some(a) => a,
        None => return,
    };

    let profiles = match auth.get("profiles").and_then(|v| v.as_object()) {
        Some(p) => p,
        None => return,
    };

    if let Some(enabled) = profiles.get("enabled") {
        if !enabled.is_boolean() {
            issues.push(SchemaIssue {
                severity: Severity::Warning,
                path: ".auth.profiles.enabled".to_string(),
                message: "enabled must be a boolean".to_string(),
            });
        }
    }

    if let Some(redirect_base_url) = profiles.get("redirectBaseUrl") {
        if !redirect_base_url.is_string() {
            issues.push(SchemaIssue {
                severity: Severity::Warning,
                path: ".auth.profiles.redirectBaseUrl".to_string(),
                message: "redirectBaseUrl must be a string".to_string(),
            });
        }
    }

    let providers = match profiles.get("providers").and_then(|v| v.as_object()) {
        Some(p) => p,
        None => return,
    };

    for provider_key in ["google", "github", "discord", "openai"] {
        let provider = match providers.get(provider_key).and_then(|v| v.as_object()) {
            Some(p) => p,
            None => continue,
        };
        for field in ["clientId", "clientSecret", "redirectUri"] {
            if let Some(value) = provider.get(field) {
                if !value.is_string() {
                    issues.push(SchemaIssue {
                        severity: Severity::Warning,
                        path: format!(".auth.profiles.providers.{provider_key}.{field}"),
                        message: format!("{field} must be a string"),
                    });
                }
            }
        }
    }
}

fn validate_google(obj: &serde_json::Map<String, Value>, issues: &mut Vec<SchemaIssue>) {
    let google = match obj.get("google").and_then(|v| v.as_object()) {
        Some(g) => g,
        None => return,
    };

    for (field, path) in [
        ("apiKey", ".google.apiKey"),
        ("baseUrl", ".google.baseUrl"),
        ("authProfile", ".google.authProfile"),
    ] {
        if let Some(value) = google.get(field) {
            if !value.is_string() {
                issues.push(SchemaIssue {
                    severity: Severity::Warning,
                    path: path.to_string(),
                    message: format!("{field} must be a string"),
                });
            }
        }
    }

    let api_key = google
        .get("apiKey")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|v| !v.is_empty());
    let auth_profile = google
        .get("authProfile")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|v| !v.is_empty());

    if api_key.is_some() && auth_profile.is_some() {
        issues.push(SchemaIssue {
            severity: Severity::Warning,
            path: ".google".to_string(),
            message: "configure either google.apiKey or google.authProfile, not both".to_string(),
        });
    }

    if auth_profile.is_some() {
        let auth_profiles_enabled = obj
            .get("auth")
            .and_then(|v| v.get("profiles"))
            .and_then(|v| v.get("enabled"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if !auth_profiles_enabled {
            issues.push(SchemaIssue {
                severity: Severity::Warning,
                path: ".google.authProfile".to_string(),
                message: "google.authProfile requires auth.profiles.enabled = true".to_string(),
            });
        }
    }
}

fn validate_codex(obj: &serde_json::Map<String, Value>, issues: &mut Vec<SchemaIssue>) {
    let codex = match obj.get("codex").and_then(|v| v.as_object()) {
        Some(c) => c,
        None => return,
    };

    if let Some(value) = codex.get("authProfile") {
        if !value.is_string() {
            issues.push(SchemaIssue {
                severity: Severity::Warning,
                path: ".codex.authProfile".to_string(),
                message: "authProfile must be a string".to_string(),
            });
        }
    }

    let auth_profile = codex
        .get("authProfile")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|v| !v.is_empty());

    if auth_profile.is_some() {
        let auth_profiles_enabled = obj
            .get("auth")
            .and_then(|v| v.get("profiles"))
            .and_then(|v| v.get("enabled"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if !auth_profiles_enabled {
            issues.push(SchemaIssue {
                severity: Severity::Warning,
                path: ".codex.authProfile".to_string(),
                message: "codex.authProfile requires auth.profiles.enabled = true".to_string(),
            });
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
    let timeout_seconds = defaults.get("timeoutSeconds");
    let timeout_legacy = defaults.get("timeout");

    if let Some(v) = timeout_seconds {
        check_positive_integer(v, ".agents.defaults.timeoutSeconds", issues);
    }
    if let Some(v) = timeout_legacy {
        check_positive_integer(v, ".agents.defaults.timeout", issues);
    }
    if timeout_seconds.is_some() && timeout_legacy.is_some() {
        issues.push(SchemaIssue {
            severity: Severity::Warning,
            path: ".agents.defaults.timeout".to_string(),
            message:
                "Both agents.defaults.timeoutSeconds and agents.defaults.timeout are set; timeoutSeconds takes precedence and timeout is legacy and should be removed"
                    .to_string(),
        });
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

    if let Some(typing_mode) = legacy_session.and_then(|s| s.get("typingMode")) {
        match typing_mode.as_str() {
            Some(mode) if mode.eq_ignore_ascii_case("thinking") => {}
            Some(mode) => issues.push(SchemaIssue {
                severity: Severity::Warning,
                path: ".session.typingMode".to_string(),
                message: format!("typingMode must be \"thinking\", got \"{}\"", mode),
            }),
            None => issues.push(SchemaIssue {
                severity: Severity::Warning,
                path: ".session.typingMode".to_string(),
                message: "typingMode must be a string".to_string(),
            }),
        }
    }

    if let Some(typing_interval) = legacy_session.and_then(|s| s.get("typingIntervalSeconds")) {
        check_positive_integer(typing_interval, ".session.typingIntervalSeconds", issues);
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
    let (prompt_guard_key, pg) = match obj.get("agents").and_then(prompt_guard_entry) {
        Some(entry) => entry,
        None => return,
    };
    let prompt_guard_path = format!(".agents.{}", prompt_guard_key);

    if let Some(enabled) = pg.get("enabled") {
        validate_enabled_bool(
            enabled,
            &format!("{prompt_guard_path}.enabled"),
            Severity::Warning,
            issues,
        );
    }

    // Validate sub-sections have boolean enabled fields.
    for section in &["preflight", "tagging", "postflight"] {
        if let Some(sub) = pg.get(*section).and_then(|v| v.as_object()) {
            if let Some(enabled) = sub.get("enabled") {
                validate_enabled_bool(
                    enabled,
                    &format!("{prompt_guard_path}.{section}.enabled"),
                    Severity::Warning,
                    issues,
                );
            }
        }
    }

    if let Some(sub) = pg.get("config_lint").and_then(|v| v.as_object()) {
        if let Some(enabled) = sub.get("enabled") {
            validate_enabled_bool(
                enabled,
                &format!("{prompt_guard_path}.config_lint.enabled"),
                Severity::Warning,
                issues,
            );
        }
    }

    if let Some(_legacy_config_lint) = pg.get("configLint") {
        issues.push(SchemaIssue {
            severity: Severity::Error,
            path: format!("{prompt_guard_path}.configLint"),
            message: "configLint is a legacy key; use config_lint".to_string(),
        });
    }
}

fn prompt_guard_obj(agents: &Value) -> Option<&serde_json::Map<String, Value>> {
    prompt_guard_entry(agents).map(|(_, value)| value)
}

fn prompt_guard_entry(agents: &Value) -> Option<(&'static str, &serde_json::Map<String, Value>)> {
    // `promptGuard` remains the canonical form. If both keys are present,
    // prefer it and ignore the legacy/alternate snake_case wrapper.
    agents
        .get("promptGuard")
        .and_then(|v| v.as_object())
        .map(|v| ("promptGuard", v))
        .or_else(|| {
            agents
                .get("prompt_guard")
                .and_then(|v| v.as_object())
                .map(|v| ("prompt_guard", v))
        })
}

fn prompt_guard_config_lint_obj(
    prompt_guard: &serde_json::Map<String, Value>,
) -> Option<&serde_json::Map<String, Value>> {
    // The lint-enable path intentionally resolves only the canonical key.
    prompt_guard.get("config_lint").and_then(|v| v.as_object())
}

fn validate_enabled_bool(
    enabled: &Value,
    path: &str,
    severity: Severity,
    issues: &mut Vec<SchemaIssue>,
) {
    if !enabled.is_boolean() {
        issues.push(SchemaIssue {
            severity,
            path: path.to_string(),
            message: "enabled must be a boolean".to_string(),
        });
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

fn validate_plugins_signature(obj: &serde_json::Map<String, Value>, issues: &mut Vec<SchemaIssue>) {
    let sig = match obj
        .get("plugins")
        .and_then(|s| s.get("signature"))
        .and_then(|v| v.as_object())
    {
        Some(s) => s,
        None => return,
    };

    if let Some(enabled) = sig.get("enabled") {
        if !enabled.is_boolean() {
            issues.push(SchemaIssue {
                severity: Severity::Error,
                path: ".plugins.signature.enabled".to_string(),
                message: "enabled must be a boolean".to_string(),
            });
        }
    }

    if let Some(require) = sig.get("requireSignature") {
        if !require.is_boolean() {
            issues.push(SchemaIssue {
                severity: Severity::Error,
                path: ".plugins.signature.requireSignature".to_string(),
                message: "requireSignature must be a boolean".to_string(),
            });
        }
    }

    if let Some(publishers) = sig.get("trustedPublishers") {
        if !publishers.is_array() {
            issues.push(SchemaIssue {
                severity: Severity::Warning,
                path: ".plugins.signature.trustedPublishers".to_string(),
                message: "trustedPublishers must be an array".to_string(),
            });
        }
    }
}

fn validate_plugins_sandbox(obj: &serde_json::Map<String, Value>, issues: &mut Vec<SchemaIssue>) {
    let sandbox = match obj
        .get("plugins")
        .and_then(|s| s.get("sandbox"))
        .and_then(|v| v.as_object())
    {
        Some(s) => s,
        None => return,
    };

    if let Some(enabled) = sandbox.get("enabled") {
        if !enabled.is_boolean() {
            issues.push(SchemaIssue {
                severity: Severity::Error,
                path: ".plugins.sandbox.enabled".to_string(),
                message: "enabled must be a boolean".to_string(),
            });
        }
    }

    if let Some(defaults) = sandbox.get("defaults").and_then(|v| v.as_object()) {
        for key in &["allowHttp", "allowCredentials", "allowMedia"] {
            if let Some(val) = defaults.get(*key) {
                if !val.is_boolean() {
                    issues.push(SchemaIssue {
                        severity: Severity::Error,
                        path: format!(".plugins.sandbox.defaults.{}", key),
                        message: format!("{} must be a boolean", key),
                    });
                }
            }
        }
    }
}

fn validate_plugins(obj: &serde_json::Map<String, Value>, issues: &mut Vec<SchemaIssue>) {
    let Some(plugins_value) = obj.get("plugins") else {
        return;
    };
    let plugins = match plugins_value.as_object() {
        Some(plugins) => plugins,
        None => {
            issues.push(SchemaIssue {
                severity: Severity::Error,
                path: ".plugins".to_string(),
                message: "plugins must be an object".to_string(),
            });
            return;
        }
    };

    if let Some(enabled) = plugins.get("enabled") {
        if !enabled.is_boolean() {
            issues.push(SchemaIssue {
                severity: Severity::Error,
                path: ".plugins.enabled".to_string(),
                message: "plugins.enabled must be a boolean".to_string(),
            });
        }
    }

    if let Some(entries) = plugins.get("entries") {
        let Some(entries_obj) = entries.as_object() else {
            issues.push(SchemaIssue {
                severity: Severity::Error,
                path: ".plugins.entries".to_string(),
                message: "plugins.entries must be an object".to_string(),
            });
            return;
        };

        for (name, entry) in entries_obj {
            if is_reserved_plugin_id(name) {
                issues.push(SchemaIssue {
                    severity: Severity::Error,
                    path: format!(".plugins.entries.{name}"),
                    message: format!(
                        "managed plugin name '{}' is reserved for plugin configuration",
                        name
                    ),
                });
            }

            let Some(entry_obj) = entry.as_object() else {
                issues.push(SchemaIssue {
                    severity: Severity::Error,
                    path: format!(".plugins.entries.{name}"),
                    message: "managed plugin entry must be an object".to_string(),
                });
                continue;
            };

            for field in entry_obj.keys() {
                if !matches!(field.as_str(), "enabled" | "installId" | "requestedAt") {
                    issues.push(SchemaIssue {
                        severity: Severity::Error,
                        path: format!(".plugins.entries.{name}.{field}"),
                        message: format!(
                            "unknown managed plugin field '{}'; plugin runtime config belongs under plugins.<plugin-id>.*, and reserved top-level plugin keys are {}",
                            field,
                            RESERVED_PLUGIN_CONFIG_KEYS.join(", ")
                        ),
                    });
                }
            }
        }
    }

    let Some(load) = plugins.get("load") else {
        return;
    };
    let Some(load_obj) = load.as_object() else {
        issues.push(SchemaIssue {
            severity: Severity::Error,
            path: ".plugins.load".to_string(),
            message: "plugins.load must be an object".to_string(),
        });
        return;
    };

    if let Some(paths) = load_obj.get("paths") {
        let Some(array) = paths.as_array() else {
            issues.push(SchemaIssue {
                severity: Severity::Error,
                path: ".plugins.load.paths".to_string(),
                message: "plugins.load.paths must be an array".to_string(),
            });
            return;
        };
        if array.iter().any(|value| !value.is_string()) {
            issues.push(SchemaIssue {
                severity: Severity::Error,
                path: ".plugins.load.paths".to_string(),
                message: "plugins.load.paths entries must be strings".to_string(),
            });
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
                severity: Severity::Error,
                path: ".sessions.integrity.enabled".to_string(),
                message: "enabled must be a boolean".to_string(),
            });
        }
    }

    if let Some(action) = integrity.get("action").and_then(|v| v.as_str()) {
        let valid = ["warn", "reject"];
        if !valid.contains(&action) {
            issues.push(SchemaIssue {
                severity: Severity::Error,
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

fn validate_vertex(obj: &serde_json::Map<String, Value>, issues: &mut Vec<SchemaIssue>) {
    let vertex = match obj.get("vertex").and_then(|v| v.as_object()) {
        Some(v) => v,
        None => return,
    };

    if let Some(project_id) = vertex.get("projectId") {
        if !project_id.is_string() {
            issues.push(SchemaIssue {
                severity: Severity::Error,
                path: ".vertex.projectId".to_string(),
                message: "projectId must be a string".to_string(),
            });
        }
    }

    if let Some(location) = vertex.get("location") {
        if !location.is_string() {
            issues.push(SchemaIssue {
                severity: Severity::Error,
                path: ".vertex.location".to_string(),
                message: "location must be a string".to_string(),
            });
        }
    }

    if let Some(model) = vertex.get("model") {
        if !model.is_string() {
            issues.push(SchemaIssue {
                severity: Severity::Error,
                path: ".vertex.model".to_string(),
                message: "model must be a string".to_string(),
            });
        }
    }
}

fn validate_filesystem(obj: &serde_json::Map<String, Value>, issues: &mut Vec<SchemaIssue>) {
    let filesystem = match obj.get("filesystem") {
        Some(value) => value,
        None => return,
    };
    let fs_cfg = match filesystem.as_object() {
        Some(f) => f,
        None => {
            issues.push(SchemaIssue {
                severity: Severity::Error,
                path: ".filesystem".to_string(),
                message: format!(
                    "filesystem configuration must be an object, got {}",
                    json_type_label(filesystem)
                ),
            });
            return;
        }
    };

    let enabled = match fs_cfg.get("enabled") {
        Some(Value::Bool(enabled)) => *enabled,
        Some(other) => {
            issues.push(SchemaIssue {
                severity: Severity::Error,
                path: ".filesystem.enabled".to_string(),
                message: format!(
                    "filesystem enabled must be a boolean, got {}",
                    json_type_label(other)
                ),
            });
            false
        }
        None => false,
    };

    // Known keys inside filesystem block
    let known_keys = [
        "enabled",
        "roots",
        "writeAccess",
        "maxReadBytes",
        "excludePatterns",
    ];
    for key in fs_cfg.keys() {
        if !known_keys.contains(&key.as_str()) {
            issues.push(SchemaIssue {
                severity: Severity::Warning,
                path: format!(".filesystem.{}", key),
                message: format!("Unknown filesystem configuration key: {}", key),
            });
        }
    }

    if let Some(write_access) = fs_cfg.get("writeAccess") {
        if !write_access.is_boolean() {
            issues.push(SchemaIssue {
                severity: Severity::Error,
                path: ".filesystem.writeAccess".to_string(),
                message: format!(
                    "filesystem writeAccess must be a boolean, got {}",
                    json_type_label(write_access)
                ),
            });
        }
    }

    if let Some(max_read_bytes) = fs_cfg.get("maxReadBytes") {
        if !max_read_bytes.is_u64() {
            issues.push(SchemaIssue {
                severity: Severity::Error,
                path: ".filesystem.maxReadBytes".to_string(),
                message: format!(
                    "filesystem maxReadBytes must be a non-negative integer, got {}",
                    json_type_label(max_read_bytes)
                ),
            });
        }
    }

    // Skip deeper validation if disabled
    if !enabled {
        return;
    }

    let roots = match fs_cfg.get("roots") {
        Some(value) if !value.is_array() => {
            issues.push(SchemaIssue {
                severity: Severity::Error,
                path: ".filesystem.roots".to_string(),
                message: format!(
                    "filesystem roots must be an array, got {}",
                    json_type_label(value)
                ),
            });
            None
        }
        Some(value) => value.as_array(),
        None => None,
    };

    let is_empty = roots.is_none_or(|a| a.is_empty());
    if is_empty {
        issues.push(SchemaIssue {
            severity: Severity::Warning,
            path: ".filesystem.roots".to_string(),
            message: "filesystem is enabled but roots is empty; all paths will be denied"
                .to_string(),
        });
    }

    if let Some(arr) = roots {
        for (i, root) in arr.iter().enumerate() {
            if let Some(s) = root.as_str() {
                let path = std::path::Path::new(s);
                if !path.is_absolute() {
                    issues.push(SchemaIssue {
                        severity: Severity::Error,
                        path: format!(".filesystem.roots[{}]", i),
                        message: format!("filesystem root must be an absolute path, got \"{}\"", s),
                    });
                } else if !path.exists() {
                    issues.push(SchemaIssue {
                        severity: Severity::Error,
                        path: format!(".filesystem.roots[{}]", i),
                        message: format!("filesystem root does not exist: \"{}\"", s),
                    });
                }
            } else {
                issues.push(SchemaIssue {
                    severity: Severity::Error,
                    path: format!(".filesystem.roots[{}]", i),
                    message: format!(
                        "filesystem root must be a string, got {}",
                        json_type_label(root)
                    ),
                });
            }
        }
    }

    // Validate excludePatterns syntax
    let patterns = match fs_cfg.get("excludePatterns") {
        Some(value) if !value.is_array() => {
            issues.push(SchemaIssue {
                severity: Severity::Error,
                path: ".filesystem.excludePatterns".to_string(),
                message: format!(
                    "filesystem excludePatterns must be an array, got {}",
                    json_type_label(value)
                ),
            });
            None
        }
        Some(value) => value.as_array(),
        None => None,
    };
    if let Some(patterns) = patterns {
        for (i, pat) in patterns.iter().enumerate() {
            if let Some(s) = pat.as_str() {
                if glob::Pattern::new(s).is_err() {
                    issues.push(SchemaIssue {
                        severity: Severity::Error,
                        path: format!(".filesystem.excludePatterns[{}]", i),
                        message: format!(
                            "invalid glob pattern \"{}\"; fix or remove it (invalid \
                             patterns cause startup failure to prevent silent access widening)",
                            s
                        ),
                    });
                }
            } else {
                issues.push(SchemaIssue {
                    severity: Severity::Error,
                    path: format!(".filesystem.excludePatterns[{}]", i),
                    message: format!(
                        "exclude pattern must be a string, got {}",
                        json_type_label(pat)
                    ),
                });
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Return a human-readable label for a JSON value's type.
fn json_type_label(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

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
            "gateway": {
                "port": 18789,
                "bind": "loopback",
                "hooks": { "enabled": true, "maxBodyBytes": 262144 }
            },
            "logging": { "level": "info", "format": "json" }
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
    fn test_hooks_root_is_error() {
        let cfg = json!({ "hooks": { "enabled": true } });
        let issues = validate_schema(&cfg);
        assert!(issues
            .iter()
            .any(|i| i.path == ".hooks" && i.severity == Severity::Error));
    }

    #[test]
    fn test_vertex_config_valid() {
        let cfg = json!({
            "vertex": {
                "projectId": "my-project",
                "location": "us-central1",
                "model": "gemini-2.0-flash"
            }
        });
        let issues = validate_schema(&cfg);
        assert!(!issues.iter().any(|i| i.path.starts_with(".vertex")));
    }

    #[test]
    fn test_vertex_project_id_must_be_string() {
        let cfg = json!({ "vertex": { "projectId": 123 } });
        let issues = validate_schema(&cfg);
        assert!(issues.iter().any(|i| i.path == ".vertex.projectId"));
    }

    #[test]
    fn test_vertex_location_must_be_string() {
        let cfg = json!({ "vertex": { "location": 123 } });
        let issues = validate_schema(&cfg);
        assert!(issues.iter().any(|i| i.path == ".vertex.location"));
    }

    #[test]
    fn test_vertex_model_must_be_string() {
        let cfg = json!({ "vertex": { "model": 123 } });
        let issues = validate_schema(&cfg);
        assert!(issues.iter().any(|i| i.path == ".vertex.model"));
    }

    #[test]
    fn test_google_auth_profile_requires_auth_profiles_enabled() {
        let cfg = json!({
            "google": { "authProfile": "google-abc123" },
            "auth": { "profiles": { "enabled": false } }
        });
        let issues = validate_schema(&cfg);
        assert!(issues.iter().any(
            |i| i.path == ".google.authProfile" && i.message.contains("auth.profiles.enabled")
        ));
    }

    #[test]
    fn test_google_api_key_and_auth_profile_warn() {
        let cfg = json!({
            "google": {
                "apiKey": "${GOOGLE_API_KEY}",
                "authProfile": "google-abc123"
            },
            "auth": { "profiles": { "enabled": true } }
        });
        let issues = validate_schema(&cfg);
        assert!(issues.iter().any(|i| i.path == ".google"
            && i.message
                .contains("either google.apiKey or google.authProfile")));
    }

    #[test]
    fn test_codex_auth_profile_requires_auth_profiles_enabled() {
        let cfg = json!({
            "codex": { "authProfile": "openai-abc123" },
            "auth": { "profiles": { "enabled": false } }
        });
        let issues = validate_schema(&cfg);
        assert!(
            issues
                .iter()
                .any(|i| i.path == ".codex.authProfile"
                    && i.message.contains("auth.profiles.enabled"))
        );
    }

    #[test]
    fn test_codex_auth_profile_must_be_string() {
        let cfg = json!({
            "codex": { "authProfile": 123 }
        });
        let issues = validate_schema(&cfg);
        assert!(issues.iter().any(|i| i.path == ".codex.authProfile"));
    }

    #[test]
    fn test_auth_profiles_provider_secret_must_be_string() {
        let cfg = json!({
            "auth": {
                "profiles": {
                    "enabled": true,
                    "providers": {
                        "google": {
                            "clientId": "abc",
                            "clientSecret": 123
                        }
                    }
                }
            }
        });
        let issues = validate_schema(&cfg);
        assert!(issues
            .iter()
            .any(|i| i.path == ".auth.profiles.providers.google.clientSecret"));
    }

    #[test]
    fn test_auth_profiles_openai_provider_secret_must_be_string() {
        let cfg = json!({
            "auth": {
                "profiles": {
                    "enabled": true,
                    "providers": {
                        "openai": {
                            "clientId": "abc",
                            "clientSecret": 123
                        }
                    }
                }
            }
        });
        let issues = validate_schema(&cfg);
        assert!(issues
            .iter()
            .any(|i| i.path == ".auth.profiles.providers.openai.clientSecret"));
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
        let cfg = json!({ "agents": { "defaults": { "maxConcurrent": 5, "timeoutSeconds": 60, "contextTokens": 8000 } } });
        let issues = validate_schema(&cfg);
        assert!(
            !issues
                .iter()
                .any(|i| i.path.starts_with(".agents.defaults")),
            "Expected no issues for agents.defaults, but found: {:?}",
            issues
        );
    }

    #[test]
    fn test_agents_defaults_timeout_legacy_alias_valid() {
        let cfg = json!({ "agents": { "defaults": { "timeout": 60 } } });
        let issues = validate_schema(&cfg);
        assert!(
            !issues
                .iter()
                .any(|i| i.path.starts_with(".agents.defaults")),
            "Expected no issues for agents.defaults, but found: {:?}",
            issues
        );
    }

    #[test]
    fn test_agents_defaults_warns_when_both_timeout_keys_are_set() {
        let cfg = json!({ "agents": { "defaults": { "timeoutSeconds": 60, "timeout": 30 } } });
        let issues = validate_schema(&cfg);
        assert!(issues.iter().any(|i| i.path == ".agents.defaults.timeout"));
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

    #[test]
    fn test_prompt_guard_config_lint_camel_case_rejected() {
        let cfg = json!({
            "agents": {
                "promptGuard": {
                    "configLint": {
                        "enabled": true
                    }
                }
            }
        });
        let issues = validate_schema(&cfg);
        assert!(issues.iter().any(|i| {
            i.path == ".agents.promptGuard.configLint"
                && i.severity == Severity::Error
                && i.message.contains("use config_lint")
        }));
    }

    #[test]
    fn test_prompt_guard_config_lint_snake_case_valid() {
        let cfg = json!({
            "agents": {
                "promptGuard": {
                    "config_lint": {
                        "enabled": true
                    }
                }
            }
        });
        let issues = validate_schema(&cfg);
        assert!(
            !issues
                .iter()
                .any(|i| i.path.starts_with(".agents.promptGuard.config_lint")),
            "Expected no config_lint issues, but found: {:?}",
            issues
        );
    }

    #[test]
    fn test_prompt_guard_config_lint_snake_case_enabled_must_be_bool() {
        let cfg = json!({
            "agents": {
                "promptGuard": {
                    "config_lint": {
                        "enabled": "true"
                    }
                }
            }
        });
        let issues = validate_schema(&cfg);
        assert!(issues
            .iter()
            .any(|i| i.path == ".agents.promptGuard.config_lint.enabled"));
    }

    #[test]
    fn test_prompt_guard_config_lint_snake_case_triggers_lint_checks() {
        let cfg = json!({
            "agents": {
                "promptGuard": {
                    "config_lint": {
                        "enabled": true
                    }
                },
                "list": [{
                    "toolPolicy": "AllowAll"
                }]
            }
        });
        let issues = validate_schema(&cfg);
        assert!(issues
            .iter()
            .any(|i| i.path == ".agents.list[0].toolPolicy"));
        assert!(issues.iter().any(|i| i.path == ".agents.list[0].maxTokens"));
        assert!(issues.iter().any(|i| i.path == ".agents.list[0].model"));
    }

    #[test]
    fn test_prompt_guard_config_lint_camel_case_does_not_trigger_lint_checks() {
        let cfg = json!({
            "agents": {
                "promptGuard": {
                    "configLint": {
                        "enabled": true
                    }
                },
                "list": [{
                    "toolPolicy": "AllowAll"
                }]
            }
        });
        let issues = validate_schema(&cfg);
        assert!(issues.iter().any(|i| {
            i.path == ".agents.promptGuard.configLint" && i.severity == Severity::Error
        }));
        assert!(!issues.iter().any(|i| i.path.starts_with(".agents.list[0]")));
    }

    #[test]
    fn test_prompt_guard_snake_case_paths_reflect_variant() {
        let cfg = json!({
            "agents": {
                "prompt_guard": {
                    "enabled": "true",
                    "configLint": {
                        "enabled": "true"
                    }
                }
            }
        });
        let issues = validate_schema(&cfg);
        assert!(issues
            .iter()
            .any(|i| i.path == ".agents.prompt_guard.enabled"));
        assert!(issues
            .iter()
            .any(|i| i.path == ".agents.prompt_guard.configLint"));
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

    #[test]
    fn test_channels_features_valid() {
        let cfg = json!({
            "channels": {
                "defaults": {
                    "features": {
                        "typing": {
                            "enabled": true,
                            "mode": "thinking",
                            "intervalSeconds": 3
                        },
                        "readReceipts": {
                            "enabled": false,
                            "mode": "after-response"
                        }
                    }
                },
                "signal": {
                    "features": {
                        "typing": {
                            "enabled": false,
                            "intervalSeconds": 7
                        },
                        "readReceipts": {
                            "enabled": true,
                            "mode": "after-response"
                        }
                    }
                }
            }
        });
        let issues = validate_schema(&cfg);
        assert!(
            !issues
                .iter()
                .any(|issue| issue.path.starts_with(".channels")),
            "unexpected channel issues: {:?}",
            issues
        );
    }

    #[test]
    fn test_channels_features_invalid_values_warn() {
        let cfg = json!({
            "channels": {
                "signal": {
                    "features": {
                        "typing": {
                            "enabled": "yes",
                            "mode": "forever",
                            "intervalSeconds": 0
                        },
                        "readReceipts": {
                            "enabled": "yes",
                            "mode": "on-receive"
                        }
                    }
                }
            }
        });
        let issues = validate_schema(&cfg);
        assert!(issues
            .iter()
            .any(|issue| issue.path == ".channels.signal.features.typing.enabled"));
        assert!(issues
            .iter()
            .any(|issue| issue.path == ".channels.signal.features.typing.mode"));
        assert!(issues
            .iter()
            .any(|issue| issue.path == ".channels.signal.features.typing.intervalSeconds"));
        assert!(issues
            .iter()
            .any(|issue| issue.path == ".channels.signal.features.readReceipts.enabled"));
        assert!(issues
            .iter()
            .any(|issue| issue.path == ".channels.signal.features.readReceipts.mode"));
    }

    #[test]
    fn test_unknown_channel_config_entry_is_accepted_for_forward_compatibility() {
        let cfg = json!({
            "channels": {
                "matrix": {
                    "features": {
                        "typing": {
                            "enabled": true
                        }
                    }
                }
            }
        });
        let issues = validate_schema(&cfg);
        assert!(
            !issues.iter().any(|issue| issue.path == ".channels.matrix"),
            "unexpected channel-id warning for forward-compatible entry: {:?}",
            issues
        );
    }

    #[test]
    fn test_builtin_channel_typo_warns_with_suggestion() {
        let cfg = json!({
            "channels": {
                "singal": {
                    "features": {
                        "typing": {
                            "enabled": true
                        }
                    }
                }
            }
        });
        let issues = validate_schema(&cfg);
        assert!(issues.iter().any(|issue| {
            issue.path == ".channels.singal" && issue.message.contains("did you mean 'signal'?")
        }));
    }

    #[test]
    fn test_unknown_channel_entry_key_warns() {
        let cfg = json!({
            "channels": {
                "signal": {
                    "feautres": {
                        "typing": {
                            "enabled": true
                        }
                    }
                }
            }
        });
        let issues = validate_schema(&cfg);
        assert!(issues.iter().any(|issue| {
            issue.path == ".channels.signal.feautres"
                && issue.message.contains("unknown channel config key")
        }));
    }

    #[test]
    fn test_channels_container_type_warns() {
        let cfg = json!({
            "channels": []
        });
        let issues = validate_schema(&cfg);
        assert!(issues.iter().any(|issue| {
            issue.path == ".channels" && issue.message.contains("channels must be an object")
        }));
    }

    #[test]
    fn test_legacy_session_typing_mode_warns_on_unknown_value() {
        let cfg = json!({
            "session": {
                "typingMode": "thinkng"
            }
        });
        let issues = validate_schema(&cfg);
        assert!(issues
            .iter()
            .any(|issue| issue.path == ".session.typingMode"
                && issue.message.contains("typingMode must be \"thinking\"")));
    }

    #[test]
    fn test_channels_features_invalid_typing_shape_still_validates_read_receipts() {
        let cfg = json!({
            "channels": {
                "signal": {
                    "features": {
                        "typing": true,
                        "readReceipts": {
                            "enabled": "yes",
                            "mode": "on-receive"
                        }
                    }
                }
            }
        });
        let issues = validate_schema(&cfg);
        assert!(issues
            .iter()
            .any(|issue| issue.path == ".channels.signal.features.typing"));
        assert!(issues
            .iter()
            .any(|issue| issue.path == ".channels.signal.features.readReceipts.enabled"));
        assert!(issues
            .iter()
            .any(|issue| issue.path == ".channels.signal.features.readReceipts.mode"));
    }

    #[test]
    fn test_channels_features_unknown_keys_warn() {
        let cfg = json!({
            "channels": {
                "signal": {
                    "features": {
                        "readReceipt": {
                            "enabled": true
                        },
                        "typing": {
                            "enabled": true,
                            "intervalSecond": 5
                        },
                        "readReceipts": {
                            "enabled": true,
                            "extra": true
                        }
                    }
                }
            }
        });
        let issues = validate_schema(&cfg);
        assert!(issues.iter().any(
            |issue| issue.path == ".channels.signal.features.readReceipt"
                && issue.message.contains("unknown channel feature")
        ));
        assert!(issues.iter().any(|issue| issue.path
            == ".channels.signal.features.typing.intervalSecond"
            && issue.message.contains("unknown typing feature key")));
        assert!(issues.iter().any(|issue| issue.path
            == ".channels.signal.features.readReceipts.extra"
            && issue.message.contains("unknown readReceipts feature key")));
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

    // ===== Filesystem validation =====

    fn test_filesystem_root() -> tempfile::TempDir {
        tempfile::TempDir::new().unwrap()
    }

    fn nonexistent_filesystem_root() -> String {
        loop {
            let dir = tempfile::TempDir::new().unwrap();
            let path = dir.path().to_path_buf();
            drop(dir);
            if !path.exists() {
                return path.to_string_lossy().into_owned();
            }
        }
    }

    #[test]
    fn test_filesystem_valid_config() {
        let root = test_filesystem_root();
        let config = json!({
            "filesystem": {
                "enabled": true,
                "roots": [root.path().to_str().unwrap()],
                "writeAccess": false
            }
        });
        let issues = validate_schema(&config);
        assert!(
            !issues.iter().any(|i| i.severity == Severity::Error),
            "unexpected errors: {:?}",
            issues
        );
    }

    #[test]
    fn test_filesystem_enabled_no_roots_warns() {
        let config = json!({
            "filesystem": {
                "enabled": true,
                "roots": []
            }
        });
        let issues = validate_schema(&config);
        assert!(issues.iter().any(|i| i.severity == Severity::Warning
            && i.path.contains("filesystem")
            && i.message.contains("roots")));
    }

    #[test]
    fn test_filesystem_relative_path_is_error() {
        let config = json!({
            "filesystem": {
                "enabled": true,
                "roots": ["relative/path"]
            }
        });
        let issues = validate_schema(&config);
        assert!(issues.iter().any(|i| i.severity == Severity::Error
            && i.path.contains("roots")
            && i.message.contains("absolute")));
    }

    #[test]
    fn test_filesystem_nonexistent_path_is_error() {
        let missing_root = nonexistent_filesystem_root();
        let config = json!({
            "filesystem": {
                "enabled": true,
                "roots": [missing_root]
            }
        });
        let issues = validate_schema(&config);
        assert!(issues
            .iter()
            .any(|i| i.severity == Severity::Error && i.message.contains("does not exist")));
    }

    #[test]
    fn test_filesystem_unknown_key_warns() {
        let root = test_filesystem_root();
        let config = json!({
            "filesystem": {
                "enabled": true,
                "roots": [root.path().to_str().unwrap()],
                "unknownSetting": true
            }
        });
        let issues = validate_schema(&config);
        assert!(issues
            .iter()
            .any(|i| i.severity == Severity::Warning && i.message.contains("unknownSetting")));
    }

    #[test]
    fn test_filesystem_invalid_exclude_pattern_is_error() {
        let root = test_filesystem_root();
        let config = json!({
            "filesystem": {
                "enabled": true,
                "roots": [root.path().to_str().unwrap()],
                "excludePatterns": ["[invalid"]
            }
        });
        let issues = validate_schema(&config);
        assert!(issues.iter().any(|i| i.severity == Severity::Error
            && i.path.contains("excludePatterns")
            && i.message.contains("invalid glob pattern")));
    }

    #[test]
    fn test_filesystem_disabled_skips_validation() {
        let config = json!({
            "filesystem": {
                "enabled": false,
                "roots": ["not-absolute"]
            }
        });
        let issues = validate_schema(&config);
        // Should not produce errors when disabled
        assert!(!issues.iter().any(|i| i.severity == Severity::Error));
    }

    #[test]
    fn test_filesystem_non_string_root_is_error() {
        let config = json!({
            "filesystem": {
                "enabled": true,
                "roots": [42, true]
            }
        });
        let issues = validate_schema(&config);
        let errors: Vec<_> = issues
            .iter()
            .filter(|i| i.severity == Severity::Error && i.path.contains("roots"))
            .collect();
        assert_eq!(errors.len(), 2, "should flag both non-string roots");
        assert!(errors[0].message.contains("must be a string"));
    }

    #[test]
    fn test_filesystem_non_string_exclude_pattern_is_error() {
        let root = test_filesystem_root();
        let config = json!({
            "filesystem": {
                "enabled": true,
                "roots": [root.path().to_str().unwrap()],
                "excludePatterns": ["*.log", 123]
            }
        });
        let issues = validate_schema(&config);
        let errors: Vec<_> = issues
            .iter()
            .filter(|i| i.severity == Severity::Error && i.path.contains("excludePatterns"))
            .collect();
        assert_eq!(errors.len(), 1, "should flag the non-string pattern");
        assert!(errors[0].message.contains("must be a string"));
    }

    #[test]
    fn test_filesystem_invalid_enabled_type_is_error() {
        let config = json!({
            "filesystem": {
                "enabled": "yes",
                "roots": []
            }
        });
        let issues = validate_schema(&config);
        assert!(issues.iter().any(|i| {
            i.severity == Severity::Error
                && i.path == ".filesystem.enabled"
                && i.message.contains("must be a boolean")
        }));
    }

    #[test]
    fn test_filesystem_invalid_write_access_type_is_error() {
        let root = test_filesystem_root();
        let config = json!({
            "filesystem": {
                "enabled": true,
                "roots": [root.path().to_str().unwrap()],
                "writeAccess": "yes"
            }
        });
        let issues = validate_schema(&config);
        assert!(issues.iter().any(|i| {
            i.severity == Severity::Error
                && i.path == ".filesystem.writeAccess"
                && i.message.contains("must be a boolean")
        }));
    }

    #[test]
    fn test_filesystem_invalid_max_read_bytes_type_is_error() {
        let root = test_filesystem_root();
        let config = json!({
            "filesystem": {
                "enabled": true,
                "roots": [root.path().to_str().unwrap()],
                "maxReadBytes": "lots"
            }
        });
        let issues = validate_schema(&config);
        assert!(issues.iter().any(|i| {
            i.severity == Severity::Error
                && i.path == ".filesystem.maxReadBytes"
                && i.message.contains("must be a non-negative integer")
        }));
    }

    #[test]
    fn test_filesystem_roots_non_array_is_error() {
        let config = json!({
            "filesystem": {
                "enabled": true,
                "roots": "/tmp"
            }
        });
        let issues = validate_schema(&config);
        assert!(issues.iter().any(|i| {
            i.severity == Severity::Error
                && i.path == ".filesystem.roots"
                && i.message.contains("must be an array")
        }));
    }

    #[test]
    fn test_filesystem_exclude_patterns_non_array_is_error() {
        let root = test_filesystem_root();
        let config = json!({
            "filesystem": {
                "enabled": true,
                "roots": [root.path().to_str().unwrap()],
                "excludePatterns": "*.log"
            }
        });
        let issues = validate_schema(&config);
        assert!(issues.iter().any(|i| {
            i.severity == Severity::Error
                && i.path == ".filesystem.excludePatterns"
                && i.message.contains("must be an array")
        }));
    }

    #[test]
    fn test_filesystem_non_object_is_error() {
        let config = json!({
            "filesystem": true
        });
        let issues = validate_schema(&config);
        assert!(issues.iter().any(|i| {
            i.severity == Severity::Error
                && i.path == ".filesystem"
                && i.message.contains("must be an object")
        }));
    }

    #[test]
    fn test_plugins_config_valid() {
        let config = json!({
            "plugins": {
                "enabled": true,
                "load": {
                    "paths": ["/tmp/plugins", "/opt/carapace/plugins"]
                }
            }
        });
        let issues = validate_schema(&config);
        assert!(!issues.iter().any(|i| i.path.starts_with(".plugins")));
    }

    #[test]
    fn test_plugins_enabled_must_be_boolean() {
        let config = json!({
            "plugins": {
                "enabled": "yes"
            }
        });
        let issues = validate_schema(&config);
        assert!(issues.iter().any(|i| {
            i.severity == Severity::Error
                && i.path == ".plugins.enabled"
                && i.message.contains("must be a boolean")
        }));
    }

    #[test]
    fn test_plugins_must_be_object() {
        let config = json!({
            "plugins": "yes"
        });
        let issues = validate_schema(&config);
        assert!(issues.iter().any(|i| {
            i.severity == Severity::Error
                && i.path == ".plugins"
                && i.message.contains("must be an object")
        }));
    }

    #[test]
    fn test_plugins_load_paths_must_be_array_of_strings() {
        let config = json!({
            "plugins": {
                "load": {
                    "paths": ["/tmp/plugins", 42]
                }
            }
        });
        let issues = validate_schema(&config);
        assert!(issues.iter().any(|i| {
            i.severity == Severity::Error
                && i.path == ".plugins.load.paths"
                && i.message.contains("entries must be strings")
        }));
    }

    #[test]
    fn test_plugins_entries_must_be_managed_entry_objects() {
        let config = json!({
            "plugins": {
                "entries": {
                    "demo": {
                        "apiKey": "${DEMO_API_KEY}"
                    }
                }
            }
        });
        let issues = validate_schema(&config);
        assert!(issues.iter().any(|i| {
            i.severity == Severity::Error
                && i.path == ".plugins.entries.demo.apiKey"
                && i.message
                    .contains("plugin runtime config belongs under plugins.<plugin-id>.*")
        }));
    }

    #[test]
    fn test_plugins_entries_reject_reserved_names() {
        let config = json!({
            "plugins": {
                "entries": {
                    "entries": {
                        "enabled": true
                    }
                }
            }
        });
        let issues = validate_schema(&config);
        assert!(issues.iter().any(|i| {
            i.severity == Severity::Error
                && i.path == ".plugins.entries.entries"
                && i.message.contains("reserved for plugin configuration")
        }));
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
