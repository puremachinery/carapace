//! Config defaults application
//!
//! Merges user-provided config with sane defaults so that partial configs work
//! correctly. Ported from clawdbot's `src/config/defaults.ts` apply* functions.
//!
//! The top-level entry point is [`apply_defaults`], which takes a raw
//! `serde_json::Value` (the JSON5-parsed config) and fills in any missing
//! sections/fields with production-ready defaults.
//!
//! Design:
//! - We use typed structs with `#[serde(default)]` so that serde fills in
//!   missing fields automatically during deserialization.
//! - For cross-field logic (e.g., deriving one default from another), we use
//!   a post-deserialization `apply_defaults()` method.
//! - The result is serialized back to `Value` so existing code that reads raw
//!   JSON values continues to work.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::debug;

// ---------------------------------------------------------------------------
// Top-level typed config (only the sections that need defaults)
// ---------------------------------------------------------------------------

/// Top-level config with all sections that receive defaults.
///
/// Sections not listed here pass through unchanged.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ConfigWithDefaults {
    #[serde(default)]
    gateway: GatewayDefaults,

    #[serde(default)]
    agents: AgentsDefaults,

    #[serde(default)]
    session: SessionDefaults,

    #[serde(default)]
    logging: LoggingDefaults,

    #[serde(default)]
    cron: CronDefaults,

    #[serde(default)]
    hooks: HooksDefaults,

    #[serde(default)]
    messages: MessagesDefaults,
}

// ---------------------------------------------------------------------------
// Gateway / Server defaults
// ---------------------------------------------------------------------------

/// Default gateway port (matches clawdbot & bind.rs).
const DEFAULT_GATEWAY_PORT: u16 = 18789;

/// Default bind mode.
const DEFAULT_BIND_MODE: &str = "loopback";

/// Default reload mode.
const DEFAULT_RELOAD_MODE: &str = "hybrid";

/// Default reload debounce (ms).
const DEFAULT_RELOAD_DEBOUNCE_MS: u32 = 300;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GatewayDefaults {
    #[serde(default = "default_gateway_port")]
    port: u16,

    #[serde(default = "default_bind_mode")]
    bind: String,

    #[serde(default)]
    reload: GatewayReloadDefaults,

    #[serde(default)]
    control_ui: GatewayControlUiDefaults,
}

impl Default for GatewayDefaults {
    fn default() -> Self {
        Self {
            port: default_gateway_port(),
            bind: default_bind_mode(),
            reload: GatewayReloadDefaults::default(),
            control_ui: GatewayControlUiDefaults::default(),
        }
    }
}

fn default_gateway_port() -> u16 {
    DEFAULT_GATEWAY_PORT
}
fn default_bind_mode() -> String {
    DEFAULT_BIND_MODE.to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GatewayReloadDefaults {
    #[serde(default = "default_reload_mode")]
    mode: String,

    #[serde(default = "default_reload_debounce_ms")]
    debounce_ms: u32,
}

impl Default for GatewayReloadDefaults {
    fn default() -> Self {
        Self {
            mode: default_reload_mode(),
            debounce_ms: default_reload_debounce_ms(),
        }
    }
}

fn default_reload_mode() -> String {
    DEFAULT_RELOAD_MODE.to_string()
}
fn default_reload_debounce_ms() -> u32 {
    DEFAULT_RELOAD_DEBOUNCE_MS
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[derive(Default)]
struct GatewayControlUiDefaults {
    #[serde(default)]
    enabled: bool,

    #[serde(default)]
    allow_insecure_auth: bool,
}

// ---------------------------------------------------------------------------
// Agent defaults
// ---------------------------------------------------------------------------

/// Default max concurrent agent runs (from clawdbot agent-limits.ts).
const DEFAULT_AGENT_MAX_CONCURRENT: u32 = 4;

/// Default max concurrent sub-agent runs.
const DEFAULT_SUBAGENT_MAX_CONCURRENT: u32 = 8;

/// Default agent timeout in seconds.
const DEFAULT_AGENT_TIMEOUT_SECONDS: u32 = 300;

/// Default context window size in tokens.
const DEFAULT_CONTEXT_TOKENS: u32 = 200_000;

/// Default thinking level.
const DEFAULT_THINKING: &str = "off";

/// Default verbose level.
const DEFAULT_VERBOSE: &str = "off";

/// Default block streaming.
const DEFAULT_BLOCK_STREAMING: &str = "off";

/// Default compaction mode (from clawdbot defaults.ts).
const DEFAULT_COMPACTION_MODE: &str = "safeguard";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[derive(Default)]
struct AgentsDefaults {
    #[serde(default)]
    defaults: AgentDefaultsSection,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AgentDefaultsSection {
    #[serde(default = "default_agent_max_concurrent")]
    max_concurrent: u32,

    #[serde(default = "default_agent_timeout_seconds")]
    timeout_seconds: u32,

    #[serde(default = "default_context_tokens")]
    context_tokens: u32,

    #[serde(default = "default_thinking")]
    thinking_default: String,

    #[serde(default = "default_verbose")]
    verbose_default: String,

    #[serde(default = "default_block_streaming")]
    block_streaming_default: String,

    #[serde(default)]
    subagents: SubagentDefaults,

    #[serde(default)]
    compaction: CompactionDefaults,
}

impl Default for AgentDefaultsSection {
    fn default() -> Self {
        Self {
            max_concurrent: default_agent_max_concurrent(),
            timeout_seconds: default_agent_timeout_seconds(),
            context_tokens: default_context_tokens(),
            thinking_default: default_thinking(),
            verbose_default: default_verbose(),
            block_streaming_default: default_block_streaming(),
            subagents: SubagentDefaults::default(),
            compaction: CompactionDefaults::default(),
        }
    }
}

fn default_agent_max_concurrent() -> u32 {
    DEFAULT_AGENT_MAX_CONCURRENT
}
fn default_agent_timeout_seconds() -> u32 {
    DEFAULT_AGENT_TIMEOUT_SECONDS
}
fn default_context_tokens() -> u32 {
    DEFAULT_CONTEXT_TOKENS
}
fn default_thinking() -> String {
    DEFAULT_THINKING.to_string()
}
fn default_verbose() -> String {
    DEFAULT_VERBOSE.to_string()
}
fn default_block_streaming() -> String {
    DEFAULT_BLOCK_STREAMING.to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SubagentDefaults {
    #[serde(default = "default_subagent_max_concurrent")]
    max_concurrent: u32,

    #[serde(default = "default_subagent_archive_after_minutes")]
    archive_after_minutes: u32,
}

impl Default for SubagentDefaults {
    fn default() -> Self {
        Self {
            max_concurrent: default_subagent_max_concurrent(),
            archive_after_minutes: default_subagent_archive_after_minutes(),
        }
    }
}

fn default_subagent_max_concurrent() -> u32 {
    DEFAULT_SUBAGENT_MAX_CONCURRENT
}
fn default_subagent_archive_after_minutes() -> u32 {
    60
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CompactionDefaults {
    #[serde(default = "default_compaction_mode")]
    mode: String,
}

impl Default for CompactionDefaults {
    fn default() -> Self {
        Self {
            mode: default_compaction_mode(),
        }
    }
}

fn default_compaction_mode() -> String {
    DEFAULT_COMPACTION_MODE.to_string()
}

// ---------------------------------------------------------------------------
// Session defaults
// ---------------------------------------------------------------------------

/// Default session scope.
const DEFAULT_SESSION_SCOPE: &str = "per-sender";

/// Default DM scope.
const DEFAULT_DM_SCOPE: &str = "main";

/// Default typing mode.
const DEFAULT_TYPING_MODE: &str = "thinking";

/// Default typing interval in seconds.
const DEFAULT_TYPING_INTERVAL_SECONDS: u32 = 3;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SessionDefaults {
    #[serde(default = "default_session_scope")]
    scope: String,

    #[serde(default = "default_dm_scope")]
    dm_scope: String,

    #[serde(default = "default_typing_mode")]
    typing_mode: String,

    #[serde(default = "default_typing_interval_seconds")]
    typing_interval_seconds: u32,

    /// The mainKey is always "main" (clawdbot enforces this).
    #[serde(default = "default_main_key")]
    main_key: String,
}

impl Default for SessionDefaults {
    fn default() -> Self {
        Self {
            scope: default_session_scope(),
            dm_scope: default_dm_scope(),
            typing_mode: default_typing_mode(),
            typing_interval_seconds: default_typing_interval_seconds(),
            main_key: default_main_key(),
        }
    }
}

fn default_session_scope() -> String {
    DEFAULT_SESSION_SCOPE.to_string()
}
fn default_dm_scope() -> String {
    DEFAULT_DM_SCOPE.to_string()
}
fn default_typing_mode() -> String {
    DEFAULT_TYPING_MODE.to_string()
}
fn default_typing_interval_seconds() -> u32 {
    DEFAULT_TYPING_INTERVAL_SECONDS
}
fn default_main_key() -> String {
    "main".to_string()
}

// ---------------------------------------------------------------------------
// Logging defaults
// ---------------------------------------------------------------------------

/// Default log level.
const DEFAULT_LOG_LEVEL: &str = "info";

/// Default console style.
const DEFAULT_CONSOLE_STYLE: &str = "pretty";

/// Default redact mode (from clawdbot applyLoggingDefaults).
const DEFAULT_REDACT_SENSITIVE: &str = "tools";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LoggingDefaults {
    #[serde(default = "default_log_level")]
    level: String,

    #[serde(default = "default_console_style")]
    console_style: String,

    #[serde(default = "default_redact_sensitive")]
    redact_sensitive: String,
}

impl Default for LoggingDefaults {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            console_style: default_console_style(),
            redact_sensitive: default_redact_sensitive(),
        }
    }
}

fn default_log_level() -> String {
    DEFAULT_LOG_LEVEL.to_string()
}
fn default_console_style() -> String {
    DEFAULT_CONSOLE_STYLE.to_string()
}
fn default_redact_sensitive() -> String {
    DEFAULT_REDACT_SENSITIVE.to_string()
}

// ---------------------------------------------------------------------------
// Cron defaults
// ---------------------------------------------------------------------------

/// Default max concurrent cron runs.
const DEFAULT_CRON_MAX_CONCURRENT: u32 = 2;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CronDefaults {
    #[serde(default)]
    enabled: bool,

    #[serde(default = "default_cron_max_concurrent")]
    max_concurrent_runs: u32,
}

impl Default for CronDefaults {
    fn default() -> Self {
        Self {
            enabled: false,
            max_concurrent_runs: default_cron_max_concurrent(),
        }
    }
}

fn default_cron_max_concurrent() -> u32 {
    DEFAULT_CRON_MAX_CONCURRENT
}

// ---------------------------------------------------------------------------
// Hooks defaults
// ---------------------------------------------------------------------------

/// Default max body bytes for hooks (256 KB).
const DEFAULT_HOOKS_MAX_BODY_BYTES: u32 = 262_144;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct HooksDefaults {
    #[serde(default)]
    enabled: bool,

    #[serde(default = "default_hooks_path")]
    path: String,

    #[serde(default = "default_hooks_max_body_bytes")]
    max_body_bytes: u32,
}

impl Default for HooksDefaults {
    fn default() -> Self {
        Self {
            enabled: false,
            path: default_hooks_path(),
            max_body_bytes: default_hooks_max_body_bytes(),
        }
    }
}

fn default_hooks_path() -> String {
    "/hooks".to_string()
}
fn default_hooks_max_body_bytes() -> u32 {
    DEFAULT_HOOKS_MAX_BODY_BYTES
}

// ---------------------------------------------------------------------------
// Messages defaults
// ---------------------------------------------------------------------------

/// Default ack reaction scope (from clawdbot applyMessageDefaults).
const DEFAULT_ACK_REACTION_SCOPE: &str = "group-mentions";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct MessagesDefaults {
    #[serde(default = "default_ack_reaction_scope")]
    ack_reaction_scope: String,
}

impl Default for MessagesDefaults {
    fn default() -> Self {
        Self {
            ack_reaction_scope: default_ack_reaction_scope(),
        }
    }
}

fn default_ack_reaction_scope() -> String {
    DEFAULT_ACK_REACTION_SCOPE.to_string()
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Apply production-ready defaults to a raw config `Value`.
///
/// This function:
/// 1. Deserializes known sections into typed structs (which fill missing fields
///    via `#[serde(default)]`).
/// 2. Serializes those structs back.
/// 3. Deep-merges the defaults *under* the original value so user-provided
///    values always win.
///
/// Sections not covered by the typed structs pass through untouched.
pub fn apply_defaults(config: &mut Value) {
    if !config.is_object() {
        *config = Value::Object(serde_json::Map::new());
    }

    // Deserialize into typed struct — missing fields get defaults.
    let with_defaults: ConfigWithDefaults = match serde_json::from_value(config.clone()) {
        Ok(v) => v,
        Err(e) => {
            debug!("config defaults: deserialization failed, using all defaults: {e}");
            ConfigWithDefaults {
                gateway: GatewayDefaults::default(),
                agents: AgentsDefaults::default(),
                session: SessionDefaults::default(),
                logging: LoggingDefaults::default(),
                cron: CronDefaults::default(),
                hooks: HooksDefaults::default(),
                messages: MessagesDefaults::default(),
            }
        }
    };

    // Serialize the defaulted structs back to Value.
    let defaults_value = serde_json::to_value(&with_defaults).unwrap_or_default();

    // Deep-merge: defaults go *under* user values (user wins).
    merge_defaults(config, defaults_value);

    // Post-merge cross-field fixups: enforce session.mainKey = "main".
    if let Some(session) = config.get_mut("session").and_then(|v| v.as_object_mut()) {
        if let Some(mk) = session.get("mainKey").and_then(|v| v.as_str()) {
            if mk != "main" {
                debug!("session.mainKey is ignored; main session is always \"main\". Was: {mk:?}");
            }
        }
        session.insert("mainKey".to_string(), Value::String("main".to_string()));
    }
}

/// Deep-merge `defaults` into `target`.
///
/// - For objects: recursively merge; keys in `target` are preserved (user wins).
/// - For all other types: `target` keeps its value if present.
fn merge_defaults(target: &mut Value, defaults: Value) {
    if let (Value::Object(target_obj), Value::Object(defaults_obj)) = (target, defaults) {
        for (key, default_value) in defaults_obj {
            match target_obj.get_mut(&key) {
                Some(existing) => {
                    // Recurse into nested objects.
                    merge_defaults(existing, default_value);
                }
                None => {
                    // Key missing in target — insert the default.
                    target_obj.insert(key, default_value);
                }
            }
        }
    }
    // target already has a non-object value — user wins, keep it.
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    #[allow(clippy::cognitive_complexity)]
    fn test_empty_config_gets_all_defaults() {
        let mut config = json!({});
        apply_defaults(&mut config);

        // Gateway defaults
        assert_eq!(config["gateway"]["port"], DEFAULT_GATEWAY_PORT);
        assert_eq!(config["gateway"]["bind"], DEFAULT_BIND_MODE);
        assert_eq!(config["gateway"]["reload"]["mode"], DEFAULT_RELOAD_MODE);
        assert_eq!(
            config["gateway"]["reload"]["debounceMs"],
            DEFAULT_RELOAD_DEBOUNCE_MS
        );
        assert_eq!(config["gateway"]["controlUi"]["enabled"], false);

        // Agent defaults
        assert_eq!(
            config["agents"]["defaults"]["maxConcurrent"],
            DEFAULT_AGENT_MAX_CONCURRENT
        );
        assert_eq!(
            config["agents"]["defaults"]["timeoutSeconds"],
            DEFAULT_AGENT_TIMEOUT_SECONDS
        );
        assert_eq!(
            config["agents"]["defaults"]["contextTokens"],
            DEFAULT_CONTEXT_TOKENS
        );
        assert_eq!(
            config["agents"]["defaults"]["thinkingDefault"],
            DEFAULT_THINKING
        );
        assert_eq!(
            config["agents"]["defaults"]["verboseDefault"],
            DEFAULT_VERBOSE
        );
        assert_eq!(
            config["agents"]["defaults"]["blockStreamingDefault"],
            DEFAULT_BLOCK_STREAMING
        );
        assert_eq!(
            config["agents"]["defaults"]["subagents"]["maxConcurrent"],
            DEFAULT_SUBAGENT_MAX_CONCURRENT
        );
        assert_eq!(
            config["agents"]["defaults"]["subagents"]["archiveAfterMinutes"],
            60
        );
        assert_eq!(
            config["agents"]["defaults"]["compaction"]["mode"],
            DEFAULT_COMPACTION_MODE
        );

        // Session defaults
        assert_eq!(config["session"]["scope"], DEFAULT_SESSION_SCOPE);
        assert_eq!(config["session"]["dmScope"], DEFAULT_DM_SCOPE);
        assert_eq!(config["session"]["typingMode"], DEFAULT_TYPING_MODE);
        assert_eq!(
            config["session"]["typingIntervalSeconds"],
            DEFAULT_TYPING_INTERVAL_SECONDS
        );
        assert_eq!(config["session"]["mainKey"], "main");

        // Logging defaults
        assert_eq!(config["logging"]["level"], DEFAULT_LOG_LEVEL);
        assert_eq!(config["logging"]["consoleStyle"], DEFAULT_CONSOLE_STYLE);
        assert_eq!(
            config["logging"]["redactSensitive"],
            DEFAULT_REDACT_SENSITIVE
        );

        // Cron defaults
        assert_eq!(config["cron"]["enabled"], false);
        assert_eq!(
            config["cron"]["maxConcurrentRuns"],
            DEFAULT_CRON_MAX_CONCURRENT
        );

        // Hooks defaults
        assert_eq!(config["hooks"]["enabled"], false);
        assert_eq!(config["hooks"]["path"], "/hooks");
        assert_eq!(
            config["hooks"]["maxBodyBytes"],
            DEFAULT_HOOKS_MAX_BODY_BYTES
        );

        // Messages defaults
        assert_eq!(
            config["messages"]["ackReactionScope"],
            DEFAULT_ACK_REACTION_SCOPE
        );
    }

    #[test]
    fn test_user_values_preserved() {
        let mut config = json!({
            "gateway": {
                "port": 9999,
                "bind": "lan"
            },
            "agents": {
                "defaults": {
                    "maxConcurrent": 16,
                    "timeoutSeconds": 600
                }
            },
            "logging": {
                "level": "debug"
            },
            "cron": {
                "enabled": true,
                "maxConcurrentRuns": 10
            }
        });

        apply_defaults(&mut config);

        // User values preserved
        assert_eq!(config["gateway"]["port"], 9999);
        assert_eq!(config["gateway"]["bind"], "lan");
        assert_eq!(config["agents"]["defaults"]["maxConcurrent"], 16);
        assert_eq!(config["agents"]["defaults"]["timeoutSeconds"], 600);
        assert_eq!(config["logging"]["level"], "debug");
        assert_eq!(config["cron"]["enabled"], true);
        assert_eq!(config["cron"]["maxConcurrentRuns"], 10);

        // Defaults filled in for missing fields
        assert_eq!(config["gateway"]["reload"]["mode"], DEFAULT_RELOAD_MODE);
        assert_eq!(
            config["agents"]["defaults"]["contextTokens"],
            DEFAULT_CONTEXT_TOKENS
        );
        assert_eq!(
            config["agents"]["defaults"]["subagents"]["maxConcurrent"],
            DEFAULT_SUBAGENT_MAX_CONCURRENT
        );
        assert_eq!(config["logging"]["consoleStyle"], DEFAULT_CONSOLE_STYLE);
        assert_eq!(
            config["logging"]["redactSensitive"],
            DEFAULT_REDACT_SENSITIVE
        );
    }

    #[test]
    fn test_session_main_key_enforced() {
        let mut config = json!({
            "session": {
                "mainKey": "custom-key"
            }
        });

        apply_defaults(&mut config);

        // mainKey is always forced to "main"
        assert_eq!(config["session"]["mainKey"], "main");
        // Other session defaults filled in
        assert_eq!(config["session"]["scope"], DEFAULT_SESSION_SCOPE);
    }

    #[test]
    fn test_partial_nested_config_preserved() {
        let mut config = json!({
            "agents": {
                "defaults": {
                    "subagents": {
                        "maxConcurrent": 2
                    }
                }
            }
        });

        apply_defaults(&mut config);

        // User sub-value preserved
        assert_eq!(
            config["agents"]["defaults"]["subagents"]["maxConcurrent"],
            2
        );
        // Missing sub-value filled in
        assert_eq!(
            config["agents"]["defaults"]["subagents"]["archiveAfterMinutes"],
            60
        );
        // Missing parent-level defaults filled in
        assert_eq!(
            config["agents"]["defaults"]["maxConcurrent"],
            DEFAULT_AGENT_MAX_CONCURRENT
        );
    }

    #[test]
    fn test_non_object_config_replaced_with_defaults() {
        let mut config = json!("not an object");
        apply_defaults(&mut config);

        // Should have been replaced with an object containing defaults
        assert!(config.is_object());
        assert_eq!(config["gateway"]["port"], DEFAULT_GATEWAY_PORT);
    }

    #[test]
    fn test_null_config_gets_defaults() {
        let mut config = Value::Null;
        apply_defaults(&mut config);

        assert!(config.is_object());
        assert_eq!(config["gateway"]["port"], DEFAULT_GATEWAY_PORT);
    }

    #[test]
    fn test_unknown_keys_pass_through() {
        let mut config = json!({
            "customPlugin": {
                "apiKey": "secret",
                "mode": "advanced"
            },
            "gateway": {
                "port": 12345
            }
        });

        apply_defaults(&mut config);

        // Custom keys preserved
        assert_eq!(config["customPlugin"]["apiKey"], "secret");
        assert_eq!(config["customPlugin"]["mode"], "advanced");

        // User value preserved
        assert_eq!(config["gateway"]["port"], 12345);

        // Defaults still filled
        assert_eq!(config["gateway"]["bind"], DEFAULT_BIND_MODE);
    }

    #[test]
    fn test_deeply_nested_defaults() {
        let mut config = json!({
            "gateway": {
                "reload": {
                    "mode": "hot"
                }
            }
        });

        apply_defaults(&mut config);

        // User value preserved
        assert_eq!(config["gateway"]["reload"]["mode"], "hot");
        // Missing sibling filled
        assert_eq!(
            config["gateway"]["reload"]["debounceMs"],
            DEFAULT_RELOAD_DEBOUNCE_MS
        );
        // Missing parent-level fields filled
        assert_eq!(config["gateway"]["port"], DEFAULT_GATEWAY_PORT);
        assert_eq!(config["gateway"]["bind"], DEFAULT_BIND_MODE);
    }

    #[test]
    fn test_merge_defaults_does_not_overwrite_existing() {
        let mut target = json!({
            "a": 1,
            "nested": {
                "b": 2
            }
        });

        let defaults = json!({
            "a": 999,
            "nested": {
                "b": 999,
                "c": 3
            },
            "new_key": "hello"
        });

        merge_defaults(&mut target, defaults);

        assert_eq!(target["a"], 1); // preserved
        assert_eq!(target["nested"]["b"], 2); // preserved
        assert_eq!(target["nested"]["c"], 3); // added
        assert_eq!(target["new_key"], "hello"); // added
    }

    #[test]
    fn test_hooks_defaults_applied() {
        let mut config = json!({
            "hooks": {
                "enabled": true
            }
        });

        apply_defaults(&mut config);

        assert_eq!(config["hooks"]["enabled"], true);
        assert_eq!(config["hooks"]["path"], "/hooks");
        assert_eq!(
            config["hooks"]["maxBodyBytes"],
            DEFAULT_HOOKS_MAX_BODY_BYTES
        );
    }

    #[test]
    fn test_messages_defaults_applied() {
        let mut config = json!({});
        apply_defaults(&mut config);

        assert_eq!(
            config["messages"]["ackReactionScope"],
            DEFAULT_ACK_REACTION_SCOPE
        );
    }

    #[test]
    fn test_compaction_defaults_applied() {
        let mut config = json!({
            "agents": {
                "defaults": {}
            }
        });

        apply_defaults(&mut config);

        assert_eq!(
            config["agents"]["defaults"]["compaction"]["mode"],
            DEFAULT_COMPACTION_MODE
        );
    }

    #[test]
    fn test_realistic_minimal_config() {
        // A realistic minimal config that a user might provide
        let mut config = json!({
            "anthropic": {
                "apiKey": "sk-ant-test"
            },
            "gateway": {
                "auth": {
                    "mode": "token",
                    "token": "my-secret-token"
                }
            }
        });

        apply_defaults(&mut config);

        // User keys preserved
        assert_eq!(config["anthropic"]["apiKey"], "sk-ant-test");
        assert_eq!(config["gateway"]["auth"]["mode"], "token");
        assert_eq!(config["gateway"]["auth"]["token"], "my-secret-token");

        // All critical defaults present
        assert_eq!(config["gateway"]["port"], DEFAULT_GATEWAY_PORT);
        assert_eq!(config["gateway"]["bind"], DEFAULT_BIND_MODE);
        assert_eq!(
            config["agents"]["defaults"]["maxConcurrent"],
            DEFAULT_AGENT_MAX_CONCURRENT
        );
        assert_eq!(
            config["agents"]["defaults"]["timeoutSeconds"],
            DEFAULT_AGENT_TIMEOUT_SECONDS
        );
        assert_eq!(config["session"]["scope"], DEFAULT_SESSION_SCOPE);
        assert_eq!(config["session"]["mainKey"], "main");
        assert_eq!(config["logging"]["level"], DEFAULT_LOG_LEVEL);
        assert_eq!(
            config["logging"]["redactSensitive"],
            DEFAULT_REDACT_SENSITIVE
        );
        assert_eq!(config["cron"]["enabled"], false);
        assert_eq!(config["hooks"]["enabled"], false);
    }
}
