//! Session scoping and automatic reset rules.
//!
//! In multi-user, multi-channel deployments each incoming message must be
//! routed to the correct session. The **scope** determines *which* session key
//! to use, and the **reset policy** determines *when* a session should be
//! automatically cleared (archived) and a fresh one started.
//!
//! ## Scoping modes
//!
//! | Mode              | Key format                      | Use case                          |
//! |-------------------|---------------------------------|-----------------------------------|
//! | `per-sender`      | `{channel}:{sender_id}`         | Each sender has their own session |
//! | `global`          | `{channel}:global`              | One shared session per channel    |
//! | `per-channel-peer`| `{channel}:{peer_id}`           | Session per channel+peer combo    |
//!
//! ## Reset policies
//!
//! | Policy   | Behaviour                                              |
//! |----------|--------------------------------------------------------|
//! | `manual` | Never auto-reset                                       |
//! | `daily`  | Reset at midnight UTC each day                         |
//! | `idle`   | Reset after N minutes of inactivity (default 60)       |
//!
//! Both the scope and the reset policy are configurable per channel via:
//!
//! ```json5
//! channels: {
//!   my_channel: {
//!     session: {
//!       scope: "per-sender",       // or "global", "per-channel-peer"
//!       reset: {
//!         mode: "idle",            // or "manual", "daily"
//!         idleMinutes: 30,
//!       }
//!     }
//!   }
//! }
//! ```

use chrono::{TimeZone, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

// ---------------------------------------------------------------------------
// Session scope
// ---------------------------------------------------------------------------

/// Determines how an incoming message is mapped to a session key.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SessionScope {
    /// Each sender gets their own session.
    /// Key = `{channel}:{sender_id}`
    #[default]
    PerSender,
    /// All messages in a channel share one session.
    /// Key = `{channel}:global`
    Global,
    /// Each channel+peer combo gets its own session.
    /// Key = `{channel}:{peer_id}`
    PerChannelPeer,
}

impl std::fmt::Display for SessionScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PerSender => write!(f, "per-sender"),
            Self::Global => write!(f, "global"),
            Self::PerChannelPeer => write!(f, "per-channel-peer"),
        }
    }
}

impl SessionScope {
    /// Parse a scope string, returning `None` for unrecognised values.
    pub fn from_str_opt(s: &str) -> Option<Self> {
        match s {
            "per-sender" => Some(Self::PerSender),
            "global" => Some(Self::Global),
            "per-channel-peer" => Some(Self::PerChannelPeer),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Session reset policy
// ---------------------------------------------------------------------------

/// Default idle timeout in minutes when mode is `idle` but no value is given.
pub const DEFAULT_IDLE_MINUTES: u32 = 60;

/// Determines when a session should be automatically cleared and recreated.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "kebab-case")]
pub enum SessionResetPolicy {
    /// Never auto-reset; the session lives until explicitly cleared.
    #[default]
    Manual,
    /// Reset at midnight UTC each day. Any session whose `updated_at` falls
    /// before today's midnight is eligible for reset.
    Daily,
    /// Reset after `minutes` of inactivity. A session whose `updated_at` is
    /// more than `minutes` ago is eligible for reset.
    Idle { minutes: u32 },
}

impl std::fmt::Display for SessionResetPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Manual => write!(f, "manual"),
            Self::Daily => write!(f, "daily"),
            Self::Idle { minutes } => write!(f, "idle({}m)", minutes),
        }
    }
}

// ---------------------------------------------------------------------------
// Session scoping configuration (per-channel)
// ---------------------------------------------------------------------------

/// Per-channel session configuration, typically read from
/// `channels.{name}.session` in the config file.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ChannelSessionConfig {
    pub scope: SessionScope,
    pub reset: SessionResetPolicy,
}

impl ChannelSessionConfig {
    /// Parse a `ChannelSessionConfig` from a JSON value.
    ///
    /// Expected shape:
    /// ```json5
    /// {
    ///   scope: "per-sender",
    ///   reset: { mode: "idle", idleMinutes: 30 }
    /// }
    /// ```
    ///
    /// All fields are optional; missing fields fall back to defaults.
    pub fn from_value(value: &Value) -> Self {
        let scope = value
            .get("scope")
            .and_then(|v| v.as_str())
            .and_then(SessionScope::from_str_opt)
            .unwrap_or_default();

        let reset = match value.get("reset") {
            Some(reset_val) => parse_reset_policy(reset_val),
            None => SessionResetPolicy::default(),
        };

        Self { scope, reset }
    }

    /// Extract `ChannelSessionConfig` from the full config for a given channel.
    ///
    /// Looks up `channels.{channel_name}.session` and parses it. Falls back
    /// to the global `session.scope` default when the channel has no override.
    pub fn from_config(config: &Value, channel_name: &str) -> Self {
        // Try channel-specific config first
        if let Some(channel_session) = config
            .get("channels")
            .and_then(|c| c.get(channel_name))
            .and_then(|ch| ch.get("session"))
        {
            return Self::from_value(channel_session);
        }

        // Fall back to global session.scope (no reset at global level)
        let scope = config
            .get("session")
            .and_then(|s| s.get("scope"))
            .and_then(|v| v.as_str())
            .and_then(SessionScope::from_str_opt)
            .unwrap_or_default();

        Self {
            scope,
            reset: SessionResetPolicy::default(),
        }
    }
}

/// Parse a reset policy from its JSON representation.
fn parse_reset_policy(value: &Value) -> SessionResetPolicy {
    let mode = value
        .get("mode")
        .and_then(|v| v.as_str())
        .unwrap_or("manual");

    match mode {
        "daily" => SessionResetPolicy::Daily,
        "idle" => {
            let minutes = value
                .get("idleMinutes")
                .and_then(|v| v.as_u64())
                .map(|v| v as u32)
                .unwrap_or(DEFAULT_IDLE_MINUTES);
            SessionResetPolicy::Idle { minutes }
        }
        _ => SessionResetPolicy::Manual,
    }
}

// ---------------------------------------------------------------------------
// Session key resolution
// ---------------------------------------------------------------------------

/// Resolve the session key for an incoming message based on the scoping mode.
///
/// # Arguments
///
/// * `channel` - Name of the channel the message arrived on
/// * `sender_id` - Identity of the message sender
/// * `peer_id` - Identity of the peer / conversation partner (may be same as
///   sender in DMs, or a group ID for group chats)
/// * `scope` - The scoping mode to apply
///
/// # Returns
///
/// A deterministic session key string.
pub fn resolve_session_key(
    channel: &str,
    sender_id: &str,
    peer_id: &str,
    scope: SessionScope,
) -> String {
    match scope {
        SessionScope::PerSender => format!("{}:{}", channel, sender_id),
        SessionScope::Global => format!("{}:global", channel),
        SessionScope::PerChannelPeer => format!("{}:{}", channel, peer_id),
    }
}

// ---------------------------------------------------------------------------
// Reset enforcement
// ---------------------------------------------------------------------------

/// Check whether a session should be reset according to the given policy.
///
/// The decision is based on the session's `updated_at` timestamp (Unix
/// milliseconds) compared to the current time.
///
/// # Arguments
///
/// * `updated_at_ms` - The session's `updated_at` field (Unix milliseconds)
/// * `policy` - The reset policy to evaluate
///
/// # Returns
///
/// `true` if the session should be archived and a fresh one created.
pub fn should_reset_session(updated_at_ms: i64, policy: &SessionResetPolicy) -> bool {
    should_reset_session_at(updated_at_ms, policy, Utc::now().timestamp_millis())
}

/// Testable version of [`should_reset_session`] that accepts an explicit
/// "current time" parameter (Unix milliseconds).
pub fn should_reset_session_at(
    updated_at_ms: i64,
    policy: &SessionResetPolicy,
    now_ms: i64,
) -> bool {
    match policy {
        SessionResetPolicy::Manual => false,

        SessionResetPolicy::Daily => {
            // Find midnight UTC for the current day.
            let now_dt = match Utc.timestamp_millis_opt(now_ms) {
                chrono::LocalResult::Single(dt) => dt,
                _ => return false,
            };
            let today_midnight = now_dt.date_naive().and_hms_opt(0, 0, 0).unwrap();
            let midnight_ms = Utc.from_utc_datetime(&today_midnight).timestamp_millis();

            // The session should reset if its last update was before today's midnight.
            updated_at_ms < midnight_ms
        }

        SessionResetPolicy::Idle { minutes } => {
            let idle_threshold_ms = now_ms - (*minutes as i64) * 60 * 1000;
            updated_at_ms < idle_threshold_ms
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // -----------------------------------------------------------------------
    // SessionScope parsing & display
    // -----------------------------------------------------------------------

    #[test]
    fn test_scope_default_is_per_sender() {
        assert_eq!(SessionScope::default(), SessionScope::PerSender);
    }

    #[test]
    fn test_scope_from_str_opt() {
        assert_eq!(
            SessionScope::from_str_opt("per-sender"),
            Some(SessionScope::PerSender)
        );
        assert_eq!(
            SessionScope::from_str_opt("global"),
            Some(SessionScope::Global)
        );
        assert_eq!(
            SessionScope::from_str_opt("per-channel-peer"),
            Some(SessionScope::PerChannelPeer)
        );
        assert_eq!(SessionScope::from_str_opt("invalid"), None);
        assert_eq!(SessionScope::from_str_opt(""), None);
    }

    #[test]
    fn test_scope_display() {
        assert_eq!(SessionScope::PerSender.to_string(), "per-sender");
        assert_eq!(SessionScope::Global.to_string(), "global");
        assert_eq!(SessionScope::PerChannelPeer.to_string(), "per-channel-peer");
    }

    #[test]
    fn test_scope_serde_roundtrip() {
        let scopes = vec![
            SessionScope::PerSender,
            SessionScope::Global,
            SessionScope::PerChannelPeer,
        ];
        for scope in scopes {
            let json = serde_json::to_string(&scope).unwrap();
            let parsed: SessionScope = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, scope);
        }
    }

    // -----------------------------------------------------------------------
    // SessionResetPolicy defaults & display
    // -----------------------------------------------------------------------

    #[test]
    fn test_reset_policy_default_is_manual() {
        assert_eq!(SessionResetPolicy::default(), SessionResetPolicy::Manual);
    }

    #[test]
    fn test_reset_policy_display() {
        assert_eq!(SessionResetPolicy::Manual.to_string(), "manual");
        assert_eq!(SessionResetPolicy::Daily.to_string(), "daily");
        assert_eq!(
            SessionResetPolicy::Idle { minutes: 30 }.to_string(),
            "idle(30m)"
        );
    }

    // -----------------------------------------------------------------------
    // resolve_session_key
    // -----------------------------------------------------------------------

    #[test]
    fn test_resolve_key_per_sender() {
        let key = resolve_session_key("telegram", "user123", "peer456", SessionScope::PerSender);
        assert_eq!(key, "telegram:user123");
    }

    #[test]
    fn test_resolve_key_global() {
        let key = resolve_session_key("slack", "user123", "peer456", SessionScope::Global);
        assert_eq!(key, "slack:global");
    }

    #[test]
    fn test_resolve_key_per_channel_peer() {
        let key = resolve_session_key(
            "discord",
            "user123",
            "group789",
            SessionScope::PerChannelPeer,
        );
        assert_eq!(key, "discord:group789");
    }

    #[test]
    fn test_resolve_key_empty_channel() {
        let key = resolve_session_key("", "user1", "peer1", SessionScope::PerSender);
        assert_eq!(key, ":user1");
    }

    #[test]
    fn test_resolve_key_special_characters() {
        let key = resolve_session_key(
            "my-channel",
            "user@domain.com",
            "peer",
            SessionScope::PerSender,
        );
        assert_eq!(key, "my-channel:user@domain.com");
    }

    // -----------------------------------------------------------------------
    // should_reset_session_at — Manual
    // -----------------------------------------------------------------------

    #[test]
    fn test_manual_never_resets() {
        let policy = SessionResetPolicy::Manual;
        // Even with a very old timestamp, manual never triggers a reset.
        assert!(!should_reset_session_at(0, &policy, 999_999_999_999));
    }

    // -----------------------------------------------------------------------
    // should_reset_session_at — Daily
    // -----------------------------------------------------------------------

    #[test]
    fn test_daily_resets_session_from_yesterday() {
        let policy = SessionResetPolicy::Daily;

        // "now" is 2025-06-15 10:00:00 UTC
        let now_ms = Utc
            .with_ymd_and_hms(2025, 6, 15, 10, 0, 0)
            .unwrap()
            .timestamp_millis();

        // session was last updated at 2025-06-14 23:59:59 UTC (yesterday)
        let updated_ms = Utc
            .with_ymd_and_hms(2025, 6, 14, 23, 59, 59)
            .unwrap()
            .timestamp_millis();

        assert!(should_reset_session_at(updated_ms, &policy, now_ms));
    }

    #[test]
    fn test_daily_does_not_reset_session_from_today() {
        let policy = SessionResetPolicy::Daily;

        // "now" is 2025-06-15 10:00:00 UTC
        let now_ms = Utc
            .with_ymd_and_hms(2025, 6, 15, 10, 0, 0)
            .unwrap()
            .timestamp_millis();

        // session was last updated at 2025-06-15 00:00:01 UTC (just after midnight today)
        let updated_ms = Utc
            .with_ymd_and_hms(2025, 6, 15, 0, 0, 1)
            .unwrap()
            .timestamp_millis();

        assert!(!should_reset_session_at(updated_ms, &policy, now_ms));
    }

    #[test]
    fn test_daily_resets_at_exact_midnight_boundary() {
        let policy = SessionResetPolicy::Daily;

        // "now" is exactly midnight 2025-06-15 00:00:00 UTC
        let now_ms = Utc
            .with_ymd_and_hms(2025, 6, 15, 0, 0, 0)
            .unwrap()
            .timestamp_millis();

        // session updated at midnight minus 1ms
        let updated_just_before = now_ms - 1;
        assert!(should_reset_session_at(
            updated_just_before,
            &policy,
            now_ms
        ));

        // session updated at exactly midnight (same instant)
        assert!(!should_reset_session_at(now_ms, &policy, now_ms));
    }

    #[test]
    fn test_daily_resets_very_old_session() {
        let policy = SessionResetPolicy::Daily;

        let now_ms = Utc
            .with_ymd_and_hms(2025, 6, 15, 12, 0, 0)
            .unwrap()
            .timestamp_millis();

        // Session from a week ago
        let updated_ms = Utc
            .with_ymd_and_hms(2025, 6, 8, 14, 0, 0)
            .unwrap()
            .timestamp_millis();

        assert!(should_reset_session_at(updated_ms, &policy, now_ms));
    }

    // -----------------------------------------------------------------------
    // should_reset_session_at — Idle
    // -----------------------------------------------------------------------

    #[test]
    fn test_idle_resets_after_timeout() {
        let policy = SessionResetPolicy::Idle { minutes: 60 };

        let now_ms: i64 = 1_000_000_000_000; // arbitrary
                                             // Last updated 61 minutes ago
        let updated_ms = now_ms - 61 * 60 * 1000;

        assert!(should_reset_session_at(updated_ms, &policy, now_ms));
    }

    #[test]
    fn test_idle_does_not_reset_within_timeout() {
        let policy = SessionResetPolicy::Idle { minutes: 60 };

        let now_ms: i64 = 1_000_000_000_000;
        // Last updated 59 minutes ago
        let updated_ms = now_ms - 59 * 60 * 1000;

        assert!(!should_reset_session_at(updated_ms, &policy, now_ms));
    }

    #[test]
    fn test_idle_exact_boundary() {
        let policy = SessionResetPolicy::Idle { minutes: 30 };

        let now_ms: i64 = 1_000_000_000_000;
        // Exactly 30 minutes ago
        let updated_ms = now_ms - 30 * 60 * 1000;

        // At the exact boundary, updated_at == threshold, so NOT less-than.
        assert!(!should_reset_session_at(updated_ms, &policy, now_ms));
    }

    #[test]
    fn test_idle_one_ms_past_boundary() {
        let policy = SessionResetPolicy::Idle { minutes: 30 };

        let now_ms: i64 = 1_000_000_000_000;
        // 30 minutes and 1 millisecond ago
        let updated_ms = now_ms - 30 * 60 * 1000 - 1;

        assert!(should_reset_session_at(updated_ms, &policy, now_ms));
    }

    #[test]
    fn test_idle_custom_minutes() {
        let policy = SessionResetPolicy::Idle { minutes: 5 };

        let now_ms: i64 = 1_000_000_000_000;
        // 6 minutes ago
        let updated_ms = now_ms - 6 * 60 * 1000;

        assert!(should_reset_session_at(updated_ms, &policy, now_ms));

        // 4 minutes ago — should NOT reset
        let updated_recent = now_ms - 4 * 60 * 1000;
        assert!(!should_reset_session_at(updated_recent, &policy, now_ms));
    }

    // -----------------------------------------------------------------------
    // Config parsing — ChannelSessionConfig::from_value
    // -----------------------------------------------------------------------

    #[test]
    fn test_config_from_empty_value() {
        let config = ChannelSessionConfig::from_value(&json!({}));
        assert_eq!(config.scope, SessionScope::PerSender);
        assert_eq!(config.reset, SessionResetPolicy::Manual);
    }

    #[test]
    fn test_config_from_value_scope_only() {
        let config = ChannelSessionConfig::from_value(&json!({
            "scope": "global"
        }));
        assert_eq!(config.scope, SessionScope::Global);
        assert_eq!(config.reset, SessionResetPolicy::Manual);
    }

    #[test]
    fn test_config_from_value_with_daily_reset() {
        let config = ChannelSessionConfig::from_value(&json!({
            "scope": "per-sender",
            "reset": { "mode": "daily" }
        }));
        assert_eq!(config.scope, SessionScope::PerSender);
        assert_eq!(config.reset, SessionResetPolicy::Daily);
    }

    #[test]
    fn test_config_from_value_with_idle_reset() {
        let config = ChannelSessionConfig::from_value(&json!({
            "scope": "per-channel-peer",
            "reset": { "mode": "idle", "idleMinutes": 30 }
        }));
        assert_eq!(config.scope, SessionScope::PerChannelPeer);
        assert_eq!(config.reset, SessionResetPolicy::Idle { minutes: 30 });
    }

    #[test]
    fn test_config_from_value_idle_default_minutes() {
        let config = ChannelSessionConfig::from_value(&json!({
            "reset": { "mode": "idle" }
        }));
        assert_eq!(
            config.reset,
            SessionResetPolicy::Idle {
                minutes: DEFAULT_IDLE_MINUTES
            }
        );
    }

    #[test]
    fn test_config_from_value_unknown_scope_falls_back() {
        let config = ChannelSessionConfig::from_value(&json!({
            "scope": "per-universe"
        }));
        assert_eq!(config.scope, SessionScope::PerSender);
    }

    #[test]
    fn test_config_from_value_unknown_reset_mode_falls_back() {
        let config = ChannelSessionConfig::from_value(&json!({
            "reset": { "mode": "cosmic-ray" }
        }));
        assert_eq!(config.reset, SessionResetPolicy::Manual);
    }

    // -----------------------------------------------------------------------
    // Config parsing — ChannelSessionConfig::from_config
    // -----------------------------------------------------------------------

    #[test]
    fn test_from_config_channel_specific() {
        let config = json!({
            "channels": {
                "telegram": {
                    "session": {
                        "scope": "global",
                        "reset": { "mode": "daily" }
                    }
                }
            }
        });

        let result = ChannelSessionConfig::from_config(&config, "telegram");
        assert_eq!(result.scope, SessionScope::Global);
        assert_eq!(result.reset, SessionResetPolicy::Daily);
    }

    #[test]
    fn test_from_config_falls_back_to_global_scope() {
        let config = json!({
            "session": {
                "scope": "global"
            }
        });

        let result = ChannelSessionConfig::from_config(&config, "telegram");
        assert_eq!(result.scope, SessionScope::Global);
        assert_eq!(result.reset, SessionResetPolicy::Manual);
    }

    #[test]
    fn test_from_config_no_config_at_all() {
        let config = json!({});
        let result = ChannelSessionConfig::from_config(&config, "telegram");
        assert_eq!(result.scope, SessionScope::PerSender);
        assert_eq!(result.reset, SessionResetPolicy::Manual);
    }

    #[test]
    fn test_from_config_channel_overrides_global() {
        let config = json!({
            "session": {
                "scope": "global"
            },
            "channels": {
                "slack": {
                    "session": {
                        "scope": "per-channel-peer",
                        "reset": { "mode": "idle", "idleMinutes": 15 }
                    }
                }
            }
        });

        // slack has its own config
        let slack = ChannelSessionConfig::from_config(&config, "slack");
        assert_eq!(slack.scope, SessionScope::PerChannelPeer);
        assert_eq!(slack.reset, SessionResetPolicy::Idle { minutes: 15 });

        // discord falls back to global
        let discord = ChannelSessionConfig::from_config(&config, "discord");
        assert_eq!(discord.scope, SessionScope::Global);
        assert_eq!(discord.reset, SessionResetPolicy::Manual);
    }

    #[test]
    fn test_from_config_channel_without_session_key() {
        let config = json!({
            "channels": {
                "telegram": {
                    "enabled": true
                }
            }
        });

        let result = ChannelSessionConfig::from_config(&config, "telegram");
        // No "session" key in the channel config => defaults
        assert_eq!(result.scope, SessionScope::PerSender);
        assert_eq!(result.reset, SessionResetPolicy::Manual);
    }

    // -----------------------------------------------------------------------
    // Integration: resolve + reset together
    // -----------------------------------------------------------------------

    #[test]
    fn test_integration_resolve_and_check_reset() {
        let config = json!({
            "channels": {
                "telegram": {
                    "session": {
                        "scope": "per-sender",
                        "reset": { "mode": "idle", "idleMinutes": 10 }
                    }
                }
            }
        });

        let channel_config = ChannelSessionConfig::from_config(&config, "telegram");

        // Resolve the session key
        let key = resolve_session_key("telegram", "alice", "group42", channel_config.scope);
        assert_eq!(key, "telegram:alice");

        let now_ms: i64 = 1_000_000_000_000;

        // Session updated 5 minutes ago — should NOT reset
        let recent = now_ms - 5 * 60 * 1000;
        assert!(!should_reset_session_at(
            recent,
            &channel_config.reset,
            now_ms
        ));

        // Session updated 15 minutes ago — should reset
        let stale = now_ms - 15 * 60 * 1000;
        assert!(should_reset_session_at(
            stale,
            &channel_config.reset,
            now_ms
        ));
    }

    #[test]
    fn test_integration_global_daily_reset() {
        let config = json!({
            "channels": {
                "broadcast": {
                    "session": {
                        "scope": "global",
                        "reset": { "mode": "daily" }
                    }
                }
            }
        });

        let channel_config = ChannelSessionConfig::from_config(&config, "broadcast");

        // Key should always be global regardless of sender/peer
        let key1 = resolve_session_key("broadcast", "alice", "peer1", channel_config.scope);
        let key2 = resolve_session_key("broadcast", "bob", "peer2", channel_config.scope);
        assert_eq!(key1, "broadcast:global");
        assert_eq!(key1, key2);

        // Check daily reset: session from yesterday should reset
        let now_ms = Utc
            .with_ymd_and_hms(2025, 3, 15, 14, 0, 0)
            .unwrap()
            .timestamp_millis();
        let yesterday = Utc
            .with_ymd_and_hms(2025, 3, 14, 22, 0, 0)
            .unwrap()
            .timestamp_millis();

        assert!(should_reset_session_at(
            yesterday,
            &channel_config.reset,
            now_ms
        ));
    }
}
