//! Webhook request handlers
//!
//! Implements:
//! - POST /hooks/wake - Wake event trigger
//! - POST /hooks/agent - Dispatch message to agent
//! - POST /hooks/<mapping> - Custom hook mappings

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Wake mode for scheduling wake events
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum WakeMode {
    #[default]
    Now,
    NextHeartbeat,
}

impl WakeMode {
    /// Parse wake mode from a string, defaulting to Now for invalid values
    pub fn from_str_lenient(s: &str) -> Self {
        match s {
            "next-heartbeat" => WakeMode::NextHeartbeat,
            _ => WakeMode::Now,
        }
    }
}

/// Request body for POST /hooks/wake
#[derive(Debug, Deserialize)]
pub struct WakeRequest {
    pub text: Option<String>,
    #[serde(default)]
    pub mode: Option<String>,
}

/// Response body for POST /hooks/wake
#[derive(Debug, Serialize)]
pub struct WakeResponse {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<WakeMode>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl WakeResponse {
    pub fn success(mode: WakeMode) -> Self {
        WakeResponse {
            ok: true,
            mode: Some(mode),
            error: None,
        }
    }

    pub fn error(msg: &str) -> Self {
        WakeResponse {
            ok: false,
            mode: None,
            error: Some(msg.to_string()),
        }
    }
}

/// Request body for POST /hooks/agent
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentRequest {
    pub message: Option<String>,
    pub name: Option<String>,
    pub channel: Option<String>,
    pub to: Option<String>,
    pub model: Option<String>,
    pub thinking: Option<String>,
    pub deliver: Option<bool>,
    pub wake_mode: Option<String>,
    pub session_key: Option<String>,
    pub timeout_seconds: Option<f64>,
    pub allow_unsafe_external_content: Option<bool>,
}

/// Response body for POST /hooks/agent
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentResponse {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl AgentResponse {
    pub fn success(run_id: String) -> Self {
        AgentResponse {
            ok: true,
            run_id: Some(run_id),
            error: None,
        }
    }

    pub fn error(msg: &str) -> Self {
        AgentResponse {
            ok: false,
            run_id: None,
            error: Some(msg.to_string()),
        }
    }
}

/// Validated wake request
#[derive(Debug)]
pub struct ValidatedWakeRequest {
    pub text: String,
    pub mode: WakeMode,
}

/// Validate a wake request
pub fn validate_wake_request(req: &WakeRequest) -> Result<ValidatedWakeRequest, String> {
    let text = req
        .text
        .as_ref()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .ok_or("text required")?
        .to_string();

    let mode = req
        .mode
        .as_ref()
        .map(|s| WakeMode::from_str_lenient(s))
        .unwrap_or(WakeMode::Now);

    Ok(ValidatedWakeRequest { text, mode })
}

/// Validated agent request
#[derive(Debug)]
pub struct ValidatedAgentRequest {
    pub message: String,
    pub name: String,
    pub channel: String,
    pub to: Option<String>,
    pub model: Option<String>,
    pub thinking: Option<String>,
    pub deliver: bool,
    pub wake_mode: WakeMode,
    pub session_key: String,
    pub timeout_seconds: Option<u32>,
    pub allow_unsafe_external_content: bool,
}

/// Channel aliases mapping
const CHANNEL_ALIASES: &[(&str, &str)] = &[
    ("imsg", "imessage"),
    ("wa", "whatsapp"),
    ("tg", "telegram"),
    ("teams", "msteams"),
];

/// Resolve channel aliases
fn resolve_channel_alias(channel: &str) -> String {
    for (alias, canonical) in CHANNEL_ALIASES {
        if channel.eq_ignore_ascii_case(alias) {
            return canonical.to_string();
        }
    }
    channel.to_string()
}

/// Validate an agent request
pub fn validate_agent_request(
    req: &AgentRequest,
    valid_channels: &[String],
) -> Result<ValidatedAgentRequest, String> {
    // Validate message (required, non-empty after trim)
    let message = req
        .message
        .as_ref()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .ok_or("message required")?
        .to_string();

    // Validate model if provided (must be non-empty after trim)
    let model = if let Some(m) = &req.model {
        let trimmed = m.trim();
        if trimmed.is_empty() {
            return Err("model required".to_string());
        }
        Some(trimmed.to_string())
    } else {
        None
    };

    // Resolve channel alias and validate
    let channel = resolve_channel_alias(req.channel.as_deref().unwrap_or("last"));
    if !valid_channels.is_empty()
        && channel != "last"
        && !valid_channels.iter().any(|c| c.eq_ignore_ascii_case(&channel))
    {
        return Err(format!(
            "channel must be one of: last, {}",
            valid_channels.join(", ")
        ));
    }

    // Generate session key if not provided
    let session_key = req
        .session_key
        .clone()
        .unwrap_or_else(|| format!("hook:{}", Uuid::new_v4()));

    // Parse timeout_seconds (floor to integer, ignore invalid values)
    let timeout_seconds = req.timeout_seconds.and_then(|t| {
        let floored = t.floor() as i64;
        if floored > 0 && t.is_finite() {
            Some(floored as u32)
        } else {
            None
        }
    });

    Ok(ValidatedAgentRequest {
        message,
        name: req.name.clone().unwrap_or_else(|| "Hook".to_string()),
        channel,
        to: req.to.clone(),
        model,
        thinking: req.thinking.clone(),
        deliver: req.deliver.unwrap_or(true),
        wake_mode: req
            .wake_mode
            .as_ref()
            .map(|s| WakeMode::from_str_lenient(s))
            .unwrap_or(WakeMode::Now),
        session_key,
        timeout_seconds,
        allow_unsafe_external_content: req.allow_unsafe_external_content.unwrap_or(false),
    })
}

/// Error response for hooks API
#[derive(Debug, Serialize)]
pub struct HooksErrorResponse {
    pub ok: bool,
    pub error: String,
}

impl HooksErrorResponse {
    pub fn new(error: &str) -> Self {
        HooksErrorResponse {
            ok: false,
            error: error.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wake_mode_from_str() {
        assert_eq!(WakeMode::from_str_lenient("now"), WakeMode::Now);
        assert_eq!(
            WakeMode::from_str_lenient("next-heartbeat"),
            WakeMode::NextHeartbeat
        );
        assert_eq!(WakeMode::from_str_lenient("invalid"), WakeMode::Now);
        assert_eq!(WakeMode::from_str_lenient(""), WakeMode::Now);
    }

    #[test]
    fn test_validate_wake_request_success() {
        let req = WakeRequest {
            text: Some("hello world".to_string()),
            mode: None,
        };
        let result = validate_wake_request(&req).unwrap();
        assert_eq!(result.text, "hello world");
        assert_eq!(result.mode, WakeMode::Now);
    }

    #[test]
    fn test_validate_wake_request_with_mode() {
        let req = WakeRequest {
            text: Some("hello".to_string()),
            mode: Some("next-heartbeat".to_string()),
        };
        let result = validate_wake_request(&req).unwrap();
        assert_eq!(result.mode, WakeMode::NextHeartbeat);
    }

    #[test]
    fn test_validate_wake_request_trims_text() {
        let req = WakeRequest {
            text: Some("  hello world  ".to_string()),
            mode: None,
        };
        let result = validate_wake_request(&req).unwrap();
        assert_eq!(result.text, "hello world");
    }

    #[test]
    fn test_validate_wake_request_missing_text() {
        let req = WakeRequest {
            text: None,
            mode: None,
        };
        let result = validate_wake_request(&req);
        assert_eq!(result.unwrap_err(), "text required");
    }

    #[test]
    fn test_validate_wake_request_blank_text() {
        let req = WakeRequest {
            text: Some("   ".to_string()),
            mode: None,
        };
        let result = validate_wake_request(&req);
        assert_eq!(result.unwrap_err(), "text required");
    }

    #[test]
    fn test_validate_wake_request_invalid_mode_defaults_to_now() {
        let req = WakeRequest {
            text: Some("test".to_string()),
            mode: Some("invalid".to_string()),
        };
        let result = validate_wake_request(&req).unwrap();
        assert_eq!(result.mode, WakeMode::Now);
    }

    #[test]
    fn test_validate_agent_request_minimal() {
        let req = AgentRequest {
            message: Some("Do something".to_string()),
            name: None,
            channel: None,
            to: None,
            model: None,
            thinking: None,
            deliver: None,
            wake_mode: None,
            session_key: None,
            timeout_seconds: None,
            allow_unsafe_external_content: None,
        };
        let result = validate_agent_request(&req, &[]).unwrap();
        assert_eq!(result.message, "Do something");
        assert_eq!(result.name, "Hook");
        assert_eq!(result.channel, "last");
        assert!(result.deliver);
        assert_eq!(result.wake_mode, WakeMode::Now);
        assert!(result.session_key.starts_with("hook:"));
    }

    #[test]
    fn test_validate_agent_request_missing_message() {
        let req = AgentRequest {
            message: None,
            name: None,
            channel: None,
            to: None,
            model: None,
            thinking: None,
            deliver: None,
            wake_mode: None,
            session_key: None,
            timeout_seconds: None,
            allow_unsafe_external_content: None,
        };
        let result = validate_agent_request(&req, &[]);
        assert_eq!(result.unwrap_err(), "message required");
    }

    #[test]
    fn test_validate_agent_request_blank_message() {
        let req = AgentRequest {
            message: Some("   ".to_string()),
            name: None,
            channel: None,
            to: None,
            model: None,
            thinking: None,
            deliver: None,
            wake_mode: None,
            session_key: None,
            timeout_seconds: None,
            allow_unsafe_external_content: None,
        };
        let result = validate_agent_request(&req, &[]);
        assert_eq!(result.unwrap_err(), "message required");
    }

    #[test]
    fn test_validate_agent_request_empty_model() {
        let req = AgentRequest {
            message: Some("test".to_string()),
            name: None,
            channel: None,
            to: None,
            model: Some("   ".to_string()),
            thinking: None,
            deliver: None,
            wake_mode: None,
            session_key: None,
            timeout_seconds: None,
            allow_unsafe_external_content: None,
        };
        let result = validate_agent_request(&req, &[]);
        assert_eq!(result.unwrap_err(), "model required");
    }

    #[test]
    fn test_validate_agent_request_channel_alias() {
        let req = AgentRequest {
            message: Some("test".to_string()),
            name: None,
            channel: Some("imsg".to_string()),
            to: None,
            model: None,
            thinking: None,
            deliver: None,
            wake_mode: None,
            session_key: None,
            timeout_seconds: None,
            allow_unsafe_external_content: None,
        };
        let result = validate_agent_request(&req, &["imessage".to_string()]).unwrap();
        assert_eq!(result.channel, "imessage");
    }

    #[test]
    fn test_validate_agent_request_invalid_channel() {
        let req = AgentRequest {
            message: Some("test".to_string()),
            name: None,
            channel: Some("sms".to_string()),
            to: None,
            model: None,
            thinking: None,
            deliver: None,
            wake_mode: None,
            session_key: None,
            timeout_seconds: None,
            allow_unsafe_external_content: None,
        };
        let result = validate_agent_request(&req, &["telegram".to_string(), "discord".to_string()]);
        assert!(result.unwrap_err().contains("channel must be"));
    }

    #[test]
    fn test_validate_agent_request_timeout_seconds_floor() {
        let req = AgentRequest {
            message: Some("test".to_string()),
            name: None,
            channel: None,
            to: None,
            model: None,
            thinking: None,
            deliver: None,
            wake_mode: None,
            session_key: None,
            timeout_seconds: Some(60.7),
            allow_unsafe_external_content: None,
        };
        let result = validate_agent_request(&req, &[]).unwrap();
        assert_eq!(result.timeout_seconds, Some(60));
    }

    #[test]
    fn test_validate_agent_request_timeout_seconds_negative() {
        let req = AgentRequest {
            message: Some("test".to_string()),
            name: None,
            channel: None,
            to: None,
            model: None,
            thinking: None,
            deliver: None,
            wake_mode: None,
            session_key: None,
            timeout_seconds: Some(-1.0),
            allow_unsafe_external_content: None,
        };
        let result = validate_agent_request(&req, &[]).unwrap();
        assert_eq!(result.timeout_seconds, None);
    }

    #[test]
    fn test_validate_agent_request_custom_session_key() {
        let req = AgentRequest {
            message: Some("test".to_string()),
            name: None,
            channel: None,
            to: None,
            model: None,
            thinking: None,
            deliver: None,
            wake_mode: None,
            session_key: Some("my-custom-session".to_string()),
            timeout_seconds: None,
            allow_unsafe_external_content: None,
        };
        let result = validate_agent_request(&req, &[]).unwrap();
        assert_eq!(result.session_key, "my-custom-session");
    }

    #[test]
    fn test_validate_agent_request_deliver_false() {
        let req = AgentRequest {
            message: Some("test".to_string()),
            name: None,
            channel: None,
            to: None,
            model: None,
            thinking: None,
            deliver: Some(false),
            wake_mode: None,
            session_key: None,
            timeout_seconds: None,
            allow_unsafe_external_content: None,
        };
        let result = validate_agent_request(&req, &[]).unwrap();
        assert!(!result.deliver);
    }

    #[test]
    fn test_resolve_channel_alias() {
        assert_eq!(resolve_channel_alias("imsg"), "imessage");
        assert_eq!(resolve_channel_alias("IMSG"), "imessage");
        assert_eq!(resolve_channel_alias("wa"), "whatsapp");
        assert_eq!(resolve_channel_alias("tg"), "telegram");
        assert_eq!(resolve_channel_alias("teams"), "msteams");
        assert_eq!(resolve_channel_alias("telegram"), "telegram");
        assert_eq!(resolve_channel_alias("unknown"), "unknown");
    }
}
