//! Slack inbound Events API helpers.

use hmac::{Hmac, Mac};
use serde_json::Value;
use sha2::Sha256;

/// Slack signature version prefix.
pub const SLACK_SIGNATURE_VERSION: &str = "v0";

/// Maximum allowed clock skew for Slack signatures (5 minutes).
pub const SLACK_SIGNATURE_TOLERANCE_SECS: i64 = 300;

/// Parsed inbound Slack message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlackInbound {
    pub sender_id: String,
    pub channel_id: String,
    pub text: String,
}

/// Verify a Slack signature against the raw request body.
pub fn verify_slack_signature(
    signing_secret: &str,
    timestamp: i64,
    signature: &str,
    body: &[u8],
) -> bool {
    let body_str = String::from_utf8_lossy(body);
    let base = format!(
        "{version}:{timestamp}:{body}",
        version = SLACK_SIGNATURE_VERSION,
        timestamp = timestamp,
        body = body_str
    );
    let mut mac = match Hmac::<Sha256>::new_from_slice(signing_secret.as_bytes()) {
        Ok(mac) => mac,
        Err(_) => return false,
    };
    mac.update(base.as_bytes());
    let digest = mac.finalize().into_bytes();
    let expected = format!("{}={}", SLACK_SIGNATURE_VERSION, hex::encode(digest));
    crate::auth::timing_safe_eq(&expected, signature)
}

/// Extract an inbound message event from a Slack event object.
pub fn extract_inbound_event(event: &Value) -> Option<SlackInbound> {
    let event_type = event.get("type").and_then(|v| v.as_str())?;
    if event_type != "message" && event_type != "app_mention" {
        return None;
    }

    if event_type == "message" && event.get("subtype").is_some() {
        return None;
    }

    let text = event.get("text").and_then(|v| v.as_str())?;
    if text.is_empty() {
        return None;
    }

    let user = event.get("user").and_then(|v| v.as_str())?;
    let channel = event.get("channel").and_then(|v| v.as_str())?;

    Some(SlackInbound {
        sender_id: user.to_string(),
        channel_id: channel.to_string(),
        text: text.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verify_slack_signature() {
        let body = br#"{"type":"url_verification","challenge":"abc"}"#;
        let timestamp = 1_700_000_000i64;
        let secret = format!("test-signing-secret-{timestamp}");
        let base = format!("v0:{timestamp}:{}", String::from_utf8_lossy(body));
        let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(base.as_bytes());
        let digest = mac.finalize().into_bytes();
        let signature = format!("v0={}", hex::encode(digest));

        assert!(verify_slack_signature(&secret, timestamp, &signature, body));
        assert!(!verify_slack_signature(
            &secret,
            timestamp,
            "v0=deadbeef",
            body
        ));
    }

    #[test]
    fn test_extract_inbound_event() {
        let json = serde_json::json!({
            "type": "message",
            "user": "U123",
            "channel": "C456",
            "text": "hello"
        });
        let inbound = extract_inbound_event(&json).unwrap();
        assert_eq!(inbound.sender_id, "U123");
        assert_eq!(inbound.channel_id, "C456");
        assert_eq!(inbound.text, "hello");
    }

    #[test]
    fn test_extract_inbound_event_ignores_subtype() {
        let json = serde_json::json!({
            "type": "message",
            "subtype": "bot_message",
            "user": "U123",
            "channel": "C456",
            "text": "hi"
        });
        assert!(extract_inbound_event(&json).is_none());
    }

    #[test]
    fn test_extract_inbound_event_app_mention() {
        let json = serde_json::json!({
            "type": "app_mention",
            "user": "U777",
            "channel": "C888",
            "text": "<@B123> hello"
        });
        let inbound = extract_inbound_event(&json).unwrap();
        assert_eq!(inbound.sender_id, "U777");
        assert_eq!(inbound.channel_id, "C888");
        assert_eq!(inbound.text, "<@B123> hello");
    }
}
