//! Telegram inbound webhook parsing helpers.

use serde::Deserialize;
use serde_json::Value;

/// Telegram update payload.
#[derive(Debug, Deserialize)]
pub struct TelegramUpdate {
    #[serde(default)]
    pub update_id: Option<i64>,
    #[serde(default)]
    pub message: Option<TelegramMessage>,
    #[serde(default, rename = "edited_message")]
    pub edited_message: Option<TelegramMessage>,
    #[serde(default, rename = "channel_post")]
    pub channel_post: Option<TelegramMessage>,
    #[serde(default, rename = "edited_channel_post")]
    pub edited_channel_post: Option<TelegramMessage>,
}

/// Telegram message payload.
#[derive(Debug, Deserialize)]
pub struct TelegramMessage {
    #[serde(default)]
    pub text: Option<String>,
    #[serde(default)]
    pub caption: Option<String>,
    pub chat: TelegramChat,
    #[serde(default)]
    pub from: Option<TelegramUser>,
    #[serde(default, rename = "sender_chat")]
    pub sender_chat: Option<TelegramChat>,
}

/// Telegram chat metadata.
#[derive(Debug, Deserialize)]
pub struct TelegramChat {
    pub id: i64,
    #[serde(default, rename = "type")]
    pub chat_type: Option<String>,
}

/// Telegram user metadata.
#[derive(Debug, Deserialize)]
pub struct TelegramUser {
    pub id: i64,
    #[serde(default)]
    pub is_bot: bool,
}

/// Parsed inbound Telegram message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TelegramInbound {
    pub sender_id: String,
    pub chat_id: String,
    pub text: String,
}

/// Extract a text-bearing inbound message from a Telegram update.
pub fn extract_inbound(update: &TelegramUpdate) -> Option<TelegramInbound> {
    let message = update
        .message
        .as_ref()
        .or(update.edited_message.as_ref())
        .or(update.channel_post.as_ref())
        .or(update.edited_channel_post.as_ref())?;

    if let Some(from) = message.from.as_ref() {
        if from.is_bot {
            return None;
        }
    }

    let text = message
        .text
        .as_ref()
        .filter(|t| !t.is_empty())
        .or_else(|| message.caption.as_ref().filter(|t| !t.is_empty()))?
        .to_string();

    let sender_id = message
        .from
        .as_ref()
        .map(|u| u.id)
        .or_else(|| message.sender_chat.as_ref().map(|c| c.id))
        .unwrap_or(message.chat.id);

    Some(TelegramInbound {
        sender_id: sender_id.to_string(),
        chat_id: message.chat.id.to_string(),
        text,
    })
}

/// Resolve Telegram webhook secret from config or environment.
pub fn resolve_webhook_secret(cfg: &Value) -> Option<String> {
    cfg.get("telegram")
        .and_then(|t| t.get("webhookSecret"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .or_else(|| std::env::var("TELEGRAM_WEBHOOK_SECRET").ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_inbound_message() {
        let json = r#"{
            "message": {
                "text": "Hello",
                "chat": { "id": 123, "type": "private" },
                "from": { "id": 456, "is_bot": false }
            }
        }"#;
        let update: TelegramUpdate = serde_json::from_str(json).unwrap();
        let inbound = extract_inbound(&update).unwrap();
        assert_eq!(inbound.sender_id, "456");
        assert_eq!(inbound.chat_id, "123");
        assert_eq!(inbound.text, "Hello");
    }

    #[test]
    fn test_extract_inbound_channel_post() {
        let json = r#"{
            "channel_post": {
                "caption": "Announcement",
                "chat": { "id": 999, "type": "channel" },
                "sender_chat": { "id": 888, "type": "channel" }
            }
        }"#;
        let update: TelegramUpdate = serde_json::from_str(json).unwrap();
        let inbound = extract_inbound(&update).unwrap();
        assert_eq!(inbound.sender_id, "888");
        assert_eq!(inbound.chat_id, "999");
        assert_eq!(inbound.text, "Announcement");
    }

    #[test]
    fn test_extract_inbound_skips_bot() {
        let json = r#"{
            "message": {
                "text": "Ignore me",
                "chat": { "id": 123, "type": "private" },
                "from": { "id": 456, "is_bot": true }
            }
        }"#;
        let update: TelegramUpdate = serde_json::from_str(json).unwrap();
        assert!(extract_inbound(&update).is_none());
    }

    #[test]
    fn test_resolve_webhook_secret_from_config() {
        let cfg = serde_json::json!({
            "telegram": {
                "webhookSecret": "secret-value"
            }
        });
        assert_eq!(
            resolve_webhook_secret(&cfg),
            Some("secret-value".to_string())
        );
    }
}
