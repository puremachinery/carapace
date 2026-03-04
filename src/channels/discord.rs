//! Discord channel plugin.
//!
//! Delivers messages via the Discord REST API. Uses `reqwest::blocking::Client`
//! since `ChannelPluginInstance` methods are sync (called via `spawn_blocking`).

use reqwest::blocking::multipart;
use reqwest::StatusCode;
use serde_json::{json, Value};

use crate::channels::media_fetch::fetch_media_bytes;
use crate::channels::{ChannelAuthError, ChannelAuthResult};
use crate::plugins::{
    BindingError, ChannelCapabilities, ChannelInfo, ChannelPluginInstance, ChatType,
    DeliveryResult, OutboundContext,
};

/// Maximum media size to fetch and upload (25 MB).
const MAX_MEDIA_BYTES: u64 = 25 * 1024 * 1024;
#[allow(dead_code)]
const VALIDATION_TIMEOUT_SECS: u64 = 5;
pub const DISCORD_DEFAULT_API_BASE_URL: &str = "https://discord.com/api/v10";

/// A channel plugin that delivers messages via the Discord REST API.
pub struct DiscordChannel {
    client: reqwest::blocking::Client,
    base_url: String,
    bot_token: String,
}

impl DiscordChannel {
    /// Create a new Discord channel targeting the given API base URL.
    pub fn new(base_url: String, bot_token: String) -> Self {
        Self {
            client: reqwest::blocking::Client::new(),
            base_url,
            bot_token,
        }
    }

    /// Build the API endpoint URL for a path.
    fn api_url(&self, path: &str) -> String {
        let base = self.base_url.trim_end_matches('/');
        format!("{}/{}", base, path)
    }

    #[allow(dead_code)]
    pub(crate) fn validate(&self) -> ChannelAuthResult {
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(VALIDATION_TIMEOUT_SECS))
            .build()
            .map_err(|e| {
                ChannelAuthError::transient(format!("discord validation client init failed: {e}"))
            })?;

        let resp = client
            .get(self.api_url("users/@me"))
            .header(
                reqwest::header::AUTHORIZATION,
                format!("Bot {}", self.bot_token),
            )
            .send()
            .map_err(|e| {
                ChannelAuthError::transient(format!("discord validation request failed: {e}"))
            })?;

        let status = resp.status();
        if status.is_success() {
            return Ok(());
        }

        let body_text = resp.text().unwrap_or_default();
        let parsed: Value = serde_json::from_str(&body_text).unwrap_or(Value::Null);
        let message = parsed
            .get("message")
            .and_then(|v| v.as_str())
            .unwrap_or("discord validation failed");

        if status == StatusCode::TOO_MANY_REQUESTS || status.is_server_error() {
            return Err(ChannelAuthError::transient(message.to_string()));
        }

        Err(ChannelAuthError::auth(message.to_string()))
    }

    #[allow(clippy::result_large_err)]
    fn fetch_media(&self, media_url: &str) -> Result<Vec<u8>, DeliveryResult> {
        fetch_media_bytes(media_url, MAX_MEDIA_BYTES)
    }

    fn parse_response(resp: reqwest::blocking::Response) -> DeliveryResult {
        let status = resp.status();
        let body_text = resp.text().unwrap_or_default();
        let parsed: Value = serde_json::from_str(&body_text).unwrap_or(Value::Null);

        if status.is_success() {
            let message_id = parsed.get("id").and_then(value_to_string);
            return success_result(message_id);
        }

        let error = parsed
            .get("message")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .or_else(|| {
                if body_text.is_empty() {
                    None
                } else {
                    Some(body_text.clone())
                }
            })
            .unwrap_or_else(|| format!("HTTP {}", status));

        error_result(
            error,
            status.is_server_error() || status == StatusCode::TOO_MANY_REQUESTS,
        )
    }
}

impl ChannelPluginInstance for DiscordChannel {
    fn get_info(&self) -> Result<ChannelInfo, BindingError> {
        Ok(ChannelInfo {
            id: "discord".to_string(),
            label: "Discord".to_string(),
            selection_label: "Discord Channel".to_string(),
            docs_path: "".to_string(),
            blurb: "Sends messages via Discord REST API".to_string(),
            order: 30,
        })
    }

    fn get_capabilities(&self) -> Result<ChannelCapabilities, BindingError> {
        Ok(ChannelCapabilities {
            chat_types: vec![
                ChatType::Dm,
                ChatType::Group,
                ChatType::Channel,
                ChatType::Thread,
            ],
            media: true,
            reply: true,
            threads: true,
            ..Default::default()
        })
    }

    fn send_text(&self, ctx: OutboundContext) -> Result<DeliveryResult, BindingError> {
        if ctx.text.is_empty() {
            return Ok(error_result("text must not be empty", false));
        }

        let channel_id = ctx
            .thread_id
            .as_deref()
            .filter(|id| !id.is_empty())
            .unwrap_or(&ctx.to);

        let mut body = json!({ "content": ctx.text });
        if let Some(reply_to) = ctx.reply_to_id.as_deref() {
            body["message_reference"] = json!({ "message_id": reply_to });
        }

        match self
            .client
            .post(self.api_url(&format!("channels/{}/messages", channel_id)))
            .header(
                reqwest::header::AUTHORIZATION,
                format!("Bot {}", self.bot_token),
            )
            .json(&body)
            .send()
        {
            Ok(resp) => Ok(Self::parse_response(resp)),
            Err(e) => Ok(error_result(format!("request failed: {}", e), true)),
        }
    }

    fn send_media(&self, ctx: OutboundContext) -> Result<DeliveryResult, BindingError> {
        let media_url = match &ctx.media_url {
            Some(url) => url,
            None => return self.send_text(ctx),
        };

        let media_bytes = match self.fetch_media(media_url) {
            Ok(bytes) => bytes,
            Err(err) => return Ok(err),
        };

        let channel_id = ctx
            .thread_id
            .as_deref()
            .filter(|id| !id.is_empty())
            .unwrap_or(&ctx.to);

        let filename = filename_from_url(media_url);

        let mut payload = json!({
            "content": ctx.text,
            "attachments": [{ "id": 0, "filename": filename }]
        });
        if let Some(reply_to) = ctx.reply_to_id.as_deref() {
            payload["message_reference"] = json!({ "message_id": reply_to });
        }

        let part = multipart::Part::bytes(media_bytes).file_name(
            payload["attachments"][0]["filename"]
                .as_str()
                .unwrap_or("attachment")
                .to_string(),
        );

        let form = multipart::Form::new()
            .text("payload_json", payload.to_string())
            .part("files[0]", part);

        match self
            .client
            .post(self.api_url(&format!("channels/{}/messages", channel_id)))
            .header(
                reqwest::header::AUTHORIZATION,
                format!("Bot {}", self.bot_token),
            )
            .multipart(form)
            .send()
        {
            Ok(resp) => Ok(Self::parse_response(resp)),
            Err(e) => Ok(error_result(format!("request failed: {}", e), true)),
        }
    }
}

fn value_to_string(value: &Value) -> Option<String> {
    value
        .as_str()
        .map(|s| s.to_string())
        .or_else(|| value.as_i64().map(|n| n.to_string()))
}

fn filename_from_url(url: &str) -> String {
    url::Url::parse(url)
        .ok()
        .and_then(|u| {
            u.path_segments()
                .and_then(|mut segments| segments.next_back().map(String::from))
        })
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| "attachment".to_string())
}

fn success_result(message_id: Option<String>) -> DeliveryResult {
    DeliveryResult {
        ok: true,
        message_id,
        error: None,
        retryable: false,
        conversation_id: None,
        to_jid: None,
        poll_id: None,
    }
}

fn error_result(error: impl Into<String>, retryable: bool) -> DeliveryResult {
    DeliveryResult {
        ok: false,
        message_id: None,
        error: Some(error.into()),
        retryable,
        conversation_id: None,
        to_jid: None,
        poll_id: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_channel() -> DiscordChannel {
        DiscordChannel::new("http://localhost:8080".to_string(), "token".to_string())
    }

    #[test]
    fn test_discord_get_info() {
        let ch = test_channel();
        let info = ch.get_info().unwrap();
        assert_eq!(info.id, "discord");
        assert_eq!(info.label, "Discord");
        assert_eq!(info.order, 30);
        assert_eq!(info.blurb, "Sends messages via Discord REST API");
    }

    #[test]
    fn test_discord_get_capabilities() {
        let ch = test_channel();
        let caps = ch.get_capabilities().unwrap();
        assert!(caps.media);
        assert!(caps.reply);
        assert!(caps.threads);
        assert_eq!(
            caps.chat_types,
            vec![
                ChatType::Dm,
                ChatType::Group,
                ChatType::Channel,
                ChatType::Thread
            ]
        );
    }

    #[test]
    fn test_discord_api_url() {
        let ch = test_channel();
        assert_eq!(
            ch.api_url("channels/123/messages"),
            "http://localhost:8080/channels/123/messages"
        );
    }

    #[test]
    fn test_discord_send_text_connection_failure() {
        let ch = DiscordChannel::new("http://192.0.2.1:1".to_string(), "token".to_string());
        let ctx = OutboundContext {
            to: "123".to_string(),
            text: "Hello Discord".to_string(),
            media_url: None,
            gif_playback: false,
            reply_to_id: None,
            thread_id: None,
            account_id: None,
        };
        let result = ch.send_text(ctx).unwrap();
        assert!(!result.ok);
        assert!(result.retryable, "connection failures should be retryable");
        assert!(result.error.is_some());
    }

    #[test]
    fn test_discord_send_media_no_url_falls_back_to_text() {
        let ch = DiscordChannel::new("http://192.0.2.1:1".to_string(), "token".to_string());
        let ctx = OutboundContext {
            to: "123".to_string(),
            text: "caption".to_string(),
            media_url: None,
            gif_playback: false,
            reply_to_id: None,
            thread_id: None,
            account_id: None,
        };
        let result = ch.send_media(ctx).unwrap();
        assert!(!result.ok);
        assert!(result.retryable);
    }
}
