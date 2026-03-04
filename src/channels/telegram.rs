//! Telegram channel plugin.
//!
//! Delivers messages via the Telegram Bot API. Uses `reqwest::blocking::Client`
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

/// Maximum media size to fetch and upload (50 MB).
const MAX_MEDIA_BYTES: u64 = 50 * 1024 * 1024;
#[allow(dead_code)]
const VALIDATION_TIMEOUT_SECS: u64 = 5;
pub const TELEGRAM_DEFAULT_API_BASE_URL: &str = "https://api.telegram.org";

/// A channel plugin that delivers messages via the Telegram Bot API.
pub struct TelegramChannel {
    client: reqwest::blocking::Client,
    base_url: String,
    bot_token: String,
}

impl TelegramChannel {
    /// Create a new Telegram channel targeting the given Bot API base URL.
    pub fn new(base_url: String, bot_token: String) -> Self {
        Self {
            client: reqwest::blocking::Client::new(),
            base_url,
            bot_token,
        }
    }

    /// Build the API endpoint URL for a method.
    fn api_url(&self, method: &str) -> String {
        let base = self.base_url.trim_end_matches('/');
        format!("{}/bot{}/{}", base, self.bot_token, method)
    }

    #[allow(dead_code)]
    pub(crate) fn validate(&self) -> ChannelAuthResult {
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(VALIDATION_TIMEOUT_SECS))
            .build()
            .map_err(|e| {
                ChannelAuthError::transient(format!("telegram validation client init failed: {e}"))
            })?;

        let resp = client.get(self.api_url("getMe")).send().map_err(|e| {
            ChannelAuthError::transient(format!("telegram validation request failed: {e}"))
        })?;

        let status = resp.status();
        let body_text = resp.text().unwrap_or_default();
        let parsed: Value = serde_json::from_str(&body_text).unwrap_or(Value::Null);
        let ok = parsed
            .get("ok")
            .and_then(|v| v.as_bool())
            .unwrap_or(status.is_success());

        if ok {
            return Ok(());
        }

        let description = parsed
            .get("description")
            .and_then(|v| v.as_str())
            .unwrap_or("telegram validation failed");

        if status == StatusCode::TOO_MANY_REQUESTS || status.is_server_error() {
            return Err(ChannelAuthError::transient(description.to_string()));
        }

        Err(ChannelAuthError::auth(description.to_string()))
    }

    #[allow(clippy::result_large_err)]
    fn fetch_media(&self, media_url: &str) -> Result<Vec<u8>, DeliveryResult> {
        fetch_media_bytes(media_url, MAX_MEDIA_BYTES)
    }

    fn parse_response(resp: reqwest::blocking::Response) -> DeliveryResult {
        let status = resp.status();
        let body_text = resp.text().unwrap_or_default();
        let parsed: Value = serde_json::from_str(&body_text).unwrap_or(Value::Null);

        let ok = parsed
            .get("ok")
            .and_then(|v| v.as_bool())
            .unwrap_or(status.is_success());

        if ok {
            let message_id = parsed
                .get("result")
                .and_then(|r| r.get("message_id"))
                .and_then(value_to_string);
            return success_result(message_id);
        }

        let error = parsed
            .get("description")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .or_else(|| {
                if body_text.is_empty() {
                    None
                } else {
                    Some(body_text.clone())
                }
            })
            .unwrap_or_else(|| "request failed".to_string());

        error_result(
            error,
            status.is_server_error() || status == StatusCode::TOO_MANY_REQUESTS,
        )
    }
}

impl ChannelPluginInstance for TelegramChannel {
    fn get_info(&self) -> Result<ChannelInfo, BindingError> {
        Ok(ChannelInfo {
            id: "telegram".to_string(),
            label: "Telegram".to_string(),
            selection_label: "Telegram Channel".to_string(),
            docs_path: "".to_string(),
            blurb: "Sends messages via Telegram Bot API".to_string(),
            order: 20,
        })
    }

    fn get_capabilities(&self) -> Result<ChannelCapabilities, BindingError> {
        Ok(ChannelCapabilities {
            chat_types: vec![ChatType::Dm, ChatType::Group, ChatType::Channel],
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

        let reply_to = match parse_optional_i64(ctx.reply_to_id.as_deref(), "reply_to_id") {
            Ok(v) => v,
            Err(e) => return Ok(e),
        };
        let thread_id = match parse_optional_i64(ctx.thread_id.as_deref(), "thread_id") {
            Ok(v) => v,
            Err(e) => return Ok(e),
        };

        let mut body = json!({
            "chat_id": ctx.to,
            "text": ctx.text,
        });

        if let Some(reply_to) = reply_to {
            body["reply_to_message_id"] = json!(reply_to);
        }
        if let Some(thread_id) = thread_id {
            body["message_thread_id"] = json!(thread_id);
        }

        match self
            .client
            .post(self.api_url("sendMessage"))
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

        let filename = filename_from_url(media_url);

        let reply_to = match parse_optional_i64(ctx.reply_to_id.as_deref(), "reply_to_id") {
            Ok(v) => v,
            Err(e) => return Ok(e),
        };
        let thread_id = match parse_optional_i64(ctx.thread_id.as_deref(), "thread_id") {
            Ok(v) => v,
            Err(e) => return Ok(e),
        };

        let mut form = multipart::Form::new().text("chat_id", ctx.to);
        if !ctx.text.is_empty() {
            form = form.text("caption", ctx.text);
        }
        if let Some(reply_to) = reply_to {
            form = form.text("reply_to_message_id", reply_to.to_string());
        }
        if let Some(thread_id) = thread_id {
            form = form.text("message_thread_id", thread_id.to_string());
        }

        let part = multipart::Part::bytes(media_bytes).file_name(filename);
        form = form.part("document", part);

        match self
            .client
            .post(self.api_url("sendDocument"))
            .multipart(form)
            .send()
        {
            Ok(resp) => Ok(Self::parse_response(resp)),
            Err(e) => Ok(error_result(format!("request failed: {}", e), true)),
        }
    }
}

#[allow(clippy::result_large_err)]
fn parse_optional_i64(value: Option<&str>, field: &str) -> Result<Option<i64>, DeliveryResult> {
    let Some(raw) = value else {
        return Ok(None);
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    match trimmed.parse::<i64>() {
        Ok(parsed) => Ok(Some(parsed)),
        Err(_) => Err(error_result(
            format!("invalid {field}: expected integer"),
            false,
        )),
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

    fn test_channel() -> TelegramChannel {
        TelegramChannel::new("http://localhost:8080".to_string(), "token".to_string())
    }

    #[test]
    fn test_telegram_get_info() {
        let ch = test_channel();
        let info = ch.get_info().unwrap();
        assert_eq!(info.id, "telegram");
        assert_eq!(info.label, "Telegram");
        assert_eq!(info.order, 20);
        assert_eq!(info.blurb, "Sends messages via Telegram Bot API");
    }

    #[test]
    fn test_telegram_get_capabilities() {
        let ch = test_channel();
        let caps = ch.get_capabilities().unwrap();
        assert!(caps.media);
        assert!(caps.reply);
        assert!(caps.threads);
        assert_eq!(
            caps.chat_types,
            vec![ChatType::Dm, ChatType::Group, ChatType::Channel]
        );
    }

    #[test]
    fn test_telegram_api_url() {
        let ch = test_channel();
        assert_eq!(
            ch.api_url("sendMessage"),
            "http://localhost:8080/bottoken/sendMessage"
        );
    }

    #[test]
    fn test_telegram_send_text_connection_failure() {
        let ch = TelegramChannel::new("http://192.0.2.1:1".to_string(), "token".to_string());
        let ctx = OutboundContext {
            to: "123456".to_string(),
            text: "Hello Telegram".to_string(),
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
    fn test_telegram_send_media_no_url_falls_back_to_text() {
        let ch = TelegramChannel::new("http://192.0.2.1:1".to_string(), "token".to_string());
        let ctx = OutboundContext {
            to: "123456".to_string(),
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
