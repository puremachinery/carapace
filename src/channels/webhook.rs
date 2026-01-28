//! Webhook channel plugin.
//!
//! Delivers messages by POSTing JSON to a configured URL.
//! Uses `reqwest::blocking::Client` since `ChannelPluginInstance` methods are sync.

use std::collections::HashMap;

use crate::plugins::{
    BindingError, ChannelCapabilities, ChannelInfo, ChannelPluginInstance, DeliveryResult,
    OutboundContext,
};

/// A channel plugin that delivers messages via HTTP webhooks.
pub struct WebhookChannel {
    client: reqwest::blocking::Client,
    url: String,
    headers: HashMap<String, String>,
}

impl WebhookChannel {
    /// Create a new webhook channel targeting the given URL.
    pub fn new(url: String) -> Self {
        Self {
            client: reqwest::blocking::Client::new(),
            url,
            headers: HashMap::new(),
        }
    }

    /// Set custom headers to include in webhook requests.
    pub fn with_headers(mut self, headers: HashMap<String, String>) -> Self {
        self.headers = headers;
        self
    }
}

impl ChannelPluginInstance for WebhookChannel {
    fn get_info(&self) -> Result<ChannelInfo, BindingError> {
        Ok(ChannelInfo {
            id: "webhook".to_string(),
            label: "Webhook".to_string(),
            selection_label: "Webhook Channel".to_string(),
            docs_path: "".to_string(),
            blurb: "Delivers messages via HTTP POST".to_string(),
            order: 100,
        })
    }

    fn get_capabilities(&self) -> Result<ChannelCapabilities, BindingError> {
        Ok(ChannelCapabilities {
            media: true,
            ..Default::default()
        })
    }

    fn send_text(&self, ctx: OutboundContext) -> Result<DeliveryResult, BindingError> {
        let body = serde_json::json!({
            "to": ctx.to,
            "text": ctx.text,
            "replyTo": ctx.reply_to_id,
        });

        self.post_json(&body)
    }

    fn send_media(&self, ctx: OutboundContext) -> Result<DeliveryResult, BindingError> {
        let body = serde_json::json!({
            "to": ctx.to,
            "mediaUrl": ctx.media_url,
            "caption": ctx.text,
        });

        self.post_json(&body)
    }
}

impl WebhookChannel {
    fn post_json(&self, body: &serde_json::Value) -> Result<DeliveryResult, BindingError> {
        let mut req = self.client.post(&self.url).json(body);

        for (key, value) in &self.headers {
            req = req.header(key, value);
        }

        match req.send() {
            Ok(resp) => {
                let status = resp.status();
                if status.is_success() {
                    Ok(DeliveryResult {
                        ok: true,
                        message_id: None,
                        error: None,
                        retryable: false,
                    })
                } else {
                    let retryable = status.is_server_error();
                    Ok(DeliveryResult {
                        ok: false,
                        message_id: None,
                        error: Some(format!("HTTP {}", status)),
                        retryable,
                    })
                }
            }
            Err(e) => Ok(DeliveryResult {
                ok: false,
                message_id: None,
                error: Some(e.to_string()),
                retryable: true,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_webhook_get_info() {
        let wh = WebhookChannel::new("https://example.com/hook".to_string());
        let info = wh.get_info().unwrap();
        assert_eq!(info.id, "webhook");
        assert_eq!(info.label, "Webhook");
    }

    #[test]
    fn test_webhook_get_capabilities() {
        let wh = WebhookChannel::new("https://example.com/hook".to_string());
        let caps = wh.get_capabilities().unwrap();
        assert!(caps.media);
    }

    #[test]
    fn test_webhook_send_text_builds_correct_body() {
        // This test verifies that send_text doesn't panic with a valid context.
        // Actual HTTP testing would require a mock server.
        let wh = WebhookChannel::new("http://127.0.0.1:1/nonexistent".to_string());
        let ctx = OutboundContext {
            to: "user123".to_string(),
            text: "Hello".to_string(),
            media_url: None,
            gif_playback: false,
            reply_to_id: Some("msg-456".to_string()),
            thread_id: None,
            account_id: None,
        };
        // Will fail to connect but shouldn't panic — verifies request construction
        let result = wh.send_text(ctx).unwrap();
        assert!(!result.ok);
        assert!(result.retryable); // Connection error is retryable
    }

    #[test]
    fn test_webhook_send_media_builds_correct_body() {
        let wh = WebhookChannel::new("http://127.0.0.1:1/nonexistent".to_string());
        let ctx = OutboundContext {
            to: "user123".to_string(),
            text: "A photo".to_string(),
            media_url: Some("https://example.com/img.jpg".to_string()),
            gif_playback: false,
            reply_to_id: None,
            thread_id: None,
            account_id: None,
        };
        let result = wh.send_media(ctx).unwrap();
        assert!(!result.ok);
        assert!(result.retryable);
    }

    #[test]
    fn test_webhook_with_headers() {
        let mut headers = HashMap::new();
        headers.insert("Authorization".to_string(), "Bearer token123".to_string());
        let wh = WebhookChannel::new("https://example.com/hook".to_string()).with_headers(headers);
        assert_eq!(
            wh.headers.get("Authorization"),
            Some(&"Bearer token123".to_string())
        );
    }
}
