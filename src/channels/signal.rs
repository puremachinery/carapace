//! Signal channel plugin.
//!
//! Delivers messages via the [signal-cli-rest-api](https://github.com/bbernhard/signal-cli-rest-api)
//! Docker sidecar. Uses `reqwest::blocking::Client` since `ChannelPluginInstance`
//! methods are sync (called via `spawn_blocking` by the delivery loop).

use base64::Engine;
use uuid::Uuid;

use crate::plugins::{
    BindingError, ChannelCapabilities, ChannelInfo, ChannelPluginInstance, ChatType,
    DeliveryResult, OutboundContext,
};

/// Maximum media size to fetch and base64-encode (50 MB).
const MAX_MEDIA_BYTES: u64 = 50 * 1024 * 1024;

/// A channel plugin that delivers messages via the signal-cli REST API.
pub struct SignalChannel {
    client: reqwest::blocking::Client,
    base_url: String,
    phone_number: String,
}

impl SignalChannel {
    /// Create a new Signal channel targeting the given signal-cli-rest-api instance.
    pub fn new(base_url: String, phone_number: String) -> Self {
        Self {
            client: reqwest::blocking::Client::new(),
            base_url,
            phone_number,
        }
    }

    /// Build the send endpoint URL.
    fn send_url(&self) -> String {
        format!("{}/v2/send", self.base_url)
    }

    fn validate_https_url(raw: &str, context: &str) -> Result<url::Url, String> {
        let parsed = url::Url::parse(raw)
            .map_err(|e| format!("invalid {} URL '{}': {}", context, raw, e))?;
        if parsed.scheme() != "https" {
            return Err(format!(
                "{} URL must use https (got scheme '{}')",
                context,
                parsed.scheme()
            ));
        }
        if parsed.host_str().is_none() {
            return Err(format!("{} URL is missing a host", context));
        }
        Ok(parsed)
    }
}

impl ChannelPluginInstance for SignalChannel {
    fn get_info(&self) -> Result<ChannelInfo, BindingError> {
        Ok(ChannelInfo {
            id: "signal".to_string(),
            label: "Signal".to_string(),
            selection_label: "Signal Channel".to_string(),
            docs_path: "".to_string(),
            blurb: "Sends messages via signal-cli REST API".to_string(),
            order: 10,
        })
    }

    fn get_capabilities(&self) -> Result<ChannelCapabilities, BindingError> {
        Ok(ChannelCapabilities {
            chat_types: vec![ChatType::Dm],
            media: true,
            reactions: true,
            ..Default::default()
        })
    }

    fn send_text(&self, ctx: OutboundContext) -> Result<DeliveryResult, BindingError> {
        let body = serde_json::json!({
            "number": self.phone_number,
            "recipients": [ctx.to],
            "message": ctx.text,
        });

        self.post_send(&body)
    }

    fn send_media(&self, ctx: OutboundContext) -> Result<DeliveryResult, BindingError> {
        let media_url = match &ctx.media_url {
            Some(url) => url,
            None => {
                // No media URL — fall back to text-only send
                return self.send_text(ctx);
            }
        };

        // Fetch media bytes (URL has already been SSRF-validated by the host)
        let media_request_url = match Self::validate_https_url(media_url, "signal media") {
            Ok(url) => url,
            Err(e) => {
                return Ok(DeliveryResult {
                    ok: false,
                    message_id: None,
                    error: Some(e),
                    retryable: false,
                    conversation_id: None,
                    to_jid: None,
                    poll_id: None,
                });
            }
        };

        let media_bytes = match self.client.get(media_request_url).send() {
            Ok(resp) if resp.status().is_success() => {
                if let Some(len) = resp.content_length() {
                    if len > MAX_MEDIA_BYTES {
                        return Ok(DeliveryResult {
                            ok: false,
                            message_id: None,
                            error: Some(format!(
                                "media too large: {} bytes (max {})",
                                len, MAX_MEDIA_BYTES
                            )),
                            retryable: false,
                            conversation_id: None,
                            to_jid: None,
                            poll_id: None,
                        });
                    }
                }
                match resp.bytes() {
                    Ok(bytes) => bytes,
                    Err(e) => {
                        return Ok(DeliveryResult {
                            ok: false,
                            message_id: None,
                            error: Some(format!("failed to read media bytes: {}", e)),
                            retryable: true,
                            conversation_id: None,
                            to_jid: None,
                            poll_id: None,
                        });
                    }
                }
            }
            Ok(resp) => {
                return Ok(DeliveryResult {
                    ok: false,
                    message_id: None,
                    error: Some(format!("media fetch HTTP {}", resp.status())),
                    retryable: resp.status().is_server_error(),
                    conversation_id: None,
                    to_jid: None,
                    poll_id: None,
                });
            }
            Err(e) => {
                return Ok(DeliveryResult {
                    ok: false,
                    message_id: None,
                    error: Some(format!("media fetch failed: {}", e)),
                    retryable: true,
                    conversation_id: None,
                    to_jid: None,
                    poll_id: None,
                });
            }
        };

        let encoded = base64::engine::general_purpose::STANDARD.encode(&media_bytes);

        let body = serde_json::json!({
            "number": self.phone_number,
            "recipients": [ctx.to],
            "message": ctx.text,
            "base64_attachments": [encoded],
        });

        self.post_send(&body)
    }
}

impl SignalChannel {
    fn post_send(&self, body: &serde_json::Value) -> Result<DeliveryResult, BindingError> {
        let send_url = match Self::validate_https_url(&self.send_url(), "signal send") {
            Ok(url) => url,
            Err(e) => {
                return Ok(DeliveryResult {
                    ok: false,
                    message_id: None,
                    error: Some(e),
                    retryable: false,
                    conversation_id: None,
                    to_jid: None,
                    poll_id: None,
                });
            }
        };

        match self.client.post(send_url).json(body).send() {
            Ok(resp) => {
                let status = resp.status();
                if status.is_success() {
                    Ok(DeliveryResult {
                        ok: true,
                        message_id: Some(Uuid::new_v4().to_string()),
                        error: None,
                        retryable: false,
                        conversation_id: None,
                        to_jid: None,
                        poll_id: None,
                    })
                } else {
                    let retryable = status.is_server_error();
                    let body_text = resp.text().unwrap_or_default();
                    Ok(DeliveryResult {
                        ok: false,
                        message_id: None,
                        error: Some(format!("HTTP {}: {}", status, body_text)),
                        retryable,
                        conversation_id: None,
                        to_jid: None,
                        poll_id: None,
                    })
                }
            }
            Err(e) => Ok(DeliveryResult {
                ok: false,
                message_id: None,
                error: Some(e.to_string()),
                retryable: true,
                conversation_id: None,
                to_jid: None,
                poll_id: None,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_channel() -> SignalChannel {
        SignalChannel::new(
            "https://localhost:8080".to_string(),
            "+15551234567".to_string(),
        )
    }

    #[test]
    fn test_signal_get_info() {
        let ch = test_channel();
        let info = ch.get_info().unwrap();
        assert_eq!(info.id, "signal");
        assert_eq!(info.label, "Signal");
        assert_eq!(info.order, 10);
        assert_eq!(info.blurb, "Sends messages via signal-cli REST API");
    }

    #[test]
    fn test_signal_get_capabilities() {
        let ch = test_channel();
        let caps = ch.get_capabilities().unwrap();
        assert!(caps.media);
        assert!(caps.reactions);
        assert_eq!(caps.chat_types, vec![ChatType::Dm]);
        assert!(!caps.polls);
        assert!(!caps.edit);
        assert!(!caps.threads);
    }

    #[test]
    fn test_signal_send_url() {
        let ch = test_channel();
        assert_eq!(ch.send_url(), "https://localhost:8080/v2/send");

        let ch2 = SignalChannel::new(
            "https://example.com:9090".to_string(),
            "+15559999999".to_string(),
        );
        assert_eq!(ch2.send_url(), "https://example.com:9090/v2/send");
    }

    #[test]
    fn test_signal_send_text_connection_failure() {
        // Use an unreachable endpoint to verify the error handling path
        let ch = SignalChannel::new(
            "https://192.0.2.1:1".to_string(),
            "+15551234567".to_string(),
        );
        let ctx = OutboundContext {
            to: "+15559876543".to_string(),
            text: "Hello from Signal!".to_string(),
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
    fn test_signal_send_media_no_url_falls_back_to_text() {
        // When media_url is None, send_media should fall back to send_text.
        // Use unreachable endpoint — we're testing the fallback logic, not delivery.
        let ch = SignalChannel::new(
            "https://192.0.2.1:1".to_string(),
            "+15551234567".to_string(),
        );
        let ctx = OutboundContext {
            to: "+15559876543".to_string(),
            text: "caption only".to_string(),
            media_url: None,
            gif_playback: false,
            reply_to_id: None,
            thread_id: None,
            account_id: None,
        };
        let result = ch.send_media(ctx).unwrap();
        // Will fail at network level, but should not panic
        assert!(!result.ok);
        assert!(result.retryable);
    }

    #[test]
    fn test_signal_send_media_connection_failure() {
        let ch = SignalChannel::new(
            "https://192.0.2.1:1".to_string(),
            "+15551234567".to_string(),
        );
        let ctx = OutboundContext {
            to: "+15559876543".to_string(),
            text: "Check this out".to_string(),
            media_url: Some("https://192.0.2.1:1/image.jpg".to_string()),
            gif_playback: false,
            reply_to_id: None,
            thread_id: None,
            account_id: None,
        };
        let result = ch.send_media(ctx).unwrap();
        assert!(!result.ok);
        assert!(result.retryable);
        assert!(result.error.is_some());
    }

    #[test]
    fn test_signal_default_construction() {
        let ch = SignalChannel::new(
            "https://localhost:8080".to_string(),
            "+15551234567".to_string(),
        );
        assert_eq!(ch.base_url, "https://localhost:8080");
        assert_eq!(ch.phone_number, "+15551234567");
    }
}
