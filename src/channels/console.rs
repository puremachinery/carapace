//! Console channel plugin.
//!
//! Prints outbound messages to stdout via `tracing::info!`.
//! Intended for testing and demo purposes — no network calls are made.

use uuid::Uuid;

use crate::plugins::{
    BindingError, ChannelCapabilities, ChannelInfo, ChannelPluginInstance, DeliveryResult,
    OutboundContext,
};

/// A channel plugin that prints messages to the console via tracing.
pub struct ConsoleChannel;

impl ConsoleChannel {
    /// Create a new console channel.
    pub fn new() -> Self {
        Self
    }
}

impl Default for ConsoleChannel {
    fn default() -> Self {
        Self::new()
    }
}

impl ChannelPluginInstance for ConsoleChannel {
    fn get_info(&self) -> Result<ChannelInfo, BindingError> {
        Ok(ChannelInfo {
            id: "console".to_string(),
            label: "Console".to_string(),
            selection_label: "Console Channel".to_string(),
            docs_path: "".to_string(),
            blurb: "Prints messages to stdout".to_string(),
            order: 999,
        })
    }

    fn get_capabilities(&self) -> Result<ChannelCapabilities, BindingError> {
        Ok(ChannelCapabilities {
            media: true,
            ..Default::default()
        })
    }

    fn send_text(&self, ctx: OutboundContext) -> Result<DeliveryResult, BindingError> {
        tracing::info!(
            channel = "console",
            to = %ctx.to,
            "[console] To {}: {}",
            ctx.to,
            ctx.text,
        );

        Ok(DeliveryResult {
            ok: true,
            message_id: Some(Uuid::new_v4().to_string()),
            error: None,
            retryable: false,
        })
    }

    fn send_media(&self, ctx: OutboundContext) -> Result<DeliveryResult, BindingError> {
        let media_url = ctx.media_url.as_deref().unwrap_or("<no url>");
        let caption = if ctx.text.is_empty() {
            "<no caption>"
        } else {
            &ctx.text
        };

        tracing::info!(
            channel = "console",
            to = %ctx.to,
            media_url = %media_url,
            "[console] To {}: [media: {}] {}",
            ctx.to,
            media_url,
            caption,
        );

        Ok(DeliveryResult {
            ok: true,
            message_id: Some(Uuid::new_v4().to_string()),
            error: None,
            retryable: false,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_console_get_info() {
        let ch = ConsoleChannel::new();
        let info = ch.get_info().unwrap();
        assert_eq!(info.id, "console");
        assert_eq!(info.label, "Console");
        assert_eq!(info.blurb, "Prints messages to stdout");
    }

    #[test]
    fn test_console_get_capabilities() {
        let ch = ConsoleChannel::new();
        let caps = ch.get_capabilities().unwrap();
        assert!(caps.media);
        assert!(!caps.polls);
        assert!(!caps.reactions);
    }

    #[test]
    fn test_console_send_text() {
        let ch = ConsoleChannel::new();
        let ctx = OutboundContext {
            to: "user123".to_string(),
            text: "Hello, world!".to_string(),
            media_url: None,
            gif_playback: false,
            reply_to_id: None,
            thread_id: None,
            account_id: None,
        };
        let result = ch.send_text(ctx).unwrap();
        assert!(result.ok);
        assert!(result.message_id.is_some());
        assert!(result.error.is_none());
        assert!(!result.retryable);
        // Verify the message_id is a valid UUID
        let id = result.message_id.unwrap();
        assert!(Uuid::parse_str(&id).is_ok());
    }

    #[test]
    fn test_console_send_media() {
        let ch = ConsoleChannel::new();
        let ctx = OutboundContext {
            to: "user456".to_string(),
            text: "Check this out".to_string(),
            media_url: Some("https://example.com/image.jpg".to_string()),
            gif_playback: false,
            reply_to_id: None,
            thread_id: None,
            account_id: None,
        };
        let result = ch.send_media(ctx).unwrap();
        assert!(result.ok);
        assert!(result.message_id.is_some());
        assert!(result.error.is_none());
        assert!(!result.retryable);
    }

    #[test]
    fn test_console_send_media_no_url() {
        let ch = ConsoleChannel::new();
        let ctx = OutboundContext {
            to: "user789".to_string(),
            text: "".to_string(),
            media_url: None,
            gif_playback: false,
            reply_to_id: None,
            thread_id: None,
            account_id: None,
        };
        let result = ch.send_media(ctx).unwrap();
        assert!(result.ok);
    }

    #[test]
    fn test_console_send_text_with_reply() {
        let ch = ConsoleChannel::new();
        let ctx = OutboundContext {
            to: "user123".to_string(),
            text: "Reply text".to_string(),
            media_url: None,
            gif_playback: false,
            reply_to_id: Some("msg-999".to_string()),
            thread_id: Some("thread-1".to_string()),
            account_id: Some("acct-1".to_string()),
        };
        let result = ch.send_text(ctx).unwrap();
        assert!(result.ok);
    }

    #[test]
    fn test_console_default() {
        let ch = ConsoleChannel;
        let info = ch.get_info().unwrap();
        assert_eq!(info.id, "console");
    }

    #[test]
    fn test_console_unique_message_ids() {
        let ch = ConsoleChannel::new();
        let ctx1 = OutboundContext {
            to: "user1".to_string(),
            text: "msg1".to_string(),
            media_url: None,
            gif_playback: false,
            reply_to_id: None,
            thread_id: None,
            account_id: None,
        };
        let ctx2 = OutboundContext {
            to: "user2".to_string(),
            text: "msg2".to_string(),
            media_url: None,
            gif_playback: false,
            reply_to_id: None,
            thread_id: None,
            account_id: None,
        };
        let r1 = ch.send_text(ctx1).unwrap();
        let r2 = ch.send_text(ctx2).unwrap();
        assert_ne!(r1.message_id, r2.message_id);
    }
}
