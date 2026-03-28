//! Signal channel plugin.
//!
//! Delivers messages via the [signal-cli-rest-api](https://github.com/bbernhard/signal-cli-rest-api)
//! Docker sidecar. Uses `reqwest::blocking::Client` since `ChannelPluginInstance`
//! methods are sync (called via `spawn_blocking` by the delivery loop).

use base64::Engine;
use reqwest::StatusCode;
use uuid::Uuid;

use crate::plugins::{
    BindingError, ChannelCapabilities, ChannelInfo, ChannelPluginInstance, ChatType,
    DeliveryResult, OutboundContext, ReadReceiptContext, TypingContext,
};

/// Maximum media size to fetch and base64-encode (50 MB).
const MAX_MEDIA_BYTES: u64 = 50 * 1024 * 1024;
const SIGNAL_HTTP_CONNECT_TIMEOUT_SECS: u64 = 5;
const SIGNAL_HTTP_TYPING_TIMEOUT_SECS: u64 = 5;
const SIGNAL_HTTP_RECEIPT_TIMEOUT_SECS: u64 = 2;
const SIGNAL_HTTP_SEND_TIMEOUT_SECS: u64 = 15;
const SIGNAL_HTTP_MEDIA_TIMEOUT_SECS: u64 = 120;

fn is_loopback_host(parsed: &url::Url) -> bool {
    match parsed.host() {
        Some(url::Host::Domain(host)) => host.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    }
}

pub(crate) fn validate_signal_url(
    raw: &str,
    context: &str,
    allow_loopback_http: bool,
) -> Result<url::Url, String> {
    let parsed = url::Url::parse(raw).map_err(|_| format!("invalid {} URL", context))?;
    match parsed.scheme() {
        "https" => {}
        "http" if allow_loopback_http && is_loopback_host(&parsed) => {}
        scheme => {
            let loopback_note = if allow_loopback_http {
                " (http is only allowed for localhost/loopback endpoints)"
            } else {
                ""
            };
            return Err(format!(
                "{} URL must use https{} (got scheme '{}')",
                context, loopback_note, scheme
            ));
        }
    }
    if parsed.host_str().is_none() {
        return Err(format!("{} URL is missing a host", context));
    }
    Ok(parsed)
}

/// A channel plugin that delivers messages via the signal-cli REST API.
pub struct SignalChannel {
    client: reqwest::blocking::Client,
    base_url: String,
    phone_number: String,
    typing_indicator_url: Result<url::Url, String>,
    receipts_url: Result<url::Url, String>,
}

impl SignalChannel {
    /// Create a new Signal channel targeting the given signal-cli-rest-api instance.
    ///
    /// This constructor intentionally does not fail closed for URL policy checks
    /// to preserve compatibility with existing configs (including localhost
    /// signal-cli-rest-api over HTTP). Enforcement happens at send time in
    /// `post_send` and `send_media`.
    pub fn new(base_url: String, phone_number: String) -> Self {
        if let Ok(parsed) = url::Url::parse(&base_url) {
            if parsed.scheme() == "http" && is_loopback_host(&parsed) {
                tracing::warn!(
                    host = parsed.host_str().unwrap_or(""),
                    "signal channel base_url uses http on loopback; use https for non-local deployments"
                );
            } else if parsed.scheme() != "https" {
                tracing::warn!(
                    scheme = parsed.scheme(),
                    host = parsed.host_str().unwrap_or(""),
                    "signal channel base_url is not usable: non-loopback endpoints must use https"
                );
            }
        } else {
            tracing::warn!("signal channel base_url is invalid and will fail send-time validation");
        }

        let typing_indicator_url = validate_signal_url(
            &Self::typing_indicator_url_for(&base_url, &phone_number),
            "signal typing indicator",
            true,
        );
        if let Err(err) = &typing_indicator_url {
            tracing::warn!(error = %err, "signal typing indicator URL is invalid");
        }

        let receipts_url = validate_signal_url(
            &Self::receipts_url_for(&base_url, &phone_number),
            "signal receipt",
            true,
        );
        if let Err(err) = &receipts_url {
            tracing::warn!(error = %err, "signal receipt URL is invalid");
        }

        Self {
            client: reqwest::blocking::Client::builder()
                .connect_timeout(std::time::Duration::from_secs(
                    SIGNAL_HTTP_CONNECT_TIMEOUT_SECS,
                ))
                .build()
                .expect("failed to build Signal HTTP client"),
            typing_indicator_url,
            receipts_url,
            base_url,
            phone_number,
        }
    }

    /// Build the send endpoint URL.
    fn send_url(&self) -> String {
        format!("{}/v2/send", self.base_url)
    }

    fn typing_indicator_url_for(base_url: &str, phone_number: &str) -> String {
        format!(
            "{}/v1/typing-indicator/{}",
            base_url,
            urlencoding::encode(phone_number)
        )
    }

    fn receipts_url_for(base_url: &str, phone_number: &str) -> String {
        format!(
            "{}/v1/receipts/{}",
            base_url,
            urlencoding::encode(phone_number)
        )
    }

    fn update_typing_indicator(&self, ctx: TypingContext, show: bool) -> Result<(), BindingError> {
        let typing_url = self
            .typing_indicator_url
            .clone()
            .map_err(BindingError::CallError)?;
        let body = serde_json::json!({
            "recipient": ctx.to,
        });
        let request = if show {
            self.client.put(typing_url)
        } else {
            self.client.delete(typing_url)
        };

        match request
            .timeout(std::time::Duration::from_secs(
                SIGNAL_HTTP_TYPING_TIMEOUT_SECS,
            ))
            .json(&body)
            .send()
        {
            Ok(resp) if resp.status().is_success() => Ok(()),
            Ok(resp) => Err(signal_http_call_error(
                "signal typing indicator",
                resp.status(),
            )),
            Err(err) => Err(BindingError::CallError(format!(
                "failed to update signal typing indicator: {}",
                err
            ))),
        }
    }

    fn send_read_receipt(&self, ctx: ReadReceiptContext) -> Result<(), BindingError> {
        let timestamp = ctx.timestamp.ok_or_else(|| {
            BindingError::CallError("signal read receipt requires a timestamp".to_string())
        })?;
        let receipts_url = self.receipts_url.clone().map_err(BindingError::CallError)?;
        let body = serde_json::json!({
            "recipient": ctx.recipient,
            "receipt_type": "read",
            "timestamp": timestamp,
        });

        match self
            .client
            .post(receipts_url)
            .timeout(std::time::Duration::from_secs(
                SIGNAL_HTTP_RECEIPT_TIMEOUT_SECS,
            ))
            .json(&body)
            .send()
        {
            Ok(resp) if resp.status().is_success() => Ok(()),
            Ok(resp) => Err(signal_http_call_error("signal read receipt", resp.status())),
            Err(err) => Err(BindingError::CallError(format!(
                "failed to send signal read receipt: {}",
                err
            ))),
        }
    }
}

fn signal_http_call_error(operation: &str, status: StatusCode) -> BindingError {
    BindingError::CallError(format!("{operation} HTTP {status}"))
}

fn signal_http_error_message_with_body_prefix(
    operation: &str,
    status: StatusCode,
    body_text: &str,
) -> String {
    let excerpt = sanitize_signal_error_excerpt(body_text);
    if excerpt.is_empty() {
        format!("{operation} HTTP {status}")
    } else {
        format!("{operation} HTTP {status}: {excerpt}")
    }
}

fn sanitize_signal_error_excerpt(body_text: &str) -> String {
    static LABELED_PHONE_RE: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
        regex::Regex::new(
            r"(?i)\b(recipient|source|sender|number)([:=])(\+?\d(?:[\d().:\-]{5,}\d))",
        )
        .expect("valid labeled phone regex")
    });
    static EMBEDDED_PHONE_RE: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
        regex::Regex::new(r"\+\d(?:[\d().:\-]{5,}\d)").expect("valid embedded phone regex")
    });

    let collapsed = body_text
        .split_whitespace()
        .map(redact_sensitive_signal_token)
        .collect::<Vec<_>>()
        .join(" ");
    let collapsed = LABELED_PHONE_RE
        .replace_all(&collapsed, "$1$2[redacted]")
        .into_owned();
    let collapsed = EMBEDDED_PHONE_RE
        .replace_all(&collapsed, "[redacted]")
        .into_owned();
    let trimmed = collapsed.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    let excerpt: String = trimmed.chars().take(120).collect();
    if trimmed.chars().count() > 120 {
        format!("{excerpt}...")
    } else {
        excerpt
    }
}

fn redact_sensitive_signal_token(token: &str) -> String {
    let trimmed =
        token.trim_matches(|ch: char| ch.is_ascii_punctuation() && ch != '+' && ch != '-');
    let phone_like_numeric = trimmed
        .strip_prefix('+')
        .is_some_and(|digits| digits.chars().all(|ch| ch.is_ascii_digit()));
    let bare_numeric = !phone_like_numeric && trimmed.chars().all(|ch| ch.is_ascii_digit());
    let digit_count = trimmed.chars().filter(|ch| ch.is_ascii_digit()).count();
    let looks_like_uuid = {
        let parts: Vec<&str> = trimmed.split('-').collect();
        parts.len() == 5
            && [8, 4, 4, 4, 12]
                .iter()
                .zip(parts.iter())
                .all(|(len, part)| {
                    part.len() == *len && part.chars().all(|ch| ch.is_ascii_hexdigit())
                })
    };
    let looks_like_hex_secret =
        trimmed.len() >= 32 && trimmed.chars().all(|ch| ch.is_ascii_hexdigit());
    let has_upper = trimmed.chars().any(|ch| ch.is_ascii_uppercase());
    let has_lower = trimmed.chars().any(|ch| ch.is_ascii_lowercase());
    let has_digit = trimmed.chars().any(|ch| ch.is_ascii_digit());
    let has_symbol = trimmed.chars().any(|ch| matches!(ch, '_' | '-' | '='));
    let character_class_count = [has_upper, has_lower, has_digit, has_symbol]
        .into_iter()
        .filter(|present| *present)
        .count();
    let looks_like_opaque_token = trimmed.len() >= 24
        && trimmed
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '='))
        && character_class_count >= 2;
    let sensitive_numeric =
        (phone_like_numeric && digit_count >= 4) || (bare_numeric && digit_count >= 7);
    if sensitive_numeric || looks_like_uuid || looks_like_hex_secret || looks_like_opaque_token {
        "[redacted]".to_string()
    } else {
        token.to_string()
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
            typing_indicators: true,
            read_receipts: true,
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
        let media_request_url = match validate_signal_url(media_url, "signal media", false) {
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

        let media_bytes = match self
            .client
            .get(media_request_url)
            .timeout(std::time::Duration::from_secs(
                SIGNAL_HTTP_MEDIA_TIMEOUT_SECS,
            ))
            .send()
        {
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

    fn start_typing(&self, ctx: TypingContext) -> Result<(), BindingError> {
        self.update_typing_indicator(ctx, true)
    }

    fn stop_typing(&self, ctx: TypingContext) -> Result<(), BindingError> {
        self.update_typing_indicator(ctx, false)
    }

    fn mark_read(&self, ctx: ReadReceiptContext) -> Result<(), BindingError> {
        self.send_read_receipt(ctx)
    }
}

impl SignalChannel {
    fn post_send(&self, body: &serde_json::Value) -> Result<DeliveryResult, BindingError> {
        let send_url = match validate_signal_url(&self.send_url(), "signal send", true) {
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

        match self
            .client
            .post(send_url)
            .timeout(std::time::Duration::from_secs(
                SIGNAL_HTTP_SEND_TIMEOUT_SECS,
            ))
            .json(body)
            .send()
        {
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
                        error: Some(signal_http_error_message_with_body_prefix(
                            "signal send",
                            status,
                            &body_text,
                        )),
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
        assert!(caps.typing_indicators);
        assert!(caps.read_receipts);
        assert_eq!(caps.chat_types, vec![ChatType::Dm]);
        assert!(!caps.polls);
        assert!(!caps.edit);
        assert!(!caps.threads);
    }

    #[test]
    fn test_signal_mark_read_requires_timestamp() {
        let ch = test_channel();
        let err = ch
            .mark_read(ReadReceiptContext {
                recipient: "+15559876543".to_string(),
                ..Default::default()
            })
            .expect_err("mark_read without timestamp should fail");
        assert!(err.to_string().contains("requires a timestamp"));
    }

    #[test]
    fn test_signal_start_typing_connection_failure() {
        let ch = SignalChannel::new("http://127.0.0.1:1".to_string(), "+15551234567".to_string());
        let err = ch
            .start_typing(TypingContext {
                to: "+15559876543".to_string(),
                ..Default::default()
            })
            .expect_err("typing update to unreachable endpoint should fail");
        assert!(err
            .to_string()
            .contains("failed to update signal typing indicator"));
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
    fn test_signal_http_error_message_with_body_prefix_truncates_body() {
        let body = "x".repeat(300);
        let message = signal_http_error_message_with_body_prefix(
            "signal send",
            StatusCode::BAD_REQUEST,
            &body,
        );
        assert!(message.starts_with("signal send HTTP 400 Bad Request: "));
        assert!(message.ends_with("..."));
        assert!(message.len() < 320);
    }

    #[test]
    fn test_signal_http_error_message_redacts_phone_like_and_numeric_tokens() {
        let message = signal_http_error_message_with_body_prefix(
            "signal send",
            StatusCode::BAD_REQUEST,
            "Unregistered user +15551234567 for account 1234567",
        );
        assert!(message.contains("Unregistered user"));
        assert!(message.contains("[redacted]"));
        assert!(!message.contains("15551234567"));
        assert!(!message.contains("1234567"));
    }

    #[test]
    fn test_signal_http_error_message_redacts_embedded_phone_tokens() {
        let message = signal_http_error_message_with_body_prefix(
            "signal send",
            StatusCode::BAD_REQUEST,
            "recipient:+15551234567 rejected by upstream",
        );
        assert!(message.contains("[redacted]"));
        assert!(!message.contains("15551234567"));
    }

    #[test]
    fn test_signal_http_error_message_redacts_labeled_phone_values_without_plus_prefix() {
        let message = signal_http_error_message_with_body_prefix(
            "signal send",
            StatusCode::BAD_REQUEST,
            "recipient:15551234567 source=15557654321 rejected by upstream",
        );
        assert!(message.contains("recipient:[redacted]"));
        assert!(message.contains("source=[redacted]"));
        assert!(!message.contains("15551234567"));
        assert!(!message.contains("15557654321"));
    }

    #[test]
    fn test_signal_http_error_message_preserves_non_numeric_diagnostics() {
        let message = signal_http_error_message_with_body_prefix(
            "signal send",
            StatusCode::BAD_REQUEST,
            "failed at 2024-01-01 for ref-1234",
        );
        assert!(message.contains("2024-01-01"));
        assert!(message.contains("ref-1234"));
    }

    #[test]
    fn test_signal_http_error_message_preserves_common_short_numeric_diagnostics() {
        let message = signal_http_error_message_with_body_prefix(
            "signal send",
            StatusCode::BAD_REQUEST,
            "connect 8080 failed after 1024 bytes with code 4000",
        );
        assert!(message.contains("8080"));
        assert!(message.contains("1024"));
        assert!(message.contains("4000"));
    }

    #[test]
    fn test_signal_http_error_message_preserves_non_phone_labeled_numbers() {
        let message = signal_http_error_message_with_body_prefix(
            "signal send",
            StatusCode::BAD_REQUEST,
            "ref:1234567890 port:8080 code=4000",
        );
        assert!(message.contains("ref:1234567890"));
        assert!(message.contains("port:8080"));
        assert!(message.contains("code=4000"));
    }

    #[test]
    fn test_signal_http_error_message_redacts_uuid_and_opaque_token_identifiers() {
        let message = signal_http_error_message_with_body_prefix(
            "signal send",
            StatusCode::BAD_REQUEST,
            "device 123e4567-e89b-12d3-a456-426614174000 token abcdefgh12345678ijklmnop87654321",
        );
        assert!(message.contains("[redacted]"));
        assert!(!message.contains("123e4567-e89b-12d3-a456-426614174000"));
        assert!(!message.contains("abcdefgh12345678ijklmnop87654321"));
    }

    #[test]
    fn test_signal_http_error_message_redacts_low_digit_opaque_tokens() {
        let message = signal_http_error_message_with_body_prefix(
            "signal send",
            StatusCode::BAD_REQUEST,
            "credential abcdefghijklmnopqrstuvwxYZAB",
        );
        assert!(message.contains("[redacted]"));
        assert!(!message.contains("abcdefghijklmnopqrstuvwxYZAB"));
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
    fn test_signal_send_rejects_non_https_non_loopback_base_url() {
        let ch = SignalChannel::new(
            "http://example.com:8080".to_string(),
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
        assert!(!result.retryable);
        assert!(result
            .error
            .as_deref()
            .unwrap_or_default()
            .contains("signal send URL must use https"));
    }

    #[test]
    fn test_signal_send_allows_http_loopback_base_url() {
        let ch = SignalChannel::new("http://127.0.0.1:1".to_string(), "+15551234567".to_string());
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
        assert!(result.retryable);
        assert!(!result
            .error
            .as_deref()
            .unwrap_or_default()
            .contains("must use https"));
    }

    #[test]
    fn test_signal_send_media_rejects_non_https_media_url() {
        let ch = SignalChannel::new(
            "https://localhost:8080".to_string(),
            "+15551234567".to_string(),
        );
        let ctx = OutboundContext {
            to: "+15559876543".to_string(),
            text: "Check this out".to_string(),
            media_url: Some("http://example.com/image.jpg".to_string()),
            gif_playback: false,
            reply_to_id: None,
            thread_id: None,
            account_id: None,
        };
        let result = ch.send_media(ctx).unwrap();
        assert!(!result.ok);
        assert!(!result.retryable);
        assert!(result
            .error
            .as_deref()
            .unwrap_or_default()
            .contains("signal media URL must use https"));
    }

    #[test]
    fn test_signal_url_parse_error_does_not_echo_raw_url() {
        let err = validate_signal_url("https://user:pass@/broken", "signal send", true)
            .expect_err("invalid URL should fail");
        assert!(!err.contains("user:pass"));
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
