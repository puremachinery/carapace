//! Hook token authentication (Bearer + header)
//!
//! Hooks use a separate token from gateway auth. Supports:
//! - Authorization: Bearer <token>
//! - X-Moltbot-Token: <token>
//! - ?token=<token> (deprecated, logs warning)

use axum::http::{HeaderMap, Uri};
use tracing::warn;

/// Extract the hooks token from the request.
/// Returns the token and whether it was from the deprecated query param.
pub fn extract_hooks_token(headers: &HeaderMap, uri: &Uri) -> Option<(String, bool)> {
    // 1. Check Authorization: Bearer <token> header
    if let Some(auth) = headers.get("authorization") {
        if let Ok(auth_str) = auth.to_str() {
            if let Some(token) = auth_str.strip_prefix("Bearer ") {
                return Some((token.trim().to_string(), false));
            }
        }
    }

    // 2. Check X-Moltbot-Token header
    if let Some(token) = headers.get("x-moltbot-token") {
        if let Ok(token_str) = token.to_str() {
            return Some((token_str.trim().to_string(), false));
        }
    }

    // 3. Check ?token=<token> query param (deprecated)
    if let Some(query) = uri.query() {
        for param in query.split('&') {
            if let Some(value) = param.strip_prefix("token=") {
                warn!("Deprecated: hooks token in query param. Use Authorization header instead.");
                return Some((value.to_string(), true));
            }
        }
    }

    None
}

/// Timing-safe comparison of two strings.
/// Uses constant-time comparison to prevent timing attacks.
pub fn timing_safe_equal(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut result: u8 = 0;
    for (x, y) in a.bytes().zip(b.bytes()) {
        result |= x ^ y;
    }
    result == 0
}

/// Validate the hooks token against the configured token.
/// Returns true if the token is valid.
pub fn validate_hooks_token(provided: &str, configured: &str) -> bool {
    if provided.is_empty() || configured.is_empty() {
        return false;
    }
    timing_safe_equal(provided, configured)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderMap, HeaderValue, Uri};

    #[test]
    fn test_extract_bearer_token() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "authorization",
            HeaderValue::from_static("Bearer my-secret-token"),
        );
        let uri: Uri = "/hooks/wake".parse().unwrap();

        let result = extract_hooks_token(&headers, &uri);
        assert_eq!(result, Some(("my-secret-token".to_string(), false)));
    }

    #[test]
    fn test_extract_x_moltbot_token() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-moltbot-token",
            HeaderValue::from_static("another-token"),
        );
        let uri: Uri = "/hooks/wake".parse().unwrap();

        let result = extract_hooks_token(&headers, &uri);
        assert_eq!(result, Some(("another-token".to_string(), false)));
    }

    #[test]
    fn test_extract_query_token() {
        let headers = HeaderMap::new();
        let uri: Uri = "/hooks/wake?token=query-token&other=value".parse().unwrap();

        let result = extract_hooks_token(&headers, &uri);
        assert_eq!(result, Some(("query-token".to_string(), true)));
    }

    #[test]
    fn test_bearer_takes_precedence() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "authorization",
            HeaderValue::from_static("Bearer bearer-token"),
        );
        headers.insert("x-moltbot-token", HeaderValue::from_static("header-token"));
        let uri: Uri = "/hooks/wake?token=query-token".parse().unwrap();

        let result = extract_hooks_token(&headers, &uri);
        assert_eq!(result, Some(("bearer-token".to_string(), false)));
    }

    #[test]
    fn test_no_token() {
        let headers = HeaderMap::new();
        let uri: Uri = "/hooks/wake".parse().unwrap();

        let result = extract_hooks_token(&headers, &uri);
        assert_eq!(result, None);
    }

    #[test]
    fn test_timing_safe_equal() {
        assert!(timing_safe_equal("secret", "secret"));
        assert!(!timing_safe_equal("secret", "secret1"));
        assert!(!timing_safe_equal("secret1", "secret"));
        assert!(!timing_safe_equal("secret", "SECRET"));
        assert!(!timing_safe_equal("", "secret"));
        assert!(!timing_safe_equal("secret", ""));
        assert!(timing_safe_equal("", ""));
    }

    #[test]
    fn test_validate_hooks_token() {
        assert!(validate_hooks_token("my-token", "my-token"));
        assert!(!validate_hooks_token("my-token", "other-token"));
        assert!(!validate_hooks_token("", "my-token"));
        assert!(!validate_hooks_token("my-token", ""));
    }
}
