//! Hook token authentication (Bearer + header)
//!
//! Hooks use a separate token from gateway auth. Supports:
//! - Authorization: Bearer <token>
//! - X-Carapace-Token: <token>
//! - ?token=<token> (deprecated, logs warning)

use axum::http::{HeaderMap, Uri};
use tracing::warn;

use crate::auth::timing_safe_eq;

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

    // 2. Check X-Carapace-Token header
    if let Some(token) = headers.get("x-carapace-token") {
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
///
/// Uses the shared gateway/auth timing-safe compare implementation.
pub fn timing_safe_equal(a: &str, b: &str) -> bool {
    timing_safe_eq(a, b)
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
    fn test_extract_x_carapace_token() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-carapace-token",
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
        headers.insert("x-carapace-token", HeaderValue::from_static("header-token"));
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
    fn test_validate_hooks_token_timing_safe_behavior() {
        assert!(validate_hooks_token("secret", "secret"));
        assert!(!validate_hooks_token("secret", "secret1"));
        assert!(!validate_hooks_token("secret1", "secret"));
        assert!(!validate_hooks_token("secret", "SECRET"));
        assert!(!validate_hooks_token("", "secret"));
        assert!(!validate_hooks_token("secret", ""));
        assert!(!validate_hooks_token("", ""));
    }

    #[test]
    fn test_validate_hooks_token() {
        assert!(validate_hooks_token("my-token", "my-token"));
        assert!(!validate_hooks_token("my-token", "other-token"));
        assert!(!validate_hooks_token("", "my-token"));
        assert!(!validate_hooks_token("my-token", ""));
    }
}
