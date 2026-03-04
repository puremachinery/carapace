//! Hook token authentication (Bearer + header)
//!
//! Hooks use a separate token from gateway auth. Supports:
//! - Authorization: Bearer <token>
//! - X-Carapace-Token: <token>

use axum::http::{HeaderMap, Uri};

use crate::auth::timing_safe_eq;

/// Extract the hooks token from the request.
pub fn extract_hooks_token(headers: &HeaderMap, _uri: &Uri) -> Option<String> {
    // 1. Check Authorization: Bearer <token> header
    if let Some(auth) = headers.get("authorization") {
        if let Ok(auth_str) = auth.to_str() {
            if let Some(token) = auth_str.strip_prefix("Bearer ") {
                return Some(token.trim().to_string());
            }
        }
    }

    // 2. Check X-Carapace-Token header
    if let Some(token) = headers.get("x-carapace-token") {
        if let Ok(token_str) = token.to_str() {
            return Some(token_str.trim().to_string());
        }
    }

    None
}

/// Validate the hooks token against the configured token.
/// Returns true if the token is valid.
pub fn validate_hooks_token(provided: &str, configured: &str) -> bool {
    if provided.is_empty() || configured.is_empty() {
        return false;
    }
    timing_safe_eq(provided, configured)
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
        assert_eq!(result, Some("my-secret-token".to_string()));
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
        assert_eq!(result, Some("another-token".to_string()));
    }

    #[test]
    fn test_extract_query_token_rejected() {
        let headers = HeaderMap::new();
        let uri: Uri = "/hooks/wake?token=query-token&other=value".parse().unwrap();

        let result = extract_hooks_token(&headers, &uri);
        assert_eq!(result, None);
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
        assert_eq!(result, Some("bearer-token".to_string()));
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
