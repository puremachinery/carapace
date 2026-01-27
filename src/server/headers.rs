//! Security headers middleware
//!
//! Adds security-related HTTP headers to responses:
//! - Content-Security-Policy (restrictive default)
//! - Strict-Transport-Security (HSTS)
//! - X-Content-Type-Options: nosniff
//! - X-Frame-Options: DENY
//! - Referrer-Policy: strict-origin-when-cross-origin

use axum::{
    body::Body,
    http::{header, Request, Response},
    middleware::Next,
};
use std::sync::Arc;

/// Security headers configuration
#[derive(Debug, Clone)]
pub struct SecurityHeadersConfig {
    /// Content-Security-Policy header value
    pub csp: String,
    /// Strict-Transport-Security header value (only sent over HTTPS)
    pub hsts: Option<String>,
    /// X-Frame-Options header value
    pub frame_options: String,
    /// X-Content-Type-Options header value
    pub content_type_options: String,
    /// Referrer-Policy header value
    pub referrer_policy: String,
    /// X-XSS-Protection header value (legacy but still useful for older browsers)
    pub xss_protection: String,
    /// Permissions-Policy header value
    pub permissions_policy: Option<String>,
    /// Whether to add HSTS header (should be true only for HTTPS)
    pub enable_hsts: bool,
}

impl Default for SecurityHeadersConfig {
    fn default() -> Self {
        SecurityHeadersConfig {
            // Restrictive default CSP:
            // - default-src 'self': only load resources from same origin
            // - script-src 'self': only execute scripts from same origin
            // - style-src 'self' 'unsafe-inline': allow inline styles (needed for many UIs)
            // - img-src 'self' data: blob:: allow images from same origin, data URIs, and blobs
            // - connect-src 'self' wss: ws:: allow WebSocket connections
            // - frame-ancestors 'none': prevent embedding in iframes
            // - base-uri 'self': restrict <base> tag
            // - form-action 'self': restrict form submissions
            csp: concat!(
                "default-src 'self'; ",
                "script-src 'self'; ",
                "style-src 'self' 'unsafe-inline'; ",
                "img-src 'self' data: blob:; ",
                "connect-src 'self' wss: ws:; ",
                "frame-ancestors 'none'; ",
                "base-uri 'self'; ",
                "form-action 'self'"
            )
            .to_string(),
            // HSTS: 1 year, include subdomains
            hsts: Some("max-age=31536000; includeSubDomains".to_string()),
            frame_options: "DENY".to_string(),
            content_type_options: "nosniff".to_string(),
            referrer_policy: "strict-origin-when-cross-origin".to_string(),
            xss_protection: "1; mode=block".to_string(),
            // Restrict potentially dangerous browser features
            permissions_policy: Some(
                concat!(
                    "accelerometer=(), ",
                    "camera=(), ",
                    "geolocation=(), ",
                    "gyroscope=(), ",
                    "magnetometer=(), ",
                    "microphone=(), ",
                    "payment=(), ",
                    "usb=()"
                )
                .to_string(),
            ),
            enable_hsts: false, // Default to false, enable only for HTTPS
        }
    }
}

impl SecurityHeadersConfig {
    /// Create a new builder for custom configuration
    pub fn builder() -> SecurityHeadersConfigBuilder {
        SecurityHeadersConfigBuilder::default()
    }

    /// Create a configuration suitable for the Control UI
    pub fn for_control_ui() -> Self {
        let mut config = Self::default();
        // Control UI may need to connect to WebSocket on different ports
        config.csp = concat!(
            "default-src 'self'; ",
            "script-src 'self' 'unsafe-eval'; ", // Some bundlers need eval
            "style-src 'self' 'unsafe-inline'; ",
            "img-src 'self' data: blob: https:; ",
            "connect-src 'self' wss: ws: http: https:; ",
            "frame-ancestors 'none'; ",
            "base-uri 'self'; ",
            "form-action 'self'"
        )
        .to_string();
        config
    }

    /// Create a configuration for API-only endpoints
    pub fn for_api() -> Self {
        let mut config = Self::default();
        // API endpoints don't serve HTML, so CSP can be more restrictive
        config.csp = "default-src 'none'; frame-ancestors 'none'".to_string();
        config.frame_options = "DENY".to_string();
        config
    }
}

/// Builder for SecurityHeadersConfig
#[derive(Default)]
pub struct SecurityHeadersConfigBuilder {
    config: SecurityHeadersConfig,
}

impl SecurityHeadersConfigBuilder {
    /// Set the Content-Security-Policy header
    pub fn csp(mut self, csp: impl Into<String>) -> Self {
        self.config.csp = csp.into();
        self
    }

    /// Set the HSTS header value
    pub fn hsts(mut self, hsts: impl Into<String>) -> Self {
        self.config.hsts = Some(hsts.into());
        self
    }

    /// Disable HSTS header
    pub fn no_hsts(mut self) -> Self {
        self.config.hsts = None;
        self
    }

    /// Set the X-Frame-Options header
    pub fn frame_options(mut self, value: impl Into<String>) -> Self {
        self.config.frame_options = value.into();
        self
    }

    /// Set the Referrer-Policy header
    pub fn referrer_policy(mut self, value: impl Into<String>) -> Self {
        self.config.referrer_policy = value.into();
        self
    }

    /// Set the Permissions-Policy header
    pub fn permissions_policy(mut self, value: impl Into<String>) -> Self {
        self.config.permissions_policy = Some(value.into());
        self
    }

    /// Enable HSTS (for HTTPS connections)
    pub fn enable_hsts(mut self, enable: bool) -> Self {
        self.config.enable_hsts = enable;
        self
    }

    /// Build the configuration
    pub fn build(self) -> SecurityHeadersConfig {
        self.config
    }
}

/// Shared state for security headers middleware
#[derive(Clone)]
pub struct SecurityHeadersLayer {
    config: Arc<SecurityHeadersConfig>,
}

impl SecurityHeadersLayer {
    /// Create a new security headers layer with default configuration
    pub fn new() -> Self {
        Self {
            config: Arc::new(SecurityHeadersConfig::default()),
        }
    }

    /// Create a new security headers layer with custom configuration
    pub fn with_config(config: SecurityHeadersConfig) -> Self {
        Self {
            config: Arc::new(config),
        }
    }
}

impl Default for SecurityHeadersLayer {
    fn default() -> Self {
        Self::new()
    }
}

/// Security headers middleware function
///
/// This middleware adds security headers to all responses.
/// Use with `axum::middleware::from_fn_with_state`.
pub async fn security_headers_middleware(
    config: axum::extract::State<Arc<SecurityHeadersConfig>>,
    request: Request<Body>,
    next: Next,
) -> Response<Body> {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();

    // Content-Security-Policy
    if !config.csp.is_empty() {
        if let Ok(value) = config.csp.parse() {
            headers.insert(header::CONTENT_SECURITY_POLICY, value);
        }
    }

    // Strict-Transport-Security (only if enabled and configured)
    if config.enable_hsts {
        if let Some(ref hsts) = config.hsts {
            if let Ok(value) = hsts.parse() {
                headers.insert(header::STRICT_TRANSPORT_SECURITY, value);
            }
        }
    }

    // X-Content-Type-Options
    if let Ok(value) = config.content_type_options.parse() {
        headers.insert(header::X_CONTENT_TYPE_OPTIONS, value);
    }

    // X-Frame-Options
    if let Ok(value) = config.frame_options.parse() {
        headers.insert(header::X_FRAME_OPTIONS, value);
    }

    // Referrer-Policy
    if let Ok(value) = config.referrer_policy.parse() {
        headers.insert(header::REFERRER_POLICY, value);
    }

    // X-XSS-Protection (legacy but still helps older browsers)
    if let Ok(value) = config.xss_protection.parse() {
        headers.insert("x-xss-protection", value);
    }

    // Permissions-Policy
    if let Some(ref policy) = config.permissions_policy {
        if let Ok(value) = policy.parse() {
            headers.insert("permissions-policy", value);
        }
    }

    response
}

/// Convenience function to create security headers middleware layer
pub fn layer() -> SecurityHeadersLayer {
    SecurityHeadersLayer::new()
}

/// Convenience function to create security headers middleware layer with config
pub fn layer_with_config(config: SecurityHeadersConfig) -> SecurityHeadersLayer {
    SecurityHeadersLayer::with_config(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
        middleware,
        routing::get,
        Router,
    };
    use tower::ServiceExt;

    async fn test_handler() -> &'static str {
        "OK"
    }

    fn create_test_router(config: SecurityHeadersConfig) -> Router {
        let config = Arc::new(config);
        Router::new()
            .route("/test", get(test_handler))
            .layer(middleware::from_fn_with_state(
                config.clone(),
                security_headers_middleware,
            ))
            .with_state(config)
    }

    #[tokio::test]
    async fn test_default_security_headers() {
        let router = create_test_router(SecurityHeadersConfig::default());

        let request = Request::builder().uri("/test").body(Body::empty()).unwrap();

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let headers = response.headers();

        // Check CSP
        assert!(headers.contains_key(header::CONTENT_SECURITY_POLICY));
        let csp = headers
            .get(header::CONTENT_SECURITY_POLICY)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(csp.contains("default-src 'self'"));

        // Check X-Content-Type-Options
        assert_eq!(
            headers.get(header::X_CONTENT_TYPE_OPTIONS).unwrap(),
            "nosniff"
        );

        // Check X-Frame-Options
        assert_eq!(headers.get(header::X_FRAME_OPTIONS).unwrap(), "DENY");

        // Check Referrer-Policy
        assert_eq!(
            headers.get(header::REFERRER_POLICY).unwrap(),
            "strict-origin-when-cross-origin"
        );

        // HSTS should NOT be present by default (enable_hsts is false)
        assert!(!headers.contains_key(header::STRICT_TRANSPORT_SECURITY));
    }

    #[tokio::test]
    async fn test_hsts_when_enabled() {
        let config = SecurityHeadersConfig {
            enable_hsts: true,
            ..Default::default()
        };
        let router = create_test_router(config);

        let request = Request::builder().uri("/test").body(Body::empty()).unwrap();

        let response = router.oneshot(request).await.unwrap();
        let headers = response.headers();

        // HSTS should be present when enabled
        assert!(headers.contains_key(header::STRICT_TRANSPORT_SECURITY));
        let hsts = headers
            .get(header::STRICT_TRANSPORT_SECURITY)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(hsts.contains("max-age=31536000"));
    }

    #[tokio::test]
    async fn test_custom_csp() {
        let config = SecurityHeadersConfig::builder()
            .csp("default-src 'none'")
            .build();

        let router = create_test_router(config);

        let request = Request::builder().uri("/test").body(Body::empty()).unwrap();

        let response = router.oneshot(request).await.unwrap();
        let headers = response.headers();

        assert_eq!(
            headers.get(header::CONTENT_SECURITY_POLICY).unwrap(),
            "default-src 'none'"
        );
    }

    #[tokio::test]
    async fn test_api_config() {
        let config = SecurityHeadersConfig::for_api();
        let router = create_test_router(config);

        let request = Request::builder().uri("/test").body(Body::empty()).unwrap();

        let response = router.oneshot(request).await.unwrap();
        let headers = response.headers();

        let csp = headers
            .get(header::CONTENT_SECURITY_POLICY)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(csp.contains("default-src 'none'"));
    }

    #[tokio::test]
    async fn test_control_ui_config() {
        let config = SecurityHeadersConfig::for_control_ui();
        let router = create_test_router(config);

        let request = Request::builder().uri("/test").body(Body::empty()).unwrap();

        let response = router.oneshot(request).await.unwrap();
        let headers = response.headers();

        let csp = headers
            .get(header::CONTENT_SECURITY_POLICY)
            .unwrap()
            .to_str()
            .unwrap();
        // Control UI config should allow more sources
        assert!(csp.contains("connect-src 'self' wss: ws: http: https:"));
    }

    #[tokio::test]
    async fn test_xss_protection_header() {
        let router = create_test_router(SecurityHeadersConfig::default());

        let request = Request::builder().uri("/test").body(Body::empty()).unwrap();

        let response = router.oneshot(request).await.unwrap();
        let headers = response.headers();

        assert_eq!(headers.get("x-xss-protection").unwrap(), "1; mode=block");
    }

    #[tokio::test]
    async fn test_permissions_policy_header() {
        let router = create_test_router(SecurityHeadersConfig::default());

        let request = Request::builder().uri("/test").body(Body::empty()).unwrap();

        let response = router.oneshot(request).await.unwrap();
        let headers = response.headers();

        let policy = headers.get("permissions-policy").unwrap().to_str().unwrap();
        assert!(policy.contains("camera=()"));
        assert!(policy.contains("microphone=()"));
    }

    #[test]
    fn test_builder_chain() {
        let config = SecurityHeadersConfig::builder()
            .csp("custom-csp")
            .hsts("max-age=3600")
            .frame_options("SAMEORIGIN")
            .referrer_policy("no-referrer")
            .enable_hsts(true)
            .build();

        assert_eq!(config.csp, "custom-csp");
        assert_eq!(config.hsts, Some("max-age=3600".to_string()));
        assert_eq!(config.frame_options, "SAMEORIGIN");
        assert_eq!(config.referrer_policy, "no-referrer");
        assert!(config.enable_hsts);
    }

    #[test]
    fn test_builder_no_hsts() {
        let config = SecurityHeadersConfig::builder().no_hsts().build();
        assert!(config.hsts.is_none());
    }

    #[test]
    fn test_default_config() {
        let config = SecurityHeadersConfig::default();
        assert!(!config.csp.is_empty());
        assert!(config.hsts.is_some());
        assert_eq!(config.frame_options, "DENY");
        assert_eq!(config.content_type_options, "nosniff");
        assert!(!config.enable_hsts); // Default should be false
    }

    #[test]
    fn test_layer_creation() {
        let _layer = layer();
        let _layer_with_config = layer_with_config(SecurityHeadersConfig::default());
    }
}
