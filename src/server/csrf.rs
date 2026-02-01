//! CSRF protection middleware
//!
//! Provides Cross-Site Request Forgery protection for state-changing routes:
//! - Token generation (cryptographically random)
//! - Token validation middleware for POST to /control/*
//! - Token stored in session/cookie

use axum::{
    body::Body,
    http::{header, HeaderMap, Method, Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;
use tracing::{debug, warn};

/// CSRF token length in bytes (before base64 encoding)
const TOKEN_BYTES: usize = 32;

/// Default CSRF token validity duration (1 hour)
const DEFAULT_TOKEN_TTL: Duration = Duration::from_secs(3600);

/// Default cookie name for CSRF token
const DEFAULT_COOKIE_NAME: &str = "__Host-csrf";

/// Default cookie name for CSRF session ID (insecure / non-TLS)
const DEFAULT_SESSION_COOKIE: &str = "session";

/// Default cookie name for CSRF session ID (secure / TLS)
const DEFAULT_SESSION_COOKIE_HOST: &str = "__Host-session";

/// Default header name for CSRF token
const DEFAULT_HEADER_NAME: &str = "x-csrf-token";

/// CSRF errors
#[derive(Error, Debug)]
pub enum CsrfError {
    #[error("CSRF token missing")]
    TokenMissing,

    #[error("CSRF token invalid")]
    TokenInvalid,

    #[error("CSRF token expired")]
    TokenExpired,

    #[error("CSRF token generation failed")]
    GenerationFailed,

    #[error("Origin mismatch: expected {expected}, got {actual}")]
    OriginMismatch { expected: String, actual: String },

    #[error("Origin missing")]
    OriginMissing,

    #[error("Origin host missing")]
    OriginHostMissing,
}

/// CSRF protection configuration
#[derive(Debug, Clone)]
pub struct CsrfConfig {
    /// Cookie name for the CSRF token
    pub cookie_name: String,
    /// Header name for the CSRF token
    pub header_name: String,
    /// Token time-to-live
    pub token_ttl: Duration,
    /// Whether to check Origin header
    pub check_origin: bool,
    /// Allowed origins (empty = allow same-origin only)
    pub allowed_origins: Vec<String>,
    /// Routes that require CSRF protection (prefix match)
    pub protected_prefixes: Vec<String>,
    /// Whether CSRF is enabled
    pub enabled: bool,
    /// Use secure cookies (HTTPS only)
    pub secure_cookie: bool,
    /// SameSite cookie attribute
    pub same_site: SameSite,
}

/// SameSite cookie attribute
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SameSite {
    Strict,
    Lax,
    None,
}

impl Default for CsrfConfig {
    fn default() -> Self {
        CsrfConfig {
            cookie_name: DEFAULT_COOKIE_NAME.to_string(),
            header_name: DEFAULT_HEADER_NAME.to_string(),
            token_ttl: DEFAULT_TOKEN_TTL,
            check_origin: true,
            allowed_origins: Vec::new(),
            protected_prefixes: vec!["/control/".to_string()],
            enabled: true,
            secure_cookie: true,
            same_site: SameSite::Strict,
        }
    }
}

impl CsrfConfig {
    /// Create a builder for custom configuration
    pub fn builder() -> CsrfConfigBuilder {
        CsrfConfigBuilder::default()
    }

    /// Check if a path requires CSRF protection
    pub fn requires_protection(&self, path: &str) -> bool {
        self.protected_prefixes.iter().any(|p| path.starts_with(p))
    }
}

/// Builder for CsrfConfig
#[derive(Default)]
pub struct CsrfConfigBuilder {
    config: CsrfConfig,
}

impl CsrfConfigBuilder {
    /// Set the cookie name
    pub fn cookie_name(mut self, name: impl Into<String>) -> Self {
        self.config.cookie_name = name.into();
        self
    }

    /// Set the header name
    pub fn header_name(mut self, name: impl Into<String>) -> Self {
        self.config.header_name = name.into();
        self
    }

    /// Set the token TTL
    pub fn token_ttl(mut self, ttl: Duration) -> Self {
        self.config.token_ttl = ttl;
        self
    }

    /// Set whether to check Origin header
    pub fn check_origin(mut self, check: bool) -> Self {
        self.config.check_origin = check;
        self
    }

    /// Add allowed origins
    pub fn allowed_origins(mut self, origins: Vec<String>) -> Self {
        self.config.allowed_origins = origins;
        self
    }

    /// Set protected route prefixes
    pub fn protected_prefixes(mut self, prefixes: Vec<String>) -> Self {
        self.config.protected_prefixes = prefixes;
        self
    }

    /// Enable or disable CSRF protection
    pub fn enabled(mut self, enabled: bool) -> Self {
        self.config.enabled = enabled;
        self
    }

    /// Set secure cookie flag
    pub fn secure_cookie(mut self, secure: bool) -> Self {
        self.config.secure_cookie = secure;
        self
    }

    /// Set SameSite attribute
    pub fn same_site(mut self, same_site: SameSite) -> Self {
        self.config.same_site = same_site;
        self
    }

    /// Build the configuration
    pub fn build(self) -> CsrfConfig {
        self.config
    }
}

/// CSRF token with metadata
#[derive(Debug, Clone)]
pub struct CsrfToken {
    /// The token value (base64url encoded)
    pub value: String,
    /// When the token was created
    pub created_at: Instant,
    /// Token TTL
    pub ttl: Duration,
}

impl CsrfToken {
    /// Check if the token is expired
    pub fn is_expired(&self) -> bool {
        self.created_at.elapsed() > self.ttl
    }
}

/// CSRF token store for managing tokens
#[derive(Clone)]
pub struct CsrfTokenStore {
    /// Map of session ID to token
    tokens: Arc<RwLock<HashMap<String, CsrfToken>>>,
    /// Configuration
    config: Arc<CsrfConfig>,
}

impl CsrfTokenStore {
    /// Create a new token store
    pub fn new(config: CsrfConfig) -> Self {
        CsrfTokenStore {
            tokens: Arc::new(RwLock::new(HashMap::new())),
            config: Arc::new(config),
        }
    }

    /// Generate a new CSRF token for a session
    pub fn generate_token(&self, session_id: &str) -> Result<CsrfToken, CsrfError> {
        let token_bytes = generate_random_bytes(TOKEN_BYTES)?;
        let token_value = URL_SAFE_NO_PAD.encode(&token_bytes);

        let token = CsrfToken {
            value: token_value,
            created_at: Instant::now(),
            ttl: self.config.token_ttl,
        };

        let mut tokens = self.tokens.write();
        tokens.insert(session_id.to_string(), token.clone());

        // Clean up expired tokens periodically
        if tokens.len() > 1000 {
            tokens.retain(|_, t| !t.is_expired());
        }

        Ok(token)
    }

    /// Validate a CSRF token
    pub fn validate_token(&self, session_id: &str, provided_token: &str) -> Result<(), CsrfError> {
        let tokens = self.tokens.read();

        let stored_token = tokens.get(session_id).ok_or(CsrfError::TokenMissing)?;

        if stored_token.is_expired() {
            return Err(CsrfError::TokenExpired);
        }

        // Timing-safe comparison
        if !crate::auth::timing_safe_eq(&stored_token.value, provided_token) {
            return Err(CsrfError::TokenInvalid);
        }

        Ok(())
    }

    /// Get the current token for a session (if valid)
    pub fn get_token(&self, session_id: &str) -> Option<CsrfToken> {
        let tokens = self.tokens.read();
        tokens.get(session_id).filter(|t| !t.is_expired()).cloned()
    }

    /// Remove a token (e.g., on logout)
    pub fn revoke_token(&self, session_id: &str) {
        let mut tokens = self.tokens.write();
        tokens.remove(session_id);
    }

    /// Get the configuration
    pub fn config(&self) -> &CsrfConfig {
        &self.config
    }
}

/// Generate cryptographically random bytes using getrandom
fn generate_random_bytes(len: usize) -> Result<Vec<u8>, CsrfError> {
    let mut bytes = vec![0u8; len];
    getrandom::getrandom(&mut bytes).map_err(|_| CsrfError::GenerationFailed)?;
    Ok(bytes)
}

/// Extract a cookie value by name from the request headers.
fn extract_cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    let cookie = headers.get(header::COOKIE)?;
    let cookie_str = cookie.to_str().ok()?;
    let prefix = format!("{}=", name);

    cookie_str
        .split(';')
        .map(|part| part.trim())
        .find_map(|part| part.strip_prefix(&prefix).map(|value| value.to_string()))
}

pub fn csrf_cookie_name(config: &CsrfConfig) -> &str {
    if config.secure_cookie {
        &config.cookie_name
    } else {
        config
            .cookie_name
            .strip_prefix("__Host-")
            .unwrap_or(&config.cookie_name)
    }
}

fn session_cookie_name(config: &CsrfConfig) -> &str {
    if config.secure_cookie {
        DEFAULT_SESSION_COOKIE_HOST
    } else {
        DEFAULT_SESSION_COOKIE
    }
}

/// Extract session ID from cookies
fn extract_session_id(headers: &HeaderMap, config: &CsrfConfig) -> Option<String> {
    extract_cookie_value(headers, session_cookie_name(config))
}

/// Extract CSRF token from request
fn extract_csrf_token(headers: &HeaderMap, config: &CsrfConfig) -> Option<String> {
    // Check header first
    if let Some(token) = headers.get(&config.header_name) {
        if let Ok(token_str) = token.to_str() {
            return Some(token_str.to_string());
        }
    }

    None
}

/// Check Origin header
fn check_origin(
    headers: &HeaderMap,
    config: &CsrfConfig,
    host: Option<&str>,
) -> Result<(), CsrfError> {
    if !config.check_origin {
        return Ok(());
    }

    let origin = headers
        .get(header::ORIGIN)
        .and_then(|v| v.to_str().ok())
        .or_else(|| headers.get(header::REFERER).and_then(|v| v.to_str().ok()));

    match origin {
        Some(origin) => {
            // Check against allowed origins
            if !config.allowed_origins.is_empty()
                && config.allowed_origins.iter().any(|o| origin.starts_with(o))
            {
                return Ok(());
            }

            // Check same-origin
            if let Some(host) = host {
                // Extract origin host
                let origin_host = origin
                    .strip_prefix("http://")
                    .or_else(|| origin.strip_prefix("https://"))
                    .unwrap_or(origin)
                    .split('/')
                    .next()
                    .unwrap_or("");

                if origin_host == host || origin_host.ends_with(&format!(".{}", host)) {
                    return Ok(());
                }

                return Err(CsrfError::OriginMismatch {
                    expected: host.to_string(),
                    actual: origin_host.to_string(),
                });
            }

            // No host to compare against; fail closed unless explicitly allowed.
            Err(CsrfError::OriginHostMissing)
        }
        None => {
            debug!("No Origin header in CSRF-protected request");
            Err(CsrfError::OriginMissing)
        }
    }
}

/// CSRF middleware shared state
#[derive(Clone)]
pub struct CsrfLayer {
    store: CsrfTokenStore,
}

impl CsrfLayer {
    /// Create a new CSRF layer with default configuration
    pub fn new() -> Self {
        Self {
            store: CsrfTokenStore::new(CsrfConfig::default()),
        }
    }

    /// Create a new CSRF layer with custom configuration
    pub fn with_config(config: CsrfConfig) -> Self {
        Self {
            store: CsrfTokenStore::new(config),
        }
    }

    /// Get the token store
    pub fn store(&self) -> &CsrfTokenStore {
        &self.store
    }
}

impl Default for CsrfLayer {
    fn default() -> Self {
        Self::new()
    }
}

/// Determine if CSRF validation is needed for this request.
///
/// Returns `true` when the HTTP method is state-changing (POST, PUT, DELETE,
/// PATCH) **and** the path matches a protected prefix.
fn should_validate_csrf(method: &Method, path: &str, config: &CsrfConfig) -> bool {
    matches!(
        *method,
        Method::POST | Method::PUT | Method::DELETE | Method::PATCH
    ) && config.requires_protection(path)
}

/// Verify the Origin header and extract the session ID and token from the
/// request.  Returns `(session_id, token)` on success, or an HTTP error
/// response when any pre-condition fails.
#[allow(clippy::result_large_err)]
fn extract_origin_session_and_token(
    headers: &HeaderMap,
    config: &CsrfConfig,
) -> Result<Option<(String, String)>, Response<Body>> {
    // Get Host header for origin check
    let host = headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.split(':').next().unwrap_or(s));

    // Extract session ID
    let session_id = match extract_session_id(headers, config) {
        Some(id) => id,
        None => return Ok(None),
    };

    // Check Origin header
    if let Err(e) = check_origin(headers, config, host) {
        warn!("CSRF origin check failed: {}", e);
        return Err(csrf_error_response(e));
    };

    // Extract token
    let provided_token = match extract_csrf_token(headers, config) {
        Some(token) => token,
        None => {
            warn!("CSRF: No token provided");
            return Err(csrf_error_response(CsrfError::TokenMissing));
        }
    };

    Ok(Some((session_id, provided_token)))
}

/// Perform origin checking, token extraction, and token validation.
///
/// Returns `Ok(())` when the request passes all CSRF checks, or an error
/// response that should be returned to the client.
#[allow(clippy::result_large_err)]
fn extract_and_validate_token(
    headers: &HeaderMap,
    config: &CsrfConfig,
    store: &CsrfTokenStore,
) -> Result<(), Response<Body>> {
    let Some((session_id, provided_token)) = extract_origin_session_and_token(headers, config)?
    else {
        return Ok(());
    };

    if let Err(e) = store.validate_token(&session_id, &provided_token) {
        warn!("CSRF validation failed: {}", e);
        return Err(csrf_error_response(e));
    }

    Ok(())
}

/// CSRF protection middleware
///
/// Validates CSRF tokens for state-changing requests to protected routes.
pub async fn csrf_middleware(
    store: axum::extract::State<CsrfTokenStore>,
    request: Request<Body>,
    next: Next,
) -> Response<Body> {
    let config = store.config();

    // Skip if CSRF is disabled
    if !config.enabled {
        return next.run(request).await;
    }

    let method = request.method().clone();
    let path = request.uri().path().to_string();
    let headers = request.headers().clone();

    if !should_validate_csrf(&method, &path, config) {
        return next.run(request).await;
    }

    if let Err(response) = extract_and_validate_token(&headers, config, &store) {
        return response;
    }

    debug!("CSRF validation passed for {}", path);
    next.run(request).await
}

/// Generate CSRF error response
fn csrf_error_response(error: CsrfError) -> Response<Body> {
    let message = match error {
        CsrfError::TokenMissing => "CSRF token missing",
        CsrfError::TokenInvalid => "CSRF token invalid",
        CsrfError::TokenExpired => "CSRF token expired",
        CsrfError::OriginMismatch { .. } => "Origin mismatch",
        CsrfError::OriginMissing => "Origin missing",
        CsrfError::OriginHostMissing => "Origin host missing",
        CsrfError::GenerationFailed => "Internal error",
    };

    (
        StatusCode::FORBIDDEN,
        [(header::CONTENT_TYPE, "application/json; charset=utf-8")],
        format!(
            r#"{{"error":{{"code":"CSRF_ERROR","message":"{}"}}}}"#,
            message
        ),
    )
        .into_response()
}

/// Generate a Set-Cookie header value for CSRF token
pub fn csrf_cookie_header(token: &CsrfToken, config: &CsrfConfig) -> String {
    let same_site = match config.same_site {
        SameSite::Strict => "Strict",
        SameSite::Lax => "Lax",
        SameSite::None => "None",
    };

    let secure = if config.secure_cookie { "; Secure" } else { "" };
    let max_age = config.token_ttl.as_secs();
    let cookie_name = csrf_cookie_name(config);

    format!(
        "{}={}; Path=/; SameSite={}{}; Max-Age={}",
        cookie_name, token.value, same_site, secure, max_age
    )
}

fn generate_session_id() -> Result<String, CsrfError> {
    let session_bytes = generate_random_bytes(TOKEN_BYTES)?;
    Ok(URL_SAFE_NO_PAD.encode(&session_bytes))
}

fn session_cookie_header(session_id: &str, config: &CsrfConfig) -> String {
    let same_site = match config.same_site {
        SameSite::Strict => "Strict",
        SameSite::Lax => "Lax",
        SameSite::None => "None",
    };

    let secure = if config.secure_cookie { "; Secure" } else { "" };
    let max_age = config.token_ttl.as_secs();

    let cookie_name = session_cookie_name(config);
    format!(
        "{}={}; Path=/; HttpOnly; SameSite={}{}; Max-Age={}",
        cookie_name, session_id, same_site, secure, max_age
    )
}

pub fn ensure_csrf_cookies(
    headers: &HeaderMap,
    store: &CsrfTokenStore,
) -> Result<Vec<String>, CsrfError> {
    let config = store.config();
    if !config.enabled {
        return Ok(Vec::new());
    }

    let existing_session = extract_session_id(headers, config);
    let session_missing = existing_session.is_none();
    let session_id = match existing_session {
        Some(id) => id,
        None => generate_session_id()?,
    };

    let mut set_cookies = Vec::new();
    if session_missing {
        set_cookies.push(session_cookie_header(&session_id, config));
    }

    let token = store
        .get_token(&session_id)
        .unwrap_or(store.generate_token(&session_id)?);
    let existing_token = extract_cookie_value(headers, csrf_cookie_name(config));
    if existing_token.as_deref() != Some(token.value.as_str()) {
        set_cookies.push(csrf_cookie_header(&token, config));
    }

    Ok(set_cookies)
}

/// Convenience function to create CSRF layer
pub fn layer() -> CsrfLayer {
    CsrfLayer::new()
}

/// Convenience function to create CSRF layer with config
pub fn layer_with_config(config: CsrfConfig) -> CsrfLayer {
    CsrfLayer::with_config(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_csrf_token_expiry() {
        // Use a zero TTL so the token is immediately expired.
        // Avoids subtracting a large duration from Instant::now(), which panics
        // on Windows when the result would precede the process start time.
        let token = CsrfToken {
            value: "test".to_string(),
            created_at: Instant::now(),
            ttl: Duration::from_secs(0), // already expired
        };

        // Give a tiny delay so elapsed() > 0
        std::thread::sleep(Duration::from_millis(1));
        assert!(token.is_expired());
    }

    #[test]
    fn test_csrf_token_not_expired() {
        let token = CsrfToken {
            value: "test".to_string(),
            created_at: Instant::now(),
            ttl: Duration::from_secs(3600),
        };

        assert!(!token.is_expired());
    }

    #[test]
    fn test_token_store_generate_and_validate() {
        let store = CsrfTokenStore::new(CsrfConfig::default());

        let token = store.generate_token("session-1").unwrap();
        assert!(!token.value.is_empty());

        // Valid token should pass
        assert!(store.validate_token("session-1", &token.value).is_ok());

        // Wrong token should fail
        assert!(store.validate_token("session-1", "wrong-token").is_err());

        // Wrong session should fail
        assert!(store.validate_token("session-2", &token.value).is_err());
    }

    #[test]
    fn test_token_store_revoke() {
        let store = CsrfTokenStore::new(CsrfConfig::default());

        let _token = store.generate_token("session-1").unwrap();
        assert!(store.get_token("session-1").is_some());

        store.revoke_token("session-1");
        assert!(store.get_token("session-1").is_none());
    }

    #[test]
    fn test_config_requires_protection() {
        let config = CsrfConfig::default();

        assert!(config.requires_protection("/control/status"));
        assert!(!config.requires_protection("/hooks/wake"));
        assert!(!config.requires_protection("/tools/invoke"));
        assert!(!config.requires_protection("/api/status"));
        assert!(!config.requires_protection("/"));
    }

    #[test]
    fn test_config_builder() {
        let config = CsrfConfig::builder()
            .cookie_name("my-csrf")
            .header_name("x-my-csrf")
            .token_ttl(Duration::from_secs(1800))
            .check_origin(false)
            .enabled(true)
            .secure_cookie(false)
            .same_site(SameSite::Lax)
            .build();

        assert_eq!(config.cookie_name, "my-csrf");
        assert_eq!(config.header_name, "x-my-csrf");
        assert_eq!(config.token_ttl, Duration::from_secs(1800));
        assert!(!config.check_origin);
        assert!(config.enabled);
        assert!(!config.secure_cookie);
        assert_eq!(config.same_site, SameSite::Lax);
    }

    #[test]
    fn test_timing_safe_equal() {
        use crate::auth::timing_safe_eq;
        assert!(timing_safe_eq("secret", "secret"));
        assert!(!timing_safe_eq("secret", "secret1"));
        assert!(!timing_safe_eq("secret1", "secret"));
        assert!(!timing_safe_eq("", "secret"));
    }

    #[test]
    fn test_csrf_cookie_header() {
        let token = CsrfToken {
            value: "test-token-value".to_string(),
            created_at: Instant::now(),
            ttl: Duration::from_secs(3600),
        };

        let config = CsrfConfig {
            cookie_name: "__Host-csrf".to_string(),
            secure_cookie: true,
            same_site: SameSite::Strict,
            token_ttl: Duration::from_secs(3600),
            ..Default::default()
        };

        let header = csrf_cookie_header(&token, &config);
        assert!(header.contains("__Host-csrf=test-token-value"));
        assert!(header.contains("SameSite=Strict"));
        assert!(header.contains("Secure"));
        assert!(header.contains("Max-Age=3600"));
        assert!(!header.contains("HttpOnly"));
    }

    #[test]
    fn test_csrf_cookie_header_no_secure() {
        let token = CsrfToken {
            value: "test-token".to_string(),
            created_at: Instant::now(),
            ttl: Duration::from_secs(3600),
        };

        let config = CsrfConfig {
            secure_cookie: false,
            same_site: SameSite::Lax,
            ..Default::default()
        };

        let header = csrf_cookie_header(&token, &config);
        assert!(!header.contains("Secure"));
        assert!(header.contains("SameSite=Lax"));
    }

    #[test]
    fn test_layer_creation() {
        let _layer = layer();
        let _layer_with_config = layer_with_config(CsrfConfig::default());
    }

    #[test]
    fn test_default_config() {
        let config = CsrfConfig::default();
        assert_eq!(config.cookie_name, "__Host-csrf");
        assert_eq!(config.header_name, "x-csrf-token");
        assert_eq!(config.token_ttl, Duration::from_secs(3600));
        assert!(config.check_origin);
        assert!(config.enabled);
        assert!(config.secure_cookie);
        assert_eq!(config.same_site, SameSite::Strict);
    }

    #[test]
    fn test_random_bytes_generation() {
        let bytes1 = generate_random_bytes(32).unwrap();
        let bytes2 = generate_random_bytes(32).unwrap();

        assert_eq!(bytes1.len(), 32);
        assert_eq!(bytes2.len(), 32);
        // Tokens should be different (extremely high probability)
        assert_ne!(bytes1, bytes2);
    }

    #[test]
    fn test_extract_csrf_token_from_header() {
        let config = CsrfConfig::default();
        let mut headers = HeaderMap::new();
        headers.insert("x-csrf-token", "my-token".parse().unwrap());

        let token = extract_csrf_token(&headers, &config);
        assert_eq!(token, Some("my-token".to_string()));
    }

    #[test]
    fn test_extract_csrf_token_from_cookie() {
        let config = CsrfConfig::default();
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            "__Host-csrf=cookie-token; other=value".parse().unwrap(),
        );

        let token = extract_csrf_token(&headers, &config);
        assert_eq!(token, None);
    }

    #[test]
    fn test_extract_csrf_token_header_precedence() {
        let config = CsrfConfig::default();
        let mut headers = HeaderMap::new();
        headers.insert("x-csrf-token", "header-token".parse().unwrap());
        headers.insert(header::COOKIE, "__Host-csrf=cookie-token".parse().unwrap());

        // Header should be used; cookie is ignored.
        let token = extract_csrf_token(&headers, &config);
        assert_eq!(token, Some("header-token".to_string()));
    }

    #[test]
    fn test_missing_session_skips_csrf_validation() {
        let store = CsrfTokenStore::new(CsrfConfig::default());
        let headers = HeaderMap::new();

        assert!(extract_and_validate_token(&headers, store.config(), &store).is_ok());
    }

    #[test]
    fn test_missing_origin_rejected_when_session_present() {
        let store = CsrfTokenStore::new(CsrfConfig::default());
        let token = store.generate_token("session-1").unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, "localhost".parse().unwrap());
        headers.insert("x-csrf-token", token.value.parse().unwrap());
        headers.insert(
            header::COOKIE,
            format!("__Host-session=session-1; __Host-csrf={}", token.value)
                .parse()
                .unwrap(),
        );

        let response = extract_and_validate_token(&headers, store.config(), &store)
            .expect_err("origin should be required when session cookie exists");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn test_missing_host_rejected_when_session_present() {
        let store = CsrfTokenStore::new(CsrfConfig::default());
        let token = store.generate_token("session-1").unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(header::ORIGIN, "https://example.com".parse().unwrap());
        headers.insert("x-csrf-token", token.value.parse().unwrap());
        headers.insert(
            header::COOKIE,
            format!("__Host-session=session-1; __Host-csrf={}", token.value)
                .parse()
                .unwrap(),
        );

        let response = extract_and_validate_token(&headers, store.config(), &store)
            .expect_err("host should be required when session cookie exists");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn test_ensure_csrf_cookies_sets_session_and_token() {
        let store = CsrfTokenStore::new(CsrfConfig::default());
        let headers = HeaderMap::new();

        let cookies = ensure_csrf_cookies(&headers, &store).unwrap();
        assert_eq!(cookies.len(), 2);
        assert!(cookies.iter().any(|c| c.starts_with("__Host-session=")));
        assert!(cookies.iter().any(|c| c.starts_with("__Host-csrf=")));
    }

    #[test]
    fn test_ensure_csrf_cookies_noop_when_present() {
        let store = CsrfTokenStore::new(CsrfConfig::default());
        let token = store.generate_token("session-1").unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            format!("__Host-session=session-1; __Host-csrf={}", token.value)
                .parse()
                .unwrap(),
        );

        let cookies = ensure_csrf_cookies(&headers, &store).unwrap();
        assert!(cookies.is_empty());
    }

    #[test]
    fn test_cookie_names_when_insecure() {
        let config = CsrfConfig {
            secure_cookie: false,
            ..Default::default()
        };

        assert_eq!(csrf_cookie_name(&config), "csrf");
        assert_eq!(session_cookie_name(&config), "session");
    }

    #[test]
    fn test_csrf_layer_store_access() {
        let layer = CsrfLayer::new();
        let token = layer.store().generate_token("test-session").unwrap();
        assert!(!token.value.is_empty());
    }
}
