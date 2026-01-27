//! Wasmtime plugin host
//!
//! Implements the host interface for WASM plugins as defined in wit/plugin.wit.
//! Provides logging, config access, credential storage, and HTTP/media fetch
//! with security enforcement.

use std::sync::Arc;
use parking_lot::RwLock;
use serde_json::Value;
use thiserror::Error;

use crate::config;
use crate::credentials::{CredentialBackend, CredentialStore};

use super::capabilities::{
    CapabilityError, ConfigEnforcer, CredentialEnforcer, RateLimiterRegistry, SsrfProtection,
};

/// Maximum message size for logging (4KB)
pub const MAX_LOG_MESSAGE_SIZE: usize = 4 * 1024;

/// Maximum HTTP request body size (10MB)
pub const MAX_HTTP_BODY_SIZE: usize = 10 * 1024 * 1024;

/// Maximum HTTP response body size (10MB)
pub const MAX_HTTP_RESPONSE_SIZE: usize = 10 * 1024 * 1024;

/// Maximum URL length
pub const MAX_URL_LENGTH: usize = 2048;

/// Default HTTP timeout in milliseconds
pub const DEFAULT_HTTP_TIMEOUT_MS: u32 = 30_000;

/// Maximum HTTP timeout in milliseconds
pub const MAX_HTTP_TIMEOUT_MS: u32 = 60_000;

/// Host errors
#[derive(Error, Debug, Clone)]
pub enum HostError {
    #[error("Capability error: {0}")]
    Capability(#[from] CapabilityError),

    #[error("Credential error: {0}")]
    Credential(String),

    #[error("Config error: {0}")]
    Config(String),

    #[error("HTTP error: {0}")]
    Http(String),

    #[error("Media fetch error: {0}")]
    MediaFetch(String),

    #[error("Message too long: {size} bytes (max {max})")]
    MessageTooLong { size: usize, max: usize },

    #[error("URL too long: {size} chars (max {max})")]
    UrlTooLong { size: usize, max: usize },

    #[error("Body too large: {size} bytes (max {max})")]
    BodyTooLarge { size: usize, max: usize },
}

/// HTTP request from plugin
#[derive(Debug, Clone)]
pub struct HttpRequest {
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<Vec<u8>>,
}

/// HTTP response to plugin
#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Option<Vec<u8>>,
}

/// Media fetch result
#[derive(Debug, Clone)]
pub struct MediaFetchResult {
    pub ok: bool,
    pub local_path: Option<String>,
    pub mime_type: Option<String>,
    pub size: Option<u64>,
    pub error: Option<String>,
}

/// Plugin host context
///
/// Holds all the state needed to execute host functions for a plugin.
/// Each plugin instance gets its own PluginHostContext.
pub struct PluginHostContext<B: CredentialBackend + 'static> {
    /// Plugin ID (used for isolation and namespacing)
    plugin_id: String,

    /// Credential store
    credential_store: Arc<CredentialStore<B>>,

    /// Rate limiter registry (shared across all plugins)
    rate_limiters: Arc<RateLimiterRegistry>,

    /// Cached config (loaded lazily)
    config_cache: RwLock<Option<Value>>,
}

impl<B: CredentialBackend + 'static> PluginHostContext<B> {
    /// Create a new plugin host context
    pub fn new(
        plugin_id: String,
        credential_store: Arc<CredentialStore<B>>,
        rate_limiters: Arc<RateLimiterRegistry>,
    ) -> Self {
        Self {
            plugin_id,
            credential_store,
            rate_limiters,
            config_cache: RwLock::new(None),
        }
    }

    /// Get the plugin ID
    pub fn plugin_id(&self) -> &str {
        &self.plugin_id
    }

    // ============== Logging Functions ==============

    /// Log a debug message
    pub fn log_debug(&self, message: &str) -> Result<(), HostError> {
        self.log_with_level(tracing::Level::DEBUG, message)
    }

    /// Log an info message
    pub fn log_info(&self, message: &str) -> Result<(), HostError> {
        self.log_with_level(tracing::Level::INFO, message)
    }

    /// Log a warning message
    pub fn log_warn(&self, message: &str) -> Result<(), HostError> {
        self.log_with_level(tracing::Level::WARN, message)
    }

    /// Log an error message
    pub fn log_error(&self, message: &str) -> Result<(), HostError> {
        self.log_with_level(tracing::Level::ERROR, message)
    }

    /// Internal logging helper with rate limiting
    fn log_with_level(&self, level: tracing::Level, message: &str) -> Result<(), HostError> {
        // Check rate limit
        self.rate_limiters.check_log_message(&self.plugin_id)?;

        // Truncate message if too long
        let truncated = if message.len() > MAX_LOG_MESSAGE_SIZE {
            &message[..MAX_LOG_MESSAGE_SIZE]
        } else {
            message
        };

        // Log with plugin context
        match level {
            tracing::Level::DEBUG => {
                tracing::debug!(plugin_id = %self.plugin_id, "{}", truncated);
            }
            tracing::Level::INFO => {
                tracing::info!(plugin_id = %self.plugin_id, "{}", truncated);
            }
            tracing::Level::WARN => {
                tracing::warn!(plugin_id = %self.plugin_id, "{}", truncated);
            }
            tracing::Level::ERROR => {
                tracing::error!(plugin_id = %self.plugin_id, "{}", truncated);
            }
            _ => {
                tracing::trace!(plugin_id = %self.plugin_id, "{}", truncated);
            }
        }

        Ok(())
    }

    // ============== Config Functions ==============

    /// Get a config value (scoped to plugins.<plugin-id>.*)
    ///
    /// The key should be relative to the plugin's config namespace.
    /// For example, calling config_get("webhook_url") will read
    /// the config value at "plugins.<plugin-id>.webhook_url".
    pub fn config_get(&self, key: &str) -> Result<Option<String>, HostError> {
        // Build the full config key
        let full_key = ConfigEnforcer::full_key(&self.plugin_id, key);

        // Verify access is allowed (defense in depth)
        ConfigEnforcer::check_access(&self.plugin_id, &full_key)?;

        // Load config if not cached
        let config = self.get_or_load_config()?;

        // Navigate to the key
        let value = self.get_config_value(&config, &full_key);

        // Convert to string
        match value {
            Some(Value::String(s)) => Ok(Some(s.clone())),
            Some(Value::Number(n)) => Ok(Some(n.to_string())),
            Some(Value::Bool(b)) => Ok(Some(b.to_string())),
            Some(Value::Null) => Ok(None),
            Some(v) => Ok(Some(v.to_string())), // Arrays/objects as JSON
            None => Ok(None),
        }
    }

    /// Get or load the config
    fn get_or_load_config(&self) -> Result<Value, HostError> {
        // Check cache first
        {
            let cache = self.config_cache.read();
            if let Some(ref config) = *cache {
                return Ok(config.clone());
            }
        }

        // Load config
        let config = config::load_config().map_err(|e| HostError::Config(e.to_string()))?;

        // Cache it
        {
            let mut cache = self.config_cache.write();
            *cache = Some(config.clone());
        }

        Ok(config)
    }

    /// Navigate a JSON value by dot-separated path
    fn get_config_value<'a>(&self, config: &'a Value, path: &str) -> Option<&'a Value> {
        let mut current = config;

        for part in path.split('.') {
            match current {
                Value::Object(obj) => {
                    current = obj.get(part)?;
                }
                _ => return None,
            }
        }

        Some(current)
    }

    // ============== Credential Functions ==============

    /// Get a credential (auto-prefixed with plugin ID)
    pub async fn credential_get(&self, key: &str) -> Result<Option<String>, HostError> {
        // Validate key
        CredentialEnforcer::validate_key(key)?;

        // Build the prefixed key
        let prefixed = CredentialEnforcer::prefix_key(&self.plugin_id, key);

        // Get from credential store
        self.credential_store
            .plugin_get(&self.plugin_id, "credential", &prefixed)
            .await
            .map_err(|e| HostError::Credential(e.to_string()))
    }

    /// Set a credential (auto-prefixed with plugin ID)
    pub async fn credential_set(&self, key: &str, value: &str) -> Result<bool, HostError> {
        // Validate key
        CredentialEnforcer::validate_key(key)?;

        // Build the prefixed key
        let prefixed = CredentialEnforcer::prefix_key(&self.plugin_id, key);

        // Set in credential store
        match self
            .credential_store
            .plugin_set(&self.plugin_id, "credential", &prefixed, value)
            .await
        {
            Ok(()) => Ok(true),
            Err(e) => {
                tracing::warn!(
                    plugin_id = %self.plugin_id,
                    key = %key,
                    error = %e,
                    "Failed to set credential"
                );
                Ok(false)
            }
        }
    }

    // ============== HTTP Functions ==============

    /// Fetch an HTTP resource with SSRF protection
    pub async fn http_fetch(&self, req: HttpRequest) -> Result<HttpResponse, HostError> {
        // Validate URL length
        if req.url.len() > MAX_URL_LENGTH {
            return Err(HostError::UrlTooLong {
                size: req.url.len(),
                max: MAX_URL_LENGTH,
            });
        }

        // Validate URL for SSRF
        SsrfProtection::validate_url(&req.url)?;

        // Check rate limit
        self.rate_limiters.check_http_request(&self.plugin_id)?;

        // Validate body size
        if let Some(ref body) = req.body {
            if body.len() > MAX_HTTP_BODY_SIZE {
                return Err(HostError::BodyTooLarge {
                    size: body.len(),
                    max: MAX_HTTP_BODY_SIZE,
                });
            }
        }

        // Validate method
        let method = req.method.to_uppercase();
        if !["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"].contains(&method.as_str())
        {
            return Err(HostError::Http(format!("Invalid HTTP method: {}", method)));
        }

        // In a real implementation, this would make the actual HTTP request.
        // For now, we return a placeholder response.
        // The actual HTTP client implementation would go here.
        tracing::debug!(
            plugin_id = %self.plugin_id,
            method = %method,
            url = %req.url,
            "HTTP fetch request"
        );

        // Placeholder: return 501 Not Implemented
        // In production, this would use reqwest or similar
        Ok(HttpResponse {
            status: 501,
            headers: vec![("Content-Type".to_string(), "text/plain".to_string())],
            body: Some(b"HTTP fetch not yet implemented".to_vec()),
        })
    }

    // ============== Media Functions ==============

    /// Fetch media with SSRF protection
    pub async fn media_fetch(
        &self,
        url: &str,
        max_bytes: Option<u64>,
        timeout_ms: Option<u32>,
    ) -> Result<MediaFetchResult, HostError> {
        // Validate URL length
        if url.len() > MAX_URL_LENGTH {
            return Err(HostError::UrlTooLong {
                size: url.len(),
                max: MAX_URL_LENGTH,
            });
        }

        // Validate URL for SSRF
        SsrfProtection::validate_url(url)?;

        // Check rate limit (media fetch counts as HTTP request)
        self.rate_limiters.check_http_request(&self.plugin_id)?;

        // Validate timeout
        let _timeout = timeout_ms
            .unwrap_or(DEFAULT_HTTP_TIMEOUT_MS)
            .min(MAX_HTTP_TIMEOUT_MS);

        // In a real implementation, this would:
        // 1. Fetch the media from the URL
        // 2. Save to a temporary file
        // 3. Return the path and metadata

        tracing::debug!(
            plugin_id = %self.plugin_id,
            url = %url,
            max_bytes = ?max_bytes,
            "Media fetch request"
        );

        // Placeholder response
        Ok(MediaFetchResult {
            ok: false,
            local_path: None,
            mime_type: None,
            size: None,
            error: Some("Media fetch not yet implemented".to_string()),
        })
    }
}

/// Builder for creating plugin host contexts
pub struct PluginHostContextBuilder<B: CredentialBackend + 'static> {
    credential_store: Option<Arc<CredentialStore<B>>>,
    rate_limiters: Option<Arc<RateLimiterRegistry>>,
}

impl<B: CredentialBackend + 'static> Default for PluginHostContextBuilder<B> {
    fn default() -> Self {
        Self::new()
    }
}

impl<B: CredentialBackend + 'static> PluginHostContextBuilder<B> {
    pub fn new() -> Self {
        Self {
            credential_store: None,
            rate_limiters: None,
        }
    }

    pub fn credential_store(mut self, store: Arc<CredentialStore<B>>) -> Self {
        self.credential_store = Some(store);
        self
    }

    pub fn rate_limiters(mut self, limiters: Arc<RateLimiterRegistry>) -> Self {
        self.rate_limiters = Some(limiters);
        self
    }

    pub fn build(self, plugin_id: String) -> Result<PluginHostContext<B>, HostError> {
        let credential_store = self
            .credential_store
            .ok_or_else(|| HostError::Config("Credential store not configured".to_string()))?;

        let rate_limiters = self
            .rate_limiters
            .unwrap_or_else(|| Arc::new(RateLimiterRegistry::new()));

        Ok(PluginHostContext::new(
            plugin_id,
            credential_store,
            rate_limiters,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credentials::MockCredentialBackend;
    use tempfile::tempdir;

    async fn create_test_context(
        plugin_id: &str,
    ) -> PluginHostContext<MockCredentialBackend> {
        let temp_dir = tempdir().unwrap();
        let backend = MockCredentialBackend::new(true);
        let credential_store = Arc::new(
            CredentialStore::new(backend, temp_dir.path().to_path_buf())
                .await
                .unwrap(),
        );

        PluginHostContext::new(
            plugin_id.to_string(),
            credential_store,
            Arc::new(RateLimiterRegistry::new()),
        )
    }

    #[tokio::test]
    async fn test_logging_rate_limit() {
        let ctx = create_test_context("test-plugin").await;

        // Should allow up to the rate limit
        for _ in 0..super::super::capabilities::LOG_RATE_LIMIT_PER_MINUTE {
            assert!(ctx.log_info("test message").is_ok());
        }

        // Next should fail
        let result = ctx.log_info("one more");
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_http_fetch_ssrf_blocking() {
        let ctx = create_test_context("test-plugin").await;

        // Should block localhost
        let req = HttpRequest {
            method: "GET".to_string(),
            url: "http://localhost/secret".to_string(),
            headers: vec![],
            body: None,
        };

        let result = ctx.http_fetch(req).await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            HostError::Capability(CapabilityError::SsrfBlocked(_))
        ));
    }

    #[tokio::test]
    async fn test_http_fetch_rate_limit() {
        let ctx = create_test_context("test-plugin").await;

        // Make requests up to the limit
        for _ in 0..super::super::capabilities::HTTP_RATE_LIMIT_PER_MINUTE {
            let req = HttpRequest {
                method: "GET".to_string(),
                url: "https://api.example.com/data".to_string(),
                headers: vec![],
                body: None,
            };
            let _ = ctx.http_fetch(req).await;
        }

        // Next should fail with rate limit
        let req = HttpRequest {
            method: "GET".to_string(),
            url: "https://api.example.com/more".to_string(),
            headers: vec![],
            body: None,
        };

        let result = ctx.http_fetch(req).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_media_fetch_ssrf_blocking() {
        let ctx = create_test_context("test-plugin").await;

        // Should block private IP
        let result = ctx.media_fetch("http://10.0.0.1/image.png", None, None).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_url_length_validation() {
        let ctx = create_test_context("test-plugin").await;

        let long_url = format!("https://example.com/{}", "x".repeat(MAX_URL_LENGTH));
        let req = HttpRequest {
            method: "GET".to_string(),
            url: long_url,
            headers: vec![],
            body: None,
        };

        let result = ctx.http_fetch(req).await;
        assert!(matches!(result.unwrap_err(), HostError::UrlTooLong { .. }));
    }

    #[tokio::test]
    async fn test_body_size_validation() {
        let ctx = create_test_context("test-plugin").await;

        let large_body = vec![0u8; MAX_HTTP_BODY_SIZE + 1];
        let req = HttpRequest {
            method: "POST".to_string(),
            url: "https://api.example.com/upload".to_string(),
            headers: vec![],
            body: Some(large_body),
        };

        let result = ctx.http_fetch(req).await;
        assert!(matches!(result.unwrap_err(), HostError::BodyTooLarge { .. }));
    }

    #[test]
    fn test_log_message_truncation() {
        // The logging should handle messages over MAX_LOG_MESSAGE_SIZE
        // by truncating them. This test just ensures no panic.
        let long_message = "x".repeat(MAX_LOG_MESSAGE_SIZE * 2);

        // Since we can't easily test the actual log output,
        // we just verify the truncation logic doesn't panic
        let truncated = if long_message.len() > MAX_LOG_MESSAGE_SIZE {
            &long_message[..MAX_LOG_MESSAGE_SIZE]
        } else {
            &long_message
        };

        assert_eq!(truncated.len(), MAX_LOG_MESSAGE_SIZE);
    }
}
