//! Wasmtime plugin host
//!
//! Implements the host interface for WASM plugins as defined in wit/plugin.wit.
//! Provides logging, config access, credential storage, and HTTP/media fetch
//! with security enforcement.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::TokioAsyncResolver;
use parking_lot::RwLock;
use reqwest::Client;
use serde_json::Value;
use thiserror::Error;

use crate::config;
use crate::credentials::{CredentialBackend, CredentialStore};

use super::capabilities::{
    CapabilityError, ConfigEnforcer, CredentialEnforcer, RateLimiterRegistry, SsrfConfig,
    SsrfProtection,
};
use super::permissions::PermissionEnforcer;

/// Maximum message size for logging (4KB)
pub const MAX_LOG_MESSAGE_SIZE: usize = 4 * 1024;

/// Safely truncate a string to at most `max_bytes` bytes without splitting
/// a multi-byte UTF-8 character. Returns the full string if it is already
/// within the limit.
fn safe_truncate(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes {
        return s;
    }
    let mut boundary = max_bytes;
    while boundary > 0 && !s.is_char_boundary(boundary) {
        boundary -= 1;
    }
    &s[..boundary]
}

/// Dispatch a log message to tracing at the given level.
#[allow(clippy::cognitive_complexity)]
fn emit_log_message(level: tracing::Level, plugin_id: &str, message: &str) {
    match level {
        tracing::Level::DEBUG => {
            tracing::debug!(plugin_id = %plugin_id, "{}", message);
        }
        tracing::Level::INFO => {
            tracing::info!(plugin_id = %plugin_id, "{}", message);
        }
        tracing::Level::WARN => {
            tracing::warn!(plugin_id = %plugin_id, "{}", message);
        }
        tracing::Level::ERROR => {
            tracing::error!(plugin_id = %plugin_id, "{}", message);
        }
        _ => {
            tracing::trace!(plugin_id = %plugin_id, "{}", message);
        }
    }
}

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

    #[error("Permission denied: {0}")]
    PermissionDenied(String),

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

    /// SSRF configuration (whether to allow Tailscale IPs, etc.)
    ssrf_config: SsrfConfig,

    /// Fine-grained permission enforcer for this plugin.
    permission_enforcer: PermissionEnforcer,
}

impl<B: CredentialBackend + 'static> PluginHostContext<B> {
    /// Create a new plugin host context
    pub fn new(
        plugin_id: String,
        credential_store: Arc<CredentialStore<B>>,
        rate_limiters: Arc<RateLimiterRegistry>,
    ) -> Self {
        Self::with_ssrf_config(
            plugin_id,
            credential_store,
            rate_limiters,
            SsrfConfig::default(),
        )
    }

    /// Create a new plugin host context with custom SSRF config
    pub fn with_ssrf_config(
        plugin_id: String,
        credential_store: Arc<CredentialStore<B>>,
        rate_limiters: Arc<RateLimiterRegistry>,
        ssrf_config: SsrfConfig,
    ) -> Self {
        let permission_enforcer = PermissionEnforcer::permissive(&plugin_id);
        Self {
            plugin_id,
            credential_store,
            rate_limiters,
            config_cache: RwLock::new(None),
            ssrf_config,
            permission_enforcer,
        }
    }

    /// Create a new plugin host context with custom SSRF config and permission enforcer
    pub fn with_permissions(
        plugin_id: String,
        credential_store: Arc<CredentialStore<B>>,
        rate_limiters: Arc<RateLimiterRegistry>,
        ssrf_config: SsrfConfig,
        permission_enforcer: PermissionEnforcer,
    ) -> Self {
        Self {
            plugin_id,
            credential_store,
            rate_limiters,
            config_cache: RwLock::new(None),
            ssrf_config,
            permission_enforcer,
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

        // Truncate message if too long (UTF-8 safe)
        let truncated = safe_truncate(message, MAX_LOG_MESSAGE_SIZE);

        // Log with plugin context
        emit_log_message(level, &self.plugin_id, truncated);

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

        // Fine-grained permission check: verify the key is in the plugin's allowed scope
        self.permission_enforcer
            .check_credential_key(key)
            .map_err(|e| HostError::PermissionDenied(e.to_string()))?;

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

        // Fine-grained permission check: verify the key is in the plugin's allowed scope
        self.permission_enforcer
            .check_credential_key(key)
            .map_err(|e| HostError::PermissionDenied(e.to_string()))?;

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

    /// Fetch an HTTP resource with SSRF protection and DNS validation
    ///
    /// This function:
    /// 1. Validates the URL for obvious SSRF attacks
    /// 2. Resolves DNS and validates each resolved IP
    /// 3. Pins the validated IP to prevent DNS rebinding
    /// 4. Disables redirects to prevent redirect-based SSRF bypass
    /// 5. Streams response with size limits to prevent memory exhaustion
    pub async fn http_fetch(&self, req: HttpRequest) -> Result<HttpResponse, HostError> {
        let (method, parsed_url) = self.validate_http_request(&req)?;

        let (host, port) = parse_host_and_port(&parsed_url)?;

        let client = self.build_secure_http_client(&host, port).await?;

        tracing::debug!(
            plugin_id = %self.plugin_id,
            method = %method,
            url = %parsed_url,
            "HTTP fetch request"
        );

        let response = send_http_request(client, &method, &parsed_url, req).await?;

        // Check content-length header if present
        let content_length = response.content_length();
        if let Some(len) = content_length {
            if len > MAX_HTTP_RESPONSE_SIZE as u64 {
                return Err(HostError::BodyTooLarge {
                    size: len as usize,
                    max: MAX_HTTP_RESPONSE_SIZE,
                });
            }
        }

        // Extract response data
        let status = response.status().as_u16();
        let headers: Vec<(String, String)> = response
            .headers()
            .iter()
            .filter_map(|(k, v)| v.to_str().ok().map(|v| (k.to_string(), v.to_string())))
            .collect();

        let body = self
            .read_response_body_limited(response, MAX_HTTP_RESPONSE_SIZE)
            .await?;

        Ok(HttpResponse {
            status,
            headers,
            body: if body.is_empty() { None } else { Some(body) },
        })
    }

    /// Validate an HTTP request's URL, method, body size, rate limit, and
    /// permissions. Returns the validated uppercase method string and parsed URL.
    fn validate_http_request(&self, req: &HttpRequest) -> Result<(String, url::Url), HostError> {
        if req.url.len() > MAX_URL_LENGTH {
            return Err(HostError::UrlTooLong {
                size: req.url.len(),
                max: MAX_URL_LENGTH,
            });
        }

        let parsed_url =
            url::Url::parse(&req.url).map_err(|_| HostError::Http("Invalid URL".to_string()))?;
        if parsed_url.scheme() != "https" {
            return Err(HostError::Http(format!(
                "Only HTTPS URLs are allowed, got '{}'",
                parsed_url.scheme()
            )));
        }

        SsrfProtection::validate_url_with_config(&req.url, &self.ssrf_config)?;

        // Fine-grained permission check: verify the URL is in the plugin's allowed patterns
        self.permission_enforcer
            .check_http_url(&req.url)
            .map_err(|e| HostError::PermissionDenied(e.to_string()))?;

        self.rate_limiters.check_http_request(&self.plugin_id)?;

        if let Some(ref body) = req.body {
            if body.len() > MAX_HTTP_BODY_SIZE {
                return Err(HostError::BodyTooLarge {
                    size: body.len(),
                    max: MAX_HTTP_BODY_SIZE,
                });
            }
        }

        let method = req.method.to_uppercase();
        if !["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"].contains(&method.as_str())
        {
            return Err(HostError::Http(format!("Invalid HTTP method: {}", method)));
        }

        Ok((method, parsed_url))
    }

    /// Build an HTTP client with SSRF protection, DNS pinning, and no redirects.
    async fn build_secure_http_client(&self, host: &str, port: u16) -> Result<Client, HostError> {
        let mut client_builder = Client::builder()
            .timeout(Duration::from_millis(DEFAULT_HTTP_TIMEOUT_MS as u64))
            .redirect(reqwest::redirect::Policy::none());

        if host.parse::<IpAddr>().is_err() {
            let validated_ip = self.resolve_and_validate_dns(host).await?;
            let socket_addr = std::net::SocketAddr::new(validated_ip, port);
            client_builder = client_builder.resolve(host, socket_addr);
        }

        client_builder
            .build()
            .map_err(|e| HostError::Http(format!("Failed to create HTTP client: {}", e)))
    }

    /// Read response body with streaming size limit
    ///
    /// Reads the response body in chunks, enforcing a hard size limit
    /// to prevent memory exhaustion from chunked/unknown-length responses.
    async fn read_response_body_limited(
        &self,
        response: reqwest::Response,
        max_size: usize,
    ) -> Result<Vec<u8>, HostError> {
        use futures_util::StreamExt;

        let mut body = Vec::new();
        let mut stream = response.bytes_stream();

        while let Some(chunk_result) = stream.next().await {
            let chunk = chunk_result
                .map_err(|e| HostError::Http(format!("Failed to read response chunk: {}", e)))?;

            if body.len() + chunk.len() > max_size {
                return Err(HostError::BodyTooLarge {
                    size: body.len() + chunk.len(),
                    max: max_size,
                });
            }

            body.extend_from_slice(&chunk);
        }

        Ok(body)
    }

    /// Resolve DNS and validate all IPs for SSRF protection
    ///
    /// Resolves the hostname and validates that all resolved IPs are safe.
    /// Returns the first validated IP to be pinned for the actual request.
    /// This prevents DNS rebinding attacks where an attacker's DNS initially
    /// returns a public IP but later returns a private IP.
    async fn resolve_and_validate_dns(&self, host: &str) -> Result<IpAddr, HostError> {
        // Create a resolver
        let resolver =
            TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());

        // Resolve the hostname
        let lookup = resolver
            .lookup_ip(host)
            .await
            .map_err(|e| HostError::Http(format!("DNS resolution failed for {}: {}", host, e)))?;

        // Collect IPs and validate each one
        let mut validated_ip: Option<IpAddr> = None;
        for ip in lookup.iter() {
            SsrfProtection::validate_resolved_ip_with_config(&ip, host, &self.ssrf_config)?;
            if validated_ip.is_none() {
                validated_ip = Some(ip);
            }
        }

        // Ensure at least one IP was resolved and validated
        validated_ip.ok_or_else(|| {
            HostError::Http(format!("DNS resolution returned no addresses for {}", host))
        })
    }

    // ============== Media Functions ==============

    /// Fetch media with SSRF protection and DNS validation
    ///
    /// Downloads media from a URL and saves it to a temporary file.
    /// Applies the same SSRF protection as http_fetch:
    /// - Pins validated DNS IPs to prevent rebinding
    /// - Disables redirects to prevent redirect-based bypass
    /// - Streams response with size limit
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
        SsrfProtection::validate_url_with_config(url, &self.ssrf_config)?;

        let parsed_url =
            url::Url::parse(url).map_err(|_| HostError::MediaFetch("Invalid URL".to_string()))?;
        if parsed_url.scheme() != "https" {
            return Err(HostError::MediaFetch(format!(
                "Only HTTPS URLs are allowed, got '{}'",
                parsed_url.scheme()
            )));
        }

        // Fine-grained permission check: verify the media URL is in the plugin's allowed patterns
        self.permission_enforcer
            .check_media_url(url)
            .map_err(|e| HostError::PermissionDenied(e.to_string()))?;

        // Check rate limit (media fetch counts as HTTP request)
        self.rate_limiters.check_http_request(&self.plugin_id)?;

        let client = self
            .build_media_fetch_client(&parsed_url, timeout_ms)
            .await?;

        tracing::debug!(
            plugin_id = %self.plugin_id,
            url = %parsed_url,
            max_bytes = ?max_bytes,
            "Media fetch request"
        );

        // Fetch the media
        let response = client
            .get(parsed_url)
            .send()
            .await
            .map_err(|e| HostError::MediaFetch(format!("Request failed: {}", e)))?;

        // Check content length header if present
        let content_length = response.content_length();
        let max_size = max_bytes.unwrap_or(MAX_HTTP_RESPONSE_SIZE as u64) as usize;
        if let Some(len) = content_length {
            if len > max_size as u64 {
                return Ok(MediaFetchResult {
                    ok: false,
                    local_path: None,
                    mime_type: None,
                    size: Some(len),
                    error: Some(format!(
                        "Content too large: {} bytes (max {})",
                        len, max_size
                    )),
                });
            }
        }

        // Get content type
        let mime_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        // Stream download with size limit
        let bytes = match self.read_response_body_limited(response, max_size).await {
            Ok(b) => b,
            Err(HostError::BodyTooLarge { size, max }) => {
                return Ok(MediaFetchResult {
                    ok: false,
                    local_path: None,
                    mime_type,
                    size: Some(size as u64),
                    error: Some(format!("Content too large: {} bytes (max {})", size, max)),
                });
            }
            Err(e) => {
                return Err(match e {
                    HostError::Http(msg) => HostError::MediaFetch(msg),
                    other => other,
                });
            }
        };

        // Create temporary file
        let temp_dir = std::env::temp_dir();
        let file_name = format!("carapace-media-{}", uuid::Uuid::new_v4());
        let temp_path = temp_dir.join(&file_name);

        // Write to file
        if let Err(e) = tokio::fs::write(&temp_path, &bytes).await {
            // Best-effort cleanup of partial file
            let _ = tokio::fs::remove_file(&temp_path).await;
            return Err(HostError::MediaFetch(format!(
                "Failed to write temp file: {}",
                e
            )));
        }

        Ok(MediaFetchResult {
            ok: true,
            local_path: Some(temp_path.to_string_lossy().to_string()),
            mime_type,
            size: Some(bytes.len() as u64),
            error: None,
        })
    }

    /// Parse the media URL, resolve DNS with SSRF validation, and build a
    /// pinned HTTP client for the media fetch request.
    async fn build_media_fetch_client(
        &self,
        parsed_url: &url::Url,
        timeout_ms: Option<u32>,
    ) -> Result<Client, HostError> {
        let host = parsed_url
            .host_str()
            .ok_or_else(|| HostError::MediaFetch("URL has no host".to_string()))?
            .to_string();

        let port = parsed_url.port_or_known_default().unwrap_or(443);

        let timeout = Duration::from_millis(
            timeout_ms
                .unwrap_or(DEFAULT_HTTP_TIMEOUT_MS)
                .min(MAX_HTTP_TIMEOUT_MS) as u64,
        );

        let mut client_builder = Client::builder()
            .timeout(timeout)
            .redirect(reqwest::redirect::Policy::none());

        if host.parse::<IpAddr>().is_err() {
            let validated_ip = self
                .resolve_and_validate_dns(&host)
                .await
                .map_err(|e| match e {
                    HostError::Http(msg) => HostError::MediaFetch(msg),
                    other => other,
                })?;
            let socket_addr = std::net::SocketAddr::new(validated_ip, port);
            client_builder = client_builder.resolve(&host, socket_addr);
        }

        client_builder
            .build()
            .map_err(|e| HostError::MediaFetch(format!("Failed to create client: {}", e)))
    }
}

/// Builder for creating plugin host contexts
pub struct PluginHostContextBuilder<B: CredentialBackend + 'static> {
    credential_store: Option<Arc<CredentialStore<B>>>,
    rate_limiters: Option<Arc<RateLimiterRegistry>>,
    ssrf_config: SsrfConfig,
    permission_enforcer: Option<PermissionEnforcer>,
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
            ssrf_config: SsrfConfig::default(),
            permission_enforcer: None,
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

    /// Configure SSRF protection (e.g., whether to allow Tailscale IPs)
    pub fn ssrf_config(mut self, config: SsrfConfig) -> Self {
        self.ssrf_config = config;
        self
    }

    /// Allow Tailscale IPs in SSRF protection (shorthand for ssrf_config)
    pub fn allow_tailscale(mut self, allow: bool) -> Self {
        self.ssrf_config.allow_tailscale = allow;
        self
    }

    /// Set the fine-grained permission enforcer
    pub fn permission_enforcer(mut self, enforcer: PermissionEnforcer) -> Self {
        self.permission_enforcer = Some(enforcer);
        self
    }

    pub fn build(self, plugin_id: String) -> Result<PluginHostContext<B>, HostError> {
        let credential_store = self
            .credential_store
            .ok_or_else(|| HostError::Config("Credential store not configured".to_string()))?;

        let rate_limiters = self
            .rate_limiters
            .unwrap_or_else(|| Arc::new(RateLimiterRegistry::new()));

        let permission_enforcer = self
            .permission_enforcer
            .ok_or_else(|| HostError::Config("Permission enforcer not configured".to_string()))?;

        Ok(PluginHostContext::with_permissions(
            plugin_id,
            credential_store,
            rate_limiters,
            self.ssrf_config,
            permission_enforcer,
        ))
    }
}

/// Parse host and port from a URL string.
fn parse_host_and_port(parsed_url: &url::Url) -> Result<(String, u16), HostError> {
    if parsed_url.scheme() != "https" {
        return Err(HostError::Http(format!(
            "Only HTTPS URLs are allowed, got '{}'",
            parsed_url.scheme()
        )));
    }
    let host = parsed_url
        .host_str()
        .ok_or_else(|| HostError::Http("URL has no host".to_string()))?
        .to_string();

    let port = parsed_url.port_or_known_default().unwrap_or(443);

    Ok((host, port))
}

/// Build and send an HTTP request using the provided client.
async fn send_http_request(
    client: Client,
    method: &str,
    url: &url::Url,
    req: HttpRequest,
) -> Result<reqwest::Response, HostError> {
    let reqwest_method = match method {
        "GET" => reqwest::Method::GET,
        "POST" => reqwest::Method::POST,
        "PUT" => reqwest::Method::PUT,
        "DELETE" => reqwest::Method::DELETE,
        "PATCH" => reqwest::Method::PATCH,
        "HEAD" => reqwest::Method::HEAD,
        "OPTIONS" => reqwest::Method::OPTIONS,
        _ => unreachable!(),
    };

    let mut request_builder = client.request(reqwest_method, url.clone());

    for (name, value) in &req.headers {
        request_builder = request_builder.header(name, value);
    }

    if let Some(body) = req.body {
        request_builder = request_builder.body(body);
    }

    request_builder
        .send()
        .await
        .map_err(|e| HostError::Http(format!("Request failed: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credentials::MockCredentialBackend;
    use tempfile::tempdir;

    async fn create_test_context(plugin_id: &str) -> PluginHostContext<MockCredentialBackend> {
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
            url: "https://localhost/secret".to_string(),
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
    async fn test_http_fetch_rejects_non_https_url() {
        let ctx = create_test_context("test-plugin").await;
        let req = HttpRequest {
            method: "GET".to_string(),
            url: "http://example.com/data".to_string(),
            headers: vec![],
            body: None,
        };
        let result = ctx.http_fetch(req).await;
        match result {
            Err(HostError::Http(msg)) => {
                assert!(
                    msg.contains("Only HTTPS URLs are allowed"),
                    "unexpected error: {msg}"
                );
            }
            other => panic!("expected HostError::Http for non-https URL, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_media_fetch_ssrf_blocking() {
        let ctx = create_test_context("test-plugin").await;

        // Should block private IP
        let result = ctx
            .media_fetch("https://10.0.0.1/image.png", None, None)
            .await;
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
        assert!(matches!(
            result.unwrap_err(),
            HostError::BodyTooLarge { .. }
        ));
    }

    #[test]
    fn test_log_message_truncation_ascii() {
        // ASCII strings truncate exactly at MAX_LOG_MESSAGE_SIZE
        let long_message = "x".repeat(MAX_LOG_MESSAGE_SIZE * 2);
        let truncated = safe_truncate(&long_message, MAX_LOG_MESSAGE_SIZE);
        assert_eq!(truncated.len(), MAX_LOG_MESSAGE_SIZE);
    }

    #[test]
    fn test_log_message_truncation_multibyte_utf8() {
        // Build a string of multi-byte chars that exceeds the limit.
        // U+00E9 (e-acute) is 2 bytes in UTF-8; U+1F600 (emoji) is 4 bytes.
        let two_byte_char = "\u{00E9}"; // 2 bytes each
        let count = MAX_LOG_MESSAGE_SIZE; // guarantees overflow
        let long_message: String = two_byte_char.repeat(count);
        assert!(long_message.len() > MAX_LOG_MESSAGE_SIZE);

        let truncated = safe_truncate(&long_message, MAX_LOG_MESSAGE_SIZE);
        // Must not exceed the limit
        assert!(truncated.len() <= MAX_LOG_MESSAGE_SIZE);
        // Must be valid UTF-8 (it is a &str, so this is guaranteed at compile time)
        // and must end on a character boundary
        assert!(truncated.is_char_boundary(truncated.len()));
        // Since each char is 2 bytes, the truncated length should be even
        assert_eq!(truncated.len() % 2, 0);
    }

    #[test]
    fn test_log_message_truncation_four_byte_utf8() {
        // 4-byte emoji repeated to exceed the limit
        let emoji = "\u{1F600}"; // 4 bytes
        let count = MAX_LOG_MESSAGE_SIZE; // way over the byte limit
        let long_message: String = emoji.repeat(count);
        assert!(long_message.len() > MAX_LOG_MESSAGE_SIZE);

        let truncated = safe_truncate(&long_message, MAX_LOG_MESSAGE_SIZE);
        assert!(truncated.len() <= MAX_LOG_MESSAGE_SIZE);
        assert!(truncated.is_char_boundary(truncated.len()));
        // Length should be a multiple of 4 since each emoji is 4 bytes
        assert_eq!(truncated.len() % 4, 0);
    }

    #[test]
    fn test_log_message_truncation_short_string() {
        // Strings shorter than the limit are returned unchanged
        let short = "hello";
        let truncated = safe_truncate(short, MAX_LOG_MESSAGE_SIZE);
        assert_eq!(truncated, "hello");
    }

    #[test]
    fn test_log_message_truncation_empty_string() {
        let truncated = safe_truncate("", MAX_LOG_MESSAGE_SIZE);
        assert_eq!(truncated, "");
    }

    #[test]
    fn test_log_message_truncation_exact_boundary() {
        // String exactly at the limit should be returned as-is
        let exact = "x".repeat(MAX_LOG_MESSAGE_SIZE);
        let truncated = safe_truncate(&exact, MAX_LOG_MESSAGE_SIZE);
        assert_eq!(truncated.len(), MAX_LOG_MESSAGE_SIZE);
        assert_eq!(truncated, exact.as_str());
    }

    #[test]
    fn test_safe_truncate_splits_inside_multibyte() {
        // "aé" is 3 bytes: 'a' (1 byte) + 'é' (2 bytes: 0xC3 0xA9)
        // Truncating at byte 2 would split the 'é', so we expect byte 1.
        let s = "a\u{00E9}";
        assert_eq!(s.len(), 3);
        let truncated = safe_truncate(s, 2);
        assert_eq!(truncated, "a");
        assert_eq!(truncated.len(), 1);
    }

    #[test]
    fn test_safe_truncate_zero_limit() {
        let truncated = safe_truncate("hello", 0);
        assert_eq!(truncated, "");
    }

    async fn create_test_context_with_tailscale(
        plugin_id: &str,
        allow_tailscale: bool,
    ) -> PluginHostContext<MockCredentialBackend> {
        let temp_dir = tempdir().unwrap();
        let backend = MockCredentialBackend::new(true);
        let credential_store = Arc::new(
            CredentialStore::new(backend, temp_dir.path().to_path_buf())
                .await
                .unwrap(),
        );

        PluginHostContext::with_ssrf_config(
            plugin_id.to_string(),
            credential_store,
            Arc::new(RateLimiterRegistry::new()),
            SsrfConfig { allow_tailscale },
        )
    }

    #[tokio::test]
    async fn test_http_fetch_blocks_tailscale_by_default() {
        let ctx = create_test_context("test-plugin").await;

        // Should block Tailscale IP (100.x.x.x) by default
        let req = HttpRequest {
            method: "GET".to_string(),
            url: "https://100.100.50.25/api".to_string(),
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
    async fn test_http_fetch_allows_tailscale_when_configured() {
        let ctx = create_test_context_with_tailscale("test-plugin", true).await;

        // Should allow Tailscale IP when configured
        // Note: This will fail at DNS/connection stage since 100.100.50.25 isn't real,
        // but it should NOT fail at SSRF validation stage
        let req = HttpRequest {
            method: "GET".to_string(),
            url: "https://100.100.50.25/api".to_string(),
            headers: vec![],
            body: None,
        };

        let result = ctx.http_fetch(req).await;
        // Should fail with HTTP error (connection failed), not SSRF blocked
        match result {
            Err(HostError::Capability(CapabilityError::SsrfBlocked(_))) => {
                panic!("Should not be blocked as SSRF when allow_tailscale is true");
            }
            Err(HostError::Http(_)) => {
                // Expected - connection/DNS error since the IP doesn't exist
            }
            Ok(_) => {
                // Unexpected but acceptable if somehow the request succeeded
            }
            Err(other) => {
                panic!("Unexpected error: {:?}", other);
            }
        }
    }

    #[tokio::test]
    async fn test_http_fetch_invalid_method() {
        let ctx = create_test_context("test-plugin").await;

        let req = HttpRequest {
            method: "INVALID".to_string(),
            url: "https://example.com/api".to_string(),
            headers: vec![],
            body: None,
        };

        let result = ctx.http_fetch(req).await;
        assert!(matches!(result.unwrap_err(), HostError::Http(_)));
    }

    #[tokio::test]
    async fn test_builder_with_ssrf_config() {
        let temp_dir = tempdir().unwrap();
        let backend = MockCredentialBackend::new(true);
        let credential_store = Arc::new(
            CredentialStore::new(backend, temp_dir.path().to_path_buf())
                .await
                .unwrap(),
        );

        // Test the builder with allow_tailscale shorthand
        let ctx = PluginHostContextBuilder::new()
            .credential_store(credential_store)
            .allow_tailscale(true)
            .permission_enforcer(PermissionEnforcer::permissive("test-plugin"))
            .build("test-plugin".to_string())
            .unwrap();

        // Should allow Tailscale IP (SSRF validation passes)
        let req = HttpRequest {
            method: "GET".to_string(),
            url: "https://100.100.50.25/api".to_string(),
            headers: vec![],
            body: None,
        };

        let result = ctx.http_fetch(req).await;
        // Should not fail with SSRF blocked
        assert!(!matches!(
            result,
            Err(HostError::Capability(CapabilityError::SsrfBlocked(_)))
        ));
    }
}
