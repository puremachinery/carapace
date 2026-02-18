//! Media fetch with SSRF protection
//!
//! Provides HTTP media fetching with comprehensive SSRF protection:
//! - HTTP/HTTPS only (no file://, ftp://, etc.)
//! - Blocks private IPv4/IPv6 ranges, link-local, localhost
//! - Blocks cloud metadata endpoints (169.254.169.254, fd00:ec2::254)
//! - Pins resolved IPs to prevent DNS rebinding attacks
//! - Disables redirects to prevent redirect-based SSRF bypass
//! - Streams response with size limit enforcement

use std::net::IpAddr;
use std::time::Duration;

use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::TokioAsyncResolver;
use reqwest::Client;
use thiserror::Error;

use crate::plugins::capabilities::{CapabilityError, SsrfConfig, SsrfProtection};

/// Maximum URL length (2KB)
pub const MAX_URL_LENGTH: usize = 2048;

/// Default fetch timeout in milliseconds (30s)
pub const DEFAULT_FETCH_TIMEOUT_MS: u64 = 30_000;

/// Maximum fetch timeout in milliseconds (5 minutes)
pub const MAX_FETCH_TIMEOUT_MS: u64 = 300_000;

/// Default maximum response size (50MB)
pub const DEFAULT_MAX_SIZE: u64 = 50 * 1024 * 1024;

/// Errors that can occur during media fetch
#[derive(Error, Debug, Clone)]
pub enum FetchError {
    #[error("SSRF protection: {0}")]
    Ssrf(#[from] CapabilityError),

    #[error("URL too long: {size} chars (max {max})")]
    UrlTooLong { size: usize, max: usize },

    #[error("Invalid URL: {0}")]
    InvalidUrl(String),

    #[error("DNS resolution failed: {0}")]
    DnsResolution(String),

    #[error("HTTP request failed: {0}")]
    HttpRequest(String),

    #[error("Response too large: {size} bytes (max {max})")]
    ResponseTooLarge { size: u64, max: u64 },

    #[error("Stream read error: {0}")]
    StreamRead(String),
}

/// Result of a successful media fetch
#[derive(Debug, Clone)]
pub struct FetchResult {
    /// The fetched bytes
    pub bytes: Vec<u8>,

    /// Content-Type from response headers, if present
    pub content_type: Option<String>,

    /// Actual size of the fetched content
    pub size: u64,
}

/// Configuration for media fetching
#[derive(Debug, Clone)]
pub struct FetchConfig {
    /// Maximum response size in bytes (default: 50MB)
    pub max_size: u64,

    /// Request timeout in milliseconds (default: 30s, max: 5min)
    pub timeout_ms: u64,

    /// SSRF protection configuration
    pub ssrf_config: SsrfConfig,
}

impl Default for FetchConfig {
    fn default() -> Self {
        Self {
            max_size: DEFAULT_MAX_SIZE,
            timeout_ms: DEFAULT_FETCH_TIMEOUT_MS,
            ssrf_config: SsrfConfig::default(),
        }
    }
}

impl FetchConfig {
    /// Create a new config with custom max size
    pub fn with_max_size(mut self, max_size: u64) -> Self {
        self.max_size = max_size;
        self
    }

    /// Create a new config with custom timeout
    pub fn with_timeout_ms(mut self, timeout_ms: u64) -> Self {
        self.timeout_ms = timeout_ms.min(MAX_FETCH_TIMEOUT_MS);
        self
    }

    /// Allow Tailscale IPs in SSRF protection
    pub fn allow_tailscale(mut self) -> Self {
        self.ssrf_config.allow_tailscale = true;
        self
    }
}

/// Media fetcher with SSRF protection
///
/// This fetcher implements comprehensive SSRF protection:
/// 1. URL validation (scheme, host checks)
/// 2. DNS resolution with IP validation
/// 3. IP pinning to prevent DNS rebinding
/// 4. Redirect disabled to prevent redirect-based bypass
/// 5. Streaming with size limits
pub struct MediaFetcher {
    config: FetchConfig,
}

impl Default for MediaFetcher {
    fn default() -> Self {
        Self::new()
    }
}

impl MediaFetcher {
    /// Create a new MediaFetcher with default configuration
    pub fn new() -> Self {
        Self {
            config: FetchConfig::default(),
        }
    }

    /// Create a new MediaFetcher with custom configuration
    pub fn with_config(config: FetchConfig) -> Self {
        Self { config }
    }

    /// Fetch media from a URL with SSRF protection
    ///
    /// # Security
    ///
    /// This method:
    /// - Validates URL scheme (HTTP/HTTPS only)
    /// - Blocks private IP ranges, localhost, cloud metadata
    /// - Resolves DNS and validates all resolved IPs
    /// - Pins validated IP to prevent DNS rebinding
    /// - Disables redirects
    /// - Enforces size limits during streaming
    ///
    /// # Example
    ///
    /// ```ignore
    /// let fetcher = MediaFetcher::new();
    /// let result = fetcher.fetch("https://example.com/image.png").await?;
    /// println!("Fetched {} bytes, type: {:?}", result.size, result.content_type);
    /// ```
    pub async fn fetch(&self, url: &str) -> Result<FetchResult, FetchError> {
        self.fetch_with_config(url, &self.config).await
    }

    /// Fetch media with custom configuration for this request
    pub async fn fetch_with_config(
        &self,
        url: &str,
        config: &FetchConfig,
    ) -> Result<FetchResult, FetchError> {
        // Validate URL length
        if url.len() > MAX_URL_LENGTH {
            return Err(FetchError::UrlTooLong {
                size: url.len(),
                max: MAX_URL_LENGTH,
            });
        }

        // Validate URL for SSRF (catches obvious attacks)
        SsrfProtection::validate_url_with_config(url, &config.ssrf_config)?;

        // Parse URL to extract host for DNS validation
        let parsed_url = url::Url::parse(url)
            .map_err(|_| FetchError::InvalidUrl("invalid media URL".to_string()))?;
        if parsed_url.scheme() != "https" {
            return Err(FetchError::InvalidUrl(format!(
                "only https URLs are allowed for media fetch, but got scheme '{}'",
                parsed_url.scheme()
            )));
        }

        let host = parsed_url
            .host_str()
            .ok_or_else(|| FetchError::InvalidUrl("URL has no host".to_string()))?
            .to_string();

        let port = parsed_url.port_or_known_default().unwrap_or(443);

        // Calculate timeout (capped at max)
        let timeout = Duration::from_millis(config.timeout_ms.min(MAX_FETCH_TIMEOUT_MS));

        // Build HTTP client with security settings
        let mut client_builder = Client::builder()
            .timeout(timeout)
            // SECURITY: Disable redirects to prevent redirect-based SSRF bypass
            // Attackers could redirect from a public URL to a private IP
            .redirect(reqwest::redirect::Policy::none());

        // If host is not already an IP, resolve DNS and pin validated IP
        if host.parse::<IpAddr>().is_err() {
            let validated_ip = self
                .resolve_and_validate_dns(&host, &config.ssrf_config)
                .await?;
            // Pin the validated IP to prevent DNS rebinding
            let socket_addr = std::net::SocketAddr::new(validated_ip, port);
            client_builder = client_builder.resolve(&host, socket_addr);

            tracing::debug!(
                url = %url,
                host = %host,
                resolved_ip = %validated_ip,
                "DNS resolved and validated for media fetch"
            );
        }

        let client = client_builder
            .build()
            .map_err(|e| FetchError::HttpRequest(format!("Failed to create HTTP client: {}", e)))?;

        // Make the request
        let response = client
            .get(url)
            .send()
            .await
            .map_err(|e| FetchError::HttpRequest(format!("Request failed: {}", e)))?;

        // Check content-length header if present
        if let Some(content_length) = response.content_length() {
            if content_length > config.max_size {
                return Err(FetchError::ResponseTooLarge {
                    size: content_length,
                    max: config.max_size,
                });
            }
        }

        // Extract content type before consuming response
        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        // Stream body with size limit
        let bytes = self
            .read_response_with_limit(response, config.max_size)
            .await?;
        let size = bytes.len() as u64;

        Ok(FetchResult {
            bytes,
            content_type,
            size,
        })
    }

    /// Resolve DNS and validate all IPs for SSRF protection
    ///
    /// Returns the first validated IP to be pinned for the actual request.
    async fn resolve_and_validate_dns(
        &self,
        host: &str,
        ssrf_config: &SsrfConfig,
    ) -> Result<IpAddr, FetchError> {
        let resolver =
            TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());

        let lookup = resolver
            .lookup_ip(host)
            .await
            .map_err(|e| FetchError::DnsResolution(format!("{}: {}", host, e)))?;

        let mut validated_ip: Option<IpAddr> = None;

        for ip in lookup.iter() {
            // Validate each resolved IP against SSRF rules
            SsrfProtection::validate_resolved_ip_with_config(&ip, host, ssrf_config)?;
            if validated_ip.is_none() {
                validated_ip = Some(ip);
            }
        }

        validated_ip
            .ok_or_else(|| FetchError::DnsResolution(format!("No addresses returned for {}", host)))
    }

    /// Read response body with streaming size limit
    async fn read_response_with_limit(
        &self,
        response: reqwest::Response,
        max_size: u64,
    ) -> Result<Vec<u8>, FetchError> {
        use futures_util::StreamExt;

        let mut body = Vec::new();
        let mut stream = response.bytes_stream();

        while let Some(chunk_result) = stream.next().await {
            let chunk = chunk_result
                .map_err(|e| FetchError::StreamRead(format!("Failed to read chunk: {}", e)))?;

            let new_size = body.len() as u64 + chunk.len() as u64;
            if new_size > max_size {
                return Err(FetchError::ResponseTooLarge {
                    size: new_size,
                    max: max_size,
                });
            }

            body.extend_from_slice(&chunk);
        }

        Ok(body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fetch_config_defaults() {
        let config = FetchConfig::default();
        assert_eq!(config.max_size, DEFAULT_MAX_SIZE);
        assert_eq!(config.timeout_ms, DEFAULT_FETCH_TIMEOUT_MS);
        assert!(!config.ssrf_config.allow_tailscale);
    }

    #[test]
    fn test_fetch_config_builder() {
        let config = FetchConfig::default()
            .with_max_size(10 * 1024 * 1024)
            .with_timeout_ms(60_000)
            .allow_tailscale();

        assert_eq!(config.max_size, 10 * 1024 * 1024);
        assert_eq!(config.timeout_ms, 60_000);
        assert!(config.ssrf_config.allow_tailscale);
    }

    #[test]
    fn test_fetch_config_timeout_capped() {
        let config = FetchConfig::default().with_timeout_ms(MAX_FETCH_TIMEOUT_MS + 100_000);
        assert_eq!(config.timeout_ms, MAX_FETCH_TIMEOUT_MS);
    }

    #[tokio::test]
    async fn test_fetch_blocks_localhost() {
        let fetcher = MediaFetcher::new();
        let result = fetcher.fetch("https://localhost/image.png").await;
        assert!(matches!(result, Err(FetchError::Ssrf(_))));

        let result = fetcher.fetch("https://127.0.0.1/image.png").await;
        assert!(matches!(result, Err(FetchError::Ssrf(_))));

        let result = fetcher.fetch("https://[::1]/image.png").await;
        assert!(matches!(result, Err(FetchError::Ssrf(_))));
    }

    #[tokio::test]
    async fn test_fetch_blocks_private_ipv4() {
        let fetcher = MediaFetcher::new();

        // 10.0.0.0/8
        let result = fetcher.fetch("https://10.0.0.1/image.png").await;
        assert!(matches!(result, Err(FetchError::Ssrf(_))));

        // 172.16.0.0/12
        let result = fetcher.fetch("https://172.16.0.1/image.png").await;
        assert!(matches!(result, Err(FetchError::Ssrf(_))));

        // 192.168.0.0/16
        let result = fetcher.fetch("https://192.168.1.1/image.png").await;
        assert!(matches!(result, Err(FetchError::Ssrf(_))));
    }

    #[tokio::test]
    async fn test_fetch_blocks_link_local() {
        let fetcher = MediaFetcher::new();
        let result = fetcher.fetch("https://169.254.1.1/image.png").await;
        assert!(matches!(result, Err(FetchError::Ssrf(_))));
    }

    #[tokio::test]
    async fn test_fetch_blocks_cloud_metadata() {
        let fetcher = MediaFetcher::new();

        // AWS/GCP/Azure metadata endpoint
        let result = fetcher
            .fetch("https://169.254.169.254/latest/meta-data/")
            .await;
        assert!(matches!(result, Err(FetchError::Ssrf(_))));
    }

    #[tokio::test]
    async fn test_fetch_blocks_private_ipv6() {
        let fetcher = MediaFetcher::new();

        // fc00::/7 (ULA)
        let result = fetcher.fetch("https://[fc00::1]/image.png").await;
        assert!(matches!(result, Err(FetchError::Ssrf(_))));

        // fe80::/10 (link-local)
        let result = fetcher.fetch("https://[fe80::1]/image.png").await;
        assert!(matches!(result, Err(FetchError::Ssrf(_))));
    }

    #[tokio::test]
    async fn test_fetch_blocks_file_protocol() {
        let fetcher = MediaFetcher::new();
        let result = fetcher.fetch("file:///etc/passwd").await;
        assert!(matches!(result, Err(FetchError::Ssrf(_))));
    }

    #[tokio::test]
    async fn test_fetch_blocks_ftp_protocol() {
        let fetcher = MediaFetcher::new();
        let result = fetcher.fetch("ftp://ftp.example.com/file").await;
        assert!(matches!(result, Err(FetchError::Ssrf(_))));
    }

    #[tokio::test]
    async fn test_fetch_url_too_long() {
        let fetcher = MediaFetcher::new();
        let long_url = format!("https://example.com/{}", "x".repeat(MAX_URL_LENGTH));
        let result = fetcher.fetch(&long_url).await;
        assert!(matches!(result, Err(FetchError::UrlTooLong { .. })));
    }

    #[tokio::test]
    async fn test_fetch_blocks_tailscale_by_default() {
        let fetcher = MediaFetcher::new();
        // 100.64.0.0/10 is CGNAT / Tailscale range
        let result = fetcher.fetch("https://100.100.50.25/image.png").await;
        assert!(matches!(result, Err(FetchError::Ssrf(_))));
    }

    #[tokio::test]
    async fn test_fetch_allows_tailscale_when_configured() {
        let config = FetchConfig::default().allow_tailscale();
        let fetcher = MediaFetcher::with_config(config);

        // Should pass SSRF validation but fail on connection (IP doesn't exist)
        let result = fetcher.fetch("https://100.100.50.25/image.png").await;
        // Should NOT be an SSRF error
        assert!(!matches!(result, Err(FetchError::Ssrf(_))));
        // Should be a connection/HTTP error instead
        assert!(matches!(result, Err(FetchError::HttpRequest(_))));
    }

    #[tokio::test]
    async fn test_fetch_rejects_http_scheme() {
        let fetcher = MediaFetcher::new();
        let result = fetcher.fetch("http://example.com/image.png").await;
        assert!(matches!(result, Err(FetchError::InvalidUrl(_))));
    }
}
