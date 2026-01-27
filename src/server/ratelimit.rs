//! Rate limiting middleware
//!
//! Provides per-client IP and per-route rate limiting using a token bucket algorithm.
//!
//! Features:
//! - Per-client IP rate limiting
//! - Per-route bucket support (different limits for different endpoints)
//! - Token bucket algorithm with configurable refill rate
//! - Configurable limits via RateLimitConfig

use axum::{
    body::Body,
    extract::ConnectInfo,
    http::{header, HeaderValue, Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;
use tracing::{debug, warn};

/// Default rate limit (requests per second)
const DEFAULT_RATE: u32 = 100;

/// Default burst size (max tokens in bucket)
const DEFAULT_BURST: u32 = 200;

/// Default cleanup interval (remove stale entries)
const DEFAULT_CLEANUP_INTERVAL: Duration = Duration::from_secs(300);

/// Default entry expiry time
const DEFAULT_ENTRY_EXPIRY: Duration = Duration::from_secs(600);

/// Rate limit errors
#[derive(Error, Debug)]
pub enum RateLimitError {
    #[error("Rate limit exceeded")]
    LimitExceeded { retry_after_secs: u64 },

    #[error("Client IP could not be determined")]
    NoClientIp,
}

/// Token bucket state for a single client
#[derive(Debug, Clone)]
struct TokenBucket {
    /// Current number of tokens
    tokens: f64,
    /// Last time tokens were refilled
    last_refill: Instant,
    /// Rate of token refill (tokens per second)
    rate: f64,
    /// Maximum tokens (burst size)
    max_tokens: f64,
}

impl TokenBucket {
    fn new(rate: u32, burst: u32) -> Self {
        TokenBucket {
            tokens: burst as f64,
            last_refill: Instant::now(),
            rate: rate as f64,
            max_tokens: burst as f64,
        }
    }

    /// Attempt to consume one token. Returns true if successful.
    fn try_consume(&mut self) -> bool {
        self.refill();

        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Refill tokens based on elapsed time
    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        let new_tokens = elapsed * self.rate;

        self.tokens = (self.tokens + new_tokens).min(self.max_tokens);
        self.last_refill = now;
    }

    /// Get the time until one token is available
    fn time_until_available(&self) -> Duration {
        if self.tokens >= 1.0 {
            return Duration::ZERO;
        }

        let needed = 1.0 - self.tokens;
        let seconds = needed / self.rate;
        Duration::from_secs_f64(seconds)
    }
}

/// Rate limit configuration for a specific route
#[derive(Debug, Clone)]
pub struct RouteLimitConfig {
    /// Route path prefix (e.g., "/hooks/")
    pub prefix: String,
    /// Requests per second
    pub rate: u32,
    /// Burst size (max tokens)
    pub burst: u32,
}

impl RouteLimitConfig {
    pub fn new(prefix: impl Into<String>, rate: u32, burst: u32) -> Self {
        RouteLimitConfig {
            prefix: prefix.into(),
            rate,
            burst,
        }
    }
}

/// Rate limiting configuration
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Default rate limit (requests per second)
    pub default_rate: u32,
    /// Default burst size
    pub default_burst: u32,
    /// Per-route configurations
    pub route_limits: Vec<RouteLimitConfig>,
    /// Whether rate limiting is enabled
    pub enabled: bool,
    /// Trusted proxy headers for client IP extraction
    pub trust_proxy_headers: bool,
    /// Cleanup interval for stale entries
    pub cleanup_interval: Duration,
    /// Entry expiry time
    pub entry_expiry: Duration,
    /// Exempt IPs (e.g., localhost)
    pub exempt_ips: Vec<IpAddr>,
    /// Whether to exempt loopback addresses
    pub exempt_loopback: bool,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        RateLimitConfig {
            default_rate: DEFAULT_RATE,
            default_burst: DEFAULT_BURST,
            route_limits: vec![
                // More restrictive limits for auth-related endpoints
                RouteLimitConfig::new("/hooks/", 50, 100),
                RouteLimitConfig::new("/tools/", 50, 100),
            ],
            enabled: true,
            trust_proxy_headers: false,
            cleanup_interval: DEFAULT_CLEANUP_INTERVAL,
            entry_expiry: DEFAULT_ENTRY_EXPIRY,
            exempt_ips: Vec::new(),
            exempt_loopback: true,
        }
    }
}

impl RateLimitConfig {
    /// Create a builder for custom configuration
    pub fn builder() -> RateLimitConfigBuilder {
        RateLimitConfigBuilder::default()
    }

    /// Get the rate limit config for a given path
    pub fn get_limit_for_path(&self, path: &str) -> (u32, u32) {
        for route in &self.route_limits {
            if path.starts_with(&route.prefix) {
                return (route.rate, route.burst);
            }
        }
        (self.default_rate, self.default_burst)
    }

    /// Check if an IP is exempt from rate limiting
    pub fn is_exempt(&self, ip: &IpAddr) -> bool {
        if self.exempt_loopback && ip.is_loopback() {
            return true;
        }
        self.exempt_ips.contains(ip)
    }
}

/// Builder for RateLimitConfig
pub struct RateLimitConfigBuilder {
    config: RateLimitConfig,
}

impl Default for RateLimitConfigBuilder {
    fn default() -> Self {
        // Builder starts with minimal config, not the full default with preset route limits
        Self {
            config: RateLimitConfig {
                default_rate: DEFAULT_RATE,
                default_burst: DEFAULT_BURST,
                route_limits: vec![], // Empty - user adds their own
                enabled: true,
                exempt_loopback: true,
                exempt_ips: vec![],
                trust_proxy_headers: false,
                cleanup_interval: DEFAULT_CLEANUP_INTERVAL,
                entry_expiry: DEFAULT_ENTRY_EXPIRY,
            },
        }
    }
}

impl RateLimitConfigBuilder {
    /// Set the default rate limit
    pub fn default_rate(mut self, rate: u32) -> Self {
        self.config.default_rate = rate;
        self
    }

    /// Set the default burst size
    pub fn default_burst(mut self, burst: u32) -> Self {
        self.config.default_burst = burst;
        self
    }

    /// Add a route-specific limit
    pub fn route_limit(mut self, prefix: impl Into<String>, rate: u32, burst: u32) -> Self {
        self.config
            .route_limits
            .push(RouteLimitConfig::new(prefix, rate, burst));
        self
    }

    /// Set route limits (replaces existing)
    pub fn route_limits(mut self, limits: Vec<RouteLimitConfig>) -> Self {
        self.config.route_limits = limits;
        self
    }

    /// Enable or disable rate limiting
    pub fn enabled(mut self, enabled: bool) -> Self {
        self.config.enabled = enabled;
        self
    }

    /// Trust proxy headers for client IP
    pub fn trust_proxy_headers(mut self, trust: bool) -> Self {
        self.config.trust_proxy_headers = trust;
        self
    }

    /// Set cleanup interval
    pub fn cleanup_interval(mut self, interval: Duration) -> Self {
        self.config.cleanup_interval = interval;
        self
    }

    /// Set entry expiry
    pub fn entry_expiry(mut self, expiry: Duration) -> Self {
        self.config.entry_expiry = expiry;
        self
    }

    /// Add exempt IPs
    pub fn exempt_ips(mut self, ips: Vec<IpAddr>) -> Self {
        self.config.exempt_ips = ips;
        self
    }

    /// Set whether to exempt loopback
    pub fn exempt_loopback(mut self, exempt: bool) -> Self {
        self.config.exempt_loopback = exempt;
        self
    }

    /// Build the configuration
    pub fn build(self) -> RateLimitConfig {
        self.config
    }
}

/// Client bucket entry with expiry tracking
#[derive(Debug)]
struct ClientEntry {
    bucket: TokenBucket,
    last_seen: Instant,
}

/// Rate limiter state
#[derive(Clone)]
pub struct RateLimiter {
    /// Per-client buckets keyed by (IP, route_prefix)
    buckets: Arc<RwLock<HashMap<(IpAddr, String), ClientEntry>>>,
    /// Configuration
    config: Arc<RateLimitConfig>,
    /// Last cleanup time
    last_cleanup: Arc<RwLock<Instant>>,
}

impl RateLimiter {
    /// Create a new rate limiter
    pub fn new(config: RateLimitConfig) -> Self {
        RateLimiter {
            buckets: Arc::new(RwLock::new(HashMap::new())),
            config: Arc::new(config),
            last_cleanup: Arc::new(RwLock::new(Instant::now())),
        }
    }

    /// Check if a request is allowed
    pub fn check(&self, client_ip: IpAddr, path: &str) -> Result<(), RateLimitError> {
        if !self.config.enabled {
            return Ok(());
        }

        // Check exemptions
        if self.config.is_exempt(&client_ip) {
            return Ok(());
        }

        // Get rate limit for this path
        let (rate, burst) = self.config.get_limit_for_path(path);

        // Get route prefix for bucket key
        let route_prefix = self.get_route_prefix(path);
        let key = (client_ip, route_prefix);

        // Periodic cleanup
        self.maybe_cleanup();

        // Check/update bucket
        let mut buckets = self.buckets.write();
        let entry = buckets.entry(key.clone()).or_insert_with(|| ClientEntry {
            bucket: TokenBucket::new(rate, burst),
            last_seen: Instant::now(),
        });

        entry.last_seen = Instant::now();

        if entry.bucket.try_consume() {
            Ok(())
        } else {
            let retry_after = entry.bucket.time_until_available();
            Err(RateLimitError::LimitExceeded {
                retry_after_secs: retry_after.as_secs().max(1),
            })
        }
    }

    /// Get the route prefix for bucket grouping
    fn get_route_prefix(&self, path: &str) -> String {
        for route in &self.config.route_limits {
            if path.starts_with(&route.prefix) {
                return route.prefix.clone();
            }
        }
        // Default bucket for unmatched routes
        "default".to_string()
    }

    /// Maybe run cleanup of stale entries
    fn maybe_cleanup(&self) {
        let mut last_cleanup = self.last_cleanup.write();
        if last_cleanup.elapsed() < self.config.cleanup_interval {
            return;
        }

        *last_cleanup = Instant::now();
        drop(last_cleanup);

        let mut buckets = self.buckets.write();
        let expiry = self.config.entry_expiry;
        buckets.retain(|_, entry| entry.last_seen.elapsed() < expiry);

        debug!("Rate limiter cleanup: {} entries remaining", buckets.len());
    }

    /// Get current bucket stats for monitoring
    pub fn stats(&self) -> RateLimiterStats {
        let buckets = self.buckets.read();
        RateLimiterStats {
            total_buckets: buckets.len(),
            config_enabled: self.config.enabled,
        }
    }

    /// Get the configuration
    pub fn config(&self) -> &RateLimitConfig {
        &self.config
    }
}

/// Rate limiter statistics
#[derive(Debug, Clone)]
pub struct RateLimiterStats {
    pub total_buckets: usize,
    pub config_enabled: bool,
}

/// Extract client IP from request
fn extract_client_ip(
    remote_addr: Option<SocketAddr>,
    headers: &axum::http::HeaderMap,
    trust_proxy: bool,
) -> Option<IpAddr> {
    // If trusting proxy headers, check X-Forwarded-For first
    if trust_proxy {
        if let Some(xff) = headers.get("x-forwarded-for") {
            if let Ok(xff_str) = xff.to_str() {
                // Take the first (leftmost) IP, which is the original client
                if let Some(ip_str) = xff_str.split(',').next() {
                    if let Ok(ip) = ip_str.trim().parse::<IpAddr>() {
                        return Some(ip);
                    }
                }
            }
        }

        // Also check X-Real-IP
        if let Some(real_ip) = headers.get("x-real-ip") {
            if let Ok(ip_str) = real_ip.to_str() {
                if let Ok(ip) = ip_str.trim().parse::<IpAddr>() {
                    return Some(ip);
                }
            }
        }
    }

    // Fall back to direct connection address
    remote_addr.map(|addr| addr.ip())
}

/// Rate limiting middleware layer
#[derive(Clone)]
pub struct RateLimitLayer {
    limiter: RateLimiter,
}

impl RateLimitLayer {
    /// Create a new rate limit layer with default configuration
    pub fn new() -> Self {
        Self {
            limiter: RateLimiter::new(RateLimitConfig::default()),
        }
    }

    /// Create a new rate limit layer with custom configuration
    pub fn with_config(config: RateLimitConfig) -> Self {
        Self {
            limiter: RateLimiter::new(config),
        }
    }

    /// Get the underlying rate limiter
    pub fn limiter(&self) -> &RateLimiter {
        &self.limiter
    }
}

impl Default for RateLimitLayer {
    fn default() -> Self {
        Self::new()
    }
}

/// Rate limiting middleware
pub async fn rate_limit_middleware(
    limiter: axum::extract::State<RateLimiter>,
    connect_info: Option<ConnectInfo<SocketAddr>>,
    request: Request<Body>,
    next: Next,
) -> Response<Body> {
    let config = limiter.config();

    // Skip if disabled
    if !config.enabled {
        return next.run(request).await;
    }

    let path = request.uri().path().to_string();
    let headers = request.headers();
    let remote_addr = connect_info.map(|ci| ci.0);

    // Extract client IP
    let client_ip = match extract_client_ip(remote_addr, headers, config.trust_proxy_headers) {
        Some(ip) => ip,
        None => {
            // Can't determine client IP - allow request but log warning
            warn!("Rate limit: Could not determine client IP");
            return next.run(request).await;
        }
    };

    // Check rate limit
    match limiter.check(client_ip, &path) {
        Ok(()) => {
            let mut response = next.run(request).await;

            // Add rate limit headers
            let (rate, burst) = config.get_limit_for_path(&path);
            add_rate_limit_headers(response.headers_mut(), rate, burst);

            response
        }
        Err(RateLimitError::LimitExceeded { retry_after_secs }) => {
            warn!("Rate limit exceeded for {} on {}", client_ip, path);
            rate_limit_exceeded_response(retry_after_secs)
        }
        Err(e) => {
            warn!("Rate limit error: {}", e);
            next.run(request).await
        }
    }
}

/// Add rate limit headers to response
fn add_rate_limit_headers(headers: &mut axum::http::HeaderMap, rate: u32, burst: u32) {
    // Standard rate limit headers
    if let Ok(value) = HeaderValue::from_str(&rate.to_string()) {
        headers.insert("x-ratelimit-limit", value);
    }

    // RateLimit header (draft standard)
    if let Ok(value) =
        HeaderValue::from_str(&format!("limit={}, remaining={}, reset=1", burst, burst))
    {
        headers.insert("ratelimit", value);
    }
}

/// Generate rate limit exceeded response
fn rate_limit_exceeded_response(retry_after_secs: u64) -> Response<Body> {
    (
        StatusCode::TOO_MANY_REQUESTS,
        [
            (header::CONTENT_TYPE, "application/json; charset=utf-8"),
            (header::RETRY_AFTER, &retry_after_secs.to_string()),
        ],
        format!(
            r#"{{"error":{{"code":"RATE_LIMIT_EXCEEDED","message":"Too many requests","retryAfter":{}}}}}"#,
            retry_after_secs
        ),
    )
        .into_response()
}

/// Convenience function to create rate limit layer
pub fn layer() -> RateLimitLayer {
    RateLimitLayer::new()
}

/// Convenience function to create rate limit layer with config
pub fn layer_with_config(config: RateLimitConfig) -> RateLimitLayer {
    RateLimitLayer::with_config(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::thread::sleep;

    #[test]
    fn test_token_bucket_basic() {
        let mut bucket = TokenBucket::new(10, 10); // 10 req/sec, burst of 10

        // Should be able to consume all initial tokens
        for _ in 0..10 {
            assert!(bucket.try_consume());
        }

        // Should be empty now
        assert!(!bucket.try_consume());
    }

    #[test]
    fn test_token_bucket_refill() {
        let mut bucket = TokenBucket::new(100, 10); // 100 req/sec, burst of 10

        // Consume all tokens
        for _ in 0..10 {
            bucket.try_consume();
        }

        // Wait a bit for refill
        sleep(Duration::from_millis(50));

        // Should have some tokens now
        bucket.refill();
        assert!(bucket.tokens > 0.0);
    }

    #[test]
    fn test_rate_limiter_basic() {
        let config = RateLimitConfig {
            default_rate: 10,
            default_burst: 5,
            route_limits: vec![],
            enabled: true,
            exempt_loopback: false,
            ..Default::default()
        };

        let limiter = RateLimiter::new(config);
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        // Should allow first 5 requests
        for _ in 0..5 {
            assert!(limiter.check(ip, "/test").is_ok());
        }

        // 6th request should be rate limited
        assert!(limiter.check(ip, "/test").is_err());
    }

    #[test]
    fn test_rate_limiter_exempt_loopback() {
        let config = RateLimitConfig {
            default_rate: 1,
            default_burst: 1,
            exempt_loopback: true,
            ..Default::default()
        };

        let limiter = RateLimiter::new(config);
        let loopback = IpAddr::V4(Ipv4Addr::LOCALHOST);

        // Loopback should always be allowed
        for _ in 0..100 {
            assert!(limiter.check(loopback, "/test").is_ok());
        }
    }

    #[test]
    fn test_rate_limiter_per_route() {
        let config = RateLimitConfig {
            default_rate: 100,
            default_burst: 100,
            route_limits: vec![RouteLimitConfig::new("/hooks/", 2, 2)],
            enabled: true,
            exempt_loopback: false,
            ..Default::default()
        };

        let limiter = RateLimiter::new(config);
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        // /hooks/ should be rate limited after 2 requests
        assert!(limiter.check(ip, "/hooks/wake").is_ok());
        assert!(limiter.check(ip, "/hooks/agent").is_ok());
        assert!(limiter.check(ip, "/hooks/test").is_err());

        // But /other should still work
        for _ in 0..50 {
            assert!(limiter.check(ip, "/other").is_ok());
        }
    }

    #[test]
    fn test_rate_limiter_per_ip() {
        let config = RateLimitConfig {
            default_rate: 10,
            default_burst: 2,
            route_limits: vec![],
            enabled: true,
            exempt_loopback: false,
            ..Default::default()
        };

        let limiter = RateLimiter::new(config);
        let ip1 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let ip2 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2));

        // IP1 uses up its quota
        assert!(limiter.check(ip1, "/test").is_ok());
        assert!(limiter.check(ip1, "/test").is_ok());
        assert!(limiter.check(ip1, "/test").is_err());

        // IP2 should still have its own quota
        assert!(limiter.check(ip2, "/test").is_ok());
        assert!(limiter.check(ip2, "/test").is_ok());
    }

    #[test]
    fn test_config_builder() {
        let config = RateLimitConfig::builder()
            .default_rate(50)
            .default_burst(100)
            .route_limit("/api/", 20, 40)
            .enabled(true)
            .trust_proxy_headers(true)
            .exempt_loopback(false)
            .build();

        assert_eq!(config.default_rate, 50);
        assert_eq!(config.default_burst, 100);
        assert_eq!(config.route_limits.len(), 1);
        assert!(config.enabled);
        assert!(config.trust_proxy_headers);
        assert!(!config.exempt_loopback);
    }

    #[test]
    fn test_config_get_limit_for_path() {
        let config = RateLimitConfig {
            default_rate: 100,
            default_burst: 200,
            route_limits: vec![
                RouteLimitConfig::new("/hooks/", 10, 20),
                RouteLimitConfig::new("/tools/", 5, 10),
            ],
            ..Default::default()
        };

        assert_eq!(config.get_limit_for_path("/hooks/wake"), (10, 20));
        assert_eq!(config.get_limit_for_path("/tools/invoke"), (5, 10));
        assert_eq!(config.get_limit_for_path("/other/path"), (100, 200));
    }

    #[test]
    fn test_config_is_exempt() {
        let exempt_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let config = RateLimitConfig {
            exempt_ips: vec![exempt_ip],
            exempt_loopback: true,
            ..Default::default()
        };

        assert!(config.is_exempt(&exempt_ip));
        assert!(config.is_exempt(&IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert!(!config.is_exempt(&IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
    }

    #[test]
    fn test_extract_client_ip_direct() {
        let headers = axum::http::HeaderMap::new();
        let addr = Some(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            12345,
        ));

        let ip = extract_client_ip(addr, &headers, false);
        assert_eq!(ip, Some(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))));
    }

    #[test]
    fn test_extract_client_ip_xff() {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            "203.0.113.50, 70.41.3.18".parse().unwrap(),
        );
        let addr = Some(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            12345,
        ));

        // Without trust, should use direct address
        let ip = extract_client_ip(addr, &headers, false);
        assert_eq!(ip, Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));

        // With trust, should use XFF
        let ip = extract_client_ip(addr, &headers, true);
        assert_eq!(ip, Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 50))));
    }

    #[test]
    fn test_extract_client_ip_real_ip() {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("x-real-ip", "203.0.113.100".parse().unwrap());
        let addr = Some(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            12345,
        ));

        let ip = extract_client_ip(addr, &headers, true);
        assert_eq!(ip, Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 100))));
    }

    #[test]
    fn test_layer_creation() {
        let _layer = layer();
        let _layer_with_config = layer_with_config(RateLimitConfig::default());
    }

    #[test]
    fn test_limiter_stats() {
        let limiter = RateLimiter::new(RateLimitConfig::default());
        let stats = limiter.stats();

        assert_eq!(stats.total_buckets, 0);
        assert!(stats.config_enabled);
    }

    #[test]
    fn test_rate_limiter_disabled() {
        let config = RateLimitConfig {
            enabled: false,
            default_burst: 1,
            ..Default::default()
        };

        let limiter = RateLimiter::new(config);
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        // Should always allow when disabled
        for _ in 0..100 {
            assert!(limiter.check(ip, "/test").is_ok());
        }
    }

    #[test]
    fn test_time_until_available() {
        let bucket = TokenBucket {
            tokens: 0.5,
            last_refill: Instant::now(),
            rate: 1.0, // 1 token per second
            max_tokens: 10.0,
        };

        let time = bucket.time_until_available();
        // Need 0.5 more tokens, at 1/sec rate, should be ~0.5 seconds
        assert!(time.as_secs_f64() >= 0.4 && time.as_secs_f64() <= 0.6);
    }

    #[test]
    fn test_route_limit_config() {
        let config = RouteLimitConfig::new("/api/v1/", 50, 100);
        assert_eq!(config.prefix, "/api/v1/");
        assert_eq!(config.rate, 50);
        assert_eq!(config.burst, 100);
    }
}
