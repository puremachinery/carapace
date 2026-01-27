//! Capability enforcement for WASM plugins
//!
//! This module implements security enforcement for plugin capabilities:
//! - Credential isolation: auto-prefix keys with plugin ID
//! - Config scoping: only allow plugins.<plugin-id>.* keys
//! - SSRF protection: block private IPv4/IPv6 ranges, localhost, cloud metadata
//! - Resource limits: track per-plugin HTTP request count (100/min)

use parking_lot::RwLock;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

/// Maximum HTTP requests per plugin per minute
pub const HTTP_RATE_LIMIT_PER_MINUTE: usize = 100;

/// Maximum log messages per plugin per minute
pub const LOG_RATE_LIMIT_PER_MINUTE: usize = 1000;

/// Capability enforcement errors
#[derive(Error, Debug, Clone, PartialEq)]
pub enum CapabilityError {
    #[error("Credential key access denied: {0}")]
    CredentialAccessDenied(String),

    #[error("Config key access denied: {0}")]
    ConfigAccessDenied(String),

    #[error("SSRF protection: blocked request to {0}")]
    SsrfBlocked(String),

    #[error("HTTP rate limit exceeded ({0} requests/minute)")]
    HttpRateLimitExceeded(usize),

    #[error("Log rate limit exceeded ({0} messages/minute)")]
    LogRateLimitExceeded(usize),

    #[error("Invalid URL: {0}")]
    InvalidUrl(String),

    #[error("Protocol not allowed: {0} (only http/https allowed)")]
    ProtocolNotAllowed(String),
}

/// Per-plugin rate limiter for tracking HTTP and logging rates
#[derive(Debug)]
pub struct PluginRateLimiter {
    /// Timestamps of HTTP requests (in seconds since epoch)
    http_requests: Vec<u64>,
    /// Timestamps of log messages (in seconds since epoch)
    log_messages: Vec<u64>,
}

impl Default for PluginRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl PluginRateLimiter {
    pub fn new() -> Self {
        Self {
            http_requests: Vec::new(),
            log_messages: Vec::new(),
        }
    }

    /// Check if an HTTP request is allowed, and record it if so
    pub fn check_http_request(&mut self) -> Result<(), CapabilityError> {
        let now = current_timestamp();
        self.prune_old_entries(now);

        if self.http_requests.len() >= HTTP_RATE_LIMIT_PER_MINUTE {
            return Err(CapabilityError::HttpRateLimitExceeded(
                HTTP_RATE_LIMIT_PER_MINUTE,
            ));
        }

        self.http_requests.push(now);
        Ok(())
    }

    /// Check if a log message is allowed, and record it if so
    pub fn check_log_message(&mut self) -> Result<(), CapabilityError> {
        let now = current_timestamp();
        self.prune_old_entries(now);

        if self.log_messages.len() >= LOG_RATE_LIMIT_PER_MINUTE {
            return Err(CapabilityError::LogRateLimitExceeded(
                LOG_RATE_LIMIT_PER_MINUTE,
            ));
        }

        self.log_messages.push(now);
        Ok(())
    }

    /// Remove entries older than 60 seconds
    fn prune_old_entries(&mut self, now: u64) {
        let cutoff = now.saturating_sub(60);
        self.http_requests.retain(|&ts| ts > cutoff);
        self.log_messages.retain(|&ts| ts > cutoff);
    }

    /// Get current HTTP request count in the last minute
    pub fn http_request_count(&self) -> usize {
        self.http_requests.len()
    }

    /// Get current log message count in the last minute
    pub fn log_message_count(&self) -> usize {
        self.log_messages.len()
    }
}

/// Global rate limiter tracker for all plugins
#[derive(Debug, Default)]
pub struct RateLimiterRegistry {
    limiters: RwLock<HashMap<String, PluginRateLimiter>>,
}

impl RateLimiterRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Get or create a rate limiter for a plugin
    pub fn get_or_create(&self, plugin_id: &str) -> PluginRateLimiter {
        let mut limiters = self.limiters.write();
        limiters.entry(plugin_id.to_string()).or_default().clone()
    }

    /// Update the rate limiter for a plugin
    pub fn update(&self, plugin_id: &str, limiter: PluginRateLimiter) {
        let mut limiters = self.limiters.write();
        limiters.insert(plugin_id.to_string(), limiter);
    }

    /// Check and record an HTTP request for a plugin
    pub fn check_http_request(&self, plugin_id: &str) -> Result<(), CapabilityError> {
        let mut limiters = self.limiters.write();
        let limiter = limiters.entry(plugin_id.to_string()).or_default();
        limiter.check_http_request()
    }

    /// Check and record a log message for a plugin
    pub fn check_log_message(&self, plugin_id: &str) -> Result<(), CapabilityError> {
        let mut limiters = self.limiters.write();
        let limiter = limiters.entry(plugin_id.to_string()).or_default();
        limiter.check_log_message()
    }
}

// Clone implementation for PluginRateLimiter (needed for get_or_create)
impl Clone for PluginRateLimiter {
    fn clone(&self) -> Self {
        Self {
            http_requests: self.http_requests.clone(),
            log_messages: self.log_messages.clone(),
        }
    }
}

/// Get current timestamp in seconds since epoch
fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Credential key enforcement
///
/// Ensures plugins can only access their own credentials by auto-prefixing
/// all keys with the plugin ID. Also sanitizes keys to prevent path traversal.
pub struct CredentialEnforcer;

impl CredentialEnforcer {
    /// Prefix a credential key with the plugin ID
    ///
    /// Input: plugin_id="msteams", key="token"
    /// Output: "msteams:token"
    pub fn prefix_key(plugin_id: &str, key: &str) -> String {
        let sanitized_plugin_id = Self::sanitize_plugin_id(plugin_id);
        let sanitized_key = Self::sanitize_key(key);
        format!("{}:{}", sanitized_plugin_id, sanitized_key)
    }

    /// Sanitize plugin ID to prevent path traversal
    fn sanitize_plugin_id(plugin_id: &str) -> String {
        plugin_id.replace("..", "_").replace(['/', '\\', ':'], "_")
    }

    /// Sanitize key to prevent injection attacks
    fn sanitize_key(key: &str) -> String {
        key.replace("..", "_").replace(['/', '\\'], "_")
    }

    /// Check if a key is valid (not too long, no invalid characters)
    pub fn validate_key(key: &str) -> Result<(), CapabilityError> {
        const MAX_KEY_LENGTH: usize = 64;

        if key.len() > MAX_KEY_LENGTH {
            return Err(CapabilityError::CredentialAccessDenied(format!(
                "Key too long: {} chars (max {})",
                key.len(),
                MAX_KEY_LENGTH
            )));
        }

        if key.is_empty() {
            return Err(CapabilityError::CredentialAccessDenied(
                "Key cannot be empty".to_string(),
            ));
        }

        Ok(())
    }
}

/// Config access enforcement
///
/// Ensures plugins can only read config keys under plugins.<plugin-id>.*
pub struct ConfigEnforcer;

impl ConfigEnforcer {
    /// Check if a plugin can access a config key
    pub fn check_access(plugin_id: &str, key: &str) -> Result<(), CapabilityError> {
        let allowed_prefix = format!("plugins.{}.", plugin_id);

        if !key.starts_with(&allowed_prefix) {
            return Err(CapabilityError::ConfigAccessDenied(format!(
                "Plugin '{}' can only access keys under '{}'",
                plugin_id, allowed_prefix
            )));
        }

        Ok(())
    }

    /// Transform a relative key to the full config path
    ///
    /// Input: plugin_id="msteams", key="webhook_url"
    /// Output: "plugins.msteams.webhook_url"
    pub fn full_key(plugin_id: &str, key: &str) -> String {
        format!("plugins.{}.{}", plugin_id, key)
    }
}

/// SSRF protection configuration
#[derive(Debug, Clone, Default)]
pub struct SsrfConfig {
    /// Allow Tailscale IPs (100.64.0.0/10 subset used by Tailscale).
    /// Enable this when the gateway runs on a Tailscale network and plugins
    /// need to access other Tailscale hosts. Default: false (block CGNAT).
    pub allow_tailscale: bool,
}

/// SSRF protection for HTTP requests
///
/// Blocks requests to:
/// - IPv4 private ranges: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
/// - IPv4 link-local: 169.254.0.0/16
/// - IPv4 localhost: 127.0.0.0/8
/// - IPv4 CGNAT: 100.64.0.0/10 (unless allow_tailscale is set)
/// - IPv6 private: fc00::/7 (unique local addresses)
/// - IPv6 link-local: fe80::/10
/// - IPv6 localhost: ::1
/// - Cloud metadata endpoints (169.254.169.254, fd00:ec2::254)
///
/// # Tailscale Compatibility
///
/// Tailscale uses addresses from 100.64.0.0/10 (CGNAT range). By default,
/// these are blocked to prevent SSRF attacks. If your deployment runs on
/// Tailscale and plugins need to access other Tailscale hosts, set
/// `allow_tailscale: true` in the SsrfConfig.
///
/// # Security Note: DNS Rebinding Protection
///
/// URL validation alone is NOT sufficient for SSRF protection. When implementing
/// HTTP fetch, you MUST:
///
/// 1. Call `validate_url()` to check the literal URL (catches obvious attacks)
/// 2. Resolve DNS to get the actual IP address(es)
/// 3. Call `validate_resolved_ip()` on EACH resolved IP before connecting
/// 4. Use the validated IP directly for the connection (not the hostname)
///
/// This prevents DNS rebinding attacks where an attacker's DNS initially returns
/// a public IP, passes validation, then returns a private IP for the actual request.
pub struct SsrfProtection;

impl SsrfProtection {
    /// Validate a URL for SSRF protection with default config (blocks CGNAT/Tailscale)
    pub fn validate_url(url: &str) -> Result<(), CapabilityError> {
        Self::validate_url_with_config(url, &SsrfConfig::default())
    }

    /// Validate a URL for SSRF protection with custom config
    pub fn validate_url_with_config(url: &str, config: &SsrfConfig) -> Result<(), CapabilityError> {
        // Parse the URL
        let parsed = url::Url::parse(url)
            .map_err(|e| CapabilityError::InvalidUrl(format!("{}: {}", url, e)))?;

        // Check protocol
        match parsed.scheme() {
            "http" | "https" => {}
            scheme => {
                return Err(CapabilityError::ProtocolNotAllowed(scheme.to_string()));
            }
        }

        // Get the host
        let host = parsed
            .host_str()
            .ok_or_else(|| CapabilityError::InvalidUrl("No host in URL".to_string()))?;

        // Check for localhost variants
        if Self::is_localhost(host) {
            return Err(CapabilityError::SsrfBlocked(format!(
                "localhost address: {}",
                host
            )));
        }

        // Check for cloud metadata endpoints
        if Self::is_metadata_endpoint(host) {
            return Err(CapabilityError::SsrfBlocked(format!(
                "cloud metadata endpoint: {}",
                host
            )));
        }

        // Try to parse as IP address
        if let Ok(ip) = host.parse::<IpAddr>() {
            if Self::is_private_ip_with_config(&ip, config) {
                return Err(CapabilityError::SsrfBlocked(format!(
                    "private IP address: {}",
                    ip
                )));
            }
        }

        // Handle bracketed IPv6 addresses (e.g., [fc00::1])
        if host.starts_with('[') && host.ends_with(']') {
            let inner = &host[1..host.len() - 1];
            if let Ok(ip) = inner.parse::<Ipv6Addr>() {
                if Self::is_private_ip_with_config(&IpAddr::V6(ip), config) {
                    return Err(CapabilityError::SsrfBlocked(format!(
                        "private IP address: {}",
                        ip
                    )));
                }
            }
        }

        Ok(())
    }

    /// Validate a resolved IP address for SSRF protection (default config).
    pub fn validate_resolved_ip(ip: &IpAddr, original_host: &str) -> Result<(), CapabilityError> {
        Self::validate_resolved_ip_with_config(ip, original_host, &SsrfConfig::default())
    }

    /// Validate a resolved IP address for SSRF protection with custom config.
    ///
    /// This MUST be called after DNS resolution, before making the actual connection.
    /// Validates that the resolved IP is not a private/internal address.
    ///
    /// # Arguments
    /// * `ip` - The IP address from DNS resolution
    /// * `original_host` - The original hostname (for error messages)
    /// * `config` - SSRF configuration (e.g., whether to allow Tailscale IPs)
    ///
    /// # Example
    /// ```ignore
    /// // After DNS resolution
    /// let config = SsrfConfig { allow_tailscale: true };
    /// for ip in resolved_ips {
    ///     SsrfProtection::validate_resolved_ip_with_config(&ip, hostname, &config)?;
    /// }
    /// // Now safe to connect using one of the validated IPs
    /// ```
    pub fn validate_resolved_ip_with_config(
        ip: &IpAddr,
        original_host: &str,
        config: &SsrfConfig,
    ) -> Result<(), CapabilityError> {
        if Self::is_private_ip_with_config(ip, config) {
            return Err(CapabilityError::SsrfBlocked(format!(
                "DNS {} resolved to private IP: {}",
                original_host, ip
            )));
        }
        Ok(())
    }

    /// Check if a host is localhost
    fn is_localhost(host: &str) -> bool {
        let host_lower = host.to_lowercase();

        // Hostname checks
        if host_lower == "localhost"
            || host_lower == "localhost.localdomain"
            || host_lower.ends_with(".localhost")
        {
            return true;
        }

        // IPv4 localhost (127.0.0.0/8)
        if let Ok(ip) = host.parse::<Ipv4Addr>() {
            if ip.octets()[0] == 127 {
                return true;
            }
        }

        // IPv6 localhost (::1)
        if let Ok(ip) = host.parse::<Ipv6Addr>() {
            if ip == Ipv6Addr::LOCALHOST {
                return true;
            }
        }

        // Bracketed IPv6 (e.g., [::1])
        if host.starts_with('[') && host.ends_with(']') {
            let inner = &host[1..host.len() - 1];
            if let Ok(ip) = inner.parse::<Ipv6Addr>() {
                if ip == Ipv6Addr::LOCALHOST {
                    return true;
                }
            }
        }

        false
    }

    /// Check if a host is a cloud metadata endpoint
    fn is_metadata_endpoint(host: &str) -> bool {
        // AWS/GCP/Azure metadata endpoint
        if host == "169.254.169.254" {
            return true;
        }

        // AWS EC2 IPv6 metadata endpoint
        if host == "fd00:ec2::254" || host == "[fd00:ec2::254]" {
            return true;
        }

        // AWS metadata hostname
        if host == "instance-data" || host.ends_with(".internal") {
            return true;
        }

        // GCP metadata hostname
        if host == "metadata.google.internal" || host == "metadata" {
            return true;
        }

        // Azure metadata endpoint
        if host == "169.254.169.254" {
            return true;
        }

        false
    }

    /// Check if an IP address is private/internal (default config)
    fn is_private_ip(ip: &IpAddr) -> bool {
        Self::is_private_ip_with_config(ip, &SsrfConfig::default())
    }

    /// Check if an IP address is private/internal with custom config
    fn is_private_ip_with_config(ip: &IpAddr, config: &SsrfConfig) -> bool {
        match ip {
            IpAddr::V4(ipv4) => Self::is_private_ipv4_with_config(ipv4, config),
            IpAddr::V6(ipv6) => Self::is_private_ipv6(ipv6),
        }
    }

    /// Check if an IPv4 address is in the Tailscale CGNAT range (100.64.0.0/10)
    fn is_tailscale_ip(ip: &Ipv4Addr) -> bool {
        let octets = ip.octets();
        octets[0] == 100 && (64..=127).contains(&octets[1])
    }

    /// Check if an IPv4 address is private (default config)
    fn is_private_ipv4(ip: &Ipv4Addr) -> bool {
        Self::is_private_ipv4_with_config(ip, &SsrfConfig::default())
    }

    /// Check if an IPv4 address is private with custom config
    fn is_private_ipv4_with_config(ip: &Ipv4Addr, config: &SsrfConfig) -> bool {
        let octets = ip.octets();

        // 10.0.0.0/8 - Private Class A
        if octets[0] == 10 {
            return true;
        }

        // 172.16.0.0/12 - Private Class B
        if octets[0] == 172 && (16..=31).contains(&octets[1]) {
            return true;
        }

        // 192.168.0.0/16 - Private Class C
        if octets[0] == 192 && octets[1] == 168 {
            return true;
        }

        // 127.0.0.0/8 - Loopback
        if octets[0] == 127 {
            return true;
        }

        // 169.254.0.0/16 - Link-local
        if octets[0] == 169 && octets[1] == 254 {
            return true;
        }

        // 0.0.0.0/8 - Current network
        if octets[0] == 0 {
            return true;
        }

        // 100.64.0.0/10 - Carrier-grade NAT (also Tailscale range)
        // Skip this check if allow_tailscale is enabled
        if Self::is_tailscale_ip(ip) && !config.allow_tailscale {
            return true;
        }

        // 192.0.0.0/24 - IETF protocol assignments
        if octets[0] == 192 && octets[1] == 0 && octets[2] == 0 {
            return true;
        }

        // 192.0.2.0/24 - TEST-NET-1
        if octets[0] == 192 && octets[1] == 0 && octets[2] == 2 {
            return true;
        }

        // 198.51.100.0/24 - TEST-NET-2
        if octets[0] == 198 && octets[1] == 51 && octets[2] == 100 {
            return true;
        }

        // 203.0.113.0/24 - TEST-NET-3
        if octets[0] == 203 && octets[1] == 0 && octets[2] == 113 {
            return true;
        }

        // 224.0.0.0/4 - Multicast
        if octets[0] >= 224 && octets[0] <= 239 {
            return true;
        }

        // 240.0.0.0/4 - Reserved for future use
        if octets[0] >= 240 {
            return true;
        }

        false
    }

    /// Check if an IPv6 address is private
    fn is_private_ipv6(ip: &Ipv6Addr) -> bool {
        let segments = ip.segments();

        // ::1 - Loopback
        if *ip == Ipv6Addr::LOCALHOST {
            return true;
        }

        // :: - Unspecified
        if *ip == Ipv6Addr::UNSPECIFIED {
            return true;
        }

        // fc00::/7 - Unique local addresses (ULA)
        // First segment starts with 0xfc or 0xfd
        if (segments[0] & 0xfe00) == 0xfc00 {
            return true;
        }

        // fe80::/10 - Link-local
        if (segments[0] & 0xffc0) == 0xfe80 {
            return true;
        }

        // ff00::/8 - Multicast
        if (segments[0] & 0xff00) == 0xff00 {
            return true;
        }

        // ::ffff:0:0/96 - IPv4-mapped addresses (check the IPv4 part)
        if segments[0] == 0
            && segments[1] == 0
            && segments[2] == 0
            && segments[3] == 0
            && segments[4] == 0
            && segments[5] == 0xffff
        {
            let ipv4 = Ipv4Addr::new(
                (segments[6] >> 8) as u8,
                (segments[6] & 0xff) as u8,
                (segments[7] >> 8) as u8,
                (segments[7] & 0xff) as u8,
            );
            return Self::is_private_ipv4(&ipv4);
        }

        // 2001:db8::/32 - Documentation
        if segments[0] == 0x2001 && segments[1] == 0x0db8 {
            return true;
        }

        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ============== Credential Enforcer Tests ==============

    #[test]
    fn test_credential_prefix_key() {
        assert_eq!(
            CredentialEnforcer::prefix_key("msteams", "token"),
            "msteams:token"
        );
    }

    #[test]
    fn test_credential_prefix_key_sanitizes_plugin_id() {
        // Path traversal attempts should be sanitized
        assert_eq!(
            CredentialEnforcer::prefix_key("../malicious", "token"),
            "__malicious:token"
        );
        assert_eq!(
            CredentialEnforcer::prefix_key("plugin/sub", "token"),
            "plugin_sub:token"
        );
        assert_eq!(
            CredentialEnforcer::prefix_key("plugin:colon", "token"),
            "plugin_colon:token"
        );
    }

    #[test]
    fn test_credential_prefix_key_sanitizes_key() {
        assert_eq!(
            CredentialEnforcer::prefix_key("msteams", "../secret"),
            "msteams:__secret"
        );
    }

    #[test]
    fn test_credential_validate_key_valid() {
        assert!(CredentialEnforcer::validate_key("token").is_ok());
        assert!(CredentialEnforcer::validate_key("api-key").is_ok());
        assert!(CredentialEnforcer::validate_key("my_credential_123").is_ok());
    }

    #[test]
    fn test_credential_validate_key_too_long() {
        let long_key = "x".repeat(100);
        let result = CredentialEnforcer::validate_key(&long_key);
        assert!(matches!(
            result,
            Err(CapabilityError::CredentialAccessDenied(_))
        ));
    }

    #[test]
    fn test_credential_validate_key_empty() {
        let result = CredentialEnforcer::validate_key("");
        assert!(matches!(
            result,
            Err(CapabilityError::CredentialAccessDenied(_))
        ));
    }

    // ============== Config Enforcer Tests ==============

    #[test]
    fn test_config_check_access_allowed() {
        assert!(ConfigEnforcer::check_access("msteams", "plugins.msteams.webhook_url").is_ok());
        assert!(ConfigEnforcer::check_access("msteams", "plugins.msteams.nested.key").is_ok());
    }

    #[test]
    fn test_config_check_access_denied() {
        // Trying to access another plugin's config
        let result = ConfigEnforcer::check_access("msteams", "plugins.other.webhook_url");
        assert!(matches!(
            result,
            Err(CapabilityError::ConfigAccessDenied(_))
        ));

        // Trying to access gateway-level config
        let result = ConfigEnforcer::check_access("msteams", "gateway.token");
        assert!(matches!(
            result,
            Err(CapabilityError::ConfigAccessDenied(_))
        ));

        // Trying to access root config
        let result = ConfigEnforcer::check_access("msteams", "auth.apiKey");
        assert!(matches!(
            result,
            Err(CapabilityError::ConfigAccessDenied(_))
        ));
    }

    #[test]
    fn test_config_full_key() {
        assert_eq!(
            ConfigEnforcer::full_key("msteams", "webhook_url"),
            "plugins.msteams.webhook_url"
        );
    }

    // ============== SSRF Protection Tests ==============

    #[test]
    fn test_ssrf_valid_urls() {
        assert!(SsrfProtection::validate_url("https://api.example.com/data").is_ok());
        assert!(SsrfProtection::validate_url("http://example.com:8080/path").is_ok());
        assert!(SsrfProtection::validate_url("https://1.2.3.4/api").is_ok());
    }

    #[test]
    fn test_ssrf_blocks_localhost() {
        let result = SsrfProtection::validate_url("http://localhost/");
        assert!(matches!(result, Err(CapabilityError::SsrfBlocked(_))));

        let result = SsrfProtection::validate_url("http://127.0.0.1/");
        assert!(matches!(result, Err(CapabilityError::SsrfBlocked(_))));

        let result = SsrfProtection::validate_url("http://127.0.0.42/");
        assert!(matches!(result, Err(CapabilityError::SsrfBlocked(_))));

        let result = SsrfProtection::validate_url("http://[::1]/");
        assert!(matches!(result, Err(CapabilityError::SsrfBlocked(_))));
    }

    #[test]
    fn test_ssrf_blocks_private_ipv4() {
        // 10.0.0.0/8
        let result = SsrfProtection::validate_url("http://10.0.0.1/");
        assert!(matches!(result, Err(CapabilityError::SsrfBlocked(_))));

        let result = SsrfProtection::validate_url("http://10.255.255.255/");
        assert!(matches!(result, Err(CapabilityError::SsrfBlocked(_))));

        // 172.16.0.0/12
        let result = SsrfProtection::validate_url("http://172.16.0.1/");
        assert!(matches!(result, Err(CapabilityError::SsrfBlocked(_))));

        let result = SsrfProtection::validate_url("http://172.31.255.255/");
        assert!(matches!(result, Err(CapabilityError::SsrfBlocked(_))));

        // But 172.15.x.x should be allowed
        assert!(SsrfProtection::validate_url("http://172.15.0.1/").is_ok());

        // 192.168.0.0/16
        let result = SsrfProtection::validate_url("http://192.168.1.1/");
        assert!(matches!(result, Err(CapabilityError::SsrfBlocked(_))));
    }

    #[test]
    fn test_ssrf_blocks_link_local() {
        // 169.254.0.0/16
        let result = SsrfProtection::validate_url("http://169.254.1.1/");
        assert!(matches!(result, Err(CapabilityError::SsrfBlocked(_))));
    }

    #[test]
    fn test_ssrf_blocks_metadata_endpoints() {
        // AWS/GCP/Azure metadata
        let result = SsrfProtection::validate_url("http://169.254.169.254/");
        assert!(matches!(result, Err(CapabilityError::SsrfBlocked(_))));

        let result = SsrfProtection::validate_url("http://169.254.169.254/latest/meta-data/");
        assert!(matches!(result, Err(CapabilityError::SsrfBlocked(_))));

        // GCP metadata hostname
        let result = SsrfProtection::validate_url("http://metadata.google.internal/");
        assert!(matches!(result, Err(CapabilityError::SsrfBlocked(_))));
    }

    #[test]
    fn test_ssrf_blocks_private_ipv6() {
        // Unique local addresses (fc00::/7)
        let result = SsrfProtection::validate_url("http://[fc00::1]/");
        assert!(matches!(result, Err(CapabilityError::SsrfBlocked(_))));

        let result = SsrfProtection::validate_url("http://[fd00::1]/");
        assert!(matches!(result, Err(CapabilityError::SsrfBlocked(_))));

        // Link-local (fe80::/10)
        let result = SsrfProtection::validate_url("http://[fe80::1]/");
        assert!(matches!(result, Err(CapabilityError::SsrfBlocked(_))));
    }

    #[test]
    fn test_ssrf_blocks_invalid_protocols() {
        let result = SsrfProtection::validate_url("file:///etc/passwd");
        assert!(matches!(
            result,
            Err(CapabilityError::ProtocolNotAllowed(_))
        ));

        let result = SsrfProtection::validate_url("ftp://example.com/file");
        assert!(matches!(
            result,
            Err(CapabilityError::ProtocolNotAllowed(_))
        ));

        let result = SsrfProtection::validate_url("gopher://example.com/");
        assert!(matches!(
            result,
            Err(CapabilityError::ProtocolNotAllowed(_))
        ));
    }

    #[test]
    fn test_ssrf_invalid_url() {
        let result = SsrfProtection::validate_url("not a url");
        assert!(matches!(result, Err(CapabilityError::InvalidUrl(_))));
    }

    // ============== Rate Limiter Tests ==============

    #[test]
    fn test_rate_limiter_allows_under_limit() {
        let mut limiter = PluginRateLimiter::new();

        for _ in 0..HTTP_RATE_LIMIT_PER_MINUTE {
            assert!(limiter.check_http_request().is_ok());
        }
    }

    #[test]
    fn test_rate_limiter_blocks_over_limit() {
        let mut limiter = PluginRateLimiter::new();

        // Fill up to limit
        for _ in 0..HTTP_RATE_LIMIT_PER_MINUTE {
            assert!(limiter.check_http_request().is_ok());
        }

        // Next should be blocked
        let result = limiter.check_http_request();
        assert!(matches!(
            result,
            Err(CapabilityError::HttpRateLimitExceeded(_))
        ));
    }

    #[test]
    fn test_rate_limiter_log_messages() {
        let mut limiter = PluginRateLimiter::new();

        for _ in 0..LOG_RATE_LIMIT_PER_MINUTE {
            assert!(limiter.check_log_message().is_ok());
        }

        let result = limiter.check_log_message();
        assert!(matches!(
            result,
            Err(CapabilityError::LogRateLimitExceeded(_))
        ));
    }

    #[test]
    fn test_rate_limiter_registry() {
        let registry = RateLimiterRegistry::new();

        // Different plugins have separate limits
        for _ in 0..HTTP_RATE_LIMIT_PER_MINUTE {
            assert!(registry.check_http_request("plugin-a").is_ok());
            assert!(registry.check_http_request("plugin-b").is_ok());
        }

        // Both should now be at limit
        assert!(registry.check_http_request("plugin-a").is_err());
        assert!(registry.check_http_request("plugin-b").is_err());
    }

    // ============== IPv4 Private Range Edge Cases ==============

    #[test]
    fn test_ipv4_private_range_boundaries() {
        // 172.16.0.0/12 boundary tests
        assert!(SsrfProtection::is_private_ipv4(&Ipv4Addr::new(
            172, 16, 0, 0
        )));
        assert!(SsrfProtection::is_private_ipv4(&Ipv4Addr::new(
            172, 31, 255, 255
        )));
        assert!(!SsrfProtection::is_private_ipv4(&Ipv4Addr::new(
            172, 15, 255, 255
        )));
        assert!(!SsrfProtection::is_private_ipv4(&Ipv4Addr::new(
            172, 32, 0, 0
        )));
    }

    #[test]
    fn test_carrier_grade_nat() {
        // 100.64.0.0/10
        assert!(SsrfProtection::is_private_ipv4(&Ipv4Addr::new(
            100, 64, 0, 0
        )));
        assert!(SsrfProtection::is_private_ipv4(&Ipv4Addr::new(
            100, 127, 255, 255
        )));
        assert!(!SsrfProtection::is_private_ipv4(&Ipv4Addr::new(
            100, 63, 255, 255
        )));
        assert!(!SsrfProtection::is_private_ipv4(&Ipv4Addr::new(
            100, 128, 0, 0
        )));
    }

    // ============== IPv6 Edge Cases ==============

    #[test]
    fn test_ipv6_ula_boundary() {
        // fc00::/7 includes fc00:: through fdff::
        assert!(SsrfProtection::is_private_ipv6(
            &"fc00::1".parse::<Ipv6Addr>().unwrap()
        ));
        assert!(SsrfProtection::is_private_ipv6(
            &"fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"
                .parse::<Ipv6Addr>()
                .unwrap()
        ));
        // fe00:: is NOT in fc00::/7
        assert!(!SsrfProtection::is_private_ipv6(
            &"fe00::1".parse::<Ipv6Addr>().unwrap()
        ));
    }

    #[test]
    fn test_ipv4_mapped_ipv6() {
        // ::ffff:192.168.1.1 should be blocked as private
        let mapped = Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0xc0a8, 0x0101);
        assert!(SsrfProtection::is_private_ipv6(&mapped));

        // ::ffff:8.8.8.8 should be allowed
        let mapped_public = Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0x0808, 0x0808);
        assert!(!SsrfProtection::is_private_ipv6(&mapped_public));
    }

    // ============== Resolved IP Validation Tests ==============

    #[test]
    fn test_validate_resolved_ip_blocks_private() {
        use std::net::Ipv4Addr;

        // Private IP should be blocked
        let private_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let result = SsrfProtection::validate_resolved_ip(&private_ip, "evil.com");
        assert!(matches!(result, Err(CapabilityError::SsrfBlocked(_))));

        // Localhost should be blocked
        let localhost = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let result = SsrfProtection::validate_resolved_ip(&localhost, "evil.com");
        assert!(matches!(result, Err(CapabilityError::SsrfBlocked(_))));

        // Cloud metadata should be blocked
        let metadata = IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254));
        let result = SsrfProtection::validate_resolved_ip(&metadata, "evil.com");
        assert!(matches!(result, Err(CapabilityError::SsrfBlocked(_))));
    }

    #[test]
    fn test_validate_resolved_ip_allows_public() {
        use std::net::Ipv4Addr;

        // Public IP should be allowed
        let public_ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        let result = SsrfProtection::validate_resolved_ip(&public_ip, "google.com");
        assert!(result.is_ok());

        // Another public IP
        let public_ip2 = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
        let result = SsrfProtection::validate_resolved_ip(&public_ip2, "cloudflare.com");
        assert!(result.is_ok());
    }

    // ============== Tailscale IP Configuration Tests ==============

    #[test]
    fn test_tailscale_ip_detection() {
        // Tailscale range: 100.64.0.0/10
        assert!(SsrfProtection::is_tailscale_ip(&Ipv4Addr::new(
            100, 64, 0, 1
        )));
        assert!(SsrfProtection::is_tailscale_ip(&Ipv4Addr::new(
            100, 100, 50, 25
        )));
        assert!(SsrfProtection::is_tailscale_ip(&Ipv4Addr::new(
            100, 127, 255, 255
        )));

        // Outside Tailscale range
        assert!(!SsrfProtection::is_tailscale_ip(&Ipv4Addr::new(
            100, 63, 255, 255
        )));
        assert!(!SsrfProtection::is_tailscale_ip(&Ipv4Addr::new(
            100, 128, 0, 0
        )));
        assert!(!SsrfProtection::is_tailscale_ip(&Ipv4Addr::new(8, 8, 8, 8)));
    }

    #[test]
    fn test_ssrf_blocks_tailscale_by_default() {
        // Default config should block Tailscale IPs
        let tailscale_ip = IpAddr::V4(Ipv4Addr::new(100, 100, 50, 25));
        let result = SsrfProtection::validate_resolved_ip(&tailscale_ip, "tailscale-host");
        assert!(matches!(result, Err(CapabilityError::SsrfBlocked(_))));

        // URL validation should also block
        let result = SsrfProtection::validate_url("http://100.100.50.25/api");
        assert!(matches!(result, Err(CapabilityError::SsrfBlocked(_))));
    }

    #[test]
    fn test_ssrf_allows_tailscale_when_configured() {
        let config = SsrfConfig {
            allow_tailscale: true,
        };

        // Tailscale IP should be allowed with config
        let tailscale_ip = IpAddr::V4(Ipv4Addr::new(100, 100, 50, 25));
        let result = SsrfProtection::validate_resolved_ip_with_config(
            &tailscale_ip,
            "tailscale-host",
            &config,
        );
        assert!(result.is_ok());

        // URL validation should also allow
        let result = SsrfProtection::validate_url_with_config("http://100.100.50.25/api", &config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_ssrf_still_blocks_other_private_when_tailscale_allowed() {
        let config = SsrfConfig {
            allow_tailscale: true,
        };

        // Other private ranges should still be blocked
        let private_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let result =
            SsrfProtection::validate_resolved_ip_with_config(&private_ip, "internal-host", &config);
        assert!(matches!(result, Err(CapabilityError::SsrfBlocked(_))));

        // Loopback should still be blocked
        let localhost = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let result =
            SsrfProtection::validate_resolved_ip_with_config(&localhost, "localhost", &config);
        assert!(matches!(result, Err(CapabilityError::SsrfBlocked(_))));
    }

    // TODO: Add integration test for DNS rebinding when http_fetch is implemented.
    // The test should:
    // 1. Set up a mock DNS that returns different IPs on subsequent queries
    // 2. First query returns public IP (1.2.3.4), passes validation
    // 3. Second query returns private IP (10.0.0.1)
    // 4. Verify that the connection uses validate_resolved_ip and blocks
}
