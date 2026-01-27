//! Authentication helpers
//!
//! Implements timing-safe comparisons, Tailscale header verification,
//! local-direct detection, and gateway token/password authorization.

use axum::http::HeaderMap;
use serde_json::Value;
use std::net::{IpAddr, SocketAddr};
use std::process::Command;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthMode {
    Token,
    Password,
}

#[derive(Clone, Debug)]
pub struct ResolvedGatewayAuth {
    pub mode: AuthMode,
    pub token: Option<String>,
    pub password: Option<String>,
    pub allow_tailscale: bool,
}

impl Default for ResolvedGatewayAuth {
    fn default() -> Self {
        Self {
            mode: AuthMode::Token,
            token: None,
            password: None,
            allow_tailscale: false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GatewayAuthMethod {
    Token,
    Password,
    Tailscale,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GatewayAuthFailure {
    TokenMissingConfig,
    TokenMissing,
    TokenMismatch,
    PasswordMissingConfig,
    PasswordMissing,
    PasswordMismatch,
    Unauthorized,
}

impl GatewayAuthFailure {
    pub fn message(self) -> &'static str {
        match self {
            GatewayAuthFailure::TokenMissingConfig => {
                "unauthorized: gateway token not configured on gateway (set gateway.auth.token)"
            }
            GatewayAuthFailure::TokenMissing => "unauthorized: token missing",
            GatewayAuthFailure::TokenMismatch => "unauthorized: token mismatch",
            GatewayAuthFailure::PasswordMissingConfig => {
                "unauthorized: gateway password not configured on gateway (set gateway.auth.password)"
            }
            GatewayAuthFailure::PasswordMissing => "unauthorized: password missing",
            GatewayAuthFailure::PasswordMismatch => "unauthorized: password mismatch",
            GatewayAuthFailure::Unauthorized => "unauthorized",
        }
    }
}

#[derive(Debug, Clone)]
pub struct GatewayAuthResult {
    pub ok: bool,
    pub method: Option<GatewayAuthMethod>,
    pub user: Option<String>,
    pub reason: Option<GatewayAuthFailure>,
}

/// Tailscale auth info extracted from headers.
#[derive(Debug, Clone)]
pub struct TailscaleAuth {
    pub user_login: String,
    pub user_name: Option<String>,
}

/// Timing-safe string equality.
pub fn timing_safe_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut out = 0u8;
    for (x, y) in a.bytes().zip(b.bytes()) {
        out |= x ^ y;
    }
    out == 0
}

/// Verify Tailscale authentication with a custom whois lookup.
///
/// Tailscale Serve adds trusted headers when proxying requests. We verify:
/// 1. Required headers are present (tailscale-user-login or x-tailscale-user)
/// 2. Proxy headers are present (x-forwarded-for/proto/host)
/// 3. The connection is from loopback (Serve proxy)
/// 4. tailscale whois for x-forwarded-for matches the header login
pub fn verify_tailscale_auth_with_whois<F>(
    headers: &HeaderMap,
    remote_addr: SocketAddr,
    whois_lookup: F,
) -> Option<TailscaleAuth>
where
    F: Fn(&str) -> Option<String>,
{
    let ip = remote_addr.ip();
    if !is_loopback_addr(ip) {
        tracing::debug!(ip = %ip, "tailscale auth rejected: not from loopback proxy");
        return None;
    }

    if !has_tailscale_proxy_headers(headers) {
        tracing::debug!("tailscale auth rejected: missing proxy headers");
        return None;
    }

    let user_login = header_value(headers, "tailscale-user-login")
        .or_else(|| header_value(headers, "x-tailscale-user"))?;
    let user_name = header_value(headers, "tailscale-user-name");

    let client_ip = parse_forwarded_for(header_value(headers, "x-forwarded-for"))?;
    let whois_login = whois_lookup(&client_ip)?;

    if normalize_login(&whois_login) != normalize_login(&user_login) {
        tracing::debug!(
            whois = %whois_login,
            header = %user_login,
            "tailscale auth rejected: login mismatch"
        );
        return None;
    }

    Some(TailscaleAuth {
        user_login: whois_login,
        user_name,
    })
}

/// Verify Tailscale authentication using `tailscale whois`.
pub fn verify_tailscale_auth(
    headers: &HeaderMap,
    remote_addr: SocketAddr,
) -> Option<TailscaleAuth> {
    verify_tailscale_auth_with_whois(headers, remote_addr, tailscale_whois_login)
}

/// Authorize a gateway connect attempt (WS/HTTP compatible).
///
/// Mirrors the Node.js gateway behavior for token/password + Tailscale auth.
pub fn authorize_gateway_connect(
    auth: &ResolvedGatewayAuth,
    token: Option<&str>,
    password: Option<&str>,
    headers: &HeaderMap,
    remote_addr: SocketAddr,
    trusted_proxies: &[String],
) -> GatewayAuthResult {
    let local_direct = is_local_direct_request(remote_addr, headers, trusted_proxies);

    if auth.allow_tailscale && !local_direct {
        if let Some(ts_auth) = verify_tailscale_auth(headers, remote_addr) {
            return GatewayAuthResult {
                ok: true,
                method: Some(GatewayAuthMethod::Tailscale),
                user: Some(ts_auth.user_login),
                reason: None,
            };
        }
    }

    match auth.mode {
        AuthMode::Token => {
            let Some(expected) = auth.token.as_deref() else {
                return GatewayAuthResult {
                    ok: false,
                    method: None,
                    user: None,
                    reason: Some(GatewayAuthFailure::TokenMissingConfig),
                };
            };
            let Some(provided) = token else {
                return GatewayAuthResult {
                    ok: false,
                    method: None,
                    user: None,
                    reason: Some(GatewayAuthFailure::TokenMissing),
                };
            };
            if timing_safe_eq(expected, provided) {
                return GatewayAuthResult {
                    ok: true,
                    method: Some(GatewayAuthMethod::Token),
                    user: None,
                    reason: None,
                };
            }
            GatewayAuthResult {
                ok: false,
                method: None,
                user: None,
                reason: Some(GatewayAuthFailure::TokenMismatch),
            }
        }
        AuthMode::Password => {
            let Some(expected) = auth.password.as_deref() else {
                return GatewayAuthResult {
                    ok: false,
                    method: None,
                    user: None,
                    reason: Some(GatewayAuthFailure::PasswordMissingConfig),
                };
            };
            let Some(provided) = password else {
                return GatewayAuthResult {
                    ok: false,
                    method: None,
                    user: None,
                    reason: Some(GatewayAuthFailure::PasswordMissing),
                };
            };
            if timing_safe_eq(expected, provided) {
                return GatewayAuthResult {
                    ok: true,
                    method: Some(GatewayAuthMethod::Password),
                    user: None,
                    reason: None,
                };
            }
            GatewayAuthResult {
                ok: false,
                method: None,
                user: None,
                reason: Some(GatewayAuthFailure::PasswordMismatch),
            }
        }
    }
}

/// Check if the request is from loopback (HTTP-only helper).
pub fn is_loopback_request(remote_addr: Option<IpAddr>, headers: &HeaderMap) -> bool {
    if let Some(addr) = remote_addr {
        if is_loopback_addr(addr) {
            if !has_proxy_headers(headers) {
                return true;
            }
        }
    }
    false
}

/// Check if an IP address is loopback.
pub fn is_loopback_addr(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => v4.is_loopback() || v4.octets()[0] == 127,
        IpAddr::V6(v6) => {
            v6.is_loopback() || {
                let octets = v6.octets();
                octets[0..10] == [0; 10]
                    && octets[10] == 0xff
                    && octets[11] == 0xff
                    && octets[12] == 127
            }
        }
    }
}

fn has_proxy_headers(headers: &HeaderMap) -> bool {
    headers.contains_key("x-forwarded-for")
        || headers.contains_key("x-forwarded-proto")
        || headers.contains_key("x-forwarded-host")
}

fn header_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn has_tailscale_proxy_headers(headers: &HeaderMap) -> bool {
    header_value(headers, "x-forwarded-for").is_some()
        && header_value(headers, "x-forwarded-proto").is_some()
        && header_value(headers, "x-forwarded-host").is_some()
}

fn normalize_login(login: &str) -> String {
    login.trim().to_lowercase()
}

fn extract_whois_login(value: &Value) -> Option<String> {
    let direct = value
        .get("LoginName")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    if direct.is_some() {
        return direct;
    }
    let paths = [
        "/UserProfile/LoginName",
        "/UserProfile/loginName",
        "/userProfile/loginName",
    ];
    for path in paths {
        if let Some(login) = value.pointer(path).and_then(|v| v.as_str()) {
            let trimmed = login.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
    }
    None
}

fn tailscale_whois_login(ip: &str) -> Option<String> {
    let output = Command::new("tailscale")
        .args(["whois", "--json", ip])
        .output()
        .ok()?;
    if !output.status.success() {
        tracing::debug!(code = ?output.status.code(), "tailscale whois failed");
        return None;
    }
    let value: Value = serde_json::from_slice(&output.stdout).ok()?;
    extract_whois_login(&value)
}

fn get_host_name(host_header: Option<String>) -> String {
    let host = host_header.unwrap_or_default();
    let trimmed = host.trim();
    if trimmed.starts_with('[') {
        if let Some(end) = trimmed.find(']') {
            return trimmed[1..end].to_string();
        }
    }
    trimmed.split(':').next().unwrap_or_default().to_string()
}

fn normalize_ip(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Some(stripped) = trimmed.strip_prefix("::ffff:") {
        return Some(stripped.to_string());
    }
    Some(trimmed.to_string())
}

fn parse_forwarded_for(value: Option<String>) -> Option<String> {
    let raw = value?;
    let first = raw.split(',').next()?.trim();
    normalize_ip(first)
}

fn is_loopback_address(ip: &str) -> bool {
    ip == "127.0.0.1" || ip.starts_with("127.") || ip == "::1" || ip.starts_with("::ffff:127.")
}

fn is_trusted_proxy(remote: Option<&str>, trusted: &[String]) -> bool {
    let remote = remote.and_then(normalize_ip);
    if remote.is_none() || trusted.is_empty() {
        return false;
    }
    let remote = remote.unwrap();
    trusted
        .iter()
        .filter_map(|p| normalize_ip(p))
        .any(|p| p == remote)
}

fn resolve_client_ip(
    remote: &str,
    forwarded_for: Option<String>,
    real_ip: Option<String>,
    trusted: &[String],
) -> Option<String> {
    if !is_trusted_proxy(Some(remote), trusted) {
        return normalize_ip(remote);
    }
    parse_forwarded_for(forwarded_for).or_else(|| normalize_ip(&real_ip.unwrap_or_default()))
}

/// Determine if the request is a local direct request.
pub fn is_local_direct_request(
    remote_addr: SocketAddr,
    headers: &HeaderMap,
    trusted: &[String],
) -> bool {
    let remote_ip = remote_addr.ip().to_string();
    let forwarded_for = header_value(headers, "x-forwarded-for");
    let real_ip = header_value(headers, "x-real-ip");
    let has_forwarded = forwarded_for.is_some() || real_ip.is_some();
    let host = get_host_name(header_value(headers, "host"));
    let host_is_local = host == "localhost" || host == "127.0.0.1" || host == "::1";
    let host_is_tailscale = host.ends_with(".ts.net");
    let client_ip = resolve_client_ip(&remote_ip, forwarded_for, real_ip, trusted);
    if !client_ip
        .as_ref()
        .map(|ip| is_loopback_address(ip))
        .unwrap_or(false)
    {
        return false;
    }
    (host_is_local || host_is_tailscale)
        && (!has_forwarded || is_trusted_proxy(Some(&remote_ip), trusted))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for (name, value) in pairs {
            headers.insert(
                axum::http::header::HeaderName::try_from(*name).unwrap(),
                axum::http::header::HeaderValue::from_str(value).unwrap(),
            );
        }
        headers
    }

    #[test]
    fn test_timing_safe_eq() {
        assert!(timing_safe_eq("abc", "abc"));
        assert!(!timing_safe_eq("abc", "abd"));
        assert!(!timing_safe_eq("abc", "ab"));
        assert!(!timing_safe_eq("ab", "abc"));
        assert!(timing_safe_eq("", ""));
    }

    #[test]
    fn test_tailscale_auth_requires_proxy_headers() {
        let headers = make_headers(&[("tailscale-user-login", "user@example.com")]);
        let addr = "127.0.0.1:1234".parse().unwrap();
        let auth = verify_tailscale_auth_with_whois(&headers, addr, |_| {
            Some("user@example.com".to_string())
        });
        assert!(auth.is_none());
    }

    #[test]
    fn test_tailscale_auth_accepts_loopback_with_matching_whois() {
        let headers = make_headers(&[
            ("tailscale-user-login", "user@example.com"),
            ("x-forwarded-for", "100.100.50.25"),
            ("x-forwarded-proto", "https"),
            ("x-forwarded-host", "example.ts.net"),
        ]);
        let addr = "127.0.0.1:1234".parse().unwrap();
        let auth = verify_tailscale_auth_with_whois(&headers, addr, |ip| {
            assert_eq!(ip, "100.100.50.25");
            Some("user@example.com".to_string())
        });
        assert!(auth.is_some());
    }

    #[test]
    fn test_tailscale_auth_accepts_x_tailscale_user_header() {
        let headers = make_headers(&[
            ("x-tailscale-user", "user@example.com"),
            ("x-forwarded-for", "100.100.50.25"),
            ("x-forwarded-proto", "https"),
            ("x-forwarded-host", "example.ts.net"),
        ]);
        let addr = "127.0.0.1:1234".parse().unwrap();
        let auth = verify_tailscale_auth_with_whois(&headers, addr, |_| {
            Some("user@example.com".to_string())
        });
        assert!(auth.is_some());
    }

    #[test]
    fn test_tailscale_auth_rejects_external_ip() {
        let headers = make_headers(&[
            ("tailscale-user-login", "user@example.com"),
            ("x-forwarded-for", "100.100.50.25"),
            ("x-forwarded-proto", "https"),
            ("x-forwarded-host", "example.ts.net"),
        ]);
        let addr = "8.8.8.8:1234".parse().unwrap();
        let auth = verify_tailscale_auth_with_whois(&headers, addr, |_| {
            Some("user@example.com".to_string())
        });
        assert!(auth.is_none());
    }

    #[test]
    fn test_tailscale_auth_rejects_missing_headers() {
        let headers = make_headers(&[]);
        let addr = "127.0.0.1:1234".parse().unwrap();
        let auth = verify_tailscale_auth_with_whois(&headers, addr, |_| {
            Some("user@example.com".to_string())
        });
        assert!(auth.is_none());
    }

    #[test]
    fn test_tailscale_auth_rejects_whois_mismatch() {
        let headers = make_headers(&[
            ("tailscale-user-login", "user@example.com"),
            ("x-forwarded-for", "100.100.50.25"),
            ("x-forwarded-proto", "https"),
            ("x-forwarded-host", "example.ts.net"),
        ]);
        let addr = "127.0.0.1:1234".parse().unwrap();
        let auth = verify_tailscale_auth_with_whois(&headers, addr, |_| {
            Some("other@example.com".to_string())
        });
        assert!(auth.is_none());
    }

    #[test]
    fn test_is_loopback_request() {
        let headers = HeaderMap::new();
        let addr = Some(IpAddr::V4("127.0.0.1".parse().unwrap()));
        assert!(is_loopback_request(addr, &headers));

        let addr = Some(IpAddr::V4("192.168.1.1".parse().unwrap()));
        assert!(!is_loopback_request(addr, &headers));

        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "1.2.3.4".parse().unwrap());
        let addr = Some(IpAddr::V4("127.0.0.1".parse().unwrap()));
        assert!(!is_loopback_request(addr, &headers));
    }
}
