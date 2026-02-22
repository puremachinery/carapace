//! Authentication helpers
//!
//! Implements timing-safe comparisons, Tailscale header verification,
//! local-direct detection, and gateway token/password authorization.

pub mod profiles;

use axum::http::HeaderMap;
use serde_json::Value;
use std::net::{IpAddr, SocketAddr};

use crate::agent::sandbox::{
    default_tailscale_cli_sandbox_config, ensure_sandbox_supported,
    run_sandboxed_std_command_output,
};

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum AuthMode {
    None,
    #[default]
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

impl Drop for ResolvedGatewayAuth {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.token.zeroize();
        self.password.zeroize();
    }
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
    Local,
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
///
/// Both inputs are hashed with SHA-256 before comparison so that the
/// constant-time loop always operates on 32-byte values, eliminating the
/// length side-channel that an early-return on mismatched lengths would leak.
pub fn timing_safe_eq(a: &str, b: &str) -> bool {
    use sha2::{Digest, Sha256};

    let hash_a = Sha256::digest(a.as_bytes());
    let hash_b = Sha256::digest(b.as_bytes());

    let mut out = 0u8;
    for (x, y) in hash_a.iter().zip(hash_b.iter()) {
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
    let whois_login = whois_lookup(&client_ip.to_string())?;

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

fn normalize_credential(value: Option<&str>) -> Option<&str> {
    value.filter(|s| !s.trim().is_empty())
}

fn authorize_gateway_credentials(
    auth: &ResolvedGatewayAuth,
    token: Option<&str>,
    password: Option<&str>,
) -> GatewayAuthResult {
    let token = normalize_credential(token);
    let password = normalize_credential(password);

    match auth.mode {
        AuthMode::None => GatewayAuthResult {
            ok: false,
            method: None,
            user: None,
            reason: Some(GatewayAuthFailure::Unauthorized),
        },
        AuthMode::Token => {
            let Some(expected) = normalize_credential(auth.token.as_deref()) else {
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
            let Some(expected) = normalize_credential(auth.password.as_deref()) else {
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

/// Authorize a gateway request with an optional remote address.
pub fn authorize_gateway_request(
    auth: &ResolvedGatewayAuth,
    token: Option<&str>,
    password: Option<&str>,
    headers: &HeaderMap,
    remote_addr: Option<SocketAddr>,
    trusted_proxies: &[String],
) -> GatewayAuthResult {
    match remote_addr {
        Some(remote_addr) => {
            authorize_gateway_connect(auth, token, password, headers, remote_addr, trusted_proxies)
        }
        None => authorize_gateway_credentials(auth, token, password),
    }
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

    if matches!(auth.mode, AuthMode::None) && local_direct {
        return GatewayAuthResult {
            ok: true,
            method: Some(GatewayAuthMethod::Local),
            user: None,
            reason: None,
        };
    }

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

    authorize_gateway_credentials(auth, token, password)
}

/// Check if the request is from loopback (HTTP-only helper).
pub fn is_loopback_request(remote_addr: Option<IpAddr>, headers: &HeaderMap) -> bool {
    if let Some(addr) = remote_addr {
        if is_loopback_addr(addr) && !has_proxy_headers(headers) {
            return true;
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
    let sandbox = default_tailscale_cli_sandbox_config();
    if let Err(e) = ensure_sandbox_supported(Some(&sandbox)) {
        tracing::debug!(error = %e, "tailscale whois sandbox unavailable on this platform");
        return None;
    }
    let output =
        run_sandboxed_std_command_output("tailscale", &["whois", "--json", ip], Some(&sandbox))
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

fn normalize_ip_addr(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4().map(IpAddr::V4).unwrap_or(IpAddr::V6(v6)),
        other => other,
    }
}

fn normalize_ip(raw: &str) -> Option<IpAddr> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    if trimmed.starts_with('[') {
        if let Some(end) = trimmed.find(']') {
            if let Ok(ip) = trimmed[1..end].parse::<IpAddr>() {
                return Some(normalize_ip_addr(ip));
            }
        }
    }
    if let Ok(ip) = trimmed.parse::<IpAddr>() {
        return Some(normalize_ip_addr(ip));
    }
    if let Ok(sock) = trimmed.parse::<SocketAddr>() {
        return Some(normalize_ip_addr(sock.ip()));
    }
    None
}

fn parse_forwarded_for(value: Option<String>) -> Option<IpAddr> {
    let raw = value?;
    let first = raw.split(',').next()?.trim();
    normalize_ip(first)
}

fn is_loopback_address(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => v6.is_loopback() || v6.to_ipv4().is_some_and(|v4| v4.is_loopback()),
    }
}

fn is_trusted_proxy(remote: Option<IpAddr>, trusted: &[String]) -> bool {
    let Some(remote) = remote else {
        return false;
    };
    if trusted.is_empty() {
        return false;
    }
    trusted
        .iter()
        .filter_map(|p| normalize_ip(p))
        .any(|p| p == remote)
}

fn resolve_client_ip(
    remote: IpAddr,
    forwarded_for: Option<String>,
    real_ip: Option<String>,
    trusted: &[String],
) -> Option<IpAddr> {
    let remote = normalize_ip_addr(remote);
    if !is_trusted_proxy(Some(remote), trusted) {
        return Some(remote);
    }
    parse_forwarded_for(forwarded_for).or_else(|| normalize_ip(&real_ip.unwrap_or_default()))
}

/// Resolve the effective client IP for a request.
///
/// Uses direct socket IP by default. If the direct remote IP is listed in
/// `trusted`, proxy headers (`X-Forwarded-For`, then `X-Real-IP`) are allowed
/// to override it. IPv4-mapped IPv6 addresses are normalized to IPv4.
pub fn resolve_request_client_ip(
    remote_addr: Option<SocketAddr>,
    headers: &HeaderMap,
    trusted: &[String],
) -> Option<IpAddr> {
    let remote_addr = remote_addr?;
    let remote_ip = normalize_ip_addr(remote_addr.ip());
    let forwarded_for = header_value(headers, "x-forwarded-for");
    let real_ip = header_value(headers, "x-real-ip");
    resolve_client_ip(remote_ip, forwarded_for, real_ip, trusted).or(Some(remote_ip))
}

/// Determine if the request is a local direct request.
pub fn is_local_direct_request(
    remote_addr: SocketAddr,
    headers: &HeaderMap,
    trusted: &[String],
) -> bool {
    let remote_ip = normalize_ip_addr(remote_addr.ip());
    let forwarded_for = header_value(headers, "x-forwarded-for");
    let real_ip = header_value(headers, "x-real-ip");
    let has_forwarded = forwarded_for.is_some() || real_ip.is_some();
    let host = get_host_name(header_value(headers, "host")).to_lowercase();
    let host_is_local = host == "localhost" || host == "127.0.0.1" || host == "::1";
    let host_is_tailscale = host.ends_with(".ts.net");
    let client_ip = resolve_client_ip(remote_ip, forwarded_for, real_ip, trusted);
    if !client_ip
        .as_ref()
        .copied()
        .map(is_loopback_address)
        .unwrap_or(false)
    {
        return false;
    }
    (host_is_local || host_is_tailscale)
        && (!has_forwarded || is_trusted_proxy(Some(remote_ip), trusted))
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

    // ============== authorize_gateway_connect Tests ==============

    /// Helper: create a non-local remote address so Tailscale/local-direct logic
    /// does not interfere with token/password auth tests.
    fn remote_addr() -> SocketAddr {
        "192.168.1.50:9999".parse().unwrap()
    }

    fn loopback() -> SocketAddr {
        "127.0.0.1:1234".parse().unwrap()
    }

    fn empty_headers() -> HeaderMap {
        HeaderMap::new()
    }

    fn no_trusted_proxies() -> Vec<String> {
        vec![]
    }

    #[test]
    fn test_resolve_request_client_ip_untrusted_proxy_ignores_forwarded_headers() {
        let headers = make_headers(&[("x-forwarded-for", "1.2.3.4"), ("x-real-ip", "2.2.2.2")]);
        let remote: SocketAddr = "203.0.113.10:8080".parse().unwrap();
        let resolved = resolve_request_client_ip(Some(remote), &headers, &[]);
        assert_eq!(resolved, Some("203.0.113.10".parse().unwrap()));
    }

    #[test]
    fn test_resolve_request_client_ip_trusted_proxy_uses_forwarded_for() {
        let headers = make_headers(&[("x-forwarded-for", "1.2.3.4"), ("x-real-ip", "2.2.2.2")]);
        let remote: SocketAddr = "10.0.0.2:8080".parse().unwrap();
        let trusted = vec!["10.0.0.2".to_string()];
        let resolved = resolve_request_client_ip(Some(remote), &headers, &trusted);
        assert_eq!(resolved, Some("1.2.3.4".parse().unwrap()));
    }

    #[test]
    fn test_resolve_request_client_ip_normalizes_ipv4_mapped_ipv6() {
        let headers = HeaderMap::new();
        let remote: SocketAddr = "[::ffff:127.0.0.1]:8080".parse().unwrap();
        let resolved = resolve_request_client_ip(Some(remote), &headers, &[]);
        assert_eq!(resolved, Some("127.0.0.1".parse().unwrap()));
    }

    // --- Token mode: valid token ---

    #[test]
    fn test_gateway_auth_token_valid() {
        let auth = ResolvedGatewayAuth {
            mode: AuthMode::Token,
            token: Some("my-secret-token".to_string()),
            password: None,
            allow_tailscale: false,
        };
        let result = authorize_gateway_connect(
            &auth,
            Some("my-secret-token"),
            None,
            &empty_headers(),
            remote_addr(),
            &no_trusted_proxies(),
        );
        assert!(result.ok, "Valid token should be accepted");
        assert_eq!(result.method, Some(GatewayAuthMethod::Token));
        assert!(result.user.is_none());
        assert!(result.reason.is_none());
    }

    #[test]
    fn test_gateway_auth_local_bypass_allows_loopback() {
        let auth = ResolvedGatewayAuth {
            mode: AuthMode::None,
            token: None,
            password: None,
            allow_tailscale: false,
        };
        let headers = make_headers(&[("host", "localhost")]);
        let addr = "127.0.0.1:1234".parse().unwrap();
        let result = authorize_gateway_connect(&auth, None, None, &headers, addr, &[]);
        assert!(result.ok);
        assert_eq!(result.method, Some(GatewayAuthMethod::Local));
    }

    #[test]
    fn test_gateway_auth_local_bypass_rejects_remote() {
        let auth = ResolvedGatewayAuth {
            mode: AuthMode::None,
            token: None,
            password: None,
            allow_tailscale: false,
        };
        let headers = make_headers(&[("host", "localhost")]);
        let addr = "8.8.8.8:1234".parse().unwrap();
        let result = authorize_gateway_connect(&auth, None, None, &headers, addr, &[]);
        assert!(!result.ok);
        assert_eq!(result.reason, Some(GatewayAuthFailure::Unauthorized));
    }

    // --- Token mode: invalid token ---

    #[test]
    fn test_gateway_auth_token_mismatch() {
        let auth = ResolvedGatewayAuth {
            mode: AuthMode::Token,
            token: Some("my-secret-token".to_string()),
            password: None,
            allow_tailscale: false,
        };
        let result = authorize_gateway_connect(
            &auth,
            Some("wrong-token"),
            None,
            &empty_headers(),
            remote_addr(),
            &no_trusted_proxies(),
        );
        assert!(!result.ok, "Wrong token should be rejected");
        assert!(result.method.is_none());
        assert_eq!(result.reason, Some(GatewayAuthFailure::TokenMismatch));
    }

    // --- Token mode: missing token in request ---

    #[test]
    fn test_gateway_auth_token_missing_from_request() {
        let auth = ResolvedGatewayAuth {
            mode: AuthMode::Token,
            token: Some("my-secret-token".to_string()),
            password: None,
            allow_tailscale: false,
        };
        let result = authorize_gateway_connect(
            &auth,
            None,
            None,
            &empty_headers(),
            remote_addr(),
            &no_trusted_proxies(),
        );
        assert!(!result.ok, "Missing token should be rejected");
        assert_eq!(result.reason, Some(GatewayAuthFailure::TokenMissing));
    }

    // --- Token mode: token not configured on server ---

    #[test]
    fn test_gateway_auth_token_not_configured() {
        let auth = ResolvedGatewayAuth {
            mode: AuthMode::Token,
            token: None,
            password: None,
            allow_tailscale: false,
        };
        let result = authorize_gateway_connect(
            &auth,
            Some("any-token"),
            None,
            &empty_headers(),
            remote_addr(),
            &no_trusted_proxies(),
        );
        assert!(!result.ok, "Token not configured should reject");
        assert_eq!(result.reason, Some(GatewayAuthFailure::TokenMissingConfig));
    }

    // --- Token mode: no token configured and no token provided ---

    #[test]
    fn test_gateway_auth_token_not_configured_and_not_provided() {
        let auth = ResolvedGatewayAuth {
            mode: AuthMode::Token,
            token: None,
            password: None,
            allow_tailscale: false,
        };
        let result = authorize_gateway_connect(
            &auth,
            None,
            None,
            &empty_headers(),
            remote_addr(),
            &no_trusted_proxies(),
        );
        assert!(
            !result.ok,
            "No config and no credential should still reject"
        );
        assert_eq!(result.reason, Some(GatewayAuthFailure::TokenMissingConfig));
    }

    // --- Password mode: valid password ---

    #[test]
    fn test_gateway_auth_password_valid() {
        let auth = ResolvedGatewayAuth {
            mode: AuthMode::Password,
            token: None,
            password: Some("my-secret-pass".to_string()),
            allow_tailscale: false,
        };
        let result = authorize_gateway_connect(
            &auth,
            None,
            Some("my-secret-pass"),
            &empty_headers(),
            remote_addr(),
            &no_trusted_proxies(),
        );
        assert!(result.ok, "Valid password should be accepted");
        assert_eq!(result.method, Some(GatewayAuthMethod::Password));
        assert!(result.user.is_none());
        assert!(result.reason.is_none());
    }

    // --- Password mode: invalid password ---

    #[test]
    fn test_gateway_auth_password_mismatch() {
        let auth = ResolvedGatewayAuth {
            mode: AuthMode::Password,
            token: None,
            password: Some("my-secret-pass".to_string()),
            allow_tailscale: false,
        };
        let result = authorize_gateway_connect(
            &auth,
            None,
            Some("wrong-pass"),
            &empty_headers(),
            remote_addr(),
            &no_trusted_proxies(),
        );
        assert!(!result.ok, "Wrong password should be rejected");
        assert_eq!(result.reason, Some(GatewayAuthFailure::PasswordMismatch));
    }

    // --- Password mode: missing password in request ---

    #[test]
    fn test_gateway_auth_password_missing_from_request() {
        let auth = ResolvedGatewayAuth {
            mode: AuthMode::Password,
            token: None,
            password: Some("my-secret-pass".to_string()),
            allow_tailscale: false,
        };
        let result = authorize_gateway_connect(
            &auth,
            None,
            None,
            &empty_headers(),
            remote_addr(),
            &no_trusted_proxies(),
        );
        assert!(!result.ok, "Missing password should be rejected");
        assert_eq!(result.reason, Some(GatewayAuthFailure::PasswordMissing));
    }

    // --- Password mode: password not configured on server ---

    #[test]
    fn test_gateway_auth_password_not_configured() {
        let auth = ResolvedGatewayAuth {
            mode: AuthMode::Password,
            token: None,
            password: None,
            allow_tailscale: false,
        };
        let result = authorize_gateway_connect(
            &auth,
            None,
            Some("any-pass"),
            &empty_headers(),
            remote_addr(),
            &no_trusted_proxies(),
        );
        assert!(!result.ok, "Password not configured should reject");
        assert_eq!(
            result.reason,
            Some(GatewayAuthFailure::PasswordMissingConfig)
        );
    }

    // --- Password mode: no password configured and no password provided ---

    #[test]
    fn test_gateway_auth_password_not_configured_and_not_provided() {
        let auth = ResolvedGatewayAuth {
            mode: AuthMode::Password,
            token: None,
            password: None,
            allow_tailscale: false,
        };
        let result = authorize_gateway_connect(
            &auth,
            None,
            None,
            &empty_headers(),
            remote_addr(),
            &no_trusted_proxies(),
        );
        assert!(!result.ok);
        assert_eq!(
            result.reason,
            Some(GatewayAuthFailure::PasswordMissingConfig)
        );
    }

    // --- Edge case: empty token ---

    #[test]
    fn test_gateway_auth_token_empty_string() {
        let auth = ResolvedGatewayAuth {
            mode: AuthMode::Token,
            token: Some("real-token".to_string()),
            password: None,
            allow_tailscale: false,
        };
        let result = authorize_gateway_connect(
            &auth,
            Some(""),
            None,
            &empty_headers(),
            remote_addr(),
            &no_trusted_proxies(),
        );
        assert!(!result.ok, "Empty token should be rejected");
        assert_eq!(result.reason, Some(GatewayAuthFailure::TokenMissing));
    }

    // --- Edge case: empty password ---

    #[test]
    fn test_gateway_auth_password_empty_string() {
        let auth = ResolvedGatewayAuth {
            mode: AuthMode::Password,
            token: None,
            password: Some("real-pass".to_string()),
            allow_tailscale: false,
        };
        let result = authorize_gateway_connect(
            &auth,
            None,
            Some(""),
            &empty_headers(),
            remote_addr(),
            &no_trusted_proxies(),
        );
        assert!(!result.ok, "Empty password should be rejected");
        assert_eq!(result.reason, Some(GatewayAuthFailure::PasswordMissing));
    }

    // --- Edge case: whitespace-only token ---

    #[test]
    fn test_gateway_auth_token_whitespace_only() {
        let auth = ResolvedGatewayAuth {
            mode: AuthMode::Token,
            token: Some("real-token".to_string()),
            password: None,
            allow_tailscale: false,
        };
        let result = authorize_gateway_connect(
            &auth,
            Some("   "),
            None,
            &empty_headers(),
            remote_addr(),
            &no_trusted_proxies(),
        );
        assert!(!result.ok, "Whitespace-only token should be rejected");
        assert_eq!(result.reason, Some(GatewayAuthFailure::TokenMissing));
    }

    // --- Edge case: whitespace-only password ---

    #[test]
    fn test_gateway_auth_password_whitespace_only() {
        let auth = ResolvedGatewayAuth {
            mode: AuthMode::Password,
            token: None,
            password: Some("real-pass".to_string()),
            allow_tailscale: false,
        };
        let result = authorize_gateway_connect(
            &auth,
            None,
            Some("   "),
            &empty_headers(),
            remote_addr(),
            &no_trusted_proxies(),
        );
        assert!(!result.ok, "Whitespace-only password should be rejected");
        assert_eq!(result.reason, Some(GatewayAuthFailure::PasswordMissing));
    }

    // --- Token mode ignores password field ---

    #[test]
    fn test_gateway_auth_token_mode_ignores_password() {
        let auth = ResolvedGatewayAuth {
            mode: AuthMode::Token,
            token: Some("my-token".to_string()),
            password: None,
            allow_tailscale: false,
        };
        // Provide password but not token -- should fail because mode is Token
        let result = authorize_gateway_connect(
            &auth,
            None,
            Some("my-token"),
            &empty_headers(),
            remote_addr(),
            &no_trusted_proxies(),
        );
        assert!(
            !result.ok,
            "Token mode should not accept password credential"
        );
        assert_eq!(result.reason, Some(GatewayAuthFailure::TokenMissing));
    }

    // --- Password mode ignores token field ---

    #[test]
    fn test_gateway_auth_password_mode_ignores_token() {
        let auth = ResolvedGatewayAuth {
            mode: AuthMode::Password,
            token: None,
            password: Some("my-pass".to_string()),
            allow_tailscale: false,
        };
        // Provide token but not password -- should fail because mode is Password
        let result = authorize_gateway_connect(
            &auth,
            Some("my-pass"),
            None,
            &empty_headers(),
            remote_addr(),
            &no_trusted_proxies(),
        );
        assert!(
            !result.ok,
            "Password mode should not accept token credential"
        );
        assert_eq!(result.reason, Some(GatewayAuthFailure::PasswordMissing));
    }

    // --- Token comparison is case-sensitive ---

    #[test]
    fn test_gateway_auth_token_case_sensitive() {
        let auth = ResolvedGatewayAuth {
            mode: AuthMode::Token,
            token: Some("MyToken".to_string()),
            password: None,
            allow_tailscale: false,
        };
        let result = authorize_gateway_connect(
            &auth,
            Some("mytoken"),
            None,
            &empty_headers(),
            remote_addr(),
            &no_trusted_proxies(),
        );
        assert!(!result.ok, "Token comparison must be case-sensitive");
        assert_eq!(result.reason, Some(GatewayAuthFailure::TokenMismatch));
    }

    // --- Password comparison is case-sensitive ---

    #[test]
    fn test_gateway_auth_password_case_sensitive() {
        let auth = ResolvedGatewayAuth {
            mode: AuthMode::Password,
            token: None,
            password: Some("MyPass".to_string()),
            allow_tailscale: false,
        };
        let result = authorize_gateway_connect(
            &auth,
            None,
            Some("mypass"),
            &empty_headers(),
            remote_addr(),
            &no_trusted_proxies(),
        );
        assert!(!result.ok, "Password comparison must be case-sensitive");
        assert_eq!(result.reason, Some(GatewayAuthFailure::PasswordMismatch));
    }

    // --- Both empty-string config and empty-string request should match ---

    #[test]
    fn test_gateway_auth_token_both_empty_rejected() {
        let auth = ResolvedGatewayAuth {
            mode: AuthMode::Token,
            token: Some(String::new()),
            password: None,
            allow_tailscale: false,
        };
        let result = authorize_gateway_connect(
            &auth,
            Some(""),
            None,
            &empty_headers(),
            remote_addr(),
            &no_trusted_proxies(),
        );
        assert!(!result.ok);
        assert_eq!(result.reason, Some(GatewayAuthFailure::TokenMissingConfig));
    }

    // --- GatewayAuthFailure message coverage ---

    #[test]
    fn test_gateway_auth_failure_messages() {
        assert!(GatewayAuthFailure::TokenMissingConfig
            .message()
            .contains("token not configured"));
        assert!(GatewayAuthFailure::TokenMissing
            .message()
            .contains("token missing"));
        assert!(GatewayAuthFailure::TokenMismatch
            .message()
            .contains("token mismatch"));
        assert!(GatewayAuthFailure::PasswordMissingConfig
            .message()
            .contains("password not configured"));
        assert!(GatewayAuthFailure::PasswordMissing
            .message()
            .contains("password missing"));
        assert!(GatewayAuthFailure::PasswordMismatch
            .message()
            .contains("password mismatch"));
        assert!(GatewayAuthFailure::Unauthorized
            .message()
            .contains("unauthorized"));
    }

    // --- GatewayAuthResult fields are correct on success ---

    #[test]
    fn test_gateway_auth_result_fields_on_token_success() {
        let auth = ResolvedGatewayAuth {
            mode: AuthMode::Token,
            token: Some("tok".to_string()),
            password: None,
            allow_tailscale: false,
        };
        let result = authorize_gateway_connect(
            &auth,
            Some("tok"),
            None,
            &empty_headers(),
            remote_addr(),
            &no_trusted_proxies(),
        );
        assert!(result.ok);
        assert_eq!(result.method, Some(GatewayAuthMethod::Token));
        assert!(result.user.is_none(), "Token auth should not set user");
        assert!(result.reason.is_none());
    }

    #[test]
    fn test_gateway_auth_result_fields_on_password_success() {
        let auth = ResolvedGatewayAuth {
            mode: AuthMode::Password,
            token: None,
            password: Some("pwd".to_string()),
            allow_tailscale: false,
        };
        let result = authorize_gateway_connect(
            &auth,
            None,
            Some("pwd"),
            &empty_headers(),
            remote_addr(),
            &no_trusted_proxies(),
        );
        assert!(result.ok);
        assert_eq!(result.method, Some(GatewayAuthMethod::Password));
        assert!(result.user.is_none(), "Password auth should not set user");
        assert!(result.reason.is_none());
    }

    // --- GatewayAuthResult fields are correct on failure ---

    #[test]
    fn test_gateway_auth_result_fields_on_failure() {
        let auth = ResolvedGatewayAuth {
            mode: AuthMode::Token,
            token: Some("tok".to_string()),
            password: None,
            allow_tailscale: false,
        };
        let result = authorize_gateway_connect(
            &auth,
            Some("bad"),
            None,
            &empty_headers(),
            remote_addr(),
            &no_trusted_proxies(),
        );
        assert!(!result.ok);
        assert!(result.method.is_none(), "Failed auth should not set method");
        assert!(result.user.is_none(), "Failed auth should not set user");
        assert!(result.reason.is_some());
    }

    // --- Default ResolvedGatewayAuth: token mode with nothing configured ---

    #[test]
    fn test_gateway_auth_default_config_rejects() {
        let auth = ResolvedGatewayAuth::default();
        // Default is Token mode with token=None, so should reject
        let result = authorize_gateway_connect(
            &auth,
            Some("any-token"),
            None,
            &empty_headers(),
            remote_addr(),
            &no_trusted_proxies(),
        );
        assert!(!result.ok);
        assert_eq!(result.reason, Some(GatewayAuthFailure::TokenMissingConfig));
    }

    // --- Token with special characters ---

    #[test]
    fn test_gateway_auth_token_special_chars() {
        let special_token = "t0k3n!@#$%^&*()_+-=[]{}|;':\",./<>?";
        let auth = ResolvedGatewayAuth {
            mode: AuthMode::Token,
            token: Some(special_token.to_string()),
            password: None,
            allow_tailscale: false,
        };
        let result = authorize_gateway_connect(
            &auth,
            Some(special_token),
            None,
            &empty_headers(),
            remote_addr(),
            &no_trusted_proxies(),
        );
        assert!(result.ok, "Token with special characters should match");
    }

    // --- Long token ---

    #[test]
    fn test_gateway_auth_token_long_value() {
        let long_token: String = "a".repeat(1024);
        let auth = ResolvedGatewayAuth {
            mode: AuthMode::Token,
            token: Some(long_token.clone()),
            password: None,
            allow_tailscale: false,
        };
        let result = authorize_gateway_connect(
            &auth,
            Some(&long_token),
            None,
            &empty_headers(),
            remote_addr(),
            &no_trusted_proxies(),
        );
        assert!(result.ok, "Long token should match");
    }

    // --- Token mode: providing both token and password, only token matters ---

    #[test]
    fn test_gateway_auth_token_mode_with_both_credentials() {
        let auth = ResolvedGatewayAuth {
            mode: AuthMode::Token,
            token: Some("correct-token".to_string()),
            password: Some("some-pass".to_string()),
            allow_tailscale: false,
        };
        // Correct token provided; password is irrelevant in token mode
        let result = authorize_gateway_connect(
            &auth,
            Some("correct-token"),
            Some("wrong-pass"),
            &empty_headers(),
            remote_addr(),
            &no_trusted_proxies(),
        );
        assert!(
            result.ok,
            "Token mode only checks token, password is ignored"
        );
        assert_eq!(result.method, Some(GatewayAuthMethod::Token));
    }

    // --- Password mode: providing both token and password, only password matters ---

    #[test]
    fn test_gateway_auth_password_mode_with_both_credentials() {
        let auth = ResolvedGatewayAuth {
            mode: AuthMode::Password,
            token: Some("some-token".to_string()),
            password: Some("correct-pass".to_string()),
            allow_tailscale: false,
        };
        // Correct password provided; token is irrelevant in password mode
        let result = authorize_gateway_connect(
            &auth,
            Some("wrong-token"),
            Some("correct-pass"),
            &empty_headers(),
            remote_addr(),
            &no_trusted_proxies(),
        );
        assert!(
            result.ok,
            "Password mode only checks password, token is ignored"
        );
        assert_eq!(result.method, Some(GatewayAuthMethod::Password));
    }

    // --- Token with trailing/leading whitespace: no implicit trimming ---

    #[test]
    fn test_gateway_auth_token_no_implicit_trimming() {
        let auth = ResolvedGatewayAuth {
            mode: AuthMode::Token,
            token: Some("my-token".to_string()),
            password: None,
            allow_tailscale: false,
        };
        // Provide token with leading/trailing space -- should NOT match
        let result = authorize_gateway_connect(
            &auth,
            Some(" my-token "),
            None,
            &empty_headers(),
            remote_addr(),
            &no_trusted_proxies(),
        );
        assert!(
            !result.ok,
            "Token comparison should not trim whitespace implicitly"
        );
    }

    // --- Password with trailing/leading whitespace: no implicit trimming ---

    #[test]
    fn test_gateway_auth_password_no_implicit_trimming() {
        let auth = ResolvedGatewayAuth {
            mode: AuthMode::Password,
            token: None,
            password: Some("my-pass".to_string()),
            allow_tailscale: false,
        };
        let result = authorize_gateway_connect(
            &auth,
            None,
            Some(" my-pass "),
            &empty_headers(),
            remote_addr(),
            &no_trusted_proxies(),
        );
        assert!(
            !result.ok,
            "Password comparison should not trim whitespace implicitly"
        );
    }

    // --- Whitespace-only configured credentials treated as missing ---

    #[test]
    fn test_gateway_auth_token_both_whitespace_rejected() {
        let auth = ResolvedGatewayAuth {
            mode: AuthMode::Token,
            token: Some("   ".to_string()),
            password: None,
            allow_tailscale: false,
        };
        let result = authorize_gateway_connect(
            &auth,
            Some("   "),
            None,
            &empty_headers(),
            remote_addr(),
            &no_trusted_proxies(),
        );
        assert!(
            !result.ok,
            "Whitespace-only token config should be treated as missing"
        );
        assert_eq!(result.reason, Some(GatewayAuthFailure::TokenMissingConfig));
    }

    #[test]
    fn test_gateway_auth_password_both_whitespace_rejected() {
        let auth = ResolvedGatewayAuth {
            mode: AuthMode::Password,
            token: None,
            password: Some("   ".to_string()),
            allow_tailscale: false,
        };
        let result = authorize_gateway_connect(
            &auth,
            None,
            Some("   "),
            &empty_headers(),
            remote_addr(),
            &no_trusted_proxies(),
        );
        assert!(
            !result.ok,
            "Whitespace-only password config should be treated as missing"
        );
        assert_eq!(
            result.reason,
            Some(GatewayAuthFailure::PasswordMissingConfig)
        );
    }

    // --- AuthMode::None + allow_tailscale interaction ---

    #[test]
    fn test_gateway_auth_mode_none_ignores_tailscale_for_local() {
        let auth = ResolvedGatewayAuth {
            mode: AuthMode::None,
            token: None,
            password: None,
            allow_tailscale: true,
        };
        let mut headers = HeaderMap::new();
        headers.insert("host", "localhost".parse().unwrap());
        let result = authorize_gateway_connect(
            &auth,
            None,
            None,
            &headers,
            loopback(),
            &no_trusted_proxies(),
        );
        assert!(result.ok);
        assert_eq!(
            result.method,
            Some(GatewayAuthMethod::Local),
            "Local request in None mode returns Local, not Tailscale"
        );
    }

    #[test]
    fn test_gateway_auth_mode_none_rejects_remote_even_with_tailscale() {
        let auth = ResolvedGatewayAuth {
            mode: AuthMode::None,
            token: None,
            password: None,
            allow_tailscale: true,
        };
        let result = authorize_gateway_connect(
            &auth,
            None,
            None,
            &empty_headers(),
            remote_addr(),
            &no_trusted_proxies(),
        );
        assert!(
            !result.ok,
            "AuthMode::None should reject remote requests even when allow_tailscale is true"
        );
    }
}
