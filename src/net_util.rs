//! Small network-related utilities shared across modules.

/// True when `host` resolves to a loopback address (or the literal
/// `localhost` alias). Strips IPv6 brackets if present so callers can
/// pass either `::1` or `[::1]`. Hostnames that don't parse as IP
/// literals (e.g. `matrix.example.com`) are treated as non-loopback —
/// DNS resolution would be both expensive and non-deterministic in a
/// schema-validation / control-auth-gating context.
pub(crate) fn is_loopback_host(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    let bracketless = host
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(host);
    bracketless
        .parse::<std::net::IpAddr>()
        .map(|ip| ip.is_loopback())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_loopback_host_canonical_forms() {
        assert!(is_loopback_host("127.0.0.1"));
        assert!(is_loopback_host("127.0.0.2"));
        assert!(is_loopback_host("::1"));
        assert!(is_loopback_host("[::1]"));
        assert!(is_loopback_host("0:0:0:0:0:0:0:1"));
        assert!(is_loopback_host("localhost"));
        assert!(is_loopback_host("LOCALHOST"));
    }

    #[test]
    fn test_is_loopback_host_rejects_non_loopback() {
        assert!(!is_loopback_host("10.0.0.1"));
        assert!(!is_loopback_host("matrix.example.com"));
        assert!(!is_loopback_host("2001:db8::1"));
        assert!(!is_loopback_host("[2001:db8::1]"));
        assert!(!is_loopback_host(""));
    }
}
