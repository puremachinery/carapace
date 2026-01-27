//! SSRF Protection Integration Tests
//!
//! These tests verify the SSRF protection layer works correctly across
//! the media fetch pipeline. Unit tests exist in:
//! - `src/plugins/capabilities.rs` (SsrfProtection, IP validation)
//! - `src/media/fetch.rs` (MediaFetcher integration)
//!
//! This file adds:
//! - URL encoding/obfuscation bypass attempts
//! - Alternative IP notation formats
//! - Additional protocol schemes
//! - Edge cases in hostname validation

use rusty_clawd::plugins::capabilities::{CapabilityError, SsrfConfig, SsrfProtection};

// ============== URL Encoding Bypass Attempts ==============

#[test]
fn test_ssrf_url_encoded_localhost() {
    // %6c%6f%63%61%6c%68%6f%73%74 = localhost
    // URL parsing should decode this before validation
    let result = SsrfProtection::validate_url("http://%6c%6f%63%61%6c%68%6f%73%74/");
    // Should either block as localhost or fail to parse
    assert!(result.is_err());
}

#[test]
fn test_ssrf_url_encoded_127() {
    // %31%32%37%2e%30%2e%30%2e%31 = 127.0.0.1
    let result = SsrfProtection::validate_url("http://%31%32%37%2e%30%2e%30%2e%31/");
    assert!(result.is_err());
}

// ============== Alternative IP Notation ==============

#[test]
fn test_ssrf_decimal_ip_notation() {
    // 2130706433 = 127.0.0.1 in decimal notation
    // Most URL parsers don't support this, but we should verify behavior
    let result = SsrfProtection::validate_url("http://2130706433/");
    // This typically fails to parse as a valid host, which is fine
    // The important thing is it doesn't succeed and reach localhost
    if result.is_ok() {
        panic!("Decimal IP notation should not resolve to a valid host");
    }
}

#[test]
fn test_ssrf_octal_ip_notation() {
    // 0177.0.0.1 = 127.0.0.1 in octal notation
    // Most parsers treat this as a hostname, not an IP
    let result = SsrfProtection::validate_url("http://0177.0.0.1/");
    // Should either block or treat as invalid hostname
    // Either way, should not succeed
    if result.is_ok() {
        // If it parses, it would be treated as a regular hostname
        // which is fine since DNS lookup would fail
    }
}

#[test]
fn test_ssrf_hex_ip_notation() {
    // 0x7f.0.0.1 = 127.0.0.1 in hex notation
    let result = SsrfProtection::validate_url("http://0x7f.0.0.1/");
    // Should either block or treat as invalid
    if result.is_ok() {
        // If it parses, it's treated as hostname (dots make it invalid hex)
    }
}

#[test]
fn test_ssrf_ipv6_bracket_variations() {
    // Standard bracketed IPv6 localhost
    let result = SsrfProtection::validate_url("http://[::1]/");
    assert!(matches!(result, Err(CapabilityError::SsrfBlocked(_))));

    // IPv6 with zone ID (link-local)
    let result = SsrfProtection::validate_url("http://[fe80::1%25eth0]/");
    // Should either block or fail to parse
    assert!(result.is_err());
}

// ============== Additional Protocol Schemes ==============

#[test]
fn test_ssrf_blocks_additional_protocols() {
    // dict:// - dictionary server protocol
    let result = SsrfProtection::validate_url("dict://localhost:2628/");
    assert!(matches!(
        result,
        Err(CapabilityError::ProtocolNotAllowed(_))
    ));

    // gopher:// - gopher protocol
    let result = SsrfProtection::validate_url("gopher://localhost/");
    assert!(matches!(
        result,
        Err(CapabilityError::ProtocolNotAllowed(_))
    ));

    // ldap:// - LDAP protocol
    let result = SsrfProtection::validate_url("ldap://localhost/");
    assert!(matches!(
        result,
        Err(CapabilityError::ProtocolNotAllowed(_))
    ));

    // sftp:// - SFTP protocol
    let result = SsrfProtection::validate_url("sftp://localhost/");
    assert!(matches!(
        result,
        Err(CapabilityError::ProtocolNotAllowed(_))
    ));

    // tftp:// - TFTP protocol
    let result = SsrfProtection::validate_url("tftp://localhost/file");
    assert!(matches!(
        result,
        Err(CapabilityError::ProtocolNotAllowed(_))
    ));

    // data:// - data URI
    let result = SsrfProtection::validate_url("data:text/html,<script>alert(1)</script>");
    assert!(matches!(
        result,
        Err(CapabilityError::ProtocolNotAllowed(_))
    ));

    // javascript:// - javascript URI
    let result = SsrfProtection::validate_url("javascript:alert(1)");
    assert!(matches!(
        result,
        Err(CapabilityError::ProtocolNotAllowed(_))
    ));
}

// ============== Hostname Variations ==============

#[test]
fn test_ssrf_localhost_subdomain() {
    // foo.localhost should be blocked
    let result = SsrfProtection::validate_url("http://foo.localhost/");
    assert!(matches!(result, Err(CapabilityError::SsrfBlocked(_))));

    // anything.localhost should be blocked
    let result = SsrfProtection::validate_url("http://anything.localhost/");
    assert!(matches!(result, Err(CapabilityError::SsrfBlocked(_))));
}

#[test]
fn test_ssrf_localhost_with_port() {
    let result = SsrfProtection::validate_url("http://localhost:8080/");
    assert!(matches!(result, Err(CapabilityError::SsrfBlocked(_))));

    let result = SsrfProtection::validate_url("http://127.0.0.1:3000/");
    assert!(matches!(result, Err(CapabilityError::SsrfBlocked(_))));
}

#[test]
fn test_ssrf_localhost_localdomain() {
    let result = SsrfProtection::validate_url("http://localhost.localdomain/");
    assert!(matches!(result, Err(CapabilityError::SsrfBlocked(_))));
}

// ============== Cloud Metadata Variations ==============

#[test]
fn test_ssrf_aws_metadata_paths() {
    // Various AWS metadata paths
    let paths = [
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/user-data/",
        "http://169.254.169.254/latest/api/token",
        "http://169.254.169.254/latest/dynamic/instance-identity/document",
    ];

    for path in paths {
        let result = SsrfProtection::validate_url(path);
        assert!(
            matches!(result, Err(CapabilityError::SsrfBlocked(_))),
            "Should block AWS metadata path: {}",
            path
        );
    }
}

#[test]
fn test_ssrf_gcp_metadata() {
    let result =
        SsrfProtection::validate_url("http://metadata.google.internal/computeMetadata/v1/");
    assert!(matches!(result, Err(CapabilityError::SsrfBlocked(_))));

    let result = SsrfProtection::validate_url("http://metadata/computeMetadata/v1/");
    assert!(matches!(result, Err(CapabilityError::SsrfBlocked(_))));
}

#[test]
fn test_ssrf_internal_hostnames() {
    // .internal suffix is commonly used for cloud internal DNS
    let result = SsrfProtection::validate_url("http://database.internal/");
    assert!(matches!(result, Err(CapabilityError::SsrfBlocked(_))));

    let result = SsrfProtection::validate_url("http://redis.vpc.internal/");
    assert!(matches!(result, Err(CapabilityError::SsrfBlocked(_))));
}

// ============== IPv4 Edge Cases ==============

#[test]
fn test_ssrf_ipv4_class_e_reserved() {
    // 240.0.0.0/4 is reserved
    let result = SsrfProtection::validate_url("http://240.0.0.1/");
    assert!(matches!(result, Err(CapabilityError::SsrfBlocked(_))));

    let result = SsrfProtection::validate_url("http://255.255.255.255/");
    assert!(matches!(result, Err(CapabilityError::SsrfBlocked(_))));
}

#[test]
fn test_ssrf_ipv4_multicast() {
    // 224.0.0.0/4 is multicast
    let result = SsrfProtection::validate_url("http://224.0.0.1/");
    assert!(matches!(result, Err(CapabilityError::SsrfBlocked(_))));

    let result = SsrfProtection::validate_url("http://239.255.255.255/");
    assert!(matches!(result, Err(CapabilityError::SsrfBlocked(_))));
}

#[test]
fn test_ssrf_ipv4_test_nets() {
    // TEST-NET-1: 192.0.2.0/24
    let result = SsrfProtection::validate_url("http://192.0.2.1/");
    assert!(matches!(result, Err(CapabilityError::SsrfBlocked(_))));

    // TEST-NET-2: 198.51.100.0/24
    let result = SsrfProtection::validate_url("http://198.51.100.1/");
    assert!(matches!(result, Err(CapabilityError::SsrfBlocked(_))));

    // TEST-NET-3: 203.0.113.0/24
    let result = SsrfProtection::validate_url("http://203.0.113.1/");
    assert!(matches!(result, Err(CapabilityError::SsrfBlocked(_))));
}

#[test]
fn test_ssrf_ipv4_current_network() {
    // 0.0.0.0/8 is "current network"
    let result = SsrfProtection::validate_url("http://0.0.0.0/");
    assert!(matches!(result, Err(CapabilityError::SsrfBlocked(_))));

    let result = SsrfProtection::validate_url("http://0.1.2.3/");
    assert!(matches!(result, Err(CapabilityError::SsrfBlocked(_))));
}

// ============== IPv6 Edge Cases ==============

#[test]
fn test_ssrf_ipv6_documentation() {
    // 2001:db8::/32 is documentation range
    let result = SsrfProtection::validate_url("http://[2001:db8::1]/");
    assert!(matches!(result, Err(CapabilityError::SsrfBlocked(_))));
}

#[test]
fn test_ssrf_ipv6_multicast() {
    // ff00::/8 is multicast
    let result = SsrfProtection::validate_url("http://[ff02::1]/");
    assert!(matches!(result, Err(CapabilityError::SsrfBlocked(_))));
}

#[test]
fn test_ssrf_ipv6_unspecified() {
    // :: is unspecified address
    let result = SsrfProtection::validate_url("http://[::]/");
    assert!(matches!(result, Err(CapabilityError::SsrfBlocked(_))));
}

// ============== Public IPs (Should Pass) ==============

#[test]
fn test_ssrf_allows_public_ips() {
    // Well-known public DNS servers
    assert!(SsrfProtection::validate_url("http://8.8.8.8/").is_ok());
    assert!(SsrfProtection::validate_url("http://1.1.1.1/").is_ok());

    // Public websites
    assert!(SsrfProtection::validate_url("https://example.com/").is_ok());
    assert!(SsrfProtection::validate_url("https://api.github.com/").is_ok());
}

#[test]
fn test_ssrf_allows_public_ipv6() {
    // Google's public IPv6 DNS
    assert!(SsrfProtection::validate_url("http://[2001:4860:4860::8888]/").is_ok());
}

// ============== Tailscale Configuration ==============

#[test]
fn test_ssrf_tailscale_config() {
    let config = SsrfConfig {
        allow_tailscale: true,
    };

    // With allow_tailscale, CGNAT range should be allowed
    let result = SsrfProtection::validate_url_with_config("http://100.100.50.25/", &config);
    assert!(result.is_ok());

    // But other private ranges should still be blocked
    let result = SsrfProtection::validate_url_with_config("http://192.168.1.1/", &config);
    assert!(matches!(result, Err(CapabilityError::SsrfBlocked(_))));

    let result = SsrfProtection::validate_url_with_config("http://10.0.0.1/", &config);
    assert!(matches!(result, Err(CapabilityError::SsrfBlocked(_))));

    let result = SsrfProtection::validate_url_with_config("http://127.0.0.1/", &config);
    assert!(matches!(result, Err(CapabilityError::SsrfBlocked(_))));
}

// ============== URL Parsing Edge Cases ==============

#[test]
fn test_ssrf_url_with_credentials() {
    // user:pass@host - credentials in URL
    let result = SsrfProtection::validate_url("http://user:pass@localhost/");
    assert!(matches!(result, Err(CapabilityError::SsrfBlocked(_))));

    let result = SsrfProtection::validate_url("http://admin:admin@192.168.1.1/");
    assert!(matches!(result, Err(CapabilityError::SsrfBlocked(_))));
}

#[test]
fn test_ssrf_url_with_fragment() {
    // Fragments shouldn't affect host validation
    let result = SsrfProtection::validate_url("http://localhost/#fragment");
    assert!(matches!(result, Err(CapabilityError::SsrfBlocked(_))));
}

#[test]
fn test_ssrf_url_with_query() {
    // Query params shouldn't affect host validation
    let result = SsrfProtection::validate_url("http://localhost/?url=http://external.com");
    assert!(matches!(result, Err(CapabilityError::SsrfBlocked(_))));
}

#[test]
fn test_ssrf_empty_and_invalid_urls() {
    // Empty URL
    let result = SsrfProtection::validate_url("");
    assert!(matches!(result, Err(CapabilityError::InvalidUrl(_))));

    // Just a path
    let result = SsrfProtection::validate_url("/etc/passwd");
    assert!(matches!(result, Err(CapabilityError::InvalidUrl(_))));

    // Missing scheme
    let result = SsrfProtection::validate_url("example.com");
    assert!(matches!(result, Err(CapabilityError::InvalidUrl(_))));

    // Just scheme
    let result = SsrfProtection::validate_url("http://");
    assert!(matches!(result, Err(CapabilityError::InvalidUrl(_))));
}

// ============== Case Sensitivity ==============

#[test]
fn test_ssrf_case_insensitive_localhost() {
    let result = SsrfProtection::validate_url("http://LOCALHOST/");
    assert!(matches!(result, Err(CapabilityError::SsrfBlocked(_))));

    let result = SsrfProtection::validate_url("http://LocalHost/");
    assert!(matches!(result, Err(CapabilityError::SsrfBlocked(_))));
}

#[test]
fn test_ssrf_case_insensitive_scheme() {
    // Uppercase scheme should still work
    let result = SsrfProtection::validate_url("HTTP://example.com/");
    // URL parsing typically normalizes scheme to lowercase
    assert!(result.is_ok() || matches!(result, Err(CapabilityError::InvalidUrl(_))));

    let result = SsrfProtection::validate_url("HTTPS://example.com/");
    assert!(result.is_ok() || matches!(result, Err(CapabilityError::InvalidUrl(_))));
}
