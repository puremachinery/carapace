//! Bind mode resolution (loopback, tailscale, etc.)
//!
//! Parses `gateway.bind` config values and resolves to socket addresses:
//! - `loopback` -> 127.0.0.1 (default, safest — local access only)
//! - `lan` -> detect first non-loopback IPv4 address (LAN-accessible)
//! - `auto` -> 0.0.0.0 (all interfaces)
//! - `tailnet` -> Tailscale IP (100.x.x.x CGNAT range)
//! - Any explicit IP address or `host:port` -> use as-is

use std::net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs};
use std::process::Command;
use thiserror::Error;

#[cfg(any(target_os = "macos", target_os = "linux"))]
use crate::agent::sandbox::{build_sandboxed_std_command, default_probe_sandbox_config};

/// Default gateway port
pub const DEFAULT_PORT: u16 = 18789;

/// Bind mode specifying how to resolve the listen address
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum BindMode {
    /// Bind to loopback only (127.0.0.1)
    #[default]
    Loopback,
    /// Bind to detected LAN interface IP
    Lan,
    /// Bind to Tailscale IP (100.x.x.x range)
    Tailnet,
    /// Bind to all interfaces (0.0.0.0)
    Auto,
    /// Bind to all interfaces (0.0.0.0) — alias for Auto
    All,
    /// Custom IP address or hostname
    Custom(String),
}

/// Errors that can occur during bind address resolution
#[derive(Error, Debug)]
pub enum BindError {
    #[error("Failed to detect LAN interface IP")]
    LanDetectionFailed,

    #[error("Failed to detect Tailscale IP: {0}")]
    TailscaleDetectionFailed(String),

    #[error("Tailscale is not running or not connected")]
    TailscaleNotRunning,

    #[error("No suitable network interface found")]
    NoInterfaceFound,

    #[error("Invalid IP address or hostname: {0}")]
    InvalidAddress(String),

    #[error("Failed to resolve hostname {host}: {message}")]
    ResolutionFailed { host: String, message: String },
}

/// Parse a bind mode string from config
pub fn parse_bind_mode(value: &str) -> BindMode {
    match value.trim().to_lowercase().as_str() {
        "loopback" | "localhost" | "local" => BindMode::Loopback,
        "lan" | "local-network" => BindMode::Lan,
        "tailnet" | "tailscale" | "ts" => BindMode::Tailnet,
        "auto" => BindMode::Auto,
        "all" | "0.0.0.0" => BindMode::All,
        other => BindMode::Custom(other.to_string()),
    }
}

/// Resolve a bind mode to a socket address.
///
/// For most modes, the `port` parameter is used directly. For `Custom` mode
/// with a `host:port` string, the embedded port overrides the `port` parameter.
pub fn resolve_bind_address(mode: &BindMode, port: u16) -> Result<SocketAddr, BindError> {
    match mode {
        BindMode::Loopback => Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)),
        BindMode::Lan => Ok(SocketAddr::new(detect_lan_ip()?, port)),
        BindMode::Tailnet => Ok(SocketAddr::new(detect_tailscale_ip()?, port)),
        BindMode::Auto | BindMode::All => {
            Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port))
        }
        BindMode::Custom(addr) => resolve_custom_address(addr, port),
    }
}

/// Detect the primary LAN interface IP address
fn detect_lan_ip() -> Result<IpAddr, BindError> {
    // Try platform-specific detection first
    #[cfg(target_os = "macos")]
    {
        if let Ok(ip) = detect_lan_ip_macos() {
            return Ok(ip);
        }
    }

    #[cfg(target_os = "linux")]
    {
        if let Ok(ip) = detect_lan_ip_linux() {
            return Ok(ip);
        }
    }

    // Fallback: try to connect to a public IP and see what local address is used
    detect_lan_ip_via_connect()
}

/// Detect LAN IP on macOS using route command
#[cfg(target_os = "macos")]
fn detect_lan_ip_macos() -> Result<IpAddr, BindError> {
    let sandbox = default_probe_sandbox_config();

    // Get the default route interface
    let output = build_sandboxed_std_command("route", &["-n", "get", "default"], Some(&sandbox))
        .output()
        .map_err(|_| BindError::LanDetectionFailed)?;

    if !output.status.success() {
        return Err(BindError::LanDetectionFailed);
    }

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Find the interface name
    let interface = stdout
        .lines()
        .find(|line| line.trim().starts_with("interface:"))
        .and_then(|line| line.split(':').nth(1))
        .map(|s| s.trim())
        .ok_or(BindError::LanDetectionFailed)?;

    // Get IP address for that interface using ifconfig
    let ifconfig_output = build_sandboxed_std_command("ifconfig", &[interface], Some(&sandbox))
        .output()
        .map_err(|_| BindError::LanDetectionFailed)?;

    if !ifconfig_output.status.success() {
        return Err(BindError::LanDetectionFailed);
    }

    let ifconfig_stdout = String::from_utf8_lossy(&ifconfig_output.stdout);

    // Find inet address (IPv4)
    for line in ifconfig_stdout.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("inet ") && !trimmed.contains("127.0.0.1") {
            let parts: Vec<&str> = trimmed.split_whitespace().collect();
            if parts.len() >= 2 {
                if let Ok(ip) = parts[1].parse::<Ipv4Addr>() {
                    if is_private_ip(ip) {
                        return Ok(IpAddr::V4(ip));
                    }
                }
            }
        }
    }

    Err(BindError::LanDetectionFailed)
}

/// Detect LAN IP on Linux using ip command
#[cfg(target_os = "linux")]
fn detect_lan_ip_linux() -> Result<IpAddr, BindError> {
    let sandbox = default_probe_sandbox_config();

    // Get the default route
    let output = build_sandboxed_std_command("ip", &["route", "get", "1.1.1.1"], Some(&sandbox))
        .output()
        .map_err(|_| BindError::LanDetectionFailed)?;

    if !output.status.success() {
        return Err(BindError::LanDetectionFailed);
    }

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Parse output like: "1.1.1.1 via 192.168.1.1 dev eth0 src 192.168.1.100 uid 1000"
    for part in stdout.split_whitespace() {
        if let Ok(ip) = part.parse::<Ipv4Addr>() {
            if is_private_ip(ip) {
                return Ok(IpAddr::V4(ip));
            }
        }
    }

    Err(BindError::LanDetectionFailed)
}

/// Fallback LAN detection by attempting to connect to a public IP
fn detect_lan_ip_via_connect() -> Result<IpAddr, BindError> {
    use std::net::UdpSocket;

    // Create a UDP socket and "connect" to a public IP (doesn't actually send data)
    // This causes the OS to select the appropriate local interface
    let socket = UdpSocket::bind("0.0.0.0:0").map_err(|_| BindError::LanDetectionFailed)?;

    socket
        .connect("8.8.8.8:80")
        .map_err(|_| BindError::LanDetectionFailed)?;

    let local_addr = socket
        .local_addr()
        .map_err(|_| BindError::LanDetectionFailed)?;

    let ip = local_addr.ip();

    // Verify it's a private IP (not loopback)
    match ip {
        IpAddr::V4(v4) if is_private_ip(v4) => Ok(ip),
        _ => Err(BindError::LanDetectionFailed),
    }
}

/// Detect the Tailscale IP address (100.x.x.x CGNAT range)
fn detect_tailscale_ip() -> Result<IpAddr, BindError> {
    // Try using tailscale CLI first
    let output = Command::new("tailscale")
        .args(["ip", "-4"])
        .output()
        .map_err(|e| BindError::TailscaleDetectionFailed(e.to_string()))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("not running") || stderr.contains("not logged in") {
            return Err(BindError::TailscaleNotRunning);
        }
        return Err(BindError::TailscaleDetectionFailed(stderr.to_string()));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let ip_str = stdout.trim();

    // Parse and verify it's a Tailscale IP
    let ip: Ipv4Addr = ip_str
        .parse()
        .map_err(|_| BindError::TailscaleDetectionFailed(format!("Invalid IP: {}", ip_str)))?;

    if is_tailscale_ip(ip) {
        Ok(IpAddr::V4(ip))
    } else {
        Err(BindError::TailscaleDetectionFailed(format!(
            "IP {} is not in Tailscale range",
            ip
        )))
    }
}

/// Resolve a custom IP address, hostname, or `host:port` string.
///
/// If the string contains a colon-separated port (e.g. `"192.168.1.5:9000"`
/// or `"myhost:9000"`), the embedded port is used instead of `default_port`.
/// A bare IP or hostname uses `default_port`.
fn resolve_custom_address(addr: &str, default_port: u16) -> Result<SocketAddr, BindError> {
    // Try parsing as a full socket address (e.g. "192.168.1.5:9000")
    if let Ok(sock) = addr.parse::<SocketAddr>() {
        return Ok(sock);
    }

    // Try parsing as a bare IP address (no port)
    if let Ok(ip) = addr.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, default_port));
    }

    // Check for host:port format (split on last colon to handle IPv6 correctly)
    if let Some((host, port_str)) = split_host_port(addr) {
        if let Ok(port) = port_str.parse::<u16>() {
            let ip = resolve_hostname(host)?;
            return Ok(SocketAddr::new(ip, port));
        }
    }

    // Treat the whole string as a hostname
    let ip = resolve_hostname(addr)?;
    Ok(SocketAddr::new(ip, default_port))
}

/// Split a `host:port` string. Returns `None` if there is no port component.
/// For IPv6 addresses in brackets (e.g. `[::1]:8080`), handles the bracket syntax.
fn split_host_port(addr: &str) -> Option<(&str, &str)> {
    // Handle bracketed IPv6: [::1]:port
    if addr.starts_with('[') {
        if let Some(bracket_end) = addr.find(']') {
            if addr.as_bytes().get(bracket_end + 1) == Some(&b':') {
                let host = &addr[1..bracket_end];
                let port = &addr[bracket_end + 2..];
                if !port.is_empty() {
                    return Some((host, port));
                }
            }
        }
        return None;
    }

    // For non-bracketed strings, only split if there's exactly one colon
    // (multiple colons would indicate an IPv6 address without brackets)
    let colon_count = addr.chars().filter(|&c| c == ':').count();
    if colon_count == 1 {
        let idx = addr.rfind(':')?;
        let host = &addr[..idx];
        let port = &addr[idx + 1..];
        if !host.is_empty() && !port.is_empty() {
            return Some((host, port));
        }
    }

    None
}

/// Resolve a hostname to an IP address, preferring IPv4.
fn resolve_hostname(host: &str) -> Result<IpAddr, BindError> {
    let socket_addr = format!("{}:0", host);
    match socket_addr.to_socket_addrs() {
        Ok(addrs) => {
            let mut ipv6 = None;
            for addr in addrs {
                match addr.ip() {
                    IpAddr::V4(_) => return Ok(addr.ip()),
                    IpAddr::V6(_) => {
                        if ipv6.is_none() {
                            ipv6 = Some(addr.ip());
                        }
                    }
                }
            }

            ipv6.ok_or_else(|| BindError::ResolutionFailed {
                host: host.to_string(),
                message: "No addresses found".to_string(),
            })
        }
        Err(e) => Err(BindError::ResolutionFailed {
            host: host.to_string(),
            message: e.to_string(),
        }),
    }
}

/// Check if an IPv4 address is in a private range (RFC 1918)
fn is_private_ip(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    // 10.0.0.0/8
    octets[0] == 10 ||
    // 172.16.0.0/12
    (octets[0] == 172 && (16..=31).contains(&octets[1])) ||
    // 192.168.0.0/16
    (octets[0] == 192 && octets[1] == 168)
}

/// Check if an IPv4 address is in the Tailscale CGNAT range (100.64.0.0/10)
fn is_tailscale_ip(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    // 100.64.0.0 - 100.127.255.255
    octets[0] == 100 && (64..=127).contains(&octets[1])
}

/// Get the display name for a bind mode
pub fn bind_mode_display_name(mode: &BindMode) -> &'static str {
    match mode {
        BindMode::Loopback => "loopback",
        BindMode::Lan => "lan",
        BindMode::Tailnet => "tailnet",
        BindMode::Auto => "auto",
        BindMode::All => "all",
        BindMode::Custom(_) => "custom",
    }
}

/// Result of bind address resolution with additional metadata
#[derive(Debug)]
pub struct ResolvedBind {
    /// The resolved socket address
    pub address: SocketAddr,
    /// The bind mode that was used
    pub mode: BindMode,
    /// Human-readable description
    pub description: String,
    /// Whether this address is accessible from other machines
    pub externally_accessible: bool,
}

/// Resolve bind address with full metadata
pub fn resolve_bind_with_metadata(mode: &BindMode, port: u16) -> Result<ResolvedBind, BindError> {
    let address = resolve_bind_address(mode, port)?;

    let (description, externally_accessible) = match mode {
        BindMode::Loopback => (format!("localhost only ({})", address), false),
        BindMode::Lan => (format!("local network ({})", address), true),
        BindMode::Tailnet => (format!("Tailscale network ({})", address), true),
        BindMode::Auto => (format!("all interfaces ({})", address), true),
        BindMode::All => (format!("all interfaces ({})", address), true),
        BindMode::Custom(addr) => (
            format!("custom ({} -> {})", addr, address),
            !address.ip().is_loopback(),
        ),
    };

    Ok(ResolvedBind {
        address,
        mode: mode.clone(),
        description,
        externally_accessible,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_bind_mode_loopback() {
        assert_eq!(parse_bind_mode("loopback"), BindMode::Loopback);
        assert_eq!(parse_bind_mode("localhost"), BindMode::Loopback);
        assert_eq!(parse_bind_mode("local"), BindMode::Loopback);
        assert_eq!(parse_bind_mode("LOOPBACK"), BindMode::Loopback);
        assert_eq!(parse_bind_mode("  loopback  "), BindMode::Loopback);
    }

    #[test]
    fn test_parse_bind_mode_lan() {
        assert_eq!(parse_bind_mode("lan"), BindMode::Lan);
        assert_eq!(parse_bind_mode("local-network"), BindMode::Lan);
        assert_eq!(parse_bind_mode("LAN"), BindMode::Lan);
    }

    #[test]
    fn test_parse_bind_mode_tailnet() {
        assert_eq!(parse_bind_mode("tailnet"), BindMode::Tailnet);
        assert_eq!(parse_bind_mode("tailscale"), BindMode::Tailnet);
        assert_eq!(parse_bind_mode("ts"), BindMode::Tailnet);
    }

    #[test]
    fn test_parse_bind_mode_auto() {
        assert_eq!(parse_bind_mode("auto"), BindMode::Auto);
        assert_eq!(parse_bind_mode("AUTO"), BindMode::Auto);
    }

    #[test]
    fn test_parse_bind_mode_all() {
        assert_eq!(parse_bind_mode("all"), BindMode::All);
        assert_eq!(parse_bind_mode("0.0.0.0"), BindMode::All);
    }

    #[test]
    fn test_parse_bind_mode_custom() {
        assert_eq!(
            parse_bind_mode("192.168.1.100"),
            BindMode::Custom("192.168.1.100".to_string())
        );
        assert_eq!(
            parse_bind_mode("myhost.local"),
            BindMode::Custom("myhost.local".to_string())
        );
    }

    #[test]
    fn test_resolve_loopback() {
        let addr = resolve_bind_address(&BindMode::Loopback, 8080).unwrap();
        assert_eq!(addr.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(addr.port(), 8080);
    }

    #[test]
    fn test_resolve_all() {
        let addr = resolve_bind_address(&BindMode::All, 9000).unwrap();
        assert_eq!(addr.ip(), IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        assert_eq!(addr.port(), 9000);
    }

    #[test]
    fn test_resolve_custom_ip() {
        let addr = resolve_bind_address(&BindMode::Custom("10.0.0.1".to_string()), 3000).unwrap();
        assert_eq!(addr.ip(), IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(addr.port(), 3000);
    }

    #[test]
    fn test_resolve_custom_ipv6() {
        let addr = resolve_bind_address(&BindMode::Custom("::1".to_string()), 3000).unwrap();
        assert!(addr.ip().is_loopback());
        assert_eq!(addr.port(), 3000);
    }

    #[test]
    fn test_is_private_ip() {
        // 10.x.x.x
        assert!(is_private_ip(Ipv4Addr::new(10, 0, 0, 1)));
        assert!(is_private_ip(Ipv4Addr::new(10, 255, 255, 255)));

        // 172.16-31.x.x
        assert!(is_private_ip(Ipv4Addr::new(172, 16, 0, 1)));
        assert!(is_private_ip(Ipv4Addr::new(172, 31, 255, 255)));
        assert!(!is_private_ip(Ipv4Addr::new(172, 15, 0, 1)));
        assert!(!is_private_ip(Ipv4Addr::new(172, 32, 0, 1)));

        // 192.168.x.x
        assert!(is_private_ip(Ipv4Addr::new(192, 168, 0, 1)));
        assert!(is_private_ip(Ipv4Addr::new(192, 168, 255, 255)));
        assert!(!is_private_ip(Ipv4Addr::new(192, 167, 0, 1)));

        // Public IPs
        assert!(!is_private_ip(Ipv4Addr::new(8, 8, 8, 8)));
        assert!(!is_private_ip(Ipv4Addr::new(1, 1, 1, 1)));
    }

    #[test]
    fn test_is_tailscale_ip() {
        // Valid Tailscale IPs (100.64.0.0 - 100.127.255.255)
        assert!(is_tailscale_ip(Ipv4Addr::new(100, 64, 0, 1)));
        assert!(is_tailscale_ip(Ipv4Addr::new(100, 100, 50, 25)));
        assert!(is_tailscale_ip(Ipv4Addr::new(100, 127, 255, 255)));

        // Not Tailscale
        assert!(!is_tailscale_ip(Ipv4Addr::new(100, 63, 255, 255)));
        assert!(!is_tailscale_ip(Ipv4Addr::new(100, 128, 0, 0)));
        assert!(!is_tailscale_ip(Ipv4Addr::new(192, 168, 1, 1)));
    }

    #[test]
    fn test_bind_mode_default() {
        assert_eq!(BindMode::default(), BindMode::Loopback);
    }

    #[test]
    fn test_bind_mode_display_name() {
        assert_eq!(bind_mode_display_name(&BindMode::Loopback), "loopback");
        assert_eq!(bind_mode_display_name(&BindMode::Lan), "lan");
        assert_eq!(bind_mode_display_name(&BindMode::Tailnet), "tailnet");
        assert_eq!(bind_mode_display_name(&BindMode::Auto), "auto");
        assert_eq!(bind_mode_display_name(&BindMode::All), "all");
        assert_eq!(
            bind_mode_display_name(&BindMode::Custom("test".to_string())),
            "custom"
        );
    }

    #[test]
    fn test_resolve_auto_binds_all_interfaces() {
        let addr = resolve_bind_address(&BindMode::Auto, 8080).unwrap();
        assert_eq!(addr.ip(), IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        assert_eq!(addr.port(), 8080);
    }

    #[test]
    fn test_resolve_auto_same_as_all() {
        let auto_addr = resolve_bind_address(&BindMode::Auto, 5000).unwrap();
        let all_addr = resolve_bind_address(&BindMode::All, 5000).unwrap();
        assert_eq!(auto_addr, all_addr);
    }

    #[test]
    fn test_resolve_custom_host_port() {
        // An explicit host:port should use the embedded port, not the default
        let addr =
            resolve_bind_address(&BindMode::Custom("127.0.0.1:9000".to_string()), 3000).unwrap();
        assert_eq!(addr.ip(), IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
        assert_eq!(addr.port(), 9000);
    }

    #[test]
    fn test_resolve_custom_bare_ip_uses_default_port() {
        let addr = resolve_bind_address(&BindMode::Custom("10.0.0.5".to_string()), 4000).unwrap();
        assert_eq!(addr.ip(), IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)));
        assert_eq!(addr.port(), 4000);
    }

    #[test]
    fn test_split_host_port_basic() {
        assert_eq!(split_host_port("host:1234"), Some(("host", "1234")));
        assert_eq!(
            split_host_port("192.168.1.1:8080"),
            Some(("192.168.1.1", "8080"))
        );
    }

    #[test]
    fn test_split_host_port_no_port() {
        assert_eq!(split_host_port("192.168.1.1"), None);
        assert_eq!(split_host_port("hostname"), None);
    }

    #[test]
    fn test_split_host_port_ipv6_no_brackets() {
        // Multiple colons without brackets -> treated as IPv6, no split
        assert_eq!(split_host_port("::1"), None);
        assert_eq!(split_host_port("fe80::1"), None);
    }

    #[test]
    fn test_split_host_port_ipv6_bracketed() {
        assert_eq!(split_host_port("[::1]:8080"), Some(("::1", "8080")));
        assert_eq!(split_host_port("[fe80::1]:443"), Some(("fe80::1", "443")));
    }

    #[test]
    fn test_split_host_port_edge_cases() {
        // Empty port
        assert_eq!(split_host_port("host:"), None);
        // Empty host
        assert_eq!(split_host_port(":1234"), None);
        // Bracket without port
        assert_eq!(split_host_port("[::1]"), None);
    }

    #[test]
    fn test_resolve_with_metadata_loopback() {
        let result = resolve_bind_with_metadata(&BindMode::Loopback, DEFAULT_PORT).unwrap();
        assert_eq!(result.address.port(), DEFAULT_PORT);
        assert!(!result.externally_accessible);
        assert!(result.description.contains("localhost"));
    }

    #[test]
    fn test_resolve_with_metadata_all() {
        let result = resolve_bind_with_metadata(&BindMode::All, 8080).unwrap();
        assert!(result.externally_accessible);
        assert!(result.description.contains("all interfaces"));
    }

    #[test]
    fn test_resolve_with_metadata_auto() {
        let result = resolve_bind_with_metadata(&BindMode::Auto, 8080).unwrap();
        assert!(result.externally_accessible);
        assert!(result.description.contains("all interfaces"));
        assert_eq!(result.address.ip(), IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    }

    #[test]
    fn test_default_port() {
        assert_eq!(DEFAULT_PORT, 18789);
    }
}
