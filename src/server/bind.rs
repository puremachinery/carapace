//! Bind mode resolution (loopback, tailscale, etc.)
//!
//! Parses `gateway.bind` config values and resolves to socket addresses:
//! - `loopback` -> 127.0.0.1
//! - `lan` -> detect LAN interface IP
//! - `tailnet` -> Tailscale IP (100.x.x.x range)
//! - `auto` -> try tailnet, fall back to lan
//! - Custom IP/hostname

use std::net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs};
use std::process::Command;
use thiserror::Error;
use tracing::debug;

/// Default gateway port
pub const DEFAULT_PORT: u16 = 18789;

/// Bind mode specifying how to resolve the listen address
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BindMode {
    /// Bind to loopback only (127.0.0.1)
    Loopback,
    /// Bind to detected LAN interface IP
    Lan,
    /// Bind to Tailscale IP (100.x.x.x range)
    Tailnet,
    /// Try tailnet first, fall back to lan
    Auto,
    /// Bind to all interfaces (0.0.0.0)
    All,
    /// Custom IP address or hostname
    Custom(String),
}

impl Default for BindMode {
    fn default() -> Self {
        BindMode::Loopback
    }
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

/// Resolve a bind mode to a socket address
pub fn resolve_bind_address(mode: &BindMode, port: u16) -> Result<SocketAddr, BindError> {
    let ip = match mode {
        BindMode::Loopback => IpAddr::V4(Ipv4Addr::LOCALHOST),
        BindMode::Lan => detect_lan_ip()?,
        BindMode::Tailnet => detect_tailscale_ip()?,
        BindMode::Auto => {
            // Try tailnet first, fall back to lan
            match detect_tailscale_ip() {
                Ok(ip) => {
                    debug!("Auto bind: using Tailscale IP {}", ip);
                    ip
                }
                Err(e) => {
                    debug!(
                        "Auto bind: Tailscale not available ({}), falling back to LAN",
                        e
                    );
                    detect_lan_ip()?
                }
            }
        }
        BindMode::All => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        BindMode::Custom(addr) => resolve_custom_address(addr)?,
    };

    Ok(SocketAddr::new(ip, port))
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
    // Get the default route interface
    let output = Command::new("route")
        .args(["-n", "get", "default"])
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
    let ifconfig_output = Command::new("ifconfig")
        .arg(interface)
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
    // Get the default route
    let output = Command::new("ip")
        .args(["route", "get", "1.1.1.1"])
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

/// Resolve a custom IP address or hostname
fn resolve_custom_address(addr: &str) -> Result<IpAddr, BindError> {
    // Try parsing as IP address first
    if let Ok(ip) = addr.parse::<IpAddr>() {
        return Ok(ip);
    }

    // Try resolving as hostname
    let socket_addr = format!("{}:0", addr);
    match socket_addr.to_socket_addrs() {
        Ok(mut addrs) => {
            // Prefer IPv4 addresses
            let mut ipv6 = None;
            for addr in addrs.by_ref() {
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
                host: addr.to_string(),
                message: "No addresses found".to_string(),
            })
        }
        Err(e) => Err(BindError::ResolutionFailed {
            host: addr.to_string(),
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
        BindMode::Auto => {
            let is_tailscale = matches!(address.ip(), IpAddr::V4(ip) if is_tailscale_ip(ip));
            if is_tailscale {
                (format!("Tailscale (auto-detected) ({})", address), true)
            } else {
                (format!("local network (auto-detected) ({})", address), true)
            }
        }
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
    fn test_default_port() {
        assert_eq!(DEFAULT_PORT, 18789);
    }
}
