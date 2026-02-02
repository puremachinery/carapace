//! TLS support for the carapace gateway
//!
//! Provides:
//! - Self-signed certificate auto-generation using `rcgen`
//! - Certificate and key loading from PEM files
//! - SHA-256 fingerprint computation for trust-on-first-use pairing
//! - TLS configuration types for the gateway config schema
//! - Cluster CA management for mTLS gateway-to-gateway authentication
//! - mTLS configuration and rustls server/client config builders

pub mod ca;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use chrono::Datelike;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tracing::{debug, info, warn};

/// Errors that can occur during TLS setup
#[derive(Error, Debug)]
pub enum TlsError {
    #[error("Failed to generate self-signed certificate: {0}")]
    CertGenerationFailed(String),

    #[error("Failed to read certificate file {path}: {message}")]
    CertReadError { path: String, message: String },

    #[error("Failed to read key file {path}: {message}")]
    KeyReadError { path: String, message: String },

    #[error("No certificates found in PEM file: {0}")]
    NoCertsFound(String),

    #[error("No private key found in PEM file: {0}")]
    NoKeyFound(String),

    #[error("Failed to build TLS config: {0}")]
    ConfigBuildError(String),

    #[error("Failed to create TLS directory {path}: {message}")]
    DirCreationError { path: String, message: String },

    #[error("Failed to write certificate file {path}: {message}")]
    CertWriteError { path: String, message: String },

    #[error("Failed to write key file {path}: {message}")]
    KeyWriteError { path: String, message: String },
}

/// TLS configuration parsed from the gateway config
#[derive(Debug, Clone)]
pub struct TlsConfig {
    /// Whether TLS is enabled
    pub enabled: bool,
    /// Path to the certificate PEM file (optional; if not provided, auto-generate)
    pub cert_path: Option<PathBuf>,
    /// Path to the private key PEM file (optional; if not provided, auto-generate)
    pub key_path: Option<PathBuf>,
    /// Whether to auto-generate a self-signed certificate when cert/key paths are not provided
    pub auto_generate: bool,
}

impl Default for TlsConfig {
    fn default() -> Self {
        TlsConfig {
            enabled: false,
            cert_path: None,
            key_path: None,
            auto_generate: true,
        }
    }
}

/// Parse TLS configuration from the loaded JSON config value.
///
/// Looks for `gateway.tls` object with keys:
/// - `enabled` (bool, default false)
/// - `certPath` (string, optional)
/// - `keyPath` (string, optional)
/// - `autoGenerate` (bool, default true)
pub fn parse_tls_config(cfg: &serde_json::Value) -> TlsConfig {
    let tls_obj = cfg
        .get("gateway")
        .and_then(|g| g.get("tls"))
        .and_then(|t| t.as_object());

    let tls_obj = match tls_obj {
        Some(obj) => obj,
        None => return TlsConfig::default(),
    };

    let enabled = tls_obj
        .get("enabled")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let cert_path = tls_obj
        .get("certPath")
        .and_then(|v| v.as_str())
        .map(PathBuf::from);

    let key_path = tls_obj
        .get("keyPath")
        .and_then(|v| v.as_str())
        .map(PathBuf::from);

    let auto_generate = tls_obj
        .get("autoGenerate")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);

    TlsConfig {
        enabled,
        cert_path,
        key_path,
        auto_generate,
    }
}

/// Result of TLS setup, containing the rustls ServerConfig and certificate fingerprint
pub struct TlsSetupResult {
    /// The rustls server configuration, ready to use with axum-server
    pub server_config: Arc<rustls::ServerConfig>,
    /// SHA-256 fingerprint of the server certificate (hex-encoded, colon-separated)
    pub fingerprint: String,
    /// Path to the certificate file being used
    pub cert_path: PathBuf,
    /// Path to the key file being used
    pub key_path: PathBuf,
}

/// Ensure a self-signed certificate exists in the default TLS directory,
/// generating one if necessary.  Returns the cert and key paths.
fn auto_generate_certificate() -> Result<(PathBuf, PathBuf), TlsError> {
    info!("Auto-generating self-signed TLS certificate");
    let tls_dir = default_tls_dir();
    ensure_tls_dir(&tls_dir)?;

    let cert_path = tls_dir.join("cert.pem");
    let key_path = tls_dir.join("key.pem");

    if !cert_path.exists() || !key_path.exists() {
        generate_self_signed_cert(&cert_path, &key_path)?;
        info!(
            "Generated self-signed certificate at {}",
            cert_path.display()
        );
    } else {
        info!(
            "Using existing self-signed certificate at {}",
            cert_path.display()
        );
    }

    Ok((cert_path, key_path))
}

/// Resolve the certificate and key file paths.
///
/// When both paths are provided in the config they are returned as-is.
/// When neither is provided and `auto_generate` is enabled, the default TLS
/// directory is created and a self-signed certificate is generated (if not
/// already present).  Returns an error for any other combination.
fn resolve_certificate_paths(config: &TlsConfig) -> Result<(PathBuf, PathBuf), TlsError> {
    match (&config.cert_path, &config.key_path) {
        (Some(cert), Some(key)) => {
            info!("Loading TLS certificate from provided paths");
            Ok((cert.clone(), key.clone()))
        }
        (None, None) if config.auto_generate => auto_generate_certificate(),
        _ => Err(TlsError::ConfigBuildError(
            "TLS enabled but cert/key paths are incomplete and auto-generate is disabled"
                .to_string(),
        )),
    }
}

/// Load certificates and key, compute the fingerprint, and assemble a
/// `rustls::ServerConfig`.
fn build_server_config(
    cert_path: &Path,
    key_path: &Path,
) -> Result<(Arc<rustls::ServerConfig>, String), TlsError> {
    let certs = load_certs(cert_path)?;
    let key = load_private_key(key_path)?;

    // Compute fingerprint from the first (leaf) certificate
    let fingerprint = compute_cert_fingerprint(&certs[0]);

    // Ensure a crypto provider is installed (required by rustls 0.23+)
    // This is idempotent; if already installed, the Err is ignored.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| TlsError::ConfigBuildError(e.to_string()))?;

    Ok((Arc::new(server_config), fingerprint))
}

/// Set up TLS based on the provided configuration.
///
/// If `cert_path` and `key_path` are provided, loads them from disk.
/// If they are not provided and `auto_generate` is true, generates a self-signed
/// certificate and stores it in the default TLS directory.
///
/// Returns a `TlsSetupResult` containing the rustls ServerConfig and fingerprint.
pub fn setup_tls(config: &TlsConfig) -> Result<TlsSetupResult, TlsError> {
    let (cert_path, key_path) = resolve_certificate_paths(config)?;
    let (server_config, fingerprint) = build_server_config(&cert_path, &key_path)?;

    Ok(TlsSetupResult {
        server_config,
        fingerprint,
        cert_path,
        key_path,
    })
}

/// Get the default TLS directory path.
///
/// Uses `~/.config/carapace/tls/` if a home directory is available,
/// otherwise falls back to `.carapace/tls/` in the current directory.
pub fn default_tls_dir() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from(".config"))
        .join("carapace")
        .join("tls")
}

/// Ensure the TLS directory exists, creating it if necessary
fn ensure_tls_dir(dir: &Path) -> Result<(), TlsError> {
    if !dir.exists() {
        std::fs::create_dir_all(dir).map_err(|e| TlsError::DirCreationError {
            path: dir.display().to_string(),
            message: e.to_string(),
        })?;
        debug!("Created TLS directory: {}", dir.display());
    }
    Ok(())
}

/// Generate a self-signed certificate and private key, writing them to PEM files.
///
/// The certificate is valid for "localhost", "127.0.0.1", and "::1" as Subject
/// Alternative Names, making it suitable for local development and loopback access.
pub fn generate_self_signed_cert(cert_path: &Path, key_path: &Path) -> Result<(), TlsError> {
    use rcgen::{CertificateParams, KeyPair, SanType};

    let mut params = CertificateParams::new(vec!["localhost".to_string()])
        .map_err(|e| TlsError::CertGenerationFailed(e.to_string()))?;

    // Add Subject Alternative Names for common local addresses
    params.subject_alt_names = vec![
        SanType::DnsName(
            "localhost"
                .try_into()
                .map_err(|e: rcgen::Error| TlsError::CertGenerationFailed(e.to_string()))?,
        ),
        SanType::IpAddress(std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1))),
        SanType::IpAddress(std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)),
    ];

    // Set a reasonable validity period (365 days)
    let now = chrono::Utc::now();
    params.not_before = rcgen::date_time_ymd(now.year(), now.month() as u8, now.day() as u8);
    let future = now + chrono::Duration::days(365);
    params.not_after =
        rcgen::date_time_ymd(future.year(), future.month() as u8, future.day() as u8);

    // Set distinguished name
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "Carapace Gateway");
    params
        .distinguished_name
        .push(rcgen::DnType::OrganizationName, "Carapace");

    // Generate key pair and certificate
    let key_pair =
        KeyPair::generate().map_err(|e| TlsError::CertGenerationFailed(e.to_string()))?;

    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| TlsError::CertGenerationFailed(e.to_string()))?;

    // Write certificate PEM
    let cert_pem = cert.pem();
    std::fs::write(cert_path, cert_pem.as_bytes()).map_err(|e| TlsError::CertWriteError {
        path: cert_path.display().to_string(),
        message: e.to_string(),
    })?;

    // Write private key PEM
    let key_pem = key_pair.serialize_pem();
    std::fs::write(key_path, key_pem.as_bytes()).map_err(|e| TlsError::KeyWriteError {
        path: key_path.display().to_string(),
        message: e.to_string(),
    })?;

    // Set restrictive permissions on the key file (Unix only)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        if let Err(e) = std::fs::set_permissions(key_path, perms) {
            warn!("Failed to set restrictive permissions on key file: {}", e);
        }
    }

    Ok(())
}

/// Load certificates from a PEM file
pub fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>, TlsError> {
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(path)
        .map_err(|e| TlsError::CertReadError {
            path: path.display().to_string(),
            message: e.to_string(),
        })?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| TlsError::CertReadError {
            path: path.display().to_string(),
            message: e.to_string(),
        })?;

    if certs.is_empty() {
        return Err(TlsError::NoCertsFound(path.display().to_string()));
    }

    debug!(
        "Loaded {} certificate(s) from {}",
        certs.len(),
        path.display()
    );
    Ok(certs)
}

/// Load a private key from a PEM file.
///
/// Supports PKCS#8 and RSA/EC keys.
pub fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>, TlsError> {
    match PrivateKeyDer::from_pem_file(path) {
        Ok(key) => {
            debug!("Loaded private key from {}", path.display());
            Ok(key)
        }
        Err(rustls_pki_types::pem::Error::NoItemsFound) => {
            Err(TlsError::NoKeyFound(path.display().to_string()))
        }
        Err(e) => Err(TlsError::KeyReadError {
            path: path.display().to_string(),
            message: e.to_string(),
        }),
    }
}

/// Compute the SHA-256 fingerprint of a DER-encoded certificate.
///
/// Returns the fingerprint as a colon-separated hex string, e.g.:
/// `AB:CD:EF:01:23:45:...`
///
/// This fingerprint is used for trust-on-first-use (TOFU) pairing,
/// where nodes verify the gateway's identity by comparing fingerprints.
pub fn compute_cert_fingerprint(cert_der: &CertificateDer<'_>) -> String {
    let mut hasher = Sha256::new();
    hasher.update(cert_der.as_ref());
    let hash = hasher.finalize();

    hash.iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .join(":")
}

// ============================================================================
// mTLS configuration
// ============================================================================

/// mTLS configuration for gateway-to-gateway communication.
#[derive(Debug, Clone)]
pub struct MtlsConfig {
    /// Whether mTLS is enabled for gateway connections.
    pub enabled: bool,
    /// Path to the cluster CA certificate PEM file.
    pub ca_cert: Option<PathBuf>,
    /// Path to this node's certificate PEM file.
    pub node_cert: Option<PathBuf>,
    /// Path to this node's private key PEM file.
    pub node_key: Option<PathBuf>,
    /// Whether to require client certificates from connecting gateways.
    pub require_client_cert: bool,
}

impl Default for MtlsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            ca_cert: None,
            node_cert: None,
            node_key: None,
            require_client_cert: true,
        }
    }
}

/// Parse mTLS configuration from the loaded JSON config value.
///
/// Looks for `gateway.mtls` object with keys:
/// - `enabled` (bool, default false)
/// - `caCert` (string, path to CA certificate PEM)
/// - `nodeCert` (string, path to node certificate PEM)
/// - `nodeKey` (string, path to node private key PEM)
/// - `requireClientCert` (bool, default true)
pub fn parse_mtls_config(cfg: &serde_json::Value) -> MtlsConfig {
    let mtls_obj = cfg
        .get("gateway")
        .and_then(|g| g.get("mtls"))
        .and_then(|t| t.as_object());

    let mtls_obj = match mtls_obj {
        Some(obj) => obj,
        None => return MtlsConfig::default(),
    };

    let enabled = mtls_obj
        .get("enabled")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let ca_cert = mtls_obj
        .get("caCert")
        .and_then(|v| v.as_str())
        .map(PathBuf::from);

    let node_cert = mtls_obj
        .get("nodeCert")
        .and_then(|v| v.as_str())
        .map(PathBuf::from);

    let node_key = mtls_obj
        .get("nodeKey")
        .and_then(|v| v.as_str())
        .map(PathBuf::from);

    let require_client_cert = mtls_obj
        .get("requireClientCert")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);

    MtlsConfig {
        enabled,
        ca_cert,
        node_cert,
        node_key,
        require_client_cert,
    }
}

/// Result of mTLS setup, containing server and client TLS configurations.
pub struct MtlsSetupResult {
    /// Server-side TLS config with client certificate verification.
    pub server_config: Arc<rustls::ServerConfig>,
    /// Client-side TLS config that presents this node's certificate.
    pub client_config: Arc<rustls::ClientConfig>,
    /// SHA-256 fingerprint of this node's certificate.
    pub node_fingerprint: String,
    /// SHA-256 fingerprint of the CA certificate.
    pub ca_fingerprint: String,
}

/// Set up mTLS for gateway-to-gateway communication.
///
/// Builds both a `rustls::ServerConfig` (for accepting connections from other
/// gateways, verifying their client certificates against the cluster CA) and
/// a `rustls::ClientConfig` (for connecting to other gateways, presenting
/// this node's certificate).
pub fn setup_mtls(config: &MtlsConfig) -> Result<MtlsSetupResult, TlsError> {
    let ca_cert_path = config.ca_cert.as_deref().ok_or_else(|| {
        TlsError::ConfigBuildError("mTLS enabled but gateway.mtls.caCert is not set".to_string())
    })?;
    let node_cert_path = config.node_cert.as_deref().ok_or_else(|| {
        TlsError::ConfigBuildError("mTLS enabled but gateway.mtls.nodeCert is not set".to_string())
    })?;
    let node_key_path = config.node_key.as_deref().ok_or_else(|| {
        TlsError::ConfigBuildError("mTLS enabled but gateway.mtls.nodeKey is not set".to_string())
    })?;

    // Load CA certificate
    let ca_certs = load_certs(ca_cert_path)?;
    let ca_fingerprint = compute_cert_fingerprint(&ca_certs[0]);

    // Load node certificate and key
    let node_certs = load_certs(node_cert_path)?;
    let node_key = load_private_key(node_key_path)?;
    let node_fingerprint = compute_cert_fingerprint(&node_certs[0]);

    // Ensure crypto provider is installed
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    // Build the root cert store with the cluster CA
    let mut root_store = rustls::RootCertStore::empty();
    for ca_cert in &ca_certs {
        root_store
            .add(ca_cert.clone())
            .map_err(|e| TlsError::ConfigBuildError(format!("failed to add CA cert: {}", e)))?;
    }

    // -- Server config: verify client certs against the cluster CA --
    let client_verifier = if config.require_client_cert {
        rustls::server::WebPkiClientVerifier::builder(Arc::new(root_store.clone()))
            .build()
            .map_err(|e| {
                TlsError::ConfigBuildError(format!("failed to build client verifier: {}", e))
            })?
    } else {
        rustls::server::WebPkiClientVerifier::builder(Arc::new(root_store.clone()))
            .allow_unauthenticated()
            .build()
            .map_err(|e| {
                TlsError::ConfigBuildError(format!("failed to build client verifier: {}", e))
            })?
    };

    let server_config = rustls::ServerConfig::builder()
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(node_certs.clone(), node_key.clone_key())
        .map_err(|e| TlsError::ConfigBuildError(format!("server config: {}", e)))?;

    // -- Client config: present node cert, verify server against CA --
    let client_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_client_auth_cert(node_certs, node_key)
        .map_err(|e| TlsError::ConfigBuildError(format!("client config: {}", e)))?;

    info!(
        node_fingerprint = %node_fingerprint,
        ca_fingerprint = %ca_fingerprint,
        require_client_cert = config.require_client_cert,
        "mTLS configured for gateway-to-gateway communication"
    );

    Ok(MtlsSetupResult {
        server_config: Arc::new(server_config),
        client_config: Arc::new(client_config),
        node_fingerprint,
        ca_fingerprint,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_default_tls_config() {
        let config = TlsConfig::default();
        assert!(!config.enabled);
        assert!(config.cert_path.is_none());
        assert!(config.key_path.is_none());
        assert!(config.auto_generate);
    }

    #[test]
    fn test_parse_tls_config_empty() {
        let cfg = serde_json::json!({});
        let tls = parse_tls_config(&cfg);
        assert!(!tls.enabled);
        assert!(tls.cert_path.is_none());
        assert!(tls.key_path.is_none());
        assert!(tls.auto_generate);
    }

    #[test]
    fn test_parse_tls_config_enabled() {
        let cfg = serde_json::json!({
            "gateway": {
                "tls": {
                    "enabled": true,
                    "certPath": "/path/to/cert.pem",
                    "keyPath": "/path/to/key.pem",
                    "autoGenerate": false
                }
            }
        });
        let tls = parse_tls_config(&cfg);
        assert!(tls.enabled);
        assert_eq!(tls.cert_path, Some(PathBuf::from("/path/to/cert.pem")));
        assert_eq!(tls.key_path, Some(PathBuf::from("/path/to/key.pem")));
        assert!(!tls.auto_generate);
    }

    #[test]
    fn test_parse_tls_config_auto_generate_default() {
        let cfg = serde_json::json!({
            "gateway": {
                "tls": {
                    "enabled": true
                }
            }
        });
        let tls = parse_tls_config(&cfg);
        assert!(tls.enabled);
        assert!(tls.cert_path.is_none());
        assert!(tls.key_path.is_none());
        assert!(tls.auto_generate); // default is true
    }

    #[test]
    fn test_parse_tls_config_no_gateway() {
        let cfg = serde_json::json!({
            "other": "stuff"
        });
        let tls = parse_tls_config(&cfg);
        assert!(!tls.enabled);
    }

    #[test]
    fn test_generate_self_signed_cert() {
        let dir = TempDir::new().unwrap();
        let cert_path = dir.path().join("cert.pem");
        let key_path = dir.path().join("key.pem");

        generate_self_signed_cert(&cert_path, &key_path).unwrap();

        // Verify files were created
        assert!(cert_path.exists());
        assert!(key_path.exists());

        // Verify cert content looks like PEM
        let cert_content = std::fs::read_to_string(&cert_path).unwrap();
        assert!(cert_content.contains("BEGIN CERTIFICATE"));
        assert!(cert_content.contains("END CERTIFICATE"));

        // Verify key content looks like PEM
        let key_content = std::fs::read_to_string(&key_path).unwrap();
        assert!(key_content.contains("BEGIN PRIVATE KEY"));
        assert!(key_content.contains("END PRIVATE KEY"));
    }

    #[test]
    fn test_load_generated_certs() {
        let dir = TempDir::new().unwrap();
        let cert_path = dir.path().join("cert.pem");
        let key_path = dir.path().join("key.pem");

        generate_self_signed_cert(&cert_path, &key_path).unwrap();

        // Load them back
        let certs = load_certs(&cert_path).unwrap();
        assert!(!certs.is_empty());
        assert_eq!(certs.len(), 1);

        let key = load_private_key(&key_path).unwrap();
        assert!(matches!(key, PrivateKeyDer::Pkcs8(_)));
    }

    #[test]
    fn test_compute_fingerprint() {
        let dir = TempDir::new().unwrap();
        let cert_path = dir.path().join("cert.pem");
        let key_path = dir.path().join("key.pem");

        generate_self_signed_cert(&cert_path, &key_path).unwrap();

        let certs = load_certs(&cert_path).unwrap();
        let fingerprint = compute_cert_fingerprint(&certs[0]);

        // Verify fingerprint format: colon-separated hex pairs, 32 bytes = 32 pairs
        let parts: Vec<&str> = fingerprint.split(':').collect();
        assert_eq!(parts.len(), 32, "SHA-256 should produce 32 bytes");

        // Each part should be exactly 2 hex characters
        for part in &parts {
            assert_eq!(part.len(), 2);
            assert!(part.chars().all(|c| c.is_ascii_hexdigit()));
        }
    }

    #[test]
    fn test_fingerprint_deterministic() {
        let dir = TempDir::new().unwrap();
        let cert_path = dir.path().join("cert.pem");
        let key_path = dir.path().join("key.pem");

        generate_self_signed_cert(&cert_path, &key_path).unwrap();

        let certs = load_certs(&cert_path).unwrap();
        let fp1 = compute_cert_fingerprint(&certs[0]);
        let fp2 = compute_cert_fingerprint(&certs[0]);
        assert_eq!(fp1, fp2, "Fingerprint should be deterministic");
    }

    #[test]
    fn test_setup_tls_auto_generate() {
        let dir = TempDir::new().unwrap();
        let cert_path = dir.path().join("cert.pem");
        let key_path = dir.path().join("key.pem");

        // Pre-generate certs so setup_tls can load them
        generate_self_signed_cert(&cert_path, &key_path).unwrap();

        let config = TlsConfig {
            enabled: true,
            cert_path: Some(cert_path.clone()),
            key_path: Some(key_path.clone()),
            auto_generate: false,
        };

        let result = setup_tls(&config).unwrap();
        assert!(!result.fingerprint.is_empty());
        assert_eq!(result.cert_path, cert_path);
        assert_eq!(result.key_path, key_path);
    }

    #[test]
    fn test_setup_tls_missing_cert_no_auto() {
        let config = TlsConfig {
            enabled: true,
            cert_path: None,
            key_path: None,
            auto_generate: false,
        };

        let result = setup_tls(&config);
        assert!(result.is_err());
    }

    #[test]
    fn test_setup_tls_partial_paths_no_auto() {
        let config = TlsConfig {
            enabled: true,
            cert_path: Some(PathBuf::from("/some/cert.pem")),
            key_path: None,
            auto_generate: false,
        };

        let result = setup_tls(&config);
        assert!(result.is_err());
    }

    #[test]
    fn test_load_certs_nonexistent() {
        let result = load_certs(Path::new("/nonexistent/cert.pem"));
        assert!(result.is_err());
    }

    #[test]
    fn test_load_key_nonexistent() {
        let result = load_private_key(Path::new("/nonexistent/key.pem"));
        assert!(result.is_err());
    }

    #[test]
    fn test_load_certs_empty_file() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("empty.pem");
        std::fs::write(&path, "").unwrap();

        let result = load_certs(&path);
        assert!(matches!(result, Err(TlsError::NoCertsFound(_))));
    }

    #[test]
    fn test_load_key_empty_file() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("empty.pem");
        std::fs::write(&path, "").unwrap();

        let result = load_private_key(&path);
        assert!(matches!(result, Err(TlsError::NoKeyFound(_))));
    }

    #[test]
    fn test_default_tls_dir() {
        let dir = default_tls_dir();
        // Should end with carapace/tls
        assert!(dir.ends_with("carapace/tls") || dir.ends_with("carapace\\tls"));
    }

    #[cfg(unix)]
    #[test]
    fn test_key_file_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        let cert_path = dir.path().join("cert.pem");
        let key_path = dir.path().join("key.pem");

        generate_self_signed_cert(&cert_path, &key_path).unwrap();

        let metadata = std::fs::metadata(&key_path).unwrap();
        let mode = metadata.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "Key file should have 600 permissions");
    }

    // ====================================================================
    // mTLS config parsing tests
    // ====================================================================

    #[test]
    fn test_mtls_config_default() {
        let config = MtlsConfig::default();
        assert!(!config.enabled);
        assert!(config.ca_cert.is_none());
        assert!(config.node_cert.is_none());
        assert!(config.node_key.is_none());
        assert!(config.require_client_cert);
    }

    #[test]
    fn test_parse_mtls_config_empty() {
        let cfg = serde_json::json!({});
        let mtls = parse_mtls_config(&cfg);
        assert!(!mtls.enabled);
        assert!(mtls.ca_cert.is_none());
        assert!(mtls.node_cert.is_none());
        assert!(mtls.node_key.is_none());
        assert!(mtls.require_client_cert);
    }

    #[test]
    fn test_parse_mtls_config_enabled() {
        let cfg = serde_json::json!({
            "gateway": {
                "mtls": {
                    "enabled": true,
                    "caCert": "/path/to/ca.pem",
                    "nodeCert": "/path/to/node-cert.pem",
                    "nodeKey": "/path/to/node-key.pem",
                    "requireClientCert": false
                }
            }
        });
        let mtls = parse_mtls_config(&cfg);
        assert!(mtls.enabled);
        assert_eq!(mtls.ca_cert, Some(PathBuf::from("/path/to/ca.pem")));
        assert_eq!(
            mtls.node_cert,
            Some(PathBuf::from("/path/to/node-cert.pem"))
        );
        assert_eq!(mtls.node_key, Some(PathBuf::from("/path/to/node-key.pem")));
        assert!(!mtls.require_client_cert);
    }

    #[test]
    fn test_parse_mtls_config_defaults() {
        let cfg = serde_json::json!({
            "gateway": {
                "mtls": {
                    "enabled": true
                }
            }
        });
        let mtls = parse_mtls_config(&cfg);
        assert!(mtls.enabled);
        assert!(mtls.ca_cert.is_none());
        assert!(mtls.node_cert.is_none());
        assert!(mtls.node_key.is_none());
        assert!(mtls.require_client_cert); // default true
    }

    #[test]
    fn test_setup_mtls_missing_ca_cert() {
        let config = MtlsConfig {
            enabled: true,
            ca_cert: None,
            node_cert: Some(PathBuf::from("/some/cert.pem")),
            node_key: Some(PathBuf::from("/some/key.pem")),
            require_client_cert: true,
        };
        let result = setup_mtls(&config);
        assert!(result.is_err());
    }

    #[test]
    fn test_setup_mtls_missing_node_cert() {
        let config = MtlsConfig {
            enabled: true,
            ca_cert: Some(PathBuf::from("/some/ca.pem")),
            node_cert: None,
            node_key: Some(PathBuf::from("/some/key.pem")),
            require_client_cert: true,
        };
        let result = setup_mtls(&config);
        assert!(result.is_err());
    }

    #[test]
    fn test_setup_mtls_missing_node_key() {
        let config = MtlsConfig {
            enabled: true,
            ca_cert: Some(PathBuf::from("/some/ca.pem")),
            node_cert: Some(PathBuf::from("/some/cert.pem")),
            node_key: None,
            require_client_cert: true,
        };
        let result = setup_mtls(&config);
        assert!(result.is_err());
    }

    #[test]
    fn test_setup_mtls_with_valid_certs() {
        let dir = TempDir::new().unwrap();

        // Generate a cluster CA and node cert
        let ca = ca::ClusterCA::generate(dir.path()).unwrap();
        let node_dir = dir.path().join("nodes");
        let node_cert = ca.issue_node_cert("test-node", &node_dir).unwrap();

        let config = MtlsConfig {
            enabled: true,
            ca_cert: Some(ca.ca_cert_path()),
            node_cert: Some(node_cert.cert_path.clone()),
            node_key: Some(node_cert.key_path.clone()),
            require_client_cert: true,
        };

        let result = setup_mtls(&config).unwrap();
        assert!(!result.node_fingerprint.is_empty());
        assert!(!result.ca_fingerprint.is_empty());
        assert_ne!(result.node_fingerprint, result.ca_fingerprint);
    }

    #[test]
    fn test_setup_mtls_optional_client_cert() {
        let dir = TempDir::new().unwrap();

        let ca = ca::ClusterCA::generate(dir.path()).unwrap();
        let node_dir = dir.path().join("nodes");
        let node_cert = ca.issue_node_cert("test-node-opt", &node_dir).unwrap();

        let config = MtlsConfig {
            enabled: true,
            ca_cert: Some(ca.ca_cert_path()),
            node_cert: Some(node_cert.cert_path.clone()),
            node_key: Some(node_cert.key_path.clone()),
            require_client_cert: false,
        };

        let result = setup_mtls(&config);
        assert!(result.is_ok());
    }
}
