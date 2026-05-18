//! Cluster Certificate Authority (CA) for mTLS gateway-to-gateway authentication.
//!
//! Provides:
//! - Self-signed CA certificate generation for the cluster
//! - Node certificate signing (CSR-less flow using rcgen)
//! - CA certificate and key loading from PEM files
//! - Certificate revocation list (CRL) management
//! - Node identity extraction from certificate CN/SAN

use std::path::{Path, PathBuf};

use chrono::Datelike;
use parking_lot::RwLock;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair, KeyUsagePurpose,
    SanType,
};
use rustls::pki_types::CertificateDer;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::{debug, info, warn};

use super::TlsError;

// ============================================================================
// Constants
// ============================================================================

/// Default CA certificate validity in days (10 years).
const CA_VALIDITY_DAYS: i64 = 3650;

/// Default node certificate validity in days (1 year).
const NODE_CERT_VALIDITY_DAYS: i64 = 365;

/// CA certificate filename.
const CA_CERT_FILENAME: &str = "cluster-ca.pem";

/// CA private key filename.
const CA_KEY_FILENAME: &str = "cluster-ca-key.pem";

/// CRL filename.
pub const CRL_FILENAME: &str = "cluster-crl.json";

/// Cap on the CA cert / key PEM file at read. Realistic PEM
/// cert+chain stays under 16 KiB; 64 KiB is generous above any
/// future format extension and still refuses a planted-multi-GB
/// attack vector at CA load (mTLS startup + every hot-reload).
const CA_PEM_FILE_MAX_BYTES: u64 = 64 * 1024;

/// Cap on the cluster CRL JSON at read. ~250k fingerprint entries
/// fit in 16 MiB; cap refuses misconfiguration pointing at
/// `/dev/zero` or a runaway log file. Matches the per-node CRL
/// cap in `src/tls/mod.rs` (B121).
const CA_CRL_FILE_MAX_BYTES: u64 = 16 * 1024 * 1024;

// ============================================================================
// CRL types
// ============================================================================

/// A revoked certificate entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RevokedCert {
    /// SHA-256 fingerprint of the revoked certificate.
    pub fingerprint: String,
    /// Node ID (from the certificate CN).
    pub node_id: String,
    /// Timestamp when the certificate was revoked (Unix ms).
    pub revoked_at_ms: u64,
    /// Reason for revocation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Persisted certificate revocation list.
///
/// NOTE: CRL entries are enforced during the mTLS handshake by the gateway's
/// custom client-certificate verifier. Application-layer checks are still
/// available via [`ClusterCA::is_revoked`].
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CertRevocationList {
    /// Schema version.
    pub version: u32,
    /// Revoked certificate entries.
    #[serde(default)]
    pub entries: Vec<RevokedCert>,
}

impl CertRevocationList {
    const VERSION: u32 = 1;

    fn new() -> Self {
        Self {
            version: Self::VERSION,
            entries: Vec::new(),
        }
    }

    /// Check whether a certificate fingerprint is revoked.
    pub fn is_revoked(&self, fingerprint: &str) -> bool {
        self.entries
            .iter()
            .any(|e| e.fingerprint.eq_ignore_ascii_case(fingerprint))
    }

    /// Revoke a certificate.
    pub fn revoke(&mut self, fingerprint: String, node_id: String, reason: Option<String>) -> bool {
        if self.is_revoked(&fingerprint) {
            return false;
        }
        self.entries.push(RevokedCert {
            fingerprint,
            node_id,
            revoked_at_ms: now_ms(),
            reason,
        });
        true
    }
}

// ============================================================================
// ClusterCA
// ============================================================================

/// Cluster Certificate Authority for mTLS.
///
/// Manages the CA certificate, issues node certificates, and maintains
/// a certificate revocation list.
pub struct ClusterCA {
    /// CA certificate in DER format.
    ca_cert_der: CertificateDer<'static>,
    /// CA certificate PEM (for distribution to nodes).
    ca_cert_pem: String,
    /// CA key pair (for signing node certificates).
    ca_key_pair: KeyPair,
    /// CA certificate parameters (for signing).
    ca_params: CertificateParams,
    /// Certificate revocation list.
    crl: RwLock<CertRevocationList>,
    /// Directory for storing CA files.
    ca_dir: PathBuf,
}

impl std::fmt::Debug for ClusterCA {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClusterCA")
            .field("ca_dir", &self.ca_dir)
            .field("fingerprint", &self.ca_fingerprint())
            .finish()
    }
}

impl ClusterCA {
    /// Generate a new self-signed cluster CA.
    pub fn generate(ca_dir: &Path) -> Result<Self, TlsError> {
        info!("Generating new cluster CA certificate");
        std::fs::create_dir_all(ca_dir).map_err(|e| TlsError::DirCreationError {
            path: ca_dir.display().to_string(),
            message: e.to_string(),
        })?;

        let mut params = CertificateParams::new(Vec::<String>::new())
            .map_err(|e| TlsError::CertGenerationFailed(e.to_string()))?;

        // CA distinguished name
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "Carapace Cluster CA");
        dn.push(DnType::OrganizationName, "Carapace");
        params.distinguished_name = dn;

        // CA constraints
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];

        // Validity period
        let now = chrono::Utc::now();
        params.not_before = rcgen::date_time_ymd(now.year(), now.month() as u8, now.day() as u8);
        let future = now + chrono::Duration::days(CA_VALIDITY_DAYS);
        params.not_after =
            rcgen::date_time_ymd(future.year(), future.month() as u8, future.day() as u8);

        // Generate key pair
        let key_pair =
            KeyPair::generate().map_err(|e| TlsError::CertGenerationFailed(e.to_string()))?;

        // Self-sign the CA certificate (clone params as self_signed consumes it)
        let ca_cert = params
            .clone()
            .self_signed(&key_pair)
            .map_err(|e| TlsError::CertGenerationFailed(e.to_string()))?;

        let ca_cert_pem = ca_cert.pem();
        let ca_cert_der = CertificateDer::from(ca_cert.der().to_vec());

        // Persist to disk via the atomic-tmp + O_NOFOLLOW + O_EXCL +
        // 0o600 + rename pipeline (B137). Bare `fs::write` followed
        // symlinks (operator-uid attacker could redirect the CA
        // private key write to an attacker-chosen target — the
        // exact threat class B116 closed for the gateway TLS cert/
        // key but missed for the cluster CA). Same shape as
        // `generate_self_signed_cert` in `tls/mod.rs`.
        let cert_path = ca_dir.join(CA_CERT_FILENAME);
        let key_path = ca_dir.join(CA_KEY_FILENAME);

        super::write_tls_pem_atomic_owner_only(&cert_path, ca_cert_pem.as_bytes()).map_err(
            |e| TlsError::CertWriteError {
                path: cert_path.display().to_string(),
                message: e.to_string(),
            },
        )?;

        let key_pem = key_pair.serialize_pem();
        super::write_tls_pem_atomic_owner_only(&key_path, key_pem.as_bytes()).map_err(|e| {
            TlsError::KeyWriteError {
                path: key_path.display().to_string(),
                message: e.to_string(),
            }
        })?;

        // Mode 0o600 was applied at tmp-creation via
        // `create_atomic_tmp_owner_only`, so no chmod-after-write
        // step is needed (and the symlink-following set_permissions
        // call from the prior shape is now unreachable).

        info!("Cluster CA generated and saved to {}", ca_dir.display());

        // Initialize empty CRL via the same atomic-tmp pipeline.
        // CRL is JSON, not PEM, but the same helper applies — it
        // writes bytes atomically with symlink defense.
        let crl = CertRevocationList::new();
        let crl_path = ca_dir.join(CRL_FILENAME);
        if let Ok(content) = serde_json::to_string_pretty(&crl) {
            let _ = super::write_tls_pem_atomic_owner_only(&crl_path, content.as_bytes());
        }

        Ok(Self {
            ca_cert_der,
            ca_cert_pem,
            ca_key_pair: key_pair,
            ca_params: params,
            crl: RwLock::new(crl),
            ca_dir: ca_dir.to_path_buf(),
        })
    }

    /// Load an existing cluster CA from disk.
    pub fn load(ca_dir: &Path) -> Result<Self, TlsError> {
        let cert_path = ca_dir.join(CA_CERT_FILENAME);
        let key_path = ca_dir.join(CA_KEY_FILENAME);

        if !cert_path.exists() || !key_path.exists() {
            return Err(TlsError::CertReadError {
                path: ca_dir.display().to_string(),
                message: "CA certificate or key not found".to_string(),
            });
        }

        // SECURITY (B130): route CA cert/key reads through the
        // FIFO-safe, no-symlink-follow, capped helper. Bare
        // `fs::read_to_string` had no cap, no O_NOFOLLOW, no
        // O_NONBLOCK — a same-uid attacker who plants a multi-GB
        // file at `ca/cert.pem` / `ca/ca.key` or a FIFO at those
        // paths OOMs / hangs the daemon at every cluster-CA load
        // (mTLS startup AND every hot-reload). 64 KiB is generous
        // above any realistic PEM cert+chain.
        let cert_bytes =
            crate::paths::read_to_vec_no_hang_no_follow_capped(&cert_path, CA_PEM_FILE_MAX_BYTES)
                .map_err(|e| TlsError::CertReadError {
                    path: cert_path.display().to_string(),
                    message: e.to_string(),
                })?
                .ok_or_else(|| TlsError::CertReadError {
                    path: cert_path.display().to_string(),
                    message: "CA certificate file disappeared between exists() and read"
                        .to_string(),
                })?;
        let ca_cert_pem = String::from_utf8(cert_bytes).map_err(|e| TlsError::CertReadError {
            path: cert_path.display().to_string(),
            message: format!("CA certificate PEM is not valid UTF-8: {e}"),
        })?;

        // SECURITY (B137): parse certificates from the already-loaded
        // PEM bytes via `load_certs_from_slice`. The prior shape
        // called `super::load_certs(&cert_path)` here, which
        // re-opens the path via `CertificateDer::pem_file_iter`
        // with NO O_NOFOLLOW, NO cap, NO FIFO defense — defeating
        // the hardened read at lines above. A same-uid attacker
        // who lost the race on the first read can hang the daemon
        // on a FIFO during the second open, or swap to a malicious
        // cert (PEM bytes used for fingerprint logging vs DER used
        // for trust would no longer match).
        let certs =
            super::load_certs_from_slice(ca_cert_pem.as_bytes(), &cert_path.display().to_string())?;
        let ca_cert_der = certs
            .into_iter()
            .next()
            .ok_or_else(|| TlsError::NoCertsFound(cert_path.display().to_string()))?;

        // Load CA key pair from PEM via the same hardened read.
        // The key is more sensitive than the cert (it can issue
        // new node certs) — the cap + FIFO-refuse are doubly
        // important.
        let key_bytes =
            crate::paths::read_to_vec_no_hang_no_follow_capped(&key_path, CA_PEM_FILE_MAX_BYTES)
                .map_err(|e| TlsError::KeyReadError {
                    path: key_path.display().to_string(),
                    message: e.to_string(),
                })?
                .ok_or_else(|| TlsError::KeyReadError {
                    path: key_path.display().to_string(),
                    message: "CA key file disappeared between exists() and read".to_string(),
                })?;
        let key_pem = String::from_utf8(key_bytes).map_err(|e| TlsError::KeyReadError {
            path: key_path.display().to_string(),
            message: format!("CA key PEM is not valid UTF-8: {e}"),
        })?;
        let ca_key_pair = KeyPair::from_pem(&key_pem).map_err(|e| TlsError::KeyReadError {
            path: key_path.display().to_string(),
            message: e.to_string(),
        })?;

        // Reconstruct CA params (needed for signing)
        let mut params = CertificateParams::new(Vec::<String>::new())
            .map_err(|e| TlsError::CertGenerationFailed(e.to_string()))?;
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "Carapace Cluster CA");
        dn.push(DnType::OrganizationName, "Carapace");
        params.distinguished_name = dn;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];

        // Load CRL via the FIFO-safe, capped helper. Prior
        // `read_to_string + unwrap_or_else("{}")` failed open on
        // read error (returning an empty CRL silently accepted
        // revoked certs); B130 keeps the cap to refuse a planted-
        // multi-GB file but preserves the warn-and-empty fallback
        // contract for parse errors (the read itself failing now
        // surfaces a warn + empty fallback rather than the prior
        // silent unwrap-or-default).
        let crl_path = ca_dir.join(CRL_FILENAME);
        let crl = if crl_path.exists() {
            let read_result = crate::paths::read_to_vec_no_hang_no_follow_capped(
                &crl_path,
                CA_CRL_FILE_MAX_BYTES,
            );
            match read_result {
                Ok(Some(bytes)) => match serde_json::from_slice::<CertRevocationList>(&bytes) {
                    // SECURITY (R16): refuse to load a CRL written
                    // by a newer daemon. A bare `from_slice` would
                    // downgrade it (drop unknown fields), the next
                    // flush_to_disk would clobber the newer-version
                    // file with v1 bytes, and the operator would lose
                    // revocations silently — an attacker who plants a
                    // v2 CRL effectively disables revocation if we
                    // fall back to empty. Refuse loud at load time.
                    Ok(crl) if crl.version > CertRevocationList::VERSION => {
                        return Err(TlsError::ConfigBuildError(format!(
                            "CRL at {} was written by a newer daemon (file version {}, this binary supports up to {}); upgrade Carapace before continuing — refusing to silently disable revocations",
                            crl_path.display(),
                            crl.version,
                            CertRevocationList::VERSION,
                        )));
                    }
                    Ok(crl) => crl,
                    Err(e) => {
                        warn!(
                            path = %crl_path.display(),
                            error = %e,
                            "CRL file is corrupted; starting with an empty revocation list"
                        );
                        CertRevocationList::new()
                    }
                },
                Ok(None) => CertRevocationList::new(),
                Err(e) => {
                    warn!(
                        path = %crl_path.display(),
                        error = %e,
                        "CRL file read failed (FIFO / symlink / oversize / IO); starting with an empty revocation list"
                    );
                    CertRevocationList::new()
                }
            }
        } else {
            CertRevocationList::new()
        };

        debug!("Loaded cluster CA from {}", ca_dir.display());

        Ok(Self {
            ca_cert_der,
            ca_cert_pem,
            ca_key_pair,
            ca_params: params,
            crl: RwLock::new(crl),
            ca_dir: ca_dir.to_path_buf(),
        })
    }

    /// Load an existing CA or generate a new one.
    pub fn load_or_generate(ca_dir: &Path) -> Result<Self, TlsError> {
        let cert_path = ca_dir.join(CA_CERT_FILENAME);
        if cert_path.exists() {
            Self::load(ca_dir)
        } else {
            Self::generate(ca_dir)
        }
    }

    /// Issue a certificate for a node.
    ///
    /// The node ID is embedded as the certificate's Common Name (CN) and
    /// also added as a DNS SAN so it can be extracted during verification.
    pub fn issue_node_cert(
        &self,
        node_id: &str,
        output_dir: &Path,
    ) -> Result<NodeCertificate, TlsError> {
        info!(node_id = %node_id, "Issuing node certificate");

        std::fs::create_dir_all(output_dir).map_err(|e| TlsError::DirCreationError {
            path: output_dir.display().to_string(),
            message: e.to_string(),
        })?;

        let mut params = CertificateParams::new(vec![node_id.to_string()])
            .map_err(|e| TlsError::CertGenerationFailed(e.to_string()))?;

        // Node distinguished name
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, node_id);
        dn.push(DnType::OrganizationName, "Carapace Cluster");
        params.distinguished_name = dn;

        // Not a CA
        params.is_ca = IsCa::NoCa;
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];

        // SAN: include node_id as DNS name so verifiers can extract it
        params.subject_alt_names =
            vec![SanType::DnsName(node_id.try_into().map_err(
                |e: rcgen::Error| TlsError::CertGenerationFailed(e.to_string()),
            )?)];

        // Validity period
        let now = chrono::Utc::now();
        params.not_before = rcgen::date_time_ymd(now.year(), now.month() as u8, now.day() as u8);
        let future = now + chrono::Duration::days(NODE_CERT_VALIDITY_DAYS);
        params.not_after =
            rcgen::date_time_ymd(future.year(), future.month() as u8, future.day() as u8);

        // Generate node key pair
        let node_key_pair =
            KeyPair::generate().map_err(|e| TlsError::CertGenerationFailed(e.to_string()))?;

        // Sign with the CA
        let issuer = rcgen::Issuer::from_params(&self.ca_params, &self.ca_key_pair);

        let node_cert = params
            .signed_by(&node_key_pair, &issuer)
            .map_err(|e| TlsError::CertGenerationFailed(e.to_string()))?;

        let cert_pem = node_cert.pem();
        let key_pem = node_key_pair.serialize_pem();
        let cert_der = CertificateDer::from(node_cert.der().to_vec());
        let fingerprint = compute_fingerprint(&cert_der);

        // Write to disk via the atomic-tmp + O_NOFOLLOW + 0o600 +
        // rename pipeline (B137). Same threat class as the CA
        // cert/key writes above — bare `fs::write` followed
        // symlinks and used the default umask.
        let cert_path = output_dir.join(format!("{}-cert.pem", node_id));
        let key_path = output_dir.join(format!("{}-key.pem", node_id));

        super::write_tls_pem_atomic_owner_only(&cert_path, cert_pem.as_bytes()).map_err(|e| {
            TlsError::CertWriteError {
                path: cert_path.display().to_string(),
                message: e.to_string(),
            }
        })?;

        super::write_tls_pem_atomic_owner_only(&key_path, key_pem.as_bytes()).map_err(|e| {
            TlsError::KeyWriteError {
                path: key_path.display().to_string(),
                message: e.to_string(),
            }
        })?;
        // Mode 0o600 applied at tmp-creation — no chmod-after step.

        info!(
            node_id = %node_id,
            fingerprint = %fingerprint,
            "Node certificate issued"
        );

        Ok(NodeCertificate {
            node_id: node_id.to_string(),
            cert_pem,
            key_pem,
            cert_path,
            key_path,
            fingerprint,
        })
    }

    /// Revoke a node certificate by fingerprint.
    pub fn revoke_cert(
        &self,
        fingerprint: &str,
        node_id: &str,
        reason: Option<String>,
    ) -> Result<bool, TlsError> {
        let mut crl = self.crl.write();
        let added = crl.revoke(fingerprint.to_string(), node_id.to_string(), reason);

        if added {
            // Persist CRL to disk via atomic-tmp + O_NOFOLLOW + 0o600
            // + rename. CRL is JSON, not PEM, but the same helper
            // applies — bytes-atomic with symlink defense (B137).
            let crl_path = self.ca_dir.join(CRL_FILENAME);
            let content = serde_json::to_string_pretty(&*crl)
                .map_err(|e| TlsError::ConfigBuildError(e.to_string()))?;
            super::write_tls_pem_atomic_owner_only(&crl_path, content.as_bytes()).map_err(|e| {
                TlsError::CertWriteError {
                    path: crl_path.display().to_string(),
                    message: e.to_string(),
                }
            })?;
            info!(fingerprint = %fingerprint, node_id = %node_id, "Certificate revoked");
        }

        Ok(added)
    }

    /// Check whether a certificate fingerprint is revoked.
    pub fn is_revoked(&self, fingerprint: &str) -> bool {
        self.crl.read().is_revoked(fingerprint)
    }

    /// Get the CRL entries.
    pub fn crl_entries(&self) -> Vec<RevokedCert> {
        self.crl.read().entries.clone()
    }

    /// Get the CA certificate in PEM format.
    pub fn ca_cert_pem(&self) -> &str {
        &self.ca_cert_pem
    }

    /// Get the CA certificate in DER format.
    pub fn ca_cert_der(&self) -> &CertificateDer<'static> {
        &self.ca_cert_der
    }

    /// Compute the SHA-256 fingerprint of the CA certificate.
    pub fn ca_fingerprint(&self) -> String {
        compute_fingerprint(&self.ca_cert_der)
    }

    /// Get the CA directory path.
    pub fn ca_dir(&self) -> &Path {
        &self.ca_dir
    }

    /// Get the CA certificate file path.
    pub fn ca_cert_path(&self) -> PathBuf {
        self.ca_dir.join(CA_CERT_FILENAME)
    }

    /// Get the CA key file path.
    pub fn ca_key_path(&self) -> PathBuf {
        self.ca_dir.join(CA_KEY_FILENAME)
    }
}

// ============================================================================
// NodeCertificate
// ============================================================================

/// Result of issuing a node certificate.
#[derive(Debug, Clone)]
pub struct NodeCertificate {
    /// Node ID embedded in the certificate CN.
    pub node_id: String,
    /// Certificate in PEM format.
    pub cert_pem: String,
    /// Private key in PEM format.
    pub key_pem: String,
    /// Path to the certificate file.
    pub cert_path: PathBuf,
    /// Path to the key file.
    pub key_path: PathBuf,
    /// SHA-256 fingerprint of the certificate.
    pub fingerprint: String,
}

// ============================================================================
// Identity extraction
// ============================================================================

/// Extract the node identity (CN) from a DER-encoded certificate.
///
/// Parses the certificate's Subject Distinguished Name to find the
/// Common Name (CN) field, which contains the node ID.
pub fn extract_node_identity(cert_der: &CertificateDer<'_>) -> Option<String> {
    let (_, cert) = x509_parser::parse_x509_certificate(cert_der.as_ref()).ok()?;
    for cn in cert.subject().iter_common_name() {
        if let Ok(value) = cn.as_str() {
            // Skip the CA's own CN
            if value != "Carapace Cluster CA" {
                return Some(value.to_string());
            }
        }
    }

    None
}

// ============================================================================
// Helpers
// ============================================================================

/// Compute the SHA-256 fingerprint of a DER-encoded certificate.
fn compute_fingerprint(cert_der: &CertificateDer<'_>) -> String {
    let mut hasher = Sha256::new();
    hasher.update(cert_der.as_ref());
    let hash = hasher.finalize();
    hash.iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .join(":")
}

/// Get current time in milliseconds since Unix epoch.
fn now_ms() -> u64 {
    crate::time::unix_now_ms_u64()
}

/// Get the default CA directory path.
pub fn default_ca_dir() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from(".config"))
        .join("carapace")
        .join("cluster-ca")
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::pki_types::PrivateKeyDer;
    use tempfile::TempDir;

    #[test]
    fn test_generate_cluster_ca() {
        let dir = TempDir::new().unwrap();
        let ca = ClusterCA::generate(dir.path()).unwrap();

        // CA cert and key files should exist
        assert!(dir.path().join(CA_CERT_FILENAME).exists());
        assert!(dir.path().join(CA_KEY_FILENAME).exists());

        // CA cert PEM should look valid
        assert!(ca.ca_cert_pem().contains("BEGIN CERTIFICATE"));
        assert!(ca.ca_cert_pem().contains("END CERTIFICATE"));

        // Fingerprint should be valid SHA-256
        let fp = ca.ca_fingerprint();
        let parts: Vec<&str> = fp.split(':').collect();
        assert_eq!(parts.len(), 32, "SHA-256 produces 32 bytes");
        for part in &parts {
            assert_eq!(part.len(), 2);
            assert!(part.chars().all(|c| c.is_ascii_hexdigit()));
        }
    }

    #[test]
    fn test_load_cluster_ca() {
        let dir = TempDir::new().unwrap();

        // Generate first
        let ca1 = ClusterCA::generate(dir.path()).unwrap();
        let fp1 = ca1.ca_fingerprint();

        // Load from disk
        let ca2 = ClusterCA::load(dir.path()).unwrap();
        let fp2 = ca2.ca_fingerprint();

        assert_eq!(fp1, fp2, "Loaded CA should have same fingerprint");
    }

    #[test]
    fn test_load_or_generate_generates() {
        let dir = TempDir::new().unwrap();
        let ca = ClusterCA::load_or_generate(dir.path()).unwrap();
        assert!(!ca.ca_fingerprint().is_empty());
        assert!(dir.path().join(CA_CERT_FILENAME).exists());
    }

    #[test]
    fn test_load_or_generate_loads_existing() {
        let dir = TempDir::new().unwrap();
        let ca1 = ClusterCA::generate(dir.path()).unwrap();
        let fp1 = ca1.ca_fingerprint();

        let ca2 = ClusterCA::load_or_generate(dir.path()).unwrap();
        assert_eq!(fp1, ca2.ca_fingerprint());
    }

    #[test]
    fn test_load_nonexistent_fails() {
        let dir = TempDir::new().unwrap();
        let result = ClusterCA::load(dir.path());
        assert!(result.is_err());
    }

    #[test]
    fn test_issue_node_cert() {
        let dir = TempDir::new().unwrap();
        let ca = ClusterCA::generate(dir.path()).unwrap();

        let node_dir = dir.path().join("nodes");
        let node_cert = ca.issue_node_cert("node-alpha", &node_dir).unwrap();

        assert_eq!(node_cert.node_id, "node-alpha");
        assert!(node_cert.cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(node_cert.key_pem.contains("BEGIN PRIVATE KEY"));
        assert!(node_cert.cert_path.exists());
        assert!(node_cert.key_path.exists());
        assert!(!node_cert.fingerprint.is_empty());

        // Fingerprint should differ from CA
        assert_ne!(node_cert.fingerprint, ca.ca_fingerprint());
    }

    #[test]
    fn test_issue_multiple_node_certs() {
        let dir = TempDir::new().unwrap();
        let ca = ClusterCA::generate(dir.path()).unwrap();

        let node_dir = dir.path().join("nodes");
        let cert_a = ca.issue_node_cert("node-a", &node_dir).unwrap();
        let cert_b = ca.issue_node_cert("node-b", &node_dir).unwrap();

        // Each node gets a unique certificate
        assert_ne!(cert_a.fingerprint, cert_b.fingerprint);
        assert_ne!(cert_a.node_id, cert_b.node_id);
    }

    #[test]
    fn test_node_cert_can_be_loaded() {
        let dir = TempDir::new().unwrap();
        let ca = ClusterCA::generate(dir.path()).unwrap();

        let node_dir = dir.path().join("nodes");
        let node_cert = ca.issue_node_cert("node-loadtest", &node_dir).unwrap();

        // Verify the issued cert can be loaded back
        let certs = super::super::load_certs(&node_cert.cert_path).unwrap();
        assert_eq!(certs.len(), 1);

        let key = super::super::load_private_key(&node_cert.key_path).unwrap();
        assert!(matches!(key, PrivateKeyDer::Pkcs8(_)));
    }

    #[test]
    fn test_extract_node_identity() {
        let dir = TempDir::new().unwrap();
        let ca = ClusterCA::generate(dir.path()).unwrap();

        let node_dir = dir.path().join("nodes");
        let node_cert = ca.issue_node_cert("gateway-east-1", &node_dir).unwrap();

        let certs = super::super::load_certs(&node_cert.cert_path).unwrap();
        let identity = extract_node_identity(&certs[0]);
        assert_eq!(identity, Some("gateway-east-1".to_string()));
    }

    #[test]
    fn test_crl_operations() {
        let dir = TempDir::new().unwrap();
        let ca = ClusterCA::generate(dir.path()).unwrap();

        let node_dir = dir.path().join("nodes");
        let node_cert = ca.issue_node_cert("node-revoke", &node_dir).unwrap();

        // Not revoked initially
        assert!(!ca.is_revoked(&node_cert.fingerprint));

        // Revoke
        let revoked = ca
            .revoke_cert(
                &node_cert.fingerprint,
                "node-revoke",
                Some("compromised".to_string()),
            )
            .unwrap();
        assert!(revoked);

        // Should be revoked now
        assert!(ca.is_revoked(&node_cert.fingerprint));

        // CRL should have entry
        let entries = ca.crl_entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].node_id, "node-revoke");
        assert_eq!(entries[0].reason, Some("compromised".to_string()));
    }

    #[test]
    fn test_crl_double_revoke() {
        let dir = TempDir::new().unwrap();
        let ca = ClusterCA::generate(dir.path()).unwrap();

        let node_dir = dir.path().join("nodes");
        let node_cert = ca.issue_node_cert("node-dupe", &node_dir).unwrap();

        // First revoke succeeds
        let first = ca
            .revoke_cert(&node_cert.fingerprint, "node-dupe", None)
            .unwrap();
        assert!(first);

        // Second revoke returns false (already revoked)
        let second = ca
            .revoke_cert(&node_cert.fingerprint, "node-dupe", None)
            .unwrap();
        assert!(!second);

        // Only one entry in CRL
        assert_eq!(ca.crl_entries().len(), 1);
    }

    #[test]
    fn test_crl_persistence() {
        let dir = TempDir::new().unwrap();

        // Generate CA and revoke a cert
        let ca = ClusterCA::generate(dir.path()).unwrap();
        let node_dir = dir.path().join("nodes");
        let node_cert = ca.issue_node_cert("node-persist", &node_dir).unwrap();
        ca.revoke_cert(&node_cert.fingerprint, "node-persist", None)
            .unwrap();

        // Load CA again and check CRL
        let ca2 = ClusterCA::load(dir.path()).unwrap();
        assert!(ca2.is_revoked(&node_cert.fingerprint));
    }

    #[test]
    fn test_crl_serialization() {
        let mut crl = CertRevocationList::new();
        assert_eq!(crl.version, 1);
        assert!(crl.entries.is_empty());

        crl.revoke("AA:BB:CC".to_string(), "node-1".to_string(), None);
        assert!(crl.is_revoked("AA:BB:CC"));
        assert!(crl.is_revoked("aa:bb:cc")); // case insensitive

        let json = serde_json::to_string(&crl).unwrap();
        let loaded: CertRevocationList = serde_json::from_str(&json).unwrap();
        assert_eq!(loaded.entries.len(), 1);
        assert!(loaded.is_revoked("AA:BB:CC"));
    }

    #[test]
    fn test_compute_fingerprint_deterministic() {
        let dir = TempDir::new().unwrap();
        let ca = ClusterCA::generate(dir.path()).unwrap();

        let fp1 = ca.ca_fingerprint();
        let fp2 = ca.ca_fingerprint();
        assert_eq!(fp1, fp2);
    }

    #[test]
    fn test_default_ca_dir() {
        let dir = default_ca_dir();
        assert!(dir.ends_with("carapace/cluster-ca") || dir.ends_with("carapace\\cluster-ca"));
    }

    #[cfg(unix)]
    #[test]
    fn test_ca_key_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        let _ca = ClusterCA::generate(dir.path()).unwrap();

        let key_path = dir.path().join(CA_KEY_FILENAME);
        let metadata = std::fs::metadata(&key_path).unwrap();
        let mode = metadata.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "CA key file should have 600 permissions");
    }

    #[cfg(unix)]
    #[test]
    fn test_node_key_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        let ca = ClusterCA::generate(dir.path()).unwrap();

        let node_dir = dir.path().join("nodes");
        let node_cert = ca.issue_node_cert("node-perms", &node_dir).unwrap();

        let metadata = std::fs::metadata(&node_cert.key_path).unwrap();
        let mode = metadata.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "Node key file should have 600 permissions");
    }
}
