//! Session integrity verification using HMAC-SHA256.
//!
//! Provides tamper detection for session files by computing and verifying
//! HMAC-SHA256 signatures stored in sidecar `.hmac` files.

use std::fs;
use std::io;
use std::io::Read;
use std::io::Write;
use std::path::{Path, PathBuf};
#[cfg(test)]
use std::sync::atomic::{AtomicUsize, Ordering};

use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;
const HMAC_DIGEST_SIZE: usize = 32;

#[cfg(test)]
static APPEND_HMAC_PATH_REBUILD_COUNT: AtomicUsize = AtomicUsize::new(0);

/// Domain separation tag for HMAC key derivation.
const KEY_DERIVATION_TAG: &[u8] = b"session-integrity-hmac-v1";

/// HMAC sidecar file extension.
const HMAC_EXTENSION: &str = "hmac";

/// Versioned sidecar prefix for HMAC digest payloads.
const HMAC_SIDECAR_V1_PREFIX: &str = "v1:";

/// Action to take when integrity verification fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntegrityAction {
    /// Log a warning and continue loading the session.
    #[default]
    Warn,
    /// Reject the session and refuse to load it.
    Reject,
}

/// Session integrity configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrityConfig {
    /// Master switch — when `false`, HMAC operations are skipped.
    #[serde(default = "default_integrity_enabled")]
    pub enabled: bool,
    /// Action on integrity failure.
    #[serde(default)]
    pub action: IntegrityAction,
}

fn default_integrity_enabled() -> bool {
    true
}

impl Default for IntegrityConfig {
    fn default() -> Self {
        Self {
            enabled: default_integrity_enabled(),
            action: IntegrityAction::Warn,
        }
    }
}

/// Integrity verification errors.
#[derive(Debug, thiserror::Error)]
pub enum IntegrityError {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
    #[error("HMAC verification failed for {file}: {reason}")]
    VerificationFailed { file: String, reason: String },
    #[error("Session rejected due to integrity violation: {file}")]
    Rejected { file: String },
}

/// Derive an HMAC key from a server secret using HKDF-SHA256.
///
/// Uses `KEY_DERIVATION_TAG` as the salt and `b"hmac-key"` as the info parameter.
pub fn derive_hmac_key(server_secret: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(KEY_DERIVATION_TAG), server_secret);
    let mut key: [u8; 32] = Default::default();
    hk.expand(b"hmac-key", &mut key)
        .expect("32-byte output is valid for HKDF-SHA256");
    key
}

/// Compute HMAC-SHA256 over the given data.
pub fn compute_hmac(key: &[u8; 32], data: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC-SHA256 accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

/// Compute HMAC-SHA256 over data read from a reader.
pub fn compute_hmac_reader<R: Read>(key: &[u8; 32], reader: &mut R) -> Result<[u8; 32], io::Error> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC-SHA256 accepts any key length");
    let mut buf = [0u8; 8192];
    loop {
        let read = reader.read(&mut buf)?;
        if read == 0 {
            break;
        }
        mac.update(&buf[..read]);
    }
    Ok(mac.finalize().into_bytes().into())
}

/// Verify HMAC-SHA256 over the given data.
pub fn verify_hmac(key: &[u8; 32], data: &[u8], expected: &[u8]) -> bool {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC-SHA256 accepts any key length");
    mac.update(data);
    mac.verify_slice(expected).is_ok()
}

/// Get the HMAC sidecar file path for a given data file.
fn hmac_path(file_path: &Path) -> PathBuf {
    let mut path = file_path.as_os_str().to_owned();
    path.push(".");
    path.push(HMAC_EXTENSION);
    PathBuf::from(path)
}

fn pending_hmac_path(file_path: &Path) -> PathBuf {
    let mut path = hmac_path(file_path).as_os_str().to_owned();
    path.push(".tmp");
    PathBuf::from(path)
}

#[derive(Clone)]
pub struct AppendHmacState(HmacSha256);

impl AppendHmacState {
    fn from_reader<R: Read>(key: &[u8; 32], reader: &mut R) -> Result<Self, io::Error> {
        let mut mac = HmacSha256::new_from_slice(key).expect("HMAC-SHA256 accepts any key length");
        let mut buf = [0u8; 8192];
        loop {
            let read = reader.read(&mut buf)?;
            if read == 0 {
                break;
            }
            mac.update(&buf[..read]);
        }
        Ok(Self(mac))
    }

    pub fn from_path(key: &[u8; 32], file_path: &Path) -> Result<Self, io::Error> {
        if !file_path.exists() {
            return Ok(Self(
                HmacSha256::new_from_slice(key).expect("HMAC-SHA256 accepts any key length"),
            ));
        }
        let mut file = fs::File::open(file_path)?;
        Self::from_reader(key, &mut file)
    }

    pub fn extend(&self, appended: &[u8]) -> Self {
        let mut mac = self.0.clone();
        mac.update(appended);
        Self(mac)
    }

    pub fn sidecar_payload(&self) -> String {
        let hmac = self.hmac();
        encode_sidecar_hmac_v1(&hmac)
    }

    pub fn hmac(&self) -> [u8; 32] {
        self.0.clone().finalize().into_bytes().into()
    }
}

fn encode_sidecar_hmac_v1(hmac: &[u8; HMAC_DIGEST_SIZE]) -> String {
    format!("{HMAC_SIDECAR_V1_PREFIX}{}", hex::encode(hmac))
}

fn parse_sidecar_hmac(raw: &str, file_name: &str) -> Result<Vec<u8>, IntegrityError> {
    let trimmed = raw.trim();

    if let Some(v1_hex) = trimmed.strip_prefix(HMAC_SIDECAR_V1_PREFIX) {
        let decoded = hex::decode(v1_hex).map_err(|e| IntegrityError::VerificationFailed {
            file: file_name.to_string(),
            reason: format!("invalid hex in versioned HMAC sidecar: {e}"),
        })?;
        if decoded.len() != HMAC_DIGEST_SIZE {
            return Err(IntegrityError::VerificationFailed {
                file: file_name.to_string(),
                reason: format!(
                    "invalid HMAC length in versioned sidecar: got {}, expected {}",
                    decoded.len(),
                    HMAC_DIGEST_SIZE
                ),
            });
        }
        return Ok(decoded);
    }

    Err(IntegrityError::VerificationFailed {
        file: file_name.to_string(),
        reason: format!("unsupported HMAC sidecar format: {trimmed}"),
    })
}

/// Write an HMAC sidecar file for the given data.
///
/// The caller provides the data bytes directly (e.g., the serialized content
/// that was just written to `file_path`). The function computes the HMAC and
/// writes it to `{file_path}.hmac`.
pub fn write_hmac_file(key: &[u8; 32], data: &[u8], file_path: &Path) -> Result<(), io::Error> {
    prepare_pending_hmac_file(key, data, file_path)?;
    commit_pending_hmac_sidecar(file_path)
}

/// Write an HMAC sidecar file for the data currently stored at `file_path`.
pub fn write_hmac_file_for_path(key: &[u8; 32], file_path: &Path) -> Result<(), io::Error> {
    prepare_pending_hmac_file_for_path(key, file_path, file_path)?;
    commit_pending_hmac_sidecar(file_path)
}

/// Prepare a pending HMAC sidecar for the provided bytes.
pub fn prepare_pending_hmac_file(
    key: &[u8; 32],
    data: &[u8],
    file_path: &Path,
) -> Result<(), io::Error> {
    let hmac = compute_hmac(key, data);
    write_pending_hmac_payload(file_path, &encode_sidecar_hmac_v1(&hmac))
}

/// Prepare a pending HMAC sidecar for data stored at `source_path`.
pub fn prepare_pending_hmac_file_for_path(
    key: &[u8; 32],
    source_path: &Path,
    file_path: &Path,
) -> Result<(), io::Error> {
    let mut file = fs::File::open(source_path)?;
    let hmac = compute_hmac_reader(key, &mut file)?;
    write_pending_hmac_payload(file_path, &encode_sidecar_hmac_v1(&hmac))
}

/// Prepare a pending HMAC sidecar from an existing rolling HMAC state.
pub fn prepare_pending_hmac_file_for_state(
    file_path: &Path,
    state: &AppendHmacState,
) -> Result<(), io::Error> {
    write_pending_hmac_payload(file_path, &state.sidecar_payload())
}

/// Prepare a pending HMAC sidecar for the current file contents plus appended bytes.
pub fn prepare_pending_hmac_file_for_appended_bytes(
    key: &[u8; 32],
    file_path: &Path,
    appended: &[u8],
) -> Result<AppendHmacState, io::Error> {
    #[cfg(test)]
    APPEND_HMAC_PATH_REBUILD_COUNT.fetch_add(1, Ordering::SeqCst);

    let base = AppendHmacState::from_path(key, file_path)?;
    prepare_pending_hmac_file_for_appended_bytes_with_state(file_path, &base, appended)
}

/// Prepare a pending HMAC sidecar for appended bytes using an already-validated state.
pub fn prepare_pending_hmac_file_for_appended_bytes_with_state(
    file_path: &Path,
    base_state: &AppendHmacState,
    appended: &[u8],
) -> Result<AppendHmacState, io::Error> {
    let next_state = base_state.extend(appended);
    write_pending_hmac_payload(file_path, &next_state.sidecar_payload())?;
    Ok(next_state)
}

/// Commit a pending HMAC sidecar prepared for `file_path`.
pub fn commit_pending_hmac_sidecar(file_path: &Path) -> Result<(), io::Error> {
    let pending = pending_hmac_path(file_path);
    let sidecar = hmac_path(file_path);
    match fs::rename(&pending, &sidecar) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == io::ErrorKind::NotFound && sidecar.exists() => Ok(()),
        Err(err) => Err(err),
    }
}

/// Delete the HMAC sidecar file for the given data file, if it exists.
pub fn delete_hmac_sidecar(file_path: &Path) -> Result<(), io::Error> {
    let sidecar = hmac_path(file_path);
    match fs::remove_file(&sidecar) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// Verify the HMAC sidecar file for the given data.
///
/// The caller provides the data bytes directly (e.g., the file content that
/// was just read from `file_path`).
///
/// # Behavior
///
/// - Missing `.hmac` file with `action: Warn` → logs warning, writes HMAC.
///   This establishes a new baseline from current bytes and cannot prove
///   historical integrity before the sidecar was created.
/// - Missing `.hmac` file with `action: Reject` → returns error.
/// - HMAC mismatch with `action: Warn` → logs warning.
/// - HMAC mismatch with `action: Reject` → returns error.
/// - Sidecar parse/format errors with `action: Warn` → logs warning.
/// - Sidecar parse/format errors with `action: Reject` → returns error.
pub fn verify_hmac_file(
    key: &[u8; 32],
    data: &[u8],
    file_path: &Path,
    config: &IntegrityConfig,
) -> Result<(), IntegrityError> {
    if !config.enabled {
        return Ok(());
    }
    let computed = compute_hmac(key, data);
    verify_hmac_digest(&computed, file_path, config)
}

/// Verify the HMAC sidecar file for the data stored at `file_path`.
pub fn verify_hmac_path(
    key: &[u8; 32],
    file_path: &Path,
    config: &IntegrityConfig,
) -> Result<(), IntegrityError> {
    if !config.enabled {
        return Ok(());
    }
    let mut file = fs::File::open(file_path)?;
    let computed = compute_hmac_reader(key, &mut file)?;
    verify_hmac_digest(&computed, file_path, config)
}

fn hmacs_match(stored: &[u8], computed: &[u8; HMAC_DIGEST_SIZE]) -> bool {
    if stored.len() != HMAC_DIGEST_SIZE {
        return false;
    }
    stored.ct_eq(computed.as_ref()).into()
}

fn verify_hmac_digest(
    computed: &[u8; 32],
    file_path: &Path,
    config: &IntegrityConfig,
) -> Result<(), IntegrityError> {
    let sidecar = hmac_path(file_path);
    let file_name = file_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("<unknown>");

    match fs::read_to_string(&sidecar) {
        Ok(stored_hex) => {
            let stored_hmac = match parse_sidecar_hmac(&stored_hex, file_name) {
                Ok(parsed) => parsed,
                Err(e) => match config.action {
                    IntegrityAction::Warn => {
                        tracing::warn!("{}", e);
                        return Ok(());
                    }
                    IntegrityAction::Reject => return Err(e),
                },
            };

            if !hmacs_match(&stored_hmac, computed) {
                if try_promote_pending_hmac_sidecar(computed, file_path)? {
                    tracing::warn!(
                        file = %file_name,
                        "recovered pending HMAC sidecar after interrupted write"
                    );
                    return Ok(());
                }
                let msg = format!("HMAC verification failed for {file_name} — possible tampering");

                match config.action {
                    IntegrityAction::Warn => {
                        tracing::warn!("{}", msg);
                        Ok(())
                    }
                    IntegrityAction::Reject => Err(IntegrityError::Rejected {
                        file: file_name.to_string(),
                    }),
                }
            } else {
                tracing::debug!(file = %file_name, "session integrity verification passed");
                Ok(())
            }
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            if try_promote_pending_hmac_sidecar(computed, file_path)? {
                tracing::warn!(
                    file = %file_name,
                    "recovered pending HMAC sidecar after interrupted write"
                );
                return Ok(());
            }
            match config.action {
                IntegrityAction::Warn => {
                    tracing::warn!(
                        file = %file_name,
                        "no HMAC sidecar found; writing current HMAC sidecar"
                    );
                    tracing::warn!(
                        file = %file_name,
                        "warn-mode integrity sidecar creation trusts current bytes; prior tampering cannot be detected"
                    );
                    if let Err(e) = fs::write(&sidecar, encode_sidecar_hmac_v1(computed)) {
                        tracing::warn!(
                            file = %file_name,
                            error = %e,
                            "failed to write HMAC sidecar"
                        );
                    }
                    Ok(())
                }
                IntegrityAction::Reject => Err(IntegrityError::Rejected {
                    file: file_name.to_string(),
                }),
            }
        }
        Err(e) => Err(IntegrityError::Io(e)),
    }
}

fn write_pending_hmac_payload(file_path: &Path, payload: &str) -> Result<(), io::Error> {
    let pending = pending_hmac_path(file_path);
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    let mut file = options.open(&pending)?;
    file.write_all(payload.as_bytes())?;
    file.sync_all()?;
    Ok(())
}

pub fn sidecar_matches_state(file_path: &Path, state: &AppendHmacState) -> Result<bool, io::Error> {
    let sidecar = hmac_path(file_path);
    match fs::read_to_string(&sidecar) {
        Ok(raw) => {
            let file_name = file_path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("<unknown>");
            let Ok(stored_hmac) = parse_sidecar_hmac(&raw, file_name) else {
                return Ok(false);
            };
            Ok(hmacs_match(&stored_hmac, &state.hmac()))
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(err),
    }
}

#[cfg(test)]
pub(crate) fn reset_append_hmac_path_rebuild_count() {
    APPEND_HMAC_PATH_REBUILD_COUNT.store(0, Ordering::SeqCst);
}

#[cfg(test)]
pub(crate) fn append_hmac_path_rebuild_count() -> usize {
    APPEND_HMAC_PATH_REBUILD_COUNT.load(Ordering::SeqCst)
}

fn try_promote_pending_hmac_sidecar(
    computed: &[u8; 32],
    file_path: &Path,
) -> Result<bool, IntegrityError> {
    let pending = pending_hmac_path(file_path);
    let pending_raw = match fs::read_to_string(&pending) {
        Ok(raw) => raw,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(err) => return Err(IntegrityError::Io(err)),
    };

    let pending_name = pending
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("<unknown>");
    let stored_hmac = match parse_sidecar_hmac(&pending_raw, pending_name) {
        Ok(parsed) => parsed,
        Err(err) => {
            tracing::warn!("{}", err);
            return Ok(false);
        }
    };

    if !hmacs_match(&stored_hmac, computed) {
        let _ = fs::remove_file(&pending);
        return Ok(false);
    }

    fs::rename(&pending, hmac_path(file_path)).map_err(IntegrityError::Io)?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    // ==================== Key Derivation ====================

    #[test]
    fn test_derive_hmac_key_deterministic() {
        let key1 = derive_hmac_key(b"server-secret-1");
        let key2 = derive_hmac_key(b"server-secret-1");
        assert_eq!(key1, key2);
    }

    #[test]
    fn test_derive_hmac_key_different_secrets() {
        let key1 = derive_hmac_key(b"secret-a");
        let key2 = derive_hmac_key(b"secret-b");
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_derive_hmac_key_length() {
        let key = derive_hmac_key(b"test");
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_derive_hmac_key_uses_hkdf() {
        // Verify the HKDF derivation produces a proper key (not all zeros, not the input)
        let key = derive_hmac_key(b"my-secret");
        assert_ne!(key, [0u8; 32]);
        // Key should differ from a simple SHA-256 hash of the secret
        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
        hasher.update(b"my-secret");
        let simple_hash: [u8; 32] = hasher.finalize().into();
        assert_ne!(key, simple_hash);
    }

    // ==================== HMAC Roundtrip ====================

    #[test]
    fn test_compute_verify_hmac_roundtrip() {
        let key = derive_hmac_key(b"test-secret");
        let data = b"session data here";
        let hmac = compute_hmac(&key, data);
        assert!(verify_hmac(&key, data, &hmac));
    }

    #[test]
    fn test_compute_hmac_returns_fixed_size() {
        let key = derive_hmac_key(b"test-secret");
        let hmac: [u8; 32] = compute_hmac(&key, b"data");
        assert_eq!(hmac.len(), 32);
    }

    #[test]
    fn test_compute_hmac_reader_matches_buffer() {
        let key = derive_hmac_key(b"test-secret");
        let data = b"streamed bytes for hmac";
        let mut reader = io::Cursor::new(data.as_slice());

        let from_buffer = compute_hmac(&key, data);
        let from_reader = compute_hmac_reader(&key, &mut reader).unwrap();

        assert_eq!(from_buffer, from_reader);
    }

    #[test]
    fn test_verify_hmac_wrong_data() {
        let key = derive_hmac_key(b"test-secret");
        let data = b"original data";
        let hmac = compute_hmac(&key, data);
        assert!(!verify_hmac(&key, b"tampered data", &hmac));
    }

    #[test]
    fn test_verify_hmac_wrong_key() {
        let key1 = derive_hmac_key(b"secret-1");
        let key2 = derive_hmac_key(b"secret-2");
        let data = b"some data";
        let hmac = compute_hmac(&key1, data);
        assert!(!verify_hmac(&key2, data, &hmac));
    }

    #[test]
    fn test_verify_hmac_wrong_mac() {
        let key = derive_hmac_key(b"secret");
        let data = b"data";
        let wrong_mac = vec![0u8; 32];
        assert!(!verify_hmac(&key, data, &wrong_mac));
    }

    // ==================== Sidecar Files ====================

    #[test]
    fn test_write_hmac_file() {
        let dir = TempDir::new().unwrap();
        let file_path = dir.path().join("meta.json");
        let data = r#"{"id":"test"}"#;
        fs::write(&file_path, data).unwrap();

        let key = derive_hmac_key(b"server-secret");
        write_hmac_file(&key, data.as_bytes(), &file_path).unwrap();

        let sidecar = dir.path().join("meta.json.hmac");
        assert!(sidecar.exists(), "HMAC sidecar should exist");

        let hmac_hex = fs::read_to_string(&sidecar).unwrap();
        assert!(!hmac_hex.is_empty());
        assert!(
            hmac_hex.starts_with(HMAC_SIDECAR_V1_PREFIX),
            "expected versioned HMAC sidecar format"
        );
    }

    #[test]
    fn test_verify_hmac_file_success() {
        let dir = TempDir::new().unwrap();
        let file_path = dir.path().join("history.jsonl");
        let data = "line1\nline2\n";
        fs::write(&file_path, data).unwrap();

        let key = derive_hmac_key(b"test-secret");
        write_hmac_file(&key, data.as_bytes(), &file_path).unwrap();

        let config = IntegrityConfig {
            enabled: true,
            action: IntegrityAction::Reject,
        };

        let result = verify_hmac_file(&key, data.as_bytes(), &file_path, &config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_hmac_path_roundtrip() {
        let dir = TempDir::new().unwrap();
        let file_path = dir.path().join("history.jsonl");
        let data = "line1\nline2\n";
        fs::write(&file_path, data).unwrap();

        let key = derive_hmac_key(b"test-secret");
        write_hmac_file_for_path(&key, &file_path).unwrap();

        let config = IntegrityConfig {
            enabled: true,
            action: IntegrityAction::Reject,
        };

        let result = verify_hmac_path(&key, &file_path, &config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_hmac_file_tampered() {
        let dir = TempDir::new().unwrap();
        let file_path = dir.path().join("meta.json");
        let original = r#"{"id":"original"}"#;
        fs::write(&file_path, original).unwrap();

        let key = derive_hmac_key(b"test-secret");
        write_hmac_file(&key, original.as_bytes(), &file_path).unwrap();

        // Tamper with the file
        let tampered = r#"{"id":"tampered"}"#;
        fs::write(&file_path, tampered).unwrap();

        let config = IntegrityConfig {
            enabled: true,
            action: IntegrityAction::Reject,
        };

        let result = verify_hmac_file(&key, tampered.as_bytes(), &file_path, &config);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_hmac_file_tampered_warn_mode() {
        let dir = TempDir::new().unwrap();
        let file_path = dir.path().join("meta.json");
        let original = r#"{"id":"original"}"#;
        fs::write(&file_path, original).unwrap();

        let key = derive_hmac_key(b"test-secret");
        write_hmac_file(&key, original.as_bytes(), &file_path).unwrap();

        // Tamper
        let tampered = r#"{"id":"tampered"}"#;
        fs::write(&file_path, tampered).unwrap();

        let config = IntegrityConfig {
            enabled: true,
            action: IntegrityAction::Warn,
        };

        // Warn mode should still return Ok
        let result = verify_hmac_file(&key, tampered.as_bytes(), &file_path, &config);
        assert!(result.is_ok());
    }

    // ==================== Missing HMAC Sidecar ====================

    #[test]
    fn test_missing_hmac_warn_writes_sidecar() {
        let dir = TempDir::new().unwrap();
        let file_path = dir.path().join("meta.json");
        let data = r#"{"id":"test"}"#;
        fs::write(&file_path, data).unwrap();

        let key = derive_hmac_key(b"test-secret");

        let config = IntegrityConfig {
            enabled: true,
            action: IntegrityAction::Warn,
        };

        // No HMAC file exists yet
        let result = verify_hmac_file(&key, data.as_bytes(), &file_path, &config);
        assert!(result.is_ok());

        let sidecar = dir.path().join("meta.json.hmac");
        assert!(sidecar.exists(), "warn mode should create HMAC sidecar");
        let sidecar_text = fs::read_to_string(&sidecar).unwrap();
        assert!(
            sidecar_text.starts_with(HMAC_SIDECAR_V1_PREFIX),
            "warn mode should write versioned HMAC sidecar"
        );

        // Now verification should pass
        let result = verify_hmac_file(&key, data.as_bytes(), &file_path, &config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_missing_hmac_path_warn_writes_sidecar() {
        let dir = TempDir::new().unwrap();
        let file_path = dir.path().join("history.jsonl");
        let data = "line1\n";
        fs::write(&file_path, data).unwrap();

        let key = derive_hmac_key(b"test-secret");

        let config = IntegrityConfig {
            enabled: true,
            action: IntegrityAction::Warn,
        };

        let result = verify_hmac_path(&key, &file_path, &config);
        assert!(result.is_ok());

        let sidecar = dir.path().join("history.jsonl.hmac");
        assert!(sidecar.exists(), "warn mode should create HMAC sidecar");
        let sidecar_text = fs::read_to_string(&sidecar).unwrap();
        assert!(
            sidecar_text.starts_with(HMAC_SIDECAR_V1_PREFIX),
            "warn mode should write versioned HMAC sidecar"
        );
    }

    #[test]
    fn test_verify_rejects_unversioned_sidecar() {
        let dir = TempDir::new().unwrap();
        let file_path = dir.path().join("meta.json");
        let data = r#"{"id":"current"}"#;
        fs::write(&file_path, data).unwrap();

        let key = derive_hmac_key(b"current-secret");
        let digest = compute_hmac(&key, data.as_bytes());
        let sidecar = dir.path().join("meta.json.hmac");
        fs::write(&sidecar, hex::encode(digest)).unwrap();

        let config = IntegrityConfig {
            enabled: true,
            action: IntegrityAction::Reject,
        };

        let result = verify_hmac_file(&key, data.as_bytes(), &file_path, &config);
        assert!(matches!(
            result,
            Err(IntegrityError::VerificationFailed { .. })
        ));
    }

    #[test]
    fn test_verify_rejects_unknown_sidecar_version() {
        let dir = TempDir::new().unwrap();
        let file_path = dir.path().join("meta.json");
        let data = r#"{"id":"version"}"#;
        fs::write(&file_path, data).unwrap();
        let sidecar = dir.path().join("meta.json.hmac");
        fs::write(&sidecar, "v2:deadbeef").unwrap();

        let key = derive_hmac_key(b"version-secret");
        let config = IntegrityConfig {
            enabled: true,
            action: IntegrityAction::Reject,
        };

        let result = verify_hmac_file(&key, data.as_bytes(), &file_path, &config);
        match result {
            Err(IntegrityError::VerificationFailed { reason, .. }) => {
                assert!(reason.contains("unsupported HMAC sidecar format"));
            }
            other => panic!("expected VerificationFailed, got {other:?}"),
        }
    }

    #[test]
    fn test_verify_warns_on_unknown_sidecar_version() {
        let dir = TempDir::new().unwrap();
        let file_path = dir.path().join("meta.json");
        let data = r#"{"id":"version"}"#;
        fs::write(&file_path, data).unwrap();
        let sidecar = dir.path().join("meta.json.hmac");
        fs::write(&sidecar, "v2:deadbeef").unwrap();

        let key = derive_hmac_key(b"version-secret");
        let config = IntegrityConfig {
            enabled: true,
            action: IntegrityAction::Warn,
        };

        let result = verify_hmac_file(&key, data.as_bytes(), &file_path, &config);
        assert!(
            result.is_ok(),
            "unknown sidecar version should warn-and-continue in Warn mode"
        );

        let unchanged = fs::read_to_string(&sidecar).unwrap();
        assert_eq!(unchanged, "v2:deadbeef");
    }

    #[test]
    fn test_missing_hmac_reject_fails() {
        let dir = TempDir::new().unwrap();
        let file_path = dir.path().join("meta.json");
        let data = r#"{"id":"test"}"#;
        fs::write(&file_path, data).unwrap();

        let key = derive_hmac_key(b"test-secret");

        let config = IntegrityConfig {
            enabled: true,
            action: IntegrityAction::Reject,
        };

        let result = verify_hmac_file(&key, data.as_bytes(), &file_path, &config);
        assert!(result.is_err());
    }

    #[test]
    fn test_commit_pending_hmac_sidecar_succeeds_if_already_promoted() {
        let dir = TempDir::new().unwrap();
        let file_path = dir.path().join("history.jsonl");
        let data = "line1\n";
        fs::write(&file_path, data).unwrap();

        let key = derive_hmac_key(b"test-secret");
        prepare_pending_hmac_file(&key, data.as_bytes(), &file_path).unwrap();

        let pending = pending_hmac_path(&file_path);
        let sidecar = hmac_path(&file_path);
        fs::rename(&pending, &sidecar).unwrap();

        let result = commit_pending_hmac_sidecar(&file_path);
        assert!(result.is_ok());
        assert!(sidecar.exists());
        assert!(!pending.exists());
    }

    #[test]
    fn test_try_promote_pending_hmac_sidecar_removes_stale_pending_file() {
        let dir = TempDir::new().unwrap();
        let file_path = dir.path().join("history.jsonl");
        let stale_data = "old\n";
        let current_data = "new\n";
        fs::write(&file_path, current_data).unwrap();

        let key = derive_hmac_key(b"test-secret");
        prepare_pending_hmac_file(&key, stale_data.as_bytes(), &file_path).unwrap();
        let pending = pending_hmac_path(&file_path);
        assert!(pending.exists());

        let computed = compute_hmac(&key, current_data.as_bytes());
        let promoted = try_promote_pending_hmac_sidecar(&computed, &file_path).unwrap();
        assert!(!promoted);
        assert!(!pending.exists());
    }

    // ==================== Disabled Config ====================

    #[test]
    fn test_disabled_config_skips_verification() {
        let key = derive_hmac_key(b"secret");
        let dir = TempDir::new().unwrap();
        let file_path = dir.path().join("meta.json");
        let data = "data";
        fs::write(&file_path, data).unwrap();

        let config = IntegrityConfig {
            enabled: false,
            action: IntegrityAction::Reject,
        };

        // No HMAC sidecar, but disabled — should pass
        let result = verify_hmac_file(&key, data.as_bytes(), &file_path, &config);
        assert!(result.is_ok());
    }

    // ==================== Config Serialization ====================

    #[test]
    fn test_integrity_config_default() {
        let config = IntegrityConfig::default();
        assert!(config.enabled);
        assert_eq!(config.action, IntegrityAction::Warn);
    }

    #[test]
    fn test_integrity_config_missing_enabled_defaults_to_true() {
        let parsed: IntegrityConfig = serde_json::from_str(r#"{"action":"reject"}"#).unwrap();
        assert!(parsed.enabled);
        assert_eq!(parsed.action, IntegrityAction::Reject);
    }

    #[test]
    fn test_integrity_config_serde_roundtrip() {
        let config = IntegrityConfig {
            enabled: true,
            action: IntegrityAction::Reject,
        };
        let json = serde_json::to_string(&config).unwrap();
        let parsed: IntegrityConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.enabled, config.enabled);
        assert_eq!(parsed.action, IntegrityAction::Reject);
    }

    // ==================== HMAC Path ====================

    #[test]
    fn test_hmac_path() {
        let path = Path::new("/sessions/abc/meta.json");
        let sidecar = hmac_path(path);
        assert_eq!(sidecar, PathBuf::from("/sessions/abc/meta.json.hmac"));
    }

    #[test]
    fn test_hmac_path_jsonl() {
        let path = Path::new("/sessions/abc/history.jsonl");
        let sidecar = hmac_path(path);
        assert_eq!(sidecar, PathBuf::from("/sessions/abc/history.jsonl.hmac"));
    }

    // ==================== Empty Data ====================

    #[test]
    fn test_hmac_empty_data() {
        let key = derive_hmac_key(b"secret");
        let hmac = compute_hmac(&key, b"");
        assert!(verify_hmac(&key, b"", &hmac));
        assert!(!verify_hmac(&key, b"non-empty", &hmac));
    }

    // ==================== Large Data ====================

    #[test]
    fn test_hmac_large_data() {
        let key = derive_hmac_key(b"secret");
        let data = vec![0xABu8; 1024 * 1024]; // 1 MB
        let hmac = compute_hmac(&key, &data);
        assert!(verify_hmac(&key, &data, &hmac));
    }

    // ==================== Multiple Files ====================

    #[test]
    fn test_multiple_files_independent_hmacs() {
        let dir = TempDir::new().unwrap();
        let key = derive_hmac_key(b"secret");

        let file1 = dir.path().join("meta.json");
        let file2 = dir.path().join("history.jsonl");
        let data1 = "meta content";
        let data2 = "history content";
        fs::write(&file1, data1).unwrap();
        fs::write(&file2, data2).unwrap();

        write_hmac_file(&key, data1.as_bytes(), &file1).unwrap();
        write_hmac_file(&key, data2.as_bytes(), &file2).unwrap();

        let config = IntegrityConfig {
            enabled: true,
            action: IntegrityAction::Reject,
        };

        assert!(verify_hmac_file(&key, data1.as_bytes(), &file1, &config).is_ok());
        assert!(verify_hmac_file(&key, data2.as_bytes(), &file2, &config).is_ok());

        // Tamper with file1 only — file2 should still pass
        let tampered = "tampered";
        fs::write(&file1, tampered).unwrap();
        assert!(verify_hmac_file(&key, tampered.as_bytes(), &file1, &config).is_err());
        assert!(verify_hmac_file(&key, data2.as_bytes(), &file2, &config).is_ok());
    }

    // ==================== HMAC hex encoding ====================

    #[test]
    fn test_compute_hmac_hex_encodes() {
        let key = derive_hmac_key(b"secret");
        let hmac = compute_hmac(&key, b"data");
        let hex_str = hex::encode(hmac);
        assert_eq!(hex_str.len(), 64); // 32 bytes -> 64 hex chars
    }
}
