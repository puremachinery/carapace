//! Session-at-rest encryption support.
//!
//! This module owns confidentiality for session artifacts:
//! - session metadata files
//! - session history JSONL lines
//! - session archive files

use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit as _, Mac};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use thiserror::Error;
use zeroize::Zeroizing;

use crate::crypto::{
    derive_key_argon2id, PasswordKdfError, ARGON2ID_V2_ITERATIONS, ARGON2ID_V2_LANES,
    ARGON2ID_V2_MEMORY_KIB, PASSWORD_DERIVED_KEY_LEN,
};
use crate::sessions::file_lock::FileLock;

const CRYPTO_MANIFEST_PATH: &str = ".crypto-manifest";
const CRYPTO_MANIFEST_VERSION: u32 = 1;
const CRYPTO_KDF_ID: &str = "argon2id-v2";
const SESSION_ENCRYPTED_FORMAT_V1: &str = "session-enc-v1";
const SESSION_ENCRYPTED_PREFIX_V1: &[u8] = b"cse1:";
const SESSION_ENCRYPTION_ROOT_TAG: &[u8] = b"carapace:session-encryption-root:v1";
const SESSION_ENCRYPTION_INFO_PREFIX: &[u8] = b"carapace:session-encryption-key:v1:";
// `:v2` here is intentional namespace separation from the pre-encryption
// integrity key derivation in `sessions::integrity` (`session-integrity-hmac-v1`).
// This label belongs to the session-encryption HKDF hierarchy, not the older
// server-secret HMAC derivation path.
const SESSION_INTEGRITY_INFO: &[u8] = b"carapace:session-integrity-hmac:v2";
const SESSION_MANIFEST_INTEGRITY_INFO: &[u8] = b"carapace:session-manifest-integrity:v1";
const SESSION_METADATA_PURPOSE: &str = "metadata";
const SESSION_HISTORY_PURPOSE: &str = "history";
const SESSION_ARCHIVE_PURPOSE: &str = "archive";
const ROOT_SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
type HmacSha256 = Hmac<Sha256>;

/// Session encryption policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EncryptionMode {
    /// Never encrypt session artifacts.
    Off,
    /// Encrypt when a config password is available.
    #[default]
    IfPassword,
    /// Require a config password and fail closed when unavailable.
    Required,
}

impl EncryptionMode {
    pub fn uses_encryption(self) -> bool {
        !matches!(self, Self::Off)
    }
}

/// Configurable session encryption settings.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EncryptionConfig {
    #[serde(default)]
    pub mode: EncryptionMode,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CryptoManifest {
    version: u32,
    kdf: String,
    root_salt: String,
    memory_kib: u32,
    iterations: u32,
    lanes: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    integrity: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct EncryptedEnvelope {
    format: String,
    n: String,
    c: String,
}

/// Session crypto initialization / encryption errors.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SessionCryptoError {
    #[error("session crypto manifest IO error: {0}")]
    Io(String),
    #[error("invalid session crypto manifest: {0}")]
    Manifest(String),
    #[error("session key derivation failed: {0}")]
    KeyDerivation(String),
    #[error("session encryption random number generation failed: {0}")]
    RandomFailure(String),
    #[error("invalid encrypted session format: {0}")]
    BadFormat(String),
    #[error("base64 decode error in field '{field}': {message}")]
    Base64Decode { field: String, message: String },
    #[error("session encryption failed: {0}")]
    EncryptionFailed(String),
    #[error("session decryption failed")]
    DecryptionFailed,
    #[error("session crypto manifest integrity verification failed")]
    ManifestIntegrityFailed,
}

impl From<std::io::Error> for SessionCryptoError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err.to_string())
    }
}

impl From<serde_json::Error> for SessionCryptoError {
    fn from(err: serde_json::Error) -> Self {
        Self::BadFormat(err.to_string())
    }
}

fn map_kdf_error(err: PasswordKdfError) -> SessionCryptoError {
    SessionCryptoError::KeyDerivation(err.to_string())
}

fn manifest_path(base_path: &Path) -> PathBuf {
    base_path.join(CRYPTO_MANIFEST_PATH)
}

fn create_private_file(path: &Path) -> Result<File, SessionCryptoError> {
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path).map_err(Into::into)
}

fn write_manifest_atomic(path: &Path, manifest: &CryptoManifest) -> Result<(), SessionCryptoError> {
    let temp_path = path.with_extension("tmp");
    let serialized = serde_json::to_vec_pretty(manifest)
        .map_err(|err| SessionCryptoError::Manifest(err.to_string()))?;
    {
        let mut file = create_private_file(&temp_path)?;
        file.write_all(&serialized)?;
        file.sync_all()?;
    }
    if let Err(err) = fs::rename(&temp_path, path) {
        let _ = fs::remove_file(&temp_path);
        return Err(err.into());
    }
    Ok(())
}

fn manifest_integrity_input(manifest: &CryptoManifest) -> Vec<u8> {
    let mut authenticated = manifest.clone();
    authenticated.integrity = None;
    serde_json::to_vec(&authenticated)
        .expect("CryptoManifest serialization for integrity input should not fail")
}

fn decode_b64<const N: usize>(
    field: &'static str,
    value: &str,
) -> Result<[u8; N], SessionCryptoError> {
    let decoded = BASE64
        .decode(value)
        .map_err(|err| SessionCryptoError::Base64Decode {
            field: field.to_string(),
            message: err.to_string(),
        })?;
    decoded.try_into().map_err(|got: Vec<u8>| {
        SessionCryptoError::BadFormat(format!(
            "field '{field}' has wrong length: expected {N}, got {}",
            got.len()
        ))
    })
}

fn expand_hkdf(
    master_key: &[u8],
    info: &[u8],
) -> Result<Zeroizing<[u8; PASSWORD_DERIVED_KEY_LEN]>, SessionCryptoError> {
    // The Argon2-derived master key is already high-entropy. This fixed HKDF
    // extract salt is therefore just the stable root-domain label for the
    // session key hierarchy; per-artifact separation still comes from the
    // caller-provided Expand `info` values.
    let hk = Hkdf::<Sha256>::new(Some(SESSION_ENCRYPTION_ROOT_TAG), master_key);
    let mut out = [0u8; PASSWORD_DERIVED_KEY_LEN];
    hk.expand(info, &mut out)
        .map_err(|err| SessionCryptoError::KeyDerivation(err.to_string()))?;
    Ok(Zeroizing::new(out))
}

fn aad_bytes(session_id: &str, purpose: &str) -> Vec<u8> {
    format!("carapace:session:{purpose}:v1:{session_id}").into_bytes()
}

fn derive_session_key_from_master(
    master_key: &[u8],
    session_id: &str,
    purpose: &str,
) -> Result<Zeroizing<[u8; PASSWORD_DERIVED_KEY_LEN]>, SessionCryptoError> {
    let mut info = Vec::with_capacity(
        SESSION_ENCRYPTION_INFO_PREFIX.len() + session_id.len() + purpose.len() + 1,
    );
    info.extend_from_slice(SESSION_ENCRYPTION_INFO_PREFIX);
    info.extend_from_slice(session_id.as_bytes());
    info.push(b':');
    info.extend_from_slice(purpose.as_bytes());
    expand_hkdf(master_key, &info)
}

fn decrypt_prefixed_bytes_with_master_key(
    master_key: &[u8],
    session_id: &str,
    purpose: &str,
    ciphertext: &[u8],
) -> Result<Vec<u8>, SessionCryptoError> {
    if !has_encrypted_payload_prefix(ciphertext) {
        return Err(SessionCryptoError::BadFormat(
            "missing cse1: prefix".to_string(),
        ));
    }
    let envelope: EncryptedEnvelope = serde_json::from_slice(strip_prefix(ciphertext))?;
    if envelope.format != SESSION_ENCRYPTED_FORMAT_V1 {
        return Err(SessionCryptoError::BadFormat(format!(
            "unsupported encrypted session format '{}'",
            envelope.format
        )));
    }

    let nonce_bytes = decode_b64::<NONCE_LEN>("n", &envelope.n)?;
    let ciphertext =
        BASE64
            .decode(&envelope.c)
            .map_err(|err| SessionCryptoError::Base64Decode {
                field: "c".to_string(),
                message: err.to_string(),
            })?;
    let key = derive_session_key_from_master(master_key, session_id, purpose)?;
    let cipher = Aes256Gcm::new((&*key).into());
    let aad = aad_bytes(session_id, purpose);
    cipher
        .decrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: ciphertext.as_ref(),
                aad: &aad,
            },
        )
        .map_err(|_| SessionCryptoError::DecryptionFailed)
}

fn read_prefixed_file_bytes(path: &Path) -> Result<Option<Vec<u8>>, SessionCryptoError> {
    let mut file = File::open(path)?;
    let mut prefix = [0u8; SESSION_ENCRYPTED_PREFIX_V1.len()];
    if file.read_exact(&mut prefix).is_err() || prefix != SESSION_ENCRYPTED_PREFIX_V1 {
        return Ok(None);
    }

    let mut bytes = Vec::new();
    bytes.extend_from_slice(&prefix);
    file.read_to_end(&mut bytes)?;
    Ok(Some(bytes))
}

fn read_prefixed_file_bytes_locked(path: &Path) -> Result<Option<Vec<u8>>, SessionCryptoError> {
    let _lock = FileLock::acquire(path)?;
    read_prefixed_file_bytes(path)
}

fn history_contains_decryptable_encrypted_line_locked(
    path: &Path,
    master_key: &[u8],
    session_id: &str,
) -> Result<bool, SessionCryptoError> {
    let _lock = FileLock::acquire(path)?;
    let reader = BufReader::new(File::open(path)?);
    for line in reader.split(b'\n') {
        let line = line?;
        if line.is_empty() || !has_encrypted_payload_prefix(&line) {
            continue;
        }
        if decrypt_prefixed_bytes_with_master_key(
            master_key,
            session_id,
            SESSION_HISTORY_PURPOSE,
            &line,
        )
        .is_ok()
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn verify_manifest_backfill_password(
    base_path: &Path,
    master_key: &[u8],
) -> Result<bool, SessionCryptoError> {
    for entry in fs::read_dir(base_path)? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }

        match path.extension().and_then(|ext| ext.to_str()) {
            Some("json") => {
                let Some(session_id) = path.file_stem().and_then(|stem| stem.to_str()) else {
                    continue;
                };
                let Some(bytes) = read_prefixed_file_bytes_locked(&path)? else {
                    continue;
                };
                if decrypt_prefixed_bytes_with_master_key(
                    master_key,
                    session_id,
                    SESSION_METADATA_PURPOSE,
                    &bytes,
                )
                .is_ok()
                {
                    return Ok(true);
                }
            }
            Some("jsonl") => {
                let Some(session_id) = path.file_stem().and_then(|stem| stem.to_str()) else {
                    continue;
                };
                if history_contains_decryptable_encrypted_line_locked(
                    &path, master_key, session_id,
                )? {
                    return Ok(true);
                }
            }
            _ => {}
        }
    }

    let archive_dir = base_path.join("archives");
    if archive_dir.is_dir() {
        for entry in fs::read_dir(&archive_dir)? {
            let entry = entry?;
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
                continue;
            };
            let Some(session_id) = file_name.strip_suffix(".archive.json") else {
                continue;
            };
            let Some(bytes) = read_prefixed_file_bytes_locked(&path)? else {
                continue;
            };
            if decrypt_prefixed_bytes_with_master_key(
                master_key,
                session_id,
                SESSION_ARCHIVE_PURPOSE,
                &bytes,
            )
            .is_ok()
            {
                return Ok(true);
            }
        }
    }

    Ok(false)
}

fn manifest_integrity_tag(
    master_key: &[u8],
    manifest: &CryptoManifest,
) -> Result<String, SessionCryptoError> {
    let key = expand_hkdf(master_key, SESSION_MANIFEST_INTEGRITY_INFO)?;
    let mut mac = HmacSha256::new_from_slice(key.as_ref())
        .map_err(|err| SessionCryptoError::KeyDerivation(err.to_string()))?;
    mac.update(&manifest_integrity_input(manifest));
    Ok(BASE64.encode(mac.finalize().into_bytes()))
}

fn verify_manifest_integrity(
    master_key: &[u8],
    manifest: &CryptoManifest,
    encoded_tag: &str,
) -> Result<bool, SessionCryptoError> {
    let key = expand_hkdf(master_key, SESSION_MANIFEST_INTEGRITY_INFO)?;
    let expected = BASE64.decode(encoded_tag).map_err(|err| {
        SessionCryptoError::BadFormat(format!("invalid base64 in manifest integrity field: {err}"))
    })?;
    let mut mac = HmacSha256::new_from_slice(key.as_ref())
        .map_err(|err| SessionCryptoError::KeyDerivation(err.to_string()))?;
    mac.update(&manifest_integrity_input(manifest));
    Ok(mac.verify_slice(&expected).is_ok())
}

fn validate_manifest_kdf_parameters(
    manifest: &CryptoManifest,
    manifest_path: &Path,
) -> Result<(), SessionCryptoError> {
    if manifest.memory_kib != ARGON2ID_V2_MEMORY_KIB
        || manifest.iterations != ARGON2ID_V2_ITERATIONS
        || manifest.lanes != ARGON2ID_V2_LANES
    {
        return Err(SessionCryptoError::Manifest(format!(
            "unsupported manifest kdf parameters in {}: expected memory_kib={}, iterations={}, lanes={}, got memory_kib={}, iterations={}, lanes={}",
            manifest_path.display(),
            ARGON2ID_V2_MEMORY_KIB,
            ARGON2ID_V2_ITERATIONS,
            ARGON2ID_V2_LANES,
            manifest.memory_kib,
            manifest.iterations,
            manifest.lanes
        )));
    }
    Ok(())
}

fn has_prefix(data: &[u8]) -> bool {
    data.starts_with(SESSION_ENCRYPTED_PREFIX_V1)
}

fn strip_prefix(data: &[u8]) -> &[u8] {
    data.strip_prefix(SESSION_ENCRYPTED_PREFIX_V1)
        .unwrap_or(data)
}

/// Root session-crypto context derived from the config password.
pub struct SessionCryptoContext {
    master_key: Zeroizing<[u8; PASSWORD_DERIVED_KEY_LEN]>,
    integrity_hmac_key: Zeroizing<[u8; 32]>,
    manifest_integrity_valid: bool,
}

impl fmt::Debug for SessionCryptoContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionCryptoContext")
            .field("master_key", &"[redacted]")
            .field("integrity_hmac_key", &"[redacted]")
            .field("manifest_integrity_valid", &self.manifest_integrity_valid)
            .finish()
    }
}

impl SessionCryptoContext {
    /// Load or create the session crypto manifest and derive the root key.
    pub fn load_or_create(base_path: &Path, password: &[u8]) -> Result<Self, SessionCryptoError> {
        fs::create_dir_all(base_path)?;
        let manifest_path = manifest_path(base_path);
        let _manifest_lock = FileLock::acquire(&manifest_path)?;
        let manifest_exists = manifest_path.exists();
        let mut manifest = if manifest_exists {
            let raw = fs::read_to_string(&manifest_path)?;
            let manifest: CryptoManifest = serde_json::from_str(&raw).map_err(|err| {
                SessionCryptoError::Manifest(format!(
                    "failed to parse {}: {}",
                    manifest_path.display(),
                    err
                ))
            })?;
            if manifest.version != CRYPTO_MANIFEST_VERSION {
                return Err(SessionCryptoError::Manifest(format!(
                    "unsupported manifest version {} in {}",
                    manifest.version,
                    manifest_path.display()
                )));
            }
            if manifest.kdf != CRYPTO_KDF_ID {
                return Err(SessionCryptoError::Manifest(format!(
                    "unsupported manifest kdf '{}' in {}",
                    manifest.kdf,
                    manifest_path.display()
                )));
            }
            validate_manifest_kdf_parameters(&manifest, &manifest_path)?;
            manifest
        } else {
            let mut salt = [0u8; ROOT_SALT_LEN];
            getrandom::fill(&mut salt)
                .map_err(|err| SessionCryptoError::RandomFailure(err.to_string()))?;
            CryptoManifest {
                version: CRYPTO_MANIFEST_VERSION,
                kdf: CRYPTO_KDF_ID.to_string(),
                root_salt: BASE64.encode(salt),
                memory_kib: ARGON2ID_V2_MEMORY_KIB,
                iterations: ARGON2ID_V2_ITERATIONS,
                lanes: ARGON2ID_V2_LANES,
                integrity: None,
            }
        };

        let root_salt = decode_b64::<ROOT_SALT_LEN>("root_salt", &manifest.root_salt)?;
        let master_key =
            Zeroizing::new(derive_key_argon2id(password, &root_salt).map_err(map_kdf_error)?);
        let manifest_integrity_valid = if !manifest_exists {
            manifest.integrity = Some(manifest_integrity_tag(master_key.as_ref(), &manifest)?);
            write_manifest_atomic(&manifest_path, &manifest)?;
            true
        } else if let Some(encoded_tag) = manifest.integrity.as_deref() {
            verify_manifest_integrity(master_key.as_ref(), &manifest, encoded_tag)?
        } else {
            if verify_manifest_backfill_password(base_path, master_key.as_ref())? {
                tracing::warn!(
                    manifest_path = %manifest_path.display(),
                    "backfilling missing session crypto manifest integrity tag"
                );
                manifest.integrity = Some(manifest_integrity_tag(master_key.as_ref(), &manifest)?);
                write_manifest_atomic(&manifest_path, &manifest)?;
                true
            } else {
                tracing::warn!(
                    manifest_path = %manifest_path.display(),
                    "refusing to backfill missing session crypto manifest integrity tag because the provided password did not decrypt any existing encrypted session artifact; encrypted session reads and new encrypted writes will remain blocked until the manifest is repaired or removed"
                );
                false
            }
        };
        let integrity_hmac_key = expand_hkdf(master_key.as_ref(), SESSION_INTEGRITY_INFO)?;

        Ok(Self {
            master_key,
            integrity_hmac_key,
            manifest_integrity_valid,
        })
    }

    pub fn manifest_integrity_valid(&self) -> bool {
        self.manifest_integrity_valid
    }

    fn ensure_manifest_integrity(&self) -> Result<(), SessionCryptoError> {
        if self.manifest_integrity_valid {
            Ok(())
        } else {
            Err(SessionCryptoError::ManifestIntegrityFailed)
        }
    }

    /// Derive a per-session encryption key for the given purpose.
    pub fn derive_session_key(
        &self,
        session_id: &str,
        purpose: &str,
    ) -> Result<Zeroizing<[u8; PASSWORD_DERIVED_KEY_LEN]>, SessionCryptoError> {
        self.ensure_manifest_integrity()?;
        derive_session_key_from_master(self.master_key.as_ref(), session_id, purpose)
    }

    /// Derive the session-store-wide HMAC key rooted in the encryption master key.
    pub fn integrity_hmac_key(&self) -> Option<Zeroizing<[u8; 32]>> {
        if !self.manifest_integrity_valid {
            return None;
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(self.integrity_hmac_key.as_ref());
        Some(Zeroizing::new(out))
    }

    pub fn encrypt_bytes(
        &self,
        session_id: &str,
        purpose: &str,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, SessionCryptoError> {
        let key = self.derive_session_key(session_id, purpose)?;
        let cipher = Aes256Gcm::new((&*key).into());

        let mut nonce_bytes = [0u8; NONCE_LEN];
        getrandom::fill(&mut nonce_bytes)
            .map_err(|err| SessionCryptoError::RandomFailure(err.to_string()))?;
        let nonce = Nonce::from_slice(&nonce_bytes);
        let aad = aad_bytes(session_id, purpose);
        let ciphertext = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|err| SessionCryptoError::EncryptionFailed(err.to_string()))?;

        let envelope = EncryptedEnvelope {
            format: SESSION_ENCRYPTED_FORMAT_V1.to_string(),
            n: BASE64.encode(nonce_bytes),
            c: BASE64.encode(ciphertext),
        };
        let envelope = serde_json::to_vec(&envelope).map_err(SessionCryptoError::from)?;
        let mut out = Vec::with_capacity(SESSION_ENCRYPTED_PREFIX_V1.len() + envelope.len());
        out.extend_from_slice(SESSION_ENCRYPTED_PREFIX_V1);
        out.extend_from_slice(&envelope);
        Ok(out)
    }

    pub fn decrypt_bytes(
        &self,
        session_id: &str,
        purpose: &str,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, SessionCryptoError> {
        self.ensure_manifest_integrity()?;
        decrypt_prefixed_bytes_with_master_key(
            self.master_key.as_ref(),
            session_id,
            purpose,
            ciphertext,
        )
    }

    pub fn encrypt_json<T: Serialize>(
        &self,
        session_id: &str,
        purpose: &str,
        value: &T,
    ) -> Result<Vec<u8>, SessionCryptoError> {
        let plaintext = serde_json::to_vec(value).map_err(SessionCryptoError::from)?;
        self.encrypt_bytes(session_id, purpose, &plaintext)
    }

    pub fn decrypt_json<T: DeserializeOwned>(
        &self,
        session_id: &str,
        purpose: &str,
        ciphertext: &[u8],
    ) -> Result<T, SessionCryptoError> {
        let plaintext = self.decrypt_bytes(session_id, purpose, ciphertext)?;
        serde_json::from_slice(&plaintext).map_err(SessionCryptoError::from)
    }
}

pub fn has_encrypted_payload_prefix(data: &[u8]) -> bool {
    has_prefix(data)
}

pub fn is_encrypted_payload(data: &[u8]) -> bool {
    if !has_encrypted_payload_prefix(data) {
        return false;
    }
    serde_json::from_slice::<EncryptedEnvelope>(strip_prefix(data))
        .map(|env| env.format == SESSION_ENCRYPTED_FORMAT_V1)
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn test_key_material() -> Vec<u8> {
        format!("fixture-{}", uuid::Uuid::new_v4()).into_bytes()
    }

    #[test]
    fn test_crypto_context_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let key_material = test_key_material();
        let ctx = SessionCryptoContext::load_or_create(dir.path(), &key_material).unwrap();
        let plaintext = br#"{"hello":"world"}"#;
        let encrypted = ctx
            .encrypt_bytes("session-1", "metadata", plaintext)
            .unwrap();
        assert!(has_encrypted_payload_prefix(&encrypted));
        assert!(is_encrypted_payload(&encrypted));
        let decrypted = ctx
            .decrypt_bytes("session-1", "metadata", &encrypted)
            .unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_crypto_context_reuses_manifest_salt() {
        let dir = tempfile::tempdir().unwrap();
        let key_material = test_key_material();
        let ctx1 = SessionCryptoContext::load_or_create(dir.path(), &key_material).unwrap();
        let ctx2 = SessionCryptoContext::load_or_create(dir.path(), &key_material).unwrap();
        assert_eq!(ctx1.integrity_hmac_key(), ctx2.integrity_hmac_key());
    }

    #[test]
    fn test_crypto_context_detects_wrong_password() {
        let dir = tempfile::tempdir().unwrap();
        let key_material = test_key_material();
        let wrong_key_material = test_key_material();
        let ctx = SessionCryptoContext::load_or_create(dir.path(), &key_material).unwrap();
        let encrypted = ctx
            .encrypt_bytes("session-1", "history", br#"{"msg":"hello"}"#)
            .unwrap();
        let wrong = SessionCryptoContext::load_or_create(dir.path(), &wrong_key_material).unwrap();
        assert!(!wrong.manifest_integrity_valid());
        let err = wrong
            .decrypt_bytes("session-1", "history", &encrypted)
            .unwrap_err();
        assert_eq!(err, SessionCryptoError::ManifestIntegrityFailed);
    }

    #[test]
    fn test_crypto_context_rejects_cross_session_decryption() {
        let dir = tempfile::tempdir().unwrap();
        let key_material = test_key_material();
        let ctx = SessionCryptoContext::load_or_create(dir.path(), &key_material).unwrap();
        let encrypted = ctx
            .encrypt_bytes("session-a", "metadata", br#"{"hello":"world"}"#)
            .unwrap();

        let err = ctx
            .decrypt_bytes("session-b", "metadata", &encrypted)
            .unwrap_err();
        assert_eq!(err, SessionCryptoError::DecryptionFailed);
    }

    #[test]
    fn test_crypto_context_rejects_cross_purpose_decryption() {
        let dir = tempfile::tempdir().unwrap();
        let key_material = test_key_material();
        let ctx = SessionCryptoContext::load_or_create(dir.path(), &key_material).unwrap();
        let encrypted = ctx
            .encrypt_bytes("session-a", "metadata", br#"{"hello":"world"}"#)
            .unwrap();

        let err = ctx
            .decrypt_bytes("session-a", "history", &encrypted)
            .unwrap_err();
        assert_eq!(err, SessionCryptoError::DecryptionFailed);
    }

    #[test]
    fn test_crypto_context_detects_tampered_manifest() {
        let dir = tempfile::tempdir().unwrap();
        let key_material = test_key_material();
        let ctx = SessionCryptoContext::load_or_create(dir.path(), &key_material).unwrap();
        let encrypted = ctx
            .encrypt_bytes("session-1", "metadata", br#"{"hello":"world"}"#)
            .unwrap();

        let manifest_path = dir.path().join(CRYPTO_MANIFEST_PATH);
        let mut manifest: Value =
            serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();
        manifest["root_salt"] = Value::String(BASE64.encode([7u8; ROOT_SALT_LEN]));
        fs::write(
            &manifest_path,
            serde_json::to_vec_pretty(&manifest).unwrap(),
        )
        .unwrap();

        let tampered = SessionCryptoContext::load_or_create(dir.path(), &key_material).unwrap();
        assert!(!tampered.manifest_integrity_valid());
        let err = tampered
            .decrypt_bytes("session-1", "metadata", &encrypted)
            .unwrap_err();
        assert_eq!(err, SessionCryptoError::ManifestIntegrityFailed);
    }

    #[test]
    fn test_crypto_context_reports_invalid_manifest_integrity_base64() {
        let dir = tempfile::tempdir().unwrap();
        let key_material = test_key_material();
        let _ctx = SessionCryptoContext::load_or_create(dir.path(), &key_material).unwrap();

        let manifest_path = dir.path().join(CRYPTO_MANIFEST_PATH);
        let mut manifest: Value =
            serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();
        manifest["integrity"] = Value::String("%%%not-base64%%%".to_string());
        fs::write(
            &manifest_path,
            serde_json::to_vec_pretty(&manifest).unwrap(),
        )
        .unwrap();

        let err = SessionCryptoContext::load_or_create(dir.path(), &key_material).unwrap_err();
        assert!(matches!(
            err,
            SessionCryptoError::BadFormat(message)
                if message.contains("invalid base64 in manifest integrity field")
        ));
    }

    #[test]
    fn test_crypto_context_rejects_manifest_with_mismatched_kdf_parameters() {
        let dir = tempfile::tempdir().unwrap();
        let key_material = test_key_material();
        let _ctx = SessionCryptoContext::load_or_create(dir.path(), &key_material).unwrap();

        let manifest_path = dir.path().join(CRYPTO_MANIFEST_PATH);
        let mut manifest: Value =
            serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();
        manifest["iterations"] = Value::from(ARGON2ID_V2_ITERATIONS + 1);
        fs::write(
            &manifest_path,
            serde_json::to_vec_pretty(&manifest).unwrap(),
        )
        .unwrap();

        let err = SessionCryptoContext::load_or_create(dir.path(), &key_material).unwrap_err();
        assert!(matches!(
            err,
            SessionCryptoError::Manifest(message)
                if message.contains("unsupported manifest kdf parameters")
        ));
    }

    #[test]
    fn test_crypto_context_backfills_missing_manifest_integrity() {
        let dir = tempfile::tempdir().unwrap();
        let key_material = test_key_material();
        let ctx = SessionCryptoContext::load_or_create(dir.path(), &key_material).unwrap();
        let encrypted = ctx
            .encrypt_bytes("session-1", "metadata", br#"{"hello":"world"}"#)
            .unwrap();
        fs::write(dir.path().join("session-1.json"), &encrypted).unwrap();

        let manifest_path = dir.path().join(CRYPTO_MANIFEST_PATH);
        let mut manifest: Value =
            serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();
        manifest.as_object_mut().unwrap().remove("integrity");
        fs::write(
            &manifest_path,
            serde_json::to_vec_pretty(&manifest).unwrap(),
        )
        .unwrap();

        let backfilled = SessionCryptoContext::load_or_create(dir.path(), &key_material).unwrap();
        assert!(backfilled.manifest_integrity_valid());
        let decrypted = backfilled
            .decrypt_bytes("session-1", "metadata", &encrypted)
            .unwrap();
        assert_eq!(decrypted, br#"{"hello":"world"}"#);

        let manifest: Value = serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();
        let integrity = manifest
            .get("integrity")
            .and_then(Value::as_str)
            .expect("integrity tag backfilled");
        assert!(!integrity.is_empty());
    }

    #[test]
    fn test_crypto_context_backfill_waits_for_locked_metadata_file() {
        let dir = tempfile::tempdir().unwrap();
        let key_material = test_key_material();
        let ctx = SessionCryptoContext::load_or_create(dir.path(), &key_material).unwrap();
        let encrypted = ctx
            .encrypt_bytes("session-1", "metadata", br#"{"hello":"world"}"#)
            .unwrap();
        let session_path = dir.path().join("session-1.json");
        fs::write(&session_path, &encrypted).unwrap();

        let manifest_path = dir.path().join(CRYPTO_MANIFEST_PATH);
        let mut manifest: Value =
            serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();
        manifest.as_object_mut().unwrap().remove("integrity");
        fs::write(
            &manifest_path,
            serde_json::to_vec_pretty(&manifest).unwrap(),
        )
        .unwrap();

        let session_lock = FileLock::acquire(&session_path).unwrap();
        let base_path = dir.path().to_path_buf();
        let thread_key_material = key_material.clone();
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (result_tx, result_rx) = std::sync::mpsc::channel();
        let join = std::thread::spawn(move || {
            started_tx.send(()).unwrap();
            let result = SessionCryptoContext::load_or_create(&base_path, &thread_key_material)
                .map(|ctx| ctx.manifest_integrity_valid());
            result_tx.send(result).unwrap();
        });

        started_rx.recv().unwrap();
        assert!(result_rx.try_recv().is_err());

        drop(session_lock);

        let manifest_valid = result_rx.recv().unwrap().unwrap();
        join.join().unwrap();
        assert!(manifest_valid);
    }

    #[test]
    fn test_crypto_context_refuses_backfill_with_unverified_password() {
        let dir = tempfile::tempdir().unwrap();
        let key_material = test_key_material();
        let wrong_key_material = test_key_material();
        let ctx = SessionCryptoContext::load_or_create(dir.path(), &key_material).unwrap();
        let encrypted = ctx
            .encrypt_bytes("session-1", "metadata", br#"{"hello":"world"}"#)
            .unwrap();
        fs::write(dir.path().join("session-1.json"), &encrypted).unwrap();

        let manifest_path = dir.path().join(CRYPTO_MANIFEST_PATH);
        let mut manifest: Value =
            serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();
        manifest.as_object_mut().unwrap().remove("integrity");
        fs::write(
            &manifest_path,
            serde_json::to_vec_pretty(&manifest).unwrap(),
        )
        .unwrap();

        let wrong = SessionCryptoContext::load_or_create(dir.path(), &wrong_key_material).unwrap();
        assert!(!wrong.manifest_integrity_valid());
        assert_eq!(
            wrong
                .decrypt_bytes("session-1", "metadata", &encrypted)
                .unwrap_err(),
            SessionCryptoError::ManifestIntegrityFailed
        );

        let manifest_after_wrong: Value =
            serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();
        assert!(manifest_after_wrong.get("integrity").is_none());

        let repaired = SessionCryptoContext::load_or_create(dir.path(), &key_material).unwrap();
        assert!(repaired.manifest_integrity_valid());
        assert_eq!(
            repaired
                .decrypt_bytes("session-1", "metadata", &encrypted)
                .unwrap(),
            br#"{"hello":"world"}"#
        );
    }

    #[test]
    fn test_crypto_context_refuses_backfill_without_encrypted_artifacts() {
        let dir = tempfile::tempdir().unwrap();
        let key_material = test_key_material();
        let _ctx = SessionCryptoContext::load_or_create(dir.path(), &key_material).unwrap();

        let manifest_path = dir.path().join(CRYPTO_MANIFEST_PATH);
        let mut manifest: Value =
            serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();
        manifest.as_object_mut().unwrap().remove("integrity");
        fs::write(
            &manifest_path,
            serde_json::to_vec_pretty(&manifest).unwrap(),
        )
        .unwrap();

        let reopened = SessionCryptoContext::load_or_create(dir.path(), &key_material).unwrap();
        assert!(!reopened.manifest_integrity_valid());

        let manifest_after: Value =
            serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();
        assert!(manifest_after.get("integrity").is_none());
    }

    #[test]
    fn test_prefixed_encrypted_payload_detection_handles_truncated_envelope() {
        let dir = tempfile::tempdir().unwrap();
        let key_material = test_key_material();
        let ctx = SessionCryptoContext::load_or_create(dir.path(), &key_material).unwrap();
        let encrypted = ctx
            .encrypt_bytes("session-1", "history", br#"{"msg":"hello"}"#)
            .unwrap();
        let truncated = encrypted[..SESSION_ENCRYPTED_PREFIX_V1.len() + 8].to_vec();

        assert!(has_encrypted_payload_prefix(&truncated));
        assert!(!is_encrypted_payload(&truncated));
        assert!(matches!(
            ctx.decrypt_bytes("session-1", "history", &truncated),
            Err(SessionCryptoError::BadFormat(_))
        ));
    }

    #[test]
    fn test_decrypt_bytes_requires_encrypted_prefix() {
        let dir = tempfile::tempdir().unwrap();
        let key_material = test_key_material();
        let ctx = SessionCryptoContext::load_or_create(dir.path(), &key_material).unwrap();
        let encrypted = ctx
            .encrypt_bytes("session-1", "history", br#"{"msg":"hello"}"#)
            .unwrap();
        let unprefixed = encrypted[SESSION_ENCRYPTED_PREFIX_V1.len()..].to_vec();

        let err = ctx
            .decrypt_bytes("session-1", "history", &unprefixed)
            .unwrap_err();
        assert_eq!(
            err,
            SessionCryptoError::BadFormat("missing cse1: prefix".to_string())
        );
    }

    #[test]
    fn test_is_encrypted_payload_rejects_unprefixed_envelope_like_json() {
        let unprefixed = br#"{"format":"session-enc-v1","n":"abc","c":"def"}"#;

        assert!(!has_encrypted_payload_prefix(unprefixed));
        assert!(!is_encrypted_payload(unprefixed));
    }

    #[cfg(unix)]
    #[test]
    fn test_crypto_manifest_is_created_with_private_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let key_material = test_key_material();
        let _ctx = SessionCryptoContext::load_or_create(dir.path(), &key_material).unwrap();

        let mode = fs::metadata(dir.path().join(CRYPTO_MANIFEST_PATH))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }
}
