//! Session-at-rest encryption support.
//!
//! This module owns confidentiality for session artifacts:
//! - session metadata files
//! - session history JSONL lines
//! - session archive files

use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use hkdf::Hkdf;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use thiserror::Error;
use zeroize::Zeroizing;

use crate::crypto::{derive_key_argon2id, PasswordKdfError, PASSWORD_DERIVED_KEY_LEN};

const CRYPTO_MANIFEST_PATH: &str = ".crypto-manifest";
const CRYPTO_MANIFEST_VERSION: u32 = 1;
const CRYPTO_KDF_ID: &str = "argon2id-v2";
const SESSION_ENCRYPTED_FORMAT_V1: &str = "session-enc-v1";
const SESSION_ENCRYPTION_ROOT_TAG: &[u8] = b"carapace:session-encryption-root:v1";
const SESSION_ENCRYPTION_INFO_PREFIX: &[u8] = b"carapace:session-encryption-key:v1:";
const SESSION_INTEGRITY_INFO: &[u8] = b"carapace:session-integrity-hmac:v2";
const ROOT_SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;

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
    fs::rename(&temp_path, path)?;
    Ok(())
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
    let hk = Hkdf::<Sha256>::new(Some(SESSION_ENCRYPTION_ROOT_TAG), master_key);
    let mut out = [0u8; PASSWORD_DERIVED_KEY_LEN];
    hk.expand(info, &mut out)
        .map_err(|err| SessionCryptoError::KeyDerivation(err.to_string()))?;
    Ok(Zeroizing::new(out))
}

fn aad_bytes(session_id: &str, purpose: &str) -> Vec<u8> {
    format!("carapace:session:{purpose}:v1:{session_id}").into_bytes()
}

/// Root session-crypto context derived from the config password.
pub struct SessionCryptoContext {
    master_key: Zeroizing<[u8; PASSWORD_DERIVED_KEY_LEN]>,
    integrity_hmac_key: Zeroizing<[u8; 32]>,
}

impl fmt::Debug for SessionCryptoContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionCryptoContext")
            .field("master_key", &"[redacted]")
            .field("integrity_hmac_key", &"[redacted]")
            .finish()
    }
}

impl SessionCryptoContext {
    /// Load or create the session crypto manifest and derive the root key.
    pub fn load_or_create(base_path: &Path, password: &[u8]) -> Result<Self, SessionCryptoError> {
        fs::create_dir_all(base_path)?;
        let manifest_path = manifest_path(base_path);
        let manifest = if manifest_path.exists() {
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
            manifest
        } else {
            let mut salt = [0u8; ROOT_SALT_LEN];
            getrandom::fill(&mut salt)
                .map_err(|err| SessionCryptoError::RandomFailure(err.to_string()))?;
            let manifest = CryptoManifest {
                version: CRYPTO_MANIFEST_VERSION,
                kdf: CRYPTO_KDF_ID.to_string(),
                root_salt: BASE64.encode(salt),
            };
            write_manifest_atomic(&manifest_path, &manifest)?;
            manifest
        };

        let root_salt = decode_b64::<ROOT_SALT_LEN>("root_salt", &manifest.root_salt)?;
        let master_key =
            Zeroizing::new(derive_key_argon2id(password, &root_salt).map_err(map_kdf_error)?);
        let integrity_hmac_key = expand_hkdf(master_key.as_ref(), SESSION_INTEGRITY_INFO)?;

        Ok(Self {
            master_key,
            integrity_hmac_key,
        })
    }

    /// Derive a per-session encryption key for the given purpose.
    pub fn derive_session_key(
        &self,
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
        expand_hkdf(self.master_key.as_ref(), &info)
    }

    /// Derive the session-store-wide HMAC key rooted in the encryption master key.
    pub fn integrity_hmac_key(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        out.copy_from_slice(self.integrity_hmac_key.as_ref());
        out
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
        serde_json::to_vec(&envelope).map_err(Into::into)
    }

    pub fn decrypt_bytes(
        &self,
        session_id: &str,
        purpose: &str,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, SessionCryptoError> {
        let envelope: EncryptedEnvelope = serde_json::from_slice(ciphertext)?;
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
        let key = self.derive_session_key(session_id, purpose)?;
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

pub fn encrypted_payload(data: &[u8]) -> bool {
    serde_json::from_slice::<EncryptedEnvelope>(data)
        .map(|env| env.format == SESSION_ENCRYPTED_FORMAT_V1)
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert!(encrypted_payload(&encrypted));
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
        let err = wrong
            .decrypt_bytes("session-1", "history", &encrypted)
            .unwrap_err();
        assert_eq!(err, SessionCryptoError::DecryptionFailed);
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
