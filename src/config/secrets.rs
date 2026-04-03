//! Encrypted secrets-at-rest for configuration values.
//!
//! Provides AES-256-GCM encryption for storing sensitive configuration values
//! (API keys, tokens, etc.) in encrypted form on disk.
//!
//! Encrypted values use versioned envelopes:
//! - `enc:v1:BASE64_NONCE:BASE64_CIPHERTEXT:BASE64_SALT` for legacy PBKDF2
//! - `enc:v2:BASE64_NONCE:BASE64_CIPHERTEXT:BASE64_SALT` for current Argon2id

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::crypto::{
    derive_key_argon2id, derive_key_pbkdf2_sha256, PasswordKdfError, PASSWORD_DERIVED_KEY_LEN,
};

const ENC_PREFIX_V1: &str = "enc:v1:";
const ENC_PREFIX_V2: &str = "enc:v2:";

/// Salt length in bytes
const SALT_LEN: usize = 16;

/// AES-GCM nonce length in bytes (96-bit)
const NONCE_LEN: usize = 12;

/// Errors that can occur during secret encryption/decryption.
#[derive(Error, Debug, PartialEq)]
pub enum SecretError {
    #[error("Invalid encrypted format: {0}")]
    BadFormat(String),

    #[error("Base64 decode error in field '{field}': {message}")]
    Base64Decode { field: String, message: String },

    #[error("Decryption failed (wrong password or corrupted data)")]
    DecryptionFailed,

    #[error("Invalid nonce length: expected {expected}, got {got}")]
    InvalidNonceLength { expected: usize, got: usize },

    #[error("Invalid salt length: expected {expected}, got {got}")]
    InvalidSaltLength { expected: usize, got: usize },

    #[error("JSON pointer path not found: {0}")]
    PathNotFound(String),

    #[error("Random number generation failed: {0}")]
    RandomFailure(String),

    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),

    #[error("Key derivation failed: {0}")]
    KeyDerivationFailed(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SecretEnvelopeVersion {
    V1,
    V2,
}

impl SecretEnvelopeVersion {
    pub(crate) fn current() -> Self {
        Self::V2
    }

    pub(crate) fn prefix(self) -> &'static str {
        match self {
            Self::V1 => ENC_PREFIX_V1,
            Self::V2 => ENC_PREFIX_V2,
        }
    }

    pub(crate) fn parse_prefix(value: &str) -> Option<Self> {
        if value.starts_with(ENC_PREFIX_V1) {
            Some(Self::V1)
        } else if value.starts_with(ENC_PREFIX_V2) {
            Some(Self::V2)
        } else {
            None
        }
    }

    pub(crate) fn derive_key(
        self,
        password: &[u8],
        salt: &[u8; SALT_LEN],
    ) -> Result<[u8; PASSWORD_DERIVED_KEY_LEN], PasswordKdfError> {
        match self {
            Self::V1 => Ok(derive_key_pbkdf2_sha256(password, salt)),
            Self::V2 => derive_key_argon2id(password, salt),
        }
    }
}

/// Holds a derived AES-256 encryption key for encrypting/decrypting secrets.
///
/// The key is zeroized on drop to prevent leaking sensitive material.
pub struct SecretStore {
    /// The derived AES-256 key (32 bytes), wrapped in Zeroizing for secure cleanup
    key: Zeroizing<[u8; PASSWORD_DERIVED_KEY_LEN]>,
    /// The salt used to derive the key (stored so encrypt can embed it)
    salt: [u8; SALT_LEN],
    /// The envelope version used for new writes.
    write_version: SecretEnvelopeVersion,
    /// Whether this store may use its in-memory key for direct encrypt/decrypt.
    mode: SecretStoreMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SecretStoreMode {
    Full,
    DecryptOnly,
}

impl SecretStore {
    /// Create a new `SecretStore` by deriving a key from a password and a random salt.
    pub fn new(password: &[u8]) -> Result<Self, SecretError> {
        let mut salt = [0u8; SALT_LEN];
        getrandom::fill(&mut salt).map_err(|e| SecretError::RandomFailure(e.to_string()))?;
        let write_version = SecretEnvelopeVersion::current();
        let key = Zeroizing::new(
            write_version
                .derive_key(password, &salt)
                .map_err(map_kdf_error)?,
        );
        Ok(Self {
            key,
            salt,
            write_version,
            mode: SecretStoreMode::Full,
        })
    }

    /// Create a `SecretStore` from an existing password and salt.
    pub fn from_password_and_salt(
        password: &[u8],
        salt: &[u8; SALT_LEN],
    ) -> Result<Self, SecretError> {
        let write_version = SecretEnvelopeVersion::current();
        let key = Zeroizing::new(
            write_version
                .derive_key(password, salt)
                .map_err(map_kdf_error)?,
        );
        Ok(Self {
            key,
            salt: *salt,
            write_version,
            mode: SecretStoreMode::Full,
        })
    }

    /// Create a store for rekey-based decryption without random salt generation.
    ///
    /// Note: `decrypt()` will always fail for real ciphertexts because the
    /// stored salt is a deterministic sentinel and the key is a dummy
    /// placeholder; use `decrypt_rekey()` for actual decryption.
    pub fn for_decrypt(password: &[u8]) -> Self {
        let sentinel_salt = derive_decrypt_sentinel_salt(password);
        Self {
            // `for_decrypt` exists to support `decrypt_rekey` fallback paths.
            // Avoid paying the full current KDF cost or risking an allocation
            // failure here because this placeholder key is never used for
            // actual ciphertext decryption. `mode` guards the direct
            // encrypt/decrypt methods so this placeholder key cannot be used.
            key: Zeroizing::new([0u8; PASSWORD_DERIVED_KEY_LEN]),
            salt: sentinel_salt,
            write_version: SecretEnvelopeVersion::current(),
            mode: SecretStoreMode::DecryptOnly,
        }
    }

    /// Encrypt a plaintext string, returning the current `enc:v2:...` format.
    pub fn encrypt(&self, plaintext: &str) -> Result<String, SecretError> {
        if self.mode == SecretStoreMode::DecryptOnly {
            return Err(SecretError::EncryptionFailed(
                "decrypt-only secret store cannot encrypt".to_string(),
            ));
        }

        let mut nonce_bytes = [0u8; NONCE_LEN];
        getrandom::fill(&mut nonce_bytes).map_err(|e| SecretError::RandomFailure(e.to_string()))?;
        let nonce = Nonce::from_slice(&nonce_bytes);

        let cipher = Aes256Gcm::new(self.key.as_ref().into());
        let ciphertext = cipher
            .encrypt(nonce, plaintext.as_bytes())
            .map_err(|e| SecretError::EncryptionFailed(e.to_string()))?;

        let nonce_b64 = BASE64.encode(nonce_bytes);
        let ct_b64 = BASE64.encode(&ciphertext);
        let salt_b64 = BASE64.encode(self.salt);

        Ok(format!(
            "{}{}:{}:{}",
            self.write_version.prefix(),
            nonce_b64,
            ct_b64,
            salt_b64
        ))
    }

    /// Decrypt a supported `enc:v1:` or `enc:v2:` string back to plaintext
    /// when it matches this store's current salt and write version.
    pub fn decrypt(&self, encrypted: &str) -> Result<String, SecretError> {
        if self.mode == SecretStoreMode::DecryptOnly {
            return Err(SecretError::DecryptionFailed);
        }

        let parts = parse_encrypted(encrypted)?;

        if parts.version == self.write_version && parts.salt == self.salt {
            decrypt_with_key(&self.key, &parts.nonce, &parts.ciphertext)
        } else {
            Err(SecretError::DecryptionFailed)
        }
    }

    /// Decrypt using the password (re-derives the key from the embedded salt).
    /// This is the general-purpose decryption path.
    pub fn decrypt_rekey(&self, encrypted: &str, password: &[u8]) -> Result<String, SecretError> {
        let parts = parse_encrypted(encrypted)?;
        let key = Zeroizing::new(
            parts
                .version
                .derive_key(password, &parts.salt)
                .map_err(map_kdf_error)?,
        );
        decrypt_with_key(&key, &parts.nonce, &parts.ciphertext)
    }
}

/// Parsed components of an encrypted value.
pub(crate) struct EncryptedParts {
    /// The secret envelope version.
    pub(crate) version: SecretEnvelopeVersion,
    /// The AES-GCM nonce (96-bit)
    pub(crate) nonce: [u8; NONCE_LEN],
    /// The encrypted ciphertext bytes
    pub(crate) ciphertext: Vec<u8>,
    /// The password-KDF salt
    pub(crate) salt: [u8; SALT_LEN],
}

/// Parse a supported `enc:v1:NONCE:CIPHERTEXT:SALT` or
/// `enc:v2:NONCE:CIPHERTEXT:SALT` string into its components.
pub(crate) fn parse_encrypted(encrypted: &str) -> Result<EncryptedParts, SecretError> {
    let Some(version) = SecretEnvelopeVersion::parse_prefix(encrypted) else {
        let preview: String = encrypted.chars().take(10).collect();
        let message = if encrypted.starts_with("enc:v") {
            format!(
                "unsupported enc version; expected enc:v1 or enc:v2, got '{}'",
                preview
            )
        } else {
            format!("expected enc:v1 or enc:v2 prefix, got '{}'", preview)
        };
        return Err(SecretError::BadFormat(message));
    };

    let prefix = version.prefix();
    let rest = &encrypted[prefix.len()..];

    let segments: Vec<&str> = rest.splitn(3, ':').collect();
    if segments.len() != 3 {
        return Err(SecretError::BadFormat(format!(
            "expected 3 colon-separated segments after prefix, got {}",
            segments.len()
        )));
    }

    let nonce_bytes = BASE64
        .decode(segments[0])
        .map_err(|e| SecretError::Base64Decode {
            field: "nonce".to_string(),
            message: e.to_string(),
        })?;

    let ciphertext = BASE64
        .decode(segments[1])
        .map_err(|e| SecretError::Base64Decode {
            field: "ciphertext".to_string(),
            message: e.to_string(),
        })?;

    let salt_bytes = BASE64
        .decode(segments[2])
        .map_err(|e| SecretError::Base64Decode {
            field: "salt".to_string(),
            message: e.to_string(),
        })?;

    if nonce_bytes.len() != NONCE_LEN {
        return Err(SecretError::InvalidNonceLength {
            expected: NONCE_LEN,
            got: nonce_bytes.len(),
        });
    }

    if salt_bytes.len() != SALT_LEN {
        return Err(SecretError::InvalidSaltLength {
            expected: SALT_LEN,
            got: salt_bytes.len(),
        });
    }

    let nonce: [u8; NONCE_LEN] =
        nonce_bytes
            .as_slice()
            .try_into()
            .map_err(|_| SecretError::InvalidNonceLength {
                expected: NONCE_LEN,
                got: nonce_bytes.len(),
            })?;

    let salt: [u8; SALT_LEN] =
        salt_bytes
            .as_slice()
            .try_into()
            .map_err(|_| SecretError::InvalidSaltLength {
                expected: SALT_LEN,
                got: salt_bytes.len(),
            })?;

    Ok(EncryptedParts {
        version,
        nonce,
        ciphertext,
        salt,
    })
}

/// Decrypt ciphertext with a pre-derived key and nonce.
fn decrypt_with_key(
    key: &[u8; PASSWORD_DERIVED_KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    ciphertext: &[u8],
) -> Result<String, SecretError> {
    let cipher = Aes256Gcm::new(key.into());
    let nonce = Nonce::from_slice(nonce);

    let plaintext_bytes = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| SecretError::DecryptionFailed)?;

    String::from_utf8(plaintext_bytes).map_err(|_| SecretError::DecryptionFailed)
}

/// Derive a deterministic, non-random sentinel salt for password-only
/// decryption stores used in fallback/error paths.
fn derive_decrypt_sentinel_salt(password: &[u8]) -> [u8; SALT_LEN] {
    // Hash incrementally to avoid allocating an intermediate buffer that
    // copies password bytes.
    let mut hasher = Sha256::new();
    hasher.update(b"carapace:decrypt-sentinel:");
    hasher.update(password);
    let digest = hasher.finalize();
    let mut derived: [u8; SALT_LEN] = Default::default();
    derived.copy_from_slice(&digest[..SALT_LEN]);
    derived
}

fn map_kdf_error(error: PasswordKdfError) -> SecretError {
    SecretError::KeyDerivationFailed(error.to_string())
}

/// Check whether a string value is in encrypted format.
pub fn is_encrypted(value: &str) -> bool {
    SecretEnvelopeVersion::parse_prefix(value).is_some()
}

/// Maximum recursion depth for `resolve_secrets` to prevent stack overflow
/// on programmatically constructed JSON trees.
const MAX_RESOLVE_DEPTH: usize = 64;

/// Maximum recursion depth for config scans.
const MAX_SCAN_DEPTH: usize = 64;

/// Check if any values in the config tree are encrypted.
pub fn contains_encrypted_values(config: &Value) -> bool {
    contains_encrypted_inner(config, 0)
}

fn contains_encrypted_inner(config: &Value, depth: usize) -> bool {
    if depth > MAX_SCAN_DEPTH {
        tracing::warn!(
            "contains_encrypted_values: maximum recursion depth ({}) exceeded, stopping scan",
            MAX_SCAN_DEPTH
        );
        return false;
    }

    match config {
        Value::String(s) => is_encrypted(s),
        Value::Object(map) => map.values().any(|v| contains_encrypted_inner(v, depth + 1)),
        Value::Array(arr) => arr.iter().any(|v| contains_encrypted_inner(v, depth + 1)),
        _ => false,
    }
}

/// Replace encrypted values with nulls in-place.
pub fn scrub_encrypted_values(config: &mut Value) {
    scrub_encrypted_inner(config, 0);
}

fn scrub_encrypted_inner(config: &mut Value, depth: usize) {
    if depth > MAX_SCAN_DEPTH {
        tracing::warn!(
            "scrub_encrypted_values: maximum recursion depth ({}) exceeded, stopping scan",
            MAX_SCAN_DEPTH
        );
        return;
    }

    match config {
        Value::String(s) => {
            if is_encrypted(s) {
                *config = Value::Null;
            }
        }
        Value::Object(map) => {
            for (_, v) in map.iter_mut() {
                scrub_encrypted_inner(v, depth + 1);
            }
        }
        Value::Array(arr) => {
            for item in arr.iter_mut() {
                scrub_encrypted_inner(item, depth + 1);
            }
        }
        _ => {}
    }
}

/// Walk a JSON value tree and decrypt all supported `enc:v1:` / `enc:v2:`
/// strings in-place.
///
/// Uses the password to re-derive keys from embedded salts so that values
/// encrypted with different salts can all be resolved.
pub fn resolve_secrets(config: &mut Value, store: &SecretStore, password: &[u8]) {
    resolve_secrets_inner(config, store, password, 0);
}

/// Internal recursive implementation with depth tracking.
fn resolve_secrets_inner(config: &mut Value, store: &SecretStore, password: &[u8], depth: usize) {
    if depth > MAX_RESOLVE_DEPTH {
        tracing::warn!(
            "resolve_secrets: maximum recursion depth ({}) exceeded, skipping deeper nodes",
            MAX_RESOLVE_DEPTH
        );
        return;
    }

    match config {
        Value::String(s) => {
            if is_encrypted(s) {
                let encrypted = s.clone();
                let mut scrub = false;
                match store.decrypt_rekey(&encrypted, password) {
                    Ok(plaintext) => *s = plaintext,
                    Err(e) => {
                        tracing::warn!("Failed to decrypt config secret: {}", e);
                        scrub = true;
                    }
                }
                if scrub {
                    *config = Value::Null;
                }
            }
        }
        Value::Object(map) => {
            for (_, v) in map.iter_mut() {
                resolve_secrets_inner(v, store, password, depth + 1);
            }
        }
        Value::Array(arr) => {
            for item in arr.iter_mut() {
                resolve_secrets_inner(item, store, password, depth + 1);
            }
        }
        _ => {}
    }
}

/// Encrypt values at the specified JSON pointer paths.
///
/// Each path should be a JSON pointer (e.g., "/auth/apiKey").
/// Only string values are encrypted; non-string or missing paths are skipped
/// with a warning.
pub fn seal_secrets(
    config: &mut Value,
    store: &SecretStore,
    keys: &[&str],
) -> Result<(), SecretError> {
    for &path in keys {
        if let Some(val) = config.pointer_mut(path) {
            if let Value::String(s) = val {
                if !is_encrypted(s) {
                    *s = store.encrypt(s)?;
                }
            } else {
                tracing::warn!("seal_secrets: path '{}' is not a string, skipping", path);
            }
        } else {
            tracing::warn!("seal_secrets: path '{}' not found, skipping", path);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn random_password() -> Vec<u8> {
        let mut bytes = [0u8; 24];
        getrandom::fill(&mut bytes).expect("random password bytes");
        bytes.to_vec()
    }

    fn random_salt() -> [u8; SALT_LEN] {
        let mut bytes = [0u8; SALT_LEN];
        getrandom::fill(&mut bytes).expect("random salt bytes");
        bytes
    }

    fn random_password_different_from(reference: &[u8]) -> Vec<u8> {
        loop {
            let candidate = random_password();
            if candidate != reference {
                return candidate;
            }
        }
    }

    fn random_salt_different_from(reference: &[u8; SALT_LEN]) -> [u8; SALT_LEN] {
        loop {
            let candidate = random_salt();
            if &candidate != reference {
                return candidate;
            }
        }
    }

    fn new_test_store() -> SecretStore {
        let password = random_password();
        SecretStore::new(&password).expect("create test secret store")
    }

    fn derive_current_key(
        password: &[u8],
        salt: &[u8; SALT_LEN],
    ) -> [u8; PASSWORD_DERIVED_KEY_LEN] {
        SecretEnvelopeVersion::current()
            .derive_key(password, salt)
            .expect("current Argon2id parameters should stay valid")
    }

    fn encrypt_with_version(
        version: SecretEnvelopeVersion,
        password: &[u8],
        plaintext: &str,
    ) -> String {
        let salt = random_salt();
        let key = version
            .derive_key(password, &salt)
            .expect("test envelope key derivation should succeed");
        let mut nonce_bytes = [0u8; NONCE_LEN];
        getrandom::fill(&mut nonce_bytes).expect("random nonce");
        let cipher = Aes256Gcm::new((&key).into());
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce_bytes), plaintext.as_bytes())
            .expect("test encryption should succeed");
        format!(
            "{}{}:{}:{}",
            version.prefix(),
            BASE64.encode(nonce_bytes),
            BASE64.encode(ciphertext),
            BASE64.encode(salt)
        )
    }

    fn encrypt_with_raw_key_and_salt(
        version: SecretEnvelopeVersion,
        key: &[u8; PASSWORD_DERIVED_KEY_LEN],
        salt: &[u8; SALT_LEN],
        plaintext: &str,
    ) -> String {
        let mut nonce_bytes = [0u8; NONCE_LEN];
        getrandom::fill(&mut nonce_bytes).expect("random nonce");
        let cipher = Aes256Gcm::new(key.into());
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce_bytes), plaintext.as_bytes())
            .expect("test encryption should succeed");
        format!(
            "{}{}:{}:{}",
            version.prefix(),
            BASE64.encode(nonce_bytes),
            BASE64.encode(ciphertext),
            BASE64.encode(salt)
        )
    }

    #[test]
    fn test_derive_key_deterministic() {
        let password = random_password();
        let salt = random_salt();
        let k1 = derive_current_key(&password, &salt);
        let k2 = derive_current_key(&password, &salt);
        assert_eq!(k1, k2, "same password+salt must produce same key");
    }

    #[test]
    fn test_derive_key_different_passwords() {
        let salt = random_salt();
        let p1 = random_password();
        let p2 = random_password_different_from(&p1);
        let k1 = derive_current_key(&p1, &salt);
        let k2 = derive_current_key(&p2, &salt);
        assert_ne!(k1, k2, "different passwords must produce different keys");
    }

    #[test]
    fn test_derive_key_different_salts() {
        let password = random_password();
        let s1 = random_salt();
        let s2 = random_salt_different_from(&s1);
        let k1 = derive_current_key(&password, &s1);
        let k2 = derive_current_key(&password, &s2);
        assert_ne!(k1, k2, "different salts must produce different keys");
    }

    #[test]
    fn test_derive_key_length() {
        let password = random_password();
        let salt = random_salt();
        let key = derive_current_key(&password, &salt);
        assert_eq!(
            key.len(),
            PASSWORD_DERIVED_KEY_LEN,
            "key must be 256 bits (32 bytes)"
        );
    }

    #[test]
    fn test_encrypt_decrypt_round_trip() {
        let store = new_test_store();
        let plaintext = "sk-live-abc123xyz";
        let encrypted = store.encrypt(plaintext).unwrap();
        let decrypted = store.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_empty_string() {
        let store = new_test_store();
        let encrypted = store.encrypt("").unwrap();
        let decrypted = store.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, "");
    }

    #[test]
    fn test_encrypt_decrypt_unicode() {
        let store = new_test_store();
        let plaintext = "hello world with accents";
        let encrypted = store.encrypt(plaintext).unwrap();
        let decrypted = store.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_long_value() {
        let store = new_test_store();
        let plaintext: String = "A".repeat(10_000);
        let encrypted = store.encrypt(&plaintext).unwrap();
        let decrypted = store.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_produces_different_ciphertext() {
        let store = new_test_store();
        let plaintext = "same-value";
        let e1 = store.encrypt(plaintext).unwrap();
        let e2 = store.encrypt(plaintext).unwrap();
        assert_ne!(e1, e2, "each encryption should use a unique nonce");
        assert_eq!(store.decrypt(&e1).unwrap(), plaintext);
        assert_eq!(store.decrypt(&e2).unwrap(), plaintext);
    }

    #[test]
    fn test_encrypted_format() {
        let store = new_test_store();
        let encrypted = store.encrypt("test").unwrap();
        assert!(
            encrypted.starts_with("enc:v2:"),
            "must start with enc:v2: prefix"
        );
        let parts: Vec<&str> = encrypted.splitn(5, ':').collect();
        assert_eq!(parts.len(), 5, "format: enc:v2:NONCE:CT:SALT");
        assert_eq!(parts[0], "enc");
        assert_eq!(parts[1], "v2");
        assert!(
            BASE64.decode(parts[2]).is_ok(),
            "nonce must be valid base64"
        );
        assert!(
            BASE64.decode(parts[3]).is_ok(),
            "ciphertext must be valid base64"
        );
        assert!(BASE64.decode(parts[4]).is_ok(), "salt must be valid base64");
    }

    #[test]
    fn test_wrong_password_fails() {
        let correct_password = random_password();
        let store1 = SecretStore::new(&correct_password).unwrap();
        let encrypted = store1.encrypt("secret-data").unwrap();

        let parts = parse_encrypted(&encrypted).unwrap();
        let wrong_password = random_password_different_from(&correct_password);
        let wrong_key = Zeroizing::new(
            parts
                .version
                .derive_key(&wrong_password, &parts.salt)
                .expect("test key derivation should succeed"),
        );
        let result = decrypt_with_key(&wrong_key, &parts.nonce, &parts.ciphertext);
        assert_eq!(result, Err(SecretError::DecryptionFailed));
    }

    #[test]
    fn test_decrypt_rekey_wrong_password() {
        let correct_password = random_password();
        let store = SecretStore::new(&correct_password).unwrap();
        let encrypted = store.encrypt("secret-data").unwrap();
        let wrong_password = random_password_different_from(&correct_password);
        let result = store.decrypt_rekey(&encrypted, &wrong_password);
        assert_eq!(result, Err(SecretError::DecryptionFailed));
    }

    #[test]
    fn test_decrypt_rekey_correct_password() {
        let password = random_password();
        let store = SecretStore::new(&password).unwrap();
        let encrypted = store.encrypt("hello").unwrap();
        let decrypted = store.decrypt_rekey(&encrypted, &password).unwrap();
        assert_eq!(decrypted, "hello");
    }

    #[test]
    fn test_decrypt_rekey_legacy_v1_correct_password() {
        let password = random_password();
        let store = SecretStore::for_decrypt(&password);
        let encrypted = encrypt_with_version(SecretEnvelopeVersion::V1, &password, "hello-v1");
        let decrypted = store.decrypt_rekey(&encrypted, &password).unwrap();
        assert_eq!(decrypted, "hello-v1");
    }

    #[test]
    fn test_for_decrypt_store_rejects_direct_encrypt_and_decrypt() {
        let password = random_password();
        let store = SecretStore::for_decrypt(&password);

        let direct_encrypt = store.encrypt("hello");
        assert!(matches!(
            direct_encrypt,
            Err(SecretError::EncryptionFailed(message))
                if message.contains("decrypt-only")
        ));

        let crafted = encrypt_with_raw_key_and_salt(
            SecretEnvelopeVersion::current(),
            &[0u8; PASSWORD_DERIVED_KEY_LEN],
            &store.salt,
            "crafted",
        );
        assert_eq!(store.decrypt(&crafted), Err(SecretError::DecryptionFailed));
    }

    #[test]
    fn test_decrypt_rejects_legacy_v1_on_current_v2_store_even_with_matching_salt() {
        let password = random_password();
        let encrypted = encrypt_with_version(SecretEnvelopeVersion::V1, &password, "hello-v1");
        let parts = parse_encrypted(&encrypted).expect("parse v1 envelope");
        let current_store =
            SecretStore::from_password_and_salt(&password, &parts.salt).expect("current store");

        assert_eq!(
            current_store.decrypt(&encrypted),
            Err(SecretError::DecryptionFailed)
        );
    }

    #[test]
    fn test_corrupted_ciphertext() {
        let store = new_test_store();
        let encrypted = store.encrypt("test").unwrap();

        let parts: Vec<&str> = encrypted.splitn(5, ':').collect();
        let mut ct_bytes = BASE64.decode(parts[3]).unwrap();
        if !ct_bytes.is_empty() {
            ct_bytes[0] ^= 0xFF;
        }
        let corrupted = format!(
            "enc:{}:{}:{}:{}",
            parts[1],
            parts[2],
            BASE64.encode(&ct_bytes),
            parts[4]
        );

        let result = store.decrypt(&corrupted);
        assert_eq!(result, Err(SecretError::DecryptionFailed));
    }

    #[test]
    fn test_corrupted_nonce() {
        let store = new_test_store();
        let encrypted = store.encrypt("test").unwrap();

        let parts: Vec<&str> = encrypted.splitn(5, ':').collect();
        let mut nonce_bytes = BASE64.decode(parts[2]).unwrap();
        nonce_bytes[0] ^= 0xFF;
        let corrupted = format!(
            "enc:{}:{}:{}:{}",
            parts[1],
            BASE64.encode(&nonce_bytes),
            parts[3],
            parts[4]
        );

        let result = store.decrypt(&corrupted);
        assert_eq!(result, Err(SecretError::DecryptionFailed));
    }

    #[test]
    fn test_bad_format_no_prefix() {
        let store = new_test_store();
        let result = store.decrypt("not-encrypted-at-all");
        assert!(matches!(result, Err(SecretError::BadFormat(_))));
    }

    #[test]
    fn test_bad_format_unsupported_version() {
        let store = new_test_store();
        let result = store.decrypt("enc:v3:aaa:bbb:ccc");
        assert!(matches!(
            result,
            Err(SecretError::BadFormat(message))
                if message.contains("unsupported enc version")
        ));
    }

    #[test]
    fn test_bad_format_missing_segments() {
        let store = new_test_store();
        let result = store.decrypt("enc:v2:onlyone");
        assert!(matches!(result, Err(SecretError::BadFormat(_))));
    }

    #[test]
    fn test_bad_format_invalid_base64_nonce() {
        let store = new_test_store();
        let salt_b64 = BASE64.encode(random_salt());
        let ct_b64 = BASE64.encode(random_password());
        let bad = format!("enc:v2:not+valid+b64!:{}:{}", ct_b64, salt_b64);
        let result = store.decrypt(&bad);
        assert!(matches!(result, Err(SecretError::Base64Decode { .. })));
    }

    #[test]
    fn test_bad_format_invalid_base64_ciphertext() {
        let store = new_test_store();
        let mut nonce = [0u8; NONCE_LEN];
        getrandom::fill(&mut nonce).unwrap();
        let nonce_b64 = BASE64.encode(nonce);
        let salt_b64 = BASE64.encode(random_salt());
        let bad = format!("enc:v2:{}:not+valid+b64!:{}", nonce_b64, salt_b64);
        let result = store.decrypt(&bad);
        assert!(matches!(result, Err(SecretError::Base64Decode { .. })));
    }

    #[test]
    fn test_bad_format_wrong_nonce_length() {
        let store = new_test_store();
        let mut nonce = [0u8; 8];
        getrandom::fill(&mut nonce).unwrap();
        let nonce_b64 = BASE64.encode(nonce);
        let ct_b64 = BASE64.encode(random_password());
        let salt_b64 = BASE64.encode(random_salt());
        let bad = format!("enc:v2:{}:{}:{}", nonce_b64, ct_b64, salt_b64);
        let result = store.decrypt(&bad);
        assert!(matches!(
            result,
            Err(SecretError::InvalidNonceLength {
                expected: 12,
                got: 8
            })
        ));
    }

    #[test]
    fn test_bad_format_wrong_salt_length() {
        let store = new_test_store();
        let mut nonce = [0u8; NONCE_LEN];
        getrandom::fill(&mut nonce).unwrap();
        let nonce_b64 = BASE64.encode(nonce);
        let ct_b64 = BASE64.encode(random_password());
        let mut short_salt = [0u8; 8];
        getrandom::fill(&mut short_salt).unwrap();
        let salt_b64 = BASE64.encode(short_salt);
        let bad = format!("enc:v2:{}:{}:{}", nonce_b64, ct_b64, salt_b64);
        let result = store.decrypt(&bad);
        assert!(matches!(
            result,
            Err(SecretError::InvalidSaltLength {
                expected: 16,
                got: 8
            })
        ));
    }

    #[test]
    fn test_is_encrypted_true() {
        assert!(is_encrypted("enc:v1:abc:def:ghi"));
        assert!(is_encrypted("enc:v2:abc:def:ghi"));
    }

    #[test]
    fn test_is_encrypted_false() {
        assert!(!is_encrypted("plain-text-value"));
        assert!(!is_encrypted(""));
        assert!(!is_encrypted("enc:v3:abc:def:ghi"));
        assert!(!is_encrypted("ENC:V1:abc:def:ghi"));
    }

    #[test]
    fn test_resolve_secrets_flat_config() {
        let password = random_password();
        let store = SecretStore::new(&password).unwrap();
        let encrypted = store.encrypt("my-api-key").unwrap();

        let mut config = json!({
            "name": "bot",
            "apiKey": encrypted,
            "port": 8080
        });

        resolve_secrets(&mut config, &store, &password);

        assert_eq!(config["apiKey"], "my-api-key");
        assert_eq!(config["name"], "bot");
        assert_eq!(config["port"], 8080);
    }

    #[test]
    fn test_resolve_secrets_nested_config() {
        let password = random_password();
        let store = SecretStore::new(&password).unwrap();
        let enc_key = store.encrypt("sk-secret").unwrap();
        let enc_token = store.encrypt("tok-12345").unwrap();

        let mut config = json!({
            "auth": {
                "provider": "openai",
                "apiKey": enc_key,
                "nested": {
                    "token": enc_token
                }
            },
            "name": "bot"
        });

        resolve_secrets(&mut config, &store, &password);

        assert_eq!(config["auth"]["apiKey"], "sk-secret");
        assert_eq!(config["auth"]["nested"]["token"], "tok-12345");
        assert_eq!(config["auth"]["provider"], "openai");
        assert_eq!(config["name"], "bot");
    }

    #[test]
    fn test_resolve_secrets_in_arrays() {
        let password = random_password();
        let store = SecretStore::new(&password).unwrap();
        let enc1 = store.encrypt("secret1").unwrap();
        let enc2 = store.encrypt("secret2").unwrap();

        let mut config = json!({
            "keys": [enc1, "plain", enc2]
        });

        resolve_secrets(&mut config, &store, &password);

        assert_eq!(config["keys"][0], "secret1");
        assert_eq!(config["keys"][1], "plain");
        assert_eq!(config["keys"][2], "secret2");
    }

    #[test]
    fn test_resolve_secrets_skips_non_encrypted() {
        let password = random_password();
        let store = SecretStore::new(&password).unwrap();

        let mut config = json!({
            "name": "bot",
            "port": 8080,
            "enabled": true,
            "tags": ["a", "b"]
        });

        let original = config.clone();
        resolve_secrets(&mut config, &store, &password);

        assert_eq!(config, original, "non-encrypted values should be untouched");
    }

    #[test]
    fn test_resolve_secrets_bad_password_scrubs_value() {
        let correct_password = random_password();
        let store = SecretStore::new(&correct_password).unwrap();
        let encrypted = store.encrypt("super-secret").unwrap();

        let mut config = json!({ "apiKey": encrypted });
        let wrong_password = random_password_different_from(&correct_password);
        let wrong_store = SecretStore::for_decrypt(&wrong_password);

        resolve_secrets(&mut config, &wrong_store, &wrong_password);

        assert!(
            config["apiKey"].is_null(),
            "bad password should scrub secrets"
        );
    }

    #[test]
    fn test_scrub_encrypted_values_replaces_with_null() {
        let store = new_test_store();
        let encrypted = store.encrypt("secret").unwrap();

        let mut config = json!({ "apiKey": encrypted, "name": "bot" });
        scrub_encrypted_values(&mut config);

        assert!(config["apiKey"].is_null());
        assert_eq!(config["name"], "bot");
    }

    #[test]
    fn test_seal_secrets_single_path() {
        let store = new_test_store();
        let mut config = json!({
            "auth": {
                "apiKey": "sk-live-abc123"
            }
        });

        seal_secrets(&mut config, &store, &["/auth/apiKey"]).unwrap();

        let sealed = config["auth"]["apiKey"].as_str().unwrap();
        assert!(is_encrypted(sealed), "value should be encrypted");
        assert_eq!(store.decrypt(sealed).unwrap(), "sk-live-abc123");
    }

    #[test]
    fn test_seal_secrets_multiple_paths() {
        let store = new_test_store();
        let mut config = json!({
            "auth": { "apiKey": "key1" },
            "db": { "password": "dbpass" }
        });

        seal_secrets(&mut config, &store, &["/auth/apiKey", "/db/password"]).unwrap();

        assert!(is_encrypted(config["auth"]["apiKey"].as_str().unwrap()));
        assert!(is_encrypted(config["db"]["password"].as_str().unwrap()));
    }

    #[test]
    fn test_seal_secrets_skips_already_encrypted() {
        let store = new_test_store();
        let already_encrypted = store.encrypt("secret").unwrap();

        let mut config = json!({
            "key": already_encrypted.clone()
        });

        seal_secrets(&mut config, &store, &["/key"]).unwrap();

        assert_eq!(
            config["key"].as_str().unwrap(),
            &already_encrypted,
            "already-encrypted value should not be re-encrypted"
        );
    }

    #[test]
    fn test_seal_secrets_missing_path_is_noop() {
        let store = new_test_store();
        let mut config = json!({ "a": 1 });
        let original = config.clone();

        seal_secrets(&mut config, &store, &["/nonexistent/path"]).unwrap();

        assert_eq!(config, original, "missing path should be a no-op");
    }

    #[test]
    fn test_seal_secrets_non_string_is_noop() {
        let store = new_test_store();
        let mut config = json!({ "port": 8080 });
        let original = config.clone();

        seal_secrets(&mut config, &store, &["/port"]).unwrap();

        assert_eq!(config, original, "non-string path should be a no-op");
    }

    #[test]
    fn test_seal_then_resolve_round_trip() {
        let password = random_password();
        let store = SecretStore::new(&password).unwrap();

        let mut config = json!({
            "auth": {
                "provider": "anthropic",
                "apiKey": "sk-ant-test123",
                "webhook": {
                    "secret": "whsec_abc"
                }
            },
            "db": {
                "connectionString": "postgres://user:pass@host/db"
            },
            "name": "mybot"
        });

        let paths = &[
            "/auth/apiKey",
            "/auth/webhook/secret",
            "/db/connectionString",
        ];

        seal_secrets(&mut config, &store, paths).unwrap();

        assert!(is_encrypted(config["auth"]["apiKey"].as_str().unwrap()));
        assert!(is_encrypted(
            config["auth"]["webhook"]["secret"].as_str().unwrap()
        ));
        assert!(is_encrypted(
            config["db"]["connectionString"].as_str().unwrap()
        ));
        assert_eq!(config["auth"]["provider"], "anthropic");
        assert_eq!(config["name"], "mybot");

        resolve_secrets(&mut config, &store, &password);

        assert_eq!(config["auth"]["apiKey"], "sk-ant-test123");
        assert_eq!(config["auth"]["webhook"]["secret"], "whsec_abc");
        assert_eq!(
            config["db"]["connectionString"],
            "postgres://user:pass@host/db"
        );
        assert_eq!(config["auth"]["provider"], "anthropic");
        assert_eq!(config["name"], "mybot");
    }

    #[test]
    fn test_from_password_and_salt() {
        let password = random_password();
        let salt = random_salt();
        let store = SecretStore::from_password_and_salt(&password, &salt).unwrap();
        let encrypted = store.encrypt("hello").unwrap();
        let decrypted = store.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, "hello");
    }

    #[test]
    fn test_store_new_generates_random_salt() {
        let s1 = new_test_store();
        let s2 = new_test_store();
        assert_ne!(s1.salt, s2.salt, "each store should have a unique salt");
    }

    #[test]
    fn test_encrypt_decrypt_special_characters() {
        let store = new_test_store();
        let plaintext = "p@w0rd!#%^&*()_+-=[]{}|;':,./<>?~";
        let encrypted = store.encrypt(plaintext).unwrap();
        let decrypted = store.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_newlines() {
        let store = new_test_store();
        let plaintext = "line1\nline2\nline3\ttab";
        let encrypted = store.encrypt(plaintext).unwrap();
        let decrypted = store.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_json_string() {
        let store = new_test_store();
        let plaintext = r#"{"key": "value", "nested": {"a": 1}}"#;
        let encrypted = store.encrypt(plaintext).unwrap();
        let decrypted = store.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_pbkdf2_known_vector() {
        let passphrase = sha2::Sha256::digest(b"carapace-secret-v1-kat-passphrase");
        let salt = sha2::Sha256::digest(b"carapace-secret-v1-kat-salt");
        // Expected output generated independently via Python hashlib.pbkdf2_hmac:
        // python3 -c 'import hashlib; p=hashlib.sha256(b"carapace-secret-v1-kat-passphrase").digest(); s=hashlib.sha256(b"carapace-secret-v1-kat-salt").digest()[:16]; print(hashlib.pbkdf2_hmac("sha256", p, s, 600000, 32).hex())'
        let expected = "fba539b769b63cfb5a65da14de9267f70c7fa022345df609c146231d5668f5a6";
        let salt_bytes: &[u8; SALT_LEN] = (&salt[..SALT_LEN]).try_into().unwrap();
        let key = derive_key_pbkdf2_sha256(passphrase.as_slice(), salt_bytes);
        assert_eq!(hex::encode(key), expected);
        let key2 = derive_key_pbkdf2_sha256(passphrase.as_slice(), salt_bytes);
        assert_eq!(key, key2, "PBKDF2 must be deterministic");
    }

    #[test]
    fn test_current_argon2id_known_answer_vector() {
        let passphrase = sha2::Sha256::digest(b"carapace-secret-kat-passphrase");
        let salt = sha2::Sha256::digest(b"carapace-secret-kat-salt");
        // Expected output generated independently via Python argon2-cffi:
        // python3 -c 'import hashlib; from argon2.low_level import hash_secret_raw, Type; p=hashlib.sha256(b"carapace-secret-kat-passphrase").digest(); s=hashlib.sha256(b"carapace-secret-kat-salt").digest()[:16]; print(hash_secret_raw(p, s, time_cost=3, memory_cost=64*1024, parallelism=1, hash_len=32, type=Type.ID, version=19).hex())'
        let expected_hex = "1e5f1e8521e6e00542bf00a0bfea29f962b9ebab0796548d79492b83b4e445ee";
        let key = derive_current_key(
            passphrase.as_slice(),
            (&salt[..SALT_LEN]).try_into().unwrap(),
        );
        assert_eq!(hex::encode(key), expected_hex);
    }

    #[test]
    fn test_argon2id_current_key_differs_from_legacy_pbkdf2() {
        let password = random_password();
        let salt = random_salt();
        let legacy = derive_key_pbkdf2_sha256(&password, &salt);
        let current = derive_current_key(&password, &salt);
        assert_ne!(
            legacy, current,
            "legacy PBKDF2 and current Argon2id derivation must not alias"
        );
    }

    #[test]
    fn test_contains_encrypted_values_detects_ciphertext() {
        let store = new_test_store();
        let encrypted = store.encrypt("secret").unwrap();

        let config = json!({ "apiKey": encrypted, "name": "bot" });
        assert!(contains_encrypted_values(&config));

        let plain = json!({ "apiKey": "plaintext", "name": "bot" });
        assert!(!contains_encrypted_values(&plain));
    }
}
