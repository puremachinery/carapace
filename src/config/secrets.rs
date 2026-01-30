//! Encrypted secrets-at-rest for configuration values.
//!
//! Provides AES-256-GCM encryption with PBKDF2-HMAC-SHA256 key derivation
//! for storing sensitive configuration values (API keys, tokens, etc.)
//! in encrypted form on disk.
//!
//! Encrypted values use the format: `enc:v1:BASE64_NONCE:BASE64_CIPHERTEXT:BASE64_SALT`

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use hmac::Hmac;
use serde_json::Value;
use sha2::Sha256;
use thiserror::Error;
use zeroize::Zeroizing;

/// Prefix identifying encrypted values
const ENC_PREFIX: &str = "enc:v1:";

/// Number of PBKDF2 iterations (OWASP recommendation for HMAC-SHA256)
const PBKDF2_ITERATIONS: u32 = 600_000;

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
}

/// Holds a derived AES-256 encryption key for encrypting/decrypting secrets.
///
/// The key is zeroized on drop to prevent leaking sensitive material.
pub struct SecretStore {
    /// The derived AES-256 key (32 bytes), wrapped in Zeroizing for secure cleanup
    key: Zeroizing<[u8; 32]>,
    /// The salt used to derive the key (stored so encrypt can embed it)
    salt: [u8; SALT_LEN],
}

impl SecretStore {
    /// Create a new `SecretStore` by deriving a key from a password and a random salt.
    pub fn new(password: &[u8]) -> Result<Self, SecretError> {
        let mut salt = [0u8; SALT_LEN];
        getrandom::getrandom(&mut salt).map_err(|e| SecretError::RandomFailure(e.to_string()))?;
        let key = Zeroizing::new(derive_key(password, &salt));
        Ok(Self { key, salt })
    }

    /// Create a `SecretStore` from an existing password and salt.
    pub fn from_password_and_salt(password: &[u8], salt: &[u8; SALT_LEN]) -> Self {
        let key = Zeroizing::new(derive_key(password, salt));
        Self { key, salt: *salt }
    }

    /// Encrypt a plaintext string, returning the `enc:v1:...` formatted string.
    pub fn encrypt(&self, plaintext: &str) -> Result<String, SecretError> {
        let mut nonce_bytes = [0u8; NONCE_LEN];
        getrandom::getrandom(&mut nonce_bytes)
            .map_err(|e| SecretError::RandomFailure(e.to_string()))?;
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
            ENC_PREFIX, nonce_b64, ct_b64, salt_b64
        ))
    }

    /// Decrypt an `enc:v1:...` formatted string back to plaintext.
    pub fn decrypt(&self, encrypted: &str) -> Result<String, SecretError> {
        let parts = parse_encrypted(encrypted)?;

        if parts.salt == self.salt {
            decrypt_with_key(&self.key, &parts.nonce, &parts.ciphertext)
        } else {
            Err(SecretError::DecryptionFailed)
        }
    }

    /// Decrypt using the password (re-derives the key from the embedded salt).
    /// This is the general-purpose decryption path.
    pub fn decrypt_rekey(&self, encrypted: &str, password: &[u8]) -> Result<String, SecretError> {
        let parts = parse_encrypted(encrypted)?;
        let key = Zeroizing::new(derive_key(password, &parts.salt));
        decrypt_with_key(&key, &parts.nonce, &parts.ciphertext)
    }
}

/// Parsed components of an encrypted value.
pub(crate) struct EncryptedParts {
    /// The AES-GCM nonce (96-bit)
    pub(crate) nonce: [u8; NONCE_LEN],
    /// The encrypted ciphertext bytes
    pub(crate) ciphertext: Vec<u8>,
    /// The PBKDF2 salt
    pub(crate) salt: [u8; SALT_LEN],
}

/// Parse an `enc:v1:NONCE:CIPHERTEXT:SALT` string into its components.
pub(crate) fn parse_encrypted(encrypted: &str) -> Result<EncryptedParts, SecretError> {
    let rest = encrypted.strip_prefix(ENC_PREFIX).ok_or_else(|| {
        let preview: String = encrypted.chars().take(10).collect();
        SecretError::BadFormat(format!("expected prefix, got '{}'", preview))
    })?;

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

    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&nonce_bytes);

    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&salt_bytes);

    Ok(EncryptedParts {
        nonce,
        ciphertext,
        salt,
    })
}

/// Decrypt ciphertext with a pre-derived key and nonce.
fn decrypt_with_key(
    key: &[u8; 32],
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

/// Derive a 256-bit key from a password and salt using PBKDF2-HMAC-SHA256.
///
/// Uses 600,000 iterations per OWASP recommendations.
pub fn derive_key(password: &[u8], salt: &[u8]) -> [u8; 32] {
    pbkdf2_hmac_sha256(password, salt, PBKDF2_ITERATIONS)
}

/// PBKDF2-HMAC-SHA256 implementation (RFC 8018 section 5.2).
///
/// `dk_len` is fixed at 32 bytes (one block for SHA-256) so we only
/// need a single iteration of the outer loop.
fn pbkdf2_hmac_sha256(password: &[u8], salt: &[u8], iterations: u32) -> [u8; 32] {
    use hmac::Mac;

    type HmacSha256 = Hmac<Sha256>;

    let mut mac =
        <HmacSha256 as hmac::Mac>::new_from_slice(password).expect("HMAC can take key of any size");
    mac.update(salt);
    mac.update(&1u32.to_be_bytes());
    let u1 = mac.finalize().into_bytes();

    let mut result = [0u8; 32];
    result.copy_from_slice(&u1);

    let mut u_prev = u1;

    for _ in 1..iterations {
        let mut mac = <HmacSha256 as hmac::Mac>::new_from_slice(password)
            .expect("HMAC can take key of any size");
        mac.update(&u_prev);
        let u_i = mac.finalize().into_bytes();

        for (r, u) in result.iter_mut().zip(u_i.iter()) {
            *r ^= u;
        }

        u_prev = u_i;
    }

    result
}

/// Check whether a string value is in encrypted format.
pub fn is_encrypted(value: &str) -> bool {
    value.starts_with(ENC_PREFIX)
}

/// Maximum recursion depth for `resolve_secrets` to prevent stack overflow
/// on programmatically constructed JSON trees.
const MAX_RESOLVE_DEPTH: usize = 64;

/// Walk a JSON value tree and decrypt all `enc:v1:` strings in-place.
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
                match store.decrypt_rekey(s, password) {
                    Ok(plaintext) => *s = plaintext,
                    Err(e) => {
                        tracing::warn!("Failed to decrypt config secret: {}", e);
                    }
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

    #[test]
    fn test_derive_key_deterministic() {
        let password = b"hunter2";
        let salt = b"1234567890abcdef";
        let k1 = derive_key(password, salt);
        let k2 = derive_key(password, salt);
        assert_eq!(k1, k2, "same password+salt must produce same key");
    }

    #[test]
    fn test_derive_key_different_passwords() {
        let salt = b"1234567890abcdef";
        let k1 = derive_key(b"password1", salt);
        let k2 = derive_key(b"password2", salt);
        assert_ne!(k1, k2, "different passwords must produce different keys");
    }

    #[test]
    fn test_derive_key_different_salts() {
        let password = b"password";
        let k1 = derive_key(password, b"salt_aaaaaaaaaaaa");
        let k2 = derive_key(password, b"salt_bbbbbbbbbbbb");
        assert_ne!(k1, k2, "different salts must produce different keys");
    }

    #[test]
    fn test_derive_key_length() {
        let key = derive_key(b"pass", b"saltsaltsaltsalt");
        assert_eq!(key.len(), 32, "key must be 256 bits (32 bytes)");
    }

    #[test]
    fn test_encrypt_decrypt_round_trip() {
        let store = SecretStore::new(b"my-secret-password").unwrap();
        let plaintext = "sk-live-abc123xyz";
        let encrypted = store.encrypt(plaintext).unwrap();
        let decrypted = store.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_empty_string() {
        let store = SecretStore::new(b"password").unwrap();
        let encrypted = store.encrypt("").unwrap();
        let decrypted = store.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, "");
    }

    #[test]
    fn test_encrypt_decrypt_unicode() {
        let store = SecretStore::new(b"password").unwrap();
        let plaintext = "hello world with accents";
        let encrypted = store.encrypt(plaintext).unwrap();
        let decrypted = store.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_long_value() {
        let store = SecretStore::new(b"password").unwrap();
        let plaintext: String = "A".repeat(10_000);
        let encrypted = store.encrypt(&plaintext).unwrap();
        let decrypted = store.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_produces_different_ciphertext() {
        let store = SecretStore::new(b"password").unwrap();
        let plaintext = "same-value";
        let e1 = store.encrypt(plaintext).unwrap();
        let e2 = store.encrypt(plaintext).unwrap();
        assert_ne!(e1, e2, "each encryption should use a unique nonce");
        assert_eq!(store.decrypt(&e1).unwrap(), plaintext);
        assert_eq!(store.decrypt(&e2).unwrap(), plaintext);
    }

    #[test]
    fn test_encrypted_format() {
        let store = SecretStore::new(b"password").unwrap();
        let encrypted = store.encrypt("test").unwrap();
        assert!(
            encrypted.starts_with("enc:v1:"),
            "must start with enc:v1: prefix"
        );
        let parts: Vec<&str> = encrypted.splitn(5, ':').collect();
        assert_eq!(parts.len(), 5, "format: enc:v1:NONCE:CT:SALT");
        assert_eq!(parts[0], "enc");
        assert_eq!(parts[1], "v1");
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
        let store1 = SecretStore::new(b"correct-password").unwrap();
        let encrypted = store1.encrypt("secret-data").unwrap();

        let parts = parse_encrypted(&encrypted).unwrap();
        let wrong_key = Zeroizing::new(derive_key(b"wrong-password", &parts.salt));
        let result = decrypt_with_key(&wrong_key, &parts.nonce, &parts.ciphertext);
        assert_eq!(result, Err(SecretError::DecryptionFailed));
    }

    #[test]
    fn test_decrypt_rekey_wrong_password() {
        let store = SecretStore::new(b"correct-password").unwrap();
        let encrypted = store.encrypt("secret-data").unwrap();
        let result = store.decrypt_rekey(&encrypted, b"wrong-password");
        assert_eq!(result, Err(SecretError::DecryptionFailed));
    }

    #[test]
    fn test_decrypt_rekey_correct_password() {
        let store = SecretStore::new(b"my-password").unwrap();
        let encrypted = store.encrypt("hello").unwrap();
        let decrypted = store.decrypt_rekey(&encrypted, b"my-password").unwrap();
        assert_eq!(decrypted, "hello");
    }

    #[test]
    fn test_corrupted_ciphertext() {
        let store = SecretStore::new(b"password").unwrap();
        let encrypted = store.encrypt("test").unwrap();

        let parts: Vec<&str> = encrypted.splitn(5, ':').collect();
        let mut ct_bytes = BASE64.decode(parts[3]).unwrap();
        if !ct_bytes.is_empty() {
            ct_bytes[0] ^= 0xFF;
        }
        let corrupted = format!(
            "enc:v1:{}:{}:{}",
            parts[2],
            BASE64.encode(&ct_bytes),
            parts[4]
        );

        let result = store.decrypt(&corrupted);
        assert_eq!(result, Err(SecretError::DecryptionFailed));
    }

    #[test]
    fn test_corrupted_nonce() {
        let store = SecretStore::new(b"password").unwrap();
        let encrypted = store.encrypt("test").unwrap();

        let parts: Vec<&str> = encrypted.splitn(5, ':').collect();
        let mut nonce_bytes = BASE64.decode(parts[2]).unwrap();
        nonce_bytes[0] ^= 0xFF;
        let corrupted = format!(
            "enc:v1:{}:{}:{}",
            BASE64.encode(&nonce_bytes),
            parts[3],
            parts[4]
        );

        let result = store.decrypt(&corrupted);
        assert_eq!(result, Err(SecretError::DecryptionFailed));
    }

    #[test]
    fn test_bad_format_no_prefix() {
        let store = SecretStore::new(b"password").unwrap();
        let result = store.decrypt("not-encrypted-at-all");
        assert!(matches!(result, Err(SecretError::BadFormat(_))));
    }

    #[test]
    fn test_bad_format_wrong_prefix() {
        let store = SecretStore::new(b"password").unwrap();
        let result = store.decrypt("enc:v2:aaa:bbb:ccc");
        assert!(matches!(result, Err(SecretError::BadFormat(_))));
    }

    #[test]
    fn test_bad_format_missing_segments() {
        let store = SecretStore::new(b"password").unwrap();
        let result = store.decrypt("enc:v1:onlyone");
        assert!(matches!(result, Err(SecretError::BadFormat(_))));
    }

    #[test]
    fn test_bad_format_invalid_base64_nonce() {
        let store = SecretStore::new(b"password").unwrap();
        let salt_b64 = BASE64.encode([0u8; SALT_LEN]);
        let ct_b64 = BASE64.encode(b"ciphertext");
        let bad = format!("enc:v1:not+valid+b64!:{}:{}", ct_b64, salt_b64);
        let result = store.decrypt(&bad);
        assert!(matches!(result, Err(SecretError::Base64Decode { .. })));
    }

    #[test]
    fn test_bad_format_invalid_base64_ciphertext() {
        let store = SecretStore::new(b"password").unwrap();
        let nonce_b64 = BASE64.encode([0u8; NONCE_LEN]);
        let salt_b64 = BASE64.encode([0u8; SALT_LEN]);
        let bad = format!("enc:v1:{}:not+valid+b64!:{}", nonce_b64, salt_b64);
        let result = store.decrypt(&bad);
        assert!(matches!(result, Err(SecretError::Base64Decode { .. })));
    }

    #[test]
    fn test_bad_format_wrong_nonce_length() {
        let store = SecretStore::new(b"password").unwrap();
        let nonce_b64 = BASE64.encode([0u8; 8]);
        let ct_b64 = BASE64.encode(b"ciphertext");
        let salt_b64 = BASE64.encode([0u8; SALT_LEN]);
        let bad = format!("enc:v1:{}:{}:{}", nonce_b64, ct_b64, salt_b64);
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
        let store = SecretStore::new(b"password").unwrap();
        let nonce_b64 = BASE64.encode([0u8; NONCE_LEN]);
        let ct_b64 = BASE64.encode(b"ciphertext");
        let salt_b64 = BASE64.encode([0u8; 8]);
        let bad = format!("enc:v1:{}:{}:{}", nonce_b64, ct_b64, salt_b64);
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
    }

    #[test]
    fn test_is_encrypted_false() {
        assert!(!is_encrypted("plain-text-value"));
        assert!(!is_encrypted(""));
        assert!(!is_encrypted("enc:v2:abc:def:ghi"));
        assert!(!is_encrypted("ENC:V1:abc:def:ghi"));
    }

    #[test]
    fn test_resolve_secrets_flat_config() {
        let password = b"test-password";
        let store = SecretStore::new(password).unwrap();
        let encrypted = store.encrypt("my-api-key").unwrap();

        let mut config = json!({
            "name": "bot",
            "apiKey": encrypted,
            "port": 8080
        });

        resolve_secrets(&mut config, &store, password);

        assert_eq!(config["apiKey"], "my-api-key");
        assert_eq!(config["name"], "bot");
        assert_eq!(config["port"], 8080);
    }

    #[test]
    fn test_resolve_secrets_nested_config() {
        let password = b"test-password";
        let store = SecretStore::new(password).unwrap();
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

        resolve_secrets(&mut config, &store, password);

        assert_eq!(config["auth"]["apiKey"], "sk-secret");
        assert_eq!(config["auth"]["nested"]["token"], "tok-12345");
        assert_eq!(config["auth"]["provider"], "openai");
        assert_eq!(config["name"], "bot");
    }

    #[test]
    fn test_resolve_secrets_in_arrays() {
        let password = b"password";
        let store = SecretStore::new(password).unwrap();
        let enc1 = store.encrypt("secret1").unwrap();
        let enc2 = store.encrypt("secret2").unwrap();

        let mut config = json!({
            "keys": [enc1, "plain", enc2]
        });

        resolve_secrets(&mut config, &store, password);

        assert_eq!(config["keys"][0], "secret1");
        assert_eq!(config["keys"][1], "plain");
        assert_eq!(config["keys"][2], "secret2");
    }

    #[test]
    fn test_resolve_secrets_skips_non_encrypted() {
        let password = b"password";
        let store = SecretStore::new(password).unwrap();

        let mut config = json!({
            "name": "bot",
            "port": 8080,
            "enabled": true,
            "tags": ["a", "b"]
        });

        let original = config.clone();
        resolve_secrets(&mut config, &store, password);

        assert_eq!(config, original, "non-encrypted values should be untouched");
    }

    #[test]
    fn test_seal_secrets_single_path() {
        let store = SecretStore::new(b"password").unwrap();
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
        let store = SecretStore::new(b"password").unwrap();
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
        let store = SecretStore::new(b"password").unwrap();
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
        let store = SecretStore::new(b"password").unwrap();
        let mut config = json!({ "a": 1 });
        let original = config.clone();

        seal_secrets(&mut config, &store, &["/nonexistent/path"]).unwrap();

        assert_eq!(config, original, "missing path should be a no-op");
    }

    #[test]
    fn test_seal_secrets_non_string_is_noop() {
        let store = SecretStore::new(b"password").unwrap();
        let mut config = json!({ "port": 8080 });
        let original = config.clone();

        seal_secrets(&mut config, &store, &["/port"]).unwrap();

        assert_eq!(config, original, "non-string path should be a no-op");
    }

    #[test]
    fn test_seal_then_resolve_round_trip() {
        let password = b"integration-test-pw";
        let store = SecretStore::new(password).unwrap();

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

        resolve_secrets(&mut config, &store, password);

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
        let password = b"my-password";
        let salt = [0xABu8; SALT_LEN];
        let store = SecretStore::from_password_and_salt(password, &salt);
        let encrypted = store.encrypt("hello").unwrap();
        let decrypted = store.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, "hello");
    }

    #[test]
    fn test_store_new_generates_random_salt() {
        let s1 = SecretStore::new(b"password").unwrap();
        let s2 = SecretStore::new(b"password").unwrap();
        assert_ne!(s1.salt, s2.salt, "each store should have a unique salt");
    }

    #[test]
    fn test_encrypt_decrypt_special_characters() {
        let store = SecretStore::new(b"password").unwrap();
        let plaintext = "p@w0rd!#%^&*()_+-=[]{}|;':,./<>?~";
        let encrypted = store.encrypt(plaintext).unwrap();
        let decrypted = store.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_newlines() {
        let store = SecretStore::new(b"password").unwrap();
        let plaintext = "line1\nline2\nline3\ttab";
        let encrypted = store.encrypt(plaintext).unwrap();
        let decrypted = store.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_json_string() {
        let store = SecretStore::new(b"password").unwrap();
        let plaintext = r#"{"key": "value", "nested": {"a": 1}}"#;
        let encrypted = store.encrypt(plaintext).unwrap();
        let decrypted = store.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_pbkdf2_known_vector() {
        let key = pbkdf2_hmac_sha256(b"password", b"salt", 1);
        assert_eq!(key.len(), 32);
        let key2 = pbkdf2_hmac_sha256(b"password", b"salt", 1);
        assert_eq!(key, key2, "PBKDF2 must be deterministic");
    }

    #[test]
    fn test_pbkdf2_more_iterations_changes_output() {
        let k1 = pbkdf2_hmac_sha256(b"password", b"salt", 1);
        let k2 = pbkdf2_hmac_sha256(b"password", b"salt", 2);
        assert_ne!(
            k1, k2,
            "different iteration counts must produce different keys"
        );
    }
}
