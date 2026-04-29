//! Backup encryption and decryption using AES-256-GCM with versioned
//! password-derived key derivation.
//!
//! File format: `[8 magic][1 version][32 salt][12 nonce][N ciphertext+tag]`
//!
//! - Magic bytes: `CRPC_ENC` (8 bytes)
//! - Format version: 1 (legacy PBKDF2) or 2 (current Argon2id) (1 byte)
//! - Salt: random 32 bytes used for the versioned password KDF
//! - Nonce: random 12 bytes for AES-256-GCM
//! - Ciphertext: AES-256-GCM encrypted data with appended 16-byte auth tag

use std::fmt;
use std::io::Write;
use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use crate::crypto::{
    decrypt_aead_blob, derive_key_argon2id, derive_key_pbkdf2_sha256, encrypt_aead_blob,
    CryptoEnvelopeError, PASSWORD_DERIVED_KEY_LEN,
};

/// Magic bytes at the start of every encrypted backup file.
pub const MAGIC: &[u8; 8] = b"CRPC_ENC";

pub const FORMAT_VERSION_V1: u8 = 1;
pub const FORMAT_VERSION_V2: u8 = 2;

/// Current format version for new backup writes.
pub const FORMAT_VERSION: u8 = FORMAT_VERSION_V2;

/// Length of the random salt in bytes.
pub const SALT_LEN: usize = 32;

/// Length of the AES-GCM nonce in bytes.
pub const NONCE_LEN: usize = 12;

/// AES-256 key length in bytes.
const KEY_LEN: usize = PASSWORD_DERIVED_KEY_LEN;

/// Total header size: magic(8) + version(1) + salt(32) + nonce(12) = 53.
const HEADER_LEN: usize = MAGIC.len() + 1 + SALT_LEN + NONCE_LEN;

/// Information returned after encrypting a backup.
#[derive(Debug, Clone)]
pub struct BackupCryptoInfo {
    /// Path to the encrypted output file.
    pub output_path: PathBuf,
    /// Hex-encoded salt used for key derivation.
    pub salt_hex: String,
    /// Size of the encrypted file in bytes.
    pub encrypted_size: u64,
}

/// Errors from backup encryption/decryption operations.
#[derive(Debug)]
pub enum BackupCryptoError {
    InvalidMagic,
    UnsupportedVersion(u8),
    DecryptionFailed,
    IoError(String),
    RandomFailure(String),
    KeyDerivationFailed(String),
}

impl fmt::Display for BackupCryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMagic => write!(f, "invalid magic bytes: not an encrypted backup"),
            Self::UnsupportedVersion(v) => write!(f, "unsupported format version: {}", v),
            Self::DecryptionFailed => {
                write!(f, "decryption failed: wrong passphrase or corrupted data")
            }
            Self::IoError(msg) => write!(f, "I/O error: {}", msg),
            Self::RandomFailure(msg) => write!(f, "random number generation failed: {}", msg),
            Self::KeyDerivationFailed(msg) => write!(f, "key derivation failed: {}", msg),
        }
    }
}

impl std::error::Error for BackupCryptoError {}

impl From<std::io::Error> for BackupCryptoError {
    fn from(e: std::io::Error) -> Self {
        Self::IoError(e.to_string())
    }
}

fn map_envelope_error(error: CryptoEnvelopeError) -> BackupCryptoError {
    match error {
        CryptoEnvelopeError::EncryptionFailed => {
            BackupCryptoError::IoError("encryption failed".to_string())
        }
        CryptoEnvelopeError::DecryptionFailed => BackupCryptoError::DecryptionFailed,
        CryptoEnvelopeError::RandomFailure(message) => BackupCryptoError::RandomFailure(message),
        CryptoEnvelopeError::Base64Decode { field, message } => {
            BackupCryptoError::IoError(format!("base64 decode for '{field}': {message}"))
        }
        CryptoEnvelopeError::FieldLength {
            field,
            expected,
            got,
        } => BackupCryptoError::IoError(format!(
            "field '{field}' has wrong length: expected {expected}, got {got}"
        )),
    }
}

/// Derive a 256-bit key from a passphrase and salt for a specific backup
/// format version.
fn derive_key(
    version: u8,
    passphrase: &[u8],
    salt: &[u8],
) -> Result<[u8; KEY_LEN], BackupCryptoError> {
    match version {
        FORMAT_VERSION_V1 => derive_key_pbkdf2_sha256(passphrase, salt)
            .map_err(|e| BackupCryptoError::KeyDerivationFailed(e.to_string())),
        FORMAT_VERSION_V2 => derive_key_argon2id(passphrase, salt)
            .map_err(|e| BackupCryptoError::KeyDerivationFailed(e.to_string())),
        other => Err(BackupCryptoError::UnsupportedVersion(other)),
    }
}

/// Write the canonical `CRPC_ENC` envelope (magic + version + salt + nonce +
/// ciphertext-with-tag) to `writer`. Shared between the production
/// `encrypt_backup` path and the test-only golden-vector helper so any drift
/// in this layout fails both call sites at once.
fn write_encrypted_backup_bytes<W: std::io::Write>(
    writer: &mut W,
    salt: &[u8; SALT_LEN],
    nonce: &[u8; NONCE_LEN],
    ciphertext: &[u8],
) -> std::io::Result<()> {
    writer.write_all(MAGIC)?;
    writer.write_all(&[FORMAT_VERSION])?;
    writer.write_all(salt)?;
    writer.write_all(nonce)?;
    writer.write_all(ciphertext)?;
    Ok(())
}

/// Test-only helper that runs the production envelope-byte path with a
/// caller-supplied key + salt + nonce so golden-vector tests can pin
/// canonical persisted bytes against what production actually writes.
#[cfg(test)]
pub(crate) fn build_encrypted_backup_bytes_for_test(
    key: &[u8; KEY_LEN],
    salt: &[u8; SALT_LEN],
    plaintext: &[u8],
    nonce: &[u8; NONCE_LEN],
) -> Result<Vec<u8>, BackupCryptoError> {
    let blob = crate::crypto::encrypt_aead_blob_with_nonce_for_test(key, nonce, plaintext, &[])
        .map_err(map_envelope_error)?;
    let mut out =
        Vec::with_capacity(MAGIC.len() + 1 + SALT_LEN + NONCE_LEN + blob.ciphertext.len());
    write_encrypted_backup_bytes(&mut out, salt, &blob.nonce, &blob.ciphertext)
        .map_err(BackupCryptoError::from)?;
    Ok(out)
}

/// Encrypt a backup file with AES-256-GCM.
///
/// Reads `input`, encrypts with a key derived from `passphrase`, and writes
/// the encrypted output (with header) to `output`.
pub fn encrypt_backup(
    input: &Path,
    passphrase: &str,
    output: &Path,
) -> Result<BackupCryptoInfo, BackupCryptoError> {
    let plaintext = std::fs::read(input).map_err(|e| {
        BackupCryptoError::IoError(format!("failed to read input {}: {}", input.display(), e))
    })?;

    let mut salt = [0u8; SALT_LEN];
    getrandom::fill(&mut salt).map_err(|e| BackupCryptoError::RandomFailure(e.to_string()))?;

    let key = Zeroizing::new(derive_key(FORMAT_VERSION, passphrase.as_bytes(), &salt)?);

    let blob = encrypt_aead_blob(&key, plaintext.as_ref(), &[]).map_err(map_envelope_error)?;

    let mut file = std::fs::File::create(output).map_err(|e| {
        BackupCryptoError::IoError(format!(
            "failed to create output {}: {}",
            output.display(),
            e
        ))
    })?;

    write_encrypted_backup_bytes(&mut file, &salt, &blob.nonce, &blob.ciphertext)?;
    file.flush()?;

    let metadata = std::fs::metadata(output)?;

    Ok(BackupCryptoInfo {
        output_path: output.to_path_buf(),
        salt_hex: hex::encode(salt),
        encrypted_size: metadata.len(),
    })
}

/// Decrypt an encrypted backup file.
///
/// Reads the encrypted `input`, derives a key from `passphrase`, and writes
/// the decrypted plaintext to `output`.
pub fn decrypt_backup(
    input: &Path,
    passphrase: &str,
    output: &Path,
) -> Result<(), BackupCryptoError> {
    let data = std::fs::read(input).map_err(|e| {
        BackupCryptoError::IoError(format!("failed to read input {}: {}", input.display(), e))
    })?;

    if data.len() < HEADER_LEN {
        return Err(BackupCryptoError::InvalidMagic);
    }

    let (magic, rest) = data.split_at(MAGIC.len());
    if magic != MAGIC.as_slice() {
        return Err(BackupCryptoError::InvalidMagic);
    }

    let version = rest[0];
    let rest = &rest[1..];
    let (salt, rest) = rest.split_at(SALT_LEN);
    let (nonce_bytes, ciphertext) = rest.split_at(NONCE_LEN);

    let key = Zeroizing::new(derive_key(version, passphrase.as_bytes(), salt)?);

    // `split_at(NONCE_LEN)` already guaranteed the slice length, but use
    // `try_into` rather than `expect` so a future refactor of the parser
    // cannot turn this into a panic in a user-facing decrypt path.
    let nonce: [u8; NONCE_LEN] = nonce_bytes
        .try_into()
        .map_err(|_| BackupCryptoError::InvalidMagic)?;
    let plaintext = decrypt_aead_blob(&key, &nonce, ciphertext, &[]).map_err(map_envelope_error)?;

    std::fs::write(output, &plaintext).map_err(|e| {
        BackupCryptoError::IoError(format!(
            "failed to write output {}: {}",
            output.display(),
            e
        ))
    })?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes_gcm::aead::{Aead, KeyInit};
    use aes_gcm::{Aes256Gcm, Nonce};
    use hmac::{Hmac, KeyInit as _, Mac};
    use sha2::Digest;
    use sha2::Sha256 as HmacSha256Digest;
    use tempfile::TempDir;
    use zeroize::Zeroize;

    fn random_bytes<const N: usize>() -> [u8; N] {
        let mut bytes = [0u8; N];
        getrandom::fill(&mut bytes).expect("random test bytes");
        bytes
    }

    fn random_passphrase() -> String {
        hex::encode(random_bytes::<24>())
    }

    fn derive_key_with_iterations(
        passphrase: &[u8],
        salt: &[u8],
        iterations: u32,
    ) -> [u8; KEY_LEN] {
        let mut key = [0u8; KEY_LEN];
        pbkdf2::pbkdf2_hmac::<sha2::Sha256>(passphrase, salt, iterations, &mut key);
        key
    }

    fn derive_key_reference_pbkdf2(
        passphrase: &[u8],
        salt: &[u8],
        iterations: u32,
    ) -> [u8; KEY_LEN] {
        type HmacSha256 = Hmac<HmacSha256Digest>;

        // This reference helper validates the PBKDF2-HMAC-SHA256 algorithm.
        // It stays on the current `hmac 0.13` stack, while the known-answer
        // vector below independently pins the production `pbkdf2` output.
        // This reference path derives exactly one PBKDF2 block. It is valid
        // because KEY_LEN is fixed to the SHA-256 output size (32 bytes).
        assert_eq!(KEY_LEN, 32, "reference PBKDF2 assumes one output block");
        assert!(iterations >= 1, "PBKDF2 requires at least one iteration");

        let mut first_block_input = Vec::with_capacity(salt.len() + 4);
        first_block_input.extend_from_slice(salt);
        first_block_input.extend_from_slice(&1u32.to_be_bytes());

        let mut mac = HmacSha256::new_from_slice(passphrase).expect("HMAC key creation");
        mac.update(&first_block_input);
        let mut u_prev: [u8; KEY_LEN] = mac.finalize().into_bytes().into();
        let mut out = u_prev;

        for _ in 1..iterations {
            let mut iter_mac = HmacSha256::new_from_slice(passphrase).expect("HMAC key creation");
            iter_mac.update(&u_prev);
            u_prev = iter_mac.finalize().into_bytes().into();
            for (dst, src) in out.iter_mut().zip(u_prev.iter()) {
                *dst ^= *src;
            }
        }

        out
    }

    fn derive_key_current(passphrase: &[u8], salt: &[u8; SALT_LEN]) -> [u8; KEY_LEN] {
        derive_key(FORMAT_VERSION, passphrase, salt).expect("current backup KDF should derive")
    }

    fn write_legacy_v1_backup_fixture(
        output: &Path,
        passphrase: &str,
        plaintext: &[u8],
    ) -> Result<(), BackupCryptoError> {
        let salt_digest = sha2::Sha256::digest(b"carapace-backup-v1-fixture-salt");
        let nonce_digest = sha2::Sha256::digest(b"carapace-backup-v1-fixture-nonce");
        let salt: [u8; SALT_LEN] = salt_digest.into();
        let nonce_bytes: [u8; NONCE_LEN] = nonce_digest[..NONCE_LEN]
            .try_into()
            .expect("fixture nonce length");

        let mut key = derive_key_reference_pbkdf2(
            passphrase.as_bytes(),
            &salt,
            crate::crypto::LEGACY_PBKDF2_ITERATIONS,
        );
        let cipher = Aes256Gcm::new((&key).into());
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|_| BackupCryptoError::IoError("fixture encryption failed".to_string()))?;
        key.zeroize();

        let mut file = std::fs::File::create(output).map_err(|e| {
            BackupCryptoError::IoError(format!(
                "failed to create output {}: {}",
                output.display(),
                e
            ))
        })?;
        file.write_all(MAGIC)?;
        file.write_all(&[FORMAT_VERSION_V1])?;
        file.write_all(&salt)?;
        file.write_all(&nonce_bytes)?;
        file.write_all(&ciphertext)?;
        file.flush()?;

        Ok(())
    }

    #[test]
    fn test_constants() {
        assert_eq!(MAGIC.len(), 8);
        assert_eq!(FORMAT_VERSION_V1, 1);
        assert_eq!(FORMAT_VERSION_V2, 2);
        assert_eq!(FORMAT_VERSION, FORMAT_VERSION_V2);
        assert_eq!(SALT_LEN, 32);
        assert_eq!(NONCE_LEN, 12);
        assert_eq!(HEADER_LEN, 53);
        assert_eq!(KEY_LEN, 32);
    }

    #[test]
    fn test_derive_key_deterministic() {
        let passphrase = random_passphrase();
        let salt = random_bytes::<SALT_LEN>();
        let key1 = derive_key_current(passphrase.as_bytes(), &salt);
        let key2 = derive_key_current(passphrase.as_bytes(), &salt);
        assert_eq!(key1, key2);
    }

    #[test]
    fn test_legacy_pbkdf2_cross_stack_consistency() {
        // Keep this test fast: compare the production and cross-stack
        // reference implementations using a reduced iteration count, not
        // production cost. The known-answer vector below anchors correctness.
        let iterations = 10_000;
        let passphrase = random_bytes::<24>();
        let salt = random_bytes::<SALT_LEN>();
        let key = derive_key_with_iterations(&passphrase, &salt, iterations);
        let reference = derive_key_reference_pbkdf2(&passphrase, &salt, iterations);
        assert_eq!(key, reference);
    }

    #[test]
    fn test_legacy_pbkdf2_known_answer_vector() {
        // Deterministic KAT inputs from hashed labels.
        let passphrase = sha2::Sha256::digest(b"carapace-backup-kat-passphrase");
        let salt = sha2::Sha256::digest(b"carapace-backup-kat-salt");
        // Expected output generated independently via Python hashlib.pbkdf2_hmac:
        // python3 -c 'import hashlib; p=hashlib.sha256(b"carapace-backup-kat-passphrase").digest(); s=hashlib.sha256(b"carapace-backup-kat-salt").digest(); print(hashlib.pbkdf2_hmac("sha256", p, s, 600000, 32).hex())'
        let expected_hex = "696c6039c67c9ce83717fe1f72e32d9c8e0b46ceaef2fa6d59268ddc49653329";

        let key = derive_key(FORMAT_VERSION_V1, passphrase.as_slice(), salt.as_slice()).unwrap();
        assert_eq!(hex::encode(key), expected_hex);
    }

    #[test]
    fn test_current_argon2id_known_answer_vector() {
        let passphrase = sha2::Sha256::digest(b"carapace-backup-v2-kat-passphrase");
        let salt = sha2::Sha256::digest(b"carapace-backup-v2-kat-salt");
        // Expected output generated independently via Python argon2-cffi:
        // python3 -c 'import hashlib; from argon2.low_level import hash_secret_raw, Type; p=hashlib.sha256(b"carapace-backup-v2-kat-passphrase").digest(); s=hashlib.sha256(b"carapace-backup-v2-kat-salt").digest(); print(hash_secret_raw(p, s, time_cost=3, memory_cost=64*1024, parallelism=1, hash_len=32, type=Type.ID, version=19).hex())'
        let expected_hex = "5b37e9dfff38746b91d3748784fc105d90cf2077c5176a8efe31d6190ca2d537";

        let key = derive_key(FORMAT_VERSION_V2, passphrase.as_slice(), salt.as_slice()).unwrap();
        assert_eq!(hex::encode(key), expected_hex);
    }

    #[test]
    fn test_current_argon2id_differs_from_legacy_pbkdf2() {
        let passphrase = random_bytes::<24>();
        let salt = random_bytes::<SALT_LEN>();
        let legacy = derive_key(FORMAT_VERSION_V1, &passphrase, &salt).unwrap();
        let current = derive_key(FORMAT_VERSION_V2, &passphrase, &salt).unwrap();
        assert_ne!(legacy, current);
    }

    #[test]
    fn test_derive_key_different_passphrases() {
        let salt = random_bytes::<SALT_LEN>();
        let passphrase_one = random_passphrase();
        let mut passphrase_two = random_passphrase();
        if passphrase_one == passphrase_two {
            passphrase_two.push('x');
        }
        let key1 = derive_key_current(passphrase_one.as_bytes(), &salt);
        let key2 = derive_key_current(passphrase_two.as_bytes(), &salt);
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_derive_key_different_salts() {
        let passphrase = random_passphrase();
        let salt1 = random_bytes::<SALT_LEN>();
        let salt2 = loop {
            let candidate = random_bytes::<SALT_LEN>();
            if candidate != salt1 {
                break candidate;
            }
        };
        let key1 = derive_key_current(passphrase.as_bytes(), &salt1);
        let key2 = derive_key_current(passphrase.as_bytes(), &salt2);
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_derive_key_length() {
        let passphrase = random_passphrase();
        let salt = random_bytes::<SALT_LEN>();
        let key = derive_key_current(passphrase.as_bytes(), &salt);
        assert_eq!(key.len(), KEY_LEN);
    }

    #[test]
    fn test_decrypt_legacy_v1_backup() {
        let dir = TempDir::new().unwrap();
        let encrypted_path = dir.path().join("legacy.enc");
        let decrypted_path = dir.path().join("legacy.dec");

        let passphrase = random_passphrase();
        write_legacy_v1_backup_fixture(&encrypted_path, &passphrase, b"legacy backup payload")
            .unwrap();

        decrypt_backup(&encrypted_path, &passphrase, &decrypted_path).unwrap();
        assert_eq!(
            std::fs::read(&decrypted_path).unwrap(),
            b"legacy backup payload"
        );
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let dir = TempDir::new().unwrap();
        let input_path = dir.path().join("backup.tar.gz");
        let encrypted_path = dir.path().join("backup.enc");
        let decrypted_path = dir.path().join("backup.dec.tar.gz");

        let original_data = b"This is test backup data with some content.\n\
            It has multiple lines and various bytes.\n\
            Including some unicode: \xc3\xa9\xc3\xa0\xc3\xbc\n";

        std::fs::write(&input_path, original_data).unwrap();

        let passphrase = random_passphrase();
        let info = encrypt_backup(&input_path, &passphrase, &encrypted_path).unwrap();
        assert_eq!(info.output_path, encrypted_path);
        assert!(!info.salt_hex.is_empty());
        assert!(info.encrypted_size > 0);
        assert!(info.encrypted_size > HEADER_LEN as u64);

        decrypt_backup(&encrypted_path, &passphrase, &decrypted_path).unwrap();

        let decrypted_data = std::fs::read(&decrypted_path).unwrap();
        assert_eq!(decrypted_data, original_data);
    }

    #[test]
    fn test_encrypt_decrypt_empty_file() {
        let dir = TempDir::new().unwrap();
        let input_path = dir.path().join("empty.dat");
        let encrypted_path = dir.path().join("empty.enc");
        let decrypted_path = dir.path().join("empty.dec");

        std::fs::write(&input_path, b"").unwrap();

        let passphrase = random_passphrase();
        encrypt_backup(&input_path, &passphrase, &encrypted_path).unwrap();
        decrypt_backup(&encrypted_path, &passphrase, &decrypted_path).unwrap();

        let decrypted = std::fs::read(&decrypted_path).unwrap();
        assert!(decrypted.is_empty());
    }

    #[test]
    fn test_encrypt_decrypt_large_data() {
        let dir = TempDir::new().unwrap();
        let input_path = dir.path().join("large.dat");
        let encrypted_path = dir.path().join("large.enc");
        let decrypted_path = dir.path().join("large.dec");

        let large_data: Vec<u8> = (0..100_000).map(|i| (i % 256) as u8).collect();
        std::fs::write(&input_path, &large_data).unwrap();

        let passphrase = random_passphrase();
        encrypt_backup(&input_path, &passphrase, &encrypted_path).unwrap();
        decrypt_backup(&encrypted_path, &passphrase, &decrypted_path).unwrap();

        let decrypted = std::fs::read(&decrypted_path).unwrap();
        assert_eq!(decrypted, large_data);
    }

    #[test]
    fn test_decrypt_wrong_passphrase() {
        let dir = TempDir::new().unwrap();
        let input_path = dir.path().join("data.dat");
        let encrypted_path = dir.path().join("data.enc");
        let decrypted_path = dir.path().join("data.dec");

        std::fs::write(&input_path, b"secret data").unwrap();
        let correct_passphrase = random_passphrase();
        let mut wrong_passphrase = random_passphrase();
        if correct_passphrase == wrong_passphrase {
            wrong_passphrase.push('x');
        }
        encrypt_backup(&input_path, &correct_passphrase, &encrypted_path).unwrap();

        let result = decrypt_backup(&encrypted_path, &wrong_passphrase, &decrypted_path);
        assert!(matches!(result, Err(BackupCryptoError::DecryptionFailed)));
    }

    #[test]
    fn test_decrypt_invalid_magic() {
        let dir = TempDir::new().unwrap();
        let bad_file = dir.path().join("not-encrypted.dat");
        let output = dir.path().join("output.dat");

        std::fs::write(
            &bad_file,
            b"NOT_CRPC data here with enough bytes to pass length check__",
        )
        .unwrap();

        let passphrase = random_passphrase();
        let result = decrypt_backup(&bad_file, &passphrase, &output);
        assert!(matches!(result, Err(BackupCryptoError::InvalidMagic)));
    }

    #[test]
    fn test_decrypt_too_short() {
        let dir = TempDir::new().unwrap();
        let short_file = dir.path().join("short.dat");
        let output = dir.path().join("output.dat");

        std::fs::write(&short_file, b"CRPC_ENC").unwrap(); // only magic, no header

        let passphrase = random_passphrase();
        let result = decrypt_backup(&short_file, &passphrase, &output);
        assert!(matches!(result, Err(BackupCryptoError::InvalidMagic)));
    }

    #[test]
    fn test_decrypt_unsupported_version() {
        let dir = TempDir::new().unwrap();
        let bad_version = dir.path().join("bad_version.dat");
        let output = dir.path().join("output.dat");

        let mut data = Vec::new();
        data.extend_from_slice(MAGIC);
        data.push(99); // unsupported version
        data.extend_from_slice(&[0u8; SALT_LEN]);
        data.extend_from_slice(&[0u8; NONCE_LEN]);
        data.extend_from_slice(b"fake ciphertext");
        std::fs::write(&bad_version, &data).unwrap();

        let passphrase = random_passphrase();
        let result = decrypt_backup(&bad_version, &passphrase, &output);
        assert!(matches!(
            result,
            Err(BackupCryptoError::UnsupportedVersion(99))
        ));
    }

    #[test]
    fn test_decrypt_corrupted_ciphertext() {
        let dir = TempDir::new().unwrap();
        let input_path = dir.path().join("data.dat");
        let encrypted_path = dir.path().join("data.enc");
        let corrupted_path = dir.path().join("data.corrupt");
        let output = dir.path().join("output.dat");

        std::fs::write(&input_path, b"test data").unwrap();
        let passphrase = random_passphrase();
        encrypt_backup(&input_path, &passphrase, &encrypted_path).unwrap();

        // Corrupt the ciphertext by flipping bits
        let mut data = std::fs::read(&encrypted_path).unwrap();
        if let Some(byte) = data.last_mut() {
            *byte ^= 0xFF;
        }
        std::fs::write(&corrupted_path, &data).unwrap();

        let result = decrypt_backup(&corrupted_path, &passphrase, &output);
        assert!(matches!(result, Err(BackupCryptoError::DecryptionFailed)));
    }

    #[test]
    fn test_encrypt_nonexistent_input() {
        let dir = TempDir::new().unwrap();
        let result = encrypt_backup(
            &dir.path().join("nonexistent.dat"),
            &random_passphrase(),
            &dir.path().join("output.enc"),
        );
        assert!(matches!(result, Err(BackupCryptoError::IoError(_))));
    }

    #[test]
    fn test_encrypted_file_has_correct_header() {
        let dir = TempDir::new().unwrap();
        let input_path = dir.path().join("data.dat");
        let encrypted_path = dir.path().join("data.enc");

        std::fs::write(&input_path, b"hello world").unwrap();
        let passphrase = random_passphrase();
        encrypt_backup(&input_path, &passphrase, &encrypted_path).unwrap();

        let data = std::fs::read(&encrypted_path).unwrap();
        assert!(data.len() > HEADER_LEN);
        assert_eq!(&data[..8], MAGIC.as_slice());
        assert_eq!(data[8], FORMAT_VERSION);
    }

    #[test]
    fn test_each_encryption_produces_different_output() {
        let dir = TempDir::new().unwrap();
        let input_path = dir.path().join("data.dat");
        let enc1 = dir.path().join("enc1");
        let enc2 = dir.path().join("enc2");

        std::fs::write(&input_path, b"same data").unwrap();
        let passphrase = random_passphrase();
        encrypt_backup(&input_path, &passphrase, &enc1).unwrap();
        encrypt_backup(&input_path, &passphrase, &enc2).unwrap();

        let data1 = std::fs::read(&enc1).unwrap();
        let data2 = std::fs::read(&enc2).unwrap();
        // Different salt and nonce means different ciphertext
        assert_ne!(data1, data2);
    }

    #[test]
    fn test_error_display() {
        assert_eq!(
            BackupCryptoError::InvalidMagic.to_string(),
            "invalid magic bytes: not an encrypted backup"
        );
        assert_eq!(
            BackupCryptoError::UnsupportedVersion(5).to_string(),
            "unsupported format version: 5"
        );
        assert_eq!(
            BackupCryptoError::DecryptionFailed.to_string(),
            "decryption failed: wrong passphrase or corrupted data"
        );
        assert_eq!(
            BackupCryptoError::IoError("disk full".to_string()).to_string(),
            "I/O error: disk full"
        );
        assert_eq!(
            BackupCryptoError::RandomFailure("rng".to_string()).to_string(),
            "random number generation failed: rng"
        );
        assert_eq!(
            BackupCryptoError::KeyDerivationFailed("oom".to_string()).to_string(),
            "key derivation failed: oom"
        );
    }

    #[test]
    fn test_from_io_error() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let crypto_err: BackupCryptoError = io_err.into();
        assert!(matches!(crypto_err, BackupCryptoError::IoError(_)));
        assert!(crypto_err.to_string().contains("file not found"));
    }

    #[test]
    fn test_crpc_enc_persisted_layout_golden_vector() {
        // True golden vector: pins the full canonical `CRPC_ENC` byte
        // sequence to a hardcoded literal `&[u8]` for a fixed key + salt +
        // nonce + plaintext. The actual bytes come from the *production*
        // envelope-writer (`build_encrypted_backup_bytes_for_test`), so any
        // drift in MAGIC, FORMAT_VERSION, segment ordering, or AEAD output
        // would break the assertion against the literal.
        let key: [u8; KEY_LEN] = sha2::Sha256::digest(b"carapace-backup-golden-key").into();
        let salt_digest = sha2::Sha256::digest(b"carapace-backup-golden-salt");
        let salt: [u8; SALT_LEN] = salt_digest.into();
        let nonce_digest = sha2::Sha256::digest(b"carapace-backup-golden-nonce");
        let nonce_bytes: [u8; NONCE_LEN] = nonce_digest[..NONCE_LEN]
            .try_into()
            .expect("nonce slice length");
        let plaintext = b"carapace backup golden plaintext";

        // Pinned canonical CRPC_ENC bytes for the inputs above. Layout:
        //   bytes  0..8  : MAGIC ("CRPC_ENC")
        //   byte      8  : FORMAT_VERSION_V2 (0x02)
        //   bytes  9..41 : salt (32 bytes)
        //   bytes 41..53 : nonce (12 bytes)
        //   bytes 53..   : AES-256-GCM ciphertext-with-tag
        // Regenerate by replacing this with `&[]`, running the test, and
        // copying the value from the assertion's "actual" panic message.
        // Any deliberate persisted-format change must update this constant.
        const EXPECTED_CRPC_BYTES: &[u8] = &[
            67, 82, 80, 67, 95, 69, 78, 67, 2, 86, 219, 5, 152, 182, 223, 204, 105, 158, 92, 27,
            245, 226, 163, 65, 202, 169, 5, 60, 96, 165, 203, 239, 47, 46, 105, 131, 248, 164, 120,
            17, 24, 141, 133, 102, 77, 194, 3, 51, 33, 145, 148, 0, 32, 173, 226, 28, 57, 88, 99,
            213, 105, 120, 109, 73, 249, 113, 243, 203, 230, 22, 129, 179, 75, 47, 255, 137, 207,
            64, 245, 147, 169, 143, 74, 182, 252, 214, 85, 185, 66, 150, 74, 144, 38, 49, 44, 107,
            139, 147, 215, 93, 128,
        ];

        let actual_bytes =
            build_encrypted_backup_bytes_for_test(&key, &salt, plaintext, &nonce_bytes)
                .expect("production backup envelope build");
        assert_eq!(actual_bytes, EXPECTED_CRPC_BYTES);

        // Round-trip via the production decrypt path: parse magic / version /
        // salt / nonce, derive key (pre-derived here), and AEAD-decrypt.
        let header_offset = MAGIC.len() + 1;
        let nonce_offset = header_offset + SALT_LEN;
        let ct_offset = nonce_offset + NONCE_LEN;
        assert_eq!(&actual_bytes[..MAGIC.len()], MAGIC.as_slice());
        assert_eq!(actual_bytes[MAGIC.len()], FORMAT_VERSION_V2);
        assert_eq!(
            &actual_bytes[header_offset..header_offset + SALT_LEN],
            salt.as_slice()
        );
        assert_eq!(
            &actual_bytes[nonce_offset..nonce_offset + NONCE_LEN],
            nonce_bytes.as_slice()
        );
        let recovered =
            crate::crypto::decrypt_aead_blob(&key, &nonce_bytes, &actual_bytes[ct_offset..], &[])
                .expect("golden backup decryption via shared helper");
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn test_backup_crypto_info_fields() {
        let info = BackupCryptoInfo {
            output_path: PathBuf::from("/tmp/test.enc"),
            salt_hex: "aabbccdd".to_string(),
            encrypted_size: 1024,
        };
        assert_eq!(info.output_path, PathBuf::from("/tmp/test.enc"));
        assert_eq!(info.salt_hex, "aabbccdd");
        assert_eq!(info.encrypted_size, 1024);
    }
}
