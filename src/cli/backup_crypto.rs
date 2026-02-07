//! Backup encryption and decryption using AES-256-GCM with PBKDF2 key derivation.
//!
//! File format: `[8 magic][1 version][32 salt][12 nonce][N ciphertext+tag]`
//!
//! - Magic bytes: `CRPC_ENC` (8 bytes)
//! - Format version: 1 (1 byte)
//! - Salt: random 32 bytes used for PBKDF2
//! - Nonce: random 12 bytes for AES-256-GCM
//! - Ciphertext: AES-256-GCM encrypted data with appended 16-byte auth tag

use std::fmt;
use std::io::Write;
use std::path::{Path, PathBuf};

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use hmac::Hmac;
use sha2::Sha256;
use zeroize::Zeroize;

/// Magic bytes at the start of every encrypted backup file.
pub const MAGIC: &[u8; 8] = b"CRPC_ENC";

/// Current format version.
pub const FORMAT_VERSION: u8 = 1;

/// Number of PBKDF2 iterations for key derivation.
pub const PBKDF2_ITERATIONS: u32 = 600_000;

/// Length of the random salt in bytes.
pub const SALT_LEN: usize = 32;

/// Length of the AES-GCM nonce in bytes.
pub const NONCE_LEN: usize = 12;

/// AES-256 key length in bytes.
const KEY_LEN: usize = 32;

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
    KeyDerivationFailed,
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
            Self::KeyDerivationFailed => write!(f, "key derivation failed"),
        }
    }
}

impl std::error::Error for BackupCryptoError {}

impl From<std::io::Error> for BackupCryptoError {
    fn from(e: std::io::Error) -> Self {
        Self::IoError(e.to_string())
    }
}

/// Derive a 256-bit key from a passphrase and salt using PBKDF2-HMAC-SHA256.
fn derive_key(passphrase: &[u8], salt: &[u8]) -> [u8; KEY_LEN] {
    use hmac::Mac;

    type HmacSha256 = Hmac<Sha256>;

    let mut key = [0u8; KEY_LEN];
    // PBKDF2: block_num = 1 since we only need 32 bytes (one HMAC-SHA256 block)
    let mut u_prev = {
        let mut mac =
            <HmacSha256 as Mac>::new_from_slice(passphrase).expect("HMAC accepts any key length");
        mac.update(salt);
        mac.update(&1u32.to_be_bytes());
        mac.finalize().into_bytes()
    };

    key.copy_from_slice(&u_prev);

    for _ in 1..PBKDF2_ITERATIONS {
        let mut mac =
            <HmacSha256 as Mac>::new_from_slice(passphrase).expect("HMAC accepts any key length");
        mac.update(&u_prev);
        u_prev = mac.finalize().into_bytes();

        for (k, u) in key.iter_mut().zip(u_prev.iter()) {
            *k ^= u;
        }
    }

    key
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
    let mut nonce_bytes = [0u8; NONCE_LEN];
    getrandom::fill(&mut salt).map_err(|_| BackupCryptoError::KeyDerivationFailed)?;
    getrandom::fill(&mut nonce_bytes).map_err(|_| BackupCryptoError::KeyDerivationFailed)?;

    let mut key = derive_key(passphrase.as_bytes(), &salt);

    let cipher =
        Aes256Gcm::new_from_slice(&key).map_err(|_| BackupCryptoError::KeyDerivationFailed)?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_ref())
        .map_err(|_| BackupCryptoError::IoError("encryption failed".to_string()))?;

    key.zeroize();

    let mut file = std::fs::File::create(output).map_err(|e| {
        BackupCryptoError::IoError(format!(
            "failed to create output {}: {}",
            output.display(),
            e
        ))
    })?;

    file.write_all(MAGIC)?;
    file.write_all(&[FORMAT_VERSION])?;
    file.write_all(&salt)?;
    file.write_all(&nonce_bytes)?;
    file.write_all(&ciphertext)?;
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
    if version != FORMAT_VERSION {
        return Err(BackupCryptoError::UnsupportedVersion(version));
    }

    let rest = &rest[1..];
    let (salt, rest) = rest.split_at(SALT_LEN);
    let (nonce_bytes, ciphertext) = rest.split_at(NONCE_LEN);

    let mut key = derive_key(passphrase.as_bytes(), salt);

    let cipher =
        Aes256Gcm::new_from_slice(&key).map_err(|_| BackupCryptoError::KeyDerivationFailed)?;
    let nonce = Nonce::from_slice(nonce_bytes);
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| BackupCryptoError::DecryptionFailed)?;

    key.zeroize();

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
    use tempfile::TempDir;

    #[test]
    fn test_constants() {
        assert_eq!(MAGIC.len(), 8);
        assert_eq!(FORMAT_VERSION, 1);
        assert_eq!(SALT_LEN, 32);
        assert_eq!(NONCE_LEN, 12);
        assert_eq!(HEADER_LEN, 53);
        assert_eq!(KEY_LEN, 32);
    }

    #[test]
    fn test_derive_key_deterministic() {
        let key1 = derive_key(b"test-passphrase", b"salt-value-32-bytes-exactly-here");
        let key2 = derive_key(b"test-passphrase", b"salt-value-32-bytes-exactly-here");
        assert_eq!(key1, key2);
    }

    #[test]
    fn test_derive_key_different_passphrases() {
        let salt = [0xAA; SALT_LEN];
        let key1 = derive_key(b"passphrase-one", &salt);
        let key2 = derive_key(b"passphrase-two", &salt);
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_derive_key_different_salts() {
        let salt1 = [0xAA; SALT_LEN];
        let salt2 = [0xBB; SALT_LEN];
        let key1 = derive_key(b"same-passphrase", &salt1);
        let key2 = derive_key(b"same-passphrase", &salt2);
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_derive_key_length() {
        let key = derive_key(b"test", &[0u8; SALT_LEN]);
        assert_eq!(key.len(), KEY_LEN);
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

        let info = encrypt_backup(&input_path, "my-secure-passphrase", &encrypted_path).unwrap();
        assert_eq!(info.output_path, encrypted_path);
        assert!(!info.salt_hex.is_empty());
        assert!(info.encrypted_size > 0);
        assert!(info.encrypted_size > HEADER_LEN as u64);

        decrypt_backup(&encrypted_path, "my-secure-passphrase", &decrypted_path).unwrap();

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

        encrypt_backup(&input_path, "pass", &encrypted_path).unwrap();
        decrypt_backup(&encrypted_path, "pass", &decrypted_path).unwrap();

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

        encrypt_backup(&input_path, "passphrase123", &encrypted_path).unwrap();
        decrypt_backup(&encrypted_path, "passphrase123", &decrypted_path).unwrap();

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
        encrypt_backup(&input_path, "correct-passphrase", &encrypted_path).unwrap();

        let result = decrypt_backup(&encrypted_path, "wrong-passphrase", &decrypted_path);
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

        let result = decrypt_backup(&bad_file, "pass", &output);
        assert!(matches!(result, Err(BackupCryptoError::InvalidMagic)));
    }

    #[test]
    fn test_decrypt_too_short() {
        let dir = TempDir::new().unwrap();
        let short_file = dir.path().join("short.dat");
        let output = dir.path().join("output.dat");

        std::fs::write(&short_file, b"CRPC_ENC").unwrap(); // only magic, no header

        let result = decrypt_backup(&short_file, "pass", &output);
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

        let result = decrypt_backup(&bad_version, "pass", &output);
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
        encrypt_backup(&input_path, "pass", &encrypted_path).unwrap();

        // Corrupt the ciphertext by flipping bits
        let mut data = std::fs::read(&encrypted_path).unwrap();
        if let Some(byte) = data.last_mut() {
            *byte ^= 0xFF;
        }
        std::fs::write(&corrupted_path, &data).unwrap();

        let result = decrypt_backup(&corrupted_path, "pass", &output);
        assert!(matches!(result, Err(BackupCryptoError::DecryptionFailed)));
    }

    #[test]
    fn test_encrypt_nonexistent_input() {
        let dir = TempDir::new().unwrap();
        let result = encrypt_backup(
            &dir.path().join("nonexistent.dat"),
            "pass",
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
        encrypt_backup(&input_path, "pass", &encrypted_path).unwrap();

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
        encrypt_backup(&input_path, "same-pass", &enc1).unwrap();
        encrypt_backup(&input_path, "same-pass", &enc2).unwrap();

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
            BackupCryptoError::KeyDerivationFailed.to_string(),
            "key derivation failed"
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
