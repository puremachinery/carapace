//! Shared cryptographic helper utilities.

#[cfg(test)]
use std::sync::{LazyLock, Mutex};

use argon2::{Algorithm, Argon2, Params, Version};
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;
use thiserror::Error;

/// Standard derived-key length for password-based encryption.
pub(crate) const PASSWORD_DERIVED_KEY_LEN: usize = 32;

/// Legacy PBKDF2 iteration count retained for decrypting older persisted
/// formats and for format-v1 compatibility tests.
pub(crate) const LEGACY_PBKDF2_ITERATIONS: u32 = 600_000;

/// Argon2id parameters for current password-derived encryption writes.
pub(crate) const ARGON2ID_V2_MEMORY_KIB: u32 = 64 * 1024;
pub(crate) const ARGON2ID_V2_ITERATIONS: u32 = 3;
pub(crate) const ARGON2ID_V2_LANES: u32 = 1;
const PASSWORD_KDF_MIN_SALT_LEN: usize = 16;

#[cfg(test)]
static ARGON2_TEST_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

#[derive(Debug, Error, PartialEq, Eq)]
pub(crate) enum PasswordKdfError {
    #[error("invalid Argon2 parameters: {0}")]
    InvalidParams(String),
    #[error("invalid password-KDF salt length: expected at least {minimum}, got {got}")]
    InvalidSaltLength { minimum: usize, got: usize },
    #[error("Argon2 derivation failed: {0}")]
    DerivationFailed(String),
}

/// Generate a random secret encoded as lowercase hex.
pub(crate) fn generate_hex_secret(byte_len: usize) -> Result<String, getrandom::Error> {
    let mut bytes = vec![0u8; byte_len];
    getrandom::fill(&mut bytes)?;
    Ok(hex::encode(bytes))
}

pub(crate) fn derive_key_pbkdf2_sha256(
    password: &[u8],
    salt: &[u8],
) -> Result<[u8; PASSWORD_DERIVED_KEY_LEN], PasswordKdfError> {
    if salt.len() < PASSWORD_KDF_MIN_SALT_LEN {
        return Err(PasswordKdfError::InvalidSaltLength {
            minimum: PASSWORD_KDF_MIN_SALT_LEN,
            got: salt.len(),
        });
    }

    let mut out = [0u8; PASSWORD_DERIVED_KEY_LEN];
    pbkdf2_hmac::<Sha256>(password, salt, LEGACY_PBKDF2_ITERATIONS, &mut out);
    Ok(out)
}

pub(crate) fn derive_key_argon2id(
    password: &[u8],
    salt: &[u8],
) -> Result<[u8; PASSWORD_DERIVED_KEY_LEN], PasswordKdfError> {
    #[cfg(test)]
    let _guard = ARGON2_TEST_LOCK
        .lock()
        .unwrap_or_else(|err| err.into_inner());

    if salt.len() < PASSWORD_KDF_MIN_SALT_LEN {
        return Err(PasswordKdfError::InvalidSaltLength {
            minimum: PASSWORD_KDF_MIN_SALT_LEN,
            got: salt.len(),
        });
    }

    let params = Params::new(
        ARGON2ID_V2_MEMORY_KIB,
        ARGON2ID_V2_ITERATIONS,
        ARGON2ID_V2_LANES,
        Some(PASSWORD_DERIVED_KEY_LEN),
    )
    .map_err(|e| PasswordKdfError::InvalidParams(e.to_string()))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; PASSWORD_DERIVED_KEY_LEN];
    argon2
        .hash_password_into(password, salt, &mut out)
        .map_err(|e| PasswordKdfError::DerivationFailed(e.to_string()))?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::Digest;

    #[test]
    fn test_derive_key_pbkdf2_sha256_rejects_short_salt() {
        let password = Sha256::digest(b"carapace-pbkdf2-short-salt-password");
        let salt = Sha256::digest(b"carapace-pbkdf2-short-salt-salt");
        let err = derive_key_pbkdf2_sha256(password.as_slice(), &salt[..15]).unwrap_err();
        assert_eq!(
            err,
            PasswordKdfError::InvalidSaltLength {
                minimum: PASSWORD_KDF_MIN_SALT_LEN,
                got: 15,
            }
        );
    }

    #[test]
    fn test_derive_key_argon2id_rejects_short_salt() {
        let password = Sha256::digest(b"carapace-argon2-short-salt-password");
        let salt = Sha256::digest(b"carapace-argon2-short-salt-salt");
        let err = derive_key_argon2id(password.as_slice(), &salt[..15]).unwrap_err();
        assert_eq!(
            err,
            PasswordKdfError::InvalidSaltLength {
                minimum: PASSWORD_KDF_MIN_SALT_LEN,
                got: 15,
            }
        );
    }
}
