//! Shared cryptographic helper utilities.

#[cfg(test)]
use std::sync::{LazyLock, Mutex};

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
#[cfg(test)]
use sha2::Sha256;
use thiserror::Error;

/// Standard derived-key length for password-based encryption.
pub(crate) const PASSWORD_DERIVED_KEY_LEN: usize = 32;

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

/// AEAD-blob length, in bytes, of the AES-256-GCM 96-bit nonce.
pub(crate) const AEAD_NONCE_LEN: usize = 12;

/// AES-256-GCM encryption-key length in bytes. Aliased to
/// `PASSWORD_DERIVED_KEY_LEN` so the KDF and AEAD layers share one
/// source of truth for the key size; if either side ever needs a
/// different size, that change should be deliberate, not silent.
pub(crate) const AEAD_KEY_LEN: usize = PASSWORD_DERIVED_KEY_LEN;

/// Inner AEAD blob produced by [`encrypt_aead_blob`].
///
/// Holds the random 96-bit nonce and the AES-256-GCM ciphertext-with-tag.
/// Outer persisted formats serialize these fields however they like
/// (`enc:vN:` strings, binary headers, JSON envelopes).
pub(crate) struct AeadBlob {
    pub nonce: [u8; AEAD_NONCE_LEN],
    pub ciphertext: Vec<u8>,
}

/// Errors from the shared AEAD-blob helpers.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub(crate) enum CryptoEnvelopeError {
    #[error("AEAD encryption failed")]
    EncryptionFailed,
    #[error("AEAD decryption failed")]
    DecryptionFailed,
    #[error("random generation failed: {0}")]
    RandomFailure(String),
    #[error("field '{field}' base64 decode: {message}")]
    Base64Decode {
        field: &'static str,
        message: String,
    },
    #[error("field '{field}' has wrong length: expected {expected}, got {got}")]
    FieldLength {
        field: &'static str,
        expected: usize,
        got: usize,
    },
}

/// Encrypt `plaintext` under `key` with AES-256-GCM and a freshly generated
/// random 96-bit nonce.
///
/// The helper owns nonce generation: callers cannot supply their own nonce
/// because nonce-uniqueness under a fixed AEAD key is a critical correctness
/// invariant. `aad` is authenticated but not encrypted; pass `&[]` when the
/// outer format does not bind any associated data.
pub(crate) fn encrypt_aead_blob(
    key: &[u8; AEAD_KEY_LEN],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<AeadBlob, CryptoEnvelopeError> {
    let mut nonce_bytes = [0u8; AEAD_NONCE_LEN];
    getrandom::fill(&mut nonce_bytes)
        .map_err(|err| CryptoEnvelopeError::RandomFailure(err.to_string()))?;
    encrypt_aead_blob_inner(key, &nonce_bytes, plaintext, aad)
}

/// Test-only variant of [`encrypt_aead_blob`] that takes a fixed nonce so
/// golden vectors can pin canonical persisted bytes without changing the
/// runtime nonce-generation contract.
#[cfg(test)]
pub(crate) fn encrypt_aead_blob_with_nonce_for_test(
    key: &[u8; AEAD_KEY_LEN],
    nonce: &[u8; AEAD_NONCE_LEN],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<AeadBlob, CryptoEnvelopeError> {
    encrypt_aead_blob_inner(key, nonce, plaintext, aad)
}

fn encrypt_aead_blob_inner(
    key: &[u8; AEAD_KEY_LEN],
    nonce_bytes: &[u8; AEAD_NONCE_LEN],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<AeadBlob, CryptoEnvelopeError> {
    let cipher = Aes256Gcm::new(key.into());
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(nonce_bytes),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| CryptoEnvelopeError::EncryptionFailed)?;
    Ok(AeadBlob {
        nonce: *nonce_bytes,
        ciphertext,
    })
}

/// Decrypt an AEAD blob under `key` and `aad`, returning the plaintext.
///
/// Takes slices for both `nonce` and `ciphertext` so callers that already
/// own borrowed views (parsed from a string segment, sliced from a file
/// buffer) can pass them through without a `to_vec()` clone. For large
/// payloads (backup files, session histories) avoiding that clone is a
/// noticeable memory-pressure win.
///
/// Returns [`CryptoEnvelopeError::DecryptionFailed`] for any AEAD failure
/// (wrong key, wrong AAD, tampered ciphertext, or truncated tag).
pub(crate) fn decrypt_aead_blob(
    key: &[u8; AEAD_KEY_LEN],
    nonce: &[u8; AEAD_NONCE_LEN],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoEnvelopeError> {
    let cipher = Aes256Gcm::new(key.into());
    cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| CryptoEnvelopeError::DecryptionFailed)
}

/// Decode a base64-encoded fixed-size byte field, attributing any error to
/// `field` for consistent error messages across persisted formats.
pub(crate) fn decode_b64_fixed<const N: usize>(
    field: &'static str,
    value: &str,
) -> Result<[u8; N], CryptoEnvelopeError> {
    let decoded = BASE64
        .decode(value)
        .map_err(|err| CryptoEnvelopeError::Base64Decode {
            field,
            message: err.to_string(),
        })?;
    let got = decoded.len();
    decoded
        .try_into()
        .map_err(|_: Vec<u8>| CryptoEnvelopeError::FieldLength {
            field,
            expected: N,
            got,
        })
}

/// Generate a random secret encoded as lowercase hex.
pub(crate) fn generate_hex_secret(byte_len: usize) -> Result<String, getrandom::Error> {
    let mut bytes = vec![0u8; byte_len];
    getrandom::fill(&mut bytes)?;
    Ok(hex::encode(bytes))
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

    fn aead_kat_key() -> [u8; AEAD_KEY_LEN] {
        Sha256::digest(b"carapace-aead-blob-helper-kat-key").into()
    }

    fn aead_kat_nonce() -> [u8; AEAD_NONCE_LEN] {
        let digest = Sha256::digest(b"carapace-aead-blob-helper-kat-nonce");
        digest[..AEAD_NONCE_LEN]
            .try_into()
            .expect("AEAD nonce length")
    }

    #[test]
    fn test_aead_blob_round_trip_empty_aad() {
        let key = aead_kat_key();
        let plaintext = b"hello AEAD world".to_vec();
        let blob = encrypt_aead_blob(&key, &plaintext, &[]).unwrap();
        let recovered = decrypt_aead_blob(&key, &blob.nonce, &blob.ciphertext, &[]).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn test_aead_blob_round_trip_with_aad() {
        let key = aead_kat_key();
        let aad = b"carapace:aead-aad-bind:v1".as_slice();
        let plaintext = b"this is bound to AAD".to_vec();
        let blob = encrypt_aead_blob(&key, &plaintext, aad).unwrap();
        let recovered = decrypt_aead_blob(&key, &blob.nonce, &blob.ciphertext, aad).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn test_aead_blob_decryption_rejects_wrong_aad() {
        let key = aead_kat_key();
        let aad = b"carapace:aead-aad-bind:v1".as_slice();
        let plaintext = b"this is bound to AAD".to_vec();
        let blob = encrypt_aead_blob(&key, &plaintext, aad).unwrap();
        let wrong_aad = b"carapace:aead-aad-bind:v2".as_slice();
        let err = decrypt_aead_blob(&key, &blob.nonce, &blob.ciphertext, wrong_aad).unwrap_err();
        assert_eq!(err, CryptoEnvelopeError::DecryptionFailed);
    }

    #[test]
    fn test_aead_blob_decryption_rejects_wrong_key() {
        let key = aead_kat_key();
        let plaintext = b"hello AEAD world".to_vec();
        let blob = encrypt_aead_blob(&key, &plaintext, &[]).unwrap();
        let mut wrong_key = key;
        wrong_key[0] ^= 0xFF;
        let err = decrypt_aead_blob(&wrong_key, &blob.nonce, &blob.ciphertext, &[]).unwrap_err();
        assert_eq!(err, CryptoEnvelopeError::DecryptionFailed);
    }

    #[test]
    fn test_aead_blob_decryption_rejects_tampered_ciphertext() {
        let key = aead_kat_key();
        let plaintext = b"hello AEAD world".to_vec();
        let mut blob = encrypt_aead_blob(&key, &plaintext, &[]).unwrap();
        if let Some(byte) = blob.ciphertext.first_mut() {
            *byte ^= 0xFF;
        }
        let err = decrypt_aead_blob(&key, &blob.nonce, &blob.ciphertext, &[]).unwrap_err();
        assert_eq!(err, CryptoEnvelopeError::DecryptionFailed);
    }

    #[test]
    fn test_aead_blob_decryption_rejects_tampered_nonce() {
        let key = aead_kat_key();
        let plaintext = b"hello AEAD world".to_vec();
        let blob = encrypt_aead_blob(&key, &plaintext, &[]).unwrap();
        let wrong_nonce = encrypt_aead_blob(&key, b"different nonce source", &[])
            .unwrap()
            .nonce;
        assert_ne!(wrong_nonce, blob.nonce);
        let err = decrypt_aead_blob(&key, &wrong_nonce, &blob.ciphertext, &[]).unwrap_err();
        assert_eq!(err, CryptoEnvelopeError::DecryptionFailed);
    }

    #[test]
    fn test_aead_blob_uses_unique_nonce_per_call() {
        let key = aead_kat_key();
        let plaintext = b"same plaintext".to_vec();
        let blob_a = encrypt_aead_blob(&key, &plaintext, &[]).unwrap();
        let blob_b = encrypt_aead_blob(&key, &plaintext, &[]).unwrap();
        // This is a probabilistic smoke check over 96-bit random nonces; it
        // catches fixed or broken RNG behavior, not a deterministic uniqueness
        // proof.
        assert_ne!(
            blob_a.nonce, blob_b.nonce,
            "each encrypt call must produce a fresh nonce"
        );
    }

    #[test]
    fn test_aead_blob_known_answer_vector_empty_aad() {
        // KAT: pin the AES-256-GCM ciphertext-with-tag bytes for fixed
        // key + nonce + plaintext + empty AAD. To regenerate, replace
        // EXPECTED_CIPHERTEXT with `&[]`, run the test, and copy the
        // "actual" value from the assertion panic.
        const EXPECTED_CIPHERTEXT: &[u8] = &[
            223, 106, 180, 182, 174, 173, 98, 110, 145, 103, 141, 196, 65, 138, 204, 55, 177, 128,
            130, 170, 2, 209, 220, 213, 236, 81, 45, 35, 87, 3, 35, 237, 247, 103, 127, 125, 150,
            146, 250, 33, 182, 179, 201,
        ];
        let key = aead_kat_key();
        let nonce = aead_kat_nonce();
        let plaintext = b"carapace-shared-aead-helper".as_slice();
        let blob = encrypt_aead_blob_with_nonce_for_test(&key, &nonce, plaintext, &[]).unwrap();
        assert_eq!(blob.ciphertext, EXPECTED_CIPHERTEXT);
    }

    #[test]
    fn test_aead_blob_known_answer_vector_with_aad() {
        // KAT: pin the AAD-bound ciphertext-with-tag bytes. Pinning the
        // literal (rather than only round-tripping) catches a regression
        // that silently swapped `msg` and `aad` at the AEAD boundary —
        // round-trip alone would still pass under a swapped convention.
        // Regenerate as for the empty-AAD KAT above.
        const EXPECTED_CIPHERTEXT_WITH_AAD: &[u8] = &[
            223, 106, 180, 182, 174, 173, 98, 110, 145, 103, 141, 196, 65, 138, 204, 55, 177, 128,
            130, 170, 2, 209, 220, 213, 236, 81, 45, 212, 153, 81, 215, 125, 195, 204, 219, 130,
            66, 62, 236, 190, 166, 28, 72,
        ];
        let key = aead_kat_key();
        let nonce = aead_kat_nonce();
        let plaintext = b"carapace-shared-aead-helper".as_slice();
        let aad = b"carapace:aead-blob-helper-aad:v1".as_slice();
        let blob = encrypt_aead_blob_with_nonce_for_test(&key, &nonce, plaintext, aad).unwrap();
        assert_eq!(blob.ciphertext, EXPECTED_CIPHERTEXT_WITH_AAD);

        let recovered = decrypt_aead_blob(&key, &blob.nonce, &blob.ciphertext, aad).unwrap();
        assert_eq!(recovered, plaintext);
        // AAD-bound ciphertext must differ from the empty-AAD KAT above.
        let no_aad_blob =
            encrypt_aead_blob_with_nonce_for_test(&key, &nonce, plaintext, &[]).unwrap();
        assert_ne!(blob.ciphertext, no_aad_blob.ciphertext);
    }

    #[test]
    fn test_decode_b64_fixed_round_trip() {
        let bytes: [u8; 5] = [1, 2, 3, 4, 5];
        let encoded = BASE64.encode(bytes);
        let decoded = decode_b64_fixed::<5>("test", &encoded).unwrap();
        assert_eq!(decoded, bytes);
    }

    #[test]
    fn test_decode_b64_fixed_invalid_base64() {
        let err = decode_b64_fixed::<5>("nonce", "not!valid!b64").unwrap_err();
        assert!(matches!(
            err,
            CryptoEnvelopeError::Base64Decode { field: "nonce", .. }
        ));
    }

    #[test]
    fn test_decode_b64_fixed_wrong_length() {
        let bytes: [u8; 3] = [1, 2, 3];
        let encoded = BASE64.encode(bytes);
        let err = decode_b64_fixed::<5>("nonce", &encoded).unwrap_err();
        assert_eq!(
            err,
            CryptoEnvelopeError::FieldLength {
                field: "nonce",
                expected: 5,
                got: 3,
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
