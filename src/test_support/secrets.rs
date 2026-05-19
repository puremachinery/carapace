//! Shared random secret fixtures for tests.

/// Generate a hex-encoded random test secret with `entropy_byte_len`
/// bytes of entropy. The returned string is 2 * `entropy_byte_len`
/// ASCII hex characters.
pub(crate) fn random_test_secret(entropy_byte_len: usize) -> String {
    crate::crypto::generate_hex_secret(entropy_byte_len).expect("generate random test secret")
}

pub(crate) fn random_test_secret_bytes(byte_len: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; byte_len];
    getrandom::fill(&mut bytes).expect("generate random test secret bytes");
    bytes
}
