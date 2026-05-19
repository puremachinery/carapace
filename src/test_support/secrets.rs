//! Shared random secret fixtures for tests.

pub(crate) fn random_test_secret(byte_len: usize) -> String {
    crate::crypto::generate_hex_secret(byte_len).expect("generate random test secret")
}

pub(crate) fn random_test_secret_bytes(byte_len: usize) -> Vec<u8> {
    random_test_secret(byte_len).into_bytes()
}
