//! Shared cryptographic helper utilities.

/// Generate a random secret encoded as lowercase hex.
pub(crate) fn generate_hex_secret(byte_len: usize) -> Result<String, getrandom::Error> {
    let mut bytes = vec![0u8; byte_len];
    getrandom::fill(&mut bytes)?;
    Ok(hex::encode(bytes))
}
