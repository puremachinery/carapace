#![no_main]

use libfuzzer_sys::fuzz_target;

use carapace::config::secrets::{is_encrypted, parse_encrypted, SecretStore};

fuzz_target!(|data: &str| {
    // Fuzz the enc:v1: format parser with arbitrary strings.
    // This must never panic regardless of input -- only return Ok/Err.
    let _ = parse_encrypted(data);

    // Also fuzz the is_encrypted check.
    let _ = is_encrypted(data);

    // Fuzz the full decrypt path (which calls parse_encrypted internally).
    // Derive password/salt from input to keep the path variable without using
    // fixed cryptographic test fixtures.
    let mut salt = [0u8; 16];
    for (idx, byte) in data.as_bytes().iter().take(16).enumerate() {
        salt[idx] = *byte;
    }
    if salt.iter().all(|b| *b == 0) {
        salt[0] = 1;
    }
    let password_storage = if data.is_empty() {
        vec![salt[0].max(1)]
    } else {
        data.as_bytes().to_vec()
    };
    let store = SecretStore::from_password_and_salt(&password_storage, &salt);
    let _ = store.decrypt(data);
});
