#![no_main]

use std::sync::LazyLock;
use std::time::{SystemTime, UNIX_EPOCH};

use libfuzzer_sys::fuzz_target;

use carapace::config::secrets::{is_encrypted, SecretStore};

fn build_fuzz_store() -> SecretStore {
    // Build once at process start to keep PBKDF2 out of the per-input hot path.
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(1);
    let salt = now.to_le_bytes();
    let mut password = now.rotate_left(29).to_be_bytes();
    if password.iter().all(|b| *b == 0) {
        password[0] = 1;
    }
    SecretStore::from_password_and_salt(&password, &salt)
}

static FUZZ_STORE: LazyLock<SecretStore> = LazyLock::new(build_fuzz_store);

fuzz_target!(|data: &str| {
    // Fuzz the marker check and decrypt parser path; these must never panic.
    let _ = is_encrypted(data);

    // Fuzz the full decrypt path (which calls parse_encrypted internally).
    // Keep key derivation out of the per-iteration hot path so parser coverage
    // remains high.
    let _ = FUZZ_STORE.decrypt(data);
});
