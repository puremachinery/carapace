#![no_main]

use std::sync::LazyLock;

use libfuzzer_sys::fuzz_target;

use carapace::config::secrets::{is_encrypted, SecretStore};

fn build_fuzz_store() -> SecretStore {
    // Intentional simple deterministic (non-cryptographic) mixer for stable
    // fuzz seed expansion.
    fn derive_seed_bytes(seed: &[u8]) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (idx, byte) in seed.iter().copied().enumerate() {
            let slot = idx % out.len();
            out[slot] = out[slot]
                .wrapping_mul(131)
                .wrapping_add(byte)
                .wrapping_add((idx as u8).rotate_left((idx % 8) as u32));
        }
        out
    }

    // Optional deterministic override for reproduction:
    // CARAPACE_FUZZ_STORE_SEED_HEX=<64 hex chars>
    let seed = std::env::var("CARAPACE_FUZZ_STORE_SEED_HEX")
        .ok()
        .and_then(|hex| hex::decode(hex).ok())
        .and_then(|bytes| bytes.try_into().ok())
        .unwrap_or_else(|| {
            // Deterministic seed keeps fuzz crash reproduction stable across restarts.
            // Note: if this seed constant changes, any corpus input that relied on a
            // successful decrypt under the previous seed may no longer reproduce.
            derive_seed_bytes(b"carapace:fuzz_secret_format_parsing:seed:v1")
        });

    let store_salt: [u8; 16] = seed[..16]
        .try_into()
        .expect("seed slice for fuzz salt has fixed size");
    let store_password = &seed[16..];
    SecretStore::from_password_and_salt(store_password, &store_salt)
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
