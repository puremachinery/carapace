//! Runtime auth-profile resolution helpers.
//!
//! This module owns process-local caching for auth-profile backed credential
//! resolution on hot paths that do not otherwise hold a long-lived
//! `ProfileStore`.

use parking_lot::{Mutex, RwLock};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;
use std::time::UNIX_EPOCH;

#[cfg(test)]
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use super::profiles::{profile_store_state_path, resolve_anthropic_profile_token, ProfileStore};

static AUTH_PROFILE_RUNTIME_RESOLVER: LazyLock<AuthProfileRuntimeResolver> =
    LazyLock::new(AuthProfileRuntimeResolver::new);

/// Bound the lifetime of a decrypted runtime store even when local inputs do
/// not change. This caps stale reuse for server-side revocation/rotation and
/// for the rare filesystem edge case where a same-length rewrite aliases the
/// cheap metadata stamp.
const ANTHROPIC_PROFILE_STORE_CACHE_TTL_MS: u64 = 60 * 1000;

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProfileStoreMetadataStamp {
    exists: bool,
    len: u64,
    modified_ns: u128,
}

impl ProfileStoreMetadataStamp {
    fn missing() -> Self {
        Self {
            exists: false,
            len: 0,
            modified_ns: 0,
        }
    }

    fn from_metadata(metadata: &fs::Metadata) -> Self {
        let modified_ns = metadata
            .modified()
            .ok()
            .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        Self {
            exists: true,
            len: metadata.len(),
            modified_ns,
        }
    }

    fn read(path: &Path) -> Self {
        fs::metadata(path)
            .map(|metadata| Self::from_metadata(&metadata))
            .unwrap_or_else(|_| Self::missing())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AnthropicProfileStoreSnapshot {
    state_dir: PathBuf,
    state_path: PathBuf,
    password_fingerprint: [u8; 32],
    file_stamp: ProfileStoreMetadataStamp,
}

impl AnthropicProfileStoreSnapshot {
    fn new(state_dir: PathBuf, password: &str) -> Self {
        let state_path = profile_store_state_path(&state_dir);
        let password_fingerprint = Sha256::digest(password.as_bytes()).into();
        let file_stamp = ProfileStoreMetadataStamp::read(&state_path);
        Self {
            state_dir,
            state_path,
            password_fingerprint,
            file_stamp,
        }
    }

    fn refreshed_after_load(&self) -> Self {
        Self {
            state_dir: self.state_dir.clone(),
            state_path: self.state_path.clone(),
            password_fingerprint: self.password_fingerprint,
            file_stamp: ProfileStoreMetadataStamp::read(&self.state_path),
        }
    }

    fn cache_key_matches(&self, other: &Self) -> bool {
        self.state_dir == other.state_dir
            && self.state_path == other.state_path
            && self.password_fingerprint == other.password_fingerprint
    }
}

struct AnthropicProfileRuntimeInputs {
    snapshot: AnthropicProfileStoreSnapshot,
    password: String,
}

impl AnthropicProfileRuntimeInputs {
    fn from_env() -> Result<Self, String> {
        let password = std::env::var("CARAPACE_CONFIG_PASSWORD")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| {
                "Anthropic auth profile is configured, but CARAPACE_CONFIG_PASSWORD is not set."
                    .to_string()
            })?;
        Ok(Self::new(crate::paths::resolve_state_dir(), password))
    }

    fn new(state_dir: PathBuf, password: String) -> Self {
        Self {
            snapshot: AnthropicProfileStoreSnapshot::new(state_dir, &password),
            password,
        }
    }
}

struct CachedAnthropicProfileStore {
    snapshot: AnthropicProfileStoreSnapshot,
    expires_at_ms: u64,
    store: ProfileStore,
}

#[derive(Default)]
struct AuthProfileRuntimeState {
    anthropic_store: Option<CachedAnthropicProfileStore>,
}

pub(crate) struct AuthProfileRuntimeResolver {
    state: RwLock<AuthProfileRuntimeState>,
    reload_lock: Mutex<()>,
    #[cfg(test)]
    anthropic_load_attempts: AtomicUsize,
    #[cfg(test)]
    test_now_ms: AtomicU64,
}

impl AuthProfileRuntimeResolver {
    pub(crate) fn new() -> Self {
        Self {
            state: RwLock::new(AuthProfileRuntimeState::default()),
            reload_lock: Mutex::new(()),
            #[cfg(test)]
            anthropic_load_attempts: AtomicUsize::new(0),
            #[cfg(test)]
            test_now_ms: AtomicU64::new(u64::MAX),
        }
    }

    fn now_ms(&self) -> u64 {
        #[cfg(test)]
        {
            let overridden = self.test_now_ms.load(Ordering::Relaxed);
            if overridden != u64::MAX {
                return overridden;
            }
        }
        crate::time::unix_now_ms_u64()
    }

    fn resolve_cached_match(
        &self,
        snapshot: &AnthropicProfileStoreSnapshot,
        now_ms: u64,
        profile_id: &str,
    ) -> Option<Result<String, String>> {
        let state = self.state.read();
        let cached = state.anthropic_store.as_ref()?;
        // Cheap metadata equality keeps the steady-state hot path to a `stat`
        // plus an in-memory lookup. The TTL above bounds stale reuse if a
        // local rewrite aliases this metadata stamp.
        (cached.snapshot.cache_key_matches(snapshot)
            && cached.snapshot.file_stamp == snapshot.file_stamp
            && now_ms < cached.expires_at_ms)
            .then(|| Self::resolve_cached_anthropic_token(&cached.store, profile_id))
    }

    fn resolve_anthropic_token(
        &self,
        inputs: AnthropicProfileRuntimeInputs,
        profile_id: &str,
    ) -> Result<String, String> {
        let now_ms = self.now_ms();
        if let Some(result) = self.resolve_cached_match(&inputs.snapshot, now_ms, profile_id) {
            return result;
        }

        let _reload_guard = self.reload_lock.lock();
        let now_ms = self.now_ms();
        if let Some(result) = self.resolve_cached_match(&inputs.snapshot, now_ms, profile_id) {
            return result;
        }

        let store = self.load_anthropic_store(&inputs)?;
        let resolved = Self::resolve_cached_anthropic_token(&store, profile_id);
        let snapshot = inputs.snapshot.refreshed_after_load();

        let mut state = self.state.write();
        state.anthropic_store = Some(CachedAnthropicProfileStore {
            snapshot,
            expires_at_ms: now_ms.saturating_add(ANTHROPIC_PROFILE_STORE_CACHE_TTL_MS),
            store,
        });
        resolved
    }

    fn load_anthropic_store(
        &self,
        inputs: &AnthropicProfileRuntimeInputs,
    ) -> Result<ProfileStore, String> {
        #[cfg(test)]
        self.anthropic_load_attempts.fetch_add(1, Ordering::Relaxed);

        let store = ProfileStore::with_encryption(
            inputs.snapshot.state_dir.clone(),
            inputs.password.as_bytes(),
        )
        .map_err(|err| format!("failed to open Anthropic auth profile store: {err}"))?;
        store
            .load()
            .map_err(|err| format!("failed to load Anthropic auth profile store: {err}"))?;
        Ok(store)
    }

    fn resolve_cached_anthropic_token(
        store: &ProfileStore,
        profile_id: &str,
    ) -> Result<String, String> {
        resolve_anthropic_profile_token(store, profile_id)
            .map_err(|err| format!("{err}; check CARAPACE_CONFIG_PASSWORD and the stored profile"))
    }

    #[cfg(test)]
    pub(crate) fn reset_for_tests(&self) {
        let mut state = self.state.write();
        state.anthropic_store = None;
        self.anthropic_load_attempts.store(0, Ordering::Relaxed);
        self.test_now_ms.store(u64::MAX, Ordering::Relaxed);
    }

    #[cfg(test)]
    pub(crate) fn anthropic_load_attempts_for_tests(&self) -> usize {
        self.anthropic_load_attempts.load(Ordering::Relaxed)
    }

    #[cfg(test)]
    fn set_now_ms_for_tests(&self, now_ms: u64) {
        self.test_now_ms.store(now_ms, Ordering::Relaxed);
    }

    #[cfg(test)]
    fn advance_now_ms_for_tests(&self, delta_ms: u64) {
        let base = match self.test_now_ms.load(Ordering::Relaxed) {
            u64::MAX => crate::time::unix_now_ms_u64(),
            overridden => overridden,
        };
        self.test_now_ms
            .store(base.saturating_add(delta_ms), Ordering::Relaxed);
    }
}

pub(crate) fn resolve_anthropic_profile_token_from_env_cached(
    profile_id: &str,
) -> Result<String, String> {
    AUTH_PROFILE_RUNTIME_RESOLVER
        .resolve_anthropic_token(AnthropicProfileRuntimeInputs::from_env()?, profile_id)
}

#[cfg(test)]
pub(crate) fn reset_auth_profile_runtime_for_tests() {
    AUTH_PROFILE_RUNTIME_RESOLVER.reset_for_tests();
}

#[cfg(test)]
pub(crate) fn anthropic_profile_runtime_load_attempts_for_tests() -> usize {
    AUTH_PROFILE_RUNTIME_RESOLVER.anthropic_load_attempts_for_tests()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::profiles::{
        AuthProfile, AuthProfileCredentialKind, OAuthProvider, ProfileStore,
    };
    use filetime::{set_file_mtime, FileTime};
    use std::sync::atomic::AtomicUsize;

    fn anthropic_token_profile(id: &str, token: &str) -> AuthProfile {
        AuthProfile {
            id: id.to_string(),
            name: "Anthropic setup token".to_string(),
            provider: OAuthProvider::Anthropic,
            user_id: None,
            email: None,
            display_name: None,
            avatar_url: None,
            created_at_ms: 1,
            last_used_ms: None,
            credential_kind: AuthProfileCredentialKind::Token,
            tokens: None,
            token: Some(token.to_string()),
            oauth_provider_config: None,
        }
    }

    static TEST_PASSWORD_COUNTER: AtomicUsize = AtomicUsize::new(0);

    fn test_password() -> String {
        format!(
            "{}-{}",
            crate::time::unix_now_ms_u64(),
            TEST_PASSWORD_COUNTER.fetch_add(1, Ordering::Relaxed)
        )
    }

    fn restore_modified_time(path: &Path, modified_ns: u128) {
        let seconds = (modified_ns / 1_000_000_000) as i64;
        let nanos = (modified_ns % 1_000_000_000) as u32;
        set_file_mtime(path, FileTime::from_unix_time(seconds, nanos))
            .expect("restore metadata alias mtime");
    }

    #[test]
    fn test_resolve_anthropic_profile_token_reuses_cached_store() {
        let temp = tempfile::tempdir().unwrap();
        let password = test_password();
        let profile_id = "anthropic:default";
        let store = ProfileStore::with_encryption(temp.path().to_path_buf(), password.as_bytes())
            .expect("encrypted profile store");
        store
            .add(anthropic_token_profile(
                profile_id,
                "sk-ant-oat01-first-token",
            ))
            .expect("store profile");

        let resolver = AuthProfileRuntimeResolver::new();
        resolver.set_now_ms_for_tests(10_000);
        let inputs =
            AnthropicProfileRuntimeInputs::new(temp.path().to_path_buf(), password.clone());
        assert_eq!(
            resolver
                .resolve_anthropic_token(inputs, profile_id)
                .expect("first resolve"),
            "sk-ant-oat01-first-token"
        );
        let inputs =
            AnthropicProfileRuntimeInputs::new(temp.path().to_path_buf(), password.clone());
        assert_eq!(
            resolver
                .resolve_anthropic_token(inputs, profile_id)
                .expect("second resolve"),
            "sk-ant-oat01-first-token"
        );
        assert_eq!(resolver.anthropic_load_attempts_for_tests(), 1);
    }

    #[test]
    fn test_resolve_anthropic_profile_token_reloads_after_store_write() {
        let temp = tempfile::tempdir().unwrap();
        let password = test_password();
        let profile_id = "anthropic:default";
        let store = ProfileStore::with_encryption(temp.path().to_path_buf(), password.as_bytes())
            .expect("encrypted profile store");
        store
            .add(anthropic_token_profile(
                profile_id,
                "sk-ant-oat01-first-token",
            ))
            .expect("store profile");

        let resolver = AuthProfileRuntimeResolver::new();
        resolver.set_now_ms_for_tests(20_000);
        let inputs =
            AnthropicProfileRuntimeInputs::new(temp.path().to_path_buf(), password.clone());
        assert_eq!(
            resolver
                .resolve_anthropic_token(inputs, profile_id)
                .expect("initial resolve"),
            "sk-ant-oat01-first-token"
        );

        let external_store =
            ProfileStore::with_encryption(temp.path().to_path_buf(), password.as_bytes())
                .expect("external store");
        external_store.load().expect("load existing profile");
        external_store
            .upsert(anthropic_token_profile(
                profile_id,
                "sk-ant-oat01-fresh-token",
            ))
            .expect("rewrite profile");

        let inputs =
            AnthropicProfileRuntimeInputs::new(temp.path().to_path_buf(), password.clone());
        assert_eq!(
            resolver
                .resolve_anthropic_token(inputs, profile_id)
                .expect("reload resolve"),
            "sk-ant-oat01-fresh-token"
        );
        assert_eq!(resolver.anthropic_load_attempts_for_tests(), 2);
    }

    #[test]
    fn test_resolve_anthropic_profile_token_reloads_after_ttl_expiry_without_store_write() {
        let temp = tempfile::tempdir().unwrap();
        let password = test_password();
        let profile_id = "anthropic:default";
        let store = ProfileStore::with_encryption(temp.path().to_path_buf(), password.as_bytes())
            .expect("encrypted profile store");
        store
            .add(anthropic_token_profile(
                profile_id,
                "sk-ant-oat01-ttl-window-token",
            ))
            .expect("store profile");

        let resolver = AuthProfileRuntimeResolver::new();
        resolver.set_now_ms_for_tests(30_000);
        let inputs =
            AnthropicProfileRuntimeInputs::new(temp.path().to_path_buf(), password.clone());
        assert_eq!(
            resolver
                .resolve_anthropic_token(inputs, profile_id)
                .expect("initial resolve"),
            "sk-ant-oat01-ttl-window-token"
        );

        resolver.advance_now_ms_for_tests(ANTHROPIC_PROFILE_STORE_CACHE_TTL_MS + 1);
        let inputs =
            AnthropicProfileRuntimeInputs::new(temp.path().to_path_buf(), password.clone());
        assert_eq!(
            resolver
                .resolve_anthropic_token(inputs, profile_id)
                .expect("ttl reload resolve"),
            "sk-ant-oat01-ttl-window-token"
        );
        assert_eq!(resolver.anthropic_load_attempts_for_tests(), 2);
    }

    #[test]
    fn test_resolve_anthropic_profile_token_reloads_after_ttl_when_metadata_aliases_store_change() {
        let temp = tempfile::tempdir().unwrap();
        let password = test_password();
        let profile_id = "anthropic:default";
        let state_path = profile_store_state_path(temp.path());
        let store = ProfileStore::with_encryption(temp.path().to_path_buf(), password.as_bytes())
            .expect("encrypted profile store");
        store
            .add(anthropic_token_profile(
                profile_id,
                "sk-ant-oat01-first-token",
            ))
            .expect("store profile");

        let resolver = AuthProfileRuntimeResolver::new();
        resolver.set_now_ms_for_tests(40_000);
        let initial_inputs =
            AnthropicProfileRuntimeInputs::new(temp.path().to_path_buf(), password.clone());
        let initial_stamp = initial_inputs.snapshot.file_stamp.clone();
        assert_eq!(
            resolver
                .resolve_anthropic_token(initial_inputs, profile_id)
                .expect("initial resolve"),
            "sk-ant-oat01-first-token"
        );

        let external_store =
            ProfileStore::with_encryption(temp.path().to_path_buf(), password.as_bytes())
                .expect("external store");
        external_store.load().expect("load existing profile");
        external_store
            .upsert(anthropic_token_profile(
                profile_id,
                "sk-ant-oat01-fresh-token",
            ))
            .expect("rewrite profile");
        restore_modified_time(&state_path, initial_stamp.modified_ns);

        let aliased_inputs =
            AnthropicProfileRuntimeInputs::new(temp.path().to_path_buf(), password.clone());
        assert_eq!(aliased_inputs.snapshot.file_stamp, initial_stamp);
        assert_eq!(
            resolver
                .resolve_anthropic_token(aliased_inputs, profile_id)
                .expect("pre-expiry resolve still uses cached store"),
            "sk-ant-oat01-first-token"
        );
        assert_eq!(resolver.anthropic_load_attempts_for_tests(), 1);

        resolver.advance_now_ms_for_tests(ANTHROPIC_PROFILE_STORE_CACHE_TTL_MS + 1);
        let aliased_inputs =
            AnthropicProfileRuntimeInputs::new(temp.path().to_path_buf(), password.clone());
        assert_eq!(aliased_inputs.snapshot.file_stamp, initial_stamp);
        assert_eq!(
            resolver
                .resolve_anthropic_token(aliased_inputs, profile_id)
                .expect("post-expiry resolve reloads changed store"),
            "sk-ant-oat01-fresh-token"
        );
        assert_eq!(resolver.anthropic_load_attempts_for_tests(), 2);
    }

    #[test]
    fn test_resolve_anthropic_profile_token_reloads_after_password_change() {
        let temp = tempfile::tempdir().unwrap();
        let correct_password = test_password();
        let wrong_password = test_password();
        let profile_id = "anthropic:default";
        let store =
            ProfileStore::with_encryption(temp.path().to_path_buf(), correct_password.as_bytes())
                .expect("encrypted profile store");
        store
            .add(anthropic_token_profile(
                profile_id,
                "sk-ant-oat01-correct-token",
            ))
            .expect("store profile");

        let resolver = AuthProfileRuntimeResolver::new();
        resolver.set_now_ms_for_tests(50_000);
        let inputs =
            AnthropicProfileRuntimeInputs::new(temp.path().to_path_buf(), correct_password.clone());
        assert_eq!(
            resolver
                .resolve_anthropic_token(inputs, profile_id)
                .expect("correct password resolve"),
            "sk-ant-oat01-correct-token"
        );

        let inputs =
            AnthropicProfileRuntimeInputs::new(temp.path().to_path_buf(), wrong_password.clone());
        let err = resolver
            .resolve_anthropic_token(inputs, profile_id)
            .expect_err("wrong password should fail");
        assert!(err.contains("could not decrypt the stored token"));

        let inputs =
            AnthropicProfileRuntimeInputs::new(temp.path().to_path_buf(), correct_password.clone());
        assert_eq!(
            resolver
                .resolve_anthropic_token(inputs, profile_id)
                .expect("correct password resolve after mismatch"),
            "sk-ant-oat01-correct-token"
        );
        assert_eq!(resolver.anthropic_load_attempts_for_tests(), 3);
    }

    #[test]
    fn test_resolve_anthropic_profile_token_caches_loaded_store_on_profile_error() {
        let temp = tempfile::tempdir().unwrap();
        let password = test_password();
        let store = ProfileStore::with_encryption(temp.path().to_path_buf(), password.as_bytes())
            .expect("encrypted profile store");
        store
            .add(anthropic_token_profile(
                "anthropic:default",
                "sk-ant-oat01-cached-token",
            ))
            .expect("store profile");

        let resolver = AuthProfileRuntimeResolver::new();
        resolver.set_now_ms_for_tests(60_000);
        let inputs =
            AnthropicProfileRuntimeInputs::new(temp.path().to_path_buf(), password.clone());
        let first = resolver
            .resolve_anthropic_token(inputs, "anthropic:missing")
            .expect_err("missing profile should fail");
        let inputs =
            AnthropicProfileRuntimeInputs::new(temp.path().to_path_buf(), password.clone());
        let second = resolver
            .resolve_anthropic_token(inputs, "anthropic:missing")
            .expect_err("missing profile should still fail");

        assert_eq!(first, second);
        assert_eq!(resolver.anthropic_load_attempts_for_tests(), 1);
    }
}
