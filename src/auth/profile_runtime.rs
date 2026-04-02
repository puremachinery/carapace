//! Runtime auth-profile resolution helpers.
//!
//! This module owns process-local caching for auth-profile backed credential
//! resolution on hot paths that do not otherwise hold a long-lived
//! `ProfileStore`.

use parking_lot::RwLock;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;
use std::time::UNIX_EPOCH;

#[cfg(test)]
use std::sync::atomic::{AtomicUsize, Ordering};

use super::profiles::{resolve_anthropic_profile_token, ProfileStore};

static AUTH_PROFILE_RUNTIME_RESOLVER: LazyLock<AuthProfileRuntimeResolver> =
    LazyLock::new(AuthProfileRuntimeResolver::new);

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProfileStoreFileStamp {
    exists: bool,
    len: u64,
    modified_ms: u64,
}

impl ProfileStoreFileStamp {
    fn read(path: &Path) -> Self {
        let Ok(metadata) = fs::metadata(path) else {
            return Self {
                exists: false,
                len: 0,
                modified_ms: 0,
            };
        };
        let modified_ms = metadata
            .modified()
            .ok()
            .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
            .map(|duration| duration.as_millis() as u64)
            .unwrap_or(0);
        Self {
            exists: true,
            len: metadata.len(),
            modified_ms,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AnthropicProfileStoreSnapshot {
    state_dir: PathBuf,
    state_path: PathBuf,
    password_fingerprint: [u8; 32],
    file_stamp: ProfileStoreFileStamp,
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
        let state_path = state_dir.join("auth_profiles.json");
        let password_fingerprint = Sha256::digest(password.as_bytes()).into();
        let file_stamp = ProfileStoreFileStamp::read(&state_path);
        Self {
            snapshot: AnthropicProfileStoreSnapshot {
                state_dir,
                state_path,
                password_fingerprint,
                file_stamp,
            },
            password,
        }
    }
}

struct CachedAnthropicProfileStore {
    snapshot: AnthropicProfileStoreSnapshot,
    store: ProfileStore,
}

#[derive(Default)]
struct AuthProfileRuntimeState {
    anthropic_store: Option<CachedAnthropicProfileStore>,
}

pub(crate) struct AuthProfileRuntimeResolver {
    state: RwLock<AuthProfileRuntimeState>,
    #[cfg(test)]
    anthropic_load_attempts: AtomicUsize,
}

impl AuthProfileRuntimeResolver {
    pub(crate) fn new() -> Self {
        Self {
            state: RwLock::new(AuthProfileRuntimeState::default()),
            #[cfg(test)]
            anthropic_load_attempts: AtomicUsize::new(0),
        }
    }

    fn resolve_anthropic_token(
        &self,
        inputs: AnthropicProfileRuntimeInputs,
        profile_id: &str,
    ) -> Result<String, String> {
        {
            let state = self.state.read();
            if let Some(cached) = state.anthropic_store.as_ref() {
                if cached.snapshot == inputs.snapshot {
                    return Self::resolve_cached_anthropic_token(&cached.store, profile_id);
                }
            }
        }

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
        let resolved = Self::resolve_cached_anthropic_token(&store, profile_id)?;

        let mut state = self.state.write();
        state.anthropic_store = Some(CachedAnthropicProfileStore {
            snapshot: inputs.snapshot,
            store,
        });
        Ok(resolved)
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
    }

    #[cfg(test)]
    pub(crate) fn anthropic_load_attempts_for_tests(&self) -> usize {
        self.anthropic_load_attempts.load(Ordering::Relaxed)
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

    #[test]
    fn test_resolve_anthropic_profile_token_reuses_cached_store() {
        let temp = tempfile::tempdir().unwrap();
        let password = "runtime-cache-password".to_string();
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
        let password = "runtime-reload-password".to_string();
        let profile_id = "anthropic:default";
        let store = ProfileStore::with_encryption(temp.path().to_path_buf(), password.as_bytes())
            .expect("encrypted profile store");
        store
            .add(anthropic_token_profile(profile_id, "sk-ant-oat01-short"))
            .expect("store profile");

        let resolver = AuthProfileRuntimeResolver::new();
        let inputs =
            AnthropicProfileRuntimeInputs::new(temp.path().to_path_buf(), password.clone());
        assert_eq!(
            resolver
                .resolve_anthropic_token(inputs, profile_id)
                .expect("initial resolve"),
            "sk-ant-oat01-short"
        );

        let external_store =
            ProfileStore::with_encryption(temp.path().to_path_buf(), password.as_bytes())
                .expect("external store");
        external_store.load().expect("load existing profile");
        external_store
            .upsert(anthropic_token_profile(
                profile_id,
                "sk-ant-oat01-much-longer-reloaded-token",
            ))
            .expect("rewrite profile");

        let inputs =
            AnthropicProfileRuntimeInputs::new(temp.path().to_path_buf(), password.clone());
        assert_eq!(
            resolver
                .resolve_anthropic_token(inputs, profile_id)
                .expect("reload resolve"),
            "sk-ant-oat01-much-longer-reloaded-token"
        );
        assert_eq!(resolver.anthropic_load_attempts_for_tests(), 2);
    }

    #[test]
    fn test_resolve_anthropic_profile_token_reloads_after_password_change() {
        let temp = tempfile::tempdir().unwrap();
        let correct_password = "runtime-correct-password".to_string();
        let wrong_password = "runtime-wrong-password".to_string();
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
        assert_eq!(resolver.anthropic_load_attempts_for_tests(), 2);
    }
}
