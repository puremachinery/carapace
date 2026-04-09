//! Session and storage layer
//!
//! Provides persistence for sessions and chat history with compaction support.
//! Sessions are stored in `~/.config/carapace/sessions/` using JSONL format for
//! append-friendly history operations.

use sha2::{Digest, Sha256};
use std::sync::Arc;

pub mod crypto;
pub mod file_lock;
pub mod integrity;
pub mod retention;
pub mod scoping;
mod store;

pub use crypto::{EncryptionConfig, EncryptionMode};
pub use store::{
    ArchiveResult, ArchivedSession, ChatMessage, CompactionMetadata, MessageRole, RestoreResult,
    Session, SessionAccessState, SessionFilter, SessionListEntry, SessionMetadata, SessionStatus,
    SessionStore, SessionStoreError,
};

pub(crate) fn resolve_session_integrity_config(
    cfg: &serde_json::Value,
) -> integrity::IntegrityConfig {
    let Some(integrity_cfg) = cfg.get("sessions").and_then(|s| s.get("integrity")) else {
        return integrity::IntegrityConfig::default();
    };

    match serde_json::from_value::<integrity::IntegrityConfig>(integrity_cfg.clone()) {
        Ok(parsed) => parsed,
        Err(err) => {
            tracing::warn!(
                error = %err,
                "invalid sessions.integrity config; using secure defaults"
            );
            integrity::IntegrityConfig::default()
        }
    }
}

pub(crate) fn resolve_session_encryption_config(
    cfg: &serde_json::Value,
) -> crypto::EncryptionConfig {
    let Some(encryption_cfg) = cfg.get("sessions").and_then(|s| s.get("encryption")) else {
        return crypto::EncryptionConfig::default();
    };

    match serde_json::from_value::<crypto::EncryptionConfig>(encryption_cfg.clone()) {
        Ok(parsed) => parsed,
        Err(err) => {
            tracing::warn!(
                error = %err,
                "invalid sessions.encryption config; using secure defaults"
            );
            crypto::EncryptionConfig::default()
        }
    }
}

pub(crate) fn resolve_session_integrity_secret_from_value(
    cfg: &serde_json::Value,
    fallback_secret: Option<(String, &'static str)>,
) -> Option<(String, &'static str)> {
    if let Some(secret) = std::env::var("CARAPACE_SERVER_SECRET")
        .ok()
        .filter(|value| !value.is_empty())
    {
        return Some((secret, "CARAPACE_SERVER_SECRET"));
    }
    if let Some(secret) = std::env::var("CARAPACE_GATEWAY_TOKEN")
        .ok()
        .filter(|value| !value.is_empty())
    {
        return Some((secret, "CARAPACE_GATEWAY_TOKEN"));
    }
    if let Some(secret) = std::env::var("CARAPACE_GATEWAY_PASSWORD")
        .ok()
        .filter(|value| !value.is_empty())
    {
        return Some((secret, "CARAPACE_GATEWAY_PASSWORD"));
    }
    if let Some(secret) = fallback_secret {
        return Some(secret);
    }
    if let Some(secret) = cfg
        .pointer("/gateway/auth/token")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        return Some((secret.to_string(), "gateway.auth.token"));
    }
    if let Some(secret) = cfg
        .pointer("/gateway/auth/password")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        return Some((secret.to_string(), "gateway.auth.password"));
    }
    None
}

/// Build a session store from the current config shape and environment.
pub fn configured_store_with_path(
    base_path: std::path::PathBuf,
    cfg: &serde_json::Value,
    fallback_integrity_secret: Option<(String, &'static str)>,
) -> Result<SessionStore, SessionStoreError> {
    let integrity_config = resolve_session_integrity_config(cfg);
    let encryption_config = resolve_session_encryption_config(cfg);

    let mut store = SessionStore::with_base_path(base_path)
        .with_integrity_action(integrity_config.action)
        .with_encryption_mode(encryption_config.mode);

    let password = crate::config::config_password();
    if let Some(password) = password
        .as_ref()
        .filter(|_| encryption_config.mode.uses_encryption())
    {
        let crypto =
            crypto::SessionCryptoContext::load_or_create(store.base_path(), password.as_ref())
                .map_err(SessionStoreError::from)?;
        let hmac_key = crypto.integrity_hmac_key();
        store = store
            .with_crypto_context(Arc::new(crypto))
            .with_hmac_key(hmac_key);
        return Ok(store);
    }

    if integrity_config.enabled {
        if let Some((server_secret, _source)) =
            resolve_session_integrity_secret_from_value(cfg, fallback_integrity_secret)
        {
            let hmac_key = integrity::derive_hmac_key(server_secret.as_bytes());
            store = store.with_hmac_key(hmac_key);
        }
    }

    Ok(store)
}

/// Build a session store from the on-disk config and current environment.
pub fn configured_store_with_path_from_current_config(
    base_path: std::path::PathBuf,
) -> Result<SessionStore, SessionStoreError> {
    let cfg = crate::config::load_config().map_err(|err| {
        SessionStoreError::Io(format!("failed to load config for sessions: {err}"))
    })?;
    configured_store_with_path(base_path, &cfg, None)
}

/// Canonicalize an explicit session hint to a deterministic opaque session ID.
pub fn canonicalize_session_hint(session_hint: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"carapace:session-hint:v1:");
    hasher.update(session_hint.as_bytes());
    format!("sid_{}", hex::encode(hasher.finalize()))
}

fn is_canonical_session_id(session_hint: &str) -> bool {
    let Some(hex_part) = session_hint.strip_prefix("sid_") else {
        return false;
    };
    hex_part.len() == 64 && hex_part.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Canonicalize an optional explicit session hint.
///
/// Empty hints are discarded. Existing canonical IDs are preserved and
/// normalized to lowercase to avoid double hashing and key mismatches.
pub fn canonicalize_optional_session_hint(session_hint: Option<&str>) -> Option<String> {
    let trimmed = match session_hint {
        Some(hint) => {
            let hint = hint.trim();
            if hint.is_empty() {
                return None;
            }
            hint
        }
        None => return None,
    };
    if is_canonical_session_id(trimmed) {
        Some(trimmed.to_ascii_lowercase())
    } else {
        Some(canonicalize_session_hint(trimmed))
    }
}

/// Resolve a session key using scoping config and optional explicit session hint.
pub fn resolve_scoped_session_key(
    config: &serde_json::Value,
    channel: &str,
    sender_id: &str,
    peer_id: &str,
    explicit_session_hint: Option<&str>,
) -> (String, scoping::ChannelSessionConfig, String) {
    let channel_name = channel.trim();
    let channel_name = if channel_name.is_empty() {
        "default"
    } else {
        channel_name
    };
    let sender = sender_id.trim();
    let sender = if sender.is_empty() { "unknown" } else { sender };
    let peer = peer_id.trim();
    let peer = if peer.is_empty() { sender } else { peer };

    let channel_config = scoping::ChannelSessionConfig::from_config(config, channel_name);
    let explicit_session_id = canonicalize_optional_session_hint(explicit_session_hint);
    let resolved_session_id = explicit_session_id.unwrap_or_else(|| {
        scoping::resolve_session_key(channel_name, sender, peer, channel_config.scope)
    });

    (
        resolved_session_id,
        channel_config,
        channel_name.to_string(),
    )
}

/// Get or create a session using scoping and reset policy enforcement.
pub fn get_or_create_scoped_session(
    store: &SessionStore,
    config: &serde_json::Value,
    channel: &str,
    sender_id: &str,
    peer_id: &str,
    explicit_session_hint: Option<&str>,
    mut metadata: SessionMetadata,
) -> Result<Session, SessionStoreError> {
    let (resolved_session_id, channel_config, channel_name) =
        resolve_scoped_session_key(config, channel, sender_id, peer_id, explicit_session_hint);

    if metadata.channel.is_none() {
        metadata.channel = Some(channel_name);
    }

    match store.get_session_by_key(&resolved_session_id) {
        Ok(existing) => {
            if scoping::should_reset_session(existing.updated_at, &channel_config.reset) {
                store.reset_session(&existing.id)
            } else {
                Ok(existing)
            }
        }
        Err(SessionStoreError::NotFound(_)) => {
            store.get_or_create_session(&resolved_session_id, metadata)
        }
        Err(e) => Err(e),
    }
}

/// Create a new session store with default settings
pub fn create_store() -> SessionStore {
    SessionStore::new()
}

/// Create a session store with a custom base path
pub fn create_store_with_path(base_path: std::path::PathBuf) -> SessionStore {
    SessionStore::with_base_path(base_path)
}

/// Append a message via a blocking worker thread.
pub async fn append_message_blocking(
    store: Arc<SessionStore>,
    message: ChatMessage,
) -> Result<(), SessionStoreError> {
    tokio::task::spawn_blocking(move || store.append_message(message))
        .await
        .map_err(|e| SessionStoreError::Io(format!("session append task failed: {e}")))?
}

/// Append multiple messages via a blocking worker thread.
pub async fn append_messages_blocking(
    store: Arc<SessionStore>,
    messages: Vec<ChatMessage>,
) -> Result<(), SessionStoreError> {
    tokio::task::spawn_blocking(move || store.append_messages(&messages))
        .await
        .map_err(|e| SessionStoreError::Io(format!("session append task failed: {e}")))?
}

/// Read session history via a blocking worker thread.
pub async fn get_history_blocking(
    store: Arc<SessionStore>,
    session_id: String,
    limit: Option<usize>,
    before_message_id: Option<String>,
) -> Result<Vec<ChatMessage>, SessionStoreError> {
    tokio::task::spawn_blocking(move || {
        store.get_history(&session_id, limit, before_message_id.as_deref())
    })
    .await
    .map_err(|e| SessionStoreError::Io(format!("session read task failed: {e}")))?
}

/// Resolve a session by key via a blocking worker thread.
pub async fn get_session_by_key_blocking(
    store: Arc<SessionStore>,
    session_key: String,
) -> Result<Session, SessionStoreError> {
    tokio::task::spawn_blocking(move || store.get_session_by_key(&session_key))
        .await
        .map_err(|e| SessionStoreError::Io(format!("session read task failed: {e}")))?
}

#[cfg(test)]
mod tests {
    use super::{canonicalize_optional_session_hint, canonicalize_session_hint};

    #[test]
    fn test_canonicalize_session_hint_pinned_hash_output() {
        let canonical = canonicalize_session_hint("my-session");
        assert_eq!(
            canonical,
            "sid_31c3253ae028e0adb3745c77672b8ea3adfc6a971c4aae07b0e26500d5886ed4"
        );
    }

    #[test]
    fn test_canonicalize_optional_session_hint_preserves_canonical_id() {
        let canonical = "sid_31c3253ae028e0adb3745c77672b8ea3adfc6a971c4aae07b0e26500d5886ed4";
        assert_eq!(
            canonicalize_optional_session_hint(Some(canonical)),
            Some(canonical.to_string())
        );
    }

    #[test]
    fn test_canonicalize_optional_session_hint_discards_empty_input() {
        assert_eq!(canonicalize_optional_session_hint(Some("   ")), None);
        assert_eq!(canonicalize_optional_session_hint(None), None);
    }

    #[test]
    fn test_canonicalize_optional_session_hint_hashes_non_canonical_hint() {
        let expected = canonicalize_session_hint("my-session");
        assert_eq!(
            canonicalize_optional_session_hint(Some("my-session")),
            Some(expected)
        );
    }

    #[test]
    fn test_canonicalize_optional_session_hint_trims_and_preserves_canonical_id() {
        let canonical = "sid_31c3253ae028e0adb3745c77672b8ea3adfc6a971c4aae07b0e26500d5886ed4";
        let padded = format!("  {}  ", canonical);
        assert_eq!(
            canonicalize_optional_session_hint(Some(&padded)),
            Some(canonical.to_string())
        );
    }

    #[test]
    fn test_canonicalize_optional_session_hint_normalizes_canonical_hex_case() {
        let upper = "sid_31C3253AE028E0ADB3745C77672B8EA3ADFC6A971C4AAE07B0E26500D5886ED4";
        let lower = "sid_31c3253ae028e0adb3745c77672b8ea3adfc6a971c4aae07b0e26500d5886ed4";
        assert_eq!(
            canonicalize_optional_session_hint(Some(upper)),
            Some(lower.to_string())
        );
    }

    #[test]
    fn test_canonicalize_optional_session_hint_rehashes_invalid_sid_forms() {
        let invalid_prefix = "SID_31c3253ae028e0adb3745c77672b8ea3adfc6a971c4aae07b0e26500d5886ed4";
        let invalid_len = "sid_31c3253ae028e0adb3745c77672b8ea3adfc6a971c4aae07b0e26500d5886ed";
        let invalid_hex = "sid_zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz";
        assert_eq!(
            canonicalize_optional_session_hint(Some(invalid_prefix)),
            Some(canonicalize_session_hint(invalid_prefix))
        );
        assert_eq!(
            canonicalize_optional_session_hint(Some(invalid_len)),
            Some(canonicalize_session_hint(invalid_len))
        );
        assert_eq!(
            canonicalize_optional_session_hint(Some(invalid_hex)),
            Some(canonicalize_session_hint(invalid_hex))
        );
    }
}
