//! Session and storage layer
//!
//! Provides persistence for sessions and chat history with compaction support.
//! Sessions are stored in `~/.config/carapace/sessions/` using JSONL format for
//! append-friendly history operations.

use sha2::{Digest, Sha256};

pub mod file_lock;
pub mod integrity;
pub mod retention;
pub mod scoping;
mod store;

pub use store::{
    ArchiveResult, ArchivedSession, ChatMessage, CompactionMetadata, MessageRole, RestoreResult,
    Session, SessionFilter, SessionMetadata, SessionStatus, SessionStore, SessionStoreError,
};

/// Canonicalize an explicit session hint to a deterministic opaque session ID.
pub fn canonicalize_session_hint(session_hint: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"carapace:session-hint:v1:");
    hasher.update(session_hint.as_bytes());
    format!("sid_{}", hex::encode(hasher.finalize()))
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
    let resolved_session_id = match explicit_session_hint
        .map(|id| id.trim())
        .filter(|id| !id.is_empty())
    {
        Some(id) => canonicalize_session_hint(id),
        None => scoping::resolve_session_key(channel_name, sender, peer, channel_config.scope),
    };

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

#[cfg(test)]
mod tests {
    use super::canonicalize_session_hint;

    #[test]
    fn test_canonicalize_session_hint_pinned_hash_output() {
        let canonical = canonicalize_session_hint("my-session");
        assert_eq!(
            canonical,
            "sid_31c3253ae028e0adb3745c77672b8ea3adfc6a971c4aae07b0e26500d5886ed4"
        );
    }
}
