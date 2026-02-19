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

fn is_canonical_session_id(session_hint: &str) -> bool {
    let Some(hex_part) = session_hint.strip_prefix("sid_") else {
        return false;
    };
    hex_part.len() == 64 && hex_part.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Canonicalize an optional explicit session hint.
///
/// Empty hints are discarded. Existing canonical IDs are preserved as-is to
/// avoid double hashing when call sites pre-canonicalize.
pub fn canonicalize_optional_session_hint(session_hint: Option<&str>) -> Option<String> {
    let trimmed = session_hint
        .map(str::trim)
        .filter(|hint| !hint.is_empty())?;
    if is_canonical_session_id(trimmed) {
        Some(trimmed.to_string())
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
}
