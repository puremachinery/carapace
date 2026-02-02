//! Session and storage layer
//!
//! Provides persistence for sessions and chat history with compaction support.
//! Sessions are stored in `~/.config/carapace/sessions/` using JSONL format for
//! append-friendly history operations.

pub mod file_lock;
pub mod integrity;
pub mod retention;
pub mod scoping;
mod store;

pub use store::{
    ArchiveResult, ArchivedSession, ChatMessage, CompactionMetadata, MessageRole, RestoreResult,
    Session, SessionFilter, SessionMetadata, SessionStatus, SessionStore, SessionStoreError,
};

/// Resolve a session key using scoping config and optional explicit key.
pub fn resolve_scoped_session_key(
    config: &serde_json::Value,
    channel: &str,
    sender_id: &str,
    peer_id: &str,
    explicit_key: Option<&str>,
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
    let session_key = match explicit_key.map(|k| k.trim()).filter(|k| !k.is_empty()) {
        Some(key) => key.to_string(),
        None => scoping::resolve_session_key(channel_name, sender, peer, channel_config.scope),
    };

    (session_key, channel_config, channel_name.to_string())
}

/// Get or create a session using scoping and reset policy enforcement.
pub fn get_or_create_scoped_session(
    store: &SessionStore,
    config: &serde_json::Value,
    channel: &str,
    sender_id: &str,
    peer_id: &str,
    explicit_key: Option<&str>,
    mut metadata: SessionMetadata,
) -> Result<Session, SessionStoreError> {
    let (session_key, channel_config, channel_name) =
        resolve_scoped_session_key(config, channel, sender_id, peer_id, explicit_key);

    if metadata.channel.is_none() {
        metadata.channel = Some(channel_name);
    }

    match store.get_session_by_key(&session_key) {
        Ok(existing) => {
            if scoping::should_reset_session(existing.updated_at, &channel_config.reset) {
                store.reset_session(&existing.id)
            } else {
                Ok(existing)
            }
        }
        Err(SessionStoreError::NotFound(_)) => store.get_or_create_session(&session_key, metadata),
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
