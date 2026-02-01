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

/// Create a new session store with default settings
pub fn create_store() -> SessionStore {
    SessionStore::new()
}

/// Create a session store with a custom base path
pub fn create_store_with_path(base_path: std::path::PathBuf) -> SessionStore {
    SessionStore::with_base_path(base_path)
}
