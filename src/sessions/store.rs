//! Session store implementation
//!
//! File-based storage for sessions and chat history. Sessions are stored
//! as JSON metadata files, and chat history is stored as JSONL for
//! append-friendly operations.

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::warn;
use uuid::Uuid;
use zeroize::Zeroizing;

use super::file_lock::FileLock;

/// Default message count threshold for auto-compaction
const DEFAULT_COMPACT_THRESHOLD: usize = 100;

/// Maximum message count before forcing compaction
const MAX_MESSAGES_BEFORE_COMPACT: usize = 500;
const SESSION_METADATA_PURPOSE: &str = "metadata";
const SESSION_HISTORY_PURPOSE: &str = "history";
const SESSION_ARCHIVE_PURPOSE: &str = "archive";

/// Error types for session store operations
#[derive(Debug, Clone, thiserror::Error)]
pub enum SessionStoreError {
    #[error("Session not found: {0}")]
    NotFound(String),
    #[error("Session already exists: {0}")]
    AlreadyExists(String),
    #[error("IO error: {0}")]
    Io(String),
    #[error("Serialization error: {0}")]
    Serialization(String),
    #[error("Invalid session key: {0}")]
    InvalidSessionKey(String),
    #[error("Compaction in progress for session: {0}")]
    CompactionInProgress(String),
    #[error("Session is already archived: {0}")]
    AlreadyArchived(String),
    #[error("Session is not archived: {0}")]
    NotArchived(String),
    #[error("Archive not found: {0}")]
    ArchiveNotFound(String),
    #[error("Invalid user ID: {0}")]
    InvalidUserId(String),
    #[error("Session store is locked: {0}")]
    Locked(String),
    #[error("Session decryption failed: {0}")]
    DecryptionFailed(String),
    #[error("Session crypto error: {0}")]
    Crypto(String),
}

impl From<std::io::Error> for SessionStoreError {
    fn from(err: std::io::Error) -> Self {
        SessionStoreError::Io(err.to_string())
    }
}

impl From<serde_json::Error> for SessionStoreError {
    fn from(err: serde_json::Error) -> Self {
        SessionStoreError::Serialization(err.to_string())
    }
}

impl From<super::crypto::SessionCryptoError> for SessionStoreError {
    fn from(err: super::crypto::SessionCryptoError) -> Self {
        match err {
            super::crypto::SessionCryptoError::DecryptionFailed => {
                SessionStoreError::DecryptionFailed(
                    "wrong password or corrupted encrypted session data".to_string(),
                )
            }
            super::crypto::SessionCryptoError::ManifestIntegrityFailed => {
                SessionStoreError::DecryptionFailed(
                    "wrong password or tampered encrypted-session manifest".to_string(),
                )
            }
            super::crypto::SessionCryptoError::Io(message)
            | super::crypto::SessionCryptoError::Manifest(message)
            | super::crypto::SessionCryptoError::KeyDerivation(message)
            | super::crypto::SessionCryptoError::RandomFailure(message)
            | super::crypto::SessionCryptoError::BadFormat(message)
            | super::crypto::SessionCryptoError::EncryptionFailed(message) => {
                SessionStoreError::Crypto(message)
            }
            super::crypto::SessionCryptoError::Base64Decode { field, message } => {
                SessionStoreError::Crypto(format!("{}: {}", field, message))
            }
        }
    }
}

fn session_store_error_kind(err: &SessionStoreError) -> &'static str {
    match err {
        SessionStoreError::NotFound(_) => "not_found",
        SessionStoreError::AlreadyExists(_) => "already_exists",
        SessionStoreError::Io(_) => "io",
        SessionStoreError::Serialization(_) => "serialization",
        SessionStoreError::InvalidSessionKey(_) => "invalid_session_key",
        SessionStoreError::CompactionInProgress(_) => "compaction_in_progress",
        SessionStoreError::AlreadyArchived(_) => "already_archived",
        SessionStoreError::NotArchived(_) => "not_archived",
        SessionStoreError::ArchiveNotFound(_) => "archive_not_found",
        SessionStoreError::InvalidUserId(_) => "invalid_user_id",
        SessionStoreError::Locked(_) => "locked",
        SessionStoreError::DecryptionFailed(_) => "decryption_failed",
        SessionStoreError::Crypto(_) => "crypto",
    }
}

fn session_store_error_export_warning(err: &SessionStoreError) -> &'static str {
    match err {
        SessionStoreError::NotFound(_) => "session data was not found on disk",
        SessionStoreError::AlreadyExists(_) => "session data already exists on disk",
        SessionStoreError::Io(_) => "session data could not be read from disk",
        SessionStoreError::Serialization(_) => "session data is malformed",
        SessionStoreError::InvalidSessionKey(_) => "session data uses an invalid session key",
        SessionStoreError::CompactionInProgress(_) => {
            "session data is being compacted and is temporarily unavailable"
        }
        SessionStoreError::AlreadyArchived(_) => "session data is already archived",
        SessionStoreError::NotArchived(_) => "session data is not archived",
        SessionStoreError::ArchiveNotFound(_) => "session archive was not found on disk",
        SessionStoreError::InvalidUserId(_) => "session data is associated with an invalid user ID",
        SessionStoreError::Locked(_) => {
            "encrypted session data is unavailable without the config password"
        }
        SessionStoreError::DecryptionFailed(_) => "encrypted session data could not be decrypted",
        SessionStoreError::Crypto(_) => "encrypted session data is unreadable or corrupted",
    }
}

fn integrity_error_kind(err: &super::integrity::IntegrityError) -> &'static str {
    match err {
        super::integrity::IntegrityError::Io(_) => "io",
        super::integrity::IntegrityError::VerificationFailed { .. } => "verification_failed",
        super::integrity::IntegrityError::Rejected { .. } => "rejected",
    }
}

/// Status of a session
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionStatus {
    /// Session is active and can receive messages
    #[default]
    Active,
    /// Session is paused (no new messages processed)
    Paused,
    /// Session is archived (read-only)
    Archived,
    /// Session is being compacted
    Compacting,
}

impl std::fmt::Display for SessionStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Active => write!(f, "active"),
            Self::Paused => write!(f, "paused"),
            Self::Archived => write!(f, "archived"),
            Self::Compacting => write!(f, "compacting"),
        }
    }
}

/// Role of a chat message sender
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageRole {
    /// User-sent message
    #[default]
    User,
    /// Assistant response
    Assistant,
    /// System message (e.g., context, instructions)
    System,
    /// Tool call or result
    Tool,
}

impl std::fmt::Display for MessageRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::User => write!(f, "user"),
            Self::Assistant => write!(f, "assistant"),
            Self::System => write!(f, "system"),
            Self::Tool => write!(f, "tool"),
        }
    }
}

/// Metadata for compaction operations
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CompactionMetadata {
    /// Number of messages compacted
    pub messages_compacted: usize,
    /// Timestamp of last compaction (Unix ms)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_compacted_at: Option<i64>,
    /// Number of compaction operations performed
    pub compaction_count: u32,
    /// Summary text from last compaction
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_summary: Option<String>,
    /// Original message count before compactions
    #[serde(default)]
    pub original_message_count: usize,
}

/// Result of an archive operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchiveResult {
    /// Session ID that was archived
    pub session_id: String,
    /// Path to the archive file
    pub archive_path: String,
    /// Number of messages archived
    pub message_count: usize,
    /// Size of the archive file in bytes
    pub archive_size: u64,
    /// Timestamp when the archive was created (Unix ms)
    pub archived_at: i64,
    /// Whether history was deleted after archiving
    pub history_deleted: bool,
}

/// Result of a restore operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RestoreResult {
    /// Session ID that was restored
    pub session_id: String,
    /// Number of messages restored
    pub message_count: usize,
    /// Timestamp when the restore happened (Unix ms)
    pub restored_at: i64,
}

/// Archived session metadata stored in archive file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchivedSession {
    /// Original session data
    pub session: Session,
    /// All messages at time of archiving
    pub messages: Vec<ChatMessage>,
    /// When the archive was created (Unix ms)
    pub archived_at: i64,
    /// Archive format version
    pub version: u32,
}

/// Metadata associated with a session
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SessionMetadata {
    /// Human-readable session name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Session description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Agent ID this session belongs to
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    /// Channel this session is associated with
    #[serde(skip_serializing_if = "Option::is_none")]
    pub channel: Option<String>,
    /// Chat/conversation ID within the channel
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chat_id: Option<String>,
    /// User ID of the session owner
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    /// Named route for this session
    #[serde(skip_serializing_if = "Option::is_none")]
    pub route: Option<String>,
    /// Model being used for this session
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    /// Thinking level for this session
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thinking_level: Option<String>,
    /// Custom tags for organization
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    /// Additional custom data
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extra: Option<serde_json::Value>,
    /// Compaction metadata
    #[serde(default)]
    pub compaction: CompactionMetadata,
}

/// A chat session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    /// Unique session identifier (UUID)
    pub id: String,
    /// Session key (human-friendly, e.g., "telegram:123456:default")
    pub session_key: String,
    /// Current status
    pub status: SessionStatus,
    /// Session metadata
    #[serde(default)]
    pub metadata: SessionMetadata,
    /// Number of messages in history
    pub message_count: usize,
    /// Timestamp when session was created (Unix ms)
    pub created_at: i64,
    /// Timestamp when session was last updated (Unix ms)
    pub updated_at: i64,
    /// Timestamp of last activity (Unix ms)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_activity_at: Option<i64>,
}

impl Session {
    /// Create a new session with the given agent ID and metadata
    pub fn new(agent_id: impl Into<String>, metadata: SessionMetadata) -> Self {
        let now = now_millis();
        let id = Uuid::new_v4().to_string();
        let agent_id_str = agent_id.into();

        // Generate session key from metadata
        let session_key = generate_session_key(&agent_id_str, &metadata);

        Self {
            id,
            session_key,
            status: SessionStatus::Active,
            metadata: SessionMetadata {
                agent_id: Some(agent_id_str),
                ..metadata
            },
            message_count: 0,
            created_at: now,
            updated_at: now,
            last_activity_at: Some(now),
        }
    }

    /// Create a session with a specific session key
    pub fn with_session_key(session_key: impl Into<String>, metadata: SessionMetadata) -> Self {
        let now = now_millis();
        Self {
            id: Uuid::new_v4().to_string(),
            session_key: session_key.into(),
            status: SessionStatus::Active,
            metadata,
            message_count: 0,
            created_at: now,
            updated_at: now,
            last_activity_at: Some(now),
        }
    }

    /// Check if the session needs compaction
    pub fn needs_compaction(&self) -> bool {
        self.message_count >= DEFAULT_COMPACT_THRESHOLD
    }

    /// Check if compaction should be forced
    pub fn force_compaction_needed(&self) -> bool {
        self.message_count >= MAX_MESSAGES_BEFORE_COMPACT
    }
}

/// Accessibility state for a session listing entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionAccessState {
    Available,
    Locked,
}

/// Session list entry that may represent either a full session or a locked stub.
#[derive(Debug, Clone)]
pub struct SessionListEntry {
    session_id: String,
    access: SessionAccessState,
    session: Option<Session>,
    updated_at: Option<i64>,
}

impl SessionListEntry {
    fn available(session: Session) -> Self {
        let updated_at = Some(session.updated_at);
        let session_id = session.id.clone();
        Self {
            session_id,
            access: SessionAccessState::Available,
            session: Some(session),
            updated_at,
        }
    }

    fn locked(session_id: String, updated_at: Option<i64>) -> Self {
        Self {
            session_id,
            access: SessionAccessState::Locked,
            session: None,
            updated_at,
        }
    }

    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    pub fn access(&self) -> SessionAccessState {
        self.access
    }

    pub fn is_locked(&self) -> bool {
        self.access == SessionAccessState::Locked
    }

    pub fn session(&self) -> Option<&Session> {
        self.session.as_ref()
    }

    pub fn into_session(self) -> Option<Session> {
        self.session
    }

    pub fn updated_at(&self) -> Option<i64> {
        self.updated_at
    }
}

/// A chat message in session history
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    /// Unique message identifier
    pub id: String,
    /// Session ID this message belongs to
    pub session_id: String,
    /// Role of the sender
    pub role: MessageRole,
    /// Message content
    pub content: String,
    /// Tool call ID (for tool messages)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_call_id: Option<String>,
    /// Tool name (for tool messages)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_name: Option<String>,
    /// Token count for this message
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tokens: Option<u64>,
    /// Timestamp when message was created (Unix ms)
    pub created_at: i64,
    /// Additional metadata
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

impl ChatMessage {
    /// Create a new chat message
    pub fn new(
        session_id: impl Into<String>,
        role: MessageRole,
        content: impl Into<String>,
    ) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            session_id: session_id.into(),
            role,
            content: content.into(),
            tool_call_id: None,
            tool_name: None,
            tokens: None,
            created_at: now_millis(),
            metadata: None,
        }
    }

    /// Create a user message
    pub fn user(session_id: impl Into<String>, content: impl Into<String>) -> Self {
        Self::new(session_id, MessageRole::User, content)
    }

    /// Create an assistant message
    pub fn assistant(session_id: impl Into<String>, content: impl Into<String>) -> Self {
        Self::new(session_id, MessageRole::Assistant, content)
    }

    /// Create a system message
    pub fn system(session_id: impl Into<String>, content: impl Into<String>) -> Self {
        Self::new(session_id, MessageRole::System, content)
    }

    /// Create a tool message
    pub fn tool(
        session_id: impl Into<String>,
        tool_name: impl Into<String>,
        tool_call_id: impl Into<String>,
        content: impl Into<String>,
    ) -> Self {
        Self {
            tool_name: Some(tool_name.into()),
            tool_call_id: Some(tool_call_id.into()),
            ..Self::new(session_id, MessageRole::Tool, content)
        }
    }

    /// Set token count
    pub fn with_tokens(mut self, tokens: u64) -> Self {
        self.tokens = Some(tokens);
        self
    }

    /// Set metadata
    pub fn with_metadata(mut self, metadata: serde_json::Value) -> Self {
        self.metadata = Some(metadata);
        self
    }
}

/// Filter criteria for listing sessions
#[derive(Debug, Clone, Default)]
pub struct SessionFilter {
    /// Filter by agent ID
    pub agent_id: Option<String>,
    /// Filter by status
    pub status: Option<SessionStatus>,
    /// Filter by channel
    pub channel: Option<String>,
    /// Filter by user ID
    pub user_id: Option<String>,
    /// Filter sessions created after this timestamp (Unix ms)
    pub created_after: Option<i64>,
    /// Filter sessions created before this timestamp (Unix ms)
    pub created_before: Option<i64>,
    /// Filter sessions updated after this timestamp (Unix ms)
    pub updated_after: Option<i64>,
    /// Filter sessions updated before this timestamp (Unix ms)
    pub updated_before: Option<i64>,
    /// Maximum number of sessions to return
    pub limit: Option<usize>,
    /// Number of sessions to skip
    pub offset: Option<usize>,
}

impl SessionFilter {
    /// Create a new filter
    pub fn new() -> Self {
        Self::default()
    }

    /// Filter by agent ID
    pub fn with_agent_id(mut self, agent_id: impl Into<String>) -> Self {
        self.agent_id = Some(agent_id.into());
        self
    }

    /// Filter by status
    pub fn with_status(mut self, status: SessionStatus) -> Self {
        self.status = Some(status);
        self
    }

    /// Filter by channel
    pub fn with_channel(mut self, channel: impl Into<String>) -> Self {
        self.channel = Some(channel.into());
        self
    }

    /// Filter by user ID
    pub fn with_user_id(mut self, user_id: impl Into<String>) -> Self {
        self.user_id = Some(user_id.into());
        self
    }

    /// Set result limit
    pub fn with_limit(mut self, limit: usize) -> Self {
        self.limit = Some(limit);
        self
    }

    /// Set result offset
    pub fn with_offset(mut self, offset: usize) -> Self {
        self.offset = Some(offset);
        self
    }

    /// Check if a session matches this filter
    fn matches(&self, session: &Session) -> bool {
        if let Some(ref agent_id) = self.agent_id {
            if session.metadata.agent_id.as_ref() != Some(agent_id) {
                return false;
            }
        }
        if let Some(status) = self.status {
            if session.status != status {
                return false;
            }
        }
        if let Some(ref channel) = self.channel {
            if session.metadata.channel.as_ref() != Some(channel) {
                return false;
            }
        }
        if let Some(ref user_id) = self.user_id {
            if session.metadata.user_id.as_ref() != Some(user_id) {
                return false;
            }
        }
        if let Some(created_after) = self.created_after {
            if session.created_at < created_after {
                return false;
            }
        }
        if let Some(created_before) = self.created_before {
            if session.created_at > created_before {
                return false;
            }
        }
        if let Some(updated_after) = self.updated_after {
            if session.updated_at < updated_after {
                return false;
            }
        }
        if let Some(updated_before) = self.updated_before {
            if session.updated_at > updated_before {
                return false;
            }
        }
        true
    }

    fn requires_decrypted_metadata(&self) -> bool {
        self.agent_id.is_some()
            || self.status.is_some()
            || self.channel.is_some()
            || self.user_id.is_some()
            || self.created_after.is_some()
            || self.created_before.is_some()
            || self.updated_after.is_some()
            || self.updated_before.is_some()
    }
}

/// In-memory session cache entry
#[derive(Debug)]
struct CachedSession {
    session: Session,
    dirty: bool,
    history_migration_satisfied: bool,
}

/// Thread-safe session store with file-based persistence
#[derive(Debug)]
pub struct SessionStore {
    /// Base path for session storage
    base_path: PathBuf,
    /// In-memory session cache
    sessions: RwLock<HashMap<String, CachedSession>>,
    /// Session key to ID mapping
    key_to_id: RwLock<HashMap<String, String>>,
    /// Compaction threshold
    compact_threshold: usize,
    /// Optional HMAC key for session integrity verification.
    hmac_key: Option<Zeroizing<[u8; 32]>>,
    /// Optional legacy HMAC key for pre-encryption session artifacts.
    legacy_hmac_key: Option<Zeroizing<[u8; 32]>>,
    /// Action to take when integrity verification fails.
    integrity_action: super::integrity::IntegrityAction,
    /// Session encryption mode.
    encryption_mode: super::crypto::EncryptionMode,
    /// Optional session crypto context for encrypted session artifacts.
    crypto: Option<Arc<super::crypto::SessionCryptoContext>>,
    /// Locked-session stubs discovered by the store-owned disk scan.
    locked_session_entries: RwLock<HashMap<String, SessionListEntry>>,
}

impl Default for SessionStore {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionStore {
    /// Create a new session store with default path (~/.config/carapace/sessions/)
    pub fn new() -> Self {
        let base_path = dirs::config_dir()
            .map(|p| p.join("carapace").join("sessions"))
            .unwrap_or_else(|| PathBuf::from(".config/carapace/sessions"));
        Self::with_base_path(base_path)
    }

    /// Create a session store with a custom base path
    pub fn with_base_path(base_path: PathBuf) -> Self {
        Self {
            base_path,
            sessions: RwLock::new(HashMap::new()),
            key_to_id: RwLock::new(HashMap::new()),
            compact_threshold: DEFAULT_COMPACT_THRESHOLD,
            hmac_key: None,
            legacy_hmac_key: None,
            integrity_action: super::integrity::IntegrityAction::Warn,
            encryption_mode: super::crypto::EncryptionMode::Off,
            crypto: None,
            locked_session_entries: RwLock::new(HashMap::new()),
        }
    }

    /// Set the compaction threshold
    pub fn with_compact_threshold(mut self, threshold: usize) -> Self {
        self.compact_threshold = threshold;
        self
    }

    /// Set the HMAC key for session integrity verification.
    pub fn with_hmac_key(mut self, key: Zeroizing<[u8; 32]>) -> Self {
        self.hmac_key = Some(key);
        self
    }

    /// Set the legacy HMAC key used for pre-encryption session artifacts.
    pub fn with_legacy_hmac_key(mut self, key: Zeroizing<[u8; 32]>) -> Self {
        self.legacy_hmac_key = Some(key);
        self
    }

    /// Set the action to take when integrity verification fails.
    pub fn with_integrity_action(mut self, action: super::integrity::IntegrityAction) -> Self {
        self.integrity_action = action;
        self
    }

    /// Set the session encryption mode.
    pub fn with_encryption_mode(mut self, mode: super::crypto::EncryptionMode) -> Self {
        self.encryption_mode = mode;
        self
    }

    /// Set the session crypto context.
    pub fn with_crypto_context(mut self, crypto: Arc<super::crypto::SessionCryptoContext>) -> Self {
        self.crypto = Some(crypto);
        self
    }

    /// Ensure the base directory exists
    fn ensure_base_dir(&self) -> Result<(), SessionStoreError> {
        if !self.base_path.exists() {
            fs::create_dir_all(&self.base_path)?;
        }
        Ok(())
    }

    fn encryption_active(&self) -> bool {
        self.crypto.is_some() && self.encryption_mode.uses_encryption()
    }

    fn new_cached_session(&self, session: Session, dirty: bool) -> CachedSession {
        CachedSession {
            session,
            dirty,
            history_migration_satisfied: self.encryption_active(),
        }
    }

    fn history_migration_satisfied_in_cache(&self, session_id: &str) -> bool {
        self.sessions
            .read()
            .get(session_id)
            .map(|cached| cached.history_migration_satisfied)
            .unwrap_or(false)
    }

    fn mark_history_migration_satisfied(&self, session_id: &str) {
        if let Some(cached) = self.sessions.write().get_mut(session_id) {
            cached.history_migration_satisfied = true;
        }
    }

    fn lock_message(reason: impl Into<String>) -> SessionStoreError {
        SessionStoreError::Locked(reason.into())
    }

    fn session_locked_without_password() -> SessionStoreError {
        Self::lock_message("session is encrypted and unavailable without the config password")
    }

    fn ensure_required_encryption_available(&self) -> Result<(), SessionStoreError> {
        if matches!(
            self.encryption_mode,
            super::crypto::EncryptionMode::Required
        ) && self.crypto.is_none()
        {
            return Err(Self::lock_message(
                "session encryption is required; provide the config password to access sessions",
            ));
        }
        Ok(())
    }

    fn encode_session_metadata(&self, session: &Session) -> Result<Vec<u8>, SessionStoreError> {
        if let Some(crypto) = self.crypto.as_ref().filter(|_| self.encryption_active()) {
            return crypto
                .encrypt_json(&session.id, SESSION_METADATA_PURPOSE, session)
                .map_err(Into::into);
        }
        serde_json::to_vec_pretty(session).map_err(Into::into)
    }

    fn decode_session_metadata(
        &self,
        session_id: &str,
        content: &[u8],
    ) -> Result<Session, SessionStoreError> {
        if super::crypto::has_encrypted_payload_prefix(content) {
            let Some(crypto) = self.crypto.as_ref() else {
                return Err(Self::session_locked_without_password());
            };
            return crypto
                .decrypt_json(session_id, SESSION_METADATA_PURPOSE, content)
                .map_err(Into::into);
        }
        serde_json::from_slice(content).map_err(Into::into)
    }

    fn encode_history_message(&self, message: &ChatMessage) -> Result<Vec<u8>, SessionStoreError> {
        if let Some(crypto) = self.crypto.as_ref().filter(|_| self.encryption_active()) {
            return crypto
                .encrypt_json(&message.session_id, SESSION_HISTORY_PURPOSE, message)
                .map_err(Into::into);
        }
        serde_json::to_vec(message).map_err(Into::into)
    }

    fn decode_history_message(
        &self,
        session_id: &str,
        line: &[u8],
        encrypted_line: bool,
    ) -> Result<ChatMessage, SessionStoreError> {
        if encrypted_line {
            let Some(crypto) = self.crypto.as_ref() else {
                return Err(Self::session_locked_without_password());
            };
            return crypto
                .decrypt_json(session_id, SESSION_HISTORY_PURPOSE, line)
                .map_err(Into::into);
        }
        serde_json::from_slice(line).map_err(Into::into)
    }

    fn encode_archive(
        &self,
        session_id: &str,
        archive: &ArchivedSession,
    ) -> Result<Vec<u8>, SessionStoreError> {
        if let Some(crypto) = self.crypto.as_ref().filter(|_| self.encryption_active()) {
            return crypto
                .encrypt_json(session_id, SESSION_ARCHIVE_PURPOSE, archive)
                .map_err(Into::into);
        }
        serde_json::to_vec_pretty(archive).map_err(Into::into)
    }

    fn decode_archive(
        &self,
        session_id: &str,
        content: &[u8],
    ) -> Result<ArchivedSession, SessionStoreError> {
        if super::crypto::has_encrypted_payload_prefix(content) {
            let Some(crypto) = self.crypto.as_ref() else {
                return Err(Self::session_locked_without_password());
            };
            return crypto
                .decrypt_json(session_id, SESSION_ARCHIVE_PURPOSE, content)
                .map_err(Into::into);
        }
        serde_json::from_slice(content).map_err(Into::into)
    }

    fn file_updated_at(path: &Path) -> Option<i64> {
        fs::metadata(path)
            .ok()
            .and_then(|meta| meta.modified().ok())
            .and_then(|ts| ts.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|dur| i64::try_from(dur.as_millis()).unwrap_or(i64::MAX))
    }

    fn record_locked_session_entry(&self, session_id: String, updated_at: Option<i64>) {
        self.locked_session_entries.write().insert(
            session_id.clone(),
            SessionListEntry::locked(session_id, updated_at),
        );
    }

    fn clear_locked_session_entry(&self, session_id: &str) {
        self.locked_session_entries.write().remove(session_id);
    }

    fn replace_locked_session_entries(&self, entries: HashMap<String, SessionListEntry>) {
        *self.locked_session_entries.write() = entries;
    }

    fn locked_session_count(&self) -> usize {
        self.locked_session_entries.read().len()
    }

    fn locked_session_entries_snapshot(&self) -> Vec<SessionListEntry> {
        self.locked_session_entries
            .read()
            .values()
            .cloned()
            .collect()
    }

    fn create_private_output_file(path: &Path) -> Result<File, SessionStoreError> {
        let mut options = OpenOptions::new();
        options.write(true).create(true).truncate(true);

        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;

            options.mode(0o600);
            Ok(options.open(path)?)
        }

        #[cfg(not(unix))]
        {
            Ok(options.open(path)?)
        }
    }

    fn open_private_append_file(path: &Path) -> Result<File, SessionStoreError> {
        let mut options = OpenOptions::new();
        options.create(true).append(true);

        #[cfg(unix)]
        {
            use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

            options.mode(0o600);
            let file = options.open(path)?;
            file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
            Ok(file)
        }

        #[cfg(not(unix))]
        {
            Ok(options.open(path)?)
        }
    }

    fn verify_integrity_path_with_compat(&self, file_path: &Path) -> Result<(), SessionStoreError> {
        let content = fs::read(file_path)?;
        self.verify_integrity_bytes_with_compat(&content, file_path)
    }

    fn verify_integrity_bytes_with_compat(
        &self,
        content: &[u8],
        file_path: &Path,
    ) -> Result<(), SessionStoreError> {
        let Some(ref key) = self.hmac_key else {
            return Ok(());
        };
        let integrity_config = super::integrity::IntegrityConfig {
            enabled: true,
            action: self.integrity_action,
        };
        match super::integrity::verify_hmac_file(key, content, file_path, &integrity_config) {
            Ok(()) => Ok(()),
            Err(super::integrity::IntegrityError::Rejected { .. }) => {
                let locked_without_crypto =
                    self.encrypted_artifact_locked_without_crypto_bytes(content);
                if locked_without_crypto {
                    return Err(Self::session_locked_without_password());
                }

                let Some(ref legacy_key) = self.legacy_hmac_key else {
                    return Err(SessionStoreError::Io(format!(
                        "session integrity verification failed for {}",
                        file_path.display()
                    )));
                };
                super::integrity::verify_hmac_file(
                    legacy_key,
                    content,
                    file_path,
                    &integrity_config,
                )
                .map_err(|err| match err {
                    super::integrity::IntegrityError::Rejected { file } => SessionStoreError::Io(
                        format!("session integrity verification failed for {}", file),
                    ),
                    other => {
                        tracing::warn!(
                            error_kind = integrity_error_kind(&other),
                            "session integrity verification issue"
                        );
                        SessionStoreError::Io(format!(
                            "session integrity verification failed for {}",
                            file_path.display()
                        ))
                    }
                })
            }
            Err(err) => {
                tracing::warn!(
                    error_kind = integrity_error_kind(&err),
                    "session integrity verification issue"
                );
                Ok(())
            }
        }
    }

    fn should_block_unknown_session_key_without_crypto(&self) -> bool {
        self.crypto.is_none()
            && self.encryption_mode.uses_encryption()
            && self.locked_session_count() > 0
    }

    fn encrypted_artifact_locked_without_crypto_bytes(&self, content: &[u8]) -> bool {
        self.crypto.is_none()
            && self.encryption_mode.uses_encryption()
            && super::crypto::has_encrypted_payload_prefix(content)
    }

    fn locked_filter_error(&self) -> SessionStoreError {
        if self.crypto.is_none() && self.encryption_mode.uses_encryption() {
            return Self::lock_message(
                "encrypted sessions are present; provide the config password to apply metadata-based session filters",
            );
        }
        Self::lock_message(
            "unavailable sessions are present; repair or unlock them to apply metadata-based session filters",
        )
    }

    fn rewrite_history_file_from_messages(
        &self,
        history_path: &Path,
        session_id: &str,
        messages: &[ChatMessage],
    ) -> Result<(), SessionStoreError> {
        let temp_path = history_path.with_extension("jsonl.tmp");
        {
            let file = Self::create_private_output_file(&temp_path)?;
            let mut writer = BufWriter::new(file);
            for message in messages {
                let encoded = self.encode_history_message(message)?;
                writer.write_all(&encoded)?;
                writeln!(writer)?;
            }
            writer.flush()?;
            writer
                .into_inner()
                .map_err(|e| std::io::Error::other(e.to_string()))?
                .sync_all()?;
        }
        self.prepare_history_hmac_for_path(&temp_path, history_path, session_id)?;
        fs::rename(&temp_path, history_path)?;
        self.commit_history_hmac(history_path, session_id)?;
        Ok(())
    }

    fn migrate_history_file_if_needed(
        &self,
        history_path: &Path,
        session_id: &str,
    ) -> Result<(), SessionStoreError> {
        if !self.encryption_active() || !history_path.exists() {
            return Ok(());
        }

        self.verify_history_hmac(history_path, session_id)?;
        let file = File::open(history_path)?;
        let reader = BufReader::new(file);
        let first_non_empty = reader
            .lines()
            .find_map(|line| match line {
                Ok(line) if !line.trim().is_empty() => Some(Ok(line)),
                Ok(_) => None,
                Err(err) => Some(Err(err)),
            })
            .transpose()?;

        let Some(line) = first_non_empty else {
            return Ok(());
        };

        if super::crypto::has_encrypted_payload_prefix(line.trim().as_bytes()) {
            return Ok(());
        }

        let messages = self.get_history(session_id, None, None)?;
        self.rewrite_history_file_from_messages(history_path, session_id, &messages)
    }

    fn migrate_archive_file_if_needed(&self, session_id: &str) -> Result<(), SessionStoreError> {
        if !self.encryption_active() {
            return Ok(());
        }

        let archive_path = self.archive_path(session_id)?;
        if !archive_path.exists() {
            return Ok(());
        }

        let _lock =
            FileLock::acquire(&archive_path).map_err(|e| SessionStoreError::Io(e.to_string()))?;
        let archive_content = fs::read(&archive_path)?;
        self.verify_archive_integrity(&archive_path, &archive_content)?;
        if super::crypto::has_encrypted_payload_prefix(&archive_content) {
            return Ok(());
        }

        let archived = self.decode_archive(session_id, &archive_content)?;
        self.write_archive_file(&archive_path, session_id, &archived)
    }

    fn migrate_session_artifacts_if_needed(
        &self,
        session: &Session,
        meta_needs_migration: bool,
    ) -> Result<(), SessionStoreError> {
        if !self.encryption_active() {
            return Ok(());
        }

        if meta_needs_migration {
            self.write_session_meta(session)?;
        }

        let history_path = self.session_history_path(&session.id)?;
        if history_path.exists() {
            let _history_lock = FileLock::acquire(&history_path)
                .map_err(|e| SessionStoreError::Io(e.to_string()))?;
            self.migrate_history_file_if_needed(&history_path, &session.id)?;
        }
        self.migrate_archive_file_if_needed(&session.id)
    }

    /// Validate session_id to prevent path traversal attacks.
    /// Session IDs must be valid UUIDs or alphanumeric slugs (letters, numbers, hyphens, underscores).
    fn validate_session_id(session_id: &str) -> Result<(), SessionStoreError> {
        // Reject empty IDs
        if session_id.is_empty() {
            return Err(SessionStoreError::InvalidSessionKey(
                "session_id cannot be empty".to_string(),
            ));
        }

        // Reject path traversal attempts
        if session_id.contains("..") || session_id.contains('/') || session_id.contains('\\') {
            return Err(SessionStoreError::InvalidSessionKey(
                "invalid session_id (path traversal detected)".to_string(),
            ));
        }

        // Allow only safe characters: alphanumeric, hyphens, underscores
        // This covers UUIDs (with hyphens) and typical slug formats
        if !session_id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err(SessionStoreError::InvalidSessionKey(
                "invalid session_id (must be alphanumeric with hyphens/underscores)".to_string(),
            ));
        }

        Ok(())
    }

    /// Get the metadata file path for a session (validates session_id)
    fn session_meta_path(&self, session_id: &str) -> Result<PathBuf, SessionStoreError> {
        Self::validate_session_id(session_id)?;
        Ok(self.base_path.join(format!("{}.json", session_id)))
    }

    /// Get the history file path for a session (validates session_id)
    fn session_history_path(&self, session_id: &str) -> Result<PathBuf, SessionStoreError> {
        Self::validate_session_id(session_id)?;
        Ok(self.base_path.join(format!("{}.jsonl", session_id)))
    }

    fn session_key_lock_path(&self, session_key: &str) -> PathBuf {
        let mut hasher = Sha256::new();
        hasher.update(session_key.as_bytes());
        let digest = hasher.finalize();
        self.base_path
            .join(format!("session-key-{}", hex::encode(digest)))
    }

    fn acquire_session_key_lock(&self, session_key: &str) -> Result<FileLock, SessionStoreError> {
        let lock_path = self.session_key_lock_path(session_key);
        FileLock::acquire(&lock_path).map_err(|e| SessionStoreError::Io(e.to_string()))
    }

    fn session_key_exists(&self, session_key: &str) -> Result<bool, SessionStoreError> {
        if self.key_to_id.read().contains_key(session_key) {
            return Ok(true);
        }

        self.load_sessions_from_disk()?;
        if self.key_to_id.read().contains_key(session_key) {
            return Ok(true);
        }

        if self.should_block_unknown_session_key_without_crypto() {
            return Err(Self::lock_message(
                "encrypted sessions are present; provide the config password before creating or resolving sessions by key",
            ));
        }

        Ok(false)
    }

    fn verify_history_hmac(
        &self,
        history_path: &Path,
        _session_id: &str,
    ) -> Result<(), SessionStoreError> {
        self.verify_integrity_path_with_compat(history_path)
    }

    fn verify_archive_integrity(
        &self,
        archive_path: &Path,
        archive_bytes: &[u8],
    ) -> Result<(), SessionStoreError> {
        self.verify_integrity_bytes_with_compat(archive_bytes, archive_path)
    }

    fn prepare_history_hmac_for_path(
        &self,
        source_path: &Path,
        history_path: &Path,
        session_id: &str,
    ) -> Result<(), SessionStoreError> {
        if let Some(ref key) = self.hmac_key {
            super::integrity::prepare_pending_hmac_file_for_path(key, source_path, history_path)
                .map_err(|e| {
                    SessionStoreError::Io(format!(
                        "failed to stage HMAC sidecar for history {}: {}",
                        session_id, e
                    ))
                })?;
        }
        Ok(())
    }

    fn prepare_history_hmac_for_appended_bytes(
        &self,
        history_path: &Path,
        appended: &[u8],
        session_id: &str,
    ) -> Result<(), SessionStoreError> {
        if let Some(ref key) = self.hmac_key {
            super::integrity::prepare_pending_hmac_file_for_appended_bytes(
                key,
                history_path,
                appended,
            )
            .map_err(|e| {
                SessionStoreError::Io(format!(
                    "failed to stage HMAC sidecar for history {}: {}",
                    session_id, e
                ))
            })?;
        }
        Ok(())
    }

    fn commit_history_hmac(
        &self,
        history_path: &Path,
        session_id: &str,
    ) -> Result<(), SessionStoreError> {
        if self.hmac_key.is_some() {
            super::integrity::commit_pending_hmac_sidecar(history_path).map_err(|e| {
                SessionStoreError::Io(format!(
                    "failed to commit HMAC sidecar for history {}: {}",
                    session_id, e
                ))
            })?;
        }
        Ok(())
    }

    fn prepare_archive_hmac(
        &self,
        archive_path: &Path,
        archive_bytes: &[u8],
        session_id: &str,
    ) -> Result<(), SessionStoreError> {
        if let Some(ref key) = self.hmac_key {
            super::integrity::prepare_pending_hmac_file(key, archive_bytes, archive_path).map_err(
                |e| {
                    SessionStoreError::Io(format!(
                        "failed to stage HMAC sidecar for archive {}: {}",
                        session_id, e
                    ))
                },
            )?;
        }
        Ok(())
    }

    fn commit_archive_hmac(
        &self,
        archive_path: &Path,
        session_id: &str,
    ) -> Result<(), SessionStoreError> {
        if self.hmac_key.is_some() {
            super::integrity::commit_pending_hmac_sidecar(archive_path).map_err(|e| {
                SessionStoreError::Io(format!(
                    "failed to commit HMAC sidecar for archive {}: {}",
                    session_id, e
                ))
            })?;
        }
        Ok(())
    }

    fn delete_archive_hmac(
        &self,
        archive_path: &Path,
        session_id: &str,
    ) -> Result<(), SessionStoreError> {
        if let Err(e) = super::integrity::delete_hmac_sidecar(archive_path) {
            return Err(SessionStoreError::Io(format!(
                "failed to remove HMAC sidecar for archive {}: {}",
                session_id, e
            )));
        }
        Ok(())
    }

    fn write_archive_file(
        &self,
        archive_path: &Path,
        session_id: &str,
        archived: &ArchivedSession,
    ) -> Result<(), SessionStoreError> {
        let temp_path = archive_path.with_extension("tmp");
        let encoded = self.encode_archive(session_id, archived)?;

        {
            let file = Self::create_private_output_file(&temp_path)?;
            let mut writer = BufWriter::new(file);
            writer.write_all(&encoded)?;
            writer.flush()?;
            writer
                .into_inner()
                .map_err(|e| std::io::Error::other(e.to_string()))?
                .sync_all()?;
        }

        self.prepare_archive_hmac(archive_path, &encoded, session_id)?;
        fs::rename(&temp_path, archive_path)?;
        self.commit_archive_hmac(archive_path, session_id)
    }

    fn delete_history_hmac(
        &self,
        history_path: &Path,
        session_id: &str,
    ) -> Result<(), SessionStoreError> {
        if let Err(e) = super::integrity::delete_hmac_sidecar(history_path) {
            return Err(SessionStoreError::Io(format!(
                "failed to remove HMAC sidecar for history {}: {}",
                session_id, e
            )));
        }
        Ok(())
    }

    /// Create a new session
    pub fn create_session(
        &self,
        agent_id: impl Into<String>,
        metadata: SessionMetadata,
    ) -> Result<Session, SessionStoreError> {
        self.ensure_base_dir()?;

        let session = Session::new(agent_id, metadata);

        let _lock = self.acquire_session_key_lock(&session.session_key)?;

        // Check for existing session with same key (cache + disk)
        if self.session_key_exists(&session.session_key)? {
            return Err(SessionStoreError::AlreadyExists(session.session_key));
        }

        // Persist to disk
        self.write_session_meta(&session)?;

        // Update caches
        {
            let mut sessions = self.sessions.write();
            let mut key_map = self.key_to_id.write();
            key_map.insert(session.session_key.clone(), session.id.clone());
            sessions.insert(
                session.id.clone(),
                self.new_cached_session(session.clone(), false),
            );
        }

        Ok(session)
    }

    /// Get a session by ID
    pub fn get_session(&self, session_id: &str) -> Result<Session, SessionStoreError> {
        // Validate session_id upfront for defense in depth
        Self::validate_session_id(session_id)?;

        // Check cache first
        {
            let sessions = self.sessions.read();
            if let Some(cached) = sessions.get(session_id) {
                return Ok(cached.session.clone());
            }
        }

        // Load from disk
        self.load_session(session_id)
    }

    /// Get a session by session key
    pub fn get_session_by_key(&self, session_key: &str) -> Result<Session, SessionStoreError> {
        // Check key map
        {
            let key_map = self.key_to_id.read();
            if let Some(id) = key_map.get(session_key) {
                return self.get_session(id);
            }
        }

        // Scan disk for matching session key
        self.load_sessions_from_disk()?;

        let key_map = self.key_to_id.read();
        if let Some(id) = key_map.get(session_key) {
            self.get_session(id)
        } else {
            drop(key_map);
            if self.should_block_unknown_session_key_without_crypto() {
                Err(Self::lock_message(
                    "encrypted sessions are present; provide the config password before resolving sessions by key",
                ))
            } else {
                Err(SessionStoreError::NotFound(session_key.to_string()))
            }
        }
    }

    /// Get or create a session by session key
    pub fn get_or_create_session(
        &self,
        session_key: impl Into<String>,
        metadata: SessionMetadata,
    ) -> Result<Session, SessionStoreError> {
        let key = session_key.into();

        self.ensure_base_dir()?;
        let _lock = self.acquire_session_key_lock(&key)?;

        match self.get_session_by_key(&key) {
            Ok(session) => Ok(session),
            Err(SessionStoreError::NotFound(_)) => {
                let session = Session::with_session_key(key, metadata);
                self.write_session_meta(&session)?;

                let mut sessions = self.sessions.write();
                let mut key_map = self.key_to_id.write();
                key_map.insert(session.session_key.clone(), session.id.clone());
                sessions.insert(
                    session.id.clone(),
                    self.new_cached_session(session.clone(), false),
                );

                Ok(session)
            }
            Err(e) => Err(e),
        }
    }

    /// List sessions with optional filtering
    pub fn list_sessions(&self, filter: SessionFilter) -> Result<Vec<Session>, SessionStoreError> {
        let entries = self.list_session_entries(filter.clone())?;
        Ok(entries
            .into_iter()
            .filter_map(SessionListEntry::into_session)
            .collect())
    }

    /// List sessions, surfacing encrypted-but-locked sessions as stubs when allowed.
    pub fn list_session_entries(
        &self,
        filter: SessionFilter,
    ) -> Result<Vec<SessionListEntry>, SessionStoreError> {
        self.ensure_required_encryption_available()?;
        self.load_sessions_from_disk()?;

        let mut available: Vec<SessionListEntry> = {
            let sessions = self.sessions.read();
            sessions
                .values()
                .map(|c| c.session.clone())
                .filter(|s| filter.matches(s))
                .map(SessionListEntry::available)
                .collect()
        };

        let mut locked = Vec::new();
        if self.locked_session_count() > 0 {
            if filter.requires_decrypted_metadata() {
                return Err(self.locked_filter_error());
            }
            locked.extend(self.locked_session_entries_snapshot());
        }

        available.extend(locked);
        available.sort_by(|a, b| b.updated_at.unwrap_or(0).cmp(&a.updated_at.unwrap_or(0)));

        let offset = filter.offset.unwrap_or(0);
        let limit = filter.limit.unwrap_or(usize::MAX);
        Ok(available.into_iter().skip(offset).take(limit).collect())
    }

    /// Update session metadata
    pub fn patch_session(
        &self,
        session_id: &str,
        updates: SessionMetadata,
    ) -> Result<Session, SessionStoreError> {
        let mut session = self.get_session(session_id)?;

        // Apply updates
        if updates.name.is_some() {
            session.metadata.name = updates.name;
        }
        if updates.description.is_some() {
            session.metadata.description = updates.description;
        }
        if updates.agent_id.is_some() {
            session.metadata.agent_id = updates.agent_id;
        }
        if updates.channel.is_some() {
            session.metadata.channel = updates.channel;
        }
        if updates.chat_id.is_some() {
            session.metadata.chat_id = updates.chat_id;
        }
        if updates.user_id.is_some() {
            session.metadata.user_id = updates.user_id;
        }
        if updates.route.is_some() {
            session.metadata.route = updates.route;
        }
        if updates.model.is_some() {
            session.metadata.model = updates.model;
        }
        if updates.thinking_level.is_some() {
            session.metadata.thinking_level = updates.thinking_level;
        }
        if !updates.tags.is_empty() {
            session.metadata.tags = updates.tags;
        }
        if updates.extra.is_some() {
            session.metadata.extra = updates.extra;
        }

        let now = now_millis();
        session.updated_at = now.max(session.updated_at.saturating_add(1));

        // Persist
        self.write_session_meta(&session)?;

        // Update cache
        {
            let mut sessions = self.sessions.write();
            if let Some(cached) = sessions.get_mut(session_id) {
                cached.session = session.clone();
                cached.dirty = false;
            }
        }

        Ok(session)
    }

    /// Reset a session (clear history but keep metadata)
    pub fn reset_session(&self, session_id: &str) -> Result<Session, SessionStoreError> {
        let mut session = self.get_session(session_id)?;

        // Delete history file
        let history_path = self.session_history_path(session_id)?;
        if history_path.exists() {
            fs::remove_file(&history_path)?;
        }
        self.delete_history_hmac(&history_path, session_id)?;

        // Reset message count and compaction metadata
        session.message_count = 0;
        session.metadata.compaction = CompactionMetadata::default();
        session.updated_at = now_millis();
        session.last_activity_at = Some(now_millis());

        // Persist
        self.write_session_meta(&session)?;

        // Update cache
        {
            let mut sessions = self.sessions.write();
            if let Some(cached) = sessions.get_mut(session_id) {
                cached.session = session.clone();
                cached.dirty = false;
            }
        }

        Ok(session)
    }

    /// Delete a session and its history
    pub fn delete_session(&self, session_id: &str) -> Result<(), SessionStoreError> {
        let session = self.get_session(session_id)?;

        // Delete files
        let meta_path = self.session_meta_path(session_id)?;
        let history_path = self.session_history_path(session_id)?;

        if meta_path.exists() {
            fs::remove_file(&meta_path)?;
        }
        if history_path.exists() {
            fs::remove_file(&history_path)?;
        }
        if let Err(e) = super::integrity::delete_hmac_sidecar(&meta_path) {
            return Err(SessionStoreError::Io(format!(
                "failed to remove HMAC sidecar for session {}: {}",
                session_id, e
            )));
        }
        self.delete_history_hmac(&history_path, session_id)?;

        // Remove from caches
        {
            let mut sessions = self.sessions.write();
            let mut key_map = self.key_to_id.write();
            sessions.remove(session_id);
            key_map.remove(&session.session_key);
        }

        Ok(())
    }

    /// Export all data for a user (GDPR Art. 20 — data portability).
    ///
    /// Returns all sessions and their chat histories for the given user_id
    /// as a portable JSON value.
    pub fn export_user_data(&self, user_id: &str) -> Result<serde_json::Value, SessionStoreError> {
        if user_id.trim().is_empty() {
            return Err(SessionStoreError::InvalidUserId(
                "userId must not be empty or whitespace-only".to_string(),
            ));
        }
        let filter = SessionFilter::new().with_user_id(user_id);
        let sessions = self.list_sessions(filter)?;

        let mut exported = Vec::new();
        let mut warnings: Vec<String> = Vec::new();
        for session in &sessions {
            match self.get_history(&session.id, None, None) {
                Ok(history) => {
                    exported.push(serde_json::json!({
                        "session": session,
                        "messages": history,
                    }));
                }
                Err(e) => {
                    warn!(
                        user_id = %user_id,
                        error_kind = session_store_error_kind(&e),
                        "failed to export session history during user data export"
                    );
                    warnings.push(format!(
                        "failed to export session {}: {}",
                        session.id,
                        session_store_error_export_warning(&e)
                    ));
                }
            }
        }

        Ok(serde_json::json!({
            "user_id": user_id,
            "exported_at": chrono::Utc::now().to_rfc3339(),
            "session_count": exported.len(),
            "sessions": exported,
            "warnings": warnings,
        }))
    }

    /// Delete all data for a user (GDPR Art. 17 — right to erasure).
    ///
    /// Deletes all sessions and their histories for the given user_id.
    /// Uses best-effort: logs individual failures and continues.
    /// Returns the number of sessions successfully deleted.
    pub fn purge_user_data(&self, user_id: &str) -> Result<(usize, usize), SessionStoreError> {
        if user_id.trim().is_empty() {
            return Err(SessionStoreError::InvalidUserId(
                "userId must not be empty or whitespace-only".to_string(),
            ));
        }
        let filter = SessionFilter::new().with_user_id(user_id);
        let sessions = self.list_sessions(filter)?;
        let total = sessions.len();
        let mut deleted = 0;

        for session in &sessions {
            if let Err(e) = self.delete_session(&session.id) {
                warn!(
                    user_id = %user_id,
                    error_kind = session_store_error_kind(&e),
                    "failed to delete session during user purge"
                );
            } else {
                deleted += 1;
            }
        }

        Ok((deleted, total))
    }

    /// Delete sessions that have not been updated within the given retention period.
    ///
    /// Returns the number of sessions deleted.
    pub fn cleanup_expired(&self, retention_days: u32) -> Result<usize, SessionStoreError> {
        let cutoff_ms = now_millis() - (retention_days as i64) * 24 * 60 * 60 * 1000;
        let filter = SessionFilter {
            updated_before: Some(cutoff_ms),
            ..SessionFilter::default()
        };
        let expired = self.list_sessions(filter)?;
        let count = expired.len();

        for session in &expired {
            if let Err(e) = self.delete_session(&session.id) {
                warn!(
                    error_kind = session_store_error_kind(&e),
                    "failed to delete expired session"
                );
            }
        }

        if count > 0 {
            tracing::info!(
                deleted = count,
                retention_days,
                "cleaned up expired sessions"
            );
        }

        Ok(count)
    }

    /// Append a message to session history
    ///
    /// Returns an error if the session is archived (read-only).
    pub fn append_message(&self, message: ChatMessage) -> Result<(), SessionStoreError> {
        self.ensure_base_dir()?;
        self.ensure_required_encryption_available()?;

        let session_id = message.session_id.clone();

        // Check session status - archived sessions are read-only.
        // Use get_session to check both cache and disk, ensuring the guard
        // works even if the session hasn't been loaded into memory yet.
        if let Ok(session) = self.get_session(&session_id) {
            if session.status == SessionStatus::Archived {
                return Err(SessionStoreError::AlreadyArchived(session_id));
            }
        }

        // Append to history file (JSONL format)
        let history_path = self.session_history_path(&session_id)?;
        let _lock =
            FileLock::acquire(&history_path).map_err(|e| SessionStoreError::Io(e.to_string()))?;
        if self.encryption_active() && !self.history_migration_satisfied_in_cache(&session_id) {
            self.migrate_history_file_if_needed(&history_path, &session_id)?;
            self.mark_history_migration_satisfied(&session_id);
        }
        let encoded = self.encode_history_message(&message)?;
        let mut appended = encoded;
        appended.push(b'\n');
        self.prepare_history_hmac_for_appended_bytes(&history_path, &appended, &session_id)?;
        let file = Self::open_private_append_file(&history_path)?;
        let mut writer = BufWriter::new(file);
        writer.write_all(&appended)?;
        writer.flush()?;
        writer
            .into_inner()
            .map_err(|e| std::io::Error::other(e.to_string()))?
            .sync_all()?;

        self.commit_history_hmac(&history_path, &session_id)?;

        // Update session message count
        self.increment_message_count(&session_id)?;

        Ok(())
    }

    /// Append multiple messages in a single file open/write/close cycle.
    /// More efficient than calling `append_message` repeatedly for batch writes
    /// (e.g., assistant message + tool results in the executor).
    pub fn append_messages(&self, messages: &[ChatMessage]) -> Result<(), SessionStoreError> {
        if messages.is_empty() {
            return Ok(());
        }
        self.ensure_base_dir()?;
        self.ensure_required_encryption_available()?;

        let session_id = &messages[0].session_id;

        // Check session status
        if let Ok(session) = self.get_session(session_id) {
            if session.status == SessionStatus::Archived {
                return Err(SessionStoreError::AlreadyArchived(session_id.to_string()));
            }
        }

        let history_path = self.session_history_path(session_id)?;
        let _lock =
            FileLock::acquire(&history_path).map_err(|e| SessionStoreError::Io(e.to_string()))?;
        if self.encryption_active() && !self.history_migration_satisfied_in_cache(session_id) {
            self.migrate_history_file_if_needed(&history_path, session_id)?;
            self.mark_history_migration_satisfied(session_id);
        }
        let mut appended = Vec::new();

        for msg in messages {
            let encoded = self.encode_history_message(msg)?;
            appended.extend_from_slice(&encoded);
            appended.push(b'\n');
        }
        self.prepare_history_hmac_for_appended_bytes(&history_path, &appended, session_id)?;
        let file = Self::open_private_append_file(&history_path)?;
        let mut writer = BufWriter::new(file);
        writer.write_all(&appended)?;
        writer.flush()?;
        writer
            .into_inner()
            .map_err(|e| std::io::Error::other(e.to_string()))?
            .sync_all()?;

        self.commit_history_hmac(&history_path, session_id)?;

        // Update message count
        for _ in messages {
            self.increment_message_count(session_id)?;
        }

        Ok(())
    }

    /// Get chat history for a session
    pub fn get_history(
        &self,
        session_id: &str,
        limit: Option<usize>,
        before_id: Option<&str>,
    ) -> Result<Vec<ChatMessage>, SessionStoreError> {
        self.ensure_required_encryption_available()?;
        let history_path = self.session_history_path(session_id)?;

        if !history_path.exists() {
            return Ok(Vec::new());
        }

        self.verify_history_hmac(&history_path, session_id)?;

        let file = File::open(&history_path)?;
        let reader = BufReader::new(file);

        let mut messages: Vec<ChatMessage> = Vec::new();
        let mut found_before = before_id.is_none();

        for line in reader.lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            let line_bytes = line.as_bytes();
            let encrypted_line = super::crypto::has_encrypted_payload_prefix(line_bytes);

            let msg = match self.decode_history_message(session_id, line_bytes, encrypted_line) {
                Ok(m) => m,
                Err(SessionStoreError::Locked(message)) => {
                    return Err(SessionStoreError::Locked(message));
                }
                Err(SessionStoreError::DecryptionFailed(message)) => {
                    return Err(SessionStoreError::DecryptionFailed(message));
                }
                Err(err) if encrypted_line => {
                    return Err(SessionStoreError::Crypto(format!(
                        "invalid encrypted session history line: {err}"
                    )));
                }
                Err(_) => {
                    tracing::warn!(
                        error_kind = "invalid_jsonl",
                        "skipping corrupt JSONL line in session history"
                    );
                    continue;
                }
            };

            if !found_before {
                if Some(msg.id.as_str()) == before_id {
                    found_before = true;
                }
                continue;
            }

            messages.push(msg);
        }

        // Apply limit (from end)
        if let Some(limit) = limit {
            if messages.len() > limit {
                messages = messages.into_iter().rev().take(limit).rev().collect();
            }
        }

        Ok(messages)
    }

    /// Clear all history for a session
    pub fn clear_history(&self, session_id: &str) -> Result<(), SessionStoreError> {
        let _ = self.get_session(session_id)?;
        let history_path = self.session_history_path(session_id)?;

        if history_path.exists() {
            fs::remove_file(&history_path)?;
        }
        self.delete_history_hmac(&history_path, session_id)?;

        // Reset message count
        {
            let mut sessions = self.sessions.write();
            if let Some(cached) = sessions.get_mut(session_id) {
                cached.session.message_count = 0;
                cached.session.updated_at = now_millis();
                cached.dirty = true;
            }
        }

        self.flush_session(session_id)?;

        Ok(())
    }

    /// Compact a session by summarizing old messages
    ///
    /// This replaces old messages with a summary, keeping recent messages intact.
    /// The summary_fn is called with the messages to summarize and should return
    /// a summary text.
    pub fn compact_session<F>(
        &self,
        session_id: &str,
        keep_recent: usize,
        summary_fn: F,
    ) -> Result<CompactionMetadata, SessionStoreError>
    where
        F: FnOnce(&[ChatMessage]) -> String,
    {
        let mut session = self.get_session(session_id)?;

        if session.status == SessionStatus::Archived {
            return Err(SessionStoreError::AlreadyArchived(session_id.to_string()));
        }

        if session.status == SessionStatus::Compacting {
            return Err(SessionStoreError::CompactionInProgress(
                session_id.to_string(),
            ));
        }

        // Acquire lock on the history file for the duration of compaction
        let history_path = self.session_history_path(session_id)?;
        let _lock =
            FileLock::acquire(&history_path).map_err(|e| SessionStoreError::Io(e.to_string()))?;

        // Mark as compacting
        session.status = SessionStatus::Compacting;
        self.write_session_meta(&session)?;

        // Read all messages
        let messages = self.get_history(session_id, None, None)?;

        if messages.len() <= keep_recent {
            // Not enough messages to compact
            session.status = SessionStatus::Active;
            self.write_session_meta(&session)?;
            return Ok(session.metadata.compaction);
        }

        // Split into messages to compact and messages to keep
        let compact_count = messages.len() - keep_recent;
        let to_compact: Vec<_> = messages.iter().take(compact_count).cloned().collect();
        let to_keep: Vec<_> = messages.into_iter().skip(compact_count).collect();

        // Generate summary
        let summary = summary_fn(&to_compact);

        let mut rewritten = Vec::with_capacity(to_keep.len() + 1);
        rewritten.push(ChatMessage::system(session_id, &summary));
        rewritten.extend(to_keep.iter().cloned());
        self.rewrite_history_file_from_messages(&history_path, session_id, &rewritten)?;

        // Update session metadata
        session.status = SessionStatus::Active;
        session.message_count = to_keep.len() + 1; // +1 for summary
        session.metadata.compaction.messages_compacted += compact_count;
        session.metadata.compaction.last_compacted_at = Some(now_millis());
        session.metadata.compaction.compaction_count += 1;
        session.metadata.compaction.last_summary = Some(summary);
        session.metadata.compaction.original_message_count += compact_count;
        session.updated_at = now_millis();

        self.write_session_meta(&session)?;

        // Update cache
        {
            let mut sessions = self.sessions.write();
            if let Some(cached) = sessions.get_mut(session_id) {
                cached.session = session.clone();
                cached.dirty = false;
            }
        }

        Ok(session.metadata.compaction)
    }

    /// Auto-compact hook - triggers compaction if message count exceeds threshold
    pub fn auto_compact_if_needed<F>(
        &self,
        session_id: &str,
        keep_recent: usize,
        summary_fn: F,
    ) -> Result<Option<CompactionMetadata>, SessionStoreError>
    where
        F: FnOnce(&[ChatMessage]) -> String,
    {
        let session = self.get_session(session_id)?;

        if session.message_count >= self.compact_threshold {
            Ok(Some(self.compact_session(
                session_id,
                keep_recent,
                summary_fn,
            )?))
        } else {
            Ok(None)
        }
    }

    // ========================================================================
    // Archive Operations
    // ========================================================================

    /// Get the archive directory path
    fn archive_dir(&self) -> PathBuf {
        self.base_path.join("archives")
    }

    /// Get the archive file path for a session
    fn archive_path(&self, session_id: &str) -> Result<PathBuf, SessionStoreError> {
        Self::validate_session_id(session_id)?;
        Ok(self
            .archive_dir()
            .join(format!("{}.archive.json", session_id)))
    }

    /// Ensure the archive directory exists
    fn ensure_archive_dir(&self) -> Result<(), SessionStoreError> {
        let archive_dir = self.archive_dir();
        if !archive_dir.exists() {
            fs::create_dir_all(&archive_dir)?;
        }
        Ok(())
    }

    /// Archive a session to a compressed file
    ///
    /// This creates an archive file containing all session metadata and messages.
    /// The session status is set to Archived, making it read-only.
    ///
    /// # Arguments
    /// * `session_id` - The session to archive
    /// * `delete_history` - If true, delete the history file after archiving (keeps metadata)
    ///
    /// # Returns
    /// Archive result with path and stats
    pub fn archive_session(
        &self,
        session_id: &str,
        delete_history: bool,
    ) -> Result<ArchiveResult, SessionStoreError> {
        self.ensure_required_encryption_available()?;
        let mut session = self.get_session(session_id)?;

        // Don't archive if already archived
        if session.status == SessionStatus::Archived {
            return Err(SessionStoreError::AlreadyArchived(session_id.to_string()));
        }

        // Acquire lock on the history file for the duration of archiving
        let history_path = self.session_history_path(session_id)?;
        let _lock =
            FileLock::acquire(&history_path).map_err(|e| SessionStoreError::Io(e.to_string()))?;

        self.ensure_archive_dir()?;

        // Get all messages
        let messages = self.get_history(session_id, None, None)?;
        let message_count = messages.len();

        // Create archive structure
        let archived = ArchivedSession {
            session: session.clone(),
            messages,
            archived_at: now_millis(),
            version: 1,
        };

        let archive_path = self.archive_path(session_id)?;
        self.write_archive_file(&archive_path, session_id, &archived)?;

        // Get archive size
        let archive_size = fs::metadata(&archive_path).map(|m| m.len()).unwrap_or(0);

        // Update session status to archived
        session.status = SessionStatus::Archived;
        session.updated_at = now_millis();
        self.write_session_meta(&session)?;

        // Optionally delete history file to save space
        if delete_history {
            let history_path = self.session_history_path(session_id)?;
            if history_path.exists() {
                fs::remove_file(&history_path)?;
            }
            self.delete_history_hmac(&history_path, session_id)?;
        } else if self.encryption_active() {
            self.rewrite_history_file_from_messages(&history_path, session_id, &archived.messages)?;
        }

        // Update cache
        {
            let mut sessions = self.sessions.write();
            if let Some(cached) = sessions.get_mut(session_id) {
                cached.session = session;
                cached.dirty = false;
            }
        }

        Ok(ArchiveResult {
            session_id: session_id.to_string(),
            archive_path: archive_path.display().to_string(),
            message_count,
            archive_size,
            archived_at: archived.archived_at,
            history_deleted: delete_history,
        })
    }

    /// Restore a session from archive
    ///
    /// This reads the archive file and restores the session history.
    /// The session status is set back to Active.
    ///
    /// # Arguments
    /// * `session_id` - The session to restore
    ///
    /// # Returns
    /// Restore result with stats
    pub fn restore_session(&self, session_id: &str) -> Result<RestoreResult, SessionStoreError> {
        self.ensure_required_encryption_available()?;
        let mut session = self.get_session(session_id)?;

        // Only restore archived sessions
        if session.status != SessionStatus::Archived {
            return Err(SessionStoreError::NotArchived(session_id.to_string()));
        }

        // Read archive file
        let archive_path = self.archive_path(session_id)?;
        if !archive_path.exists() {
            return Err(SessionStoreError::ArchiveNotFound(session_id.to_string()));
        }

        let archive_content = fs::read(&archive_path)?;
        self.verify_archive_integrity(&archive_path, &archive_content)?;
        let archive_was_plaintext = !super::crypto::has_encrypted_payload_prefix(&archive_content);
        let archived = self.decode_archive(session_id, &archive_content)?;

        let history_path = self.session_history_path(session_id)?;
        self.rewrite_history_file_from_messages(&history_path, session_id, &archived.messages)?;

        if self.encryption_active() && archive_was_plaintext {
            self.write_archive_file(&archive_path, session_id, &archived)?;
        }

        let message_count = archived.messages.len();

        // Update session status to active
        session.status = SessionStatus::Active;
        session.message_count = message_count;
        session.updated_at = now_millis();
        session.last_activity_at = Some(now_millis());
        self.write_session_meta(&session)?;

        // Update cache
        {
            let mut sessions = self.sessions.write();
            if let Some(cached) = sessions.get_mut(session_id) {
                cached.session = session;
                cached.dirty = false;
            }
        }

        Ok(RestoreResult {
            session_id: session_id.to_string(),
            message_count,
            restored_at: now_millis(),
        })
    }

    /// List all archived sessions
    ///
    /// Returns sessions with Archived status along with archive file info
    pub fn list_archived_sessions(&self) -> Result<Vec<(Session, Option<u64>)>, SessionStoreError> {
        self.load_sessions_from_disk()?;

        let sessions = self.sessions.read();
        let mut result = Vec::new();

        for cached in sessions.values() {
            if cached.session.status == SessionStatus::Archived {
                // Skip sessions with invalid IDs (shouldn't happen, but defensive)
                let archive_path = match self.archive_path(&cached.session.id) {
                    Ok(p) => p,
                    Err(_) => continue,
                };
                let archive_size = if archive_path.exists() {
                    fs::metadata(&archive_path).ok().map(|m| m.len())
                } else {
                    None
                };
                result.push((cached.session.clone(), archive_size));
            }
        }

        // Sort by updated_at descending
        result.sort_by(|a, b| b.0.updated_at.cmp(&a.0.updated_at));

        Ok(result)
    }

    /// Delete an archive file without restoring
    ///
    /// This removes the archive file but keeps the session metadata.
    /// Use this to clean up archives that are no longer needed.
    pub fn delete_archive(&self, session_id: &str) -> Result<bool, SessionStoreError> {
        self.ensure_required_encryption_available()?;
        let _ = self.get_session(session_id)?;
        let archive_path = self.archive_path(session_id)?;
        let existed = archive_path.exists();
        if existed {
            fs::remove_file(&archive_path)?;
        }
        self.delete_archive_hmac(&archive_path, session_id)?;
        Ok(existed)
    }

    /// Get archive info for a session
    pub fn get_archive_info(
        &self,
        session_id: &str,
    ) -> Result<Option<(PathBuf, u64, i64)>, SessionStoreError> {
        self.ensure_required_encryption_available()?;
        let archive_path = self.archive_path(session_id)?;
        if !archive_path.exists() {
            return Ok(None);
        }

        let metadata = fs::metadata(&archive_path)?;
        let size = metadata.len();

        // Read archived_at from the file
        let content = fs::read(&archive_path)?;
        self.verify_archive_integrity(&archive_path, &content)?;
        let archived = self.decode_archive(session_id, &content)?;

        Ok(Some((archive_path, size, archived.archived_at)))
    }

    /// Archive old inactive sessions automatically
    ///
    /// Archives sessions that haven't been updated within the given threshold.
    ///
    /// # Arguments
    /// * `inactive_days` - Archive sessions not updated in this many days
    /// * `delete_history` - Whether to delete history after archiving
    ///
    /// # Returns
    /// Number of sessions archived
    pub fn archive_inactive_sessions(
        &self,
        inactive_days: u32,
        delete_history: bool,
    ) -> Result<Vec<ArchiveResult>, SessionStoreError> {
        self.load_sessions_from_disk()?;

        let cutoff = now_millis() - (inactive_days as i64 * 24 * 60 * 60 * 1000);
        let to_archive: Vec<String> = {
            let sessions = self.sessions.read();
            sessions
                .values()
                .filter(|c| {
                    c.session.status == SessionStatus::Active && c.session.updated_at < cutoff
                })
                .map(|c| c.session.id.clone())
                .collect()
        };

        let mut results = Vec::new();
        for session_id in to_archive {
            match self.archive_session(&session_id, delete_history) {
                Ok(result) => results.push(result),
                Err(e) => {
                    // Log but continue with other sessions
                    warn!(
                        error_kind = session_store_error_kind(&e),
                        "failed to archive inactive session"
                    );
                }
            }
        }

        Ok(results)
    }

    /// Load a session from disk
    fn load_session(&self, session_id: &str) -> Result<Session, SessionStoreError> {
        self.load_session_with_locked_tracking(session_id, true)
    }

    fn load_session_with_locked_tracking(
        &self,
        session_id: &str,
        update_locked_scan_state: bool,
    ) -> Result<Session, SessionStoreError> {
        self.ensure_required_encryption_available()?;
        let meta_path = self.session_meta_path(session_id)?;

        if !meta_path.exists() {
            return Err(SessionStoreError::NotFound(session_id.to_string()));
        }

        let content = fs::read(&meta_path)?;
        let meta_was_encrypted = super::crypto::has_encrypted_payload_prefix(&content);
        let meta_needs_migration = !meta_was_encrypted;

        // Verify session integrity if HMAC key is configured
        self.verify_integrity_bytes_with_compat(&content, &meta_path)?;

        let session = match self.decode_session_metadata(session_id, &content) {
            Ok(session) => session,
            Err(SessionStoreError::Locked(message)) => {
                if update_locked_scan_state {
                    self.record_locked_session_entry(
                        session_id.to_string(),
                        Self::file_updated_at(&meta_path),
                    );
                }
                return Err(SessionStoreError::Locked(message));
            }
            Err(err @ SessionStoreError::Crypto(_)) if meta_was_encrypted => {
                if update_locked_scan_state {
                    self.record_locked_session_entry(
                        session_id.to_string(),
                        Self::file_updated_at(&meta_path),
                    );
                }
                return Err(err);
            }
            Err(err) => return Err(err),
        };

        self.migrate_session_artifacts_if_needed(&session, meta_needs_migration)?;

        if update_locked_scan_state {
            self.clear_locked_session_entry(session_id);
        }

        // Update caches
        {
            let mut sessions = self.sessions.write();
            let mut key_map = self.key_to_id.write();
            key_map.insert(session.session_key.clone(), session.id.clone());
            sessions.insert(
                session.id.clone(),
                self.new_cached_session(session.clone(), false),
            );
        }

        Ok(session)
    }

    /// Load all sessions from disk into cache
    fn load_sessions_from_disk(&self) -> Result<(), SessionStoreError> {
        self.ensure_required_encryption_available()?;
        if !self.base_path.exists() {
            self.replace_locked_session_entries(HashMap::new());
            return Ok(());
        }

        let entries = fs::read_dir(&self.base_path)?;
        let mut locked_session_entries = HashMap::new();

        for entry in entries {
            let entry = entry?;
            let path = entry.path();

            if path.extension().and_then(|s| s.to_str()) == Some("json") {
                if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                    // Skip if already cached
                    {
                        let sessions = self.sessions.read();
                        if sessions.contains_key(stem) {
                            continue;
                        }
                    }

                    match self.load_session_with_locked_tracking(stem, false) {
                        Ok(_) => {}
                        Err(SessionStoreError::Locked(_)) => {
                            locked_session_entries.insert(
                                stem.to_string(),
                                SessionListEntry::locked(
                                    stem.to_string(),
                                    Self::file_updated_at(&path),
                                ),
                            );
                        }
                        Err(err @ SessionStoreError::DecryptionFailed(_))
                            if self.crypto.is_some() =>
                        {
                            let manifest_locked = self
                                .crypto
                                .as_ref()
                                .is_some_and(|crypto| !crypto.manifest_integrity_valid());
                            if manifest_locked {
                                return Err(err);
                            }
                            locked_session_entries.insert(
                                stem.to_string(),
                                SessionListEntry::locked(
                                    stem.to_string(),
                                    Self::file_updated_at(&path),
                                ),
                            );
                            tracing::warn!(
                                error_kind = session_store_error_kind(&err),
                                "skipping undecryptable encrypted session metadata during scan"
                            );
                        }
                        Err(err @ SessionStoreError::Crypto(_)) if self.crypto.is_some() => {
                            locked_session_entries.insert(
                                stem.to_string(),
                                SessionListEntry::locked(
                                    stem.to_string(),
                                    Self::file_updated_at(&path),
                                ),
                            );
                            tracing::warn!(
                                error_kind = session_store_error_kind(&err),
                                "skipping unreadable encrypted session metadata during scan"
                            );
                        }
                        Err(err) => {
                            tracing::warn!(
                                error_kind = session_store_error_kind(&err),
                                "failed to load session metadata from disk"
                            );
                        }
                    }
                }
            }
        }

        self.replace_locked_session_entries(locked_session_entries);
        Ok(())
    }

    /// Write session metadata to disk
    fn write_session_meta(&self, session: &Session) -> Result<(), SessionStoreError> {
        self.ensure_base_dir()?;
        self.ensure_required_encryption_available()?;

        let meta_path = self.session_meta_path(&session.id)?;
        let _lock =
            FileLock::acquire(&meta_path).map_err(|e| SessionStoreError::Io(e.to_string()))?;

        let temp_path = meta_path.with_extension("json.tmp");

        // Serialize to bytes so we can reuse for HMAC
        let serialized = self.encode_session_metadata(session)?;

        // Write to temp file first, then sync
        {
            let file = Self::create_private_output_file(&temp_path)?;
            let mut writer = BufWriter::new(file);
            writer.write_all(&serialized)?;
            writer.flush()?;
            writer
                .into_inner()
                .map_err(|e| std::io::Error::other(e.to_string()))?
                .sync_all()?;
        }

        if let Some(ref key) = self.hmac_key {
            super::integrity::prepare_pending_hmac_file(key, &serialized, &meta_path).map_err(
                |e| {
                    SessionStoreError::Io(format!(
                        "failed to stage HMAC sidecar for session {}: {}",
                        session.id, e
                    ))
                },
            )?;
        }

        // Atomic rename
        fs::rename(&temp_path, &meta_path)?;

        // Commit HMAC sidecar if integrity is enabled.
        if self.hmac_key.is_some() {
            super::integrity::commit_pending_hmac_sidecar(&meta_path).map_err(|e| {
                SessionStoreError::Io(format!(
                    "failed to commit HMAC sidecar for session {}: {}",
                    session.id, e
                ))
            })?;
        }

        Ok(())
    }

    /// Flush a session's changes to disk
    fn flush_session(&self, session_id: &str) -> Result<(), SessionStoreError> {
        let session = {
            let sessions = self.sessions.read();
            sessions.get(session_id).map(|c| c.session.clone())
        };

        if let Some(session) = session {
            self.write_session_meta(&session)?;

            let mut sessions = self.sessions.write();
            if let Some(cached) = sessions.get_mut(session_id) {
                cached.dirty = false;
            }
        }

        Ok(())
    }

    /// Increment message count for a session
    fn increment_message_count(&self, session_id: &str) -> Result<(), SessionStoreError> {
        // Update message count in a scoped block to ensure write lock is released
        // before attempting to acquire read lock for periodic flush
        {
            let mut sessions = self.sessions.write();

            if let Some(cached) = sessions.get_mut(session_id) {
                cached.session.message_count += 1;
                cached.session.updated_at = now_millis();
                cached.session.last_activity_at = Some(now_millis());
                cached.dirty = true;
            } else {
                drop(sessions);

                // Load session if not cached
                let mut session = self.load_session(session_id)?;
                session.message_count += 1;
                session.updated_at = now_millis();
                session.last_activity_at = Some(now_millis());

                let mut sessions = self.sessions.write();
                sessions.insert(
                    session_id.to_string(),
                    self.new_cached_session(session, true),
                );
            }
        }

        // Periodic flush (every 10 messages)
        {
            let sessions = self.sessions.read();
            if let Some(cached) = sessions.get(session_id) {
                if cached.session.message_count % 10 == 0 {
                    drop(sessions);
                    self.flush_session(session_id)?;
                }
            }
        }

        Ok(())
    }

    /// Flush all dirty sessions to disk
    pub fn flush_all(&self) -> Result<(), SessionStoreError> {
        let dirty_ids: Vec<String> = {
            let sessions = self.sessions.read();
            sessions
                .iter()
                .filter(|(_, c)| c.dirty)
                .map(|(id, _)| id.clone())
                .collect()
        };

        for id in dirty_ids {
            self.flush_session(&id)?;
        }

        Ok(())
    }

    /// Get the base path for session storage
    pub fn base_path(&self) -> &PathBuf {
        &self.base_path
    }

    /// Get session count
    pub fn session_count(&self) -> usize {
        self.sessions.read().len()
    }
}

/// Generate a session key from agent ID and metadata
fn generate_session_key(agent_id: &str, metadata: &SessionMetadata) -> String {
    let channel = metadata.channel.as_deref().unwrap_or("default");
    let chat_id = metadata.chat_id.as_deref().unwrap_or("default");

    format!("{}:{}:{}", agent_id, channel, chat_id)
}

/// Get current time in milliseconds since Unix epoch
fn now_millis() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sessions::crypto::{self, EncryptionMode, SessionCryptoContext};
    use crate::sessions::integrity;
    use tempfile::TempDir;

    #[cfg(unix)]
    fn assert_private_mode(path: &Path) {
        use std::os::unix::fs::PermissionsExt;

        let mode = fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    fn create_test_store() -> (SessionStore, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let store = SessionStore::with_base_path(temp_dir.path().to_path_buf());
        (store, temp_dir)
    }

    fn create_encrypted_store(password: &[u8]) -> (SessionStore, TempDir) {
        create_encrypted_store_with_mode(password, EncryptionMode::IfPassword)
    }

    fn create_encrypted_store_with_mode(
        password: &[u8],
        mode: EncryptionMode,
    ) -> (SessionStore, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let store = reopen_store_with_encryption(temp_dir.path(), Some(password), mode);
        (store, temp_dir)
    }

    fn create_encrypted_store_without_hmac(password: &[u8]) -> (SessionStore, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let crypto = SessionCryptoContext::load_or_create(temp_dir.path(), password).unwrap();
        let store = SessionStore::with_base_path(temp_dir.path().to_path_buf())
            .with_encryption_mode(EncryptionMode::IfPassword)
            .with_crypto_context(Arc::new(crypto));
        (store, temp_dir)
    }

    fn test_key_material() -> Vec<u8> {
        format!("fixture-{}", uuid::Uuid::new_v4()).into_bytes()
    }

    fn hmac_sidecar_path(path: &Path) -> PathBuf {
        let mut sidecar = path.as_os_str().to_owned();
        sidecar.push(".hmac");
        PathBuf::from(sidecar)
    }

    fn reopen_store_with_encryption(
        base_path: &Path,
        password: Option<&[u8]>,
        mode: EncryptionMode,
    ) -> SessionStore {
        let mut store =
            SessionStore::with_base_path(base_path.to_path_buf()).with_encryption_mode(mode);
        if let Some(password) = password {
            let crypto = SessionCryptoContext::load_or_create(base_path, password).unwrap();
            let hmac_key = crypto.integrity_hmac_key();
            store = store.with_crypto_context(Arc::new(crypto));
            if let Some(hmac_key) = hmac_key {
                store = store.with_hmac_key(hmac_key);
            }
        }
        store
    }

    fn reopen_store_with_encryption_and_legacy_hmac(
        base_path: &Path,
        password: Option<&[u8]>,
        mode: EncryptionMode,
        legacy_secret: Option<&[u8]>,
    ) -> SessionStore {
        let mut store = reopen_store_with_encryption(base_path, password, mode);
        if let Some(secret) = legacy_secret {
            store = store.with_legacy_hmac_key(Zeroizing::new(integrity::derive_hmac_key(secret)));
        }
        store
    }

    #[test]
    fn test_session_status_default() {
        assert_eq!(SessionStatus::default(), SessionStatus::Active);
    }

    #[test]
    fn test_session_status_display() {
        assert_eq!(SessionStatus::Active.to_string(), "active");
        assert_eq!(SessionStatus::Paused.to_string(), "paused");
        assert_eq!(SessionStatus::Archived.to_string(), "archived");
        assert_eq!(SessionStatus::Compacting.to_string(), "compacting");
    }

    #[test]
    fn test_message_role_default() {
        assert_eq!(MessageRole::default(), MessageRole::User);
    }

    #[test]
    fn test_message_role_display() {
        assert_eq!(MessageRole::User.to_string(), "user");
        assert_eq!(MessageRole::Assistant.to_string(), "assistant");
        assert_eq!(MessageRole::System.to_string(), "system");
        assert_eq!(MessageRole::Tool.to_string(), "tool");
    }

    #[test]
    fn test_session_creation() {
        let metadata = SessionMetadata {
            name: Some("Test Session".into()),
            channel: Some("telegram".into()),
            chat_id: Some("123456".into()),
            ..Default::default()
        };

        let session = Session::new("default", metadata);

        assert!(!session.id.is_empty());
        assert_eq!(session.session_key, "default:telegram:123456");
        assert_eq!(session.status, SessionStatus::Active);
        assert_eq!(session.metadata.agent_id, Some("default".into()));
        assert_eq!(session.metadata.name, Some("Test Session".into()));
        assert_eq!(session.message_count, 0);
        assert!(session.created_at > 0);
    }

    #[test]
    fn test_session_with_session_key() {
        let session = Session::with_session_key(
            "custom:key:here",
            SessionMetadata {
                name: Some("Custom".into()),
                ..Default::default()
            },
        );

        assert_eq!(session.session_key, "custom:key:here");
    }

    #[test]
    fn test_session_needs_compaction() {
        let mut session = Session::new("agent", SessionMetadata::default());

        assert!(!session.needs_compaction());

        session.message_count = 100;
        assert!(session.needs_compaction());

        session.message_count = 500;
        assert!(session.force_compaction_needed());
    }

    #[test]
    fn test_chat_message_creation() {
        let msg = ChatMessage::user("session-123", "Hello, world!");

        assert!(!msg.id.is_empty());
        assert_eq!(msg.session_id, "session-123");
        assert_eq!(msg.role, MessageRole::User);
        assert_eq!(msg.content, "Hello, world!");
        assert!(msg.created_at > 0);
    }

    #[test]
    fn test_chat_message_builders() {
        let user_msg = ChatMessage::user("s1", "Hi");
        assert_eq!(user_msg.role, MessageRole::User);

        let assistant_msg = ChatMessage::assistant("s1", "Hello!");
        assert_eq!(assistant_msg.role, MessageRole::Assistant);

        let system_msg = ChatMessage::system("s1", "Instructions");
        assert_eq!(system_msg.role, MessageRole::System);

        let tool_msg = ChatMessage::tool("s1", "calculator", "call-1", "42");
        assert_eq!(tool_msg.role, MessageRole::Tool);
        assert_eq!(tool_msg.tool_name, Some("calculator".into()));
        assert_eq!(tool_msg.tool_call_id, Some("call-1".into()));
    }

    #[test]
    fn test_chat_message_with_tokens() {
        let msg = ChatMessage::user("s1", "Hello").with_tokens(10);
        assert_eq!(msg.tokens, Some(10));
    }

    #[test]
    fn test_session_filter() {
        let filter = SessionFilter::new()
            .with_agent_id("agent-1")
            .with_status(SessionStatus::Active)
            .with_channel("telegram")
            .with_limit(10)
            .with_offset(5);

        assert_eq!(filter.agent_id, Some("agent-1".into()));
        assert_eq!(filter.status, Some(SessionStatus::Active));
        assert_eq!(filter.channel, Some("telegram".into()));
        assert_eq!(filter.limit, Some(10));
        assert_eq!(filter.offset, Some(5));
    }

    #[test]
    fn test_session_filter_matches() {
        let session = Session::new(
            "agent-1",
            SessionMetadata {
                channel: Some("telegram".into()),
                ..Default::default()
            },
        );

        let filter = SessionFilter::new()
            .with_agent_id("agent-1")
            .with_channel("telegram");

        assert!(filter.matches(&session));

        let non_matching_filter = SessionFilter::new().with_agent_id("agent-2");
        assert!(!non_matching_filter.matches(&session));
    }

    #[test]
    fn test_store_create_session() {
        let (store, _temp) = create_test_store();

        let metadata = SessionMetadata {
            name: Some("Test".into()),
            ..Default::default()
        };

        let session = store.create_session("agent-1", metadata).unwrap();

        assert!(!session.id.is_empty());
        assert_eq!(session.metadata.agent_id, Some("agent-1".into()));

        // Verify persistence
        let loaded = store.get_session(&session.id).unwrap();
        assert_eq!(loaded.id, session.id);
        assert_eq!(loaded.metadata.name, Some("Test".into()));
    }

    #[test]
    fn test_store_duplicate_session_key() {
        let (store, _temp) = create_test_store();

        let metadata = SessionMetadata {
            channel: Some("telegram".into()),
            chat_id: Some("123".into()),
            ..Default::default()
        };

        store.create_session("agent-1", metadata.clone()).unwrap();

        // Should fail with duplicate key
        let result = store.create_session("agent-1", metadata);
        assert!(matches!(result, Err(SessionStoreError::AlreadyExists(_))));
    }

    #[test]
    fn test_store_get_session_by_key() {
        let (store, _temp) = create_test_store();

        let metadata = SessionMetadata {
            channel: Some("discord".into()),
            chat_id: Some("456".into()),
            ..Default::default()
        };

        let session = store.create_session("agent-2", metadata).unwrap();
        let loaded = store.get_session_by_key(&session.session_key).unwrap();

        assert_eq!(loaded.id, session.id);
    }

    #[test]
    fn test_encrypted_session_store_round_trip() {
        let key_material = test_key_material();
        let (store, _temp) = create_encrypted_store(&key_material);

        let metadata = SessionMetadata {
            name: Some("Secret chat".into()),
            ..Default::default()
        };
        let session = store.create_session("agent-1", metadata).unwrap();
        store
            .append_message(ChatMessage::user(&session.id, "top secret"))
            .unwrap();

        let meta_path = store.session_meta_path(&session.id).unwrap();
        let meta_raw = fs::read(&meta_path).unwrap();
        assert!(crypto::is_encrypted_payload(&meta_raw));
        #[cfg(unix)]
        assert_private_mode(&meta_path);

        let history_path = store.session_history_path(&session.id).unwrap();
        let history_raw = fs::read_to_string(&history_path).unwrap();
        let first_line = history_raw
            .lines()
            .find(|line| !line.trim().is_empty())
            .unwrap();
        assert!(crypto::is_encrypted_payload(first_line.as_bytes()));
        #[cfg(unix)]
        assert_private_mode(&history_path);

        let history = store.get_history(&session.id, None, None).unwrap();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].content, "top secret");

        let archived = store.archive_session(&session.id, false).unwrap();
        let archive_path = PathBuf::from(&archived.archive_path);
        let archive_raw = fs::read(&archive_path).unwrap();
        assert!(crypto::is_encrypted_payload(&archive_raw));
        #[cfg(unix)]
        assert_private_mode(&archive_path);
    }

    #[test]
    fn test_if_password_without_password_lists_locked_encrypted_sessions() {
        let key_material = test_key_material();
        let (encrypted_store, temp_dir) = create_encrypted_store(&key_material);
        let session = encrypted_store
            .create_session("agent-1", SessionMetadata::default())
            .unwrap();
        encrypted_store
            .append_message(ChatMessage::user(&session.id, "hello"))
            .unwrap();

        let locked_store =
            reopen_store_with_encryption(temp_dir.path(), None, EncryptionMode::IfPassword);
        let entries = locked_store
            .list_session_entries(SessionFilter::default())
            .unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].session_id, session.id);
        assert_eq!(entries[0].access, SessionAccessState::Locked);
        assert!(entries[0].session.is_none());

        let err = locked_store.get_session(&session.id).unwrap_err();
        assert!(matches!(err, SessionStoreError::Locked(_)));

        let err = locked_store
            .get_session_by_key(&session.session_key)
            .unwrap_err();
        assert!(matches!(err, SessionStoreError::Locked(_)));
    }

    #[test]
    fn test_reject_mode_without_password_keeps_encrypted_sessions_locked_when_hmac_is_configured() {
        let key_material = test_key_material();
        let server_secret = test_key_material();
        let (encrypted_store, temp_dir) = create_encrypted_store(&key_material);
        let session = encrypted_store
            .create_session("agent-1", SessionMetadata::default())
            .unwrap();
        encrypted_store
            .append_message(ChatMessage::user(&session.id, "hello"))
            .unwrap();

        let locked_store = SessionStore::with_base_path(temp_dir.path().to_path_buf())
            .with_encryption_mode(EncryptionMode::IfPassword)
            .with_hmac_key(Zeroizing::new(integrity::derive_hmac_key(&server_secret)))
            .with_integrity_action(integrity::IntegrityAction::Reject);

        let entries = locked_store
            .list_session_entries(SessionFilter::default())
            .unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].session_id(), session.id);
        assert_eq!(entries[0].access(), SessionAccessState::Locked);

        assert!(matches!(
            locked_store.get_session(&session.id),
            Err(SessionStoreError::Locked(_))
        ));
        assert!(matches!(
            locked_store.get_history(&session.id, None, None),
            Err(SessionStoreError::Locked(_))
        ));
        assert!(matches!(
            locked_store.get_session_by_key(&session.session_key),
            Err(SessionStoreError::Locked(_))
        ));
    }

    #[test]
    fn test_required_mode_without_password_fails_closed() {
        let temp_dir = TempDir::new().unwrap();
        let store = reopen_store_with_encryption(temp_dir.path(), None, EncryptionMode::Required);
        let err = store
            .list_session_entries(SessionFilter::default())
            .unwrap_err();
        assert!(matches!(err, SessionStoreError::Locked(_)));
    }

    #[test]
    fn test_required_mode_with_password_round_trip() {
        let key_material = test_key_material();
        let (store, temp_dir) =
            create_encrypted_store_with_mode(&key_material, EncryptionMode::Required);

        let session = store
            .create_session("agent-1", SessionMetadata::default())
            .unwrap();
        store
            .append_message(ChatMessage::user(&session.id, "hello"))
            .unwrap();

        let history = store.get_history(&session.id, None, None).unwrap();
        assert_eq!(history.len(), 1);

        let entries = store
            .list_session_entries(SessionFilter::default())
            .unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].session_id(), session.id);
        assert_eq!(entries[0].access(), SessionAccessState::Available);

        let archived = store.archive_session(&session.id, false).unwrap();
        let restored = store.restore_session(&archived.session_id).unwrap();
        let restored_history = store.get_history(&restored.session_id, None, None).unwrap();
        assert_eq!(restored_history.len(), 1);

        let reopened = reopen_store_with_encryption(
            temp_dir.path(),
            Some(&key_material),
            EncryptionMode::Required,
        );
        let reopened_history = reopened.get_history(&session.id, None, None).unwrap();
        assert_eq!(reopened_history.len(), 1);
    }

    #[test]
    fn test_reject_mode_migrates_legacy_integrity_sidecars_when_encryption_enabled() {
        let temp_dir = TempDir::new().unwrap();
        let key_material = test_key_material();
        let legacy_secret = test_key_material();
        let legacy_hmac_key = Zeroizing::new(integrity::derive_hmac_key(&legacy_secret));

        let plaintext_store = SessionStore::with_base_path(temp_dir.path().to_path_buf())
            .with_hmac_key(legacy_hmac_key)
            .with_integrity_action(integrity::IntegrityAction::Reject);
        let session = plaintext_store
            .create_session("agent-1", SessionMetadata::default())
            .unwrap();
        plaintext_store
            .append_message(ChatMessage::user(&session.id, "before"))
            .unwrap();

        let encrypted_store = reopen_store_with_encryption_and_legacy_hmac(
            temp_dir.path(),
            Some(&key_material),
            EncryptionMode::IfPassword,
            Some(&legacy_secret),
        )
        .with_integrity_action(integrity::IntegrityAction::Reject);

        encrypted_store
            .append_message(ChatMessage::user(&session.id, "after"))
            .unwrap();

        let history = encrypted_store
            .get_history(&session.id, None, None)
            .unwrap();
        assert_eq!(history.len(), 2);

        let meta_raw = fs::read(encrypted_store.session_meta_path(&session.id).unwrap()).unwrap();
        assert!(crypto::is_encrypted_payload(&meta_raw));
        let history_raw =
            fs::read_to_string(encrypted_store.session_history_path(&session.id).unwrap()).unwrap();
        let first_line = history_raw
            .lines()
            .find(|line| !line.trim().is_empty())
            .unwrap();
        assert!(crypto::is_encrypted_payload(first_line.as_bytes()));

        let reopened = reopen_store_with_encryption(
            temp_dir.path(),
            Some(&key_material),
            EncryptionMode::IfPassword,
        )
        .with_integrity_action(integrity::IntegrityAction::Reject);
        let reopened_history = reopened.get_history(&session.id, None, None).unwrap();
        assert_eq!(reopened_history.len(), 2);
    }

    #[test]
    fn test_encrypted_append_migrates_legacy_plaintext_history_and_metadata() {
        let temp_dir = TempDir::new().unwrap();
        let key_material = test_key_material();
        let plaintext_store = SessionStore::with_base_path(temp_dir.path().to_path_buf());
        let session = plaintext_store
            .create_session("agent-1", SessionMetadata::default())
            .unwrap();
        plaintext_store
            .append_message(ChatMessage::user(&session.id, "before"))
            .unwrap();

        let history_path = plaintext_store.session_history_path(&session.id).unwrap();
        let meta_path = plaintext_store.session_meta_path(&session.id).unwrap();
        let legacy_line = fs::read_to_string(&history_path).unwrap();
        assert!(!crypto::is_encrypted_payload(
            legacy_line.lines().next().unwrap().as_bytes()
        ));
        assert!(!crypto::is_encrypted_payload(
            &fs::read(&meta_path).unwrap()
        ));

        let encrypted_store = reopen_store_with_encryption(
            temp_dir.path(),
            Some(&key_material),
            EncryptionMode::IfPassword,
        );
        encrypted_store
            .append_message(ChatMessage::assistant(&session.id, "after"))
            .unwrap();

        let history_lines = fs::read_to_string(&history_path).unwrap();
        assert!(history_lines
            .lines()
            .filter(|line| !line.trim().is_empty())
            .all(|line| crypto::is_encrypted_payload(line.as_bytes())));
        assert!(crypto::is_encrypted_payload(&fs::read(&meta_path).unwrap()));

        let history = encrypted_store
            .get_history(&session.id, None, None)
            .unwrap();
        assert_eq!(history.len(), 2);
        assert_eq!(history[0].content, "before");
        assert_eq!(history[1].content, "after");
    }

    #[test]
    fn test_loading_plaintext_session_under_encryption_migrates_all_artifacts() {
        let temp_dir = TempDir::new().unwrap();
        let key_material = test_key_material();
        let plaintext_store = SessionStore::with_base_path(temp_dir.path().to_path_buf());
        let session = plaintext_store
            .create_session("agent-1", SessionMetadata::default())
            .unwrap();
        plaintext_store
            .append_message(ChatMessage::user(&session.id, "before"))
            .unwrap();
        plaintext_store.archive_session(&session.id, false).unwrap();

        let history_path = plaintext_store.session_history_path(&session.id).unwrap();
        let meta_path = plaintext_store.session_meta_path(&session.id).unwrap();
        let archive_path = plaintext_store.archive_path(&session.id).unwrap();

        assert!(!crypto::is_encrypted_payload(
            &fs::read(&meta_path).unwrap()
        ));
        assert!(fs::read_to_string(&history_path)
            .unwrap()
            .lines()
            .filter(|line| !line.trim().is_empty())
            .all(|line| !crypto::is_encrypted_payload(line.as_bytes())));
        assert!(!crypto::is_encrypted_payload(
            &fs::read(&archive_path).unwrap()
        ));

        let encrypted_store = reopen_store_with_encryption(
            temp_dir.path(),
            Some(&key_material),
            EncryptionMode::IfPassword,
        );
        let entries = encrypted_store
            .list_session_entries(SessionFilter::default())
            .unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].session_id(), session.id);

        assert!(crypto::is_encrypted_payload(&fs::read(&meta_path).unwrap()));
        assert!(fs::read_to_string(&history_path)
            .unwrap()
            .lines()
            .filter(|line| !line.trim().is_empty())
            .all(|line| crypto::is_encrypted_payload(line.as_bytes())));
        assert!(crypto::is_encrypted_payload(
            &fs::read(&archive_path).unwrap()
        ));
    }

    #[test]
    fn test_encrypted_compaction_rewrites_history_as_ciphertext() {
        let key_material = test_key_material();
        let (store, _temp) = create_encrypted_store(&key_material);
        let session = store
            .create_session("agent-1", SessionMetadata::default())
            .unwrap();
        for idx in 0..6 {
            store
                .append_message(ChatMessage::user(&session.id, format!("message-{idx}")))
                .unwrap();
        }

        let metadata = store
            .compact_session(&session.id, 2, |msgs| format!("summary: {}", msgs.len()))
            .unwrap();
        assert_eq!(metadata.messages_compacted, 4);

        let history_path = store.session_history_path(&session.id).unwrap();
        let history_raw = fs::read_to_string(&history_path).unwrap();
        assert!(history_raw
            .lines()
            .filter(|line| !line.trim().is_empty())
            .all(|line| crypto::is_encrypted_payload(line.as_bytes())));

        let history = store.get_history(&session.id, None, None).unwrap();
        assert_eq!(history.len(), 3);
        assert_eq!(history[0].role, MessageRole::System);
        assert_eq!(history[0].content, "summary: 4");
        assert_eq!(history[1].content, "message-4");
        assert_eq!(history[2].content, "message-5");
    }

    #[test]
    fn test_restore_session_reencrypts_plaintext_archive_when_encryption_enabled() {
        let temp_dir = TempDir::new().unwrap();
        let plaintext_store = SessionStore::with_base_path(temp_dir.path().to_path_buf());
        let session = plaintext_store
            .create_session("agent-1", SessionMetadata::default())
            .unwrap();
        plaintext_store
            .append_message(ChatMessage::user(&session.id, "before-archive"))
            .unwrap();
        let archive_result = plaintext_store.archive_session(&session.id, true).unwrap();
        let archive_path = PathBuf::from(&archive_result.archive_path);
        assert!(!crypto::is_encrypted_payload(
            &fs::read(&archive_path).unwrap()
        ));

        let key_material = test_key_material();
        let encrypted_store = reopen_store_with_encryption(
            temp_dir.path(),
            Some(&key_material),
            EncryptionMode::IfPassword,
        );
        let restored = encrypted_store.restore_session(&session.id).unwrap();
        assert_eq!(restored.message_count, 1);

        let archive_raw = fs::read(&archive_path).unwrap();
        assert!(crypto::is_encrypted_payload(&archive_raw));
        #[cfg(unix)]
        assert_private_mode(&archive_path);

        let history_path = encrypted_store.session_history_path(&session.id).unwrap();
        let history_raw = fs::read_to_string(&history_path).unwrap();
        assert!(history_raw
            .lines()
            .filter(|line| !line.trim().is_empty())
            .all(|line| crypto::is_encrypted_payload(line.as_bytes())));
        #[cfg(unix)]
        assert_private_mode(&history_path);
    }

    #[test]
    fn test_restore_session_rejects_tampered_plaintext_archive_under_integrity_reject() {
        let temp_dir = TempDir::new().unwrap();
        let hmac_key = Zeroizing::new(integrity::derive_hmac_key(b"archive-secret"));
        let store = SessionStore::with_base_path(temp_dir.path().to_path_buf())
            .with_hmac_key(hmac_key)
            .with_integrity_action(integrity::IntegrityAction::Reject);
        let session = store
            .create_session("agent-1", SessionMetadata::default())
            .unwrap();
        store
            .append_message(ChatMessage::user(&session.id, "before-archive"))
            .unwrap();
        store.archive_session(&session.id, false).unwrap();

        let archive_path = store.archive_path(&session.id).unwrap();
        fs::write(&archive_path, br#"{"tampered":true}"#).unwrap();

        let err = store.restore_session(&session.id).unwrap_err();
        assert!(matches!(err, SessionStoreError::Io(_)));
    }

    #[test]
    fn test_get_archive_info_rejects_tampered_plaintext_archive_under_integrity_reject() {
        let temp_dir = TempDir::new().unwrap();
        let hmac_key = Zeroizing::new(integrity::derive_hmac_key(b"archive-secret"));
        let store = SessionStore::with_base_path(temp_dir.path().to_path_buf())
            .with_hmac_key(hmac_key)
            .with_integrity_action(integrity::IntegrityAction::Reject);
        let session = store
            .create_session("agent-1", SessionMetadata::default())
            .unwrap();
        store
            .append_message(ChatMessage::user(&session.id, "before-archive"))
            .unwrap();
        store.archive_session(&session.id, false).unwrap();

        let archive_path = store.archive_path(&session.id).unwrap();
        fs::write(&archive_path, br#"{"tampered":true}"#).unwrap();

        let err = store.get_archive_info(&session.id).unwrap_err();
        assert!(matches!(err, SessionStoreError::Io(_)));
    }

    #[test]
    fn test_encryption_migration_rejects_tampered_plaintext_archive_under_integrity_reject() {
        let temp_dir = TempDir::new().unwrap();
        let key_material = test_key_material();
        let legacy_secret = test_key_material();
        let legacy_hmac_key = Zeroizing::new(integrity::derive_hmac_key(&legacy_secret));

        let plaintext_store = SessionStore::with_base_path(temp_dir.path().to_path_buf())
            .with_hmac_key(legacy_hmac_key)
            .with_integrity_action(integrity::IntegrityAction::Reject);
        let session = plaintext_store
            .create_session("agent-1", SessionMetadata::default())
            .unwrap();
        plaintext_store
            .append_message(ChatMessage::user(&session.id, "before-archive"))
            .unwrap();
        plaintext_store.archive_session(&session.id, false).unwrap();

        let archive_path = plaintext_store.archive_path(&session.id).unwrap();
        fs::write(&archive_path, br#"{"tampered":true}"#).unwrap();

        let encrypted_store = reopen_store_with_encryption_and_legacy_hmac(
            temp_dir.path(),
            Some(&key_material),
            EncryptionMode::IfPassword,
            Some(&legacy_secret),
        )
        .with_integrity_action(integrity::IntegrityAction::Reject);

        let err = encrypted_store.get_session(&session.id).unwrap_err();
        assert!(matches!(err, SessionStoreError::Io(_)));
    }

    #[test]
    fn test_archive_migration_updates_hmac_sidecar_under_reject_mode() {
        let temp_dir = TempDir::new().unwrap();
        let key_material = test_key_material();
        let legacy_secret = test_key_material();
        let legacy_hmac_key = Zeroizing::new(integrity::derive_hmac_key(&legacy_secret));

        let plaintext_store = SessionStore::with_base_path(temp_dir.path().to_path_buf())
            .with_hmac_key(legacy_hmac_key)
            .with_integrity_action(integrity::IntegrityAction::Reject);
        let session = plaintext_store
            .create_session("agent-1", SessionMetadata::default())
            .unwrap();
        plaintext_store
            .append_message(ChatMessage::user(&session.id, "before-archive"))
            .unwrap();
        plaintext_store.archive_session(&session.id, false).unwrap();

        let archive_path = plaintext_store.archive_path(&session.id).unwrap();
        let archive_raw = fs::read(&archive_path).unwrap();
        let reject = integrity::IntegrityConfig {
            enabled: true,
            action: integrity::IntegrityAction::Reject,
        };
        integrity::verify_hmac_file(
            plaintext_store.hmac_key.as_ref().unwrap(),
            &archive_raw,
            &archive_path,
            &reject,
        )
        .unwrap();

        let encrypted_store = reopen_store_with_encryption_and_legacy_hmac(
            temp_dir.path(),
            Some(&key_material),
            EncryptionMode::IfPassword,
            Some(&legacy_secret),
        )
        .with_integrity_action(integrity::IntegrityAction::Reject);
        let entries = encrypted_store
            .list_session_entries(SessionFilter::default())
            .unwrap();
        assert_eq!(entries.len(), 1);

        let migrated_archive_raw = fs::read(&archive_path).unwrap();
        assert!(crypto::is_encrypted_payload(&migrated_archive_raw));
        integrity::verify_hmac_file(
            encrypted_store.hmac_key.as_ref().unwrap(),
            &migrated_archive_raw,
            &archive_path,
            &reject,
        )
        .unwrap();
    }

    #[test]
    fn test_wrong_password_returns_decryption_failed_for_encrypted_session() {
        let key_material = test_key_material();
        let (store, temp_dir) = create_encrypted_store(&key_material);
        let session = store
            .create_session("agent-1", SessionMetadata::default())
            .unwrap();
        store
            .append_message(ChatMessage::user(&session.id, "hello"))
            .unwrap();

        let wrong_key_material = test_key_material();
        let wrong_store = reopen_store_with_encryption(
            temp_dir.path(),
            Some(&wrong_key_material),
            EncryptionMode::IfPassword,
        );
        let err = wrong_store.get_session(&session.id).unwrap_err();
        assert!(matches!(err, SessionStoreError::DecryptionFailed(_)));
    }

    #[test]
    fn test_list_sessions_fails_closed_on_wrong_password_for_encrypted_store() {
        let key_material = test_key_material();
        let (store, temp_dir) = create_encrypted_store(&key_material);
        let session = store
            .create_session("agent-1", SessionMetadata::default())
            .unwrap();
        store
            .append_message(ChatMessage::user(&session.id, "secret"))
            .unwrap();

        let wrong_password = test_key_material();
        let wrong_store = reopen_store_with_encryption(
            temp_dir.path(),
            Some(&wrong_password),
            EncryptionMode::IfPassword,
        );

        let err = wrong_store
            .list_session_entries(SessionFilter::default())
            .unwrap_err();
        assert!(matches!(err, SessionStoreError::DecryptionFailed(_)));
    }

    #[test]
    fn test_list_sessions_isolates_malformed_prefixed_encrypted_metadata_to_locked_stub() {
        let key_material = test_key_material();
        let (store, temp_dir) = create_encrypted_store(&key_material);
        let healthy = store
            .create_session(
                "agent-1",
                SessionMetadata {
                    channel: Some("channel-a".into()),
                    chat_id: Some("chat-a".into()),
                    user_id: Some("user-a".into()),
                    ..Default::default()
                },
            )
            .unwrap();
        let corrupt = store
            .create_session(
                "agent-1",
                SessionMetadata {
                    channel: Some("channel-b".into()),
                    chat_id: Some("chat-b".into()),
                    user_id: Some("user-b".into()),
                    ..Default::default()
                },
            )
            .unwrap();
        store
            .append_message(ChatMessage::user(&healthy.id, "still-readable"))
            .unwrap();
        store
            .append_message(ChatMessage::user(&corrupt.id, "will-corrupt"))
            .unwrap();

        let corrupt_meta_path = store.session_meta_path(&corrupt.id).unwrap();
        let malformed = b"cse1:{\"format\":\"session-enc-v1\"}";
        fs::write(&corrupt_meta_path, malformed).unwrap();
        integrity::write_hmac_file(
            store.hmac_key.as_ref().unwrap(),
            malformed,
            &corrupt_meta_path,
        )
        .unwrap();

        let reopened = reopen_store_with_encryption(
            temp_dir.path(),
            Some(&key_material),
            EncryptionMode::IfPassword,
        );
        let entries = reopened
            .list_session_entries(SessionFilter::default())
            .unwrap();
        assert_eq!(entries.len(), 2);

        let healthy_entry = entries
            .iter()
            .find(|entry| entry.session_id() == healthy.id)
            .unwrap();
        assert_eq!(healthy_entry.access(), SessionAccessState::Available);

        let corrupt_entry = entries
            .iter()
            .find(|entry| entry.session_id() == corrupt.id)
            .unwrap();
        assert_eq!(corrupt_entry.access(), SessionAccessState::Locked);

        let loaded_healthy = reopened.get_session(&healthy.id).unwrap();
        assert_eq!(loaded_healthy.id, healthy.id);

        let err = reopened.get_session(&corrupt.id).unwrap_err();
        assert!(matches!(err, SessionStoreError::Crypto(_)));

        let err = reopened
            .list_session_entries(SessionFilter::new().with_user_id("user-a"))
            .unwrap_err();
        assert!(matches!(err, SessionStoreError::Locked(_)));
    }

    #[test]
    fn test_list_sessions_isolates_truncated_prefixed_encrypted_metadata_to_locked_stub() {
        let key_material = test_key_material();
        let (store, temp_dir) = create_encrypted_store(&key_material);
        let healthy = store
            .create_session(
                "agent-1",
                SessionMetadata {
                    channel: Some("channel-a".into()),
                    chat_id: Some("chat-a".into()),
                    user_id: Some("user-a".into()),
                    ..Default::default()
                },
            )
            .unwrap();
        let corrupt = store
            .create_session(
                "agent-1",
                SessionMetadata {
                    channel: Some("channel-b".into()),
                    chat_id: Some("chat-b".into()),
                    user_id: Some("user-b".into()),
                    ..Default::default()
                },
            )
            .unwrap();
        store
            .append_message(ChatMessage::user(&healthy.id, "still-readable"))
            .unwrap();
        store
            .append_message(ChatMessage::user(&corrupt.id, "will-corrupt"))
            .unwrap();

        let corrupt_meta_path = store.session_meta_path(&corrupt.id).unwrap();
        let encrypted = fs::read(&corrupt_meta_path).unwrap();
        assert!(crypto::has_encrypted_payload_prefix(&encrypted));
        let truncated = encrypted[..12].to_vec();
        fs::write(&corrupt_meta_path, &truncated).unwrap();
        integrity::write_hmac_file(
            store.hmac_key.as_ref().unwrap(),
            &truncated,
            &corrupt_meta_path,
        )
        .unwrap();

        let reopened = reopen_store_with_encryption(
            temp_dir.path(),
            Some(&key_material),
            EncryptionMode::IfPassword,
        );
        let entries = reopened
            .list_session_entries(SessionFilter::default())
            .unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(
            entries
                .iter()
                .find(|entry| entry.session_id() == healthy.id)
                .unwrap()
                .access(),
            SessionAccessState::Available
        );
        assert_eq!(
            entries
                .iter()
                .find(|entry| entry.session_id() == corrupt.id)
                .unwrap()
                .access(),
            SessionAccessState::Locked
        );
        assert!(matches!(
            reopened.get_session(&corrupt.id),
            Err(SessionStoreError::Crypto(_))
        ));
    }

    #[test]
    fn test_list_sessions_isolates_undecryptable_encrypted_metadata_to_locked_stub() {
        let key_material = test_key_material();
        let (store, temp_dir) = create_encrypted_store(&key_material);
        let healthy = store
            .create_session(
                "agent-1",
                SessionMetadata {
                    channel: Some("channel-a".into()),
                    chat_id: Some("chat-a".into()),
                    user_id: Some("user-a".into()),
                    ..Default::default()
                },
            )
            .unwrap();
        let corrupt = store
            .create_session(
                "agent-1",
                SessionMetadata {
                    channel: Some("channel-b".into()),
                    chat_id: Some("chat-b".into()),
                    user_id: Some("user-b".into()),
                    ..Default::default()
                },
            )
            .unwrap();
        store
            .append_message(ChatMessage::user(&healthy.id, "still-readable"))
            .unwrap();
        store
            .append_message(ChatMessage::user(&corrupt.id, "will-corrupt"))
            .unwrap();

        let corrupt_meta_path = store.session_meta_path(&corrupt.id).unwrap();
        let encrypted = fs::read(&corrupt_meta_path).unwrap();
        assert!(crypto::has_encrypted_payload_prefix(&encrypted));

        let prefix = b"cse1:";
        let mut envelope: serde_json::Value =
            serde_json::from_slice(encrypted.strip_prefix(prefix).unwrap()).unwrap();
        let ciphertext = envelope.get("c").and_then(|value| value.as_str()).unwrap();
        let mut chars: Vec<char> = ciphertext.chars().collect();
        let flip_idx = chars.iter().position(|ch| *ch != 'A').unwrap_or(0);
        chars[flip_idx] = if chars[flip_idx] == 'B' { 'C' } else { 'B' };
        envelope["c"] = serde_json::Value::String(chars.into_iter().collect());

        let mut tampered = prefix.to_vec();
        tampered.extend(serde_json::to_vec(&envelope).unwrap());
        fs::write(&corrupt_meta_path, &tampered).unwrap();
        integrity::write_hmac_file(
            store.hmac_key.as_ref().unwrap(),
            &tampered,
            &corrupt_meta_path,
        )
        .unwrap();

        let reopened = reopen_store_with_encryption(
            temp_dir.path(),
            Some(&key_material),
            EncryptionMode::IfPassword,
        );
        let entries = reopened
            .list_session_entries(SessionFilter::default())
            .unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(
            entries
                .iter()
                .find(|entry| entry.session_id() == healthy.id)
                .unwrap()
                .access(),
            SessionAccessState::Available
        );
        assert_eq!(
            entries
                .iter()
                .find(|entry| entry.session_id() == corrupt.id)
                .unwrap()
                .access(),
            SessionAccessState::Locked
        );

        let loaded_healthy = reopened.get_session(&healthy.id).unwrap();
        assert_eq!(loaded_healthy.id, healthy.id);
        assert!(matches!(
            reopened.get_session(&corrupt.id),
            Err(SessionStoreError::DecryptionFailed(_))
        ));
        assert!(matches!(
            reopened.list_session_entries(SessionFilter::new().with_user_id("user-a")),
            Err(SessionStoreError::Locked(_))
        ));
    }

    #[test]
    fn test_reject_mode_recovers_pending_history_hmac_after_interrupted_rewrite() {
        let temp_dir = TempDir::new().unwrap();
        let key_material = test_key_material();
        let store = reopen_store_with_encryption(
            temp_dir.path(),
            Some(&key_material),
            EncryptionMode::IfPassword,
        )
        .with_integrity_action(integrity::IntegrityAction::Reject);
        let session = store
            .create_session("agent-1", SessionMetadata::default())
            .unwrap();
        store
            .append_message(ChatMessage::user(&session.id, "before"))
            .unwrap();

        let history_path = store.session_history_path(&session.id).unwrap();
        let temp_path = history_path.with_extension("tmp");
        {
            let file = SessionStore::create_private_output_file(&temp_path).unwrap();
            let mut writer = BufWriter::new(file);
            for message in [
                ChatMessage::user(&session.id, "before"),
                ChatMessage::assistant(&session.id, "after"),
            ] {
                let encoded = store.encode_history_message(&message).unwrap();
                writer.write_all(&encoded).unwrap();
                writeln!(writer).unwrap();
            }
            writer.flush().unwrap();
            writer
                .into_inner()
                .map_err(|e| std::io::Error::other(e.to_string()))
                .unwrap()
                .sync_all()
                .unwrap();
        }
        store
            .prepare_history_hmac_for_path(&temp_path, &history_path, &session.id)
            .unwrap();
        fs::rename(&temp_path, &history_path).unwrap();

        let mut pending_sidecar = history_path.as_os_str().to_owned();
        pending_sidecar.push(".hmac.tmp");
        let pending_sidecar = PathBuf::from(pending_sidecar);
        assert!(pending_sidecar.exists());

        let reopened = reopen_store_with_encryption(
            temp_dir.path(),
            Some(&key_material),
            EncryptionMode::IfPassword,
        )
        .with_integrity_action(integrity::IntegrityAction::Reject);
        let history = reopened.get_history(&session.id, None, None).unwrap();
        assert_eq!(history.len(), 2);
        assert_eq!(history[0].content, "before");
        assert_eq!(history[1].content, "after");
        assert!(!pending_sidecar.exists());
    }

    #[test]
    fn test_store_get_or_create_session() {
        let (store, _temp) = create_test_store();

        let metadata = SessionMetadata {
            name: Some("First".into()),
            ..Default::default()
        };

        // First call creates
        let session1 = store
            .get_or_create_session("test:key:1", metadata.clone())
            .unwrap();
        assert_eq!(session1.metadata.name, Some("First".into()));

        // Second call gets existing
        let session2 = store
            .get_or_create_session(
                "test:key:1",
                SessionMetadata {
                    name: Some("Second".into()),
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(session2.id, session1.id);
        assert_eq!(session2.metadata.name, Some("First".into())); // Not updated
    }

    #[test]
    fn test_store_list_sessions() {
        let (store, _temp) = create_test_store();

        store
            .create_session(
                "agent-1",
                SessionMetadata {
                    channel: Some("telegram".into()),
                    ..Default::default()
                },
            )
            .unwrap();

        store
            .create_session(
                "agent-1",
                SessionMetadata {
                    channel: Some("discord".into()),
                    ..Default::default()
                },
            )
            .unwrap();

        store
            .create_session(
                "agent-2",
                SessionMetadata {
                    channel: Some("telegram".into()),
                    ..Default::default()
                },
            )
            .unwrap();

        // List all
        let all = store.list_sessions(SessionFilter::new()).unwrap();
        assert_eq!(all.len(), 3);

        // Filter by agent
        let agent1_only = store
            .list_sessions(SessionFilter::new().with_agent_id("agent-1"))
            .unwrap();
        assert_eq!(agent1_only.len(), 2);

        // Filter by channel
        let telegram_only = store
            .list_sessions(SessionFilter::new().with_channel("telegram"))
            .unwrap();
        assert_eq!(telegram_only.len(), 2);
    }

    #[test]
    fn test_store_patch_session() {
        let (store, _temp) = create_test_store();

        let session = store
            .create_session("agent-1", SessionMetadata::default())
            .unwrap();

        let updated = store
            .patch_session(
                &session.id,
                SessionMetadata {
                    name: Some("Updated Name".into()),
                    agent_id: Some("agent-2".into()),
                    channel: Some("signal".into()),
                    chat_id: Some("123".into()),
                    user_id: Some("user-1".into()),
                    model: Some("claude-3".into()),
                    ..Default::default()
                },
            )
            .unwrap();

        assert_eq!(updated.metadata.name, Some("Updated Name".into()));
        assert_eq!(updated.metadata.agent_id, Some("agent-2".into()));
        assert_eq!(updated.metadata.channel, Some("signal".into()));
        assert_eq!(updated.metadata.chat_id, Some("123".into()));
        assert_eq!(updated.metadata.user_id, Some("user-1".into()));
        assert_eq!(updated.metadata.model, Some("claude-3".into()));
        assert!(updated.updated_at > session.updated_at);
    }

    #[test]
    fn test_store_reset_session() {
        let (store, _temp) = create_test_store();

        let session = store
            .create_session("agent-1", SessionMetadata::default())
            .unwrap();

        // Add some messages
        store
            .append_message(ChatMessage::user(&session.id, "Hello"))
            .unwrap();
        store
            .append_message(ChatMessage::assistant(&session.id, "Hi there!"))
            .unwrap();

        // Verify messages exist
        let history = store.get_history(&session.id, None, None).unwrap();
        assert_eq!(history.len(), 2);

        // Reset
        let reset = store.reset_session(&session.id).unwrap();
        assert_eq!(reset.message_count, 0);

        // Verify history cleared
        let history = store.get_history(&session.id, None, None).unwrap();
        assert!(history.is_empty());
    }

    #[test]
    fn test_store_delete_session() {
        let (store, _temp) = create_test_store();

        let session = store
            .create_session("agent-1", SessionMetadata::default())
            .unwrap();

        store.delete_session(&session.id).unwrap();

        // Should not be found
        let result = store.get_session(&session.id);
        assert!(matches!(result, Err(SessionStoreError::NotFound(_))));
    }

    #[test]
    fn test_store_append_and_get_history() {
        let (store, _temp) = create_test_store();

        let session = store
            .create_session("agent-1", SessionMetadata::default())
            .unwrap();

        // Append messages
        store
            .append_message(ChatMessage::user(&session.id, "First"))
            .unwrap();
        store
            .append_message(ChatMessage::assistant(&session.id, "Second"))
            .unwrap();
        store
            .append_message(ChatMessage::user(&session.id, "Third"))
            .unwrap();

        // Get all
        let history = store.get_history(&session.id, None, None).unwrap();
        assert_eq!(history.len(), 3);
        assert_eq!(history[0].content, "First");
        assert_eq!(history[1].content, "Second");
        assert_eq!(history[2].content, "Third");

        // Get with limit
        let limited = store.get_history(&session.id, Some(2), None).unwrap();
        assert_eq!(limited.len(), 2);
        assert_eq!(limited[0].content, "Second");
        assert_eq!(limited[1].content, "Third");
    }

    #[test]
    fn test_history_hmac_is_written_and_verified() {
        let temp_dir = TempDir::new().unwrap();
        let key = Zeroizing::new(integrity::derive_hmac_key(b"history-secret"));
        let store = SessionStore::with_base_path(temp_dir.path().to_path_buf())
            .with_hmac_key(key)
            .with_integrity_action(integrity::IntegrityAction::Reject);

        let session = store
            .create_session("agent-1", SessionMetadata::default())
            .unwrap();

        store
            .append_message(ChatMessage::user(&session.id, "Hello"))
            .unwrap();

        let history_path = store.session_history_path(&session.id).unwrap();
        let sidecar = history_path.with_extension("jsonl.hmac");
        assert!(sidecar.exists(), "history HMAC sidecar should exist");

        let history = store.get_history(&session.id, None, None).unwrap();
        assert_eq!(history.len(), 1);

        fs::write(&history_path, "tampered\n").unwrap();
        let result = store.get_history(&session.id, None, None);
        assert!(result.is_err(), "tampered history should be rejected");
    }

    #[test]
    fn test_store_clear_history() {
        let (store, _temp) = create_test_store();

        let session = store
            .create_session("agent-1", SessionMetadata::default())
            .unwrap();

        store
            .append_message(ChatMessage::user(&session.id, "Hello"))
            .unwrap();

        store.clear_history(&session.id).unwrap();

        let history = store.get_history(&session.id, None, None).unwrap();
        assert!(history.is_empty());
    }

    #[test]
    fn test_get_history_fails_closed_on_invalid_encrypted_line() {
        let key_material = test_key_material();
        let (store, _temp) = create_encrypted_store_without_hmac(&key_material);

        let session = store
            .create_session("agent-1", SessionMetadata::default())
            .unwrap();

        store
            .append_message(ChatMessage::user(&session.id, "Hello"))
            .unwrap();

        let history_path = store.session_history_path(&session.id).unwrap();
        fs::write(
            &history_path,
            b"cse1:{\"format\":\"session-enc-v1\",\"n\":\"%%%\",\"c\":\"bad\"}\n",
        )
        .unwrap();

        let err = store.get_history(&session.id, None, None).unwrap_err();
        assert!(matches!(
            err,
            SessionStoreError::Crypto(ref message)
                if message.contains("invalid encrypted session history line")
        ));
    }

    #[test]
    fn test_get_history_ignores_plaintext_format_field_matching_encryption_format() {
        let (store, _temp) = create_test_store();
        let session = store
            .create_session("agent-1", SessionMetadata::default())
            .unwrap();

        let mut message = serde_json::to_value(ChatMessage::user(&session.id, "hello")).unwrap();
        message.as_object_mut().unwrap().insert(
            "format".to_string(),
            serde_json::Value::String("session-enc-v1".to_string()),
        );

        let history_path = store.session_history_path(&session.id).unwrap();
        fs::write(
            &history_path,
            format!("{}\n", serde_json::to_string(&message).unwrap()),
        )
        .unwrap();

        let history = store.get_history(&session.id, None, None).unwrap();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].content, "hello");
    }

    #[test]
    fn test_store_compact_session() {
        let (store, _temp) = create_test_store();

        let session = store
            .create_session("agent-1", SessionMetadata::default())
            .unwrap();

        // Add many messages
        for i in 0..10 {
            store
                .append_message(ChatMessage::user(&session.id, format!("Message {}", i)))
                .unwrap();
        }

        // Compact, keeping last 3
        let metadata = store
            .compact_session(&session.id, 3, |msgs| {
                format!("Summary of {} messages", msgs.len())
            })
            .unwrap();

        assert_eq!(metadata.messages_compacted, 7);
        assert_eq!(metadata.compaction_count, 1);
        assert!(metadata.last_compacted_at.is_some());

        // Check history has summary + 3 kept messages
        let history = store.get_history(&session.id, None, None).unwrap();
        assert_eq!(history.len(), 4);
        assert_eq!(history[0].role, MessageRole::System);
        assert!(history[0].content.contains("Summary of 7 messages"));
    }

    #[test]
    fn test_store_auto_compact() {
        let (store, _temp) = create_test_store();
        let store = store.with_compact_threshold(5);

        let session = store
            .create_session("agent-1", SessionMetadata::default())
            .unwrap();

        // Below threshold
        for _ in 0..4 {
            store
                .append_message(ChatMessage::user(&session.id, "msg"))
                .unwrap();
        }

        let result = store
            .auto_compact_if_needed(&session.id, 2, |_| "summary".into())
            .unwrap();
        assert!(result.is_none());

        // At threshold
        store
            .append_message(ChatMessage::user(&session.id, "msg"))
            .unwrap();

        let result = store
            .auto_compact_if_needed(&session.id, 2, |_| "summary".into())
            .unwrap();
        assert!(result.is_some());
    }

    #[test]
    fn test_store_persistence() {
        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path().to_path_buf();

        // Create and populate store
        let session_id = {
            let store = SessionStore::with_base_path(base_path.clone());
            let session = store
                .create_session(
                    "agent-1",
                    SessionMetadata {
                        name: Some("Persistent".into()),
                        ..Default::default()
                    },
                )
                .unwrap();

            store
                .append_message(ChatMessage::user(&session.id, "Hello"))
                .unwrap();

            session.id
        };

        // Create new store instance and verify data persists
        let store2 = SessionStore::with_base_path(base_path);
        let loaded = store2.get_session(&session_id).unwrap();

        assert_eq!(loaded.metadata.name, Some("Persistent".into()));

        let history = store2.get_history(&session_id, None, None).unwrap();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].content, "Hello");
    }

    #[test]
    fn test_store_flush_all() {
        let (store, _temp) = create_test_store();

        let session = store
            .create_session("agent-1", SessionMetadata::default())
            .unwrap();

        // Append message (makes session dirty via increment_message_count)
        store
            .append_message(ChatMessage::user(&session.id, "Test"))
            .unwrap();

        // Flush all
        store.flush_all().unwrap();

        // Verify no errors
    }

    #[test]
    fn test_chat_message_serialization() {
        let msg = ChatMessage::user("session-1", "Hello, world!")
            .with_tokens(15)
            .with_metadata(serde_json::json!({"key": "value"}));

        let json = serde_json::to_string(&msg).unwrap();
        let parsed: ChatMessage = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.session_id, "session-1");
        assert_eq!(parsed.content, "Hello, world!");
        assert_eq!(parsed.tokens, Some(15));
    }

    #[test]
    fn test_session_serialization() {
        let session = Session::new(
            "agent-1",
            SessionMetadata {
                name: Some("Test Session".into()),
                model: Some("claude-3".into()),
                ..Default::default()
            },
        );

        let json = serde_json::to_string(&session).unwrap();
        let parsed: Session = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.id, session.id);
        assert_eq!(parsed.session_key, session.session_key);
        assert_eq!(parsed.metadata.name, Some("Test Session".into()));
    }

    #[test]
    fn test_compaction_metadata_serialization() {
        let metadata = CompactionMetadata {
            messages_compacted: 50,
            last_compacted_at: Some(1234567890),
            compaction_count: 3,
            last_summary: Some("Summary text".into()),
            original_message_count: 100,
        };

        let json = serde_json::to_string(&metadata).unwrap();
        let parsed: CompactionMetadata = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.messages_compacted, 50);
        assert_eq!(parsed.compaction_count, 3);
    }

    #[test]
    fn test_store_session_count() {
        let (store, _temp) = create_test_store();

        assert_eq!(store.session_count(), 0);

        store
            .create_session("agent-1", SessionMetadata::default())
            .unwrap();
        assert_eq!(store.session_count(), 1);

        store
            .create_session(
                "agent-1",
                SessionMetadata {
                    channel: Some("different".into()),
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(store.session_count(), 2);
    }

    #[test]
    fn test_thread_safety() {
        use std::sync::{Arc, Barrier};
        use std::thread;

        let temp_dir = TempDir::new().unwrap();
        let store = Arc::new(SessionStore::with_base_path(temp_dir.path().to_path_buf()));

        let session = store
            .create_session("agent-1", SessionMetadata::default())
            .unwrap();
        let session_id = session.id.clone();

        // Use a barrier so all threads start writing at roughly the same time
        let barrier = Arc::new(Barrier::new(10));
        let mut handles = vec![];

        // Spawn multiple threads appending messages
        for i in 0..10 {
            let store_clone = Arc::clone(&store);
            let sid = session_id.clone();
            let bar = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                bar.wait();
                store_clone
                    .append_message(ChatMessage::user(&sid, format!("Message {}", i)))
                    .unwrap();
            }));
        }

        for handle in handles {
            handle.join().unwrap();
        }

        let history = store.get_history(&session_id, None, None).unwrap();
        // All 10 messages should be present. get_history skips corrupt lines,
        // so if concurrent appends interleaved we may see fewer — but append
        // mode on POSIX guarantees atomic writes under PIPE_BUF (4 KiB+).
        assert_eq!(history.len(), 10);
    }

    #[test]
    fn test_get_history_with_before_id() {
        let (store, _temp) = create_test_store();

        let session = store
            .create_session("agent-1", SessionMetadata::default())
            .unwrap();

        // Add messages
        let msg1 = ChatMessage::user(&session.id, "First");
        let msg1_id = msg1.id.clone();
        store.append_message(msg1).unwrap();

        let msg2 = ChatMessage::user(&session.id, "Second");
        let msg2_id = msg2.id.clone();
        store.append_message(msg2).unwrap();

        store
            .append_message(ChatMessage::user(&session.id, "Third"))
            .unwrap();

        // Get after msg1
        let history = store
            .get_history(&session.id, None, Some(&msg1_id))
            .unwrap();
        assert_eq!(history.len(), 2);
        assert_eq!(history[0].content, "Second");
        assert_eq!(history[1].content, "Third");

        // Get after msg2
        let history = store
            .get_history(&session.id, None, Some(&msg2_id))
            .unwrap();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].content, "Third");
    }

    #[test]
    fn test_session_filter_date_range() {
        let (store, _temp) = create_test_store();

        let _session = store
            .create_session("agent-1", SessionMetadata::default())
            .unwrap();

        // Filter with timestamp range
        let filter = SessionFilter::new().with_agent_id("agent-1").with_limit(10);

        // Created after 0 should match
        let mut f = filter.clone();
        f.created_after = Some(0);
        let result = store.list_sessions(f).unwrap();
        assert_eq!(result.len(), 1);

        // Created after future timestamp should not match
        let mut f = filter.clone();
        f.created_after = Some(i64::MAX);
        let result = store.list_sessions(f).unwrap();
        assert!(result.is_empty());

        // Created before now should match
        let mut f = filter.clone();
        f.created_before = Some(now_millis() + 1000);
        let result = store.list_sessions(f).unwrap();
        assert_eq!(result.len(), 1);
    }

    // ============== Archive Tests ==============

    #[test]
    fn test_archive_session() {
        let (store, _temp) = create_test_store();

        let session = store
            .create_session(
                "agent-1",
                SessionMetadata {
                    name: Some("Archive Test".into()),
                    ..Default::default()
                },
            )
            .unwrap();

        // Add some messages
        for i in 0..5 {
            store
                .append_message(ChatMessage::user(&session.id, format!("Message {}", i)))
                .unwrap();
        }

        // Archive the session
        let result = store.archive_session(&session.id, false).unwrap();

        assert_eq!(result.session_id, session.id);
        assert_eq!(result.message_count, 5);
        assert!(result.archive_size > 0);
        assert!(!result.history_deleted);

        // Verify session status changed
        let archived = store.get_session(&session.id).unwrap();
        assert_eq!(archived.status, SessionStatus::Archived);

        // Verify archive file exists
        let archive_path = store.archive_path(&session.id).unwrap();
        assert!(archive_path.exists());
    }

    #[test]
    fn test_archive_session_with_history_deletion() {
        let (store, _temp) = create_test_store();

        let session = store
            .create_session("agent-1", SessionMetadata::default())
            .unwrap();

        store
            .append_message(ChatMessage::user(&session.id, "Hello"))
            .unwrap();

        // Archive with history deletion
        let result = store.archive_session(&session.id, true).unwrap();
        assert!(result.history_deleted);

        // Verify history file is deleted
        let history_path = store.session_history_path(&session.id).unwrap();
        assert!(!history_path.exists());
    }

    #[test]
    fn test_archive_already_archived() {
        let (store, _temp) = create_test_store();

        let session = store
            .create_session("agent-1", SessionMetadata::default())
            .unwrap();

        store
            .append_message(ChatMessage::user(&session.id, "Hello"))
            .unwrap();

        // Archive first time
        store.archive_session(&session.id, false).unwrap();

        // Try to archive again
        let result = store.archive_session(&session.id, false);
        assert!(matches!(result, Err(SessionStoreError::AlreadyArchived(_))));
    }

    #[test]
    fn test_append_message_rejected_for_archived_session() {
        let (store, _temp) = create_test_store();

        let session = store
            .create_session("agent-1", SessionMetadata::default())
            .unwrap();

        store
            .append_message(ChatMessage::user(&session.id, "Before archive"))
            .unwrap();

        // Archive the session
        store.archive_session(&session.id, false).unwrap();

        // Attempting to append to an archived session must fail
        let result = store.append_message(ChatMessage::user(&session.id, "After archive"));
        assert!(
            matches!(result, Err(SessionStoreError::AlreadyArchived(_))),
            "append_message should reject writes to archived sessions"
        );

        // Verify history was not modified (still just the one pre-archive message)
        let history = store.get_history(&session.id, None, None).unwrap();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].content, "Before archive");
    }

    #[test]
    fn test_restore_session() {
        let (store, _temp) = create_test_store();

        let session = store
            .create_session("agent-1", SessionMetadata::default())
            .unwrap();

        // Add messages
        store
            .append_message(ChatMessage::user(&session.id, "Hello"))
            .unwrap();
        store
            .append_message(ChatMessage::assistant(&session.id, "Hi there!"))
            .unwrap();

        // Archive with history deletion
        store.archive_session(&session.id, true).unwrap();

        // Verify history is gone
        let history_before = store.get_history(&session.id, None, None).unwrap();
        assert!(history_before.is_empty());

        // Restore
        let result = store.restore_session(&session.id).unwrap();
        assert_eq!(result.session_id, session.id);
        assert_eq!(result.message_count, 2);

        // Verify session status is active again
        let restored = store.get_session(&session.id).unwrap();
        assert_eq!(restored.status, SessionStatus::Active);

        // Verify history is restored
        let history_after = store.get_history(&session.id, None, None).unwrap();
        assert_eq!(history_after.len(), 2);
        assert_eq!(history_after[0].content, "Hello");
        assert_eq!(history_after[1].content, "Hi there!");
    }

    #[test]
    fn test_restore_not_archived() {
        let (store, _temp) = create_test_store();

        let session = store
            .create_session("agent-1", SessionMetadata::default())
            .unwrap();

        // Try to restore non-archived session
        let result = store.restore_session(&session.id);
        assert!(matches!(result, Err(SessionStoreError::NotArchived(_))));
    }

    #[test]
    fn test_list_archived_sessions() {
        let (store, _temp) = create_test_store();

        // Create and archive some sessions
        let session1 = store
            .create_session("agent-1", SessionMetadata::default())
            .unwrap();
        let session2 = store
            .create_session(
                "agent-1",
                SessionMetadata {
                    channel: Some("discord".into()),
                    ..Default::default()
                },
            )
            .unwrap();
        let _session3 = store
            .create_session(
                "agent-1",
                SessionMetadata {
                    channel: Some("telegram".into()),
                    ..Default::default()
                },
            )
            .unwrap();

        store.archive_session(&session1.id, false).unwrap();
        store.archive_session(&session2.id, false).unwrap();
        // session3 not archived

        let archived = store.list_archived_sessions().unwrap();
        assert_eq!(archived.len(), 2);
    }

    #[test]
    fn test_delete_archive() {
        let (store, _temp) = create_test_store();

        let session = store
            .create_session("agent-1", SessionMetadata::default())
            .unwrap();

        store
            .append_message(ChatMessage::user(&session.id, "Hello"))
            .unwrap();

        store.archive_session(&session.id, false).unwrap();

        // Verify archive exists
        let archive_path = store.archive_path(&session.id).unwrap();
        assert!(archive_path.exists());

        // Delete archive
        let deleted = store.delete_archive(&session.id).unwrap();
        assert!(deleted);

        // Verify archive is gone
        assert!(!archive_path.exists());

        // Delete again returns false
        let deleted_again = store.delete_archive(&session.id).unwrap();
        assert!(!deleted_again);
    }

    #[test]
    fn test_delete_archive_removes_archive_hmac_sidecar() {
        let key_material = test_key_material();
        let (store, _temp) = create_encrypted_store(&key_material);

        let session = store
            .create_session("agent-1", SessionMetadata::default())
            .unwrap();
        store
            .append_message(ChatMessage::user(&session.id, "Hello"))
            .unwrap();
        store.archive_session(&session.id, false).unwrap();

        let archive_path = store.archive_path(&session.id).unwrap();
        let sidecar_path = hmac_sidecar_path(&archive_path);
        assert!(archive_path.exists());
        assert!(sidecar_path.exists());

        let deleted = store.delete_archive(&session.id).unwrap();
        assert!(deleted);
        assert!(!archive_path.exists());
        assert!(!sidecar_path.exists());
    }

    #[test]
    fn test_get_archive_info() {
        let (store, _temp) = create_test_store();

        let session = store
            .create_session("agent-1", SessionMetadata::default())
            .unwrap();

        store
            .append_message(ChatMessage::user(&session.id, "Hello"))
            .unwrap();

        // No archive yet
        let info = store.get_archive_info(&session.id).unwrap();
        assert!(info.is_none());

        // Archive
        store.archive_session(&session.id, false).unwrap();

        // Get archive info
        let info = store.get_archive_info(&session.id).unwrap();
        assert!(info.is_some());
        let (path, size, archived_at) = info.unwrap();
        assert!(path.exists());
        assert!(size > 0);
        assert!(archived_at > 0);
    }

    #[test]
    fn test_archive_result_serialization() {
        let result = ArchiveResult {
            session_id: "session-1".to_string(),
            archive_path: "/path/to/archive.json".to_string(),
            message_count: 42,
            archive_size: 12345,
            archived_at: 1234567890,
            history_deleted: false,
        };

        let json = serde_json::to_string(&result).unwrap();
        let parsed: ArchiveResult = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.session_id, "session-1");
        assert_eq!(parsed.message_count, 42);
        assert_eq!(parsed.archive_size, 12345);
    }

    #[test]
    fn test_archived_session_serialization() {
        let session = Session::new("agent-1", SessionMetadata::default());
        let messages = vec![
            ChatMessage::user(&session.id, "Hello"),
            ChatMessage::assistant(&session.id, "Hi!"),
        ];

        let archived = ArchivedSession {
            session: session.clone(),
            messages,
            archived_at: 1234567890,
            version: 1,
        };

        let json = serde_json::to_string(&archived).unwrap();
        let parsed: ArchivedSession = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.session.id, session.id);
        assert_eq!(parsed.messages.len(), 2);
        assert_eq!(parsed.archived_at, 1234567890);
        assert_eq!(parsed.version, 1);
    }

    #[test]
    fn test_archive_empty_session() {
        let (store, _temp) = create_test_store();

        let session = store
            .create_session("agent-1", SessionMetadata::default())
            .unwrap();

        // Archive with no messages
        let result = store.archive_session(&session.id, false).unwrap();
        assert_eq!(result.message_count, 0);

        // Restore should work
        let restored = store.restore_session(&session.id).unwrap();
        assert_eq!(restored.message_count, 0);
    }

    #[test]
    fn test_archive_inactive_sessions() {
        let (store, _temp) = create_test_store();

        // Create sessions (all will be "recent" since created now)
        let _s1 = store
            .create_session("agent-1", SessionMetadata::default())
            .unwrap();
        let _s2 = store
            .create_session(
                "agent-1",
                SessionMetadata {
                    channel: Some("ch2".into()),
                    ..Default::default()
                },
            )
            .unwrap();

        // Try to archive sessions older than 30 days (none should match)
        let results = store.archive_inactive_sessions(30, false).unwrap();
        assert!(results.is_empty());
    }

    // ==================== Path Traversal Security Tests ====================

    #[test]
    fn test_validate_session_id_rejects_path_traversal() {
        // Path traversal with ..
        assert!(SessionStore::validate_session_id("../etc/passwd").is_err());
        assert!(SessionStore::validate_session_id("foo/../bar").is_err());
        assert!(SessionStore::validate_session_id("..").is_err());

        // Path traversal with slashes
        assert!(SessionStore::validate_session_id("/etc/passwd").is_err());
        assert!(SessionStore::validate_session_id("foo/bar").is_err());
        assert!(SessionStore::validate_session_id("foo\\bar").is_err());

        // Empty ID
        assert!(SessionStore::validate_session_id("").is_err());

        // Invalid characters
        assert!(SessionStore::validate_session_id("foo bar").is_err());
        assert!(SessionStore::validate_session_id("foo@bar").is_err());
        assert!(SessionStore::validate_session_id("foo:bar").is_err());
    }

    #[test]
    fn test_validate_session_id_accepts_valid_ids() {
        // UUIDs
        assert!(SessionStore::validate_session_id("550e8400-e29b-41d4-a716-446655440000").is_ok());

        // Alphanumeric slugs
        assert!(SessionStore::validate_session_id("my-session-123").is_ok());
        assert!(SessionStore::validate_session_id("session_with_underscores").is_ok());
        assert!(SessionStore::validate_session_id("ABC123").is_ok());
    }

    #[test]
    fn test_get_session_rejects_path_traversal() {
        let (store, _temp) = create_test_store();

        // Create a valid session first
        let session = store
            .create_session("agent-1", SessionMetadata::default())
            .unwrap();
        assert!(store.get_session(&session.id).is_ok());

        // Path traversal attempts should fail with InvalidSessionKey error
        let result = store.get_session("../malicious");
        assert!(matches!(
            result,
            Err(SessionStoreError::InvalidSessionKey(_))
        ));

        let result = store.get_session("foo/../bar");
        assert!(matches!(
            result,
            Err(SessionStoreError::InvalidSessionKey(_))
        ));

        let result = store.get_session("/etc/passwd");
        assert!(matches!(
            result,
            Err(SessionStoreError::InvalidSessionKey(_))
        ));
    }

    #[test]
    fn test_delete_session_rejects_path_traversal() {
        let (store, _temp) = create_test_store();

        // Path traversal attempts should fail
        let result = store.delete_session("../malicious");
        assert!(matches!(
            result,
            Err(SessionStoreError::InvalidSessionKey(_))
        ));
    }

    #[test]
    fn test_get_history_rejects_path_traversal() {
        let (store, _temp) = create_test_store();

        // Path traversal attempts should fail
        let result = store.get_history("../malicious", None, None);
        assert!(matches!(
            result,
            Err(SessionStoreError::InvalidSessionKey(_))
        ));
    }

    // ==================== Export / Purge User Data Tests ====================

    #[test]
    fn test_export_user_data_empty() {
        let (store, _temp) = create_test_store();

        let result = store.export_user_data("nonexistent-user").unwrap();

        assert_eq!(result["user_id"], "nonexistent-user");
        assert_eq!(result["session_count"], 0);
        assert!(result["sessions"].as_array().unwrap().is_empty());
        assert!(result["warnings"].as_array().unwrap().is_empty());
        assert!(result["exported_at"].as_str().is_some());
    }

    #[test]
    fn test_export_user_data_with_sessions() {
        let (store, _temp) = create_test_store();

        // Create two sessions for user-1
        let s1 = store
            .create_session(
                "agent-1",
                SessionMetadata {
                    user_id: Some("user-1".into()),
                    channel: Some("telegram".into()),
                    ..Default::default()
                },
            )
            .unwrap();

        let s2 = store
            .create_session(
                "agent-1",
                SessionMetadata {
                    user_id: Some("user-1".into()),
                    channel: Some("discord".into()),
                    ..Default::default()
                },
            )
            .unwrap();

        // Add messages to both sessions
        store
            .append_message(ChatMessage::user(&s1.id, "Hello from session 1"))
            .unwrap();
        store
            .append_message(ChatMessage::assistant(&s1.id, "Hi there!"))
            .unwrap();
        store
            .append_message(ChatMessage::user(&s2.id, "Hello from session 2"))
            .unwrap();

        let result = store.export_user_data("user-1").unwrap();

        assert_eq!(result["user_id"], "user-1");
        assert_eq!(result["session_count"], 2);

        let sessions = result["sessions"].as_array().unwrap();
        assert_eq!(sessions.len(), 2);

        // Verify each exported session has both "session" and "messages" keys
        for exported in sessions {
            assert!(exported["session"].is_object());
            assert!(exported["messages"].is_array());
        }

        assert!(result["warnings"].as_array().unwrap().is_empty());
    }

    #[test]
    fn test_export_user_data_redacts_error_detail_in_warnings() {
        let temp_dir = TempDir::new().unwrap();
        let key = Zeroizing::new(integrity::derive_hmac_key(b"history-secret"));
        let store = SessionStore::with_base_path(temp_dir.path().to_path_buf())
            .with_hmac_key(key)
            .with_integrity_action(integrity::IntegrityAction::Reject);

        let session = store
            .create_session(
                "agent-1",
                SessionMetadata {
                    user_id: Some("user-1".into()),
                    ..Default::default()
                },
            )
            .unwrap();
        store
            .append_message(ChatMessage::user(&session.id, "Hello"))
            .unwrap();

        let history_path = store.session_history_path(&session.id).unwrap();
        fs::write(&history_path, "tampered\n").unwrap();

        let result = store.export_user_data("user-1").unwrap();
        let warnings = result["warnings"].as_array().unwrap();
        assert_eq!(warnings.len(), 1);
        let warning = warnings[0].as_str().unwrap();
        assert!(warning.contains("failed to export session"));
        assert!(warning.ends_with(": session data could not be read from disk"));
        assert!(!warning.contains("Session store is locked"));
        assert!(!warning.contains("history-secret"));
    }

    #[test]
    fn test_purge_user_data_empty() {
        let (store, _temp) = create_test_store();

        let (deleted, total) = store.purge_user_data("nonexistent-user").unwrap();
        assert_eq!(deleted, 0);
        assert_eq!(total, 0);
    }

    #[test]
    fn test_purge_user_data_deletes_user_sessions() {
        let (store, _temp) = create_test_store();

        // Create sessions for user-1
        let s1 = store
            .create_session(
                "agent-1",
                SessionMetadata {
                    user_id: Some("user-1".into()),
                    channel: Some("telegram".into()),
                    chat_id: Some("u1-chat1".into()),
                    ..Default::default()
                },
            )
            .unwrap();
        store
            .create_session(
                "agent-1",
                SessionMetadata {
                    user_id: Some("user-1".into()),
                    channel: Some("discord".into()),
                    chat_id: Some("u1-chat2".into()),
                    ..Default::default()
                },
            )
            .unwrap();

        // Create session for user-2
        let s3 = store
            .create_session(
                "agent-1",
                SessionMetadata {
                    user_id: Some("user-2".into()),
                    channel: Some("telegram".into()),
                    chat_id: Some("u2-chat1".into()),
                    ..Default::default()
                },
            )
            .unwrap();

        // Add messages
        store
            .append_message(ChatMessage::user(&s1.id, "Hello"))
            .unwrap();

        // Purge user-1
        let (deleted, total) = store.purge_user_data("user-1").unwrap();
        assert_eq!(deleted, 2);
        assert_eq!(total, 2);

        // Verify user-1 sessions are gone
        let user1_sessions = store
            .list_sessions(SessionFilter::new().with_user_id("user-1"))
            .unwrap();
        assert!(user1_sessions.is_empty());

        // Verify user-2 sessions are still intact
        let user2_sessions = store
            .list_sessions(SessionFilter::new().with_user_id("user-2"))
            .unwrap();
        assert_eq!(user2_sessions.len(), 1);
        assert_eq!(user2_sessions[0].id, s3.id);
    }

    #[test]
    fn test_purge_user_data_returns_total() {
        let (store, _temp) = create_test_store();

        // Create 3 sessions for user-1
        for i in 0..3 {
            store
                .create_session(
                    "agent-1",
                    SessionMetadata {
                        user_id: Some("user-1".into()),
                        channel: Some(format!("ch-{}", i)),
                        ..Default::default()
                    },
                )
                .unwrap();
        }

        let (deleted, total) = store.purge_user_data("user-1").unwrap();
        assert_eq!(total, 3);
        assert_eq!(
            deleted, total,
            "all sessions should be successfully deleted"
        );
    }

    #[test]
    fn test_export_user_data_rejects_empty_user_id() {
        let (store, _temp) = create_test_store();
        let result = store.export_user_data("");
        assert!(result.is_err());
        assert!(matches!(result, Err(SessionStoreError::InvalidUserId(_))));
    }

    #[test]
    fn test_export_user_data_rejects_whitespace_user_id() {
        let (store, _temp) = create_test_store();
        let result = store.export_user_data("   ");
        assert!(result.is_err());
        assert!(matches!(result, Err(SessionStoreError::InvalidUserId(_))));
    }

    #[test]
    fn test_purge_user_data_rejects_empty_user_id() {
        let (store, _temp) = create_test_store();
        let result = store.purge_user_data("");
        assert!(result.is_err());
        assert!(matches!(result, Err(SessionStoreError::InvalidUserId(_))));
    }

    #[test]
    fn test_purge_user_data_rejects_whitespace_user_id() {
        let (store, _temp) = create_test_store();
        let result = store.purge_user_data("  \t  ");
        assert!(result.is_err());
        assert!(matches!(result, Err(SessionStoreError::InvalidUserId(_))));
    }

    #[test]
    fn test_export_user_data_returns_sessions() {
        let (store, _temp) = create_test_store();

        // Create sessions for the user
        let _s1 = store
            .create_session(
                "agent-1",
                SessionMetadata {
                    user_id: Some("user123".into()),
                    channel: Some("channel1".into()),
                    ..Default::default()
                },
            )
            .unwrap();
        let _s2 = store
            .create_session(
                "agent-1",
                SessionMetadata {
                    user_id: Some("user123".into()),
                    channel: Some("channel2".into()),
                    ..Default::default()
                },
            )
            .unwrap();
        // Create session for different user
        let _s3 = store
            .create_session(
                "agent-1",
                SessionMetadata {
                    user_id: Some("other_user".into()),
                    channel: Some("channel1".into()),
                    chat_id: Some("other".into()),
                    ..Default::default()
                },
            )
            .unwrap();

        let export = store.export_user_data("user123").unwrap();
        assert_eq!(export["session_count"], 2);
        assert_eq!(export["user_id"], "user123");
        assert!(export["exported_at"].is_string());
        assert!(export["warnings"].as_array().unwrap().is_empty());
    }

    #[test]
    fn test_export_user_data_empty_user() {
        let (store, _temp) = create_test_store();

        let result = store.export_user_data("");
        assert!(result.is_err());
    }

    #[test]
    fn test_export_user_data_whitespace_user() {
        let (store, _temp) = create_test_store();

        let result = store.export_user_data("   ");
        assert!(result.is_err());
    }

    #[test]
    fn test_export_user_data_no_sessions() {
        let (store, _temp) = create_test_store();

        let export = store.export_user_data("nonexistent").unwrap();
        assert_eq!(export["session_count"], 0);
        assert!(export["sessions"].as_array().unwrap().is_empty());
    }

    #[test]
    fn test_purge_user_data_deletes_sessions() {
        let (store, _temp) = create_test_store();

        let _s1 = store
            .create_session(
                "agent-1",
                SessionMetadata {
                    user_id: Some("user123".into()),
                    channel: Some("channel1".into()),
                    chat_id: Some("purge-c1".into()),
                    ..Default::default()
                },
            )
            .unwrap();
        let _s2 = store
            .create_session(
                "agent-1",
                SessionMetadata {
                    user_id: Some("user123".into()),
                    channel: Some("channel2".into()),
                    chat_id: Some("purge-c2".into()),
                    ..Default::default()
                },
            )
            .unwrap();
        let _s3 = store
            .create_session(
                "agent-1",
                SessionMetadata {
                    user_id: Some("other_user".into()),
                    channel: Some("channel1".into()),
                    chat_id: Some("purge-other".into()),
                    ..Default::default()
                },
            )
            .unwrap();

        let (deleted, total) = store.purge_user_data("user123").unwrap();
        assert_eq!(deleted, 2);
        assert_eq!(total, 2);

        // Verify user123's sessions are gone
        let export = store.export_user_data("user123").unwrap();
        assert_eq!(export["session_count"], 0);

        // Verify other_user's sessions remain
        let export = store.export_user_data("other_user").unwrap();
        assert_eq!(export["session_count"], 1);
    }

    #[test]
    fn test_purge_user_data_empty_user() {
        let (store, _temp) = create_test_store();

        let result = store.purge_user_data("");
        assert!(result.is_err());
    }

    #[test]
    fn test_purge_user_data_no_sessions() {
        let (store, _temp) = create_test_store();

        let (deleted, total) = store.purge_user_data("nonexistent").unwrap();
        assert_eq!(deleted, 0);
        assert_eq!(total, 0);
    }
}
