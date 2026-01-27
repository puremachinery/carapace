//! Session store implementation
//!
//! File-based storage for sessions and chat history. Sessions are stored
//! as JSON metadata files, and chat history is stored as JSONL for
//! append-friendly operations.

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::PathBuf;
use std::sync::Arc;
use uuid::Uuid;

/// Default message count threshold for auto-compaction
const DEFAULT_COMPACT_THRESHOLD: usize = 100;

/// Maximum message count before forcing compaction
const MAX_MESSAGES_BEFORE_COMPACT: usize = 500;

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
    pub tokens: Option<u32>,
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
    pub fn with_tokens(mut self, tokens: u32) -> Self {
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
        true
    }
}

/// In-memory session cache entry
#[derive(Debug)]
struct CachedSession {
    session: Session,
    dirty: bool,
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
}

impl Default for SessionStore {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionStore {
    /// Create a new session store with default path (~/.moltbot/sessions/)
    pub fn new() -> Self {
        let base_path = dirs::home_dir()
            .map(|p| p.join(".moltbot").join("sessions"))
            .unwrap_or_else(|| PathBuf::from(".moltbot/sessions"));
        Self::with_base_path(base_path)
    }

    /// Create a session store with a custom base path
    pub fn with_base_path(base_path: PathBuf) -> Self {
        Self {
            base_path,
            sessions: RwLock::new(HashMap::new()),
            key_to_id: RwLock::new(HashMap::new()),
            compact_threshold: DEFAULT_COMPACT_THRESHOLD,
        }
    }

    /// Set the compaction threshold
    pub fn with_compact_threshold(mut self, threshold: usize) -> Self {
        self.compact_threshold = threshold;
        self
    }

    /// Ensure the base directory exists
    fn ensure_base_dir(&self) -> Result<(), SessionStoreError> {
        if !self.base_path.exists() {
            fs::create_dir_all(&self.base_path)?;
        }
        Ok(())
    }

    /// Get the metadata file path for a session
    fn session_meta_path(&self, session_id: &str) -> PathBuf {
        self.base_path.join(format!("{}.json", session_id))
    }

    /// Get the history file path for a session
    fn session_history_path(&self, session_id: &str) -> PathBuf {
        self.base_path.join(format!("{}.jsonl", session_id))
    }

    /// Create a new session
    pub fn create_session(
        &self,
        agent_id: impl Into<String>,
        metadata: SessionMetadata,
    ) -> Result<Session, SessionStoreError> {
        self.ensure_base_dir()?;

        let session = Session::new(agent_id, metadata);

        // Check for existing session with same key
        {
            let key_map = self.key_to_id.read();
            if key_map.contains_key(&session.session_key) {
                return Err(SessionStoreError::AlreadyExists(session.session_key));
            }
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
                CachedSession {
                    session: session.clone(),
                    dirty: false,
                },
            );
        }

        Ok(session)
    }

    /// Get a session by ID
    pub fn get_session(&self, session_id: &str) -> Result<Session, SessionStoreError> {
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
            Err(SessionStoreError::NotFound(session_key.to_string()))
        }
    }

    /// Get or create a session by session key
    pub fn get_or_create_session(
        &self,
        session_key: impl Into<String>,
        metadata: SessionMetadata,
    ) -> Result<Session, SessionStoreError> {
        let key = session_key.into();

        match self.get_session_by_key(&key) {
            Ok(session) => Ok(session),
            Err(SessionStoreError::NotFound(_)) => {
                let session = Session::with_session_key(key, metadata);
                self.ensure_base_dir()?;
                self.write_session_meta(&session)?;

                let mut sessions = self.sessions.write();
                let mut key_map = self.key_to_id.write();
                key_map.insert(session.session_key.clone(), session.id.clone());
                sessions.insert(
                    session.id.clone(),
                    CachedSession {
                        session: session.clone(),
                        dirty: false,
                    },
                );

                Ok(session)
            }
            Err(e) => Err(e),
        }
    }

    /// List sessions with optional filtering
    pub fn list_sessions(&self, filter: SessionFilter) -> Result<Vec<Session>, SessionStoreError> {
        // Load all sessions from disk
        self.load_sessions_from_disk()?;

        let sessions = self.sessions.read();
        let mut result: Vec<Session> = sessions
            .values()
            .map(|c| c.session.clone())
            .filter(|s| filter.matches(s))
            .collect();

        // Sort by updated_at descending
        result.sort_by(|a, b| b.updated_at.cmp(&a.updated_at));

        // Apply offset and limit
        let offset = filter.offset.unwrap_or(0);
        let limit = filter.limit.unwrap_or(usize::MAX);

        Ok(result.into_iter().skip(offset).take(limit).collect())
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
        let history_path = self.session_history_path(session_id);
        if history_path.exists() {
            fs::remove_file(&history_path)?;
        }

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
        let meta_path = self.session_meta_path(session_id);
        let history_path = self.session_history_path(session_id);

        if meta_path.exists() {
            fs::remove_file(&meta_path)?;
        }
        if history_path.exists() {
            fs::remove_file(&history_path)?;
        }

        // Remove from caches
        {
            let mut sessions = self.sessions.write();
            let mut key_map = self.key_to_id.write();
            sessions.remove(session_id);
            key_map.remove(&session.session_key);
        }

        Ok(())
    }

    /// Append a message to session history
    pub fn append_message(&self, message: ChatMessage) -> Result<(), SessionStoreError> {
        self.ensure_base_dir()?;

        let session_id = message.session_id.clone();

        // Append to history file (JSONL format)
        let history_path = self.session_history_path(&session_id);
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&history_path)?;
        let mut writer = BufWriter::new(file);
        serde_json::to_writer(&mut writer, &message)?;
        writeln!(writer)?;
        writer.flush()?;

        // Update session message count
        self.increment_message_count(&session_id)?;

        Ok(())
    }

    /// Get chat history for a session
    pub fn get_history(
        &self,
        session_id: &str,
        limit: Option<usize>,
        before_id: Option<&str>,
    ) -> Result<Vec<ChatMessage>, SessionStoreError> {
        let history_path = self.session_history_path(session_id);

        if !history_path.exists() {
            return Ok(Vec::new());
        }

        let file = File::open(&history_path)?;
        let reader = BufReader::new(file);

        let mut messages: Vec<ChatMessage> = Vec::new();
        let mut found_before = before_id.is_none();

        for line in reader.lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }

            let msg: ChatMessage = serde_json::from_str(&line)?;

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
        let history_path = self.session_history_path(session_id);

        if history_path.exists() {
            fs::remove_file(&history_path)?;
        }

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

        if session.status == SessionStatus::Compacting {
            return Err(SessionStoreError::CompactionInProgress(
                session_id.to_string(),
            ));
        }

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

        // Write new history file atomically
        let history_path = self.session_history_path(session_id);
        let temp_path = history_path.with_extension("jsonl.tmp");

        {
            let file = File::create(&temp_path)?;
            let mut writer = BufWriter::new(file);

            // Write summary as system message
            let summary_msg = ChatMessage::system(session_id, &summary);
            serde_json::to_writer(&mut writer, &summary_msg)?;
            writeln!(writer)?;

            // Write kept messages
            for msg in &to_keep {
                serde_json::to_writer(&mut writer, msg)?;
                writeln!(writer)?;
            }

            writer.flush()?;
        }

        // Atomic rename
        fs::rename(&temp_path, &history_path)?;

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

    /// Load a session from disk
    fn load_session(&self, session_id: &str) -> Result<Session, SessionStoreError> {
        let meta_path = self.session_meta_path(session_id);

        if !meta_path.exists() {
            return Err(SessionStoreError::NotFound(session_id.to_string()));
        }

        let content = fs::read_to_string(&meta_path)?;
        let session: Session = serde_json::from_str(&content)?;

        // Update caches
        {
            let mut sessions = self.sessions.write();
            let mut key_map = self.key_to_id.write();
            key_map.insert(session.session_key.clone(), session.id.clone());
            sessions.insert(
                session.id.clone(),
                CachedSession {
                    session: session.clone(),
                    dirty: false,
                },
            );
        }

        Ok(session)
    }

    /// Load all sessions from disk into cache
    fn load_sessions_from_disk(&self) -> Result<(), SessionStoreError> {
        if !self.base_path.exists() {
            return Ok(());
        }

        let entries = fs::read_dir(&self.base_path)?;

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

                    // Load session
                    if let Ok(session) = self.load_session(stem) {
                        let mut sessions = self.sessions.write();
                        let mut key_map = self.key_to_id.write();
                        key_map.insert(session.session_key.clone(), session.id.clone());
                        sessions.insert(
                            session.id.clone(),
                            CachedSession {
                                session,
                                dirty: false,
                            },
                        );
                    }
                }
            }
        }

        Ok(())
    }

    /// Write session metadata to disk
    fn write_session_meta(&self, session: &Session) -> Result<(), SessionStoreError> {
        self.ensure_base_dir()?;

        let meta_path = self.session_meta_path(&session.id);
        let temp_path = meta_path.with_extension("json.tmp");

        // Write to temp file first
        {
            let file = File::create(&temp_path)?;
            let writer = BufWriter::new(file);
            serde_json::to_writer_pretty(writer, session)?;
        }

        // Atomic rename
        fs::rename(&temp_path, &meta_path)?;

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
                    CachedSession {
                        session,
                        dirty: true,
                    },
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

/// Create a shared session store
pub fn create_store() -> Arc<SessionStore> {
    Arc::new(SessionStore::new())
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
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn create_test_store() -> (SessionStore, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let store = SessionStore::with_base_path(temp_dir.path().to_path_buf());
        (store, temp_dir)
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
                    model: Some("claude-3".into()),
                    ..Default::default()
                },
            )
            .unwrap();

        assert_eq!(updated.metadata.name, Some("Updated Name".into()));
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
        use std::sync::Arc;
        use std::thread;

        let temp_dir = TempDir::new().unwrap();
        let store = Arc::new(SessionStore::with_base_path(temp_dir.path().to_path_buf()));

        let session = store
            .create_session("agent-1", SessionMetadata::default())
            .unwrap();
        let session_id = session.id.clone();

        let mut handles = vec![];

        // Spawn multiple threads appending messages
        for i in 0..10 {
            let store_clone = Arc::clone(&store);
            let sid = session_id.clone();
            handles.push(thread::spawn(move || {
                store_clone
                    .append_message(ChatMessage::user(&sid, format!("Message {}", i)))
                    .unwrap();
            }));
        }

        for handle in handles {
            handle.join().unwrap();
        }

        let history = store.get_history(&session_id, None, None).unwrap();
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
}
