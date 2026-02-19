//! Session, agent, and chat handlers.
//!
//! This module implements the agent and chat methods for the WebSocket server:
//! - `agent`: Send a message to the agent and start a streaming response
//! - `agent.wait`: Wait for an agent run to complete
//! - `chat.send`: Send a chat message and queue an agent response
//! - `chat.abort`: Cancel an in-progress agent run
//!
//! ## Streaming Events
//!
//! During agent execution, the following events are emitted:
//! - `agent.started`: Agent run has started
//! - `agent.delta`: Partial response content (streaming)
//! - `agent.tool.start`: Tool execution started
//! - `agent.tool.end`: Tool execution completed
//! - `agent.completed`: Agent run completed successfully
//! - `agent.error`: Agent run failed
//!
//! ## Cancellation
//!
//! Agent runs can be cancelled via `chat.abort`. The cancellation is coordinated
//! through a per-session cancellation token that is checked periodically during
//! execution.

use serde_json::{json, Value};
use std::collections::HashMap;
use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use super::super::*;

/// Status of an agent run
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentRunStatus {
    /// Run is queued but not yet started
    Queued,
    /// Run is currently executing
    Running,
    /// Run completed successfully
    Completed,
    /// Run failed with an error
    Failed,
    /// Run was cancelled
    Cancelled,
}

impl std::fmt::Display for AgentRunStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Queued => write!(f, "queued"),
            Self::Running => write!(f, "running"),
            Self::Completed => write!(f, "completed"),
            Self::Failed => write!(f, "failed"),
            Self::Cancelled => write!(f, "cancelled"),
        }
    }
}

/// Represents an active agent run
#[derive(Debug)]
pub struct AgentRun {
    /// Unique run identifier
    pub run_id: String,
    /// Session key this run belongs to
    pub session_key: String,
    /// Current status
    pub status: AgentRunStatus,
    /// Original message that started this run
    pub message: String,
    /// Accumulated response content
    pub response: String,
    /// Error message if failed
    pub error: Option<String>,
    /// When the run was created (Unix ms)
    pub created_at: u64,
    /// When the run started executing (Unix ms)
    pub started_at: Option<u64>,
    /// When the run completed (Unix ms)
    pub completed_at: Option<u64>,
    /// Token that signals cancellation to the running executor task.
    pub cancel_token: CancellationToken,
    /// Waiters for this run to complete
    pub(crate) waiters: Vec<oneshot::Sender<AgentRunResult>>,
}

/// Result of an agent run for waiters
#[derive(Debug, Clone)]
pub struct AgentRunResult {
    pub run_id: String,
    pub status: AgentRunStatus,
    pub response: Option<String>,
    pub error: Option<String>,
    pub started_at: Option<u64>,
    pub completed_at: Option<u64>,
}

/// Registry for tracking active agent runs
#[derive(Debug, Default)]
pub struct AgentRunRegistry {
    /// Active runs by run_id
    runs: HashMap<String, AgentRun>,
    /// Run IDs by session key (for looking up runs by session)
    runs_by_session: HashMap<String, Vec<String>>,
}

impl AgentRunRegistry {
    /// Create a new empty registry
    pub fn new() -> Self {
        Self::default()
    }

    /// Maximum number of runs to keep in the registry before pruning.
    const MAX_RUNS: usize = 1000;

    /// Register a new agent run.
    ///
    /// Returns `false` if a run with the same ID already exists and is still
    /// active (Queued or Running). Callers should treat this as an idempotent
    /// duplicate and return the existing run's status instead of spawning a new
    /// executor.
    ///
    /// Automatically prunes old completed runs when the registry exceeds
    /// [`MAX_RUNS`] to prevent unbounded memory growth.
    pub fn register(&mut self, run: AgentRun) -> bool {
        // Reject duplicate registration for active runs
        if let Some(existing) = self.runs.get(&run.run_id) {
            if matches!(
                existing.status,
                AgentRunStatus::Queued | AgentRunStatus::Running
            ) {
                tracing::warn!(
                    run_id = %run.run_id,
                    status = %existing.status,
                    "duplicate run registration rejected — run already active"
                );
                return false;
            }
        }

        let run_id = run.run_id.clone();
        let session_key = run.session_key.clone();
        self.runs.insert(run_id.clone(), run);
        self.runs_by_session
            .entry(session_key)
            .or_default()
            .push(run_id);

        if self.runs.len() > Self::MAX_RUNS {
            self.prune_completed();
        }
        true
    }

    /// Remove the oldest completed/failed/cancelled runs to stay under the cap.
    fn prune_completed(&mut self) {
        let target = Self::MAX_RUNS / 2;
        if self.runs.len() <= target {
            return;
        }

        // Collect terminal run IDs sorted by completed_at (oldest first)
        let mut terminal: Vec<(String, u64)> = self
            .runs
            .iter()
            .filter(|(_, r)| {
                matches!(
                    r.status,
                    AgentRunStatus::Completed | AgentRunStatus::Failed | AgentRunStatus::Cancelled
                )
            })
            .map(|(id, r)| (id.clone(), r.completed_at.unwrap_or(0)))
            .collect();
        terminal.sort_by_key(|(_, ts)| *ts);

        let to_remove = self.runs.len().saturating_sub(target);
        for (run_id, _) in terminal.into_iter().take(to_remove) {
            self.remove(&run_id);
        }
    }

    /// Get a run by ID
    pub fn get(&self, run_id: &str) -> Option<&AgentRun> {
        self.runs.get(run_id)
    }

    /// Get a mutable run by ID
    pub fn get_mut(&mut self, run_id: &str) -> Option<&mut AgentRun> {
        self.runs.get_mut(run_id)
    }

    /// Get all run IDs for a session
    pub fn get_runs_for_session(&self, session_key: &str) -> Vec<String> {
        self.runs_by_session
            .get(session_key)
            .cloned()
            .unwrap_or_default()
    }

    /// Remove a completed run
    pub fn remove(&mut self, run_id: &str) -> Option<AgentRun> {
        if let Some(run) = self.runs.remove(run_id) {
            if let Some(runs) = self.runs_by_session.get_mut(&run.session_key) {
                runs.retain(|id| id != run_id);
            }
            Some(run)
        } else {
            None
        }
    }

    /// Mark a run as started.
    /// Returns false if the run was already cancelled (avoids TOCTOU race).
    pub fn mark_started(&mut self, run_id: &str) -> bool {
        if let Some(run) = self.runs.get_mut(run_id) {
            if run.status == AgentRunStatus::Cancelled || run.cancel_token.is_cancelled() {
                return false;
            }
            run.status = AgentRunStatus::Running;
            run.started_at = Some(now_ms());
            true
        } else {
            false
        }
    }

    /// Mark a run as completed with a response
    pub fn mark_completed(&mut self, run_id: &str, response: String) -> bool {
        if let Some(run) = self.runs.get_mut(run_id) {
            run.status = AgentRunStatus::Completed;
            run.response = response.clone();
            run.completed_at = Some(now_ms());

            // Notify all waiters
            let result = AgentRunResult {
                run_id: run.run_id.clone(),
                status: AgentRunStatus::Completed,
                response: Some(response),
                error: None,
                started_at: run.started_at,
                completed_at: run.completed_at,
            };
            for waiter in run.waiters.drain(..) {
                let _ = waiter.send(result.clone());
            }
            true
        } else {
            false
        }
    }

    /// Mark a run as failed with an error
    pub fn mark_failed(&mut self, run_id: &str, error: String) -> bool {
        if let Some(run) = self.runs.get_mut(run_id) {
            run.status = AgentRunStatus::Failed;
            run.error = Some(error.clone());
            run.completed_at = Some(now_ms());

            // Notify all waiters
            let result = AgentRunResult {
                run_id: run.run_id.clone(),
                status: AgentRunStatus::Failed,
                response: None,
                error: Some(error),
                started_at: run.started_at,
                completed_at: run.completed_at,
            };
            for waiter in run.waiters.drain(..) {
                let _ = waiter.send(result.clone());
            }
            true
        } else {
            false
        }
    }

    /// Mark a run as cancelled
    pub fn mark_cancelled(&mut self, run_id: &str) -> bool {
        if let Some(run) = self.runs.get_mut(run_id) {
            run.cancel_token.cancel();
            run.status = AgentRunStatus::Cancelled;
            run.completed_at = Some(now_ms());

            // Notify all waiters
            let result = AgentRunResult {
                run_id: run.run_id.clone(),
                status: AgentRunStatus::Cancelled,
                response: None,
                error: Some("cancelled".to_string()),
                started_at: run.started_at,
                completed_at: run.completed_at,
            };
            for waiter in run.waiters.drain(..) {
                let _ = waiter.send(result.clone());
            }
            true
        } else {
            false
        }
    }

    /// Append delta content to a running run
    pub fn append_delta(&mut self, run_id: &str, delta: &str) -> bool {
        if let Some(run) = self.runs.get_mut(run_id) {
            if run.status == AgentRunStatus::Running {
                run.response.push_str(delta);
                return true;
            }
        }
        false
    }

    /// Add a waiter for a run
    pub fn add_waiter(&mut self, run_id: &str) -> Option<oneshot::Receiver<AgentRunResult>> {
        if let Some(run) = self.runs.get_mut(run_id) {
            // If already completed, return the result immediately
            if matches!(
                run.status,
                AgentRunStatus::Completed | AgentRunStatus::Failed | AgentRunStatus::Cancelled
            ) {
                let (tx, rx) = oneshot::channel();
                let result = AgentRunResult {
                    run_id: run.run_id.clone(),
                    status: run.status,
                    response: if run.status == AgentRunStatus::Completed {
                        Some(run.response.clone())
                    } else {
                        None
                    },
                    error: run.error.clone(),
                    started_at: run.started_at,
                    completed_at: run.completed_at,
                };
                let _ = tx.send(result);
                return Some(rx);
            }

            // Otherwise add to waiters
            let (tx, rx) = oneshot::channel();
            run.waiters.push(tx);
            Some(rx)
        } else {
            None
        }
    }

    /// Get active (non-completed) runs for a session
    pub fn get_active_runs_for_session(&self, session_key: &str) -> Vec<String> {
        self.runs_by_session
            .get(session_key)
            .map(|runs| {
                runs.iter()
                    .filter(|run_id| {
                        self.runs.get(*run_id).is_some_and(|r| {
                            matches!(r.status, AgentRunStatus::Queued | AgentRunStatus::Running)
                        })
                    })
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Clean up old completed runs (older than 1 hour)
    pub fn cleanup_old_runs(&mut self) {
        let cutoff = now_ms().saturating_sub(3600 * 1000);
        let to_remove: Vec<String> = self
            .runs
            .iter()
            .filter(|(_, run)| {
                matches!(
                    run.status,
                    AgentRunStatus::Completed | AgentRunStatus::Failed | AgentRunStatus::Cancelled
                ) && run.completed_at.unwrap_or(0) < cutoff
            })
            .map(|(id, _)| id.clone())
            .collect();

        for run_id in to_remove {
            self.remove(&run_id);
        }
    }
}

/// Parsed filter/sort/pagination parameters for session listing.
struct SessionListFilters {
    filter: sessions::SessionFilter,
    active_minutes: Option<i64>,
    label_filter: Option<String>,
    search_filter: Option<String>,
    include_global: bool,
    include_unknown: bool,
    agent_filter: Option<String>,
    include_last_message: bool,
    include_derived_titles: bool,
}

/// Parse filter, sort, and pagination parameters from a sessions.list request.
fn parse_session_list_filters(params: Option<&Value>) -> SessionListFilters {
    let mut filter = sessions::SessionFilter::new();
    if let Some(limit) = params.and_then(|v| v.get("limit")).and_then(|v| v.as_i64()) {
        if limit > 0 {
            filter = filter.with_limit((limit as usize).min(1000)); // Cap at 1000
        }
    }
    if let Some(offset) = params
        .and_then(|v| v.get("offset"))
        .and_then(|v| v.as_i64())
    {
        if offset >= 0 {
            filter = filter.with_offset(offset as usize);
        }
    }
    if let Some(agent_id) = params
        .and_then(|v| v.get("agentId"))
        .and_then(|v| v.as_str())
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
    {
        filter = filter.with_agent_id(agent_id);
    }
    if let Some(channel) = params
        .and_then(|v| v.get("channel"))
        .and_then(|v| v.as_str())
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
    {
        filter = filter.with_channel(channel);
    }
    if let Some(user_id) = params
        .and_then(|v| v.get("userId"))
        .and_then(|v| v.as_str())
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
    {
        filter.user_id = Some(user_id.to_string());
    }
    if let Some(status) = params
        .and_then(|v| v.get("status"))
        .and_then(|v| v.as_str())
        .and_then(parse_session_status)
    {
        filter = filter.with_status(status);
    }
    let active_minutes = params
        .and_then(|v| v.get("activeMinutes"))
        .and_then(|v| v.as_i64())
        .map(|v| v.max(1));
    let label_filter = params
        .and_then(|v| v.get("label"))
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let search_filter = params
        .and_then(|v| v.get("search"))
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let include_global = params
        .and_then(|v| v.get("includeGlobal"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let include_unknown = params
        .and_then(|v| v.get("includeUnknown"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let agent_filter = params
        .and_then(|v| v.get("agentId"))
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let include_last_message = params
        .and_then(|v| v.get("includeLastMessage"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let include_derived_titles = params
        .and_then(|v| v.get("includeDerivedTitles"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    SessionListFilters {
        filter,
        active_minutes,
        label_filter,
        search_filter,
        include_global,
        include_unknown,
        agent_filter,
        include_last_message,
        include_derived_titles,
    }
}

/// Add metadata (last message preview, derived title, etc.) to session list entries.
/// Also applies client-side filters (global/unknown exclusion, agent, active minutes, label, search).
fn enrich_session_list(
    state: &WsServerState,
    sessions: &[sessions::Session],
    filters: &SessionListFilters,
) -> Vec<Value> {
    let now = now_ms() as i64;
    sessions
        .iter()
        .filter(|session| {
            if !filters.include_global && session.session_key == "global" {
                return false;
            }
            if !filters.include_unknown && session.session_key == "unknown" {
                return false;
            }
            if let Some(ref agent_id) = filters.agent_filter {
                if let Some(meta_id) = session.metadata.agent_id.as_deref() {
                    if meta_id != agent_id.as_str() {
                        return false;
                    }
                } else if let Some(parsed) = parse_agent_session_key(&session.session_key) {
                    if parsed != agent_id.as_str() {
                        return false;
                    }
                } else {
                    return false;
                }
            }
            if let Some(minutes) = filters.active_minutes {
                let cutoff = now - minutes * 60_000;
                if session.updated_at < cutoff {
                    return false;
                }
            }
            if let Some(ref label) = filters.label_filter {
                if session.metadata.name.as_deref() != Some(label.as_str()) {
                    return false;
                }
            }
            if let Some(ref search) = filters.search_filter {
                let mut haystack = session.session_key.clone();
                if let Some(name) = session.metadata.name.as_ref() {
                    haystack.push(' ');
                    haystack.push_str(name);
                }
                if !haystack.to_lowercase().contains(&search.to_lowercase()) {
                    return false;
                }
            }
            true
        })
        .map(|session| {
            let mut row = session_row(session);
            if filters.include_last_message {
                if let Ok(messages) = state.session_store.get_history(&session.id, Some(1), None) {
                    if let Some(last) = messages.last() {
                        if let Some(obj) = row.as_object_mut() {
                            obj.insert(
                                "lastMessagePreview".to_string(),
                                Value::String(truncate_preview(&last.content, 200)),
                            );
                        }
                    }
                }
            }
            if filters.include_derived_titles {
                if let Ok(messages) = state.session_store.get_history(&session.id, None, None) {
                    let title = messages
                        .iter()
                        .find(|msg| matches!(msg.role, sessions::MessageRole::User))
                        .map(|msg| truncate_preview(&msg.content, 60));
                    if let Some(title) = title {
                        if let Some(obj) = row.as_object_mut() {
                            obj.insert("derivedTitle".to_string(), Value::String(title));
                        }
                    }
                }
            }
            row
        })
        .collect::<Vec<_>>()
}

pub(super) fn handle_sessions_list(
    state: &WsServerState,
    params: Option<&Value>,
) -> Result<Value, ErrorShape> {
    let filters = parse_session_list_filters(params);

    let sessions = state
        .session_store
        .list_sessions(filters.filter.clone())
        .map_err(|err| {
            error_shape(
                ERROR_UNAVAILABLE,
                &format!("session list failed: {}", err),
                None,
            )
        })?;

    let rows = enrich_session_list(state, &sessions, &filters);
    Ok(json!({
        "ts": now_ms(),
        "path": state.session_store.base_path().display().to_string(),
        "count": rows.len(),
        "defaults": {
            "modelProvider": null,
            "model": null,
            "contextTokens": null
        },
        "sessions": rows
    }))
}

pub(super) fn handle_sessions_preview(
    state: &WsServerState,
    params: Option<&Value>,
) -> Result<Value, ErrorShape> {
    let keys = params
        .and_then(|v| v.get("keys"))
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.trim().to_string()))
                .filter(|s| !s.is_empty())
                .take(64)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let limit = params
        .and_then(|v| v.get("limit"))
        .and_then(|v| v.as_i64())
        .map(|v| v.max(1) as usize)
        .unwrap_or(12);
    let max_chars = params
        .and_then(|v| v.get("maxChars"))
        .and_then(|v| v.as_i64())
        .map(|v| v.max(20) as usize)
        .unwrap_or(240);

    let previews = keys
        .into_iter()
        .map(|key| match state.session_store.get_session_by_key(&key) {
            Ok(session) => match state
                .session_store
                .get_history(&session.id, Some(limit), None)
            {
                Ok(messages) => {
                    if messages.is_empty() {
                        json!({ "key": key, "status": "empty", "items": [] })
                    } else {
                        let items = messages
                            .into_iter()
                            .map(|msg| {
                                let text = truncate_preview(&msg.content, max_chars);
                                json!({
                                    "role": role_to_string(msg.role),
                                    "text": text
                                })
                            })
                            .collect::<Vec<_>>();
                        json!({ "key": key, "status": "ok", "items": items })
                    }
                }
                Err(_) => json!({ "key": key, "status": "error", "items": [] }),
            },
            Err(sessions::SessionStoreError::NotFound(_)) => {
                json!({ "key": key, "status": "missing", "items": [] })
            }
            Err(_) => json!({ "key": key, "status": "error", "items": [] }),
        })
        .collect::<Vec<_>>();

    Ok(json!({
        "ts": now_ms(),
        "previews": previews
    }))
}

/// Extract session key from params (supports both "key" and "sessionKey" fields)
fn extract_session_key(params: Option<&Value>) -> Option<String> {
    params
        .and_then(|v| v.get("key").or_else(|| v.get("sessionKey")))
        .and_then(|v| v.as_str())
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
}

fn resolve_session_from_params(
    state: &WsServerState,
    params: Option<&Value>,
) -> Result<sessions::Session, ErrorShape> {
    let session_id = params
        .and_then(|v| v.get("sessionId"))
        .and_then(|v| v.as_str())
        .map(|s| s.trim())
        .filter(|s| !s.is_empty());
    if let Some(session_id) = session_id {
        return state
            .session_store
            .get_session(session_id)
            .map_err(|err| error_shape(ERROR_INVALID_REQUEST, &err.to_string(), None));
    }
    let key = extract_session_key(params)
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "key is required", None))?;
    state
        .session_store
        .get_session_by_key(&key)
        .map_err(|err| error_shape(ERROR_INVALID_REQUEST, &err.to_string(), None))
}

fn read_string_param(params: Option<&Value>, key: &str) -> Option<String> {
    params
        .and_then(|v| v.get(key))
        .and_then(|v| v.as_str())
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
}

fn parse_session_status(raw: &str) -> Option<sessions::SessionStatus> {
    match raw {
        "active" => Some(sessions::SessionStatus::Active),
        "paused" => Some(sessions::SessionStatus::Paused),
        "archived" => Some(sessions::SessionStatus::Archived),
        "compacting" => Some(sessions::SessionStatus::Compacting),
        _ => None,
    }
}

fn role_to_string(role: sessions::MessageRole) -> &'static str {
    match role {
        sessions::MessageRole::User => "user",
        sessions::MessageRole::Assistant => "assistant",
        sessions::MessageRole::System => "system",
        sessions::MessageRole::Tool => "tool",
    }
}

fn session_row(session: &sessions::Session) -> Value {
    json!({
        "key": session.session_key,
        "kind": classify_session_key(&session.session_key, &session.metadata),
        "label": session.metadata.name,
        "displayName": session.metadata.description,
        "channel": session.metadata.channel,
        "chatId": session.metadata.chat_id,
        "userId": session.metadata.user_id,
        "updatedAt": session.updated_at,
        "sessionId": session.id,
        "messageCount": session.message_count,
        "thinkingLevel": session.metadata.thinking_level,
        "model": session.metadata.model
    })
}

fn session_entry(session: &sessions::Session) -> Value {
    json!({
        "sessionId": session.id,
        "updatedAt": session.updated_at,
        "label": session.metadata.name,
        "thinkingLevel": session.metadata.thinking_level,
        "model": session.metadata.model,
        "channel": session.metadata.channel,
        "chatId": session.metadata.chat_id,
        "agentId": session.metadata.agent_id,
        "userId": session.metadata.user_id,
        "status": session.status.to_string()
    })
}

fn classify_session_key(key: &str, metadata: &sessions::SessionMetadata) -> &'static str {
    if key == "global" {
        return "global";
    }
    if key == "unknown" {
        return "unknown";
    }
    if key.contains(":group:") || key.contains(":channel:") {
        return "group";
    }
    if let Some(chat_id) = metadata.chat_id.as_deref() {
        if chat_id.contains(":group:") || chat_id.contains(":channel:") {
            return "group";
        }
    }
    "direct"
}

fn parse_agent_session_key(key: &str) -> Option<&str> {
    if key == "global" || key == "unknown" {
        return None;
    }
    let mut parts = key.splitn(3, ':');
    let agent = parts.next()?;
    let channel = parts.next()?;
    let chat = parts.next()?;
    if agent.is_empty() || channel.is_empty() || chat.is_empty() {
        return None;
    }
    Some(agent)
}

fn truncate_preview(text: &str, max_len: usize) -> String {
    if text.len() <= max_len {
        return text.to_string();
    }
    // Find the last char boundary at or before max_len to avoid
    // panicking on multi-byte UTF-8 characters.
    let boundary = text[..=max_len.min(text.len() - 1)]
        .char_indices()
        .map(|(i, _)| i)
        .next_back()
        .unwrap_or(0);
    let mut out = text[..boundary].to_string();
    out.push('…');
    out
}

fn normalize_channel_param(
    channel: &str,
    channel_registry: &channels::ChannelRegistry,
) -> Option<String> {
    let trimmed = channel.trim();
    if trimmed.is_empty() {
        return None;
    }
    let normalized = trimmed.to_ascii_lowercase();
    if channel_registry.get(&normalized).is_some() {
        return Some(normalized);
    }
    tracing::warn!(
        channel = %trimmed,
        "unsupported channel requested for session metadata"
    );
    None
}

fn build_session_metadata(
    params: Option<&Value>,
    channel_registry: &channels::ChannelRegistry,
) -> sessions::SessionMetadata {
    let mut meta = sessions::SessionMetadata::default();
    if let Some(label) = read_string_param(params, "label") {
        meta.name = Some(label);
    }
    if let Some(description) = read_string_param(params, "description") {
        meta.description = Some(description);
    }
    if let Some(agent_id) = read_string_param(params, "agentId") {
        meta.agent_id = Some(agent_id);
    }
    if let Some(channel) = read_string_param(params, "channel") {
        if let Some(normalized) = normalize_channel_param(&channel, channel_registry) {
            meta.channel = Some(normalized);
        }
    }
    if let Some(chat_id) = read_string_param(params, "chatId") {
        meta.chat_id = Some(chat_id);
    }
    if let Some(user_id) = read_string_param(params, "userId") {
        meta.user_id = Some(user_id);
    }
    if let Some(model) = read_string_param(params, "model") {
        meta.model = Some(model);
    }
    if let Some(thinking_level) = read_string_param(params, "thinkingLevel") {
        meta.thinking_level = Some(thinking_level);
    }
    if let Some(tags) = params
        .and_then(|v| v.get("tags"))
        .and_then(|v| v.as_array())
    {
        meta.tags = tags
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.trim().to_string()))
            .filter(|s| !s.is_empty())
            .collect();
    }
    if let Some(extra) = params.and_then(|v| v.get("extra")) {
        if !extra.is_null() {
            meta.extra = Some(extra.clone());
        }
    }
    meta
}

fn has_metadata_updates(meta: &sessions::SessionMetadata) -> bool {
    meta.name.is_some()
        || meta.description.is_some()
        || meta.agent_id.is_some()
        || meta.channel.is_some()
        || meta.user_id.is_some()
        || meta.model.is_some()
        || meta.thinking_level.is_some()
        || !meta.tags.is_empty()
        || meta.extra.is_some()
}

fn apply_metadata_updates(
    target: &mut sessions::SessionMetadata,
    updates: &sessions::SessionMetadata,
) {
    if updates.name.is_some() {
        target.name = updates.name.clone();
    }
    if updates.description.is_some() {
        target.description = updates.description.clone();
    }
    if updates.agent_id.is_some() {
        target.agent_id = updates.agent_id.clone();
    }
    if updates.channel.is_some() {
        target.channel = updates.channel.clone();
    }
    if updates.chat_id.is_some() {
        target.chat_id = updates.chat_id.clone();
    }
    if updates.user_id.is_some() {
        target.user_id = updates.user_id.clone();
    }
    if updates.model.is_some() {
        target.model = updates.model.clone();
    }
    if updates.thinking_level.is_some() {
        target.thinking_level = updates.thinking_level.clone();
    }
    if !updates.tags.is_empty() {
        target.tags = updates.tags.clone();
    }
    if updates.extra.is_some() {
        target.extra = updates.extra.clone();
    }
}

fn derive_fork_session_key(state: &WsServerState, base_key: &str) -> Result<String, ErrorShape> {
    let mut candidate = format!("{}-fork", base_key);
    for suffix in 2..=1000 {
        match state.session_store.get_session_by_key(&candidate) {
            Ok(_) => {
                candidate = format!("{}-fork-{}", base_key, suffix);
            }
            Err(sessions::SessionStoreError::NotFound(_)) => return Ok(candidate),
            Err(err) => {
                return Err(error_shape(
                    ERROR_UNAVAILABLE,
                    &format!("session lookup failed: {}", err),
                    None,
                ))
            }
        }
    }
    Err(error_shape(
        ERROR_UNAVAILABLE,
        "failed to derive unique fork session key",
        None,
    ))
}

fn clone_message_for_session(
    message: &sessions::ChatMessage,
    session_id: &str,
) -> sessions::ChatMessage {
    sessions::ChatMessage {
        id: Uuid::new_v4().to_string(),
        session_id: session_id.to_string(),
        role: message.role,
        content: message.content.clone(),
        tool_call_id: message.tool_call_id.clone(),
        tool_name: message.tool_name.clone(),
        tokens: message.tokens,
        created_at: message.created_at,
        metadata: message.metadata.clone(),
    }
}

pub(super) fn handle_sessions_create(
    state: &WsServerState,
    params: Option<&Value>,
) -> Result<Value, ErrorShape> {
    let key = extract_session_key(params);
    let metadata = build_session_metadata(params, state.channel_registry());

    let session = if let Some(ref key) = key {
        match state.session_store.get_session_by_key(key) {
            Ok(_) => {
                return Err(error_shape(
                    ERROR_INVALID_REQUEST,
                    "session already exists",
                    Some(json!({ "key": key })),
                ))
            }
            Err(sessions::SessionStoreError::NotFound(_)) => {}
            Err(err) => {
                return Err(error_shape(
                    ERROR_UNAVAILABLE,
                    &format!("session lookup failed: {}", err),
                    None,
                ))
            }
        }
        state
            .session_store
            .get_or_create_session(key, metadata)
            .map_err(|err| {
                error_shape(
                    ERROR_UNAVAILABLE,
                    &format!("session create failed: {}", err),
                    None,
                )
            })?
    } else {
        let agent_id = metadata
            .agent_id
            .clone()
            .unwrap_or_else(|| "default".to_string());
        state
            .session_store
            .create_session(agent_id, metadata)
            .map_err(|err| {
                error_shape(
                    ERROR_UNAVAILABLE,
                    &format!("session create failed: {}", err),
                    None,
                )
            })?
    };

    Ok(json!({
        "ok": true,
        "key": session.session_key,
        "entry": session_entry(&session)
    }))
}

pub(super) fn handle_sessions_load(
    state: &WsServerState,
    params: Option<&Value>,
) -> Result<Value, ErrorShape> {
    let session = resolve_session_from_params(state, params)?;
    let include_messages = params
        .and_then(|v| v.get("includeMessages"))
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    let limit = params
        .and_then(|v| v.get("limit"))
        .and_then(|v| v.as_i64())
        .map(|v| v.max(1) as usize)
        .unwrap_or(200)
        .min(1000);

    let messages = if include_messages {
        state
            .session_store
            .get_history(&session.id, Some(limit), None)
            .map_err(|err| error_shape(ERROR_UNAVAILABLE, &err.to_string(), None))?
            .into_iter()
            .map(|m| {
                json!({
                    "id": m.id,
                    "role": role_to_string(m.role),
                    "content": m.content,
                    "ts": m.created_at
                })
            })
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };

    Ok(json!({
        "ok": true,
        "key": session.session_key,
        "sessionId": session.id,
        "messageCount": session.message_count,
        "entry": session_entry(&session),
        "messages": messages
    }))
}

pub(super) fn handle_sessions_fork(
    state: &WsServerState,
    params: Option<&Value>,
) -> Result<Value, ErrorShape> {
    let source = resolve_session_from_params(state, params)?;
    let updates = build_session_metadata(params, state.channel_registry());
    let mut metadata = source.metadata.clone();
    metadata.compaction = sessions::CompactionMetadata::default();
    apply_metadata_updates(&mut metadata, &updates);

    let requested_key =
        read_string_param(params, "newKey").or_else(|| read_string_param(params, "targetKey"));
    let target_key = if let Some(key) = requested_key {
        key
    } else {
        derive_fork_session_key(state, &source.session_key)?
    };

    match state.session_store.get_session_by_key(&target_key) {
        Ok(_) => {
            return Err(error_shape(
                ERROR_INVALID_REQUEST,
                "session already exists",
                Some(json!({ "key": target_key })),
            ))
        }
        Err(sessions::SessionStoreError::NotFound(_)) => {}
        Err(err) => {
            return Err(error_shape(
                ERROR_UNAVAILABLE,
                &format!("session lookup failed: {}", err),
                None,
            ))
        }
    }

    let session = state
        .session_store
        .get_or_create_session(&target_key, metadata)
        .map_err(|err| {
            error_shape(
                ERROR_UNAVAILABLE,
                &format!("session create failed: {}", err),
                None,
            )
        })?;

    let copy_history = params
        .and_then(|v| v.get("copyHistory"))
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    if copy_history {
        let limit = params
            .and_then(|v| v.get("limit"))
            .and_then(|v| v.as_i64())
            .map(|v| v.max(1) as usize)
            .unwrap_or(200)
            .min(1000);
        let history = state
            .session_store
            .get_history(&source.id, Some(limit), None)
            .map_err(|err| error_shape(ERROR_UNAVAILABLE, &err.to_string(), None))?;
        let cloned = history
            .iter()
            .map(|msg| clone_message_for_session(msg, &session.id))
            .collect::<Vec<_>>();
        state
            .session_store
            .append_messages(&cloned)
            .map_err(|err| error_shape(ERROR_UNAVAILABLE, &err.to_string(), None))?;
    }

    Ok(json!({
        "ok": true,
        "sourceKey": source.session_key,
        "key": session.session_key,
        "entry": session_entry(&session)
    }))
}

pub(super) fn handle_sessions_rename(
    state: &WsServerState,
    params: Option<&Value>,
) -> Result<Value, ErrorShape> {
    let key = extract_session_key(params)
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "key is required", None))?;
    let name = read_string_param(params, "label")
        .or_else(|| read_string_param(params, "name"))
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "name is required", None))?;
    let updates = sessions::SessionMetadata {
        name: Some(name),
        ..sessions::SessionMetadata::default()
    };

    let session = match state.session_store.get_session_by_key(&key) {
        Ok(existing) => state
            .session_store
            .patch_session(&existing.id, updates)
            .map_err(|err| {
                error_shape(
                    ERROR_UNAVAILABLE,
                    &format!("session rename failed: {}", err),
                    None,
                )
            })?,
        Err(sessions::SessionStoreError::NotFound(_)) => {
            return Err(error_shape(
                ERROR_INVALID_REQUEST,
                "session not found",
                Some(json!({ "key": key })),
            ))
        }
        Err(err) => {
            return Err(error_shape(
                ERROR_UNAVAILABLE,
                &format!("session load failed: {}", err),
                None,
            ))
        }
    };

    Ok(json!({
        "ok": true,
        "key": session.session_key,
        "entry": session_entry(&session)
    }))
}

pub(super) fn handle_sessions_switch(
    state: &WsServerState,
    params: Option<&Value>,
    conn: &ConnectionContext,
) -> Result<Value, ErrorShape> {
    let session = resolve_session_from_params(state, params)?;
    let scope = read_string_param(params, "scope");
    let defaults = state.update_session_defaults(
        &conn.conn_id,
        session.session_key.clone(),
        session.metadata.agent_id.clone(),
        scope,
    );

    Ok(json!({
        "ok": true,
        "key": session.session_key,
        "entry": session_entry(&session),
        "defaults": defaults
    }))
}

pub(super) fn handle_sessions_patch(
    state: &WsServerState,
    params: Option<&Value>,
) -> Result<Value, ErrorShape> {
    let key = extract_session_key(params)
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "key is required", None))?;
    let updates = build_session_metadata(params, state.channel_registry());
    let has_updates = has_metadata_updates(&updates);

    let session = match state.session_store.get_session_by_key(&key) {
        Ok(existing) => {
            if has_updates {
                state
                    .session_store
                    .patch_session(&existing.id, updates)
                    .map_err(|err| {
                        error_shape(
                            ERROR_UNAVAILABLE,
                            &format!("session patch failed: {}", err),
                            None,
                        )
                    })?
            } else {
                existing
            }
        }
        Err(sessions::SessionStoreError::NotFound(_)) => {
            let metadata = if has_updates {
                updates
            } else {
                sessions::SessionMetadata::default()
            };
            state
                .session_store
                .get_or_create_session(&key, metadata)
                .map_err(|err| {
                    error_shape(
                        ERROR_UNAVAILABLE,
                        &format!("session create failed: {}", err),
                        None,
                    )
                })?
        }
        Err(err) => {
            return Err(error_shape(
                ERROR_UNAVAILABLE,
                &format!("session load failed: {}", err),
                None,
            ))
        }
    };

    Ok(json!({
        "ok": true,
        "path": state.session_store.base_path().display().to_string(),
        "key": session.session_key,
        "entry": session_entry(&session)
    }))
}

pub(super) fn handle_sessions_reset(
    state: &WsServerState,
    params: Option<&Value>,
) -> Result<Value, ErrorShape> {
    let key = extract_session_key(params)
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "key is required", None))?;
    let session = state
        .session_store
        .get_or_create_session(&key, sessions::SessionMetadata::default())
        .map_err(|err| {
            error_shape(
                ERROR_UNAVAILABLE,
                &format!("session create failed: {}", err),
                None,
            )
        })?;
    let reset = state
        .session_store
        .reset_session(&session.id)
        .map_err(|err| {
            error_shape(
                ERROR_UNAVAILABLE,
                &format!("session reset failed: {}", err),
                None,
            )
        })?;
    Ok(json!({ "ok": true, "key": reset.session_key, "entry": session_entry(&reset) }))
}

pub(super) fn handle_sessions_delete(
    state: &WsServerState,
    params: Option<&Value>,
) -> Result<Value, ErrorShape> {
    let key = extract_session_key(params)
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "key is required", None))?;
    let session = match state.session_store.get_session_by_key(&key) {
        Ok(session) => Some(session),
        Err(sessions::SessionStoreError::NotFound(_)) => None,
        Err(err) => {
            return Err(error_shape(
                ERROR_UNAVAILABLE,
                &format!("session load failed: {}", err),
                None,
            ))
        }
    };

    let deleted = if let Some(session) = session {
        state
            .session_store
            .delete_session(&session.id)
            .map_err(|err| {
                error_shape(
                    ERROR_UNAVAILABLE,
                    &format!("session delete failed: {}", err),
                    None,
                )
            })?;
        true
    } else {
        false
    };

    Ok(json!({ "ok": true, "key": key, "deleted": deleted }))
}

/// Handle sessions.export_user — GDPR data portability (Art. 20)
pub(super) fn handle_sessions_export_user(
    state: &WsServerState,
    params: Option<&Value>,
) -> Result<Value, ErrorShape> {
    let user_id = params
        .and_then(|p| p.get("userId"))
        .and_then(|v| v.as_str())
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "userId is required", None))?;

    let data = state
        .session_store
        .export_user_data(user_id)
        .map_err(|err| {
            error_shape(
                ERROR_UNAVAILABLE,
                &format!("user data export failed: {}", err),
                None,
            )
        })?;

    let warnings = data.get("warnings").cloned().unwrap_or(json!([]));
    Ok(json!({ "ok": true, "data": data, "warnings": warnings }))
}

/// Handle sessions.purge_user — GDPR right to erasure (Art. 17)
pub(super) fn handle_sessions_purge_user(
    state: &WsServerState,
    params: Option<&Value>,
) -> Result<Value, ErrorShape> {
    let user_id = params
        .and_then(|p| p.get("userId"))
        .and_then(|v| v.as_str())
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "userId is required", None))?;

    let (deleted, total) = state
        .session_store
        .purge_user_data(user_id)
        .map_err(|err| {
            error_shape(
                ERROR_UNAVAILABLE,
                &format!("user data purge failed: {}", err),
                None,
            )
        })?;

    Ok(json!({
        "ok": true,
        "userId": user_id,
        "sessionsDeleted": deleted,
        "sessionsTotal": total,
    }))
}

pub(super) fn handle_sessions_compact(
    state: &WsServerState,
    params: Option<&Value>,
) -> Result<Value, ErrorShape> {
    let key = extract_session_key(params)
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "key is required", None))?;
    let keep_recent = params
        .and_then(|v| v.get("maxLines"))
        .and_then(|v| v.as_i64())
        .map(|v| v.max(1) as usize)
        .unwrap_or(400);

    let session = match state.session_store.get_session_by_key(&key) {
        Ok(session) => session,
        Err(sessions::SessionStoreError::NotFound(_)) => {
            return Ok(json!({
                "ok": true,
                "key": key,
                "compacted": false,
                "reason": "not_found"
            }))
        }
        Err(err) => {
            return Err(error_shape(
                ERROR_UNAVAILABLE,
                &format!("session load failed: {}", err),
                None,
            ))
        }
    };

    // Archived sessions are read-only — reject compaction
    if session.status == sessions::SessionStatus::Archived {
        return Err(error_shape(
            ERROR_INVALID_REQUEST,
            "cannot compact an archived session",
            Some(json!({ "key": key, "status": "archived" })),
        ));
    }

    let history_len = state
        .session_store
        .get_history(&session.id, None, None)
        .map_err(|err| {
            error_shape(
                ERROR_UNAVAILABLE,
                &format!("session history failed: {}", err),
                None,
            )
        })?
        .len();

    if history_len <= keep_recent {
        return Ok(json!({
            "ok": true,
            "key": key,
            "compacted": false,
            "kept": history_len
        }));
    }

    let compacted = state
        .session_store
        .compact_session(
            &session.id,
            keep_recent,
            |messages: &[sessions::ChatMessage]| format!("Compacted {} messages.", messages.len()),
        )
        .map_err(|err| {
            error_shape(
                ERROR_UNAVAILABLE,
                &format!("session compact failed: {}", err),
                None,
            )
        })?;

    // Return the compaction result
    Ok(json!({
        "ok": true,
        "key": session.session_key,
        "compacted": compacted.messages_compacted > 0,
        "kept": keep_recent,
        "messagesCompacted": compacted.messages_compacted
    }))
}

/// Handle `sessions.archive` - archive a session to persistent storage
///
/// Archives the session metadata and all messages to a single archive file.
/// The session status is set to Archived, making it read-only.
///
/// ## Parameters
/// - `key` or `sessionKey` (required): Session key to archive
/// - `deleteHistory` (optional): Whether to delete the history file after archiving (default: false)
///
/// ## Response
/// ```json
/// {
///   "ok": true,
///   "key": "...",
///   "archived": true,
///   "archivePath": "/path/to/archive.json",
///   "messageCount": 42,
///   "archiveSize": 12345,
///   "archivedAt": 1234567890
/// }
/// ```
pub(super) fn handle_sessions_archive(
    state: &WsServerState,
    params: Option<&Value>,
) -> Result<Value, ErrorShape> {
    let key = extract_session_key(params)
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "key is required", None))?;
    let delete_history = params
        .and_then(|v| v.get("deleteHistory"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let session = match state.session_store.get_session_by_key(&key) {
        Ok(session) => session,
        Err(sessions::SessionStoreError::NotFound(_)) => {
            return Ok(json!({
                "ok": true,
                "key": key,
                "archived": false,
                "reason": "not_found"
            }))
        }
        Err(err) => {
            return Err(error_shape(
                ERROR_UNAVAILABLE,
                &format!("session load failed: {}", err),
                None,
            ))
        }
    };

    // Check if already archived
    if session.status == sessions::SessionStatus::Archived {
        return Ok(json!({
            "ok": true,
            "key": key,
            "archived": false,
            "reason": "already_archived"
        }));
    }

    let result = state
        .session_store
        .archive_session(&session.id, delete_history)
        .map_err(|err| {
            error_shape(
                ERROR_UNAVAILABLE,
                &format!("session archive failed: {}", err),
                None,
            )
        })?;

    Ok(json!({
        "ok": true,
        "key": key,
        "archived": true,
        "archivePath": result.archive_path,
        "messageCount": result.message_count,
        "archiveSize": result.archive_size,
        "archivedAt": result.archived_at,
        "historyDeleted": result.history_deleted
    }))
}

/// Handle `sessions.restore` - restore an archived session
///
/// Restores session history from the archive file and sets status back to Active.
///
/// ## Parameters
/// - `key` or `sessionKey` (required): Session key to restore
///
/// ## Response
/// ```json
/// {
///   "ok": true,
///   "key": "...",
///   "restored": true,
///   "messageCount": 42,
///   "restoredAt": 1234567890
/// }
/// ```
pub(super) fn handle_sessions_restore(
    state: &WsServerState,
    params: Option<&Value>,
) -> Result<Value, ErrorShape> {
    let key = extract_session_key(params)
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "key is required", None))?;

    let session = match state.session_store.get_session_by_key(&key) {
        Ok(session) => session,
        Err(sessions::SessionStoreError::NotFound(_)) => {
            return Ok(json!({
                "ok": true,
                "key": key,
                "restored": false,
                "reason": "not_found"
            }))
        }
        Err(err) => {
            return Err(error_shape(
                ERROR_UNAVAILABLE,
                &format!("session load failed: {}", err),
                None,
            ))
        }
    };

    // Check if not archived
    if session.status != sessions::SessionStatus::Archived {
        return Ok(json!({
            "ok": true,
            "key": key,
            "restored": false,
            "reason": "not_archived"
        }));
    }

    let result = state
        .session_store
        .restore_session(&session.id)
        .map_err(|err| {
            error_shape(
                ERROR_UNAVAILABLE,
                &format!("session restore failed: {}", err),
                None,
            )
        })?;

    Ok(json!({
        "ok": true,
        "key": key,
        "restored": true,
        "messageCount": result.message_count,
        "restoredAt": result.restored_at
    }))
}

/// Handle `sessions.archives` - list all archived sessions
///
/// Returns a list of all sessions with Archived status.
///
/// ## Parameters
/// - `limit` (optional): Maximum number of sessions to return (default: 100)
/// - `offset` (optional): Number of sessions to skip (default: 0)
///
/// ## Response
/// ```json
/// {
///   "ts": 1234567890,
///   "count": 5,
///   "archives": [
///     {
///       "key": "...",
///       "sessionId": "...",
///       "archiveSize": 12345,
///       "updatedAt": 1234567890
///     }
///   ]
/// }
/// ```
pub(super) fn handle_sessions_archives(
    state: &WsServerState,
    params: Option<&Value>,
) -> Result<Value, ErrorShape> {
    let limit = params
        .and_then(|v| v.get("limit"))
        .and_then(|v| v.as_i64())
        .map(|v| (v.max(1) as usize).min(1000)) // Cap at 1000 to prevent DoS
        .unwrap_or(100);
    let offset = params
        .and_then(|v| v.get("offset"))
        .and_then(|v| v.as_i64())
        .map(|v| v.max(0) as usize)
        .unwrap_or(0);

    let archived_sessions = state
        .session_store
        .list_archived_sessions()
        .map_err(|err| {
            error_shape(
                ERROR_UNAVAILABLE,
                &format!("failed to list archives: {}", err),
                None,
            )
        })?;

    let total = archived_sessions.len();

    let archives: Vec<_> = archived_sessions
        .into_iter()
        .skip(offset)
        .take(limit)
        .map(|(session, archive_size)| {
            json!({
                "key": session.session_key,
                "sessionId": session.id,
                "label": session.metadata.name,
                "messageCount": session.message_count,
                "archiveSize": archive_size,
                "updatedAt": session.updated_at,
                "createdAt": session.created_at
            })
        })
        .collect();

    Ok(json!({
        "ts": now_ms(),
        "total": total,
        "count": archives.len(),
        "archives": archives
    }))
}

/// Handle `sessions.archive.delete` - delete an archive file
///
/// Deletes the archive file without affecting the session metadata.
/// The session remains in Archived status.
///
/// ## Parameters
/// - `key` or `sessionKey` (required): Session key whose archive to delete
///
/// ## Response
/// ```json
/// {
///   "ok": true,
///   "key": "...",
///   "deleted": true
/// }
/// ```
pub(super) fn handle_sessions_archive_delete(
    state: &WsServerState,
    params: Option<&Value>,
) -> Result<Value, ErrorShape> {
    let key = extract_session_key(params)
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "key is required", None))?;

    let session = match state.session_store.get_session_by_key(&key) {
        Ok(session) => session,
        Err(sessions::SessionStoreError::NotFound(_)) => {
            return Ok(json!({
                "ok": true,
                "key": key,
                "deleted": false,
                "reason": "not_found"
            }))
        }
        Err(err) => {
            return Err(error_shape(
                ERROR_UNAVAILABLE,
                &format!("session load failed: {}", err),
                None,
            ))
        }
    };

    let deleted = state
        .session_store
        .delete_archive(&session.id)
        .map_err(|err| {
            error_shape(
                ERROR_UNAVAILABLE,
                &format!("archive delete failed: {}", err),
                None,
            )
        })?;

    Ok(json!({
        "ok": true,
        "key": key,
        "deleted": deleted
    }))
}

/// Handle the `agent` method - start an agent run with streaming support
///
/// This method:
/// 1. Creates or retrieves the session
/// 2. Appends the user message to session history
/// 3. Registers a new agent run in the registry
/// 4. Returns immediately with the run ID
///
/// The actual agent execution happens asynchronously, and streaming events
/// are emitted via the WebSocket connection.
///
/// ## Parameters
/// - `message` (required): The user message to send to the agent
/// - `idempotencyKey` (required): Unique key for this request (becomes run ID)
/// - `sessionKey` (optional): Session key (derived via scoping when omitted)
/// - `stream` (optional): Whether to stream responses (defaults to true)
/// - Additional session metadata fields (label, model, thinkingLevel, etc.)
///
/// ## Response
/// ```json
/// {
///   "runId": "...",
///   "status": "started",
///   "message": "...",
///   "sessionKey": "...",
///   "streaming": true
/// }
/// ```
/// Parsed agent request parameters.
struct AgentRequestParams<'a> {
    message: &'a str,
    idempotency_key: &'a str,
    session_hint: Option<String>,
    stream: bool,
}

/// Extract and validate agent request parameters (message, idempotencyKey, sessionKey, stream).
fn parse_agent_request_params<'a>(
    params: Option<&'a Value>,
    fallback_session_hint: Option<&'a str>,
) -> Result<AgentRequestParams<'a>, ErrorShape> {
    let message = params
        .and_then(|v| v.get("message"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "message is required", None))?;
    if message.trim().is_empty() {
        return Err(error_shape(
            ERROR_INVALID_REQUEST,
            "message is required",
            None,
        ));
    }
    let idempotency_key = params
        .and_then(|v| v.get("idempotencyKey"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "idempotencyKey is required", None))?;
    let session_hint = params
        .and_then(|v| v.get("sessionKey"))
        .and_then(|v| v.as_str())
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .or_else(|| fallback_session_hint.map(|s| s.to_string()));
    let stream = params
        .and_then(|v| v.get("stream"))
        .and_then(|v| v.as_bool())
        .unwrap_or(true);

    Ok(AgentRequestParams {
        message,
        idempotency_key,
        session_hint,
        stream,
    })
}

/// Register the agent run and append the user message.
/// Returns (run_id, session_key, cancel_token).
fn setup_agent_session(
    state: &Arc<WsServerState>,
    session: sessions::Session,
    message: &str,
    idempotency_key: &str,
) -> Result<(String, String, CancellationToken), ErrorShape> {
    state
        .session_store
        .append_message(sessions::ChatMessage::user(session.id.clone(), message))
        .map_err(|err| {
            error_shape(
                ERROR_UNAVAILABLE,
                &format!("session write failed: {}", err),
                None,
            )
        })?;

    // Create the agent run
    let cancel_token = CancellationToken::new();
    let run = AgentRun {
        run_id: idempotency_key.to_string(),
        session_key: session.session_key.clone(),
        status: AgentRunStatus::Queued,
        message: message.to_string(),
        response: String::new(),
        error: None,
        created_at: now_ms(),
        started_at: None,
        completed_at: None,
        cancel_token: cancel_token.clone(),
        waiters: Vec::new(),
    };

    let run_id = run.run_id.clone();
    let session_key_out = run.session_key.clone();

    // Register the run in the agent_run_registry
    {
        let mut registry = state.agent_run_registry.lock();
        registry.register(run);
    }

    Ok((run_id, session_key_out, cancel_token))
}

pub(super) fn handle_agent(
    params: Option<&Value>,
    state: Arc<WsServerState>,
    conn: &ConnectionContext,
) -> Result<Value, ErrorShape> {
    let default_session_key = state.default_session_key(&conn.conn_id);
    let agent_params = parse_agent_request_params(params, default_session_key.as_deref())?;
    let cfg = config::load_config().unwrap_or(Value::Object(serde_json::Map::new()));

    // Check for duplicate idempotencyKey — return existing run status
    {
        let registry = state.agent_run_registry.lock();
        if let Some(existing) = registry.get(agent_params.idempotency_key) {
            if matches!(
                existing.status,
                AgentRunStatus::Queued | AgentRunStatus::Running
            ) {
                return Ok(json!({
                    "runId": existing.run_id,
                    "status": existing.status.to_string(),
                    "sessionKey": existing.session_key,
                    "duplicate": true,
                    "streaming": agent_params.stream
                }));
            }
        }
    }

    let mut metadata = build_session_metadata(params, state.channel_registry());
    let channel = metadata
        .channel
        .clone()
        .unwrap_or_else(|| "default".to_string());
    let sender_id = metadata
        .user_id
        .clone()
        .unwrap_or_else(|| conn.client.id.to_string());
    if metadata.user_id.is_none() {
        metadata.user_id = Some(sender_id.clone());
    }
    let peer_id = params
        .and_then(|v| v.get("chatId").or_else(|| v.get("to")))
        .and_then(|v| v.as_str())
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .unwrap_or(sender_id.as_str())
        .to_string();
    let explicit_session_hint =
        sessions::canonicalize_optional_session_hint(agent_params.session_hint.as_deref());
    let session = sessions::get_or_create_scoped_session(
        state.session_store(),
        &cfg,
        channel.as_str(),
        sender_id.as_str(),
        peer_id.as_str(),
        explicit_session_hint.as_deref(),
        metadata,
    )
    .map_err(|err| {
        error_shape(
            ERROR_UNAVAILABLE,
            &format!("session create failed: {}", err),
            None,
        )
    })?;
    let (run_id, session_key_out, cancel_token) = setup_agent_session(
        &state,
        session,
        agent_params.message,
        agent_params.idempotency_key,
    )?;

    // Spawn the agent executor if an LLM provider is configured
    let status = if let Some(provider) = state.llm_provider() {
        let model = params
            .and_then(|v| v.get("model"))
            .and_then(|v| v.as_str())
            .unwrap_or(crate::agent::DEFAULT_MODEL);
        let mut config = crate::agent::AgentConfig::default();
        let agent_id = params
            .and_then(|v| v.get("agentId"))
            .and_then(|v| v.as_str());
        crate::agent::apply_agent_config_from_settings(&mut config, &cfg, agent_id);
        config.model = model.to_string();
        config.system = params
            .and_then(|v| v.get("system"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        config.deliver = params
            .and_then(|v| v.get("deliver"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        config.extra = params
            .and_then(|v| v.get("venice_parameters"))
            .filter(|v| v.is_object())
            .cloned();
        crate::agent::spawn_run(
            run_id.clone(),
            session_key_out.clone(),
            config,
            state.clone(),
            provider,
            cancel_token,
        );
        "accepted"
    } else {
        // No provider configured — run stays queued
        "queued"
    };

    Ok(json!({
        "runId": run_id,
        "status": status,
        "message": agent_params.message,
        "sessionKey": session_key_out,
        "streaming": agent_params.stream
    }))
}

pub(super) fn handle_agent_identity_get(params: Option<&Value>) -> Result<Value, ErrorShape> {
    let cfg = config::load_config().unwrap_or(Value::Object(serde_json::Map::new()));
    let agent_id = params
        .and_then(|v| v.get("agentId"))
        .and_then(|v| v.as_str())
        .map(|s| s.trim())
        .filter(|s| !s.is_empty());

    let agents_list = cfg
        .get("agents")
        .and_then(|v| v.get("list"))
        .and_then(|v| v.as_array());

    // If an explicit agentId was requested, it must be found or we error
    if let Some(requested_id) = agent_id {
        let found = agents_list.and_then(|list| {
            list.iter()
                .find(|entry| entry.get("id").and_then(|v| v.as_str()) == Some(requested_id))
        });
        return match found {
            Some(entry) => {
                let identity = entry.get("identity");
                let name = identity
                    .and_then(|v| v.get("name"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("Carapace");
                let description = identity
                    .and_then(|v| v.get("description"))
                    .and_then(|v| v.as_str());
                Ok(json!({
                    "agentId": requested_id,
                    "name": name,
                    "description": description,
                }))
            }
            None => Err(error_shape(
                ERROR_INVALID_REQUEST,
                &format!("agent not found: {}", requested_id),
                Some(json!({ "agentId": requested_id })),
            )),
        };
    }

    // No agentId: find default agent, fall back to first
    let agent = agents_list.and_then(|list| {
        let default = list.iter().find(|entry| {
            entry
                .get("default")
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
        });
        default.or_else(|| list.first())
    });

    match agent {
        Some(entry) => {
            let id = entry
                .get("id")
                .and_then(|v| v.as_str())
                .unwrap_or("default");
            let identity = entry.get("identity");
            let name = identity
                .and_then(|v| v.get("name"))
                .and_then(|v| v.as_str())
                .unwrap_or("Carapace");
            let description = identity
                .and_then(|v| v.get("description"))
                .and_then(|v| v.as_str());
            Ok(json!({
                "agentId": id,
                "name": name,
                "description": description,
            }))
        }
        None => {
            // No agents configured — return hardcoded default
            Ok(json!({
                "agentId": "default",
                "name": "Carapace",
                "description": null,
            }))
        }
    }
}

/// Handle the `agent.wait` method - wait for an agent run to complete
///
/// Blocks until the run completes or times out, per Node semantics.
///
/// ## Parameters
/// - `runId` (required): The run ID to wait for
/// - `timeoutMs` (optional): Maximum time to wait in milliseconds (default: 120000 = 2 min)
///
/// ## Response (Node-compatible)
/// ```json
/// {
///   "runId": "...",
///   "status": "ok" | "error" | "timeout",
///   "startedAt": 1234567890 | null,
///   "endedAt": 1234567890 | null
/// }
/// ```
pub(super) async fn handle_agent_wait(
    params: Option<&Value>,
    state: &WsServerState,
) -> Result<Value, ErrorShape> {
    let run_id = params
        .and_then(|v| v.get("runId"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "runId is required", None))?;
    // Node uses timeoutMs (not timeout)
    let timeout_ms = params
        .and_then(|v| v.get("timeoutMs"))
        .and_then(|v| v.as_u64())
        .unwrap_or(120_000)
        .min(600_000); // Max 10 minutes

    // Helper to convert internal status to Node status
    fn to_node_status(status: AgentRunStatus) -> &'static str {
        match status {
            AgentRunStatus::Completed => "ok",
            AgentRunStatus::Failed | AgentRunStatus::Cancelled => "error",
            AgentRunStatus::Queued | AgentRunStatus::Running => "timeout",
        }
    }

    // Try to add a waiter for this run
    let waiter = {
        let mut registry = state.agent_run_registry.lock();
        registry.add_waiter(run_id)
    };

    if let Some(rx) = waiter {
        // Wait for completion or timeout
        match tokio::time::timeout(std::time::Duration::from_millis(timeout_ms), rx).await {
            Ok(Ok(result)) => {
                // Run completed (or was already completed)
                Ok(json!({
                    "runId": result.run_id,
                    "status": to_node_status(result.status),
                    "startedAt": result.started_at,
                    "endedAt": result.completed_at
                }))
            }
            Ok(Err(_)) => {
                // Channel closed unexpectedly - check registry for final state
                let registry = state.agent_run_registry.lock();
                if let Some(run) = registry.get(run_id) {
                    Ok(json!({
                        "runId": run.run_id,
                        "status": to_node_status(run.status),
                        "startedAt": run.started_at,
                        "endedAt": run.completed_at
                    }))
                } else {
                    Ok(json!({
                        "runId": run_id,
                        "status": "timeout",
                        "startedAt": null,
                        "endedAt": null
                    }))
                }
            }
            Err(_) => {
                // Timeout - return timeout status
                let registry = state.agent_run_registry.lock();
                let (started_at, ended_at) = if let Some(run) = registry.get(run_id) {
                    (run.started_at, run.completed_at)
                } else {
                    (None, None)
                };
                Ok(json!({
                    "runId": run_id,
                    "status": "timeout",
                    "startedAt": started_at,
                    "endedAt": ended_at
                }))
            }
        }
    } else {
        // Run not found - return timeout status per Node semantics
        Ok(json!({
            "runId": run_id,
            "status": "timeout",
            "startedAt": null,
            "endedAt": null
        }))
    }
}

pub(super) fn handle_chat_history(
    state: &WsServerState,
    params: Option<&Value>,
) -> Result<Value, ErrorShape> {
    let session_id = params
        .and_then(|v| v.get("sessionId"))
        .and_then(|v| v.as_str())
        .map(|s| s.trim())
        .filter(|s| !s.is_empty());
    let session_key = extract_session_key(params);
    let limit = params
        .and_then(|v| v.get("limit"))
        .and_then(|v| v.as_i64())
        .map(|v| v.max(1) as usize)
        .unwrap_or(200)
        .min(1000);

    let session = if let Some(session_id) = session_id {
        state
            .session_store
            .get_session(session_id)
            .map_err(|err| error_shape(ERROR_INVALID_REQUEST, &err.to_string(), None))?
    } else {
        let key = session_key
            .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "sessionKey is required", None))?;
        state
            .session_store
            .get_session_by_key(&key)
            .map_err(|err| error_shape(ERROR_INVALID_REQUEST, &err.to_string(), None))?
    };

    let messages = state
        .session_store
        .get_history(&session.id, Some(limit), None)
        .map_err(|err| error_shape(ERROR_UNAVAILABLE, &err.to_string(), None))?
        .into_iter()
        .map(|m| {
            json!({
                "id": m.id,
                "role": role_to_string(m.role),
                "content": m.content,
                "ts": m.created_at
            })
        })
        .collect::<Vec<_>>();

    Ok(json!({
        "sessionKey": session.session_key,
        "sessionId": session.id,
        "messages": messages,
        "thinkingLevel": session
            .metadata
            .thinking_level
            .clone()
            .unwrap_or_else(|| "off".to_string())
    }))
}

/// Handle the `chat.send` method - send a chat message and queue an agent response
///
/// This is similar to `agent` but designed for chat UI flows where:
/// - The message is always appended to history
/// - A response is queued (but may not stream)
/// - The caller typically polls for completion or uses WebSocket events
///
/// ## Parameters
/// - `message` (required): The user message to send
/// - `idempotencyKey` (required): Unique key for this request (becomes run ID)
/// - `sessionId` or `sessionKey` (one required): Identifies the session
/// - `stream` (optional): Whether to stream responses (defaults to true)
/// - `triggerAgent` (optional): Whether to trigger an agent run (defaults to true)
///
/// ## Response
/// ```json
/// {
///   "runId": "..." | null,
///   "messageId": "...",
///   "status": "queued" | "sent",
///   "sessionKey": "...",
///   "agentTriggered": true | false
/// }
/// ```
/// Parsed chat send parameters.
struct ChatSendParams<'a> {
    session_id: Option<&'a str>,
    session_key: Option<String>,
    message: &'a str,
    idempotency_key: &'a str,
    stream: bool,
    trigger_agent: bool,
}

/// Extract and validate chat send parameters (session key, message, idempotencyKey, etc.).
fn parse_chat_send_params<'a>(params: Option<&'a Value>) -> Result<ChatSendParams<'a>, ErrorShape> {
    let session_id = params
        .and_then(|v| v.get("sessionId"))
        .and_then(|v| v.as_str())
        .map(|s| s.trim())
        .filter(|s| !s.is_empty());
    let session_key = extract_session_key(params);
    let message = params
        .and_then(|v| v.get("message"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "message is required", None))?;
    if message.trim().is_empty() {
        return Err(error_shape(
            ERROR_INVALID_REQUEST,
            "message is required",
            None,
        ));
    }
    let idempotency_key = params
        .and_then(|v| v.get("idempotencyKey"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "idempotencyKey is required", None))?;
    let stream = params
        .and_then(|v| v.get("stream"))
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    let trigger_agent = params
        .and_then(|v| v.get("triggerAgent"))
        .and_then(|v| v.as_bool())
        .unwrap_or(true);

    Ok(ChatSendParams {
        session_id,
        session_key,
        message,
        idempotency_key,
        stream,
        trigger_agent,
    })
}

/// Check if agent auto-reply is enabled and spawn agent run if so.
/// Returns (run_id, status_str).
fn trigger_agent_if_enabled(
    state: &Arc<WsServerState>,
    trigger_agent: bool,
    idempotency_key: &str,
    message: &str,
    session_key: &str,
    extra: Option<serde_json::Value>,
) -> (Option<String>, &'static str) {
    if !trigger_agent {
        return (None, "sent");
    }

    // Create the agent run
    let cancel_token = CancellationToken::new();
    let run = AgentRun {
        run_id: idempotency_key.to_string(),
        session_key: session_key.to_string(),
        status: AgentRunStatus::Queued,
        message: message.to_string(),
        response: String::new(),
        error: None,
        created_at: now_ms(),
        started_at: None,
        completed_at: None,
        cancel_token: cancel_token.clone(),
        waiters: Vec::new(),
    };

    let run_id = run.run_id.clone();

    // Register the run in the agent_run_registry
    {
        let mut registry = state.agent_run_registry.lock();
        registry.register(run);
    }

    // Spawn the agent executor if an LLM provider is configured
    let status = if let Some(provider) = state.llm_provider() {
        let cfg = config::load_config().unwrap_or(Value::Object(serde_json::Map::new()));
        let mut config = crate::agent::AgentConfig::default();
        crate::agent::apply_agent_config_from_settings(&mut config, &cfg, None);
        config.model = crate::agent::DEFAULT_MODEL.to_string();
        config.deliver = true;
        config.extra = extra;
        crate::agent::spawn_run(
            run_id.clone(),
            session_key.to_string(),
            config,
            state.clone(),
            provider,
            cancel_token,
        );
        "accepted"
    } else {
        // No provider configured — run stays queued
        "queued"
    };

    (Some(run_id), status)
}

pub(super) fn handle_chat_send(
    state: Arc<WsServerState>,
    params: Option<&Value>,
    conn: &ConnectionContext,
) -> Result<Value, ErrorShape> {
    let chat_params = parse_chat_send_params(params)?;
    let default_session_key = state.default_session_key(&conn.conn_id);
    let cfg = config::load_config().unwrap_or(Value::Object(serde_json::Map::new()));
    let mut metadata = build_session_metadata(params, state.channel_registry());
    let channel = metadata
        .channel
        .clone()
        .unwrap_or_else(|| "default".to_string());
    let sender_id = metadata
        .user_id
        .clone()
        .unwrap_or_else(|| conn.client.id.to_string());
    if metadata.user_id.is_none() {
        metadata.user_id = Some(sender_id.clone());
    }
    let peer_id = params
        .and_then(|v| v.get("chatId").or_else(|| v.get("to")))
        .and_then(|v| v.as_str())
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .unwrap_or(sender_id.as_str())
        .to_string();

    // Check for duplicate idempotencyKey — return existing run status
    {
        let registry = state.agent_run_registry.lock();
        if let Some(existing) = registry.get(chat_params.idempotency_key) {
            if matches!(
                existing.status,
                AgentRunStatus::Queued | AgentRunStatus::Running
            ) {
                return Ok(json!({
                    "runId": existing.run_id,
                    "status": existing.status.to_string(),
                    "sessionKey": existing.session_key,
                    "duplicate": true,
                    "streaming": chat_params.stream
                }));
            }
        }
    }

    let session = if let Some(session_id) = chat_params.session_id {
        let session = state
            .session_store
            .get_session(session_id)
            .map_err(|err| error_shape(ERROR_INVALID_REQUEST, &err.to_string(), None))?;
        let reset_channel = session
            .metadata
            .channel
            .as_deref()
            .unwrap_or(channel.as_str());
        let channel_config =
            sessions::scoping::ChannelSessionConfig::from_config(&cfg, reset_channel);
        if sessions::scoping::should_reset_session(session.updated_at, &channel_config.reset) {
            state
                .session_store
                .reset_session(&session.id)
                .map_err(|err| {
                    error_shape(
                        ERROR_UNAVAILABLE,
                        &format!("session reset failed: {}", err),
                        None,
                    )
                })?
        } else {
            session
        }
    } else {
        let explicit_key = chat_params
            .session_key
            .as_deref()
            .or(default_session_key.as_deref());
        sessions::get_or_create_scoped_session(
            state.session_store(),
            &cfg,
            channel.as_str(),
            sender_id.as_str(),
            peer_id.as_str(),
            explicit_key,
            metadata,
        )
        .map_err(|err| {
            error_shape(
                ERROR_UNAVAILABLE,
                &format!("session create failed: {}", err),
                None,
            )
        })?
    };

    // Create and append the user message
    let chat_message = sessions::ChatMessage::user(session.id.clone(), chat_params.message);
    let message_id = chat_message.id.clone();
    state
        .session_store
        .append_message(chat_message)
        .map_err(|err| {
            error_shape(
                ERROR_UNAVAILABLE,
                &format!("session write failed: {}", err),
                None,
            )
        })?;

    // Emit chat event for the user message
    broadcast_chat_event(
        &state,
        chat_params.idempotency_key,
        &session.session_key,
        0, // First event in this run
        "delta",
        Some(json!({
            "role": "user",
            "content": chat_params.message
        })),
        None,
        None,
        None,
    );

    // If agent triggering is enabled, queue the agent run
    let (run_id, status) = trigger_agent_if_enabled(
        &state,
        chat_params.trigger_agent,
        chat_params.idempotency_key,
        chat_params.message,
        &session.session_key,
        params
            .and_then(|v| v.get("venice_parameters"))
            .filter(|v| v.is_object())
            .cloned(),
    );

    Ok(json!({
        "runId": run_id,
        "messageId": message_id,
        "status": status,
        "sessionKey": session.session_key,
        "agentTriggered": chat_params.trigger_agent,
        "streaming": chat_params.stream
    }))
}

/// Handle the `chat.abort` method - cancel in-progress agent runs
///
/// This method cancels one or more agent runs. It can cancel:
/// - A specific run by `runId`
/// - All active runs for a session by `sessionId` or `sessionKey`
/// - All active runs if neither is specified (not recommended)
///
/// ## Parameters
/// - `runId` (optional): Specific run ID to cancel
/// - `sessionId` or `sessionKey` (optional): Cancel all runs for this session
/// - `reason` (optional): Cancellation reason for logging
///
/// ## Response
/// ```json
/// {
///   "ok": true,
///   "aborted": true | false,
///   "sessionKey": "..." | null,
///   "runIds": ["..."],
///   "reason": "..." | null
/// }
/// ```
pub(super) fn handle_chat_abort(
    state: &WsServerState,
    params: Option<&Value>,
) -> Result<Value, ErrorShape> {
    let session_id = params
        .and_then(|v| v.get("sessionId"))
        .and_then(|v| v.as_str())
        .map(|s| s.trim())
        .filter(|s| !s.is_empty());
    let session_key = extract_session_key(params);
    let run_id = params
        .and_then(|v| v.get("runId"))
        .and_then(|v| v.as_str())
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());
    let reason = params
        .and_then(|v| v.get("reason"))
        .and_then(|v| v.as_str())
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());

    // Resolve the session (if provided)
    let session = if let Some(session_id) = session_id {
        state.session_store.get_session(session_id).ok()
    } else if let Some(key) = session_key.as_deref() {
        state.session_store.get_session_by_key(key).ok()
    } else {
        None
    };
    let resolved_session_key = session
        .as_ref()
        .map(|s| s.session_key.clone())
        .or(session_key);

    // Collect run IDs to cancel
    let runs_to_cancel: Vec<String> = if let Some(run_id) = run_id.clone() {
        // Cancel specific run
        vec![run_id]
    } else if let Some(ref session_key) = resolved_session_key {
        // Cancel all active runs for the session
        let registry = state.agent_run_registry.lock();
        registry.get_active_runs_for_session(session_key)
    } else {
        // No specific target - return empty list
        Vec::new()
    };

    // Cancel each run and track which were actually cancelled
    let mut cancelled_runs: Vec<String> = Vec::new();
    {
        let mut registry = state.agent_run_registry.lock();
        for run_id in &runs_to_cancel {
            if registry.mark_cancelled(run_id) {
                cancelled_runs.push(run_id.clone());
            }
        }
    }

    let aborted = !cancelled_runs.is_empty();

    Ok(json!({
        "ok": true,
        "aborted": aborted,
        "sessionKey": resolved_session_key,
        "runIds": if run_id.is_some() { runs_to_cancel } else { cancelled_runs },
        "reason": reason
    }))
}

// ============== Tests ==============

#[cfg(test)]
mod tests {
    use super::*;

    // ============== AgentRunStatus Tests ==============

    #[test]
    fn test_agent_run_status_display() {
        assert_eq!(AgentRunStatus::Queued.to_string(), "queued");
        assert_eq!(AgentRunStatus::Running.to_string(), "running");
        assert_eq!(AgentRunStatus::Completed.to_string(), "completed");
        assert_eq!(AgentRunStatus::Failed.to_string(), "failed");
        assert_eq!(AgentRunStatus::Cancelled.to_string(), "cancelled");
    }

    // ============== AgentRunRegistry Tests ==============

    fn create_test_run(run_id: &str, session_key: &str) -> AgentRun {
        AgentRun {
            run_id: run_id.to_string(),
            session_key: session_key.to_string(),
            status: AgentRunStatus::Queued,
            message: "test message".to_string(),
            response: String::new(),
            error: None,
            created_at: now_ms(),
            started_at: None,
            completed_at: None,
            cancel_token: CancellationToken::new(),
            waiters: Vec::new(),
        }
    }

    #[test]
    fn test_agent_run_registry_register_and_get() {
        let mut registry = AgentRunRegistry::new();
        let run = create_test_run("run-1", "session-1");

        registry.register(run);

        let retrieved = registry.get("run-1");
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().run_id, "run-1");
        assert_eq!(retrieved.unwrap().session_key, "session-1");
    }

    #[test]
    fn test_agent_run_registry_get_runs_for_session() {
        let mut registry = AgentRunRegistry::new();
        registry.register(create_test_run("run-1", "session-1"));
        registry.register(create_test_run("run-2", "session-1"));
        registry.register(create_test_run("run-3", "session-2"));

        let session1_runs = registry.get_runs_for_session("session-1");
        assert_eq!(session1_runs.len(), 2);
        assert!(session1_runs.contains(&"run-1".to_string()));
        assert!(session1_runs.contains(&"run-2".to_string()));

        let session2_runs = registry.get_runs_for_session("session-2");
        assert_eq!(session2_runs.len(), 1);
        assert!(session2_runs.contains(&"run-3".to_string()));
    }

    #[test]
    fn test_agent_run_registry_mark_started() {
        let mut registry = AgentRunRegistry::new();
        registry.register(create_test_run("run-1", "session-1"));

        assert!(registry.mark_started("run-1"));

        let run = registry.get("run-1").unwrap();
        assert_eq!(run.status, AgentRunStatus::Running);
        assert!(run.started_at.is_some());
    }

    #[test]
    fn test_agent_run_registry_mark_completed() {
        let mut registry = AgentRunRegistry::new();
        registry.register(create_test_run("run-1", "session-1"));
        registry.mark_started("run-1");

        assert!(registry.mark_completed("run-1", "test response".to_string()));

        let run = registry.get("run-1").unwrap();
        assert_eq!(run.status, AgentRunStatus::Completed);
        assert_eq!(run.response, "test response");
        assert!(run.completed_at.is_some());
    }

    #[test]
    fn test_agent_run_registry_mark_failed() {
        let mut registry = AgentRunRegistry::new();
        registry.register(create_test_run("run-1", "session-1"));
        registry.mark_started("run-1");

        assert!(registry.mark_failed("run-1", "test error".to_string()));

        let run = registry.get("run-1").unwrap();
        assert_eq!(run.status, AgentRunStatus::Failed);
        assert_eq!(run.error, Some("test error".to_string()));
        assert!(run.completed_at.is_some());
    }

    #[test]
    fn test_agent_run_registry_mark_cancelled() {
        let mut registry = AgentRunRegistry::new();
        registry.register(create_test_run("run-1", "session-1"));
        registry.mark_started("run-1");

        assert!(registry.mark_cancelled("run-1"));

        let run = registry.get("run-1").unwrap();
        assert_eq!(run.status, AgentRunStatus::Cancelled);
        assert!(run.completed_at.is_some());
    }

    #[test]
    fn test_agent_run_registry_append_delta() {
        let mut registry = AgentRunRegistry::new();
        registry.register(create_test_run("run-1", "session-1"));
        registry.mark_started("run-1");

        assert!(registry.append_delta("run-1", "Hello"));
        assert!(registry.append_delta("run-1", " World"));

        let run = registry.get("run-1").unwrap();
        assert_eq!(run.response, "Hello World");
    }

    #[test]
    fn test_agent_run_registry_append_delta_only_when_running() {
        let mut registry = AgentRunRegistry::new();
        registry.register(create_test_run("run-1", "session-1"));

        // Should not append when queued
        assert!(!registry.append_delta("run-1", "test"));

        registry.mark_started("run-1");
        assert!(registry.append_delta("run-1", "test"));

        registry.mark_completed("run-1", "done".to_string());
        // Should not append when completed
        assert!(!registry.append_delta("run-1", "more"));
    }

    #[test]
    fn test_agent_run_registry_remove() {
        let mut registry = AgentRunRegistry::new();
        registry.register(create_test_run("run-1", "session-1"));

        let removed = registry.remove("run-1");
        assert!(removed.is_some());
        assert_eq!(removed.unwrap().run_id, "run-1");

        assert!(registry.get("run-1").is_none());
        assert!(registry.get_runs_for_session("session-1").is_empty());
    }

    #[test]
    fn test_agent_run_registry_get_active_runs() {
        let mut registry = AgentRunRegistry::new();
        registry.register(create_test_run("run-1", "session-1"));
        registry.register(create_test_run("run-2", "session-1"));
        registry.register(create_test_run("run-3", "session-1"));

        registry.mark_started("run-1");
        registry.mark_completed("run-2", "done".to_string());
        // run-3 stays queued

        let active = registry.get_active_runs_for_session("session-1");
        assert_eq!(active.len(), 2);
        assert!(active.contains(&"run-1".to_string()));
        assert!(active.contains(&"run-3".to_string()));
    }

    #[tokio::test]
    async fn test_agent_run_registry_add_waiter_immediate_completion() {
        let mut registry = AgentRunRegistry::new();
        registry.register(create_test_run("run-1", "session-1"));
        registry.mark_started("run-1");
        registry.mark_completed("run-1", "final response".to_string());

        // Adding a waiter to a completed run should return immediately
        let rx = registry.add_waiter("run-1").unwrap();
        let result = rx.await.unwrap();

        assert_eq!(result.run_id, "run-1");
        assert_eq!(result.status, AgentRunStatus::Completed);
        assert_eq!(result.response, Some("final response".to_string()));
    }

    #[tokio::test]
    async fn test_agent_run_registry_waiter_notified_on_completion() {
        let mut registry = AgentRunRegistry::new();
        registry.register(create_test_run("run-1", "session-1"));
        registry.mark_started("run-1");

        // Add waiter before completion
        let rx = registry.add_waiter("run-1").unwrap();

        // Complete the run
        registry.mark_completed("run-1", "final response".to_string());

        // Waiter should receive the result
        let result = rx.await.unwrap();
        assert_eq!(result.status, AgentRunStatus::Completed);
        assert_eq!(result.response, Some("final response".to_string()));
    }

    #[test]
    fn test_agent_run_registry_register_rejects_active_duplicate() {
        let mut registry = AgentRunRegistry::new();

        // First registration succeeds
        assert!(registry.register(create_test_run("run-1", "session-1")));
        assert!(registry.get("run-1").is_some());

        // Duplicate registration while Queued is rejected
        assert!(!registry.register(create_test_run("run-1", "session-1")));

        // Mark as Running — duplicate still rejected
        registry.mark_started("run-1");
        assert!(!registry.register(create_test_run("run-1", "session-1")));

        // Mark as Completed — re-registration now allowed (terminal state)
        registry.mark_completed("run-1", "done".to_string());
        assert!(registry.register(create_test_run("run-1", "session-1")));
    }

    // ============== Session Archive Handler Tests ==============

    use crate::sessions;

    fn make_state_with_temp_sessions() -> (WsServerState, tempfile::TempDir) {
        let tmp = tempfile::tempdir().unwrap();
        let store = std::sync::Arc::new(sessions::SessionStore::with_base_path(
            tmp.path().join("sessions"),
        ));
        let state = WsServerState::new(crate::server::ws::WsServerConfig::default())
            .with_session_store(store);
        (state, tmp)
    }

    fn make_conn(conn_id: &str) -> ConnectionContext {
        ConnectionContext {
            conn_id: conn_id.to_string(),
            role: "admin".to_string(),
            scopes: vec![],
            client: ClientInfo {
                id: "test-client".to_string(),
                version: "1.0.0".to_string(),
                platform: "test".to_string(),
                mode: "test".to_string(),
                display_name: None,
                device_family: None,
                model_identifier: None,
                instance_id: None,
            },
            device_id: None,
        }
    }

    #[test]
    fn test_handle_sessions_create_with_key() {
        let (state, _tmp) = make_state_with_temp_sessions();
        let params = json!({ "key": "session-1", "label": "My Session" });
        let result = handle_sessions_create(&state, Some(&params)).unwrap();
        assert_eq!(result["ok"], true);
        assert_eq!(result["key"], "session-1");
        let session = state.session_store.get_session_by_key("session-1").unwrap();
        assert_eq!(session.metadata.name.as_deref(), Some("My Session"));
    }

    #[test]
    fn test_handle_sessions_load_includes_messages() {
        let (state, _tmp) = make_state_with_temp_sessions();
        let session = state
            .session_store
            .create_session("agent-1", sessions::SessionMetadata::default())
            .unwrap();
        state
            .session_store
            .append_message(sessions::ChatMessage::user(session.id.clone(), "hello"))
            .unwrap();
        let params = json!({ "key": session.session_key });
        let result = handle_sessions_load(&state, Some(&params)).unwrap();
        assert_eq!(result["ok"], true);
        assert_eq!(result["messages"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn test_handle_sessions_fork_copies_history() {
        let (state, _tmp) = make_state_with_temp_sessions();
        let session = state
            .session_store
            .create_session("agent-1", sessions::SessionMetadata::default())
            .unwrap();
        state
            .session_store
            .append_message(sessions::ChatMessage::user(session.id.clone(), "hello"))
            .unwrap();
        let params = json!({ "key": session.session_key, "newKey": "session-fork" });
        let result = handle_sessions_fork(&state, Some(&params)).unwrap();
        assert_eq!(result["ok"], true);
        let forked = state
            .session_store
            .get_session_by_key("session-fork")
            .unwrap();
        assert_eq!(forked.message_count, 1);
        let history = state
            .session_store
            .get_history(&forked.id, Some(10), None)
            .unwrap();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].content, "hello");
    }

    #[test]
    fn test_handle_sessions_rename_updates_label() {
        let (state, _tmp) = make_state_with_temp_sessions();
        let session = state
            .session_store
            .create_session("agent-1", sessions::SessionMetadata::default())
            .unwrap();
        let params = json!({ "key": session.session_key, "name": "Renamed" });
        let result = handle_sessions_rename(&state, Some(&params)).unwrap();
        assert_eq!(result["ok"], true);
        let updated = state
            .session_store
            .get_session_by_key(&session.session_key)
            .unwrap();
        assert_eq!(updated.metadata.name.as_deref(), Some("Renamed"));
    }

    #[test]
    fn test_handle_sessions_switch_sets_default() {
        let (state, _tmp) = make_state_with_temp_sessions();
        let session = state
            .session_store
            .create_session("agent-1", sessions::SessionMetadata::default())
            .unwrap();
        let conn = make_conn("conn-1");
        let params = json!({ "key": session.session_key });
        let result = handle_sessions_switch(&state, Some(&params), &conn).unwrap();
        assert_eq!(result["ok"], true);
        assert_eq!(
            state.default_session_key(&conn.conn_id).as_deref(),
            Some(session.session_key.as_str())
        );
    }

    #[test]
    fn test_handle_sessions_archive_requires_key() {
        let (state, _tmp) = make_state_with_temp_sessions();
        let result = handle_sessions_archive(&state, None);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code, "INVALID_REQUEST");
    }

    #[test]
    fn test_handle_sessions_archive_not_found() {
        let (state, _tmp) = make_state_with_temp_sessions();
        let params = json!({ "key": "nonexistent-key" });
        let result = handle_sessions_archive(&state, Some(&params)).unwrap();
        assert_eq!(result["ok"], true);
        assert_eq!(result["archived"], false);
        assert_eq!(result["reason"], "not_found");
    }

    #[test]
    fn test_handle_sessions_archive_success() {
        let (state, _tmp) = make_state_with_temp_sessions();

        let session = state
            .session_store
            .create_session("agent-1", sessions::SessionMetadata::default())
            .unwrap();
        state
            .session_store
            .append_message(sessions::ChatMessage::user(&session.id, "Hello"))
            .unwrap();

        let params = json!({ "key": session.session_key });
        let result = handle_sessions_archive(&state, Some(&params)).unwrap();
        assert_eq!(result["ok"], true);
        assert_eq!(result["archived"], true);
        assert_eq!(result["messageCount"], 1);
        assert!(result["archiveSize"].as_u64().unwrap() > 0);
        assert!(result["archivedAt"].as_i64().is_some());
    }

    #[test]
    fn test_handle_sessions_archive_already_archived() {
        let (state, _tmp) = make_state_with_temp_sessions();

        let session = state
            .session_store
            .create_session("agent-1", sessions::SessionMetadata::default())
            .unwrap();
        state
            .session_store
            .append_message(sessions::ChatMessage::user(&session.id, "Hello"))
            .unwrap();
        state
            .session_store
            .archive_session(&session.id, false)
            .unwrap();

        let params = json!({ "key": session.session_key });
        let result = handle_sessions_archive(&state, Some(&params)).unwrap();
        assert_eq!(result["ok"], true);
        assert_eq!(result["archived"], false);
        assert_eq!(result["reason"], "already_archived");
    }

    #[test]
    fn test_handle_sessions_restore_requires_key() {
        let (state, _tmp) = make_state_with_temp_sessions();
        let result = handle_sessions_restore(&state, None);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code, "INVALID_REQUEST");
    }

    #[test]
    fn test_handle_sessions_restore_not_found() {
        let (state, _tmp) = make_state_with_temp_sessions();
        let params = json!({ "key": "nonexistent-key" });
        let result = handle_sessions_restore(&state, Some(&params)).unwrap();
        assert_eq!(result["ok"], true);
        assert_eq!(result["restored"], false);
        assert_eq!(result["reason"], "not_found");
    }

    #[test]
    fn test_handle_sessions_restore_success() {
        let (state, _tmp) = make_state_with_temp_sessions();

        let session = state
            .session_store
            .create_session("agent-1", sessions::SessionMetadata::default())
            .unwrap();
        state
            .session_store
            .append_message(sessions::ChatMessage::user(&session.id, "Hello"))
            .unwrap();
        state
            .session_store
            .archive_session(&session.id, true)
            .unwrap();

        let params = json!({ "key": session.session_key });
        let result = handle_sessions_restore(&state, Some(&params)).unwrap();
        assert_eq!(result["ok"], true);
        assert_eq!(result["restored"], true);
        assert_eq!(result["messageCount"], 1);
    }

    #[test]
    fn test_handle_sessions_archives_list() {
        let (state, _tmp) = make_state_with_temp_sessions();

        for i in 0..2 {
            let session = state
                .session_store
                .create_session(
                    format!("agent-{}", i),
                    sessions::SessionMetadata {
                        name: Some(format!("Session {}", i)),
                        ..Default::default()
                    },
                )
                .unwrap();
            state
                .session_store
                .append_message(sessions::ChatMessage::user(&session.id, "msg"))
                .unwrap();
            state
                .session_store
                .archive_session(&session.id, false)
                .unwrap();
        }

        let result = handle_sessions_archives(&state, None).unwrap();
        assert_eq!(result["total"], 2);
        let archives = result["archives"].as_array().unwrap();
        assert_eq!(archives.len(), 2);
        for entry in archives {
            assert!(entry["sessionId"].is_string());
            assert!(entry["key"].is_string());
            assert!(entry["messageCount"].as_u64().is_some());
        }
    }

    #[test]
    fn test_handle_sessions_archive_delete_requires_key() {
        let (state, _tmp) = make_state_with_temp_sessions();
        let result = handle_sessions_archive_delete(&state, None);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code, "INVALID_REQUEST");
    }

    #[test]
    fn test_handle_sessions_archive_delete_success() {
        let (state, _tmp) = make_state_with_temp_sessions();

        let session = state
            .session_store
            .create_session("agent-1", sessions::SessionMetadata::default())
            .unwrap();
        state
            .session_store
            .append_message(sessions::ChatMessage::user(&session.id, "Hello"))
            .unwrap();
        state
            .session_store
            .archive_session(&session.id, false)
            .unwrap();

        let params = json!({ "key": session.session_key });
        let result = handle_sessions_archive_delete(&state, Some(&params)).unwrap();
        assert_eq!(result["ok"], true);
        assert_eq!(result["deleted"], true);
    }

    // ============== Export/Purge User Tests ==============

    #[test]
    fn test_handle_sessions_export_user_requires_user_id() {
        let (state, _tmp) = make_state_with_temp_sessions();
        let result = handle_sessions_export_user(&state, None);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code, "INVALID_REQUEST");
    }

    #[test]
    fn test_handle_sessions_export_user_rejects_empty_user_id() {
        let (state, _tmp) = make_state_with_temp_sessions();
        let params = json!({ "userId": "" });
        let result = handle_sessions_export_user(&state, Some(&params));
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code, "INVALID_REQUEST");
    }

    #[test]
    fn test_handle_sessions_export_user_rejects_whitespace_user_id() {
        let (state, _tmp) = make_state_with_temp_sessions();
        let params = json!({ "userId": "   " });
        let result = handle_sessions_export_user(&state, Some(&params));
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code, "INVALID_REQUEST");
    }

    #[test]
    fn test_handle_sessions_export_user_empty() {
        let (state, _tmp) = make_state_with_temp_sessions();
        let params = json!({ "userId": "user-999" });
        let result = handle_sessions_export_user(&state, Some(&params)).unwrap();
        assert_eq!(result["ok"], true);
        assert_eq!(result["data"]["user_id"], "user-999");
        assert_eq!(result["data"]["session_count"], 0);
        assert_eq!(result["data"]["sessions"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn test_handle_sessions_export_user_with_data() {
        let (state, _tmp) = make_state_with_temp_sessions();

        let meta = sessions::SessionMetadata {
            user_id: Some("user-42".to_string()),
            ..Default::default()
        };
        let session = state.session_store.create_session("agent-1", meta).unwrap();
        state
            .session_store
            .append_message(sessions::ChatMessage::user(&session.id, "Hello"))
            .unwrap();

        let params = json!({ "userId": "user-42" });
        let result = handle_sessions_export_user(&state, Some(&params)).unwrap();
        assert_eq!(result["ok"], true);
        let data = &result["data"];
        assert_eq!(data["user_id"], "user-42");
        assert_eq!(data["session_count"], 1);
        let exported_sessions = data["sessions"].as_array().unwrap();
        assert_eq!(exported_sessions.len(), 1);
        let messages = exported_sessions[0]["messages"].as_array().unwrap();
        assert_eq!(messages.len(), 1);
        assert!(result["warnings"].is_array());
        assert_eq!(result["warnings"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn test_handle_sessions_purge_user_requires_user_id() {
        let (state, _tmp) = make_state_with_temp_sessions();
        let result = handle_sessions_purge_user(&state, None);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code, "INVALID_REQUEST");
    }

    #[test]
    fn test_handle_sessions_purge_user_rejects_empty_user_id() {
        let (state, _tmp) = make_state_with_temp_sessions();
        let params = json!({ "userId": "" });
        let result = handle_sessions_purge_user(&state, Some(&params));
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code, "INVALID_REQUEST");
    }

    #[test]
    fn test_handle_sessions_purge_user_rejects_whitespace_user_id() {
        let (state, _tmp) = make_state_with_temp_sessions();
        let params = json!({ "userId": "  \t  " });
        let result = handle_sessions_purge_user(&state, Some(&params));
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code, "INVALID_REQUEST");
    }

    #[test]
    fn test_handle_sessions_purge_user_empty() {
        let (state, _tmp) = make_state_with_temp_sessions();
        let params = json!({ "userId": "user-999" });
        let result = handle_sessions_purge_user(&state, Some(&params)).unwrap();
        assert_eq!(result["ok"], true);
        assert_eq!(result["sessionsDeleted"], 0);
        assert_eq!(result["sessionsTotal"], 0);
    }

    #[test]
    fn test_handle_sessions_purge_user_deletes_sessions() {
        let (state, _tmp) = make_state_with_temp_sessions();

        for i in 0..3 {
            let meta = sessions::SessionMetadata {
                user_id: Some("user-42".to_string()),
                chat_id: Some(format!("chat-{}", i)),
                ..Default::default()
            };
            state.session_store.create_session("agent-1", meta).unwrap();
        }
        // Create a session for a different user that should NOT be deleted
        let other_meta = sessions::SessionMetadata {
            user_id: Some("user-99".to_string()),
            chat_id: Some("other-chat".to_string()),
            ..Default::default()
        };
        state
            .session_store
            .create_session("agent-1", other_meta)
            .unwrap();

        let params = json!({ "userId": "user-42" });
        let result = handle_sessions_purge_user(&state, Some(&params)).unwrap();
        assert_eq!(result["ok"], true);
        assert_eq!(result["sessionsDeleted"], 3);
        assert_eq!(result["sessionsTotal"], 3);

        // Verify the other user's session is still there
        let remaining = state
            .session_store
            .list_sessions(sessions::SessionFilter::new().with_user_id("user-99"))
            .unwrap();
        assert_eq!(remaining.len(), 1);
    }

    // ============== Agent Identity Tests ==============

    #[test]
    fn test_agent_identity_get_no_params_no_config() {
        // With no config, should return hardcoded default
        let result = handle_agent_identity_get(None).unwrap();
        assert_eq!(result["agentId"], "default");
        assert_eq!(result["name"], "Carapace");
    }

    #[test]
    fn test_agent_identity_get_unknown_agent_id_errors() {
        let params = json!({ "agentId": "nonexistent-agent" });
        let result = handle_agent_identity_get(Some(&params));
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code, ERROR_INVALID_REQUEST);
    }

    #[test]
    fn test_agent_identity_get_response_shape() {
        let result = handle_agent_identity_get(None).unwrap();
        assert!(result.get("agentId").is_some());
        assert!(result.get("name").is_some());
        // description should be present (even if null)
        assert!(result.get("description").is_some());
    }
}
