//! Outbound message pipeline
//!
//! Provides types and interfaces for queuing and delivering messages
//! to messaging channels.

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::Notify;
use uuid::Uuid;

/// Maximum number of completed messages to retain for status lookup
const MAX_COMPLETED_MESSAGES: usize = 10_000;

/// TTL for completed messages (1 hour)
const COMPLETED_MESSAGE_TTL_MS: i64 = 3600 * 1000;

/// TTL for idempotency keys (24 hours)
const IDEMPOTENCY_KEY_TTL_MS: i64 = 24 * 3600 * 1000;

/// Unique identifier for a message in the pipeline
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MessageId(pub String);

impl MessageId {
    /// Generate a new unique message ID
    pub fn new() -> Self {
        Self(Uuid::new_v4().to_string())
    }

    /// Create a message ID from a string
    pub fn from_string(s: impl Into<String>) -> Self {
        Self(s.into())
    }
}

impl Default for MessageId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for MessageId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl AsRef<str> for MessageId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// Delivery status of an outbound message
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryStatus {
    /// Message is queued for delivery
    #[default]
    Queued,
    /// Message is being sent
    Sending,
    /// Message was successfully sent
    Sent,
    /// Message delivery failed
    Failed,
    /// Message was cancelled before delivery
    Cancelled,
    /// Message expired before delivery
    Expired,
}

impl std::fmt::Display for DeliveryStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Queued => write!(f, "queued"),
            Self::Sending => write!(f, "sending"),
            Self::Sent => write!(f, "sent"),
            Self::Failed => write!(f, "failed"),
            Self::Cancelled => write!(f, "cancelled"),
            Self::Expired => write!(f, "expired"),
        }
    }
}

/// Type of message content
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum MessageContent {
    /// Plain text message
    Text { text: String },
    /// Message with media attachment
    Media {
        /// Optional caption text
        #[serde(skip_serializing_if = "Option::is_none")]
        caption: Option<String>,
        /// Media reference (URL or local path)
        media_ref: String,
        /// MIME type of the media
        #[serde(skip_serializing_if = "Option::is_none")]
        mime_type: Option<String>,
    },
    /// Multiple content items (e.g., text + images)
    Composite { parts: Vec<MessageContent> },
}

impl MessageContent {
    /// Create a text message content
    pub fn text(text: impl Into<String>) -> Self {
        Self::Text { text: text.into() }
    }

    /// Create a media message content
    pub fn media(media_ref: impl Into<String>) -> Self {
        Self::Media {
            caption: None,
            media_ref: media_ref.into(),
            mime_type: None,
        }
    }

    /// Create a media message with caption
    pub fn media_with_caption(media_ref: impl Into<String>, caption: impl Into<String>) -> Self {
        Self::Media {
            caption: Some(caption.into()),
            media_ref: media_ref.into(),
            mime_type: None,
        }
    }
}

/// Metadata for message delivery context
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MessageMetadata {
    /// ID of message being replied to
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reply_to: Option<String>,
    /// Thread or conversation ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thread_id: Option<String>,
    /// Chat or conversation ID within the channel
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chat_id: Option<String>,
    /// User ID of the recipient
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recipient_id: Option<String>,
    /// Channel-specific extra data
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extra: Option<serde_json::Value>,
    /// Priority (higher = more urgent, default 0)
    #[serde(default)]
    pub priority: i32,
    /// Time-to-live in milliseconds (0 = no expiry)
    #[serde(default)]
    pub ttl_ms: u64,
}

/// An outbound message to be delivered
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutboundMessage {
    /// Unique message identifier
    pub id: MessageId,
    /// Target channel ID
    pub channel_id: String,
    /// Message content
    pub content: MessageContent,
    /// Delivery metadata
    #[serde(default)]
    pub metadata: MessageMetadata,
    /// When the message was created (Unix ms)
    pub created_at: i64,
}

impl OutboundMessage {
    /// Create a new outbound message
    pub fn new(channel_id: impl Into<String>, content: MessageContent) -> Self {
        Self {
            id: MessageId::new(),
            channel_id: channel_id.into(),
            content,
            metadata: MessageMetadata::default(),
            created_at: now_millis(),
        }
    }

    /// Set metadata on the message
    pub fn with_metadata(mut self, metadata: MessageMetadata) -> Self {
        self.metadata = metadata;
        self
    }

    /// Set reply-to on the message
    pub fn reply_to(mut self, message_id: impl Into<String>) -> Self {
        self.metadata.reply_to = Some(message_id.into());
        self
    }

    /// Set thread ID on the message
    pub fn in_thread(mut self, thread_id: impl Into<String>) -> Self {
        self.metadata.thread_id = Some(thread_id.into());
        self
    }

    /// Set chat ID on the message
    #[allow(clippy::wrong_self_convention)] // Builder pattern - takes ownership intentionally
    pub fn to_chat(mut self, chat_id: impl Into<String>) -> Self {
        self.metadata.chat_id = Some(chat_id.into());
        self
    }

    /// Check if the message has expired based on TTL
    pub fn is_expired(&self) -> bool {
        if self.metadata.ttl_ms == 0 {
            return false;
        }
        let now = now_millis();
        now - self.created_at > self.metadata.ttl_ms as i64
    }
}

/// Context for message delivery
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OutboundContext {
    /// Session or request ID for tracing
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
    /// Source of the message (e.g., "agent", "user", "system")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// Whether to retry on failure
    #[serde(default)]
    pub retry_enabled: bool,
    /// Maximum retry attempts
    #[serde(default)]
    pub max_retries: u32,
    /// Callback URL for delivery status updates
    #[serde(skip_serializing_if = "Option::is_none")]
    pub callback_url: Option<String>,
}

impl OutboundContext {
    /// Create a new outbound context
    pub fn new() -> Self {
        Self::default()
    }

    /// Enable retries with a maximum count
    pub fn with_retries(mut self, max_retries: u32) -> Self {
        self.retry_enabled = true;
        self.max_retries = max_retries;
        self
    }

    /// Set the trace ID
    pub fn with_trace_id(mut self, trace_id: impl Into<String>) -> Self {
        self.trace_id = Some(trace_id.into());
        self
    }

    /// Set the source
    pub fn with_source(mut self, source: impl Into<String>) -> Self {
        self.source = Some(source.into());
        self
    }
}

/// Entry in the message queue with status tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueuedMessage {
    /// The outbound message
    pub message: OutboundMessage,
    /// Delivery context
    pub context: OutboundContext,
    /// Current delivery status
    pub status: DeliveryStatus,
    /// Number of delivery attempts
    pub attempts: u32,
    /// Last error message if failed
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    /// When status was last updated (Unix ms)
    pub updated_at: i64,
}

impl QueuedMessage {
    /// Create a new queued message
    pub fn new(message: OutboundMessage, context: OutboundContext) -> Self {
        Self {
            message,
            context,
            status: DeliveryStatus::Queued,
            attempts: 0,
            last_error: None,
            updated_at: now_millis(),
        }
    }

    /// Mark the message as being sent
    pub fn mark_sending(&mut self) {
        self.status = DeliveryStatus::Sending;
        self.attempts += 1;
        self.updated_at = now_millis();
    }

    /// Mark the message as sent
    pub fn mark_sent(&mut self) {
        self.status = DeliveryStatus::Sent;
        self.updated_at = now_millis();
    }

    /// Mark the message as failed
    pub fn mark_failed(&mut self, error: impl Into<String>) {
        self.status = DeliveryStatus::Failed;
        self.last_error = Some(error.into());
        self.updated_at = now_millis();
    }

    /// Mark the message as cancelled
    pub fn mark_cancelled(&mut self) {
        self.status = DeliveryStatus::Cancelled;
        self.updated_at = now_millis();
    }

    /// Reset the message to Queued for retry after a failed delivery attempt.
    ///
    /// Records the error from the failed attempt but resets status so the
    /// message will be picked up again by the delivery loop.
    pub fn mark_retry(&mut self, error: impl Into<String>) {
        self.status = DeliveryStatus::Queued;
        self.last_error = Some(error.into());
        self.updated_at = now_millis();
    }

    /// Check if the message can be retried
    pub fn can_retry(&self) -> bool {
        self.context.retry_enabled && self.attempts < self.context.max_retries
    }
}

/// Delivery result fields returned from channel plugins (re-exported for convenience)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DeliveryResultFields {
    /// Channel-specific conversation identifier
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conversation_id: Option<String>,
    /// Recipient JID (Jabber ID) for XMPP-based channels
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to_jid: Option<String>,
    /// Poll identifier when the message is a poll
    #[serde(skip_serializing_if = "Option::is_none")]
    pub poll_id: Option<String>,
}

/// Result of queueing a message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueueResult {
    /// The assigned message ID
    pub message_id: MessageId,
    /// Current status
    pub status: DeliveryStatus,
    /// Position in queue (if queued)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub queue_position: Option<usize>,
    /// Optional delivery result fields populated after delivery
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delivery_result: Option<DeliveryResultFields>,
}

/// Error types for pipeline operations
#[derive(Debug, Clone, thiserror::Error)]
pub enum PipelineError {
    #[error("Channel not found: {0}")]
    ChannelNotFound(String),
    #[error("Channel not connected: {0}")]
    ChannelNotConnected(String),
    #[error("Message not found: {0}")]
    MessageNotFound(String),
    #[error("Queue full for channel: {0}")]
    QueueFull(String),
    #[error("Invalid message: {0}")]
    InvalidMessage(String),
    #[error("Delivery failed: {0}")]
    DeliveryFailed(String),
}

/// Statistics for the message pipeline
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PipelineStats {
    /// Total messages queued
    pub total_queued: u64,
    /// Total messages sent successfully
    pub total_sent: u64,
    /// Total messages failed
    pub total_failed: u64,
    /// Currently queued messages
    pub current_queue_size: usize,
    /// Messages by channel
    pub by_channel: HashMap<String, ChannelStats>,
}

/// Per-channel statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ChannelStats {
    pub queued: u64,
    pub sent: u64,
    pub failed: u64,
    pub queue_size: usize,
}

/// Tracks an idempotency key to prevent duplicate message delivery.
#[derive(Debug, Clone)]
struct IdempotencyEntry {
    /// The message ID that was created for this idempotency key
    message_id: MessageId,
    /// When this entry was recorded (Unix ms)
    created_at: i64,
}

/// Message pipeline for queuing and tracking outbound messages.
///
/// Provides per-channel FIFO queues with idempotency-key deduplication,
/// TTL-based expiration, retry tracking, and cancellation support.
/// Delivery workers call [`next_for_channel`](Self::next_for_channel) to
/// dequeue messages and [`mark_sent`](Self::mark_sent) /
/// [`mark_failed`](Self::mark_failed) to report outcomes.
pub struct MessagePipeline {
    /// Queued messages by channel
    queues: RwLock<HashMap<String, VecDeque<QueuedMessage>>>,
    /// Message lookup by ID
    messages: RwLock<HashMap<String, QueuedMessage>>,
    /// Idempotency key deduplication store: key -> entry
    idempotency_keys: RwLock<HashMap<String, IdempotencyEntry>>,
    /// Maximum queue size per channel
    max_queue_size: usize,
    /// Statistics counters
    stats_queued: AtomicU64,
    stats_sent: AtomicU64,
    stats_failed: AtomicU64,
    /// Notify delivery workers when messages are queued
    notify: Arc<Notify>,
}

impl std::fmt::Debug for MessagePipeline {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MessagePipeline")
            .field("queues", &self.queues)
            .field("messages", &self.messages)
            .field("idempotency_keys", &self.idempotency_keys)
            .field("max_queue_size", &self.max_queue_size)
            .field("notify", &"Notify")
            .finish()
    }
}

impl Default for MessagePipeline {
    fn default() -> Self {
        Self::new()
    }
}

impl MessagePipeline {
    /// Create a new message pipeline
    pub fn new() -> Self {
        Self::with_max_queue_size(1000)
    }

    /// Create a pipeline with a custom max queue size
    pub fn with_max_queue_size(max_queue_size: usize) -> Self {
        Self {
            queues: RwLock::new(HashMap::new()),
            messages: RwLock::new(HashMap::new()),
            idempotency_keys: RwLock::new(HashMap::new()),
            max_queue_size,
            stats_queued: AtomicU64::new(0),
            stats_sent: AtomicU64::new(0),
            stats_failed: AtomicU64::new(0),
            notify: Arc::new(Notify::new()),
        }
    }

    /// Get the notifier for delivery workers to await on
    pub fn notifier(&self) -> &Arc<Notify> {
        &self.notify
    }

    /// Queue a message for delivery
    ///
    /// Returns the message ID and queue position on success.
    pub fn queue(
        &self,
        message: OutboundMessage,
        context: OutboundContext,
    ) -> Result<QueueResult, PipelineError> {
        self.queue_with_idempotency(message, context, None)
    }

    /// Queue a message for delivery with an explicit idempotency key.
    ///
    /// If `idempotency_key` is `Some` and matches an already-queued or
    /// delivered message within the TTL window (24 hours), the original
    /// message's status is returned without creating a duplicate entry.
    pub fn queue_with_idempotency(
        &self,
        message: OutboundMessage,
        context: OutboundContext,
        idempotency_key: Option<&str>,
    ) -> Result<QueueResult, PipelineError> {
        // Check idempotency key for deduplication
        if let Some(key) = idempotency_key {
            let now = now_millis();
            let idempotency_store = self.idempotency_keys.read();
            if let Some(entry) = idempotency_store.get(key) {
                if now - entry.created_at < IDEMPOTENCY_KEY_TTL_MS {
                    // Return existing message status
                    let messages = self.messages.read();
                    if let Some(queued) = messages.get(&entry.message_id.0) {
                        return Ok(QueueResult {
                            message_id: entry.message_id.clone(),
                            status: queued.status,
                            queue_position: None,
                            delivery_result: None,
                        });
                    }
                    // Message was cleaned up but key still present; return
                    // the recorded message ID with a Sent status as a
                    // best-effort indicator that the message was processed.
                    return Ok(QueueResult {
                        message_id: entry.message_id.clone(),
                        status: DeliveryStatus::Sent,
                        queue_position: None,
                        delivery_result: None,
                    });
                }
            }
        }

        let channel_id = message.channel_id.clone();
        let message_id = message.id.clone();

        let queued = QueuedMessage::new(message, context);

        // Check queue size limit
        {
            let queues = self.queues.read();
            if let Some(queue) = queues.get(&channel_id) {
                if queue.len() >= self.max_queue_size {
                    return Err(PipelineError::QueueFull(channel_id));
                }
            }
        }

        // Add to queues
        let queue_position = {
            let mut queues = self.queues.write();
            let queue = queues.entry(channel_id).or_default();
            queue.push_back(queued.clone());
            queue.len()
        };

        // Add to message lookup
        {
            let mut messages = self.messages.write();
            messages.insert(message_id.0.clone(), queued);
        }

        // Record idempotency key
        if let Some(key) = idempotency_key {
            let mut idempotency_store = self.idempotency_keys.write();
            idempotency_store.insert(
                key.to_string(),
                IdempotencyEntry {
                    message_id: message_id.clone(),
                    created_at: now_millis(),
                },
            );
        }

        self.stats_queued.fetch_add(1, Ordering::Relaxed);

        // Wake delivery worker
        self.notify.notify_one();

        Ok(QueueResult {
            message_id,
            status: DeliveryStatus::Queued,
            queue_position: Some(queue_position),
            delivery_result: None,
        })
    }

    /// Get the status of a queued message
    pub fn get_status(&self, message_id: &MessageId) -> Option<DeliveryStatus> {
        let messages = self.messages.read();
        messages.get(&message_id.0).map(|m| m.status)
    }

    /// Get full details of a queued message
    pub fn get_message(&self, message_id: &MessageId) -> Option<QueuedMessage> {
        let messages = self.messages.read();
        messages.get(&message_id.0).cloned()
    }

    /// Cancel a queued message
    ///
    /// Only works for messages that haven't been sent yet.
    pub fn cancel(&self, message_id: &MessageId) -> Result<(), PipelineError> {
        let mut messages = self.messages.write();
        if let Some(queued) = messages.get_mut(&message_id.0) {
            if queued.status == DeliveryStatus::Queued {
                queued.mark_cancelled();
                Ok(())
            } else {
                Err(PipelineError::InvalidMessage(format!(
                    "Cannot cancel message with status: {}",
                    queued.status
                )))
            }
        } else {
            Err(PipelineError::MessageNotFound(message_id.0.clone()))
        }
    }

    /// Check if a message can be retried (from the authoritative messages map).
    ///
    /// This reads the current attempt count and retry settings, ensuring
    /// the retry decision is based on up-to-date state rather than a stale clone.
    pub fn can_retry(&self, message_id: &MessageId) -> bool {
        let messages = self.messages.read();
        messages
            .get(&message_id.0)
            .map(|m| m.can_retry())
            .unwrap_or(false)
    }

    /// Get the next message to deliver for a channel
    ///
    /// This is used by delivery workers to get messages to send.
    pub fn next_for_channel(&self, channel_id: &str) -> Option<QueuedMessage> {
        let queues = self.queues.read();
        if let Some(queue) = queues.get(channel_id) {
            // Find first non-cancelled, non-expired message
            for msg in queue.iter() {
                if msg.status == DeliveryStatus::Queued && !msg.message.is_expired() {
                    return Some(msg.clone());
                }
            }
        }
        None
    }

    /// Mark a message as being sent
    ///
    /// Updates both the `messages` lookup map and the `queues` entry so that
    /// `next_for_channel` will not return a message that is already in-flight.
    pub fn mark_sending(&self, message_id: &MessageId) -> Result<(), PipelineError> {
        let channel_id = {
            let mut messages = self.messages.write();
            if let Some(queued) = messages.get_mut(&message_id.0) {
                queued.mark_sending();
                queued.message.channel_id.clone()
            } else {
                return Err(PipelineError::MessageNotFound(message_id.0.clone()));
            }
        };

        // Also update the queue entry so next_for_channel skips this message
        let mut queues = self.queues.write();
        if let Some(queue) = queues.get_mut(&channel_id) {
            for entry in queue.iter_mut() {
                if entry.message.id == *message_id {
                    entry.mark_sending();
                    break;
                }
            }
        }

        Ok(())
    }

    /// Mark a message as sent successfully
    pub fn mark_sent(&self, message_id: &MessageId) -> Result<(), PipelineError> {
        {
            let mut messages = self.messages.write();
            if let Some(queued) = messages.get_mut(&message_id.0) {
                queued.mark_sent();
            } else {
                return Err(PipelineError::MessageNotFound(message_id.0.clone()));
            }
        }

        self.stats_sent.fetch_add(1, Ordering::Relaxed);

        // Remove from queue
        self.remove_from_queue(message_id);

        // Clean up old completed messages to prevent memory leak
        self.maybe_cleanup_completed();

        Ok(())
    }

    /// Reset a message to Queued so it can be retried by the delivery loop.
    ///
    /// Updates both the `messages` lookup map and the `queues` entry so that
    /// `next_for_channel` will return this message again on the next iteration.
    pub fn mark_retry(
        &self,
        message_id: &MessageId,
        error: impl Into<String>,
    ) -> Result<(), PipelineError> {
        let (channel_id, error_str) = {
            let error_string = error.into();
            let mut messages = self.messages.write();
            if let Some(queued) = messages.get_mut(&message_id.0) {
                queued.mark_retry(&error_string);
                (queued.message.channel_id.clone(), error_string)
            } else {
                return Err(PipelineError::MessageNotFound(message_id.0.clone()));
            }
        };

        // Also update the queue entry so next_for_channel picks it up again
        let mut queues = self.queues.write();
        if let Some(queue) = queues.get_mut(&channel_id) {
            for entry in queue.iter_mut() {
                if entry.message.id == *message_id {
                    entry.mark_retry(error_str);
                    break;
                }
            }
        }

        Ok(())
    }

    /// Mark a message as failed
    pub fn mark_failed(
        &self,
        message_id: &MessageId,
        error: impl Into<String>,
    ) -> Result<(), PipelineError> {
        {
            let mut messages = self.messages.write();
            if let Some(queued) = messages.get_mut(&message_id.0) {
                queued.mark_failed(error);
            } else {
                return Err(PipelineError::MessageNotFound(message_id.0.clone()));
            }
        }

        self.stats_failed.fetch_add(1, Ordering::Relaxed);

        // Remove from queue
        self.remove_from_queue(message_id);

        // Clean up old completed messages to prevent memory leak
        self.maybe_cleanup_completed();

        Ok(())
    }

    /// Clean up old completed messages if the map is getting too large
    fn maybe_cleanup_completed(&self) {
        let messages = self.messages.read();
        if messages.len() <= MAX_COMPLETED_MESSAGES {
            return;
        }
        drop(messages);

        self.cleanup_completed();
    }

    /// Remove completed messages older than TTL and expired idempotency keys.
    pub fn cleanup_completed(&self) -> usize {
        let now = now_millis();
        let cutoff = now - COMPLETED_MESSAGE_TTL_MS;

        let mut messages = self.messages.write();
        let before = messages.len();

        // Remove completed messages older than TTL
        messages.retain(|_, msg| {
            // Keep if still queued/sending
            if matches!(msg.status, DeliveryStatus::Queued | DeliveryStatus::Sending) {
                return true;
            }
            // Remove if completed and older than TTL
            msg.updated_at > cutoff
        });

        // Clean up expired idempotency keys
        let idempotency_cutoff = now - IDEMPOTENCY_KEY_TTL_MS;
        let mut idempotency_store = self.idempotency_keys.write();
        idempotency_store.retain(|_, entry| entry.created_at > idempotency_cutoff);

        before - messages.len()
    }

    /// Remove a message from its channel queue
    fn remove_from_queue(&self, message_id: &MessageId) {
        // Get the channel ID first
        let channel_id = {
            let messages = self.messages.read();
            messages
                .get(&message_id.0)
                .map(|m| m.message.channel_id.clone())
        };

        if let Some(channel_id) = channel_id {
            let mut queues = self.queues.write();
            if let Some(queue) = queues.get_mut(&channel_id) {
                queue.retain(|m| m.message.id != *message_id);
            }
        }
    }

    /// Get queue size for a channel
    pub fn queue_size(&self, channel_id: &str) -> usize {
        let queues = self.queues.read();
        queues.get(channel_id).map(|q| q.len()).unwrap_or(0)
    }

    /// Get total queue size across all channels
    pub fn total_queue_size(&self) -> usize {
        let queues = self.queues.read();
        queues.values().map(|q| q.len()).sum()
    }

    /// Get pipeline statistics
    pub fn stats(&self) -> PipelineStats {
        let queues = self.queues.read();
        let mut by_channel = HashMap::new();

        for (channel_id, queue) in queues.iter() {
            by_channel.insert(
                channel_id.clone(),
                ChannelStats {
                    queued: 0, // Would need per-channel tracking
                    sent: 0,
                    failed: 0,
                    queue_size: queue.len(),
                },
            );
        }

        PipelineStats {
            total_queued: self.stats_queued.load(Ordering::Relaxed),
            total_sent: self.stats_sent.load(Ordering::Relaxed),
            total_failed: self.stats_failed.load(Ordering::Relaxed),
            current_queue_size: self.total_queue_size(),
            by_channel,
        }
    }

    /// Clear all queues (for testing or shutdown)
    pub fn clear(&self) {
        let mut queues = self.queues.write();
        let mut messages = self.messages.write();
        let mut idempotency_store = self.idempotency_keys.write();
        queues.clear();
        messages.clear();
        idempotency_store.clear();
    }

    /// List all channel IDs with queued messages
    pub fn channels_with_messages(&self) -> Vec<String> {
        let queues = self.queues.read();
        queues
            .iter()
            .filter(|(_, q)| !q.is_empty())
            .map(|(id, _)| id.clone())
            .collect()
    }
}

/// Create a shared message pipeline
pub fn create_pipeline() -> Arc<MessagePipeline> {
    Arc::new(MessagePipeline::new())
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

    #[test]
    fn test_message_id_generation() {
        let id1 = MessageId::new();
        let id2 = MessageId::new();
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_message_id_from_string() {
        let id = MessageId::from_string("test-123");
        assert_eq!(id.0, "test-123");
        assert_eq!(id.to_string(), "test-123");
    }

    #[test]
    fn test_delivery_status_display() {
        assert_eq!(DeliveryStatus::Queued.to_string(), "queued");
        assert_eq!(DeliveryStatus::Sent.to_string(), "sent");
        assert_eq!(DeliveryStatus::Failed.to_string(), "failed");
    }

    #[test]
    fn test_message_content_text() {
        let content = MessageContent::text("Hello, world!");
        match content {
            MessageContent::Text { text } => assert_eq!(text, "Hello, world!"),
            _ => panic!("Expected text content"),
        }
    }

    #[test]
    fn test_message_content_media() {
        let content =
            MessageContent::media_with_caption("https://example.com/image.jpg", "A photo");
        match content {
            MessageContent::Media {
                caption, media_ref, ..
            } => {
                assert_eq!(caption, Some("A photo".into()));
                assert_eq!(media_ref, "https://example.com/image.jpg");
            }
            _ => panic!("Expected media content"),
        }
    }

    #[test]
    fn test_outbound_message_builder() {
        let msg = OutboundMessage::new("telegram", MessageContent::text("Hello"))
            .reply_to("msg-123")
            .in_thread("thread-456")
            .to_chat("chat-789");

        assert_eq!(msg.channel_id, "telegram");
        assert_eq!(msg.metadata.reply_to, Some("msg-123".into()));
        assert_eq!(msg.metadata.thread_id, Some("thread-456".into()));
        assert_eq!(msg.metadata.chat_id, Some("chat-789".into()));
    }

    #[test]
    fn test_outbound_message_expiry() {
        let mut msg = OutboundMessage::new("telegram", MessageContent::text("Hello"));
        msg.metadata.ttl_ms = 1000;
        msg.created_at = now_millis() - 2000; // Created 2 seconds ago

        assert!(msg.is_expired());
    }

    #[test]
    fn test_outbound_message_no_expiry() {
        let msg = OutboundMessage::new("telegram", MessageContent::text("Hello"));
        assert!(!msg.is_expired()); // ttl_ms = 0 means no expiry
    }

    #[test]
    fn test_outbound_context_builder() {
        let ctx = OutboundContext::new()
            .with_retries(3)
            .with_trace_id("trace-123")
            .with_source("agent");

        assert!(ctx.retry_enabled);
        assert_eq!(ctx.max_retries, 3);
        assert_eq!(ctx.trace_id, Some("trace-123".into()));
        assert_eq!(ctx.source, Some("agent".into()));
    }

    #[test]
    fn test_queued_message_status_transitions() {
        let msg = OutboundMessage::new("telegram", MessageContent::text("Hello"));
        let ctx = OutboundContext::new();
        let mut queued = QueuedMessage::new(msg, ctx);

        assert_eq!(queued.status, DeliveryStatus::Queued);
        assert_eq!(queued.attempts, 0);

        queued.mark_sending();
        assert_eq!(queued.status, DeliveryStatus::Sending);
        assert_eq!(queued.attempts, 1);

        queued.mark_sent();
        assert_eq!(queued.status, DeliveryStatus::Sent);
    }

    #[test]
    fn test_queued_message_can_retry() {
        let msg = OutboundMessage::new("telegram", MessageContent::text("Hello"));
        let ctx = OutboundContext::new().with_retries(3);
        let mut queued = QueuedMessage::new(msg, ctx);

        assert!(queued.can_retry());

        queued.attempts = 3;
        assert!(!queued.can_retry());
    }

    #[test]
    fn test_queued_message_mark_retry_resets_to_queued() {
        let msg = OutboundMessage::new("telegram", MessageContent::text("Hello"));
        let ctx = OutboundContext::new().with_retries(3);
        let mut queued = QueuedMessage::new(msg, ctx);

        // Simulate a delivery attempt
        queued.mark_sending();
        assert_eq!(queued.status, DeliveryStatus::Sending);
        assert_eq!(queued.attempts, 1);

        // Simulate retryable failure: reset to Queued
        queued.mark_retry("temporary error");
        assert_eq!(queued.status, DeliveryStatus::Queued);
        assert_eq!(queued.last_error, Some("temporary error".to_string()));
        // attempts should remain at 1 (incremented by mark_sending, not by mark_retry)
        assert_eq!(queued.attempts, 1);
        assert!(queued.can_retry()); // still under max_retries=3
    }

    #[test]
    fn test_pipeline_mark_retry_resets_status_in_both_stores() {
        let pipeline = MessagePipeline::new();
        let msg = OutboundMessage::new("telegram", MessageContent::text("Hello"));
        let ctx = OutboundContext::new().with_retries(3);
        let result = pipeline.queue(msg, ctx).unwrap();

        // mark_sending sets status to Sending in both messages map and queue
        pipeline.mark_sending(&result.message_id).unwrap();
        assert_eq!(
            pipeline.get_status(&result.message_id),
            Some(DeliveryStatus::Sending)
        );
        // next_for_channel should NOT return a Sending message
        assert!(pipeline.next_for_channel("telegram").is_none());

        // mark_retry resets status to Queued in both messages map and queue
        pipeline
            .mark_retry(&result.message_id, "transient error")
            .unwrap();
        assert_eq!(
            pipeline.get_status(&result.message_id),
            Some(DeliveryStatus::Queued)
        );
        // next_for_channel should now return the message again
        let next = pipeline.next_for_channel("telegram");
        assert!(next.is_some(), "message should be available for retry");
        assert_eq!(next.unwrap().message.id, result.message_id);
    }

    #[test]
    fn test_pipeline_can_retry_uses_authoritative_state() {
        let pipeline = MessagePipeline::new();
        let msg = OutboundMessage::new("telegram", MessageContent::text("Hello"));
        let ctx = OutboundContext::new().with_retries(2);
        let result = pipeline.queue(msg, ctx).unwrap();

        // Initially can retry (0 attempts < 2 max)
        assert!(pipeline.can_retry(&result.message_id));

        // First attempt
        pipeline.mark_sending(&result.message_id).unwrap();
        // After 1 attempt, can still retry (1 < 2)
        assert!(pipeline.can_retry(&result.message_id));

        pipeline.mark_retry(&result.message_id, "error 1").unwrap();

        // Second attempt
        pipeline.mark_sending(&result.message_id).unwrap();
        // After 2 attempts, cannot retry (2 >= 2)
        assert!(!pipeline.can_retry(&result.message_id));
    }

    #[test]
    fn test_pipeline_queue_and_get() {
        let pipeline = MessagePipeline::new();
        let msg = OutboundMessage::new("telegram", MessageContent::text("Hello"));
        let ctx = OutboundContext::new();

        let result = pipeline.queue(msg.clone(), ctx).unwrap();

        assert_eq!(result.status, DeliveryStatus::Queued);
        assert_eq!(result.queue_position, Some(1));

        let status = pipeline.get_status(&result.message_id);
        assert_eq!(status, Some(DeliveryStatus::Queued));

        let retrieved = pipeline.get_message(&result.message_id).unwrap();
        assert_eq!(retrieved.message.channel_id, "telegram");
    }

    #[test]
    fn test_pipeline_queue_full() {
        let pipeline = MessagePipeline::with_max_queue_size(2);

        for i in 0..2 {
            let msg = OutboundMessage::new("telegram", MessageContent::text(format!("Msg {}", i)));
            pipeline.queue(msg, OutboundContext::new()).unwrap();
        }

        let msg = OutboundMessage::new("telegram", MessageContent::text("Overflow"));
        let result = pipeline.queue(msg, OutboundContext::new());

        assert!(matches!(result, Err(PipelineError::QueueFull(_))));
    }

    #[test]
    fn test_pipeline_cancel() {
        let pipeline = MessagePipeline::new();
        let msg = OutboundMessage::new("telegram", MessageContent::text("Hello"));
        let result = pipeline.queue(msg, OutboundContext::new()).unwrap();

        pipeline.cancel(&result.message_id).unwrap();

        let status = pipeline.get_status(&result.message_id);
        assert_eq!(status, Some(DeliveryStatus::Cancelled));
    }

    #[test]
    fn test_pipeline_mark_sent() {
        let pipeline = MessagePipeline::new();
        let msg = OutboundMessage::new("telegram", MessageContent::text("Hello"));
        let result = pipeline.queue(msg, OutboundContext::new()).unwrap();

        pipeline.mark_sending(&result.message_id).unwrap();
        pipeline.mark_sent(&result.message_id).unwrap();

        let status = pipeline.get_status(&result.message_id);
        assert_eq!(status, Some(DeliveryStatus::Sent));

        // Should be removed from queue
        assert_eq!(pipeline.queue_size("telegram"), 0);
    }

    #[test]
    fn test_pipeline_mark_failed() {
        let pipeline = MessagePipeline::new();
        let msg = OutboundMessage::new("telegram", MessageContent::text("Hello"));
        let result = pipeline.queue(msg, OutboundContext::new()).unwrap();

        pipeline
            .mark_failed(&result.message_id, "Network error")
            .unwrap();

        let queued = pipeline.get_message(&result.message_id).unwrap();
        assert_eq!(queued.status, DeliveryStatus::Failed);
        assert_eq!(queued.last_error, Some("Network error".into()));
    }

    #[test]
    fn test_pipeline_next_for_channel() {
        let pipeline = MessagePipeline::new();
        let msg1 = OutboundMessage::new("telegram", MessageContent::text("First"));
        let msg2 = OutboundMessage::new("telegram", MessageContent::text("Second"));

        pipeline.queue(msg1, OutboundContext::new()).unwrap();
        pipeline.queue(msg2, OutboundContext::new()).unwrap();

        let next = pipeline.next_for_channel("telegram").unwrap();
        match &next.message.content {
            MessageContent::Text { text } => assert_eq!(text, "First"),
            _ => panic!("Expected text content"),
        }
    }

    #[test]
    fn test_pipeline_stats() {
        let pipeline = MessagePipeline::new();
        let msg = OutboundMessage::new("telegram", MessageContent::text("Hello"));
        let result = pipeline.queue(msg, OutboundContext::new()).unwrap();

        let stats = pipeline.stats();
        assert_eq!(stats.total_queued, 1);
        assert_eq!(stats.current_queue_size, 1);

        pipeline.mark_sent(&result.message_id).unwrap();

        let stats = pipeline.stats();
        assert_eq!(stats.total_sent, 1);
        assert_eq!(stats.current_queue_size, 0);
    }

    #[test]
    fn test_pipeline_channels_with_messages() {
        let pipeline = MessagePipeline::new();
        pipeline
            .queue(
                OutboundMessage::new("telegram", MessageContent::text("Hello")),
                OutboundContext::new(),
            )
            .unwrap();
        pipeline
            .queue(
                OutboundMessage::new("discord", MessageContent::text("Hello")),
                OutboundContext::new(),
            )
            .unwrap();

        let channels = pipeline.channels_with_messages();
        assert_eq!(channels.len(), 2);
        assert!(channels.contains(&"telegram".to_string()));
        assert!(channels.contains(&"discord".to_string()));
    }

    #[test]
    fn test_pipeline_clear() {
        let pipeline = MessagePipeline::new();
        pipeline
            .queue(
                OutboundMessage::new("telegram", MessageContent::text("Hello")),
                OutboundContext::new(),
            )
            .unwrap();

        assert_eq!(pipeline.total_queue_size(), 1);

        pipeline.clear();

        assert_eq!(pipeline.total_queue_size(), 0);
    }

    #[test]
    fn test_pipeline_thread_safety() {
        use std::thread;

        let pipeline = Arc::new(MessagePipeline::new());
        let mut handles = vec![];

        // Spawn multiple threads that queue messages
        for i in 0..10 {
            let p = Arc::clone(&pipeline);
            handles.push(thread::spawn(move || {
                let msg =
                    OutboundMessage::new("telegram", MessageContent::text(format!("Msg {}", i)));
                p.queue(msg, OutboundContext::new()).unwrap();
            }));
        }

        for handle in handles {
            handle.join().unwrap();
        }

        assert_eq!(pipeline.queue_size("telegram"), 10);
    }

    #[test]
    fn test_outbound_message_serialization() {
        let msg = OutboundMessage::new("telegram", MessageContent::text("Hello"))
            .reply_to("msg-123")
            .in_thread("thread-456");

        let json = serde_json::to_string(&msg).unwrap();
        let parsed: OutboundMessage = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.channel_id, msg.channel_id);
        assert_eq!(parsed.metadata.reply_to, msg.metadata.reply_to);
    }

    #[test]
    fn test_queue_result_serialization() {
        let result = QueueResult {
            message_id: MessageId::from_string("test-123"),
            status: DeliveryStatus::Queued,
            queue_position: Some(1),
            delivery_result: None,
        };

        let json = serde_json::to_string(&result).unwrap();
        let parsed: QueueResult = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.message_id.0, "test-123");
        assert_eq!(parsed.status, DeliveryStatus::Queued);
    }

    #[test]
    fn test_queue_result_with_delivery_fields() {
        let result = QueueResult {
            message_id: MessageId::from_string("test-456"),
            status: DeliveryStatus::Sent,
            queue_position: None,
            delivery_result: Some(DeliveryResultFields {
                conversation_id: Some("conv-123".to_string()),
                to_jid: Some("user@chat.example.com".to_string()),
                poll_id: None,
            }),
        };

        let json = serde_json::to_string(&result).unwrap();
        let parsed: QueueResult = serde_json::from_str(&json).unwrap();

        let delivery = parsed.delivery_result.unwrap();
        assert_eq!(delivery.conversation_id, Some("conv-123".to_string()));
        assert_eq!(delivery.to_jid, Some("user@chat.example.com".to_string()));
        assert_eq!(delivery.poll_id, None);
    }

    #[test]
    fn test_delivery_result_fields_default() {
        let fields = DeliveryResultFields::default();
        assert_eq!(fields.conversation_id, None);
        assert_eq!(fields.to_jid, None);
        assert_eq!(fields.poll_id, None);
    }

    #[test]
    fn test_pipeline_stats_serialization() {
        let pipeline = MessagePipeline::new();
        pipeline
            .queue(
                OutboundMessage::new("telegram", MessageContent::text("Hello")),
                OutboundContext::new(),
            )
            .unwrap();

        let stats = pipeline.stats();
        let json = serde_json::to_string(&stats).unwrap();
        let parsed: PipelineStats = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.total_queued, 1);
    }

    #[test]
    fn test_idempotency_first_send_succeeds() {
        let pipeline = MessagePipeline::new();
        let msg = OutboundMessage::new("telegram", MessageContent::text("Hello"));
        let ctx = OutboundContext::new();

        let result = pipeline
            .queue_with_idempotency(msg, ctx, Some("idem-key-1"))
            .unwrap();

        assert_eq!(result.status, DeliveryStatus::Queued);
        assert!(result.queue_position.is_some());
        assert_eq!(pipeline.queue_size("telegram"), 1);
    }

    #[test]
    fn test_idempotency_duplicate_returns_original() {
        let pipeline = MessagePipeline::new();

        // First send
        let msg1 = OutboundMessage::new("telegram", MessageContent::text("Hello"));
        let ctx1 = OutboundContext::new();
        let result1 = pipeline
            .queue_with_idempotency(msg1, ctx1, Some("idem-key-dup"))
            .unwrap();
        let original_id = result1.message_id.clone();

        // Second send with same idempotency key
        let msg2 = OutboundMessage::new("telegram", MessageContent::text("Hello again"));
        let ctx2 = OutboundContext::new();
        let result2 = pipeline
            .queue_with_idempotency(msg2, ctx2, Some("idem-key-dup"))
            .unwrap();

        // Should return the original message ID, not create a new one
        assert_eq!(result2.message_id, original_id);
        // Should not have a queue_position (deduplication short-circuits queueing)
        assert!(result2.queue_position.is_none());
        // Only one message should be in the queue
        assert_eq!(pipeline.queue_size("telegram"), 1);
        // Total queued counter should be 1 (not 2)
        assert_eq!(pipeline.stats().total_queued, 1);
    }

    #[test]
    fn test_idempotency_different_keys_create_separate_messages() {
        let pipeline = MessagePipeline::new();

        let msg1 = OutboundMessage::new("telegram", MessageContent::text("First"));
        let result1 = pipeline
            .queue_with_idempotency(msg1, OutboundContext::new(), Some("key-a"))
            .unwrap();

        let msg2 = OutboundMessage::new("telegram", MessageContent::text("Second"));
        let result2 = pipeline
            .queue_with_idempotency(msg2, OutboundContext::new(), Some("key-b"))
            .unwrap();

        // Different keys should produce different message IDs
        assert_ne!(result1.message_id, result2.message_id);
        // Both should be queued
        assert_eq!(pipeline.queue_size("telegram"), 2);
        assert_eq!(pipeline.stats().total_queued, 2);
    }

    #[test]
    fn test_idempotency_expired_key_allows_reuse() {
        let pipeline = MessagePipeline::new();

        // First send
        let msg1 = OutboundMessage::new("telegram", MessageContent::text("Hello"));
        let result1 = pipeline
            .queue_with_idempotency(msg1, OutboundContext::new(), Some("expire-key"))
            .unwrap();
        let original_id = result1.message_id.clone();

        // Manually expire the idempotency entry by backdating its created_at
        {
            let mut idempotency_store = pipeline.idempotency_keys.write();
            if let Some(entry) = idempotency_store.get_mut("expire-key") {
                // Set created_at to well beyond the TTL in the past
                entry.created_at = now_millis() - IDEMPOTENCY_KEY_TTL_MS - 1000;
            }
        }

        // Second send with same key should create a new message (key expired)
        let msg2 = OutboundMessage::new("telegram", MessageContent::text("Hello again"));
        let result2 = pipeline
            .queue_with_idempotency(msg2, OutboundContext::new(), Some("expire-key"))
            .unwrap();

        // Should get a new message ID
        assert_ne!(result2.message_id, original_id);
        // Should have a queue position (was actually queued)
        assert!(result2.queue_position.is_some());
        // Two messages should be in the queue
        assert_eq!(pipeline.queue_size("telegram"), 2);
    }

    #[test]
    fn test_idempotency_no_key_always_queues() {
        let pipeline = MessagePipeline::new();

        // Queue two messages without idempotency keys
        let msg1 = OutboundMessage::new("telegram", MessageContent::text("First"));
        let result1 = pipeline.queue(msg1, OutboundContext::new()).unwrap();

        let msg2 = OutboundMessage::new("telegram", MessageContent::text("Second"));
        let result2 = pipeline.queue(msg2, OutboundContext::new()).unwrap();

        // Both should get unique message IDs
        assert_ne!(result1.message_id, result2.message_id);
        assert_eq!(pipeline.queue_size("telegram"), 2);
    }

    #[test]
    fn test_idempotency_returns_current_status_of_original() {
        let pipeline = MessagePipeline::new();

        // Queue a message
        let msg = OutboundMessage::new("telegram", MessageContent::text("Hello"));
        let result = pipeline
            .queue_with_idempotency(msg, OutboundContext::new(), Some("status-key"))
            .unwrap();

        // Mark the original as sent
        pipeline.mark_sending(&result.message_id).unwrap();
        pipeline.mark_sent(&result.message_id).unwrap();

        // Re-send with same key should return Sent status
        let msg2 = OutboundMessage::new("telegram", MessageContent::text("Hello again"));
        let result2 = pipeline
            .queue_with_idempotency(msg2, OutboundContext::new(), Some("status-key"))
            .unwrap();

        assert_eq!(result2.message_id, result.message_id);
        assert_eq!(result2.status, DeliveryStatus::Sent);
    }

    #[test]
    fn test_idempotency_cleanup_removes_expired_keys() {
        let pipeline = MessagePipeline::new();

        // Queue a message with an idempotency key
        let msg = OutboundMessage::new("telegram", MessageContent::text("Hello"));
        pipeline
            .queue_with_idempotency(msg, OutboundContext::new(), Some("cleanup-key"))
            .unwrap();

        // Verify key exists
        {
            let store = pipeline.idempotency_keys.read();
            assert!(store.contains_key("cleanup-key"));
        }

        // Backdate the entry to make it expired
        {
            let mut store = pipeline.idempotency_keys.write();
            if let Some(entry) = store.get_mut("cleanup-key") {
                entry.created_at = now_millis() - IDEMPOTENCY_KEY_TTL_MS - 1000;
            }
        }

        // Run cleanup
        pipeline.cleanup_completed();

        // Key should be removed
        {
            let store = pipeline.idempotency_keys.read();
            assert!(
                !store.contains_key("cleanup-key"),
                "expired idempotency key should be removed by cleanup"
            );
        }
    }

    #[test]
    fn test_idempotency_clear_removes_all_keys() {
        let pipeline = MessagePipeline::new();

        let msg = OutboundMessage::new("telegram", MessageContent::text("Hello"));
        pipeline
            .queue_with_idempotency(msg, OutboundContext::new(), Some("clear-key"))
            .unwrap();

        {
            let store = pipeline.idempotency_keys.read();
            assert!(!store.is_empty());
        }

        pipeline.clear();

        {
            let store = pipeline.idempotency_keys.read();
            assert!(store.is_empty());
        }
    }
}
