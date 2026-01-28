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

    /// Check if the message can be retried
    pub fn can_retry(&self) -> bool {
        self.context.retry_enabled && self.attempts < self.context.max_retries
    }
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

/// Message pipeline for queuing outbound messages
///
/// This is a skeleton implementation - actual delivery logic
/// will be added when channel implementations are ready.
pub struct MessagePipeline {
    /// Queued messages by channel
    queues: RwLock<HashMap<String, VecDeque<QueuedMessage>>>,
    /// Message lookup by ID
    messages: RwLock<HashMap<String, QueuedMessage>>,
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

        self.stats_queued.fetch_add(1, Ordering::Relaxed);

        // Wake delivery worker
        self.notify.notify_one();

        Ok(QueueResult {
            message_id,
            status: DeliveryStatus::Queued,
            queue_position: Some(queue_position),
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
    pub fn mark_sending(&self, message_id: &MessageId) -> Result<(), PipelineError> {
        let mut messages = self.messages.write();
        if let Some(queued) = messages.get_mut(&message_id.0) {
            queued.mark_sending();
            Ok(())
        } else {
            Err(PipelineError::MessageNotFound(message_id.0.clone()))
        }
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

    /// Remove completed messages older than TTL
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
        queues.clear();
        messages.clear();
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
        };

        let json = serde_json::to_string(&result).unwrap();
        let parsed: QueueResult = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.message_id.0, "test-123");
        assert_eq!(parsed.status, DeliveryStatus::Queued);
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
}
