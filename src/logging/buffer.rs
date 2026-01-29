//! In-memory log buffer for real-time log streaming.
//!
//! This module provides a ring buffer that captures log entries from the tracing
//! subscriber, enabling real-time log streaming via the `logs.tail` WebSocket method.

use parking_lot::RwLock;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::LazyLock;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::field::{Field, Visit};
use tracing::span::Attributes;
use tracing::{Event, Id, Level, Subscriber};
use tracing_subscriber::layer::Context;
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::Layer;

/// Default capacity for the log ring buffer (number of entries)
pub const DEFAULT_BUFFER_CAPACITY: usize = 1000;

/// Maximum buffer capacity
pub const MAX_BUFFER_CAPACITY: usize = 10_000;

/// Global log buffer instance
pub static LOG_BUFFER: LazyLock<LogBuffer> = LazyLock::new(LogBuffer::new);

/// Log level for filtering
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Trace = 0,
    Debug = 1,
    Info = 2,
    Warn = 3,
    Error = 4,
}

impl std::str::FromStr for LogLevel {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "trace" => Ok(LogLevel::Trace),
            "debug" => Ok(LogLevel::Debug),
            "info" => Ok(LogLevel::Info),
            "warn" | "warning" => Ok(LogLevel::Warn),
            "error" => Ok(LogLevel::Error),
            _ => Err(format!("unknown log level: {s}")),
        }
    }
}

impl LogLevel {
    /// Convert tracing Level to LogLevel
    pub fn from_tracing(level: &Level) -> Self {
        match *level {
            Level::TRACE => LogLevel::Trace,
            Level::DEBUG => LogLevel::Debug,
            Level::INFO => LogLevel::Info,
            Level::WARN => LogLevel::Warn,
            Level::ERROR => LogLevel::Error,
        }
    }
}

impl std::fmt::Display for LogLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LogLevel::Trace => write!(f, "trace"),
            LogLevel::Debug => write!(f, "debug"),
            LogLevel::Info => write!(f, "info"),
            LogLevel::Warn => write!(f, "warn"),
            LogLevel::Error => write!(f, "error"),
        }
    }
}

/// A captured log entry
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LogEntry {
    /// Unique sequence number for this entry
    pub seq: u64,
    /// Unix timestamp in milliseconds
    pub timestamp: u64,
    /// Log level
    pub level: LogLevel,
    /// Target/module path (e.g., "ws", "gateway")
    pub target: String,
    /// Log message
    pub message: String,
    /// Optional span name if within a span
    #[serde(skip_serializing_if = "Option::is_none")]
    pub span: Option<String>,
    /// Optional additional fields
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fields: Option<serde_json::Value>,
}

/// Filter criteria for querying logs
#[derive(Debug, Clone, Default)]
pub struct LogFilter {
    /// Minimum log level (inclusive)
    pub level: Option<LogLevel>,
    /// Regex pattern to match against target
    pub pattern: Option<Regex>,
    /// Maximum number of entries to return
    pub limit: Option<usize>,
    /// Return entries with seq > after_seq (for pagination/streaming)
    pub after_seq: Option<u64>,
}

impl LogFilter {
    /// Create a new empty filter
    pub fn new() -> Self {
        Self::default()
    }

    /// Set minimum level filter
    pub fn with_level(mut self, level: LogLevel) -> Self {
        self.level = Some(level);
        self
    }

    /// Set target pattern filter (regex)
    pub fn with_pattern(mut self, pattern: Regex) -> Self {
        self.pattern = Some(pattern);
        self
    }

    /// Set pattern from string (returns None if invalid regex)
    pub fn with_pattern_str(mut self, pattern: &str) -> Option<Self> {
        match Regex::new(pattern) {
            Ok(re) => {
                self.pattern = Some(re);
                Some(self)
            }
            Err(_) => None,
        }
    }

    /// Set maximum entries to return
    pub fn with_limit(mut self, limit: usize) -> Self {
        self.limit = Some(limit);
        self
    }

    /// Set after_seq for pagination
    pub fn with_after_seq(mut self, seq: u64) -> Self {
        self.after_seq = Some(seq);
        self
    }

    /// Check if an entry matches this filter
    pub fn matches(&self, entry: &LogEntry) -> bool {
        // Check level
        if let Some(min_level) = self.level {
            if entry.level < min_level {
                return false;
            }
        }

        // Check pattern against target
        if let Some(ref pattern) = self.pattern {
            if !pattern.is_match(&entry.target) {
                return false;
            }
        }

        // Check sequence number for pagination
        if let Some(after_seq) = self.after_seq {
            if entry.seq <= after_seq {
                return false;
            }
        }

        true
    }
}

/// Result of a log query
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LogQueryResult {
    /// Matching log entries
    pub entries: Vec<LogEntry>,
    /// Cursor for pagination (highest seq returned)
    pub cursor: u64,
    /// Total entries in buffer (before filtering)
    pub total: usize,
    /// Whether more entries exist after cursor
    pub has_more: bool,
}

/// Thread-safe ring buffer for log entries
pub struct LogBuffer {
    inner: RwLock<LogBufferInner>,
}

struct LogBufferInner {
    /// Ring buffer of log entries
    entries: VecDeque<LogEntry>,
    /// Maximum capacity
    capacity: usize,
    /// Next sequence number
    next_seq: u64,
}

impl LogBuffer {
    /// Create a new log buffer with default capacity
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_BUFFER_CAPACITY)
    }

    /// Create a new log buffer with specified capacity
    pub fn with_capacity(capacity: usize) -> Self {
        let capacity = capacity.min(MAX_BUFFER_CAPACITY);
        Self {
            inner: RwLock::new(LogBufferInner {
                entries: VecDeque::with_capacity(capacity),
                capacity,
                next_seq: 1,
            }),
        }
    }

    /// Push a new log entry into the buffer
    pub fn push(&self, entry: LogEntry) {
        let mut inner = self.inner.write();
        if inner.entries.len() >= inner.capacity {
            inner.entries.pop_front();
        }
        inner.entries.push_back(entry);
    }

    /// Push a log entry, assigning a sequence number
    pub fn push_with_seq(
        &self,
        level: LogLevel,
        target: String,
        message: String,
        span: Option<String>,
        fields: Option<serde_json::Value>,
    ) -> u64 {
        let mut inner = self.inner.write();
        let seq = inner.next_seq;
        inner.next_seq += 1;

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        let entry = LogEntry {
            seq,
            timestamp,
            level,
            target,
            message,
            span,
            fields,
        };

        if inner.entries.len() >= inner.capacity {
            inner.entries.pop_front();
        }
        inner.entries.push_back(entry);

        seq
    }

    /// Query log entries with a filter
    pub fn query(&self, filter: &LogFilter) -> LogQueryResult {
        let inner = self.inner.read();
        let total = inner.entries.len();

        let mut entries: Vec<LogEntry> = inner
            .entries
            .iter()
            .filter(|e| filter.matches(e))
            .cloned()
            .collect();

        // Apply limit (take from end to get most recent)
        let limit = filter.limit.unwrap_or(100);
        let has_more = entries.len() > limit;
        if entries.len() > limit {
            entries = entries.split_off(entries.len() - limit);
        }

        let cursor = entries.last().map(|e| e.seq).unwrap_or(0);

        LogQueryResult {
            entries,
            cursor,
            total,
            has_more,
        }
    }

    /// Get entries after a specific sequence number (for streaming)
    pub fn get_after(&self, seq: u64, limit: usize) -> Vec<LogEntry> {
        let inner = self.inner.read();
        inner
            .entries
            .iter()
            .filter(|e| e.seq > seq)
            .take(limit)
            .cloned()
            .collect()
    }

    /// Get the current sequence number (last assigned)
    pub fn current_seq(&self) -> u64 {
        let inner = self.inner.read();
        inner.next_seq.saturating_sub(1)
    }

    /// Get the number of entries in the buffer
    pub fn len(&self) -> usize {
        self.inner.read().entries.len()
    }

    /// Check if the buffer is empty
    pub fn is_empty(&self) -> bool {
        self.inner.read().entries.is_empty()
    }

    /// Clear all entries
    pub fn clear(&self) {
        let mut inner = self.inner.write();
        inner.entries.clear();
    }

    /// Set the capacity (will truncate if needed)
    pub fn set_capacity(&self, capacity: usize) {
        let capacity = capacity.min(MAX_BUFFER_CAPACITY);
        let mut inner = self.inner.write();
        inner.capacity = capacity;
        while inner.entries.len() > capacity {
            inner.entries.pop_front();
        }
    }
}

impl Default for LogBuffer {
    fn default() -> Self {
        Self::new()
    }
}

/// Visitor to extract fields from a tracing event
struct FieldVisitor {
    message: String,
    fields: serde_json::Map<String, serde_json::Value>,
}

impl FieldVisitor {
    fn new() -> Self {
        Self {
            message: String::new(),
            fields: serde_json::Map::new(),
        }
    }
}

impl Visit for FieldVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        let name = field.name();
        if name == "message" {
            self.message = format!("{:?}", value);
            // Remove surrounding quotes if present (need at least 2 chars to have content)
            if self.message.len() > 2
                && self.message.starts_with('"')
                && self.message.ends_with('"')
            {
                self.message = self.message[1..self.message.len() - 1].to_string();
            }
        } else {
            self.fields
                .insert(name.to_string(), serde_json::json!(format!("{:?}", value)));
        }
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        let name = field.name();
        if name == "message" {
            self.message = value.to_string();
        } else {
            self.fields
                .insert(name.to_string(), serde_json::json!(value));
        }
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.fields
            .insert(field.name().to_string(), serde_json::json!(value));
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.fields
            .insert(field.name().to_string(), serde_json::json!(value));
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.fields
            .insert(field.name().to_string(), serde_json::json!(value));
    }
}

/// Tracing layer that captures logs to the global buffer
pub struct LogBufferLayer;

impl LogBufferLayer {
    /// Create a new log buffer layer
    pub fn new() -> Self {
        Self
    }
}

impl Default for LogBufferLayer {
    fn default() -> Self {
        Self::new()
    }
}

impl<S> Layer<S> for LogBufferLayer
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_event(&self, event: &Event<'_>, ctx: Context<'_, S>) {
        let level = LogLevel::from_tracing(event.metadata().level());
        let target = event.metadata().target().to_string();

        // Extract message and fields
        let mut visitor = FieldVisitor::new();
        event.record(&mut visitor);

        // Get current span name
        let span = ctx
            .current_span()
            .id()
            .and_then(|id| ctx.span(id).map(|span| span.metadata().name().to_string()));

        // Convert fields to JSON if not empty
        let fields = if visitor.fields.is_empty() {
            None
        } else {
            Some(serde_json::Value::Object(visitor.fields))
        };

        // Push to global buffer
        LOG_BUFFER.push_with_seq(level, target, visitor.message, span, fields);
    }

    fn on_new_span(&self, _attrs: &Attributes<'_>, _id: &Id, _ctx: Context<'_, S>) {
        // We don't need to track spans for the buffer
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_level_ordering() {
        assert!(LogLevel::Trace < LogLevel::Debug);
        assert!(LogLevel::Debug < LogLevel::Info);
        assert!(LogLevel::Info < LogLevel::Warn);
        assert!(LogLevel::Warn < LogLevel::Error);
    }

    #[test]
    fn test_log_level_from_str() {
        assert_eq!("trace".parse::<LogLevel>(), Ok(LogLevel::Trace));
        assert_eq!("DEBUG".parse::<LogLevel>(), Ok(LogLevel::Debug));
        assert_eq!("Info".parse::<LogLevel>(), Ok(LogLevel::Info));
        assert_eq!("warn".parse::<LogLevel>(), Ok(LogLevel::Warn));
        assert_eq!("warning".parse::<LogLevel>(), Ok(LogLevel::Warn));
        assert_eq!("error".parse::<LogLevel>(), Ok(LogLevel::Error));
        assert!("invalid".parse::<LogLevel>().is_err());
    }

    #[test]
    fn test_buffer_push_and_query() {
        let buffer = LogBuffer::with_capacity(10);

        // Push some entries
        for i in 0..5 {
            buffer.push_with_seq(
                LogLevel::Info,
                format!("test::module{}", i),
                format!("message {}", i),
                None,
                None,
            );
        }

        assert_eq!(buffer.len(), 5);

        // Query all
        let result = buffer.query(&LogFilter::new());
        assert_eq!(result.entries.len(), 5);
        assert_eq!(result.total, 5);
    }

    #[test]
    fn test_buffer_capacity() {
        let buffer = LogBuffer::with_capacity(3);

        // Push more than capacity
        for i in 0..5 {
            buffer.push_with_seq(
                LogLevel::Info,
                "test".to_string(),
                format!("message {}", i),
                None,
                None,
            );
        }

        // Should only have 3 entries (most recent)
        assert_eq!(buffer.len(), 3);

        let result = buffer.query(&LogFilter::new());
        assert_eq!(result.entries.len(), 3);
        // Messages should be 2, 3, 4 (oldest dropped)
        assert!(result.entries[0].message.contains('2'));
        assert!(result.entries[1].message.contains('3'));
        assert!(result.entries[2].message.contains('4'));
    }

    #[test]
    fn test_filter_by_level() {
        let buffer = LogBuffer::new();

        buffer.push_with_seq(
            LogLevel::Debug,
            "test".to_string(),
            "debug msg".to_string(),
            None,
            None,
        );
        buffer.push_with_seq(
            LogLevel::Info,
            "test".to_string(),
            "info msg".to_string(),
            None,
            None,
        );
        buffer.push_with_seq(
            LogLevel::Warn,
            "test".to_string(),
            "warn msg".to_string(),
            None,
            None,
        );
        buffer.push_with_seq(
            LogLevel::Error,
            "test".to_string(),
            "error msg".to_string(),
            None,
            None,
        );

        // Filter for warn and above
        let filter = LogFilter::new().with_level(LogLevel::Warn);
        let result = buffer.query(&filter);
        assert_eq!(result.entries.len(), 2);
        assert_eq!(result.entries[0].level, LogLevel::Warn);
        assert_eq!(result.entries[1].level, LogLevel::Error);
    }

    #[test]
    fn test_filter_by_pattern() {
        let buffer = LogBuffer::new();

        buffer.push_with_seq(
            LogLevel::Info,
            "ws::handler".to_string(),
            "ws msg".to_string(),
            None,
            None,
        );
        buffer.push_with_seq(
            LogLevel::Info,
            "http::server".to_string(),
            "http msg".to_string(),
            None,
            None,
        );
        buffer.push_with_seq(
            LogLevel::Info,
            "ws::client".to_string(),
            "ws client msg".to_string(),
            None,
            None,
        );
        buffer.push_with_seq(
            LogLevel::Info,
            "gateway".to_string(),
            "gateway msg".to_string(),
            None,
            None,
        );

        // Filter for ws targets
        let filter = LogFilter::new().with_pattern(Regex::new("^ws::").unwrap());
        let result = buffer.query(&filter);
        assert_eq!(result.entries.len(), 2);
        assert!(result.entries[0].target.starts_with("ws::"));
        assert!(result.entries[1].target.starts_with("ws::"));
    }

    #[test]
    fn test_filter_with_limit() {
        let buffer = LogBuffer::new();

        for i in 0..10 {
            buffer.push_with_seq(
                LogLevel::Info,
                "test".to_string(),
                format!("message {}", i),
                None,
                None,
            );
        }

        // Limit to 3
        let filter = LogFilter::new().with_limit(3);
        let result = buffer.query(&filter);
        assert_eq!(result.entries.len(), 3);
        assert!(result.has_more);
        // Should be most recent entries
        assert!(result.entries[0].message.contains('7'));
        assert!(result.entries[1].message.contains('8'));
        assert!(result.entries[2].message.contains('9'));
    }

    #[test]
    fn test_filter_after_seq() {
        let buffer = LogBuffer::new();

        for i in 0..5 {
            buffer.push_with_seq(
                LogLevel::Info,
                "test".to_string(),
                format!("message {}", i),
                None,
                None,
            );
        }

        // Get entries after seq 2
        let filter = LogFilter::new().with_after_seq(2);
        let result = buffer.query(&filter);
        assert_eq!(result.entries.len(), 3);
        assert!(result.entries[0].seq > 2);
    }

    #[test]
    fn test_get_after() {
        let buffer = LogBuffer::new();

        for i in 0..5 {
            buffer.push_with_seq(
                LogLevel::Info,
                "test".to_string(),
                format!("message {}", i),
                None,
                None,
            );
        }

        // Get entries after seq 3
        let entries = buffer.get_after(3, 10);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].seq, 4);
        assert_eq!(entries[1].seq, 5);
    }

    #[test]
    fn test_combined_filters() {
        let buffer = LogBuffer::new();

        buffer.push_with_seq(
            LogLevel::Debug,
            "ws::handler".to_string(),
            "debug ws".to_string(),
            None,
            None,
        );
        buffer.push_with_seq(
            LogLevel::Info,
            "ws::handler".to_string(),
            "info ws".to_string(),
            None,
            None,
        );
        buffer.push_with_seq(
            LogLevel::Warn,
            "ws::handler".to_string(),
            "warn ws".to_string(),
            None,
            None,
        );
        buffer.push_with_seq(
            LogLevel::Info,
            "http::server".to_string(),
            "info http".to_string(),
            None,
            None,
        );
        buffer.push_with_seq(
            LogLevel::Error,
            "ws::client".to_string(),
            "error ws".to_string(),
            None,
            None,
        );

        // Filter for ws targets at warn level or above
        let filter = LogFilter::new()
            .with_level(LogLevel::Warn)
            .with_pattern(Regex::new("^ws::").unwrap());
        let result = buffer.query(&filter);
        assert_eq!(result.entries.len(), 2);
        assert_eq!(result.entries[0].level, LogLevel::Warn);
        assert_eq!(result.entries[1].level, LogLevel::Error);
    }

    #[test]
    fn test_log_entry_serialization() {
        let entry = LogEntry {
            seq: 1,
            timestamp: 1234567890000,
            level: LogLevel::Info,
            target: "test".to_string(),
            message: "test message".to_string(),
            span: Some("my_span".to_string()),
            fields: Some(serde_json::json!({"key": "value"})),
        };

        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("\"seq\":1"));
        assert!(json.contains("\"level\":\"info\""));
        assert!(json.contains("\"target\":\"test\""));
        assert!(json.contains("\"span\":\"my_span\""));
    }

    #[test]
    fn test_clear_buffer() {
        let buffer = LogBuffer::new();

        for i in 0..5 {
            buffer.push_with_seq(
                LogLevel::Info,
                "test".to_string(),
                format!("message {}", i),
                None,
                None,
            );
        }

        assert_eq!(buffer.len(), 5);
        buffer.clear();
        assert!(buffer.is_empty());
        assert_eq!(buffer.len(), 0);
    }
}
