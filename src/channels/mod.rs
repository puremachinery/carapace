//! Channel management module
//!
//! Provides channel registry for tracking active messaging channels
//! and their connection states.

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

/// Connection status of a channel
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChannelStatus {
    /// Channel is connected and ready
    Connected,
    /// Channel is disconnected
    Disconnected,
    /// Channel is in the process of connecting
    Connecting,
    /// Channel encountered an error
    Error,
    /// Channel is paused/suspended
    Paused,
    /// Channel logged out explicitly
    LoggedOut,
}

impl Default for ChannelStatus {
    fn default() -> Self {
        Self::Disconnected
    }
}

impl std::fmt::Display for ChannelStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Connected => write!(f, "connected"),
            Self::Disconnected => write!(f, "disconnected"),
            Self::Connecting => write!(f, "connecting"),
            Self::Error => write!(f, "error"),
            Self::Paused => write!(f, "paused"),
            Self::LoggedOut => write!(f, "logged_out"),
        }
    }
}

/// Metadata associated with a channel
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ChannelMetadata {
    /// Human-readable description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Channel-specific configuration or state
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extra: Option<serde_json::Value>,
    /// Last error message if status is Error
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    /// Timestamp of last successful connection (Unix ms)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_connected_at: Option<i64>,
    /// Timestamp of last status change (Unix ms)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_changed_at: Option<i64>,
}

/// Information about a registered channel
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelInfo {
    /// Unique channel identifier (e.g., "telegram", "discord", "slack")
    pub id: String,
    /// Human-readable channel name
    pub name: String,
    /// Current connection status
    pub status: ChannelStatus,
    /// Additional metadata
    #[serde(default)]
    pub metadata: ChannelMetadata,
}

impl ChannelInfo {
    /// Create a new channel info with the given ID and name
    pub fn new(id: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            status: ChannelStatus::Disconnected,
            metadata: ChannelMetadata::default(),
        }
    }

    /// Create a channel info with status
    pub fn with_status(mut self, status: ChannelStatus) -> Self {
        self.status = status;
        self
    }

    /// Create a channel info with metadata
    pub fn with_metadata(mut self, metadata: ChannelMetadata) -> Self {
        self.metadata = metadata;
        self
    }
}

/// Snapshot of the channel registry state for API responses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrySnapshot {
    /// All registered channels
    pub channels: Vec<ChannelInfo>,
    /// Timestamp when snapshot was taken (Unix ms)
    pub timestamp: i64,
}

/// Thread-safe registry for tracking active channels
#[derive(Debug)]
pub struct ChannelRegistry {
    channels: RwLock<HashMap<String, ChannelInfo>>,
}

impl Default for ChannelRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ChannelRegistry {
    /// Create a new empty channel registry
    pub fn new() -> Self {
        Self {
            channels: RwLock::new(HashMap::new()),
        }
    }

    /// Register a channel in the registry
    ///
    /// If a channel with the same ID already exists, it will be replaced.
    pub fn register(&self, info: ChannelInfo) {
        let mut channels = self.channels.write();
        channels.insert(info.id.clone(), info);
    }

    /// Unregister a channel from the registry
    ///
    /// Returns the removed channel info if it existed.
    pub fn unregister(&self, channel_id: &str) -> Option<ChannelInfo> {
        let mut channels = self.channels.write();
        channels.remove(channel_id)
    }

    /// Get the status of a specific channel
    pub fn get_status(&self, channel_id: &str) -> Option<ChannelStatus> {
        let channels = self.channels.read();
        channels.get(channel_id).map(|info| info.status)
    }

    /// Get full info for a specific channel
    pub fn get(&self, channel_id: &str) -> Option<ChannelInfo> {
        let channels = self.channels.read();
        channels.get(channel_id).cloned()
    }

    /// List all registered channels
    pub fn list(&self) -> Vec<ChannelInfo> {
        let channels = self.channels.read();
        channels.values().cloned().collect()
    }

    /// Update the status of a channel
    ///
    /// Returns true if the channel existed and was updated.
    pub fn update_status(&self, channel_id: &str, status: ChannelStatus) -> bool {
        let mut channels = self.channels.write();
        if let Some(info) = channels.get_mut(channel_id) {
            info.status = status;
            info.metadata.status_changed_at = Some(now_millis());
            if status == ChannelStatus::Connected {
                info.metadata.last_connected_at = Some(now_millis());
            }
            true
        } else {
            false
        }
    }

    /// Update the status and set an error message
    pub fn set_error(&self, channel_id: &str, error: impl Into<String>) -> bool {
        let mut channels = self.channels.write();
        if let Some(info) = channels.get_mut(channel_id) {
            info.status = ChannelStatus::Error;
            info.metadata.last_error = Some(error.into());
            info.metadata.status_changed_at = Some(now_millis());
            true
        } else {
            false
        }
    }

    /// Handle logout for a channel (sets status to LoggedOut)
    pub fn logout(&self, channel_id: &str) -> bool {
        self.update_status(channel_id, ChannelStatus::LoggedOut)
    }

    /// Create a serializable snapshot of the registry state
    pub fn snapshot(&self) -> RegistrySnapshot {
        RegistrySnapshot {
            channels: self.list(),
            timestamp: now_millis(),
        }
    }

    /// Check if a channel is currently connected
    pub fn is_connected(&self, channel_id: &str) -> bool {
        self.get_status(channel_id) == Some(ChannelStatus::Connected)
    }

    /// Get count of channels by status
    pub fn count_by_status(&self, status: ChannelStatus) -> usize {
        let channels = self.channels.read();
        channels.values().filter(|c| c.status == status).count()
    }

    /// Get total number of registered channels
    pub fn len(&self) -> usize {
        self.channels.read().len()
    }

    /// Check if registry is empty
    pub fn is_empty(&self) -> bool {
        self.channels.read().is_empty()
    }
}

/// Create a shared channel registry
pub fn create_registry() -> Arc<ChannelRegistry> {
    Arc::new(ChannelRegistry::new())
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
    fn test_channel_status_default() {
        assert_eq!(ChannelStatus::default(), ChannelStatus::Disconnected);
    }

    #[test]
    fn test_channel_status_display() {
        assert_eq!(ChannelStatus::Connected.to_string(), "connected");
        assert_eq!(ChannelStatus::Disconnected.to_string(), "disconnected");
        assert_eq!(ChannelStatus::Error.to_string(), "error");
        assert_eq!(ChannelStatus::LoggedOut.to_string(), "logged_out");
    }

    #[test]
    fn test_channel_info_builder() {
        let info = ChannelInfo::new("telegram", "Telegram")
            .with_status(ChannelStatus::Connected)
            .with_metadata(ChannelMetadata {
                description: Some("Main bot".into()),
                ..Default::default()
            });

        assert_eq!(info.id, "telegram");
        assert_eq!(info.name, "Telegram");
        assert_eq!(info.status, ChannelStatus::Connected);
        assert_eq!(info.metadata.description, Some("Main bot".into()));
    }

    #[test]
    fn test_registry_register_and_get() {
        let registry = ChannelRegistry::new();
        let info = ChannelInfo::new("telegram", "Telegram");

        registry.register(info.clone());

        let retrieved = registry.get("telegram").unwrap();
        assert_eq!(retrieved.id, "telegram");
        assert_eq!(retrieved.name, "Telegram");
    }

    #[test]
    fn test_registry_unregister() {
        let registry = ChannelRegistry::new();
        registry.register(ChannelInfo::new("telegram", "Telegram"));

        let removed = registry.unregister("telegram");
        assert!(removed.is_some());
        assert_eq!(removed.unwrap().id, "telegram");

        assert!(registry.get("telegram").is_none());
    }

    #[test]
    fn test_registry_get_status() {
        let registry = ChannelRegistry::new();
        registry.register(
            ChannelInfo::new("telegram", "Telegram").with_status(ChannelStatus::Connected),
        );

        assert_eq!(
            registry.get_status("telegram"),
            Some(ChannelStatus::Connected)
        );
        assert_eq!(registry.get_status("nonexistent"), None);
    }

    #[test]
    fn test_registry_update_status() {
        let registry = ChannelRegistry::new();
        registry.register(ChannelInfo::new("telegram", "Telegram"));

        assert!(registry.update_status("telegram", ChannelStatus::Connected));
        assert_eq!(
            registry.get_status("telegram"),
            Some(ChannelStatus::Connected)
        );

        // Verify last_connected_at was set
        let info = registry.get("telegram").unwrap();
        assert!(info.metadata.last_connected_at.is_some());
        assert!(info.metadata.status_changed_at.is_some());
    }

    #[test]
    fn test_registry_set_error() {
        let registry = ChannelRegistry::new();
        registry.register(ChannelInfo::new("telegram", "Telegram"));

        assert!(registry.set_error("telegram", "Connection failed"));
        let info = registry.get("telegram").unwrap();
        assert_eq!(info.status, ChannelStatus::Error);
        assert_eq!(info.metadata.last_error, Some("Connection failed".into()));
    }

    #[test]
    fn test_registry_logout() {
        let registry = ChannelRegistry::new();
        registry.register(
            ChannelInfo::new("telegram", "Telegram").with_status(ChannelStatus::Connected),
        );

        assert!(registry.logout("telegram"));
        assert_eq!(
            registry.get_status("telegram"),
            Some(ChannelStatus::LoggedOut)
        );
    }

    #[test]
    fn test_registry_list() {
        let registry = ChannelRegistry::new();
        registry.register(ChannelInfo::new("telegram", "Telegram"));
        registry.register(ChannelInfo::new("discord", "Discord"));

        let list = registry.list();
        assert_eq!(list.len(), 2);
    }

    #[test]
    fn test_registry_snapshot() {
        let registry = ChannelRegistry::new();
        registry.register(ChannelInfo::new("telegram", "Telegram"));

        let snapshot = registry.snapshot();
        assert_eq!(snapshot.channels.len(), 1);
        assert!(snapshot.timestamp > 0);
    }

    #[test]
    fn test_registry_is_connected() {
        let registry = ChannelRegistry::new();
        registry.register(
            ChannelInfo::new("telegram", "Telegram").with_status(ChannelStatus::Connected),
        );
        registry.register(ChannelInfo::new("discord", "Discord"));

        assert!(registry.is_connected("telegram"));
        assert!(!registry.is_connected("discord"));
        assert!(!registry.is_connected("nonexistent"));
    }

    #[test]
    fn test_registry_count_by_status() {
        let registry = ChannelRegistry::new();
        registry.register(
            ChannelInfo::new("telegram", "Telegram").with_status(ChannelStatus::Connected),
        );
        registry
            .register(ChannelInfo::new("discord", "Discord").with_status(ChannelStatus::Connected));
        registry.register(ChannelInfo::new("slack", "Slack").with_status(ChannelStatus::Error));

        assert_eq!(registry.count_by_status(ChannelStatus::Connected), 2);
        assert_eq!(registry.count_by_status(ChannelStatus::Error), 1);
        assert_eq!(registry.count_by_status(ChannelStatus::Disconnected), 0);
    }

    #[test]
    fn test_registry_len_and_is_empty() {
        let registry = ChannelRegistry::new();
        assert!(registry.is_empty());
        assert_eq!(registry.len(), 0);

        registry.register(ChannelInfo::new("telegram", "Telegram"));
        assert!(!registry.is_empty());
        assert_eq!(registry.len(), 1);
    }

    #[test]
    fn test_registry_thread_safety() {
        use std::thread;

        let registry = Arc::new(ChannelRegistry::new());
        let mut handles = vec![];

        // Spawn multiple threads that register channels
        for i in 0..10 {
            let reg = Arc::clone(&registry);
            handles.push(thread::spawn(move || {
                reg.register(ChannelInfo::new(
                    format!("channel_{}", i),
                    format!("Channel {}", i),
                ));
            }));
        }

        for handle in handles {
            handle.join().unwrap();
        }

        assert_eq!(registry.len(), 10);
    }

    #[test]
    fn test_channel_info_serialization() {
        let info = ChannelInfo::new("telegram", "Telegram")
            .with_status(ChannelStatus::Connected)
            .with_metadata(ChannelMetadata {
                description: Some("Test channel".into()),
                ..Default::default()
            });

        let json = serde_json::to_string(&info).unwrap();
        let parsed: ChannelInfo = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.id, info.id);
        assert_eq!(parsed.name, info.name);
        assert_eq!(parsed.status, info.status);
    }

    #[test]
    fn test_registry_snapshot_serialization() {
        let registry = ChannelRegistry::new();
        registry.register(ChannelInfo::new("telegram", "Telegram"));

        let snapshot = registry.snapshot();
        let json = serde_json::to_string(&snapshot).unwrap();
        let parsed: RegistrySnapshot = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.channels.len(), 1);
        assert!(parsed.timestamp > 0);
    }
}
