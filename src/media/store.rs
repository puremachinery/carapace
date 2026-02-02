//! Media store with cleanup
//!
//! Provides temporary file storage for fetched media with:
//! - Configurable size limits per file
//! - TTL-based automatic cleanup
//! - Concurrent-safe operations
//! - Stored file metadata tracking

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use parking_lot::RwLock;
use thiserror::Error;
use tokio::fs;
use uuid::Uuid;

/// Default maximum file size (50MB)
pub const DEFAULT_MAX_FILE_SIZE: u64 = 50 * 1024 * 1024;

/// Default TTL for stored files (1 hour)
pub const DEFAULT_TTL_SECS: u64 = 3600;

/// Default cleanup interval (5 minutes)
pub const DEFAULT_CLEANUP_INTERVAL_SECS: u64 = 300;

/// Errors that can occur during media store operations
#[derive(Error, Debug, Clone)]
pub enum StoreError {
    #[error("File too large: {size} bytes (max {max})")]
    FileTooLarge { size: u64, max: u64 },

    #[error("File not found: {0}")]
    NotFound(String),

    #[error("IO error: {0}")]
    Io(String),

    #[error("Store not initialized")]
    NotInitialized,
}

/// Metadata for a stored media file
#[derive(Debug, Clone)]
pub struct MediaMetadata {
    /// Path to the stored file
    pub path: PathBuf,

    /// MIME type, if known
    pub mime_type: Option<String>,

    /// File size in bytes
    pub size: u64,

    /// When the file was stored
    pub created_at: DateTime<Utc>,
}

impl MediaMetadata {
    /// Check if this file has expired based on TTL
    pub fn is_expired(&self, ttl: Duration) -> bool {
        let now = Utc::now();
        let age = now.signed_duration_since(self.created_at);
        // Use milliseconds for more precision
        age.num_milliseconds() >= ttl.as_millis() as i64
    }
}

/// Configuration for the media store
#[derive(Debug, Clone)]
pub struct StoreConfig {
    /// Base directory for storing files
    pub base_dir: PathBuf,

    /// Maximum file size in bytes
    pub max_file_size: u64,

    /// Time-to-live for stored files
    pub ttl: Duration,

    /// Interval between cleanup runs
    pub cleanup_interval: Duration,
}

impl Default for StoreConfig {
    fn default() -> Self {
        Self {
            base_dir: std::env::temp_dir().join("carapace-media"),
            max_file_size: DEFAULT_MAX_FILE_SIZE,
            ttl: Duration::from_secs(DEFAULT_TTL_SECS),
            cleanup_interval: Duration::from_secs(DEFAULT_CLEANUP_INTERVAL_SECS),
        }
    }
}

impl StoreConfig {
    /// Create config with custom base directory
    pub fn with_base_dir(mut self, base_dir: PathBuf) -> Self {
        self.base_dir = base_dir;
        self
    }

    /// Create config with custom max file size
    pub fn with_max_file_size(mut self, max_file_size: u64) -> Self {
        self.max_file_size = max_file_size;
        self
    }

    /// Create config with custom TTL
    pub fn with_ttl(mut self, ttl: Duration) -> Self {
        self.ttl = ttl;
        self
    }

    /// Create config with custom cleanup interval
    pub fn with_cleanup_interval(mut self, interval: Duration) -> Self {
        self.cleanup_interval = interval;
        self
    }
}

/// Internal entry tracking stored files
#[derive(Debug, Clone)]
struct StoreEntry {
    metadata: MediaMetadata,
}

/// Concurrent-safe media store for temporary file storage
///
/// This store provides:
/// - Temporary file storage with automatic cleanup
/// - Size limit enforcement
/// - TTL-based expiration
/// - Thread-safe concurrent access
///
/// # Example
///
/// ```ignore
/// let store = MediaStore::new(StoreConfig::default()).await?;
///
/// // Store some bytes
/// let metadata = store.store(bytes, Some("image/png")).await?;
/// println!("Stored at: {:?}", metadata.path);
///
/// // Retrieve later
/// if let Some(metadata) = store.get(&metadata.path).await? {
///     println!("File size: {}", metadata.size);
/// }
///
/// // Run cleanup to remove expired files
/// let removed = store.cleanup().await?;
/// ```
pub struct MediaStore {
    config: StoreConfig,
    /// Map of file ID to store entry
    entries: Arc<RwLock<HashMap<String, StoreEntry>>>,
    /// Whether the store has been initialized
    initialized: bool,
}

impl MediaStore {
    /// Create a new MediaStore with the given configuration
    ///
    /// This will create the base directory if it doesn't exist.
    pub async fn new(config: StoreConfig) -> Result<Self, StoreError> {
        // Create base directory if it doesn't exist
        fs::create_dir_all(&config.base_dir)
            .await
            .map_err(|e| StoreError::Io(format!("Failed to create base directory: {}", e)))?;

        let store = Self {
            config,
            entries: Arc::new(RwLock::new(HashMap::new())),
            initialized: true,
        };

        store.load_existing_entries().await?;
        let _ = store.cleanup().await?;

        Ok(store)
    }

    /// Create a new MediaStore with default configuration
    pub async fn default_store() -> Result<Self, StoreError> {
        Self::new(StoreConfig::default()).await
    }

    /// Store bytes and return metadata
    ///
    /// # Arguments
    /// * `bytes` - The data to store
    /// * `mime_type` - Optional MIME type for the data
    ///
    /// # Returns
    /// Metadata for the stored file including path, size, and creation time
    pub async fn store(
        &self,
        bytes: Vec<u8>,
        mime_type: Option<String>,
    ) -> Result<MediaMetadata, StoreError> {
        if !self.initialized {
            return Err(StoreError::NotInitialized);
        }

        let size = bytes.len() as u64;

        // Check size limit
        if size > self.config.max_file_size {
            return Err(StoreError::FileTooLarge {
                size,
                max: self.config.max_file_size,
            });
        }

        // Generate unique file ID and path
        let file_id = Uuid::new_v4().to_string();
        let extension = mime_type_to_extension(mime_type.as_deref());
        let filename = format!("{}{}", file_id, extension);
        let path = self.config.base_dir.join(&filename);

        // Write file
        fs::write(&path, &bytes)
            .await
            .map_err(|e| StoreError::Io(format!("Failed to write file: {}", e)))?;

        let metadata = MediaMetadata {
            path: path.clone(),
            mime_type,
            size,
            created_at: Utc::now(),
        };

        // Track in entries
        {
            let mut entries = self.entries.write();
            entries.insert(
                file_id.clone(),
                StoreEntry {
                    metadata: metadata.clone(),
                },
            );
        }

        tracing::debug!(
            file_id = %file_id,
            path = %path.display(),
            size = size,
            "Stored media file"
        );

        Ok(metadata)
    }

    /// Store bytes from a slice
    pub async fn store_bytes(
        &self,
        bytes: &[u8],
        mime_type: Option<String>,
    ) -> Result<MediaMetadata, StoreError> {
        self.store(bytes.to_vec(), mime_type).await
    }

    /// Get metadata for a stored file by path
    ///
    /// Returns None if the file is not tracked or has been cleaned up.
    pub async fn get(&self, path: &Path) -> Result<Option<MediaMetadata>, StoreError> {
        if !self.initialized {
            return Err(StoreError::NotInitialized);
        }

        // Find entry by path
        let entries = self.entries.read();
        for entry in entries.values() {
            if entry.metadata.path == path {
                // Check if file still exists
                if path.exists() {
                    return Ok(Some(entry.metadata.clone()));
                } else {
                    return Ok(None);
                }
            }
        }

        Ok(None)
    }

    /// Get metadata for a stored file by ID
    pub async fn get_by_id(&self, file_id: &str) -> Result<Option<MediaMetadata>, StoreError> {
        if !self.initialized {
            return Err(StoreError::NotInitialized);
        }

        let entries = self.entries.read();
        if let Some(entry) = entries.get(file_id) {
            if entry.metadata.path.exists() {
                return Ok(Some(entry.metadata.clone()));
            }
        }

        Ok(None)
    }

    /// Remove a specific file from the store
    pub async fn remove(&self, path: &Path) -> Result<bool, StoreError> {
        if !self.initialized {
            return Err(StoreError::NotInitialized);
        }

        // Find and remove the entry
        let file_id = {
            let entries = self.entries.read();
            entries
                .iter()
                .find(|(_, e)| e.metadata.path == path)
                .map(|(id, _)| id.clone())
        };

        if let Some(id) = file_id {
            // Remove from tracking
            {
                let mut entries = self.entries.write();
                entries.remove(&id);
            }

            // Delete file and sidecar cache
            if path.exists() {
                fs::remove_file(path)
                    .await
                    .map_err(|e| StoreError::Io(format!("Failed to remove file: {}", e)))?;
            }
            let sidecar = analysis_cache_path(path);
            if sidecar.exists() {
                fs::remove_file(&sidecar)
                    .await
                    .map_err(|e| StoreError::Io(format!("Failed to remove sidecar: {}", e)))?;
            }

            tracing::debug!(path = %path.display(), "Removed media file");
            return Ok(true);
        }

        Ok(false)
    }

    /// Remove a file by ID
    pub async fn remove_by_id(&self, file_id: &str) -> Result<bool, StoreError> {
        if !self.initialized {
            return Err(StoreError::NotInitialized);
        }

        let path = {
            let entries = self.entries.read();
            entries.get(file_id).map(|e| e.metadata.path.clone())
        };

        if let Some(path) = path {
            return self.remove(&path).await;
        }

        Ok(false)
    }

    /// Run cleanup to remove expired files
    ///
    /// Returns the number of files removed.
    pub async fn cleanup(&self) -> Result<usize, StoreError> {
        if !self.initialized {
            return Err(StoreError::NotInitialized);
        }

        let ttl = self.config.ttl;
        let to_remove = self.collect_expired_entries(ttl);

        let count = to_remove.len();
        self.remove_expired_entries(to_remove).await;

        if count > 0 {
            tracing::info!(count = count, "Cleaned up expired media files");
        }

        Ok(count)
    }

    /// Collect IDs and paths of entries whose TTL has elapsed.
    fn collect_expired_entries(&self, ttl: std::time::Duration) -> Vec<(String, PathBuf)> {
        let entries = self.entries.read();
        entries
            .iter()
            .filter(|(_, entry)| entry.metadata.is_expired(ttl))
            .map(|(id, entry)| (id.clone(), entry.metadata.path.clone()))
            .collect()
    }

    /// Remove the given entries from tracking and delete their files from disk.
    async fn remove_expired_entries(&self, to_remove: Vec<(String, PathBuf)>) {
        for (id, path) in to_remove {
            {
                let mut entries = self.entries.write();
                entries.remove(&id);
            }

            if path.exists() {
                if let Err(e) = fs::remove_file(&path).await {
                    tracing::warn!(
                        path = %path.display(),
                        error = %e,
                        "Failed to remove expired media file"
                    );
                } else {
                    tracing::debug!(
                        path = %path.display(),
                        "Removed expired media file"
                    );
                }
            }
            let sidecar = analysis_cache_path(&path);
            if sidecar.exists() {
                if let Err(e) = fs::remove_file(&sidecar).await {
                    tracing::warn!(
                        path = %sidecar.display(),
                        error = %e,
                        "Failed to remove expired media sidecar"
                    );
                }
            }
        }
    }

    /// Get the number of tracked files
    pub fn file_count(&self) -> usize {
        self.entries.read().len()
    }

    /// Get total size of tracked files
    pub fn total_size(&self) -> u64 {
        self.entries.read().values().map(|e| e.metadata.size).sum()
    }

    /// Get the store configuration
    pub fn config(&self) -> &StoreConfig {
        &self.config
    }

    /// List all tracked files
    pub fn list(&self) -> Vec<MediaMetadata> {
        self.entries
            .read()
            .values()
            .map(|e| e.metadata.clone())
            .collect()
    }

    /// Start a background cleanup task
    ///
    /// This spawns a tokio task that periodically runs cleanup.
    /// Returns a handle that can be used to abort the task.
    pub fn start_cleanup_task(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        let interval = self.config.cleanup_interval;

        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            loop {
                ticker.tick().await;

                if let Err(e) = self.cleanup().await {
                    tracing::error!(error = %e, "Media store cleanup failed");
                }
            }
        })
    }
}

impl MediaStore {
    async fn load_existing_entries(&self) -> Result<(), StoreError> {
        let mut dir = fs::read_dir(&self.config.base_dir)
            .await
            .map_err(|e| StoreError::Io(format!("Failed to read base directory: {}", e)))?;

        while let Some(entry) = dir
            .next_entry()
            .await
            .map_err(|e| StoreError::Io(format!("Failed to read directory entry: {}", e)))?
        {
            let path = entry.path();
            if is_analysis_sidecar(&path) {
                continue;
            }

            let file_type = match entry.file_type().await {
                Ok(ft) => ft,
                Err(e) => {
                    tracing::warn!(
                        path = %path.display(),
                        error = %e,
                        "Failed to read media file type"
                    );
                    continue;
                }
            };
            if file_type.is_dir() {
                continue;
            }

            let metadata = match entry.metadata().await {
                Ok(meta) => meta,
                Err(e) => {
                    tracing::warn!(
                        path = %path.display(),
                        error = %e,
                        "Failed to read media file metadata"
                    );
                    continue;
                }
            };

            let created_at = metadata
                .modified()
                .map(DateTime::<Utc>::from)
                .unwrap_or_else(|_| Utc::now());
            let size = metadata.len();
            let file_id = path
                .file_stem()
                .or_else(|| path.file_name())
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_else(|| Uuid::new_v4().to_string());

            let metadata = MediaMetadata {
                path: path.clone(),
                mime_type: None,
                size,
                created_at,
            };

            let mut entries = self.entries.write();
            entries.insert(file_id, StoreEntry { metadata });
        }

        Ok(())
    }
}

/// Convert MIME type to file extension
fn mime_type_to_extension(mime_type: Option<&str>) -> &'static str {
    match mime_type {
        Some(mime) => {
            // Extract the subtype after the slash
            let subtype = mime.split('/').nth(1).unwrap_or("");
            // Remove any parameters (e.g., "jpeg; charset=utf-8" -> "jpeg")
            let subtype = subtype.split(';').next().unwrap_or("").trim();

            match subtype {
                // Images
                "jpeg" | "jpg" => ".jpg",
                "png" => ".png",
                "gif" => ".gif",
                "webp" => ".webp",
                "svg+xml" => ".svg",
                "bmp" => ".bmp",
                "tiff" => ".tiff",
                "ico" | "x-icon" => ".ico",

                // Audio
                "mpeg" if mime.starts_with("audio") => ".mp3",
                "mp3" => ".mp3",
                "wav" | "x-wav" => ".wav",
                "ogg" if mime.starts_with("audio") => ".ogg",
                "flac" => ".flac",
                "aac" => ".aac",
                "webm" if mime.starts_with("audio") => ".weba",
                "m4a" | "x-m4a" => ".m4a",

                // Video
                "mp4" => ".mp4",
                "webm" => ".webm",
                "ogg" => ".ogv",
                "quicktime" => ".mov",
                "x-msvideo" => ".avi",
                "x-matroska" => ".mkv",

                // Documents
                "pdf" => ".pdf",
                "json" => ".json",
                "xml" => ".xml",
                "html" => ".html",
                "plain" => ".txt",
                "css" => ".css",
                "javascript" => ".js",
                "x-javascript" => ".js",

                // Archives
                "zip" => ".zip",
                "x-tar" => ".tar",
                "gzip" | "x-gzip" => ".gz",
                "x-bzip2" => ".bz2",
                "x-7z-compressed" => ".7z",

                // Fallback
                _ => ".bin",
            }
        }
        None => ".bin",
    }
}

fn analysis_cache_path(media_path: &Path) -> PathBuf {
    let mut cache_path = media_path.as_os_str().to_owned();
    cache_path.push(".analysis.json");
    PathBuf::from(cache_path)
}

fn is_analysis_sidecar(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .map(|name| name.ends_with(".analysis.json"))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    async fn create_test_store() -> (MediaStore, tempfile::TempDir) {
        let temp_dir = tempdir().unwrap();
        let config = StoreConfig::default()
            .with_base_dir(temp_dir.path().to_path_buf())
            .with_ttl(Duration::from_secs(1)); // Short TTL for testing

        let store = MediaStore::new(config).await.unwrap();
        (store, temp_dir)
    }

    #[tokio::test]
    async fn test_store_and_get() {
        let (store, _temp_dir) = create_test_store().await;

        let bytes = b"Hello, world!".to_vec();
        let metadata = store
            .store(bytes.clone(), Some("text/plain".to_string()))
            .await
            .unwrap();

        assert_eq!(metadata.size, 13);
        assert_eq!(metadata.mime_type, Some("text/plain".to_string()));
        assert!(metadata.path.exists());

        // Read back
        let contents = fs::read(&metadata.path).await.unwrap();
        assert_eq!(contents, bytes);

        // Get metadata
        let retrieved = store.get(&metadata.path).await.unwrap();
        assert!(retrieved.is_some());
        let retrieved = retrieved.unwrap();
        assert_eq!(retrieved.size, 13);
    }

    #[tokio::test]
    async fn test_store_bytes() {
        let (store, _temp_dir) = create_test_store().await;

        let bytes = b"Test data";
        let metadata = store.store_bytes(bytes, None).await.unwrap();

        assert_eq!(metadata.size, 9);
        assert_eq!(metadata.mime_type, None);
        assert!(metadata.path.exists());
    }

    #[tokio::test]
    async fn test_file_too_large() {
        let temp_dir = tempdir().unwrap();
        let config = StoreConfig::default()
            .with_base_dir(temp_dir.path().to_path_buf())
            .with_max_file_size(10); // Very small limit

        let store = MediaStore::new(config).await.unwrap();

        let bytes = vec![0u8; 100]; // Larger than limit
        let result = store.store(bytes, None).await;

        assert!(matches!(
            result,
            Err(StoreError::FileTooLarge { size: 100, max: 10 })
        ));
    }

    #[tokio::test]
    async fn test_remove_file() {
        let (store, _temp_dir) = create_test_store().await;

        let metadata = store.store(b"test".to_vec(), None).await.unwrap();
        assert!(metadata.path.exists());

        let removed = store.remove(&metadata.path).await.unwrap();
        assert!(removed);
        assert!(!metadata.path.exists());

        // Second remove should return false
        let removed = store.remove(&metadata.path).await.unwrap();
        assert!(!removed);
    }

    #[tokio::test]
    async fn test_cleanup_expired() {
        let (store, _temp_dir) = create_test_store().await;

        // Store a file
        let metadata = store.store(b"test".to_vec(), None).await.unwrap();
        assert!(metadata.path.exists());
        assert_eq!(store.file_count(), 1);

        // Wait for TTL to expire (1 second + buffer)
        tokio::time::sleep(Duration::from_millis(1500)).await;

        // Run cleanup
        let removed = store.cleanup().await.unwrap();
        assert_eq!(removed, 1);
        assert_eq!(store.file_count(), 0);
        assert!(!metadata.path.exists());
    }

    #[tokio::test]
    async fn test_cleanup_removes_sidecar() {
        let (store, _temp_dir) = create_test_store().await;

        let metadata = store.store(b"test".to_vec(), None).await.unwrap();
        let sidecar = analysis_cache_path(&metadata.path);
        fs::write(&sidecar, b"{}").await.unwrap();
        assert!(sidecar.exists());

        tokio::time::sleep(Duration::from_millis(1500)).await;

        let removed = store.cleanup().await.unwrap();
        assert_eq!(removed, 1);
        assert!(!sidecar.exists());
    }

    #[tokio::test]
    async fn test_cleanup_keeps_fresh_files() {
        let temp_dir = tempdir().unwrap();
        let config = StoreConfig::default()
            .with_base_dir(temp_dir.path().to_path_buf())
            .with_ttl(Duration::from_secs(3600)); // Long TTL

        let store = MediaStore::new(config).await.unwrap();

        let metadata = store.store(b"test".to_vec(), None).await.unwrap();
        assert!(metadata.path.exists());

        // Run cleanup immediately
        let removed = store.cleanup().await.unwrap();
        assert_eq!(removed, 0);
        assert_eq!(store.file_count(), 1);
        assert!(metadata.path.exists());
    }

    #[tokio::test]
    async fn test_file_count_and_total_size() {
        let (store, _temp_dir) = create_test_store().await;

        assert_eq!(store.file_count(), 0);
        assert_eq!(store.total_size(), 0);

        store.store(b"12345".to_vec(), None).await.unwrap();
        store.store(b"67890".to_vec(), None).await.unwrap();

        assert_eq!(store.file_count(), 2);
        assert_eq!(store.total_size(), 10);
    }

    #[tokio::test]
    async fn test_load_existing_entries_on_startup() {
        let temp_dir = tempdir().unwrap();
        let file_path = temp_dir.path().join("existing.bin");
        fs::write(&file_path, b"data").await.unwrap();

        let config = StoreConfig::default()
            .with_base_dir(temp_dir.path().to_path_buf())
            .with_ttl(Duration::from_secs(3600));
        let store = MediaStore::new(config).await.unwrap();

        assert_eq!(store.file_count(), 1);
        let found = store.get(&file_path).await.unwrap();
        assert!(found.is_some());
    }

    #[tokio::test]
    async fn test_list_files() {
        let (store, _temp_dir) = create_test_store().await;

        store
            .store(b"test1".to_vec(), Some("text/plain".to_string()))
            .await
            .unwrap();
        store
            .store(b"test2".to_vec(), Some("image/png".to_string()))
            .await
            .unwrap();

        let files = store.list();
        assert_eq!(files.len(), 2);
    }

    #[test]
    fn test_mime_type_to_extension() {
        assert_eq!(mime_type_to_extension(Some("image/jpeg")), ".jpg");
        assert_eq!(mime_type_to_extension(Some("image/png")), ".png");
        assert_eq!(mime_type_to_extension(Some("audio/mpeg")), ".mp3");
        assert_eq!(mime_type_to_extension(Some("video/mp4")), ".mp4");
        assert_eq!(mime_type_to_extension(Some("application/pdf")), ".pdf");
        assert_eq!(mime_type_to_extension(Some("text/plain")), ".txt");
        assert_eq!(mime_type_to_extension(Some("application/json")), ".json");
        assert_eq!(mime_type_to_extension(Some("application/unknown")), ".bin");
        assert_eq!(mime_type_to_extension(None), ".bin");

        // With parameters
        assert_eq!(
            mime_type_to_extension(Some("text/plain; charset=utf-8")),
            ".txt"
        );
    }

    #[test]
    fn test_media_metadata_is_expired() {
        let metadata = MediaMetadata {
            path: PathBuf::from("/tmp/test"),
            mime_type: None,
            size: 100,
            created_at: Utc::now() - chrono::Duration::seconds(120),
        };

        // Should be expired with 60s TTL
        assert!(metadata.is_expired(Duration::from_secs(60)));

        // Should not be expired with 300s TTL
        assert!(!metadata.is_expired(Duration::from_secs(300)));
    }

    #[test]
    fn test_store_config_builder() {
        let config = StoreConfig::default()
            .with_base_dir(PathBuf::from("/custom/path"))
            .with_max_file_size(100 * 1024 * 1024)
            .with_ttl(Duration::from_secs(7200))
            .with_cleanup_interval(Duration::from_secs(600));

        assert_eq!(config.base_dir, PathBuf::from("/custom/path"));
        assert_eq!(config.max_file_size, 100 * 1024 * 1024);
        assert_eq!(config.ttl, Duration::from_secs(7200));
        assert_eq!(config.cleanup_interval, Duration::from_secs(600));
    }
}
