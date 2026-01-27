//! Media pipeline module
//!
//! Provides media fetching and storage with security protections:
//!
//! - **MediaFetcher**: HTTP/HTTPS media fetching with comprehensive SSRF protection
//!   - Blocks private IP ranges, localhost, cloud metadata endpoints
//!   - DNS resolution with IP validation and pinning (prevents DNS rebinding)
//!   - Redirects disabled (prevents redirect-based SSRF bypass)
//!   - Streaming with size limits
//!
//! - **MediaStore**: Temporary file storage with automatic cleanup
//!   - Configurable size limits per file
//!   - TTL-based expiration
//!   - Concurrent-safe operations
//!   - Background cleanup task
//!
//! # Example
//!
//! ```ignore
//! use carapace::media::{MediaFetcher, MediaStore, FetchConfig, StoreConfig};
//!
//! // Fetch media with SSRF protection
//! let fetcher = MediaFetcher::new();
//! let result = fetcher.fetch("https://example.com/image.png").await?;
//!
//! // Store the fetched media
//! let store = MediaStore::new(StoreConfig::default()).await?;
//! let metadata = store.store(result.bytes, result.content_type).await?;
//!
//! println!("Stored at: {:?}, size: {}", metadata.path, metadata.size);
//!
//! // Cleanup expired files
//! let removed = store.cleanup().await?;
//! ```

pub mod fetch;
pub mod store;

// Re-export commonly used types
pub use fetch::{
    FetchConfig, FetchError, FetchResult, MediaFetcher, DEFAULT_FETCH_TIMEOUT_MS, DEFAULT_MAX_SIZE,
    MAX_FETCH_TIMEOUT_MS, MAX_URL_LENGTH,
};
pub use store::{
    MediaMetadata, MediaStore, StoreConfig, StoreError, DEFAULT_CLEANUP_INTERVAL_SECS,
    DEFAULT_MAX_FILE_SIZE, DEFAULT_TTL_SECS,
};
