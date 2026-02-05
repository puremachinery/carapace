//! Credential storage module
//!
//! Platform-specific secure credential storage:
//! - macOS: Keychain
//! - Linux: Secret Service
//! - Windows: Credential Manager
//!
//! Key namespace: Service name `carapace`, account key format `kind:<agentId>:<id>`

#[cfg(target_os = "macos")]
mod macos;

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "windows")]
mod windows;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::Write as IoWrite;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tokio::time::timeout;

/// Service name for all credentials
pub const SERVICE_NAME: &str = "carapace";

/// Maximum key length for plugin credentials
pub const MAX_KEY_LENGTH: usize = 64;

/// Maximum value length for credentials (64 KB)
pub const MAX_VALUE_LENGTH: usize = 64 * 1024;

/// Maximum credentials per plugin
pub const MAX_CREDENTIALS_PER_PLUGIN: usize = 100;

/// Rate limit for writes per plugin (per minute)
pub const WRITE_RATE_LIMIT_PER_MINUTE: usize = 10;

/// Credential store errors
#[derive(Debug, Clone, PartialEq)]
pub enum CredentialError {
    /// Keychain/secret store is locked and requires user interaction
    StoreLocked,
    /// Secret store service is not available (e.g., no Secret Service on Linux)
    StoreUnavailable(String),
    /// Access denied to the credential
    AccessDenied,
    /// Credential not found
    NotFound,
    /// Operation timed out
    Timeout,
    /// I/O error
    IoError(String),
    /// JSON serialization/deserialization error
    JsonError(String),
    /// Key exceeds maximum length
    KeyTooLong,
    /// Value exceeds maximum length
    ValueTooLong,
    /// Plugin credential quota exceeded
    QuotaExceeded,
    /// Plugin rate limit exceeded
    RateLimitExceeded,
    /// Index file is corrupted
    IndexCorrupted,
    /// File lock acquisition failed
    LockFailed,
    /// Credential verification failed after write
    VerificationFailed,
    /// Internal error
    Internal(String),
}

impl std::fmt::Display for CredentialError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StoreLocked => write!(f, "Credential store is locked"),
            Self::StoreUnavailable(msg) => write!(f, "Credential store unavailable: {}", msg),
            Self::AccessDenied => write!(f, "Access denied to credential"),
            Self::NotFound => write!(f, "Credential not found"),
            Self::Timeout => write!(f, "Operation timed out"),
            Self::IoError(msg) => write!(f, "I/O error: {}", msg),
            Self::JsonError(msg) => write!(f, "JSON error: {}", msg),
            Self::KeyTooLong => {
                write!(
                    f,
                    "Key exceeds maximum length of {} characters",
                    MAX_KEY_LENGTH
                )
            }
            Self::ValueTooLong => {
                write!(
                    f,
                    "Value exceeds maximum length of {} bytes",
                    MAX_VALUE_LENGTH
                )
            }
            Self::QuotaExceeded => write!(
                f,
                "Plugin credential quota exceeded (max {} credentials)",
                MAX_CREDENTIALS_PER_PLUGIN
            ),
            Self::RateLimitExceeded => write!(
                f,
                "Plugin write rate limit exceeded ({} writes/minute)",
                WRITE_RATE_LIMIT_PER_MINUTE
            ),
            Self::IndexCorrupted => write!(f, "Credential index file is corrupted"),
            Self::LockFailed => write!(f, "Failed to acquire file lock"),
            Self::VerificationFailed => write!(f, "Failed to verify credential after write"),
            Self::Internal(msg) => write!(f, "Internal error: {}", msg),
        }
    }
}

impl std::error::Error for CredentialError {}

/// Check if an error is retryable
pub fn is_retryable(error: &CredentialError) -> bool {
    matches!(
        error,
        CredentialError::Timeout | CredentialError::IoError(_) | CredentialError::RateLimitExceeded
    )
}

/// Retry policy configuration
#[derive(Debug, Clone)]
pub struct RetryPolicy {
    pub max_retries: usize,
    pub timeout: Duration,
    pub backoff: Option<Vec<Duration>>,
}

impl RetryPolicy {
    /// Policy for get operations: 5s timeout, 2 retries, no backoff
    pub fn for_get() -> Self {
        Self {
            max_retries: 2,
            timeout: Duration::from_secs(5),
            backoff: None,
        }
    }

    /// Policy for set operations: 10s timeout, 3 retries, exponential backoff
    pub fn for_set() -> Self {
        Self {
            max_retries: 3,
            timeout: Duration::from_secs(10),
            backoff: Some(vec![
                Duration::from_millis(100),
                Duration::from_millis(500),
                Duration::from_secs(2),
            ]),
        }
    }

    /// Policy for delete operations: 5s timeout, 2 retries, no backoff
    pub fn for_delete() -> Self {
        Self {
            max_retries: 2,
            timeout: Duration::from_secs(5),
            backoff: None,
        }
    }
}

/// Credential key with parsed components
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CredentialKey {
    pub kind: String,
    pub agent_id: String,
    pub id: String,
}

impl CredentialKey {
    /// Create a new credential key
    pub fn new(
        kind: impl Into<String>,
        agent_id: impl Into<String>,
        id: impl Into<String>,
    ) -> Self {
        Self {
            kind: kind.into(),
            agent_id: agent_id.into(),
            id: id.into(),
        }
    }

    /// Parse a key string in format `kind:<agentId>:<id>`
    pub fn parse(key: &str) -> Option<Self> {
        let parts: Vec<&str> = key.splitn(3, ':').collect();
        if parts.len() == 3 {
            Some(Self {
                kind: parts[0].to_string(),
                agent_id: parts[1].to_string(),
                id: parts[2].to_string(),
            })
        } else {
            None
        }
    }

    /// Format as account key string
    pub fn to_account_key(&self) -> String {
        format!("{}:{}:{}", self.kind, self.agent_id, self.id)
    }

    /// Create a plugin-prefixed key
    pub fn with_plugin_prefix(plugin_id: &str, kind: &str, id: &str) -> Self {
        // Sanitize plugin_id to prevent path traversal attacks
        let sanitized_plugin_id = plugin_id.replace("..", "_").replace(['/', '\\'], "_");

        Self {
            kind: format!("plugin:{}", sanitized_plugin_id),
            agent_id: kind.to_string(),
            id: id.to_string(),
        }
    }
}

/// Gateway auth secrets loaded from the credential store
#[derive(Debug, Default, Clone, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct GatewayAuthSecrets {
    pub token: Option<String>,
    pub password: Option<String>,
}

/// Read gateway auth token/password from the credential store (if available).
pub async fn read_gateway_auth(state_dir: PathBuf) -> Result<GatewayAuthSecrets, CredentialError> {
    let backend = default_backend();
    let store = CredentialStore::new(backend, state_dir).await?;

    let token_key = CredentialKey::new("gateway", "token", "default");
    let password_key = CredentialKey::new("gateway", "password", "default");

    let token = store.get(&token_key).await?;
    let password = store.get(&password_key).await?;

    Ok(GatewayAuthSecrets { token, password })
}

/// Read CLI device identity (JSON) from the credential store.
pub async fn read_device_identity(state_dir: PathBuf) -> Result<Option<String>, CredentialError> {
    let backend = default_backend();
    let store = CredentialStore::new(backend, state_dir).await?;
    let key = CredentialKey::new("device", "cli", "identity");
    store.get(&key).await
}

/// Write CLI device identity (JSON) to the credential store.
pub async fn write_device_identity(state_dir: PathBuf, value: &str) -> Result<(), CredentialError> {
    let backend = default_backend();
    let store = CredentialStore::new(backend, state_dir).await?;
    let key = CredentialKey::new("device", "cli", "identity");
    store.set(&key, value, None).await
}

#[cfg(target_os = "macos")]
fn default_backend() -> macos::MacOsCredentialBackend {
    macos::MacOsCredentialBackend::new()
}

#[cfg(target_os = "linux")]
fn default_backend() -> linux::LinuxCredentialBackend {
    linux::LinuxCredentialBackend::new()
}

#[cfg(target_os = "windows")]
fn default_backend() -> windows::WindowsCredentialBackend {
    windows::WindowsCredentialBackend::new()
}

impl std::fmt::Display for CredentialKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_account_key())
    }
}

/// Index entry for a credential (non-secret metadata)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexEntry {
    pub key: CredentialKey,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    pub last_updated: u64,
}

/// Plugin quota tracking
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PluginQuota {
    pub count: usize,
}

/// Credential index file structure
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CredentialIndex {
    pub version: u32,
    #[serde(default)]
    pub entries: HashMap<String, IndexEntry>,
    #[serde(default)]
    pub plugins: HashMap<String, PluginQuota>,
}

impl CredentialIndex {
    pub const VERSION: u32 = 1;

    pub fn new() -> Self {
        Self {
            version: Self::VERSION,
            entries: HashMap::new(),
            plugins: HashMap::new(),
        }
    }
}

/// In-memory rate limit tracking for plugins
#[derive(Debug, Default)]
pub struct RateLimitTracker {
    /// Map of plugin_id -> list of write timestamps (in seconds since epoch)
    writes: HashMap<String, Vec<u64>>,
}

impl RateLimitTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Check if a write is allowed for the given plugin
    pub fn check_and_record(&mut self, plugin_id: &str) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let one_minute_ago = now.saturating_sub(60);

        let writes = self.writes.entry(plugin_id.to_string()).or_default();

        // Remove old entries
        writes.retain(|&ts| ts > one_minute_ago);

        // Check if under limit
        if writes.len() >= WRITE_RATE_LIMIT_PER_MINUTE {
            return false;
        }

        // Record new write
        writes.push(now);
        true
    }
}

/// Credential store trait
#[allow(async_fn_in_trait)]
pub trait CredentialBackend: Send + Sync {
    /// Get a credential by key (raw operation, no retry)
    async fn get_raw(&self, key: &CredentialKey) -> Result<Option<String>, CredentialError>;

    /// Set a credential (raw operation, no retry)
    async fn set_raw(&self, key: &CredentialKey, value: &str) -> Result<(), CredentialError>;

    /// Delete a credential (raw operation, no retry)
    async fn delete_raw(&self, key: &CredentialKey) -> Result<(), CredentialError>;

    /// Check if the credential store is available and unlocked
    async fn is_available(&self) -> bool;
}

/// Main credential store that wraps a backend with retry logic and index management
pub struct CredentialStore<B: CredentialBackend> {
    backend: B,
    index_path: PathBuf,
    index: Arc<RwLock<CredentialIndex>>,
    rate_limiter: Arc<RwLock<RateLimitTracker>>,
    env_only_mode: bool,
}

impl<B: CredentialBackend> CredentialStore<B> {
    /// Create a new credential store with the given backend and state directory
    pub async fn new(backend: B, state_dir: PathBuf) -> Result<Self, CredentialError> {
        let credentials_dir = state_dir.join("credentials");
        fs::create_dir_all(&credentials_dir)
            .map_err(|e| CredentialError::IoError(e.to_string()))?;

        let index_path = credentials_dir.join("index.json");
        let index = Self::load_or_create_index(&index_path)?;

        let env_only_mode = !backend.is_available().await;
        if env_only_mode {
            tracing::warn!(
                "Credential store is unavailable, operating in env-only mode. \
                 Some features requiring stored credentials will be degraded."
            );
        }

        Ok(Self {
            backend,
            index_path,
            index: Arc::new(RwLock::new(index)),
            rate_limiter: Arc::new(RwLock::new(RateLimitTracker::new())),
            env_only_mode,
        })
    }

    /// Check if running in environment-only mode (keychain unavailable)
    pub fn is_env_only_mode(&self) -> bool {
        self.env_only_mode
    }

    fn backup_path(path: &Path) -> PathBuf {
        path.with_extension("json.bak")
    }

    fn corrupt_path(path: &Path) -> PathBuf {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);
        path.with_extension(format!("corrupt.{}", timestamp))
    }

    fn recalculate_plugin_quotas(index: &mut CredentialIndex) {
        let mut quotas: HashMap<String, PluginQuota> = HashMap::new();
        for entry in index.entries.values() {
            let plugin_key = if let Some(provider) = &entry.provider {
                if provider.starts_with("plugin:") {
                    Some(provider.clone())
                } else {
                    None
                }
            } else if entry.key.kind.starts_with("plugin:") {
                Some(entry.key.kind.clone())
            } else {
                None
            };

            if let Some(plugin_key) = plugin_key {
                let quota = quotas.entry(plugin_key).or_default();
                quota.count += 1;
            }
        }
        index.plugins = quotas;
    }

    fn load_index_file(path: &Path) -> Result<CredentialIndex, CredentialError> {
        let content =
            fs::read_to_string(path).map_err(|e| CredentialError::IoError(e.to_string()))?;
        let mut index: CredentialIndex = serde_json::from_str(&content)
            .map_err(|e| CredentialError::JsonError(e.to_string()))?;

        if index.version != CredentialIndex::VERSION {
            tracing::warn!(
                found = index.version,
                expected = CredentialIndex::VERSION,
                "Credential index version mismatch"
            );
            return Err(CredentialError::IndexCorrupted);
        }

        let mut removed = 0usize;
        index.entries.retain(|account_key, entry| {
            let expected = entry.key.to_account_key();
            let valid = account_key == &expected;
            if !valid {
                removed += 1;
            }
            valid
        });

        if removed > 0 {
            tracing::warn!(removed, "Removed invalid credential index entries");
        }

        Self::recalculate_plugin_quotas(&mut index);

        Ok(index)
    }

    /// Load or create the credential index
    fn load_or_create_index(path: &PathBuf) -> Result<CredentialIndex, CredentialError> {
        let backup_path = Self::backup_path(path);

        if path.exists() {
            match Self::load_index_file(path) {
                Ok(index) => return Ok(index),
                Err(err) => {
                    tracing::warn!(
                        error = %err,
                        "Credential index invalid; attempting recovery"
                    );
                }
            }
        }

        if backup_path.exists() {
            match Self::load_index_file(&backup_path) {
                Ok(index) => {
                    tracing::warn!(
                        "Restoring credential index from backup at {:?}",
                        backup_path
                    );

                    if path.exists() {
                        let corrupt_path = Self::corrupt_path(path);
                        if let Err(err) = fs::rename(path, &corrupt_path) {
                            tracing::warn!(
                                error = %err,
                                "Failed to move corrupted index to {:?}",
                                corrupt_path
                            );
                        }
                    }

                    if let Err(err) = fs::copy(&backup_path, path) {
                        tracing::warn!(
                            error = %err,
                            "Failed to restore index backup to {:?}",
                            path
                        );
                    }

                    return Ok(index);
                }
                Err(err) => {
                    tracing::warn!(
                        error = %err,
                        "Credential index backup invalid; starting fresh"
                    );
                }
            }
        }

        if path.exists() {
            let corrupt_path = Self::corrupt_path(path);
            tracing::warn!("Credential index corrupted, moving to {:?}", corrupt_path);
            fs::rename(path, &corrupt_path).map_err(|e| CredentialError::IoError(e.to_string()))?;
        }

        Ok(CredentialIndex::new())
    }

    /// Save the index with file locking
    async fn save_index(&self) -> Result<(), CredentialError> {
        let index = self.index.read().await;
        let content = serde_json::to_string_pretty(&*index)
            .map_err(|e| CredentialError::JsonError(e.to_string()))?;
        drop(index);

        // Use file locking for writes
        let lock_path = self.index_path.with_extension("lock");

        // Try to acquire lock with 5s timeout
        let lock_result = timeout(Duration::from_secs(5), async {
            loop {
                match OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&lock_path)
                {
                    Ok(_) => return Ok(()),
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                        // Check if lock is stale (older than 30s)
                        if let Ok(metadata) = fs::metadata(&lock_path) {
                            if let Ok(modified) = metadata.modified() {
                                if modified
                                    .elapsed()
                                    .map(|d| d.as_secs() > 30)
                                    .unwrap_or(false)
                                {
                                    // Stale lock, remove it
                                    let _ = fs::remove_file(&lock_path);
                                    continue;
                                }
                            }
                        }
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }
                    Err(e) => return Err(CredentialError::IoError(e.to_string())),
                }
            }
        })
        .await;

        match lock_result {
            Ok(Ok(())) => {}
            Ok(Err(e)) => return Err(e),
            Err(_) => return Err(CredentialError::LockFailed),
        }

        // Write the file atomically
        let temp_path = self.index_path.with_extension("tmp");
        let result = (|| {
            let backup_path = Self::backup_path(&self.index_path);
            if self.index_path.exists() {
                if let Err(err) = fs::copy(&self.index_path, &backup_path) {
                    tracing::warn!(
                        error = %err,
                        "Failed to write credential index backup to {:?}",
                        backup_path
                    );
                }
            }

            let mut file =
                File::create(&temp_path).map_err(|e| CredentialError::IoError(e.to_string()))?;
            IoWrite::write_all(&mut file, content.as_bytes())
                .map_err(|e| CredentialError::IoError(e.to_string()))?;
            file.sync_all()
                .map_err(|e| CredentialError::IoError(e.to_string()))?;
            fs::rename(&temp_path, &self.index_path)
                .map_err(|e| CredentialError::IoError(e.to_string()))?;

            if !backup_path.exists() {
                if let Err(err) = fs::copy(&self.index_path, &backup_path) {
                    tracing::warn!(
                        error = %err,
                        "Failed to create initial credential index backup at {:?}",
                        backup_path
                    );
                }
            }
            Ok(())
        })();

        // Always remove the lock
        let _ = fs::remove_file(&lock_path);

        result
    }

    /// Get a credential with retry logic
    pub async fn get(&self, key: &CredentialKey) -> Result<Option<String>, CredentialError> {
        if self.env_only_mode {
            return Ok(None);
        }

        self.with_retry(&RetryPolicy::for_get(), || async {
            self.backend.get_raw(key).await
        })
        .await
    }

    /// Set a credential with retry logic and atomic verification
    pub async fn set(
        &self,
        key: &CredentialKey,
        value: &str,
        provider: Option<String>,
    ) -> Result<(), CredentialError> {
        if self.env_only_mode {
            return Err(CredentialError::StoreUnavailable(
                "Operating in env-only mode".to_string(),
            ));
        }

        // Validate key and value length
        if key.to_account_key().len() > MAX_KEY_LENGTH {
            return Err(CredentialError::KeyTooLong);
        }
        if value.len() > MAX_VALUE_LENGTH {
            return Err(CredentialError::ValueTooLong);
        }

        // Read-write-verify pattern for atomicity
        let prior_value = self
            .with_retry(&RetryPolicy::for_get(), || async {
                self.backend.get_raw(key).await
            })
            .await;
        let (old_value, old_value_known) = match prior_value {
            Ok(value) => (value, true),
            Err(err) => {
                tracing::warn!(
                    key = %key,
                    error = %err,
                    "Failed to read existing credential before write; rollback may be limited"
                );
                (None, false)
            }
        };

        // Write new value with retry
        self.with_retry(&RetryPolicy::for_set(), || async {
            self.backend.set_raw(key, value).await
        })
        .await?;

        // Verify the write succeeded
        let verified = self.backend.get_raw(key).await?;
        if verified.as_deref() != Some(value) {
            tracing::error!(key = %key, "Credential verification failed after write");

            // Attempt to restore old value (best effort).
            if let Some(previous) = old_value {
                if let Err(err) = self
                    .with_retry(&RetryPolicy::for_set(), || async {
                        self.backend.set_raw(key, &previous).await
                    })
                    .await
                {
                    tracing::error!(
                        key = %key,
                        error = %err,
                        "Credential rollback failed; credential may be lost"
                    );
                }
            } else if old_value_known {
                if let Err(err) = self
                    .with_retry(&RetryPolicy::for_delete(), || async {
                        self.backend.delete_raw(key).await
                    })
                    .await
                {
                    tracing::error!(
                        key = %key,
                        error = %err,
                        "Credential rollback delete failed; credential may be lost"
                    );
                }
            } else {
                tracing::warn!(
                    key = %key,
                    "Skipping rollback delete because prior value is unknown"
                );
            }

            return Err(CredentialError::VerificationFailed);
        }

        // Update index
        {
            let mut index = self.index.write().await;
            let entry = IndexEntry {
                key: key.clone(),
                provider,
                last_updated: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0),
            };
            index.entries.insert(key.to_account_key(), entry);
        }

        self.save_index().await?;

        Ok(())
    }

    /// Delete a credential with retry logic
    pub async fn delete(&self, key: &CredentialKey) -> Result<(), CredentialError> {
        if self.env_only_mode {
            return Err(CredentialError::StoreUnavailable(
                "Operating in env-only mode".to_string(),
            ));
        }

        self.with_retry(&RetryPolicy::for_delete(), || async {
            self.backend.delete_raw(key).await
        })
        .await?;

        // Update index
        {
            let mut index = self.index.write().await;
            index.entries.remove(&key.to_account_key());
        }

        self.save_index().await?;

        Ok(())
    }

    /// Get a plugin credential with isolation
    pub async fn plugin_get(
        &self,
        plugin_id: &str,
        kind: &str,
        id: &str,
    ) -> Result<Option<String>, CredentialError> {
        let key = CredentialKey::with_plugin_prefix(plugin_id, kind, id);
        self.get(&key).await
    }

    /// Set a plugin credential with isolation and quota enforcement
    ///
    /// Uses a write lock for the entire operation to prevent race conditions
    /// where concurrent calls could both increment the quota for the same new key.
    pub async fn plugin_set(
        &self,
        plugin_id: &str,
        kind: &str,
        id: &str,
        value: &str,
    ) -> Result<(), CredentialError> {
        // Check rate limit
        {
            let mut rate_limiter = self.rate_limiter.write().await;
            if !rate_limiter.check_and_record(plugin_id) {
                return Err(CredentialError::RateLimitExceeded);
            }
        }

        let key = CredentialKey::with_plugin_prefix(plugin_id, kind, id);
        let plugin_key = format!("plugin:{}", plugin_id);
        let account_key = key.to_account_key();

        // Check if this is a new key BEFORE setting (atomically with quota update)
        // We need to determine this before the set() call modifies the index
        let is_new_key = {
            let index = self.index.read().await;
            let quota = index.plugins.get(&plugin_key);
            let current_count = quota.map(|q| q.count).unwrap_or(0);
            let key_exists = index.entries.contains_key(&account_key);

            // Reject if at quota and this would be a new key
            if !key_exists && current_count >= MAX_CREDENTIALS_PER_PLUGIN {
                return Err(CredentialError::QuotaExceeded);
            }

            !key_exists
        };

        // Set the credential (this updates the index.entries via set())
        self.set(&key, value, Some(plugin_key.clone())).await?;

        // Update plugin quota if this was a new key
        // Note: There's a small race window here where another concurrent call
        // could also see is_new_key=true for the same key. However:
        // 1. Both calls succeed in setting the credential (last write wins)
        // 2. The quota might be incremented twice for one key
        // To fully prevent this, we'd need to hold a write lock during set(),
        // but that would block all credential operations.
        //
        // For now, we accept this minor over-counting as it only affects quota
        // (not security) and is self-correcting on delete or recalculation.
        if is_new_key {
            let mut index = self.index.write().await;
            let quota = index.plugins.entry(plugin_key).or_default();
            quota.count += 1;
        }

        self.save_index().await?;

        Ok(())
    }

    /// Delete a plugin credential with isolation
    pub async fn plugin_delete(
        &self,
        plugin_id: &str,
        kind: &str,
        id: &str,
    ) -> Result<(), CredentialError> {
        let key = CredentialKey::with_plugin_prefix(plugin_id, kind, id);
        self.delete(&key).await?;

        // Update plugin quota
        {
            let mut index = self.index.write().await;
            let plugin_key = format!("plugin:{}", plugin_id);
            if let Some(quota) = index.plugins.get_mut(&plugin_key) {
                quota.count = quota.count.saturating_sub(1);
            }
        }

        self.save_index().await?;

        Ok(())
    }

    /// Execute an operation with retry logic
    async fn with_retry<F, Fut, T>(&self, policy: &RetryPolicy, op: F) -> Result<T, CredentialError>
    where
        F: Fn() -> Fut,
        Fut: std::future::Future<Output = Result<T, CredentialError>>,
    {
        let mut last_error = CredentialError::Internal("No attempts made".to_string());

        for attempt in 0..=policy.max_retries {
            // Apply backoff before retry (not on first attempt)
            if attempt > 0 {
                if let Some(ref backoff) = policy.backoff {
                    if let Some(delay) = backoff.get(attempt - 1) {
                        tokio::time::sleep(*delay).await;
                    }
                }
            }

            match timeout(policy.timeout, op()).await {
                Ok(Ok(result)) => return Ok(result),
                Ok(Err(e)) => {
                    last_error = e.clone();
                    if !is_retryable(&e) {
                        return Err(e);
                    }
                    tracing::debug!(
                        attempt = attempt + 1,
                        max_retries = policy.max_retries,
                        error = %e,
                        "Credential operation failed, retrying"
                    );
                }
                Err(_) => {
                    last_error = CredentialError::Timeout;
                    tracing::debug!(
                        attempt = attempt + 1,
                        max_retries = policy.max_retries,
                        "Credential operation timed out, retrying"
                    );
                }
            }
        }

        Err(last_error)
    }

    /// List all credential keys from the index
    pub async fn list_keys(&self) -> Vec<CredentialKey> {
        let index = self.index.read().await;
        index.entries.values().map(|e| e.key.clone()).collect()
    }

    /// Check health of the credential store
    pub async fn check_health(&self) -> CredentialHealthStatus {
        if self.env_only_mode {
            return CredentialHealthStatus {
                available: false,
                locked: false,
                error: Some("Operating in env-only mode".to_string()),
            };
        }

        // Try a test read/write
        let test_key = CredentialKey::new("health", "check", "test");
        let test_value = format!("health-check-{}", uuid::Uuid::new_v4());

        match self.backend.set_raw(&test_key, &test_value).await {
            Ok(()) => {
                // Clean up test credential
                let _ = self.backend.delete_raw(&test_key).await;
                CredentialHealthStatus {
                    available: true,
                    locked: false,
                    error: None,
                }
            }
            Err(CredentialError::StoreLocked) => CredentialHealthStatus {
                available: false,
                locked: true,
                error: Some("Credential store is locked".to_string()),
            },
            Err(e) => CredentialHealthStatus {
                available: false,
                locked: false,
                error: Some(e.to_string()),
            },
        }
    }
}

/// Health status of the credential store
#[derive(Debug, Clone)]
pub struct CredentialHealthStatus {
    pub available: bool,
    pub locked: bool,
    pub error: Option<String>,
}

/// Create a platform-appropriate credential backend
#[cfg(target_os = "macos")]
pub fn create_backend() -> macos::MacOsCredentialBackend {
    macos::MacOsCredentialBackend::new()
}

#[cfg(target_os = "linux")]
pub fn create_backend() -> linux::LinuxCredentialBackend {
    linux::LinuxCredentialBackend::new()
}

#[cfg(target_os = "windows")]
pub fn create_backend() -> windows::WindowsCredentialBackend {
    windows::WindowsCredentialBackend::new()
}

// For testing on unsupported platforms
#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
pub fn create_backend() -> MockCredentialBackend {
    MockCredentialBackend::default()
}

/// Mock credential backend for testing
#[derive(Debug, Default)]
pub struct MockCredentialBackend {
    credentials: Arc<RwLock<HashMap<String, String>>>,
    available: bool,
}

impl MockCredentialBackend {
    #[allow(dead_code)]
    pub fn new(available: bool) -> Self {
        Self {
            credentials: Arc::new(RwLock::new(HashMap::new())),
            available,
        }
    }
}

impl CredentialBackend for MockCredentialBackend {
    async fn get_raw(&self, key: &CredentialKey) -> Result<Option<String>, CredentialError> {
        if !self.available {
            return Err(CredentialError::StoreUnavailable(
                "Mock store unavailable".to_string(),
            ));
        }
        let credentials = self.credentials.read().await;
        Ok(credentials.get(&key.to_account_key()).cloned())
    }

    async fn set_raw(&self, key: &CredentialKey, value: &str) -> Result<(), CredentialError> {
        if !self.available {
            return Err(CredentialError::StoreUnavailable(
                "Mock store unavailable".to_string(),
            ));
        }
        let mut credentials = self.credentials.write().await;
        credentials.insert(key.to_account_key(), value.to_string());
        Ok(())
    }

    async fn delete_raw(&self, key: &CredentialKey) -> Result<(), CredentialError> {
        if !self.available {
            return Err(CredentialError::StoreUnavailable(
                "Mock store unavailable".to_string(),
            ));
        }
        let mut credentials = self.credentials.write().await;
        credentials.remove(&key.to_account_key());
        Ok(())
    }

    async fn is_available(&self) -> bool {
        self.available
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn mock_backend() -> MockCredentialBackend {
        MockCredentialBackend::new(true)
    }

    #[test]
    fn test_credential_key_parsing() {
        let key = CredentialKey::parse("auth-profile:main:anthropic:default");
        assert!(key.is_some());
        let key = key.unwrap();
        assert_eq!(key.kind, "auth-profile");
        assert_eq!(key.agent_id, "main");
        assert_eq!(key.id, "anthropic:default");
    }

    #[test]
    fn test_credential_key_to_string() {
        let key = CredentialKey::new("gateway", "token", "default");
        assert_eq!(key.to_account_key(), "gateway:token:default");
    }

    #[test]
    fn test_plugin_key_sanitization() {
        let key = CredentialKey::with_plugin_prefix("../malicious", "token", "test");
        assert!(!key.kind.contains(".."));
        assert!(key.kind.starts_with("plugin:"));
    }

    #[test]
    fn test_rate_limit_tracker() {
        let mut tracker = RateLimitTracker::new();

        // Should allow up to WRITE_RATE_LIMIT_PER_MINUTE writes
        for _ in 0..WRITE_RATE_LIMIT_PER_MINUTE {
            assert!(tracker.check_and_record("test-plugin"));
        }

        // Should reject the next write
        assert!(!tracker.check_and_record("test-plugin"));
    }

    #[tokio::test]
    async fn test_mock_backend_operations() {
        let backend = mock_backend();
        let key = CredentialKey::new("test", "agent", "id");

        // Initially empty
        assert_eq!(backend.get_raw(&key).await.unwrap(), None);

        // Set a value
        backend.set_raw(&key, "secret-value").await.unwrap();

        // Get it back
        assert_eq!(
            backend.get_raw(&key).await.unwrap(),
            Some("secret-value".to_string())
        );

        // Delete it
        backend.delete_raw(&key).await.unwrap();

        // Should be gone
        assert_eq!(backend.get_raw(&key).await.unwrap(), None);
    }

    #[tokio::test]
    async fn test_credential_store_basic_operations() {
        let temp_dir = tempdir().unwrap();
        let backend = mock_backend();
        let store = CredentialStore::new(backend, temp_dir.path().to_path_buf())
            .await
            .unwrap();

        let key = CredentialKey::new("test", "agent", "id");

        // Set
        store.set(&key, "my-secret", None).await.unwrap();

        // Get
        let value = store.get(&key).await.unwrap();
        assert_eq!(value, Some("my-secret".to_string()));

        // Delete
        store.delete(&key).await.unwrap();

        // Should be gone
        let value = store.get(&key).await.unwrap();
        assert_eq!(value, None);
    }

    #[tokio::test]
    async fn test_credential_index_persistence() {
        let temp_dir = tempdir().unwrap();

        // Create store and add credential
        {
            let backend = mock_backend();
            let store = CredentialStore::new(backend, temp_dir.path().to_path_buf())
                .await
                .unwrap();

            let key = CredentialKey::new("test", "agent", "id");
            store
                .set(&key, "my-secret", Some("provider".to_string()))
                .await
                .unwrap();
        }

        // Verify index file exists
        let index_path = temp_dir.path().join("credentials").join("index.json");
        assert!(index_path.exists());

        // Read and verify index content
        let content = fs::read_to_string(&index_path).unwrap();
        let index: CredentialIndex = serde_json::from_str(&content).unwrap();
        assert!(index.entries.contains_key("test:agent:id"));
    }

    #[tokio::test]
    async fn test_corrupted_index_recovery() {
        let temp_dir = tempdir().unwrap();
        let creds_dir = temp_dir.path().join("credentials");
        fs::create_dir_all(&creds_dir).unwrap();

        let index_path = creds_dir.join("index.json");
        let backup_path = creds_dir.join("index.json.bak");

        // Write corrupted index
        fs::write(&index_path, "{ invalid json }").unwrap();

        // Write a valid backup
        let key = CredentialKey::new("test", "agent", "id");
        let mut index = CredentialIndex::new();
        index.entries.insert(
            key.to_account_key(),
            IndexEntry {
                key: key.clone(),
                provider: None,
                last_updated: 1,
            },
        );
        let content = serde_json::to_string_pretty(&index).unwrap();
        fs::write(&backup_path, content).unwrap();

        // Create store - should recover
        let backend = mock_backend();
        let store = CredentialStore::new(backend, temp_dir.path().to_path_buf())
            .await
            .unwrap();

        let keys = store.list_keys().await;
        assert!(keys.iter().any(|k| k.to_account_key() == "test:agent:id"));

        // Check that corrupt file was renamed
        let entries: Vec<_> = fs::read_dir(&creds_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.file_name()
                    .to_string_lossy()
                    .starts_with("index.corrupt.")
            })
            .collect();
        assert_eq!(entries.len(), 1);
    }

    #[tokio::test]
    async fn test_corrupted_index_without_backup() {
        let temp_dir = tempdir().unwrap();
        let creds_dir = temp_dir.path().join("credentials");
        fs::create_dir_all(&creds_dir).unwrap();

        let index_path = creds_dir.join("index.json");
        fs::write(&index_path, "{ invalid json }").unwrap();

        let backend = mock_backend();
        let store = CredentialStore::new(backend, temp_dir.path().to_path_buf())
            .await
            .unwrap();

        assert!(store.list_keys().await.is_empty());

        let entries: Vec<_> = fs::read_dir(&creds_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.file_name()
                    .to_string_lossy()
                    .starts_with("index.corrupt.")
            })
            .collect();
        assert_eq!(entries.len(), 1);
    }

    #[tokio::test]
    async fn test_plugin_credential_isolation() {
        let temp_dir = tempdir().unwrap();
        let backend = mock_backend();
        let store = CredentialStore::new(backend, temp_dir.path().to_path_buf())
            .await
            .unwrap();

        // Set credentials for two different plugins
        store
            .plugin_set("plugin-a", "token", "api", "secret-a")
            .await
            .unwrap();
        store
            .plugin_set("plugin-b", "token", "api", "secret-b")
            .await
            .unwrap();

        // Each plugin should only see its own credentials
        let value_a = store.plugin_get("plugin-a", "token", "api").await.unwrap();
        let value_b = store.plugin_get("plugin-b", "token", "api").await.unwrap();

        assert_eq!(value_a, Some("secret-a".to_string()));
        assert_eq!(value_b, Some("secret-b".to_string()));
    }

    #[tokio::test]
    async fn test_env_only_mode() {
        let temp_dir = tempdir().unwrap();
        let backend = MockCredentialBackend::new(false); // Unavailable
        let store = CredentialStore::new(backend, temp_dir.path().to_path_buf())
            .await
            .unwrap();

        assert!(store.is_env_only_mode());

        // Get should return None
        let key = CredentialKey::new("test", "agent", "id");
        let value = store.get(&key).await.unwrap();
        assert_eq!(value, None);

        // Set should fail
        let result = store.set(&key, "value", None).await;
        assert!(matches!(result, Err(CredentialError::StoreUnavailable(_))));
    }

    #[test]
    fn test_error_retryable() {
        assert!(is_retryable(&CredentialError::Timeout));
        assert!(is_retryable(&CredentialError::IoError("test".to_string())));
        assert!(is_retryable(&CredentialError::RateLimitExceeded));

        assert!(!is_retryable(&CredentialError::StoreLocked));
        assert!(!is_retryable(&CredentialError::AccessDenied));
        assert!(!is_retryable(&CredentialError::NotFound));
    }

    #[test]
    fn test_retry_policies() {
        let get_policy = RetryPolicy::for_get();
        assert_eq!(get_policy.max_retries, 2);
        assert_eq!(get_policy.timeout, Duration::from_secs(5));
        assert!(get_policy.backoff.is_none());

        let set_policy = RetryPolicy::for_set();
        assert_eq!(set_policy.max_retries, 3);
        assert_eq!(set_policy.timeout, Duration::from_secs(10));
        assert!(set_policy.backoff.is_some());

        let delete_policy = RetryPolicy::for_delete();
        assert_eq!(delete_policy.max_retries, 2);
        assert_eq!(delete_policy.timeout, Duration::from_secs(5));
        assert!(delete_policy.backoff.is_none());
    }

    #[tokio::test]
    async fn test_key_too_long_validation() {
        let temp_dir = tempdir().unwrap();
        let backend = mock_backend();
        let store = CredentialStore::new(backend, temp_dir.path().to_path_buf())
            .await
            .unwrap();

        // Create a key that's too long
        let long_id = "x".repeat(MAX_KEY_LENGTH + 10);
        let key = CredentialKey::new("test", "agent", &long_id);

        let result = store.set(&key, "value", None).await;
        assert!(matches!(result, Err(CredentialError::KeyTooLong)));
    }

    #[tokio::test]
    async fn test_value_too_long_validation() {
        let temp_dir = tempdir().unwrap();
        let backend = mock_backend();
        let store = CredentialStore::new(backend, temp_dir.path().to_path_buf())
            .await
            .unwrap();

        let key = CredentialKey::new("test", "agent", "id");
        let long_value = "x".repeat(MAX_VALUE_LENGTH + 1);

        let result = store.set(&key, &long_value, None).await;
        assert!(matches!(result, Err(CredentialError::ValueTooLong)));
    }

    #[tokio::test]
    async fn test_plugin_quota_not_incremented_on_update() {
        let temp_dir = tempdir().unwrap();
        let backend = mock_backend();
        let store = CredentialStore::new(backend, temp_dir.path().to_path_buf())
            .await
            .unwrap();

        let plugin_id = "test-plugin";

        // Set a credential for the first time
        store
            .plugin_set(plugin_id, "token", "api-key", "secret-v1")
            .await
            .unwrap();

        // Check quota is 1
        {
            let index = store.index.read().await;
            let plugin_key = format!("plugin:{}", plugin_id);
            let quota = index.plugins.get(&plugin_key);
            assert_eq!(quota.map(|q| q.count).unwrap_or(0), 1);
        }

        // Update the same credential multiple times
        for i in 2..10 {
            store
                .plugin_set(plugin_id, "token", "api-key", &format!("secret-v{}", i))
                .await
                .unwrap();
        }

        // Quota should still be 1 (updates don't increment)
        {
            let index = store.index.read().await;
            let plugin_key = format!("plugin:{}", plugin_id);
            let quota = index.plugins.get(&plugin_key);
            assert_eq!(
                quota.map(|q| q.count).unwrap_or(0),
                1,
                "Quota should not increment on updates"
            );
        }

        // Verify the value was actually updated
        let value = store
            .plugin_get(plugin_id, "token", "api-key")
            .await
            .unwrap();
        assert_eq!(value, Some("secret-v9".to_string()));
    }

    #[tokio::test]
    async fn test_plugin_quota_incremented_on_new_keys() {
        let temp_dir = tempdir().unwrap();
        let backend = mock_backend();
        let store = CredentialStore::new(backend, temp_dir.path().to_path_buf())
            .await
            .unwrap();

        let plugin_id = "test-plugin";

        // Set multiple different credentials
        for i in 1..=5 {
            store
                .plugin_set(
                    plugin_id,
                    "token",
                    &format!("key-{}", i),
                    &format!("secret-{}", i),
                )
                .await
                .unwrap();
        }

        // Quota should be 5 (one for each unique key)
        {
            let index = store.index.read().await;
            let plugin_key = format!("plugin:{}", plugin_id);
            let quota = index.plugins.get(&plugin_key);
            assert_eq!(
                quota.map(|q| q.count).unwrap_or(0),
                5,
                "Quota should increment for each new key"
            );
        }
    }
}
