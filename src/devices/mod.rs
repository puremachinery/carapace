//! Device pairing and registry module
//!
//! Manages device pairing state machine (request -> pending -> approved/rejected),
//! token verification, and device authentication.

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::Write as IoWrite;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use uuid::Uuid;

/// Maximum number of paired devices
pub const MAX_PAIRED_DEVICES: usize = 50;

/// Maximum number of pending pairing requests
pub const MAX_PENDING_REQUESTS: usize = 25;

/// Maximum number of device tokens
pub const MAX_DEVICE_TOKENS: usize = 200;

/// Pairing request expiry (1 hour)
pub const PAIRING_REQUEST_EXPIRY_MS: u64 = 60 * 60 * 1000;

/// Device token expiry (90 days)
pub const DEVICE_TOKEN_EXPIRY_MS: u64 = 90 * 24 * 60 * 60 * 1000;

/// Pairing request state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PairingState {
    #[default]
    Pending,
    Approved,
    Rejected,
    Expired,
}

/// A device pairing request
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DevicePairingRequest {
    /// Unique request ID
    pub request_id: String,
    /// Device ID requesting pairing
    pub device_id: String,
    /// Device public key
    pub public_key: String,
    /// Current state of the request
    pub state: PairingState,
    /// Requested role (primary)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    /// Requested roles
    #[serde(default)]
    pub requested_roles: Vec<String>,
    /// Requested scopes
    #[serde(default)]
    pub requested_scopes: Vec<String>,
    /// Display name for the device
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    /// Platform identifier
    #[serde(skip_serializing_if = "Option::is_none")]
    pub platform: Option<String>,
    /// Client ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    /// Client mode
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_mode: Option<String>,
    /// Remote IP address
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_ip: Option<String>,
    /// Whether this request should be silent (auto-approve)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub silent: Option<bool>,
    /// Whether this is a repair request for an existing device
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_repair: Option<bool>,
    /// Timestamp when request was created (Unix ms)
    pub created_at_ms: u64,
    /// Timestamp when request was resolved (Unix ms)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolved_at_ms: Option<u64>,
    /// Reason for rejection (if rejected)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rejection_reason: Option<String>,
}

pub struct PairingRequestOutcome {
    pub request: DevicePairingRequest,
    pub created: bool,
}

#[derive(Default, Clone)]
pub struct DeviceMetadataPatch {
    pub display_name: Option<String>,
    pub platform: Option<String>,
    pub client_id: Option<String>,
    pub client_mode: Option<String>,
    pub remote_ip: Option<String>,
    pub role: Option<String>,
    pub scopes: Option<Vec<String>>,
}

impl DevicePairingRequest {
    /// Create a new pending pairing request
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        device_id: String,
        public_key: String,
        requested_roles: Vec<String>,
        requested_scopes: Vec<String>,
        display_name: Option<String>,
        platform: Option<String>,
        client_id: Option<String>,
        client_mode: Option<String>,
        remote_ip: Option<String>,
        silent: Option<bool>,
        is_repair: Option<bool>,
    ) -> Self {
        Self {
            request_id: Uuid::new_v4().to_string(),
            device_id,
            public_key,
            state: PairingState::Pending,
            role: requested_roles.first().cloned(),
            requested_roles,
            requested_scopes,
            display_name,
            platform,
            client_id,
            client_mode,
            remote_ip,
            silent,
            is_repair,
            created_at_ms: now_ms(),
            resolved_at_ms: None,
            rejection_reason: None,
        }
    }

    /// Check if the request has expired
    pub fn is_expired(&self) -> bool {
        if self.state != PairingState::Pending {
            return false;
        }
        let age = now_ms().saturating_sub(self.created_at_ms);
        age > PAIRING_REQUEST_EXPIRY_MS
    }

    /// Approve the request
    pub fn approve(&mut self) {
        self.state = PairingState::Approved;
        self.resolved_at_ms = Some(now_ms());
    }

    /// Reject the request
    pub fn reject(&mut self, reason: Option<String>) {
        self.state = PairingState::Rejected;
        self.resolved_at_ms = Some(now_ms());
        self.rejection_reason = reason;
    }

    /// Mark as expired
    pub fn mark_expired(&mut self) {
        self.state = PairingState::Expired;
        self.resolved_at_ms = Some(now_ms());
    }
}

/// A paired device
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PairedDevice {
    /// Device ID
    pub device_id: String,
    /// Device public key
    pub public_key: String,
    /// Granted roles
    #[serde(default)]
    pub roles: Vec<String>,
    /// Granted scopes
    #[serde(default)]
    pub scopes: Vec<String>,
    /// Display name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    /// Platform identifier
    #[serde(skip_serializing_if = "Option::is_none")]
    pub platform: Option<String>,
    /// Client ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    /// Client mode
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_mode: Option<String>,
    /// Remote IP address
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_ip: Option<String>,
    /// Timestamp when paired (Unix ms)
    pub paired_at_ms: u64,
    /// Last seen timestamp (Unix ms)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_seen_ms: Option<u64>,
}

impl PairedDevice {
    /// Create from an approved pairing request
    pub fn from_request(
        request: &DevicePairingRequest,
        roles: Vec<String>,
        scopes: Vec<String>,
    ) -> Self {
        Self {
            device_id: request.device_id.clone(),
            public_key: request.public_key.clone(),
            roles,
            scopes,
            display_name: request.display_name.clone(),
            platform: request.platform.clone(),
            client_id: request.client_id.clone(),
            client_mode: request.client_mode.clone(),
            remote_ip: request.remote_ip.clone(),
            paired_at_ms: now_ms(),
            last_seen_ms: None,
        }
    }

    /// Update last seen timestamp
    pub fn touch(&mut self) {
        self.last_seen_ms = Some(now_ms());
    }
}

/// A device authentication token
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceToken {
    /// Token hash for secure storage
    pub token_hash: String,
    /// Device ID this token belongs to
    pub device_id: String,
    /// Role this token is valid for
    pub role: String,
    /// Scopes this token is valid for
    #[serde(default)]
    pub scopes: Vec<String>,
    /// Issued timestamp (Unix ms)
    pub issued_at_ms: u64,
    /// Expiry timestamp (Unix ms)
    pub expires_at_ms: u64,
    /// Whether this token has been revoked
    pub revoked: bool,
}

impl DeviceToken {
    /// Create a new token for a device
    pub fn new(device_id: String, role: String, scopes: Vec<String>) -> (Self, String) {
        let token = Uuid::new_v4().to_string();
        let token_hash = hash_token(&token);
        let now = now_ms();
        (
            Self {
                token_hash,
                device_id,
                role,
                scopes,
                issued_at_ms: now,
                expires_at_ms: now + DEVICE_TOKEN_EXPIRY_MS,
                revoked: false,
            },
            token,
        )
    }

    /// Check if token is valid (not expired, not revoked)
    pub fn is_valid(&self) -> bool {
        !self.revoked && now_ms() < self.expires_at_ms
    }

    /// Verify a token against this entry
    pub fn verify(&self, token: &str) -> bool {
        if !self.is_valid() {
            return false;
        }
        let provided_hash = hash_token(token);
        constant_time_eq(&self.token_hash, &provided_hash)
    }

    /// Revoke the token
    pub fn revoke(&mut self) {
        self.revoked = true;
    }
}

/// Issued device token (plaintext returned to client)
#[derive(Debug, Clone)]
pub struct IssuedDeviceToken {
    pub token: String,
    pub role: String,
    pub scopes: Vec<String>,
    pub issued_at_ms: u64,
}

/// Hash a token for secure storage
fn hash_token(token: &str) -> String {
    let digest = Sha256::digest(token.as_bytes());
    hex::encode(digest)
}

/// Constant-time string comparison
fn constant_time_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut result = 0u8;
    for (x, y) in a.bytes().zip(b.bytes()) {
        result |= x ^ y;
    }
    result == 0
}

/// Persistent store for device pairing data
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DevicePairingStore {
    /// Version for schema migration
    pub version: u32,
    /// Pending pairing requests by request_id
    #[serde(default)]
    pub pending_requests: HashMap<String, DevicePairingRequest>,
    /// Paired devices by device_id
    #[serde(default)]
    pub paired_devices: HashMap<String, PairedDevice>,
    /// Tokens by token_hash
    #[serde(default)]
    pub tokens: HashMap<String, DeviceToken>,
}

impl DevicePairingStore {
    pub const VERSION: u32 = 1;

    pub fn new() -> Self {
        Self {
            version: Self::VERSION,
            pending_requests: HashMap::new(),
            paired_devices: HashMap::new(),
            tokens: HashMap::new(),
        }
    }
}

/// Errors that can occur during device pairing operations
#[derive(Debug, Clone, PartialEq)]
pub enum DevicePairingError {
    /// Request not found
    RequestNotFound,
    /// Request already resolved
    RequestAlreadyResolved,
    /// Request expired
    RequestExpired,
    /// Device not paired
    DeviceNotPaired,
    /// Device already paired
    DeviceAlreadyPaired,
    /// Public key mismatch
    PublicKeyMismatch,
    /// Token invalid
    TokenInvalid,
    /// Token expired
    TokenExpired,
    /// Token revoked
    TokenRevoked,
    /// Role not allowed
    RoleNotAllowed,
    /// Scope not allowed
    ScopeNotAllowed,
    /// Too many pending requests
    TooManyPendingRequests,
    /// Too many paired devices
    TooManyPairedDevices,
    /// I/O error
    IoError(String),
    /// JSON error
    JsonError(String),
}

impl std::fmt::Display for DevicePairingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RequestNotFound => write!(f, "pairing request not found"),
            Self::RequestAlreadyResolved => write!(f, "pairing request already resolved"),
            Self::RequestExpired => write!(f, "pairing request expired"),
            Self::DeviceNotPaired => write!(f, "device not paired"),
            Self::DeviceAlreadyPaired => write!(f, "device already paired"),
            Self::PublicKeyMismatch => write!(f, "device public key mismatch"),
            Self::TokenInvalid => write!(f, "token invalid"),
            Self::TokenExpired => write!(f, "token expired"),
            Self::TokenRevoked => write!(f, "token revoked"),
            Self::RoleNotAllowed => write!(f, "role not allowed for this device"),
            Self::ScopeNotAllowed => write!(f, "scope not allowed for this device"),
            Self::TooManyPendingRequests => write!(f, "too many pending pairing requests"),
            Self::TooManyPairedDevices => write!(f, "too many paired devices"),
            Self::IoError(msg) => write!(f, "I/O error: {}", msg),
            Self::JsonError(msg) => write!(f, "JSON error: {}", msg),
        }
    }
}

impl std::error::Error for DevicePairingError {}

/// Thread-safe device pairing registry with persistence
pub struct DevicePairingRegistry {
    /// In-memory store
    store: RwLock<DevicePairingStore>,
    /// Path to persistent storage
    storage_path: PathBuf,
    /// Whether to auto-save on changes
    auto_save: bool,
}

impl std::fmt::Debug for DevicePairingRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DevicePairingRegistry")
            .field("storage_path", &self.storage_path)
            .field("auto_save", &self.auto_save)
            .finish()
    }
}

impl DevicePairingRegistry {
    /// Create a new registry with the given storage path
    pub fn new(storage_path: PathBuf) -> Result<Self, DevicePairingError> {
        let store = Self::load_or_create(&storage_path)?;
        Ok(Self {
            store: RwLock::new(store),
            storage_path,
            auto_save: true,
        })
    }

    pub fn with_auto_save(
        storage_path: PathBuf,
        auto_save: bool,
    ) -> Result<Self, DevicePairingError> {
        let store = Self::load_or_create(&storage_path)?;
        Ok(Self {
            store: RwLock::new(store),
            storage_path,
            auto_save,
        })
    }

    /// Create an in-memory only registry (for testing)
    pub fn in_memory() -> Self {
        Self {
            store: RwLock::new(DevicePairingStore::new()),
            storage_path: PathBuf::new(),
            auto_save: false,
        }
    }

    /// Load store from disk or create a new one
    fn load_or_create(path: &PathBuf) -> Result<DevicePairingStore, DevicePairingError> {
        if !path.exists() {
            return Ok(DevicePairingStore::new());
        }

        let content =
            fs::read_to_string(path).map_err(|e| DevicePairingError::IoError(e.to_string()))?;

        serde_json::from_str(&content).map_err(|e| {
            // If corrupted, backup and create new
            let timestamp = now_ms();
            let backup = path.with_extension(format!("corrupt.{}.json", timestamp));
            if let Err(err) = fs::rename(path, &backup) {
                tracing::warn!(
                    path = %path.display(),
                    backup = %backup.display(),
                    error = %err,
                    "failed to backup corrupted device pairing store"
                );
            } else {
                tracing::warn!(
                    path = %path.display(),
                    backup = %backup.display(),
                    "backed up corrupted device pairing store"
                );
            }
            DevicePairingError::JsonError(e.to_string())
        })
    }

    /// Save store to disk
    fn save(&self) -> Result<(), DevicePairingError> {
        if !self.auto_save || self.storage_path.as_os_str().is_empty() {
            return Ok(());
        }

        let store = self.store.read();
        let content = serde_json::to_string_pretty(&*store)
            .map_err(|e| DevicePairingError::JsonError(e.to_string()))?;
        drop(store);

        // Ensure parent directory exists
        if let Some(parent) = self.storage_path.parent() {
            fs::create_dir_all(parent).map_err(|e| DevicePairingError::IoError(e.to_string()))?;
        }

        // Write atomically
        let temp_path = self.storage_path.with_extension("tmp");
        let mut file =
            File::create(&temp_path).map_err(|e| DevicePairingError::IoError(e.to_string()))?;
        IoWrite::write_all(&mut file, content.as_bytes())
            .map_err(|e| DevicePairingError::IoError(e.to_string()))?;
        file.sync_all()
            .map_err(|e| DevicePairingError::IoError(e.to_string()))?;
        fs::rename(&temp_path, &self.storage_path)
            .map_err(|e| DevicePairingError::IoError(e.to_string()))?;

        Ok(())
    }

    /// Clean up expired requests
    fn cleanup_expired(&self) {
        let mut store = self.store.write();
        let expired: Vec<String> = store
            .pending_requests
            .iter()
            .filter(|(_, req)| req.is_expired())
            .map(|(id, _)| id.clone())
            .collect();

        for id in expired {
            if let Some(mut req) = store.pending_requests.remove(&id) {
                req.mark_expired();
                // Keep expired requests for a short time for audit
                store.pending_requests.insert(id, req);
            }
        }

        // Remove old expired/rejected requests (older than 1 hour)
        let cutoff = now_ms().saturating_sub(60 * 60 * 1000);
        store.pending_requests.retain(|_, req| {
            req.state == PairingState::Pending
                || req.resolved_at_ms.map(|t| t > cutoff).unwrap_or(true)
        });

        // Clean up expired tokens
        store
            .tokens
            .retain(|_, token| !token.revoked || token.expires_at_ms > cutoff);
    }

    // === Pairing Request Methods ===

    /// Create a new pairing request
    #[allow(clippy::too_many_arguments)]
    pub fn request_pairing(
        &self,
        device_id: String,
        public_key: String,
        requested_roles: Vec<String>,
        requested_scopes: Vec<String>,
        display_name: Option<String>,
        platform: Option<String>,
        client_id: Option<String>,
        client_mode: Option<String>,
        remote_ip: Option<String>,
        silent: Option<bool>,
    ) -> Result<DevicePairingRequest, DevicePairingError> {
        let outcome = self.request_pairing_with_status(
            device_id,
            public_key,
            requested_roles,
            requested_scopes,
            display_name,
            platform,
            client_id,
            client_mode,
            remote_ip,
            silent,
        )?;
        Ok(outcome.request)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn request_pairing_with_status(
        &self,
        device_id: String,
        public_key: String,
        requested_roles: Vec<String>,
        requested_scopes: Vec<String>,
        display_name: Option<String>,
        platform: Option<String>,
        client_id: Option<String>,
        client_mode: Option<String>,
        remote_ip: Option<String>,
        silent: Option<bool>,
    ) -> Result<PairingRequestOutcome, DevicePairingError> {
        self.cleanup_expired();

        let mut store = self.store.write();

        // Check for existing pending request for this device
        if let Some(existing) = store
            .pending_requests
            .values()
            .find(|r| r.device_id == device_id && r.state == PairingState::Pending)
        {
            // Verify public key matches
            if existing.public_key != public_key {
                return Err(DevicePairingError::PublicKeyMismatch);
            }
            return Ok(PairingRequestOutcome {
                request: existing.clone(),
                created: false,
            });
        }

        // Check pending request limit
        let pending_count = store
            .pending_requests
            .values()
            .filter(|r| r.state == PairingState::Pending)
            .count();
        if pending_count >= MAX_PENDING_REQUESTS {
            return Err(DevicePairingError::TooManyPendingRequests);
        }

        let is_repair = store.paired_devices.contains_key(&device_id);
        let request = DevicePairingRequest::new(
            device_id,
            public_key,
            requested_roles,
            requested_scopes,
            display_name,
            platform,
            client_id,
            client_mode,
            remote_ip,
            silent,
            Some(is_repair),
        );
        store
            .pending_requests
            .insert(request.request_id.clone(), request.clone());
        drop(store);

        if let Err(e) = self.save() {
            tracing::error!(error = %e, "failed to persist device registry state to disk");
        }
        Ok(PairingRequestOutcome {
            request,
            created: true,
        })
    }

    /// List all pairing requests (pending and recent resolved)
    pub fn list_requests(&self) -> (Vec<DevicePairingRequest>, Vec<DevicePairingRequest>) {
        self.cleanup_expired();
        let store = self.store.read();
        let pending: Vec<_> = store
            .pending_requests
            .values()
            .filter(|r| r.state == PairingState::Pending)
            .cloned()
            .collect();
        let resolved: Vec<_> = store
            .pending_requests
            .values()
            .filter(|r| r.state != PairingState::Pending)
            .cloned()
            .collect();
        (pending, resolved)
    }

    /// Get a specific pairing request
    pub fn get_request(&self, request_id: &str) -> Option<DevicePairingRequest> {
        let store = self.store.read();
        store.pending_requests.get(request_id).cloned()
    }

    /// Approve a pairing request
    pub fn approve_request(
        &self,
        request_id: &str,
        roles: Vec<String>,
        scopes: Vec<String>,
    ) -> Result<(PairedDevice, String), DevicePairingError> {
        let mut store = self.store.write();

        // First, validate and get the request info
        let request = store
            .pending_requests
            .get(request_id)
            .ok_or(DevicePairingError::RequestNotFound)?;

        if request.state != PairingState::Pending {
            return Err(DevicePairingError::RequestAlreadyResolved);
        }

        if request.is_expired() {
            // Mark as expired
            if let Some(req) = store.pending_requests.get_mut(request_id) {
                req.mark_expired();
            }
            return Err(DevicePairingError::RequestExpired);
        }

        // Clone data we need
        let device_id = request.device_id.clone();
        let public_key = request.public_key.clone();
        let display_name = request.display_name.clone();
        let platform = request.platform.clone();
        let client_id = request.client_id.clone();
        let client_mode = request.client_mode.clone();
        let remote_ip = request.remote_ip.clone();

        // Check paired device limit and evict if needed
        if store.paired_devices.len() >= MAX_PAIRED_DEVICES {
            // Evict oldest paired device
            if let Some(oldest_id) = store
                .paired_devices
                .values()
                .min_by(|a, b| {
                    (a.paired_at_ms, a.device_id.as_str())
                        .cmp(&(b.paired_at_ms, b.device_id.as_str()))
                })
                .map(|d| d.device_id.clone())
            {
                store.paired_devices.remove(&oldest_id);
                // Remove tokens for evicted device
                store.tokens.retain(|_, t| t.device_id != oldest_id);
            }
        }

        // Approve the request
        if let Some(req) = store.pending_requests.get_mut(request_id) {
            req.approve();
        }

        // Create the paired device
        let paired_device = PairedDevice {
            device_id: device_id.clone(),
            public_key,
            roles: roles.clone(),
            scopes: scopes.clone(),
            display_name,
            platform,
            client_id,
            client_mode,
            remote_ip,
            paired_at_ms: now_ms(),
            last_seen_ms: None,
        };
        store
            .paired_devices
            .insert(device_id.clone(), paired_device.clone());

        // Issue a token for the newly paired device
        let default_role = roles
            .first()
            .cloned()
            .unwrap_or_else(|| "operator".to_string());
        let (token_entry, plain_token) = DeviceToken::new(device_id, default_role, scopes);
        store
            .tokens
            .insert(token_entry.token_hash.clone(), token_entry);

        drop(store);
        if let Err(e) = self.save() {
            tracing::error!(error = %e, "failed to persist device registry state to disk");
        }

        Ok((paired_device, plain_token))
    }

    /// Reject a pairing request
    pub fn reject_request(
        &self,
        request_id: &str,
        reason: Option<String>,
    ) -> Result<DevicePairingRequest, DevicePairingError> {
        let mut store = self.store.write();

        let request = store
            .pending_requests
            .get_mut(request_id)
            .ok_or(DevicePairingError::RequestNotFound)?;

        if request.state != PairingState::Pending {
            return Err(DevicePairingError::RequestAlreadyResolved);
        }

        request.reject(reason);
        let result = request.clone();
        drop(store);

        if let Err(e) = self.save() {
            tracing::error!(error = %e, "failed to persist device registry state to disk");
        }
        Ok(result)
    }

    // === Paired Device Methods ===

    /// List all paired devices
    pub fn list_paired_devices(&self) -> Vec<PairedDevice> {
        let store = self.store.read();
        store.paired_devices.values().cloned().collect()
    }

    /// Get a specific paired device
    pub fn get_paired_device(&self, device_id: &str) -> Option<PairedDevice> {
        let store = self.store.read();
        store.paired_devices.get(device_id).cloned()
    }

    /// Get the most recent token scopes for a device role
    pub fn latest_token_scopes(&self, device_id: &str, role: &str) -> Option<Vec<String>> {
        let store = self.store.read();
        if !store.paired_devices.contains_key(device_id) {
            return None;
        }
        store
            .tokens
            .values()
            .filter(|token| token.device_id == device_id && token.role == role)
            .max_by_key(|token| token.issued_at_ms)
            .map(|token| token.scopes.clone())
    }

    /// Check if a device is paired
    pub fn is_paired(&self, device_id: &str) -> bool {
        let store = self.store.read();
        store.paired_devices.contains_key(device_id)
    }

    /// Check if a device is paired with matching public key
    pub fn is_paired_with_key(&self, device_id: &str, public_key: &str) -> bool {
        let store = self.store.read();
        store
            .paired_devices
            .get(device_id)
            .map(|d| d.public_key == public_key)
            .unwrap_or(false)
    }

    /// Update last seen time for a device
    pub fn touch_device(&self, device_id: &str) {
        let mut store = self.store.write();
        if let Some(device) = store.paired_devices.get_mut(device_id) {
            device.touch();
        }
        // Don't save on every touch to avoid excessive I/O
    }

    /// Update metadata for a paired device
    pub fn update_metadata(
        &self,
        device_id: &str,
        patch: DeviceMetadataPatch,
    ) -> Result<(), DevicePairingError> {
        let mut store = self.store.write();
        let device = store
            .paired_devices
            .get_mut(device_id)
            .ok_or(DevicePairingError::DeviceNotPaired)?;

        if let Some(display_name) = patch.display_name {
            device.display_name = Some(display_name);
        }
        if let Some(platform) = patch.platform {
            device.platform = Some(platform);
        }
        if let Some(client_id) = patch.client_id {
            device.client_id = Some(client_id);
        }
        if let Some(client_mode) = patch.client_mode {
            device.client_mode = Some(client_mode);
        }
        if let Some(remote_ip) = patch.remote_ip {
            device.remote_ip = Some(remote_ip);
        }
        if let Some(role) = patch.role {
            if !device.roles.contains(&role) {
                device.roles.push(role);
            }
        }
        if let Some(scopes) = patch.scopes {
            for scope in scopes {
                if !device.scopes.contains(&scope) {
                    device.scopes.push(scope);
                }
            }
        }
        device.touch();

        drop(store);
        if let Err(e) = self.save() {
            tracing::error!(error = %e, "failed to persist device registry state to disk");
        }
        Ok(())
    }

    /// Unpair a device
    pub fn unpair_device(&self, device_id: &str) -> Result<PairedDevice, DevicePairingError> {
        let mut store = self.store.write();
        let device = store
            .paired_devices
            .remove(device_id)
            .ok_or(DevicePairingError::DeviceNotPaired)?;

        // Revoke all tokens for this device
        for token in store.tokens.values_mut() {
            if token.device_id == device_id {
                token.revoke();
            }
        }

        drop(store);
        if let Err(e) = self.save() {
            tracing::error!(error = %e, "failed to persist device registry state to disk");
        }
        Ok(device)
    }

    // === Token Methods ===

    /// Verify a device token
    pub fn verify_token(
        &self,
        device_id: &str,
        token: &str,
        required_role: Option<&str>,
        required_scopes: &[String],
    ) -> Result<(), DevicePairingError> {
        let store = self.store.read();

        // Check if device is paired
        let device = store
            .paired_devices
            .get(device_id)
            .ok_or(DevicePairingError::DeviceNotPaired)?;

        // Find and verify token
        let token_hash = hash_token(token);
        let token_entry = store
            .tokens
            .get(&token_hash)
            .ok_or(DevicePairingError::TokenInvalid)?;

        if token_entry.device_id != device_id {
            return Err(DevicePairingError::TokenInvalid);
        }

        if token_entry.revoked {
            return Err(DevicePairingError::TokenRevoked);
        }

        if now_ms() >= token_entry.expires_at_ms {
            return Err(DevicePairingError::TokenExpired);
        }

        // Check role if required
        if let Some(role) = required_role {
            if token_entry.role != role {
                return Err(DevicePairingError::TokenInvalid);
            }
            if !device.roles.contains(&role.to_string()) && !device.roles.is_empty() {
                return Err(DevicePairingError::RoleNotAllowed);
            }
        }

        // Check scopes if required
        if !required_scopes.is_empty() {
            if !scopes_allow(required_scopes, &token_entry.scopes) {
                return Err(DevicePairingError::ScopeNotAllowed);
            }
            if !scopes_allow(required_scopes, &device.scopes) && !device.scopes.is_empty() {
                return Err(DevicePairingError::ScopeNotAllowed);
            }
        }

        Ok(())
    }

    /// Issue a new token for a paired device
    pub fn issue_token(
        &self,
        device_id: &str,
        role: String,
        scopes: Vec<String>,
    ) -> Result<IssuedDeviceToken, DevicePairingError> {
        let mut store = self.store.write();

        let device = store
            .paired_devices
            .get(device_id)
            .ok_or(DevicePairingError::DeviceNotPaired)?;

        // Validate role is allowed
        if !device.roles.contains(&role) && !device.roles.is_empty() {
            return Err(DevicePairingError::RoleNotAllowed);
        }

        // Validate scopes are allowed
        for scope in &scopes {
            if !device.scopes.contains(scope) && !device.scopes.is_empty() {
                return Err(DevicePairingError::ScopeNotAllowed);
            }
        }

        // Check token limit
        if store.tokens.len() >= MAX_DEVICE_TOKENS {
            // Evict oldest token
            if let Some(oldest_hash) = store
                .tokens
                .iter()
                .min_by_key(|(_, t)| t.issued_at_ms)
                .map(|(h, _)| h.clone())
            {
                store.tokens.remove(&oldest_hash);
            }
        }

        let (token_entry, plain_token) =
            DeviceToken::new(device_id.to_string(), role.clone(), scopes.clone());
        let issued_at_ms = token_entry.issued_at_ms;
        store
            .tokens
            .insert(token_entry.token_hash.clone(), token_entry);

        drop(store);
        if let Err(e) = self.save() {
            tracing::error!(error = %e, "failed to persist device registry state to disk");
        }

        Ok(IssuedDeviceToken {
            token: plain_token,
            role,
            scopes,
            issued_at_ms,
        })
    }

    /// Ensure a token exists for the device (rotates if needed)
    pub fn ensure_token(
        &self,
        device_id: &str,
        role: String,
        scopes: Vec<String>,
    ) -> Result<IssuedDeviceToken, DevicePairingError> {
        let store = self.store.read();

        let device = store
            .paired_devices
            .get(device_id)
            .ok_or(DevicePairingError::DeviceNotPaired)?;

        // Validate role is allowed
        if !device.roles.contains(&role) && !device.roles.is_empty() {
            return Err(DevicePairingError::RoleNotAllowed);
        }

        // Validate scopes are allowed
        if !scopes_allow(&scopes, &device.scopes) && !device.scopes.is_empty() {
            return Err(DevicePairingError::ScopeNotAllowed);
        }

        // Plaintext token is no longer stored; always rotate to issue a fresh one.
        drop(store);
        self.rotate_token(device_id, role, scopes)
    }

    /// Rotate a token for a device and role
    pub fn rotate_token(
        &self,
        device_id: &str,
        role: String,
        scopes: Vec<String>,
    ) -> Result<IssuedDeviceToken, DevicePairingError> {
        let mut store = self.store.write();

        let device = store
            .paired_devices
            .get(device_id)
            .ok_or(DevicePairingError::DeviceNotPaired)?;

        // Validate role is allowed
        if !device.roles.contains(&role) && !device.roles.is_empty() {
            return Err(DevicePairingError::RoleNotAllowed);
        }

        // Validate scopes are allowed
        if !scopes_allow(&scopes, &device.scopes) && !device.scopes.is_empty() {
            return Err(DevicePairingError::ScopeNotAllowed);
        }

        // Revoke existing tokens for this role
        for token in store.tokens.values_mut() {
            if token.device_id == device_id && token.role == role && !token.revoked {
                token.revoke();
            }
        }

        // Check token limit and evict oldest if needed
        if store.tokens.len() >= MAX_DEVICE_TOKENS {
            if let Some(oldest_hash) = store
                .tokens
                .iter()
                .min_by_key(|(_, t)| t.issued_at_ms)
                .map(|(h, _)| h.clone())
            {
                store.tokens.remove(&oldest_hash);
            }
        }

        let (token_entry, plain_token) =
            DeviceToken::new(device_id.to_string(), role.clone(), scopes.clone());
        let issued_at_ms = token_entry.issued_at_ms;
        store
            .tokens
            .insert(token_entry.token_hash.clone(), token_entry);

        drop(store);
        if let Err(e) = self.save() {
            tracing::error!(error = %e, "failed to persist device registry state to disk");
        }

        Ok(IssuedDeviceToken {
            token: plain_token,
            role,
            scopes,
            issued_at_ms,
        })
    }

    /// Revoke a token for a device and role
    pub fn revoke_token(&self, device_id: &str, role: &str) -> Result<u64, DevicePairingError> {
        let mut store = self.store.write();

        if !store.paired_devices.contains_key(device_id) {
            return Err(DevicePairingError::DeviceNotPaired);
        }

        let mut revoked = false;
        for token in store.tokens.values_mut() {
            if token.device_id == device_id && token.role == role && !token.revoked {
                token.revoke();
                revoked = true;
            }
        }

        if !revoked {
            return Err(DevicePairingError::TokenInvalid);
        }

        drop(store);
        if let Err(e) = self.save() {
            tracing::error!(error = %e, "failed to persist device registry state to disk");
        }

        Ok(now_ms())
    }

    /// Revoke all tokens for a device (rotate)
    pub fn revoke_tokens(&self, device_id: &str) -> Result<usize, DevicePairingError> {
        let mut store = self.store.write();

        if !store.paired_devices.contains_key(device_id) {
            return Err(DevicePairingError::DeviceNotPaired);
        }

        let mut count = 0;
        for token in store.tokens.values_mut() {
            if token.device_id == device_id && !token.revoked {
                token.revoke();
                count += 1;
            }
        }

        drop(store);
        if let Err(e) = self.save() {
            tracing::error!(error = %e, "failed to persist device registry state to disk");
        }

        Ok(count)
    }
}

/// Get current time in milliseconds
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_millis() as u64
}

fn scopes_allow(requested: &[String], allowed: &[String]) -> bool {
    if requested.is_empty() {
        return true;
    }
    if allowed.is_empty() {
        return false;
    }
    requested.iter().all(|scope| allowed.contains(scope))
}

/// Create a shared device pairing registry
pub fn create_registry(
    state_dir: PathBuf,
) -> Result<Arc<DevicePairingRegistry>, DevicePairingError> {
    let storage_path = state_dir.join("device-pairing.json");
    Ok(Arc::new(DevicePairingRegistry::new(storage_path)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_registry() -> DevicePairingRegistry {
        DevicePairingRegistry::in_memory()
    }

    #[test]
    fn test_request_pairing_creates_pending_request() {
        let registry = test_registry();
        let result = registry.request_pairing(
            "device-1".to_string(),
            "pubkey-1".to_string(),
            vec!["operator".to_string()],
            vec!["operator.read".to_string()],
            Some("Test Device".to_string()),
            Some("darwin".to_string()),
            Some("cli".to_string()),
            None,
            None,
            None,
        );

        assert!(result.is_ok());
        let request = result.unwrap();
        assert_eq!(request.device_id, "device-1");
        assert_eq!(request.state, PairingState::Pending);
        assert!(!request.request_id.is_empty());
    }

    #[test]
    fn test_duplicate_request_returns_existing() {
        let registry = test_registry();

        let req1 = registry
            .request_pairing(
                "device-1".to_string(),
                "pubkey-1".to_string(),
                vec![],
                vec![],
                None,
                None,
                None,
                None,
                None,
                None,
            )
            .unwrap();
        let req2 = registry
            .request_pairing(
                "device-1".to_string(),
                "pubkey-1".to_string(),
                vec![],
                vec![],
                None,
                None,
                None,
                None,
                None,
                None,
            )
            .unwrap();

        assert_eq!(req1.request_id, req2.request_id);
    }

    #[test]
    fn test_public_key_mismatch_error() {
        let registry = test_registry();

        registry
            .request_pairing(
                "device-1".to_string(),
                "pubkey-1".to_string(),
                vec![],
                vec![],
                None,
                None,
                None,
                None,
                None,
                None,
            )
            .unwrap();

        let result = registry.request_pairing(
            "device-1".to_string(),
            "pubkey-2".to_string(), // Different key
            vec![],
            vec![],
            None,
            None,
            None,
            None,
            None,
            None,
        );
        assert!(matches!(result, Err(DevicePairingError::PublicKeyMismatch)));
    }

    #[test]
    fn test_approve_request() {
        let registry = test_registry();

        let req = registry
            .request_pairing(
                "device-1".to_string(),
                "pubkey-1".to_string(),
                vec!["operator".to_string()],
                vec![],
                Some("Test Device".to_string()),
                None,
                None,
                None,
                None,
                None,
            )
            .unwrap();

        let result = registry.approve_request(
            &req.request_id,
            vec!["operator".to_string()],
            vec!["operator.read".to_string()],
        );
        assert!(result.is_ok());

        let (device, token) = result.unwrap();
        assert_eq!(device.device_id, "device-1");
        assert!(!token.is_empty());

        // Device should be paired
        assert!(registry.is_paired("device-1"));

        // Request should be marked as approved
        let updated_req = registry.get_request(&req.request_id).unwrap();
        assert_eq!(updated_req.state, PairingState::Approved);
    }

    #[test]
    fn test_reject_request() {
        let registry = test_registry();

        let req = registry
            .request_pairing(
                "device-1".to_string(),
                "pubkey-1".to_string(),
                vec![],
                vec![],
                None,
                None,
                None,
                None,
                None,
                None,
            )
            .unwrap();

        let result = registry.reject_request(&req.request_id, Some("Not authorized".to_string()));
        assert!(result.is_ok());

        let rejected = result.unwrap();
        assert_eq!(rejected.state, PairingState::Rejected);
        assert_eq!(
            rejected.rejection_reason,
            Some("Not authorized".to_string())
        );

        // Device should not be paired
        assert!(!registry.is_paired("device-1"));
    }

    #[test]
    fn test_token_verification() {
        let registry = test_registry();

        // Pair a device
        let req = registry
            .request_pairing(
                "device-1".to_string(),
                "pubkey-1".to_string(),
                vec![],
                vec![],
                None,
                None,
                None,
                None,
                None,
                None,
            )
            .unwrap();
        let (_device, token) = registry
            .approve_request(&req.request_id, vec![], vec![])
            .unwrap();

        // Verify the token
        assert!(registry.verify_token("device-1", &token, None, &[]).is_ok());

        // Wrong token
        assert!(registry
            .verify_token("device-1", "wrong-token", None, &[])
            .is_err());

        // Wrong device
        assert!(registry
            .verify_token("device-2", &token, None, &[])
            .is_err());
    }

    #[test]
    fn test_revoke_tokens() {
        let registry = test_registry();

        // Pair a device
        let req = registry
            .request_pairing(
                "device-1".to_string(),
                "pubkey-1".to_string(),
                vec![],
                vec![],
                None,
                None,
                None,
                None,
                None,
                None,
            )
            .unwrap();
        let (_device, token) = registry
            .approve_request(&req.request_id, vec![], vec![])
            .unwrap();

        // Token should work
        assert!(registry.verify_token("device-1", &token, None, &[]).is_ok());

        // Revoke tokens
        registry.revoke_tokens("device-1").unwrap();

        // Token should no longer work
        assert!(matches!(
            registry.verify_token("device-1", &token, None, &[]),
            Err(DevicePairingError::TokenRevoked)
        ));
    }

    #[test]
    fn test_unpair_device() {
        let registry = test_registry();

        let req = registry
            .request_pairing(
                "device-1".to_string(),
                "pubkey-1".to_string(),
                vec![],
                vec![],
                None,
                None,
                None,
                None,
                None,
                None,
            )
            .unwrap();
        let (_device, token) = registry
            .approve_request(&req.request_id, vec![], vec![])
            .unwrap();

        assert!(registry.is_paired("device-1"));

        let unpaired = registry.unpair_device("device-1").unwrap();
        assert_eq!(unpaired.device_id, "device-1");

        assert!(!registry.is_paired("device-1"));

        // Token should be revoked
        assert!(matches!(
            registry.verify_token("device-1", &token, None, &[]),
            Err(DevicePairingError::DeviceNotPaired)
        ));
    }

    #[test]
    fn test_max_pending_requests_limit() {
        let registry = test_registry();

        // Fill up to limit
        for i in 0..MAX_PENDING_REQUESTS {
            registry
                .request_pairing(
                    format!("device-{}", i),
                    format!("pubkey-{}", i),
                    vec![],
                    vec![],
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                )
                .unwrap();
        }

        // Next request should fail
        let result = registry.request_pairing(
            "device-overflow".to_string(),
            "pubkey-overflow".to_string(),
            vec![],
            vec![],
            None,
            None,
            None,
            None,
            None,
            None,
        );
        assert!(matches!(
            result,
            Err(DevicePairingError::TooManyPendingRequests)
        ));
    }

    #[test]
    fn test_paired_device_limit_evicts_oldest() {
        let registry = test_registry();

        // Pair up to limit
        for i in 0..MAX_PAIRED_DEVICES {
            let req = registry
                .request_pairing(
                    format!("device-{}", i),
                    format!("pubkey-{}", i),
                    vec![],
                    vec![],
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                )
                .unwrap();
            registry
                .approve_request(&req.request_id, vec![], vec![])
                .unwrap();
        }

        assert!(registry.is_paired("device-0"));

        // Next pairing should evict oldest
        let req = registry
            .request_pairing(
                "device-new".to_string(),
                "pubkey-new".to_string(),
                vec![],
                vec![],
                None,
                None,
                None,
                None,
                None,
                None,
            )
            .unwrap();
        registry
            .approve_request(&req.request_id, vec![], vec![])
            .unwrap();

        assert!(registry.is_paired("device-new"));
        assert!(
            !registry.is_paired("device-0"),
            "oldest device should be evicted"
        );
    }

    #[test]
    fn test_pairing_state_transitions() {
        let mut request = DevicePairingRequest::new(
            "device-1".to_string(),
            "pubkey-1".to_string(),
            vec![],
            vec![],
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        );

        assert_eq!(request.state, PairingState::Pending);
        assert!(!request.is_expired());

        request.approve();
        assert_eq!(request.state, PairingState::Approved);
        assert!(request.resolved_at_ms.is_some());

        // Test rejection
        let mut request2 = DevicePairingRequest::new(
            "device-2".to_string(),
            "pubkey-2".to_string(),
            vec![],
            vec![],
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        );
        request2.reject(Some("test reason".to_string()));
        assert_eq!(request2.state, PairingState::Rejected);
        assert_eq!(request2.rejection_reason, Some("test reason".to_string()));
    }
}
