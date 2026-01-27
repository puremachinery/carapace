//! Node pairing and registry module
//!
//! Manages node pairing state machine (request -> pending -> approved/rejected),
//! token verification, and node event delivery.

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

/// Maximum number of paired nodes
pub const MAX_PAIRED_NODES: usize = 100;

/// Maximum number of pending pairing requests
pub const MAX_PENDING_REQUESTS: usize = 50;

/// Maximum number of node tokens
pub const MAX_NODE_TOKENS: usize = 500;

/// Pairing request expiry (24 hours)
pub const PAIRING_REQUEST_EXPIRY_MS: u64 = 24 * 60 * 60 * 1000;

/// Node token expiry (30 days)
pub const NODE_TOKEN_EXPIRY_MS: u64 = 30 * 24 * 60 * 60 * 1000;

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

/// A node pairing request
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NodePairingRequest {
    /// Unique request ID
    pub request_id: String,
    /// Node ID requesting pairing
    pub node_id: String,
    /// Optional public key for verification
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
    /// Current state of the request
    pub state: PairingState,
    /// Commands the node wants to expose
    #[serde(default)]
    pub commands: Vec<String>,
    /// Display name for the node
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    /// Platform identifier
    #[serde(skip_serializing_if = "Option::is_none")]
    pub platform: Option<String>,
    /// Node version
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Core version (for split-version nodes)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub core_version: Option<String>,
    /// UI version (for split-version nodes)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ui_version: Option<String>,
    /// Device family (e.g., "iPhone", "iPad", "Mac")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_family: Option<String>,
    /// Model identifier (e.g., "iPhone13,3")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model_identifier: Option<String>,
    /// Node capabilities
    #[serde(default)]
    pub caps: Vec<String>,
    /// Node permissions
    #[serde(skip_serializing_if = "Option::is_none")]
    pub permissions: Option<HashMap<String, bool>>,
    /// Remote IP address
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_ip: Option<String>,
    /// Whether the request was made silently (for auto-approval flows)
    #[serde(default)]
    pub silent: bool,
    /// Whether this is a repair request (node was previously paired)
    #[serde(default)]
    pub is_repair: bool,
    /// Timestamp when request was created (Unix ms)
    pub created_at_ms: u64,
    /// Timestamp when request was resolved (Unix ms)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolved_at_ms: Option<u64>,
    /// Reason for rejection (if rejected)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rejection_reason: Option<String>,
}

pub struct NodePairingOutcome {
    pub request: NodePairingRequest,
    pub created: bool,
}

/// Builder for NodePairingRequest
#[derive(Debug, Clone, Default)]
pub struct NodePairingRequestBuilder {
    pub node_id: String,
    pub public_key: Option<String>,
    pub commands: Vec<String>,
    pub display_name: Option<String>,
    pub platform: Option<String>,
    pub version: Option<String>,
    pub core_version: Option<String>,
    pub ui_version: Option<String>,
    pub device_family: Option<String>,
    pub model_identifier: Option<String>,
    pub caps: Vec<String>,
    pub permissions: Option<HashMap<String, bool>>,
    pub remote_ip: Option<String>,
    pub silent: bool,
}

impl NodePairingRequestBuilder {
    pub fn new(node_id: String) -> Self {
        Self {
            node_id,
            ..Default::default()
        }
    }
}

impl NodePairingRequest {
    /// Create a new pending pairing request (legacy API for backward compatibility)
    pub fn new(
        node_id: String,
        public_key: Option<String>,
        commands: Vec<String>,
        display_name: Option<String>,
        platform: Option<String>,
    ) -> Self {
        Self::from_builder(
            NodePairingRequestBuilder {
                node_id,
                public_key,
                commands,
                display_name,
                platform,
                ..Default::default()
            },
            false,
        )
    }

    /// Create a new pending pairing request from builder
    pub fn from_builder(builder: NodePairingRequestBuilder, is_repair: bool) -> Self {
        Self {
            request_id: Uuid::new_v4().to_string(),
            node_id: builder.node_id,
            public_key: builder.public_key,
            state: PairingState::Pending,
            commands: builder.commands,
            display_name: builder.display_name,
            platform: builder.platform,
            version: builder.version,
            core_version: builder.core_version,
            ui_version: builder.ui_version,
            device_family: builder.device_family,
            model_identifier: builder.model_identifier,
            caps: builder.caps,
            permissions: builder.permissions,
            remote_ip: builder.remote_ip,
            silent: builder.silent,
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

/// A paired node
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PairedNode {
    /// Node ID
    pub node_id: String,
    /// Optional public key for verification
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
    /// Allowed commands for this node
    #[serde(default)]
    pub commands: Vec<String>,
    /// Display name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    /// Platform identifier
    #[serde(skip_serializing_if = "Option::is_none")]
    pub platform: Option<String>,
    /// Node version
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Core version (for split-version nodes)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub core_version: Option<String>,
    /// UI version (for split-version nodes)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ui_version: Option<String>,
    /// Device family (e.g., "iPhone", "iPad", "Mac")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_family: Option<String>,
    /// Model identifier (e.g., "iPhone13,3")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model_identifier: Option<String>,
    /// Node capabilities
    #[serde(default)]
    pub caps: Vec<String>,
    /// Node permissions
    #[serde(skip_serializing_if = "Option::is_none")]
    pub permissions: Option<HashMap<String, bool>>,
    /// Remote IP address
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_ip: Option<String>,
    /// Timestamp when originally created (Unix ms)
    pub created_at_ms: u64,
    /// Timestamp when approved/paired (Unix ms)
    pub paired_at_ms: u64,
    /// Last seen timestamp (Unix ms)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_seen_ms: Option<u64>,
}

impl PairedNode {
    /// Create from an approved pairing request
    pub fn from_request(request: &NodePairingRequest, existing_created_at: Option<u64>) -> Self {
        let now = now_ms();
        Self {
            node_id: request.node_id.clone(),
            public_key: request.public_key.clone(),
            commands: request.commands.clone(),
            display_name: request.display_name.clone(),
            platform: request.platform.clone(),
            version: request.version.clone(),
            core_version: request.core_version.clone(),
            ui_version: request.ui_version.clone(),
            device_family: request.device_family.clone(),
            model_identifier: request.model_identifier.clone(),
            caps: request.caps.clone(),
            permissions: request.permissions.clone(),
            remote_ip: request.remote_ip.clone(),
            created_at_ms: existing_created_at.unwrap_or(now),
            paired_at_ms: now,
            last_seen_ms: None,
        }
    }

    /// Update last seen timestamp
    pub fn touch(&mut self) {
        self.last_seen_ms = Some(now_ms());
    }
}

/// A node authentication token
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NodeToken {
    /// Token value
    pub token: String,
    /// Token hash for secure storage
    pub token_hash: String,
    /// Node ID this token belongs to
    pub node_id: String,
    /// Issued timestamp (Unix ms)
    pub issued_at_ms: u64,
    /// Expiry timestamp (Unix ms)
    pub expires_at_ms: u64,
    /// Whether this token has been revoked
    pub revoked: bool,
}

impl NodeToken {
    /// Create a new token for a node
    pub fn new(node_id: String) -> (Self, String) {
        let token = Uuid::new_v4().to_string();
        let token_hash = hash_token(&token);
        let now = now_ms();
        (
            Self {
                token: String::new(), // Don't store plain token
                token_hash,
                node_id,
                issued_at_ms: now,
                expires_at_ms: now + NODE_TOKEN_EXPIRY_MS,
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

/// Persistent store for node pairing data
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NodePairingStore {
    /// Version for schema migration
    pub version: u32,
    /// Pending pairing requests by request_id
    #[serde(default)]
    pub pending_requests: HashMap<String, NodePairingRequest>,
    /// Paired nodes by node_id
    #[serde(default)]
    pub paired_nodes: HashMap<String, PairedNode>,
    /// Tokens by token_hash
    #[serde(default)]
    pub tokens: HashMap<String, NodeToken>,
}

impl NodePairingStore {
    pub const VERSION: u32 = 1;

    pub fn new() -> Self {
        Self {
            version: Self::VERSION,
            pending_requests: HashMap::new(),
            paired_nodes: HashMap::new(),
            tokens: HashMap::new(),
        }
    }
}

/// Errors that can occur during node pairing operations
#[derive(Debug, Clone, PartialEq)]
pub enum NodePairingError {
    /// Request not found
    RequestNotFound,
    /// Request already resolved
    RequestAlreadyResolved,
    /// Request expired
    RequestExpired,
    /// Node not paired
    NodeNotPaired,
    /// Node already paired
    NodeAlreadyPaired,
    /// Token invalid
    TokenInvalid,
    /// Token expired
    TokenExpired,
    /// Token revoked
    TokenRevoked,
    /// Too many pending requests
    TooManyPendingRequests,
    /// Too many paired nodes
    TooManyPairedNodes,
    /// I/O error
    IoError(String),
    /// JSON error
    JsonError(String),
}

impl std::fmt::Display for NodePairingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RequestNotFound => write!(f, "pairing request not found"),
            Self::RequestAlreadyResolved => write!(f, "pairing request already resolved"),
            Self::RequestExpired => write!(f, "pairing request expired"),
            Self::NodeNotPaired => write!(f, "node not paired"),
            Self::NodeAlreadyPaired => write!(f, "node already paired"),
            Self::TokenInvalid => write!(f, "token invalid"),
            Self::TokenExpired => write!(f, "token expired"),
            Self::TokenRevoked => write!(f, "token revoked"),
            Self::TooManyPendingRequests => write!(f, "too many pending pairing requests"),
            Self::TooManyPairedNodes => write!(f, "too many paired nodes"),
            Self::IoError(msg) => write!(f, "I/O error: {}", msg),
            Self::JsonError(msg) => write!(f, "JSON error: {}", msg),
        }
    }
}

impl std::error::Error for NodePairingError {}

/// Thread-safe node pairing registry with persistence
pub struct NodePairingRegistry {
    /// In-memory store
    store: RwLock<NodePairingStore>,
    /// Path to persistent storage
    storage_path: PathBuf,
    /// Whether to auto-save on changes
    auto_save: bool,
}

impl std::fmt::Debug for NodePairingRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodePairingRegistry")
            .field("storage_path", &self.storage_path)
            .field("auto_save", &self.auto_save)
            .finish()
    }
}

impl NodePairingRegistry {
    /// Create a new registry with the given storage path
    pub fn new(storage_path: PathBuf) -> Result<Self, NodePairingError> {
        let store = Self::load_or_create(&storage_path)?;
        Ok(Self {
            store: RwLock::new(store),
            storage_path,
            auto_save: true,
        })
    }

    /// Create an in-memory only registry (for testing)
    pub fn in_memory() -> Self {
        Self {
            store: RwLock::new(NodePairingStore::new()),
            storage_path: PathBuf::new(),
            auto_save: false,
        }
    }

    /// Load store from disk or create a new one
    fn load_or_create(path: &PathBuf) -> Result<NodePairingStore, NodePairingError> {
        if !path.exists() {
            return Ok(NodePairingStore::new());
        }

        let content =
            fs::read_to_string(path).map_err(|e| NodePairingError::IoError(e.to_string()))?;

        serde_json::from_str(&content).map_err(|e| {
            // If corrupted, backup and create new
            let timestamp = now_ms();
            let backup = path.with_extension(format!("corrupt.{}.json", timestamp));
            if let Err(err) = fs::rename(path, &backup) {
                tracing::warn!(
                    path = %path.display(),
                    backup = %backup.display(),
                    error = %err,
                    "failed to backup corrupted node pairing store"
                );
            } else {
                tracing::warn!(
                    path = %path.display(),
                    backup = %backup.display(),
                    "backed up corrupted node pairing store"
                );
            }
            NodePairingError::JsonError(e.to_string())
        })
    }

    /// Save store to disk
    fn save(&self) -> Result<(), NodePairingError> {
        if !self.auto_save || self.storage_path.as_os_str().is_empty() {
            return Ok(());
        }

        let store = self.store.read();
        let content = serde_json::to_string_pretty(&*store)
            .map_err(|e| NodePairingError::JsonError(e.to_string()))?;
        drop(store);

        // Ensure parent directory exists
        if let Some(parent) = self.storage_path.parent() {
            fs::create_dir_all(parent).map_err(|e| NodePairingError::IoError(e.to_string()))?;
        }

        // Write atomically
        let temp_path = self.storage_path.with_extension("tmp");
        let mut file =
            File::create(&temp_path).map_err(|e| NodePairingError::IoError(e.to_string()))?;
        IoWrite::write_all(&mut file, content.as_bytes())
            .map_err(|e| NodePairingError::IoError(e.to_string()))?;
        file.sync_all()
            .map_err(|e| NodePairingError::IoError(e.to_string()))?;
        fs::rename(&temp_path, &self.storage_path)
            .map_err(|e| NodePairingError::IoError(e.to_string()))?;

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

    /// Create a new pairing request (legacy API for backward compatibility)
    pub fn request_pairing(
        &self,
        node_id: String,
        public_key: Option<String>,
        commands: Vec<String>,
        display_name: Option<String>,
        platform: Option<String>,
    ) -> Result<NodePairingRequest, NodePairingError> {
        let builder = NodePairingRequestBuilder {
            node_id,
            public_key,
            commands,
            display_name,
            platform,
            ..Default::default()
        };
        let outcome = self.request_pairing_with_builder(builder)?;
        Ok(outcome.request)
    }

    /// Create a new pairing request (legacy API for backward compatibility)
    pub fn request_pairing_with_status(
        &self,
        node_id: String,
        public_key: Option<String>,
        commands: Vec<String>,
        display_name: Option<String>,
        platform: Option<String>,
    ) -> Result<NodePairingOutcome, NodePairingError> {
        let builder = NodePairingRequestBuilder {
            node_id,
            public_key,
            commands,
            display_name,
            platform,
            ..Default::default()
        };
        self.request_pairing_with_builder(builder)
    }

    /// Create a new pairing request with full options
    pub fn request_pairing_with_builder(
        &self,
        builder: NodePairingRequestBuilder,
    ) -> Result<NodePairingOutcome, NodePairingError> {
        self.cleanup_expired();

        let mut store = self.store.write();

        let node_id = &builder.node_id;

        // Check for existing pending request for this node
        if let Some(existing) = store
            .pending_requests
            .values()
            .find(|r| &r.node_id == node_id && r.state == PairingState::Pending)
        {
            return Ok(NodePairingOutcome {
                request: existing.clone(),
                created: false,
            });
        }

        // Check if node is already paired (this is a repair request)
        let is_repair = store.paired_nodes.contains_key(node_id);

        // Check pending request limit
        let pending_count = store
            .pending_requests
            .values()
            .filter(|r| r.state == PairingState::Pending)
            .count();
        if pending_count >= MAX_PENDING_REQUESTS {
            return Err(NodePairingError::TooManyPendingRequests);
        }

        let request = NodePairingRequest::from_builder(builder, is_repair);
        store
            .pending_requests
            .insert(request.request_id.clone(), request.clone());
        drop(store);

        let _ = self.save();
        Ok(NodePairingOutcome {
            request,
            created: true,
        })
    }

    /// List all pairing requests (pending and recent resolved)
    pub fn list_requests(&self) -> (Vec<NodePairingRequest>, Vec<NodePairingRequest>) {
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
    pub fn get_request(&self, request_id: &str) -> Option<NodePairingRequest> {
        let store = self.store.read();
        store.pending_requests.get(request_id).cloned()
    }

    /// Approve a pairing request
    pub fn approve_request(
        &self,
        request_id: &str,
    ) -> Result<(PairedNode, String), NodePairingError> {
        let mut store = self.store.write();

        // First, validate and get the request info without holding the mutable borrow
        let request = store
            .pending_requests
            .get(request_id)
            .ok_or(NodePairingError::RequestNotFound)?;

        if request.state != PairingState::Pending {
            return Err(NodePairingError::RequestAlreadyResolved);
        }

        if request.is_expired() {
            // Mark as expired
            if let Some(req) = store.pending_requests.get_mut(request_id) {
                req.mark_expired();
            }
            return Err(NodePairingError::RequestExpired);
        }

        // Clone the full request to use for creating the paired node
        let request_clone = request.clone();
        let node_id = request.node_id.clone();

        // Check paired node limit and evict if needed
        if store.paired_nodes.len() >= MAX_PAIRED_NODES {
            // Evict oldest paired node
            if let Some(oldest_id) = store
                .paired_nodes
                .values()
                .min_by(|a, b| {
                    (a.paired_at_ms, a.node_id.as_str()).cmp(&(b.paired_at_ms, b.node_id.as_str()))
                })
                .map(|n| n.node_id.clone())
            {
                store.paired_nodes.remove(&oldest_id);
                // Remove tokens for evicted node
                store.tokens.retain(|_, t| t.node_id != oldest_id);
            }
        }

        // Get existing created_at if this is a re-pair (repair) situation
        let existing_created_at = store.paired_nodes.get(&node_id).map(|n| n.created_at_ms);

        // Now approve the request
        if let Some(req) = store.pending_requests.get_mut(request_id) {
            req.approve();
        }

        // Create the paired node from the full request
        let paired_node = PairedNode::from_request(&request_clone, existing_created_at);
        store
            .paired_nodes
            .insert(node_id.clone(), paired_node.clone());

        // Issue a token for the newly paired node
        let (token_entry, plain_token) = NodeToken::new(node_id);
        store
            .tokens
            .insert(token_entry.token_hash.clone(), token_entry);

        drop(store);
        let _ = self.save();

        Ok((paired_node, plain_token))
    }

    /// Reject a pairing request
    pub fn reject_request(
        &self,
        request_id: &str,
        reason: Option<String>,
    ) -> Result<NodePairingRequest, NodePairingError> {
        let mut store = self.store.write();

        let request = store
            .pending_requests
            .get_mut(request_id)
            .ok_or(NodePairingError::RequestNotFound)?;

        if request.state != PairingState::Pending {
            return Err(NodePairingError::RequestAlreadyResolved);
        }

        request.reject(reason);
        let result = request.clone();
        drop(store);

        let _ = self.save();
        Ok(result)
    }

    // === Paired Node Methods ===

    /// List all paired nodes
    pub fn list_paired_nodes(&self) -> Vec<PairedNode> {
        let store = self.store.read();
        store.paired_nodes.values().cloned().collect()
    }

    /// Get a specific paired node
    pub fn get_paired_node(&self, node_id: &str) -> Option<PairedNode> {
        let store = self.store.read();
        store.paired_nodes.get(node_id).cloned()
    }

    /// Check if a node is paired
    pub fn is_paired(&self, node_id: &str) -> bool {
        let store = self.store.read();
        store.paired_nodes.contains_key(node_id)
    }

    /// Rename a paired node
    pub fn rename_node(
        &self,
        node_id: &str,
        new_name: String,
    ) -> Result<PairedNode, NodePairingError> {
        let mut store = self.store.write();
        let node = store
            .paired_nodes
            .get_mut(node_id)
            .ok_or(NodePairingError::NodeNotPaired)?;
        node.display_name = Some(new_name);
        let result = node.clone();
        drop(store);

        let _ = self.save();
        Ok(result)
    }

    /// Update last seen time for a node
    pub fn touch_node(&self, node_id: &str) {
        let mut store = self.store.write();
        if let Some(node) = store.paired_nodes.get_mut(node_id) {
            node.touch();
        }
        // Don't save on every touch to avoid excessive I/O
    }

    /// Unpair a node
    pub fn unpair_node(&self, node_id: &str) -> Result<PairedNode, NodePairingError> {
        let mut store = self.store.write();
        let node = store
            .paired_nodes
            .remove(node_id)
            .ok_or(NodePairingError::NodeNotPaired)?;

        // Revoke all tokens for this node
        for token in store.tokens.values_mut() {
            if token.node_id == node_id {
                token.revoke();
            }
        }

        drop(store);
        let _ = self.save();
        Ok(node)
    }

    // === Token Methods ===

    /// Verify a node token
    pub fn verify_token(&self, node_id: &str, token: &str) -> Result<(), NodePairingError> {
        let store = self.store.read();

        // Check if node is paired
        if !store.paired_nodes.contains_key(node_id) {
            return Err(NodePairingError::NodeNotPaired);
        }

        // Find and verify token
        let token_hash = hash_token(token);
        let token_entry = store
            .tokens
            .get(&token_hash)
            .ok_or(NodePairingError::TokenInvalid)?;

        if token_entry.node_id != node_id {
            return Err(NodePairingError::TokenInvalid);
        }

        if token_entry.revoked {
            return Err(NodePairingError::TokenRevoked);
        }

        if now_ms() >= token_entry.expires_at_ms {
            return Err(NodePairingError::TokenExpired);
        }

        Ok(())
    }

    /// Issue a new token for a paired node
    pub fn issue_token(&self, node_id: &str) -> Result<String, NodePairingError> {
        let mut store = self.store.write();

        if !store.paired_nodes.contains_key(node_id) {
            return Err(NodePairingError::NodeNotPaired);
        }

        // Clean up old tokens for this node
        let now = now_ms();
        store
            .tokens
            .retain(|_, t| t.node_id != node_id || (t.is_valid() && t.expires_at_ms > now));

        // Check token limit
        if store.tokens.len() >= MAX_NODE_TOKENS {
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

        let (token_entry, plain_token) = NodeToken::new(node_id.to_string());
        store
            .tokens
            .insert(token_entry.token_hash.clone(), token_entry);

        drop(store);
        let _ = self.save();

        Ok(plain_token)
    }

    /// Revoke all tokens for a node
    pub fn revoke_tokens(&self, node_id: &str) -> Result<usize, NodePairingError> {
        let mut store = self.store.write();

        if !store.paired_nodes.contains_key(node_id) {
            return Err(NodePairingError::NodeNotPaired);
        }

        let mut count = 0;
        for token in store.tokens.values_mut() {
            if token.node_id == node_id && !token.revoked {
                token.revoke();
                count += 1;
            }
        }

        drop(store);
        let _ = self.save();

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

/// Create a shared node pairing registry
pub fn create_registry(state_dir: PathBuf) -> Result<Arc<NodePairingRegistry>, NodePairingError> {
    let storage_path = state_dir.join("node-pairing.json");
    Ok(Arc::new(NodePairingRegistry::new(storage_path)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_registry() -> NodePairingRegistry {
        NodePairingRegistry::in_memory()
    }

    #[test]
    fn test_request_pairing_creates_pending_request() {
        let registry = test_registry();
        let result = registry.request_pairing(
            "node-1".to_string(),
            Some("pubkey-1".to_string()),
            vec!["system.run".to_string()],
            Some("Test Node".to_string()),
            Some("darwin".to_string()),
        );

        assert!(result.is_ok());
        let request = result.unwrap();
        assert_eq!(request.node_id, "node-1");
        assert_eq!(request.state, PairingState::Pending);
        assert!(!request.request_id.is_empty());
    }

    #[test]
    fn test_duplicate_request_returns_existing() {
        let registry = test_registry();

        let req1 = registry
            .request_pairing("node-1".to_string(), None, vec![], None, None)
            .unwrap();
        let req2 = registry
            .request_pairing("node-1".to_string(), None, vec![], None, None)
            .unwrap();

        assert_eq!(req1.request_id, req2.request_id);
    }

    #[test]
    fn test_already_paired_node_can_request_repair() {
        let registry = test_registry();

        // Create and approve a request
        let req = registry
            .request_pairing("node-1".to_string(), None, vec![], None, None)
            .unwrap();
        assert!(!req.is_repair, "first request should not be a repair");
        registry.approve_request(&req.request_id).unwrap();

        // Try to request again - should succeed as a repair request
        let result = registry.request_pairing_with_builder(NodePairingRequestBuilder {
            node_id: "node-1".to_string(),
            ..Default::default()
        });
        assert!(result.is_ok(), "repair request should succeed");
        let outcome = result.unwrap();
        assert!(
            outcome.request.is_repair,
            "second request should be a repair"
        );
        assert!(
            outcome.created,
            "repair request should create a new pending request"
        );
    }

    #[test]
    fn test_approve_request() {
        let registry = test_registry();

        let req = registry
            .request_pairing(
                "node-1".to_string(),
                Some("pubkey-1".to_string()),
                vec!["system.run".to_string()],
                Some("Test Node".to_string()),
                None,
            )
            .unwrap();

        let result = registry.approve_request(&req.request_id);
        assert!(result.is_ok());

        let (node, token) = result.unwrap();
        assert_eq!(node.node_id, "node-1");
        assert!(!token.is_empty());

        // Node should be paired
        assert!(registry.is_paired("node-1"));

        // Request should be marked as approved
        let updated_req = registry.get_request(&req.request_id).unwrap();
        assert_eq!(updated_req.state, PairingState::Approved);
    }

    #[test]
    fn test_reject_request() {
        let registry = test_registry();

        let req = registry
            .request_pairing("node-1".to_string(), None, vec![], None, None)
            .unwrap();

        let result = registry.reject_request(&req.request_id, Some("Not authorized".to_string()));
        assert!(result.is_ok());

        let rejected = result.unwrap();
        assert_eq!(rejected.state, PairingState::Rejected);
        assert_eq!(
            rejected.rejection_reason,
            Some("Not authorized".to_string())
        );

        // Node should not be paired
        assert!(!registry.is_paired("node-1"));
    }

    #[test]
    fn test_cannot_resolve_already_resolved_request() {
        let registry = test_registry();

        let req = registry
            .request_pairing("node-1".to_string(), None, vec![], None, None)
            .unwrap();
        registry.approve_request(&req.request_id).unwrap();

        // Try to reject the already approved request
        let result = registry.reject_request(&req.request_id, None);
        assert!(matches!(
            result,
            Err(NodePairingError::RequestAlreadyResolved)
        ));
    }

    #[test]
    fn test_list_requests() {
        let registry = test_registry();

        // Create some requests
        let req1 = registry
            .request_pairing("node-1".to_string(), None, vec![], None, None)
            .unwrap();
        let req2 = registry
            .request_pairing("node-2".to_string(), None, vec![], None, None)
            .unwrap();
        let _req3 = registry
            .request_pairing("node-3".to_string(), None, vec![], None, None)
            .unwrap();

        // Approve one, reject one
        registry.approve_request(&req1.request_id).unwrap();
        registry.reject_request(&req2.request_id, None).unwrap();

        let (pending, resolved) = registry.list_requests();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].node_id, "node-3");
        assert_eq!(resolved.len(), 2);
    }

    #[test]
    fn test_token_verification() {
        let registry = test_registry();

        // Pair a node
        let req = registry
            .request_pairing("node-1".to_string(), None, vec![], None, None)
            .unwrap();
        let (_node, token) = registry.approve_request(&req.request_id).unwrap();

        // Verify the token
        assert!(registry.verify_token("node-1", &token).is_ok());

        // Wrong token
        assert!(registry.verify_token("node-1", "wrong-token").is_err());

        // Wrong node
        assert!(registry.verify_token("node-2", &token).is_err());
    }

    #[test]
    fn test_revoke_tokens() {
        let registry = test_registry();

        // Pair a node
        let req = registry
            .request_pairing("node-1".to_string(), None, vec![], None, None)
            .unwrap();
        let (_node, token) = registry.approve_request(&req.request_id).unwrap();

        // Token should work
        assert!(registry.verify_token("node-1", &token).is_ok());

        // Revoke tokens
        registry.revoke_tokens("node-1").unwrap();

        // Token should no longer work
        assert!(matches!(
            registry.verify_token("node-1", &token),
            Err(NodePairingError::TokenRevoked)
        ));
    }

    #[test]
    fn test_rename_node() {
        let registry = test_registry();

        let req = registry
            .request_pairing(
                "node-1".to_string(),
                None,
                vec![],
                Some("Old Name".to_string()),
                None,
            )
            .unwrap();
        registry.approve_request(&req.request_id).unwrap();

        let result = registry.rename_node("node-1", "New Name".to_string());
        assert!(result.is_ok());

        let node = registry.get_paired_node("node-1").unwrap();
        assert_eq!(node.display_name, Some("New Name".to_string()));
    }

    #[test]
    fn test_unpair_node() {
        let registry = test_registry();

        let req = registry
            .request_pairing("node-1".to_string(), None, vec![], None, None)
            .unwrap();
        let (_node, token) = registry.approve_request(&req.request_id).unwrap();

        assert!(registry.is_paired("node-1"));

        let unpaired = registry.unpair_node("node-1").unwrap();
        assert_eq!(unpaired.node_id, "node-1");

        assert!(!registry.is_paired("node-1"));

        // Token should be revoked
        assert!(matches!(
            registry.verify_token("node-1", &token),
            Err(NodePairingError::NodeNotPaired)
        ));
    }

    #[test]
    fn test_max_pending_requests_limit() {
        let registry = test_registry();

        // Fill up to limit
        for i in 0..MAX_PENDING_REQUESTS {
            registry
                .request_pairing(format!("node-{}", i), None, vec![], None, None)
                .unwrap();
        }

        // Next request should fail
        let result =
            registry.request_pairing("node-overflow".to_string(), None, vec![], None, None);
        assert!(matches!(
            result,
            Err(NodePairingError::TooManyPendingRequests)
        ));
    }

    #[test]
    fn test_paired_node_limit_evicts_oldest() {
        let registry = test_registry();

        // Pair up to limit
        for i in 0..MAX_PAIRED_NODES {
            let req = registry
                .request_pairing(format!("node-{}", i), None, vec![], None, None)
                .unwrap();
            registry.approve_request(&req.request_id).unwrap();
        }

        assert!(registry.is_paired("node-0"));

        // Next pairing should evict oldest
        let req = registry
            .request_pairing("node-new".to_string(), None, vec![], None, None)
            .unwrap();
        registry.approve_request(&req.request_id).unwrap();

        assert!(registry.is_paired("node-new"));
        assert!(
            !registry.is_paired("node-0"),
            "oldest node should be evicted"
        );
    }

    #[test]
    fn test_request_not_found() {
        let registry = test_registry();

        let result = registry.approve_request("nonexistent");
        assert!(matches!(result, Err(NodePairingError::RequestNotFound)));
    }

    #[test]
    fn test_pairing_state_transitions() {
        let mut request = NodePairingRequest::new("node-1".to_string(), None, vec![], None, None);

        assert_eq!(request.state, PairingState::Pending);
        assert!(!request.is_expired());

        request.approve();
        assert_eq!(request.state, PairingState::Approved);
        assert!(request.resolved_at_ms.is_some());

        // Test rejection
        let mut request2 = NodePairingRequest::new("node-2".to_string(), None, vec![], None, None);
        request2.reject(Some("test reason".to_string()));
        assert_eq!(request2.state, PairingState::Rejected);
        assert_eq!(request2.rejection_reason, Some("test reason".to_string()));
    }

    #[test]
    fn test_issue_new_token() {
        let registry = test_registry();

        let req = registry
            .request_pairing("node-1".to_string(), None, vec![], None, None)
            .unwrap();
        let (_node, token1) = registry.approve_request(&req.request_id).unwrap();

        // Issue a new token
        let token2 = registry.issue_token("node-1").unwrap();

        // Both tokens should work
        assert!(registry.verify_token("node-1", &token1).is_ok());
        assert!(registry.verify_token("node-1", &token2).is_ok());
        assert_ne!(token1, token2);
    }

    #[test]
    fn test_constant_time_eq() {
        assert!(constant_time_eq("abc", "abc"));
        assert!(!constant_time_eq("abc", "abd"));
        assert!(!constant_time_eq("abc", "ab"));
        assert!(!constant_time_eq("ab", "abc"));
        assert!(constant_time_eq("", ""));
    }

    #[test]
    fn test_extended_fields_in_pairing_request() {
        let mut permissions = HashMap::new();
        permissions.insert("camera".to_string(), true);
        permissions.insert("location".to_string(), false);

        let builder = NodePairingRequestBuilder {
            node_id: "node-extended".to_string(),
            public_key: Some("pubkey".to_string()),
            commands: vec!["cmd1".to_string(), "cmd2".to_string()],
            display_name: Some("Extended Node".to_string()),
            platform: Some("ios".to_string()),
            version: Some("2.0.0".to_string()),
            core_version: Some("1.5.0".to_string()),
            ui_version: Some("2.0.0-beta".to_string()),
            device_family: Some("iPhone".to_string()),
            model_identifier: Some("iPhone14,2".to_string()),
            caps: vec!["audio".to_string(), "camera".to_string()],
            permissions: Some(permissions.clone()),
            remote_ip: Some("192.168.1.100".to_string()),
            silent: true,
        };

        let request = NodePairingRequest::from_builder(builder, false);

        assert_eq!(request.node_id, "node-extended");
        assert_eq!(request.version, Some("2.0.0".to_string()));
        assert_eq!(request.core_version, Some("1.5.0".to_string()));
        assert_eq!(request.ui_version, Some("2.0.0-beta".to_string()));
        assert_eq!(request.device_family, Some("iPhone".to_string()));
        assert_eq!(request.model_identifier, Some("iPhone14,2".to_string()));
        assert_eq!(
            request.caps,
            vec!["audio".to_string(), "camera".to_string()]
        );
        assert_eq!(request.permissions, Some(permissions));
        assert_eq!(request.remote_ip, Some("192.168.1.100".to_string()));
        assert!(request.silent);
        assert!(!request.is_repair);
    }

    #[test]
    fn test_extended_fields_carried_to_paired_node() {
        let registry = test_registry();

        let mut permissions = HashMap::new();
        permissions.insert("filesystem".to_string(), true);

        let builder = NodePairingRequestBuilder {
            node_id: "node-carry-fields".to_string(),
            public_key: None,
            commands: vec!["system.run".to_string()],
            display_name: Some("Carry Fields Node".to_string()),
            platform: Some("darwin".to_string()),
            version: Some("3.0.0".to_string()),
            core_version: Some("2.5.0".to_string()),
            ui_version: Some("3.0.0".to_string()),
            device_family: Some("Mac".to_string()),
            model_identifier: Some("MacBookPro18,3".to_string()),
            caps: vec!["exec".to_string()],
            permissions: Some(permissions.clone()),
            remote_ip: Some("10.0.0.50".to_string()),
            silent: false,
        };

        let outcome = registry.request_pairing_with_builder(builder).unwrap();
        let (paired_node, _token) = registry
            .approve_request(&outcome.request.request_id)
            .unwrap();

        assert_eq!(paired_node.node_id, "node-carry-fields");
        assert_eq!(paired_node.version, Some("3.0.0".to_string()));
        assert_eq!(paired_node.core_version, Some("2.5.0".to_string()));
        assert_eq!(paired_node.ui_version, Some("3.0.0".to_string()));
        assert_eq!(paired_node.device_family, Some("Mac".to_string()));
        assert_eq!(
            paired_node.model_identifier,
            Some("MacBookPro18,3".to_string())
        );
        assert_eq!(paired_node.caps, vec!["exec".to_string()]);
        assert_eq!(paired_node.permissions, Some(permissions));
        assert_eq!(paired_node.remote_ip, Some("10.0.0.50".to_string()));
        assert!(paired_node.created_at_ms > 0);
        assert!(paired_node.paired_at_ms > 0);
    }

    #[test]
    fn test_repair_preserves_created_at_ms() {
        let registry = test_registry();

        // First pairing
        let builder1 = NodePairingRequestBuilder {
            node_id: "node-repair-test".to_string(),
            display_name: Some("Repair Test Node".to_string()),
            ..Default::default()
        };
        let outcome1 = registry.request_pairing_with_builder(builder1).unwrap();
        let (first_node, _) = registry
            .approve_request(&outcome1.request.request_id)
            .unwrap();
        let original_created_at = first_node.created_at_ms;

        // Wait a tiny bit to ensure timestamps are different
        std::thread::sleep(std::time::Duration::from_millis(10));

        // Re-pair (repair)
        let builder2 = NodePairingRequestBuilder {
            node_id: "node-repair-test".to_string(),
            display_name: Some("Repair Test Node Updated".to_string()),
            version: Some("2.0.0".to_string()),
            ..Default::default()
        };
        let outcome2 = registry.request_pairing_with_builder(builder2).unwrap();
        assert!(outcome2.request.is_repair);

        let (repaired_node, _) = registry
            .approve_request(&outcome2.request.request_id)
            .unwrap();

        // created_at_ms should be preserved from the original pairing
        assert_eq!(repaired_node.created_at_ms, original_created_at);
        // paired_at_ms should be updated
        assert!(repaired_node.paired_at_ms > original_created_at);
        // New fields should be updated
        assert_eq!(
            repaired_node.display_name,
            Some("Repair Test Node Updated".to_string())
        );
        assert_eq!(repaired_node.version, Some("2.0.0".to_string()));
    }
}
