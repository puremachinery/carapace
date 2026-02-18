//! OAuth2 authentication profiles
//!
//! Multi-provider OAuth2 authentication supporting Google, GitHub, and Discord.
//! Each profile stores OAuth2 tokens, supports token refresh, and can be managed
//! via WS methods. Profiles are persisted to disk as JSON.

use base64::Engine as _;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::sync::LazyLock;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::config::secrets::{is_encrypted, SecretStore};

/// Maximum number of auth profiles that can be stored.
const MAX_PROFILES: usize = 20;

/// Shared HTTP client for all OAuth2 requests, with a 30-second timeout.
static OAUTH_CLIENT: LazyLock<reqwest::Client> = LazyLock::new(|| {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
});

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors that can occur during auth profile operations.
#[derive(Debug)]
pub enum AuthProfileError {
    ProviderNotConfigured(String),
    TokenExchangeFailed(String),
    TokenRefreshFailed(String),
    UserInfoFailed(String),
    ProfileNotFound,
    MaxProfilesExceeded,
    IoError(String),
    SerializationError(String),
    InvalidState,
    PkceError(String),
    DuplicateProfileId(String),
}

impl fmt::Display for AuthProfileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ProviderNotConfigured(p) => write!(f, "Provider not configured: {}", p),
            Self::TokenExchangeFailed(msg) => write!(f, "Token exchange failed: {}", msg),
            Self::TokenRefreshFailed(msg) => write!(f, "Token refresh failed: {}", msg),
            Self::UserInfoFailed(msg) => write!(f, "User info fetch failed: {}", msg),
            Self::ProfileNotFound => write!(f, "Profile not found"),
            Self::MaxProfilesExceeded => {
                write!(f, "Maximum number of profiles ({}) exceeded", MAX_PROFILES)
            }
            Self::IoError(msg) => write!(f, "I/O error: {}", msg),
            Self::SerializationError(msg) => write!(f, "Serialization error: {}", msg),
            Self::InvalidState => write!(f, "Invalid state parameter"),
            Self::PkceError(msg) => write!(f, "PKCE error: {}", msg),
            Self::DuplicateProfileId(id) => write!(f, "Duplicate profile ID: {}", id),
        }
    }
}

impl std::error::Error for AuthProfileError {}

// ---------------------------------------------------------------------------
// Data structures
// ---------------------------------------------------------------------------

/// Supported OAuth providers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OAuthProvider {
    Google,
    GitHub,
    Discord,
}

impl fmt::Display for OAuthProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Google => write!(f, "google"),
            Self::GitHub => write!(f, "github"),
            Self::Discord => write!(f, "discord"),
        }
    }
}

/// OAuth2 token set for a profile.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthTokens {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub token_type: String,
    pub expires_at_ms: Option<u64>,
    pub scope: Option<String>,
}

/// A stored auth profile.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthProfile {
    pub id: String,
    pub name: String,
    pub provider: OAuthProvider,
    pub user_id: Option<String>,
    pub email: Option<String>,
    pub display_name: Option<String>,
    pub avatar_url: Option<String>,
    pub created_at_ms: u64,
    pub last_used_ms: Option<u64>,
    pub tokens: OAuthTokens,
}

/// Profile summary (no tokens exposed).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthProfileSummary {
    pub id: String,
    pub name: String,
    pub provider: OAuthProvider,
    pub email: Option<String>,
    pub display_name: Option<String>,
    pub avatar_url: Option<String>,
    pub created_at_ms: u64,
    pub last_used_ms: Option<u64>,
    pub token_valid: bool,
}

impl AuthProfile {
    /// Convert to a summary that does not contain any token values.
    pub fn to_summary(&self) -> AuthProfileSummary {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        let token_valid = match self.tokens.expires_at_ms {
            Some(expires) => now_ms < expires,
            None => true, // No expiry means we assume valid
        };

        AuthProfileSummary {
            id: self.id.clone(),
            name: self.name.clone(),
            provider: self.provider,
            email: self.email.clone(),
            display_name: self.display_name.clone(),
            avatar_url: self.avatar_url.clone(),
            created_at_ms: self.created_at_ms,
            last_used_ms: self.last_used_ms,
            token_valid,
        }
    }
}

/// User information returned from a provider's userinfo endpoint.
#[derive(Debug, Clone)]
pub struct UserInfo {
    pub user_id: String,
    pub email: Option<String>,
    pub display_name: Option<String>,
    pub avatar_url: Option<String>,
}

/// Provider-specific OAuth2 configuration.
#[derive(Debug, Clone)]
pub struct OAuthProviderConfig {
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
    pub auth_url: String,
    pub token_url: String,
    pub userinfo_url: String,
    pub scopes: Vec<String>,
}

// ---------------------------------------------------------------------------
// Provider configurations
// ---------------------------------------------------------------------------

impl OAuthProvider {
    /// Build a provider config with default endpoints for this provider.
    pub fn default_config(
        &self,
        client_id: &str,
        client_secret: &str,
        redirect_uri: &str,
    ) -> OAuthProviderConfig {
        match self {
            OAuthProvider::Google => OAuthProviderConfig {
                client_id: client_id.to_string(),
                client_secret: client_secret.to_string(),
                redirect_uri: redirect_uri.to_string(),
                auth_url: "https://accounts.google.com/o/oauth2/v2/auth".to_string(),
                token_url: "https://oauth2.googleapis.com/token".to_string(),
                userinfo_url: "https://openidconnect.googleapis.com/v1/userinfo".to_string(),
                scopes: vec![
                    "openid".to_string(),
                    "email".to_string(),
                    "profile".to_string(),
                ],
            },
            OAuthProvider::GitHub => OAuthProviderConfig {
                client_id: client_id.to_string(),
                client_secret: client_secret.to_string(),
                redirect_uri: redirect_uri.to_string(),
                auth_url: "https://github.com/login/oauth/authorize".to_string(),
                token_url: "https://github.com/login/oauth/access_token".to_string(),
                userinfo_url: "https://api.github.com/user".to_string(),
                scopes: vec!["read:user".to_string(), "user:email".to_string()],
            },
            OAuthProvider::Discord => OAuthProviderConfig {
                client_id: client_id.to_string(),
                client_secret: client_secret.to_string(),
                redirect_uri: redirect_uri.to_string(),
                auth_url: "https://discord.com/api/oauth2/authorize".to_string(),
                token_url: "https://discord.com/api/oauth2/token".to_string(),
                userinfo_url: "https://discord.com/api/users/@me".to_string(),
                scopes: vec!["identify".to_string(), "email".to_string()],
            },
        }
    }
}

// ---------------------------------------------------------------------------
// PKCE helpers
// ---------------------------------------------------------------------------

/// Generate a cryptographically random PKCE code verifier (43-128 chars, URL-safe).
fn generate_code_verifier() -> Result<String, AuthProfileError> {
    // 32 random bytes -> 43 base64url chars (without padding)
    let mut buf = [0u8; 32];
    getrandom::fill(&mut buf)
        .map_err(|e| AuthProfileError::PkceError(format!("RNG failed: {}", e)))?;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf))
}

/// Compute the PKCE code challenge = base64url(SHA256(code_verifier)).
fn compute_code_challenge(verifier: &str) -> String {
    let digest = Sha256::digest(verifier.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
}

// ---------------------------------------------------------------------------
// OAuth2 flow functions
// ---------------------------------------------------------------------------

/// Generate the OAuth2 authorization URL with PKCE and state parameter.
///
/// Returns `(authorization_url, code_verifier)`.
pub fn generate_auth_url(
    provider_config: &OAuthProviderConfig,
    state: &str,
) -> Result<(String, String), AuthProfileError> {
    let code_verifier = generate_code_verifier()?;
    let code_challenge = compute_code_challenge(&code_verifier);

    let scope = provider_config.scopes.join(" ");

    let params = [
        ("response_type", "code"),
        ("client_id", &provider_config.client_id),
        ("redirect_uri", &provider_config.redirect_uri),
        ("scope", &scope),
        ("state", state),
        ("code_challenge", &code_challenge),
        ("code_challenge_method", "S256"),
    ];

    let query = params
        .iter()
        .map(|(k, v)| format!("{}={}", url_encode(k), url_encode(v)))
        .collect::<Vec<_>>()
        .join("&");

    let url = format!("{}?{}", provider_config.auth_url, query);
    Ok((url, code_verifier))
}

/// Minimal percent-encoding for URL query parameters.
fn url_encode(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                result.push(b as char);
            }
            _ => {
                result.push('%');
                result.push_str(&format!("{:02X}", b));
            }
        }
    }
    result
}

/// Exchange an authorization code for tokens.
pub async fn exchange_code(
    provider_config: &OAuthProviderConfig,
    code: &str,
    code_verifier: &str,
) -> Result<OAuthTokens, AuthProfileError> {
    let params = [
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", &provider_config.redirect_uri),
        ("client_id", &provider_config.client_id),
        ("client_secret", &provider_config.client_secret),
        ("code_verifier", code_verifier),
    ];

    let resp = OAUTH_CLIENT
        .post(&provider_config.token_url)
        .header("Accept", "application/json")
        .form(&params)
        .send()
        .await
        .map_err(|e| AuthProfileError::TokenExchangeFailed(e.to_string()))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp
            .text()
            .await
            .unwrap_or_else(|_| "<unreadable>".to_string());
        return Err(AuthProfileError::TokenExchangeFailed(format!(
            "HTTP {}: {}",
            status, body
        )));
    }

    let body: Value = resp
        .json()
        .await
        .map_err(|e| AuthProfileError::TokenExchangeFailed(e.to_string()))?;

    parse_token_response(&body)
}

/// Refresh an expired access token.
pub async fn refresh_token(
    provider_config: &OAuthProviderConfig,
    refresh_tok: &str,
) -> Result<OAuthTokens, AuthProfileError> {
    let params = [
        ("grant_type", "refresh_token"),
        ("refresh_token", refresh_tok),
        ("client_id", &provider_config.client_id),
        ("client_secret", &provider_config.client_secret),
    ];

    let resp = OAUTH_CLIENT
        .post(&provider_config.token_url)
        .header("Accept", "application/json")
        .form(&params)
        .send()
        .await
        .map_err(|e| AuthProfileError::TokenRefreshFailed(e.to_string()))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp
            .text()
            .await
            .unwrap_or_else(|_| "<unreadable>".to_string());
        return Err(AuthProfileError::TokenRefreshFailed(format!(
            "HTTP {}: {}",
            status, body
        )));
    }

    let body: Value = resp
        .json()
        .await
        .map_err(|e| AuthProfileError::TokenRefreshFailed(e.to_string()))?;

    let mut tokens = parse_token_response(&body)?;

    // Preserve the original refresh token if the response did not include one
    if tokens.refresh_token.is_none() {
        tokens.refresh_token = Some(refresh_tok.to_string());
    }

    Ok(tokens)
}

/// Parse an OAuth2 token JSON response into `OAuthTokens`.
fn parse_token_response(body: &Value) -> Result<OAuthTokens, AuthProfileError> {
    let access_token = body
        .get("access_token")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            AuthProfileError::TokenExchangeFailed("Missing access_token in response".to_string())
        })?
        .to_string();

    let refresh_token = body
        .get("refresh_token")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let token_type = body
        .get("token_type")
        .and_then(|v| v.as_str())
        .unwrap_or("Bearer")
        .to_string();

    let scope = body
        .get("scope")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let expires_at_ms = body.get("expires_in").and_then(|v| v.as_u64()).map(|secs| {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        now_ms + secs * 1000
    });

    Ok(OAuthTokens {
        access_token,
        refresh_token,
        token_type,
        expires_at_ms,
        scope,
    })
}

/// Compute `expires_at_ms` from an `expires_in` value in seconds.
///
/// This is a public helper so callers can manually compute expiry timestamps.
pub fn compute_expires_at_ms(expires_in_secs: u64) -> u64 {
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    now_ms + expires_in_secs * 1000
}

/// Fetch user info from the provider's userinfo endpoint.
pub async fn fetch_user_info(
    provider: OAuthProvider,
    provider_config: &OAuthProviderConfig,
    access_token: &str,
) -> Result<UserInfo, AuthProfileError> {
    let mut req = OAUTH_CLIENT
        .get(&provider_config.userinfo_url)
        .bearer_auth(access_token);

    // GitHub requires an Accept header for JSON
    if provider == OAuthProvider::GitHub {
        req = req.header("Accept", "application/vnd.github+json");
        req = req.header("User-Agent", "carapace-gateway");
    }

    let resp = req
        .send()
        .await
        .map_err(|e| AuthProfileError::UserInfoFailed(e.to_string()))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp
            .text()
            .await
            .unwrap_or_else(|_| "<unreadable>".to_string());
        return Err(AuthProfileError::UserInfoFailed(format!(
            "HTTP {}: {}",
            status, body
        )));
    }

    let body: Value = resp
        .json()
        .await
        .map_err(|e| AuthProfileError::UserInfoFailed(e.to_string()))?;

    match provider {
        OAuthProvider::Google => Ok(UserInfo {
            user_id: body
                .get("sub")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            email: body
                .get("email")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            display_name: body
                .get("name")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            avatar_url: body
                .get("picture")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
        }),
        OAuthProvider::GitHub => Ok(UserInfo {
            user_id: body
                .get("id")
                .and_then(|v| v.as_u64())
                .map(|id| id.to_string())
                .unwrap_or_default(),
            email: body
                .get("email")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            display_name: body
                .get("name")
                .and_then(|v| v.as_str())
                .or_else(|| body.get("login").and_then(|v| v.as_str()))
                .map(|s| s.to_string()),
            avatar_url: body
                .get("avatar_url")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
        }),
        OAuthProvider::Discord => Ok(UserInfo {
            user_id: body
                .get("id")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            email: body
                .get("email")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            display_name: body
                .get("global_name")
                .and_then(|v| v.as_str())
                .or_else(|| body.get("username").and_then(|v| v.as_str()))
                .map(|s| s.to_string()),
            avatar_url: body.get("avatar").and_then(|v| v.as_str()).map(|hash| {
                let user_id = body.get("id").and_then(|v| v.as_str()).unwrap_or("0");
                format!(
                    "https://cdn.discordapp.com/avatars/{}/{}.png",
                    user_id, hash
                )
            }),
        }),
    }
}

// ---------------------------------------------------------------------------
// ProfileStore
// ---------------------------------------------------------------------------

/// Persistent store for auth profiles.
///
/// Profiles are stored as a JSON array in `{state_dir}/auth_profiles.json`.
/// Uses `parking_lot::RwLock` for synchronous interior mutability.
///
/// When a `SecretStore` is provided, sensitive token fields (`access_token`,
/// `refresh_token`) are encrypted at rest using AES-256-GCM.  Plaintext
/// values loaded from disk (backward-compatible) are transparently encrypted
/// on the next save.
pub struct ProfileStore {
    profiles: RwLock<Vec<AuthProfile>>,
    state_path: PathBuf,
    secret_store: Option<SecretStore>,
    /// Password bytes kept for `decrypt_rekey` (values on disk may have been
    /// encrypted with a different salt than the current `SecretStore`).
    encryption_password: Option<zeroize::Zeroizing<Vec<u8>>>,
}

impl ProfileStore {
    /// Create a new profile store that persists to `{state_dir}/auth_profiles.json`.
    ///
    /// Token fields are stored as plaintext.  Use [`with_encryption`](Self::with_encryption)
    /// to enable at-rest encryption.
    pub fn new(state_dir: PathBuf) -> Self {
        let state_path = state_dir.join("auth_profiles.json");
        Self {
            profiles: RwLock::new(Vec::new()),
            state_path,
            secret_store: None,
            encryption_password: None,
        }
    }

    /// Create a new profile store with at-rest encryption for token fields.
    ///
    /// When a `SecretStore` is provided, `access_token` and `refresh_token`
    /// values are encrypted before being written to disk and decrypted when
    /// loaded.  Existing plaintext values are accepted on load (backward
    /// compatible) and will be encrypted on the next save.
    ///
    /// The `password` is retained so that values encrypted with a different
    /// salt (e.g. from a previous run) can still be decrypted via key
    /// re-derivation.
    pub fn with_encryption(state_dir: PathBuf, password: &[u8]) -> Result<Self, AuthProfileError> {
        let state_path = state_dir.join("auth_profiles.json");
        let secret_store = SecretStore::new(password)
            .map_err(|e| AuthProfileError::IoError(format!("encryption init failed: {e}")))?;
        Ok(Self {
            profiles: RwLock::new(Vec::new()),
            state_path,
            secret_store: Some(secret_store),
            encryption_password: Some(zeroize::Zeroizing::new(password.to_vec())),
        })
    }

    /// Load profiles from disk. Replaces any in-memory data.
    ///
    /// If a `SecretStore` is configured, encrypted token fields are decrypted
    /// transparently.  Plaintext values (no `enc:v1:` prefix) are left as-is
    /// for backward compatibility.
    pub fn load(&self) -> Result<(), AuthProfileError> {
        if !self.state_path.exists() {
            return Ok(());
        }

        let content = fs::read_to_string(&self.state_path)
            .map_err(|e| AuthProfileError::IoError(e.to_string()))?;

        let mut profiles: Vec<AuthProfile> = serde_json::from_str(&content)
            .map_err(|e| AuthProfileError::SerializationError(e.to_string()))?;

        // Decrypt token fields if we have a SecretStore
        if let Some(ref store) = self.secret_store {
            let password: &[u8] = self
                .encryption_password
                .as_deref()
                .map(|v| v.as_slice())
                .unwrap_or(&[]);
            for profile in profiles.iter_mut() {
                Self::decrypt_tokens(&mut profile.tokens, store, password);
            }
        }

        let mut guard = self.profiles.write();
        *guard = profiles;
        Ok(())
    }

    /// Save profiles to disk atomically (write temp file, fsync, rename).
    ///
    /// If a `SecretStore` is configured, `access_token` and `refresh_token`
    /// fields are encrypted before serialization.  In-memory profiles remain
    /// in plaintext so that callers never see encrypted values.
    pub fn save(&self) -> Result<(), AuthProfileError> {
        let guard = self.profiles.read();
        self.save_profiles(&guard)
    }

    /// Internal save that operates on an already-borrowed slice of profiles.
    ///
    /// This avoids the TOCTOU race where a caller drops its write lock before
    /// `save()` re-acquires a read lock -- another thread could interleave and
    /// mutate the data between the two lock acquisitions.  Callers that already
    /// hold a write guard should use this method directly.
    fn save_profiles(&self, profiles: &[AuthProfile]) -> Result<(), AuthProfileError> {
        // Clone so we can encrypt without mutating in-memory state
        let mut to_save = profiles.to_vec();

        // Encrypt token fields if we have a SecretStore
        if let Some(ref store) = self.secret_store {
            for profile in to_save.iter_mut() {
                Self::encrypt_tokens(&mut profile.tokens, store);
            }
        }

        let content = serde_json::to_string_pretty(&to_save)
            .map_err(|e| AuthProfileError::SerializationError(e.to_string()))?;

        // Ensure parent directory exists
        if let Some(parent) = self.state_path.parent() {
            fs::create_dir_all(parent).map_err(|e| AuthProfileError::IoError(e.to_string()))?;
        }

        let temp_path = self.state_path.with_extension("tmp");

        let mut file =
            fs::File::create(&temp_path).map_err(|e| AuthProfileError::IoError(e.to_string()))?;

        file.write_all(content.as_bytes())
            .map_err(|e| AuthProfileError::IoError(e.to_string()))?;

        file.sync_all()
            .map_err(|e| AuthProfileError::IoError(e.to_string()))?;

        fs::rename(&temp_path, &self.state_path)
            .map_err(|e| AuthProfileError::IoError(e.to_string()))?;

        Ok(())
    }

    // -- private helpers for token encryption/decryption --

    /// Encrypt sensitive token fields in-place.  Already-encrypted values
    /// (prefixed with `enc:v1:`) are skipped to avoid double-encryption.
    fn encrypt_tokens(tokens: &mut OAuthTokens, store: &SecretStore) {
        if !is_encrypted(&tokens.access_token) {
            match store.encrypt(&tokens.access_token) {
                Ok(encrypted) => tokens.access_token = encrypted,
                Err(e) => {
                    tracing::warn!("Failed to encrypt access_token for profile: {}", e);
                }
            }
        }
        if let Some(ref rt) = tokens.refresh_token {
            if !is_encrypted(rt) {
                match store.encrypt(rt) {
                    Ok(encrypted) => tokens.refresh_token = Some(encrypted),
                    Err(e) => {
                        tracing::warn!("Failed to encrypt refresh_token for profile: {}", e);
                    }
                }
            }
        }
    }

    /// Decrypt sensitive token fields in-place.  Plaintext values (no
    /// `enc:v1:` prefix) are left as-is for backward compatibility.
    ///
    /// Uses `decrypt_rekey` so that values encrypted with a different salt
    /// (e.g. from a previous `SecretStore` instance) are still decryptable
    /// as long as the same password is used.
    fn decrypt_tokens(tokens: &mut OAuthTokens, store: &SecretStore, password: &[u8]) {
        if is_encrypted(&tokens.access_token) {
            match store.decrypt_rekey(&tokens.access_token, password) {
                Ok(plaintext) => tokens.access_token = plaintext,
                Err(e) => {
                    tracing::warn!("Failed to decrypt access_token for profile: {}; clearing token to prevent opaque downstream errors", e);
                    tokens.access_token = String::new();
                }
            }
        }
        if let Some(ref rt) = tokens.refresh_token {
            if is_encrypted(rt) {
                match store.decrypt_rekey(rt, password) {
                    Ok(plaintext) => tokens.refresh_token = Some(plaintext),
                    Err(e) => {
                        tracing::warn!("Failed to decrypt refresh_token for profile: {}; clearing token to prevent opaque downstream errors", e);
                        tokens.refresh_token = Some(String::new());
                    }
                }
            }
        }
    }

    /// Add a profile. Fails if MAX_PROFILES would be exceeded.
    pub fn add(&self, profile: AuthProfile) -> Result<(), AuthProfileError> {
        let mut guard = self.profiles.write();
        if guard.len() >= MAX_PROFILES {
            return Err(AuthProfileError::MaxProfilesExceeded);
        }
        if guard.iter().any(|p| p.id == profile.id) {
            return Err(AuthProfileError::DuplicateProfileId(profile.id));
        }
        guard.push(profile);
        self.save_profiles(&guard)
    }

    /// Remove a profile by ID. Returns `true` if a profile was removed.
    pub fn remove(&self, id: &str) -> Result<bool, AuthProfileError> {
        let mut guard = self.profiles.write();
        let before = guard.len();
        guard.retain(|p| p.id != id);
        let removed = guard.len() < before;
        if removed {
            self.save_profiles(&guard)?;
        }
        Ok(removed)
    }

    /// Get a profile by ID (cloned).
    pub fn get(&self, id: &str) -> Option<AuthProfile> {
        let guard = self.profiles.read();
        guard.iter().find(|p| p.id == id).cloned()
    }

    /// List all profiles as summaries (no tokens exposed).
    pub fn list(&self) -> Vec<AuthProfileSummary> {
        let guard = self.profiles.read();
        guard.iter().map(|p| p.to_summary()).collect()
    }

    /// Update the tokens for a profile.
    pub fn update_tokens(&self, id: &str, tokens: OAuthTokens) -> Result<(), AuthProfileError> {
        let mut guard = self.profiles.write();
        let profile = guard
            .iter_mut()
            .find(|p| p.id == id)
            .ok_or(AuthProfileError::ProfileNotFound)?;
        profile.tokens = tokens;
        self.save_profiles(&guard)
    }

    /// Update the last-used timestamp for a profile.
    pub fn update_last_used(&self, id: &str) {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        let mut guard = self.profiles.write();
        if let Some(profile) = guard.iter_mut().find(|p| p.id == id) {
            profile.last_used_ms = Some(now_ms);
        }
        // Best-effort save; ignore errors for a timestamp update
        let _ = self.save_profiles(&guard);
    }
}

// ---------------------------------------------------------------------------
// Config integration
// ---------------------------------------------------------------------------

/// Auth profiles configuration parsed from the application config.
#[derive(Debug, Clone, Default)]
pub struct AuthProfilesConfig {
    pub enabled: bool,
    pub providers: HashMap<OAuthProvider, OAuthProviderConfig>,
    pub redirect_base_url: Option<String>,
}

/// Build auth profiles configuration from the root config `Value`.
///
/// Expected config path: `auth.profiles`.
pub fn build_auth_profiles_config(cfg: &Value) -> AuthProfilesConfig {
    let section = match cfg.pointer("/auth/profiles") {
        Some(v) => v,
        None => return AuthProfilesConfig::default(),
    };

    let enabled = section
        .get("enabled")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let redirect_base_url = section
        .get("redirectBaseUrl")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let default_redirect = redirect_base_url
        .as_deref()
        .map(|base| format!("{}/auth/callback", base))
        .unwrap_or_else(|| "http://localhost:3000/auth/callback".to_string());

    let mut providers = HashMap::new();

    if let Some(providers_obj) = section.get("providers").and_then(|v| v.as_object()) {
        let provider_entries: &[(&str, OAuthProvider)] = &[
            ("google", OAuthProvider::Google),
            ("github", OAuthProvider::GitHub),
            ("discord", OAuthProvider::Discord),
        ];

        for &(key, provider) in provider_entries {
            if let Some(pcfg) = providers_obj.get(key) {
                let client_id = pcfg
                    .get("clientId")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let client_secret = pcfg
                    .get("clientSecret")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let redirect_uri = pcfg
                    .get("redirectUri")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| default_redirect.clone());

                if !client_id.is_empty() && !client_secret.is_empty() {
                    providers.insert(
                        provider,
                        provider.default_config(&client_id, &client_secret, &redirect_uri),
                    );
                }
            }
        }
    }

    AuthProfilesConfig {
        enabled,
        providers,
        redirect_base_url,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    // -----------------------------------------------------------------------
    // Helper builders
    // -----------------------------------------------------------------------

    fn sample_tokens() -> OAuthTokens {
        OAuthTokens {
            access_token: "access-123".to_string(),
            refresh_token: Some("refresh-456".to_string()),
            token_type: "Bearer".to_string(),
            expires_at_ms: Some(9_999_999_999_999),
            scope: Some("openid email".to_string()),
        }
    }

    fn sample_profile(id: &str) -> AuthProfile {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        AuthProfile {
            id: id.to_string(),
            name: format!("Test Profile {}", id),
            provider: OAuthProvider::Google,
            user_id: Some("user-1".to_string()),
            email: Some("test@example.com".to_string()),
            display_name: Some("Test User".to_string()),
            avatar_url: Some("https://example.com/avatar.png".to_string()),
            created_at_ms: now_ms,
            last_used_ms: None,
            tokens: sample_tokens(),
        }
    }

    fn google_config() -> OAuthProviderConfig {
        OAuthProvider::Google.default_config("cid", "csecret", "https://example.com/cb")
    }

    fn github_config() -> OAuthProviderConfig {
        OAuthProvider::GitHub.default_config("cid", "csecret", "https://example.com/cb")
    }

    fn discord_config() -> OAuthProviderConfig {
        OAuthProvider::Discord.default_config("cid", "csecret", "https://example.com/cb")
    }

    fn random_password() -> Vec<u8> {
        let mut bytes = [0u8; 32];
        getrandom::fill(&mut bytes).expect("random test password bytes");
        bytes.to_vec()
    }

    // -----------------------------------------------------------------------
    // Provider config tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_provider_default_configs() {
        let g = google_config();
        let gh = github_config();
        let d = discord_config();

        assert!(g.auth_url.contains("accounts.google.com"));
        assert!(gh.auth_url.contains("github.com"));
        assert!(d.auth_url.contains("discord.com"));

        assert_eq!(g.client_id, "cid");
        assert_eq!(gh.client_secret, "csecret");
        assert_eq!(d.redirect_uri, "https://example.com/cb");
    }

    #[test]
    fn test_google_config_endpoints() {
        let cfg = google_config();
        assert_eq!(cfg.auth_url, "https://accounts.google.com/o/oauth2/v2/auth");
        assert_eq!(cfg.token_url, "https://oauth2.googleapis.com/token");
        assert_eq!(
            cfg.userinfo_url,
            "https://openidconnect.googleapis.com/v1/userinfo"
        );
        assert_eq!(cfg.scopes, vec!["openid", "email", "profile"]);
    }

    #[test]
    fn test_github_config_endpoints() {
        let cfg = github_config();
        assert_eq!(cfg.auth_url, "https://github.com/login/oauth/authorize");
        assert_eq!(cfg.token_url, "https://github.com/login/oauth/access_token");
        assert_eq!(cfg.userinfo_url, "https://api.github.com/user");
        assert_eq!(cfg.scopes, vec!["read:user", "user:email"]);
    }

    #[test]
    fn test_discord_config_endpoints() {
        let cfg = discord_config();
        assert_eq!(cfg.auth_url, "https://discord.com/api/oauth2/authorize");
        assert_eq!(cfg.token_url, "https://discord.com/api/oauth2/token");
        assert_eq!(cfg.userinfo_url, "https://discord.com/api/users/@me");
        assert_eq!(cfg.scopes, vec!["identify", "email"]);
    }

    // -----------------------------------------------------------------------
    // Auth URL / PKCE tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_generate_auth_url_contains_required_params() {
        let cfg = google_config();
        let (url, _verifier) = generate_auth_url(&cfg, "test-state").unwrap();

        assert!(url.contains("response_type=code"), "missing response_type");
        assert!(url.contains("client_id=cid"), "missing client_id");
        assert!(url.contains("redirect_uri="), "missing redirect_uri");
        assert!(url.contains("scope="), "missing scope");
        assert!(url.contains("state=test-state"), "missing state");
        assert!(url.contains("code_challenge="), "missing code_challenge");
        assert!(
            url.contains("code_challenge_method=S256"),
            "missing code_challenge_method"
        );
    }

    #[test]
    fn test_generate_auth_url_pkce_challenge() {
        let cfg = google_config();
        let (url, verifier) = generate_auth_url(&cfg, "s").unwrap();

        // Manually compute expected challenge
        let expected_challenge = compute_code_challenge(&verifier);

        // The URL should contain the expected challenge
        assert!(
            url.contains(&expected_challenge),
            "URL does not contain correct PKCE code_challenge. Expected: {}",
            expected_challenge
        );
    }

    #[test]
    fn test_generate_auth_url_state_param() {
        let cfg = google_config();
        let (url, _) = generate_auth_url(&cfg, "my-unique-state-42").unwrap();
        assert!(url.contains("state=my-unique-state-42"));
    }

    #[test]
    fn test_pkce_verifier_length() {
        let verifier = generate_code_verifier().unwrap();
        // 32 bytes -> 43 base64url chars without padding
        assert!(
            verifier.len() >= 43 && verifier.len() <= 128,
            "Verifier length {} is out of valid PKCE range 43-128",
            verifier.len()
        );
    }

    #[test]
    fn test_pkce_challenge_is_base64url() {
        let verifier = generate_code_verifier().unwrap();
        let challenge = compute_code_challenge(&verifier);

        // base64url uses A-Z a-z 0-9 - _ and no padding
        for ch in challenge.chars() {
            assert!(
                ch.is_ascii_alphanumeric() || ch == '-' || ch == '_',
                "Challenge contains non-base64url character: '{}'",
                ch
            );
        }
        assert!(
            !challenge.contains('='),
            "Challenge should not have padding"
        );
        assert!(!challenge.contains('+'), "Challenge should not contain '+'");
        assert!(!challenge.contains('/'), "Challenge should not contain '/'");
    }

    // -----------------------------------------------------------------------
    // Serialization round-trip tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_oauth_tokens_serialization() {
        let tokens = sample_tokens();
        let json = serde_json::to_string(&tokens).unwrap();
        let deserialized: OAuthTokens = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.access_token, tokens.access_token);
        assert_eq!(deserialized.refresh_token, tokens.refresh_token);
        assert_eq!(deserialized.token_type, tokens.token_type);
        assert_eq!(deserialized.expires_at_ms, tokens.expires_at_ms);
        assert_eq!(deserialized.scope, tokens.scope);
    }

    #[test]
    fn test_auth_profile_serialization() {
        let profile = sample_profile("abc-123");
        let json = serde_json::to_string(&profile).unwrap();
        let deserialized: AuthProfile = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.id, profile.id);
        assert_eq!(deserialized.name, profile.name);
        assert_eq!(deserialized.provider, profile.provider);
        assert_eq!(deserialized.user_id, profile.user_id);
        assert_eq!(deserialized.email, profile.email);
        assert_eq!(deserialized.display_name, profile.display_name);
        assert_eq!(deserialized.avatar_url, profile.avatar_url);
        assert_eq!(deserialized.created_at_ms, profile.created_at_ms);
        assert_eq!(deserialized.last_used_ms, profile.last_used_ms);
        assert_eq!(
            deserialized.tokens.access_token,
            profile.tokens.access_token
        );
    }

    // -----------------------------------------------------------------------
    // Profile summary tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_profile_summary_no_tokens() {
        let profile = sample_profile("id-1");
        let summary = profile.to_summary();

        // Summary must not contain access_token or refresh_token
        let json = serde_json::to_string(&summary).unwrap();
        assert!(!json.contains("access-123"), "Summary leaks access_token");
        assert!(!json.contains("refresh-456"), "Summary leaks refresh_token");

        assert_eq!(summary.id, "id-1");
        assert_eq!(summary.provider, OAuthProvider::Google);
    }

    #[test]
    fn test_profile_summary_token_valid() {
        let far_future_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
            + 3_600_000; // +1 hour

        let mut profile = sample_profile("valid");
        profile.tokens.expires_at_ms = Some(far_future_ms);
        let summary = profile.to_summary();
        assert!(
            summary.token_valid,
            "Token expiring in the future should be valid"
        );
    }

    #[test]
    fn test_profile_summary_token_expired() {
        let mut profile = sample_profile("expired");
        profile.tokens.expires_at_ms = Some(1000); // far in the past
        let summary = profile.to_summary();
        assert!(
            !summary.token_valid,
            "Token that expired long ago should be invalid"
        );
    }

    // -----------------------------------------------------------------------
    // ProfileStore CRUD tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_profile_store_add_remove() {
        let dir = tempdir().unwrap();
        let store = ProfileStore::new(dir.path().to_path_buf());

        let profile = sample_profile("p1");
        store.add(profile).unwrap();

        assert!(store.get("p1").is_some());
        assert_eq!(store.list().len(), 1);

        let removed = store.remove("p1").unwrap();
        assert!(removed);
        assert!(store.get("p1").is_none());
        assert_eq!(store.list().len(), 0);
    }

    #[test]
    fn test_profile_store_max_profiles() {
        let dir = tempdir().unwrap();
        let store = ProfileStore::new(dir.path().to_path_buf());

        for i in 0..MAX_PROFILES {
            store.add(sample_profile(&format!("p-{}", i))).unwrap();
        }

        // Next add should fail
        let result = store.add(sample_profile("overflow"));
        assert!(
            matches!(result, Err(AuthProfileError::MaxProfilesExceeded)),
            "Expected MaxProfilesExceeded error"
        );
    }

    #[test]
    fn test_profile_store_persistence() {
        let dir = tempdir().unwrap();

        // Create store and add profile
        {
            let store = ProfileStore::new(dir.path().to_path_buf());
            store.add(sample_profile("persist-1")).unwrap();
            store.add(sample_profile("persist-2")).unwrap();
        }

        // Create a new store and load
        {
            let store = ProfileStore::new(dir.path().to_path_buf());
            store.load().unwrap();

            let profiles = store.list();
            assert_eq!(profiles.len(), 2);
            assert!(store.get("persist-1").is_some());
            assert!(store.get("persist-2").is_some());
        }
    }

    #[test]
    fn test_profile_store_duplicate_id() {
        let dir = tempdir().unwrap();
        let store = ProfileStore::new(dir.path().to_path_buf());

        store.add(sample_profile("dup")).unwrap();
        // Adding another profile with the same ID should be rejected.
        let result = store.add(sample_profile("dup"));
        assert!(
            matches!(result, Err(AuthProfileError::DuplicateProfileId(ref id)) if id == "dup"),
            "Expected DuplicateProfileId error"
        );

        // Only the first profile exists
        assert_eq!(store.list().len(), 1);
    }

    #[test]
    fn test_profile_store_list_returns_summaries() {
        let dir = tempdir().unwrap();
        let store = ProfileStore::new(dir.path().to_path_buf());

        store.add(sample_profile("ls-1")).unwrap();
        store.add(sample_profile("ls-2")).unwrap();

        let summaries = store.list();
        assert_eq!(summaries.len(), 2);

        // Verify summaries do not leak tokens
        for summary in &summaries {
            let json = serde_json::to_string(summary).unwrap();
            assert!(!json.contains("access-123"));
            assert!(!json.contains("refresh-456"));
        }
    }

    #[test]
    fn test_profile_store_update_tokens() {
        let dir = tempdir().unwrap();
        let store = ProfileStore::new(dir.path().to_path_buf());

        store.add(sample_profile("upd")).unwrap();

        let new_tokens = OAuthTokens {
            access_token: "new-access".to_string(),
            refresh_token: Some("new-refresh".to_string()),
            token_type: "Bearer".to_string(),
            expires_at_ms: Some(123_456_789),
            scope: None,
        };

        store.update_tokens("upd", new_tokens).unwrap();

        let profile = store.get("upd").unwrap();
        assert_eq!(profile.tokens.access_token, "new-access");
        assert_eq!(
            profile.tokens.refresh_token,
            Some("new-refresh".to_string())
        );
    }

    #[test]
    fn test_profile_store_update_last_used() {
        let dir = tempdir().unwrap();
        let store = ProfileStore::new(dir.path().to_path_buf());

        store.add(sample_profile("lu")).unwrap();

        // Initially None
        assert!(store.get("lu").unwrap().last_used_ms.is_none());

        store.update_last_used("lu");

        let profile = store.get("lu").unwrap();
        assert!(
            profile.last_used_ms.is_some(),
            "last_used_ms should be set after update"
        );
    }

    #[test]
    fn test_profile_store_get_nonexistent() {
        let dir = tempdir().unwrap();
        let store = ProfileStore::new(dir.path().to_path_buf());
        assert!(store.get("does-not-exist").is_none());
    }

    #[test]
    fn test_profile_store_remove_nonexistent() {
        let dir = tempdir().unwrap();
        let store = ProfileStore::new(dir.path().to_path_buf());
        let removed = store.remove("nope").unwrap();
        assert!(!removed);
    }

    #[test]
    fn test_profile_store_empty_initial() {
        let dir = tempdir().unwrap();
        let store = ProfileStore::new(dir.path().to_path_buf());
        assert_eq!(store.list().len(), 0);
        assert!(store.get("any").is_none());
    }

    // -----------------------------------------------------------------------
    // Config integration tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_config_defaults() {
        let cfg = serde_json::json!({});
        let result = build_auth_profiles_config(&cfg);
        assert!(!result.enabled);
        assert!(result.providers.is_empty());
        assert!(result.redirect_base_url.is_none());
    }

    #[test]
    fn test_build_config_enabled() {
        let cfg = serde_json::json!({
            "auth": {
                "profiles": {
                    "enabled": true
                }
            }
        });
        let result = build_auth_profiles_config(&cfg);
        assert!(result.enabled);
    }

    #[test]
    fn test_build_config_with_providers() {
        let cfg = serde_json::json!({
            "auth": {
                "profiles": {
                    "enabled": true,
                    "redirectBaseUrl": "https://gw.example.com",
                    "providers": {
                        "google": {
                            "clientId": "google-cid",
                            "clientSecret": "google-cs"
                        },
                        "github": {
                            "clientId": "gh-cid",
                            "clientSecret": "gh-cs"
                        },
                        "discord": {
                            "clientId": "dc-cid",
                            "clientSecret": "dc-cs"
                        }
                    }
                }
            }
        });
        let result = build_auth_profiles_config(&cfg);
        assert!(result.enabled);
        assert_eq!(
            result.redirect_base_url.as_deref(),
            Some("https://gw.example.com")
        );
        assert_eq!(result.providers.len(), 3);

        let google = result.providers.get(&OAuthProvider::Google).unwrap();
        assert_eq!(google.client_id, "google-cid");
        assert_eq!(google.client_secret, "google-cs");
        assert_eq!(google.redirect_uri, "https://gw.example.com/auth/callback");

        let github = result.providers.get(&OAuthProvider::GitHub).unwrap();
        assert_eq!(github.client_id, "gh-cid");

        let discord = result.providers.get(&OAuthProvider::Discord).unwrap();
        assert_eq!(discord.client_id, "dc-cid");
    }

    #[test]
    fn test_build_config_missing_section() {
        let cfg = serde_json::json!({
            "auth": {
                "mode": "token"
            }
        });
        let result = build_auth_profiles_config(&cfg);
        assert!(!result.enabled);
        assert!(result.providers.is_empty());
    }

    // -----------------------------------------------------------------------
    // Display / error tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_provider_display() {
        assert_eq!(format!("{}", OAuthProvider::Google), "google");
        assert_eq!(format!("{}", OAuthProvider::GitHub), "github");
        assert_eq!(format!("{}", OAuthProvider::Discord), "discord");
    }

    #[test]
    fn test_error_display() {
        let err = AuthProfileError::ProviderNotConfigured("google".to_string());
        assert!(err.to_string().contains("Provider not configured"));
        assert!(err.to_string().contains("google"));

        let err = AuthProfileError::TokenExchangeFailed("timeout".to_string());
        assert!(err.to_string().contains("Token exchange failed"));

        let err = AuthProfileError::TokenRefreshFailed("expired".to_string());
        assert!(err.to_string().contains("Token refresh failed"));

        let err = AuthProfileError::UserInfoFailed("403".to_string());
        assert!(err.to_string().contains("User info fetch failed"));

        let err = AuthProfileError::ProfileNotFound;
        assert!(err.to_string().contains("Profile not found"));

        let err = AuthProfileError::MaxProfilesExceeded;
        assert!(err.to_string().contains("Maximum number of profiles"));
        assert!(err.to_string().contains("20"));

        let err = AuthProfileError::IoError("disk full".to_string());
        assert!(err.to_string().contains("I/O error"));

        let err = AuthProfileError::SerializationError("bad json".to_string());
        assert!(err.to_string().contains("Serialization error"));

        let err = AuthProfileError::InvalidState;
        assert!(err.to_string().contains("Invalid state"));

        let err = AuthProfileError::PkceError("rng fail".to_string());
        assert!(err.to_string().contains("PKCE error"));
    }

    // -----------------------------------------------------------------------
    // PKCE / token computation tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_oauth_tokens_expires_at_computation() {
        let before = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        let expires_at = compute_expires_at_ms(3600);

        let after = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        // expires_at should be now + 3600 seconds
        assert!(expires_at >= before + 3_600_000);
        assert!(expires_at <= after + 3_600_000);
    }

    #[test]
    fn test_auth_profile_created_at_set() {
        let before_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        let profile = sample_profile("ts-test");

        let after_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        assert!(
            profile.created_at_ms >= before_ms && profile.created_at_ms <= after_ms,
            "created_at_ms ({}) should be between {} and {}",
            profile.created_at_ms,
            before_ms,
            after_ms,
        );
    }

    // -----------------------------------------------------------------------
    // OAuthProvider serde tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_oauth_provider_serde_lowercase() {
        let json = serde_json::to_string(&OAuthProvider::Google).unwrap();
        assert_eq!(json, "\"google\"");

        let json = serde_json::to_string(&OAuthProvider::GitHub).unwrap();
        assert_eq!(json, "\"github\"");

        let json = serde_json::to_string(&OAuthProvider::Discord).unwrap();
        assert_eq!(json, "\"discord\"");

        // Deserialize
        let provider: OAuthProvider = serde_json::from_str("\"google\"").unwrap();
        assert_eq!(provider, OAuthProvider::Google);

        let provider: OAuthProvider = serde_json::from_str("\"github\"").unwrap();
        assert_eq!(provider, OAuthProvider::GitHub);

        let provider: OAuthProvider = serde_json::from_str("\"discord\"").unwrap();
        assert_eq!(provider, OAuthProvider::Discord);
    }

    // -----------------------------------------------------------------------
    // URL encoding test
    // -----------------------------------------------------------------------

    #[test]
    fn test_url_encode_special_chars() {
        assert_eq!(url_encode("hello world"), "hello%20world");
        assert_eq!(url_encode("a+b"), "a%2Bb");
        assert_eq!(url_encode("key=val&x=y"), "key%3Dval%26x%3Dy");
        assert_eq!(url_encode("safe-chars_here.ok~"), "safe-chars_here.ok~");
    }

    // -----------------------------------------------------------------------
    // At-rest encryption tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_encrypted_profile_store_roundtrip() {
        let dir = tempdir().unwrap();
        let password = random_password();

        // Create an encrypted store, add a profile, and save
        {
            let store = ProfileStore::with_encryption(dir.path().to_path_buf(), &password).unwrap();

            store.add(sample_profile("enc-1")).unwrap();
        }

        // Read the raw file and verify tokens are encrypted on disk
        let raw = std::fs::read_to_string(dir.path().join("auth_profiles.json")).unwrap();
        assert!(
            !raw.contains("access-123"),
            "access_token must not appear in plaintext on disk"
        );
        assert!(
            !raw.contains("refresh-456"),
            "refresh_token must not appear in plaintext on disk"
        );
        assert!(
            raw.contains("enc:v1:"),
            "encrypted tokens should be present on disk"
        );

        // Load the profiles back with a new store derived from the same password
        let store2 = ProfileStore::with_encryption(dir.path().to_path_buf(), &password).unwrap();
        store2.load().unwrap();

        let profile = store2.get("enc-1").unwrap();
        assert_eq!(
            profile.tokens.access_token, "access-123",
            "access_token should be decrypted correctly"
        );
        assert_eq!(
            profile.tokens.refresh_token,
            Some("refresh-456".to_string()),
            "refresh_token should be decrypted correctly"
        );
    }

    #[test]
    fn test_encrypted_profile_store_backward_compat_plaintext_load() {
        let dir = tempdir().unwrap();

        // First, write profiles using a plaintext store (no encryption)
        {
            let store = ProfileStore::new(dir.path().to_path_buf());
            store.add(sample_profile("plain-1")).unwrap();
        }

        // Verify it's plaintext on disk
        let raw = std::fs::read_to_string(dir.path().join("auth_profiles.json")).unwrap();
        assert!(
            raw.contains("access-123"),
            "plaintext store should write tokens in clear"
        );

        // Now load with an encrypted store -- plaintext values should be read fine.
        // Password value is irrelevant here because no ciphertext is being decrypted;
        // this verifies backward-compatible opening of plaintext profile files.
        let password = random_password();
        let store2 = ProfileStore::with_encryption(dir.path().to_path_buf(), &password).unwrap();
        store2.load().unwrap();

        let profile = store2.get("plain-1").unwrap();
        assert_eq!(
            profile.tokens.access_token, "access-123",
            "plaintext access_token should load correctly in encrypted store"
        );
        assert_eq!(
            profile.tokens.refresh_token,
            Some("refresh-456".to_string()),
            "plaintext refresh_token should load correctly in encrypted store"
        );

        // Trigger a save -- tokens should now be encrypted
        store2.update_last_used("plain-1");

        let raw2 = std::fs::read_to_string(dir.path().join("auth_profiles.json")).unwrap();
        assert!(
            !raw2.contains("access-123"),
            "after save, access_token should be encrypted"
        );
        assert!(
            raw2.contains("enc:v1:"),
            "after save, encrypted tokens should be on disk"
        );
    }

    #[test]
    fn test_no_secret_store_saves_plaintext() {
        let dir = tempdir().unwrap();
        let store = ProfileStore::new(dir.path().to_path_buf());

        store.add(sample_profile("pt-1")).unwrap();

        let raw = std::fs::read_to_string(dir.path().join("auth_profiles.json")).unwrap();
        assert!(
            raw.contains("access-123"),
            "without SecretStore, tokens should remain plaintext"
        );
        assert!(
            raw.contains("refresh-456"),
            "without SecretStore, refresh_token should remain plaintext"
        );
        assert!(
            !raw.contains("enc:v1:"),
            "without SecretStore, no encryption prefix should appear"
        );
    }

    #[test]
    fn test_encrypted_store_no_double_encryption() {
        let dir = tempdir().unwrap();
        let password = random_password();

        // Save a profile (tokens get encrypted on disk)
        {
            let store = ProfileStore::with_encryption(dir.path().to_path_buf(), &password).unwrap();
            store.add(sample_profile("de-1")).unwrap();
        }

        // Load and save again -- should not double-encrypt
        let store2 = ProfileStore::with_encryption(dir.path().to_path_buf(), &password).unwrap();
        store2.load().unwrap();

        // In-memory tokens should be plaintext
        let profile = store2.get("de-1").unwrap();
        assert_eq!(profile.tokens.access_token, "access-123");

        // Force a re-save
        store2.update_last_used("de-1");

        // Load yet again to verify
        let store3 = ProfileStore::with_encryption(dir.path().to_path_buf(), &password).unwrap();
        store3.load().unwrap();

        let profile2 = store3.get("de-1").unwrap();
        assert_eq!(
            profile2.tokens.access_token, "access-123",
            "tokens should survive multiple save/load cycles"
        );
        assert_eq!(
            profile2.tokens.refresh_token,
            Some("refresh-456".to_string()),
        );
    }

    #[test]
    fn test_encrypted_store_no_refresh_token() {
        let dir = tempdir().unwrap();
        let password = random_password();

        // Create a profile without a refresh token
        let mut profile = sample_profile("nrt-1");
        profile.tokens.refresh_token = None;

        let store = ProfileStore::with_encryption(dir.path().to_path_buf(), &password).unwrap();
        store.add(profile).unwrap();

        // Reload and verify
        let store2 = ProfileStore::with_encryption(dir.path().to_path_buf(), &password).unwrap();
        store2.load().unwrap();

        let loaded = store2.get("nrt-1").unwrap();
        assert_eq!(loaded.tokens.access_token, "access-123");
        assert_eq!(loaded.tokens.refresh_token, None);
    }
}
