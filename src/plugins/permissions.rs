//! Fine-grained permission model for WASM plugins.
//!
//! Extends the coarse-grained capability sandbox (`sandbox.rs`) with granular
//! policies that control *how* a capability may be used:
//!
//! - **HTTP**: restrict outbound requests to specific URL patterns
//! - **Credentials**: restrict credential key access to declared scopes
//! - **Media**: restrict media downloads to specific URL patterns
//! - **Config**: (always scoped to `plugins.<id>.*` by default)
//!
//! # Architecture
//!
//! ```text
//! PluginManifest        PermissionConfig (gateway config)
//!       |                        |
//!       v                        v
//! DeclaredPermissions   PermissionOverrides (per-plugin)
//!       |                        |
//!       +------------------------+
//!                   |
//!                   v
//!           EffectivePermissions  <-- computed at load time
//!                   |
//!                   v
//!           PermissionEnforcer    <-- checked at runtime on each invocation
//! ```
//!
//! # Load-time validation
//!
//! When a plugin is loaded, its declared permissions are validated against the
//! gateway's permission configuration. If a plugin declares a permission that
//! the gateway config does not grant, instantiation is blocked.
//!
//! # Runtime enforcement
//!
//! On each host function call (HTTP fetch, credential get/set, media fetch),
//! the `PermissionEnforcer` checks the request against the effective
//! permissions. Denied requests are logged and returned as errors.

use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Errors from permission enforcement.
#[derive(Debug, Clone, PartialEq)]
pub enum PermissionError {
    /// An HTTP request URL did not match any allowed URL pattern.
    HttpUrlDenied {
        plugin_id: String,
        url: String,
        reason: String,
    },
    /// A credential key was not in the declared scope.
    CredentialScopeDenied {
        plugin_id: String,
        key: String,
        reason: String,
    },
    /// A media URL did not match any allowed URL pattern.
    MediaUrlDenied {
        plugin_id: String,
        url: String,
        reason: String,
    },
    /// A declared permission is not granted by the gateway config.
    PermissionNotGranted {
        plugin_id: String,
        permission: String,
        reason: String,
    },
}

impl std::fmt::Display for PermissionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PermissionError::HttpUrlDenied {
                plugin_id,
                url,
                reason,
            } => write!(
                f,
                "Plugin '{}' HTTP request to '{}' denied: {}",
                plugin_id, url, reason
            ),
            PermissionError::CredentialScopeDenied {
                plugin_id,
                key,
                reason,
            } => write!(
                f,
                "Plugin '{}' credential access to '{}' denied: {}",
                plugin_id, key, reason
            ),
            PermissionError::MediaUrlDenied {
                plugin_id,
                url,
                reason,
            } => write!(
                f,
                "Plugin '{}' media fetch from '{}' denied: {}",
                plugin_id, url, reason
            ),
            PermissionError::PermissionNotGranted {
                plugin_id,
                permission,
                reason,
            } => write!(
                f,
                "Plugin '{}' permission '{}' not granted: {}",
                plugin_id, permission, reason
            ),
        }
    }
}

impl std::error::Error for PermissionError {}

// ============== Declared Permissions (Plugin Manifest) ==============

/// Permissions declared by a plugin in its manifest.
///
/// A plugin declares what it *needs*. The gateway decides whether to grant it.
/// If a plugin does not declare permissions, it inherits the defaults from the
/// sandbox `CapabilityPolicy`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DeclaredPermissions {
    /// HTTP permission declarations.
    #[serde(default)]
    pub http: Option<HttpPermission>,

    /// Credential permission declarations.
    #[serde(default)]
    pub credentials: Option<CredentialPermission>,

    /// Media permission declarations.
    #[serde(default)]
    pub media: Option<MediaPermission>,
}

/// HTTP permission: which URL patterns the plugin may access.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpPermission {
    /// Allowed URL patterns (glob-style). An empty list means no HTTP access.
    ///
    /// Patterns are matched against the full URL. Supported wildcards:
    /// - `*` matches any sequence of non-`/` characters within a path segment
    /// - `**` matches any sequence of characters (including `/`)
    ///
    /// Examples:
    /// - `"https://api.example.com/**"` -- any path on api.example.com
    /// - `"https://*.slack.com/api/**"` -- any Slack API subdomain
    /// - `"https://api.github.com/repos/*/issues"` -- issues endpoint for any repo
    #[serde(default)]
    pub allowed_urls: Vec<String>,

    /// Maximum requests per minute (overrides global rate limit).
    /// Must be <= the global HTTP_RATE_LIMIT_PER_MINUTE.
    #[serde(default)]
    pub max_requests_per_minute: Option<usize>,
}

/// Credential permission: which credential keys the plugin may access.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialPermission {
    /// Allowed credential key patterns. Keys are always auto-prefixed with the
    /// plugin ID, so these patterns match the suffix after the prefix.
    ///
    /// Examples:
    /// - `"token"` -- only the key named "token"
    /// - `"api-*"` -- any key starting with "api-"
    /// - `"*"` -- any key (equivalent to the boolean allow_credentials)
    #[serde(default)]
    pub allowed_keys: Vec<String>,
}

/// Media permission: which URL patterns the plugin may download media from.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MediaPermission {
    /// Allowed URL patterns for media downloads (same syntax as HTTP).
    #[serde(default)]
    pub allowed_urls: Vec<String>,
}

// ============== Permission Configuration (Gateway Config) ==============

/// Per-plugin permission overrides in the gateway configuration.
///
/// The gateway operator can tighten or loosen permissions for individual plugins.
/// These overrides are applied on top of the plugin's declared permissions.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PermissionOverride {
    /// Override HTTP URL patterns. If set, replaces the plugin's declared patterns.
    #[serde(default)]
    pub http_allowed_urls: Option<Vec<String>>,

    /// Override max HTTP requests per minute.
    #[serde(default)]
    pub http_max_requests_per_minute: Option<usize>,

    /// Override credential key patterns.
    #[serde(default)]
    pub credential_allowed_keys: Option<Vec<String>>,

    /// Override media URL patterns.
    #[serde(default)]
    pub media_allowed_urls: Option<Vec<String>>,

    /// Deny all permissions regardless of declarations.
    /// When true, the plugin is blocked from all capability use.
    #[serde(default)]
    pub deny_all: bool,
}

/// Gateway-level permission configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PermissionConfig {
    /// Whether fine-grained permissions are enabled.
    /// When false, falls back to the coarse-grained sandbox.
    #[serde(default)]
    pub enabled: bool,

    /// Per-plugin permission overrides, keyed by plugin ID.
    #[serde(default)]
    pub overrides: HashMap<String, PermissionOverride>,
}

// ============== Effective Permissions ==============

/// The computed effective permissions for a plugin, merging declared + overrides.
///
/// Computed once at plugin load time and cached for runtime enforcement.
#[derive(Debug, Clone)]
pub struct EffectivePermissions {
    /// Plugin ID this applies to.
    pub plugin_id: String,

    /// Compiled HTTP URL matchers. Empty means no HTTP access.
    pub http_url_matchers: Vec<UrlMatcher>,

    /// Effective max HTTP requests per minute. None means use global default.
    pub http_max_requests_per_minute: Option<usize>,

    /// Compiled credential key matchers. Empty means no credential access.
    pub credential_key_matchers: Vec<GlobMatcher>,

    /// Compiled media URL matchers. Empty means no media access.
    pub media_url_matchers: Vec<UrlMatcher>,

    /// Whether the plugin has any HTTP permission at all.
    pub has_http: bool,

    /// Whether the plugin has any credential permission at all.
    pub has_credentials: bool,

    /// Whether the plugin has any media permission at all.
    pub has_media: bool,
}

/// Compute effective permissions by merging declared permissions with config overrides.
pub fn compute_effective_permissions(
    plugin_id: &str,
    declared: &DeclaredPermissions,
    config: &PermissionConfig,
) -> EffectivePermissions {
    let override_cfg = config.overrides.get(plugin_id);

    // If deny_all is set, return empty permissions
    if let Some(ov) = override_cfg {
        if ov.deny_all {
            return EffectivePermissions {
                plugin_id: plugin_id.to_string(),
                http_url_matchers: Vec::new(),
                http_max_requests_per_minute: None,
                credential_key_matchers: Vec::new(),
                media_url_matchers: Vec::new(),
                has_http: false,
                has_credentials: false,
                has_media: false,
            };
        }
    }

    // HTTP permissions
    let (http_url_matchers, http_max_rpm, has_http) =
        compute_http_permissions(plugin_id, declared.http.as_ref(), override_cfg);

    // Credential permissions
    let (credential_key_matchers, has_credentials) =
        compute_credential_permissions(plugin_id, declared.credentials.as_ref(), override_cfg);

    // Media permissions
    let (media_url_matchers, has_media) =
        compute_media_permissions(plugin_id, declared.media.as_ref(), override_cfg);

    EffectivePermissions {
        plugin_id: plugin_id.to_string(),
        http_url_matchers,
        http_max_requests_per_minute: http_max_rpm,
        credential_key_matchers,
        media_url_matchers,
        has_http,
        has_credentials,
        has_media,
    }
}

fn compute_http_permissions(
    plugin_id: &str,
    declared: Option<&HttpPermission>,
    override_cfg: Option<&PermissionOverride>,
) -> (Vec<UrlMatcher>, Option<usize>, bool) {
    let patterns = if let Some(ov) = override_cfg {
        if let Some(ref urls) = ov.http_allowed_urls {
            urls.clone()
        } else {
            declared.map(|d| d.allowed_urls.clone()).unwrap_or_default()
        }
    } else {
        declared.map(|d| d.allowed_urls.clone()).unwrap_or_default()
    };

    let has_http =
        declared.is_some() || override_cfg.is_some_and(|o| o.http_allowed_urls.is_some());

    let max_rpm = if let Some(ov) = override_cfg {
        ov.http_max_requests_per_minute
            .or_else(|| declared.and_then(|d| d.max_requests_per_minute))
    } else {
        declared.and_then(|d| d.max_requests_per_minute)
    };

    let matchers = compile_url_matchers(plugin_id, "http", &patterns);

    (matchers, max_rpm, has_http)
}

fn compute_credential_permissions(
    plugin_id: &str,
    declared: Option<&CredentialPermission>,
    override_cfg: Option<&PermissionOverride>,
) -> (Vec<GlobMatcher>, bool) {
    let patterns = if let Some(ov) = override_cfg {
        if let Some(ref keys) = ov.credential_allowed_keys {
            keys.clone()
        } else {
            declared.map(|d| d.allowed_keys.clone()).unwrap_or_default()
        }
    } else {
        declared.map(|d| d.allowed_keys.clone()).unwrap_or_default()
    };

    let has_credentials =
        declared.is_some() || override_cfg.is_some_and(|o| o.credential_allowed_keys.is_some());

    let matchers = compile_glob_matchers(plugin_id, "credentials", &patterns);

    (matchers, has_credentials)
}

fn compute_media_permissions(
    plugin_id: &str,
    declared: Option<&MediaPermission>,
    override_cfg: Option<&PermissionOverride>,
) -> (Vec<UrlMatcher>, bool) {
    let patterns = if let Some(ov) = override_cfg {
        if let Some(ref urls) = ov.media_allowed_urls {
            urls.clone()
        } else {
            declared.map(|d| d.allowed_urls.clone()).unwrap_or_default()
        }
    } else {
        declared.map(|d| d.allowed_urls.clone()).unwrap_or_default()
    };

    let has_media =
        declared.is_some() || override_cfg.is_some_and(|o| o.media_allowed_urls.is_some());

    let matchers = compile_url_matchers(plugin_id, "media", &patterns);

    (matchers, has_media)
}

fn compile_url_matchers(plugin_id: &str, scope: &str, patterns: &[String]) -> Vec<UrlMatcher> {
    patterns
        .iter()
        .filter_map(|pattern| match UrlMatcher::new(pattern) {
            Ok(matcher) => Some(matcher),
            Err(error) => {
                tracing::warn!(
                    plugin_id = %plugin_id,
                    scope = %scope,
                    pattern = %pattern,
                    error = %error,
                    "invalid URL permission pattern ignored"
                );
                None
            }
        })
        .collect()
}

fn compile_glob_matchers(plugin_id: &str, scope: &str, patterns: &[String]) -> Vec<GlobMatcher> {
    patterns
        .iter()
        .filter_map(|pattern| match GlobMatcher::new(pattern) {
            Ok(matcher) => Some(matcher),
            Err(error) => {
                tracing::warn!(
                    plugin_id = %plugin_id,
                    scope = %scope,
                    pattern = %pattern,
                    error = %error,
                    "invalid glob permission pattern ignored"
                );
                None
            }
        })
        .collect()
}

// ============== Pattern Matching ==============

/// A compiled URL matcher that supports glob-style patterns.
///
/// Patterns are converted to regular expressions:
/// - `**` becomes `.*` (match everything)
/// - `*` becomes `[^/]*` (match within a path segment)
/// - All other regex metacharacters are escaped
#[derive(Debug, Clone)]
pub struct UrlMatcher {
    /// The original pattern string.
    pub pattern: String,
    /// Compiled regex.
    regex: Regex,
}

impl UrlMatcher {
    /// Create a new URL matcher from a glob-style pattern.
    pub fn new(pattern: &str) -> Result<Self, String> {
        let regex_str = glob_to_regex(pattern);
        let regex = Regex::new(&regex_str).map_err(|e| {
            format!(
                "Invalid URL pattern '{}' (compiled to '{}'): {}",
                pattern, regex_str, e
            )
        })?;
        Ok(Self {
            pattern: pattern.to_string(),
            regex,
        })
    }

    /// Check if a URL matches this pattern.
    pub fn matches(&self, url: &str) -> bool {
        self.regex.is_match(url)
    }
}

/// A compiled glob matcher for simple key patterns.
///
/// Supports:
/// - `*` matches any sequence of characters
/// - All other regex metacharacters are escaped
#[derive(Debug, Clone)]
pub struct GlobMatcher {
    /// The original pattern string.
    pub pattern: String,
    /// Compiled regex.
    regex: Regex,
}

impl GlobMatcher {
    /// Create a new glob matcher.
    pub fn new(pattern: &str) -> Result<Self, String> {
        let regex_str = simple_glob_to_regex(pattern);
        let regex = Regex::new(&regex_str).map_err(|e| {
            format!(
                "Invalid key pattern '{}' (compiled to '{}'): {}",
                pattern, regex_str, e
            )
        })?;
        Ok(Self {
            pattern: pattern.to_string(),
            regex,
        })
    }

    /// Check if a key matches this pattern.
    pub fn matches(&self, key: &str) -> bool {
        self.regex.is_match(key)
    }
}

/// Convert a URL glob pattern to a regex string.
///
/// Processing order matters: `**` must be handled before `*`.
fn glob_to_regex(pattern: &str) -> String {
    // First, split on `**` to handle it specially
    let parts: Vec<&str> = pattern.split("**").collect();

    let escaped_parts: Vec<String> = parts
        .iter()
        .map(|part| {
            // Within each part, escape regex metacharacters, then replace `*` with `[^/]*`
            let escaped = regex::escape(part);
            escaped.replace(r"\*", "[^/]*")
        })
        .collect();

    // Join with `.*` for the `**` wildcard
    format!("^{}$", escaped_parts.join(".*"))
}

/// Convert a simple glob pattern to a regex string.
///
/// `*` matches any characters (including none).
fn simple_glob_to_regex(pattern: &str) -> String {
    let escaped = regex::escape(pattern);
    format!("^{}$", escaped.replace(r"\*", ".*"))
}

// ============== Runtime Enforcement ==============

/// Runtime permission enforcer.
///
/// Created once per plugin with the effective permissions, and consulted
/// on every host function call that requires permission checks.
#[derive(Debug, Clone)]
pub struct PermissionEnforcer {
    permissions: EffectivePermissions,
    /// Whether fine-grained enforcement is active.
    enabled: bool,
}

impl PermissionEnforcer {
    /// Create a new enforcer. If `enabled` is false, all checks pass.
    pub fn new(permissions: EffectivePermissions, enabled: bool) -> Self {
        Self {
            permissions,
            enabled,
        }
    }

    /// Create a permissive enforcer that allows everything.
    pub fn permissive(plugin_id: &str) -> Self {
        Self {
            permissions: EffectivePermissions {
                plugin_id: plugin_id.to_string(),
                http_url_matchers: Vec::new(),
                http_max_requests_per_minute: None,
                credential_key_matchers: Vec::new(),
                media_url_matchers: Vec::new(),
                has_http: false,
                has_credentials: false,
                has_media: false,
            },
            enabled: false,
        }
    }

    /// Check if the enforcer is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Get the plugin ID.
    pub fn plugin_id(&self) -> &str {
        &self.permissions.plugin_id
    }

    /// Get the effective max HTTP requests per minute, if set.
    pub fn http_max_requests_per_minute(&self) -> Option<usize> {
        if self.enabled {
            self.permissions.http_max_requests_per_minute
        } else {
            None
        }
    }

    /// Check if an HTTP request to the given URL is permitted.
    ///
    /// Returns `Ok(())` if:
    /// - Fine-grained permissions are disabled, OR
    /// - The plugin has no HTTP permission declared (falls back to sandbox), OR
    /// - The URL matches at least one allowed pattern
    pub fn check_http_url(&self, url: &str) -> Result<(), PermissionError> {
        if !self.enabled || !self.permissions.has_http {
            return Ok(());
        }

        if self.permissions.http_url_matchers.is_empty() {
            return Err(PermissionError::HttpUrlDenied {
                plugin_id: self.permissions.plugin_id.clone(),
                url: url.to_string(),
                reason: "no URL patterns allowed".to_string(),
            });
        }

        if self
            .permissions
            .http_url_matchers
            .iter()
            .any(|m| m.matches(url))
        {
            Ok(())
        } else {
            Err(PermissionError::HttpUrlDenied {
                plugin_id: self.permissions.plugin_id.clone(),
                url: url.to_string(),
                reason: format!(
                    "URL does not match any allowed pattern (allowed: [{}])",
                    self.permissions
                        .http_url_matchers
                        .iter()
                        .map(|m| m.pattern.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            })
        }
    }

    /// Check if a credential key access is permitted.
    ///
    /// The key is the *unprefixed* key (before the plugin ID prefix is added).
    pub fn check_credential_key(&self, key: &str) -> Result<(), PermissionError> {
        if !self.enabled || !self.permissions.has_credentials {
            return Ok(());
        }

        if self.permissions.credential_key_matchers.is_empty() {
            return Err(PermissionError::CredentialScopeDenied {
                plugin_id: self.permissions.plugin_id.clone(),
                key: key.to_string(),
                reason: "no credential key patterns allowed".to_string(),
            });
        }

        if self
            .permissions
            .credential_key_matchers
            .iter()
            .any(|m| m.matches(key))
        {
            Ok(())
        } else {
            Err(PermissionError::CredentialScopeDenied {
                plugin_id: self.permissions.plugin_id.clone(),
                key: key.to_string(),
                reason: format!(
                    "key does not match any allowed pattern (allowed: [{}])",
                    self.permissions
                        .credential_key_matchers
                        .iter()
                        .map(|m| m.pattern.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            })
        }
    }

    /// Check if a media fetch from the given URL is permitted.
    pub fn check_media_url(&self, url: &str) -> Result<(), PermissionError> {
        if !self.enabled || !self.permissions.has_media {
            return Ok(());
        }

        if self.permissions.media_url_matchers.is_empty() {
            return Err(PermissionError::MediaUrlDenied {
                plugin_id: self.permissions.plugin_id.clone(),
                url: url.to_string(),
                reason: "no media URL patterns allowed".to_string(),
            });
        }

        if self
            .permissions
            .media_url_matchers
            .iter()
            .any(|m| m.matches(url))
        {
            Ok(())
        } else {
            Err(PermissionError::MediaUrlDenied {
                plugin_id: self.permissions.plugin_id.clone(),
                url: url.to_string(),
                reason: format!(
                    "URL does not match any allowed pattern (allowed: [{}])",
                    self.permissions
                        .media_url_matchers
                        .iter()
                        .map(|m| m.pattern.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            })
        }
    }
}

// ============== Load-time Validation ==============

/// Validate that a plugin's declared permissions are consistent with the
/// gateway's permission configuration.
///
/// This is called at plugin load time, before instantiation.
/// Returns a list of denied permission descriptions, or an empty vec if all granted.
pub fn validate_declared_permissions(
    plugin_id: &str,
    declared: &DeclaredPermissions,
    config: &PermissionConfig,
) -> Vec<PermissionError> {
    if !config.enabled {
        return Vec::new();
    }

    let mut errors = Vec::new();

    // Check if the plugin is explicitly denied
    if let Some(ov) = config.overrides.get(plugin_id) {
        if ov.deny_all {
            if declared.http.is_some() || declared.credentials.is_some() || declared.media.is_some()
            {
                errors.push(PermissionError::PermissionNotGranted {
                    plugin_id: plugin_id.to_string(),
                    permission: "all".to_string(),
                    reason: "plugin is deny_all in gateway config".to_string(),
                });
            }
            return errors;
        }
    }

    // Validate each declared permission compiles correctly
    if let Some(ref http) = declared.http {
        for pattern in &http.allowed_urls {
            if UrlMatcher::new(pattern).is_err() {
                errors.push(PermissionError::PermissionNotGranted {
                    plugin_id: plugin_id.to_string(),
                    permission: format!("http.allowed_urls: {}", pattern),
                    reason: "invalid URL pattern".to_string(),
                });
            }
        }

        // Validate rate limit
        if let Some(rpm) = http.max_requests_per_minute {
            if rpm > super::capabilities::HTTP_RATE_LIMIT_PER_MINUTE {
                errors.push(PermissionError::PermissionNotGranted {
                    plugin_id: plugin_id.to_string(),
                    permission: format!("http.max_requests_per_minute: {}", rpm),
                    reason: format!(
                        "exceeds global limit of {}",
                        super::capabilities::HTTP_RATE_LIMIT_PER_MINUTE
                    ),
                });
            }
        }
    }

    if let Some(ref creds) = declared.credentials {
        for pattern in &creds.allowed_keys {
            if GlobMatcher::new(pattern).is_err() {
                errors.push(PermissionError::PermissionNotGranted {
                    plugin_id: plugin_id.to_string(),
                    permission: format!("credentials.allowed_keys: {}", pattern),
                    reason: "invalid key pattern".to_string(),
                });
            }
        }
    }

    if let Some(ref media) = declared.media {
        for pattern in &media.allowed_urls {
            if UrlMatcher::new(pattern).is_err() {
                errors.push(PermissionError::PermissionNotGranted {
                    plugin_id: plugin_id.to_string(),
                    permission: format!("media.allowed_urls: {}", pattern),
                    reason: "invalid URL pattern".to_string(),
                });
            }
        }
    }

    errors
}

#[cfg(test)]
mod tests {
    use super::*;

    // ============== URL Pattern Matching ==============

    #[test]
    fn test_url_matcher_exact() {
        let m = UrlMatcher::new("https://api.example.com/v1/data").unwrap();
        assert!(m.matches("https://api.example.com/v1/data"));
        assert!(!m.matches("https://api.example.com/v1/other"));
        assert!(!m.matches("https://api.example.com/v1/data/extra"));
    }

    #[test]
    fn test_url_matcher_single_star() {
        // `*` matches within a single path segment (no slashes)
        let m = UrlMatcher::new("https://api.example.com/*/data").unwrap();
        assert!(m.matches("https://api.example.com/v1/data"));
        assert!(m.matches("https://api.example.com/v2/data"));
        assert!(!m.matches("https://api.example.com/v1/v2/data"));
    }

    #[test]
    fn test_url_matcher_double_star() {
        // `**` matches any sequence of characters (including slashes)
        let m = UrlMatcher::new("https://api.example.com/**").unwrap();
        assert!(m.matches("https://api.example.com/v1/data"));
        assert!(m.matches("https://api.example.com/"));
        assert!(m.matches("https://api.example.com/a/b/c/d"));
        assert!(!m.matches("https://other.example.com/v1/data"));
    }

    #[test]
    fn test_url_matcher_subdomain_star() {
        let m = UrlMatcher::new("https://*.slack.com/api/**").unwrap();
        assert!(m.matches("https://hooks.slack.com/api/webhook"));
        assert!(m.matches("https://files.slack.com/api/upload/file"));
        assert!(!m.matches("https://slack.com/api/webhook")); // no subdomain
        assert!(!m.matches("https://evil-slack.com/api/webhook")); // different domain
    }

    #[test]
    fn test_url_matcher_escapes_regex_metacharacters() {
        // The `.` in the domain should be treated literally, not as regex wildcard
        let m = UrlMatcher::new("https://api.example.com/v1").unwrap();
        assert!(m.matches("https://api.example.com/v1"));
        assert!(!m.matches("https://apiXexample.com/v1")); // `.` should not match `X`
    }

    #[test]
    fn test_url_matcher_question_mark_escaped() {
        let m = UrlMatcher::new("https://api.example.com/search?q=test").unwrap();
        assert!(m.matches("https://api.example.com/search?q=test"));
        assert!(!m.matches("https://api.example.com/searchXq=test"));
    }

    #[test]
    fn test_url_matcher_invalid_pattern() {
        // This should succeed because the glob-to-regex conversion handles escaping
        let result = UrlMatcher::new("https://api.example.com/**");
        assert!(result.is_ok());
    }

    // ============== Glob Pattern Matching (Credential Keys) ==============

    #[test]
    fn test_glob_matcher_exact() {
        let m = GlobMatcher::new("token").unwrap();
        assert!(m.matches("token"));
        assert!(!m.matches("token-extra"));
        assert!(!m.matches("my-token"));
    }

    #[test]
    fn test_glob_matcher_wildcard() {
        let m = GlobMatcher::new("api-*").unwrap();
        assert!(m.matches("api-key"));
        assert!(m.matches("api-token"));
        assert!(m.matches("api-"));
        assert!(!m.matches("my-api-key"));
    }

    #[test]
    fn test_glob_matcher_star_only() {
        let m = GlobMatcher::new("*").unwrap();
        assert!(m.matches("anything"));
        assert!(m.matches("token"));
        assert!(m.matches(""));
    }

    #[test]
    fn test_glob_matcher_prefix_and_suffix() {
        let m = GlobMatcher::new("oauth-*-token").unwrap();
        assert!(m.matches("oauth-slack-token"));
        assert!(m.matches("oauth-github-token"));
        assert!(!m.matches("oauth-token")); // missing middle part... actually `*` matches empty
    }

    // ============== Effective Permissions Computation ==============

    #[test]
    fn test_compute_effective_no_config() {
        let declared = DeclaredPermissions {
            http: Some(HttpPermission {
                allowed_urls: vec!["https://api.example.com/**".to_string()],
                max_requests_per_minute: Some(50),
            }),
            credentials: Some(CredentialPermission {
                allowed_keys: vec!["token".to_string()],
            }),
            media: None,
        };

        let config = PermissionConfig::default();
        let eff = compute_effective_permissions("test-plugin", &declared, &config);

        assert_eq!(eff.plugin_id, "test-plugin");
        assert!(eff.has_http);
        assert_eq!(eff.http_url_matchers.len(), 1);
        assert_eq!(eff.http_max_requests_per_minute, Some(50));
        assert!(eff.has_credentials);
        assert_eq!(eff.credential_key_matchers.len(), 1);
        assert!(!eff.has_media);
    }

    #[test]
    fn test_compute_effective_with_override() {
        let declared = DeclaredPermissions {
            http: Some(HttpPermission {
                allowed_urls: vec!["https://api.example.com/**".to_string()],
                max_requests_per_minute: None,
            }),
            credentials: None,
            media: None,
        };

        let mut overrides = HashMap::new();
        overrides.insert(
            "test-plugin".to_string(),
            PermissionOverride {
                http_allowed_urls: Some(vec![
                    "https://api.example.com/v1/**".to_string(),
                    "https://api.example.com/v2/**".to_string(),
                ]),
                http_max_requests_per_minute: Some(30),
                credential_allowed_keys: None,
                media_allowed_urls: None,
                deny_all: false,
            },
        );

        let config = PermissionConfig {
            enabled: true,
            overrides,
        };

        let eff = compute_effective_permissions("test-plugin", &declared, &config);
        assert_eq!(eff.http_url_matchers.len(), 2);
        assert_eq!(eff.http_max_requests_per_minute, Some(30));
    }

    #[test]
    fn test_compute_effective_deny_all() {
        let declared = DeclaredPermissions {
            http: Some(HttpPermission {
                allowed_urls: vec!["https://api.example.com/**".to_string()],
                max_requests_per_minute: None,
            }),
            credentials: Some(CredentialPermission {
                allowed_keys: vec!["*".to_string()],
            }),
            media: Some(MediaPermission {
                allowed_urls: vec!["https://media.example.com/**".to_string()],
            }),
        };

        let mut overrides = HashMap::new();
        overrides.insert(
            "blocked-plugin".to_string(),
            PermissionOverride {
                deny_all: true,
                ..Default::default()
            },
        );

        let config = PermissionConfig {
            enabled: true,
            overrides,
        };

        let eff = compute_effective_permissions("blocked-plugin", &declared, &config);
        assert!(!eff.has_http);
        assert!(!eff.has_credentials);
        assert!(!eff.has_media);
        assert!(eff.http_url_matchers.is_empty());
        assert!(eff.credential_key_matchers.is_empty());
        assert!(eff.media_url_matchers.is_empty());
    }

    #[test]
    fn test_compute_effective_no_declared() {
        let declared = DeclaredPermissions::default();
        let config = PermissionConfig::default();

        let eff = compute_effective_permissions("minimal-plugin", &declared, &config);
        assert!(!eff.has_http);
        assert!(!eff.has_credentials);
        assert!(!eff.has_media);
    }

    // ============== Permission Enforcer ==============

    #[test]
    fn test_enforcer_disabled() {
        let declared = DeclaredPermissions {
            http: Some(HttpPermission {
                allowed_urls: vec!["https://only-this.com/**".to_string()],
                max_requests_per_minute: None,
            }),
            credentials: None,
            media: None,
        };
        let config = PermissionConfig::default();
        let eff = compute_effective_permissions("test", &declared, &config);
        let enforcer = PermissionEnforcer::new(eff, false);

        // Disabled enforcer allows everything
        assert!(enforcer.check_http_url("https://anything.com/api").is_ok());
        assert!(enforcer.check_credential_key("any-key").is_ok());
        assert!(enforcer
            .check_media_url("https://anything.com/file.png")
            .is_ok());
    }

    #[test]
    fn test_enforcer_http_allowed() {
        let declared = DeclaredPermissions {
            http: Some(HttpPermission {
                allowed_urls: vec![
                    "https://api.example.com/**".to_string(),
                    "https://hooks.slack.com/**".to_string(),
                ],
                max_requests_per_minute: None,
            }),
            credentials: None,
            media: None,
        };
        let config = PermissionConfig {
            enabled: true,
            ..Default::default()
        };
        let eff = compute_effective_permissions("test", &declared, &config);
        let enforcer = PermissionEnforcer::new(eff, true);

        assert!(enforcer
            .check_http_url("https://api.example.com/v1/data")
            .is_ok());
        assert!(enforcer
            .check_http_url("https://hooks.slack.com/services/abc")
            .is_ok());
    }

    #[test]
    fn test_enforcer_http_denied() {
        let declared = DeclaredPermissions {
            http: Some(HttpPermission {
                allowed_urls: vec!["https://api.example.com/**".to_string()],
                max_requests_per_minute: None,
            }),
            credentials: None,
            media: None,
        };
        let config = PermissionConfig {
            enabled: true,
            ..Default::default()
        };
        let eff = compute_effective_permissions("test", &declared, &config);
        let enforcer = PermissionEnforcer::new(eff, true);

        let result = enforcer.check_http_url("https://evil.com/steal");
        assert!(result.is_err());
        match result.unwrap_err() {
            PermissionError::HttpUrlDenied {
                plugin_id,
                url,
                reason,
            } => {
                assert_eq!(plugin_id, "test");
                assert_eq!(url, "https://evil.com/steal");
                assert!(reason.contains("does not match"));
            }
            other => panic!("Expected HttpUrlDenied, got: {:?}", other),
        }
    }

    #[test]
    fn test_enforcer_credentials_allowed() {
        let declared = DeclaredPermissions {
            http: None,
            credentials: Some(CredentialPermission {
                allowed_keys: vec!["token".to_string(), "api-*".to_string()],
            }),
            media: None,
        };
        let config = PermissionConfig {
            enabled: true,
            ..Default::default()
        };
        let eff = compute_effective_permissions("test", &declared, &config);
        let enforcer = PermissionEnforcer::new(eff, true);

        assert!(enforcer.check_credential_key("token").is_ok());
        assert!(enforcer.check_credential_key("api-key").is_ok());
        assert!(enforcer.check_credential_key("api-secret").is_ok());
    }

    #[test]
    fn test_enforcer_credentials_denied() {
        let declared = DeclaredPermissions {
            http: None,
            credentials: Some(CredentialPermission {
                allowed_keys: vec!["token".to_string()],
            }),
            media: None,
        };
        let config = PermissionConfig {
            enabled: true,
            ..Default::default()
        };
        let eff = compute_effective_permissions("test", &declared, &config);
        let enforcer = PermissionEnforcer::new(eff, true);

        let result = enforcer.check_credential_key("secret");
        assert!(result.is_err());
        match result.unwrap_err() {
            PermissionError::CredentialScopeDenied { plugin_id, key, .. } => {
                assert_eq!(plugin_id, "test");
                assert_eq!(key, "secret");
            }
            other => panic!("Expected CredentialScopeDenied, got: {:?}", other),
        }
    }

    #[test]
    fn test_enforcer_media_allowed() {
        let declared = DeclaredPermissions {
            http: None,
            credentials: None,
            media: Some(MediaPermission {
                allowed_urls: vec!["https://media.example.com/**".to_string()],
            }),
        };
        let config = PermissionConfig {
            enabled: true,
            ..Default::default()
        };
        let eff = compute_effective_permissions("test", &declared, &config);
        let enforcer = PermissionEnforcer::new(eff, true);

        assert!(enforcer
            .check_media_url("https://media.example.com/images/photo.jpg")
            .is_ok());
    }

    #[test]
    fn test_enforcer_media_denied() {
        let declared = DeclaredPermissions {
            http: None,
            credentials: None,
            media: Some(MediaPermission {
                allowed_urls: vec!["https://media.example.com/**".to_string()],
            }),
        };
        let config = PermissionConfig {
            enabled: true,
            ..Default::default()
        };
        let eff = compute_effective_permissions("test", &declared, &config);
        let enforcer = PermissionEnforcer::new(eff, true);

        let result = enforcer.check_media_url("https://evil.com/malware.exe");
        assert!(result.is_err());
    }

    #[test]
    fn test_enforcer_no_http_declared_falls_back() {
        // If the plugin did NOT declare HTTP permissions, the enforcer passes
        // (falls back to the sandbox's coarse-grained check)
        let declared = DeclaredPermissions::default();
        let config = PermissionConfig {
            enabled: true,
            ..Default::default()
        };
        let eff = compute_effective_permissions("test", &declared, &config);
        let enforcer = PermissionEnforcer::new(eff, true);

        assert!(enforcer.check_http_url("https://anything.com/api").is_ok());
    }

    #[test]
    fn test_enforcer_empty_patterns_denies_all() {
        // If a plugin declares HTTP permission but with empty patterns, all URLs are denied
        let declared = DeclaredPermissions {
            http: Some(HttpPermission {
                allowed_urls: vec![],
                max_requests_per_minute: None,
            }),
            credentials: None,
            media: None,
        };
        let config = PermissionConfig {
            enabled: true,
            ..Default::default()
        };
        let eff = compute_effective_permissions("test", &declared, &config);
        let enforcer = PermissionEnforcer::new(eff, true);

        let result = enforcer.check_http_url("https://any.com/api");
        assert!(result.is_err());
    }

    #[test]
    fn test_enforcer_permissive() {
        let enforcer = PermissionEnforcer::permissive("any-plugin");
        assert!(!enforcer.is_enabled());
        assert!(enforcer.check_http_url("https://anything.com").is_ok());
        assert!(enforcer.check_credential_key("any-key").is_ok());
        assert!(enforcer
            .check_media_url("https://anything.com/file")
            .is_ok());
    }

    // ============== Load-time Validation ==============

    #[test]
    fn test_validate_declared_disabled() {
        let declared = DeclaredPermissions {
            http: Some(HttpPermission {
                allowed_urls: vec!["[invalid-regex".to_string()],
                max_requests_per_minute: Some(9999),
            }),
            credentials: None,
            media: None,
        };
        let config = PermissionConfig {
            enabled: false,
            ..Default::default()
        };

        // Validation is skipped when disabled
        let errors = validate_declared_permissions("test", &declared, &config);
        assert!(errors.is_empty());
    }

    #[test]
    fn test_validate_declared_deny_all() {
        let declared = DeclaredPermissions {
            http: Some(HttpPermission {
                allowed_urls: vec!["https://api.example.com/**".to_string()],
                max_requests_per_minute: None,
            }),
            credentials: None,
            media: None,
        };

        let mut overrides = HashMap::new();
        overrides.insert(
            "test".to_string(),
            PermissionOverride {
                deny_all: true,
                ..Default::default()
            },
        );
        let config = PermissionConfig {
            enabled: true,
            overrides,
        };

        let errors = validate_declared_permissions("test", &declared, &config);
        assert_eq!(errors.len(), 1);
        match &errors[0] {
            PermissionError::PermissionNotGranted { reason, .. } => {
                assert!(reason.contains("deny_all"));
            }
            other => panic!("Expected PermissionNotGranted, got: {:?}", other),
        }
    }

    #[test]
    fn test_validate_declared_excessive_rate_limit() {
        let declared = DeclaredPermissions {
            http: Some(HttpPermission {
                allowed_urls: vec!["https://api.example.com/**".to_string()],
                max_requests_per_minute: Some(9999),
            }),
            credentials: None,
            media: None,
        };
        let config = PermissionConfig {
            enabled: true,
            ..Default::default()
        };

        let errors = validate_declared_permissions("test", &declared, &config);
        assert_eq!(errors.len(), 1);
        match &errors[0] {
            PermissionError::PermissionNotGranted {
                permission, reason, ..
            } => {
                assert!(permission.contains("max_requests_per_minute"));
                assert!(reason.contains("exceeds global limit"));
            }
            other => panic!("Expected PermissionNotGranted, got: {:?}", other),
        }
    }

    #[test]
    fn test_validate_declared_valid() {
        let declared = DeclaredPermissions {
            http: Some(HttpPermission {
                allowed_urls: vec![
                    "https://api.example.com/**".to_string(),
                    "https://*.slack.com/api/**".to_string(),
                ],
                max_requests_per_minute: Some(50),
            }),
            credentials: Some(CredentialPermission {
                allowed_keys: vec!["token".to_string(), "api-*".to_string()],
            }),
            media: Some(MediaPermission {
                allowed_urls: vec!["https://media.example.com/**".to_string()],
            }),
        };
        let config = PermissionConfig {
            enabled: true,
            ..Default::default()
        };

        let errors = validate_declared_permissions("test", &declared, &config);
        assert!(errors.is_empty(), "Expected no errors, got: {:?}", errors);
    }

    // ============== Glob-to-Regex Conversion ==============

    #[test]
    fn test_glob_to_regex_exact() {
        let re = glob_to_regex("https://api.example.com/v1");
        assert_eq!(re, r"^https://api\.example\.com/v1$");
    }

    #[test]
    fn test_glob_to_regex_double_star() {
        let re = glob_to_regex("https://api.example.com/**");
        assert_eq!(re, r"^https://api\.example\.com/.*$");
    }

    #[test]
    fn test_glob_to_regex_single_star() {
        let re = glob_to_regex("https://api.example.com/*/data");
        assert_eq!(re, r"^https://api\.example\.com/[^/]*/data$");
    }

    #[test]
    fn test_simple_glob_to_regex_exact() {
        let re = simple_glob_to_regex("token");
        assert_eq!(re, "^token$");
    }

    #[test]
    fn test_simple_glob_to_regex_wildcard() {
        let re = simple_glob_to_regex("api-*");
        assert_eq!(re, "^api\\-.*$");
    }

    // ============== Serde Round-trip ==============

    #[test]
    fn test_declared_permissions_serde() {
        let declared = DeclaredPermissions {
            http: Some(HttpPermission {
                allowed_urls: vec!["https://api.example.com/**".to_string()],
                max_requests_per_minute: Some(50),
            }),
            credentials: Some(CredentialPermission {
                allowed_keys: vec!["token".to_string(), "api-*".to_string()],
            }),
            media: None,
        };

        let json = serde_json::to_string(&declared).unwrap();
        let parsed: DeclaredPermissions = serde_json::from_str(&json).unwrap();

        assert!(parsed.http.is_some());
        assert_eq!(parsed.http.as_ref().unwrap().allowed_urls.len(), 1);
        assert_eq!(
            parsed.http.as_ref().unwrap().max_requests_per_minute,
            Some(50)
        );
        assert!(parsed.credentials.is_some());
        assert_eq!(parsed.credentials.as_ref().unwrap().allowed_keys.len(), 2);
        assert!(parsed.media.is_none());
    }

    #[test]
    fn test_permission_config_serde() {
        let mut overrides = HashMap::new();
        overrides.insert(
            "my-plugin".to_string(),
            PermissionOverride {
                http_allowed_urls: Some(vec!["https://api.example.com/**".to_string()]),
                http_max_requests_per_minute: Some(30),
                credential_allowed_keys: None,
                media_allowed_urls: None,
                deny_all: false,
            },
        );

        let config = PermissionConfig {
            enabled: true,
            overrides,
        };

        let json = serde_json::to_string(&config).unwrap();
        let parsed: PermissionConfig = serde_json::from_str(&json).unwrap();

        assert!(parsed.enabled);
        assert!(parsed.overrides.contains_key("my-plugin"));
        let ov = &parsed.overrides["my-plugin"];
        assert_eq!(ov.http_allowed_urls.as_ref().unwrap().len(), 1);
        assert_eq!(ov.http_max_requests_per_minute, Some(30));
        assert!(!ov.deny_all);
    }

    #[test]
    fn test_permission_override_default() {
        let ov = PermissionOverride::default();
        assert!(!ov.deny_all);
        assert!(ov.http_allowed_urls.is_none());
        assert!(ov.http_max_requests_per_minute.is_none());
        assert!(ov.credential_allowed_keys.is_none());
        assert!(ov.media_allowed_urls.is_none());
    }

    // ============== Error Display ==============

    #[test]
    fn test_permission_error_display_http() {
        let err = PermissionError::HttpUrlDenied {
            plugin_id: "my-plugin".to_string(),
            url: "https://evil.com/api".to_string(),
            reason: "URL does not match".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("my-plugin"));
        assert!(msg.contains("https://evil.com/api"));
        assert!(msg.contains("denied"));
    }

    #[test]
    fn test_permission_error_display_credential() {
        let err = PermissionError::CredentialScopeDenied {
            plugin_id: "my-plugin".to_string(),
            key: "secret-key".to_string(),
            reason: "not in scope".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("my-plugin"));
        assert!(msg.contains("secret-key"));
    }

    #[test]
    fn test_permission_error_display_media() {
        let err = PermissionError::MediaUrlDenied {
            plugin_id: "my-plugin".to_string(),
            url: "https://evil.com/malware".to_string(),
            reason: "not allowed".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("my-plugin"));
        assert!(msg.contains("malware"));
    }

    #[test]
    fn test_permission_error_display_not_granted() {
        let err = PermissionError::PermissionNotGranted {
            plugin_id: "my-plugin".to_string(),
            permission: "http".to_string(),
            reason: "denied by config".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("my-plugin"));
        assert!(msg.contains("not granted"));
    }

    // ============== Integration: Full Workflow ==============

    #[test]
    fn test_full_permission_workflow() {
        // Step 1: Plugin declares its permissions
        let declared = DeclaredPermissions {
            http: Some(HttpPermission {
                allowed_urls: vec![
                    "https://api.github.com/**".to_string(),
                    "https://hooks.slack.com/**".to_string(),
                ],
                max_requests_per_minute: Some(60),
            }),
            credentials: Some(CredentialPermission {
                allowed_keys: vec!["github-token".to_string(), "slack-webhook-*".to_string()],
            }),
            media: Some(MediaPermission {
                allowed_urls: vec!["https://avatars.githubusercontent.com/**".to_string()],
            }),
        };

        // Step 2: Gateway validates at load time
        let config = PermissionConfig {
            enabled: true,
            ..Default::default()
        };
        let errors = validate_declared_permissions("github-slack-bridge", &declared, &config);
        assert!(errors.is_empty());

        // Step 3: Compute effective permissions
        let eff = compute_effective_permissions("github-slack-bridge", &declared, &config);
        assert!(eff.has_http);
        assert!(eff.has_credentials);
        assert!(eff.has_media);

        // Step 4: Create enforcer
        let enforcer = PermissionEnforcer::new(eff, true);

        // Step 5: Runtime checks
        // Allowed requests
        assert!(enforcer
            .check_http_url("https://api.github.com/repos/user/repo/issues")
            .is_ok());
        assert!(enforcer
            .check_http_url("https://hooks.slack.com/services/T00/B00/xxx")
            .is_ok());
        assert!(enforcer.check_credential_key("github-token").is_ok());
        assert!(enforcer.check_credential_key("slack-webhook-main").is_ok());
        assert!(enforcer
            .check_media_url("https://avatars.githubusercontent.com/u/12345")
            .is_ok());

        // Denied requests
        assert!(enforcer
            .check_http_url("https://evil.com/steal-data")
            .is_err());
        assert!(enforcer.check_credential_key("aws-secret").is_err());
        assert!(enforcer
            .check_media_url("https://evil.com/malware.exe")
            .is_err());
    }

    #[test]
    fn test_gateway_operator_tightens_permissions() {
        // Plugin declares broad permissions
        let declared = DeclaredPermissions {
            http: Some(HttpPermission {
                allowed_urls: vec!["https://**".to_string()], // all HTTPS
                max_requests_per_minute: None,
            }),
            credentials: Some(CredentialPermission {
                allowed_keys: vec!["*".to_string()], // all keys
            }),
            media: None,
        };

        // Gateway operator restricts via config
        let mut overrides = HashMap::new();
        overrides.insert(
            "untrusted-plugin".to_string(),
            PermissionOverride {
                http_allowed_urls: Some(vec!["https://api.safe-service.com/**".to_string()]),
                http_max_requests_per_minute: Some(10),
                credential_allowed_keys: Some(vec!["api-key".to_string()]),
                media_allowed_urls: None,
                deny_all: false,
            },
        );
        let config = PermissionConfig {
            enabled: true,
            overrides,
        };

        let eff = compute_effective_permissions("untrusted-plugin", &declared, &config);
        let enforcer = PermissionEnforcer::new(eff, true);

        // Only the restricted URL is allowed
        assert!(enforcer
            .check_http_url("https://api.safe-service.com/v1/data")
            .is_ok());
        assert!(enforcer.check_http_url("https://evil.com/data").is_err());

        // Only the restricted credential is allowed
        assert!(enforcer.check_credential_key("api-key").is_ok());
        assert!(enforcer.check_credential_key("other-secret").is_err());

        // Rate limit is overridden
        assert_eq!(enforcer.http_max_requests_per_minute(), Some(10));
    }
}
