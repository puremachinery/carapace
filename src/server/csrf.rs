//! CSRF protection middleware
//!
//! Provides Cross-Site Request Forgery protection for state-changing routes:
//! - Token generation (cryptographically random)
//! - Token validation middleware for POST to /control/*
//! - Token stored in session/cookie

use axum::{
    body::Body,
    http::{header, HeaderMap, Method, Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;
use tracing::{debug, warn};

/// CSRF token length in bytes (before base64 encoding)
const TOKEN_BYTES: usize = 32;

/// Default CSRF token validity duration (1 hour)
const DEFAULT_TOKEN_TTL: Duration = Duration::from_secs(3600);

/// Default cookie name for CSRF token
const DEFAULT_COOKIE_NAME: &str = "__Host-csrf";

/// Default cookie name for CSRF session ID (insecure / non-TLS)
const DEFAULT_SESSION_COOKIE: &str = "session";

/// Default cookie name for CSRF session ID (secure / TLS)
const DEFAULT_SESSION_COOKIE_HOST: &str = "__Host-session";

/// Default header name for CSRF token
const DEFAULT_HEADER_NAME: &str = "x-csrf-token";

/// CSRF errors
#[derive(Error, Debug, Clone)]
pub enum CsrfError {
    #[error("CSRF token missing")]
    TokenMissing,

    #[error("CSRF token invalid")]
    TokenInvalid,

    #[error("CSRF token expired")]
    TokenExpired,

    #[error("CSRF token generation failed")]
    GenerationFailed,

    #[error("Origin mismatch: expected {expected}, got {actual}")]
    OriginMismatch { expected: String, actual: String },

    #[error("Origin missing")]
    OriginMissing,

    #[error("Origin host missing")]
    OriginHostMissing,
}

/// CSRF protection configuration
#[derive(Debug, Clone)]
pub struct CsrfConfig {
    /// Cookie name for the CSRF token
    pub cookie_name: String,
    /// Header name for the CSRF token
    pub header_name: String,
    /// Token time-to-live
    pub token_ttl: Duration,
    /// Whether to check Origin header
    pub check_origin: bool,
    /// Allowed origins (empty = allow same-origin only)
    pub allowed_origins: Vec<String>,
    /// Routes that require CSRF protection (prefix match)
    pub protected_prefixes: Vec<String>,
    /// Whether CSRF is enabled
    pub enabled: bool,
    /// Use secure cookies (HTTPS only)
    pub secure_cookie: bool,
    /// SameSite cookie attribute
    pub same_site: SameSite,
}

/// SameSite cookie attribute
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SameSite {
    Strict,
    Lax,
    None,
}

impl Default for CsrfConfig {
    fn default() -> Self {
        CsrfConfig {
            cookie_name: DEFAULT_COOKIE_NAME.to_string(),
            header_name: DEFAULT_HEADER_NAME.to_string(),
            token_ttl: DEFAULT_TOKEN_TTL,
            check_origin: true,
            allowed_origins: Vec::new(),
            protected_prefixes: vec!["/control/".to_string()],
            enabled: true,
            secure_cookie: true,
            same_site: SameSite::Strict,
        }
    }
}

impl CsrfConfig {
    /// Create a builder for custom configuration
    pub fn builder() -> CsrfConfigBuilder {
        CsrfConfigBuilder::default()
    }

    /// Check if a path requires CSRF protection
    pub fn requires_protection(&self, path: &str) -> bool {
        self.protected_prefixes.iter().any(|p| path.starts_with(p))
    }
}

/// Builder for CsrfConfig
#[derive(Default)]
pub struct CsrfConfigBuilder {
    config: CsrfConfig,
}

impl CsrfConfigBuilder {
    /// Set the cookie name
    pub fn cookie_name(mut self, name: impl Into<String>) -> Self {
        self.config.cookie_name = name.into();
        self
    }

    /// Set the header name
    pub fn header_name(mut self, name: impl Into<String>) -> Self {
        self.config.header_name = name.into();
        self
    }

    /// Set the token TTL
    pub fn token_ttl(mut self, ttl: Duration) -> Self {
        self.config.token_ttl = ttl;
        self
    }

    /// Set whether to check Origin header
    pub fn check_origin(mut self, check: bool) -> Self {
        self.config.check_origin = check;
        self
    }

    /// Add allowed origins
    pub fn allowed_origins(mut self, origins: Vec<String>) -> Self {
        self.config.allowed_origins = origins;
        self
    }

    /// Set protected route prefixes
    pub fn protected_prefixes(mut self, prefixes: Vec<String>) -> Self {
        self.config.protected_prefixes = prefixes;
        self
    }

    /// Enable or disable CSRF protection
    pub fn enabled(mut self, enabled: bool) -> Self {
        self.config.enabled = enabled;
        self
    }

    /// Set secure cookie flag
    pub fn secure_cookie(mut self, secure: bool) -> Self {
        self.config.secure_cookie = secure;
        self
    }

    /// Set SameSite attribute
    pub fn same_site(mut self, same_site: SameSite) -> Self {
        self.config.same_site = same_site;
        self
    }

    /// Build the configuration
    pub fn build(self) -> CsrfConfig {
        self.config
    }
}

/// CSRF token with metadata
#[derive(Debug, Clone)]
pub struct CsrfToken {
    /// The token value (base64url encoded)
    pub value: String,
    /// When the token was created
    pub created_at: Instant,
    /// Token TTL
    pub ttl: Duration,
}

impl CsrfToken {
    /// Check if the token is expired
    pub fn is_expired(&self) -> bool {
        self.created_at.elapsed() > self.ttl
    }
}

/// CSRF token store for managing tokens
#[derive(Clone)]
pub struct CsrfTokenStore {
    /// Map of session ID to token
    tokens: Arc<RwLock<HashMap<String, CsrfToken>>>,
    /// Configuration
    config: Arc<CsrfConfig>,
}

impl CsrfTokenStore {
    /// Create a new token store
    pub fn new(config: CsrfConfig) -> Self {
        CsrfTokenStore {
            tokens: Arc::new(RwLock::new(HashMap::new())),
            config: Arc::new(config),
        }
    }

    /// Generate a new CSRF token for a session
    pub fn generate_token(&self, session_id: &str) -> Result<CsrfToken, CsrfError> {
        let token_bytes = generate_random_bytes(TOKEN_BYTES)?;
        let token_value = URL_SAFE_NO_PAD.encode(&token_bytes);

        let token = CsrfToken {
            value: token_value,
            created_at: Instant::now(),
            ttl: self.config.token_ttl,
        };

        let mut tokens = self.tokens.write();
        tokens.insert(session_id.to_string(), token.clone());

        // Clean up expired tokens periodically
        if tokens.len() > 1000 {
            tokens.retain(|_, t| !t.is_expired());
        }

        Ok(token)
    }

    /// Validate a CSRF token
    pub fn validate_token(&self, session_id: &str, provided_token: &str) -> Result<(), CsrfError> {
        let tokens = self.tokens.read();

        let stored_token = tokens.get(session_id).ok_or(CsrfError::TokenMissing)?;

        if stored_token.is_expired() {
            return Err(CsrfError::TokenExpired);
        }

        // Timing-safe comparison
        if !crate::auth::timing_safe_eq(&stored_token.value, provided_token) {
            return Err(CsrfError::TokenInvalid);
        }

        Ok(())
    }

    /// Get the current token for a session (if valid)
    pub fn get_token(&self, session_id: &str) -> Option<CsrfToken> {
        let tokens = self.tokens.read();
        tokens.get(session_id).filter(|t| !t.is_expired()).cloned()
    }

    /// Remove a token (e.g., on logout)
    pub fn revoke_token(&self, session_id: &str) {
        let mut tokens = self.tokens.write();
        tokens.remove(session_id);
    }

    /// Get the configuration
    pub fn config(&self) -> &CsrfConfig {
        &self.config
    }
}

/// Generate cryptographically random bytes using getrandom
fn generate_random_bytes(len: usize) -> Result<Vec<u8>, CsrfError> {
    let mut bytes = vec![0u8; len];
    getrandom::fill(&mut bytes).map_err(|_| CsrfError::GenerationFailed)?;
    Ok(bytes)
}

/// Extract a cookie value by name from the request headers.
fn extract_cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    let cookie = headers.get(header::COOKIE)?;
    let cookie_str = cookie.to_str().ok()?;
    let prefix = format!("{}=", name);

    cookie_str
        .split(';')
        .map(|part| part.trim())
        .find_map(|part| part.strip_prefix(&prefix).map(|value| value.to_string()))
}

pub fn csrf_cookie_name(config: &CsrfConfig) -> &str {
    if config.secure_cookie {
        &config.cookie_name
    } else {
        config
            .cookie_name
            .strip_prefix("__Host-")
            .unwrap_or(&config.cookie_name)
    }
}

fn session_cookie_name(config: &CsrfConfig) -> &str {
    if config.secure_cookie {
        DEFAULT_SESSION_COOKIE_HOST
    } else {
        DEFAULT_SESSION_COOKIE
    }
}

/// Extract session ID from cookies
fn extract_session_id(headers: &HeaderMap, config: &CsrfConfig) -> Option<String> {
    extract_cookie_value(headers, session_cookie_name(config))
}

/// Extract CSRF token from request
fn extract_csrf_token(headers: &HeaderMap, config: &CsrfConfig) -> Option<String> {
    // Check header first
    if let Some(token) = headers.get(&config.header_name) {
        if let Ok(token_str) = token.to_str() {
            return Some(token_str.to_string());
        }
    }

    None
}

/// Result of checking the Origin/Referer header against the request's host.
/// Split into three states so the caller can distinguish:
/// - `Ok` — Origin present AND matches expected (browser, same-origin)
/// - `Absent` — Origin/Referer both absent (non-browser CLI/curl path)
/// - `Mismatch` — Origin present AND does NOT match (cross-origin browser
///   fetch; always reject)
///
/// Pre-fix `check_origin` returned `Err(OriginMissing)` for the Absent case,
/// which conflated CLI callers with cross-origin attackers. The session-cookie
/// branch in `extract_origin_session_and_token` then masked this by skipping
/// the origin check entirely whenever no cookie was present — letting a
/// cross-origin `fetch({credentials:"omit"})` from a malicious page issue
/// state-changing requests to `/control/matrix/verifications/*/confirm` under
/// AuthMode::None+loopback. Splitting the result lets the caller fail-fast on
/// Mismatch while still allowing CLI/curl through on Absent.
#[derive(Debug)]
enum OriginCheck {
    Ok,
    Absent,
    Mismatch(CsrfError),
}

/// Strip the optional `:port` from a host[:port] authority. Handles
/// both bracketed IPv6 (`[::1]:8080` → `[::1]`, `[::1]` → `[::1]`)
/// and IPv4 / hostname (`127.0.0.1:8080` → `127.0.0.1`,
/// `localhost` → `localhost`). A naive `rsplit_once(':')` would
/// mis-strip the LAST `:` inside an unbracketed IPv6 literal — but
/// IPv6 in URL authority is always bracketed per RFC 3986 §3.2.2, so
/// we only need to special-case the leading bracket.
fn strip_authority_port(s: &str) -> &str {
    if let Some(after_lbracket) = s.strip_prefix('[') {
        if let Some(rbracket_in_stripped) = after_lbracket.find(']') {
            // Include the leading `[` and trailing `]`, drop any
            // `:port` (or anything else) after the closing bracket.
            return &s[..rbracket_in_stripped + 2];
        }
        // Malformed (no closing bracket): return raw and let exact
        // compare fail closed.
        return s;
    }
    s.rsplit_once(':').map_or(s, |(host, _)| host)
}

/// Normalize an origin string to `scheme://host[:port]` for exact-match
/// comparison against `allowed_origins`. Strips path, query, AND
/// fragment components a misconfigured allow-list entry might carry,
/// and lowercases the scheme+host portion for case-insensitive compare
/// per RFC 6454 §4. Scheme prefix matching is also case-insensitive.
/// Returns the input unchanged (preserving case) when no scheme is
/// detected — exact comparison then surfaces a schemeless entry as
/// no-match rather than widening trust.
fn normalize_origin_for_allowlist(raw: &str) -> std::borrow::Cow<'_, str> {
    // Use byte-slice comparison rather than `&raw[..7]` str slicing —
    // an operator-configured `allowed_origins` entry like `"😀😁"`
    // (8 bytes, with byte-index 7 falling in the middle of the second
    // 4-byte UTF-8 emoji) would panic the request thread on the next
    // protected POST. `<[u8]>::eq_ignore_ascii_case` is purely
    // byte-indexed and panics only on out-of-bounds, already guarded
    // by the `len() >=` checks.
    let bytes = raw.as_bytes();
    let scheme_len = if bytes.len() >= 7 && bytes[..7].eq_ignore_ascii_case(b"http://") {
        Some(7)
    } else if bytes.len() >= 8 && bytes[..8].eq_ignore_ascii_case(b"https://") {
        Some(8)
    } else {
        None
    };
    match scheme_len {
        // `raw` had a scheme; cut at the first `/`, `?`, or `#` so
        // `https://example.com/foo`, `https://example.com?x=1`, and
        // `https://example.com#frag` all normalize equivalently.
        Some(prefix_len) => {
            let after_scheme = &raw[prefix_len..];
            let authority_len = after_scheme
                .find(['/', '?', '#'])
                .unwrap_or(after_scheme.len());
            let head = &raw[..prefix_len + authority_len];
            if head.bytes().any(|b| b.is_ascii_uppercase()) {
                std::borrow::Cow::Owned(head.to_ascii_lowercase())
            } else {
                std::borrow::Cow::Borrowed(head)
            }
        }
        None => std::borrow::Cow::Borrowed(raw),
    }
}

fn check_origin_state(headers: &HeaderMap, config: &CsrfConfig, host: Option<&str>) -> OriginCheck {
    if !config.check_origin {
        return OriginCheck::Ok;
    }

    let origin = headers
        .get(header::ORIGIN)
        .and_then(|v| v.to_str().ok())
        .or_else(|| headers.get(header::REFERER).and_then(|v| v.to_str().ok()));

    let Some(origin) = origin else {
        debug!("No Origin/Referer header on CSRF-protected request");
        return OriginCheck::Absent;
    };

    // Check against allowed origins. Normalize both sides to
    // `scheme://host` (path stripped) and require EXACT match. The
    // naive `origin.starts_with(o)` shape would accept
    // `https://example.com.attacker.com` as matching the configured
    // `https://example.com`, because `starts_with` has no terminator.
    // Today no production code path populates `allowed_origins`
    // (default empty Vec), but it is part of the public CsrfConfig
    // API and the builder is exposed, so the footgun has to be
    // closed at the comparison site rather than relying on "nobody
    // calls this yet".
    if !config.allowed_origins.is_empty() {
        let origin_normalized = normalize_origin_for_allowlist(origin);
        if config
            .allowed_origins
            .iter()
            .any(|o| normalize_origin_for_allowlist(o) == origin_normalized)
        {
            return OriginCheck::Ok;
        }
    }

    // Check same-origin. Normalize BOTH sides to host-only (strip the
    // optional `:port`) via the same IPv6-bracket-aware helper so the
    // realistic deployment shape — browser at
    // `Origin: http://127.0.0.1:18789` and `Host: 127.0.0.1:18789` —
    // compares as `"127.0.0.1" == "127.0.0.1"`. IPv6 (`[::1]:8080` /
    // `[::1]`) must also normalize symmetrically; pre-fix the Host
    // side used `split(':').next()` which yields `"["` for IPv6
    // (the first colon is inside the bracket), making the pre-Batch-1
    // origin compare match only by coincidence of both sides being
    // broken identically. Browser same-origin policy already pins
    // port-level isolation (a cross-port attacker cannot read the
    // cross-port response), so dropping the port from this server-side
    // backup check is safe under the threat model the Origin check
    // exists to address (cross-host CSRF from a malicious page).
    if let Some(host) = host {
        // Scheme strip is case-insensitive per RFC 6454 §4 (matching
        // the allowlist path's normalization). Use case-insensitive
        // byte-prefix compare; this also handles
        // `Origin: HTTP://...` from non-standard clients without
        // fail-closing a legitimate same-origin request.
        let origin_bytes = origin.as_bytes();
        let after_scheme = if origin_bytes.len() >= 7
            && origin_bytes[..7].eq_ignore_ascii_case(b"http://")
        {
            &origin[7..]
        } else if origin_bytes.len() >= 8 && origin_bytes[..8].eq_ignore_ascii_case(b"https://") {
            &origin[8..]
        } else {
            origin
        };
        let origin_authority = after_scheme.split('/').next().unwrap_or("");
        let origin_host = strip_authority_port(origin_authority);

        // Host comparison is ASCII case-insensitive per RFC 3986 §3.2.2
        // and RFC 6454 §4. The allowlist path already lowercases via
        // `normalize_origin_for_allowlist`; this same-origin path was
        // previously byte-exact, so a Tailscale `*.ts.net` URL with
        // operator-typed mixed case in Host could fail-close.
        if origin_host.eq_ignore_ascii_case(host) {
            return OriginCheck::Ok;
        }
        // Subdomain trust: `evil.example.com` for `Host: example.com`.
        // Also case-insensitive so the same RFC reasoning applies.
        //
        // Defense-in-depth: compare via byte-slices (not str-slices) so
        // a non-ASCII byte in `origin_host` cannot land mid-UTF-8-
        // codepoint and panic the request thread. Today
        // `HeaderValue::to_str()` upstream filters non-ASCII bytes
        // before either side gets here, so the panic shape isn't
        // reachable via the HTTP path — but a future refactor that
        // relaxes that gate (e.g. swapping to `from_utf8(v.as_bytes())`
        // to accept IDN-shaped Origins) would re-open it. The byte-
        // slice pattern matches what `normalize_origin_for_allowlist`
        // already uses for the same hazard class.
        let dot_host = format!(".{}", host);
        let oh = origin_host.as_bytes();
        let dh = dot_host.as_bytes();
        if oh.len() > dh.len() && oh[oh.len() - dh.len()..].eq_ignore_ascii_case(dh) {
            return OriginCheck::Ok;
        }

        return OriginCheck::Mismatch(CsrfError::OriginMismatch {
            expected: host.to_string(),
            actual: origin_host.to_string(),
        });
    }

    // No host to compare against; fail closed unless explicitly allowed.
    OriginCheck::Mismatch(CsrfError::OriginHostMissing)
}

/// Determine if CSRF validation is needed for this request.
///
/// Returns `true` when the HTTP method is state-changing (POST, PUT, DELETE,
/// PATCH) **and** the path matches a protected prefix.
fn should_validate_csrf(method: &Method, path: &str, config: &CsrfConfig) -> bool {
    matches!(
        *method,
        Method::POST | Method::PUT | Method::DELETE | Method::PATCH
    ) && config.requires_protection(path)
}

/// Verify the Origin header and extract the session ID and token from the
/// request.  Returns `(session_id, token)` on success, or an HTTP error
/// response when any pre-condition fails.
#[allow(clippy::result_large_err)]
fn extract_origin_session_and_token(
    headers: &HeaderMap,
    config: &CsrfConfig,
) -> Result<Option<(String, String)>, Response<Body>> {
    // Get Host header for origin check. Use the IPv6-bracket-aware
    // `strip_authority_port` helper so a bracketed IPv6 Host like
    // `[::1]:8080` or `[::1]` normalizes to `[::1]` symmetrically
    // with the Origin parse below. The pre-fix `split(':').next()`
    // yielded `"["` for both shapes (the first colon falls inside
    // the bracket), which silently matched against the Origin parse
    // when Origin was also broken in the same way — Batch 1 fixed
    // the Origin side to use `rsplit_once(':')` but left this site
    // asymmetric, fail-closing legitimate IPv6 same-origin requests.
    let host = headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(strip_authority_port);

    // Run the Origin/Referer check FIRST, BEFORE consulting the
    // session cookie. The pre-fix shape ran the session check first
    // and short-circuited to "skip CSRF" on session-less requests.
    // That let a cross-origin browser `fetch({credentials:"omit"})`
    // from a malicious page bypass CSRF entirely — no cookie → no
    // checks — and reach state-changing endpoints like
    // `/control/matrix/verifications/*/confirm` under AuthMode::None+
    // loopback. A standards-compliant browser sends Origin on every
    // POST/PUT/DELETE/PATCH per the Fetch spec; an Origin/Referer
    // that IS present and does NOT match the host is therefore
    // always a CSRF failure regardless of whether a session cookie
    // is present.
    //
    // Three resulting states:
    //   - Ok:       Origin matches → continue to session check.
    //   - Mismatch: cross-origin → ALWAYS reject.
    //   - Absent:   no Origin/Referer → defer judgement; this could
    //               be a CLI/curl caller (no Origin by design) OR a
    //               non-standard browser session-riding attempt.
    //               Resolve below: session-absent → pass (handler
    //               auth gates); session-present → strict reject
    //               (preserves the pre-fix "session present requires
    //               Origin" contract pinned by
    //               test_missing_origin_rejected_when_session_present).
    let origin_state = check_origin_state(headers, config, host);
    if let OriginCheck::Mismatch(err) = &origin_state {
        warn!("CSRF origin check failed: {}", err);
        return Err(csrf_error_response(err.clone()));
    }

    // Extract session ID
    let session_id = match extract_session_id(headers, config) {
        Some(id) => id,
        None => {
            // Session-less. Origin was Ok or Absent (Mismatch was
            // rejected above). Both are acceptable here:
            //   - Origin Ok    → standards-compliant non-browser
            //                    request from a trusted origin
            //                    (rare but legal).
            //   - Origin Absent → CLI/curl, non-browser path. Gated
            //                    downstream by check_control_auth.
            return Ok(None);
        }
    };

    // Session cookie IS present. Origin-Absent in this branch is a
    // browser-shaped request that didn't send Origin — non-standard;
    // fail-closed. Origin-Ok continues to token validation.
    if matches!(origin_state, OriginCheck::Absent) {
        warn!("CSRF origin check failed: Origin/Referer missing on session-bearing request");
        return Err(csrf_error_response(CsrfError::OriginMissing));
    }

    // Extract token
    let provided_token = match extract_csrf_token(headers, config) {
        Some(token) => token,
        None => {
            warn!("CSRF: No token provided");
            return Err(csrf_error_response(CsrfError::TokenMissing));
        }
    };

    Ok(Some((session_id, provided_token)))
}

/// Perform origin checking, token extraction, and token validation.
///
/// Returns `Ok(())` when the request passes all CSRF checks, or an error
/// response that should be returned to the client.
#[allow(clippy::result_large_err)]
fn extract_and_validate_token(
    headers: &HeaderMap,
    config: &CsrfConfig,
    store: &CsrfTokenStore,
) -> Result<(), Response<Body>> {
    let Some((session_id, provided_token)) = extract_origin_session_and_token(headers, config)?
    else {
        return Ok(());
    };

    if let Err(e) = store.validate_token(&session_id, &provided_token) {
        warn!("CSRF validation failed: {}", e);
        return Err(csrf_error_response(e));
    }

    Ok(())
}

/// CSRF protection middleware
///
/// Validates CSRF tokens for state-changing requests to protected routes.
pub async fn csrf_middleware(
    store: axum::extract::State<CsrfTokenStore>,
    request: Request<Body>,
    next: Next,
) -> Response<Body> {
    let config = store.config();

    // Skip if CSRF is disabled
    if !config.enabled {
        return next.run(request).await;
    }

    let method = request.method().clone();
    let path = request.uri().path().to_string();
    let headers = request.headers().clone();

    if !should_validate_csrf(&method, &path, config) {
        return next.run(request).await;
    }

    if let Err(response) = extract_and_validate_token(&headers, config, &store) {
        return response;
    }

    debug!("CSRF validation passed for {}", path);
    next.run(request).await
}

/// Generate CSRF error response
fn csrf_error_response(error: CsrfError) -> Response<Body> {
    let message = match error {
        CsrfError::TokenMissing => "CSRF token missing",
        CsrfError::TokenInvalid => "CSRF token invalid",
        CsrfError::TokenExpired => "CSRF token expired",
        CsrfError::OriginMismatch { .. } => "Origin mismatch",
        CsrfError::OriginMissing => "Origin missing",
        CsrfError::OriginHostMissing => "Origin host missing",
        CsrfError::GenerationFailed => "Internal error",
    };

    (
        StatusCode::FORBIDDEN,
        [(header::CONTENT_TYPE, "application/json; charset=utf-8")],
        format!(
            r#"{{"error":{{"code":"csrf_error","message":"{}"}}}}"#,
            message
        ),
    )
        .into_response()
}

/// Generate a Set-Cookie header value for CSRF token
pub fn csrf_cookie_header(token: &CsrfToken, config: &CsrfConfig) -> String {
    let same_site = match config.same_site {
        SameSite::Strict => "Strict",
        SameSite::Lax => "Lax",
        SameSite::None => "None",
    };

    let secure = if config.secure_cookie { "; Secure" } else { "" };
    let max_age = config.token_ttl.as_secs();
    let cookie_name = csrf_cookie_name(config);

    format!(
        "{}={}; Path=/; SameSite={}{}; Max-Age={}",
        cookie_name, token.value, same_site, secure, max_age
    )
}

fn generate_session_id() -> Result<String, CsrfError> {
    let session_bytes = generate_random_bytes(TOKEN_BYTES)?;
    Ok(URL_SAFE_NO_PAD.encode(&session_bytes))
}

fn session_cookie_header(session_id: &str, config: &CsrfConfig) -> String {
    let same_site = match config.same_site {
        SameSite::Strict => "Strict",
        SameSite::Lax => "Lax",
        SameSite::None => "None",
    };

    let secure = if config.secure_cookie { "; Secure" } else { "" };
    let max_age = config.token_ttl.as_secs();

    let cookie_name = session_cookie_name(config);
    format!(
        "{}={}; Path=/; HttpOnly; SameSite={}{}; Max-Age={}",
        cookie_name, session_id, same_site, secure, max_age
    )
}

pub fn ensure_csrf_cookies(
    headers: &HeaderMap,
    store: &CsrfTokenStore,
) -> Result<Vec<String>, CsrfError> {
    let config = store.config();
    if !config.enabled {
        return Ok(Vec::new());
    }

    let existing_session = extract_session_id(headers, config);
    let session_missing = existing_session.is_none();
    let session_id = match existing_session {
        Some(id) => id,
        None => generate_session_id()?,
    };

    let mut set_cookies = Vec::new();
    if session_missing {
        set_cookies.push(session_cookie_header(&session_id, config));
    }

    let token = store
        .get_token(&session_id)
        .unwrap_or(store.generate_token(&session_id)?);
    let existing_token = extract_cookie_value(headers, csrf_cookie_name(config));
    if existing_token.as_deref() != Some(token.value.as_str()) {
        set_cookies.push(csrf_cookie_header(&token, config));
    }

    Ok(set_cookies)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_csrf_token_expiry() {
        // Use a zero TTL so the token is immediately expired.
        // Avoids subtracting a large duration from Instant::now(), which panics
        // on Windows when the result would precede the process start time.
        let token = CsrfToken {
            value: "test".to_string(),
            created_at: Instant::now(),
            ttl: Duration::from_secs(0), // already expired
        };

        // Give a tiny delay so elapsed() > 0
        std::thread::sleep(Duration::from_millis(1));
        assert!(token.is_expired());
    }

    #[test]
    fn test_csrf_token_not_expired() {
        let token = CsrfToken {
            value: "test".to_string(),
            created_at: Instant::now(),
            ttl: Duration::from_secs(3600),
        };

        assert!(!token.is_expired());
    }

    #[test]
    fn test_token_store_generate_and_validate() {
        let store = CsrfTokenStore::new(CsrfConfig::default());

        let token = store.generate_token("session-1").unwrap();
        assert!(!token.value.is_empty());

        // Valid token should pass
        assert!(store.validate_token("session-1", &token.value).is_ok());

        // Wrong token should fail
        assert!(store.validate_token("session-1", "wrong-token").is_err());

        // Wrong session should fail
        assert!(store.validate_token("session-2", &token.value).is_err());
    }

    #[test]
    fn test_token_store_revoke() {
        let store = CsrfTokenStore::new(CsrfConfig::default());

        let _token = store.generate_token("session-1").unwrap();
        assert!(store.get_token("session-1").is_some());

        store.revoke_token("session-1");
        assert!(store.get_token("session-1").is_none());
    }

    #[test]
    fn test_config_requires_protection() {
        let config = CsrfConfig::default();

        assert!(config.requires_protection("/control/status"));
        assert!(!config.requires_protection("/hooks/wake"));
        assert!(!config.requires_protection("/tools/invoke"));
        assert!(!config.requires_protection("/api/status"));
        assert!(!config.requires_protection("/"));
    }

    #[test]
    fn test_config_builder() {
        let config = CsrfConfig::builder()
            .cookie_name("my-csrf")
            .header_name("x-my-csrf")
            .token_ttl(Duration::from_secs(1800))
            .check_origin(false)
            .enabled(true)
            .secure_cookie(false)
            .same_site(SameSite::Lax)
            .build();

        assert_eq!(config.cookie_name, "my-csrf");
        assert_eq!(config.header_name, "x-my-csrf");
        assert_eq!(config.token_ttl, Duration::from_secs(1800));
        assert!(!config.check_origin);
        assert!(config.enabled);
        assert!(!config.secure_cookie);
        assert_eq!(config.same_site, SameSite::Lax);
    }

    #[test]
    fn test_timing_safe_equal() {
        use crate::auth::timing_safe_eq;
        assert!(timing_safe_eq("secret", "secret"));
        assert!(!timing_safe_eq("secret", "secret1"));
        assert!(!timing_safe_eq("secret1", "secret"));
        assert!(!timing_safe_eq("", "secret"));
    }

    #[test]
    fn test_csrf_cookie_header() {
        let token = CsrfToken {
            value: "test-token-value".to_string(),
            created_at: Instant::now(),
            ttl: Duration::from_secs(3600),
        };

        let config = CsrfConfig {
            cookie_name: "__Host-csrf".to_string(),
            secure_cookie: true,
            same_site: SameSite::Strict,
            token_ttl: Duration::from_secs(3600),
            ..Default::default()
        };

        let header = csrf_cookie_header(&token, &config);
        assert!(header.contains("__Host-csrf=test-token-value"));
        assert!(header.contains("SameSite=Strict"));
        assert!(header.contains("Secure"));
        assert!(header.contains("Max-Age=3600"));
        assert!(!header.contains("HttpOnly"));
    }

    #[test]
    fn test_csrf_cookie_header_no_secure() {
        let token = CsrfToken {
            value: "test-token".to_string(),
            created_at: Instant::now(),
            ttl: Duration::from_secs(3600),
        };

        let config = CsrfConfig {
            secure_cookie: false,
            same_site: SameSite::Lax,
            ..Default::default()
        };

        let header = csrf_cookie_header(&token, &config);
        assert!(!header.contains("Secure"));
        assert!(header.contains("SameSite=Lax"));
    }

    #[test]
    fn test_default_config() {
        let config = CsrfConfig::default();
        assert_eq!(config.cookie_name, "__Host-csrf");
        assert_eq!(config.header_name, "x-csrf-token");
        assert_eq!(config.token_ttl, Duration::from_secs(3600));
        assert!(config.check_origin);
        assert!(config.enabled);
        assert!(config.secure_cookie);
        assert_eq!(config.same_site, SameSite::Strict);
    }

    #[test]
    fn test_random_bytes_generation() {
        let bytes1 = generate_random_bytes(32).unwrap();
        let bytes2 = generate_random_bytes(32).unwrap();

        assert_eq!(bytes1.len(), 32);
        assert_eq!(bytes2.len(), 32);
        // Tokens should be different (extremely high probability)
        assert_ne!(bytes1, bytes2);
    }

    #[test]
    fn test_extract_csrf_token_from_header() {
        let config = CsrfConfig::default();
        let mut headers = HeaderMap::new();
        headers.insert("x-csrf-token", "my-token".parse().unwrap());

        let token = extract_csrf_token(&headers, &config);
        assert_eq!(token, Some("my-token".to_string()));
    }

    #[test]
    fn test_extract_csrf_token_from_cookie() {
        let config = CsrfConfig::default();
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            "__Host-csrf=cookie-token; other=value".parse().unwrap(),
        );

        let token = extract_csrf_token(&headers, &config);
        assert_eq!(token, None);
    }

    #[test]
    fn test_extract_csrf_token_header_precedence() {
        let config = CsrfConfig::default();
        let mut headers = HeaderMap::new();
        headers.insert("x-csrf-token", "header-token".parse().unwrap());
        headers.insert(header::COOKIE, "__Host-csrf=cookie-token".parse().unwrap());

        // Header should be used; cookie is ignored.
        let token = extract_csrf_token(&headers, &config);
        assert_eq!(token, Some("header-token".to_string()));
    }

    /// Pins the CLI/curl path: a non-browser caller with NO session
    /// cookie AND NO Origin/Referer header (the shape of every
    /// `curl http://127.0.0.1:PORT/control/...` invocation in this
    /// project's smoke harness) MUST pass through CSRF validation so
    /// it can be authenticated downstream by `check_control_auth`'s
    /// bearer/password/loopback discipline. Before the
    /// Origin-before-session fix, this test pinned the (broader)
    /// "no session cookie → skip everything" bypass that ALSO let
    /// cross-origin browser fetches with credentials:'omit' through.
    /// The narrower contract pinned here is the post-fix one: only
    /// the Origin-absent case is exempt; cross-origin browser
    /// requests (Origin present, mismatched) are caught regardless
    /// of session-cookie state (see
    /// test_missing_session_with_mismatched_origin_is_rejected below).
    #[test]
    fn test_missing_session_no_origin_passes_csrf_validation() {
        let store = CsrfTokenStore::new(CsrfConfig::default());
        let headers = HeaderMap::new();

        assert!(extract_and_validate_token(&headers, store.config(), &store).is_ok());
    }

    /// Pins the post-fix CSRF Origin enforcement: a session-LESS
    /// state-changing request with a MISMATCHED Origin (the shape
    /// of a cross-origin browser fetch with `credentials:"omit"`)
    /// MUST be rejected, even though the pre-fix shape short-
    /// circuited to "skip CSRF" on session-less requests. The
    /// reachable attack this defends against: a malicious page on
    /// `http://evil.example` issuing
    /// `fetch("http://127.0.0.1:PORT/control/matrix/verifications/<flow>/confirm",
    /// {method:"POST", body:'{"matches":true}', credentials:"omit"})`
    /// under AuthMode::None+loopback. Browser sets Origin
    /// automatically per Fetch spec; pre-fix middleware skipped the
    /// origin check because no session cookie was present.
    /// Pin closure of the `allowed_origins` prefix-match footgun:
    /// `https://example.com.attacker.com` MUST NOT be accepted when
    /// the allow-list contains `https://example.com`. Pre-fix
    /// `origin.starts_with(o)` would allow it because `starts_with`
    /// has no terminator; the post-fix exact-match shape rejects.
    #[test]
    fn test_allowed_origins_prefix_match_does_not_widen_trust() {
        let store = CsrfTokenStore::new(
            CsrfConfigBuilder::default()
                .allowed_origins(vec!["https://example.com".to_string()])
                .build(),
        );
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, "internal.gateway".parse().unwrap());
        headers.insert(
            header::ORIGIN,
            "https://example.com.attacker.com".parse().unwrap(),
        );

        let response = extract_and_validate_token(&headers, store.config(), &store)
            .expect_err("evil prefix-match origin must be rejected");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    /// Companion positive pin: an exact match against `allowed_origins`
    /// (with trailing path stripped) must still pass. Without this we
    /// would not know the post-fix shape can still accept legitimate
    /// cross-origin browsers in operator-configured deployments.
    #[test]
    fn test_allowed_origins_exact_match_passes_origin_check() {
        let store = CsrfTokenStore::new(
            CsrfConfigBuilder::default()
                .allowed_origins(vec!["https://example.com".to_string()])
                .build(),
        );
        let token = store.generate_token("session-allow").unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, "internal.gateway".parse().unwrap());
        headers.insert(header::ORIGIN, "https://example.com/path".parse().unwrap());
        headers.insert("x-csrf-token", token.value.parse().unwrap());
        headers.insert(
            header::COOKIE,
            format!("__Host-session=session-allow; __Host-csrf={}", token.value)
                .parse()
                .unwrap(),
        );

        let result = extract_and_validate_token(&headers, store.config(), &store);
        assert!(
            result.is_ok(),
            "exact-match allowed origin should pass: {:?}",
            result.err().map(|r| r.status())
        );
    }

    /// Pin the subdomain-trust correctness against the classic prefix-
    /// match attack: `Host: example.com` MUST NOT match
    /// `Origin: http://example.com.attacker.com`. The subdomain branch
    /// uses byte-slice `ends_with(".example.com")` shape — the attacker
    /// origin ends with `.attacker.com`, not `.example.com`, so it
    /// must fail-close. Without this pin a future refactor that
    /// accidentally switched to a non-anchored substring match or
    /// dropped the leading dot would silently widen trust.
    #[test]
    fn test_subdomain_trust_rejects_prefix_match_attack() {
        let store = CsrfTokenStore::new(CsrfConfig::default());
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, "example.com".parse().unwrap());
        headers.insert(
            header::ORIGIN,
            "http://example.com.attacker.com".parse().unwrap(),
        );

        let response = extract_and_validate_token(&headers, store.config(), &store)
            .expect_err("prefix-match origin must be rejected");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    /// Pin RFC 6454 §4 / RFC 3986 §3.2.2 case-insensitivity on the
    /// same-origin compare path. The allowlist path was already
    /// case-insensitive; pre-fix the same-origin path was byte-exact,
    /// causing an asymmetric failure for legitimate mixed-case
    /// Host/Origin headers (e.g., a Tailscale `*.ts.net` URL with
    /// operator-typed mixed case in Host).
    #[test]
    fn test_same_origin_compare_is_ascii_case_insensitive() {
        let store = CsrfTokenStore::new(CsrfConfig::default());
        let token = store.generate_token("session-case").unwrap();
        let mut headers = HeaderMap::new();
        // Mixed-case scheme + uppercase Host. Browsers always emit
        // lowercase, but non-standard clients and operator-typed
        // URLs can produce mixed case.
        headers.insert(header::HOST, "EXAMPLE.COM".parse().unwrap());
        headers.insert(header::ORIGIN, "HTTPS://Example.COM".parse().unwrap());
        headers.insert("x-csrf-token", token.value.parse().unwrap());
        headers.insert(
            header::COOKIE,
            format!("__Host-session=session-case; __Host-csrf={}", token.value)
                .parse()
                .unwrap(),
        );

        let result = extract_and_validate_token(&headers, store.config(), &store);
        assert!(
            result.is_ok(),
            "mixed-case scheme + host same-origin should pass: {:?}",
            result.err().map(|r| r.status())
        );
    }

    /// Sibling-case pin: case-insensitivity must also apply to the
    /// subdomain-trust branch. `Evil.Example.COM` against
    /// `Host: example.com` should still get matched as a subdomain.
    /// (This is intentional subdomain trust — pinning that the case
    /// difference doesn't accidentally fail-close legitimate browser
    /// canonicalization.)
    #[test]
    fn test_same_origin_subdomain_trust_is_ascii_case_insensitive() {
        let store = CsrfTokenStore::new(CsrfConfig::default());
        let token = store.generate_token("session-sub").unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, "example.com".parse().unwrap());
        headers.insert(header::ORIGIN, "http://API.Example.COM".parse().unwrap());
        headers.insert("x-csrf-token", token.value.parse().unwrap());
        headers.insert(
            header::COOKIE,
            format!("__Host-session=session-sub; __Host-csrf={}", token.value)
                .parse()
                .unwrap(),
        );

        let result = extract_and_validate_token(&headers, store.config(), &store);
        assert!(
            result.is_ok(),
            "case-insensitive subdomain trust should pass: {:?}",
            result.err().map(|r| r.status())
        );
    }

    /// IPv6 bracket-aware authority parsing. Pre-fix the Host side
    /// used `split(':').next()` which yields `"["` for a bracketed
    /// IPv6 literal (the first colon falls inside the bracket).
    /// Origin parsing matched that brokenness pre-Batch-1, so same-
    /// origin checks coincidentally passed for IPv6. Batch 1 fixed
    /// the Origin side to use `rsplit_once(':')` without touching
    /// the Host side, fail-closing legitimate IPv6 same-origin
    /// browser requests. The post-fix shape uses one shared helper
    /// (`strip_authority_port`) for both sides; this pin proves a
    /// bracketed-IPv6 same-origin request now passes end-to-end.
    #[test]
    fn test_strip_authority_port_handles_ipv6_and_ipv4() {
        // IPv6 with port.
        assert_eq!(super::strip_authority_port("[::1]:8080"), "[::1]");
        // IPv6 without port.
        assert_eq!(super::strip_authority_port("[::1]"), "[::1]");
        // IPv4 with port.
        assert_eq!(super::strip_authority_port("127.0.0.1:8080"), "127.0.0.1");
        // IPv4 without port.
        assert_eq!(super::strip_authority_port("127.0.0.1"), "127.0.0.1");
        // Hostname with port.
        assert_eq!(super::strip_authority_port("localhost:18789"), "localhost");
        // Hostname without port.
        assert_eq!(super::strip_authority_port("localhost"), "localhost");
        // Malformed IPv6 (no closing bracket) — return raw so exact
        // compare fail-closes rather than panicking.
        assert_eq!(super::strip_authority_port("[::1"), "[::1");
    }

    #[test]
    fn test_same_origin_ipv6_loopback_with_port_passes() {
        let store = CsrfTokenStore::new(CsrfConfig::default());
        let token = store.generate_token("session-ipv6").unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, "[::1]:18789".parse().unwrap());
        headers.insert(header::ORIGIN, "http://[::1]:18789".parse().unwrap());
        headers.insert("x-csrf-token", token.value.parse().unwrap());
        headers.insert(
            header::COOKIE,
            format!("__Host-session=session-ipv6; __Host-csrf={}", token.value)
                .parse()
                .unwrap(),
        );

        let result = extract_and_validate_token(&headers, store.config(), &store);
        assert!(
            result.is_ok(),
            "IPv6 same-origin with port should pass: {:?}",
            result.err().map(|r| r.status())
        );
    }

    /// Pin the documented `normalize_origin_for_allowlist` contract:
    /// scheme+host comparison is ASCII case-insensitive (RFC 6454 §4)
    /// AND query/fragment components are stripped along with path.
    #[test]
    fn test_normalize_origin_for_allowlist_is_case_and_path_query_normalized() {
        // Path strip.
        assert_eq!(
            super::normalize_origin_for_allowlist("https://example.com/foo"),
            "https://example.com"
        );
        // Query strip.
        assert_eq!(
            super::normalize_origin_for_allowlist("https://example.com?x=1"),
            "https://example.com"
        );
        // Fragment strip.
        assert_eq!(
            super::normalize_origin_for_allowlist("https://example.com#frag"),
            "https://example.com"
        );
        // Case lowering for scheme+host.
        assert_eq!(
            super::normalize_origin_for_allowlist("HTTPS://EXAMPLE.COM"),
            "https://example.com"
        );
        // Schemeless input preserved unchanged (so exact compare
        // fail-closes against scheme-prefixed allow-list entries).
        assert_eq!(
            super::normalize_origin_for_allowlist("example.com"),
            "example.com"
        );
    }

    /// Pins same-origin acceptance when both `Host` and `Origin`
    /// carry a port: the realistic browser deployment shape (e.g.
    /// `127.0.0.1:18789`). Without symmetric port stripping this
    /// would fail-close a legitimate request because Host parsing
    /// strips port but origin_host parsing previously preserved it.
    #[test]
    fn test_same_origin_with_matching_port_passes() {
        let store = CsrfTokenStore::new(CsrfConfig::default());
        let token = store.generate_token("session-port").unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, "127.0.0.1:18789".parse().unwrap());
        headers.insert(header::ORIGIN, "http://127.0.0.1:18789".parse().unwrap());
        headers.insert("x-csrf-token", token.value.parse().unwrap());
        headers.insert(
            header::COOKIE,
            format!("__Host-session=session-port; __Host-csrf={}", token.value)
                .parse()
                .unwrap(),
        );

        let result = extract_and_validate_token(&headers, store.config(), &store);
        assert!(
            result.is_ok(),
            "same-origin request with port should pass: {:?}",
            result.err().map(|r| r.status())
        );
    }

    #[test]
    fn test_missing_session_with_mismatched_origin_is_rejected() {
        let store = CsrfTokenStore::new(CsrfConfig::default());
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, "127.0.0.1".parse().unwrap());
        headers.insert(header::ORIGIN, "http://evil.example".parse().unwrap());

        let response = extract_and_validate_token(&headers, store.config(), &store)
            .expect_err("cross-origin session-less request must be rejected");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn test_missing_origin_rejected_when_session_present() {
        let store = CsrfTokenStore::new(CsrfConfig::default());
        let token = store.generate_token("session-1").unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, "localhost".parse().unwrap());
        headers.insert("x-csrf-token", token.value.parse().unwrap());
        headers.insert(
            header::COOKIE,
            format!("__Host-session=session-1; __Host-csrf={}", token.value)
                .parse()
                .unwrap(),
        );

        let response = extract_and_validate_token(&headers, store.config(), &store)
            .expect_err("origin should be required when session cookie exists");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn test_missing_host_rejected_when_session_present() {
        let store = CsrfTokenStore::new(CsrfConfig::default());
        let token = store.generate_token("session-1").unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(header::ORIGIN, "https://example.com".parse().unwrap());
        headers.insert("x-csrf-token", token.value.parse().unwrap());
        headers.insert(
            header::COOKIE,
            format!("__Host-session=session-1; __Host-csrf={}", token.value)
                .parse()
                .unwrap(),
        );

        let response = extract_and_validate_token(&headers, store.config(), &store)
            .expect_err("host should be required when session cookie exists");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn test_ensure_csrf_cookies_sets_session_and_token() {
        let store = CsrfTokenStore::new(CsrfConfig::default());
        let headers = HeaderMap::new();

        let cookies = ensure_csrf_cookies(&headers, &store).unwrap();
        assert_eq!(cookies.len(), 2);
        assert!(cookies.iter().any(|c| c.starts_with("__Host-session=")));
        assert!(cookies.iter().any(|c| c.starts_with("__Host-csrf=")));
    }

    #[test]
    fn test_ensure_csrf_cookies_noop_when_present() {
        let store = CsrfTokenStore::new(CsrfConfig::default());
        let token = store.generate_token("session-1").unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            format!("__Host-session=session-1; __Host-csrf={}", token.value)
                .parse()
                .unwrap(),
        );

        let cookies = ensure_csrf_cookies(&headers, &store).unwrap();
        assert!(cookies.is_empty());
    }

    #[test]
    fn test_cookie_names_when_insecure() {
        let config = CsrfConfig {
            secure_cookie: false,
            ..Default::default()
        };

        assert_eq!(csrf_cookie_name(&config), "csrf");
        assert_eq!(session_cookie_name(&config), "session");
    }
}
