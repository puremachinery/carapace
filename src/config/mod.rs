//! Configuration parsing module
//!
//! Handles JSON5 configuration with includes, environment variable substitution,
//! and caching.

pub mod defaults;
pub mod routes;
pub mod schema;
pub mod secrets;
pub mod watcher;

use parking_lot::{Mutex, MutexGuard, RwLock};
use regex::Regex;
use serde_json::Value;
use std::cell::{Cell, RefCell};
use std::collections::{HashMap, HashSet};
use std::env;
use std::ffi::OsString;
use std::fs;
use std::mem::ManuallyDrop;
use std::ops::{Deref, DerefMut};
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};
use thiserror::Error;
use zeroize::Zeroizing;

/// Maximum depth for $include directives to prevent infinite recursion
const MAX_INCLUDE_DEPTH: usize = 10;

/// Default config cache TTL in milliseconds
const DEFAULT_CACHE_TTL_MS: u64 = 200;

/// Env var for config secret encryption/decryption.
const CONFIG_PASSWORD_ENV: &str = "CARAPACE_CONFIG_PASSWORD";
const LOADER_CONTROL_ENV_VARS: &[&str] = &[
    "CARAPACE_CONFIG_PATH",
    "CARAPACE_STATE_DIR",
    "CARAPACE_DISABLE_CONFIG_CACHE",
    "CARAPACE_CONFIG_CACHE_MS",
    CONFIG_PASSWORD_ENV,
];

/// JSON pointer paths that should be encrypted at rest.
const CONFIG_SECRET_PATHS: &[&str] = &[
    "/gateway/auth/token",
    "/gateway/auth/password",
    "/gateway/hooks/token",
    "/anthropic/apiKey",
    "/openai/apiKey",
    "/google/apiKey",
    "/venice/apiKey",
    "/ollama/apiKey",
    "/providers/ollama/apiKey",
    "/bedrock/accessKeyId",
    "/bedrock/secretAccessKey",
    "/bedrock/sessionToken",
    "/models/providers/openai/apiKey",
    "/auth/profiles/providers/google/clientSecret",
    "/auth/profiles/providers/github/clientSecret",
    "/auth/profiles/providers/discord/clientSecret",
    "/auth/profiles/providers/openai/clientSecret",
    "/telegram/botToken",
    "/telegram/webhookSecret",
    "/discord/botToken",
    "/slack/botToken",
    "/slack/signingSecret",
];

// Regex pattern for env vars: ${VAR} where VAR is uppercase with underscores and digits.
// `$${VAR}` is treated as an escaped literal and should not be surfaced as a live reference.
static ENV_VAR_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\$\$?\{([A-Z_][A-Z0-9_]*)\}").expect("failed to compile regex: env_var_pattern")
});

/// Configuration errors
#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("Failed to parse JSON5 at {path}: {message}")]
    ParseError { path: String, message: String },

    #[error("Circular include detected: {path}")]
    CircularInclude { path: String },

    #[error("Include depth exceeded (max {max}): {path}")]
    IncludeDepthExceeded { path: String, max: usize },

    #[error("Failed to read config file {path}: {message}")]
    ReadError { path: String, message: String },

    #[error("Missing environment variable: {var}")]
    MissingEnvVar { var: String },

    #[error("Include file not found: {path}")]
    IncludeNotFound { path: String },

    #[error("Include directive must be a string or array of strings at {path}")]
    InvalidIncludeDirective { path: String },

    #[error("Included file must be an object when merged with sibling keys at {path}")]
    IncludeMustBeObject { path: String },

    #[error("Validation error at {path}: {message}")]
    ValidationError { path: String, message: String },

    #[error("config env state is already locked on this thread")]
    ReentrantConfigEnvAccess,

    #[error("runtime env substitution attempted while config env state is locked")]
    ReentrantConfigEnvSubstitution,
}

/// Cached configuration entry
struct CachedConfig {
    value: Arc<Value>,
    raw_value: Arc<Value>,
    loaded_at: Instant,
}

/// Global config cache
static CONFIG_CACHE: LazyLock<RwLock<Option<CachedConfig>>> = LazyLock::new(|| RwLock::new(None));
static CONFIG_CHANGE_TX: LazyLock<tokio::sync::watch::Sender<u64>> = LazyLock::new(|| {
    let (tx, _rx) = tokio::sync::watch::channel(0_u64);
    tx
});

#[derive(Clone, Default)]
pub(crate) struct InjectedConfigEnvState {
    active_values: HashMap<String, String>,
    previous_values: HashMap<String, Option<OsString>>,
}

static CONFIG_ENV_STATE: LazyLock<Mutex<InjectedConfigEnvState>> =
    LazyLock::new(|| Mutex::new(InjectedConfigEnvState::default()));

thread_local! {
    static CONFIG_ENV_STATE_LOCK_DEPTH: Cell<usize> = const { Cell::new(0) };
    static CONFIG_ENV_STATE_ACTIVE_SNAPSHOT: RefCell<Option<HashMap<String, String>>> =
        const { RefCell::new(None) };
}

struct ConfigEnvStateGuard {
    inner: ManuallyDrop<MutexGuard<'static, InjectedConfigEnvState>>,
}

impl ConfigEnvStateGuard {
    fn new(inner: MutexGuard<'static, InjectedConfigEnvState>) -> Self {
        refresh_config_env_state_active_snapshot(&inner);
        CONFIG_ENV_STATE_LOCK_DEPTH.with(|depth| {
            depth.set(depth.get() + 1);
        });
        Self {
            inner: ManuallyDrop::new(inner),
        }
    }
}

impl Deref for ConfigEnvStateGuard {
    type Target = InjectedConfigEnvState;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for ConfigEnvStateGuard {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl Drop for ConfigEnvStateGuard {
    fn drop(&mut self) {
        // Release the mutex explicitly before marking the thread-local depth as
        // clear, so the logical guard state never under-reports the physical
        // mutex hold.
        unsafe {
            ManuallyDrop::drop(&mut self.inner);
        }
        CONFIG_ENV_STATE_ACTIVE_SNAPSHOT.with(|snapshot| {
            *snapshot.borrow_mut() = None;
        });
        CONFIG_ENV_STATE_LOCK_DEPTH.with(|depth| {
            depth.set(depth.get().saturating_sub(1));
        });
    }
}

fn config_env_state_locked_on_current_thread() -> bool {
    CONFIG_ENV_STATE_LOCK_DEPTH.with(|depth| depth.get() > 0)
}

fn try_lock_config_env_state() -> Result<ConfigEnvStateGuard, ConfigError> {
    if config_env_state_locked_on_current_thread() {
        return Err(ConfigError::ReentrantConfigEnvAccess);
    }
    Ok(ConfigEnvStateGuard::new(CONFIG_ENV_STATE.lock()))
}

fn refresh_config_env_state_active_snapshot(state: &InjectedConfigEnvState) {
    CONFIG_ENV_STATE_ACTIVE_SNAPSHOT.with(|snapshot| {
        *snapshot.borrow_mut() = Some(state.active_values.clone());
    });
}

fn read_reentrant_config_env_os(key: &str) -> Option<OsString> {
    let config_value = CONFIG_ENV_STATE_ACTIVE_SNAPSHOT.with(|snapshot| {
        snapshot
            .borrow()
            .as_ref()
            .and_then(|active_values| active_values.get(key).map(OsString::from))
    });
    config_value.or_else(|| read_process_env_os(key))
}

fn read_reentrant_config_env_os_many<'a, I>(keys: I) -> Vec<(OsString, OsString)>
where
    I: IntoIterator<Item = &'a str>,
{
    CONFIG_ENV_STATE_ACTIVE_SNAPSHOT.with(|snapshot| {
        let snapshot = snapshot.borrow();
        let active_values = snapshot.as_ref();
        keys.into_iter()
            .filter_map(|key| {
                let value = active_values
                    .and_then(|values| values.get(key))
                    .map(OsString::from)
                    .or_else(|| read_process_env_os(key))?;
                Some((OsString::from(key), value))
            })
            .collect()
    })
}

fn lock_config_env_state_for_internal_state() -> ConfigEnvStateGuard {
    try_lock_config_env_state().expect("CONFIG_ENV_STATE is not reentrant")
}

/// Snapshot of the currently-injected config env state, opaque to callers.
pub(crate) fn snapshot_env_state() -> InjectedConfigEnvState {
    lock_config_env_state_for_internal_state().clone()
}

/// Restore process env to the state captured by [`snapshot_env_state`].
pub(crate) fn restore_env_state(snapshot: &InjectedConfigEnvState) {
    let mut current = lock_config_env_state_for_internal_state();
    restore_config_env_state(snapshot, &mut current);
}

#[cfg(test)]
pub(crate) fn apply_config_env_for_test(vars: HashMap<String, String>) {
    let mut state = lock_config_env_state_for_internal_state();
    apply_config_env_vars(&vars, &mut state);
}

#[cfg(test)]
fn reset_config_env_state() {
    let mut state = lock_config_env_state_for_internal_state();
    let empty = InjectedConfigEnvState::default();
    restore_config_env_state(&empty, &mut state);
}

/// RAII guard that empties `CONFIG_ENV_STATE` on construction and drop, so
/// tests that mutate the global env tracker can't bleed into each other.
/// `#[must_use]` so a bare `ScopedEnvStateForTest::new();` (which would drop
/// the guard immediately and leave the test body unprotected) is a warning.
#[cfg(test)]
#[must_use = "ScopedEnvStateForTest must be bound to a binding that lives for the test body; otherwise it drops immediately and leaves the test unprotected"]
pub(crate) struct ScopedEnvStateForTest;

#[cfg(test)]
impl ScopedEnvStateForTest {
    pub(crate) fn new() -> Self {
        reset_config_env_state();
        Self
    }
}

#[cfg(test)]
impl Drop for ScopedEnvStateForTest {
    fn drop(&mut self) {
        reset_config_env_state();
    }
}

/// Read an environment variable that may be supplied by `config.env`.
///
/// Config reloads mutate process env under `CONFIG_ENV_STATE`; runtime reads of
/// config-injectable keys must use the same lock so they cannot race
/// `set_var`/`remove_var`.
pub fn read_config_env(key: &str) -> Option<String> {
    os_string_to_string(key, read_config_env_os(key)?, "config env")
}

/// Read an OS environment variable that may be supplied by `config.env`.
///
/// Use this for runtime forwarding of environment values where non-Unicode
/// values must be preserved.
pub(crate) fn read_config_env_os(key: &str) -> Option<OsString> {
    let state = match try_lock_config_env_state() {
        Ok(state) => state,
        Err(ConfigError::ReentrantConfigEnvAccess) => {
            tracing::warn!(
                key,
                "reentrant config env read using active snapshot fallback"
            );
            return read_reentrant_config_env_os(key);
        }
        Err(err) => unreachable!("unexpected config env lock error: {err}"),
    };
    state
        .active_values
        .get(key)
        .map(OsString::from)
        .or_else(|| read_process_env_os(key))
}

/// Read several config-injectable environment variables as one consistent snapshot.
pub(crate) fn read_config_env_os_many<'a, I>(keys: I) -> Vec<(OsString, OsString)>
where
    I: IntoIterator<Item = &'a str>,
{
    let state = match try_lock_config_env_state() {
        Ok(state) => state,
        Err(ConfigError::ReentrantConfigEnvAccess) => {
            tracing::warn!("reentrant batched config env read using active snapshot fallback");
            return read_reentrant_config_env_os_many(keys);
        }
        Err(err) => unreachable!("unexpected config env lock error: {err}"),
    };
    keys.into_iter()
        .filter_map(|key| {
            let value = state
                .active_values
                .get(key)
                .map(OsString::from)
                .or_else(|| read_process_env_os(key))?;
            Some((OsString::from(key), value))
        })
        .collect()
}

/// Read a process-only environment variable.
///
/// Use this for loader-control, build metadata, OS/system values, and import
/// probes that must not be shadowed by `config.env`.
pub fn read_process_env(key: &str) -> Option<String> {
    os_string_to_string(key, read_process_env_os(key)?, "process env")
}

/// Read a process-only OS environment variable.
///
/// This intentionally bypasses `CONFIG_ENV_STATE`; do not use it for values
/// that users are allowed to inject through `config.env`.
#[allow(
    clippy::disallowed_methods,
    reason = "central raw process-env wrapper; callers must choose this explicitly"
)]
pub fn read_process_env_os(key: &str) -> Option<OsString> {
    env::var_os(key)
}

fn os_string_to_string(key: &str, value: OsString, source: &str) -> Option<String> {
    match value.into_string() {
        Ok(value) => Some(value),
        Err(_) => {
            tracing::warn!(
                env_var = %key,
                source = %source,
                "environment variable value is not valid UTF-8; treating it as unset"
            );
            None
        }
    }
}

/// Get the config file path.
/// Priority: CARAPACE_CONFIG_PATH > CARAPACE_STATE_DIR/carapace.json5 > ~/.config/carapace/carapace.json5
/// Falls back to .json extension if the .json5 file doesn't exist.
pub fn get_config_path() -> PathBuf {
    if let Some(path) = read_process_env("CARAPACE_CONFIG_PATH") {
        return PathBuf::from(path);
    }

    if let Some(state_dir) = read_process_env("CARAPACE_STATE_DIR") {
        let dir = PathBuf::from(state_dir);
        let json5 = dir.join("carapace.json5");
        if json5.exists() {
            return json5;
        }
        return dir.join("carapace.json");
    }

    let base = dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from(".config"))
        .join("carapace");
    let json5 = base.join("carapace.json5");
    if json5.exists() {
        return json5;
    }
    base.join("carapace.json")
}

/// Get the cache TTL duration
fn get_cache_ttl() -> Option<Duration> {
    // Check if caching is disabled
    if read_process_env("CARAPACE_DISABLE_CONFIG_CACHE").is_some() {
        return None;
    }

    let ms = read_process_env("CARAPACE_CONFIG_CACHE_MS")
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(DEFAULT_CACHE_TTL_MS);

    Some(Duration::from_millis(ms))
}

pub(crate) fn config_password() -> Option<Zeroizing<Vec<u8>>> {
    let password = read_process_env(CONFIG_PASSWORD_ENV)?;
    if password.is_empty() {
        return None;
    }
    Some(Zeroizing::new(password.into_bytes()))
}

fn resolve_config_secrets(value: &mut Value) -> Result<(), ConfigError> {
    let has_encrypted_values = secrets::contains_encrypted_values(value);
    if !has_encrypted_values {
        return Ok(());
    }

    match secrets::find_unsupported_encrypted_values(value) {
        Ok(unsupported) if !unsupported.is_empty() => {
            let path = if unsupported.len() == 1 {
                unsupported[0].path.clone()
            } else {
                ".".to_string()
            };
            let message = if unsupported.len() == 1 {
                format!(
                    "unsupported encrypted config secret envelope {} at {}; only enc:v2 is supported; re-enter or re-encrypt this config secret",
                    unsupported[0].prefix, unsupported[0].path
                )
            } else {
                let entries = unsupported
                    .iter()
                    .map(|value| format!("{} at {}", value.prefix, value.path))
                    .collect::<Vec<_>>()
                    .join(", ");
                format!(
                    "unsupported encrypted config secret envelopes: {entries}; only enc:v2 is supported; re-enter or re-encrypt these config secrets"
                )
            };
            return Err(ConfigError::ValidationError { path, message });
        }
        Ok(_) => {}
        Err(err) => {
            return Err(ConfigError::ValidationError {
                path: err.path,
                message: format!(
                    "config secret scan exceeded maximum depth {}; reduce config nesting before using encrypted config secrets",
                    err.max_depth
                ),
            });
        }
    }

    let Some(password) = config_password() else {
        tracing::warn!(
            "{} is not set; encrypted config values will remain locked",
            CONFIG_PASSWORD_ENV
        );
        secrets::scrub_encrypted_values(value);
        return Ok(());
    };
    let store = secrets::SecretStore::for_decrypt(password.as_ref());
    secrets::resolve_secrets(value, &store, password.as_ref());
    Ok(())
}

pub(crate) fn seal_config_secrets(value: &mut Value) -> Result<(), String> {
    let Some(password) = config_password() else {
        return Ok(());
    };
    let store = secrets::SecretStore::new(password.as_ref())
        .map_err(|err| format!("failed to initialize config secret store: {}", err))?;
    let mut paths = Vec::new();
    for &path in CONFIG_SECRET_PATHS {
        match value.pointer(path) {
            Some(Value::String(_)) => paths.push(path),
            Some(_) => tracing::warn!("config secret path '{}' is not a string, skipping", path),
            None => {}
        }
    }
    if paths.is_empty() {
        return Ok(());
    }
    secrets::seal_secrets(value, &store, &paths)
        .map_err(|err| format!("failed to encrypt config secrets: {}", err))
}

/// Load and parse the configuration file with caching.
/// Returns empty object `{}` if file doesn't exist.
///
/// The returned value has all config defaults applied so that missing
/// sections/fields have production-ready values.
pub fn load_config() -> Result<Value, ConfigError> {
    Ok(load_config_shared()?.as_ref().clone())
}

/// Load and parse the configuration file with caching, returning a shared value.
pub fn load_config_shared() -> Result<Arc<Value>, ConfigError> {
    with_cached_config(|cached| Arc::clone(&cached.value))
}

/// Load the explicit user config without applying defaults, returning a shared value.
///
/// The returned value still has includes resolved, env substitution applied,
/// and encrypted secrets decrypted. Missing files return an empty object `{}`.
pub(crate) fn load_raw_config_shared() -> Result<Arc<Value>, ConfigError> {
    with_cached_config(|cached| Arc::clone(&cached.raw_value))
}

/// Run `project` against the current cached config, refreshing from disk
/// if the cache is empty / TTL-expired / cache-disabled. Centralizes the
/// TTL guard + cache-miss + `maybe_store_cached_config` path so policy
/// changes (e.g. event-based invalidation, separate raw/normalized TTLs)
/// only need editing in one place.
fn with_cached_config<R>(project: impl FnOnce(&CachedConfig) -> R) -> Result<R, ConfigError> {
    if let Some(ttl) = get_cache_ttl() {
        let cache = CONFIG_CACHE.read();
        if let Some(cached) = cache.as_ref() {
            if cached.loaded_at.elapsed() < ttl {
                return Ok(project(cached));
            }
        }
    }

    let cached = load_cached_config_uncached(&get_config_path())?;
    let result = project(&cached);
    maybe_store_cached_config(cached);
    Ok(result)
}

/// Return the currently cached explicit user config if the cache entry is still fresh.
///
/// Unlike `load_raw_config_shared`, this never forces a disk reload. Callers can
/// use it on hot async paths to avoid unnecessary blocking work, while still
/// honoring the configured cache TTL.
pub(crate) fn peek_fresh_raw_config_shared() -> Option<Arc<Value>> {
    let ttl = get_cache_ttl()?;
    let cache = CONFIG_CACHE.read();
    let cached = cache.as_ref()?;
    if cached.loaded_at.elapsed() < ttl {
        Some(Arc::clone(&cached.raw_value))
    } else {
        None
    }
}

/// Load config without using the cache.
///
/// After parsing, include resolution, and env var substitution, this applies
/// config defaults so that missing sections/fields have sensible values.
pub fn load_config_uncached(path: &Path) -> Result<Value, ConfigError> {
    Ok(load_cached_config_uncached(path)?.value.as_ref().clone())
}

pub(crate) fn load_config_pair_uncached(path: &Path) -> Result<(Value, Value), ConfigError> {
    let cached = load_cached_config_uncached(path)?;
    Ok((
        cached.raw_value.as_ref().clone(),
        cached.value.as_ref().clone(),
    ))
}

fn load_raw_config_uncached(path: &Path) -> Result<Value, ConfigError> {
    // Return empty object if file doesn't exist.
    if !path.exists() {
        let mut env_state = try_lock_config_env_state()?;
        let empty_env_state = InjectedConfigEnvState::default();
        restore_config_env_state(&empty_env_state, &mut env_state);
        return Ok(Value::Object(serde_json::Map::new()));
    }

    // Read and parse the config file
    let content = fs::read_to_string(path).map_err(|e| ConfigError::ReadError {
        path: path.display().to_string(),
        message: e.to_string(),
    })?;

    let mut value = parse_json5(&content, path)?;

    // Resolve $include directives
    let mut visited = HashSet::new();
    visited.insert(path.canonicalize().unwrap_or_else(|_| path.to_path_buf()));
    resolve_includes(&mut value, path, &mut visited, 0)?;

    // Export config-provided env vars before ${VAR} substitution so included
    // env blocks can satisfy later placeholders and runtime env lookups.
    //
    // This intentionally mutates process env because later config/runtime
    // lookups rely on these values, but the mutation is serialized and rolled
    // back if substitution fails.
    let mut env_state = try_lock_config_env_state()?;
    let resolved_env = resolve_config_env_vars(&value, &env_state)?;
    let previous_env_state = env_state.clone();
    apply_config_env_vars(&resolved_env, &mut env_state);

    // Apply environment variable substitution against the process env after the
    // config-provided values have been installed.
    if let Err(err) = substitute_env_vars(&mut value) {
        restore_config_env_state(&previous_env_state, &mut env_state);
        return Err(err);
    }
    drop(env_state);

    // Resolve encrypted secrets if configured.
    resolve_config_secrets(&mut value)?;

    Ok(value)
}

fn load_cached_config_uncached(path: &Path) -> Result<CachedConfig, ConfigError> {
    let raw_value = load_raw_config_uncached(path)?;
    let mut value = raw_value.clone();
    defaults::apply_defaults(&mut value);
    crate::usage::update_pricing_from_config(&value);
    Ok(CachedConfig {
        value: Arc::new(value),
        raw_value: Arc::new(raw_value),
        loaded_at: Instant::now(),
    })
}

fn maybe_store_cached_config(cached: CachedConfig) {
    if get_cache_ttl().is_some() {
        let mut cache = CONFIG_CACHE.write();
        *cache = Some(cached);
    }
}

fn collect_config_env_vars(value: &Value) -> Result<Vec<(String, String)>, ConfigError> {
    let Some(env_obj) = value.get("env").and_then(|v| v.as_object()) else {
        return Ok(Vec::new());
    };

    let mut collected = Vec::new();

    if let Some(vars_obj) = env_obj.get("vars").and_then(|v| v.as_object()) {
        for (key, value) in vars_obj {
            collect_config_env_entry(
                &mut collected,
                key,
                value.as_str(),
                &format!(".env.vars.{}", key),
            )?;
        }
    }

    for (key, value) in env_obj {
        if key == "vars" || key == "shellEnv" {
            continue;
        }
        collect_config_env_entry(
            &mut collected,
            key,
            value.as_str(),
            &format!(".env.{}", key),
        )?;
    }

    Ok(collected)
}

fn collect_config_env_entry(
    entries: &mut Vec<(String, String)>,
    key: &str,
    value: Option<&str>,
    path: &str,
) -> Result<(), ConfigError> {
    if !is_valid_env_var_name(key) {
        tracing::warn!(env_var = %key, "ignoring invalid config env key");
        return Ok(());
    }

    if is_loader_control_env_var(key) {
        return Err(ConfigError::ValidationError {
            path: path.to_string(),
            message: format!(
                "{} cannot be set from config.env because it controls config loading behavior",
                key
            ),
        });
    }

    let Some(value) = value else {
        tracing::warn!(env_var = %key, "ignoring non-string config env value");
        return Ok(());
    };

    if value.contains('\0') {
        return Err(ConfigError::ValidationError {
            path: path.to_string(),
            message: "env values must not contain NUL bytes".to_string(),
        });
    };

    entries.push((key.to_string(), value.to_string()));
    Ok(())
}

fn is_valid_env_var_name(key: &str) -> bool {
    !key.is_empty() && !key.contains('=') && !key.contains('\0')
}

fn is_loader_control_env_var(key: &str) -> bool {
    LOADER_CONTROL_ENV_VARS
        .iter()
        .any(|blocked| blocked.eq_ignore_ascii_case(key))
}

fn resolve_config_env_vars(
    value: &Value,
    state: &InjectedConfigEnvState,
) -> Result<HashMap<String, String>, ConfigError> {
    let raw_entries = collect_config_env_vars(value);
    if raw_entries.as_ref().is_ok_and(|entries| entries.is_empty()) {
        return Ok(HashMap::new());
    }

    let raw: HashMap<String, String> = raw_entries?.into_iter().collect();
    let mut resolved = HashMap::new();
    let mut resolving = HashSet::new();

    for key in raw.keys() {
        resolve_config_env_var(key, &raw, state, &mut resolved, &mut resolving)?;
    }

    Ok(resolved)
}

fn resolve_config_env_var(
    key: &str,
    raw: &HashMap<String, String>,
    state: &InjectedConfigEnvState,
    resolved: &mut HashMap<String, String>,
    resolving: &mut HashSet<String>,
) -> Result<String, ConfigError> {
    if let Some(value) = resolved.get(key) {
        return Ok(value.clone());
    }

    if !resolving.insert(key.to_string()) {
        return Err(ConfigError::ValidationError {
            path: ".env".to_string(),
            message: format!("circular config env reference involving {}", key),
        });
    }

    let raw_value = raw.get(key).ok_or_else(|| ConfigError::MissingEnvVar {
        var: key.to_string(),
    })?;

    let value = substitute_env_in_string_with(raw_value, |var_name| {
        if raw.contains_key(var_name) {
            resolve_config_env_var(var_name, raw, state, resolved, resolving)
        } else {
            resolve_external_env_var(var_name, state)
        }
    })?;

    resolving.remove(key);
    resolved.insert(key.to_string(), value.clone());
    Ok(value)
}

fn resolve_external_env_var(
    key: &str,
    state: &InjectedConfigEnvState,
) -> Result<String, ConfigError> {
    if state.active_values.contains_key(key) {
        let previous = state.previous_values.get(key).cloned().flatten();
        let value = previous.ok_or_else(|| ConfigError::MissingEnvVar {
            var: key.to_string(),
        })?;
        return value.into_string().map_err(|_| ConfigError::MissingEnvVar {
            var: key.to_string(),
        });
    }

    resolve_process_env_var(key)
}

fn apply_config_env_vars(next: &HashMap<String, String>, state: &mut InjectedConfigEnvState) {
    let next_keys: HashSet<String> = next.keys().cloned().collect();

    for key in state.active_values.keys().cloned().collect::<Vec<_>>() {
        if next_keys.contains(&key) {
            continue;
        }

        restore_previous_config_env_value(&key, state);
    }

    for (key, value) in next {
        if state
            .active_values
            .get(key)
            .is_some_and(|current| current == value)
        {
            continue;
        }
        set_config_env_value(key, value, state);
    }

    refresh_config_env_state_active_snapshot(state);
}

fn restore_config_env_state(
    previous: &InjectedConfigEnvState,
    current: &mut InjectedConfigEnvState,
) {
    for key in current.active_values.keys().cloned().collect::<Vec<_>>() {
        if previous.active_values.contains_key(&key) {
            continue;
        }

        restore_previous_config_env_value(&key, current);
    }

    for (key, value) in &previous.active_values {
        set_process_env_value(key, value);
    }

    *current = previous.clone();
    refresh_config_env_state_active_snapshot(current);
}

fn set_config_env_value(key: &str, value: &str, state: &mut InjectedConfigEnvState) {
    let previous = (!state.active_values.contains_key(key)).then(|| read_process_env_os(key));

    // Config env entries are validated by collect_config_env_entry before
    // reaching this writer, so std::env::set_var should not reject these keys
    // or values. Mutate process env first so the same-thread reentrant fallback
    // never observes active_values ahead of process env.
    set_process_env_value(key, value);

    if let Some(previous) = previous {
        state.previous_values.insert(key.to_string(), previous);
    }
    state
        .active_values
        .insert(key.to_string(), value.to_string());
}

fn restore_previous_config_env_value(key: &str, state: &mut InjectedConfigEnvState) {
    match state.previous_values.get(key).cloned().flatten() {
        Some(value) => set_process_env_value(key, value),
        None => remove_process_env_value(key),
    }
    state.previous_values.remove(key);
    state.active_values.remove(key);
}

#[allow(
    clippy::disallowed_methods,
    reason = "central serialized config-env process writer; callers must hold CONFIG_ENV_STATE"
)]
fn set_process_env_value<K, V>(key: K, value: V)
where
    K: AsRef<std::ffi::OsStr>,
    V: AsRef<std::ffi::OsStr>,
{
    env::set_var(key, value);
}

#[allow(
    clippy::disallowed_methods,
    reason = "central serialized config-env process remover; callers must hold CONFIG_ENV_STATE"
)]
fn remove_process_env_value<K>(key: K)
where
    K: AsRef<std::ffi::OsStr>,
{
    env::remove_var(key);
}

/// Parse JSON5 content
fn parse_json5(content: &str, path: &Path) -> Result<Value, ConfigError> {
    json5::from_str(content).map_err(|e| ConfigError::ParseError {
        path: path.display().to_string(),
        message: e.to_string(),
    })
}

/// Recursively resolve $include directives
fn resolve_includes(
    value: &mut Value,
    parent_path: &Path,
    visited: &mut HashSet<PathBuf>,
    depth: usize,
) -> Result<(), ConfigError> {
    if depth > MAX_INCLUDE_DEPTH {
        return Err(ConfigError::IncludeDepthExceeded {
            path: parent_path.display().to_string(),
            max: MAX_INCLUDE_DEPTH,
        });
    }

    if let Value::Object(obj) = value {
        // Check for $include directive
        if let Some(include_value) = obj.remove("$include") {
            let parent_dir = parent_path.parent().unwrap_or(Path::new("."));
            let include_paths = get_include_paths(&include_value, parent_path)?;

            // Load and merge all included files
            let mut merged = Value::Object(serde_json::Map::new());
            for include_path in include_paths {
                let resolved_path = parent_dir.join(&include_path);
                let canonical = resolved_path
                    .canonicalize()
                    .unwrap_or_else(|_| resolved_path.clone());

                // Check for circular includes
                if visited.contains(&canonical) {
                    return Err(ConfigError::CircularInclude {
                        path: resolved_path.display().to_string(),
                    });
                }

                // Check if file exists
                if !resolved_path.exists() {
                    return Err(ConfigError::IncludeNotFound {
                        path: resolved_path.display().to_string(),
                    });
                }

                visited.insert(canonical);

                let content =
                    fs::read_to_string(&resolved_path).map_err(|e| ConfigError::ReadError {
                        path: resolved_path.display().to_string(),
                        message: e.to_string(),
                    })?;

                let mut included = parse_json5(&content, &resolved_path)?;

                // Recursively resolve includes in the included file
                resolve_includes(&mut included, &resolved_path, visited, depth + 1)?;

                // Merge included content
                deep_merge(&mut merged, included);
            }

            // If there are sibling keys, merge them on top of included content
            if obj.is_empty() {
                // Only $include was present, replace value with merged content
                *value = merged;
            } else {
                // Sibling keys present - included content must be an object
                if !merged.is_object() {
                    return Err(ConfigError::IncludeMustBeObject {
                        path: parent_path.display().to_string(),
                    });
                }

                // First merge included content into merged, then merge siblings on top
                let siblings = Value::Object(std::mem::take(obj));
                deep_merge(&mut merged, siblings);
                *value = merged;
            }
        }

        // Recursively process nested objects
        if let Value::Object(obj) = value {
            for (_, v) in obj.iter_mut() {
                resolve_includes(v, parent_path, visited, depth)?;
            }
        }
    }

    // Also process arrays
    if let Value::Array(arr) = value {
        for item in arr.iter_mut() {
            resolve_includes(item, parent_path, visited, depth)?;
        }
    }

    Ok(())
}

/// Extract include paths from the $include value (string or array)
fn get_include_paths(value: &Value, parent_path: &Path) -> Result<Vec<String>, ConfigError> {
    match value {
        Value::String(s) => Ok(vec![s.clone()]),
        Value::Array(arr) => {
            let mut paths = Vec::new();
            for item in arr {
                match item {
                    Value::String(s) => paths.push(s.clone()),
                    _ => {
                        return Err(ConfigError::InvalidIncludeDirective {
                            path: parent_path.display().to_string(),
                        })
                    }
                }
            }
            Ok(paths)
        }
        _ => Err(ConfigError::InvalidIncludeDirective {
            path: parent_path.display().to_string(),
        }),
    }
}

/// Deep merge two JSON values.
/// Rules: objects merge recursively, arrays concatenate, primitives override.
fn deep_merge(base: &mut Value, overlay: Value) {
    match (base, overlay) {
        (Value::Object(base_obj), Value::Object(overlay_obj)) => {
            for (key, overlay_value) in overlay_obj {
                match base_obj.get_mut(&key) {
                    Some(base_value) => deep_merge(base_value, overlay_value),
                    None => {
                        base_obj.insert(key, overlay_value);
                    }
                }
            }
        }
        (Value::Array(base_arr), Value::Array(overlay_arr)) => {
            // Arrays concatenate
            base_arr.extend(overlay_arr);
        }
        (base, overlay) => {
            // Primitives override
            *base = overlay;
        }
    }
}

/// Substitute environment variables in string values.
/// Pattern: ${VAR} where VAR matches [A-Z_][A-Z0-9_]*
/// Escape with $${VAR} to get literal ${VAR}
fn substitute_env_vars(value: &mut Value) -> Result<(), ConfigError> {
    match value {
        Value::String(s) => {
            // The config loader calls this while holding CONFIG_ENV_STATE after
            // installing config env values, so avoid re-locking here.
            *s = substitute_env_in_string_with(s, resolve_process_env_var)?;
        }
        Value::Object(obj) => {
            for (_, v) in obj.iter_mut() {
                substitute_env_vars(v)?;
            }
        }
        Value::Array(arr) => {
            for item in arr.iter_mut() {
                substitute_env_vars(item)?;
            }
        }
        _ => {}
    }
    Ok(())
}

/// Substitute environment variables in a single runtime string.
///
/// This resolves through [`read_config_env`] and therefore acquires
/// `CONFIG_ENV_STATE`. Loader paths that already hold that lock must use
/// `substitute_env_in_string_with(..., resolve_process_env_var)` instead.
pub(crate) fn substitute_env_in_string(s: &str) -> Result<String, ConfigError> {
    if config_env_state_locked_on_current_thread() {
        return Err(ConfigError::ReentrantConfigEnvSubstitution);
    }
    substitute_env_in_string_with(s, resolve_runtime_env_var)
}

fn resolve_process_env_var(var_name: &str) -> Result<String, ConfigError> {
    read_process_env(var_name).ok_or_else(|| ConfigError::MissingEnvVar {
        var: var_name.to_string(),
    })
}

fn resolve_runtime_env_var(var_name: &str) -> Result<String, ConfigError> {
    read_config_env(var_name).ok_or_else(|| ConfigError::MissingEnvVar {
        var: var_name.to_string(),
    })
}

pub(crate) fn env_var_references_in_string(s: &str) -> Vec<String> {
    let mut references = Vec::new();
    let mut seen = HashSet::new();

    for caps in ENV_VAR_PATTERN.captures_iter(s) {
        let full_match = caps
            .get(0)
            .expect("env var regex must produce a full match");
        if full_match.as_str().starts_with("$$") {
            continue;
        }
        let reference = caps
            .get(1)
            .expect("env var regex must capture the variable name")
            .as_str()
            .to_string();
        if seen.insert(reference.clone()) {
            references.push(reference);
        }
    }

    references
}

pub(crate) fn substitute_env_in_string_with<F>(
    s: &str,
    mut resolver: F,
) -> Result<String, ConfigError>
where
    F: FnMut(&str) -> Result<String, ConfigError>,
{
    let mut result = String::with_capacity(s.len());
    let mut last_end = 0;

    for caps in ENV_VAR_PATTERN.captures_iter(s) {
        let full_match = caps.get(0).unwrap();
        let var_name = caps.get(1).unwrap().as_str();

        // Add text before this match
        result.push_str(&s[last_end..full_match.start()]);

        // Check if this is an escaped pattern ($${ instead of ${)
        let match_str = full_match.as_str();
        if match_str.starts_with("$$") {
            // Escaped - output literal ${VAR}
            result.push_str(&format!("${{{}}}", var_name));
        } else {
            // Not escaped - substitute with env var value
            let value = resolver(var_name)?;
            result.push_str(&value);
        }

        last_end = full_match.end();
    }

    // Add remaining text
    result.push_str(&s[last_end..]);

    Ok(result)
}

/// Clear the config cache (useful for testing or forced reload)
pub fn clear_cache() {
    let mut cache = CONFIG_CACHE.write();
    *cache = None;
    broadcast_config_change();
}

/// Atomically update the config cache with a pre-validated config value.
///
/// This is used by the config watcher and reload mechanism to install a new
/// raw + normalized config pair without going through file I/O again.
pub fn update_cache(raw_value: Value, value: Value) {
    update_cache_arc(Arc::new(raw_value), Arc::new(value));
}

/// `Arc`-taking variant of [`update_cache`] for callers that already hold
/// `Arc<Value>` snapshots — avoids a deep JSON clone at the cache boundary.
pub(crate) fn update_cache_arc(raw_value: Arc<Value>, value: Arc<Value>) {
    let mut cache = CONFIG_CACHE.write();
    *cache = Some(CachedConfig {
        value,
        raw_value,
        loaded_at: Instant::now(),
    });
    broadcast_config_change();
}

#[cfg(test)]
pub(crate) fn update_cache_for_test_with_age(raw_value: Value, value: Value, age: Duration) {
    let mut cache = CONFIG_CACHE.write();
    *cache = Some(CachedConfig {
        value: Arc::new(value),
        raw_value: Arc::new(raw_value),
        loaded_at: Instant::now().checked_sub(age).unwrap_or_else(Instant::now),
    });
    broadcast_config_change();
}

/// Subscribe to in-process config-change notifications.
///
/// Subscribers wake on cache updates via [`update_cache`] /
/// [`update_cache_arc`] and should re-read the cache via
/// [`load_config_shared`] / [`load_raw_config_shared`] on each tick.
///
/// The hot-reload bridge installs the cache only on validated reloads, so
/// each tick corresponds to a successfully-validated config snapshot:
/// rejected reloads (no provider, build failure, parse error) produce zero
/// ticks. Subscribers can therefore re-read the cache without needing to
/// tolerate a transient bad-state read.
///
/// The disk-fallback path in `with_cached_config` (cache-miss / TTL-expired
/// reads of the config file) writes silently — it does not broadcast — so
/// subscribers see only validated reload events.
pub fn subscribe_config_changes() -> tokio::sync::watch::Receiver<u64> {
    CONFIG_CHANGE_TX.subscribe()
}

fn broadcast_config_change() {
    let next = CONFIG_CHANGE_TX.borrow().wrapping_add(1);
    let _ = CONFIG_CHANGE_TX.send(next);
}

/// Reload the config from disk, validate it, and install it in `CONFIG_CACHE`.
///
/// Returns the new config on success or a `ConfigError` if the file cannot be
/// read or parsed. Validation warnings are returned alongside the config; only
/// hard parse/read errors cause an `Err`.
///
/// Prefer [`load_pending_config`] when the caller wants to validate the
/// reloaded payload (e.g. against provider invariants in the hot-reload
/// bridge) **before** committing it. `reload_config` always commits, so any
/// validation it skips happens too late to suppress the resulting cache
/// broadcast.
pub fn reload_config() -> Result<(Value, Vec<ValidationIssue>), ConfigError> {
    let pending = load_pending_config()?;
    let new_config = pending.normalized.as_ref().clone();
    update_cache_arc(pending.raw, pending.normalized);
    Ok((new_config, pending.issues))
}

/// Result of a cache-less config load: the raw and normalized halves plus
/// any validation issues. Both halves come from the same load generation —
/// the caller decides whether (and when) to install via [`update_cache_arc`].
pub(crate) struct PendingConfig {
    pub raw: Arc<Value>,
    pub normalized: Arc<Value>,
    pub issues: Vec<ValidationIssue>,
}

/// Read the config from disk without touching `CONFIG_CACHE`.
///
/// Includes are resolved and env vars are substituted as part of the load
/// (the substitution requires injecting config-provided env vars into the
/// process, so this side-effect happens here regardless of whether the
/// caller commits the result). Subscribers of [`subscribe_config_changes`]
/// are NOT notified — only [`update_cache`] / [`update_cache_arc`] broadcast.
///
/// Used by the hot-reload bridge to obtain the new `(raw, normalized)` pair
/// for provider validation; on a rejected reload the bridge can simply drop
/// the returned `PendingConfig` and `CONFIG_CACHE` stays at the last
/// committed value.
pub(crate) fn load_pending_config() -> Result<PendingConfig, ConfigError> {
    let path = get_config_path();
    let cached = load_cached_config_uncached(&path)?;
    let issues = validate_config(&cached.value);
    Ok(PendingConfig {
        raw: cached.raw_value,
        normalized: cached.value,
        issues,
    })
}

/// Validation error with path context
#[derive(Debug)]
pub struct ValidationIssue {
    pub path: String,
    pub message: String,
}

/// Validate a config value against the schema.
///
/// Delegates to the typed schema validation in [`schema::validate_schema`]
/// and converts results to the public [`ValidationIssue`] type.
pub fn validate_config(config: &Value) -> Vec<ValidationIssue> {
    schema::validate_schema(config)
        .into_iter()
        .map(|si| ValidationIssue {
            path: si.path,
            message: si.message,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::env::ScopedEnv;
    use std::fs::File;
    use std::io::Write;
    use tempfile::TempDir;

    /// Helper to create a temp config file
    fn create_temp_config(dir: &TempDir, name: &str, content: &str) -> PathBuf {
        let path = dir.path().join(name);
        let mut file = File::create(&path).unwrap();
        file.write_all(content.as_bytes()).unwrap();
        path
    }

    fn reset_config_env_state_for_test() {
        super::reset_config_env_state();
    }

    #[test]
    fn test_parse_json5_basic() {
        let content = r#"{
            // This is a comment
            "key": "value",
            "number": 42,
            trailing: "comma",
        }"#;

        let path = Path::new("test.json5");
        let result = parse_json5(content, path).unwrap();

        assert_eq!(result["key"], "value");
        assert_eq!(result["number"], 42);
        assert_eq!(result["trailing"], "comma");
    }

    #[test]
    fn test_parse_json5_unquoted_keys() {
        let content = r#"{
            unquotedKey: "value",
            "quotedKey": "value2"
        }"#;

        let path = Path::new("test.json5");
        let result = parse_json5(content, path).unwrap();

        assert_eq!(result["unquotedKey"], "value");
        assert_eq!(result["quotedKey"], "value2");
    }

    #[test]
    fn test_parse_json5_error() {
        let content = r#"{ invalid json }"#;
        let path = Path::new("test.json5");
        let result = parse_json5(content, path);

        assert!(matches!(result, Err(ConfigError::ParseError { .. })));
    }

    #[test]
    fn test_env_var_substitution() {
        let mut env_guard = ScopedEnv::new();
        env_guard.set("TEST_VAR_ONE", "hello");
        env_guard.set("TEST_VAR_TWO", "world");

        let result = substitute_env_in_string("${TEST_VAR_ONE} ${TEST_VAR_TWO}!").unwrap();
        assert_eq!(result, "hello world!");
    }

    #[test]
    fn test_env_var_escaped() {
        let result = substitute_env_in_string("$${ESCAPED_VAR}").unwrap();
        assert_eq!(result, "${ESCAPED_VAR}");
    }

    #[test]
    fn test_env_var_missing() {
        let mut env_guard = ScopedEnv::new();
        env_guard.unset("NONEXISTENT_VAR_12345");
        let result = substitute_env_in_string("${NONEXISTENT_VAR_12345}");

        assert!(
            matches!(result, Err(ConfigError::MissingEnvVar { var }) if var == "NONEXISTENT_VAR_12345")
        );
    }

    #[test]
    fn test_env_var_partial_string() {
        let mut env_guard = ScopedEnv::new();
        env_guard.set("TEST_API_KEY", "sk-secret");

        let result = substitute_env_in_string("Bearer ${TEST_API_KEY}").unwrap();
        assert_eq!(result, "Bearer sk-secret");
    }

    #[test]
    fn test_env_var_substitution_reads_active_config_env_state() {
        let mut env_guard = ScopedEnv::new();
        let _env_state_guard = ScopedEnvStateForTest::new();
        env_guard.set("TEST_CONFIG_SUBSTITUTE_ENV", "external-value");
        apply_config_env_for_test(HashMap::from([(
            "TEST_CONFIG_SUBSTITUTE_ENV".to_string(),
            "config-value".to_string(),
        )]));

        let result = substitute_env_in_string("${TEST_CONFIG_SUBSTITUTE_ENV}").unwrap();

        assert_eq!(result, "config-value");
        env_guard.unset("TEST_CONFIG_SUBSTITUTE_ENV");
    }

    #[test]
    fn test_runtime_env_substitution_rejects_reentrant_config_env_lock() {
        let _env_state_guard = ScopedEnvStateForTest::new();
        let _state = lock_config_env_state_for_internal_state();

        let result = substitute_env_in_string("${TEST_CONFIG_SUBSTITUTE_ENV}");

        assert!(matches!(
            result,
            Err(ConfigError::ReentrantConfigEnvSubstitution)
        ));
    }

    #[test]
    fn test_config_env_readers_use_active_snapshot_when_reentrant() {
        let mut env_guard = ScopedEnv::new();
        let _env_state_guard = ScopedEnvStateForTest::new();
        env_guard.unset("TEST_REENTRANT_CONFIG_ENV_READ");
        apply_config_env_for_test(HashMap::from([(
            "TEST_REENTRANT_CONFIG_ENV_READ".to_string(),
            "config-value".to_string(),
        )]));
        // Prove the reentrant path is backed by the active config-env snapshot,
        // not by the raw process environment side effect.
        env_guard.unset("TEST_REENTRANT_CONFIG_ENV_READ");

        let _state = lock_config_env_state_for_internal_state();

        assert_eq!(
            read_config_env("TEST_REENTRANT_CONFIG_ENV_READ").as_deref(),
            Some("config-value")
        );
        assert_eq!(
            read_config_env_os("TEST_REENTRANT_CONFIG_ENV_READ").as_deref(),
            Some(std::ffi::OsStr::new("config-value"))
        );
        assert_eq!(
            read_config_env_os_many(["TEST_REENTRANT_CONFIG_ENV_READ"]),
            vec![(
                OsString::from("TEST_REENTRANT_CONFIG_ENV_READ"),
                OsString::from("config-value")
            )]
        );
    }

    #[test]
    fn test_env_var_references_in_string_deduplicates_preserving_first_seen_order() {
        let references = env_var_references_in_string("${HOST}:${HOST}/v1/${PORT}?mirror=${HOST}");

        assert_eq!(references, vec!["HOST".to_string(), "PORT".to_string()]);
    }

    #[test]
    fn test_deep_merge_objects() {
        let mut base = serde_json::json!({
            "a": 1,
            "b": {
                "c": 2,
                "d": 3
            }
        });

        let overlay = serde_json::json!({
            "b": {
                "d": 4,
                "e": 5
            },
            "f": 6
        });

        deep_merge(&mut base, overlay);

        assert_eq!(base["a"], 1);
        assert_eq!(base["b"]["c"], 2);
        assert_eq!(base["b"]["d"], 4); // Overridden
        assert_eq!(base["b"]["e"], 5); // Added
        assert_eq!(base["f"], 6); // Added
    }

    #[test]
    fn test_deep_merge_arrays_concatenate() {
        let mut base = serde_json::json!({
            "arr": [1, 2]
        });

        let overlay = serde_json::json!({
            "arr": [3, 4]
        });

        deep_merge(&mut base, overlay);

        let arr = base["arr"].as_array().unwrap();
        assert_eq!(arr.len(), 4);
        assert_eq!(arr, &vec![1, 2, 3, 4]);
    }

    #[test]
    fn test_include_single_file() {
        let dir = TempDir::new().unwrap();

        create_temp_config(&dir, "base.json5", r#"{ "baseKey": "baseValue" }"#);
        let main_path = create_temp_config(
            &dir,
            "main.json5",
            r#"{
                "$include": "./base.json5",
                "mainKey": "mainValue"
            }"#,
        );

        let config = load_config_uncached(&main_path).unwrap();

        assert_eq!(config["baseKey"], "baseValue");
        assert_eq!(config["mainKey"], "mainValue");
    }

    #[test]
    fn test_include_multiple_files() {
        let dir = TempDir::new().unwrap();

        create_temp_config(&dir, "a.json5", r#"{ "a": 1 }"#);
        create_temp_config(&dir, "b.json5", r#"{ "b": 2 }"#);
        let main_path = create_temp_config(
            &dir,
            "main.json5",
            r#"{
                "$include": ["./a.json5", "./b.json5"],
                "main": 3
            }"#,
        );

        let config = load_config_uncached(&main_path).unwrap();

        assert_eq!(config["a"], 1);
        assert_eq!(config["b"], 2);
        assert_eq!(config["main"], 3);
    }

    #[test]
    fn test_include_only() {
        let dir = TempDir::new().unwrap();

        create_temp_config(&dir, "base.json5", r#"{ "imported": true }"#);
        let main_path = create_temp_config(
            &dir,
            "main.json5",
            r#"{
                "$include": "./base.json5"
            }"#,
        );

        let config = load_config_uncached(&main_path).unwrap();

        assert_eq!(config["imported"], true);
    }

    #[test]
    fn test_circular_include_detection() {
        let dir = TempDir::new().unwrap();

        create_temp_config(&dir, "a.json5", r#"{ "$include": "./b.json5", "a": 1 }"#);
        create_temp_config(&dir, "b.json5", r#"{ "$include": "./a.json5", "b": 2 }"#);
        let main_path = dir.path().join("a.json5");

        let result = load_config_uncached(&main_path);

        assert!(matches!(result, Err(ConfigError::CircularInclude { .. })));
    }

    #[test]
    fn test_include_not_found() {
        let dir = TempDir::new().unwrap();

        let main_path = create_temp_config(
            &dir,
            "main.json5",
            r#"{ "$include": "./nonexistent.json5" }"#,
        );

        let result = load_config_uncached(&main_path);

        assert!(matches!(result, Err(ConfigError::IncludeNotFound { .. })));
    }

    #[test]
    fn test_config_not_exists_returns_defaults() {
        let path = PathBuf::from("/nonexistent/path/config.json");
        let result = load_config_uncached(&path).unwrap();

        assert!(result.is_object());
        // When config file doesn't exist, defaults are applied so the object
        // is non-empty and contains the essential sections.
        let obj = result.as_object().unwrap();
        assert!(!obj.is_empty(), "missing config should return defaults");
        assert!(obj.contains_key("gateway"), "should have gateway defaults");
        assert_eq!(result["gateway"]["port"], 18789);
        assert_eq!(result["gateway"]["bind"], "loopback");
        assert!(obj.contains_key("logging"), "should have logging defaults");
        assert_eq!(result["logging"]["level"], "info");
    }

    #[test]
    fn test_validation_unknown_key() {
        let config = serde_json::json!({
            "gateway": { "port": 18789 },
            "unknownKey": "value"
        });

        let issues = validate_config(&config);

        assert_eq!(issues.len(), 1);
        assert!(issues[0].path.contains("unknownKey"));
    }

    #[test]
    fn test_validation_known_keys_pass() {
        let config = serde_json::json!({
            "gateway": { "port": 18789, "hooks": { "enabled": true } },
            "logging": { "level": "debug" }
        });

        let issues = validate_config(&config);

        assert!(issues.is_empty());
    }

    #[test]
    fn test_validation_invalid_port_type() {
        let config = serde_json::json!({
            "gateway": { "port": "not-a-number" }
        });

        let issues = validate_config(&config);

        assert_eq!(issues.len(), 1);
        assert!(issues[0]
            .message
            .contains("port must be a positive integer"));
    }

    #[test]
    fn test_config_cache_ttl_default() {
        let mut env_guard = ScopedEnv::new();
        env_guard.unset("CARAPACE_CONFIG_CACHE_MS");
        env_guard.unset("CARAPACE_DISABLE_CONFIG_CACHE");

        let ttl = get_cache_ttl();
        assert_eq!(ttl, Some(Duration::from_millis(200)));
    }

    #[test]
    fn test_config_cache_ttl_custom() {
        let mut env_guard = ScopedEnv::new();
        // Ensure disabled cache env var is not set
        env_guard.unset("CARAPACE_DISABLE_CONFIG_CACHE");
        env_guard.set("CARAPACE_CONFIG_CACHE_MS", "500");

        let ttl = get_cache_ttl();
        assert_eq!(ttl, Some(Duration::from_millis(500)));
    }

    #[test]
    fn test_config_cache_disabled() {
        let mut env_guard = ScopedEnv::new();
        env_guard.set("CARAPACE_DISABLE_CONFIG_CACHE", "1");

        let ttl = get_cache_ttl();
        assert!(ttl.is_none());
    }

    #[test]
    fn test_get_config_path_default() {
        let mut env_guard = ScopedEnv::new();
        env_guard.unset("CARAPACE_CONFIG_PATH");
        env_guard.unset("CARAPACE_STATE_DIR");

        let path = get_config_path();
        let expected_base = dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from(".config"))
            .join("carapace");

        assert_eq!(path.parent().unwrap(), expected_base.as_path());
        let ext = path.extension().unwrap().to_str().unwrap();
        assert!(ext == "json" || ext == "json5");
    }

    #[test]
    fn test_get_config_path_override() {
        let mut env_guard = ScopedEnv::new();
        env_guard.unset("CARAPACE_STATE_DIR");
        env_guard.set("CARAPACE_CONFIG_PATH", "/custom/path/config.json");

        let path = get_config_path();
        assert_eq!(path, PathBuf::from("/custom/path/config.json"));
    }

    #[test]
    fn test_get_config_path_state_dir() {
        let mut env_guard = ScopedEnv::new();
        env_guard.unset("CARAPACE_CONFIG_PATH");
        env_guard.set("CARAPACE_STATE_DIR", "/custom/state");

        let path = get_config_path();
        // Falls back to .json when .json5 doesn't exist on disk
        assert_eq!(path, PathBuf::from("/custom/state/carapace.json"));
    }

    #[test]
    fn test_env_substitution_in_nested_config() {
        let mut env_guard = ScopedEnv::new();
        env_guard.set("TEST_OPENAI_KEY", "sk-test-key");

        let dir = TempDir::new().unwrap();
        let main_path = create_temp_config(
            &dir,
            "config.json5",
            r#"{
                "models": {
                    "providers": {
                        "openai": { "apiKey": "${TEST_OPENAI_KEY}" }
                    }
                }
            }"#,
        );

        let config = load_config_uncached(&main_path).unwrap();

        assert_eq!(
            config["models"]["providers"]["openai"]["apiKey"],
            "sk-test-key"
        );
    }

    #[test]
    fn test_secret_encryption_round_trip() {
        let mut env_guard = ScopedEnv::new();
        env_guard.set("CARAPACE_CONFIG_PASSWORD", "test-password");

        let dir = TempDir::new().unwrap();
        let main_path = create_temp_config(
            &dir,
            "config.json5",
            r#"{
                "anthropic": { "apiKey": "sk-test" },
                "gateway": { "auth": { "token": "token123" } }
            }"#,
        );

        let mut config = load_config_uncached(&main_path).unwrap();
        assert_eq!(config["anthropic"]["apiKey"], "sk-test");
        assert_eq!(config["gateway"]["auth"]["token"], "token123");

        seal_config_secrets(&mut config).unwrap();
        let sealed = config["anthropic"]["apiKey"].as_str().unwrap();
        assert!(secrets::is_encrypted(sealed));

        let content = serde_json::to_string_pretty(&config).unwrap();
        let mut file = File::create(&main_path).unwrap();
        file.write_all(content.as_bytes()).unwrap();

        let reloaded = load_config_uncached(&main_path).unwrap();
        assert_eq!(reloaded["anthropic"]["apiKey"], "sk-test");
        assert_eq!(reloaded["gateway"]["auth"]["token"], "token123");
    }

    #[test]
    fn test_load_config_rejects_unsupported_encrypted_secret_prefix() {
        let dir = TempDir::new().unwrap();
        let main_path = create_temp_config(
            &dir,
            "config.json5",
            r#"{
                "anthropic": { "apiKey": "enc:v1:aaa:bbb:ccc" }
            }"#,
        );

        let result = load_config_uncached(&main_path);
        assert!(matches!(
            result,
            Err(ConfigError::ValidationError { path, message })
                if path == ".anthropic.apiKey"
                    && message.contains("unsupported encrypted config secret envelope enc:v1")
                    && message.contains("enc:v2")
        ));
    }

    #[test]
    fn test_load_config_reports_all_unsupported_encrypted_secret_prefixes() {
        let dir = TempDir::new().unwrap();
        let main_path = create_temp_config(
            &dir,
            "config.json5",
            r#"{
                "anthropic": { "apiKey": "enc:v1:aaa:bbb:ccc" },
                "openai": { "apiKey": "enc:v3:ddd:eee:fff" }
            }"#,
        );

        let result = load_config_uncached(&main_path);
        assert!(matches!(
            result,
            Err(ConfigError::ValidationError { path, message })
                if path == "."
                    && message.contains("enc:v1 at .anthropic.apiKey")
                    && message.contains("enc:v3 at .openai.apiKey")
                    && message.contains("enc:v2")
        ));
    }

    #[test]
    fn test_load_config_rejects_unsupported_encrypted_secret_prefix_with_password() {
        let mut env_guard = ScopedEnv::new();
        env_guard.set("CARAPACE_CONFIG_PASSWORD", "test-password");

        let dir = TempDir::new().unwrap();
        let main_path = create_temp_config(
            &dir,
            "config.json5",
            r#"{
                "anthropic": { "apiKey": "enc:v1:aaa:bbb:ccc" }
            }"#,
        );

        let result = load_config_uncached(&main_path);
        assert!(matches!(
            result,
            Err(ConfigError::ValidationError { path, message })
                if path == ".anthropic.apiKey"
                    && message.contains("unsupported encrypted config secret envelope enc:v1")
                    && message.contains("enc:v2")
        ));
    }

    #[test]
    fn test_resolve_config_secrets_allows_deep_plain_config() {
        let mut config = serde_json::json!("plain");
        for index in 0..70 {
            config = serde_json::json!({ format!("level{index}"): config });
        }

        resolve_config_secrets(&mut config)
            .expect("deep plain config should not fail encrypted-secret scanning");
    }

    #[test]
    fn test_resolve_config_secrets_rejects_deep_unsupported_encrypted_secret() {
        let mut config = serde_json::json!("enc:v1:aaa:bbb:ccc");
        for index in 0..70 {
            config = serde_json::json!({ format!("level{index}"): config });
        }

        let err = resolve_config_secrets(&mut config)
            .expect_err("deep unsupported encrypted secret should fail startup");

        assert!(matches!(err, ConfigError::ValidationError { path, message }
            if path.contains(".level")
                && message.contains("config secret scan exceeded maximum depth")));
    }

    #[test]
    fn test_include_depth_limit() {
        let dir = TempDir::new().unwrap();

        // Create a chain of includes that exceeds the limit
        for i in 0..12 {
            let next = if i < 11 {
                format!(r#"{{ "$include": "./{}.json5", "level": {} }}"#, i + 1, i)
            } else {
                format!(r#"{{ "level": {} }}"#, i)
            };
            create_temp_config(&dir, &format!("{}.json5", i), &next);
        }

        let main_path = dir.path().join("0.json5");
        let result = load_config_uncached(&main_path);

        assert!(matches!(
            result,
            Err(ConfigError::IncludeDepthExceeded { .. })
        ));
    }

    #[test]
    fn test_clear_cache() {
        // Just verify it doesn't panic
        clear_cache();
    }

    #[test]
    fn test_subscribe_config_changes_notified_on_update_cache() {
        clear_cache();
        let mut rx = subscribe_config_changes();
        let before = *rx.borrow_and_update();

        update_cache(serde_json::json!({}), serde_json::json!({}));

        assert!(rx.has_changed().unwrap());
        let after = *rx.borrow_and_update();
        assert!(after > before);
    }

    #[test]
    fn test_snapshot_then_restore_env_state_reverts_config_injected_var() {
        // Test-unique key so we don't fight other env-touching tests.
        const TEST_KEY: &str = "CARAPACE_TEST_ENV_RESTORE_VAR";
        let _env_state_guard = ScopedEnvStateForTest::new();
        let mut env_guard = ScopedEnv::new();
        env_guard.unset(TEST_KEY);

        {
            let mut state = lock_config_env_state_for_internal_state();
            apply_config_env_vars(
                &HashMap::from([(TEST_KEY.to_string(), "initial".to_string())]),
                &mut state,
            );
        }
        assert_eq!(read_process_env(TEST_KEY), Some("initial".to_string()));

        let snapshot = snapshot_env_state();

        {
            let mut state = lock_config_env_state_for_internal_state();
            apply_config_env_vars(
                &HashMap::from([(TEST_KEY.to_string(), "bad".to_string())]),
                &mut state,
            );
        }
        assert_eq!(read_process_env(TEST_KEY), Some("bad".to_string()));

        restore_env_state(&snapshot);
        assert_eq!(
            read_process_env(TEST_KEY),
            Some("initial".to_string()),
            "restore_env_state must put process env back to the snapshot value"
        );
    }

    #[test]
    fn test_raw_and_normalized_cache_share_one_file_snapshot() {
        clear_cache();
        let mut env_guard = ScopedEnv::new();
        env_guard
            .unset("CARAPACE_DISABLE_CONFIG_CACHE")
            .set("CARAPACE_CONFIG_CACHE_MS", "60000");

        let dir = TempDir::new().unwrap();
        let config_path = create_temp_config(
            &dir,
            "config.json5",
            r#"{
                "channels": {
                    "signal": {
                        "features": {
                            "typing": {
                                "enabled": true
                            }
                        }
                    }
                }
            }"#,
        );
        env_guard.set("CARAPACE_CONFIG_PATH", config_path.as_os_str());

        let normalized = load_config_shared().unwrap();
        assert_eq!(
            normalized["channels"]["signal"]["features"]["typing"]["enabled"],
            Value::Bool(true)
        );

        std::fs::write(
            &config_path,
            r#"{
                "channels": {
                    "signal": {
                        "features": {
                            "typing": {
                                "enabled": false
                            }
                        }
                    }
                }
            }"#,
        )
        .unwrap();

        let raw = load_raw_config_shared().unwrap();
        assert_eq!(
            raw["channels"]["signal"]["features"]["typing"]["enabled"],
            Value::Bool(true)
        );

        clear_cache();
    }

    #[test]
    fn test_load_config_pair_uncached_bypasses_stale_cache() {
        clear_cache();
        let mut env_guard = ScopedEnv::new();
        env_guard
            .unset("CARAPACE_DISABLE_CONFIG_CACHE")
            .set("CARAPACE_CONFIG_CACHE_MS", "60000");

        let dir = TempDir::new().unwrap();
        let config_path = create_temp_config(
            &dir,
            "config.json5",
            r#"{
                "channels": {
                    "signal": {
                        "features": {
                            "typing": {
                                "enabled": true
                            }
                        }
                    }
                }
            }"#,
        );
        env_guard.set("CARAPACE_CONFIG_PATH", config_path.as_os_str());

        let _stale = load_config_shared().unwrap();

        std::fs::write(
            &config_path,
            r#"{
                "channels": {
                    "signal": {
                        "features": {
                            "typing": {
                                "enabled": false
                            }
                        }
                    }
                }
            }"#,
        )
        .unwrap();

        let (raw, normalized) = load_config_pair_uncached(&config_path).unwrap();
        assert_eq!(
            raw["channels"]["signal"]["features"]["typing"]["enabled"],
            Value::Bool(false)
        );
        assert_eq!(
            normalized["channels"]["signal"]["features"]["typing"]["enabled"],
            Value::Bool(false)
        );

        clear_cache();
    }

    #[test]
    fn test_nested_include_in_array() {
        let dir = TempDir::new().unwrap();

        create_temp_config(&dir, "item.json5", r#"{ "name": "item1" }"#);
        let main_path = create_temp_config(
            &dir,
            "main.json5",
            r#"{
                "items": [
                    { "$include": "./item.json5" }
                ]
            }"#,
        );

        let config = load_config_uncached(&main_path).unwrap();

        assert_eq!(config["items"][0]["name"], "item1");
    }

    #[test]
    fn test_include_env_vars_are_injected_before_substitution() {
        let mut env_guard = ScopedEnv::new();
        reset_config_env_state_for_test();
        env_guard.unset("TEST_INCLUDED_GATEWAY_TOKEN");
        env_guard.unset("TEST_INCLUDED_VERTEX_PROJECT_ID");

        let dir = TempDir::new().unwrap();
        create_temp_config(
            &dir,
            "vars.json5",
            r#"{
                "env": {
                    "vars": {
                        "TEST_INCLUDED_GATEWAY_TOKEN": "sometoken"
                    },
                    "TEST_INCLUDED_VERTEX_PROJECT_ID": "someproject"
                }
            }"#,
        );
        let main_path = create_temp_config(
            &dir,
            "main.json5",
            r#"{
                "$include": "./vars.json5",
                "gateway": {
                    "auth": {
                        "token": "${TEST_INCLUDED_GATEWAY_TOKEN}"
                    }
                },
                "vertex": {
                    "projectId": "${TEST_INCLUDED_VERTEX_PROJECT_ID}"
                }
            }"#,
        );

        let config = load_config_uncached(&main_path).unwrap();

        assert_eq!(config["gateway"]["auth"]["token"], "sometoken");
        assert_eq!(config["vertex"]["projectId"], "someproject");
        assert_eq!(
            read_process_env("TEST_INCLUDED_GATEWAY_TOKEN").unwrap(),
            "sometoken"
        );
        assert_eq!(
            read_process_env("TEST_INCLUDED_VERTEX_PROJECT_ID").unwrap(),
            "someproject"
        );

        env_guard.unset("TEST_INCLUDED_GATEWAY_TOKEN");
        env_guard.unset("TEST_INCLUDED_VERTEX_PROJECT_ID");
        reset_config_env_state_for_test();
    }

    #[test]
    fn test_nested_env_include_injects_before_substitution() {
        let mut env_guard = ScopedEnv::new();
        reset_config_env_state_for_test();
        env_guard.unset("TEST_NESTED_ENV_INCLUDE");

        let dir = TempDir::new().unwrap();
        create_temp_config(
            &dir,
            "env-vars.json5",
            r#"{
                "vars": {
                    "TEST_NESTED_ENV_INCLUDE": "nested-token"
                }
            }"#,
        );
        let main_path = create_temp_config(
            &dir,
            "main.json5",
            r#"{
                "env": {
                    "$include": "./env-vars.json5",
                    "shellEnv": {
                        "PATH": ["/tmp/example"]
                    }
                },
                "gateway": {
                    "auth": {
                        "token": "${TEST_NESTED_ENV_INCLUDE}"
                    }
                }
            }"#,
        );

        let config = load_config_uncached(&main_path).unwrap();

        assert_eq!(config["gateway"]["auth"]["token"], "nested-token");
        assert_eq!(
            read_process_env("TEST_NESTED_ENV_INCLUDE").unwrap(),
            "nested-token"
        );

        env_guard.unset("TEST_NESTED_ENV_INCLUDE");
        reset_config_env_state_for_test();
    }

    fn assert_loader_control_env_var_is_rejected(config_content: &str, expected_path: &str) {
        // Hold the global env lock while reset_config_env_state_for_test()
        // restores any previously injected config env vars.
        let _env_guard = ScopedEnv::new();
        reset_config_env_state_for_test();

        let dir = TempDir::new().unwrap();
        let main_path = create_temp_config(&dir, "config.json5", config_content);

        let result = load_config_uncached(&main_path);
        assert!(matches!(
            result,
            Err(ConfigError::ValidationError { path, .. }) if path == expected_path
        ));
    }

    #[test]
    fn test_loader_control_env_var_in_env_vars_is_rejected() {
        assert_loader_control_env_var_is_rejected(
            r#"{
                "env": {
                    "vars": {
                        "CARAPACE_CONFIG_PATH": "/tmp/redirected.json5"
                    }
                }
            }"#,
            ".env.vars.CARAPACE_CONFIG_PATH",
        );
    }

    #[test]
    fn test_loader_control_env_var_as_direct_env_field_is_rejected() {
        assert_loader_control_env_var_is_rejected(
            r#"{
                "env": {
                    "CARAPACE_STATE_DIR": "/tmp/redirected-state"
                }
            }"#,
            ".env.CARAPACE_STATE_DIR",
        );
    }

    #[test]
    fn test_loader_control_env_var_case_variant_is_rejected() {
        assert_loader_control_env_var_is_rejected(
            r#"{
                "env": {
                    "vars": {
                        "carapace_config_path": "/tmp/redirected.json5"
                    }
                }
            }"#,
            ".env.vars.carapace_config_path",
        );
    }

    #[test]
    fn test_env_vars_and_string_fields_both_inject() {
        let mut env_guard = ScopedEnv::new();
        reset_config_env_state_for_test();
        env_guard.unset("TEST_API_KEY_FROM_ENV_BLOCK");
        env_guard.unset("TEST_OTHER_FLAG");

        let dir = TempDir::new().unwrap();
        let main_path = create_temp_config(
            &dir,
            "config.json5",
            r#"{
                "env": {
                    "vars": {
                        "TEST_API_KEY_FROM_ENV_BLOCK": "sk-test-from-env-block"
                    },
                    "TEST_OTHER_FLAG": "enabled"
                },
                "openai": {
                    "apiKey": "${TEST_API_KEY_FROM_ENV_BLOCK}"
                },
                "meta": {
                    "lastVersion": "${TEST_OTHER_FLAG}"
                }
            }"#,
        );

        let config = load_config_uncached(&main_path).unwrap();

        assert_eq!(config["openai"]["apiKey"], "sk-test-from-env-block");
        assert_eq!(config["meta"]["lastVersion"], "enabled");
        assert_eq!(
            read_process_env("TEST_API_KEY_FROM_ENV_BLOCK").unwrap(),
            "sk-test-from-env-block"
        );
        assert_eq!(read_process_env("TEST_OTHER_FLAG").unwrap(), "enabled");

        env_guard.unset("TEST_API_KEY_FROM_ENV_BLOCK");
        env_guard.unset("TEST_OTHER_FLAG");
        reset_config_env_state_for_test();
    }

    #[test]
    fn test_read_config_env_serializes_active_and_external_values() {
        let mut env_guard = ScopedEnv::new();
        let _env_state_guard = ScopedEnvStateForTest::new();
        env_guard.set("TEST_SERIALIZED_CONFIG_ENV", "external-value");

        assert_eq!(
            read_config_env("TEST_SERIALIZED_CONFIG_ENV").as_deref(),
            Some("external-value")
        );

        let dir = TempDir::new().unwrap();
        let main_path = create_temp_config(
            &dir,
            "config.json5",
            r#"{
                "env": {
                    "vars": {
                        "TEST_SERIALIZED_CONFIG_ENV": "config-value"
                    }
                }
            }"#,
        );

        load_config_uncached(&main_path).unwrap();
        assert_eq!(
            read_config_env("TEST_SERIALIZED_CONFIG_ENV").as_deref(),
            Some("config-value")
        );

        reset_config_env_state_for_test();
        assert_eq!(
            read_config_env("TEST_SERIALIZED_CONFIG_ENV").as_deref(),
            Some("external-value")
        );

        env_guard.unset("TEST_SERIALIZED_CONFIG_ENV");
    }

    #[test]
    fn test_read_config_env_os_many_returns_consistent_snapshot() {
        let mut env_guard = ScopedEnv::new();
        let _env_state_guard = ScopedEnvStateForTest::new();
        env_guard.set("TEST_CONFIG_ENV_MANY_EXTERNAL", "external-value");
        env_guard.set("TEST_CONFIG_ENV_MANY_SHADOWED", "external-shadow");
        env_guard.unset("TEST_CONFIG_ENV_MANY_MISSING");
        apply_config_env_for_test(HashMap::from([(
            "TEST_CONFIG_ENV_MANY_SHADOWED".to_string(),
            "config-shadow".to_string(),
        )]));

        let values = read_config_env_os_many([
            "TEST_CONFIG_ENV_MANY_SHADOWED",
            "TEST_CONFIG_ENV_MANY_EXTERNAL",
            "TEST_CONFIG_ENV_MANY_MISSING",
        ]);

        assert_eq!(
            values,
            vec![
                (
                    OsString::from("TEST_CONFIG_ENV_MANY_SHADOWED"),
                    OsString::from("config-shadow"),
                ),
                (
                    OsString::from("TEST_CONFIG_ENV_MANY_EXTERNAL"),
                    OsString::from("external-value"),
                ),
            ]
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_read_config_env_rejects_non_utf8_process_value() {
        use std::os::unix::ffi::OsStringExt;

        let mut env_guard = ScopedEnv::new();
        let _env_state_guard = ScopedEnvStateForTest::new();
        env_guard.set(
            "TEST_NON_UTF8_CONFIG_ENV",
            OsString::from_vec(vec![b'o', 0xff]),
        );

        assert_eq!(read_config_env("TEST_NON_UTF8_CONFIG_ENV"), None);
        assert!(read_config_env_os("TEST_NON_UTF8_CONFIG_ENV").is_some());
    }

    #[test]
    fn test_config_env_values_can_reference_other_config_env_values() {
        let mut env_guard = ScopedEnv::new();
        reset_config_env_state_for_test();
        env_guard.unset("TEST_BASE_TOKEN");
        env_guard.unset("TEST_COMPOSED_TOKEN");

        let dir = TempDir::new().unwrap();
        let main_path = create_temp_config(
            &dir,
            "config.json5",
            r#"{
                "env": {
                    "vars": {
                        "TEST_BASE_TOKEN": "base-token",
                        "TEST_COMPOSED_TOKEN": "${TEST_BASE_TOKEN}-suffix"
                    }
                },
                "gateway": {
                    "auth": {
                        "token": "${TEST_COMPOSED_TOKEN}"
                    }
                }
            }"#,
        );

        let config = load_config_uncached(&main_path).unwrap();

        assert_eq!(config["gateway"]["auth"]["token"], "base-token-suffix");
        assert_eq!(
            read_process_env("TEST_COMPOSED_TOKEN").unwrap(),
            "base-token-suffix"
        );

        env_guard.unset("TEST_BASE_TOKEN");
        env_guard.unset("TEST_COMPOSED_TOKEN");
        reset_config_env_state_for_test();
    }

    #[test]
    fn test_removed_config_env_vars_restore_previous_environment() {
        let mut env_guard = ScopedEnv::new();
        reset_config_env_state_for_test();
        env_guard.set("TEST_RELOAD_ENV", "preexisting");

        let dir = TempDir::new().unwrap();
        let first_path = create_temp_config(
            &dir,
            "first.json5",
            r#"{
                "env": {
                    "vars": {
                        "TEST_RELOAD_ENV": "from-config"
                    }
                },
                "meta": {
                    "lastVersion": "${TEST_RELOAD_ENV}"
                }
            }"#,
        );
        let second_path = create_temp_config(
            &dir,
            "second.json5",
            r#"{
                "meta": {
                    "lastVersion": "${TEST_RELOAD_ENV}"
                }
            }"#,
        );

        let first = load_config_uncached(&first_path).unwrap();
        assert_eq!(first["meta"]["lastVersion"], "from-config");
        assert_eq!(read_process_env("TEST_RELOAD_ENV").unwrap(), "from-config");

        let second = load_config_uncached(&second_path).unwrap();
        assert_eq!(second["meta"]["lastVersion"], "preexisting");
        assert_eq!(read_process_env("TEST_RELOAD_ENV").unwrap(), "preexisting");

        env_guard.unset("TEST_RELOAD_ENV");
        reset_config_env_state_for_test();
    }

    #[test]
    fn test_failed_substitution_restores_previous_environment() {
        let mut env_guard = ScopedEnv::new();
        reset_config_env_state_for_test();
        env_guard.set("TEST_FAILED_SUBSTITUTION_ENV", "preexisting");
        env_guard.unset("TEST_MISSING_AFTER_INJECTION");

        let dir = TempDir::new().unwrap();
        let broken_path = create_temp_config(
            &dir,
            "broken.json5",
            r#"{
                "env": {
                    "vars": {
                        "TEST_FAILED_SUBSTITUTION_ENV": "from-config"
                    }
                },
                "meta": {
                    "lastVersion": "${TEST_MISSING_AFTER_INJECTION}"
                }
            }"#,
        );

        let result = load_config_uncached(&broken_path);
        assert!(matches!(
            result,
            Err(ConfigError::MissingEnvVar { var }) if var == "TEST_MISSING_AFTER_INJECTION"
        ));
        assert_eq!(
            read_process_env("TEST_FAILED_SUBSTITUTION_ENV").unwrap(),
            "preexisting"
        );

        env_guard.unset("TEST_FAILED_SUBSTITUTION_ENV");
        reset_config_env_state_for_test();
    }

    #[test]
    fn test_failed_reload_restores_previous_injected_environment() {
        let mut env_guard = ScopedEnv::new();
        reset_config_env_state_for_test();
        env_guard.unset("TEST_RELOAD_ROLLBACK_ENV");
        env_guard.unset("TEST_RELOAD_ROLLBACK_MISSING");

        let dir = TempDir::new().unwrap();
        let working_path = create_temp_config(
            &dir,
            "working.json5",
            r#"{
                "env": {
                    "vars": {
                        "TEST_RELOAD_ROLLBACK_ENV": "from-first-load"
                    }
                },
                "meta": {
                    "lastVersion": "${TEST_RELOAD_ROLLBACK_ENV}"
                }
            }"#,
        );
        let broken_path = create_temp_config(
            &dir,
            "broken.json5",
            r#"{
                "env": {
                    "vars": {
                        "TEST_RELOAD_ROLLBACK_ENV": "from-broken-load"
                    }
                },
                "meta": {
                    "lastVersion": "${TEST_RELOAD_ROLLBACK_MISSING}"
                }
            }"#,
        );

        let first = load_config_uncached(&working_path).unwrap();
        assert_eq!(first["meta"]["lastVersion"], "from-first-load");
        assert_eq!(
            read_process_env("TEST_RELOAD_ROLLBACK_ENV").unwrap(),
            "from-first-load"
        );

        let result = load_config_uncached(&broken_path);
        assert!(matches!(
            result,
            Err(ConfigError::MissingEnvVar { var }) if var == "TEST_RELOAD_ROLLBACK_MISSING"
        ));
        assert_eq!(
            read_process_env("TEST_RELOAD_ROLLBACK_ENV").unwrap(),
            "from-first-load"
        );

        env_guard.unset("TEST_RELOAD_ROLLBACK_ENV");
        reset_config_env_state_for_test();
    }

    #[test]
    fn test_removed_injected_env_does_not_resolve_new_references() {
        let mut env_guard = ScopedEnv::new();
        reset_config_env_state_for_test();
        env_guard.unset("TEST_STALE_CONFIG_ENV");
        env_guard.unset("TEST_STALE_CONFIG_COMBINED");

        let dir = TempDir::new().unwrap();
        let first_path = create_temp_config(
            &dir,
            "first.json5",
            r#"{
                "env": {
                    "vars": {
                        "TEST_STALE_CONFIG_ENV": "first-token"
                    }
                },
                "meta": {
                    "lastVersion": "${TEST_STALE_CONFIG_ENV}"
                }
            }"#,
        );
        let second_path = create_temp_config(
            &dir,
            "second.json5",
            r#"{
                "env": {
                    "vars": {
                        "TEST_STALE_CONFIG_COMBINED": "${TEST_STALE_CONFIG_ENV}-suffix"
                    }
                }
            }"#,
        );

        let first = load_config_uncached(&first_path).unwrap();
        assert_eq!(first["meta"]["lastVersion"], "first-token");
        assert_eq!(
            read_process_env("TEST_STALE_CONFIG_ENV").unwrap(),
            "first-token"
        );

        let second = load_config_uncached(&second_path);
        assert!(matches!(
            second,
            Err(ConfigError::MissingEnvVar { var }) if var == "TEST_STALE_CONFIG_ENV"
        ));

        env_guard.unset("TEST_STALE_CONFIG_ENV");
        env_guard.unset("TEST_STALE_CONFIG_COMBINED");
        reset_config_env_state_for_test();
    }

    #[test]
    fn test_config_env_with_nul_byte_is_rejected() {
        // Hold the global env lock while reset_config_env_state_for_test()
        // restores any previously injected config env vars.
        let _env_guard = ScopedEnv::new();
        reset_config_env_state_for_test();

        let dir = TempDir::new().unwrap();
        let main_path = create_temp_config(
            &dir,
            "config.json5",
            "{\n  env: {\n    vars: {\n      TEST_BAD_VALUE: \"bad\\0value\"\n    }\n  }\n}",
        );

        let result = load_config_uncached(&main_path);
        assert!(matches!(
            result,
            Err(ConfigError::ValidationError { path, message })
            if path == ".env.vars.TEST_BAD_VALUE" && message.contains("NUL bytes")
        ));

        reset_config_env_state_for_test();
    }

    #[test]
    fn test_missing_config_clears_previous_injected_environment() {
        let mut env_guard = ScopedEnv::new();
        reset_config_env_state_for_test();
        env_guard.unset("TEST_MISSING_CONFIG_ENV");

        let dir = TempDir::new().unwrap();
        let working_path = create_temp_config(
            &dir,
            "working.json5",
            r#"{
                "env": {
                    "vars": {
                        "TEST_MISSING_CONFIG_ENV": "from-config"
                    }
                },
                "meta": {
                    "lastVersion": "${TEST_MISSING_CONFIG_ENV}"
                }
            }"#,
        );

        let working = load_config_uncached(&working_path).unwrap();
        assert_eq!(working["meta"]["lastVersion"], "from-config");
        assert_eq!(
            read_process_env("TEST_MISSING_CONFIG_ENV").unwrap(),
            "from-config"
        );

        let missing_path = dir.path().join("deleted.json5");
        let missing = load_config_uncached(&missing_path).unwrap();
        assert!(missing.is_object());
        assert!(read_process_env("TEST_MISSING_CONFIG_ENV").is_none());

        reset_config_env_state_for_test();
    }
}
