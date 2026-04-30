//! Configuration parsing module
//!
//! Handles JSON5 configuration with includes, environment variable substitution,
//! and caching.

pub mod defaults;
pub mod routes;
pub mod schema;
pub mod secrets;
pub mod watcher;

use parking_lot::{Mutex, RwLock};
use regex::Regex;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::env;
use std::ffi::OsString;
use std::fs;
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

/// Snapshot of the currently-injected config env state, opaque to callers.
pub(crate) fn snapshot_env_state() -> InjectedConfigEnvState {
    CONFIG_ENV_STATE.lock().clone()
}

/// Restore process env to the state captured by [`snapshot_env_state`].
pub(crate) fn restore_env_state(snapshot: &InjectedConfigEnvState) {
    let mut current = CONFIG_ENV_STATE.lock();
    restore_config_env_state(snapshot, &mut current);
}

#[cfg(test)]
pub(crate) fn apply_config_env_for_test(vars: HashMap<String, String>) {
    let mut state = CONFIG_ENV_STATE.lock();
    apply_config_env_vars(&vars, &mut state);
}

#[cfg(test)]
fn reset_config_env_state() {
    let mut state = CONFIG_ENV_STATE.lock();
    let empty = InjectedConfigEnvState::default();
    restore_config_env_state(&empty, &mut state);
}

/// RAII guard that empties `CONFIG_ENV_STATE` on construction and drop, so
/// tests that mutate the global env tracker can't bleed into each other.
#[cfg(test)]
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

/// Get the config file path.
/// Priority: CARAPACE_CONFIG_PATH > CARAPACE_STATE_DIR/carapace.json5 > ~/.config/carapace/carapace.json5
/// Falls back to .json extension if the .json5 file doesn't exist.
pub fn get_config_path() -> PathBuf {
    if let Ok(path) = env::var("CARAPACE_CONFIG_PATH") {
        return PathBuf::from(path);
    }

    if let Ok(state_dir) = env::var("CARAPACE_STATE_DIR") {
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
    if env::var("CARAPACE_DISABLE_CONFIG_CACHE").is_ok() {
        return None;
    }

    let ms = env::var("CARAPACE_CONFIG_CACHE_MS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(DEFAULT_CACHE_TTL_MS);

    Some(Duration::from_millis(ms))
}

pub(crate) fn config_password() -> Option<Zeroizing<Vec<u8>>> {
    let password = env::var(CONFIG_PASSWORD_ENV).ok()?;
    if password.is_empty() {
        return None;
    }
    Some(Zeroizing::new(password.into_bytes()))
}

fn resolve_config_secrets(value: &mut Value) {
    let Some(password) = config_password() else {
        if secrets::contains_encrypted_values(value) {
            tracing::warn!(
                "{} is not set; encrypted config values will remain locked",
                CONFIG_PASSWORD_ENV
            );
            secrets::scrub_encrypted_values(value);
        }
        return;
    };
    let store = secrets::SecretStore::for_decrypt(password.as_ref());
    secrets::resolve_secrets(value, &store, password.as_ref());
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

/// Load a consistent `(raw, normalized)` pair from the same cache
/// generation. On the cache-hit path this is a single `CONFIG_CACHE` read
/// lock; on the cache-miss path both halves come from the same
/// `CachedConfig` produced by `load_cached_config_uncached`. The hot-reload
/// bridge relies on raw and normalized describing the same underlying
/// snapshot, never two different generations.
pub(crate) fn load_both_config_shared() -> Result<(Arc<Value>, Arc<Value>), ConfigError> {
    with_cached_config(|cached| (Arc::clone(&cached.raw_value), Arc::clone(&cached.value)))
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
        let mut env_state = CONFIG_ENV_STATE.lock();
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
    let mut env_state = CONFIG_ENV_STATE.lock();
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
    resolve_config_secrets(&mut value);

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

    env::var(key).map_err(|_| ConfigError::MissingEnvVar {
        var: key.to_string(),
    })
}

fn apply_config_env_vars(next: &HashMap<String, String>, state: &mut InjectedConfigEnvState) {
    let next_keys: HashSet<String> = next.keys().cloned().collect();

    for key in state.active_values.keys().cloned().collect::<Vec<_>>() {
        if next_keys.contains(&key) {
            continue;
        }

        match state.previous_values.remove(&key).flatten() {
            Some(previous) => env::set_var(&key, previous),
            None => env::remove_var(&key),
        }
        state.active_values.remove(&key);
    }

    for (key, value) in next {
        if state
            .active_values
            .get(key)
            .is_some_and(|current| current == value)
        {
            continue;
        }
        if !state.active_values.contains_key(key) {
            state.previous_values.insert(key.clone(), env::var_os(key));
        }
        env::set_var(key, value);
        state.active_values.insert(key.clone(), value.clone());
    }
}

fn restore_config_env_state(
    previous: &InjectedConfigEnvState,
    current: &mut InjectedConfigEnvState,
) {
    for key in current.active_values.keys().cloned().collect::<Vec<_>>() {
        if previous.active_values.contains_key(&key) {
            continue;
        }

        match current.previous_values.remove(&key).flatten() {
            Some(value) => env::set_var(&key, value),
            None => env::remove_var(&key),
        }
    }

    for (key, value) in &previous.active_values {
        env::set_var(key, value);
    }

    *current = previous.clone();
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
            *s = substitute_env_in_string(s)?;
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

/// Substitute environment variables in a single string
pub(crate) fn substitute_env_in_string(s: &str) -> Result<String, ConfigError> {
    substitute_env_in_string_with(s, |var_name| {
        env::var(var_name).map_err(|_| ConfigError::MissingEnvVar {
            var: var_name.to_string(),
        })
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

pub fn subscribe_config_changes() -> tokio::sync::watch::Receiver<u64> {
    CONFIG_CHANGE_TX.subscribe()
}

fn broadcast_config_change() {
    let next = CONFIG_CHANGE_TX.borrow().wrapping_add(1);
    let _ = CONFIG_CHANGE_TX.send(next);
}

/// Reload the config from disk, validate it, and update the cache atomically.
///
/// Returns the new config on success or a `ConfigError` if the file cannot be
/// read or parsed. Validation warnings are returned alongside the config; only
/// hard parse/read errors cause an `Err`.
pub fn reload_config() -> Result<(Value, Vec<ValidationIssue>), ConfigError> {
    let path = get_config_path();
    let cached = load_cached_config_uncached(&path)?;
    let new_config = cached.value.as_ref().clone();
    let issues = validate_config(&new_config);
    // Update the cache with the freshly loaded config
    update_cache(cached.raw_value.as_ref().clone(), new_config.clone());
    Ok((new_config, issues))
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
/// and converts results to the legacy [`ValidationIssue`] type.
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
        reset_config_env_state_for_test();
        std::env::remove_var(TEST_KEY);

        {
            let mut state = CONFIG_ENV_STATE.lock();
            apply_config_env_vars(
                &HashMap::from([(TEST_KEY.to_string(), "initial".to_string())]),
                &mut state,
            );
        }
        assert_eq!(std::env::var(TEST_KEY).ok(), Some("initial".to_string()));

        let snapshot = snapshot_env_state();

        {
            let mut state = CONFIG_ENV_STATE.lock();
            apply_config_env_vars(
                &HashMap::from([(TEST_KEY.to_string(), "bad".to_string())]),
                &mut state,
            );
        }
        assert_eq!(std::env::var(TEST_KEY).ok(), Some("bad".to_string()));

        restore_env_state(&snapshot);
        assert_eq!(
            std::env::var(TEST_KEY).ok(),
            Some("initial".to_string()),
            "restore_env_state must put process env back to the snapshot value"
        );

        reset_config_env_state_for_test();
        std::env::remove_var(TEST_KEY);
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
            normalized["session"]["typingMode"],
            Value::String("thinking".to_string())
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
            env::var("TEST_INCLUDED_GATEWAY_TOKEN").unwrap(),
            "sometoken"
        );
        assert_eq!(
            env::var("TEST_INCLUDED_VERTEX_PROJECT_ID").unwrap(),
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
        assert_eq!(env::var("TEST_NESTED_ENV_INCLUDE").unwrap(), "nested-token");

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
            env::var("TEST_API_KEY_FROM_ENV_BLOCK").unwrap(),
            "sk-test-from-env-block"
        );
        assert_eq!(env::var("TEST_OTHER_FLAG").unwrap(), "enabled");

        env_guard.unset("TEST_API_KEY_FROM_ENV_BLOCK");
        env_guard.unset("TEST_OTHER_FLAG");
        reset_config_env_state_for_test();
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
            env::var("TEST_COMPOSED_TOKEN").unwrap(),
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
        assert_eq!(env::var("TEST_RELOAD_ENV").unwrap(), "from-config");

        let second = load_config_uncached(&second_path).unwrap();
        assert_eq!(second["meta"]["lastVersion"], "preexisting");
        assert_eq!(env::var("TEST_RELOAD_ENV").unwrap(), "preexisting");

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
            env::var("TEST_FAILED_SUBSTITUTION_ENV").unwrap(),
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
            env::var("TEST_RELOAD_ROLLBACK_ENV").unwrap(),
            "from-first-load"
        );

        let result = load_config_uncached(&broken_path);
        assert!(matches!(
            result,
            Err(ConfigError::MissingEnvVar { var }) if var == "TEST_RELOAD_ROLLBACK_MISSING"
        ));
        assert_eq!(
            env::var("TEST_RELOAD_ROLLBACK_ENV").unwrap(),
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
        assert_eq!(env::var("TEST_STALE_CONFIG_ENV").unwrap(), "first-token");

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
        assert_eq!(env::var("TEST_MISSING_CONFIG_ENV").unwrap(), "from-config");

        let missing_path = dir.path().join("deleted.json5");
        let missing = load_config_uncached(&missing_path).unwrap();
        assert!(missing.is_object());
        assert!(env::var("TEST_MISSING_CONFIG_ENV").is_err());

        reset_config_env_state_for_test();
    }
}
