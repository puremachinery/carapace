//! Configuration parsing module
//!
//! Handles JSON5 configuration with includes, environment variable substitution,
//! and caching. Matches moltbot's format for drop-in compatibility.

pub mod defaults;
pub mod secrets;
pub mod watcher;

use parking_lot::RwLock;
use regex::Regex;
use serde_json::Value;
use std::collections::HashSet;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;
use std::time::{Duration, Instant};
use thiserror::Error;

/// Maximum depth for $include directives to prevent infinite recursion
const MAX_INCLUDE_DEPTH: usize = 10;

/// Default config cache TTL in milliseconds
const DEFAULT_CACHE_TTL_MS: u64 = 200;

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
    value: Value,
    loaded_at: Instant,
}

/// Global config cache
static CONFIG_CACHE: LazyLock<RwLock<Option<CachedConfig>>> = LazyLock::new(|| RwLock::new(None));

/// Get the config file path.
/// Priority: MOLTBOT_CONFIG_PATH > MOLTBOT_STATE_DIR/moltbot.json5 > ~/.moltbot/moltbot.json5
/// Falls back to .json extension if the .json5 file doesn't exist.
pub fn get_config_path() -> PathBuf {
    if let Ok(path) = env::var("MOLTBOT_CONFIG_PATH") {
        return PathBuf::from(path);
    }

    if let Ok(state_dir) = env::var("MOLTBOT_STATE_DIR") {
        let dir = PathBuf::from(state_dir);
        let json5 = dir.join("moltbot.json5");
        if json5.exists() {
            return json5;
        }
        return dir.join("moltbot.json");
    }

    let base = dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".moltbot");
    let json5 = base.join("moltbot.json5");
    if json5.exists() {
        return json5;
    }
    base.join("moltbot.json")
}

/// Get the cache TTL duration
fn get_cache_ttl() -> Option<Duration> {
    // Check if caching is disabled
    if env::var("MOLTBOT_DISABLE_CONFIG_CACHE").is_ok() {
        return None;
    }

    let ms = env::var("MOLTBOT_CONFIG_CACHE_MS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(DEFAULT_CACHE_TTL_MS);

    Some(Duration::from_millis(ms))
}

/// Load and parse the configuration file with caching.
/// Returns empty object `{}` if file doesn't exist.
///
/// The returned value has all config defaults applied so that missing
/// sections/fields have production-ready values.
pub fn load_config() -> Result<Value, ConfigError> {
    let path = get_config_path();

    // Check cache first
    if let Some(ttl) = get_cache_ttl() {
        let cache = CONFIG_CACHE.read();
        if let Some(cached) = cache.as_ref() {
            if cached.loaded_at.elapsed() < ttl {
                return Ok(cached.value.clone());
            }
        }
    }

    // Load fresh config
    let config = load_config_uncached(&path)?;

    // Update cache if caching is enabled
    if get_cache_ttl().is_some() {
        let mut cache = CONFIG_CACHE.write();
        *cache = Some(CachedConfig {
            value: config.clone(),
            loaded_at: Instant::now(),
        });
    }

    Ok(config)
}

/// Load config without using the cache.
///
/// After parsing, include resolution, and env var substitution, this applies
/// config defaults so that missing sections/fields have sensible values.
pub fn load_config_uncached(path: &Path) -> Result<Value, ConfigError> {
    // Return empty object with defaults if file doesn't exist
    if !path.exists() {
        let mut empty = Value::Object(serde_json::Map::new());
        defaults::apply_defaults(&mut empty);
        return Ok(empty);
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

    // Apply environment variable substitution
    substitute_env_vars(&mut value)?;

    // Apply config defaults (fill in missing sections/fields with
    // production-ready values — mirrors clawdbot's apply* pipeline).
    defaults::apply_defaults(&mut value);

    Ok(value)
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
fn substitute_env_in_string(s: &str) -> Result<String, ConfigError> {
    // Regex pattern for env vars: ${VAR} where VAR is uppercase with underscores and digits
    static ENV_VAR_PATTERN: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"\$\$?\{([A-Z_][A-Z0-9_]*)\}").unwrap());

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
            let value = env::var(var_name).map_err(|_| ConfigError::MissingEnvVar {
                var: var_name.to_string(),
            })?;
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
}

/// Atomically update the config cache with a pre-validated config value.
///
/// This is used by the config watcher and reload mechanism to install a new
/// config without going through file I/O again (the caller has already parsed
/// and validated the new config).
pub fn update_cache(value: Value) {
    let mut cache = CONFIG_CACHE.write();
    *cache = Some(CachedConfig {
        value,
        loaded_at: Instant::now(),
    });
}

/// Reload the config from disk, validate it, and update the cache atomically.
///
/// Returns the new config on success or a `ConfigError` if the file cannot be
/// read or parsed. Validation warnings are returned alongside the config; only
/// hard parse/read errors cause an `Err`.
pub fn reload_config() -> Result<(Value, Vec<ValidationIssue>), ConfigError> {
    let path = get_config_path();
    let new_config = load_config_uncached(&path)?;
    let issues = validate_config(&new_config);
    // Update the cache with the freshly loaded config
    update_cache(new_config.clone());
    Ok((new_config, issues))
}

/// Validation error with path context
#[derive(Debug)]
pub struct ValidationIssue {
    pub path: String,
    pub message: String,
}

/// Validate a config value against basic structural expectations.
/// Returns a list of validation issues (empty if valid).
pub fn validate_config(config: &Value) -> Vec<ValidationIssue> {
    let mut issues = Vec::new();

    if let Value::Object(obj) = config {
        // Check for unknown top-level keys
        let known_keys = [
            "meta",
            "env",
            "wizard",
            "diagnostics",
            "logging",
            "update",
            "browser",
            "ui",
            "auth",
            "models",
            "nodeHost",
            "agents",
            "tools",
            "bindings",
            "broadcast",
            "audio",
            "media",
            "messages",
            "commands",
            "approvals",
            "session",
            "cron",
            "hooks",
            "web",
            "channels",
            "discovery",
            "canvasHost",
            "talk",
            "gateway",
            "skills",
            "plugins",
            "anthropic",
            "sessions",
            "openai",
            "google",
            "providers",
        ];

        for key in obj.keys() {
            if !known_keys.contains(&key.as_str()) {
                issues.push(ValidationIssue {
                    path: format!(".{}", key),
                    message: format!("Unknown configuration key: {}", key),
                });
            }
        }

        // Validate gateway section if present
        if let Some(Value::Object(gateway)) = obj.get("gateway") {
            if let Some(port) = gateway.get("port") {
                if !port.is_number() {
                    issues.push(ValidationIssue {
                        path: ".gateway.port".to_string(),
                        message: "port must be a number".to_string(),
                    });
                }
            }
        }

        // Validate hooks section if present
        if let Some(Value::Object(hooks)) = obj.get("hooks") {
            if let Some(max_bytes) = hooks.get("maxBodyBytes") {
                if !max_bytes.is_number() {
                    issues.push(ValidationIssue {
                        path: ".hooks.maxBodyBytes".to_string(),
                        message: "maxBodyBytes must be a number".to_string(),
                    });
                }
            }
        }
    } else if !config.is_object() {
        issues.push(ValidationIssue {
            path: ".".to_string(),
            message: "Config root must be an object".to_string(),
        });
    }

    issues
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;
    use std::sync::Mutex;
    use tempfile::TempDir;

    /// Mutex to serialize tests that modify environment variables
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    /// Helper to create a temp config file
    fn create_temp_config(dir: &TempDir, name: &str, content: &str) -> PathBuf {
        let path = dir.path().join(name);
        let mut file = File::create(&path).unwrap();
        file.write_all(content.as_bytes()).unwrap();
        path
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
        let _lock = ENV_LOCK.lock().unwrap();
        env::set_var("TEST_VAR_ONE", "hello");
        env::set_var("TEST_VAR_TWO", "world");

        let result = substitute_env_in_string("${TEST_VAR_ONE} ${TEST_VAR_TWO}!").unwrap();
        assert_eq!(result, "hello world!");

        env::remove_var("TEST_VAR_ONE");
        env::remove_var("TEST_VAR_TWO");
    }

    #[test]
    fn test_env_var_escaped() {
        let result = substitute_env_in_string("$${ESCAPED_VAR}").unwrap();
        assert_eq!(result, "${ESCAPED_VAR}");
    }

    #[test]
    fn test_env_var_missing() {
        let _lock = ENV_LOCK.lock().unwrap();
        env::remove_var("NONEXISTENT_VAR_12345");
        let result = substitute_env_in_string("${NONEXISTENT_VAR_12345}");

        assert!(
            matches!(result, Err(ConfigError::MissingEnvVar { var }) if var == "NONEXISTENT_VAR_12345")
        );
    }

    #[test]
    fn test_env_var_partial_string() {
        let _lock = ENV_LOCK.lock().unwrap();
        env::set_var("TEST_API_KEY", "sk-secret");

        let result = substitute_env_in_string("Bearer ${TEST_API_KEY}").unwrap();
        assert_eq!(result, "Bearer sk-secret");

        env::remove_var("TEST_API_KEY");
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
            "gateway": { "port": 18789 },
            "hooks": { "enabled": true },
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
        assert!(issues[0].message.contains("port must be a number"));
    }

    #[test]
    fn test_config_cache_ttl_default() {
        let _lock = ENV_LOCK.lock().unwrap();
        env::remove_var("MOLTBOT_CONFIG_CACHE_MS");
        env::remove_var("MOLTBOT_DISABLE_CONFIG_CACHE");

        let ttl = get_cache_ttl();
        assert_eq!(ttl, Some(Duration::from_millis(200)));
    }

    #[test]
    fn test_config_cache_ttl_custom() {
        let _lock = ENV_LOCK.lock().unwrap();
        // Ensure disabled cache env var is not set
        env::remove_var("MOLTBOT_DISABLE_CONFIG_CACHE");
        env::set_var("MOLTBOT_CONFIG_CACHE_MS", "500");

        let ttl = get_cache_ttl();
        assert_eq!(ttl, Some(Duration::from_millis(500)));

        env::remove_var("MOLTBOT_CONFIG_CACHE_MS");
    }

    #[test]
    fn test_config_cache_disabled() {
        let _lock = ENV_LOCK.lock().unwrap();
        env::set_var("MOLTBOT_DISABLE_CONFIG_CACHE", "1");

        let ttl = get_cache_ttl();
        assert!(ttl.is_none());

        env::remove_var("MOLTBOT_DISABLE_CONFIG_CACHE");
    }

    #[test]
    fn test_get_config_path_default() {
        let _lock = ENV_LOCK.lock().unwrap();
        env::remove_var("MOLTBOT_CONFIG_PATH");
        env::remove_var("MOLTBOT_STATE_DIR");

        let path = get_config_path();
        // Falls back to .json when .json5 doesn't exist on disk
        assert!(path.ends_with(".moltbot/moltbot.json"));
    }

    #[test]
    fn test_get_config_path_override() {
        let _lock = ENV_LOCK.lock().unwrap();
        env::remove_var("MOLTBOT_STATE_DIR");
        env::set_var("MOLTBOT_CONFIG_PATH", "/custom/path/config.json");

        let path = get_config_path();
        assert_eq!(path, PathBuf::from("/custom/path/config.json"));

        env::remove_var("MOLTBOT_CONFIG_PATH");
    }

    #[test]
    fn test_get_config_path_state_dir() {
        let _lock = ENV_LOCK.lock().unwrap();
        env::remove_var("MOLTBOT_CONFIG_PATH");
        env::set_var("MOLTBOT_STATE_DIR", "/custom/state");

        let path = get_config_path();
        // Falls back to .json when .json5 doesn't exist on disk
        assert_eq!(path, PathBuf::from("/custom/state/moltbot.json"));

        env::remove_var("MOLTBOT_STATE_DIR");
    }

    #[test]
    fn test_env_substitution_in_nested_config() {
        let _lock = ENV_LOCK.lock().unwrap();
        env::set_var("TEST_OPENAI_KEY", "sk-test-key");

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

        env::remove_var("TEST_OPENAI_KEY");
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
}
