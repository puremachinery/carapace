//! Skills handlers.

use serde_json::{json, Value};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

use super::super::*;
use super::config::{map_validation_issues, read_config_snapshot, write_config_file};

/// WASM binary magic bytes: `\0asm`
const WASM_MAGIC: [u8; 4] = [0x00, 0x61, 0x73, 0x6D];

/// Maximum download size for a skill WASM binary (50 MB).
const MAX_SKILL_DOWNLOAD_BYTES: usize = 50 * 1024 * 1024;

/// Default HTTP timeout for skill downloads (60 seconds).
const SKILL_DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(60);

/// Name of the skills manifest file stored alongside WASM binaries.
const SKILLS_MANIFEST_FILE: &str = "skills-manifest.json";

fn ensure_object(value: &mut Value) -> &mut serde_json::Map<String, Value> {
    if !value.is_object() {
        *value = Value::Object(serde_json::Map::new());
    }
    value.as_object_mut().expect("value is object")
}

fn resolve_workspace_dir(cfg: &Value) -> PathBuf {
    if let Ok(dir) = env::var("MOLTBOT_WORKSPACE_DIR") {
        if !dir.trim().is_empty() {
            return PathBuf::from(dir);
        }
    }
    if let Some(workspace) = cfg
        .get("agents")
        .and_then(|v| v.get("defaults"))
        .and_then(|v| v.get("workspace"))
        .and_then(|v| v.as_str())
    {
        if !workspace.trim().is_empty() {
            return PathBuf::from(workspace);
        }
    }
    if let Some(list) = cfg
        .get("agents")
        .and_then(|v| v.get("list"))
        .and_then(|v| v.as_array())
    {
        for entry in list {
            if entry
                .get("default")
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
            {
                if let Some(workspace) = entry.get("workspace").and_then(|v| v.as_str()) {
                    if !workspace.trim().is_empty() {
                        return PathBuf::from(workspace);
                    }
                }
            }
        }
        if let Some(first) = list.first() {
            if let Some(workspace) = first.get("workspace").and_then(|v| v.as_str()) {
                if !workspace.trim().is_empty() {
                    return PathBuf::from(workspace);
                }
            }
        }
    }
    std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
}

/// Resolve the managed skills directory under the state dir.
fn resolve_skills_dir() -> PathBuf {
    resolve_state_dir().join("skills")
}

/// Validate that a skill name is safe: non-empty, ASCII alphanumeric plus hyphens and
/// underscores, no path separators, and reasonable length.
fn validate_skill_name(name: &str) -> Result<(), ErrorShape> {
    if name.is_empty() {
        return Err(error_shape(
            ERROR_INVALID_REQUEST,
            "skill name must not be empty",
            None,
        ));
    }
    if name.len() > 128 {
        return Err(error_shape(
            ERROR_INVALID_REQUEST,
            "skill name is too long (max 128 characters)",
            None,
        ));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(error_shape(
            ERROR_INVALID_REQUEST,
            "skill name may only contain ASCII alphanumeric characters, hyphens, and underscores",
            None,
        ));
    }
    Ok(())
}

/// Validate that a URL string is a well-formed HTTP or HTTPS URL.
fn validate_url(raw: &str) -> Result<url::Url, ErrorShape> {
    let parsed = url::Url::parse(raw)
        .map_err(|e| error_shape(ERROR_INVALID_REQUEST, &format!("invalid url: {}", e), None))?;
    match parsed.scheme() {
        "http" | "https" => Ok(parsed),
        other => Err(error_shape(
            ERROR_INVALID_REQUEST,
            &format!("unsupported url scheme '{}', must be http or https", other),
            None,
        )),
    }
}

/// Read the skills manifest JSON from the managed skills directory.
/// Returns an empty object if the file does not exist or cannot be parsed.
fn read_skills_manifest(skills_dir: &Path) -> Value {
    let manifest_path = skills_dir.join(SKILLS_MANIFEST_FILE);
    match std::fs::read_to_string(&manifest_path) {
        Ok(contents) => serde_json::from_str(&contents).unwrap_or_else(|_| json!({})),
        Err(_) => json!({}),
    }
}

/// Write the skills manifest JSON to the managed skills directory using atomic
/// tmp + rename.
fn write_skills_manifest(skills_dir: &Path, manifest: &Value) -> Result<(), ErrorShape> {
    std::fs::create_dir_all(skills_dir).map_err(|e| {
        error_shape(
            ERROR_UNAVAILABLE,
            &format!("failed to create skills directory: {}", e),
            None,
        )
    })?;

    let manifest_path = skills_dir.join(SKILLS_MANIFEST_FILE);
    let tmp_path = skills_dir.join(format!("{}.tmp", SKILLS_MANIFEST_FILE));

    let content = serde_json::to_string_pretty(manifest).map_err(|e| {
        error_shape(
            ERROR_UNAVAILABLE,
            &format!("failed to serialize manifest: {}", e),
            None,
        )
    })?;
    {
        let mut file = std::fs::File::create(&tmp_path).map_err(|e| {
            error_shape(
                ERROR_UNAVAILABLE,
                &format!("failed to write skills manifest: {}", e),
                None,
            )
        })?;
        file.write_all(content.as_bytes()).map_err(|e| {
            error_shape(
                ERROR_UNAVAILABLE,
                &format!("failed to write skills manifest: {}", e),
                None,
            )
        })?;
        file.write_all(b"\n").map_err(|e| {
            error_shape(
                ERROR_UNAVAILABLE,
                &format!("failed to write skills manifest: {}", e),
                None,
            )
        })?;
    }
    std::fs::rename(&tmp_path, &manifest_path).map_err(|e| {
        error_shape(
            ERROR_UNAVAILABLE,
            &format!("failed to replace skills manifest: {}", e),
            None,
        )
    })?;
    Ok(())
}

/// Download a WASM binary from the given URL and save it atomically to the skills
/// directory.  Returns the final file path on success.
fn download_skill_wasm(
    url: &url::Url,
    skills_dir: &Path,
    file_name: &str,
) -> Result<PathBuf, ErrorShape> {
    std::fs::create_dir_all(skills_dir).map_err(|e| {
        error_shape(
            ERROR_UNAVAILABLE,
            &format!("failed to create skills directory: {}", e),
            None,
        )
    })?;

    let client = reqwest::blocking::Client::builder()
        .timeout(SKILL_DOWNLOAD_TIMEOUT)
        .build()
        .map_err(|e| {
            error_shape(
                ERROR_UNAVAILABLE,
                &format!("failed to create HTTP client: {}", e),
                None,
            )
        })?;

    let response = client.get(url.as_str()).send().map_err(|e| {
        error_shape(
            ERROR_UNAVAILABLE,
            &format!("failed to download skill: {}", e),
            None,
        )
    })?;

    if !response.status().is_success() {
        return Err(error_shape(
            ERROR_UNAVAILABLE,
            &format!(
                "skill download failed with HTTP {}",
                response.status().as_u16()
            ),
            None,
        ));
    }

    let bytes = response.bytes().map_err(|e| {
        error_shape(
            ERROR_UNAVAILABLE,
            &format!("failed to read skill download body: {}", e),
            None,
        )
    })?;

    if bytes.len() > MAX_SKILL_DOWNLOAD_BYTES {
        return Err(error_shape(
            ERROR_INVALID_REQUEST,
            &format!(
                "downloaded skill exceeds maximum size ({} bytes > {} bytes)",
                bytes.len(),
                MAX_SKILL_DOWNLOAD_BYTES
            ),
            None,
        ));
    }

    // Validate WASM magic bytes
    if bytes.len() < 4 || bytes[..4] != WASM_MAGIC {
        return Err(error_shape(
            ERROR_INVALID_REQUEST,
            "downloaded file is not a valid WASM module (bad magic bytes)",
            None,
        ));
    }

    let dest_path = skills_dir.join(file_name);
    let tmp_path = skills_dir.join(format!("{}.tmp", file_name));

    {
        let mut file = std::fs::File::create(&tmp_path).map_err(|e| {
            error_shape(
                ERROR_UNAVAILABLE,
                &format!("failed to write skill binary: {}", e),
                None,
            )
        })?;
        file.write_all(&bytes).map_err(|e| {
            error_shape(
                ERROR_UNAVAILABLE,
                &format!("failed to write skill binary: {}", e),
                None,
            )
        })?;
    }
    std::fs::rename(&tmp_path, &dest_path).map_err(|e| {
        error_shape(
            ERROR_UNAVAILABLE,
            &format!("failed to replace skill binary: {}", e),
            None,
        )
    })?;

    Ok(dest_path)
}

pub(super) fn handle_skills_status() -> Result<Value, ErrorShape> {
    let cfg = config::load_config().unwrap_or(Value::Object(serde_json::Map::new()));
    let workspace_dir = resolve_workspace_dir(&cfg);
    let managed_skills_dir = workspace_dir.join("skills");

    let skills_arr = build_skills_array(&cfg);

    Ok(json!({
        "workspaceDir": workspace_dir.to_string_lossy(),
        "managedSkillsDir": managed_skills_dir.to_string_lossy(),
        "skills": skills_arr
    }))
}

/// Build a JSON array of skill entries from the config's `skills.entries` map.
fn build_skills_array(cfg: &Value) -> Vec<Value> {
    let entries = match cfg
        .get("skills")
        .and_then(|s| s.get("entries"))
        .and_then(|e| e.as_object())
    {
        Some(map) => map,
        None => return Vec::new(),
    };

    entries
        .iter()
        .map(|(key, entry)| {
            json!({
                "name": key,
                "enabled": entry.get("enabled").and_then(|v| v.as_bool()).unwrap_or(true),
                "installId": entry.get("installId").cloned().unwrap_or(Value::Null),
                "requestedAt": entry.get("requestedAt").cloned().unwrap_or(Value::Null),
            })
        })
        .collect()
}

pub(super) fn handle_skills_bins() -> Result<Value, ErrorShape> {
    let cfg = config::load_config().unwrap_or(Value::Object(serde_json::Map::new()));
    let workspace_dir = resolve_workspace_dir(&cfg);
    let managed_skills_dir = workspace_dir.join("skills");

    let bins = scan_skills_bins(&managed_skills_dir);

    Ok(json!({ "bins": bins }))
}

/// Scan the managed skills directory for binary files.
/// Returns an empty vec if the directory does not exist or cannot be read.
fn scan_skills_bins(dir: &std::path::Path) -> Vec<Value> {
    let read_dir = match std::fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(_) => return Vec::new(),
    };

    let mut bins = Vec::new();
    for entry in read_dir {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };
        let path = entry.path();
        // Only include files (skip subdirectories)
        if path.is_file() {
            let name = entry.file_name().to_string_lossy().to_string();
            bins.push(json!({
                "name": name,
                "path": path.to_string_lossy(),
            }));
        }
    }
    bins
}

pub(super) fn handle_skills_install(params: Option<&Value>) -> Result<Value, ErrorShape> {
    handle_skills_install_inner(params, &resolve_skills_dir())
}

/// Inner implementation of skills.install, accepting a skills directory for testability.
fn handle_skills_install_inner(
    params: Option<&Value>,
    skills_dir: &Path,
) -> Result<Value, ErrorShape> {
    // --- Parse and validate params ---
    let name = params
        .and_then(|v| v.get("name"))
        .and_then(|v| v.as_str())
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "name is required", None))?;
    validate_skill_name(name)?;

    let url_str = params
        .and_then(|v| v.get("url"))
        .and_then(|v| v.as_str())
        .map(|s| s.trim())
        .filter(|s| !s.is_empty());
    let version = params
        .and_then(|v| v.get("version"))
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    let wasm_file_name = format!("{}.wasm", name);
    let installed_at = now_ms();

    // If URL is provided, download and validate the WASM binary
    let mut wasm_path: Option<PathBuf> = None;
    if let Some(raw_url) = url_str {
        let parsed_url = validate_url(raw_url)?;
        let dest = download_skill_wasm(&parsed_url, skills_dir, &wasm_file_name)?;
        wasm_path = Some(dest);
    }

    // Record metadata in the skills manifest
    let mut manifest = read_skills_manifest(skills_dir);
    let manifest_obj = ensure_object(&mut manifest);
    let entry = manifest_obj
        .entry(name.to_string())
        .or_insert_with(|| json!({}));
    let entry_obj = ensure_object(entry);
    entry_obj.insert("name".to_string(), Value::String(name.to_string()));
    if let Some(ref v) = version {
        entry_obj.insert("version".to_string(), Value::String(v.clone()));
    }
    entry_obj.insert(
        "installed_at".to_string(),
        Value::Number(installed_at.into()),
    );
    if let Some(ref p) = wasm_path {
        entry_obj.insert(
            "path".to_string(),
            Value::String(p.to_string_lossy().to_string()),
        );
    }
    if let Some(raw_url) = url_str {
        entry_obj.insert("url".to_string(), Value::String(raw_url.to_string()));
    }
    write_skills_manifest(skills_dir, &manifest)?;

    // Also record the skill in the main config (preserving existing behaviour)
    let mut config_value = read_config_snapshot().config;
    let root = ensure_object(&mut config_value);
    let skills = root.entry("skills").or_insert_with(|| json!({}));
    let skills_obj = ensure_object(skills);
    let entries = skills_obj.entry("entries").or_insert_with(|| json!({}));
    let entries_obj = ensure_object(entries);
    let cfg_entry = entries_obj
        .entry(name.to_string())
        .or_insert_with(|| json!({}));
    let cfg_entry_obj = ensure_object(cfg_entry);
    cfg_entry_obj.insert("enabled".to_string(), Value::Bool(true));
    cfg_entry_obj.insert("name".to_string(), Value::String(name.to_string()));
    cfg_entry_obj.insert(
        "requestedAt".to_string(),
        Value::Number(installed_at.into()),
    );

    let issues = map_validation_issues(config::validate_config(&config_value));
    if !issues.is_empty() {
        return Err(error_shape(
            ERROR_INVALID_REQUEST,
            "invalid config",
            Some(json!({ "issues": issues })),
        ));
    }
    write_config_file(&config::get_config_path(), &config_value)?;

    Ok(json!({
        "ok": true,
        "name": name,
        "version": version,
        "installed_at": installed_at,
        "path": wasm_path.map(|p| p.to_string_lossy().to_string()),
        "skills_dir": skills_dir.to_string_lossy(),
    }))
}

pub(super) fn handle_skills_update(params: Option<&Value>) -> Result<Value, ErrorShape> {
    handle_skills_update_inner(params, &resolve_skills_dir())
}

/// Inner implementation of skills.update, accepting a skills directory for testability.
fn handle_skills_update_inner(
    params: Option<&Value>,
    skills_dir: &Path,
) -> Result<Value, ErrorShape> {
    // --- Parse and validate params ---
    let name = params
        .and_then(|v| v.get("name"))
        .and_then(|v| v.as_str())
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "name is required", None))?;
    validate_skill_name(name)?;

    let url_str = params
        .and_then(|v| v.get("url"))
        .and_then(|v| v.as_str())
        .map(|s| s.trim())
        .filter(|s| !s.is_empty());
    let version = params
        .and_then(|v| v.get("version"))
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    // Verify the skill exists in the manifest
    let mut manifest = read_skills_manifest(skills_dir);
    {
        let manifest_obj = manifest
            .as_object()
            .unwrap_or(&serde_json::Map::new())
            .clone();
        if !manifest_obj.contains_key(name) {
            // Also check the filesystem as a fallback
            let wasm_path = skills_dir.join(format!("{}.wasm", name));
            if !wasm_path.is_file() {
                return Err(error_shape(
                    ERROR_INVALID_REQUEST,
                    &format!("skill '{}' is not installed", name),
                    None,
                ));
            }
        }
    }

    // URL is required to perform an actual update (download new version)
    let url_str = match url_str {
        Some(u) => u,
        None => {
            return Err(error_shape(
                ERROR_INVALID_REQUEST,
                "no update source available: url is required to update a skill",
                None,
            ));
        }
    };

    let parsed_url = validate_url(url_str)?;
    let wasm_file_name = format!("{}.wasm", name);
    let dest = download_skill_wasm(&parsed_url, skills_dir, &wasm_file_name)?;
    let updated_at = now_ms();

    // Update the manifest entry
    let manifest_obj = ensure_object(&mut manifest);
    let entry = manifest_obj
        .entry(name.to_string())
        .or_insert_with(|| json!({}));
    let entry_obj = ensure_object(entry);
    entry_obj.insert("name".to_string(), Value::String(name.to_string()));
    if let Some(ref v) = version {
        entry_obj.insert("version".to_string(), Value::String(v.clone()));
    }
    entry_obj.insert("updated_at".to_string(), Value::Number(updated_at.into()));
    entry_obj.insert(
        "path".to_string(),
        Value::String(dest.to_string_lossy().to_string()),
    );
    entry_obj.insert("url".to_string(), Value::String(url_str.to_string()));
    write_skills_manifest(skills_dir, &manifest)?;

    Ok(json!({
        "ok": true,
        "name": name,
        "version": version,
        "updated_at": updated_at,
        "path": dest.to_string_lossy(),
        "skills_dir": skills_dir.to_string_lossy(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_build_skills_array_empty_config() {
        let cfg = json!({});
        let result = build_skills_array(&cfg);
        assert!(result.is_empty());
    }

    #[test]
    fn test_build_skills_array_no_entries() {
        let cfg = json!({ "skills": {} });
        let result = build_skills_array(&cfg);
        assert!(result.is_empty());
    }

    #[test]
    fn test_build_skills_array_empty_entries() {
        let cfg = json!({ "skills": { "entries": {} } });
        let result = build_skills_array(&cfg);
        assert!(result.is_empty());
    }

    #[test]
    fn test_build_skills_array_with_entries() {
        let cfg = json!({
            "skills": {
                "entries": {
                    "weather": {
                        "enabled": true,
                        "installId": "abc-123",
                        "requestedAt": 1700000000000u64
                    },
                    "calendar": {
                        "enabled": false,
                        "installId": "def-456",
                        "requestedAt": 1700000001000u64
                    }
                }
            }
        });
        let result = build_skills_array(&cfg);
        assert_eq!(result.len(), 2);

        // Find weather and calendar entries (order is not guaranteed in JSON objects)
        let weather = result.iter().find(|v| v["name"] == "weather").unwrap();
        assert_eq!(weather["enabled"], true);
        assert_eq!(weather["installId"], "abc-123");
        assert_eq!(weather["requestedAt"], 1700000000000u64);

        let calendar = result.iter().find(|v| v["name"] == "calendar").unwrap();
        assert_eq!(calendar["enabled"], false);
        assert_eq!(calendar["installId"], "def-456");
        assert_eq!(calendar["requestedAt"], 1700000001000u64);
    }

    #[test]
    fn test_build_skills_array_enabled_defaults_true() {
        let cfg = json!({
            "skills": {
                "entries": {
                    "minimal": {}
                }
            }
        });
        let result = build_skills_array(&cfg);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0]["name"], "minimal");
        assert_eq!(result[0]["enabled"], true);
        assert!(result[0]["installId"].is_null());
        assert!(result[0]["requestedAt"].is_null());
    }

    #[test]
    fn test_build_skills_array_entries_not_object() {
        // If entries is not an object (e.g. an array), return empty
        let cfg = json!({ "skills": { "entries": [1, 2, 3] } });
        let result = build_skills_array(&cfg);
        assert!(result.is_empty());
    }

    #[test]
    fn test_scan_skills_bins_nonexistent_dir() {
        let result = scan_skills_bins(std::path::Path::new(
            "/nonexistent/path/that/does/not/exist/skills",
        ));
        assert!(result.is_empty());
    }

    #[test]
    fn test_scan_skills_bins_empty_dir() {
        let dir = TempDir::new().unwrap();
        let result = scan_skills_bins(dir.path());
        assert!(result.is_empty());
    }

    #[test]
    fn test_scan_skills_bins_with_files() {
        let dir = TempDir::new().unwrap();
        // Create some files
        std::fs::write(dir.path().join("skill-a"), b"#!/bin/sh\n").unwrap();
        std::fs::write(dir.path().join("skill-b"), b"#!/bin/sh\n").unwrap();
        // Create a subdirectory (should be skipped)
        std::fs::create_dir(dir.path().join("subdir")).unwrap();

        let result = scan_skills_bins(dir.path());
        assert_eq!(result.len(), 2);

        let names: Vec<&str> = result.iter().map(|v| v["name"].as_str().unwrap()).collect();
        assert!(names.contains(&"skill-a"));
        assert!(names.contains(&"skill-b"));

        // Verify paths are absolute
        for bin in &result {
            let path = bin["path"].as_str().unwrap();
            assert!(
                std::path::Path::new(path).is_absolute(),
                "path should be absolute: {}",
                path
            );
        }
    }

    // ---- Validation tests ----

    #[test]
    fn test_validate_skill_name_valid() {
        assert!(validate_skill_name("weather").is_ok());
        assert!(validate_skill_name("my-skill").is_ok());
        assert!(validate_skill_name("my_skill_v2").is_ok());
        assert!(validate_skill_name("a").is_ok());
        assert!(validate_skill_name("ABC123").is_ok());
    }

    #[test]
    fn test_validate_skill_name_empty() {
        let err = validate_skill_name("").unwrap_err();
        assert_eq!(err.code, ERROR_INVALID_REQUEST);
        assert!(err.message.contains("empty"));
    }

    #[test]
    fn test_validate_skill_name_too_long() {
        let long_name = "a".repeat(129);
        let err = validate_skill_name(&long_name).unwrap_err();
        assert_eq!(err.code, ERROR_INVALID_REQUEST);
        assert!(err.message.contains("too long"));
    }

    #[test]
    fn test_validate_skill_name_bad_chars() {
        let err = validate_skill_name("my skill").unwrap_err();
        assert_eq!(err.code, ERROR_INVALID_REQUEST);

        let err = validate_skill_name("../escape").unwrap_err();
        assert_eq!(err.code, ERROR_INVALID_REQUEST);

        let err = validate_skill_name("path/traversal").unwrap_err();
        assert_eq!(err.code, ERROR_INVALID_REQUEST);

        let err = validate_skill_name("has.dot").unwrap_err();
        assert_eq!(err.code, ERROR_INVALID_REQUEST);
    }

    #[test]
    fn test_validate_url_valid() {
        assert!(validate_url("https://example.com/skill.wasm").is_ok());
        assert!(validate_url("http://localhost:8080/skill.wasm").is_ok());
    }

    #[test]
    fn test_validate_url_bad_scheme() {
        let err = validate_url("ftp://example.com/skill.wasm").unwrap_err();
        assert!(err.message.contains("unsupported url scheme"));
    }

    #[test]
    fn test_validate_url_invalid() {
        let err = validate_url("not a url at all").unwrap_err();
        assert!(err.message.contains("invalid url"));
    }

    // ---- Manifest read/write tests ----

    #[test]
    fn test_read_skills_manifest_nonexistent() {
        let dir = TempDir::new().unwrap();
        let manifest = read_skills_manifest(dir.path());
        assert_eq!(manifest, json!({}));
    }

    #[test]
    fn test_write_and_read_skills_manifest() {
        let dir = TempDir::new().unwrap();
        let manifest = json!({
            "weather": {
                "name": "weather",
                "version": "1.0.0",
                "installed_at": 1700000000000u64
            }
        });
        write_skills_manifest(dir.path(), &manifest).unwrap();

        let read_back = read_skills_manifest(dir.path());
        assert_eq!(read_back["weather"]["name"], "weather");
        assert_eq!(read_back["weather"]["version"], "1.0.0");
        assert_eq!(read_back["weather"]["installed_at"], 1700000000000u64);
    }

    #[test]
    fn test_write_skills_manifest_creates_directory() {
        let dir = TempDir::new().unwrap();
        let nested = dir.path().join("nested").join("skills");
        let manifest = json!({ "test": {} });
        write_skills_manifest(&nested, &manifest).unwrap();
        assert!(nested.join(SKILLS_MANIFEST_FILE).is_file());
    }

    #[test]
    fn test_read_skills_manifest_corrupt_json() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join(SKILLS_MANIFEST_FILE), b"not json").unwrap();
        let manifest = read_skills_manifest(dir.path());
        assert_eq!(manifest, json!({}));
    }

    // ---- WASM magic validation test ----

    #[test]
    fn test_wasm_magic_bytes() {
        // Verify the constant matches the WASM spec
        assert_eq!(WASM_MAGIC, [0x00, 0x61, 0x73, 0x6D]);
        // "\0asm" in ASCII
        assert_eq!(&WASM_MAGIC[1..], b"asm");
    }

    // ---- Install handler tests ----

    #[test]
    fn test_install_missing_name() {
        let dir = TempDir::new().unwrap();
        let result = handle_skills_install_inner(None, dir.path());
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code, ERROR_INVALID_REQUEST);
        assert!(err.message.contains("name is required"));
    }

    #[test]
    fn test_install_empty_name() {
        let dir = TempDir::new().unwrap();
        let params = json!({ "name": "  " });
        let result = handle_skills_install_inner(Some(&params), dir.path());
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.message.contains("name is required"));
    }

    #[test]
    fn test_install_invalid_name_chars() {
        let dir = TempDir::new().unwrap();
        let params = json!({ "name": "../etc/passwd" });
        let result = handle_skills_install_inner(Some(&params), dir.path());
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.message.contains("alphanumeric"));
    }

    #[test]
    fn test_install_invalid_url_scheme() {
        let dir = TempDir::new().unwrap();
        let params = json!({ "name": "test-skill", "url": "ftp://example.com/foo.wasm" });
        let result = handle_skills_install_inner(Some(&params), dir.path());
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.message.contains("unsupported url scheme"));
    }

    #[test]
    fn test_install_invalid_url_parse() {
        let dir = TempDir::new().unwrap();
        let params = json!({ "name": "test-skill", "url": "not a url" });
        let result = handle_skills_install_inner(Some(&params), dir.path());
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.message.contains("invalid url"));
    }

    #[test]
    fn test_install_no_url_writes_manifest_only() {
        let dir = TempDir::new().unwrap();
        let skills_dir = dir.path().join("skills");
        let params = json!({ "name": "my-skill", "version": "2.0.0" });

        // This will fail at the config write stage (no real config file in test env),
        // but we can verify the manifest was written before that point.
        let _ = handle_skills_install_inner(Some(&params), &skills_dir);

        // Check that the manifest was created
        let manifest = read_skills_manifest(&skills_dir);
        assert_eq!(manifest["my-skill"]["name"], "my-skill");
        assert_eq!(manifest["my-skill"]["version"], "2.0.0");
        assert!(manifest["my-skill"]["installed_at"].is_number());
    }

    // ---- Update handler tests ----

    #[test]
    fn test_update_missing_name() {
        let dir = TempDir::new().unwrap();
        let result = handle_skills_update_inner(None, dir.path());
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code, ERROR_INVALID_REQUEST);
        assert!(err.message.contains("name is required"));
    }

    #[test]
    fn test_update_empty_name() {
        let dir = TempDir::new().unwrap();
        let params = json!({ "name": "" });
        let result = handle_skills_update_inner(Some(&params), dir.path());
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.message.contains("name is required"));
    }

    #[test]
    fn test_update_invalid_name() {
        let dir = TempDir::new().unwrap();
        let params = json!({ "name": "bad/name" });
        let result = handle_skills_update_inner(Some(&params), dir.path());
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.message.contains("alphanumeric"));
    }

    #[test]
    fn test_update_skill_not_installed() {
        let dir = TempDir::new().unwrap();
        let params = json!({ "name": "nonexistent", "url": "https://example.com/skill.wasm" });
        let result = handle_skills_update_inner(Some(&params), dir.path());
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.message.contains("not installed"));
    }

    #[test]
    fn test_update_no_url_returns_error() {
        let dir = TempDir::new().unwrap();
        // Pre-create a manifest entry so the skill is "installed"
        let manifest = json!({
            "my-skill": {
                "name": "my-skill",
                "version": "1.0.0",
                "installed_at": 1700000000000u64
            }
        });
        write_skills_manifest(dir.path(), &manifest).unwrap();

        let params = json!({ "name": "my-skill" });
        let result = handle_skills_update_inner(Some(&params), dir.path());
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.message.contains("no update source available"));
    }

    #[test]
    fn test_update_skill_found_by_wasm_file() {
        // Even if the manifest doesn't have the entry, a .wasm file on disk counts
        let dir = TempDir::new().unwrap();
        // Create the wasm file (with valid magic bytes)
        let mut wasm_bytes = WASM_MAGIC.to_vec();
        wasm_bytes.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]); // version 1
        std::fs::write(dir.path().join("disk-skill.wasm"), &wasm_bytes).unwrap();

        // No URL provided, so it should fail with "no update source" (not "not installed")
        let params = json!({ "name": "disk-skill" });
        let result = handle_skills_update_inner(Some(&params), dir.path());
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.message.contains("no update source"),
            "expected 'no update source' but got: {}",
            err.message
        );
    }

    #[test]
    fn test_update_invalid_url_scheme() {
        let dir = TempDir::new().unwrap();
        let manifest = json!({ "my-skill": { "name": "my-skill" } });
        write_skills_manifest(dir.path(), &manifest).unwrap();

        let params = json!({ "name": "my-skill", "url": "ftp://example.com/skill.wasm" });
        let result = handle_skills_update_inner(Some(&params), dir.path());
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.message.contains("unsupported url scheme"));
    }

    // ---- download_skill_wasm tests ----

    #[test]
    fn test_download_skill_wasm_connection_refused() {
        // Attempting to download from a port that is not listening
        let dir = TempDir::new().unwrap();
        let url = url::Url::parse("http://127.0.0.1:1/nonexistent.wasm").unwrap();
        let result = download_skill_wasm(&url, dir.path(), "test.wasm");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.message.contains("failed to download skill"),
            "unexpected error message: {}",
            err.message
        );
    }
}
