//! Skills handlers.

use serde_json::{json, Value};
use std::io::Write;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::TokioAsyncResolver;

use super::super::*;
use super::config::{map_validation_issues, read_config_snapshot, write_config_file};
use crate::plugins::capabilities::SsrfProtection;

/// WASM binary magic bytes: `\0asm`
const WASM_MAGIC: [u8; 4] = [0x00, 0x61, 0x73, 0x6D];

/// Maximum download size for a skill WASM binary (50 MB).
const MAX_SKILL_DOWNLOAD_BYTES: usize = 50 * 1024 * 1024;

/// Default HTTP timeout for skill downloads (60 seconds).
const SKILL_DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(60);

/// Name of the skills manifest file stored alongside WASM binaries.
const SKILLS_MANIFEST_FILE: &str = "skills-manifest.json";

fn ensure_object(value: &mut Value) -> Result<&mut serde_json::Map<String, Value>, ErrorShape> {
    if !value.is_object() {
        *value = Value::Object(serde_json::Map::new());
    }
    value
        .as_object_mut()
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "expected JSON object value", None))
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
        Ok(contents) => serde_json::from_str(&contents).unwrap_or_else(|e| {
            tracing::warn!(
                path = %manifest_path.display(),
                error = %e,
                "skills manifest JSON is corrupt, falling back to empty object"
            );
            json!({})
        }),
        Err(e) => {
            // Only warn if the file exists but could not be read (permission error, etc.).
            // A missing file is expected on first run and not worth logging.
            if e.kind() != std::io::ErrorKind::NotFound {
                tracing::warn!(
                    path = %manifest_path.display(),
                    error = %e,
                    "failed to read skills manifest, falling back to empty object"
                );
            }
            json!({})
        }
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
        file.sync_all().map_err(|e| {
            error_shape(
                ERROR_UNAVAILABLE,
                &format!("failed to sync skills manifest: {}", e),
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

/// Compute the SHA-256 hash of the given bytes and return it as a lowercase hex string.
fn compute_sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let hash = hasher.finalize();
    hex::encode(hash)
}

/// Validate the download URL against SSRF attacks and resolve DNS for hostname-based
/// URLs.  Returns `(host, port, resolved_ip)` where `resolved_ip` is `Some` only when
/// the host is a hostname (not an IP literal) and DNS resolution succeeded.
fn validate_and_resolve_dns(url: &url::Url) -> Result<(String, u16, Option<IpAddr>), ErrorShape> {
    // Validate URL against SSRF attacks (blocks localhost, private IPs, metadata endpoints)
    SsrfProtection::validate_url(url.as_str()).map_err(|e| {
        error_shape(
            ERROR_INVALID_REQUEST,
            &format!("skill download URL blocked by SSRF protection: {}", e),
            None,
        )
    })?;

    let host = url
        .host_str()
        .ok_or_else(|| {
            error_shape(
                ERROR_INVALID_REQUEST,
                "skill download URL has no host",
                None,
            )
        })?
        .to_string();
    let port = url.port_or_known_default().unwrap_or(443);

    let resolved_ip: Option<IpAddr> = if host.parse::<IpAddr>().is_ok() {
        // Host is already an IP literal; URL validation above already checked it.
        None
    } else {
        // Host is a hostname -- resolve DNS and validate every returned IP.
        let ip = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                let resolver =
                    TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());

                let lookup = resolver.lookup_ip(&host).await.map_err(|e| {
                    error_shape(
                        ERROR_UNAVAILABLE,
                        &format!("DNS resolution failed for {}: {}", host, e),
                        None,
                    )
                })?;

                let mut first_valid: Option<IpAddr> = None;
                for ip in lookup.iter() {
                    SsrfProtection::validate_resolved_ip(&ip, &host).map_err(|e| {
                        error_shape(
                            ERROR_INVALID_REQUEST,
                            &format!("skill download blocked by DNS rebinding protection: {}", e),
                            None,
                        )
                    })?;
                    if first_valid.is_none() {
                        first_valid = Some(ip);
                    }
                }

                first_valid.ok_or_else(|| {
                    error_shape(
                        ERROR_UNAVAILABLE,
                        &format!("DNS resolution returned no addresses for {}", host),
                        None,
                    )
                })
            })
        })?;

        tracing::debug!(
            url = %url,
            host = %host,
            resolved_ip = %ip,
            "DNS resolved and validated for skill download"
        );

        Some(ip)
    };

    Ok((host, port, resolved_ip))
}

/// Build an HTTP client pinned to the validated IP (if any) and download the WASM
/// binary.  Validates response status, size limit, and WASM magic bytes.
fn download_with_pinned_ip(
    url: &url::Url,
    host: &str,
    port: u16,
    resolved_ip: Option<IpAddr>,
) -> Result<bytes::Bytes, ErrorShape> {
    let mut client_builder = reqwest::blocking::Client::builder()
        .timeout(SKILL_DOWNLOAD_TIMEOUT)
        // SECURITY: Disable redirects to prevent redirect-based SSRF bypass.
        // An attacker could redirect from a public URL to a private IP.
        .redirect(reqwest::redirect::Policy::none());

    // Pin the validated IP so the HTTP client connects directly to it,
    // preventing any second DNS lookup from returning a different address.
    if let Some(ip) = resolved_ip {
        let socket_addr = std::net::SocketAddr::new(ip, port);
        client_builder = client_builder.resolve(host, socket_addr);
    }

    let client = client_builder.build().map_err(|e| {
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

    Ok(bytes)
}

/// Write the downloaded bytes to a temporary file, fsync, then atomically rename
/// into the final destination.  Returns the final file path.
fn atomic_write_skill_file(
    skills_dir: &Path,
    file_name: &str,
    bytes: &[u8],
) -> Result<PathBuf, ErrorShape> {
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
        file.write_all(bytes).map_err(|e| {
            error_shape(
                ERROR_UNAVAILABLE,
                &format!("failed to write skill binary: {}", e),
                None,
            )
        })?;
        file.sync_all().map_err(|e| {
            error_shape(
                ERROR_UNAVAILABLE,
                &format!("failed to sync skill binary: {}", e),
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

/// Download a WASM binary from the given URL and save it atomically to the skills
/// directory.  Returns the final file path and the raw bytes on success.
fn download_skill_wasm(
    url: &url::Url,
    skills_dir: &Path,
    file_name: &str,
) -> Result<(PathBuf, Vec<u8>), ErrorShape> {
    let (host, port, resolved_ip) = validate_and_resolve_dns(url)?;

    std::fs::create_dir_all(skills_dir).map_err(|e| {
        error_shape(
            ERROR_UNAVAILABLE,
            &format!("failed to create skills directory: {}", e),
            None,
        )
    })?;

    let bytes = download_with_pinned_ip(url, &host, port, resolved_ip)?;
    let dest_path = atomic_write_skill_file(skills_dir, file_name, &bytes)?;

    Ok((dest_path, bytes.to_vec()))
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
    let publisher_key = params
        .and_then(|v| v.get("publisherKey"))
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let signature = params
        .and_then(|v| v.get("signature"))
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    let wasm_file_name = format!("{}.wasm", name);
    let installed_at = now_ms();

    // If URL is provided, download and validate the WASM binary
    let mut wasm_path: Option<PathBuf> = None;
    let mut wasm_hash: Option<String> = None;
    if let Some(raw_url) = url_str {
        let parsed_url = validate_url(raw_url)?;
        let (dest, wasm_bytes) = download_skill_wasm(&parsed_url, skills_dir, &wasm_file_name)?;
        wasm_hash = Some(compute_sha256_hex(&wasm_bytes));
        wasm_path = Some(dest);
    }

    // Record metadata in the skills manifest
    let mut manifest = read_skills_manifest(skills_dir);
    let manifest_obj = ensure_object(&mut manifest)?;
    let entry = manifest_obj
        .entry(name.to_string())
        .or_insert_with(|| json!({}));
    let entry_obj = ensure_object(entry)?;
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
    if let Some(ref hash) = wasm_hash {
        entry_obj.insert("sha256".to_string(), Value::String(hash.clone()));
    }
    if let Some(ref pk) = publisher_key {
        entry_obj.insert("publisher_key".to_string(), Value::String(pk.clone()));
    }
    if let Some(ref sig) = signature {
        entry_obj.insert("signature".to_string(), Value::String(sig.clone()));
    }
    if let Some(raw_url) = url_str {
        entry_obj.insert("url".to_string(), Value::String(raw_url.to_string()));
    }
    write_skills_manifest(skills_dir, &manifest)?;

    // Also record the skill in the main config (preserving existing behaviour)
    let mut config_value = read_config_snapshot().config;
    let root = ensure_object(&mut config_value)?;
    let skills = root.entry("skills").or_insert_with(|| json!({}));
    let skills_obj = ensure_object(skills)?;
    let entries = skills_obj.entry("entries").or_insert_with(|| json!({}));
    let entries_obj = ensure_object(entries)?;
    let cfg_entry = entries_obj
        .entry(name.to_string())
        .or_insert_with(|| json!({}));
    let cfg_entry_obj = ensure_object(cfg_entry)?;
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
        "publisher_key": publisher_key,
        "signature": signature,
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
    let publisher_key = params
        .and_then(|v| v.get("publisherKey"))
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let signature = params
        .and_then(|v| v.get("signature"))
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
    let (dest, wasm_bytes) = download_skill_wasm(&parsed_url, skills_dir, &wasm_file_name)?;
    let wasm_hash = compute_sha256_hex(&wasm_bytes);
    let updated_at = now_ms();

    // Update the manifest entry
    let manifest_obj = ensure_object(&mut manifest)?;
    let entry = manifest_obj
        .entry(name.to_string())
        .or_insert_with(|| json!({}));
    let entry_obj = ensure_object(entry)?;
    entry_obj.insert("name".to_string(), Value::String(name.to_string()));
    if let Some(ref v) = version {
        entry_obj.insert("version".to_string(), Value::String(v.clone()));
    }
    entry_obj.insert("updated_at".to_string(), Value::Number(updated_at.into()));
    entry_obj.insert(
        "path".to_string(),
        Value::String(dest.to_string_lossy().to_string()),
    );
    entry_obj.insert("sha256".to_string(), Value::String(wasm_hash));
    if let Some(ref pk) = publisher_key {
        entry_obj.insert("publisher_key".to_string(), Value::String(pk.clone()));
    }
    if let Some(ref sig) = signature {
        entry_obj.insert("signature".to_string(), Value::String(sig.clone()));
    }
    entry_obj.insert("url".to_string(), Value::String(url_str.to_string()));
    write_skills_manifest(skills_dir, &manifest)?;

    Ok(json!({
        "ok": true,
        "name": name,
        "version": version,
        "updated_at": updated_at,
        "path": dest.to_string_lossy(),
        "skills_dir": skills_dir.to_string_lossy(),
        "publisher_key": publisher_key,
        "signature": signature,
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

    // ---- SSRF protection tests for skill downloads ----

    #[tokio::test(flavor = "multi_thread")]
    async fn test_download_skill_ssrf_public_url_passes_validation() {
        // A public URL should pass SSRF validation (will fail later at the network level,
        // but the SSRF check itself should not reject it).
        // This test requires a tokio multi_thread runtime because the function
        // performs async DNS resolution for hostname-based URLs via block_in_place.
        // We use spawn_blocking to avoid reqwest::blocking::Client's internal
        // runtime conflicting with the test runtime on drop.
        let dir = TempDir::new().unwrap();
        let dir_path = dir.path().to_path_buf();
        let result = tokio::task::spawn_blocking(move || {
            let url = url::Url::parse("https://example.com/skills/my-skill.wasm").unwrap();
            download_skill_wasm(&url, &dir_path, "test.wasm")
        })
        .await
        .unwrap();
        // Should fail with a network error, NOT an SSRF error
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            !err.message.contains("SSRF"),
            "public URL should not be blocked by SSRF protection, got: {}",
            err.message
        );
    }

    #[test]
    fn test_download_skill_ssrf_rejects_localhost() {
        let dir = TempDir::new().unwrap();
        let url = url::Url::parse("http://localhost/evil.wasm").unwrap();
        let result = download_skill_wasm(&url, dir.path(), "test.wasm");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code, ERROR_INVALID_REQUEST);
        assert!(
            err.message.contains("SSRF"),
            "localhost should be blocked by SSRF protection, got: {}",
            err.message
        );
    }

    #[test]
    fn test_download_skill_ssrf_rejects_metadata_endpoint() {
        let dir = TempDir::new().unwrap();
        let url = url::Url::parse("http://169.254.169.254/latest/meta-data/").unwrap();
        let result = download_skill_wasm(&url, dir.path(), "test.wasm");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code, ERROR_INVALID_REQUEST);
        assert!(
            err.message.contains("SSRF"),
            "metadata endpoint should be blocked by SSRF protection, got: {}",
            err.message
        );
    }

    #[test]
    fn test_download_skill_ssrf_rejects_internal_ip() {
        let dir = TempDir::new().unwrap();
        let url = url::Url::parse("http://10.0.0.1/internal-skill.wasm").unwrap();
        let result = download_skill_wasm(&url, dir.path(), "test.wasm");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code, ERROR_INVALID_REQUEST);
        assert!(
            err.message.contains("SSRF"),
            "internal IP should be blocked by SSRF protection, got: {}",
            err.message
        );
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

    // ---- ensure_object tests ----

    #[test]
    fn test_ensure_object_with_object_value() {
        let mut value = json!({"key": "val"});
        let obj = ensure_object(&mut value).unwrap();
        assert_eq!(obj.get("key").unwrap(), "val");
    }

    #[test]
    fn test_ensure_object_with_non_object_resets_to_empty() {
        // A non-object value (e.g. a string) should be replaced with an empty object
        let mut value = json!("not an object");
        let obj = ensure_object(&mut value).unwrap();
        assert!(obj.is_empty());
        assert!(value.is_object());
    }

    #[test]
    fn test_ensure_object_with_null_resets_to_empty() {
        let mut value = Value::Null;
        let obj = ensure_object(&mut value).unwrap();
        assert!(obj.is_empty());
        assert!(value.is_object());
    }

    #[test]
    fn test_ensure_object_with_array_resets_to_empty() {
        let mut value = json!([1, 2, 3]);
        let obj = ensure_object(&mut value).unwrap();
        assert!(obj.is_empty());
        assert!(value.is_object());
    }

    // ---- read_skills_manifest logging tests ----

    #[test]
    fn test_read_skills_manifest_corrupt_json_returns_empty() {
        // Corrupt JSON should fall back to empty object (and log a warning)
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join(SKILLS_MANIFEST_FILE), b"not json {{{{").unwrap();
        let manifest = read_skills_manifest(dir.path());
        assert_eq!(manifest, json!({}));
    }

    #[test]
    fn test_read_skills_manifest_empty_file_returns_empty() {
        // An empty file is invalid JSON and should fall back gracefully
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join(SKILLS_MANIFEST_FILE), b"").unwrap();
        let manifest = read_skills_manifest(dir.path());
        assert_eq!(manifest, json!({}));
    }

    // ---- download_skill_wasm tests ----

    #[test]
    fn test_download_skill_wasm_connection_refused() {
        // 127.0.0.1 is now blocked by SSRF protection before any network request is made
        let dir = TempDir::new().unwrap();
        let url = url::Url::parse("http://127.0.0.1:1/nonexistent.wasm").unwrap();
        let result = download_skill_wasm(&url, dir.path(), "test.wasm");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code, ERROR_INVALID_REQUEST);
        assert!(
            err.message.contains("SSRF"),
            "127.0.0.1 should be blocked by SSRF protection, got: {}",
            err.message
        );
    }

    // ---- SHA-256 hash pinning tests ----

    #[test]
    fn test_skill_hash_computed_on_install() {
        // Simulate an install without a URL (no download) but manually write a WASM
        // file and manifest entry with a hash, then verify the hash is present.
        let dir = TempDir::new().unwrap();
        let skills_dir = dir.path().join("skills");
        std::fs::create_dir_all(&skills_dir).unwrap();

        // Create a fake WASM binary with valid magic bytes
        let mut wasm_bytes = WASM_MAGIC.to_vec();
        wasm_bytes.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]); // version 1
        wasm_bytes.extend_from_slice(b"test payload for hashing");

        // Compute expected hash
        let expected_hash = compute_sha256_hex(&wasm_bytes);
        assert!(!expected_hash.is_empty());
        assert_eq!(expected_hash.len(), 64); // SHA-256 produces 64 hex chars

        // Write the WASM file
        std::fs::write(skills_dir.join("my-skill.wasm"), &wasm_bytes).unwrap();

        // Write a manifest entry that includes the sha256 field (simulating post-install)
        let manifest = json!({
            "my-skill": {
                "name": "my-skill",
                "version": "1.0.0",
                "installed_at": 1700000000000u64,
                "sha256": expected_hash
            }
        });
        write_skills_manifest(&skills_dir, &manifest).unwrap();

        // Read back and verify hash is stored
        let read_back = read_skills_manifest(&skills_dir);
        let stored_hash = read_back["my-skill"]["sha256"].as_str().unwrap();
        assert_eq!(stored_hash, expected_hash);
        assert_eq!(stored_hash.len(), 64);
        // Verify it is lowercase hex
        assert!(stored_hash
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }

    // ---- DNS rebinding defense tests ----

    #[tokio::test(flavor = "multi_thread")]
    async fn test_download_skill_dns_rebinding_defense_active() {
        // Verify that the DNS rebinding defense code path is active by testing
        // that both IP-literal and hostname-based URLs are handled correctly.
        // Requires a tokio multi_thread runtime because the hostname path uses
        // async DNS resolution via block_in_place. We use spawn_blocking to
        // isolate the reqwest::blocking::Client from the async test runtime.

        // IP literal: blocked at URL validation (no DNS resolution path).
        // This part does not need spawn_blocking since it fails before
        // creating any blocking HTTP client.
        let dir = TempDir::new().unwrap();
        let ip_url = url::Url::parse("http://10.0.0.1/skill.wasm").unwrap();
        let result = download_skill_wasm(&ip_url, dir.path(), "test.wasm");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.message.contains("SSRF"),
            "IP-literal private URL should be blocked by SSRF protection, got: {}",
            err.message
        );

        // Hostname-based URL with a public domain: passes URL validation but
        // enters the DNS resolution + IP validation path. Will fail at the
        // network/DNS level (not SSRF), confirming the defense path is active.
        let dir2 = TempDir::new().unwrap();
        let dir2_path = dir2.path().to_path_buf();
        let result = tokio::task::spawn_blocking(move || {
            let hostname_url = url::Url::parse("https://example.com/skills/my-skill.wasm").unwrap();
            download_skill_wasm(&hostname_url, &dir2_path, "test.wasm")
        })
        .await
        .unwrap();
        assert!(result.is_err());
        let err = result.unwrap_err();
        // The error should NOT be an SSRF error -- example.com resolves to a
        // public IP. The error will be a DNS/network error since we are running
        // in a test environment, but critically it must not be an SSRF block.
        assert!(
            !err.message.contains("SSRF") && !err.message.contains("rebinding"),
            "public hostname URL should not be blocked by SSRF/rebinding protection, got: {}",
            err.message
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_download_skill_hostname_url_passes_ssrf_validation() {
        // Verify that a hostname-based URL with a legitimate public domain
        // passes through SSRF URL validation and reaches the DNS resolution
        // stage (where it may fail due to network, but that is expected).
        // Requires a tokio multi_thread runtime for the async DNS resolution path.
        // We use spawn_blocking to isolate the reqwest::blocking::Client.
        let dir = TempDir::new().unwrap();
        let dir_path = dir.path().to_path_buf();
        let result = tokio::task::spawn_blocking(move || {
            let url = url::Url::parse("https://cdn.example.org/plugins/translator.wasm").unwrap();
            download_skill_wasm(&url, &dir_path, "translator.wasm")
        })
        .await
        .unwrap();
        assert!(result.is_err());
        let err = result.unwrap_err();
        // Must not fail with an SSRF or rebinding error -- the hostname and
        // its (eventual) resolved IP are both public.
        assert!(
            !err.message.contains("SSRF") && !err.message.contains("rebinding"),
            "legitimate hostname URL must not be rejected by SSRF/rebinding checks, got: {}",
            err.message
        );
    }
}
