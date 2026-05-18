//! Plugin handlers.

use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;
use std::time::Duration;

use hickory_resolver::TokioResolver;
use parking_lot::Mutex;

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use super::super::*;
#[cfg(test)]
use super::config::write_config_file;
use super::config::{
    has_config_errors, map_validation_issues, read_config_snapshot,
    update_config_file_with_error_shape,
};
use crate::plugins::capabilities::{SsrfConfig, SsrfProtection};
use crate::plugins::loader::{validate_plugin_component_bytes, LoaderError, PLUGINS_MANIFEST_FILE};
use crate::plugins::{
    open_managed_plugin_path_no_follow, open_managed_plugin_wasm_no_follow,
    read_managed_plugin_wasm_no_follow, read_managed_plugins_manifest_no_follow,
    validate_managed_plugin_name, validate_managed_plugin_path_no_follow,
    MAX_MANAGED_PLUGIN_ARTIFACT_BYTES, MAX_MANAGED_PLUGIN_MANIFEST_BYTES,
};
use crate::runtime_bridge::{run_sync_blocking_send, BridgeError};

/// Maximum download size for a managed plugin WASM binary (50 MB).
const MAX_PLUGIN_DOWNLOAD_BYTES: usize = MAX_MANAGED_PLUGIN_ARTIFACT_BYTES as usize;

/// Default HTTP timeout for plugin downloads (60 seconds).
const PLUGIN_DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(60);
static PLUGINS_MANIFEST_RMW_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

/// Cross-process advisory lock for `<plugins_dir>/<name>.wasm` mutations.
///
/// CLI `cara plugins install --file` / `update --file` acquires
/// `<dest>.cli-lock` as an `O_NOFOLLOW + O_EXCL` create-only sentinel for
/// its rename-into-place transaction (see `acquire_plugin_file_transaction_lock`
/// in `src/cli/mod.rs`). The CLI is loopback-only and holds that lock until
/// the follow-up WS `plugins.install/update` (url=None, adopt path) returns.
///
/// The daemon's WS handler used to mutate the same `<name>.wasm` path
/// without honoring that sentinel, so a concurrent download-driven WS
/// install (url=Some) for the same plugin name could overwrite the CLI's
/// freshly-renamed artifact bytes between rename and adopt — leaving wasm
/// bytes on disk that did not match the manifest sha256/signature the
/// CLI's adopt path then recorded.
///
/// This guard makes the daemon a peer on the same advisory lock for the
/// download-driven write path. It is only acquired when the daemon
/// actually writes wasm bytes (`url_str.is_some()`); the adopt path
/// (`url_str.is_none()`) intentionally does NOT acquire because the CLI
/// is the holder in that flow.
struct PluginCliLockGuard {
    path: PathBuf,
}

impl Drop for PluginCliLockGuard {
    fn drop(&mut self) {
        match std::fs::remove_file(&self.path) {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            // SECURITY: a same-uid attacker (or operator manual
            // recovery) could swap the dirent to a directory between
            // acquire and release. `remove_file` errno varies by
            // platform — EISDIR on Linux, EPERM on macOS — and
            // both map to non-portable `ErrorKind` values. Use a
            // `symlink_metadata` probe (does NOT follow symlinks) to
            // disambiguate "dirent is a directory" from other errors,
            // then attempt `remove_dir` (succeeds only on empty
            // directories). Without this fallback, every subsequent
            // `acquire_plugin_cli_lock_for_daemon_write` for the same
            // plugin returns `Unavailable` until operator
            // intervention — effectively a denial-of-service on
            // plugin install/update for that plugin.
            Err(err) => {
                let dirent_is_directory = std::fs::symlink_metadata(&self.path)
                    .ok()
                    .is_some_and(|metadata| metadata.file_type().is_dir());
                if dirent_is_directory {
                    if let Err(dir_err) = std::fs::remove_dir(&self.path) {
                        tracing::warn!(
                            target: "carapace::plugins",
                            "failed to release plugin staging lock '{}' (dirent was a directory; remove_dir fallback also failed): file_err={}, dir_err={}",
                            self.path.display(),
                            err,
                            dir_err
                        );
                    }
                } else {
                    tracing::warn!(
                        target: "carapace::plugins",
                        "failed to release plugin staging lock '{}': {}",
                        self.path.display(),
                        err
                    );
                }
            }
        }
    }
}

fn plugin_cli_lock_path_for(plugins_dir: &Path, name: &str) -> PathBuf {
    plugins_dir.join(format!("{}.wasm.cli-lock", name))
}

/// On Unix, probe whether a recorded lock-owner PID is still alive.
/// Mirrors the `rekey_pid_is_alive` discipline in `src/cli/mod.rs`:
/// `kill(pid, 0)` is the canonical liveness probe. Treat the process
/// as alive on success or EPERM (process exists but caller can't
/// signal it — different uid). Treat as dead on ESRCH or unusual
/// errnos (EINVAL, ENOSYS, EACCES from a seccomp filter). PID <= 1
/// is invalid and treated as dead. SAFETY: libc::kill is unsafe; we
/// pass signal 0 which never delivers.
#[cfg(unix)]
fn lock_owner_pid_is_alive(pid: i32) -> bool {
    if pid <= 1 {
        return false;
    }
    let rc = unsafe { libc::kill(pid, 0) };
    if rc == 0 {
        return true;
    }
    let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
    errno == libc::EPERM
}

#[cfg(not(unix))]
fn lock_owner_pid_is_alive(_pid: i32) -> bool {
    // Non-Unix platforms: conservatively treat any recorded PID as
    // alive so the sweep never removes a lock that might still be
    // valid. Operators on non-Unix hosts can remove stale locks
    // manually. The carapace daemon's primary deployment is Unix
    // (Linux/macOS), so this is a minor degradation in coverage.
    true
}

/// Sweep `<plugins_dir>/*.wasm.cli-lock` at daemon startup, removing
/// any sentinel whose recorded owner PID is no longer alive.
///
/// SECURITY / DoS recovery: the `.cli-lock` sentinel is released
/// only by `PluginCliLockGuard::drop` (daemon side) and
/// `ManagedPluginFileTransaction::drop` (CLI side). SIGKILL, abort,
/// OOM-kill, or any other Drop-bypassing termination leaves the
/// sentinel on disk indefinitely. Subsequent install/update for
/// that plugin then returns `ERROR_UNAVAILABLE` ("another plugin
/// file mutation is already in progress") forever — a soft DoS that
/// only operator manual `rm` can recover from. The PID was already
/// written into the sentinel at `acquire_plugin_cli_lock_for_daemon_write`
/// precisely to enable this sweep.
///
/// At daemon startup no plugin install/update is in flight from this
/// daemon, so a sentinel whose recorded PID is no longer alive can
/// be safely removed without racing an in-flight transaction. If
/// the PID belongs to a still-running CLI process (the common
/// concurrent case), the probe returns alive and the sweep leaves
/// the sentinel in place.
///
/// Failure modes (read errors, unparseable PIDs, post-probe race
/// where the PID dies and another process reuses the dirent) are
/// handled best-effort with warn logs: the sweep is defense in
/// depth, not load-bearing correctness. Worst case the sweep does
/// nothing and the operator manually removes the file (the
/// pre-sweep recovery posture).
pub(crate) fn sweep_stale_plugin_cli_locks(plugins_dir: &Path) {
    let entries = match std::fs::read_dir(plugins_dir) {
        Ok(entries) => entries,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return,
        Err(err) => {
            tracing::warn!(
                path = %plugins_dir.display(),
                error = %err,
                "failed to enumerate plugins directory for stale .cli-lock sweep; \
                 continuing without sweep"
            );
            return;
        }
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if !name.ends_with(".wasm.cli-lock") {
            continue;
        }
        // Open with O_NOFOLLOW so a same-uid attacker who races the
        // sweep by symlinking the sentinel cannot redirect the
        // PID-read to attacker-chosen content.
        let bytes = match crate::paths::read_to_vec_no_hang_no_follow_capped(
            &path,
            PLUGIN_CLI_LOCK_PID_MAX_BYTES,
        ) {
            Ok(Some(bytes)) => bytes,
            Ok(None) => continue,
            Err(err) => {
                tracing::warn!(
                    path = %path.display(),
                    error = %err,
                    "failed to read .cli-lock for stale-lock sweep; leaving in place"
                );
                continue;
            }
        };
        let pid_text = match std::str::from_utf8(&bytes) {
            Ok(text) => text.trim(),
            Err(_) => {
                tracing::warn!(
                    path = %path.display(),
                    "stale-lock sweep: .cli-lock contents are not UTF-8; leaving in place"
                );
                continue;
            }
        };
        let pid = match pid_text.parse::<i32>() {
            Ok(pid) => pid,
            Err(err) => {
                // An empty PID file means the lock-holder created
                // the sentinel but had not yet written the PID
                // (legitimate race window during acquire). Leave
                // alone; either the lock holder will complete, or
                // the next sweep will catch a stale one.
                if pid_text.is_empty() {
                    continue;
                }
                tracing::warn!(
                    path = %path.display(),
                    error = %err,
                    "stale-lock sweep: .cli-lock PID is unparseable; leaving in place"
                );
                continue;
            }
        };
        if lock_owner_pid_is_alive(pid) {
            continue;
        }
        match std::fs::remove_file(&path) {
            Ok(()) => {
                tracing::info!(
                    path = %path.display(),
                    pid,
                    "stale-lock sweep: removed plugin .cli-lock whose owner PID is dead"
                );
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => {
                tracing::warn!(
                    path = %path.display(),
                    pid,
                    error = %err,
                    "stale-lock sweep: failed to remove stale .cli-lock"
                );
            }
        }
    }
}

/// Cap on the .cli-lock sidecar size when read for PID-liveness
/// sweep. PID strings are at most ~20 bytes (u32 max + newline);
/// 256 bytes is more than enough headroom for any future format
/// extension and still refuses a planted-multi-GB sentinel.
const PLUGIN_CLI_LOCK_PID_MAX_BYTES: u64 = 256;

/// Acquire the `<dest>.cli-lock` sidecar for daemon-side wasm writes.
///
/// Mirrors `acquire_plugin_file_transaction_lock` in `src/cli/mod.rs`:
/// `O_NOFOLLOW + O_EXCL + create_new` ensures the lock is symlink-resistant
/// and atomic across CLI and daemon processes. On `AlreadyExists` the daemon
/// returns a retryable `unavailable` error rather than overwriting the
/// other holder's in-flight write.
fn acquire_plugin_cli_lock_for_daemon_write(
    plugins_dir: &Path,
    name: &str,
) -> Result<PluginCliLockGuard, ErrorShape> {
    let lock_path = plugin_cli_lock_path_for(plugins_dir, name);
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        options.custom_flags(libc::O_NOFOLLOW);
        options.mode(0o600);
    }
    let mut file = match options.open(&lock_path) {
        Ok(file) => file,
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(error_shape(
                ERROR_UNAVAILABLE,
                &format!(
                    "another plugin file mutation for '{}' is already in progress (staging lock exists); retry shortly",
                    name
                ),
                None,
            ));
        }
        Err(err) => {
            return Err(error_shape(
                ERROR_UNAVAILABLE,
                &format!(
                    "failed to acquire plugin staging lock '{}': {}",
                    lock_path.display(),
                    err
                ),
                None,
            ));
        }
    };
    // PID is advisory diagnostics only — the lock semantic is "file
    // exists". Mirrors the CLI helper's PID write so an operator
    // investigating a stale lock can see who created it.
    let pid = std::process::id().to_string();
    if let Err(err) = file.write_all(pid.as_bytes()) {
        drop(file);
        let _ = std::fs::remove_file(&lock_path);
        return Err(error_shape(
            ERROR_UNAVAILABLE,
            &format!(
                "failed to record plugin staging lock owner in '{}': {}",
                lock_path.display(),
                err
            ),
            None,
        ));
    }
    Ok(PluginCliLockGuard { path: lock_path })
}

type PluginDownloadFn = fn(&url::Url, &Path, &SsrfConfig) -> Result<Vec<u8>, ErrorShape>;

#[cfg(test)]
type TransactionRestoreHook = Box<dyn Fn(&Path, &Path) + Send + Sync + 'static>;

#[cfg(test)]
static TRANSACTION_RESTORE_AFTER_BACKUP_OPEN_HOOK: LazyLock<Mutex<Option<TransactionRestoreHook>>> =
    LazyLock::new(|| Mutex::new(None));

enum PluginDnsError {
    InvalidRequest(String),
    Unavailable(String),
}

impl std::fmt::Display for PluginDnsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidRequest(msg) | Self::Unavailable(msg) => write!(f, "{}", msg),
        }
    }
}

impl PluginDnsError {
    fn into_error_shape(self) -> ErrorShape {
        match self {
            Self::InvalidRequest(msg) => error_shape(ERROR_INVALID_REQUEST, &msg, None),
            Self::Unavailable(msg) => error_shape(ERROR_UNAVAILABLE, &msg, None),
        }
    }
}

fn ensure_object(value: &mut Value) -> Result<&mut serde_json::Map<String, Value>, ErrorShape> {
    if !value.is_object() {
        *value = Value::Object(serde_json::Map::new());
    }
    value
        .as_object_mut()
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "expected JSON object value", None))
}

/// Typed representation of an entry in `plugins-manifest.json`.
///
/// SECURITY/CORRECTNESS: previously the install/update handlers
/// constructed manifest entries by inserting string literals like
/// `entry_obj.insert("sha256".to_string(), Value::String(...))` —
/// a writer-side typo (e.g. `"sha-256"`) would silently drift from
/// the reader at `verify_plugin_hash_on_load` and produce the
/// operationally-catastrophic `MissingPluginHash` error on every
/// managed plugin while the on-disk manifest looked superficially
/// correct. Routing writes through this typed struct binds the wire
/// field names to Rust identifiers — a writer typo is now a compile
/// error.
///
/// `extra` preserves any forward-compat fields a future daemon may
/// add (an older binary reading + rewriting won't silently drop
/// them).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct ManagedPluginManifestEntry {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub installed_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<u64>,
    /// `path` and `sha256` are populated by install/update but may
    /// be absent in entries created by the adopt-existing-local-wasm
    /// pre-flight (which creates a stub `{name, version,
    /// installed_at}` entry before the first update completes). The
    /// read-side hash verification at `verify_plugin_hash_on_load`
    /// fails closed with `MissingPluginHash` when `sha256` is None
    /// at load time, so making this Option here is the safer
    /// fail-closed contract: the writer always sets it post-install,
    /// the on-disk shape can omit it temporarily.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub publisher_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// Forward-compat catch-all for fields a newer daemon may add;
    /// preserved on roundtrip so an older binary's rewrite doesn't
    /// silently drop them.
    #[serde(flatten, default)]
    pub extra: BTreeMap<String, Value>,
}

/// Read an existing entry from a manifest Value, returning `None`
/// if the entry doesn't exist or doesn't parse as the typed shape.
/// Used by the update handler to preserve `installed_at` and any
/// forward-compat `extra` fields across the update.
fn read_existing_manifest_entry(
    manifest: &Value,
    name: &str,
) -> Option<ManagedPluginManifestEntry> {
    let entry = manifest.get(name)?;
    serde_json::from_value(entry.clone()).ok()
}

/// Write a typed manifest entry into the manifest object. Replaces
/// any existing entry under the same name.
fn write_typed_manifest_entry(
    manifest_obj: &mut serde_json::Map<String, Value>,
    name: &str,
    entry: &ManagedPluginManifestEntry,
) -> Result<(), ErrorShape> {
    let value = serde_json::to_value(entry).map_err(|e| {
        error_shape(
            ERROR_UNAVAILABLE,
            &format!("failed to serialize plugin manifest entry: {e}"),
            None,
        )
    })?;
    manifest_obj.insert(name.to_string(), value);
    Ok(())
}

fn apply_managed_plugin_config_entry(
    config_value: &mut Value,
    name: &str,
    requested_at: u64,
    force_enable: bool,
) -> Result<(), ErrorShape> {
    let root = ensure_object(config_value)?;
    let plugins = root.entry("plugins").or_insert_with(|| json!({}));
    let plugins_obj = ensure_object(plugins)?;
    let entries = plugins_obj.entry("entries").or_insert_with(|| json!({}));
    let entries_obj = ensure_object(entries)?;
    let cfg_entry = entries_obj
        .entry(name.to_string())
        .or_insert_with(|| json!({}));
    let cfg_entry_obj = ensure_object(cfg_entry)?;
    if force_enable || !cfg_entry_obj.contains_key("enabled") {
        cfg_entry_obj.insert("enabled".to_string(), Value::Bool(true));
    }
    cfg_entry_obj.insert(
        "requestedAt".to_string(),
        Value::Number(requested_at.into()),
    );
    Ok(())
}

fn validate_config_update(config_value: &Value) -> Result<(), ErrorShape> {
    let issues = config::validate_runtime_config_candidate(config_value)
        .map(|(_, issues)| map_validation_issues(issues))
        .map_err(|err| error_shape(ERROR_INVALID_REQUEST, &err.to_string(), None))?;
    if has_config_errors(&issues) {
        return Err(error_shape(
            ERROR_INVALID_REQUEST,
            "invalid config",
            Some(json!({ "issues": issues })),
        ));
    }
    Ok(())
}

/// Resolve the managed plugins directory under the state dir.
fn resolve_plugins_dir() -> PathBuf {
    resolve_state_dir().join("plugins")
}

/// Validate that a plugin name is safe: non-empty, ASCII alphanumeric plus hyphens and
/// underscores, no path separators, and reasonable length.
fn validate_plugin_name(name: &str) -> Result<(), ErrorShape> {
    validate_managed_plugin_name(name)
        .map_err(|message| error_shape(ERROR_INVALID_REQUEST, &message, None))
}

fn validate_plugin_wasm_bytes(bytes: &[u8], source: &str) -> Result<(), ErrorShape> {
    validate_plugin_wasm_size(bytes.len() as u64, source)?;
    validate_plugin_component_bytes(source, bytes).map_err(|error| match error {
        LoaderError::WasmCompileError { message, .. } => error_shape(
            ERROR_INVALID_REQUEST,
            &format!("{source} is not a valid WASM plugin component: {message}"),
            None,
        ),
        other => error_shape(
            ERROR_UNAVAILABLE,
            &format!("failed to validate {source}: {other}"),
            None,
        ),
    })
}

fn validate_plugin_wasm_size(size_bytes: u64, source: &str) -> Result<(), ErrorShape> {
    if size_bytes > MAX_PLUGIN_DOWNLOAD_BYTES as u64 {
        return Err(error_shape(
            ERROR_INVALID_REQUEST,
            &format!(
                "{source} exceeds maximum size ({} bytes > {} bytes)",
                size_bytes, MAX_PLUGIN_DOWNLOAD_BYTES
            ),
            None,
        ));
    }

    Ok(())
}

fn adopt_existing_managed_plugin_wasm(
    local_wasm_path: &Path,
) -> Result<(PathBuf, Vec<u8>, String), ErrorShape> {
    let path_metadata = match std::fs::symlink_metadata(local_wasm_path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(error_shape(
                ERROR_INVALID_REQUEST,
                "url is required unless a matching local WASM already exists in the managed plugins directory",
                None,
            ));
        }
        Err(error) => {
            return Err(error_shape(
                ERROR_UNAVAILABLE,
                &format!(
                    "failed to stat existing plugin binary at '{}': {}",
                    local_wasm_path.display(),
                    error
                ),
                None,
            ));
        }
    };
    if path_metadata.file_type().is_symlink() || !path_metadata.is_file() {
        return Err(error_shape(
            ERROR_INVALID_REQUEST,
            &format!(
                "managed plugin artifact at '{}' is not a regular file",
                local_wasm_path.display()
            ),
            None,
        ));
    }
    let mut local_wasm = match open_managed_plugin_wasm_no_follow(local_wasm_path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(error_shape(
                ERROR_INVALID_REQUEST,
                "url is required unless a matching local WASM already exists in the managed plugins directory",
                None,
            ));
        }
        Err(error) if error.kind() == std::io::ErrorKind::InvalidInput => {
            return Err(error_shape(ERROR_INVALID_REQUEST, &error.to_string(), None));
        }
        Err(error) => {
            return Err(error_shape(
                ERROR_UNAVAILABLE,
                &format!(
                    "failed to open existing plugin binary at '{}': {}",
                    local_wasm_path.display(),
                    error
                ),
                None,
            ));
        }
    };
    let wasm_metadata = local_wasm.metadata().map_err(|e| {
        error_shape(
            ERROR_UNAVAILABLE,
            &format!(
                "failed to stat existing plugin binary at '{}': {}",
                local_wasm_path.display(),
                e
            ),
            None,
        )
    })?;
    if !wasm_metadata.is_file() {
        return Err(error_shape(
            ERROR_INVALID_REQUEST,
            &format!(
                "managed plugin artifact at '{}' is not a regular file",
                local_wasm_path.display()
            ),
            None,
        ));
    }
    validate_plugin_wasm_size(wasm_metadata.len(), "existing managed plugin binary")?;
    let mut wasm_bytes = Vec::new();
    local_wasm.read_to_end(&mut wasm_bytes).map_err(|e| {
        error_shape(
            ERROR_UNAVAILABLE,
            &format!(
                "failed to read existing plugin binary at '{}': {}",
                local_wasm_path.display(),
                e
            ),
            None,
        )
    })?;
    validate_plugin_wasm_bytes(&wasm_bytes, "existing managed plugin binary")?;
    Ok((
        local_wasm_path.to_path_buf(),
        wasm_bytes.clone(),
        compute_sha256_hex(&wasm_bytes),
    ))
}

fn plugin_signature_config_from_config_value(
    cfg: &Value,
) -> Result<crate::plugins::signature::SignatureConfig, ErrorShape> {
    let Some(value) = cfg.pointer("/plugins/signature").cloned() else {
        return Ok(crate::plugins::signature::SignatureConfig::default());
    };
    serde_json::from_value(value).map_err(|error| {
        error_shape(
            ERROR_INVALID_REQUEST,
            &format!(
                "invalid plugins.signature config: {error}; use enabled, requireSignature, and trustedPublishers"
            ),
            None,
        )
    })
}

fn validate_plugin_signature_policy_for_manifest(
    plugin_name: &str,
    wasm_bytes: &[u8],
    manifest: &Value,
    cfg: &Value,
) -> Result<(), ErrorShape> {
    let signature_config = plugin_signature_config_from_config_value(cfg)?;
    crate::plugins::signature::verify_plugin_signature(
        plugin_name,
        wasm_bytes,
        manifest,
        &signature_config,
    )
    .map_err(|error| {
        error_shape(
            ERROR_INVALID_REQUEST,
            &format!("plugin signature policy rejected install/update: {error}"),
            None,
        )
    })
}

/// Validate that a URL string is a well-formed HTTP or HTTPS URL.
fn validate_url(raw: &str) -> Result<url::Url, ErrorShape> {
    let parsed = url::Url::parse(raw)
        .map_err(|e| error_shape(ERROR_INVALID_REQUEST, &format!("invalid url: {}", e), None))?;
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(error_shape(
            ERROR_INVALID_REQUEST,
            "plugin download url must not contain embedded credentials",
            None,
        ));
    }
    match parsed.scheme() {
        "http" | "https" => Ok(parsed),
        other => Err(error_shape(
            ERROR_INVALID_REQUEST,
            &format!("unsupported url scheme '{}', must be http or https", other),
            None,
        )),
    }
}

/// Read the plugins manifest JSON from the managed plugins directory.
/// Returns an empty object when the file does not exist (first-install
/// state). A present-but-corrupt manifest is a typed error rather than
/// a silent fall-back to `{}`: the install/update RMW writers reconstruct
/// the manifest from this read and persist back only the entry they're
/// touching, so a silent `{}` truncation would wipe every other managed
/// plugin's signature/sha256/publisher_key on the next install (the
/// plugin trust root). A same-uid attacker who can write to plugins_dir
/// could weaponize this: corrupt the manifest, wait for an operator
/// install, walk away with all signature anchors gone. Fail closed —
/// the operator must repair (or remove) the manifest before any further
/// install/update can proceed.
fn read_plugins_manifest(plugins_dir: &Path) -> Result<Value, ErrorShape> {
    let manifest_path = plugins_dir.join(PLUGINS_MANIFEST_FILE);
    let contents = match read_plugins_manifest_no_follow(&manifest_path)? {
        Some(contents) => contents,
        None => return Ok(json!({})),
    };
    let value: Value = serde_json::from_str(&contents).map_err(|e| {
        tracing::warn!(
            path = %manifest_path.display(),
            error = %e,
            "plugins manifest JSON is corrupt; refusing to fall back to empty \
             object so a future install/update does not silently wipe every \
             other managed plugin entry"
        );
        error_shape(
            ERROR_UNAVAILABLE,
            &format!(
                "plugins manifest is corrupt: {e}. Repair or remove \
                 the file at {} before retrying install/update.",
                manifest_path.display()
            ),
            None,
        )
    })?;
    // SECURITY (B125): also refuse a present-but-not-an-object manifest.
    // Without this, a same-uid attacker can replace the manifest contents
    // with a top-level JSON scalar/array (`42`, `"x"`, `null`, `[]`),
    // which `from_str::<Value>` parses successfully but does NOT represent
    // a valid manifest. Downstream `ensure_object(&mut manifest)` silently
    // resets a non-object to `{}` — re-introducing the exact wipe-out
    // attack B115 was meant to close (the install/update RMW reconstructs
    // the manifest from `{}` and writes back only the new entry, losing
    // every peer entry's `sha256` / `signature` / `publisherKey` /
    // `path` / `url`). Fail closed at the read site instead.
    if !value.is_object() {
        tracing::warn!(
            path = %manifest_path.display(),
            "plugins manifest JSON parses but is not a top-level object; \
             refusing to operate on a malformed manifest"
        );
        return Err(error_shape(
            ERROR_UNAVAILABLE,
            &format!(
                "plugins manifest at {} parses but is not a top-level JSON \
                 object; this would silently wipe peer plugin entries if \
                 the install/update reconstructor accepted it. Repair or \
                 remove the file before retrying install/update.",
                manifest_path.display()
            ),
            None,
        ));
    }
    Ok(value)
}

fn read_plugins_manifest_no_follow(manifest_path: &Path) -> Result<Option<String>, ErrorShape> {
    read_managed_plugins_manifest_no_follow(manifest_path).map_err(|e| {
        tracing::warn!(
            path = %manifest_path.display(),
            error = %e,
            "failed to read plugins manifest"
        );
        if e.kind() == std::io::ErrorKind::InvalidInput {
            error_shape(ERROR_INVALID_REQUEST, &e.to_string(), None)
        } else {
            error_shape(
                ERROR_UNAVAILABLE,
                &format!("failed to read plugins manifest: {e}"),
                None,
            )
        }
    })
}

/// Write the plugins manifest JSON to the managed plugins directory using atomic
/// tmp + rename.
fn write_plugins_manifest(plugins_dir: &Path, manifest: &Value) -> Result<(), ErrorShape> {
    std::fs::create_dir_all(plugins_dir).map_err(|e| {
        error_shape(
            ERROR_UNAVAILABLE,
            &format!("failed to create plugins directory: {}", e),
            None,
        )
    })?;

    let manifest_path = plugins_dir.join(PLUGINS_MANIFEST_FILE);
    let tmp_path = unique_plugins_tmp_path(plugins_dir, PLUGINS_MANIFEST_FILE);

    let content = serde_json::to_string_pretty(manifest).map_err(|e| {
        error_shape(
            ERROR_UNAVAILABLE,
            &format!("failed to serialize manifest: {}", e),
            None,
        )
    })?;
    let mut bytes = content.into_bytes();
    bytes.push(b'\n');
    // Fail-closed at write time so a corrupt over-size manifest can
    // never reach disk. Without this, the bootstrap read path on
    // the next start would reject the whole manifest and mark every
    // managed plugin as Failed with the same generic
    // "invalid manifest" error — an operationally-catastrophic
    // blanket failure for what may be a single bad entry. Bound at
    // the same cap the loader enforces so write and read agree.
    if bytes.len() as u64 > MAX_MANAGED_PLUGIN_MANIFEST_BYTES {
        return Err(error_shape(
            ERROR_INVALID_REQUEST,
            &format!(
                "plugins manifest exceeds maximum size ({} bytes > {} bytes); \
                 refuse to write a manifest the bootstrap loader would reject",
                bytes.len(),
                MAX_MANAGED_PLUGIN_MANIFEST_BYTES
            ),
            None,
        ));
    }
    write_atomic_plugins_file(&tmp_path, &manifest_path, &bytes, "plugins manifest")?;
    Ok(())
}

fn unique_plugins_tmp_path(plugins_dir: &Path, file_name: &str) -> PathBuf {
    plugins_dir.join(format!(".{}.{}.tmp", file_name, uuid::Uuid::new_v4()))
}

fn open_plugins_tmp_file(tmp_path: &Path, file_label: &str) -> Result<std::fs::File, ErrorShape> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        options.mode(0o600);
        options.custom_flags(libc::O_NOFOLLOW);
    }
    options.open(tmp_path).map_err(|e| {
        error_shape(
            ERROR_UNAVAILABLE,
            &format!("failed to write {file_label}: {e}"),
            None,
        )
    })
}

fn write_atomic_plugins_file(
    tmp_path: &Path,
    dest_path: &Path,
    bytes: &[u8],
    label: &str,
) -> Result<(), ErrorShape> {
    let mut file = open_plugins_tmp_file(tmp_path, label)?;
    if let Err(err) = (|| {
        file.write_all(bytes).map_err(|e| {
            error_shape(
                ERROR_UNAVAILABLE,
                &format!("failed to write {label}: {e}"),
                None,
            )
        })?;
        file.sync_all().map_err(|e| {
            error_shape(
                ERROR_UNAVAILABLE,
                &format!("failed to sync {label}: {e}"),
                None,
            )
        })?;
        Ok::<(), ErrorShape>(())
    })() {
        log_plugins_tmp_cleanup_failure(tmp_path, label);
        return Err(err);
    }

    if let Err(e) = std::fs::rename(tmp_path, dest_path) {
        log_plugins_tmp_cleanup_failure(tmp_path, label);
        return Err(error_shape(
            ERROR_UNAVAILABLE,
            &format!("failed to replace {label}: {e}"),
            None,
        ));
    }
    crate::paths::sync_parent_dir_blocking(dest_path).map_err(|e| {
        error_shape(
            ERROR_UNAVAILABLE,
            &format!("failed to sync {label} parent directory: {e}"),
            None,
        )
    })?;
    Ok(())
}

fn log_plugins_tmp_cleanup_failure(tmp_path: &Path, label: &str) {
    if let Err(cleanup_error) = std::fs::remove_file(tmp_path) {
        if cleanup_error.kind() == std::io::ErrorKind::NotFound {
            return;
        }
        tracing::warn!(
            path = %tmp_path.display(),
            %label,
            %cleanup_error,
            "failed to clean up temporary plugin file"
        );
    }
}

fn validate_transaction_restore_path(
    path: &Path,
    label: &str,
    max_len: u64,
    allow_missing: bool,
) -> Result<(), ErrorShape> {
    match validate_managed_plugin_path_no_follow(path, label, max_len) {
        Ok(()) => Ok(()),
        Err(error) if allow_missing && error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error_shape(
            ERROR_INVALID_REQUEST,
            &format!("refusing to roll back {label}: {error}"),
            None,
        )),
    }
}

fn open_transaction_restore_backup(
    path: &Path,
    label: &str,
    max_len: u64,
) -> Result<std::fs::File, ErrorShape> {
    open_managed_plugin_path_no_follow(path, label, max_len).map_err(|error| {
        error_shape(
            ERROR_INVALID_REQUEST,
            &format!("refusing to roll back {label}: {error}"),
            None,
        )
    })
}

#[cfg(test)]
fn run_transaction_restore_after_backup_open_hook(backup: &Path, dest: &Path) {
    if let Some(hook) = TRANSACTION_RESTORE_AFTER_BACKUP_OPEN_HOOK.lock().as_ref() {
        hook(backup, dest);
    }
}

#[cfg(not(test))]
fn run_transaction_restore_after_backup_open_hook(_backup: &Path, _dest: &Path) {}

fn write_opened_transaction_backup_to_tmp(
    backup_file: &mut std::fs::File,
    tmp_path: &Path,
    label: &str,
) -> Result<(), ErrorShape> {
    let mut tmp_file = open_plugins_tmp_file(tmp_path, &format!("rolled back {label}"))?;
    if let Err(err) = std::io::copy(backup_file, &mut tmp_file).map_err(|e| {
        error_shape(
            ERROR_UNAVAILABLE,
            &format!("failed to copy {label} backup for rollback: {e}"),
            None,
        )
    }) {
        log_plugins_tmp_cleanup_failure(tmp_path, label);
        return Err(err);
    }
    if let Err(err) = tmp_file.sync_all().map_err(|e| {
        error_shape(
            ERROR_UNAVAILABLE,
            &format!("failed to sync rolled back {label}: {e}"),
            None,
        )
    }) {
        log_plugins_tmp_cleanup_failure(tmp_path, label);
        return Err(err);
    }
    Ok(())
}

// Used by the Windows fallback in `cleanup_restored_transaction_backup_path_based`.
#[cfg_attr(unix, allow(dead_code))]
fn metadata_matches_opened_transaction_backup(
    path_metadata: &std::fs::Metadata,
    opened_metadata: &std::fs::Metadata,
) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        path_metadata.dev() == opened_metadata.dev() && path_metadata.ino() == opened_metadata.ino()
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        path_metadata.volume_serial_number() == opened_metadata.volume_serial_number()
            && path_metadata.file_index() == opened_metadata.file_index()
    }
    #[cfg(all(not(unix), not(windows)))]
    {
        let _ = (path_metadata, opened_metadata);
        false
    }
}

fn cleanup_restored_transaction_backup(
    backup: &Path,
    opened_metadata: &std::fs::Metadata,
    label: &str,
) {
    #[cfg(unix)]
    {
        cleanup_restored_transaction_backup_unix(backup, opened_metadata, label);
    }
    #[cfg(not(unix))]
    {
        cleanup_restored_transaction_backup_path_based(backup, opened_metadata, label);
    }
}

#[cfg(unix)]
fn cleanup_restored_transaction_backup_unix(
    backup: &Path,
    opened_metadata: &std::fs::Metadata,
    label: &str,
) {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::io::AsRawFd;
    let (parent, file_name) = match (backup.parent(), backup.file_name()) {
        (Some(parent), Some(name)) => (parent, name),
        _ => {
            tracing::warn!(
                path = %backup.display(),
                %label,
                "skipping plugin rollback backup cleanup because the path has no parent or file name"
            );
            return;
        }
    };
    // Open the parent directory with `O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC`
    // so the fstatat/unlinkat below resolve against this specific
    // dirent table — not a path that an attacker can swap between
    // the identity check and the unlink. This eliminates the
    // path-based TOCTOU that existed when both `symlink_metadata`
    // and `remove_file` resolved the backup path independently.
    let dir_fd = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(parent)
    {
        Ok(fd) => fd,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return,
        Err(err) => {
            tracing::warn!(
                path = %backup.display(),
                %label,
                %err,
                "failed to open parent directory of plugin transaction backup for cleanup"
            );
            return;
        }
    };
    let name_cstr = match CString::new(file_name.as_bytes()) {
        Ok(cstr) => cstr,
        Err(_) => {
            tracing::warn!(
                path = %backup.display(),
                %label,
                "skipping plugin rollback backup cleanup because the file name contains a NUL byte"
            );
            return;
        }
    };
    // SAFETY: `libc::stat` is `repr(C)` POD; the immediate `fstatat`
    // below overwrites the buffer before any field is read, and the
    // `rc != 0` short-circuit returns before any read on the
    // syscall-failed branch. All-zero is a valid initial state for a
    // C POD struct.
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    let rc = unsafe {
        libc::fstatat(
            dir_fd.as_raw_fd(),
            name_cstr.as_ptr(),
            &mut stat,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if rc != 0 {
        let err = std::io::Error::last_os_error();
        if err.kind() == std::io::ErrorKind::NotFound {
            return;
        }
        tracing::warn!(
            path = %backup.display(),
            %label,
            %err,
            "failed to stat plugin transaction backup for cleanup"
        );
        return;
    }
    // `libc::stat.st_dev` and `st_ino` are typed differently across
    // platforms (u64 on Linux, dev_t/ino_t aliases on macOS that
    // expand to different widths). The `as u64` coercions are
    // necessary on macOS and a no-op on Linux — clippy flags the
    // Linux case as redundant.
    #[allow(clippy::unnecessary_cast)]
    let st_dev = stat.st_dev as u64;
    #[allow(clippy::unnecessary_cast)]
    let st_ino = stat.st_ino as u64;
    if st_dev != opened_metadata.dev() || st_ino != opened_metadata.ino() {
        tracing::warn!(
            path = %backup.display(),
            %label,
            "skipping plugin rollback backup cleanup because the path identity changed"
        );
        return;
    }
    let rc = unsafe { libc::unlinkat(dir_fd.as_raw_fd(), name_cstr.as_ptr(), 0) };
    if rc != 0 {
        let err = std::io::Error::last_os_error();
        if err.kind() != std::io::ErrorKind::NotFound {
            tracing::warn!(
                path = %backup.display(),
                %label,
                %err,
                "failed to remove restored plugin transaction backup"
            );
        }
        return;
    }
    if let Err(err) = crate::paths::sync_parent_dir_blocking(backup) {
        tracing::warn!(
            path = %backup.display(),
            %label,
            %err,
            "failed to sync restored plugin transaction backup cleanup"
        );
    }
}

#[cfg(not(unix))]
fn cleanup_restored_transaction_backup_path_based(
    backup: &Path,
    opened_metadata: &std::fs::Metadata,
    label: &str,
) {
    // Windows fallback: no unlinkat. Best-effort path-based cleanup
    // with the same identity check. The TOCTOU window between
    // `symlink_metadata` and `remove_file` is narrow but not
    // eliminated; on Windows it is bounded by the surrounding
    // tmp+rename discipline.
    match std::fs::symlink_metadata(backup) {
        Ok(path_metadata)
            if metadata_matches_opened_transaction_backup(&path_metadata, opened_metadata) =>
        {
            match std::fs::remove_file(backup) {
                Ok(()) => {
                    if let Err(err) = crate::paths::sync_parent_dir_blocking(backup) {
                        tracing::warn!(
                            path = %backup.display(),
                            %label,
                            %err,
                            "failed to sync restored plugin transaction backup cleanup"
                        );
                    }
                }
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                Err(err) => {
                    tracing::warn!(
                        path = %backup.display(),
                        %label,
                        %err,
                        "failed to remove restored plugin transaction backup"
                    );
                }
            }
        }
        Ok(_) => {
            tracing::warn!(
                path = %backup.display(),
                %label,
                "skipping plugin rollback backup cleanup because the path identity changed"
            );
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => {
            tracing::warn!(
                path = %backup.display(),
                %label,
                %err,
                "failed to inspect restored plugin transaction backup for cleanup"
            );
        }
    }
}

fn restore_transaction_backup(
    backup: &Path,
    dest: &Path,
    label: &str,
    max_len: u64,
) -> Result<(), ErrorShape> {
    let mut backup_file =
        open_transaction_restore_backup(backup, &format!("{label} backup"), max_len)?;
    let backup_metadata = backup_file.metadata().map_err(|e| {
        error_shape(
            ERROR_UNAVAILABLE,
            &format!("failed to inspect opened {label} backup for rollback: {e}"),
            None,
        )
    })?;
    validate_transaction_restore_path(dest, label, max_len, true)?;
    run_transaction_restore_after_backup_open_hook(backup, dest);

    let dest_parent = dest.parent().ok_or_else(|| {
        error_shape(
            ERROR_INVALID_REQUEST,
            &format!("refusing to roll back {label}: destination has no parent directory"),
            None,
        )
    })?;
    let dest_name = dest
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("plugin-rollback");
    let tmp_path = unique_plugins_tmp_path(dest_parent, &format!("{dest_name}.rollback"));
    write_opened_transaction_backup_to_tmp(&mut backup_file, &tmp_path, label)?;

    if let Err(e) = std::fs::rename(&tmp_path, dest) {
        log_plugins_tmp_cleanup_failure(&tmp_path, label);
        return Err(error_shape(
            ERROR_UNAVAILABLE,
            &format!("failed to roll back {label} from backup: {e}"),
            None,
        ));
    }
    crate::paths::sync_parent_dir_blocking(dest).map_err(|e| {
        error_shape(
            ERROR_UNAVAILABLE,
            &format!("failed to sync rolled back {label} parent directory: {e}"),
            None,
        )
    })?;
    cleanup_restored_transaction_backup(backup, &backup_metadata, label);
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
fn validate_and_resolve_dns(
    url: &url::Url,
    ssrf_config: &SsrfConfig,
) -> Result<(String, u16, Option<IpAddr>), ErrorShape> {
    // Validate URL against SSRF attacks (blocks localhost, private IPs, metadata endpoints)
    SsrfProtection::validate_url_with_config(url.as_str(), ssrf_config).map_err(|e| {
        error_shape(
            ERROR_INVALID_REQUEST,
            &format!("plugin download URL blocked by SSRF protection: {}", e),
            None,
        )
    })?;

    let host = url
        .host_str()
        .ok_or_else(|| {
            error_shape(
                ERROR_INVALID_REQUEST,
                "plugin download URL has no host",
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
        let host_for_lookup = host.clone();
        let ssrf_config = ssrf_config.clone();
        let ip = run_sync_blocking_send(async move {
            let resolver = TokioResolver::builder_tokio()
                .and_then(|builder| builder.build())
                .map_err(|e| {
                    PluginDnsError::Unavailable(format!("DNS resolver initialization failed: {e}"))
                })?;

            let lookup = resolver.lookup_ip(&host_for_lookup).await.map_err(|e| {
                PluginDnsError::Unavailable(format!(
                    "DNS resolution failed for {}: {}",
                    host_for_lookup, e
                ))
            })?;

            let mut first_valid: Option<IpAddr> = None;
            for ip in lookup.iter() {
                SsrfProtection::validate_resolved_ip_with_config(
                    &ip,
                    &host_for_lookup,
                    &ssrf_config,
                )
                .map_err(|e| {
                    PluginDnsError::InvalidRequest(format!(
                        "plugin download blocked by DNS rebinding protection: {}",
                        e
                    ))
                })?;
                if first_valid.is_none() {
                    first_valid = Some(ip);
                }
            }

            first_valid.ok_or_else(|| {
                PluginDnsError::Unavailable(format!(
                    "DNS resolution returned no addresses for {}",
                    host_for_lookup
                ))
            })
        })
        .map_err(|err| match err {
            BridgeError::Inner(inner) => inner.into_error_shape(),
            other => error_shape(ERROR_UNAVAILABLE, &other.to_string(), None),
        })?;

        tracing::debug!(
            url = %url,
            host = %host,
            resolved_ip = %ip,
            "DNS resolved and validated for plugin download"
        );

        Some(ip)
    };

    Ok((host, port, resolved_ip))
}

/// Build an HTTP client pinned to the validated IP (if any) and download the WASM
/// binary. Validates response status, size limit, and component requirements.
fn download_with_pinned_ip(
    url: &url::Url,
    host: &str,
    port: u16,
    resolved_ip: Option<IpAddr>,
) -> Result<bytes::Bytes, ErrorShape> {
    let mut client_builder = reqwest::blocking::Client::builder()
        .timeout(PLUGIN_DOWNLOAD_TIMEOUT)
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

    let mut response = client.get(url.as_str()).send().map_err(|e| {
        // SECURITY: scrub the URL from the reqwest error Display. Plugin
        // install/update URLs are operator-supplied, but operator-visible
        // error logs may be shipped off-box (journald, log aggregators,
        // alerting webhooks) where an operator's plugin source URL
        // unnecessarily lands in third-party systems. `e.without_url()`
        // keeps the failure class signal (timeout, connect refused, dns
        // failure) without the URL itself.
        error_shape(
            ERROR_UNAVAILABLE,
            &format!("failed to download plugin: {}", e.without_url()),
            None,
        )
    })?;

    if !response.status().is_success() {
        return Err(error_shape(
            ERROR_UNAVAILABLE,
            &format!(
                "plugin download failed with HTTP {}",
                response.status().as_u16()
            ),
            None,
        ));
    }

    // SECURITY: enforce the size cap BEFORE buffering, not after.
    // The pre-fix path called `response.bytes()` which buffers the
    // entire body into memory before `validate_plugin_wasm_bytes`
    // checks `MAX_PLUGIN_DOWNLOAD_BYTES`. A malicious plugin server
    // could stream a multi-GB body over the 60s PLUGIN_DOWNLOAD_TIMEOUT
    // (≈7.5 GB at 1 Gbps) and OOM the daemon before the cap fires.
    // Two-layer defense:
    //   1. Pre-flight `Content-Length` rejection — covers honest servers.
    //   2. `read_capped_into` helper (Read::take(cap + 1) +
    //      read_to_end + post-read overflow check) so a chunked-
    //      encoding or lying-Content-Length response is bounded
    //      mid-stream at cap+1 bytes.
    if let Some(declared_len) = response.content_length() {
        if declared_len > MAX_PLUGIN_DOWNLOAD_BYTES as u64 {
            return Err(error_shape(
                ERROR_INVALID_REQUEST,
                &format!(
                    "plugin download declares {} bytes which exceeds the {} byte cap",
                    declared_len, MAX_PLUGIN_DOWNLOAD_BYTES
                ),
                None,
            ));
        }
    }
    // Bounded read via the shared `read_capped_into` helper — wraps
    // `Read::take(cap + 1) + read_to_end` + post-read overflow check
    // so a chunked or lying-Content-Length response is bounded
    // mid-stream. The helper's unit tests in `src/net_util.rs` pin
    // the at-cap / over-cap / large-source behaviors; centralizing
    // the pattern means a future regression in this cap-enforcement
    // shape gets caught by the helper tests without needing a full
    // HTTP-server fixture for each call site.
    let mut buf: Vec<u8> = Vec::new();
    let outcome = crate::net_util::read_capped_into(
        &mut response,
        &mut buf,
        MAX_PLUGIN_DOWNLOAD_BYTES as u64,
    )
    .map_err(|e| match e {
        // SECURITY: route `Misconfigured` (caller-side misuse — cap ==
        // u64::MAX) to `ERROR_INVALID_REQUEST` so a future refactor
        // that lets `MAX_PLUGIN_DOWNLOAD_BYTES` come from a config
        // knob and reaches u64::MAX does NOT silently re-classify as a
        // transient availability blip the UI keeps retrying.
        // `ReadCappedError::Transport` exposes only `io::ErrorKind`,
        // never the full `io::Error` whose Display would render the
        // wrapped `reqwest::Error` (URL-bearing) and re-leak the
        // operator-supplied plugin URL.
        crate::net_util::ReadCappedError::Misconfigured => error_shape(
            ERROR_INVALID_REQUEST,
            &format!("plugin download cap is misconfigured: {e}"),
            None,
        ),
        crate::net_util::ReadCappedError::Transport(kind) => error_shape(
            ERROR_UNAVAILABLE,
            &format!("failed to read plugin download body: {kind:?}"),
            None,
        ),
    })?;
    if outcome == crate::net_util::ReadCappedOutcome::Overflow {
        return Err(error_shape(
            ERROR_INVALID_REQUEST,
            &format!(
                "plugin download exceeded {} byte cap mid-stream (server lied about Content-Length or used chunked encoding)",
                MAX_PLUGIN_DOWNLOAD_BYTES
            ),
            None,
        ));
    }
    let bytes = bytes::Bytes::from(buf);

    validate_plugin_wasm_bytes(&bytes, "downloaded plugin")?;

    Ok(bytes)
}

/// Write the downloaded bytes to a temporary file, fsync, then atomically rename
/// into the final destination.  Returns the final file path.
fn atomic_write_plugin_file(
    plugins_dir: &Path,
    file_name: &str,
    bytes: &[u8],
) -> Result<PathBuf, ErrorShape> {
    let dest_path = plugins_dir.join(file_name);
    let tmp_path = unique_plugins_tmp_path(plugins_dir, file_name);

    write_atomic_plugins_file(&tmp_path, &dest_path, bytes, "plugin binary")?;

    Ok(dest_path)
}

/// Download a WASM binary from the given URL and save it atomically to the plugins
/// directory.  Returns the final file path and the raw bytes on success.
/// Download a plugin WASM binary without writing it to disk.
///
/// Returns the raw bytes after DNS validation and SSRF checks.
/// Combined download+write for tests that need the old behavior.
#[cfg(test)]
fn download_plugin_wasm(
    url: &url::Url,
    plugins_dir: &Path,
    file_name: &str,
) -> Result<(PathBuf, Vec<u8>), ErrorShape> {
    let bytes = download_plugin_wasm_bytes(url, plugins_dir, &SsrfConfig::default())?;
    let dest = atomic_write_plugin_file(plugins_dir, file_name, &bytes)?;
    Ok((dest, bytes))
}

/// The caller is responsible for writing the bytes via
/// `atomic_write_plugin_file` at the appropriate transactional point.
fn download_plugin_wasm_bytes(
    url: &url::Url,
    plugins_dir: &Path,
    ssrf_config: &SsrfConfig,
) -> Result<Vec<u8>, ErrorShape> {
    let (host, port, resolved_ip) = validate_and_resolve_dns(url, ssrf_config)?;

    std::fs::create_dir_all(plugins_dir).map_err(|e| {
        error_shape(
            ERROR_UNAVAILABLE,
            &format!("failed to create plugins directory: {}", e),
            None,
        )
    })?;

    let bytes = download_with_pinned_ip(url, &host, port, resolved_ip)?;
    Ok(bytes.to_vec())
}

pub(super) fn handle_plugins_status(state: &WsServerState) -> Result<Value, ErrorShape> {
    let cfg = config::load_config().unwrap_or(Value::Object(serde_json::Map::new()));
    let (
        plugins_enabled,
        configured_path_count,
        activation_error_count,
        plugins_arr,
        restart_required,
    ) = if let Some(report) = state.plugin_activation_report() {
        let failed_plugin_count = report
            .entries
            .iter()
            .filter(|entry| {
                entry.state == crate::server::plugin_bootstrap::PluginActivationState::Failed
            })
            .count();
        (
            report.enabled,
            report.configured_paths.len(),
            report.errors.len() + failed_plugin_count,
            build_plugins_array_from_report_and_config(report, &cfg),
            report.restart_required_for_changes,
        )
    } else {
        (
            cfg.pointer("/plugins/enabled")
                .and_then(|value| value.as_bool())
                .unwrap_or(true),
            crate::server::plugin_bootstrap::configured_plugin_paths(&cfg).len(),
            0usize,
            build_plugins_array(&cfg),
            true,
        )
    };

    Ok(json!({
        "pluginsEnabled": plugins_enabled,
        "configuredPluginPathCount": configured_path_count,
        "restartRequiredForChanges": restart_required,
        "activationErrorCount": activation_error_count,
        "plugins": plugins_arr
    }))
}

/// Build a JSON array of plugin entries from the config's `plugins.entries` map.
fn build_plugins_array(cfg: &Value) -> Vec<Value> {
    let entries = match cfg
        .get("plugins")
        .and_then(|s| s.get("entries"))
        .and_then(|e| e.as_object())
    {
        Some(map) => map,
        None => return Vec::new(),
    };

    entries
        .iter()
        .filter_map(|(key, entry)| {
            let entry = entry.as_object()?;
            let unexpected_fields = entry
                .keys()
                .filter(|field| !matches!(field.as_str(), "enabled" | "installId" | "requestedAt"))
                .cloned()
                .collect::<Vec<_>>();
            if !unexpected_fields.is_empty() {
                tracing::warn!(
                    name = %key,
                    unexpected_fields = ?unexpected_fields,
                    "skipping plugins.entries entry with unexpected fields"
                );
                return None;
            }
            Some(json!({
                "name": key,
                "enabled": entry.get("enabled").and_then(|v| v.as_bool()).unwrap_or(true),
                "installId": entry.get("installId").cloned().unwrap_or(Value::Null),
                "requestedAt": entry.get("requestedAt").cloned().unwrap_or(Value::Null),
            }))
        })
        .collect()
}

fn token_looks_like_filesystem_path(token: &str) -> bool {
    token.starts_with('/')
        || token.starts_with("./")
        || token.starts_with("../")
        || token.starts_with("~/")
        || (token.len() > 2
            && token.as_bytes()[1] == b':'
            && matches!(token.as_bytes()[2], b'\\' | b'/'))
        || (token.contains('\\') && !token.contains(':'))
}

fn sanitize_activation_reason(reason: &str) -> String {
    if reason.starts_with("failed to read configured plugin path ") {
        return "configured plugin directory is unreadable".to_string();
    }
    if reason.starts_with("failed to resolve managed plugin directory ") {
        return "failed to resolve managed plugin directory".to_string();
    }
    if reason.starts_with("failed to resolve ") {
        return "failed to resolve plugin artifact path".to_string();
    }
    if reason.starts_with("Failed to read WASM file ") {
        return "failed to read WASM plugin artifact".to_string();
    }
    if reason.starts_with("Failed to compile WASM component ") {
        return "failed to compile WASM plugin component".to_string();
    }
    if reason
        .split_whitespace()
        .any(token_looks_like_filesystem_path)
    {
        return "plugin activation failed; see server logs for details".to_string();
    }
    reason.to_string()
}

fn build_plugins_array_from_report(
    report: &crate::server::plugin_bootstrap::PluginActivationReport,
) -> Vec<Value> {
    report
        .entries
        .iter()
        .map(|entry| {
            json!({
                "name": entry.name,
                "pluginId": entry.plugin_id,
                "enabled": entry.enabled,
                "installId": entry.install_id.clone().unwrap_or(Value::Null),
                "requestedAt": entry.requested_at.map(Value::from).unwrap_or(Value::Null),
                "source": entry.source.label(),
                "state": entry.state.label(),
                "reason": entry.reason.as_deref().map(sanitize_activation_reason),
            })
        })
        .collect()
}

fn pending_plugin_value(plugin: &Value) -> Value {
    let enabled = plugin
        .get("enabled")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    json!({
        "name": plugin.get("name").cloned().unwrap_or(Value::Null),
        "pluginId": Value::Null,
        "enabled": enabled,
        "installId": plugin.get("installId").cloned().unwrap_or(Value::Null),
        "requestedAt": plugin.get("requestedAt").cloned().unwrap_or(Value::Null),
        "source": crate::server::plugin_bootstrap::PluginActivationSource::Managed.label(),
        "state": if enabled {
            crate::server::plugin_bootstrap::PluginActivationState::Ignored.label()
        } else {
            crate::server::plugin_bootstrap::PluginActivationState::Disabled.label()
        },
        "reason": if enabled {
            Value::String("plugin is configured and will activate after restart".to_string())
        } else {
            Value::String("managed plugin is disabled in plugins.entries".to_string())
        },
    })
}

fn merge_managed_plugin_config(existing: &mut Value, plugin: &Value) {
    // The activation report is a startup-time snapshot. `plugins.status` refreshes
    // these config-owned fields so post-startup installs/enables show the current
    // desired state even though activation itself still requires restart.
    let enabled = plugin
        .get("enabled")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    let previous_enabled = existing
        .get("enabled")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    let previous_state = existing
        .get("state")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();

    existing["enabled"] = Value::Bool(enabled);
    existing["installId"] = plugin.get("installId").cloned().unwrap_or(Value::Null);
    existing["requestedAt"] = plugin.get("requestedAt").cloned().unwrap_or(Value::Null);

    if enabled == previous_enabled {
        return;
    }

    if enabled {
        let pending = pending_plugin_value(plugin);
        existing["state"] = pending["state"].clone();
        existing["reason"] = pending["reason"].clone();
        return;
    }

    existing["state"] = Value::String(
        crate::server::plugin_bootstrap::PluginActivationState::Disabled
            .label()
            .to_string(),
    );
    existing["reason"] = Value::String(
        if previous_state == crate::server::plugin_bootstrap::PluginActivationState::Active.label()
        {
            "managed plugin is currently active and will be disabled after restart".to_string()
        } else {
            "managed plugin is disabled in plugins.entries".to_string()
        },
    );
}

fn mark_removed_managed_plugin(existing: &mut Value) {
    let previous_state = existing
        .get("state")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();

    existing["enabled"] = Value::Bool(false);
    existing["installId"] = Value::Null;
    existing["requestedAt"] = Value::Null;
    existing["state"] = Value::String(
        crate::server::plugin_bootstrap::PluginActivationState::Disabled
            .label()
            .to_string(),
    );
    existing["reason"] = Value::String(
        if previous_state == crate::server::plugin_bootstrap::PluginActivationState::Active.label()
        {
            "managed plugin is currently active and will be removed after restart".to_string()
        } else {
            "managed plugin has been removed from plugins.entries and will stay inactive after restart"
                .to_string()
        },
    );
}

fn is_stray_managed_plugin(existing: &Value) -> bool {
    existing.get("source").and_then(Value::as_str)
        == Some(crate::server::plugin_bootstrap::PluginActivationSource::Managed.label())
        && existing.get("enabled").and_then(Value::as_bool) == Some(false)
        && (existing.get("pluginId").is_none()
            || existing.get("pluginId").is_some_and(Value::is_null))
        && existing.get("state").and_then(Value::as_str)
            == Some(crate::server::plugin_bootstrap::PluginActivationState::Ignored.label())
        && (existing.get("installId").is_none()
            || existing.get("installId").is_some_and(Value::is_null))
        && (existing.get("requestedAt").is_none()
            || existing.get("requestedAt").is_some_and(Value::is_null))
}

fn build_plugins_array_from_report_and_config(
    report: &crate::server::plugin_bootstrap::PluginActivationReport,
    cfg: &Value,
) -> Vec<Value> {
    let mut by_name: BTreeMap<String, Vec<Value>> = BTreeMap::new();
    for plugin in build_plugins_array_from_report(report) {
        let Some(name) = plugin.get("name").and_then(Value::as_str) else {
            continue;
        };
        by_name.entry(name.to_string()).or_default().push(plugin);
    }

    let config_plugins = build_plugins_array(cfg);
    let configured_names = config_plugins
        .iter()
        .filter_map(|plugin| plugin.get("name").and_then(Value::as_str))
        .map(str::to_string)
        .collect::<std::collections::HashSet<_>>();

    for plugin in config_plugins {
        let Some(name) = plugin.get("name").and_then(Value::as_str) else {
            continue;
        };
        if let Some(existing_plugins) = by_name.get_mut(name) {
            if let Some(existing) = existing_plugins.iter_mut().find(|entry| {
                // Config-backed merge only targets the managed entry for a plugin name.
                // Config-path rows are runtime observations/conflicts and stay separate.
                // There should be at most one managed row per plugin name because startup
                // only emits one managed activation entry per configured plugin.
                entry.get("source").and_then(Value::as_str)
                    == Some(
                        crate::server::plugin_bootstrap::PluginActivationSource::Managed.label(),
                    )
            }) {
                merge_managed_plugin_config(existing, &plugin);
            } else {
                existing_plugins.push(pending_plugin_value(&plugin));
            }
        } else {
            by_name.insert(name.to_string(), vec![pending_plugin_value(&plugin)]);
        }
    }

    for (name, plugins) in &mut by_name {
        if configured_names.contains(name) {
            continue;
        }
        for existing in plugins.iter_mut().filter(|entry| {
            entry.get("source").and_then(Value::as_str)
                == Some(crate::server::plugin_bootstrap::PluginActivationSource::Managed.label())
        }) {
            if is_stray_managed_plugin(existing) {
                continue;
            }
            mark_removed_managed_plugin(existing);
        }
    }

    by_name
        .into_values()
        .flat_map(|plugins| plugins.into_iter())
        .collect()
}

pub(super) fn handle_plugins_bins() -> Result<Value, ErrorShape> {
    let managed_plugins_dir = resolve_plugins_dir();

    let bins = scan_plugins_bins(&managed_plugins_dir);

    Ok(json!({ "bins": bins }))
}

/// Scan the managed plugins directory for binary files.
/// Returns an empty vec if the directory does not exist or cannot be read.
fn scan_plugins_bins(dir: &std::path::Path) -> Vec<Value> {
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
        // Only include managed plugin artifacts (skip subdirectories and metadata files).
        let Some(file_name) = entry.file_name().to_str().map(str::to_string) else {
            continue;
        };
        let Some(stem) = path.file_stem().and_then(|value| value.to_str()) else {
            continue;
        };
        if validate_managed_plugin_name(stem).is_err() {
            continue;
        }
        if crate::plugins::open_managed_plugin_wasm_no_follow(&path).is_ok()
            && path
                .extension()
                .and_then(|extension| extension.to_str())
                .is_some_and(|extension| extension.eq_ignore_ascii_case("wasm"))
        {
            bins.push(json!({ "name": file_name }));
        }
    }
    bins
}

// ---------------------------------------------------------------------------
// Transactional write support for managed plugin install/update
// ---------------------------------------------------------------------------

/// Backup and rollback support for the multi-file write sequence in managed
/// plugin install/update operations.
///
/// Write order: artifact → manifest → config. If any write fails after a
/// previous one committed, the earlier writes are rolled back from backups.
struct PluginWriteTransaction {
    plugins_dir: PathBuf,
    plugin_name: String,
    artifact_backup: Option<PathBuf>,
    manifest_backup: Option<PathBuf>,
    /// Whether the artifact was written by this transaction (for rollback
    /// of first-install where no backup exists).
    artifact_written: bool,
    /// Set by `commit()` once the transaction's downstream config write
    /// has succeeded and `commit()` has run. The `Drop` impl
    /// uses this to distinguish "explicitly committed" (no rollback)
    /// from "dropped without commit" (likely a panic between artifact
    /// write and the explicit commit at the bottom of
    /// `handle_plugins_install_inner_with_downloader` /
    /// `handle_plugins_update_inner_with_downloader`). The panic path
    /// is the gap C5's HIGH finding flagged: without Drop-driven
    /// rollback, a panic inside `validate_plugin_signature_policy_for_manifest`,
    /// the `update_config_file_with_error_shape` closure, or any
    /// helper between artifact-write and commit would leave the live
    /// wasm + manifest pointing at the new version with `.txn-bak`
    /// backups on disk and nothing scheduled to reconcile them.
    committed: bool,
}

fn record_managed_plugin_rollback_audit(event: crate::logging::audit::AuditEvent) {
    if let Err(err) = crate::logging::audit::audit_durable_for_state_dir(resolve_state_dir(), event)
    {
        tracing::error!(
            %err,
            "failed to durably audit managed plugin rollback failure"
        );
    }
}

impl PluginWriteTransaction {
    fn new(plugins_dir: PathBuf, plugin_name: String) -> Self {
        Self {
            plugins_dir,
            plugin_name,
            artifact_backup: None,
            manifest_backup: None,
            artifact_written: false,
            committed: false,
        }
    }

    /// Back up the existing artifact before overwriting it.
    fn backup_artifact(&mut self) -> Result<(), ErrorShape> {
        let name = &self.plugin_name;
        let artifact = self.plugins_dir.join(format!("{name}.wasm"));
        let artifact_bytes = match read_managed_plugin_wasm_no_follow(&artifact) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::InvalidInput => {
                return Err(error_shape(ERROR_INVALID_REQUEST, &error.to_string(), None));
            }
            Err(error) => {
                return Err(error_shape(
                    ERROR_UNAVAILABLE,
                    &format!(
                        "failed to read plugin artifact for backup at '{}': {}",
                        artifact.display(),
                        error
                    ),
                    None,
                ));
            }
        };
        let backup = self.plugins_dir.join(format!("{name}.wasm.txn-bak"));
        write_atomic_plugins_file(
            &unique_plugins_tmp_path(&self.plugins_dir, &format!("{name}.wasm.txn-bak")),
            &backup,
            &artifact_bytes,
            "plugin artifact backup",
        )?;
        self.artifact_backup = Some(backup);
        Ok(())
    }

    /// Back up the existing manifest before overwriting it.
    fn backup_manifest(&mut self) -> Result<(), ErrorShape> {
        let manifest = self.plugins_dir.join(PLUGINS_MANIFEST_FILE);
        let Some(manifest_bytes) =
            read_plugins_manifest_no_follow(&manifest)?.map(String::into_bytes)
        else {
            return Ok(());
        };
        let backup = self
            .plugins_dir
            .join(format!("{PLUGINS_MANIFEST_FILE}.txn-bak"));
        write_atomic_plugins_file(
            &unique_plugins_tmp_path(
                &self.plugins_dir,
                &format!("{PLUGINS_MANIFEST_FILE}.txn-bak"),
            ),
            &backup,
            &manifest_bytes,
            "plugins manifest backup",
        )?;
        self.manifest_backup = Some(backup);
        Ok(())
    }

    /// Roll back the manifest to its pre-transaction state.
    ///
    /// **Best-effort follow-up.** A `restore_transaction_backup`
    /// failure here is currently demoted to a durable audit record
    /// (`ManagedPluginManifestRollbackFailed`) + a `tracing::warn!`,
    /// and the caller proceeds as if rollback succeeded. The 16 MiB
    /// manifest cap enlarges the blast radius of a swallowed failure:
    /// a manifest that fails to restore is silently lost on the live
    /// path, leaving an in-flight install/update in transactional
    /// limbo until startup reconciliation (or operator intervention).
    /// Promoting this to a hard abort means surfacing rollback
    /// failures up through `PluginWriteTransaction::commit` to the WS
    /// handler so the client sees a typed "plugin transaction
    /// abandoned, manual recovery required" error. Deferred because
    /// the change ripples through every caller of the transaction
    /// guard and crosses the WS-error-shape boundary. Tracked as a
    /// separate PR.
    fn rollback_manifest(&mut self) {
        // Take the backup path so a subsequent rollback (from Drop)
        // is a no-op — manual rollback at an Err branch must NOT
        // race with the panic-safety-net Drop rollback.
        if let Some(backup) = self.manifest_backup.take() {
            let manifest = self.plugins_dir.join(PLUGINS_MANIFEST_FILE);
            if let Err(e) = restore_transaction_backup(
                &backup,
                &manifest,
                "plugins manifest",
                MAX_MANAGED_PLUGIN_MANIFEST_BYTES,
            ) {
                record_managed_plugin_rollback_audit(
                    crate::logging::audit::AuditEvent::ManagedPluginManifestRollbackFailed {
                        plugin_id: self.plugin_name.clone(),
                        error: e.message.clone(),
                    },
                );
                tracing::warn!(
                    error = %e.message,
                    "failed to roll back plugins manifest from backup"
                );
            }
        }
    }

    /// Roll back the artifact to its pre-transaction state.
    fn rollback_artifact(&mut self) {
        let name = &self.plugin_name;
        let artifact = self.plugins_dir.join(format!("{name}.wasm"));
        if let Some(backup) = self.artifact_backup.take() {
            // Restore from backup (update case). rename atomically replaces
            // the destination on Unix — no need to remove_file first.
            if let Err(e) = restore_transaction_backup(
                &backup,
                &artifact,
                "managed plugin artifact",
                MAX_MANAGED_PLUGIN_ARTIFACT_BYTES,
            ) {
                record_managed_plugin_rollback_audit(
                    crate::logging::audit::AuditEvent::ManagedPluginArtifactRollbackFailed {
                        plugin_id: name.clone(),
                        error: e.message.clone(),
                    },
                );
                tracing::warn!(
                    error = %e.message,
                    plugin = name,
                    "failed to roll back plugin artifact from backup"
                );
            }
            // Whether restore succeeded or failed, clear artifact_written
            // so the first-install branch in Drop / re-call doesn't fire.
            self.artifact_written = false;
        } else if self.artifact_written {
            // First install — no backup, just remove the newly written file.
            if let Err(e) = std::fs::remove_file(&artifact) {
                record_managed_plugin_rollback_audit(
                    crate::logging::audit::AuditEvent::ManagedPluginFirstInstallCleanupFailed {
                        plugin_id: name.clone(),
                        error: e.to_string(),
                    },
                );
                tracing::warn!(
                    error = %e,
                    plugin = name,
                    "failed to remove newly written plugin artifact during rollback"
                );
            }
            self.artifact_written = false;
        }
    }

    /// Commit a successfully completed transaction: removes backup
    /// `.txn-bak` sidecars and marks the transaction as committed so
    /// the `Drop` impl panic-safety net does NOT attempt rollback.
    ///
    /// Best-effort `remove_file`: a successful transaction has already
    /// committed the new artifact + manifest + config; leaving backups
    /// on disk wastes space but does not endanger correctness. The
    /// daemon does not currently age out orphan `.txn-bak` sidecars
    /// at startup, so an operator with a long sequence of failing
    /// `remove_file` calls (e.g., on a filesystem where the daemon
    /// uid no longer has write to `plugins_dir`) accumulates orphans.
    /// `tracing::warn!` gives the operator a signal so the orphans
    /// can be reaped manually before they become noise.
    fn commit(&mut self) {
        if let Some(backup) = self.artifact_backup.take() {
            match std::fs::remove_file(&backup) {
                Ok(()) => {}
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                Err(err) => {
                    tracing::warn!(
                        plugin = %self.plugin_name,
                        backup_path = %backup.display(),
                        error = %err,
                        "failed to remove plugin artifact backup after successful transaction; orphan .txn-bak left in plugins dir for operator cleanup"
                    );
                }
            }
        }
        if let Some(backup) = self.manifest_backup.take() {
            match std::fs::remove_file(&backup) {
                Ok(()) => {}
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                Err(err) => {
                    tracing::warn!(
                        plugin = %self.plugin_name,
                        backup_path = %backup.display(),
                        error = %err,
                        "failed to remove plugin manifest backup after successful transaction; orphan .txn-bak left in plugins dir for operator cleanup"
                    );
                }
            }
        }
        self.artifact_written = false;
        self.committed = true;
    }
}

impl Drop for PluginWriteTransaction {
    /// Panic-safety net for rollback.
    ///
    /// A `PluginWriteTransaction` flows artifact → manifest → config
    /// writes through a hand-rolled error chain in
    /// `handle_plugins_install_inner_with_downloader` and
    /// `handle_plugins_update_inner_with_downloader`. Each Err
    /// branch calls `rollback_manifest()` / `rollback_artifact()`
    /// manually, then returns `Err`, then drops the transaction.
    ///
    /// The HIGH-finding C5 flagged a gap: a PANIC between artifact
    /// write and the final `commit()` call (panic inside
    /// `validate_plugin_signature_policy_for_manifest`, the
    /// `update_config_file_with_error_shape` closure, a helper
    /// allocation OOM, etc.) bypasses all manual rollbacks and
    /// leaves the daemon with a half-installed plugin — the live
    /// artifact + manifest point at the new version, the
    /// `.txn-bak` backups still sit on disk with the old bytes,
    /// and nothing is scheduled to reconcile the inconsistency.
    ///
    /// This `Drop` impl closes the gap by re-running rollback if
    /// the transaction was not explicitly committed. The
    /// `rollback_*` methods are `&mut self` and take their backup
    /// fields via `Option::take()`, so an Err-branch manual
    /// rollback that already cleared the fields makes this Drop a
    /// no-op — there is no double-rollback hazard.
    ///
    /// Panic-during-Drop discipline: the rollback methods invoke
    /// `restore_transaction_backup` (sync file I/O),
    /// `tracing::warn!`, and `audit_durable_for_state_dir`. The
    /// last one is itself a chain — `serde_json::to_value` +
    /// `disk_writer.write_entry` + `resolve_state_dir` + (under
    /// `audit_state_dirs_match`) `state_dir.canonicalize()`. A
    /// canonicalize on a partially-rolled-back FS state can
    /// surface unexpected errors; nothing in that chain should
    /// panic on operator-influenced state, but Drop is a hard
    /// constraint where a double-panic ABORTS the process —
    /// strictly worse than the silent leak we are trying to
    /// avoid. B122 wraps each rollback in `catch_unwind` so a
    /// panic during Drop becomes a tracing warn instead of a
    /// process abort. The next daemon start will still see the
    /// `.txn-bak` backups on disk, which a future operator-
    /// driven recovery (or the reconciliation sweep) can clean
    /// up; aborting the process loses every in-flight WS
    /// session for marginal forensic value.
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        // Manifest first, then artifact — matches the manual
        // rollback order at the Err branches in the install/update
        // handlers (manifest references artifact path, so restoring
        // manifest first leaves the daemon's on-disk manifest
        // pointing at the prior artifact bytes that the next
        // rollback step then restores).
        for (label, step) in [
            ("manifest", "rollback_manifest"),
            ("artifact", "rollback_artifact"),
        ] {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| match label {
                "manifest" => self.rollback_manifest(),
                "artifact" => self.rollback_artifact(),
                _ => {}
            }));
            if let Err(payload) = result {
                let detail = if let Some(s) = payload.downcast_ref::<&'static str>() {
                    (*s).to_string()
                } else if let Some(s) = payload.downcast_ref::<String>() {
                    s.clone()
                } else {
                    "non-string panic payload".to_string()
                };
                tracing::warn!(
                    plugin = %self.plugin_name,
                    step,
                    panic = %detail,
                    "panic during PluginWriteTransaction::drop rollback step; \
                     `.txn-bak` backups remain on disk for operator cleanup \
                     rather than abort-on-double-panic"
                );
            }
        }
    }
}

pub(super) fn handle_plugins_install(
    params: Option<&Value>,
    state: &WsServerState,
) -> Result<Value, ErrorShape> {
    handle_plugins_install_inner(
        params,
        &resolve_plugins_dir(),
        &state.config.operator_ssrf_config,
    )
}

/// Inner implementation of plugins.install, accepting a plugins directory for testability.
fn handle_plugins_install_inner(
    params: Option<&Value>,
    plugins_dir: &Path,
    ssrf_config: &SsrfConfig,
) -> Result<Value, ErrorShape> {
    handle_plugins_install_inner_with_downloader(
        params,
        plugins_dir,
        ssrf_config,
        download_plugin_wasm_bytes,
    )
}

fn handle_plugins_install_inner_with_downloader(
    params: Option<&Value>,
    plugins_dir: &Path,
    ssrf_config: &SsrfConfig,
    downloader: PluginDownloadFn,
) -> Result<Value, ErrorShape> {
    // --- Parse and validate params ---
    let name = params
        .and_then(|v| v.get("name"))
        .and_then(|v| v.as_str())
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "name is required", None))?;
    validate_plugin_name(name)?;

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
    let local_wasm_path = plugins_dir.join(&wasm_file_name);
    let installed_at = now_ms();

    // --- Phase 1: Prepare all payloads and validate config BEFORE any writes ---

    // Resolve the artifact bytes (download or read existing).
    // Download returns bytes only — no disk write yet (that happens in Phase 2).
    let (wasm_bytes_for_write, mut wasm_bytes_for_signature, mut wasm_hash) =
        if let Some(raw_url) = url_str {
            let parsed_url = validate_url(raw_url)?;
            let wasm_bytes = downloader(&parsed_url, plugins_dir, ssrf_config)?;
            let hash = compute_sha256_hex(&wasm_bytes);
            (Some(wasm_bytes.clone()), wasm_bytes, hash)
        } else {
            (None, Vec::new(), String::new()) // None = no write needed, artifact already in place
        };

    let _manifest_guard = PLUGINS_MANIFEST_RMW_LOCK.lock();
    // SECURITY: download-driven daemon installs must coordinate with the
    // CLI's `<dest>.cli-lock` sidecar so a `cara plugins install --file`
    // in flight (CLI process holding the lock) cannot have its newly-
    // renamed wasm bytes silently overwritten by a concurrent WS install.
    // Adopt path (url_str.is_none()) intentionally skips: in that flow
    // the CLI is the lock holder and the daemon is reading its bytes.
    let _cli_lock_guard = if url_str.is_some() {
        Some(acquire_plugin_cli_lock_for_daemon_write(plugins_dir, name)?)
    } else {
        None
    };
    if url_str.is_none() {
        let (_path, wasm_bytes, hash) = adopt_existing_managed_plugin_wasm(&local_wasm_path)?;
        wasm_bytes_for_signature = wasm_bytes;
        wasm_hash = hash;
    }

    // Prepare manifest payload via the typed manifest entry so
    // writer-side typos on field names are compile errors (see the
    // SECURITY/CORRECTNESS note on `ManagedPluginManifestEntry`).
    // Preserve any forward-compat `extra` fields a previous newer
    // daemon may have written into the entry.
    let mut manifest = read_plugins_manifest(plugins_dir)?;
    let extra = read_existing_manifest_entry(&manifest, name)
        .map(|e| e.extra)
        .unwrap_or_default();
    let new_entry = ManagedPluginManifestEntry {
        name: name.to_string(),
        version: version.clone(),
        installed_at: Some(installed_at),
        updated_at: None,
        // CORRECTNESS: emit the RELATIVE artifact filename, not
        // `local_wasm_path.to_string_lossy()` which is absolute
        // (`plugins_dir.join(wasm_file_name)`). The bootstrap loader
        // at `plugin_bootstrap::manifest_entry_relative_path`
        // tightened the read-side contract on this branch to require
        // relative paths; emitting absolute paths would land every
        // newly-installed plugin in PluginActivationState::Failed
        // after the next daemon restart. Master's loader
        // `manifest_entry_path` accepted both forms (relative →
        // join with managed_dir; absolute → use as-is), so the
        // pre-Batch-40 wire shape was tolerated; the tightened
        // loader needs the matching writer change.
        path: Some(wasm_file_name.clone()),
        sha256: Some(wasm_hash),
        publisher_key: publisher_key.clone(),
        signature: signature.clone(),
        url: url_str.map(str::to_string),
        extra,
    };
    let manifest_obj = ensure_object(&mut manifest)?;
    write_typed_manifest_entry(manifest_obj, name, &new_entry)?;

    // Prepare config payload and validate BEFORE writing anything. Use
    // the raw parsed config, not the resolved snapshot, so unrelated
    // plugin writes do not materialize env-supplied or decrypted
    // secrets into the config file.
    let mut config_value = read_config_snapshot().parsed;
    apply_managed_plugin_config_entry(&mut config_value, name, installed_at, true)?;
    validate_config_update(&config_value)?;
    validate_plugin_signature_policy_for_manifest(
        name,
        &wasm_bytes_for_signature,
        &manifest,
        &config_value,
    )?;

    // --- Phase 2: Commit all writes with backup-based rollback ---

    let mut txn = PluginWriteTransaction::new(plugins_dir.to_path_buf(), name.to_string());

    // Write 1: artifact (if download path).
    if let Some(ref bytes) = wasm_bytes_for_write {
        txn.backup_artifact()?;
        if let Err(e) = atomic_write_plugin_file(plugins_dir, &wasm_file_name, bytes) {
            txn.rollback_artifact();
            return Err(e);
        }
        txn.artifact_written = true;
    }

    // Write 2: manifest.
    if let Err(e) = txn.backup_manifest() {
        txn.rollback_artifact();
        return Err(e);
    }
    if let Err(e) = write_plugins_manifest(plugins_dir, &manifest) {
        txn.rollback_manifest();
        txn.rollback_artifact();
        return Err(e);
    }

    // Write 3: config. Reapply to the current raw config inside the
    // config write lock so a concurrent config change is preserved.
    if let Err(e) = update_config_file_with_error_shape(&config::get_config_path(), |value| {
        apply_managed_plugin_config_entry(value, name, installed_at, true)?;
        validate_config_update(value)?;
        validate_plugin_signature_policy_for_manifest(
            name,
            &wasm_bytes_for_signature,
            &manifest,
            value,
        )
    }) {
        txn.rollback_manifest();
        txn.rollback_artifact();
        return Err(e);
    }

    txn.commit();

    Ok(json!({
        "ok": true,
        "name": name,
        "version": version,
        "installed_at": installed_at,
        "publisher_key": publisher_key,
        "signature": signature,
        "activation": {
            "state": "restart-required",
            "message": "restart Carapace to activate the installed plugin"
        }
    }))
}

pub(super) fn handle_plugins_update(
    params: Option<&Value>,
    state: &WsServerState,
) -> Result<Value, ErrorShape> {
    handle_plugins_update_inner(
        params,
        &resolve_plugins_dir(),
        &state.config.operator_ssrf_config,
    )
}

/// Inner implementation of plugins.update, accepting a plugins directory for testability.
fn handle_plugins_update_inner(
    params: Option<&Value>,
    plugins_dir: &Path,
    ssrf_config: &SsrfConfig,
) -> Result<Value, ErrorShape> {
    handle_plugins_update_inner_with_downloader(
        params,
        plugins_dir,
        ssrf_config,
        download_plugin_wasm_bytes,
    )
}

fn handle_plugins_update_inner_with_downloader(
    params: Option<&Value>,
    plugins_dir: &Path,
    ssrf_config: &SsrfConfig,
    downloader: PluginDownloadFn,
) -> Result<Value, ErrorShape> {
    // --- Parse and validate params ---
    let name = params
        .and_then(|v| v.get("name"))
        .and_then(|v| v.as_str())
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "name is required", None))?;
    validate_plugin_name(name)?;

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
    let local_wasm_path = plugins_dir.join(&wasm_file_name);

    // --- Phase 1: Prepare network/local artifact bytes before taking the manifest RMW lock. ---

    let (wasm_bytes_for_write, mut wasm_bytes_for_signature, mut wasm_hash, source_url) =
        if let Some(url_str) = url_str {
            let parsed_url = validate_url(url_str)?;
            let wasm_bytes = downloader(&parsed_url, plugins_dir, ssrf_config)?;
            let hash = compute_sha256_hex(&wasm_bytes);
            (
                Some(wasm_bytes.clone()),
                wasm_bytes,
                hash,
                Some(url_str.to_string()),
            )
        } else {
            (None, Vec::new(), String::new(), None)
        };
    let updated_at = now_ms();

    let _manifest_guard = PLUGINS_MANIFEST_RMW_LOCK.lock();
    // SECURITY: see companion comment in
    // `handle_plugins_install_inner_with_downloader` — download path
    // takes `<dest>.cli-lock` to serialize with CLI `--file` mutations.
    let _cli_lock_guard = if url_str.is_some() {
        Some(acquire_plugin_cli_lock_for_daemon_write(plugins_dir, name)?)
    } else {
        None
    };

    if url_str.is_none() {
        let (_path, wasm_bytes, hash) = adopt_existing_managed_plugin_wasm(&local_wasm_path)?;
        wasm_bytes_for_signature = wasm_bytes;
        wasm_hash = hash;
    }

    // Re-read under the manifest RMW lock so a concurrent uninstall or
    // manifest rewrite cannot be overwritten by a stale pre-download snapshot.
    let mut manifest = read_plugins_manifest(plugins_dir)?;
    let installed = manifest
        .as_object()
        .is_some_and(|manifest_obj| manifest_obj.contains_key(name));
    if !installed {
        return Err(error_shape(
            ERROR_INVALID_REQUEST,
            &format!("managed plugin '{}' is not installed", name),
            None,
        ));
    }

    // Prepare manifest payload via the typed manifest entry; field
    // names are bound to Rust identifiers so writer-side typos are
    // compile errors. Carry forward `installed_at` and any
    // forward-compat `extra` fields from the existing entry.
    let existing = read_existing_manifest_entry(&manifest, name).ok_or_else(|| {
        error_shape(
            ERROR_INVALID_REQUEST,
            &format!("managed plugin '{}' is not installed", name),
            None,
        )
    })?;
    let new_entry = ManagedPluginManifestEntry {
        name: name.to_string(),
        version: version.clone().or(existing.version),
        installed_at: existing.installed_at,
        updated_at: Some(updated_at),
        // CORRECTNESS: emit relative `wasm_file_name`, not absolute
        // `local_wasm_path`. See companion comment in
        // `handle_plugins_install_inner` — the tightened loader at
        // `plugin_bootstrap::manifest_entry_relative_path` requires
        // relative paths.
        path: Some(wasm_file_name.clone()),
        sha256: Some(wasm_hash),
        publisher_key: publisher_key.clone().or(existing.publisher_key),
        signature: signature.clone().or(existing.signature),
        url: source_url.clone(),
        extra: existing.extra,
    };
    let manifest_obj = ensure_object(&mut manifest)?;
    write_typed_manifest_entry(manifest_obj, name, &new_entry)?;

    // Prepare config payload and validate BEFORE writing anything. Use
    // the raw parsed config, not the resolved snapshot, so unrelated
    // plugin writes do not materialize env-supplied or decrypted
    // secrets into the config file.
    let mut config_value = read_config_snapshot().parsed;
    apply_managed_plugin_config_entry(&mut config_value, name, updated_at, false)?;
    validate_config_update(&config_value)?;
    validate_plugin_signature_policy_for_manifest(
        name,
        &wasm_bytes_for_signature,
        &manifest,
        &config_value,
    )?;

    // --- Phase 2: Commit all writes with backup-based rollback ---

    let mut txn = PluginWriteTransaction::new(plugins_dir.to_path_buf(), name.to_string());

    // Write 1: artifact (if download path).
    if let Some(ref bytes) = wasm_bytes_for_write {
        txn.backup_artifact()?;
        if let Err(e) = atomic_write_plugin_file(plugins_dir, &wasm_file_name, bytes) {
            txn.rollback_artifact();
            return Err(e);
        }
        txn.artifact_written = true;
    }

    // Write 2: manifest.
    if let Err(e) = txn.backup_manifest() {
        txn.rollback_artifact();
        return Err(e);
    }
    if let Err(e) = write_plugins_manifest(plugins_dir, &manifest) {
        txn.rollback_manifest();
        txn.rollback_artifact();
        return Err(e);
    }

    // Write 3: config. Reapply to the current raw config inside the
    // config write lock so a concurrent config change is preserved.
    if let Err(e) = update_config_file_with_error_shape(&config::get_config_path(), |value| {
        apply_managed_plugin_config_entry(value, name, updated_at, false)?;
        validate_config_update(value)?;
        validate_plugin_signature_policy_for_manifest(
            name,
            &wasm_bytes_for_signature,
            &manifest,
            value,
        )
    }) {
        txn.rollback_manifest();
        txn.rollback_artifact();
        return Err(e);
    }

    txn.commit();

    Ok(json!({
        "ok": true,
        "name": name,
        "version": version,
        "updated_at": updated_at,
        "publisher_key": publisher_key,
        "signature": signature,
        "activation": {
            "state": "restart-required",
            "message": "restart Carapace to activate the updated plugin"
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::ws::{WsServerConfig, WsServerState};
    use crate::test_support::{env::ScopedEnv, plugins::tool_plugin_component_bytes};
    use tempfile::TempDir;

    struct TestConfigEnv {
        _env: ScopedEnv,
        _dir: TempDir,
    }

    impl TestConfigEnv {
        fn new() -> Self {
            let dir = TempDir::new().unwrap();
            let config_path = dir.path().join("carapace.json");
            let mut env = ScopedEnv::new();
            env.set("CARAPACE_CONFIG_PATH", config_path.as_os_str())
                .set("CARAPACE_DISABLE_CONFIG_CACHE", "1");
            crate::config::clear_cache();
            write_config_file(
                &config_path,
                &json!({ "plugins": { "signature": { "requireSignature": false } } }),
            )
            .unwrap();
            crate::config::clear_cache();

            Self {
                _env: env,
                _dir: dir,
            }
        }

        fn set_state_dir(&mut self, state_dir: &Path) {
            self._env.set("CARAPACE_STATE_DIR", state_dir.as_os_str());
        }
    }

    fn downloaded_test_plugin_wasm(
        _url: &url::Url,
        _plugins_dir: &Path,
        _ssrf_config: &SsrfConfig,
    ) -> Result<Vec<u8>, ErrorShape> {
        Ok(tool_plugin_component_bytes())
    }

    impl Drop for TestConfigEnv {
        fn drop(&mut self) {
            crate::config::clear_cache();
        }
    }

    struct TransactionRestoreHookGuard;

    impl TransactionRestoreHookGuard {
        fn set(hook: TransactionRestoreHook) -> Self {
            *TRANSACTION_RESTORE_AFTER_BACKUP_OPEN_HOOK.lock() = Some(hook);
            Self
        }
    }

    impl Drop for TransactionRestoreHookGuard {
        fn drop(&mut self) {
            *TRANSACTION_RESTORE_AFTER_BACKUP_OPEN_HOOK.lock() = None;
        }
    }

    fn audit_event_names(state_dir: &Path) -> Vec<String> {
        let audit_path = state_dir.join("audit.jsonl");
        let contents = std::fs::read_to_string(audit_path).unwrap();
        contents
            .lines()
            .map(|line| {
                serde_json::from_str::<serde_json::Value>(line).unwrap()["event"]
                    .as_str()
                    .unwrap()
                    .to_string()
            })
            .collect()
    }

    #[test]
    fn test_build_plugins_array_empty_config() {
        let cfg = json!({});
        let result = build_plugins_array(&cfg);
        assert!(result.is_empty());
    }

    #[test]
    fn test_build_plugins_array_no_entries() {
        let cfg = json!({ "plugins": {} });
        let result = build_plugins_array(&cfg);
        assert!(result.is_empty());
    }

    #[test]
    fn test_build_plugins_array_empty_entries() {
        let cfg = json!({ "plugins": { "entries": {} } });
        let result = build_plugins_array(&cfg);
        assert!(result.is_empty());
    }

    #[test]
    fn test_build_plugins_array_with_entries() {
        let cfg = json!({
            "plugins": {
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
        let result = build_plugins_array(&cfg);
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
    fn test_build_plugins_array_enabled_defaults_true() {
        let cfg = json!({
            "plugins": {
                "entries": {
                    "minimal": {}
                }
            }
        });
        let result = build_plugins_array(&cfg);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0]["name"], "minimal");
        assert_eq!(result[0]["enabled"], true);
        assert!(result[0]["installId"].is_null());
        assert!(result[0]["requestedAt"].is_null());
    }

    #[test]
    fn test_build_plugins_array_entries_not_object() {
        // If entries is not an object (e.g. an array), return empty
        let cfg = json!({ "plugins": { "entries": [1, 2, 3] } });
        let result = build_plugins_array(&cfg);
        assert!(result.is_empty());
    }

    #[test]
    fn test_build_plugins_array_skips_invalid_managed_entry_shapes() {
        let cfg = json!({
            "plugins": {
                "entries": {
                    "demo": {
                        "apiKey": "${DEMO_API_KEY}"
                    }
                }
            }
        });
        let result = build_plugins_array(&cfg);
        assert!(result.is_empty());
    }

    #[test]
    fn test_handle_plugins_status_uses_plugin_activation_report() {
        let env_state_dir = TempDir::new().unwrap();
        let report_state_dir = TempDir::new().unwrap();
        let config_dir = TempDir::new().unwrap();
        let config_path = config_dir.path().join("carapace.json");
        std::fs::write(
            &config_path,
            json!({
                "plugins": {
                    "entries": {
                        "weather": {
                            "enabled": true,
                            "installId": "install-weather",
                            "requestedAt": 1700000000000u64
                        }
                    }
                }
            })
            .to_string(),
        )
        .unwrap();
        let mut env = ScopedEnv::new();
        env.set("CARAPACE_STATE_DIR", env_state_dir.path().as_os_str())
            .set("CARAPACE_CONFIG_PATH", config_path.as_os_str())
            .set("CARAPACE_DISABLE_CONFIG_CACHE", "1");
        crate::config::clear_cache();

        let state = WsServerState::new(WsServerConfig::default()).with_plugin_activation_report(
            crate::server::plugin_bootstrap::PluginActivationReport {
                enabled: true,
                configured_paths: vec![report_state_dir.path().join("dev-plugins")],
                restart_required_for_changes: true,
                errors: vec!["failed to read configured plugin path".to_string()],
                entries: vec![crate::server::plugin_bootstrap::PluginActivationEntry {
                    name: "weather".to_string(),
                    plugin_id: Some("weather".to_string()),
                    source: crate::server::plugin_bootstrap::PluginActivationSource::Managed,
                    enabled: true,
                    path: Some(report_state_dir.path().join("plugins/weather.wasm")),
                    requested_at: Some(1700000000000u64),
                    install_id: Some(json!("install-weather")),
                    state: crate::server::plugin_bootstrap::PluginActivationState::Active,
                    reason: None,
                }],
            },
        );

        let result = handle_plugins_status(&state).unwrap();
        assert_eq!(result["pluginsEnabled"], true);
        assert_eq!(result["configuredPluginPathCount"], 1);
        assert_eq!(result["restartRequiredForChanges"], true);
        assert_eq!(result["activationErrorCount"], 1);
        assert_eq!(result["plugins"].as_array().unwrap().len(), 1);
        let entry = &result["plugins"][0];
        assert_eq!(entry["name"], "weather");
        assert_eq!(entry["pluginId"], "weather");
        assert_eq!(entry["source"], "managed");
        assert_eq!(entry["state"], "active");
        assert_eq!(entry["enabled"], true);
        assert!(entry.get("path").is_none());

        crate::config::clear_cache();
    }

    #[test]
    fn test_handle_plugins_status_merges_pending_configured_plugins_into_report() {
        let env_state_dir = TempDir::new().unwrap();
        let report_state_dir = TempDir::new().unwrap();
        let config_dir = TempDir::new().unwrap();
        let config_path = config_dir.path().join("carapace.json");
        std::fs::write(
            &config_path,
            json!({
                "plugins": {
                    "entries": {
                        "weather": {
                            "enabled": true,
                            "installId": "install-weather-new",
                            "requestedAt": 1700000001000u64
                        },
                        "calendar": {
                            "enabled": true,
                            "installId": "install-calendar",
                            "requestedAt": 1700000002000u64
                        }
                    }
                }
            })
            .to_string(),
        )
        .unwrap();
        let mut env = ScopedEnv::new();
        env.set("CARAPACE_STATE_DIR", env_state_dir.path().as_os_str())
            .set("CARAPACE_CONFIG_PATH", config_path.as_os_str())
            .set("CARAPACE_DISABLE_CONFIG_CACHE", "1");
        crate::config::clear_cache();

        let state = WsServerState::new(WsServerConfig::default()).with_plugin_activation_report(
            crate::server::plugin_bootstrap::PluginActivationReport {
                enabled: true,
                configured_paths: vec![],
                restart_required_for_changes: true,
                errors: vec![],
                entries: vec![crate::server::plugin_bootstrap::PluginActivationEntry {
                    name: "weather".to_string(),
                    plugin_id: Some("weather".to_string()),
                    source: crate::server::plugin_bootstrap::PluginActivationSource::Managed,
                    enabled: true,
                    path: Some(report_state_dir.path().join("plugins/weather.wasm")),
                    requested_at: Some(1700000000000u64),
                    install_id: Some(json!("install-weather")),
                    state: crate::server::plugin_bootstrap::PluginActivationState::Active,
                    reason: None,
                }],
            },
        );

        let result = handle_plugins_status(&state).unwrap();
        assert_eq!(result["plugins"].as_array().unwrap().len(), 2);
        let weather = result["plugins"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["name"] == "weather")
            .unwrap();
        assert_eq!(weather["state"], "active");
        assert_eq!(weather["installId"], "install-weather-new");
        assert_eq!(weather["requestedAt"], 1700000001000u64);
        let calendar = result["plugins"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["name"] == "calendar")
            .unwrap();
        assert_eq!(calendar["state"], "ignored");
        assert_eq!(calendar["source"], "managed");
        assert_eq!(
            calendar["reason"],
            "plugin is configured and will activate after restart"
        );

        crate::config::clear_cache();
    }

    #[test]
    fn test_handle_plugins_status_without_report_counts_configured_plugin_paths() {
        let env_state_dir = TempDir::new().unwrap();
        let config_dir = TempDir::new().unwrap();
        let config_path = config_dir.path().join("carapace.json");
        std::fs::write(
            &config_path,
            json!({
                "plugins": {
                    "load": {
                        "paths": [
                            "  /tmp/plugins-a  ",
                            "",
                            "/tmp/plugins-a",
                            "/tmp/plugins-b"
                        ]
                    }
                }
            })
            .to_string(),
        )
        .unwrap();
        let mut env = ScopedEnv::new();
        env.set("CARAPACE_STATE_DIR", env_state_dir.path().as_os_str())
            .set("CARAPACE_CONFIG_PATH", config_path.as_os_str())
            .set("CARAPACE_DISABLE_CONFIG_CACHE", "1");
        crate::config::clear_cache();

        let state = WsServerState::new(WsServerConfig::default());
        let result = handle_plugins_status(&state).unwrap();
        assert_eq!(result["configuredPluginPathCount"], 2);

        crate::config::clear_cache();
    }

    #[test]
    fn test_handle_plugins_status_preserves_duplicate_name_report_entries() {
        let config_dir = TempDir::new().unwrap();
        let config_path = config_dir.path().join("carapace.json");
        std::fs::write(
            &config_path,
            json!({
                "plugins": {
                    "entries": {
                        "weather": {
                            "enabled": true,
                            "installId": "install-weather",
                            "requestedAt": 1700000003000u64
                        }
                    }
                }
            })
            .to_string(),
        )
        .unwrap();
        let mut env = ScopedEnv::new();
        env.set("CARAPACE_CONFIG_PATH", config_path.as_os_str())
            .set("CARAPACE_DISABLE_CONFIG_CACHE", "1");
        crate::config::clear_cache();

        let state = WsServerState::new(WsServerConfig::default()).with_plugin_activation_report(
            crate::server::plugin_bootstrap::PluginActivationReport {
                enabled: true,
                configured_paths: vec![PathBuf::from("/plugins-dev")],
                restart_required_for_changes: true,
                errors: vec![],
                entries: vec![
                    crate::server::plugin_bootstrap::PluginActivationEntry {
                        name: "weather".to_string(),
                        plugin_id: Some("weather".to_string()),
                        source: crate::server::plugin_bootstrap::PluginActivationSource::Managed,
                        enabled: true,
                        path: Some(PathBuf::from("/managed/weather.wasm")),
                        requested_at: Some(1700000000000u64),
                        install_id: Some(json!("install-weather-old")),
                        state: crate::server::plugin_bootstrap::PluginActivationState::Active,
                        reason: None,
                    },
                    crate::server::plugin_bootstrap::PluginActivationEntry {
                        name: "weather".to_string(),
                        plugin_id: Some("weather".to_string()),
                        source: crate::server::plugin_bootstrap::PluginActivationSource::ConfigPath,
                        enabled: true,
                        path: Some(PathBuf::from("/plugins-dev/weather.wasm")),
                        requested_at: None,
                        install_id: None,
                        state: crate::server::plugin_bootstrap::PluginActivationState::Failed,
                        reason: Some(
                            "plugin ID conflict with an earlier activation source: weather"
                                .to_string(),
                        ),
                    },
                ],
            },
        );

        let result = handle_plugins_status(&state).unwrap();
        let weather_entries = result["plugins"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|entry| entry["name"] == "weather")
            .collect::<Vec<_>>();
        assert_eq!(weather_entries.len(), 2);
        let managed_entry = weather_entries
            .iter()
            .find(|entry| entry["source"] == "managed")
            .unwrap();
        assert_eq!(managed_entry["installId"], "install-weather");
        assert_eq!(managed_entry["requestedAt"], 1700000003000u64);
        let config_entry = weather_entries
            .iter()
            .find(|entry| entry["source"] == "config")
            .unwrap();
        assert_eq!(config_entry["state"], "failed");
        assert_eq!(
            config_entry["reason"],
            "plugin ID conflict with an earlier activation source: weather"
        );

        crate::config::clear_cache();
    }

    #[test]
    fn test_handle_plugins_status_reports_loader_init_failures_per_managed_plugin() {
        let config_dir = TempDir::new().unwrap();
        let config_path = config_dir.path().join("carapace.json");
        std::fs::write(
            &config_path,
            json!({
                "plugins": {
                    "entries": {
                        "alpha": {
                            "enabled": true,
                            "installId": "install-alpha",
                            "requestedAt": 1700000001000u64
                        },
                        "beta": {
                            "enabled": false,
                            "installId": "install-beta",
                            "requestedAt": 1700000002000u64
                        }
                    }
                }
            })
            .to_string(),
        )
        .unwrap();
        let mut env = ScopedEnv::new();
        env.set("CARAPACE_CONFIG_PATH", config_path.as_os_str())
            .set("CARAPACE_DISABLE_CONFIG_CACHE", "1");
        crate::config::clear_cache();

        let loader_init_reason =
            "failed to initialize plugin loader: Wasmtime engine error: forced loader init failure";
        let state = WsServerState::new(WsServerConfig::default()).with_plugin_activation_report(
            crate::server::plugin_bootstrap::PluginActivationReport {
                enabled: true,
                configured_paths: vec![],
                restart_required_for_changes: true,
                errors: vec![loader_init_reason.to_string()],
                entries: vec![
                    crate::server::plugin_bootstrap::PluginActivationEntry {
                        name: "alpha".to_string(),
                        plugin_id: None,
                        source: crate::server::plugin_bootstrap::PluginActivationSource::Managed,
                        enabled: true,
                        path: None,
                        requested_at: Some(1700000001000u64),
                        install_id: Some(json!("install-alpha")),
                        state: crate::server::plugin_bootstrap::PluginActivationState::Failed,
                        reason: Some(loader_init_reason.to_string()),
                    },
                    crate::server::plugin_bootstrap::PluginActivationEntry {
                        name: "beta".to_string(),
                        plugin_id: None,
                        source: crate::server::plugin_bootstrap::PluginActivationSource::Managed,
                        enabled: false,
                        path: None,
                        requested_at: Some(1700000002000u64),
                        install_id: Some(json!("install-beta")),
                        state: crate::server::plugin_bootstrap::PluginActivationState::Disabled,
                        reason: Some("managed plugin is disabled in plugins.entries".to_string()),
                    },
                ],
            },
        );

        let result = handle_plugins_status(&state).unwrap();
        assert_eq!(result["activationErrorCount"], 2);

        let alpha = result["plugins"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["name"] == "alpha")
            .unwrap();
        assert_eq!(alpha["enabled"], true);
        assert_eq!(alpha["state"], "failed");
        assert_eq!(alpha["installId"], "install-alpha");
        assert_eq!(alpha["requestedAt"], 1700000001000u64);
        assert_eq!(alpha["reason"], loader_init_reason);

        let beta = result["plugins"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["name"] == "beta")
            .unwrap();
        assert_eq!(beta["enabled"], false);
        assert_eq!(beta["state"], "disabled");
        assert_eq!(beta["installId"], "install-beta");
        assert_eq!(beta["requestedAt"], 1700000002000u64);
        assert_eq!(
            beta["reason"],
            "managed plugin is disabled in plugins.entries"
        );

        crate::config::clear_cache();
    }

    #[test]
    fn test_handle_plugins_status_sanitizes_path_bearing_reasons() {
        let state = WsServerState::new(WsServerConfig::default()).with_plugin_activation_report(
            crate::server::plugin_bootstrap::PluginActivationReport {
                enabled: true,
                configured_paths: vec![PathBuf::from("/plugins-dev")],
                restart_required_for_changes: true,
                errors: vec![
                    "failed to read configured plugin path /plugins-dev: denied".to_string()
                ],
                entries: vec![crate::server::plugin_bootstrap::PluginActivationEntry {
                    name: "weather".to_string(),
                    plugin_id: None,
                    source: crate::server::plugin_bootstrap::PluginActivationSource::ConfigPath,
                    enabled: true,
                    path: Some(PathBuf::from("/plugins-dev/weather.wasm")),
                    requested_at: None,
                    install_id: None,
                    state: crate::server::plugin_bootstrap::PluginActivationState::Failed,
                    reason: Some(
                        "Failed to compile WASM component /plugins-dev/weather.wasm: bad module"
                            .to_string(),
                    ),
                }],
            },
        );

        let result = handle_plugins_status(&state).unwrap();
        assert_eq!(result["activationErrorCount"], 2);
        let weather = result["plugins"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["name"] == "weather")
            .unwrap();
        assert_eq!(weather["reason"], "failed to compile WASM plugin component");
        assert!(weather.get("path").is_none());
    }

    #[test]
    fn test_sanitize_activation_reason_preserves_namespaced_identifiers() {
        assert_eq!(
            sanitize_activation_reason("unknown import: carapace:plugin/host@1.0.0"),
            "unknown import: carapace:plugin/host@1.0.0"
        );
    }

    #[test]
    fn test_handle_plugins_status_recomputes_pending_enable_after_config_change() {
        let config_dir = TempDir::new().unwrap();
        let config_path = config_dir.path().join("carapace.json");
        std::fs::write(
            &config_path,
            json!({
                "plugins": {
                    "entries": {
                        "weather": {
                            "enabled": true,
                            "installId": "install-weather",
                            "requestedAt": 1700000003000u64
                        }
                    }
                }
            })
            .to_string(),
        )
        .unwrap();
        let mut env = ScopedEnv::new();
        env.set("CARAPACE_CONFIG_PATH", config_path.as_os_str())
            .set("CARAPACE_DISABLE_CONFIG_CACHE", "1");
        crate::config::clear_cache();

        let state = WsServerState::new(WsServerConfig::default()).with_plugin_activation_report(
            crate::server::plugin_bootstrap::PluginActivationReport {
                enabled: true,
                configured_paths: vec![],
                restart_required_for_changes: true,
                errors: vec![],
                entries: vec![crate::server::plugin_bootstrap::PluginActivationEntry {
                    name: "weather".to_string(),
                    plugin_id: None,
                    source: crate::server::plugin_bootstrap::PluginActivationSource::Managed,
                    enabled: false,
                    path: Some(PathBuf::from("/managed/weather.wasm")),
                    requested_at: Some(1700000000000u64),
                    install_id: Some(json!("install-weather-old")),
                    state: crate::server::plugin_bootstrap::PluginActivationState::Disabled,
                    reason: Some("managed plugin is disabled in plugins.entries".to_string()),
                }],
            },
        );

        let result = handle_plugins_status(&state).unwrap();
        let weather = result["plugins"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["name"] == "weather")
            .unwrap();
        assert_eq!(weather["enabled"], true);
        assert_eq!(weather["state"], "ignored");
        assert_eq!(
            weather["reason"],
            "plugin is configured and will activate after restart"
        );

        crate::config::clear_cache();
    }

    #[test]
    fn test_handle_plugins_status_marks_disable_after_config_change_as_pending_restart() {
        let config_dir = TempDir::new().unwrap();
        let config_path = config_dir.path().join("carapace.json");
        std::fs::write(
            &config_path,
            json!({
                "plugins": {
                    "entries": {
                        "weather": {
                            "enabled": false,
                            "installId": "install-weather",
                            "requestedAt": 1700000003000u64
                        }
                    }
                }
            })
            .to_string(),
        )
        .unwrap();
        let mut env = ScopedEnv::new();
        env.set("CARAPACE_CONFIG_PATH", config_path.as_os_str())
            .set("CARAPACE_DISABLE_CONFIG_CACHE", "1");
        crate::config::clear_cache();

        let state = WsServerState::new(WsServerConfig::default()).with_plugin_activation_report(
            crate::server::plugin_bootstrap::PluginActivationReport {
                enabled: true,
                configured_paths: vec![],
                restart_required_for_changes: true,
                errors: vec![],
                entries: vec![crate::server::plugin_bootstrap::PluginActivationEntry {
                    name: "weather".to_string(),
                    plugin_id: Some("weather".to_string()),
                    source: crate::server::plugin_bootstrap::PluginActivationSource::Managed,
                    enabled: true,
                    path: Some(PathBuf::from("/managed/weather.wasm")),
                    requested_at: Some(1700000000000u64),
                    install_id: Some(json!("install-weather-old")),
                    state: crate::server::plugin_bootstrap::PluginActivationState::Active,
                    reason: None,
                }],
            },
        );

        let result = handle_plugins_status(&state).unwrap();
        let weather = result["plugins"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["name"] == "weather")
            .unwrap();
        assert_eq!(weather["enabled"], false);
        assert_eq!(weather["state"], "disabled");
        assert_eq!(
            weather["reason"],
            "managed plugin is currently active and will be disabled after restart"
        );

        crate::config::clear_cache();
    }

    #[test]
    fn test_handle_plugins_status_marks_removed_managed_plugin_as_pending_restart() {
        let config_dir = TempDir::new().unwrap();
        let config_path = config_dir.path().join("carapace.json");
        std::fs::write(
            &config_path,
            json!({ "plugins": { "entries": {} } }).to_string(),
        )
        .unwrap();
        let mut env = ScopedEnv::new();
        env.set("CARAPACE_CONFIG_PATH", config_path.as_os_str())
            .set("CARAPACE_DISABLE_CONFIG_CACHE", "1");
        crate::config::clear_cache();

        let state = WsServerState::new(WsServerConfig::default()).with_plugin_activation_report(
            crate::server::plugin_bootstrap::PluginActivationReport {
                enabled: true,
                configured_paths: vec![],
                restart_required_for_changes: true,
                errors: vec![],
                entries: vec![crate::server::plugin_bootstrap::PluginActivationEntry {
                    name: "weather".to_string(),
                    plugin_id: Some("weather".to_string()),
                    source: crate::server::plugin_bootstrap::PluginActivationSource::Managed,
                    enabled: true,
                    path: Some(PathBuf::from("/managed/weather.wasm")),
                    requested_at: Some(1700000000000u64),
                    install_id: Some(json!("install-weather-old")),
                    state: crate::server::plugin_bootstrap::PluginActivationState::Active,
                    reason: None,
                }],
            },
        );

        let result = handle_plugins_status(&state).unwrap();
        let weather = result["plugins"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["name"] == "weather")
            .unwrap();
        assert_eq!(weather["enabled"], false);
        assert_eq!(weather["installId"], Value::Null);
        assert_eq!(weather["requestedAt"], Value::Null);
        assert_eq!(weather["state"], "disabled");
        assert_eq!(
            weather["reason"],
            "managed plugin is currently active and will be removed after restart"
        );

        crate::config::clear_cache();
    }

    #[test]
    fn test_handle_plugins_status_preserves_stray_managed_plugin_reason() {
        let state = WsServerState::new(WsServerConfig::default()).with_plugin_activation_report(
            crate::server::plugin_bootstrap::PluginActivationReport {
                enabled: true,
                configured_paths: vec![],
                restart_required_for_changes: true,
                errors: vec![],
                entries: vec![crate::server::plugin_bootstrap::PluginActivationEntry {
                    name: "weather".to_string(),
                    plugin_id: None,
                    source: crate::server::plugin_bootstrap::PluginActivationSource::Managed,
                    enabled: false,
                    path: Some(PathBuf::from("/managed/weather.wasm")),
                    requested_at: None,
                    install_id: None,
                    state: crate::server::plugin_bootstrap::PluginActivationState::Ignored,
                    reason: Some(
                        "WASM file is present in the managed plugin directory but not declared in plugins.entries"
                            .to_string(),
                    ),
                }],
            },
        );

        let result = handle_plugins_status(&state).unwrap();
        let weather = result["plugins"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["name"] == "weather")
            .unwrap();
        assert_eq!(weather["state"], "ignored");
        assert_eq!(
            weather["reason"],
            "WASM file is present in the managed plugin directory but not declared in plugins.entries"
        );
    }

    #[test]
    fn test_scan_plugins_bins_nonexistent_dir() {
        let result = scan_plugins_bins(std::path::Path::new(
            "/nonexistent/path/that/does/not/exist/plugins",
        ));
        assert!(result.is_empty());
    }

    #[test]
    fn test_scan_plugins_bins_empty_dir() {
        let dir = TempDir::new().unwrap();
        let result = scan_plugins_bins(dir.path());
        assert!(result.is_empty());
    }

    #[test]
    fn test_scan_plugins_bins_with_files() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("plugin-a.wasm"), b"wasm").unwrap();
        std::fs::write(dir.path().join("plugin-b.wasm"), b"wasm").unwrap();
        std::fs::write(dir.path().join("secret\nname.wasm"), b"wasm").unwrap();
        std::fs::write(dir.path().join("plugins-manifest.json"), b"{}").unwrap();
        std::fs::write(dir.path().join("note.txt"), b"ignored").unwrap();
        std::fs::create_dir(dir.path().join("nested.wasm")).unwrap();
        std::fs::create_dir(dir.path().join("subdir")).unwrap();

        let result = scan_plugins_bins(dir.path());
        assert_eq!(result.len(), 2);

        let names: Vec<&str> = result.iter().map(|v| v["name"].as_str().unwrap()).collect();
        assert!(names.contains(&"plugin-a.wasm"));
        assert!(names.contains(&"plugin-b.wasm"));
        assert!(
            !names.contains(&"secret\nname.wasm"),
            "bins response must not disclose attacker-shaped managed filenames"
        );
        assert!(result.iter().all(|bin| bin.get("path").is_none()));
    }

    #[cfg(unix)]
    #[test]
    fn test_scan_plugins_bins_rejects_symlinked_wasm() {
        use std::os::unix::fs::symlink;

        let dir = TempDir::new().unwrap();
        let target = dir.path().join("target.wasm");
        let link = dir.path().join("linked.wasm");
        std::fs::write(&target, b"wasm").unwrap();
        symlink(&target, &link).unwrap();

        let result = scan_plugins_bins(dir.path());
        let names: Vec<&str> = result.iter().map(|v| v["name"].as_str().unwrap()).collect();

        assert!(names.contains(&"target.wasm"));
        assert!(!names.contains(&"linked.wasm"));
    }

    // ---- Validation tests ----

    #[test]
    fn test_validate_plugin_name_valid() {
        assert!(validate_plugin_name("weather").is_ok());
        assert!(validate_plugin_name("my-plugin").is_ok());
        assert!(validate_plugin_name("my_plugin_v2").is_ok());
        assert!(validate_plugin_name("a").is_ok());
        assert!(validate_plugin_name("ABC123").is_ok());
    }

    #[test]
    fn test_validate_plugin_name_empty() {
        let err = validate_plugin_name("").unwrap_err();
        assert_eq!(err.code, ERROR_INVALID_REQUEST);
        assert!(err.message.contains("empty"));
    }

    #[test]
    fn test_validate_plugin_name_too_long() {
        let long_name = "a".repeat(129);
        let err = validate_plugin_name(&long_name).unwrap_err();
        assert_eq!(err.code, ERROR_INVALID_REQUEST);
        assert!(err.message.contains("too long"));
    }

    #[test]
    fn test_validate_plugin_name_bad_chars() {
        let err = validate_plugin_name("my plugin").unwrap_err();
        assert_eq!(err.code, ERROR_INVALID_REQUEST);

        let err = validate_plugin_name("../escape").unwrap_err();
        assert_eq!(err.code, ERROR_INVALID_REQUEST);

        let err = validate_plugin_name("path/traversal").unwrap_err();
        assert_eq!(err.code, ERROR_INVALID_REQUEST);

        let err = validate_plugin_name("has.dot").unwrap_err();
        assert_eq!(err.code, ERROR_INVALID_REQUEST);
    }

    #[test]
    fn test_validate_plugin_name_reserved() {
        let err = validate_plugin_name("entries").unwrap_err();
        assert_eq!(err.code, ERROR_INVALID_REQUEST);
        assert!(err.message.contains("reserved"));
    }

    #[test]
    fn test_validate_url_valid() {
        assert!(validate_url("https://example.com/plugin.wasm").is_ok());
        assert!(validate_url("http://localhost:8080/plugin.wasm").is_ok());
    }

    #[test]
    fn test_validate_url_bad_scheme() {
        let err = validate_url("ftp://example.com/plugin.wasm").unwrap_err();
        assert!(err.message.contains("unsupported url scheme"));
    }

    #[test]
    fn test_validate_url_rejects_embedded_credentials() {
        let err = validate_url("https://user:pass@example.com/plugin.wasm").unwrap_err();
        assert_eq!(err.code, ERROR_INVALID_REQUEST);
        assert!(err.message.contains("embedded credentials"));
    }

    #[test]
    fn test_validate_url_invalid() {
        let err = validate_url("not a url at all").unwrap_err();
        assert!(err.message.contains("invalid url"));
    }

    #[test]
    fn test_validate_and_resolve_dns_inside_current_thread_runtime_is_panic_free() {
        let url = url::Url::parse("https://example.com/plugin.wasm").unwrap();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let dns_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            rt.block_on(async { validate_and_resolve_dns(&url, &SsrfConfig::default()) })
        }));

        assert!(
            dns_result.is_ok(),
            "DNS resolve path should not panic in current-thread runtime"
        );

        match dns_result.unwrap() {
            Ok((host, port, _resolved_ip)) => {
                assert!(!host.is_empty());
                assert!(port > 0);
            }
            Err(err) => {
                assert_ne!(
                    err.code, ERROR_INVALID_REQUEST,
                    "DNS validation should not fail SSRF validation for a public URL"
                );
            }
        }
    }

    // ---- SSRF protection tests for plugin downloads ----

    #[tokio::test(flavor = "multi_thread")]
    async fn test_download_plugin_ssrf_public_url_passes_validation() {
        // A public URL should pass SSRF validation (will fail later at the network level,
        // but the SSRF check itself should not reject it).
        // This test requires a tokio multi_thread runtime because the function
        // performs async DNS resolution for hostname-based URLs via block_in_place.
        // We use spawn_blocking to avoid reqwest::blocking::Client's internal
        // runtime conflicting with the test runtime on drop.
        let dir = TempDir::new().unwrap();
        let dir_path = dir.path().to_path_buf();
        let result = tokio::task::spawn_blocking(move || {
            let url = url::Url::parse("https://example.com/plugins/my-plugin.wasm").unwrap();
            download_plugin_wasm(&url, &dir_path, "test.wasm")
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
    fn test_download_plugin_ssrf_rejects_localhost() {
        let dir = TempDir::new().unwrap();
        let url = url::Url::parse("http://localhost/evil.wasm").unwrap();
        let result = download_plugin_wasm(&url, dir.path(), "test.wasm");
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
    fn test_download_plugin_ssrf_rejects_metadata_endpoint() {
        let dir = TempDir::new().unwrap();
        let url = url::Url::parse("http://169.254.169.254/latest/meta-data/").unwrap();
        let result = download_plugin_wasm(&url, dir.path(), "test.wasm");
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
    fn test_download_plugin_ssrf_rejects_internal_ip() {
        let dir = TempDir::new().unwrap();
        let url = url::Url::parse("http://10.0.0.1/internal-plugin.wasm").unwrap();
        let result = download_plugin_wasm(&url, dir.path(), "test.wasm");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code, ERROR_INVALID_REQUEST);
        assert!(
            err.message.contains("SSRF"),
            "internal IP should be blocked by SSRF protection, got: {}",
            err.message
        );
    }

    #[test]
    fn test_plugin_download_ssrf_honors_allow_tailscale_for_artifact_url() {
        let url = url::Url::parse("http://100.64.0.1/plugin.wasm").unwrap();
        let default_err = validate_and_resolve_dns(&url, &SsrfConfig::default())
            .expect_err("default SSRF config must block Tailscale CGNAT addresses");
        assert_eq!(default_err.code, ERROR_INVALID_REQUEST);

        let allow_tailscale = SsrfConfig {
            allow_tailscale: true,
        };
        let resolved = validate_and_resolve_dns(&url, &allow_tailscale)
            .expect("allow_tailscale should permit Tailscale plugin artifact URLs");
        assert_eq!(resolved.0, "100.64.0.1");
        assert_eq!(resolved.2, None);
    }

    // ---- Manifest read/write tests ----

    #[test]
    fn test_read_plugins_manifest_nonexistent() {
        let dir = TempDir::new().unwrap();
        let manifest = read_plugins_manifest(dir.path()).unwrap();
        assert_eq!(manifest, json!({}));
    }

    #[test]
    fn test_write_and_read_plugins_manifest() {
        let dir = TempDir::new().unwrap();
        let manifest = json!({
            "weather": {
                "name": "weather",
                "version": "1.0.0",
                "installed_at": 1700000000000u64
            }
        });
        write_plugins_manifest(dir.path(), &manifest).unwrap();

        let read_back = read_plugins_manifest(dir.path()).unwrap();
        assert_eq!(read_back["weather"]["name"], "weather");
        assert_eq!(read_back["weather"]["version"], "1.0.0");
        assert_eq!(read_back["weather"]["installed_at"], 1700000000000u64);
    }

    #[test]
    fn test_write_plugins_manifest_creates_directory() {
        let dir = TempDir::new().unwrap();
        let nested = dir.path().join("nested").join("plugins");
        let manifest = json!({ "test": {} });
        write_plugins_manifest(&nested, &manifest).unwrap();
        assert!(nested.join(PLUGINS_MANIFEST_FILE).is_file());
    }

    /// Regression for R58 M-PL4: `write_plugins_manifest` must
    /// refuse to persist a manifest that exceeds
    /// `MAX_MANAGED_PLUGIN_MANIFEST_BYTES`. Without this,
    /// `plugins.install` / `plugins.update` could lay down an
    /// over-size manifest that the bootstrap loader rejects on next
    /// start — marking every managed plugin Failed with the same
    /// generic message.
    /// Pin the on-disk wire format of `ManagedPluginManifestEntry`
    /// so a refactor that renames a struct field doesn't silently
    /// drift from the disk format the loader/bootstrap/signature
    /// readers expect. Tests cover: full-fields entry, minimal stub
    /// entry (just name/version/installed_at), and a roundtrip with
    /// unknown forward-compat fields preserved.
    #[test]
    fn test_managed_plugin_manifest_entry_serde_pins_wire_field_names() {
        let entry = ManagedPluginManifestEntry {
            name: "weather".into(),
            version: Some("1.2.3".into()),
            installed_at: Some(1_700_000_000_000),
            updated_at: Some(1_700_000_100_000),
            path: Some("/p/weather.wasm".into()),
            sha256: Some("ab".repeat(32)),
            publisher_key: Some("pk-hex".into()),
            signature: Some("sig-hex".into()),
            url: Some("https://example.com/weather.wasm".into()),
            extra: BTreeMap::new(),
        };
        let value = serde_json::to_value(&entry).unwrap();
        let obj = value.as_object().unwrap();
        // Pin every field name. A rename refactor on the struct would
        // be a compile error after this test references all field names
        // verbatim through serde keys; the assertions below catch a
        // rename-via-#[serde(rename)] silent break.
        assert_eq!(obj["name"], "weather");
        assert_eq!(obj["version"], "1.2.3");
        assert_eq!(obj["installed_at"], 1_700_000_000_000u64);
        assert_eq!(obj["updated_at"], 1_700_000_100_000u64);
        assert_eq!(obj["path"], "/p/weather.wasm");
        assert_eq!(obj["sha256"], "ab".repeat(32));
        assert_eq!(obj["publisher_key"], "pk-hex");
        assert_eq!(obj["signature"], "sig-hex");
        assert_eq!(obj["url"], "https://example.com/weather.wasm");
        // None-fields are skipped when the Option is None
        let minimal = ManagedPluginManifestEntry {
            name: "tiny".into(),
            version: None,
            installed_at: Some(0),
            updated_at: None,
            path: None,
            sha256: None,
            publisher_key: None,
            signature: None,
            url: None,
            extra: BTreeMap::new(),
        };
        let value = serde_json::to_value(&minimal).unwrap();
        let obj = value.as_object().unwrap();
        assert!(obj.contains_key("name"));
        assert!(obj.contains_key("installed_at"));
        assert!(!obj.contains_key("version"));
        assert!(!obj.contains_key("path"));
        assert!(!obj.contains_key("sha256"));
        assert!(!obj.contains_key("url"));
        // Forward-compat: unknown fields written by a newer daemon
        // must roundtrip through deserialize → reserialize without
        // being silently dropped.
        let raw = json!({
            "name": "future",
            "version": "9.9.9",
            "installed_at": 1u64,
            "path": "/p/future.wasm",
            "sha256": "00".repeat(32),
            "future_field_added_in_v2": {"nested": "value"}
        });
        let parsed: ManagedPluginManifestEntry =
            serde_json::from_value(raw.clone()).expect("forward-compat extra must parse");
        assert!(parsed.extra.contains_key("future_field_added_in_v2"));
        let reserialized = serde_json::to_value(&parsed).unwrap();
        assert_eq!(
            reserialized["future_field_added_in_v2"]["nested"], "value",
            "extra fields must roundtrip without being dropped"
        );
    }

    #[test]
    fn test_write_plugins_manifest_rejects_oversize_payload() {
        let dir = TempDir::new().unwrap();
        let plugins_dir = dir.path().join("plugins");
        std::fs::create_dir_all(&plugins_dir).unwrap();
        // A single entry whose value is larger than the cap.
        let oversize_value = "x".repeat((MAX_MANAGED_PLUGIN_MANIFEST_BYTES as usize) + 1);
        let manifest = json!({ "huge": { "data": oversize_value } });

        let err = write_plugins_manifest(&plugins_dir, &manifest)
            .expect_err("oversize manifest write must fail");

        assert_eq!(err.code, ERROR_INVALID_REQUEST);
        assert!(
            err.message.contains("exceeds maximum size"),
            "oversize rejection must surface the cap: {}",
            err.message
        );
        assert!(
            !plugins_dir.join(PLUGINS_MANIFEST_FILE).exists(),
            "oversize manifest must NOT be persisted to disk"
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_write_atomic_plugins_file_rejects_symlinked_tmp_path() {
        use std::os::unix::fs::symlink;

        let dir = TempDir::new().unwrap();
        let dest_path = dir.path().join("plugin.wasm");
        let tmp_path = dir.path().join("plugin.wasm.tmp");
        let redirected_target = dir.path().join("redirected-target");

        std::fs::write(&redirected_target, b"existing-target").unwrap();
        symlink(&redirected_target, &tmp_path).unwrap();

        let err =
            write_atomic_plugins_file(&tmp_path, &dest_path, b"new-plugin-bytes", "plugin binary")
                .unwrap_err();

        assert_eq!(err.code, ERROR_UNAVAILABLE);
        assert!(
            err.message.contains("failed to write plugin binary"),
            "unexpected error: {}",
            err.message
        );
        assert_eq!(
            std::fs::read(&redirected_target).unwrap(),
            b"existing-target",
            "symlink target must not be overwritten"
        );
        assert!(!dest_path.exists(), "destination should not be created");
    }

    #[test]
    fn test_read_plugins_manifest_corrupt_json_fails_closed() {
        // A present-but-corrupt manifest must fail closed, never silently
        // truncate to {}: the install/update RMW reconstructs the manifest
        // from this read and would otherwise wipe every other managed
        // plugin's signature/sha256/publisher_key on the next install.
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join(PLUGINS_MANIFEST_FILE), b"not json").unwrap();
        let err = read_plugins_manifest(dir.path()).expect_err("corrupt manifest must fail closed");
        assert_eq!(err.code, ERROR_UNAVAILABLE);
        assert!(
            err.message.contains("plugins manifest is corrupt"),
            "operator sees corrupt-manifest error: {}",
            err.message
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_read_plugins_manifest_rejects_symlink() {
        use std::os::unix::fs::symlink;

        let dir = TempDir::new().unwrap();
        let target = dir.path().join("outside-manifest.json");
        std::fs::write(&target, br#"{"redirected":true}"#).unwrap();
        symlink(&target, dir.path().join(PLUGINS_MANIFEST_FILE)).unwrap();

        let err = read_plugins_manifest(dir.path())
            .expect_err("manifest reads must reject symlinked manifests");

        assert_eq!(err.code, ERROR_INVALID_REQUEST);
        assert!(err.message.contains("plugins manifest"));
        assert!(err.message.contains("is not a regular file"));
    }

    #[test]
    fn test_read_plugins_manifest_rejects_non_file() {
        let dir = TempDir::new().unwrap();
        std::fs::create_dir(dir.path().join(PLUGINS_MANIFEST_FILE)).unwrap();

        let err = read_plugins_manifest(dir.path())
            .expect_err("manifest reads must reject non-file manifests");

        assert_eq!(err.code, ERROR_INVALID_REQUEST);
        assert!(err.message.contains("is not a regular file"));
    }

    #[cfg(unix)]
    #[test]
    fn test_read_plugins_manifest_rejects_unix_hardlink() {
        let dir = TempDir::new().unwrap();
        let target = dir.path().join("outside-manifest.json");
        std::fs::write(&target, br#"{"outside":true}"#).unwrap();
        std::fs::hard_link(&target, dir.path().join(PLUGINS_MANIFEST_FILE)).unwrap();

        let err = read_plugins_manifest(dir.path())
            .expect_err("manifest reads must reject hardlinked manifests");

        assert_eq!(err.code, ERROR_INVALID_REQUEST);
        assert!(err.message.contains("plugins manifest"));
        assert!(err.message.contains("is not a regular file"));
    }

    #[cfg(unix)]
    #[test]
    fn test_backup_manifest_rejects_symlink() {
        use std::os::unix::fs::symlink;

        let dir = TempDir::new().unwrap();
        let plugins_dir = dir.path().join("plugins");
        std::fs::create_dir_all(&plugins_dir).unwrap();
        let target = dir.path().join("outside-manifest.json");
        std::fs::write(&target, br#"{"outside":true}"#).unwrap();
        symlink(&target, plugins_dir.join(PLUGINS_MANIFEST_FILE)).unwrap();
        let mut txn = PluginWriteTransaction::new(plugins_dir.clone(), "my-plugin".to_string());

        let err = txn
            .backup_manifest()
            .expect_err("manifest backup must reject symlinked manifest");

        assert_eq!(err.code, ERROR_INVALID_REQUEST);
        assert!(err.message.contains("plugins manifest"));
        assert!(err.message.contains("is not a regular file"));
        assert!(
            !plugins_dir
                .join(format!("{PLUGINS_MANIFEST_FILE}.txn-bak"))
                .exists(),
            "manifest backup must not be created from symlink target bytes"
        );
    }

    #[test]
    fn test_backup_manifest_rejects_non_file() {
        let dir = TempDir::new().unwrap();
        let plugins_dir = dir.path().join("plugins");
        std::fs::create_dir_all(&plugins_dir).unwrap();
        std::fs::create_dir(plugins_dir.join(PLUGINS_MANIFEST_FILE)).unwrap();
        let mut txn = PluginWriteTransaction::new(plugins_dir, "my-plugin".to_string());

        let err = txn
            .backup_manifest()
            .expect_err("manifest backup must reject non-file manifest path");

        assert_eq!(err.code, ERROR_INVALID_REQUEST);
        assert!(err.message.contains("is not a regular file"));
    }

    #[cfg(unix)]
    #[test]
    fn test_rollback_manifest_rejects_symlinked_backup() {
        use std::os::unix::fs::symlink;

        let dir = TempDir::new().unwrap();
        let plugins_dir = dir.path().join("plugins");
        std::fs::create_dir_all(&plugins_dir).unwrap();
        let manifest = plugins_dir.join(PLUGINS_MANIFEST_FILE);
        let backup = plugins_dir.join(format!("{PLUGINS_MANIFEST_FILE}.txn-bak"));
        let outside = dir.path().join("outside-manifest.json");

        std::fs::write(&manifest, br#"{"after_failed_write":true}"#).unwrap();
        std::fs::write(&outside, br#"{"outside":true}"#).unwrap();
        symlink(&outside, &backup).unwrap();

        let mut txn = PluginWriteTransaction::new(plugins_dir.clone(), "my-plugin".to_string());
        txn.manifest_backup = Some(backup.clone());
        txn.rollback_manifest();

        assert_eq!(
            std::fs::read_to_string(&manifest).unwrap(),
            r#"{"after_failed_write":true}"#
        );
        assert_eq!(
            std::fs::read_to_string(&outside).unwrap(),
            r#"{"outside":true}"#
        );
        assert!(
            std::fs::symlink_metadata(&backup)
                .unwrap()
                .file_type()
                .is_symlink(),
            "symlinked rollback backup must not be renamed into the manifest path"
        );
    }

    #[test]
    fn test_validate_plugin_wasm_bytes_rejects_invalid_component() {
        let err = validate_plugin_wasm_bytes(
            &[0x00, 0x61, 0x73, 0x6D, 0x02, 0x00, 0x00, 0x00],
            "test plugin",
        )
        .unwrap_err();
        assert_eq!(err.code, ERROR_INVALID_REQUEST);
        assert!(err
            .message
            .contains("test plugin is not a valid WASM plugin component"));
    }

    // ---- Install handler tests ----

    #[test]
    fn test_install_refuses_corrupt_manifest_so_peer_entries_are_not_wiped() {
        // SECURITY regression: a corrupt manifest must NOT be silently
        // treated as empty by the install handler. Before the fix, the
        // install RMW path read manifest -> {}, added the new entry,
        // wrote back the manifest containing only the new entry — every
        // peer plugin's signature/sha256/publisher_key was lost on the
        // next install operation. Now the read fails fast and the
        // operator must repair (or remove) the manifest before any
        // further install/update can proceed. Uses the adopt path
        // (no URL) so we exercise the manifest read without needing
        // to mock the downloader.
        let dir = TempDir::new().unwrap();
        let plugins_dir = dir.path().join("plugins");
        std::fs::create_dir_all(&plugins_dir).unwrap();
        let wasm_bytes = tool_plugin_component_bytes();
        std::fs::write(plugins_dir.join("new-plugin.wasm"), &wasm_bytes).unwrap();
        // Seed the manifest with peer entries plus corruption appended.
        let peer_manifest_json = serde_json::to_string_pretty(&json!({
            "peer-plugin-one": {
                "name": "peer-plugin-one",
                "version": "0.1.0",
                "path": "peer-plugin-one.wasm",
                "sha256": "abc123",
                "signature": "deadbeef",
                "publisherKey": "key-one"
            }
        }))
        .unwrap();
        let corrupted = format!("{peer_manifest_json}\n<<truncated by disk failure>>");
        std::fs::write(plugins_dir.join(PLUGINS_MANIFEST_FILE), &corrupted).unwrap();
        let params = json!({ "name": "new-plugin", "version": "1.0.0" });
        let _env = TestConfigEnv::new();
        let err = handle_plugins_install_inner(Some(&params), &plugins_dir, &SsrfConfig::default())
            .expect_err("install must refuse to proceed on corrupt manifest");
        assert_eq!(err.code, ERROR_UNAVAILABLE);
        assert!(
            err.message.contains("plugins manifest is corrupt"),
            "operator sees corrupt-manifest error rather than a generic install failure: {}",
            err.message
        );
        // The manifest on disk must remain untouched: a fail-closed
        // install MUST NOT have rewritten it.
        let on_disk = std::fs::read_to_string(plugins_dir.join(PLUGINS_MANIFEST_FILE)).unwrap();
        assert_eq!(
            on_disk, corrupted,
            "corrupt manifest must not be rewritten by a failed install attempt"
        );
    }

    #[test]
    fn test_install_missing_name() {
        let dir = TempDir::new().unwrap();
        let result = handle_plugins_install_inner(None, dir.path(), &SsrfConfig::default());
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code, ERROR_INVALID_REQUEST);
        assert!(err.message.contains("name is required"));
    }

    #[test]
    fn test_install_empty_name() {
        let dir = TempDir::new().unwrap();
        let params = json!({ "name": "  " });
        let result =
            handle_plugins_install_inner(Some(&params), dir.path(), &SsrfConfig::default());
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.message.contains("name is required"));
    }

    #[test]
    fn test_install_invalid_name_chars() {
        let dir = TempDir::new().unwrap();
        let params = json!({ "name": "../etc/passwd" });
        let result =
            handle_plugins_install_inner(Some(&params), dir.path(), &SsrfConfig::default());
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.message.contains("alphanumeric"));
    }

    #[test]
    fn test_install_reserved_name() {
        let dir = TempDir::new().unwrap();
        let params = json!({ "name": "entries" });
        let result =
            handle_plugins_install_inner(Some(&params), dir.path(), &SsrfConfig::default());
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.message.contains("reserved"));
    }

    #[test]
    fn test_install_invalid_url_scheme() {
        let dir = TempDir::new().unwrap();
        let params = json!({ "name": "test-plugin", "url": "ftp://example.com/foo.wasm" });
        let result =
            handle_plugins_install_inner(Some(&params), dir.path(), &SsrfConfig::default());
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.message.contains("unsupported url scheme"));
    }

    #[test]
    fn test_install_invalid_url_parse() {
        let dir = TempDir::new().unwrap();
        let params = json!({ "name": "test-plugin", "url": "not a url" });
        let result =
            handle_plugins_install_inner(Some(&params), dir.path(), &SsrfConfig::default());
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.message.contains("invalid url"));
    }

    #[test]
    fn test_install_no_url_requires_existing_local_wasm() {
        let dir = TempDir::new().unwrap();
        let plugins_dir = dir.path().join("plugins");
        let params = json!({ "name": "my-plugin", "version": "2.0.0" });

        let _env = TestConfigEnv::new();

        let err = handle_plugins_install_inner(Some(&params), &plugins_dir, &SsrfConfig::default())
            .unwrap_err();
        assert!(err
            .message
            .contains("url is required unless a matching local WASM already exists"));
    }

    #[test]
    fn test_install_no_url_adopts_existing_local_wasm() {
        let dir = TempDir::new().unwrap();
        let plugins_dir = dir.path().join("plugins");
        std::fs::create_dir_all(&plugins_dir).unwrap();
        let wasm_bytes = tool_plugin_component_bytes();
        let wasm_path = plugins_dir.join("my-plugin.wasm");
        std::fs::write(&wasm_path, &wasm_bytes).unwrap();
        let params = json!({ "name": "my-plugin", "version": "2.0.0" });

        let _env = TestConfigEnv::new();
        let result =
            handle_plugins_install_inner(Some(&params), &plugins_dir, &SsrfConfig::default())
                .unwrap();

        let manifest = read_plugins_manifest(&plugins_dir).unwrap();
        assert_eq!(manifest["my-plugin"]["name"], "my-plugin");
        assert_eq!(manifest["my-plugin"]["version"], "2.0.0");
        // CORRECTNESS: manifest stores RELATIVE artifact filename
        // (e.g. "my-plugin.wasm"), not absolute path. The bootstrap
        // loader (`plugin_bootstrap::manifest_entry_relative_path`)
        // requires relative; an absolute write would land every
        // plugin in PluginActivationState::Failed on next daemon
        // restart. The pre-Batch-45 wire shape was absolute and
        // accepted by master's looser loader, but the tightened
        // loader now requires relative.
        let _ = &wasm_path; // path was previously asserted absolute
        assert_eq!(manifest["my-plugin"]["path"], "my-plugin.wasm");
        assert_eq!(
            manifest["my-plugin"]["sha256"],
            compute_sha256_hex(&wasm_bytes)
        );
        assert_eq!(result["activation"]["state"], "restart-required");
    }

    #[cfg(unix)]
    #[test]
    fn test_install_no_url_rejects_symlinked_existing_local_wasm() {
        use std::os::unix::fs::symlink;

        let dir = TempDir::new().unwrap();
        let plugins_dir = dir.path().join("plugins");
        std::fs::create_dir_all(&plugins_dir).unwrap();
        let target = dir.path().join("outside.wasm");
        std::fs::write(&target, tool_plugin_component_bytes()).unwrap();
        symlink(&target, plugins_dir.join("my-plugin.wasm")).unwrap();
        let params = json!({ "name": "my-plugin", "version": "2.0.0" });

        let _env = TestConfigEnv::new();
        let err = handle_plugins_install_inner(Some(&params), &plugins_dir, &SsrfConfig::default())
            .unwrap_err();

        assert_eq!(err.code, ERROR_INVALID_REQUEST);
        assert!(err.message.contains("is not a regular file"));
    }

    #[cfg(unix)]
    #[test]
    fn test_url_transaction_rejects_symlinked_existing_artifact_before_backup() {
        use std::os::unix::fs::symlink;

        let dir = TempDir::new().unwrap();
        let plugins_dir = dir.path().join("plugins");
        std::fs::create_dir_all(&plugins_dir).unwrap();
        let target = dir.path().join("outside.wasm");
        std::fs::write(&target, tool_plugin_component_bytes()).unwrap();
        symlink(&target, plugins_dir.join("my-plugin.wasm")).unwrap();
        let mut txn = PluginWriteTransaction::new(plugins_dir.clone(), "my-plugin".to_string());

        let err = txn
            .backup_artifact()
            .expect_err("downloaded install/update must reject symlinked active artifact");

        assert_eq!(err.code, ERROR_INVALID_REQUEST);
        assert!(err.message.contains("is not a regular file"));
        assert!(
            !plugins_dir.join("my-plugin.wasm.txn-bak").exists(),
            "backup must not be created from a dereferenced symlink target"
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_url_transaction_rejects_hardlinked_existing_artifact_before_backup() {
        let dir = TempDir::new().unwrap();
        let plugins_dir = dir.path().join("plugins");
        std::fs::create_dir_all(&plugins_dir).unwrap();
        let target = dir.path().join("outside.wasm");
        std::fs::write(&target, tool_plugin_component_bytes()).unwrap();
        std::fs::hard_link(&target, plugins_dir.join("my-plugin.wasm")).unwrap();
        let mut txn = PluginWriteTransaction::new(plugins_dir.clone(), "my-plugin".to_string());

        let err = txn
            .backup_artifact()
            .expect_err("downloaded install/update must reject hardlinked active artifact");

        assert_eq!(err.code, ERROR_INVALID_REQUEST);
        assert!(err.message.contains("is not a regular file"));
        assert!(
            !plugins_dir.join("my-plugin.wasm.txn-bak").exists(),
            "backup must not be created from a hardlinked artifact"
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_rollback_artifact_rejects_symlinked_backup() {
        use std::os::unix::fs::symlink;

        let dir = TempDir::new().unwrap();
        let plugins_dir = dir.path().join("plugins");
        std::fs::create_dir_all(&plugins_dir).unwrap();
        let artifact = plugins_dir.join("my-plugin.wasm");
        let backup = plugins_dir.join("my-plugin.wasm.txn-bak");
        let outside = dir.path().join("outside.wasm");

        std::fs::write(&artifact, b"new-after-failed-write").unwrap();
        std::fs::write(&outside, b"outside-original").unwrap();
        symlink(&outside, &backup).unwrap();

        let mut txn = PluginWriteTransaction::new(plugins_dir.clone(), "my-plugin".to_string());
        txn.artifact_backup = Some(backup.clone());
        txn.rollback_artifact();

        assert_eq!(std::fs::read(&artifact).unwrap(), b"new-after-failed-write");
        assert_eq!(std::fs::read(&outside).unwrap(), b"outside-original");
        assert!(
            std::fs::symlink_metadata(&backup)
                .unwrap()
                .file_type()
                .is_symlink(),
            "symlinked rollback backup must not be renamed into the artifact path"
        );
    }

    /// Regression for R58 H-PL1: after a successful rollback the
    /// cleanup must remove the .txn-bak file when no swap has
    /// occurred. Pairs with the swap-test below which verifies the
    /// cleanup correctly SKIPS removal on identity mismatch.
    #[cfg(unix)]
    #[test]
    fn test_rollback_restore_cleans_up_backup_on_happy_path() {
        let dir = TempDir::new().unwrap();
        let plugins_dir = dir.path().join("plugins");
        std::fs::create_dir_all(&plugins_dir).unwrap();
        let manifest = plugins_dir.join(PLUGINS_MANIFEST_FILE);
        let backup = plugins_dir.join(format!("{PLUGINS_MANIFEST_FILE}.txn-bak"));

        std::fs::write(&manifest, br#"{"after_failed_write":true}"#).unwrap();
        std::fs::write(&backup, br#"{"original_manifest":true}"#).unwrap();

        restore_transaction_backup(
            &backup,
            &manifest,
            "plugins manifest",
            MAX_MANAGED_PLUGIN_MANIFEST_BYTES,
        )
        .unwrap();

        assert_eq!(
            std::fs::read_to_string(&manifest).unwrap(),
            r#"{"original_manifest":true}"#,
            "rollback must restore the backup over the destination"
        );
        assert!(
            !backup.exists(),
            "cleanup must remove the .txn-bak after a successful rollback"
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_rollback_restore_uses_opened_backup_identity_after_path_swap() {
        let dir = TempDir::new().unwrap();
        let plugins_dir = dir.path().join("plugins");
        std::fs::create_dir_all(&plugins_dir).unwrap();
        let manifest = plugins_dir.join(PLUGINS_MANIFEST_FILE);
        let backup = plugins_dir.join(format!("{PLUGINS_MANIFEST_FILE}.txn-bak"));
        let outside = dir.path().join("outside-manifest.json");

        std::fs::write(&manifest, br#"{"after_failed_write":true}"#).unwrap();
        std::fs::write(&backup, br#"{"original_manifest":true}"#).unwrap();
        std::fs::write(&outside, br#"{"outside":true}"#).unwrap();

        let backup_for_hook = backup.clone();
        let outside_for_hook = outside.clone();
        let _hook = TransactionRestoreHookGuard::set(Box::new(move |backup_path, _dest| {
            if backup_path == backup_for_hook {
                std::fs::remove_file(&backup_for_hook).unwrap();
                std::fs::hard_link(&outside_for_hook, &backup_for_hook).unwrap();
            }
        }));

        restore_transaction_backup(
            &backup,
            &manifest,
            "plugins manifest",
            MAX_MANAGED_PLUGIN_MANIFEST_BYTES,
        )
        .unwrap();

        assert_eq!(
            std::fs::read_to_string(&manifest).unwrap(),
            r#"{"original_manifest":true}"#
        );
        assert_eq!(
            std::fs::read_to_string(&outside).unwrap(),
            r#"{"outside":true}"#
        );
        assert_eq!(
            std::fs::read_to_string(&backup).unwrap(),
            r#"{"outside":true}"#,
            "swapped backup path must not be renamed into the manifest"
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_rollback_failures_are_durably_audited() {
        use std::os::unix::fs::symlink;

        let mut env = TestConfigEnv::new();
        let dir = TempDir::new().unwrap();
        let state_dir = dir.path().join("state");
        let plugins_dir = dir.path().join("plugins");
        std::fs::create_dir_all(&plugins_dir).unwrap();
        std::fs::create_dir_all(&state_dir).unwrap();
        env.set_state_dir(&state_dir);

        let manifest = plugins_dir.join(PLUGINS_MANIFEST_FILE);
        let manifest_backup = plugins_dir.join(format!("{PLUGINS_MANIFEST_FILE}.txn-bak"));
        let artifact = plugins_dir.join("my-plugin.wasm");
        let artifact_backup = plugins_dir.join("my-plugin.wasm.txn-bak");
        let outside_manifest = dir.path().join("outside-manifest.json");
        let outside_artifact = dir.path().join("outside.wasm");

        std::fs::write(&manifest, br#"{"after_failed_write":true}"#).unwrap();
        std::fs::write(&outside_manifest, br#"{"outside":true}"#).unwrap();
        symlink(&outside_manifest, &manifest_backup).unwrap();
        let mut manifest_txn =
            PluginWriteTransaction::new(plugins_dir.clone(), "my-plugin".to_string());
        manifest_txn.manifest_backup = Some(manifest_backup);
        manifest_txn.rollback_manifest();

        std::fs::write(&artifact, b"new-after-failed-write").unwrap();
        std::fs::write(&outside_artifact, b"outside-original").unwrap();
        symlink(&outside_artifact, &artifact_backup).unwrap();
        let mut artifact_txn =
            PluginWriteTransaction::new(plugins_dir.clone(), "my-plugin".to_string());
        artifact_txn.artifact_backup = Some(artifact_backup);
        artifact_txn.rollback_artifact();

        std::fs::remove_file(&artifact).unwrap();
        std::fs::create_dir(&artifact).unwrap();
        let mut first_install_txn =
            PluginWriteTransaction::new(plugins_dir.clone(), "my-plugin".to_string());
        first_install_txn.artifact_written = true;
        first_install_txn.rollback_artifact();

        let events = audit_event_names(&state_dir);
        assert!(events.contains(&"managed_plugin_manifest_rollback_failed".to_string()));
        assert!(events.contains(&"managed_plugin_artifact_rollback_failed".to_string()));
        assert!(events.contains(&"managed_plugin_first_install_cleanup_failed".to_string()));
    }

    #[test]
    fn test_url_transaction_rejects_oversized_existing_artifact_before_backup_allocation() {
        let dir = TempDir::new().unwrap();
        let plugins_dir = dir.path().join("plugins");
        std::fs::create_dir_all(&plugins_dir).unwrap();
        let artifact = plugins_dir.join("my-plugin.wasm");
        std::fs::File::create(&artifact)
            .unwrap()
            .set_len(MAX_MANAGED_PLUGIN_ARTIFACT_BYTES + 1)
            .unwrap();
        let mut txn = PluginWriteTransaction::new(plugins_dir.clone(), "my-plugin".to_string());

        let err = txn
            .backup_artifact()
            .expect_err("oversized active artifact must be rejected before backup allocation");

        assert_eq!(err.code, ERROR_INVALID_REQUEST);
        assert!(err.message.contains("exceeds maximum size"));
        assert!(
            !plugins_dir.join("my-plugin.wasm.txn-bak").exists(),
            "oversized artifact must not produce a transaction backup"
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_url_install_handler_rejects_symlinked_active_artifact() {
        use std::os::unix::fs::symlink;

        let dir = TempDir::new().unwrap();
        let plugins_dir = dir.path().join("plugins");
        std::fs::create_dir_all(&plugins_dir).unwrap();
        let target = dir.path().join("outside.wasm");
        std::fs::write(&target, b"outside-original").unwrap();
        let active_artifact = plugins_dir.join("my-plugin.wasm");
        symlink(&target, &active_artifact).unwrap();
        let params = json!({
            "name": "my-plugin",
            "url": "https://example.com/my-plugin.wasm"
        });

        let _env = TestConfigEnv::new();
        let err = handle_plugins_install_inner_with_downloader(
            Some(&params),
            &plugins_dir,
            &SsrfConfig::default(),
            downloaded_test_plugin_wasm,
        )
        .expect_err("URL install must reject symlinked active artifact before overwrite");

        assert_eq!(err.code, ERROR_INVALID_REQUEST);
        assert!(err.message.contains("managed plugin artifact"));
        assert!(err.message.contains("is not a regular file"));
        assert_eq!(std::fs::read(&target).unwrap(), b"outside-original");
        assert!(
            std::fs::symlink_metadata(&active_artifact)
                .unwrap()
                .file_type()
                .is_symlink(),
            "active artifact symlink must remain untouched"
        );
    }

    #[test]
    fn test_install_rejects_missing_signature_before_manifest_write() {
        let dir = TempDir::new().unwrap();
        let plugins_dir = dir.path().join("plugins");
        std::fs::create_dir_all(&plugins_dir).unwrap();
        let wasm_bytes = tool_plugin_component_bytes();
        std::fs::write(plugins_dir.join("my-plugin.wasm"), &wasm_bytes).unwrap();
        let params = json!({ "name": "my-plugin", "version": "2.0.0" });

        let _env = TestConfigEnv::new();
        write_config_file(
            &config::get_config_path(),
            &json!({ "plugins": { "signature": { "requireSignature": true } } }),
        )
        .unwrap();
        crate::config::clear_cache();

        let err = handle_plugins_install_inner(Some(&params), &plugins_dir, &SsrfConfig::default())
            .unwrap_err();

        assert_eq!(err.code, ERROR_INVALID_REQUEST);
        assert!(err.message.contains("plugin signature policy rejected"));
        assert!(
            !plugins_dir.join(PLUGINS_MANIFEST_FILE).exists(),
            "signature-policy rejection must happen before manifest write"
        );
    }

    /// Batch 113: `PluginCliLockGuard::drop` must recover when a
    /// same-uid attacker (or operator manual cleanup) replaced the
    /// `.cli-lock` dirent with a directory between acquire and
    /// release. Without the EISDIR fallback, every subsequent
    /// acquire for that plugin returns `Unavailable` because the
    /// B118: stale `.cli-lock` sweep at daemon startup. Pre-seed
    /// the plugins dir with three sentinel sidecars:
    ///   - one whose recorded PID belongs to a dead process (PID
    ///     2_000_000_001 — a u32 well above any realistic running
    ///     PID; `kill(pid, 0)` returns ESRCH)
    ///   - one whose recorded PID is the running test process
    ///     (alive — must NOT be swept)
    ///   - one whose contents are garbage (must NOT be swept — the
    ///     sweep declines to interpret unparseable PIDs)
    ///
    /// Plus a non-`.cli-lock` peer file (must not be touched).
    #[cfg(unix)]
    #[test]
    fn test_sweep_stale_plugin_cli_locks_removes_only_dead_pids() {
        let dir = TempDir::new().unwrap();
        let plugins_dir = dir.path().join("plugins");
        std::fs::create_dir_all(&plugins_dir).unwrap();

        let dead = plugins_dir.join("dead.wasm.cli-lock");
        std::fs::write(&dead, "2000000001").unwrap();
        let alive = plugins_dir.join("alive.wasm.cli-lock");
        std::fs::write(&alive, std::process::id().to_string()).unwrap();
        let garbage = plugins_dir.join("garbage.wasm.cli-lock");
        std::fs::write(&garbage, "not-a-pid").unwrap();
        let peer = plugins_dir.join("peer.wasm");
        std::fs::write(&peer, b"wasm-bytes").unwrap();

        sweep_stale_plugin_cli_locks(&plugins_dir);

        assert!(
            !dead.exists(),
            "dead-PID .cli-lock must be reaped by the startup sweep"
        );
        assert!(
            alive.exists(),
            "alive-PID .cli-lock must remain — the sweep must not race a still-running lock holder"
        );
        assert!(
            garbage.exists(),
            "unparseable .cli-lock must remain — the sweep declines to interpret"
        );
        assert!(peer.exists(), "non-.cli-lock peer files must be untouched");
    }

    /// B118: empty plugins dir must be a no-op (no panic, no error).
    #[test]
    fn test_sweep_stale_plugin_cli_locks_empty_dir_is_noop() {
        let dir = TempDir::new().unwrap();
        let plugins_dir = dir.path().join("plugins");
        std::fs::create_dir_all(&plugins_dir).unwrap();
        sweep_stale_plugin_cli_locks(&plugins_dir);
        assert!(plugins_dir.exists());
    }

    /// B118: missing plugins dir must be a no-op (first-run startup
    /// where the dir hasn't been created yet should not panic).
    #[test]
    fn test_sweep_stale_plugin_cli_locks_missing_dir_is_noop() {
        let dir = TempDir::new().unwrap();
        let plugins_dir = dir.path().join("nonexistent-plugins-dir");
        sweep_stale_plugin_cli_locks(&plugins_dir);
        assert!(!plugins_dir.exists());
    }

    /// dirent still exists.
    #[cfg(unix)]
    #[test]
    fn test_plugin_cli_lock_guard_drop_removes_dirent_replaced_by_directory() {
        let dir = TempDir::new().unwrap();
        let plugins_dir = dir.path().join("plugins");
        std::fs::create_dir_all(&plugins_dir).unwrap();
        let guard = acquire_plugin_cli_lock_for_daemon_write(&plugins_dir, "demo").unwrap();
        let lock_path = guard.path.clone();
        // Simulate the attacker swap: remove the file, then create
        // an EMPTY directory at the same path. (`remove_dir` only
        // succeeds on empty dirs, so the fallback must also leave
        // it in a removable state.)
        std::fs::remove_file(&lock_path).unwrap();
        std::fs::create_dir(&lock_path).unwrap();
        // Drop the guard — Drop's EISDIR fallback should reap the
        // directory.
        drop(guard);
        assert!(
            !lock_path.exists(),
            "Drop must reap the directory dirent via remove_dir fallback"
        );
    }

    /// Batch 112: `PluginWriteTransaction`'s `Drop` impl is the
    /// panic-safety net for the install/update flow. If the
    /// transaction is dropped without `commit()`, Drop must run
    /// rollback on both the manifest and the artifact so a panic
    /// between artifact-write and the final commit does not leave
    /// the daemon with a half-installed plugin.
    ///
    /// This test exercises the Drop path directly: build a
    /// transaction, simulate the post-artifact-write state by
    /// hand, then drop without committing. The on-disk artifact
    /// should be restored from `.txn-bak`.
    #[test]
    fn test_plugin_write_transaction_drop_restores_artifact() {
        let dir = TempDir::new().unwrap();
        let plugins_dir = dir.path().join("plugins");
        std::fs::create_dir_all(&plugins_dir).unwrap();
        let original_bytes = b"original-wasm-bytes".to_vec();
        let artifact_path = plugins_dir.join("demo.wasm");
        std::fs::write(&artifact_path, &original_bytes).unwrap();

        // Use a hand-crafted backup at `.txn-bak`, mark the
        // transaction as having backed up + written the artifact,
        // and then OVERWRITE the live artifact with new bytes (the
        // post-write-but-pre-commit state).
        let backup_path = plugins_dir.join("demo.wasm.txn-bak");
        std::fs::write(&backup_path, &original_bytes).unwrap();
        std::fs::write(&artifact_path, b"new-bytes-that-must-be-rolled-back").unwrap();

        {
            let mut txn = PluginWriteTransaction::new(plugins_dir.clone(), "demo".to_string());
            txn.artifact_backup = Some(backup_path.clone());
            txn.artifact_written = true;
            // Drop without commit — simulates a panic between
            // artifact write and the final commit().
        }

        let restored = std::fs::read(&artifact_path).expect("restored artifact must exist");
        assert_eq!(
            restored, original_bytes,
            "Drop must restore artifact from .txn-bak when not committed"
        );
        assert!(
            !backup_path.exists(),
            "Drop must consume the backup after successful restore"
        );
    }

    /// Companion: when `commit()` is called, Drop is a no-op.
    #[test]
    fn test_plugin_write_transaction_drop_after_commit_is_noop() {
        let dir = TempDir::new().unwrap();
        let plugins_dir = dir.path().join("plugins");
        std::fs::create_dir_all(&plugins_dir).unwrap();
        let committed_bytes = b"committed-bytes-stay-on-disk".to_vec();
        let artifact_path = plugins_dir.join("demo.wasm");
        std::fs::write(&artifact_path, &committed_bytes).unwrap();

        {
            let mut txn = PluginWriteTransaction::new(plugins_dir.clone(), "demo".to_string());
            // No backup created; the install is effectively complete.
            txn.artifact_written = true;
            txn.commit();
            // commit() must clear artifact_written so Drop sees no
            // work to do.
            assert!(!txn.artifact_written);
            assert!(txn.committed);
            // Drop runs here — should NOT touch the live artifact.
        }

        assert_eq!(
            std::fs::read(&artifact_path).unwrap(),
            committed_bytes,
            "post-commit Drop must NOT remove or modify the live artifact"
        );
    }

    #[test]
    fn test_concurrent_installs_preserve_manifest_entries() {
        let dir = TempDir::new().unwrap();
        let plugins_dir = dir.path().join("plugins");
        std::fs::create_dir_all(&plugins_dir).unwrap();
        let wasm_bytes = tool_plugin_component_bytes();
        std::fs::write(plugins_dir.join("alpha.wasm"), &wasm_bytes).unwrap();
        std::fs::write(plugins_dir.join("beta.wasm"), &wasm_bytes).unwrap();

        let _env = TestConfigEnv::new();
        let alpha_dir = plugins_dir.clone();
        let beta_dir = plugins_dir.clone();

        std::thread::scope(|scope| {
            let alpha = scope.spawn(move || {
                let params = json!({ "name": "alpha" });
                handle_plugins_install_inner(Some(&params), &alpha_dir, &SsrfConfig::default())
            });
            let beta = scope.spawn(move || {
                let params = json!({ "name": "beta" });
                handle_plugins_install_inner(Some(&params), &beta_dir, &SsrfConfig::default())
            });
            alpha
                .join()
                .expect("alpha install thread should not panic")
                .unwrap();
            beta.join()
                .expect("beta install thread should not panic")
                .unwrap();
        });

        let manifest = read_plugins_manifest(&plugins_dir).unwrap();
        assert_eq!(manifest["alpha"]["name"], "alpha");
        assert_eq!(manifest["beta"]["name"], "beta");
    }

    #[test]
    fn test_install_with_url_refuses_when_cli_lock_present() {
        // SECURITY: download-driven daemon install must not overwrite a
        // wasm artifact that a CLI `--file` mutation is currently staging
        // (or has just renamed into place). The CLI advertises its
        // ownership of `<dest>.wasm.cli-lock`; the daemon must honor it.
        let dir = TempDir::new().unwrap();
        let plugins_dir = dir.path().join("plugins");
        std::fs::create_dir_all(&plugins_dir).unwrap();
        let pre_existing_bytes = b"cli-staged-bytes".to_vec();
        std::fs::write(plugins_dir.join("my-plugin.wasm"), &pre_existing_bytes).unwrap();
        let cli_lock = plugins_dir.join("my-plugin.wasm.cli-lock");
        std::fs::write(&cli_lock, "12345").unwrap();

        let _env = TestConfigEnv::new();
        let params = json!({
            "name": "my-plugin",
            "url": "https://example.com/my-plugin.wasm"
        });
        let err = handle_plugins_install_inner_with_downloader(
            Some(&params),
            &plugins_dir,
            &SsrfConfig::default(),
            downloaded_test_plugin_wasm,
        )
        .expect_err("daemon install with URL must refuse while .cli-lock is held");

        assert_eq!(err.code, ERROR_UNAVAILABLE);
        assert!(
            err.message.contains("staging lock"),
            "expected message to mention staging lock: {}",
            err.message
        );
        assert!(err.retryable, "lock-busy error must be retryable");
        // CLI's pre-existing wasm bytes must not have been clobbered.
        assert_eq!(
            std::fs::read(plugins_dir.join("my-plugin.wasm")).unwrap(),
            pre_existing_bytes,
            "daemon must not overwrite the CLI-staged artifact while lock is held"
        );
        // Daemon must not have removed the CLI's lock file.
        assert!(
            cli_lock.exists(),
            "daemon must not remove a lock it did not acquire"
        );
    }

    #[test]
    fn test_install_no_url_does_not_acquire_cli_lock() {
        // The adopt path (url=None) is the CLI's `--file` round-trip;
        // the CLI process is the lock holder here. The daemon must NOT
        // try to take the lock itself, or it would deadlock the very
        // CLI request that's calling it.
        let dir = TempDir::new().unwrap();
        let plugins_dir = dir.path().join("plugins");
        std::fs::create_dir_all(&plugins_dir).unwrap();
        let wasm_bytes = tool_plugin_component_bytes();
        std::fs::write(plugins_dir.join("my-plugin.wasm"), &wasm_bytes).unwrap();
        // Simulate the CLI holding its own lock during the adopt call.
        let cli_lock = plugins_dir.join("my-plugin.wasm.cli-lock");
        std::fs::write(&cli_lock, "12345").unwrap();

        let _env = TestConfigEnv::new();
        let params = json!({ "name": "my-plugin" });
        handle_plugins_install_inner(Some(&params), &plugins_dir, &SsrfConfig::default())
            .expect("adopt path must succeed even when the CLI lock is held");

        // CLI lock must still be present — daemon did not own it, so
        // daemon's guard drop must not have removed it.
        assert!(cli_lock.exists(), "daemon must not remove the CLI's lock");
    }

    #[test]
    fn test_install_with_url_removes_cli_lock_after_success() {
        // When the daemon owns the lock for its download-driven write,
        // the guard's Drop must release the sentinel so a follow-up
        // mutation can proceed.
        let dir = TempDir::new().unwrap();
        let plugins_dir = dir.path().join("plugins");
        std::fs::create_dir_all(&plugins_dir).unwrap();

        let _env = TestConfigEnv::new();
        let params = json!({
            "name": "my-plugin",
            "url": "https://example.com/my-plugin.wasm"
        });
        handle_plugins_install_inner_with_downloader(
            Some(&params),
            &plugins_dir,
            &SsrfConfig::default(),
            downloaded_test_plugin_wasm,
        )
        .expect("daemon install with URL should succeed when no lock contention");

        let cli_lock = plugins_dir.join("my-plugin.wasm.cli-lock");
        assert!(
            !cli_lock.exists(),
            "daemon must release its staging lock on success"
        );
    }

    #[test]
    fn test_update_with_url_refuses_when_cli_lock_present() {
        // Same contract as install: the update path must also honor the
        // CLI-side advisory lock so CLI `update --file` is not overrun.
        let dir = TempDir::new().unwrap();
        let plugins_dir = dir.path().join("plugins");
        std::fs::create_dir_all(&plugins_dir).unwrap();
        let wasm_bytes = tool_plugin_component_bytes();
        std::fs::write(plugins_dir.join("my-plugin.wasm"), &wasm_bytes).unwrap();

        // Seed the manifest so update has something to update.
        let _env = TestConfigEnv::new();
        let install_params = json!({ "name": "my-plugin" });
        handle_plugins_install_inner(Some(&install_params), &plugins_dir, &SsrfConfig::default())
            .expect("seed install should succeed");

        let cli_lock = plugins_dir.join("my-plugin.wasm.cli-lock");
        std::fs::write(&cli_lock, "12345").unwrap();
        let pre_update_bytes = std::fs::read(plugins_dir.join("my-plugin.wasm")).unwrap();

        let update_params = json!({
            "name": "my-plugin",
            "url": "https://example.com/my-plugin.wasm"
        });
        let err = handle_plugins_update_inner_with_downloader(
            Some(&update_params),
            &plugins_dir,
            &SsrfConfig::default(),
            downloaded_test_plugin_wasm,
        )
        .expect_err("daemon update with URL must refuse while .cli-lock is held");

        assert_eq!(err.code, ERROR_UNAVAILABLE);
        assert!(err.retryable);
        assert_eq!(
            std::fs::read(plugins_dir.join("my-plugin.wasm")).unwrap(),
            pre_update_bytes,
            "daemon must not overwrite the CLI-staged artifact during update"
        );
        assert!(cli_lock.exists());
    }

    #[test]
    fn test_install_no_url_rejects_oversized_existing_local_wasm_before_read() {
        let dir = TempDir::new().unwrap();
        let plugins_dir = dir.path().join("plugins");
        std::fs::create_dir_all(&plugins_dir).unwrap();
        let wasm_path = plugins_dir.join("my-plugin.wasm");
        let wasm_file = std::fs::File::create(&wasm_path).unwrap();
        wasm_file
            .set_len((MAX_PLUGIN_DOWNLOAD_BYTES as u64) + 1)
            .unwrap();
        let params = json!({ "name": "my-plugin", "version": "2.0.0" });

        let _env = TestConfigEnv::new();
        let err = handle_plugins_install_inner(Some(&params), &plugins_dir, &SsrfConfig::default())
            .unwrap_err();

        assert_eq!(err.code, ERROR_INVALID_REQUEST);
        assert!(err
            .message
            .contains("existing managed plugin binary exceeds maximum size"));
    }

    #[test]
    fn test_install_reports_restart_required_activation() {
        let dir = TempDir::new().unwrap();
        let plugins_dir = dir.path().join("plugins");
        std::fs::create_dir_all(&plugins_dir).unwrap();
        let wasm_bytes = tool_plugin_component_bytes();
        std::fs::write(plugins_dir.join("my-plugin.wasm"), wasm_bytes).unwrap();
        let params = json!({ "name": "my-plugin", "version": "2.0.0" });

        let _env = TestConfigEnv::new();
        let result =
            handle_plugins_install_inner(Some(&params), &plugins_dir, &SsrfConfig::default())
                .unwrap();

        assert_eq!(result["ok"], true);
        assert_eq!(result["activation"]["state"], "restart-required");
        assert_eq!(
            result["activation"]["message"],
            "restart Carapace to activate the installed plugin"
        );
    }

    // ---- Update handler tests ----

    #[test]
    fn test_update_missing_name() {
        let dir = TempDir::new().unwrap();
        let result = handle_plugins_update_inner(None, dir.path(), &SsrfConfig::default());
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code, ERROR_INVALID_REQUEST);
        assert!(err.message.contains("name is required"));
    }

    #[test]
    fn test_update_empty_name() {
        let dir = TempDir::new().unwrap();
        let params = json!({ "name": "" });
        let result = handle_plugins_update_inner(Some(&params), dir.path(), &SsrfConfig::default());
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.message.contains("name is required"));
    }

    #[test]
    fn test_update_invalid_name() {
        let dir = TempDir::new().unwrap();
        let params = json!({ "name": "bad/name" });
        let result = handle_plugins_update_inner(Some(&params), dir.path(), &SsrfConfig::default());
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.message.contains("alphanumeric"));
    }

    #[test]
    fn test_update_reserved_name() {
        let dir = TempDir::new().unwrap();
        let params = json!({ "name": "signature" });
        let result = handle_plugins_update_inner(Some(&params), dir.path(), &SsrfConfig::default());
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.message.contains("reserved"));
    }

    #[test]
    fn test_update_plugin_not_installed() {
        let dir = TempDir::new().unwrap();
        let _env = TestConfigEnv::new();
        std::fs::write(
            dir.path().join("nonexistent.wasm"),
            tool_plugin_component_bytes(),
        )
        .unwrap();
        let params = json!({ "name": "nonexistent" });
        let result = handle_plugins_update_inner(Some(&params), dir.path(), &SsrfConfig::default());
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.message.contains("not installed"));
    }

    #[test]
    fn test_update_adopts_existing_local_wasm_without_url() {
        let dir = TempDir::new().unwrap();
        let _env = TestConfigEnv::new();
        // Pre-create a manifest entry so the plugin is "installed"
        let manifest = json!({
            "my-plugin": {
                "name": "my-plugin",
                "version": "1.0.0",
                "installed_at": 1700000000000u64
            }
        });
        write_plugins_manifest(dir.path(), &manifest).unwrap();
        let wasm_bytes = tool_plugin_component_bytes();
        std::fs::write(dir.path().join("my-plugin.wasm"), &wasm_bytes).unwrap();

        let params = json!({ "name": "my-plugin" });
        let result = handle_plugins_update_inner(Some(&params), dir.path(), &SsrfConfig::default());
        assert!(result.is_ok(), "expected local adoption update to succeed");
        let value = result.unwrap();
        assert_eq!(value["ok"], Value::Bool(true));
        assert_eq!(value["name"], Value::String("my-plugin".to_string()));
        assert_eq!(
            value["activation"]["state"],
            Value::String("restart-required".to_string())
        );
        let read_back = read_plugins_manifest(dir.path()).unwrap();
        assert!(read_back["my-plugin"].get("url").is_none());
    }

    #[cfg(unix)]
    #[test]
    fn test_update_no_url_rejects_symlinked_existing_local_wasm() {
        use std::os::unix::fs::symlink;

        let dir = TempDir::new().unwrap();
        let _env = TestConfigEnv::new();
        let target = dir.path().join("outside.wasm");
        std::fs::write(&target, tool_plugin_component_bytes()).unwrap();
        symlink(&target, dir.path().join("my-plugin.wasm")).unwrap();
        let manifest = json!({
            "my-plugin": {
                "name": "my-plugin",
                "version": "1.0.0",
                "installed_at": 1700000000000u64
            }
        });
        write_plugins_manifest(dir.path(), &manifest).unwrap();

        let err = handle_plugins_update_inner(
            Some(&json!({ "name": "my-plugin" })),
            dir.path(),
            &SsrfConfig::default(),
        )
        .expect_err("update without URL must reject symlinked local WASM");

        assert_eq!(err.code, ERROR_INVALID_REQUEST);
        assert!(err.message.contains("is not a regular file"));
    }

    #[cfg(unix)]
    #[test]
    fn test_install_no_url_rejects_hardlinked_existing_local_wasm() {
        let dir = TempDir::new().unwrap();
        let plugins_dir = dir.path().join("plugins");
        std::fs::create_dir_all(&plugins_dir).unwrap();
        let target = dir.path().join("outside.wasm");
        std::fs::write(&target, tool_plugin_component_bytes()).unwrap();
        std::fs::hard_link(&target, plugins_dir.join("my-plugin.wasm")).unwrap();
        let params = json!({ "name": "my-plugin", "version": "2.0.0" });

        let _env = TestConfigEnv::new();
        let err = handle_plugins_install_inner(Some(&params), &plugins_dir, &SsrfConfig::default())
            .unwrap_err();

        assert_eq!(err.code, ERROR_INVALID_REQUEST);
        assert!(err.message.contains("is not a regular file"));
    }

    #[cfg(unix)]
    #[test]
    fn test_url_update_handler_rejects_symlinked_active_artifact() {
        use std::os::unix::fs::symlink;

        let dir = TempDir::new().unwrap();
        let _env = TestConfigEnv::new();
        let target = dir.path().join("outside.wasm");
        std::fs::write(&target, b"outside-original").unwrap();
        let active_artifact = dir.path().join("my-plugin.wasm");
        symlink(&target, &active_artifact).unwrap();
        let manifest = json!({
            "my-plugin": {
                "name": "my-plugin",
                "version": "1.0.0",
                "installed_at": 1700000000000u64
            }
        });
        write_plugins_manifest(dir.path(), &manifest).unwrap();
        let params = json!({
            "name": "my-plugin",
            "url": "https://example.com/my-plugin.wasm"
        });

        let err = handle_plugins_update_inner_with_downloader(
            Some(&params),
            dir.path(),
            &SsrfConfig::default(),
            downloaded_test_plugin_wasm,
        )
        .expect_err("URL update must reject symlinked active artifact before overwrite");

        assert_eq!(err.code, ERROR_INVALID_REQUEST);
        assert!(err.message.contains("managed plugin artifact"));
        assert!(err.message.contains("is not a regular file"));
        assert_eq!(std::fs::read(&target).unwrap(), b"outside-original");
        assert!(
            std::fs::symlink_metadata(&active_artifact)
                .unwrap()
                .file_type()
                .is_symlink(),
            "active artifact symlink must remain untouched"
        );
    }

    #[test]
    fn test_update_rejects_missing_signature_before_manifest_write() {
        let dir = TempDir::new().unwrap();
        let _env = TestConfigEnv::new();
        let wasm_bytes = tool_plugin_component_bytes();
        std::fs::write(dir.path().join("my-plugin.wasm"), &wasm_bytes).unwrap();

        let manifest = json!({
            "my-plugin": {
                "name": "my-plugin",
                "version": "1.0.0",
                "installed_at": 1700000000000u64
            }
        });
        write_plugins_manifest(dir.path(), &manifest).unwrap();
        write_config_file(
            &config::get_config_path(),
            &json!({ "plugins": { "signature": { "requireSignature": true } } }),
        )
        .unwrap();
        crate::config::clear_cache();

        let err = handle_plugins_update_inner(
            Some(&json!({ "name": "my-plugin" })),
            dir.path(),
            &SsrfConfig::default(),
        )
        .unwrap_err();

        assert_eq!(err.code, ERROR_INVALID_REQUEST);
        assert!(err.message.contains("plugin signature policy rejected"));
        let read_back = read_plugins_manifest(dir.path()).unwrap();
        assert_eq!(read_back["my-plugin"]["version"], "1.0.0");
        assert!(read_back["my-plugin"].get("updated_at").is_none());
    }

    #[test]
    fn test_update_rejects_unmanifested_wasm_file() {
        let dir = TempDir::new().unwrap();
        let _env = TestConfigEnv::new();
        let wasm_bytes = tool_plugin_component_bytes();
        std::fs::write(dir.path().join("disk-plugin.wasm"), &wasm_bytes).unwrap();

        let params = json!({ "name": "disk-plugin" });
        let err = handle_plugins_update_inner(Some(&params), dir.path(), &SsrfConfig::default())
            .expect_err("update must not adopt an unmanifested wasm file");

        assert_eq!(err.code, ERROR_INVALID_REQUEST);
        assert!(err.message.contains("not installed"));
    }

    #[test]
    fn test_update_refreshes_requested_at_and_clears_stale_url() {
        let dir = TempDir::new().unwrap();
        let _env = TestConfigEnv::new();
        let wasm_bytes = tool_plugin_component_bytes();
        std::fs::write(dir.path().join("my-plugin.wasm"), &wasm_bytes).unwrap();

        let manifest = json!({
            "my-plugin": {
                "name": "my-plugin",
                "version": "1.0.0",
                "installed_at": 1700000000000u64,
                "url": "https://example.com/old.wasm"
            }
        });
        write_plugins_manifest(dir.path(), &manifest).unwrap();

        let config_path = config::get_config_path();
        let config_value = json!({
            "plugins": {
                "signature": {
                    "requireSignature": false
                },
                "entries": {
                    "my-plugin": {
                        "enabled": true,
                        "requestedAt": 1700000000000u64
                    }
                }
            }
        });
        write_config_file(&config_path, &config_value).unwrap();

        let result = handle_plugins_update_inner(
            Some(&json!({ "name": "my-plugin" })),
            dir.path(),
            &SsrfConfig::default(),
        )
        .unwrap();
        let updated_at = result["updated_at"].as_u64().unwrap();

        let read_back = read_plugins_manifest(dir.path()).unwrap();
        assert!(read_back["my-plugin"].get("url").is_none());

        let updated_config = read_config_snapshot().config;
        assert_eq!(
            updated_config["plugins"]["entries"]["my-plugin"]["requestedAt"].as_u64(),
            Some(updated_at)
        );
    }

    #[test]
    fn test_update_preserves_disabled_state() {
        let dir = TempDir::new().unwrap();
        let _env = TestConfigEnv::new();
        let wasm_bytes = tool_plugin_component_bytes();
        std::fs::write(dir.path().join("my-plugin.wasm"), &wasm_bytes).unwrap();

        let manifest = json!({
            "my-plugin": {
                "name": "my-plugin",
                "version": "1.0.0",
                "installed_at": 1700000000000u64
            }
        });
        write_plugins_manifest(dir.path(), &manifest).unwrap();

        let config_path = config::get_config_path();
        let config_value = json!({
            "plugins": {
                "signature": {
                    "requireSignature": false
                },
                "entries": {
                    "my-plugin": {
                        "enabled": false,
                        "requestedAt": 1700000000000u64
                    }
                }
            }
        });
        write_config_file(&config_path, &config_value).unwrap();

        let result = handle_plugins_update_inner(
            Some(&json!({ "name": "my-plugin" })),
            dir.path(),
            &SsrfConfig::default(),
        )
        .unwrap();
        assert_eq!(result["ok"], Value::Bool(true));

        let updated_config = read_config_snapshot().config;
        assert_eq!(
            updated_config["plugins"]["entries"]["my-plugin"]["enabled"],
            Value::Bool(false),
            "update should preserve the operator's explicit disabled state"
        );
    }

    #[test]
    fn test_update_preserves_env_placeholder_matrix_secret() {
        let dir = TempDir::new().unwrap();
        let mut env = TestConfigEnv::new();
        env._env
            .set("MATRIX_PASSWORD", "plaintext-from-env")
            .unset("CARAPACE_CONFIG_PASSWORD");
        let wasm_bytes = tool_plugin_component_bytes();
        std::fs::write(dir.path().join("my-plugin.wasm"), &wasm_bytes).unwrap();

        let manifest = json!({
            "my-plugin": {
                "name": "my-plugin",
                "version": "1.0.0",
                "installed_at": 1700000000000u64
            }
        });
        write_plugins_manifest(dir.path(), &manifest).unwrap();

        let config_path = config::get_config_path();
        let config_value = json!({
            "matrix": {
                "homeserverUrl": "https://matrix.example.com",
                "userId": "@cara:example.com",
                "password": "${MATRIX_PASSWORD}",
                "encrypted": false
            },
            "plugins": {
                "signature": {
                    "requireSignature": false
                },
                "entries": {
                    "my-plugin": {
                        "enabled": true,
                        "requestedAt": 1700000000000u64
                    }
                }
            }
        });
        write_config_file(&config_path, &config_value).unwrap();

        handle_plugins_update_inner(
            Some(&json!({ "name": "my-plugin" })),
            dir.path(),
            &SsrfConfig::default(),
        )
        .unwrap();

        let raw = std::fs::read_to_string(&config_path).unwrap();
        assert!(raw.contains("${MATRIX_PASSWORD}"));
        assert!(!raw.contains("plaintext-from-env"));
    }

    #[test]
    fn test_update_without_url_requires_matching_local_wasm() {
        let dir = TempDir::new().unwrap();
        let manifest = json!({
            "missing-wasm": {
                "name": "missing-wasm",
                "installed_at": 1700000000000u64
            }
        });
        write_plugins_manifest(dir.path(), &manifest).unwrap();

        let params = json!({ "name": "missing-wasm" });
        let result = handle_plugins_update_inner(Some(&params), dir.path(), &SsrfConfig::default());
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err
            .message
            .contains("url is required unless a matching local WASM already exists"));
    }

    #[test]
    fn test_update_invalid_url_scheme() {
        let dir = TempDir::new().unwrap();
        let manifest = json!({ "my-plugin": { "name": "my-plugin" } });
        write_plugins_manifest(dir.path(), &manifest).unwrap();

        let params = json!({ "name": "my-plugin", "url": "ftp://example.com/plugin.wasm" });
        let result = handle_plugins_update_inner(Some(&params), dir.path(), &SsrfConfig::default());
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

    // ---- read_plugins_manifest fail-closed tests ----

    #[test]
    fn test_read_plugins_manifest_corrupt_json_fails_closed_with_warning() {
        // Corrupt JSON must fail closed: a silent fallback to {} on
        // parse failure would let install/update RMW wipe every other
        // managed plugin's manifest entry on the next operation.
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join(PLUGINS_MANIFEST_FILE), b"not json {{{{").unwrap();
        let err = read_plugins_manifest(dir.path()).expect_err("corrupt manifest must fail closed");
        assert_eq!(err.code, ERROR_UNAVAILABLE);
        assert!(
            err.message.contains("plugins manifest is corrupt"),
            "operator sees corrupt-manifest error: {}",
            err.message
        );
    }

    #[test]
    fn test_read_plugins_manifest_empty_file_fails_closed() {
        // A present-but-empty file is a torn write (rename happened
        // before content was synced) or operator damage; either way
        // the reconstructor must refuse to start from {} and lose
        // every other entry. The legitimate "no manifest yet" path
        // is file-does-not-exist, which still returns Ok({}).
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join(PLUGINS_MANIFEST_FILE), b"").unwrap();
        let err = read_plugins_manifest(dir.path())
            .expect_err("empty manifest file must fail closed (not interpreted as fresh install)");
        assert_eq!(err.code, ERROR_UNAVAILABLE);
        assert!(
            err.message.contains("plugins manifest is corrupt"),
            "operator sees corrupt-manifest error: {}",
            err.message
        );
    }

    /// B125 regression: a present-but-not-an-object manifest must
    /// fail closed. Without the `value.is_object()` check, a same-
    /// uid attacker who writes `42`, `"hello"`, `null`, or `[]` as
    /// the manifest contents would pass the `from_str::<Value>` parse
    /// and downstream `ensure_object(&mut manifest)` would silently
    /// replace with `{}`, re-introducing the exact wipe-out attack
    /// B115 was meant to close.
    #[test]
    fn test_read_plugins_manifest_top_level_number_fails_closed() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join(PLUGINS_MANIFEST_FILE), b"42").unwrap();
        let err =
            read_plugins_manifest(dir.path()).expect_err("non-object manifest must fail closed");
        assert_eq!(err.code, ERROR_UNAVAILABLE);
        assert!(
            err.message.contains("not a top-level JSON object"),
            "operator sees shape-error message: {}",
            err.message
        );
    }

    #[test]
    fn test_read_plugins_manifest_top_level_array_fails_closed() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join(PLUGINS_MANIFEST_FILE), b"[]").unwrap();
        let err = read_plugins_manifest(dir.path()).expect_err("top-level array must fail closed");
        assert_eq!(err.code, ERROR_UNAVAILABLE);
        assert!(err.message.contains("not a top-level JSON object"));
    }

    #[test]
    fn test_read_plugins_manifest_top_level_string_fails_closed() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join(PLUGINS_MANIFEST_FILE), b"\"hello\"").unwrap();
        let err = read_plugins_manifest(dir.path()).expect_err("top-level string must fail closed");
        assert_eq!(err.code, ERROR_UNAVAILABLE);
        assert!(err.message.contains("not a top-level JSON object"));
    }

    #[test]
    fn test_read_plugins_manifest_top_level_null_fails_closed() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join(PLUGINS_MANIFEST_FILE), b"null").unwrap();
        let err = read_plugins_manifest(dir.path()).expect_err("top-level null must fail closed");
        assert_eq!(err.code, ERROR_UNAVAILABLE);
        assert!(err.message.contains("not a top-level JSON object"));
    }

    // ---- download_plugin_wasm tests ----

    #[test]
    fn test_download_plugin_wasm_connection_refused() {
        // 127.0.0.1 is now blocked by SSRF protection before any network request is made
        let dir = TempDir::new().unwrap();
        let url = url::Url::parse("http://127.0.0.1:1/nonexistent.wasm").unwrap();
        let result = download_plugin_wasm(&url, dir.path(), "test.wasm");
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
    fn test_plugin_hash_computed_on_install() {
        // Simulate an install without a URL (no download) but manually write a plugin
        // component file and manifest entry with a hash, then verify the hash is present.
        let dir = TempDir::new().unwrap();
        let plugins_dir = dir.path().join("plugins");
        std::fs::create_dir_all(&plugins_dir).unwrap();

        let wasm_bytes = tool_plugin_component_bytes();

        // Compute expected hash
        let expected_hash = compute_sha256_hex(&wasm_bytes);
        assert!(!expected_hash.is_empty());
        assert_eq!(expected_hash.len(), 64); // SHA-256 produces 64 hex chars

        // Write the WASM file
        std::fs::write(plugins_dir.join("my-plugin.wasm"), &wasm_bytes).unwrap();

        // Write a manifest entry that includes the sha256 field (simulating post-install)
        let manifest = json!({
            "my-plugin": {
                "name": "my-plugin",
                "version": "1.0.0",
                "installed_at": 1700000000000u64,
                "sha256": expected_hash
            }
        });
        write_plugins_manifest(&plugins_dir, &manifest).unwrap();

        // Read back and verify hash is stored
        let read_back = read_plugins_manifest(&plugins_dir).unwrap();
        let stored_hash = read_back["my-plugin"]["sha256"].as_str().unwrap();
        assert_eq!(stored_hash, expected_hash);
        assert_eq!(stored_hash.len(), 64);
        // Verify it is lowercase hex
        assert!(stored_hash
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }

    // ---- DNS rebinding defense tests ----

    #[tokio::test(flavor = "multi_thread")]
    async fn test_download_plugin_dns_rebinding_defense_active() {
        // Verify that the DNS rebinding defense code path is active by testing
        // that both IP-literal and hostname-based URLs are handled correctly.
        // Requires a tokio multi_thread runtime because the hostname path uses
        // async DNS resolution via block_in_place. We use spawn_blocking to
        // isolate the reqwest::blocking::Client from the async test runtime.

        // IP literal: blocked at URL validation (no DNS resolution path).
        // This part does not need spawn_blocking since it fails before
        // creating any blocking HTTP client.
        let dir = TempDir::new().unwrap();
        let ip_url = url::Url::parse("http://10.0.0.1/plugin.wasm").unwrap();
        let result = download_plugin_wasm(&ip_url, dir.path(), "test.wasm");
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
            let hostname_url =
                url::Url::parse("https://example.com/plugins/my-plugin.wasm").unwrap();
            download_plugin_wasm(&hostname_url, &dir2_path, "test.wasm")
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
    async fn test_download_plugin_hostname_url_passes_ssrf_validation() {
        // Verify that a hostname-based URL with a legitimate public domain
        // passes through SSRF URL validation and reaches the DNS resolution
        // stage (where it may fail due to network, but that is expected).
        // Requires a tokio multi_thread runtime for the async DNS resolution path.
        // We use spawn_blocking to isolate the reqwest::blocking::Client.
        let dir = TempDir::new().unwrap();
        let dir_path = dir.path().to_path_buf();
        let result = tokio::task::spawn_blocking(move || {
            let url = url::Url::parse("https://cdn.example.org/plugins/translator.wasm").unwrap();
            download_plugin_wasm(&url, &dir_path, "translator.wasm")
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
