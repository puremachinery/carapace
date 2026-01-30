//! Update handlers.
//!
//! Manages application updates including checking for updates,
//! triggering update installation, and managing update channels.

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::io::Read;
use std::sync::LazyLock;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::AsyncWriteExt;
use tracing::warn;

use super::super::*;

/// GitHub API response for a release asset
#[derive(Debug, Deserialize)]
struct GitHubAsset {
    name: String,
    browser_download_url: String,
    size: u64,
}

/// GitHub API response for the latest release
#[derive(Debug, Deserialize)]
struct GitHubRelease {
    tag_name: String,
    html_url: String,
    body: Option<String>,
    #[serde(default)]
    assets: Vec<GitHubAsset>,
}

/// Available update channels
pub const UPDATE_CHANNELS: [&str; 3] = ["stable", "beta", "dev"];

/// Global update state
static UPDATE_STATE: LazyLock<RwLock<UpdateState>> =
    LazyLock::new(|| RwLock::new(UpdateState::default()));

/// Update configuration and status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateState {
    /// Current version
    pub current_version: String,
    /// Latest available version (if known)
    pub latest_version: Option<String>,
    /// Whether an update is available
    pub update_available: bool,
    /// Update channel (stable, beta, dev)
    pub channel: String,
    /// Whether auto-update is enabled
    pub auto_update: bool,
    /// Whether an update check is in progress
    pub checking: bool,
    /// Whether an update is being installed
    pub installing: bool,
    /// Last check timestamp (ms)
    pub last_check_at: Option<u64>,
    /// Last error message
    pub last_error: Option<String>,
    /// Release notes for available update
    pub release_notes: Option<String>,
    /// Download URL for available update
    pub download_url: Option<String>,
}

impl Default for UpdateState {
    fn default() -> Self {
        Self {
            current_version: env!("CARGO_PKG_VERSION").to_string(),
            latest_version: None,
            update_available: false,
            channel: "stable".to_string(),
            auto_update: true,
            checking: false,
            installing: false,
            last_check_at: None,
            last_error: None,
            release_notes: None,
            download_url: None,
        }
    }
}

/// Result of applying a staged update binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplyResult {
    /// Whether the update was successfully applied
    pub applied: bool,
    /// SHA-256 hash of the new binary
    pub sha256: String,
    /// Path to the binary that was replaced
    pub binary_path: String,
}

/// Compute SHA-256 hex digest of a file at the given path.
fn compute_sha256(path: &str) -> Result<String, String> {
    let mut file =
        std::fs::File::open(path).map_err(|e| format!("failed to open file for hashing: {e}"))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];
    loop {
        let n = file
            .read(&mut buffer)
            .map_err(|e| format!("failed to read file for hashing: {e}"))?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

/// Apply a staged binary update atomically.
pub fn apply_staged_update(staged_path: &str) -> Result<ApplyResult, String> {
    let staged_meta = std::fs::metadata(staged_path)
        .map_err(|e| format!("staged binary not found at '{}': {e}", staged_path))?;
    if staged_meta.len() == 0 {
        return Err(format!("staged binary at '{}' is empty", staged_path));
    }

    let sha256 = compute_sha256(staged_path)?;

    let current_exe = std::env::current_exe()
        .map_err(|e| format!("failed to determine current binary path: {e}"))?;
    let current_path = current_exe
        .canonicalize()
        .map_err(|e| format!("failed to canonicalize current binary path: {e}"))?;
    let binary_path = current_path.to_string_lossy().into_owned();

    let backup_path = format!("{}.bak", current_path.display());

    std::fs::rename(&current_path, &backup_path)
        .map_err(|e| format!("failed to rename current binary to .bak: {e}"))?;

    if let Err(copy_err) = std::fs::copy(staged_path, &current_path) {
        if let Err(restore_err) = std::fs::rename(&backup_path, &current_path) {
            return Err(format!(
                "CRITICAL: copy failed ({copy_err}) AND restore failed ({restore_err}). Backup at: {backup_path}"
            ));
        }
        return Err(format!(
            "failed to copy staged binary to current path: {copy_err}"
        ));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o755);
        if let Err(e) = std::fs::set_permissions(&current_path, perms) {
            warn!("failed to set executable permissions on updated binary: {e}");
        }
    }

    if let Err(e) = std::fs::remove_file(&backup_path) {
        warn!("failed to remove backup file {}: {e}", backup_path);
    }

    Ok(ApplyResult {
        applied: true,
        sha256,
        binary_path,
    })
}

/// Remove stale backup and old update files.
pub fn cleanup_old_binaries() {
    cleanup_bak_files_near_exe();
    cleanup_stale_staged_updates();
}

/// Remove `.bak` and `.old` files next to the current executable.
fn cleanup_bak_files_near_exe() {
    let exe = match std::env::current_exe() {
        Ok(e) => e,
        Err(_) => return,
    };
    let parent = match exe.parent() {
        Some(p) => p,
        None => return,
    };
    let entries = match std::fs::read_dir(parent) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let dominated = path
            .extension()
            .is_some_and(|ext| ext == "bak" || ext == "old");
        if dominated {
            if let Err(e) = std::fs::remove_file(&path) {
                warn!("failed to remove old binary {}: {e}", path.display());
            }
        }
    }
}

/// Remove staged update files older than 7 days.
fn cleanup_stale_staged_updates() {
    let updates_dir = resolve_state_dir().join("updates");
    let entries = match std::fs::read_dir(&updates_dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    let seven_days = Duration::from_secs(7 * 24 * 60 * 60);
    for entry in entries.flatten() {
        let path = entry.path();
        let stale = path
            .metadata()
            .ok()
            .and_then(|meta| meta.modified().ok())
            .and_then(|m| m.elapsed().ok())
            .is_some_and(|age| age > seven_days);
        if stale {
            if let Err(e) = std::fs::remove_file(&path) {
                warn!("failed to remove stale staged file {}: {e}", path.display());
            }
        }
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_millis() as u64
}

/// Fetch the latest release from GitHub and update global state.
///
/// On success, populates `latest_version`, `update_available`, `download_url`,
/// and `release_notes`. On failure, sets `last_error` and leaves
/// `update_available` as `false`. Always clears the `checking` flag before
/// returning.
async fn fetch_latest_release() {
    let current_version = {
        let state = UPDATE_STATE.read();
        state.current_version.clone()
    };

    let user_agent = format!("carapace/{}", current_version);

    let result: Result<GitHubRelease, String> = async {
        let client = reqwest::Client::new();
        let resp = client
            .get("https://api.github.com/repos/puremachinery/carapace/releases/latest")
            .header("User-Agent", &user_agent)
            .header("Accept", "application/vnd.github+json")
            .timeout(Duration::from_secs(15))
            .send()
            .await
            .map_err(|e| format!("HTTP request failed: {e}"))?;

        if !resp.status().is_success() {
            return Err(format!("GitHub API returned status {}", resp.status()));
        }

        resp.json::<GitHubRelease>()
            .await
            .map_err(|e| format!("failed to parse release JSON: {e}"))
    }
    .await;

    let mut state = UPDATE_STATE.write();
    match result {
        Ok(release) => {
            let latest = release
                .tag_name
                .strip_prefix('v')
                .unwrap_or(&release.tag_name)
                .to_string();

            state.update_available = latest != current_version;
            state.latest_version = Some(latest);

            // Prefer the platform-specific asset download URL; fall back to
            // the release page URL so the user can still reach the release.
            let wanted = expected_asset_name();
            let asset_url = release
                .assets
                .iter()
                .find(|a| a.name == wanted)
                .map(|a| a.browser_download_url.clone());
            state.download_url = Some(asset_url.unwrap_or(release.html_url));

            state.release_notes = release.body;
            state.last_error = None;
        }
        Err(err) => {
            warn!("update check failed: {err}");
            state.last_error = Some(err);
            state.update_available = false;
        }
    }
    state.checking = false;
}

/// Trigger an update check and optionally install.
///
/// When `checkOnly` is false (the default) and an update is available, the
/// handler proceeds to download and install the update, returning the same
/// response shape as `update.install`.  When `checkOnly` is true the handler
/// only performs the version check.
pub(super) async fn handle_update_run(params: Option<&Value>) -> Result<Value, ErrorShape> {
    let check_only = params
        .and_then(|v| v.get("checkOnly"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let force = params
        .and_then(|v| v.get("force"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    // Acquire lock briefly to validate and set flags
    {
        let mut state = UPDATE_STATE.write();

        // Prevent concurrent update operations
        if state.checking || state.installing {
            return Err(error_shape(
                ERROR_UNAVAILABLE,
                "update operation already in progress",
                Some(json!({
                    "checking": state.checking,
                    "installing": state.installing
                })),
            ));
        }

        state.checking = true;
        state.last_check_at = Some(now_ms());
        state.last_error = None;
    }

    // Perform the real HTTP check (lock is not held during the await)
    fetch_latest_release().await;

    // Determine whether we should install
    let should_install = {
        let state = UPDATE_STATE.read();
        !check_only && (state.update_available || force)
    };

    if should_install {
        // Delegate to the install handler which handles download, staging,
        // and atomic replacement.
        return handle_update_install().await;
    }

    let state = UPDATE_STATE.read();
    Ok(json!({
        "ok": true,
        "currentVersion": state.current_version,
        "latestVersion": state.latest_version,
        "updateAvailable": state.update_available,
        "checkOnly": check_only,
        "force": force,
        "channel": state.channel
    }))
}

/// Get update status
pub(super) fn handle_update_status() -> Result<Value, ErrorShape> {
    let state = UPDATE_STATE.read();

    Ok(json!({
        "currentVersion": state.current_version,
        "latestVersion": state.latest_version,
        "updateAvailable": state.update_available,
        "channel": state.channel,
        "autoUpdate": state.auto_update,
        "checking": state.checking,
        "installing": state.installing,
        "lastCheckAt": state.last_check_at,
        "lastError": state.last_error,
        "releaseNotes": state.release_notes,
        "downloadUrl": state.download_url
    }))
}

/// Check for updates without installing
pub(super) async fn handle_update_check() -> Result<Value, ErrorShape> {
    // Acquire lock briefly to validate and set checking flag
    {
        let mut state = UPDATE_STATE.write();

        if state.checking {
            return Err(error_shape(
                ERROR_UNAVAILABLE,
                "update check already in progress",
                None,
            ));
        }

        state.checking = true;
        state.last_check_at = Some(now_ms());
        state.last_error = None;
    }

    // Perform the actual HTTP check (lock is not held during the await)
    fetch_latest_release().await;

    // Read final state and build response
    let state = UPDATE_STATE.read();
    Ok(json!({
        "ok": true,
        "currentVersion": state.current_version,
        "latestVersion": state.latest_version,
        "updateAvailable": state.update_available,
        "channel": state.channel
    }))
}

/// Set update channel
pub(super) fn handle_update_set_channel(params: Option<&Value>) -> Result<Value, ErrorShape> {
    let channel = params
        .and_then(|v| v.get("channel"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "channel is required", None))?;

    if !UPDATE_CHANNELS.contains(&channel) {
        return Err(error_shape(
            ERROR_INVALID_REQUEST,
            &format!("unknown update channel: {}", channel),
            Some(json!({ "validChannels": UPDATE_CHANNELS })),
        ));
    }

    let mut state = UPDATE_STATE.write();
    let previous = state.channel.clone();
    state.channel = channel.to_string();

    // Clear cached update info when changing channels
    if previous != channel {
        state.latest_version = None;
        state.update_available = false;
        state.release_notes = None;
        state.download_url = None;
    }

    Ok(json!({
        "ok": true,
        "channel": channel,
        "previousChannel": previous
    }))
}

/// Configure auto-update settings
pub(super) fn handle_update_configure(params: Option<&Value>) -> Result<Value, ErrorShape> {
    let mut state = UPDATE_STATE.write();

    if let Some(auto) = params
        .and_then(|v| v.get("autoUpdate"))
        .and_then(|v| v.as_bool())
    {
        state.auto_update = auto;
    }

    if let Some(channel) = params
        .and_then(|v| v.get("channel"))
        .and_then(|v| v.as_str())
    {
        if UPDATE_CHANNELS.contains(&channel) {
            state.channel = channel.to_string();
        }
    }

    Ok(json!({
        "ok": true,
        "autoUpdate": state.auto_update,
        "channel": state.channel
    }))
}

/// Build the expected release asset name for the current platform.
///
/// GitHub release assets follow the pattern `carapace-{os}-{arch}` (with `.exe`
/// on Windows). We map Rust's `std::env::consts` values to the names used in
/// the release workflow.
fn expected_asset_name() -> String {
    let os = match std::env::consts::OS {
        "macos" => "darwin",
        other => other,
    };
    let arch = std::env::consts::ARCH;
    let ext = if std::env::consts::OS == "windows" {
        ".exe"
    } else {
        ""
    };
    format!("carapace-{os}-{arch}{ext}")
}

/// Compute the SHA-256 hex digest of an in-memory byte buffer.
fn sha256_bytes(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

/// Verify the downloaded binary against a SHA-256 checksum file.
///
/// The `checksum_text` is expected to be in the GNU coreutils format:
///   `<hex_hash>  <filename>` (or just a bare hex hash).
///
/// Returns `Ok(())` when the hashes match, or an `Err` describing the
/// mismatch.
fn verify_checksum(actual_hash: &str, checksum_text: &str) -> Result<(), String> {
    // The checksum file may contain: "<hash>  <filename>\n" or just "<hash>\n".
    let expected = checksum_text
        .split_whitespace()
        .next()
        .unwrap_or("")
        .trim()
        .to_lowercase();

    if expected.is_empty() {
        return Err("checksum file is empty or malformed".to_string());
    }

    if expected.len() != 64 || !expected.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(format!(
            "checksum file does not contain a valid SHA-256 hash: '{expected}'"
        ));
    }

    if actual_hash != expected {
        return Err(format!(
            "SHA-256 mismatch: expected {expected}, got {actual_hash}"
        ));
    }

    Ok(())
}

/// Download the release binary from GitHub and stage it in the state directory.
///
/// The function:
/// 1. Re-fetches the latest release to obtain the asset list.
/// 2. Locates the asset matching the current platform.
/// 3. Downloads the binary to `{state_dir}/updates/carapace-{version}`.
/// 4. If a `.sha256` checksum asset exists, downloads it and verifies integrity.
/// 5. On Unix, sets executable permissions.
///
/// On success the staging path is returned. On failure, `last_error` is set and
/// the `installing` flag is cleared.
async fn download_and_stage(version: &str) -> Result<String, String> {
    let current_version = {
        let state = UPDATE_STATE.read();
        state.current_version.clone()
    };
    let user_agent = format!("carapace/{}", current_version);

    // Fetch release metadata (with asset list) ----------------------------
    let client = reqwest::Client::new();
    let release: GitHubRelease = client
        .get("https://api.github.com/repos/puremachinery/carapace/releases/latest")
        .header("User-Agent", &user_agent)
        .header("Accept", "application/vnd.github+json")
        .timeout(Duration::from_secs(15))
        .send()
        .await
        .map_err(|e| format!("failed to fetch release metadata: {e}"))?
        .json()
        .await
        .map_err(|e| format!("failed to parse release metadata: {e}"))?;

    // Find the matching asset for this platform ---------------------------
    let wanted = expected_asset_name();
    let asset = release
        .assets
        .iter()
        .find(|a| a.name == wanted)
        .ok_or_else(|| {
            format!(
                "no matching asset '{}' in release {} (available: {})",
                wanted,
                release.tag_name,
                release
                    .assets
                    .iter()
                    .map(|a| a.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        })?;

    // Check for a companion checksum asset (e.g. carapace-darwin-aarch64.sha256)
    let checksum_name = format!("{wanted}.sha256");
    let checksum_asset = release.assets.iter().find(|a| a.name == checksum_name);

    // Prepare staging directory -------------------------------------------
    let updates_dir = resolve_state_dir().join("updates");
    tokio::fs::create_dir_all(&updates_dir)
        .await
        .map_err(|e| format!("failed to create updates directory: {e}"))?;

    let staged_name = format!("carapace-{version}");
    let staged_path = updates_dir.join(&staged_name);

    // Download the binary -------------------------------------------------
    let resp = client
        .get(&asset.browser_download_url)
        .header("User-Agent", &user_agent)
        .timeout(Duration::from_secs(300))
        .send()
        .await
        .map_err(|e| format!("failed to download asset: {e}"))?;

    if !resp.status().is_success() {
        return Err(format!("asset download returned status {}", resp.status()));
    }

    let bytes = resp
        .bytes()
        .await
        .map_err(|e| format!("failed to read asset bytes: {e}"))?;

    // Verify download integrity -------------------------------------------
    if bytes.is_empty() {
        return Err("downloaded asset is empty".to_string());
    }

    // If a checksum asset is available, download and verify
    if let Some(cksum) = checksum_asset {
        let cksum_resp = client
            .get(&cksum.browser_download_url)
            .header("User-Agent", &user_agent)
            .timeout(Duration::from_secs(30))
            .send()
            .await
            .map_err(|e| format!("failed to download checksum file: {e}"))?;

        if cksum_resp.status().is_success() {
            let cksum_text = cksum_resp
                .text()
                .await
                .map_err(|e| format!("failed to read checksum file: {e}"))?;

            let actual_hash = sha256_bytes(&bytes);
            verify_checksum(&actual_hash, &cksum_text)?;
        } else {
            warn!(
                "checksum asset download returned status {}; skipping verification",
                cksum_resp.status()
            );
        }
    }

    // Write to staging path -----------------------------------------------
    let mut file = tokio::fs::File::create(&staged_path)
        .await
        .map_err(|e| format!("failed to create staged file: {e}"))?;

    file.write_all(&bytes)
        .await
        .map_err(|e| format!("failed to write staged file: {e}"))?;

    file.flush()
        .await
        .map_err(|e| format!("failed to flush staged file: {e}"))?;

    // On Unix, make the staged binary executable --------------------------
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o755);
        std::fs::set_permissions(&staged_path, perms)
            .map_err(|e| format!("failed to set executable permissions: {e}"))?;
    }

    Ok(staged_path.to_string_lossy().into_owned())
}

/// Install an available update
pub(super) async fn handle_update_install() -> Result<Value, ErrorShape> {
    // Validate and set the installing flag --------------------------------
    let version = {
        let mut state = UPDATE_STATE.write();

        if !state.update_available {
            return Err(error_shape(
                ERROR_INVALID_REQUEST,
                "no update available",
                None,
            ));
        }

        if state.installing {
            return Err(error_shape(
                ERROR_UNAVAILABLE,
                "update installation already in progress",
                None,
            ));
        }

        let version = match &state.latest_version {
            Some(v) => v.clone(),
            None => {
                return Err(error_shape(
                    ERROR_INVALID_REQUEST,
                    "latest version not known; run update.check first",
                    None,
                ));
            }
        };

        state.installing = true;
        state.last_error = None;
        version
    };

    // Perform the download (lock is NOT held during the await) ------------
    let result = download_and_stage(&version).await;

    // Update state based on outcome ---------------------------------------
    let mut state = UPDATE_STATE.write();
    state.installing = false;

    match result {
        Ok(staged_path) => {
            // Apply the staged binary atomically
            match apply_staged_update(&staged_path) {
                Ok(apply_result) => {
                    // Mark update as consumed so callers don't re-install.
                    state.update_available = false;

                    // Clean up old binaries in the background
                    cleanup_old_binaries();
                    Ok(json!({
                        "ok": true,
                        "status": "success",
                        "version": version,
                        "stagedPath": staged_path,
                        "applied": apply_result.applied,
                        "sha256": apply_result.sha256,
                        "binaryPath": apply_result.binary_path,
                        "restartRequired": true,
                        "message": "Update applied successfully. Restart to use new version."
                    }))
                }
                Err(apply_err) => {
                    warn!("update apply failed: {apply_err}");
                    state.last_error = Some(apply_err.clone());
                    Err(error_shape(
                        ERROR_UNAVAILABLE,
                        &format!("update apply failed: {apply_err}"),
                        Some(json!({
                            "version": version,
                            "stagedPath": staged_path
                        })),
                    ))
                }
            }
        }
        Err(err) => {
            warn!("update install failed: {err}");
            state.last_error = Some(err.clone());
            Err(error_shape(
                ERROR_UNAVAILABLE,
                &format!("update install failed: {err}"),
                Some(json!({ "version": version })),
            ))
        }
    }
}

/// Dismiss an available update notification
pub(super) fn handle_update_dismiss() -> Result<Value, ErrorShape> {
    let state = UPDATE_STATE.read();

    // Don't actually hide the update, just acknowledge dismissal
    // This is useful for UI to track user preferences

    Ok(json!({
        "ok": true,
        "dismissed": state.update_available,
        "version": state.latest_version
    }))
}

/// Get release notes for available update
pub(super) fn handle_update_release_notes() -> Result<Value, ErrorShape> {
    let state = UPDATE_STATE.read();

    Ok(json!({
        "currentVersion": state.current_version,
        "latestVersion": state.latest_version,
        "releaseNotes": state.release_notes,
        "updateAvailable": state.update_available
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Mutex to serialize tests that modify global state
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    fn reset_state() {
        let mut state = UPDATE_STATE.write();
        *state = UpdateState::default();
    }

    #[test]
    fn test_update_status() {
        let _lock = TEST_LOCK.lock().unwrap();
        reset_state();
        let result = handle_update_status().unwrap();
        assert!(!result["currentVersion"].as_str().unwrap().is_empty());
        assert_eq!(result["channel"], "stable");
        assert_eq!(result["autoUpdate"], true);
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn test_update_run() {
        let _lock = TEST_LOCK.lock().unwrap();
        reset_state();
        // In test environments the HTTP request will fail, but the handler
        // must still succeed (returning updateAvailable: false with a last_error).
        let result = handle_update_run(None).await.unwrap();
        assert_eq!(result["ok"], true);
        assert_eq!(result["updateAvailable"], false);
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn test_update_run_check_only() {
        let _lock = TEST_LOCK.lock().unwrap();
        reset_state();
        let params = json!({ "checkOnly": true });
        let result = handle_update_run(Some(&params)).await.unwrap();
        assert_eq!(result["checkOnly"], true);
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn test_update_check() {
        let _lock = TEST_LOCK.lock().unwrap();
        reset_state();
        // HTTP will fail in tests, but handler returns Ok with an error recorded in state
        let result = handle_update_check().await.unwrap();
        assert_eq!(result["ok"], true);
    }

    #[test]
    fn test_update_set_channel() {
        let _lock = TEST_LOCK.lock().unwrap();
        reset_state();

        let params = json!({ "channel": "beta" });
        let result = handle_update_set_channel(Some(&params)).unwrap();
        assert_eq!(result["channel"], "beta");
        assert_eq!(result["previousChannel"], "stable");
    }

    #[test]
    fn test_update_set_invalid_channel() {
        let _lock = TEST_LOCK.lock().unwrap();
        reset_state();

        let params = json!({ "channel": "invalid" });
        let result = handle_update_set_channel(Some(&params));
        assert!(result.is_err());
    }

    #[test]
    fn test_update_configure() {
        let _lock = TEST_LOCK.lock().unwrap();
        reset_state();

        let params = json!({
            "autoUpdate": false,
            "channel": "beta"
        });
        let result = handle_update_configure(Some(&params)).unwrap();
        assert_eq!(result["autoUpdate"], false);
        assert_eq!(result["channel"], "beta");
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn test_update_install_no_update() {
        let _lock = TEST_LOCK.lock().unwrap();
        reset_state();
        let result = handle_update_install().await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code, ERROR_INVALID_REQUEST);
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn test_update_install_already_installing() {
        let _lock = TEST_LOCK.lock().unwrap();
        reset_state();
        {
            let mut state = UPDATE_STATE.write();
            state.update_available = true;
            state.latest_version = Some("99.0.0".to_string());
            state.installing = true;
        }
        let result = handle_update_install().await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code, ERROR_UNAVAILABLE);
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn test_update_install_no_version() {
        let _lock = TEST_LOCK.lock().unwrap();
        reset_state();
        {
            let mut state = UPDATE_STATE.write();
            state.update_available = true;
            // latest_version left as None
        }
        let result = handle_update_install().await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code, ERROR_INVALID_REQUEST);
        // installing flag must be cleared even on validation failure path
        let state = UPDATE_STATE.read();
        assert!(!state.installing);
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn test_update_install_download_failure_clears_flag() {
        let _lock = TEST_LOCK.lock().unwrap();
        reset_state();
        {
            let mut state = UPDATE_STATE.write();
            state.update_available = true;
            state.latest_version = Some("99.0.0".to_string());
            state.download_url =
                Some("https://github.com/puremachinery/carapace/releases/tag/v99.0.0".to_string());
        }
        // The download will fail in test environments (no such release).
        let result = handle_update_install().await;
        assert!(result.is_err());
        // Verify installing flag is cleared after failure
        let state = UPDATE_STATE.read();
        assert!(!state.installing);
        // last_error should be populated
        assert!(state.last_error.is_some());
    }

    #[test]
    fn test_expected_asset_name() {
        let name = expected_asset_name();
        // Must start with "carapace-"
        assert!(
            name.starts_with("carapace-"),
            "unexpected asset name: {name}"
        );
        // Must contain a platform identifier
        let os = std::env::consts::OS;
        let expected_os = match os {
            "macos" => "darwin",
            other => other,
        };
        assert!(
            name.contains(expected_os),
            "asset name '{name}' does not contain expected OS '{expected_os}'"
        );
    }

    #[test]
    fn test_update_dismiss() {
        let _lock = TEST_LOCK.lock().unwrap();
        reset_state();
        let result = handle_update_dismiss().unwrap();
        assert_eq!(result["ok"], true);
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn test_update_check_records_error_on_http_failure() {
        let _lock = TEST_LOCK.lock().unwrap();
        reset_state();
        // This will attempt to reach GitHub and fail in test environments
        let result = handle_update_check().await.unwrap();
        assert_eq!(result["ok"], true);
        // After a failed HTTP call, checking flag must be cleared
        let state = UPDATE_STATE.read();
        assert!(!state.checking);
        // last_error should be populated since HTTP failed
        assert!(state.last_error.is_some());
        assert!(!state.update_available);
    }

    // -----------------------------------------------------------------------
    // apply_staged_update tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_apply_staged_update_nonexistent_path() {
        let result = apply_staged_update("/nonexistent/path/to/binary");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.contains("staged binary not found"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_apply_staged_update_empty_file() {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let empty_file = dir.path().join("empty-binary");
        std::fs::write(&empty_file, b"").expect("failed to write empty file");
        let result = apply_staged_update(empty_file.to_str().unwrap());
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("is empty"), "unexpected error: {err}");
    }

    // -----------------------------------------------------------------------
    // SHA-256 computation tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_compute_sha256_known_value() {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let file_path = dir.path().join("test-hash");
        // SHA-256 of b"hello world\n"
        std::fs::write(&file_path, b"hello world\n").expect("failed to write file");
        let hash = compute_sha256(file_path.to_str().unwrap()).unwrap();
        assert_eq!(
            hash, "a948904f2f0f479b8f8197694b30184b0d2ed1c1cd2a1ec0fb85d299a192a447",
            "SHA-256 mismatch for known input"
        );
    }

    #[test]
    fn test_compute_sha256_empty_file() {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let file_path = dir.path().join("empty");
        std::fs::write(&file_path, b"").expect("failed to write file");
        let hash = compute_sha256(file_path.to_str().unwrap()).unwrap();
        assert_eq!(
            hash,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn test_compute_sha256_nonexistent_file() {
        let result = compute_sha256("/nonexistent/file/path");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("failed to open file"));
    }

    #[test]
    fn test_compute_sha256_deterministic() {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let file_path = dir.path().join("deterministic");
        std::fs::write(&file_path, b"deterministic content").expect("failed to write");
        let path_str = file_path.to_str().unwrap();
        let hash1 = compute_sha256(path_str).unwrap();
        let hash2 = compute_sha256(path_str).unwrap();
        assert_eq!(hash1, hash2, "SHA-256 should be deterministic");
    }

    // -----------------------------------------------------------------------
    // cleanup_old_binaries tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_cleanup_old_binaries_removes_bak_files() {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let bak_file = dir.path().join("carapace.bak");
        let old_file = dir.path().join("carapace.old");
        std::fs::write(&bak_file, b"backup").expect("write bak");
        std::fs::write(&old_file, b"old").expect("write old");
        cleanup_old_binaries();
    }

    #[test]
    fn test_cleanup_old_binaries_preserves_non_backup_files() {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let normal_file = dir.path().join("important.txt");
        std::fs::write(&normal_file, b"keep me").expect("write");
        cleanup_old_binaries();
        assert!(
            normal_file.exists(),
            "cleanup_old_binaries should not remove non-backup files"
        );
    }

    #[test]
    fn test_cleanup_old_binaries_no_panic_on_missing_dirs() {
        cleanup_old_binaries();
    }

    // -----------------------------------------------------------------------
    // expected_asset_name tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_expected_asset_name_format() {
        let name = expected_asset_name();
        let parts: Vec<&str> = name.split('-').collect();
        assert!(
            parts.len() >= 3,
            "asset name should have at least 3 dash-separated parts: {name}"
        );
        assert_eq!(parts[0], "carapace");
    }

    #[test]
    fn test_expected_asset_name_no_exe_on_unix() {
        let name = expected_asset_name();
        if cfg!(unix) {
            assert!(
                !name.ends_with(".exe"),
                "Unix asset name should not end with .exe: {name}"
            );
        }
    }

    // -----------------------------------------------------------------------
    // Staged path construction tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_staged_path_construction() {
        let updates_dir = resolve_state_dir().join("updates");
        let version = "1.2.3";
        let staged_name = format!("carapace-{version}");
        let staged_path = updates_dir.join(&staged_name);
        let path_str = staged_path.to_string_lossy();
        assert!(
            path_str.contains("updates") && path_str.contains("carapace-1.2.3"),
            "staged path should contain updates/carapace-VERSION: {}",
            staged_path.display()
        );
    }

    #[test]
    fn test_staged_path_different_versions() {
        let updates_dir = resolve_state_dir().join("updates");
        let path_a = updates_dir.join("carapace-1.0.0");
        let path_b = updates_dir.join("carapace-2.0.0");
        assert_ne!(
            path_a, path_b,
            "different versions should have different paths"
        );
    }

    // -----------------------------------------------------------------------
    // State transition tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_install_sets_installing_flag() {
        let _lock = TEST_LOCK.lock().unwrap();
        reset_state();
        {
            let mut state = UPDATE_STATE.write();
            state.update_available = true;
            state.latest_version = Some("99.0.0".to_string());
            state.installing = false;
        }
        let state = UPDATE_STATE.read();
        assert!(!state.installing);
        assert!(state.update_available);
    }

    #[test]
    fn test_state_default_values() {
        let state = UpdateState::default();
        assert!(!state.update_available);
        assert!(!state.checking);
        assert!(!state.installing);
        assert_eq!(state.channel, "stable");
        assert!(state.auto_update);
        assert!(state.latest_version.is_none());
        assert!(state.last_error.is_none());
        assert!(state.download_url.is_none());
        assert!(state.release_notes.is_none());
        assert!(state.last_check_at.is_none());
    }

    // -----------------------------------------------------------------------
    // ApplyResult struct tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_apply_result_fields() {
        let result = ApplyResult {
            applied: true,
            sha256: "abc123".to_string(),
            binary_path: "/usr/bin/carapace".to_string(),
        };
        assert!(result.applied);
        assert_eq!(result.sha256, "abc123");
        assert_eq!(result.binary_path, "/usr/bin/carapace");
    }

    #[test]
    fn test_apply_result_serialize() {
        let result = ApplyResult {
            applied: true,
            sha256: "deadbeef".to_string(),
            binary_path: "/tmp/test".to_string(),
        };
        let json = serde_json::to_value(&result).expect("serialize ApplyResult");
        assert_eq!(json["applied"], true);
        assert_eq!(json["sha256"], "deadbeef");
        assert_eq!(json["binary_path"], "/tmp/test");
    }

    #[test]
    fn test_apply_result_deserialize() {
        let json_str = r##"{"applied":false,"sha256":"abc","binary_path":"/bin/ttt"}"##;
        let result: ApplyResult = serde_json::from_str(json_str).expect("deserialize ApplyResult");
        assert!(!result.applied);
        assert_eq!(result.sha256, "abc");
        assert_eq!(result.binary_path, "/bin/ttt");
    }

    // -----------------------------------------------------------------------
    // sha256_bytes tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_sha256_bytes_known_value() {
        let hash = sha256_bytes(b"hello world\n");
        assert_eq!(
            hash, "a948904f2f0f479b8f8197694b30184b0d2ed1c1cd2a1ec0fb85d299a192a447",
            "SHA-256 of 'hello world\\n' mismatch"
        );
    }

    #[test]
    fn test_sha256_bytes_empty() {
        let hash = sha256_bytes(b"");
        assert_eq!(
            hash,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn test_sha256_bytes_deterministic() {
        let h1 = sha256_bytes(b"test data");
        let h2 = sha256_bytes(b"test data");
        assert_eq!(h1, h2);
    }

    // -----------------------------------------------------------------------
    // verify_checksum tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_verify_checksum_match_bare_hash() {
        let data = b"hello";
        let hash = sha256_bytes(data);
        // checksum file contains just the hash
        let result = verify_checksum(&hash, &hash);
        assert!(result.is_ok(), "bare hash should match: {:?}", result);
    }

    #[test]
    fn test_verify_checksum_match_gnu_format() {
        let data = b"hello";
        let hash = sha256_bytes(data);
        // GNU coreutils format: "<hash>  <filename>"
        let checksum_text = format!("{}  carapace-darwin-aarch64", hash);
        let result = verify_checksum(&hash, &checksum_text);
        assert!(result.is_ok(), "GNU format should match: {:?}", result);
    }

    #[test]
    fn test_verify_checksum_mismatch() {
        let result = verify_checksum(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb  file.bin",
        );
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.contains("mismatch"),
            "error should mention mismatch: {err}"
        );
    }

    #[test]
    fn test_verify_checksum_empty_file() {
        let result = verify_checksum(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "",
        );
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("empty"), "error should mention empty: {err}");
    }

    #[test]
    fn test_verify_checksum_malformed() {
        let result = verify_checksum(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "not-a-valid-sha256",
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_checksum_with_trailing_whitespace() {
        let hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let checksum_text = format!("{}  empty.bin\n", hash);
        let result = verify_checksum(hash, &checksum_text);
        assert!(
            result.is_ok(),
            "trailing whitespace should not cause failure: {:?}",
            result
        );
    }

    #[test]
    fn test_verify_checksum_case_insensitive() {
        let hash_lower = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let hash_upper = "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855";
        let result = verify_checksum(hash_lower, hash_upper);
        assert!(
            result.is_ok(),
            "checksum verification should be case-insensitive: {:?}",
            result
        );
    }

    // -----------------------------------------------------------------------
    // Platform detection tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_expected_asset_name_contains_arch() {
        let name = expected_asset_name();
        let arch = std::env::consts::ARCH;
        assert!(
            name.contains(arch),
            "asset name '{name}' does not contain arch '{arch}'"
        );
    }

    #[test]
    fn test_expected_asset_name_checksum_companion() {
        let name = expected_asset_name();
        let checksum_name = format!("{name}.sha256");
        assert!(
            checksum_name.ends_with(".sha256"),
            "checksum name should end with .sha256: {checksum_name}"
        );
        assert!(
            checksum_name.starts_with("carapace-"),
            "checksum name should start with carapace-: {checksum_name}"
        );
    }
}
