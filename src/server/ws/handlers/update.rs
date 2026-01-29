//! Update handlers.
//!
//! Manages application updates including checking for updates,
//! triggering update installation, and managing update channels.

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
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
            state.download_url = Some(release.html_url);
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

/// Trigger an update check and optionally install
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

    // When check_only is false and an update is available, the state is
    // already populated. Actual download/install is a future task.

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

/// Download the release binary from GitHub and stage it in the state directory.
///
/// The function:
/// 1. Re-fetches the latest release to obtain the asset list.
/// 2. Locates the asset matching the current platform.
/// 3. Streams the binary to `{state_dir}/updates/carapace-{version}`.
/// 4. Verifies the download size is non-zero.
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

    // Verify download integrity (minimum: non-empty) ----------------------
    if bytes.is_empty() {
        return Err("downloaded asset is empty".to_string());
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
        Ok(staged_path) => Ok(json!({
            "ok": true,
            "version": version,
            "stagedPath": staged_path,
            "message": "Update staged successfully. Restart to apply."
        })),
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
}
