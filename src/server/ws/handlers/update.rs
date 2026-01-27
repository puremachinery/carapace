//! Update handlers.
//!
//! Manages application updates including checking for updates,
//! triggering update installation, and managing update channels.

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::LazyLock;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::super::*;

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

/// Trigger an update check and optionally install
pub(super) fn handle_update_run(params: Option<&Value>) -> Result<Value, ErrorShape> {
    let check_only = params
        .and_then(|v| v.get("checkOnly"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let force = params
        .and_then(|v| v.get("force"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

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

    state.last_check_at = Some(now_ms());
    state.last_error = None;

    // In a real implementation, this would:
    // 1. Check for updates from the update server
    // 2. Download and install if available and not check_only
    // For now, simulate no update available

    state.checking = false;
    state.update_available = false;

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
pub(super) fn handle_update_check() -> Result<Value, ErrorShape> {
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

    // Simulate update check
    // In production, this would make an HTTP request to the update server
    state.checking = false;
    state.update_available = false;
    state.latest_version = Some(state.current_version.clone());

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

/// Install an available update
pub(super) fn handle_update_install() -> Result<Value, ErrorShape> {
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

    state.installing = true;

    // In a real implementation, this would:
    // 1. Download the update if not already cached
    // 2. Verify the download integrity
    // 3. Install the update
    // 4. Restart the application

    Ok(json!({
        "ok": true,
        "installing": true,
        "version": state.latest_version,
        "message": "Update will be installed on restart"
    }))
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

    #[test]
    fn test_update_run() {
        let _lock = TEST_LOCK.lock().unwrap();
        reset_state();
        let result = handle_update_run(None).unwrap();
        assert_eq!(result["ok"], true);
        assert_eq!(result["updateAvailable"], false);
    }

    #[test]
    fn test_update_run_check_only() {
        let _lock = TEST_LOCK.lock().unwrap();
        reset_state();
        let params = json!({ "checkOnly": true });
        let result = handle_update_run(Some(&params)).unwrap();
        assert_eq!(result["checkOnly"], true);
    }

    #[test]
    fn test_update_check() {
        let _lock = TEST_LOCK.lock().unwrap();
        reset_state();
        let result = handle_update_check().unwrap();
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

    #[test]
    fn test_update_install_no_update() {
        let _lock = TEST_LOCK.lock().unwrap();
        reset_state();
        let result = handle_update_install();
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code, ERROR_INVALID_REQUEST);
    }

    #[test]
    fn test_update_dismiss() {
        let _lock = TEST_LOCK.lock().unwrap();
        reset_state();
        let result = handle_update_dismiss().unwrap();
        assert_eq!(result["ok"], true);
    }
}
