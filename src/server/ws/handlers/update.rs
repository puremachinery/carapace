//! Update handlers.
//!
//! Manages update checks and delegates installation to the shared updater
//! pipeline in `crate::update`.

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::LazyLock;

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

/// Fetch the latest release from GitHub and update global state.
async fn fetch_latest_release() {
    let current_version = {
        let state = UPDATE_STATE.read();
        state.current_version.clone()
    };

    let result = crate::update::fetch_release_info(&current_version, None).await;

    let mut state = UPDATE_STATE.write();
    match result {
        Ok(release) => {
            let latest = crate::update::tag_to_version(&release.tag_name);
            state.update_available = latest != current_version;
            state.latest_version = Some(latest);

            let wanted = crate::update::expected_asset_name();
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
            tracing::warn!("update check failed: {}", err.message);
            state.last_error = Some(err.message);
            state.update_available = false;
        }
    }
    state.checking = false;
}

/// Trigger an update check and optionally install.
pub(super) async fn handle_update_run(params: Option<&Value>) -> Result<Value, ErrorShape> {
    let check_only = params
        .and_then(|v| v.get("checkOnly"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let force = params
        .and_then(|v| v.get("force"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    {
        let mut state = UPDATE_STATE.write();
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
        state.last_check_at = Some(crate::update::now_ms());
        state.last_error = None;
    }

    fetch_latest_release().await;

    let should_install = {
        let state = UPDATE_STATE.read();
        !check_only && (state.update_available || force)
    };

    if should_install {
        return handle_update_install_with_force(force).await;
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

/// Get update status.
pub(super) async fn handle_update_status() -> Result<Value, ErrorShape> {
    let state_dir = resolve_state_dir();
    let tx = match tokio::task::spawn_blocking(move || {
        crate::update::load_update_transaction(&state_dir)
    })
    .await
    {
        Ok(Ok(tx)) => tx,
        Ok(Err(err)) => {
            tracing::warn!(
                error = %err.message,
                retryable = err.retryable,
                phase = ?err.phase,
                "failed to load update transaction for status; returning status without transaction details"
            );
            None
        }
        Err(err) => {
            tracing::warn!(
                error = %err,
                "failed to join update transaction load task for status; returning status without transaction details"
            );
            None
        }
    };
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
        "downloadUrl": state.download_url,
        "transactionState": tx.as_ref().map(|t| t.state),
        "transactionVersion": tx.as_ref().map(|t| t.version.clone()),
        "transactionAttempt": tx.as_ref().map(|t| t.attempt),
        "transactionLastError": tx.as_ref().and_then(|t| t.last_error.clone()),
        "resumePending": tx.as_ref().is_some_and(crate::update::transaction_resume_pending),
    }))
}

/// Check for updates without installing.
pub(super) async fn handle_update_check() -> Result<Value, ErrorShape> {
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
        state.last_check_at = Some(crate::update::now_ms());
        state.last_error = None;
    }

    fetch_latest_release().await;

    let state = UPDATE_STATE.read();
    Ok(json!({
        "ok": true,
        "currentVersion": state.current_version,
        "latestVersion": state.latest_version,
        "updateAvailable": state.update_available,
        "channel": state.channel
    }))
}

/// Set update channel.
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

/// Configure auto-update settings.
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

/// Install an available update.
pub(super) async fn handle_update_install() -> Result<Value, ErrorShape> {
    handle_update_install_with_force(false).await
}

async fn handle_update_install_with_force(force: bool) -> Result<Value, ErrorShape> {
    let state_dir = resolve_state_dir();
    let (version, current_version) = {
        let mut state = UPDATE_STATE.write();

        if !state.update_available && !force {
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

        let version = state.latest_version.clone().ok_or_else(|| {
            error_shape(
                ERROR_INVALID_REQUEST,
                "latest version not known; run update.check first",
                None,
            )
        })?;

        state.installing = true;
        state.last_error = None;
        (version, state.current_version.clone())
    };

    let request = crate::update::InstallRequest {
        current_version,
        state_dir,
        requested_version: Some(version.clone()),
        apply_update: !cfg!(test),
    };

    let result = crate::update::install_or_resume(request).await;

    let mut state = UPDATE_STATE.write();
    state.installing = false;

    match result {
        Ok(outcome) => {
            state.update_available = false;
            Ok(json!({
                "ok": true,
                "status": "success",
                "version": outcome.version,
                "stagedPath": outcome.staged_path,
                "applied": outcome.applied,
                "sha256": outcome.apply_result.as_ref().map(|r| r.sha256.clone()),
                "binaryPath": outcome.apply_result.as_ref().map(|r| r.binary_path.clone()),
                "restartRequired": outcome.applied,
                "verification": {
                    "bundleVerified": outcome.verification.bundle_verified,
                    "checksumVerified": outcome.verification.checksum_verified,
                    "expectedIdentity": outcome.verification.expected_identity,
                },
                "message": if outcome.applied {
                    "Update applied successfully. Restart to use new version."
                } else {
                    "Update staged successfully."
                }
            }))
        }
        Err(err) => {
            tracing::warn!("update install failed: {}", err.message);
            state.last_error = Some(err.message.clone());
            Err(error_shape(
                ERROR_UNAVAILABLE,
                &format!("update install failed: {}", err.message),
                Some(json!({
                    "version": version,
                    "retryable": err.retryable,
                    "phase": err.phase
                })),
            ))
        }
    }
}

/// Dismiss an available update notification.
pub(super) fn handle_update_dismiss() -> Result<Value, ErrorShape> {
    let state = UPDATE_STATE.read();
    Ok(json!({
        "ok": true,
        "dismissed": state.update_available,
        "version": state.latest_version
    }))
}

/// Get release notes for available update.
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

    static TEST_LOCK: Mutex<()> = Mutex::new(());

    fn reset_state() {
        let mut state = UPDATE_STATE.write();
        *state = UpdateState::default();
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn test_update_status() {
        let _lock = TEST_LOCK.lock().unwrap();
        reset_state();
        let result = handle_update_status().await.unwrap();
        assert!(!result["currentVersion"].as_str().unwrap().is_empty());
        assert_eq!(result["channel"], "stable");
        assert_eq!(result["autoUpdate"], true);
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn test_update_run() {
        let _lock = TEST_LOCK.lock().unwrap();
        reset_state();
        // Runtime behavior may vary by network and latest release state.
        // Accept either a successful run result or a retryable unavailable error.
        match handle_update_run(None).await {
            Ok(result) => assert_eq!(result["ok"], true),
            Err(err) => {
                assert_eq!(err.code, ERROR_UNAVAILABLE);
                assert!(err.retryable);
            }
        }
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
    }

    #[test]
    fn test_update_set_invalid_channel() {
        let _lock = TEST_LOCK.lock().unwrap();
        reset_state();

        let params = json!({ "channel": "invalid" });
        let result = handle_update_set_channel(Some(&params));
        assert!(result.is_err());
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn test_update_install_no_update() {
        let _lock = TEST_LOCK.lock().unwrap();
        reset_state();
        let result = handle_update_install().await;
        assert!(result.is_err());
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn test_update_install_already_installing() {
        let _lock = TEST_LOCK.lock().unwrap();
        reset_state();
        {
            let mut state = UPDATE_STATE.write();
            state.update_available = true;
            state.latest_version = Some("9.9.9".to_string());
            state.installing = true;
        }
        let err = handle_update_install()
            .await
            .expect_err("install guard should reject");
        assert_eq!(err.code, ERROR_UNAVAILABLE);
        assert!(err.message.contains("already in progress"));
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn test_update_install_force_bypasses_no_update_guard() {
        let _lock = TEST_LOCK.lock().unwrap();
        reset_state();
        let err = handle_update_install_with_force(true)
            .await
            .expect_err("force should bypass no-update check");
        assert_eq!(err.code, ERROR_INVALID_REQUEST);
        assert!(err.message.contains("latest version not known"));
    }

    #[test]
    fn test_update_dismiss() {
        let _lock = TEST_LOCK.lock().unwrap();
        reset_state();
        let result = handle_update_dismiss().unwrap();
        assert_eq!(result["ok"], true);
    }
}
