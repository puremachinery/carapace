//! Config file watcher with debounced reload.
//!
//! Watches the config file for changes and reloads the config automatically
//! based on the configured reload mode. Supports hot reload (in-place config
//! update), hybrid reload (config update + component restart signal), and off
//! (manual restart only).
//!
//! Debouncing prevents multiple reloads from editor save patterns (e.g.,
//! write-to-temp-then-rename). The default debounce is 300 ms.

use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use serde_json::Value;
use std::path::PathBuf;
use std::time::Duration;
use tokio::sync::watch;
use tokio::task;
use tracing::{debug, error, info, warn};

/// Reload mode for the gateway config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReloadMode {
    /// Hot reload: update config in-place, no service interruption.
    Hot,
    /// Hybrid reload: update config, signal components that need restart
    /// (e.g., HTTP bind address), keep WS connections alive.
    Hybrid,
    /// No automatic reload; manual process restart required.
    Off,
}

impl ReloadMode {
    /// Parse a reload mode string from config.
    pub fn parse_mode(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "hot" => ReloadMode::Hot,
            "hybrid" => ReloadMode::Hybrid,
            "off" | "none" | "disabled" => ReloadMode::Off,
            _ => {
                warn!("Unknown reload mode '{}', defaulting to off", s);
                ReloadMode::Off
            }
        }
    }

    /// Whether this mode is active (will watch for changes).
    pub fn is_active(&self) -> bool {
        !matches!(self, ReloadMode::Off)
    }
}

/// Result of a config reload attempt.
#[derive(Debug, Clone)]
pub struct ReloadResult {
    /// Whether the reload succeeded.
    pub success: bool,
    /// The reload mode that was applied.
    pub mode: String,
    /// Validation warnings (non-fatal).
    pub warnings: Vec<String>,
    /// Error message if the reload failed.
    pub error: Option<String>,
}

/// Notification sent when config changes are detected and applied.
#[derive(Debug, Clone)]
pub enum ConfigEvent {
    /// Config was successfully reloaded.
    Reloaded(ReloadResult),
    /// Config reload failed (invalid config, parse error, etc.).
    ReloadFailed(ReloadResult),
}

/// Config watcher that monitors the config file and reloads on changes.
///
/// Spawns a background task that uses `notify` to watch for file system events
/// and a debounce timer to coalesce rapid changes.
pub struct ConfigWatcher {
    /// The reload mode.
    mode: ReloadMode,
    /// Debounce duration.
    debounce: Duration,
    /// Sender for config change events.
    event_tx: tokio::sync::broadcast::Sender<ConfigEvent>,
}

impl ConfigWatcher {
    /// Create a new config watcher from the loaded config.
    ///
    /// Reads `gateway.reload.mode` and `gateway.reload.debounceMs` from the
    /// config to determine behavior.
    pub fn from_config(config: &Value) -> Self {
        let gateway = config.get("gateway").and_then(|v| v.as_object());
        let reload = gateway
            .and_then(|g| g.get("reload"))
            .and_then(|v| v.as_object());

        let mode_str = reload
            .and_then(|r| r.get("mode"))
            .and_then(|v| v.as_str())
            .unwrap_or("off");

        let debounce_ms = reload
            .and_then(|r| r.get("debounceMs"))
            .and_then(|v| v.as_u64())
            .unwrap_or(300);

        let mode = ReloadMode::parse_mode(mode_str);
        let debounce = Duration::from_millis(debounce_ms);
        let (event_tx, _) = tokio::sync::broadcast::channel(16);

        Self {
            mode,
            debounce,
            event_tx,
        }
    }

    /// Get the reload mode.
    pub fn mode(&self) -> &ReloadMode {
        &self.mode
    }

    /// Subscribe to config change events.
    pub fn subscribe(&self) -> tokio::sync::broadcast::Receiver<ConfigEvent> {
        self.event_tx.subscribe()
    }

    /// Get a clone of the event sender (for manual reload triggers).
    pub fn event_sender(&self) -> tokio::sync::broadcast::Sender<ConfigEvent> {
        self.event_tx.clone()
    }

    /// Start watching the config file.
    ///
    /// Returns immediately after spawning the background watcher task.
    /// The watcher will shut down when the `shutdown_rx` signal fires.
    ///
    /// Does nothing if the reload mode is `Off`.
    pub fn start(&self, config_path: PathBuf, shutdown_rx: watch::Receiver<bool>) {
        if !self.mode.is_active() {
            info!("Config reload mode is off; file watcher not started");
            return;
        }

        let mode = self.mode.clone();
        let debounce = self.debounce;
        let event_tx = self.event_tx.clone();

        info!(
            "Config watcher starting: mode={:?}, debounce={}ms, path={}",
            mode,
            debounce.as_millis(),
            config_path.display()
        );

        tokio::spawn(watcher_task(
            config_path,
            mode,
            debounce,
            event_tx,
            shutdown_rx,
        ));
    }
}

/// Convert a `ReloadMode` to its string label.
fn mode_label(mode: &ReloadMode) -> &'static str {
    match mode {
        ReloadMode::Hot => "hot",
        ReloadMode::Hybrid => "hybrid",
        ReloadMode::Off => "off",
    }
}

/// Validate the reloaded configuration, apply it, and build a `ReloadResult`.
///
/// Called by `perform_reload` after `super::reload_config()` returns.
fn process_config_reload_event(
    mode: &ReloadMode,
    outcome: Result<(serde_json::Value, Vec<super::ValidationIssue>), super::ConfigError>,
) -> ReloadResult {
    let mode_str = mode_label(mode);
    match outcome {
        Ok((_config, issues)) => {
            let warnings: Vec<String> = issues
                .iter()
                .map(|i| format!("{}: {}", i.path, i.message))
                .collect();

            if !warnings.is_empty() {
                for w in &warnings {
                    warn!("Config validation warning: {}", w);
                }
            }

            info!(
                "Config reloaded successfully (mode={}, warnings={})",
                mode_str,
                warnings.len()
            );

            ReloadResult {
                success: true,
                mode: mode_str.to_string(),
                warnings,
                error: None,
            }
        }
        Err(e) => {
            let error_msg = e.to_string();
            error!(
                "Config reload failed, keeping previous config: {}",
                error_msg
            );

            ReloadResult {
                success: false,
                mode: mode_str.to_string(),
                warnings: Vec::new(),
                error: Some(error_msg),
            }
        }
    }
}

/// Perform a config reload (parse, validate, update cache).
///
/// This is the core reload logic shared by the file watcher, SIGHUP handler,
/// and the `config.reload` WS method.
pub fn perform_reload(mode: &ReloadMode) -> ReloadResult {
    info!("Config reload triggered (mode={:?})", mode);
    let outcome = super::reload_config();
    process_config_reload_event(mode, outcome)
}

/// Perform a config reload on a blocking thread to avoid stalling async tasks.
pub async fn perform_reload_async(mode: &ReloadMode) -> ReloadResult {
    info!("Config reload triggered (mode={:?})", mode);
    let outcome = task::spawn_blocking(super::reload_config).await;
    match outcome {
        Ok(result) => process_config_reload_event(mode, result),
        Err(err) => {
            let error_msg = format!("Config reload task failed: {err}");
            error!("{error_msg}");
            ReloadResult {
                success: false,
                mode: mode_label(mode).to_string(),
                warnings: Vec::new(),
                error: Some(error_msg),
            }
        }
    }
}

/// Create a filesystem watcher that forwards config-file events to `fs_tx`.
///
/// Returns the `RecommendedWatcher` and the directory being watched, or an
/// error string if creation or watch-registration fails.
fn create_file_watcher(
    file_name: &str,
    fs_tx: tokio::sync::mpsc::Sender<()>,
) -> Result<RecommendedWatcher, String> {
    let file_name_clone = file_name.to_string();
    let watcher: RecommendedWatcher =
        notify::recommended_watcher(move |res: Result<Event, notify::Error>| {
            match res {
                Ok(event) => {
                    // Only trigger on content-relevant events
                    let dominated = matches!(
                        event.kind,
                        EventKind::Create(_) | EventKind::Modify(_) | EventKind::Remove(_)
                    );
                    if !dominated {
                        return;
                    }
                    // Check if the event is for our config file
                    let is_config_file = event.paths.iter().any(|p| {
                        p.file_name()
                            .map(|n| n.to_string_lossy() == file_name_clone)
                            .unwrap_or(false)
                    });
                    if is_config_file {
                        let _ = fs_tx.try_send(());
                    }
                }
                Err(e) => {
                    warn!("File watcher error: {}", e);
                }
            }
        })
        .map_err(|e| format!("Failed to create file watcher: {}", e))?;

    Ok(watcher)
}

/// Resolve the watch directory and file name from a config path.
fn resolve_watch_targets(config_path: &std::path::Path) -> (PathBuf, String) {
    let watch_dir = config_path
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."));

    let file_name = config_path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();

    (watch_dir, file_name)
}

/// Initialize the filesystem watcher and begin watching the target directory.
///
/// Returns the watcher and an mpsc receiver for file-change notifications, or
/// `None` if watcher creation or directory registration fails.
fn init_fs_watcher(
    watch_dir: &std::path::Path,
    file_name: &str,
) -> Option<(RecommendedWatcher, tokio::sync::mpsc::Receiver<()>)> {
    let (fs_tx, fs_rx) = tokio::sync::mpsc::channel::<()>(32);

    let mut watcher = match create_file_watcher(file_name, fs_tx) {
        Ok(w) => w,
        Err(e) => {
            error!("{}", e);
            return None;
        }
    };

    if let Err(e) = watcher.watch(watch_dir, RecursiveMode::NonRecursive) {
        error!("Failed to watch directory {}: {}", watch_dir.display(), e);
        return None;
    }

    Some((watcher, fs_rx))
}

/// Perform a debounced reload and broadcast the resulting event.
async fn execute_reload_and_broadcast(
    mode: &ReloadMode,
    event_tx: &tokio::sync::broadcast::Sender<ConfigEvent>,
) {
    let result = perform_reload_async(mode).await;
    let event = if result.success {
        ConfigEvent::Reloaded(result)
    } else {
        ConfigEvent::ReloadFailed(result)
    };
    // Broadcast to subscribers (ignore send errors if no receivers)
    let _ = event_tx.send(event);
}

/// Run the debounced select loop, waiting for fs events, shutdown signals, or
/// debounce timer expiry.  Extracted from `watcher_task` to reduce cognitive
/// complexity.
async fn run_debounce_loop(
    debounce: Duration,
    mode: &ReloadMode,
    event_tx: &tokio::sync::broadcast::Sender<ConfigEvent>,
    fs_rx: &mut tokio::sync::mpsc::Receiver<()>,
    shutdown_rx: &mut watch::Receiver<bool>,
) {
    let mut debounce_active = false;
    let debounce_sleep = tokio::time::sleep(debounce);
    tokio::pin!(debounce_sleep);

    loop {
        tokio::select! {
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    info!("Config watcher shutting down");
                    break;
                }
            }

            Some(()) = fs_rx.recv() => {
                debug!(
                    "Config file change detected, starting debounce timer ({}ms)",
                    debounce.as_millis()
                );
                debounce_sleep.as_mut().reset(tokio::time::Instant::now() + debounce);
                debounce_active = true;
            }

            _ = &mut debounce_sleep, if debounce_active => {
                debounce_active = false;
                execute_reload_and_broadcast(mode, event_tx).await;
            }
        }
    }
}

/// Background task that watches the config file and triggers debounced reloads.
async fn watcher_task(
    config_path: PathBuf,
    mode: ReloadMode,
    debounce: Duration,
    event_tx: tokio::sync::broadcast::Sender<ConfigEvent>,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    let (watch_dir, file_name) = resolve_watch_targets(&config_path);

    let (watcher, mut fs_rx) = match init_fs_watcher(&watch_dir, &file_name) {
        Some(pair) => pair,
        None => return,
    };

    info!(
        "File watcher active on {} (file={})",
        watch_dir.display(),
        file_name
    );

    run_debounce_loop(debounce, &mode, &event_tx, &mut fs_rx, &mut shutdown_rx).await;

    // Drop the watcher to stop watching
    drop(watcher);
    info!("Config watcher stopped");
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_reload_mode_from_str() {
        assert_eq!(ReloadMode::parse_mode("hot"), ReloadMode::Hot);
        assert_eq!(ReloadMode::parse_mode("Hot"), ReloadMode::Hot);
        assert_eq!(ReloadMode::parse_mode("HOT"), ReloadMode::Hot);
        assert_eq!(ReloadMode::parse_mode("hybrid"), ReloadMode::Hybrid);
        assert_eq!(ReloadMode::parse_mode("Hybrid"), ReloadMode::Hybrid);
        assert_eq!(ReloadMode::parse_mode("off"), ReloadMode::Off);
        assert_eq!(ReloadMode::parse_mode("none"), ReloadMode::Off);
        assert_eq!(ReloadMode::parse_mode("disabled"), ReloadMode::Off);
        assert_eq!(ReloadMode::parse_mode("unknown"), ReloadMode::Off);
    }

    #[test]
    fn test_reload_mode_is_active() {
        assert!(ReloadMode::Hot.is_active());
        assert!(ReloadMode::Hybrid.is_active());
        assert!(!ReloadMode::Off.is_active());
    }

    #[test]
    fn test_config_watcher_from_config_defaults() {
        let config = json!({});
        let watcher = ConfigWatcher::from_config(&config);
        assert_eq!(*watcher.mode(), ReloadMode::Off);
    }

    #[test]
    fn test_config_watcher_from_config_hot() {
        let config = json!({
            "gateway": {
                "reload": {
                    "mode": "hot",
                    "debounceMs": 500
                }
            }
        });
        let watcher = ConfigWatcher::from_config(&config);
        assert_eq!(*watcher.mode(), ReloadMode::Hot);
        assert_eq!(watcher.debounce, Duration::from_millis(500));
    }

    #[test]
    fn test_config_watcher_from_config_hybrid() {
        let config = json!({
            "gateway": {
                "reload": {
                    "mode": "hybrid"
                }
            }
        });
        let watcher = ConfigWatcher::from_config(&config);
        assert_eq!(*watcher.mode(), ReloadMode::Hybrid);
        assert_eq!(watcher.debounce, Duration::from_millis(300));
    }

    #[test]
    fn test_config_watcher_from_config_off() {
        let config = json!({
            "gateway": {
                "reload": {
                    "mode": "off"
                }
            }
        });
        let watcher = ConfigWatcher::from_config(&config);
        assert_eq!(*watcher.mode(), ReloadMode::Off);
        assert!(!watcher.mode().is_active());
    }

    #[test]
    fn test_perform_reload_with_no_config_file() {
        // When no config file exists, reload should succeed with defaults
        // (load_config_uncached returns defaults for missing files)
        let result = perform_reload(&ReloadMode::Hot);
        // This should succeed since load_config_uncached returns defaults
        // for non-existent files
        assert!(result.success);
        assert_eq!(result.mode, "hot");
    }

    #[test]
    fn test_debounce_timer_default() {
        let config = json!({
            "gateway": {
                "reload": {
                    "mode": "hot"
                }
            }
        });
        let watcher = ConfigWatcher::from_config(&config);
        assert_eq!(watcher.debounce, Duration::from_millis(300));
    }

    #[test]
    fn test_debounce_timer_custom() {
        let config = json!({
            "gateway": {
                "reload": {
                    "mode": "hot",
                    "debounceMs": 1000
                }
            }
        });
        let watcher = ConfigWatcher::from_config(&config);
        assert_eq!(watcher.debounce, Duration::from_millis(1000));
    }

    #[tokio::test]
    async fn test_watcher_does_not_start_when_off() {
        let config = json!({
            "gateway": {
                "reload": {
                    "mode": "off"
                }
            }
        });
        let watcher = ConfigWatcher::from_config(&config);
        let (_shutdown_tx, shutdown_rx) = watch::channel(false);

        // Should return immediately without spawning a task
        watcher.start(PathBuf::from("/nonexistent/config.json"), shutdown_rx);
        // No panic = success
    }

    #[tokio::test]
    async fn test_watcher_subscribe() {
        let config = json!({
            "gateway": {
                "reload": {
                    "mode": "hot"
                }
            }
        });
        let watcher = ConfigWatcher::from_config(&config);
        let mut rx = watcher.subscribe();

        // Manually send an event
        let result = ReloadResult {
            success: true,
            mode: "hot".to_string(),
            warnings: Vec::new(),
            error: None,
        };
        watcher
            .event_sender()
            .send(ConfigEvent::Reloaded(result))
            .unwrap();

        // Should receive it
        let event = rx.recv().await.unwrap();
        match event {
            ConfigEvent::Reloaded(r) => {
                assert!(r.success);
                assert_eq!(r.mode, "hot");
            }
            _ => panic!("Expected Reloaded event"),
        }
    }

    #[tokio::test]
    async fn test_reload_validation_with_temp_config() {
        use std::io::Write;
        let dir = tempfile::TempDir::new().unwrap();
        let config_path = dir.path().join("carapace.json5");

        // Write a valid config
        {
            let mut f = std::fs::File::create(&config_path).unwrap();
            f.write_all(b"{ \"gateway\": { \"port\": 9999 } }").unwrap();
        }

        // Set the env var to point to our test config
        let _guard = EnvVarGuard::set("CARAPACE_CONFIG_PATH", config_path.to_str().unwrap());
        let result = perform_reload(&ReloadMode::Hot);
        assert!(result.success);
        assert_eq!(result.mode, "hot");
    }

    #[tokio::test]
    async fn test_reload_invalid_config_fails() {
        use std::io::Write;
        let dir = tempfile::TempDir::new().unwrap();
        let config_path = dir.path().join("carapace.json5");

        // Write an invalid config (not valid JSON5)
        {
            let mut f = std::fs::File::create(&config_path).unwrap();
            f.write_all(b"this is not valid json5 {{{{").unwrap();
        }

        let _guard = EnvVarGuard::set("CARAPACE_CONFIG_PATH", config_path.to_str().unwrap());
        let result = perform_reload(&ReloadMode::Hybrid);
        assert!(!result.success);
        assert_eq!(result.mode, "hybrid");
        assert!(result.error.is_some());
    }

    /// RAII guard for temporarily setting an environment variable.
    struct EnvVarGuard {
        key: String,
        prev: Option<String>,
    }

    impl EnvVarGuard {
        fn set(key: &str, value: &str) -> Self {
            let prev = std::env::var(key).ok();
            std::env::set_var(key, value);
            Self {
                key: key.to_string(),
                prev,
            }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            match &self.prev {
                Some(v) => std::env::set_var(&self.key, v),
                None => std::env::remove_var(&self.key),
            }
        }
    }
}
