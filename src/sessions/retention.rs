//! Session retention cleanup.
//!
//! Background task that periodically purges sessions whose `updated_at`
//! timestamp is older than the configured retention period.

use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use super::SessionStore;

/// Configuration for automatic session retention cleanup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetentionConfig {
    /// Whether automatic cleanup is enabled.
    pub enabled: bool,
    /// Sessions not updated within this many days are deleted.
    pub retention_days: u32,
    /// How often (in hours) the cleanup task runs.
    pub interval_hours: u32,
}

impl Default for RetentionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            retention_days: 30,
            interval_hours: 6,
        }
    }
}

/// Build a `RetentionConfig` from the top-level configuration value.
///
/// Reads from `sessions.retention.enabled`, `sessions.retention.days`, and
/// `sessions.retention.intervalHours`, falling back to defaults when keys are
/// absent. Legacy keys (`session.retention.*`, `sessions.retentionDays`) are
/// accepted for backward compatibility.
pub fn build_retention_config(cfg: &Value) -> RetentionConfig {
    let sessions_obj = cfg.get("sessions").and_then(|v| v.as_object());
    let legacy_session_obj = cfg.get("session").and_then(|v| v.as_object());

    let retention_obj = sessions_obj
        .and_then(|v| v.get("retention"))
        .and_then(|v| v.as_object())
        .or_else(|| {
            legacy_session_obj
                .and_then(|v| v.get("retention"))
                .and_then(|v| v.as_object())
        });

    let defaults = RetentionConfig::default();

    let enabled = retention_obj
        .and_then(|o| o.get("enabled"))
        .and_then(|v| v.as_bool())
        .unwrap_or(defaults.enabled);

    let retention_days = retention_obj
        .and_then(|o| o.get("days"))
        .and_then(|v| v.as_u64())
        .map(|d| d as u32)
        .or_else(|| {
            sessions_obj
                .and_then(|o| o.get("retentionDays"))
                .and_then(|v| v.as_u64())
                .map(|d| d as u32)
        })
        .unwrap_or(defaults.retention_days);

    let interval_hours = retention_obj
        .and_then(|o| o.get("intervalHours"))
        .and_then(|v| v.as_u64())
        .map(|h| h as u32)
        .unwrap_or(defaults.interval_hours);

    RetentionConfig {
        enabled,
        retention_days,
        interval_hours,
    }
}

/// Background loop that periodically cleans up expired sessions.
///
/// Runs an initial cleanup after a short startup delay (30 seconds), then
/// repeats at the configured interval. Exits cleanly when the shutdown
/// signal fires.
pub async fn retention_cleanup_loop(
    store: Arc<SessionStore>,
    config: RetentionConfig,
    mut shutdown: watch::Receiver<bool>,
) {
    if !config.enabled {
        debug!("Session retention cleanup is disabled");
        return;
    }

    let interval = Duration::from_secs(u64::from(config.interval_hours) * 3600);

    info!(
        retention_days = config.retention_days,
        interval_hours = config.interval_hours,
        "Session retention cleanup scheduled"
    );

    if !wait_for_startup_delay(&mut shutdown).await {
        return;
    }

    // Run the first cleanup immediately after the startup delay.
    run_cleanup(store.clone(), config.retention_days).await;

    // Then run on the configured interval.
    let mut ticker = tokio::time::interval(interval);
    // The first tick fires immediately; consume it since we already ran above.
    ticker.tick().await;

    loop {
        tokio::select! {
            _ = ticker.tick() => {}
            _ = shutdown.changed() => break,
        }

        if *shutdown.borrow() {
            break;
        }

        run_cleanup(store.clone(), config.retention_days).await;
    }
}

/// Wait for the initial startup delay, returning `false` if shutdown was
/// signalled before the delay elapsed.
async fn wait_for_startup_delay(shutdown: &mut watch::Receiver<bool>) -> bool {
    let startup_delay = Duration::from_secs(30);

    tokio::select! {
        _ = tokio::time::sleep(startup_delay) => {}
        _ = shutdown.changed() => return false,
    }

    !*shutdown.borrow()
}

/// Execute a single cleanup pass, logging the result.
async fn run_cleanup(store: Arc<SessionStore>, retention_days: u32) {
    let outcome =
        tokio::task::spawn_blocking(move || store.cleanup_expired(retention_days)).await;
    match outcome {
        Ok(Ok(deleted)) => {
            if deleted > 0 {
                info!(
                    deleted,
                    retention_days, "Retention cleanup: purged expired sessions"
                );
            } else {
                debug!(
                    retention_days,
                    "Retention cleanup: no expired sessions found"
                );
            }
        }
        Ok(Err(e)) => {
            warn!(error = %e, "Retention cleanup failed");
        }
        Err(e) => {
            warn!(error = %e, "Retention cleanup task failed");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ---------------------------------------------------------------
    // Config parsing tests
    // ---------------------------------------------------------------

    #[test]
    fn test_defaults_when_no_config() {
        let cfg = json!({});
        let rc = build_retention_config(&cfg);
        assert_eq!(rc, RetentionConfig::default());
        assert!(rc.enabled);
        assert_eq!(rc.retention_days, 30);
        assert_eq!(rc.interval_hours, 6);
    }

    #[test]
    fn test_defaults_when_session_key_missing() {
        let cfg = json!({ "gateway": { "port": 3000 } });
        let rc = build_retention_config(&cfg);
        assert_eq!(rc, RetentionConfig::default());
    }

    #[test]
    fn test_partial_override() {
        let cfg = json!({
            "sessions": {
                "retention": {
                    "days": 7
                }
            }
        });
        let rc = build_retention_config(&cfg);
        assert!(rc.enabled);
        assert_eq!(rc.retention_days, 7);
        assert_eq!(rc.interval_hours, 6); // default
    }

    #[test]
    fn test_full_override() {
        let cfg = json!({
            "sessions": {
                "retention": {
                    "enabled": false,
                    "days": 90,
                    "intervalHours": 12
                }
            }
        });
        let rc = build_retention_config(&cfg);
        assert!(!rc.enabled);
        assert_eq!(rc.retention_days, 90);
        assert_eq!(rc.interval_hours, 12);
    }

    #[test]
    fn test_disabled_cleanup() {
        let cfg = json!({
            "sessions": {
                "retention": {
                    "enabled": false
                }
            }
        });
        let rc = build_retention_config(&cfg);
        assert!(!rc.enabled);
    }

    #[test]
    fn test_legacy_session_retention_still_parses() {
        let cfg = json!({
            "session": {
                "retention": {
                    "days": 5
                }
            }
        });
        let rc = build_retention_config(&cfg);
        assert_eq!(rc.retention_days, 5);
    }

    #[test]
    fn test_retention_config_default_trait() {
        let rc = RetentionConfig::default();
        assert!(rc.enabled);
        assert_eq!(rc.retention_days, 30);
        assert_eq!(rc.interval_hours, 6);
    }

    // ---------------------------------------------------------------
    // Cleanup loop tests
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn test_loop_exits_when_disabled() {
        let store = Arc::new(SessionStore::with_base_path(
            std::env::temp_dir().join("carapace_test_retention_disabled"),
        ));
        let config = RetentionConfig {
            enabled: false,
            ..Default::default()
        };
        let (_tx, rx) = watch::channel(false);

        // Should return immediately when disabled.
        let handle = tokio::spawn(retention_cleanup_loop(store, config, rx));
        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("loop should exit promptly when disabled")
            .expect("task should not panic");
    }

    #[tokio::test]
    async fn test_loop_exits_on_shutdown() {
        let store = Arc::new(SessionStore::with_base_path(
            std::env::temp_dir().join("carapace_test_retention_shutdown"),
        ));
        let config = RetentionConfig {
            enabled: true,
            retention_days: 30,
            interval_hours: 1,
        };
        let (tx, rx) = watch::channel(false);

        let handle = tokio::spawn(retention_cleanup_loop(store, config, rx));

        // Send shutdown before the startup delay completes.
        let _ = tx.send(true);

        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("loop should exit on shutdown signal")
            .expect("task should not panic");
    }

    #[tokio::test]
    async fn test_run_cleanup_no_sessions() {
        let dir = std::env::temp_dir().join("carapace_test_retention_empty");
        let _ = std::fs::create_dir_all(&dir);
        let store = SessionStore::with_base_path(dir);

        // Should succeed with 0 deleted when there are no sessions.
        let result = store.cleanup_expired(30);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 0);
    }
}
