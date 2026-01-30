//! Background resource monitoring with Prometheus gauge updates.
//!
//! Periodically samples system metrics (disk free space, RSS, open FDs) via
//! [`HealthChecker`] and updates the corresponding Prometheus gauges in the
//! global metrics registry. Emits `tracing::warn!` when resource usage crosses
//! configurable thresholds.

use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::watch;
use tracing::{info, warn};

use crate::server::health::HealthChecker;
use crate::server::metrics::{Gauge, METRICS};

/// Background resource monitor that samples system metrics and updates
/// Prometheus gauges.
pub struct ResourceMonitor {
    health_checker: Arc<HealthChecker>,
    disk_free_bytes: Arc<Gauge>,
    memory_rss_bytes: Arc<Gauge>,
    open_fds: Arc<Gauge>,
    uptime_seconds: Arc<Gauge>,
    start_time: Instant,
}

/// Thresholds that trigger warning log emissions when crossed.
pub struct ResourceThresholds {
    /// Minimum free disk space before warning (bytes). Default: 100 MB.
    pub disk_min_bytes: u64,
    /// Fraction of `ulimit -n` at which to warn about FDs. Default: 0.8.
    pub fd_warn_fraction: f64,
    /// Maximum RSS before warning (bytes). Default: 1 GB.
    pub rss_warn_bytes: u64,
}

impl Default for ResourceThresholds {
    fn default() -> Self {
        Self {
            disk_min_bytes: 100 * 1024 * 1024,  // 100 MB
            fd_warn_fraction: 0.8,              // 80%
            rss_warn_bytes: 1024 * 1024 * 1024, // 1 GB
        }
    }
}

impl ResourceMonitor {
    /// Create a new monitor, registering gauges in the global metrics registry.
    pub fn new(health_checker: Arc<HealthChecker>) -> Self {
        let disk_free_bytes = METRICS.register_gauge(
            "carapace_disk_free_bytes",
            "Free disk space on state directory filesystem",
        );
        let memory_rss_bytes = METRICS.register_gauge(
            "carapace_memory_rss_bytes",
            "Process resident set size in bytes",
        );
        let open_fds =
            METRICS.register_gauge("carapace_open_fds", "Number of open file descriptors");
        let uptime_seconds = METRICS.register_gauge(
            "carapace_resource_uptime_seconds",
            "Process uptime in seconds (from resource monitor start)",
        );

        Self {
            health_checker,
            disk_free_bytes,
            memory_rss_bytes,
            open_fds,
            uptime_seconds,
            start_time: Instant::now(),
        }
    }

    /// Sample current resource usage and update gauges.
    pub fn sample(&self) {
        let diag = self.health_checker.gather_diagnostics(false);
        if let Some(v) = diag.disk_free_bytes {
            self.disk_free_bytes.set(v as f64);
        }
        if let Some(v) = diag.memory_rss_bytes {
            self.memory_rss_bytes.set(v as f64);
        }
        if let Some(v) = diag.open_fds {
            self.open_fds.set(v as f64);
        }
        self.uptime_seconds
            .set(self.start_time.elapsed().as_secs_f64());
    }

    /// Check thresholds and emit warnings for any that are exceeded.
    pub fn check_thresholds(&self, thresholds: &ResourceThresholds) {
        let diag = self.health_checker.gather_diagnostics(false);

        if let Some(free) = diag.disk_free_bytes {
            if free < thresholds.disk_min_bytes {
                warn!(
                    free_bytes = free,
                    threshold = thresholds.disk_min_bytes,
                    "disk space low"
                );
            }
        }

        if let Some(rss) = diag.memory_rss_bytes {
            if rss > thresholds.rss_warn_bytes {
                warn!(
                    rss_bytes = rss,
                    threshold = thresholds.rss_warn_bytes,
                    "memory RSS exceeds threshold"
                );
            }
        }

        if let Some(fds) = diag.open_fds {
            let fd_limit = fd_soft_limit();
            if let Some(limit) = fd_limit {
                let fraction = fds as f64 / limit as f64;
                if fraction >= thresholds.fd_warn_fraction {
                    warn!(
                        open_fds = fds,
                        limit = limit,
                        fraction = format!("{:.1}%", fraction * 100.0),
                        "file descriptor usage high"
                    );
                }
            }
        }
    }
}

/// Get the soft file descriptor limit (`ulimit -n`).
#[cfg(unix)]
fn fd_soft_limit() -> Option<u64> {
    unsafe {
        let mut rlim: libc::rlimit = std::mem::zeroed();
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut rlim) == 0 {
            Some(rlim.rlim_cur)
        } else {
            None
        }
    }
}

#[cfg(not(unix))]
fn fd_soft_limit() -> Option<u64> {
    None
}

/// Run the resource monitor loop.
///
/// Samples metrics every `interval`, checks thresholds, and stops when the
/// shutdown signal is received.
pub async fn run_resource_monitor(
    monitor: Arc<ResourceMonitor>,
    interval: Duration,
    thresholds: ResourceThresholds,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    info!("resource monitor started (interval={:?})", interval);
    let mut ticker = tokio::time::interval(interval);
    loop {
        tokio::select! {
            _ = ticker.tick() => {
                monitor.sample();
                monitor.check_thresholds(&thresholds);
            }
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    info!("resource monitor stopped");
                    break;
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn make_monitor() -> (TempDir, Arc<ResourceMonitor>) {
        let dir = TempDir::new().unwrap();
        let hc = Arc::new(HealthChecker::new(dir.path().to_path_buf()));
        let monitor = Arc::new(ResourceMonitor::new(hc));
        (dir, monitor)
    }

    #[test]
    fn test_sample_updates_gauges() {
        let (_dir, monitor) = make_monitor();
        monitor.sample();

        // On macOS/Linux these should be populated
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        {
            assert!(monitor.disk_free_bytes.get() > 0.0);
            assert!(monitor.memory_rss_bytes.get() > 0.0);
            assert!(monitor.open_fds.get() > 0.0);
        }
        assert!(monitor.uptime_seconds.get() >= 0.0);
    }

    #[test]
    fn test_check_thresholds_disk_low() {
        let (_dir, monitor) = make_monitor();
        // Set a very high threshold to trigger the warning
        let thresholds = ResourceThresholds {
            disk_min_bytes: u64::MAX,
            fd_warn_fraction: 1.0, // don't trigger FD warning
            rss_warn_bytes: u64::MAX,
        };
        // This should log a warning but not panic
        monitor.check_thresholds(&thresholds);
    }

    #[test]
    fn test_check_thresholds_rss_high() {
        let (_dir, monitor) = make_monitor();
        let thresholds = ResourceThresholds {
            disk_min_bytes: 0,
            fd_warn_fraction: 1.0,
            rss_warn_bytes: 1, // 1 byte — will always trigger
        };
        monitor.check_thresholds(&thresholds);
    }

    #[test]
    fn test_default_thresholds() {
        let t = ResourceThresholds::default();
        assert_eq!(t.disk_min_bytes, 100 * 1024 * 1024);
        assert!((t.fd_warn_fraction - 0.8).abs() < f64::EPSILON);
        assert_eq!(t.rss_warn_bytes, 1024 * 1024 * 1024);
    }

    #[tokio::test]
    async fn test_monitor_loop_runs_and_stops() {
        let (_dir, monitor) = make_monitor();
        let (tx, rx) = watch::channel(false);

        let monitor_clone = monitor.clone();
        let handle = tokio::spawn(run_resource_monitor(
            monitor_clone,
            Duration::from_millis(50),
            ResourceThresholds::default(),
            rx,
        ));

        // Let it run a couple of ticks
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert!(monitor.uptime_seconds.get() > 0.0);

        // Signal shutdown
        tx.send(true).unwrap();
        handle.await.unwrap();
    }
}
