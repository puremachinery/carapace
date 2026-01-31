//! WebSocket connection limits.
//!
//! Provides a `ConnectionTracker` that enforces a global cap on total
//! concurrent WebSocket connections and a per-IP cap.  Each successful
//! `try_acquire` returns a `ConnectionGuard` whose `Drop` impl
//! automatically decrements the counters.

use parking_lot::RwLock;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use crate::server::metrics::{Counter, Gauge, METRICS};

/// Default maximum total concurrent WebSocket connections.
pub const DEFAULT_MAX_CONNECTIONS: usize = 1024;

/// Default maximum concurrent WebSocket connections from a single IP.
pub const DEFAULT_MAX_PER_IP: usize = 32;

/// Error returned when a connection limit is exceeded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LimitExceeded {
    /// Total connection cap reached.
    TotalLimit,
    /// Per-IP connection cap reached.
    PerIpLimit,
}

impl std::fmt::Display for LimitExceeded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LimitExceeded::TotalLimit => write!(f, "total connection limit reached"),
            LimitExceeded::PerIpLimit => write!(f, "per-IP connection limit reached"),
        }
    }
}

/// Shared inner state for the connection tracker.
struct TrackerInner {
    total: AtomicUsize,
    per_ip: RwLock<HashMap<IpAddr, usize>>,
    max_connections: usize,
    max_per_ip: usize,
    // Prometheus metrics
    active_gauge: Arc<Gauge>,
    rejected_counter: Arc<Counter>,
}

/// Tracks the number of active WebSocket connections and enforces limits.
#[derive(Clone)]
pub struct ConnectionTracker {
    inner: Arc<TrackerInner>,
}

impl ConnectionTracker {
    /// Create a new tracker with the default limits.
    pub fn new() -> Self {
        Self::with_limits(DEFAULT_MAX_CONNECTIONS, DEFAULT_MAX_PER_IP)
    }

    /// Create a new tracker with explicit limits.
    pub fn with_limits(max_connections: usize, max_per_ip: usize) -> Self {
        let active_gauge = METRICS.register_gauge(
            "carapace_ws_connections_limited_active",
            "Active WebSocket connections tracked by the limiter",
        );
        let rejected_counter = METRICS.register_counter(
            "carapace_ws_connections_rejected_total",
            "Total WebSocket connections rejected due to limits",
        );

        Self {
            inner: Arc::new(TrackerInner {
                total: AtomicUsize::new(0),
                per_ip: RwLock::new(HashMap::new()),
                max_connections,
                max_per_ip,
                active_gauge,
                rejected_counter,
            }),
        }
    }

    /// Try to acquire a connection slot for the given IP.
    ///
    /// On success, returns a [`ConnectionGuard`] that decrements counters on
    /// drop.  On failure, returns [`LimitExceeded`].
    ///
    /// Loopback addresses (`127.0.0.1` / `::1`) are exempt from the per-IP
    /// limit but still count towards the total limit.
    pub fn try_acquire(&self, ip: IpAddr) -> Result<ConnectionGuard, LimitExceeded> {
        let inner = &self.inner;

        // Check + increment total.  We optimistically increment first and
        // roll back if the limit was exceeded.
        let prev = inner.total.fetch_add(1, Ordering::SeqCst);
        if prev >= inner.max_connections {
            inner.total.fetch_sub(1, Ordering::SeqCst);
            inner.rejected_counter.inc();
            return Err(LimitExceeded::TotalLimit);
        }

        // Loopback addresses are exempt from per-IP limits.
        let is_loopback = ip.is_loopback();

        if !is_loopback {
            let mut map = inner.per_ip.write();
            let count = map.entry(ip).or_insert(0);
            if *count >= inner.max_per_ip {
                // Roll back the total increment.
                inner.total.fetch_sub(1, Ordering::SeqCst);
                inner.rejected_counter.inc();
                return Err(LimitExceeded::PerIpLimit);
            }
            *count += 1;
        }

        inner.active_gauge.inc();

        Ok(ConnectionGuard {
            tracker: Arc::clone(&self.inner),
            ip,
            is_loopback,
        })
    }

    /// Current total active connections.
    pub fn total(&self) -> usize {
        self.inner.total.load(Ordering::SeqCst)
    }
}

impl Default for ConnectionTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for ConnectionTracker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnectionTracker")
            .field("total", &self.total())
            .field("max_connections", &self.inner.max_connections)
            .field("max_per_ip", &self.inner.max_per_ip)
            .finish()
    }
}

/// RAII guard that decrements connection counts when dropped.
pub struct ConnectionGuard {
    tracker: Arc<TrackerInner>,
    ip: IpAddr,
    is_loopback: bool,
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.tracker.total.fetch_sub(1, Ordering::SeqCst);
        self.tracker.active_gauge.dec();

        if !self.is_loopback {
            let mut map = self.tracker.per_ip.write();
            if let Some(count) = map.get_mut(&self.ip) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    map.remove(&self.ip);
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
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn ip(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    #[test]
    fn test_acquire_within_limit() {
        let tracker = ConnectionTracker::with_limits(4, 2);
        let guard = tracker.try_acquire(ip(10, 0, 0, 1));
        assert!(guard.is_ok());
        assert_eq!(tracker.total(), 1);
    }

    #[test]
    fn test_acquire_exceeds_total_limit() {
        let tracker = ConnectionTracker::with_limits(2, 10);
        let _g1 = tracker.try_acquire(ip(10, 0, 0, 1)).unwrap();
        let _g2 = tracker.try_acquire(ip(10, 0, 0, 2)).unwrap();

        let result = tracker.try_acquire(ip(10, 0, 0, 3));
        assert_eq!(result.err(), Some(LimitExceeded::TotalLimit));
        assert_eq!(tracker.total(), 2);
    }

    #[test]
    fn test_acquire_exceeds_per_ip_limit() {
        let tracker = ConnectionTracker::with_limits(100, 2);
        let _g1 = tracker.try_acquire(ip(10, 0, 0, 1)).unwrap();
        let _g2 = tracker.try_acquire(ip(10, 0, 0, 1)).unwrap();

        let result = tracker.try_acquire(ip(10, 0, 0, 1));
        assert_eq!(result.err(), Some(LimitExceeded::PerIpLimit));
        assert_eq!(tracker.total(), 2);
    }

    #[test]
    fn test_guard_drop_decrements() {
        let tracker = ConnectionTracker::with_limits(10, 10);
        let guard = tracker.try_acquire(ip(10, 0, 0, 1)).unwrap();
        assert_eq!(tracker.total(), 1);

        drop(guard);
        assert_eq!(tracker.total(), 0);
    }

    #[test]
    fn test_different_ips_tracked_independently() {
        let tracker = ConnectionTracker::with_limits(100, 2);
        let _g1 = tracker.try_acquire(ip(10, 0, 0, 1)).unwrap();
        let _g2 = tracker.try_acquire(ip(10, 0, 0, 1)).unwrap();
        let _g3 = tracker.try_acquire(ip(10, 0, 0, 2)).unwrap();

        // IP 10.0.0.1 is at its per-IP cap
        assert_eq!(
            tracker.try_acquire(ip(10, 0, 0, 1)).err(),
            Some(LimitExceeded::PerIpLimit)
        );
        // IP 10.0.0.2 still has room
        let _g4 = tracker.try_acquire(ip(10, 0, 0, 2)).unwrap();
        assert_eq!(tracker.total(), 4);
    }

    #[test]
    fn test_loopback_exempt() {
        let tracker = ConnectionTracker::with_limits(100, 1);
        let loopback_v4 = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let loopback_v6 = IpAddr::V6(Ipv6Addr::LOCALHOST);

        // Loopback should bypass the per-IP limit (which is 1)
        let _g1 = tracker.try_acquire(loopback_v4).unwrap();
        let _g2 = tracker.try_acquire(loopback_v4).unwrap();
        let _g3 = tracker.try_acquire(loopback_v6).unwrap();
        assert_eq!(tracker.total(), 3);

        // But a non-loopback IP at per-IP limit of 1 should be rejected
        let _g4 = tracker.try_acquire(ip(10, 0, 0, 1)).unwrap();
        assert_eq!(
            tracker.try_acquire(ip(10, 0, 0, 1)).err(),
            Some(LimitExceeded::PerIpLimit)
        );
    }
}
