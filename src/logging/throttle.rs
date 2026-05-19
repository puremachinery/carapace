//! Process-global "fire at most once per hour" throttle gates for
//! operator-facing warns whose rate would otherwise track an attacker-
//! influenced per-event hot path (verification floods, channel-drop
//! storms, manifest-near-cap polls, audit-stream backpressure).

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

const HOURLY_THROTTLE_SECS: u64 = 3600;

/// Returns true at most once per hour per process, gated on the
/// supplied `AtomicU64` state. Each call site provides its own state
/// atomic so independent warns don't suppress each other.
///
/// Uses wall-clock seconds since UNIX epoch. `saturating_sub` keeps
/// the gate engaged across backward clock steps (fail-closed). The
/// CAS-with-stale-`last` ensures exactly one winner under concurrent
/// first-call races.
///
/// NOT FOR clock-failure paths: if a warn fires precisely *because*
/// `SystemTime::now()` failed, use an `Instant`-based gate instead —
/// this helper would silently suppress every warn in the broken-clock
/// window because both `last` and `now_secs` saturate at 0. The
/// `now_millis_broken_clock_warn_should_fire` gate in
/// `src/channels/matrix.rs` is the canonical Instant-based variant.
pub fn throttled_once_per_hour(state: &AtomicU64) -> bool {
    throttled_with_period(state, HOURLY_THROTTLE_SECS)
}

/// Returns true at most once per minute per process. Shape mirrors
/// `throttled_once_per_hour` — see that function's docs for the
/// clock-step / fail-closed semantics. Tighter cadence is appropriate
/// for warns whose underlying condition is benign-and-recoverable but
/// driven by peer traffic the daemon cannot rate-limit upstream.
pub fn throttled_once_per_minute(state: &AtomicU64) -> bool {
    throttled_with_period(state, 60)
}

fn throttled_with_period(state: &AtomicU64, period_secs: u64) -> bool {
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let last = state.load(Ordering::Relaxed);
    if now_secs.saturating_sub(last) < period_secs {
        return false;
    }
    state
        .compare_exchange(last, now_secs, Ordering::Relaxed, Ordering::Relaxed)
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_call_fires_then_suppresses() {
        let state = AtomicU64::new(0);
        assert!(throttled_once_per_hour(&state));
        assert!(!throttled_once_per_hour(&state));
        assert!(!throttled_once_per_hour(&state));
    }

    /// Pre-load the gate with a future timestamp to simulate a
    /// backward clock step. Without `saturating_sub` the subtraction
    /// would underflow and produce a huge gap, firing every call.
    #[test]
    fn fail_closed_under_backward_clock_step() {
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let future = now_secs.saturating_add(7200);
        let state = AtomicU64::new(future);
        assert!(
            !throttled_once_per_hour(&state),
            "saturating_sub must keep the gate engaged across backward clock steps"
        );
    }
}
