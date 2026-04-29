use std::path::{Path, PathBuf};

use parking_lot::{Mutex, MutexGuard};
use serde_json::Value;
use tempfile::TempDir;

use super::env::ScopedEnv;

static TEST_CONFIG_CACHE_LOCK: Mutex<()> = parking_lot::const_mutex(());

/// Scoped global config-cache mutation helper for tests.
///
/// Tests that call `crate::config::clear_cache()` / `update_cache()` and then
/// rely on that process-global state across assertions or `.await` points
/// should hold this guard for the full test lifetime so they cannot race other
/// config-cache-mutating tests.
///
/// Under the current `parking_lot` configuration this guard is not `Send`, so
/// async tests on a multi-thread runtime should not hold it across an `.await`.
///
/// **Lock order:** when a test holds both this guard and a
/// [`ScopedEnv`](super::env::ScopedEnv), always acquire `ScopedConfigCache`
/// first and `ScopedEnv` second. [`StableConfigFixture`] follows this order;
/// new helpers that combine both locks must too, otherwise a future test that
/// inverts them could deadlock under parallel execution.
pub(crate) struct ScopedConfigCache {
    _lock: MutexGuard<'static, ()>,
}

impl ScopedConfigCache {
    pub(crate) fn new() -> Self {
        Self {
            _lock: TEST_CONFIG_CACHE_LOCK.lock(),
        }
    }
}

const FIXTURE_CONFIG_FILE_NAME: &str = "carapace.json5";

/// Stable config fixture for tests that read channel-activity policy (or any
/// other config-cache-backed state) across an `.await`.
///
/// Why this exists: `crate::config::update_cache(...)` populates an in-memory
/// cache with a 200 ms TTL. On slow CI (Windows in particular) the gap
/// between `update_cache` and a downstream `peek_fresh_raw_config_shared()`
/// call can exceed the TTL; the policy reader then falls through to a disk
/// read via `load_raw_config_shared` and gets defaults, silently disabling
/// the test's intended behavior. See issue #328 for the original flake.
///
/// `StableConfigFixture` defends against that by writing the desired config
/// to a real temp file, pointing `CARAPACE_CONFIG_PATH` at it, and priming
/// the in-memory cache from the same file via `load_config_pair_uncached`.
/// If the cache later expires, the disk fallback returns identical content.
///
/// Field declaration order is load-bearing: the explicit `Drop` impl runs
/// first (clears the cache), then fields drop top-to-bottom. `_cache_guard`
/// is declared LAST so the global cache lock is still held while the env
/// and tempdir teardown runs — no other cache user can observe a stale
/// lock window. Adding a new field below `_cache_guard` would re-introduce
/// that window.
pub(crate) struct StableConfigFixture {
    config_path: PathBuf,
    _env_guard: ScopedEnv,
    _tempdir: TempDir,
    _cache_guard: ScopedConfigCache,
}

impl StableConfigFixture {
    pub(crate) fn new(raw_value: Value) -> Self {
        let cache_guard = ScopedConfigCache::new();

        let tempdir = tempfile::tempdir().expect("tempdir for config fixture");
        let config_path = tempdir.path().join(FIXTURE_CONFIG_FILE_NAME);
        write_and_prime(&config_path, &raw_value);

        let mut env_guard = ScopedEnv::new();
        env_guard.set("CARAPACE_CONFIG_PATH", config_path.as_os_str());

        Self {
            config_path,
            _env_guard: env_guard,
            _tempdir: tempdir,
            _cache_guard: cache_guard,
        }
    }

    pub(crate) fn update(&self, raw_value: Value) {
        write_and_prime(&self.config_path, &raw_value);
    }
}

impl Drop for StableConfigFixture {
    fn drop(&mut self) {
        // Runs before any field drops. Clearing here ensures the cache is
        // empty while `_cache_guard` still holds the global cache lock,
        // preventing the next test from observing leaked state.
        crate::config::clear_cache();
    }
}

fn write_and_prime(config_path: &Path, raw_value: &Value) {
    std::fs::write(
        config_path,
        serde_json::to_string(raw_value).expect("serialize fixture config"),
    )
    .expect("write fixture config file");

    let (raw, value) = crate::config::load_config_pair_uncached(config_path)
        .expect("load_config_pair_uncached on fixture file");
    crate::config::update_cache(raw, value);
}
