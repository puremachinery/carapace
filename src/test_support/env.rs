use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::ffi::{OsStr, OsString};

use parking_lot::{Mutex, MutexGuard};

static TEST_ENV_LOCK: Mutex<()> = parking_lot::const_mutex(());

/// Scoped process-env mutation helper for tests.
///
/// This holds a global mutex for the lifetime of the helper so env-sensitive
/// tests cannot race each other across modules.
///
/// Under the current `parking_lot` configuration this guard is not `Send`, so
/// async tests on a multi-thread runtime should not hold it across an `.await`.
pub(crate) struct ScopedEnv {
    _lock: MutexGuard<'static, ()>,
    original_values: HashMap<OsString, Option<OsString>>,
    mutation_order: Vec<OsString>,
}

impl ScopedEnv {
    pub(crate) fn new() -> Self {
        Self {
            _lock: TEST_ENV_LOCK.lock(),
            original_values: HashMap::new(),
            mutation_order: Vec::new(),
        }
    }

    pub(crate) fn set<K, V>(&mut self, key: K, value: V) -> &mut Self
    where
        K: AsRef<OsStr>,
        V: AsRef<OsStr>,
    {
        let key = self.record_original(key.as_ref());
        std::env::set_var(&key, value);
        self
    }

    pub(crate) fn unset<K>(&mut self, key: K) -> &mut Self
    where
        K: AsRef<OsStr>,
    {
        let key = self.record_original(key.as_ref());
        std::env::remove_var(&key);
        self
    }

    fn record_original(&mut self, key: &OsStr) -> OsString {
        let key = key.to_os_string();
        match self.original_values.entry(key.clone()) {
            Entry::Occupied(_) => {}
            Entry::Vacant(entry) => {
                self.mutation_order.push(key.clone());
                entry.insert(std::env::var_os(&key));
            }
        }
        key
    }
}

impl Drop for ScopedEnv {
    fn drop(&mut self) {
        for key in self.mutation_order.iter().rev() {
            match self.original_values.remove(key).flatten() {
                Some(value) => std::env::set_var(key, value),
                None => std::env::remove_var(key),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ScopedEnv;
    use std::ffi::OsString;

    const TEST_KEY: &str = "CARAPACE_TEST_SCOPED_ENV_VALUE";
    const MISSING_KEY: &str = "CARAPACE_TEST_SCOPED_ENV_MISSING";
    const REUSE_KEY: &str = "CARAPACE_TEST_SCOPED_ENV_REUSE";

    struct SeededEnvVar {
        key: &'static str,
        original: Option<OsString>,
    }

    impl SeededEnvVar {
        fn set(key: &'static str, value: &str) -> Self {
            let original = std::env::var_os(key);
            std::env::set_var(key, value);
            Self { key, original }
        }

        fn unset(key: &'static str) -> Self {
            let original = std::env::var_os(key);
            std::env::remove_var(key);
            Self { key, original }
        }
    }

    impl Drop for SeededEnvVar {
        fn drop(&mut self) {
            match self.original.take() {
                Some(value) => std::env::set_var(self.key, value),
                None => std::env::remove_var(self.key),
            }
        }
    }

    #[test]
    fn test_scoped_env_restores_original_value_after_drop() {
        let _seed = SeededEnvVar::set(TEST_KEY, "original");

        {
            let mut env_guard = ScopedEnv::new();
            env_guard.set(TEST_KEY, "updated");
            assert_eq!(std::env::var_os(TEST_KEY), Some(OsString::from("updated")));
        }

        assert_eq!(std::env::var_os(TEST_KEY), Some(OsString::from("original")));
    }

    #[test]
    fn test_scoped_env_restores_missing_value_after_set() {
        let _seed = SeededEnvVar::unset(MISSING_KEY);

        {
            let mut env_guard = ScopedEnv::new();
            env_guard.set(MISSING_KEY, "temporary");
            assert_eq!(
                std::env::var_os(MISSING_KEY),
                Some(OsString::from("temporary"))
            );
        }

        assert_eq!(std::env::var_os(MISSING_KEY), None);
    }

    #[test]
    fn test_scoped_env_preserves_first_original_across_unset_and_reset() {
        let _seed = SeededEnvVar::set(REUSE_KEY, "original");

        {
            let mut env_guard = ScopedEnv::new();
            env_guard.unset(REUSE_KEY);
            assert_eq!(std::env::var_os(REUSE_KEY), None);

            env_guard.set(REUSE_KEY, "temporary");
            assert_eq!(
                std::env::var_os(REUSE_KEY),
                Some(OsString::from("temporary"))
            );
        }

        assert_eq!(
            std::env::var_os(REUSE_KEY),
            Some(OsString::from("original"))
        );
    }
}
