use std::collections::{HashMap, HashSet};
use std::ffi::{OsStr, OsString};

use parking_lot::{Mutex, MutexGuard};

static TEST_ENV_LOCK: Mutex<()> = parking_lot::const_mutex(());

/// Scoped process-env mutation helper for tests.
///
/// This holds a global mutex for the lifetime of the helper so env-sensitive
/// tests cannot race each other across modules.
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
        self.original_values
            .entry(key.clone())
            .or_insert_with(|| std::env::var_os(&key));
        self.mutation_order.push(key.clone());
        key
    }
}

impl Drop for ScopedEnv {
    fn drop(&mut self) {
        let mut restored = HashSet::new();
        for key in self.mutation_order.iter().rev() {
            if !restored.insert(key.clone()) {
                continue;
            }

            match self.original_values.remove(key).flatten() {
                Some(value) => std::env::set_var(key, value),
                None => std::env::remove_var(key),
            }
        }
    }
}
