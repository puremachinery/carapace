use parking_lot::{Condvar, Mutex};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock, Weak};
use std::time::Duration;
use wasmtime::{Config, Engine};

use crate::thread_util::{
    spawn_named_thread, spawn_startup_named_thread_with_spawner, NamedThreadSpawner,
};
use crate::StartupThreadSpawnError;

pub(crate) const EPOCH_TICKER_THREAD_NAME: &str = "plugin-epoch-ticker";

fn normalize_epoch_ticker_interval(interval: Duration) -> Duration {
    interval.max(Duration::from_millis(1))
}

// Single source of truth for plugin engine configuration. Standalone
// validation, loader compilation, and runtime instantiation must stay aligned
// so install-time validation matches the engine later used for cached
// component compilation and execution.
fn plugin_engine_config() -> Config {
    let mut config = Config::new();
    config.wasm_component_model(true);
    config.consume_fuel(true);
    config.epoch_interruption(true);
    config
}

fn build_plugin_engine() -> Result<Engine, String> {
    Engine::new(&plugin_engine_config()).map_err(|e| e.to_string())
}

// Standalone validation may happen before the loader/runtime pair exists
// (for example during plugin install/update handling), so it uses a shared
// fallback engine configured identically to the runtime engine.
pub(crate) fn shared_component_validation_engine() -> Result<&'static Engine, String> {
    static ENGINE: OnceLock<Engine> = OnceLock::new();
    static INIT_LOCK: Mutex<()> = Mutex::new(());
    get_or_init_shared_engine(&ENGINE, &INIT_LOCK, build_plugin_engine)
}

fn get_or_init_shared_engine<'a, F>(
    engine_cell: &'a OnceLock<Engine>,
    init_lock: &'a Mutex<()>,
    init: F,
) -> Result<&'a Engine, String>
where
    F: FnOnce() -> Result<Engine, String>,
{
    if let Some(engine) = engine_cell.get() {
        return Ok(engine);
    }

    // `OnceLock::get_or_try_init` would express this more directly, but it is
    // still unstable in the toolchain used here. We serialize first-use
    // initialization so only one expensive `Engine::new` runs at a time, while
    // still caching only successful construction so transient failures retry.
    let _init_guard = init_lock.lock();
    if let Some(engine) = engine_cell.get() {
        return Ok(engine);
    }

    let engine = init()?;
    match engine_cell.set(engine) {
        Ok(()) => {}
        Err(_) => unreachable!(
            "OnceLock::set cannot fail while init_lock is held and cell is confirmed empty"
        ),
    }

    Ok(engine_cell
        .get()
        .expect("engine must be set after successful OnceLock::set or concurrent set"))
}

#[derive(Debug)]
pub(crate) enum EnsureEpochTickerError<E> {
    IntervalMismatch {
        existing: Duration,
        requested: Duration,
    },
    Start(E),
}

struct EpochTickerState {
    interval: Duration,
    ticker: Weak<EpochTicker>,
}

enum EpochTickerSlot {
    Starting { interval: Duration },
    Ready(EpochTickerState),
}

struct StartingTickerGuard<'a> {
    slot: &'a Mutex<Option<EpochTickerSlot>>,
    ready: &'a Condvar,
}

impl Drop for StartingTickerGuard<'_> {
    fn drop(&mut self) {
        let mut slot = self.slot.lock();
        if matches!(slot.as_ref(), Some(EpochTickerSlot::Starting { .. })) {
            *slot = None;
            self.ready.notify_all();
        }
    }
}

pub(crate) struct PluginEngine {
    engine: Engine,
    epoch_ticker: Mutex<Option<EpochTickerSlot>>,
    epoch_ticker_ready: Condvar,
}

impl PluginEngine {
    pub(crate) fn for_runtime() -> Result<Arc<Self>, String> {
        Ok(Arc::new(Self {
            engine: build_plugin_engine()?,
            epoch_ticker: Mutex::new(None),
            epoch_ticker_ready: Condvar::new(),
        }))
    }

    pub(crate) fn engine(&self) -> &Engine {
        &self.engine
    }

    /// Ensure there is a live epoch ticker for this engine.
    ///
    /// Interval mismatches are rejected only while a ticker is still live and
    /// shared by current runtime holders. Once the last `Arc<EpochTicker>` is
    /// dropped, the next caller starts a fresh ticker and may choose a new
    /// interval. Mismatches against an in-flight `Starting` slot also return
    /// immediately; callers that still want a different interval after that
    /// startup fails or panics must schedule their own retry after receiving
    /// `EnsureEpochTickerError::IntervalMismatch`.
    pub(crate) fn ensure_epoch_ticker<F, E>(
        &self,
        interval: Duration,
        factory: F,
    ) -> Result<Arc<EpochTicker>, EnsureEpochTickerError<E>>
    where
        F: FnOnce(Engine, Duration) -> Result<EpochTicker, E>,
    {
        let interval = normalize_epoch_ticker_interval(interval);
        let mut ticker = self.epoch_ticker.lock();
        loop {
            match ticker.as_ref() {
                Some(EpochTickerSlot::Ready(existing)) => {
                    let existing_interval = existing.interval;
                    if let Some(existing_ticker) = existing.ticker.upgrade() {
                        if existing_interval != interval {
                            return Err(EnsureEpochTickerError::IntervalMismatch {
                                existing: existing_interval,
                                requested: interval,
                            });
                        }
                        return Ok(existing_ticker);
                    }
                    *ticker = None;
                }
                Some(EpochTickerSlot::Starting {
                    interval: existing_interval,
                }) => {
                    let existing_interval = *existing_interval;
                    if existing_interval != interval {
                        // Mismatches against an in-flight startup are reported
                        // immediately. If that startup later fails or panics,
                        // `StartingTickerGuard` clears the slot back to `None`,
                        // and callers that still want a different interval may
                        // retry against the now-empty slot.
                        return Err(EnsureEpochTickerError::IntervalMismatch {
                            existing: existing_interval,
                            requested: interval,
                        });
                    }
                    self.epoch_ticker_ready.wait(&mut ticker);
                }
                None => {
                    *ticker = Some(EpochTickerSlot::Starting { interval });
                    break;
                }
            }
        }

        drop(ticker);
        let starting_guard = StartingTickerGuard {
            slot: &self.epoch_ticker,
            ready: &self.epoch_ticker_ready,
        };
        let created = match factory(self.engine.clone(), interval) {
            Ok(ticker) => Arc::new(ticker),
            Err(error) => return Err(EnsureEpochTickerError::Start(error)),
        };

        let mut ticker = self.epoch_ticker.lock();
        *ticker = Some(EpochTickerSlot::Ready(EpochTickerState {
            interval,
            ticker: Arc::downgrade(&created),
        }));
        self.epoch_ticker_ready.notify_all();
        drop(ticker);
        drop(starting_guard);
        Ok(created)
    }
}

pub(crate) struct EpochTicker {
    stop: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl EpochTicker {
    fn routine(
        engine: Engine,
        interval: Duration,
        stop: Arc<AtomicBool>,
    ) -> crate::thread_util::NamedThreadRoutine {
        Box::new(move || {
            while !stop.load(Ordering::SeqCst) {
                std::thread::sleep(interval);
                engine.increment_epoch();
            }
        })
    }

    pub(crate) fn start(
        engine: Engine,
        interval: Duration,
    ) -> Result<Self, StartupThreadSpawnError> {
        Self::start_with_spawner(engine, interval, spawn_named_thread)
    }

    fn start_with_spawner(
        engine: Engine,
        interval: Duration,
        spawner: NamedThreadSpawner,
    ) -> Result<Self, StartupThreadSpawnError> {
        let stop = Arc::new(AtomicBool::new(false));
        let handle = spawn_startup_named_thread_with_spawner(
            EPOCH_TICKER_THREAD_NAME,
            Self::routine(engine, interval, Arc::clone(&stop)),
            spawner,
        )?;

        Ok(Self {
            stop,
            handle: Some(handle),
        })
    }
}

impl Drop for EpochTicker {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugins::runtime::DEFAULT_EPOCH_TICK_INTERVAL;
    use std::error::Error;
    use std::io;
    use std::panic::AssertUnwindSafe;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn ensure_epoch_ticker_rejects_mismatched_interval_requests() {
        let plugin_engine = PluginEngine::for_runtime().expect("plugin engine");

        let first = plugin_engine
            .ensure_epoch_ticker(Duration::ZERO, |_engine, _interval| {
                Ok::<EpochTicker, ()>(EpochTicker {
                    stop: Arc::new(AtomicBool::new(false)),
                    handle: None,
                })
            })
            .expect("first ticker request should succeed");

        let err = match plugin_engine.ensure_epoch_ticker(
            Duration::from_millis(2),
            |_engine, _interval| {
                Ok::<EpochTicker, ()>(EpochTicker {
                    stop: Arc::new(AtomicBool::new(false)),
                    handle: None,
                })
            },
        ) {
            Ok(_) => panic!("mismatched interval should be rejected"),
            Err(err) => err,
        };

        assert!(matches!(
            err,
            EnsureEpochTickerError::IntervalMismatch {
                existing,
                requested,
            } if existing == Duration::from_millis(1)
                && requested == Duration::from_millis(2)
        ));

        drop(first);
    }

    #[test]
    fn ensure_epoch_ticker_allows_interval_change_after_last_runtime_reference_drops() {
        let plugin_engine = PluginEngine::for_runtime().expect("plugin engine");
        let starts = AtomicUsize::new(0);

        let first = plugin_engine
            .ensure_epoch_ticker(Duration::from_millis(1), |_engine, _interval| {
                starts.fetch_add(1, Ordering::SeqCst);
                Ok::<EpochTicker, ()>(EpochTicker {
                    stop: Arc::new(AtomicBool::new(false)),
                    handle: None,
                })
            })
            .expect("first ticker start should succeed");

        let second = plugin_engine
            .ensure_epoch_ticker(Duration::from_millis(1), |_engine, _interval| {
                starts.fetch_add(1, Ordering::SeqCst);
                Ok::<EpochTicker, ()>(EpochTicker {
                    stop: Arc::new(AtomicBool::new(false)),
                    handle: None,
                })
            })
            .expect("concurrent ticker reuse should succeed");

        assert!(Arc::ptr_eq(&first, &second));
        assert_eq!(starts.load(Ordering::SeqCst), 1);

        drop(first);
        drop(second);

        let third = plugin_engine
            .ensure_epoch_ticker(Duration::from_millis(2), |_engine, interval| {
                starts.fetch_add(1, Ordering::SeqCst);
                assert_eq!(interval, Duration::from_millis(2));
                Ok::<EpochTicker, ()>(EpochTicker {
                    stop: Arc::new(AtomicBool::new(false)),
                    handle: None,
                })
            })
            .expect("ticker should restart after all runtime references drop");

        assert_eq!(starts.load(Ordering::SeqCst), 2);
        drop(third);
    }

    #[test]
    fn epoch_ticker_start_reports_thread_spawn_error() {
        fn fail_spawner(
            _builder: std::thread::Builder,
            routine: crate::thread_util::NamedThreadRoutine,
        ) -> io::Result<std::thread::JoinHandle<()>> {
            drop(routine);
            Err(io::Error::other("simulated epoch ticker thread exhaustion"))
        }

        let engine = Engine::default();
        let err = match EpochTicker::start_with_spawner(
            engine,
            DEFAULT_EPOCH_TICK_INTERVAL,
            fail_spawner,
        ) {
            Ok(_) => panic!("epoch ticker startup should report thread spawn failure"),
            Err(err) => err,
        };

        let io_source = err
            .source()
            .expect("thread spawn error should preserve the original io::Error source");
        let io_error = io_source
            .downcast_ref::<io::Error>()
            .expect("thread spawn error source should remain an io::Error");

        assert_eq!(io_error.kind(), io::ErrorKind::Other);
        assert_eq!(err.thread_name(), EPOCH_TICKER_THREAD_NAME);
        assert!(err
            .to_string()
            .contains("simulated epoch ticker thread exhaustion"));
    }

    #[test]
    fn shared_validation_engine_retries_after_failed_initialization() {
        let engine_cell = OnceLock::new();
        let init_lock = Mutex::new(());
        let attempts = AtomicUsize::new(0);

        let first_err = match get_or_init_shared_engine(&engine_cell, &init_lock, || {
            attempts.fetch_add(1, Ordering::SeqCst);
            Err("transient init failure".to_string())
        }) {
            Ok(_) => panic!("first shared engine initialization should fail"),
            Err(err) => err,
        };

        assert_eq!(first_err, "transient init failure");
        assert!(engine_cell.get().is_none());
        assert_eq!(attempts.load(Ordering::SeqCst), 1);

        let engine = get_or_init_shared_engine(&engine_cell, &init_lock, || {
            attempts.fetch_add(1, Ordering::SeqCst);
            build_plugin_engine()
        })
        .expect("second shared engine initialization should retry and succeed");

        assert!(std::ptr::eq(
            engine,
            engine_cell
                .get()
                .expect("successful init should cache the engine")
        ));
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn shared_validation_engine_serializes_concurrent_first_use() {
        let engine_cell = OnceLock::new();
        let init_lock = Mutex::new(());
        let attempts = AtomicUsize::new(0);

        std::thread::scope(|scope| {
            let mut joins = Vec::new();
            for _ in 0..8 {
                joins.push(scope.spawn(|| {
                    get_or_init_shared_engine(&engine_cell, &init_lock, || {
                        attempts.fetch_add(1, Ordering::SeqCst);
                        build_plugin_engine()
                    })
                    .expect("concurrent initialization should succeed")
                        as *const Engine as usize
                }));
            }

            let first = joins
                .pop()
                .expect("at least one join handle")
                .join()
                .expect("first thread should succeed");
            for join in joins {
                let engine = join.join().expect("thread should succeed");
                assert_eq!(engine, first);
            }
        });

        assert_eq!(
            attempts.load(Ordering::SeqCst),
            1,
            "only one thread should run the expensive engine initializer"
        );
    }

    #[test]
    fn ensure_epoch_ticker_serializes_concurrent_creation() {
        let plugin_engine = PluginEngine::for_runtime().expect("plugin engine");
        let attempts = AtomicUsize::new(0);
        let release = AtomicBool::new(false);

        std::thread::scope(|scope| {
            let mut joins = Vec::new();
            for _ in 0..8 {
                joins.push(scope.spawn(|| {
                    plugin_engine
                        .ensure_epoch_ticker(Duration::from_millis(1), |_engine, _interval| {
                            attempts.fetch_add(1, Ordering::SeqCst);
                            while !release.load(Ordering::SeqCst) {
                                std::hint::spin_loop();
                            }
                            Ok::<EpochTicker, ()>(EpochTicker {
                                stop: Arc::new(AtomicBool::new(false)),
                                handle: None,
                            })
                        })
                        .expect("concurrent ticker initialization should succeed")
                }));
            }

            while attempts.load(Ordering::SeqCst) == 0 {
                std::hint::spin_loop();
            }
            release.store(true, Ordering::SeqCst);

            let first = joins
                .pop()
                .expect("at least one join handle")
                .join()
                .expect("first thread should succeed");
            for join in joins {
                let ticker = join.join().expect("thread should succeed");
                assert!(Arc::ptr_eq(&ticker, &first));
            }
        });

        assert_eq!(
            attempts.load(Ordering::SeqCst),
            1,
            "only one ticker factory should run for concurrent same-interval requests"
        );
    }

    #[test]
    fn ensure_epoch_ticker_clears_starting_slot_after_factory_panic() {
        let plugin_engine = PluginEngine::for_runtime().expect("plugin engine");

        let panic_result = std::panic::catch_unwind(AssertUnwindSafe(|| {
            let _ = plugin_engine.ensure_epoch_ticker(
                Duration::from_millis(1),
                |_engine, _interval| {
                    panic!("simulated ticker startup panic");
                    #[allow(unreachable_code)]
                    Ok::<EpochTicker, ()>(EpochTicker {
                        stop: Arc::new(AtomicBool::new(false)),
                        handle: None,
                    })
                },
            );
        }));
        assert!(panic_result.is_err());

        let (tx, rx) = std::sync::mpsc::channel();
        let plugin_engine = Arc::clone(&plugin_engine);
        let join = std::thread::spawn(move || {
            let result = plugin_engine.ensure_epoch_ticker(
                Duration::from_millis(1),
                |_engine, _interval| {
                    Ok::<EpochTicker, ()>(EpochTicker {
                        stop: Arc::new(AtomicBool::new(false)),
                        handle: None,
                    })
                },
            );
            tx.send(result.is_ok()).expect("send result");
        });

        assert_eq!(
            rx.recv_timeout(Duration::from_secs(1)),
            Ok(true),
            "subsequent callers should not block forever after a startup panic"
        );
        join.join().expect("join waiter thread");
    }

    #[test]
    fn ensure_epoch_ticker_clears_starting_slot_after_factory_error() {
        let plugin_engine = PluginEngine::for_runtime().expect("plugin engine");

        let err = match plugin_engine
            .ensure_epoch_ticker(Duration::from_millis(1), |_engine, _interval| {
                Err::<EpochTicker, _>("simulated ticker startup error")
            }) {
            Ok(_) => panic!("ticker startup error should be returned"),
            Err(err) => err,
        };
        assert!(matches!(
            err,
            EnsureEpochTickerError::Start("simulated ticker startup error")
        ));

        let (tx, rx) = std::sync::mpsc::channel();
        let plugin_engine = Arc::clone(&plugin_engine);
        let join = std::thread::spawn(move || {
            let result = plugin_engine.ensure_epoch_ticker(
                Duration::from_millis(1),
                |_engine, _interval| {
                    Ok::<EpochTicker, &str>(EpochTicker {
                        stop: Arc::new(AtomicBool::new(false)),
                        handle: None,
                    })
                },
            );
            tx.send(result.is_ok()).expect("send result");
        });

        assert_eq!(
            rx.recv_timeout(Duration::from_secs(1)),
            Ok(true),
            "subsequent callers should not block forever after a startup error"
        );
        join.join().expect("join waiter thread");
    }
}
