use parking_lot::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use wasmtime::{Config, Engine};

use crate::thread_util::{
    spawn_named_thread, spawn_startup_named_thread_with_spawner, NamedThreadSpawner,
};
use crate::StartupThreadSpawnError;

pub(crate) const EPOCH_TICKER_THREAD_NAME: &str = "plugin-epoch-ticker";

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
    static ENGINE: OnceLock<Result<Engine, String>> = OnceLock::new();
    match ENGINE.get_or_init(build_plugin_engine) {
        Ok(engine) => Ok(engine),
        Err(message) => Err(message.clone()),
    }
}

pub(crate) struct PluginEngine {
    engine: Engine,
    epoch_ticker: Mutex<Option<Arc<EpochTicker>>>,
}

impl PluginEngine {
    pub(crate) fn for_runtime() -> Result<Arc<Self>, String> {
        Ok(Arc::new(Self {
            engine: build_plugin_engine()?,
            epoch_ticker: Mutex::new(None),
        }))
    }

    pub(crate) fn engine(&self) -> &Engine {
        &self.engine
    }

    pub(crate) fn ensure_epoch_ticker<F, E>(
        &self,
        interval: Duration,
        factory: F,
    ) -> Result<Arc<EpochTicker>, E>
    where
        F: FnOnce(Engine, Duration) -> Result<EpochTicker, E>,
    {
        let mut ticker = self.epoch_ticker.lock();
        if let Some(existing) = ticker.as_ref() {
            return Ok(existing.clone());
        }

        let created = Arc::new(factory(self.engine.clone(), interval)?);
        *ticker = Some(created.clone());
        Ok(created)
    }
}

impl Default for PluginEngine {
    fn default() -> Self {
        Self {
            engine: build_plugin_engine().expect("plugin engine should initialize"),
            epoch_ticker: Mutex::new(None),
        }
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

    pub(crate) fn start_with_spawner(
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
