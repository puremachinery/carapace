use std::io;
use std::thread;

use thiserror::Error;

pub(crate) type NamedThreadRoutine = Box<dyn FnOnce() + Send + 'static>;
pub(crate) type NamedThreadSpawner =
    fn(thread::Builder, NamedThreadRoutine) -> io::Result<thread::JoinHandle<()>>;

pub(crate) fn spawn_named_thread(
    builder: thread::Builder,
    routine: NamedThreadRoutine,
) -> io::Result<thread::JoinHandle<()>> {
    builder.spawn(routine)
}

#[derive(Debug, Error)]
#[error("failed to spawn startup thread '{thread_name}': {source}")]
pub struct StartupThreadSpawnError {
    thread_name: &'static str,
    #[source]
    source: io::Error,
}

impl StartupThreadSpawnError {
    pub(crate) fn new(thread_name: &'static str, source: io::Error) -> Self {
        Self {
            thread_name,
            source,
        }
    }

    pub fn thread_name(&self) -> &'static str {
        self.thread_name
    }
}

pub(crate) fn spawn_startup_named_thread_with_spawner(
    thread_name: &'static str,
    routine: NamedThreadRoutine,
    spawner: NamedThreadSpawner,
) -> Result<thread::JoinHandle<()>, StartupThreadSpawnError> {
    spawner(
        thread::Builder::new().name(thread_name.to_string()),
        routine,
    )
    .map_err(|source| StartupThreadSpawnError::new(thread_name, source))
}
