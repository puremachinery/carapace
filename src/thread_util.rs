use std::io;
use std::thread;

pub(crate) type NamedThreadRoutine = Box<dyn FnOnce() + Send + 'static>;
pub(crate) type NamedThreadSpawner =
    fn(thread::Builder, NamedThreadRoutine) -> io::Result<thread::JoinHandle<()>>;

pub(crate) fn spawn_named_thread(
    builder: thread::Builder,
    routine: NamedThreadRoutine,
) -> io::Result<thread::JoinHandle<()>> {
    builder.spawn(routine)
}
