use std::{any::Any, fmt::Display, future::Future, thread};

use tokio::{
    runtime::{Builder, Handle, RuntimeFlavor},
    task::block_in_place,
};

pub const CURRENT_THREAD_RUNTIME_MESSAGE: &str =
    "cannot run blocking sync-async bridge from current-thread runtime";

#[derive(Debug)]
pub enum BridgeError<E> {
    CurrentThreadRuntime,
    RuntimeCreate(String),
    WorkerPanicked(String),
    Inner(E),
}

impl<E> BridgeError<E> {
    pub fn is_current_thread_runtime(&self) -> bool {
        matches!(self, Self::CurrentThreadRuntime)
    }
}

impl<E: Display> std::fmt::Display for BridgeError<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CurrentThreadRuntime => write!(f, "{}", CURRENT_THREAD_RUNTIME_MESSAGE),
            Self::RuntimeCreate(msg) => write!(f, "{}", msg),
            Self::WorkerPanicked(msg) => write!(f, "async runtime bridge worker panicked: {}", msg),
            Self::Inner(err) => write!(f, "{}", err),
        }
    }
}

/// Run a sync-facing async boundary when the future is not required to be `Send`.
///
/// - If running inside a multi-threaded Tokio runtime, uses `block_in_place` + `Handle::block_on`.
/// - If no runtime exists, creates a temporary current-thread runtime.
/// - If running inside a current-thread runtime, returns an explicit error.
pub fn run_sync_blocking<T, E>(
    future: impl Future<Output = Result<T, E>>,
) -> Result<T, BridgeError<E>>
where
    E: Display,
{
    if let Ok(handle) = Handle::try_current() {
        if handle.runtime_flavor() == RuntimeFlavor::MultiThread {
            return block_in_place(|| handle.block_on(future).map_err(BridgeError::Inner));
        }
        return Err(BridgeError::CurrentThreadRuntime);
    }

    run_in_current_thread_runtime(future)
}

/// Run a sync-facing async boundary when the future can be moved across threads.
///
/// This helper uses the multi-threaded fast path when available and a dedicated
/// worker thread when called inside a current-thread runtime to avoid hard panics.
pub fn run_sync_blocking_send<T, E>(
    future: impl Future<Output = Result<T, E>> + Send + 'static,
) -> Result<T, BridgeError<E>>
where
    T: Send + 'static,
    E: Display + Send + 'static,
{
    if let Ok(handle) = Handle::try_current() {
        if handle.runtime_flavor() == RuntimeFlavor::MultiThread {
            return block_in_place(|| handle.block_on(future).map_err(BridgeError::Inner));
        }
        return run_in_spawned_runtime(future);
    }

    run_in_current_thread_runtime(future)
}

fn run_in_spawned_runtime<T, E>(
    future: impl Future<Output = Result<T, E>> + Send + 'static,
) -> Result<T, BridgeError<E>>
where
    T: Send + 'static,
    E: Display + Send + 'static,
{
    let handle = thread::spawn(move || run_in_current_thread_runtime(future));

    match handle.join() {
        Ok(result) => result,
        Err(payload) => Err(BridgeError::WorkerPanicked(panic_to_string(payload))),
    }
}

fn run_in_current_thread_runtime<T, E>(
    future: impl Future<Output = Result<T, E>>,
) -> Result<T, BridgeError<E>>
where
    E: Display,
{
    Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| BridgeError::RuntimeCreate(format!("failed to create runtime: {e}")))?
        .block_on(future)
        .map_err(BridgeError::Inner)
}

fn panic_to_string(payload: Box<dyn Any + Send>) -> String {
    if let Some(message) = payload.downcast_ref::<&'static str>() {
        (*message).to_string()
    } else if let Some(message) = payload.downcast_ref::<String>() {
        message.clone()
    } else {
        "unknown panic payload".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::{run_sync_blocking, run_sync_blocking_send, BridgeError};

    #[test]
    fn run_sync_blocking_outside_runtime() {
        let value = run_sync_blocking(async { Ok::<u16, std::io::Error>(17) }).unwrap();
        assert_eq!(value, 17);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn run_sync_blocking_inside_multi_thread_runtime() {
        let value = run_sync_blocking(async { Ok::<u16, std::io::Error>(99) }).unwrap();
        assert_eq!(value, 99);
    }

    #[test]
    fn run_sync_blocking_inside_current_thread_runtime_returns_error() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let err = rt.block_on(async {
            run_sync_blocking(async { Ok::<u16, std::io::Error>(11) })
                .expect_err("current-thread runtime should return an explicit error")
        });
        assert!(matches!(err, BridgeError::CurrentThreadRuntime));
    }

    #[test]
    fn run_sync_blocking_send_outside_runtime_works() {
        let value = run_sync_blocking_send(async { Ok::<u16, std::io::Error>(22) }).unwrap();
        assert_eq!(value, 22);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn run_sync_blocking_send_inside_multi_thread_runtime_works() {
        let value = run_sync_blocking_send(async { Ok::<u16, std::io::Error>(33) }).unwrap();
        assert_eq!(value, 33);
    }

    #[test]
    fn run_sync_blocking_send_inside_current_thread_runtime_works() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let value = rt.block_on(async {
            run_sync_blocking_send(async { Ok::<u16, std::io::Error>(44) }).unwrap()
        });
        assert_eq!(value, 44);
    }
}
