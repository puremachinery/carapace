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
    pub const fn is_current_thread_runtime(&self) -> bool {
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

#[cfg(test)]
/// Run a synchronous blocking operation from code that may be inside a Tokio runtime.
///
/// - If running inside a multi-threaded Tokio runtime, uses `block_in_place`.
/// - If running inside a current-thread Tokio runtime, hands the work to a
///   dedicated OS thread and synchronously waits for it to finish.
/// - If no runtime exists, runs the work inline.
pub fn run_blocking_value<T>(work: impl FnOnce() -> T + Send + 'static) -> T
where
    T: Send + 'static,
{
    match Handle::try_current() {
        Ok(handle) if handle.runtime_flavor() == RuntimeFlavor::MultiThread => block_in_place(work),
        Ok(_) => match thread::spawn(work).join() {
            Ok(value) => value,
            Err(payload) => std::panic::resume_unwind(payload),
        },
        Err(_) => work(),
    }
}

/// Sleep `duration` while yielding the calling tokio worker on a multi-thread
/// runtime.
///
/// Sync code that retries a blocking primitive (flock with backoff, etc.)
/// would otherwise pin the calling tokio worker for the full `sleep`
/// duration. On a multi-thread runtime, route the sleep through
/// `block_in_place` so the scheduler can migrate the worker's queued
/// tasks before it parks; on the current-thread runtime or outside any
/// tokio runtime, fall back to a plain `thread::sleep` because there
/// are no other tasks that could benefit from migration.
///
/// Centralised in this module so the runtime-bridge guard
/// (`scripts/check-runtime-bridge-usage.sh`) has a single audited home
/// for `block_in_place`; callers must not invoke `block_in_place`
/// directly from non-allowlisted modules.
pub fn cooperative_blocking_sleep(duration: std::time::Duration) {
    if matches!(
        Handle::try_current().map(|h| h.runtime_flavor()),
        Ok(RuntimeFlavor::MultiThread)
    ) {
        block_in_place(|| thread::sleep(duration));
    } else {
        thread::sleep(duration);
    }
}

/// Run a synchronous closure that may park briefly (e.g. acquiring a
/// `std::sync::Mutex`), yielding the calling tokio worker on a
/// multi-thread runtime so the scheduler can migrate queued tasks.
///
/// Same trade-off as `cooperative_blocking_sleep` — exists in the
/// runtime-bridge module so the guard at
/// `scripts/check-runtime-bridge-usage.sh` only has to vet one
/// `block_in_place` use site. Callers should reach for this when the
/// inner work is short and non-await (a lock, a quick syscall, a small
/// hash); for long blocking work use `spawn_blocking` instead.
pub fn cooperative_blocking_call<F, R>(f: F) -> R
where
    F: FnOnce() -> R,
{
    if matches!(
        Handle::try_current().map(|h| h.runtime_flavor()),
        Ok(RuntimeFlavor::MultiThread)
    ) {
        block_in_place(f)
    } else {
        f()
    }
}

/// Run a best-effort drop-time cleanup closure from code that may be dropped inside a Tokio runtime.
///
/// This helper is only for `Drop` paths where cleanup cannot `await` and any error handling must
/// happen inside the closure itself.
///
/// - If running inside a multi-threaded Tokio runtime, uses `block_in_place` so the scheduler can
///   compensate for the blocking section while the cleanup still completes before `Drop` returns.
/// - If running inside a current-thread Tokio runtime, hands the cleanup to a dedicated OS thread
///   and synchronously waits for it to finish so `Drop` still has deterministic completion
///   semantics without re-entering Tokio. If that helper thread panics, we log it instead of
///   re-raising, because this helper is used from `Drop` paths where propagating a panic could
///   trigger a process-aborting double panic.
/// - If no runtime exists, runs the cleanup inline.
pub fn run_blocking_cleanup(cleanup: impl FnOnce() + Send + 'static) {
    match Handle::try_current() {
        Ok(handle) if handle.runtime_flavor() == RuntimeFlavor::MultiThread => {
            block_in_place(cleanup)
        }
        Ok(_) => {
            let handle = thread::spawn(cleanup);
            if let Err(payload) = handle.join() {
                eprintln!(
                    "Warning: blocking cleanup helper thread panicked: {}",
                    panic_to_string(payload)
                );
            }
        }
        Err(_) => cleanup(),
    }
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
    use super::{
        cooperative_blocking_call, cooperative_blocking_sleep, run_blocking_cleanup,
        run_blocking_value, run_sync_blocking, run_sync_blocking_send, BridgeError,
    };
    use std::sync::{
        atomic::{AtomicU16, Ordering},
        Arc, Mutex,
    };
    use std::time::Duration;

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

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn run_blocking_cleanup_inside_multi_thread_runtime_works() {
        let value = Arc::new(AtomicU16::new(0));
        let written = value.clone();
        run_blocking_cleanup(move || {
            written.store(55, Ordering::SeqCst);
        });
        assert_eq!(value.load(Ordering::SeqCst), 55);
    }

    #[test]
    fn run_blocking_cleanup_outside_runtime_works() {
        let value = Arc::new(AtomicU16::new(0));
        let written = value.clone();
        run_blocking_cleanup(move || {
            written.store(66, Ordering::SeqCst);
        });
        assert_eq!(value.load(Ordering::SeqCst), 66);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn run_blocking_cleanup_inside_current_thread_runtime_works() {
        let caller = std::thread::current().id();
        let (tx, rx) = tokio::sync::oneshot::channel();
        run_blocking_cleanup(move || {
            let _ = tx.send(std::thread::current().id());
        });
        let cleanup_thread = tokio::time::timeout(Duration::from_secs(1), rx)
            .await
            .expect("cleanup should finish promptly")
            .expect("cleanup thread should report its thread id");
        assert_ne!(cleanup_thread, caller);
    }

    #[test]
    fn run_blocking_value_outside_runtime_works() {
        assert_eq!(run_blocking_value(|| 77_u16), 77);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn run_blocking_value_inside_multi_thread_runtime_works() {
        assert_eq!(run_blocking_value(|| 88_u16), 88);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn run_blocking_value_inside_current_thread_runtime_works() {
        let caller = std::thread::current().id();
        let (tx, rx) = tokio::sync::oneshot::channel();
        let value = run_blocking_value(move || {
            let _ = tx.send(std::thread::current().id());
            99_u16
        });
        let worker = tokio::time::timeout(Duration::from_secs(1), rx)
            .await
            .expect("blocking helper should finish promptly")
            .expect("blocking helper should report its thread id");
        assert_eq!(value, 99);
        assert_ne!(worker, caller);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn run_blocking_cleanup_inside_current_thread_runtime_swallows_cleanup_panic() {
        let result = std::panic::catch_unwind(|| {
            run_blocking_cleanup(|| panic!("simulated cleanup panic"));
        });
        assert!(result.is_ok());
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

    /// `cooperative_blocking_sleep` must finish in all three contexts the
    /// config-write retry loop can reach: non-tokio sync code (CLI), a
    /// tokio current-thread runtime (test harnesses), and a tokio
    /// multi-thread worker (production daemon). The multi-thread branch
    /// is the only one where `block_in_place` actually runs; the other
    /// two fall through to the plain `thread::sleep`. All three must
    /// observe at least the requested duration.
    #[test]
    fn cooperative_blocking_sleep_finishes_outside_runtime() {
        let start = std::time::Instant::now();
        cooperative_blocking_sleep(Duration::from_millis(1));
        assert!(start.elapsed() >= Duration::from_millis(1));
    }

    #[test]
    fn cooperative_blocking_sleep_finishes_on_current_thread_runtime() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("current-thread runtime");
        rt.block_on(async {
            let start = std::time::Instant::now();
            cooperative_blocking_sleep(Duration::from_millis(1));
            assert!(start.elapsed() >= Duration::from_millis(1));
        });
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cooperative_blocking_sleep_finishes_on_multi_thread_runtime() {
        let start = std::time::Instant::now();
        cooperative_blocking_sleep(Duration::from_millis(1));
        assert!(start.elapsed() >= Duration::from_millis(1));
    }

    /// `cooperative_blocking_call` must run its closure and return the
    /// closure's value across all three runtime contexts. Tracks both
    /// closure invocation (counter increment) and return-value
    /// pass-through, so a regression that drops either part fails
    /// loudly.
    #[test]
    fn cooperative_blocking_call_runs_closure_outside_runtime() {
        let counter = Arc::new(Mutex::new(0u32));
        let counter_clone = counter.clone();
        let value = cooperative_blocking_call(move || {
            *counter_clone.lock().unwrap() += 1;
            42u32
        });
        assert_eq!(value, 42);
        assert_eq!(*counter.lock().unwrap(), 1);
    }

    #[test]
    fn cooperative_blocking_call_runs_closure_on_current_thread_runtime() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("current-thread runtime");
        rt.block_on(async {
            let value = cooperative_blocking_call(|| 77u32);
            assert_eq!(value, 77);
        });
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cooperative_blocking_call_runs_closure_on_multi_thread_runtime() {
        let value = cooperative_blocking_call(|| 88u32);
        assert_eq!(value, 88);
    }
}
