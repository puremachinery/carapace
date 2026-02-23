//! Durable task queue primitives.
//!
//! Provides persisted task state and a worker loop for deferred/retried work.

use async_trait::async_trait;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::watch;
use tracing::warn;
use uuid::Uuid;

const MAX_TASKS: usize = 10_000;

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Durable lifecycle states for long-running task processing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskState {
    Queued,
    Running,
    Blocked,
    RetryWait,
    Done,
    Failed,
    Cancelled,
}

/// A single persisted task record.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DurableTask {
    pub id: String,
    pub state: TaskState,
    pub attempts: u32,
    pub next_run_at_ms: Option<u64>,
    pub last_error: Option<String>,
    pub payload: Value,
    pub created_at_ms: u64,
    pub updated_at_ms: u64,
}

/// Queue stats by state.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TaskQueueStats {
    pub total: usize,
    pub queued: usize,
    pub running: usize,
    pub blocked: usize,
    pub retry_wait: usize,
    pub done: usize,
    pub failed: usize,
    pub cancelled: usize,
}

/// Durable task queue with atomic on-disk persistence.
#[derive(Debug)]
pub struct TaskQueue {
    tasks: RwLock<Vec<DurableTask>>,
    persist_path: Option<PathBuf>,
    dir_ensured: AtomicBool,
}

impl TaskQueue {
    /// Create a queue. If `persist_path` is set, mutations flush to disk.
    pub fn new(persist_path: Option<PathBuf>) -> Self {
        Self {
            tasks: RwLock::new(Vec::new()),
            persist_path,
            dir_ensured: AtomicBool::new(false),
        }
    }

    /// In-memory queue for tests.
    pub fn in_memory() -> Self {
        Self::new(None)
    }

    /// Load tasks from disk and recover stale `running` entries.
    pub fn load(&self) {
        let path = match &self.persist_path {
            Some(p) => p,
            None => return,
        };

        let data = match fs::read(path) {
            Ok(bytes) => bytes,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return,
            Err(err) => {
                warn!(path = %path.display(), error = %err, "failed to read tasks file");
                return;
            }
        };

        let mut loaded: Vec<DurableTask> = match serde_json::from_slice(&data) {
            Ok(tasks) => tasks,
            Err(err) => {
                warn!(path = %path.display(), error = %err, "failed to parse tasks file");
                return;
            }
        };

        let now = now_ms();
        for task in &mut loaded {
            if task.state == TaskState::Running {
                task.state = TaskState::RetryWait;
                task.next_run_at_ms = Some(now);
                task.updated_at_ms = now;
                if task.last_error.is_none() {
                    task.last_error = Some("recovered after restart".to_string());
                }
            }
        }

        *self.tasks.write() = loaded;
    }

    /// Add a new task in `queued` state.
    pub fn enqueue(&self, payload: Value, next_run_at_ms: Option<u64>) -> DurableTask {
        let now = now_ms();
        let task = DurableTask {
            id: Uuid::new_v4().to_string(),
            state: TaskState::Queued,
            attempts: 0,
            next_run_at_ms,
            last_error: None,
            payload,
            created_at_ms: now,
            updated_at_ms: now,
        };

        {
            let mut tasks = self.tasks.write();
            if tasks.len() >= MAX_TASKS {
                // Evict oldest terminal task first.
                if let Some((idx, _)) = tasks
                    .iter()
                    .enumerate()
                    .filter(|(_, t)| {
                        matches!(
                            t.state,
                            TaskState::Done
                                | TaskState::Failed
                                | TaskState::Cancelled
                                | TaskState::Blocked
                        )
                    })
                    .min_by_key(|(_, t)| t.updated_at_ms)
                {
                    tasks.remove(idx);
                }
            }
            tasks.push(task.clone());
        }
        self.flush_to_disk();
        task
    }

    /// Get a task by ID.
    pub fn get(&self, id: &str) -> Option<DurableTask> {
        self.tasks.read().iter().find(|t| t.id == id).cloned()
    }

    /// List tasks newest-first.
    pub fn list(&self) -> Vec<DurableTask> {
        let mut tasks = self.tasks.read().clone();
        tasks.sort_by_key(|t| std::cmp::Reverse(t.updated_at_ms));
        tasks
    }

    /// Claim due tasks and move them to `running`.
    ///
    /// Claimed tasks increment `attempts`.
    pub fn claim_due(&self, now: u64, limit: usize) -> Vec<DurableTask> {
        if limit == 0 {
            return Vec::new();
        }

        let mut claimed = Vec::new();
        {
            let mut tasks = self.tasks.write();
            for task in tasks.iter_mut() {
                if claimed.len() >= limit {
                    break;
                }
                if !is_due(task, now) {
                    continue;
                }

                task.state = TaskState::Running;
                task.attempts = task.attempts.saturating_add(1);
                task.next_run_at_ms = None;
                task.updated_at_ms = now;
                claimed.push(task.clone());
            }
        }

        if !claimed.is_empty() {
            self.flush_to_disk();
        }
        claimed
    }

    /// Mark a task as done.
    pub fn mark_done(&self, id: &str) -> bool {
        self.update_task(id, |task, now| {
            task.state = TaskState::Done;
            task.last_error = None;
            task.next_run_at_ms = None;
            task.updated_at_ms = now;
        })
    }

    /// Mark a task as failed.
    pub fn mark_failed(&self, id: &str, error: &str) -> bool {
        self.update_task(id, |task, now| {
            task.state = TaskState::Failed;
            task.last_error = Some(error.to_string());
            task.next_run_at_ms = None;
            task.updated_at_ms = now;
        })
    }

    /// Mark a task as blocked.
    pub fn mark_blocked(&self, id: &str, reason: &str) -> bool {
        self.update_task(id, |task, now| {
            task.state = TaskState::Blocked;
            task.last_error = Some(reason.to_string());
            task.next_run_at_ms = None;
            task.updated_at_ms = now;
        })
    }

    /// Mark a task as cancelled.
    pub fn mark_cancelled(&self, id: &str, reason: Option<&str>) -> bool {
        self.update_task(id, |task, now| {
            task.state = TaskState::Cancelled;
            task.last_error = reason.map(ToString::to_string);
            task.next_run_at_ms = None;
            task.updated_at_ms = now;
        })
    }

    /// Mark a task for retry at `now + delay_ms`.
    pub fn mark_retry_wait(&self, id: &str, delay_ms: u64, error: &str) -> bool {
        self.update_task(id, |task, now| {
            task.state = TaskState::RetryWait;
            task.last_error = Some(error.to_string());
            task.next_run_at_ms = Some(now.saturating_add(delay_ms));
            task.updated_at_ms = now;
        })
    }

    /// Queue stats by state.
    pub fn stats(&self) -> TaskQueueStats {
        let tasks = self.tasks.read();
        let mut stats = TaskQueueStats {
            total: tasks.len(),
            ..TaskQueueStats::default()
        };
        for task in tasks.iter() {
            match task.state {
                TaskState::Queued => stats.queued += 1,
                TaskState::Running => stats.running += 1,
                TaskState::Blocked => stats.blocked += 1,
                TaskState::RetryWait => stats.retry_wait += 1,
                TaskState::Done => stats.done += 1,
                TaskState::Failed => stats.failed += 1,
                TaskState::Cancelled => stats.cancelled += 1,
            }
        }
        stats
    }

    fn update_task(&self, id: &str, mut apply: impl FnMut(&mut DurableTask, u64)) -> bool {
        let now = now_ms();
        let updated = {
            let mut tasks = self.tasks.write();
            if let Some(task) = tasks.iter_mut().find(|t| t.id == id) {
                apply(task, now);
                true
            } else {
                false
            }
        };
        if updated {
            self.flush_to_disk();
        }
        updated
    }

    fn flush_to_disk(&self) {
        let path = match &self.persist_path {
            Some(p) => p,
            None => return,
        };

        if !self.dir_ensured.load(Ordering::Relaxed) {
            if let Some(parent) = path.parent() {
                if let Err(err) = fs::create_dir_all(parent) {
                    warn!(path = %parent.display(), error = %err, "failed to create tasks dir");
                    return;
                }
            }
            self.dir_ensured.store(true, Ordering::Relaxed);
        }

        let tmp_path = {
            let mut s = path.as_os_str().to_os_string();
            s.push(".tmp");
            PathBuf::from(s)
        };

        let mut data = {
            let tasks = self.tasks.read();
            match serde_json::to_vec_pretty(&*tasks) {
                Ok(v) => v,
                Err(err) => {
                    warn!(error = %err, "failed to serialize tasks");
                    return;
                }
            }
        };
        data.push(b'\n');

        let write_result = (|| -> std::io::Result<()> {
            let mut file = File::create(&tmp_path)?;
            file.write_all(&data)?;
            file.sync_data()?;
            fs::rename(&tmp_path, path)?;
            Ok(())
        })();

        if let Err(err) = write_result {
            warn!(path = %path.display(), error = %err, "failed to flush tasks to disk");
            let _ = fs::remove_file(&tmp_path);
        }
    }
}

fn is_due(task: &DurableTask, now: u64) -> bool {
    match task.state {
        TaskState::Queued => task.next_run_at_ms.is_none_or(|ts| now >= ts),
        TaskState::RetryWait => task.next_run_at_ms.is_some_and(|ts| now >= ts),
        _ => false,
    }
}

/// Result of executing a claimed task.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaskExecutionOutcome {
    Done,
    RetryWait { delay_ms: u64, error: String },
    Blocked { reason: String },
    Failed { error: String },
    Cancelled { reason: Option<String> },
}

#[async_trait]
pub trait TaskExecutor: Send + Sync {
    async fn execute(&self, task: DurableTask) -> TaskExecutionOutcome;
}

/// Poll-and-execute worker loop for durable tasks.
pub async fn task_worker_loop(
    queue: Arc<TaskQueue>,
    executor: Arc<dyn TaskExecutor>,
    interval: Duration,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut ticker = tokio::time::interval(interval);
    loop {
        tokio::select! {
            _ = ticker.tick() => {}
            _ = shutdown.changed() => break,
        }

        if *shutdown.borrow() {
            break;
        }

        let now = now_ms();
        let due = queue.claim_due(now, 32);
        for task in due {
            let outcome = executor.execute(task.clone()).await;
            match outcome {
                TaskExecutionOutcome::Done => {
                    let _ = queue.mark_done(&task.id);
                }
                TaskExecutionOutcome::RetryWait { delay_ms, error } => {
                    let _ = queue.mark_retry_wait(&task.id, delay_ms, &error);
                }
                TaskExecutionOutcome::Blocked { reason } => {
                    let _ = queue.mark_blocked(&task.id, &reason);
                }
                TaskExecutionOutcome::Failed { error } => {
                    let _ = queue.mark_failed(&task.id, &error);
                }
                TaskExecutionOutcome::Cancelled { reason } => {
                    let _ = queue.mark_cancelled(&task.id, reason.as_deref());
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tempfile::tempdir;

    #[test]
    fn test_claim_due_marks_running_and_increments_attempts() {
        let queue = TaskQueue::in_memory();
        let task = queue.enqueue(serde_json::json!({"kind":"demo"}), Some(1));

        let claimed = queue.claim_due(10, 10);
        assert_eq!(claimed.len(), 1);
        assert_eq!(claimed[0].id, task.id);
        assert_eq!(claimed[0].state, TaskState::Running);
        assert_eq!(claimed[0].attempts, 1);
    }

    #[test]
    fn test_mark_retry_wait_tracks_next_run_and_error() {
        let queue = TaskQueue::in_memory();
        let task = queue.enqueue(serde_json::json!({"kind":"demo"}), None);
        let _ = queue.claim_due(now_ms(), 1);
        assert!(queue.mark_retry_wait(&task.id, 5_000, "temporary failure"));
        let updated = queue.get(&task.id).expect("task should exist");
        assert_eq!(updated.state, TaskState::RetryWait);
        assert_eq!(updated.last_error.as_deref(), Some("temporary failure"));
        assert!(updated.next_run_at_ms.is_some());
    }

    #[test]
    fn test_flush_and_load_round_trip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("tasks").join("queue.json");

        let queue = TaskQueue::new(Some(path.clone()));
        let task = queue.enqueue(serde_json::json!({"kind":"demo"}), Some(123));
        assert!(queue.mark_failed(&task.id, "boom"));

        let loaded = TaskQueue::new(Some(path));
        loaded.load();
        let persisted = loaded.get(&task.id).expect("task should load");
        assert_eq!(persisted.state, TaskState::Failed);
        assert_eq!(persisted.last_error.as_deref(), Some("boom"));
        assert_eq!(persisted.next_run_at_ms, None);
    }

    #[test]
    fn test_load_recovers_running_to_retry_wait() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("tasks").join("queue.json");

        let queue = TaskQueue::new(Some(path.clone()));
        let task = queue.enqueue(serde_json::json!({"kind":"demo"}), None);
        let _ = queue.claim_due(now_ms(), 1);

        let recovered = TaskQueue::new(Some(path));
        recovered.load();
        let loaded = recovered.get(&task.id).expect("task should load");
        assert_eq!(loaded.state, TaskState::RetryWait);
        assert!(loaded.next_run_at_ms.is_some());
    }

    struct DoneExecutor {
        calls: AtomicUsize,
    }

    #[async_trait]
    impl TaskExecutor for DoneExecutor {
        async fn execute(&self, _task: DurableTask) -> TaskExecutionOutcome {
            self.calls.fetch_add(1, Ordering::Relaxed);
            TaskExecutionOutcome::Done
        }
    }

    #[tokio::test]
    async fn test_task_worker_loop_processes_due_tasks() {
        let queue = Arc::new(TaskQueue::in_memory());
        queue.enqueue(serde_json::json!({"kind":"demo-1"}), None);
        queue.enqueue(serde_json::json!({"kind":"demo-2"}), None);

        let executor = Arc::new(DoneExecutor {
            calls: AtomicUsize::new(0),
        });
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let worker = tokio::spawn(task_worker_loop(
            queue.clone(),
            executor.clone(),
            Duration::from_millis(10),
            shutdown_rx,
        ));

        tokio::time::sleep(Duration::from_millis(75)).await;
        let _ = shutdown_tx.send(true);
        let _ = worker.await;

        assert_eq!(executor.calls.load(Ordering::Relaxed), 2);
        let stats = queue.stats();
        assert_eq!(stats.done, 2);
        assert_eq!(stats.running, 0);
    }
}
