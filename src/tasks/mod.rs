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
const TASK_QUEUE_FULL_NO_EVICTION_ERROR: &str =
    "task queue full: no terminal tasks available for eviction";
const ENQUEUE_WORKER_FAILED_ERROR: &str = "task queue enqueue worker failed";
pub const DEFAULT_TASK_MAX_ATTEMPTS: u32 = 100;
pub const DEFAULT_TASK_MAX_TOTAL_RUNTIME_MS: u64 = 7 * 24 * 60 * 60 * 1000;
pub const DEFAULT_TASK_MAX_TURNS: u32 = 25;
pub const DEFAULT_TASK_MAX_RUN_TIMEOUT_SECONDS: u32 = 600;

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

impl TaskState {
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            TaskState::Done | TaskState::Failed | TaskState::Cancelled
        )
    }
}

/// Per-task continuation policy budgets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TaskPolicy {
    pub max_attempts: u32,
    pub max_total_runtime_ms: u64,
    pub max_turns: u32,
    pub max_run_timeout_seconds: u32,
}

impl Default for TaskPolicy {
    fn default() -> Self {
        Self {
            max_attempts: DEFAULT_TASK_MAX_ATTEMPTS,
            max_total_runtime_ms: DEFAULT_TASK_MAX_TOTAL_RUNTIME_MS,
            max_turns: DEFAULT_TASK_MAX_TURNS,
            max_run_timeout_seconds: DEFAULT_TASK_MAX_RUN_TIMEOUT_SECONDS,
        }
    }
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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub run_ids: Vec<String>,
    #[serde(default)]
    pub policy: TaskPolicy,
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
                tracing::error!(
                    path = %path.display(),
                    error = %err,
                    "failed to parse tasks file; starting with empty task queue"
                );
                return;
            }
        };

        let now = now_ms();
        let mut recovered_running = false;
        for task in &mut loaded {
            if task.state == TaskState::Running {
                task.state = TaskState::RetryWait;
                task.next_run_at_ms = Some(now);
                task.updated_at_ms = now;
                recovered_running = true;
                if task.last_error.is_none() {
                    task.last_error = Some("recovered after restart".to_string());
                }
            }
        }

        *self.tasks.write() = loaded;
        if recovered_running {
            self.flush_to_disk();
        }
    }

    /// Add a new task in `queued` state.
    ///
    /// For Tokio async call sites, prefer [`Self::enqueue_async`] to avoid
    /// blocking runtime worker threads on fsync.
    ///
    /// If the queue is full and has no terminal task to evict, this returns a
    /// synthetic `Failed` task and does not insert it into the queue. Callers
    /// must not assume the returned task ID is persisted in that case.
    pub fn enqueue(&self, payload: Value, next_run_at_ms: Option<u64>) -> DurableTask {
        self.enqueue_with_policy(payload, next_run_at_ms, TaskPolicy::default())
    }

    /// Add a new task with an explicit continuation policy.
    pub fn enqueue_with_policy(
        &self,
        payload: Value,
        next_run_at_ms: Option<u64>,
        policy: TaskPolicy,
    ) -> DurableTask {
        let now = now_ms();
        let mut task = DurableTask {
            id: Uuid::new_v4().to_string(),
            state: TaskState::Queued,
            attempts: 0,
            next_run_at_ms,
            last_error: None,
            payload,
            created_at_ms: now,
            updated_at_ms: now,
            run_ids: Vec::new(),
            policy,
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
                            TaskState::Done | TaskState::Failed | TaskState::Cancelled
                        )
                    })
                    .min_by_key(|(_, t)| t.updated_at_ms)
                {
                    tasks.remove(idx);
                } else {
                    task.state = TaskState::Failed;
                    task.last_error = Some(TASK_QUEUE_FULL_NO_EVICTION_ERROR.to_string());
                    task.updated_at_ms = now;
                    warn!(
                        max_tasks = MAX_TASKS,
                        "task queue full with no terminal tasks; dropping enqueue request"
                    );
                    return task;
                }
            }
            tasks.push(task.clone());
        }
        self.flush_to_disk();
        task
    }

    /// Async-safe enqueue wrapper for Tokio call sites.
    ///
    /// This offloads sync queue mutation and fsync persistence to a blocking
    /// thread, so async handlers do not block runtime worker threads.
    ///
    /// The same capacity-full contract as [`Self::enqueue`] applies: on full
    /// queue with no evictable terminal task, the returned `Failed` task ID is
    /// synthetic and not present in the queue.
    pub async fn enqueue_async(
        self: &Arc<Self>,
        payload: Value,
        next_run_at_ms: Option<u64>,
    ) -> DurableTask {
        self.enqueue_async_with_policy(payload, next_run_at_ms, TaskPolicy::default())
            .await
    }

    /// Async-safe enqueue wrapper with explicit continuation policy.
    pub async fn enqueue_async_with_policy(
        self: &Arc<Self>,
        payload: Value,
        next_run_at_ms: Option<u64>,
        policy: TaskPolicy,
    ) -> DurableTask {
        let queue = Arc::clone(self);
        let payload_fallback = payload.clone();
        let policy_fallback = policy.clone();
        match tokio::task::spawn_blocking(move || {
            queue.enqueue_with_policy(payload, next_run_at_ms, policy)
        })
        .await
        {
            Ok(task) => task,
            Err(err) => {
                let now = now_ms();
                warn!(error = %err, "enqueue worker failed");
                DurableTask {
                    id: Uuid::new_v4().to_string(),
                    state: TaskState::Failed,
                    attempts: 0,
                    next_run_at_ms,
                    last_error: Some(ENQUEUE_WORKER_FAILED_ERROR.to_string()),
                    payload: payload_fallback,
                    created_at_ms: now,
                    updated_at_ms: now,
                    run_ids: Vec::new(),
                    policy: policy_fallback,
                }
            }
        }
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

    /// List tasks with optional state filtering and limit, newest-first.
    pub fn list_filtered(
        &self,
        state_filter: Option<TaskState>,
        limit: Option<usize>,
    ) -> (usize, Vec<DurableTask>) {
        let tasks = self.tasks.read();
        let mut matched: Vec<&DurableTask> = tasks
            .iter()
            .filter(|task| state_filter.is_none_or(|state| task.state == state))
            .collect();
        matched.sort_by_key(|task| std::cmp::Reverse(task.updated_at_ms));
        let total = matched.len();
        if let Some(limit) = limit {
            matched.truncate(limit);
        }
        let listed = matched.into_iter().cloned().collect();
        (total, listed)
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
    pub fn mark_done(&self, id: &str, run_id: Option<&str>) -> bool {
        self.update_task_if(
            id,
            |task| task.state == TaskState::Running,
            |task, now| {
                task.state = TaskState::Done;
                task.last_error = None;
                task.next_run_at_ms = None;
                task.updated_at_ms = now;
                if let Some(run_id) = run_id {
                    let run_id = run_id.trim();
                    if !run_id.is_empty() && !task.run_ids.iter().any(|existing| existing == run_id)
                    {
                        task.run_ids.push(run_id.to_string());
                    }
                }
            },
        )
    }

    /// Mark a task as failed.
    pub fn mark_failed(&self, id: &str, error: &str) -> bool {
        self.update_task_if(
            id,
            |task| task.state == TaskState::Running,
            |task, now| {
                task.state = TaskState::Failed;
                task.last_error = Some(error.to_string());
                task.next_run_at_ms = None;
                task.updated_at_ms = now;
            },
        )
    }

    /// Mark a task as blocked.
    pub fn mark_blocked(&self, id: &str, reason: &str) -> bool {
        self.update_task_if(
            id,
            |task| task.state == TaskState::Running,
            |task, now| {
                task.state = TaskState::Blocked;
                task.last_error = Some(reason.to_string());
                task.next_run_at_ms = None;
                task.updated_at_ms = now;
            },
        )
    }

    /// Mark a task as cancelled.
    pub fn mark_cancelled(&self, id: &str, reason: Option<&str>) -> bool {
        self.update_task_if(
            id,
            |task| !task.state.is_terminal(),
            |task, now| {
                task.state = TaskState::Cancelled;
                task.last_error = reason.map(ToString::to_string);
                task.next_run_at_ms = None;
                task.updated_at_ms = now;
            },
        )
    }

    /// Mark a task for retry at `now + delay_ms`.
    pub fn mark_retry_wait(&self, id: &str, delay_ms: u64, error: &str) -> bool {
        self.update_task_if(
            id,
            |task| {
                matches!(
                    task.state,
                    TaskState::Running
                        | TaskState::Failed
                        | TaskState::Blocked
                        | TaskState::RetryWait
                        | TaskState::Cancelled
                )
            },
            |task, now| {
                task.state = TaskState::RetryWait;
                task.last_error = Some(error.to_string());
                task.next_run_at_ms = Some(now.saturating_add(delay_ms));
                task.updated_at_ms = now;
            },
        )
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

    fn update_task_if(
        &self,
        id: &str,
        mut predicate: impl FnMut(&DurableTask) -> bool,
        mut apply: impl FnMut(&mut DurableTask, u64),
    ) -> bool {
        let now = now_ms();
        let updated = {
            let mut tasks = self.tasks.write();
            if let Some(task) = tasks.iter_mut().find(|t| t.id == id) {
                if predicate(task) {
                    apply(task, now);
                    true
                } else {
                    false
                }
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

        if !self.dir_ensured.load(Ordering::Acquire) {
            if let Some(parent) = path.parent() {
                if let Err(err) = fs::create_dir_all(parent) {
                    warn!(path = %parent.display(), error = %err, "failed to create tasks dir");
                    return;
                }
            }
            self.dir_ensured.store(true, Ordering::Release);
        }

        let tmp_path = {
            let mut s = path.as_os_str().to_os_string();
            s.push(".tmp");
            PathBuf::from(s)
        };

        let snapshot = self.tasks.read().clone();
        let mut data = match serde_json::to_vec_pretty(&snapshot) {
            Ok(v) => v,
            Err(err) => {
                warn!(error = %err, "failed to serialize tasks");
                return;
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
    Done { run_id: Option<String> },
    RetryWait { delay_ms: u64, error: String },
    Blocked { reason: String },
    Failed { error: String },
    Cancelled { reason: Option<String> },
}

#[async_trait]
pub trait TaskExecutor: Send + Sync {
    /// Retry-cap policy is intentionally executor-owned; queue records attempts only.
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
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = ticker.tick() => {}
            _ = shutdown.changed() => {
                tracing::info!("durable task worker received shutdown signal");
                break;
            }
        }

        if *shutdown.borrow() {
            tracing::info!("durable task worker observed shutdown state");
            break;
        }

        let now = now_ms();
        let due = match tokio::task::spawn_blocking({
            let queue = queue.clone();
            move || queue.claim_due(now, 32)
        })
        .await
        {
            Ok(due) => due,
            Err(err) => {
                warn!(error = %err, "failed to claim due tasks in worker");
                continue;
            }
        };
        // Intentionally sequential for now: each tick claims at most 32 tasks.
        // Future work may add bounded parallelism once dispatch paths are
        // validated under concurrent execution.
        for task in due {
            let outcome = executor.execute(task.clone()).await;
            let task_id = task.id.clone();
            let (state_name, update_result) = match outcome {
                TaskExecutionOutcome::Done { run_id } => (
                    "done",
                    tokio::task::spawn_blocking({
                        let queue = queue.clone();
                        let task_id = task_id.clone();
                        move || queue.mark_done(&task_id, run_id.as_deref())
                    })
                    .await,
                ),
                TaskExecutionOutcome::RetryWait { delay_ms, error } => (
                    "retry_wait",
                    tokio::task::spawn_blocking({
                        let queue = queue.clone();
                        let task_id = task_id.clone();
                        let error = error.clone();
                        move || queue.mark_retry_wait(&task_id, delay_ms, &error)
                    })
                    .await,
                ),
                TaskExecutionOutcome::Blocked { reason } => (
                    "blocked",
                    tokio::task::spawn_blocking({
                        let queue = queue.clone();
                        let task_id = task_id.clone();
                        let reason = reason.clone();
                        move || queue.mark_blocked(&task_id, &reason)
                    })
                    .await,
                ),
                TaskExecutionOutcome::Failed { error } => (
                    "failed",
                    tokio::task::spawn_blocking({
                        let queue = queue.clone();
                        let task_id = task_id.clone();
                        let error = error.clone();
                        move || queue.mark_failed(&task_id, &error)
                    })
                    .await,
                ),
                TaskExecutionOutcome::Cancelled { reason } => (
                    "cancelled",
                    tokio::task::spawn_blocking({
                        let queue = queue.clone();
                        let task_id = task_id.clone();
                        move || queue.mark_cancelled(&task_id, reason.as_deref())
                    })
                    .await,
                ),
            };
            match update_result {
                Ok(true) => {}
                Ok(false) => {
                    warn!(task_id = %task_id, state = state_name, "failed to update task state")
                }
                Err(err) => warn!(
                    task_id = %task_id,
                    state = state_name,
                    error = %err,
                    "task state update worker failed"
                ),
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
        assert!(queue.mark_cancelled(&task.id, Some("operator cancel")));
        assert!(queue.mark_retry_wait(&task.id, 5_000, "temporary failure"));
        let updated = queue.get(&task.id).expect("task should exist");
        assert_eq!(updated.state, TaskState::RetryWait);
        assert_eq!(updated.last_error.as_deref(), Some("temporary failure"));
        assert!(updated.next_run_at_ms.is_some());
    }

    #[test]
    fn test_mark_retry_wait_allows_running_and_rejects_queued_done() {
        let queue = TaskQueue::in_memory();
        let queued = queue.enqueue(serde_json::json!({"kind":"queued"}), None);
        assert!(!queue.mark_retry_wait(&queued.id, 1_000, "reject queued"));

        let running = queue.enqueue(serde_json::json!({"kind":"running"}), None);
        let _ = queue.claim_due(now_ms(), 10);
        assert!(queue.mark_retry_wait(&running.id, 1_000, "allow running"));
        let running_updated = queue.get(&running.id).expect("running task should exist");
        assert_eq!(running_updated.state, TaskState::RetryWait);

        let done = queue.enqueue(serde_json::json!({"kind":"done"}), None);
        let _ = queue.claim_due(now_ms(), 10);
        assert!(queue.mark_done(&done.id, Some("run-1")));
        assert!(!queue.mark_retry_wait(&done.id, 1_000, "reject done"));
    }

    #[test]
    fn test_mark_done_requires_running_and_records_run_id() {
        let queue = TaskQueue::in_memory();
        let task = queue.enqueue(serde_json::json!({"kind":"demo"}), None);
        let _ = queue.claim_due(now_ms(), 1);

        assert!(queue.mark_done(&task.id, Some("run-1")));
        assert!(!queue.mark_done(&task.id, Some("run-1")));
        assert!(!queue.mark_done(&task.id, Some("run-2")));

        let updated = queue.get(&task.id).expect("task should exist");
        assert_eq!(updated.state, TaskState::Done);
        assert_eq!(updated.run_ids, vec!["run-1".to_string()]);
    }

    #[test]
    fn test_mark_blocked_tracks_reason() {
        let queue = TaskQueue::in_memory();
        let task = queue.enqueue(serde_json::json!({"kind":"demo"}), None);
        let _ = queue.claim_due(now_ms(), 1);
        assert!(queue.mark_blocked(&task.id, "waiting approval"));
        let updated = queue.get(&task.id).expect("task should exist");
        assert_eq!(updated.state, TaskState::Blocked);
        assert_eq!(updated.last_error.as_deref(), Some("waiting approval"));
        assert_eq!(updated.next_run_at_ms, None);
    }

    #[test]
    fn test_mark_cancelled_rejects_terminal_state() {
        let queue = TaskQueue::in_memory();
        let task = queue.enqueue(serde_json::json!({"kind":"demo"}), None);
        let _ = queue.claim_due(now_ms(), 1);
        assert!(queue.mark_done(&task.id, Some("run-1")));
        assert!(!queue.mark_cancelled(&task.id, Some("too late")));
    }

    #[test]
    fn test_mark_cancelled_tracks_reason() {
        let queue = TaskQueue::in_memory();
        let task = queue.enqueue(serde_json::json!({"kind":"demo"}), None);
        let _ = queue.claim_due(now_ms(), 1);
        assert!(queue.mark_cancelled(&task.id, Some("operator cancel")));
        let updated = queue.get(&task.id).expect("task should exist");
        assert_eq!(updated.state, TaskState::Cancelled);
        assert_eq!(updated.last_error.as_deref(), Some("operator cancel"));
        assert_eq!(updated.next_run_at_ms, None);
    }

    #[test]
    fn test_list_filtered_applies_state_and_limit() {
        let queue = TaskQueue::in_memory();
        let done = queue.enqueue(serde_json::json!({"kind":"done"}), None);
        let queued = queue.enqueue(serde_json::json!({"kind":"queued"}), None);
        let _ = queue.claim_due(now_ms(), 1);
        assert!(queue.mark_done(&done.id, Some("run-1")));

        let (total_done, done_only) = queue.list_filtered(Some(TaskState::Done), Some(10));
        assert_eq!(total_done, 1);
        assert_eq!(done_only.len(), 1);
        assert_eq!(done_only[0].id, done.id);

        let (total_all, limited) = queue.list_filtered(None, Some(1));
        assert_eq!(total_all, 2);
        assert_eq!(limited.len(), 1);
        assert!(limited[0].id == done.id || limited[0].id == queued.id);
    }

    #[test]
    fn test_flush_and_load_round_trip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("tasks").join("queue.json");

        let queue = TaskQueue::new(Some(path.clone()));
        let task = queue.enqueue(serde_json::json!({"kind":"demo"}), Some(123));
        let _ = queue.claim_due(now_ms(), 1);
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

    #[test]
    fn test_load_recovery_persists_to_disk() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("tasks").join("queue.json");

        let queue = TaskQueue::new(Some(path.clone()));
        queue.enqueue(serde_json::json!({"kind":"demo"}), None);
        let _ = queue.claim_due(now_ms(), 1);

        let recovered = TaskQueue::new(Some(path.clone()));
        recovered.load();

        let persisted: Vec<DurableTask> =
            serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        assert_eq!(persisted.len(), 1);
        assert_eq!(persisted[0].state, TaskState::RetryWait);
        assert!(persisted[0].next_run_at_ms.is_some());
    }

    #[test]
    fn test_enqueue_evicts_terminal_before_blocked() {
        let queue = TaskQueue::in_memory();
        {
            let mut tasks = queue.tasks.write();
            for idx in 0..MAX_TASKS {
                tasks.push(DurableTask {
                    id: format!("blocked-{idx}"),
                    state: TaskState::Blocked,
                    attempts: 1,
                    next_run_at_ms: None,
                    last_error: Some("blocked".to_string()),
                    payload: serde_json::json!({"kind":"demo"}),
                    created_at_ms: idx as u64 + 1,
                    updated_at_ms: idx as u64 + 1,
                    run_ids: Vec::new(),
                    policy: TaskPolicy::default(),
                });
            }
            tasks[0].id = "done-oldest".to_string();
            tasks[0].state = TaskState::Done;
            tasks[0].last_error = None;
            tasks[0].updated_at_ms = 0;
        }

        let _ = queue.enqueue(serde_json::json!({"kind":"new"}), None);
        assert!(queue.get("done-oldest").is_none());
        assert_eq!(queue.stats().blocked, MAX_TASKS - 1);
        assert_eq!(queue.stats().total, MAX_TASKS);
    }

    #[test]
    fn test_enqueue_drops_when_full_without_terminal_capacity() {
        let queue = TaskQueue::in_memory();
        {
            let mut tasks = queue.tasks.write();
            for idx in 0..MAX_TASKS {
                tasks.push(DurableTask {
                    id: format!("running-{idx}"),
                    state: TaskState::Running,
                    attempts: 1,
                    next_run_at_ms: None,
                    last_error: None,
                    payload: serde_json::json!({"kind":"demo"}),
                    created_at_ms: idx as u64 + 1,
                    updated_at_ms: idx as u64 + 1,
                    run_ids: Vec::new(),
                    policy: TaskPolicy::default(),
                });
            }
        }

        let dropped = queue.enqueue(serde_json::json!({"kind":"new"}), None);
        assert_eq!(queue.stats().total, MAX_TASKS);
        assert_eq!(dropped.state, TaskState::Failed);
        assert_eq!(
            dropped.last_error.as_deref(),
            Some(TASK_QUEUE_FULL_NO_EVICTION_ERROR)
        );
        assert!(queue.get(&dropped.id).is_none());
    }

    #[tokio::test]
    async fn test_enqueue_async_queues_without_blocking_callsite() {
        let queue = Arc::new(TaskQueue::in_memory());
        let task = queue
            .enqueue_async(serde_json::json!({"kind":"demo-async"}), None)
            .await;
        assert_eq!(task.state, TaskState::Queued);
        let persisted = queue.get(&task.id).expect("task should be queued");
        assert_eq!(persisted.payload, serde_json::json!({"kind":"demo-async"}));
    }

    #[tokio::test]
    async fn test_enqueue_async_drops_when_full_without_terminal_capacity() {
        let queue = Arc::new(TaskQueue::in_memory());
        {
            let mut tasks = queue.tasks.write();
            for idx in 0..MAX_TASKS {
                tasks.push(DurableTask {
                    id: format!("running-{idx}"),
                    state: TaskState::Running,
                    attempts: 1,
                    next_run_at_ms: None,
                    last_error: None,
                    payload: serde_json::json!({"kind":"demo"}),
                    created_at_ms: idx as u64 + 1,
                    updated_at_ms: idx as u64 + 1,
                    run_ids: Vec::new(),
                    policy: TaskPolicy::default(),
                });
            }
        }

        let dropped = queue
            .enqueue_async(serde_json::json!({"kind":"new-async"}), None)
            .await;
        assert_eq!(queue.stats().total, MAX_TASKS);
        assert_eq!(dropped.state, TaskState::Failed);
        assert_eq!(
            dropped.last_error.as_deref(),
            Some(TASK_QUEUE_FULL_NO_EVICTION_ERROR)
        );
        assert!(queue.get(&dropped.id).is_none());
    }

    struct DoneExecutor {
        calls: AtomicUsize,
    }

    #[async_trait]
    impl TaskExecutor for DoneExecutor {
        async fn execute(&self, _task: DurableTask) -> TaskExecutionOutcome {
            self.calls.fetch_add(1, Ordering::Relaxed);
            TaskExecutionOutcome::Done { run_id: None }
        }
    }

    struct FixedOutcomeExecutor {
        outcome: TaskExecutionOutcome,
    }

    #[async_trait]
    impl TaskExecutor for FixedOutcomeExecutor {
        async fn execute(&self, _task: DurableTask) -> TaskExecutionOutcome {
            self.outcome.clone()
        }
    }

    async fn run_worker_once_with_outcome(queue: Arc<TaskQueue>, outcome: TaskExecutionOutcome) {
        let executor = Arc::new(FixedOutcomeExecutor { outcome });
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let worker = tokio::spawn(task_worker_loop(
            queue,
            executor,
            Duration::from_millis(10),
            shutdown_rx,
        ));

        tokio::time::sleep(Duration::from_millis(60)).await;
        let _ = shutdown_tx.send(true);
        let _ = worker.await;
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

    #[tokio::test]
    async fn test_task_worker_loop_retry_wait_outcome_branch() {
        let queue = Arc::new(TaskQueue::in_memory());
        let task = queue.enqueue(serde_json::json!({"kind":"demo"}), None);

        run_worker_once_with_outcome(
            queue.clone(),
            TaskExecutionOutcome::RetryWait {
                delay_ms: 5_000,
                error: "temporary failure".to_string(),
            },
        )
        .await;

        let updated = queue.get(&task.id).expect("task should exist");
        assert_eq!(updated.state, TaskState::RetryWait);
        assert_eq!(updated.last_error.as_deref(), Some("temporary failure"));
        assert!(updated.next_run_at_ms.is_some());
    }

    #[tokio::test]
    async fn test_task_worker_loop_failed_outcome_branch() {
        let queue = Arc::new(TaskQueue::in_memory());
        let task = queue.enqueue(serde_json::json!({"kind":"demo"}), None);

        run_worker_once_with_outcome(
            queue.clone(),
            TaskExecutionOutcome::Failed {
                error: "fatal".to_string(),
            },
        )
        .await;

        let updated = queue.get(&task.id).expect("task should exist");
        assert_eq!(updated.state, TaskState::Failed);
        assert_eq!(updated.last_error.as_deref(), Some("fatal"));
        assert_eq!(updated.next_run_at_ms, None);
    }

    #[tokio::test]
    async fn test_task_worker_loop_blocked_outcome_branch() {
        let queue = Arc::new(TaskQueue::in_memory());
        let task = queue.enqueue(serde_json::json!({"kind":"demo"}), None);

        run_worker_once_with_outcome(
            queue.clone(),
            TaskExecutionOutcome::Blocked {
                reason: "needs operator action".to_string(),
            },
        )
        .await;

        let updated = queue.get(&task.id).expect("task should exist");
        assert_eq!(updated.state, TaskState::Blocked);
        assert_eq!(updated.last_error.as_deref(), Some("needs operator action"));
        assert_eq!(updated.next_run_at_ms, None);
    }

    #[tokio::test]
    async fn test_task_worker_loop_cancelled_outcome_branch() {
        let queue = Arc::new(TaskQueue::in_memory());
        let task = queue.enqueue(serde_json::json!({"kind":"demo"}), None);

        run_worker_once_with_outcome(
            queue.clone(),
            TaskExecutionOutcome::Cancelled {
                reason: Some("operator cancelled".to_string()),
            },
        )
        .await;

        let updated = queue.get(&task.id).expect("task should exist");
        assert_eq!(updated.state, TaskState::Cancelled);
        assert_eq!(updated.last_error.as_deref(), Some("operator cancelled"));
        assert_eq!(updated.next_run_at_ms, None);
    }
}
