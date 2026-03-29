//! Shared channel activity feature policy and runtime helpers.
//!
//! This module handles per-channel activity policy (typing indicators and read
//! receipts) and the runtime helpers that drive those side effects.
//!
//! Activity subsystem contract:
//! - `WsServerState` owns the runtime activity service and is the only runtime
//!   shutdown entrypoint.
//! - shutdown closes intake first, then drains already-queued work until a
//!   deadline, joining the real worker threads directly.
//! - work still queued after the deadline is dropped explicitly with logging.
//! - read receipts are committed as non-lossy in-process obligations so
//!   successful delivery never waits on receipt-worker capacity.
//! - activity-capable channel implementations must bound their own blocking
//!   I/O; the dispatcher does not spawn detached per-operation timeout threads.
//! - config reload only affects future polls/messages because each receive loop
//!   iteration snapshots its activity policy before polling and dispatch.
//! - enabled-but-unsupported features warn both at runtime and when startup or
//!   config reload evaluates channel capabilities against policy.

use std::any::Any;
use std::collections::HashMap;
use std::panic::{catch_unwind, resume_unwind, AssertUnwindSafe};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};
use std::sync::mpsc as sync_mpsc;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::runtime::{Handle, RuntimeFlavor};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::plugins::{
    BindingError, ChannelPluginInstance, PluginRegistry, ReadReceiptContext, TypingContext,
};
use crate::runtime_bridge::run_sync_blocking_send;
use crate::server::ws::WsServerState;
use crate::tasks::{TaskBlockedReason, TaskExecutionOutcome, TaskExecutor, TaskQueue};

const DEFAULT_TYPING_INTERVAL_SECONDS: u32 = 3;
const MAX_TYPING_REFRESH_BACKOFF_SECONDS: u64 = 30;
const ACTIVITY_DISPATCH_BACKLOG_WARNING_THRESHOLD: usize = 64;
const ACTIVITY_BLOCKING_IO_MAX_SECS: u64 = 5;
const READ_RECEIPT_RETRY_DELAY_MS: u64 = 5_000;
const READ_RECEIPT_OWNERSHIP_HIGH_WATERMARK: usize = 10_000;
const READ_RECEIPT_PENDING_REASON: &str = "waiting for successful response delivery";
pub(crate) const READ_RECEIPT_WITHHELD_REASON: &str =
    "withholding explicit read receipt because after-response policy requires a successful response delivery";
const READ_RECEIPT_TASK_KIND: &str = "activityReadReceipt";
// This budget must stay at or above the longest built-in activity operation
// timeout so graceful shutdown drains already-queued work instead of routinely
// dropping it. Built-in channel activity implementations must keep their own
// blocking I/O bounded within this shared ceiling.
const ACTIVITY_DISPATCH_SHUTDOWN_GRACE_MS: u64 = ACTIVITY_BLOCKING_IO_MAX_SECS * 1000;
const _: () = {
    assert!(
        ACTIVITY_BLOCKING_IO_MAX_SECS >= crate::channels::signal::SIGNAL_HTTP_TYPING_TIMEOUT_SECS
    );
    assert!(
        ACTIVITY_BLOCKING_IO_MAX_SECS >= crate::channels::signal::SIGNAL_HTTP_RECEIPT_TIMEOUT_SECS
    );
};
const UNSUPPORTED_ACTIVITY_WARNING_COOLDOWN_SECS: u64 = 300;
// Stop-state machine:
// - NOT_REQUESTED -> TASK_RESERVED -> TASK_RUNNING -> COMPLETED
// - NOT_REQUESTED -> FALLBACK_RESERVED -> COMPLETED
// - TASK_RESERVED -> FALLBACK_RESERVED -> COMPLETED
// TASK_RUNNING means the task-owned stop worker has exclusive ownership of the
// final stop_typing call. FALLBACK_RESERVED means implicit-drop cleanup won the
// race before the task handed stop_typing to that worker.
const STOP_STATE_NOT_REQUESTED: u8 = 0;
const STOP_STATE_TASK_RESERVED: u8 = 1;
const STOP_STATE_TASK_RUNNING: u8 = 2;
const STOP_STATE_FALLBACK_RESERVED: u8 = 3;
const STOP_STATE_COMPLETED: u8 = 4;

struct UnsupportedActivityWarningRegistry {
    seen_at: HashMap<String, Instant>,
    cooldown: Duration,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ReadReceiptTaskPayload {
    kind: String,
    channel_id: String,
    context: ReadReceiptContext,
}

impl ReadReceiptTaskPayload {
    fn new(channel_id: &str, context: ReadReceiptContext) -> Self {
        Self {
            kind: READ_RECEIPT_TASK_KIND.to_string(),
            channel_id: channel_id.to_string(),
            context,
        }
    }

    fn from_value(value: serde_json::Value) -> Result<Self, serde_json::Error> {
        serde_json::from_value(value)
    }
}

impl Default for UnsupportedActivityWarningRegistry {
    fn default() -> Self {
        Self {
            seen_at: HashMap::new(),
            cooldown: Duration::from_secs(UNSUPPORTED_ACTIVITY_WARNING_COOLDOWN_SECS),
        }
    }
}

impl UnsupportedActivityWarningRegistry {
    fn should_warn(&mut self, key: &str, now: Instant) -> bool {
        self.seen_at
            .retain(|_, last_seen| now.saturating_duration_since(*last_seen) < self.cooldown);
        match self.seen_at.get(key) {
            Some(last_seen) if now.saturating_duration_since(*last_seen) < self.cooldown => false,
            _ => {
                self.seen_at.insert(key.to_string(), now);
                true
            }
        }
    }

    #[cfg(test)]
    fn with_cooldown_for_test(cooldown: Duration) -> Self {
        Self {
            seen_at: HashMap::new(),
            cooldown,
        }
    }

    #[cfg(test)]
    fn reset(&mut self) {
        self.seen_at.clear();
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum TypingMode {
    #[default]
    Thinking,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum ReadReceiptMode {
    // Carapace sends an explicit receipt only after the assistant response has
    // been delivered successfully. Failed or cancelled runs intentionally
    // leave the inbound message unread.
    #[default]
    AfterResponse,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TypingFeaturePolicy {
    pub enabled: bool,
    pub mode: TypingMode,
    pub interval_seconds: u32,
}

impl Default for TypingFeaturePolicy {
    fn default() -> Self {
        Self {
            enabled: false,
            mode: TypingMode::Thinking,
            interval_seconds: DEFAULT_TYPING_INTERVAL_SECONDS,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReadReceiptFeaturePolicy {
    pub enabled: bool,
    pub mode: ReadReceiptMode,
}

impl Default for ReadReceiptFeaturePolicy {
    fn default() -> Self {
        Self {
            enabled: false,
            mode: ReadReceiptMode::AfterResponse,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ChannelActivityPolicy {
    pub typing: TypingFeaturePolicy,
    pub read_receipts: ReadReceiptFeaturePolicy,
}

pub struct TypingLoopHandle {
    cancel: CancellationToken,
    task: Option<JoinHandle<()>>,
    runtime_handle: Handle,
    plugin: Arc<dyn ChannelPluginInstance>,
    ctx: TypingContext,
    channel_id: String,
    stop_state: Arc<AtomicU8>,
    activity_dispatcher: Arc<ActivityDispatcher>,
}

struct StopTypingDispatchRequest {
    plugin: Arc<dyn ChannelPluginInstance>,
    channel_id: String,
    ctx: TypingContext,
    stop_states: Vec<Arc<AtomicU8>>,
    queued: bool,
    in_flight: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct StopTypingDispatchKey {
    channel_id: String,
    recipient: String,
    thread_id: Option<String>,
    account_id: Option<String>,
}

impl StopTypingDispatchKey {
    fn new(channel_id: &str, ctx: &TypingContext) -> Self {
        Self {
            channel_id: channel_id.to_string(),
            recipient: ctx.to.clone(),
            thread_id: ctx.thread_id.clone(),
            account_id: ctx.account_id.clone(),
        }
    }
}

pub struct ActivityService {
    dispatcher: Arc<ActivityDispatcher>,
    read_receipt_queue: Arc<TaskQueue>,
    unsupported_feature_warnings: Mutex<UnsupportedActivityWarningRegistry>,
    read_receipt_ownership_high_watermark: usize,
}

impl Default for ActivityService {
    fn default() -> Self {
        Self::new()
    }
}

impl ActivityService {
    pub fn new() -> Self {
        Self::with_read_receipt_queue(Arc::new(TaskQueue::in_memory_unbounded()))
    }

    pub fn new_persistent(state_dir: PathBuf) -> Self {
        Self::with_read_receipt_queue(Arc::new(TaskQueue::new_unbounded(Some(
            state_dir.join("activity").join("read_receipts.json"),
        ))))
    }

    fn with_read_receipt_queue(read_receipt_queue: Arc<TaskQueue>) -> Self {
        Self {
            dispatcher: Arc::new(ActivityDispatcher::new()),
            read_receipt_queue,
            unsupported_feature_warnings: Mutex::new(UnsupportedActivityWarningRegistry::default()),
            read_receipt_ownership_high_watermark: READ_RECEIPT_OWNERSHIP_HIGH_WATERMARK,
        }
    }

    #[cfg(test)]
    pub(crate) fn with_backlog_warning_threshold(backlog_warning_threshold: usize) -> Self {
        Self::with_limits_for_test(
            backlog_warning_threshold,
            READ_RECEIPT_OWNERSHIP_HIGH_WATERMARK,
        )
    }

    #[cfg(test)]
    pub(crate) fn with_limits_for_test(
        backlog_warning_threshold: usize,
        read_receipt_ownership_high_watermark: usize,
    ) -> Self {
        Self {
            dispatcher: Arc::new(ActivityDispatcher::with_backlog_warning_threshold(
                backlog_warning_threshold,
            )),
            read_receipt_queue: Arc::new(TaskQueue::in_memory_unbounded()),
            unsupported_feature_warnings: Mutex::new(UnsupportedActivityWarningRegistry::default()),
            read_receipt_ownership_high_watermark,
        }
    }

    pub fn dispatcher(&self) -> &Arc<ActivityDispatcher> {
        &self.dispatcher
    }

    pub fn read_receipt_queue(&self) -> &Arc<TaskQueue> {
        &self.read_receipt_queue
    }

    pub async fn enqueue_after_response_read_receipt(
        &self,
        channel_id: &str,
        ctx: ReadReceiptContext,
    ) -> Option<String> {
        let task = self
            .read_receipt_queue
            .enqueue_blocked_async_with_policy(
                serde_json::to_value(ReadReceiptTaskPayload::new(channel_id, ctx))
                    .expect("read receipt task payload should serialize"),
                READ_RECEIPT_PENDING_REASON,
                TaskBlockedReason::ExternalDependency,
                crate::tasks::TaskPolicy::default(),
            )
            .await;
        if task.state == crate::tasks::TaskState::Failed {
            tracing::warn!(
                channel = %channel_id,
                error = ?task.last_error,
                "failed to persist after-response read receipt obligation"
            );
            None
        } else {
            Some(task.id)
        }
    }

    pub async fn enqueue_ready_read_receipt(
        &self,
        channel_id: &str,
        ctx: ReadReceiptContext,
    ) -> Option<String> {
        let task = self
            .read_receipt_queue
            .enqueue_async(
                serde_json::to_value(ReadReceiptTaskPayload::new(channel_id, ctx))
                    .expect("read receipt task payload should serialize"),
                None,
            )
            .await;
        if task.state == crate::tasks::TaskState::Failed {
            tracing::warn!(
                channel = %channel_id,
                error = ?task.last_error,
                "failed to persist immediate read receipt obligation"
            );
            None
        } else {
            Some(task.id)
        }
    }

    pub async fn activate_read_receipt(&self, task_id: &str) {
        let task_id = task_id.to_string();
        let task_id_for_log = task_id.clone();
        let queue = self.read_receipt_queue.clone();
        match tokio::task::spawn_blocking(move || {
            queue.resume_blocked_task(&task_id, 0, "response delivered")
        })
        .await
        {
            Ok(true) => {}
            Ok(false) => tracing::warn!(
                task_id = %task_id_for_log,
                "failed to activate read receipt obligation after successful delivery"
            ),
            Err(err) => tracing::warn!(
                task_id = %task_id_for_log,
                error = %err,
                "read receipt activation worker failed"
            ),
        }
    }

    pub async fn withhold_read_receipt(&self, task_id: &str, reason: &str) {
        let task_id = task_id.to_string();
        let reason = reason.to_string();
        let task_id_for_log = task_id.clone();
        let reason_for_log = reason.clone();
        let queue = self.read_receipt_queue.clone();
        match tokio::task::spawn_blocking(move || queue.mark_cancelled(&task_id, Some(&reason)))
            .await
        {
            Ok(true) => {}
            Ok(false) => tracing::warn!(
                task_id = %task_id_for_log,
                reason = %reason_for_log,
                "failed to mark read receipt obligation as withheld"
            ),
            Err(err) => tracing::warn!(
                task_id = %task_id_for_log,
                error = %err,
                "read receipt withholding worker failed"
            ),
        }
    }

    pub async fn cleanup_orphaned_blocked_read_receipts_after_restart(
        &self,
    ) -> Result<usize, String> {
        let queue = self.read_receipt_queue.clone();
        let cancelled = tokio::task::spawn_blocking(move || {
            let blocked = queue.list_filtered(Some(crate::tasks::TaskState::Blocked), None).1;
            let mut cancelled = 0usize;
            for task in blocked {
                let is_after_response_pending = task.blocked_reason
                    == Some(TaskBlockedReason::ExternalDependency)
                    && task.last_error.as_deref() == Some(READ_RECEIPT_PENDING_REASON)
                    && ReadReceiptTaskPayload::from_value(task.payload.clone()).is_ok();
                if is_after_response_pending
                    && queue.mark_cancelled(
                        &task.id,
                        Some("discarding blocked read receipt orphaned by restart before response delivery"),
                    )
                {
                    cancelled += 1;
                }
            }
            cancelled
        })
        .await
        .map_err(|err| {
            format!("read receipt orphan cleanup worker failed during startup: {err}")
        })?;

        if cancelled > 0 {
            tracing::warn!(
                cancelled,
                "cancelled blocked read receipt obligations orphaned by restart before response delivery"
            );
        }

        Ok(cancelled)
    }

    pub fn dispatch_stop_typing(
        &self,
        plugin: Arc<dyn ChannelPluginInstance>,
        channel_id: &str,
        ctx: TypingContext,
        stop_state: Arc<AtomicU8>,
    ) {
        self.dispatcher
            .dispatch_stop_typing(plugin, channel_id, ctx, stop_state);
    }

    pub fn warn_unsupported_feature(&self, channel_id: &str, feature: &str) {
        let key = format!("{channel_id}:{feature}");
        let should_warn = {
            let mut registry = self.unsupported_feature_warnings.lock();
            registry.should_warn(&key, Instant::now())
        };
        if should_warn {
            tracing::warn!(
                channel = %channel_id,
                feature,
                "channel activity feature is enabled in config but unsupported by this channel; ignoring"
            );
        }
    }

    fn read_receipt_obligation_count(&self) -> usize {
        let stats = self.read_receipt_queue.stats();
        stats.queued + stats.running + stats.blocked + stats.retry_wait
    }

    pub fn can_accept_read_receipt_ownership(&self, channel_id: &str) -> bool {
        let outstanding = self.read_receipt_obligation_count();
        if outstanding < self.read_receipt_ownership_high_watermark {
            return true;
        }

        let key = format!("{channel_id}:read_receipts_backpressure");
        let should_warn = {
            let mut registry = self.unsupported_feature_warnings.lock();
            registry.should_warn(&key, Instant::now())
        };
        if should_warn {
            tracing::warn!(
                channel = %channel_id,
                outstanding,
                high_watermark = self.read_receipt_ownership_high_watermark,
                "read receipt backlog reached the high-water mark; leaving upstream auto-receipts enabled for new messages until the durable queue drains"
            );
        }
        false
    }

    pub async fn shutdown(&self) {
        let dispatcher = self.dispatcher.clone();
        if let Err(err) = tokio::task::spawn_blocking(move || dispatcher.shutdown()).await {
            tracing::warn!(error = %err, "activity service shutdown worker failed");
        }
    }

    pub async fn warn_configured_unsupported_features_for_registered_channels(
        &self,
        plugin_registry: Arc<PluginRegistry>,
    ) {
        for (channel_id, feature) in
            collect_configured_unsupported_features_for_registered_channels(plugin_registry).await
        {
            self.warn_unsupported_feature(&channel_id, feature);
        }
    }

    #[cfg(test)]
    pub(crate) fn reset_unsupported_activity_feature_warnings_for_test(&self) {
        self.unsupported_feature_warnings.lock().reset();
    }

    pub fn spawn_read_receipt_worker(
        &self,
        state: Arc<WsServerState>,
        shutdown: tokio::sync::watch::Receiver<bool>,
    ) {
        let queue = self.read_receipt_queue.clone();
        let executor = Arc::new(ReadReceiptTaskExecutor { state });
        tokio::spawn(crate::tasks::task_worker_loop(
            queue,
            executor,
            Duration::from_secs(1),
            shutdown,
        ));
    }
}

pub struct ActivityDispatcher {
    stop_typing_tx: Mutex<Option<sync_mpsc::Sender<StopTypingDispatchKey>>>,
    stop_typing_worker: Mutex<Option<thread::JoinHandle<()>>>,
    stop_typing_pending: Arc<Mutex<HashMap<StopTypingDispatchKey, StopTypingDispatchRequest>>>,
    stop_typing_backlog: Arc<AtomicUsize>,
    backlog_warning_threshold: usize,
    shutting_down: Arc<AtomicBool>,
    shutdown_deadline: Arc<Mutex<Option<Instant>>>,
}

impl Default for ActivityDispatcher {
    fn default() -> Self {
        Self::new()
    }
}

impl ActivityDispatcher {
    pub fn new() -> Self {
        Self::with_options(ACTIVITY_DISPATCH_BACKLOG_WARNING_THRESHOLD)
    }

    #[cfg(test)]
    pub(crate) fn with_backlog_warning_threshold(backlog_warning_threshold: usize) -> Self {
        Self::with_options(backlog_warning_threshold)
    }

    pub(crate) fn with_options(backlog_warning_threshold: usize) -> Self {
        let stop_typing_backlog = Arc::new(AtomicUsize::new(0));
        let shutting_down = Arc::new(AtomicBool::new(false));
        let shutdown_deadline = Arc::new(Mutex::new(None));

        let stop_typing_pending = Arc::new(Mutex::new(HashMap::<
            StopTypingDispatchKey,
            StopTypingDispatchRequest,
        >::new()));
        let stop_typing_pending_worker = stop_typing_pending.clone();
        let (stop_typing_tx_raw, stop_typing_rx) = sync_mpsc::channel::<StopTypingDispatchKey>();
        let stop_typing_tx = Mutex::new(Some(stop_typing_tx_raw));
        let stop_typing_backlog_worker = stop_typing_backlog.clone();
        let stop_typing_shutdown = shutting_down.clone();
        let stop_typing_deadline = shutdown_deadline.clone();
        let stop_typing_worker = thread::Builder::new()
            .name("carapace-stop-typing".to_string())
            .spawn(move || {
                // Stop-typing is cleanup, not optional side work. Keep this
                // path non-lossy, but coalesce requests per channel/recipient
                // so a stalled stop call cannot grow an unbounded duplicate
                // queue for the same remote typing state.
                while let Ok(key) = stop_typing_rx.recv() {
                    stop_typing_backlog_worker.fetch_sub(1, Ordering::AcqRel);
                    let maybe_request = {
                        let mut pending = stop_typing_pending_worker.lock();
                        let Some(request) = pending.get_mut(&key) else {
                            continue;
                        };
                        if should_drop_activity_work(
                            stop_typing_shutdown.as_ref(),
                            &stop_typing_deadline,
                        ) {
                            match pending.remove(&key) {
                                Some(request) => Some(Err(request)),
                                None => {
                                    tracing::warn!(
                                        "stop typing dispatcher lost a pending request during shutdown"
                                    );
                                    None
                                }
                            }
                        } else {
                            request.queued = false;
                            request.in_flight = true;
                            Some(Ok((
                                request.plugin.clone(),
                                request.channel_id.clone(),
                                request.ctx.clone(),
                                std::mem::take(&mut request.stop_states),
                            )))
                        }
                    };

                    let Some(request) = maybe_request else {
                        continue;
                    };

                    match request {
                        Err(request) => {
                            mark_stop_states_completed(&request.stop_states);
                            log_dropped_stop_typing_after_shutdown(
                                &request.channel_id,
                                &request.ctx,
                            );
                        }
                        Ok((mut plugin, mut channel_id, mut ctx, mut stop_states)) => loop {
                            dispatch_stop_typing_blocking(
                                plugin,
                                &channel_id,
                                ctx.clone(),
                                &stop_states,
                            );

                            let next_batch = {
                                let mut pending = stop_typing_pending_worker.lock();
                                let Some(request) = pending.get_mut(&key) else {
                                    break;
                                };
                                if should_drop_activity_work(
                                    stop_typing_shutdown.as_ref(),
                                    &stop_typing_deadline,
                                ) {
                                    match pending.remove(&key) {
                                        Some(request) => Some(Err(request)),
                                        None => {
                                            tracing::warn!(
                                                "stop typing dispatcher lost a pending request during shutdown"
                                            );
                                            None
                                        }
                                    }
                                } else if request.stop_states.is_empty() {
                                    pending.remove(&key);
                                    None
                                } else {
                                    Some(Ok((
                                        request.plugin.clone(),
                                        request.channel_id.clone(),
                                        request.ctx.clone(),
                                        std::mem::take(&mut request.stop_states),
                                    )))
                                }
                            };

                            match next_batch {
                                None => break,
                                Some(Err(request)) => {
                                    mark_stop_states_completed(&request.stop_states);
                                    log_dropped_stop_typing_after_shutdown(
                                        &request.channel_id,
                                        &request.ctx,
                                    );
                                    break;
                                }
                                Some(Ok((
                                    next_plugin,
                                    next_channel_id,
                                    next_ctx,
                                    next_stop_states,
                                ))) => {
                                    plugin = next_plugin;
                                    channel_id = next_channel_id;
                                    ctx = next_ctx;
                                    stop_states = next_stop_states;
                                }
                            }
                        },
                    }
                }
            })
            .expect("failed to spawn stop typing dispatcher thread");

        Self {
            stop_typing_tx,
            stop_typing_worker: Mutex::new(Some(stop_typing_worker)),
            stop_typing_pending,
            stop_typing_backlog,
            backlog_warning_threshold,
            shutting_down,
            shutdown_deadline,
        }
    }

    pub fn dispatch_stop_typing(
        &self,
        plugin: Arc<dyn ChannelPluginInstance>,
        channel_id: &str,
        ctx: TypingContext,
        stop_state: Arc<AtomicU8>,
    ) {
        let key = StopTypingDispatchKey::new(channel_id, &ctx);
        let mut should_enqueue = false;
        {
            let mut pending = self.stop_typing_pending.lock();
            if let Some(request) = pending.get_mut(&key) {
                request.stop_states.push(stop_state.clone());
                if !request.queued && !request.in_flight {
                    request.queued = true;
                    should_enqueue = true;
                }
            } else {
                pending.insert(
                    key.clone(),
                    StopTypingDispatchRequest {
                        plugin,
                        channel_id: channel_id.to_string(),
                        ctx,
                        stop_states: vec![stop_state.clone()],
                        queued: true,
                        in_flight: false,
                    },
                );
                should_enqueue = true;
            }
        }

        if !should_enqueue {
            return;
        }

        let Some(sender) = self.stop_typing_tx.lock().as_ref().cloned() else {
            let dropped = self.stop_typing_pending.lock().remove(&key);
            if let Some(request) = dropped {
                mark_stop_states_completed(&request.stop_states);
            } else {
                mark_stop_completed(stop_state.as_ref());
            }
            tracing::warn!(
                channel = %channel_id,
                "stop typing dispatcher is shut down; dropping implicit stop request"
            );
            return;
        };

        let backlog = self.stop_typing_backlog.fetch_add(1, Ordering::AcqRel) + 1;
        log_activity_backlog_if_needed(
            "stop typing",
            channel_id,
            backlog,
            self.backlog_warning_threshold,
        );

        if sender.send(key.clone()).is_err() {
            self.stop_typing_backlog.fetch_sub(1, Ordering::AcqRel);
            let dropped = self.stop_typing_pending.lock().remove(&key);
            if let Some(request) = dropped {
                mark_stop_states_completed(&request.stop_states);
            } else {
                mark_stop_completed(stop_state.as_ref());
            }
            tracing::warn!(
                channel = %channel_id,
                "stop typing dispatcher is shut down; dropping implicit stop request"
            );
        }
    }

    pub(crate) fn shutdown(&self) {
        self.shutdown_with_deadline(Duration::from_millis(ACTIVITY_DISPATCH_SHUTDOWN_GRACE_MS));
    }

    fn shutdown_with_deadline(&self, grace: Duration) {
        if self
            .shutting_down
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }
        let deadline = Instant::now() + grace;
        *self.shutdown_deadline.lock() = Some(deadline);
        self.stop_typing_tx.lock().take();

        if let Some(worker) = self.stop_typing_worker.lock().take() {
            join_activity_worker(worker, "stop typing");
        }
    }
}

impl Drop for ActivityDispatcher {
    fn drop(&mut self) {
        self.shutdown_with_deadline(Duration::ZERO);
    }
}

struct ReadReceiptTaskExecutor {
    state: Arc<WsServerState>,
}

#[async_trait::async_trait]
impl TaskExecutor for ReadReceiptTaskExecutor {
    async fn execute(&self, task: crate::tasks::DurableTask) -> TaskExecutionOutcome {
        let payload = match ReadReceiptTaskPayload::from_value(task.payload) {
            Ok(payload) => payload,
            Err(err) => {
                return TaskExecutionOutcome::Failed {
                    error: format!("invalid read receipt task payload: {err}"),
                };
            }
        };

        let Some(plugin_registry) = self.state.plugin_registry().cloned() else {
            return TaskExecutionOutcome::RetryWait {
                delay_ms: READ_RECEIPT_RETRY_DELAY_MS,
                error: "plugin registry unavailable for read receipt dispatch".to_string(),
            };
        };

        let Some(plugin) = plugin_registry.get_channel(&payload.channel_id) else {
            return TaskExecutionOutcome::RetryWait {
                delay_ms: READ_RECEIPT_RETRY_DELAY_MS,
                error: format!(
                    "channel plugin '{}' unavailable for read receipt dispatch",
                    payload.channel_id
                ),
            };
        };

        match get_capabilities(plugin.clone()).await {
            Ok(capabilities) if capabilities.read_receipts => {}
            Ok(_) => {
                self.state
                    .activity_service()
                    .warn_unsupported_feature(&payload.channel_id, "read_receipts");
                return TaskExecutionOutcome::Failed {
                    error: format!(
                        "channel '{}' does not support read receipts after activation",
                        payload.channel_id
                    ),
                };
            }
            Err(err) => {
                return TaskExecutionOutcome::RetryWait {
                    delay_ms: READ_RECEIPT_RETRY_DELAY_MS,
                    error: format!(
                        "failed to load channel capabilities for read receipt dispatch: {err}"
                    ),
                };
            }
        }

        match send_verified_read_receipt_with_plugin(plugin, &payload.channel_id, payload.context)
            .await
        {
            Ok(()) => TaskExecutionOutcome::Done { run_id: None },
            Err(ReadReceiptDispatchError::Retryable(err)) => TaskExecutionOutcome::RetryWait {
                delay_ms: READ_RECEIPT_RETRY_DELAY_MS,
                error: err,
            },
            Err(ReadReceiptDispatchError::Permanent(err)) => {
                TaskExecutionOutcome::Failed { error: err }
            }
        }
    }
}

impl std::fmt::Debug for TypingLoopHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TypingLoopHandle")
            .field("channel_id", &self.channel_id)
            .finish_non_exhaustive()
    }
}

impl TypingLoopHandle {
    pub async fn stop(mut self) {
        self.cancel.cancel();
        if let Some(task) = self.task.take() {
            if let Err(err) = finish_typing_task(
                task,
                self.plugin.clone(),
                self.ctx.clone(),
                self.stop_state.clone(),
            )
            .await
            {
                tracing::warn!(
                    channel = %self.channel_id,
                    error = %err,
                    "failed to finish typing cleanup during explicit stop"
                );
            }
        }
    }
}

impl Drop for TypingLoopHandle {
    fn drop(&mut self) {
        if self.task.is_none() {
            return;
        }
        self.cancel.cancel();
        match Handle::try_current() {
            Ok(handle) if handle.runtime_flavor() == RuntimeFlavor::MultiThread => {
                if let Some(task) = self.task.take() {
                    let plugin = self.plugin.clone();
                    let ctx = self.ctx.clone();
                    let channel_id = self.channel_id.clone();
                    let stop_state = self.stop_state.clone();
                    if let Err(err) =
                        run_sync_blocking_send(finish_typing_task(task, plugin, ctx, stop_state))
                    {
                        tracing::warn!(
                            channel = %channel_id,
                            error = %err,
                            "failed to finish typing cleanup after drop"
                        );
                    }
                }
            }
            _ => self.drop_without_multithread_runtime(),
        }
    }
}

impl TypingLoopHandle {
    fn drop_without_multithread_runtime(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
            observe_finished_typing_task_after_abort(
                task,
                self.runtime_handle.clone(),
                &self.channel_id,
            );
            if stop_fallback_needed(self.stop_state.as_ref()) {
                self.activity_dispatcher.dispatch_stop_typing(
                    self.plugin.clone(),
                    &self.channel_id,
                    self.ctx.clone(),
                    self.stop_state.clone(),
                );
            }
        }
    }
}

pub fn resolve_channel_activity_policy(config: &Value, channel: &str) -> ChannelActivityPolicy {
    let mut policy = ChannelActivityPolicy::default();
    apply_legacy_session_typing_fallback(config, &mut policy.typing);
    apply_channel_activity_overrides(
        config
            .get("channels")
            .and_then(|channels| channels.get("defaults"))
            .and_then(|defaults| defaults.get("features")),
        &mut policy,
    );
    apply_channel_activity_overrides(
        config
            .get("channels")
            .and_then(|channels| channels.get(channel))
            .and_then(|entry| entry.get("features")),
        &mut policy,
    );
    if policy.typing.interval_seconds == 0 {
        policy.typing.interval_seconds = DEFAULT_TYPING_INTERVAL_SECONDS;
    }
    policy
}

pub fn load_channel_activity_policy(channel: &str) -> ChannelActivityPolicy {
    let config = match crate::config::load_raw_config_shared() {
        Ok(config) => config,
        Err(err) => {
            tracing::warn!(
                channel = %channel,
                error = %err,
                "failed to load config for channel activity policy; using disabled defaults"
            );
            Arc::new(serde_json::json!({}))
        }
    };
    resolve_channel_activity_policy(config.as_ref(), channel)
}

pub async fn load_channel_activity_policy_async(channel: &str) -> ChannelActivityPolicy {
    if let Some(config) = crate::config::peek_fresh_raw_config_shared() {
        return resolve_channel_activity_policy(config.as_ref(), channel);
    }

    let channel = channel.to_string();
    let worker_channel = channel.clone();
    match tokio::task::spawn_blocking(move || load_channel_activity_policy(&worker_channel)).await {
        Ok(policy) => policy,
        Err(err) => {
            tracing::warn!(
                channel = %channel,
                error = %err,
                "failed to load channel activity policy on blocking worker; using disabled defaults"
            );
            ChannelActivityPolicy::default()
        }
    }
}

pub async fn collect_configured_unsupported_features_for_registered_channels(
    plugin_registry: Arc<PluginRegistry>,
) -> Vec<(String, &'static str)> {
    let mut unsupported = Vec::new();
    for (channel_id, plugin) in plugin_registry.get_channels() {
        let policy = load_channel_activity_policy_async(&channel_id).await;
        if !policy.typing.enabled && !policy.read_receipts.enabled {
            continue;
        }

        let capabilities = match get_capabilities(plugin).await {
            Ok(capabilities) => capabilities,
            Err(err) => {
                tracing::warn!(
                    channel = %channel_id,
                    error = %err,
                    "failed to load channel capabilities while checking configured activity feature support"
                );
                continue;
            }
        };

        if policy.typing.enabled && !capabilities.typing_indicators {
            unsupported.push((channel_id.clone(), "typing"));
        }
        if policy.read_receipts.enabled && !capabilities.read_receipts {
            unsupported.push((channel_id, "read_receipts"));
        }
    }
    unsupported
}

fn apply_legacy_session_typing_fallback(config: &Value, policy: &mut TypingFeaturePolicy) {
    let Some(session) = config.get("session") else {
        return;
    };

    // This is intentionally a global legacy fallback: if a user explicitly set
    // session.typingMode/session.typingIntervalSeconds, those values apply to
    // every typing-capable channel unless channels.defaults/features or a
    // per-channel channels.<id>.features.typing override replaces them.
    if let Some(mode) = session.get("typingMode").and_then(|value| value.as_str()) {
        if mode.eq_ignore_ascii_case("thinking") {
            policy.enabled = true;
            policy.mode = TypingMode::Thinking;
        } else {
            tracing::warn!(
                mode = %mode,
                "unknown legacy session.typingMode value; disabling legacy typing fallback"
            );
            policy.enabled = false;
        }
    }

    if let Some(interval) = parse_positive_u32_from_value(session, "typingIntervalSeconds") {
        policy.interval_seconds = interval;
    }
}

fn apply_channel_activity_overrides(features: Option<&Value>, policy: &mut ChannelActivityPolicy) {
    let Some(features) = features.and_then(|value| value.as_object()) else {
        return;
    };

    if let Some(typing_value) = features.get("typing") {
        if let Some(typing) = typing_value.as_object() {
            if let Some(enabled) = typing.get("enabled").and_then(|value| value.as_bool()) {
                policy.typing.enabled = enabled;
            }
            if let Some(mode) = typing.get("mode").and_then(|value| value.as_str()) {
                if mode.eq_ignore_ascii_case("thinking") {
                    policy.typing.mode = TypingMode::Thinking;
                } else {
                    tracing::warn!(
                        mode = %mode,
                        "unknown channels.*.features.typing.mode value; ignoring"
                    );
                }
            }
            if let Some(interval) = parse_positive_u32_from_value(typing_value, "intervalSeconds") {
                policy.typing.interval_seconds = interval;
            }
        }
    }

    if let Some(receipts) = features
        .get("readReceipts")
        .and_then(|value| value.as_object())
    {
        if let Some(enabled) = receipts.get("enabled").and_then(|value| value.as_bool()) {
            policy.read_receipts.enabled = enabled;
        }
        if let Some(mode) = receipts.get("mode").and_then(|value| value.as_str()) {
            if mode.eq_ignore_ascii_case("after-response") {
                policy.read_receipts.mode = ReadReceiptMode::AfterResponse;
            } else {
                tracing::warn!(
                    mode = %mode,
                    "unknown channels.*.features.readReceipts.mode value; ignoring"
                );
            }
        }
    }
}

fn parse_positive_u32_from_value(value: &Value, key: &str) -> Option<u32> {
    value
        .get(key)
        .and_then(|entry| entry.as_u64())
        .filter(|entry| *entry > 0)
        .map(|entry| entry.min(u32::MAX as u64) as u32)
}

pub async fn maybe_start_typing_loop(
    plugin_registry: Arc<PluginRegistry>,
    channel_id: &str,
    policy: &ChannelActivityPolicy,
    prefetched_capabilities: Option<crate::plugins::ChannelCapabilities>,
    activity_service: Arc<ActivityService>,
    ctx: TypingContext,
) -> Option<TypingLoopHandle> {
    if !policy.typing.enabled {
        return None;
    }

    let plugin = plugin_registry.get_channel(channel_id)?;
    let capabilities = match prefetched_capabilities {
        Some(capabilities) => capabilities,
        None => get_capabilities(plugin.clone()).await.ok()?,
    };
    if !capabilities.typing_indicators {
        activity_service.warn_unsupported_feature(channel_id, "typing");
        return None;
    }

    if let Err(err) = invoke_start_typing(plugin.clone(), ctx.clone()).await {
        tracing::warn!(channel = %channel_id, error = %err, "failed to start typing indicator");
        return None;
    }

    let cancel = CancellationToken::new();
    let stop_state = Arc::new(AtomicU8::new(STOP_STATE_NOT_REQUESTED));
    let interval_seconds = policy.typing.interval_seconds.max(1);
    let runtime_handle = Handle::current();
    let channel_id = channel_id.to_string();
    let handle_channel_id = channel_id.clone();
    let handle_plugin = plugin.clone();
    let handle_ctx = ctx.clone();
    let handle_stop_state = stop_state.clone();
    let task_cancel = cancel.clone();
    let task_stop_state = stop_state.clone();
    let task = tokio::spawn(async move {
        let base_refresh_delay = Duration::from_secs(interval_seconds as u64);
        let mut consecutive_refresh_failures = 0_u32;
        let mut next_refresh_at = tokio::time::Instant::now() + base_refresh_delay;
        loop {
            tokio::select! {
                _ = task_cancel.cancelled() => {
                    break;
                }
                _ = tokio::time::sleep_until(next_refresh_at) => {
                    if let Err(err) = invoke_start_typing(plugin.clone(), ctx.clone()).await {
                        consecutive_refresh_failures = consecutive_refresh_failures.saturating_add(1);
                        let retry_delay = typing_refresh_retry_delay(
                            base_refresh_delay,
                            consecutive_refresh_failures,
                        );
                        next_refresh_at = tokio::time::Instant::now() + retry_delay;
                        if should_log_typing_refresh_failure(consecutive_refresh_failures) {
                            tracing::warn!(
                                channel = %channel_id,
                                error = %err,
                                failures = consecutive_refresh_failures,
                                retry_in_ms = retry_delay.as_millis(),
                                "failed to refresh typing indicator"
                            );
                        }
                    } else {
                        consecutive_refresh_failures = 0;
                        next_refresh_at = next_typing_refresh_deadline(
                            next_refresh_at,
                            base_refresh_delay,
                            tokio::time::Instant::now(),
                        );
                    }
                }
            }
        }

        if reserve_task_stop(task_stop_state.as_ref()) {
            if let Err(err) =
                invoke_stop_typing_with_running_state(plugin, ctx, task_stop_state).await
            {
                tracing::warn!(channel = %channel_id, error = %err, "failed to stop typing indicator");
            }
        }
    });

    Some(TypingLoopHandle {
        cancel,
        task: Some(task),
        runtime_handle,
        plugin: handle_plugin,
        ctx: handle_ctx,
        channel_id: handle_channel_id,
        stop_state: handle_stop_state,
        activity_dispatcher: activity_service.dispatcher().clone(),
    })
}

fn reserve_task_stop(stop_state: &AtomicU8) -> bool {
    stop_state
        .compare_exchange(
            STOP_STATE_NOT_REQUESTED,
            STOP_STATE_TASK_RESERVED,
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .is_ok()
}

fn stop_fallback_needed(stop_state: &AtomicU8) -> bool {
    let mut current = stop_state.load(Ordering::Acquire);
    loop {
        match current {
            STOP_STATE_NOT_REQUESTED | STOP_STATE_TASK_RESERVED => {
                match stop_state.compare_exchange(
                    current,
                    STOP_STATE_FALLBACK_RESERVED,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                ) {
                    Ok(_) => return true,
                    Err(next) => current = next,
                }
            }
            STOP_STATE_TASK_RUNNING | STOP_STATE_FALLBACK_RESERVED | STOP_STATE_COMPLETED => {
                return false;
            }
            _ => return false,
        }
    }
}

fn mark_stop_completed(stop_state: &AtomicU8) {
    stop_state.store(STOP_STATE_COMPLETED, Ordering::Release);
}

fn mark_stop_states_completed(stop_states: &[Arc<AtomicU8>]) {
    for stop_state in stop_states {
        mark_stop_completed(stop_state.as_ref());
    }
}

async fn finish_typing_task(
    task: JoinHandle<()>,
    plugin: Arc<dyn ChannelPluginInstance>,
    ctx: TypingContext,
    stop_state: Arc<AtomicU8>,
) -> Result<(), String> {
    match task.await {
        Ok(()) => Ok(()),
        Err(join_err) => {
            if stop_fallback_needed(stop_state.as_ref()) {
                invoke_stop_typing(plugin, ctx)
                    .await
                    .map_err(|err| format!(
                        "typing task ended unexpectedly ({join_err}); fallback stop_typing also failed: {err}"
                    ))?;
                mark_stop_completed(stop_state.as_ref());
                Err(format!(
                    "typing task ended unexpectedly ({join_err}); sent fallback stop_typing"
                ))
            } else {
                Err(format!(
                    "typing task ended unexpectedly ({join_err}) after typing cleanup already completed"
                ))
            }
        }
    }
}

fn typing_refresh_retry_delay(base_delay: Duration, consecutive_failures: u32) -> Duration {
    if consecutive_failures == 0 {
        return base_delay;
    }
    let base_secs = base_delay.as_secs().max(1);
    let exponent = consecutive_failures.saturating_sub(1).min(4);
    let multiplier = 1_u64 << exponent;
    Duration::from_secs(
        base_secs
            .saturating_mul(multiplier)
            .min(MAX_TYPING_REFRESH_BACKOFF_SECONDS),
    )
}

fn next_typing_refresh_deadline(
    previous_deadline: tokio::time::Instant,
    cadence: Duration,
    now: tokio::time::Instant,
) -> tokio::time::Instant {
    let mut next_deadline = previous_deadline + cadence;
    while next_deadline <= now {
        next_deadline += cadence;
    }
    next_deadline
}

fn should_log_typing_refresh_failure(consecutive_failures: u32) -> bool {
    consecutive_failures <= 3 || consecutive_failures.is_power_of_two()
}

fn log_activity_backlog_if_needed(
    activity: &str,
    channel_id: &str,
    backlog: usize,
    threshold: usize,
) {
    if backlog >= threshold && backlog.is_power_of_two() {
        tracing::warn!(
            channel = %channel_id,
            backlog,
            activity,
            "activity dispatcher backlog is growing"
        );
    }
}

fn should_drop_activity_work(
    shutting_down: &AtomicBool,
    shutdown_deadline: &Mutex<Option<Instant>>,
) -> bool {
    if !shutting_down.load(Ordering::Acquire) {
        return false;
    }
    shutdown_deadline
        .lock()
        .as_ref()
        .is_some_and(|deadline| Instant::now() > *deadline)
}

fn log_dropped_stop_typing_after_shutdown(channel_id: &str, ctx: &TypingContext) {
    tracing::warn!(
        channel = %channel_id,
        recipient = %ctx.to,
        "dropped queued stop-typing cleanup after activity shutdown deadline"
    );
}

fn observe_finished_typing_task_after_abort(
    task: JoinHandle<()>,
    runtime_handle: Handle,
    channel_id: &str,
) {
    let channel_id = channel_id.to_string();
    runtime_handle.spawn(async move {
        if let Err(err) = task.await {
            if err.is_panic() {
                tracing::warn!(
                    channel = %channel_id,
                    error = %panic_payload_to_string(err.into_panic()),
                    "typing task panicked during implicit drop cleanup"
                );
            }
        }
    });
}

fn join_activity_worker(worker: thread::JoinHandle<()>, activity: &'static str) {
    if let Err(payload) = worker.join() {
        tracing::warn!(
            activity,
            error = %panic_payload_to_string(payload),
            "activity dispatcher worker panicked during shutdown"
        );
    }
}

async fn invoke_stop_typing_with_running_state(
    plugin: Arc<dyn ChannelPluginInstance>,
    ctx: TypingContext,
    stop_state: Arc<AtomicU8>,
) -> Result<(), BindingError> {
    let Some(stop_task) = spawn_stop_typing_worker(plugin, ctx, stop_state) else {
        return Ok(());
    };
    let result = stop_task
        .await
        .map_err(|err| BindingError::CallError(err.to_string()))
        .and_then(|result| result);
    result
}

fn spawn_stop_typing_worker(
    plugin: Arc<dyn ChannelPluginInstance>,
    ctx: TypingContext,
    stop_state: Arc<AtomicU8>,
) -> Option<tokio::task::JoinHandle<Result<(), BindingError>>> {
    if stop_state
        .compare_exchange(
            STOP_STATE_TASK_RESERVED,
            STOP_STATE_TASK_RUNNING,
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .is_err()
    {
        return None;
    }

    Some(tokio::task::spawn_blocking(move || {
        let result = catch_unwind(AssertUnwindSafe(|| plugin.stop_typing(ctx)));
        mark_stop_completed(stop_state.as_ref());
        match result {
            Ok(result) => result,
            Err(payload) => resume_unwind(payload),
        }
    }))
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ReadReceiptDispatchError {
    Retryable(String),
    Permanent(String),
}

async fn send_verified_read_receipt_with_plugin(
    plugin: Arc<dyn ChannelPluginInstance>,
    channel_id: &str,
    ctx: ReadReceiptContext,
) -> Result<(), ReadReceiptDispatchError> {
    let channel_id = channel_id.to_string();
    let worker_channel_id = channel_id.clone();
    match tokio::task::spawn_blocking(move || {
        dispatch_read_receipt_blocking(plugin, &worker_channel_id, ctx)
    })
    .await
    {
        Ok(result) => result,
        Err(err) if err.is_panic() => Err(ReadReceiptDispatchError::Permanent(format!(
            "read receipt worker task panicked: {}",
            panic_payload_to_string(err.into_panic())
        ))),
        Err(err) => Err(ReadReceiptDispatchError::Retryable(format!(
            "read receipt worker task failed: {err}"
        ))),
    }
}

async fn get_capabilities(
    plugin: Arc<dyn ChannelPluginInstance>,
) -> Result<crate::plugins::ChannelCapabilities, BindingError> {
    tokio::task::spawn_blocking(move || plugin.get_capabilities())
        .await
        .map_err(|err| BindingError::CallError(err.to_string()))?
}

async fn invoke_start_typing(
    plugin: Arc<dyn ChannelPluginInstance>,
    ctx: TypingContext,
) -> Result<(), BindingError> {
    tokio::task::spawn_blocking(move || plugin.start_typing(ctx))
        .await
        .map_err(|err| BindingError::CallError(err.to_string()))?
}

async fn invoke_stop_typing(
    plugin: Arc<dyn ChannelPluginInstance>,
    ctx: TypingContext,
) -> Result<(), BindingError> {
    tokio::task::spawn_blocking(move || plugin.stop_typing(ctx))
        .await
        .map_err(|err| BindingError::CallError(err.to_string()))?
}

fn dispatch_read_receipt_blocking(
    plugin: Arc<dyn ChannelPluginInstance>,
    channel_id: &str,
    ctx: ReadReceiptContext,
) -> Result<(), ReadReceiptDispatchError> {
    match catch_unwind(AssertUnwindSafe(|| plugin.mark_read(ctx))) {
        Ok(Ok(())) => Ok(()),
        Ok(Err(err)) => Err(ReadReceiptDispatchError::Retryable(format!(
            "failed to send read receipt on channel '{channel_id}': {err}"
        ))),
        Err(payload) => Err(ReadReceiptDispatchError::Permanent(format!(
            "read receipt dispatcher panicked on channel '{channel_id}': {}",
            panic_payload_to_string(payload)
        ))),
    }
}

fn dispatch_stop_typing_blocking(
    plugin: Arc<dyn ChannelPluginInstance>,
    channel_id: &str,
    ctx: TypingContext,
    stop_states: &[Arc<AtomicU8>],
) {
    let result = catch_unwind(AssertUnwindSafe(|| plugin.stop_typing(ctx)));
    mark_stop_states_completed(stop_states);
    match result {
        Ok(Ok(())) => {}
        Ok(Err(err)) => {
            tracing::warn!(
                channel = %channel_id,
                error = %err,
                "failed to stop typing indicator after drop"
            );
        }
        Err(payload) => {
            tracing::warn!(
                channel = %channel_id,
                error = %panic_payload_to_string(payload),
                "stop typing dispatcher panicked"
            );
        }
    }
}

fn panic_payload_to_string(payload: Box<dyn Any + Send + 'static>) -> String {
    let payload = payload.as_ref();
    if let Some(message) = payload.downcast_ref::<&str>() {
        (*message).to_string()
    } else if let Some(message) = payload.downcast_ref::<String>() {
        message.clone()
    } else {
        "non-string panic payload".to_string()
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::sync::atomic::{AtomicU32, Ordering};

    use super::*;
    use crate::plugins::{ChannelCapabilities, ChannelInfo, DeliveryResult, OutboundContext};
    use tokio::sync::Notify;

    struct MockChannel {
        caps: ChannelCapabilities,
        start_typing_count: AtomicU32,
        stop_typing_count: AtomicU32,
        mark_read_count: AtomicU32,
        mark_read_started_notify: Option<Arc<Notify>>,
        mark_read_notify: Option<Arc<Notify>>,
        stop_typing_started_notify: Option<Arc<Notify>>,
        stop_typing_notify: Option<Arc<Notify>>,
        mark_read_delay: Duration,
        stop_typing_delay: Duration,
        panic_get_capabilities: bool,
        panic_mark_read_count: AtomicU32,
    }

    impl MockChannel {
        fn new(caps: ChannelCapabilities) -> Self {
            Self::with_stop_typing_notify(caps, None)
        }

        fn with_stop_typing_notify(
            caps: ChannelCapabilities,
            stop_typing_notify: Option<Arc<Notify>>,
        ) -> Self {
            Self {
                caps,
                start_typing_count: AtomicU32::new(0),
                stop_typing_count: AtomicU32::new(0),
                mark_read_count: AtomicU32::new(0),
                mark_read_started_notify: None,
                mark_read_notify: None,
                stop_typing_started_notify: None,
                stop_typing_notify,
                mark_read_delay: Duration::ZERO,
                stop_typing_delay: Duration::ZERO,
                panic_get_capabilities: false,
                panic_mark_read_count: AtomicU32::new(0),
            }
        }

        fn with_stop_typing_delay(caps: ChannelCapabilities, stop_typing_delay: Duration) -> Self {
            Self {
                stop_typing_delay,
                ..Self::with_stop_typing_notify(caps, None)
            }
        }

        fn with_stop_typing_delay_and_notify(
            caps: ChannelCapabilities,
            stop_typing_delay: Duration,
            stop_typing_notify: Arc<Notify>,
        ) -> Self {
            Self {
                stop_typing_delay,
                stop_typing_notify: Some(stop_typing_notify),
                ..Self::with_stop_typing_notify(caps, None)
            }
        }

        fn with_stop_typing_delay_and_started_notify(
            caps: ChannelCapabilities,
            stop_typing_delay: Duration,
            stop_typing_started_notify: Arc<Notify>,
        ) -> Self {
            Self {
                stop_typing_delay,
                stop_typing_started_notify: Some(stop_typing_started_notify),
                ..Self::with_stop_typing_notify(caps, None)
            }
        }

        fn with_panicking_mark_read(caps: ChannelCapabilities, panic_count: u32) -> Self {
            Self {
                panic_mark_read_count: AtomicU32::new(panic_count),
                ..Self::with_stop_typing_notify(caps, None)
            }
        }

        fn with_mark_read_delay(caps: ChannelCapabilities, mark_read_delay: Duration) -> Self {
            Self {
                mark_read_delay,
                ..Self::with_stop_typing_notify(caps, None)
            }
        }
    }

    impl ChannelPluginInstance for MockChannel {
        fn get_info(&self) -> Result<ChannelInfo, BindingError> {
            Ok(ChannelInfo {
                id: "mock".to_string(),
                label: "Mock".to_string(),
                selection_label: "Mock".to_string(),
                docs_path: String::new(),
                blurb: String::new(),
                order: 0,
            })
        }

        fn get_capabilities(&self) -> Result<crate::plugins::ChannelCapabilities, BindingError> {
            assert!(!self.panic_get_capabilities, "mock get_capabilities panic");
            Ok(self.caps.clone())
        }

        fn send_text(&self, _ctx: OutboundContext) -> Result<DeliveryResult, BindingError> {
            unreachable!()
        }

        fn send_media(&self, _ctx: OutboundContext) -> Result<DeliveryResult, BindingError> {
            unreachable!()
        }

        fn start_typing(&self, _ctx: TypingContext) -> Result<(), BindingError> {
            self.start_typing_count.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }

        fn stop_typing(&self, _ctx: TypingContext) -> Result<(), BindingError> {
            if let Some(notify) = &self.stop_typing_started_notify {
                notify.notify_one();
            }
            if !self.stop_typing_delay.is_zero() {
                std::thread::sleep(self.stop_typing_delay);
            }
            self.stop_typing_count.fetch_add(1, Ordering::Relaxed);
            if let Some(notify) = &self.stop_typing_notify {
                notify.notify_one();
            }
            Ok(())
        }

        fn mark_read(&self, _ctx: ReadReceiptContext) -> Result<(), BindingError> {
            if let Some(notify) = &self.mark_read_started_notify {
                notify.notify_one();
            }
            if self.panic_mark_read_count.load(Ordering::Relaxed) > 0 {
                self.panic_mark_read_count.fetch_sub(1, Ordering::Relaxed);
                panic!("mock mark_read panic");
            }
            if !self.mark_read_delay.is_zero() {
                std::thread::sleep(self.mark_read_delay);
            }
            self.mark_read_count.fetch_add(1, Ordering::Relaxed);
            if let Some(notify) = &self.mark_read_notify {
                notify.notify_one();
            }
            Ok(())
        }
    }

    #[test]
    fn test_resolve_channel_activity_policy_defaults_disabled() {
        let policy = resolve_channel_activity_policy(&serde_json::json!({}), "signal");
        assert!(!policy.typing.enabled);
        assert_eq!(
            policy.typing.interval_seconds,
            DEFAULT_TYPING_INTERVAL_SECONDS
        );
        assert!(!policy.read_receipts.enabled);
        assert_eq!(policy.read_receipts.mode, ReadReceiptMode::AfterResponse);
    }

    #[test]
    fn test_resolve_channel_activity_policy_uses_legacy_session_typing_fallback() {
        let policy = resolve_channel_activity_policy(
            &serde_json::json!({
                "session": {
                    "typingMode": "thinking",
                    "typingIntervalSeconds": 7
                }
            }),
            "signal",
        );
        assert!(policy.typing.enabled);
        assert_eq!(policy.typing.mode, TypingMode::Thinking);
        assert_eq!(policy.typing.interval_seconds, 7);
    }

    #[test]
    fn test_resolve_channel_activity_policy_channel_override_wins() {
        let policy = resolve_channel_activity_policy(
            &serde_json::json!({
                "session": {
                    "typingMode": "thinking",
                    "typingIntervalSeconds": 7
                },
                "channels": {
                    "defaults": {
                        "features": {
                            "typing": {
                                "enabled": true,
                                "intervalSeconds": 5
                            },
                            "readReceipts": {
                                "enabled": false
                            }
                        }
                    },
                    "signal": {
                        "features": {
                            "typing": {
                                "enabled": false,
                                "intervalSeconds": 11
                            },
                            "readReceipts": {
                                "enabled": true,
                                "mode": "after-response"
                            }
                        }
                    }
                }
            }),
            "signal",
        );
        assert!(!policy.typing.enabled);
        assert_eq!(policy.typing.interval_seconds, 11);
        assert!(policy.read_receipts.enabled);
    }

    #[test]
    fn test_load_channel_activity_policy_ignores_defaulted_legacy_typing() {
        let temp = tempfile::tempdir().unwrap();
        let config_path = temp.path().join("carapace.json5");
        fs::write(&config_path, "{}").unwrap();

        crate::config::clear_cache();
        let mut env_guard = crate::test_support::env::ScopedEnv::new();
        env_guard
            .set("CARAPACE_CONFIG_PATH", config_path.as_os_str())
            .set("CARAPACE_DISABLE_CONFIG_CACHE", "1");

        let policy = load_channel_activity_policy("signal");
        assert!(!policy.typing.enabled);
        assert_eq!(
            policy.typing.interval_seconds,
            DEFAULT_TYPING_INTERVAL_SECONDS
        );
    }

    #[test]
    fn test_load_channel_activity_policy_falls_back_to_defaults_on_load_error() {
        crate::config::clear_cache();
        let mut env_guard = crate::test_support::env::ScopedEnv::new();
        env_guard
            .set(
                "CARAPACE_CONFIG_PATH",
                std::path::Path::new("/definitely/missing/carapace.json5").as_os_str(),
            )
            .set("CARAPACE_DISABLE_CONFIG_CACHE", "1");

        let policy = load_channel_activity_policy("signal");
        assert!(!policy.typing.enabled);
        assert_eq!(
            policy.typing.interval_seconds,
            DEFAULT_TYPING_INTERVAL_SECONDS
        );
        assert!(!policy.read_receipts.enabled);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_load_channel_activity_policy_async_uses_cached_snapshot_without_disk_reload() {
        crate::config::clear_cache();
        let mut env_guard = crate::test_support::env::ScopedEnv::new();
        env_guard.set(
            "CARAPACE_CONFIG_PATH",
            std::path::Path::new("/definitely/missing/carapace.json5").as_os_str(),
        );

        crate::config::update_cache(
            serde_json::json!({
                "channels": {
                    "signal": {
                        "features": {
                            "typing": {
                                "enabled": true,
                                "intervalSeconds": 7
                            }
                        }
                    }
                }
            }),
            serde_json::json!({}),
        );

        let policy = load_channel_activity_policy_async("signal").await;
        assert!(policy.typing.enabled);
        assert_eq!(policy.typing.interval_seconds, 7);

        crate::config::clear_cache();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_load_channel_activity_policy_async_refreshes_stale_cache_from_disk() {
        crate::config::clear_cache();
        let temp = tempfile::tempdir().unwrap();
        let config_path = temp.path().join("carapace.json5");
        fs::write(
            &config_path,
            r#"{
                "channels": {
                    "signal": {
                        "features": {
                            "typing": {
                                "enabled": false
                            }
                        }
                    }
                }
            }"#,
        )
        .unwrap();

        let mut env_guard = crate::test_support::env::ScopedEnv::new();
        env_guard
            .set("CARAPACE_CONFIG_PATH", config_path.as_os_str())
            .unset("CARAPACE_DISABLE_CONFIG_CACHE")
            .set("CARAPACE_CONFIG_CACHE_MS", "1");

        crate::config::update_cache_for_test_with_age(
            serde_json::json!({
                "channels": {
                    "signal": {
                        "features": {
                            "typing": {
                                "enabled": true
                            }
                        }
                    }
                }
            }),
            serde_json::json!({}),
            Duration::from_secs(1),
        );

        let policy = load_channel_activity_policy_async("signal").await;
        assert!(!policy.typing.enabled);

        crate::config::clear_cache();
    }

    #[tokio::test]
    async fn test_maybe_start_typing_loop_drives_start_and_stop() {
        let plugin = Arc::new(MockChannel::new(ChannelCapabilities {
            typing_indicators: true,
            ..Default::default()
        }));
        let registry = Arc::new(PluginRegistry::new());
        registry.register_channel("signal".to_string(), plugin.clone());
        let policy = ChannelActivityPolicy {
            typing: TypingFeaturePolicy {
                enabled: true,
                interval_seconds: 1,
                ..Default::default()
            },
            ..Default::default()
        };

        let activity_service = Arc::new(ActivityService::new());
        let handle = maybe_start_typing_loop(
            registry,
            "signal",
            &policy,
            None,
            activity_service.clone(),
            TypingContext {
                to: "+15551234567".to_string(),
                ..Default::default()
            },
        )
        .await
        .expect("typing loop should start");

        tokio::time::sleep(Duration::from_millis(30)).await;
        handle.stop().await;

        assert!(plugin.start_typing_count.load(Ordering::Relaxed) >= 1);
        assert_eq!(plugin.stop_typing_count.load(Ordering::Relaxed), 1);
        activity_service.shutdown().await;
    }

    #[tokio::test]
    async fn test_maybe_start_typing_loop_drop_cancels_background_task() {
        let stop_typing_notify = Arc::new(Notify::new());
        let plugin = Arc::new(MockChannel::with_stop_typing_notify(
            ChannelCapabilities {
                typing_indicators: true,
                ..Default::default()
            },
            Some(stop_typing_notify.clone()),
        ));
        let registry = Arc::new(PluginRegistry::new());
        registry.register_channel("signal".to_string(), plugin.clone());
        let policy = ChannelActivityPolicy {
            typing: TypingFeaturePolicy {
                enabled: true,
                interval_seconds: 1,
                ..Default::default()
            },
            ..Default::default()
        };

        let activity_service = Arc::new(ActivityService::new());
        let handle = maybe_start_typing_loop(
            registry,
            "signal",
            &policy,
            None,
            activity_service.clone(),
            TypingContext {
                to: "+15551234567".to_string(),
                ..Default::default()
            },
        )
        .await
        .expect("typing loop should start");

        drop(handle);
        tokio::time::timeout(Duration::from_secs(1), stop_typing_notify.notified())
            .await
            .expect("drop should stop typing promptly");

        assert!(plugin.start_typing_count.load(Ordering::Relaxed) >= 1);
        assert_eq!(plugin.stop_typing_count.load(Ordering::Relaxed), 1);
        activity_service.shutdown().await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_maybe_start_typing_loop_drop_cancels_background_task_current_thread() {
        let stop_typing_notify = Arc::new(Notify::new());
        let plugin = Arc::new(MockChannel::with_stop_typing_notify(
            ChannelCapabilities {
                typing_indicators: true,
                ..Default::default()
            },
            Some(stop_typing_notify.clone()),
        ));
        let registry = Arc::new(PluginRegistry::new());
        registry.register_channel("signal".to_string(), plugin.clone());
        let policy = ChannelActivityPolicy {
            typing: TypingFeaturePolicy {
                enabled: true,
                interval_seconds: 1,
                ..Default::default()
            },
            ..Default::default()
        };

        let activity_service = Arc::new(ActivityService::new());
        let handle = maybe_start_typing_loop(
            registry,
            "signal",
            &policy,
            None,
            activity_service.clone(),
            TypingContext {
                to: "+15551234567".to_string(),
                ..Default::default()
            },
        )
        .await
        .expect("typing loop should start");

        drop(handle);
        tokio::time::timeout(Duration::from_secs(1), stop_typing_notify.notified())
            .await
            .expect("drop should stop typing promptly on current-thread runtimes");
        tokio::task::yield_now().await;

        assert!(plugin.start_typing_count.load(Ordering::Relaxed) >= 1);
        assert_eq!(plugin.stop_typing_count.load(Ordering::Relaxed), 1);
        activity_service.shutdown().await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_maybe_start_typing_loop_drop_does_not_block_current_thread_runtime() {
        let stop_typing_notify = Arc::new(Notify::new());
        let plugin = Arc::new(MockChannel::with_stop_typing_delay_and_notify(
            ChannelCapabilities {
                typing_indicators: true,
                ..Default::default()
            },
            Duration::from_millis(250),
            stop_typing_notify.clone(),
        ));
        let registry = Arc::new(PluginRegistry::new());
        registry.register_channel("signal".to_string(), plugin.clone());
        let policy = ChannelActivityPolicy {
            typing: TypingFeaturePolicy {
                enabled: true,
                interval_seconds: 1,
                ..Default::default()
            },
            ..Default::default()
        };

        let activity_service = Arc::new(ActivityService::new());
        let handle = maybe_start_typing_loop(
            registry,
            "signal",
            &policy,
            None,
            activity_service.clone(),
            TypingContext {
                to: "+15551234567".to_string(),
                ..Default::default()
            },
        )
        .await
        .expect("typing loop should start");

        drop(handle);
        assert_eq!(
            plugin.stop_typing_count.load(Ordering::Relaxed),
            0,
            "drop should return before slow stop_typing completes"
        );
        tokio::time::timeout(Duration::from_secs(1), stop_typing_notify.notified())
            .await
            .expect("drop should still schedule stop_typing asynchronously");
        assert_eq!(plugin.stop_typing_count.load(Ordering::Relaxed), 1);
        activity_service.shutdown().await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_maybe_start_typing_loop_drop_stops_when_cleanup_was_only_reserved() {
        let stop_typing_notify = Arc::new(Notify::new());
        let plugin = Arc::new(MockChannel::with_stop_typing_notify(
            ChannelCapabilities {
                typing_indicators: true,
                ..Default::default()
            },
            Some(stop_typing_notify.clone()),
        ));
        let registry = Arc::new(PluginRegistry::new());
        registry.register_channel("signal".to_string(), plugin.clone());
        let policy = ChannelActivityPolicy {
            typing: TypingFeaturePolicy {
                enabled: true,
                interval_seconds: 1,
                ..Default::default()
            },
            ..Default::default()
        };

        let activity_service = Arc::new(ActivityService::new());
        let handle = maybe_start_typing_loop(
            registry,
            "signal",
            &policy,
            None,
            activity_service.clone(),
            TypingContext {
                to: "+15551234567".to_string(),
                ..Default::default()
            },
        )
        .await
        .expect("typing loop should start");

        handle
            .stop_state
            .store(STOP_STATE_TASK_RESERVED, Ordering::Release);
        drop(handle);
        tokio::time::timeout(Duration::from_secs(1), stop_typing_notify.notified())
            .await
            .expect("drop should still stop typing when task cleanup was only reserved");
        tokio::task::yield_now().await;

        assert_eq!(plugin.stop_typing_count.load(Ordering::Relaxed), 1);
        activity_service.shutdown().await;
    }

    #[tokio::test]
    async fn test_finish_typing_task_recovers_from_panicked_task() {
        let stop_typing_notify = Arc::new(Notify::new());
        let plugin = Arc::new(MockChannel::with_stop_typing_notify(
            ChannelCapabilities {
                typing_indicators: true,
                ..Default::default()
            },
            Some(stop_typing_notify.clone()),
        ));
        let task = tokio::spawn(async move {
            panic!("mock typing task panic");
        });

        let result = finish_typing_task(
            task,
            plugin.clone(),
            TypingContext {
                to: "+15551234567".to_string(),
                ..Default::default()
            },
            Arc::new(AtomicU8::new(STOP_STATE_NOT_REQUESTED)),
        )
        .await;

        let err = result.expect_err("panicked task should report fallback cleanup");
        assert!(
            err.contains("sent fallback stop_typing"),
            "expected fallback stop_typing diagnostic, got: {err}"
        );
        tokio::time::timeout(Duration::from_secs(1), stop_typing_notify.notified())
            .await
            .expect("panicked task should still trigger fallback stop_typing");

        assert_eq!(plugin.stop_typing_count.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_stop_fallback_needed_skips_when_task_stop_worker_is_running() {
        let stop_state = AtomicU8::new(STOP_STATE_TASK_RUNNING);
        assert!(!stop_fallback_needed(&stop_state));
        assert_eq!(stop_state.load(Ordering::Acquire), STOP_STATE_TASK_RUNNING);
    }

    #[test]
    fn test_stop_fallback_needed_claims_reserved_state() {
        let stop_state = AtomicU8::new(STOP_STATE_TASK_RESERVED);
        assert!(stop_fallback_needed(&stop_state));
        assert_eq!(
            stop_state.load(Ordering::Acquire),
            STOP_STATE_FALLBACK_RESERVED
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_invoke_stop_typing_marks_completed_even_if_waiter_is_aborted() {
        let plugin = Arc::new(MockChannel::with_stop_typing_delay(
            ChannelCapabilities {
                typing_indicators: true,
                ..Default::default()
            },
            Duration::from_millis(50),
        ));
        let stop_state = Arc::new(AtomicU8::new(STOP_STATE_TASK_RESERVED));
        let task = tokio::spawn(invoke_stop_typing_with_running_state(
            plugin.clone(),
            TypingContext {
                to: "+15551234567".to_string(),
                ..Default::default()
            },
            stop_state.clone(),
        ));

        tokio::time::timeout(Duration::from_secs(1), async {
            while stop_state.load(Ordering::Acquire) != STOP_STATE_TASK_RUNNING {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("stop worker should enter TASK_RUNNING");

        task.abort();
        tokio::time::sleep(Duration::from_millis(100)).await;

        assert_eq!(plugin.stop_typing_count.load(Ordering::Relaxed), 1);
        assert_eq!(stop_state.load(Ordering::Acquire), STOP_STATE_COMPLETED);
    }

    #[test]
    fn test_spawn_stop_typing_worker_requires_reserved_state() {
        let plugin = Arc::new(MockChannel::new(ChannelCapabilities {
            typing_indicators: true,
            ..Default::default()
        }));
        let stop_state = Arc::new(AtomicU8::new(STOP_STATE_COMPLETED));
        let worker = spawn_stop_typing_worker(
            plugin,
            TypingContext {
                to: "+15551234567".to_string(),
                ..Default::default()
            },
            stop_state.clone(),
        );

        assert!(worker.is_none());
        assert_eq!(stop_state.load(Ordering::Acquire), STOP_STATE_COMPLETED);
    }

    #[test]
    fn test_stop_fallback_needed_preserves_completed_state() {
        let stop_state = AtomicU8::new(STOP_STATE_COMPLETED);
        assert!(!stop_fallback_needed(&stop_state));
        assert_eq!(stop_state.load(Ordering::Acquire), STOP_STATE_COMPLETED);
    }

    #[test]
    fn test_stop_fallback_needed_preserves_fallback_reserved_state() {
        let stop_state = AtomicU8::new(STOP_STATE_FALLBACK_RESERVED);
        assert!(!stop_fallback_needed(&stop_state));
        assert_eq!(
            stop_state.load(Ordering::Acquire),
            STOP_STATE_FALLBACK_RESERVED
        );
    }

    #[test]
    fn test_typing_refresh_retry_delay_backs_off_and_caps() {
        let base = Duration::from_secs(2);
        assert_eq!(typing_refresh_retry_delay(base, 0), Duration::from_secs(2));
        assert_eq!(typing_refresh_retry_delay(base, 1), Duration::from_secs(2));
        assert_eq!(typing_refresh_retry_delay(base, 2), Duration::from_secs(4));
        assert_eq!(typing_refresh_retry_delay(base, 3), Duration::from_secs(8));
        assert_eq!(
            typing_refresh_retry_delay(base, 10),
            Duration::from_secs(30)
        );
    }

    #[test]
    fn test_next_typing_refresh_deadline_stays_on_wall_clock_cadence() {
        let start = tokio::time::Instant::now();
        let cadence = Duration::from_secs(3);

        let next =
            next_typing_refresh_deadline(start + cadence, cadence, start + Duration::from_secs(7));

        assert_eq!(next, start + Duration::from_secs(9));
    }

    #[test]
    fn test_should_log_typing_refresh_failure_throttles_noise() {
        assert!(should_log_typing_refresh_failure(1));
        assert!(should_log_typing_refresh_failure(2));
        assert!(should_log_typing_refresh_failure(3));
        assert!(should_log_typing_refresh_failure(4));
        assert!(!should_log_typing_refresh_failure(5));
        assert!(should_log_typing_refresh_failure(8));
    }

    #[test]
    fn test_stop_typing_dispatcher_does_not_drop_bursty_distinct_cleanup_requests() {
        let dispatcher = ActivityDispatcher::with_backlog_warning_threshold(1);
        let plugin = Arc::new(MockChannel::with_stop_typing_delay(
            ChannelCapabilities {
                typing_indicators: true,
                ..Default::default()
            },
            Duration::from_millis(10),
        ));
        let stop_states = (0..32_u32)
            .map(|recipient_index| {
                (
                    recipient_index,
                    Arc::new(AtomicU8::new(STOP_STATE_FALLBACK_RESERVED)),
                )
            })
            .collect::<Vec<_>>();

        for (recipient_index, stop_state) in &stop_states {
            dispatcher.dispatch_stop_typing(
                plugin.clone(),
                "signal",
                TypingContext {
                    to: format!("+1555123{recipient_index:04}"),
                    ..Default::default()
                },
                stop_state.clone(),
            );
        }

        std::thread::sleep(Duration::from_millis(500));
        dispatcher.shutdown();

        assert_eq!(plugin.stop_typing_count.load(Ordering::Relaxed), 32);
        assert!(stop_states
            .iter()
            .all(|(_, state)| state.load(Ordering::Acquire) == STOP_STATE_COMPLETED));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_stop_typing_dispatcher_coalesces_duplicate_recipient_cleanup_requests() {
        let stop_typing_started_notify = Arc::new(Notify::new());
        let dispatcher = ActivityDispatcher::with_backlog_warning_threshold(1);
        let plugin = Arc::new(MockChannel::with_stop_typing_delay_and_started_notify(
            ChannelCapabilities {
                typing_indicators: true,
                ..Default::default()
            },
            Duration::from_millis(50),
            stop_typing_started_notify.clone(),
        ));

        let first_stop_state = Arc::new(AtomicU8::new(STOP_STATE_FALLBACK_RESERVED));
        dispatcher.dispatch_stop_typing(
            plugin.clone(),
            "signal",
            TypingContext {
                to: "+15551234567".to_string(),
                ..Default::default()
            },
            first_stop_state.clone(),
        );

        tokio::time::timeout(
            Duration::from_secs(1),
            stop_typing_started_notify.notified(),
        )
        .await
        .expect("first stop_typing call should start");

        let additional_stop_states = (0..8)
            .map(|_| Arc::new(AtomicU8::new(STOP_STATE_FALLBACK_RESERVED)))
            .collect::<Vec<_>>();

        for stop_state in &additional_stop_states {
            dispatcher.dispatch_stop_typing(
                plugin.clone(),
                "signal",
                TypingContext {
                    to: "+15551234567".to_string(),
                    ..Default::default()
                },
                stop_state.clone(),
            );
        }

        dispatcher.shutdown();

        assert_eq!(
            plugin.stop_typing_count.load(Ordering::Relaxed),
            2,
            "duplicate recipient cleanup should coalesce into one in-flight call plus one rerun"
        );
        assert_eq!(
            first_stop_state.load(Ordering::Acquire),
            STOP_STATE_COMPLETED
        );
        assert!(additional_stop_states
            .iter()
            .all(|state| state.load(Ordering::Acquire) == STOP_STATE_COMPLETED));
    }

    #[tokio::test]
    async fn test_send_verified_read_receipt_marks_read() {
        let plugin = Arc::new(MockChannel::new(ChannelCapabilities {
            read_receipts: true,
            ..Default::default()
        }));
        send_verified_read_receipt_with_plugin(
            plugin.clone(),
            "signal",
            ReadReceiptContext {
                recipient: "+15551234567".to_string(),
                timestamp: Some(123),
                ..Default::default()
            },
        )
        .await
        .expect("read receipt dispatch should succeed");

        assert_eq!(plugin.mark_read_count.load(Ordering::Relaxed), 1);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_send_verified_read_receipt_reports_plugin_panic_as_permanent_failure() {
        let plugin = Arc::new(MockChannel {
            ..MockChannel::with_panicking_mark_read(
                ChannelCapabilities {
                    read_receipts: true,
                    ..Default::default()
                },
                1,
            )
        });

        let err = send_verified_read_receipt_with_plugin(
            plugin,
            "signal",
            ReadReceiptContext {
                recipient: "+15551234567".to_string(),
                timestamp: Some(123),
                ..Default::default()
            },
        )
        .await
        .expect_err("plugin panic should report a permanent dispatch failure");

        assert!(matches!(err, ReadReceiptDispatchError::Permanent(_)));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_send_verified_read_receipt_waits_for_slow_io() {
        let plugin = Arc::new(MockChannel::with_mark_read_delay(
            ChannelCapabilities {
                read_receipts: true,
                ..Default::default()
            },
            Duration::from_millis(150),
        ));

        let started_at = std::time::Instant::now();
        send_verified_read_receipt_with_plugin(
            plugin.clone(),
            "signal",
            ReadReceiptContext {
                recipient: "+15551234567".to_string(),
                timestamp: Some(1),
                ..Default::default()
            },
        )
        .await
        .expect("slow read receipt should still succeed");

        assert!(
            started_at.elapsed() >= Duration::from_millis(100),
            "direct read receipt dispatch should reflect the underlying slow I/O"
        );
        assert_eq!(plugin.mark_read_count.load(Ordering::Relaxed), 1);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_read_receipt_task_executor_fails_when_capability_disappears_after_activation() {
        let plugin_registry = Arc::new(PluginRegistry::new());
        plugin_registry.register_channel(
            "signal".to_string(),
            Arc::new(MockChannel::new(ChannelCapabilities::default())),
        );
        let state = Arc::new(
            crate::server::ws::WsServerState::new(crate::server::ws::WsServerConfig::default())
                .with_plugin_registry(plugin_registry),
        );
        let executor = ReadReceiptTaskExecutor {
            state: state.clone(),
        };

        let task = state
            .activity_service()
            .read_receipt_queue()
            .enqueue_async(
                serde_json::to_value(ReadReceiptTaskPayload::new(
                    "signal",
                    ReadReceiptContext {
                        recipient: "+15551234567".to_string(),
                        timestamp: Some(123),
                        ..Default::default()
                    },
                ))
                .expect("read receipt payload should serialize"),
                None,
            )
            .await;
        let claimed = state
            .activity_service()
            .read_receipt_queue()
            .claim_due(crate::time::unix_now_ms_u64(), 1);
        assert_eq!(claimed.len(), 1);
        assert_eq!(claimed[0].id, task.id);

        let outcome = executor.execute(claimed[0].clone()).await;

        match outcome {
            TaskExecutionOutcome::Failed { error } => {
                assert!(
                    error.contains("does not support read receipts after activation"),
                    "unexpected failure message: {error}"
                );
            }
            other => panic!("expected terminal failure, got {other:?}"),
        }
    }

    #[test]
    fn test_reset_unsupported_activity_feature_warnings_for_test_clears_seen_keys() {
        let service = ActivityService::new();
        service.reset_unsupported_activity_feature_warnings_for_test();
        service.warn_unsupported_feature("signal", "typing");
        assert!(service
            .unsupported_feature_warnings
            .lock()
            .seen_at
            .contains_key("signal:typing"));

        service.reset_unsupported_activity_feature_warnings_for_test();
        assert!(service
            .unsupported_feature_warnings
            .lock()
            .seen_at
            .is_empty());
    }

    #[test]
    fn test_unsupported_activity_warning_registry_rewarns_after_cooldown() {
        let mut registry =
            UnsupportedActivityWarningRegistry::with_cooldown_for_test(Duration::from_secs(1));
        let start = Instant::now();

        assert!(registry.should_warn("signal:typing", start));
        assert!(!registry.should_warn("signal:typing", start + Duration::from_millis(500)));
        assert!(registry.should_warn("signal:typing", start + Duration::from_secs(2)));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_collect_configured_unsupported_features_for_registered_channels() {
        crate::config::clear_cache();
        crate::config::update_cache(
            serde_json::json!({
                "channels": {
                    "custom": {
                        "features": {
                            "typing": { "enabled": true },
                            "readReceipts": { "enabled": true },
                        }
                    }
                }
            }),
            serde_json::json!({
                "channels": {
                    "custom": {
                        "features": {
                            "typing": { "enabled": true },
                            "readReceipts": { "enabled": true },
                        }
                    }
                }
            }),
        );

        let plugin_registry = Arc::new(PluginRegistry::new());
        plugin_registry.register_channel(
            "custom".to_string(),
            Arc::new(MockChannel::new(ChannelCapabilities::default())),
        );

        let unsupported =
            collect_configured_unsupported_features_for_registered_channels(plugin_registry).await;

        assert!(unsupported.contains(&("custom".to_string(), "typing")));
        assert!(unsupported.contains(&("custom".to_string(), "read_receipts")));
        crate::config::clear_cache();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_can_accept_read_receipt_ownership_disables_new_obligations_at_high_watermark() {
        let service = ActivityService::with_limits_for_test(8, 2);
        assert!(service.can_accept_read_receipt_ownership("signal"));

        let first = service
            .enqueue_after_response_read_receipt(
                "signal",
                ReadReceiptContext {
                    recipient: "+15551230001".to_string(),
                    timestamp: Some(1),
                    ..Default::default()
                },
            )
            .await;
        let second = service
            .enqueue_after_response_read_receipt(
                "signal",
                ReadReceiptContext {
                    recipient: "+15551230002".to_string(),
                    timestamp: Some(2),
                    ..Default::default()
                },
            )
            .await;

        assert!(first.is_some());
        assert!(second.is_some());
        assert!(
            !service.can_accept_read_receipt_ownership("signal"),
            "new ownership should stop once the durable backlog reaches the high-water mark"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_cleanup_orphaned_blocked_read_receipts_after_restart_cancels_pending_tasks() {
        let service = ActivityService::new();
        let orphaned = service
            .read_receipt_queue()
            .enqueue_blocked_async_with_policy(
                serde_json::to_value(ReadReceiptTaskPayload::new(
                    "signal",
                    ReadReceiptContext {
                        recipient: "+15551234567".to_string(),
                        timestamp: Some(123),
                        ..Default::default()
                    },
                ))
                .expect("read receipt task payload should serialize"),
                READ_RECEIPT_PENDING_REASON,
                TaskBlockedReason::ExternalDependency,
                crate::tasks::TaskPolicy::default(),
            )
            .await;
        let retained = service
            .read_receipt_queue()
            .enqueue_async(
                serde_json::to_value(ReadReceiptTaskPayload::new(
                    "signal",
                    ReadReceiptContext {
                        recipient: "+15557654321".to_string(),
                        timestamp: Some(456),
                        ..Default::default()
                    },
                ))
                .expect("read receipt task payload should serialize"),
                None,
            )
            .await;

        let cancelled = service
            .cleanup_orphaned_blocked_read_receipts_after_restart()
            .await
            .expect("startup orphan cleanup should succeed");
        assert_eq!(cancelled, 1);

        let orphaned_task = service
            .read_receipt_queue()
            .get(&orphaned.id)
            .expect("orphaned task should still be present for audit");
        assert_eq!(orphaned_task.state, crate::tasks::TaskState::Cancelled);

        let retained_task = service
            .read_receipt_queue()
            .get(&retained.id)
            .expect("queued task should remain present");
        assert_eq!(retained_task.state, crate::tasks::TaskState::Queued);
    }
}
