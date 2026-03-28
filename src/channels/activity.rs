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
//! - activity-capable channel implementations must bound their own blocking
//!   I/O; the dispatcher does not spawn detached per-operation timeout threads.
//! - config reload only affects future polls/messages because each receive loop
//!   iteration snapshots its activity policy before polling and dispatch.

use std::any::Any;
use std::collections::HashMap;
use std::panic::{catch_unwind, resume_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};
use std::sync::mpsc as sync_mpsc;
use std::sync::{Arc, LazyLock};
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

const DEFAULT_TYPING_INTERVAL_SECONDS: u32 = 3;
const MAX_TYPING_REFRESH_BACKOFF_SECONDS: u64 = 30;
const ACTIVITY_DISPATCH_BACKLOG_WARNING_THRESHOLD: usize = 64;
// This budget must stay at or above the longest built-in activity operation
// timeout so graceful shutdown drains already-queued work instead of routinely
// dropping it. It currently matches Signal's bounded typing timeout.
const ACTIVITY_DISPATCH_SHUTDOWN_GRACE_MS: u64 =
    crate::channels::signal::SIGNAL_HTTP_TYPING_TIMEOUT_SECS * 1000;
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

static UNSUPPORTED_ACTIVITY_FEATURE_WARNINGS: LazyLock<Mutex<UnsupportedActivityWarningRegistry>> =
    LazyLock::new(|| Mutex::new(UnsupportedActivityWarningRegistry::default()));

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum TypingMode {
    #[default]
    Thinking,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum ReadReceiptMode {
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

// Read-receipt requests are only enqueued after policy/capability checks pass
// on the async path, so the worker can execute mark_read directly.
struct VerifiedReadReceiptDispatchRequest {
    plugin: Arc<dyn ChannelPluginInstance>,
    channel_id: String,
    ctx: ReadReceiptContext,
}

struct StopTypingDispatchRequest {
    plugin: Arc<dyn ChannelPluginInstance>,
    channel_id: String,
    ctx: TypingContext,
    stop_state: Arc<AtomicU8>,
}

pub struct ActivityDispatcher {
    read_receipt_tx: Mutex<Option<sync_mpsc::Sender<VerifiedReadReceiptDispatchRequest>>>,
    read_receipt_worker: Mutex<Option<thread::JoinHandle<()>>>,
    stop_typing_tx: Mutex<Option<sync_mpsc::Sender<StopTypingDispatchRequest>>>,
    stop_typing_worker: Mutex<Option<thread::JoinHandle<()>>>,
    read_receipt_backlog: Arc<AtomicUsize>,
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
        let read_receipt_backlog = Arc::new(AtomicUsize::new(0));
        let stop_typing_backlog = Arc::new(AtomicUsize::new(0));
        let shutting_down = Arc::new(AtomicBool::new(false));
        let shutdown_deadline = Arc::new(Mutex::new(None));

        // Once upstream auto-receipts are disabled, Carapace owns explicit
        // read-receipt delivery for the message. Keep this queue non-lossy so
        // slow receipt I/O cannot silently drop acknowledgements; observe
        // backlog growth instead of dropping work.
        let (read_receipt_tx, read_receipt_rx) =
            sync_mpsc::channel::<VerifiedReadReceiptDispatchRequest>();
        let read_receipt_backlog_worker = read_receipt_backlog.clone();
        let read_receipt_shutdown = shutting_down.clone();
        let read_receipt_deadline = shutdown_deadline.clone();
        let read_receipt_worker = thread::Builder::new()
            .name("carapace-read-receipts".to_string())
            .spawn(move || {
                while let Ok(request) = read_receipt_rx.recv() {
                    read_receipt_backlog_worker.fetch_sub(1, Ordering::AcqRel);
                    if should_drop_activity_work(
                        read_receipt_shutdown.as_ref(),
                        &read_receipt_deadline,
                    ) {
                        log_dropped_read_receipt_after_shutdown(&request.channel_id, &request.ctx);
                        continue;
                    }
                    dispatch_read_receipt_blocking(
                        request.plugin,
                        &request.channel_id,
                        request.ctx,
                    );
                }
            })
            .expect("failed to spawn read receipt dispatcher thread");

        let (stop_typing_tx, stop_typing_rx) = sync_mpsc::channel::<StopTypingDispatchRequest>();
        let stop_typing_backlog_worker = stop_typing_backlog.clone();
        let stop_typing_shutdown = shutting_down.clone();
        let stop_typing_deadline = shutdown_deadline.clone();
        let stop_typing_worker = thread::Builder::new()
            .name("carapace-stop-typing".to_string())
            .spawn(move || {
                // Stop-typing is cleanup, not optional side work. Keep this
                // queue non-lossy so completion bursts cannot drop stop
                // signals; the queue is still naturally bounded by the number
                // of active typing loops in the runtime.
                while let Ok(request) = stop_typing_rx.recv() {
                    stop_typing_backlog_worker.fetch_sub(1, Ordering::AcqRel);
                    if should_drop_activity_work(
                        stop_typing_shutdown.as_ref(),
                        &stop_typing_deadline,
                    ) {
                        mark_stop_completed(request.stop_state.as_ref());
                        log_dropped_stop_typing_after_shutdown(&request.channel_id, &request.ctx);
                        continue;
                    }
                    dispatch_stop_typing_blocking(
                        request.plugin,
                        &request.channel_id,
                        request.ctx,
                        request.stop_state,
                    );
                }
            })
            .expect("failed to spawn stop typing dispatcher thread");

        Self {
            read_receipt_tx: Mutex::new(Some(read_receipt_tx)),
            read_receipt_worker: Mutex::new(Some(read_receipt_worker)),
            stop_typing_tx: Mutex::new(Some(stop_typing_tx)),
            stop_typing_worker: Mutex::new(Some(stop_typing_worker)),
            read_receipt_backlog,
            stop_typing_backlog,
            backlog_warning_threshold,
            shutting_down,
            shutdown_deadline,
        }
    }

    pub fn dispatch_verified_read_receipt(
        &self,
        plugin: Arc<dyn ChannelPluginInstance>,
        channel_id: &str,
        ctx: ReadReceiptContext,
    ) {
        let request = VerifiedReadReceiptDispatchRequest {
            plugin,
            channel_id: channel_id.to_string(),
            ctx,
        };
        let Some(sender) = self.read_receipt_tx.lock().as_ref().cloned() else {
            tracing::warn!(
                channel = %channel_id,
                "read receipt dispatcher is shut down; dropping read receipt"
            );
            return;
        };

        let backlog = self.read_receipt_backlog.fetch_add(1, Ordering::AcqRel) + 1;
        log_activity_backlog_if_needed(
            "read receipt",
            channel_id,
            backlog,
            self.backlog_warning_threshold,
        );

        match sender.send(request) {
            Ok(()) => {}
            Err(sync_mpsc::SendError(_)) => {
                self.read_receipt_backlog.fetch_sub(1, Ordering::AcqRel);
                tracing::warn!(
                    channel = %channel_id,
                    "read receipt dispatcher is shut down; dropping read receipt"
                );
            }
        }
    }

    pub fn dispatch_stop_typing(
        &self,
        plugin: Arc<dyn ChannelPluginInstance>,
        channel_id: &str,
        ctx: TypingContext,
        stop_state: Arc<AtomicU8>,
    ) {
        let request = StopTypingDispatchRequest {
            plugin,
            channel_id: channel_id.to_string(),
            ctx,
            stop_state: stop_state.clone(),
        };
        let Some(sender) = self.stop_typing_tx.lock().as_ref().cloned() else {
            mark_stop_completed(stop_state.as_ref());
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

        match sender.send(request) {
            Ok(()) => {}
            Err(sync_mpsc::SendError(request)) => {
                self.stop_typing_backlog.fetch_sub(1, Ordering::AcqRel);
                mark_stop_completed(request.stop_state.as_ref());
                tracing::warn!(
                    channel = %channel_id,
                    "stop typing dispatcher is shut down; dropping implicit stop request"
                );
            }
        }
    }

    pub(crate) fn shutdown(&self) {
        self.shutdown_with_deadline(Duration::from_millis(ACTIVITY_DISPATCH_SHUTDOWN_GRACE_MS));
    }

    #[cfg(test)]
    pub(crate) fn shutdown_for_test(&self, grace: Duration) {
        self.shutdown_with_deadline(grace);
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
        self.read_receipt_tx.lock().take();
        self.stop_typing_tx.lock().take();

        if let Some(worker) = self.read_receipt_worker.lock().take() {
            join_activity_worker(worker, "read receipt");
        }

        if let Some(worker) = self.stop_typing_worker.lock().take() {
            join_activity_worker(worker, "stop typing");
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
            Ok(_) => {
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
            Err(_) => {
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
    activity_dispatcher: Arc<ActivityDispatcher>,
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
        warn_unsupported_activity_feature(channel_id, "typing");
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
        activity_dispatcher,
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

fn log_dropped_read_receipt_after_shutdown(channel_id: &str, ctx: &ReadReceiptContext) {
    tracing::warn!(
        channel = %channel_id,
        recipient = %ctx.recipient,
        timestamp = ?ctx.timestamp,
        "dropped queued read receipt after activity shutdown deadline"
    );
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

#[cfg(test)]
async fn send_verified_read_receipt_with_plugin(
    plugin: Arc<dyn ChannelPluginInstance>,
    channel_id: &str,
    ctx: ReadReceiptContext,
) {
    let channel_id = channel_id.to_string();
    let worker_channel_id = channel_id.clone();
    match tokio::task::spawn_blocking(move || {
        dispatch_read_receipt_blocking(plugin, &worker_channel_id, ctx);
    })
    .await
    {
        Ok(()) => {}
        Err(err) if err.is_panic() => {
            tracing::warn!(
                channel = %channel_id,
                error = %panic_payload_to_string(err.into_panic()),
                "read receipt worker task panicked"
            );
        }
        Err(err) => tracing::warn!(error = %err, "read receipt worker task failed"),
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
) {
    match catch_unwind(AssertUnwindSafe(|| plugin.mark_read(ctx))) {
        Ok(Ok(())) => {}
        Ok(Err(err)) => {
            tracing::warn!(channel = %channel_id, error = %err, "failed to send read receipt");
        }
        Err(payload) => {
            tracing::warn!(
                channel = %channel_id,
                error = %panic_payload_to_string(payload),
                "read receipt dispatcher panicked"
            );
        }
    }
}

fn dispatch_stop_typing_blocking(
    plugin: Arc<dyn ChannelPluginInstance>,
    channel_id: &str,
    ctx: TypingContext,
    stop_state: Arc<AtomicU8>,
) {
    let result = catch_unwind(AssertUnwindSafe(|| plugin.stop_typing(ctx)));
    mark_stop_completed(stop_state.as_ref());
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

pub(crate) fn warn_unsupported_activity_feature(channel_id: &str, feature: &str) {
    let key = format!("{channel_id}:{feature}");
    let should_warn = {
        let mut registry = UNSUPPORTED_ACTIVITY_FEATURE_WARNINGS.lock();
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

#[cfg(test)]
fn reset_unsupported_activity_feature_warnings_for_test() {
    UNSUPPORTED_ACTIVITY_FEATURE_WARNINGS.lock().reset();
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
        mark_read_notify: Option<Arc<Notify>>,
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
                mark_read_notify: None,
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

        fn with_panicking_capabilities(caps: ChannelCapabilities) -> Self {
            Self {
                panic_get_capabilities: true,
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

        let dispatcher = Arc::new(ActivityDispatcher::new());
        let handle = maybe_start_typing_loop(
            registry,
            "signal",
            &policy,
            None,
            dispatcher.clone(),
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
        dispatcher.shutdown();
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

        let dispatcher = Arc::new(ActivityDispatcher::new());
        let handle = maybe_start_typing_loop(
            registry,
            "signal",
            &policy,
            None,
            dispatcher.clone(),
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
        dispatcher.shutdown();
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

        let dispatcher = Arc::new(ActivityDispatcher::new());
        let handle = maybe_start_typing_loop(
            registry,
            "signal",
            &policy,
            None,
            dispatcher.clone(),
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
        dispatcher.shutdown();
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

        let dispatcher = Arc::new(ActivityDispatcher::new());
        let handle = maybe_start_typing_loop(
            registry,
            "signal",
            &policy,
            None,
            dispatcher.clone(),
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
        dispatcher.shutdown();
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

        let dispatcher = Arc::new(ActivityDispatcher::new());
        let handle = maybe_start_typing_loop(
            registry,
            "signal",
            &policy,
            None,
            dispatcher.clone(),
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
        dispatcher.shutdown();
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
    fn test_activity_dispatcher_shutdown_waits_for_inflight_bounded_operation() {
        let dispatcher = ActivityDispatcher::with_options(8);
        let plugin = Arc::new(MockChannel::with_mark_read_delay(
            ChannelCapabilities {
                read_receipts: true,
                ..Default::default()
            },
            Duration::from_millis(25),
        ));
        dispatcher.dispatch_verified_read_receipt(
            plugin.clone(),
            "signal",
            ReadReceiptContext {
                recipient: "+15551234567".to_string(),
                timestamp: Some(123),
                ..Default::default()
            },
        );
        let started_at = std::time::Instant::now();
        dispatcher.shutdown();

        assert!(
            started_at.elapsed() >= Duration::from_millis(20),
            "shutdown should wait for the in-flight bounded activity operation"
        );
        assert_eq!(plugin.mark_read_count.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_activity_dispatcher_shutdown_drains_queued_read_receipts_until_deadline() {
        let dispatcher = ActivityDispatcher::with_options(8);
        let plugin = Arc::new(MockChannel::with_mark_read_delay(
            ChannelCapabilities {
                read_receipts: true,
                ..Default::default()
            },
            Duration::from_millis(5),
        ));

        for timestamp in 0..4_u64 {
            dispatcher.dispatch_verified_read_receipt(
                plugin.clone(),
                "signal",
                ReadReceiptContext {
                    recipient: "+15551234567".to_string(),
                    timestamp: Some(timestamp),
                    ..Default::default()
                },
            );
        }

        dispatcher.shutdown_for_test(Duration::from_millis(100));

        assert_eq!(plugin.mark_read_count.load(Ordering::Relaxed), 4);
    }

    #[test]
    fn test_stop_typing_dispatcher_does_not_drop_bursty_cleanup_requests() {
        let dispatcher = ActivityDispatcher::with_backlog_warning_threshold(1);
        let plugin = Arc::new(MockChannel::with_stop_typing_delay(
            ChannelCapabilities {
                typing_indicators: true,
                ..Default::default()
            },
            Duration::from_millis(10),
        ));
        let stop_states = (0..32)
            .map(|_| Arc::new(AtomicU8::new(STOP_STATE_FALLBACK_RESERVED)))
            .collect::<Vec<_>>();

        for stop_state in &stop_states {
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

        std::thread::sleep(Duration::from_millis(500));
        dispatcher.shutdown();

        assert_eq!(plugin.stop_typing_count.load(Ordering::Relaxed), 32);
        assert!(stop_states
            .iter()
            .all(|state| state.load(Ordering::Acquire) == STOP_STATE_COMPLETED));
    }

    #[test]
    fn test_read_receipt_dispatcher_does_not_drop_bursty_requests() {
        let dispatcher = ActivityDispatcher::with_backlog_warning_threshold(1);
        let plugin = Arc::new(MockChannel::with_mark_read_delay(
            ChannelCapabilities {
                read_receipts: true,
                ..Default::default()
            },
            Duration::from_millis(10),
        ));

        for timestamp in 0..32_u64 {
            dispatcher.dispatch_verified_read_receipt(
                plugin.clone(),
                "signal",
                ReadReceiptContext {
                    recipient: "+15551234567".to_string(),
                    timestamp: Some(timestamp),
                    ..Default::default()
                },
            );
        }

        std::thread::sleep(Duration::from_millis(500));
        dispatcher.shutdown();

        assert_eq!(plugin.mark_read_count.load(Ordering::Relaxed), 32);
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
        .await;

        assert_eq!(plugin.mark_read_count.load(Ordering::Relaxed), 1);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_read_receipt_dispatch_skips_capability_probe() {
        let notify = Arc::new(Notify::new());
        let plugin = Arc::new(MockChannel {
            mark_read_notify: Some(notify.clone()),
            ..MockChannel::with_panicking_capabilities(ChannelCapabilities::default())
        });
        let dispatcher = ActivityDispatcher::with_backlog_warning_threshold(8);

        dispatcher.dispatch_verified_read_receipt(
            plugin.clone(),
            "signal",
            ReadReceiptContext {
                recipient: "+15551234567".to_string(),
                timestamp: Some(123),
                ..Default::default()
            },
        );

        tokio::time::timeout(Duration::from_secs(1), notify.notified())
            .await
            .expect("verified read receipt dispatch should not probe capabilities");
        dispatcher.shutdown();

        assert_eq!(plugin.mark_read_count.load(Ordering::Relaxed), 1);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_read_receipt_dispatcher_survives_plugin_panic() {
        let notify = Arc::new(Notify::new());
        let plugin = Arc::new(MockChannel {
            mark_read_notify: Some(notify.clone()),
            ..MockChannel::with_panicking_mark_read(
                ChannelCapabilities {
                    read_receipts: true,
                    ..Default::default()
                },
                1,
            )
        });
        let dispatcher = ActivityDispatcher::with_backlog_warning_threshold(8);

        dispatcher.dispatch_verified_read_receipt(
            plugin.clone(),
            "signal",
            ReadReceiptContext {
                recipient: "+15551234567".to_string(),
                timestamp: Some(123),
                ..Default::default()
            },
        );
        dispatcher.dispatch_verified_read_receipt(
            plugin.clone(),
            "signal",
            ReadReceiptContext {
                recipient: "+15551234567".to_string(),
                timestamp: Some(124),
                ..Default::default()
            },
        );

        tokio::time::timeout(Duration::from_secs(1), notify.notified())
            .await
            .expect("dispatcher should continue after a panicking read receipt");
        dispatcher.shutdown();

        assert_eq!(plugin.mark_read_count.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_reset_unsupported_activity_feature_warnings_for_test_clears_seen_keys() {
        reset_unsupported_activity_feature_warnings_for_test();
        warn_unsupported_activity_feature("signal", "typing");
        assert!(UNSUPPORTED_ACTIVITY_FEATURE_WARNINGS
            .lock()
            .seen_at
            .contains_key("signal:typing"));

        reset_unsupported_activity_feature_warnings_for_test();
        assert!(UNSUPPORTED_ACTIVITY_FEATURE_WARNINGS
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
}
