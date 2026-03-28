//! Message delivery worker.
//!
//! Background loop that drains the outbound message pipeline and delivers
//! messages via channel plugins. Wakes on `Notify` or periodic 5-second poll.

use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};
use tracing::warn;

use crate::channels::ChannelRegistry;
use crate::messages::outbound::{MessageContent, MessagePipeline};
use crate::plugins::hook_utils;
use crate::plugins::{self, OutboundContext, PluginRegistry};
use crate::server::ws::WsServerState;

/// Run the delivery worker loop.
///
/// Wakes when notified by the pipeline, every 5 seconds, or on shutdown.
pub async fn delivery_loop(
    pipeline: Arc<MessagePipeline>,
    plugin_registry: Arc<PluginRegistry>,
    channel_registry: Arc<ChannelRegistry>,
    _state: Arc<WsServerState>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    loop {
        // Wait for notification, timeout, or shutdown
        tokio::select! {
            _ = pipeline.notifier().notified() => {}
            _ = tokio::time::sleep(Duration::from_secs(5)) => {}
            _ = shutdown.changed() => {
                break;
            }
        }

        // Check shutdown after waking
        if *shutdown.borrow() {
            break;
        }

        let channel_ids = pipeline.channels_with_messages();

        process_channel_messages(
            &channel_ids,
            &pipeline,
            &plugin_registry,
            &channel_registry,
            crate::channels::activity::shared_activity_dispatcher(),
        )
        .await;
    }
}

/// Process pending messages for each connected channel.
pub(crate) async fn process_channel_messages(
    channel_ids: &[String],
    pipeline: &MessagePipeline,
    plugin_registry: &Arc<PluginRegistry>,
    channel_registry: &ChannelRegistry,
    activity_dispatcher: &crate::channels::activity::ActivityDispatcher,
) {
    for channel_id in channel_ids {
        if !channel_registry.is_connected(channel_id) {
            continue;
        }

        let msg = match pipeline.next_for_channel(channel_id) {
            Some(m) => m,
            None => continue,
        };

        let message_id = msg.message.id.clone();
        let mut message = msg.message.clone();

        if let Some(result) = dispatch_message_hook(
            plugin_registry,
            "message_sending",
            &json!({
                "messageId": message_id.0.clone(),
                "channel": channel_id,
                "content": &message.content,
                "metadata": &message.metadata,
            }),
        ) {
            if result.cancelled {
                if let Err(err) = pipeline.cancel(&message_id) {
                    warn!(
                        id = %message_id,
                        error = %err,
                        "failed to cancel message after hook cancellation"
                    );
                    let _ = pipeline.mark_failed(&message_id, "message cancelled by hook");
                }
                continue;
            }

            if let Some(payload) = parse_hook_payload(&result, "message_sending") {
                apply_message_hook_overrides(&mut message, &payload);
                if let Err(err) = pipeline.update_message(&message_id, message.clone()) {
                    warn!(
                        id = %message_id,
                        error = %err,
                        "failed to persist message updates from hook"
                    );
                }
            }
        }

        if let Err(e) = pipeline.mark_sending(&message_id) {
            warn!(id = %message_id, error = %e, "failed to mark message as sending");
            continue;
        }

        let plugin = match plugin_registry.get_channel(channel_id) {
            Some(p) => p,
            None => {
                let _ = pipeline.mark_failed(&message_id, "no plugin registered for channel");
                continue;
            }
        };

        let metadata = &message.metadata;

        let result = deliver_message(
            &plugin,
            &message.content,
            metadata.recipient_id.as_deref().unwrap_or_default(),
            metadata.reply_to.as_deref(),
            metadata.thread_id.as_deref(),
        )
        .await;

        let delivery_snapshot = match &result {
            Ok(delivery) => json!({
                "ok": delivery.ok,
                "messageId": delivery.message_id,
                "error": delivery.error,
                "retryable": delivery.retryable,
                "conversationId": delivery.conversation_id,
                "toJid": delivery.to_jid,
                "pollId": delivery.poll_id,
            }),
            Err(err) => json!({
                "ok": false,
                "error": err.to_string(),
            }),
        };

        let _ = dispatch_message_hook(
            plugin_registry,
            "message_sent",
            &json!({
                "messageId": message_id.0.clone(),
                "channel": channel_id,
                "content": &message.content,
                "metadata": &message.metadata,
                "delivery": delivery_snapshot,
            }),
        );

        handle_delivery_result(
            pipeline,
            &plugin,
            channel_id,
            &message.metadata,
            &message_id,
            result,
            activity_dispatcher,
        )
        .await;
    }
}

/// Handle the result of a message delivery attempt.
async fn handle_delivery_result(
    pipeline: &MessagePipeline,
    plugin: &Arc<dyn plugins::ChannelPluginInstance>,
    channel_id: &str,
    metadata: &crate::messages::outbound::MessageMetadata,
    message_id: &crate::messages::outbound::MessageId,
    result: Result<plugins::DeliveryResult, plugins::BindingError>,
    activity_dispatcher: &crate::channels::activity::ActivityDispatcher,
) {
    match result {
        Ok(delivery) if delivery.ok => {
            let _ = pipeline.mark_sent(message_id);
            if let Some(read_receipt) = metadata.read_receipt.clone() {
                // Keep delivery success on the hot path and dispatch read
                // receipts through the owned activity worker.
                activity_dispatcher.try_dispatch_verified_read_receipt(
                    plugin.clone(),
                    channel_id,
                    read_receipt,
                );
            }
        }
        Ok(delivery) => {
            let error = delivery
                .error
                .unwrap_or_else(|| "delivery failed".to_string());
            if delivery.retryable && pipeline.can_retry(message_id) {
                let _ = pipeline.mark_retry(message_id, &error);
                warn!(
                    id = %message_id,
                    error = %error,
                    "retryable delivery failure, reset to queued for retry"
                );
            } else {
                let _ = pipeline.mark_failed(message_id, &error);
            }
        }
        Err(e) => {
            let _ = pipeline.mark_failed(message_id, e.to_string());
        }
    }
}

fn dispatch_message_hook(
    plugin_registry: &Arc<PluginRegistry>,
    hook_name: &str,
    payload: &Value,
) -> Option<plugins::HookDispatchResult> {
    hook_utils::dispatch_hook(plugin_registry.clone(), hook_name, payload)
}

fn parse_hook_payload(result: &plugins::HookDispatchResult, hook_name: &str) -> Option<Value> {
    hook_utils::parse_hook_payload(result, hook_name)
}

fn apply_message_hook_overrides(
    message: &mut crate::messages::outbound::OutboundMessage,
    payload: &Value,
) {
    let Some(obj) = payload.as_object() else {
        return;
    };

    if let Some(content) = obj.get("content") {
        if let Ok(content) = serde_json::from_value::<MessageContent>(content.clone()) {
            message.content = content;
        }
    }

    if let Some(metadata) = obj.get("metadata") {
        if let Ok(mut metadata) =
            serde_json::from_value::<crate::messages::outbound::MessageMetadata>(metadata.clone())
        {
            metadata.restore_runtime_only_fields_from(&message.metadata);
            message.metadata = metadata;
        }
    }
}

/// Deliver a message via the channel plugin, dispatching to send_text or send_media.
///
/// `ChannelPluginInstance` methods are sync, so we run them via `spawn_blocking`.
async fn deliver_message(
    plugin: &Arc<dyn plugins::ChannelPluginInstance>,
    content: &MessageContent,
    to: &str,
    reply_to_id: Option<&str>,
    thread_id: Option<&str>,
) -> Result<plugins::DeliveryResult, plugins::BindingError> {
    match content {
        MessageContent::Text { text } => {
            let ctx = OutboundContext {
                to: to.to_string(),
                text: text.clone(),
                media_url: None,
                gif_playback: false,
                reply_to_id: reply_to_id.map(|s| s.to_string()),
                thread_id: thread_id.map(|s| s.to_string()),
                account_id: None,
            };
            let p = plugin.clone();
            tokio::task::spawn_blocking(move || p.send_text(ctx))
                .await
                .map_err(|e| plugins::BindingError::CallError(e.to_string()))?
        }
        MessageContent::Media {
            caption, media_ref, ..
        } => {
            let ctx = OutboundContext {
                to: to.to_string(),
                text: caption.clone().unwrap_or_default(),
                media_url: Some(media_ref.clone()),
                gif_playback: false,
                reply_to_id: reply_to_id.map(|s| s.to_string()),
                thread_id: thread_id.map(|s| s.to_string()),
                account_id: None,
            };
            let p = plugin.clone();
            tokio::task::spawn_blocking(move || p.send_media(ctx))
                .await
                .map_err(|e| plugins::BindingError::CallError(e.to_string()))?
        }
        MessageContent::Composite { parts } => {
            // Send each part sequentially; return first failure or last success
            let mut last_result = plugins::DeliveryResult {
                ok: true,
                message_id: None,
                error: None,
                retryable: false,
                conversation_id: None,
                to_jid: None,
                poll_id: None,
            };
            for part in parts {
                last_result =
                    Box::pin(deliver_message(plugin, part, to, reply_to_id, thread_id)).await?;
                if !last_result.ok {
                    return Ok(last_result);
                }
            }
            Ok(last_result)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::messages::outbound::{
        MessageContent, OutboundContext as MsgOutboundContext, OutboundMessage,
    };
    use crate::plugins::{
        BindingError, ChannelCapabilities, ChannelPluginInstance, DeliveryResult, OutboundContext,
        ReadReceiptContext,
    };
    use std::fs;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;
    use tokio::sync::Notify;

    /// Mock channel plugin that records calls.
    struct MockChannel {
        caps: ChannelCapabilities,
        send_text_count: AtomicU32,
        send_media_count: AtomicU32,
        mark_read_count: AtomicU32,
        mark_read_notify: Option<Arc<Notify>>,
        mark_read_delay: Duration,
        fail: bool,
        retryable: bool,
    }

    impl MockChannel {
        fn new() -> Self {
            Self {
                caps: ChannelCapabilities::default(),
                send_text_count: AtomicU32::new(0),
                send_media_count: AtomicU32::new(0),
                mark_read_count: AtomicU32::new(0),
                mark_read_notify: None,
                mark_read_delay: Duration::ZERO,
                fail: false,
                retryable: false,
            }
        }

        fn failing(retryable: bool) -> Self {
            Self {
                caps: ChannelCapabilities::default(),
                send_text_count: AtomicU32::new(0),
                send_media_count: AtomicU32::new(0),
                mark_read_count: AtomicU32::new(0),
                mark_read_notify: None,
                mark_read_delay: Duration::ZERO,
                fail: true,
                retryable,
            }
        }

        fn with_read_receipts() -> Self {
            Self {
                caps: ChannelCapabilities {
                    read_receipts: true,
                    ..Default::default()
                },
                send_text_count: AtomicU32::new(0),
                send_media_count: AtomicU32::new(0),
                mark_read_count: AtomicU32::new(0),
                mark_read_notify: None,
                mark_read_delay: Duration::ZERO,
                fail: false,
                retryable: false,
            }
        }

        fn with_read_receipts_notify(mark_read_notify: Arc<Notify>) -> Self {
            Self {
                mark_read_notify: Some(mark_read_notify),
                ..Self::with_read_receipts()
            }
        }

        fn with_read_receipts_delay(mark_read_delay: Duration) -> Self {
            Self {
                mark_read_delay,
                ..Self::with_read_receipts()
            }
        }
    }

    impl ChannelPluginInstance for MockChannel {
        fn get_info(&self) -> Result<plugins::ChannelInfo, BindingError> {
            Ok(plugins::ChannelInfo {
                id: "mock".to_string(),
                label: "Mock".to_string(),
                selection_label: "Mock Channel".to_string(),
                docs_path: "".to_string(),
                blurb: "".to_string(),
                order: 0,
            })
        }

        fn get_capabilities(&self) -> Result<ChannelCapabilities, BindingError> {
            Ok(self.caps.clone())
        }

        fn send_text(&self, _ctx: OutboundContext) -> Result<DeliveryResult, BindingError> {
            self.send_text_count.fetch_add(1, Ordering::Relaxed);
            if self.fail {
                Ok(DeliveryResult {
                    ok: false,
                    message_id: None,
                    error: Some("mock failure".to_string()),
                    retryable: self.retryable,
                    conversation_id: None,
                    to_jid: None,
                    poll_id: None,
                })
            } else {
                Ok(DeliveryResult {
                    ok: true,
                    message_id: Some("sent-1".to_string()),
                    error: None,
                    retryable: false,
                    conversation_id: None,
                    to_jid: None,
                    poll_id: None,
                })
            }
        }

        fn send_media(&self, _ctx: OutboundContext) -> Result<DeliveryResult, BindingError> {
            self.send_media_count.fetch_add(1, Ordering::Relaxed);
            Ok(DeliveryResult {
                ok: true,
                message_id: Some("sent-media-1".to_string()),
                error: None,
                retryable: false,
                conversation_id: None,
                to_jid: None,
                poll_id: None,
            })
        }

        fn mark_read(&self, _ctx: ReadReceiptContext) -> Result<(), BindingError> {
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

    fn test_activity_dispatcher() -> crate::channels::activity::ActivityDispatcher {
        crate::channels::activity::ActivityDispatcher::with_queue_capacity(8)
    }

    fn make_pipeline_and_registries(
        channel_id: &str,
        plugin: Option<Arc<dyn ChannelPluginInstance>>,
        connected: bool,
    ) -> (
        Arc<MessagePipeline>,
        Arc<PluginRegistry>,
        Arc<ChannelRegistry>,
    ) {
        let pipeline = Arc::new(MessagePipeline::new());

        let plugin_registry = Arc::new(PluginRegistry::new());
        if let Some(p) = plugin {
            plugin_registry.register_channel(channel_id.to_string(), p);
        }

        let channel_registry = Arc::new(ChannelRegistry::new());
        let status = if connected {
            crate::channels::ChannelStatus::Connected
        } else {
            crate::channels::ChannelStatus::Disconnected
        };
        channel_registry.register(
            crate::channels::ChannelInfo::new(channel_id, channel_id).with_status(status),
        );

        (pipeline, plugin_registry, channel_registry)
    }

    #[tokio::test]
    async fn test_delivery_sends_text_message() {
        let mock = Arc::new(MockChannel::new());
        let (pipeline, plugin_reg, channel_reg) =
            make_pipeline_and_registries("test-ch", Some(mock.clone()), true);

        // Queue a text message
        let msg = OutboundMessage::new("test-ch", MessageContent::text("hello"));
        pipeline.queue(msg, MsgOutboundContext::new()).unwrap();

        // Run one iteration (use shutdown to stop after one pass)
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let state = Arc::new(crate::server::ws::WsServerState::new(
            crate::server::ws::WsServerConfig::default(),
        ));

        let pl = pipeline.clone();
        let pr = plugin_reg.clone();
        let cr = channel_reg.clone();
        let st = state.clone();
        let handle = tokio::spawn(async move {
            delivery_loop(pl, pr, cr, st, shutdown_rx).await;
        });

        // Give it time to process
        tokio::time::sleep(Duration::from_millis(100)).await;
        let _ = shutdown_tx.send(true);
        // Notify to unblock select
        pipeline.notifier().notify_one();
        let _ = handle.await;

        assert_eq!(mock.send_text_count.load(Ordering::Relaxed), 1);
        assert_eq!(pipeline.channels_with_messages().len(), 0);
    }

    #[tokio::test]
    async fn test_delivery_marks_failed_no_plugin() {
        let (pipeline, plugin_reg, channel_reg) =
            make_pipeline_and_registries("no-plugin-ch", None, true);

        let msg = OutboundMessage::new("no-plugin-ch", MessageContent::text("hello"));
        let result = pipeline.queue(msg, MsgOutboundContext::new()).unwrap();

        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let state = Arc::new(crate::server::ws::WsServerState::new(
            crate::server::ws::WsServerConfig::default(),
        ));

        let pl = pipeline.clone();
        let handle = tokio::spawn(async move {
            delivery_loop(pl, plugin_reg, channel_reg, state, shutdown_rx).await;
        });

        tokio::time::sleep(Duration::from_millis(100)).await;
        let _ = shutdown_tx.send(true);
        pipeline.notifier().notify_one();
        let _ = handle.await;

        let status = pipeline.get_status(&result.message_id);
        assert_eq!(
            status,
            Some(crate::messages::outbound::DeliveryStatus::Failed)
        );
    }

    #[tokio::test]
    async fn test_delivery_skips_disconnected_channel() {
        let mock = Arc::new(MockChannel::new());
        let (pipeline, plugin_reg, channel_reg) =
            make_pipeline_and_registries("disc-ch", Some(mock.clone()), false);

        let msg = OutboundMessage::new("disc-ch", MessageContent::text("hello"));
        pipeline.queue(msg, MsgOutboundContext::new()).unwrap();

        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let state = Arc::new(crate::server::ws::WsServerState::new(
            crate::server::ws::WsServerConfig::default(),
        ));

        let pl = pipeline.clone();
        let handle = tokio::spawn(async move {
            delivery_loop(pl, plugin_reg, channel_reg, state, shutdown_rx).await;
        });

        tokio::time::sleep(Duration::from_millis(100)).await;
        let _ = shutdown_tx.send(true);
        pipeline.notifier().notify_one();
        let _ = handle.await;

        // Message should still be queued (not sent, not failed)
        assert_eq!(mock.send_text_count.load(Ordering::Relaxed), 0);
        assert_eq!(pipeline.channels_with_messages().len(), 1);
    }

    #[tokio::test]
    async fn test_delivery_retries_on_retryable_failure_resets_status() {
        let mock = Arc::new(MockChannel::failing(true));
        let (pipeline, plugin_reg, channel_reg) =
            make_pipeline_and_registries("retry-ch", Some(mock.clone()), true);

        let msg = OutboundMessage::new("retry-ch", MessageContent::text("hello"));
        let ctx = MsgOutboundContext::new().with_retries(3);
        let result = pipeline.queue(msg, ctx).unwrap();

        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let state = Arc::new(crate::server::ws::WsServerState::new(
            crate::server::ws::WsServerConfig::default(),
        ));

        let pl = pipeline.clone();
        let handle = tokio::spawn(async move {
            delivery_loop(pl, plugin_reg, channel_reg, state, shutdown_rx).await;
        });

        tokio::time::sleep(Duration::from_millis(100)).await;
        let _ = shutdown_tx.send(true);
        pipeline.notifier().notify_one();
        let _ = handle.await;

        // Message status must be reset to Queued (not stuck at Sending, not Failed)
        let status = pipeline.get_status(&result.message_id);
        assert_eq!(
            status,
            Some(crate::messages::outbound::DeliveryStatus::Queued),
            "retryable failure must reset status to Queued, not leave it as Sending"
        );

        // Message should still be in the channel queue for retry
        assert_eq!(
            pipeline.channels_with_messages().len(),
            1,
            "message should remain in channel queue after retryable failure"
        );

        // The error from the failed attempt should be recorded
        let queued = pipeline.get_message(&result.message_id).unwrap();
        assert_eq!(queued.last_error, Some("mock failure".to_string()));
    }

    #[tokio::test]
    async fn test_delivery_non_retryable_failure_marks_failed() {
        let mock = Arc::new(MockChannel::failing(false));
        let (pipeline, plugin_reg, channel_reg) =
            make_pipeline_and_registries("noretry-ch", Some(mock.clone()), true);

        let msg = OutboundMessage::new("noretry-ch", MessageContent::text("hello"));
        let ctx = MsgOutboundContext::new().with_retries(3);
        let result = pipeline.queue(msg, ctx).unwrap();

        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let state = Arc::new(crate::server::ws::WsServerState::new(
            crate::server::ws::WsServerConfig::default(),
        ));

        let pl = pipeline.clone();
        let handle = tokio::spawn(async move {
            delivery_loop(pl, plugin_reg, channel_reg, state, shutdown_rx).await;
        });

        tokio::time::sleep(Duration::from_millis(100)).await;
        let _ = shutdown_tx.send(true);
        pipeline.notifier().notify_one();
        let _ = handle.await;

        // Non-retryable failure must be marked as Failed
        let status = pipeline.get_status(&result.message_id);
        assert_eq!(
            status,
            Some(crate::messages::outbound::DeliveryStatus::Failed),
            "non-retryable failure must be marked as Failed"
        );

        // Message should be removed from the channel queue
        assert_eq!(
            pipeline.queue_size("noretry-ch"),
            0,
            "failed message should be removed from channel queue"
        );
    }

    #[tokio::test]
    async fn test_retry_mechanism_picks_up_reset_messages() {
        // Use a mock that always fails with retryable=true
        let mock = Arc::new(MockChannel::failing(true));
        let (pipeline, plugin_reg, channel_reg) =
            make_pipeline_and_registries("pickup-ch", Some(mock.clone()), true);

        let msg = OutboundMessage::new("pickup-ch", MessageContent::text("hello"));
        // Allow 3 retries so the message can be retried multiple times
        let ctx = MsgOutboundContext::new().with_retries(3);
        let result = pipeline.queue(msg, ctx).unwrap();

        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let state = Arc::new(crate::server::ws::WsServerState::new(
            crate::server::ws::WsServerConfig::default(),
        ));

        let pl = pipeline.clone();
        let handle = tokio::spawn(async move {
            delivery_loop(pl, plugin_reg, channel_reg, state, shutdown_rx).await;
        });

        // Allow enough time for multiple delivery loop iterations to run.
        // The loop wakes on notify or every 5s; we notify it repeatedly.
        for _ in 0..5 {
            tokio::time::sleep(Duration::from_millis(80)).await;
            pipeline.notifier().notify_one();
        }

        let _ = shutdown_tx.send(true);
        pipeline.notifier().notify_one();
        let _ = handle.await;

        // The mock should have been called more than once, proving the retry
        // mechanism picked up the message again after it was reset to Queued.
        let send_count = mock.send_text_count.load(Ordering::Relaxed);
        assert!(
            send_count > 1,
            "expected multiple delivery attempts from retry, got {}",
            send_count
        );

        // After exhausting retries (3 attempts), the message should be Failed
        // since can_retry() returns false when attempts >= max_retries.
        let queued = pipeline.get_message(&result.message_id).unwrap();
        assert_eq!(
            queued.status,
            crate::messages::outbound::DeliveryStatus::Failed,
            "message should be Failed after exhausting retries (attempts={}, max=3)",
            queued.attempts
        );
    }

    #[tokio::test]
    async fn test_delivery_shutdown() {
        let (pipeline, plugin_reg, channel_reg) =
            make_pipeline_and_registries("shutdown-ch", None, true);

        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(true); // already shut down
        let state = Arc::new(crate::server::ws::WsServerState::new(
            crate::server::ws::WsServerConfig::default(),
        ));

        let handle = tokio::spawn(async move {
            delivery_loop(pipeline, plugin_reg, channel_reg, state, shutdown_rx).await;
        });

        // Should exit quickly since shutdown is already true
        let _ = shutdown_tx.send(true);
        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("delivery loop should exit on shutdown")
            .expect("task should not panic");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_handle_delivery_result_marks_read_after_success_when_enabled() {
        let mark_read_notify = Arc::new(Notify::new());
        let mock = Arc::new(MockChannel::with_read_receipts_notify(
            mark_read_notify.clone(),
        ));
        let (pipeline, _plugin_reg, _channel_reg) =
            make_pipeline_and_registries("signal", Some(mock.clone()), true);
        let dispatcher = test_activity_dispatcher();

        let temp = tempfile::tempdir().unwrap();
        let config_path = temp.path().join("carapace.json5");
        fs::write(
            &config_path,
            r#"{
                channels: {
                    signal: {
                        features: {
                            readReceipts: {
                                enabled: true,
                                mode: "after-response",
                            },
                        },
                    },
                },
            }"#,
        )
        .unwrap();
        crate::config::clear_cache();
        let mut env_guard = crate::test_support::env::ScopedEnv::new();
        env_guard
            .set("CARAPACE_CONFIG_PATH", config_path.as_os_str())
            .set("CARAPACE_DISABLE_CONFIG_CACHE", "1");

        let msg = OutboundMessage::new("signal", MessageContent::text("hello")).with_metadata(
            crate::messages::outbound::MessageMetadata {
                recipient_id: Some("+15551234567".to_string()),
                read_receipt: Some(ReadReceiptContext {
                    recipient: "+15551234567".to_string(),
                    timestamp: Some(123),
                    ..Default::default()
                }),
                ..Default::default()
            },
        );
        let queued = pipeline.queue(msg, MsgOutboundContext::new()).unwrap();
        let message = pipeline
            .get_message(&queued.message_id)
            .expect("queued message should be available");
        let plugin: Arc<dyn ChannelPluginInstance> = mock.clone();

        handle_delivery_result(
            &pipeline,
            &plugin,
            "signal",
            &message.message.metadata,
            &queued.message_id,
            Ok(plugins::DeliveryResult {
                ok: true,
                message_id: Some("sent-1".to_string()),
                error: None,
                retryable: false,
                conversation_id: None,
                to_jid: None,
                poll_id: None,
            }),
            &dispatcher,
        )
        .await;

        tokio::time::timeout(Duration::from_secs(1), mark_read_notify.notified())
            .await
            .expect("read receipt should be dispatched asynchronously");
        dispatcher.shutdown();

        assert_eq!(
            pipeline.get_status(&queued.message_id),
            Some(crate::messages::outbound::DeliveryStatus::Sent)
        );
        assert_eq!(mock.mark_read_count.load(Ordering::Relaxed), 1);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_process_channel_messages_marks_read_after_success_when_enabled() {
        let mark_read_notify = Arc::new(Notify::new());
        let mock = Arc::new(MockChannel::with_read_receipts_notify(
            mark_read_notify.clone(),
        ));
        let (pipeline, plugin_reg, channel_reg) =
            make_pipeline_and_registries("signal", Some(mock.clone()), true);
        let dispatcher = test_activity_dispatcher();

        let msg = OutboundMessage::new("signal", MessageContent::text("hello")).with_metadata(
            crate::messages::outbound::MessageMetadata {
                recipient_id: Some("+15551234567".to_string()),
                read_receipt: Some(ReadReceiptContext {
                    recipient: "+15551234567".to_string(),
                    timestamp: Some(123),
                    ..Default::default()
                }),
                ..Default::default()
            },
        );
        let queued = pipeline.queue(msg, MsgOutboundContext::new()).unwrap();

        process_channel_messages(
            &["signal".to_string()],
            &pipeline,
            &plugin_reg,
            &channel_reg,
            &dispatcher,
        )
        .await;

        tokio::time::timeout(Duration::from_secs(1), mark_read_notify.notified())
            .await
            .expect("read receipt should be dispatched asynchronously");
        dispatcher.shutdown();

        assert_eq!(mock.send_text_count.load(Ordering::Relaxed), 1);
        assert_eq!(mock.mark_read_count.load(Ordering::Relaxed), 1);
        assert_eq!(
            pipeline.get_status(&queued.message_id),
            Some(crate::messages::outbound::DeliveryStatus::Sent)
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_handle_delivery_result_skips_read_receipt_on_delivery_failure() {
        let mock = Arc::new(MockChannel::with_read_receipts());
        let (pipeline, _plugin_reg, _channel_reg) =
            make_pipeline_and_registries("signal", Some(mock.clone()), true);
        let dispatcher = test_activity_dispatcher();

        let msg = OutboundMessage::new("signal", MessageContent::text("hello")).with_metadata(
            crate::messages::outbound::MessageMetadata {
                recipient_id: Some("+15551234567".to_string()),
                read_receipt: Some(ReadReceiptContext {
                    recipient: "+15551234567".to_string(),
                    timestamp: Some(123),
                    ..Default::default()
                }),
                ..Default::default()
            },
        );
        let queued = pipeline.queue(msg, MsgOutboundContext::new()).unwrap();
        let message = pipeline
            .get_message(&queued.message_id)
            .expect("queued message should be available");
        let plugin: Arc<dyn ChannelPluginInstance> = mock.clone();

        handle_delivery_result(
            &pipeline,
            &plugin,
            "signal",
            &message.message.metadata,
            &queued.message_id,
            Ok(plugins::DeliveryResult {
                ok: false,
                message_id: None,
                error: Some("send failed".to_string()),
                retryable: false,
                conversation_id: None,
                to_jid: None,
                poll_id: None,
            }),
            &dispatcher,
        )
        .await;
        dispatcher.shutdown();

        assert_eq!(
            pipeline.get_status(&queued.message_id),
            Some(crate::messages::outbound::DeliveryStatus::Failed)
        );
        assert_eq!(mock.mark_read_count.load(Ordering::Relaxed), 0);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_handle_delivery_result_skips_read_receipt_when_metadata_absent() {
        let mock = Arc::new(MockChannel::with_read_receipts());
        let (pipeline, _plugin_reg, _channel_reg) =
            make_pipeline_and_registries("signal", Some(mock.clone()), true);
        let dispatcher = test_activity_dispatcher();

        let msg = OutboundMessage::new("signal", MessageContent::text("hello")).with_metadata(
            crate::messages::outbound::MessageMetadata {
                recipient_id: Some("+15551234567".to_string()),
                ..Default::default()
            },
        );
        let queued = pipeline.queue(msg, MsgOutboundContext::new()).unwrap();
        let message = pipeline
            .get_message(&queued.message_id)
            .expect("queued message should be available");
        let plugin: Arc<dyn ChannelPluginInstance> = mock.clone();

        handle_delivery_result(
            &pipeline,
            &plugin,
            "signal",
            &message.message.metadata,
            &queued.message_id,
            Ok(plugins::DeliveryResult {
                ok: true,
                message_id: Some("sent-1".to_string()),
                error: None,
                retryable: false,
                conversation_id: None,
                to_jid: None,
                poll_id: None,
            }),
            &dispatcher,
        )
        .await;
        dispatcher.shutdown();

        assert_eq!(
            pipeline.get_status(&queued.message_id),
            Some(crate::messages::outbound::DeliveryStatus::Sent)
        );
        assert_eq!(mock.mark_read_count.load(Ordering::Relaxed), 0);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_handle_delivery_result_does_not_block_on_slow_read_receipt_dispatch() {
        let mock = Arc::new(MockChannel::with_read_receipts_delay(
            Duration::from_millis(250),
        ));
        let (pipeline, _plugin_reg, _channel_reg) =
            make_pipeline_and_registries("signal", Some(mock.clone()), true);
        let dispatcher = test_activity_dispatcher();

        let msg = OutboundMessage::new("signal", MessageContent::text("hello")).with_metadata(
            crate::messages::outbound::MessageMetadata {
                recipient_id: Some("+15551234567".to_string()),
                read_receipt: Some(ReadReceiptContext {
                    recipient: "+15551234567".to_string(),
                    timestamp: Some(123),
                    ..Default::default()
                }),
                ..Default::default()
            },
        );
        let queued = pipeline.queue(msg, MsgOutboundContext::new()).unwrap();
        let message = pipeline
            .get_message(&queued.message_id)
            .expect("queued message should be available");
        let plugin: Arc<dyn ChannelPluginInstance> = mock.clone();

        tokio::time::timeout(
            Duration::from_millis(50),
            handle_delivery_result(
                &pipeline,
                &plugin,
                "signal",
                &message.message.metadata,
                &queued.message_id,
                Ok(plugins::DeliveryResult {
                    ok: true,
                    message_id: Some("sent-1".to_string()),
                    error: None,
                    retryable: false,
                    conversation_id: None,
                    to_jid: None,
                    poll_id: None,
                }),
                &dispatcher,
            ),
        )
        .await
        .expect("delivery result handling should not wait for slow read receipt I/O");

        tokio::time::sleep(Duration::from_millis(300)).await;
        dispatcher.shutdown();
        assert_eq!(mock.mark_read_count.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_apply_message_hook_overrides_preserves_runtime_read_receipt() {
        let mut message = OutboundMessage::new("signal", MessageContent::text("hello"));
        message.metadata = crate::messages::outbound::MessageMetadata {
            recipient_id: Some("+15551234567".to_string()),
            read_receipt: Some(ReadReceiptContext {
                recipient: "+15551234567".to_string(),
                timestamp: Some(123),
                ..Default::default()
            }),
            ..Default::default()
        };

        apply_message_hook_overrides(
            &mut message,
            &json!({
                "metadata": {
                    "recipient_id": "+15557654321",
                    "priority": 2
                }
            }),
        );

        assert_eq!(
            message.metadata.recipient_id.as_deref(),
            Some("+15557654321")
        );
        assert_eq!(message.metadata.priority, 2);
        assert_eq!(
            message
                .metadata
                .read_receipt
                .as_ref()
                .and_then(|ctx| ctx.timestamp),
            Some(123)
        );
    }
}
