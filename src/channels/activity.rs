//! Shared channel activity feature policy and runtime helpers.
//!
//! This module handles per-channel activity policy (typing indicators and read
//! receipts) and the runtime helpers that drive those side effects.

use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::plugins::{
    BindingError, ChannelPluginInstance, PluginRegistry, ReadReceiptContext, TypingContext,
};

const DEFAULT_TYPING_INTERVAL_SECONDS: u32 = 3;

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

#[derive(Debug)]
pub struct TypingLoopHandle {
    cancel: CancellationToken,
    task: JoinHandle<()>,
}

impl TypingLoopHandle {
    pub async fn stop(self) {
        self.cancel.cancel();
        let _ = self.task.await;
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

fn apply_legacy_session_typing_fallback(config: &Value, policy: &mut TypingFeaturePolicy) {
    let Some(session) = config.get("session") else {
        return;
    };

    if let Some(mode) = session.get("typingMode").and_then(|value| value.as_str()) {
        if mode.eq_ignore_ascii_case("thinking") {
            policy.enabled = true;
            policy.mode = TypingMode::Thinking;
        } else {
            policy.enabled = false;
        }
    }

    if let Some(interval) = session
        .get("typingIntervalSeconds")
        .and_then(|value| value.as_u64())
        .filter(|value| *value > 0)
    {
        policy.interval_seconds = interval.min(u32::MAX as u64) as u32;
    }
}

fn apply_channel_activity_overrides(features: Option<&Value>, policy: &mut ChannelActivityPolicy) {
    let Some(features) = features.and_then(|value| value.as_object()) else {
        return;
    };

    if let Some(typing) = features.get("typing").and_then(|value| value.as_object()) {
        if let Some(enabled) = typing.get("enabled").and_then(|value| value.as_bool()) {
            policy.typing.enabled = enabled;
        }
        if let Some(mode) = typing.get("mode").and_then(|value| value.as_str()) {
            if mode.eq_ignore_ascii_case("thinking") {
                policy.typing.mode = TypingMode::Thinking;
            }
        }
        if let Some(interval) = typing
            .get("intervalSeconds")
            .and_then(|value| value.as_u64())
            .filter(|value| *value > 0)
        {
            policy.typing.interval_seconds = interval.min(u32::MAX as u64) as u32;
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
            }
        }
    }
}

pub async fn maybe_start_typing_loop(
    plugin_registry: Arc<PluginRegistry>,
    channel_id: &str,
    policy: &ChannelActivityPolicy,
    ctx: TypingContext,
) -> Option<TypingLoopHandle> {
    if !policy.typing.enabled {
        return None;
    }

    let plugin = plugin_registry.get_channel(channel_id)?;
    let capabilities = get_capabilities(plugin.clone()).await.ok()?;
    if !capabilities.typing_indicators {
        return None;
    }

    if let Err(err) = invoke_start_typing(plugin.clone(), ctx.clone()).await {
        tracing::warn!(channel = %channel_id, error = %err, "failed to start typing indicator");
        return None;
    }

    let cancel = CancellationToken::new();
    let interval_seconds = policy.typing.interval_seconds.max(1);
    let channel_id = channel_id.to_string();
    let task_cancel = cancel.clone();
    let task = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(interval_seconds as u64));
        loop {
            tokio::select! {
                _ = task_cancel.cancelled() => {
                    break;
                }
                _ = interval.tick() => {
                    if let Err(err) = invoke_start_typing(plugin.clone(), ctx.clone()).await {
                        tracing::warn!(channel = %channel_id, error = %err, "failed to refresh typing indicator");
                    }
                }
            }
        }

        if let Err(err) = invoke_stop_typing(plugin, ctx).await {
            tracing::warn!(channel = %channel_id, error = %err, "failed to stop typing indicator");
        }
    });

    Some(TypingLoopHandle { cancel, task })
}

pub async fn maybe_send_read_receipt(
    plugin_registry: &Arc<PluginRegistry>,
    channel_id: &str,
    policy: &ChannelActivityPolicy,
    ctx: ReadReceiptContext,
) {
    if !policy.read_receipts.enabled || policy.read_receipts.mode != ReadReceiptMode::AfterResponse
    {
        return;
    }

    let Some(plugin) = plugin_registry.get_channel(channel_id) else {
        return;
    };

    match get_capabilities(plugin.clone()).await {
        Ok(capabilities) if capabilities.read_receipts => {
            if let Err(err) = invoke_mark_read(plugin, ctx).await {
                tracing::warn!(channel = %channel_id, error = %err, "failed to send read receipt");
            }
        }
        Ok(_) => {}
        Err(err) => {
            tracing::warn!(channel = %channel_id, error = %err, "failed to fetch channel capabilities for read receipt");
        }
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

async fn invoke_mark_read(
    plugin: Arc<dyn ChannelPluginInstance>,
    ctx: ReadReceiptContext,
) -> Result<(), BindingError> {
    tokio::task::spawn_blocking(move || plugin.mark_read(ctx))
        .await
        .map_err(|err| BindingError::CallError(err.to_string()))?
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU32, Ordering};

    use super::*;
    use crate::plugins::{ChannelCapabilities, ChannelInfo, DeliveryResult, OutboundContext};

    struct MockChannel {
        caps: ChannelCapabilities,
        start_typing_count: AtomicU32,
        stop_typing_count: AtomicU32,
        mark_read_count: AtomicU32,
    }

    impl MockChannel {
        fn new(caps: ChannelCapabilities) -> Self {
            Self {
                caps,
                start_typing_count: AtomicU32::new(0),
                stop_typing_count: AtomicU32::new(0),
                mark_read_count: AtomicU32::new(0),
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
            self.stop_typing_count.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }

        fn mark_read(&self, _ctx: ReadReceiptContext) -> Result<(), BindingError> {
            self.mark_read_count.fetch_add(1, Ordering::Relaxed);
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

        let handle = maybe_start_typing_loop(
            registry,
            "signal",
            &policy,
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
    }

    #[tokio::test]
    async fn test_maybe_send_read_receipt_honors_capability() {
        let plugin = Arc::new(MockChannel::new(ChannelCapabilities {
            read_receipts: true,
            ..Default::default()
        }));
        let registry = Arc::new(PluginRegistry::new());
        registry.register_channel("signal".to_string(), plugin.clone());
        let policy = ChannelActivityPolicy {
            read_receipts: ReadReceiptFeaturePolicy {
                enabled: true,
                ..Default::default()
            },
            ..Default::default()
        };

        maybe_send_read_receipt(
            &registry,
            "signal",
            &policy,
            ReadReceiptContext {
                recipient: "+15551234567".to_string(),
                timestamp: Some(123),
                ..Default::default()
            },
        )
        .await;

        assert_eq!(plugin.mark_read_count.load(Ordering::Relaxed), 1);
    }
}
