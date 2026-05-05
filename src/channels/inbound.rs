//! Shared inbound channel dispatch helpers.
//!
//! Routes inbound text messages into the session + agent pipeline.

use std::sync::Arc;

use serde_json::Value;
use tracing::{debug, warn};

use crate::plugins::TypingContext;
use crate::server::ws::{AgentRun, AgentRunStatus, WsServerState};
use crate::sessions::{get_or_create_scoped_session, ChatMessage, SessionMetadata};

/// Inbound-event idempotency key used to dedupe a single channel-side
/// event across redelivery paths (sync handler ↔ DLQ replay ↔ future
/// retry middleware).
///
/// The contract is: dispatch is idempotent on `(channel,
/// IdempotencyKey)`. The newtype enforces the canonicalization that
/// would otherwise have to be hand-written at every call site:
///
/// - empty / whitespace-only inputs are rejected at construction time
/// - control bytes (NUL, ASCII control range) are rejected so a
///   "abc\0def" string can't pass an empty-check while carrying
///   invisible bytes that interact badly with anything that later
///   re-tokenises the value (`trim()` does not strip these)
/// - the stored value is trimmed so two callers that disagree on
///   surrounding whitespace cannot produce different keys for the same
///   underlying event
///
/// Equality is byte-exact on the trimmed string. The newtype keeps the
/// inner field private so future strengthening (e.g. NFC-normalization,
/// length cap, additional char-class denials) can be added without
/// touching every call site.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IdempotencyKey(String);

impl IdempotencyKey {
    /// Construct from a borrowed event-id string. Returns `None` if the
    /// trimmed value is empty OR contains any ASCII control byte
    /// (including NUL) — callers fall through to the non-deduped path
    /// rather than risk inserting a malformed key into the
    /// session-history match.
    pub fn from_str_opt(value: &str) -> Option<Self> {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            return None;
        }
        if trimmed.chars().any(|c| c.is_control()) {
            return None;
        }
        Some(Self(trimmed.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for IdempotencyKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for IdempotencyKey {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// Optional per-channel activity context captured from an inbound message.
#[derive(Debug, Clone, Default)]
pub struct InboundDispatchOptions {
    pub inbound_event_id: Option<IdempotencyKey>,
    pub delivery_recipient_id: Option<String>,
    pub typing_context: Option<TypingContext>,
    pub claimed_read_receipt: Option<crate::channels::activity::ClaimedReadReceipt>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboundDispatchResult {
    pub run_id: String,
    pub run_spawned: bool,
}

/// Dispatch an inbound text message into the agent pipeline.
///
/// Returns the run ID if queued successfully.
pub async fn dispatch_inbound_text(
    state: &Arc<WsServerState>,
    channel: &str,
    sender_id: &str,
    peer_id: &str,
    text: &str,
    chat_id: Option<String>,
) -> Result<String, String> {
    dispatch_inbound_text_with_options(
        state,
        channel,
        sender_id,
        peer_id,
        text,
        chat_id,
        InboundDispatchOptions::default(),
    )
    .await
    .map(|result| result.run_id)
}

/// Dispatch an inbound text message with optional channel activity context.
pub async fn dispatch_inbound_text_with_options(
    state: &Arc<WsServerState>,
    channel: &str,
    sender_id: &str,
    peer_id: &str,
    text: &str,
    chat_id: Option<String>,
    options: InboundDispatchOptions,
) -> Result<InboundDispatchResult, String> {
    let cfg = crate::config::load_config_shared()
        .unwrap_or_else(|_| Arc::new(Value::Object(serde_json::Map::new())));
    let effective_peer_id = if peer_id.is_empty() {
        sender_id
    } else {
        peer_id
    };

    let InboundDispatchOptions {
        inbound_event_id,
        delivery_recipient_id,
        typing_context,
        claimed_read_receipt,
    } = options;
    let delivery_recipient_id = delivery_recipient_id.or_else(|| chat_id.clone());
    let metadata = SessionMetadata {
        channel: Some(channel.to_string()),
        user_id: Some(sender_id.to_string()),
        chat_id,
        ..Default::default()
    };

    let session_store = state.session_store();
    let session = get_or_create_scoped_session(
        session_store,
        cfg.as_ref(),
        channel,
        sender_id,
        effective_peer_id,
        None,
        metadata,
    )
    .map_err(|e| {
        if let Some(claimed_read_receipt) = claimed_read_receipt.as_ref() {
            state
                .activity_service()
                .withhold_claimed_read_receipt(claimed_read_receipt);
        }
        format!("failed to get/create session: {}", e)
    })?;

    let mut message = ChatMessage::user(session.id.clone(), text);
    if let Some(idempotency_key) = inbound_event_id.as_ref() {
        message = message.with_metadata(serde_json::json!({
            "inbound_event_id": idempotency_key.as_str(),
        }));
    }

    if let Some(idempotency_key) = inbound_event_id {
        // Atomic dedupe + append under the per-session FileLock. The
        // pre-fix version did `session_contains_inbound_event(...)`
        // followed by `append_message_blocking(...)` as two separate
        // lock acquisitions, leaving a TOCTOU window where two
        // concurrent dispatchers with the same event_id could both
        // pass the dedupe check and both append. Single-call
        // `append_message_if_new_inbound_blocking` holds the lock
        // across both steps.
        match crate::sessions::append_message_if_new_inbound_blocking(
            state.session_store().clone(),
            message,
            idempotency_key.as_str().to_string(),
        )
        .await
        {
            Ok(true) => {}
            Ok(false) => {
                // Duplicate already on history. Complete any pending
                // read receipt the way the pre-fix dedupe branch did
                // — the inbound event was already durably appended on
                // an earlier dispatch, so the channel-side ack is
                // safe.
                //
                // M3: emit a debug log so a redelivered event leaves
                // a journal entry an operator can grep for. Without
                // this, a redelivered event silently produces no
                // journal entry — operators cannot correlate "the
                // user said X twice but we only ran once".
                debug!(
                    channel = %channel,
                    sender = %sender_id,
                    idempotency_key = %idempotency_key,
                    "duplicate inbound event suppressed by idempotency dedupe"
                );
                if let Some(claimed_read_receipt) = claimed_read_receipt.as_ref() {
                    if let Err(err) = state
                        .activity_service()
                        .complete_claimed_read_receipt(state.as_ref(), claimed_read_receipt)
                        .await
                    {
                        warn!(
                            channel = %claimed_read_receipt.channel_id(),
                            error = %err,
                            "failed to complete explicit read receipt for duplicate inbound event"
                        );
                    }
                }
                return Ok(InboundDispatchResult {
                    run_id: uuid::Uuid::new_v4().to_string(),
                    run_spawned: false,
                });
            }
            Err(e) => {
                if let Some(claimed_read_receipt) = claimed_read_receipt.as_ref() {
                    state
                        .activity_service()
                        .withhold_claimed_read_receipt(claimed_read_receipt);
                }
                return Err(format!("failed to append message: {}", e));
            }
        }
    } else {
        // No idempotency key — caller has opted out of dedupe.
        // Fall back to the unguarded append.
        if let Err(e) =
            crate::sessions::append_message_blocking(state.session_store().clone(), message).await
        {
            if let Some(claimed_read_receipt) = claimed_read_receipt.as_ref() {
                state
                    .activity_service()
                    .withhold_claimed_read_receipt(claimed_read_receipt);
            }
            return Err(format!("failed to append message: {}", e));
        }
    }

    if let Some(claimed_read_receipt) = claimed_read_receipt.as_ref() {
        if let Err(err) = state
            .activity_service()
            .complete_claimed_read_receipt(state.as_ref(), claimed_read_receipt)
            .await
        {
            warn!(
                channel = %claimed_read_receipt.channel_id(),
                error = %err,
                "failed to complete explicit read receipt after durable inbound append"
            );
        }
    }

    let run_id = uuid::Uuid::new_v4().to_string();

    // Provider availability gates the run-tracking entry; the user message
    // + read receipt above were persisted unconditionally because the
    // channel already acknowledged receipt.
    let Some(provider) = state.llm_provider() else {
        crate::agent::AgentConfigurationError::provider_not_configured().log_operator_hint();
        return Ok(InboundDispatchResult {
            run_id,
            run_spawned: false,
        });
    };

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    let typing_context = typing_context.or_else(|| {
        delivery_recipient_id
            .clone()
            .or_else(|| session.metadata.chat_id.clone())
            .map(|to| TypingContext {
                to,
                ..Default::default()
            })
    });
    let cancel_token = tokio_util::sync::CancellationToken::new();
    let run = AgentRun {
        run_id: run_id.clone(),
        session_key: session.session_key.clone(),
        delivery_recipient_id,
        typing_context,
        status: AgentRunStatus::Queued,
        message: text.to_string(),
        response: String::new(),
        error: None,
        created_at: now,
        started_at: None,
        completed_at: None,
        cancel_token: cancel_token.clone(),
        waiters: Vec::new(),
    };

    {
        let mut registry = state.agent_run_registry.lock();
        registry.register(run);
    }

    let mut config = crate::agent::AgentConfig::default();
    if let Err(e) = crate::agent::resolve_agent_model(
        &mut config,
        cfg.as_ref(),
        None,
        &crate::agent::ModelResolutionOverrides {
            session_route: session.metadata.route.as_deref(),
            session_model: session.metadata.model.as_deref(),
            ..Default::default()
        },
    ) {
        warn!(error = %e, "inbound agent run skipped: model resolution failed");
        return Ok(InboundDispatchResult {
            run_id,
            run_spawned: false,
        });
    }
    crate::agent::apply_agent_config_from_settings(&mut config, cfg.as_ref(), None);
    config.deliver = true;
    crate::agent::spawn_run(
        run_id.clone(),
        session.session_key.clone(),
        config,
        state.clone(),
        provider,
        cancel_token,
    );
    debug!(
        run_id = %run_id,
        channel = %channel,
        sender = %sender_id,
        "Inbound agent run dispatched"
    );

    Ok(InboundDispatchResult {
        run_id,
        run_spawned: true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;

    use serde_json::json;
    use tokio::sync::Notify;

    use crate::channels::activity::ActivityService;
    use crate::plugins::{
        BindingError, ChannelCapabilities, ChannelInfo, ChannelPluginInstance, PluginRegistry,
        ReadReceiptContext,
    };
    use crate::server::ws::WsServerConfig;

    /// IdempotencyKey constructor must reject empty / whitespace-only
    /// inputs. The dedupe contract relies on byte-exact equality of
    /// trimmed values, and a stray whitespace-only key (e.g. from a
    /// future SDK quirk in event-id parsing) would otherwise sit in
    /// session history and dedupe every subsequent inbound event.
    #[test]
    fn test_idempotency_key_rejects_empty_or_whitespace() {
        assert_eq!(IdempotencyKey::from_str_opt(""), None);
        assert_eq!(IdempotencyKey::from_str_opt("   "), None);
        assert_eq!(IdempotencyKey::from_str_opt("\t\n"), None);
    }

    /// IdempotencyKey trims surrounding whitespace so two callers that
    /// disagree on whitespace produce the same key for the same event.
    #[test]
    fn test_idempotency_key_canonicalizes_whitespace() {
        let bare = IdempotencyKey::from_str_opt("$abc:matrix.org").expect("non-empty");
        let padded = IdempotencyKey::from_str_opt("  $abc:matrix.org\n").expect("non-empty");
        assert_eq!(bare, padded);
        assert_eq!(bare.as_str(), "$abc:matrix.org");
    }

    /// IdempotencyKey rejects any value containing ASCII control
    /// bytes (NUL, BEL, etc.) so a "abc\0def" string can't slip past
    /// the empty-check and produce a key that interacts badly with
    /// anything that re-tokenises the value later.
    #[test]
    fn test_idempotency_key_rejects_control_bytes() {
        assert_eq!(IdempotencyKey::from_str_opt("abc\0def"), None);
        assert_eq!(IdempotencyKey::from_str_opt("hello\x07world"), None);
        // Tab/newline ARE in the ASCII control range and the trim
        // already strips them surrounding; embedded ones still reject.
        assert_eq!(IdempotencyKey::from_str_opt("foo\tbar"), None);
    }

    /// AsRef<str> impl lets callers pass an `IdempotencyKey` directly
    /// into APIs that want `impl AsRef<str>` without round-tripping
    /// through String.
    #[test]
    fn test_idempotency_key_as_ref_str() {
        let key = IdempotencyKey::from_str_opt("$abc:matrix.org").expect("non-empty");
        fn takes_str(s: impl AsRef<str>) -> String {
            s.as_ref().to_string()
        }
        assert_eq!(takes_str(&key), "$abc:matrix.org");
        assert_eq!(takes_str(key), "$abc:matrix.org");
    }
    use crate::sessions::{resolve_scoped_session_key, SessionStore};
    use crate::tasks::TaskQueue;

    struct MockReadReceiptChannel {
        mark_read_count: AtomicU32,
        mark_read_notify: Arc<Notify>,
    }

    impl MockReadReceiptChannel {
        fn new(mark_read_notify: Arc<Notify>) -> Self {
            Self {
                mark_read_count: AtomicU32::new(0),
                mark_read_notify,
            }
        }
    }

    impl ChannelPluginInstance for MockReadReceiptChannel {
        fn get_info(&self) -> Result<ChannelInfo, BindingError> {
            Ok(ChannelInfo {
                id: "signal".to_string(),
                label: "Signal".to_string(),
                selection_label: "Signal".to_string(),
                docs_path: String::new(),
                blurb: String::new(),
                order: 0,
            })
        }

        fn get_capabilities(&self) -> Result<ChannelCapabilities, BindingError> {
            Ok(ChannelCapabilities {
                read_receipts: true,
                ..Default::default()
            })
        }

        fn send_text(
            &self,
            _ctx: crate::plugins::OutboundContext,
        ) -> Result<crate::plugins::DeliveryResult, BindingError> {
            unreachable!()
        }

        fn send_media(
            &self,
            _ctx: crate::plugins::OutboundContext,
        ) -> Result<crate::plugins::DeliveryResult, BindingError> {
            unreachable!()
        }

        fn mark_read(&self, _ctx: ReadReceiptContext) -> Result<(), BindingError> {
            self.mark_read_count.fetch_add(1, Ordering::Relaxed);
            self.mark_read_notify.notify_one();
            Ok(())
        }
    }

    use crate::test_support::agent::StaticTestProvider;

    fn install_empty_config() -> serde_json::Value {
        let cfg = json!({});
        crate::config::clear_cache();
        crate::config::update_cache(cfg.clone(), cfg.clone());
        cfg
    }

    fn build_state(
        session_store: Arc<SessionStore>,
        activity_service: Arc<ActivityService>,
        plugin_registry: Option<Arc<PluginRegistry>>,
    ) -> Arc<WsServerState> {
        let state = WsServerState::new(WsServerConfig::default())
            .with_session_store(session_store)
            .with_activity_service(activity_service);
        match plugin_registry {
            Some(plugin_registry) => Arc::new(state.with_plugin_registry(plugin_registry)),
            None => Arc::new(state),
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_dispatch_inbound_text_releases_claim_and_sends_no_receipt_when_append_fails() {
        let cfg = install_empty_config();
        let temp = tempfile::tempdir().expect("tempdir");
        let session_store = Arc::new(SessionStore::with_base_path(temp.path().to_path_buf()));
        let activity_service = Arc::new(ActivityService::with_limits_for_test(8, 1));
        let signal_channel = Arc::new(MockReadReceiptChannel::new(Arc::new(Notify::new())));
        let plugin_registry = Arc::new(PluginRegistry::new());
        plugin_registry.register_channel("signal".to_string(), signal_channel.clone());
        let state = build_state(
            session_store.clone(),
            activity_service.clone(),
            Some(plugin_registry),
        );

        let (session_key, _, _) =
            resolve_scoped_session_key(&cfg, "signal", "+15559876543", "+15559876543", None);
        let session = session_store
            .get_or_create_session(
                &session_key,
                SessionMetadata {
                    channel: Some("signal".to_string()),
                    user_id: Some("+15559876543".to_string()),
                    chat_id: Some("+15559876543".to_string()),
                    ..Default::default()
                },
            )
            .expect("session should be created");
        session_store
            .archive_session(&session.id, false)
            .expect("session should archive cleanly");

        let claimed_read_receipt = activity_service
            .try_claim_read_receipt(
                "signal",
                ReadReceiptContext {
                    recipient: "+15559876543".to_string(),
                    timestamp: Some(1706745600000),
                    ..Default::default()
                },
            )
            .expect("receipt claim should reserve the only slot");
        assert!(
            !activity_service.can_accept_read_receipt_ownership("signal"),
            "the claim should consume the only ownership slot before dispatch"
        );

        let err = dispatch_inbound_text_with_options(
            &state,
            "signal",
            "+15559876543",
            "+15559876543",
            "hello",
            Some("+15559876543".to_string()),
            InboundDispatchOptions {
                claimed_read_receipt: Some(claimed_read_receipt),
                ..Default::default()
            },
        )
        .await
        .expect_err("archived sessions should fail durable append");

        assert!(err.contains("failed to append message"));
        assert_eq!(signal_channel.mark_read_count.load(Ordering::Relaxed), 0);
        assert!(activity_service.read_receipt_queue().list().is_empty());
        assert!(
            activity_service.can_accept_read_receipt_ownership("signal"),
            "append failure should release the claimed receipt reservation"
        );
        assert!(
            state.agent_run_registry.lock().snapshot_runs().is_empty(),
            "append failure should not register an agent run"
        );

        state.shutdown_activity_service().await;
        crate::config::clear_cache();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_dispatch_inbound_text_continues_when_receipt_completion_fails() {
        install_empty_config();
        let temp = tempfile::tempdir().expect("tempdir");
        let session_store = Arc::new(SessionStore::with_base_path(temp.path().to_path_buf()));
        let activity_service = Arc::new(
            ActivityService::with_read_receipt_queue_and_limits_for_test(
                Arc::new(TaskQueue::with_capacity_limit(None, Some(0))),
                8,
                1,
            ),
        );
        // Inject an inert provider so dispatch reaches the registry-register
        // arm. This test is about receipt-completion failure semantics, not
        // provider absence.
        let state = Arc::new(
            WsServerState::new(WsServerConfig::default())
                .with_session_store(session_store)
                .with_activity_service(activity_service.clone())
                .with_llm_provider(Arc::new(StaticTestProvider)),
        );

        let claimed_read_receipt = activity_service
            .try_claim_read_receipt(
                "signal",
                ReadReceiptContext {
                    recipient: "+15559876543".to_string(),
                    timestamp: Some(1706745600000),
                    ..Default::default()
                },
            )
            .expect("receipt claim should reserve the only slot");
        assert!(
            !activity_service.can_accept_read_receipt_ownership("signal"),
            "the claim should consume the only ownership slot before dispatch"
        );

        let result = dispatch_inbound_text_with_options(
            &state,
            "signal",
            "+15559876543",
            "+15559876543",
            "hello",
            Some("+15559876543".to_string()),
            InboundDispatchOptions {
                claimed_read_receipt: Some(claimed_read_receipt),
                ..Default::default()
            },
        )
        .await
        .expect("receipt completion failure should not abort inbound dispatch");

        // Empty config means no model resolves, so the spawn arm is skipped
        // even though the provider is configured.
        assert!(!result.run_spawned);
        assert!(activity_service.read_receipt_queue().list().is_empty());
        assert!(
            activity_service.can_accept_read_receipt_ownership("signal"),
            "completion failure should still release the claimed receipt reservation"
        );
        let runs = state.agent_run_registry.lock().snapshot_runs();
        assert!(
            runs.iter().any(|run| run.message == "hello"),
            "the durable append should still register the inbound run context"
        );

        state.shutdown_activity_service().await;
        crate::config::clear_cache();
    }

    /// Pin the no-provider observable behavior on the inbound path: dispatch
    /// returns `run_spawned: false` with the run *not* registered in the
    /// agent_run_registry (no orphan), the user message is still durably
    /// persisted (channels acknowledge receipt regardless of provider state),
    /// and `session_key` is returned so out-of-band callers can correlate.
    #[tokio::test(flavor = "current_thread")]
    async fn test_dispatch_inbound_text_no_provider_skips_register_without_orphan() {
        install_empty_config();
        let temp = tempfile::tempdir().expect("tempdir");
        let session_store = Arc::new(SessionStore::with_base_path(temp.path().to_path_buf()));
        let activity_service = Arc::new(ActivityService::with_limits_for_test(8, 1));
        // No provider — exercises the defensive provider_not_configured path.
        let state = build_state(session_store.clone(), activity_service.clone(), None);

        let result = dispatch_inbound_text_with_options(
            &state,
            "signal",
            "+15551234567",
            "+15551234567",
            "hello",
            Some("+15551234567".to_string()),
            InboundDispatchOptions::default(),
        )
        .await
        .expect("dispatch should still return Ok in the defensive no-provider path");

        assert!(!result.run_spawned, "no provider → no spawn");
        assert!(
            !result.run_id.is_empty(),
            "run_id is generated even when not registered, for caller correlation"
        );
        assert!(
            state.agent_run_registry.lock().snapshot_runs().is_empty(),
            "no provider → no orphan registry entry"
        );

        // The user message was still durably appended; resolve the same
        // session key dispatch used and verify the message landed.
        let cfg = json!({});
        let (session_key, _, _) =
            resolve_scoped_session_key(&cfg, "signal", "+15551234567", "+15551234567", None);
        let session = session_store
            .get_session_by_key(&session_key)
            .expect("dispatch should create the session");
        let messages = session_store
            .get_history(&session.id, None, None)
            .expect("session history should be readable");
        assert!(
            messages.iter().any(|m| m.content == "hello"),
            "inbound message must be persisted even on the no-provider path"
        );

        state.shutdown_activity_service().await;
        crate::config::clear_cache();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_dispatch_inbound_text_persists_inbound_event_id() {
        install_empty_config();
        let temp = tempfile::tempdir().expect("tempdir");
        let session_store = Arc::new(SessionStore::with_base_path(temp.path().to_path_buf()));
        let activity_service = Arc::new(ActivityService::with_limits_for_test(8, 1));
        let state = build_state(session_store.clone(), activity_service.clone(), None);

        dispatch_inbound_text_with_options(
            &state,
            "matrix",
            "@alice:example.com",
            "!room:example.com",
            "hello",
            Some("!room:example.com".to_string()),
            InboundDispatchOptions {
                inbound_event_id: IdempotencyKey::from_str_opt("$event:example.com"),
                delivery_recipient_id: Some("!room:example.com".to_string()),
                ..Default::default()
            },
        )
        .await
        .expect("dispatch should persist Matrix inbound metadata");

        let cfg = json!({});
        let (session_key, _, _) = resolve_scoped_session_key(
            &cfg,
            "matrix",
            "@alice:example.com",
            "!room:example.com",
            None,
        );
        let session = session_store
            .get_session_by_key(&session_key)
            .expect("dispatch should create the Matrix session");
        let messages = session_store
            .get_history(&session.id, None, None)
            .expect("session history should be readable");
        let message = messages
            .iter()
            .find(|message| message.content == "hello")
            .expect("inbound message should be persisted");
        assert_eq!(
            message
                .metadata
                .as_ref()
                .and_then(|metadata| metadata.get("inbound_event_id"))
                .and_then(|value| value.as_str()),
            Some("$event:example.com")
        );

        state.shutdown_activity_service().await;
        crate::config::clear_cache();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_dispatch_inbound_text_dedupes_inbound_event_id() {
        install_empty_config();
        let temp = tempfile::tempdir().expect("tempdir");
        let session_store = Arc::new(SessionStore::with_base_path(temp.path().to_path_buf()));
        let activity_service = Arc::new(ActivityService::with_limits_for_test(8, 1));
        let state = build_state(session_store.clone(), activity_service.clone(), None);

        let first = dispatch_inbound_text_with_options(
            &state,
            "matrix",
            "@alice:example.com",
            "!room:example.com",
            "hello",
            Some("!room:example.com".to_string()),
            InboundDispatchOptions {
                inbound_event_id: IdempotencyKey::from_str_opt("$event:example.com"),
                delivery_recipient_id: Some("!room:example.com".to_string()),
                ..Default::default()
            },
        )
        .await
        .expect("first dispatch should persist");
        let duplicate = dispatch_inbound_text_with_options(
            &state,
            "matrix",
            "@alice:example.com",
            "!room:example.com",
            "hello again",
            Some("!room:example.com".to_string()),
            InboundDispatchOptions {
                inbound_event_id: IdempotencyKey::from_str_opt("$event:example.com"),
                delivery_recipient_id: Some("!room:example.com".to_string()),
                ..Default::default()
            },
        )
        .await
        .expect("duplicate dispatch should be treated as already delivered");

        assert!(!first.run_spawned);
        assert!(!duplicate.run_spawned);

        let cfg = json!({});
        let (session_key, _, _) = resolve_scoped_session_key(
            &cfg,
            "matrix",
            "@alice:example.com",
            "!room:example.com",
            None,
        );
        let session = session_store
            .get_session_by_key(&session_key)
            .expect("dispatch should create the Matrix session");
        let messages = session_store
            .get_history(&session.id, None, None)
            .expect("session history should be readable");
        let event_messages = messages
            .iter()
            .filter(|message| {
                message
                    .metadata
                    .as_ref()
                    .and_then(|metadata| metadata.get("inbound_event_id"))
                    .and_then(|value| value.as_str())
                    == Some("$event:example.com")
            })
            .count();
        assert_eq!(
            event_messages, 1,
            "duplicate Matrix event must not append twice"
        );
        assert!(
            messages
                .iter()
                .all(|message| message.content != "hello again"),
            "duplicate Matrix event must not spawn a second user message"
        );

        state.shutdown_activity_service().await;
        crate::config::clear_cache();
    }
}
