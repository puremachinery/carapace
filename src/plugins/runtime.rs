//! WASM plugin runtime
//!
//! Provides wasmtime-based instantiation of WASM plugins with host function bindings.
//! Implements the host interface defined in wit/plugin.wit.
//!
//! # Architecture
//!
//! The runtime consists of:
//! - `PluginRuntime`: Main runtime that manages plugin instances
//! - `PluginInstance`: A single instantiated plugin with its store and exports
//! - `HostState`: Per-instance state containing host context and async support
//!
//! # Security
//!
//! Each plugin instance has isolated:
//! - Memory (64MB limit enforced by wasmtime)
//! - Credentials (auto-prefixed with plugin ID)
//! - Config (scoped to plugins.<plugin-id>.*)
//! - HTTP rate limits (100/minute)
//! - Execution timeout (30s per call)

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use parking_lot::RwLock;
use thiserror::Error;
use wasmtime::component::{Component, ComponentType, Lift, Linker, Lower};
use wasmtime::{Config, Engine, ResourceLimiter, Store, StoreContextMut};

use crate::credentials::{CredentialBackend, CredentialStore};

use super::bindings::{
    BindingError, ChannelCapabilities, ChannelInfo, ChannelPluginInstance, ChatType,
    DeliveryResult, HookEvent, HookPluginInstance, HookResult, OutboundContext, PluginRegistry,
    ServicePluginInstance, ToolContext, ToolDefinition, ToolPluginInstance, ToolResult,
    WebhookPluginInstance, WebhookRequest, WebhookResponse, WitHost,
};
use super::capabilities::{RateLimiterRegistry, SsrfConfig};
use super::host::{HostError, HttpRequest, PluginHostContext};
use super::loader::{LoadedPlugin, PluginKind, PluginLoader, PluginManifest};
use super::permissions::{
    compute_effective_permissions, validate_declared_permissions, PermissionConfig,
    PermissionEnforcer,
};

/// Maximum memory per plugin instance (64MB)
pub const MAX_PLUGIN_MEMORY_BYTES: u64 = 64 * 1024 * 1024;

/// Maximum table entries per plugin instance.
pub const MAX_PLUGIN_TABLE_ELEMENTS: usize = 100_000;

/// Default execution timeout per function call (30s)
pub const DEFAULT_EXECUTION_TIMEOUT: Duration = Duration::from_secs(30);

/// Epoch tick interval for wall-clock timeout enforcement.
pub const DEFAULT_EPOCH_TICK_INTERVAL: Duration = Duration::from_millis(100);

/// Default fuel budget per WASM function call (1 billion instructions).
///
/// Fuel provides a deterministic CPU budget that complements the epoch-based
/// wall-clock timeout. A tight infinite loop will exhaust fuel before the
/// epoch deadline fires, giving a clearer error message.
pub const DEFAULT_FUEL_BUDGET: u64 = 1_000_000_000;

fn compute_epoch_deadline_ticks(timeout: Duration) -> u64 {
    let interval_ms = DEFAULT_EPOCH_TICK_INTERVAL.as_millis().max(1);
    let timeout_ms = timeout.as_millis().max(1);
    let ticks = timeout_ms.div_ceil(interval_ms);
    ticks as u64
}

struct EpochTicker {
    stop: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl EpochTicker {
    fn start(engine: Engine, interval: Duration) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let stop_clone = stop.clone();
        let handle = std::thread::Builder::new()
            .name("plugin-epoch-ticker".to_string())
            .spawn(move || {
                while !stop_clone.load(Ordering::SeqCst) {
                    std::thread::sleep(interval);
                    engine.increment_epoch();
                }
            })
            .expect("failed to spawn plugin epoch ticker thread");

        Self {
            stop,
            handle: Some(handle),
        }
    }
}

impl Drop for EpochTicker {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

struct PluginResourceLimiter {
    max_memory_bytes: usize,
    max_table_elements: usize,
}

impl ResourceLimiter for PluginResourceLimiter {
    fn memory_growing(
        &mut self,
        _current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        Ok(desired <= self.max_memory_bytes)
    }

    fn table_growing(
        &mut self,
        _current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        Ok(desired <= self.max_table_elements)
    }
}

// ============== WIT Component Model Types ==============
//
// These types mirror the WIT record definitions in wit/plugin.wit and are used
// by the component model linker to marshal data between host and guest.

/// Assert that a future is Send.
///
/// # Safety
///
/// The caller must guarantee that the future is actually Send-safe.
/// This is needed because `CredentialBackend` uses `async fn` in trait
/// which doesn't imply `Send` at the trait level, even though all concrete
/// implementations are Send (the backend type `B` is bound as `Send + Sync`).
unsafe fn assert_send<T>(
    fut: impl std::future::Future<Output = T>,
) -> impl std::future::Future<Output = T> + Send {
    /// Wrapper that unsafely implements Send for a future.
    struct AssertSend<F>(F);
    // SAFETY: Caller guarantees the inner future is Send-safe.
    unsafe impl<F> Send for AssertSend<F> {}
    impl<F: std::future::Future> std::future::Future for AssertSend<F> {
        type Output = F::Output;
        fn poll(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Self::Output> {
            // SAFETY: We are not moving the inner future, just projecting through the wrapper.
            unsafe { self.map_unchecked_mut(|s| &mut s.0).poll(cx) }
        }
    }
    AssertSend(fut)
}

/// WIT `http-request` record for the component model linker.
#[derive(Clone, Debug, ComponentType, Lift, Lower)]
#[component(record)]
struct WitHttpRequest {
    #[component(name = "method")]
    method: String,
    #[component(name = "url")]
    url: String,
    #[component(name = "headers")]
    headers: Vec<(String, String)>,
    #[component(name = "body")]
    body: Option<Vec<u8>>,
}

/// WIT `http-response` record for the component model linker.
#[derive(Clone, Debug, ComponentType, Lift, Lower)]
#[component(record)]
struct WitHttpResponse {
    #[component(name = "status")]
    status: u16,
    #[component(name = "headers")]
    headers: Vec<(String, String)>,
    #[component(name = "body")]
    body: Option<Vec<u8>>,
}

/// WIT `media-fetch-result` record for the component model linker.
#[derive(Clone, Debug, ComponentType, Lift, Lower)]
#[component(record)]
struct WitMediaFetchResult {
    #[component(name = "ok")]
    ok: bool,
    #[component(name = "local-path")]
    local_path: Option<String>,
    #[component(name = "mime-type")]
    mime_type: Option<String>,
    #[component(name = "size")]
    size: Option<u64>,
    #[component(name = "error")]
    error: Option<String>,
}

// ============== WIT Export Types (Guest -> Host) ==============
//
// These types represent the return values from WASM component exports.
// They implement `Lift` to be deserialized from WASM memory.

/// WIT `channel-info` record returned by `channel-meta.get-info` export.
#[derive(Clone, Debug, ComponentType, Lift, Lower)]
#[component(record)]
struct WitChannelInfo {
    #[component(name = "id")]
    id: String,
    #[component(name = "label")]
    label: String,
    #[component(name = "selection-label")]
    selection_label: String,
    #[component(name = "docs-path")]
    docs_path: String,
    #[component(name = "blurb")]
    blurb: String,
    #[component(name = "order")]
    order: u32,
}

/// WIT `chat-type` enum used in channel capabilities.
#[derive(Clone, Copy, Debug, ComponentType, Lift, Lower)]
#[component(enum)]
#[repr(u8)]
enum WitChatType {
    #[component(name = "dm")]
    Dm,
    #[component(name = "group")]
    Group,
    #[component(name = "channel")]
    Channel,
    #[component(name = "thread")]
    Thread,
}

const ALL_WIT_CHAT_TYPES: [WitChatType; 4] = [
    WitChatType::Dm,
    WitChatType::Group,
    WitChatType::Channel,
    WitChatType::Thread,
];

/// WIT `channel-capabilities` record returned by `channel-meta.get-capabilities` export.
#[derive(Clone, Debug, ComponentType, Lift, Lower)]
#[component(record)]
struct WitChannelCapabilities {
    #[component(name = "chat-types")]
    chat_types: Vec<WitChatType>,
    #[component(name = "polls")]
    polls: bool,
    #[component(name = "reactions")]
    reactions: bool,
    #[component(name = "edit")]
    edit: bool,
    #[component(name = "unsend")]
    unsend: bool,
    #[component(name = "reply")]
    reply: bool,
    #[component(name = "effects")]
    effects: bool,
    #[component(name = "group-management")]
    group_management: bool,
    #[component(name = "threads")]
    threads: bool,
    #[component(name = "media")]
    media: bool,
    #[component(name = "native-commands")]
    native_commands: bool,
    #[component(name = "block-streaming")]
    block_streaming: bool,
}

/// WIT `outbound-context` record passed to channel send functions.
#[derive(Clone, Debug, ComponentType, Lift, Lower)]
#[component(record)]
struct WitOutboundContext {
    #[component(name = "to")]
    to: String,
    #[component(name = "text")]
    text: String,
    #[component(name = "media-url")]
    media_url: Option<String>,
    #[component(name = "gif-playback")]
    gif_playback: bool,
    #[component(name = "reply-to-id")]
    reply_to_id: Option<String>,
    #[component(name = "thread-id")]
    thread_id: Option<String>,
    #[component(name = "account-id")]
    account_id: Option<String>,
}

/// WIT `plugin-error` record returned in `result<T, plugin-error>` exports.
#[derive(Clone, Debug, ComponentType, Lift, Lower)]
#[component(record)]
struct WitPluginError {
    #[component(name = "code")]
    code: String,
    #[component(name = "message")]
    message: String,
    #[component(name = "retryable")]
    retryable: bool,
}

/// WIT `delivery-result` record returned by send functions.
#[derive(Clone, Debug, ComponentType, Lift, Lower)]
#[component(record)]
struct WitDeliveryResult {
    #[component(name = "ok")]
    ok: bool,
    #[component(name = "message-id")]
    message_id: Option<String>,
    #[component(name = "error")]
    error: Option<String>,
    #[component(name = "retryable")]
    retryable: bool,
}

/// WIT `tool-definition` record returned by `tool.get-definitions` export.
#[derive(Clone, Debug, ComponentType, Lift, Lower)]
#[component(record)]
struct WitToolDefinition {
    #[component(name = "name")]
    name: String,
    #[component(name = "description")]
    description: String,
    #[component(name = "input-schema")]
    input_schema: String,
}

/// WIT `tool-context` record passed to `tool.invoke` export.
#[derive(Clone, Debug, ComponentType, Lift, Lower)]
#[component(record)]
struct WitToolContext {
    #[component(name = "agent-id")]
    agent_id: Option<String>,
    #[component(name = "session-key")]
    session_key: Option<String>,
    #[component(name = "message-channel")]
    message_channel: Option<String>,
    #[component(name = "sandboxed")]
    sandboxed: bool,
}

/// WIT `tool-result` record returned by `tool.invoke` export.
#[derive(Clone, Debug, ComponentType, Lift, Lower)]
#[component(record)]
struct WitToolResult {
    #[component(name = "success")]
    success: bool,
    #[component(name = "result")]
    result: Option<String>,
    #[component(name = "error")]
    error: Option<String>,
}

/// WIT `webhook-request` record passed to `webhook.handle` export.
#[derive(Clone, Debug, ComponentType, Lift, Lower)]
#[component(record)]
struct WitWebhookRequest {
    #[component(name = "method")]
    method: String,
    #[component(name = "path")]
    path: String,
    #[component(name = "headers")]
    headers: Vec<(String, String)>,
    #[component(name = "body")]
    body: Option<Vec<u8>>,
    #[component(name = "query")]
    query: Option<String>,
}

/// WIT `webhook-response` record returned by `webhook.handle` export.
#[derive(Clone, Debug, ComponentType, Lift, Lower)]
#[component(record)]
struct WitWebhookResponse {
    #[component(name = "status")]
    status: u16,
    #[component(name = "headers")]
    headers: Vec<(String, String)>,
    #[component(name = "body")]
    body: Option<Vec<u8>>,
}

/// WIT `hook-event` record passed to `hooks.handle` export.
#[derive(Clone, Debug, ComponentType, Lift, Lower)]
#[component(record)]
struct WitHookEvent {
    #[component(name = "hook-name")]
    hook_name: String,
    #[component(name = "payload")]
    payload: String,
}

/// WIT `hook-result` record returned by `hooks.handle` export.
#[derive(Clone, Debug, ComponentType, Lift, Lower)]
#[component(record)]
struct WitHookResult {
    #[component(name = "handled")]
    handled: bool,
    #[component(name = "cancel")]
    cancel: bool,
    #[component(name = "modified-payload")]
    modified_payload: Option<String>,
}

// ============== Type Conversions ==============

impl From<WitChannelInfo> for ChannelInfo {
    fn from(wit: WitChannelInfo) -> Self {
        Self {
            id: wit.id,
            label: wit.label,
            selection_label: wit.selection_label,
            docs_path: wit.docs_path,
            blurb: wit.blurb,
            order: wit.order,
        }
    }
}

impl From<WitChatType> for ChatType {
    fn from(wit: WitChatType) -> Self {
        match wit {
            WitChatType::Dm => ChatType::Dm,
            WitChatType::Group => ChatType::Group,
            WitChatType::Channel => ChatType::Channel,
            WitChatType::Thread => ChatType::Thread,
        }
    }
}

impl From<WitChannelCapabilities> for ChannelCapabilities {
    fn from(wit: WitChannelCapabilities) -> Self {
        // Keep all WIT variants referenced; they are constructed by Wasmtime at runtime.
        let _ = ALL_WIT_CHAT_TYPES;
        Self {
            chat_types: wit.chat_types.into_iter().map(ChatType::from).collect(),
            polls: wit.polls,
            reactions: wit.reactions,
            edit: wit.edit,
            unsend: wit.unsend,
            reply: wit.reply,
            effects: wit.effects,
            group_management: wit.group_management,
            threads: wit.threads,
            media: wit.media,
            native_commands: wit.native_commands,
            block_streaming: wit.block_streaming,
        }
    }
}

impl From<&OutboundContext> for WitOutboundContext {
    fn from(ctx: &OutboundContext) -> Self {
        Self {
            to: ctx.to.clone(),
            text: ctx.text.clone(),
            media_url: ctx.media_url.clone(),
            gif_playback: ctx.gif_playback,
            reply_to_id: ctx.reply_to_id.clone(),
            thread_id: ctx.thread_id.clone(),
            account_id: ctx.account_id.clone(),
        }
    }
}

impl From<WitDeliveryResult> for DeliveryResult {
    fn from(wit: WitDeliveryResult) -> Self {
        Self {
            ok: wit.ok,
            message_id: wit.message_id,
            error: wit.error,
            retryable: wit.retryable,
            // These fields are not in the WIT delivery-result type;
            // they are host-side extensions. Default to None.
            conversation_id: None,
            to_jid: None,
            poll_id: None,
        }
    }
}

impl From<WitToolDefinition> for ToolDefinition {
    fn from(wit: WitToolDefinition) -> Self {
        Self {
            name: wit.name,
            description: wit.description,
            input_schema: wit.input_schema,
        }
    }
}

impl From<&ToolContext> for WitToolContext {
    fn from(ctx: &ToolContext) -> Self {
        Self {
            agent_id: ctx.agent_id.clone(),
            session_key: ctx.session_key.clone(),
            message_channel: ctx.message_channel.clone(),
            sandboxed: ctx.sandboxed,
        }
    }
}

impl From<WitToolResult> for ToolResult {
    fn from(wit: WitToolResult) -> Self {
        Self {
            success: wit.success,
            result: wit.result,
            error: wit.error,
        }
    }
}

impl From<&WebhookRequest> for WitWebhookRequest {
    fn from(req: &WebhookRequest) -> Self {
        Self {
            method: req.method.clone(),
            path: req.path.clone(),
            headers: req.headers.clone(),
            body: req.body.clone(),
            query: req.query.clone(),
        }
    }
}

impl From<WitWebhookResponse> for WebhookResponse {
    fn from(wit: WitWebhookResponse) -> Self {
        Self {
            status: wit.status,
            headers: wit.headers,
            body: wit.body,
        }
    }
}

impl From<&HookEvent> for WitHookEvent {
    fn from(event: &HookEvent) -> Self {
        Self {
            hook_name: event.hook_name.clone(),
            payload: event.payload.clone(),
        }
    }
}

impl From<WitHookResult> for HookResult {
    fn from(wit: WitHookResult) -> Self {
        Self {
            handled: wit.handled,
            cancel: wit.cancel,
            modified_payload: wit.modified_payload,
        }
    }
}

/// Plugin runtime errors
#[derive(Error, Debug)]
pub enum RuntimeError {
    #[error("Plugin not found: {0}")]
    PluginNotFound(String),

    #[error("Plugin instantiation failed: {0}")]
    InstantiationError(String),

    #[error("Plugin function call failed: {0}")]
    CallError(String),

    #[error("Plugin execution timeout")]
    ExecutionTimeout,

    #[error("Plugin memory limit exceeded")]
    MemoryLimitExceeded,

    #[error("Host error: {0}")]
    HostError(#[from] HostError),

    #[error("Loader error: {0}")]
    LoaderError(#[from] super::loader::LoaderError),

    #[error("Wasmtime error: {0}")]
    WasmtimeError(String),

    #[error("Plugin returned error: [{code}] {message}")]
    PluginError { code: String, message: String },

    #[error("WASM fuel exhausted (budget: {budget} instructions)")]
    FuelExhausted { budget: u64 },

    #[error("Plugin '{plugin_id}' denied capabilities: {capabilities:?}")]
    CapabilityDenied {
        plugin_id: String,
        capabilities: Vec<String>,
    },
}

/// State held in each plugin's wasmtime store
pub struct HostState<B: CredentialBackend + Send + Sync + 'static> {
    /// Plugin ID for this instance
    pub plugin_id: String,

    /// Host context for capability access
    pub host_ctx: Arc<PluginHostContext<B>>,

    /// Resource limiter for this plugin instance
    limiter: PluginResourceLimiter,
}

// Note: Full WASI integration will be added when we upgrade to wasmtime with
// component model preview2 support fully stable. For now, we implement the
// minimal host functions needed by plugins directly.

/// Plugin runtime that manages WASM plugin instances
pub struct PluginRuntime<B: CredentialBackend + 'static> {
    /// Wasmtime engine (shared)
    engine: Engine,

    /// Plugin loader
    loader: Arc<PluginLoader>,

    /// Credential store (shared across all plugins)
    credential_store: Arc<CredentialStore<B>>,

    /// Rate limiters (shared)
    rate_limiters: Arc<RateLimiterRegistry>,

    /// SSRF configuration
    ssrf_config: SsrfConfig,

    /// Sandbox configuration for capability enforcement
    sandbox_config: super::sandbox::SandboxConfig,

    /// Fine-grained permission configuration
    permission_config: PermissionConfig,

    /// Epoch deadline ticks for wall-clock timeouts
    epoch_deadline_ticks: u64,

    /// Epoch ticker for wall-clock timeouts (kept for drop)
    _epoch_ticker: EpochTicker,

    /// Loaded plugin instances by ID
    instances: RwLock<HashMap<String, Arc<PluginInstanceHandle<B>>>>,

    /// Plugin registry for dispatch
    registry: Arc<PluginRegistry>,
}

/// Handle to an instantiated plugin
pub struct PluginInstanceHandle<B: CredentialBackend + Send + Sync + 'static> {
    /// Plugin manifest
    pub manifest: PluginManifest,

    /// Epoch deadline ticks for wall-clock timeouts
    epoch_deadline_ticks: u64,

    /// The wasmtime store with plugin state
    store: RwLock<Store<HostState<B>>>,

    /// Component instance (for calling exports)
    instance: wasmtime::component::Instance,

    /// Component (needed for export index lookups in wasmtime 29+)
    component: Component,
}

impl<B: CredentialBackend + Send + Sync + 'static> PluginInstanceHandle<B> {
    /// Look up a typed function from a named exported interface.
    ///
    /// Uses `Component::get_export_index` to navigate the interface hierarchy
    /// (wasmtime 24+ removed `Instance::exports()` in favour of index-based lookups).
    fn get_iface_typed_func<P, R>(
        &self,
        store: &mut Store<HostState<B>>,
        iface_name: &str,
        func_name: &str,
    ) -> Result<wasmtime::component::TypedFunc<P, R>, BindingError>
    where
        P: wasmtime::component::ComponentNamedList + Lower + Send + Sync + 'static,
        R: wasmtime::component::ComponentNamedList + Lift + Send + Sync + 'static,
    {
        // Step 1: look up the exported interface index
        let iface_idx = self
            .component
            .get_export_index(None, iface_name)
            .ok_or_else(|| {
                BindingError::CallError(format!("exported interface '{}' not found", iface_name))
            })?;

        // Step 2: look up the function within that interface
        let func_idx = self
            .component
            .get_export_index(Some(&iface_idx), func_name)
            .ok_or_else(|| {
                BindingError::CallError(format!(
                    "function '{}' not found in interface '{}'",
                    func_name, iface_name
                ))
            })?;

        // Step 3: get the typed func from the instance using the index
        self.instance
            .get_typed_func::<P, R>(&mut *store, &func_idx)
            .map_err(|e| {
                BindingError::CallError(format!(
                    "failed to get typed func '{}.{}': {}",
                    iface_name, func_name, e
                ))
            })
    }

    /// Call an exported function from a named interface with no parameters.
    ///
    /// Looks up the function `func_name` within the exported interface `iface_name`,
    /// calls it asynchronously (required by the async-enabled engine), and returns
    /// the result. Handles the `post_return_async` cleanup automatically.
    fn call_export_no_args<R>(&self, iface_name: &str, func_name: &str) -> Result<R, BindingError>
    where
        R: wasmtime::component::ComponentNamedList + Lift + Send + Sync + 'static,
    {
        let mut store = self.store.write();

        store.set_epoch_deadline(self.epoch_deadline_ticks);

        // Set fuel budget for this call
        if let Err(e) = store.set_fuel(DEFAULT_FUEL_BUDGET) {
            return Err(BindingError::CallError(format!(
                "failed to set fuel budget: {}",
                e
            )));
        }

        // Get the exported interface, then get the typed function
        let func = self.get_iface_typed_func::<(), R>(&mut store, iface_name, func_name)?;

        // Call the function asynchronously (required by async-enabled engine)
        // We bridge sync -> async using tokio's block_in_place + block_on
        let result = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current()
                .block_on(async { func.call_async(&mut *store, ()).await })
        })
        .map_err(|e: wasmtime::Error| {
            let msg = e.to_string();
            let msg_lower = msg.to_lowercase();
            if msg_lower.contains("fuel") {
                BindingError::CallError(format!(
                    "WASM fuel exhausted during '{}.{}' (budget: {} instructions)",
                    iface_name, func_name, DEFAULT_FUEL_BUDGET
                ))
            } else if msg_lower.contains("epoch") || msg_lower.contains("interrupt") {
                BindingError::CallError(format!(
                    "WASM execution timed out during '{}.{}' (timeout: {}s)",
                    iface_name,
                    func_name,
                    DEFAULT_EXECUTION_TIMEOUT.as_secs()
                ))
            } else {
                BindingError::CallError(format!(
                    "call to '{}.{}' failed: {}",
                    iface_name, func_name, msg
                ))
            }
        })?;

        // Post-return cleanup
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current()
                .block_on(async { func.post_return_async(&mut *store).await })
        })
        .map_err(|e| {
            BindingError::CallError(format!(
                "post_return for '{}.{}' failed: {}",
                iface_name, func_name, e
            ))
        })?;

        Ok(result)
    }

    /// Call an exported function from a named interface with one parameter.
    ///
    /// Same as [`call_export_no_args`] but accepts a single typed parameter.
    fn call_export_one_arg<P, R>(
        &self,
        iface_name: &str,
        func_name: &str,
        param: P,
    ) -> Result<R, BindingError>
    where
        P: wasmtime::component::ComponentNamedList + Lower + Send + Sync + 'static,
        R: wasmtime::component::ComponentNamedList + Lift + Send + Sync + 'static,
    {
        let mut store = self.store.write();

        store.set_epoch_deadline(self.epoch_deadline_ticks);

        // Set fuel budget for this call
        if let Err(e) = store.set_fuel(DEFAULT_FUEL_BUDGET) {
            return Err(BindingError::CallError(format!(
                "failed to set fuel budget: {}",
                e
            )));
        }

        let func = self.get_iface_typed_func::<P, R>(&mut store, iface_name, func_name)?;

        let result = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current()
                .block_on(async { func.call_async(&mut *store, param).await })
        })
        .map_err(|e: wasmtime::Error| {
            let msg = e.to_string();
            let msg_lower = msg.to_lowercase();
            if msg_lower.contains("fuel") {
                BindingError::CallError(format!(
                    "WASM fuel exhausted during '{}.{}' (budget: {} instructions)",
                    iface_name, func_name, DEFAULT_FUEL_BUDGET
                ))
            } else if msg_lower.contains("epoch") || msg_lower.contains("interrupt") {
                BindingError::CallError(format!(
                    "WASM execution timed out during '{}.{}' (timeout: {}s)",
                    iface_name,
                    func_name,
                    DEFAULT_EXECUTION_TIMEOUT.as_secs()
                ))
            } else {
                BindingError::CallError(format!(
                    "call to '{}.{}' failed: {}",
                    iface_name, func_name, msg
                ))
            }
        })?;

        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current()
                .block_on(async { func.post_return_async(&mut *store).await })
        })
        .map_err(|e| {
            BindingError::CallError(format!(
                "post_return for '{}.{}' failed: {}",
                iface_name, func_name, e
            ))
        })?;

        Ok(result)
    }
}

impl<B: CredentialBackend + Send + Sync + 'static> PluginRuntime<B> {
    /// Create a new plugin runtime
    pub fn new(
        loader: Arc<PluginLoader>,
        credential_store: Arc<CredentialStore<B>>,
    ) -> Result<Self, RuntimeError> {
        Self::with_config(
            loader,
            credential_store,
            Arc::new(RateLimiterRegistry::new()),
            SsrfConfig::default(),
        )
    }

    /// Create a new plugin runtime with custom configuration
    pub fn with_config(
        loader: Arc<PluginLoader>,
        credential_store: Arc<CredentialStore<B>>,
        rate_limiters: Arc<RateLimiterRegistry>,
        ssrf_config: SsrfConfig,
    ) -> Result<Self, RuntimeError> {
        Self::with_full_config(
            loader,
            credential_store,
            rate_limiters,
            ssrf_config,
            super::sandbox::SandboxConfig::default(),
        )
    }

    /// Create a new plugin runtime with all configuration including sandbox policy
    pub fn with_full_config(
        loader: Arc<PluginLoader>,
        credential_store: Arc<CredentialStore<B>>,
        rate_limiters: Arc<RateLimiterRegistry>,
        ssrf_config: SsrfConfig,
        sandbox_config: super::sandbox::SandboxConfig,
    ) -> Result<Self, RuntimeError> {
        Self::with_permissions_config(
            loader,
            credential_store,
            rate_limiters,
            ssrf_config,
            sandbox_config,
            PermissionConfig::default(),
        )
    }

    /// Create a new plugin runtime with all configuration including fine-grained permissions
    pub fn with_permissions_config(
        loader: Arc<PluginLoader>,
        credential_store: Arc<CredentialStore<B>>,
        rate_limiters: Arc<RateLimiterRegistry>,
        ssrf_config: SsrfConfig,
        sandbox_config: super::sandbox::SandboxConfig,
        permission_config: PermissionConfig,
    ) -> Result<Self, RuntimeError> {
        // Configure wasmtime engine
        let mut config = Config::new();
        config.wasm_component_model(true);
        config.async_support(true);
        config.consume_fuel(true);
        config.epoch_interruption(true);
        // Memory limits are enforced per-instance via resource limiter

        let engine =
            Engine::new(&config).map_err(|e| RuntimeError::WasmtimeError(e.to_string()))?;

        let epoch_deadline_ticks = compute_epoch_deadline_ticks(DEFAULT_EXECUTION_TIMEOUT);
        let epoch_ticker = EpochTicker::start(engine.clone(), DEFAULT_EPOCH_TICK_INTERVAL);

        Ok(Self {
            engine,
            loader,
            credential_store,
            rate_limiters,
            ssrf_config,
            sandbox_config,
            permission_config,
            epoch_deadline_ticks,
            _epoch_ticker: epoch_ticker,
            instances: RwLock::new(HashMap::new()),
            registry: Arc::new(PluginRegistry::new()),
        })
    }

    /// Get the plugin registry
    pub fn registry(&self) -> Arc<PluginRegistry> {
        self.registry.clone()
    }

    /// Load and instantiate all plugins from the loader
    pub async fn load_all(&self) -> Result<Vec<String>, RuntimeError> {
        let plugin_ids = self.loader.list_plugins();
        let mut loaded = Vec::new();

        for plugin_id in plugin_ids {
            match self.instantiate_plugin(&plugin_id).await {
                Ok(()) => {
                    tracing::info!(plugin_id = %plugin_id, "Plugin instantiated");
                    loaded.push(plugin_id);
                }
                Err(e) => {
                    tracing::warn!(plugin_id = %plugin_id, error = %e, "Failed to instantiate plugin");
                }
            }
        }

        Ok(loaded)
    }

    /// Instantiate a single plugin by ID
    pub async fn instantiate_plugin(&self, plugin_id: &str) -> Result<(), RuntimeError> {
        // Get the loaded plugin
        let loaded = self
            .loader
            .get_plugin(plugin_id)
            .ok_or_else(|| RuntimeError::PluginNotFound(plugin_id.to_string()))?;

        // Check capabilities against sandbox policy — block if denied
        if let Some(ref discovered) = loaded.discovered_capabilities {
            if let Err(denied) =
                super::sandbox::check_capabilities(plugin_id, discovered, &self.sandbox_config)
            {
                let denied_names: Vec<String> = denied.iter().map(|c| c.to_string()).collect();
                tracing::warn!(
                    plugin_id = %plugin_id,
                    denied = ?denied_names,
                    "plugin capabilities denied by sandbox policy — blocking instantiation"
                );
                crate::logging::audit::audit(
                    crate::logging::audit::AuditEvent::SkillCapabilityDenied {
                        skill_id: plugin_id.to_string(),
                        capabilities: denied_names.clone(),
                    },
                );
                return Err(RuntimeError::CapabilityDenied {
                    plugin_id: plugin_id.to_string(),
                    capabilities: denied_names,
                });
            }
        }

        // Validate fine-grained permissions at load time
        let permission_errors = validate_declared_permissions(
            plugin_id,
            &loaded.manifest.permissions,
            &self.permission_config,
        );
        if !permission_errors.is_empty() {
            let error_msgs: Vec<String> = permission_errors.iter().map(|e| e.to_string()).collect();
            tracing::warn!(
                plugin_id = %plugin_id,
                errors = ?error_msgs,
                "plugin declared permissions failed validation"
            );
            return Err(RuntimeError::CapabilityDenied {
                plugin_id: plugin_id.to_string(),
                capabilities: error_msgs,
            });
        }

        // Compute effective permissions for this plugin
        let effective_permissions = compute_effective_permissions(
            plugin_id,
            &loaded.manifest.permissions,
            &self.permission_config,
        );
        let permission_enforcer =
            PermissionEnforcer::new(effective_permissions, self.permission_config.enabled);

        // Create host context for this plugin with permission enforcement
        let host_ctx = Arc::new(PluginHostContext::with_permissions(
            plugin_id.to_string(),
            self.credential_store.clone(),
            self.rate_limiters.clone(),
            self.ssrf_config.clone(),
            permission_enforcer,
        ));

        // Create the host state
        let host_state = HostState {
            plugin_id: plugin_id.to_string(),
            host_ctx,
            limiter: PluginResourceLimiter {
                max_memory_bytes: MAX_PLUGIN_MEMORY_BYTES as usize,
                max_table_elements: MAX_PLUGIN_TABLE_ELEMENTS,
            },
        };

        // Create the store with host state
        let mut store = Store::new(&self.engine, host_state);
        // SECURITY: enforce per-instance memory limits for plugin code.
        store.limiter(|state| &mut state.limiter);

        // Set epoch deadline for wall-clock timeout enforcement
        store.set_epoch_deadline(self.epoch_deadline_ticks);

        // Set initial fuel budget (replenished before each call)
        if let Err(e) = store.set_fuel(DEFAULT_FUEL_BUDGET) {
            return Err(RuntimeError::WasmtimeError(format!(
                "Failed to set initial fuel budget: {}",
                e
            )));
        }

        // Create a linker and add host functions
        let mut linker: Linker<HostState<B>> = Linker::new(&self.engine);

        // Add our host functions to the linker
        self.add_host_functions(&mut linker)?;

        // Create component from the module bytes
        let component = Component::new(&self.engine, &loaded.wasm_bytes).map_err(|e| {
            RuntimeError::WasmtimeError(format!("Failed to create component: {}", e))
        })?;

        // Instantiate the component
        let instance = linker
            .instantiate_async(&mut store, &component)
            .await
            .map_err(|e| RuntimeError::InstantiationError(e.to_string()))?;

        // Create the instance handle
        let handle = Arc::new(PluginInstanceHandle {
            manifest: loaded.manifest.clone(),
            epoch_deadline_ticks: self.epoch_deadline_ticks,
            store: RwLock::new(store),
            instance,
            component,
        });

        // Store the instance
        {
            let mut instances = self.instances.write();
            instances.insert(plugin_id.to_string(), handle.clone());
        }

        // Register capabilities based on plugin kind
        self.register_capabilities(plugin_id, &loaded, handle)?;

        Ok(())
    }

    /// Add host functions to the linker.
    ///
    /// Registers all host interface functions defined in `wit/plugin.wit` with the
    /// wasmtime component model linker. Each function is bound under the `"host"`
    /// instance namespace and delegates to [`WitHost`] which wraps
    /// [`PluginHostContext`] for the actual implementation.
    ///
    /// Sync functions (logging, config) use `func_wrap`.
    /// Async functions (credentials, HTTP, media) use `func_wrap_async`.
    fn add_host_functions(&self, linker: &mut Linker<HostState<B>>) -> Result<(), RuntimeError> {
        let mut host_instance = linker.instance("host").map_err(|e| {
            RuntimeError::WasmtimeError(format!("Failed to create host instance in linker: {}", e))
        })?;

        Self::add_logging_fns(&mut host_instance)?;
        Self::add_config_fns(&mut host_instance)?;
        Self::add_credential_fns(&mut host_instance)?;
        Self::add_http_fns(&mut host_instance)?;
        Self::add_media_fns(&mut host_instance)?;

        Ok(())
    }

    /// Register logging host functions (sync).
    fn add_logging_fns(
        host_instance: &mut wasmtime::component::LinkerInstance<'_, HostState<B>>,
    ) -> Result<(), RuntimeError> {
        host_instance
            .func_wrap(
                "log-debug",
                |ctx: StoreContextMut<'_, HostState<B>>, (message,): (String,)| {
                    let wit = WitHost::new(ctx.data().host_ctx.clone());
                    wit.log_debug(&message);
                    Ok(())
                },
            )
            .map_err(|e| RuntimeError::WasmtimeError(format!("Failed to bind log-debug: {}", e)))?;

        host_instance
            .func_wrap(
                "log-info",
                |ctx: StoreContextMut<'_, HostState<B>>, (message,): (String,)| {
                    let wit = WitHost::new(ctx.data().host_ctx.clone());
                    wit.log_info(&message);
                    Ok(())
                },
            )
            .map_err(|e| RuntimeError::WasmtimeError(format!("Failed to bind log-info: {}", e)))?;

        host_instance
            .func_wrap(
                "log-warn",
                |ctx: StoreContextMut<'_, HostState<B>>, (message,): (String,)| {
                    let wit = WitHost::new(ctx.data().host_ctx.clone());
                    wit.log_warn(&message);
                    Ok(())
                },
            )
            .map_err(|e| RuntimeError::WasmtimeError(format!("Failed to bind log-warn: {}", e)))?;

        host_instance
            .func_wrap(
                "log-error",
                |ctx: StoreContextMut<'_, HostState<B>>, (message,): (String,)| {
                    let wit = WitHost::new(ctx.data().host_ctx.clone());
                    wit.log_error(&message);
                    Ok(())
                },
            )
            .map_err(|e| RuntimeError::WasmtimeError(format!("Failed to bind log-error: {}", e)))?;

        Ok(())
    }

    /// Register config host functions (sync).
    fn add_config_fns(
        host_instance: &mut wasmtime::component::LinkerInstance<'_, HostState<B>>,
    ) -> Result<(), RuntimeError> {
        host_instance
            .func_wrap(
                "config-get",
                |ctx: StoreContextMut<'_, HostState<B>>,
                 (key,): (String,)|
                 -> wasmtime::Result<(Option<String>,)> {
                    let wit = WitHost::new(ctx.data().host_ctx.clone());
                    Ok((wit.config_get(&key),))
                },
            )
            .map_err(|e| {
                RuntimeError::WasmtimeError(format!("Failed to bind config-get: {}", e))
            })?;

        Ok(())
    }

    /// Register credential host functions (async).
    fn add_credential_fns(
        host_instance: &mut wasmtime::component::LinkerInstance<'_, HostState<B>>,
    ) -> Result<(), RuntimeError> {
        host_instance
            .func_wrap_async(
                "credential-get",
                |ctx: StoreContextMut<'_, HostState<B>>,
                 (key,): (String,)|
                 -> Box<
                    dyn std::future::Future<Output = wasmtime::Result<(Option<String>,)>>
                        + Send
                        + '_,
                > {
                    let host_ctx = ctx.data().host_ctx.clone();
                    // SAFETY: PluginHostContext<B> is Send+Sync (B: Send+Sync),
                    // and all concrete CredentialBackend impls produce Send futures.
                    Box::new(unsafe {
                        assert_send(async move {
                            let wit = WitHost::new(host_ctx);
                            Ok((wit.credential_get(&key).await,))
                        })
                    })
                },
            )
            .map_err(|e| {
                RuntimeError::WasmtimeError(format!("Failed to bind credential-get: {}", e))
            })?;

        host_instance
            .func_wrap_async(
                "credential-set",
                |ctx: StoreContextMut<'_, HostState<B>>,
                 (key, value): (String, String)|
                 -> Box<
                    dyn std::future::Future<Output = wasmtime::Result<(bool,)>> + Send + '_,
                > {
                    let host_ctx = ctx.data().host_ctx.clone();
                    // SAFETY: Same reasoning as credential-get above.
                    Box::new(unsafe {
                        assert_send(async move {
                            let wit = WitHost::new(host_ctx);
                            Ok((wit.credential_set(&key, &value).await,))
                        })
                    })
                },
            )
            .map_err(|e| {
                RuntimeError::WasmtimeError(format!("Failed to bind credential-set: {}", e))
            })?;

        Ok(())
    }

    /// Register HTTP host functions (async).
    fn add_http_fns(
        host_instance: &mut wasmtime::component::LinkerInstance<'_, HostState<B>>,
    ) -> Result<(), RuntimeError> {
        host_instance
            .func_wrap_async(
                "http-fetch",
                |ctx: StoreContextMut<'_, HostState<B>>,
                 (req,): (WitHttpRequest,)|
                 -> Box<
                    dyn std::future::Future<
                            Output = wasmtime::Result<(Result<WitHttpResponse, String>,)>,
                        > + Send
                        + '_,
                > {
                    let host_ctx = ctx.data().host_ctx.clone();
                    Box::new(async move {
                        let wit = WitHost::new(host_ctx);
                        let host_req = HttpRequest {
                            method: req.method,
                            url: req.url,
                            headers: req.headers,
                            body: req.body,
                        };
                        let result = match wit.http_fetch(host_req).await {
                            Ok(resp) => Ok(WitHttpResponse {
                                status: resp.status,
                                headers: resp.headers,
                                body: resp.body,
                            }),
                            Err(e) => Err(e),
                        };
                        Ok((result,))
                    })
                },
            )
            .map_err(|e| {
                RuntimeError::WasmtimeError(format!("Failed to bind http-fetch: {}", e))
            })?;

        Ok(())
    }

    /// Register media host functions (async).
    fn add_media_fns(
        host_instance: &mut wasmtime::component::LinkerInstance<'_, HostState<B>>,
    ) -> Result<(), RuntimeError> {
        host_instance
            .func_wrap_async(
                "media-fetch",
                |ctx: StoreContextMut<'_, HostState<B>>,
                 (url, max_bytes, timeout_ms): (String, Option<u64>, Option<u32>)|
                 -> Box<
                    dyn std::future::Future<Output = wasmtime::Result<(WitMediaFetchResult,)>>
                        + Send
                        + '_,
                > {
                    let host_ctx = ctx.data().host_ctx.clone();
                    Box::new(async move {
                        let wit = WitHost::new(host_ctx);
                        let result = wit.media_fetch(&url, max_bytes, timeout_ms).await;
                        Ok((WitMediaFetchResult {
                            ok: result.ok,
                            local_path: result.local_path,
                            mime_type: result.mime_type,
                            size: result.size,
                            error: result.error,
                        },))
                    })
                },
            )
            .map_err(|e| {
                RuntimeError::WasmtimeError(format!("Failed to bind media-fetch: {}", e))
            })?;

        Ok(())
    }

    /// Register plugin capabilities with the registry
    fn register_capabilities(
        &self,
        plugin_id: &str,
        loaded: &LoadedPlugin,
        handle: Arc<PluginInstanceHandle<B>>,
    ) -> Result<(), RuntimeError> {
        match loaded.manifest.kind {
            PluginKind::Channel => {
                let adapter = ChannelAdapter::new(plugin_id.to_string(), handle);
                self.registry
                    .register_channel(plugin_id.to_string(), Arc::new(adapter));
            }
            PluginKind::Tool => {
                let adapter = ToolAdapter::new(plugin_id.to_string(), handle);
                self.registry
                    .register_tool(plugin_id.to_string(), Arc::new(adapter));
            }
            PluginKind::Webhook => {
                let adapter = WebhookAdapter::new(plugin_id.to_string(), handle);
                self.registry
                    .register_webhook(plugin_id.to_string(), Arc::new(adapter));
            }
            PluginKind::Service => {
                let adapter = ServiceAdapter::new(plugin_id.to_string(), handle);
                self.registry
                    .register_service(plugin_id.to_string(), Arc::new(adapter));
            }
            PluginKind::Hook => {
                let adapter = HookAdapter::new(plugin_id.to_string(), handle);
                self.registry
                    .register_hook(plugin_id.to_string(), Arc::new(adapter));
            }
            PluginKind::Provider => {
                // Provider plugins are handled separately
                tracing::debug!(plugin_id = %plugin_id, "Provider plugin registered (inference only)");
            }
        }

        Ok(())
    }

    /// Unload a plugin instance
    pub fn unload_plugin(&self, plugin_id: &str) -> Result<(), RuntimeError> {
        // Remove from instances
        {
            let mut instances = self.instances.write();
            instances.remove(plugin_id);
        }

        // Remove from registry
        self.registry.unregister(plugin_id);

        Ok(())
    }

    /// Get a plugin instance by ID
    pub fn get_instance(&self, plugin_id: &str) -> Option<Arc<PluginInstanceHandle<B>>> {
        let instances = self.instances.read();
        instances.get(plugin_id).cloned()
    }

    /// List all loaded plugin IDs
    pub fn list_plugins(&self) -> Vec<String> {
        let instances = self.instances.read();
        instances.keys().cloned().collect()
    }

    /// Start all service plugins
    pub async fn start_services(&self) -> Result<(), RuntimeError> {
        let services = self.registry.get_services();
        for (id, service) in services {
            match service.start() {
                Ok(()) => {
                    tracing::info!(plugin_id = %id, "Service plugin started");
                }
                Err(e) => {
                    tracing::error!(plugin_id = %id, error = %e, "Failed to start service plugin");
                }
            }
        }
        Ok(())
    }

    /// Stop all service plugins
    pub async fn stop_services(&self) -> Result<(), RuntimeError> {
        let services = self.registry.get_services();
        for (id, service) in services {
            match service.stop() {
                Ok(()) => {
                    tracing::info!(plugin_id = %id, "Service plugin stopped");
                }
                Err(e) => {
                    tracing::warn!(plugin_id = %id, error = %e, "Error stopping service plugin");
                }
            }
        }
        Ok(())
    }
}

// ============== Capability Adapters ==============

/// Adapter that implements ChannelPluginInstance for WASM plugins
struct ChannelAdapter<B: CredentialBackend + Send + Sync + 'static> {
    plugin_id: String,
    handle: Arc<PluginInstanceHandle<B>>,
}

impl<B: CredentialBackend + Send + Sync + 'static> ChannelAdapter<B> {
    fn new(plugin_id: String, handle: Arc<PluginInstanceHandle<B>>) -> Self {
        Self { plugin_id, handle }
    }
}

// SAFETY: ChannelAdapter only holds an Arc<PluginInstanceHandle<B>> whose interior
// wasmtime Store is guarded by an RwLock.  All access goes through the lock,
// so sharing across threads is safe.
unsafe impl<B: CredentialBackend + Send + Sync + 'static> Send for ChannelAdapter<B> {}
unsafe impl<B: CredentialBackend + Send + Sync + 'static> Sync for ChannelAdapter<B> {}

impl<B: CredentialBackend + Send + Sync + 'static> ChannelPluginInstance for ChannelAdapter<B> {
    fn get_info(&self) -> Result<ChannelInfo, BindingError> {
        tracing::debug!(plugin_id = %self.plugin_id, "Calling WASM export channel-meta.get-info");
        let (wit_info,): (WitChannelInfo,) = self
            .handle
            .call_export_no_args("channel-meta", "get-info")?;
        Ok(ChannelInfo::from(wit_info))
    }

    fn get_capabilities(&self) -> Result<ChannelCapabilities, BindingError> {
        tracing::debug!(plugin_id = %self.plugin_id, "Calling WASM export channel-meta.get-capabilities");
        let (wit_caps,): (WitChannelCapabilities,) = self
            .handle
            .call_export_no_args("channel-meta", "get-capabilities")?;
        Ok(ChannelCapabilities::from(wit_caps))
    }

    fn send_text(&self, ctx: OutboundContext) -> Result<DeliveryResult, BindingError> {
        tracing::debug!(plugin_id = %self.plugin_id, to = %ctx.to, "Calling WASM export channel-adapter.send-text");
        let wit_ctx = WitOutboundContext::from(&ctx);
        // The WIT export returns `result<delivery-result, plugin-error>`
        let (result,): (Result<WitDeliveryResult, WitPluginError>,) = self
            .handle
            .call_export_one_arg("channel-adapter", "send-text", (wit_ctx,))?;
        match result {
            Ok(dr) => Ok(DeliveryResult::from(dr)),
            Err(pe) => Err(BindingError::CallError(format!(
                "plugin error [{}]: {}",
                pe.code, pe.message
            ))),
        }
    }

    fn send_media(&self, ctx: OutboundContext) -> Result<DeliveryResult, BindingError> {
        tracing::debug!(plugin_id = %self.plugin_id, to = %ctx.to, "Calling WASM export channel-adapter.send-media");
        let wit_ctx = WitOutboundContext::from(&ctx);
        let (result,): (Result<WitDeliveryResult, WitPluginError>,) = self
            .handle
            .call_export_one_arg("channel-adapter", "send-media", (wit_ctx,))?;
        match result {
            Ok(dr) => Ok(DeliveryResult::from(dr)),
            Err(pe) => Err(BindingError::CallError(format!(
                "plugin error [{}]: {}",
                pe.code, pe.message
            ))),
        }
    }
}

/// Adapter that implements ToolPluginInstance for WASM plugins
struct ToolAdapter<B: CredentialBackend + Send + Sync + 'static> {
    plugin_id: String,
    handle: Arc<PluginInstanceHandle<B>>,
}

impl<B: CredentialBackend + Send + Sync + 'static> ToolAdapter<B> {
    fn new(plugin_id: String, handle: Arc<PluginInstanceHandle<B>>) -> Self {
        Self { plugin_id, handle }
    }
}

// SAFETY: ToolAdapter only holds an Arc<PluginInstanceHandle<B>> whose interior
// wasmtime Store is guarded by an RwLock.  All access goes through the lock,
// so sharing across threads is safe.
unsafe impl<B: CredentialBackend + Send + Sync + 'static> Send for ToolAdapter<B> {}
unsafe impl<B: CredentialBackend + Send + Sync + 'static> Sync for ToolAdapter<B> {}

impl<B: CredentialBackend + Send + Sync + 'static> ToolPluginInstance for ToolAdapter<B> {
    fn get_definitions(&self) -> Result<Vec<ToolDefinition>, BindingError> {
        tracing::debug!(plugin_id = %self.plugin_id, "Calling WASM export tool.get-definitions");
        let (wit_defs,): (Vec<WitToolDefinition>,) =
            self.handle.call_export_no_args("tool", "get-definitions")?;
        Ok(wit_defs.into_iter().map(ToolDefinition::from).collect())
    }

    fn invoke(
        &self,
        name: &str,
        params: &str,
        ctx: ToolContext,
    ) -> Result<ToolResult, BindingError> {
        tracing::debug!(plugin_id = %self.plugin_id, tool = %name, "Calling WASM export tool.invoke");
        let wit_ctx = WitToolContext::from(&ctx);
        // The WIT export signature: invoke(name: string, params: string, ctx: tool-context) -> result<tool-result, plugin-error>
        let (result,): (Result<WitToolResult, WitPluginError>,) = self.handle.call_export_one_arg(
            "tool",
            "invoke",
            (name.to_string(), params.to_string(), wit_ctx),
        )?;
        match result {
            Ok(tr) => Ok(ToolResult::from(tr)),
            Err(pe) => Err(BindingError::CallError(format!(
                "plugin error [{}]: {}",
                pe.code, pe.message
            ))),
        }
    }
}

/// Adapter that implements WebhookPluginInstance for WASM plugins
struct WebhookAdapter<B: CredentialBackend + Send + Sync + 'static> {
    plugin_id: String,
    handle: Arc<PluginInstanceHandle<B>>,
}

impl<B: CredentialBackend + Send + Sync + 'static> WebhookAdapter<B> {
    fn new(plugin_id: String, handle: Arc<PluginInstanceHandle<B>>) -> Self {
        Self { plugin_id, handle }
    }
}

// SAFETY: WebhookAdapter only holds an Arc<PluginInstanceHandle<B>> whose interior
// wasmtime Store is guarded by an RwLock.  All access goes through the lock,
// so sharing across threads is safe.
unsafe impl<B: CredentialBackend + Send + Sync + 'static> Send for WebhookAdapter<B> {}
unsafe impl<B: CredentialBackend + Send + Sync + 'static> Sync for WebhookAdapter<B> {}

impl<B: CredentialBackend + Send + Sync + 'static> WebhookPluginInstance for WebhookAdapter<B> {
    fn get_paths(&self) -> Result<Vec<String>, BindingError> {
        tracing::debug!(plugin_id = %self.plugin_id, "Calling WASM export webhook.get-paths");
        let (paths,): (Vec<String>,) = self.handle.call_export_no_args("webhook", "get-paths")?;
        Ok(paths)
    }

    fn handle(&self, req: WebhookRequest) -> Result<WebhookResponse, BindingError> {
        tracing::debug!(
            plugin_id = %self.plugin_id,
            method = %req.method,
            path = %req.path,
            "Calling WASM export webhook.handle"
        );
        let wit_req = WitWebhookRequest::from(&req);
        // The WIT export returns `result<webhook-response, plugin-error>`
        let (result,): (Result<WitWebhookResponse, WitPluginError>,) = self
            .handle
            .call_export_one_arg("webhook", "handle", (wit_req,))?;
        match result {
            Ok(wr) => Ok(WebhookResponse::from(wr)),
            Err(pe) => Err(BindingError::CallError(format!(
                "plugin error [{}]: {}",
                pe.code, pe.message
            ))),
        }
    }
}

/// Adapter that implements ServicePluginInstance for WASM plugins
struct ServiceAdapter<B: CredentialBackend + Send + Sync + 'static> {
    plugin_id: String,
    handle: Arc<PluginInstanceHandle<B>>,
}

impl<B: CredentialBackend + Send + Sync + 'static> ServiceAdapter<B> {
    fn new(plugin_id: String, handle: Arc<PluginInstanceHandle<B>>) -> Self {
        Self { plugin_id, handle }
    }
}

// SAFETY: ServiceAdapter only holds an Arc<PluginInstanceHandle<B>> whose interior
// wasmtime Store is guarded by an RwLock.  All access goes through the lock,
// so sharing across threads is safe.
unsafe impl<B: CredentialBackend + Send + Sync + 'static> Send for ServiceAdapter<B> {}
unsafe impl<B: CredentialBackend + Send + Sync + 'static> Sync for ServiceAdapter<B> {}

impl<B: CredentialBackend + Send + Sync + 'static> ServicePluginInstance for ServiceAdapter<B> {
    fn start(&self) -> Result<(), BindingError> {
        tracing::debug!(plugin_id = %self.plugin_id, "Calling WASM export service.start");
        // The WIT export returns `result<_, plugin-error>`
        let (result,): (Result<(), WitPluginError>,) =
            self.handle.call_export_no_args("service", "start")?;
        result.map_err(|pe| {
            BindingError::CallError(format!("plugin error [{}]: {}", pe.code, pe.message))
        })
    }

    fn stop(&self) -> Result<(), BindingError> {
        tracing::debug!(plugin_id = %self.plugin_id, "Calling WASM export service.stop");
        let (result,): (Result<(), WitPluginError>,) =
            self.handle.call_export_no_args("service", "stop")?;
        result.map_err(|pe| {
            BindingError::CallError(format!("plugin error [{}]: {}", pe.code, pe.message))
        })
    }

    fn health(&self) -> Result<bool, BindingError> {
        tracing::debug!(plugin_id = %self.plugin_id, "Calling WASM export service.health");
        let (healthy,): (bool,) = self.handle.call_export_no_args("service", "health")?;
        Ok(healthy)
    }
}

/// Adapter that implements HookPluginInstance for WASM plugins
struct HookAdapter<B: CredentialBackend + Send + Sync + 'static> {
    plugin_id: String,
    handle: Arc<PluginInstanceHandle<B>>,
}

impl<B: CredentialBackend + Send + Sync + 'static> HookAdapter<B> {
    fn new(plugin_id: String, handle: Arc<PluginInstanceHandle<B>>) -> Self {
        Self { plugin_id, handle }
    }
}

// SAFETY: HookAdapter only holds an Arc<PluginInstanceHandle<B>> whose interior
// wasmtime Store is guarded by an RwLock.  All access goes through the lock,
// so sharing across threads is safe.
unsafe impl<B: CredentialBackend + Send + Sync + 'static> Send for HookAdapter<B> {}
unsafe impl<B: CredentialBackend + Send + Sync + 'static> Sync for HookAdapter<B> {}

impl<B: CredentialBackend + Send + Sync + 'static> HookPluginInstance for HookAdapter<B> {
    fn get_hooks(&self) -> Result<Vec<String>, BindingError> {
        tracing::debug!(plugin_id = %self.plugin_id, "Calling WASM export hooks.get-hooks");
        let (hooks,): (Vec<String>,) = self.handle.call_export_no_args("hooks", "get-hooks")?;
        Ok(hooks)
    }

    fn handle(&self, event: HookEvent) -> Result<HookResult, BindingError> {
        tracing::debug!(
            plugin_id = %self.plugin_id,
            hook = %event.hook_name,
            "Calling WASM export hooks.handle"
        );
        let wit_event = WitHookEvent::from(&event);
        // The WIT export returns `result<hook-result, plugin-error>`
        let (result,): (Result<WitHookResult, WitPluginError>,) =
            self.handle
                .call_export_one_arg("hooks", "handle", (wit_event,))?;
        match result {
            Ok(hr) => Ok(HookResult::from(hr)),
            Err(pe) => Err(BindingError::CallError(format!(
                "plugin error [{}]: {}",
                pe.code, pe.message
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credentials::MockCredentialBackend;
    use tempfile::tempdir;

    async fn create_test_runtime() -> PluginRuntime<MockCredentialBackend> {
        let temp_dir = tempdir().unwrap();
        let plugins_dir = temp_dir.path().join("plugins");
        std::fs::create_dir_all(&plugins_dir).unwrap();

        let loader = Arc::new(PluginLoader::new(plugins_dir).unwrap());
        let backend = MockCredentialBackend::new(true);
        let credential_store = Arc::new(
            CredentialStore::new(backend, temp_dir.path().to_path_buf())
                .await
                .unwrap(),
        );

        PluginRuntime::new(loader, credential_store).unwrap()
    }

    #[tokio::test]
    async fn test_runtime_creation() {
        let runtime = create_test_runtime().await;
        assert!(runtime.list_plugins().is_empty());
    }

    #[tokio::test]
    async fn test_registry_access() {
        let runtime = create_test_runtime().await;
        let registry = runtime.registry();
        assert_eq!(registry.count(), 0);
    }

    #[tokio::test]
    async fn test_load_all_empty() {
        let runtime = create_test_runtime().await;
        let loaded = runtime.load_all().await.unwrap();
        assert!(loaded.is_empty());
    }

    #[test]
    fn test_channel_adapter_info() {
        // Test that channel adapter returns expected info
        let info = ChannelInfo {
            id: "test".to_string(),
            label: "Test".to_string(),
            selection_label: "Test".to_string(),
            docs_path: "/channels/test".to_string(),
            blurb: "Test channel".to_string(),
            order: 100,
        };
        assert_eq!(info.id, "test");
    }

    #[test]
    fn test_tool_definition() {
        let def = ToolDefinition {
            name: "test_tool".to_string(),
            description: "A test tool".to_string(),
            input_schema: r#"{"type": "object"}"#.to_string(),
        };
        assert_eq!(def.name, "test_tool");
    }

    #[test]
    fn test_hook_event() {
        let event = HookEvent {
            hook_name: "before_agent_start".to_string(),
            payload: r#"{"prompt": "test"}"#.to_string(),
        };
        assert_eq!(event.hook_name, "before_agent_start");
    }

    #[test]
    fn test_hook_result() {
        let result = HookResult {
            handled: true,
            cancel: false,
            modified_payload: Some(r#"{"modified": true}"#.to_string()),
        };
        assert!(result.handled);
        assert!(result.modified_payload.is_some());
    }

    // ============== WIT Type Conversion Tests ==============

    #[test]
    fn test_wit_channel_info_conversion() {
        let wit = WitChannelInfo {
            id: "msteams".to_string(),
            label: "Microsoft Teams".to_string(),
            selection_label: "Teams".to_string(),
            docs_path: "/channels/msteams".to_string(),
            blurb: "Microsoft Teams channel".to_string(),
            order: 10,
        };
        let info = ChannelInfo::from(wit);
        assert_eq!(info.id, "msteams");
        assert_eq!(info.label, "Microsoft Teams");
        assert_eq!(info.selection_label, "Teams");
        assert_eq!(info.docs_path, "/channels/msteams");
        assert_eq!(info.blurb, "Microsoft Teams channel");
        assert_eq!(info.order, 10);
    }

    #[test]
    fn test_wit_chat_type_conversion() {
        assert!(matches!(ChatType::from(WitChatType::Dm), ChatType::Dm));
        assert!(matches!(
            ChatType::from(WitChatType::Group),
            ChatType::Group
        ));
        assert!(matches!(
            ChatType::from(WitChatType::Channel),
            ChatType::Channel
        ));
        assert!(matches!(
            ChatType::from(WitChatType::Thread),
            ChatType::Thread
        ));
    }

    #[test]
    fn test_wit_channel_capabilities_conversion() {
        let wit = WitChannelCapabilities {
            chat_types: vec![WitChatType::Dm, WitChatType::Group],
            polls: true,
            reactions: true,
            edit: false,
            unsend: false,
            reply: true,
            effects: false,
            group_management: true,
            threads: true,
            media: true,
            native_commands: false,
            block_streaming: true,
        };
        let caps = ChannelCapabilities::from(wit);
        assert_eq!(caps.chat_types.len(), 2);
        assert_eq!(caps.chat_types[0], ChatType::Dm);
        assert_eq!(caps.chat_types[1], ChatType::Group);
        assert!(caps.polls);
        assert!(caps.reactions);
        assert!(!caps.edit);
        assert!(!caps.unsend);
        assert!(caps.reply);
        assert!(!caps.effects);
        assert!(caps.group_management);
        assert!(caps.threads);
        assert!(caps.media);
        assert!(!caps.native_commands);
        assert!(caps.block_streaming);
    }

    #[test]
    fn test_wit_outbound_context_conversion() {
        let ctx = OutboundContext {
            to: "user@example.com".to_string(),
            text: "Hello, world!".to_string(),
            media_url: Some("https://example.com/image.png".to_string()),
            gif_playback: true,
            reply_to_id: Some("msg-123".to_string()),
            thread_id: None,
            account_id: Some("acc-456".to_string()),
        };
        let wit = WitOutboundContext::from(&ctx);
        assert_eq!(wit.to, "user@example.com");
        assert_eq!(wit.text, "Hello, world!");
        assert_eq!(
            wit.media_url,
            Some("https://example.com/image.png".to_string())
        );
        assert!(wit.gif_playback);
        assert_eq!(wit.reply_to_id, Some("msg-123".to_string()));
        assert!(wit.thread_id.is_none());
        assert_eq!(wit.account_id, Some("acc-456".to_string()));
    }

    #[test]
    fn test_wit_delivery_result_conversion() {
        let wit = WitDeliveryResult {
            ok: true,
            message_id: Some("msg-789".to_string()),
            error: None,
            retryable: false,
        };
        let result = DeliveryResult::from(wit);
        assert!(result.ok);
        assert_eq!(result.message_id, Some("msg-789".to_string()));
        assert!(result.error.is_none());
        assert!(!result.retryable);
        // Host-side extensions default to None
        assert!(result.conversation_id.is_none());
        assert!(result.to_jid.is_none());
        assert!(result.poll_id.is_none());
    }

    #[test]
    fn test_wit_delivery_result_conversion_error() {
        let wit = WitDeliveryResult {
            ok: false,
            message_id: None,
            error: Some("Rate limited".to_string()),
            retryable: true,
        };
        let result = DeliveryResult::from(wit);
        assert!(!result.ok);
        assert!(result.message_id.is_none());
        assert_eq!(result.error, Some("Rate limited".to_string()));
        assert!(result.retryable);
    }

    #[test]
    fn test_wit_tool_definition_conversion() {
        let wit = WitToolDefinition {
            name: "web_search".to_string(),
            description: "Search the web".to_string(),
            input_schema: r#"{"type": "object", "properties": {"query": {"type": "string"}}}"#
                .to_string(),
        };
        let def = ToolDefinition::from(wit);
        assert_eq!(def.name, "web_search");
        assert_eq!(def.description, "Search the web");
        assert!(def.input_schema.contains("query"));
    }

    #[test]
    fn test_wit_tool_context_conversion() {
        let ctx = ToolContext {
            agent_id: Some("agent-1".to_string()),
            session_key: Some("session-abc".to_string()),
            message_channel: Some("slack".to_string()),
            sandboxed: true,
        };
        let wit = WitToolContext::from(&ctx);
        assert_eq!(wit.agent_id, Some("agent-1".to_string()));
        assert_eq!(wit.session_key, Some("session-abc".to_string()));
        assert_eq!(wit.message_channel, Some("slack".to_string()));
        assert!(wit.sandboxed);
    }

    #[test]
    fn test_wit_tool_result_conversion() {
        let wit = WitToolResult {
            success: true,
            result: Some("42".to_string()),
            error: None,
        };
        let result = ToolResult::from(wit);
        assert!(result.success);
        assert_eq!(result.result, Some("42".to_string()));
        assert!(result.error.is_none());
    }

    #[test]
    fn test_wit_webhook_request_conversion() {
        let req = WebhookRequest {
            method: "POST".to_string(),
            path: "/webhook/events".to_string(),
            headers: vec![("Content-Type".to_string(), "application/json".to_string())],
            body: Some(br#"{"event": "test"}"#.to_vec()),
            query: Some("token=abc".to_string()),
        };
        let wit = WitWebhookRequest::from(&req);
        assert_eq!(wit.method, "POST");
        assert_eq!(wit.path, "/webhook/events");
        assert_eq!(wit.headers.len(), 1);
        assert!(wit.body.is_some());
        assert_eq!(wit.query, Some("token=abc".to_string()));
    }

    #[test]
    fn test_wit_webhook_response_conversion() {
        let wit = WitWebhookResponse {
            status: 200,
            headers: vec![("Content-Type".to_string(), "text/plain".to_string())],
            body: Some(b"OK".to_vec()),
        };
        let resp = WebhookResponse::from(wit);
        assert_eq!(resp.status, 200);
        assert_eq!(resp.headers.len(), 1);
        assert_eq!(resp.body, Some(b"OK".to_vec()));
    }

    #[test]
    fn test_wit_hook_event_conversion() {
        let event = HookEvent {
            hook_name: "message_sending".to_string(),
            payload: r#"{"to": "user", "content": "hi"}"#.to_string(),
        };
        let wit = WitHookEvent::from(&event);
        assert_eq!(wit.hook_name, "message_sending");
        assert!(wit.payload.contains("content"));
    }

    #[test]
    fn test_wit_hook_result_conversion() {
        let wit = WitHookResult {
            handled: true,
            cancel: false,
            modified_payload: Some(r#"{"content": "modified"}"#.to_string()),
        };
        let result = HookResult::from(wit);
        assert!(result.handled);
        assert!(!result.cancel);
        assert_eq!(
            result.modified_payload,
            Some(r#"{"content": "modified"}"#.to_string())
        );
    }

    #[test]
    fn test_wit_hook_result_conversion_cancel() {
        let wit = WitHookResult {
            handled: true,
            cancel: true,
            modified_payload: None,
        };
        let result = HookResult::from(wit);
        assert!(result.handled);
        assert!(result.cancel);
        assert!(result.modified_payload.is_none());
    }

    #[test]
    fn test_wit_plugin_error_fields() {
        let pe = WitPluginError {
            code: "RATE_LIMITED".to_string(),
            message: "Too many requests".to_string(),
            retryable: true,
        };
        assert_eq!(pe.code, "RATE_LIMITED");
        assert_eq!(pe.message, "Too many requests");
        assert!(pe.retryable);
    }

    // ============== Fuel Budget Tests ==============

    #[test]
    fn test_default_fuel_budget_is_reasonable() {
        // 1 billion instructions — enough for real work, bounded enough to catch infinite loops
        assert_eq!(DEFAULT_FUEL_BUDGET, 1_000_000_000);
        // Compile-time checks that the budget is in a sane range
        const _: () = assert!(DEFAULT_FUEL_BUDGET > 1_000_000); // not too small
        const _: () = assert!(DEFAULT_FUEL_BUDGET <= 10_000_000_000); // not unbounded
    }

    #[test]
    fn test_compute_epoch_deadline_ticks() {
        let ticks = compute_epoch_deadline_ticks(DEFAULT_EXECUTION_TIMEOUT);
        let interval_ms = DEFAULT_EPOCH_TICK_INTERVAL.as_millis().max(1);
        let timeout_ms = DEFAULT_EXECUTION_TIMEOUT.as_millis().max(1);
        let expected = timeout_ms.div_ceil(interval_ms);
        assert_eq!(ticks, expected as u64);
    }

    #[test]
    fn test_plugin_resource_limiter_bounds() {
        let mut limiter = PluginResourceLimiter {
            max_memory_bytes: 1024,
            max_table_elements: 10,
        };
        assert!(limiter.memory_growing(0, 1024, None).unwrap());
        assert!(!limiter.memory_growing(0, 1025, None).unwrap());
        assert!(limiter.table_growing(0, 10, None).unwrap());
        assert!(!limiter.table_growing(0, 11, None).unwrap());
    }

    #[tokio::test]
    async fn test_engine_has_fuel_enabled() {
        let runtime = create_test_runtime().await;
        // Verify the engine was created with fuel consumption enabled
        // by checking that we can create a store and set fuel on it
        let store = Store::new(
            &runtime.engine,
            HostState {
                plugin_id: "test".to_string(),
                host_ctx: Arc::new(PluginHostContext::new(
                    "test".to_string(),
                    runtime.credential_store.clone(),
                    runtime.rate_limiters.clone(),
                )),
                limiter: PluginResourceLimiter {
                    max_memory_bytes: MAX_PLUGIN_MEMORY_BYTES as usize,
                    max_table_elements: MAX_PLUGIN_TABLE_ELEMENTS,
                },
            },
        );
        // If fuel is not enabled on the engine, set_fuel would return an error
        let mut store = store;
        assert!(
            store.set_fuel(100).is_ok(),
            "Engine should have fuel consumption enabled"
        );
    }

    #[tokio::test]
    async fn test_zero_fuel_store() {
        let runtime = create_test_runtime().await;
        let mut store = Store::new(
            &runtime.engine,
            HostState {
                plugin_id: "test".to_string(),
                host_ctx: Arc::new(PluginHostContext::new(
                    "test".to_string(),
                    runtime.credential_store.clone(),
                    runtime.rate_limiters.clone(),
                )),
                limiter: PluginResourceLimiter {
                    max_memory_bytes: MAX_PLUGIN_MEMORY_BYTES as usize,
                    max_table_elements: MAX_PLUGIN_TABLE_ELEMENTS,
                },
            },
        );
        // Setting zero fuel should succeed (but any execution would trap immediately)
        assert!(store.set_fuel(0).is_ok());
        assert_eq!(store.get_fuel().unwrap(), 0);
    }

    #[test]
    fn test_fuel_exhausted_error_variant() {
        let err = RuntimeError::FuelExhausted {
            budget: DEFAULT_FUEL_BUDGET,
        };
        let msg = err.to_string();
        assert!(msg.contains("fuel exhausted"), "got: {msg}");
        assert!(msg.contains(&DEFAULT_FUEL_BUDGET.to_string()), "got: {msg}");
    }
}
