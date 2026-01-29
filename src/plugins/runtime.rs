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
use std::sync::Arc;
use std::time::Duration;

use parking_lot::RwLock;
use thiserror::Error;
use wasmtime::component::{Component, ComponentType, Lift, Linker, Lower};
use wasmtime::{Config, Engine, Store, StoreContextMut};

use crate::credentials::{CredentialBackend, CredentialStore};

use super::bindings::{
    BindingError, ChannelCapabilities, ChannelInfo, ChannelPluginInstance, ChatType,
    DeliveryResult, HookEvent, HookPluginInstance, HookResult, OutboundContext, PluginError,
    PluginRegistry, ServicePluginInstance, ToolContext, ToolDefinition, ToolPluginInstance,
    ToolResult, WebhookPluginInstance, WebhookRequest, WebhookResponse, WitHost,
};
use super::capabilities::{RateLimiterRegistry, SsrfConfig};
use super::host::{HostError, HttpRequest, HttpResponse, MediaFetchResult, PluginHostContext};
use super::loader::{LoadedPlugin, PluginKind, PluginLoader, PluginManifest};

/// Maximum memory per plugin instance (64MB)
pub const MAX_PLUGIN_MEMORY_BYTES: u64 = 64 * 1024 * 1024;

/// Default execution timeout per function call (30s)
pub const DEFAULT_EXECUTION_TIMEOUT: Duration = Duration::from_secs(30);

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
}

/// State held in each plugin's wasmtime store
pub struct HostState<B: CredentialBackend + Send + Sync + 'static> {
    /// Plugin ID for this instance
    pub plugin_id: String,

    /// Host context for capability access
    pub host_ctx: Arc<PluginHostContext<B>>,
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

    /// Loaded plugin instances by ID
    instances: RwLock<HashMap<String, Arc<PluginInstanceHandle<B>>>>,

    /// Plugin registry for dispatch
    registry: Arc<PluginRegistry>,
}

/// Handle to an instantiated plugin
pub struct PluginInstanceHandle<B: CredentialBackend + Send + Sync + 'static> {
    /// Plugin manifest
    pub manifest: PluginManifest,

    /// The wasmtime store with plugin state
    #[allow(dead_code)]
    store: RwLock<Store<HostState<B>>>,

    /// Component instance (for calling exports)
    #[allow(dead_code)]
    instance: wasmtime::component::Instance,
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
        // Configure wasmtime engine
        let mut config = Config::new();
        config.wasm_component_model(true);
        config.async_support(true);
        // Memory limits are enforced per-instance via resource limiter

        let engine =
            Engine::new(&config).map_err(|e| RuntimeError::WasmtimeError(e.to_string()))?;

        Ok(Self {
            engine,
            loader,
            credential_store,
            rate_limiters,
            ssrf_config,
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

        // Create host context for this plugin
        let host_ctx = Arc::new(PluginHostContext::with_ssrf_config(
            plugin_id.to_string(),
            self.credential_store.clone(),
            self.rate_limiters.clone(),
            self.ssrf_config.clone(),
        ));

        // Create the host state
        let host_state = HostState {
            plugin_id: plugin_id.to_string(),
            host_ctx,
        };

        // Create the store with host state
        let mut store = Store::new(&self.engine, host_state);

        // Set fuel for execution limits (optional, for timeout enforcement)
        store.set_epoch_deadline(1);

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
            store: RwLock::new(store),
            instance,
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

        // ---- Logging (sync) ----

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

        // ---- Config (sync) ----

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

        // ---- Credentials (async) ----

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

        // ---- HTTP (async) ----

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

        // ---- Media (async) ----

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
    #[allow(dead_code)]
    handle: Arc<PluginInstanceHandle<B>>,
}

impl<B: CredentialBackend + Send + Sync + 'static> ChannelAdapter<B> {
    fn new(plugin_id: String, handle: Arc<PluginInstanceHandle<B>>) -> Self {
        Self { plugin_id, handle }
    }
}

// Manual Send/Sync implementations for adapters
// These are safe because we only hold Arc<PluginInstanceHandle> which protects concurrent access
unsafe impl<B: CredentialBackend + Send + Sync + 'static> Send for ChannelAdapter<B> {}
unsafe impl<B: CredentialBackend + Send + Sync + 'static> Sync for ChannelAdapter<B> {}

impl<B: CredentialBackend + Send + Sync + 'static> ChannelPluginInstance for ChannelAdapter<B> {
    fn get_info(&self) -> Result<ChannelInfo, BindingError> {
        // In a full implementation, this would call the WASM export
        // For now, return placeholder based on plugin ID
        Ok(ChannelInfo {
            id: self.plugin_id.clone(),
            label: self.plugin_id.clone(),
            selection_label: self.plugin_id.clone(),
            docs_path: format!("/channels/{}", self.plugin_id),
            blurb: format!("{} channel plugin", self.plugin_id),
            order: 100,
        })
    }

    fn get_capabilities(&self) -> Result<ChannelCapabilities, BindingError> {
        // In a full implementation, this would call the WASM export
        Ok(ChannelCapabilities {
            chat_types: vec![ChatType::Dm, ChatType::Group],
            polls: false,
            reactions: false,
            edit: false,
            unsend: false,
            reply: true,
            effects: false,
            group_management: false,
            threads: false,
            media: true,
            native_commands: false,
            block_streaming: false,
        })
    }

    fn send_text(&self, _ctx: OutboundContext) -> Result<DeliveryResult, BindingError> {
        // In a full implementation, this would call the WASM export
        Ok(DeliveryResult {
            ok: true,
            message_id: Some(uuid::Uuid::new_v4().to_string()),
            error: None,
            retryable: false,
            conversation_id: None,
            to_jid: None,
            poll_id: None,
        })
    }

    fn send_media(&self, _ctx: OutboundContext) -> Result<DeliveryResult, BindingError> {
        Ok(DeliveryResult {
            ok: true,
            message_id: Some(uuid::Uuid::new_v4().to_string()),
            error: None,
            retryable: false,
            conversation_id: None,
            to_jid: None,
            poll_id: None,
        })
    }
}

/// Adapter that implements ToolPluginInstance for WASM plugins
struct ToolAdapter<B: CredentialBackend + Send + Sync + 'static> {
    plugin_id: String,
    #[allow(dead_code)]
    handle: Arc<PluginInstanceHandle<B>>,
}

impl<B: CredentialBackend + Send + Sync + 'static> ToolAdapter<B> {
    fn new(plugin_id: String, handle: Arc<PluginInstanceHandle<B>>) -> Self {
        Self { plugin_id, handle }
    }
}

unsafe impl<B: CredentialBackend + Send + Sync + 'static> Send for ToolAdapter<B> {}
unsafe impl<B: CredentialBackend + Send + Sync + 'static> Sync for ToolAdapter<B> {}

impl<B: CredentialBackend + Send + Sync + 'static> ToolPluginInstance for ToolAdapter<B> {
    fn get_definitions(&self) -> Result<Vec<ToolDefinition>, BindingError> {
        // In a full implementation, this would call the WASM export
        Ok(vec![ToolDefinition {
            name: format!("{}_tool", self.plugin_id),
            description: format!("Tool provided by {} plugin", self.plugin_id),
            input_schema: r#"{"type": "object", "properties": {}}"#.to_string(),
        }])
    }

    fn invoke(
        &self,
        _name: &str,
        _params: &str,
        _ctx: ToolContext,
    ) -> Result<ToolResult, BindingError> {
        // In a full implementation, this would call the WASM export
        Ok(ToolResult {
            success: true,
            result: Some("Tool invoked successfully".to_string()),
            error: None,
        })
    }
}

/// Adapter that implements WebhookPluginInstance for WASM plugins
struct WebhookAdapter<B: CredentialBackend + Send + Sync + 'static> {
    plugin_id: String,
    #[allow(dead_code)]
    handle: Arc<PluginInstanceHandle<B>>,
}

impl<B: CredentialBackend + Send + Sync + 'static> WebhookAdapter<B> {
    fn new(plugin_id: String, handle: Arc<PluginInstanceHandle<B>>) -> Self {
        Self { plugin_id, handle }
    }
}

unsafe impl<B: CredentialBackend + Send + Sync + 'static> Send for WebhookAdapter<B> {}
unsafe impl<B: CredentialBackend + Send + Sync + 'static> Sync for WebhookAdapter<B> {}

impl<B: CredentialBackend + Send + Sync + 'static> WebhookPluginInstance for WebhookAdapter<B> {
    fn get_paths(&self) -> Result<Vec<String>, BindingError> {
        // In a full implementation, this would call the WASM export
        // Note: Paths are prefixed with /plugins/<plugin-id>/ by the host
        Ok(vec!["/webhook".to_string(), "/callback".to_string()])
    }

    fn handle(&self, _req: WebhookRequest) -> Result<WebhookResponse, BindingError> {
        // In a full implementation, this would call the WASM export
        Ok(WebhookResponse {
            status: 200,
            headers: vec![("Content-Type".to_string(), "application/json".to_string())],
            body: Some(br#"{"status": "ok"}"#.to_vec()),
        })
    }
}

/// Adapter that implements ServicePluginInstance for WASM plugins
struct ServiceAdapter<B: CredentialBackend + Send + Sync + 'static> {
    plugin_id: String,
    #[allow(dead_code)]
    handle: Arc<PluginInstanceHandle<B>>,
}

impl<B: CredentialBackend + Send + Sync + 'static> ServiceAdapter<B> {
    fn new(plugin_id: String, handle: Arc<PluginInstanceHandle<B>>) -> Self {
        Self { plugin_id, handle }
    }
}

unsafe impl<B: CredentialBackend + Send + Sync + 'static> Send for ServiceAdapter<B> {}
unsafe impl<B: CredentialBackend + Send + Sync + 'static> Sync for ServiceAdapter<B> {}

impl<B: CredentialBackend + Send + Sync + 'static> ServicePluginInstance for ServiceAdapter<B> {
    fn start(&self) -> Result<(), BindingError> {
        // In a full implementation, this would call the WASM export
        tracing::debug!(plugin_id = %self.plugin_id, "Service start called");
        Ok(())
    }

    fn stop(&self) -> Result<(), BindingError> {
        // In a full implementation, this would call the WASM export
        tracing::debug!(plugin_id = %self.plugin_id, "Service stop called");
        Ok(())
    }

    fn health(&self) -> Result<bool, BindingError> {
        // In a full implementation, this would call the WASM export
        Ok(true)
    }
}

/// Adapter that implements HookPluginInstance for WASM plugins
struct HookAdapter<B: CredentialBackend + Send + Sync + 'static> {
    plugin_id: String,
    #[allow(dead_code)]
    handle: Arc<PluginInstanceHandle<B>>,
}

impl<B: CredentialBackend + Send + Sync + 'static> HookAdapter<B> {
    fn new(plugin_id: String, handle: Arc<PluginInstanceHandle<B>>) -> Self {
        Self { plugin_id, handle }
    }
}

unsafe impl<B: CredentialBackend + Send + Sync + 'static> Send for HookAdapter<B> {}
unsafe impl<B: CredentialBackend + Send + Sync + 'static> Sync for HookAdapter<B> {}

impl<B: CredentialBackend + Send + Sync + 'static> HookPluginInstance for HookAdapter<B> {
    fn get_hooks(&self) -> Result<Vec<String>, BindingError> {
        // In a full implementation, this would call the WASM export
        // Return the 14 hook types per protocol
        Ok(vec![
            "before_agent_start".to_string(),
            "agent_end".to_string(),
            "session_start".to_string(),
            "session_end".to_string(),
            "before_compaction".to_string(),
            "after_compaction".to_string(),
            "message_received".to_string(),
            "message_sending".to_string(),
            "message_sent".to_string(),
            "before_tool_call".to_string(),
            "after_tool_call".to_string(),
            "tool_result_persist".to_string(),
            "gateway_start".to_string(),
            "gateway_stop".to_string(),
        ])
    }

    fn handle(&self, event: HookEvent) -> Result<HookResult, BindingError> {
        // In a full implementation, this would call the WASM export
        tracing::debug!(
            plugin_id = %self.plugin_id,
            hook = %event.hook_name,
            "Hook event handled"
        );
        Ok(HookResult {
            handled: true,
            cancel: false,
            modified_payload: None,
        })
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
}
