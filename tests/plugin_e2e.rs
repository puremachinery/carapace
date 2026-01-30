//! Plugin System End-to-End Tests
//!
//! These tests verify the full plugin dispatch pipeline works correctly,
//! from registration through dispatch to result handling.
//!
//! Unit tests exist in:
//! - `src/plugins/bindings.rs` (types and registry)
//! - `src/plugins/dispatch.rs` (dispatchers)
//! - `src/plugins/loader.rs` (plugin loading)
//! - `src/plugins/runtime.rs` (wasmtime runtime)
//! - `src/plugins/tests.rs` (integration tests)
//!
//! This file adds:
//! - Full dispatch pipeline tests
//! - Multi-plugin interaction tests
//! - Error propagation tests
//! - Capability enforcement tests

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

use carapace::plugins::{
    is_modifiable_hook, BindingError, ChannelCapabilities, ChannelInfo, ChannelPluginInstance,
    ChatType, DeliveryResult, HookDispatcher, HookEvent, HookPluginInstance, HookResult,
    OutboundContext, PluginKind, PluginManifest, PluginRegistry, ServicePluginInstance,
    ToolContext, ToolDefinition, ToolDispatcher, ToolPluginInstance, ToolResult, WebhookDispatcher,
    WebhookPluginInstance, WebhookRequest, WebhookResponse, MODIFIABLE_HOOKS,
};

// ============== Mock Implementations ==============

/// Mock channel plugin with configurable behavior
struct MockChannel {
    id: String,
    fail_sends: AtomicBool,
    send_count: AtomicUsize,
}

impl MockChannel {
    fn new(id: &str) -> Self {
        Self {
            id: id.to_string(),
            fail_sends: AtomicBool::new(false),
            send_count: AtomicUsize::new(0),
        }
    }

    fn set_fail_sends(&self, fail: bool) {
        self.fail_sends.store(fail, Ordering::SeqCst);
    }

    fn send_count(&self) -> usize {
        self.send_count.load(Ordering::SeqCst)
    }
}

impl ChannelPluginInstance for MockChannel {
    fn get_info(&self) -> Result<ChannelInfo, BindingError> {
        Ok(ChannelInfo {
            id: self.id.clone(),
            label: format!("{} Channel", self.id),
            selection_label: self.id.clone(),
            docs_path: format!("/channels/{}", self.id),
            blurb: format!("Mock {} channel", self.id),
            order: 100,
        })
    }

    fn get_capabilities(&self) -> Result<ChannelCapabilities, BindingError> {
        Ok(ChannelCapabilities {
            chat_types: vec![ChatType::Dm, ChatType::Group],
            polls: false,
            reactions: true,
            edit: true,
            unsend: false,
            reply: true,
            effects: false,
            group_management: false,
            threads: true,
            media: true,
            native_commands: false,
            block_streaming: false,
        })
    }

    fn send_text(&self, ctx: OutboundContext) -> Result<DeliveryResult, BindingError> {
        self.send_count.fetch_add(1, Ordering::SeqCst);

        if self.fail_sends.load(Ordering::SeqCst) {
            Ok(DeliveryResult {
                ok: false,
                message_id: None,
                error: Some("Simulated failure".to_string()),
                retryable: true,
                conversation_id: None,
                to_jid: None,
                poll_id: None,
            })
        } else {
            Ok(DeliveryResult {
                ok: true,
                message_id: Some(format!("msg-{}-{}", self.id, ctx.to)),
                error: None,
                retryable: false,
                conversation_id: None,
                to_jid: None,
                poll_id: None,
            })
        }
    }

    fn send_media(&self, ctx: OutboundContext) -> Result<DeliveryResult, BindingError> {
        self.send_count.fetch_add(1, Ordering::SeqCst);
        Ok(DeliveryResult {
            ok: true,
            message_id: Some(format!("media-{}-{}", self.id, ctx.to)),
            error: None,
            retryable: false,
            conversation_id: None,
            to_jid: None,
            poll_id: None,
        })
    }
}

/// Mock tool plugin with multiple tools
struct MockToolPlugin {
    id: String,
    tools: Vec<ToolDefinition>,
    invocation_count: AtomicUsize,
}

impl MockToolPlugin {
    fn new(id: &str, tools: Vec<ToolDefinition>) -> Self {
        Self {
            id: id.to_string(),
            tools,
            invocation_count: AtomicUsize::new(0),
        }
    }

    fn invocation_count(&self) -> usize {
        self.invocation_count.load(Ordering::SeqCst)
    }
}

impl ToolPluginInstance for MockToolPlugin {
    fn get_definitions(&self) -> Result<Vec<ToolDefinition>, BindingError> {
        Ok(self.tools.clone())
    }

    fn invoke(
        &self,
        name: &str,
        params: &str,
        ctx: ToolContext,
    ) -> Result<ToolResult, BindingError> {
        self.invocation_count.fetch_add(1, Ordering::SeqCst);

        if !self.tools.iter().any(|t| t.name == name) {
            return Ok(ToolResult {
                success: false,
                result: None,
                error: Some(format!("Tool '{}' not found in plugin '{}'", name, self.id)),
            });
        }

        // Simulate tool execution
        Ok(ToolResult {
            success: true,
            result: Some(format!(
                r#"{{"tool":"{}","plugin":"{}","params":{},"agent_id":{}}}"#,
                name,
                self.id,
                params,
                ctx.agent_id
                    .as_ref()
                    .map(|s| format!("\"{}\"", s))
                    .unwrap_or_else(|| "null".to_string())
            )),
            error: None,
        })
    }
}

/// Mock webhook plugin
struct MockWebhookPlugin {
    id: String,
    paths: Vec<String>,
    request_count: AtomicUsize,
}

impl MockWebhookPlugin {
    fn new(id: &str, paths: Vec<String>) -> Self {
        Self {
            id: id.to_string(),
            paths,
            request_count: AtomicUsize::new(0),
        }
    }

    fn request_count(&self) -> usize {
        self.request_count.load(Ordering::SeqCst)
    }
}

impl WebhookPluginInstance for MockWebhookPlugin {
    fn get_paths(&self) -> Result<Vec<String>, BindingError> {
        Ok(self.paths.clone())
    }

    fn handle(&self, req: WebhookRequest) -> Result<WebhookResponse, BindingError> {
        self.request_count.fetch_add(1, Ordering::SeqCst);

        let body = format!(
            r#"{{"plugin":"{}","path":"{}","method":"{}"}}"#,
            self.id, req.path, req.method
        );

        Ok(WebhookResponse {
            status: 200,
            headers: vec![("Content-Type".to_string(), "application/json".to_string())],
            body: Some(body.into_bytes()),
        })
    }
}

/// Mock service plugin
struct MockServicePlugin {
    #[allow(dead_code)]
    id: String,
    running: AtomicBool,
    start_count: AtomicUsize,
    stop_count: AtomicUsize,
}

impl MockServicePlugin {
    fn new(id: &str) -> Self {
        Self {
            id: id.to_string(),
            running: AtomicBool::new(false),
            start_count: AtomicUsize::new(0),
            stop_count: AtomicUsize::new(0),
        }
    }

    #[allow(dead_code)]
    fn start_count(&self) -> usize {
        self.start_count.load(Ordering::SeqCst)
    }

    #[allow(dead_code)]
    fn stop_count(&self) -> usize {
        self.stop_count.load(Ordering::SeqCst)
    }
}

impl ServicePluginInstance for MockServicePlugin {
    fn start(&self) -> Result<(), BindingError> {
        self.start_count.fetch_add(1, Ordering::SeqCst);
        self.running.store(true, Ordering::SeqCst);
        Ok(())
    }

    fn stop(&self) -> Result<(), BindingError> {
        self.stop_count.fetch_add(1, Ordering::SeqCst);
        self.running.store(false, Ordering::SeqCst);
        Ok(())
    }

    fn health(&self) -> Result<bool, BindingError> {
        Ok(self.running.load(Ordering::SeqCst))
    }
}

/// Mock hook plugin with payload modification
struct MockHookPlugin {
    id: String,
    hooks: Vec<String>,
    modify: bool,
    cancel: bool,
    handle_count: AtomicUsize,
}

impl MockHookPlugin {
    fn new(id: &str, hooks: Vec<String>, modify: bool, cancel: bool) -> Self {
        Self {
            id: id.to_string(),
            hooks,
            modify,
            cancel,
            handle_count: AtomicUsize::new(0),
        }
    }

    fn handle_count(&self) -> usize {
        self.handle_count.load(Ordering::SeqCst)
    }
}

impl HookPluginInstance for MockHookPlugin {
    fn get_hooks(&self) -> Result<Vec<String>, BindingError> {
        Ok(self.hooks.clone())
    }

    fn handle(&self, event: HookEvent) -> Result<HookResult, BindingError> {
        self.handle_count.fetch_add(1, Ordering::SeqCst);

        let modified = if self.modify && is_modifiable_hook(&event.hook_name) {
            Some(format!(
                r#"{{"modified_by":"{}","hook":"{}","original":{}}}"#,
                self.id, event.hook_name, event.payload
            ))
        } else {
            None
        };

        Ok(HookResult {
            handled: true,
            cancel: self.cancel,
            modified_payload: modified,
        })
    }
}

// ============== Tool Dispatcher Tests ==============

#[test]
fn test_tool_dispatcher_full_flow() {
    let registry = Arc::new(PluginRegistry::new());

    // Register multiple tool plugins
    let tools1 = vec![
        ToolDefinition {
            name: "search".to_string(),
            description: "Search the web".to_string(),
            input_schema: r#"{"type":"object","properties":{"query":{"type":"string"}}}"#
                .to_string(),
        },
        ToolDefinition {
            name: "fetch".to_string(),
            description: "Fetch a URL".to_string(),
            input_schema: r#"{"type":"object","properties":{"url":{"type":"string"}}}"#.to_string(),
        },
    ];
    let plugin1 = Arc::new(MockToolPlugin::new("web-tools", tools1));

    let tools2 = vec![ToolDefinition {
        name: "calculate".to_string(),
        description: "Calculate expression".to_string(),
        input_schema: r#"{"type":"object","properties":{"expr":{"type":"string"}}}"#.to_string(),
    }];
    let plugin2 = Arc::new(MockToolPlugin::new("math-tools", tools2));

    registry.register_tool("web-tools".to_string(), plugin1.clone());
    registry.register_tool("math-tools".to_string(), plugin2.clone());

    let dispatcher = ToolDispatcher::new(registry);
    dispatcher.refresh_tool_map().unwrap();

    // List all tools
    let tools = dispatcher.list_tools().unwrap();
    assert_eq!(tools.len(), 3);

    // Invoke tools from different plugins
    let ctx = ToolContext {
        agent_id: Some("test-agent".to_string()),
        session_key: Some("main".to_string()),
        message_channel: Some("telegram".to_string()),
        sandboxed: false,
    };

    // Invoke search tool
    let result = dispatcher
        .invoke("search", r#"{"query":"rust"}"#, ctx.clone())
        .unwrap();
    assert!(result.success);
    assert!(result.result.unwrap().contains("web-tools"));

    // Invoke calculate tool
    let result = dispatcher
        .invoke("calculate", r#"{"expr":"2+2"}"#, ctx.clone())
        .unwrap();
    assert!(result.success);
    assert!(result.result.unwrap().contains("math-tools"));

    // Check invocation counts
    assert_eq!(plugin1.invocation_count(), 1);
    assert_eq!(plugin2.invocation_count(), 1);
}

#[test]
fn test_tool_dispatcher_namespaced_tools() {
    let registry = Arc::new(PluginRegistry::new());

    let tools = vec![ToolDefinition {
        name: "run".to_string(),
        description: "Run something".to_string(),
        input_schema: "{}".to_string(),
    }];

    registry.register_tool(
        "plugin-a".to_string(),
        Arc::new(MockToolPlugin::new("plugin-a", tools.clone())),
    );
    registry.register_tool(
        "plugin-b".to_string(),
        Arc::new(MockToolPlugin::new("plugin-b", tools)),
    );

    let dispatcher = ToolDispatcher::new(registry);
    dispatcher.refresh_tool_map().unwrap();

    let ctx = default_tool_context();

    // Both namespaced versions should work
    let result = dispatcher
        .invoke("plugin-a_run", "{}", ctx.clone())
        .unwrap();
    assert!(result.success);
    assert!(result.result.unwrap().contains("plugin-a"));

    let result = dispatcher
        .invoke("plugin-b_run", "{}", default_tool_context())
        .unwrap();
    assert!(result.success);
    assert!(result.result.unwrap().contains("plugin-b"));
}

#[test]
fn test_tool_dispatcher_not_found() {
    let registry = Arc::new(PluginRegistry::new());
    let dispatcher = ToolDispatcher::new(registry);

    let ctx = default_tool_context();
    let result = dispatcher.invoke("nonexistent", "{}", ctx);

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.to_string().contains("not found"));
}

// ============== Webhook Dispatcher Tests ==============

#[test]
fn test_webhook_dispatcher_full_flow() {
    let registry = Arc::new(PluginRegistry::new());

    let plugin1 = Arc::new(MockWebhookPlugin::new(
        "github",
        vec!["/webhook".to_string(), "/events".to_string()],
    ));
    let plugin2 = Arc::new(MockWebhookPlugin::new(
        "stripe",
        vec!["/webhook".to_string()],
    ));

    registry.register_webhook("github".to_string(), plugin1.clone());
    registry.register_webhook("stripe".to_string(), plugin2.clone());

    let dispatcher = WebhookDispatcher::new(registry);
    dispatcher.refresh_path_map().unwrap();

    // List paths
    let paths = dispatcher.list_paths().unwrap();
    assert_eq!(paths.len(), 3);
    assert!(paths.contains(&"/plugins/github/webhook".to_string()));
    assert!(paths.contains(&"/plugins/github/events".to_string()));
    assert!(paths.contains(&"/plugins/stripe/webhook".to_string()));

    // Handle GitHub webhook
    let req = WebhookRequest {
        method: "POST".to_string(),
        path: "/plugins/github/webhook".to_string(),
        headers: vec![
            ("Content-Type".to_string(), "application/json".to_string()),
            ("X-GitHub-Event".to_string(), "push".to_string()),
        ],
        body: Some(br#"{"action":"push"}"#.to_vec()),
        query: None,
    };

    let response = dispatcher.handle("/plugins/github/webhook", req).unwrap();
    assert_eq!(response.status, 200);
    assert_eq!(plugin1.request_count(), 1);
    assert_eq!(plugin2.request_count(), 0);

    // Handle Stripe webhook
    let req = WebhookRequest {
        method: "POST".to_string(),
        path: "/plugins/stripe/webhook".to_string(),
        headers: vec![],
        body: Some(br#"{"type":"payment.succeeded"}"#.to_vec()),
        query: None,
    };

    let response = dispatcher.handle("/plugins/stripe/webhook", req).unwrap();
    assert_eq!(response.status, 200);
    assert_eq!(plugin1.request_count(), 1);
    assert_eq!(plugin2.request_count(), 1);
}

#[test]
fn test_webhook_dispatcher_path_stripping() {
    let registry = Arc::new(PluginRegistry::new());

    let plugin = Arc::new(MockWebhookPlugin::new(
        "test-plugin",
        vec!["/callback".to_string()],
    ));
    registry.register_webhook("test-plugin".to_string(), plugin);

    let dispatcher = WebhookDispatcher::new(registry);
    dispatcher.refresh_path_map().unwrap();

    let req = WebhookRequest {
        method: "GET".to_string(),
        path: "/plugins/test-plugin/callback".to_string(),
        headers: vec![],
        body: None,
        query: Some("code=abc123".to_string()),
    };

    let response = dispatcher
        .handle("/plugins/test-plugin/callback", req)
        .unwrap();

    // Verify the path was stripped to just /callback for the plugin
    let body = String::from_utf8(response.body.unwrap()).unwrap();
    assert!(body.contains(r#""path":"/callback""#));
}

#[test]
fn test_webhook_dispatcher_not_found() {
    let registry = Arc::new(PluginRegistry::new());
    let dispatcher = WebhookDispatcher::new(registry);

    let req = WebhookRequest {
        method: "POST".to_string(),
        path: "/plugins/nonexistent/webhook".to_string(),
        headers: vec![],
        body: None,
        query: None,
    };

    let result = dispatcher.handle("/plugins/nonexistent/webhook", req);
    assert!(result.is_err());
}

// ============== Hook Dispatcher Tests ==============

#[test]
fn test_hook_dispatcher_modifiable_chain() {
    let registry = Arc::new(PluginRegistry::new());

    // Two plugins that modify the payload
    let plugin1 = Arc::new(MockHookPlugin::new(
        "plugin-a",
        vec!["before_agent_start".to_string()],
        true,
        false,
    ));
    let plugin2 = Arc::new(MockHookPlugin::new(
        "plugin-b",
        vec!["before_agent_start".to_string()],
        true,
        false,
    ));

    registry.register_hook("plugin-a".to_string(), plugin1.clone());
    registry.register_hook("plugin-b".to_string(), plugin2.clone());

    let dispatcher = HookDispatcher::new(registry);

    let result = dispatcher
        .dispatch("before_agent_start", r#"{"prompt":"hello"}"#)
        .unwrap();

    assert!(result.handled);
    assert_eq!(result.handler_count, 2);
    assert!(!result.cancelled);
    assert!(result.final_payload.is_some());

    // Both plugins should have been called
    assert_eq!(plugin1.handle_count(), 1);
    assert_eq!(plugin2.handle_count(), 1);

    // Payload should have been modified (nested modifications)
    let payload = result.final_payload.unwrap();
    assert!(payload.contains("modified_by"));
}

#[test]
fn test_hook_dispatcher_readonly_hooks() {
    let registry = Arc::new(PluginRegistry::new());

    // Plugin that tries to modify a read-only hook
    let plugin = Arc::new(MockHookPlugin::new(
        "logger",
        vec!["agent_end".to_string()],
        true, // tries to modify
        false,
    ));
    registry.register_hook("logger".to_string(), plugin.clone());

    let dispatcher = HookDispatcher::new(registry);

    let result = dispatcher
        .dispatch("agent_end", r#"{"success":true}"#)
        .unwrap();

    assert!(result.handled);
    assert_eq!(result.handler_count, 1);

    // For read-only hooks, final_payload should be None
    assert!(result.final_payload.is_none());
    assert_eq!(plugin.handle_count(), 1);
}

#[test]
fn test_hook_dispatcher_cancellation() {
    let registry = Arc::new(PluginRegistry::new());

    let plugin = Arc::new(MockHookPlugin::new(
        "blocker",
        vec!["before_tool_call".to_string()],
        false,
        true, // cancels
    ));
    registry.register_hook("blocker".to_string(), plugin);

    let dispatcher = HookDispatcher::new(registry);

    let result = dispatcher
        .dispatch("before_tool_call", r#"{"tool":"dangerous"}"#)
        .unwrap();

    assert!(result.handled);
    assert!(result.cancelled);
}

#[test]
fn test_hook_dispatcher_no_handlers() {
    let registry = Arc::new(PluginRegistry::new());
    let dispatcher = HookDispatcher::new(registry);

    let result = dispatcher
        .dispatch("gateway_start", r#"{"port":18789}"#)
        .unwrap();

    assert!(!result.handled);
    assert_eq!(result.handler_count, 0);
    assert!(!result.cancelled);
}

#[test]
fn test_hook_dispatcher_partial_handlers() {
    let registry = Arc::new(PluginRegistry::new());

    // Plugin that only handles specific hooks
    let plugin = Arc::new(MockHookPlugin::new(
        "metrics",
        vec!["session_start".to_string(), "session_end".to_string()],
        false,
        false,
    ));
    registry.register_hook("metrics".to_string(), plugin.clone());

    let dispatcher = HookDispatcher::new(registry);

    // This hook is handled
    let result = dispatcher
        .dispatch("session_start", r#"{"user":"test"}"#)
        .unwrap();
    assert!(result.handled);
    assert_eq!(result.handler_count, 1);

    // This hook is NOT handled by the plugin
    let result = dispatcher
        .dispatch("gateway_start", r#"{"port":18789}"#)
        .unwrap();
    assert!(!result.handled);
    assert_eq!(result.handler_count, 0);

    assert_eq!(plugin.handle_count(), 1);
}

// ============== Plugin Registry Tests ==============

#[test]
fn test_registry_multi_type_plugin() {
    let registry = PluginRegistry::new();

    // Some plugins might provide multiple capabilities
    // (though typically they're separate instances)
    let channel = Arc::new(MockChannel::new("multi"));
    let tools = vec![ToolDefinition {
        name: "helper".to_string(),
        description: "Helper tool".to_string(),
        input_schema: "{}".to_string(),
    }];
    let tool = Arc::new(MockToolPlugin::new("multi", tools));

    registry.register_channel("multi".to_string(), channel);
    registry.register_tool("multi".to_string(), tool);

    assert_eq!(registry.count(), 2);

    // Unregister removes all
    registry.unregister("multi");
    assert_eq!(registry.count(), 0);
}

#[test]
fn test_registry_get_by_id() {
    let registry = PluginRegistry::new();

    registry.register_channel(
        "telegram".to_string(),
        Arc::new(MockChannel::new("telegram")),
    );
    registry.register_channel("discord".to_string(), Arc::new(MockChannel::new("discord")));

    assert!(registry.get_channel("telegram").is_some());
    assert!(registry.get_channel("discord").is_some());
    assert!(registry.get_channel("slack").is_none());
}

// ============== Service Plugin Tests ==============

#[test]
fn test_service_lifecycle() {
    let registry = PluginRegistry::new();

    let service1 = Arc::new(MockServicePlugin::new("worker-1"));
    let service2 = Arc::new(MockServicePlugin::new("worker-2"));

    registry.register_service("worker-1".to_string(), service1.clone());
    registry.register_service("worker-2".to_string(), service2.clone());

    // Initially not healthy
    assert!(!service1.health().unwrap());
    assert!(!service2.health().unwrap());

    // Start services
    for (_, service) in registry.get_services() {
        service.start().unwrap();
    }

    assert!(service1.health().unwrap());
    assert!(service2.health().unwrap());

    // Stop services
    for (_, service) in registry.get_services() {
        service.stop().unwrap();
    }

    assert!(!service1.health().unwrap());
    assert!(!service2.health().unwrap());
}

// ============== Channel Plugin Tests ==============

#[test]
fn test_channel_send_flow() {
    let registry = PluginRegistry::new();

    let channel = Arc::new(MockChannel::new("test"));
    registry.register_channel("test".to_string(), channel.clone());

    let ctx = OutboundContext {
        to: "user123".to_string(),
        text: "Hello!".to_string(),
        media_url: None,
        gif_playback: false,
        reply_to_id: None,
        thread_id: None,
        account_id: None,
    };

    // Success case
    let result = channel.send_text(ctx.clone()).unwrap();
    assert!(result.ok);
    assert!(result.message_id.is_some());
    assert_eq!(channel.send_count(), 1);

    // Failure case
    channel.set_fail_sends(true);
    let result = channel.send_text(ctx).unwrap();
    assert!(!result.ok);
    assert!(result.error.is_some());
    assert!(result.retryable);
    assert_eq!(channel.send_count(), 2);
}

// ============== Manifest Validation Tests ==============

#[test]
fn test_manifest_validation_valid() {
    let manifest = PluginManifest {
        id: "my-plugin".to_string(),
        name: "My Plugin".to_string(),
        description: "A test plugin".to_string(),
        version: "1.0.0".to_string(),
        kind: PluginKind::Tool,
        permissions: Default::default(),
    };
    assert!(manifest.validate().is_ok());
}

#[test]
fn test_manifest_validation_id_format() {
    // Empty ID
    let manifest = PluginManifest {
        id: "".to_string(),
        name: "Test".to_string(),
        description: "Test".to_string(),
        version: "1.0.0".to_string(),
        kind: PluginKind::Tool,
        permissions: Default::default(),
    };
    assert!(manifest.validate().is_err());

    // ID too long
    let manifest = PluginManifest {
        id: "x".repeat(33),
        name: "Test".to_string(),
        description: "Test".to_string(),
        version: "1.0.0".to_string(),
        kind: PluginKind::Tool,
        permissions: Default::default(),
    };
    assert!(manifest.validate().is_err());

    // Uppercase in ID
    let manifest = PluginManifest {
        id: "MyPlugin".to_string(),
        name: "Test".to_string(),
        description: "Test".to_string(),
        version: "1.0.0".to_string(),
        kind: PluginKind::Tool,
        permissions: Default::default(),
    };
    assert!(manifest.validate().is_err());

    // Underscores in ID (not allowed)
    let manifest = PluginManifest {
        id: "my_plugin".to_string(),
        name: "Test".to_string(),
        description: "Test".to_string(),
        version: "1.0.0".to_string(),
        kind: PluginKind::Tool,
        permissions: Default::default(),
    };
    assert!(manifest.validate().is_err());

    // Hyphens are allowed
    let manifest = PluginManifest {
        id: "my-plugin-123".to_string(),
        name: "Test".to_string(),
        description: "Test".to_string(),
        version: "1.0.0".to_string(),
        kind: PluginKind::Tool,
        permissions: Default::default(),
    };
    assert!(manifest.validate().is_ok());
}

#[test]
fn test_manifest_validation_version() {
    // Invalid version (no dot)
    let manifest = PluginManifest {
        id: "test".to_string(),
        name: "Test".to_string(),
        description: "Test".to_string(),
        version: "1".to_string(),
        kind: PluginKind::Tool,
        permissions: Default::default(),
    };
    assert!(manifest.validate().is_err());

    // Valid versions
    for version in ["1.0", "1.0.0", "0.1.0-beta", "2.0.0-rc.1"] {
        let manifest = PluginManifest {
            id: "test".to_string(),
            name: "Test".to_string(),
            description: "Test".to_string(),
            version: version.to_string(),
            kind: PluginKind::Tool,
            permissions: Default::default(),
        };
        assert!(
            manifest.validate().is_ok(),
            "Version '{}' should be valid",
            version
        );
    }
}

// ============== Constants Tests ==============

#[test]
fn test_modifiable_hooks_list() {
    // Verify the expected modifiable hooks
    assert!(MODIFIABLE_HOOKS.contains(&"before_agent_start"));
    assert!(MODIFIABLE_HOOKS.contains(&"message_sending"));
    assert!(MODIFIABLE_HOOKS.contains(&"before_tool_call"));
    assert!(MODIFIABLE_HOOKS.contains(&"tool_result_persist"));

    // Verify is_modifiable_hook matches
    for hook in MODIFIABLE_HOOKS {
        assert!(is_modifiable_hook(hook), "{} should be modifiable", hook);
    }

    // Non-modifiable hooks
    let readonly_hooks = [
        "agent_end",
        "session_start",
        "session_end",
        "before_compaction",
        "after_compaction",
        "message_received",
        "message_sent",
        "after_tool_call",
        "gateway_start",
        "gateway_stop",
    ];

    for hook in readonly_hooks {
        assert!(
            !is_modifiable_hook(hook),
            "{} should NOT be modifiable",
            hook
        );
    }
}

#[test]
fn test_plugin_kind_display() {
    assert_eq!(PluginKind::Channel.to_string(), "channel");
    assert_eq!(PluginKind::Tool.to_string(), "tool");
    assert_eq!(PluginKind::Webhook.to_string(), "webhook");
    assert_eq!(PluginKind::Service.to_string(), "service");
    assert_eq!(PluginKind::Provider.to_string(), "provider");
    assert_eq!(PluginKind::Hook.to_string(), "hook");
}

// ============== Helper Functions ==============

fn default_tool_context() -> ToolContext {
    ToolContext {
        agent_id: None,
        session_key: None,
        message_channel: None,
        sandboxed: false,
    }
}
