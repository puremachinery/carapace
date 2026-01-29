//! Integration tests for the plugin system
//!
//! These tests verify the plugin registry, dispatchers, and host context
//! work correctly with mock implementations.

#[cfg(test)]
mod integration_tests {
    use std::sync::Arc;

    use crate::plugins::{
        dispatch::is_modifiable_hook, BindingError, ChannelCapabilities, ChannelInfo,
        ChannelPluginInstance, ChatType, DeliveryResult, HookDispatcher, HookEvent,
        HookPluginInstance, HookResult, OutboundContext, PluginKind, PluginLoader, PluginManifest,
        PluginRegistry, ServicePluginInstance, ToolContext, ToolDefinition, ToolDispatcher,
        ToolPluginInstance, ToolResult, WebhookDispatcher, WebhookPluginInstance, WebhookRequest,
        WebhookResponse,
    };

    // ============== Mock Plugin Implementations ==============

    /// Mock channel plugin for testing
    struct MockChannelPlugin {
        id: String,
        capabilities: ChannelCapabilities,
    }

    impl MockChannelPlugin {
        fn new(id: &str) -> Self {
            Self {
                id: id.to_string(),
                capabilities: ChannelCapabilities {
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
                },
            }
        }
    }

    impl ChannelPluginInstance for MockChannelPlugin {
        fn get_info(&self) -> Result<ChannelInfo, BindingError> {
            Ok(ChannelInfo {
                id: self.id.clone(),
                label: format!("{} Channel", self.id),
                selection_label: self.id.clone(),
                docs_path: format!("/channels/{}", self.id),
                blurb: format!("Mock {} channel for testing", self.id),
                order: 100,
            })
        }

        fn get_capabilities(&self) -> Result<ChannelCapabilities, BindingError> {
            Ok(self.capabilities.clone())
        }

        fn send_text(&self, ctx: OutboundContext) -> Result<DeliveryResult, BindingError> {
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

        fn send_media(&self, ctx: OutboundContext) -> Result<DeliveryResult, BindingError> {
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

    /// Mock tool plugin for testing
    struct MockToolPlugin {
        id: String,
        tools: Vec<ToolDefinition>,
    }

    impl MockToolPlugin {
        fn new(id: &str, tools: Vec<ToolDefinition>) -> Self {
            Self {
                id: id.to_string(),
                tools,
            }
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
            _ctx: ToolContext,
        ) -> Result<ToolResult, BindingError> {
            if self.tools.iter().any(|t| t.name == name) {
                Ok(ToolResult {
                    success: true,
                    result: Some(format!(
                        r#"{{"tool": "{}", "plugin": "{}", "params": {}}}"#,
                        name, self.id, params
                    )),
                    error: None,
                })
            } else {
                Ok(ToolResult {
                    success: false,
                    result: None,
                    error: Some(format!("Tool not found: {}", name)),
                })
            }
        }
    }

    /// Mock webhook plugin for testing
    struct MockWebhookPlugin {
        id: String,
        paths: Vec<String>,
    }

    impl MockWebhookPlugin {
        fn new(id: &str, paths: Vec<String>) -> Self {
            Self {
                id: id.to_string(),
                paths,
            }
        }
    }

    impl WebhookPluginInstance for MockWebhookPlugin {
        fn get_paths(&self) -> Result<Vec<String>, BindingError> {
            Ok(self.paths.clone())
        }

        fn handle(&self, req: WebhookRequest) -> Result<WebhookResponse, BindingError> {
            Ok(WebhookResponse {
                status: 200,
                headers: vec![("Content-Type".to_string(), "application/json".to_string())],
                body: Some(
                    format!(
                        r#"{{"plugin": "{}", "path": "{}", "method": "{}"}}"#,
                        self.id, req.path, req.method
                    )
                    .into_bytes(),
                ),
            })
        }
    }

    /// Mock service plugin for testing
    struct MockServicePlugin {
        #[allow(dead_code)]
        id: String,
        started: std::sync::atomic::AtomicBool,
    }

    impl MockServicePlugin {
        fn new(id: &str) -> Self {
            Self {
                id: id.to_string(),
                started: std::sync::atomic::AtomicBool::new(false),
            }
        }
    }

    impl ServicePluginInstance for MockServicePlugin {
        fn start(&self) -> Result<(), BindingError> {
            self.started
                .store(true, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        }

        fn stop(&self) -> Result<(), BindingError> {
            self.started
                .store(false, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        }

        fn health(&self) -> Result<bool, BindingError> {
            Ok(self.started.load(std::sync::atomic::Ordering::SeqCst))
        }
    }

    /// Mock hook plugin for testing
    struct MockHookPlugin {
        id: String,
        hooks: Vec<String>,
        modify_payload: bool,
    }

    impl MockHookPlugin {
        fn new(id: &str, hooks: Vec<String>, modify_payload: bool) -> Self {
            Self {
                id: id.to_string(),
                hooks,
                modify_payload,
            }
        }
    }

    impl HookPluginInstance for MockHookPlugin {
        fn get_hooks(&self) -> Result<Vec<String>, BindingError> {
            Ok(self.hooks.clone())
        }

        fn handle(&self, event: HookEvent) -> Result<HookResult, BindingError> {
            let modified = if self.modify_payload && is_modifiable_hook(&event.hook_name) {
                Some(format!(
                    r#"{{"modified_by": "{}", "original": {}}}"#,
                    self.id, event.payload
                ))
            } else {
                None
            };

            Ok(HookResult {
                handled: true,
                cancel: false,
                modified_payload: modified,
            })
        }
    }

    // ============== Tests ==============

    #[test]
    fn test_plugin_registry_channel() {
        let registry = PluginRegistry::new();
        let plugin = Arc::new(MockChannelPlugin::new("test-channel"));

        registry.register_channel("test-channel".to_string(), plugin.clone());

        assert_eq!(registry.count(), 1);

        let channels = registry.get_channels();
        assert_eq!(channels.len(), 1);
        assert_eq!(channels[0].0, "test-channel");

        let info = channels[0].1.get_info().unwrap();
        assert_eq!(info.id, "test-channel");
    }

    #[test]
    fn test_plugin_registry_tool() {
        let registry = PluginRegistry::new();
        let tools = vec![ToolDefinition {
            name: "search".to_string(),
            description: "Search the web".to_string(),
            input_schema: r#"{"type": "object"}"#.to_string(),
        }];
        let plugin = Arc::new(MockToolPlugin::new("search-plugin", tools));

        registry.register_tool("search-plugin".to_string(), plugin.clone());

        assert_eq!(registry.count(), 1);

        let result = plugin
            .invoke(
                "search",
                r#"{"query": "test"}"#,
                ToolContext {
                    agent_id: None,
                    session_key: None,
                    message_channel: None,
                    sandboxed: false,
                },
            )
            .unwrap();

        assert!(result.success);
        assert!(result.result.is_some());
    }

    #[test]
    fn test_plugin_registry_webhook() {
        let registry = PluginRegistry::new();
        let plugin = Arc::new(MockWebhookPlugin::new(
            "webhook-plugin",
            vec!["/callback".to_string(), "/events".to_string()],
        ));

        registry.register_webhook("webhook-plugin".to_string(), plugin.clone());

        assert_eq!(registry.count(), 1);

        let paths = plugin.get_paths().unwrap();
        assert_eq!(paths.len(), 2);
        assert!(paths.contains(&"/callback".to_string()));
    }

    #[test]
    fn test_plugin_registry_service() {
        let registry = PluginRegistry::new();
        let plugin = Arc::new(MockServicePlugin::new("service-plugin"));

        registry.register_service("service-plugin".to_string(), plugin.clone());

        assert_eq!(registry.count(), 1);

        // Test lifecycle
        assert!(!plugin.health().unwrap());
        plugin.start().unwrap();
        assert!(plugin.health().unwrap());
        plugin.stop().unwrap();
        assert!(!plugin.health().unwrap());
    }

    #[test]
    fn test_plugin_registry_hook() {
        let registry = PluginRegistry::new();
        let plugin = Arc::new(MockHookPlugin::new(
            "hook-plugin",
            vec!["before_agent_start".to_string(), "agent_end".to_string()],
            true,
        ));

        registry.register_hook("hook-plugin".to_string(), plugin.clone());

        assert_eq!(registry.count(), 1);

        let hooks = plugin.get_hooks().unwrap();
        assert_eq!(hooks.len(), 2);
        assert!(hooks.contains(&"before_agent_start".to_string()));
    }

    #[test]
    fn test_plugin_registry_unregister() {
        let registry = PluginRegistry::new();

        registry.register_channel("chan".to_string(), Arc::new(MockChannelPlugin::new("chan")));
        registry.register_tool(
            "tool".to_string(),
            Arc::new(MockToolPlugin::new("tool", vec![])),
        );

        assert_eq!(registry.count(), 2);

        registry.unregister("chan");
        assert_eq!(registry.count(), 1);

        registry.unregister("tool");
        assert_eq!(registry.count(), 0);
    }

    #[test]
    fn test_tool_dispatcher() {
        let registry = Arc::new(PluginRegistry::new());

        let tools = vec![
            ToolDefinition {
                name: "search".to_string(),
                description: "Search".to_string(),
                input_schema: "{}".to_string(),
            },
            ToolDefinition {
                name: "fetch".to_string(),
                description: "Fetch".to_string(),
                input_schema: "{}".to_string(),
            },
        ];
        registry.register_tool(
            "web-tools".to_string(),
            Arc::new(MockToolPlugin::new("web-tools", tools)),
        );

        let dispatcher = ToolDispatcher::new(registry);
        dispatcher.refresh_tool_map().unwrap();

        let listed = dispatcher.list_tools().unwrap();
        assert_eq!(listed.len(), 2);

        // Invoke a tool
        let ctx = ToolContext {
            agent_id: Some("test".to_string()),
            session_key: Some("main".to_string()),
            message_channel: None,
            sandboxed: false,
        };

        let result = dispatcher
            .invoke("search", r#"{"q": "test"}"#, ctx)
            .unwrap();
        assert!(result.success);
    }

    #[test]
    fn test_webhook_dispatcher() {
        let registry = Arc::new(PluginRegistry::new());

        registry.register_webhook(
            "my-plugin".to_string(),
            Arc::new(MockWebhookPlugin::new(
                "my-plugin",
                vec!["/webhook".to_string()],
            )),
        );

        let dispatcher = WebhookDispatcher::new(registry);
        dispatcher.refresh_path_map().unwrap();

        let paths = dispatcher.list_paths().unwrap();
        assert!(paths.contains(&"/plugins/my-plugin/webhook".to_string()));

        // Handle a webhook
        let request = WebhookRequest {
            method: "POST".to_string(),
            path: "/plugins/my-plugin/webhook".to_string(),
            headers: vec![],
            body: None,
            query: None,
        };

        let response = dispatcher
            .handle("/plugins/my-plugin/webhook", request)
            .unwrap();
        assert_eq!(response.status, 200);
    }

    #[test]
    fn test_hook_dispatcher() {
        let registry = Arc::new(PluginRegistry::new());

        // Register two hook plugins
        registry.register_hook(
            "plugin-a".to_string(),
            Arc::new(MockHookPlugin::new(
                "plugin-a",
                vec!["before_agent_start".to_string()],
                true,
            )),
        );
        registry.register_hook(
            "plugin-b".to_string(),
            Arc::new(MockHookPlugin::new(
                "plugin-b",
                vec!["before_agent_start".to_string(), "agent_end".to_string()],
                false,
            )),
        );

        let dispatcher = HookDispatcher::new(registry);

        // Dispatch a modifiable hook
        let result = dispatcher
            .dispatch("before_agent_start", r#"{"prompt": "test"}"#)
            .unwrap();

        assert!(result.handled);
        assert_eq!(result.handler_count, 2);
        assert!(result.final_payload.is_some());

        // The payload should be modified by plugin-a
        let payload = result.final_payload.unwrap();
        assert!(payload.contains("modified_by"));

        // Dispatch a read-only hook
        let result = dispatcher
            .dispatch("agent_end", r#"{"success": true}"#)
            .unwrap();

        assert!(result.handled);
        assert_eq!(result.handler_count, 1); // Only plugin-b handles this
        assert!(result.final_payload.is_none()); // Read-only hook
    }

    #[test]
    fn test_hook_dispatcher_unhandled() {
        let registry = Arc::new(PluginRegistry::new());
        let dispatcher = HookDispatcher::new(registry);

        // Dispatch a hook with no handlers
        let result = dispatcher
            .dispatch("gateway_start", r#"{"port": 18789}"#)
            .unwrap();

        assert!(!result.handled);
        assert_eq!(result.handler_count, 0);
    }

    #[test]
    fn test_modifiable_hooks() {
        // Test the is_modifiable_hook function
        assert!(is_modifiable_hook("before_agent_start"));
        assert!(is_modifiable_hook("message_sending"));
        assert!(is_modifiable_hook("before_tool_call"));
        assert!(is_modifiable_hook("tool_result_persist"));

        // These should NOT be modifiable
        assert!(!is_modifiable_hook("agent_end"));
        assert!(!is_modifiable_hook("session_start"));
        assert!(!is_modifiable_hook("session_end"));
        assert!(!is_modifiable_hook("message_received"));
        assert!(!is_modifiable_hook("message_sent"));
        assert!(!is_modifiable_hook("after_tool_call"));
        assert!(!is_modifiable_hook("gateway_start"));
        assert!(!is_modifiable_hook("gateway_stop"));
    }

    #[test]
    fn test_channel_capabilities() {
        let plugin = MockChannelPlugin::new("test");
        let caps = plugin.get_capabilities().unwrap();

        assert!(caps.reply);
        assert!(caps.media);
        assert!(caps.threads);
        assert!(!caps.polls);
        assert!(!caps.block_streaming);

        assert_eq!(caps.chat_types.len(), 2);
        assert!(caps.chat_types.contains(&ChatType::Dm));
        assert!(caps.chat_types.contains(&ChatType::Group));
    }

    #[test]
    fn test_channel_send_text() {
        let plugin = MockChannelPlugin::new("test");
        let ctx = OutboundContext {
            to: "user123".to_string(),
            text: "Hello, world!".to_string(),
            media_url: None,
            gif_playback: false,
            reply_to_id: None,
            thread_id: None,
            account_id: None,
        };

        let result = plugin.send_text(ctx).unwrap();
        assert!(result.ok);
        assert!(result.message_id.is_some());
        assert!(result.message_id.unwrap().contains("user123"));
    }

    #[test]
    fn test_plugin_manifest_validation() {
        // Valid manifest
        let manifest = PluginManifest {
            id: "my-plugin".to_string(),
            name: "My Plugin".to_string(),
            description: "A test plugin".to_string(),
            version: "1.0.0".to_string(),
            kind: PluginKind::Tool,
        };
        assert!(manifest.validate().is_ok());

        // Invalid: ID too long
        let manifest = PluginManifest {
            id: "x".repeat(33),
            name: "Test".to_string(),
            description: "Test".to_string(),
            version: "1.0.0".to_string(),
            kind: PluginKind::Tool,
        };
        assert!(manifest.validate().is_err());

        // Invalid: uppercase in ID
        let manifest = PluginManifest {
            id: "MyPlugin".to_string(),
            name: "Test".to_string(),
            description: "Test".to_string(),
            version: "1.0.0".to_string(),
            kind: PluginKind::Tool,
        };
        assert!(manifest.validate().is_err());
    }

    #[test]
    fn test_plugin_loader_creation() {
        let temp_dir = tempfile::tempdir().unwrap();
        let loader = PluginLoader::new(temp_dir.path().to_path_buf()).unwrap();

        assert!(loader.list_plugins().is_empty());
    }

    #[test]
    fn test_plugin_loader_nonexistent_dir() {
        let loader = PluginLoader::new(std::path::PathBuf::from("/nonexistent/plugins")).unwrap();
        let loaded = loader.load_all().unwrap();
        assert!(loaded.is_empty());
    }
}
