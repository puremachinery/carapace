//! Golden trace tests for WS handler dispatch.
//!
//! These tests replay recorded JSON-RPC request/response sequences against
//! [`dispatch_method`] to verify protocol parity. Each test calls a WS method
//! and snapshots the result with [`insta::assert_json_snapshot!`], ensuring the
//! protocol contract is maintained across changes.

#[cfg(test)]
mod golden_trace {
    use crate::logging::buffer::{LogLevel, LOG_BUFFER};
    use crate::server::ws::handlers::dispatch_method;
    use crate::server::ws::*;
    use serde_json::{json, Value};
    use std::sync::Arc;

    // ───────────────────────── helpers ─────────────────────────

    /// Create a default test server state (in-memory, no persistence).
    fn test_state() -> Arc<WsServerState> {
        Arc::new(WsServerState::new(WsServerConfig::default()))
    }

    /// Create an admin connection context.
    ///
    /// Admin role is used so that all methods are accessible without
    /// scope restrictions, allowing us to exercise every handler.
    fn admin_conn() -> ConnectionContext {
        ConnectionContext {
            conn_id: "test-conn-1".to_string(),
            role: "admin".to_string(),
            scopes: vec![],
            client: ClientInfo {
                id: "test-client".to_string(),
                version: "1.0.0".to_string(),
                platform: "test".to_string(),
                mode: "test".to_string(),
                display_name: None,
                device_family: None,
                model_identifier: None,
                instance_id: None,
            },
            device_id: None,
        }
    }

    /// Create a read-only connection context (role = "read").
    fn read_conn() -> ConnectionContext {
        ConnectionContext {
            conn_id: "test-conn-read".to_string(),
            role: "read".to_string(),
            scopes: vec![],
            client: ClientInfo {
                id: "test-client".to_string(),
                version: "1.0.0".to_string(),
                platform: "test".to_string(),
                mode: "test".to_string(),
                display_name: None,
                device_family: None,
                model_identifier: None,
                instance_id: None,
            },
            device_id: None,
        }
    }

    /// Create a node connection context for node-only methods.
    fn node_conn() -> ConnectionContext {
        ConnectionContext {
            conn_id: "test-node-conn".to_string(),
            role: "node".to_string(),
            scopes: vec![],
            client: ClientInfo {
                id: "node-host".to_string(),
                version: "1.0.0".to_string(),
                platform: "test".to_string(),
                mode: "node".to_string(),
                display_name: None,
                device_family: None,
                model_identifier: None,
                instance_id: None,
            },
            device_id: Some("node-test-1".to_string()),
        }
    }

    /// Register a connection so handlers that inspect connection state work.
    fn register_conn(state: &WsServerState, conn: &ConnectionContext) {
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        state.register_connection(conn, tx, None);
    }

    // ───────────────────────── normalization ─────────────────────────

    /// Normalize dynamic values in a dispatch result for stable snapshots.
    ///
    /// Timestamps, UUIDs, file-system paths, and environment-dependent data
    /// (session lists, config content) are replaced with placeholder strings
    /// so that snapshots do not break across machines or time.
    fn normalize_for_snapshot(value: &Result<Value, ErrorShape>) -> Value {
        match value {
            Ok(v) => {
                let mut normalized = v.clone();
                normalize_value(&mut normalized);
                json!({ "ok": true, "result": normalized })
            }
            Err(e) => {
                json!({
                    "ok": false,
                    "error": {
                        "code": e.code,
                        "message": e.message,
                        "retryable": e.retryable
                    }
                })
            }
        }
    }

    fn normalize_value(value: &mut Value) {
        match value {
            Value::Object(map) => {
                normalize_session_fields(map);
                normalize_config_fields(map);
                normalize_skills_fields(map);
                normalize_approvals_fields(map);
                normalize_count_fields(map);
                normalize_usage_fields(map);
                normalize_tts_talk_fields(map);

                for (key, val) in map.iter_mut() {
                    normalize_per_key_field(key, val);
                    normalize_value(val);
                }
            }
            Value::Array(arr) => {
                for item in arr.iter_mut() {
                    normalize_value(item);
                }
            }
            _ => {}
        }
    }

    /// Normalize session-related array fields.
    fn normalize_session_fields(map: &mut serde_json::Map<String, Value>) {
        if let Some(Value::Array(_)) = map.get("sessions") {
            map.insert("sessions".to_string(), json!("<SESSIONS_LIST>"));
        }
        if let Some(Value::Array(_)) = map.get("recent") {
            map.insert("recent".to_string(), json!("<RECENT_LIST>"));
        }
    }

    /// Normalize config snapshot response fields.
    fn normalize_config_fields(map: &mut serde_json::Map<String, Value>) {
        // Config snapshot response (has both "raw" and "parsed" keys)
        if map.contains_key("raw") && map.contains_key("parsed") {
            if let Some(raw) = map.get("raw") {
                if raw.is_string() || raw.is_null() {
                    map.insert("raw".to_string(), json!("<CONFIG_RAW>"));
                }
            }
            if map.contains_key("parsed") {
                map.insert("parsed".to_string(), json!("<CONFIG_PARSED>"));
            }
            if map.contains_key("config") {
                map.insert("config".to_string(), json!("<CONFIG_DATA>"));
            }
            if map.contains_key("exists") {
                map.insert("exists".to_string(), json!("<CONFIG_EXISTS>"));
            }
            if map.contains_key("valid") {
                map.insert("valid".to_string(), json!("<CONFIG_VALID>"));
            }
            if let Some(hash) = map.get("hash") {
                if hash.is_string() || hash.is_null() {
                    map.insert("hash".to_string(), json!("<CONFIG_HASH>"));
                }
            }
            if map.contains_key("issues") {
                map.insert("issues".to_string(), json!("<CONFIG_ISSUES>"));
            }
        }

        // Config key lookup responses (config.get with a key param)
        if map.contains_key("key") && map.contains_key("value") {
            if let Some(Value::String(_)) = map.get("key") {
                map.insert("value".to_string(), json!("<CONFIG_VALUE>"));
            }
        }
    }

    /// Normalize skills.status response fields.
    fn normalize_skills_fields(map: &mut serde_json::Map<String, Value>) {
        if let Some(Value::Array(_)) = map.get("skills") {
            map.insert("skills".to_string(), json!([]));
        }
    }

    /// Normalize approvals-related fields.
    fn normalize_approvals_fields(map: &mut serde_json::Map<String, Value>) {
        if !(map.contains_key("exists") && map.contains_key("file") && map.contains_key("hash")) {
            return;
        }
        map.insert("exists".to_string(), json!("<APPROVALS_EXISTS>"));
        if let Some(hash) = map.get("hash") {
            if hash.is_string() || hash.is_null() {
                map.insert("hash".to_string(), json!("<APPROVALS_HASH>"));
            }
        }
        if let Some(Value::Object(file_obj)) = map.get_mut("file") {
            if let Some(mode) = file_obj.get_mut("mode") {
                *mode = json!("<APPROVALS_MODE>");
            }
        }
    }

    /// Normalize session and status count fields.
    fn normalize_count_fields(map: &mut serde_json::Map<String, Value>) {
        if map.contains_key("count") && map.contains_key("defaults") {
            map.insert("count".to_string(), json!("<SESSION_COUNT>"));
        }
        if map.contains_key("count") && map.contains_key("recent") {
            map.insert("count".to_string(), json!("<SESSION_COUNT>"));
        }
    }

    /// Normalize usage.status response fields.
    fn normalize_usage_fields(map: &mut serde_json::Map<String, Value>) {
        if !(map.contains_key("tracking") && map.contains_key("summary")) {
            return;
        }
        if let Some(val) = map.get_mut("enabled") {
            *val = json!("<ENABLED>");
        }
        if let Some(val) = map.get_mut("tracking") {
            *val = json!("<TRACKING>");
        }
        if let Some(val) = map.get_mut("sessionCount") {
            *val = json!("<USAGE_SESSION_COUNT>");
        }
        if let Some(val) = map.get_mut("providerCount") {
            *val = json!("<USAGE_PROVIDER_COUNT>");
        }
        if let Some(Value::Object(summary)) = map.get_mut("summary") {
            for (_, v) in summary.iter_mut() {
                *v = json!("<USAGE_METRIC>");
            }
        }
    }

    /// Normalize TTS and Talk global-state fields.
    fn normalize_tts_talk_fields(map: &mut serde_json::Map<String, Value>) {
        if map.contains_key("provider") && map.contains_key("voice") {
            for tts_key in &["enabled", "provider", "voice", "rate", "pitch", "volume"] {
                if let Some(val) = map.get_mut(*tts_key) {
                    *val = json!(format!("<TTS_{}>", tts_key.to_uppercase()));
                }
            }
        }
        if map.contains_key("current") && map.contains_key("providers") {
            if let Some(val) = map.get_mut("current") {
                *val = json!("<TTS_CURRENT>");
            }
        }
        if map.contains_key("active") && map.contains_key("availableModes") {
            for talk_key in &[
                "active",
                "mode",
                "vadThreshold",
                "silenceTimeoutMs",
                "autoRespond",
                "inputDevice",
                "outputDevice",
            ] {
                if let Some(val) = map.get_mut(*talk_key) {
                    *val = json!(format!("<TALK_{}>", talk_key.to_uppercase()));
                }
            }
        }
    }

    /// Normalize a single key-value pair for volatile fields (timestamps, UUIDs, paths, etc.).
    fn normalize_per_key_field(key: &str, val: &mut Value) {
        // Replace timestamp-like numeric fields.
        if (key.ends_with("_ms")
            || key.ends_with("Ms")
            || key.ends_with("At")
            || key.ends_with("_at")
            || key.ends_with("AtMs")
            || key == "timestamp"
            || key == "time"
            || key == "uptime"
            || key == "uptimeMs"
            || key == "ts"
            || key == "nextRunAtMs"
            || key == "lastCheckAt")
            && val.is_number()
        {
            *val = json!("<TIMESTAMP>");
        }

        if (key == "cursor" || key == "seq") && val.is_number() {
            *val = json!(format!("<{}>", key.to_uppercase()));
        }

        if (key == "size" || key == "total") && val.is_number() {
            *val = json!("<COUNT>");
        }

        // Replace UUID-like string fields.
        if key == "id" || key == "connId" || key == "sessionId" || key.ends_with("Id") {
            if let Some(s) = val.as_str() {
                if s.len() >= 32 && s.contains('-') {
                    *val = json!("<UUID>");
                }
            }
        }

        // Replace file-system paths.
        if key == "path"
            || key == "file"
            || key == "storePath"
            || key == "workspaceDir"
            || key == "managedSkillsDir"
        {
            if let Some(s) = val.as_str() {
                if s.contains('/') || s.contains('\\') {
                    *val = json!("<PATH>");
                }
            }
        }

        // Replace host-name field.
        if key == "host" && val.is_string() {
            *val = json!("<HOST>");
        }

        // Replace version field.
        if key == "version" {
            if let Some(s) = val.as_str() {
                if s.contains('.') && s.chars().next().is_some_and(|c| c.is_ascii_digit()) {
                    *val = json!("<VERSION>");
                }
            }
        }

        // Replace the currentVersion field (update status).
        if key == "currentVersion" && (val.is_string() || val.is_null()) {
            *val = json!("<VERSION>");
        }

        // Replace architecture field for cross-platform stability.
        if key == "arch" && val.is_string() {
            *val = json!("<ARCH>");
        }

        // Replace platform field for cross-platform stability.
        if key == "platform" && val.is_string() {
            *val = json!("<PLATFORM>");
        }
    }

    // ───────────────────────── macro ─────────────────────────

    /// Convenience macro for single-method golden trace tests.
    ///
    /// Creates an admin connection, registers it, dispatches the given method
    /// with the given params, normalizes the result, and asserts a named
    /// JSON snapshot.
    macro_rules! golden_test {
        ($name:ident, $method:expr, $params:expr) => {
            #[tokio::test]
            async fn $name() {
                let state = test_state();
                let conn = admin_conn();
                register_conn(&state, &conn);
                let params_val: Value = $params;
                let result = dispatch_method($method, Some(&params_val), &state, &conn).await;
                let normalized = normalize_for_snapshot(&result);
                insta::assert_json_snapshot!(stringify!($name), normalized);
            }
        };
        // Variant that takes no params (passes None).
        ($name:ident, $method:expr) => {
            #[tokio::test]
            async fn $name() {
                let state = test_state();
                let conn = admin_conn();
                register_conn(&state, &conn);
                let result = dispatch_method($method, None, &state, &conn).await;
                let normalized = normalize_for_snapshot(&result);
                insta::assert_json_snapshot!(stringify!($name), normalized);
            }
        };
    }

    // ───────────────────────── Health / Status ─────────────────────────

    golden_test!(golden_health, "health", json!({}));
    golden_test!(golden_status, "status", json!({}));

    // ───────────────────────── Config ─────────────────────────

    golden_test!(golden_config_get, "config.get", json!({}));
    golden_test!(
        golden_config_get_key,
        "config.get",
        json!({ "key": "gateway.port" })
    );

    // ───────────────────────── Sessions ─────────────────────────

    golden_test!(golden_sessions_list_empty, "sessions.list", json!({}));

    #[tokio::test]
    async fn golden_sessions_list_after_create() {
        let state = test_state();
        let conn = admin_conn();
        register_conn(&state, &conn);

        // Create a session by sending a chat message.
        let send_params = json!({
            "sessionKey": "golden-test-session",
            "message": "hello from golden test"
        });
        let _ = dispatch_method("chat.send", Some(&send_params), &state, &conn).await;

        // Now list sessions.
        let result = dispatch_method("sessions.list", Some(&json!({})), &state, &conn).await;
        let normalized = normalize_for_snapshot(&result);
        insta::assert_json_snapshot!("golden_sessions_list_after_create", normalized);
    }

    // ───────────────────────── Channels ─────────────────────────

    golden_test!(golden_channels_status, "channels.status", json!({}));

    // ───────────────────────── Models / Agents ─────────────────────────

    golden_test!(golden_models_list, "models.list", json!({}));
    golden_test!(golden_agents_list, "agents.list", json!({}));

    // ───────────────────────── Cron ─────────────────────────

    golden_test!(golden_cron_list_empty, "cron.list", json!({}));
    golden_test!(golden_cron_status, "cron.status", json!({}));

    // ───────────────────────── Usage ─────────────────────────

    golden_test!(golden_usage_status, "usage.status", json!({}));

    // ───────────────────────── TTS ─────────────────────────

    golden_test!(golden_tts_status, "tts.status", json!({}));
    golden_test!(golden_tts_providers, "tts.providers", json!({}));

    // ───────────────────────── Talk ─────────────────────────

    golden_test!(golden_talk_status, "talk.status", json!({}));

    // ───────────────────────── Wizard ─────────────────────────

    golden_test!(golden_wizard_status, "wizard.status", json!({}));

    // ───────────────────────── Voicewake ─────────────────────────

    golden_test!(golden_voicewake_get, "voicewake.get", json!({}));

    // ───────────────────────── Node / Device pairing ─────────────────────────

    golden_test!(golden_node_pair_list, "node.pair.list", json!({}));
    golden_test!(golden_device_pair_list, "device.pair.list", json!({}));

    // ───────────────────────── Skills ─────────────────────────

    golden_test!(golden_skills_status, "skills.status", json!({}));

    /// `skills.bins` is a node-only method; use a node connection.
    #[tokio::test]
    async fn golden_skills_bins() {
        let state = test_state();
        let conn = node_conn();
        register_conn(&state, &conn);
        let result = dispatch_method("skills.bins", Some(&json!({})), &state, &conn).await;
        let normalized = normalize_for_snapshot(&result);
        insta::assert_json_snapshot!("golden_skills_bins", normalized);
    }

    // ───────────────────────── Exec approvals ─────────────────────────

    golden_test!(golden_exec_approvals_get, "exec.approvals.get", json!({}));

    // ───────────────────────── Update ─────────────────────────

    golden_test!(golden_update_status, "update.status", json!({}));

    // ───────────────────────── Heartbeat ─────────────────────────

    golden_test!(golden_last_heartbeat, "last-heartbeat", json!({}));

    // ───────────────────────── Error cases ─────────────────────────

    /// Unknown method returns UNAVAILABLE error.
    #[tokio::test]
    async fn golden_unknown_method() {
        let state = test_state();
        let conn = admin_conn();
        register_conn(&state, &conn);
        let result = dispatch_method("nonexistent.method", Some(&json!({})), &state, &conn).await;
        let normalized = normalize_for_snapshot(&result);
        insta::assert_json_snapshot!("golden_unknown_method", normalized);
    }

    /// Method called with wrong param type to trigger validation error.
    #[tokio::test]
    async fn golden_invalid_params() {
        let state = test_state();
        let conn = admin_conn();
        register_conn(&state, &conn);
        // cron.add requires a name string; passing a number should fail.
        let result =
            dispatch_method("cron.add", Some(&json!({ "name": 12345 })), &state, &conn).await;
        let normalized = normalize_for_snapshot(&result);
        insta::assert_json_snapshot!("golden_invalid_params", normalized);
    }

    /// Calling a node-only method with a non-node role returns an error.
    #[tokio::test]
    async fn golden_node_only_method_forbidden() {
        let state = test_state();
        let conn = admin_conn(); // admin, not node
        register_conn(&state, &conn);
        let result = dispatch_method("skills.bins", Some(&json!({})), &state, &conn).await;
        let normalized = normalize_for_snapshot(&result);
        insta::assert_json_snapshot!("golden_node_only_method_forbidden", normalized);
    }

    /// Read role calling a write method results in authorization error.
    #[tokio::test]
    async fn golden_write_method_read_role() {
        let state = test_state();
        let conn = read_conn();
        register_conn(&state, &conn);
        let result = dispatch_method("config.set", Some(&json!({})), &state, &conn).await;
        let normalized = normalize_for_snapshot(&result);
        insta::assert_json_snapshot!("golden_write_method_read_role", normalized);
    }

    // ───────────────────────── Workflow: cron lifecycle ─────────────────────────

    #[tokio::test]
    async fn golden_cron_lifecycle() {
        let state = test_state();
        let conn = admin_conn();
        register_conn(&state, &conn);

        // Step 1: List (empty)
        let result = dispatch_method("cron.list", Some(&json!({})), &state, &conn).await;
        let normalized = normalize_for_snapshot(&result);
        insta::assert_json_snapshot!("cron_lifecycle_1_list_empty", normalized);

        // Step 2: Add a cron job
        let result = dispatch_method(
            "cron.add",
            Some(&json!({
                "name": "golden-test-job",
                "schedule": { "kind": "cron", "expr": "*/5 * * * *" },
                "payload": { "kind": "systemEvent", "text": "test golden" }
            })),
            &state,
            &conn,
        )
        .await;
        let normalized = normalize_for_snapshot(&result);
        insta::assert_json_snapshot!("cron_lifecycle_2_add", normalized);

        // Step 3: List (has one)
        let result = dispatch_method("cron.list", Some(&json!({})), &state, &conn).await;
        let normalized = normalize_for_snapshot(&result);
        insta::assert_json_snapshot!("cron_lifecycle_3_list_with_job", normalized);

        // Step 4: Status
        let result = dispatch_method("cron.status", Some(&json!({})), &state, &conn).await;
        let normalized = normalize_for_snapshot(&result);
        insta::assert_json_snapshot!("cron_lifecycle_4_status", normalized);
    }

    // ───────────────────────── Workflow: session lifecycle ─────────────────────────

    #[tokio::test]
    async fn golden_session_lifecycle() {
        let state = test_state();
        let conn = admin_conn();
        register_conn(&state, &conn);

        // Step 1: List sessions (may have disk-resident sessions)
        let result = dispatch_method("sessions.list", Some(&json!({})), &state, &conn).await;
        let normalized = normalize_for_snapshot(&result);
        insta::assert_json_snapshot!("session_lifecycle_1_list_empty", normalized);

        // Step 2: Send a chat message (creates a session)
        let result = dispatch_method(
            "chat.send",
            Some(&json!({
                "sessionKey": "lifecycle-session",
                "message": "hello lifecycle"
            })),
            &state,
            &conn,
        )
        .await;
        let normalized = normalize_for_snapshot(&result);
        insta::assert_json_snapshot!("session_lifecycle_2_send", normalized);

        // Step 3: List sessions (should include the new one)
        let result = dispatch_method("sessions.list", Some(&json!({})), &state, &conn).await;
        let normalized = normalize_for_snapshot(&result);
        insta::assert_json_snapshot!("session_lifecycle_3_list_after_send", normalized);

        // Step 4: Preview the session
        let result = dispatch_method(
            "sessions.preview",
            Some(&json!({ "sessionKey": "lifecycle-session" })),
            &state,
            &conn,
        )
        .await;
        let normalized = normalize_for_snapshot(&result);
        insta::assert_json_snapshot!("session_lifecycle_4_preview", normalized);

        // Step 5: Delete the session
        let result = dispatch_method(
            "sessions.delete",
            Some(&json!({ "sessionKey": "lifecycle-session" })),
            &state,
            &conn,
        )
        .await;
        let normalized = normalize_for_snapshot(&result);
        insta::assert_json_snapshot!("session_lifecycle_5_delete", normalized);

        // Step 6: List sessions (one fewer)
        let result = dispatch_method("sessions.list", Some(&json!({})), &state, &conn).await;
        let normalized = normalize_for_snapshot(&result);
        insta::assert_json_snapshot!("session_lifecycle_6_list_final", normalized);
    }

    // ───────────────────────── Workflow: config lifecycle ─────────────────────────

    #[tokio::test]
    async fn golden_config_lifecycle() {
        let state = test_state();
        let conn = admin_conn();
        register_conn(&state, &conn);

        // Step 1: Get full config
        let result = dispatch_method("config.get", Some(&json!({})), &state, &conn).await;
        let normalized = normalize_for_snapshot(&result);
        insta::assert_json_snapshot!("config_lifecycle_1_get", normalized);

        // Step 2: Get specific key
        let result = dispatch_method(
            "config.get",
            Some(&json!({ "key": "gateway.port" })),
            &state,
            &conn,
        )
        .await;
        let normalized = normalize_for_snapshot(&result);
        insta::assert_json_snapshot!("config_lifecycle_2_get_key", normalized);

        // Step 3: Get schema
        let result = dispatch_method("config.schema", Some(&json!({})), &state, &conn).await;
        let normalized = normalize_for_snapshot(&result);
        insta::assert_json_snapshot!("config_lifecycle_3_schema", normalized);
    }

    // ───────────────────────── Workflow: TTS lifecycle ─────────────────────────

    #[tokio::test]
    async fn golden_tts_lifecycle() {
        let state = test_state();
        let conn = admin_conn();
        register_conn(&state, &conn);

        // Step 1: Status (disabled by default)
        let result = dispatch_method("tts.status", Some(&json!({})), &state, &conn).await;
        let normalized = normalize_for_snapshot(&result);
        insta::assert_json_snapshot!("tts_lifecycle_1_status", normalized);

        // Step 2: List providers
        let result = dispatch_method("tts.providers", Some(&json!({})), &state, &conn).await;
        let normalized = normalize_for_snapshot(&result);
        insta::assert_json_snapshot!("tts_lifecycle_2_providers", normalized);

        // Step 3: List voices
        let result = dispatch_method("tts.voices", Some(&json!({})), &state, &conn).await;
        let normalized = normalize_for_snapshot(&result);
        insta::assert_json_snapshot!("tts_lifecycle_3_voices", normalized);

        // Step 4: Enable TTS
        let result = dispatch_method("tts.enable", Some(&json!({})), &state, &conn).await;
        let normalized = normalize_for_snapshot(&result);
        insta::assert_json_snapshot!("tts_lifecycle_4_enable", normalized);

        // Step 5: Status after enable
        let result = dispatch_method("tts.status", Some(&json!({})), &state, &conn).await;
        let normalized = normalize_for_snapshot(&result);
        insta::assert_json_snapshot!("tts_lifecycle_5_status_after_enable", normalized);
    }

    // ───────────────────────── Additional read-only snapshots ─────────────────────────

    #[tokio::test]
    async fn golden_logs_tail() {
        let state = test_state();
        let conn = admin_conn();
        register_conn(&state, &conn);

        LOG_BUFFER.clear();
        LOG_BUFFER.push_with_seq(
            LogLevel::Info,
            "golden.logs.tail".to_string(),
            "golden log line".to_string(),
            None,
            None,
        );

        let params_val: Value = json!({
            "limit": 10,
            "pattern": "^golden\\.logs\\.tail$"
        });
        let result = dispatch_method("logs.tail", Some(&params_val), &state, &conn).await;
        let normalized = normalize_for_snapshot(&result);
        insta::assert_json_snapshot!("golden_logs_tail", normalized);
    }

    golden_test!(golden_system_presence, "system-presence", json!({}));

    golden_test!(golden_voicewake_keywords, "voicewake.keywords", json!({}));

    golden_test!(golden_talk_devices, "talk.devices", json!({}));

    golden_test!(golden_wizard_list, "wizard.list", json!({}));

    golden_test!(golden_config_schema, "config.schema", json!({}));
}
