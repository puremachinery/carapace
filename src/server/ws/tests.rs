use super::*;

#[test]
fn test_error_shape() {
    let err = error_shape(ERROR_INVALID_REQUEST, "test error", None);
    assert_eq!(err.code, "INVALID_REQUEST");
    assert_eq!(err.message, "test error");
    assert!(!err.retryable);

    let err2 = error_shape(ERROR_UNAVAILABLE, "temp error", Some(json!({"foo": "bar"})));
    assert_eq!(err2.code, "UNAVAILABLE");
    assert!(err2.retryable);
    assert!(err2.details.is_some());
}

#[test]
fn test_canonicalize_ws_method_name_aliases() {
    assert_eq!(canonicalize_ws_method_name("agent.run"), "agent");
    assert_eq!(canonicalize_ws_method_name("agent.cancel"), "chat.abort");
    assert_eq!(canonicalize_ws_method_name("session.list"), "sessions.list");
    assert_eq!(canonicalize_ws_method_name("config.update"), "config.patch");
    assert_eq!(
        canonicalize_ws_method_name("exec.list"),
        "exec.approvals.get"
    );
    assert_eq!(
        canonicalize_ws_method_name("exec.approvals.list"),
        "exec.approvals.get"
    );
    assert_eq!(
        canonicalize_ws_method_name("exec.approve"),
        "exec.approval.resolve"
    );
    assert_eq!(
        canonicalize_ws_method_name("exec.deny"),
        "exec.approval.resolve"
    );
    assert_eq!(
        canonicalize_ws_method_name("config.validate"),
        "config.validate"
    );
}

#[test]
fn test_get_value_at_path() {
    let root = json!({
        "gateway": {
            "port": 8080,
            "auth": {
                "mode": "token"
            }
        }
    });

    assert_eq!(get_value_at_path(&root, "gateway.port"), Some(json!(8080)));
    assert_eq!(
        get_value_at_path(&root, "gateway.auth.mode"),
        Some(json!("token"))
    );
    assert_eq!(get_value_at_path(&root, "gateway.missing"), None);
    assert_eq!(get_value_at_path(&root, "unknown"), None);
}

#[tokio::test]
async fn test_handle_node_invoke_enforces_allowlist() {
    let state = Arc::new(WsServerState::new(WsServerConfig::default()));
    let (tx, mut rx) = mpsc::unbounded_channel();
    let node_conn = ConnectionContext {
        conn_id: "conn-1".to_string(),
        role: "node".to_string(),
        scopes: vec![],
        client: ClientInfo {
            id: "node-1".to_string(),
            version: "1.0".to_string(),
            platform: "test".to_string(),
            mode: "test".to_string(),
            display_name: None,
            device_family: None,
            model_identifier: None,
            instance_id: None,
        },
        device_id: Some("node-1".to_string()),
    };
    state.register_connection(&node_conn, tx, None);
    {
        let mut registry = state.node_registry.lock();
        registry.register(NodeSession {
            node_id: "node-1".to_string(),
            conn_id: "conn-1".to_string(),
            display_name: None,
            platform: Some("test".to_string()),
            version: Some("1.0".to_string()),
            device_family: None,
            model_identifier: None,
            remote_ip: None,
            caps: vec![],
            commands: HashSet::from(["system.run".to_string()]),
            permissions: None,
            path_env: None,
            connected_at_ms: now_ms(),
        });
    }

    let outcome = state
        .node_pairing
        .request_pairing_with_status(
            "node-1".to_string(),
            None,
            vec!["system.run".to_string()],
            None,
            None,
        )
        .unwrap();
    let _ = state
        .node_pairing
        .approve_request(&outcome.request.request_id)
        .unwrap();

    let node_state = Arc::clone(&state);
    let node_conn = node_conn.clone();
    let responder = tokio::spawn(async move {
        if let Some(Message::Text(text)) = rx.recv().await {
            let value: Value = serde_json::from_str(&text).unwrap();
            let invoke_id = value
                .get("payload")
                .and_then(|v| v.get("id"))
                .and_then(|v| v.as_str())
                .unwrap()
                .to_string();
            let params = json!({
                "id": invoke_id,
                "nodeId": "node-1",
                "ok": true,
                "payload": { "ok": true }
            });
            let _ = handle_node_invoke_result(Some(&params), node_state.as_ref(), &node_conn);
        }
    });

    let ok_params = json!({
        "nodeId": "node-1",
        "command": "system.run",
        "idempotencyKey": "req-1"
    });
    assert!(handle_node_invoke(Some(&ok_params), state.as_ref())
        .await
        .is_ok());
    let _ = responder.await;

    let bad_params = json!({
        "nodeId": "node-1",
        "command": "sms.send",
        "idempotencyKey": "req-2"
    });
    let err = handle_node_invoke(Some(&bad_params), state.as_ref())
        .await
        .unwrap_err();
    assert_eq!(err.code, ERROR_INVALID_REQUEST);
}

#[tokio::test]
async fn test_handle_node_invoke_allows_unmapped_commands() {
    let state = Arc::new(WsServerState::new(WsServerConfig::default()));
    let (tx, mut rx) = mpsc::unbounded_channel();
    let node_conn = ConnectionContext {
        conn_id: "conn-2".to_string(),
        role: "node".to_string(),
        scopes: vec![],
        client: ClientInfo {
            id: "node-2".to_string(),
            version: "1.0".to_string(),
            platform: "test".to_string(),
            mode: "test".to_string(),
            display_name: None,
            device_family: None,
            model_identifier: None,
            instance_id: None,
        },
        device_id: Some("node-2".to_string()),
    };
    state.register_connection(&node_conn, tx, None);
    {
        let mut registry = state.node_registry.lock();
        registry.register(NodeSession {
            node_id: "node-2".to_string(),
            conn_id: "conn-2".to_string(),
            display_name: None,
            platform: Some("test".to_string()),
            version: Some("1.0".to_string()),
            device_family: None,
            model_identifier: None,
            remote_ip: None,
            caps: vec![],
            commands: HashSet::from(["custom.action".to_string()]),
            permissions: None,
            path_env: None,
            connected_at_ms: now_ms(),
        });
    }

    let outcome = state
        .node_pairing
        .request_pairing_with_status(
            "node-2".to_string(),
            None,
            vec!["custom.action".to_string()],
            None,
            None,
        )
        .unwrap();
    let _ = state
        .node_pairing
        .approve_request(&outcome.request.request_id)
        .unwrap();

    let node_state = Arc::clone(&state);
    let node_conn = node_conn.clone();
    let responder = tokio::spawn(async move {
        if let Some(Message::Text(text)) = rx.recv().await {
            let value: Value = serde_json::from_str(&text).unwrap();
            let invoke_id = value
                .get("payload")
                .and_then(|v| v.get("id"))
                .and_then(|v| v.as_str())
                .unwrap()
                .to_string();
            let params = json!({
                "id": invoke_id,
                "nodeId": "node-2",
                "ok": true,
                "payload": { "ok": true }
            });
            let _ = handle_node_invoke_result(Some(&params), node_state.as_ref(), &node_conn);
        }
    });

    let ok_params = json!({
        "nodeId": "node-2",
        "command": "custom.action",
        "idempotencyKey": "req-custom-1"
    });
    assert!(handle_node_invoke(Some(&ok_params), state.as_ref())
        .await
        .is_ok());
    let _ = responder.await;
}

#[tokio::test]
async fn test_handle_node_invoke_allows_missing_paired_permission_key() {
    let state = Arc::new(WsServerState::new(WsServerConfig::default()));
    let (tx, mut rx) = mpsc::unbounded_channel();
    let node_conn = ConnectionContext {
        conn_id: "conn-3".to_string(),
        role: "node".to_string(),
        scopes: vec![],
        client: ClientInfo {
            id: "node-3".to_string(),
            version: "1.0".to_string(),
            platform: "test".to_string(),
            mode: "test".to_string(),
            display_name: None,
            device_family: None,
            model_identifier: None,
            instance_id: None,
        },
        device_id: Some("node-3".to_string()),
    };
    state.register_connection(&node_conn, tx, None);
    {
        let mut registry = state.node_registry.lock();
        registry.register(NodeSession {
            node_id: "node-3".to_string(),
            conn_id: "conn-3".to_string(),
            display_name: None,
            platform: Some("test".to_string()),
            version: Some("1.0".to_string()),
            device_family: None,
            model_identifier: None,
            remote_ip: None,
            caps: vec![],
            commands: HashSet::from(["system.run".to_string()]),
            permissions: None,
            path_env: None,
            connected_at_ms: now_ms(),
        });
    }

    let builder = crate::nodes::NodePairingRequestBuilder {
        node_id: "node-3".to_string(),
        commands: vec!["system.run".to_string()],
        permissions: Some(HashMap::from([("camera".to_string(), true)])),
        ..Default::default()
    };
    let outcome = state
        .node_pairing
        .request_pairing_with_builder(builder)
        .unwrap();
    let request_id = outcome.request.request_id.clone();
    let _ = state.node_pairing.approve_request(&request_id).unwrap();

    let node_state = Arc::clone(&state);
    let node_conn = node_conn.clone();
    let responder = tokio::spawn(async move {
        if let Some(Message::Text(text)) = rx.recv().await {
            let value: Value = serde_json::from_str(&text).unwrap();
            let invoke_id = value
                .get("payload")
                .and_then(|v| v.get("id"))
                .and_then(|v| v.as_str())
                .unwrap()
                .to_string();
            let params = json!({
                "id": invoke_id,
                "nodeId": "node-3",
                "ok": true,
                "payload": { "ok": true }
            });
            let _ = handle_node_invoke_result(Some(&params), node_state.as_ref(), &node_conn);
        }
    });

    let ok_params = json!({
        "nodeId": "node-3",
        "command": "system.run",
        "idempotencyKey": "req-missing-perm-1"
    });
    assert!(handle_node_invoke(Some(&ok_params), state.as_ref())
        .await
        .is_ok());
    let _ = responder.await;
}

#[tokio::test]
async fn test_handle_node_invoke_enforces_permissions() {
    let state = Arc::new(WsServerState::new(WsServerConfig::default()));
    {
        let mut registry = state.node_registry.lock();
        let mut permissions = HashMap::new();
        permissions.insert("camera".to_string(), false);
        permissions.insert("exec".to_string(), true);
        registry.register(NodeSession {
            node_id: "node-perms".to_string(),
            conn_id: "conn-perms".to_string(),
            display_name: None,
            platform: Some("test".to_string()),
            version: Some("1.0".to_string()),
            device_family: None,
            model_identifier: None,
            remote_ip: None,
            caps: vec!["camera".to_string(), "exec".to_string()],
            commands: HashSet::from(["camera.snap".to_string(), "system.run".to_string()]),
            permissions: Some(permissions),
            path_env: None,
            connected_at_ms: now_ms(),
        });
    }

    let params = json!({
        "nodeId": "node-perms",
        "command": "camera.snap",
        "idempotencyKey": "req-perms-1"
    });
    let err = handle_node_invoke(Some(&params), state.as_ref())
        .await
        .unwrap_err();
    assert_eq!(err.code, ERROR_INVALID_REQUEST);
    assert_eq!(err.message, "node permission denied");
}

#[tokio::test]
async fn test_handle_node_invoke_enforces_caps() {
    let state = Arc::new(WsServerState::new(WsServerConfig::default()));
    {
        let mut registry = state.node_registry.lock();
        let mut permissions = HashMap::new();
        permissions.insert("camera".to_string(), true);
        registry.register(NodeSession {
            node_id: "node-caps".to_string(),
            conn_id: "conn-caps".to_string(),
            display_name: None,
            platform: Some("test".to_string()),
            version: Some("1.0".to_string()),
            device_family: None,
            model_identifier: None,
            remote_ip: None,
            caps: vec!["location".to_string()],
            commands: HashSet::from(["camera.snap".to_string()]),
            permissions: Some(permissions),
            path_env: None,
            connected_at_ms: now_ms(),
        });
    }

    let params = json!({
        "nodeId": "node-caps",
        "command": "camera.snap",
        "idempotencyKey": "req-caps-1"
    });
    let err = handle_node_invoke(Some(&params), state.as_ref())
        .await
        .unwrap_err();
    assert_eq!(err.code, ERROR_INVALID_REQUEST);
    assert_eq!(err.message, "node capability missing");
}

#[test]
fn test_normalize_platform_id() {
    assert_eq!(normalize_platform_id(Some("Darwin"), None), "macos");
    assert_eq!(normalize_platform_id(None, Some("iPhone13,3")), "ios");
    assert_eq!(normalize_platform_id(Some("android"), None), "android");
    assert_eq!(normalize_platform_id(None, None), "unknown");
}

#[test]
fn test_resolve_node_command_allowlist() {
    let allow = vec!["custom.command".to_string()];
    let deny = vec!["canvas.present".to_string()];
    let allowlist = resolve_node_command_allowlist(&allow, &deny, Some("darwin"), None);
    assert!(allowlist.contains("system.run"));
    assert!(!allowlist.contains("sms.send"));
    assert!(allowlist.contains("custom.command"));
    assert!(!allowlist.contains("canvas.present"));
}

// ============== Method Authorization Tests ==============

fn make_conn(role: &str) -> ConnectionContext {
    make_conn_with_scopes(role, vec![])
}

fn make_conn_with_scopes(role: &str, scopes: Vec<String>) -> ConnectionContext {
    ConnectionContext {
        conn_id: "test-conn".to_string(),
        role: role.to_string(),
        scopes,
        client: ClientInfo {
            id: "test-client".to_string(),
            version: "1.0".to_string(),
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

fn make_conn_with_id(role: &str, scopes: Vec<String>, conn_id: &str) -> ConnectionContext {
    ConnectionContext {
        conn_id: conn_id.to_string(),
        role: role.to_string(),
        scopes,
        client: ClientInfo {
            id: "test-client".to_string(),
            version: "1.0".to_string(),
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

#[test]
fn test_broadcast_event_scope_guard() {
    let state = WsServerState::new(WsServerConfig::default());
    let (tx_denied, mut rx_denied) = mpsc::unbounded_channel();
    let (tx_allowed, mut rx_allowed) = mpsc::unbounded_channel();
    let denied = make_conn_with_id("operator", vec![], "conn-denied");
    let allowed = make_conn_with_id(
        "operator",
        vec!["operator.pairing".to_string()],
        "conn-allowed",
    );

    state.register_connection(&denied, tx_denied, None);
    state.register_connection(&allowed, tx_allowed, None);

    // Clear presence broadcasts that are sent on connection registration
    let _ = rx_denied.try_recv();
    let _ = rx_denied.try_recv();
    let _ = rx_allowed.try_recv();
    let _ = rx_allowed.try_recv();

    broadcast_event(
        &state,
        "device.pair.requested",
        json!({ "requestId": "req-1" }),
    );

    assert!(rx_allowed.try_recv().is_ok());
    assert!(rx_denied.try_recv().is_err());
}

#[test]
fn test_role_satisfies() {
    // Any role satisfies read
    assert!(role_satisfies("read", "read"));
    assert!(role_satisfies("write", "read"));
    assert!(role_satisfies("admin", "read"));
    assert!(role_satisfies("operator", "read"));

    // Only write, admin, operator satisfy write
    assert!(!role_satisfies("read", "write"));
    assert!(role_satisfies("write", "write"));
    assert!(role_satisfies("admin", "write"));
    assert!(role_satisfies("operator", "write"));

    // Only admin satisfies admin
    assert!(!role_satisfies("read", "admin"));
    assert!(!role_satisfies("write", "admin"));
    assert!(role_satisfies("admin", "admin"));
}

#[test]
fn test_method_authorization_read_methods() {
    // Read-only methods should be allowed by any role
    let read_methods = [
        "health",
        "status",
        "config.get",
        "sessions.list",
        "channels.status",
    ];

    for method in read_methods {
        for role in ["read", "write", "admin"] {
            let conn = make_conn(role);
            let result = check_method_authorization(method, &conn);
            assert!(
                result.is_ok(),
                "Method '{}' should be allowed for role '{}'",
                method,
                role
            );
        }
    }
}

#[test]
fn test_method_authorization_write_methods() {
    // Write methods should not be allowed by read role
    let write_methods = ["config.set", "agent", "chat.send", "cron.add"];

    for method in write_methods {
        let read_conn = make_conn("read");
        let result = check_method_authorization(method, &read_conn);
        assert!(
            result.is_err(),
            "Method '{}' should NOT be allowed for role 'read'",
            method
        );

        // But allowed for write and admin
        for role in ["write", "admin"] {
            let conn = make_conn(role);
            let result = check_method_authorization(method, &conn);
            assert!(
                result.is_ok(),
                "Method '{}' should be allowed for role '{}'",
                method,
                role
            );
        }
    }
}

#[test]
fn test_method_authorization_admin_methods() {
    // Admin methods should only be allowed by admin role
    let admin_methods = [
        "device.pair.approve",
        "device.token.rotate",
        "exec.approvals.set",
        "node.pair.approve",
    ];

    for method in admin_methods {
        // Not allowed for read or write
        for role in ["read", "write"] {
            let conn = make_conn(role);
            let result = check_method_authorization(method, &conn);
            assert!(
                result.is_err(),
                "Method '{}' should NOT be allowed for role '{}'",
                method,
                role
            );
        }

        // Allowed for admin
        let admin_conn = make_conn("admin");
        let result = check_method_authorization(method, &admin_conn);
        assert!(
            result.is_ok(),
            "Method '{}' should be allowed for role 'admin'",
            method
        );
    }
}

#[test]
fn test_method_authorization_unknown_method_requires_admin() {
    // Unknown methods should require admin (fail secure)
    let conn = make_conn("write");
    let result = check_method_authorization("unknown.method.xyz", &conn);
    assert!(result.is_err(), "Unknown method should require admin role");

    let admin_conn = make_conn("admin");
    let result = check_method_authorization("unknown.method.xyz", &admin_conn);
    assert!(result.is_ok(), "Unknown method should be allowed for admin");
}

#[test]
fn test_method_authorization_error_contains_details() {
    let conn = make_conn("read");
    let result = check_method_authorization("config.set", &conn);

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(err.code, "INVALID_REQUEST");
    assert!(err.message.contains("config.set"));
    assert!(err.message.contains("write"));
    assert!(err.message.contains("read"));
}

// ============== Node Role Allowlist Tests ==============

#[test]
fn test_node_role_only_allows_specific_methods() {
    let conn = make_conn("node");

    // Allowed methods for node role
    for method in NODE_ONLY_METHODS {
        let result = check_method_authorization(method, &conn);
        assert!(
            result.is_ok(),
            "Method '{}' should be allowed for node role",
            method
        );
    }

    // Read methods should NOT be allowed for node role
    let blocked_methods = ["health", "status", "config.get", "sessions.list"];
    for method in blocked_methods {
        let result = check_method_authorization(method, &conn);
        assert!(
            result.is_err(),
            "Method '{}' should NOT be allowed for node role",
            method
        );
    }
}

// ============== Operator Scope Tests ==============

#[test]
fn test_operator_without_scopes_cannot_write() {
    // Operator with no scopes should not be able to call write methods
    let conn = make_conn_with_scopes("operator", vec![]);

    let result = check_method_authorization("config.set", &conn);
    assert!(
        result.is_err(),
        "Operator without scopes should not be able to write"
    );
}

#[test]
fn test_operator_with_write_scope_can_write() {
    let conn = make_conn_with_scopes("operator", vec!["operator.write".to_string()]);

    // config.set requires operator.admin (it's in OPERATOR_ADMIN_REQUIRED_METHODS)
    let result = check_method_authorization("config.set", &conn);
    assert!(
        result.is_err(),
        "config.set requires operator.admin, not just write scope"
    );

    // sessions.patch also requires operator.admin
    let result = check_method_authorization("sessions.patch", &conn);
    assert!(
        result.is_err(),
        "sessions.patch requires operator.admin, not just write scope"
    );

    // agent/chat are write-level methods that DO work with operator.write
    let result = check_method_authorization("agent", &conn);
    assert!(
        result.is_ok(),
        "agent is a write-level method that works with operator.write"
    );

    let result = check_method_authorization("chat.send", &conn);
    assert!(
        result.is_ok(),
        "chat.send is a write-level method that works with operator.write"
    );
}

#[test]
fn test_operator_with_read_scope_can_read() {
    let conn = make_conn_with_scopes("operator", vec!["operator.read".to_string()]);

    // Read methods should work
    let result = check_method_authorization("health", &conn);
    assert!(
        result.is_ok(),
        "Operator with read scope should be able to read"
    );

    // Write methods should not work
    let result = check_method_authorization("config.set", &conn);
    assert!(
        result.is_err(),
        "Operator with only read scope should not be able to write"
    );
}

#[test]
fn test_operator_needs_pairing_scope_for_pairing() {
    // Per Node.js gateway: operator.pairing allows pairing methods WITHOUT needing operator.admin
    // This enables granular access control where operators can be granted just pairing rights

    // Operator with admin scope - can pair (admin covers all)
    let conn = make_conn_with_scopes("operator", vec!["operator.admin".to_string()]);
    let result = check_method_authorization("device.pair.approve", &conn);
    assert!(
        result.is_ok(),
        "Operator with admin scope should be able to pair"
    );

    // Operator with only write scope - cannot pair (needs pairing or admin)
    let conn_write = make_conn_with_scopes("operator", vec!["operator.write".to_string()]);
    let result = check_method_authorization("device.pair.approve", &conn_write);
    assert!(
        result.is_err(),
        "Operator with only write scope should not be able to pair"
    );

    // Operator with just pairing scope - CAN pair (per Node.js gateway)
    let conn_pairing = make_conn_with_scopes("operator", vec!["operator.pairing".to_string()]);
    let result = check_method_authorization("device.pair.approve", &conn_pairing);
    assert!(
        result.is_ok(),
        "Operator with pairing scope should be able to pair (Node.js parity)"
    );

    // Operator with read scope only - cannot pair
    let conn_read = make_conn_with_scopes("operator", vec!["operator.read".to_string()]);
    let result = check_method_authorization("device.pair.approve", &conn_read);
    assert!(
        result.is_err(),
        "Operator with only read scope should not be able to pair"
    );
}

#[test]
fn test_operator_needs_approvals_scope_for_exec_approvals() {
    // Per Node.js gateway: operator.approvals allows exec approval methods WITHOUT needing operator.admin

    let conn = make_conn_with_scopes("operator", vec!["operator.write".to_string()]);
    let result = check_method_authorization("exec.approvals.set", &conn);
    assert!(
        result.is_err(),
        "Operator without approvals scope should not set approvals"
    );

    // Admin scope covers all
    let conn_admin = make_conn_with_scopes("operator", vec!["operator.admin".to_string()]);
    let result = check_method_authorization("exec.approvals.set", &conn_admin);
    assert!(
        result.is_ok(),
        "Operator with admin scope should set approvals"
    );

    // Approvals scope alone allows exec approval methods (per Node.js gateway)
    let conn_approvals = make_conn_with_scopes("operator", vec!["operator.approvals".to_string()]);
    let result = check_method_authorization("exec.approvals.set", &conn_approvals);
    assert!(
        result.is_ok(),
        "Operator with approvals scope should set approvals (Node.js parity)"
    );
}

#[test]
fn test_operator_wildcard_scope() {
    let conn = make_conn_with_scopes("operator", vec!["operator.*".to_string()]);

    // Wildcard should cover all operations (covers operator.admin, operator.pairing, etc.)
    assert!(
        check_method_authorization("config.set", &conn).is_ok(),
        "wildcard covers operator.admin for config.set"
    );
    assert!(
        check_method_authorization("device.pair.approve", &conn).is_ok(),
        "wildcard covers operator.pairing"
    );
    assert!(
        check_method_authorization("exec.approvals.set", &conn).is_ok(),
        "wildcard covers operator.approvals"
    );
    assert!(
        check_method_authorization("agent", &conn).is_ok(),
        "wildcard covers operator.write"
    );
    assert!(
        check_method_authorization("health", &conn).is_ok(),
        "wildcard covers operator.read"
    );
}

#[test]
fn test_scope_satisfies() {
    // Exact match
    assert!(scope_satisfies(
        &["operator.write".to_string()],
        "operator.write"
    ));
    assert!(!scope_satisfies(
        &["operator.read".to_string()],
        "operator.write"
    ));

    // Wildcard
    assert!(scope_satisfies(
        &["operator.*".to_string()],
        "operator.pairing"
    ));
    assert!(scope_satisfies(
        &["operator.*".to_string()],
        "operator.admin"
    ));

    // Admin covers all
    assert!(scope_satisfies(
        &["operator.admin".to_string()],
        "operator.pairing"
    ));
    assert!(scope_satisfies(
        &["operator.admin".to_string()],
        "operator.approvals"
    ));

    // Write covers read
    assert!(scope_satisfies(
        &["operator.write".to_string()],
        "operator.read"
    ));
}

// ============== Node Pairing Handler Tests ==============

#[test]
fn test_handle_node_pair_request() {
    let state = WsServerState::new(WsServerConfig::default());

    let params = json!({
        "nodeId": "test-node-1",
        "displayName": "Test Node",
        "platform": "darwin",
        "commands": ["system.run", "camera.snap"]
    });

    let result = handle_node_pair_request(Some(&params), &state);
    assert!(result.is_ok());

    let response = result.unwrap();
    assert_eq!(response["status"], "pending");
    assert_eq!(response["created"], true);
    assert_eq!(response["request"]["nodeId"], "test-node-1");
    assert!(response["request"]["requestId"].as_str().is_some());
}

#[test]
fn test_handle_node_pair_request_requires_node_id() {
    let state = WsServerState::new(WsServerConfig::default());

    let params = json!({
        "displayName": "Test Node"
    });

    let result = handle_node_pair_request(Some(&params), &state);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code, ERROR_INVALID_REQUEST);
}

#[test]
fn test_handle_node_pair_list() {
    let state = WsServerState::new(WsServerConfig::default());

    // Create a pairing request
    let params = json!({
        "nodeId": "test-node-1",
        "displayName": "Test Node"
    });
    handle_node_pair_request(Some(&params), &state).unwrap();

    // List should show the pending request
    let result = handle_node_pair_list(&state);
    assert!(result.is_ok());

    let response = result.unwrap();
    assert_eq!(response["paired"].as_array().unwrap().len(), 0);
    assert_eq!(response["pending"].as_array().unwrap().len(), 1);
    assert_eq!(response["pending"][0]["nodeId"], "test-node-1");
}

#[test]
fn test_handle_node_pair_approve_and_verify() {
    let state = WsServerState::new(WsServerConfig::default());

    // Create a pairing request
    let request_params = json!({
        "nodeId": "test-node-1",
        "displayName": "Test Node"
    });
    let request_response = handle_node_pair_request(Some(&request_params), &state).unwrap();
    let request_id = request_response["request"]["requestId"].as_str().unwrap();

    // Approve the request
    let approve_params = json!({ "requestId": request_id });
    let approve_result = handle_node_pair_approve(Some(&approve_params), &state);
    assert!(approve_result.is_ok());

    let approve_response = approve_result.unwrap();
    assert_eq!(approve_response["requestId"], request_id);
    assert_eq!(approve_response["node"]["nodeId"], "test-node-1");
    let token = approve_response["node"]["token"].as_str().unwrap();
    assert!(!token.is_empty());

    // Verify the token
    let verify_params = json!({
        "nodeId": "test-node-1",
        "token": token
    });
    let verify_result = handle_node_pair_verify(Some(&verify_params), &state);
    assert!(verify_result.is_ok());
    assert_eq!(verify_result.unwrap()["ok"], true);
}

#[test]
fn test_handle_node_pair_reject() {
    let state = WsServerState::new(WsServerConfig::default());

    // Create a pairing request
    let request_params = json!({
        "nodeId": "test-node-1"
    });
    let request_response = handle_node_pair_request(Some(&request_params), &state).unwrap();
    let request_id = request_response["request"]["requestId"].as_str().unwrap();

    // Reject the request
    let reject_params = json!({
        "requestId": request_id,
        "reason": "Not authorized"
    });
    let reject_result = handle_node_pair_reject(Some(&reject_params), &state);
    assert!(reject_result.is_ok());

    let reject_response = reject_result.unwrap();
    assert_eq!(reject_response["requestId"], request_id);
    assert_eq!(reject_response["nodeId"], "test-node-1");

    // Node should not be paired
    assert!(!state.node_pairing.is_paired("test-node-1"));
}

#[test]
fn test_handle_node_pair_verify_requires_pairing() {
    let state = WsServerState::new(WsServerConfig::default());

    // Try to verify without pairing
    let verify_params = json!({
        "nodeId": "unpaired-node",
        "token": "some-token"
    });
    let verify_result = handle_node_pair_verify(Some(&verify_params), &state);
    assert!(verify_result.is_ok());
    assert_eq!(verify_result.unwrap()["ok"], false);
}

#[test]
fn test_handle_node_list() {
    let state = WsServerState::new(WsServerConfig::default());

    // Initially empty
    let result = handle_node_list(&state);
    assert!(result.is_ok());
    assert_eq!(result.unwrap()["nodes"].as_array().unwrap().len(), 0);

    // Pair a node
    let request_params = json!({
        "nodeId": "test-node-1",
        "displayName": "Test Node",
        "platform": "darwin"
    });
    let request_response = handle_node_pair_request(Some(&request_params), &state).unwrap();
    let request_id = request_response["request"]["requestId"].as_str().unwrap();
    handle_node_pair_approve(Some(&json!({ "requestId": request_id })), &state).unwrap();

    // Should now have one node
    let result = handle_node_list(&state);
    assert!(result.is_ok());
    let binding = result.unwrap();
    let nodes = binding["nodes"].as_array().unwrap();
    assert_eq!(nodes.len(), 1);
    assert_eq!(nodes[0]["nodeId"], "test-node-1");
    assert_eq!(nodes[0]["displayName"], "Test Node");
    assert_eq!(nodes[0]["platform"], "darwin");
    assert_eq!(nodes[0]["paired"], true);
    assert_eq!(nodes[0]["connected"], false);
}

#[test]
fn test_handle_node_rename() {
    let state = WsServerState::new(WsServerConfig::default());

    // Pair a node
    let request_params = json!({
        "nodeId": "test-node-1",
        "displayName": "Old Name"
    });
    let request_response = handle_node_pair_request(Some(&request_params), &state).unwrap();
    let request_id = request_response["request"]["requestId"].as_str().unwrap();
    handle_node_pair_approve(Some(&json!({ "requestId": request_id })), &state).unwrap();

    // Rename the node
    let rename_params = json!({
        "nodeId": "test-node-1",
        "name": "New Name"
    });
    let result = handle_node_rename(Some(&rename_params), &state);
    assert!(result.is_ok());
    assert_eq!(result.unwrap()["name"], "New Name");

    // Verify the name changed
    let node = state.node_pairing.get_paired_node("test-node-1").unwrap();
    assert_eq!(node.display_name, Some("New Name".to_string()));
}

#[test]
fn test_handle_node_describe() {
    let state = WsServerState::new(WsServerConfig::default());

    // Pair a node
    let request_params = json!({
        "nodeId": "test-node-1",
        "displayName": "Test Node",
        "platform": "darwin",
        "commands": ["system.run"]
    });
    let request_response = handle_node_pair_request(Some(&request_params), &state).unwrap();
    let request_id = request_response["request"]["requestId"].as_str().unwrap();
    handle_node_pair_approve(Some(&json!({ "requestId": request_id })), &state).unwrap();

    // Describe the node
    let describe_params = json!({ "nodeId": "test-node-1" });
    let result = handle_node_describe(Some(&describe_params), &state);
    assert!(result.is_ok());

    let response = result.unwrap();
    assert_eq!(response["nodeId"], "test-node-1");
    assert_eq!(response["displayName"], "Test Node");
    assert_eq!(response["platform"], "darwin");
    assert_eq!(
        response["commands"].as_array().unwrap(),
        &vec![json!("system.run")]
    );
    assert_eq!(response["paired"], true);
    assert_eq!(response["connected"], false);
}

#[test]
fn test_handle_node_describe_requires_pairing() {
    let state = WsServerState::new(WsServerConfig::default());

    let describe_params = json!({ "nodeId": "unpaired-node" });
    let result = handle_node_describe(Some(&describe_params), &state);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code, ERROR_INVALID_REQUEST);
}

#[test]
fn test_handle_node_pair_request_with_extended_fields() {
    let state = WsServerState::new(WsServerConfig::default());

    let params = json!({
        "nodeId": "test-node-extended",
        "displayName": "Extended Node",
        "platform": "ios",
        "version": "2.0.0",
        "coreVersion": "1.5.0",
        "uiVersion": "2.0.0-beta",
        "deviceFamily": "iPhone",
        "modelIdentifier": "iPhone14,2",
        "caps": ["audio", "camera", "location"],
        "commands": ["system.run", "camera.snap"],
        "permissions": { "camera": true, "location": false },
        "remoteIp": "192.168.1.100",
        "silent": true
    });

    let result = handle_node_pair_request(Some(&params), &state);
    assert!(result.is_ok());

    let response = result.unwrap();
    assert_eq!(response["status"], "pending");
    assert_eq!(response["created"], true);

    let request = &response["request"];
    assert_eq!(request["nodeId"], "test-node-extended");
    assert_eq!(request["displayName"], "Extended Node");
    assert_eq!(request["platform"], "ios");
    assert_eq!(request["version"], "2.0.0");
    assert_eq!(request["coreVersion"], "1.5.0");
    assert_eq!(request["uiVersion"], "2.0.0-beta");
    assert_eq!(request["deviceFamily"], "iPhone");
    assert_eq!(request["modelIdentifier"], "iPhone14,2");
    assert_eq!(request["caps"], json!(["audio", "camera", "location"]));
    assert_eq!(request["commands"], json!(["system.run", "camera.snap"]));
    assert_eq!(
        request["permissions"],
        json!({ "camera": true, "location": false })
    );
    assert_eq!(request["remoteIp"], "192.168.1.100");
    assert_eq!(request["silent"], true);
    assert_eq!(request["isRepair"], false);
}

#[test]
fn test_handle_node_pair_approve_preserves_extended_fields() {
    let state = WsServerState::new(WsServerConfig::default());

    // Create request with extended fields
    let request_params = json!({
        "nodeId": "test-node-extended-approve",
        "displayName": "Extended Approve Node",
        "platform": "darwin",
        "version": "3.0.0",
        "coreVersion": "2.5.0",
        "uiVersion": "3.0.0",
        "deviceFamily": "Mac",
        "modelIdentifier": "MacBookPro18,3",
        "caps": ["exec", "filesystem"],
        "commands": ["system.run", "file.read"],
        "permissions": { "filesystem": true },
        "remoteIp": "10.0.0.50"
    });
    let request_response = handle_node_pair_request(Some(&request_params), &state).unwrap();
    let request_id = request_response["request"]["requestId"].as_str().unwrap();

    // Approve the request
    let approve_params = json!({ "requestId": request_id });
    let approve_result = handle_node_pair_approve(Some(&approve_params), &state);
    assert!(approve_result.is_ok());

    let node = &approve_result.unwrap()["node"];
    assert_eq!(node["nodeId"], "test-node-extended-approve");
    assert_eq!(node["displayName"], "Extended Approve Node");
    assert_eq!(node["platform"], "darwin");
    assert_eq!(node["version"], "3.0.0");
    assert_eq!(node["coreVersion"], "2.5.0");
    assert_eq!(node["uiVersion"], "3.0.0");
    assert_eq!(node["deviceFamily"], "Mac");
    assert_eq!(node["modelIdentifier"], "MacBookPro18,3");
    assert_eq!(node["caps"], json!(["exec", "filesystem"]));
    assert_eq!(node["permissions"], json!({ "filesystem": true }));
    assert_eq!(node["remoteIp"], "10.0.0.50");
    assert!(node["createdAtMs"].as_u64().is_some());
    assert!(node["approvedAtMs"].as_u64().is_some());
}

#[test]
fn test_handle_node_list_includes_extended_fields() {
    let state = WsServerState::new(WsServerConfig::default());

    // Pair a node with extended fields
    let request_params = json!({
        "nodeId": "test-node-list-extended",
        "displayName": "List Extended Node",
        "platform": "ios",
        "version": "4.0.0",
        "coreVersion": "3.0.0",
        "uiVersion": "4.0.0",
        "deviceFamily": "iPad",
        "modelIdentifier": "iPad13,8",
        "caps": ["audio", "video"],
        "commands": ["media.play"],
        "permissions": { "audio": true },
        "remoteIp": "172.16.0.1"
    });
    let request_response = handle_node_pair_request(Some(&request_params), &state).unwrap();
    let request_id = request_response["request"]["requestId"].as_str().unwrap();
    handle_node_pair_approve(Some(&json!({ "requestId": request_id })), &state).unwrap();

    // List nodes should include extended fields
    let result = handle_node_list(&state);
    assert!(result.is_ok());

    let result_value = result.unwrap();
    let nodes = result_value["nodes"].as_array().unwrap();
    assert_eq!(nodes.len(), 1);

    let node = &nodes[0];
    assert_eq!(node["nodeId"], "test-node-list-extended");
    assert_eq!(node["platform"], "ios");
    assert_eq!(node["version"], "4.0.0");
    assert_eq!(node["coreVersion"], "3.0.0");
    assert_eq!(node["uiVersion"], "4.0.0");
    assert_eq!(node["deviceFamily"], "iPad");
    assert_eq!(node["modelIdentifier"], "iPad13,8");
    assert_eq!(node["remoteIp"], "172.16.0.1");
    assert_eq!(node["paired"], true);
}

#[test]
fn test_handle_node_describe_includes_extended_fields() {
    let state = WsServerState::new(WsServerConfig::default());

    // Pair a node with extended fields
    let request_params = json!({
        "nodeId": "test-node-describe-extended",
        "displayName": "Describe Extended Node",
        "platform": "android",
        "version": "5.0.0",
        "coreVersion": "4.0.0",
        "uiVersion": "5.0.0",
        "deviceFamily": "Pixel",
        "modelIdentifier": "Pixel 7 Pro",
        "caps": ["notification", "sms"],
        "commands": ["notification.send"],
        "permissions": { "notification": true, "sms": false },
        "remoteIp": "192.168.0.200"
    });
    let request_response = handle_node_pair_request(Some(&request_params), &state).unwrap();
    let request_id = request_response["request"]["requestId"].as_str().unwrap();
    handle_node_pair_approve(Some(&json!({ "requestId": request_id })), &state).unwrap();

    // Describe should include extended fields
    let describe_params = json!({ "nodeId": "test-node-describe-extended" });
    let result = handle_node_describe(Some(&describe_params), &state);
    assert!(result.is_ok());

    let node = result.unwrap();
    assert_eq!(node["nodeId"], "test-node-describe-extended");
    assert_eq!(node["platform"], "android");
    assert_eq!(node["version"], "5.0.0");
    assert_eq!(node["coreVersion"], "4.0.0");
    assert_eq!(node["uiVersion"], "5.0.0");
    assert_eq!(node["deviceFamily"], "Pixel");
    assert_eq!(node["modelIdentifier"], "Pixel 7 Pro");
    assert_eq!(node["remoteIp"], "192.168.0.200");
    assert_eq!(node["paired"], true);
    // caps and commands are merged from paired, should be sorted
    assert!(node["caps"].as_array().is_some());
    assert!(node["commands"].as_array().is_some());
}

#[test]
fn test_handle_node_pair_request_is_repair_flag() {
    let state = WsServerState::new(WsServerConfig::default());

    // First pairing - should not be a repair
    let params1 = json!({
        "nodeId": "test-node-repair",
        "displayName": "Repair Test Node"
    });
    let result1 = handle_node_pair_request(Some(&params1), &state).unwrap();
    assert_eq!(result1["request"]["isRepair"], false);

    // Approve the first request
    let request_id = result1["request"]["requestId"].as_str().unwrap();
    handle_node_pair_approve(Some(&json!({ "requestId": request_id })), &state).unwrap();

    // Second pairing request - should be a repair since node is already paired
    let params2 = json!({
        "nodeId": "test-node-repair",
        "displayName": "Repair Test Node Updated"
    });
    let result2 = handle_node_pair_request(Some(&params2), &state).unwrap();
    assert_eq!(result2["request"]["isRepair"], true);
}

#[test]
fn test_handle_node_pair_verify_includes_extended_fields() {
    let state = WsServerState::new(WsServerConfig::default());

    // Create and approve request with extended fields
    let request_params = json!({
        "nodeId": "test-node-verify-extended",
        "displayName": "Verify Extended Node",
        "platform": "linux",
        "version": "1.0.0",
        "coreVersion": "1.0.0",
        "deviceFamily": "Server",
        "caps": ["exec"],
        "commands": ["system.run"]
    });
    let request_response = handle_node_pair_request(Some(&request_params), &state).unwrap();
    let request_id = request_response["request"]["requestId"].as_str().unwrap();
    let approve_response =
        handle_node_pair_approve(Some(&json!({ "requestId": request_id })), &state).unwrap();
    let token = approve_response["node"]["token"].as_str().unwrap();

    // Verify should include extended fields in the node response
    let verify_params = json!({
        "nodeId": "test-node-verify-extended",
        "token": token
    });
    let result = handle_node_pair_verify(Some(&verify_params), &state);
    assert!(result.is_ok());

    let response = result.unwrap();
    assert_eq!(response["ok"], true);
    let node = &response["node"];
    assert_eq!(node["nodeId"], "test-node-verify-extended");
    assert_eq!(node["platform"], "linux");
    assert_eq!(node["version"], "1.0.0");
    assert_eq!(node["coreVersion"], "1.0.0");
    assert_eq!(node["deviceFamily"], "Server");
}

// ============== Event System Tests ==============

#[test]
fn test_state_version_tracking() {
    let state = WsServerState::new(WsServerConfig::default());

    // Initial state version should be 0,0
    let version = state.current_state_version();
    assert_eq!(version.presence, 0);
    assert_eq!(version.health, 0);

    // Create a connection to trigger presence update
    let (tx, _rx) = mpsc::unbounded_channel();
    let conn = make_conn_with_id("operator", vec![], "conn-1");
    state.register_connection(&conn, tx, None);

    // Presence version should be incremented
    let version = state.current_state_version();
    assert_eq!(version.presence, 1);
    assert_eq!(version.health, 0);

    // Unregister should also increment presence version
    state.unregister_connection("conn-1");
    let version = state.current_state_version();
    assert_eq!(version.presence, 2);
    assert_eq!(version.health, 0);
}

#[test]
fn test_presence_tracking() {
    let state = WsServerState::new(WsServerConfig::default());

    // Initially empty
    let presence = state.get_presence_list();
    assert!(presence.is_empty());

    // Register a connection
    let (tx, _rx) = mpsc::unbounded_channel();
    let conn = ConnectionContext {
        conn_id: "conn-1".to_string(),
        role: "operator".to_string(),
        scopes: vec!["operator.admin".to_string()],
        client: ClientInfo {
            id: "test-client".to_string(),
            version: "1.0.0".to_string(),
            platform: "darwin".to_string(),
            mode: "ui".to_string(),
            display_name: Some("Test Mac".to_string()),
            device_family: Some("MacBookPro".to_string()),
            model_identifier: Some("Mac14,5".to_string()),
            instance_id: Some("inst-1".to_string()),
        },
        device_id: Some("device-1".to_string()),
    };
    state.register_connection(&conn, tx, Some("192.168.1.100".to_string()));

    // Should now have one presence entry
    let presence = state.get_presence_list();
    assert_eq!(presence.len(), 1);

    let entry = &presence[0];
    assert_eq!(entry["host"], "Test Mac");
    assert_eq!(entry["ip"], "192.168.1.100");
    assert_eq!(entry["version"], "1.0.0");
    assert_eq!(entry["platform"], "darwin");
    assert_eq!(entry["mode"], "ui");
    assert_eq!(entry["deviceFamily"], "MacBookPro");
    assert_eq!(entry["modelIdentifier"], "Mac14,5");
    assert_eq!(entry["deviceId"], "device-1");
    assert_eq!(entry["reason"], "connect");
    assert_eq!(entry["roles"], json!(["operator"]));
    assert_eq!(entry["scopes"], json!(["operator.admin"]));
    assert_eq!(entry["instanceId"], "inst-1");
    // connId and clientId are internal fields, not serialized per Node schema
    assert!(entry.get("connId").is_none() || entry["connId"].is_null());
    assert!(entry.get("clientId").is_none() || entry["clientId"].is_null());

    // Unregister should remove presence
    state.unregister_connection("conn-1");
    let presence = state.get_presence_list();
    assert!(presence.is_empty());
}

#[test]
fn test_health_snapshot_cache() {
    let state = WsServerState::new(WsServerConfig::default());

    // Initial health should be "healthy"
    let health = state.get_health_snapshot();
    assert_eq!(health.status, "healthy");
    assert!(health.ts > 0);

    // Update health
    state.update_health("degraded", Some(json!({"whatsapp": "disconnected"})), None);

    let health = state.get_health_snapshot();
    assert_eq!(health.status, "degraded");
    assert_eq!(health.channels, Some(json!({"whatsapp": "disconnected"})));

    // State version should be incremented for health
    let version = state.current_state_version();
    assert_eq!(version.health, 1);
}

#[test]
fn test_presence_broadcast_on_connect() {
    let state = WsServerState::new(WsServerConfig::default());

    // Register first connection (will receive broadcasts)
    let (tx1, mut rx1) = mpsc::unbounded_channel();
    let conn1 = make_conn_with_id("operator", vec!["operator.admin".to_string()], "conn-1");
    state.register_connection(&conn1, tx1, None);

    // First connection should receive presence update about itself
    let msg = rx1.try_recv();
    assert!(msg.is_ok());
    let Message::Text(text) = msg.unwrap() else {
        panic!("expected text message");
    };
    let event: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(event["type"], "event");
    assert_eq!(event["event"], "presence");
    assert!(event["seq"].as_u64().is_some());
    assert!(event["stateVersion"]["presence"].as_u64().unwrap() >= 1);
    assert!(!event["payload"]["presence"].as_array().unwrap().is_empty());

    // Register second connection
    let (tx2, _rx2) = mpsc::unbounded_channel();
    let conn2 = make_conn_with_id("operator", vec![], "conn-2");
    state.register_connection(&conn2, tx2, None);

    // First connection should receive another presence update
    let msg = rx1.try_recv();
    assert!(msg.is_ok());
    let Message::Text(text) = msg.unwrap() else {
        panic!("expected text message");
    };
    let event: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(event["event"], "presence");
    assert_eq!(event["payload"]["presence"].as_array().unwrap().len(), 2);
}

#[test]
fn test_presence_broadcast_excludes_nodes() {
    let state = WsServerState::new(WsServerConfig::default());

    // Register a node connection
    let (tx_node, mut rx_node) = mpsc::unbounded_channel();
    let node_conn = make_conn_with_id("node", vec![], "node-conn");
    state.register_connection(&node_conn, tx_node, None);

    // Node should not receive presence broadcast
    let msg = rx_node.try_recv();
    assert!(msg.is_err(), "Node should not receive presence broadcasts");

    // Register an operator
    let (tx_op, mut rx_op) = mpsc::unbounded_channel();
    let op_conn = make_conn_with_id("operator", vec![], "op-conn");
    state.register_connection(&op_conn, tx_op, None);

    // Operator should receive presence broadcast
    let msg = rx_op.try_recv();
    assert!(msg.is_ok(), "Operator should receive presence broadcasts");

    // Node still should not have received anything
    let msg = rx_node.try_recv();
    assert!(msg.is_err(), "Node should not receive presence broadcasts");
}

#[test]
fn test_broadcast_agent_event() {
    let state = WsServerState::new(WsServerConfig::default());

    let (tx, mut rx) = mpsc::unbounded_channel();
    let conn = make_conn_with_id("operator", vec![], "conn-1");
    state.register_connection(&conn, tx, None);

    // Clear the presence broadcast
    let _ = rx.try_recv();

    // Broadcast an agent event
    broadcast_agent_event(&state, "run-123", 1, "text", json!({"text": "Hello!"}));

    let msg = rx.try_recv();
    assert!(msg.is_ok());
    let Message::Text(text) = msg.unwrap() else {
        panic!("expected text message");
    };
    let event: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(event["type"], "event");
    assert_eq!(event["event"], "agent");
    assert_eq!(event["payload"]["runId"], "run-123");
    assert_eq!(event["payload"]["seq"], 1);
    assert_eq!(event["payload"]["stream"], "text");
    assert_eq!(event["payload"]["data"]["text"], "Hello!");
    assert!(event["payload"]["ts"].as_u64().is_some());
}

#[test]
fn test_broadcast_chat_event() {
    let state = WsServerState::new(WsServerConfig::default());

    let (tx, mut rx) = mpsc::unbounded_channel();
    let conn = make_conn_with_id("operator", vec![], "conn-1");
    state.register_connection(&conn, tx, None);

    // Clear the presence broadcast
    let _ = rx.try_recv();

    // Broadcast a chat event
    broadcast_chat_event(
        &state,
        "msg-123",
        "main",
        5,
        "final",
        Some(json!({"role": "assistant", "content": "Hello!"})),
        None,
        Some(json!({"input": 10, "output": 20})),
        Some("end_turn"),
    );

    let msg = rx.try_recv();
    assert!(msg.is_ok());
    let Message::Text(text) = msg.unwrap() else {
        panic!("expected text message");
    };
    let event: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(event["event"], "chat");
    assert_eq!(event["payload"]["runId"], "msg-123");
    assert_eq!(event["payload"]["sessionKey"], "main");
    assert_eq!(event["payload"]["seq"], 5);
    assert_eq!(event["payload"]["state"], "final");
    assert_eq!(event["payload"]["message"]["role"], "assistant");
    assert_eq!(event["payload"]["usage"]["input"], 10);
    assert_eq!(event["payload"]["stopReason"], "end_turn");
}

#[test]
fn test_broadcast_cron_event() {
    let state = WsServerState::new(WsServerConfig::default());

    let (tx, mut rx) = mpsc::unbounded_channel();
    let conn = make_conn_with_id("operator", vec![], "conn-1");
    state.register_connection(&conn, tx, None);

    // Clear the presence broadcast
    let _ = rx.try_recv();

    // Broadcast a cron event
    broadcast_cron_event(
        &state,
        "job-1",
        "completed",
        Some("run-456"),
        Some(json!({"ok": true})),
    );

    let msg = rx.try_recv();
    assert!(msg.is_ok());
    let Message::Text(text) = msg.unwrap() else {
        panic!("expected text message");
    };
    let event: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(event["event"], "cron");
    assert_eq!(event["payload"]["jobId"], "job-1");
    assert_eq!(event["payload"]["status"], "completed");
    assert_eq!(event["payload"]["runId"], "run-456");
    assert_eq!(event["payload"]["result"]["ok"], true);
}

#[test]
fn test_broadcast_voicewake_changed() {
    let state = WsServerState::new(WsServerConfig::default());

    // voicewake.changed should go to both operators AND nodes
    let (tx_op, mut rx_op) = mpsc::unbounded_channel();
    let op_conn = make_conn_with_id("operator", vec![], "op-conn");
    state.register_connection(&op_conn, tx_op, None);

    let (tx_node, mut rx_node) = mpsc::unbounded_channel();
    let node_conn = make_conn_with_id("node", vec![], "node-conn");
    state.register_connection(&node_conn, tx_node, None);

    // Clear presence broadcasts for operator
    let _ = rx_op.try_recv();
    let _ = rx_op.try_recv();

    // Broadcast voicewake change
    broadcast_voicewake_changed(
        &state,
        vec!["hey claude".to_string(), "ok claude".to_string()],
    );

    // Operator should receive it
    let msg = rx_op.try_recv();
    assert!(msg.is_ok());
    let Message::Text(text) = msg.unwrap() else {
        panic!("expected text message");
    };
    let event: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(event["event"], "voicewake.changed");
    assert_eq!(
        event["payload"]["triggers"],
        json!(["hey claude", "ok claude"])
    );

    // Node should also receive it
    let msg = rx_node.try_recv();
    assert!(msg.is_ok());
    let Message::Text(text) = msg.unwrap() else {
        panic!("expected text message");
    };
    let event: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(event["event"], "voicewake.changed");
}

#[test]
fn test_broadcast_exec_approval_events() {
    let state = WsServerState::new(WsServerConfig::default());

    // Create connection with approvals scope
    let (tx_with_scope, mut rx_with_scope) = mpsc::unbounded_channel();
    let conn_with_scope = make_conn_with_id(
        "operator",
        vec!["operator.approvals".to_string()],
        "conn-with-scope",
    );
    state.register_connection(&conn_with_scope, tx_with_scope, None);

    // Create connection without approvals scope
    let (tx_without_scope, mut rx_without_scope) = mpsc::unbounded_channel();
    let conn_without_scope = make_conn_with_id("operator", vec![], "conn-without-scope");
    state.register_connection(&conn_without_scope, tx_without_scope, None);

    // Clear presence broadcasts
    let _ = rx_with_scope.try_recv();
    let _ = rx_with_scope.try_recv();
    let _ = rx_without_scope.try_recv();
    let _ = rx_without_scope.try_recv();

    // Broadcast exec approval requested
    broadcast_exec_approval_requested(
        &state,
        "req-1",
        "rm",
        vec!["-rf".to_string(), "/tmp/test".to_string()],
        Some("/home/user"),
        Some("agent-1"),
        Some("main"),
    );

    // Connection with scope should receive it
    let msg = rx_with_scope.try_recv();
    assert!(msg.is_ok());
    let Message::Text(text) = msg.unwrap() else {
        panic!("expected text message");
    };
    let event: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(event["event"], "exec.approval.requested");
    assert_eq!(event["payload"]["requestId"], "req-1");
    assert_eq!(event["payload"]["command"], "rm");
    assert_eq!(event["payload"]["args"], json!(["-rf", "/tmp/test"]));
    assert_eq!(event["payload"]["cwd"], "/home/user");
    assert_eq!(event["payload"]["agentId"], "agent-1");
    assert_eq!(event["payload"]["sessionKey"], "main");

    // Connection without scope should NOT receive it
    let msg = rx_without_scope.try_recv();
    assert!(
        msg.is_err(),
        "Connection without scope should not receive exec.approval events"
    );

    // Broadcast exec approval resolved
    broadcast_exec_approval_resolved(&state, "req-1", "approved");

    // Connection with scope should receive it
    let msg = rx_with_scope.try_recv();
    assert!(msg.is_ok());
    let Message::Text(text) = msg.unwrap() else {
        panic!("expected text message");
    };
    let event: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(event["event"], "exec.approval.resolved");
    assert_eq!(event["payload"]["requestId"], "req-1");
    assert_eq!(event["payload"]["decision"], "approved");

    // Connection without scope should NOT receive it
    let msg = rx_without_scope.try_recv();
    assert!(msg.is_err());
}

#[test]
fn test_broadcast_shutdown() {
    let state = WsServerState::new(WsServerConfig::default());

    // Shutdown goes to ALL connections including nodes
    let (tx_op, mut rx_op) = mpsc::unbounded_channel();
    let op_conn = make_conn_with_id("operator", vec![], "op-conn");
    state.register_connection(&op_conn, tx_op, None);

    let (tx_node, mut rx_node) = mpsc::unbounded_channel();
    let node_conn = make_conn_with_id("node", vec![], "node-conn");
    state.register_connection(&node_conn, tx_node, None);

    // Clear presence broadcasts
    let _ = rx_op.try_recv();
    let _ = rx_op.try_recv();

    // Broadcast shutdown
    broadcast_shutdown(&state, "update", Some(5000));

    // Operator should receive it
    let msg = rx_op.try_recv();
    assert!(msg.is_ok());
    let Message::Text(text) = msg.unwrap() else {
        panic!("expected text message");
    };
    let event: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(event["event"], "shutdown");
    assert_eq!(event["payload"]["reason"], "update");
    assert_eq!(event["payload"]["restartExpectedMs"], 5000);

    // Node should also receive it
    let msg = rx_node.try_recv();
    assert!(msg.is_ok());
    let Message::Text(text) = msg.unwrap() else {
        panic!("expected text message");
    };
    let event: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(event["event"], "shutdown");
}

#[test]
fn test_broadcast_heartbeat() {
    let state = WsServerState::new(WsServerConfig::default());

    let (tx, mut rx) = mpsc::unbounded_channel();
    let conn = make_conn_with_id("operator", vec![], "conn-1");
    state.register_connection(&conn, tx, None);

    // Clear presence broadcast
    let _ = rx.try_recv();

    broadcast_heartbeat(&state);

    let msg = rx.try_recv();
    assert!(msg.is_ok());
    let Message::Text(text) = msg.unwrap() else {
        panic!("expected text message");
    };
    let event: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(event["event"], "heartbeat");
    assert!(event["payload"]["ts"].as_u64().is_some());
}

#[test]
fn test_broadcast_talk_mode() {
    let state = WsServerState::new(WsServerConfig::default());

    let (tx, mut rx) = mpsc::unbounded_channel();
    let conn = make_conn_with_id("operator", vec![], "conn-1");
    state.register_connection(&conn, tx, None);

    // Clear presence broadcast
    let _ = rx.try_recv();

    broadcast_talk_mode(&state, true, Some("whatsapp"));

    let msg = rx.try_recv();
    assert!(msg.is_ok());
    let Message::Text(text) = msg.unwrap() else {
        panic!("expected text message");
    };
    let event: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(event["event"], "talk.mode");
    assert_eq!(event["payload"]["enabled"], true);
    assert_eq!(event["payload"]["channel"], "whatsapp");
}

#[test]
fn test_event_seq_increments() {
    let state = WsServerState::new(WsServerConfig::default());

    let (tx, mut rx) = mpsc::unbounded_channel();
    let conn = make_conn_with_id("operator", vec![], "conn-1");
    state.register_connection(&conn, tx, None);

    // Get seq from presence event
    let msg = rx.try_recv().unwrap();
    let Message::Text(text) = msg else { panic!() };
    let event: Value = serde_json::from_str(&text).unwrap();
    let seq1 = event["seq"].as_u64().unwrap();

    // Broadcast another event
    broadcast_heartbeat(&state);
    let msg = rx.try_recv().unwrap();
    let Message::Text(text) = msg else { panic!() };
    let event: Value = serde_json::from_str(&text).unwrap();
    let seq2 = event["seq"].as_u64().unwrap();

    // Seq should be monotonically increasing
    assert!(seq2 > seq1, "Event seq should be monotonically increasing");
}

#[test]
fn test_health_broadcast_on_status_change() {
    let state = WsServerState::new(WsServerConfig::default());

    let (tx, mut rx) = mpsc::unbounded_channel();
    let conn = make_conn_with_id("operator", vec![], "conn-1");
    state.register_connection(&conn, tx, None);

    // Clear presence broadcast
    let _ = rx.try_recv();

    // Update health - should broadcast since status changes
    state.update_health("degraded", None, None);

    let msg = rx.try_recv();
    assert!(
        msg.is_ok(),
        "Should receive health broadcast on status change"
    );
    let Message::Text(text) = msg.unwrap() else {
        panic!("expected text message");
    };
    let event: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(event["event"], "health");
    assert_eq!(event["payload"]["status"], "degraded");
    assert!(event["stateVersion"]["health"].as_u64().unwrap() >= 1);

    // Update health with same status - should NOT broadcast
    state.update_health("degraded", Some(json!({"more": "data"})), None);
    let msg = rx.try_recv();
    assert!(msg.is_err(), "Should not broadcast when status unchanged");
}

// ============================================================================
// Cron Scheduler Integration Tests
// ============================================================================

#[test]
fn test_cron_scheduler_integration() {
    use crate::cron::{
        CronJobCreate, CronJobPatch, CronPayload, CronRunMode, CronSchedule, CronSessionTarget,
        CronWakeMode,
    };

    let state = WsServerState::new(WsServerConfig::default());

    // Test scheduler status
    let status = state.cron_scheduler.status();
    assert!(status.enabled);
    assert_eq!(status.jobs, 0);

    // Add a job
    let job = state
        .cron_scheduler
        .add(CronJobCreate {
            name: "Test Job".to_string(),
            agent_id: None,
            description: None,
            enabled: true,
            delete_after_run: None,
            schedule: CronSchedule::Every {
                every_ms: 60000,
                anchor_ms: None,
            },
            session_target: CronSessionTarget::Main,
            wake_mode: CronWakeMode::Now,
            payload: CronPayload::SystemEvent {
                text: "Hello!".to_string(),
            },
            isolation: None,
        })
        .unwrap();
    assert_eq!(job.name, "Test Job");
    assert!(job.state.next_run_at_ms.is_some());

    // List jobs
    let jobs = state.cron_scheduler.list(true);
    assert_eq!(jobs.len(), 1);

    // Check status after adding
    let status = state.cron_scheduler.status();
    assert_eq!(status.jobs, 1);

    // Update the job
    let updated = state
        .cron_scheduler
        .update(
            &job.id,
            CronJobPatch {
                name: Some("Updated Job".to_string()),
                enabled: Some(false),
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(updated.name, "Updated Job");
    assert!(!updated.enabled);

    // Force run the job
    let result = state
        .cron_scheduler
        .run(&job.id, Some(CronRunMode::Force))
        .unwrap();
    assert!(result.ok);
    assert!(result.ran);
    assert!(result.payload.is_some());

    // Run no longer records log entry — mark_run_finished does.
    state
        .cron_scheduler
        .mark_run_finished(&job.id, crate::cron::CronJobStatus::Ok, 0, None)
        .unwrap();

    // Check runs
    let runs = state.cron_scheduler.runs(Some(&job.id), None);
    assert_eq!(runs.len(), 1);

    // Remove the job
    let remove_result = state.cron_scheduler.remove(&job.id);
    assert!(remove_result.ok);
    assert!(remove_result.removed);

    // Verify removed
    let jobs = state.cron_scheduler.list(true);
    assert_eq!(jobs.len(), 0);
}

#[test]
fn test_cron_scheduler_update_job_not_found() {
    use crate::cron::CronJobPatch;

    let state = WsServerState::new(WsServerConfig::default());

    let result = state.cron_scheduler.update(
        "non-existent-job",
        CronJobPatch {
            name: Some("Updated".to_string()),
            ..Default::default()
        },
    );
    assert!(result.is_err());
}

#[test]
fn test_cron_scheduler_run_not_found() {
    use crate::cron::CronRunMode;

    let state = WsServerState::new(WsServerConfig::default());

    let result = state
        .cron_scheduler
        .run("non-existent-job", Some(CronRunMode::Force));
    assert!(result.is_err());
}

#[test]
fn test_cron_scheduler_event_integration() {
    use crate::cron::{
        CronJobCreate, CronPayload, CronRunMode, CronSchedule, CronSessionTarget, CronWakeMode,
    };

    let state = WsServerState::new(WsServerConfig::default());

    let (tx, mut rx) = mpsc::unbounded_channel();
    let conn = make_conn_with_id("operator", vec![], "conn-1");
    state.register_connection(&conn, tx, None);

    // Clear the presence broadcast
    let _ = rx.try_recv();

    // Add a job and manually broadcast event (simulating what handlers do)
    let job = state
        .cron_scheduler
        .add(CronJobCreate {
            name: "Test Job".to_string(),
            agent_id: None,
            description: None,
            enabled: true,
            delete_after_run: None,
            schedule: CronSchedule::Every {
                every_ms: 60000,
                anchor_ms: None,
            },
            session_target: CronSessionTarget::Main,
            wake_mode: CronWakeMode::Now,
            payload: CronPayload::SystemEvent {
                text: "Hello!".to_string(),
            },
            isolation: None,
        })
        .unwrap();

    // Broadcast event manually (normally done by handlers)
    broadcast_cron_event(
        &state,
        &job.id,
        "scheduled",
        None,
        Some(json!({"name": job.name})),
    );

    // Should receive cron event
    let msg = rx.try_recv();
    assert!(msg.is_ok());
    let Message::Text(text) = msg.unwrap() else {
        panic!("expected text message");
    };
    let event: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(event["event"], "cron");
    assert_eq!(event["payload"]["jobId"], job.id);
    assert_eq!(event["payload"]["status"], "scheduled");

    // Run the job and broadcast events
    let result = state
        .cron_scheduler
        .run(&job.id, Some(CronRunMode::Force))
        .unwrap();
    assert!(result.ran);

    broadcast_cron_event(&state, &job.id, "started", None, None);
    broadcast_cron_event(
        &state,
        &job.id,
        "completed",
        None,
        Some(json!({"status": "ok"})),
    );

    // Should receive started event
    let msg = rx.try_recv().unwrap();
    let Message::Text(text) = msg else { panic!() };
    let event: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(event["payload"]["status"], "started");

    // Should receive completed event
    let msg = rx.try_recv().unwrap();
    let Message::Text(text) = msg else { panic!() };
    let event: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(event["payload"]["status"], "completed");
}

// ============== Node Event Routing Tests ==============

fn make_node_conn(node_id: &str, conn_id: &str) -> ConnectionContext {
    ConnectionContext {
        conn_id: conn_id.to_string(),
        role: "node".to_string(),
        scopes: vec![],
        client: ClientInfo {
            id: node_id.to_string(),
            version: "1.0".to_string(),
            platform: "test".to_string(),
            mode: "node".to_string(),
            display_name: None,
            device_family: None,
            model_identifier: None,
            instance_id: None,
        },
        device_id: Some(node_id.to_string()),
    }
}

fn pair_node(state: &WsServerState, node_id: &str) {
    let params = json!({ "nodeId": node_id, "displayName": node_id });
    let result = handle_node_pair_request(Some(&params), state).unwrap();
    let request_id = result["request"]["requestId"].as_str().unwrap();
    handle_node_pair_approve(Some(&json!({ "requestId": request_id })), state).unwrap();
}

#[test]
fn test_handle_node_event_requires_node_role() {
    let state = WsServerState::new(WsServerConfig::default());
    let conn = make_conn("admin");

    let params = json!({
        "nodeId": "node-1",
        "event": "some.event",
        "payload": { "key": "value" }
    });
    let result = handle_node_event(Some(&params), &state, &conn);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code, ERROR_INVALID_REQUEST);
}

#[test]
fn test_handle_node_event_requires_pairing() {
    let state = WsServerState::new(WsServerConfig::default());
    let conn = make_node_conn("unpaired-node", "conn-node");

    let params = json!({
        "nodeId": "unpaired-node",
        "event": "some.event"
    });
    let result = handle_node_event(Some(&params), &state, &conn);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code, ERROR_NOT_PAIRED);
}

#[test]
fn test_handle_node_event_requires_event_field() {
    let state = WsServerState::new(WsServerConfig::default());
    pair_node(&state, "node-1");
    let conn = make_node_conn("node-1", "conn-node-1");

    let params = json!({
        "nodeId": "node-1",
        "payload": { "key": "value" }
    });
    let result = handle_node_event(Some(&params), &state, &conn);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code, ERROR_INVALID_REQUEST);
}

#[test]
fn test_handle_node_event_prevents_node_id_mismatch() {
    let state = WsServerState::new(WsServerConfig::default());
    pair_node(&state, "node-1");
    let conn = make_node_conn("node-1", "conn-node-1");

    let params = json!({
        "nodeId": "node-other",
        "event": "some.event"
    });
    let result = handle_node_event(Some(&params), &state, &conn);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code, ERROR_INVALID_REQUEST);
}

#[test]
fn test_handle_node_event_broadcasts_to_operators() {
    let state = WsServerState::new(WsServerConfig::default());
    pair_node(&state, "node-1");

    // Register an operator connection to receive broadcasts
    let (tx_op, mut rx_op) = mpsc::unbounded_channel();
    let op_conn = make_conn_with_id("operator", vec![], "op-conn");
    state.register_connection(&op_conn, tx_op, None);

    // Clear the presence broadcast
    let _ = rx_op.try_recv();

    // Send a node event
    let node_conn = make_node_conn("node-1", "conn-node-1");
    let params = json!({
        "nodeId": "node-1",
        "event": "status.changed",
        "payload": { "status": "idle", "battery": 85 }
    });
    let result = handle_node_event(Some(&params), &state, &node_conn);
    assert!(result.is_ok());

    let response = result.unwrap();
    assert_eq!(response["ok"], true);
    assert_eq!(response["nodeId"], "node-1");
    assert_eq!(response["event"], "status.changed");
    assert_eq!(response["hasPayload"], true);

    // Operator should receive the broadcast
    let msg = rx_op.try_recv();
    assert!(msg.is_ok(), "Operator should receive node.event broadcast");
    let Message::Text(text) = msg.unwrap() else {
        panic!("expected text message");
    };
    let event: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(event["type"], "event");
    assert_eq!(event["event"], "node.event");
    assert_eq!(event["payload"]["nodeId"], "node-1");
    assert_eq!(event["payload"]["event"], "status.changed");
    assert_eq!(event["payload"]["payload"]["status"], "idle");
    assert_eq!(event["payload"]["payload"]["battery"], 85);
    assert!(event["payload"]["ts"].as_u64().is_some());
}

#[test]
fn test_handle_node_event_does_not_broadcast_to_nodes() {
    let state = WsServerState::new(WsServerConfig::default());
    pair_node(&state, "node-1");
    pair_node(&state, "node-2");

    // Register a node connection (should NOT receive broadcasts)
    let (tx_node2, mut rx_node2) = mpsc::unbounded_channel();
    let node2_conn = make_node_conn("node-2", "conn-node-2");
    state.register_connection(&node2_conn, tx_node2, None);

    // Register an operator connection (should receive broadcasts)
    let (tx_op, mut rx_op) = mpsc::unbounded_channel();
    let op_conn = make_conn_with_id("operator", vec![], "op-conn");
    state.register_connection(&op_conn, tx_op, None);

    // Clear presence broadcasts
    let _ = rx_op.try_recv();
    let _ = rx_op.try_recv();

    // Send a node event from node-1
    let node1_conn = make_node_conn("node-1", "conn-node-1");
    let params = json!({
        "nodeId": "node-1",
        "event": "heartbeat",
        "payload": { "uptime": 12345 }
    });
    let result = handle_node_event(Some(&params), &state, &node1_conn);
    assert!(result.is_ok());

    // Operator should receive it
    assert!(rx_op.try_recv().is_ok(), "Operator should receive event");

    // Node-2 should NOT receive it
    assert!(
        rx_node2.try_recv().is_err(),
        "Other nodes should not receive node.event broadcasts"
    );
}

#[test]
fn test_handle_node_event_with_payload_json() {
    let state = WsServerState::new(WsServerConfig::default());
    pair_node(&state, "node-1");

    // Register an operator connection
    let (tx_op, mut rx_op) = mpsc::unbounded_channel();
    let op_conn = make_conn_with_id("operator", vec![], "op-conn");
    state.register_connection(&op_conn, tx_op, None);

    // Clear the presence broadcast
    let _ = rx_op.try_recv();

    // Send a node event with payloadJSON (string-encoded JSON)
    let node_conn = make_node_conn("node-1", "conn-node-1");
    let params = json!({
        "nodeId": "node-1",
        "event": "data.update",
        "payloadJSON": r#"{"temperature":22.5,"humidity":60}"#
    });
    let result = handle_node_event(Some(&params), &state, &node_conn);
    assert!(result.is_ok());
    assert_eq!(result.unwrap()["hasPayload"], true);

    // Operator should receive the broadcast with parsed payloadJSON
    let msg = rx_op.try_recv();
    assert!(msg.is_ok());
    let Message::Text(text) = msg.unwrap() else {
        panic!("expected text message");
    };
    let event: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(event["payload"]["event"], "data.update");
    assert_eq!(event["payload"]["payload"]["temperature"], 22.5);
    assert_eq!(event["payload"]["payload"]["humidity"], 60);
}

#[test]
fn test_handle_node_event_without_payload() {
    let state = WsServerState::new(WsServerConfig::default());
    pair_node(&state, "node-1");

    // Register an operator connection
    let (tx_op, mut rx_op) = mpsc::unbounded_channel();
    let op_conn = make_conn_with_id("operator", vec![], "op-conn");
    state.register_connection(&op_conn, tx_op, None);

    // Clear the presence broadcast
    let _ = rx_op.try_recv();

    // Send a node event without any payload
    let node_conn = make_node_conn("node-1", "conn-node-1");
    let params = json!({
        "nodeId": "node-1",
        "event": "ready"
    });
    let result = handle_node_event(Some(&params), &state, &node_conn);
    assert!(result.is_ok());
    assert_eq!(result.unwrap()["hasPayload"], false);

    // Operator should receive the broadcast with null payload
    let msg = rx_op.try_recv();
    assert!(msg.is_ok());
    let Message::Text(text) = msg.unwrap() else {
        panic!("expected text message");
    };
    let event: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(event["payload"]["event"], "ready");
    assert_eq!(event["payload"]["payload"], Value::Null);
}

#[test]
fn test_handle_node_event_defaults_node_id_from_connection() {
    let state = WsServerState::new(WsServerConfig::default());
    pair_node(&state, "node-1");

    let node_conn = make_node_conn("node-1", "conn-node-1");

    // Send without explicit nodeId -- should default to connection's node id
    let params = json!({
        "event": "ping"
    });
    let result = handle_node_event(Some(&params), &state, &node_conn);
    assert!(result.is_ok());
    assert_eq!(result.unwrap()["nodeId"], "node-1");
}

#[test]
fn test_node_event_in_gateway_events() {
    // Verify that node.event is registered as a known gateway event
    assert!(
        GATEWAY_EVENTS.contains(&"node.event"),
        "node.event should be in GATEWAY_EVENTS"
    );
}

#[test]
fn test_node_list_merges_paired_metadata_with_live_data() {
    let state = WsServerState::new(WsServerConfig::default());

    // Pair a node with extended fields
    let params = json!({
        "nodeId": "node-merge",
        "displayName": "Merge Node",
        "platform": "darwin",
        "version": "1.0.0",
        "coreVersion": "0.9.0",
        "uiVersion": "1.0.0",
        "deviceFamily": "Mac",
        "modelIdentifier": "MacBookPro18,3",
        "caps": ["exec", "audio"],
        "commands": ["system.run"],
        "permissions": { "filesystem": true },
        "remoteIp": "192.168.1.10"
    });
    let result = handle_node_pair_request(Some(&params), &state).unwrap();
    let request_id = result["request"]["requestId"].as_str().unwrap();
    handle_node_pair_approve(Some(&json!({ "requestId": request_id })), &state).unwrap();

    // Register a live session with updated version
    {
        let mut registry = state.node_registry.lock();
        registry.register(NodeSession {
            node_id: "node-merge".to_string(),
            conn_id: "conn-merge".to_string(),
            display_name: Some("Merge Node Live".to_string()),
            platform: Some("darwin".to_string()),
            version: Some("2.0.0".to_string()),
            device_family: Some("Mac".to_string()),
            model_identifier: Some("MacBookPro18,3".to_string()),
            remote_ip: Some("10.0.0.5".to_string()),
            caps: vec!["exec".to_string(), "video".to_string()],
            commands: HashSet::from(["system.run".to_string(), "screen.capture".to_string()]),
            permissions: Some({
                let mut m = HashMap::new();
                m.insert("filesystem".to_string(), true);
                m.insert("screen".to_string(), true);
                m
            }),
            path_env: Some("/usr/local/bin".to_string()),
            connected_at_ms: now_ms(),
        });
    }

    // node.list should merge paired + live data
    let result = handle_node_list(&state).unwrap();
    let nodes = result["nodes"].as_array().unwrap();
    assert_eq!(nodes.len(), 1);

    let node = &nodes[0];
    // Live data should take precedence for version and display name
    assert_eq!(node["version"], "2.0.0");
    assert_eq!(node["displayName"], "Merge Node Live");
    assert_eq!(node["remoteIp"], "10.0.0.5");
    // Paired-only fields should still be present
    assert_eq!(node["coreVersion"], "0.9.0");
    assert_eq!(node["uiVersion"], "1.0.0");
    // Caps should be merged (union of both)
    let caps = node["caps"].as_array().unwrap();
    let cap_strs: Vec<&str> = caps.iter().map(|v| v.as_str().unwrap()).collect();
    assert!(cap_strs.contains(&"exec"));
    assert!(cap_strs.contains(&"audio"));
    assert!(cap_strs.contains(&"video"));
    // Commands should be merged
    let commands = node["commands"].as_array().unwrap();
    let cmd_strs: Vec<&str> = commands.iter().map(|v| v.as_str().unwrap()).collect();
    assert!(cmd_strs.contains(&"system.run"));
    assert!(cmd_strs.contains(&"screen.capture"));
    // Should be connected and paired
    assert_eq!(node["connected"], true);
    assert_eq!(node["paired"], true);
    // pathEnv from live data
    assert_eq!(node["pathEnv"], "/usr/local/bin");
}

#[test]
fn test_node_describe_merges_paired_metadata_with_live_data() {
    let state = WsServerState::new(WsServerConfig::default());

    // Pair a node with extended fields
    let params = json!({
        "nodeId": "node-describe-merge",
        "displayName": "Describe Merge",
        "platform": "ios",
        "version": "1.0.0",
        "coreVersion": "0.8.0",
        "uiVersion": "1.0.0",
        "deviceFamily": "iPhone",
        "modelIdentifier": "iPhone14,2",
        "caps": ["camera"],
        "commands": ["camera.snap"],
        "permissions": { "camera": true },
        "remoteIp": "172.16.0.1"
    });
    let result = handle_node_pair_request(Some(&params), &state).unwrap();
    let request_id = result["request"]["requestId"].as_str().unwrap();
    handle_node_pair_approve(Some(&json!({ "requestId": request_id })), &state).unwrap();

    // Register a live session with additional caps
    {
        let mut registry = state.node_registry.lock();
        registry.register(NodeSession {
            node_id: "node-describe-merge".to_string(),
            conn_id: "conn-describe-merge".to_string(),
            display_name: Some("Describe Merge Live".to_string()),
            platform: Some("ios".to_string()),
            version: Some("2.0.0".to_string()),
            device_family: Some("iPhone".to_string()),
            model_identifier: Some("iPhone14,2".to_string()),
            remote_ip: Some("172.16.0.2".to_string()),
            caps: vec!["camera".to_string(), "location".to_string()],
            commands: HashSet::from(["camera.snap".to_string(), "location.get".to_string()]),
            permissions: None,
            path_env: None,
            connected_at_ms: now_ms(),
        });
    }

    // node.describe should merge paired + live data
    let describe_params = json!({ "nodeId": "node-describe-merge" });
    let result = handle_node_describe(Some(&describe_params), &state).unwrap();

    // Live data should take precedence
    assert_eq!(result["version"], "2.0.0");
    assert_eq!(result["displayName"], "Describe Merge Live");
    assert_eq!(result["remoteIp"], "172.16.0.2");
    // Paired-only fields should still be present
    assert_eq!(result["coreVersion"], "0.8.0");
    assert_eq!(result["uiVersion"], "1.0.0");
    // Caps merged
    let caps = result["caps"].as_array().unwrap();
    let cap_strs: Vec<&str> = caps.iter().map(|v| v.as_str().unwrap()).collect();
    assert!(cap_strs.contains(&"camera"));
    assert!(cap_strs.contains(&"location"));
    // Commands merged
    let commands = result["commands"].as_array().unwrap();
    let cmd_strs: Vec<&str> = commands.iter().map(|v| v.as_str().unwrap()).collect();
    assert!(cmd_strs.contains(&"camera.snap"));
    assert!(cmd_strs.contains(&"location.get"));
    // Permissions from paired data should be used since live has None
    assert_eq!(result["permissions"], json!({ "camera": true }));
    // Connected and paired
    assert_eq!(result["connected"], true);
    assert_eq!(result["paired"], true);
}

#[tokio::test]
async fn test_shutdown_watch_channel_propagates() {
    let (tx, mut rx) = tokio::sync::watch::channel(false);

    // Initially not shut down
    assert!(!*rx.borrow());

    // Simulate shutdown signal
    tx.send(true).unwrap();

    // Receiver should observe the change
    rx.changed().await.unwrap();
    assert!(*rx.borrow());
}

#[tokio::test]
async fn test_shutdown_watch_channel_multiple_receivers() {
    let (tx, rx1) = tokio::sync::watch::channel(false);
    let mut rx2 = rx1.clone();
    let mut rx3 = rx1.clone();

    // All receivers start as false
    assert!(!*rx1.borrow());
    assert!(!*rx2.borrow());
    assert!(!*rx3.borrow());

    // Trigger shutdown
    tx.send(true).unwrap();

    // All receivers see the update
    rx2.changed().await.unwrap();
    rx3.changed().await.unwrap();
    assert!(*rx2.borrow());
    assert!(*rx3.borrow());
}

#[test]
fn test_broadcast_shutdown_notifies_connected_clients() {
    let state = Arc::new(WsServerState::new(WsServerConfig::default()));

    // Register a mock connection
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let conn = ConnectionContext {
        conn_id: "conn-shutdown-test".to_string(),
        role: "operator".to_string(),
        scopes: vec![],
        client: ClientInfo {
            id: "test".to_string(),
            version: "1.0".to_string(),
            platform: "test".to_string(),
            mode: "test".to_string(),
            display_name: None,
            device_family: None,
            model_identifier: None,
            instance_id: None,
        },
        device_id: None,
    };
    state.register_connection(&conn, tx, None);

    // Drain any messages sent during registration (e.g. presence broadcast)
    while rx.try_recv().is_ok() {}

    // Broadcast shutdown
    broadcast_shutdown(&state, "SIGTERM", None);

    // The connected client should receive a shutdown event frame
    let msg = rx
        .try_recv()
        .expect("should have received shutdown message");
    let text = match msg {
        Message::Text(t) => t,
        other => panic!("expected text message, got {:?}", other),
    };
    let parsed: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(parsed["event"], "shutdown");
    assert_eq!(parsed["payload"]["reason"], "SIGTERM");
}

#[test]
fn test_broadcast_sends_identical_bytes_to_all_connections() {
    let state = WsServerState::new(WsServerConfig::default());

    // Register three operator connections
    let (tx1, mut rx1) = mpsc::unbounded_channel();
    let (tx2, mut rx2) = mpsc::unbounded_channel();
    let (tx3, mut rx3) = mpsc::unbounded_channel();

    let conn1 = make_conn_with_id("operator", vec![], "conn-1");
    let conn2 = make_conn_with_id("operator", vec![], "conn-2");
    let conn3 = make_conn_with_id("operator", vec![], "conn-3");

    state.register_connection(&conn1, tx1, None);
    state.register_connection(&conn2, tx2, None);
    state.register_connection(&conn3, tx3, None);

    // Drain all presence broadcasts from registration
    while rx1.try_recv().is_ok() {}
    while rx2.try_recv().is_ok() {}
    while rx3.try_recv().is_ok() {}

    // Broadcast a general event
    broadcast_event(
        &state,
        "agent",
        json!({"runId": "run-1", "seq": 1, "stream": "text", "data": {"text": "Hello!"}}),
    );

    let msg1 = rx1.try_recv().expect("conn-1 should receive broadcast");
    let msg2 = rx2.try_recv().expect("conn-2 should receive broadcast");
    let msg3 = rx3.try_recv().expect("conn-3 should receive broadcast");

    // Extract text from each message
    let text1 = match msg1 {
        Message::Text(t) => t,
        other => panic!("expected text message, got {:?}", other),
    };
    let text2 = match msg2 {
        Message::Text(t) => t,
        other => panic!("expected text message, got {:?}", other),
    };
    let text3 = match msg3 {
        Message::Text(t) => t,
        other => panic!("expected text message, got {:?}", other),
    };

    // All three connections must receive byte-identical JSON strings.
    // This verifies that broadcast serializes once and clones the string,
    // rather than re-serializing per connection (which could produce
    // different key orderings or whitespace).
    assert_eq!(
        text1, text2,
        "conn-1 and conn-2 should receive identical bytes"
    );
    assert_eq!(
        text2, text3,
        "conn-2 and conn-3 should receive identical bytes"
    );

    // Sanity: verify the content is valid JSON with expected fields
    let parsed: Value = serde_json::from_str(&text1).unwrap();
    assert_eq!(parsed["type"], "event");
    assert_eq!(parsed["event"], "agent");
    assert_eq!(parsed["payload"]["runId"], "run-1");

    // Also verify shutdown broadcast sends identical bytes (different code path)
    while rx1.try_recv().is_ok() {}
    while rx2.try_recv().is_ok() {}
    while rx3.try_recv().is_ok() {}

    broadcast_shutdown(&state, "update", Some(3000));

    let s1 = match rx1.try_recv().unwrap() {
        Message::Text(t) => t,
        other => panic!("expected text, got {:?}", other),
    };
    let s2 = match rx2.try_recv().unwrap() {
        Message::Text(t) => t,
        other => panic!("expected text, got {:?}", other),
    };
    let s3 = match rx3.try_recv().unwrap() {
        Message::Text(t) => t,
        other => panic!("expected text, got {:?}", other),
    };

    assert_eq!(
        s1, s2,
        "shutdown bytes must be identical across connections"
    );
    assert_eq!(
        s2, s3,
        "shutdown bytes must be identical across connections"
    );

    // Also verify voicewake broadcast (sends to all including nodes)
    let (tx_node, mut rx_node) = mpsc::unbounded_channel();
    let node_conn = make_conn_with_id("node", vec![], "node-conn");
    state.register_connection(&node_conn, tx_node, None);

    while rx1.try_recv().is_ok() {}
    while rx_node.try_recv().is_ok() {}

    broadcast_voicewake_changed(&state, vec!["hey claude".to_string()]);

    let v1 = match rx1.try_recv().unwrap() {
        Message::Text(t) => t,
        other => panic!("expected text, got {:?}", other),
    };
    let v_node = match rx_node.try_recv().unwrap() {
        Message::Text(t) => t,
        other => panic!("expected text, got {:?}", other),
    };

    assert_eq!(
        v1, v_node,
        "voicewake broadcast bytes must be identical for operator and node"
    );
}

#[test]
fn test_every_gateway_method_has_explicit_role_assignment() {
    // Methods that are explicitly assigned "admin" in get_method_required_role.
    // If a method returns "admin" but is NOT in this list, it means the method
    // is falling through to the default `_ => "admin"` arm, which is a bug —
    // it should be explicitly listed.
    let explicit_admin_methods: std::collections::HashSet<&str> = [
        "device.pair.approve",
        "device.pair.reject",
        "device.token.rotate",
        "device.token.revoke",
        "node.pair.request",
        "node.pair.approve",
        "node.pair.reject",
        "node.pair.verify",
        "node.rename",
        "exec.approvals.set",
        "exec.approvals.node.set",
        "exec.approval.request",
        "exec.approval.resolve",
        "sessions.export_user",
        "sessions.purge_user",
        "system-event",
        "config.reload",
    ]
    .into_iter()
    .collect();

    // Node-only methods are dispatched before role checks, so they
    // legitimately have no explicit role assignment.
    let node_only: std::collections::HashSet<&str> = NODE_ONLY_METHODS.iter().copied().collect();

    for method in &GATEWAY_METHODS {
        if node_only.contains(method) {
            continue;
        }
        let role = get_method_required_role(method);
        assert!(
            role == "read" || role == "write" || explicit_admin_methods.contains(method),
            "GATEWAY_METHODS entry '{}' returns role '{}' via default fallthrough — \
             add it to an explicit arm in get_method_required_role()",
            method,
            role,
        );
    }
}

// ---------------------------------------------------------------------------
// JSON depth validation tests
// ---------------------------------------------------------------------------

/// Helper: build a JSON value nested to exactly `depth` levels using objects.
fn nested_object(depth: usize) -> Value {
    let mut value = json!("leaf");
    for _ in 0..depth.saturating_sub(1) {
        value = json!({ "nested": value });
    }
    value
}

/// Helper: build a JSON value nested to exactly `depth` levels using arrays.
fn nested_array(depth: usize) -> Value {
    let mut value = json!("leaf");
    for _ in 0..depth.saturating_sub(1) {
        value = json!([value]);
    }
    value
}

/// Helper: build mixed nesting (alternating objects and arrays) to `depth`.
fn mixed_nesting(depth: usize) -> Value {
    let mut value = json!("leaf");
    for i in 0..depth.saturating_sub(1) {
        if i % 2 == 0 {
            value = json!({ "nested": value });
        } else {
            value = json!([value]);
        }
    }
    value
}

#[test]
fn test_shallow_json_passes() {
    // Depth 1: simple scalar values
    assert!(validate_json_depth(&json!("hello"), MAX_JSON_DEPTH).is_ok());
    assert!(validate_json_depth(&json!(42), MAX_JSON_DEPTH).is_ok());

    // Depth 2: one level of nesting
    assert!(validate_json_depth(&json!({"a": 1}), MAX_JSON_DEPTH).is_ok());

    // Depth 3-5: a few levels
    assert!(validate_json_depth(&nested_object(3), MAX_JSON_DEPTH).is_ok());
    assert!(validate_json_depth(&nested_object(5), MAX_JSON_DEPTH).is_ok());
}

#[test]
fn test_exact_limit_passes() {
    let value = nested_object(MAX_JSON_DEPTH);
    assert!(validate_json_depth(&value, MAX_JSON_DEPTH).is_ok());
}

#[test]
fn test_exceeds_limit_fails() {
    let value = nested_object(MAX_JSON_DEPTH + 1);
    let result = validate_json_depth(&value, MAX_JSON_DEPTH);
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .contains("JSON nesting depth exceeds maximum"));
}

#[test]
fn test_deeply_nested_array_fails() {
    let value = nested_array(MAX_JSON_DEPTH + 1);
    let result = validate_json_depth(&value, MAX_JSON_DEPTH);
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .contains("JSON nesting depth exceeds maximum"));
}

#[test]
fn test_mixed_nesting_fails() {
    let value = mixed_nesting(MAX_JSON_DEPTH + 1);
    let result = validate_json_depth(&value, MAX_JSON_DEPTH);
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .contains("JSON nesting depth exceeds maximum"));
}

#[test]
fn test_flat_large_object_passes() {
    // 1000 keys at depth 1 -- size != depth
    let mut map = serde_json::Map::new();
    for i in 0..1000 {
        map.insert(format!("key_{i}"), json!(i));
    }
    let value = Value::Object(map);
    assert!(validate_json_depth(&value, MAX_JSON_DEPTH).is_ok());
}

#[test]
fn test_empty_value_passes() {
    assert!(validate_json_depth(&json!(null), MAX_JSON_DEPTH).is_ok());
    assert!(validate_json_depth(&json!(true), MAX_JSON_DEPTH).is_ok());
    assert!(validate_json_depth(&json!(false), MAX_JSON_DEPTH).is_ok());
    assert!(validate_json_depth(&json!(0), MAX_JSON_DEPTH).is_ok());
    assert!(validate_json_depth(&json!(3.15), MAX_JSON_DEPTH).is_ok());
    assert!(validate_json_depth(&json!(""), MAX_JSON_DEPTH).is_ok());
}

#[test]
fn test_validate_json_depth_at_small_limit() {
    // Test with a smaller limit.
    // Depth model: root value starts at depth 1.
    // {"a": {"b": 1}} has leaf at depth 3, so it needs max_depth >= 3.
    assert!(validate_json_depth(&json!({"a": {"b": 1}}), 3).is_ok());
    // {"a": {"b": {"c": 1}}} has leaf at depth 4, so max_depth 3 rejects it.
    assert!(validate_json_depth(&json!({"a": {"b": {"c": 1}}}), 3).is_err());
}

#[test]
fn test_validate_json_depth_zero_rejects_nested() {
    // Depth 0 rejects everything because even a scalar starts at depth 1.
    assert!(validate_json_depth(&json!("hello"), 0).is_err());
    assert!(validate_json_depth(&json!(42), 0).is_err());
    // Nested structures are also rejected.
    assert!(validate_json_depth(&json!({"a": 1}), 0).is_err());
    assert!(validate_json_depth(&json!([1]), 0).is_err());
}

#[test]
fn test_validate_json_depth_limit_1() {
    // Depth 1 allows only scalar values (root at depth 1, no children).
    assert!(validate_json_depth(&json!("hello"), 1).is_ok());
    assert!(validate_json_depth(&json!(42), 1).is_ok());
    // Objects and arrays have children at depth 2, which exceeds limit 1.
    assert!(validate_json_depth(&json!({"a": 1}), 1).is_err());
    assert!(validate_json_depth(&json!([1, 2, 3]), 1).is_err());
    // Nested structures are also rejected.
    assert!(validate_json_depth(&json!({"a": {"b": 1}}), 1).is_err());
    assert!(validate_json_depth(&json!([[1]]), 1).is_err());
}
