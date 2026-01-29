//! Node handlers.

use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::time::Duration;
use tokio::sync::oneshot;
use uuid::Uuid;

use super::super::*;
use crate::nodes::NodePairingRequestBuilder;

/// Helper to extract a string array from JSON
fn extract_string_array(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default()
}

/// Helper to extract a permissions map from JSON
fn extract_permissions(value: Option<&Value>) -> Option<HashMap<String, bool>> {
    value.and_then(|v| v.as_object()).map(|obj| {
        obj.iter()
            .filter_map(|(k, v)| v.as_bool().map(|b| (k.clone(), b)))
            .collect()
    })
}

pub(crate) fn handle_node_pair_request(
    params: Option<&Value>,
    state: &WsServerState,
) -> Result<Value, ErrorShape> {
    let node_id = params
        .and_then(|v| v.get("nodeId"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "nodeId is required", None))?;
    let public_key = params
        .and_then(|v| v.get("publicKey"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let commands = extract_string_array(params.and_then(|v| v.get("commands")));
    let display_name = params
        .and_then(|v| v.get("displayName"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let platform = params
        .and_then(|v| v.get("platform"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let version = params
        .and_then(|v| v.get("version"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let core_version = params
        .and_then(|v| v.get("coreVersion"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let ui_version = params
        .and_then(|v| v.get("uiVersion"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let device_family = params
        .and_then(|v| v.get("deviceFamily"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let model_identifier = params
        .and_then(|v| v.get("modelIdentifier"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let caps = extract_string_array(params.and_then(|v| v.get("caps")));
    let permissions = extract_permissions(params.and_then(|v| v.get("permissions")));
    let remote_ip = params
        .and_then(|v| v.get("remoteIp"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let silent = params
        .and_then(|v| v.get("silent"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let builder = NodePairingRequestBuilder {
        node_id: node_id.to_string(),
        public_key,
        commands,
        display_name,
        platform,
        version,
        core_version,
        ui_version,
        device_family,
        model_identifier,
        caps,
        permissions,
        remote_ip,
        silent,
    };

    let outcome = state
        .node_pairing
        .request_pairing_with_builder(builder)
        .map_err(|e| match e {
            nodes::NodePairingError::TooManyPendingRequests => {
                error_shape(ERROR_UNAVAILABLE, "too many pending pairing requests", None)
            }
            _ => error_shape(ERROR_UNAVAILABLE, &e.to_string(), None),
        })?;

    let request = &outcome.request;
    let request_value = json!({
        "requestId": request.request_id,
        "nodeId": request.node_id,
        "displayName": request.display_name,
        "platform": request.platform,
        "version": request.version,
        "coreVersion": request.core_version,
        "uiVersion": request.ui_version,
        "deviceFamily": request.device_family,
        "modelIdentifier": request.model_identifier,
        "caps": request.caps,
        "commands": request.commands,
        "permissions": request.permissions,
        "remoteIp": request.remote_ip,
        "silent": request.silent,
        "isRepair": request.is_repair,
        "ts": request.created_at_ms
    });

    if outcome.created {
        broadcast_event(state, "node.pair.requested", request_value.clone());
    }

    Ok(json!({
        "status": "pending",
        "request": request_value,
        "created": outcome.created
    }))
}

pub(crate) fn handle_node_pair_list(state: &WsServerState) -> Result<Value, ErrorShape> {
    let paired_nodes = state.node_pairing.list_paired_nodes();
    let (pending_requests, _resolved) = state.node_pairing.list_requests();

    let paired: Vec<Value> = paired_nodes
        .iter()
        .map(|n| {
            json!({
                "nodeId": n.node_id,
                "token": null,
                "displayName": n.display_name,
                "platform": n.platform,
                "version": n.version,
                "coreVersion": n.core_version,
                "uiVersion": n.ui_version,
                "deviceFamily": n.device_family,
                "modelIdentifier": n.model_identifier,
                "caps": n.caps,
                "commands": n.commands,
                "permissions": n.permissions,
                "remoteIp": n.remote_ip,
                "createdAtMs": n.created_at_ms,
                "approvedAtMs": n.paired_at_ms,
                "lastConnectedAtMs": n.last_seen_ms
            })
        })
        .collect();

    let pending: Vec<Value> = pending_requests
        .iter()
        .map(|r| {
            json!({
                "requestId": r.request_id,
                "nodeId": r.node_id,
                "displayName": r.display_name,
                "platform": r.platform,
                "version": r.version,
                "coreVersion": r.core_version,
                "uiVersion": r.ui_version,
                "deviceFamily": r.device_family,
                "modelIdentifier": r.model_identifier,
                "caps": r.caps,
                "commands": r.commands,
                "permissions": r.permissions,
                "remoteIp": r.remote_ip,
                "silent": r.silent,
                "isRepair": r.is_repair,
                "ts": r.created_at_ms
            })
        })
        .collect();

    Ok(json!({
        "pending": pending,
        "paired": paired
    }))
}

pub(crate) fn handle_node_pair_approve(
    params: Option<&Value>,
    state: &WsServerState,
) -> Result<Value, ErrorShape> {
    let request_id = params
        .and_then(|v| v.get("requestId"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "requestId is required", None))?;

    let (node, token) = state
        .node_pairing
        .approve_request(request_id)
        .map_err(|e| match e {
            nodes::NodePairingError::RequestNotFound => {
                error_shape(ERROR_INVALID_REQUEST, "request not found", None)
            }
            nodes::NodePairingError::RequestAlreadyResolved => {
                error_shape(ERROR_INVALID_REQUEST, "request already resolved", None)
            }
            nodes::NodePairingError::RequestExpired => {
                error_shape(ERROR_INVALID_REQUEST, "request expired", None)
            }
            _ => error_shape(ERROR_UNAVAILABLE, &e.to_string(), None),
        })?;

    broadcast_event(
        state,
        "node.pair.resolved",
        json!({
            "requestId": request_id,
            "nodeId": node.node_id,
            "decision": "approved",
            "ts": now_ms()
        }),
    );

    Ok(json!({
        "requestId": request_id,
        "node": {
            "nodeId": node.node_id,
            "token": token,
            "displayName": node.display_name,
            "platform": node.platform,
            "version": node.version,
            "coreVersion": node.core_version,
            "uiVersion": node.ui_version,
            "deviceFamily": node.device_family,
            "modelIdentifier": node.model_identifier,
            "caps": node.caps,
            "commands": node.commands,
            "permissions": node.permissions,
            "remoteIp": node.remote_ip,
            "createdAtMs": node.created_at_ms,
            "approvedAtMs": node.paired_at_ms,
            "lastConnectedAtMs": node.last_seen_ms
        }
    }))
}

pub(crate) fn handle_node_pair_reject(
    params: Option<&Value>,
    state: &WsServerState,
) -> Result<Value, ErrorShape> {
    let request_id = params
        .and_then(|v| v.get("requestId"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "requestId is required", None))?;
    let reason = params
        .and_then(|v| v.get("reason"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let request = state
        .node_pairing
        .reject_request(request_id, reason)
        .map_err(|e| match e {
            nodes::NodePairingError::RequestNotFound => {
                error_shape(ERROR_INVALID_REQUEST, "request not found", None)
            }
            nodes::NodePairingError::RequestAlreadyResolved => {
                error_shape(ERROR_INVALID_REQUEST, "request already resolved", None)
            }
            _ => error_shape(ERROR_UNAVAILABLE, &e.to_string(), None),
        })?;

    broadcast_event(
        state,
        "node.pair.resolved",
        json!({
            "requestId": request_id,
            "nodeId": request.node_id,
            "decision": "rejected",
            "ts": now_ms()
        }),
    );

    Ok(json!({
        "requestId": request_id,
        "nodeId": request.node_id
    }))
}

pub(crate) fn handle_node_pair_verify(
    params: Option<&Value>,
    state: &WsServerState,
) -> Result<Value, ErrorShape> {
    let node_id = params
        .and_then(|v| v.get("nodeId"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "nodeId is required", None))?;
    let token = params
        .and_then(|v| v.get("token"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "token is required", None))?;

    let verified = state.node_pairing.verify_token(node_id, token);
    let ok = match verified {
        Ok(()) => {
            state.node_pairing.touch_node(node_id);
            true
        }
        Err(
            nodes::NodePairingError::NodeNotPaired
            | nodes::NodePairingError::TokenInvalid
            | nodes::NodePairingError::TokenExpired
            | nodes::NodePairingError::TokenRevoked,
        ) => false,
        Err(err) => {
            return Err(error_shape(ERROR_UNAVAILABLE, &err.to_string(), None));
        }
    };

    let node_value = if ok {
        state.node_pairing.get_paired_node(node_id).map(|node| {
            json!({
                "nodeId": node.node_id,
                "token": null,
                "displayName": node.display_name,
                "platform": node.platform,
                "version": node.version,
                "coreVersion": node.core_version,
                "uiVersion": node.ui_version,
                "deviceFamily": node.device_family,
                "modelIdentifier": node.model_identifier,
                "caps": node.caps,
                "commands": node.commands,
                "permissions": node.permissions,
                "remoteIp": node.remote_ip,
                "createdAtMs": node.created_at_ms,
                "approvedAtMs": node.paired_at_ms,
                "lastConnectedAtMs": node.last_seen_ms
            })
        })
    } else {
        None
    };

    Ok(json!({
        "ok": ok,
        "node": node_value
    }))
}

pub(crate) fn handle_node_rename(
    params: Option<&Value>,
    state: &WsServerState,
) -> Result<Value, ErrorShape> {
    let node_id = params
        .and_then(|v| v.get("nodeId"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "nodeId is required", None))?;
    let name = params
        .and_then(|v| v.get("name"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "name is required", None))?;

    state
        .node_pairing
        .rename_node(node_id, name.to_string())
        .map_err(|e| match e {
            nodes::NodePairingError::NodeNotPaired => {
                error_shape(ERROR_NOT_PAIRED, "node not paired", None)
            }
            _ => error_shape(ERROR_UNAVAILABLE, &e.to_string(), None),
        })?;

    Ok(json!({
        "ok": true,
        "nodeId": node_id,
        "name": name
    }))
}

pub(crate) fn handle_node_list(state: &WsServerState) -> Result<Value, ErrorShape> {
    let paired_nodes = state.node_pairing.list_paired_nodes();
    let connected = state.node_registry.lock().list_connected();
    let paired_by_id: HashMap<String, nodes::PairedNode> = paired_nodes
        .into_iter()
        .map(|node| (node.node_id.clone(), node))
        .collect();
    let connected_by_id: HashMap<String, NodeSession> = connected
        .into_iter()
        .map(|node| (node.node_id.clone(), node))
        .collect();
    let mut node_ids = HashSet::new();
    node_ids.extend(paired_by_id.keys().cloned());
    node_ids.extend(connected_by_id.keys().cloned());

    let mut entries: Vec<(bool, String, String, Value)> = Vec::new();
    for node_id in node_ids {
        let paired = paired_by_id.get(&node_id);
        let live = connected_by_id.get(&node_id);

        // Merge fields: prefer live data, fall back to paired data
        let display_name = live
            .and_then(|n| n.display_name.clone())
            .or_else(|| paired.and_then(|n| n.display_name.clone()));
        let platform = live
            .and_then(|n| n.platform.clone())
            .or_else(|| paired.and_then(|n| n.platform.clone()));
        let version = live
            .and_then(|n| n.version.clone())
            .or_else(|| paired.and_then(|n| n.version.clone()));
        let core_version = paired.and_then(|n| n.core_version.clone());
        let ui_version = paired.and_then(|n| n.ui_version.clone());
        let device_family = live
            .and_then(|n| n.device_family.clone())
            .or_else(|| paired.and_then(|n| n.device_family.clone()));
        let model_identifier = live
            .and_then(|n| n.model_identifier.clone())
            .or_else(|| paired.and_then(|n| n.model_identifier.clone()));
        let remote_ip = live
            .and_then(|n| n.remote_ip.clone())
            .or_else(|| paired.and_then(|n| n.remote_ip.clone()));

        // Merge caps from live and paired
        let mut caps_set: HashSet<String> = HashSet::new();
        if let Some(live) = live {
            caps_set.extend(live.caps.iter().cloned());
        }
        if let Some(paired) = paired {
            caps_set.extend(paired.caps.iter().cloned());
        }
        let mut caps: Vec<String> = caps_set.into_iter().collect();
        caps.sort();

        // Merge commands from live and paired
        let mut commands_set = HashSet::new();
        if let Some(live) = live {
            commands_set.extend(live.commands.iter().cloned());
        }
        if let Some(paired) = paired {
            commands_set.extend(paired.commands.iter().cloned());
        }
        let mut commands: Vec<String> = commands_set.into_iter().collect();
        commands.sort();

        // Prefer live permissions, fall back to paired
        let permissions = live
            .and_then(|n| n.permissions.clone())
            .or_else(|| paired.and_then(|n| n.permissions.clone()));

        let connected = live.is_some();
        let is_paired = paired.is_some();
        let name_key = display_name
            .clone()
            .unwrap_or_else(|| node_id.clone())
            .to_lowercase();

        let value = json!({
            "nodeId": node_id,
            "displayName": display_name,
            "platform": platform,
            "version": version,
            "coreVersion": core_version,
            "uiVersion": ui_version,
            "deviceFamily": device_family,
            "modelIdentifier": model_identifier,
            "remoteIp": remote_ip,
            "caps": caps,
            "commands": commands,
            "pathEnv": live.and_then(|n| n.path_env.clone()),
            "permissions": permissions,
            "connectedAtMs": live.map(|n| n.connected_at_ms),
            "paired": is_paired,
            "connected": connected
        });

        entries.push((connected, name_key, node_id, value));
    }

    entries.sort_by(|a, b| {
        if a.0 != b.0 {
            return b.0.cmp(&a.0);
        }
        let name_cmp = a.1.cmp(&b.1);
        if name_cmp != std::cmp::Ordering::Equal {
            return name_cmp;
        }
        a.2.cmp(&b.2)
    });

    let nodes: Vec<Value> = entries.into_iter().map(|(_, _, _, value)| value).collect();
    Ok(json!({ "ts": now_ms(), "nodes": nodes }))
}

pub(crate) fn handle_node_describe(
    params: Option<&Value>,
    state: &WsServerState,
) -> Result<Value, ErrorShape> {
    let node_id = params
        .and_then(|v| v.get("nodeId"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "nodeId is required", None))?;

    let paired = state.node_pairing.get_paired_node(node_id);
    let live = state.node_registry.lock().get(node_id).cloned();

    if paired.is_none() && live.is_none() {
        return Err(error_shape(ERROR_INVALID_REQUEST, "unknown nodeId", None));
    }

    // Merge fields: prefer live data, fall back to paired data
    let display_name = live
        .as_ref()
        .and_then(|n| n.display_name.clone())
        .or_else(|| paired.as_ref().and_then(|n| n.display_name.clone()));
    let platform = live
        .as_ref()
        .and_then(|n| n.platform.clone())
        .or_else(|| paired.as_ref().and_then(|n| n.platform.clone()));
    let version = live
        .as_ref()
        .and_then(|n| n.version.clone())
        .or_else(|| paired.as_ref().and_then(|n| n.version.clone()));
    let core_version = paired.as_ref().and_then(|n| n.core_version.clone());
    let ui_version = paired.as_ref().and_then(|n| n.ui_version.clone());
    let device_family = live
        .as_ref()
        .and_then(|n| n.device_family.clone())
        .or_else(|| paired.as_ref().and_then(|n| n.device_family.clone()));
    let model_identifier = live
        .as_ref()
        .and_then(|n| n.model_identifier.clone())
        .or_else(|| paired.as_ref().and_then(|n| n.model_identifier.clone()));
    let remote_ip = live
        .as_ref()
        .and_then(|n| n.remote_ip.clone())
        .or_else(|| paired.as_ref().and_then(|n| n.remote_ip.clone()));

    // Merge caps from live and paired
    let mut caps_set: HashSet<String> = HashSet::new();
    if let Some(live) = live.as_ref() {
        caps_set.extend(live.caps.iter().cloned());
    }
    if let Some(paired) = paired.as_ref() {
        caps_set.extend(paired.caps.iter().cloned());
    }
    let mut caps: Vec<String> = caps_set.into_iter().collect();
    caps.sort();

    // Merge commands from live and paired
    let mut commands_set = HashSet::new();
    if let Some(live) = live.as_ref() {
        commands_set.extend(live.commands.iter().cloned());
    }
    if let Some(paired) = paired.as_ref() {
        commands_set.extend(paired.commands.iter().cloned());
    }
    let mut commands: Vec<String> = commands_set.into_iter().collect();
    commands.sort();

    // Prefer live permissions, fall back to paired
    let permissions = live
        .as_ref()
        .and_then(|n| n.permissions.clone())
        .or_else(|| paired.as_ref().and_then(|n| n.permissions.clone()));

    Ok(json!({
        "ts": now_ms(),
        "nodeId": node_id,
        "displayName": display_name,
        "platform": platform,
        "version": version,
        "coreVersion": core_version,
        "uiVersion": ui_version,
        "deviceFamily": device_family,
        "modelIdentifier": model_identifier,
        "remoteIp": remote_ip,
        "caps": caps,
        "commands": commands,
        "pathEnv": live.as_ref().and_then(|n| n.path_env.clone()),
        "permissions": permissions,
        "connectedAtMs": live.as_ref().map(|n| n.connected_at_ms),
        "paired": paired.is_some(),
        "connected": live.is_some()
    }))
}

pub(crate) async fn handle_node_invoke(
    params: Option<&Value>,
    state: &WsServerState,
) -> Result<Value, ErrorShape> {
    let params =
        params.ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "params required", None))?;
    let node_id = params
        .get("nodeId")
        .and_then(|v| v.as_str())
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "nodeId is required", None))?;
    let command = params
        .get("command")
        .or_else(|| params.get("method"))
        .and_then(|v| v.as_str())
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "command is required", None))?;
    let idempotency_key = params
        .get("idempotencyKey")
        .and_then(|v| v.as_str())
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "idempotencyKey is required", None))?;
    let timeout_ms = params
        .get("timeoutMs")
        .and_then(|v| v.as_i64())
        .filter(|v| *v >= 0)
        .map(|v| v as u64);
    let params_value = params.get("params").cloned();
    let params_json = match params_value {
        Some(value) => Some(
            serde_json::to_string(&value)
                .map_err(|_| error_shape(ERROR_INVALID_REQUEST, "params not serializable", None))?,
        ),
        None => None,
    };

    let (conn_id, commands) = {
        let registry = state.node_registry.lock();
        let node = registry.get(node_id).ok_or_else(|| {
            error_shape(
                ERROR_UNAVAILABLE,
                "node not connected",
                Some(json!({
                    "details": { "nodeId": node_id, "nodeError": { "code": "NOT_CONNECTED" } }
                })),
            )
        })?;
        (node.conn_id.clone(), node.commands.clone())
    };

    if commands.is_empty() {
        return Err(error_shape(
            ERROR_INVALID_REQUEST,
            "node did not declare commands",
            Some(json!({ "nodeId": node_id })),
        ));
    }
    if !commands.contains(command) {
        return Err(error_shape(
            ERROR_INVALID_REQUEST,
            "command not allowlisted",
            Some(json!({ "nodeId": node_id, "command": command })),
        ));
    }

    let invoke_id = Uuid::new_v4().to_string();
    let (responder, receiver) = oneshot::channel();
    {
        let mut registry = state.node_registry.lock();
        registry.insert_pending_invoke(
            invoke_id.clone(),
            PendingInvoke {
                node_id: node_id.to_string(),
                command: command.to_string(),
                responder,
            },
        );
    }

    let mut payload = serde_json::Map::new();
    payload.insert("id".to_string(), json!(invoke_id));
    payload.insert("nodeId".to_string(), json!(node_id));
    payload.insert("command".to_string(), json!(command));
    payload.insert("idempotencyKey".to_string(), json!(idempotency_key));
    if let Some(params_json) = params_json {
        payload.insert("paramsJSON".to_string(), json!(params_json));
    }
    if let Some(timeout_ms) = timeout_ms {
        payload.insert("timeoutMs".to_string(), json!(timeout_ms));
    }

    if !send_event_to_connection(
        state,
        &conn_id,
        "node.invoke.request",
        Value::Object(payload),
    ) {
        state.node_registry.lock().remove_pending_invoke(&invoke_id);
        return Err(error_shape(
            ERROR_UNAVAILABLE,
            "failed to send invoke to node",
            Some(json!({
                "details": {
                    "nodeId": node_id,
                    "command": command,
                    "nodeError": { "code": "UNAVAILABLE" }
                }
            })),
        ));
    }

    let timeout_ms = timeout_ms.unwrap_or(30_000);
    let result = match tokio::time::timeout(Duration::from_millis(timeout_ms), receiver).await {
        Ok(Ok(result)) => result,
        Ok(Err(_)) => NodeInvokeResult {
            ok: false,
            payload: None,
            payload_json: None,
            error: Some(NodeInvokeError {
                code: Some("UNAVAILABLE".to_string()),
                message: Some("node invoke failed".to_string()),
            }),
        },
        Err(_) => {
            state.node_registry.lock().remove_pending_invoke(&invoke_id);
            return Err(error_shape(
                ERROR_UNAVAILABLE,
                "node invoke timed out",
                Some(json!({
                    "details": { "code": "TIMEOUT", "nodeId": node_id, "command": command }
                })),
            ));
        }
    };

    if !result.ok {
        let error = result.error.unwrap_or(NodeInvokeError {
            code: None,
            message: None,
        });
        return Err(error_shape(
            ERROR_UNAVAILABLE,
            error.message.as_deref().unwrap_or("node invoke failed"),
            Some(json!({
                "details": {
                    "nodeId": node_id,
                    "command": command,
                    "nodeError": {
                        "code": error.code,
                        "message": error.message
                    }
                }
            })),
        ));
    }

    let payload = if let Some(payload_json) = result.payload_json.clone() {
        serde_json::from_str(&payload_json).unwrap_or(Value::Null)
    } else {
        result.payload.unwrap_or(Value::Null)
    };

    Ok(json!({
        "ok": true,
        "nodeId": node_id,
        "command": command,
        "payload": payload,
        "payloadJSON": result.payload_json
    }))
}

pub(crate) fn handle_node_invoke_result(
    params: Option<&Value>,
    state: &WsServerState,
    conn: &ConnectionContext,
) -> Result<Value, ErrorShape> {
    // This method is called by nodes to report results of invocations
    // Verify the node is paired and the connection is authorized
    if conn.role != "node" {
        return Err(error_shape(
            ERROR_INVALID_REQUEST,
            "only node connections can send invoke results",
            None,
        ));
    }

    let invoke_id = params
        .and_then(|v| v.get("id").or_else(|| v.get("invokeId")))
        .and_then(|v| v.as_str())
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "id is required", None))?;
    let node_id = params
        .and_then(|v| v.get("nodeId"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "nodeId is required", None))?;
    let ok = params
        .and_then(|v| v.get("ok"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let payload = params.and_then(|v| v.get("payload")).cloned();
    let payload_json = params
        .and_then(|v| v.get("payloadJSON"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let error = params
        .and_then(|v| v.get("error"))
        .and_then(|v| v.as_object());

    let caller_node_id = conn
        .device_id
        .as_ref()
        .or(Some(&conn.client.id))
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "node identity required", None))?;
    if caller_node_id != node_id {
        return Err(error_shape(ERROR_INVALID_REQUEST, "nodeId mismatch", None));
    }

    // Verify the node is paired
    if !state.node_pairing.is_paired(node_id) {
        return Err(error_shape(ERROR_NOT_PAIRED, "node not paired", None));
    }

    // Update last seen time
    state.node_pairing.touch_node(node_id);

    let result = NodeInvokeResult {
        ok,
        payload,
        payload_json,
        error: error.map(|err| NodeInvokeError {
            code: err
                .get("code")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            message: err
                .get("message")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
        }),
    };

    let resolved = state
        .node_registry
        .lock()
        .resolve_invoke(invoke_id, node_id, result);
    if !resolved {
        return Ok(json!({ "ok": true, "ignored": true }));
    }

    Ok(json!({ "ok": true }))
}

pub(crate) fn handle_node_event(
    params: Option<&Value>,
    state: &WsServerState,
    conn: &ConnectionContext,
) -> Result<Value, ErrorShape> {
    // This method is called by nodes to emit events
    if conn.role != "node" {
        return Err(error_shape(
            ERROR_INVALID_REQUEST,
            "only node connections can send events",
            None,
        ));
    }

    let caller_node_id = conn
        .device_id
        .as_ref()
        .or(Some(&conn.client.id))
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "node identity required", None))?;
    let node_id = params
        .and_then(|v| v.get("nodeId"))
        .and_then(|v| v.as_str())
        .unwrap_or(caller_node_id);
    if node_id != caller_node_id {
        return Err(error_shape(ERROR_INVALID_REQUEST, "nodeId mismatch", None));
    }
    let event = params
        .and_then(|v| v.get("event"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "event is required", None))?;
    let payload = params.and_then(|v| v.get("payload")).cloned();
    let payload_json = params
        .and_then(|v| v.get("payloadJSON"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    // Verify the node is paired
    if !state.node_pairing.is_paired(node_id) {
        return Err(error_shape(ERROR_NOT_PAIRED, "node not paired", None));
    }

    // Update last seen time
    state.node_pairing.touch_node(node_id);

    // Resolve the effective payload: prefer parsed payload, fall back to payloadJSON
    let effective_payload = if let Some(pj) = &payload_json {
        serde_json::from_str(pj).unwrap_or(Value::Null)
    } else {
        payload.clone().unwrap_or(Value::Null)
    };

    // Broadcast the node event to all operator connections
    broadcast_event(
        state,
        "node.event",
        json!({
            "nodeId": node_id,
            "event": event,
            "payload": effective_payload,
            "ts": now_ms()
        }),
    );

    Ok(json!({
        "ok": true,
        "nodeId": node_id,
        "event": event,
        "hasPayload": payload.is_some() || payload_json.is_some()
    }))
}
