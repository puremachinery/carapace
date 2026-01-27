//! Device pairing handlers.

use serde_json::{json, Value};

use super::super::*;

pub(super) fn handle_device_pair_list(state: &WsServerState) -> Result<Value, ErrorShape> {
    let (pending_requests, _resolved) = state.device_registry.list_requests();
    let paired_devices = state.device_registry.list_paired_devices();

    let pending = pending_requests
        .iter()
        .map(|req| {
            json!({
                "requestId": req.request_id,
                "deviceId": req.device_id,
                "publicKey": req.public_key,
                "displayName": req.display_name,
                "platform": req.platform,
                "clientId": req.client_id,
                "clientMode": req.client_mode,
                "role": req.role,
                "roles": req.requested_roles,
                "scopes": req.requested_scopes,
                "remoteIp": req.remote_ip,
                "silent": req.silent,
                "isRepair": req.is_repair,
                "ts": req.created_at_ms
            })
        })
        .collect::<Vec<_>>();

    let paired = paired_devices
        .iter()
        .map(|device| {
            json!({
                "deviceId": device.device_id,
                "publicKey": device.public_key,
                "displayName": device.display_name,
                "platform": device.platform,
                "clientId": device.client_id,
                "clientMode": device.client_mode,
                "remoteIp": device.remote_ip,
                "roles": device.roles,
                "scopes": device.scopes,
                "createdAtMs": device.paired_at_ms,
                "approvedAtMs": device.paired_at_ms,
                "lastSeenAtMs": device.last_seen_ms
            })
        })
        .collect::<Vec<_>>();

    Ok(json!({ "pending": pending, "paired": paired }))
}

pub(super) fn handle_device_pair_approve(
    params: Option<&Value>,
    state: &WsServerState,
) -> Result<Value, ErrorShape> {
    let request_id = params
        .and_then(|v| v.get("requestId"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "requestId is required", None))?;

    let request = state
        .device_registry
        .get_request(request_id)
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "request not found", None))?;

    let (device, _token) = state
        .device_registry
        .approve_request(
            request_id,
            request.requested_roles,
            request.requested_scopes,
        )
        .map_err(|e| match e {
            devices::DevicePairingError::RequestNotFound => {
                error_shape(ERROR_INVALID_REQUEST, "request not found", None)
            }
            devices::DevicePairingError::RequestAlreadyResolved => {
                error_shape(ERROR_INVALID_REQUEST, "request already resolved", None)
            }
            devices::DevicePairingError::RequestExpired => {
                error_shape(ERROR_INVALID_REQUEST, "request expired", None)
            }
            _ => error_shape(ERROR_UNAVAILABLE, &e.to_string(), None),
        })?;

    broadcast_event(
        state,
        "device.pair.resolved",
        json!({
            "requestId": request_id,
            "deviceId": device.device_id,
            "decision": "approved",
            "ts": now_ms()
        }),
    );

    Ok(json!({
        "requestId": request_id,
        "device": {
            "deviceId": device.device_id,
            "publicKey": device.public_key,
            "displayName": device.display_name,
            "platform": device.platform,
            "clientId": device.client_id,
            "roles": device.roles,
            "scopes": device.scopes,
            "createdAtMs": device.paired_at_ms,
            "approvedAtMs": device.paired_at_ms,
            "lastSeenAtMs": device.last_seen_ms
        }
    }))
}

pub(super) fn handle_device_pair_reject(
    params: Option<&Value>,
    state: &WsServerState,
) -> Result<Value, ErrorShape> {
    let request_id = params
        .and_then(|v| v.get("requestId"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "requestId is required", None))?;
    let request = state
        .device_registry
        .reject_request(request_id, None)
        .map_err(|e| match e {
            devices::DevicePairingError::RequestNotFound => {
                error_shape(ERROR_INVALID_REQUEST, "request not found", None)
            }
            devices::DevicePairingError::RequestAlreadyResolved => {
                error_shape(ERROR_INVALID_REQUEST, "request already resolved", None)
            }
            _ => error_shape(ERROR_UNAVAILABLE, &e.to_string(), None),
        })?;

    broadcast_event(
        state,
        "device.pair.resolved",
        json!({
            "requestId": request_id,
            "deviceId": request.device_id,
            "decision": "rejected",
            "ts": now_ms()
        }),
    );

    Ok(json!({
        "requestId": request_id,
        "deviceId": request.device_id
    }))
}

pub(super) fn handle_device_token_rotate(
    params: Option<&Value>,
    state: &WsServerState,
) -> Result<Value, ErrorShape> {
    let device_id = params
        .and_then(|v| v.get("deviceId"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "deviceId is required", None))?;
    let role = params
        .and_then(|v| v.get("role"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "role is required", None))?;
    let scopes = params
        .and_then(|v| v.get("scopes"))
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect::<Vec<_>>()
        });
    let scopes = match scopes {
        Some(scopes) => scopes,
        None => state
            .device_registry
            .latest_token_scopes(device_id, role)
            .or_else(|| {
                state
                    .device_registry
                    .get_paired_device(device_id)
                    .map(|device| device.scopes)
            })
            .unwrap_or_default(),
    };

    let meta = state
        .device_registry
        .rotate_token(device_id, role.to_string(), scopes)
        .map_err(|e| match e {
            devices::DevicePairingError::DeviceNotPaired => {
                error_shape(ERROR_INVALID_REQUEST, "unknown deviceId/role", None)
            }
            devices::DevicePairingError::RoleNotAllowed => {
                error_shape(ERROR_INVALID_REQUEST, "role not allowed", None)
            }
            devices::DevicePairingError::ScopeNotAllowed => {
                error_shape(ERROR_INVALID_REQUEST, "scope not allowed", None)
            }
            _ => error_shape(ERROR_UNAVAILABLE, &e.to_string(), None),
        })?;

    Ok(json!({
        "deviceId": device_id,
        "role": role,
        "token": meta.token,
        "scopes": meta.scopes,
        "rotatedAtMs": meta.issued_at_ms
    }))
}

pub(super) fn handle_device_token_revoke(
    params: Option<&Value>,
    state: &WsServerState,
) -> Result<Value, ErrorShape> {
    let device_id = params
        .and_then(|v| v.get("deviceId"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "deviceId is required", None))?;
    let role = params
        .and_then(|v| v.get("role"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "role is required", None))?;

    let revoked_at_ms = state
        .device_registry
        .revoke_token(device_id, role)
        .map_err(|e| match e {
            devices::DevicePairingError::DeviceNotPaired => {
                error_shape(ERROR_INVALID_REQUEST, "unknown deviceId/role", None)
            }
            devices::DevicePairingError::TokenInvalid => {
                error_shape(ERROR_INVALID_REQUEST, "unknown deviceId/role", None)
            }
            _ => error_shape(ERROR_UNAVAILABLE, &e.to_string(), None),
        })?;

    Ok(json!({
        "deviceId": device_id,
        "role": role,
        "revokedAtMs": revoked_at_ms
    }))
}
