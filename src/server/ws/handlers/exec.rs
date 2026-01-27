//! Exec approval handlers.
//!
//! This module implements the exec approval workflow:
//! - exec.approvals.get: Get the global exec approvals configuration
//! - exec.approvals.set: Set the global exec approvals configuration
//! - exec.approvals.node.get: Get exec approvals for a specific node
//! - exec.approvals.node.set: Set exec approvals for a specific node
//! - exec.approval.request: Request approval for a command (async, waits for decision)
//! - exec.approval.resolve: Resolve a pending approval request
//!
//! TODO(Package 1 coordination): The exec.approval.request and exec.approval.resolve
//! handlers need access to an ExecApprovalManager instance on WsServerState.
//! Add `exec_manager: Arc<ExecApprovalManager>` to WsServerState and update
//! the handler calls in dispatch_method to pass state and conn.

use serde_json::{json, Value};
use uuid::Uuid;

use super::super::*;

// Re-export types for use by other modules
pub use crate::exec::{
    ExecApprovalDecision, ExecApprovalManager, ExecApprovalRecord, ExecApprovalRequestPayload,
};

/// Default timeout for approval requests (2 minutes).
const DEFAULT_APPROVAL_TIMEOUT_MS: u64 = 120_000;

/// Get global exec approvals configuration.
///
/// This returns the exec approvals settings stored on the gateway.
/// In a full implementation, this would read from disk.
pub(super) fn handle_exec_approvals_get() -> Result<Value, ErrorShape> {
    // TODO: Implement reading from disk when exec approvals store is implemented
    Ok(json!({
        "path": null,
        "exists": false,
        "hash": null,
        "file": {
            "mode": "ask",
            "rules": []
        }
    }))
}

/// Set global exec approvals configuration.
///
/// This updates the exec approvals settings on the gateway.
/// Requires a baseHash parameter for optimistic concurrency control.
pub(super) fn handle_exec_approvals_set(params: Option<&Value>) -> Result<Value, ErrorShape> {
    let file = params
        .and_then(|v| v.get("file"))
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "file is required", None))?;

    // Validate file structure
    if !file.is_object() {
        return Err(error_shape(
            ERROR_INVALID_REQUEST,
            "file must be an object",
            None,
        ));
    }

    // TODO: Implement writing to disk when exec approvals store is implemented
    // For now, return the file as confirmation

    Ok(json!({
        "path": null,
        "exists": true,
        "hash": Uuid::new_v4().to_string(),
        "file": file.clone()
    }))
}

/// Get exec approvals for a specific node.
///
/// This proxies to the node to get its local exec approvals configuration.
pub(super) fn handle_exec_approvals_node_get(params: Option<&Value>) -> Result<Value, ErrorShape> {
    let node_id = params
        .and_then(|v| v.get("nodeId"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "nodeId is required", None))?;

    if node_id.trim().is_empty() {
        return Err(error_shape(
            ERROR_INVALID_REQUEST,
            "nodeId cannot be empty",
            None,
        ));
    }

    // TODO: Invoke system.execApprovals.get on the node
    // For now, return a placeholder response
    Ok(json!({
        "nodeId": node_id,
        "path": null,
        "exists": false,
        "hash": null,
        "file": {
            "mode": "ask",
            "rules": []
        }
    }))
}

/// Set exec approvals for a specific node.
///
/// This proxies to the node to update its local exec approvals configuration.
pub(super) fn handle_exec_approvals_node_set(params: Option<&Value>) -> Result<Value, ErrorShape> {
    let node_id = params
        .and_then(|v| v.get("nodeId"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "nodeId is required", None))?;

    if node_id.trim().is_empty() {
        return Err(error_shape(
            ERROR_INVALID_REQUEST,
            "nodeId cannot be empty",
            None,
        ));
    }

    let file = params
        .and_then(|v| v.get("file"))
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "file is required", None))?;

    if !file.is_object() {
        return Err(error_shape(
            ERROR_INVALID_REQUEST,
            "file must be an object",
            None,
        ));
    }

    // TODO: Invoke system.execApprovals.set on the node
    // For now, return the file as confirmation
    Ok(json!({
        "ok": true,
        "nodeId": node_id,
        "path": null,
        "exists": true,
        "hash": Uuid::new_v4().to_string(),
        "file": file.clone()
    }))
}

/// Request approval for a command execution.
///
/// This creates a pending approval request and broadcasts an exec.approval.requested event.
/// Returns immediately with the request ID; the caller should listen for the
/// exec.approval.resolved event or call exec.approval.resolve.
///
/// TODO(Package 1 coordination): This should be changed to:
/// ```ignore
/// pub(super) async fn handle_exec_approval_request(
///     params: Option<&Value>,
///     state: &WsServerState,
///     conn: &ConnectionContext,
/// ) -> Result<Value, ErrorShape>
/// ```
/// And use state.exec_manager to create and track the approval request.
///
/// Parameters:
/// - command: The command being requested (required)
/// - id: Optional explicit ID for the request
/// - cwd: Current working directory
/// - host: Host where command will run
/// - security: Security classification
/// - ask: Human-readable explanation
/// - agentId: The requesting agent's ID
/// - resolvedPath: Resolved path to command binary
/// - sessionKey: Associated session key
/// - timeoutMs: How long to wait for decision (default 120000)
pub(super) fn handle_exec_approval_request(params: Option<&Value>) -> Result<Value, ErrorShape> {
    let command = params
        .and_then(|v| v.get("command"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "command is required", None))?;

    if command.trim().is_empty() {
        return Err(error_shape(
            ERROR_INVALID_REQUEST,
            "command cannot be empty",
            None,
        ));
    }

    let explicit_id = params
        .and_then(|v| v.get("id"))
        .and_then(|v| v.as_str())
        .filter(|s| !s.trim().is_empty())
        .map(|s| s.trim().to_string());

    let request_id = explicit_id.unwrap_or_else(|| Uuid::new_v4().to_string());

    let timeout_ms = params
        .and_then(|v| v.get("timeoutMs"))
        .and_then(|v| v.as_u64())
        .unwrap_or(DEFAULT_APPROVAL_TIMEOUT_MS);

    let now = now_ms();

    // TODO(Package 1 coordination): Broadcast exec.approval.requested event
    // broadcast_event(state, "exec.approval.requested", json!({...}));

    // For now, return the request info immediately
    // In the full implementation, this would be async and wait for the decision
    Ok(json!({
        "id": request_id,
        "command": command,
        "createdAtMs": now,
        "expiresAtMs": now + timeout_ms,
        "decision": null,
        "status": "pending"
    }))
}

/// Resolve a pending approval request.
///
/// This resolves an existing approval request with a decision.
/// Broadcasts an exec.approval.resolved event.
///
/// TODO(Package 1 coordination): This should be changed to:
/// ```ignore
/// pub(super) fn handle_exec_approval_resolve(
///     params: Option<&Value>,
///     state: &WsServerState,
///     conn: &ConnectionContext,
/// ) -> Result<Value, ErrorShape>
/// ```
/// And use state.exec_manager to resolve the request.
///
/// Parameters:
/// - id: The approval request ID (required)
/// - decision: The decision - "allow-once", "allow-always", or "deny" (required)
pub(super) fn handle_exec_approval_resolve(params: Option<&Value>) -> Result<Value, ErrorShape> {
    let request_id = params
        .and_then(|v| v.get("id"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "id is required", None))?;

    if request_id.trim().is_empty() {
        return Err(error_shape(
            ERROR_INVALID_REQUEST,
            "id cannot be empty",
            None,
        ));
    }

    let decision_str = params
        .and_then(|v| v.get("decision"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "decision is required", None))?;

    let decision = ExecApprovalDecision::from_str(decision_str).ok_or_else(|| {
        error_shape(
            ERROR_INVALID_REQUEST,
            "invalid decision (must be allow-once, allow-always, or deny)",
            None,
        )
    })?;

    // TODO(Package 1 coordination):
    // 1. Use state.exec_manager.resolve(request_id, decision, Some(&resolved_by))
    // 2. Broadcast exec.approval.resolved event
    // broadcast_event(state, "exec.approval.resolved", json!({...}));

    Ok(json!({
        "ok": true,
        "id": request_id,
        "decision": decision.as_str()
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handle_exec_approvals_get() {
        let result = handle_exec_approvals_get();
        assert!(result.is_ok());
        let value = result.unwrap();
        assert_eq!(value["exists"], false);
    }

    #[test]
    fn test_handle_exec_approvals_set_requires_file() {
        let result = handle_exec_approvals_set(None);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code, ERROR_INVALID_REQUEST);

        let params = json!({});
        let result = handle_exec_approvals_set(Some(&params));
        assert!(result.is_err());
    }

    #[test]
    fn test_handle_exec_approvals_set_validates_file() {
        let params = json!({ "file": "not an object" });
        let result = handle_exec_approvals_set(Some(&params));
        assert!(result.is_err());

        let params = json!({ "file": { "mode": "ask", "rules": [] } });
        let result = handle_exec_approvals_set(Some(&params));
        assert!(result.is_ok());
    }

    #[test]
    fn test_handle_exec_approvals_node_get_requires_node_id() {
        let result = handle_exec_approvals_node_get(None);
        assert!(result.is_err());

        let params = json!({ "nodeId": "" });
        let result = handle_exec_approvals_node_get(Some(&params));
        assert!(result.is_err());

        let params = json!({ "nodeId": "node-1" });
        let result = handle_exec_approvals_node_get(Some(&params));
        assert!(result.is_ok());
        assert_eq!(result.unwrap()["nodeId"], "node-1");
    }

    #[test]
    fn test_handle_exec_approvals_node_set_requires_params() {
        let result = handle_exec_approvals_node_set(None);
        assert!(result.is_err());

        let params = json!({ "nodeId": "node-1" });
        let result = handle_exec_approvals_node_set(Some(&params));
        assert!(result.is_err()); // Missing file

        let params = json!({ "nodeId": "node-1", "file": { "mode": "ask" } });
        let result = handle_exec_approvals_node_set(Some(&params));
        assert!(result.is_ok());
    }

    #[test]
    fn test_handle_exec_approval_request_requires_command() {
        let result = handle_exec_approval_request(None);
        assert!(result.is_err());

        let params = json!({ "command": "" });
        let result = handle_exec_approval_request(Some(&params));
        assert!(result.is_err());

        let params = json!({ "command": "ls -la" });
        let result = handle_exec_approval_request(Some(&params));
        assert!(result.is_ok());
        let value = result.unwrap();
        assert_eq!(value["command"], "ls -la");
        assert_eq!(value["status"], "pending");
    }

    #[test]
    fn test_handle_exec_approval_request_uses_explicit_id() {
        let params = json!({ "command": "test", "id": "custom-id-123" });
        let result = handle_exec_approval_request(Some(&params));
        assert!(result.is_ok());
        assert_eq!(result.unwrap()["id"], "custom-id-123");
    }

    #[test]
    fn test_handle_exec_approval_resolve_requires_params() {
        let result = handle_exec_approval_resolve(None);
        assert!(result.is_err());

        let params = json!({ "id": "test-id" });
        let result = handle_exec_approval_resolve(Some(&params));
        assert!(result.is_err()); // Missing decision

        let params = json!({ "id": "", "decision": "allow-once" });
        let result = handle_exec_approval_resolve(Some(&params));
        assert!(result.is_err()); // Empty id
    }

    #[test]
    fn test_handle_exec_approval_resolve_validates_decision() {
        let params = json!({ "id": "test-id", "decision": "invalid" });
        let result = handle_exec_approval_resolve(Some(&params));
        assert!(result.is_err());

        let params = json!({ "id": "test-id", "decision": "allow-once" });
        let result = handle_exec_approval_resolve(Some(&params));
        assert!(result.is_ok());
        assert_eq!(result.unwrap()["decision"], "allow-once");

        let params = json!({ "id": "test-id", "decision": "allow-always" });
        let result = handle_exec_approval_resolve(Some(&params));
        assert!(result.is_ok());

        let params = json!({ "id": "test-id", "decision": "deny" });
        let result = handle_exec_approval_resolve(Some(&params));
        assert!(result.is_ok());
    }
}
