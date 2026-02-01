//! WebSocket handlers

use serde_json::{json, Value};

use super::*;

mod channels;
mod config;
mod cron;
mod device;
mod exec;
mod logs;
mod misc;
mod node;
pub(crate) mod sessions;
mod skills;
mod system;
mod talk;
mod tts;
mod update;
mod usage;
mod voicewake;
mod wizard;

use channels::*;
pub(super) use config::*;
pub(super) use cron::*;
use device::*;
pub(super) use exec::*;
use logs::*;
use misc::*;
pub(super) use node::*;
pub(super) use sessions::*;
use skills::*;
use system::*;
pub(super) use talk::*;
pub(super) use tts::*;
pub(super) use update::*;
pub(crate) use update::{apply_staged_update, cleanup_old_binaries};
pub(super) use usage::*;
pub(super) use voicewake::*;

// Re-export types needed outside the handlers module
pub(crate) use config::{
    broadcast_config_changed, map_validation_issues, persist_config_file, read_config_snapshot,
};
pub use sessions::AgentRunRegistry;
pub use sessions::AgentRunStatus;
pub use usage::record_usage;
pub(super) use wizard::*;

pub(super) fn handle_health() -> Value {
    json!({
        "ts": now_ms(),
        "status": "healthy"
    })
}

/// Build the full status JSON response payload.
fn build_status_response(state: &WsServerState) -> Value {
    let sessions = state
        .session_store
        .list_sessions(crate::sessions::SessionFilter::new())
        .unwrap_or_default();
    let recent_sessions = sessions
        .iter()
        .take(10)
        .map(|session| {
            json!({
                "sessionId": session.id,
                "key": session.session_key,
                "updatedAt": session.updated_at
            })
        })
        .collect::<Vec<_>>();
    json!({
        "ts": now_ms(),
        "status": "ok",
        "uptimeMs": state.start_time.elapsed().as_millis() as u64,
        "version": env!("CARGO_PKG_VERSION"),
        "runtime": {
            "name": "carapace",
            "platform": std::env::consts::OS,
            "arch": std::env::consts::ARCH
        },
        "channels": {
            "total": state.channel_registry.len(),
            "connected": state
                .channel_registry
                .count_by_status(crate::channels::ChannelStatus::Connected)
        },
        "sessions": {
            "count": sessions.len(),
            "recent": recent_sessions
        }
    })
}

pub(super) fn handle_status(state: &WsServerState) -> Value {
    build_status_response(state)
}

pub(super) fn canonicalize_ws_method_name(method: &str) -> &str {
    match method {
        "agent.run" => "agent",
        "agent.cancel" => "chat.abort",
        "session.list" => "sessions.list",
        "session.preview" => "sessions.preview",
        "session.patch" => "sessions.patch",
        "session.reset" => "sessions.reset",
        "session.delete" => "sessions.delete",
        "session.compact" => "sessions.compact",
        "session.archive" => "sessions.archive",
        "session.restore" => "sessions.restore",
        "session.archives" => "sessions.archives",
        "session.archive.delete" => "sessions.archive.delete",
        "session.export_user" => "sessions.export_user",
        "session.purge_user" => "sessions.purge_user",
        "config.update" => "config.patch",
        "exec.list" | "exec.approvals.list" => "exec.approvals.get",
        "exec.approve" | "exec.deny" => "exec.approval.resolve",
        _ => method,
    }
}

fn with_decision_override(params: Option<&Value>, decision: &str) -> Option<Value> {
    let mut value = params.cloned().unwrap_or_else(|| json!({}));
    if let Value::Object(ref mut map) = value {
        map.entry("decision".to_string())
            .or_insert_with(|| Value::String(decision.to_string()));
    }
    Some(value)
}

fn normalize_ws_request<'a>(method: &'a str, params: Option<&Value>) -> (&'a str, Option<Value>) {
    let canonical = canonicalize_ws_method_name(method);
    let params = match method {
        "exec.approve" => with_decision_override(params, "allow-once"),
        "exec.deny" => with_decision_override(params, "deny"),
        _ => None,
    };
    (canonical, params)
}

/// Methods exclusively for the `node` role
///
/// These methods can ONLY be called by node connections.
/// Non-node roles are explicitly blocked from calling these.
/// This matches Node.js gateway behavior in src/gateway/server-methods.ts.
pub(super) const NODE_ONLY_METHODS: [&str; 3] = ["node.invoke.result", "node.event", "skills.bins"];

/// Methods that require operator.admin scope for operator role
///
/// Per Node.js gateway: config.*, wizard.*, update.*, skills.install/update,
/// channels.logout, sessions.*, and cron.* require operator.admin for operators.
const OPERATOR_ADMIN_REQUIRED_METHODS: [&str; 39] = [
    "config.get",
    "config.set",
    "config.apply",
    "config.patch",
    "config.validate",
    "config.schema",
    "config.reload",
    "sessions.patch",
    "sessions.reset",
    "sessions.delete",
    "sessions.compact",
    "sessions.archive",
    "sessions.restore",
    "sessions.archives",
    "sessions.archive.delete",
    "sessions.export_user",
    "sessions.purge_user",
    // All wizard.* methods
    "wizard.start",
    "wizard.next",
    "wizard.back",
    "wizard.cancel",
    "wizard.status",
    "wizard.list",
    // All update.* methods
    "update.run",
    "update.check",
    "update.status",
    "update.setChannel",
    "update.configure",
    "update.install",
    "update.dismiss",
    "update.releaseNotes",
    // Skills
    "skills.install",
    "skills.update",
    // Cron
    "cron.add",
    "cron.update",
    "cron.remove",
    "cron.run",
    // Channels
    "channels.logout",
    // System
    "system-event",
];

/// Read-only methods (any authenticated role).
const READ_METHODS: &[&str] = &[
    "health",
    "status",
    "last-heartbeat",
    "config.get",
    "config.validate",
    "config.schema",
    "sessions.list",
    "sessions.preview",
    "sessions.archives",
    "channels.status",
    "agent.identity.get",
    "chat.history",
    "tts.status",
    "tts.providers",
    "tts.voices",
    "voicewake.get",
    "voicewake.keywords",
    "wizard.status",
    "wizard.list",
    "talk.status",
    "talk.devices",
    "models.list",
    "agents.list",
    "skills.status",
    "cron.status",
    "cron.list",
    "cron.runs",
    "node.list",
    "node.describe",
    "node.pair.list",
    "device.pair.list",
    "exec.approvals.get",
    "exec.approvals.node.get",
    "usage.status",
    "usage.cost",
    "usage.session",
    "usage.providers",
    "usage.daily",
    "update.status",
    "update.releaseNotes",
    "logs.tail",
    "system-presence",
];

/// Write methods (requires write or admin role).
const WRITE_METHODS: &[&str] = &[
    "config.set",
    "config.apply",
    "config.patch",
    "sessions.patch",
    "sessions.reset",
    "sessions.delete",
    "sessions.compact",
    "sessions.archive",
    "sessions.restore",
    "sessions.archive.delete",
    "channels.logout",
    "agent",
    "agent.wait",
    "chat.send",
    "chat.abort",
    "tts.enable",
    "tts.disable",
    "tts.convert",
    "tts.setProvider",
    "tts.setVoice",
    "tts.configure",
    "tts.speak",
    "tts.stop",
    "voicewake.set",
    "voicewake.enable",
    "voicewake.disable",
    "voicewake.test",
    "wizard.start",
    "wizard.next",
    "wizard.back",
    "wizard.cancel",
    "talk.mode",
    "talk.start",
    "talk.stop",
    "talk.configure",
    "skills.install",
    "skills.update",
    "update.run",
    "update.check",
    "update.setChannel",
    "update.configure",
    "update.install",
    "update.dismiss",
    "usage.enable",
    "usage.disable",
    "usage.reset",
    "cron.add",
    "cron.update",
    "cron.remove",
    "cron.run",
    "node.invoke",
    "set-heartbeats",
    "wake",
    "send",
];

/// Admin methods (requires admin role, or operator with specific scopes).
const ADMIN_METHODS: &[&str] = &[
    "system-event",
    "config.reload",
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
];

/// Method authorization levels
///
/// Methods are categorized by the minimum role required to call them:
/// - read: health, status, list operations (any authenticated connection)
/// - write: session modifications, agent invocations
/// - admin: device pairing, exec approvals, sensitive operations
///
/// Note: For operators, additional scope checks are applied separately.
pub(super) fn get_method_required_role(method: &str) -> &'static str {
    if READ_METHODS.contains(&method) {
        "read"
    } else if WRITE_METHODS.contains(&method) {
        "write"
    } else if ADMIN_METHODS.contains(&method) {
        "admin"
    } else {
        // Unknown methods default to admin (fail secure)
        "admin"
    }
}

/// Get the required scope for admin-level methods (for operator role)
///
/// These are methods that require a specific scope beyond operator.admin.
/// Operators can call these with the specific scope without needing full operator.admin.
pub(super) fn get_method_specific_scope(method: &str) -> Option<&'static str> {
    match method {
        // Pairing operations require operator.pairing scope
        "device.pair.approve"
        | "device.pair.reject"
        | "device.token.rotate"
        | "device.token.revoke"
        | "node.pair.request"
        | "node.pair.approve"
        | "node.pair.reject"
        | "node.pair.verify"
        | "node.rename" => Some("operator.pairing"),

        // Exec approval operations require operator.approvals scope
        "exec.approvals.set"
        | "exec.approvals.node.set"
        | "exec.approval.request"
        | "exec.approval.resolve" => Some("operator.approvals"),

        // All other methods don't have a specific scope override
        _ => None,
    }
}

/// Check if a role satisfies the required role level
///
/// Role hierarchy: admin > operator > write > read
pub(super) fn role_satisfies(has_role: &str, required_role: &str) -> bool {
    match required_role {
        "read" => true, // Any role satisfies read
        "write" => matches!(has_role, "write" | "admin" | "operator"),
        "admin" => has_role == "admin",
        _ => false,
    }
}

/// Check if scopes satisfy the required scope
pub(super) fn scope_satisfies(scopes: &[String], required_scope: &str) -> bool {
    for scope in scopes {
        // Exact match
        if scope == required_scope {
            return true;
        }

        // Wildcard: operator.* covers all operator scopes
        if scope == "operator.*" && required_scope.starts_with("operator.") {
            return true;
        }

        // operator.admin covers all operator scopes
        if scope == "operator.admin" && required_scope.starts_with("operator.") {
            return true;
        }

        // operator.write covers operator.read
        if scope == "operator.write" && required_scope == "operator.read" {
            return true;
        }
    }

    false
}

/// Check if the connection is authorized to call a method
///
/// Authorization flow (matching Node.js gateway):
/// 1. Block node-only methods for non-node roles
/// 2. Node role: only allow node-only methods
/// 3. Admin role: full access
/// 4. Operator role: check scopes per method requirements
/// 5. Other roles: check role hierarchy
pub(super) fn check_method_authorization(
    method: &str,
    conn: &ConnectionContext,
) -> Result<(), ErrorShape> {
    // Block node-only methods for non-node roles
    if NODE_ONLY_METHODS.contains(&method) && conn.role != "node" {
        return Err(error_shape(
            ERROR_INVALID_REQUEST,
            &format!("method '{}' is only allowed for node role", method),
            Some(json!({
                "method": method,
                "connection_role": conn.role,
                "required_role": "node"
            })),
        ));
    }

    // Node role: only allow node-only methods
    if conn.role == "node" {
        if NODE_ONLY_METHODS.contains(&method) {
            return Ok(());
        }
        return Err(error_shape(
            ERROR_INVALID_REQUEST,
            &format!(
                "method '{}' not allowed for node role (allowed: {:?})",
                method, NODE_ONLY_METHODS
            ),
            Some(json!({
                "method": method,
                "connection_role": "node",
                "allowed_methods": NODE_ONLY_METHODS
            })),
        ));
    }

    // Admin role: full access
    if conn.role == "admin" {
        return Ok(());
    }

    let required_role = get_method_required_role(method);

    // Operator role: check scopes per Node.js gateway model
    if conn.role == "operator" {
        return check_operator_authorization(method, required_role, conn);
    }

    // Other roles: check role hierarchy
    if !role_satisfies(&conn.role, required_role) {
        return Err(error_shape(
            ERROR_INVALID_REQUEST,
            &format!(
                "method '{}' requires role '{}', connection has role '{}'",
                method, required_role, conn.role
            ),
            Some(json!({
                "method": method,
                "required_role": required_role,
                "connection_role": conn.role
            })),
        ));
    }

    Ok(())
}

/// Check operator authorization with scope-based access control
///
/// Per Node.js gateway:
/// - operator.admin required for: config.*, wizard.*, update.*, skills.install/update, channels.logout
/// - operator.pairing allows: device pairing methods (without needing operator.admin)
/// - operator.approvals allows: exec approval methods (without needing operator.admin)
/// - operator.write required for write-level methods
/// - operator.read required for read-level methods
fn check_operator_authorization(
    method: &str,
    required_role: &str,
    conn: &ConnectionContext,
) -> Result<(), ErrorShape> {
    // Check if method requires operator.admin (config.*, wizard.*, etc.)
    if OPERATOR_ADMIN_REQUIRED_METHODS.contains(&method) {
        if !scope_satisfies(&conn.scopes, "operator.admin") {
            return Err(error_shape(
                ERROR_INVALID_REQUEST,
                &format!("method '{}' requires 'operator.admin' scope", method),
                Some(json!({
                    "method": method,
                    "required_scope": "operator.admin",
                    "connection_scopes": conn.scopes
                })),
            ));
        }
        return Ok(());
    }

    // Check if method has a specific scope that can bypass operator.admin
    // E.g., operator.pairing allows device.pair.* without full admin
    if let Some(specific_scope) = get_method_specific_scope(method) {
        if scope_satisfies(&conn.scopes, specific_scope) {
            return Ok(());
        }
        // Also allow if they have operator.admin
        if scope_satisfies(&conn.scopes, "operator.admin") {
            return Ok(());
        }
        return Err(error_shape(
            ERROR_INVALID_REQUEST,
            &format!(
                "method '{}' requires '{}' or 'operator.admin' scope",
                method, specific_scope
            ),
            Some(json!({
                "method": method,
                "required_scope": specific_scope,
                "connection_scopes": conn.scopes
            })),
        ));
    }

    // Check scope based on required role level
    match required_role {
        "write" => {
            if !scope_satisfies(&conn.scopes, "operator.write") {
                return Err(error_shape(
                    ERROR_INVALID_REQUEST,
                    &format!("method '{}' requires 'operator.write' scope", method),
                    Some(json!({
                        "method": method,
                        "required_scope": "operator.write",
                        "connection_scopes": conn.scopes
                    })),
                ));
            }
        }
        "read" => {
            if !scope_satisfies(&conn.scopes, "operator.read") {
                return Err(error_shape(
                    ERROR_INVALID_REQUEST,
                    &format!("method '{}' requires 'operator.read' scope", method),
                    Some(json!({
                        "method": method,
                        "required_scope": "operator.read",
                        "connection_scopes": conn.scopes
                    })),
                ));
            }
        }
        "admin" => {
            // Admin methods that don't have specific scopes require operator.admin
            if !scope_satisfies(&conn.scopes, "operator.admin") {
                return Err(error_shape(
                    ERROR_INVALID_REQUEST,
                    &format!("method '{}' requires 'operator.admin' scope", method),
                    Some(json!({
                        "method": method,
                        "required_scope": "operator.admin",
                        "connection_scopes": conn.scopes
                    })),
                ));
            }
        }
        _ => {
            // Unknown role level, fail secure
            return Err(error_shape(
                ERROR_INVALID_REQUEST,
                &format!(
                    "method '{}' has unknown required role '{}'",
                    method, required_role
                ),
                Some(json!({
                    "method": method,
                    "required_role": required_role
                })),
            ));
        }
    }

    Ok(())
}

/// Dispatch config methods.
fn dispatch_config(
    method: &str,
    params: Option<&Value>,
    state: &Arc<WsServerState>,
) -> Option<Result<Value, ErrorShape>> {
    match method {
        "config.get" => Some(handle_config_get(params)),
        "config.set" => Some(handle_config_set(params)),
        "config.apply" => Some(handle_config_apply(params)),
        "config.patch" => Some(handle_config_patch(params)),
        "config.validate" => Some(handle_config_validate(params)),
        "config.schema" => Some(handle_config_schema()),
        "config.reload" => Some(handle_config_reload(state)),
        _ => None,
    }
}

/// Dispatch session methods.
fn dispatch_sessions(
    method: &str,
    params: Option<&Value>,
    state: &Arc<WsServerState>,
) -> Option<Result<Value, ErrorShape>> {
    match method {
        "sessions.list" => Some(handle_sessions_list(state, params)),
        "sessions.preview" => Some(handle_sessions_preview(state, params)),
        "sessions.patch" => Some(handle_sessions_patch(state, params)),
        "sessions.reset" => Some(handle_sessions_reset(state, params)),
        "sessions.delete" => Some(handle_sessions_delete(state, params)),
        "sessions.compact" => Some(handle_sessions_compact(state, params)),
        "sessions.archive" => Some(handle_sessions_archive(state, params)),
        "sessions.restore" => Some(handle_sessions_restore(state, params)),
        "sessions.archives" => Some(handle_sessions_archives(state, params)),
        "sessions.archive.delete" => Some(handle_sessions_archive_delete(state, params)),
        "sessions.export_user" => Some(handle_sessions_export_user(state, params)),
        "sessions.purge_user" => Some(handle_sessions_purge_user(state, params)),
        _ => None,
    }
}

/// Dispatch TTS and voice wake methods.
fn dispatch_tts_voice(
    method: &str,
    params: Option<&Value>,
    state: &Arc<WsServerState>,
) -> Option<Result<Value, ErrorShape>> {
    match method {
        "tts.status" => Some(handle_tts_status()),
        "tts.providers" => Some(handle_tts_providers()),
        "tts.voices" => Some(handle_tts_voices()),
        "tts.enable" => Some(handle_tts_enable()),
        "tts.disable" => Some(handle_tts_disable()),
        "tts.setProvider" => Some(handle_tts_set_provider(params)),
        "tts.setVoice" => Some(handle_tts_set_voice(params)),
        "tts.configure" => Some(handle_tts_configure(params)),
        "tts.stop" => Some(handle_tts_stop()),
        "voicewake.get" => Some(handle_voicewake_get()),
        "voicewake.set" => Some(handle_voicewake_set(params, Some(state))),
        "voicewake.enable" => Some(handle_voicewake_enable(params)),
        "voicewake.disable" => Some(handle_voicewake_disable()),
        "voicewake.keywords" => Some(handle_voicewake_keywords()),
        "voicewake.test" => Some(handle_voicewake_test(params)),
        _ => None,
    }
}

/// Dispatch node and device pairing methods.
fn dispatch_node_device(
    method: &str,
    params: Option<&Value>,
    state: &Arc<WsServerState>,
    conn: &ConnectionContext,
) -> Option<Result<Value, ErrorShape>> {
    match method {
        "node.pair.request" => Some(handle_node_pair_request(params, state)),
        "node.pair.list" => Some(handle_node_pair_list(state)),
        "node.pair.approve" => Some(handle_node_pair_approve(params, state)),
        "node.pair.reject" => Some(handle_node_pair_reject(params, state)),
        "node.pair.verify" => Some(handle_node_pair_verify(params, state)),
        "node.rename" => Some(handle_node_rename(params, state)),
        "node.list" => Some(handle_node_list(state)),
        "node.describe" => Some(handle_node_describe(params, state)),
        "node.invoke.result" => Some(handle_node_invoke_result(params, state, conn)),
        "node.event" => Some(handle_node_event(params, state, conn)),
        "device.pair.list" => Some(handle_device_pair_list(state)),
        "device.pair.approve" => Some(handle_device_pair_approve(params, state)),
        "device.pair.reject" => Some(handle_device_pair_reject(params, state)),
        "device.token.rotate" => Some(handle_device_token_rotate(params, state)),
        "device.token.revoke" => Some(handle_device_token_revoke(params, state)),
        _ => None,
    }
}

/// Dispatch cron, usage, and update methods (sync only).
fn dispatch_cron_usage_update(
    method: &str,
    params: Option<&Value>,
    state: &Arc<WsServerState>,
) -> Option<Result<Value, ErrorShape>> {
    match method {
        "cron.status" => Some(handle_cron_status(state)),
        "cron.list" => Some(handle_cron_list(state, params)),
        "cron.add" => Some(handle_cron_add(state, params)),
        "cron.update" => Some(handle_cron_update(state, params)),
        "cron.remove" => Some(handle_cron_remove(state, params)),
        "cron.run" => Some(handle_cron_run(state.clone(), params)),
        "cron.runs" => Some(handle_cron_runs(state, params)),
        "usage.status" => Some(handle_usage_status()),
        "usage.enable" => Some(handle_usage_enable()),
        "usage.disable" => Some(handle_usage_disable()),
        "usage.cost" => Some(handle_usage_cost(params)),
        "usage.session" => Some(handle_usage_session(params)),
        "usage.providers" => Some(handle_usage_providers()),
        "usage.daily" => Some(handle_usage_daily(params)),
        "usage.reset" => Some(handle_usage_reset(params)),
        "update.status" => Some(handle_update_status()),
        "update.setChannel" => Some(handle_update_set_channel(params)),
        "update.configure" => Some(handle_update_configure(params)),
        "update.dismiss" => Some(handle_update_dismiss()),
        "update.releaseNotes" => Some(handle_update_release_notes()),
        _ => None,
    }
}

pub(super) async fn dispatch_method(
    method: &str,
    params: Option<&Value>,
    state: &Arc<WsServerState>,
    conn: &ConnectionContext,
) -> Result<Value, ErrorShape> {
    let original_method = method;
    let (method, params_override) = normalize_ws_request(method, params);
    let params = params_override.as_ref().or(params);

    // Check authorization before dispatching
    check_method_authorization(method, conn)?;

    // Health/status
    match method {
        "health" => return Ok(handle_health()),
        "status" => return Ok(handle_status(state)),
        _ => {}
    }

    // Sync sub-dispatchers
    if let Some(result) = dispatch_config(method, params, state) {
        return result;
    }
    if let Some(result) = dispatch_sessions(method, params, state) {
        return result;
    }
    if let Some(result) = dispatch_tts_voice(method, params, state) {
        return result;
    }
    if let Some(result) = dispatch_node_device(method, params, state, conn) {
        return result;
    }
    if let Some(result) = dispatch_cron_usage_update(method, params, state) {
        return result;
    }

    // Remaining methods (async or unique signatures)
    match method {
        // Channels
        "channels.status" => handle_channels_status(state),
        "channels.logout" => handle_channels_logout(params, state),

        // Agent
        "agent" => handle_agent(params, state.clone(), conn),
        "agent.identity.get" => handle_agent_identity_get(params),
        "agent.wait" => handle_agent_wait(params, state).await,

        // Chat
        "chat.history" => handle_chat_history(state, params),
        "chat.send" => handle_chat_send(state.clone(), params, conn),
        "chat.abort" => handle_chat_abort(state, params),

        // TTS async
        "tts.convert" => handle_tts_convert(params).await,
        "tts.speak" => handle_tts_speak(params).await,

        // Wizard
        "wizard.start" => handle_wizard_start(params),
        "wizard.next" => handle_wizard_next(params),
        "wizard.back" => handle_wizard_back(params),
        "wizard.cancel" => handle_wizard_cancel(params),
        "wizard.status" => handle_wizard_status(params),
        "wizard.list" => handle_wizard_list(),

        // Talk mode
        "talk.mode" => handle_talk_mode(params),
        "talk.status" => handle_talk_status(),
        "talk.start" => handle_talk_start(params),
        "talk.stop" => handle_talk_stop(),
        "talk.configure" => handle_talk_configure(params),
        "talk.devices" => handle_talk_devices(),

        // Models/agents/skills
        "models.list" => handle_models_list(),
        "agents.list" => handle_agents_list(),
        "skills.status" => handle_skills_status(),
        "skills.bins" => handle_skills_bins(),
        "skills.install" => handle_skills_install(params),
        "skills.update" => handle_skills_update(params),

        // Update (async)
        "update.run" => handle_update_run(params).await,
        "update.check" => handle_update_check().await,
        "update.install" => handle_update_install().await,

        // Node invoke (async)
        "node.invoke" => handle_node_invoke(params, state).await,

        // Exec approvals (mixed sync/async)
        "exec.approvals.get" => handle_exec_approvals_get(),
        "exec.approvals.set" => handle_exec_approvals_set(params),
        "exec.approvals.node.get" => handle_exec_approvals_node_get(params, state).await,
        "exec.approvals.node.set" => handle_exec_approvals_node_set(params, state).await,
        "exec.approval.request" => handle_exec_approval_request(params, state).await,
        "exec.approval.resolve" => handle_exec_approval_resolve(params, state),

        // Logs
        "logs.tail" => handle_logs_tail(params),

        // Misc
        "last-heartbeat" => handle_last_heartbeat(),
        "set-heartbeats" => handle_set_heartbeats(params),
        "wake" => handle_wake(params),
        "send" => handle_send(state, params, conn),
        "system-presence" => handle_system_presence(state),
        "system-event" => handle_system_event(params, state, conn),

        _ => Err(error_shape(
            ERROR_UNAVAILABLE,
            "method unavailable",
            Some(json!({ "method": original_method })),
        )),
    }
}
