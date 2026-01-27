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
mod sessions;
mod skills;
mod system;
mod talk;
mod tts;
mod update;
mod usage;
mod voicewake;
mod wizard;

pub(super) use channels::*;
pub(super) use config::*;
pub(super) use cron::*;
pub(super) use device::*;
pub(super) use exec::*;
pub(super) use logs::*;
pub(super) use misc::*;
pub(super) use node::*;
pub(super) use sessions::*;
pub(super) use skills::*;
pub(super) use system::*;
pub(super) use talk::*;
pub(super) use tts::*;
pub(super) use update::*;
pub(super) use usage::*;
pub(super) use voicewake::*;

// Re-export AgentRunRegistry for use in WsServerState
pub use sessions::AgentRunRegistry;
pub(super) use wizard::*;

pub(super) fn handle_health() -> Value {
    json!({
        "ts": now_ms(),
        "status": "healthy"
    })
}

pub(super) fn handle_status(state: &WsServerState) -> Value {
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
            "name": "rusty-clawd",
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
const OPERATOR_ADMIN_REQUIRED_METHODS: [&str; 31] = [
    "config.get",
    "config.set",
    "config.apply",
    "config.patch",
    "config.schema",
    "sessions.patch",
    "sessions.reset",
    "sessions.delete",
    "sessions.compact",
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

/// Method authorization levels
///
/// Methods are categorized by the minimum role required to call them:
/// - read: health, status, list operations (any authenticated connection)
/// - write: session modifications, agent invocations
/// - admin: device pairing, exec approvals, sensitive operations
///
/// Note: For operators, additional scope checks are applied separately.
fn get_method_required_role(method: &str) -> &'static str {
    match method {
        // Read-only operations (any authenticated role)
        "health"
        | "status"
        | "last-heartbeat"
        | "config.get"
        | "config.schema"
        | "sessions.list"
        | "sessions.preview"
        | "channels.status"
        | "agent.identity.get"
        | "chat.history"
        | "tts.status"
        | "tts.providers"
        | "tts.voices"
        | "voicewake.get"
        | "voicewake.keywords"
        | "wizard.status"
        | "wizard.list"
        | "talk.status"
        | "talk.devices"
        | "models.list"
        | "agents.list"
        | "skills.status"
        | "cron.status"
        | "cron.list"
        | "cron.runs"
        | "node.list"
        | "node.describe"
        | "node.pair.list"
        | "device.pair.list"
        | "exec.approvals.get"
        | "exec.approvals.node.get"
        | "usage.status"
        | "usage.cost"
        | "usage.session"
        | "usage.providers"
        | "usage.daily"
        | "update.status"
        | "update.releaseNotes"
        | "logs.tail" => "read",

        // Write operations (requires write or admin role)
        "config.set" | "config.apply" | "config.patch" | "sessions.patch" | "sessions.reset"
        | "sessions.delete" | "sessions.compact" | "channels.logout" | "agent" | "agent.wait"
        | "chat.send" | "chat.abort" | "tts.enable" | "tts.disable" | "tts.convert"
        | "tts.setProvider" | "tts.setVoice" | "tts.configure" | "tts.speak" | "tts.stop"
        | "voicewake.set" | "voicewake.enable" | "voicewake.disable" | "voicewake.test"
        | "wizard.start" | "wizard.next" | "wizard.back" | "wizard.cancel"
        | "talk.mode" | "talk.start" | "talk.stop" | "talk.configure"
        | "skills.install" | "skills.update"
        | "update.run" | "update.check" | "update.setChannel" | "update.configure"
        | "update.install" | "update.dismiss"
        | "usage.enable" | "usage.disable" | "usage.reset"
        | "cron.add" | "cron.update" | "cron.remove" | "cron.run" | "node.invoke"
        | "set-heartbeats" | "wake" | "send" => "write",

        // system-presence is read-only (lists system presence)
        "system-presence" => "read",

        // system-event is admin-only (can trigger system events)
        "system-event" => "admin",

        // Admin operations (requires admin role, or operator with specific scopes)
        "device.pair.approve"
        | "device.pair.reject"
        | "device.token.rotate"
        | "device.token.revoke"
        | "node.pair.request"
        | "node.pair.approve"
        | "node.pair.reject"
        | "node.pair.verify"
        | "node.rename"
        | "exec.approvals.set"
        | "exec.approvals.node.set"
        | "exec.approval.request"
        | "exec.approval.resolve" => "admin",

        // Unknown methods default to admin (fail secure)
        _ => "admin",
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

pub(super) async fn dispatch_method(
    method: &str,
    params: Option<&Value>,
    state: &WsServerState,
    conn: &ConnectionContext,
) -> Result<Value, ErrorShape> {
    // Check authorization before dispatching
    check_method_authorization(method, conn)?;

    match method {
        // Health/status
        "health" => Ok(handle_health()),
        "status" => Ok(handle_status(state)),

        // Config
        "config.get" => handle_config_get(params),
        "config.set" => handle_config_set(params),
        "config.apply" => handle_config_apply(params),
        "config.patch" => handle_config_patch(params),
        "config.schema" => handle_config_schema(),

        // Sessions
        "sessions.list" => handle_sessions_list(state, params),
        "sessions.preview" => handle_sessions_preview(state, params),
        "sessions.patch" => handle_sessions_patch(state, params),
        "sessions.reset" => handle_sessions_reset(state, params),
        "sessions.delete" => handle_sessions_delete(state, params),
        "sessions.compact" => handle_sessions_compact(state, params),

        // Channels
        "channels.status" => handle_channels_status(state),
        "channels.logout" => handle_channels_logout(params, state),

        // Agent
        "agent" => handle_agent(params, state, conn),
        "agent.identity.get" => handle_agent_identity_get(state),
        "agent.wait" => handle_agent_wait(params, state).await,

        // Chat
        "chat.history" => handle_chat_history(state, params),
        "chat.send" => handle_chat_send(state, params, conn),
        "chat.abort" => handle_chat_abort(state, params),

        // TTS
        "tts.status" => handle_tts_status(),
        "tts.providers" => handle_tts_providers(),
        "tts.voices" => handle_tts_voices(),
        "tts.enable" => handle_tts_enable(),
        "tts.disable" => handle_tts_disable(),
        "tts.convert" => handle_tts_convert(params),
        "tts.setProvider" => handle_tts_set_provider(params),
        "tts.setVoice" => handle_tts_set_voice(params),
        "tts.configure" => handle_tts_configure(params),
        "tts.speak" => handle_tts_speak(params),
        "tts.stop" => handle_tts_stop(),

        // Voice wake
        "voicewake.get" => handle_voicewake_get(),
        "voicewake.set" => handle_voicewake_set(params, Some(state)),
        "voicewake.enable" => handle_voicewake_enable(params),
        "voicewake.disable" => handle_voicewake_disable(),
        "voicewake.keywords" => handle_voicewake_keywords(),
        "voicewake.test" => handle_voicewake_test(params),

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

        // Update
        "update.run" => handle_update_run(params),
        "update.status" => handle_update_status(),
        "update.check" => handle_update_check(),
        "update.setChannel" => handle_update_set_channel(params),
        "update.configure" => handle_update_configure(params),
        "update.install" => handle_update_install(),
        "update.dismiss" => handle_update_dismiss(),
        "update.releaseNotes" => handle_update_release_notes(),

        // Cron
        "cron.status" => handle_cron_status(),
        "cron.list" => handle_cron_list(),
        "cron.add" => handle_cron_add(params),
        "cron.update" => handle_cron_update(params),
        "cron.remove" => handle_cron_remove(params),
        "cron.run" => handle_cron_run(params),
        "cron.runs" => handle_cron_runs(params),

        // Node pairing
        "node.pair.request" => handle_node_pair_request(params, state),
        "node.pair.list" => handle_node_pair_list(state),
        "node.pair.approve" => handle_node_pair_approve(params, state),
        "node.pair.reject" => handle_node_pair_reject(params, state),
        "node.pair.verify" => handle_node_pair_verify(params, state),
        "node.rename" => handle_node_rename(params, state),
        "node.list" => handle_node_list(state),
        "node.describe" => handle_node_describe(params, state),
        "node.invoke" => handle_node_invoke(params, state).await,
        "node.invoke.result" => handle_node_invoke_result(params, state, conn),
        "node.event" => handle_node_event(params, state, conn),

        // Device pairing
        "device.pair.list" => handle_device_pair_list(state),
        "device.pair.approve" => handle_device_pair_approve(params, state),
        "device.pair.reject" => handle_device_pair_reject(params, state),
        "device.token.rotate" => handle_device_token_rotate(params, state),
        "device.token.revoke" => handle_device_token_revoke(params, state),

        // Exec approvals
        "exec.approvals.get" => handle_exec_approvals_get(),
        "exec.approvals.set" => handle_exec_approvals_set(params),
        "exec.approvals.node.get" => handle_exec_approvals_node_get(params),
        "exec.approvals.node.set" => handle_exec_approvals_node_set(params),
        "exec.approval.request" => handle_exec_approval_request(params),
        "exec.approval.resolve" => handle_exec_approval_resolve(params),

        // Usage
        "usage.status" => handle_usage_status(),
        "usage.enable" => handle_usage_enable(),
        "usage.disable" => handle_usage_disable(),
        "usage.cost" => handle_usage_cost(params),
        "usage.session" => handle_usage_session(params),
        "usage.providers" => handle_usage_providers(),
        "usage.daily" => handle_usage_daily(params),
        "usage.reset" => handle_usage_reset(params),

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
            Some(json!({ "method": method })),
        )),
    }
}
