//! Webhook handling module
//!
//! Provides hooks API for external integrations:
//! - POST /hooks/wake - Wake event trigger
//! - POST /hooks/agent - Dispatch message to agent
//! - POST /hooks/<mapping> - Custom hook mappings

pub mod auth;
pub mod handler;
pub mod registry;

fn reject_removed_session_scope_aliases(
    session_scope_alias: Option<serde::de::IgnoredAny>,
    session_key_snake_alias: Option<serde::de::IgnoredAny>,
) -> Result<(), String> {
    if session_scope_alias.is_some() {
        return Err("unknown field `sessionScope`; use `sessionKey`".to_string());
    }
    if session_key_snake_alias.is_some() {
        return Err("unknown field `session_key`; use `sessionKey`".to_string());
    }
    Ok(())
}

pub use auth::{extract_hooks_token, validate_hooks_token};
pub use handler::{
    validate_agent_request, validate_wake_request, AgentRequest, AgentResponse, HooksErrorResponse,
    ValidatedAgentRequest, ValidatedWakeRequest, WakeMode, WakeRequest, WakeResponse,
};
pub use registry::{
    create_registry as create_hook_registry, HookAction, HookMapping, HookMappingContext,
    HookMappingError, HookMappingResult, HookMatch, HookRegistry, HookTransform,
};
