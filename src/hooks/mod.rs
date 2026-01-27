//! Webhook handling module
//!
//! Provides hooks API for external integrations:
//! - POST /hooks/wake - Wake event trigger
//! - POST /hooks/agent - Dispatch message to agent
//! - POST /hooks/<mapping> - Custom hook mappings

pub mod auth;
pub mod handler;
pub mod registry;

pub use auth::{extract_hooks_token, timing_safe_equal, validate_hooks_token};
pub use handler::{
    validate_agent_request, validate_wake_request, AgentRequest, AgentResponse, HooksErrorResponse,
    ValidatedAgentRequest, ValidatedWakeRequest, WakeMode, WakeRequest, WakeResponse,
};
pub use registry::{
    create_registry as create_hook_registry, HookAction, HookMapping, HookMappingContext,
    HookMappingError, HookMappingResult, HookMatch, HookRegistry, HookTransform,
};
