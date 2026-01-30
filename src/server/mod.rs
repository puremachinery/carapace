//! Server module
//!
//! HTTP and WebSocket servers with real handlers.

pub mod bind;
pub mod control;
pub mod csrf;
pub mod headers;
pub mod health;
pub mod http;
pub mod metrics;
pub mod openai;
pub mod ratelimit;
pub mod startup;
pub mod ws;

// Re-export key types
pub use control::{
    channels_handler, config_handler, status_handler, ChannelStatusItem, ChannelsStatusResponse,
    ConfigUpdateRequest, ConfigUpdateResponse, ControlError, ControlState, GatewayStatusResponse,
    RuntimeInfo,
};
pub use openai::{
    chat_completions_handler, responses_handler, ChatChoice, ChatCompletionChunk,
    ChatCompletionResponse, ChatCompletionsRequest, ChatContent, ChatMessage, ChatUsage,
    ChunkChoice, ChunkDelta, ContentPart, OpenAiError, OpenAiState, ResponsesRequest,
    ResponsesResponse,
};
