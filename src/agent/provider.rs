//! LLM provider trait and common types.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

use crate::agent::AgentError;

/// A streaming event from the LLM.
#[derive(Debug, Clone)]
pub enum StreamEvent {
    /// Incremental text output.
    TextDelta { text: String },

    /// The model wants to call a tool.
    ToolUse {
        id: String,
        name: String,
        input: serde_json::Value,
    },

    /// The model finished its turn.
    Stop {
        reason: StopReason,
        usage: TokenUsage,
    },

    /// Unrecoverable error from the provider.
    Error { message: String },
}

/// Why the model stopped generating.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StopReason {
    EndTurn,
    ToolUse,
    MaxTokens,
}

/// Token counts for a single LLM response.
#[derive(Debug, Clone, Copy, Default)]
pub struct TokenUsage {
    pub input_tokens: u64,
    pub output_tokens: u64,
}

/// A request to the LLM.
#[derive(Debug, Clone)]
pub struct CompletionRequest {
    pub model: String,
    pub messages: Vec<LlmMessage>,
    pub system: Option<String>,
    pub tools: Vec<ToolDefinition>,
    pub max_tokens: u32,
    pub temperature: Option<f64>,
}

/// A message in the LLM conversation.
#[derive(Debug, Clone)]
pub struct LlmMessage {
    pub role: LlmRole,
    pub content: Vec<ContentBlock>,
}

/// Role of a message in the LLM conversation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LlmRole {
    User,
    Assistant,
}

/// A content block within a message.
#[derive(Debug, Clone)]
pub enum ContentBlock {
    Text {
        text: String,
    },
    ToolUse {
        id: String,
        name: String,
        input: serde_json::Value,
    },
    ToolResult {
        tool_use_id: String,
        content: String,
        is_error: bool,
    },
}

/// A tool definition for the LLM.
#[derive(Debug, Clone)]
pub struct ToolDefinition {
    pub name: String,
    pub description: String,
    pub input_schema: serde_json::Value,
}

/// Trait for LLM providers (Anthropic, OpenAI, etc.).
///
/// Implementations send a completion request and return a channel that
/// yields streaming events until the model stops or errors.
#[async_trait]
pub trait LlmProvider: Send + Sync {
    async fn complete(
        &self,
        request: CompletionRequest,
    ) -> Result<mpsc::Receiver<StreamEvent>, AgentError>;
}
