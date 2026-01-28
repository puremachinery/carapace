//! Context builder: converts session history into LLM messages.

use crate::agent::provider::{ContentBlock, LlmMessage, LlmRole};
use crate::sessions::{ChatMessage, MessageRole};

/// Convert session chat history into LLM messages.
///
/// Maps `ChatMessage` entries from the session store into the `LlmMessage`
/// format expected by LLM providers.
///
/// Returns `(system_prompt, messages)`.
pub fn build_context(
    history: &[ChatMessage],
    system_prompt: Option<&str>,
) -> (Option<String>, Vec<LlmMessage>) {
    let mut system_parts: Vec<String> = Vec::new();
    let mut messages: Vec<LlmMessage> = Vec::new();

    if let Some(prompt) = system_prompt {
        system_parts.push(prompt.to_string());
    }

    for msg in history {
        match msg.role {
            MessageRole::System => {
                // System messages get prepended to the system prompt
                system_parts.push(msg.content.clone());
            }
            MessageRole::User => {
                messages.push(LlmMessage {
                    role: LlmRole::User,
                    content: vec![ContentBlock::Text {
                        text: msg.content.clone(),
                    }],
                });
            }
            MessageRole::Assistant => {
                // Check if the content looks like a tool_use block (JSON with tool calls)
                // Otherwise treat as plain text
                if let Some(tool_blocks) = try_parse_assistant_tool_use(&msg.content) {
                    messages.push(LlmMessage {
                        role: LlmRole::Assistant,
                        content: tool_blocks,
                    });
                } else {
                    messages.push(LlmMessage {
                        role: LlmRole::Assistant,
                        content: vec![ContentBlock::Text {
                            text: msg.content.clone(),
                        }],
                    });
                }
            }
            MessageRole::Tool => {
                // Tool results get appended as a user message with ToolResult block.
                // The Anthropic API expects tool results in a user-role message.
                let tool_use_id = msg.tool_call_id.as_deref().unwrap_or("").to_string();
                let is_error = msg
                    .metadata
                    .as_ref()
                    .and_then(|m| m.get("is_error"))
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);

                messages.push(LlmMessage {
                    role: LlmRole::User,
                    content: vec![ContentBlock::ToolResult {
                        tool_use_id,
                        content: msg.content.clone(),
                        is_error,
                    }],
                });
            }
        }
    }

    let system = if system_parts.is_empty() {
        None
    } else {
        Some(system_parts.join("\n\n"))
    };

    (system, messages)
}

/// Try to parse assistant content as tool_use blocks.
///
/// If the content is a JSON array of tool_use objects (stored from a previous
/// run), we reconstruct the ContentBlock representation. Otherwise returns None.
fn try_parse_assistant_tool_use(content: &str) -> Option<Vec<ContentBlock>> {
    let parsed: serde_json::Value = serde_json::from_str(content).ok()?;
    let arr = parsed.as_array()?;

    // Must have at least one tool_use block
    if arr.is_empty() || arr.iter().all(|v| v["type"].as_str() != Some("tool_use")) {
        return None;
    }

    let mut blocks = Vec::new();
    for item in arr {
        match item["type"].as_str() {
            Some("text") => {
                blocks.push(ContentBlock::Text {
                    text: item["text"].as_str().unwrap_or("").to_string(),
                });
            }
            Some("tool_use") => {
                blocks.push(ContentBlock::ToolUse {
                    id: item["id"].as_str().unwrap_or("").to_string(),
                    name: item["name"].as_str().unwrap_or("").to_string(),
                    input: item["input"].clone(),
                });
            }
            _ => {}
        }
    }

    if blocks.is_empty() {
        None
    } else {
        Some(blocks)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_user_assistant_conversation() {
        let history = vec![
            ChatMessage::user("sess1", "Hello"),
            ChatMessage::assistant("sess1", "Hi there!"),
            ChatMessage::user("sess1", "How are you?"),
        ];

        let (system, messages) = build_context(&history, None);
        assert!(system.is_none());
        assert_eq!(messages.len(), 3);

        assert_eq!(messages[0].role, LlmRole::User);
        assert_eq!(messages[1].role, LlmRole::Assistant);
        assert_eq!(messages[2].role, LlmRole::User);

        match &messages[0].content[0] {
            ContentBlock::Text { text } => assert_eq!(text, "Hello"),
            _ => panic!("expected Text block"),
        }
    }

    #[test]
    fn test_system_messages_merge_into_system_prompt() {
        let history = vec![
            ChatMessage::system("sess1", "You are a bot."),
            ChatMessage::user("sess1", "Hello"),
        ];

        let (system, messages) = build_context(&history, Some("Base prompt"));
        assert_eq!(system.unwrap(), "Base prompt\n\nYou are a bot.");
        // System message should not appear in messages array
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].role, LlmRole::User);
    }

    #[test]
    fn test_tool_result_becomes_user_message() {
        let history = vec![
            ChatMessage::user("sess1", "What's the weather?"),
            ChatMessage::assistant("sess1", "Let me check."),
            ChatMessage::tool("sess1", "get_weather", "call_123", r#"{"temp": 72}"#),
        ];

        let (_, messages) = build_context(&history, None);
        assert_eq!(messages.len(), 3);

        // Tool result should be a user message with ToolResult block
        assert_eq!(messages[2].role, LlmRole::User);
        match &messages[2].content[0] {
            ContentBlock::ToolResult {
                tool_use_id,
                content,
                is_error,
            } => {
                assert_eq!(tool_use_id, "call_123");
                assert_eq!(content, r#"{"temp": 72}"#);
                assert!(!is_error);
            }
            _ => panic!("expected ToolResult block"),
        }
    }

    #[test]
    fn test_system_prompt_only_no_history_system_messages() {
        let history = vec![ChatMessage::user("sess1", "Hi")];
        let (system, _) = build_context(&history, Some("System prompt"));
        assert_eq!(system.unwrap(), "System prompt");
    }

    #[test]
    fn test_no_system_prompt_or_system_messages() {
        let history = vec![ChatMessage::user("sess1", "Hi")];
        let (system, _) = build_context(&history, None);
        assert!(system.is_none());
    }

    #[test]
    fn test_empty_history() {
        let (system, messages) = build_context(&[], Some("prompt"));
        assert_eq!(system.unwrap(), "prompt");
        assert!(messages.is_empty());
    }

    #[test]
    fn test_assistant_with_tool_use_json() {
        let tool_use_json = serde_json::to_string(&serde_json::json!([
            {"type": "text", "text": "Let me check."},
            {"type": "tool_use", "id": "call_1", "name": "search", "input": {"q": "test"}}
        ]))
        .unwrap();

        let history = vec![
            ChatMessage::user("sess1", "Search for test"),
            ChatMessage::assistant("sess1", &tool_use_json),
        ];

        let (_, messages) = build_context(&history, None);
        assert_eq!(messages.len(), 2);
        assert_eq!(messages[1].content.len(), 2);

        match &messages[1].content[0] {
            ContentBlock::Text { text } => assert_eq!(text, "Let me check."),
            _ => panic!("expected Text block"),
        }
        match &messages[1].content[1] {
            ContentBlock::ToolUse { id, name, input } => {
                assert_eq!(id, "call_1");
                assert_eq!(name, "search");
                assert_eq!(input["q"], "test");
            }
            _ => panic!("expected ToolUse block"),
        }
    }
}
