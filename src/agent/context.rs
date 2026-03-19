//! Context builder: converts session history into LLM messages.

use crate::agent::prompt_guard::tagging::{self, ContentSource};
use crate::agent::prompt_guard::TaggingConfig;
use crate::agent::provider::{ContentBlock, ContentBlockMetadata, LlmMessage, LlmRole};
use crate::sessions::{ChatMessage, MessageRole};
use serde_json::{json, Value};

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
    build_context_with_tagging(history, system_prompt, &TaggingConfig { enabled: false })
}

/// Convert session chat history into LLM messages with untrusted content tagging.
pub fn build_context_with_tagging(
    history: &[ChatMessage],
    system_prompt: Option<&str>,
    tagging_config: &TaggingConfig,
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
                        metadata: None,
                    }],
                });
            }
            MessageRole::Assistant => {
                if let Some(blocks) = try_parse_assistant_blocks(&msg.content) {
                    messages.push(LlmMessage {
                        role: LlmRole::Assistant,
                        content: blocks,
                    });
                } else {
                    messages.push(LlmMessage {
                        role: LlmRole::Assistant,
                        content: vec![ContentBlock::Text {
                            text: msg.content.clone(),
                            metadata: None,
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

                let tagged_content =
                    tagging::tag_content(&msg.content, ContentSource::ToolResult, tagging_config);

                messages.push(LlmMessage {
                    role: LlmRole::User,
                    content: vec![ContentBlock::ToolResult {
                        tool_use_id,
                        content: tagged_content,
                        is_error,
                        metadata: None,
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

pub(crate) fn serialize_assistant_blocks(
    blocks: &[ContentBlock],
) -> Result<String, serde_json::Error> {
    let serialized: Vec<Value> = blocks.iter().map(serialize_assistant_block).collect();
    serde_json::to_string(&serialized)
}

fn serialize_assistant_block(block: &ContentBlock) -> Value {
    match block {
        ContentBlock::Text { text, metadata } => {
            let mut block_json = json!({
                "type": "text",
                "text": text,
            });
            if let Some(metadata) = metadata {
                block_json["metadata"] = serde_json::to_value(metadata).unwrap_or(Value::Null);
            }
            block_json
        }
        ContentBlock::ToolUse {
            id,
            name,
            input,
            metadata,
        } => {
            let mut block_json = json!({
                "type": "tool_use",
                "id": id,
                "name": name,
                "input": input,
            });
            if let Some(metadata) = metadata {
                block_json["metadata"] = serde_json::to_value(metadata).unwrap_or(Value::Null);
            }
            block_json
        }
        ContentBlock::ToolResult {
            tool_use_id,
            content,
            is_error,
            metadata: _,
        } => {
            // ToolResult blocks are user-side function responses. Provider-specific
            // metadata such as Gemini thought signatures is intentionally not
            // serialized or replayed for them.
            json!({
                "type": "tool_result",
                "tool_use_id": tool_use_id,
                "content": content,
                "is_error": is_error,
            })
        }
    }
}

fn parse_block_metadata(item: &Value) -> Option<ContentBlockMetadata> {
    item.get("metadata")
        .cloned()
        .and_then(|metadata| serde_json::from_value(metadata).ok())
}

/// Try to parse assistant content as structured blocks.
///
/// Accepts the legacy tool-use JSON shape plus the newer metadata-bearing text
/// block shape used for Gemini/Vertex thought-signature round-tripping.
fn try_parse_assistant_blocks(content: &str) -> Option<Vec<ContentBlock>> {
    let parsed: Value = serde_json::from_str(content).ok()?;
    let arr = parsed.as_array()?;

    if arr.is_empty() {
        return None;
    }

    let mut blocks = Vec::new();
    let mut has_tool_use = false;
    let mut has_provider_metadata = false;

    for item in arr {
        match item.get("type").and_then(Value::as_str) {
            Some("text") => {
                let metadata = parse_block_metadata(item);
                has_provider_metadata |= metadata.is_some();
                blocks.push(ContentBlock::Text {
                    text: item
                        .get("text")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string(),
                    metadata,
                });
            }
            Some("tool_use") => {
                let metadata = parse_block_metadata(item);
                has_provider_metadata |= metadata.is_some();
                has_tool_use = true;
                blocks.push(ContentBlock::ToolUse {
                    id: item
                        .get("id")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string(),
                    name: item
                        .get("name")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string(),
                    input: item.get("input").cloned().unwrap_or_else(|| json!({})),
                    metadata,
                });
            }
            Some("tool_result") => {
                // Assistant turns do not currently serialize ToolResult blocks, but
                // the parser stays tolerant here so future/external structured
                // history entries are not dropped wholesale. Any metadata on
                // ToolResult is intentionally ignored because provider metadata
                // only applies to model-generated assistant parts.
                blocks.push(ContentBlock::ToolResult {
                    tool_use_id: item
                        .get("tool_use_id")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string(),
                    content: item
                        .get("content")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string(),
                    is_error: item
                        .get("is_error")
                        .and_then(Value::as_bool)
                        .unwrap_or(false),
                    metadata: None,
                });
            }
            _ => continue,
        }
    }

    if blocks.is_empty() || (!has_tool_use && !has_provider_metadata) {
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
            ContentBlock::Text { text, metadata } => {
                assert_eq!(text, "Hello");
                assert!(metadata.is_none());
            }
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

        assert_eq!(messages[2].role, LlmRole::User);
        match &messages[2].content[0] {
            ContentBlock::ToolResult {
                tool_use_id,
                content,
                is_error,
                metadata,
            } => {
                assert_eq!(tool_use_id, "call_123");
                assert_eq!(content, r#"{"temp": 72}"#);
                assert!(!is_error);
                assert!(metadata.is_none());
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
            ContentBlock::Text { text, metadata } => {
                assert_eq!(text, "Let me check.");
                assert!(metadata.is_none());
            }
            _ => panic!("expected Text block"),
        }
        match &messages[1].content[1] {
            ContentBlock::ToolUse {
                id,
                name,
                input,
                metadata,
            } => {
                assert_eq!(id, "call_1");
                assert_eq!(name, "search");
                assert_eq!(input["q"], "test");
                assert!(metadata.is_none());
            }
            _ => panic!("expected ToolUse block"),
        }
    }

    #[test]
    fn test_assistant_with_metadata_json() {
        let structured = serde_json::to_string(&serde_json::json!([
            {
                "type": "text",
                "text": "Thinking aloud",
                "metadata": {
                    "gemini": {
                        "thoughtSignature": "sig-123"
                    }
                }
            }
        ]))
        .unwrap();

        let history = vec![ChatMessage::assistant("sess1", &structured)];
        let (_, messages) = build_context(&history, None);
        assert_eq!(messages.len(), 1);
        match &messages[0].content[0] {
            ContentBlock::Text { text, metadata } => {
                assert_eq!(text, "Thinking aloud");
                assert_eq!(
                    metadata.as_ref().and_then(|m| m.gemini_thought_signature()),
                    Some("sig-123")
                );
            }
            _ => panic!("expected Text block"),
        }
    }

    #[test]
    fn test_assistant_blocks_skip_unknown_block_types() {
        let structured = serde_json::to_string(&serde_json::json!([
            {
                "type": "text",
                "text": "Let me check."
            },
            {
                "type": "future_type",
                "payload": "ignored"
            },
            {
                "type": "tool_use",
                "id": "call_1",
                "name": "search",
                "input": {"q": "test"}
            }
        ]))
        .unwrap();

        let history = vec![ChatMessage::assistant("sess1", &structured)];
        let (_, messages) = build_context(&history, None);

        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].content.len(), 2);
        match &messages[0].content[0] {
            ContentBlock::Text { text, metadata } => {
                assert_eq!(text, "Let me check.");
                assert!(metadata.is_none());
            }
            other => panic!("expected text block, got {other:?}"),
        }
        match &messages[0].content[1] {
            ContentBlock::ToolUse {
                id,
                name,
                input,
                metadata,
            } => {
                assert_eq!(id, "call_1");
                assert_eq!(name, "search");
                assert_eq!(input["q"], "test");
                assert!(metadata.is_none());
            }
            other => panic!("expected tool_use block, got {other:?}"),
        }
    }

    #[test]
    fn test_serialize_assistant_blocks_with_metadata() {
        let serialized = serialize_assistant_blocks(&[ContentBlock::Text {
            text: "Hello".to_string(),
            metadata: ContentBlockMetadata::with_gemini_thought_signature(Some(
                "sig-xyz".to_string(),
            )),
        }])
        .unwrap();
        let parsed: Value = serde_json::from_str(&serialized).unwrap();
        assert_eq!(parsed[0]["type"], "text");
        assert_eq!(parsed[0]["text"], "Hello");
        assert_eq!(
            parsed[0]["metadata"]["gemini"]["thoughtSignature"],
            "sig-xyz"
        );
    }

    #[test]
    fn test_serialize_assistant_blocks_drops_tool_result_metadata() {
        let serialized = serialize_assistant_blocks(&[ContentBlock::ToolResult {
            tool_use_id: "tool-1".to_string(),
            content: "ok".to_string(),
            is_error: false,
            metadata: ContentBlockMetadata::with_gemini_thought_signature(Some(
                "sig-should-drop".to_string(),
            )),
        }])
        .unwrap();
        let parsed: Value = serde_json::from_str(&serialized).unwrap();
        assert_eq!(parsed[0]["type"], "tool_result");
        assert!(
            parsed[0].get("metadata").is_none(),
            "ToolResult metadata should not be serialized into assistant history"
        );
    }

    #[test]
    fn test_try_parse_assistant_blocks_ignores_tool_result_metadata() {
        let parsed = try_parse_assistant_blocks(
            r#"[{"type":"tool_result","tool_use_id":"tool-1","content":"ok","is_error":false,"metadata":{"gemini":{"thoughtSignature":"sig-should-drop"}}},{"type":"tool_use","id":"call-1","name":"get_weather","input":{}}]"#,
        )
        .expect("assistant blocks should parse");

        match &parsed[0] {
            ContentBlock::ToolResult { metadata, .. } => {
                assert!(
                    metadata.is_none(),
                    "ToolResult metadata should be ignored during assistant history parse"
                );
            }
            other => panic!("expected ToolResult block, got {other:?}"),
        }
    }
}
