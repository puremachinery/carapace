//! OpenAI Chat Completions wire format.
//!
//! Auth-agnostic body builder and SSE stream parser shared by the direct
//! OpenAI provider (`openai.rs`), the Ollama provider (`ollama.rs`), and
//! the Vertex AI OpenAI-compatible publisher path (`vertex.rs`).

use futures_util::StreamExt;
use serde_json::{json, Value};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::agent::provider::*;

/// Build the common OpenAI Chat Completions body.
///
/// Returns a JSON object with `messages`, `stream`, and optional
/// `temperature` and `tools` fields.
///
/// Callers add context-specific fields before sending:
/// - Direct OpenAI adds `model`, `max_completion_tokens`, `stream_options`
/// - Vertex AI adds `model`, `max_tokens`
pub(crate) fn build_openai_messages_body(request: &CompletionRequest) -> Value {
    let mut messages: Vec<Value> = Vec::new();

    if let Some(ref system) = request.system {
        messages.push(json!({
            "role": "system",
            "content": system,
        }));
    }

    for msg in &request.messages {
        match msg.role {
            LlmRole::User => convert_user_message(msg, &mut messages),
            LlmRole::Assistant => convert_assistant_message(msg, &mut messages),
        }
    }

    let mut body = json!({
        "messages": messages,
        "stream": true,
    });

    if let Some(temp) = request.temperature {
        body["temperature"] = json!(temp);
    }

    append_tools(&request.tools, &mut body);

    body
}

/// Convert a user-role `LlmMessage` into one or more OpenAI-format messages.
fn convert_user_message(msg: &LlmMessage, messages: &mut Vec<Value>) {
    let has_tool_result = msg
        .content
        .iter()
        .any(|b| matches!(b, ContentBlock::ToolResult { .. }));

    if has_tool_result {
        for block in &msg.content {
            match block {
                ContentBlock::ToolResult {
                    tool_use_id,
                    content,
                    ..
                } => {
                    messages.push(json!({
                        "role": "tool",
                        "tool_call_id": tool_use_id,
                        "content": content,
                    }));
                }
                ContentBlock::Text { text, .. } => {
                    messages.push(json!({
                        "role": "user",
                        "content": text,
                    }));
                }
                _ => {}
            }
        }
    } else {
        let text = collect_text_blocks(&msg.content);
        if !text.is_empty() {
            messages.push(json!({
                "role": "user",
                "content": text,
            }));
        }
    }
}

/// Convert an assistant-role `LlmMessage` into an OpenAI-format message.
fn convert_assistant_message(msg: &LlmMessage, messages: &mut Vec<Value>) {
    let has_tool_use = msg
        .content
        .iter()
        .any(|b| matches!(b, ContentBlock::ToolUse { .. }));

    if has_tool_use {
        let text_content = collect_text_blocks(&msg.content);

        let tool_calls: Vec<Value> = msg
            .content
            .iter()
            .filter_map(|b| match b {
                ContentBlock::ToolUse {
                    id, name, input, ..
                } => Some(json!({
                    "id": id,
                    "type": "function",
                    "function": {
                        "name": name,
                        "arguments": input.to_string(),
                    }
                })),
                _ => None,
            })
            .collect();

        let mut msg_obj = json!({
            "role": "assistant",
            "tool_calls": tool_calls,
        });
        if !text_content.is_empty() {
            msg_obj["content"] = json!(text_content);
        }
        messages.push(msg_obj);
    } else {
        let text = collect_text_blocks(&msg.content);
        messages.push(json!({
            "role": "assistant",
            "content": text,
        }));
    }
}

/// Concatenate all `Text` blocks in a content slice into a single string.
fn collect_text_blocks(content: &[ContentBlock]) -> String {
    content
        .iter()
        .filter_map(|b| match b {
            ContentBlock::Text { text, .. } => Some(text.as_str()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("")
}

/// Append tool definitions to the body if any are present.
fn append_tools(tools: &[ToolDefinition], body: &mut Value) {
    if !tools.is_empty() {
        let tool_values: Vec<Value> = tools
            .iter()
            .map(|t| {
                json!({
                    "type": "function",
                    "function": {
                        "name": t.name,
                        "description": t.description,
                        "parameters": t.input_schema,
                    }
                })
            })
            .collect();
        body["tools"] = json!(tool_values);
    }
}

/// Process an OpenAI-compatible SSE byte stream into [`StreamEvent`]s.
pub(crate) async fn process_openai_sse_stream<S>(
    mut stream: S,
    tx: &mpsc::Sender<StreamEvent>,
    cancel_token: &CancellationToken,
) -> Result<(), String>
where
    S: futures_util::Stream<Item = Result<bytes::Bytes, reqwest::Error>> + Unpin,
{
    let mut buffer = String::new();
    let mut tool_calls: std::collections::HashMap<u64, (String, String, String)> =
        std::collections::HashMap::new();
    let mut accumulated_usage = TokenUsage::default();
    let mut got_done = false;

    loop {
        let chunk = tokio::select! {
            _ = cancel_token.cancelled() => return Ok(()),
            chunk = stream.next() => chunk,
        };
        let Some(chunk) = chunk else {
            break;
        };
        let chunk = chunk.map_err(|e| format!("stream read error: {e}"))?;
        buffer.push_str(&String::from_utf8_lossy(&chunk));

        if buffer.len() > MAX_SSE_BUFFER_BYTES {
            return Err(format!(
                "SSE buffer exceeded {} bytes, aborting stream",
                MAX_SSE_BUFFER_BYTES
            ));
        }

        let mut consumed = 0;
        while let Some(rel_pos) = buffer[consumed..].find('\n') {
            let newline_pos = consumed + rel_pos;
            let line = buffer[consumed..newline_pos].trim_end_matches('\r');
            consumed = newline_pos + 1;

            if let Some(data) = line.strip_prefix("data: ") {
                if data.trim() == "[DONE]" {
                    got_done = true;
                    let stop_event =
                        flush_tool_calls_and_stop(&mut tool_calls, &accumulated_usage, tx).await;
                    if let Some(event) = stop_event {
                        let is_stop = matches!(event, StreamEvent::Stop { .. });
                        if tx.send(event).await.is_err() {
                            return Ok(());
                        }
                        if is_stop {
                            return Ok(());
                        }
                    }
                    continue;
                }

                if let Some(event) =
                    parse_openai_sse_data(data, &mut tool_calls, &mut accumulated_usage)
                {
                    let is_stop = matches!(event, StreamEvent::Stop { .. });
                    let is_error = matches!(event, StreamEvent::Error { .. });
                    if tx.send(event).await.is_err() {
                        return Ok(());
                    }
                    if is_stop || is_error {
                        return Ok(());
                    }
                }
            }
        }
        if consumed > 0 {
            buffer.drain(..consumed);
        }
    }

    if got_done {
        Ok(())
    } else {
        Err("stream ended without [DONE] sentinel (premature termination)".to_string())
    }
}

/// Parse a single SSE data payload from OpenAI's streaming format.
pub(crate) fn parse_openai_sse_data(
    data: &str,
    tool_calls: &mut std::collections::HashMap<u64, (String, String, String)>,
    accumulated_usage: &mut TokenUsage,
) -> Option<StreamEvent> {
    let parsed: Value = serde_json::from_str(data).ok()?;

    if let Some(error) = parsed.get("error") {
        let message = error
            .get("message")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown API error")
            .to_string();
        return Some(StreamEvent::Error { message });
    }

    if let Some(usage) = parsed.get("usage") {
        if let Some(prompt_tokens) = usage.get("prompt_tokens").and_then(|v| v.as_u64()) {
            accumulated_usage.input_tokens = prompt_tokens;
        }
        if let Some(completion_tokens) = usage.get("completion_tokens").and_then(|v| v.as_u64()) {
            accumulated_usage.output_tokens = completion_tokens;
        }
    }

    let choices = parsed.get("choices")?.as_array()?;
    if choices.is_empty() {
        return None;
    }

    let choice = &choices[0];

    if let Some(finish_reason) = choice.get("finish_reason").and_then(|v| v.as_str()) {
        let reason = match finish_reason {
            "stop" => StopReason::EndTurn,
            "tool_calls" => StopReason::ToolUse,
            "length" => StopReason::MaxTokens,
            _ => StopReason::EndTurn,
        };

        if reason == StopReason::ToolUse {
            return None;
        }

        return Some(StreamEvent::Stop {
            reason,
            usage: *accumulated_usage,
        });
    }

    let delta = choice.get("delta")?;

    if let Some(content) = delta.get("content").and_then(|v| v.as_str()) {
        if !content.is_empty() {
            return Some(StreamEvent::TextDelta {
                text: content.to_string(),
                metadata: None,
            });
        }
    }

    if let Some(tc_array) = delta.get("tool_calls").and_then(|v| v.as_array()) {
        for tc in tc_array {
            let index = tc.get("index").and_then(|v| v.as_u64()).unwrap_or(0);

            if let Some(id) = tc.get("id").and_then(|v| v.as_str()) {
                let name = tc
                    .get("function")
                    .and_then(|f| f.get("name"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let args = tc
                    .get("function")
                    .and_then(|f| f.get("arguments"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                tool_calls.insert(index, (id.to_string(), name, args));
            } else if let Some(entry) = tool_calls.get_mut(&index) {
                if let Some(args_chunk) = tc
                    .get("function")
                    .and_then(|f| f.get("arguments"))
                    .and_then(|v| v.as_str())
                {
                    entry.2.push_str(args_chunk);
                }
            }
        }
    }

    None
}

/// Flush accumulated tool calls as StreamEvents and emit a Stop event.
async fn flush_tool_calls_and_stop(
    tool_calls: &mut std::collections::HashMap<u64, (String, String, String)>,
    usage: &TokenUsage,
    tx: &mpsc::Sender<StreamEvent>,
) -> Option<StreamEvent> {
    if tool_calls.is_empty() {
        return None;
    }

    let mut sorted: Vec<(u64, (String, String, String))> = tool_calls.drain().collect();
    sorted.sort_by_key(|(idx, _)| *idx);

    for (_index, (id, name, args_json)) in sorted {
        let input: Value = serde_json::from_str(&args_json).unwrap_or(json!({}));
        let event = StreamEvent::ToolUse {
            id,
            name,
            input,
            metadata: None,
        };
        if tx.send(event).await.is_err() {
            return None;
        }
    }

    Some(StreamEvent::Stop {
        reason: StopReason::ToolUse,
        usage: *usage,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::provider::{
        CompletionRequest, ContentBlock, LlmMessage, LlmRole, ToolDefinition,
    };

    #[test]
    fn test_build_openai_messages_body_basic() {
        let request = CompletionRequest {
            model: "gpt-5.5".to_string(),
            messages: vec![LlmMessage {
                role: LlmRole::User,
                content: vec![ContentBlock::Text {
                    text: "Hello".to_string(),
                    metadata: None,
                }],
            }],
            system: Some("You are helpful.".to_string()),
            tools: vec![],
            max_tokens: 1024,
            temperature: Some(0.7),
            extra: None,
        };
        let body = build_openai_messages_body(&request);
        // No model or max_tokens — callers add those
        assert!(body.get("model").is_none());
        assert!(body.get("max_completion_tokens").is_none());
        assert!(body.get("max_tokens").is_none());
        assert_eq!(body["stream"], true);
        assert_eq!(body["temperature"], 0.7);
        let messages = body["messages"].as_array().unwrap();
        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0]["role"], "system");
        assert_eq!(messages[1]["role"], "user");
        assert!(body.get("tools").is_none());
    }

    #[test]
    fn test_build_openai_messages_body_with_tools() {
        let request = CompletionRequest {
            model: "gpt-5.5".to_string(),
            messages: vec![],
            system: None,
            tools: vec![ToolDefinition {
                name: "get_weather".to_string(),
                description: "Get weather".to_string(),
                input_schema: json!({"type": "object", "properties": {}}),
            }],
            max_tokens: 4096,
            temperature: None,
            extra: None,
        };
        let body = build_openai_messages_body(&request);
        assert!(body["tools"].is_array());
        assert_eq!(body["tools"][0]["type"], "function");
        assert_eq!(body["tools"][0]["function"]["name"], "get_weather");
        assert!(body.get("temperature").is_none());
    }

    #[test]
    fn test_parse_text_delta() {
        let mut tool_calls = std::collections::HashMap::new();
        let mut usage = TokenUsage::default();
        let event = parse_openai_sse_data(
            r#"{"id":"chatcmpl-123","choices":[{"index":0,"delta":{"content":"Hello"},"finish_reason":null}]}"#,
            &mut tool_calls,
            &mut usage,
        );
        match event {
            Some(StreamEvent::TextDelta { text, .. }) => assert_eq!(text, "Hello"),
            other => panic!("expected TextDelta, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_stop_reason_end_turn() {
        let mut tool_calls = std::collections::HashMap::new();
        let mut usage = TokenUsage {
            input_tokens: 100,
            output_tokens: 42,
        };
        let event = parse_openai_sse_data(
            r#"{"id":"chatcmpl-123","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}"#,
            &mut tool_calls,
            &mut usage,
        );
        match event {
            Some(StreamEvent::Stop { reason, usage }) => {
                assert_eq!(reason, StopReason::EndTurn);
                assert_eq!(usage.input_tokens, 100);
                assert_eq!(usage.output_tokens, 42);
            }
            other => panic!("expected Stop, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_tool_call_accumulation() {
        let mut tool_calls = std::collections::HashMap::new();
        let mut usage = TokenUsage::default();

        parse_openai_sse_data(
            r#"{"id":"chatcmpl-123","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_abc","type":"function","function":{"name":"get_weather","arguments":""}}]},"finish_reason":null}]}"#,
            &mut tool_calls,
            &mut usage,
        );
        assert!(tool_calls.contains_key(&0));
        assert_eq!(tool_calls[&0].0, "call_abc");
        assert_eq!(tool_calls[&0].1, "get_weather");

        parse_openai_sse_data(
            r#"{"id":"chatcmpl-123","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\"city\":"}}]},"finish_reason":null}]}"#,
            &mut tool_calls,
            &mut usage,
        );

        parse_openai_sse_data(
            r#"{"id":"chatcmpl-123","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"\"SF\"}"}}]},"finish_reason":null}]}"#,
            &mut tool_calls,
            &mut usage,
        );
        assert_eq!(tool_calls[&0].2, r#"{"city":"SF"}"#);
    }

    #[test]
    fn test_parse_usage_from_final_chunk() {
        let mut tool_calls = std::collections::HashMap::new();
        let mut usage = TokenUsage::default();
        parse_openai_sse_data(
            r#"{"id":"chatcmpl-123","choices":[],"usage":{"prompt_tokens":150,"completion_tokens":42,"total_tokens":192}}"#,
            &mut tool_calls,
            &mut usage,
        );
        assert_eq!(usage.input_tokens, 150);
        assert_eq!(usage.output_tokens, 42);
    }

    #[test]
    fn test_parse_error_response() {
        let mut tool_calls = std::collections::HashMap::new();
        let mut usage = TokenUsage::default();
        let event = parse_openai_sse_data(
            r#"{"error":{"message":"Rate limit exceeded","type":"rate_limit_error"}}"#,
            &mut tool_calls,
            &mut usage,
        );
        match event {
            Some(StreamEvent::Error { message }) => assert_eq!(message, "Rate limit exceeded"),
            other => panic!("expected Error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_flush_tool_calls_emits_tool_use_then_stop() {
        let (tx, mut rx) = mpsc::channel(64);
        let mut tool_calls = std::collections::HashMap::new();
        tool_calls.insert(
            0,
            (
                "call_1".to_string(),
                "get_weather".to_string(),
                r#"{"city":"SF"}"#.to_string(),
            ),
        );
        let usage = TokenUsage {
            input_tokens: 100,
            output_tokens: 50,
        };

        let stop_event = flush_tool_calls_and_stop(&mut tool_calls, &usage, &tx).await;
        assert!(stop_event.is_some());

        let event = rx.try_recv().unwrap();
        match event {
            StreamEvent::ToolUse {
                id, name, input, ..
            } => {
                assert_eq!(id, "call_1");
                assert_eq!(name, "get_weather");
                assert_eq!(input["city"], "SF");
            }
            other => panic!("expected ToolUse, got {other:?}"),
        }

        match stop_event.unwrap() {
            StreamEvent::Stop { reason, usage } => {
                assert_eq!(reason, StopReason::ToolUse);
                assert_eq!(usage.input_tokens, 100);
                assert_eq!(usage.output_tokens, 50);
            }
            other => panic!("expected Stop, got {other:?}"),
        }
    }

    fn mock_sse_stream(
        chunks: Vec<&str>,
    ) -> futures_util::stream::Iter<std::vec::IntoIter<Result<bytes::Bytes, reqwest::Error>>> {
        let items: Vec<Result<bytes::Bytes, reqwest::Error>> = chunks
            .into_iter()
            .map(|s| Ok(bytes::Bytes::from(s.to_owned())))
            .collect();
        futures_util::stream::iter(items)
    }

    #[tokio::test]
    async fn test_complete_text_stream() {
        let sse_data = concat!(
            "data: {\"id\":\"chatcmpl-1\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"Hello\"},\"finish_reason\":null}]}\n\n",
            "data: {\"id\":\"chatcmpl-1\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n",
            "data: {\"id\":\"chatcmpl-1\",\"choices\":[],\"usage\":{\"prompt_tokens\":10,\"completion_tokens\":5}}\n\n",
            "data: [DONE]\n\n",
        );

        let stream = mock_sse_stream(vec![sse_data]);
        let (tx, mut rx) = mpsc::channel(64);

        let result = process_openai_sse_stream(stream, &tx, &CancellationToken::new()).await;
        assert!(result.is_ok(), "expected Ok, got: {:?}", result);

        let mut events = Vec::new();
        while let Ok(event) = rx.try_recv() {
            events.push(event);
        }
        assert!(events
            .iter()
            .any(|e| matches!(e, StreamEvent::TextDelta { text, .. } if text == "Hello")));
        assert!(events.iter().any(|e| matches!(
            e,
            StreamEvent::Stop {
                reason: StopReason::EndTurn,
                ..
            }
        )));
    }

    #[tokio::test]
    async fn test_complete_tool_call_stream() {
        let sse_data = concat!(
            "data: {\"id\":\"chatcmpl-1\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":null,\"tool_calls\":[{\"index\":0,\"id\":\"call_abc\",\"type\":\"function\",\"function\":{\"name\":\"get_weather\",\"arguments\":\"\"}}]},\"finish_reason\":null}]}\n\n",
            "data: {\"id\":\"chatcmpl-1\",\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"{\\\"city\\\":\\\"SF\\\"}\"}}]},\"finish_reason\":null}]}\n\n",
            "data: {\"id\":\"chatcmpl-1\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"tool_calls\"}]}\n\n",
            "data: {\"id\":\"chatcmpl-1\",\"choices\":[],\"usage\":{\"prompt_tokens\":20,\"completion_tokens\":10,\"total_tokens\":30}}\n\n",
            "data: [DONE]\n\n",
        );

        let stream = mock_sse_stream(vec![sse_data]);
        let (tx, mut rx) = mpsc::channel(64);

        let result = process_openai_sse_stream(stream, &tx, &CancellationToken::new()).await;
        assert!(result.is_ok(), "expected Ok, got: {:?}", result);

        let mut events = Vec::new();
        while let Ok(event) = rx.try_recv() {
            events.push(event);
        }
        assert!(
            events.iter().any(|e| matches!(
                e,
                StreamEvent::ToolUse { id, name, .. }
                if id == "call_abc" && name == "get_weather"
            )),
            "expected ToolUse for get_weather, got: {:?}",
            events,
        );
        assert!(
            events.iter().any(|e| matches!(
                e,
                StreamEvent::Stop {
                    reason: StopReason::ToolUse,
                    ..
                }
            )),
            "expected Stop with ToolUse, got: {:?}",
            events,
        );
    }

    #[tokio::test]
    async fn test_truncated_stream_without_done_returns_error() {
        let sse_data = "data: {\"id\":\"chatcmpl-1\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"Hello\"},\"finish_reason\":null}]}\n\n";

        let stream = mock_sse_stream(vec![sse_data]);
        let (tx, _rx) = mpsc::channel(64);

        let result = process_openai_sse_stream(stream, &tx, &CancellationToken::new()).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("[DONE]"));
    }
}
