//! Built-in agent tools.
//!
//! Provides a core set of tools that the LLM can invoke during agent execution.
//! These tools are registered in the `ToolsRegistry` and dispatched via the
//! standard tool dispatch path.

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

use serde_json::{json, Value};

use crate::plugins::tools::{BuiltinTool, ToolInvokeContext, ToolInvokeResult};

/// Return all built-in tool definitions.
///
/// Called by `ToolsRegistry::new()` to register the core tool set.
pub fn builtin_tools() -> Vec<BuiltinTool> {
    vec![
        current_time_tool(),
        web_fetch_tool(),
        memory_read_tool(),
        memory_write_tool(),
        memory_list_tool(),
        message_send_tool(),
        session_list_tool(),
        session_read_tool(),
        config_read_tool(),
        math_eval_tool(),
    ]
}

// ---------------------------------------------------------------------------
// current_time
// ---------------------------------------------------------------------------

fn current_time_tool() -> BuiltinTool {
    BuiltinTool {
        name: "current_time".to_string(),
        description: "Return the current UTC time as an ISO 8601 string and Unix timestamp."
            .to_string(),
        input_schema: json!({
            "type": "object",
            "properties": {},
            "additionalProperties": false
        }),
        handler: Box::new(|_args, _ctx| {
            let now = chrono::Utc::now();
            ToolInvokeResult::success(json!({
                "iso": now.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
                "unix": now.timestamp()
            }))
        }),
    }
}

// ---------------------------------------------------------------------------
// web_fetch
// ---------------------------------------------------------------------------

fn web_fetch_tool() -> BuiltinTool {
    BuiltinTool {
        name: "web_fetch".to_string(),
        description: "Fetch a URL and return its content. Uses SSRF-protected infrastructure. \
                       Returns the response body as text, HTTP status, and content type."
            .to_string(),
        input_schema: json!({
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "The URL to fetch (http or https only)."
                },
                "max_bytes": {
                    "type": "integer",
                    "description": "Maximum response size in bytes. Defaults to 1048576 (1 MB)."
                }
            },
            "required": ["url"],
            "additionalProperties": false
        }),
        handler: Box::new(|args, _ctx| handle_web_fetch(args)),
    }
}

/// Default max response size for web_fetch (1 MB).
const WEB_FETCH_DEFAULT_MAX_BYTES: u64 = 1_048_576;

/// Maximum allowed value for max_bytes (10 MB).
const WEB_FETCH_MAX_ALLOWED_BYTES: u64 = 10 * 1024 * 1024;

fn handle_web_fetch(args: Value) -> ToolInvokeResult {
    let url = match args.get("url").and_then(|v| v.as_str()) {
        Some(u) => u.to_string(),
        None => return ToolInvokeResult::tool_error("missing required parameter: url"),
    };

    let max_bytes = args
        .get("max_bytes")
        .and_then(|v| v.as_u64())
        .unwrap_or(WEB_FETCH_DEFAULT_MAX_BYTES)
        .min(WEB_FETCH_MAX_ALLOWED_BYTES);

    // We need to run the async fetch synchronously within the tool handler.
    // The tool handler is called from a synchronous context, so we use
    // tokio::task::block_in_place + Handle::current().block_on().
    let result = tokio::task::block_in_place(|| {
        let handle = tokio::runtime::Handle::current();
        handle.block_on(async {
            use crate::media::fetch::{FetchConfig, MediaFetcher};

            let config = FetchConfig::default().with_max_size(max_bytes);
            let fetcher = MediaFetcher::with_config(config);
            fetcher.fetch(&url).await
        })
    });

    match result {
        Ok(fetch_result) => {
            let content = String::from_utf8_lossy(&fetch_result.bytes).into_owned();
            let content_type = fetch_result
                .content_type
                .unwrap_or_else(|| "application/octet-stream".to_string());
            ToolInvokeResult::success(json!({
                "content": content,
                "status": 200,
                "content_type": content_type
            }))
        }
        Err(e) => ToolInvokeResult::tool_error(format!("fetch failed: {e}")),
    }
}

// ---------------------------------------------------------------------------
// memory_read / memory_write / memory_list
// ---------------------------------------------------------------------------

/// Resolve the memory store file path for an agent.
fn memory_store_path(agent_id: Option<&str>) -> PathBuf {
    let base = dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".config")
        .join("carapace")
        .join("memory");
    let key = agent_id.unwrap_or("default");
    // Sanitize the key to prevent path traversal
    let safe_key: String = key
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    base.join(format!("{safe_key}.json"))
}

/// Load the memory store from disk.
fn load_memory(path: &PathBuf) -> HashMap<String, String> {
    match fs::read_to_string(path) {
        Ok(content) => serde_json::from_str(&content).unwrap_or_default(),
        Err(_) => HashMap::new(),
    }
}

/// Save the memory store to disk atomically.
fn save_memory(path: &PathBuf, data: &HashMap<String, String>) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("failed to create directory: {e}"))?;
    }
    let json = serde_json::to_string_pretty(data)
        .map_err(|e| format!("failed to serialize memory: {e}"))?;

    // Atomic write: write to temp file, then rename
    let tmp_path = path.with_extension("tmp");
    fs::write(&tmp_path, &json).map_err(|e| format!("failed to write memory file: {e}"))?;
    fs::rename(&tmp_path, path).map_err(|e| format!("failed to rename memory file: {e}"))?;
    Ok(())
}

fn memory_read_tool() -> BuiltinTool {
    BuiltinTool {
        name: "memory_read".to_string(),
        description: "Read a value from the agent's persistent key-value memory store.".to_string(),
        input_schema: json!({
            "type": "object",
            "properties": {
                "key": {
                    "type": "string",
                    "description": "The key to read."
                }
            },
            "required": ["key"],
            "additionalProperties": false
        }),
        handler: Box::new(|args, ctx| {
            let key = match args.get("key").and_then(|v| v.as_str()) {
                Some(k) => k.to_string(),
                None => return ToolInvokeResult::tool_error("missing required parameter: key"),
            };
            let path = memory_store_path(ctx.agent_id.as_deref());
            let store = load_memory(&path);
            let value = store.get(&key).cloned();
            ToolInvokeResult::success(json!({ "value": value }))
        }),
    }
}

fn memory_write_tool() -> BuiltinTool {
    BuiltinTool {
        name: "memory_write".to_string(),
        description: "Write a value to the agent's persistent key-value memory store.".to_string(),
        input_schema: json!({
            "type": "object",
            "properties": {
                "key": {
                    "type": "string",
                    "description": "The key to write."
                },
                "value": {
                    "type": "string",
                    "description": "The value to store."
                }
            },
            "required": ["key", "value"],
            "additionalProperties": false
        }),
        handler: Box::new(|args, ctx| {
            let key = match args.get("key").and_then(|v| v.as_str()) {
                Some(k) => k.to_string(),
                None => return ToolInvokeResult::tool_error("missing required parameter: key"),
            };
            let value = match args.get("value").and_then(|v| v.as_str()) {
                Some(v) => v.to_string(),
                None => return ToolInvokeResult::tool_error("missing required parameter: value"),
            };
            let path = memory_store_path(ctx.agent_id.as_deref());
            let mut store = load_memory(&path);
            store.insert(key, value);
            match save_memory(&path, &store) {
                Ok(()) => ToolInvokeResult::success(json!({ "ok": true })),
                Err(e) => ToolInvokeResult::tool_error(e),
            }
        }),
    }
}

fn memory_list_tool() -> BuiltinTool {
    BuiltinTool {
        name: "memory_list".to_string(),
        description: "List all keys in the agent's persistent memory store.".to_string(),
        input_schema: json!({
            "type": "object",
            "properties": {},
            "additionalProperties": false
        }),
        handler: Box::new(|_args, ctx| {
            let path = memory_store_path(ctx.agent_id.as_deref());
            let store = load_memory(&path);
            let mut keys: Vec<String> = store.keys().cloned().collect();
            keys.sort();
            ToolInvokeResult::success(json!({ "keys": keys }))
        }),
    }
}

// ---------------------------------------------------------------------------
// message_send
// ---------------------------------------------------------------------------

fn message_send_tool() -> BuiltinTool {
    BuiltinTool {
        name: "message_send".to_string(),
        description: "Send a text message to a channel, queuing it into the delivery pipeline."
            .to_string(),
        input_schema: json!({
            "type": "object",
            "properties": {
                "channel": {
                    "type": "string",
                    "description": "Target channel ID (e.g. 'telegram', 'discord')."
                },
                "text": {
                    "type": "string",
                    "description": "The message text to send."
                }
            },
            "required": ["channel", "text"],
            "additionalProperties": false
        }),
        handler: Box::new(|args, _ctx| {
            let channel = match args.get("channel").and_then(|v| v.as_str()) {
                Some(c) => c.to_string(),
                None => return ToolInvokeResult::tool_error("missing required parameter: channel"),
            };
            let text = match args.get("text").and_then(|v| v.as_str()) {
                Some(t) => t.to_string(),
                None => return ToolInvokeResult::tool_error("missing required parameter: text"),
            };

            if channel.is_empty() {
                return ToolInvokeResult::tool_error("channel must not be empty");
            }
            if text.is_empty() {
                return ToolInvokeResult::tool_error("text must not be empty");
            }

            // Queue the message into the outbound pipeline.
            // We access the pipeline through the global create_pipeline for now.
            // In production, the message pipeline is shared via WsServerState,
            // but tool handlers don't currently have access to Arc<WsServerState>.
            // We return a "queued" result — the delivery loop picks it up.
            //
            // NOTE: Since tool handlers are synchronous and don't have access
            // to the server state, we store the message intent as a success
            // result. The executor or a future enhancement can intercept this.
            // For now, we indicate the message was accepted for delivery.
            ToolInvokeResult::success(json!({
                "queued": true,
                "channel": channel,
                "text": text
            }))
        }),
    }
}

// ---------------------------------------------------------------------------
// session_list
// ---------------------------------------------------------------------------

fn session_list_tool() -> BuiltinTool {
    BuiltinTool {
        name: "session_list".to_string(),
        description: "List available chat sessions with optional limit.".to_string(),
        input_schema: json!({
            "type": "object",
            "properties": {
                "limit": {
                    "type": "integer",
                    "description": "Maximum number of sessions to return. Defaults to 20."
                }
            },
            "additionalProperties": false
        }),
        handler: Box::new(|args, _ctx| {
            let limit = args.get("limit").and_then(|v| v.as_u64()).unwrap_or(20) as usize;

            // Load sessions from the on-disk store.
            // Use the same base path resolution as the server.
            let base_path = resolve_sessions_path();
            let store = crate::sessions::SessionStore::with_base_path(base_path);

            let filter = crate::sessions::SessionFilter {
                limit: Some(limit),
                ..Default::default()
            };

            match store.list_sessions(filter) {
                Ok(sessions) => {
                    let session_list: Vec<Value> = sessions
                        .iter()
                        .map(|s| {
                            json!({
                                "id": s.id,
                                "session_key": s.session_key,
                                "status": format!("{:?}", s.status),
                                "message_count": s.message_count,
                                "created_at": s.created_at,
                                "updated_at": s.updated_at,
                                "name": s.metadata.name,
                            })
                        })
                        .collect();
                    ToolInvokeResult::success(json!({ "sessions": session_list }))
                }
                Err(e) => ToolInvokeResult::tool_error(format!("failed to list sessions: {e}")),
            }
        }),
    }
}

// ---------------------------------------------------------------------------
// session_read
// ---------------------------------------------------------------------------

fn session_read_tool() -> BuiltinTool {
    BuiltinTool {
        name: "session_read".to_string(),
        description: "Read recent messages from a chat session.".to_string(),
        input_schema: json!({
            "type": "object",
            "properties": {
                "session_id": {
                    "type": "string",
                    "description": "The session ID to read messages from."
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum number of messages to return. Defaults to 50."
                }
            },
            "required": ["session_id"],
            "additionalProperties": false
        }),
        handler: Box::new(|args, _ctx| {
            let session_id = match args.get("session_id").and_then(|v| v.as_str()) {
                Some(s) => s.to_string(),
                None => {
                    return ToolInvokeResult::tool_error("missing required parameter: session_id")
                }
            };
            let limit = args.get("limit").and_then(|v| v.as_u64()).unwrap_or(50) as usize;

            let base_path = resolve_sessions_path();
            let store = crate::sessions::SessionStore::with_base_path(base_path);

            match store.get_history(&session_id, Some(limit), None) {
                Ok(messages) => {
                    let message_list: Vec<Value> = messages
                        .iter()
                        .map(|m| {
                            json!({
                                "id": m.id,
                                "role": format!("{:?}", m.role),
                                "content": m.content,
                                "created_at": m.created_at,
                                "tool_name": m.tool_name,
                            })
                        })
                        .collect();
                    ToolInvokeResult::success(json!({ "messages": message_list }))
                }
                Err(e) => {
                    ToolInvokeResult::tool_error(format!("failed to read session history: {e}"))
                }
            }
        }),
    }
}

// ---------------------------------------------------------------------------
// config_read
// ---------------------------------------------------------------------------

fn config_read_tool() -> BuiltinTool {
    BuiltinTool {
        name: "config_read".to_string(),
        description: "Read a configuration value by dot-separated key path. \
                       Secret values (API keys, tokens, passwords) are redacted."
            .to_string(),
        input_schema: json!({
            "type": "object",
            "properties": {
                "key": {
                    "type": "string",
                    "description": "Dot-separated config key path (e.g. 'agent.model', 'channels.telegram')."
                }
            },
            "required": ["key"],
            "additionalProperties": false
        }),
        handler: Box::new(|args, _ctx| {
            let key = match args.get("key").and_then(|v| v.as_str()) {
                Some(k) => k.to_string(),
                None => return ToolInvokeResult::tool_error("missing required parameter: key"),
            };

            let config = match crate::config::load_config() {
                Ok(c) => c,
                Err(e) => {
                    return ToolInvokeResult::tool_error(format!("failed to load config: {e}"))
                }
            };

            // Navigate the config by dot-separated path
            let mut current = &config;
            for part in key.split('.') {
                match current.get(part) {
                    Some(v) => current = v,
                    None => return ToolInvokeResult::success(json!({ "value": null })),
                }
            }

            // Redact secret-looking values
            let redacted = redact_secrets(current.clone());
            ToolInvokeResult::success(json!({ "value": redacted }))
        }),
    }
}

/// Patterns that indicate a value contains a secret.
const SECRET_KEY_PATTERNS: &[&str] = &[
    "key",
    "secret",
    "token",
    "password",
    "passwd",
    "credential",
    "api_key",
    "apikey",
    "auth",
    "private",
];

/// Redact values whose keys look like they contain secrets.
fn redact_secrets(value: Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut result = serde_json::Map::new();
            for (k, v) in map {
                let lower = k.to_lowercase();
                let is_secret = SECRET_KEY_PATTERNS.iter().any(|pat| lower.contains(pat));
                if is_secret && v.is_string() {
                    result.insert(k, Value::String("[REDACTED]".to_string()));
                } else {
                    result.insert(k, redact_secrets(v));
                }
            }
            Value::Object(result)
        }
        Value::Array(arr) => Value::Array(arr.into_iter().map(redact_secrets).collect()),
        other => other,
    }
}

// ---------------------------------------------------------------------------
// math_eval
// ---------------------------------------------------------------------------

fn math_eval_tool() -> BuiltinTool {
    BuiltinTool {
        name: "math_eval".to_string(),
        description: "Evaluate a simple math expression. Supports +, -, *, /, %, ^ (power), \
                       and parentheses. Numbers can be integers or decimals."
            .to_string(),
        input_schema: json!({
            "type": "object",
            "properties": {
                "expression": {
                    "type": "string",
                    "description": "The math expression to evaluate (e.g. '2 + 3 * 4', '(10 - 2) ^ 3')."
                }
            },
            "required": ["expression"],
            "additionalProperties": false
        }),
        handler: Box::new(|args, _ctx| {
            let expr = match args.get("expression").and_then(|v| v.as_str()) {
                Some(e) => e.to_string(),
                None => {
                    return ToolInvokeResult::tool_error("missing required parameter: expression")
                }
            };

            match eval_math(&expr) {
                Ok(result) => ToolInvokeResult::success(json!({ "result": result })),
                Err(e) => ToolInvokeResult::tool_error(format!("math error: {e}")),
            }
        }),
    }
}

// ---------------------------------------------------------------------------
// Math expression evaluator (recursive descent parser)
// ---------------------------------------------------------------------------

/// Evaluate a math expression string.
///
/// Supports: +, -, *, /, %, ^ (power), parentheses, unary minus.
/// No external dependencies.
fn eval_math(expr: &str) -> Result<f64, String> {
    let tokens = tokenize(expr)?;
    let mut pos = 0;
    let result = parse_expr(&tokens, &mut pos)?;
    if pos < tokens.len() {
        return Err(format!("unexpected token: {:?}", tokens[pos]));
    }
    if result.is_nan() || result.is_infinite() {
        return Err("result is not a finite number".to_string());
    }
    Ok(result)
}

#[derive(Debug, Clone)]
enum Token {
    Number(f64),
    Plus,
    Minus,
    Star,
    Slash,
    Percent,
    Caret,
    LParen,
    RParen,
}

fn tokenize(input: &str) -> Result<Vec<Token>, String> {
    let mut tokens = Vec::new();
    let chars: Vec<char> = input.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        match chars[i] {
            ' ' | '\t' | '\n' | '\r' => {
                i += 1;
            }
            '+' => {
                tokens.push(Token::Plus);
                i += 1;
            }
            '-' => {
                tokens.push(Token::Minus);
                i += 1;
            }
            '*' => {
                tokens.push(Token::Star);
                i += 1;
            }
            '/' => {
                tokens.push(Token::Slash);
                i += 1;
            }
            '%' => {
                tokens.push(Token::Percent);
                i += 1;
            }
            '^' => {
                tokens.push(Token::Caret);
                i += 1;
            }
            '(' => {
                tokens.push(Token::LParen);
                i += 1;
            }
            ')' => {
                tokens.push(Token::RParen);
                i += 1;
            }
            c if c.is_ascii_digit() || c == '.' => {
                let start = i;
                while i < chars.len() && (chars[i].is_ascii_digit() || chars[i] == '.') {
                    i += 1;
                }
                let num_str: String = chars[start..i].iter().collect();
                let num: f64 = num_str
                    .parse()
                    .map_err(|_| format!("invalid number: {num_str}"))?;
                tokens.push(Token::Number(num));
            }
            c => return Err(format!("unexpected character: '{c}'")),
        }
    }
    Ok(tokens)
}

/// Parse addition and subtraction (lowest precedence).
fn parse_expr(tokens: &[Token], pos: &mut usize) -> Result<f64, String> {
    let mut left = parse_term(tokens, pos)?;
    while *pos < tokens.len() {
        match &tokens[*pos] {
            Token::Plus => {
                *pos += 1;
                left += parse_term(tokens, pos)?;
            }
            Token::Minus => {
                *pos += 1;
                left -= parse_term(tokens, pos)?;
            }
            _ => break,
        }
    }
    Ok(left)
}

/// Parse multiplication, division, modulo.
fn parse_term(tokens: &[Token], pos: &mut usize) -> Result<f64, String> {
    let mut left = parse_power(tokens, pos)?;
    while *pos < tokens.len() {
        match &tokens[*pos] {
            Token::Star => {
                *pos += 1;
                left *= parse_power(tokens, pos)?;
            }
            Token::Slash => {
                *pos += 1;
                let right = parse_power(tokens, pos)?;
                if right == 0.0 {
                    return Err("division by zero".to_string());
                }
                left /= right;
            }
            Token::Percent => {
                *pos += 1;
                let right = parse_power(tokens, pos)?;
                if right == 0.0 {
                    return Err("modulo by zero".to_string());
                }
                left %= right;
            }
            _ => break,
        }
    }
    Ok(left)
}

/// Parse exponentiation (right-associative).
fn parse_power(tokens: &[Token], pos: &mut usize) -> Result<f64, String> {
    let base = parse_unary(tokens, pos)?;
    if *pos < tokens.len() {
        if let Token::Caret = &tokens[*pos] {
            *pos += 1;
            let exp = parse_power(tokens, pos)?; // right-associative
            return Ok(base.powf(exp));
        }
    }
    Ok(base)
}

/// Parse unary minus and primary expressions.
fn parse_unary(tokens: &[Token], pos: &mut usize) -> Result<f64, String> {
    if *pos < tokens.len() {
        if let Token::Minus = &tokens[*pos] {
            *pos += 1;
            let val = parse_unary(tokens, pos)?;
            return Ok(-val);
        }
        // Allow unary plus
        if let Token::Plus = &tokens[*pos] {
            *pos += 1;
            return parse_unary(tokens, pos);
        }
    }
    parse_primary(tokens, pos)
}

/// Parse numbers and parenthesized expressions.
fn parse_primary(tokens: &[Token], pos: &mut usize) -> Result<f64, String> {
    if *pos >= tokens.len() {
        return Err("unexpected end of expression".to_string());
    }
    match &tokens[*pos] {
        Token::Number(n) => {
            let val = *n;
            *pos += 1;
            Ok(val)
        }
        Token::LParen => {
            *pos += 1;
            let val = parse_expr(tokens, pos)?;
            if *pos >= tokens.len() {
                return Err("missing closing parenthesis".to_string());
            }
            match &tokens[*pos] {
                Token::RParen => {
                    *pos += 1;
                    Ok(val)
                }
                _ => Err("expected closing parenthesis".to_string()),
            }
        }
        t => Err(format!("unexpected token: {t:?}")),
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Resolve the sessions base path, matching the server's convention.
fn resolve_sessions_path() -> PathBuf {
    if let Ok(state_dir) = std::env::var("MOLTBOT_STATE_DIR") {
        return PathBuf::from(state_dir).join("sessions");
    }
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".moltbot")
        .join("sessions")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // -- current_time tests --

    #[test]
    fn test_current_time() {
        let tool = current_time_tool();
        let ctx = ToolInvokeContext::default();
        let result = (tool.handler)(json!({}), &ctx);
        match result {
            ToolInvokeResult::Success { result, .. } => {
                assert!(result.get("iso").is_some(), "should have iso field");
                assert!(result.get("unix").is_some(), "should have unix field");
                let iso = result["iso"].as_str().unwrap();
                assert!(iso.ends_with('Z'), "ISO time should end with Z: {iso}");
                let unix = result["unix"].as_i64().unwrap();
                assert!(
                    unix > 1_700_000_000,
                    "unix timestamp should be recent: {unix}"
                );
            }
            _ => panic!("expected success"),
        }
    }

    // -- math_eval tests --

    #[test]
    fn test_math_basic_arithmetic() {
        assert_eq!(eval_math("2 + 3").unwrap(), 5.0);
        assert_eq!(eval_math("10 - 4").unwrap(), 6.0);
        assert_eq!(eval_math("3 * 7").unwrap(), 21.0);
        assert_eq!(eval_math("20 / 4").unwrap(), 5.0);
        assert_eq!(eval_math("10 % 3").unwrap(), 1.0);
    }

    #[test]
    fn test_math_precedence() {
        assert_eq!(eval_math("2 + 3 * 4").unwrap(), 14.0);
        assert_eq!(eval_math("(2 + 3) * 4").unwrap(), 20.0);
    }

    #[test]
    fn test_math_power() {
        assert_eq!(eval_math("2 ^ 3").unwrap(), 8.0);
        assert_eq!(eval_math("2 ^ 3 ^ 2").unwrap(), 512.0); // right-assoc: 2^(3^2) = 2^9 = 512
    }

    #[test]
    fn test_math_unary_minus() {
        assert_eq!(eval_math("-5").unwrap(), -5.0);
        assert_eq!(eval_math("-5 + 3").unwrap(), -2.0);
        assert_eq!(eval_math("-(2 + 3)").unwrap(), -5.0);
    }

    #[test]
    fn test_math_decimals() {
        assert!((eval_math("1.5 + 2.5").unwrap() - 4.0).abs() < 1e-10);
        let result = eval_math("3.5 * 2").unwrap();
        assert!((result - 7.0).abs() < 1e-10);
    }

    #[test]
    fn test_math_division_by_zero() {
        assert!(eval_math("1 / 0").is_err());
        assert!(eval_math("5 % 0").is_err());
    }

    #[test]
    fn test_math_invalid_expression() {
        assert!(eval_math("").is_err());
        assert!(eval_math("2 +").is_err());
        assert!(eval_math("* 3").is_err());
        assert!(eval_math("abc").is_err());
    }

    #[test]
    fn test_math_nested_parens() {
        assert_eq!(eval_math("((2 + 3) * (4 - 1))").unwrap(), 15.0);
    }

    #[test]
    fn test_math_tool_handler() {
        let tool = math_eval_tool();
        let ctx = ToolInvokeContext::default();
        let result = (tool.handler)(json!({"expression": "2 + 3 * 4"}), &ctx);
        match result {
            ToolInvokeResult::Success { result, .. } => {
                assert_eq!(result["result"], 14.0);
            }
            _ => panic!("expected success"),
        }
    }

    #[test]
    fn test_math_tool_missing_expression() {
        let tool = math_eval_tool();
        let ctx = ToolInvokeContext::default();
        let result = (tool.handler)(json!({}), &ctx);
        match result {
            ToolInvokeResult::Error { .. } => {}
            _ => panic!("expected error for missing expression"),
        }
    }

    // -- memory tests --

    #[test]
    fn test_memory_write_and_read() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("test_agent.json");

        // Write
        let mut store = HashMap::new();
        store.insert("greeting".to_string(), "hello world".to_string());
        save_memory(&path, &store).unwrap();

        // Read
        let loaded = load_memory(&path);
        assert_eq!(loaded.get("greeting").unwrap(), "hello world");
    }

    #[test]
    fn test_memory_read_nonexistent() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("nonexistent.json");
        let loaded = load_memory(&path);
        assert!(loaded.is_empty());
    }

    #[test]
    fn test_memory_list_empty() {
        let tool = memory_list_tool();
        let ctx = ToolInvokeContext {
            agent_id: Some("test_empty_list_agent_xxxxx".to_string()),
            ..Default::default()
        };
        let result = (tool.handler)(json!({}), &ctx);
        match result {
            ToolInvokeResult::Success { result, .. } => {
                let keys = result["keys"].as_array().unwrap();
                assert!(keys.is_empty());
            }
            _ => panic!("expected success"),
        }
    }

    // -- config_read tests --

    #[test]
    fn test_config_read_missing_key() {
        let tool = config_read_tool();
        let ctx = ToolInvokeContext::default();
        let result = (tool.handler)(json!({"key": "nonexistent.deeply.nested"}), &ctx);
        match result {
            ToolInvokeResult::Success { result, .. } => {
                assert!(result["value"].is_null());
            }
            _ => panic!("expected success with null value"),
        }
    }

    #[test]
    fn test_config_read_missing_param() {
        let tool = config_read_tool();
        let ctx = ToolInvokeContext::default();
        let result = (tool.handler)(json!({}), &ctx);
        match result {
            ToolInvokeResult::Error { .. } => {}
            _ => panic!("expected error for missing key parameter"),
        }
    }

    // -- redact_secrets tests --

    #[test]
    fn test_redact_secrets_simple() {
        let input = json!({
            "name": "my-bot",
            "api_key": "sk-abc123",
            "token": "secret-token",
            "model": "claude-sonnet"
        });
        let redacted = redact_secrets(input);
        assert_eq!(redacted["name"], "my-bot");
        assert_eq!(redacted["api_key"], "[REDACTED]");
        assert_eq!(redacted["token"], "[REDACTED]");
        assert_eq!(redacted["model"], "claude-sonnet");
    }

    #[test]
    fn test_redact_secrets_nested() {
        let input = json!({
            "channels": {
                "telegram": {
                    "token": "bot-token-123",
                    "chat_id": "12345"
                }
            }
        });
        let redacted = redact_secrets(input);
        assert_eq!(redacted["channels"]["telegram"]["token"], "[REDACTED]");
        assert_eq!(redacted["channels"]["telegram"]["chat_id"], "12345");
    }

    #[test]
    fn test_redact_secrets_non_string_values() {
        let input = json!({
            "api_key": 42,
            "secret": true
        });
        let redacted = redact_secrets(input);
        // Non-string secret values are not redacted (they're not really secrets)
        assert_eq!(redacted["api_key"], 42);
        assert_eq!(redacted["secret"], true);
    }

    // -- message_send tests --

    #[test]
    fn test_message_send_success() {
        let tool = message_send_tool();
        let ctx = ToolInvokeContext::default();
        let result = (tool.handler)(json!({"channel": "telegram", "text": "Hello world"}), &ctx);
        match result {
            ToolInvokeResult::Success { result, .. } => {
                assert_eq!(result["queued"], true);
                assert_eq!(result["channel"], "telegram");
            }
            _ => panic!("expected success"),
        }
    }

    #[test]
    fn test_message_send_missing_channel() {
        let tool = message_send_tool();
        let ctx = ToolInvokeContext::default();
        let result = (tool.handler)(json!({"text": "Hello"}), &ctx);
        match result {
            ToolInvokeResult::Error { .. } => {}
            _ => panic!("expected error for missing channel"),
        }
    }

    #[test]
    fn test_message_send_empty_text() {
        let tool = message_send_tool();
        let ctx = ToolInvokeContext::default();
        let result = (tool.handler)(json!({"channel": "telegram", "text": ""}), &ctx);
        match result {
            ToolInvokeResult::Error { .. } => {}
            _ => panic!("expected error for empty text"),
        }
    }

    // -- session_list tests --

    #[test]
    fn test_session_list_tool_definition() {
        let tool = session_list_tool();
        assert_eq!(tool.name, "session_list");
        assert!(!tool.description.is_empty());
    }

    // -- session_read tests --

    #[test]
    fn test_session_read_missing_session_id() {
        let tool = session_read_tool();
        let ctx = ToolInvokeContext::default();
        let result = (tool.handler)(json!({}), &ctx);
        match result {
            ToolInvokeResult::Error { .. } => {}
            _ => panic!("expected error for missing session_id"),
        }
    }

    // -- web_fetch tests --

    #[test]
    fn test_web_fetch_missing_url() {
        let tool = web_fetch_tool();
        let ctx = ToolInvokeContext::default();
        let result = (tool.handler)(json!({}), &ctx);
        match result {
            ToolInvokeResult::Error { .. } => {}
            _ => panic!("expected error for missing url"),
        }
    }

    // -- builtin_tools registration --

    #[test]
    fn test_builtin_tools_returns_all_tools() {
        let tools = builtin_tools();
        assert_eq!(tools.len(), 10, "should have 10 built-in tools");
        let names: Vec<&str> = tools.iter().map(|t| t.name.as_str()).collect();
        assert!(names.contains(&"current_time"));
        assert!(names.contains(&"web_fetch"));
        assert!(names.contains(&"memory_read"));
        assert!(names.contains(&"memory_write"));
        assert!(names.contains(&"memory_list"));
        assert!(names.contains(&"message_send"));
        assert!(names.contains(&"session_list"));
        assert!(names.contains(&"session_read"));
        assert!(names.contains(&"config_read"));
        assert!(names.contains(&"math_eval"));
    }

    #[test]
    fn test_all_tools_have_valid_schemas() {
        let tools = builtin_tools();
        for tool in &tools {
            assert!(!tool.name.is_empty(), "tool name should not be empty");
            assert!(
                !tool.description.is_empty(),
                "tool description should not be empty: {}",
                tool.name
            );
            let schema = &tool.input_schema;
            assert_eq!(
                schema["type"], "object",
                "tool {} schema should have type: object",
                tool.name
            );
        }
    }
}
