//! Secret masking and redaction for logs and error responses.
//!
//! Provides utilities to scrub API keys, tokens, passwords, and other
//! sensitive data from log output and error response bodies.

use regex::Regex;
use serde_json::Value;
use std::io::{self, Write};
use std::sync::LazyLock;
use tracing_subscriber::fmt::MakeWriter;

const SECRET_KEY_NAMES: &[&str] = &[
    "apikey",
    "api_key",
    "token",
    "secret",
    "password",
    "credentials",
    "client_secret",
    "refresh_token",
    "access_token",
];

static RE_OPENAI_KEY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"sk-[a-zA-Z0-9]{20,}").expect("failed to compile regex: openai_key")
});

static RE_BEARER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"Bearer [a-zA-Z0-9._\-]+").expect("failed to compile regex: bearer")
});

static RE_BASIC_AUTH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"Basic [a-zA-Z0-9+/=]+").expect("failed to compile regex: basic_auth")
});

static RE_QUERY_SECRET: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(key|token)=([a-zA-Z0-9]{40,})").expect("failed to compile regex: query_secret")
});

pub struct Redactor;

impl Redactor {
    pub fn new() -> Self {
        Self
    }

    pub fn redact_string(&self, input: &str) -> String {
        redact_string(input)
    }

    pub fn redact_json_value(&self, value: &mut Value) {
        redact_json_value(value);
    }

    pub fn redact_error_response(&self, response: &mut Value) {
        redact_error_response(response);
    }
}

impl Default for Redactor {
    fn default() -> Self {
        Self::new()
    }
}

pub struct RedactingWriter<W: Write> {
    inner: W,
    buffer: Vec<u8>,
}

const MAX_BUFFER_BYTES: usize = 8192;

impl<W: Write> RedactingWriter<W> {
    pub fn new(inner: W) -> Self {
        Self {
            inner,
            buffer: Vec::new(),
        }
    }

    fn flush_buffer(&mut self) -> io::Result<()> {
        if self.buffer.is_empty() {
            return Ok(());
        }
        let text = String::from_utf8_lossy(&self.buffer);
        let redacted = redact_string(&text);
        self.inner.write_all(redacted.as_bytes())?;
        self.zeroize_buffer();
        Ok(())
    }

    fn zeroize_buffer(&mut self) {
        if !self.buffer.is_empty() {
            self.buffer.fill(0);
            self.buffer.clear();
        }
    }
}

impl<W: Write> Write for RedactingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        self.buffer.extend_from_slice(buf);
        if self.buffer.len() > MAX_BUFFER_BYTES {
            self.flush_buffer()?;
        }
        while let Some(pos) = self.buffer.iter().position(|b| *b == b'\n') {
            let mut line = self.buffer.drain(..=pos).collect::<Vec<u8>>();
            let has_newline = matches!(line.last(), Some(b'\n'));
            if has_newline {
                line.pop();
            }
            let text = String::from_utf8_lossy(&line);
            let redacted = redact_string(&text);
            self.inner.write_all(redacted.as_bytes())?;
            if has_newline {
                self.inner.write_all(b"\n")?;
            }
            line.fill(0);
        }

        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.flush_buffer()?;
        self.inner.flush()
    }
}

impl<W: Write> Drop for RedactingWriter<W> {
    fn drop(&mut self) {
        let _ = self.flush_buffer();
        let _ = self.inner.flush();
    }
}

pub struct RedactingMakeWriter<M> {
    inner: M,
}

impl<M> RedactingMakeWriter<M> {
    pub fn new(inner: M) -> Self {
        Self { inner }
    }
}

impl<'a, M> MakeWriter<'a> for RedactingMakeWriter<M>
where
    M: MakeWriter<'a>,
    M::Writer: Write,
{
    type Writer = RedactingWriter<M::Writer>;

    fn make_writer(&'a self) -> Self::Writer {
        RedactingWriter::new(self.inner.make_writer())
    }
}

pub fn redact_string(input: &str) -> String {
    if input.is_empty() {
        return String::new();
    }

    let mut result = RE_OPENAI_KEY.replace_all(input, "[REDACTED]").into_owned();
    result = RE_BEARER.replace_all(&result, "[REDACTED]").into_owned();
    result = RE_BASIC_AUTH
        .replace_all(&result, "[REDACTED]")
        .into_owned();
    result = RE_QUERY_SECRET
        .replace_all(&result, "$1=[REDACTED]")
        .into_owned();

    result
}

pub fn redact_json_value(value: &mut Value) {
    match value {
        Value::Object(map) => {
            let keys: Vec<String> = map.keys().cloned().collect();
            for key in keys {
                let lower = key.to_lowercase();
                let is_secret = SECRET_KEY_NAMES.iter().any(|s| lower.contains(s));

                if is_secret {
                    if let Some(v) = map.get(&key) {
                        if v.is_string() {
                            map.insert(key, Value::String("[REDACTED]".to_string()));
                        }
                    }
                } else if let Some(child) = map.get_mut(&key) {
                    redact_json_value(child);
                }
            }
        }
        Value::Array(arr) => {
            for item in arr.iter_mut() {
                redact_json_value(item);
            }
        }
        _ => {}
    }
}

pub fn redact_error_response(response: &mut Value) {
    redact_json_value(response);

    if let Some(msg) = response.get("message").and_then(|v| v.as_str()) {
        let scrubbed = redact_string(msg);
        if scrubbed != msg {
            response["message"] = Value::String(scrubbed);
        }
    }
}

pub struct RedactedDisplay<T: std::fmt::Display>(pub T);

impl<T: std::fmt::Display> std::fmt::Display for RedactedDisplay<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let raw = self.0.to_string();
        let redacted = redact_string(&raw);
        f.write_str(&redacted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::io::Write;

    #[test]
    fn test_openai_key_is_redacted() {
        let input = "key is sk-abcdefghijklmnopqrstuvwxyz1234567890abcdef end";
        let result = redact_string(input);
        assert!(!result.contains("sk-abcdefghij"));
        assert!(result.contains("[REDACTED]"));
        assert!(result.contains("key is "));
        assert!(result.contains(" end"));
    }

    #[test]
    fn test_bearer_token_is_redacted() {
        let input = "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig";
        let result = redact_string(input);
        assert!(!result.contains("eyJhbGci"));
        assert!(result.contains("[REDACTED]"));
    }

    #[test]
    fn test_basic_auth_is_redacted() {
        let input = "Authorization: Basic dXNlcjpwYXNzd29yZA==";
        let result = redact_string(input);
        assert!(!result.contains("dXNlcjpwYXNzd29yZA=="));
        assert!(result.contains("[REDACTED]"));
    }

    #[test]
    fn test_api_key_in_query_param_is_redacted() {
        let long_key = "a".repeat(50);
        let input = format!("https://api.example.com/v1?key={long_key}&other=safe");
        let result = redact_string(&input);
        assert!(!result.contains(&long_key));
        assert!(result.contains("key=[REDACTED]"));
        assert!(result.contains("&other=safe"));
    }

    #[test]
    fn test_token_in_query_param_is_redacted() {
        let long_token = "b".repeat(45);
        let input = format!("ws://host/ws?token={long_token}");
        let result = redact_string(&input);
        assert!(!result.contains(&long_token));
        assert!(result.contains("token=[REDACTED]"));
    }

    #[test]
    fn test_json_known_keys_redacted() {
        let mut val = json!({
            "apiKey": "my-secret-api-key",
            "token": "tok_123",
            "secret": "s3cr3t",
            "password": "hunter2",
            "name": "test-bot"
        });
        redact_json_value(&mut val);
        assert_eq!(val["apiKey"], "[REDACTED]");
        assert_eq!(val["token"], "[REDACTED]");
        assert_eq!(val["secret"], "[REDACTED]");
        assert_eq!(val["password"], "[REDACTED]");
        assert_eq!(val["name"], "test-bot");
    }

    #[test]
    fn test_json_case_insensitive_keys() {
        let mut val = json!({
            "ApiKey": "key1",
            "API_KEY": "key2",
            "apikey": "key3",
            "TOKEN": "tok1",
            "Password": "pw"
        });
        redact_json_value(&mut val);
        assert_eq!(val["ApiKey"], "[REDACTED]");
        assert_eq!(val["API_KEY"], "[REDACTED]");
        assert_eq!(val["apikey"], "[REDACTED]");
        assert_eq!(val["TOKEN"], "[REDACTED]");
        assert_eq!(val["Password"], "[REDACTED]");
    }

    #[test]
    fn test_json_non_secret_keys_preserved() {
        let mut val = json!({
            "name": "MyBot",
            "id": "12345",
            "description": "A helpful bot",
            "version": "1.0"
        });
        let original = val.clone();
        redact_json_value(&mut val);
        assert_eq!(val, original);
    }

    #[test]
    fn test_json_nested_objects() {
        let mut val = json!({
            "config": {
                "provider": {
                    "apiKey": "nested-key",
                    "model": "gpt-4"
                },
                "name": "bot"
            }
        });
        redact_json_value(&mut val);
        assert_eq!(val["config"]["provider"]["apiKey"], "[REDACTED]");
        assert_eq!(val["config"]["provider"]["model"], "gpt-4");
        assert_eq!(val["config"]["name"], "bot");
    }

    #[test]
    fn test_json_arrays_of_objects() {
        let mut val = json!([
            {"token": "tok1", "name": "a"},
            {"token": "tok2", "name": "b"},
            {"id": 3}
        ]);
        redact_json_value(&mut val);
        assert_eq!(val[0]["token"], "[REDACTED]");
        assert_eq!(val[0]["name"], "a");
        assert_eq!(val[1]["token"], "[REDACTED]");
        assert_eq!(val[1]["name"], "b");
        assert_eq!(val[2]["id"], 3);
    }

    #[test]
    fn test_normal_string_unchanged() {
        let input = "INFO gateway: connected to provider model=gpt-4 latency_ms=42";
        let result = redact_string(input);
        assert_eq!(result, input);
    }

    #[test]
    fn test_empty_string_returns_empty() {
        let result = redact_string("");
        assert_eq!(result, "");
    }

    #[test]
    fn test_multiple_secrets_all_redacted() {
        let input = "auth: Bearer abc.def.ghi key: sk-aaaabbbbccccddddeeeeffffgggg";
        let result = redact_string(input);
        assert!(!result.contains("abc.def.ghi"));
        assert!(!result.contains("sk-aaaa"));
        assert_eq!(result.matches("[REDACTED]").count(), 2);
    }

    #[test]
    fn test_redacted_display_wraps_and_redacts() {
        let msg = "failed: Bearer eyToken123.payload.sig";
        let displayed = format!("{}", RedactedDisplay(msg));
        assert!(!displayed.contains("eyToken123"));
        assert!(displayed.contains("[REDACTED]"));
        assert!(displayed.contains("failed: "));
    }

    #[test]
    fn test_redacted_display_no_secret_passthrough() {
        let msg = "all good, nothing secret here";
        let displayed = format!("{}", RedactedDisplay(msg));
        assert_eq!(displayed, msg);
    }

    #[test]
    fn test_redacting_writer_redacts_lines() {
        let mut inner: Vec<u8> = Vec::new();
        {
            let mut writer = RedactingWriter::new(&mut inner);
            write!(writer, "Authorization: Bearer abc.def.ghi\nok").unwrap();
            writer.flush().unwrap();
        }
        let output = String::from_utf8(inner).unwrap();
        assert!(!output.contains("abc.def.ghi"));
        assert!(output.contains("[REDACTED]"));
        assert!(output.contains("ok"));
    }

    #[test]
    fn test_redacting_writer_flushes_on_max_buffer() {
        let mut inner: Vec<u8> = Vec::new();
        let chunk = "Bearer abc.def.ghi ";
        let repeat = (MAX_BUFFER_BYTES / chunk.len()) + 2;
        let payload = chunk.repeat(repeat);
        {
            let mut writer = RedactingWriter::new(&mut inner);
            write!(writer, "{}", payload).unwrap();
            writer.flush().unwrap();
        }
        let output = String::from_utf8(inner).unwrap();
        assert!(!output.contains("abc.def.ghi"));
        assert!(output.contains("[REDACTED]"));
    }

    #[test]
    fn test_error_response_message_scrubbed() {
        let mut resp = json!({
            "error": true,
            "message": "auth failed with Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig",
            "code": 401
        });
        redact_error_response(&mut resp);
        let msg = resp["message"].as_str().unwrap();
        assert!(!msg.contains("eyJhbGci"));
        assert!(msg.contains("[REDACTED]"));
        assert_eq!(resp["code"], 401);
    }

    #[test]
    fn test_error_response_key_based_redaction() {
        let mut resp = json!({
            "error": "unauthorized",
            "credentials": "secret-creds",
            "request_id": "abc-123"
        });
        redact_error_response(&mut resp);
        assert_eq!(resp["credentials"], "[REDACTED]");
        assert_eq!(resp["request_id"], "abc-123");
    }

    #[test]
    fn test_config_mixed_secret_and_non_secret() {
        let mut val = json!({
            "provider": "openai",
            "api_key": "sk-test123456789",
            "model": "gpt-4",
            "client_secret": "cs_verysecret",
            "max_tokens": 4096
        });
        redact_json_value(&mut val);
        assert_eq!(val["provider"], "openai");
        assert_eq!(val["api_key"], "[REDACTED]");
        assert_eq!(val["model"], "gpt-4");
        assert_eq!(val["client_secret"], "[REDACTED]");
        assert_eq!(val["max_tokens"], 4096);
    }

    #[test]
    fn test_long_string_no_backtracking() {
        let long = "a]".repeat(50_000);
        let start = std::time::Instant::now();
        let result = redact_string(&long);
        let elapsed = start.elapsed();
        assert!(elapsed.as_secs() < 2);
        assert_eq!(result, long);
    }

    #[test]
    fn test_unicode_preserved() {
        let input = " {7528} {6237} said:  {3053} {3093} {306b} {3061} {306f}! Bearer abc.def.ghi  {2014} done  {2713}";
        let result = redact_string(input);
        assert!(result.contains(" {7528} {6237} said:"));
        assert!(result.contains(" {2014} done  {2713}"));
        assert!(!result.contains("abc.def.ghi"));
    }

    #[test]
    fn test_partial_key_substring_match() {
        let mut val = json!({
            "token_count": "1500",
            "status": "ok"
        });
        redact_json_value(&mut val);
        assert_eq!(val["token_count"], "[REDACTED]");
        assert_eq!(val["status"], "ok");
    }

    #[test]
    fn test_key_containing_api_key_redacts() {
        let mut val = json!({
            "is_api_key_valid": "yes",
            "my_secret_value": "hidden"
        });
        redact_json_value(&mut val);
        assert_eq!(val["is_api_key_valid"], "[REDACTED]");
        assert_eq!(val["my_secret_value"], "[REDACTED]");
    }

    #[test]
    fn test_json_null_bool_number_noop() {
        let mut null_val = Value::Null;
        redact_json_value(&mut null_val);
        assert_eq!(null_val, Value::Null);

        let mut bool_val = Value::Bool(true);
        redact_json_value(&mut bool_val);
        assert_eq!(bool_val, Value::Bool(true));

        let mut num_val = json!(42);
        redact_json_value(&mut num_val);
        assert_eq!(num_val, json!(42));
    }

    #[test]
    fn test_secret_key_non_string_value_not_replaced() {
        let mut val = json!({
            "token": 12345,
            "password": true,
            "secret": null
        });
        redact_json_value(&mut val);
        assert_eq!(val["token"], 12345);
        assert_eq!(val["password"], true);
        assert!(val["secret"].is_null());
    }

    #[test]
    fn test_refresh_and_access_token_keys() {
        let mut val = json!({
            "refresh_token": "rt_abc123",
            "access_token": "at_xyz789",
            "scope": "read"
        });
        redact_json_value(&mut val);
        assert_eq!(val["refresh_token"], "[REDACTED]");
        assert_eq!(val["access_token"], "[REDACTED]");
        assert_eq!(val["scope"], "read");
    }

    #[test]
    fn test_multiline_input() {
        let input = "line1
Authorization: Bearer token123.payload.sig
line3
";
        let result = redact_string(input);
        assert!(result.contains(
            "line1
"
        ));
        assert!(result.contains(
            "
line3
"
        ));
        assert!(!result.contains("token123.payload.sig"));
    }

    #[test]
    fn test_error_response_nested() {
        let mut resp = json!({
            "error": {
                "message": "something went wrong with sk-aaaa1111bbbb2222cccc3333dddd4444eeee",
                "details": {
                    "apiKey": "leaked-key"
                }
            },
            "status": 500
        });
        redact_error_response(&mut resp);
        assert_eq!(resp["error"]["details"]["apiKey"], "[REDACTED]");
        assert_eq!(resp["status"], 500);
    }
}
