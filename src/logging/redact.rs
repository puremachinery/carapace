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
    "accesskeyid",
    "access_key_id",
    "token",
    "secret",
    "password",
    "passphrase",
    "recovery",
    "recoverykey",
    "recovery_key",
    "credentials",
    "client_secret",
    "clientsecret",
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
    // The `recovery_key` and `recoveryKey` arms in earlier versions
    // were dead under regex left-most match (`key` matches as a
    // suffix of either) and contributed only confusion. Stick with
    // `key|token|secret` and require ≥32 chars to avoid scrubbing
    // benign short hex tokens, room IDs, and pagination cursors —
    // realistic secret tokens are well above this floor.
    Regex::new(r"(?i)(key|token|secret)=([a-zA-Z0-9._\-]{32,})")
        .expect("failed to compile regex: query_secret")
});

/// Matrix recovery keys are encoded as 12 four-character groups
/// separated by single ASCII spaces (e.g. "EsTb XYZ1 ABC2 DEF3 ...
/// CDEF"). matrix-sdk emits them via base58 (Bitcoin alphabet, which
/// excludes `0/O/I/l`), so tightening the alphabet from generic
/// alphanumeric to base58 keeps the redactor specific to recovery
/// keys and avoids over-redacting hex dumps, mac-address listings,
/// and base32 blobs that happen to chunk by 4. Without this tightening
/// every "DEAD BEEF FACE FEED CAFE BABE 1234 5678 9ABC DEF0 1122 3344"
/// hex string would be silently scrubbed from logs.
static RE_MATRIX_RECOVERY_KEY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b[a-km-zA-HJ-NP-Z1-9]{4}(?:\s[a-km-zA-HJ-NP-Z1-9]{4}){11}\b")
        .expect("failed to compile regex: matrix_recovery_key")
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

    pub fn redact_value_at_key(&self, value: &mut Value, key_name: &str) {
        redact_value_at_key(value, key_name);
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
        // Drop is the canonical place for unrecoverable I/O errors to
        // surface — we cannot return them up the call stack. A silent
        // `let _ = ...` here loses the trailing log buffer (up to 8 KiB
        // of context that never reaches disk) without leaving any
        // operator-visible signal that the loss happened. `eprintln!`
        // is the documented escape hatch for Drop-time I/O reporting:
        // no allocation, no chance of recursive logger reentry, and the
        // message reaches the operator's terminal at process shutdown.
        if let Err(err) = self.flush_buffer() {
            eprintln!("RedactingWriter: dropping unsynced log buffer at shutdown: {err}");
        }
        if let Err(err) = self.inner.flush() {
            eprintln!("RedactingWriter: inner writer flush failed at shutdown: {err}");
        }
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
    result = RE_MATRIX_RECOVERY_KEY
        .replace_all(&result, "[REDACTED]")
        .into_owned();

    result
}

pub fn redact_json_value(value: &mut Value) {
    match value {
        Value::Object(map) => {
            let keys: Vec<String> = map.keys().cloned().collect();
            for key in keys {
                if is_secret_key_name(&key) {
                    if let Some(value) = map.get_mut(&key) {
                        redact_secret_named_value(value);
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

fn redact_secret_named_value(value: &mut Value) {
    match value {
        Value::String(_) => {
            *value = Value::String("[REDACTED]".to_string());
        }
        Value::Number(_) | Value::Bool(_) => {
            *value = Value::Null;
        }
        Value::Null => {}
        Value::Object(_) | Value::Array(_) => redact_json_value(value),
    }
}

/// Redact a single JSON value when its associated key name (e.g. the
/// trailing path segment from a `config.get` per-key lookup) matches a
/// known secret name. This lets callers redact a leaf string without
/// the wrap-leaf-in-temp-object dance `redact_json_value` requires.
///
/// Non-string leaves at a secret-named key (Number/Bool — unusual but
/// possible if a future config field stores a numeric/bool secret) are
/// replaced with `Null` rather than passed through, so the redactor
/// fails closed rather than leaking the value verbatim.
pub fn redact_value_at_key(value: &mut Value, key_name: &str) {
    if is_secret_key_name(key_name) {
        redact_secret_named_value(value);
    } else {
        redact_json_value(value);
    }
}

fn is_secret_key_name(key: &str) -> bool {
    let lower = key.to_lowercase();
    if matches!(
        lower.as_str(),
        "max_token"
            | "max_tokens"
            | "maxtoken"
            | "maxtokens"
            | "input_token"
            | "input_tokens"
            | "inputtoken"
            | "inputtokens"
            | "output_token"
            | "output_tokens"
            | "outputtoken"
            | "outputtokens"
            | "total_token"
            | "total_tokens"
            | "totaltoken"
            | "totaltokens"
            | "token_count"
            | "tokencount"
    ) {
        return false;
    }
    SECRET_KEY_NAMES.iter().any(|s| lower.contains(s))
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
        let input = format!("wss://host/ws?token={long_token}");
        let result = redact_string(&input);
        assert!(!result.contains(&long_token));
        assert!(result.contains("token=[REDACTED]"));
    }

    /// Matrix recovery keys appear in free-form error messages with no
    /// `recovery_key=` prefix the JSON-key or query-param redactors would
    /// catch — the bare-shape regex must scrub them so they never reach
    /// log sinks or the channel-registry `last_error` field. The fixture
    /// uses base58 characters only (matching matrix-sdk's encoding —
    /// excludes 0/O/I/l) so the tightened alphabet still matches.
    #[test]
    fn test_matrix_recovery_key_shape_redacted() {
        let recovery_key = "EsTb XYZ1 abc2 def3 GhJ4 KkL5 MnP6 PqR7 StU8 VwX9 YzAb cDeF";
        let input = format!("recovery failed for key '{recovery_key}' on device DEVICE");
        let result = redact_string(&input);
        assert!(
            !result.contains("EsTb"),
            "recovery key first group must be scrubbed; got: {result}"
        );
        assert!(
            !result.contains("cDeF"),
            "recovery key last group must be scrubbed; got: {result}"
        );
        assert!(result.contains("[REDACTED]"));
        // Surrounding context preserved so operators can tell what failed
        assert!(result.contains("recovery failed"));
        assert!(result.contains("DEVICE"));
    }

    /// The 12×4 pattern shouldn't trigger on benign 4-char-group strings
    /// of similar shape that aren't recovery keys.
    #[test]
    fn test_matrix_recovery_key_pattern_is_not_overly_greedy() {
        // 11 groups (one short of recovery-key length) — should not match
        let almost = "ABCD efgh JKLM NPqr stuv WXYZ abcd EFGH JKLM NPqr stuv";
        let input = format!("ids: {almost}");
        let result = redact_string(&input);
        assert_eq!(result, input, "11-group string must not be redacted");
    }

    /// Hex dumps and base32 blobs that happen to chunk by 4 must NOT
    /// be redacted — they aren't recovery keys (they contain
    /// 0/O/I/l, which base58 excludes) and scrubbing them would
    /// silently lose debugging context.
    #[test]
    fn test_matrix_recovery_key_pattern_skips_hex_dump_chunks() {
        // 12 hex groups containing 0 — recovery keys never contain `0`
        let hex_dump = "DEAD BEEF FACE FEED CAFE BABE 1234 5678 9ABC DEF0 1122 3344";
        let input = format!("dump: {hex_dump}");
        let result = redact_string(&input);
        assert_eq!(
            result, input,
            "hex chunks containing `0` (excluded from base58) must not be redacted"
        );
    }

    #[test]
    fn test_json_known_keys_redacted() {
        let mut val = json!({
            "apiKey": "my-secret-api-key",
            "accessKeyId": "AKIAIOSFODNN7EXAMPLE",
            "token": "tok_123",
            "secret": "s3cr3t",
            "password": "hunter2",
            "name": "test-bot"
        });
        redact_json_value(&mut val);
        assert_eq!(val["apiKey"], "[REDACTED]");
        assert_eq!(val["accessKeyId"], "[REDACTED]");
        assert_eq!(val["token"], "[REDACTED]");
        assert_eq!(val["secret"], "[REDACTED]");
        assert_eq!(val["password"], "[REDACTED]");
        assert_eq!(val["name"], "test-bot");
    }

    #[test]
    fn test_matrix_secret_keys_redacted() {
        let mut val = json!({
            "matrix": {
                "homeserverUrl": "https://matrix.example.com",
                "accessToken": "matrix-access-token",
                "storePassphrase": "matrix-store-passphrase",
                "recoveryKey": "matrix-recovery-key"
            }
        });

        redact_json_value(&mut val);

        assert_eq!(val["matrix"]["homeserverUrl"], "https://matrix.example.com");
        assert_eq!(val["matrix"]["accessToken"], "[REDACTED]");
        assert_eq!(val["matrix"]["storePassphrase"], "[REDACTED]");
        assert_eq!(val["matrix"]["recoveryKey"], "[REDACTED]");
    }

    /// `redact_value_at_key` is the entry point used by `config.get`'s
    /// per-key lookup. A leaf string at a secret-named key must
    /// scrub; a non-string leaf at a secret-named key must clear
    /// (defense-in-depth for future numeric/bool secret fields); and
    /// non-secret keys descend recursively.
    #[test]
    fn test_redact_value_at_key_redacts_string_at_secret_name() {
        let mut value = json!("plaintext-secret-value");
        redact_value_at_key(&mut value, "accessToken");
        assert_eq!(value, json!("[REDACTED]"));

        let mut value = json!(42);
        redact_value_at_key(&mut value, "password");
        assert_eq!(value, Value::Null);

        let mut value = json!(true);
        redact_value_at_key(&mut value, "secret");
        assert_eq!(value, Value::Null);
    }

    #[test]
    fn test_redact_value_at_key_recurses_for_non_secret_object() {
        let mut value = json!({
            "homeserverUrl": "https://matrix.example.com",
            "nested": {
                "apiKey": "leak-me",
            },
        });
        redact_value_at_key(&mut value, "matrix");
        assert_eq!(
            value["homeserverUrl"], "https://matrix.example.com",
            "non-secret leaf untouched"
        );
        assert_eq!(
            value["nested"]["apiKey"], "[REDACTED]",
            "nested secret-named key scrubbed via recursion"
        );
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
    fn test_token_count_key_is_not_secret() {
        let mut val = json!({
            "token_count": "1500",
            "status": "ok"
        });
        redact_json_value(&mut val);
        assert_eq!(val["token_count"], "1500");
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
    fn test_secret_key_non_string_value_redacts_fail_closed() {
        let mut val = json!({
            "token": 12345,
            "password": true,
            "secret": null
        });
        redact_json_value(&mut val);
        assert!(val["token"].is_null());
        assert!(val["password"].is_null());
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
