//! Secret masking and redaction for logs and error responses.
//!
//! Provides utilities to scrub API keys, tokens, passwords, and other
//! sensitive data from log output and error response bodies.

use regex::Regex;
use serde_json::Value;
use std::borrow::Cow;
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

/// Matrix homeserver URL redactor. Matches any `http://` or
/// `https://` URL containing `/_matrix/` — the canonical path prefix
/// of every Matrix client/federation API endpoint. Closes the
/// transitive URL leak class:
///
///   `matrix_sdk::Error::Http(matrix_sdk::HttpError::Reqwest(
///   reqwest::Error))` Display embeds the full request URL
///   (`https://matrix.example.org/_matrix/client/v3/sync?since=...`),
///   which carries the operator-configured homeserver hostname,
///   room IDs in path segments, and sync since-tokens / filter IDs
///   in query params.
///
/// `.without_url()` is the surgical fix at known direct
/// `reqwest::Error` sites, but `matrix_sdk::Error` wraps reqwest
/// transitively through several variants and `RedactedDisplay`-
/// wrapped sites in `channels/matrix.rs` (×23) can't peel through
/// arbitrary SDK errors at format time. This regex catches the
/// homeserver-shaped URL at the redactor layer — the final
/// operator-visible barrier.
///
/// SCOPE: only Matrix homeserver URLs (`/_matrix/` is unique to
/// Matrix Client-Server / Federation API per the spec). Non-Matrix
/// URLs (provider endpoints, vendored crate metadata) are NOT
/// touched, preserving log debuggability.
static RE_MATRIX_HOMESERVER_URL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"https?://[^\s"<>]*?/_matrix/[^\s"<>]*"#)
        .expect("failed to compile regex: matrix_homeserver_url")
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
    // matrix-rust-sdk's `BackupDecryptionKey::to_base58` encodes a
    // 35-byte payload via `bs58::encode`, which produces 47 OR 48
    // ASCII chars depending on key-material byte values. The
    // `Display` impl chunks via `chunks(4)` and joins with spaces:
    // a 48-char key serializes as 12 groups of 4, a 47-char key
    // as 11 groups of 4 plus a trailing group of 3. Both shapes
    // appear in the wild (~50/50). The trailing alternation
    // `[a-km-zA-HJ-NP-Z1-9]{3,4}` matches both widths.
    Regex::new(
        r"\b[a-km-zA-HJ-NP-Z1-9]{4}(?:\s[a-km-zA-HJ-NP-Z1-9]{4}){10}\s[a-km-zA-HJ-NP-Z1-9]{3,4}\b",
    )
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
    dropping_overlong_line: bool,
}

const MAX_BUFFER_BYTES: usize = 8192;
const OVERLONG_REDACTION_MARKER: &[u8] = b"[REDACTED_LOG_LINE_TOO_LONG]";

impl<W: Write> RedactingWriter<W> {
    pub fn new(inner: W) -> Self {
        Self {
            inner,
            buffer: Vec::new(),
            dropping_overlong_line: false,
        }
    }

    fn flush_buffer(&mut self) -> io::Result<()> {
        if self.buffer.is_empty() {
            return Ok(());
        }
        let text = String::from_utf8_lossy(&self.buffer);
        let redacted = redact_string(&text);
        let result = self.inner.write_all(redacted.as_bytes());
        self.zeroize_buffer();
        result
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

        let mut offset = 0;
        while offset < buf.len() {
            if self.dropping_overlong_line {
                if let Some(pos) = buf[offset..].iter().position(|b| *b == b'\n') {
                    self.inner.write_all(b"\n")?;
                    self.dropping_overlong_line = false;
                    offset += pos + 1;
                    continue;
                }
                return Ok(buf.len());
            }

            let next_newline = buf[offset..].iter().position(|b| *b == b'\n');
            let end = next_newline.map(|pos| offset + pos).unwrap_or(buf.len());
            let segment = &buf[offset..end];
            if self.buffer.len().saturating_add(segment.len()) > MAX_BUFFER_BYTES {
                let remaining_capacity = MAX_BUFFER_BYTES.saturating_sub(self.buffer.len());
                self.buffer
                    .extend_from_slice(&segment[..remaining_capacity]);
                self.inner.write_all(OVERLONG_REDACTION_MARKER)?;
                self.zeroize_buffer();
                if next_newline.is_some() {
                    self.inner.write_all(b"\n")?;
                    offset = end + 1;
                } else {
                    self.dropping_overlong_line = true;
                    return Ok(buf.len());
                }
                continue;
            }
            self.buffer.extend_from_slice(segment);

            if next_newline.is_some() {
                self.flush_buffer()?;
                self.inner.write_all(b"\n")?;
                offset = end + 1;
            } else {
                break;
            }
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
        if self.dropping_overlong_line {
            if let Err(err) = self.inner.write_all(b"\n") {
                eprintln!("RedactingWriter: failed to terminate overlong log marker: {err}");
            }
            self.dropping_overlong_line = false;
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

    // Strip control bytes + Cf-class formatting characters BEFORE
    // running the secret-pattern regexes. The strip protects two
    // distinct surfaces:
    //
    // 1. Terminal scrollback: ANSI escapes, bidi overrides,
    //    zero-width chars, TAG codepoints all alter what an
    //    operator actually sees vs. what was sent. Hostile content
    //    (e.g. an adversarial Matrix homeserver echoing operator
    //    bytes back) flows through `redact_string` into operator
    //    logs and `cara verify` stdout.
    //
    // 2. Regex-evasion: a single stripped char inserted mid-token
    //    (e.g. `Bearer eyJ\u{200B}foo.bar.baz`) terminates the
    //    bearer-regex match early — U+200B isn't in
    //    `[a-zA-Z0-9._\-]`. If we stripped AFTER the regex pass,
    //    the redaction would replace `Bearer eyJ` and leave the
    //    attacker-controlled `foo.bar.baz` suffix in the output.
    //    Stripping FIRST gives the regexes a clean canonical
    //    string with no embedded splitters.
    let stripped = strip_terminal_unsafe_chars(input);

    // Each `replace_all` call short-circuits via `is_match` to
    // avoid allocating a fresh `String` on the no-match path.
    // For typical INFO-level log lines (all-ASCII, no secrets),
    // the strip pass returns `Cow::Borrowed` (via `bytes().all`
    // ASCII-printable check) and every regex pass returns
    // `Cow::Borrowed` of the same underlying buffer. Only when
    // a regex actually matches is an owned `String` allocated.
    let s = redact_with(&stripped, &RE_OPENAI_KEY, "[REDACTED]");
    let s = redact_with(&s, &RE_BEARER, "[REDACTED]");
    let s = redact_with(&s, &RE_BASIC_AUTH, "[REDACTED]");
    let s = redact_with(&s, &RE_QUERY_SECRET, "$1=[REDACTED]");
    let s = redact_with(&s, &RE_MATRIX_RECOVERY_KEY, "[REDACTED]");
    // Matrix homeserver URLs are the last redaction pass. Runs AFTER
    // RE_QUERY_SECRET so any `?key=…` / `?token=…` value inside the
    // URL has already been redacted with the finer-grained
    // `key=[REDACTED]` shape; the URL pass then replaces the rest of
    // the URL (host + path + non-secret query) which carries
    // operator-configured homeserver + room IDs + since-tokens.
    let s = redact_with(&s, &RE_MATRIX_HOMESERVER_URL, "[REDACTED-MATRIX-URL]");
    s.into_owned()
}

/// Apply a replace-all only when the regex actually matches.
/// `Regex::replace_all` always allocates a fresh `String` on
/// `into_owned()`, even when no replacement occurred — wasted
/// work on the no-match path. `is_match` is a single regex pass
/// that doesn't allocate; gate the rewrite behind it.
fn redact_with<'a>(input: &'a str, re: &Regex, replacement: &str) -> Cow<'a, str> {
    if re.is_match(input) {
        Cow::Owned(re.replace_all(input, replacement).into_owned())
    } else {
        Cow::Borrowed(input)
    }
}

/// Strip ASCII control bytes (except LF / TAB) and Unicode bidi /
/// zero-width / TAG / line-separator codepoints. Returns
/// `Cow::Borrowed` of the input on the all-clean path (every byte
/// is printable ASCII or LF/TAB) — the common case for typical
/// log lines, where the per-line cost drops from one allocation
/// + N-char copy to one O(N) byte scan.
fn strip_terminal_unsafe_chars(input: &str) -> Cow<'_, str> {
    // Fast path: all-clean, no allocation. The byte scan is
    // O(N) and stops the moment it sees a non-printable byte.
    // Multi-byte UTF-8 starts with a byte ≥ 0x80, which fails
    // the `<= 0x7E` check and falls into the slow path that
    // does the proper char-level filter.
    let all_clean = input
        .bytes()
        .all(|b| (0x20..=0x7E).contains(&b) || b == b'\n' || b == b'\t');
    if all_clean {
        return Cow::Borrowed(input);
    }

    // Slow path: walk by char and drop strippable codepoints.
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        let code = ch as u32;
        let is_control_excluding_lf_tab = ch.is_control() && ch != '\n' && ch != '\t';
        let is_format_or_separator = matches!(
            code,
            0x061C
            | 0x200B..=0x200F
            | 0x2028..=0x2029
            | 0x202A..=0x202E
            | 0x2060..=0x2064
            | 0x2066..=0x2069
            | 0x206A..=0x206F
            | 0xFEFF
            | 0xFFF9..=0xFFFB
            | 0xE0001
            | 0xE0020..=0xE007F
        );
        if is_control_excluding_lf_tab || is_format_or_separator {
            continue;
        }
        out.push(ch);
    }
    Cow::Owned(out)
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

    /// Matrix homeserver URLs (containing `/_matrix/`) get redacted to
    /// scrub the operator-configured homeserver, room IDs in paths,
    /// and since-tokens / filter IDs in query params — the URL leak
    /// vector via `matrix_sdk::Error::Http(reqwest::Error)` Display.
    #[test]
    fn test_matrix_homeserver_url_is_redacted() {
        let input = "Matrix sync failed: error sending request for url \
             https://matrix.example.org/_matrix/client/v3/sync?since=s12345abcdef&timeout=30000";
        let result = redact_string(input);
        assert!(
            !result.contains("matrix.example.org"),
            "homeserver host must be scrubbed; got: {result}"
        );
        assert!(
            !result.contains("s12345abcdef"),
            "since-token in query must be scrubbed; got: {result}"
        );
        assert!(
            result.contains("[REDACTED-MATRIX-URL]"),
            "replacement marker must appear; got: {result}"
        );
        // Surrounding context preserved
        assert!(result.contains("Matrix sync failed"));
    }

    /// Non-Matrix URLs must NOT be touched by the Matrix-URL regex.
    /// Provider endpoints, vendored crate metadata, GitHub release
    /// URLs are debugging-helpful and operator-known.
    #[test]
    fn test_non_matrix_url_is_not_redacted() {
        let input = "request to https://api.openai.com/v1/messages failed; \
             see https://github.com/RustCrypto/AEADs for details";
        let result = redact_string(input);
        assert!(
            result.contains("https://api.openai.com/v1/messages"),
            "non-Matrix URL must NOT be redacted; got: {result}"
        );
        assert!(
            result.contains("https://github.com/RustCrypto/AEADs"),
            "GitHub URL must NOT be redacted; got: {result}"
        );
    }

    /// Matrix URL inside a JSON-quoted string must redact without
    /// swallowing the closing quote — the regex excludes `"` from the
    /// URL character class.
    #[test]
    fn test_matrix_url_in_json_quoted_string_preserves_quote_boundary() {
        let input = r#"{"error":"GET https://hs.example.org/_matrix/client/v3/sync failed"}"#;
        let result = redact_string(input);
        assert!(
            !result.contains("hs.example.org"),
            "homeserver must be scrubbed; got: {result}"
        );
        assert!(
            result.contains("[REDACTED-MATRIX-URL]"),
            "replacement marker must appear; got: {result}"
        );
        assert!(
            result.contains("failed\"}"),
            "trailing JSON quote+brace must survive; got: {result}"
        );
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
        assert!(output.contains("[REDACTED_LOG_LINE_TOO_LONG]"));
    }

    #[test]
    fn test_redacting_writer_caps_no_newline_buffer_before_append() {
        let mut writer = RedactingWriter::new(Vec::new());
        let payload = vec![b'a'; MAX_BUFFER_BYTES * 4];

        writer.write_all(&payload).unwrap();

        assert!(writer.buffer.is_empty());
        assert!(writer.dropping_overlong_line);
        assert_eq!(writer.inner, OVERLONG_REDACTION_MARKER);
    }

    #[test]
    fn test_redacting_writer_drop_terminates_overlong_marker() {
        let mut inner: Vec<u8> = Vec::new();
        {
            let mut writer = RedactingWriter::new(&mut inner);
            let payload = vec![b'a'; MAX_BUFFER_BYTES * 2];
            writer.write_all(&payload).unwrap();
        }

        assert_eq!(
            String::from_utf8(inner).unwrap(),
            "[REDACTED_LOG_LINE_TOO_LONG]\n"
        );
    }

    #[test]
    fn test_redacting_writer_zeroizes_buffer_after_flush_error() {
        struct FailingWriter;

        impl Write for FailingWriter {
            fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
                Err(io::Error::other("forced write failure"))
            }

            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        let mut writer = RedactingWriter::new(FailingWriter);
        writer
            .write_all(b"Authorization: Bearer abc.def.ghi")
            .unwrap();

        assert!(writer.flush().is_err());
        assert!(
            writer.buffer.is_empty(),
            "secret-bearing buffer must be cleared even when the inner writer fails"
        );
    }

    #[test]
    fn test_redacting_writer_does_not_leak_secret_split_at_buffer_boundary() {
        let mut inner: Vec<u8> = Vec::new();
        {
            let mut writer = RedactingWriter::new(&mut inner);
            write!(writer, "{}", "a".repeat(MAX_BUFFER_BYTES - "Bearer ".len())).unwrap();
            write!(writer, "Bearer abc.def.ghi\nok").unwrap();
            writer.flush().unwrap();
        }
        let output = String::from_utf8(inner).unwrap();
        assert!(!output.contains("abc.def.ghi"));
        assert!(output.contains("[REDACTED_LOG_LINE_TOO_LONG]"));
        assert!(output.ends_with("\nok"));
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
        let input = "用户 said: こんにちは! Bearer abc.def.ghi — done ✓";
        let result = redact_string(input);
        assert!(result.contains("用户 said:"));
        assert!(result.contains("— done ✓"));
        assert!(!result.contains("abc.def.ghi"));
    }

    /// Regression pin for the `strip_terminal_unsafe_chars` defense
    /// against hostile-content sources (e.g. an adversarial Matrix
    /// homeserver echoing operator bytes back) injecting ANSI
    /// escapes, bidi overrides, or zero-width chars into operator-
    /// visible terminal output via `last_error` / log lines. Without
    /// this pin a future "let me clean this up" refactor could
    /// silently drop the strip pass.
    #[test]
    fn test_redact_strips_ansi_escape_sequences() {
        let result = redact_string("prefix\x1b[31mred\x1b[0msuffix");
        assert!(!result.contains('\x1b'));
        assert_eq!(result, "prefix[31mred[0msuffix");
    }

    #[test]
    fn test_redact_strips_bidi_override() {
        let result = redact_string("\u{202E}reverse");
        assert_eq!(result, "reverse");
    }

    #[test]
    fn test_redact_strips_zero_width_and_bom() {
        let result = redact_string("a\u{200B}b\u{200D}c\u{FEFF}d");
        assert_eq!(result, "abcd");
    }

    #[test]
    fn test_redact_strips_tag_codepoints() {
        let result = redact_string("tag\u{E0041}injection");
        assert_eq!(result, "taginjection");
    }

    #[test]
    fn test_redact_preserves_lf_and_tab() {
        let result = redact_string("line1\nline2\ttab");
        assert_eq!(result, "line1\nline2\ttab");
    }

    #[test]
    fn test_redact_strips_other_c0_controls() {
        let result = redact_string("a\x07b\x01c");
        assert_eq!(result, "abc");
    }

    /// Pin the fast-path: an all-clean ASCII-printable input
    /// (with optional LF / TAB) that contains NO secret-pattern
    /// matches must round-trip byte-for-byte. The fast-path
    /// branches in `strip_terminal_unsafe_chars` (returns
    /// `Cow::Borrowed`) and `redact_with` (returns
    /// `Cow::Borrowed` when no regex matches) are both exercised
    /// — a future contributor "simplifying" either branch back
    /// to unconditional allocation would still pass the
    /// correctness tests but would silently regress the
    /// per-log-line allocator footprint that this file's hot path
    /// depends on. Equality checks the correctness invariant; the
    /// allocation-count invariant is enforced by code shape (the
    /// two branches MUST exist).
    #[test]
    fn test_redact_fast_path_ascii_no_match_round_trips_byte_identical() {
        // Typical INFO-level log lines: ASCII only, no secrets.
        for input in [
            "Server bound on 127.0.0.1:9999",
            "Inbound message dispatched in 142ms",
            "Channel telegram connected at 2026-05-08T12:34:56Z",
            "  multi\tcolumn\tlog\nwith\tnewlines",
            "Plain ASCII with punctuation: hello, world! (n=42)",
        ] {
            assert_eq!(
                redact_string(input),
                input,
                "fast path must round-trip clean ASCII byte-for-byte"
            );
        }
    }

    /// Regression pin for the strip-then-regex order. A hostile
    /// content source could otherwise inject a stripped char (e.g.
    /// U+200B zero-width space) into the middle of a bearer token to
    /// terminate the regex match early. With strip-then-regex the
    /// regex sees the canonical token shape and replaces the whole
    /// thing.
    #[test]
    fn test_redact_strip_first_defeats_zwsp_token_split_evasion() {
        let result = redact_string("Authorization: Bearer eyJ\u{200B}foo.payload.signature\n");
        assert!(!result.contains("foo.payload.signature"));
        assert!(result.contains("[REDACTED]"));
    }

    /// Pin both 47-char and 48-char recovery key shapes so the
    /// `RE_MATRIX_RECOVERY_KEY` regex catches both wire shapes
    /// matrix-rust-sdk emits depending on key-material byte values.
    #[test]
    fn test_redact_matrix_recovery_key_47_char_form() {
        // 11 groups of 4 + trailing 3-char group.
        let key = "EsAH r2Pq Ueyu G2dh oxmW xfo7 NDvP UrXC dJWp aHy5 dCVN HUd";
        let input = format!("recovery: {key}");
        let result = redact_string(&input);
        assert!(
            !result.contains(key),
            "47-char recovery key not redacted: {result}"
        );
        assert!(result.contains("[REDACTED]"));
    }

    #[test]
    fn test_redact_matrix_recovery_key_48_char_form() {
        // 12 groups of 4.
        let key = "EsAH r2Pq Ueyu G2dh oxmW xfo7 NDvP UrXC dJWp aHy5 dCVN HUdW";
        let input = format!("recovery: {key}");
        let result = redact_string(&input);
        assert!(
            !result.contains(key),
            "48-char recovery key not redacted: {result}"
        );
        assert!(result.contains("[REDACTED]"));
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
