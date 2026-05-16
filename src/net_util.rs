//! Small network-related utilities shared across modules.

/// Outcome of `read_capped_into`: distinguishes "read complete within
/// cap" from "hit cap+1 bytes (server lied / chunked encoding)".
/// Lets callers attach their own error type without forcing this
/// helper to know about HTTP error shapes.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ReadCappedOutcome {
    /// Read finished within the cap. Returned buffer length is `<= cap`.
    Complete,
    /// Read hit `cap + 1` bytes — over the cap. The buffer contains
    /// exactly `cap + 1` bytes; the caller should reject.
    Overflow,
}

/// Error returned by `read_capped_into`. The transport variant exposes
/// only the underlying `io::ErrorKind`, never the full `io::Error`
/// whose Display may render a wrapped `reqwest::Error` that embeds
/// (and thus leaks) the request URL — bot tokens, OAuth bearer URLs,
/// and operator-supplied URL segments must never reach operator-
/// visible state through this path. Callers SHOULD route
/// `Misconfigured` to a non-retryable terminal class so the
/// programming bug surfaces instead of being retried in a loop.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ReadCappedError {
    /// The helper was called with `cap == u64::MAX`, which would
    /// silently disable overflow detection (`buf.len() > u64::MAX` is
    /// mathematically impossible). Misconfiguration, not a transport
    /// error — callers should route this to a programming-bug /
    /// fail-closed class, not a retry loop.
    Misconfigured,
    /// The underlying `Read` returned an `io::Error`. Only the kind
    /// is preserved; the Display body is intentionally dropped so a
    /// future caller can't re-leak URLs via `format!("{e}")`.
    Transport(std::io::ErrorKind),
}

impl std::fmt::Display for ReadCappedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Misconfigured => {
                write!(f, "read_capped_into cap is misconfigured (cap == u64::MAX)")
            }
            Self::Transport(kind) => write!(f, "transport error: {kind:?}"),
        }
    }
}

impl std::error::Error for ReadCappedError {}

/// Read up to `cap + 1` bytes from `reader` into `buf`, returning
/// `Complete` if the source ended at or below `cap`, or `Overflow` if
/// the source had at least `cap + 1` bytes. The +1 byte is the
/// disambiguator: a buffer of exactly `cap` bytes means "source had
/// at most `cap` bytes"; `cap + 1` bytes means "source had at least
/// `cap + 1` bytes". Callers use the outcome to fail-closed on
/// over-cap before passing the buffer downstream.
///
/// Returns `ReadCappedError::Misconfigured` for `cap == u64::MAX`
/// (programming bug) and `ReadCappedError::Transport(kind)` for
/// underlying `Read` failures. Misconfigured must route to a
/// non-retryable terminal class — never to a retry loop — because
/// retrying a programming bug burns CPU without progress. Transport
/// exposes only the `io::ErrorKind`, never the full `io::Error`, so
/// a wrapped `reqwest::Error` (which embeds the request URL) can't
/// re-leak through `format!("{}", e)`.
///
/// This abstracts the bounded-read pattern used by the plugin-
/// download path (`src/server/ws/handlers/plugins.rs`), the
/// Signal outbound media path (`src/channels/signal.rs`), and the
/// channel media-fetch path (`src/channels/media_fetch.rs`): each
/// wraps `Read::take(cap + 1)` + `read_to_end` + post-read overflow
/// check. Centralizing it makes the cap-enforcement code unit-
/// testable without spinning up an HTTP server fixture.
pub(crate) fn read_capped_into<R: std::io::Read>(
    mut reader: R,
    buf: &mut Vec<u8>,
    cap: u64,
) -> Result<ReadCappedOutcome, ReadCappedError> {
    // Reject the fail-open `cap == u64::MAX` case explicitly. With
    // `saturating_add(1)`, that cap would yield `cap_with_overflow ==
    // u64::MAX` and `buf.len() as u64 > u64::MAX` is mathematically
    // impossible, so the function would always return `Complete` —
    // silently defeating the cap. Surface the misuse explicitly via
    // `Misconfigured` rather than silently failing open.
    if cap == u64::MAX {
        return Err(ReadCappedError::Misconfigured);
    }
    let cap_with_overflow = cap.saturating_add(1);
    let mut bounded = std::io::Read::take(&mut reader, cap_with_overflow);
    std::io::Read::read_to_end(&mut bounded, buf)
        .map_err(|e| ReadCappedError::Transport(e.kind()))?;
    if buf.len() as u64 > cap {
        Ok(ReadCappedOutcome::Overflow)
    } else {
        Ok(ReadCappedOutcome::Complete)
    }
}

/// Default cap for reading reqwest response bodies via
/// `read_response_body_text_capped`. 256 KiB is large enough that any
/// legitimate error JSON / status payload fits comfortably, and small
/// enough that thousands of concurrent attacks against
/// `response.text()` can't OOM the process. Callers SHOULD use this
/// constant unless they have a reason to choose a tighter or wider cap.
pub(crate) const MAX_RESPONSE_BODY_BYTES: usize = 256 * 1024;

/// Read at most `cap` bytes from a reqwest response body and return
/// them as a UTF-8 string (lossy at any codepoint boundary that gets
/// truncated at the cap). Use this instead of `Response::text().await`
/// when the peer is untrusted or operator-influenced:
/// `Response::text()` reads the full body before returning, so a
/// malicious or MITM-attacked server can stream gigabytes into RAM via
/// `Transfer-Encoding: chunked` before the request timeout fires.
///
/// On reqwest streaming error, the underlying URL is stripped via
/// `Error::without_url()` to avoid leaking bot tokens, OAuth bearer
/// URLs, or other operator-supplied URL segments into operator-visible
/// error state. The returned `io::Error` wraps only the scrubbed
/// Display.
pub(crate) async fn read_response_body_text_capped(
    response: reqwest::Response,
    cap: usize,
) -> Result<String, std::io::Error> {
    use futures_util::StreamExt;
    let stream = response.bytes_stream().map(|r| {
        r.map_err(|e| std::io::Error::other(format!("body read failed: {}", e.without_url())))
    });
    let bytes = collect_capped_bytes(stream, cap).await?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

/// Read at most `cap` bytes from a reqwest response body and return
/// them as a `Vec<u8>`. Same threat model as
/// `read_response_body_text_capped` — use this for binary response
/// bodies (audio, update bundles, downloads) where the peer is
/// untrusted or operator-influenced.
pub(crate) async fn read_response_body_bytes_capped(
    response: reqwest::Response,
    cap: usize,
) -> Result<Vec<u8>, std::io::Error> {
    use futures_util::StreamExt;
    let stream = response.bytes_stream().map(|r| {
        r.map_err(|e| std::io::Error::other(format!("body read failed: {}", e.without_url())))
    });
    collect_capped_bytes(stream, cap).await
}

/// Inner streaming-cap loop, factored out so it can be unit-tested
/// against a fabricated stream. Consumes `stream` until exhaustion or
/// until `cap` bytes have been buffered (whichever comes first) and
/// returns the buffered prefix.
async fn collect_capped_bytes<S>(mut stream: S, cap: usize) -> Result<Vec<u8>, std::io::Error>
where
    S: futures_util::Stream<Item = Result<bytes::Bytes, std::io::Error>> + Unpin,
{
    use futures_util::StreamExt;
    let mut buf: Vec<u8> = Vec::with_capacity(cap.min(8 * 1024));
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        let remaining = cap.saturating_sub(buf.len());
        if remaining == 0 {
            break;
        }
        if chunk.len() <= remaining {
            buf.extend_from_slice(&chunk);
        } else {
            buf.extend_from_slice(&chunk[..remaining]);
            break;
        }
    }
    Ok(buf)
}

/// True when `host` resolves to a loopback address (or the literal
/// `localhost` alias). Strips IPv6 brackets if present so callers can
/// pass either `::1` or `[::1]`. Hostnames that don't parse as IP
/// literals (e.g. `matrix.example.com`) are treated as non-loopback —
/// DNS resolution would be both expensive and non-deterministic in a
/// schema-validation / control-auth-gating context.
pub(crate) fn is_loopback_host(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    let bracketless = host
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(host);
    bracketless
        .parse::<std::net::IpAddr>()
        .map(|ip| ip.is_loopback())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_loopback_host_canonical_forms() {
        assert!(is_loopback_host("127.0.0.1"));
        assert!(is_loopback_host("127.0.0.2"));
        assert!(is_loopback_host("::1"));
        assert!(is_loopback_host("[::1]"));
        assert!(is_loopback_host("0:0:0:0:0:0:0:1"));
        assert!(is_loopback_host("localhost"));
        assert!(is_loopback_host("LOCALHOST"));
    }

    #[test]
    fn test_is_loopback_host_rejects_non_loopback() {
        assert!(!is_loopback_host("10.0.0.1"));
        assert!(!is_loopback_host("matrix.example.com"));
        assert!(!is_loopback_host("2001:db8::1"));
        assert!(!is_loopback_host("[2001:db8::1]"));
        assert!(!is_loopback_host(""));
    }

    /// `0.0.0.0` is the IPv4 wildcard listen address — a common
    /// operator-misconfig where they expect "any local interface" to
    /// mean "loopback". `Ipv4Addr::is_loopback()` returns false for
    /// `0.0.0.0` (only `127.0.0.0/8` is loopback), but a future
    /// reviewer or refactor might wrongly add a special case for it.
    /// Pin the negative so the bearer-over-plaintext guard keeps
    /// refusing to send credentials to a wildcard address.
    #[test]
    fn test_is_loopback_host_rejects_ipv4_wildcard() {
        assert!(!is_loopback_host("0.0.0.0"));
        assert!(!is_loopback_host("::"));
        assert!(!is_loopback_host("[::]"));
    }

    /// Pins `read_capped_into` Complete-at-exactly-cap: a source that
    /// produces exactly `cap` bytes returns `Complete` and the buffer
    /// holds the whole payload. The +1 byte from `Read::take(cap + 1)`
    /// is the disambiguator — without it, a payload of exactly `cap`
    /// bytes would be ambiguous with cap+1.
    #[test]
    fn test_read_capped_into_at_cap_exact_returns_complete() {
        let source = vec![0xABu8; 100];
        let mut buf = Vec::new();
        let outcome = read_capped_into(source.as_slice(), &mut buf, 100).expect("read");
        assert_eq!(outcome, ReadCappedOutcome::Complete);
        assert_eq!(buf.len(), 100);
    }

    /// Pins `read_capped_into` Complete-under-cap.
    #[test]
    fn test_read_capped_into_under_cap_returns_complete() {
        let source = vec![0xCDu8; 50];
        let mut buf = Vec::new();
        let outcome = read_capped_into(source.as_slice(), &mut buf, 100).expect("read");
        assert_eq!(outcome, ReadCappedOutcome::Complete);
        assert_eq!(buf.len(), 50);
    }

    /// Pins `read_capped_into` Overflow-at-cap-plus-one: source has
    /// cap+1 bytes, helper returns Overflow with buffer of exactly
    /// `cap + 1` bytes. Caller is expected to reject the buffer.
    #[test]
    fn test_read_capped_into_one_over_cap_returns_overflow() {
        let source = vec![0xEFu8; 101];
        let mut buf = Vec::new();
        let outcome = read_capped_into(source.as_slice(), &mut buf, 100).expect("read");
        assert_eq!(outcome, ReadCappedOutcome::Overflow);
        assert_eq!(buf.len(), 101);
    }

    /// Pins `read_capped_into` bounded read against a much-larger
    /// source: a 1 MB source with cap=100 should stop reading after
    /// 101 bytes, NOT buffer the whole MB. Without `Read::take(cap+1)`
    /// the helper would buffer the entire source.
    #[test]
    fn test_read_capped_into_bounds_large_source() {
        let source = vec![0xFFu8; 1_000_000];
        let mut buf = Vec::new();
        let outcome = read_capped_into(source.as_slice(), &mut buf, 100).expect("read");
        assert_eq!(outcome, ReadCappedOutcome::Overflow);
        assert_eq!(buf.len(), 101);
    }

    /// Pins `read_capped_into` empty-source: returns Complete with
    /// zero-length buffer.
    #[test]
    fn test_read_capped_into_empty_source_returns_complete() {
        let source: Vec<u8> = Vec::new();
        let mut buf = Vec::new();
        let outcome = read_capped_into(source.as_slice(), &mut buf, 100).expect("read");
        assert_eq!(outcome, ReadCappedOutcome::Complete);
        assert!(buf.is_empty());
    }

    /// Pins `read_capped_into` cap=0: any non-empty source returns
    /// Overflow. Used by callers that want to reject any body.
    #[test]
    fn test_read_capped_into_cap_zero_rejects_any_byte() {
        let source = vec![0u8; 1];
        let mut buf = Vec::new();
        let outcome = read_capped_into(source.as_slice(), &mut buf, 0).expect("read");
        assert_eq!(outcome, ReadCappedOutcome::Overflow);
        assert_eq!(buf.len(), 1);
    }

    /// Pins the fail-open guard for `cap == u64::MAX`. With saturating
    /// add, `cap_with_overflow` would equal `u64::MAX` and the
    /// post-read `buf.len() as u64 > cap` could never fire, silently
    /// disabling overflow detection. The helper rejects this misuse
    /// explicitly via `ReadCappedError::Misconfigured`.
    #[test]
    fn test_read_capped_into_rejects_cap_u64_max() {
        let source = vec![0u8; 8];
        let mut buf = Vec::new();
        let err = read_capped_into(source.as_slice(), &mut buf, u64::MAX)
            .expect_err("must refuse u64::MAX cap");
        assert_eq!(err, ReadCappedError::Misconfigured);
    }

    /// Pins `read_capped_into` propagates underlying read errors as
    /// `ReadCappedError::Transport(kind)`, exposing only the kind so a
    /// wrapped `reqwest::Error` (whose Display embeds the URL) can't
    /// re-leak through `format!("{}", e)`.
    #[test]
    fn test_read_capped_into_propagates_read_errors() {
        struct AlwaysFail;
        impl std::io::Read for AlwaysFail {
            fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("synthetic"))
            }
        }
        let mut buf = Vec::new();
        let err = read_capped_into(AlwaysFail, &mut buf, 100).expect_err("must propagate");
        assert_eq!(err, ReadCappedError::Transport(std::io::ErrorKind::Other));
    }

    /// Pins the Display contract: even if a future caller does
    /// `format!("{}", err)`, no `io::Error` Display body (which would
    /// render a wrapped `reqwest::Error` including its URL) leaks
    /// through. Only the canonical kind name appears.
    #[test]
    fn test_read_capped_error_display_does_not_render_full_io_error() {
        let err = ReadCappedError::Transport(std::io::ErrorKind::ConnectionReset);
        let display = err.to_string();
        assert!(display.contains("transport error"));
        assert!(display.contains("ConnectionReset"));
    }

    fn ok_chunk(bytes: &'static [u8]) -> Result<bytes::Bytes, std::io::Error> {
        Ok(bytes::Bytes::from_static(bytes))
    }

    #[tokio::test]
    async fn test_collect_capped_bytes_under_cap_returns_full_body() {
        let stream = futures_util::stream::iter(vec![ok_chunk(b"hello"), ok_chunk(b" world")]);
        let buf = collect_capped_bytes(stream, 100).await.expect("read");
        assert_eq!(buf, b"hello world");
    }

    #[tokio::test]
    async fn test_collect_capped_bytes_at_cap_returns_full_body() {
        let stream = futures_util::stream::iter(vec![ok_chunk(b"hello"), ok_chunk(b" world")]);
        let buf = collect_capped_bytes(stream, 11).await.expect("read");
        assert_eq!(buf, b"hello world");
    }

    #[tokio::test]
    async fn test_collect_capped_bytes_over_cap_truncates_mid_chunk() {
        let stream = futures_util::stream::iter(vec![
            ok_chunk(b"hello"),
            ok_chunk(b" world from a very large response"),
        ]);
        let buf = collect_capped_bytes(stream, 8).await.expect("read");
        assert_eq!(buf, b"hello wo");
    }

    #[tokio::test]
    async fn test_collect_capped_bytes_zero_cap_returns_empty() {
        let stream = futures_util::stream::iter(vec![ok_chunk(b"anything")]);
        let buf = collect_capped_bytes(stream, 0).await.expect("read");
        assert!(buf.is_empty());
    }

    #[tokio::test]
    async fn test_collect_capped_bytes_propagates_stream_error() {
        let stream = futures_util::stream::iter(vec![
            ok_chunk(b"hello"),
            Err(std::io::Error::other("synthetic")),
        ]);
        let err = collect_capped_bytes(stream, 100)
            .await
            .expect_err("must propagate");
        assert_eq!(err.kind(), std::io::ErrorKind::Other);
    }

    /// Stops draining the stream as soon as the cap is reached. Pins
    /// the "don't keep allocating after we have what we need" behavior
    /// that motivates the helper — under attack, the rest of the body
    /// must be dropped, not buffered.
    #[tokio::test]
    async fn test_collect_capped_bytes_stops_polling_once_full() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let polled = std::sync::Arc::new(AtomicUsize::new(0));
        let polled_clone = polled.clone();
        let stream = futures_util::stream::unfold(0u8, move |state| {
            let polled = polled_clone.clone();
            async move {
                polled.fetch_add(1, Ordering::Relaxed);
                if state >= 10 {
                    None
                } else {
                    Some((
                        Ok::<_, std::io::Error>(bytes::Bytes::from(vec![state; 16])),
                        state + 1,
                    ))
                }
            }
        });
        let buf = collect_capped_bytes(Box::pin(stream), 32)
            .await
            .expect("read");
        assert_eq!(buf.len(), 32);
        // We required at most 2 chunks of 16 bytes each. With +1 sentinel
        // for "did we poll one extra to discover the cap was hit?":
        // accept up to 3 polls but no more. If this regresses to draining
        // the full 10-chunk stream we'd see 10+ polls.
        let n = polled.load(Ordering::Relaxed);
        assert!(n <= 3, "expected <= 3 polls before stopping, got {n}");
    }

    /// Pins the contract that every URL-scrub call site in this repo
    /// depends on: `reqwest::Error::without_url()` strips the request
    /// URL from the error's `Display` output. If this assertion ever
    /// fires it means reqwest changed semantics (or the precondition
    /// check below changed) and ~66 `.without_url()` call sites across
    /// `src/agent/`, `src/channels/`, `src/server/ws/handlers/`,
    /// `src/auth/`, `src/update/`, `src/media/`, `src/plugins/host.rs`,
    /// `src/onboarding/` would simultaneously silently regress.
    ///
    /// This canary forces a connection failure against TEST-NET-1
    /// (RFC 5737 — guaranteed not routable) with a fake bot-token-shaped
    /// path segment, so the reqwest error carries an embedded URL.
    #[tokio::test]
    async fn test_reqwest_without_url_strips_url_from_display() {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_millis(100))
            .build()
            .expect("client");
        let secret_token = "SECRET_TOKEN_PROBE_BHj47Ab9";
        let url = format!("http://192.0.2.1:1/bot{secret_token}/sendMessage");
        let err = client
            .get(&url)
            .send()
            .await
            .expect_err("connection to TEST-NET-1 must fail");

        let raw = err.to_string();
        // Precondition: this canary is meaningful only if reqwest's
        // raw `Display` embeds the URL. If a future reqwest release
        // stops doing that, this assertion fires — at which point the
        // URL-scrub discipline is either redundant (delete this test)
        // or reqwest reshaped its Display surface (update the test).
        assert!(
            raw.contains(secret_token) || raw.contains("192.0.2.1"),
            "precondition: raw reqwest::Error Display should embed URL — got `{raw}`"
        );

        let scrubbed = err.without_url().to_string();
        assert!(
            !scrubbed.contains(secret_token),
            "without_url() must strip embedded credentials — got `{scrubbed}`"
        );
        assert!(
            !scrubbed.contains("192.0.2.1"),
            "without_url() must strip host — got `{scrubbed}`"
        );
    }
}
