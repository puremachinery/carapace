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

/// Read up to `cap + 1` bytes from `reader` into `buf`, returning
/// `Complete` if the source ended at or below `cap`, or `Overflow` if
/// the source had at least `cap + 1` bytes. The +1 byte is the
/// disambiguator: a buffer of exactly `cap` bytes means "source had
/// at most `cap` bytes"; `cap + 1` bytes means "source had at least
/// `cap + 1` bytes". Callers use the outcome to fail-closed on
/// over-cap before passing the buffer downstream.
///
/// This abstracts the bounded-read pattern used by the plugin-
/// download path (`src/server/ws/handlers/plugins.rs`) and the
/// Signal outbound media path (`src/channels/signal.rs`): both wrap
/// `Read::take(cap + 1)` + `read_to_end` + post-read overflow check.
/// Centralizing it makes the cap-enforcement code unit-testable
/// without spinning up an HTTP server fixture.
pub(crate) fn read_capped_into<R: std::io::Read>(
    mut reader: R,
    buf: &mut Vec<u8>,
    cap: u64,
) -> std::io::Result<ReadCappedOutcome> {
    // Reject the fail-open `cap == u64::MAX` case explicitly. With
    // `saturating_add(1)`, that cap would yield `cap_with_overflow ==
    // u64::MAX` and `buf.len() as u64 > u64::MAX` is mathematically
    // impossible, so the function would always return `Complete` —
    // silently defeating the cap. Callers who genuinely want
    // "no cap" should not call this helper; surface the misuse
    // explicitly via InvalidInput rather than silently failing open.
    if cap == u64::MAX {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "read_capped_into refuses cap == u64::MAX (would silently disable overflow detection)",
        ));
    }
    let cap_with_overflow = cap.saturating_add(1);
    let mut bounded = std::io::Read::take(&mut reader, cap_with_overflow);
    std::io::Read::read_to_end(&mut bounded, buf)?;
    if buf.len() as u64 > cap {
        Ok(ReadCappedOutcome::Overflow)
    } else {
        Ok(ReadCappedOutcome::Complete)
    }
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
    /// explicitly via `InvalidInput` rather than failing open.
    #[test]
    fn test_read_capped_into_rejects_cap_u64_max() {
        let source = vec![0u8; 8];
        let mut buf = Vec::new();
        let err = read_capped_into(source.as_slice(), &mut buf, u64::MAX)
            .expect_err("must refuse u64::MAX cap");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }

    /// Pins `read_capped_into` propagates underlying read errors via
    /// `io::Result::Err` rather than swallowing them into Overflow.
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
        assert_eq!(err.kind(), std::io::ErrorKind::Other);
    }
}
