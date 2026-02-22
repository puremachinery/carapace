//! Shared media fetcher for channel plugins with SSRF protection.

use std::net::IpAddr;
use std::time::Duration;

use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::TokioAsyncResolver;

use crate::media::fetch::{DEFAULT_FETCH_TIMEOUT_MS, MAX_FETCH_TIMEOUT_MS, MAX_URL_LENGTH};
use crate::plugins::capabilities::{SsrfConfig, SsrfProtection};
use crate::plugins::DeliveryResult;
use crate::runtime_bridge::{run_sync_blocking, BridgeError};

enum ResolveDnsError {
    Retryable(String),
    NonRetryable(String),
}

impl std::fmt::Display for ResolveDnsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Retryable(msg) | Self::NonRetryable(msg) => write!(f, "{}", msg),
        }
    }
}

impl ResolveDnsError {
    fn into_delivery_result(self) -> DeliveryResult {
        match self {
            Self::Retryable(msg) => error_result(msg, true),
            Self::NonRetryable(msg) => error_result(msg, false),
        }
    }
}

/// Fetch media bytes with SSRF protection and size limits.
#[allow(clippy::result_large_err)]
pub(crate) fn fetch_media_bytes(url: &str, max_size: u64) -> Result<Vec<u8>, DeliveryResult> {
    if url.len() > MAX_URL_LENGTH {
        return Err(error_result(
            format!("URL too long: {} chars (max {})", url.len(), MAX_URL_LENGTH),
            false,
        ));
    }

    let ssrf_config = SsrfConfig::default();
    if let Err(err) = SsrfProtection::validate_url_with_config(url, &ssrf_config) {
        return Err(error_result(format!("SSRF protection: {err}"), false));
    }

    let parsed_url = match url::Url::parse(url) {
        Ok(parsed) => parsed,
        Err(e) => return Err(error_result(format!("Invalid URL: {e}"), false)),
    };

    let host = match parsed_url.host_str() {
        Some(host) => host.to_string(),
        None => return Err(error_result("Invalid URL: missing host", false)),
    };

    let port = parsed_url.port_or_known_default().unwrap_or(80);
    let timeout = Duration::from_millis(DEFAULT_FETCH_TIMEOUT_MS.min(MAX_FETCH_TIMEOUT_MS));

    let mut client_builder = reqwest::blocking::Client::builder()
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::none());

    if host.parse::<IpAddr>().is_err() {
        let validated_ip = resolve_and_validate_dns(&host, &ssrf_config)?;
        let socket_addr = std::net::SocketAddr::new(validated_ip, port);
        client_builder = client_builder.resolve(&host, socket_addr);
    }

    let client = client_builder
        .build()
        .map_err(|e| error_result(format!("Failed to create HTTP client: {e}"), true))?;

    let response = client
        .get(url)
        .send()
        .map_err(|e| error_result(format!("Request failed: {e}"), true))?;

    let status = response.status();
    if !status.is_success() {
        return Err(error_result(
            format!("HTTP {}", status),
            status.is_server_error(),
        ));
    }

    if let Some(content_length) = response.content_length() {
        if content_length > max_size {
            return Err(error_result(
                format!(
                    "media too large: {} bytes (max {})",
                    content_length, max_size
                ),
                false,
            ));
        }
    }

    let bytes = response
        .bytes()
        .map_err(|e| error_result(format!("failed to read media bytes: {e}"), true))?;

    if bytes.len() as u64 > max_size {
        return Err(error_result(
            format!("media too large: {} bytes (max {})", bytes.len(), max_size),
            false,
        ));
    }

    Ok(bytes.to_vec())
}

#[allow(clippy::result_large_err)]
fn resolve_and_validate_dns(
    host: &str,
    ssrf_config: &SsrfConfig,
) -> Result<IpAddr, DeliveryResult> {
    let fut = async {
        let resolver =
            TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());
        let lookup = resolver.lookup_ip(host).await.map_err(|e| {
            ResolveDnsError::Retryable(format!("DNS resolution failed: {host}: {e}"))
        })?;

        let mut validated_ip: Option<IpAddr> = None;
        for ip in lookup.iter() {
            if let Err(e) = SsrfProtection::validate_resolved_ip_with_config(&ip, host, ssrf_config)
            {
                return Err(ResolveDnsError::NonRetryable(format!(
                    "SSRF protection: {e}"
                )));
            }
            if validated_ip.is_none() {
                validated_ip = Some(ip);
            }
        }

        validated_ip
            .ok_or_else(|| ResolveDnsError::Retryable(format!("DNS resolution failed: {host}")))
    };

    run_sync_blocking(fut).map_err(|err| match err {
        BridgeError::Inner(inner) => inner.into_delivery_result(),
        other => error_result(format!("media fetch runtime error: {other}"), false),
    })
}

fn error_result(error: impl Into<String>, retryable: bool) -> DeliveryResult {
    DeliveryResult {
        ok: false,
        message_id: None,
        error: Some(error.into()),
        retryable,
        conversation_id: None,
        to_jid: None,
        poll_id: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_and_validate_dns_inside_current_thread_runtime_is_panic_free() {
        let ssrf_config = SsrfConfig::default();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            rt.block_on(async { resolve_and_validate_dns("localhost", &ssrf_config) })
        }));

        assert!(
            result.is_ok(),
            "DNS resolution helper should not panic in current-thread runtime"
        );
        assert!(
            result.unwrap().is_err(),
            "localhost resolution should return a transport/SSRF error in this test setup"
        );
    }
}
