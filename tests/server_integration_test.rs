//! Integration tests for the server startup / shutdown lifecycle.
//!
//! Each test spins up a real (non-TLS) Carapace server on an ephemeral port via
//! [`run_server_with_config`], exercises it, and shuts it down cleanly.

use std::sync::Arc;

use carapace::server::startup::{run_server_with_config, ServerConfig, ServerHandle};
use carapace::server::ws::{WsServerConfig, WsServerState};

/// Spin up a lightweight test server with all defaults.
async fn start_test_server() -> ServerHandle {
    let ws_state = Arc::new(WsServerState::new(WsServerConfig::default()));
    let config = ServerConfig::for_testing(ws_state);
    run_server_with_config(config).await.unwrap()
}

// ---------------------------------------------------------------------------
// 1. Server starts and binds to a real port
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_server_starts_and_binds() {
    let handle = start_test_server().await;
    assert_ne!(handle.port(), 0, "OS should assign a non-zero port");
    handle.shutdown().await;
}

// ---------------------------------------------------------------------------
// 2. Health endpoint responds with 200 + expected JSON fields
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_health_endpoint_responds() {
    let handle = start_test_server().await;
    let url = format!("{}/health", handle.base_url());

    let resp = reqwest::get(&url).await.expect("GET /health failed");
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "ok");
    assert!(
        body.get("version").is_some(),
        "response should include version"
    );

    handle.shutdown().await;
}

// ---------------------------------------------------------------------------
// 3. Non-existent route returns 404
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_nonexistent_route_returns_404() {
    let handle = start_test_server().await;
    let url = format!("{}/does-not-exist", handle.base_url());

    let resp = reqwest::get(&url)
        .await
        .expect("GET /does-not-exist failed");
    assert_eq!(resp.status(), 404);

    handle.shutdown().await;
}

// ---------------------------------------------------------------------------
// 4. WebSocket upgrade request responds with 101
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_ws_upgrade_responds_101() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let handle = start_test_server().await;
    let addr = handle.local_addr();

    let mut stream = tokio::net::TcpStream::connect(addr)
        .await
        .expect("TCP connect failed");

    // Send a minimal HTTP/1.1 WebSocket upgrade request
    let request = format!(
        "GET /ws HTTP/1.1\r\n\
         Host: {}\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
         Sec-WebSocket-Version: 13\r\n\
         \r\n",
        addr
    );
    stream.write_all(request.as_bytes()).await.unwrap();

    let mut buf = vec![0u8; 1024];
    let n = stream.read(&mut buf).await.unwrap();
    let response = String::from_utf8_lossy(&buf[..n]);
    assert!(
        response.contains("101"),
        "Expected 101 Switching Protocols, got: {}",
        response
    );

    handle.shutdown().await;
}

// ---------------------------------------------------------------------------
// 5. Graceful shutdown completes within a reasonable timeout
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_graceful_shutdown_completes() {
    let handle = start_test_server().await;
    let url = format!("{}/health", handle.base_url());

    // Verify the server is alive
    let resp = reqwest::get(&url).await.expect("GET /health failed");
    assert_eq!(resp.status(), 200);

    // Shutdown should complete within 5 seconds
    tokio::time::timeout(std::time::Duration::from_secs(5), handle.shutdown())
        .await
        .expect("Shutdown did not complete within 5s");
}

// ---------------------------------------------------------------------------
// 6. Server is unreachable after shutdown
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_server_unreachable_after_shutdown() {
    let handle = start_test_server().await;
    let url = format!("{}/health", handle.base_url());

    // Confirm alive
    let resp = reqwest::get(&url).await.unwrap();
    assert_eq!(resp.status(), 200);

    // Shut down
    handle.shutdown().await;

    // After shutdown, connecting should fail
    let result = reqwest::get(&url).await;
    assert!(result.is_err(), "Expected connection error after shutdown");
}

// ---------------------------------------------------------------------------
// 7. Multiple servers run in parallel on different ports
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_multiple_servers_parallel() {
    let handle_a = start_test_server().await;
    let handle_b = start_test_server().await;

    assert_ne!(
        handle_a.port(),
        handle_b.port(),
        "Two servers should bind to different ports"
    );

    // Both should respond to /health
    let resp_a = reqwest::get(&format!("{}/health", handle_a.base_url()))
        .await
        .unwrap();
    let resp_b = reqwest::get(&format!("{}/health", handle_b.base_url()))
        .await
        .unwrap();

    assert_eq!(resp_a.status(), 200);
    assert_eq!(resp_b.status(), 200);

    handle_a.shutdown().await;
    handle_b.shutdown().await;
}

// ---------------------------------------------------------------------------
// 8. Health liveness probe returns 200
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_health_live_endpoint_responds() {
    let handle = start_test_server().await;
    let url = format!("{}/health/live", handle.base_url());

    let resp = reqwest::get(&url).await.expect("GET /health/live failed");
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "ok");

    handle.shutdown().await;
}

// ---------------------------------------------------------------------------
// 9. Health readiness probe returns 200 (no LLM configured = still ready)
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_health_ready_endpoint_responds() {
    let handle = start_test_server().await;
    let url = format!("{}/health/ready", handle.base_url());

    let resp = reqwest::get(&url).await.expect("GET /health/ready failed");
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "ready");

    handle.shutdown().await;
}
