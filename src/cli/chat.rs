//! Interactive CLI chat REPL.
//!
//! Provides a zero-config interactive session: starts an embedded gateway
//! (or connects to a running one) and streams responses via WebSocket.

use futures_util::{SinkExt, StreamExt};
use serde_json::Value;
use std::io::Write;
use tokio_tungstenite::tungstenite::Message;
use uuid::Uuid;

use super::{
    await_connect_challenge, await_ws_response_with_error, build_device_identity_for_connect,
    connect_ws, load_or_create_device_identity, read_ws_json, resolve_gateway_auth, resolve_port,
    resolve_state_dir, GatewayAuth, WsRead, WsWrite,
};

const CHAT_CLIENT_ID: &str = "cli";
const CHAT_CLIENT_MODE: &str = "cli";
const MAX_PENDING_VERIFY_EVENTS: usize = 64;
const MAX_VERIFY_ERROR_CHARS: usize = 160;

/// REPL commands recognised in the input loop.
#[derive(Debug, PartialEq)]
enum ReplCommand {
    Exit,
    New,
    Help,
    Message(String),
}

fn parse_repl_input(line: &str) -> ReplCommand {
    let trimmed = line.trim();
    match trimmed {
        "/exit" | "/quit" => ReplCommand::Exit,
        "/new" => ReplCommand::New,
        "/help" => ReplCommand::Help,
        _ => ReplCommand::Message(trimmed.to_string()),
    }
}

fn print_help() {
    eprintln!("Commands:");
    eprintln!("  /new   — start a new session");
    eprintln!("  /help  — show this help");
    eprintln!("  /exit or /quit  — quit (or press Ctrl+D)");
}

fn generate_session_key(new_session: bool) -> String {
    if new_session {
        format!("cli-chat-{}", Uuid::new_v4())
    } else {
        "cli-chat".to_string()
    }
}

/// Check if a gateway is already reachable on the given port.
async fn health_check(client: &reqwest::Client, port: u16) -> bool {
    let url = format!("http://127.0.0.1:{}/health", port);
    client
        .get(&url)
        .send()
        .await
        .map(|resp| resp.status().is_success())
        .unwrap_or(false)
}

/// Start the gateway in-process as a background task.
/// Returns a `ServerHandle` for the started gateway.
async fn start_embedded_gateway(
    port: u16,
) -> Result<crate::server::startup::ServerHandle, Box<dyn std::error::Error>> {
    let cfg = crate::config::load_config().unwrap_or_else(|e| {
        eprintln!(
            "Warning: could not load config file: {}. Proceeding with default configuration.",
            e
        );
        Value::Object(serde_json::Map::new())
    });

    crate::server::startup::prepare_runtime_environment().await?;

    // Set up plugin/tools registries
    let plugin_registry = std::sync::Arc::new(crate::plugins::PluginRegistry::new());
    let tools_registry = std::sync::Arc::new(crate::plugins::tools::ToolsRegistry::new());
    let ws_state = crate::server::startup::build_ws_state_with_runtime_dependencies(
        &cfg,
        tools_registry.clone(),
        plugin_registry.clone(),
    )
    .await?;

    let hook_registry = std::sync::Arc::new(crate::hooks::registry::HookRegistry::new());

    let bind_addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
    let http_config = crate::server::http::build_http_config(&cfg)?;

    let server_config = crate::server::startup::ServerConfig {
        ws_state,
        http_config,
        middleware_config: crate::server::http::MiddlewareConfig::default(),
        hook_registry,
        tools_registry,
        bind_address: bind_addr,
        raw_config: cfg,
        spawn_background_tasks: true,
    };

    let handle = crate::server::startup::run_server_with_config(server_config).await?;
    Ok(handle)
}

/// Wait for the gateway health endpoint to become available.
async fn wait_for_health(
    client: &reqwest::Client,
    port: u16,
    timeout: std::time::Duration,
) -> bool {
    let start = tokio::time::Instant::now();
    let interval = std::time::Duration::from_millis(100);
    while start.elapsed() < timeout {
        if health_check(client, port).await {
            return true;
        }
        tokio::time::sleep(interval).await;
    }
    false
}

/// Ensure a local gateway is running for CLI operations.
///
/// Returns `Some(ServerHandle)` when this call started an embedded gateway and
/// the caller is responsible for shutting it down. Returns `None` when a
/// gateway was already reachable.
pub(crate) async fn ensure_local_gateway_running(
    port: u16,
) -> Result<Option<crate::server::startup::ServerHandle>, Box<dyn std::error::Error>> {
    let health_client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(2))
        .build()?;

    if health_check(&health_client, port).await {
        return Ok(None);
    }

    eprintln!("Starting embedded gateway on port {}...", port);
    let handle = start_embedded_gateway(port).await?;
    let health_ready =
        wait_for_health(&health_client, port, std::time::Duration::from_secs(10)).await;
    if !health_ready {
        handle.shutdown().await;
        return Err("gateway startup timeout".into());
    }

    Ok(Some(handle))
}

/// Read a line from stdin in a blocking task.
enum ReadLineResult {
    Line(String),
    Eof,
    Interrupted,
}

enum StreamLoopControl {
    Continue,
    Break,
}

async fn read_line() -> ReadLineResult {
    tokio::task::spawn_blocking(|| {
        let mut line = String::new();
        match std::io::stdin().read_line(&mut line) {
            Ok(0) => ReadLineResult::Eof,
            Ok(_) => ReadLineResult::Line(line),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => ReadLineResult::Interrupted,
            Err(e) => {
                eprintln!("\nError reading from stdin: {}", e);
                ReadLineResult::Eof
            }
        }
    })
    .await
    .unwrap_or(ReadLineResult::Eof)
}

fn tool_name_from_payload(payload: &Value) -> &str {
    payload
        .get("data")
        .and_then(|d| d.get("name"))
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
}

async fn print_final_newline_if_needed(got_output: bool) -> std::io::Result<()> {
    if got_output {
        write_stdout("\n").await?;
    }
    Ok(())
}

/// Print the prompt and flush stdout.
async fn print_prompt() -> std::io::Result<()> {
    tokio::task::spawn_blocking(|| {
        let mut stderr = std::io::stderr();
        stderr.write_all(b"> ")?;
        stderr.flush()
    })
    .await
    .map_err(|e| std::io::Error::other(format!("stderr write task failed: {}", e)))?
}

async fn write_stdout(text: &str) -> std::io::Result<()> {
    let text = text.to_owned();
    tokio::task::spawn_blocking(move || {
        let mut stdout = std::io::stdout();
        stdout.write_all(text.as_bytes())?;
        stdout.flush()
    })
    .await
    .map_err(|e| std::io::Error::other(format!("stdout write task failed: {}", e)))?
}

async fn connect_and_handshake(port: u16) -> Result<(WsWrite, WsRead), Box<dyn std::error::Error>> {
    let ws_url = format!("ws://127.0.0.1:{}/ws", port);
    let ws_stream = match connect_ws(&ws_url, false).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Failed to connect to gateway: {}", e);
            return Err(e);
        }
    };
    let (mut ws_write, mut ws_read) = ws_stream.split();

    let auth = resolve_gateway_auth().await;
    let state_dir = resolve_state_dir();
    let device_identity = load_or_create_device_identity(&state_dir).await?;
    let nonce = await_connect_challenge(&mut ws_read, &mut ws_write).await?;

    let role = "operator";
    let scopes = vec!["operator.write".to_string()];
    let mut connect_params = serde_json::json!({
        "minProtocol": 3,
        "maxProtocol": 3,
        "client": {
            "id": CHAT_CLIENT_ID,
            "version": env!("CARGO_PKG_VERSION"),
            "platform": std::env::consts::OS,
            "mode": CHAT_CLIENT_MODE
        },
        "role": role,
        "scopes": scopes.clone()
    });
    let GatewayAuth { token, password } = auth;
    let token_for_sig = token.clone();
    if let Some(token) = token {
        connect_params["auth"] = serde_json::json!({ "token": token });
    } else if let Some(password) = password {
        connect_params["auth"] = serde_json::json!({ "password": password });
    }
    connect_params["device"] = build_device_identity_for_connect(
        &device_identity,
        CHAT_CLIENT_ID,
        CHAT_CLIENT_MODE,
        role,
        &scopes,
        token_for_sig.as_deref(),
        Some(&nonce),
    )?;

    let connect_frame = serde_json::json!({
        "type": "req",
        "id": "connect-1",
        "method": "connect",
        "params": connect_params
    });
    ws_write
        .send(Message::Text(serde_json::to_string(&connect_frame)?.into()))
        .await?;

    if let Err(err) = await_ws_response_with_error(&mut ws_read, &mut ws_write, "connect-1").await {
        eprintln!("WebSocket connect failed: {}", err.message);
        return Err(Box::new(err));
    }

    Ok((ws_write, ws_read))
}

async fn send_abort_request(msg_counter: u64, expected_run_id: &str, ws_write: &mut WsWrite) {
    let abort_frame = serde_json::json!({
        "type": "req",
        "id": format!("abort-{}", msg_counter),
        "method": "chat.abort",
        "params": {
            "runId": expected_run_id,
            "reason": "user_interrupt"
        }
    });
    match serde_json::to_string(&abort_frame) {
        Ok(abort_msg) => {
            if ws_write
                .send(Message::Text(abort_msg.into()))
                .await
                .is_err()
            {
                eprintln!("\nWarning: could not send abort message to gateway.");
            }
        }
        Err(e) => {
            eprintln!("\nError: failed to serialize abort message: {}", e);
        }
    }
}

fn handle_response_frame(frame: &Value, req_id: &str) -> StreamLoopControl {
    let response_id = frame.get("id").and_then(|v| v.as_str()).unwrap_or("");
    if response_id != req_id {
        return StreamLoopControl::Continue;
    }

    let ok = frame.get("ok").and_then(|v| v.as_bool()).unwrap_or(false);
    if !ok {
        let msg = frame
            .get("error")
            .and_then(|e| e.get("message"))
            .and_then(|v| v.as_str())
            .unwrap_or("request failed");
        eprintln!("\nError: {}", msg);
        return StreamLoopControl::Break;
    }

    let status = frame
        .get("payload")
        .and_then(|p| p.get("status"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if status == "queued" {
        eprintln!("[chat: queued] no provider is currently available.");
        return StreamLoopControl::Break;
    }

    StreamLoopControl::Continue
}

async fn handle_agent_stream_event(
    payload: &Value,
    got_output: &mut bool,
) -> Result<StreamLoopControl, Box<dyn std::error::Error>> {
    let stream = payload.get("stream").and_then(|v| v.as_str()).unwrap_or("");
    match stream {
        "text" => {
            if let Some(delta) = payload
                .get("data")
                .and_then(|d| d.get("delta"))
                .and_then(|v| v.as_str())
            {
                write_stdout(delta).await?;
                *got_output = true;
            }
            Ok(StreamLoopControl::Continue)
        }
        "tool_use" => {
            let name = tool_name_from_payload(payload);
            eprintln!("[tool: {}]", name);
            Ok(StreamLoopControl::Continue)
        }
        "tool_result" => {
            let name = tool_name_from_payload(payload);
            eprintln!("[tool: {} → done]", name);
            Ok(StreamLoopControl::Continue)
        }
        "error" => {
            let msg = payload
                .get("data")
                .and_then(|d| d.get("message"))
                .and_then(|v| v.as_str())
                .unwrap_or("unknown error");
            eprintln!("\nError: {}", msg);
            Ok(StreamLoopControl::Break)
        }
        "final" => {
            print_final_newline_if_needed(*got_output).await?;
            Ok(StreamLoopControl::Break)
        }
        _ => Ok(StreamLoopControl::Continue),
    }
}

async fn handle_chat_state_event(
    payload: &Value,
    got_output: bool,
) -> Result<StreamLoopControl, Box<dyn std::error::Error>> {
    let state = payload.get("state").and_then(|v| v.as_str()).unwrap_or("");
    match state {
        "final" => {
            print_final_newline_if_needed(got_output).await?;
            Ok(StreamLoopControl::Break)
        }
        "error" => {
            let msg = payload
                .get("errorMessage")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown error");
            eprintln!("\nError: {}", msg);
            Ok(StreamLoopControl::Break)
        }
        _ => Ok(StreamLoopControl::Continue),
    }
}

async fn handle_event_frame(
    frame: &Value,
    expected_run_id: &str,
    got_output: &mut bool,
) -> Result<StreamLoopControl, Box<dyn std::error::Error>> {
    let payload = frame.get("payload").cloned().unwrap_or(Value::Null);
    let run_id = payload.get("runId").and_then(|v| v.as_str()).unwrap_or("");
    if run_id != expected_run_id {
        return Ok(StreamLoopControl::Continue);
    }

    match frame.get("event").and_then(|v| v.as_str()).unwrap_or("") {
        "agent" => handle_agent_stream_event(&payload, got_output).await,
        "chat" => handle_chat_state_event(&payload, *got_output).await,
        _ => Ok(StreamLoopControl::Continue),
    }
}

async fn stream_chat_response(
    req_id: &str,
    expected_run_id: &str,
    msg_counter: u64,
    ws_read: &mut WsRead,
    ws_write: &mut WsWrite,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut got_output = false;
    loop {
        let frame = tokio::select! {
            frame = async { read_ws_json(ws_read, ws_write).await.map_err(|e| e.to_string()) } => {
                match frame {
                    Ok(f) => f,
                    Err(e) => {
                        eprintln!("\nConnection lost: {}", e);
                        return Err(std::io::Error::other(e).into());
                    }
                }
            }
            _ = tokio::signal::ctrl_c() => {
                eprintln!();
                send_abort_request(msg_counter, expected_run_id, ws_write).await;
                eprintln!("Aborted current run.");
                break;
            }
        };

        let control = match frame.get("type").and_then(|v| v.as_str()).unwrap_or("") {
            "res" => handle_response_frame(&frame, req_id),
            "event" => handle_event_frame(&frame, expected_run_id, &mut got_output).await?,
            _ => StreamLoopControl::Continue,
        };
        if let StreamLoopControl::Break = control {
            break;
        }
    }

    Ok(())
}

fn verify_frame_run_id(frame: &Value) -> Option<&str> {
    frame
        .get("payload")
        .and_then(|p| p.get("runId"))
        .and_then(|v| v.as_str())
        .filter(|value| !value.is_empty())
}

fn sanitize_verify_error_message(raw: Option<&str>, fallback: &str) -> String {
    let Some(message) = raw.map(str::trim).filter(|value| !value.is_empty()) else {
        return fallback.to_string();
    };
    if message.contains('<') || message.contains('{') || message.contains('\n') {
        return fallback.to_string();
    }
    if message.chars().count() > MAX_VERIFY_ERROR_CHARS {
        let excerpt: String = message.chars().take(MAX_VERIFY_ERROR_CHARS).collect();
        return format!("{excerpt}... (truncated)");
    }
    message.to_string()
}

fn evaluate_verify_event_frame(
    frame: &Value,
    active_run_id: Option<&str>,
) -> Option<Result<(), String>> {
    let payload = frame.get("payload").cloned().unwrap_or(Value::Null);
    let run_id = payload.get("runId").and_then(|v| v.as_str()).unwrap_or("");

    let expected_run_id = active_run_id?;
    if run_id != expected_run_id {
        return None;
    }

    match frame.get("event").and_then(|v| v.as_str()).unwrap_or("") {
        "chat" => match payload.get("state").and_then(|v| v.as_str()).unwrap_or("") {
            "final" => Some(Ok(())),
            "error" => Some(Err(sanitize_verify_error_message(
                payload.get("errorMessage").and_then(|v| v.as_str()),
                "chat run failed",
            ))),
            _ => None,
        },
        "agent" => {
            let stream = payload.get("stream").and_then(|v| v.as_str()).unwrap_or("");
            if stream == "error" {
                Some(Err(sanitize_verify_error_message(
                    payload
                        .get("data")
                        .and_then(|d| d.get("message"))
                        .and_then(|v| v.as_str()),
                    "agent stream error",
                )))
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Execute a non-interactive single chat roundtrip and confirm it reaches final state.
pub(crate) async fn verify_chat_roundtrip(
    port: u16,
    prompt: &str,
    timeout: std::time::Duration,
) -> Result<(), String> {
    let (mut ws_write, mut ws_read) = connect_and_handshake(port)
        .await
        .map_err(|e| format!("failed to connect to chat endpoint: {e}"))?;

    let req_id = format!("verify-{}", Uuid::new_v4());
    let idempotency_key = Uuid::new_v4().to_string();
    let session_key = format!("cli-verify-{}", Uuid::new_v4());
    let mut active_run_id: Option<String> = None;
    let mut seen_response = false;
    // Bound only the number of pre-response events buffered.
    // This prevents unlimited queue growth, but it does not cap per-frame byte size.
    let mut pending_events: Vec<Value> = Vec::with_capacity(MAX_PENDING_VERIFY_EVENTS);

    let chat_frame = serde_json::json!({
        "type": "req",
        "id": req_id,
        "method": "chat.send",
        "params": {
            "message": prompt,
            "sessionKey": session_key,
            "idempotencyKey": idempotency_key,
            "stream": true,
            "triggerAgent": true
        }
    });

    ws_write
        .send(Message::Text(chat_frame.to_string().into()))
        .await
        .map_err(|e| format!("failed to send verification request: {e}"))?;

    let result = tokio::time::timeout(timeout, async {
        loop {
            let frame = read_ws_json(&mut ws_read, &mut ws_write)
                .await
                .map_err(|e| format!("chat stream failed: {e}"))?;
            match frame.get("type").and_then(|v| v.as_str()).unwrap_or("") {
                "res" => {
                    let response_id = frame.get("id").and_then(|v| v.as_str()).unwrap_or("");
                    if response_id != req_id {
                        continue;
                    }

                    let ok = frame.get("ok").and_then(|v| v.as_bool()).unwrap_or(false);
                    if !ok {
                        return Err(sanitize_verify_error_message(
                            frame
                                .get("error")
                                .and_then(|e| e.get("message"))
                                .and_then(|v| v.as_str()),
                            "chat.send failed",
                        ));
                    }

                    let status = frame
                        .get("payload")
                        .and_then(|p| p.get("status"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    if status == "queued" {
                        return Err(
                            "agent run is queued; no provider currently available".to_string()
                        );
                    }

                    active_run_id = verify_frame_run_id(&frame).map(str::to_string);
                    if active_run_id.is_none() {
                        return Err(
                            "chat.send response missing runId; cannot correlate verification events"
                                .to_string(),
                        );
                    }
                    seen_response = true;

                    for pending in pending_events.drain(..) {
                        if let Some(result) =
                            evaluate_verify_event_frame(&pending, active_run_id.as_deref())
                        {
                            return result;
                        }
                    }
                }
                "event" => {
                    if !seen_response {
                        if pending_events.len() >= MAX_PENDING_VERIFY_EVENTS {
                            return Err(
                                "too many server events before response; aborting verification"
                                    .to_string(),
                            );
                        }
                        pending_events.push(frame);
                        continue;
                    }
                    if let Some(result) =
                        evaluate_verify_event_frame(&frame, active_run_id.as_deref())
                    {
                        return result;
                    }
                }
                _ => {
                    continue;
                }
            }
        }
    })
    .await;

    if result.is_err() {
        if let Some(run_id) = active_run_id.as_deref() {
            send_abort_request(0, run_id, &mut ws_write).await;
        }
    }
    let _ = ws_write.send(Message::Close(None)).await;

    match result {
        Ok(inner) => inner,
        Err(_) => Err(format!(
            "timed out waiting for chat verification response after {} seconds",
            timeout.as_secs()
        )),
    }
}

pub(crate) async fn run_chat_session(
    new_session: bool,
    port: u16,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut ws_write, mut ws_read) = connect_and_handshake(port).await?;

    // REPL
    let mut session_key = generate_session_key(new_session);
    let mut msg_counter: u64 = 0;

    eprintln!();
    eprintln!(
        "  cara v{} \u{2014} type /help for commands, Ctrl+D to exit",
        env!("CARGO_PKG_VERSION")
    );
    eprintln!();

    loop {
        print_prompt().await?;

        let line_result = tokio::select! {
            line = read_line() => line,
            _ = tokio::signal::ctrl_c() => {
                eprintln!();
                ReadLineResult::Interrupted
            }
        };

        let line = match line_result {
            ReadLineResult::Line(l) => l,
            ReadLineResult::Interrupted => continue,
            ReadLineResult::Eof => {
                // EOF (Ctrl+D)
                eprintln!();
                break;
            }
        };

        match parse_repl_input(&line) {
            ReplCommand::Exit => break,
            ReplCommand::Help => {
                print_help();
                continue;
            }
            ReplCommand::New => {
                session_key = generate_session_key(true);
                eprintln!("Session reset.");
                continue;
            }
            ReplCommand::Message(msg) => {
                if msg.is_empty() {
                    continue;
                }

                msg_counter += 1;
                let req_id = format!("chat-{}", msg_counter);
                let expected_run_id = Uuid::new_v4().to_string();

                let chat_frame = serde_json::json!({
                    "type": "req",
                    "id": req_id.clone(),
                    "method": "chat.send",
                    "params": {
                        "message": msg,
                        "sessionKey": session_key.clone(),
                        "idempotencyKey": expected_run_id.clone(),
                        "stream": true,
                        "triggerAgent": true
                    }
                });
                ws_write
                    .send(Message::Text(serde_json::to_string(&chat_frame)?.into()))
                    .await?;

                stream_chat_response(
                    &req_id,
                    &expected_run_id,
                    msg_counter,
                    &mut ws_read,
                    &mut ws_write,
                )
                .await?;
            }
        }
    }

    // Best-effort WebSocket close before returning.
    let _ = ws_write.send(Message::Close(None)).await;
    Ok(())
}

/// Entry point for `cara chat`.
pub async fn handle_chat(
    new_session: bool,
    port: Option<u16>,
) -> Result<(), Box<dyn std::error::Error>> {
    let port = resolve_port(port);
    let embedded_server_handle = ensure_local_gateway_running(port).await?;

    let result = run_chat_session(new_session, port).await;

    if let Some(handle) = embedded_server_handle {
        handle.shutdown().await;
    }

    result
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_repl_command() {
        assert_eq!(parse_repl_input("/exit"), ReplCommand::Exit);
        assert_eq!(parse_repl_input("/quit"), ReplCommand::Exit);
        assert_eq!(parse_repl_input("/new"), ReplCommand::New);
        assert_eq!(parse_repl_input("/help"), ReplCommand::Help);
        assert_eq!(
            parse_repl_input("hello world"),
            ReplCommand::Message("hello world".to_string())
        );
        assert_eq!(parse_repl_input("  /exit  "), ReplCommand::Exit);
        assert_eq!(
            parse_repl_input("  some message  "),
            ReplCommand::Message("some message".to_string())
        );
    }

    #[test]
    fn test_session_key_generation() {
        let stable = generate_session_key(false);
        assert_eq!(stable, "cli-chat");

        let new1 = generate_session_key(true);
        let new2 = generate_session_key(true);
        assert!(new1.starts_with("cli-chat-"));
        assert!(new2.starts_with("cli-chat-"));
        assert_ne!(new1, new2);
    }
}
