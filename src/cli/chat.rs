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
    resolve_state_dir, GatewayAuth,
};

const CHAT_CLIENT_ID: &str = "cli";
const CHAT_CLIENT_MODE: &str = "cli";

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

async fn init_media_store_cleanup() {
    let store = match crate::media::MediaStore::new(crate::media::StoreConfig::default()).await {
        Ok(store) => store,
        Err(e) => {
            eprintln!("Warning: could not initialize media store cleanup: {}", e);
            return;
        }
    };
    let store = std::sync::Arc::new(store);
    let _cleanup = store.clone().start_cleanup_task();
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

    let state_dir = crate::server::ws::resolve_state_dir();
    tokio::fs::create_dir_all(&state_dir).await?;
    tokio::fs::create_dir_all(state_dir.join("sessions")).await?;
    tokio::fs::create_dir_all(state_dir.join("cron")).await?;
    crate::logging::audit::AuditLog::init(state_dir.clone()).await;
    init_media_store_cleanup().await;

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

/// Read a line from stdin in a blocking task.
async fn read_line() -> Option<String> {
    tokio::task::spawn_blocking(|| {
        let mut line = String::new();
        match std::io::stdin().read_line(&mut line) {
            Ok(0) => None, // EOF
            Ok(_) => Some(line),
            Err(e) => {
                eprintln!("\nError reading from stdin: {}", e);
                None
            }
        }
    })
    .await
    .ok()
    .flatten()
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

/// Entry point for `cara chat`.
pub async fn handle_chat(
    new_session: bool,
    port: Option<u16>,
) -> Result<(), Box<dyn std::error::Error>> {
    let port = resolve_port(port);
    let health_client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(2))
        .build()
    {
        Ok(client) => Some(client),
        Err(e) => {
            eprintln!(
                "Warning: could not create http client for health checks: {}",
                e
            );
            None
        }
    };

    // Check if gateway is already running.
    let mut embedded_server_handle = None;
    let already_running = if let Some(client) = health_client.as_ref() {
        health_check(client, port).await
    } else {
        false
    };

    if !already_running {
        eprintln!("Starting embedded gateway on port {}...", port);
        let handle = start_embedded_gateway(port).await?;
        let health_ready = if let Some(client) = health_client.as_ref() {
            wait_for_health(client, port, std::time::Duration::from_secs(10)).await
        } else {
            false
        };
        if !health_ready {
            eprintln!("Gateway failed to start within 10 seconds.");
            handle.shutdown().await;
            return Err("gateway startup timeout".into());
        }
        embedded_server_handle = Some(handle);
    }
    let result = async {
        // Connect via WebSocket
        let ws_url = format!("ws://127.0.0.1:{}/ws", port);
        let ws_stream = match connect_ws(&ws_url, false).await {
            Ok(s) => s,
            Err(e) => {
                eprintln!("Failed to connect to gateway: {}", e);
                return Err(e);
            }
        };
        let (mut ws_write, mut ws_read) = ws_stream.split();

        // Handshake
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

        if let Err(err) =
            await_ws_response_with_error(&mut ws_read, &mut ws_write, "connect-1").await
        {
            eprintln!("WebSocket connect failed: {}", err.message);
            return Err(Box::new(err));
        }

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

            let line = read_line().await;

            let line = match line {
                Some(l) => l,
                None => {
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

                    // Stream response
                    let mut got_output = false;
                    loop {
                        let frame = tokio::select! {
                            frame = read_ws_json(&mut ws_read, &mut ws_write) => {
                                match frame {
                                    Ok(f) => f,
                                    Err(e) => {
                                        eprintln!("\nConnection lost: {}", e);
                                        return Err(e);
                                    }
                                }
                            }
                            _ = tokio::signal::ctrl_c() => {
                                eprintln!();
                                let abort_frame = serde_json::json!({
                                    "type": "req",
                                    "id": format!("abort-{}", msg_counter),
                                    "method": "chat.abort",
                                    "params": {
                                        "runId": expected_run_id.clone(),
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
                                            eprintln!(
                                                "\nWarning: could not send abort message to gateway."
                                            );
                                        }
                                    }
                                    Err(e) => {
                                        eprintln!("\nError: failed to serialize abort message: {}", e);
                                    }
                                }
                                eprintln!("Aborted current run.");
                                break;
                            }
                        };

                        let frame_type = frame.get("type").and_then(|v| v.as_str()).unwrap_or("");

                        if frame_type == "res" {
                            let response_id = frame.get("id").and_then(|v| v.as_str()).unwrap_or("");
                            if response_id != req_id {
                                continue;
                            }

                            let ok = frame.get("ok").and_then(|v| v.as_bool()).unwrap_or(false);
                            if !ok {
                                let msg = frame
                                    .get("error")
                                    .and_then(|e| e.get("message"))
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("request failed");
                                eprintln!("\nError: {}", msg);
                                break;
                            }

                            let status = frame
                                .get("payload")
                                .and_then(|p| p.get("status"))
                                .and_then(|v| v.as_str())
                                .unwrap_or("");
                            if status == "queued" {
                                eprintln!("[chat: queued] no provider is currently available.");
                                break;
                            }

                            continue;
                        }

                        if frame_type != "event" {
                            continue;
                        }

                        let event = frame.get("event").and_then(|v| v.as_str()).unwrap_or("");
                        let payload = frame.get("payload").cloned().unwrap_or(Value::Null);
                        let run_id = payload.get("runId").and_then(|v| v.as_str()).unwrap_or("");
                        if run_id != expected_run_id {
                            continue;
                        }

                        match event {
                            "agent" => {
                                let stream =
                                    payload.get("stream").and_then(|v| v.as_str()).unwrap_or("");
                                match stream {
                                    "text" => {
                                        if let Some(delta) = payload
                                            .get("data")
                                            .and_then(|d| d.get("delta"))
                                            .and_then(|v| v.as_str())
                                        {
                                            write_stdout(delta).await?;
                                            got_output = true;
                                        }
                                    }
                                    "tool_use" => {
                                        let name = tool_name_from_payload(&payload);
                                        eprintln!("[tool: {}]", name);
                                    }
                                    "tool_result" => {
                                        let name = tool_name_from_payload(&payload);
                                        eprintln!("[tool: {} \u{2192} done]", name);
                                    }
                                    "error" => {
                                        let msg = payload
                                            .get("data")
                                            .and_then(|d| d.get("message"))
                                            .and_then(|v| v.as_str())
                                            .unwrap_or("unknown error");
                                        eprintln!("\nError: {}", msg);
                                        break;
                                    }
                                    "final" => {
                                        print_final_newline_if_needed(got_output).await?;
                                        break;
                                    }
                                    _ => {}
                                }
                            }
                            "chat" => {
                                let state = payload.get("state").and_then(|v| v.as_str()).unwrap_or("");
                                match state {
                                    "final" => {
                                        print_final_newline_if_needed(got_output).await?;
                                        break;
                                    }
                                    "error" => {
                                        let msg = payload
                                            .get("errorMessage")
                                            .and_then(|v| v.as_str())
                                            .unwrap_or("unknown error");
                                        eprintln!("\nError: {}", msg);
                                        break;
                                    }
                                    _ => {}
                                }
                            }
                            _ => {
                                // Ignore heartbeat, config changes, etc.
                            }
                        }
                    }
                }
            }
        }

        // Best-effort WebSocket close before returning.
        let _ = ws_write.send(Message::Close(None)).await;
        Ok(())
    }
    .await;

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
