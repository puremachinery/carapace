//! Claude CLI backend provider.
//!
//! Spawns the local `claude` CLI binary in non-interactive mode (`--bare -p`)
//! and streams the response back through `stream-json` output format. This is
//! a distinct backend from the direct Anthropic API provider — auth comes from
//! the CLI's own login state, and the CLI runs its own agent loop (including
//! tool use) internally.

use async_trait::async_trait;
use serde_json::Value;
use tokio::io::AsyncBufReadExt;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::agent::provider::*;
use crate::agent::AgentError;

/// Default binary name for the Claude CLI.
const DEFAULT_CLAUDE_CLI_PATH: &str = "claude";

/// Default maximum agent turns to prevent runaway loops.
const DEFAULT_MAX_TURNS: u32 = 10;

/// Claude CLI backend provider.
#[derive(Debug)]
pub struct ClaudeCliProvider {
    binary_path: String,
    max_turns: u32,
}

impl Default for ClaudeCliProvider {
    fn default() -> Self {
        Self {
            binary_path: DEFAULT_CLAUDE_CLI_PATH.to_string(),
            max_turns: DEFAULT_MAX_TURNS,
        }
    }
}

impl ClaudeCliProvider {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_binary_path(mut self, path: String) -> Self {
        if !path.is_empty() {
            self.binary_path = path;
        }
        self
    }

    pub fn with_max_turns(mut self, max_turns: u32) -> Self {
        if max_turns > 0 {
            self.max_turns = max_turns;
        }
        self
    }

    /// Check whether the Claude CLI binary is available and signed in.
    pub async fn check_availability(&self) -> Result<(), String> {
        // Check binary exists by running `claude auth status`.
        let output = tokio::process::Command::new(&self.binary_path)
            .args(["auth", "status"])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::NotFound {
                    format!(
                        "Claude CLI binary '{}' not found on PATH; install it from https://claude.ai/code",
                        self.binary_path
                    )
                } else {
                    format!("failed to spawn Claude CLI: {e}")
                }
            })?
            .wait_with_output();

        let output = tokio::time::timeout(std::time::Duration::from_secs(10), output)
            .await
            .map_err(|_| "Claude CLI auth status check timed out after 10s".to_string())?
            .map_err(|e| format!("failed to check Claude CLI auth status: {e}"))?;

        if output.status.success() {
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            Err(format!(
                "Claude CLI is not signed in; run `claude auth login` to authenticate. {}",
                stderr.trim()
            ))
        }
    }
}

/// Check whether the Claude CLI provider is enabled via config or env.
pub fn is_enabled(cfg: &serde_json::Value) -> bool {
    cfg.pointer("/claudeCli/enabled")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
        || std::env::var("CLAUDE_CLI_ENABLED")
            .ok()
            .is_some_and(|v| v == "1" || v.eq_ignore_ascii_case("true"))
}

/// Check whether a model ID should be routed to the Claude CLI provider.
///
/// Matches `claude-cli` (bare, uses CLI default) or `claude-cli:model`.
pub fn is_claude_cli_model(model: &str) -> bool {
    model == "claude-cli" || model.starts_with("claude-cli:")
}

/// Strip the `claude-cli:` prefix from a model ID.
///
/// If the model is bare `claude-cli` or `claude-cli:default`, returns an
/// empty string to let the CLI use its own default model.
pub fn strip_claude_cli_prefix(model: &str) -> &str {
    if model == "claude-cli" || model == "claude-cli:default" {
        return "";
    }
    if let Some(rest) = model.strip_prefix("claude-cli:") {
        rest
    } else {
        model
    }
}

#[async_trait]
impl LlmProvider for ClaudeCliProvider {
    async fn complete(
        &self,
        request: CompletionRequest,
        cancel_token: CancellationToken,
    ) -> Result<mpsc::Receiver<StreamEvent>, AgentError> {
        if cancel_token.is_cancelled() {
            return Err(AgentError::Cancelled);
        }

        // Build the prompt from the messages.
        let prompt = build_prompt_from_messages(&request);

        // Pipe the prompt via stdin to avoid exposing conversation content
        // in process arguments (visible via /proc/pid/cmdline on Linux).
        let mut cmd = tokio::process::Command::new(&self.binary_path);
        cmd.arg("--bare")
            .arg("-p")
            .arg("-") // read prompt from stdin
            .arg("--output-format")
            .arg("stream-json")
            .arg("--verbose")
            .arg("--include-partial-messages")
            .arg("--max-turns")
            .arg(self.max_turns.to_string())
            .arg("--no-session-persistence");

        // Pass model if specified (non-empty after prefix stripping).
        let model = strip_claude_cli_prefix(&request.model);
        if !model.is_empty() {
            cmd.arg("--model").arg(model);
        }

        // Write system prompt to a temp file to avoid exposing it in process
        // arguments. Uses a random suffix to prevent predictable-path attacks.
        // Cleaned up after the child process exits (not after spawn, since the
        // CLI needs time to read it).
        let system_prompt_path = if let Some(ref system) = request.system {
            let mut rng_bytes = [0u8; 8];
            getrandom::fill(&mut rng_bytes).map_err(|e| {
                AgentError::Provider(format!("failed to generate random temp file name: {e}"))
            })?;
            let path = std::env::temp_dir()
                .join(format!("carapace-sysprompt-{}.txt", hex::encode(rng_bytes)));
            {
                let mut options = std::fs::OpenOptions::new();
                options.write(true).create_new(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt;
                    options.mode(0o600);
                }
                let mut file = options.open(&path).map_err(|e| {
                    AgentError::Provider(format!("failed to create system prompt temp file: {e}"))
                })?;
                std::io::Write::write_all(&mut file, system.as_bytes()).map_err(|e| {
                    AgentError::Provider(format!("failed to write system prompt temp file: {e}"))
                })?;
            }
            cmd.arg("--system-prompt-file").arg(&path);
            Some(path)
        } else {
            None
        };

        // Suppress telemetry/updates in subprocess mode.
        cmd.env("DISABLE_NONESSENTIAL_TRAFFIC", "1");

        cmd.stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null()) // prevent stderr pipe buffer from blocking
            .stdin(std::process::Stdio::piped());

        let mut child = cmd.spawn().map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                AgentError::Provider(format!(
                    "Claude CLI binary '{}' not found; install from https://claude.ai/code",
                    self.binary_path
                ))
            } else {
                AgentError::Provider(format!("failed to spawn Claude CLI: {e}"))
            }
        })?;

        // Write prompt to stdin and close it so the CLI starts processing.
        if let Some(mut stdin) = child.stdin.take() {
            use tokio::io::AsyncWriteExt;
            if let Err(e) = stdin.write_all(prompt.as_bytes()).await {
                let _ = child.kill().await;
                return Err(AgentError::Provider(format!(
                    "failed to write prompt to Claude CLI stdin: {e}"
                )));
            }
            // Drop stdin to signal EOF.
        }

        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| AgentError::Provider("failed to capture Claude CLI stdout".into()))?;

        let (tx, rx) = mpsc::channel(64);

        // Spawn a task to read the stream-json output line by line.
        tokio::spawn(async move {
            let reader = tokio::io::BufReader::new(stdout);
            let mut lines = reader.lines();
            let mut cancelled = false;

            loop {
                tokio::select! {
                    _ = cancel_token.cancelled() => {
                        let _ = child.kill().await;
                        cancelled = true;
                        break;
                    }
                    line_result = lines.next_line() => {
                        match line_result {
                            Ok(Some(line)) => {
                                if let Some(event) = parse_stream_json_line(&line) {
                                    if tx.send(event).await.is_err() {
                                        let _ = child.kill().await;
                                        break;
                                    }
                                }
                            }
                            Ok(None) => {
                                // EOF — process finished.
                                break;
                            }
                            Err(e) => {
                                let _ = tx.send(StreamEvent::Error {
                                    message: format!("failed to read Claude CLI output: {e}"),
                                }).await;
                                break;
                            }
                        }
                    }
                }
            }

            if !cancelled {
                // Wait for the process to finish. Send Stop only on success;
                // send Error on failure (not both).
                match child.wait().await {
                    Ok(status) if status.success() => {
                        let _ = tx
                            .send(StreamEvent::Stop {
                                reason: StopReason::EndTurn,
                                usage: TokenUsage::default(),
                            })
                            .await;
                    }
                    Ok(status) => {
                        let _ = tx
                            .send(StreamEvent::Error {
                                message: format!("Claude CLI exited with status {status}"),
                            })
                            .await;
                    }
                    Err(e) => {
                        let _ = tx
                            .send(StreamEvent::Error {
                                message: format!("failed to wait for Claude CLI: {e}"),
                            })
                            .await;
                    }
                }
            }

            // Clean up system prompt temp file after the process exits.
            if let Some(ref path) = system_prompt_path {
                let _ = std::fs::remove_file(path);
            }
        });

        Ok(rx)
    }
}

/// Build a text prompt from a CompletionRequest's messages.
///
/// The Claude CLI takes a single text prompt, not a structured message array.
/// We concatenate messages with role labels for multi-turn context.
fn build_prompt_from_messages(request: &CompletionRequest) -> String {
    let mut parts = Vec::new();

    for msg in &request.messages {
        let role_label = match msg.role {
            LlmRole::User => "User",
            LlmRole::Assistant => "Assistant",
        };

        for block in &msg.content {
            match block {
                ContentBlock::Text { text, .. } => {
                    parts.push(format!("{role_label}: {text}"));
                }
                ContentBlock::ToolResult { content, .. } => {
                    parts.push(format!("User: [tool result] {content}"));
                }
                ContentBlock::ToolUse { name, input, .. } => {
                    parts.push(format!("Assistant: [tool use: {name}] {input}"));
                }
            }
        }
    }

    parts.join("\n\n")
}

/// Parse a single line of stream-json output into a StreamEvent.
///
/// Returns None for lines that don't contain useful content (system events,
/// non-text deltas, etc.).
fn parse_stream_json_line(line: &str) -> Option<StreamEvent> {
    let parsed: Value = serde_json::from_str(line).ok()?;

    // Check for text_delta events in the streaming output.
    if parsed.get("type")?.as_str()? == "stream_event" {
        let event = parsed.get("event")?;
        let delta = event.get("delta")?;
        if delta.get("type")?.as_str()? == "text_delta" {
            let text = delta.get("text")?.as_str()?.to_string();
            return Some(StreamEvent::TextDelta {
                text,
                metadata: None,
            });
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_claude_cli_model_matches() {
        assert!(is_claude_cli_model("claude-cli:default"));
        assert!(is_claude_cli_model("claude-cli:opus"));
        assert!(is_claude_cli_model("claude-cli"));
    }

    #[test]
    fn is_claude_cli_model_rejects() {
        assert!(!is_claude_cli_model("claude-sonnet-4-20250514"));
        assert!(!is_claude_cli_model("claude-cli/sonnet")); // slash no longer accepted
        assert!(!is_claude_cli_model("ollama:llama3"));
    }

    #[test]
    fn strip_prefix_default() {
        assert_eq!(strip_claude_cli_prefix("claude-cli"), "");
        assert_eq!(strip_claude_cli_prefix("claude-cli:default"), "");
    }

    #[test]
    fn strip_prefix_specific_model() {
        assert_eq!(strip_claude_cli_prefix("claude-cli:opus"), "opus");
        assert_eq!(
            strip_claude_cli_prefix("claude-cli:claude-sonnet-4-20250514"),
            "claude-sonnet-4-20250514"
        );
    }

    #[test]
    fn strip_prefix_passthrough() {
        assert_eq!(strip_claude_cli_prefix("some-model"), "some-model");
    }

    #[test]
    fn parse_text_delta_event() {
        let line =
            r#"{"type":"stream_event","event":{"delta":{"type":"text_delta","text":"Hello"}}}"#;
        let event = parse_stream_json_line(line);
        match event {
            Some(StreamEvent::TextDelta { text, .. }) => assert_eq!(text, "Hello"),
            other => panic!("expected TextDelta, got {other:?}"),
        }
    }

    #[test]
    fn parse_non_text_event_returns_none() {
        let line = r#"{"type":"system","subtype":"api_retry","attempt":1}"#;
        assert!(parse_stream_json_line(line).is_none());
    }

    #[test]
    fn parse_invalid_json_returns_none() {
        assert!(parse_stream_json_line("not json").is_none());
    }

    #[test]
    fn build_prompt_single_user_message() {
        let request = CompletionRequest {
            model: "claude-cli:default".to_string(),
            messages: vec![LlmMessage {
                role: LlmRole::User,
                content: vec![ContentBlock::Text {
                    text: "Hello".to_string(),
                    metadata: None,
                }],
            }],
            system: None,
            tools: vec![],
            max_tokens: 1024,
            temperature: None,
            extra: None,
        };
        let prompt = build_prompt_from_messages(&request);
        assert_eq!(prompt, "User: Hello");
    }

    #[test]
    fn build_prompt_multi_turn() {
        let request = CompletionRequest {
            model: "claude-cli:default".to_string(),
            messages: vec![
                LlmMessage {
                    role: LlmRole::User,
                    content: vec![ContentBlock::Text {
                        text: "Hi".to_string(),
                        metadata: None,
                    }],
                },
                LlmMessage {
                    role: LlmRole::Assistant,
                    content: vec![ContentBlock::Text {
                        text: "Hello!".to_string(),
                        metadata: None,
                    }],
                },
                LlmMessage {
                    role: LlmRole::User,
                    content: vec![ContentBlock::Text {
                        text: "How are you?".to_string(),
                        metadata: None,
                    }],
                },
            ],
            system: None,
            tools: vec![],
            max_tokens: 1024,
            temperature: None,
            extra: None,
        };
        let prompt = build_prompt_from_messages(&request);
        assert!(prompt.contains("User: Hi"));
        assert!(prompt.contains("Assistant: Hello!"));
        assert!(prompt.contains("User: How are you?"));
    }
}
