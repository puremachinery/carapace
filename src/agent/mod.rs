//! Agent execution engine.
//!
//! Provides the LLM provider abstraction, context building, tool dispatch,
//! and the core agent run loop that ties everything together.

pub mod anthropic;
pub mod azure_openai;
pub mod bedrock;
pub mod builtin_tools;
pub mod channel_tools;
pub mod classifier;
pub mod context;
pub mod executor;
pub mod exfiltration;
pub mod factory;
pub mod gemini;
pub mod ollama;
pub mod openai;
pub mod openai_compatible;
pub mod output_sanitizer;
pub mod prompt_guard;
pub mod provider;
pub mod sandbox;
pub mod tool_policy;
pub mod tools;
pub mod venice;
pub mod vertex;

use std::sync::Arc;

use futures_util::FutureExt;
use serde_json::Value;
use tracing::warn;

use crate::server::ws::{AgentRunStatus, WsServerState};
pub use executor::execute_run;
pub use provider::{LlmProvider, StreamEvent};
use tokio_util::sync::CancellationToken;
pub use tool_policy::ToolPolicy;

/// Default LLM model used when none is specified.
pub const DEFAULT_MODEL: &str = "claude-sonnet-4-20250514";

/// Errors that can occur during agent execution.
#[derive(Debug, thiserror::Error)]
pub enum AgentError {
    #[error("LLM provider error: {0}")]
    Provider(String),

    #[error("session not found: {0}")]
    SessionNotFound(String),

    #[error("session store error: {0}")]
    SessionStore(String),

    #[error("tool execution error: {0}")]
    ToolExecution(String),

    #[error("invalid API key: {0}")]
    InvalidApiKey(String),

    #[error("invalid base URL: {0}")]
    InvalidBaseUrl(String),

    #[error("run cancelled")]
    Cancelled,

    #[error("max turns exceeded ({0})")]
    MaxTurns(u32),

    #[error("streaming error: {0}")]
    Stream(String),

    #[error("classifier blocked message ({0}): {1}")]
    ClassifierBlocked(String, String),
}

/// Configuration for an agent run.
#[derive(Debug, Clone)]
pub struct AgentConfig {
    /// LLM model identifier (e.g., "claude-sonnet-4-20250514").
    pub model: String,
    /// Optional system prompt prepended to context.
    pub system: Option<String>,
    /// Maximum agentic turns (LLM round-trips). Default 25.
    pub max_turns: u32,
    /// Maximum output tokens per LLM call. Default 8192.
    pub max_tokens: u32,
    /// Sampling temperature. None means provider default.
    pub temperature: Option<f64>,
    /// Whether to deliver the final message via the channel pipeline.
    pub deliver: bool,
    /// Tool policy controlling which tools this agent may invoke.
    pub tool_policy: ToolPolicy,
    /// When `true`, exfiltration-sensitive tools (those that send data to
    /// external services) are blocked at both the definition and dispatch
    /// levels.  This prevents prompt-injection attacks from silently
    /// exfiltrating user data.  Default: `false` (backward-compatible).
    pub exfiltration_guard: bool,
    /// Prompt guard configuration for defense-in-depth filtering.
    pub prompt_guard: prompt_guard::PromptGuardConfig,
    /// OS-level sandbox configuration for tool subprocess execution.
    pub process_sandbox: sandbox::ProcessSandboxConfig,
    /// Output sanitizer configuration for safe web rendering (CSP, HTML/Markdown
    /// sanitization).
    pub output_sanitizer: output_sanitizer::OutputSanitizerConfig,
    /// Inbound message classifier configuration (off by default).
    pub classifier: Option<classifier::ClassifierConfig>,
    /// Provider-specific parameters injected into the request body.
    ///
    /// Populated from the `venice_parameters` key in WS/HTTP requests.
    /// The Venice provider writes this as `body["venice_parameters"]`;
    /// other providers ignore it.
    pub extra: Option<serde_json::Value>,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            model: DEFAULT_MODEL.to_string(),
            system: None,
            max_turns: 25,
            max_tokens: 8192,
            temperature: None,
            deliver: false,
            tool_policy: ToolPolicy::default(),
            exfiltration_guard: false,
            prompt_guard: prompt_guard::PromptGuardConfig::default(),
            process_sandbox: sandbox::ProcessSandboxConfig::default(),
            output_sanitizer: output_sanitizer::OutputSanitizerConfig::default(),
            classifier: None,
            extra: None,
        }
    }
}

/// Apply agent config overrides from the global configuration object.
///
/// This allows runtime toggles for safety features, tool policy, and classifier
/// settings, with optional per-agent overrides.
pub fn apply_agent_config_from_settings(
    config: &mut AgentConfig,
    settings: &Value,
    agent_id: Option<&str>,
) {
    // Global classifier config (top-level)
    if let Some(classifier_value) = settings.get("classifier") {
        match serde_json::from_value(classifier_value.clone()) {
            Ok(cfg) => config.classifier = Some(cfg),
            Err(e) => {
                warn!(error = %e, "invalid classifier config; classifier disabled");
                config.classifier = None;
            }
        }
    }

    let agents = match settings.get("agents").and_then(|v| v.as_object()) {
        Some(a) => a,
        None => return,
    };

    // Global prompt guard/output sanitizer defaults
    if let Some(pg_value) = agents
        .get("promptGuard")
        .or_else(|| agents.get("prompt_guard"))
    {
        match serde_json::from_value(pg_value.clone()) {
            Ok(pg_cfg) => {
                config.prompt_guard = pg_cfg;
            }
            Err(e) => {
                warn!(error = %e, "invalid agents.promptGuard config; using defaults");
            }
        }
    }

    let output_value = agents
        .get("outputSanitizer")
        .or_else(|| agents.get("output_sanitizer"));
    if let Some(os_value) = output_value {
        match serde_json::from_value(os_value.clone()) {
            Ok(os_cfg) => {
                config.output_sanitizer = os_cfg;
            }
            Err(e) => {
                warn!(error = %e, "invalid agents.outputSanitizer config; using defaults");
            }
        }
    }

    // Apply defaults from agents.defaults
    if let Some(defaults) = agents.get("defaults").and_then(|v| v.as_object()) {
        apply_agent_overrides(config, defaults);
    }

    // Apply per-agent overrides (by id or default entry)
    if let Some(entry) = select_agent_entry(agents, agent_id) {
        apply_agent_overrides(config, entry);
    }
}

fn select_agent_entry<'a>(
    agents: &'a serde_json::Map<String, Value>,
    agent_id: Option<&str>,
) -> Option<&'a serde_json::Map<String, Value>> {
    let list = agents.get("list").and_then(|v| v.as_array())?;

    if let Some(id) = agent_id {
        if let Some(found) = list.iter().find(|entry| {
            entry
                .get("id")
                .and_then(|v| v.as_str())
                .is_some_and(|v| v == id)
        }) {
            return found.as_object();
        }
    }

    if let Some(default_entry) = list.iter().find(|entry| {
        entry
            .get("default")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
    }) {
        return default_entry.as_object();
    }

    if let Some(id) = agent_id {
        warn!(agent_id = %id, "agentId not found and no default agent configured");
    }

    None
}

fn apply_agent_overrides(config: &mut AgentConfig, agent_obj: &serde_json::Map<String, Value>) {
    if let Some(model) = agent_obj.get("model").and_then(|v| v.as_str()) {
        if !model.trim().is_empty() {
            config.model = model.to_string();
        }
    }

    if let Some(system) = agent_obj.get("system").and_then(|v| v.as_str()) {
        if !system.trim().is_empty() {
            config.system = Some(system.to_string());
        }
    }

    if let Some(max_turns) = agent_obj
        .get("maxTurns")
        .or_else(|| agent_obj.get("max_turns"))
        .and_then(|v| v.as_u64())
    {
        if max_turns > 0 {
            config.max_turns = max_turns.min(u32::MAX as u64) as u32;
        }
    }

    if let Some(max_tokens) = agent_obj
        .get("maxTokens")
        .or_else(|| agent_obj.get("max_tokens"))
        .and_then(|v| v.as_u64())
    {
        if max_tokens > 0 {
            config.max_tokens = max_tokens.min(u32::MAX as u64) as u32;
        }
    }

    if let Some(temp) = agent_obj.get("temperature").and_then(|v| v.as_f64()) {
        config.temperature = Some(temp);
    }

    if let Some(deliver) = agent_obj.get("deliver").and_then(|v| v.as_bool()) {
        config.deliver = deliver;
    }

    // Tool policy config (preferred: tools.policy/list)
    if let Some(tools_cfg) = agent_obj.get("tools") {
        config.tool_policy = ToolPolicy::from_config(Some(tools_cfg));
    } else if let Some(policy_str) = agent_obj.get("toolPolicy").and_then(|v| v.as_str()) {
        if let Some(policy) = parse_tool_policy_string(policy_str) {
            config.tool_policy = policy;
        }
    }

    if let Some(exfiltration_guard) = agent_obj
        .get("exfiltrationGuard")
        .or_else(|| agent_obj.get("exfiltration_guard"))
        .and_then(|v| v.as_bool())
    {
        config.exfiltration_guard = exfiltration_guard;
    }

    if let Some(pg_value) = agent_obj
        .get("promptGuard")
        .or_else(|| agent_obj.get("prompt_guard"))
    {
        match serde_json::from_value(pg_value.clone()) {
            Ok(pg_cfg) => config.prompt_guard = pg_cfg,
            Err(e) => warn!(error = %e, "invalid agent promptGuard config; using defaults"),
        }
    }

    if let Some(os_value) = agent_obj
        .get("outputSanitizer")
        .or_else(|| agent_obj.get("output_sanitizer"))
    {
        match serde_json::from_value(os_value.clone()) {
            Ok(os_cfg) => config.output_sanitizer = os_cfg,
            Err(e) => warn!(error = %e, "invalid agent outputSanitizer config; using defaults"),
        }
    }

    if let Some(sandbox_value) = agent_obj
        .get("sandbox")
        .or_else(|| agent_obj.get("processSandbox"))
        .or_else(|| agent_obj.get("process_sandbox"))
    {
        config.process_sandbox = sandbox::ProcessSandboxConfig::from_config(Some(sandbox_value));
    }

    if let Some(classifier_value) = agent_obj.get("classifier") {
        match serde_json::from_value(classifier_value.clone()) {
            Ok(cfg) => config.classifier = Some(cfg),
            Err(e) => warn!(error = %e, "invalid agent classifier config; classifier disabled"),
        }
    }
}

fn parse_tool_policy_string(value: &str) -> Option<ToolPolicy> {
    let normalized = value.to_lowercase().replace('_', "");
    match normalized.as_str() {
        "allowall" => Some(ToolPolicy::AllowAll),
        "allowlist" | "denylist" => {
            warn!(
                policy = %value,
                "toolPolicy requires tools.list; ignoring string-only policy"
            );
            None
        }
        _ => {
            warn!(policy = %value, "unrecognized toolPolicy value; ignoring");
            None
        }
    }
}

/// Spawn an agent run as a background tokio task.
///
/// Called from `handle_agent` and `handle_chat_send` after creating the `AgentRun`.
/// The task runs `execute_run()` and handles errors/panics.
///
/// A secondary supervisor task monitors the `JoinHandle` so that even if the
/// inner task panics in a way that `catch_unwind` does not capture (e.g. a
/// double-panic or a panic in the error-handling code itself), the run is
/// still marked as failed instead of staying in `Running` state forever.
pub fn spawn_run(
    run_id: String,
    session_key: String,
    config: AgentConfig,
    state: Arc<WsServerState>,
    provider: Arc<dyn LlmProvider>,
    cancel_token: CancellationToken,
) -> tokio::task::JoinHandle<()> {
    let supervisor_state = Arc::clone(&state);
    let supervisor_run_id = run_id.clone();

    let handle = tokio::spawn(async move {
        let result: Result<Result<(), AgentError>, _> = std::panic::AssertUnwindSafe(execute_run(
            run_id.clone(),
            session_key,
            config,
            state.clone(),
            provider,
            cancel_token,
        ))
        .catch_unwind()
        .await;

        match result {
            Ok(Ok(())) => { /* marked completed inside execute_run */ }
            Ok(Err(AgentError::Cancelled)) => {
                // Ensure marked as cancelled (may already be set by chat.abort)
                let mut registry = state.agent_run_registry.lock();
                if !registry
                    .get(&run_id)
                    .is_some_and(|r| r.status == AgentRunStatus::Cancelled)
                {
                    registry.mark_cancelled(&run_id);
                }
            }
            Ok(Err(e)) => {
                tracing::error!(run_id = %run_id, error = %e, "agent run failed");
                let mut registry = state.agent_run_registry.lock();
                registry.mark_failed(&run_id, e.to_string());
            }
            Err(panic_payload) => {
                let msg = if let Some(s) = panic_payload.downcast_ref::<&str>() {
                    (*s).to_string()
                } else if let Some(s) = panic_payload.downcast_ref::<String>() {
                    s.clone()
                } else {
                    "unknown panic".to_string()
                };
                tracing::error!(run_id = %run_id, panic = %msg, "agent run panicked");
                let mut registry = state.agent_run_registry.lock();
                registry.mark_failed(&run_id, format!("panic: {msg}"));
            }
        }
    });

    // Supervisor task: if the inner task panics in a way that bypasses
    // catch_unwind (e.g. the match/error-handling code itself panics),
    // the JoinHandle will return Err(JoinError). We catch that here as
    // a last-resort safety net so the run never stays stuck in Running.
    tokio::spawn(async move {
        if let Err(join_err) = handle.await {
            let msg = if join_err.is_panic() {
                let panic_payload = join_err.into_panic();
                if let Some(s) = panic_payload.downcast_ref::<&str>() {
                    format!("task panic: {s}")
                } else if let Some(s) = panic_payload.downcast_ref::<String>() {
                    format!("task panic: {s}")
                } else {
                    "task panic: unknown payload".to_string()
                }
            } else {
                format!("task failed: {join_err}")
            };

            tracing::error!(
                run_id = %supervisor_run_id,
                error = %msg,
                "agent task terminated unexpectedly — marking run as failed"
            );

            let mut registry = supervisor_state.agent_run_registry.lock();
            // Only mark failed if the run is still in a non-terminal state
            // (the inner handler may have already marked it).
            if registry.get(&supervisor_run_id).is_some_and(|r| {
                r.status == AgentRunStatus::Running || r.status == AgentRunStatus::Queued
            }) {
                registry.mark_failed(&supervisor_run_id, msg);
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::provider::{CompletionRequest, LlmProvider, StreamEvent};
    use crate::server::ws::{AgentRun, AgentRunStatus, WsServerConfig, WsServerState};
    use crate::sessions;
    use async_trait::async_trait;
    use std::sync::Arc;
    use tokio::sync::mpsc;
    use tokio_util::sync::CancellationToken;

    /// Mock provider whose `complete` method panics with a `&str` message.
    struct PanickingProvider {
        message: &'static str,
    }

    #[async_trait]
    impl LlmProvider for PanickingProvider {
        async fn complete(
            &self,
            _request: CompletionRequest,
            _cancel_token: CancellationToken,
        ) -> Result<mpsc::Receiver<StreamEvent>, AgentError> {
            panic!("{}", self.message);
        }
    }

    /// Mock provider whose `complete` method panics with a `String` message.
    struct PanickingStringProvider {
        message: String,
    }

    #[async_trait]
    impl LlmProvider for PanickingStringProvider {
        async fn complete(
            &self,
            _request: CompletionRequest,
            _cancel_token: CancellationToken,
        ) -> Result<mpsc::Receiver<StreamEvent>, AgentError> {
            panic!("{}", self.message);
        }
    }

    /// Helper to set up test state with a temp session store.
    fn make_test_state() -> (Arc<WsServerState>, tempfile::TempDir) {
        let tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(sessions::SessionStore::with_base_path(
            tmp.path().join("sessions"),
        ));
        let state = WsServerState::new(WsServerConfig::default()).with_session_store(store);
        (Arc::new(state), tmp)
    }

    /// Helper to set up a session and register an agent run.
    fn setup_session_and_run(state: &WsServerState, session_key: &str, run_id: &str) {
        let session = state
            .session_store()
            .get_or_create_session(session_key, sessions::SessionMetadata::default())
            .unwrap();
        state
            .session_store()
            .append_message(sessions::ChatMessage::user(&session.id, "Hello"))
            .unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let mut registry = state.agent_run_registry.lock();
        registry.register(AgentRun {
            run_id: run_id.to_string(),
            session_key: session_key.to_string(),
            status: AgentRunStatus::Queued,
            message: "Hello".to_string(),
            response: String::new(),
            error: None,
            created_at: now,
            started_at: None,
            completed_at: None,
            cancel_token: CancellationToken::new(),
            waiters: Vec::new(),
        });
    }

    #[tokio::test]
    async fn test_spawn_run_panic_marks_run_failed() {
        let (state, _tmp) = make_test_state();
        let run_id = "run-panic-str";
        let session_key = "session-panic-str";
        setup_session_and_run(&state, session_key, run_id);

        let provider: Arc<dyn LlmProvider> = Arc::new(PanickingProvider {
            message: "provider exploded",
        });
        let config = AgentConfig {
            max_turns: 1,
            ..Default::default()
        };

        let supervisor_handle = spawn_run(
            run_id.to_string(),
            session_key.to_string(),
            config,
            state.clone(),
            provider,
            CancellationToken::new(),
        );

        // Wait for the supervisor task to complete
        supervisor_handle.await.unwrap();

        // The run should be marked as failed with a panic message
        let registry = state.agent_run_registry.lock();
        let run = registry.get(run_id).expect("run should exist in registry");
        assert_eq!(
            run.status,
            AgentRunStatus::Failed,
            "run should be Failed, got: {:?}",
            run.status
        );
        let error = run.error.as_deref().expect("run should have an error");
        assert!(
            error.contains("panic"),
            "error should mention panic, got: {error}"
        );
        assert!(
            error.contains("provider exploded"),
            "error should contain panic message, got: {error}"
        );
    }

    #[tokio::test]
    async fn test_spawn_run_panic_string_payload_marks_run_failed() {
        let (state, _tmp) = make_test_state();
        let run_id = "run-panic-string";
        let session_key = "session-panic-string";
        setup_session_and_run(&state, session_key, run_id);

        let provider: Arc<dyn LlmProvider> = Arc::new(PanickingStringProvider {
            message: "string panic payload".to_string(),
        });
        let config = AgentConfig {
            max_turns: 1,
            ..Default::default()
        };

        let supervisor_handle = spawn_run(
            run_id.to_string(),
            session_key.to_string(),
            config,
            state.clone(),
            provider,
            CancellationToken::new(),
        );

        supervisor_handle.await.unwrap();

        let registry = state.agent_run_registry.lock();
        let run = registry.get(run_id).expect("run should exist in registry");
        assert_eq!(run.status, AgentRunStatus::Failed);
        let error = run.error.as_deref().expect("run should have an error");
        assert!(
            error.contains("panic"),
            "error should mention panic, got: {error}"
        );
        assert!(
            error.contains("string panic payload"),
            "error should contain panic message, got: {error}"
        );
    }

    #[tokio::test]
    async fn test_spawn_run_panic_does_not_leave_run_in_running_state() {
        let (state, _tmp) = make_test_state();
        let run_id = "run-not-stuck";
        let session_key = "session-not-stuck";
        setup_session_and_run(&state, session_key, run_id);

        let provider: Arc<dyn LlmProvider> = Arc::new(PanickingProvider { message: "boom" });
        let config = AgentConfig::default();

        let supervisor_handle = spawn_run(
            run_id.to_string(),
            session_key.to_string(),
            config,
            state.clone(),
            provider,
            CancellationToken::new(),
        );

        supervisor_handle.await.unwrap();

        let registry = state.agent_run_registry.lock();
        let run = registry.get(run_id).expect("run should exist");
        // The key invariant: the run must NOT be in Running or Queued state
        assert_ne!(
            run.status,
            AgentRunStatus::Running,
            "run must not be stuck in Running after panic"
        );
        assert_ne!(
            run.status,
            AgentRunStatus::Queued,
            "run must not be stuck in Queued after panic"
        );
    }
}
