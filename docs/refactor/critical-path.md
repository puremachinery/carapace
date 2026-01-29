# Critical Path: Agent, Channels, Cron

> **Status: ALL THREE SUBSYSTEMS IMPLEMENTED.** This document is retained as architectural reference. See the implementation status tables at the bottom for completion details.

Three subsystems were required to make carapace a functional gateway. This document contains the architecture, interface designs, and implementation history for each.

## Dependency Graph

```
                    ┌──────────────────────┐
                    │  1. Agent Executor    │  ✓ DONE
                    │  (LLM + streaming +   │
                    │   tool orchestration) │
                    └──────┬───────┬───────┘
                           │       │
              ┌────────────┘       └────────────┐
              ▼                                  ▼
┌─────────────────────────┐        ┌─────────────────────────┐
│  2. Channel Delivery    │  ✓     │  3. Cron Execution      │  ✓
│  (outbound pipeline +   │  DONE  │  (background tick +     │  DONE
│   plugin invocation)    │        │   payload dispatch)     │
└─────────────────────────┘        └─────────────────────────┘
```

---

## 1. Agent/LLM Execution Engine

### Implementation Summary

All components are implemented and wired together:

| Component | Location | Status |
|-----------|----------|--------|
| `handle_agent` | `src/server/ws/handlers/sessions.rs` | Creates `AgentRun`, spawns `agent::spawn_run()` |
| `handle_agent_wait` | `src/server/ws/handlers/sessions.rs` | Blocks on oneshot channel waiting for run completion |
| `handle_chat_send` | `src/server/ws/handlers/sessions.rs` | Queues user message, spawns agent run if `triggerAgent=true` |
| `handle_chat_abort` | `src/server/ws/handlers/sessions.rs` | Cancels runs via `mark_cancelled()` → `CancellationToken` |
| `AgentRunRegistry` | `src/server/ws/handlers/sessions.rs` | Tracks run lifecycle with `Queued`, `Running`, `Completed`, `Failed`, `Cancelled` states |
| `SessionStore` | `src/sessions/store.rs` | Full history management (JSONL append, get_history, compaction) |
| `ExecApprovalManager` | `src/exec/mod.rs` | Approval workflow with oneshot wait/resolve channels |
| Usage tracking | `src/usage/mod.rs` | Model pricing, token counting, cost calculation |
| Broadcast infrastructure | `src/server/ws/mod.rs` | `broadcast_agent_event`, `broadcast_chat_event` for streaming to WS clients |
| Agent executor | `src/agent/executor.rs` | Core run loop: history → LLM → stream → tools → history → complete |
| Anthropic provider | `src/agent/anthropic.rs` | SSE streaming client for Anthropic Messages API |
| Context builder | `src/agent/context.rs` | Converts `ChatMessage` history to `LlmMessage` format |
| Tool dispatch | `src/agent/tools.rs` | Plugin tool invocation via `ToolsRegistry` |
| Cancellation | `src/server/ws/handlers/sessions.rs` | `CancellationToken` in `AgentRun`, `tokio::select!` in stream loop |

### Module Structure

```
src/agent/
├── mod.rs          # Public API: spawn_run(), AgentError
├── executor.rs     # Core run loop: history → LLM → stream → tools → history
├── provider.rs     # LlmProvider trait + Anthropic implementation
├── context.rs      # Build LLM messages from SessionStore history
└── tools.rs        # Tool dispatch: plugin tools + exec approval integration
```

### Interface Design

#### LLM Provider Trait (`provider.rs`)

```rust
use async_trait::async_trait;
use tokio::sync::mpsc;

/// A stream event from the LLM.
pub enum StreamEvent {
    /// Incremental text output.
    TextDelta { text: String },

    /// The model wants to call a tool.
    ToolUse { id: String, name: String, input: serde_json::Value },

    /// The model finished its turn.
    Stop { reason: StopReason, usage: TokenUsage },

    /// Unrecoverable error from the provider.
    Error { message: String },
}

pub enum StopReason {
    EndTurn,
    ToolUse,
    MaxTokens,
}

pub struct TokenUsage {
    pub input_tokens: u64,
    pub output_tokens: u64,
}

pub struct CompletionRequest {
    pub model: String,
    pub messages: Vec<LlmMessage>,
    pub system: Option<String>,
    pub tools: Vec<ToolDefinition>,
    pub max_tokens: u32,
    pub temperature: Option<f64>,
    /// Anthropic extended thinking.
    pub thinking: Option<ThinkingConfig>,
}

pub struct LlmMessage {
    pub role: LlmRole,
    pub content: Vec<ContentBlock>,
}

pub enum LlmRole { User, Assistant }

pub enum ContentBlock {
    Text { text: String },
    ToolUse { id: String, name: String, input: serde_json::Value },
    ToolResult { tool_use_id: String, content: String, is_error: bool },
}

pub struct ToolDefinition {
    pub name: String,
    pub description: String,
    pub input_schema: serde_json::Value,
}

#[async_trait]
pub trait LlmProvider: Send + Sync {
    /// Send a completion request and receive a stream of events.
    /// The returned receiver yields events until the model stops or errors.
    async fn complete(
        &self,
        request: CompletionRequest,
    ) -> Result<mpsc::Receiver<StreamEvent>, AgentError>;
}
```

#### Anthropic Implementation (`provider.rs`)

```rust
pub struct AnthropicProvider {
    client: reqwest::Client,
    api_key: String,
    base_url: String,  // default: https://api.anthropic.com
}

impl AnthropicProvider {
    pub fn new(api_key: String) -> Self { ... }
    pub fn with_base_url(mut self, url: String) -> Self { ... }
}
```

Uses `reqwest` (already a dependency) to POST to `/v1/messages` with `stream: true`. Parses SSE lines into `StreamEvent` variants. Runs the SSE read loop in a spawned task, sending events through the `mpsc::Receiver`.

#### Context Builder (`context.rs`)

```rust
/// Convert session history into LLM messages.
///
/// Reads ChatMessage entries from the session store and maps them
/// to the LlmMessage format expected by providers.
pub fn build_context(
    history: &[sessions::ChatMessage],
    system_prompt: Option<&str>,
    agent_config: &AgentConfig,
) -> (Option<String>, Vec<LlmMessage>)
```

Mapping:
- `ChatMessage { role: User, content }` → `LlmMessage { role: User, content: [Text { text }] }`
- `ChatMessage { role: Assistant, content }` → `LlmMessage { role: Assistant, content: [Text { text }] }`
- `ChatMessage { role: Tool, content }` → `ContentBlock::ToolResult` appended to preceding user message
- `ChatMessage { role: System, content }` → prepended to system prompt

#### Tool Dispatch (`tools.rs`)

```rust
/// Execute a tool call, going through exec approval if required.
pub async fn execute_tool_call(
    tool_name: &str,
    tool_input: serde_json::Value,
    state: &WsServerState,
    run_id: &str,
    conn_id: &str,
) -> Result<ToolResult, AgentError>
```

Flow:
1. Look up tool in plugin registry (`state.plugin_registry.get_tool(tool_name)`)
2. Check if tool requires approval (based on tool policy in config)
3. If approval required:
   a. Create `ExecApprovalRecord` via `state.exec_manager`
   b. Broadcast `exec.approval.requested` event
   c. `await` decision (timeout from config, default 5 min)
   d. If denied → return `ToolResult::Denied`
4. Call plugin tool's `invoke()` method
5. Return `ToolResult::Ok { output }` or `ToolResult::Error { message }`

#### Agent Executor (`executor.rs`)

```rust
/// Execute an agent run to completion.
///
/// This is the core loop: load history, call LLM, stream results,
/// handle tool calls, append to history, mark complete.
pub async fn execute_run(
    run_id: String,
    state: Arc<WsServerState>,
    provider: Arc<dyn LlmProvider>,
) -> Result<(), AgentError>
```

**Core loop pseudocode:**

```
1. Mark run as Running in agent_run_registry
2. Load session from session_store
3. Load agent config (model, system prompt, tools, thinking level)
4. Build LLM context from session history
5. LOOP (max iterations = config.max_turns, default 25):
   a. Build CompletionRequest with messages + available tools
   b. Call provider.complete(request) → stream receiver
   c. Collect assistant response while streaming:
      - TextDelta → broadcast "agent" event with delta payload to WS clients
      - ToolUse → collect into pending_tool_calls
      - Stop(EndTurn) → break loop
      - Stop(ToolUse) → proceed to tool execution
      - Error → mark run failed, break
   d. Append assistant message to session history
   e. Record usage via usage tracker
   f. Check cancellation (agent_run_registry.is_cancelled(run_id))
   g. If pending_tool_calls:
      - For each tool call:
        i.  Broadcast "agent" event with tool_use payload
        ii. execute_tool_call(name, input, state, run_id)
        iii. Broadcast "agent" event with tool_result payload
        iv. Append tool result as ChatMessage to history
      - Continue loop (send tool results back to LLM)
   h. If Stop(EndTurn) or Stop(MaxTokens) → break
6. Broadcast "agent" event with "complete" payload
7. Mark run as Completed in agent_run_registry (wakes agent.wait waiters)
8. If deliver=true, queue outbound message via message_pipeline
```

#### Spawn Entry Point (`mod.rs`)

```rust
/// Spawn an agent run as a background tokio task.
///
/// Called from handle_agent and handle_chat_send after creating the AgentRun.
/// The task runs execute_run() and handles errors/panics.
pub fn spawn_run(
    run_id: String,
    state: Arc<WsServerState>,
    provider: Arc<dyn LlmProvider>,
) -> tokio::task::JoinHandle<()>
```

This is the glue that connects existing handlers to the new executor. `handle_agent` currently creates the `AgentRun` and returns — the only change needed is adding a `spawn_run()` call after registration.

### Integration Points (Existing Code Changes)

| File | Change |
|------|--------|
| `src/server/ws/mod.rs` | Add `provider: Arc<dyn LlmProvider>` field to `WsServerState` |
| `src/server/ws/handlers/sessions.rs` (`handle_agent`) | After registering `AgentRun`, call `agent::spawn_run(run_id, state, provider)` |
| `src/server/ws/handlers/sessions.rs` (`handle_chat_send`) | Same — spawn run when `triggerAgent=true` |
| `Cargo.toml` | Add `async-trait = "0.1"` (for `LlmProvider` trait) |
| `src/lib.rs` or `src/main.rs` | Initialize `AnthropicProvider` with API key from config/credentials |

### Implementation Steps

1. **Create `src/agent/mod.rs`** — module declaration, `AgentError` type, re-exports
2. **Create `src/agent/provider.rs`** — `LlmProvider` trait, `StreamEvent`, `CompletionRequest` types
3. **Create `src/agent/provider/anthropic.rs`** — Anthropic Messages API SSE client using `reqwest`
4. **Create `src/agent/context.rs`** — `build_context()` mapping `ChatMessage` → `LlmMessage`
5. **Create `src/agent/tools.rs`** — `execute_tool_call()` with exec approval integration
6. **Create `src/agent/executor.rs`** — `execute_run()` core loop
7. **Add `spawn_run()`** to `src/agent/mod.rs`
8. **Wire into `WsServerState`** — add provider field, initialize at startup
9. **Wire into `handle_agent`** — call `spawn_run()` after registering run
10. **Wire into `handle_chat_send`** — call `spawn_run()` when `triggerAgent=true`

### Testing Strategy

- **Unit**: `context.rs` — test history-to-LlmMessage conversion with various message sequences
- **Unit**: `tools.rs` — test approval flow with mock `ExecApprovalManager`
- **Unit**: `provider.rs` — test SSE parsing with recorded Anthropic response fixtures
- **Integration**: Mock `LlmProvider` that returns canned `StreamEvent` sequences → verify `execute_run` produces correct history entries, events, and run status
- **Integration**: End-to-end `handle_agent` → `spawn_run` → mock provider → verify `agent.wait` returns

---

## 2. Channel Message Delivery

### Implementation Summary

| Component | Location | Status |
|-----------|----------|--------|
| `ChannelRegistry` | `src/channels/mod.rs` | Status tracker — `register`, `update_status`, `is_connected` |
| `MessagePipeline` | `src/messages/outbound.rs` | In-memory queue with `queue()`, `next_for_channel()`, `mark_sent/failed()`, `Notify` for wake |
| `delivery_loop` | `src/messages/delivery.rs` | Background task draining queue, invoking channel plugins, handling retries |
| Plugin registry | `src/plugins/bindings.rs` | `register_channel()`, `get_channel()` |
| `handle_send` | `src/server/ws/handlers/system.rs` | Calls `message_pipeline.queue()`, returns `runId`/`messageId`/`channel` |
| Startup wiring | `src/main.rs` | Spawns `delivery_loop` as background tokio task |

### Architecture

```
handle_send / agent executor
        │
        ▼
┌──────────────────┐
│  MessagePipeline │ ← queue(message, context)
│  (in-memory)     │
└────────┬─────────┘
         │ delivery_worker polls
         ▼
┌──────────────────┐     ┌─────────────────────┐
│  DeliveryWorker  │────▶│  ChannelPluginInst.  │
│  (tokio task)    │     │  send_text/media()   │
└────────┬─────────┘     └─────────────────────┘
         │
         ▼
  mark_sent / mark_failed
  broadcast delivery event
```

### Interface Design

#### Delivery Worker (`src/messages/delivery.rs`)

```rust
/// Background task that dequeues messages and delivers via channel plugins.
///
/// Spawned once at server startup. Runs until shutdown signal.
pub async fn delivery_loop(
    pipeline: Arc<MessagePipeline>,
    plugin_registry: Arc<PluginRegistry>,
    channel_registry: Arc<ChannelRegistry>,
    broadcast_tx: broadcast::Sender<WsEvent>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
)
```

**Loop pseudocode:**

```
1. LOOP:
   a. For each channel in channel_registry.list():
      - Skip if not Connected
      - Call pipeline.next_for_channel(channel_id)
      - If no message, continue
      - pipeline.mark_sending(message_id)
      - Look up channel plugin: plugin_registry.get_channel(channel_id)
      - If no plugin found: pipeline.mark_failed(message_id, "no plugin"); continue
      - Match message content:
        - Text → plugin.send_text(context)
        - Media → plugin.send_media(context)
        - Composite → send_text for text parts, send_media for media parts
      - On success: pipeline.mark_sent(message_id, delivery_result)
      - On failure: pipeline.mark_failed(message_id, error)
        - If retryable and retries < max: re-queue
      - Broadcast delivery status event to WS clients
   b. Sleep 100ms (or use notify/condvar for immediate wake on new queue entry)
2. On shutdown: drain remaining messages, log count
```

#### Delivery Events

Broadcast to WS clients on delivery status changes:

```json
{ "type": "event", "event": "message.delivered", "payload": {
    "messageId": "...", "channel": "...", "status": "sent",
    "externalId": "...", "deliveredAt": 1234567890
}}
```

```json
{ "type": "event", "event": "message.failed", "payload": {
    "messageId": "...", "channel": "...", "error": "...",
    "retryable": true, "retryCount": 1
}}
```

#### Queue Notification (`src/messages/outbound.rs` change)

Add a `tokio::sync::Notify` to `MessagePipeline` so the delivery worker wakes immediately when a message is queued, rather than polling on a timer:

```rust
pub struct MessagePipeline {
    queues: RwLock<HashMap<String, VecDeque<QueuedMessage>>>,
    notify: Notify,  // NEW: wake delivery worker
    // ... existing fields
}

pub fn queue(&self, ...) -> Result<QueueResult> {
    // ... existing queue logic ...
    self.notify.notify_one();  // Wake delivery worker
    Ok(result)
}
```

### Channel Plugin Bootstrapping

For initial functionality, implement one channel. Options (in order of simplicity):

**Option A: Webhook channel (simplest, recommended for bootstrapping)**

A channel that POSTs message content to a configured URL. No SDK, no auth flow — just HTTP POST. Useful for integration testing and connecting to arbitrary services.

```rust
pub struct WebhookChannel {
    client: reqwest::Client,
    url: String,
    headers: HashMap<String, String>,
}

impl ChannelPluginInstance for WebhookChannel {
    fn send_text(&self, ctx: OutboundContext) -> Result<DeliveryResult, BindingError> {
        // POST { text, to, metadata } to self.url
    }
}
```

**Option B: Telegram channel (most useful)**

Uses Telegram Bot API (HTTP, no WebSocket). Requires bot token from config/credentials. Well-documented API, good for a real channel implementation.

**Option C: Discord channel**

Uses Discord bot API. More complex (requires gateway WebSocket for inbound, HTTP for outbound).

**Recommendation**: Start with Option A (webhook) for bootstrapping and testing, then implement Option B (Telegram) for real usage.

### Inbound Message Flow (Future)

Inbound messages (external service → gateway → agent) flow through the hooks system:

```
External service → POST /hooks/agent → validate → create AgentRun → spawn_run()
```

The hooks HTTP handler already exists (`src/hooks/handler.rs`). It needs to call `agent::spawn_run()` instead of returning a stub.

### Integration Points (Existing Code Changes)

| File | Change |
|------|--------|
| `src/messages/outbound.rs` | Add `Notify` field, call `notify_one()` in `queue()` |
| `src/messages/delivery.rs` | New file: `delivery_loop()` |
| `src/messages/mod.rs` | Re-export delivery module |
| `src/server/ws/mod.rs` (startup) | Spawn `delivery_loop` as background task |
| `src/server/ws/handlers/system.rs` (`handle_send`) | Update return to include delivery tracking (optional) |

### Implementation Steps

1. **Add `Notify` to `MessagePipeline`** — wake delivery worker on queue
2. **Create `src/messages/delivery.rs`** — delivery worker loop
3. **Create webhook channel** — `src/channels/webhook.rs` implementing `ChannelPluginInstance`
4. **Register webhook channel at startup** — from config, register in plugin registry
5. **Spawn delivery worker at startup** — in server initialization
6. **Wire `handle_send` delivery result fields** — return `conversationId`, delivery status
7. **Wire hooks/agent handler** — call `agent::spawn_run()` for inbound messages

### Testing Strategy

- **Unit**: Mock `ChannelPluginInstance` → verify delivery worker calls `send_text`/`send_media` and updates status
- **Unit**: Webhook channel with `mockito` or `wiremock` HTTP server → verify POST format
- **Integration**: `handle_send` → queue → delivery worker → mock channel → verify `mark_sent`
- **Integration**: Full round-trip: agent run → deliver=true → queue → deliver → verify external call

---

## 3. Cron Background Execution

### Implementation Summary

| Component | Location | Status |
|-----------|----------|--------|
| `CronScheduler` | `src/cron/mod.rs` | Full CRUD, schedule parsing, state tracking, 500-job limit |
| `CronPayload` | `src/cron/mod.rs` | `SystemEvent { text }` and `AgentTurn { message, model, ... }` |
| `execute_payload` | `src/cron/executor.rs` | Dispatches `SystemEvent` (broadcast) and `AgentTurn` (spawn agent run) |
| `cron_tick_loop` | `src/cron/tick.rs` | Background task (10s interval) scanning for due jobs and spawning execution |
| `handle_cron_run` | `src/server/ws/handlers/cron.rs` | Manual trigger via WS method call |
| Startup wiring | `src/main.rs` | Spawns `cron_tick_loop` as background tokio task |

### Architecture

```
Server startup
      │
      ▼
┌──────────────────┐
│  cron_tick_loop   │  ← tokio::spawn, runs forever
│  (every 10s)      │
└────────┬─────────┘
         │ scan for due jobs
         ▼
┌──────────────────┐     ┌───────────────────────────────┐
│  CronScheduler   │────▶│  execute_payload()            │
│  .get_due_jobs() │     │  ├─ SystemEvent → broadcast    │
└──────────────────┘     │  └─ AgentTurn → spawn_run()   │
                         └───────────────────────────────┘
```

### Interface Design

#### Due Job Scanner (`src/cron/mod.rs` addition)

Add a method to `CronScheduler` that returns all jobs whose `next_run_at_ms <= now` and `enabled == true`:

```rust
impl CronScheduler {
    /// Return IDs of all jobs that are due for execution.
    pub fn get_due_job_ids(&self) -> Vec<String> {
        let now = now_ms();
        let jobs = self.jobs.read();
        jobs.values()
            .filter(|j| {
                j.enabled
                    && j.state.running_at_ms.is_none()  // not already running
                    && j.state.next_run_at_ms.map_or(false, |next| now >= next)
            })
            .map(|j| j.id.clone())
            .collect()
    }
}
```

#### Payload Execution (`src/cron/executor.rs`)

```rust
/// Execute a cron job's payload.
///
/// For SystemEvent payloads, broadcasts the event to WS clients.
/// For AgentTurn payloads, spawns an agent run.
pub async fn execute_payload(
    job: &CronJob,
    state: Arc<WsServerState>,
    provider: Arc<dyn LlmProvider>,
) -> Result<CronRunOutcome, CronError>
```

**Implementation:**

```rust
match &job.payload {
    CronPayload::SystemEvent { text } => {
        state.broadcast_event("system-event", json!({
            "text": text,
            "source": "cron",
            "jobId": job.id,
        }));
        Ok(CronRunOutcome::Ok)
    }
    CronPayload::AgentTurn { message, model, channel, deliver, session_key } => {
        // Create session key from cron job config or default
        let key = session_key.as_deref().unwrap_or(&format!("cron:{}", job.id));

        // Create and register an AgentRun
        let run_id = uuid::Uuid::new_v4().to_string();
        // ... register in agent_run_registry ...

        // Append user message to session
        // ... append_message with role User ...

        // Spawn agent execution
        agent::spawn_run(run_id, state.clone(), provider);
        Ok(CronRunOutcome::Spawned { run_id })
    }
}
```

#### Background Tick Loop (`src/cron/tick.rs`)

```rust
/// Background task that checks for due cron jobs and executes them.
///
/// Spawned once at server startup. Checks every `interval` for due jobs.
pub async fn cron_tick_loop(
    scheduler: Arc<CronScheduler>,
    state: Arc<WsServerState>,
    provider: Arc<dyn LlmProvider>,
    interval: Duration,  // default: 10 seconds
    mut shutdown: tokio::sync::watch::Receiver<bool>,
)
```

**Loop pseudocode:**

```
1. LOOP:
   a. Wait for interval OR shutdown signal
   b. If shutdown → break
   c. let due_ids = scheduler.get_due_job_ids()
   d. For each job_id in due_ids:
      - Call scheduler.run(job_id, Some(CronRunMode::Due))
        (this updates state: marks running, computes next_run)
      - Get job payload from scheduler
      - tokio::spawn(execute_payload(job, state.clone(), provider.clone()))
   e. Continue
```

#### Update `run()` for Real Execution (`src/cron/mod.rs`)

The current `run()` method needs to be split:

- **`run()`** keeps its role: check due, update state (mark running → mark complete), compute next_run. But it returns the payload so the caller can execute it.
- **Return type change**: `CronRunResult` gains a `payload: Option<CronPayload>` field so the caller knows what to execute.

```rust
pub struct CronRunResult {
    pub ok: bool,
    pub ran: bool,
    pub reason: Option<CronRunReason>,
    pub payload: Option<CronPayload>,  // NEW: the payload to execute
    pub job_id: String,                // NEW: for tracking
}
```

The tick loop calls `run()` to get the payload, then calls `execute_payload()` to actually do the work. When execution completes (or fails), it calls a new `mark_run_finished()` to record actual duration and status.

```rust
impl CronScheduler {
    /// Record the outcome of a completed cron job execution.
    pub fn mark_run_finished(
        &self,
        job_id: &str,
        status: CronJobStatus,
        duration_ms: u64,
    ) -> Result<(), CronError>
}
```

### Integration Points (Existing Code Changes)

| File | Change |
|------|--------|
| `src/cron/mod.rs` | Add `get_due_job_ids()`, add `payload` to `CronRunResult`, add `mark_run_finished()`, remove simulated execution from `run()` |
| `src/cron/executor.rs` | New file: `execute_payload()` |
| `src/cron/tick.rs` | New file: `cron_tick_loop()` |
| `src/cron/mod.rs` | Re-export new submodules |
| `src/server/ws/mod.rs` (startup) | Spawn `cron_tick_loop` as background task |
| `src/server/ws/handlers/cron.rs` (`handle_cron_run`) | After `scheduler.run()`, call `execute_payload()` with the returned payload |

### Implementation Steps

1. **Add `get_due_job_ids()`** to `CronScheduler`
2. **Add `payload` field** to `CronRunResult`; update `run()` to return payload instead of simulating
3. **Add `mark_run_finished()`** to `CronScheduler`
4. **Create `src/cron/executor.rs`** — `execute_payload()` with `SystemEvent` and `AgentTurn` branches
5. **Create `src/cron/tick.rs`** — `cron_tick_loop()` background task
6. **Update `handle_cron_run`** — after `run()`, spawn `execute_payload()` for the returned payload
7. **Spawn tick loop at startup** — in server initialization, with configurable interval

### Testing Strategy

- **Unit**: `get_due_job_ids()` — create jobs with various `next_run_at_ms` values, verify correct filtering
- **Unit**: `execute_payload(SystemEvent)` — verify broadcast event content
- **Unit**: `execute_payload(AgentTurn)` — mock provider, verify agent run is spawned and message appended
- **Integration**: Full cycle: add job → advance time → tick loop fires → verify execution
- **Integration**: `handle_cron_run` with Force mode → verify payload executes

---

## Implementation Order (All Complete)

### Phase A: Agent Executor (Blocker 1) — COMPLETE

| Step | Task | Files | Depends On | Status |
|------|------|-------|------------|--------|
| A1 | LLM types (`StreamEvent`, `CompletionRequest`, `LlmMessage`) | `src/agent/provider.rs` | — | DONE |
| A2 | `LlmProvider` trait | `src/agent/provider.rs` | A1 | DONE |
| A3 | Anthropic SSE streaming client | `src/agent/anthropic.rs` | A2, `reqwest` | DONE |
| A4 | Context builder (history → LLM messages) | `src/agent/context.rs` | A1 | DONE |
| A5 | Tool dispatch with exec approval | `src/agent/tools.rs` | A2 | DONE |
| A6 | Agent executor core loop | `src/agent/executor.rs` | A3, A4, A5 | DONE |
| A7 | `spawn_run()` entry point | `src/agent/mod.rs` | A6 | DONE |
| A8 | Add `LlmProvider` to `WsServerState` | `src/server/ws/mod.rs` | A7 | DONE |
| A9 | Wire `handle_agent` → `spawn_run()` | `src/server/ws/handlers/sessions.rs` | A8 | DONE |
| A10 | Wire `handle_chat_send` → `spawn_run()` | `src/server/ws/handlers/sessions.rs` | A8 | DONE |

### Phase B: Channel Delivery (Blocker 2) — COMPLETE

| Step | Task | Files | Depends On | Status |
|------|------|-------|------------|--------|
| B1 | Add `Notify` to `MessagePipeline` | `src/messages/outbound.rs` | — | DONE |
| B2 | Delivery worker loop | `src/messages/delivery.rs` | B1 | DONE |
| B3 | Webhook channel implementation | `src/channels/webhook.rs` | — | DONE |
| B4 | Register webhook channel from config | startup code | B3 | DONE (on-demand via plugin registry) |
| B5 | Spawn delivery worker at startup | `src/main.rs` | B2, B4 | DONE |
| B6 | Wire hooks/agent → `spawn_run()` | `src/server/http.rs` | A7 | DONE |

### Phase C: Cron Execution (Blocker 3) — COMPLETE

| Step | Task | Files | Depends On | Status |
|------|------|-------|------------|--------|
| C1 | Add `get_due_job_ids()` | `src/cron/mod.rs` | — | DONE |
| C2 | Update `run()` to return payload | `src/cron/mod.rs` | — | DONE |
| C3 | Add `mark_run_finished()` | `src/cron/mod.rs` | — | DONE |
| C4 | Payload executor | `src/cron/executor.rs` | A7 | DONE |
| C5 | Background tick loop | `src/cron/tick.rs` | C1, C4 | DONE |
| C6 | Spawn tick loop at startup | `src/main.rs` | C5 | DONE |
| C7 | Update `handle_cron_run` | `src/server/ws/handlers/cron.rs` | C2, C4 | DONE |

### Server Startup Harness — DONE

| Task | Files | Status |
|------|-------|--------|
| `main.rs` with tokio runtime, config loading, HTTP+WS bind | `src/main.rs` | DONE |
| `build_http_config()` from JSON config | `src/server/http.rs` | DONE |
| `WsServerState` accessors for `message_pipeline`, `channel_registry` | `src/server/ws/mod.rs` | DONE |
| `resolve_state_dir` made `pub(crate)` | `src/server/ws/mod.rs` | DONE |
| State directory creation (`~/.moltbot`, `~/.moltbot/sessions`) | `src/main.rs` | DONE |
| Graceful shutdown via `watch::channel` + `ctrl_c` signal | `src/main.rs` | DONE |
