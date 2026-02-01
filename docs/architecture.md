# carapace Architecture

High-level overview of carapace components and their relationships.

## Component Diagram

```mermaid
graph TB
    subgraph Clients
        CLI[CLI / Control UI]
        Mobile[Mobile Apps]
        ExtNodes[External Nodes]
    end

    subgraph "Gateway Core"
        subgraph "Transport Layer"
            WS[WS Server<br/>JSON-RPC]
            HTTP[HTTP Gateway]
        end

        subgraph "Security"
            Auth[Auth<br/>tokens, passwords, loopback]
            RateLimit[Rate Limiter]
        end

        subgraph "Routing & Dispatch"
            Channels[Channel Registry]
            Messages[Outbound Messages]
            Hooks[Hook Mappings]
        end

        subgraph "State Management"
            Sessions[Session Store<br/>JSONL history, archiving]
            Nodes[Node Registry<br/>pairing, tokens]
            Devices[Device Registry<br/>pairing, tokens]
            Cron[Cron Scheduler<br/>scheduled jobs]
            ExecMgr[Exec Approvals<br/>tool execution gates]
        end

        subgraph "Voice & TTS"
            TTS[TTS Providers<br/>text-to-speech]
            VoiceWake[Voice Wake<br/>trigger detection]
            TalkMode[Talk Mode<br/>voice interaction state]
        end

        subgraph "Extensions"
            Plugins[Plugin Runtime<br/>WASM/wasmtime]
            PluginDispatch[Plugin Dispatch<br/>tools, webhooks, hooks]
        end

        subgraph "Infrastructure"
            Logging[Log Buffer<br/>tracing, ring buffer]
            Media[Media Pipeline<br/>fetch, store]
            Creds[Credential Store]
            Usage[Usage Tracking<br/>token costs]
        end
    end

    subgraph "External Services"
        Telegram[Telegram]
        Discord[Discord]
        Slack[Slack]
        Signal[Signal]
        OtherCh[Other Channels...]
    end

    subgraph "Storage"
        FS[(Config Dir<br/>~/.config/carapace (Linux))]
    end

    %% Client connections
    CLI --> WS
    CLI --> HTTP
    Mobile --> WS
    ExtNodes --> WS

    %% Transport to security
    WS --> Auth
    HTTP --> Auth
    WS --> RateLimit
    HTTP --> RateLimit

    %% Core routing
    Auth --> Channels
    Auth --> Sessions
    Channels --> Messages
    Messages --> Telegram
    Messages --> Discord
    Messages --> Slack
    Messages --> Signal
    Messages --> OtherCh

    %% Hooks flow
    HTTP --> Hooks
    Hooks --> Messages

    %% State management
    Sessions --> FS
    Nodes --> FS
    Devices --> FS
    Creds --> FS
    Cron --> FS
    Cron --> Sessions

    %% Plugin integration
    Plugins --> PluginDispatch
    PluginDispatch --> Channels
    PluginDispatch --> Hooks

    %% Media flow
    Messages --> Media
    Media --> FS
```

## Request Flow

```mermaid
sequenceDiagram
    participant C as Client
    participant WS as WS Server
    participant Auth as Auth
    participant S as Sessions
    participant Ch as Channels
    participant Ext as External Channel

    C->>WS: Connect (Bearer token)
    WS->>Auth: Verify token
    Auth-->>WS: OK / Reject

    C->>WS: message.send
    WS->>S: Get/create session
    S-->>WS: Session context
    WS->>Ch: Route to channel
    Ch->>Ext: Deliver message
    Ext-->>Ch: Delivery receipt
    Ch-->>WS: Result
    WS-->>C: Response
```

## Pairing Flow (Nodes/Devices)

See [Pairing Protocol](protocol/pairing.md) for detailed protocol documentation.

```mermaid
sequenceDiagram
    participant N as Node/Device
    participant WS as WS Server
    participant R as Registry
    participant Op as Operator

    N->>WS: pairing.request
    WS->>R: Create pending request
    R-->>WS: Request ID
    WS-->>N: Pending (request_id)

    Note over Op: Operator reviews request

    Op->>WS: pairing.approve(request_id)
    WS->>R: Approve + issue token
    R-->>WS: Token (hashed storage)
    WS-->>Op: Approved
    WS-->>N: Approved + token

    Note over N: Node stores token for future auth
```

## Agent Execution Pipeline

```mermaid
sequenceDiagram
    participant In as Inbound Message
    participant PG as Prompt Guard
    participant CLF as Classifier
    participant Ctx as Context Builder
    participant LLM as LLM Provider
    participant TD as Tool Dispatch
    participant EA as Exec Approval
    participant SB as OS Sandbox
    participant OC as Output Sanitizer
    participant PII as PII Filter
    participant Out as Outbound

    In->>PG: Raw message
    PG->>PG: Pre-flight injection scan
    PG->>PG: Tag untrusted content
    PG->>CLF: Guarded message

    CLF->>CLF: Classify (optional, fail-open)
    Note over CLF: Off / Warn / Block mode
    CLF->>Ctx: Verdict: clean or warned

    Ctx->>LLM: Session history + system prompt + tools

    loop Tool use loop (max N turns)
        LLM-->>TD: tool_use request
        TD->>TD: Check allowlist / deny-list
        TD->>EA: Requires approval?
        EA-->>TD: allow-once / allow-always / deny
        TD->>SB: Execute in sandbox
        SB->>SB: Seatbelt (macOS) / Landlock (Linux)
        SB->>SB: rlimits (CPU, memory, fds)
        SB-->>TD: Tool result
        TD-->>LLM: Tool result
    end

    LLM-->>OC: Final response
    OC->>OC: Strip XSS, dangerous tags, data URIs
    OC->>PII: Sanitized output
    PII->>PII: Redact API keys, tokens, PII
    PII->>Out: Safe output → channel delivery
```

## Key Files

| Component | Path | Description |
|-----------|------|-------------|
| WS Server | `src/server/ws/` | WebSocket JSON-RPC, method dispatch |
| HTTP Gateway | `src/server/http.rs` | HTTP endpoints, static files |
| OpenAI Compat | `src/server/openai.rs` | /v1/chat/completions, /v1/responses |
| Control API | `src/server/control.rs` | /control/status, /control/channels |
| Auth | `src/auth/mod.rs` | Token/password verification, loopback detection |
| Channels | `src/channels/mod.rs` | Channel registry, status tracking |
| Sessions | `src/sessions/store.rs` | Session CRUD, JSONL history, compaction, archiving |
| Nodes | `src/nodes/mod.rs` | Node pairing state machine |
| Devices | `src/devices/mod.rs` | Device pairing state machine |
| Cron | `src/cron/mod.rs` | Scheduled job management, run history |
| Exec Approvals | `src/exec/mod.rs` | Tool execution approval workflow |
| TTS | `src/server/ws/handlers/tts.rs` | Text-to-speech provider abstraction |
| Voice Wake | WS handler | Wake word trigger management |
| Talk Mode | WS handler | Voice interaction state machine |
| Usage | WS handler | Token/cost tracking |
| Plugins | `src/plugins/runtime.rs` | WASM plugin loading, wasmtime |
| Plugin Dispatch | `src/plugins/dispatch.rs` | Tool/webhook/hook routing |
| Hooks | `src/hooks/registry.rs` | Webhook transformations, templates |
| Messages | `src/messages/outbound.rs` | Outbound message queue |
| Media | `src/media/` | Media fetch, store, pipeline |
| Credentials | `src/credentials/mod.rs` | Encrypted credential storage |
| Venice Provider | `src/agent/venice.rs` | Venice AI provider (OpenAI-compatible composition) |
| Classifier | `src/agent/classifier.rs` | Inbound message classifier (prompt injection, social engineering) |
| Logging | `src/logging/mod.rs` | tracing setup, ring buffer, log tail streaming |

## Design Decisions

- **Async runtime**: tokio
- **WS library**: tokio-tungstenite
- **HTTP framework**: axum
- **Serialization**: serde + serde_json
- **Concurrency**: parking_lot (RwLock), Arc for shared state
- **Plugin runtime**: wasmtime (WASM component model)
- **Token security**: SHA-256 hashing, constant-time comparison
- **Persistence**: Atomic writes (temp file + rename)
