# TODO

## Status Legend

- [x] Complete — fully implemented and tested
- [~] Partial — handler exists with real logic, but some aspects stubbed
- [ ] Not started — no implementation

## Port Status Overview

| Category | Completion | Notes |
|----------|-----------|-------|
| Infrastructure (WS, HTTP, config, logging) | ~99% | Production-quality, TLS, mDNS, config reload, CLI |
| Security (auth, credentials, rate limiting) | ~97% | Real, reviewed, tool allowlists |
| Data storage (sessions, cron, usage, nodes, devices) | ~99% | Real, tested, file-backed, retention cleanup |
| Core functionality (agent/LLM, channel delivery, cron execution) | ~98% | Multi-provider (Anthropic/OpenAI/Ollama), built-in tools, media analysis, link understanding |

## Infrastructure (Complete)

- [x] Config parsing — JSON5, `$include`, env substitution, caching
- [x] Auth — token, password, loopback, Tailscale whois, device identity, timing-safe
- [x] Credential storage — macOS Keychain, Linux Secret Service, Windows Credential Manager
- [x] Logging — structured tracing, ring buffer, JSON/plaintext, log tail streaming
- [x] Rate limiting — per-IP, per-endpoint, 429 responses
- [x] CSRF protection — token generation/validation
- [x] Security headers — CSP, HSTS, X-Content-Type-Options
- [x] HTTP server — static files, routing, health check, hooks, OpenAI-compatible chat endpoint (wired to LLM provider)
- [x] Config control HTTP endpoint — PATCH config with validation, optimistic concurrency, persistence
- [x] WebSocket server — JSON-RPC dispatch, auth, handshake, broadcast
- [x] Media pipeline — SSRF-protected fetch, temp storage, cleanup, image/audio analysis
- [x] Plugin runtime — wasmtime, capability enforcement, sandbox, real WASM export calls
- [x] Plugin loader — WASM metadata extraction, manifest derivation, kind detection from exports
- [x] Hooks — webhook handler, token auth, mappings
- [x] Server startup harness — `main.rs` with tokio runtime, config loading, HTTP+WS bind, graceful shutdown
- [x] TLS — self-signed cert auto-generation, configurable cert/key paths, SHA-256 fingerprint, `axum-server` rustls binding
- [x] mDNS discovery — `_moltbot._tcp.local.` Bonjour broadcast, off/minimal/full modes, graceful shutdown
- [x] Config defaults — 7-section defaults pipeline, deep-merge with user-wins semantics, partial config support
- [x] Config hot reload — file watcher (notify), SIGHUP handler, `config.reload` WS method, debounce, validation
- [x] CLI — `start`, `config`, `status`, `logs`, `version`, `backup`, `restore`, `reset` subcommands via clap
- [x] Network binding modes — loopback/lan/auto/tailnet/custom with interface detection
- [x] Link understanding — URL extraction, SSRF-safe fetching, HTML-to-text, LRU cache

## Core Functionality

- [x] Agent/LLM execution engine — `src/agent/` with Anthropic + OpenAI + Ollama streaming, MultiProvider dispatch, tool dispatch, context building, cancellation token, per-chunk stream timeout
- [x] Built-in agent tools — 10 tools: current_time, web_fetch, memory_read/write/list, message_send, session_list/read, config_read, math_eval
- [x] Agent tool allowlists — AllowAll/AllowList/DenyList policy with enforcement at definition filtering and dispatch gating
- [x] Media understanding — Anthropic + OpenAI image analysis, OpenAI Whisper audio transcription, result caching
- [x] Channel message delivery — `src/messages/delivery.rs` delivery loop spawned at startup, drains queue, invokes channel plugins
- [x] Cron background execution — `src/cron/tick.rs` tick loop (10s interval) spawned at startup, payload execution via `src/cron/executor.rs`
- [x] GDPR data portability — `sessions.export_user` exports all user sessions/histories, resilient to per-session failures with warnings
- [x] GDPR right to erasure — `sessions.purge_user` deletes all user data (best-effort), reports deleted/total counts
- [x] Session retention — automatic cleanup via background timer with configurable interval and retention days
- [x] Session scoping — per-sender/global/per-channel-peer session isolation with daily/idle/manual reset policies
- [x] Exec approvals persistence — `exec.approvals.get/set` with atomic file I/O and SHA256 optimistic concurrency

## WS Method Handlers

### Complete (real logic)

- [x] `sessions.*` — CRUD, history, archiving, compaction, archive protection, GDPR export/purge
- [x] `cron.*` — scheduler CRUD, events, run history, 500-job limit, background tick, payload execution
- [x] `exec.approvals.*` — file-backed store with atomic writes, SHA256 concurrency control, workflow, wait/resolve via oneshot channels
- [x] `usage.status` / `usage.cost` — token counting, cost calculation, model pricing
- [x] `last-heartbeat` / `set-heartbeats` — heartbeat tracking with real values
- [x] `voicewake.*` — config, multiple wake words, thresholds
- [x] `talk.mode` — state machine (off, push-to-talk, voice-activated, continuous)
- [x] `wizard.*` — onboarding state machine
- [x] `logs.tail` — real log source, ring buffer, streaming
- [x] `system-presence` / `system-event` — presence tracking, event broadcast
- [x] `wake` — wake trigger
- [x] `channels.status` / `channels.logout` — registry queries
- [x] `node.*` / `device.*` — pairing state machines, token management
- [x] `config.get` — config reading
- [x] `config.set` / `config.apply` / `config.patch` — config writing with validation, optimistic concurrency, JSON merge-patch
- [x] `config.reload` — hot/hybrid reload with validation, broadcasts `config.changed` event
- [x] `agent` / `agent.wait` — LLM execution with streaming, tool orchestration, cancellation via `CancellationToken`
- [x] `agent.identity.get` — reads from config `agents.list`, supports explicit `agentId` lookup
- [x] `chat.send` / `chat.abort` — queues messages, spawns agent run, cancellation
- [x] `models.list` — reads from config `agents.defaults.models` and `models.providers`
- [x] `agents.list` — reads from config `agents.list`
- [x] `send` — queues outbound message, delivery loop invokes channel plugins, delivery result fields wired through
- [x] `skills.status` / `skills.bins` — reads `skills.entries` from config, scans managed bins directory
- [x] `skills.install` / `skills.update` — WASM download, magic byte validation, atomic writes, manifest tracking

### Partial (handler exists, some aspects stubbed)

- [~] `tts.convert` / `tts.speak` — config, provider/voice selection, rate/pitch/volume all work; OpenAI TTS wired (returns null audio when no API key)
- [~] `update.run` / `update.check` — real GitHub Releases API check, state tracking, install stub

## Node Parity Gaps

- [x] `sessions.compact` — archiving with archived path
- [x] `last-heartbeat` — tracks heartbeat, returns real value
- [x] `send` — delivery result fields wired through from channel plugins
- [x] Node event routing — `node.event` → operator broadcast mapping
- [x] Node pairing payload parity — accept/record version, coreVersion, uiVersion, deviceFamily, modelIdentifier, caps, permissions, remoteIp, silent, isRepair
- [x] Node list/describe integration — merge paired metadata into output

## Remaining Code TODOs

No TODO comments remain in the codebase.

## Feature Gaps (clawdbot parity)

Priority order reflects what blocks real-world usage soonest.

### P0 — Required for LAN deployment

- [x] **TLS termination** — `src/tls/mod.rs`
- [x] **mDNS service discovery** — `src/discovery/mod.rs`
- [x] **Config defaults application** — `src/config/defaults.rs`

### P1 — Required for real agent usage

- [~] **Multiple LLM providers** — Anthropic, OpenAI, and Ollama implemented with `MultiProvider` dispatch. Still needed: Google Gemini, AWS Bedrock.
- [x] **Built-in agent tools** — 10 core tools in `src/agent/builtin_tools.rs`, wired into `ToolsRegistry`
- [x] **Media understanding pipeline** — `src/media/analysis.rs` with Anthropic + OpenAI image analysis, Whisper transcription, caching

### P2 — Required for multi-user / multi-channel deployments

- [x] **Session scoping and reset rules** — `src/sessions/scoping.rs` with per-sender/global/per-channel-peer, daily/idle/manual reset
- [x] **Config reload modes** — `src/config/watcher.rs` with hot/hybrid/off, file watcher, SIGHUP, WS method
- [ ] **Channel-specific agent tools** — Telegram (edit_message, delete_message, pin, reply_markup), Discord (reactions, embeds, threads), Slack (blocks, modals, ephemeral). These are built-in tools gated by which channel the conversation originated from.

### P3 — Needed for production operations

- [ ] **Remote gateway support** — SSH tunnel transport for NAT traversal, direct WebSocket with fingerprint-based trust-on-first-use verification. Enables nodes to connect to gateways they can't reach directly.
- [~] **CLI subcommands** — `start`, `config`, `status`, `logs`, `version`, `backup`, `restore`, `reset` implemented. Still needed: `setup` (interactive first-run), `pair` (node pairing), `update`.
- [ ] **Auth profiles** — OAuth flow for multi-provider auth (Google, GitHub, Discord), profile storage, token refresh. Currently only supports static token/password auth.
- [x] **Network binding modes** — loopback/lan/auto/tailnet/custom in `src/server/bind.rs`

### P4 — Nice to have

- [x] **Link understanding pipeline** — `src/links/mod.rs` with URL extraction, SSRF-safe fetching, HTML-to-text, LRU cache
- [ ] **Tailscale serve/funnel modes** — auto-configure Tailscale serve (LAN proxy) or funnel (public internet) for zero-config HTTPS exposure. Requires Tailscale CLI integration.
- [x] **Agent tool allowlists** — `src/agent/tool_policy.rs` with AllowAll/AllowList/DenyList, enforcement at definition filtering and dispatch
- [x] **Automatic session retention cleanup** — `src/sessions/retention.rs` with background timer, configurable interval/retention days

## Missing Non-Code Artifacts

- [x] Example config file — `config.example.json5`
- [x] Dockerfile — multi-stage build with health check
- [x] Release workflow — `.github/workflows/release.yml` (tag-triggered, cross-platform binary builds)
- [ ] CONTRIBUTING.md
- [ ] CHANGELOG.md

## Tests

- [x] 1,497 tests passing (`cargo nextest run`)
- [x] Pre-commit hooks: `cargo fmt --check` + `cargo clippy -- -D warnings`
- [x] Pre-push hooks: full test suite via `cargo nextest run`
- [x] CI: fmt, clippy -D warnings, build, test, cross-platform build matrix (macOS, Windows, Linux)
- [ ] Golden trace tests — expand as protocol parity is verified
- [ ] Cross-platform CI tests (currently builds only on macOS/Windows, tests only on Linux)
