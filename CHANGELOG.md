# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Cron timezone support:** cron expressions honour the optional `tz`
  field (any IANA timezone). DST transitions handled correctly.
- **Cron job persistence:** jobs survive process restarts via
  `state_dir/cron/jobs.json`. Stale runtime state cleared on load.
- **Bedrock provider wiring:** AWS Bedrock models available via config or
  standard AWS env vars (`AWS_REGION`, `AWS_ACCESS_KEY_ID`,
  `AWS_SECRET_ACCESS_KEY`). Optional session token and explicit kill switch.
- **Signal channel:** Built-in channel plugin wrapping signal-cli-rest-api.
  Outbound via `POST /v2/send` with text and base64 media attachments. Inbound
  via polling `GET /v1/receive/{number}` every 2s with automatic agent dispatch.
  Config via `signal` section in config.json5 or `SIGNAL_CLI_URL` +
  `SIGNAL_PHONE_NUMBER` env vars.
- **Local LLM documentation:** "Other local servers" README section covering
  vLLM, llama.cpp, LM Studio, and MLX. Commented config example in
  config.example.json5 for OpenAI-compatible and Ollama providers.

## [0.1.0] - Unreleased

### Added

- **Core infrastructure:** HTTP/WebSocket gateway server with JSON-RPC protocol.
- **Multi-provider LLM support:** Anthropic, OpenAI, Ollama, Google Gemini,
  AWS Bedrock, and Venice AI with MultiProvider dispatch.
- **Built-in agent tools:** 10 core tools -- current_time, web_fetch,
  memory_read/write/list, message_send, session_list/read, config_read,
  math_eval.
- **Channel-specific tools:** 15 tools for Telegram (edit, delete, pin,
  reply_markup, send_photo), Discord (reaction, embed, thread, edit, delete),
  and Slack (blocks, ephemeral, reaction, update, delete).
- **Agent tool allowlists:** AllowAll, AllowList, and DenyList policy
  enforcement.
- **Authentication:** Token, password, and Tailscale authentication with
  timing-safe comparison.
- **OAuth profiles:** Multi-provider OAuth2 (Google, GitHub, Discord) with PKCE
  and token refresh.
- **Credential storage:** Platform-specific backends -- macOS Keychain, Linux
  Secret Service, Windows Credential Manager.
- **TLS:** Self-signed certificate auto-generation, configurable cert/key paths,
  SHA-256 fingerprint display.
- **mDNS discovery:** `_moltbot._tcp.local.` Bonjour broadcast with off,
  minimal, and full modes.
- **Config system:** JSON5 with `$include` directive, environment variable
  substitution, hot reload via file watcher and SIGHUP, defaults pipeline.
- **Session management:** Per-sender, global, and per-channel-peer scoping with
  daily, idle, and manual reset policies. Retention cleanup. GDPR
  export/purge support.
- **Cron scheduler:** Background execution on a 10-second tick, 500-job limit,
  run history, real cron expression parsing.
- **Plugin system:** WASM runtime (wasmtime) with capability enforcement and
  sandboxing.
- **Media pipeline:** SSRF-protected fetch, image and audio analysis via
  Anthropic, OpenAI, and Whisper.
- **Link understanding:** URL extraction, SSRF-safe fetching, HTML-to-text
  conversion, LRU cache.
- **Message delivery:** Background delivery loop with channel plugin invocation.
- **Node pairing:** 5-stage state machine, ED25519 device identity, token
  management.
- **Remote gateway:** Direct WebSocket with TOFU fingerprint verification and
  SSH tunnel transport.
- **Tailscale integration:** Serve and funnel modes, CLI wrapper, lifecycle
  management.
- **CLI subcommands:** start, config, status, logs, version, backup, restore,
  reset, setup, pair, update.
- **Network binding:** Loopback, LAN, auto, tailnet, and custom modes with
  interface detection.
- **Rate limiting:** Per-IP and per-endpoint rate limits with 429 responses.
- **Security headers:** CSP, HSTS, X-Content-Type-Options, CSRF protection.
- **Logging:** Structured tracing, ring buffer, JSON and plaintext output, log
  tail streaming.
- **Exec approvals:** File-backed store with atomic writes and SHA256
  concurrency control.
- **CI/CD:** Format, lint, build, and test pipelines (cross-platform) with
  security audit and release workflow.
- **Prompt guard:** pre-flight system prompt analysis, untrusted content tagging,
  post-flight PII/credential filtering, config lint.
- **Skill signatures:** Ed25519 verification with trusted publisher lists.
- **Capability sandbox:** WASM import-based capability enumeration and policy
  enforcement.
- **Session integrity:** HMAC-SHA256 sidecar verification with auto-migration.
- **Health endpoints:** `/health/live`, `/health/ready`.
- **Prometheus metrics endpoint:** `/metrics`.
- **Resource monitoring:** disk, memory, file descriptor threshold warnings.
- **Encrypted config secrets:** AES-256-GCM at-rest encryption with PBKDF2 key
  derivation for sensitive configuration values.
- **Structured audit logging:** append-only JSONL audit trail with 19 event types
  and file rotation at 50 MB.
- **Secret masking in logs:** regex-based redaction of API keys, bearer tokens,
  passwords, and query parameters in log output.
- **Backup encryption:** AES-256-GCM archive encryption with PBKDF2-HMAC-SHA256
  (600K iterations).
- **Config schema validation:** typed startup-time validation with fail-fast on
  errors and warnings for unknown keys.
- **WebSocket hardening:** per-connection token-bucket rate limiting, global and
  per-IP connection caps, JSON depth/size limits.
- **WASM fuel limits:** deterministic CPU budget per plugin call via wasmtime fuel
  metering.
- **Provider hot-swap:** automatic LLM provider rebuild on API key rotation
  without restart.
- **wasmtime 29:** upgraded from 18, resolving 3 RustSec advisories. Fuel
  metering, component model export index API.
- **Fine-grained plugin permissions:** URL pattern matching, credential key
  scopes, per-plugin overrides with load-time validation and runtime enforcement.
- **mTLS gateway clustering:** cluster CA generation (rcgen), node certificate
  issuance/revocation, rustls mutual TLS for gateway-to-gateway connections.
- **TLS CLI:** `tls init-ca`, `tls issue-cert`, `tls revoke-cert`, `tls show-ca`
  subcommands.
- **Agent execution sandboxing:** macOS Seatbelt (sandbox-exec SBPL profiles),
  Linux Landlock (raw syscalls), resource limits (CPU, memory, file descriptors)
  per tool subprocess.
- **Output content security:** HTML/Markdown sanitizer stripping XSS vectors,
  dangerous tags, and non-image data URIs from agent output.
- **TTS audio pipeline:** OpenAI TTS API with format selection (mp3, opus, aac,
  flac) and base64 encoding.
- **Self-update installer:** platform-specific binary download with SHA-256
  checksum verification and atomic replacement.
- **Venice AI provider:** OpenAI-compatible provider wrapping `OpenAiProvider`
  via composition. Routes `venice:` prefixed models to `https://api.venice.ai/api`.
  Env: `VENICE_API_KEY`, optional `VENICE_BASE_URL`.
- **Inbound message classifier:** LLM-based pre-dispatch filter classifying
  inbound messages for prompt injection, social engineering, instruction override,
  data exfiltration, and tool abuse. Off by default, fail-open on errors. Three
  modes: `off`, `warn`, `block`. Configurable model, provider, and block threshold.

### Security

- SSRF protection with DNS rebinding guards.
- Timing-safe authentication comparison.
- PKCE for all OAuth2 flows.
- Platform-native credential storage.
- Input sanitization and validation throughout.
- Ed25519 skill signature verification.
- WASM capability sandbox enforcement (deny-by-default for HTTP, credentials,
  media).
- Session file tamper detection via HMAC-SHA256 sidecars.
- Prompt injection detection in system prompts.
- Output PII and credential redaction.
- AES-256-GCM encrypted config secrets at rest.
- Backup archive encryption (PBKDF2, 600K iterations).
- Secret redaction in structured log output.
- WebSocket connection and message rate limits.
- JSON depth and payload size limits.
- WASM fuel-based CPU limits per plugin call.
- File locking and atomic writes with fsync for session storage.
- Auth profile token encryption at rest via platform keychain.
- cargo-deny, gitleaks, trivy, hadolint, and cargo-geiger in CI.
- OS-level sandboxing for agent tool subprocesses (Seatbelt, Landlock, rlimits).
- Output HTML/Markdown sanitization (XSS, dangerous tags, data URI filtering).
- mTLS with cluster CA for gateway-to-gateway authentication.
- Fine-grained WASM plugin permission enforcement (URL, credential, media scopes).
- wasmtime 29 (resolves RUSTSEC-2024-0006, -0007, -0384).
- Inbound message classifier with structured attack taxonomy and audit logging
  (`classifier_blocked`, `classifier_warned` events).

[Unreleased]: https://github.com/your-org/carapace/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/your-org/carapace/releases/tag/v0.1.0
