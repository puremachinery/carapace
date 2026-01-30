# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - Unreleased

### Added

- **Core infrastructure:** HTTP/WebSocket gateway server with JSON-RPC protocol.
- **Multi-provider LLM support:** Anthropic, OpenAI, Ollama, Google Gemini, and
  AWS Bedrock with MultiProvider dispatch.
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

[Unreleased]: https://github.com/your-org/carapace/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/your-org/carapace/releases/tag/v0.1.0
