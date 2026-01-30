# carapace

A security-focused, open-source personal AI assistant. Runs on your machine. Works through Telegram, Discord, Slack, and webhooks. Supports Anthropic, OpenAI, Ollama, Gemini, and Bedrock. Extensible via WASM plugins. Written in Rust.

A hardened alternative to openclaw / moltbot / clawdbot — for when your molt needs a hard shell.

## Features

- **Multi-provider LLM engine** — Anthropic, OpenAI, Ollama, Google Gemini, AWS Bedrock with streaming, tool dispatch, and cancellation
- **Multi-channel messaging** — Telegram, Discord, Slack with platform-specific tools (25 total: 10 built-in + 15 channel-specific)
- **WASM plugin runtime** — wasmtime 29 with Ed25519 signature verification, capability sandboxing, and fuel-based CPU limits
- **Security by default** — fail-closed auth, localhost-only binding, encrypted secrets (AES-256-GCM), SSRF/DNS-rebinding defense, prompt guard, OS-level sandboxing (Seatbelt/Landlock), output content security
- **Infrastructure** — TLS, mTLS for gateway clustering, mDNS discovery, config hot-reload, Tailscale integration, Prometheus metrics, structured audit logging

## Security

Carapace is hardened against every major vulnerability class reported in the [January 2026 moltbot security disclosures](https://www.theregister.com/2026/01/27/clawdbot_moltbot_security_concerns/):

| Threat | Carapace defense |
|---|---|
| Unauthenticated access | Denied by default (fail-closed) |
| Exposed network ports | Localhost-only binding (127.0.0.1) |
| Plaintext secret storage | AES-256-GCM at rest, zeroized in memory |
| Skills supply chain | Ed25519 signatures + WASM capability sandbox |
| Prompt injection | Prompt guard + exec approval flow + tool policies |
| No process sandboxing | Seatbelt (macOS) / Landlock (Linux) + rlimits |
| SSRF / DNS rebinding | Private IP blocking + post-resolution validation |

See [CHANGELOG.md](CHANGELOG.md) for the full security feature list.

## Requirements

- Rust 1.93+ (MSRV enforced in CI)
- wasmtime 29 (included as dependency)

### Recommended Tools

```bash
cargo install just            # Task runner
cargo install cargo-nextest   # Faster test runner
cargo install cargo-watch     # File watcher (optional)
cargo install cargo-tarpaulin # Coverage (optional)
```

## Quick Start

```bash
just          # Show all available recipes
just build    # Build the project
just test     # Run tests with nextest
just lint     # Run clippy
just check    # Run lint + fmt-check + test
just watch    # Watch for changes and run tests
```

## Testing

2,436 lib tests + 10 integration tests. Zero Clippy warnings. Cross-platform CI (Linux, macOS, Windows).

```bash
cargo nextest run       # or: just test
cargo test              # or: just test-cargo
just test-one test_name # Run specific test
just test-coverage      # With coverage
```

## CI Pipeline

Format, Clippy, nextest (cross-platform), MSRV 1.93, cargo-audit, cargo-deny, gitleaks, trivy, hadolint, cargo-geiger.

## Project Structure

```
src/
├── agent/          # LLM execution engine, prompt guard, sandbox, output sanitizer
├── auth/           # Token, password, and Tailscale authentication
├── channels/       # Channel registry (Telegram, Discord, Slack)
├── cli/            # CLI subcommands (start, config, backup, tls, etc.)
├── config/         # JSON5 config with $include, env substitution, hot reload
├── credentials/    # Platform-native credential storage (Keychain, Secret Service, Windows)
├── cron/           # Cron scheduler, background tick loop
├── devices/        # Device pairing state machine
├── exec/           # Exec approval workflow (request, wait, resolve)
├── gateway/        # Gateway connections with mTLS support
├── hooks/          # Webhook mappings
├── logging/        # Structured logging, ring buffer, secret masking
├── media/          # SSRF-protected media fetch/store
├── messages/       # Outbound message pipeline and delivery loop
├── nodes/          # Node pairing state machine
├── plugins/        # WASM plugin runtime, permissions, signature verification
├── server/         # HTTP + WebSocket server, handlers, rate limiting, CSP
├── sessions/       # Session storage (JSONL, compaction, HMAC integrity)
├── tls/            # TLS, mTLS, cluster CA management
└── usage/          # Token counting, cost calculation, model pricing

tests/
├── golden/         # Golden test traces
└── *.rs            # Integration tests
```

## Documentation

- [Architecture](docs/architecture.md) — component diagrams, request flows, agent execution pipeline
- [Security](docs/security.md) — threat model, trust boundaries, implementation checklist
- [Full documentation index](docs/README.md)

## License

MIT — see [LICENSE](LICENSE).
