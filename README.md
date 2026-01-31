# carapace

> **Under active development.** Kicking the tires is welcome, but don't expect everything to work yet.

A security-focused, open-source personal AI assistant. Runs on your machine. Works through Telegram, Discord, Slack, and webhooks. Supports Anthropic, OpenAI, Ollama, Gemini, Bedrock, and Venice AI. Extensible via WASM plugins. Written in Rust.

A hardened alternative to openclaw / moltbot / clawdbot — for when your molt needs a hard shell.

## Features

- **Multi-provider LLM engine** — Anthropic, OpenAI, Ollama, Google Gemini, AWS Bedrock, Venice AI with streaming, tool dispatch, and cancellation
- **Multi-channel messaging** — Telegram, Discord, Slack with platform-specific tools (25 total: 10 built-in + 15 channel-specific)
- **WASM plugin runtime** — wasmtime 41 with Ed25519 signature verification, capability sandboxing, and fuel-based CPU limits
- **Security by default** — fail-closed auth, localhost-only binding, encrypted secrets (AES-256-GCM), SSRF/DNS-rebinding defense, prompt guard, inbound message classifier, OS-level sandboxing (Seatbelt/Landlock), output content security
- **Infrastructure** — TLS, mTLS for gateway clustering, mDNS discovery, config hot-reload, Tailscale integration, Prometheus metrics, structured audit logging

## Security

Carapace is hardened against every major vulnerability class reported in the [January 2026 moltbot security disclosures](https://www.theregister.com/2026/01/27/clawdbot_moltbot_security_concerns/):

| Threat | Carapace defense |
|---|---|
| Unauthenticated access | Denied by default (fail-closed) |
| Exposed network ports | Localhost-only binding (127.0.0.1) |
| Plaintext secret storage | AES-256-GCM at rest, zeroized in memory |
| Skills supply chain | Ed25519 signatures + WASM capability sandbox |
| Prompt injection | Prompt guard + inbound classifier + exec approval flow + tool policies |
| No process sandboxing | Seatbelt (macOS) / Landlock (Linux) + rlimits |
| SSRF / DNS rebinding | Private IP blocking + post-resolution validation |

See [docs/security.md](docs/security.md) for the full security model.

## Requirements

- Rust 1.93+ (MSRV enforced in CI)
- wasmtime 41 (included as dependency)

### Recommended Tools

```bash
cargo install just            # Task runner
cargo install cargo-nextest   # Faster test runner
cargo install cargo-watch     # File watcher (optional)
cargo install cargo-tarpaulin # Coverage (optional)
```

## Getting Started

### With Ollama (free, local)

1. [Install Ollama](https://ollama.com) and pull a model:
   ```bash
   ollama pull llama3.2
   ```

2. Build and run carapace:
   ```bash
   OLLAMA_BASE_URL=http://localhost:11434 cargo run
   ```

3. Connect via WebSocket at `ws://127.0.0.1:18789/ws`.

### With a cloud provider

Set one API key and run:

```bash
export ANTHROPIC_API_KEY="sk-ant-..."   # or OPENAI_API_KEY, GOOGLE_API_KEY, VENICE_API_KEY
cargo run
```

### Other local servers (vLLM, llama.cpp, LM Studio, MLX)

Any OpenAI-compatible server works — point the OpenAI provider at it.
HTTP is allowed for loopback addresses (`localhost` / `127.0.0.1` / `::1`).

```bash
# vLLM
OPENAI_BASE_URL=http://localhost:8000/v1 OPENAI_API_KEY=unused cargo run

# llama.cpp server (llama-server --port 8080)
OPENAI_BASE_URL=http://localhost:8080/v1 OPENAI_API_KEY=unused cargo run

# LM Studio (default port 1234)
OPENAI_BASE_URL=http://localhost:1234/v1 OPENAI_API_KEY=unused cargo run

# MLX (default port 8080)
OPENAI_BASE_URL=http://localhost:8080/v1 OPENAI_API_KEY=unused cargo run
```

You can also use the Ollama provider with non-Ollama servers that expose an
OpenAI-compatible `/v1/chat/completions` endpoint:

```bash
OLLAMA_BASE_URL=http://localhost:8000 cargo run
```

Or configure via `config.json5` — see [`config.example.json5`](config.example.json5)
for the `openai` and `ollama` provider sections.

### Signal

Requires [signal-cli-rest-api](https://github.com/bbernhard/signal-cli-rest-api):

```bash
docker run -d -p 8080:8080 -v $HOME/.local/share/signal-api:/home/.local/share/signal-cli \
  -e MODE=native bbernhard/signal-cli-rest-api
```

Then configure carapace:

```bash
SIGNAL_CLI_URL=http://localhost:8080 SIGNAL_PHONE_NUMBER=+15551234567 cargo run
```

Or via `config.json5` — see `config.example.json5` for the `signal` section.

## Development

```bash
just          # Show all available recipes
just run      # Run the gateway server (debug build)
just build    # Build the project
just test     # Run tests with nextest
just lint     # Run clippy
just check    # Run lint + fmt-check + test
just watch    # Watch for changes and run tests
```

## Testing

2,472 lib tests + 10 integration tests. Zero Clippy warnings. Cross-platform CI (Linux, macOS, Windows).

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
├── agent/          # LLM execution engine, prompt guard, classifier, sandbox, output sanitizer
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
