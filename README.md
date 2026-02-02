# carapace

> **Under active development.** Kicking the tires is welcome, but don't expect everything to work yet.

A security-focused, open-source personal AI assistant. Runs on your machine. Works through Signal, Telegram, Discord, Slack, webhooks, and console. Supports Anthropic, OpenAI, Ollama, Gemini, Bedrock, and Venice AI. Extensible via WASM plugins. Written in Rust.

A hardened alternative to openclaw / clawdbot — for when your assistant needs a hard shell.

## Features

- **Multi-provider LLM engine** — Anthropic, OpenAI, Ollama, Google Gemini, AWS Bedrock, Venice AI with streaming, tool dispatch, and cancellation
- **Multi-channel messaging** — Signal, Telegram, Discord, Slack, console, and webhooks. 10 built-in tools + 15 channel-specific tool schemas
- **WASM plugin runtime** — wasmtime 41 with Ed25519 signature verification, capability sandboxing, resource limits (64MB memory, fuel CPU budget, epoch wall-clock timeout), and permission enforcement
- **Security by default** — localhost-only binding, SSRF/DNS-rebinding defense, prompt guard, inbound message classifier, exec approval flow, output content security. Auth denies by default when no credentials configured; CSRF-protected control endpoints. AES-256-GCM secret encryption at rest with PBKDF2 key derivation. OS-level sandbox primitives (Seatbelt/Landlock/rlimits) implemented, subprocess wiring in progress
- **Infrastructure** — TLS, mTLS, mDNS discovery, config hot-reload, Tailscale integration, Prometheus metrics, audit logging. Gateway clustering is partially implemented

## Security

Carapace is hardened against every major vulnerability class reported in the January 2026 openclaw security disclosures:

| Threat | Carapace defense |
|---|---|
| Unauthenticated access | Denied by default when credentials configured; CSRF-protected control endpoints |
| Exposed network ports | Localhost-only binding (127.0.0.1) |
| Plaintext secret storage | AES-256-GCM encryption at rest with PBKDF2 key derivation |
| Skills supply chain | Ed25519 signatures + WASM capability sandbox + resource limits |
| Prompt injection | Prompt guard + inbound classifier + exec approval flow + tool policies |
| No process sandboxing | Seatbelt / Landlock / rlimits primitives implemented; subprocess wiring in progress |
| SSRF / DNS rebinding | Private IP blocking + post-resolution validation |

See [docs/security.md](docs/security.md) for the full security model.

## Requirements

- Rust 1.93+ (MSRV enforced in CI)
- wasmtime 41 (included as dependency)

## Install

### Prebuilt binaries (GitHub Releases)

Download the matching binary from the GitHub Releases page:

- `carapace-x86_64-linux`
- `carapace-aarch64-linux`
- `carapace-x86_64-darwin`
- `carapace-aarch64-darwin`
- `carapace-x86_64-windows.exe`

Optionally verify with cosign (signatures and certificates are published alongside each release):

```bash
cosign verify-blob \
  --certificate carapace-x86_64-linux.pem \
  --signature carapace-x86_64-linux.sig \
  --certificate-identity-regexp "https://github.com/puremachinery/carapace/.github/workflows/release.yml@refs/tags/v.*" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  carapace-x86_64-linux
```

Then make it executable (macOS/Linux) and move it into your PATH:

```bash
chmod +x carapace-x86_64-linux
sudo mv carapace-x86_64-linux /usr/local/bin/carapace
```

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

### Channels

Setup guides for Signal, Telegram, Discord, and Slack (including inbound
webhooks and gateway configuration) live in:

- `docs/channels.md`

### Full Setup Guide

End‑to‑end setup, auth, TLS, and ops guidance:

- `docs/getting-started.md`

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

Thousands of tests (4,700+ via nextest). Zero Clippy warnings. Cross-platform CI (Linux, macOS, Windows).

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
├── channels/       # Channel registry, Signal, Telegram, Discord, Slack, console
├── cli/            # CLI subcommands (start, config, backup, tls, etc.)
├── config/         # JSON5 config with $include, env substitution, hot reload
├── credentials/    # Platform-native credential storage (Keychain, Keyutils, Windows)
├── cron/           # Cron scheduler, background tick loop
├── devices/        # Device pairing state machine
├── exec/           # Exec approval workflow (request, wait, resolve)
├── gateway/        # Gateway connections with mTLS support
├── hooks/          # Webhook mappings
├── logging/        # Structured logging, ring buffer
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
