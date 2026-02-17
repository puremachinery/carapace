# carapace

> **Under active development.** Kicking the tires is welcome, but don't expect everything to work yet.

A security-focused, open-source personal AI assistant. Runs on your machine. Works through Signal, Telegram, Discord, Slack, webhooks, and console. Supports Anthropic, OpenAI, Ollama, Gemini, Bedrock, and Venice AI. Extensible via WASM plugins. Written in Rust.

A hardened alternative to openclaw / clawdbot — for when your assistant needs a hard shell.

## Features

- **Multi-provider LLM engine** — Anthropic, OpenAI, Ollama, Google Gemini, AWS Bedrock, Venice AI with streaming, tool dispatch, and cancellation
- **Multi-channel messaging** — Signal, Telegram, Discord, Slack, console, and webhooks. 10 built-in tools + 15 channel-specific tool schemas
- **WASM plugin runtime** — wasmtime 41 with Ed25519 signature verification, capability sandboxing, resource limits (64MB memory, fuel CPU budget, epoch wall-clock timeout), and permission enforcement
- **Security by default** — localhost-only binding, SSRF/DNS-rebinding defense, prompt guard, inbound message classifier, exec approval flow, output content security. Auth denies by default when no credentials configured; CSRF-protected control endpoints. AES-256-GCM secret encryption at rest with PBKDF2 key derivation. OS-level sandbox primitives (Seatbelt/Landlock/rlimits) implemented, subprocess wiring in progress
- **Infrastructure** — TLS, mTLS, mDNS discovery, config hot-reload, Tailscale integration, Prometheus metrics, audit logging. Multi-node clustering is partially implemented

## Expectations vs OpenClaw

Carapace focuses on a hardened core first. If you're coming from openclaw, the
following are **planned** but not yet on par:

- Broader channel coverage (e.g., WhatsApp/iMessage/Teams/Matrix/WebChat)
- Companion apps / nodes (macOS + iOS/Android clients)
- Browser control and live canvas/A2UI experiences
- Skills/onboarding UX and multi-agent routing
- Automatic model/provider failover

## Security

Carapace is hardened against every major vulnerability class reported in the January 2026 openclaw security disclosures:

| Threat | Carapace defense |
|---|---|
| Unauthenticated access | Denied by default when credentials configured; CSRF-protected control endpoints |
| Exposed network ports | Localhost-only binding (127.0.0.1) |
| Plaintext secret storage | OS credential store (Keychain / Keyutils / Credential Manager) with AES-256-GCM fallback |
| Skills supply chain | Ed25519 signatures + WASM capability sandbox + resource limits |
| Prompt injection | Prompt guard + inbound classifier + exec approval flow + tool policies |
| No process sandboxing | Seatbelt / Landlock / rlimits primitives implemented; subprocess wiring in progress |
| SSRF / DNS rebinding | Private IP blocking + post-resolution validation |

See [docs/security.md](docs/security.md) for the full security model.
See [docs/security-comparison.md](docs/security-comparison.md) for a threat-by-threat comparison with OpenClaw.

## Docs

- [Website](https://getcara.io) — install, first run, cookbook, and troubleshooting
- [Getting started](docs/getting-started.md) — install, first run, and ops
- [Install](docs/site/install.md) — release binaries, signatures, and install commands
- [First run](docs/site/first-run.md) — secure local startup + smoke checks
- [Get unstuck](docs/site/get-unstuck.md) — quick troubleshooting and report paths
- [Cookbook](docs/cookbook/README.md) — practical "do X" walkthroughs
- [Channel setup](docs/channels.md) — Signal, Telegram, Discord, Slack, webhooks
- [CLI guide](docs/cli.md) — subcommands, flags, and device identity
- [Documentation index](docs/README.md) — architecture, protocol, security
- [Report feedback or bugs](https://github.com/puremachinery/carapace/issues/new/choose) — setup smoke reports, bug reports, and feature requests

## Status (Preview)

This project is in preview. Core paths are tested and verified. Expect gaps and sharp edges.

Known working:

- Setup wizard from clean state
- Anthropic LLM provider (via OpenAI-compatible API)
- Token auth enforcement
- Discord channel (end-to-end: inbound message, agent run, outbound reply)
- Health endpoint (`/health`)
- Restart persistence (sessions, cron, config)
- WebSocket protocol handlers (golden trace tests)
- OpenAI-compatible HTTP endpoints (`/v1/chat/completions`, `/v1/responses`)
- Config loading, defaults, and validation
- Interactive CLI chat REPL (`cara chat`)

Known gaps:

- Control UI frontend (backend wired, no frontend built/bundled yet)
- Telegram is webhook-only (no long-polling; requires a tunnel or public endpoint for inbound)
- Signal, Slack channels (not yet smoke-tested in real environments)
- Public internet deployments (TLS/mTLS, reverse proxy, auth hardening)

## Install

### Prebuilt binaries

Download from the [latest release](https://github.com/puremachinery/carapace/releases):

- `cara-x86_64-linux`
- `cara-aarch64-linux`
- `cara-x86_64-darwin`
- `cara-aarch64-darwin`
- `cara-x86_64-windows.exe`

Release binaries include Sigstore signatures and certificates (`.sig` + `.pem`).
You can verify with cosign:

```bash
cosign verify-blob \
  --certificate cara-x86_64-linux.pem \
  --signature cara-x86_64-linux.sig \
  --certificate-identity-regexp "https://github.com/puremachinery/carapace/.github/workflows/release.yml@refs/tags/v.*" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  cara-x86_64-linux
```

### Build from source (current)

```bash
cargo build --release
./target/release/cara --help
```

### Install (macOS/Linux, manual)

Make it executable and move it into your PATH:

```bash
chmod +x cara-x86_64-linux
sudo mv cara-x86_64-linux /usr/local/bin/cara
```

### Install (Windows, manual)

Copy the binary into a folder on your PATH:

```powershell
$installDir = "$env:LOCALAPPDATA\\cara\\bin"
New-Item -ItemType Directory -Force -Path $installDir | Out-Null
Copy-Item .\\cara-x86_64-windows.exe (Join-Path $installDir "cara.exe")
```

### Install helper (macOS/Linux)

If you cloned the repo, the install script copies the binary into place:

```bash
sudo ./scripts/install.sh --binary ./cara-x86_64-linux
```

If you downloaded a release binary, use the manual steps above.

### Install helper (Windows PowerShell)

If you cloned the repo, the install script copies the binary into place:

```powershell
.\scripts\install.ps1 -BinaryPath .\cara-x86_64-windows.exe
```

If you downloaded a release binary, use the manual steps above.

## Getting Started

### First run (setup wizard)

1. Create a minimal config interactively:
   ```bash
   cara setup
   ```

2. Start Carapace:
   ```bash
   cara
   ```

3. Check status:
   ```bash
   cara status --host 127.0.0.1 --port 18789
   ```

4. Verify your first-run outcome:
   ```bash
   cara verify --outcome local-chat --port 18789
   ```

5. Open a local interactive chat session:
   ```bash
   cara chat
   ```
   Use `/help` for a list of REPL commands:
   - `/new` — start a fresh session
   - `/exit` or `/quit` — exit chat

### With Ollama (free, local)

1. [Install Ollama](https://ollama.com) and pull a model:
   ```bash
   ollama pull llama3.2
   ```

2. Run cara:
   ```bash
   OLLAMA_BASE_URL=http://localhost:11434 cara
   ```

3. Connect a channel (Signal/Telegram/Discord/Slack/webhooks) or enable the
   Control UI — see `docs/channels.md` and `docs/getting-started.md`.

### With a cloud provider

Set one API key and run:

```bash
export ANTHROPIC_API_KEY="sk-ant-..."   # or OPENAI_API_KEY, GOOGLE_API_KEY, VENICE_API_KEY
cara
```

Then connect a channel or enable the Control UI — see `docs/channels.md` and
`docs/getting-started.md`.

### Other local servers (vLLM, llama.cpp, LM Studio, MLX)

Any OpenAI-compatible server works — point the OpenAI provider at it.
HTTP is allowed for loopback addresses (`localhost` / `127.0.0.1` / `::1`).

```bash
# vLLM
OPENAI_BASE_URL=http://localhost:8000/v1 OPENAI_API_KEY=unused cara

# llama.cpp server (llama-server --port 8080)
OPENAI_BASE_URL=http://localhost:8080/v1 OPENAI_API_KEY=unused cara

# LM Studio (default port 1234)
OPENAI_BASE_URL=http://localhost:1234/v1 OPENAI_API_KEY=unused cara

# MLX (default port 8080)
OPENAI_BASE_URL=http://localhost:8080/v1 OPENAI_API_KEY=unused cara
```

You can also use the Ollama provider with non-Ollama servers that expose an
OpenAI-compatible `/v1/chat/completions` endpoint:

```bash
OLLAMA_BASE_URL=http://localhost:8000 cara
```

Or configure via `config.json5` — see [`config.example.json5`](config.example.json5)
for the `openai` and `ollama` provider sections.

### Channels

Setup guides for Signal, Telegram, Discord, and Slack (including inbound
webhooks and service configuration) live in:

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
SIGNAL_CLI_URL=http://localhost:8080 SIGNAL_PHONE_NUMBER=+15551234567 cara
```

Or via `config.json5` — see `config.example.json5` for the `signal` section.

## Contributing

If you want to build from source or contribute, start here:

- [CONTRIBUTING.md](CONTRIBUTING.md)
- [docs/README.md](docs/README.md)

## License

Apache-2.0 — see [LICENSE](LICENSE).
