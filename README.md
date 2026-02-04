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
| Plaintext secret storage | AES-256-GCM encryption at rest with PBKDF2 key derivation |
| Skills supply chain | Ed25519 signatures + WASM capability sandbox + resource limits |
| Prompt injection | Prompt guard + inbound classifier + exec approval flow + tool policies |
| No process sandboxing | Seatbelt / Landlock / rlimits primitives implemented; subprocess wiring in progress |
| SSRF / DNS rebinding | Private IP blocking + post-resolution validation |

See [docs/security.md](docs/security.md) for the full security model.

## Docs

- [Getting started](docs/getting-started.md) — install, first run, and ops
- [Channel setup](docs/channels.md) — Signal, Telegram, Discord, Slack, webhooks
- [CLI guide](docs/cli.md) — subcommands, flags, and device identity
- [Documentation index](docs/README.md) — architecture, protocol, security

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

### Install (macOS/Linux)

Make it executable and move it into your PATH:

```bash
chmod +x carapace-x86_64-linux
sudo mv carapace-x86_64-linux /usr/local/bin/carapace
```

Optional: create a `cara` alias (macOS/Linux):

```bash
sudo ln -sf /usr/local/bin/carapace /usr/local/bin/cara
```

### Install (Windows)

Copy the binary into a folder on your PATH:

```powershell
$installDir = "$env:LOCALAPPDATA\\carapace\\bin"
New-Item -ItemType Directory -Force -Path $installDir | Out-Null
Copy-Item .\\carapace-x86_64-windows.exe (Join-Path $installDir "carapace.exe")
```

Optional: create a `cara` alias:

```powershell
'@echo off
"%~dp0carapace.exe" %*
' | Set-Content -Encoding ASCII -Path (Join-Path $installDir "cara.cmd")
```

### Install helper (macOS/Linux)

If you cloned the repo, the install script copies the binary and creates a
`cara` symlink (use `--no-cara` to skip the alias):

```bash
sudo ./scripts/install.sh --binary ./carapace-x86_64-linux
```

If you downloaded only the release binary, use the manual steps above.

### Install helper (Windows PowerShell)

If you cloned the repo, the install script copies the binary and creates a
`cara.cmd` shim (use `-NoCara` to skip the alias):

```powershell
.\scripts\install.ps1 -BinaryPath .\carapace-x86_64-windows.exe
```

If you downloaded only the release binary, use the manual steps above.

## Getting Started

### First run (setup wizard)

1. Create a minimal config interactively:
   ```bash
   carapace setup
   ```

2. Start the gateway:
   ```bash
   carapace
   ```

3. Check status:
   ```bash
   carapace status --host 127.0.0.1 --port 18789
   ```

### With Ollama (free, local)

1. [Install Ollama](https://ollama.com) and pull a model:
   ```bash
   ollama pull llama3.2
   ```

2. Run carapace:
   ```bash
   OLLAMA_BASE_URL=http://localhost:11434 carapace
   ```

3. Connect a channel (Signal/Telegram/Discord/Slack/webhooks) or enable the
   Control UI — see `docs/channels.md` and `docs/getting-started.md`.

### With a cloud provider

Set one API key and run:

```bash
export ANTHROPIC_API_KEY="sk-ant-..."   # or OPENAI_API_KEY, GOOGLE_API_KEY, VENICE_API_KEY
carapace
```

Then connect a channel or enable the Control UI — see `docs/channels.md` and
`docs/getting-started.md`.

### Other local servers (vLLM, llama.cpp, LM Studio, MLX)

Any OpenAI-compatible server works — point the OpenAI provider at it.
HTTP is allowed for loopback addresses (`localhost` / `127.0.0.1` / `::1`).

```bash
# vLLM
OPENAI_BASE_URL=http://localhost:8000/v1 OPENAI_API_KEY=unused carapace

# llama.cpp server (llama-server --port 8080)
OPENAI_BASE_URL=http://localhost:8080/v1 OPENAI_API_KEY=unused carapace

# LM Studio (default port 1234)
OPENAI_BASE_URL=http://localhost:1234/v1 OPENAI_API_KEY=unused carapace

# MLX (default port 8080)
OPENAI_BASE_URL=http://localhost:8080/v1 OPENAI_API_KEY=unused carapace
```

You can also use the Ollama provider with non-Ollama servers that expose an
OpenAI-compatible `/v1/chat/completions` endpoint:

```bash
OLLAMA_BASE_URL=http://localhost:8000 carapace
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
SIGNAL_CLI_URL=http://localhost:8080 SIGNAL_PHONE_NUMBER=+15551234567 carapace
```

Or via `config.json5` — see `config.example.json5` for the `signal` section.

## Contributing

If you want to build from source or contribute, start here:

- [CONTRIBUTING.md](CONTRIBUTING.md)
- [docs/README.md](docs/README.md)

## License

MIT — see [LICENSE](LICENSE).
