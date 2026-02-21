# carapace

> **Under active development.** Kicking the tires is welcome, but don't expect everything to work yet.

A security-focused, open-source personal AI assistant. Runs on your machine. Works through Signal, Telegram, Discord, Slack, webhooks, and console. Supports Anthropic, OpenAI, Ollama, Gemini, Bedrock, and Venice AI. Extensible via WASM plugins. Written in Rust.

A hardened alternative to openclaw / clawdbot — for when your assistant needs a hard shell.

## Features

- **Multi-provider LLM engine** — Anthropic, OpenAI, Ollama, Google Gemini, AWS Bedrock, Venice AI with streaming, tool dispatch, and cancellation
- **Multi-channel messaging** — Signal, Telegram, Discord, Slack, console, and webhooks. 10 built-in tools + 15 channel-specific tool schemas
- **Signed plugin runtime** — plugins are signature-verified and run with strict permissions and resource limits
- **Secure defaults** — local-first binding, locked-down auth behavior, encrypted secret storage, guarded tool execution, and OS-level subprocess sandboxing for protected paths
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

Carapace is designed to address the major vulnerability classes reported in the January 2026 openclaw security disclosures:

| Threat | Carapace defense |
|---|---|
| Unauthenticated access | Denied by default when credentials configured; CSRF-protected control endpoints |
| Exposed network ports | Localhost-only binding (127.0.0.1) |
| Plaintext secret storage | OS credential store (Keychain / Keyutils / Credential Manager) with AES-256-GCM fallback |
| Skills supply chain | Ed25519 signatures + WASM capability sandbox + resource limits |
| Prompt injection | Prompt guard + inbound classifier + exec approval flow + tool policies |
| No process sandboxing | OS-level subprocess sandboxing on macOS/Linux/Windows for sandbox-required paths; unsupported paths fail closed |
| SSRF / DNS rebinding | Private IP blocking + post-resolution validation |

See [docs/security.md](docs/security.md) for the full security model.
See [docs/security-comparison.md](docs/security-comparison.md) for a threat-by-threat comparison with OpenClaw.
See [docs/feature-status.yaml](docs/feature-status.yaml) and [docs/feature-evidence.yaml](docs/feature-evidence.yaml) for verified-vs-partial implementation status.

## Quick Start

1. Install `cara` from the latest release (Linux/macOS/Windows):
   - <https://getcara.io/install>
   - [docs/site/install.md](docs/site/install.md)
2. Run guided setup:
   ```bash
   cara setup
   ```
3. Start the assistant:
   ```bash
   cara
   ```
4. Verify first-run outcome:
   ```bash
   cara verify --outcome auto --port 18789
   ```
5. Start local interactive chat:
   ```bash
   cara chat
   ```

Use `/help` in chat for REPL commands (`/new`, `/exit`, `/quit`).

If you use cloud models, set one provider key before launching (for example
`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GOOGLE_API_KEY`, or `VENICE_API_KEY`).

## Status (Preview)

This project is in preview. Core paths are tested and verified, but expect gaps.

- Working now: setup wizard, local chat (`cara chat`), token auth enforcement,
  health/control endpoints, and OpenAI-compatible HTTP endpoints.
- In progress: Control UI frontend (backend is wired), broader channel smoke
  evidence, and hardened internet-facing deployment guidance.

See [docs/feature-status.yaml](docs/feature-status.yaml) and
[docs/feature-evidence.yaml](docs/feature-evidence.yaml) for the current source
of truth.

## Roadmap

- [Roadmap](docs/roadmap.md) — what we're building now, next, and later
- Up next: long-running assistant MVP, Control UI frontend, and stable release gate
- Recently shipped: cross-platform subprocess sandboxing, guided setup
  (`cara setup`), and first-run verifier (`cara verify`)

## Docs

- [Website](https://getcara.io) — install, first run, security, ops, cookbook, troubleshooting
- [Getting started](docs/getting-started.md) — full setup and operations
- [Install](docs/site/install.md) — release binaries, signatures, and install commands
- [First run](docs/site/first-run.md) — secure local startup and smoke checks
- [Security model](docs/security.md) — architecture and trust boundaries
- [Security comparison](docs/security-comparison.md) — threat-by-threat view
- [Channel setup](docs/channels.md) — Signal, Telegram, Discord, Slack, webhooks
- [Channel smoke validation](docs/channel-smoke.md) — live checks and evidence capture
- [Cookbook](docs/cookbook/README.md) — outcome-first walkthroughs
- [Roadmap](docs/roadmap.md) — near-term and longer-term priorities
- [CLI guide](docs/cli.md) — subcommands, flags, and device identity
- [Documentation index](docs/README.md) — architecture/protocol/security references
- [Report feedback or bugs](https://github.com/puremachinery/carapace/issues/new/choose)

## Contributing

If you want to build from source or contribute, start here:

- [CONTRIBUTING.md](CONTRIBUTING.md)
- [docs/README.md](docs/README.md)

## License

Apache-2.0 — see [LICENSE](LICENSE).
