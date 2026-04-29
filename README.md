# carapace

> **Stable release available.** Carapace is ready for real use on its verified stable paths; partial and in-progress areas are called out explicitly in the docs.

A security-focused, open-source personal AI assistant. Runs on your machine. Works through Signal, Telegram, Discord, Slack, webhooks, and console. Supports Anthropic, OpenAI, Codex, Ollama, Gemini, Vertex AI, Bedrock, and Venice AI. Extensible via WASM plugins and guarded filesystem tools. Written in Rust.

A hardened alternative to openclaw / clawdbot — for when your assistant needs a hard shell.

## Features

- **Multi-provider LLM engine** — Anthropic, OpenAI API key, Codex subscription login, Ollama, Google Gemini, Vertex AI, AWS Bedrock, and Venice AI with streaming, tool dispatch, and cancellation
- **Multi-channel messaging** — Signal, Telegram, Discord, Slack, console, and webhooks
- **Channel activity framework** — per-channel typing indicators and append-time read receipts, with Signal as the first activity-enabled built-in channel
- **Tooling and local workspace access** — built-in agent tools, guarded filesystem tools for explicit roots, and channel-specific tool schemas
- **Signed plugin runtime** — plugins are signature-verified and run with strict permissions and resource limits
- **Secure defaults** — local-first binding, locked-down auth behavior, encrypted secret storage, guarded tool execution, root-scoped filesystem access, and OS-level subprocess sandboxing for protected paths
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

If you use cloud models, finish one provider onboarding path before launching:
set one provider key (for example `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`,
`GOOGLE_API_KEY`, or `VENICE_API_KEY`), use Codex sign-in through
`cara setup --provider codex` or the Control UI, or use Gemini Google sign-in
through `cara setup --provider gemini --auth-mode oauth` or the Control UI.
Codex and Gemini Google sign-in both require `CARAPACE_CONFIG_PASSWORD` so the
stored auth profile stays encrypted at rest.
If you are not sure where to start, choose `local-chat` as your first outcome,
start with one provider, and add channels only after `cara verify --outcome auto`
passes.
If you want Cara to inspect one local project directory, enable the
`filesystem` block for a single workspace root and start with the
[guarded local project assistant recipe](docs/cookbook/guarded-local-project-assistant.md).

## Roadmap

Active and planned work is tracked on
[GitHub Issues](https://github.com/puremachinery/carapace/issues).
The [feature inventory](docs/feature-status.yaml) is the source of truth for
what currently ships.

Recently shipped: long-running assistant MVP (durable queue + autonomy
verify), cross-platform subprocess sandboxing, guided setup
(`cara setup`), first-run verifier (`cara verify`), Gemini onboarding
(Google sign-in or API key via CLI and Control UI), Codex onboarding
(OpenAI subscription login via CLI and Control UI), Vertex AI provider
support, per-channel activity features with Signal typing indicators and
append-time read receipts, guarded filesystem tools for explicit workspace
roots, named execution routes, and session encryption at rest.

## Docs

- [Website](https://getcara.io) — install, first run, security, ops, cookbook, troubleshooting
- [Getting started](docs/getting-started.md) — full setup and operations
- [Install](docs/site/install.md) — release binaries, signatures, and install commands
- [First run](docs/site/first-run.md) — secure local startup and smoke checks
- [Help](docs/site/help.md) — setup help, team evaluation, and cookbook request paths
- [Security model](docs/security.md) — architecture and trust boundaries
- [Security comparison](docs/security-comparison.md) — threat-by-threat view
- [Channel setup](docs/channels.md) — Signal, Telegram, Discord, Slack, webhooks
- [Channel smoke validation](docs/channel-smoke.md) — live checks and evidence capture
- [Cookbook](docs/cookbook/README.md) — outcome-first walkthroughs
- [Release & upgrade policy](docs/release.md) — upgrade, migration, rollback, release checklist
- [CLI guide](docs/cli.md) — subcommands, flags, and device identity
- [Documentation index](docs/README.md) — architecture/protocol/security references
- [Security reporting policy](SECURITY.md) — private vulnerability reporting and response expectations
- [Report feedback or bugs](https://github.com/puremachinery/carapace/issues/new/choose)

## Contributing

If you want to build from source or contribute, start here:

- [CONTRIBUTING.md](CONTRIBUTING.md)
- [docs/README.md](docs/README.md)

## License

Apache-2.0 — see [LICENSE](LICENSE).
