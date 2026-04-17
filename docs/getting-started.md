# Getting Started

Carapace is a security-focused personal AI assistant that runs locally and
connects through Signal, Telegram, Discord, Slack, webhooks, or console.

This guide covers first‑run setup, security basics, and day‑to‑day operations.
It’s intentionally practical: copy/paste steps, then customize.

If you prefer outcome-first walkthroughs (for example "add Discord"), see
the [Cookbook](cookbook/README.md).
If you want the website flow instead of Markdown docs, start at
<https://getcara.io>:
- <https://getcara.io/install.html>
- <https://getcara.io/first-run.html>
- <https://getcara.io/security.html>
- <https://getcara.io/ops.html>
- <https://getcara.io/get-unstuck.html>

## Prerequisites

- A `cara` binary on your PATH
- A supported LLM provider API key (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`,
  `GOOGLE_API_KEY`, or `VENICE_API_KEY`), local Ollama, or a local Claude CLI
- For Gemini Google sign-in: `GOOGLE_OAUTH_CLIENT_ID` and `GOOGLE_OAUTH_CLIENT_SECRET`
  available in the shell running `cara setup`, or supplied through the Control UI onboarding form
- For Gemini Google sign-in: `CARAPACE_CONFIG_PASSWORD`
- Optional: TLS certs if exposing Carapace publicly

Install options:
- Prebuilt binaries + signature/checksum verification:
  [docs/site/install.md](site/install.md)
- Source build: [CONTRIBUTING.md](../CONTRIBUTING.md)

## Recommended first path

If you are starting from zero, optimize for a fast verified first outcome:

- Choose `local-chat` first unless you already know you need a channel on day 1.
- Fastest cloud start: set `ANTHROPIC_API_KEY` or `OPENAI_API_KEY` and configure
  a qualified `provider:model` default (e.g. `anthropic:claude-sonnet-4-6`).
- Fastest fully local start: run Ollama and point Carapace at `OLLAMA_BASE_URL`,
  or use an installed Claude CLI via `claude-cli:` routing.
- If you want a guarded local workspace assistant, start with the
  [guarded local project assistant recipe](cookbook/guarded-local-project-assistant.md)
  after your first successful local-chat verify.
- Add Discord, Telegram, or hooks only after `cara verify --outcome auto` passes.

If you are still unsure which path fits your environment, use the
[Providers hub](site/providers.md) or [Help page](site/help.md).

## Quick Start (Recommended: setup wizard)

Run the interactive setup:

```bash
cara setup
```

Or skip the provider menu explicitly by choosing one provider:

```bash
# Choose ONE of these commands:
cara setup --provider ollama
cara setup --provider gemini --auth-mode api-key
cara setup --provider gemini --auth-mode oauth
```

To use the local Claude CLI provider, configure it directly in
`carapace.json5` using `claude-cli:<model>` in `agents.defaults.model`
or a specific agent's `model` field. The setup wizard does not currently
expose Claude CLI as a `--provider` option.

### Migrating from another tool?

If you already have provider keys configured in OpenClaw, OpenCode, Aider, or
NemoClaw, import them instead of re-entering manually:

```bash
cara import openclaw   # from ~/.openclaw/
cara import opencode   # from ~/.opencode.json
cara import aider      # from ~/.aider.conf.yml + .env
cara import nemoclaw   # from ~/.nemoclaw/config.json
```

Import shows a preview of what will be mapped and asks for confirmation before
writing. Run `cara verify` afterward to validate the imported setup works.

`--auth-mode oauth` is interactive-only in the CLI. It launches a Google
sign-in flow and completes through a loopback callback on a local port. The Control UI exposes
the same Gemini onboarding choices if you prefer to do it in the browser.
Gemini Google sign-in requires `CARAPACE_CONFIG_PASSWORD`.

Then start Carapace:

```bash
cara
```

In another terminal:

```bash
cara verify --outcome auto --port 18789
cara verify --outcome autonomy --port 18789
cara status --port 18789
cara chat --port 18789
```

The setup wizard asks for:
- which model provider you want to use,
- how locked down you want access to be,
- whether to keep the service local-only or reachable on your network,
- your first desired outcome (`local-chat`, `discord`, `telegram`, or `hooks`).

If you picked a custom port in setup, use that instead of `18789`.
If your selected outcome is `discord` or `telegram`, `cara verify` may also
need destination flags (`--discord-to` / `--telegram-to`).
`cara verify --outcome autonomy` submits a real durable task and verifies it
starts and reaches `done`/`blocked`.

Helpful REPL commands:
- `/help` — show available commands
- `/new` — start a fresh chat session
- `/exit` or `/quit` — leave chat

For full first-run flow, use [site/first-run.md](site/first-run.md).
Manual configuration is documented in `config.example.json5`.

## Need guided help?

- [Guided setup help](site/help.md#guided-setup-help)
- [Team setup / pilot request](site/help.md#team-setup-and-pilot-request)
- [Request a cookbook recipe](https://github.com/puremachinery/carapace/issues/new?template=cookbook-recipe-request.yml&title=cookbook%3A+%3Cuse+case%3E)

## Configuration Basics

If you just want a working first run, you can skip this section and come back later.

Config is JSON5 and can live in:
- `${CARAPACE_CONFIG_PATH}` (highest priority)
- `${CARAPACE_STATE_DIR}/carapace.json5`
- `~/.config/carapace/carapace.json5` (Linux)
- `~/Library/Application Support/carapace/carapace.json5` (macOS)
- `%APPDATA%\\carapace\\carapace.json5` (Windows)

See `config.example.json5` and `docs/protocol/config.md` for all keys.

### Secrets at Rest

If `CARAPACE_CONFIG_PASSWORD` is set, secrets at known paths are encrypted
at rest (AES‑256‑GCM). If the password is missing or wrong at startup,
encrypted values are replaced with empty strings in the loaded config (the
on-disk file is not modified).

### Session Encryption at Rest

Session history and metadata can be encrypted at rest via
`sessions.encryption.mode`. When enabled with `CARAPACE_CONFIG_PASSWORD`,
sessions are AES‑256‑GCM encrypted with `.crypto-manifest` recovery
metadata. There is no in-place rekey — changing the password requires a
fresh encrypted session store. See `docs/protocol/config-reference.md` for
mode options.

### Named Execution Routes

Instead of repeating `provider:model` strings across agents, define named
routes once under the top-level `routes` map and reference them by name:

```json5
{
  "routes": {
    "fast":   { "model": "gemini:gemini-2.5-flash" },
    "strong": { "model": "anthropic:claude-opus-4-6" }
  },
  "agents": {
    "defaults": { "route": "fast" }
  }
}
```

See the [named routes cookbook recipe](cookbook/named-routes-multi-model.md)
for a full walkthrough.

## Security Baseline

Minimum recommendations:

- Do **not** expose hooks (`/hooks/*`) without a hooks token.
- Use service auth (`gateway.auth.mode = token` or `password`).
- Use TLS if Carapace is reachable outside localhost.
- Rotate tokens if the state directory is exposed.

### Auth Modes

```json5
"gateway": {
  "auth": {
    "mode": "token",   // or "password" or "none"
    "token": "..."
  }
}
```

`mode = none` is **localhost only**; remote requests are denied.

## Control UI

Enable the Control UI:

```json5
{
  "gateway": {
    "controlUi": { "enabled": true }
  }
}
```

Then visit `/ui` on the Carapace host.
You can override the base path via `gateway.controlUi.basePath`.
If you are modifying the frontend assets, rebuild with `./scripts/build-control-ui.sh`.

## Hooks (Web API)

Hooks let external systems send messages through Carapace — useful for CI/CD
notifications, monitoring alerts, or custom integrations. They are separate
from service auth and require their own token.

```json5
{
  "gateway": {
    "hooks": {
      "enabled": true,
      "token": "${CARAPACE_HOOKS_TOKEN}"
    }
  }
}
```

See `docs/protocol/http.md` for request/response shapes.

## Running Behind a Reverse Proxy

If you terminate TLS in a reverse proxy:

1) Keep Carapace on localhost or a private network.
2) Forward `/` to Carapace.
3) Preserve request headers.
4) Set `gateway.trustedProxies` to your proxy IPs so local‑direct detection
   works correctly.

## Operations
Use the dedicated ops guide for day-2 workflows:
- [site/ops.md](site/ops.md)
- [site/get-unstuck.md](site/get-unstuck.md)

Most common commands:

```bash
cara status --port 18789
cara logs -n 200
cara backup --output ./carapace-backup.tar.gz
cara update
```

`cara logs` prints the last N log lines; it does not stream continuously.

## Troubleshooting

- **401 Unauthorized**: check auth token or hooks token.
- **403 Forbidden**: CSRF or Origin failure for Control UI endpoints.
- **LLM requests fail**: verify the selected provider credentials (API key or
  auth profile) and model name.
- **No replies**: ensure an LLM provider is configured; check `/health/ready`.

If unsure, start with `RUST_LOG=debug` and inspect logs.
For a structured checklist, use [site/get-unstuck.md](site/get-unstuck.md).
