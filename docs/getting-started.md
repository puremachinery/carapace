# Getting Started

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
- A supported LLM provider API key (OpenAI/Anthropic/etc), or Ollama
- Optional: TLS certs if exposing Carapace publicly

Install options:
- Prebuilt binaries + signature/checksum verification:
  [docs/site/install.md](site/install.md)
- Source build: [CONTRIBUTING.md](../CONTRIBUTING.md)

## Quick Start (Recommended: setup wizard)

Run the interactive setup:

```bash
cara setup
```

Then start Carapace:

```bash
cara
```

In another terminal:

```bash
cara status --host 127.0.0.1 --port 18789
cara verify --outcome local-chat --port 18789
cara chat --port 18789
```

The setup wizard asks for provider/auth/bind settings, first-run outcome
(`local-chat`, `discord`, `telegram`, `hooks`), and optional hooks/control-ui
configuration.

If you set `gateway.port`, use that port instead of `18789`.

Helpful REPL commands:
- `/help` — show available commands
- `/new` — start a fresh chat session
- `/exit` or `/quit` — leave chat

For full first-run flow, use [site/first-run.md](site/first-run.md).
Manual configuration is documented in `config.example.json5`.

## Configuration Basics

Config is JSON5 and can live in:
- `${CARAPACE_CONFIG_PATH}` (highest priority)
- `${CARAPACE_STATE_DIR}/carapace.json5`
- `~/.config/carapace/carapace.json5` (Linux)
- `~/Library/Application Support/carapace/carapace.json5` (macOS)
- `%APPDATA%\\carapace\\carapace.json5` (Windows)

See `config.example.json5` and `docs/protocol/config.md` for all keys.

### Secrets at Rest

If `CARAPACE_CONFIG_PASSWORD` is set, secrets at known paths are encrypted
at rest (AES‑256‑GCM). If the password is missing or wrong, encrypted values
are scrubbed on load.

## Security Baseline

Minimum recommendations:

- Use service auth (`gateway.auth.mode = token` or `password`).
- Use TLS if Carapace is reachable outside localhost.
- Do **not** expose hooks (`/hooks/*`) without a hooks token.
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

`mode = none` is **local‑direct only** (loopback); remote requests are denied.

## Running Behind a Reverse Proxy

If you terminate TLS in a reverse proxy:

1) Keep Carapace on localhost or a private network.
2) Forward `/` to Carapace.
3) Preserve request headers.
4) Set `gateway.trustedProxies` to your proxy IPs so local‑direct detection
   works correctly.

## Hooks (Web API)

Hooks are separate from service auth and require a hooks token.

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

## Operations
Use the dedicated ops guide for day-2 workflows:
- [site/ops.md](site/ops.md)
- [site/get-unstuck.md](site/get-unstuck.md)

Most common commands:

```bash
cara status --host 127.0.0.1 --port 18789
cara logs --follow
cara backup --out ./carapace-backup.tar.gz
cara update
```

## Troubleshooting

- **401 Unauthorized**: check auth token or hooks token.
- **403 Forbidden**: CSRF or Origin failure for Control UI endpoints.
- **LLM requests fail**: verify provider key and model name.
- **No replies**: ensure an LLM provider is configured; check `/health/ready`.

If unsure, start with `RUST_LOG=debug` and inspect logs.
For a structured checklist, use [site/get-unstuck.md](site/get-unstuck.md).
