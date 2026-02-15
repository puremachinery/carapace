# Getting Started

This guide covers first‑run setup, security basics, and day‑to‑day operations.
It’s intentionally practical: copy/paste steps, then customize.

## Prerequisites

- A `cara` binary on your PATH (from GitHub Releases)
- A supported LLM provider API key (OpenAI/Anthropic/etc), or Ollama
- Optional: TLS certs if exposing the gateway publicly

If you want to build from source, see [CONTRIBUTING.md](../CONTRIBUTING.md).

## Quick Start (Local, Token Auth)

1) Generate a gateway token:

```bash
export CARAPACE_GATEWAY_TOKEN="$(openssl rand -hex 32)"
```

2) Create a minimal config (save as `carapace.json5`):

```json5
{
  "gateway": {
    "auth": { "mode": "token", "token": "${CARAPACE_GATEWAY_TOKEN}" }
  },
  "openai": {
    "apiKey": "${OPENAI_API_KEY}"
  }
}
```

3) Run the gateway:

```bash
CARAPACE_CONFIG_PATH=./carapace.json5 cara
```

4) Verify:

```bash
cara status --host 127.0.0.1 --port 18789
```

Or:

```bash
curl -H "Authorization: Bearer ${CARAPACE_GATEWAY_TOKEN}" http://localhost:18789/health
```

Expected response:

```json
{ "status": "ok", "version": "x.y.z", "uptimeSeconds": 12 }
```

If you set `gateway.port`, use that port instead of `18789`.

5) Open a local interactive chat REPL:

```bash
cara chat
```

Helpful REPL commands:
- `/help` — show available commands
- `/new` — start a fresh chat session
- `/exit` or `/quit` — leave chat

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

- Use gateway auth (`gateway.auth.mode = token` or `password`).
- Use TLS if the gateway is reachable outside localhost.
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

1) Keep the gateway on localhost or a private network.
2) Forward `/` to the gateway.
3) Preserve request headers.
4) Set `gateway.trustedProxies` to your proxy IPs so local‑direct detection
   works correctly.

## Hooks (Web API)

Hooks are separate from gateway auth and require a hooks token.

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

Then visit `/ui` on the gateway host.
You can override the base path via `gateway.controlUi.basePath`.

## Operations

### Health Checks

- `GET /health` – liveness
- `GET /health/ready` – readiness (storage + provider reachability)

### Logs

Use the CLI:

```bash
cara logs --follow
```

### Backups

```bash
cara backup --out ./carapace-backup.tar.gz
cara restore --path ./carapace-backup.tar.gz
```

### Update

```bash
cara update
```

## Troubleshooting

- **401 Unauthorized**: check gateway token or hooks token.
- **403 Forbidden**: CSRF or Origin failure for Control UI endpoints.
- **LLM requests fail**: verify provider key and model name.
- **No replies**: ensure an LLM provider is configured; check `/health/ready`.

If unsure, start with `RUST_LOG=debug` and inspect logs.
