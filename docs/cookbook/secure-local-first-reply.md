# 5-minute secure local setup + first reply

## Outcome

Run Carapace locally with token auth enabled, verify health, and send your first
message in `cara chat`.

## Prerequisites

- `cara` installed and on your PATH.
- One provider API key available:
  - `ANTHROPIC_API_KEY` or
  - `OPENAI_API_KEY`

## 1) Create config

Generate a gateway token:

```bash
export CARAPACE_GATEWAY_TOKEN="$(openssl rand -hex 32)"
```

Windows (PowerShell) alternative:

```powershell
$bytes = [byte[]]::new(32)
[System.Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
$env:CARAPACE_GATEWAY_TOKEN = [System.BitConverter]::ToString($bytes).Replace('-', '').ToLower()
```

Create `carapace.json5`:

```json5
{
  "gateway": {
    "bind": "loopback",
    "port": 18789,
    "auth": {
      "mode": "token",
      "token": "${CARAPACE_GATEWAY_TOKEN}"
    }
  },
  "anthropic": {
    "apiKey": "${ANTHROPIC_API_KEY}"
  }
}
```

If you use OpenAI instead, replace the provider block with:

```json5
"openai": {
  "apiKey": "${OPENAI_API_KEY}"
}
```

## 2) Run commands

Start Carapace:

```bash
CARAPACE_CONFIG_PATH=./carapace.json5 cara
```

In another terminal:

```bash
cara status --port 18789
curl -H "Authorization: Bearer ${CARAPACE_GATEWAY_TOKEN}" http://127.0.0.1:18789/health
cara chat
```

Optional built-in verifier:

```bash
cara verify --outcome local-chat --port 18789
```

## 3) Verify

- `cara status` reports healthy.
- `/health` returns JSON with `status: "ok"`.
- `cara chat` opens an interactive REPL and returns a model response.
- `cara verify --outcome local-chat` reports PASS.

## Next step

- [Connect VS Code, chat UIs, or scripts](openai-compatible-endpoint.md)
- [Add Discord](discord-assistant.md) or [Telegram](telegram-webhook-assistant.md)

## Common failures and fixes

- Symptom: `401 Unauthorized` from `/health`.
  - Fix: Confirm `Authorization: Bearer ...` matches `gateway.auth.token`.
- Symptom: `No provider is currently available` in chat.
  - Fix: Confirm your provider API key env var is set in the same shell.
- Symptom: Connection refused on port `18789`.
  - Fix: Ensure Carapace is running and the config port matches your status/chat commands.
