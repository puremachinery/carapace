# Use Cara with VS Code, JetBrains, chat UIs, and scripts

## Outcome

Run Cara locally with OpenAI-style endpoints enabled, then connect:

- VS Code / JetBrains (via Continue)
- Open WebUI
- LibreChat
- Scripts and automations (`curl`)

## Prerequisites

- `cara` installed.
- `ANTHROPIC_API_KEY` or `OPENAI_API_KEY`.
- Optional client app: Continue, Open WebUI, or LibreChat.

## 1) Create config

Export a gateway token:

```bash
export CARAPACE_GATEWAY_TOKEN="$(openssl rand -hex 32)"
```

Windows (PowerShell) alternative:

```powershell
$bytes = [byte[]]::new(32)
[System.Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
$env:CARAPACE_GATEWAY_TOKEN = [System.BitConverter]::ToString($bytes).Replace('-', '').ToLower()
```

```json5
{
  "gateway": {
    "bind": "loopback",
    "port": 18789,
    "auth": {
      "mode": "token",
      "token": "${CARAPACE_GATEWAY_TOKEN}"
    },
    "openai": {
      "chatCompletions": true,
      "responses": true
    }
  },
  "anthropic": {
    "apiKey": "${ANTHROPIC_API_KEY}"
  }
}
```

## 2) Start Cara

```bash
CARAPACE_CONFIG_PATH=./carapace.json5 cara
```

## 3) Connect your app

Use these values in your app's model/provider settings:

- Provider type: `OpenAI` / `OpenAI-compatible`
- Base URL: `http://127.0.0.1:18789/v1`
- API key/token: same value as `CARAPACE_GATEWAY_TOKEN`
- Model: `carapace` (this is the fixed model name Cara exposes; the actual backend model is determined by your provider config)

### VS Code / JetBrains (Continue)

In Continue model/provider settings, point the model to the values above.

### Open WebUI / LibreChat

Add a custom OpenAI-compatible connection and use the same values above.
Field names vary by UI, but the required pieces are always: base URL, API key,
and model.

## 4) Script smoke test (`curl`)

Chat Completions:

```bash
curl -sS \
  -H "Authorization: Bearer ${CARAPACE_GATEWAY_TOKEN}" \
  -H "Content-Type: application/json" \
  -X POST http://127.0.0.1:18789/v1/chat/completions \
  -d '{
    "model": "carapace",
    "messages": [
      {"role":"user","content":"Say hello in one sentence."}
    ]
  }'
```

Responses:

```bash
curl -sS \
  -H "Authorization: Bearer ${CARAPACE_GATEWAY_TOKEN}" \
  -H "Content-Type: application/json" \
  -X POST http://127.0.0.1:18789/v1/responses \
  -d '{
    "model": "carapace",
    "input": "List three secure defaults for a local AI assistant."
  }'
```

## 5) Verify

- Your client app returns assistant output through Cara.
- `curl` calls return `200` JSON responses with assistant output.
- Unauthorized calls return `401` (auth enforcement working).

## Next step

- [Trigger Cara from other apps](hooks-safe-automation.md)
- [Add Discord](discord-assistant.md) or [Telegram](telegram-webhook-assistant.md)

## Common failures and fixes

- Symptom: `404` on `/v1/chat/completions` or `/v1/responses`.
  - Fix: Ensure `gateway.openai.chatCompletions` / `gateway.openai.responses` are enabled.
- Symptom: app says endpoint not found.
  - Fix: Confirm base URL is `http://127.0.0.1:18789/v1` (include `/v1`).
- Symptom: `401 Unauthorized`.
  - Fix: Confirm bearer token matches `gateway.auth.token`.
- Symptom: `500` provider error.
  - Fix: Verify provider key/model config and check logs with `cara logs -n 200`.
- Symptom: app on another device cannot connect.
  - Fix: This recipe is local-only (`127.0.0.1`). If you need remote access, use
    a LAN/Tailnet setup with TLS and auth hardening.
