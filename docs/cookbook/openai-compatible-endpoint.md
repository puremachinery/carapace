# Use Carapace as a local OpenAI-compatible endpoint

## Outcome

Expose `/v1/chat/completions` and `/v1/responses` on your local Carapace service
and call them with standard OpenAI-style HTTP requests.

## Prerequisites

- `cara` installed.
- `ANTHROPIC_API_KEY` or `OPENAI_API_KEY`.
- `curl` or an OpenAI-compatible client.

## 1) Create config

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

## 2) Run commands

```bash
export CARAPACE_GATEWAY_TOKEN="$(openssl rand -hex 32)"
CARAPACE_CONFIG_PATH=./carapace.json5 cara
```

Call chat completions:

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

Call responses:

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

## 3) Verify

- Both endpoints return `200` JSON responses with assistant output.
- Unauthorized calls return `401`, confirming auth is enforced.

## Common failures and fixes

- Symptom: `404` on `/v1/chat/completions` or `/v1/responses`.
  - Fix: Ensure `gateway.openai.chatCompletions` / `gateway.openai.responses` are enabled.
- Symptom: `401 Unauthorized`.
  - Fix: Confirm bearer token matches `gateway.auth.token`.
- Symptom: `500` provider error.
  - Fix: Verify provider key/model config and check server logs for upstream API errors.
