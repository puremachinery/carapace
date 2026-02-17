# Expose hooks safely for automation

## Outcome

Enable Carapace hooks endpoints with dedicated hooks auth, then trigger wake/agent
actions from external automation.

## Prerequisites

- `cara` installed.
- `ANTHROPIC_API_KEY` or `OPENAI_API_KEY`.
- `curl`.

## 1) Create config

Generate dedicated tokens:

```bash
export CARAPACE_GATEWAY_TOKEN="$(openssl rand -hex 32)"
export CARAPACE_HOOKS_TOKEN="$(openssl rand -hex 32)"
```

Windows (PowerShell) alternative:

```powershell
$bytes = [byte[]]::new(32)
[System.Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
$env:CARAPACE_GATEWAY_TOKEN = [System.BitConverter]::ToString($bytes).Replace('-', '').ToLower()

$bytes = [byte[]]::new(32)
[System.Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
$env:CARAPACE_HOOKS_TOKEN = [System.BitConverter]::ToString($bytes).Replace('-', '').ToLower()
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
    },
    "hooks": {
      "enabled": true,
      "token": "${CARAPACE_HOOKS_TOKEN}",
      "path": "/hooks"
    }
  },
  "anthropic": {
    "apiKey": "${ANTHROPIC_API_KEY}"
  }
}
```

## 2) Run commands

```bash
CARAPACE_CONFIG_PATH=./carapace.json5 cara
```

Trigger wake:

```bash
curl -sS \
  -H "Authorization: Bearer ${CARAPACE_HOOKS_TOKEN}" \
  -H "Content-Type: application/json" \
  -X POST http://127.0.0.1:18789/hooks/wake \
  -d '{"text":"wake now","mode":"now"}'
```

Dispatch agent:

```bash
curl -sS \
  -H "Authorization: Bearer ${CARAPACE_HOOKS_TOKEN}" \
  -H "Content-Type: application/json" \
  -X POST http://127.0.0.1:18789/hooks/agent \
  -d '{"message":"Summarize the latest system status in one paragraph."}'
```

## 3) Verify

- `/hooks/wake` returns `{"ok":true,...}`.
- `/hooks/agent` returns `{"ok":true,"runId":"..."}`.
- Using service token for hooks fails, proving token separation works.

## Common failures and fixes

- Symptom: `401 Unauthorized`.
  - Fix: Use `CARAPACE_HOOKS_TOKEN` for hooks endpoints, not service auth token.
- Symptom: `404 Not Found` for hooks path.
  - Fix: Confirm `gateway.hooks.enabled=true` and `gateway.hooks.path` matches URL.
- Symptom: `400` payload errors.
  - Fix: Send JSON body and required fields (`text` for wake, `message` for agent).
