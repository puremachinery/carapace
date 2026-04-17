# Add Carapace to Signal

## Outcome

Connect Carapace to Signal so inbound direct messages trigger agent responses,
with typing indicators and explicit read receipts.

## Prerequisites

- `cara` installed.
- `ANTHROPIC_API_KEY` or another provider API key.
- A running `signal-cli-rest-api` container with a registered phone number.
- Docker installed (to run `signal-cli-rest-api`).

## 1) Start signal-cli-rest-api

```bash
docker run -d -p 8080:8080 \
  -v $HOME/.local/share/signal-api:/home/.local/share/signal-cli \
  -e MODE=native \
  bbernhard/signal-cli-rest-api
```

Register or link your phone number via the signal-cli-rest-api
[documentation](https://github.com/bbernhard/signal-cli-rest-api#getting-started).

## 2) Create config

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
  "agents": {
    "defaults": {
      "model": "anthropic:claude-sonnet-4-6"
    }
  },
  "anthropic": {
    "apiKey": "${ANTHROPIC_API_KEY}"
  },
  "signal": {
    "baseUrl": "http://localhost:8080",
    "phoneNumber": "+15551234567"       // your registered Signal number
  },
  "channels": {
    "signal": {
      "features": {
        "typing": {
          "enabled": true
        },
        "readReceipts": {
          "enabled": true
        }
      }
    }
  }
}
```

Replace `+15551234567` with your actual registered Signal phone number.

For non-loopback Signal API deployments, use `https://` — Carapace rejects
non-HTTPS non-loopback Signal URLs.

## 3) Run commands

```bash
CARAPACE_CONFIG_PATH=./carapace.json5 cara
```

Optional status check:

```bash
cara status --port 18789
curl -H "Authorization: Bearer ${CARAPACE_GATEWAY_TOKEN}" http://127.0.0.1:18789/health
```

## 4) Verify

1. Send a direct message to your Signal number from another device.
2. Confirm Carapace logs show the inbound message.
3. Confirm a typing indicator appears while the assistant generates a reply.
4. Confirm the inbound message is marked as read in Signal at or before the
   assistant reply arrives. (See [channel setup](../channels.md) for the
   exact session-append ordering if you need to debug receipt timing.)
5. Confirm the assistant reply arrives.

For reproducible live checks, use [Channel Smoke Validation](../channel-smoke.md).

## Next step

- [Trigger Cara from other apps](hooks-safe-automation.md)
- [Day-2 ops](../site/ops.md)

## Common failures and fixes

- Symptom: No inbound messages in logs.
  - Fix: Confirm signal-cli-rest-api is running and reachable at the
    configured `baseUrl`. Check that `phoneNumber` matches the registered
    number.
- Symptom: `SSRF validation failed` error.
  - Fix: Use `http://localhost:8080` (loopback) or `https://` for
    non-loopback deployments. Carapace blocks non-HTTPS non-loopback URLs.
- Symptom: Messages arrive but sender shows as UUID instead of phone number.
  - Fix: This is expected when the sender has phone-number privacy enabled.
    Carapace falls back to `sourceUuid` as the sender identifier.
- Symptom: Read receipts not sent.
  - Fix: Confirm `channels.signal.features.readReceipts.enabled` is `true`.
    Unsupported messages (groups, non-text) remain unread by design.
- Symptom: No typing indicator.
  - Fix: Confirm `channels.signal.features.typing.enabled` is `true`.
