# Add Carapace to Telegram

## Outcome

Connect Carapace to Telegram for inbound and outbound bot messaging using a
webhook endpoint.

## Prerequisites

- `cara` installed.
- `ANTHROPIC_API_KEY` or `OPENAI_API_KEY`.
- Telegram bot token from BotFather (`TELEGRAM_BOT_TOKEN`).
- Public HTTPS URL that can reach your Carapace server.
- Webhook secret token (`TELEGRAM_WEBHOOK_SECRET`).

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

```json5
{
  "gateway": {
    "bind": "all",          // exposes port to the network — keep auth enabled
    "port": 18789,
    "auth": {
      "mode": "token",
      "token": "${CARAPACE_GATEWAY_TOKEN}"
    }
  },
  "anthropic": {
    "apiKey": "${ANTHROPIC_API_KEY}"
  },
  "telegram": {
    "botToken": "${TELEGRAM_BOT_TOKEN}",
    "webhookSecret": "${TELEGRAM_WEBHOOK_SECRET}"
  }
}
```

## 2) Run commands

Start Carapace:

```bash
CARAPACE_CONFIG_PATH=./carapace.json5 cara
```

Optional local auth check:

```bash
curl -H "Authorization: Bearer ${CARAPACE_GATEWAY_TOKEN}" http://127.0.0.1:18789/health
```

Register webhook with Telegram:

```bash
curl -sS \
  -X POST "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/setWebhook" \
  -d "url=https://YOUR_PUBLIC_HOST/channels/telegram/webhook" \
  -d "secret_token=${TELEGRAM_WEBHOOK_SECRET}"
```

Check webhook status:

```bash
curl -sS "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/getWebhookInfo"
```

Optional built-in verifier (credential checks; send-path is optional):

```bash
cara verify --outcome telegram --port 18789
```

For full send-path verification, rerun with `--telegram-to YOUR_CHAT_ID`.

## 3) Verify

1. Send a message to your bot in Telegram.
2. Confirm Carapace receives it and returns a reply.
3. `getWebhookInfo` shows no delivery errors.
4. If you ran `cara verify`, confirm Telegram checks report PASS/SKIP (SKIP is expected when no `--telegram-to` is provided).

## Next step

- [Trigger Cara from other apps](hooks-safe-automation.md)
- [Day-2 ops](../site/ops.md)

## Common failures and fixes

- Symptom: Telegram webhook set succeeds, but inbound messages do not arrive.
  - Fix: Verify public HTTPS reachability to `/channels/telegram/webhook`.
- Symptom: Inbound requests return unauthorized/ignored.
  - Fix: Ensure `webhookSecret` matches Telegram `secret_token`.
- Symptom: Local status or health checks return `401 Unauthorized`.
  - Fix: Use `Authorization: Bearer ${CARAPACE_GATEWAY_TOKEN}` and confirm it matches `gateway.auth.token`.
- Symptom: Telegram shows webhook error status.
  - Fix: Check `getWebhookInfo` last error message and Carapace logs.

## Note

This recipe is webhook-based. For local-only inbound without a public webhook,
Carapace also supports Telegram long-polling mode when `telegram.webhookSecret`
is unset.
When `gateway.bind` is `all`, keep `gateway.auth` enabled and use a strong token.
