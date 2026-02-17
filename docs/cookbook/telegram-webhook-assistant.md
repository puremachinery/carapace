# Add Carapace to Telegram (webhook mode)

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

```json5
{
  "gateway": {
    "bind": "all",
    "port": 18789
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

## 3) Verify

1. Send a message to your bot in Telegram.
2. Confirm Carapace receives it and returns a reply.

## Common failures and fixes

- Symptom: Telegram webhook set succeeds, but inbound messages do not arrive.
  - Fix: Verify public HTTPS reachability to `/channels/telegram/webhook`.
- Symptom: Inbound requests return unauthorized/ignored.
  - Fix: Ensure `webhookSecret` matches Telegram `secret_token`.
- Symptom: Telegram shows webhook error status.
  - Fix: Check `getWebhookInfo` last error message and Carapace logs.

## Note

Current Telegram inbound support is webhook-based. Local-only inbound without a
public webhook requires long-polling support, which is planned.
