# Add Carapace to Discord

## Outcome

Connect Carapace to Discord so inbound messages can trigger agent responses.

## Prerequisites

- `cara` installed.
- `ANTHROPIC_API_KEY` or `OPENAI_API_KEY`.
- Discord bot token (`DISCORD_BOT_TOKEN`).
- Discord bot added to your server.
- Message Content Intent enabled in the Discord developer portal.

## 1) Create config

Generate a gateway token:

```bash
export CARAPACE_GATEWAY_TOKEN="$(openssl rand -hex 32)"
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
  "anthropic": {
    "apiKey": "${ANTHROPIC_API_KEY}"
  },
  "discord": {
    "botToken": "${DISCORD_BOT_TOKEN}",
    "gatewayEnabled": true,
    "gatewayIntents": 37377
  }
}
```

If using OpenAI, swap the provider block:

```json5
"openai": {
  "apiKey": "${OPENAI_API_KEY}"
}
```

## 2) Run commands

```bash
CARAPACE_CONFIG_PATH=./carapace.json5 cara
```

Optional status check:

```bash
cara status --host 127.0.0.1 --port 18789
curl -H "Authorization: Bearer ${CARAPACE_GATEWAY_TOKEN}" http://127.0.0.1:18789/health
```

## 3) Verify

1. Send a message in a Discord channel where the bot is present.
2. Confirm Carapace receives it and sends a reply.

## Common failures and fixes

- Symptom: Bot sends messages but does not react to inbound messages.
  - Fix: Enable Message Content Intent and re-invite bot with correct scopes/intents.
- Symptom: No outbound responses at all.
  - Fix: Confirm `DISCORD_BOT_TOKEN` is valid and provider API key is configured.
- Symptom: Service starts but Discord remains disconnected.
  - Fix: Check logs for Discord gateway/auth errors and verify network egress to Discord.
