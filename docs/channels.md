# Channel Setup

This guide explains how to configure inbound/outbound messaging for Signal,
Telegram, Discord, and Slack. It focuses on Carapace service wiring and
the minimum external setup needed to make each channel usable.

For step-by-step channel onboarding recipes, see the
[Cookbook](cookbook/README.md).
For real-world validation criteria and evidence capture, see
[Channel Smoke Validation](channel-smoke.md).

All examples assume `carapace.json5` (see `config.example.json5`) and the default
service HTTP port 18789. Adjust paths/ports for your deployment.

## Common Notes

- Webhook-based inbound modes require a public HTTPS URL (for example, Telegram
  webhook mode and Slack Events API). Polling/Gateway modes (Signal polling,
  Telegram polling fallback, Discord Gateway) do not require a public webhook
  endpoint.
- If you are behind a reverse proxy, ensure it forwards to Carapace and
  preserves the request body.
- Secrets are encrypted at rest when config encryption is enabled.
- Channel tools (agent actions) are available when `session.metadata.channel`
  is set for the conversation.
- Signal’s REST API defaults to port 8080; this is separate from the Carapace port.

## Signal (signal-cli-rest-api)

Signal uses a polling loop against the local `signal-cli-rest-api` container.
Inbound messages are delivered by polling `GET /v1/receive/{number}`.

1) Start signal-cli-rest-api:

```bash
docker run -d -p 8080:8080 -v $HOME/.local/share/signal-api:/home/.local/share/signal-cli \
  -e MODE=native bbernhard/signal-cli-rest-api
```

2) Configure Carapace:

```json5
{
  "signal": {
    "baseUrl": "http://localhost:8080",
    "phoneNumber": "+15551234567"
  }
}
```

For non-loopback Signal deployments, set `signal.baseUrl` to `https://...`.
Carapace rejects non-HTTPS non-loopback Signal URLs.

## Telegram (Bot API + Webhook or Polling)

Telegram uses the Bot API for outbound delivery. Inbound can run in either mode:

- **Webhook mode** (recommended for public deployments): set
  `telegram.webhookSecret`, expose `/channels/telegram/webhook` over HTTPS, and
  configure Telegram to send `X-Telegram-Bot-Api-Secret-Token`.
- **Long-polling fallback** (default for local/private setups): if
  `telegram.webhookSecret` is unset, Carapace automatically uses `getUpdates`
  polling for inbound messages (no public webhook required). On startup,
  Carapace also makes a best-effort `deleteWebhook` call so polling is not
  starved by a previously registered webhook.

1) Create a Telegram bot token (via BotFather).
2) Configure Carapace:

```json5
{
  "telegram": {
    "botToken": "${TELEGRAM_BOT_TOKEN}",
    // webhookSecret: "${TELEGRAM_WEBHOOK_SECRET}" // optional; enables webhook mode
  }
}
```

3) Optional webhook setup (if using webhook mode):

```
https://YOUR_HOST/channels/telegram/webhook
```

Inbound webhook requests are rejected if the configured secret is missing or
does not match.

## Slack (Web API + Events API)

Slack uses the Web API for outbound delivery and the Events API for inbound
messages.

1) Create a Slack app, install it to your workspace, and obtain a bot token
   (`xoxb-...`).
2) Enable **Events API** and set the request URL to:

```
https://YOUR_HOST/channels/slack/events
```

3) Configure the Slack signing secret in Carapace:

```json5
{
  "slack": {
    "botToken": "${SLACK_BOT_TOKEN}",
    "signingSecret": "${SLACK_SIGNING_SECRET}"
  }
}
```

Carapace validates `X-Slack-Request-Timestamp` and `X-Slack-Signature`.
Slack’s `url_verification` handshake is supported.

## Discord (REST + Gateway)

Discord uses the REST API for outbound delivery and the Discord Gateway WebSocket for
inbound messages.

1) Create a Discord application and bot token.
2) Enable the **Message Content Intent** if you want access to full message
   content in guilds.
3) Configure Carapace:

```json5
{
  "discord": {
    "botToken": "${DISCORD_BOT_TOKEN}",
    "gatewayEnabled": true,
    "gatewayIntents": 37377 // includes MESSAGE_CONTENT by default
  }
}
```

Carapace connects to Discord and dispatches `MESSAGE_CREATE` events into
the agent pipeline.

## Verify Channel Wiring

After configuring a channel, validate from another terminal while Carapace is
running:

```bash
cara verify --outcome discord --port 18789 --discord-to "<channel_id>"
cara verify --outcome telegram --port 18789 --telegram-to "<chat_id>"
```

Notes:
- Discord/Telegram send-path verification sends a real test message to the
  destination you provide.
- `cara verify` currently targets local loopback (`127.0.0.1`).
- For reproducible live checks and evidence capture, use
  [Channel Smoke Validation](channel-smoke.md).

## Environment Variables

All channel config can be supplied via environment variables:

- `SIGNAL_CLI_URL`, `SIGNAL_PHONE_NUMBER`
- `TELEGRAM_BOT_TOKEN`, `TELEGRAM_WEBHOOK_SECRET`, `TELEGRAM_BASE_URL`
- `DISCORD_BOT_TOKEN`, `DISCORD_BASE_URL`, `DISCORD_GATEWAY_URL`, `DISCORD_GATEWAY_INTENTS`
- `SLACK_BOT_TOKEN`, `SLACK_SIGNING_SECRET`, `SLACK_BASE_URL`

## Inbound Session Routing

Inbound messages create (or reuse) a scoped session key based on channel +
sender + peer ID. Responses are delivered back through the channel pipeline.
