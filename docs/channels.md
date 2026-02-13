# Channels Setup

This guide explains how to configure inbound/outbound messaging for Signal,
Telegram, Discord, and Slack. It focuses on the *carapace* gateway wiring and
the minimum external setup needed to make each channel usable.

All examples assume `carapace.json5` (see `config.example.json5`) and the default
gateway HTTP port 18789. Adjust paths/ports for your deployment.

## Common Notes

- Inbound webhooks require a public HTTPS URL. If you are behind a reverse
  proxy, ensure it forwards to the gateway and preserves the request body.
- Secrets are encrypted at rest when config encryption is enabled.
- Channel tools (agent actions) are available when `session.metadata.channel`
  is set for the conversation.
- Signal’s REST API defaults to port 8080; this is separate from the gateway port.

## Signal (signal-cli-rest-api)

Signal uses a polling loop against the local `signal-cli-rest-api` container.
Inbound messages are delivered by polling `GET /v1/receive/{number}`.

1) Start signal-cli-rest-api:

```bash
docker run -d -p 8080:8080 -v $HOME/.local/share/signal-api:/home/.local/share/signal-cli \
  -e MODE=native bbernhard/signal-cli-rest-api
```

2) Configure carapace:

```json5
{
  "signal": {
    "baseUrl": "http://localhost:8080",
    "phoneNumber": "+15551234567"
  }
}
```

Implementation references:
- `src/channels/signal_receive.rs`
- `src/main.rs::spawn_signal_receive_loop_if_configured`

## Telegram (Bot API + Webhook)

Telegram uses the Bot API for outbound delivery and a webhook for inbound
messages.

1) Create a Telegram bot token (via BotFather).
2) Configure carapace:

```json5
{
  "telegram": {
    "botToken": "${TELEGRAM_BOT_TOKEN}",
    "webhookSecret": "${TELEGRAM_WEBHOOK_SECRET}" // required for inbound webhooks
  }
}
```

3) Set the webhook URL on Telegram to:

```
https://YOUR_HOST/channels/telegram/webhook
```

Configure Telegram to send `X-Telegram-Bot-Api-Secret-Token` with the same
value. Inbound webhooks are rejected if the secret is missing or does not
match.

Implementation references:
- `src/server/http.rs::telegram_webhook_handler`
- `src/channels/telegram_inbound.rs`

## Slack (Web API + Events API)

Slack uses the Web API for outbound delivery and the Events API for inbound
messages.

1) Create a Slack app, install it to your workspace, and obtain a bot token
   (`xoxb-...`).
2) Enable **Events API** and set the request URL to:

```
https://YOUR_HOST/channels/slack/events
```

3) Configure the Slack signing secret in carapace:

```json5
{
  "slack": {
    "botToken": "${SLACK_BOT_TOKEN}",
    "signingSecret": "${SLACK_SIGNING_SECRET}"
  }
}
```

The gateway validates `X-Slack-Request-Timestamp` and `X-Slack-Signature`.
Slack’s `url_verification` handshake is supported.

Implementation references:
- `src/server/http.rs::slack_events_handler`
- `src/channels/slack_inbound.rs`

## Discord (REST + Gateway)

Discord uses the REST API for outbound delivery and the Gateway WebSocket for
inbound messages.

1) Create a Discord application and bot token.
2) Enable the **Message Content Intent** if you want access to full message
   content in guilds.
3) Configure carapace:

```json5
{
  "discord": {
    "botToken": "${DISCORD_BOT_TOKEN}",
    "gatewayEnabled": true,
    "gatewayIntents": 37377 // includes MESSAGE_CONTENT by default
  }
}
```

The gateway connects to Discord and dispatches `MESSAGE_CREATE` events into
the agent pipeline.

Implementation references:
- `src/channels/discord_gateway.rs`
- `src/main.rs::spawn_discord_gateway_loop_if_configured`

## WhatsApp (WhatsApp Web Protocol)

WhatsApp uses the unofficial WhatsApp Web protocol via the `whatsapp-rust`
library (based on whatsmeow and Baileys). This provides end-to-end encrypted
messaging without requiring a business API account.

### Current Implementation Status

> **Note**: WhatsApp channel support is fully implemented. The following table shows the supported features:

| Feature | Status |
|---------|--------|
| Text messages (send/receive) | Implemented |
| Images (send/receive) | Implemented |
| Videos (send/receive) | Implemented |
| Audio/voice messages (send/receive) | Implemented |
| Documents (send/receive) | Implemented |
| Stickers (send/receive) | Implemented |
| Location messages | Implemented |
| Contact messages (vCard) | Implemented |
| Poll messages | Implemented |
| List messages (interactive) | Implemented |
| Button messages | Implemented |
| Message replies/quotes | Implemented |
| Message reactions | Implemented |
| Message editing | Implemented |
| Message deletion | Implemented |
| Read/delivery receipts | Implemented |
| Typing indicators | Implemented |
| Group chats | Implemented |
| Group management (create, leave, add/remove participants) | Implemented |
| QR code authentication | Implemented |
| Pair code authentication | Implemented |
| Presence (online/offline) | Implemented |
| Blocking | Implemented |

### Authentication Options

1. **QR Code (default)**: Scan a QR code from your WhatsApp mobile app
2. **Pair Code**: Link using your phone number and a verification code

### Configuration

```json5
{
  "whatsapp": {
    "phoneNumber": "+15551234567",     // E.164 format for pair code auth
    "usePairCode": false,               // set true to use pair code instead of QR
    "sessionPath": "~/.config/carapace/whatsapp_session.db",
    "enabled": true
  }
}
```

### Planned Features

The whatsapp-rust library supports the following capabilities that will be
integrated:

- **Messaging**:
  - End-to-end encrypted messages (Signal Protocol)
  - One-on-one and group chats
  - Message editing and reactions
  - Quoting/replying to messages
  - Delivery, read, and played receipts

- **Media**:
  - Upload and download images, videos, documents, GIFs, and audio
  - Automatic encryption and decryption

- **Contacts & Groups**:
  - Check if phone numbers are on WhatsApp
  - Fetch profile pictures and user info
  - Query group metadata and participants
  - List all groups you're participating in

- **Presence & Chat State**:
  - Set online/offline presence
  - Typing indicators (composing, recording, paused)
  - Block and unblock contacts

### Security Considerations

> **Warning**: This is an unofficial implementation using the WhatsApp Web
> protocol. Using custom WhatsApp clients may violate Meta's Terms of Service
> and could result in account suspension. Use at your own risk.

- Session data is stored locally and encrypted at rest
- End-to-end encryption is preserved (Signal Protocol)
- Credentials are stored in the system keychain when available

Implementation references:
- `src/channels/whatsapp.rs`
- Uses: `whatsapp-rust` crate (v0.2+)

## Environment Variables

All channel config can be supplied via environment variables:

- `SIGNAL_CLI_URL`, `SIGNAL_PHONE_NUMBER`
- `TELEGRAM_BOT_TOKEN`, `TELEGRAM_WEBHOOK_SECRET`, `TELEGRAM_BASE_URL`
- `DISCORD_BOT_TOKEN`, `DISCORD_BASE_URL`, `DISCORD_GATEWAY_URL`, `DISCORD_GATEWAY_INTENTS`
- `SLACK_BOT_TOKEN`, `SLACK_SIGNING_SECRET`, `SLACK_BASE_URL`
- `WHATSAPP_PHONE_NUMBER`, `WHATSAPP_USE_PAIR_CODE`, `WHATSAPP_SESSION_PATH`

## Inbound Session Routing

Inbound messages create (or reuse) a scoped session key based on channel +
sender + peer ID. Responses are delivered back through the channel pipeline.

Implementation references:
- `src/channels/inbound.rs`
- `src/sessions/mod.rs::get_or_create_scoped_session`
