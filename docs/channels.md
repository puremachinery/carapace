# Channel Setup

This guide explains how to configure inbound/outbound messaging for Matrix,
Signal, Telegram, Discord, and Slack. It focuses on Carapace service wiring and
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
- Channel activity features are configured under `channels.defaults.features.*`
  and `channels.<channel>.features.*`.
- Today those channel-specific activity settings are implemented for built-in
  native channels; external/plugin channel entries may be ignored until plugin
  channel activity capabilities are added.
- Configure typing indicators with `channels.defaults.features.typing` or
  `channels.<channel>.features.typing`.

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

For non-loopback Signal deployments, set `signal.baseUrl` to `https://...`.
Carapace rejects non-HTTPS non-loopback Signal URLs.

When the sender has phone-number privacy enabled, Signal delivers a
`sourceUuid` instead of a `sourceNumber`. Carapace falls back to the UUID
as the sender identifier in that case.

When `channels.signal.features.typing.enabled` is true, Carapace refreshes the
Signal typing indicator while the assistant is generating a reply and clears it
before outbound delivery.
When `channels.signal.features.readReceipts.enabled` is true, Carapace polls
Signal with `send_read_receipts=false` and only sends a read receipt after the
inbound message is durably appended to Carapace's session/history store. This
happens before any LLM response is generated or delivered. If the append fails,
Carapace leaves the message unread. Unsupported Signal messages that Carapace
does not ingest today, including group messages and non-text messages, also
remain unread while this feature is enabled. When the feature is disabled,
Signal keeps its normal auto-read-receipt behavior.

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
cara verify --outcome matrix --port 18789 --matrix-to "<room_id>"
```

Notes:
- Discord/Telegram send-path verification sends a real test message to the
  destination you provide.
- Matrix verification checks daemon/runtime/control wiring and, when
  `--matrix-to` is supplied, sends a real Matrix test message to that room.
- `cara verify` currently targets local loopback (`127.0.0.1`).
- For reproducible live checks and evidence capture, use
  [Channel Smoke Validation](channel-smoke.md).

## Matrix / Element

Matrix support is a native stateful channel, not a webhook adapter. Carapace
owns the Matrix SDK client, login/session restore, sync loop, invite decisions,
device verification state, encrypted SQLite store, and outbound queue.

This implementation is pinned to `matrix-sdk` 0.14.x with
`default-features = false` and `e2e-encryption`, `sqlite`, and `rustls-tls`.
The current 0.16.x SDK line was checked during this work but overflows the
current Rust compiler query-depth limit while compiling `matrix-sdk`; revisit
the pin when the SDK or toolchain resolves that compiler failure.

```json5
{
  "matrix": {
    "enabled": true,
    "homeserverUrl": "https://matrix.example.com",
    "userId": "@cara:example.com",
    "password": "${MATRIX_PASSWORD}",        // first login only when token is not yet stored
    // "accessToken": "${MATRIX_ACCESS_TOKEN}",
    // "deviceId": "${MATRIX_DEVICE_ID}",
    // "storePassphrase": "${MATRIX_STORE_PASSPHRASE}",
    "encrypted": true,
    "autoJoin": {
      "allowUsers": ["@alice:example.com"],
      "allowServerNames": ["example.org"]
    }
  }
}
```

`matrix.encrypted` defaults to `true`. Encrypted Matrix rooms require
password-protected local state because Carapace owns the Matrix device keys,
cross-signing keys, and room session keys. This is different from Signal, where
crypto state is owned by `signal-cli-rest-api` outside Carapace.

Set `MATRIX_STORE_PASSPHRASE` to pin the Matrix store key directly. Otherwise
Carapace derives the Matrix store key from `CARAPACE_CONFIG_PASSWORD` and a
local `{state_dir}/installation_id`. Before rotating
`CARAPACE_CONFIG_PASSWORD`, stop the daemon and run
`cara matrix rekey-store --new` while the old password is still available. The
command rewraps the Matrix SDK SQLite store cipher records with a fresh random
passphrase and writes that passphrase to an owner-only
`{state_dir}/matrix/store_passphrase` file, so future starts no longer depend
on the old config password for Matrix store access. Stores configured with an
explicit `MATRIX_STORE_PASSPHRASE` / `matrix.storePassphrase` are rotated
outside Carapace.

The CLI refuses to run `rekey-store --new` while it sees a live carapace
daemon (PID file at `{state_dir}/daemon.pid` resolves to a running process);
stop the daemon first.

**If `cara matrix rekey-store --new` is interrupted** (machine power loss,
operator Ctrl-C between phases), the rotation leaves
`{state_dir}/matrix/store_passphrase.pending` and
`{state_dir}/matrix/rekey-marker` on disk without the final
`store_passphrase`. The carapace daemon refuses to start in this state with a
`StartupFailed: interrupted Matrix store rekey detected` error. Recovery is
idempotent: with the daemon stopped, re-run `cara matrix rekey-store --new`
and the CLI will detect the in-flight rotation, advance any per-store ciphers
that were left behind, promote `store_passphrase.pending` to
`store_passphrase`, and remove the marker. Do **not** delete these files
manually — that would strand the encrypted SDK store with no decryptable
passphrase.

Cross-signing bootstrap requires the Matrix account password (UIA) at least
once even when `accessToken` is in use; provide `matrix.password` /
`MATRIX_PASSWORD` for that bootstrap. After cross-signing is set up and the
recovery key is captured (`cara matrix recovery-key show`), the password is
no longer needed.

`cara matrix recovery-key restore` stages the restored key on disk; restart
the daemon for the new key to take effect.

With `matrix.encrypted=false`, Carapace only supports unencrypted rooms. It
refuses encrypted invites; if a joined room later becomes encrypted, Carapace
marks the room unsupported in channel status and stops inbound/outbound
processing for that room.

Auto-join allowlists are fail-closed: an empty allowlist rejects all invites.
`allowUsers` matches full Matrix user IDs. `allowServerNames` matches the server
part or a suffix such as `example.org` matching `chat.example.org`.

Useful Matrix commands:

```bash
cara matrix devices
cara matrix verifications
cara matrix verify '@alice:example.org' DEVICEID
cara matrix accept <flow_id>
cara matrix confirm <flow_id> --match
cara matrix confirm <flow_id> --no-match
cara matrix cancel <flow_id>
cara matrix recovery-key show
cara matrix recovery-key restore --key-file ./matrix-recovery-key.txt
printf '%s\n' '<recovery-key>' | cara matrix recovery-key restore
```

### SAS verification flow (the comparison step)

Matrix uses Short Authentication String (SAS) verification: both sides
display the same emoji or decimal sequence and the operator confirms
they match. The bot stores the SAS payload locally so the operator can
inspect it before confirming.

A flow's `state` field walks the following progression. `cara matrix
confirm --match` requires `Accepted` or `KeysExchanged`; earlier states
return `409 VerificationFlowNotReady`.

| State | Meaning |
|-------|---------|
| `Created` | Flow object exists locally but no protocol message has been exchanged. |
| `Requested` | The peer asked us to verify; we have not yet accepted. |
| `Ready` | Both sides agreed to verify but SAS has not started. |
| `Started` | SAS protocol has begun; emoji/decimals not yet computed. |
| `Accepted` | SAS values are computed and ready for the human to compare. |
| `KeysExchanged` | Same — keys are exchanged, peer is awaiting our match decision. |
| `Confirmed` | Local side has run `confirm --match`; awaiting peer confirmation. |
| `Done` | Both sides confirmed; the flow has succeeded. |
| `Cancelled` | Flow was cancelled (by either side or by timeout). |
| `Mismatched` | Operator ran `confirm --no-match`; the flow is invalid. |
| `Transitioned` | Flow has moved into a SAS sub-state; refresh to see the SAS view. |

The full flow is:

1. **Trigger or accept the request.** Either side can initiate; the
   bot accepts the partner's request via `cara matrix accept <flow_id>`,
   or initiates with `cara matrix verify <user> [device]`. The accept
   response carries any SAS data already exchanged inline (the
   `verification.sas` field on the response object) so you don't have
   to race the next refresh sync.
2. **Read the SAS payload.** Run `cara matrix verifications` to list
   pending flows. Each entry includes a `sas` field with `emoji`
   (array of `{symbol, description}`) and `decimals` (three numbers).
   Compare these against what your peer's Matrix client (Element,
   Cinny, etc.) is showing for the same flow.
3. **Confirm the match.** If the values match, run `cara matrix confirm
   <flow_id> --match`. If they do not, run `--no-match` and the flow
   transitions to `Mismatched` — investigate before retrying because a
   mismatch usually indicates a MITM attempt or a desynchronized peer.

`cara matrix confirm --match` refuses to call into the SDK unless the
bot has captured SAS data for the flow. This prevents an operator from
blind-confirming a verification without ever seeing the comparison
values, which would defeat the entire MITM-resistance the SAS step
provides.

If `cara matrix accept` succeeds before SAS is ready, the response still
returns the updated verification record; run `cara matrix verifications` until
the `sas` field appears, then compare and confirm. `cara matrix confirm
--match` returns `VerificationFlowNotReady` if the daemon has not captured SAS
data for that flow yet.

## Environment Variables

All channel config can be supplied via environment variables:

- `MATRIX_HOMESERVER_URL`, `MATRIX_USER_ID`, `MATRIX_ACCESS_TOKEN`,
  `MATRIX_PASSWORD`, `MATRIX_DEVICE_ID`, `MATRIX_STORE_PASSPHRASE`
- `SIGNAL_CLI_URL`, `SIGNAL_PHONE_NUMBER`
- `TELEGRAM_BOT_TOKEN`, `TELEGRAM_WEBHOOK_SECRET`, `TELEGRAM_BASE_URL`
- `DISCORD_BOT_TOKEN`, `DISCORD_BASE_URL`, `DISCORD_GATEWAY_URL`, `DISCORD_GATEWAY_INTENTS`
- `SLACK_BOT_TOKEN`, `SLACK_SIGNING_SECRET`, `SLACK_BASE_URL`

## Inbound Session Routing

Inbound messages create (or reuse) a scoped session key based on channel +
sender + peer ID. Responses are delivered back through the channel pipeline.
