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

### Outbound HTTP discipline (operator-relevant)

Every outbound channel client (Telegram / Discord / Slack / Webhook /
Signal / Matrix SDK / TTS) carries an explicit per-request timeout
(30s for blocking send-clients, 60s for the OpenAI TTS async client)
and reads response bodies through size-capped helpers in
`src/net_util.rs`. A hostile or MITM-attacked bot endpoint cannot
hold a delivery thread indefinitely or stream unbounded bytes into
RAM.

URLs are NEVER logged or surfaced in error responses verbatim — every
`reqwest::Error` formatted into operator-visible state strips its
URL via `Error::without_url()`. Matrix homeserver URLs that may
transit `matrix_sdk::Error::Http(reqwest::Error)` Display chains are
caught at the redactor layer (`src/logging/redact.rs::
RE_MATRIX_HOMESERVER_URL`) and replaced with `[REDACTED-MATRIX-URL]`
before reaching log writers or HTTP error bodies. Operators should
not see Telegram bot tokens, OAuth bearer URLs, or Matrix
homeserver paths in any `cara verify` / `cara logs` / control-API
error output.

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

**TLS-backend policy.** The Matrix dependency graph stays on rustls. CI
enforces this via the "Matrix OpenSSL Guard" job, which fails the build
if `openssl`, `openssl-sys`, or `native-tls` appear in the Cargo feature
graph. `openssl-probe` is explicitly allowed because it does not link
OpenSSL itself — it is a small no-OpenSSL utility used by rustls for
locating system CA certificate paths at runtime.

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

Encrypted Matrix state is currently supported on Unix/macOS only. On Windows,
`matrix.encrypted=true` fails closed at Matrix runtime startup because this PR
does not yet implement owner-only ACL enforcement for the Matrix SDK store,
recovery key, installation id, store passphrase, and DLQ files. Use a
Unix/macOS host for encrypted Matrix rooms, or set `matrix.encrypted=false`
only for unencrypted-room operation.

Set `MATRIX_STORE_PASSPHRASE` to pin the Matrix store key directly. Otherwise
Carapace derives the Matrix store key from `CARAPACE_CONFIG_PASSWORD` and a
local `{state_dir}/installation_id`.

### Matrix observability

The Matrix runtime exports Prometheus metrics on the normal `/metrics`
endpoint. These names, labels, and histogram buckets are stable operator-facing
contracts once released:

| Metric | Type | Labels / buckets | Semantics |
| --- | --- | --- | --- |
| `carapace_matrix_inbound_dispatch_failures_total` | counter | `failure_stage="dispatch"` or `"dlq_append"` | Inbound Matrix events that failed agent/session dispatch, and the stricter case where dispatch failed and durable DLQ append also failed. |
| `carapace_matrix_inbound_dlq_lost_event_ids_total` | counter | none | Number of event IDs added to the capped lost-ID forensic surface during DLQ replay cleanup failures. |
| `carapace_matrix_sync_failures_total` | counter | `class="transient"` or `"permanent"` | Sync failures after the runtime classifier decides whether the failure is retryable or terminal. |
| `carapace_matrix_unsupported_inbound_total` | counter | `kind="encrypted_room"`, `"msgtype"`, or `"oversize"` | Peer-controlled inbound Matrix events dropped before dispatch because the room is unsupported, the message type is unsupported, or the text body exceeded the inbound size cap. |
| `carapace_matrix_pending_verifications` | gauge | none | Current daemon-side Matrix verification record count. Updated when verification records change and when channel status metadata is projected. |
| `carapace_matrix_dlq_records` | gauge | none | Matrix inbound DLQ line count sampled during post-sync maintenance only; live counting is disk I/O and is intentionally not on the inbound hot path. |
| `carapace_matrix_outbound_send_duration_seconds` | histogram | buckets `0.05`, `0.1`, `0.25`, `0.5`, `1`, `2.5`, `5`, `10`, `30` | Completed outbound Matrix send attempts. |
| `carapace_matrix_sync_cycle_seconds` | histogram | buckets `1`, `5`, `10`, `30`, `60`, `120`, `300` | Completed Matrix sync cycles, including the Matrix long-poll wait. Backoff sleep before a retry is not part of the cycle duration. |

New Matrix tracing spans and events use the flat target `matrix` so operators
can enable Matrix runtime diagnostics without depending on Rust module paths:

```bash
CARAPACE_LOG=matrix=debug,matrix_sdk=warn cara
```

The flat target covers new Matrix runtime, inbound, DLQ replay, and
verification observability. Older module-path logs still use their Rust module
targets; for those, use a full path directive such as:

```bash
CARAPACE_LOG=carapace::channels::matrix=debug,matrix=debug,matrix_sdk=warn cara
```

Carapace does not rewrite `CARAPACE_LOG` aliases. `matrix=debug` is a stable
operator-facing target for the new observability surface, not a catch-all alias
for every historical Matrix log line.

`ChannelMetadata.last_error` remains a human-readable string for compatibility.
Matrix's typed discriminator is `metadata.extra.lastErrorKind`; automation
should match that field instead of parsing `lastError`.

### Matrix store rekey lifecycle

Before rotating `CARAPACE_CONFIG_PASSWORD`, stop the daemon and run
`cara matrix rekey-store --new` while the old password is still available. The
command rewraps the Matrix SDK SQLite store cipher records with a fresh random
passphrase and writes that passphrase to an owner-only
`{state_dir}/matrix/store_passphrase` file, so future starts no longer depend
on the old config password for Matrix store access. Stores configured with an
explicit `MATRIX_STORE_PASSPHRASE` / `matrix.storePassphrase` are rotated
outside Carapace.

`rekey-store --new` rotates `{state_dir}/matrix/inbound_dlq.jsonl` in the same
transaction when the DLQ is non-empty. It decrypts existing DLQ records with
the old store material, re-encrypts them with the new v2 Argon2id envelope,
and restores the old DLQ file if the SQLite rekey phase fails.

**Full `CARAPACE_CONFIG_PASSWORD` rotation procedure** (config secrets +
Matrix store):

1. **Stop the daemon.** Keep the OLD `CARAPACE_CONFIG_PASSWORD` in the
   environment so the CLI can decrypt the current Matrix store and any pending
   DLQ records.
2. **Rekey the Matrix store and DLQ.** With the daemon stopped and OLD
   `CARAPACE_CONFIG_PASSWORD` still set in the environment, run
   `cara matrix rekey-store --new`. The Matrix store passphrase is
   now decoupled from `CARAPACE_CONFIG_PASSWORD`, and any Matrix inbound DLQ
   records were re-encrypted in the same transaction.
3. **Inventory every config-sealed secret, not just Matrix.** `cara`
   does not expose `config decrypt` / `config seal` commands. If your
   config file contains sealed (`enc:v2:...`) values encrypted under
   the OLD `CARAPACE_CONFIG_PASSWORD`, every such value — Matrix
   credentials AND any provider/integration credentials (e.g.
   `anthropic.apiKey`, `openai.apiKey`, `slack.botToken`,
   `slack.signingSecret`, `telegram.botToken`, plugin-owned secrets) —
   becomes unrecoverable the moment the daemon restarts under the NEW
   `CARAPACE_CONFIG_PASSWORD`. The Matrix-specific guidance below
   covers ONLY the `matrix.*` keys; if your config has non-Matrix
   sealed values, you MUST re-enter each through its own provider /
   setup flow during step 4 or the daemon will start with that
   provider silently broken until the first request lands.

   **Inventory command:** with the daemon stopped, run
   `grep -nE 'enc:v2:' "${CARAPACE_CONFIG_PATH:-$HOME/.config/carapace/carapace.json5}"`
   to list every sealed config path. Anything that isn't matrix.* must
   be replaced via the provider's own setup before step 4 completes,
   or the daemon must be re-restarted with the NEW password AFTER the
   non-Matrix secrets are re-enrolled.

4. **Rotate the Matrix config-sealed secrets.** Keep a backup, temporarily
   restore the OLD password, edit the config so Matrix credentials come
   from env placeholders or direct process env, then restart under the
   NEW password. For Matrix, the supported low-risk path is env-only
   credentials: set `MATRIX_ACCESS_TOKEN`, `MATRIX_PASSWORD`,
   `MATRIX_DEVICE_ID`, and `MATRIX_STORE_PASSPHRASE` as needed in the
   daemon environment and remove only the corresponding plaintext
   secret keys (`matrix.accessToken`, `matrix.password`, and
   `matrix.storePassphrase`) from `carapace.json5`. Keep non-secret
   Matrix identity and routing keys such as `matrix.homeserverUrl`,
   `matrix.userId`, and `matrix.deviceId` unless you are intentionally
   changing the account binding; config values take precedence over
   direct environment fallback for the same field.
5. **Re-enroll non-Matrix sealed secrets BEFORE restarting under the NEW
   password.** Per-provider setup flows are out of scope for this doc;
   consult the channel/provider-specific section for each integration
   you identified in step 3. Verify each non-Matrix integration with a
   smoke probe (e.g. `cara verify --outcome <name>`) after restart so a
   silently-broken provider is surfaced before user traffic lands.
6. **Restart the daemon under the NEW `CARAPACE_CONFIG_PASSWORD`.**

Skipping step 4 leaves Matrix config secrets sealed under the old password.
The Matrix store rotation may have completed, but config-backed credentials can
still fail as revoked or missing auth material after restart because the daemon
cannot unwrap the old sealed config values with the new
`CARAPACE_CONFIG_PASSWORD`. The common `lastErrorKind` values are
[`auth-token-revoked`](#auth-token-revoked),
[`auth-session-user-mismatch`](#auth-session-user-mismatch),
[`auth-session-device-mismatch`](#auth-session-device-mismatch), and
[`missing-store-secret`](#missing-store-secret). Legacy DLQ policy refusals
surface as `legacy-dlq-envelope-refused`; set
`matrix.inboundDlq.legacyEnvelopePolicy` back to `accept` only when you intend
to drain preserved v1 records. The recovery is to restore the
OLD password temporarily and complete the procedure.

Skipping step 5 (the non-Matrix re-enrollment pass) leaves the daemon
running under the NEW password with non-Matrix sealed values it cannot
unwrap. Symptoms vary by provider: missing API keys typically surface
as the provider's own auth-failure shape on the next request, NOT as a
startup error. The recovery is the same as above — restore the OLD
password long enough to re-enter each provider's secret through its
setup flow, then proceed under the NEW password.

The CLI refuses to run `rekey-store --new` while the exclusive
`{state_dir}/.matrix-rekey.lock` maintenance lock is held by the daemon or
another Matrix secret-maintenance command; stop the daemon first.

**If `cara matrix rekey-store --new` is interrupted** (machine power loss,
operator Ctrl-C between phases), the rotation leaves
`{state_dir}/matrix/store_passphrase.pending` and
`{state_dir}/matrix/store_passphrase.rekeying` on disk without the final
`store_passphrase`. The carapace daemon refuses to start in this state with a
`Matrix store rekey interrupted: <pending-path> or <marker-path> present
without <final-path>. Re-run \`cara matrix rekey-store --new\` to advance
or roll back the in-flight rotation before starting the daemon.` error
(visible via `cara status` and on stdout at startup). The operator-grepable
prefix is `Matrix store rekey interrupted:` — the rest of the message is
path evidence + recovery command. Recovery is
idempotent: with the daemon stopped, re-run `cara matrix rekey-store --new`
and the CLI will detect the in-flight rotation, advance any per-store ciphers
that were left behind, promote `store_passphrase.pending` to
`store_passphrase`, and remove the marker. Do **not** delete these files
manually — that would strand the encrypted SDK store with no decryptable
passphrase.

Cross-signing bootstrap requires the Matrix account password (UIA) at least
once even when `accessToken` is in use; provide `matrix.password` /
`MATRIX_PASSWORD` for that bootstrap. After cross-signing is set up and the
recovery key is captured (`cara matrix recovery-key show`), the daemon removes
the persisted password after access-token write-back. Do not remove it manually
while the daemon is running.

Stop the daemon before `cara matrix recovery-key restore`; the command stages
the restored key on disk and the running Matrix runtime will not pick it up
until restart. Use `--key-file <path>` or explicit `--stdin` for piped input.
Recovery-key files (and stdin input) are capped at 4 KiB — well above the
~50-90 ASCII bytes a valid recovery key needs. The daemon enforces the same
4 KiB cap when reading `recovery_key{,.pending,.minting}` from disk. The
CLI-side error string is "refuse to read ...; exceeds 4096 bytes" and the
daemon-side string is "failed to read {label}: exceeds {n} bytes" — both
share the literal token `exceeds 4096 bytes` for log-grep correlation. An
error of this shape from either side usually indicates a wrong path or
stray content (PEM headers, log output, accidental concatenation) rather
than a legitimately oversize key.
Restore can exit non-zero after writing the key if stale
`recovery_key.rotating` or `recovery_key.pending` cleanup fails; treat that as
an operator repair signal, because stale rotation artifacts must not survive
silently and overwrite the restored key on the next daemon start.
Cleanup is journaled at `{state_dir}/matrix/recovery_key.cleanup`: a `started`
journal lists `recovery_key.rotating`, `recovery_key.minting`, and
`recovery_key.pending` plus per-artifact removal results. A healthy cleanup
writes `completed` before removing the journal. If startup sees a `started`,
corrupt, or unsupported cleanup journal, it refuses recovery repair rather than
trusting pending key material without provenance.
`cara matrix recovery-key show --allow-non-terminal` is required when stdout is
redirected intentionally.

`recovery_key.rotating` is JSON when written by current versions:

```json
{
  "stage": "pending_key_written",
  "keySha256": "<new recovery-key sha256>",
  "previousKeySha256": "<previous recovery-key sha256>",
  "updatedAtMs": 1760000000000
}
```

`stage` is one of `started`, `pending_key_written`, or `final_key_replaced`.
Only `pending_key_written` is promotion-capable on restart, and only when the
pending key digest matches `keySha256`, the current key is present, and that
current key still matches `previousKeySha256`. If the current key is missing,
startup refuses promotion with `current_key_missing` and leaves
`recovery_key`, `recovery_key.pending`, and `recovery_key.rotating` untouched
for operator repair. `started` has no new-key digest binding, so a surviving
pending key fails closed. `final_key_replaced` never promotes pending material;
if the current key already matches `keySha256`, startup only clears stale
marker/pending files. Legacy typed JSON may lack `previousKeySha256`; legacy
text markers recorded no digest at all. Both are treated as manual-repair
states rather than blind promotion. Malformed typed JSON is reported separately
from unknown legacy marker bytes as `corrupt_typed_marker`, without logging raw
marker contents, paths, or key digests.

The refusal reason wire values are `missing_previous_key_digest`,
`missing_new_key_digest`, `pending_key_missing`,
`pending_key_digest_mismatch`, `current_key_mismatch`,
`current_key_missing`, `unbound_started_pending`,
`final_stage_pending_present`, and
`legacy_marker_missing_previous_key_digest`. Audit key-state values are
`missing`, `matches_previous_key`, `matches_new_key`, `mismatch`, and
`unknown`.

| Refusal reason | Meaning | Operator action |
| --- | --- | --- |
| `missing_previous_key_digest` | The marker does not bind the original current key. | Inspect `recovery_key.rotating`; restore a known-good current key or remove stale rotation artifacts after confirming no pending rotation is valid. |
| `missing_new_key_digest` | The marker does not bind the pending replacement key. | Treat `recovery_key.pending` as untrusted; restart rotation from a verified recovery key. |
| `pending_key_missing` | The marker expects a pending key file, but it is absent. | Restore the pending key from backup or remove the stale marker after confirming the current key is correct. |
| `pending_key_digest_mismatch` | The pending key does not match the digest recorded in the marker. | Do not promote the pending file; replace it with the expected key or restart rotation. |
| `current_key_mismatch` | The current key exists but does not match the marker's recorded previous digest. | Verify the current key out-of-band before touching pending material; the daemon will not overwrite it. |
| `current_key_missing` | The marker is at `pending_key_written`, but the current key is absent. | Restore the current key first, then restart the daemon; Carapace leaves marker and pending files untouched. |
| `unbound_started_pending` | A `started` marker survived with pending material but no digest binding. | Treat pending material as untrusted and restart rotation from a verified current key. |
| `final_stage_pending_present` | Rotation reached `final_key_replaced`, but stale pending material remains. | Confirm the current key matches the intended new key, then remove the stale pending file and marker. |
| `legacy_marker_missing_previous_key_digest` | A legacy marker lacks the previous-key digest needed for safe promotion. | Use manual recovery: verify the on-disk current key and restart rotation; do not rely on automatic promotion. |

#### DLQ envelope v1 → v2 migration (no operator action)

Existing on-disk Matrix inbound DLQ records encoded under envelope
v1 (HKDF-SHA256-derived keys) continue to decode after upgrading to
the daemon version that introduced envelope v2 (Argon2id-derived
keys). Reads accept either version; new writes always emit v2.
Operators do not need to drain the DLQ before bumping carapace.

The v2 migration improves the DLQ's local-attacker resistance: a
local attacker with read access to `state_dir/matrix/inbound_dlq.jsonl`
plus `state_dir/installation_id` can no longer mount HKDF-fast
offline brute-force on `CARAPACE_CONFIG_PASSWORD` (microseconds per
guess). Argon2id is memory-hard, raising the per-guess cost into
the tens of milliseconds at the daemon's configured parameters. The
state directory is also locked down to `0o700` on Unix as a defense-
in-depth layer.

V1 records are rotated to v2 organically: when the DLQ replay loop
re-encodes a record (after a transient dispatch failure), it always
emits v2. Eventually all on-disk records are v2; the v1 read path
remains in the source for cross-version compatibility within the
supported upgrade window.

Operators who want to refuse legacy DLQ envelopes can set
`matrix.inboundDlq.legacyEnvelopePolicy` to `refuse`. The default is
`accept` so existing v1 records remain replayable after upgrade. Refused v1
records are preserved in the live DLQ rather than silently dropped, allowing
operators to revert the policy to `accept` and drain them deliberately.

With `matrix.encrypted=false`, Carapace only supports unencrypted rooms. It
refuses encrypted invites; if a joined room later becomes encrypted, Carapace
marks the room unsupported in channel status and stops inbound/outbound
processing for that room.

Auto-join allowlists are fail-closed: an empty allowlist rejects all invites.
`allowUsers` matches full Matrix user IDs. `allowServerNames` uses a
label-anchored suffix match on the server part, such as `example.org` matching
`chat.example.org`. It does not do substring matching:
`example.org` does not match `evil-example.org`.

The two lists are **unioned**, not intersected: an invite is admitted if
either the inviter's full user ID appears in `allowUsers` OR the inviter's
server matches a `allowServerNames` entry. Setting both does not narrow
admission — it widens. To restrict to specific users on a specific server,
list those users in `allowUsers` only and leave `allowServerNames` empty.

Useful Matrix commands. Note that `cara matrix verify <user> <device>` (an
interactive cryptographic SAS device verification with a peer) is unrelated
to `cara verify --outcome matrix` (a daemon wiring health check) — the two
share the word "verify" but operate on different surfaces:

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
printf '%s\n' '<recovery-key>' | cara matrix recovery-key restore --stdin
cara matrix recovery-key rotate
```

Without `--key-file` or `--stdin`, `cara matrix recovery-key restore` reads
from a non-echoing terminal prompt. Do not pipe the key through shell history
or scrollback. Stop the daemon before `restore` or `rotate`; rotation abandons
the previous recovery key and writes the new key to the owner-only local file.
If `restore` reports stale cleanup failure after writing the key, leave the
daemon stopped and inspect/remove `recovery_key.rotating` and
`recovery_key.pending` only after confirming the restored `recovery_key` is the
intended current key.

`cara matrix devices` JSON entries carry an optional `rawDeviceIdHex`
field populated only when identifier sanitization altered the
homeserver-original device_id (bidi controls, zero-width chars,
TAG codepoints, ASCII control bytes, Variation Selectors). It is
the **hex encoding** of the original UTF-8 bytes — operator scripts
performing byte-exact SDK lookups decode the hex and use the bytes
directly; humans copy-paste the sanitized `deviceId` and rely on
`cara matrix verify`'s sanitization-equivalence resolver. When a
sanitization collision is reported, pass the hex form explicitly with
`cara matrix verify <user> --device-id-hex <rawDeviceIdHex>` (or
`rawDeviceIdHex` in the control API request) to select the byte-exact
SDK device. Hex
encoding at the wire boundary keeps the JSON terminal-safe even
on adversarial peer entries (raw control bytes never reach
`cara matrix devices` stdout). See
[`docs/protocol/http.md` → GET /control/matrix/devices](protocol/http.md#get-controlmatrixdevices).

### Matrix runtime startup failure modes

`cara verify --outcome matrix` reads the runtime's typed
`lastErrorKind` from `/control/channels` and routes per-variant
operator hints. The full table of `lastErrorKind` values and their
operator actions is documented in
[`docs/protocol/http.md` → `extra.lastErrorKind` (Matrix)](protocol/http.md#extralasterrorkind-matrix).
The most common cases are summarized below; if `cara verify` reports
a kind not listed here, see the protocol doc for the complete list.

<a id="auth-token-revoked"></a>**`auth-token-revoked`** — homeserver
rejected the access token (revoked, account deactivated, locked, or
suspended). For accessToken-configured deployments, mint a new token
and either edit `carapace.json5` while the daemon is stopped or omit
`matrix.accessToken` / `matrix.deviceId` from config and set
`MATRIX_ACCESS_TOKEN` / `MATRIX_DEVICE_ID` in the daemon environment,
then restart. Config values, including env placeholders in config, take
precedence over direct environment fallback. The `matrix.accessToken`
and `matrix.deviceId` runtime config paths are protected and `cara config
set` rejects them. For password-configured deployments, verify the
password is correct and the account is not locked, then restart.

<a id="auth-probe"></a>**`auth-probe`** — `/whoami` validation exhausted its
bounded retry budget without a terminal token-revoked/account-state response.
Treat this as transient homeserver or network reachability; retry after the
control-plane retry window and inspect the runtime log if it persists.

<a id="homeserver-unreachable"></a>**Slow / hung homeserver TLS handshake.**
Daemon startup wraps each SDK HTTP call in a 30-second
`RequestConfig::short_retry().timeout(...)` (see `MATRIX_RUNTIME_OPERATION_TIMEOUT`).
A wedged TLS handshake on the homeserver therefore bounds startup
to roughly `30s × short_retry_budget` (≈90s for the default 3-attempt
budget — `retry_limit=3` in matrix-sdk 0.14.0 yields 3 total attempts,
not 4) rather than hanging forever. If `cara verify --outcome matrix`
reports `auth-probe` or a generic runtime-init timeout AND the
homeserver is reachable via `curl https://<homeserver>/_matrix/client/versions`
but slow, suspect homeserver-side TLS / sync-loop wedging rather
than a Carapace config error. The fall-back operator action is the
same as `auth-probe`: retry after the control-plane retry window
and inspect the runtime log. No file recovery is needed; the daemon
fails the startup probe and surfaces the error rather than holding
the `DaemonPidGuard` open indefinitely.

<a id="encrypted-store-passphrase-mismatch"></a>**`encrypted-store-passphrase-mismatch`**
— the encrypted SQLite store rejected the resolved passphrase.
Check whether `CARAPACE_CONFIG_PASSWORD` changed since the last
successful start, and look for an interrupted rekey at
`{state_dir}/matrix/store_passphrase.{pending,rekeying}`. See
[Matrix store rekey lifecycle](#matrix-store-rekey-lifecycle) for
the recovery procedure.

<a id="interrupted-rekey"></a>**`interrupted-rekey`** — pending or
rekeying-marker found on disk without a canonical passphrase file
(prior `cara matrix rekey-store --new` run crashed mid-rotation).
Stop any running daemon and re-run `cara matrix rekey-store --new`
to advance or roll back before starting the daemon.

<a id="missing-store-secret"></a>**`missing-store-secret`** — the
encrypted store needs a passphrase but none is set. Set
`CARAPACE_CONFIG_PASSWORD` (or `matrix.storePassphrase` /
`MATRIX_STORE_PASSPHRASE`) and rerun.

<a id="auth-session-user-mismatch"></a>**`auth-session-user-mismatch`**
— the restored access token belongs to a different user than
`matrix.userId`. Check `matrix.userId` against the token's owner,
or rotate the token to one issued for the configured user.

<a id="auth-session-device-mismatch"></a>**`auth-session-device-mismatch`**
— the restored access token belongs to a different device than
`matrix.deviceId`. Check `matrix.deviceId` against the device the
token was issued for.

### SAS verification flow (the comparison step)

Matrix uses Short Authentication String (SAS) verification: both sides
display the same emoji or decimal sequence and the operator confirms
they match. The bot stores the SAS payload locally so the operator can
inspect it before confirming.

A flow's `state` field walks the following progression. `cara matrix
confirm --match` requires `accepted` or `keys_exchanged`; earlier states
return `409 VerificationFlowNotReady`. JSON outputs of
`cara matrix verifications` and `/control/matrix/verifications` show
these as snake_case wire values.

| State | Meaning |
|-------|---------|
| `created` | Flow object exists locally but no protocol message has been exchanged. |
| `requested` | The peer asked us to verify; we have not yet accepted. |
| `ready` | Both sides agreed to verify but SAS has not started. |
| `started` | SAS protocol has begun; emoji/decimals not yet computed. |
| `accepted` | SAS values are computed and ready for the human to compare. |
| `keys_exchanged` | Same — keys are exchanged, peer is awaiting our match decision. |
| `confirmed` | Local side has run `confirm --match`; awaiting peer confirmation. |
| `done` | Both sides confirmed; the flow has succeeded. |
| `cancelled` | Flow was cancelled (by either side or by timeout). |
| `mismatched` | Operator ran `confirm --no-match`; the flow is invalid. |
| `transitioned` | Flow has moved into a SAS sub-state; refresh to see the SAS view. |

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
provides. The CLI also displays the SAS emoji + decimal codes and
prompts for an interactive `yes` confirmation before submitting the
match. Automation paths can override this with `--unsafe-skip-sas-prompt`,
but ONLY after the SAS values have been compared by a human through a
separate channel — bypassing the prompt without out-of-band human
comparison defeats the same MITM-resistance.

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

`MATRIX_ACCESS_TOKEN`, `MATRIX_PASSWORD`, and `MATRIX_STORE_PASSPHRASE`
are secret material and are stripped from child-process environments.
`MATRIX_DEVICE_ID` is an identifier, not a credential; it is protected
from config mutation as Matrix identity, but it is not stripped as a
secret from child processes.

For Matrix, explicit config values are resolved before direct environment
fallback. `MATRIX_HOMESERVER_URL`, `MATRIX_USER_ID`, `MATRIX_ACCESS_TOKEN`,
`MATRIX_PASSWORD`, `MATRIX_DEVICE_ID`, and `MATRIX_STORE_PASSPHRASE` are
used only when the matching `matrix.*` key is omitted from config; a
`${MATRIX_*}` placeholder inside config counts as a config value after
the config loader resolves it.

## Inbound Session Routing

Inbound messages create (or reuse) a scoped session key based on channel +
sender + peer ID. Responses are delivered back through the channel pipeline.
