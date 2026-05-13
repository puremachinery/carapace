# Add Carapace to Matrix / Element

## Outcome

Connect Carapace to a Matrix homeserver so encrypted DMs and rooms can
trigger agent responses, with full Matrix end-to-end encryption (E2EE) via
the matrix-sdk.

## Prerequisites

- `cara` installed.
- `ANTHROPIC_API_KEY` or `OPENAI_API_KEY`.
- A Matrix account on a homeserver you control or trust (e.g.
  `matrix.org`, a self-hosted Synapse/Dendrite).
- The account's password (used once for first login + cross-signing
  bootstrap; can be removed after the access token is persisted).
- Optionally a second Matrix client (Element, Cinny, etc.) on a verified
  device, for SAS verification of Carapace's device.

Matrix support is opt-in via `matrix.enabled: true`. Carapace pins
`matrix-sdk` 0.14.x with `default-features = false` and the
`e2e-encryption`, `sqlite`, and `rustls-tls` features.

## 1) Create config

Generate a gateway token:

```bash
export CARAPACE_GATEWAY_TOKEN="$(openssl rand -hex 32)"
```

Set a config password so persisted secrets (including the access token
and store passphrase) encrypt at rest:

```bash
export CARAPACE_CONFIG_PASSWORD="$(openssl rand -hex 32)"
```

Keep this value in the daemon environment and in any terminal that runs
Matrix maintenance commands. Losing it is a lockout: it seals config secrets,
derives the default Matrix SDK store key, and protects Matrix DLQ envelopes.
Store it in a password manager or off-host vault before starting the daemon;
do not leave the only copy in shell history, a terminal scrollback buffer, or a
single process-manager environment file.
`cara matrix rekey-store --new` still needs the old value before it can
decouple the Matrix store from that password.

Then create `~/.config/carapace/carapace.json5`:

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
  "matrix": {
    "enabled": true,
    "homeserverUrl": "https://matrix.example.com",
    "userId": "@cara:example.com",
    // First login only. The daemon removes the persisted password after
    // access-token write-back; do not manually edit it out while the daemon is
    // running. Cross-signing bootstrap also needs the password once.
    "password": "${MATRIX_PASSWORD}",
    "encrypted": true,
    "autoJoin": {
      // Empty allowlist means NO auto-joins. Add the MXIDs you want
      // Cara to follow into rooms, plus the homeserver suffixes you
      // trust to invite the bot.
      "allowUsers": ["@you:example.com"],
      "allowServerNames": ["example.com"]
    }
  },
  "anthropic": {
    "apiKey": "${ANTHROPIC_API_KEY}"
  },
  "agents": {
    "default": {
      "model": "anthropic:claude-sonnet-4-6"
    }
  }
}
```

`matrix.encrypted` defaults to `true`. Encrypted Matrix rooms require
password-protected local state because Carapace owns the SDK device keys
and room-session keys. Without `MATRIX_STORE_PASSPHRASE`, Carapace
derives the SDK store key via HKDF-SHA256 from `CARAPACE_CONFIG_PASSWORD`
and a per-installation salt at `{state_dir}/installation_id`.

## 2) Start Carapace and verify the channel

```bash
export MATRIX_PASSWORD="<your matrix account password>"
cara
```

In a second terminal:

```bash
export CARAPACE_CONFIG_PASSWORD="<same value from terminal 1>"
export CARAPACE_GATEWAY_TOKEN="<same value from terminal 1>"
cara verify --outcome matrix --port 18789
```

Expected: a `PASS` for Matrix runtime registration. The first run
performs password login and persists the access token back to
`carapace.json5` (encrypted via `enc:v2:...` because
`CARAPACE_CONFIG_PASSWORD` is set). Subsequent restarts use the persisted
token; the password is only needed again for cross-signing bootstrap.

## 3) Verify Carapace's device with another client

Encrypted rooms require Carapace's device to be cross-signed and
verified. From your second client (Element, etc.):

1. Find Carapace's device under the bot's user → device list.
2. Start a verification flow against that device.
3. In Carapace's terminal, run:

   ```bash
   cara matrix verifications
   ```

   to list pending flows. Accept the request:

   ```bash
   cara matrix accept <flow-id>
   ```

   Then rerun `cara matrix verifications` until the entry includes a
   `sas` field with `emoji` (e.g. `🐱 cat`) and `decimals`. Compare
   against what the other client shows.

4. If they match:

   ```bash
   cara matrix confirm <flow-id> --match
   ```

   Returns `409 VerificationFlowNotReady` if SAS values haven't been
   captured yet — wait a few seconds and retry.

5. If they don't match (potentially MITM):

   ```bash
   cara matrix confirm <flow-id> --no-match
   ```

   Investigate the discrepancy before trusting the device.

`cara matrix verify <user> [device]` initiates a flow from Carapace's
side to verify another device on the same account.

## 4) Capture the recovery key

Cross-signing creates a recovery key during first-run bootstrap. Save
it somewhere durable:

```bash
cara matrix recovery-key show
```

Lost recovery keys lock you out of past encrypted history.
`recovery-key show`, `recovery-key restore`, `recovery-key rotate`, and
`rekey-store` are CLI-only by design — they never traverse the control API.
If stdout is redirected intentionally, use
`cara matrix recovery-key show --allow-non-terminal`; otherwise the CLI refuses
non-terminal capture.

To restore from a previously-saved key:

```bash
systemctl --user stop carapace # or stop the foreground daemon
cara matrix recovery-key restore --key-file ./matrix-recovery-key.txt
# or
printf '%s\n' '<recovery-key>' | cara matrix recovery-key restore --stdin
```

After `restore`, **restart the daemon** for the new key to take effect.
If restore exits non-zero after writing the key because stale rotation cleanup
failed, keep the daemon stopped and resolve `recovery_key.rotating` /
`recovery_key.pending` before restarting. During rotation recovery, the daemon
only promotes `recovery_key.pending` from a `pending_key_written` marker when
the pending digest and the current key both match the marker; malformed markers
or a missing current key fail closed and keep both files for manual inspection.
To rotate after suspected disclosure, stop the daemon and run:

```bash
cara matrix recovery-key rotate
cara matrix recovery-key show
```

The old recovery key is abandoned. Save the new key before relying on encrypted
Matrix backup.

## 5) Invite Carapace to a room

Use your second Matrix client to invite Carapace to the room you want it
to serve. If `matrix.autoJoin` is enabled, confirm the inviter is covered by
`allowUsers` or `allowServerNames`; otherwise join the room manually from the
Carapace account before testing the room ID.

`matrix.autoJoin` is fail-closed. An empty allowlist rejects every
invite. `allowUsers` matches full MXIDs; `allowServerNames` matches the
server-name part with a label-anchored suffix match (so `example.com`
matches `chat.example.com` but NOT `evil-example.com`).

## 6) Send a test message

```bash
cara verify --outcome matrix --matrix-to '!room:example.com' --port 18789
```

Where `!room:example.com` is a real room ID (find it in your client's
room settings). The verifier sends a probe message and expects an event
ID in response.

## Common mistakes

- **`matrix.encrypted=false` plus `matrix.storePassphrase`** — schema
  warns; the storePassphrase is unused in unencrypted-only mode.
- **`matrix.userId` not in canonical MXID form** (`@local:server`) —
  schema rejects with `Severity::Error` at startup.
- **Missing `agents`** — the Matrix channel can connect but inbound dispatch
  has no default model/agent route to run.
- **Env only exported in one terminal** — `cara verify`, `cara matrix ...`,
  and rekey commands need the same `CARAPACE_CONFIG_PASSWORD`, gateway token,
  Matrix env, and provider keys unless they are supplied by the daemon's
  process manager environment.
- **Manual password removal** — password cleanup is daemon-owned after
  access-token persistence. Stop the daemon before editing Matrix credentials.
- **Cross-signing not bootstrapped** — encrypted rooms need a verified
  Carapace device. Some clients show emoji SAS, some show decimal SAS, and
  older clients may show only decimals; compare the same representation on
  both sides before confirming.
- **Running `cara matrix rekey-store --new` while the daemon is up** —
  the rekey CLI refuses because the daemon holds the exclusive
  `.matrix-rekey.lock` maintenance lock in the state directory. Stop the
  daemon first.
- **Interrupted rekey** — `~/.config/carapace/matrix/store_passphrase.pending`
  + `store_passphrase.rekeying` on disk without the final
  `store_passphrase`. The daemon refuses to start in this state with a
  `Matrix store rekey interrupted: ...` error (see
  [Channel Setup → Matrix store rekey lifecycle](../channels.md#matrix-store-rekey-lifecycle)).
  Recovery: rerun `cara matrix rekey-store --new` (idempotent). Do
  NOT delete the marker / pending files manually.
- **Lost local recovery key** — do not try to repair this by manually deleting
  `recovery_key`, `recovery_key.pending`, or Matrix SQLite files. Use
  `cara matrix recovery-key restore` if you have the current key, or rotate
  through the supported recovery-key flow from a verified Matrix client.

## What this gives you

- Native Matrix runtime with E2EE for message sending and receipt.
- Cross-signed bot device, verifiable from any Matrix client.
- Per-installation derived SDK store key, rotatable via `cara matrix
  rekey-store --new`.
- Auto-join allowlist that fails closed.
- WS events for verification flows
  (`matrix.verification.requested` / `matrix.verification.updated`).
- Channel-status metadata via `cara status` and `/control/channels`
  (joined room count, encrypted/unencrypted/unsupported breakdown,
  pending verification count, last successful sync, DLQ counters).

See also:

- `docs/channels.md#matrix--element` — full reference.
- `docs/protocol/http.md` — control endpoints and error mapping.
- `docs/protocol/websocket.md` — WS event payloads.
- `docs/security.md` — Matrix sensitive-data locations and rekey
  recovery procedure.
