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
    // First login only — once the access token is persisted, you can
    // remove this line. Cross-signing bootstrap also needs the
    // password once.
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
  }
}
```

`matrix.encrypted` defaults to `true`. Encrypted Matrix rooms require
password-protected local state because Carapace owns the SDK device keys
and room-session keys. Without `MATRIX_STORE_PASSPHRASE`, Carapace
derives the SDK store key via HKDF-SHA256 from `CARAPACE_CONFIG_PASSWORD`
and a per-installation salt at `~/.config/carapace/installation_id`.

## 2) Start Carapace and verify the channel

```bash
export MATRIX_PASSWORD="<your matrix account password>"
cara
```

In a second terminal:

```bash
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

   to list pending flows. Each entry includes a `sas` field with
   `emoji` (e.g. `🐱 cat`) and `decimals`. Compare against what
   the other client shows.

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

Lost recovery keys lock you out of past encrypted history. The key is
CLI-only by design — it never traverses the control API.

To restore from a previously-saved key:

```bash
cara matrix recovery-key restore --key-file ./matrix-recovery-key.txt
# or
printf '%s\n' '<recovery-key>' | cara matrix recovery-key restore
```

After `restore`, **restart the daemon** for the new key to take effect.

## 5) Send a test message

```bash
cara verify --outcome matrix --matrix-to '!room:example.com' --port 18789
```

Where `!room:example.com` is a real room ID (find it in your client's
room settings). The verifier sends a probe message and expects an event
ID in response.

## 6) Configure auto-join carefully

`matrix.autoJoin` is fail-closed. An empty allowlist rejects every
invite. `allowUsers` matches full MXIDs; `allowServerNames` matches the
server-name part with a leading-dot suffix anchor (so
`example.com` matches `chat.example.com` but NOT `evil-example.com`).

## Common mistakes

- **`matrix.encrypted=false` plus `matrix.storePassphrase`** — schema
  warns; the storePassphrase is unused in unencrypted-only mode.
- **`matrix.userId` not in canonical MXID form** (`@local:server`) —
  schema rejects with `Severity::Error` at startup.
- **Running `cara matrix rekey-store --new` while the daemon is up** —
  the rekey CLI refuses; the daemon's `DaemonPidGuard` holds an
  exclusive flock on `~/.config/carapace/.matrix-rekey.lock`. Stop the
  daemon first.
- **Interrupted rekey** — `~/.config/carapace/matrix/store_passphrase.pending`
  + `store_passphrase.rekeying` on disk without the final
  `store_passphrase`. The daemon refuses to start in this state with a
  `StartupFailed: interrupted Matrix store rekey detected` error.
  Recovery: rerun `cara matrix rekey-store --new` (idempotent). Do
  NOT delete the marker / pending files manually.

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
