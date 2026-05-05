# Channel Smoke Validation

This playbook defines reproducible, real-world smoke checks for channel
integrations. Use it to produce concrete pass/fail evidence before upgrading
channel claims in `docs/feature-status.yaml` and `docs/feature-evidence.yaml`.

## Scope

Priority for current validation wave:

- Signal
- Slack
- Matrix

The smoke report template also supports Telegram and Discord; use the same
evidence format.

## Preflight

1. Record version and OS:
   - `cara version`
   - platform details (`uname -a` or Windows equivalent)
2. Start Carapace with target channel configured.
3. Keep logs open:

```bash
cara logs -n 200
```

`cara logs` prints a recent tail (not a live follow stream). Re-run it at key
steps and after failures to capture relevant evidence.

## Pass Criteria

A channel smoke run is considered **pass** when all are true:

1. Carapace health is good (`cara status` healthy).
2. Channel registration succeeds at startup (no repeated auth/signature errors).
3. One inbound message is received and produces an agent run.
4. One outbound reply is delivered back to the same channel.
5. If optional channel-activity features are enabled for the target channel,
   those behaviors also match the configured policy.

If any step fails, capture the first failing step and logs.

## Signal Smoke

Assumes `signal-cli-rest-api` is running and configured in `carapace.json5`
(see [Signal Channel Setup](channels.md#signal-signal-cli-rest-api)).

1. Start services and verify health:
   - `cara status --port 18789`
2. Send one test message from another Signal device/account to the configured
   Signal number.
3. Confirm logs show inbound parsing + agent run dispatch from
   `signal_receive`.
4. Confirm reply is delivered in Signal.
5. If `channels.signal.features.typing.enabled` is true, confirm the sending
   device/account sees a typing indicator while Carapace is generating the
   reply.
6. If `channels.signal.features.readReceipts.enabled` is true, confirm the
   inbound message stays unread until Carapace durably appends it to the
   session/history store, then transitions to read before the assistant reply
   is generated or delivered.

Common failure indicators:

- repeated HTTP errors polling `/v1/receive/{number}`
- missing/incorrect `signal.phoneNumber`
- signal-cli service not reachable from Carapace host

## Slack Smoke

Assumes Slack bot token and signing secret are configured and Events API request
URL points to `/channels/slack/events` (see
[Slack Channel Setup](channels.md#slack-web-api--events-api)).

1. Verify Slack Events URL challenge succeeds.
2. Send one message in a subscribed Slack channel.
3. Confirm logs show inbound event parsing and agent run.
4. Confirm outbound reply appears in Slack.

Common failure indicators:

- `X-Slack-Signature` validation errors
- stale timestamp rejection
- missing bot scopes or channel permissions

## Matrix Smoke

Assumes Matrix credentials and encrypted store state are configured (see
[Matrix / Element](channels.md#matrix--element)).

1. Start Carapace and verify runtime wiring:
   - `cara status --port 18789`
   - `cara verify --outcome matrix --port 18789 --matrix-to "<room_id>"`
   - `cara verify` confirms config, runtime registration, control-API
     reachability, encrypted-store prerequisites, and sends a real Matrix
     test message to `--matrix-to` through the daemon-owned Matrix runtime.
2. Confirm password login persists `matrix.accessToken`, then restart and
   confirm token restore works without `MATRIX_PASSWORD`.
3. Send one message in an unencrypted room and confirm an agent run is created.
4. Confirm the assistant reply appears in the same Matrix room. This is
   the normal conversation-path smoke; record the event ID returned in the
   agent run as evidence of delivery.
5. Repeat receive/send in an encrypted room when `matrix.encrypted=true`.
6. Invite Carapace from an allowed user/server and confirm auto-join succeeds.
7. Invite Carapace from a user/server outside the allowlist and confirm the
   invite is rejected.
8. Run a SAS verification flow:
   - `cara matrix devices`
   - `cara matrix verify <user> [device]`
   - `cara matrix accept <flow>`
   - read the returned `verification.sas` emoji or decimals, or rerun
     `cara matrix verifications` until SAS data appears
   - compare the SAS values with the other Matrix device out-of-band
   - `cara matrix confirm <flow> --match`
9. Restart Carapace and confirm the encrypted Matrix store opens successfully.

Common failure indicators:

- missing `CARAPACE_CONFIG_PASSWORD` or `MATRIX_STORE_PASSPHRASE`
- encrypted rooms marked unsupported while `matrix.encrypted=false`
- Matrix sync retry loop with repeated auth or store-open errors
- invite sender not covered by `autoJoin.allowUsers` or
  `autoJoin.allowServerNames`

## Evidence Capture

Open a smoke report with:

- channel name
- pass/fail result
- exact failing step (if fail)
- relevant logs (redacted)

Template:

[Open a smoke report](https://github.com/puremachinery/carapace/issues/new?template=channel-smoke-report.yml&title=channel+smoke%3A+%3CCHANNEL%3E+%3CPASS%7CFAIL%3E)
