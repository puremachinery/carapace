# Channel Smoke Validation

This playbook defines reproducible, real-world smoke checks for channel
integrations. Use it to produce concrete pass/fail evidence before upgrading
channel claims in `docs/feature-status.yaml` and `docs/feature-evidence.yaml`.

## Scope

Priority for current validation wave:

- Signal
- Slack

Other channels can follow the same evidence format.

## Preflight

1. Record version and OS:
   - `cara version`
   - platform details (`uname -a` or Windows equivalent)
2. Start Carapace with target channel configured.
3. Keep logs open:

```bash
cara logs --follow
```

## Pass Criteria

A channel smoke run is considered **pass** when all are true:

1. Carapace health is good (`cara status` healthy).
2. Channel registration succeeds at startup (no repeated auth/signature errors).
3. One inbound message is received and produces an agent run.
4. One outbound reply is delivered back to the same channel.

If any step fails, capture the first failing step and logs.

## Signal Smoke

Assumes `signal-cli-rest-api` is running and configured in `carapace.json5`
(see [Signal Channel Setup](channels.md#signal-signal-cli-rest-api)).

1. Start services and verify health:
   - `cara status --host 127.0.0.1 --port 18789`
2. Send one test message from another Signal device/account to the configured
   Signal number.
3. Confirm logs show inbound parsing + agent run dispatch from
   `signal_receive`.
4. Confirm reply is delivered in Signal.

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

## Evidence Capture

Open a smoke report with:

- channel name
- pass/fail result
- exact failing step (if fail)
- relevant logs (redacted)

Template:

<https://github.com/puremachinery/carapace/issues/new?template=channel-smoke-report.yml&title=channel+smoke%3A+%3Csignal%7Cslack%3E+%3Cpass%7Cfail%3E>
