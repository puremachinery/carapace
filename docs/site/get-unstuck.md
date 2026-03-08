# Get Unstuck

## On this page

- [Quick triage command ladder](#quick-triage-command-ladder-copy-paste)
- [Typical failures](#typical-failures)
- [Task stuck or blocked](#task-stuck-or-blocked)
- [Capture useful logs](#capture-useful-logs)
- [Validate config quickly](#validate-config-quickly)

## Quick triage command ladder (copy/paste)

```bash
cara version
cara status --port 18789
curl -sS http://127.0.0.1:18789/health
cara logs -n 80
```

Run top-to-bottom, then branch into the sections below based on first failure.

## Typical failures

- `401 Unauthorized`
  - Token mismatch between request and `gateway.auth.token`.
- `Connection refused`
  - Service not running, wrong host/port, or bind mode mismatch.
- `No provider is currently available`
  - Provider key not set in same shell/session.
- Channel inbound not working
  - Missing channel token/secret or external platform webhook/intents not configured.

## Task stuck or blocked

If long-running autonomy tasks are not progressing:

```bash
curl -sS -H "Authorization: Bearer ${CARAPACE_GATEWAY_TOKEN}" \
  "http://127.0.0.1:18789/control/tasks?state=blocked&limit=20"
```

Inspect a specific task:

```bash
curl -sS -H "Authorization: Bearer ${CARAPACE_GATEWAY_TOKEN}" \
  "http://127.0.0.1:18789/control/tasks/<task_id>"
```

Common operator actions:
- Resume blocked task:
  ```bash
  curl -sS -X POST -H "Authorization: Bearer ${CARAPACE_GATEWAY_TOKEN}" \
    -H "content-type: application/json" \
    -d '{"delayMs":1000,"reason":"operator resume"}' \
    "http://127.0.0.1:18789/control/tasks/<task_id>/resume"
  ```
- Retry failed/cancelled task:
  ```bash
  curl -sS -X POST -H "Authorization: Bearer ${CARAPACE_GATEWAY_TOKEN}" \
    -H "content-type: application/json" \
    -d '{"delayMs":500,"reason":"operator retry"}' \
    "http://127.0.0.1:18789/control/tasks/<task_id>/retry"
  ```
- Patch payload/policy before retry:
  ```bash
  curl -sS -X PATCH -H "Authorization: Bearer ${CARAPACE_GATEWAY_TOKEN}" \
    -H "content-type: application/json" \
    -d '{"policy":{"maxRunTimeoutSeconds":45},"reason":"operator patch"}' \
    "http://127.0.0.1:18789/control/tasks/<task_id>"
  ```

## Capture useful logs

Run with debug logging:

```bash
RUST_LOG=debug CARAPACE_CONFIG_PATH=./carapace.json5 cara
```

If service is running already:

```bash
cara logs -n 200
```

`cara logs` prints the last N log lines (it does not stream continuously),
so re-run it as needed while debugging.

## Validate config quickly

- Compare your config against `config.example.json5`
- Confirm auth mode is intentional (`token`, `password`, or `none` for local-only)
- Confirm channel secrets are present for enabled channels

## Ask for help or report problems

- Guided setup or team evaluation: [Help](help.md)
- Setup smoke feedback: <https://github.com/puremachinery/carapace/issues/new?template=setup-smoke-report.yml>
- Bug report: <https://github.com/puremachinery/carapace/issues/new?template=bug-report.yml>
- Feature request: <https://github.com/puremachinery/carapace/issues/new?template=feature-request.yml>

For security vulnerabilities, use private reporting:
<https://github.com/puremachinery/carapace/security/advisories/new>
