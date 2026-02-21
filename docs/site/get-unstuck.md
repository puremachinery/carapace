# Get Unstuck

## Quick triage (copy/paste)

```bash
cara version
cara status --port 18789
curl -sS http://127.0.0.1:18789/health
cara logs -n 80
```

## Typical failures

- `401 Unauthorized`
  - Token mismatch between request and `gateway.auth.token`.
- `Connection refused`
  - Service not running, wrong host/port, or bind mode mismatch.
- `No provider is currently available`
  - Provider key not set in same shell/session.
- Channel inbound not working
  - Missing channel token/secret or external platform webhook/intents not configured.

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

- Setup smoke feedback: <https://github.com/puremachinery/carapace/issues/new?template=setup-smoke-report.yml>
- Bug report: <https://github.com/puremachinery/carapace/issues/new?template=bug-report.yml>
- Feature request: <https://github.com/puremachinery/carapace/issues/new?template=feature-request.yml>

For security vulnerabilities, use private reporting:
<https://github.com/puremachinery/carapace/security/advisories/new>
