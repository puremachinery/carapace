# Get Unstuck

## Quick triage (copy/paste)

```bash
cara version
cara status --host 127.0.0.1 --port 18789
curl -H "Authorization: Bearer ${CARAPACE_GATEWAY_TOKEN}" http://127.0.0.1:18789/health
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
cara logs --follow
```

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
