# Security

## Outcome

Understand current security controls, known partial areas, and how to verify
your local deployment quickly.

## 1) Security defaults

By default, Carapace starts in a local-first, fail-closed posture:

- Binds to loopback (`127.0.0.1`) unless you explicitly choose otherwise.
- Denies authenticated control requests when auth config is missing.
- Stores credentials in OS keychains when available, with encrypted fallback.
- Applies SSRF and DNS-rebinding protections for outbound fetch paths.

## 2) Subprocess sandboxing status

Current platform status for sandbox-required subprocess paths:

- macOS: Seatbelt + resource limits
- Linux: Landlock + resource limits
- Windows: sandboxes subprocesses with Job Objects + AppContainer. If a
  deny-network spawn flow is unsupported, Carapace blocks it instead of
  running unsandboxed.
- Other targets: fail closed for sandbox-required subprocess paths.

## 3) Verify key controls

Run these from a second terminal while Carapace is running:

```bash
cara status --host 127.0.0.1 --port 18789
curl -sS http://127.0.0.1:18789/health
curl -sS -o /dev/null -w "%{http_code}\n" http://127.0.0.1:18789/control/status
curl -sS -o /dev/null -w "%{http_code}\n" -H "Authorization: Bearer ${CARAPACE_GATEWAY_TOKEN}" http://127.0.0.1:18789/control/status
cara logs -n 200
```

Quick checks:

- `cara status` should report healthy.
- `/health` should return `status: "ok"` (public liveness probe).
- `/control/status` should return `401` without auth and `200` with a valid
  service auth token/password.
- `cara logs -n 200` should show expected startup/auth/channel events.

## 4) Trust model and caveats

Carapace is preview software. Verified and partial feature status is tracked in:

- [`docs/feature-status.yaml`](https://github.com/puremachinery/carapace/blob/main/docs/feature-status.yaml)
- [`docs/feature-evidence.yaml`](https://github.com/puremachinery/carapace/blob/main/docs/feature-evidence.yaml)

Read the full threat model and control details:

- [Security model](https://github.com/puremachinery/carapace/blob/main/docs/security.md)
- [Security comparison](https://github.com/puremachinery/carapace/blob/main/docs/security-comparison.md)

## 5) Report vulnerabilities privately

Do not post security vulnerabilities publicly. Use:

<https://github.com/puremachinery/carapace/security/advisories/new>
