# Security

## Outcome

Understand what Carapace enforces today, what is partial, and how to verify
your local deployment quickly.

## 1) Security defaults

By default, Carapace starts in a local-first, fail-closed posture:

- binds to loopback (`127.0.0.1`) unless you explicitly choose otherwise
- denies authenticated control requests when auth config is missing
- stores credentials in OS keychains when available, with encrypted fallback
- applies SSRF and DNS-rebinding protections for outbound fetch paths

## 2) Subprocess sandboxing status

Current platform status for sandbox-required subprocess paths:

- macOS: Seatbelt + resource limits
- Linux: Landlock + resource limits
- Windows: process limits and path allowlisting; network-deny mode currently
  fails closed
- other targets: fail closed for sandbox-required subprocess paths

## 3) Verify key controls

Run these from a second terminal while Carapace is running:

```bash
cara status --host 127.0.0.1 --port 18789
curl -sS http://127.0.0.1:18789/health
cara logs --follow
```

Quick checks:

- `cara status` should report healthy.
- `/health` should return `status: "ok"`.
- logs should show expected startup/auth/channel events and no repeated
  sandbox/auth errors.

## 4) Trust model and caveats

Carapace is preview software. Verified and partial feature status is tracked in:

- `docs/feature-status.yaml`
- `docs/feature-evidence.yaml`

Read the full threat model and control details:

- [Security model](https://github.com/puremachinery/carapace/blob/HEAD/docs/security.md)
- [Security comparison](https://github.com/puremachinery/carapace/blob/HEAD/docs/security-comparison.md)

## 5) Report vulnerabilities privately

Do not post security vulnerabilities publicly. Use:

<https://github.com/puremachinery/carapace/security/advisories/new>
