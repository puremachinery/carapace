# Ops

## Outcome

Run day-2 operations safely: health checks, logs, backups, updates, and
practical recovery steps.

## On this page

- [Health command ladder](#1-health-command-ladder)
- [Logs and diagnosis ladder](#2-logs-and-diagnosis-ladder)
- [Autonomy smoke check](#3-autonomy-smoke-check)
- [Task payload storage note](#4-task-payload-storage-note)
- [Production secret baseline](#5-production-secret-baseline)
- [Backup and restore](#6-backup-and-restore)
- [Update flow](#7-update-flow)
- [First-response recovery checklist](#8-first-response-recovery-checklist)
- [Next paths](#9-next-paths)
- [Security reporting](#10-security-reporting)

## 1) Health command ladder

Start with service health:

```bash
cara status --port 18789
curl -sS http://127.0.0.1:18789/health
```

If you changed bind/port in setup, use those values instead of `127.0.0.1:18789`.

## 2) Logs and diagnosis ladder

If health checks fail or degrade:

```bash
cara logs -n 200
```

For deeper troubleshooting, use:

- [Get Unstuck](get-unstuck.md)
- [CLI guide](../cli.md)

## 3) Autonomy smoke check

Verify long-running task execution behavior:

```bash
cara verify --outcome autonomy --port 18789
```

This check submits a real durable task and verifies both:
- start proof (`attempts > 0`)
- terminal proof (`done` or `blocked`)

## 4) Task payload storage note

Durable task payloads are persisted in plaintext at:

- `~/.config/carapace/tasks/queue.json`

Treat task payload text as operational state, not secret storage. Do not place
raw secrets/tokens in task messages.

## 5) Production secret baseline

Set a deployment-specific server secret in production:

```bash
export CARAPACE_SERVER_SECRET='<long-random-secret>'
```

This avoids hooks sender-scoping fallback behavior that is acceptable for local
development but not ideal for long-lived production deployments.

## 6) Backup and restore

Create a backup before major config/channel changes:

```bash
cara backup --output ./carapace-backup.tar.gz
```

Restore from backup:

```bash
cara restore --path ./carapace-backup.tar.gz
```

## 7) Update flow

Quick path:

```bash
cara update
```

Production/reproducible path:

- Use pinned release tags instead of `releases/latest`.
- Validate signatures/checksums before rollout.
- Keep a recent backup to support fast rollback.
- `cara update` is fail-closed on authenticity verification:
  - requires `<asset>.bundle` verification
  - rejects issuer/identity mismatch
  - does not apply unverified binaries

Interrupted/failed update handling:

- Update transactions are persisted at `{state_dir}/updates/transaction.json`
  (override with `CARAPACE_STATE_DIR` if needed).
- Resume is automatic on startup and when you rerun `cara update`.
- Transaction states: `in_progress`, `applied`, `failed`.
- Transaction phases: `created`, `downloading`, `downloaded`, `verified`,
  `applying`, `failed`, `applied`.
- Retryable failures are retried with bounded backoff; non-retryable failures
  require operator action (artifact/policy mismatch, malformed bundle, etc.).

Quick checks:

```bash
cara update --check
# Optional: inspect {state_dir}/updates/transaction.json
# (set CARAPACE_STATE_DIR to your state path if you use a non-default location)
```

Reference docs:

- [Install](install.md)
- [Release & upgrade policy](../release.md)

## 8) First-response recovery checklist

1. Confirm service health and port/bind settings.
2. Capture recent logs and isolate the first failing component (provider/channel/auth).
3. Re-run setup for misconfigured auth/network/channel values.
4. Restore from latest known-good backup if needed.
5. Open an issue with logs + exact steps if still blocked.

## 9) Next paths

- Day 1/startup docs: [First Run](first-run.md), [Cookbook](../cookbook/README.md)
- Day 2/operator docs: [Security & Ops hub](security-ops.md), [CLI reference hub](cli-reference.md)
- [Get Unstuck](get-unstuck.md)

## 10) Security reporting

For suspected vulnerabilities, use private reporting:

- <https://github.com/puremachinery/carapace/security/advisories/new>
- [Security policy](../../SECURITY.md)
