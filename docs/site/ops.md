# Ops

## Outcome

Run day-2 operations safely: health checks, logs, backups, updates, and
practical recovery steps.

## 1) Health and status

```bash
cara status --port 18789
curl -sS http://127.0.0.1:18789/health
```

If you changed bind/port in setup, use those values instead of `127.0.0.1:18789`.

## 2) Logs and diagnosis

```bash
cara logs -n 200
```

For deeper troubleshooting, use:

- [Get Unstuck](get-unstuck.md)
- [CLI guide](../cli.md)

## 3) Backup and restore

Create a backup before major config/channel changes:

```bash
cara backup --output ./carapace-backup.tar.gz
```

Restore from backup:

```bash
cara restore --path ./carapace-backup.tar.gz
```

## 4) Update flow

Check/update the local binary:

```bash
cara update
```

For pinned or reproducible installs, use the install guide:

- [Install](install.md)

## 5) First-response recovery checklist

1. Confirm service health and port/bind settings.
2. Capture recent logs and isolate the first failing component (provider/channel/auth).
3. Re-run setup for misconfigured auth/network/channel values.
4. Restore from latest known-good backup if needed.
5. Open an issue with logs + exact steps if still blocked.

## 6) Next paths

- [First Run](first-run.md)
- [Cookbook](../cookbook/README.md)
