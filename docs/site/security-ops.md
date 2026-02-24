# Security & Ops Hub

## Outcome

Run Cara safely in day-2 operation with clear security and recovery paths.

## Core paths

- [Security quick path](security.md)
- [Ops runbook](ops.md)
- [Troubleshooting](get-unstuck.md)

## Security deep dives

- [Security model](../security.md)
- [Security comparison](../security-comparison.md)
- [Security policy](../../SECURITY.md)

## Operational lifecycle

- [Install + verification](install.md)
- [First run flow](first-run.md)
- [Release & upgrade policy](../release.md)

## High-signal checks

```bash
cara status --port 18789
cara logs -n 200
cara verify --outcome auto --port 18789
cara verify --outcome autonomy --port 18789
```
