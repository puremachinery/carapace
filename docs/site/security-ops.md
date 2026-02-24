# Security & Ops Hub

## Outcome

Run Cara safely in day-2 operation with clear security and recovery paths.

## On this page

- [Day 1 safety baseline](#day-1-safety-baseline)
- [Day 2 runbook and recovery](#day-2-runbook-and-recovery)
- [Security deep dives](#security-deep-dives)
- [High-signal command ladder](#high-signal-command-ladder)

## Day 1 safety baseline

- [Install + verification](install.md)
- [First run flow](first-run.md)
- [Security quick path](security.md)

## Day 2 runbook and recovery

- [Ops runbook](ops.md)
- [Troubleshooting](get-unstuck.md)
- [CLI reference hub](cli-reference.md)

## Security deep dives

- [Security model](../security.md)
- [Security comparison](../security-comparison.md)
- [Security policy](../../SECURITY.md)

## High-signal command ladder

```bash
cara status --port 18789
cara logs -n 200
cara verify --outcome auto --port 18789
cara verify --outcome autonomy --port 18789
```

If checks fail, move to [Get Unstuck](get-unstuck.md), then apply
[Ops runbook](ops.md) recovery steps.

## Operational lifecycle

- [Release & upgrade policy](../release.md)
