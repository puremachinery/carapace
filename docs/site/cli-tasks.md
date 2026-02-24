# CLI Tasks Index

## Outcome

Find the right `cara` command by outcome instead of scanning the full CLI reference.

## Setup and first value

- Initial setup wizard: `cara setup`
- Verify current setup outcome: `cara verify --outcome auto`
- Start local chat: `cara chat`

## Operate and diagnose

- Health/status: `cara status --port 18789`
- Recent logs: `cara logs -n 200`
- Config path/value: `cara config path`, `cara config get <key>`

## Secure access and pairing

- Pair a CLI/device: `cara pair https://HOST:PORT --name "..." --trust`
- Gateway auth via env: `CARAPACE_GATEWAY_TOKEN`, `CARAPACE_GATEWAY_PASSWORD`

## Backup, restore, reset

- Backup state: `cara backup --output ./carapace-backup.tar.gz`
- Restore state: `cara restore --path ./carapace-backup.tar.gz`
- Reset categories: `cara reset --all --force`

## Update lifecycle

- Check updates only: `cara update --check`
- Install update: `cara update`
- Pin version: `cara update --version <x.y.z>`

## Advanced verification

- Hooks path: `cara verify --outcome hooks --port 18789`
- Channel send-path checks: `cara verify --outcome discord|telegram ...`
- Long-running autonomy path: `cara verify --outcome autonomy --port 18789`

## Deeper reference

- [CLI guide](../cli.md)
- [Ops guide](ops.md)
- [Get Unstuck](get-unstuck.md)
