# CLI Tasks Index

## Outcome

Find the right `cara` command by outcome instead of scanning the full CLI reference.

## On this page

- [Setup and first value](#setup-and-first-value)
- [Operate and diagnose](#operate-and-diagnose)
- [Secure access and pairing](#secure-access-and-pairing)
- [Backup, restore, reset](#backup-restore-reset)
- [Update lifecycle](#update-lifecycle)
- [Advanced verification](#advanced-verification)
- [Deeper references](#deeper-reference)

## Setup and first value

- Initial setup wizard: `cara setup` or `cara setup --provider <provider>`
- Codex sign-in onboarding: `cara setup --provider codex`
- Gemini onboarding modes: `cara setup --provider gemini --auth-mode oauth|api-key`
- Verify current setup outcome: `cara verify --outcome auto`
- Start local chat: `cara chat`

Command ladder:
- Start with `cara setup` or `cara setup --provider <provider>`
- For Gemini, choose the credential mode explicitly when scripting: `--auth-mode oauth|api-key`
- For Codex, run interactive setup with `OPENAI_OAUTH_CLIENT_ID`, `OPENAI_OAUTH_CLIENT_SECRET`, and `CARAPACE_CONFIG_PASSWORD` available in the shell
- Validate with `cara verify --outcome auto`
- Move to `cara verify --outcome autonomy` for task-runtime proof

## Operate and diagnose

- Health/status: `cara status --port 18789`
- Recent logs: `cara logs -n 200`
- Config path/value: `cara config path`, `cara config get <key>`

## Secure access and pairing

- Pair a CLI/device: `cara pair https://HOST:PORT --name "..." --trust`
- Gateway auth via env: `CARAPACE_GATEWAY_TOKEN`, `CARAPACE_GATEWAY_PASSWORD`

## Backup, restore, reset

- Backup state: `cara backup --output ./carapace-backup.tar.gz`
- Restore state: `cara restore ./carapace-backup.tar.gz`
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

- [CLI reference hub](cli-reference.md)
- [CLI guide](../cli.md)
- [Ops guide](ops.md)
- [Get Unstuck](get-unstuck.md)
