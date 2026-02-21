# cara CLI Guide

This page is command-reference-first: subcommands, key flags, and CLI-specific
behavior that is easy to miss from `--help`.

For first-run walkthroughs and channel onboarding:
- [First Run](site/first-run.md)
- [Getting Started](getting-started.md)
- [Channel Setup](channels.md)

## Command Reference

### `cara` / `cara start`
Starts the Carapace service (default when no subcommand is given).

### `cara config`
Manage configuration values.

- `cara config show` — print resolved config as JSON (secrets redacted)
- `cara config get <key>` — read value by dot path
- `cara config set <key> <value>` — set value (JSON interpreted, string fallback)
- `cara config path` — print the config file path

### `cara setup`
Interactive first-run wizard for provider/auth/network/channel setup.

Wizard outcomes include `local-chat`, `discord`, `telegram`, and `hooks`.
Use `--force` to overwrite an existing config file.
For the full setup flow and decision guidance, use [First Run](site/first-run.md).

### `cara verify`
Run first-run outcome checks with pass/fail output and next-step guidance.

```bash
cara verify --outcome auto --port 18789
```

Outcomes:
- `auto` — infer from current config
- `local-chat` — local reachability + one non-interactive `chat.send` roundtrip
- `hooks` — signed `POST /hooks/wake` with configured token
- `discord` / `telegram` — credential validity + outbound send-path verification

Options:
- `--port` / `-p` — local service port (default: config or `18789`)
- `--discord-to <channel_id>` — required for Discord send-path verification
- `--telegram-to <chat_id>` — required for Telegram send-path verification

Notes:
- `cara verify` currently targets local loopback only (`127.0.0.1`)
- Discord/Telegram verification sends a real test message
- Hooks verification may trigger a real agent run

### `cara status`
Health/status check via HTTP.

```bash
cara status --port 18789
```

### `cara logs`
Fetch log lines via WebSocket (`logs.tail`).

```bash
cara logs -n 50 --port 18789
```

`cara logs` is a snapshot tail request (not a persistent follow stream).

Remote hosts require TLS or explicit plaintext opt-in:
- `--tls` — use `wss://` (recommended for remote)
- `--trust` — accept invalid TLS certs (only with `--tls`)
- `--allow-plaintext` — permit `ws://` on non-loopback hosts (unsafe; warns)

### `cara chat`
Start an interactive chat REPL (`chat.send` over WebSocket).

```bash
cara chat
```

Options:
- `--new` — start a new session key instead of resuming `cli-chat`
- `--port` / `-p` — connect to a specific local Carapace port

REPL commands:
- `/help` — show command help
- `/new` — start a fresh session
- `/exit` or `/quit` — exit chat

### `cara pair`
Pair this CLI with a Carapace service.

```bash
cara pair https://gateway.local:3001 --name "My CLI" --trust
```

Notes:
- Requires service auth (token/password)
- Performs device-identity challenge/response during WS connect
- If pairing approval is required, the CLI prints a `requestId` for control UI approval

### `cara backup` / `cara restore`
Create or restore a backup archive of Carapace state.

### `cara reset`
Remove state data categories. Use `--all` or explicit flags plus `--force`.

### `cara update`
Check for or install updates from GitHub releases.

- `cara update --check` — check only (no install)
- `cara update --version <x.y.z>` — install a specific version

### `cara version`
Print version/build info.

### `cara tls`
Manage cluster CA and node certificates:
- `cara tls init-ca`
- `cara tls issue-cert`
- `cara tls revoke-cert`
- `cara tls show-ca`

## Authentication Inputs

The CLI resolves auth inputs in this order:

1. Environment: `CARAPACE_GATEWAY_TOKEN` / `CARAPACE_GATEWAY_PASSWORD`
2. Config file: `gateway.auth.token` / `gateway.auth.password`
3. OS credential store (Keychain / Secret Service / Credential Manager)

If none are found, local-direct access may still work when configured.

## Device Identity (CLI)

The CLI creates a device identity for WebSocket access:

- Stored in OS credential store when available
- Legacy fallback file: `{config_dir}/device-identity.json` (owner-only perms)
- A service-issued `connect.challenge` nonce is signed and sent in `connect`

Strict mode to disallow legacy fallback:

- `CARAPACE_DEVICE_IDENTITY_STRICT=1`

Strict mode behavior:
- credential store unavailable -> hard error
- legacy fallback file present -> hard error

## State Directory

Default: platform config directory (for example `~/.config/carapace/` on Linux).

Override with:
- `CARAPACE_STATE_DIR=/path/to/state`

## Common Snippets

Tail logs over TLS (self-signed service cert):

```bash
cara logs --host gateway.local --port 3001 --tls --trust -n 200
```

Allow plaintext logs (unsafe):

```bash
cara logs --host 10.0.0.12 --port 18789 --allow-plaintext
```

Pair with a remote Carapace service:

```bash
CARAPACE_GATEWAY_TOKEN=... cara pair https://gateway.local:3001 --name "Ops CLI" --trust
```

Start a fresh local chat session:

```bash
cara chat --new
```
