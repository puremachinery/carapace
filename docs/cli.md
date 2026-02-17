# cara CLI Guide

This guide covers the CLI subcommands, common flags, and behavior that is not obvious
from `--help`, including recent changes around device identity and TLS requirements.

## Commands

### start
Starts the Carapace service (default when no subcommand is given).

### config
Manage configuration values.

- `config show` — print resolved config as JSON (secrets redacted).
- `config get {key}` — read value by dot path.
- `config set {key} {value}` — set a value (JSON interpreted, string fallback).
- `config path` — print the config file path.

### status
Health/status check via HTTP.

```
cara status --host 127.0.0.1 --port 18789
```

### logs
Fetch recent log lines via WebSocket (`logs.tail`).

```
cara logs -n 50 --host 127.0.0.1 --port 18789
```

Remote hosts require TLS or explicit plaintext opt-in:

- `--tls` — use `wss://` (recommended for remote).
- `--trust` — accept invalid TLS certs (only with `--tls`).
- `--allow-plaintext` — permit `ws://` on non-loopback hosts (unsafe; warns).

### version
Prints version/build info.

### backup / restore
Create or restore a backup archive of Carapace state.

### reset
Remove state data categories. Use `--all` or explicit flags plus `--force`.

### setup
Interactive first-run configuration wizard.

It prompts for:
- provider + API key (with optional credential validation),
- gateway auth mode + generated/custom secret,
- bind mode + port,
- first-run outcome (`local-chat`, `discord`, `telegram`, `hooks`),
- optional hooks API token and Control UI toggle.

At the end, it offers immediate smoke checks (`cara status`) and a first action
(`cara chat`), plus outcome verification (`cara verify`), then prints
outcome-specific next steps.

### verify
Run first-run outcome checks with pass/fail output and next-step guidance.

```bash
cara verify --outcome auto --port 18789
```

Outcomes:
- `auto` — infer from current config.
- `local-chat` — verify local reachability + one non-interactive `chat.send` roundtrip.
- `hooks` — verify signed `POST /hooks/wake` with configured token.
- `discord` / `telegram` — verify bot credential validity and outbound send path.

Options:
- `--port` / `-p` — local service port (default: config or `18789`).
- `--discord-to <channel_id>` — required for Discord send-path check to pass.
- `--telegram-to <chat_id>` — required for Telegram send-path check to pass.

### pair
Pair this CLI with a Carapace service.

```
cara pair https://gateway.local:3001 --name "My CLI" --trust
```

Notes:
- Requires service auth (token or password).
- Performs the device-identity challenge/response during WS connect.
- If pairing is required, the CLI prints a `requestId` to approve in the control UI.

### chat
Start an interactive chat REPL (`chat.send` over WebSocket).

```bash
cara chat
```

Options:
- `--new` — start a new session key instead of resuming `cli-chat`.
- `--port` / `-p` — connect to a specific local Carapace port.

REPL commands:
- `/help` — show command help.
- `/new` — start a fresh session.
- `/exit` or `/quit` — exit chat.

### update
Check for or install updates from GitHub releases.

### tls
Manage cluster CA and node certs:

- `tls init-ca`
- `tls issue-cert`
- `tls revoke-cert`
- `tls show-ca`

## Authentication Inputs

The CLI will try, in order:

1. Environment variables: `CARAPACE_GATEWAY_TOKEN` / `CARAPACE_GATEWAY_PASSWORD`
2. Config file: `gateway.auth.token` / `gateway.auth.password`
3. Credential store (OS keychain/keyutils)

If nothing is found, local-direct access may still work when configured.

## Device Identity (CLI)

The CLI generates and stores a device identity for WebSocket access:

- Stored in the OS credential store when available.
- Legacy on-disk fallback: `{config_dir}/device-identity.json` (e.g.
  `~/.config/carapace/device-identity.json` on Linux; owner-only perms).
- A service-issued `connect.challenge` nonce is signed and sent in `connect`.

Strict mode: set this env var to *disallow* fallback to the legacy file:

- `CARAPACE_DEVICE_IDENTITY_STRICT=1`

When strict mode is enabled:
- credential store unavailable → hard error
- legacy file present → hard error

## State Directories

Default state directory: platform config directory (e.g. `~/.config/carapace/` on Linux).

Override with:

- `CARAPACE_STATE_DIR=/path/to/state`

## Examples

### Tail logs over TLS (self-signed service cert)
```
cara logs --host gateway.local --port 3001 --tls --trust -n 200
```

### Allow plaintext logs (unsafe)
```
cara logs --host 10.0.0.12 --port 18789 --allow-plaintext
```

### Pair with a remote Carapace service
```
CARAPACE_GATEWAY_TOKEN=... cara pair https://gateway.local:3001 --name "Ops CLI" --trust
```

### Start a fresh local chat session
```bash
cara chat --new
```
