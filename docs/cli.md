# carapace CLI Guide

This guide covers the CLI subcommands, common flags, and behavior that is not obvious
from `--help`, including recent changes around device identity and TLS requirements.

## Commands

### start
Starts the gateway server (default when no subcommand is given).

### config
Manage configuration values.

- `config show` — print resolved config as JSON (secrets redacted).
- `config get <key>` — read value by dot path.
- `config set <key> <value>` — set a value (JSON interpreted, string fallback).
- `config path` — print the config file path.

### status
Health/status check via HTTP.

```
carapace status --host 127.0.0.1 --port 18789
```

### logs
Fetch recent log lines via WebSocket (`logs.tail`).

```
carapace logs -n 50 --host 127.0.0.1 --port 18789
```

Remote hosts require TLS or explicit plaintext opt-in:

- `--tls` — use `wss://` (recommended for remote).
- `--trust` — accept invalid TLS certs (only with `--tls`).
- `--allow-plaintext` — permit `ws://` on non-loopback hosts (unsafe; warns).

### version
Prints version/build info.

### backup / restore
Create or restore a backup archive of gateway state.

### reset
Remove state data categories. Use `--all` or explicit flags plus `--force`.

### setup
Interactive first-run configuration wizard.

### pair
Pair this CLI with a gateway.

```
carapace pair https://gateway.local:3001 --name "My CLI" --trust
```

Notes:
- Requires gateway auth (token or password).
- Performs the device-identity challenge/response during WS connect.
- If pairing is required, the CLI prints a `requestId` to approve in the control UI.

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
- Legacy on-disk fallback: `<config dir>/device-identity.json` (e.g.
  `~/.config/carapace/device-identity.json` on Linux; owner-only perms).
- A gateway-issued `connect.challenge` nonce is signed and sent in `connect`.

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

### Tail logs over TLS (self-signed gateway)
```
carapace logs --host gateway.local --port 3001 --tls --trust -n 200
```

### Allow plaintext logs (unsafe)
```
carapace logs --host 10.0.0.12 --port 18789 --allow-plaintext
```

### Pair with a remote gateway
```
CARAPACE_GATEWAY_TOKEN=... carapace pair https://gateway.local:3001 --name "Ops CLI" --trust
```
