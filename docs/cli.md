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

Supported `--provider` values: Anthropic, OpenAI, Gemini (API key or OAuth),
Ollama, Bedrock, Vertex, Codex, and Venice. The Claude CLI provider is
configured directly in `carapace.json5` via `claude-cli:<model>` in agent
`model` fields; it is not currently exposed through `cara setup --provider`.
`claude` is an Anthropic setup alias, and `gpt` is an OpenAI setup alias.

Wizard outcomes include `local-chat`, `discord`, `telegram`, and `hooks`.
Use `--force` to overwrite an existing config file.

All model references require explicit `provider:model` routing (e.g.
`anthropic:claude-sonnet-4-6`). Bare model names are rejected.

`--auth-mode` is accepted for Anthropic and Gemini setup. Anthropic supports
`api-key` and `setup-token`; Gemini supports `api-key` and `oauth`. Non-
interactive Gemini OAuth setup is rejected because the Google sign-in flow is
interactive. Codex auth is fixed to OAuth-only — pass `--provider codex`
without `--auth-mode`; the wizard completes the sign-in via a loopback
callback and writes `codex.authProfile`.

For the full setup flow and decision guidance, use [First Run](site/first-run.md).

### `cara import`
Import configuration from another tool into Carapace.

```bash
cara import <source> [--force]
```

Supported sources:
- `openclaw` — imports from `~/.openclaw/openclaw.json`, `.env`, and
  `~/.clawdbot/`. Maps provider API keys, channel tokens, gateway auth, model
  selection, and env-block secrets. Supports JSON5 config and dotenv files.
- `opencode` — imports from `~/.opencode.json` (home, XDG, or local project).
  Maps provider API keys and the coder agent model.
- `aider` — imports from `~/.aider.conf.yml` (home or project) and `.env`.
  Maps API keys and model from YAML and dotenv with litellm model ID
  remapping.
- `nemoclaw` — imports from `~/.nemoclaw/config.json`. Resolves credentials
  from the env var named in `credentialEnv`. Maps Anthropic, OpenAI, Gemini,
  and Ollama endpoints.

The import flow:
1. Discovers the source config on disk
2. Shows a preview table of mapped fields (secrets redacted) and skipped
   surfaces with reasons
3. Asks for confirmation before writing
4. Writes Carapace config with restricted file permissions and secret
   encryption

Use `--force` to overwrite an existing Carapace config.

After import, run `cara verify` to validate the imported providers work.

### `cara verify`
Run first-run outcome checks with pass/fail output and next-step guidance.

```bash
cara verify --outcome auto --port 18789
```

Autonomy scenario:

```bash
cara verify --outcome autonomy --port 18789
```

Outcomes:
- `auto` — infer from current config
- `local-chat` — local reachability + one non-interactive `chat.send` roundtrip
- `hooks` — signed `POST /hooks/wake` with configured token
- `discord` / `telegram` — credential validity + outbound send-path verification
- `autonomy` — creates a durable objective task and verifies start proof
  (`attempts > 0`) plus terminal proof (`done` or `blocked`)

Options:
- `--port` / `-p` — local service port (default: config or `18789`)
- `--discord-to <channel_id>` — required for Discord send-path verification
- `--telegram-to <chat_id>` — required for Telegram send-path verification

Notes:
- `cara verify` currently targets local loopback only (`127.0.0.1`)
- Discord/Telegram verification sends a real test message
- Hooks verification may trigger a real agent run
- Autonomy verification submits a real task to the task queue

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

### `cara plugins`
Inspect runtime plugin status and manage installed plugins.

#### `cara plugins status`
Fetch plugin activation state via WebSocket (`plugins.status`).

```bash
cara plugins status --strict
```

Useful flags:
- `--json` — print JSON instead of human-readable output
- `--name <name>` — filter by configured plugin name
- `--plugin-id <id>` — filter by instantiated plugin ID
- `--source <managed|config>` — filter by activation source
- `--state <active|disabled|ignored|failed>` — filter by activation state
- `--only-failed` — show only failed plugin entries
- `--strict` — exit nonzero if activation errors exist, the filtered result is empty, or any returned plugin is not `active`

#### `cara plugins bins`
List managed plugin binary names tracked on disk (`plugins.bins`).

```bash
cara plugins bins
```

Use `--json` to print the raw response payload.

#### `cara plugins install`
Install a managed plugin (`plugins.install`).

```bash
cara plugins install demo-plugin --url https://example.com/demo-plugin.wasm
```

Local file workflow:

```bash
cara plugins install demo-plugin --file ./target/wasm32-wasip1/release/demo_plugin.wasm
```

Options:
- exactly one of `--url <url>` or `--file <path>` is required
- `--version <version>` — optional version string stored in the managed manifest
- `--publisher-key <key>` — optional publisher key to record with the managed artifact
- `--signature <signature>` — optional detached signature to record with the managed artifact
- `--json` — print the raw response payload

Notes:
- `--file` is local-only and stages the file into `state_dir/plugins/<name>.wasm` before calling `plugins.install`
- `--file` is intended for direct loopback targets; SSH port-forwarded remotes are not a supported workflow
- If the follow-up `plugins.install` request fails, the CLI restores the previous local managed artifact state when possible and reports the recovery action explicitly
- If `plugins.install` succeeds but the CLI cannot remove its local `.cli-backup` / `.cli-lock` staging files, the command exits nonzero and tells you to recover or remove those files before the next local `--file` mutation
- If a previous local `--file` install/update was interrupted and left `.cli-backup` or `.cli-lock` files under `state_dir/plugins`, the CLI fails closed instead of mutating plugin files again; verify that no other local file-based plugin mutation is still running, inspect the PID recorded in `.cli-lock` if needed, remember that PID values may have been recycled if the original process crashed, restore from the `.cli-backup` file if needed, remove stale `.cli-backup` / `.cli-lock` files, and then retry
- `--publisher-key` and `--signature` are recorded at install/update time; signature verification happens later at plugin load time according to `plugins.signature` policy
- managed plugin installs still require a Carapace restart before activation
- remote hosts use the same TLS/plaintext flags as `cara logs`

#### `cara plugins update`
Update a managed plugin (`plugins.update`).

```bash
cara plugins update demo-plugin --url https://example.com/demo-plugin.wasm
```

Local file workflow:

```bash
cara plugins update demo-plugin --file ./target/wasm32-wasip1/release/demo_plugin.wasm
```

`cara plugins update` accepts the same flags as `cara plugins install`.
If `--file` is used, the CLI stages the file into `state_dir/plugins/<name>.wasm`
and the server adopts that managed artifact on update. Managed plugin updates
still require restart before the new artifact becomes active. If the update
request fails after local staging, the CLI restores the previous local managed
artifact state when possible and reports the recovery action explicitly. If
`plugins.update` succeeds but the CLI cannot remove its local `.cli-backup` /
`.cli-lock` staging files, the command exits nonzero and tells you to recover
or remove those files before the next local `--file` mutation. If a
previous local `--file` install/update was interrupted and left `.cli-backup`
or `.cli-lock` files under `state_dir/plugins`, the CLI fails closed instead of
mutating plugin files again; verify that no other local file-based plugin
mutation is still running, inspect the PID recorded in `.cli-lock` if needed,
remember that PID values may have been recycled if the original process
crashed, restore from the `.cli-backup` file if needed, remove stale
`.cli-backup` / `.cli-lock` files, and then retry.

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

### `cara task`
Manage durable objective tasks through the control API.

```bash
cara task create --payload '{"kind":"agentTurn","message":"summarize recent logs"}'
cara task list --state queued --limit 20
cara task get <task_id>
cara task cancel <task_id> --reason "operator cancelled"
cara task retry <task_id> --delay-ms 60000 --reason "transient provider error"
cara task resume <task_id> --reason "operator approved continuation"
cara task update <task_id> --max-attempts 3 --reason "tighten retry budget"
```

Policy flags on `create` and `update` map to durable task budgets:
`--max-attempts`, `--max-total-runtime-ms`, `--max-turns`, and
`--max-run-timeout-seconds`.

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

`cara backup` writes a `.tar.gz` archive with a Carapace marker and the
operator state sections currently handled by the CLI: `sessions`, `config`,
`memory`, `cron`, `tasks`, and `usage` when those files/directories exist.
Restore validates the marker and rejects path traversal entries before writing.

The archive does not export secrets from the OS credential store,
`auth_profiles.json`, managed plugin binaries, node/device pairing registries,
or other state-dir files that are outside those sections. Keep provider
recovery material available or re-enroll credentials after moving to a new
machine.

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

- Stored in the OS credential store when available
- Falls back to `{state_dir}/device-identity.json` with owner-only file
  permissions when the credential store is unavailable, locked, or denied
- A service-issued `connect.challenge` nonce is signed and sent in `connect`

Set `CARAPACE_DEVICE_IDENTITY_STRICT=1` to fail instead of using the file-backed
device identity fallback.

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
