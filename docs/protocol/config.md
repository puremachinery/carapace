# Config File Format

This document describes the config file format as implemented by the carapace
gateway. The format is compatible with the original Node.js openclaw gateway.

## File Location

Default config path:

- Uses the platform config directory (e.g. `~/.config/carapace` on Linux,
  `~/Library/Application Support/carapace` on macOS, `%APPDATA%\\carapace` on Windows).
- `~/.config/carapace/carapace.json5` (falls back to `.json` if `.json5` does not exist)
- If `CARAPACE_STATE_DIR` is set, defaults to `${CARAPACE_STATE_DIR}/carapace.json5` (falls back to `.json`)
- Override with `CARAPACE_CONFIG_PATH`

The file is parsed as **JSON5** (comments, trailing commas allowed).

## Load Order

1. Read config file (JSON5).
2. Resolve `$include` directives (see below).
3. Apply `env` entries into `process.env` **before** substitution.
4. Substitute `${VAR}` references in string values.
5. Validate against the schema.
6. Apply defaults.
7. Normalize paths.
8. Apply runtime overrides.

If validation fails, the gateway logs errors and falls back to `{}`.

## `$include` Directive

Use `$include` to compose configs from multiple files.

```json5
{
  "$include": "./base.json5",
  "gateway": { "bind": "loopback" }
}
```

Rules:

- `$include` accepts a string path or an array of paths.
- Paths are resolved relative to the including file.
- If the object contains **only** `$include`, the included content replaces the object.
- If the object has sibling keys, the included content **must be an object** and is merged with siblings.
- **Deep merge** rules: objects merge recursively, arrays concatenate, primitives override.
- Maximum include depth: **10**.
- Circular includes throw a `CircularIncludeError`.

## Environment Variable Substitution

String values may include `${VAR}` placeholders.

```json5
{
  "models": {
    "providers": {
      "openai": { "apiKey": "${OPENAI_API_KEY}" }
    }
  }
}
```

Rules:

- Only uppercase names matching `[A-Z_][A-Z0-9_]*` are substituted.
- Missing env vars throw `MissingEnvVarError` and fail config load.
- Escape with `$${VAR}` to output a literal `${VAR}`.
- Substitution happens **after** `$include` resolution.

### `env` injection

`config.env` can populate `process.env` before substitution:

```json5
{
  "env": {
    "vars": { "OPENAI_API_KEY": "sk-..." },
    "SOME_FLAG": "1",
    "shellEnv": { "enabled": true }
  }
}
```

- `env.vars` is a map of key → value.
- Any other string fields under `env` (excluding `vars` and `shellEnv`) are also exported.

## Schema: Top-Level Keys

All keys are optional. Unknown keys are rejected (strict schema).

- `meta` – config metadata (last touched version/time)
- `env` – env injection + shell env fallback settings
- `wizard` – onboarding metadata
- `diagnostics` – diagnostics and OpenTelemetry settings
- `logging` – logging levels, format, redaction
- `update` – update channel and check‑on‑start
- `browser` – browser control config and profiles
- `ui` – Control UI identity settings
- `auth` – auth profiles and provider order
- `models` – provider/model catalog overrides
- `nodeHost` – node browser proxy settings
- `agents` – agents list, defaults, runtime caps
- `tools` – tool policy + tool configuration
- `bindings` – key bindings and shortcuts
- `broadcast` – agent broadcast configuration
- `audio` – audio config (input/output)
- `media` – media handling options
- `messages` – messaging behavior defaults
- `commands` – command policy/config
- `approvals` – exec approval settings
- `sessions` – session behavior (retention, cleanup)
- `cron` – cron scheduler settings
- `hooks` – HTTP hooks config
- `web` – web provider settings (WhatsApp Web)
- `channels` – per-channel configs
- `discovery` – gateway discovery settings
- `canvasHost` – canvas host server settings
- `talk` – TTS/voice settings
- `gateway` – gateway server settings
- `skills` – skills registry settings
- `plugins` – plugin load/allowlist/config
- `venice` – Venice AI provider settings (apiKey, baseUrl)
- `classifier` – inbound message classifier (mode, model, blockThreshold)
- `signal` – Signal channel settings (via signal-cli REST API)
- `telegram` – Telegram Bot API settings (botToken, baseUrl, webhookSecret)
- `discord` – Discord Bot API settings (botToken, baseUrl, gatewayEnabled, gatewayIntents, gatewayUrl)
- `slack` – Slack Web API settings (botToken, baseUrl, signingSecret)

### Notable subkeys

This is a condensed map; refer to the JSON schema for full detail.

- `gateway`
  - `port`, `mode`, `bind`, `controlUi`, `auth`, `trustedProxies`, `tailscale`, `remote`, `reload`, `tls`, `http.endpoints`, `nodes`
- `hooks`
  - `enabled`, `path`, `token`, `maxBodyBytes`, `mappings`, `gmail`, `internal`
- `browser`
  - `enabled`, `controlUrl`, `cdpUrl`, `profiles` (names must match `/^[a-z0-9-]+$/`)
- `plugins`
  - `enabled`, `allow`, `deny`, `load.paths`, `slots`, `entries`, `installs`
- `auth`
  - `profiles`, `order`, `cooldowns`
- `venice`
  - `apiKey`, `baseUrl`
- `classifier`
  - `enabled`, `mode` (`off` | `warn` | `block`), `model`, `blockThreshold`
- `sessions`
  - `retention.enabled`, `retention.days`, `retention.intervalHours`
  - Legacy: `sessions.retentionDays`, `session.retention.*`
- `telegram`
  - `webhookSecret` (required for inbound webhooks; validates `X-Telegram-Bot-Api-Secret-Token`)
- `discord`
  - `gatewayEnabled` (connect to the Gateway for inbound messages)
  - `gatewayIntents` (intents bitmask, default includes MESSAGE_CONTENT)
  - `gatewayUrl` (override Gateway URL)
- `slack`
  - `signingSecret` (validates Events API signatures)

## Defaults

Defaults are applied after validation. Key defaults include:

- `messages.ackReactionScope`: `"group-mentions"`
- `logging.redactSensitive`: `"tools"`
- `agents.defaults.maxConcurrent`: `DEFAULT_AGENT_MAX_CONCURRENT`
- `agents.defaults.subagents.maxConcurrent`: `DEFAULT_SUBAGENT_MAX_CONCURRENT`
- `agents.defaults.compaction.mode`: `"safeguard"`
- `agents.defaults.contextPruning.mode`: `"cache-ttl"` (when anthropic auth is detected)
  - `contextPruning.ttl`: `"1h"`
  - `agents.defaults.heartbeat.every`: `"30m"` or `"1h"` depending on auth mode
- Model defaults when defined in `models.providers.*.models`:
  - `reasoning`: `false`
  - `input`: `["text"]`
  - `cost`: `{ input: 0, output: 0, cacheRead: 0, cacheWrite: 0 }`
  - `contextWindow`: `DEFAULT_CONTEXT_TOKENS`
  - `maxTokens`: `min(8192, contextWindow)`
- `talk.apiKey` may be injected from the environment if missing.

## Validation Rules (Highlights)

- Schema is strict: unknown keys are rejected.
- Duplicate agent directories are rejected.
- `agents.list[].identity.avatar` must be workspace‑relative or http(s)/data URI.
- `plugins.allow/deny/entries/slots` must reference known plugin IDs.
- `channels` keys must map to known channel IDs.
- `browser.profiles` names must be `^[a-z0-9-]+$` and must set `cdpPort` or `cdpUrl`.

## Errors

- JSON5 parse errors produce an invalid config snapshot.
- `$include` errors raise `ConfigIncludeError` / `CircularIncludeError`.
- Missing env vars in `${VAR}` substitution raise `MissingEnvVarError`.
