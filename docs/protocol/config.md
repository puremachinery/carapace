# Config File Format

This document describes the config file format used by Carapace.

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
5. Apply defaults.
6. Validate against the schema.
7. Normalize paths.
8. Apply runtime overrides.

If validation fails, Carapace logs errors and falls back to `{}`.

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

All keys are optional. Unknown top-level keys produce schema warnings; they do
not, by themselves, abort startup.

For a plain-English guide to the most commonly tuned sections, see
[`docs/protocol/config-reference.md`](config-reference.md).

- `meta` – config metadata (last touched version/time)
- `env` – env injection + shell env fallback settings
- `wizard` – onboarding metadata
- `diagnostics` – diagnostics and OpenTelemetry settings
- `logging` – logging levels, format, redaction
- `update` – update channel and check‑on‑start
- `browser` – browser control config and profiles
- `ui` – Control UI identity settings
- `auth` – auth profile provider configuration and OAuth callback settings
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
- `session` – session defaults plus legacy/global typing fallback (`scope`, `dmScope`, `typingMode`, `typingIntervalSeconds`, `mainKey`)
- `sessions` – session behavior (retention, cleanup)
- `usage` – usage tracking configuration (pricing overrides)
- `cron` – cron scheduler settings
- `web` – web provider settings (WhatsApp Web)
- `channels` – per-channel overrides and activity feature policy
- `discovery` – service discovery settings
- `canvasHost` – canvas host server settings
- `talk` – TTS/voice settings
- `gateway` – service settings
- `routes` – named execution routes (`routes.<name>.model`)
- `plugins` – plugin load/allowlist/config
- `filesystem` – root-scoped filesystem tool registration and limits
- `anthropic` – Anthropic provider settings (apiKey, authProfile, baseUrl)
- `openai` – OpenAI provider settings (apiKey, baseUrl, httpReferer, title)
- `codex` – Codex/OpenAI subscription settings (`authProfile`)
- `google` – Google Gemini provider settings (`apiKey`, `authProfile`, `baseUrl`)
- `vertex` – Google Cloud Vertex AI provider settings (`projectId`, `location`, `model`)
- `providers` – provider-specific settings such as `providers.ollama`
- `bedrock` – AWS Bedrock provider settings (region, accessKeyId, secretAccessKey, sessionToken)
- `venice` – Venice AI provider settings (apiKey, baseUrl)
- `classifier` – inbound message classifier (mode, model, blockThreshold)
- `signal` – Signal channel settings (via signal-cli REST API)
- `telegram` – Telegram Bot API settings (botToken, baseUrl, webhookSecret)
- `discord` – Discord Bot API settings (botToken, baseUrl, gatewayEnabled, gatewayIntents, gatewayUrl)
- `slack` – Slack Web API settings (botToken, baseUrl, signingSecret)

### Notable subkeys

This is a condensed map; refer to the JSON schema for full detail.

- `gateway`
  - `port`, `mode`, `bind`, `controlUi`, `hooks`, `auth`, `trustedProxies`, `tailscale`, `remote`, `reload`, `tls`, `mtls`, `http.endpoints`, `nodes`
  - `controlUi`: `enabled`, `path`, `basePath`, `allowInsecureAuth`, `dangerouslyDisableDeviceAuth`
  - `mtls` – service-to-service mTLS (`enabled`, `caCert`, `nodeCert`, `nodeKey`, `crlPath`, `requireClientCert`)
  - `remote` – outbound service connections (`enabled`, `authToken`, `autoReconnect`,
    `reconnectIntervalMs`, `maxReconnectAttempts`, `gateways[]`)
    - `gateways[]` entries: `name`, `url`, `fingerprint` (TOFU pin), `autoConnect`,
      optional `ssh` (`host`, `port`, `user`, `remotePort`)
- `gateway.hooks`
  - `enabled`, `token`, `path`, `maxBodyBytes`
- `browser`
  - `enabled`, `controlUrl`, `cdpUrl`, `profiles` (names must match `/^[a-z0-9-]+$/`)
- `plugins`
  - `enabled`, `load.paths`, `entries`, `sandbox`, `signature`
- `filesystem`
  - `enabled`, `roots`, `writeAccess`, `maxReadBytes`, `excludePatterns`
- `auth`
  - `profiles.enabled`, `profiles.redirectBaseUrl`
  - `profiles.providers.{google,github,discord,openai}.{clientId,clientSecret,redirectUri}`
- `anthropic`
  - `apiKey`, `authProfile`, `baseUrl`
- `openai`
  - `apiKey`, `baseUrl`, `httpReferer`, `title`
- `codex`
  - `authProfile`
- `google`
  - `apiKey`, `authProfile`, `baseUrl`
- `providers.ollama`
  - `baseUrl`, `apiKey`
- `bedrock`
  - `region`, `accessKeyId`, `secretAccessKey`, `sessionToken`, `enabled`
- `venice`
  - `apiKey`, `baseUrl`
- `vertex`
  - `projectId`, `location`, `model`
- `classifier`
  - `enabled`, `mode` (`off` | `warn` | `block`), `model`, `blockThreshold`
- `session`
  - `scope`, `dmScope`, `typingMode`, `typingIntervalSeconds`, `mainKey`
  - `typingMode` / `typingIntervalSeconds` are legacy/global fallback for channel typing only when you explicitly set them in config; prefer `channels.defaults.features.typing` and `channels.<channel>.features.typing`
- `channels`
  - `defaults.features.typing`, `defaults.features.readReceipts`
  - `<channel>.features.typing`, `<channel>.features.readReceipts`
- `sessions`
  - `retention.enabled`, `retention.days`, `retention.intervalHours`
  - `integrity.enabled` (default `true`), `integrity.action` (`warn` | `reject`, default `warn`)
  - `encryption.mode` (`off` | `if_password` | `required`) – session encryption at rest with `.crypto-manifest` recovery metadata; no in-place rekey
  - Legacy: `sessions.retentionDays`, `session.retention.*`
- `logging`
  - `level`, `format`, `consoleStyle`, `redactSensitive`
- `cron`
  - `enabled`, `maxConcurrentRuns`, `entries[]`
- `usage`
  - `pricing.default` – fallback pricing (`inputCostPerMTok`, `outputCostPerMTok`)
  - `pricing.overrides[]` – per-model overrides (`match`, `matchType`, `inputCostPerMTok`, `outputCostPerMTok`)
- `telegram`
  - `webhookSecret` (required for inbound webhooks; validates `X-Telegram-Bot-Api-Secret-Token`)
- `discord`
  - `gatewayEnabled` (connect to the Discord Gateway for inbound messages)
  - `gatewayIntents` (intents bitmask, default includes MESSAGE_CONTENT)
  - `gatewayUrl` (override Discord Gateway URL)
- `slack`
  - `signingSecret` (validates Events API signatures)

### Anthropic credential modes

Anthropic can authenticate in either of these ways:

- `anthropic.apiKey` or `ANTHROPIC_API_KEY`
- `anthropic.authProfile` pointing at a stored Anthropic setup-token profile under `auth.profiles`

If both are present, runtime prefers the API-key path and setup assessment
surfaces that dual configuration explicitly.

Example API-key config:

```json5
{
  "anthropic": {
    "apiKey": "${ANTHROPIC_API_KEY}"
  }
}
```

Example setup-token config:

```json5
{
  "auth": {
    "profiles": {
      "enabled": true
    }
  },
  "anthropic": {
    "authProfile": "anthropic:default"
  }
}
```

Notes:

- `cara setup --provider anthropic --auth-mode setup-token` writes this shape.
- Anthropic setup-token mode requires `CARAPACE_CONFIG_PASSWORD` because the
  stored token is kept in the encrypted auth-profile store instead of config.
- `cara setup --provider anthropic --auth-mode api-key` keeps the existing
  direct API-key path.

### Gemini credential modes

Gemini can authenticate in either of these ways:

- `google.apiKey` or `GOOGLE_API_KEY`
- `google.authProfile` pointing at a stored Google OAuth profile under `auth.profiles`

If both are present, runtime prefers the API key path.

Example API-key config:

```json5
{
  "google": {
    "apiKey": "${GOOGLE_API_KEY}"
  }
}
```

Example auth-profile config:

```json5
{
  "auth": {
    "profiles": {
      "enabled": true,
      "providers": {
        "google": {
          "clientId": "${GOOGLE_OAUTH_CLIENT_ID}"
        }
      }
    }
  },
  "google": {
    "authProfile": "google-abc123"
  }
}
```

`cara setup --provider gemini` can now create either shape.
Gemini Google sign-in also requires `CARAPACE_CONFIG_PASSWORD` because the
stored auth profile contains refreshable credentials and the OAuth client secret.

### Codex credential mode

Codex is separate from the API-key `openai` provider.

Codex uses:

- `codex.authProfile` pointing at a stored OpenAI auth profile under `auth.profiles`
- `auth.profiles.providers.openai.*` for OAuth client configuration

Example config:

```json5
{
  "auth": {
    "profiles": {
      "enabled": true,
      "providers": {
        "openai": {
          "clientId": "${OPENAI_OAUTH_CLIENT_ID}"
        }
      }
    }
  },
  "codex": {
    "authProfile": "openai-abc123"
  }
}
```

Notes:

- `cara setup --provider codex` writes this shape.
- Codex sign-in requires `CARAPACE_CONFIG_PASSWORD` because the stored auth
  profile contains refreshable tokens and the OAuth client secret.
- `openai` remains the API-key provider. Do not add `openai.authProfile`.
- Use explicit model routing such as `codex:default` or `codex:gpt-5.4` when you
  want to pin requests to Codex.

### `auth.profiles`

`auth.profiles` stores OAuth onboarding configuration and redirect settings used
to create stored auth profiles.

Relevant subkeys:

- `auth.profiles.enabled`
- `auth.profiles.redirectBaseUrl`
- `auth.profiles.providers.google.{clientId,clientSecret,redirectUri}`
- `auth.profiles.providers.openai.{clientId,clientSecret,redirectUri}`
- `auth.profiles.providers.github.{clientId,clientSecret,redirectUri}`
- `auth.profiles.providers.discord.{clientId,clientSecret,redirectUri}`

For Gemini onboarding:

- Control UI Google sign-in uses `/control/onboarding/gemini/callback` based on the
  current UI base URL or `auth.profiles.redirectBaseUrl`
- CLI Google sign-in uses a loopback callback on a local port (`http://127.0.0.1:<port>/auth/callback`)
- Gemini onboarding accepts the Google OAuth client secret via environment or explicit onboarding input, then stores it with the auth profile instead of persisting it in config
- `CARAPACE_CONFIG_PASSWORD` must be set when using Gemini Google sign-in so the stored auth profile is encrypted at rest
- if Google OAuth client config is unavailable, Gemini onboarding must use API-key mode

### `filesystem`

`filesystem` controls the built-in local filesystem tools.

Relevant subkeys:

- `filesystem.enabled`
- `filesystem.roots`
- `filesystem.writeAccess`
- `filesystem.maxReadBytes`
- `filesystem.excludePatterns`

Behavior:

- when `filesystem.enabled` is absent or `false`, filesystem tools are not registered
- when enabled, read-tier tools are registered:
  - `file_read`
  - `directory_list`
  - `file_stat`
  - `file_search`
- `file_write` and `file_move` are only registered when `filesystem.writeAccess = true`
- `filesystem.roots` should be absolute existing paths
- `filesystem.excludePatterns` deny matching paths even when they are inside an allowed root
- malformed filesystem config fail-closes startup with schema errors; if validation is bypassed in a runtime/test path, filesystem tool registration still disables itself rather than enabling a partial tool set
- changing `filesystem.*` requires a process restart because tool registration happens at startup
- if enabled with an empty `roots` list, the tools register but every requested path is denied

## Defaults

Defaults are applied during config loading before validation. Key defaults include:

- `messages.ackReactionScope`: `"group-mentions"`
- `logging.consoleStyle`: `"pretty"`
- `logging.redactSensitive`: `"tools"`
- `agents.defaults.maxConcurrent`: `DEFAULT_AGENT_MAX_CONCURRENT`
- `agents.defaults.timeoutSeconds`: `DEFAULT_AGENT_TIMEOUT_SECONDS`
- `agents.defaults.contextTokens`: `DEFAULT_CONTEXT_TOKENS`
- `agents.defaults.subagents.maxConcurrent`: `DEFAULT_SUBAGENT_MAX_CONCURRENT`
- `agents.defaults.subagents.archiveAfterMinutes`: `60`
- `agents.defaults.compaction.mode`: `"safeguard"`
- `session.scope`: `"per-sender"`
- `session.dmScope`: `"main"`
- `session.typingMode`: `"thinking"` (defaulted session value; legacy/global channel-typing fallback only when explicitly set in config, and applies across all typing-capable channels unless overridden under `channels.*.features.typing`)
- `session.typingIntervalSeconds`: `3` (defaulted session value; legacy/global channel-typing fallback only when explicitly set in config, and applies across all typing-capable channels unless overridden under `channels.*.features.typing`)
- `session.mainKey`: `"main"` (enforced even if another value is supplied)
- Channel typing activity defaults: typing is disabled by default; when enabled by `channels.defaults.features.typing` or `channels.<channel>.features.typing`, the default mode is `"thinking"` with a `3`-second interval.
- Channel read-receipt activity defaults: read receipts are disabled by default; when enabled by `channels.defaults.features.readReceipts` or `channels.<channel>.features.readReceipts`, Carapace sends an explicit receipt immediately after the inbound message is durably appended to the session store.
- `cron.maxConcurrentRuns`: `2`
- `gateway.port`: `18789`
- `gateway.bind`: `"loopback"`
- `gateway.reload.mode`: `"hybrid"`
- `gateway.reload.debounceMs`: `300`
- `gateway.hooks.path`: `"/hooks"`
- `gateway.hooks.maxBodyBytes`: `262144`
- `filesystem.enabled`: `false`
- `filesystem.writeAccess`: `false`
- `filesystem.maxReadBytes`: `10485760`
- `filesystem.roots`: `[]`
- `filesystem.excludePatterns`: `[]`
- `vertex.location`: `"us-central1"`
- `vertex.projectId`: omitted unless `VERTEX_PROJECT_ID` is set
- Model defaults when defined in `models.providers.*.models`:
  - `reasoning`: `false`
  - `input`: `["text"]`
  - `cost`: `{ input: 0, output: 0, cacheRead: 0, cacheWrite: 0 }`
  - `contextWindow`: `DEFAULT_CONTEXT_TOKENS`
  - `maxTokens`: `min(8192, contextWindow)`
- `talk.apiKey` may be injected from the environment if missing.
- `sessions.integrity.enabled`: `true` (HMAC key source order: `CARAPACE_SERVER_SECRET` → gateway auth secrets; keep a stable `CARAPACE_SERVER_SECRET` while unread plaintext sessions are still being touch-migrated)
- `sessions.integrity.action`: `"warn"` (missing/mismatched sidecars are advisory-only; use `"reject"` to fail closed, including encrypted-history deletion/reordering detection)

## Validation Rules (Highlights)

- Unknown top-level keys produce schema warnings; they do not, by themselves, abort startup.
- Duplicate agent directories are rejected.
- `agents.list[].identity.avatar` must be workspace‑relative or http(s)/data URI.
- `plugins.entries.<plugin-id>` may only contain `enabled`, `installId`, and `requestedAt`.
- `channels.*.features.typing.mode` currently supports `"thinking"`.
- `browser.profiles` names must be `^[a-z0-9-]+$` and must set `cdpPort` or `cdpUrl`.

## Errors

- JSON5 parse errors produce an invalid config snapshot.
- `$include` errors raise `ConfigIncludeError` / `CircularIncludeError`.
- Missing env vars in `${VAR}` substitution raise `MissingEnvVarError`.
