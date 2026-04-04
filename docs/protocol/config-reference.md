# Carapace Configuration Guide

This document is a source-grounded, plain-English guide to the most commonly tuned **Carapace** configuration sections.

For raw load/validation semantics, the current top-level key list, and a runnable example config, use:

- [`docs/protocol/config.md`](config.md)
- [`config.example.json5`](../../config.example.json5)

## Where to Put Your Configuration

Your main configuration file is placed securely on your computer depending on your operating system:

- **Linux:** `~/.config/carapace/carapace.json5`
- **macOS:** `~/Library/Application Support/carapace/carapace.json5`
- **Windows:** `%APPDATA%\\carapace\\carapace.json5`

You can explicitly set a custom folder by changing the `CARAPACE_STATE_DIR` or the full path via `CARAPACE_CONFIG_PATH` environment variables. The file is written in **JSON5**, which means you can safely use comments (like `// this is a comment`) and aren't heavily penalized for trailing commas or unquoted keys. If a `carapace.json5` file is not found at the expected location, Carapace will automatically fall back to loading `carapace.json` from the same directory.

---

## 1. Gateway (Server & Connection Settings)

This section controls how the internal Carapace server connects to the outside world, your local network, or other applications.

- **`gateway.port`**
  - *What it does:* The network port the gateway server runs on.
  - *Possible values:* Any integer from `1` to `65535`. (Default: `18789`)
- **`gateway.bind`**
  - *What it does:* Determines which networks can access the gateway.
  - *Possible values:*
    - `"loopback"` (Default) - Only allows connections from this computer (binds to `127.0.0.1` / `localhost`).
    - `"lan"` - Opens access to people on your local network.
    - `"auto"` - Currently behaves like `"all"` / `"0.0.0.0"` and listens on all network interfaces. This is convenient for development but less secure than `"loopback"` because it exposes the gateway on every reachable interface.
    - `"tailnet"` - Exposes the gateway over a Tailscale VPN only.
    - `"all"` / `"0.0.0.0"` - Explicitly listen on all network interfaces (same behavior and security considerations as `"auto"`).
    - `"localhost"` / `"local"` - Aliases for `"loopback"`.
    - `"local-network"` - Alias for `"lan"`.
    - `"tailscale"` / `"ts"` - Aliases for `"tailnet"`.
    - Or any specific IP address like `"127.0.0.1"`.
- **`gateway.auth`**
  - *What it does:* Decides how external programs prove they're allowed to connect.
  - *Possible values:*
    - `mode`:
      - `"none"` - Disables additional gateway-level authentication but still only permits direct connections from the local machine. Non-local-direct requests are rejected, so this does not allow unauthenticated remote access even if `gateway.bind` exposes the gateway on the network.
      - `"local"` - Currently behaves the same as `"none"`: it only allows direct local connections and rejects non-local-direct requests unless another trusted path (for example Tailscale auth) succeeds.
      - `"token"` - Uses a generated secret API token for authentication.
      - `"password"` - Uses a standard password for authentication.
    - `token`: The secret text token string you specify (e.g., `"${CARAPACE_GATEWAY_TOKEN}"`).
    - `password`: A password string you specify (e.g., `"${CARAPACE_GATEWAY_PASSWORD}"`).
    - `allowTailscale`:
      - `true` - Permits connections that are already safely authenticated through Tailscale VPN.
      - `false` - Still requires the configured auth mode (for example, token/password) even if the connection is over Tailscale.
      - *Default / implicit behavior:* If you do not set this explicitly, behavior differs by server path. The HTTP gateway currently defaults this to `false`. The WebSocket path currently auto-allows Tailscale-authenticated connections when `gateway.tailscale.mode = "serve"` and the auth mode is not `password`. Set this explicitly to `true` or `false` for predictable security.
- **`gateway.reload`**
  - *What it does:* Setting for hot-reloading configurations when you save changes to the file.
  - *Possible values:*
    - `mode`:
      - `"hot"` - Reloads the configuration instantly without dropping active connections.
      - `"hybrid"` (Default) - Reloads instantly where possible, but safely restarts components that require a full reset.
      - `"off"` - Disables automatic configuration reloading completely.
    - `debounceMs`: Integer. The waiting time in milliseconds before applying reloads. (Default: `300`)
- **`gateway.controlUi`**
  - *What it does:* Exposes a web-based dashboard and control panel.
  - *Possible values:*
    - `enabled`:
      - `true` - Turns on the dashboard.
      - `false` - Turns off the dashboard.
    - `path`: String. Represents the file system directory where UI assets live (e.g. `"dist/control-ui"`).
    - `basePath`: String. Base URL path to mount the UI on the web server.
    - `allowInsecureAuth`:
      - `true` - Lets the Control UI satisfy the pairing check with token/password auth instead of requiring a local device identity.
      - `false` - Keeps the normal device-identity requirement unless `dangerouslyDisableDeviceAuth` is also enabled.
    - `dangerouslyDisableDeviceAuth`:
      - `true` - Disables the device-auth pairing path for the Control UI.
      - `false` - Leaves device-auth pairing available.
- **`gateway.hooks`**
  - *What it does:* Set up incoming webhook URLs for sending commands directly via API.
  - *Possible values:*
    - `enabled`:
      - `true` - Turns on webhooks.
      - `false` - Turns off webhooks.
    - `path`: String. The specific web address path to receive webhooks. (Default: `"/hooks"`)
    - `token`: String. Your custom security password/token required for incoming hooks.
    - `maxBodyBytes`: Integer. The maximum file size of a webhook in bytes. (Default: `262144` bytes or 256 KB)
- **`gateway.ws`** (WebSockets)
  - *What it does:* Limits how fast socket connections can send messages.
  - *Possible values:*
    - `messageRate`: Positive decimal number. The permitted persistent amount of messages per second.
    - `messageBurst`: Positive integer. The maximum allowed burst of messages sent at once.
- **`gateway.tailscale`**
  - *What it does:* Enables direct VPN networking for Carapace.
  - *Possible values:*
    - `mode`:
      - `"off"` - Disables Tailscale integration.
      - `"serve"` - Securely serves the gateway over your private Tailscale VPN network.
      - `"funnel"` - Exposes the gateway to the public internet via Tailscale Funnel, while still running over your Tailscale connection.
    - `externalPort`: Integer. The external port to expose when using Tailscale (for example with `"serve"` or `"funnel"` modes).
    - `cliPath`: String. Filesystem path to the Tailscale CLI binary to use instead of the default lookup.
    - `resetOnShutdown`:
      - `true` - Attempts to reset any Tailscale serve/funnel configuration created by Carapace when the gateway shuts down.
      - `false` - Leaves Tailscale serve/funnel configuration as-is on shutdown.
- **`gateway.remote`**
  - *What it does:* Lets your Carapace installation connect outward to remote gateway installations.
  - *Possible values:*
    - `enabled`: `true` (activate remote connection) or `false` (disable remote connection).
    - `authToken`: String. The token verifying your identity to the remote server.
    - `autoReconnect`: `true` (automatically try to connect if disconnected) or `false`.
    - `reconnectIntervalMs`: Integer. How many milliseconds to wait before retrying a connection.
    - `maxReconnectAttempts`: Integer. The maximum number of failed attempts before giving up.
    - `gateways`: An array (list) of connection objects. Each gateway object can include:
      - `name`: String. A human-readable label for this remote gateway.
      - `url`: String. The WebSocket URL for the remote gateway (e.g., `"wss://example.com/gateway"`).
      - `autoConnect`: Boolean. Whether Carapace should automatically establish this connection on startup.
      - `fingerprint`: String (optional). A pinned certificate fingerprint used for TOFU (trust-on-first-use) style verification.
      - `ssh`: Object (optional). Settings for tunneling the remote gateway over SSH instead of connecting directly:
        - `host`: String. SSH server hostname or IP address.
        - `port`: Integer. SSH server port. (Default is typically `22` if omitted.)
        - `user`: String. SSH username to authenticate as.
        - `remotePort`: Integer. Remote port on the SSH server that exposes the gateway service.
- **`gateway.tls`**
  - *What it does:* Configures standard HTTPS (TLS) for encrypting traffic to the gateway. We recommend reviewing the [Security documentation](../security.md) for more setup guidance.
  - *Possible values:*
    - `enabled`: `true` (enforce HTTPS) or `false` (plain HTTP).
    - `autoGenerate`: `true` (automatically generate a self-signed certificate and key) or `false` (use the provided certificate files).
    - `certPath`: String. Filesystem path to the server certificate presented to clients.
    - `keyPath`: String. Filesystem path to the private key that matches `certPath`.
- **`gateway.mtls`**
  - *What it does:* Configures mutual TLS (mTLS), where both server and client authenticate using certificates. Used for higher-assurance deployments and automated clients.
  - *Possible values:*
    - `enabled`: `true` (enable mTLS processing for incoming connections) or `false`.
    - `requireClientCert`: `true` (clients must present a valid certificate) or `false` (allow connections without a client certificate, while still supporting those that present one).
    - `caCert`: String. Filesystem path to the CA certificate or bundle used to validate client certificates.
    - `nodeCert`: String. Filesystem path to the certificate the gateway presents when doing mTLS.
    - `nodeKey`: String. Filesystem path to the private key corresponding to `nodeCert`.
    - `crlPath`: String. Optional filesystem path to a certificate revocation list used when validating client certificates.
- **`gateway.trustedProxies`**
  - *What it does:* Recognizes traffic originating from trusted forwarders (like Nginx) to securely read real IP addresses.
  - *Possible values:* A list of IP addresses (e.g. `["127.0.0.1", "::1"]`).

---

## 2. Agents (AI Behavior & Capability Limits)

This block shapes how smart your AI behaves and what limits apply during execution.

- **`agents.list`**
  - *What it does:* An array of specific agent configurations. You can define multiple distinct personas or special-purpose agents here.
  - *Possible values:* A list of objects containing keys such as:
    - `id`: String. A unique name for this agent (e.g., `"coder"`, `"researcher"`).
    - `default`: Boolean. Set to `true` to make this the primary agent used if no ID is specified. (Default: `false`)
    - `identity.name`: String. Human-visible display name for the agent.
    - `identity.description`: String. Short summary shown in UIs or listings.
    - `identity.avatar`: String. Workspace-relative path or `http(s)` / `data:` URI used as the agent avatar.
    - `model`: String. The exact LLM name used by this agent, determining both the underlying model and the provider.
      - **Provider Routing:** Every model requires a canonical `provider:model` colon prefix: `anthropic:model`, `openai:model`, `gemini:model`, `vertex:model`, `bedrock:model`, `ollama:model`, `codex:model`, `venice:model`, `claude-cli:model`. Bare model names without a prefix are rejected, except for bare `claude-cli` which means "use the Claude CLI default model."
    - `system`: String. The system prompt or core identity instructions for this agent.
    - `maxTurns`: Integer. Maximum LLM round-trips allowed per single user request. (Default: `25`)
    - `maxTokens`: Integer. Maximum output tokens the LLM is permitted to generate in one response. (Default: `8192`)
    - `temperature`: Decimal. Creativity/randomness scaler.
    - `deliver`: Boolean. Whether the final message from this agent is delivered to the channel. (Default: `true`)
    - `toolPolicy`: String (`"allowlist"`, `"denylist"`, `"allowall"`) managing which tools this agent can use. (Default: `"allowall"`)
    - `exfiltrationGuard`: Boolean. If `true`, blocks tools known to be capable of sending data externally. (Default: `false`)
    - `promptGuard` / `outputSanitizer` / `sandbox` / `classifier`: These agent-specific blocks override the global `agents.*` for this entity.

- **`agents.defaults.maxConcurrent`**
  - *What it does:* Maximum number of simultaneous main AI tasks that run.
  - *Possible values:* Positive integer. (Default: `4`)
- **`agents.defaults.timeoutSeconds`**
  - *What it does:* The maximum number of seconds an agent is allowed to think before giving up on a task.
  - *Possible values:* Positive integer. (Default: `300`)
- **`agents.defaults.contextTokens`**
  - *What it does:* How much memory or text the AI can remember at once.
  - *Possible values:* Positive integer. (Default: `200000`)
- **`agents.defaults.thinkingDefault`**
  - *What it does:* Decides whether the AI is allowed extra time to reason internally before answering.
  - *Possible values:*
    - `"off"` (Default)
    - `"on"`
    - `"auto"`
- **`agents.defaults.verboseDefault`**
  - *What it does:* Controls whether internal tool and diagnostic detail is surfaced directly to the user.
  - *Possible values:*
    - `"off"` (Default)
    - `"on"`
- **`agents.defaults.blockStreamingDefault`**
  - *What it does:* Controls whether responses are streamed incrementally or delivered as one completed chunk.
  - *Possible values:*
    - `"off"` (Default)
    - `"on"`
- **`agents.defaults.subagents`**
  - *What it does:* Rules for smaller child agents that the main agent can dispatch for background work.
  - *Possible values:*
    - `maxConcurrent`: Integer. (Default: `8`)
    - `archiveAfterMinutes`: Integer. (Default: `60`)
- **`agents.defaults.compaction.mode`**
  - *What it does:* Controls how older context is compacted to make room for new conversation state.
  - *Possible values:*
    - `"safeguard"` (Default)
- **`agents.defaults.sandbox`**
  - *What it does:* OS-level sandboxing that limits what tools and background scripts can do.
  - *Possible values:*
    - `enabled`: `true` (Default) or `false`.
    - `max_cpu_seconds`: Integer. (Default: `30`)
    - `max_memory_mb`: Integer. (Default: `512`)
    - `max_fds`: Integer. (Default: `256`)
    - `allowed_paths`: Array of string paths the tool is permanently allowed to read/write to. (Default: `["/tmp", "/usr/bin", "/usr/local/bin", "/bin"]`)
    - `network_access`: Boolean. (Default: `false`)
    - `env_filter`: Array of environment variable names to allow through to the sandbox. If empty, no filter is applied and all env vars pass through.
- **`agents.defaults.classifier`**
  - *What it does:* An LLM-based pre-dispatch filter that intercepts potentially malicious inbound prompts before they execute on the main agent.
  - *Possible values:*
    - `enabled`: `true` or `false` (Default).
    - `mode`: `"off"` (Default), `"warn"`, or `"block"`.
    - `model`: String specifying the smaller model to use (Default: `"gpt-4o-mini"`).
    - `blockThreshold`: Decimal from `0.0` to `1.0`. (Default: `0.8`)
- **`agents.promptGuard`**
  - *What it does:* Enforces prompt-injection guardrails.
  - *Possible values:*
    - `enabled`: `true` or `false`
    - nested `preflight`, `tagging`, `postflight`, and `config_lint` sub-sections with their own `enabled` flags
- **`agents.outputSanitizer`**
  - *What it does:* Scrubs unsafe output before it reaches users.
  - *Possible values:*
    - `sanitizeHtml`: `true` or `false`
    - `cspPolicy`: String representing a Content Security Policy

---

## 3. Providers & LLMs (Common Provider Settings)

These are the most commonly used provider sections for first-run setup and day-1 operation.

- **`anthropic`**, **`openai`**, **`venice`**
  - *What it does:* Connects directly to commercial AI clouds like Claude, ChatGPT, or Venice.
  - *Common values:*
    - `apiKey`: Secret credential string, often sourced from an environment variable like `"${OPENAI_API_KEY}"`.
    - `baseUrl`: String. Useful if passing through an enterprise proxy or alternate endpoint.
- **`anthropic`**
  - *Additional values:*
    - `authProfile`: String. Name of a stored Anthropic setup-token profile under `auth.profiles` (alternative to `apiKey`).
  - *Behavior notes:*
    - `cara setup --provider anthropic --auth-mode setup-token` writes `anthropic.authProfile`.
    - Anthropic setup-token mode requires `CARAPACE_CONFIG_PASSWORD` so the stored token stays encrypted at rest.
    - If both `anthropic.apiKey` and `anthropic.authProfile` are present, runtime prefers `apiKey`.
- **`openai`**
  - *Additional values:*
    - `httpReferer`: String. Sends the `HTTP-Referer` header to OpenAI-compatible backends that use it for app identification or routing.
    - `title`: String. Sends the `X-Title` header to OpenAI-compatible backends that use it for app identification.
- **`google`**
  - *What it does:* Connects to Gemini.
  - *Common values:*
    - `apiKey`: Secret credential string, often sourced from `GOOGLE_API_KEY`.
    - `authProfile`: String. Name of a stored Google OAuth profile under `auth.profiles` (alternative to `apiKey`).
    - `baseUrl`: String. Useful for alternate endpoints or proxies.
- **`codex`**
  - *What it does:* Connects to Codex using a stored OpenAI auth profile instead of an API key.
  - *Common values:*
    - `authProfile`: String. Name of a stored OpenAI OAuth profile under `auth.profiles`.
  - *Behavior notes:*
    - This is separate from the API-key `openai` provider.
    - `cara setup --provider codex` writes `codex.authProfile` and defaults the agent model to `codex:default`.
    - Codex sign-in requires `CARAPACE_CONFIG_PASSWORD` so the stored auth profile stays encrypted at rest.
- **`bedrock`**
  - *What it does:* Connects to AWS Bedrock.
  - *Common values:*
    - `region`: String. AWS region used for Bedrock runtime requests.
    - `accessKeyId`: String. AWS access key ID for request signing.
    - `secretAccessKey`: String. AWS secret key paired with `accessKeyId`.
    - `sessionToken`: String. Optional temporary-session token for STS credentials.
    - `enabled`: `true` or `false`.
- **`providers.ollama`**
  - *What it does:* Connects to local Ollama models.
  - *Common values:*
    - `baseUrl`: String endpoint address. (Default: `"http://localhost:11434"`)
    - `apiKey`: Optional authentication key if you've locked the Ollama server.
- **`vertex`**
  - *What it does:* Connects to Google Cloud Vertex AI.
  - *Common values:*
    - `projectId`: String. Your Google Cloud Project ID.
    - `location`: String. The server location region. (Default: `"us-central1"`)
    - `model`: String. The model tag.

- **`auth.profiles`**
  - *What it does:* Defines OAuth provider configuration used by Carapace auth profiles.
  - *Common values:*
    - `enabled`: `true` or `false`.
    - `redirectBaseUrl`: Base URL used to derive provider callback URLs when `redirectUri` is not set explicitly.
    - `providers.google.clientId`
    - `providers.google.clientSecret`
    - `providers.google.redirectUri`
    - `providers.openai.clientId`
    - `providers.openai.clientSecret`
    - `providers.openai.redirectUri`
    - `providers.github.clientId`
    - `providers.github.clientSecret`
    - `providers.github.redirectUri`
    - `providers.discord.clientId`
    - `providers.discord.clientSecret`
    - `providers.discord.redirectUri`

---

## 4. Local Workspace Tools

- **`filesystem`**
  - *What it does:* Enables guarded local filesystem tools so Cara can inspect,
    search, and optionally modify files inside explicit workspace roots.
  - *Common values:*
    - `enabled`: `true` or `false`. When `false` or omitted, filesystem tools are not registered.
    - `roots`: Array of absolute existing paths. Cara only serves file operations inside these roots.
    - `writeAccess`: `true` or `false`. When `true`, Cara also registers `file_write` and `file_move`.
    - `maxReadBytes`: Integer byte cap for `file_read` and per-file content matching in `file_search`. (Default: `10485760`)
    - `excludePatterns`: Array of glob patterns denied even inside allowed roots (for example `[".git", "node_modules", "*.env"]`).
  - *Behavior notes:*
    - `file_read`, `directory_list`, `file_stat`, and `file_search` register when `filesystem.enabled = true`.
    - `file_write` and `file_move` only register when `filesystem.writeAccess = true`.
    - Invalid filesystem config normally fails startup with schema errors. Runtime tool registration also fail-closes and disables the tool set if malformed config somehow bypasses validation.
    - Filesystem tool registration happens at startup; changing `filesystem.*` requires restart.

---

## 5. Channels (Common Messaging Integrations)

Enable Carapace to listen and respond on external chat platforms.

- **`signal`**
  - *What it does:* Uses `signal-cli` REST integration.
  - *Common values:*
    - `baseUrl`: String address to the REST wrapper.
    - `phoneNumber`: String. Your registered number (like `"+15551234567"`).
    - `enabled`: `true` or `false`.
- **`telegram`**
  - *What it does:* Connects a Telegram bot.
  - *Common values:*
    - `botToken`: String from BotFather.
    - `webhookSecret`: String used to validate inbound webhook updates.
    - `baseUrl`: String. Replaces the default Telegram endpoint.
    - `enabled`: `true` or `false`.
- **`discord`**
  - *What it does:* Connects Carapace to Discord.
  - *Common values:*
    - `botToken`: String. Your Discord bot token.
    - `gatewayEnabled`: `true` to connect via WebSocket.
    - `gatewayIntents`: Integer bitmask.
    - `gatewayUrl`: String.
    - `baseUrl`: String.
    - `enabled`: `true` or `false`.
- **`slack`**
  - *What it does:* Connects Carapace to Slack.
  - *Common values:*
    - `botToken`: String starting with `xoxb-`.
    - `signingSecret`: String used to validate Slack Events requests.
    - `baseUrl`: String.
    - `enabled`: `true` or `false`.

---

## 6. Security, Sessions, and Operations

- **`sessions`**
  - *What it does:* Governs how long the system remembers long-running chat history and whether it gets automatically purged.
  - *Common values:*
    - `retention.enabled`: `true` or `false`. (Default: `true`)
    - `retention.days`: Integer. (Default: `30`)
    - `retention.intervalHours`: Integer. (Default: `6`)
    - `integrity.enabled`: `true` or `false`. (Default: `true`)
    - `integrity.action`: `"warn"` (Default) or `"reject"`.
- **`session`**
  - *What it does:* Governs active chat/session scoping behavior and provides a legacy/global fallback for channel typing.
  - *Common values:*
    - `scope`: `"per-sender"` (Default), `"global"`, or `"per-channel-peer"`.
    - `dmScope`: `"main"` (Default).
    - `typingMode`: `"thinking"` (Default session value; legacy/global channel-typing fallback only when explicitly set in config, and it applies across all typing-capable channels unless overridden under `channels.*.features.typing`).
    - `typingIntervalSeconds`: Integer. Seconds between typing-indicator pulses. (Default: `3`; legacy/global channel-typing fallback only when explicitly set in config, and it applies across all typing-capable channels unless overridden under `channels.*.features.typing`)
    - `mainKey`: String. Identifier for the main session slot. Always enforced as `"main"` regardless of what you set. (Default: `"main"`)
- **`channels`**
  - *What it does:* Applies per-channel override policy, including channel activity features such as typing indicators and read receipts.
  - *Common values:*
    - `defaults.features.typing.enabled`: `true` or `false`. (Default: `false`)
    - `defaults.features.typing.mode`: `"thinking"` (Default)
    - `defaults.features.typing.intervalSeconds`: Integer. (Default: `3`)
    - `defaults.features.readReceipts.enabled`: `true` or `false`. (Default: `false`)
    - `defaults.features.readReceipts.mode`: `"after-response"` (Default)
    - `<channel>.features.typing.*`: Per-channel override for typing behavior.
    - `<channel>.features.readReceipts.*`: Per-channel override for read receipts.
- **`logging`**
  - *What it does:* Dictates what diagnostic events are printed into terminal or backend logs.
  - *Common values:*
    - `level`: `"trace"`, `"debug"`, `"info"` (Default), `"warn"`, `"error"`.
    - `format`: `"text"` or `"json"`.
    - `consoleStyle`: String. Current default is `"pretty"`.
    - `redactSensitive`: `"tools"` (Default).
- **`plugins.sandbox`** and **`plugins.signature`**
  - *What it does:* Controls sandboxing and signature policy for downloaded plugins.
  - *Common values:*
    - `sandbox.enabled`: `true` or `false`.
    - `sandbox.defaults.allowHttp`, `allowCredentials`, `allowMedia`: `true` or `false`.
    - `signature.enabled`, `signature.requireSignature`: `true` or `false`.
    - `signature.trustedPublishers`: Array of hex-encoded Ed25519 public keys.
- **`cron`**
  - *What it does:* Schedules automated jobs.
  - *Common values:*
    - `enabled`: `true` or `false`.
    - `maxConcurrentRuns`: Integer.
    - `entries`: Array of cron job objects.
- **`usage`**
  - *What it does:* Tracks and prices model usage.
  - *Common values:*
    - `pricing.default.inputCostPerMTok`
    - `pricing.default.outputCostPerMTok`
    - `pricing.overrides[]` with `match`, `matchType`, `inputCostPerMTok`, and `outputCostPerMTok`
- **`plugins`**
  - *What it does:* Loads and manages WASM plugins.
  - *Common values:*
    - `enabled`: `true` or `false`.
    - `load.paths`: Array of explicit dev/advanced plugin directories.
  - *Notes:*
    - Managed plugin installs live under `state_dir/plugins` and are activated on restart.
    - Managed plugin installs require `plugins-manifest.json` entries with pinned `sha256` values.
    - `plugins.load.paths` is an explicit dev/advanced path and does not use the managed plugin manifest `sha256` pinning flow; treat those directories as trusted local inputs.
    - `plugins.enabled = false` disables both managed plugin activation and configured `load.paths`.
    - Plugin components must target the current WIT package namespace `carapace:plugin@1.0.0`.
    - For plugin authoring and the supported local development workflow, see [Plugin Development](../plugin-development.md).
- **`messages`**
  - *What it does:* Messaging behavior defaults.
  - *Common values:*
    - `ackReactionScope`: `"group-mentions"`.

---

## Additional Config Areas

Carapace supports more configuration than this guide covers. If you need the broader surface area, check the current protocol docs and example config for:

- `models`
- `tools`
- `bindings`
- `broadcast`
- `audio`
- `media`
- `commands`
- `approvals`
- `web`
- `channels`
- `discovery`
- `canvasHost`
- `nodeHost`
- `meta`
- `env`
- `gateway.openai` for enabling the OpenAI-compatible `/v1/chat/completions` and `/v1/responses` endpoints
- `browser`
- `talk`

## Validation Rules (Highlights)

- Unknown top-level keys produce schema warnings; they do not, by themselves, abort startup.
- Duplicate agent directories are rejected.
- `agents.list[].identity.avatar` must be workspace-relative or http(s)/data URI.
- `plugins.entries.<plugin-id>` may only contain `enabled`, `installId`, and `requestedAt`.
- `channels` keys must map to known channel IDs.
- `browser.profiles` names must be `^[a-z0-9-]+$` and must set `cdpPort` or `cdpUrl`.

## Errors

- JSON5 parse errors produce an invalid config snapshot.
- `$include` errors raise `ConfigIncludeError` / `CircularIncludeError`.
- Missing env vars in `${VAR}` substitution raise `MissingEnvVarError`.
