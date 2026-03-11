# Carapace Configuration Reference

This document provides a comprehensive, plain-English reference for every setting you can configure in **Carapace**.

## Where to Put Your Configuration

Your main configuration file is placed securely on your computer depending on your operating system:

* **Linux:** `~/.config/carapace/carapace.json5`
* **macOS:** `~/Library/Application Support/carapace/carapace.json5`
* **Windows:** `%APPDATA%\carapace\carapace.json5`

You can explicitly set a custom folder by changing the `CARAPACE_STATE_DIR` or the full path via `CARAPACE_CONFIG_PATH` environment variables. The file is written in **JSON5**, which means you can safely use comments (like `// this is a comment`) and aren't heavily penalized for trailing commas or unquoted keys.

---

## 1. Gateway (Server & Connection Settings)

This section controls how the internal Carapace server connects to the outside world, your local network, or other applications.

* **`gateway.port`**
  * *What it does:* The network port the gateway server runs on.
  * *Possible values:* Any integer from `1` to `65535`. (Default: `18789`)
* **`gateway.bind`**
  * *What it does:* Determines which networks can access the gateway.
  * *Possible values:*
    * `"loopback"` (Default) - Only allows connections from this computer (binds to `127.0.0.1` / `localhost`).
    * `"lan"` - Opens access to people on your local network.
    * `"auto"` - Currently behaves like `"all"` / `"0.0.0.0"` and listens on all network interfaces. This is convenient for development but less secure than `"loopback"` because it exposes the gateway on every reachable interface.
    * `"tailnet"` - Exposes the gateway over a Tailscale VPN only.
    * `"all"` / `"0.0.0.0"` - Explicitly listen on all network interfaces (same behavior and security considerations as `"auto"`).
    * `"localhost"` - Alias for `"loopback"`.
    * `"ts"` - Alias for `"tailnet"`.
    * Or any specific IP address like `"127.0.0.1"`.
* **`gateway.auth`**
  * *What it does:* Decides how external programs prove they're allowed to connect.
  * *Possible values:*
    * `mode`:
      * `"none"` - Disables additional gateway-level authentication. Only use this for local development or when you fully trust the network and other protections in front of Carapace.
      * `"local"` - Trusts connections that originate from the local machine or other trusted local mechanisms, without requiring a separate token/password.
      * `"token"` - Uses a generated secret API token for authentication.
      * `"password"` - Uses a standard password for authentication.
    * `token`: The secret text token string you specify (e.g., `"${CARAPACE_GATEWAY_TOKEN}"`).
    * `password`: A password string you specify (e.g., `"${CARAPACE_GATEWAY_PASSWORD}"`).
    * `allowTailscale`:
      * `true` - Permits connections that are already safely authenticated through Tailscale VPN.
      * `false` - Still requires the configured auth mode (for example, token/password) even if the connection is over Tailscale.
      * *Default / implicit behavior:* If you do not set this explicitly, Carapace may automatically allow Tailscale-authenticated connections when `gateway.tailscale.mode` is configured to serve the gateway and depending on the selected auth `mode`. For predictable security, set `allowTailscale` explicitly to `true` or `false`.
* **`gateway.reload`**
  * *What it does:* Setting for hot-reloading configurations when you save changes to the file.
  * *Possible values:*
    * `mode`:
      * `"hot"` - Reloads the configuration instantly without dropping active connections.
      * `"hybrid"` (Default) - Reloads instantly where possible, but safely restarts components that require a full reset.
      * `"off"` - Disables automatic configuration reloading completely.
    * `debounceMs`: Integer. The waiting time in milliseconds before applying reloads. (Default: `300`)
* **`gateway.controlUi`**
  * *What it does:* Exposes a web-based dashboard and control panel.
  * *Possible values:*
    * `enabled`:
      * `true` - Turns on the dashboard.
      * `false` - Turns off the dashboard.
    * `path`: String. Represents the file system directory where UI assets live (e.g. `"dist/control-ui"`).
    * `basePath`: String. Base URL path to mount the UI on the web server.
    * `allowInsecureAuth`:
      * `true` - Allows logins over unencrypted HTTP connections.
      * `false` - Requires a secure HTTPS connection to log in.
* **`gateway.hooks`**
  * *What it does:* Set up incoming webhook URLs for sending commands directly via API.
  * *Possible values:*
    * `enabled`:
      * `true` - Turns on webhooks.
      * `false` - Turns off webhooks.
    * `path`: String. The specific web address path to receive webhooks. (Default: `"/hooks"`)
    * `token`: String. Your custom security password/token required for incoming hooks.
    * `maxBodyBytes`: Integer. The maximum file size of a webhook in bytes. (Default: `262144` bytes or 256 KB)
* **`gateway.ws`** (WebSockets)
  * *What it does:* Limits how fast socket connections can send messages.
  * *Possible values:*
    * `messageRate`: Positive decimal number. The permitted persistent amount of messages per second.
    * `messageBurst`: Positive integer. The maximum allowed burst of messages sent at once.
* **`gateway.tailscale`**
  * *What it does:* Enables direct VPN networking for Carapace.
  * *Possible values:*
    * `mode`:
      * `"off"` - Disables Tailscale integration.
      * `"serve"` - Securely serves the gateway over your private Tailscale VPN network.
      * `"funnel"` - Exposes the gateway to the public internet via Tailscale Funnel, while still running over your Tailscale connection.
    * `externalPort`: Integer. The external port to expose when using Tailscale (for example with `"serve"` or `"funnel"` modes).
    * `cliPath`: String. Filesystem path to the Tailscale CLI binary to use instead of the default lookup.
    * `resetOnShutdown`:
      * `true` - Attempts to reset any Tailscale serve/funnel configuration created by Carapace when the gateway shuts down.
      * `false` - Leaves Tailscale serve/funnel configuration as-is on shutdown.
* **`gateway.remote`**
  * *What it does:* Let your Carapace installation secretly connect outward to heavily guarded server installations.
  * *Possible values:*
    * `enabled`: `true` (activate remote connection) or `false` (disable remote connection).
    * `authToken`: String. The token verifying your identity to the remote server.
    * `autoReconnect`: `true` (automatically try to connect if disconnected) or `false`.
    * `reconnectIntervalMs`: Integer. How many milliseconds to wait before retrying a connection.
    * `maxReconnectAttempts`: Integer. The maximum number of failed attempts before giving up.
    * `gateways`: An array (list) of connection objects. Each gateway object can include:
      * `name`: String. A human-readable label for this remote gateway.
      * `url`: String. The WebSocket URL for the remote gateway (e.g., `"wss://example.com/gateway"`).
      * `autoConnect`: Boolean. Whether Carapace should automatically establish this connection on startup.
      * `fingerprint`: String (optional). A pinned certificate fingerprint used for TOFU (trust-on-first-use) style verification.
      * `ssh`: Object (optional). Settings for tunneling the remote gateway over SSH instead of connecting directly:
        * `host`: String. SSH server hostname or IP address.
        * `port`: Integer. SSH server port. (Default is typically `22` if omitted.)
        * `user`: String. SSH username to authenticate as.
        * `remotePort`: Integer. Remote port on the SSH server that exposes the gateway service.
* **`gateway.tls`**
  * *What it does:* Configures standard HTTPS (TLS) for encrypting traffic to the gateway. We recommend reviewing the [Security documentation](./security.md) for more setup guidance.
  * *Possible values:*
    * `enabled`: `true` (enforce HTTPS) or `false` (plain HTTP).
    * `autoGenerate`: `true` (automatically generate a self-signed certificate and key) or `false` (use the provided certificate files).
    * `certPath`: String. Filesystem path to the server certificate presented to clients.
    * `keyPath`: String. Filesystem path to the private key that matches `certPath`.
* **`gateway.mtls`**
  * *What it does:* Configures mutual TLS (mTLS), where both server and client authenticate using certificates. Used for higher-assurance deployments and automated clients.
  * *Possible values:*
    * `enabled`: `true` (enable mTLS processing for incoming connections) or `false`.
    * `requireClientCert`: `true` (clients must present a valid certificate) or `false` (allow connections without a client certificate, while still supporting those that present one).
    * `caCert`: String. Filesystem path to the CA certificate or bundle used to validate client certificates.
    * `nodeCert`: String. Filesystem path to the certificate the gateway presents when doing mTLS.
    * `nodeKey`: String. Filesystem path to the private key corresponding to `nodeCert`.
    * `crlPath`: String. Optional filesystem path to a certificate revocation list used when validating client certificates.
* **`gateway.trustedProxies`**
  * *What it does:* Recognizes traffic originating from trusted forwarders (like Nginx) to securely read real IP addresses.
  * *Possible values:* A list of IP addresses (e.g. `["127.0.0.1", "::1"]`).

---

## 2. Agents (AI Behavior & Capability Limits)

This block shapes how smart your AI behaves, how large its memory is, and performance.

* **`agents.defaults.maxConcurrent`**
  * *What it does:* Maximum number of simultaneous main AI tasks that run.
  * *Possible values:* Positive integer. (Default: `4`)
* **`agents.defaults.timeout`**
  * *What it does:* The maximum number of seconds an agent is allowed to think before giving up on a task.
  * *Possible values:* Positive integer. (Default: `300` - aka 5 minutes)
* **`agents.defaults.contextTokens`**
  * *What it does:* How much memory or text the AI can remember at once.
  * *Possible values:* Positive integer. (Default: `200000`)
* **`agents.defaults.thinkingDefault`**
  * *What it does:* Decides whether the AI is allowed extra time to "think" or reason internally before answering.
  * *Possible values:*
    * `"off"` (Default) - Standard conversational mode with no hidden internal reasoning time.
    * `"on"` - The AI will always reason internally extensively before every reply.
    * `"auto"` - The AI automatically decides whether internal reasoning is necessary based on the complexity of your prompt.
* **`agents.defaults.verboseDefault`**
  * *What it does:* If checked, outputs massive detail on what the AI is executing mechanically under the hood.
  * *Possible values:*
    * `"off"` (Default) - Hides internal tool usage details and raw process steps.
    * `"on"` - Reveals full operational and diagnostic steps directly to the user's interface.
* **`agents.defaults.blockStreamingDefault`**
  * *What it does:* If toggled, the AI gathers its entire answer and sends it out in one massive chunk instead of typing it letter by letter.
  * *Possible values:*
    * `"off"` (Default) - Streams the text smoothly to your screen as the AI generates it.
    * `"on"` - Waits until the entire response is completed on the server before displaying it.
* **`agents.defaults.subagents`**
  * *What it does:* Rules for smaller "child" AIs that the main AI commands to do distinct background jobs.
  * *Possible values:*
    * `maxConcurrent`: Integer. The maximum amount of sub-agents permitted. (Default `8`)
    * `archiveAfterMinutes`: Integer. The minutes before a dormant sub-agent is archived to save resources. (Default `60`)
* **`agents.defaults.compaction.mode`**
  * *What it does:* How Carapace squishes old memory down to make room for new thoughts.
  * *Possible values:*
    * `"safeguard"` (Default) - Intelligently and safely summarizes or compresses older conversation history without losing the most critical recent information.
* **`agents.defaults.contextPruning.mode`**
  * *What it does:* How Carapace prunes or clears completely old historical memory (If Anthropic API key is detected)
  * *Possible values:*
    * `"cache-ttl"` - Clears or prunes old memory strictly based on how long it has been stored (Time-to-Live).
* **`agents.defaults.contextPruning.ttl`**
  * *What it does:* The duration for the time-to-live before pruning occurs.
  * *Possible values:* A time string like `"1h"` or `"30m"`.
* **`agents.promptGuard`**
  * *What it does:* Enforces security guardrails to make sure the AI isn't tricked into attacking you (Prompt Injection).
  * *Possible values:*
    * `enabled`:
      * `true` - Enables Prompt Injection protections.
      * `false` - Disables protections.
    * You can also specifically enable `preflight`, `tagging`, `postflight`, and `configLint` sections by changing their sub-value to `enabled: true`.
* **`agents.outputSanitizer`**
  * *What it does:* Scrubs the AI's final responses to keep malicious code off your computer screen.
  * *Possible values:*
    * `sanitizeHtml`: `true` (Strip out dangerous HTML) or `false` (Allow all HTML).
    * `cspPolicy`: String representing a strict Content Security Policy.

---

## 3. Providers & LLMs (Connecting to AI Brains)

You can directly link different AI services seamlessly by pasting your secret API keys here.

* **`anthropic`**, **`openai`**, **`google`**, **`venice`**, **`bedrock`**
  * *What it does:* Connects directly to commercial AI clouds like Claude, ChatGPT, Gemini, Venice, or AWS.
  * *Possible values:*
    * `apiKey`: Your secret string password. (Can be drawn from environment variables safely like `"${OPENAI_API_KEY}"`).
    * `baseUrl`: String. Useful if passing through an enterprise proxy.
    * *(Bedrock specific)* `region`, `accessKeyId`, `secretAccessKey`, `sessionToken`, `enabled`.
* **`providers.ollama`** (Or similar local programs)
  * *What it does:* Connects to free AIs running on your own CPU/GPU locally.
  * *Possible values:*
    * `baseUrl`: String endpoint address. (Default: `"http://localhost:11434"`)
    * `apiKey`: Your authentication key if you've locked your Ollama server.
* **`vertex`** (Google Cloud Vertex AI)
  * *What it does:* Connects directly to Google's specialized Enterprise AI.
  * *Possible values:*
    * `projectId`: String. Your Google Cloud Project ID.
    * `location`: String. The server location region (Default: `"us-central1"`).
    * `model`: String. The exact model tag.

---

## 4. Channels (Chat Apps & Interfaces)

Enable Carapace to listen and chat dynamically on different popular platforms.

* **`signal`** (Signal Messenger)
  * *What it does:* Uses `signal-cli` to let the AI text securely via a phone number.
  * *Possible values:*
    * `baseUrl`: String address to the CLI wrapper.
    * `phoneNumber`: String. Your registered number (like `"+15551234567"`).
    * `enabled`: `true` (Connect to Signal) or `false`.
* **`telegram`**
  * *What it does:* Connects a telegram bot.
  * *Possible values:*
    * `botToken`: String. The code from the BotFather.
    * `webhookSecret`: String. Security token for highly secure inbound webhook updates.
    * `baseUrl`: String. Replaces the default telegram endpoint.
    * `enabled`: `true` (Connect to Telegram) or `false`.
* **`discord`**
  * *What it does:* Invites Carapace into Discord servers.
  * *Possible values:*
    * `botToken`: String. Your Discord Developer bot token.
    * `gatewayEnabled`: `true` to connect via WebSocket.
    * `gatewayIntents`: Integer mask for permissions (typically `37377`).
    * `gatewayUrl`: String.
    * `baseUrl`: String.
    * `enabled`: `true` (Connect to Discord) or `false`.
* **`slack`**
  * *What it does:* Brings the agent to your Slack workflow.
  * *Possible values:*
    * `botToken`: String starting with `xoxb-`.
    * `signingSecret`: String to strictly enforce origin validity for Slack Events.
    * `baseUrl`: String.
    * `enabled`: `true` (Connect to Slack) or `false`.

---

## 5. Security, Sessions, & Logs

* **`sessions`**
  * *What it does:* Governs how long the system remembers your long-running chat history and whether it gets automatically purged.
  * *Possible values:*
    * `retention.enabled`: `true` (Automatically wipe old memory) or `false` (Keep memory forever). (Default: `true`)
    * `retention.days`: Integer representing days until unread memory is wiped. (Default: `30`)
    * `retention.intervalHours`: Hourly cleanup rhythm. (Default: `6`)
    * `integrity.enabled`: Validates chat history files so attackers can't forge secret payloads. (`true`/`false`, default `true`).
    * `integrity.action`:
      * `"warn"` (Default) - Issues a warning and attempts to auto-migrate missing data signatures harmlessly.
      * `"reject"` - The system will fail completely and shut down if it detects altered chat history.
* **`session`**
  * *What it does:* Governs active interactive chat settings.
  * *Possible values:*
    * `scope`:
      * `"per-sender"` - Maintains a separate distinct timeline and context for each conversational participant.
    * `dmScope`:
      * `"main"` - Routes direct messages to the general, main timeline sequence.
    * `typingMode`:
      * `"thinking"` - Displays a typing indicator exclusively when the AI is currently utilizing reasoning cycles.
* **`logging`**
  * *What it does:* Dictates what diagnostic events are printed into your terminal or backend system files.
  * *Possible values:*
    * `level`:
      * `"trace"` - Extremely detailed low-level logs.
      * `"debug"` - Diagnostic information useful for active troubleshooting.
      * `"info"` (Default) - Standard operational events.
      * `"warn"` - Non-critical issues or warnings.
      * `"error"` - Serious problems that require immediate attention.
    * `format`:
      * `"text"` - Standard readable text format.
      * `"json"` - Structured data blob meant to be easily read by machines or logging pipelines.
    * `consoleStyle`:
      * `"pretty"` (Default) - Colorful text suitable for human reading in the console/terminal.
    * `redactSensitive`:
      * `"tools"` (Default) - Automatically blanks out potentially sensitive data passed back and forth between the AI and its tools to protect you.
* **`skills.sandbox`** & **`skills.signature`**
  * *What it does:* Stops downloaded third-party tricks/skills from destroying your computer or leaking.
  * *Possible values:*
    * `sandbox.enabled`: `true` (Run skills in a safe isolated box) or `false`.
    * `sandbox.defaults.allowHttp`, `allowCredentials`, `allowMedia`: `true` or `false` to punch strictly sized holes in the sandbox if a skill explicitly requires it.
    * `signature.enabled`, `signature.requireSignature`: `true` (Force skills to be cryptographically signed by their author) or `false`.
    * `signature.trustedPublishers`: Array of trusted author names permitted strictly to bypass blocks.

---

## 6. Utilities & Economy

* **`cron`**
  * *What it does:* Tells the AI to wake up and perform chores on an automated timeline.
  * *Possible values:*
    * `enabled`: `true` (Activates cron scheduling) or `false`.
    * `maxConcurrentRuns`: Integer. The maximum jobs permitted to happen simultaneously without being queued.
    * `entries`: An Array of task job objects. Example object: `{ schedule: "0 * * * *", payload: {} }`.
* **`usage`**
  * *What it does:* Implements cost-tracking to make sure the AI doesn't bill you out of house and home running expensive models repeatedly.
  * *Possible values:*
    * `pricing.default` object: Dictates `inputCostPerMTok` (Positive Decimal) and `outputCostPerMTok` (Positive Decimal) for models that lack specific pricing instructions.
    * `pricing.overrides` List: specific objects detailing `match` (String name like `"gpt-4o"`), `matchType` (`"exact"` match or `"contains"` string match), and per-token rates overrides that supersede defaults.
* **`classifier`**
  * *What it does:* Operates a lightweight, cheaper AI at the gateway to pre-read messages before the massive expensive one does, dropping dangerous or useless junk automatically.
  * *Possible values:*
    * `enabled`: `true` (Turn on pre-reading) or `false`.
    * `mode`:
      * `"off"` - Fully bypasses classifier warnings.
      * `"warn"` - Flags suspicious messages with a warning but lets them through to the main AI.
      * `"block"` - Completely blocks messages deemed dangerous.
    * `model`: String specifying the smaller model to use (like `"gpt-4o-mini"`).
    * `blockThreshold`: Decimal representing the threshold of confidence required from the classifier from `0.0` to `1.0`.
* **`plugins`** (WASM expansions)
  * *What it does:* Lets users supercharge the system using fast runtime plugins.
  * *Possible values:*
    * `enabled`: `true` or `false`.
    * `load.paths`: Array of directory strings outlining where the `*.wasm` plugins are installed on the local system.
* **`messages`**
  * *What it does:* Universal text messaging fallbacks.
  * *Possible values:*
    * `ackReactionScope`:
      * `"group-mentions"` - The bot reacts to acknowledge a message only when specifically tagged in group chats.

---

## Other Valid Schema Fields

These items are permitted in the configuration and perform specific functions to alter your system but generally accept empty JSON objects `{}` or internal flags:

* `meta` (Update version tracking data)
* `env` (Provides direct shell environment variable replacements `process.env` under `.vars`)
* `wizard` (Tracks onboarding progress)
* `diagnostics` (OpenTelemetry instrumentation)
* `update` (Release channels)
* `browser` (Puppeteer/Playwright integrations, `.enabled`, `.cdpUrl`, `.profiles`)
* `ui` (Interface personalization setups)
* `auth` (Authorizations & permissions profile mapping)
* `talk` (Voice and Speech-to-Text configuration)
