# Rust Gateway Compatibility Checklist

This checklist defines parity requirements for the Rust gateway migration. Each item must be verified to ensure drop-in compatibility with existing Moltbot clients.

## 1. Config Compatibility

### JSON Config File Format

- [ ] Support JSON5 parsing (comments, trailing commas, unquoted keys)
- [ ] Config file location: `~/.moltbot/moltbot.json` (or `MOLTBOT_CONFIG_PATH` override)
- [ ] Support `$include` directive for config file composition
  - [ ] Relative path resolution from parent config
  - [ ] Circular include detection and error
- [ ] Support `${VAR}` environment variable substitution in config values
- [ ] Config validation with schema (report path + message for each issue)
- [ ] Return empty config `{}` when file does not exist
- [ ] Config caching with 200ms TTL (configurable via `MOLTBOT_CONFIG_CACHE_MS`)

### Environment Variable Overrides

| Variable | Purpose |
|----------|---------|
| `MOLTBOT_CONFIG_PATH` | Override config file location |
| `MOLTBOT_GATEWAY_PORT` | Override default port (18789) |
| `MOLTBOT_GATEWAY_TOKEN` | Gateway auth token |
| `MOLTBOT_GATEWAY_PASSWORD` | Gateway auth password |
| `MOLTBOT_CONFIG_CACHE_MS` | Config cache TTL |
| `MOLTBOT_DISABLE_CONFIG_CACHE` | Disable config caching |

- [ ] All environment variables take precedence over config file values
- [ ] Support `config.env` section to set environment variables from config

### Default Values

| Config Key | Default Value |
|------------|---------------|
| `gateway.port` | `18789` |
| `gateway.bind` | `"loopback"` (127.0.0.1) |
| `hooks.path` | `"/hooks"` |
| `hooks.maxBodyBytes` | `262144` (256 KB) |

- [ ] Apply model defaults (`applyModelDefaults`)
- [ ] Apply session defaults (`applySessionDefaults`)
- [ ] Apply logging defaults (`applyLoggingDefaults`)
- [ ] Apply message defaults (`applyMessageDefaults`)
- [ ] Apply agent defaults (`applyAgentDefaults`)
- [ ] Normalize config paths (expand `~`, resolve relative paths)

---

## 2. Auth Compatibility

### Token Auth

- [ ] Timing-safe comparison using constant-time equality (`timingSafeEqual`)
- [ ] Token from `gateway.auth.token` config or `MOLTBOT_GATEWAY_TOKEN` env var
- [ ] Token provided in connect params: `{ auth: { token: "..." } }`
- [ ] Return `token_missing` when client provides no token
- [ ] Return `token_mismatch` when token does not match
- [ ] Return `token_missing_config` when gateway has no token configured

### Password Auth

- [ ] Timing-safe comparison using constant-time equality
- [ ] Password from `gateway.auth.password` config or `MOLTBOT_GATEWAY_PASSWORD` env var
- [ ] Password provided in connect params: `{ auth: { password: "..." } }`
- [ ] Return `password_missing` when client provides no password
- [ ] Return `password_mismatch` when password does not match
- [ ] Return `password_missing_config` when gateway has no password configured

### Tailscale Auth (whois verification)

- [ ] Check `allowTailscale` setting (default: true when `tailscale.mode=serve` and not password mode)
- [ ] Verify Tailscale proxy headers: `x-forwarded-for`, `x-forwarded-proto`, `x-forwarded-host`
- [ ] Extract client IP from `x-forwarded-for` header
- [ ] Call `tailscale whois` to verify identity
- [ ] Compare whois login with `tailscale-user-login` header (case-insensitive)
- [ ] Return `tailscale_user_missing` when header absent
- [ ] Return `tailscale_proxy_missing` when proxy headers absent
- [ ] Return `tailscale_whois_failed` when whois lookup fails
- [ ] Return `tailscale_user_mismatch` when login does not match

### Local Loopback Bypass

- [ ] Detect loopback addresses: `127.0.0.1`, `127.x.x.x`, `::1`, `::ffff:127.x.x.x`
- [ ] Check Host header: `localhost`, `127.0.0.1`, `::1`, or `*.ts.net`
- [ ] Verify no proxy headers present (unless from trusted proxy)
- [ ] Support `gateway.trustedProxies` config for reverse proxy setups
- [ ] Log warning when proxy headers detected from untrusted address

### Device Identity Auth

- [ ] Derive device ID from public key (base64url-encoded SHA-256)
- [ ] Verify device signature against auth payload
- [ ] Signature payload version v1 (legacy) and v2 (with nonce)
- [ ] Signature skew window: 10 minutes (`DEVICE_SIGNATURE_SKEW_MS`)
- [ ] Require nonce for non-loopback connections
- [ ] Support device token verification for paired devices
- [ ] Device pairing flow: request -> approve/reject -> store

---

## 3. WebSocket Protocol

### Protocol Version

- [ ] Current protocol version: Check `PROTOCOL_VERSION` constant
- [ ] Protocol negotiation via `minProtocol`/`maxProtocol` in connect params
- [ ] Reject connections when `maxProtocol < PROTOCOL_VERSION` or `minProtocol > PROTOCOL_VERSION`
- [ ] Return error code `1002` (protocol error) for version mismatch

### Connection Handshake

1. [ ] Server sends `connect.challenge` event on connection open:
   ```json
   { "type": "event", "event": "connect.challenge", "payload": { "nonce": "<uuid>", "ts": <timestamp> } }
   ```

2. [ ] Client sends `connect` request:
   ```json
   { "type": "req", "id": "<uuid>", "method": "connect", "params": <ConnectParams> }
   ```

3. [ ] Server validates auth and responds with `hello-ok`:
   ```json
   { "type": "res", "id": "<uuid>", "ok": true, "payload": <HelloOk> }
   ```

4. [ ] Handshake timeout: configurable (default in `getHandshakeTimeoutMs()`)

### ConnectParams Schema

```typescript
{
  minProtocol: number;
  maxProtocol: number;
  client: {
    id: string;           // e.g., "control-ui", "cli", "macos-app"
    displayName?: string;
    version: string;
    platform: string;     // e.g., "darwin", "linux", "win32"
    deviceFamily?: string;
    modelIdentifier?: string;
    mode: string;         // e.g., "operator", "node"
    instanceId?: string;
  };
  caps?: string[];
  commands?: string[];    // For node role
  permissions?: Record<string, boolean>;
  pathEnv?: string;
  role?: "operator" | "node";
  scopes?: string[];
  device?: {
    id: string;
    publicKey: string;
    signature: string;
    signedAt: number;
    nonce?: string;
  };
  auth?: {
    token?: string;
    password?: string;
  };
  locale?: string;
  userAgent?: string;
}
```

### HelloOk Response

```typescript
{
  type: "hello-ok";
  protocol: number;
  server: {
    version: string;
    commit?: string;
    host?: string;
    connId: string;
  };
  features: {
    methods: string[];
    events: string[];
  };
  snapshot: Snapshot;
  canvasHostUrl?: string;
  auth?: {
    deviceToken: string;
    role: string;
    scopes: string[];
    issuedAtMs?: number;
  };
  policy: {
    maxPayload: number;
    maxBufferedBytes: number;
    tickIntervalMs: number;
  };
}
```

### Message Format

#### Request Frame
```json
{ "type": "req", "id": "<uuid>", "method": "<method>", "params": <optional object> }
```

#### Response Frame
```json
{ "type": "res", "id": "<uuid>", "ok": true|false, "payload": <optional>, "error": <optional ErrorShape> }
```

#### Event Frame
```json
{ "type": "event", "event": "<name>", "payload": <optional>, "seq": <optional number>, "stateVersion": <optional> }
```

### Error Shape

```typescript
{
  code: string;      // e.g., "INVALID_REQUEST", "NOT_PAIRED", "UNAVAILABLE"
  message: string;
  details?: unknown;
  retryable?: boolean;
  retryAfterMs?: number;
}
```

### Error Codes

| Code | Meaning |
|------|---------|
| `NOT_LINKED` | Channel not linked |
| `NOT_PAIRED` | Device not paired |
| `AGENT_TIMEOUT` | Agent request timed out |
| `INVALID_REQUEST` | Invalid request format or params |
| `UNAVAILABLE` | Service unavailable |

- [ ] Implement all error codes
- [ ] Include error shape in response when `ok: false`

### Event Types

| Event | Payload Description |
|-------|---------------------|
| `connect.challenge` | `{ nonce, ts }` |
| `agent` | Agent run events (start, delta, tool_use, complete) |
| `chat` | Chat events for WebChat |
| `presence` | Client presence updates |
| `tick` | Periodic heartbeat `{ ts }` |
| `talk.mode` | Talk mode state changes |
| `shutdown` | Gateway shutdown notification `{ reason, restartExpectedMs? }` |
| `health` | Health snapshot updates |
| `heartbeat` | Heartbeat events |
| `cron` | Cron job events |
| `node.pair.requested` | Node pairing request |
| `node.pair.resolved` | Node pairing resolved |
| `node.invoke.request` | Node invocation request |
| `device.pair.requested` | Device pairing request |
| `device.pair.resolved` | Device pairing resolved |
| `voicewake.changed` | Voice wake triggers changed |
| `exec.approval.requested` | Exec approval requested |
| `exec.approval.resolved` | Exec approval resolved |

- [ ] Implement all event types
- [ ] Include `stateVersion` in presence/health events
- [ ] Support `dropIfSlow` broadcast option

### WebSocket Close Codes

| Code | Reason |
|------|--------|
| `1000` | Normal closure |
| `1002` | Protocol error (version mismatch) |
| `1008` | Policy violation (auth failure, handshake error) |

- [ ] Truncate close reason to fit WebSocket limit (123 bytes)

---

## 4. HTTP Endpoints

### Endpoint List (from server-http.ts)

| Method | Path | Handler |
|--------|------|---------|
| POST | `/hooks/wake` | Wake hook |
| POST | `/hooks/agent` | Agent hook |
| POST | `/hooks/<mapping>` | Custom hook mappings |
| POST | `/tools/invoke` | Tool invocation |
| POST | `/v1/chat/completions` | OpenAI-compatible chat (optional) |
| POST | `/v1/responses` | OpenResponses API (optional) |
| * | `/slack/*` | Slack HTTP handlers |
| * | `/<controlUiBasePath>/*` | Control UI static files |
| * | `/a2ui/*` | A2UI (canvas host) |

### Request/Response Formats

#### Hooks API

**Token Auth:**
- Header: `Authorization: Bearer <token>` (preferred)
- Header: `X-Moltbot-Token: <token>` (alternative)
- Query: `?token=<token>` (deprecated, logs warning)

**POST /hooks/wake**

Request:
```json
{ "text": "...", "mode": "now" | "next-heartbeat" }
```

Response (200):
```json
{ "ok": true, "mode": "now" | "next-heartbeat" }
```

**POST /hooks/agent**

Request:
```json
{
  "message": "...",
  "name": "Hook",
  "wakeMode": "now" | "next-heartbeat",
  "sessionKey": "...",
  "channel": "last" | "<channel-id>",
  "deliver": true,
  "to": "...",
  "model": "...",
  "thinking": "...",
  "timeoutSeconds": 60
}
```

Response (202):
```json
{ "ok": true, "runId": "<uuid>" }
```

**POST /tools/invoke**

Request:
```json
{
  "tool": "<tool-name>",
  "action": "<action>",
  "args": { ... },
  "sessionKey": "...",
  "dryRun": false
}
```

Response (200):
```json
{ "ok": true, "result": <tool result> }
```

Response (404):
```json
{ "ok": false, "error": { "type": "not_found", "message": "Tool not available: <name>" } }
```

Response (400):
```json
{ "ok": false, "error": { "type": "tool_error", "message": "..." } }
```

### Status Codes

| Code | Meaning |
|------|---------|
| 200 | Success |
| 202 | Accepted (async operation) |
| 204 | No content (hook mapping with null action) |
| 400 | Bad request (invalid JSON, missing field) |
| 401 | Unauthorized (missing/invalid token) |
| 404 | Not found (unknown path, unknown tool) |
| 405 | Method not allowed |
| 413 | Payload too large |
| 500 | Internal server error |

- [ ] Implement all status codes
- [ ] Set `Content-Type: application/json; charset=utf-8` for JSON responses
- [ ] Set `Content-Type: text/plain; charset=utf-8` for error messages
- [ ] Set `Allow: POST` header for 405 responses

### HTTP/WebSocket Upgrade

- [ ] Handle WebSocket upgrade requests (do not interfere with ws library)
- [ ] Support canvas host upgrade for live-reload

---

## 5. Hooks API

### /hooks/wake

- [ ] Validate `text` field is non-empty string
- [ ] Validate `mode` is "now" or "next-heartbeat" (default: "now")
- [ ] Return 400 with `{ ok: false, error: "text required" }` when missing

### /hooks/agent

- [ ] Validate `message` field is non-empty string
- [ ] Default `name` to "Hook" when absent
- [ ] Default `wakeMode` to "now"
- [ ] Generate `sessionKey` as `hook:<uuid>` when absent
- [ ] Validate `channel` is valid channel ID or "last"
- [ ] Default `deliver` to true unless explicitly false
- [ ] Return 202 with `runId` (async dispatch)

### Token Auth

- [ ] Check `Authorization: Bearer <token>` header first
- [ ] Check `X-Moltbot-Token: <token>` header second
- [ ] Check `?token=<token>` query param last (log deprecation warning)
- [ ] Return 401 "Unauthorized" for invalid/missing token
- [ ] Timing-safe token comparison

### Hook Mappings

- [ ] Support custom hook mappings from config `hooks.mappings`
- [ ] Apply mapping transformations (path match, payload extraction)
- [ ] Return 204 No Content for mappings with null action

---

## 6. CLI Compatibility

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | General error (invalid args, runtime error) |

- [ ] Exit 0 on successful completion
- [ ] Exit 1 on error with message to stderr

### Gateway Command Flags

| Flag | Description |
|------|-------------|
| `--port <port>` | Gateway port (default: 18789) |
| `--bind <mode>` | Bind mode: loopback, lan, auto, tailnet, custom |
| `--host <ip>` | Custom bind address |
| `--force` | Force start even if port in use |

- [ ] Support all existing flag names
- [ ] Maintain flag short aliases where they exist
- [ ] Print startup message with bound address and port

### Config Command Flags

- [ ] `config get <key>` - Get config value
- [ ] `config set <key> <value>` - Set config value
- [ ] Support JSON value parsing for complex types

---

## 7. Gateway Methods (WebSocket RPC)

### Core Methods

| Method | Description |
|--------|-------------|
| `health` | Get health snapshot |
| `logs.tail` | Tail log entries |
| `channels.status` | Get channel status |
| `channels.logout` | Logout from channel |
| `status` | Get gateway status |
| `usage.status` | Get usage status |
| `usage.cost` | Get usage cost |
| `tts.status` | TTS status |
| `tts.providers` | List TTS providers |
| `tts.enable` | Enable TTS |
| `tts.disable` | Disable TTS |
| `tts.convert` | Convert text to speech |
| `tts.setProvider` | Set TTS provider |
| `config.get` | Get config value |
| `config.set` | Set config value |
| `config.apply` | Apply config changes |
| `config.patch` | Patch config |
| `config.schema` | Get config schema |
| `exec.approvals.*` | Exec approval methods |
| `wizard.*` | Onboarding wizard methods |
| `talk.mode` | Talk mode control |
| `models.list` | List available models |
| `agents.list` | List agents |
| `skills.*` | Skills management |
| `update.run` | Run update |
| `voicewake.*` | Voice wake methods |
| `sessions.*` | Session management |
| `last-heartbeat` | Get last heartbeat |
| `set-heartbeats` | Set heartbeat config |
| `wake` | Wake agent |
| `node.*` | Node management |
| `device.*` | Device pairing |
| `cron.*` | Cron job management |
| `system-presence` | System presence |
| `system-event` | System event |
| `send` | Send message |
| `agent` | Run agent |
| `agent.identity.get` | Get agent identity |
| `agent.wait` | Wait for agent |
| `chat.*` | WebChat methods |

- [ ] Implement all base methods
- [ ] Support channel-specific gateway methods from plugins
- [ ] Validate params with AJV schemas
- [ ] Return proper error shapes for validation failures

---

## 8. TLS Support

### Configuration

```typescript
{
  gateway: {
    tls: {
      enabled: boolean;
      autoGenerate?: boolean;  // default: true
      certPath?: string;
      keyPath?: string;
      caPath?: string;
    }
  }
}
```

- [ ] Support TLS termination at gateway
- [ ] Auto-generate self-signed cert when paths not provided
- [ ] Support custom cert/key paths
- [ ] Support CA bundle for mTLS
- [ ] Include TLS fingerprint (SHA-256) in discovery

---

## 9. Discovery

### mDNS/Bonjour

- [ ] Broadcast `_moltbot._tcp` service
- [ ] Include TXT records: machine name, port, TLS fingerprint
- [ ] Support modes: off, minimal (no cli/ssh), full
- [ ] Clean shutdown: unregister service

### Wide Area Discovery

- [ ] Support wide area discovery when enabled
- [ ] Include gateway metadata in discovery payload

---

## 10. Constants

### Server Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `MAX_PAYLOAD_BYTES` | Check source | Max WebSocket payload |
| `MAX_BUFFERED_BYTES` | Check source | Max buffered bytes per client |
| `TICK_INTERVAL_MS` | Check source | Tick event interval |
| `DEFAULT_PORT` | 18789 | Default gateway port |

- [ ] Match all constant values exactly

---

## Verification Checklist

### Unit Tests
- [ ] Config parsing (JSON5, includes, env substitution)
- [ ] Auth logic (token, password, Tailscale, loopback)
- [ ] Protocol validation (AJV schemas)
- [ ] HTTP endpoint handlers

### Integration Tests
- [ ] WebSocket handshake flow
- [ ] Full auth scenarios
- [ ] Hooks API end-to-end
- [ ] Gateway method round-trips

### Compatibility Tests
- [ ] Connect with existing Node.js CLI
- [ ] Connect with macOS app
- [ ] Connect with Control UI
- [ ] Connect with mobile apps (iOS/Android)

---

## Intentional Breaking Changes

The following changes are deliberate security improvements that break compatibility
with some Node gateway behaviors. These are documented here for migration planning.

### Plugin Webhook Path Namespacing

**Node behavior:** Plugins could register arbitrary HTTP paths via `registerHttpRoute()`.

**Rust behavior:** All plugin routes are namespaced under `/plugins/{pluginId}/`.

**Migration:** Update external webhook URLs to include the `/plugins/{pluginId}/` prefix.

**Rationale:** Prevents plugins from hijacking core gateway routes or impersonating
other plugins' endpoints.

### Provider Plugin Auth Flows

**Node behavior:** Provider plugins used `registerProvider()` with interactive auth
flows (prompts, configPatch, profiles).

**Rust behavior:** WASM provider plugins handle inference only. Auth/registration is
configured via host config or CLI, with credentials stored in the host credential store.

**Migration:** Configure provider credentials via `moltbot config set` or environment
variables. Provider plugins read credentials via `credential-get()`.

**Rationale:** WASM sandbox cannot access terminal/UI for interactive prompts, and
config mutations require host coordination for safety.

---

## Migration Notes

- The Rust gateway should be a drop-in replacement for most use cases
- Client-side changes are NOT required for core protocol functionality
- Plugin authors may need to update for webhook namespacing and provider auth changes
- Config file format must be identical
- Protocol version must match exactly
- All error codes and messages should match for proper client error handling
