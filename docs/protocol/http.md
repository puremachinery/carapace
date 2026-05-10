# Carapace HTTP API

This document describes the HTTP endpoints wired in the current Rust Carapace implementation.
It focuses on endpoints handled directly by the service and the Control UI.

## Authentication Overview

Endpoints fall into two buckets:

- **Hooks** use a separate hooks token (`gateway.hooks.token`) and do **not** use service auth.
- **Service endpoints** use **service auth** (token/password) or **Tailscale Serve** when enabled.

Service auth uses a bearer token in the `Authorization` header:

```
Authorization: Bearer ${CARAPACE_GATEWAY_TOKEN}
```

If service auth mode is `password`, the same bearer token is treated as the password.
If auth mode is `none` (loopback-only), the endpoints are open to local loopback requests.
If Tailscale Serve auth is enabled, verified Tailscale identity can satisfy auth for non-local requests.

Error formats vary by endpoint; each section calls out the exact JSON shape.

## Hooks

Hooks are enabled only when `gateway.hooks.enabled=true`.
The base path is `/hooks` by default and is configurable via `gateway.hooks.path`.
Max body size is configurable via `gateway.hooks.maxBodyBytes`.
The path **must not** be `/`.

### Auth
Hooks require a **hooks token** (not service auth). Accepted forms:

- `Authorization: Bearer ${CARAPACE_HOOKS_TOKEN}`
- `X-Carapace-Token: ${CARAPACE_HOOKS_TOKEN}`

### Common behavior
- Method: **POST** only
- Content-Type: `application/json`
- Max body size: 256 KB (override via `gateway.hooks.maxBodyBytes`)
- Errors:
  - 401 Unauthorized (token missing/mismatch)
  - 405 Method Not Allowed
  - 404 Not Found (unknown subpath)
  - 413 Payload Too Large
  - 400 Bad Request (invalid JSON or payload)

Error body format for JSON parse/validation errors:

```json
{ "ok": false, "error": "{message}" }
```

### Production secret hygiene

For production deployments, set `CARAPACE_SERVER_SECRET`.
When this is unset, hooks sender-scoping key derivation falls back to a built-in
constant intended for local/dev use, not long-lived production environments.

#### POST `{basePath}/wake`
Trigger a wake event.

Request body:
```json
{
  "text": "hello",
  "mode": "now" // optional: "now" (default) or "next-heartbeat"
}
```

Responses:
- 200 OK
```json
{ "ok": true, "mode": "now" }
```
- 400 Bad Request
```json
{ "ok": false, "error": "text required" }
```

#### POST `{basePath}/agent`
Dispatch a message to the agent.

Request body:
```json
{
  "message": "Run the report",
  "name": "Hook",
  "wakeMode": "now",
  "sessionKey": "hook:...",
  "channel": "last",
  "deliver": true,
  "to": "optional-target",
  "route": "optional-route",
  "model": "optional-provider:model",
  "thinking": "optional",
  "timeoutSeconds": 120,
  "allowUnsafeExternalContent": false,
  "veniceParameters": {"enable_web_search": "on"}
}
```

Set either `route` or `model`, not both. `route` references the top-level
`routes` map. `model` must use canonical `provider:model` syntax. Direct
`/hooks/agent` JSON uses camelCase for all optional request fields
(`wakeMode`, `timeoutSeconds`, `allowUnsafeExternalContent`,
`veniceParameters`, `sessionKey`).

Responses:
- 202 Accepted
```json
{ "ok": true, "runId": "{id}" }
```
- 400 Bad Request (invalid payload)
```json
{ "ok": false, "error": "{message}" }
```
- 400 Bad Request (route/model configuration error)
```json
{ "ok": false, "error": "requested route is not configured", "errorCode": "unknown_route" }
```
- 400 Bad Request (no route/model resolved)
```json
{ "ok": false, "error": "agent model is not configured", "errorCode": "missing_model" }
```
- 503 Service Unavailable (no LLM provider configured)
```json
{ "ok": false, "error": "no LLM provider is configured", "errorCode": "provider_not_configured" }
```

The public `error` strings for configuration failures are sanitized. Operator
details such as config key paths and examples are written to server logs.

#### POST `{basePath}/*` (hook mappings)
If hook mappings are configured, Carapace applies them to the incoming payload.
Possible responses:
- 200 OK / 202 Accepted for mapped actions
- 204 No Content if mapping returns `null`
- 400 Bad Request for invalid mapping
- 500 Internal Server Error if mapping evaluation fails

## Channel Webhooks

Inbound channel integrations are handled via dedicated HTTP endpoints.
These are **not** protected by service auth; each channel uses its own
validation mechanism.

Common behavior:
- Method: **POST**
- Max body size: 256 KB (override via `gateway.hooks.maxBodyBytes`)

### POST `/channels/telegram/webhook`
Telegram Bot API webhook endpoint.

- Auth: requires `X-Telegram-Bot-Api-Secret-Token` matching `telegram.webhookSecret`.
- Body: Telegram Update JSON.
- Response: `200 OK` on success (ignored updates still return 200).

### POST `/channels/slack/events`
Slack Events API endpoint.

- Auth: Slack signature validation using `slack.signingSecret`.
  - Requires `X-Slack-Request-Timestamp` and `X-Slack-Signature` headers.
- Body: Slack Events API JSON.
- Response:
  - `200 OK` with `{ "challenge": "..." }` for `url_verification`.
- `200 OK` for event callbacks.

## Plugin Webhooks

Plugins can register webhook paths. Carapace routes any request under
`/plugins/{plugin_id}/...` to the owning plugin.

Common behavior:
- Method: **any**
- Max body size: 256 KB (override via `gateway.hooks.maxBodyBytes`)
- Auth: hooks token required (same auth check as `/hooks/*`).
  Plugins may still perform additional validation (for example shared secrets or
  signatures in request payloads/headers).
- Response: status, headers, and body are forwarded from the plugin.

### `ANY /plugins/{plugin_id}/*`

- Path is matched against the plugin’s registered webhook paths.
- `404 Not Found` if no plugin claims the path.

## OpenAI-Compatible

### POST `/v1/chat/completions`
OpenAI-style Chat Completions endpoint (when enabled).

Auth: **service auth** (Bearer token/password or Tailscale Serve).

Request body (subset supported):
```json
{
  "model": "carapace",
  "stream": false,
  "messages": [
    {"role": "system", "content": "You are..."},
    {"role": "user", "content": "Hello"}
  ],
  "user": "optional-user-id"
}
```

`model: "carapace"`, `carapace:<agent-id>`, and `agent:<agent-id>` route
through the configured default agent model. A concrete provider request may pass
the canonical provider model directly, for example `openai:gpt-5.5` or
`anthropic:claude-sonnet-4-6`.

Response (non-stream):
- 200 OK
```json
{
  "id": "chatcmpl_{id}",
  "object": "chat.completion",
  "created": 1700000000,
  "model": "carapace",
  "choices": [
    {"index": 0, "message": {"role": "assistant", "content": "..."}, "finish_reason": "stop"}
  ],
  "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}
}
```

Streaming:
- Content-Type: `text/event-stream`
- Emits `data: {json}` chunks
- Terminates with `data: [DONE]`

Errors:
- 400 Bad Request (missing user message)
```json
{
  "error": {"message": "Missing user message in `messages`.", "type": "invalid_request_error"}
}
```
- 401 Unauthorized
```json
{ "error": {"message": "Unauthorized", "type": "invalid_request_error"} }
```
- 422 Unprocessable Entity (the `carapace` / `agent:*` alias has no configured default model)
```json
{ "error": {"message": "agent model is not configured", "type": "invalid_request_error"} }
```
- 503 Service Unavailable (no LLM provider is configured)
```json
{ "error": {"message": "No LLM provider configured. Configure an LLM provider for the selected model and retry.", "type": "api_error"} }
```
- 500 Internal Server Error
```json
{ "error": {"message": "{error}", "type": "api_error"} }
```

### POST `/v1/responses`
OpenAI-style Responses endpoint (when enabled).

Auth: **service auth** (Bearer token/password or Tailscale Serve).

Request body (subset supported):
```json
{
  "model": "carapace",
  "input": "Hello",
  "instructions": "Be concise",
  "stream": false,
  "tools": [],
  "tool_choice": "auto",
  "user": "optional-user-id"
}
```

`input` may be a string or an array of typed input items. Message items are
converted into chat messages; function-call items are currently ignored during
model dispatch. `model` alias behavior and configuration errors match
`/v1/chat/completions`.

Response:
```json
{
  "id": "resp_{id}",
  "object": "response",
  "created_at": 1700000000,
  "status": "completed",
  "model": "carapace",
  "output": [
    {
      "type": "message",
      "id": "msg_{id}",
      "role": "assistant",
      "content": [{"type": "output_text", "text": "..."}],
      "status": "completed"
    }
  ],
  "usage": {"input_tokens": 0, "output_tokens": 0, "total_tokens": 0}
}
```

Errors:
- 400 Bad Request for invalid JSON, missing user input, or invalid `tool_choice`
- 401 Unauthorized
- 422 Unprocessable Entity when the `carapace` / `agent:*` alias has no configured default model
- 503 Service Unavailable when no LLM provider is configured
- 500 Internal Server Error for provider execution errors

## Tools Invoke

### POST `/tools/invoke`
Executes a single tool by name (when enabled).

Auth: **service auth** (Bearer token/password or Tailscale Serve).

Request headers:
- `Authorization: Bearer ${CARAPACE_GATEWAY_TOKEN}`
- Optional policy hints:
  - `X-Carapace-Message-Channel: {channel}`
  - `X-Carapace-Account-Id: {account_id}`

Request body:
```json
{
  "tool": "tool.name",
  "action": "optional",
  "args": {"key": "value"},
  "sessionKey": "optional",
  "dryRun": false
}
```

Responses:
- 200 OK
```json
{ "ok": true, "result": {"...": "..."} }
```
- 404 Not Found (tool not available)
```json
{ "ok": false, "error": {"type": "not_found", "message": "Tool not available: {tool}"} }
```
- 400 Bad Request (invalid body or tool error)
```json
{ "ok": false, "error": {"type": "tool_error", "message": "{message}"} }
```
- 401 Unauthorized
```json
{ "error": {"message": "Unauthorized", "type": "unauthorized"} }
```

## Control UI

The Control UI is served as static assets + SPA.
Base path is `/ui` by default and configurable via `gateway.controlUi.basePath`.

### GET/HEAD `{basePath}/...`
- A request to `{basePath}` redirects to `{basePath}/`.
- Assets are served from the `dist/control-ui` directory.
- Unknown paths fall back to `index.html` for SPA routing.

### GET/HEAD `{basePath}/avatar/{agentId}`
Serves local avatar file for a valid agent ID.

- `GET`: returns image bytes
- `HEAD`: returns headers only
- `?meta=1`: returns JSON metadata

Metadata response:
```json
{ "avatarUrl": "{url-or-null}" }
```

Errors:
- 404 Not Found (invalid agent ID or no local avatar)
- 405 Method Not Allowed (non-GET/HEAD)

## Control API

Control endpoints use service auth (Bearer token/password or Tailscale Serve
identity), not hooks token.

### GET `/control/status`

Returns gateway/runtime status + diagnostics snapshot.

Response:

```json
{
  "ok": true,
  "version": "X.Y.Z",
  "startedAt": "2026-02-24T00:00:00Z",
  "uptimeSeconds": 123,
  "connectedChannels": 1,
  "totalChannels": 2,
  "runtime": {
    "name": "carapace",
    "version": "X.Y.Z",
    "platform": "linux",
    "arch": "x86_64"
  },
  "diagnostics": { "...": "..." }
}
```

### GET `/control/channels`

Returns channel connectivity state:

```json
{
  "total": 2,
  "connected": 1,
  "channels": [
    {
      "id": "telegram",
      "name": "telegram",
      "status": "connected",
      "lastConnectedAt": "2026-02-24T00:00:00Z",
      "lastError": null
    },
    {
      "id": "matrix",
      "name": "Matrix",
      "status": "error",
      "lastError": "Matrix access token rejected by homeserver: ...",
      "extra": {
        "lastErrorKind": "auth-token-revoked",
        "joinedRoomCount": 4,
        "encryptedRoomCount": 4,
        "unencryptedRoomCount": 0,
        "unsupportedRoomCount": 0,
        "pendingVerificationCount": 0,
        "lastSuccessfulSyncAt": null,
        "unsupportedRooms": [],
        "unsupportedInboundCount": 0,
        "inboundDispatchFailureTotal": 0,
        "inboundDlqAppendFailureTotal": 0,
        "inboundDlqDurabilityErrorAt": null,
        "inboundDlqLostEventIdsAt": null,
        "inboundDlqUndecodableLostCount": 0,
        "lastInboundFailureAt": null,
        "lastInboundDlqAppendFailureAt": null
      }
    }
  ]
}
```

The optional `extra` object on each channel carries channel-
specific runtime metadata. Matrix populates the
`MatrixStatusMetadata` shape; other channels populate their own
diagnostic blob or omit `extra` entirely.

#### `extra.lastErrorKind` (Matrix)

When a Matrix channel transitions to `status: "error"`, the runtime
stamps a stable kebab-case discriminator on `extra.lastErrorKind`
alongside the human-readable message in the top-level `lastError`.
External consumers (the bundled CLI, automation scripts, dashboards)
can match on this exact-token field to route per-variant operator
remediation hints WITHOUT substring-matching the redacted Display
text — a future copy-edit of the message does not break the routing.
Wire-stable: renaming any value here is a breaking change.

| `lastErrorKind` | Meaning | Operator action |
|---|---|---|
| `auth-token-revoked` | Homeserver rejected the access token (revoked, deactivated, locked, suspended). | accessToken-mode: mint a new token, stop the daemon, edit config directly or set `MATRIX_ACCESS_TOKEN` / `MATRIX_DEVICE_ID` in the daemon environment, then restart. password-mode: verify password / unlock account, restart. |
| `auth-session-user-mismatch` | Restored token belongs to a different user than `matrix.userId`. | Re-check `matrix.userId` against the token's owner, or rotate the token to one issued for the configured user. |
| `auth-session-device-mismatch` | Restored token belongs to a different device than `matrix.deviceId`. | Re-check `matrix.deviceId` against the device the token was issued for. |
| `auth-session-missing-device-id` | Homeserver did not return a device id (homeserver bug). | File an issue with the homeserver software, try a fresh token. |
| `auth` | Unspecified authentication failure (transport / wrong password). | Verify `matrix.homeserverUrl` reachable; verify token / password and userId / deviceId; inspect runtime log. |
| `encrypted-store-passphrase-mismatch` | Encrypted SQLite store rejected the resolved passphrase. | Check `CARAPACE_CONFIG_PASSWORD` did not change; look for an interrupted rekey at `{state_dir}/matrix/store_passphrase.{pending,rekeying}`. See [Channel Setup → Matrix store rekey lifecycle](../channels.md#matrix-store-rekey-lifecycle). |
| `interrupted-rekey` | Pending or rekeying-marker on disk without canonical passphrase file. | Stop daemon, run `cara matrix rekey-store --new` to advance or roll back. |
| `missing-store-secret` | Encrypted store needs a passphrase but none is set. | Set `CARAPACE_CONFIG_PASSWORD` (or `matrix.storePassphrase` / `MATRIX_STORE_PASSPHRASE`) and rerun. |
| `clock` | Host system clock is not advancing or is out of sync. | Verify NTP source health, restart daemon. |
| `client-build` | Matrix SDK client failed to construct. | Check write permissions on the state directory; inspect runtime log for the underlying error. |
| `e2ee` | E2EE setup failed (recovery key, cross-signing). | Inspect runtime log; follow rekey-recovery procedure if needed. |
| `installation-id` | Could not read or create the Matrix installation id file under the state directory. | Verify state directory is writable. |
| `sync-failed` / `send-failed` / `verification` / `verification-timeout` / `command-queue-full` | Transient runtime errors. | Retry; inspect runtime log if persistent. |
| `sync-loop-give-up` | Matrix has not completed a successful sync for at least 24h; daemon has slowed retries from 60s to once per hour. | Verify `matrix.homeserverUrl` is reachable, check account state, inspect the runtime log for the underlying transient error. The state clears on the next successful sync. |
| `not-connected` / `room-not-found` / `unsupported-room` / `invalid-user-id` / `device-not-found` / `user-identity-not-found` / `verification-flow-not-found` / `verification-flow-not-ready` / `verification-cancelled` / `send-terminal` | Resource / state errors surfaced via specific endpoints. | See [Matrix endpoint error mapping](#matrix-endpoint-error-mapping) for HTTP status routing. |
| `startup-failed` / `token-persistence` / `store-key-derivation` / `invalid-config-root` / `invalid-string` / `invalid-bool` / `invalid-string-array` / `invalid-length` / `invalid-url` / `allowlist-too-large` / `missing-homeserver-url` / `missing-user-id` / `missing-credentials` / `missing-device-id-for-token-restore` | Configuration / setup-time errors. | Fix `matrix:` section of config and rerun. |

### GET `/control/config`

Returns a **redacted** config snapshot plus optimistic-concurrency hash:

```json
{
  "ok": true,
  "config": { "...": "..." },
  "hash": "abc123..."
}
```

Secret-like keys are redacted as `"[REDACTED]"`.

#### `extra` forensic timestamps and DLQ-loss fields (Matrix)

The following optional fields stamp Unix-millisecond timestamps and
recovery data for inbound failures so operators driving forensics
off `cara status` / `GET /control/channels` can answer "when did X
break?" without grepping journald. All are wire-stable; renaming
any field is a breaking change. Fields with `null` / `0` / `[]`
defaults are omitted-by-default in JSON when the runtime has never
stamped them.

| Field | Stamps on | Clears on | Operator hint |
|---|---|---|---|
| `inboundDlqDurabilityError` | A DLQ append failed; the runtime captured a redacted error string. | The next successful DLQ append. | Pair with `inboundDlqDurabilityErrorAt` to bound the failure window. |
| `inboundDlqDurabilityErrorAt` | Same event as `inboundDlqDurabilityError`. | Same as above. | Use to scope a journald search; without it you only see the live message. |
| `inboundDlqLostEventIds` | DLQ replay phase-3 cleanup failed to persist a record back to disk; the event ID is appended (capped). | Next successful replay. | These IDs were lost; investigate the replay pipeline before journald rotates the original `lost_event_ids` warn-log. |
| `inboundDlqLostEventIdsAt` | Same event as `inboundDlqLostEventIds` (latest append). | Same as above. | Tracks the LATEST loss, not the oldest. |
| `inboundDlqUndecodableLostCount` | A cap-clamp tail-truncation dropped a record that failed to decode (typically a store-key mismatch from a prior `CARAPACE_CONFIG_PASSWORD` rotation). | Never auto-clears — cumulative. | A non-zero value indicates the DLQ contained records that no live key could decode. Investigate config-password rotations. |
| `lastInboundFailureAt` | Any inbound dispatch failure stamps via `record_inbound_failure_with_error`. | Survives consecutive-failure decay; only overwritten by a fresher failure. | Use to audit "did inbound break in the last hour?" even after `lastError` has cleared. |
| `lastInboundDlqAppendFailureAt` | DLQ append-failure counter incremented (durability failure: dispatch AND DLQ append both failed). | Survives the same decay as `lastInboundFailureAt`. | Distinct from `lastInboundFailureAt` because durability failures need stricter recovery; pair with `inboundDlqAppendFailureTotal`. |

### Matrix endpoint error mapping

All `/control/matrix/*` endpoints share a common `MatrixError` →
HTTP-status mapping:

| Status | When |
|--------|------|
| `400 Bad Request` | `matrix:` config-shape errors: malformed JSON body, invalid type for a field, missing required fields, length-cap exceeded (`invalid-length`), invalid URL scheme / embedded credentials (`invalid-url`), or allowlist over the entry cap (`allowlist-too-large`). Runtime-rejected identifiers (e.g. invalid `userId` after parse) route to 422, not 400. |
| `404 Not Found` | Verification flow / device / user / room is no longer known to the daemon. |
| `409 Conflict` | `VerificationFlowNotReady` — confirm called before SAS is captured for the flow. |
| `410 Gone` | `VerificationCancelled` — accept/confirm called against a flow already in a terminal state (`cancelled` / `done` / `mismatched`). The flow id is permanently invalid; start a new flow with `cara matrix verify`. |
| `422 Unprocessable Entity` | Matrix-runtime input validation failure: malformed identifier (`InvalidUserId`), unsupported room type (`UnsupportedRoom`), OR a permanently-rejected send for which the homeserver gave a non-token reason (`M_TOO_LARGE`, `M_BAD_JSON`, `M_GUEST_ACCESS_FORBIDDEN`, `M_UNRECOGNIZED`). Token-revocation classes do NOT land here — they route to 503 via `AuthTokenRevoked`. |
| `502 Bad Gateway` | Matrix-server send/sync/verification call failed transiently. Retry. |
| `503 Service Unavailable` | Matrix runtime is unavailable. Covers: runtime not started or shut down (`NotConnected`, `StartupFailed`, `ClientBuild`, `Auth*` family, `TokenPersistence`, `InstallationId`, `StoreKeyDerivation`, `MissingStoreSecret`, `Clock`, `E2ee`, `CommandQueueFull`); store-passphrase mismatch (`EncryptedStorePassphraseMismatch` — see [Channel Setup → Matrix store rekey lifecycle](../channels.md#matrix-store-rekey-lifecycle)); interrupted rekey (`InterruptedRekey`); account-state class (`M_FORBIDDEN`, `M_UNKNOWN_TOKEN`, `M_USER_DEACTIVATED`, `M_USER_LOCKED`, `M_USER_SUSPENDED` → `AuthTokenRevoked` — operator action: re-mint token, get account unlocked externally, or re-authenticate); and sustained sync failure (`SyncLoopGaveUp` — fires after 24h of failed syncs; daemon has slowed retries to once per hour, see [`extra.lastErrorKind` (Matrix)](#extralasterrorkind-matrix)). |
| `504 Gateway Timeout` | Verification command exceeded the per-call timeout. Retry. |

Error response body is always `{ "error": "human-readable message" }`.

### POST `/control/matrix/send-test`

Sends a Matrix verification test message through the daemon-owned Matrix
runtime. This endpoint is used by `cara verify --outcome matrix --matrix-to` to
prove the configured destination and outbound send path:

```json
{ "roomId": "!room:example.com", "text": "Carapace Matrix verification" }
```

`text` is optional; when omitted the daemon generates a default body
(`"Carapace Matrix verification ping at <RFC3339 timestamp>"`).

Response: `200 OK` with `{ "ok": <bool>, "delivery": <DeliveryOutcome> }`.
`delivery` is a tagged sum keyed on `outcome`:

```json
// success
{ "ok": true,  "delivery": { "outcome": "sent",   "messageId": "$evt:server", "conversationId": "!room:server" } }
// failure (best-effort surfaced even at 200; transient means the dispatch pipeline will retry)
{ "ok": false, "delivery": { "outcome": "failed", "error": "...", "retryability": { "kind": "transient", "retryAfterMs": 60000 }, "conversationId": "!room:server" } }
```

`ok` is derived: `ok=true` iff `outcome="sent"`. Delivery failures
returned by the Matrix runtime still use `200 OK` so clients can inspect
the tagged `delivery` body; hard binding failures return `502 Bad Gateway`.
Clients that need to distinguish terminal vs transient send-test outcomes
must inspect `delivery.outcome` and `delivery.retryability.kind`, not the
HTTP status. The status-table-style routing (410/422/503) above applies
only to the verification endpoints (`/control/matrix/verifications/*`).
Transient provider errors may include `retryability.retryAfterMs` when the
upstream channel exposes a Retry-After value; locally honored retry-after
values are capped at one hour. Message hook payloads also carry the legacy
`delivery.retryable` boolean alongside tagged `delivery.retryability` for
compatibility. Matrix send-test error text is redacted before it is placed in
the response body, hook payloads, queue state, or logs.

### GET `/control/matrix/devices`

Lists Matrix devices known to the daemon-owned Matrix runtime:

```json
{
  "ok": true,
  "devices": [
    {
      "userId": "@cara:example.com",
      "deviceId": "DEVICEID",
      "displayName": "Carapace Matrix",
      "verified": true
    },
    {
      "userId": "@bob:example.com",
      "deviceId": "DEVICEID",
      "rawDeviceIdHex": "e2808e4445564943454944",
      "displayName": "Bob's laptop",
      "verified": false
    }
  ]
}
```

`rawDeviceIdHex` is **omitted** in the steady-state case where the
homeserver-original device_id was already ASCII-safe. It is populated
only when identifier sanitization (bidi controls, zero-width chars,
TAG codepoints, Variation Selectors, ASCII control bytes) altered the
bytes that became `deviceId`. The value is the **hex encoding of the
homeserver-original UTF-8 bytes**, so the JSON is guaranteed terminal-
safe even on adversarial peer entries — operator scripts that need
the byte-exact form for the SDK lookup decode the hex back to bytes;
humans copy-paste the sanitized `deviceId` and rely on
`cara matrix verify`'s sanitization-equivalence resolver.

### GET `/control/matrix/verifications`

Lists Matrix verification flows still tracked by the daemon:

```json
{
  "ok": true,
  "verifications": [
    {
      "flowId": "flow-id",
      "protocolFlowId": "matrix-protocol-flow-id",
      "userId": "@alice:example.com",
      "deviceId": "DEVICEID",
      "state": "requested",
      "sas": {
        "emoji": [
          { "symbol": "🐱", "description": "cat" }
        ],
        "decimals": [1234, 5678, 9012]
      },
      "createdAt": 1767225600000,
      "updatedAt": 1767225600000
    }
  ]
}
```

### POST `/control/matrix/verifications`

Starts a Matrix verification flow:

```json
{ "userId": "@alice:example.com", "deviceId": "DEVICEID" }
```

`deviceId` is optional. For sanitized/colliding device IDs returned by
`GET /control/matrix/devices`, callers may instead provide
`rawDeviceIdHex` (hex-encoded original UTF-8 bytes). `deviceId` and
`rawDeviceIdHex` are mutually exclusive.

Response: `201 Created` with `{ "ok": true, "verification": {...} }`.

### POST `/control/matrix/verifications/{flow_id}/accept`

Accepts a pending Matrix verification flow. Response: `200 OK` with
`{ "ok": true, "verification": {...} }`. When the partner device has already
reached SAS, `verification.sas` carries emoji and/or decimal values for manual
comparison. If SAS is not ready yet, poll `GET /control/matrix/verifications`
until `sas` appears before confirming a match.

### POST `/control/matrix/verifications/{flow_id}/confirm`

Confirms or rejects a Matrix SAS match. Call this only after comparing the
`verification.sas` values with the other device:

```json
{ "match": true }
```

Returns `409 Conflict` with `VerificationFlowNotReady` if the SAS comparison
data has not yet been captured for the flow — poll
`GET /control/matrix/verifications` until `sas` is populated, then retry.

### POST `/control/matrix/verifications/{flow_id}/cancel`

Cancels a Matrix verification flow.

### PATCH `/control/config`

Applies a **safe allowlisted** single-path update with optimistic concurrency.
Only `gateway.controlUi.*` paths are accepted on this endpoint.

Request:

```json
{
  "path": "gateway.controlUi.enabled",
  "value": true,
  "baseHash": "abc123..."
}
```

Responses:
- `200 OK` with `{ "ok": true, "applied": {...}, "hash": "..." }`
- `400 Bad Request` for invalid JSON/path/baseHash usage
- `403 Forbidden` for non-allowlisted paths or protected paths
- `409 Conflict` when config changed since provided hash
- `422 Unprocessable Entity` for schema-invalid updates

## Control Task API

Control task endpoints are part of the service control plane and use **service
auth** (Bearer token/password or Tailscale Serve identity), not hooks token.

If runtime state is unavailable (for example startup race/misconfiguration),
task endpoints return:

```json
{ "ok": false, "error": "Task queue unavailable" }
```

with `503 Service Unavailable`.

### Durable task model

Task lifecycle states:
- `queued`
- `running`
- `blocked`
- `retry_wait`
- `done`
- `failed`
- `cancelled`

Continuation policy fields (camelCase):
- `maxAttempts` (default `100`)
- `maxTotalRuntimeMs` (default `604800000`)
- `maxTurns` (default `25`)
- `maxRunTimeoutSeconds` (default `600`)

Blocked tasks may include `blockedReason` values such as:
- `approval_required`
- `config_missing`
- `delivery_failure`
- `external_dependency`
- `operator_action_required`
- `unknown`

### POST `/control/tasks`

Create a durable objective task.

Request:

```json
{
  "payload": { "kind": "systemEvent", "text": "run nightly summary" },
  "nextRunAtMs": 1735689600000,
  "policy": {
    "maxAttempts": 10,
    "maxTotalRuntimeMs": 3600000,
    "maxTurns": 10,
    "maxRunTimeoutSeconds": 120
  }
}
```

`payload.kind` supports:
- `systemEvent`
- `agentTurn`

Responses:
- `201 Created` with `{ "ok": true, "task": { ... } }`
- `400 Bad Request` for invalid JSON/payload/policy
- `503 Service Unavailable` when queue is full or unavailable

### GET `/control/tasks`

List tasks (newest-first).

Query params:
- `state` optional (`queued`, `running`, `blocked`, `retry_wait`, `done`, `failed`, `cancelled`)
- `limit` optional (max rows returned)

Response:

```json
{
  "ok": true,
  "total": 42,
  "tasks": [ ... ]
}
```

Errors:
- `400 Bad Request` (invalid state filter)

### GET `/control/tasks/{id}`

Fetch one task by ID.

Responses:
- `200 OK` with `{ "ok": true, "task": { ... } }`
- `404 Not Found` when missing

### PATCH `/control/tasks/{id}`

Patch mutable task fields:
- `payload` (full replacement; validated as `CronPayload`)
- `policy` (partial policy patch)
- `reason` (stored into `lastError`, max 1024 chars)

Request:

```json
{
  "payload": { "kind": "systemEvent", "text": "updated task payload" },
  "policy": { "maxRunTimeoutSeconds": 45 },
  "reason": "operator patch"
}
```

Responses:
- `200 OK` on success
- `400 Bad Request` for invalid JSON/payload/policy/reason length or empty patch body
- `404 Not Found` when missing
- `409 Conflict` when state is not patchable (`running`/`done`) or changed concurrently

### POST `/control/tasks/{id}/cancel`

Cancel a task (optional body `{ "reason": "..." }`).

Responses:
- `200 OK` on success
- `400 Bad Request` for invalid reason length/JSON
- `404 Not Found` when missing
- `409 Conflict` when already terminal (`done`/`failed`/`cancelled`) or changed concurrently

### POST `/control/tasks/{id}/retry`

Move a retryable task to `retry_wait`.

Request:

```json
{ "delayMs": 500, "reason": "operator retry" }
```

If `reason` is omitted/blank, default is `"retried by operator"`.

Responses:
- `200 OK` on success
- `400 Bad Request` for invalid reason length/JSON
- `404 Not Found` when missing
- `409 Conflict` when not retryable in current state (`queued`/`running`/`done`) or changed concurrently

### POST `/control/tasks/{id}/resume`

Resume a blocked task (moves `blocked -> retry_wait`).

Request:

```json
{ "delayMs": 1000, "reason": "operator resume" }
```

If `reason` is omitted/blank, default is `"resumed by operator"`.

Responses:
- `200 OK` on success
- `400 Bad Request` for invalid reason length/JSON
- `404 Not Found` when missing
- `409 Conflict` when task is not blocked

### Audit coverage

Successful task mutations emit audit event type `task_mutated` with:
- `task_id`
- `action` (`cancel` / `patch` / `retry` / `resume`)
- `actor` (remote IP or `unknown`)
- `resulting_state`

## Health / Status

### GET `/health`

Returns service liveness. No authentication required. Always 200 if the
HTTP server is up. Backed by the same handler as `/health/live`.

Response:
- 200 OK
```json
{ "status": "ok", "version": "...", "uptimeSeconds": <int> }
```

### GET `/health/live`

Liveness probe. Always 200 if the HTTP server is responding. Use this
for k8s-style liveness, container-orchestrator restart triggers.

Response:
- 200 OK
```json
{ "status": "ok", "version": "...", "uptimeSeconds": <int> }
```

### GET `/health/ready`

Readiness probe. Returns 503 if the daemon has any blocking-issue that
makes new requests likely to fail. Returns 200 otherwise.

The 503 criterion includes:

- State directory is not writable (host-level filesystem issue).
- LLM provider has been unreachable in the cached health window.
- **Any registered channel is in `ChannelStatus::Error`** (since v0.8.x).
  This includes a configured Matrix channel that died at startup
  (interrupted rekey, wrong passphrase, homeserver-revoked token), a
  Slack channel that lost its WebSocket token, etc. Only configured
  channels contribute — an unconfigured channel cannot drop readiness
  because it doesn't register in the channel registry. Operators relying
  on `/health/ready` for k8s readiness probes / load-balancer
  membership will see pod-level `503` when a channel goes Error;
  use `cara status` or `GET /control/channels` to identify which
  channel is broken.

Response (200):
```json
{ "status": "ready", "version": "...", "uptimeSeconds": <int> }
```

Response (503):
```json
{ "status": "not_ready", "version": "...", "uptimeSeconds": <int> }
```

## Additional HTTP Handlers

The following handlers are available but require additional documentation:

### Slack HTTP Handlers
- OAuth callback endpoints for Slack integration
- Event subscription webhook receiver
- Slash command handlers
- Interactive component handlers

### Canvas Host / A2UI Endpoints
- `/a2ui/*` - Artifact-to-UI canvas host
- Static asset serving for canvas artifacts
- WebSocket upgrade for live canvas updates

See `src/server/http.rs` for the Rust implementation of HTTP handlers.
