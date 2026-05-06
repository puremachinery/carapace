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
    }
  ]
}
```

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

### Matrix endpoint error mapping

All `/control/matrix/*` endpoints share a common `MatrixError` →
HTTP-status mapping:

| Status | When |
|--------|------|
| `400 Bad Request` | Malformed JSON body (including invalid `userId` / `roomId` / `deviceId` rejected at deserialize). |
| `404 Not Found` | Verification flow / device / user / room is no longer known to the daemon. |
| `409 Conflict` | `VerificationFlowNotReady` — confirm called before SAS is captured for the flow. |
| `422 Unprocessable Entity` | Matrix-runtime input validation failure (unsupported room type, malformed identifier surfaced by the runtime). |
| `502 Bad Gateway` | Matrix-server send/sync/verification call failed. Retry. |
| `503 Service Unavailable` | Matrix runtime not started, authentication failed, or store load failed. Operator action usually required. |
| `504 Gateway Timeout` | Verification command exceeded the per-call timeout. Retry. |

Error response body is always `{ "error": "human-readable message" }`.

### POST `/control/matrix/send-test`

Sends a Matrix verification test message through the daemon-owned Matrix
runtime. This endpoint is used by `cara verify --outcome matrix --matrix-to` to
prove the configured destination and outbound send path:

```json
{ "roomId": "!room:example.com", "text": "Carapace Matrix verification" }
```

Response: `200 OK` with `{ "ok": true, "delivery": {...} }` when Matrix
accepted the message. Send-path runtime failures map to the status table
above (typically `502 Bad Gateway` for retryable Matrix-server errors).

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
    }
  ]
}
```

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

Returns service health status. No authentication required.

Response:
- 200 OK
```json
{ "status": "ok" }
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
