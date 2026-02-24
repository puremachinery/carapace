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
  "model": "optional-model",
  "thinking": "optional",
  "timeoutSeconds": 120
}
```

Responses:
- 202 Accepted
```json
{ "ok": true, "runId": "{id}" }
```
- 400 Bad Request (invalid payload)
```json
{ "ok": false, "error": "{message}" }
```

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
{ "error": {"message": "Unauthorized", "type": "unauthorized"} }
```
- 500 Internal Server Error
```json
{ "error": {"message": "{error}", "type": "api_error"} }
```

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

### OpenResponses API
- `/v1/responses` - OpenAI-compatible responses endpoint
- Streaming SSE support
- Tool use and function calling

These endpoints require additional documentation of:
- Authentication requirements (which use service auth vs hooks token vs none)
- Request/response schemas
- Error handling behavior

See `src/server/http.rs` for the Rust implementation of HTTP handlers.
