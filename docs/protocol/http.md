# Gateway HTTP API

This document describes the gateway HTTP endpoints wired in the current Node gateway implementation.
It focuses on endpoints handled directly by the gateway server and the Control UI.

## Authentication Overview

Endpoints fall into two buckets:

- **Hooks** use a separate hooks token (`hooks.token`) and do **not** use gateway auth.
- **Gateway endpoints** use **gateway auth** (token/password) or **Tailscale Serve** when enabled.

Gateway auth uses a bearer token in the `Authorization` header:

```
Authorization: Bearer <token>
```

If gateway auth mode is `password`, the same bearer token is treated as the password.
If auth mode is `none` (loopback-only), the endpoints are open to local loopback requests.
If Tailscale Serve auth is enabled, verified Tailscale identity can satisfy auth for non-local requests.

Error formats vary by endpoint; each section calls out the exact JSON shape.

## Hooks

Hooks are enabled only when `hooks.enabled=true`. The base path defaults to `/hooks` and can be overridden by `hooks.path`.
The path **must not** be `/`.

### Auth
Hooks require a **hooks token** (not gateway auth). Accepted forms:

- `Authorization: Bearer <hooks-token>`
- `X-Moltbot-Token: <hooks-token>`
- `?token=<hooks-token>` (deprecated; logs a warning)

### Common behavior
- Method: **POST** only
- Content-Type: `application/json`
- Max body size: `hooks.maxBodyBytes` (default 256 KB)
- Errors:
  - 401 Unauthorized (token missing/mismatch)
  - 405 Method Not Allowed
  - 404 Not Found (unknown subpath)
  - 413 Payload Too Large
  - 400 Bad Request (invalid JSON or payload)

Error body format for JSON parse/validation errors:

```json
{ "ok": false, "error": "<message>" }
```

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
{ "ok": true, "runId": "<id>" }
```
- 400 Bad Request (invalid payload)
```json
{ "ok": false, "error": "<message>" }
```

#### POST `{basePath}/*` (hook mappings)
If hook mappings are configured, the gateway applies them to the incoming payload.
Possible responses:
- 200 OK / 202 Accepted for mapped actions
- 204 No Content if mapping returns `null`
- 400 Bad Request for invalid mapping
- 500 Internal Server Error if mapping evaluation fails

## OpenAI-Compatible

### POST `/v1/chat/completions`
OpenAI-style Chat Completions endpoint (when enabled).

Auth: **gateway auth** (Bearer token/password or Tailscale Serve).

Request body (subset supported):
```json
{
  "model": "moltbot",
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
  "id": "chatcmpl_<id>",
  "object": "chat.completion",
  "created": 1700000000,
  "model": "moltbot",
  "choices": [
    {"index": 0, "message": {"role": "assistant", "content": "..."}, "finish_reason": "stop"}
  ],
  "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}
}
```

Streaming:
- Content-Type: `text/event-stream`
- Emits `data: <json>` chunks
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
{ "error": {"message": "<error>", "type": "api_error"} }
```

## Tools Invoke

### POST `/tools/invoke`
Executes a single tool by name (when enabled).

Auth: **gateway auth** (Bearer token/password or Tailscale Serve).

Request headers:
- `Authorization: Bearer <token>`
- Optional policy hints:
  - `X-Moltbot-Message-Channel: <channel>`
  - `X-Moltbot-Account-Id: <accountId>`

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
{ "ok": false, "error": {"type": "not_found", "message": "Tool not available: <tool>"} }
```
- 400 Bad Request (invalid body or tool error)
```json
{ "ok": false, "error": {"type": "tool_error", "message": "<message>"} }
```
- 401 Unauthorized
```json
{ "error": {"message": "Unauthorized", "type": "unauthorized"} }
```

## Control UI

The Control UI is served as static assets + SPA.
Base path is `gateway.controlUi.basePath` (normalized to `""` or `"/path"`).

### GET/HEAD `{basePath}/...`
- If `basePath` is set, a request to `{basePath}` redirects to `{basePath}/`.
- Assets are served from the `dist/control-ui` directory.
- Unknown paths fall back to `index.html` for SPA routing.
- If `basePath` is not set, `/ui` is explicitly rejected with 404.

### GET/HEAD `{basePath}/avatar/{agentId}`
Serves local avatar file for a valid agent ID.

- `GET`: returns image bytes
- `HEAD`: returns headers only
- `?meta=1`: returns JSON metadata

Metadata response:
```json
{ "avatarUrl": "<url-or-null>" }
```

Errors:
- 404 Not Found (invalid agent ID or no local avatar)
- 405 Method Not Allowed (non-GET/HEAD)

## Health / Status

No dedicated HTTP health endpoint is wired in the gateway HTTP server.
Health is exposed over the WebSocket protocol (`health` method) and via WS events.

## Additional HTTP Handlers

The following handlers are available but require additional documentation:

### Slack HTTP Handlers
- OAuth callback endpoints for Slack integration
- Event subscription webhook receiver
- Slash command handlers
- Interactive component handlers

### Plugin HTTP Handlers
- `POST /plugins/{pluginId}/{path}` - Plugin webhook routes
- Registered via `registerHttpRoute()` in plugin API
- Each plugin's routes are namespaced under `/plugins/{pluginId}/`

**BREAKING CHANGE from Node gateway:**
The Node gateway allowed plugins to register arbitrary paths (e.g., `/my-webhook`).
The Rust gateway enforces namespacing for security isolation. All plugin routes
are prefixed with `/plugins/{pluginId}/`. Existing webhook integrations must
update their URLs accordingly.

### Canvas Host / A2UI Endpoints
- `/a2ui/*` - Artifact-to-UI canvas host
- Static asset serving for canvas artifacts
- WebSocket upgrade for live canvas updates

### OpenResponses API
- `/v1/responses` - OpenAI-compatible responses endpoint
- Streaming SSE support
- Tool use and function calling

These endpoints require additional documentation of:
- Authentication requirements (which use gateway auth vs hooks token vs none)
- Request/response schemas
- Error handling behavior

See `src/server/http.rs` for the Rust implementation of HTTP handlers.
