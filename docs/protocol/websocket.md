# carapace Gateway WebSocket Protocol

Protocol Version: 3

## Connection Lifecycle

### Handshake Flow

```
Client                              Server
   |                                   |
   |-------- WS Connect -------------->|
   |                                   |
   |<------ connect.challenge ---------|  (event with nonce, ts)
   |                                   |
   |-------- connect (req) ----------->|  (auth + device identity)
   |                                   |
   |<------ hello-ok (res) ------------|  (features, snapshot, policy)
   |                                   |
   |<======= authenticated ============|
```

### Challenge Event

Sent immediately on WebSocket connection:

```json
{
  "type": "event",
  "event": "connect.challenge",
  "payload": {
    "nonce": "550e8400-e29b-41d4-a716-446655440000",
    "ts": 1706000000000
  }
}
```

### Connect Request

```json
{
  "type": "req",
  "id": "connect-1",
  "method": "connect",
  "params": {
    "minProtocol": 3,
    "maxProtocol": 3,
    "client": {
      "id": "my-client",
      "version": "1.0.0",
      "platform": "macos",
      "mode": "cli"
    },
    "device": {
      "id": "device-uuid",
      "publicKey": "base64-ed25519-pubkey",
      "signature": "base64-signature",
      "signedAt": 1706000000000,
      "nonce": "550e8400-e29b-41d4-a716-446655440000"
    },
    "auth": {
      "token": "gateway-token"
    }
  }
}
```

### Auth Methods

| Method | Field | Notes |
|--------|-------|-------|
| Token | `auth.token` | Timing-safe comparison against `gateway.auth.token` |
| Password | `auth.password` | Timing-safe comparison against `gateway.auth.password` |
| Tailscale | HTTP headers | Verified via `tailscale whois` (x-forwarded-for, tailscale-user-login) |
| Device Identity | `device.*` | Ed25519 signature verification (see Device Identity below) |
| Local Bypass | - | Loopback connections may skip auth if `gateway.bind=loopback` |

Note: The `auth` object only contains `token` and `password` fields. Device authentication
uses the separate `device` object with `id`, `publicKey`, `signature`, `signedAt`, and `nonce`.

### Hello-Ok Response

```json
{
  "type": "res",
  "id": "connect-1",
  "ok": true,
  "payload": {
    "type": "hello-ok",
    "protocol": 3,
    "server": {
      "version": "2025.1.26",
      "commit": "abc123",
      "host": "my-machine",
      "connId": "conn-uuid"
    },
    "features": {
      "methods": ["health", "sessions.list", ...],
      "events": ["tick", "presence", ...]
    },
    "snapshot": {
      "presence": [],
      "health": {},
      "stateVersion": { "presence": 1, "health": 1 },
      "uptimeMs": 12345
    },
    "policy": {
      "maxPayload": 524288,
      "maxBufferedBytes": 1572864,
      "tickIntervalMs": 30000
    }
  }
}
```

## Message Framing

### Request Frame

```json
{
  "type": "req",
  "id": "unique-request-id",
  "method": "method.name",
  "params": { ... }
}
```

### Response Frame

Success:
```json
{
  "type": "res",
  "id": "unique-request-id",
  "ok": true,
  "payload": { ... }
}
```

Error:
```json
{
  "type": "res",
  "id": "unique-request-id",
  "ok": false,
  "error": {
    "code": "INVALID_REQUEST",
    "message": "description",
    "details": { ... },
    "retryable": false
  }
}
```

### Event Frame

```json
{
  "type": "event",
  "event": "event.name",
  "payload": { ... },
  "stateVersion": { "presence": 5, "health": 3 }
}
```

## Methods

Base methods (108+) plus channel plugin methods. Channel plugins may add additional methods.

Note: Method dispatch is implemented in `src/server/ws/handlers/mod.rs`.

### Health & Status
- `health` - Get gateway health status
- `status` - Get gateway status summary

### Logs
- `logs.tail` - Stream log output

### Channels
- `channels.status` - Get channel connection status
- `channels.logout` - Logout from a channel

### Config
- `config.get` - Get configuration value
- `config.set` - Set configuration value
- `config.apply` - Apply configuration changes
- `config.patch` - Patch configuration object
- `config.validate` - Validate configuration without persisting
- `config.schema` - Get configuration schema

### Agent
- `agent` - Run agent with message
- `agent.identity.get` - Get agent identity
- `agent.wait` - Wait for agent completion

### Chat (WebChat WebSocket-native)
- `chat.send` - Send chat message
- `chat.history` - Get chat history
- `chat.abort` - Abort current chat

### Sessions
- `sessions.list` - List sessions
- `sessions.preview` - Preview session content
- `sessions.patch` - Patch session metadata
- `sessions.reset` - Reset session
- `sessions.delete` - Delete session
- `sessions.compact` - Compact session storage
- `sessions.archive` - Archive session to persistent storage (sets status to Archived/read-only)
- `sessions.restore` - Restore an archived session (sets status back to Active)
- `sessions.archives` - List all archived sessions with metadata and archive size
- `sessions.archive.delete` - Delete an archive file without affecting session metadata
- `sessions.export_user` - Export all sessions and histories for a user (GDPR data portability)
- `sessions.purge_user` - Delete all sessions and histories for a user (GDPR right to erasure)

Compatibility aliases:
- `agent.run` → `agent`
- `agent.cancel` → `chat.abort`
- `session.*` → `sessions.*`
- `config.update` → `config.patch`
- `exec.list` / `exec.approvals.list` → `exec.approvals.get`
- `exec.approve` / `exec.deny` → `exec.approval.resolve` (defaults decision to allow-once/deny when missing)

### TTS (Text-to-Speech)
- `tts.status` - Get TTS status
- `tts.providers` - List TTS providers
- `tts.voices` - List voices for current provider
- `tts.enable` - Enable TTS
- `tts.disable` - Disable TTS
- `tts.convert` - Convert text to speech
- `tts.speak` - Speak text immediately
- `tts.stop` - Stop TTS playback
- `tts.setProvider` - Set TTS provider
- `tts.setVoice` - Set TTS voice
- `tts.configure` - Configure TTS settings (rate, pitch, volume)

### Voice Wake
- `voicewake.get` - Get voice wake triggers
- `voicewake.set` - Set voice wake triggers (broadcasts `voicewake.changed`)
- `voicewake.enable` - Enable voice wake
- `voicewake.disable` - Disable voice wake
- `voicewake.keywords` - List available wake keywords
- `voicewake.test` - Test voice wake detection

### Wizard
- `wizard.start` - Start onboarding wizard
- `wizard.next` - Advance wizard step
- `wizard.cancel` - Cancel wizard
- `wizard.status` - Get wizard status

### Talk Mode
- `talk.mode` - Set talk mode (off, push-to-talk, voice-activated, continuous)
- `talk.status` - Get talk mode status
- `talk.start` - Start talk (begin listening)
- `talk.stop` - Stop talk (stop listening)
- `talk.configure` - Configure talk settings (VAD threshold, silence timeout)
- `talk.devices` - List available audio devices

### Models & Skills
- `models.list` - List available models
- `agents.list` - List available agents
- `skills.status` - Get skills status
- `skills.bins` - List skill binaries
- `skills.install` - Install a skill
- `skills.update` - Update skills

### Updates
- `update.run` - Run gateway update

### Cron
- `cron.list` - List cron jobs
- `cron.status` - Get cron status
- `cron.add` - Add cron job
- `cron.update` - Update cron job
- `cron.remove` - Remove cron job
- `cron.run` - Manually trigger cron job
- `cron.runs` - List cron run history

### Node Pairing (multi-gateway)
- `node.pair.request` - Request node pairing
- `node.pair.list` - List pairing requests
- `node.pair.approve` - Approve pairing
- `node.pair.reject` - Reject pairing
- `node.pair.verify` - Verify pairing

### Node Management
- `node.rename` - Rename a node
- `node.list` - List nodes
- `node.describe` - Get node details
- `node.invoke` - Invoke method on remote node
- `node.invoke.result` - Get invocation result
- `node.event` - Send event to node

### Device Pairing
- `device.pair.list` - List device pairing requests
- `device.pair.approve` - Approve device pairing
- `device.pair.reject` - Reject device pairing
- `device.token.rotate` - Rotate device token
- `device.token.revoke` - Revoke device token

### Exec Approvals
- `exec.approvals.get` - Get exec approval settings
- `exec.approvals.set` - Set exec approval settings
- `exec.approvals.node.get` - Get node-specific approvals
- `exec.approvals.node.set` - Set node-specific approvals
- `exec.approval.request` - Request exec approval
- `exec.approval.resolve` - Resolve exec approval

### Usage
- `usage.status` - Get usage status
- `usage.cost` - Get usage cost

### Heartbeat
- `last-heartbeat` - Get last heartbeat time
- `set-heartbeats` - Configure heartbeat settings

### System
- `wake` - Wake the gateway
- `send` - Send a message
- `system-presence` - Report system presence
- `system-event` - Send system event

## Events

Events are broadcast to connected clients. See `src/server/ws/mod.rs` for implementation.

| Event | Description |
|-------|-------------|
| `connect.challenge` | Sent on connection with nonce for auth |
| `agent` | Agent lifecycle events (start, progress, complete) |
| `chat` | Chat message events |
| `presence` | Connected clients update |
| `tick` | Periodic heartbeat (30s default) |
| `talk.mode` | Talk mode changed |
| `shutdown` | Server shutting down |
| `health` | Health status change |
| `heartbeat` | Heartbeat received |
| `cron` | Cron job events |
| `node.pair.requested` | Node pairing request received |
| `node.pair.resolved` | Node pairing decision made |
| `node.invoke.request` | Remote invocation request |
| `device.pair.requested` | Device pairing request received |
| `device.pair.resolved` | Device pairing decision made |
| `voicewake.changed` | Voice wake config changed |
| `exec.approval.requested` | Exec approval needed |
| `exec.approval.resolved` | Exec approval decided |

## Error Codes

| Code | Description | Retryable |
|------|-------------|-----------|
| `INVALID_REQUEST` | Validation/protocol error | No |
| `NOT_LINKED` | Channel not configured | No |
| `NOT_PAIRED` | Device not paired | No |
| `AGENT_TIMEOUT` | Agent exceeded timeout | Yes |
| `UNAVAILABLE` | Service temporarily unavailable | Yes |

## Close Codes

| Code | Meaning |
|------|---------|
| 1000 | Normal closure |
| 1002 | Protocol error (version mismatch) |
| 1008 | Policy violation (auth failure) |

### Common Close Reasons
- `handshake timeout` - No connect within 10s
- `protocol mismatch` - Incompatible protocol version
- `unauthorized` - Auth failed
- `device nonce required` - Remote connection missing nonce
- `device signature invalid` - Signature verification failed
- `pairing required` - Unknown device needs approval

## Constants

| Constant | Value |
|----------|-------|
| `PROTOCOL_VERSION` | 3 |
| `MAX_PAYLOAD_BYTES` | 524288 (512KB) |
| `MAX_BUFFERED_BYTES` | 1572864 (1.5MB) |
| `TICK_INTERVAL_MS` | 30000 (30s) |
| `HANDSHAKE_TIMEOUT_MS` | 10000 (10s) |
| `SIGNATURE_SKEW_MS` | 600000 (10min) |
