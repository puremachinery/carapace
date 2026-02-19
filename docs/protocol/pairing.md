# Node and Device Pairing

Carapace manages two separate pairing subsystems for remote entities:

1. **Node pairing** (`node.pair.*`) - For application-level nodes (iOS app, headless services)
2. **Device pairing** (`device.pair.*`) - For WS connection-level device identity

Both follow the same state machine pattern but serve different purposes.

## Concepts

- **Pending request**: Entity asked to join; requires operator approval
- **Paired entity**: Approved with an issued auth token
- **Token**: Secret credential issued on approval (SHA-256 hashed in storage)

## State Machine

```
┌─────────┐     request      ┌─────────┐
│         │ ───────────────> │         │
│  (new)  │                  │ Pending │
│         │                  │         │
└─────────┘                  └────┬────┘
                                  │
                    ┌─────────────┼─────────────┐
                    │             │             │
                    ▼             ▼             ▼
              ┌──────────┐ ┌──────────┐ ┌─────────┐
              │ Approved │ │ Rejected │ │ Expired │
              └──────────┘ └──────────┘ └─────────┘
                    │
                    ▼
              Token issued
```

Pending requests expire after **5 minutes** (configurable via `PAIRING_EXPIRY_MS`).

## How Pairing Works

1. Entity connects to the Carapace WS endpoint and sends `node.pair.request` (or `device.pair.request`)
2. Carapace creates a **pending request** and emits `node.pair.requested` event
3. Operator approves or rejects via CLI or control API
4. On approval, Carapace issues a **new token** (tokens rotate on re-pair)
5. Entity stores token and uses it for future authentication

## Protocol Methods

### Node Pairing (`src/nodes/mod.rs`)

| Method | Description |
|--------|-------------|
| `node.pair.request` | Create or reuse a pending request |
| `node.pair.list` | List pending + paired nodes |
| `node.pair.approve` | Approve pending request (issues token) |
| `node.pair.reject` | Reject pending request |
| `node.pair.verify` | Verify `{ nodeId, token }` |

### Device Pairing (`src/devices/mod.rs`)

| Method | Description |
|--------|-------------|
| `device.pair.request` | Request device pairing |
| `device.pair.list` | List pending + paired devices |
| `device.pair.approve` | Approve with roles/scopes |
| `device.pair.reject` | Reject pending request |
| `device.pair.verify` | Verify device token |
| `device.token.rotate` | Rotate device token |
| `device.token.revoke` | Revoke device token |

### Events

- `node.pair.requested` / `device.pair.requested` - New pending request created
- `node.pair.resolved` / `device.pair.resolved` - Request approved/rejected/expired

## Request Parameters

### node.pair.request

```json
{
  "nodeId": "ios-device-abc123",
  "name": "Living Room iPad",
  "capabilities": ["audio", "camera", "location"],
  "publicKey": "base64-encoded-public-key",
  "silent": false
}
```

- `silent: true` hints that auto-approval flows may apply (e.g., same-host SSH verification)

### device.pair.request

```json
{
  "deviceId": "device-fingerprint",
  "name": "Peter's MacBook",
  "publicKey": "base64-encoded-public-key",
  "roles": ["operator"],
  "scopes": ["operator.read", "operator.write"],
  "clientId": "macos-app"
}
```

## Token Security

Tokens are sensitive credentials:

- **Storage**: SHA-256 hashed before persistence (never stored in plaintext)
- **Verification**: Constant-time comparison to prevent timing attacks
- **Rotation**: New token generated on each approval (old token invalidated)
- **Expiry**: Device tokens expire after 90 days by default

```rust
// From src/nodes/mod.rs
fn hash_token(token: &str) -> String {
    let digest = Sha256::digest(token.as_bytes());
    hex::encode(digest)
}

fn constant_time_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() { return false; }
    let mut result = 0u8;
    for (x, y) in a.bytes().zip(b.bytes()) {
        result |= x ^ y;
    }
    result == 0
}
```

## Storage

Pairing state is stored under the Carapace state directory:

Examples below use the Linux config directory (`~/.config/carapace`).

```
~/.config/carapace/
├── nodes/
│   ├── paired.json      # Paired nodes with hashed tokens
│   └── pending.json     # Pending requests (auto-expire)
└── devices/
    ├── paired.json      # Paired devices
    └── pending.json     # Pending requests
```

Files are written atomically (temp file + rename) to prevent corruption.

## Limits

To prevent resource exhaustion:

| Limit | Value | Purpose |
|-------|-------|---------|
| `MAX_PAIRED_NODES` | 100 | Max paired nodes (LRU eviction) |
| `MAX_PENDING_REQUESTS` | 50 | Max concurrent pending requests |
| `MAX_NODE_TOKENS` | 500 | Max total node tokens |
| `PAIRING_EXPIRY_MS` | 300,000 | Request expiry (5 minutes) |

## Implementation Files

| File | Description |
|------|-------------|
| `src/nodes/mod.rs` | Node pairing registry |
| `src/devices/mod.rs` | Device pairing registry |

Both modules include comprehensive test coverage. See also [Security](../security.md) for threat model and anti-patterns.

## Differences: Nodes vs Devices

| Aspect | Nodes | Devices |
|--------|-------|---------|
| Purpose | Application-level pairing | WS connection identity |
| Capabilities | Audio, camera, location, etc. | Roles and scopes |
| Token expiry | 30 days | 90 days |
| Use case | iOS/Android apps, headless nodes | CLI and other paired operator clients |
