# Credential Storage

This document describes how carapace stores secrets.

## Status

This document mixes current behavior with planned design. Sections labeled
**Planned** describe future work; everything else describes current behavior.

## Scope

Secrets covered:
- Gateway auth tokens/passwords
- Provider auth profiles (API keys, OAuth access/refresh tokens, bearer tokens)
- Hooks token and browser control token
- GitHub Copilot token cache
- WhatsApp Web session material (treated as secret data)

Non-secrets (allowed to remain on disk as plaintext metadata):
- Config files (`carapace.json`) and include files
- Profile ordering/usage stats metadata (no secret fields)

## Storage API (Rust)

### Key namespace (all platforms)

Use a single service/namespace for all secrets and stable account keys:

- **Service name:** `carapace`
- **Account key:** `kind:{agentId}:{id}`

Examples:
- `auth-profile:main:anthropic:default`
- `gateway:token:default`
- `gateway:password:default`
- `hooks:token:default`
- `browser:control-token:default`
- `copilot:token:default`
- `whatsapp:session-key:default`
- `pairing:store:telegram`
- `pairing:allowFrom:telegram`

Values are stored as JSON strings so we can evolve schemas without changing the
secret store interface.

### Data payloads

Minimum JSON schema per secret type:

- **Auth profile credential** (`auth-profile:...`)
  ```json
  {
    "type": "api_key|oauth|token",
    "provider": "anthropic",
    "key": "...",
    "access": "...",
    "refresh": "...",
    "expires": 1700000000000,
    "email": "user@example.com",
    "accountId": "...",
    "projectId": "...",
    "enterpriseUrl": "..."
  }
  ```
  Fields mirror the gateway's `AuthProfileCredential` shape; only the fields
  present for the specific `type` are required.

- **Gateway auth**
  ```json
  { "token": "..." }
  ```
  ```json
  { "password": "..." }
  ```

- **Hooks token / browser control token**
  ```json
  { "token": "..." }
  ```

- **GitHub Copilot token cache**
  ```json
  { "token": "...", "expiresAt": 1700000000000, "updatedAt": 1700000000000 }
  ```

- **WhatsApp Web session key**
  ```json
  { "key": "{base64-encoded symmetric key}", "format": "v1" }
  ```
  The symmetric key is used to encrypt/decrypt the WhatsApp session bundle on disk.

- **Pairing store / allowlist**
  ```json
  { "version": 1, "payload": { "...": "..." } }
  ```
  Store the JSON as-is to avoid schema drift.

### Non-secret metadata (plaintext)

To support listing without relying on secret-store listing APIs:

- Store a non-secret index at `~/.config/carapace/credentials/index.json` containing:
  - secret key IDs (`kind`, `agentId`, `id`)
  - provider info (for auth profiles)
  - last updated timestamp

No secret fields are written to this file.

## Platform Backends

### macOS Keychain

- **Recommended crate:** `keyring` (uses Keychain on macOS)
- **Alternative:** `security-framework` if direct API access is needed
- **Service:** `carapace`
- **Account:** `kind:{agentId}:{id}`
- **Storage:** JSON string payloads

### Linux Keyutils (kernel keyring)

- **Recommended crate:** `keyring` (Keyutils backend)
- **Alternative:** `secret-service` when attribute queries are required (not used by default)
- **Collection:** kernel keyring (no D-Bus dependency)

**Fallback behavior if keyring storage is unavailable:**
- Do not persist secrets to disk.
- Log a clear error instructing the operator to enable kernel keyring support.
- Continue only with environment-sourced credentials for the current session.

### Windows Credential Manager

- **Recommended crate:** `keyring` (uses Credential Manager on Windows)
- **Alternative:** `windows-credentials` for direct access
- **Target name:** `carapace:{kind}:{agentId}:{id}`
- **Username:** `carapace` (static)
- **Storage:** JSON string payloads

## Edge Cases and Error Handling

Current behavior includes retry policy + backoff, index file locking, and basic
credential store health checks. The remainder of this section is planned unless noted.

### Locked Keychain / Unavailable Secret Store

**Scenario:** Gateway starts but the OS secret store is locked or unavailable.

**Behavior by platform:**

| Platform | Interactive Mode | Daemon Mode |
|----------|-----------------|-------------|
| macOS    | System prompts for keychain unlock | Fail with clear error; require unlock before daemon start |
| Linux    | Keyutils unavailable: warn and continue with env-only credentials | Same; no automatic prompt possible |
| Windows  | Credential Manager always available if user is logged in | N/A (Windows services run in session 0) |

**Implementation notes:**
- At startup, attempt a test read/write to detect locked state
- Log `WARN` if credentials unavailable; list which features are degraded
- Consider adding a `cara doctor` check for credential store health

### Timeout and Retry Policy

Keychain operations may block (e.g., waiting for user unlock prompt).

| Operation | Timeout | Retries | Backoff |
|-----------|---------|---------|---------|
| `get`     | 5s      | 2       | None (fail fast) |
| `set`     | 10s     | 3       | Exponential (100ms, 500ms, 2s) |
| `delete`  | 5s      | 2       | None |

**Retryable errors:**
- Transient keyring backend errors (Linux keyutils)
- Keychain temporarily locked during transition
- Transient I/O errors

**Non-retryable errors:**
- Keychain permanently locked (requires user action)
- Access denied (permission error)
- Keyring backend unavailable (e.g., kernel keyring disabled or unsupported)

### Credential Rotation Atomicity (rollback best-effort)

Current behavior:

1. Read current value (best-effort) and store in memory
2. Write new value to secret store
3. Verify new value can be read back
4. On verification failure, attempt rollback to the previous value (or delete if the prior value is known absent)
5. Update index.json only after successful write

Staged rotation:
1. Write the new value to `{key}:pending`
2. Validate out-of-band (e.g., test the new credential)
3. Promote with `commit_pending` (moves pending to active) or `discard_pending`

Currently this is exposed via the internal credential store APIs; no CLI command is wired yet.

**Failure modes:**
- If step 2 fails: credential unchanged, operation returns error
- If step 3 fails: log error, attempt rollback, return error (skip delete if prior value is unknown)

### Concurrent Access

Multiple processes may access credentials simultaneously:

**Index file (`credentials/index.json`):**
- Use a lock file for writes (not OS-level `flock`/`LockFileEx`)
- Reads do not require locks (eventual consistency acceptable)
- Lock timeout: 5 seconds, then fail with clear error

**Secret store:**
- OS secret stores handle their own concurrency
- No additional locking required for keychain operations

**Plugin credential isolation:**
- Prefix enforcement happens in the host, not the WASM plugin
- Even if a plugin attempts key injection (`../other-plugin:token`), the host
  sanitizes the key and always prepends `{plugin_id}:`

### Corruption Handling

**Corrupted index.json:**
- If JSON parse or validation fails, attempt to restore from `index.json.bak`
- If backup is valid, restore it to `index.json`
- If no valid backup exists, rename to `index.corrupt.{timestamp}` and create a new empty index
- On each save, write a best-effort backup of the previous index to `index.json.bak`
- On the first save, create a backup from the new index if none exists

**Planned:**
- Rebuild index by scanning secret store (if platform supports listing)
- On platforms without listing (macOS), document manual recovery workflow

**Invalid JSON in secret store:**
- If stored value is not valid JSON, treat as corrupt
- Log error with key name (not value)
- Return `None` from `credential-get`, do not crash

**Empty or missing values:**
- Treat empty string as "not set" (same as missing)
- `credential-get` returns `None` for empty values

### Plugin Credential Limits

To prevent abuse by malicious or buggy plugins:

| Limit | Value | Enforcement |
|-------|-------|-------------|
| Max credentials per plugin | 100 | Host rejects `set` after limit |
| Max key length | 64 characters | Host truncates/rejects |
| Max value length | 64 KB | Host rejects |
| Rate limit (writes) | 10/minute per plugin | Host rejects with retryable error |

**Quota tracking:**
- Store credential count in index.json under `plugins.{id}.count`
- Decrement on delete, increment on create
- Rate limit tracked in memory (resets on restart)
