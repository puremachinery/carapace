# Credential Storage

This document describes how carapace stores secrets and how to migrate legacy
plaintext credentials from the Node.js openclaw gateway.

## Status

This document mixes implemented behavior with planned design. Status tags:

- **Implemented** — present in the Rust gateway today.
- **Planned** — not implemented yet.
- **Partially implemented** — some pieces exist; remainder is planned.

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

## Legacy Plaintext Locations (Node Gateway)

Current sources to migrate, based on the Node implementation:

Paths below are under the platform config directory (examples use Linux
`~/.config/carapace`).

- `~/.config/carapace/credentials/oauth.json`
  - OAuth credentials keyed by provider.
  - Loaded via `resolveOAuthPath()` and merged into auth profiles.
- `~/.config/carapace/agents/{agentId}/agent/auth-profiles.json`
  - Primary auth store; contains API keys, tokens, OAuth credentials.
- `~/.config/carapace/agents/{agentId}/agent/auth.json`
  - Legacy auth store (same data shape as auth profiles, older format).
- `~/.config/carapace/credentials/github-copilot.token.json`
  - Cached GitHub Copilot API token (`token`, `expiresAt`, `updatedAt`).
- `~/.config/carapace/credentials/whatsapp/{accountId}/creds.json`
  - WhatsApp Web session credentials (Baileys state).
  - Legacy default account may use `~/.config/carapace/credentials/creds.json`.
  - Additional per-session JSON files may exist in the same directory.
- `~/.config/carapace/credentials/{channel}-pairing.json`
  - Pending pairing requests (short-lived but sensitive).
- `~/.config/carapace/credentials/{channel}-allowFrom.json`
  - Allowlist entries for pairing-based channels.

Notes:
- The credentials directory can be overridden by `CARAPACE_OAUTH_DIR`.
- The state directory can be overridden by `CARAPACE_STATE_DIR`.

## Storage API (Rust) — Implemented

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
  Fields mirror `AuthProfileCredential` from the Node gateway; only the fields
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
  Store the JSON as-is from legacy files to avoid schema drift.

### Non-secret metadata (plaintext) — Implemented

To support listing and migration without relying on secret-store listing APIs:

- Store a non-secret index at `~/.config/carapace/credentials/index.json` containing:
  - secret key IDs (`kind`, `agentId`, `id`)
  - provider info (for auth profiles)
  - last updated timestamp

No secret fields are written to this file.

## Platform Backends — Implemented

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

## Migration from Plaintext — Planned

### Strategy

1. Locate legacy credential roots:
   - `stateDir = CARAPACE_STATE_DIR ?? ~/.config/carapace`
   - `credentialsDir = CARAPACE_OAUTH_DIR ?? ${stateDir}/credentials`
   - `agentDir = ${stateDir}/agents/{agentId}/agent`
2. Load legacy files; for each secret:
   - Write to OS secret store under the new key namespace.
   - Record the key in `credentials/index.json` (non-secret metadata).
3. After successful writes:
   - Delete legacy plaintext files containing secrets.
   - Leave non-secret metadata files intact.

### File-by-file mapping

- `credentials/oauth.json`
  - For each provider entry, create `auth-profile:{agentId}:{provider}:default`.
- `agents/{agentId}/agent/auth-profiles.json`
  - For each profile entry, create `auth-profile:{agentId}:{profileId}`.
  - Rewrite the file to remove secret fields, keeping only non-secret metadata
    (profile IDs, provider, type, order, lastGood, usageStats).
- `agents/{agentId}/agent/auth.json` (legacy)
  - Same mapping as above, then delete the legacy file.
- `credentials/github-copilot.token.json`
  - Store as `copilot:token:default`, then delete the plaintext file.
- `credentials/whatsapp/{accountId}/...`
  - Generate a per-account symmetric key in the secret store:
    `whatsapp:session-key:{accountId}`.
  - Encrypt the WhatsApp session bundle on disk (format: `whatsapp/session.enc`).
  - Delete plaintext session files after successful encryption.
- `credentials/{channel}-pairing.json`
  - Store as `pairing:store:{channel}`, then delete plaintext.
- `credentials/{channel}-allowFrom.json`
  - Store as `pairing:allowFrom:{channel}`, then delete plaintext.

### External CLI credentials (read-only) — Planned

The Node gateway can sync external CLI credentials from:
- `~/.claude/.credentials.json` (Claude Code)
- `~/.codex/auth.json` (Codex)
- `~/.qwen/oauth_creds.json` (Qwen)

These files are owned by their respective CLIs. Do not delete or migrate them.
Instead, the Rust gateway should continue to read and import them into the
secret store (using the same `auth-profile` keys).

## Edge Cases and Error Handling — Partially implemented

Implemented today: retry policy + backoff, index file locking, and basic credential
store health checks. The remainder of this section is planned unless noted.

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

### Timeout and Retry Policy — Implemented

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

### Credential Rotation Atomicity — Implemented (rollback best-effort)

Current behavior:

1. Read current value (best-effort) and store in memory
2. Write new value to secret store
3. Verify new value can be read back
4. On verification failure, attempt rollback to the previous value (or delete if the prior value is known absent)
5. Update index.json only after successful write

Planned improvements:
- Support a `{key}:pending` staging key for critical credentials

**Failure modes:**
- If step 2 fails: credential unchanged, operation returns error
- If step 3 fails: log error, attempt rollback, return error (skip delete if prior value is unknown)

### Concurrent Access — Implemented

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

### Migration Failure Recovery — Planned

Migration may fail partway through (crash, power loss, etc.).

**State tracking:**
- Create `credentials/migration.state` before starting migration
- Record: `{ "version": 1, "startedAt": {ts}, "completed": [] }`
- Append each successfully migrated key to `completed` array
- Delete state file only after full migration success

**Recovery behavior:**
- On startup, if `migration.state` exists, resume migration
- Skip keys already in `completed` array
- If legacy file exists AND key in secret store, verify match, then delete legacy

**Integrity checks:**
- After migration, verify all keys in index.json are readable
- If any key unreadable, log WARN but continue (operator may need to re-enter)

### Corruption Handling — Partially implemented

**Corrupted index.json (implemented):**
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
- Provide `cara credential repair {key}` command for manual fix

**Empty or missing values:**
- Treat empty string as "not set" (same as missing)
- `credential-get` returns `None` for empty values

### Plugin Credential Limits — Implemented

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
