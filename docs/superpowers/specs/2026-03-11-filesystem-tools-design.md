# Filesystem Tools

Built-in tools that let agents read, search, write, and move files within operator-defined directory roots.

## Config & Validation

Top-level `filesystem` block in JSON5 config:

```json5
{
  filesystem: {
    enabled: false,           // default: disabled
    roots: [],                // absolute paths; required when enabled
    writeAccess: false,       // default: read-only
    maxReadBytes: 10485760,   // 10 MiB default
    excludePatterns: []       // glob patterns denied even within roots
  }
}
```

**Schema validation** (`src/config/schema.rs`):

- Add `"filesystem"` to `KNOWN_TOP_LEVEL_KEYS`.
- `validate_filesystem(cfg) -> Vec<Issue>`:
  - `enabled: true` with empty `roots` → `Severity::Warning` (tools register but every path is denied — fail-closed).
  - Non-absolute path in `roots` → `Severity::Error`.
  - Non-existent path in `roots` → `Severity::Warning`.
  - Unknown keys inside the block → `Severity::Warning`.

**Defaults** (`src/config/defaults.rs`):

Add a `FilesystemDefaults` struct with `#[serde(default)]` fields matching the values above. Merged under user values via the existing deep-merge path.

**Wiring**:

- Add `ToolsRegistry::with_config(cfg: &Value)` that calls `builtin_tools()` (existing, no args) and conditionally calls `filesystem_tools(cfg)` when `filesystem.enabled` is truthy.
- Add `pub mod filesystem_tools;` to `src/agent/mod.rs`.
- Keep `ToolsRegistry::new()` unchanged for existing tests.
- Change `src/main.rs` line ~173 from `ToolsRegistry::new()` to `ToolsRegistry::with_config(&cfg)`.

## Tools

Six tools in two tiers, gated by config.

### Read tier (always available when filesystem enabled)

| Tool | Parameters | Returns |
|------|-----------|---------|
| `file_read` | `path` (required), `offset` (bytes, optional), `limit` (bytes, optional) | `content`, `encoding` ("utf-8" or "base64"), `size`, `truncated` |
| `directory_list` | `path` (required), `glob` (filter pattern, optional) | `entries[]` with `name`, `type` ("file"/"dir"/"symlink"), `size`, `modified` |
| `file_stat` | `path` (required) | `size`, `modified`, `created`, `isDir`, `isSymlink`, `permissions` |
| `file_search` | `pattern` (required), `path` (root to search, required), `max_depth` (default 10), `content_pattern` (regex, optional) | `matches[]` with `path` and optional `line`/`snippet`, plus `entriesScanned` and `truncated` |

### Write tier (requires `writeAccess: true`)

| Tool | Parameters | Returns |
|------|-----------|---------|
| `file_write` | `path` (required), `content` (required), `create_dirs` (default true) | `bytesWritten`, `path` |
| `file_move` | `source` (required), `destination` (required) | `source`, `destination` |

No `file_delete` in the initial implementation. Agents can use `file_move` to move files to a staging area.

### Implementation pattern

All tools follow the existing `BuiltinTool` pattern from `src/agent/builtin_tools.rs`: struct with name, description, `input_schema` (JSON Schema), and handler closure `Box<dyn Fn(Value, &ToolInvokeContext) -> ToolInvokeResult + Send + Sync>`.

Read-tier tools and `file_write`/`file_move` use `std::fs` directly (synchronous), matching the pattern of the existing memory tools. These are single-file operations with bounded I/O.

`file_search` is the exception: it traverses up to 10,000 filesystem entries with optional regex content matching, which can block for a noticeable duration. Run the traversal through `crate::runtime_bridge::run_sync_blocking_send(async move { tokio::task::spawn_blocking(...) })` so multi-threaded runtimes get a proper blocking worker and current-thread runtimes use the existing spawned-runtime bridge instead of direct `block_in_place`.

`file_search` has a hard entry budget of 10,000 filesystem entries scanned. When hit, returns partial results with `truncated: true`.

New tools live in a new `src/agent/filesystem_tools.rs` module. A `pub fn filesystem_tools(cfg: &Value) -> Vec<BuiltinTool>` function returns the tool list, reading config values from the `filesystem` block.

Filesystem tools are automatically subject to the existing `ToolPolicy` system (`src/agent/tool_policy.rs`). Operators can restrict filesystem tools via allow-list/deny-list policies without additional work.

## Path Validation

Central `validate_path` function used by every tool before any I/O:

```
validate_path(requested: &str, roots: &[PathBuf], exclude_patterns: &[Pattern]) -> Result<PathBuf, String>
```

Steps:

1. **Canonicalize** the requested path (`std::fs::canonicalize`). This resolves symlinks, `..`, and `.` — a symlink pointing outside roots is caught here.
2. **Root check**: the canonical path must start with at least one configured root.
3. **Exclude pattern check**: match `excludePatterns` globs against the canonical path relative to its matching root. For example, pattern `node_modules` matches an entry named `node_modules` at any depth. Patterns support full glob syntax (`**/`, `*.log`, etc.) via the `glob` crate's `Pattern::matches_path`.

**Special case for `file_write`**: the target file may not exist yet. Canonicalize the *parent* directory instead, then append the filename. If the parent doesn't exist and `create_dirs` is true, canonicalize the nearest existing ancestor and verify it's within a root before creating intermediate directories.

**Glob dependency**: Add `glob` as a direct dependency in `Cargo.toml`. Version 0.3.3 is already in `Cargo.lock` as a transitive dependency.

### `directory_list` glob filter

The optional `glob` parameter on `directory_list` matches against entry *names only* (not full paths) and applies only to immediate children of the listed directory (non-recursive). This is a display filter, not a search — use `file_search` for recursive matching.
Invalid `glob` values return a tool error rather than silently disabling filtering.

## Testing Strategy

### Unit tests for `validate_path`

- Path within a root → allowed
- Path outside all roots → denied
- Path with `..` that escapes root → denied
- Symlink pointing outside root → denied
- Path matching exclude pattern → denied
- Multiple roots — path in second root works
- Empty roots list → all paths denied
- Non-existent path → error (not panic)

### Unit tests for each tool handler

All tests use a `tempdir` with a controlled file tree. The tempdir root is the single allowed root.

- Missing required params → `tool_error`
- Path outside roots → permission denied
- Happy path → correct result shape
- `file_read` on binary → base64 result with `encoding: "base64"`
- `file_read` exceeding `maxReadBytes` → truncated with indicator
- `file_write` when `writeAccess: false` → denied
- `file_search` hitting entry budget → partial results with `truncated: true`
- `directory_list` with glob filter → only matching entries

### Registration tests

- Filesystem disabled → baseline tool count unchanged (12 — 11 from `builtin_tools()` + 1 inline `time` tool)
- Filesystem enabled, read-only → 12 + 4 = 16
- Filesystem enabled, write access → 12 + 6 = 18

Approximately 25–35 new tests total. No golden/snapshot tests — pure logic tests.

## Error Handling & Edge Cases

- **File not found**: Tool error with the path included.
- **Permission denied (OS-level)**: Tool error with "permission denied" message, no raw OS error code.
- **Binary detection** (`file_read`): Read up to `maxReadBytes`. Check the first 8 KB of the read buffer (or the entire buffer if smaller than 8 KB) for null bytes. Binary → return content as base64 with `encoding: "base64"`. Text → return as utf-8 with `encoding: "utf-8"`. The detection happens on the already-read buffer, not as a separate I/O pass.
- **`maxReadBytes` exceeded**: Read up to the limit, return content plus `truncated: true` and `totalBytes`.
- **`file_write` to non-existent parent**: Create intermediate directories (path already validated).
- **`file_move` destination exists**: On Unix, `fs::rename` atomically overwrites. On Windows, `fs::rename` fails if the destination exists — use `fs::remove_file` then `fs::rename` as a fallback. Both source and destination must pass path validation.
- **`file_move` symlink source**: Rejected. The initial implementation only moves regular files and refuses symlink sources rather than renaming the symlink target implicitly.
- **`file_move` cross-device**: `fs::rename` fails with EXDEV when source and destination are on different filesystems. Since multiple `roots` could span mount points, return a clear tool error ("cannot move across filesystems") rather than a raw OS error. Copy-then-delete is out of scope for the initial implementation.
- **`file_search` scalability**: Entry budget (10,000) and capped `max_depth` are the protection. No wall-clock timeout — budget makes it deterministic. Handler runs through `runtime_bridge` + `spawn_blocking` to avoid starving tokio.
- **Config reload behavior**: Filesystem tool registration happens at startup. Changing `filesystem.*` config requires a process restart to take effect; hot reload does not currently add/remove tools or retune roots in-place.
- **Symlink loops**: `canonicalize` returns `Err` → tool error.
- **Empty roots when enabled**: Schema warns. Tools register but every path is denied (fail-closed).
- **TOCTOU race conditions**: Not addressed. Canonicalize-then-operate is the standard pattern used by Claude Code and similar tools. Acceptable for a local assistant.
