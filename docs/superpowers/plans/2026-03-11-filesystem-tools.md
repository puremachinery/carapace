# Filesystem Tools Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add six built-in filesystem tools (file_read, directory_list, file_stat, file_search, file_write, file_move) gated by a top-level `filesystem` config block.

**Architecture:** New `src/agent/filesystem_tools.rs` module provides path validation and tool handlers. Config defaults and schema validation follow existing patterns in `src/config/defaults.rs` and `src/config/schema.rs`. `ToolsRegistry::with_config()` conditionally registers filesystem tools at startup.

**Tech Stack:** Rust std::fs, glob 0.3, regex, base64, serde_json, runtime_bridge::run_sync_blocking_send + tokio::task::spawn_blocking (for all filesystem tool handlers).

**Spec:** `docs/superpowers/specs/2026-03-11-filesystem-tools-design.md`

---

## File Structure

| Action | File | Responsibility |
|--------|------|---------------|
| Create | `src/agent/filesystem_tools.rs` | Path validation, 6 tool handlers, `filesystem_tools(cfg)` entry point |
| Modify | `src/agent/mod.rs:24` | Add `pub mod filesystem_tools;` |
| Modify | `src/config/schema.rs:28-74` | Add `"filesystem"` to `KNOWN_TOP_LEVEL_KEYS`, add `validate_filesystem()` |
| Modify | `src/config/defaults.rs:30-53` | Add `FilesystemDefaults` struct, add field to `ConfigWithDefaults` |
| Modify | `src/plugins/tools.rs:121-158` | Add `ToolsRegistry::with_config(cfg)` method |
| Modify | `src/main.rs:173` | Change `ToolsRegistry::new()` to `ToolsRegistry::with_config(&cfg)` |
| Modify | `src/cli/chat.rs:85` | Change `ToolsRegistry::new()` to `ToolsRegistry::with_config(&cfg)` |
| Modify | `Cargo.toml:9` | Add `glob = "0.3"` to `[dependencies]` |

---

## Chunk 1: Foundation (Config, Defaults, Schema, Dependency)

### Task 1: Add glob dependency

**Files:**
- Modify: `Cargo.toml:9` (dependencies section)

- [ ] **Step 1: Add glob to Cargo.toml**

Add after the `regex = "1"` line:

```toml
glob = "0.3"
```

- [ ] **Step 2: Verify it compiles**

Run: `cargo check 2>&1 | tail -20`
Expected: compiles with no errors (glob 0.3.3 already in Cargo.lock)

- [ ] **Step 3: Commit**

```bash
git add Cargo.toml
git commit -m "build: add glob as direct dependency for filesystem tools"
```

---

### Task 2: Add filesystem defaults

**Files:**
- Modify: `src/config/defaults.rs`

- [ ] **Step 1: Write the test**

Add to the `tests` module at the bottom of `src/config/defaults.rs`:

```rust
    #[test]
    fn test_filesystem_defaults_applied() {
        let mut config = json!({});
        apply_defaults(&mut config);

        assert_eq!(config["filesystem"]["enabled"], false);
        assert_eq!(config["filesystem"]["writeAccess"], false);
        assert_eq!(config["filesystem"]["maxReadBytes"], 10_485_760);
        assert!(config["filesystem"]["roots"].as_array().unwrap().is_empty());
        assert!(config["filesystem"]["excludePatterns"].as_array().unwrap().is_empty());
    }

    #[test]
    fn test_filesystem_user_values_preserved() {
        let mut config = json!({
            "filesystem": {
                "enabled": true,
                "roots": ["/home/user/docs"],
                "writeAccess": true,
                "maxReadBytes": 1024
            }
        });
        apply_defaults(&mut config);

        assert_eq!(config["filesystem"]["enabled"], true);
        assert_eq!(config["filesystem"]["writeAccess"], true);
        assert_eq!(config["filesystem"]["maxReadBytes"], 1024);
        assert_eq!(config["filesystem"]["roots"][0], "/home/user/docs");
        // Missing field gets default
        assert!(config["filesystem"]["excludePatterns"].as_array().unwrap().is_empty());
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo nextest run -p carapace test_filesystem_defaults_applied test_filesystem_user_values_preserved 2>&1 | tail -20`
Expected: FAIL — `config["filesystem"]` is Null

- [ ] **Step 3: Add the FilesystemDefaults struct and wire it**

Add before the `// Public API` section (~line 526) in `src/config/defaults.rs`:

```rust
// ---------------------------------------------------------------------------
// Filesystem defaults
// ---------------------------------------------------------------------------

/// Default max read bytes (10 MiB).
const DEFAULT_FILESYSTEM_MAX_READ_BYTES: u64 = 10_485_760;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct FilesystemDefaults {
    #[serde(default)]
    enabled: bool,

    #[serde(default)]
    roots: Vec<String>,

    #[serde(default)]
    write_access: bool,

    #[serde(default = "default_filesystem_max_read_bytes")]
    max_read_bytes: u64,

    #[serde(default)]
    exclude_patterns: Vec<String>,
}

impl Default for FilesystemDefaults {
    fn default() -> Self {
        Self {
            enabled: false,
            roots: Vec::new(),
            write_access: false,
            max_read_bytes: default_filesystem_max_read_bytes(),
            exclude_patterns: Vec::new(),
        }
    }
}

fn default_filesystem_max_read_bytes() -> u64 {
    DEFAULT_FILESYSTEM_MAX_READ_BYTES
}
```

Then add the field to `ConfigWithDefaults` (after `vertex`):

```rust
    #[serde(default)]
    filesystem: FilesystemDefaults,
```

And add it to the fallback `ConfigWithDefaults` inside `apply_defaults()` (the `Err(e)` branch):

```rust
                filesystem: FilesystemDefaults::default(),
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo nextest run -p carapace test_filesystem_defaults 2>&1 | tail -20`
Expected: both tests PASS

- [ ] **Step 5: Run full test suite to check for regressions**

Run: `just test 2>&1 | tail -30`
Expected: all tests pass

- [ ] **Step 6: Commit**

```bash
git add src/config/defaults.rs
git commit -m "feat: add filesystem config defaults"
```

---

### Task 3: Add filesystem schema validation

**Files:**
- Modify: `src/config/schema.rs`

- [ ] **Step 1: Write the tests**

Add to the `tests` module at the bottom of `src/config/schema.rs`:

```rust
    // ===== Filesystem validation =====

    #[test]
    fn test_filesystem_valid_config() {
        let config = json!({
            "filesystem": {
                "enabled": true,
                "roots": ["/home/user/docs"],
                "writeAccess": false
            }
        });
        let issues = validate_schema(&config);
        assert!(issues.is_empty(), "unexpected issues: {:?}", issues);
    }

    #[test]
    fn test_filesystem_enabled_no_roots_warns() {
        let config = json!({
            "filesystem": {
                "enabled": true,
                "roots": []
            }
        });
        let issues = validate_schema(&config);
        assert!(issues.iter().any(|i| i.severity == Severity::Warning
            && i.path.contains("filesystem")
            && i.message.contains("roots")));
    }

    #[test]
    fn test_filesystem_relative_path_is_error() {
        let config = json!({
            "filesystem": {
                "enabled": true,
                "roots": ["relative/path"]
            }
        });
        let issues = validate_schema(&config);
        assert!(issues.iter().any(|i| i.severity == Severity::Error
            && i.path.contains("roots")
            && i.message.contains("absolute")));
    }

    #[test]
    fn test_filesystem_nonexistent_path_warns() {
        let config = json!({
            "filesystem": {
                "enabled": true,
                "roots": ["/nonexistent/path/that/does/not/exist/27364"]
            }
        });
        let issues = validate_schema(&config);
        assert!(issues.iter().any(|i| i.severity == Severity::Warning
            && i.message.contains("does not exist")));
    }

    #[test]
    fn test_filesystem_unknown_key_warns() {
        let config = json!({
            "filesystem": {
                "enabled": true,
                "roots": ["/tmp"],
                "unknownSetting": true
            }
        });
        let issues = validate_schema(&config);
        assert!(issues.iter().any(|i| i.severity == Severity::Warning
            && i.message.contains("unknownSetting")));
    }

    #[test]
    fn test_filesystem_invalid_exclude_pattern_is_error() {
        let config = json!({
            "filesystem": {
                "enabled": true,
                "roots": ["/tmp"],
                "excludePatterns": ["[invalid"]
            }
        });
        let issues = validate_schema(&config);
        assert!(issues.iter().any(|i| i.severity == Severity::Error
            && i.path.contains("excludePatterns")
            && i.message.contains("invalid glob pattern")));
    }

    #[test]
    fn test_filesystem_disabled_skips_validation() {
        let config = json!({
            "filesystem": {
                "enabled": false,
                "roots": ["not-absolute"]
            }
        });
        let issues = validate_schema(&config);
        // Should not produce errors when disabled
        assert!(!issues.iter().any(|i| i.severity == Severity::Error));
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo nextest run -p carapace test_filesystem_valid_config test_filesystem_enabled_no_roots_warns test_filesystem_relative_path_is_error test_filesystem_nonexistent_path_warns test_filesystem_unknown_key_warns test_filesystem_disabled_skips_validation 2>&1 | tail -30`
Expected: most FAIL — `validate_filesystem` doesn't exist yet

- [ ] **Step 3: Add "filesystem" to KNOWN_TOP_LEVEL_KEYS**

In `src/config/schema.rs`, add `"filesystem"` to the `KNOWN_TOP_LEVEL_KEYS` array (after `"vertex"`):

```rust
    "vertex",
    "filesystem",
```

- [ ] **Step 4: Add validate_filesystem function**

Add after the last `validate_*` function in `src/config/schema.rs`:

```rust
fn validate_filesystem(obj: &serde_json::Map<String, Value>, issues: &mut Vec<SchemaIssue>) {
    let fs_cfg = match obj.get("filesystem").and_then(|v| v.as_object()) {
        Some(f) => f,
        None => return,
    };

    let enabled = fs_cfg
        .get("enabled")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    // Known keys inside filesystem block
    let known_keys = [
        "enabled",
        "roots",
        "writeAccess",
        "maxReadBytes",
        "excludePatterns",
    ];
    for key in fs_cfg.keys() {
        if !known_keys.contains(&key.as_str()) {
            issues.push(SchemaIssue {
                severity: Severity::Warning,
                path: format!(".filesystem.{}", key),
                message: format!("Unknown filesystem configuration key: {}", key),
            });
        }
    }

    // Skip deeper validation if disabled
    if !enabled {
        return;
    }

    let roots = fs_cfg.get("roots").and_then(|v| v.as_array());

    let is_empty = roots.map_or(true, |a| a.is_empty());
    if is_empty {
        issues.push(SchemaIssue {
            severity: Severity::Warning,
            path: ".filesystem.roots".to_string(),
            message: "filesystem is enabled but roots is empty; all paths will be denied"
                .to_string(),
        });
    }

    if let Some(arr) = roots {
        for (i, root) in arr.iter().enumerate() {
            if let Some(s) = root.as_str() {
                let path = std::path::Path::new(s);
                if !path.is_absolute() {
                    issues.push(SchemaIssue {
                        severity: Severity::Error,
                        path: format!(".filesystem.roots[{}]", i),
                        message: format!(
                            "filesystem root must be an absolute path, got \"{}\"",
                            s
                        ),
                    });
                } else if !path.exists() {
                    issues.push(SchemaIssue {
                        severity: Severity::Warning,
                        path: format!(".filesystem.roots[{}]", i),
                        message: format!("filesystem root does not exist: \"{}\"", s),
                    });
                }
            }
        }
    }

    // Validate excludePatterns syntax
    if let Some(patterns) = fs_cfg.get("excludePatterns").and_then(|v| v.as_array()) {
        for (i, pat) in patterns.iter().enumerate() {
            if let Some(s) = pat.as_str() {
                if glob::Pattern::new(s).is_err() {
                    issues.push(SchemaIssue {
                        severity: Severity::Error,
                        path: format!(".filesystem.excludePatterns[{}]", i),
                        message: format!(
                            "invalid glob pattern \"{}\"; fix or remove it (invalid \
                             patterns cause startup failure to prevent silent access widening)",
                            s
                        ),
                    });
                }
            }
        }
    }
}
```

- [ ] **Step 5: Wire validate_filesystem into validate_schema**

Add the call in `validate_schema()` after `validate_vertex(obj, &mut issues);`:

```rust
    validate_filesystem(obj, &mut issues);
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `cargo nextest run -p carapace test_filesystem_ 2>&1 | tail -30`
Expected: all 6 filesystem schema tests PASS

- [ ] **Step 7: Run full test suite**

Run: `just test 2>&1 | tail -30`
Expected: all tests pass

- [ ] **Step 8: Commit**

```bash
git add src/config/schema.rs
git commit -m "feat: add filesystem config schema validation"
```

---

## Chunk 2: Path Validation & Module Setup

### Task 4: Create filesystem_tools module with path validation

**Files:**
- Create: `src/agent/filesystem_tools.rs`
- Modify: `src/agent/mod.rs:24`

- [ ] **Step 1: Write path validation tests**

Create `src/agent/filesystem_tools.rs` with the test module first:

```rust
//! Filesystem tools — read, search, write, and move files within configured roots.

use std::path::PathBuf;

use glob::Pattern;

/// Validate that a requested path is allowed by the configured roots and exclude patterns.
///
/// Returns the canonicalized path on success, or an error message on failure.
pub fn validate_path(
    requested: &str,
    roots: &[PathBuf],
    exclude_patterns: &[Pattern],
) -> Result<PathBuf, String> {
    todo!()
}

/// Validate a path for write operations where the target file may not exist yet.
///
/// Canonicalizes the parent directory and appends the filename.
pub fn validate_write_path(
    requested: &str,
    roots: &[PathBuf],
    exclude_patterns: &[Pattern],
    create_dirs: bool,
) -> Result<PathBuf, String> {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn setup_test_tree() -> TempDir {
        let tmp = TempDir::new().unwrap();
        fs::create_dir_all(tmp.path().join("subdir")).unwrap();
        fs::write(tmp.path().join("hello.txt"), "hello world").unwrap();
        fs::write(tmp.path().join("subdir/nested.txt"), "nested content").unwrap();
        fs::write(tmp.path().join("secret.log"), "sensitive data").unwrap();
        tmp
    }

    #[test]
    fn test_validate_path_within_root() {
        let tmp = setup_test_tree();
        let roots = vec![tmp.path().to_path_buf()];
        let result = validate_path(
            tmp.path().join("hello.txt").to_str().unwrap(),
            &roots,
            &[],
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_path_outside_root() {
        let tmp = setup_test_tree();
        let roots = vec![tmp.path().join("subdir")];
        let result = validate_path(
            tmp.path().join("hello.txt").to_str().unwrap(),
            &roots,
            &[],
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("outside"));
    }

    #[test]
    fn test_validate_path_dotdot_escape() {
        let tmp = setup_test_tree();
        let roots = vec![tmp.path().join("subdir")];
        let escaped = tmp.path().join("subdir/../hello.txt");
        let result = validate_path(escaped.to_str().unwrap(), &roots, &[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_path_exclude_pattern() {
        let tmp = setup_test_tree();
        let roots = vec![tmp.path().to_path_buf()];
        let pattern = Pattern::new("*.log").unwrap();
        let result = validate_path(
            tmp.path().join("secret.log").to_str().unwrap(),
            &roots,
            &[pattern],
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("excluded"));
    }

    #[test]
    fn test_validate_path_multiple_roots() {
        let tmp1 = TempDir::new().unwrap();
        let tmp2 = TempDir::new().unwrap();
        fs::write(tmp2.path().join("file.txt"), "content").unwrap();
        let roots = vec![tmp1.path().to_path_buf(), tmp2.path().to_path_buf()];
        let result = validate_path(
            tmp2.path().join("file.txt").to_str().unwrap(),
            &roots,
            &[],
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_path_empty_roots() {
        let tmp = setup_test_tree();
        let result = validate_path(
            tmp.path().join("hello.txt").to_str().unwrap(),
            &[],
            &[],
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_path_nonexistent() {
        let tmp = setup_test_tree();
        let roots = vec![tmp.path().to_path_buf()];
        let result = validate_path(
            tmp.path().join("no_such_file.txt").to_str().unwrap(),
            &roots,
            &[],
        );
        assert!(result.is_err());
    }

    #[cfg(unix)]
    #[test]
    fn test_validate_path_symlink_outside_root() {
        let tmp = setup_test_tree();
        let outside = TempDir::new().unwrap();
        fs::write(outside.path().join("secret.txt"), "outside").unwrap();
        std::os::unix::fs::symlink(
            outside.path().join("secret.txt"),
            tmp.path().join("link.txt"),
        ).unwrap();
        let roots = vec![tmp.path().to_path_buf()];
        let result = validate_path(
            tmp.path().join("link.txt").to_str().unwrap(),
            &roots,
            &[],
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_write_path_new_file() {
        let tmp = setup_test_tree();
        let roots = vec![tmp.path().to_path_buf()];
        let result = validate_write_path(
            tmp.path().join("new_file.txt").to_str().unwrap(),
            &roots,
            &[],
            false,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_write_path_new_dir_with_create() {
        let tmp = setup_test_tree();
        let roots = vec![tmp.path().to_path_buf()];
        let result = validate_write_path(
            tmp.path().join("newdir/file.txt").to_str().unwrap(),
            &roots,
            &[],
            true,
        );
        assert!(result.is_ok());
        // Directory should have been created
        assert!(tmp.path().join("newdir").exists());
    }

    #[test]
    fn test_validate_write_path_no_create_dirs() {
        let tmp = setup_test_tree();
        let roots = vec![tmp.path().to_path_buf()];
        let result = validate_write_path(
            tmp.path().join("nonexistent_dir/file.txt").to_str().unwrap(),
            &roots,
            &[],
            false,
        );
        assert!(result.is_err());
    }
}
```

- [ ] **Step 2: Add module declaration to mod.rs**

Add after `pub mod builtin_tools;` in `src/agent/mod.rs`:

```rust
pub mod filesystem_tools;
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cargo nextest run -p carapace filesystem_tools::tests 2>&1 | tail -20`
Expected: FAIL — `todo!()` panics

- [ ] **Step 4: Implement validate_path**

Replace the `todo!()` in `validate_path`:

```rust
pub fn validate_path(
    requested: &str,
    roots: &[PathBuf],
    exclude_patterns: &[Pattern],
) -> Result<PathBuf, String> {
    let canonical = std::fs::canonicalize(requested)
        .map_err(|e| format!("cannot resolve path \"{}\": {}", requested, e))?;

    // Root check
    let matching_root = roots.iter().find(|root| canonical.starts_with(root));
    if matching_root.is_none() {
        return Err(format!(
            "path \"{}\" is outside all configured filesystem roots",
            canonical.display()
        ));
    }
    let root = matching_root.unwrap();

    // Exclude pattern check (match against path relative to root)
    let relative = canonical.strip_prefix(root).unwrap_or(&canonical);
    for pattern in exclude_patterns {
        if pattern.matches_path(relative) {
            return Err(format!(
                "path \"{}\" is excluded by pattern \"{}\"",
                canonical.display(),
                pattern
            ));
        }
        // Also check each component for directory-level patterns like "node_modules"
        for component in relative.components() {
            if let std::path::Component::Normal(name) = component {
                if pattern.matches(name.to_str().unwrap_or("")) {
                    return Err(format!(
                        "path \"{}\" is excluded by pattern \"{}\"",
                        canonical.display(),
                        pattern
                    ));
                }
            }
        }
    }

    Ok(canonical)
}
```

- [ ] **Step 5: Implement validate_write_path**

Replace the `todo!()` in `validate_write_path`:

```rust
pub fn validate_write_path(
    requested: &str,
    roots: &[PathBuf],
    exclude_patterns: &[Pattern],
    create_dirs: bool,
) -> Result<PathBuf, String> {
    let path = PathBuf::from(requested);
    let filename = path
        .file_name()
        .ok_or_else(|| format!("path \"{}\" has no filename", requested))?;

    let parent = path
        .parent()
        .ok_or_else(|| format!("path \"{}\" has no parent directory", requested))?;

    if !parent.exists() {
        if !create_dirs {
            return Err(format!(
                "parent directory \"{}\" does not exist",
                parent.display()
            ));
        }
        // Find the nearest existing ancestor within a root
        let mut ancestor = parent.to_path_buf();
        while !ancestor.exists() {
            ancestor = ancestor
                .parent()
                .ok_or_else(|| "cannot find existing ancestor directory".to_string())?
                .to_path_buf();
        }
        let canonical_ancestor = std::fs::canonicalize(&ancestor)
            .map_err(|e| format!("cannot resolve ancestor \"{}\": {}", ancestor.display(), e))?;

        if !roots.iter().any(|root| canonical_ancestor.starts_with(root)) {
            return Err(format!(
                "path \"{}\" is outside all configured filesystem roots",
                requested
            ));
        }

        std::fs::create_dir_all(parent)
            .map_err(|e| format!("failed to create directories: {}", e))?;
    }

    let canonical_parent = std::fs::canonicalize(parent)
        .map_err(|e| format!("cannot resolve parent \"{}\": {}", parent.display(), e))?;

    // Check parent is within a root
    let matching_root = roots.iter().find(|root| canonical_parent.starts_with(root));
    if matching_root.is_none() {
        return Err(format!(
            "path \"{}\" is outside all configured filesystem roots",
            requested
        ));
    }
    let root = matching_root.unwrap();

    let full_path = canonical_parent.join(filename);

    // Exclude pattern check
    let relative = full_path.strip_prefix(root).unwrap_or(&full_path);
    for pattern in exclude_patterns {
        if pattern.matches_path(relative) {
            return Err(format!(
                "path \"{}\" is excluded by pattern \"{}\"",
                full_path.display(),
                pattern
            ));
        }
        for component in relative.components() {
            if let std::path::Component::Normal(name) = component {
                if pattern.matches(name.to_str().unwrap_or("")) {
                    return Err(format!(
                        "path \"{}\" is excluded by pattern \"{}\"",
                        full_path.display(),
                        pattern
                    ));
                }
            }
        }
    }

    Ok(full_path)
}
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `cargo nextest run -p carapace filesystem_tools::tests 2>&1 | tail -30`
Expected: all tests PASS

- [ ] **Step 7: Run full test suite**

Run: `just test 2>&1 | tail -30`
Expected: all tests pass

- [ ] **Step 8: Commit**

```bash
git add src/agent/filesystem_tools.rs src/agent/mod.rs
git commit -m "feat: add filesystem_tools module with path validation"
```

---

## Chunk 3: Read-Tier Tool Handlers

### Task 5: Implement file_read tool

**Files:**
- Modify: `src/agent/filesystem_tools.rs`

- [ ] **Step 1: Write file_read tests**

Add to the `tests` module in `src/agent/filesystem_tools.rs`:

```rust
    use crate::plugins::tools::{ToolInvokeContext, ToolInvokeResult};
    use serde_json::json;

    fn test_ctx() -> ToolInvokeContext {
        ToolInvokeContext::default()
    }

    // ===== file_read =====

    #[test]
    fn test_file_read_happy_path() {
        let tmp = setup_test_tree();
        let cfg = make_test_config(tmp.path(), false);
        let tools = filesystem_tools(&cfg);
        let tool = tools.iter().find(|t| t.name == "file_read").unwrap();
        let result = (tool.handler)(
            json!({ "path": tmp.path().join("hello.txt").to_str().unwrap() }),
            &test_ctx(),
        );
        match &result {
            ToolInvokeResult::Success { ok, result } => {
                assert!(ok);
                assert_eq!(result["content"], "hello world");
                assert_eq!(result["encoding"], "utf-8");
                assert_eq!(result["truncated"], false);
            }
            _ => panic!("expected success, got {:?}", result),
        }
    }

    #[test]
    fn test_file_read_missing_path_param() {
        let tmp = setup_test_tree();
        let cfg = make_test_config(tmp.path(), false);
        let tools = filesystem_tools(&cfg);
        let tool = tools.iter().find(|t| t.name == "file_read").unwrap();
        let result = (tool.handler)(json!({}), &test_ctx());
        match &result {
            ToolInvokeResult::Error { ok, .. } => assert!(!ok),
            _ => panic!("expected error"),
        }
    }

    #[test]
    fn test_file_read_outside_root() {
        let tmp = setup_test_tree();
        let cfg = make_test_config(tmp.path().join("subdir").as_path(), false);
        let tools = filesystem_tools(&cfg);
        let tool = tools.iter().find(|t| t.name == "file_read").unwrap();
        let result = (tool.handler)(
            json!({ "path": tmp.path().join("hello.txt").to_str().unwrap() }),
            &test_ctx(),
        );
        match &result {
            ToolInvokeResult::Error { .. } => {}
            _ => panic!("expected error for path outside root"),
        }
    }

    #[test]
    fn test_file_read_binary_returns_base64() {
        let tmp = setup_test_tree();
        fs::write(tmp.path().join("binary.bin"), b"\x00\x01\x02\xff").unwrap();
        let cfg = make_test_config(tmp.path(), false);
        let tools = filesystem_tools(&cfg);
        let tool = tools.iter().find(|t| t.name == "file_read").unwrap();
        let result = (tool.handler)(
            json!({ "path": tmp.path().join("binary.bin").to_str().unwrap() }),
            &test_ctx(),
        );
        match &result {
            ToolInvokeResult::Success { result, .. } => {
                assert_eq!(result["encoding"], "base64");
            }
            _ => panic!("expected success"),
        }
    }

    #[test]
    fn test_file_read_truncation() {
        let tmp = setup_test_tree();
        fs::write(tmp.path().join("big.txt"), "x".repeat(200)).unwrap();
        // Use a config with tiny maxReadBytes
        let cfg = json!({
            "filesystem": {
                "enabled": true,
                "roots": [tmp.path().to_str().unwrap()],
                "maxReadBytes": 50
            }
        });
        let tools = filesystem_tools(&cfg);
        let tool = tools.iter().find(|t| t.name == "file_read").unwrap();
        let result = (tool.handler)(
            json!({ "path": tmp.path().join("big.txt").to_str().unwrap() }),
            &test_ctx(),
        );
        match &result {
            ToolInvokeResult::Success { result, .. } => {
                assert_eq!(result["truncated"], true);
                assert_eq!(result["content"].as_str().unwrap().len(), 50);
            }
            _ => panic!("expected success"),
        }
    }
```

Also add the `make_test_config` helper above the tests:

```rust
    fn make_test_config(root: &std::path::Path, write_access: bool) -> serde_json::Value {
        json!({
            "filesystem": {
                "enabled": true,
                "roots": [root.to_str().unwrap()],
                "writeAccess": write_access,
                "maxReadBytes": 10_485_760
            }
        })
    }
```

- [ ] **Step 2: Add filesystem_tools function stub and file_read handler**

Add at the top of `src/agent/filesystem_tools.rs` (after the existing imports):

```rust
use std::fs;
use std::io::Read;

use base64::Engine;
use serde_json::{json, Value};

use crate::plugins::tools::{BuiltinTool, ToolInvokeContext, ToolInvokeResult};

/// Run a potentially long-running sync closure, signaling the tokio runtime
/// when running inside a multi-threaded scheduler.
///
/// Carapace always runs with `rt-multi-thread` in production (see Cargo.toml
/// tokio features), so `block_in_place` is the expected path. The direct-
/// execution fallback covers two cases:
///   1. Unit tests that run without a tokio runtime.
///   2. Current-thread runtimes, where `block_in_place` panics. Since tool
///      handlers are already sync (`Fn(Value, &Ctx) -> Result`), executing
///      directly is correct — it blocks the single thread, but so would any
///      other sync tool handler.
///
/// This is for *sync* work, not async futures — the runtime_bridge
/// (`run_sync_blocking_send`) bridges async-to-sync, a different use case.
fn run_blocking<T>(f: impl FnOnce() -> T) -> T {
    match tokio::runtime::Handle::try_current() {
        Ok(h) if h.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
            tokio::task::block_in_place(f)
        }
        _ => f(),
    }
}
```

Add the `FilesystemConfig` struct and `filesystem_tools` function:

```rust
/// Parsed filesystem configuration snapshot, captured at tool registration time.
#[derive(Debug, Clone)]
/// Default entry budget for file_search traversal.
const DEFAULT_SEARCH_ENTRY_BUDGET: usize = 10_000;

struct FilesystemConfig {
    roots: Vec<PathBuf>,
    write_access: bool,
    max_read_bytes: u64,
    exclude_patterns: Vec<Pattern>,
    search_entry_budget: usize,
    /// Set to true when config has fatal errors (e.g., invalid exclude patterns).
    /// When poisoned, `filesystem_tools()` returns no tools.
    poisoned: bool,
}

impl FilesystemConfig {
    fn from_value(cfg: &Value) -> Self {
        let fs_cfg = cfg.get("filesystem").unwrap_or(&Value::Null);
        // Canonicalize roots at config-parse time so that starts_with comparisons
        // work correctly (e.g., /tmp -> /private/tmp on macOS).
        // Roots that fail to canonicalize are logged and excluded (fail-closed:
        // an invalid root grants zero access, not wider access).
        let roots: Vec<PathBuf> = fs_cfg
            .get("roots")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str())
                    .filter_map(|s| match std::fs::canonicalize(s) {
                        Ok(p) => Some(p),
                        Err(e) => {
                            tracing::warn!(
                                root = %s,
                                error = %e,
                                "filesystem root cannot be resolved; it will be excluded"
                            );
                            None
                        }
                    })
                    .collect()
            })
            .unwrap_or_default();

        let write_access = fs_cfg
            .get("writeAccess")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let max_read_bytes = fs_cfg
            .get("maxReadBytes")
            .and_then(|v| v.as_u64())
            .unwrap_or(10_485_760);

        // Invalid patterns cause the entire filesystem feature to be disabled
        // (fail-closed). Schema validation catches these at startup with
        // Severity::Error, so this is a defence-in-depth measure.
        let mut has_invalid_pattern = false;
        let exclude_patterns: Vec<Pattern> = fs_cfg
            .get("excludePatterns")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str())
                    .filter_map(|s| match Pattern::new(s) {
                        Ok(p) => Some(p),
                        Err(e) => {
                            tracing::error!(
                                pattern = %s,
                                error = %e,
                                "invalid exclude pattern; filesystem tools will be disabled"
                            );
                            has_invalid_pattern = true;
                            None
                        }
                    })
                    .collect()
            })
            .unwrap_or_default();


        Self {
            roots,
            write_access,
            max_read_bytes,
            exclude_patterns,
            search_entry_budget: DEFAULT_SEARCH_ENTRY_BUDGET,
            poisoned: has_invalid_pattern,
        }
    }
}

/// Return filesystem tool definitions based on config.
///
/// Only called when `filesystem.enabled` is truthy. Config values are
/// snapshot-captured into handler closures at registration time.
pub fn filesystem_tools(cfg: &Value) -> Vec<BuiltinTool> {
    let config = FilesystemConfig::from_value(cfg);

    if config.poisoned {
        tracing::error!("filesystem tools disabled due to invalid configuration");
        return Vec::new();
    }

    let mut tools = Vec::new();

    // Read tier (always)
    tools.push(file_read_tool(config.clone()));

    tools
}
```

Then add the `file_read_tool` function:

```rust
fn file_read_tool(config: FilesystemConfig) -> BuiltinTool {
    BuiltinTool {
        name: "file_read".to_string(),
        description: "Read the contents of a file within configured filesystem roots.".to_string(),
        input_schema: json!({
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Absolute path to the file to read."
                },
                "offset": {
                    "type": "integer",
                    "description": "Byte offset to start reading from (optional)."
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum bytes to read (optional, defaults to maxReadBytes)."
                }
            },
            "required": ["path"],
            "additionalProperties": false
        }),
        handler: Box::new(move |args, _ctx| {
            let path_str = match args.get("path").and_then(|v| v.as_str()) {
                Some(p) => p,
                None => return ToolInvokeResult::tool_error("missing required parameter: path"),
            };

            let canonical = match validate_path(path_str, &config.roots, &config.exclude_patterns) {
                Ok(p) => p,
                Err(e) => return ToolInvokeResult::tool_error(e),
            };

            let metadata = match fs::metadata(&canonical) {
                Ok(m) => m,
                Err(e) => return ToolInvokeResult::tool_error(format!("cannot stat \"{}\": {}", path_str, e)),
            };

            if metadata.is_dir() {
                return ToolInvokeResult::tool_error(format!("\"{}\" is a directory, not a file", path_str));
            }

            let file_size = metadata.len();
            let offset = args.get("offset").and_then(|v| v.as_u64()).unwrap_or(0);
            let limit = args
                .get("limit")
                .and_then(|v| v.as_u64())
                .unwrap_or(config.max_read_bytes)
                .min(config.max_read_bytes);

            let mut file = match fs::File::open(&canonical) {
                Ok(f) => f,
                Err(e) => {
                    let msg = if e.kind() == std::io::ErrorKind::PermissionDenied {
                        format!("permission denied: \"{}\"", path_str)
                    } else {
                        format!("cannot read \"{}\": {}", path_str, e)
                    };
                    return ToolInvokeResult::tool_error(msg);
                }
            };

            if offset > 0 {
                use std::io::Seek;
                if let Err(e) = file.seek(std::io::SeekFrom::Start(offset)) {
                    return ToolInvokeResult::tool_error(format!("seek failed: {}", e));
                }
            }

            let mut buf = Vec::new();
            match file.take(limit).read_to_end(&mut buf) {
                Ok(_) => {}
                Err(e) => {
                    let msg = if e.kind() == std::io::ErrorKind::PermissionDenied {
                        format!("permission denied: \"{}\"", path_str)
                    } else {
                        format!("cannot read \"{}\": {}", path_str, e)
                    };
                    return ToolInvokeResult::tool_error(msg);
                }
            };

            let truncated = file_size > offset + buf.len() as u64;

            // Binary detection: check first 8KB (or entire buffer) for null bytes
            let check_len = bytes_read.min(8192);
            let is_binary = buf[..check_len].contains(&0);

            let (content, encoding) = if is_binary {
                (
                    base64::engine::general_purpose::STANDARD.encode(&buf),
                    "base64",
                )
            } else {
                (String::from_utf8_lossy(&buf).into_owned(), "utf-8")
            };

            ToolInvokeResult::success(json!({
                "content": content,
                "encoding": encoding,
                "size": file_size,
                "truncated": truncated,
                "totalBytes": file_size
            }))
        }),
    }
}
```

- [ ] **Step 3: Run file_read tests**

Run: `cargo nextest run -p carapace test_file_read 2>&1 | tail -30`
Expected: all file_read tests PASS

- [ ] **Step 4: Commit**

```bash
git add src/agent/filesystem_tools.rs
git commit -m "feat: add file_read filesystem tool"
```

---

### Task 6: Implement directory_list tool

**Files:**
- Modify: `src/agent/filesystem_tools.rs`

- [ ] **Step 1: Write directory_list tests**

Add to the `tests` module:

```rust
    // ===== directory_list =====

    #[test]
    fn test_directory_list_happy_path() {
        let tmp = setup_test_tree();
        let cfg = make_test_config(tmp.path(), false);
        let tools = filesystem_tools(&cfg);
        let tool = tools.iter().find(|t| t.name == "directory_list").unwrap();
        let result = (tool.handler)(
            json!({ "path": tmp.path().to_str().unwrap() }),
            &test_ctx(),
        );
        match &result {
            ToolInvokeResult::Success { result, .. } => {
                let entries = result["entries"].as_array().unwrap();
                let names: Vec<&str> = entries.iter()
                    .map(|e| e["name"].as_str().unwrap())
                    .collect();
                assert!(names.contains(&"hello.txt"));
                assert!(names.contains(&"subdir"));
                assert!(names.contains(&"secret.log"));
            }
            _ => panic!("expected success"),
        }
    }

    #[test]
    fn test_directory_list_with_glob_filter() {
        let tmp = setup_test_tree();
        let cfg = make_test_config(tmp.path(), false);
        let tools = filesystem_tools(&cfg);
        let tool = tools.iter().find(|t| t.name == "directory_list").unwrap();
        let result = (tool.handler)(
            json!({ "path": tmp.path().to_str().unwrap(), "glob": "*.txt" }),
            &test_ctx(),
        );
        match &result {
            ToolInvokeResult::Success { result, .. } => {
                let entries = result["entries"].as_array().unwrap();
                let names: Vec<&str> = entries.iter()
                    .map(|e| e["name"].as_str().unwrap())
                    .collect();
                assert!(names.contains(&"hello.txt"));
                assert!(!names.contains(&"secret.log"));
                assert!(!names.contains(&"subdir"));
            }
            _ => panic!("expected success"),
        }
    }

    #[test]
    fn test_directory_list_on_file_errors() {
        let tmp = setup_test_tree();
        let cfg = make_test_config(tmp.path(), false);
        let tools = filesystem_tools(&cfg);
        let tool = tools.iter().find(|t| t.name == "directory_list").unwrap();
        let result = (tool.handler)(
            json!({ "path": tmp.path().join("hello.txt").to_str().unwrap() }),
            &test_ctx(),
        );
        match &result {
            ToolInvokeResult::Error { .. } => {}
            _ => panic!("expected error for non-directory"),
        }
    }
```

- [ ] **Step 2: Add directory_list to filesystem_tools() and implement**

Add `tools.push(directory_list_tool(config.clone()));` in `filesystem_tools()`.

```rust
fn directory_list_tool(config: FilesystemConfig) -> BuiltinTool {
    BuiltinTool {
        name: "directory_list".to_string(),
        description: "List the contents of a directory within configured filesystem roots.".to_string(),
        input_schema: json!({
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Absolute path to the directory to list."
                },
                "glob": {
                    "type": "string",
                    "description": "Optional glob pattern to filter entries by name."
                }
            },
            "required": ["path"],
            "additionalProperties": false
        }),
        handler: Box::new(move |args, _ctx| {
            let path_str = match args.get("path").and_then(|v| v.as_str()) {
                Some(p) => p,
                None => return ToolInvokeResult::tool_error("missing required parameter: path"),
            };

            let canonical = match validate_path(path_str, &config.roots, &config.exclude_patterns) {
                Ok(p) => p,
                Err(e) => return ToolInvokeResult::tool_error(e),
            };

            if !canonical.is_dir() {
                return ToolInvokeResult::tool_error(format!("\"{}\" is not a directory", path_str));
            }

            let glob_filter = args
                .get("glob")
                .and_then(|v| v.as_str())
                .and_then(|s| Pattern::new(s).ok());

            let entries = match fs::read_dir(&canonical) {
                Ok(rd) => rd,
                Err(e) => {
                    let msg = if e.kind() == std::io::ErrorKind::PermissionDenied {
                        format!("permission denied: \"{}\"", path_str)
                    } else {
                        format!("cannot read directory \"{}\": {}", path_str, e)
                    };
                    return ToolInvokeResult::tool_error(msg);
                }
            };

            let mut results = Vec::new();
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().into_owned();

                // Apply glob filter against entry name only
                if let Some(ref pattern) = glob_filter {
                    if !pattern.matches(&name) {
                        continue;
                    }
                }

                let meta = entry.metadata();
                let file_type = entry.file_type();

                let type_str = match file_type {
                    Ok(ft) if ft.is_symlink() => "symlink",
                    Ok(ft) if ft.is_dir() => "dir",
                    _ => "file",
                };

                let (size, modified) = match meta {
                    Ok(m) => {
                        let size = m.len();
                        let modified = m
                            .modified()
                            .ok()
                            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                            .map(|d| d.as_secs());
                        (size, modified)
                    }
                    Err(_) => (0, None),
                };

                results.push(json!({
                    "name": name,
                    "type": type_str,
                    "size": size,
                    "modified": modified
                }));
            }

            ToolInvokeResult::success(json!({ "entries": results }))
        }),
    }
}
```

- [ ] **Step 3: Run tests**

Run: `cargo nextest run -p carapace test_directory_list 2>&1 | tail -20`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add src/agent/filesystem_tools.rs
git commit -m "feat: add directory_list filesystem tool"
```

---

### Task 7: Implement file_stat tool

**Files:**
- Modify: `src/agent/filesystem_tools.rs`

- [ ] **Step 1: Write test, implement, verify**

Add test:

```rust
    #[test]
    fn test_file_stat_happy_path() {
        let tmp = setup_test_tree();
        let cfg = make_test_config(tmp.path(), false);
        let tools = filesystem_tools(&cfg);
        let tool = tools.iter().find(|t| t.name == "file_stat").unwrap();
        let result = (tool.handler)(
            json!({ "path": tmp.path().join("hello.txt").to_str().unwrap() }),
            &test_ctx(),
        );
        match &result {
            ToolInvokeResult::Success { result, .. } => {
                assert_eq!(result["size"], 11); // "hello world"
                assert_eq!(result["isDir"], false);
                assert_eq!(result["isSymlink"], false);
            }
            _ => panic!("expected success"),
        }
    }

    #[test]
    fn test_file_stat_directory() {
        let tmp = setup_test_tree();
        let cfg = make_test_config(tmp.path(), false);
        let tools = filesystem_tools(&cfg);
        let tool = tools.iter().find(|t| t.name == "file_stat").unwrap();
        let result = (tool.handler)(
            json!({ "path": tmp.path().join("subdir").to_str().unwrap() }),
            &test_ctx(),
        );
        match &result {
            ToolInvokeResult::Success { result, .. } => {
                assert_eq!(result["isDir"], true);
            }
            _ => panic!("expected success"),
        }
    }
```

Add `tools.push(file_stat_tool(config.clone()));` and implement:

```rust
fn file_stat_tool(config: FilesystemConfig) -> BuiltinTool {
    BuiltinTool {
        name: "file_stat".to_string(),
        description: "Get metadata about a file or directory.".to_string(),
        input_schema: json!({
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Absolute path to stat."
                }
            },
            "required": ["path"],
            "additionalProperties": false
        }),
        handler: Box::new(move |args, _ctx| {
            let path_str = match args.get("path").and_then(|v| v.as_str()) {
                Some(p) => p,
                None => return ToolInvokeResult::tool_error("missing required parameter: path"),
            };

            let canonical = match validate_path(path_str, &config.roots, &config.exclude_patterns) {
                Ok(p) => p,
                Err(e) => return ToolInvokeResult::tool_error(e),
            };

            let meta = match fs::symlink_metadata(&canonical) {
                Ok(m) => m,
                Err(e) => {
                    let msg = if e.kind() == std::io::ErrorKind::PermissionDenied {
                        format!("permission denied: \"{}\"", path_str)
                    } else {
                        format!("cannot stat \"{}\": {}", path_str, e)
                    };
                    return ToolInvokeResult::tool_error(msg);
                }
            };

            let modified = meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs());
            let created = meta
                .created()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs());

            let permissions = format!("{:o}", meta.permissions().mode() & 0o777);

            ToolInvokeResult::success(json!({
                "size": meta.len(),
                "modified": modified,
                "created": created,
                "isDir": meta.is_dir(),
                "isSymlink": meta.file_type().is_symlink(),
                "permissions": permissions
            }))
        }),
    }
}
```

Note: `permissions().mode()` requires `use std::os::unix::fs::PermissionsExt;` on Unix. Add a platform guard:

```rust
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
```

For the permissions field, use a cfg block:

```rust
            #[cfg(unix)]
            let permissions = format!("{:o}", meta.permissions().mode() & 0o777);
            #[cfg(not(unix))]
            let permissions = if meta.permissions().readonly() { "readonly" } else { "read-write" }.to_string();
```

- [ ] **Step 2: Run tests**

Run: `cargo nextest run -p carapace test_file_stat 2>&1 | tail -20`
Expected: PASS

- [ ] **Step 3: Commit**

```bash
git add src/agent/filesystem_tools.rs
git commit -m "feat: add file_stat filesystem tool"
```

---

### Task 8: Implement file_search tool

**Files:**
- Modify: `src/agent/filesystem_tools.rs`

- [ ] **Step 1: Write tests**

```rust
    #[test]
    fn test_file_search_by_name() {
        let tmp = setup_test_tree();
        let cfg = make_test_config(tmp.path(), false);
        let tools = filesystem_tools(&cfg);
        let tool = tools.iter().find(|t| t.name == "file_search").unwrap();
        let result = (tool.handler)(
            json!({
                "pattern": "*.txt",
                "path": tmp.path().to_str().unwrap()
            }),
            &test_ctx(),
        );
        match &result {
            ToolInvokeResult::Success { result, .. } => {
                let matches = result["matches"].as_array().unwrap();
                assert!(matches.len() >= 2); // hello.txt, nested.txt
            }
            _ => panic!("expected success"),
        }
    }

    #[test]
    fn test_file_search_with_content_pattern() {
        let tmp = setup_test_tree();
        let cfg = make_test_config(tmp.path(), false);
        let tools = filesystem_tools(&cfg);
        let tool = tools.iter().find(|t| t.name == "file_search").unwrap();
        let result = (tool.handler)(
            json!({
                "pattern": "*.txt",
                "path": tmp.path().to_str().unwrap(),
                "content_pattern": "nested"
            }),
            &test_ctx(),
        );
        match &result {
            ToolInvokeResult::Success { result, .. } => {
                let matches = result["matches"].as_array().unwrap();
                assert_eq!(matches.len(), 1);
                assert!(matches[0]["path"].as_str().unwrap().contains("nested.txt"));
            }
            _ => panic!("expected success"),
        }
    }

    /// Create filesystem tools with a custom search entry budget (for testing truncation).
    fn filesystem_tools_with_budget(cfg: &serde_json::Value, budget: usize) -> Vec<BuiltinTool> {
        let mut config = FilesystemConfig::from_value(cfg);
        config.search_entry_budget = budget;
        let mut tools = Vec::new();
        tools.push(file_read_tool(config.clone()));
        tools.push(directory_list_tool(config.clone()));
        tools.push(file_stat_tool(config.clone()));
        tools.push(file_search_tool(config.clone()));
        if config.write_access {
            tools.push(file_write_tool(config.clone()));
            tools.push(file_move_tool(config.clone()));
        }
        tools
    }

    #[test]
    fn test_file_search_budget_truncation() {
        let tmp = TempDir::new().unwrap();
        for i in 0..20 {
            fs::write(tmp.path().join(format!("f{i}.txt")), format!("content {i}")).unwrap();
        }
        let cfg = json!({
            "filesystem": {
                "enabled": true,
                "roots": [tmp.path().to_str().unwrap()]
            }
        });
        // Use a budget of 5 so that 20 files triggers truncation
        let tools = filesystem_tools_with_budget(&cfg, 5);
        let tool = tools.iter().find(|t| t.name == "file_search").unwrap();
        let result = (tool.handler)(
            json!({
                "pattern": "*.txt",
                "path": tmp.path().to_str().unwrap()
            }),
            &test_ctx(),
        );
        match &result {
            ToolInvokeResult::Success { result, .. } => {
                assert_eq!(result["truncated"], true);
                let matches = result["matches"].as_array().unwrap();
                assert!(matches.len() < 20, "should have fewer than 20 matches due to budget");
            }
            _ => panic!("expected success"),
        }
    }

    #[test]
    fn test_file_search_basic_count() {
        let tmp = TempDir::new().unwrap();
        for i in 0..20 {
            fs::write(tmp.path().join(format!("f{i}.txt")), format!("content {i}")).unwrap();
        }
        let cfg = json!({
            "filesystem": {
                "enabled": true,
                "roots": [tmp.path().to_str().unwrap()]
            }
        });
        let tools = filesystem_tools(&cfg);
        let tool = tools.iter().find(|t| t.name == "file_search").unwrap();
        let result = (tool.handler)(
            json!({
                "pattern": "*.txt",
                "path": tmp.path().to_str().unwrap()
            }),
            &test_ctx(),
        );
        match &result {
            ToolInvokeResult::Success { result, .. } => {
                let matches = result["matches"].as_array().unwrap();
                assert_eq!(matches.len(), 20);
                assert_eq!(result["truncated"], false);
            }
            _ => panic!("expected success"),
        }
    }
```

- [ ] **Step 2: Implement file_search**

Add `tools.push(file_search_tool(config.clone()));` and implement. This tool uses `block_in_place`:

```rust
fn file_search_tool(config: FilesystemConfig) -> BuiltinTool {
    BuiltinTool {
        name: "file_search".to_string(),
        description: "Search for files by name pattern, optionally filtering by content.".to_string(),
        input_schema: json!({
            "type": "object",
            "properties": {
                "pattern": {
                    "type": "string",
                    "description": "Glob pattern to match file names (e.g., \"*.rs\", \"config.*\")."
                },
                "path": {
                    "type": "string",
                    "description": "Root directory to search from."
                },
                "max_depth": {
                    "type": "integer",
                    "description": "Maximum directory depth (default 10)."
                },
                "content_pattern": {
                    "type": "string",
                    "description": "Optional regex to filter files by content."
                }
            },
            "required": ["pattern", "path"],
            "additionalProperties": false
        }),
        handler: Box::new(move |args, _ctx| {
            let name_pattern = match args.get("pattern").and_then(|v| v.as_str()) {
                Some(p) => p.to_string(),
                None => return ToolInvokeResult::tool_error("missing required parameter: pattern"),
            };
            let search_root = match args.get("path").and_then(|v| v.as_str()) {
                Some(p) => p.to_string(),
                None => return ToolInvokeResult::tool_error("missing required parameter: path"),
            };
            let max_depth = args.get("max_depth").and_then(|v| v.as_u64()).unwrap_or(10) as usize;
            let content_pattern = args
                .get("content_pattern")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());

            let canonical_root = match validate_path(&search_root, &config.roots, &config.exclude_patterns) {
                Ok(p) => p,
                Err(e) => return ToolInvokeResult::tool_error(e),
            };

            let glob_pattern = match Pattern::new(&name_pattern) {
                Ok(p) => p,
                Err(e) => return ToolInvokeResult::tool_error(format!("invalid glob pattern: {}", e)),
            };

            let content_regex = match content_pattern {
                Some(ref pat) => match regex::Regex::new(pat) {
                    Ok(r) => Some(r),
                    Err(e) => return ToolInvokeResult::tool_error(format!("invalid regex: {}", e)),
                },
                None => None,
            };

            // Heavy traversal — signal tokio the thread is blocked when running
            // inside a multi-threaded runtime. Falls back to direct execution in
            // tests (which have no runtime) or current-thread runtimes.
            let do_search = || {
                const ENTRY_BUDGET: usize = 10_000;
                let mut matches = Vec::new();
                let mut entries_scanned: usize = 0;
                let mut truncated = false;

                fn walk(
                    dir: &std::path::Path,
                    depth: usize,
                    max_depth: usize,
                    budget: usize,
                    glob_pattern: &Pattern,
                    content_regex: &Option<regex::Regex>,
                    config: &FilesystemConfig,
                    matches: &mut Vec<Value>,
                    entries_scanned: &mut usize,
                    truncated: &mut bool,
                ) {
                    if depth > max_depth || *truncated {
                        return;
                    }
                    let entries = match fs::read_dir(dir) {
                        Ok(e) => e,
                        Err(_) => return,
                    };
                    for entry in entries.flatten() {
                        if *truncated {
                            return;
                        }
                        *entries_scanned += 1;
                        if *entries_scanned > budget {
                            *truncated = true;
                            return;
                        }

                        let path = entry.path();
                        let name = entry.file_name().to_string_lossy().into_owned();

                        if path.is_dir() {
                            walk(
                                &path, depth + 1, max_depth, budget, glob_pattern,
                                content_regex, config, matches, entries_scanned, truncated,
                            );
                            continue;
                        }

                        if !glob_pattern.matches(&name) {
                            continue;
                        }

                        // Check path is within roots (for safety)
                        if let Ok(canonical) = std::fs::canonicalize(&path) {
                            if !config.roots.iter().any(|r| canonical.starts_with(r)) {
                                continue;
                            }
                        }

                        if let Some(ref regex) = content_regex {
                            // Cap content reads at max_read_bytes to bound memory usage.
                            // Files larger than the cap are searched on their prefix only.
                            let content_result = {
                                let mut file = match fs::File::open(&path) {
                                    Ok(f) => f,
                                    Err(_) => continue,
                                };
                                let meta = file.metadata().ok();
                                let file_size = meta.map(|m| m.len()).unwrap_or(0);
                                if file_size > config.max_read_bytes * 2 {
                                    // Skip very large files entirely for content search
                                    None
                                } else {
                                    let limit = config.max_read_bytes.min(file_size);
                                    let mut buf = Vec::with_capacity(limit as usize);
                                    use std::io::Read;
                                    let _ = file.take(limit).read_to_end(&mut buf);
                                    String::from_utf8(buf).ok()
                                }
                            };
                            match content_result {
                                Some(content) => {
                                    if let Some(m) = regex.find(&content) {
                                        let line_num = content[..m.start()]
                                            .chars()
                                            .filter(|c| *c == '\n')
                                            .count() + 1;
                                        let line = content.lines().nth(line_num - 1).unwrap_or("");
                                        matches.push(json!({
                                            "path": path.to_string_lossy(),
                                            "line": line_num,
                                            "snippet": line.chars().take(200).collect::<String>()
                                        }));
                                    }
                                }
                                None => {} // skip binary/unreadable/oversized files
                            }
                        } else {
                            matches.push(json!({
                                "path": path.to_string_lossy()
                            }));
                        }
                    }
                }

                walk(
                    &canonical_root, 0, max_depth, config.search_entry_budget,
                    &glob_pattern, &content_regex, &config, &mut matches,
                    &mut entries_scanned, &mut truncated,
                );

                json!({
                    "matches": matches,
                    "entriesScanned": entries_scanned,
                    "truncated": truncated
                })
            };

            let result = run_blocking(do_search);

            ToolInvokeResult::success(result)
        }),
    }
}
```

- [ ] **Step 3: Run tests**

Run: `cargo nextest run -p carapace test_file_search 2>&1 | tail -20`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add src/agent/filesystem_tools.rs
git commit -m "feat: add file_search filesystem tool"
```

---

## Chunk 4: Write-Tier Tools & Wiring

### Task 9: Implement file_write and file_move tools

**Files:**
- Modify: `src/agent/filesystem_tools.rs`

- [ ] **Step 1: Write tests**

```rust
    // ===== file_write =====

    #[test]
    fn test_file_write_happy_path() {
        let tmp = setup_test_tree();
        let cfg = make_test_config(tmp.path(), true);
        let tools = filesystem_tools(&cfg);
        let tool = tools.iter().find(|t| t.name == "file_write").unwrap();
        let new_path = tmp.path().join("written.txt");
        let result = (tool.handler)(
            json!({
                "path": new_path.to_str().unwrap(),
                "content": "new content"
            }),
            &test_ctx(),
        );
        match &result {
            ToolInvokeResult::Success { result, .. } => {
                assert_eq!(result["bytesWritten"], 11);
            }
            _ => panic!("expected success"),
        }
        assert_eq!(fs::read_to_string(&new_path).unwrap(), "new content");
    }

    #[test]
    fn test_file_write_denied_without_write_access() {
        let tmp = setup_test_tree();
        let cfg = make_test_config(tmp.path(), false); // writeAccess: false
        let tools = filesystem_tools(&cfg);
        // file_write should not even be registered
        assert!(tools.iter().find(|t| t.name == "file_write").is_none());
    }

    #[test]
    fn test_file_write_creates_dirs() {
        let tmp = setup_test_tree();
        let cfg = make_test_config(tmp.path(), true);
        let tools = filesystem_tools(&cfg);
        let tool = tools.iter().find(|t| t.name == "file_write").unwrap();
        let new_path = tmp.path().join("new_dir/deep/file.txt");
        let result = (tool.handler)(
            json!({
                "path": new_path.to_str().unwrap(),
                "content": "deep content"
            }),
            &test_ctx(),
        );
        match &result {
            ToolInvokeResult::Success { .. } => {}
            _ => panic!("expected success"),
        }
        assert!(new_path.exists());
    }

    // ===== file_move =====

    #[test]
    fn test_file_move_happy_path() {
        let tmp = setup_test_tree();
        let cfg = make_test_config(tmp.path(), true);
        let tools = filesystem_tools(&cfg);
        let tool = tools.iter().find(|t| t.name == "file_move").unwrap();
        let src = tmp.path().join("hello.txt");
        let dst = tmp.path().join("moved.txt");
        let result = (tool.handler)(
            json!({
                "source": src.to_str().unwrap(),
                "destination": dst.to_str().unwrap()
            }),
            &test_ctx(),
        );
        match &result {
            ToolInvokeResult::Success { .. } => {}
            _ => panic!("expected success"),
        }
        assert!(!src.exists());
        assert!(dst.exists());
        assert_eq!(fs::read_to_string(&dst).unwrap(), "hello world");
    }

    #[test]
    fn test_file_move_rejects_directory() {
        let tmp = setup_test_tree();
        let cfg = make_test_config(tmp.path(), true);
        let tools = filesystem_tools(&cfg);
        let tool = tools.iter().find(|t| t.name == "file_move").unwrap();
        let result = (tool.handler)(
            json!({
                "source": tmp.path().join("subdir").to_str().unwrap(),
                "destination": tmp.path().join("moved_dir").to_str().unwrap()
            }),
            &test_ctx(),
        );
        match &result {
            ToolInvokeResult::Error { error, .. } => {
                assert!(error.message.contains("directory"));
            }
            _ => panic!("expected error for directory move"),
        }
    }

    #[test]
    fn test_file_move_denied_without_write_access() {
        let tmp = setup_test_tree();
        let cfg = make_test_config(tmp.path(), false);
        let tools = filesystem_tools(&cfg);
        assert!(tools.iter().find(|t| t.name == "file_move").is_none());
    }
```

- [ ] **Step 2: Implement file_write**

Add to `filesystem_tools()` conditionally:

```rust
    // Write tier (only when writeAccess is true)
    if config.write_access {
        tools.push(file_write_tool(config.clone()));
        tools.push(file_move_tool(config.clone()));
    }
```

```rust
fn file_write_tool(config: FilesystemConfig) -> BuiltinTool {
    BuiltinTool {
        name: "file_write".to_string(),
        description: "Write content to a file within configured filesystem roots.".to_string(),
        input_schema: json!({
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Absolute path to write to."
                },
                "content": {
                    "type": "string",
                    "description": "Content to write."
                },
                "create_dirs": {
                    "type": "boolean",
                    "description": "Create parent directories if they don't exist (default true)."
                }
            },
            "required": ["path", "content"],
            "additionalProperties": false
        }),
        handler: Box::new(move |args, _ctx| {
            let path_str = match args.get("path").and_then(|v| v.as_str()) {
                Some(p) => p,
                None => return ToolInvokeResult::tool_error("missing required parameter: path"),
            };
            let content = match args.get("content").and_then(|v| v.as_str()) {
                Some(c) => c,
                None => return ToolInvokeResult::tool_error("missing required parameter: content"),
            };
            let create_dirs = args
                .get("create_dirs")
                .and_then(|v| v.as_bool())
                .unwrap_or(true);

            let target = match validate_write_path(
                path_str,
                &config.roots,
                &config.exclude_patterns,
                create_dirs,
            ) {
                Ok(p) => p,
                Err(e) => return ToolInvokeResult::tool_error(e),
            };

            match fs::write(&target, content) {
                Ok(()) => ToolInvokeResult::success(json!({
                    "bytesWritten": content.len(),
                    "path": target.to_string_lossy()
                })),
                Err(e) => {
                    let msg = if e.kind() == std::io::ErrorKind::PermissionDenied {
                        format!("permission denied: \"{}\"", path_str)
                    } else {
                        format!("cannot write \"{}\": {}", path_str, e)
                    };
                    ToolInvokeResult::tool_error(msg)
                }
            }
        }),
    }
}
```

- [ ] **Step 3: Implement file_move**

```rust
fn file_move_tool(config: FilesystemConfig) -> BuiltinTool {
    BuiltinTool {
        name: "file_move".to_string(),
        description: "Move or rename a file within configured filesystem roots.".to_string(),
        input_schema: json!({
            "type": "object",
            "properties": {
                "source": {
                    "type": "string",
                    "description": "Absolute path of the file to move."
                },
                "destination": {
                    "type": "string",
                    "description": "Absolute destination path."
                }
            },
            "required": ["source", "destination"],
            "additionalProperties": false
        }),
        handler: Box::new(move |args, _ctx| {
            let source_str = match args.get("source").and_then(|v| v.as_str()) {
                Some(p) => p,
                None => return ToolInvokeResult::tool_error("missing required parameter: source"),
            };
            let dest_str = match args.get("destination").and_then(|v| v.as_str()) {
                Some(p) => p,
                None => return ToolInvokeResult::tool_error("missing required parameter: destination"),
            };

            // Validate source exists and is within roots
            let source = match validate_path(source_str, &config.roots, &config.exclude_patterns) {
                Ok(p) => p,
                Err(e) => return ToolInvokeResult::tool_error(e),
            };

            // Only files can be moved — directory moves are out of scope
            if source.is_dir() {
                return ToolInvokeResult::tool_error(
                    format!("\"{}\" is a directory; file_move only supports files", source_str)
                );
            }

            // Validate destination is within roots
            let dest = match validate_write_path(dest_str, &config.roots, &config.exclude_patterns, false) {
                Ok(p) => p,
                Err(e) => return ToolInvokeResult::tool_error(e),
            };

            let rename_result = fs::rename(&source, &dest);

            // On Windows, rename fails if destination exists — try remove+rename
            #[cfg(windows)]
            let rename_result = if rename_result.is_err() && dest.exists() {
                fs::remove_file(&dest)
                    .and_then(|()| fs::rename(&source, &dest))
            } else {
                rename_result
            };

            match rename_result {
                Ok(()) => ToolInvokeResult::success(json!({
                    "source": source.to_string_lossy(),
                    "destination": dest.to_string_lossy()
                })),
                Err(e) => {
                    let msg = if e.raw_os_error() == Some(18) {
                        "cannot move across filesystems".to_string()
                    } else if e.kind() == std::io::ErrorKind::PermissionDenied {
                        "permission denied".to_string()
                    } else {
                        format!("cannot move: {}", e)
                    };
                    ToolInvokeResult::tool_error(msg)
                }
            }
        }),
    }
}
```

- [ ] **Step 4: Run tests**

Run: `cargo nextest run -p carapace test_file_write test_file_move 2>&1 | tail -30`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/agent/filesystem_tools.rs
git commit -m "feat: add file_write and file_move filesystem tools"
```

---

### Task 10: Wire ToolsRegistry::with_config and production entry points

**Files:**
- Modify: `src/plugins/tools.rs`
- Modify: `src/main.rs:173`
- Modify: `src/cli/chat.rs:85`

- [ ] **Step 1: Write registration tests**

Add to the `tests` module in `src/plugins/tools.rs`:

```rust
    #[test]
    fn test_with_config_filesystem_disabled() {
        let cfg = serde_json::json!({});
        let registry = ToolsRegistry::with_config(&cfg);
        // Same count as new() — filesystem not registered
        let baseline = ToolsRegistry::new();
        assert_eq!(registry.len(), baseline.len());
    }

    #[test]
    fn test_with_config_filesystem_enabled_read_only() {
        let cfg = serde_json::json!({
            "filesystem": {
                "enabled": true,
                "roots": ["/tmp"],
                "writeAccess": false
            }
        });
        let registry = ToolsRegistry::with_config(&cfg);
        assert!(registry.has_tool("file_read"));
        assert!(registry.has_tool("directory_list"));
        assert!(registry.has_tool("file_stat"));
        assert!(registry.has_tool("file_search"));
        assert!(!registry.has_tool("file_write"));
        assert!(!registry.has_tool("file_move"));
    }

    #[test]
    fn test_with_config_filesystem_enabled_write_access() {
        let cfg = serde_json::json!({
            "filesystem": {
                "enabled": true,
                "roots": ["/tmp"],
                "writeAccess": true
            }
        });
        let registry = ToolsRegistry::with_config(&cfg);
        assert!(registry.has_tool("file_read"));
        assert!(registry.has_tool("file_write"));
        assert!(registry.has_tool("file_move"));
    }
```

- [ ] **Step 2: Add with_config method**

Add after `pub fn new()` in `ToolsRegistry` impl:

```rust
    /// Create a new tools registry with config-dependent tools.
    ///
    /// Registers all standard built-in tools plus filesystem tools when
    /// `filesystem.enabled` is truthy.
    pub fn with_config(cfg: &Value) -> Self {
        let registry = Self::new();

        let fs_enabled = cfg
            .pointer("/filesystem/enabled")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        if fs_enabled {
            for tool in crate::agent::filesystem_tools::filesystem_tools(cfg) {
                registry.register_builtin_tool(tool);
            }
        }

        registry
    }
```

Add `use serde_json::Value;` if not already imported (it already is via `use serde_json::Value;` at line 8).

- [ ] **Step 3: Run registration tests**

Run: `cargo nextest run -p carapace test_with_config 2>&1 | tail -20`
Expected: PASS

- [ ] **Step 4: Update main.rs**

Change line 173 of `src/main.rs` from:

```rust
    let tools_registry = Arc::new(plugins::tools::ToolsRegistry::new());
```

to:

```rust
    let tools_registry = Arc::new(plugins::tools::ToolsRegistry::with_config(&cfg));
```

- [ ] **Step 4b: Update cli/chat.rs**

Change line 85 of `src/cli/chat.rs` from:

```rust
    let tools_registry = std::sync::Arc::new(crate::plugins::tools::ToolsRegistry::new());
```

to:

```rust
    let tools_registry = std::sync::Arc::new(crate::plugins::tools::ToolsRegistry::with_config(&cfg));
```

Note: other `ToolsRegistry::new()` calls in the codebase are intentionally left as `new()`:
- `startup.rs:188` — `ServerConfig::for_testing()`, test-only helper
- `executor.rs:1147` — `make_test_state_with_tools()`, test-only helper
- `http.rs:2405/2420` — test-only helpers
- `http.rs:390` — `create_router_with_middleware()`, a convenience wrapper only called by `create_router()` which is itself only called in test code (`http.rs:2393`). If this function is ever used in a production path, it would need a config parameter, but today it is test-only.

- [ ] **Step 5: Verify compilation**

Run: `cargo check 2>&1 | tail -20`
Expected: compiles clean

- [ ] **Step 6: Run full test suite**

Run: `just test 2>&1 | tail -30`
Expected: all tests pass

- [ ] **Step 7: Commit**

```bash
git add src/plugins/tools.rs src/main.rs src/cli/chat.rs
git commit -m "feat: wire filesystem tools via ToolsRegistry::with_config"
```

---

## Chunk 5: Final Verification

### Task 11: Full test suite and cleanup

- [ ] **Step 1: Run full test suite**

Run: `just test 2>&1 | tail -50`
Expected: all tests pass, no regressions

- [ ] **Step 2: Run clippy**

Run: `cargo clippy --all-targets -- -D warnings 2>&1 | tail -30`
Expected: no warnings

- [ ] **Step 3: Run cargo fmt check**

Run: `cargo fmt --check 2>&1 | tail -10`
Expected: no formatting issues

- [ ] **Step 4: Verify tool count**

Run: `cargo nextest run -p carapace test_tools_registry_default_tools test_with_config 2>&1 | tail -20`
Expected: all pass

- [ ] **Step 5: Final commit if any fixups needed**

If clippy/fmt required changes:
```bash
git add -A
git commit -m "chore: fix clippy/fmt issues in filesystem tools"
```
