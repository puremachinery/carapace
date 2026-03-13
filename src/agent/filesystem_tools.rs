//! Filesystem tools — read, search, write, and move files within configured roots.

use std::fs;
use std::io::Read;
use std::path::PathBuf;
use std::sync::Arc;

use base64::Engine;
use glob::Pattern;
use serde_json::{json, Value};

use crate::plugins::tools::{BuiltinTool, ToolInvokeContext, ToolInvokeResult};
use crate::runtime_bridge::run_sync_blocking_send;

const DEFAULT_SEARCH_ENTRY_BUDGET: usize = 10_000;
const DEFAULT_MAX_READ_BYTES: u64 = 10_485_760;
const DEFAULT_MAX_SEARCH_DEPTH: usize = 64;

/// Check whether `path` is excluded by any of the configured patterns relative to `root`.
///
/// Returns the matching pattern as a string if excluded, `None` otherwise.
fn excluded_by(
    path: &std::path::Path,
    root: &std::path::Path,
    exclude_patterns: &[Pattern],
) -> Option<String> {
    let relative = path.strip_prefix(root).unwrap_or(path);
    for pattern in exclude_patterns {
        if pattern.matches_path(relative) {
            return Some(pattern.to_string());
        }
        for component in relative.components() {
            if let std::path::Component::Normal(name) = component {
                if pattern.matches(name.to_str().unwrap_or("")) {
                    return Some(pattern.to_string());
                }
            }
        }
    }
    None
}

fn matching_roots<'a>(canonical: &std::path::Path, roots: &'a [PathBuf]) -> Vec<&'a PathBuf> {
    roots
        .iter()
        .filter(|root| canonical.starts_with(root.as_path()))
        .collect()
}

fn validate_canonical_path(
    canonical: &std::path::Path,
    roots: &[PathBuf],
    exclude_patterns: &[Pattern],
) -> Result<(), String> {
    let matching = matching_roots(canonical, roots);
    if matching.is_empty() {
        return Err(format!(
            "path \"{}\" is outside all configured filesystem roots",
            canonical.display()
        ));
    }

    if let Some(pattern) = matching
        .into_iter()
        .find_map(|root| excluded_by(canonical, root, exclude_patterns))
    {
        return Err(format!(
            "path \"{}\" is excluded by pattern \"{}\"",
            canonical.display(),
            pattern
        ));
    }

    Ok(())
}

fn canonicalize_allowed_path(
    path: &std::path::Path,
    roots: &[PathBuf],
    exclude_patterns: &[Pattern],
) -> Option<PathBuf> {
    let canonical = std::fs::canonicalize(path).ok()?;
    validate_canonical_path(&canonical, roots, exclude_patterns).ok()?;
    Some(canonical)
}

fn run_blocking_tool<F>(label: &'static str, work: F) -> ToolInvokeResult
where
    F: FnOnce() -> ToolInvokeResult + Send + 'static,
{
    match run_sync_blocking_send(async move {
        tokio::task::spawn_blocking(work)
            .await
            .map_err(|e| format!("{label} worker failed: {e}"))
    }) {
        Ok(result) => result,
        Err(e) => ToolInvokeResult::tool_error(format!("{label} failed: {e}")),
    }
}

/// Validate that a requested path is allowed by the configured roots and exclude patterns.
///
/// SECURITY: this check canonicalizes and validates the path before later file operations, but
/// local filesystem mutations can still race between validation and use. That TOCTOU risk is
/// accepted for this local-assistant feature; call sites should still minimize the gap and avoid
/// broadening capabilities around symlink or directory traversal behavior.
pub fn validate_path(
    requested: &str,
    roots: &[PathBuf],
    exclude_patterns: &[Pattern],
) -> Result<PathBuf, String> {
    if !std::path::Path::new(requested).is_absolute() {
        return Err(format!("path \"{}\" must be absolute", requested));
    }

    let canonical = std::fs::canonicalize(requested)
        .map_err(|e| format!("cannot resolve path \"{}\": {}", requested, e))?;
    validate_canonical_path(&canonical, roots, exclude_patterns)?;

    Ok(canonical)
}

/// Resolve and validate a path for write operations where the target file may not exist yet.
///
/// When `create_dirs` is true, intermediate directories are created only after
/// validating that the target path falls within a configured root and does not
/// match any exclude pattern.
pub fn validate_write_path(
    requested: &str,
    roots: &[PathBuf],
    exclude_patterns: &[Pattern],
    create_dirs: bool,
) -> Result<PathBuf, String> {
    let path = PathBuf::from(requested);
    if !path.is_absolute() {
        return Err(format!("path \"{}\" must be absolute", requested));
    }
    if path
        .components()
        .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err(format!(
            "path \"{}\" must not contain parent-directory components",
            requested
        ));
    }
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
        let mut ancestor = parent.to_path_buf();
        while !ancestor.exists() {
            ancestor = ancestor
                .parent()
                .ok_or_else(|| "cannot find existing ancestor directory".to_string())?
                .to_path_buf();
        }
        let canonical_ancestor = std::fs::canonicalize(&ancestor)
            .map_err(|e| format!("cannot resolve ancestor \"{}\": {}", ancestor.display(), e))?;

        // Check exclude patterns on the planned path *before* creating directories.
        let planned_relative = parent.strip_prefix(&ancestor).map_err(|_| {
            format!(
                "cannot resolve planned write path \"{}\" relative to ancestor \"{}\"",
                parent.display(),
                ancestor.display()
            )
        })?;
        let planned_path = canonical_ancestor.join(planned_relative);
        let planned_full = planned_path.join(filename);
        let matching = matching_roots(&planned_full, roots);
        if matching.is_empty() {
            return Err(format!(
                "path \"{}\" is outside all configured filesystem roots",
                requested
            ));
        }
        if let Some(pattern) = matching
            .into_iter()
            .find_map(|root| excluded_by(&planned_full, root, exclude_patterns))
        {
            return Err(format!(
                "path \"{}\" is excluded by pattern \"{}\"",
                planned_full.display(),
                pattern
            ));
        }

        std::fs::create_dir_all(parent)
            .map_err(|e| format!("failed to create directories: {}", e))?;
    }

    let canonical_parent = std::fs::canonicalize(parent)
        .map_err(|e| format!("cannot resolve parent \"{}\": {}", parent.display(), e))?;

    let full_path = canonical_parent.join(filename);
    if full_path.exists() {
        let meta = std::fs::symlink_metadata(&full_path)
            .map_err(|e| format!("cannot inspect target \"{}\": {}", full_path.display(), e))?;
        if meta.file_type().is_symlink() {
            return Err(format!(
                "refusing to write to symlink target \"{}\"",
                full_path.display()
            ));
        }
        let canonical_full = std::fs::canonicalize(&full_path)
            .map_err(|e| format!("cannot resolve target \"{}\": {}", full_path.display(), e))?;
        validate_canonical_path(&canonical_full, roots, exclude_patterns)?;
    } else {
        validate_canonical_path(&full_path, roots, exclude_patterns)?;
    }

    Ok(full_path)
}

#[derive(Debug, Clone)]
struct FilesystemConfig {
    roots: Vec<PathBuf>,
    write_access: bool,
    max_read_bytes: u64,
    exclude_patterns: Vec<Pattern>,
    search_entry_budget: usize,
    poisoned: bool,
}

impl FilesystemConfig {
    fn from_value(cfg: &Value) -> Self {
        let fs_cfg = cfg.get("filesystem").unwrap_or(&Value::Null);
        let mut poisoned = false;

        let roots: Vec<PathBuf> = match fs_cfg.get("roots") {
            Some(Value::Array(arr)) => arr
                .iter()
                .filter_map(|value| match value.as_str() {
                    Some(root) => {
                        let path = std::path::Path::new(root);
                        if !path.is_absolute() {
                            tracing::error!(
                                root = %root,
                                "filesystem root must be absolute; filesystem tools will be disabled"
                            );
                            poisoned = true;
                            None
                        } else {
                            match std::fs::canonicalize(path) {
                                Ok(path) => Some(path),
                                Err(e) => {
                                    tracing::error!(root = %root, error = %e, "filesystem root cannot be resolved; filesystem tools will be disabled");
                                    poisoned = true;
                                    None
                                }
                            }
                        }
                    }
                    None => {
                        tracing::error!(
                            "filesystem.roots contains a non-string entry; filesystem tools will be disabled"
                        );
                        poisoned = true;
                        None
                    }
                })
                .collect(),
            Some(other) if !other.is_null() => {
                tracing::error!(
                    "filesystem.roots must be an array; filesystem tools will be disabled"
                );
                poisoned = true;
                Vec::new()
            }
            _ => Vec::new(),
        };

        let write_access = match fs_cfg.get("writeAccess") {
            Some(value) => match value.as_bool() {
                Some(flag) => flag,
                None => {
                    tracing::error!(
                        "filesystem.writeAccess must be a boolean; filesystem tools will be disabled"
                    );
                    poisoned = true;
                    false
                }
            },
            None => false,
        };

        let max_read_bytes = match fs_cfg.get("maxReadBytes") {
            Some(value) => match value.as_u64() {
                Some(limit) => limit,
                None => {
                    tracing::error!(
                        "filesystem.maxReadBytes must be an integer; filesystem tools will be disabled"
                    );
                    poisoned = true;
                    DEFAULT_MAX_READ_BYTES
                }
            },
            None => DEFAULT_MAX_READ_BYTES,
        };

        let exclude_patterns: Vec<Pattern> = match fs_cfg.get("excludePatterns") {
            Some(Value::Array(arr)) => arr
                .iter()
                .filter_map(|value| match value.as_str() {
                    Some(pattern) => match Pattern::new(pattern) {
                        Ok(pattern) => Some(pattern),
                        Err(e) => {
                            tracing::error!(pattern = %pattern, error = %e, "invalid exclude pattern; filesystem tools will be disabled");
                            poisoned = true;
                            None
                        }
                    },
                    None => {
                        tracing::error!(
                            "filesystem.excludePatterns contains a non-string entry; filesystem tools will be disabled"
                        );
                        poisoned = true;
                        None
                    }
                })
                .collect(),
            Some(other) if !other.is_null() => {
                tracing::error!(
                    "filesystem.excludePatterns must be an array; filesystem tools will be disabled"
                );
                poisoned = true;
                Vec::new()
            }
            _ => Vec::new(),
        };

        Self {
            roots,
            write_access,
            max_read_bytes,
            exclude_patterns,
            search_entry_budget: DEFAULT_SEARCH_ENTRY_BUDGET,
            poisoned,
        }
    }
}

/// Build the filesystem tools from the given configuration value.
///
/// Read-tier tools (file_read, directory_list, file_stat, file_search) are always
/// included. Write-tier tools (file_write, file_move) are only included when
/// `writeAccess` is enabled in the configuration.
pub fn filesystem_tools(cfg: &Value) -> Vec<BuiltinTool> {
    let config = FilesystemConfig::from_value(cfg);
    if config.poisoned {
        tracing::error!("filesystem tools disabled due to invalid configuration");
        return Vec::new();
    }
    let config = Arc::new(config);
    let mut tools = vec![
        file_read_tool(Arc::clone(&config)),
        directory_list_tool(Arc::clone(&config)),
        file_stat_tool(Arc::clone(&config)),
        file_search_tool(Arc::clone(&config)),
    ];

    if config.write_access {
        tools.push(file_write_tool(Arc::clone(&config)));
        tools.push(file_move_tool(Arc::clone(&config)));
    }

    tools
}

fn file_read_tool(config: Arc<FilesystemConfig>) -> BuiltinTool {
    BuiltinTool {
        name: "file_read".to_string(),
        description: "Read the contents of a file within configured filesystem roots.".to_string(),
        input_schema: json!({
            "type": "object",
            "properties": {
                "path": { "type": "string", "description": "Absolute path to the file to read." },
                "offset": { "type": "integer", "description": "Byte offset to start reading from." },
                "limit": { "type": "integer", "description": "Maximum bytes to read (capped at maxReadBytes)." }
            },
            "required": ["path"],
            "additionalProperties": false
        }),
        handler: Box::new(move |args, _ctx: &ToolInvokeContext| {
            let path_str = match args.get("path").and_then(|v| v.as_str()) {
                Some(p) => p.to_string(),
                None => return ToolInvokeResult::tool_error("missing required parameter: path"),
            };
            let offset = args.get("offset").and_then(|v| v.as_u64()).unwrap_or(0);
            let limit = args
                .get("limit")
                .and_then(|v| v.as_u64())
                .unwrap_or(config.max_read_bytes)
                .min(config.max_read_bytes);
            let config = Arc::clone(&config);
            run_blocking_tool("filesystem read", move || {
                let canonical =
                    match validate_path(&path_str, &config.roots, &config.exclude_patterns) {
                        Ok(p) => p,
                        Err(e) => return ToolInvokeResult::tool_error(e),
                    };
                let metadata = match fs::metadata(&canonical) {
                    Ok(m) => m,
                    Err(e) => {
                        return ToolInvokeResult::tool_error(format!(
                            "cannot stat \"{}\": {}",
                            path_str, e
                        ))
                    }
                };
                if metadata.is_dir() {
                    return ToolInvokeResult::tool_error(format!(
                        "\"{}\" is a directory, not a file",
                        path_str
                    ));
                }
                let file_size = metadata.len();

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
                if let Err(e) = file.take(limit).read_to_end(&mut buf) {
                    let msg = if e.kind() == std::io::ErrorKind::PermissionDenied {
                        format!("permission denied: \"{}\"", path_str)
                    } else {
                        format!("cannot read \"{}\": {}", path_str, e)
                    };
                    return ToolInvokeResult::tool_error(msg);
                }

                let bytes_read = buf.len() as u64;
                let truncated = file_size > offset.saturating_add(bytes_read);
                let check_len = buf.len().min(8192);
                let is_binary = buf[..check_len].contains(&0u8);

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
                }))
            })
        }),
    }
}

fn directory_list_tool(config: Arc<FilesystemConfig>) -> BuiltinTool {
    BuiltinTool {
        name: "directory_list".to_string(),
        description: "List the contents of a directory within configured filesystem roots."
            .to_string(),
        input_schema: json!({
            "type": "object",
            "properties": {
                "path": { "type": "string", "description": "Absolute path to the directory to list." },
                "glob": { "type": "string", "description": "Optional glob pattern to filter entries by name." }
            },
            "required": ["path"],
            "additionalProperties": false
        }),
        handler: Box::new(move |args, _ctx: &ToolInvokeContext| {
            let path_str = match args.get("path").and_then(|v| v.as_str()) {
                Some(p) => p.to_string(),
                None => return ToolInvokeResult::tool_error("missing required parameter: path"),
            };
            let glob_filter = match args.get("glob").and_then(|v| v.as_str()) {
                Some(glob) => match Pattern::new(glob) {
                    Ok(pattern) => Some(pattern),
                    Err(e) => {
                        return ToolInvokeResult::tool_error(format!("invalid glob pattern: {}", e))
                    }
                },
                None => None,
            };
            let config = Arc::clone(&config);
            run_blocking_tool("filesystem directory list", move || {
                if !std::path::Path::new(&path_str).is_absolute() {
                    return ToolInvokeResult::tool_error(format!(
                        "path \"{}\" must be absolute",
                        path_str
                    ));
                }
                let canonical =
                    match validate_path(&path_str, &config.roots, &config.exclude_patterns) {
                        Ok(p) => p,
                        Err(e) => return ToolInvokeResult::tool_error(e),
                    };
                if !canonical.is_dir() {
                    return ToolInvokeResult::tool_error(format!(
                        "\"{}\" is not a directory",
                        path_str
                    ));
                }

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

                    if let Some(ref pattern) = glob_filter {
                        if !pattern.matches(&name) {
                            continue;
                        }
                    }

                    let path = entry.path();
                    let Some(canonical_child) =
                        canonicalize_allowed_path(&path, &config.roots, &config.exclude_patterns)
                    else {
                        continue;
                    };

                    let file_type = match entry.file_type() {
                        Ok(ft) => ft,
                        Err(_) => continue,
                    };
                    let meta = entry.metadata();
                    let type_str = match file_type {
                        ft if ft.is_symlink() => "symlink",
                        _ if canonical_child.is_dir() => "dir",
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
            })
        }),
    }
}

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

fn file_stat_tool(config: Arc<FilesystemConfig>) -> BuiltinTool {
    BuiltinTool {
        name: "file_stat".to_string(),
        description: "Get metadata about a file or directory.".to_string(),
        input_schema: json!({
            "type": "object",
            "properties": {
                "path": { "type": "string", "description": "Absolute path to stat." }
            },
            "required": ["path"],
            "additionalProperties": false
        }),
        handler: Box::new(move |args, _ctx: &ToolInvokeContext| {
            let path_str = match args.get("path").and_then(|v| v.as_str()) {
                Some(p) => p.to_string(),
                None => return ToolInvokeResult::tool_error("missing required parameter: path"),
            };
            let config = Arc::clone(&config);
            run_blocking_tool("filesystem stat", move || {
                if !std::path::Path::new(&path_str).is_absolute() {
                    return ToolInvokeResult::tool_error(format!(
                        "path \"{}\" must be absolute",
                        path_str
                    ));
                }
                let canonical =
                    match validate_path(&path_str, &config.roots, &config.exclude_patterns) {
                        Ok(p) => p,
                        Err(e) => return ToolInvokeResult::tool_error(e),
                    };
                let original_meta = match fs::symlink_metadata(&path_str) {
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
                let meta = match fs::metadata(&canonical) {
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

                #[cfg(unix)]
                let permissions = format!("{:o}", meta.permissions().mode() & 0o777);
                #[cfg(not(unix))]
                let permissions = if meta.permissions().readonly() {
                    "readonly"
                } else {
                    "read-write"
                }
                .to_string();

                ToolInvokeResult::success(json!({
                    "size": meta.len(),
                    "modified": modified,
                    "created": created,
                    "isDir": meta.is_dir(),
                    "isSymlink": original_meta.file_type().is_symlink(),
                    "permissions": permissions
                }))
            })
        }),
    }
}

fn file_search_tool(config: Arc<FilesystemConfig>) -> BuiltinTool {
    BuiltinTool {
        name: "file_search".to_string(),
        description: "Search for files by name pattern, optionally filtering by content."
            .to_string(),
        input_schema: json!({
            "type": "object",
            "properties": {
                "pattern": { "type": "string", "description": "Glob pattern to match file names." },
                "path": { "type": "string", "description": "Root directory to search from." },
                "max_depth": { "type": "integer", "description": "Maximum directory depth (default 10)." },
                "content_pattern": { "type": "string", "description": "Optional regex to filter files by content." }
            },
            "required": ["pattern", "path"],
            "additionalProperties": false
        }),
        handler: Box::new(move |args, _ctx: &ToolInvokeContext| {
            let name_pattern = match args.get("pattern").and_then(|v| v.as_str()) {
                Some(p) => p.to_string(),
                None => return ToolInvokeResult::tool_error("missing required parameter: pattern"),
            };
            let search_root = match args.get("path").and_then(|v| v.as_str()) {
                Some(p) => p.to_string(),
                None => return ToolInvokeResult::tool_error("missing required parameter: path"),
            };
            let requested_max_depth =
                args.get("max_depth").and_then(|v| v.as_u64()).unwrap_or(10) as usize;
            if requested_max_depth > DEFAULT_MAX_SEARCH_DEPTH {
                return ToolInvokeResult::tool_error(format!(
                    "max_depth too large ({} > {})",
                    requested_max_depth, DEFAULT_MAX_SEARCH_DEPTH
                ));
            }
            let max_depth = requested_max_depth;
            let content_pattern = args
                .get("content_pattern")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());

            let glob_pattern = match Pattern::new(&name_pattern) {
                Ok(p) => p,
                Err(e) => {
                    return ToolInvokeResult::tool_error(format!("invalid glob pattern: {}", e))
                }
            };
            // Cap regex length to prevent expensive compilation.
            const MAX_REGEX_LEN: usize = 10_000;
            let content_regex = match content_pattern {
                Some(ref pat) => {
                    if pat.len() > MAX_REGEX_LEN {
                        return ToolInvokeResult::tool_error(format!(
                            "content_pattern too long ({} chars, max {})",
                            pat.len(),
                            MAX_REGEX_LEN
                        ));
                    }
                    match regex::Regex::new(pat) {
                        Ok(r) => Some(r),
                        Err(e) => {
                            return ToolInvokeResult::tool_error(format!("invalid regex: {}", e))
                        }
                    }
                }
                None => None,
            };

            let search_config = Arc::clone(&config);
            let do_search = move || {
                let canonical_root = match validate_path(
                    &search_root,
                    &search_config.roots,
                    &search_config.exclude_patterns,
                ) {
                    Ok(p) => p,
                    Err(e) => return ToolInvokeResult::tool_error(e),
                };

                struct WalkCtx<'a> {
                    max_depth: usize,
                    budget: usize,
                    glob_pattern: &'a Pattern,
                    content_regex: &'a Option<regex::Regex>,
                    max_read: u64,
                    roots: &'a [PathBuf],
                    exclude_patterns: &'a [Pattern],
                    matches: Vec<Value>,
                    entries_scanned: usize,
                    skipped_non_utf8: usize,
                    truncated: bool,
                }

                fn walk(dir: &std::path::Path, depth: usize, ctx: &mut WalkCtx<'_>) {
                    if depth > ctx.max_depth || ctx.truncated {
                        return;
                    }
                    let entries = match fs::read_dir(dir) {
                        Ok(e) => e,
                        Err(_) => return,
                    };
                    for entry in entries.flatten() {
                        if ctx.truncated {
                            return;
                        }
                        ctx.entries_scanned += 1;
                        if ctx.entries_scanned > ctx.budget {
                            ctx.truncated = true;
                            return;
                        }
                        let path = entry.path();
                        let name = entry.file_name().to_string_lossy().into_owned();
                        let file_type = match entry.file_type() {
                            Ok(ft) => ft,
                            Err(_) => continue,
                        };
                        let Some(canonical) =
                            canonicalize_allowed_path(&path, ctx.roots, ctx.exclude_patterns)
                        else {
                            continue;
                        };

                        if file_type.is_dir() {
                            walk(&canonical, depth + 1, ctx);
                            continue;
                        }
                        if file_type.is_symlink() && canonical.is_dir() {
                            continue;
                        }
                        if !ctx.glob_pattern.matches(&name) {
                            continue;
                        }

                        if let Some(ref regex) = ctx.content_regex {
                            let content_result = {
                                let file = match fs::File::open(&canonical) {
                                    Ok(f) => f,
                                    Err(_) => continue,
                                };
                                let file_size = file.metadata().map(|m| m.len()).unwrap_or(0);
                                // Skip files larger than 2x max_read for content matching.
                                if file_size > ctx.max_read * 2 {
                                    None
                                } else {
                                    let limit = ctx.max_read.min(file_size);
                                    let mut buf = Vec::with_capacity(limit as usize);
                                    let _ = file.take(limit).read_to_end(&mut buf);
                                    match String::from_utf8(buf) {
                                        Ok(content) => Some(content),
                                        Err(_) => {
                                            ctx.skipped_non_utf8 += 1;
                                            None
                                        }
                                    }
                                }
                            };
                            if let Some(content) = content_result {
                                if let Some(m) = regex.find(&content) {
                                    let line_num =
                                        content[..m.start()].chars().filter(|c| *c == '\n').count()
                                            + 1;
                                    let line = content.lines().nth(line_num - 1).unwrap_or("");
                                    ctx.matches.push(json!({
                                        "path": canonical.to_string_lossy(),
                                        "line": line_num,
                                        "snippet": line.chars().take(200).collect::<String>()
                                    }));
                                }
                            }
                        } else {
                            ctx.matches
                                .push(json!({ "path": canonical.to_string_lossy() }));
                        }
                    }
                }

                let mut ctx = WalkCtx {
                    max_depth,
                    budget: search_config.search_entry_budget,
                    glob_pattern: &glob_pattern,
                    content_regex: &content_regex,
                    max_read: search_config.max_read_bytes,
                    roots: &search_config.roots,
                    exclude_patterns: &search_config.exclude_patterns,
                    matches: Vec::new(),
                    entries_scanned: 0,
                    skipped_non_utf8: 0,
                    truncated: false,
                };

                walk(&canonical_root, 0, &mut ctx);

                ToolInvokeResult::success(json!({
                    "matches": ctx.matches,
                    "entriesScanned": ctx.entries_scanned,
                    "skippedNonUtf8": ctx.skipped_non_utf8,
                    "truncated": ctx.truncated
                }))
            };
            run_blocking_tool("filesystem search", do_search)
        }),
    }
}

fn file_write_tool(config: Arc<FilesystemConfig>) -> BuiltinTool {
    BuiltinTool {
        name: "file_write".to_string(),
        description: "Write content to a file within configured filesystem roots.".to_string(),
        input_schema: json!({
            "type": "object",
            "properties": {
                "path": { "type": "string", "description": "Absolute path to write to." },
                "content": { "type": "string", "description": "Content to write." },
                "create_dirs": { "type": "boolean", "description": "Create parent directories if they don't exist (default true)." }
            },
            "required": ["path", "content"],
            "additionalProperties": false
        }),
        handler: Box::new(move |args, _ctx| {
            let path_str = match args.get("path").and_then(|v| v.as_str()) {
                Some(p) => p.to_string(),
                None => return ToolInvokeResult::tool_error("missing required parameter: path"),
            };
            let content = match args.get("content").and_then(|v| v.as_str()) {
                Some(c) => c.to_string(),
                None => return ToolInvokeResult::tool_error("missing required parameter: content"),
            };
            if content.len() as u64 > config.max_read_bytes {
                return ToolInvokeResult::tool_error(format!(
                    "content too large ({} bytes, max {})",
                    content.len(),
                    config.max_read_bytes
                ));
            }
            let create_dirs = args
                .get("create_dirs")
                .and_then(|v| v.as_bool())
                .unwrap_or(true);
            let config = Arc::clone(&config);
            run_blocking_tool("filesystem write", move || {
                let target = match validate_write_path(
                    &path_str,
                    &config.roots,
                    &config.exclude_patterns,
                    create_dirs,
                ) {
                    Ok(p) => p,
                    Err(e) => return ToolInvokeResult::tool_error(e),
                };

                match fs::write(&target, &content) {
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
            })
        }),
    }
}

fn file_move_tool(config: Arc<FilesystemConfig>) -> BuiltinTool {
    BuiltinTool {
        name: "file_move".to_string(),
        description: "Move or rename a file within configured filesystem roots.".to_string(),
        input_schema: json!({
            "type": "object",
            "properties": {
                "source": { "type": "string", "description": "Absolute path of the file to move." },
                "destination": { "type": "string", "description": "Absolute destination path." }
            },
            "required": ["source", "destination"],
            "additionalProperties": false
        }),
        handler: Box::new(move |args, _ctx| {
            let source_str = match args.get("source").and_then(|v| v.as_str()) {
                Some(p) => p.to_string(),
                None => return ToolInvokeResult::tool_error("missing required parameter: source"),
            };
            let dest_str = match args.get("destination").and_then(|v| v.as_str()) {
                Some(p) => p.to_string(),
                None => {
                    return ToolInvokeResult::tool_error("missing required parameter: destination")
                }
            };
            let config = Arc::clone(&config);
            run_blocking_tool("filesystem move", move || {
                let source =
                    match validate_path(&source_str, &config.roots, &config.exclude_patterns) {
                        Ok(p) => p,
                        Err(e) => return ToolInvokeResult::tool_error(e),
                    };
                let source_meta = match fs::symlink_metadata(&source_str) {
                    Ok(m) => m,
                    Err(e) => {
                        let msg = if e.kind() == std::io::ErrorKind::PermissionDenied {
                            format!("permission denied: \"{}\"", source_str)
                        } else {
                            format!("cannot stat \"{}\": {}", source_str, e)
                        };
                        return ToolInvokeResult::tool_error(msg);
                    }
                };
                if source_meta.file_type().is_symlink() {
                    return ToolInvokeResult::tool_error(format!(
                        "\"{}\" is a symlink; file_move only supports regular files",
                        source_str
                    ));
                }

                if source.is_dir() {
                    return ToolInvokeResult::tool_error(format!(
                        "\"{}\" is a directory; file_move only supports files",
                        source_str
                    ));
                }

                let dest = match validate_write_path(
                    &dest_str,
                    &config.roots,
                    &config.exclude_patterns,
                    false,
                ) {
                    Ok(p) => p,
                    Err(e) => return ToolInvokeResult::tool_error(e),
                };

                let rename_result = fs::rename(&source, &dest);

                #[cfg(windows)]
                let rename_result = if rename_result.is_err() && dest.exists() {
                    // Windows std::fs::rename does not replace an existing destination.
                    // This remove-then-rename fallback still has an inherent TOCTOU gap:
                    // another process can recreate `dest` between the remove and rename.
                    fs::remove_file(&dest).and_then(|()| fs::rename(&source, &dest))
                } else {
                    rename_result
                };

                match rename_result {
                    Ok(()) => ToolInvokeResult::success(json!({
                        "source": source.to_string_lossy(),
                        "destination": dest.to_string_lossy()
                    })),
                    Err(e) => {
                        let msg = if e.kind() == std::io::ErrorKind::CrossesDevices {
                            format!(
                                "cannot move across filesystems from \"{}\" to \"{}\"",
                                source.display(),
                                dest.display()
                            )
                        } else if e.kind() == std::io::ErrorKind::PermissionDenied {
                            format!(
                                "permission denied moving \"{}\" to \"{}\"",
                                source.display(),
                                dest.display()
                            )
                        } else {
                            format!("cannot move: {}", e)
                        };
                        ToolInvokeResult::tool_error(msg)
                    }
                }
            })
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    use crate::plugins::tools::{ToolInvokeContext, ToolInvokeResult};
    use serde_json::json;

    fn setup_test_tree() -> TempDir {
        let tmp = TempDir::new().unwrap();
        fs::create_dir_all(tmp.path().join("subdir")).unwrap();
        fs::write(tmp.path().join("hello.txt"), "hello world").unwrap();
        fs::write(tmp.path().join("subdir/nested.txt"), "nested content").unwrap();
        fs::write(tmp.path().join("secret.log"), "sensitive data").unwrap();
        tmp
    }

    fn test_ctx() -> ToolInvokeContext {
        ToolInvokeContext::default()
    }

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

    #[test]
    fn test_validate_path_within_root() {
        let tmp = setup_test_tree();
        let roots = vec![tmp.path().canonicalize().unwrap()];
        let result = validate_path(tmp.path().join("hello.txt").to_str().unwrap(), &roots, &[]);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_path_outside_root() {
        let tmp = setup_test_tree();
        let roots = vec![tmp.path().join("subdir").canonicalize().unwrap()];
        let result = validate_path(tmp.path().join("hello.txt").to_str().unwrap(), &roots, &[]);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("outside"));
    }

    #[test]
    fn test_validate_path_dotdot_escape() {
        let tmp = setup_test_tree();
        let roots = vec![tmp.path().join("subdir").canonicalize().unwrap()];
        let escaped = tmp.path().join("subdir/../hello.txt");
        let result = validate_path(escaped.to_str().unwrap(), &roots, &[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_path_exclude_pattern() {
        let tmp = setup_test_tree();
        let roots = vec![tmp.path().canonicalize().unwrap()];
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
        let roots = vec![
            tmp1.path().canonicalize().unwrap(),
            tmp2.path().canonicalize().unwrap(),
        ];
        let result = validate_path(tmp2.path().join("file.txt").to_str().unwrap(), &roots, &[]);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_path_empty_roots() {
        let tmp = setup_test_tree();
        let result = validate_path(tmp.path().join("hello.txt").to_str().unwrap(), &[], &[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_path_nonexistent() {
        let tmp = setup_test_tree();
        let roots = vec![tmp.path().canonicalize().unwrap()];
        let result = validate_path(
            tmp.path().join("no_such_file.txt").to_str().unwrap(),
            &roots,
            &[],
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_write_path_rejects_relative_path() {
        let tmp = setup_test_tree();
        let roots = vec![tmp.path().canonicalize().unwrap()];
        let result = validate_write_path("relative/file.txt", &roots, &[], true);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("must be absolute"));
    }

    #[test]
    fn test_validate_path_rejects_relative_path() {
        let tmp = setup_test_tree();
        let roots = vec![tmp.path().canonicalize().unwrap()];
        let result = validate_path("relative/path.txt", &roots, &[]);
        assert!(result.is_err());
        assert!(
            result.unwrap_err().contains("must be absolute"),
            "should reject relative paths explicitly"
        );
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
        )
        .unwrap();
        let roots = vec![tmp.path().canonicalize().unwrap()];
        let result = validate_path(tmp.path().join("link.txt").to_str().unwrap(), &roots, &[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_write_path_new_file() {
        let tmp = setup_test_tree();
        let roots = vec![tmp.path().canonicalize().unwrap()];
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
        let roots = vec![tmp.path().canonicalize().unwrap()];
        let result = validate_write_path(
            tmp.path().join("newdir/file.txt").to_str().unwrap(),
            &roots,
            &[],
            true,
        );
        assert!(result.is_ok());
        assert!(tmp.path().join("newdir").exists());
    }

    #[test]
    fn test_validate_write_path_no_create_dirs() {
        let tmp = setup_test_tree();
        let roots = vec![tmp.path().canonicalize().unwrap()];
        let result = validate_write_path(
            tmp.path()
                .join("nonexistent_dir/file.txt")
                .to_str()
                .unwrap(),
            &roots,
            &[],
            false,
        );
        assert!(result.is_err());
    }

    // ===== file_read tests =====

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

    // ===== directory_list tests =====

    #[test]
    fn test_directory_list_happy_path() {
        let tmp = setup_test_tree();
        let cfg = make_test_config(tmp.path(), false);
        let tools = filesystem_tools(&cfg);
        let tool = tools.iter().find(|t| t.name == "directory_list").unwrap();
        let result = (tool.handler)(json!({ "path": tmp.path().to_str().unwrap() }), &test_ctx());
        match &result {
            ToolInvokeResult::Success { result, .. } => {
                let entries = result["entries"].as_array().unwrap();
                let names: Vec<&str> = entries
                    .iter()
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
                let names: Vec<&str> = entries
                    .iter()
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
    fn test_directory_list_invalid_glob_errors() {
        let tmp = setup_test_tree();
        let cfg = make_test_config(tmp.path(), false);
        let tools = filesystem_tools(&cfg);
        let tool = tools.iter().find(|t| t.name == "directory_list").unwrap();
        let result = (tool.handler)(
            json!({ "path": tmp.path().to_str().unwrap(), "glob": "[" }),
            &test_ctx(),
        );
        match &result {
            ToolInvokeResult::Error { error, .. } => {
                assert!(error.message.contains("invalid glob pattern"));
            }
            _ => panic!("expected invalid glob error"),
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

    // ===== file_stat tests =====

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
                assert_eq!(result["size"], 11);
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

    #[cfg(unix)]
    #[test]
    fn test_file_stat_reports_symlink() {
        let tmp = setup_test_tree();
        std::os::unix::fs::symlink(
            tmp.path().join("hello.txt"),
            tmp.path().join("hello-link.txt"),
        )
        .unwrap();
        let cfg = make_test_config(tmp.path(), false);
        let tools = filesystem_tools(&cfg);
        let tool = tools.iter().find(|t| t.name == "file_stat").unwrap();
        let result = (tool.handler)(
            json!({ "path": tmp.path().join("hello-link.txt").to_str().unwrap() }),
            &test_ctx(),
        );
        match &result {
            ToolInvokeResult::Success { result, .. } => {
                assert_eq!(result["isSymlink"], true);
                assert_eq!(result["isDir"], false);
            }
            _ => panic!("expected success"),
        }
    }

    // ===== file_search tests =====

    #[test]
    fn test_file_search_by_name() {
        let tmp = setup_test_tree();
        let cfg = make_test_config(tmp.path(), false);
        let tools = filesystem_tools(&cfg);
        let tool = tools.iter().find(|t| t.name == "file_search").unwrap();
        let result = (tool.handler)(
            json!({ "pattern": "*.txt", "path": tmp.path().to_str().unwrap() }),
            &test_ctx(),
        );
        match &result {
            ToolInvokeResult::Success { result, .. } => {
                let matches = result["matches"].as_array().unwrap();
                assert!(matches.len() >= 2);
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
            json!({ "pattern": "*.txt", "path": tmp.path().to_str().unwrap(), "content_pattern": "nested" }),
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

    #[test]
    fn test_file_search_reports_skipped_non_utf8_content() {
        let tmp = TempDir::new().unwrap();
        fs::write(tmp.path().join("binary.bin"), [0xff, 0xfe, 0xfd]).unwrap();
        let cfg = make_test_config(tmp.path(), false);
        let tools = filesystem_tools(&cfg);
        let tool = tools.iter().find(|t| t.name == "file_search").unwrap();
        let result = (tool.handler)(
            json!({
                "pattern": "*.bin",
                "path": tmp.path().to_str().unwrap(),
                "content_pattern": "anything"
            }),
            &test_ctx(),
        );
        match &result {
            ToolInvokeResult::Success { result, .. } => {
                assert_eq!(result["matches"].as_array().unwrap().len(), 0);
                assert_eq!(result["skippedNonUtf8"], 1);
            }
            _ => panic!("expected success"),
        }
    }

    fn filesystem_tools_with_budget(cfg: &serde_json::Value, budget: usize) -> Vec<BuiltinTool> {
        let mut config = FilesystemConfig::from_value(cfg);
        config.search_entry_budget = budget;
        let config = Arc::new(config);
        let mut tools = vec![
            file_read_tool(Arc::clone(&config)),
            directory_list_tool(Arc::clone(&config)),
            file_stat_tool(Arc::clone(&config)),
            file_search_tool(Arc::clone(&config)),
        ];
        if config.write_access {
            tools.push(file_write_tool(Arc::clone(&config)));
            tools.push(file_move_tool(Arc::clone(&config)));
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
            "filesystem": { "enabled": true, "roots": [tmp.path().to_str().unwrap()] }
        });
        let tools = filesystem_tools_with_budget(&cfg, 5);
        let tool = tools.iter().find(|t| t.name == "file_search").unwrap();
        let result = (tool.handler)(
            json!({ "pattern": "*.txt", "path": tmp.path().to_str().unwrap() }),
            &test_ctx(),
        );
        match &result {
            ToolInvokeResult::Success { result, .. } => {
                assert_eq!(result["truncated"], true);
                let matches = result["matches"].as_array().unwrap();
                assert!(matches.len() < 20);
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
            "filesystem": { "enabled": true, "roots": [tmp.path().to_str().unwrap()] }
        });
        let tools = filesystem_tools(&cfg);
        let tool = tools.iter().find(|t| t.name == "file_search").unwrap();
        let result = (tool.handler)(
            json!({ "pattern": "*.txt", "path": tmp.path().to_str().unwrap() }),
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

    // ===== file_write tests =====

    #[test]
    fn test_file_write_happy_path() {
        let tmp = setup_test_tree();
        let cfg = make_test_config(tmp.path(), true);
        let tools = filesystem_tools(&cfg);
        let tool = tools.iter().find(|t| t.name == "file_write").unwrap();
        let new_path = tmp.path().join("written.txt");
        let result = (tool.handler)(
            json!({ "path": new_path.to_str().unwrap(), "content": "new content" }),
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
        let cfg = make_test_config(tmp.path(), false);
        let tools = filesystem_tools(&cfg);
        assert!(!tools.iter().any(|t| t.name == "file_write"));
    }

    #[test]
    fn test_file_write_creates_dirs() {
        let tmp = setup_test_tree();
        let cfg = make_test_config(tmp.path(), true);
        let tools = filesystem_tools(&cfg);
        let tool = tools.iter().find(|t| t.name == "file_write").unwrap();
        let new_path = tmp.path().join("new_dir/deep/file.txt");
        let result = (tool.handler)(
            json!({ "path": new_path.to_str().unwrap(), "content": "deep content" }),
            &test_ctx(),
        );
        match &result {
            ToolInvokeResult::Success { .. } => {}
            _ => panic!("expected success"),
        }
        assert!(new_path.exists());
    }

    // ===== file_move tests =====

    #[test]
    fn test_file_move_happy_path() {
        let tmp = setup_test_tree();
        let cfg = make_test_config(tmp.path(), true);
        let tools = filesystem_tools(&cfg);
        let tool = tools.iter().find(|t| t.name == "file_move").unwrap();
        let src = tmp.path().join("hello.txt");
        let dst = tmp.path().join("moved.txt");
        let result = (tool.handler)(
            json!({ "source": src.to_str().unwrap(), "destination": dst.to_str().unwrap() }),
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

    #[cfg(unix)]
    #[test]
    fn test_file_move_rejects_symlink_source() {
        let tmp = setup_test_tree();
        std::os::unix::fs::symlink(
            tmp.path().join("hello.txt"),
            tmp.path().join("hello-link.txt"),
        )
        .unwrap();
        let cfg = make_test_config(tmp.path(), true);
        let tools = filesystem_tools(&cfg);
        let tool = tools.iter().find(|t| t.name == "file_move").unwrap();
        let result = (tool.handler)(
            json!({
                "source": tmp.path().join("hello-link.txt").to_str().unwrap(),
                "destination": tmp.path().join("moved.txt").to_str().unwrap()
            }),
            &test_ctx(),
        );
        match &result {
            ToolInvokeResult::Error { error, .. } => {
                assert!(error.message.contains("is a symlink"));
            }
            _ => panic!("expected symlink-source error"),
        }
    }

    #[test]
    fn test_file_move_denied_without_write_access() {
        let tmp = setup_test_tree();
        let cfg = make_test_config(tmp.path(), false);
        let tools = filesystem_tools(&cfg);
        assert!(!tools.iter().any(|t| t.name == "file_move"));
    }

    // ===== exclude pattern enforcement tests =====

    #[test]
    fn test_directory_list_filters_excluded_entries() {
        let tmp = setup_test_tree();
        fs::write(tmp.path().join(".env"), "SECRET=foo").unwrap();
        let cfg = json!({
            "filesystem": {
                "enabled": true,
                "roots": [tmp.path().to_str().unwrap()],
                "excludePatterns": ["*.env", "*.log"]
            }
        });
        let tools = filesystem_tools(&cfg);
        let tool = tools.iter().find(|t| t.name == "directory_list").unwrap();
        let result = (tool.handler)(json!({ "path": tmp.path().to_str().unwrap() }), &test_ctx());
        match &result {
            ToolInvokeResult::Success { result, .. } => {
                let entries = result["entries"].as_array().unwrap();
                let names: Vec<&str> = entries
                    .iter()
                    .map(|e| e["name"].as_str().unwrap())
                    .collect();
                assert!(
                    !names.contains(&".env"),
                    "excluded .env should not appear in listing"
                );
                assert!(
                    !names.contains(&"secret.log"),
                    "excluded *.log should not appear in listing"
                );
                assert!(
                    names.contains(&"hello.txt"),
                    "non-excluded files should appear"
                );
            }
            _ => panic!("expected success"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn test_directory_list_skips_symlink_outside_root() {
        let tmp = setup_test_tree();
        let outside = TempDir::new().unwrap();
        fs::write(outside.path().join("secret.txt"), "outside").unwrap();
        std::os::unix::fs::symlink(
            outside.path().join("secret.txt"),
            tmp.path().join("outside-link.txt"),
        )
        .unwrap();
        let cfg = make_test_config(tmp.path(), false);
        let tools = filesystem_tools(&cfg);
        let tool = tools.iter().find(|t| t.name == "directory_list").unwrap();
        let result = (tool.handler)(json!({ "path": tmp.path().to_str().unwrap() }), &test_ctx());
        match &result {
            ToolInvokeResult::Success { result, .. } => {
                let names: Vec<&str> = result["entries"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|e| e["name"].as_str().unwrap())
                    .collect();
                assert!(!names.contains(&"outside-link.txt"));
            }
            _ => panic!("expected success"),
        }
    }

    #[test]
    fn test_file_search_enforces_exclude_patterns() {
        let tmp = setup_test_tree();
        fs::write(tmp.path().join(".env"), "SECRET=foo").unwrap();
        let cfg = json!({
            "filesystem": {
                "enabled": true,
                "roots": [tmp.path().to_str().unwrap()],
                "excludePatterns": ["*.log"]
            }
        });
        let tools = filesystem_tools(&cfg);
        let tool = tools.iter().find(|t| t.name == "file_search").unwrap();
        let result = (tool.handler)(
            json!({ "pattern": "*", "path": tmp.path().to_str().unwrap() }),
            &test_ctx(),
        );
        match &result {
            ToolInvokeResult::Success { result, .. } => {
                let matches = result["matches"].as_array().unwrap();
                let paths: Vec<&str> = matches.iter().filter_map(|m| m["path"].as_str()).collect();
                assert!(
                    !paths.iter().any(|p| p.contains("secret.log")),
                    "excluded *.log should not appear in search results"
                );
                assert!(
                    paths.iter().any(|p| p.contains("hello.txt")),
                    "non-excluded files should appear in search results"
                );
            }
            _ => panic!("expected success"),
        }
    }

    #[test]
    fn test_file_search_prunes_excluded_directories() {
        let tmp = TempDir::new().unwrap();
        fs::create_dir_all(tmp.path().join("node_modules/pkg")).unwrap();
        fs::write(tmp.path().join("node_modules/pkg/index.js"), "module").unwrap();
        fs::write(tmp.path().join("app.js"), "app").unwrap();
        let cfg = json!({
            "filesystem": {
                "enabled": true,
                "roots": [tmp.path().to_str().unwrap()],
                "excludePatterns": ["node_modules"]
            }
        });
        let tools = filesystem_tools(&cfg);
        let tool = tools.iter().find(|t| t.name == "file_search").unwrap();
        let result = (tool.handler)(
            json!({ "pattern": "*.js", "path": tmp.path().to_str().unwrap() }),
            &test_ctx(),
        );
        match &result {
            ToolInvokeResult::Success { result, .. } => {
                let matches = result["matches"].as_array().unwrap();
                let paths: Vec<&str> = matches.iter().filter_map(|m| m["path"].as_str()).collect();
                assert!(
                    !paths.iter().any(|p| p.contains("node_modules")),
                    "search should not descend into excluded directories"
                );
                assert_eq!(matches.len(), 1, "only app.js should match");
            }
            _ => panic!("expected success"),
        }
    }

    #[test]
    fn test_file_search_with_content_excludes_log() {
        let tmp = setup_test_tree();
        let cfg = json!({
            "filesystem": {
                "enabled": true,
                "roots": [tmp.path().to_str().unwrap()],
                "excludePatterns": ["*.log"]
            }
        });
        let tools = filesystem_tools(&cfg);
        let tool = tools.iter().find(|t| t.name == "file_search").unwrap();
        let result = (tool.handler)(
            json!({ "pattern": "*", "path": tmp.path().to_str().unwrap(), "content_pattern": "sensitive" }),
            &test_ctx(),
        );
        match &result {
            ToolInvokeResult::Success { result, .. } => {
                let matches = result["matches"].as_array().unwrap();
                assert!(
                    !matches
                        .iter()
                        .any(|m| m["path"].as_str().unwrap_or("").contains("secret.log")),
                    "content search should not return excluded files"
                );
            }
            _ => panic!("expected success"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn test_file_search_skips_symlinked_directory_outside_root() {
        let tmp = TempDir::new().unwrap();
        let outside = TempDir::new().unwrap();
        fs::write(tmp.path().join("inside.txt"), "inside").unwrap();
        fs::create_dir_all(outside.path().join("deep")).unwrap();
        fs::write(outside.path().join("deep/outside.txt"), "outside").unwrap();
        std::os::unix::fs::symlink(outside.path(), tmp.path().join("outside-link")).unwrap();

        let cfg = json!({
            "filesystem": {
                "enabled": true,
                "roots": [tmp.path().to_str().unwrap()]
            }
        });
        let tools = filesystem_tools(&cfg);
        let tool = tools.iter().find(|t| t.name == "file_search").unwrap();
        let result = (tool.handler)(
            json!({ "pattern": "*.txt", "path": tmp.path().to_str().unwrap() }),
            &test_ctx(),
        );
        match &result {
            ToolInvokeResult::Success { result, .. } => {
                let paths: Vec<&str> = result["matches"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .filter_map(|m| m["path"].as_str())
                    .collect();
                assert!(paths.iter().any(|p| p.contains("inside.txt")));
                assert!(!paths.iter().any(|p| p.contains("outside.txt")));
                assert!(!result["truncated"].as_bool().unwrap());
            }
            _ => panic!("expected success"),
        }
    }

    // ===== additional coverage tests =====

    #[test]
    fn test_file_read_with_offset() {
        let tmp = setup_test_tree();
        let cfg = make_test_config(tmp.path(), false);
        let tools = filesystem_tools(&cfg);
        let tool = tools.iter().find(|t| t.name == "file_read").unwrap();
        let result = (tool.handler)(
            json!({ "path": tmp.path().join("hello.txt").to_str().unwrap(), "offset": 6 }),
            &test_ctx(),
        );
        match &result {
            ToolInvokeResult::Success { result, .. } => {
                assert_eq!(result["content"], "world");
            }
            _ => panic!("expected success"),
        }
    }

    #[test]
    fn test_file_search_invalid_regex() {
        let tmp = setup_test_tree();
        let cfg = make_test_config(tmp.path(), false);
        let tools = filesystem_tools(&cfg);
        let tool = tools.iter().find(|t| t.name == "file_search").unwrap();
        let result = (tool.handler)(
            json!({ "pattern": "*", "path": tmp.path().to_str().unwrap(), "content_pattern": "[invalid" }),
            &test_ctx(),
        );
        match &result {
            ToolInvokeResult::Error { error, .. } => {
                assert!(error.message.contains("invalid regex"));
            }
            _ => panic!("expected error for invalid regex"),
        }
    }

    #[test]
    fn test_file_search_regex_too_long() {
        let tmp = setup_test_tree();
        let cfg = make_test_config(tmp.path(), false);
        let tools = filesystem_tools(&cfg);
        let tool = tools.iter().find(|t| t.name == "file_search").unwrap();
        let long_pattern = "a".repeat(10_001);
        let result = (tool.handler)(
            json!({ "pattern": "*", "path": tmp.path().to_str().unwrap(), "content_pattern": long_pattern }),
            &test_ctx(),
        );
        match &result {
            ToolInvokeResult::Error { error, .. } => {
                assert!(error.message.contains("too long"));
            }
            _ => panic!("expected error for overly long regex"),
        }
    }

    #[test]
    fn test_file_search_rejects_excessive_max_depth() {
        let tmp = setup_test_tree();
        let cfg = make_test_config(tmp.path(), false);
        let tools = filesystem_tools(&cfg);
        let tool = tools.iter().find(|t| t.name == "file_search").unwrap();
        let result = (tool.handler)(
            json!({
                "pattern": "*",
                "path": tmp.path().to_str().unwrap(),
                "max_depth": DEFAULT_MAX_SEARCH_DEPTH as u64 + 1
            }),
            &test_ctx(),
        );
        match &result {
            ToolInvokeResult::Error { error, .. } => {
                assert!(error.message.contains("max_depth too large"));
            }
            _ => panic!("expected error for overly large max_depth"),
        }
    }

    #[test]
    fn test_validate_write_path_excludes_rejected() {
        let tmp = setup_test_tree();
        let roots = vec![tmp.path().canonicalize().unwrap()];
        let pattern = Pattern::new("*.log").unwrap();
        let result = validate_write_path(
            tmp.path().join("new.log").to_str().unwrap(),
            &roots,
            &[pattern],
            false,
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("excluded"));
    }

    #[test]
    fn test_validate_write_path_create_dirs_excludes_checked_before_mkdir() {
        let tmp = setup_test_tree();
        let roots = vec![tmp.path().canonicalize().unwrap()];
        let pattern = Pattern::new("secret_dir").unwrap();
        let result = validate_write_path(
            tmp.path().join("secret_dir/file.txt").to_str().unwrap(),
            &roots,
            &[pattern],
            true,
        );
        assert!(result.is_err());
        // Verify the directory was NOT created since exclude check runs first.
        assert!(!tmp.path().join("secret_dir").exists());
    }

    #[test]
    fn test_validate_write_path_rejects_parent_dir_components() {
        let tmp = setup_test_tree();
        let roots = vec![tmp.path().canonicalize().unwrap()];
        let requested = tmp.path().join("nested/../escape/file.txt");
        let result = validate_write_path(requested.to_str().unwrap(), &roots, &[], true);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("must not contain parent-directory"));
        assert!(!tmp.path().join("nested").exists());
        assert!(!tmp.path().join("escape").exists());
    }

    #[test]
    fn test_validate_write_path_precreate_checks_nested_root_excludes() {
        let tmp = TempDir::new().unwrap();
        fs::create_dir_all(tmp.path().join("nested-root")).unwrap();
        let roots = vec![
            tmp.path().canonicalize().unwrap(),
            tmp.path().join("nested-root").canonicalize().unwrap(),
        ];
        let pattern = Pattern::new("private/**").unwrap();
        let requested = tmp.path().join("nested-root/private/new/file.txt");
        let result = validate_write_path(requested.to_str().unwrap(), &roots, &[pattern], true);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("excluded"));
        assert!(!tmp.path().join("nested-root/private").exists());
    }

    #[test]
    fn test_validate_path_denies_when_any_matching_root_excludes_path() {
        let tmp = TempDir::new().unwrap();
        fs::create_dir_all(tmp.path().join("private")).unwrap();
        fs::write(tmp.path().join("private/secret.txt"), "secret").unwrap();
        let roots = vec![
            tmp.path().join("private").canonicalize().unwrap(),
            tmp.path().canonicalize().unwrap(),
        ];
        let pattern = Pattern::new("private/**").unwrap();
        let result = validate_path(
            tmp.path().join("private/secret.txt").to_str().unwrap(),
            &roots,
            &[pattern],
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("excluded"));
    }

    #[cfg(unix)]
    #[test]
    fn test_validate_write_path_rejects_existing_symlink_target() {
        let tmp = setup_test_tree();
        let outside = TempDir::new().unwrap();
        fs::write(outside.path().join("outside.txt"), "outside").unwrap();
        std::os::unix::fs::symlink(
            outside.path().join("outside.txt"),
            tmp.path().join("symlink-target.txt"),
        )
        .unwrap();
        let roots = vec![tmp.path().canonicalize().unwrap()];
        let result = validate_write_path(
            tmp.path().join("symlink-target.txt").to_str().unwrap(),
            &roots,
            &[],
            false,
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("symlink target"));
    }

    #[test]
    fn test_file_write_rejects_oversized_content() {
        let tmp = setup_test_tree();
        let cfg = json!({
            "filesystem": {
                "enabled": true,
                "roots": [tmp.path().to_str().unwrap()],
                "writeAccess": true,
                "maxReadBytes": 8
            }
        });
        let tools = filesystem_tools(&cfg);
        let tool = tools.iter().find(|t| t.name == "file_write").unwrap();
        let result = (tool.handler)(
            json!({
                "path": tmp.path().join("too-big.txt").to_str().unwrap(),
                "content": "123456789"
            }),
            &test_ctx(),
        );
        match &result {
            ToolInvokeResult::Error { error, .. } => {
                assert!(error.message.contains("content too large"));
            }
            _ => panic!("expected oversized content error"),
        }
    }

    #[test]
    fn test_filesystem_tools_disable_on_invalid_unvalidated_config() {
        let tmp = TempDir::new().unwrap();
        let cfg = json!({
            "filesystem": {
                "enabled": true,
                "roots": [tmp.path().to_str().unwrap()],
                "excludePatterns": [123]
            }
        });
        let tools = filesystem_tools(&cfg);
        assert!(tools.is_empty());
    }

    #[test]
    fn test_filesystem_tools_disable_on_relative_root_config() {
        let cfg = json!({
            "filesystem": {
                "enabled": true,
                "roots": ["./relative-root"]
            }
        });
        let tools = filesystem_tools(&cfg);
        assert!(tools.is_empty());
    }

    #[test]
    fn test_file_read_empty_file() {
        let tmp = TempDir::new().unwrap();
        fs::write(tmp.path().join("empty.txt"), "").unwrap();
        let cfg = make_test_config(tmp.path(), false);
        let tools = filesystem_tools(&cfg);
        let tool = tools.iter().find(|t| t.name == "file_read").unwrap();
        let result = (tool.handler)(
            json!({ "path": tmp.path().join("empty.txt").to_str().unwrap() }),
            &test_ctx(),
        );
        match &result {
            ToolInvokeResult::Success { result, .. } => {
                assert_eq!(result["content"], "");
                assert_eq!(result["encoding"], "utf-8");
                assert_eq!(result["size"], 0);
                assert_eq!(result["truncated"], false);
            }
            _ => panic!("expected success"),
        }
    }
}
