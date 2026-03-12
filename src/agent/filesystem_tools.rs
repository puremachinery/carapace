//! Filesystem tools — read, search, write, and move files within configured roots.

use std::fs;
use std::io::Read;
use std::path::PathBuf;

use base64::Engine;
use glob::Pattern;
use serde_json::{json, Value};

use crate::plugins::tools::{BuiltinTool, ToolInvokeContext, ToolInvokeResult};

const DEFAULT_SEARCH_ENTRY_BUDGET: usize = 10_000;

/// Run a sync closure, signaling tokio when in a multi-threaded runtime.
fn run_blocking<T>(f: impl FnOnce() -> T) -> T {
    match tokio::runtime::Handle::try_current() {
        Ok(h) if h.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
            tokio::task::block_in_place(f)
        }
        _ => f(),
    }
}

/// Validate that a requested path is allowed by the configured roots and exclude patterns.
pub fn validate_path(
    requested: &str,
    roots: &[PathBuf],
    exclude_patterns: &[Pattern],
) -> Result<PathBuf, String> {
    let canonical = std::fs::canonicalize(requested)
        .map_err(|e| format!("cannot resolve path \"{}\": {}", requested, e))?;

    let matching_root = roots.iter().find(|root| canonical.starts_with(root));
    if matching_root.is_none() {
        return Err(format!(
            "path \"{}\" is outside all configured filesystem roots",
            canonical.display()
        ));
    }
    let root = matching_root.unwrap();

    let relative = canonical.strip_prefix(root).unwrap_or(&canonical);
    for pattern in exclude_patterns {
        if pattern.matches_path(relative) {
            return Err(format!(
                "path \"{}\" is excluded by pattern \"{}\"",
                canonical.display(),
                pattern
            ));
        }
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

/// Validate a path for write operations where the target file may not exist yet.
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
        let mut ancestor = parent.to_path_buf();
        while !ancestor.exists() {
            ancestor = ancestor
                .parent()
                .ok_or_else(|| "cannot find existing ancestor directory".to_string())?
                .to_path_buf();
        }
        let canonical_ancestor = std::fs::canonicalize(&ancestor)
            .map_err(|e| format!("cannot resolve ancestor \"{}\": {}", ancestor.display(), e))?;

        if !roots
            .iter()
            .any(|root| canonical_ancestor.starts_with(root))
        {
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

    let matching_root = roots.iter().find(|root| canonical_parent.starts_with(root));
    if matching_root.is_none() {
        return Err(format!(
            "path \"{}\" is outside all configured filesystem roots",
            requested
        ));
    }
    let root = matching_root.unwrap();

    let full_path = canonical_parent.join(filename);

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
        let roots: Vec<PathBuf> = fs_cfg
            .get("roots")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str())
                    .filter_map(|s| match std::fs::canonicalize(s) {
                        Ok(p) => Some(p),
                        Err(e) => {
                            tracing::warn!(root = %s, error = %e, "filesystem root cannot be resolved; it will be excluded");
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
                            tracing::error!(pattern = %s, error = %e, "invalid exclude pattern; filesystem tools will be disabled");
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
    let mut tools = vec![
        file_read_tool(config.clone()),
        directory_list_tool(config.clone()),
        file_stat_tool(config.clone()),
        file_search_tool(config.clone()),
    ];

    if config.write_access {
        tools.push(file_write_tool(config.clone()));
        tools.push(file_move_tool(config.clone()));
    }

    tools
}

fn file_read_tool(config: FilesystemConfig) -> BuiltinTool {
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
                Some(p) => p,
                None => return ToolInvokeResult::tool_error("missing required parameter: path"),
            };
            let canonical = match validate_path(path_str, &config.roots, &config.exclude_patterns) {
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
            if let Err(e) = file.take(limit).read_to_end(&mut buf) {
                let msg = if e.kind() == std::io::ErrorKind::PermissionDenied {
                    format!("permission denied: \"{}\"", path_str)
                } else {
                    format!("cannot read \"{}\": {}", path_str, e)
                };
                return ToolInvokeResult::tool_error(msg);
            }

            let truncated = file_size > offset + buf.len() as u64;
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
                "totalBytes": file_size
            }))
        }),
    }
}

fn directory_list_tool(config: FilesystemConfig) -> BuiltinTool {
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
                Some(p) => p,
                None => return ToolInvokeResult::tool_error("missing required parameter: path"),
            };
            let canonical = match validate_path(path_str, &config.roots, &config.exclude_patterns) {
                Ok(p) => p,
                Err(e) => return ToolInvokeResult::tool_error(e),
            };
            if !canonical.is_dir() {
                return ToolInvokeResult::tool_error(format!(
                    "\"{}\" is not a directory",
                    path_str
                ));
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
                results.push(
                    json!({ "name": name, "type": type_str, "size": size, "modified": modified }),
                );
            }

            ToolInvokeResult::success(json!({ "entries": results }))
        }),
    }
}

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

fn file_stat_tool(config: FilesystemConfig) -> BuiltinTool {
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
                "isSymlink": meta.file_type().is_symlink(),
                "permissions": permissions
            }))
        }),
    }
}

fn file_search_tool(config: FilesystemConfig) -> BuiltinTool {
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
            let max_depth = args.get("max_depth").and_then(|v| v.as_u64()).unwrap_or(10) as usize;
            let content_pattern = args
                .get("content_pattern")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());

            let canonical_root =
                match validate_path(&search_root, &config.roots, &config.exclude_patterns) {
                    Ok(p) => p,
                    Err(e) => return ToolInvokeResult::tool_error(e),
                };
            let glob_pattern = match Pattern::new(&name_pattern) {
                Ok(p) => p,
                Err(e) => {
                    return ToolInvokeResult::tool_error(format!("invalid glob pattern: {}", e))
                }
            };
            let content_regex = match content_pattern {
                Some(ref pat) => match regex::Regex::new(pat) {
                    Ok(r) => Some(r),
                    Err(e) => return ToolInvokeResult::tool_error(format!("invalid regex: {}", e)),
                },
                None => None,
            };

            let budget = config.search_entry_budget;
            let max_read = config.max_read_bytes;
            let roots_clone = config.roots.clone();

            let do_search = move || {
                struct WalkCtx<'a> {
                    max_depth: usize,
                    budget: usize,
                    glob_pattern: &'a Pattern,
                    content_regex: &'a Option<regex::Regex>,
                    max_read: u64,
                    roots: &'a [PathBuf],
                    matches: Vec<Value>,
                    entries_scanned: usize,
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
                        if path.is_dir() {
                            walk(&path, depth + 1, ctx);
                            continue;
                        }
                        if !ctx.glob_pattern.matches(&name) {
                            continue;
                        }
                        // Verify path is within roots
                        if let Ok(canonical) = std::fs::canonicalize(&path) {
                            if !ctx.roots.iter().any(|r| canonical.starts_with(r)) {
                                continue;
                            }
                        }
                        if let Some(ref regex) = ctx.content_regex {
                            let content_result = {
                                let file = match fs::File::open(&path) {
                                    Ok(f) => f,
                                    Err(_) => continue,
                                };
                                let file_size = file.metadata().map(|m| m.len()).unwrap_or(0);
                                if file_size > ctx.max_read * 2 {
                                    None
                                } else {
                                    let limit = ctx.max_read.min(file_size);
                                    let mut buf = Vec::with_capacity(limit as usize);
                                    let _ = file.take(limit).read_to_end(&mut buf);
                                    String::from_utf8(buf).ok()
                                }
                            };
                            if let Some(content) = content_result {
                                if let Some(m) = regex.find(&content) {
                                    let line_num =
                                        content[..m.start()].chars().filter(|c| *c == '\n').count()
                                            + 1;
                                    let line = content.lines().nth(line_num - 1).unwrap_or("");
                                    ctx.matches.push(json!({
                                        "path": path.to_string_lossy(),
                                        "line": line_num,
                                        "snippet": line.chars().take(200).collect::<String>()
                                    }));
                                }
                            }
                        } else {
                            ctx.matches.push(json!({ "path": path.to_string_lossy() }));
                        }
                    }
                }

                let mut ctx = WalkCtx {
                    max_depth,
                    budget,
                    glob_pattern: &glob_pattern,
                    content_regex: &content_regex,
                    max_read,
                    roots: &roots_clone,
                    matches: Vec::new(),
                    entries_scanned: 0,
                    truncated: false,
                };

                walk(&canonical_root, 0, &mut ctx);

                json!({ "matches": ctx.matches, "entriesScanned": ctx.entries_scanned, "truncated": ctx.truncated })
            };

            let result = run_blocking(do_search);
            ToolInvokeResult::success(result)
        }),
    }
}

fn file_write_tool(config: FilesystemConfig) -> BuiltinTool {
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

fn file_move_tool(config: FilesystemConfig) -> BuiltinTool {
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
                Some(p) => p,
                None => return ToolInvokeResult::tool_error("missing required parameter: source"),
            };
            let dest_str = match args.get("destination").and_then(|v| v.as_str()) {
                Some(p) => p,
                None => {
                    return ToolInvokeResult::tool_error("missing required parameter: destination")
                }
            };

            let source = match validate_path(source_str, &config.roots, &config.exclude_patterns) {
                Ok(p) => p,
                Err(e) => return ToolInvokeResult::tool_error(e),
            };

            if source.is_dir() {
                return ToolInvokeResult::tool_error(format!(
                    "\"{}\" is a directory; file_move only supports files",
                    source_str
                ));
            }

            let dest =
                match validate_write_path(dest_str, &config.roots, &config.exclude_patterns, false)
                {
                    Ok(p) => p,
                    Err(e) => return ToolInvokeResult::tool_error(e),
                };

            let rename_result = fs::rename(&source, &dest);

            #[cfg(windows)]
            let rename_result = if rename_result.is_err() && dest.exists() {
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

    fn filesystem_tools_with_budget(cfg: &serde_json::Value, budget: usize) -> Vec<BuiltinTool> {
        let mut config = FilesystemConfig::from_value(cfg);
        config.search_entry_budget = budget;
        let mut tools = vec![
            file_read_tool(config.clone()),
            directory_list_tool(config.clone()),
            file_stat_tool(config.clone()),
            file_search_tool(config.clone()),
        ];
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

    #[test]
    fn test_file_move_denied_without_write_access() {
        let tmp = setup_test_tree();
        let cfg = make_test_config(tmp.path(), false);
        let tools = filesystem_tools(&cfg);
        assert!(!tools.iter().any(|t| t.name == "file_move"));
    }
}
