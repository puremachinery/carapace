//! Log handlers.

use serde_json::{json, Value};
use std::fs;
use std::io::{Read, Seek, SeekFrom};
use std::path::PathBuf;
use std::sync::LazyLock;

use regex::Regex;

use super::super::*;

fn clamp_i64(value: i64, min: i64, max: i64) -> i64 {
    value.max(min).min(max)
}

#[derive(Debug)]
struct LogSlice {
    cursor: u64,
    size: u64,
    lines: Vec<String>,
    truncated: bool,
    reset: bool,
}

fn resolve_log_file_path() -> PathBuf {
    if let Ok(path) = env::var("MOLTBOT_LOG_FILE") {
        if !path.trim().is_empty() {
            return PathBuf::from(path);
        }
    }
    resolve_state_dir().join("logs").join("moltbot.log")
}

fn resolve_log_file(path: &PathBuf) -> PathBuf {
    if path.exists() {
        return path.clone();
    }
    static ROLLING_RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"^moltbot-\d{4}-\d{2}-\d{2}\.log$").unwrap());
    let file_name = path.file_name().and_then(|v| v.to_str()).unwrap_or("");
    if !ROLLING_RE.is_match(file_name) {
        return path.clone();
    }
    let dir = path.parent().unwrap_or_else(|| std::path::Path::new("."));
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(_) => return path.clone(),
    };
    let mut newest: Option<(PathBuf, std::time::SystemTime)> = None;
    for entry in entries.flatten() {
        let candidate = entry.path();
        let candidate_name = candidate.file_name().and_then(|v| v.to_str()).unwrap_or("");
        if !ROLLING_RE.is_match(candidate_name) {
            continue;
        }
        if let Ok(meta) = entry.metadata() {
            if let Ok(modified) = meta.modified() {
                let is_newer = newest
                    .as_ref()
                    .map(|(_, ts)| modified > *ts)
                    .unwrap_or(true);
                if is_newer {
                    newest = Some((candidate.clone(), modified));
                }
            }
        }
    }
    newest.map(|(path, _)| path).unwrap_or_else(|| path.clone())
}

fn read_log_slice(
    file: &PathBuf,
    cursor: Option<u64>,
    limit: usize,
    max_bytes: usize,
) -> Result<LogSlice, ErrorShape> {
    let meta = match fs::metadata(file) {
        Ok(meta) => meta,
        Err(_) => {
            return Ok(LogSlice {
                cursor: 0,
                size: 0,
                lines: Vec::new(),
                truncated: false,
                reset: false,
            })
        }
    };
    let size = meta.len();
    let mut reset = false;
    let mut truncated = false;
    let mut start: u64;

    if let Some(cursor) = cursor {
        if cursor > size {
            reset = true;
            start = size.saturating_sub(max_bytes as u64);
            truncated = start > 0;
        } else {
            start = cursor;
            if size.saturating_sub(start) > max_bytes as u64 {
                reset = true;
                truncated = true;
                start = size.saturating_sub(max_bytes as u64);
            }
        }
    } else {
        start = size.saturating_sub(max_bytes as u64);
        truncated = start > 0;
    }

    if size == 0 || size <= start {
        return Ok(LogSlice {
            cursor: size,
            size,
            lines: Vec::new(),
            truncated,
            reset,
        });
    }

    let mut file_handle = fs::File::open(file).map_err(|err| {
        error_shape(
            ERROR_UNAVAILABLE,
            &format!("log read failed: {}", err),
            None,
        )
    })?;
    let mut prefix = String::new();
    if start > 0 {
        file_handle.seek(SeekFrom::Start(start - 1)).ok();
        let mut buf = [0u8; 1];
        if let Ok(read) = file_handle.read(&mut buf) {
            if read > 0 {
                prefix = String::from_utf8_lossy(&buf[..read]).to_string();
            }
        }
    }
    file_handle.seek(SeekFrom::Start(start)).ok();
    let mut buffer = vec![0u8; (size - start) as usize];
    let read = file_handle.read(&mut buffer).unwrap_or(0);
    buffer.truncate(read);
    let text = String::from_utf8_lossy(&buffer).to_string();
    let mut lines: Vec<String> = text.split('\n').map(|s| s.to_string()).collect();
    if start > 0 && prefix != "\n" && !lines.is_empty() {
        lines.remove(0);
    }
    if lines.last().map(|s| s.is_empty()).unwrap_or(false) {
        lines.pop();
    }
    if lines.len() > limit {
        lines = lines.split_off(lines.len() - limit);
    }

    Ok(LogSlice {
        cursor: size,
        size,
        lines,
        truncated,
        reset,
    })
}

pub(super) fn handle_logs_tail(params: Option<&Value>) -> Result<Value, ErrorShape> {
    let limit = params
        .and_then(|v| v.get("limit"))
        .and_then(|v| v.as_i64())
        .map(|v| clamp_i64(v, 1, LOGS_MAX_LIMIT as i64) as usize)
        .unwrap_or(LOGS_DEFAULT_LIMIT);
    let max_bytes = params
        .and_then(|v| v.get("maxBytes"))
        .and_then(|v| v.as_i64())
        .map(|v| clamp_i64(v, 1, LOGS_MAX_BYTES as i64) as usize)
        .unwrap_or(LOGS_DEFAULT_MAX_BYTES);
    let cursor = params
        .and_then(|v| v.get("cursor"))
        .and_then(|v| v.as_i64())
        .filter(|v| *v >= 0)
        .map(|v| v as u64);

    let configured = resolve_log_file_path();
    let file = resolve_log_file(&configured);
    let result = read_log_slice(&file, cursor, limit, max_bytes)?;

    Ok(json!({
        "file": file.to_string_lossy(),
        "cursor": result.cursor,
        "size": result.size,
        "lines": result.lines,
        "truncated": result.truncated,
        "reset": result.reset
    }))
}
