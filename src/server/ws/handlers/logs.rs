//! Log handlers.

use serde_json::{json, Value};

use crate::logging::buffer::{LogEntry, LogFilter, LogLevel, LOG_BUFFER};

use super::super::*;

fn clamp_i64(value: i64, min: i64, max: i64) -> i64 {
    value.max(min).min(max)
}

fn trim_entries_by_bytes(entries: Vec<LogEntry>, max_bytes: usize) -> (Vec<LogEntry>, bool) {
    if entries.is_empty() || max_bytes == 0 {
        return (entries, false);
    }

    let mut selected = Vec::new();
    let mut total_bytes = 0usize;
    let mut truncated = false;

    for entry in entries.iter().rev() {
        let entry_bytes = entry.message.len();
        if !selected.is_empty() && total_bytes + entry_bytes > max_bytes {
            truncated = true;
            break;
        }
        total_bytes += entry_bytes;
        selected.push(entry.clone());
        if total_bytes >= max_bytes && selected.len() < entries.len() {
            truncated = true;
            break;
        }
    }

    selected.reverse();
    (selected, truncated)
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
    let level = params.and_then(|v| v.get("level")).and_then(|v| v.as_str());
    let pattern = params
        .and_then(|v| v.get("pattern"))
        .and_then(|v| v.as_str());

    let buffer_len = LOG_BUFFER.len() as u64;
    let current_seq = LOG_BUFFER.current_seq();
    let earliest_seq = if buffer_len == 0 {
        0
    } else {
        current_seq.saturating_sub(buffer_len.saturating_sub(1))
    };

    let mut reset = false;
    let mut after_seq = cursor;
    if let Some(cursor) = cursor {
        if cursor > current_seq || cursor < earliest_seq {
            reset = true;
            after_seq = None;
        }
    }

    let mut filter = LogFilter::new().with_limit(limit);
    if let Some(level) = level {
        let level = level.parse::<LogLevel>().map_err(|err| {
            error_shape(
                ERROR_INVALID_REQUEST,
                &format!("invalid log level: {}", err),
                None,
            )
        })?;
        filter = filter.with_level(level);
    }
    if let Some(pattern) = pattern {
        filter = filter.with_pattern_str(pattern).ok_or_else(|| {
            error_shape(
                ERROR_INVALID_REQUEST,
                "invalid logs.tail pattern regex",
                None,
            )
        })?;
    }
    if let Some(after_seq) = after_seq {
        filter = filter.with_after_seq(after_seq);
    }

    let result = LOG_BUFFER.query(&filter);
    let (entries, trimmed) = trim_entries_by_bytes(result.entries, max_bytes);
    let truncated = result.has_more || trimmed;
    let cursor = entries.last().map(|entry| entry.seq).unwrap_or(0);
    let lines = entries
        .iter()
        .map(|entry| entry.message.clone())
        .collect::<Vec<_>>();

    Ok(json!({
        "cursor": cursor,
        "size": result.total,
        "entries": entries,
        "lines": lines,
        "truncated": truncated,
        "reset": reset
    }))
}
