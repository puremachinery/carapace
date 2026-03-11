use std::time::{SystemTime, UNIX_EPOCH};

pub(crate) fn unix_now_ms_u64() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

pub(crate) fn unix_now_ms_i64() -> i64 {
    unix_now_ms_u64() as i64
}
