use std::path::{Path, PathBuf};

pub(crate) fn resolve_state_dir() -> PathBuf {
    if let Some(dir) = crate::config::read_process_env("CARAPACE_STATE_DIR") {
        return PathBuf::from(dir);
    }
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from(".config"))
        .join("carapace")
}

/// Open the parent directory of `path` and call `sync_all` so a
/// preceding `rename(2)` becomes durable.
///
/// Falls through to the current working directory when `path.parent()`
/// returns `Some("")` (cwd-relative paths). When the path has no
/// parent at all (filesystem root etc.) returns `Ok(())` since there
/// is nothing to flush.
///
/// Callers translate the `io::Error` into their domain error
/// (`MatrixError::SyncFailed`, `String`, etc.). For best-effort
/// variants where a fsync failure must not override a primary error,
/// use `sync_parent_dir_best_effort_blocking`.
pub(crate) fn sync_parent_dir_blocking(path: &Path) -> std::io::Result<()> {
    let parent = match path.parent() {
        None => return Ok(()),
        Some(p) if p.as_os_str().is_empty() => Path::new("."),
        Some(p) => p,
    };
    let dir = std::fs::File::open(parent)?;
    dir.sync_all()
}

/// Best-effort variant: silently ignore parent-fsync failures. Use
/// only on cleanup paths where a primary error is already in flight
/// and the fsync result is purely defensive.
pub(crate) fn sync_parent_dir_best_effort_blocking(path: &Path) {
    let _ = sync_parent_dir_blocking(path);
}
