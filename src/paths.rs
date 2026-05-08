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
/// Windows has no portable equivalent: `File::open(directory)` returns
/// `ERROR_ACCESS_DENIED` (or the open succeeds but `FlushFileBuffers`
/// on a directory handle does), and NTFS provides directory durability
/// via the journal automatically once the rename completes. Return
/// `Ok(())` on Windows and rely on the OS contract there.
///
/// Callers translate the `io::Error` into their domain error
/// (`MatrixError::SyncFailed`, `String`, etc.). For best-effort
/// variants where a fsync failure must not override a primary error,
/// use `sync_parent_dir_best_effort_blocking`.
#[cfg(unix)]
pub(crate) fn sync_parent_dir_blocking(path: &Path) -> std::io::Result<()> {
    let parent = match path.parent() {
        None => return Ok(()),
        Some(p) if p.as_os_str().is_empty() => Path::new("."),
        Some(p) => p,
    };
    let dir = std::fs::File::open(parent)?;
    dir.sync_all()
}

#[cfg(not(unix))]
pub(crate) fn sync_parent_dir_blocking(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

/// Best-effort variant: silently ignore parent-fsync failures. Use
/// only on cleanup paths where a primary error is already in flight
/// and the fsync result is purely defensive.
pub(crate) fn sync_parent_dir_best_effort_blocking(path: &Path) {
    let _ = sync_parent_dir_blocking(path);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// On Unix, `sync_parent_dir_blocking` opens the parent directory
    /// and calls `sync_all` — exercising it against a real temp
    /// directory must succeed for both regular paths and cwd-relative
    /// paths.
    #[cfg(unix)]
    #[test]
    fn test_sync_parent_dir_blocking_unix_smoke() {
        let temp = tempfile::tempdir().expect("tempdir");
        let target = temp.path().join("file");
        std::fs::write(&target, b"x").expect("write");
        sync_parent_dir_blocking(&target).expect("parent fsync must succeed");
    }

    /// `path.parent() == None` (filesystem root) should be a no-op.
    #[test]
    fn test_sync_parent_dir_blocking_root_is_noop() {
        let root = Path::new("/");
        sync_parent_dir_blocking(root).expect("root path must be a no-op");
    }

    /// On Windows, the function is unconditionally `Ok(())` — pin
    /// that contract so a future refactor that introduces a Windows
    /// implementation doesn't silently break existing call sites
    /// that translate `io::Error` into a hard rekey-abort.
    #[cfg(not(unix))]
    #[test]
    fn test_sync_parent_dir_blocking_windows_is_noop() {
        // Even bogus paths must return Ok on non-Unix targets.
        sync_parent_dir_blocking(Path::new(r"Z:\does\not\exist\file.bin"))
            .expect("non-unix sync_parent_dir_blocking must always succeed");
        sync_parent_dir_blocking(Path::new(""))
            .expect("non-unix sync_parent_dir_blocking must accept empty path");
    }
}
