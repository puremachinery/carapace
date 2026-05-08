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

/// Compute a unique sibling-path for atomic temp+rename writes.
///
/// Returns `{base.file_name}.{infix}.tmp.{pid}.{counter}` in the same
/// directory as `base`, where `counter` comes from a shared
/// process-monotonic atomic. Two concurrent writers (different
/// callers, different files) can never collide on the same tmp path
/// even within the same PID. Use one helper across all atomic-write
/// sites — `persist_config_file_locked`, session-store rewrites, CLI
/// secret writes — so the pattern stays consistent and a single
/// convention can be hardened in one place.
pub(crate) fn atomic_tmp_path(base: &Path, infix: &str) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static ATOMIC_TMP_COUNTER: AtomicU64 = AtomicU64::new(0);
    let counter = ATOMIC_TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    let stem = base
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("carapace");
    base.with_file_name(format!("{stem}.{infix}.tmp.{pid}.{counter}"))
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

    /// Pin every infix string used by the four atomic-write call sites
    /// (`config_write_temp_path`, `secret_file_temp_path`,
    /// `installation_id_temp_path`, `cli_secret_temp_path`). A typo
    /// in any one of these would not compile-fail but would
    /// silently break operator journal globs that filter on
    /// `*.{infix}.tmp.*` — and the unique counter pin protects
    /// against a regression that loses monotonicity.
    #[test]
    fn test_atomic_tmp_path_infix_variants_pin_journal_glob_contract() {
        let base = Path::new("/tmp/x/file.bin");
        for infix in &["cfg", "secret", "iid", "cli-secret"] {
            let p = atomic_tmp_path(base, infix);
            let name = p.file_name().expect("file_name").to_str().expect("utf8");
            assert!(
                name.starts_with(&format!("file.bin.{infix}.tmp.")),
                "infix {infix} must appear after stem; journal cleanup greps on this. got: {name}"
            );
            assert_eq!(p.parent(), base.parent(), "tmp path must be a sibling");
        }
        // Counter monotonicity within a process: two consecutive
        // calls with the same infix MUST produce distinct paths.
        let a = atomic_tmp_path(base, "cfg");
        let b = atomic_tmp_path(base, "cfg");
        assert_ne!(a, b, "shared atomic counter must produce unique paths");
    }
}
