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

/// Open an atomic-write tmp file with security-hardened flags:
/// `O_CREAT | O_EXCL | O_WRONLY | O_NOFOLLOW`, mode `0o600`.
///
/// SECURITY: prior to this helper, atomic-write tmp opens across the
/// tree used `OpenOptions::write+create+truncate` against a
/// deterministic sibling path (`path.with_extension("tmp")`). A
/// same-uid attacker (same daemon UID on a multi-tenant host, or
/// another process owned by the operator on a shared workstation)
/// could pre-plant a symlink at the predictable tmp path → arbitrary
/// daemon-uid-writable file. The daemon's `create+truncate` open
/// would FOLLOW the symlink, truncate the redirected target, and
/// write the serialized policy/state content there. Subsequent
/// `rename(tmp, dst)` would then move the symlink dirent onto the
/// live path, leaving the live file as a symlink whose subsequent
/// reads follow back to the attacker's target. Highest-stakes
/// surfaces were `exec-approvals.json` (gates elevated-privilege
/// command execution) and `auth-profiles` (OAuth secrets), but the
/// same primitive was reachable across devices / nodes / usage /
/// sessions / save-memory / daemon-pid.
///
/// `O_EXCL` + `O_NOFOLLOW` together close the threat:
/// - `O_EXCL` refuses to open any pre-existing dirent (regular file
///   OR symlink), so a planted tmp is rejected outright.
/// - `O_NOFOLLOW` is a second-line guard in case a future change
///   weakens `O_EXCL` (e.g. removes `.create_new(true)`).
///
/// Pair with `atomic_tmp_path` for the unique-per-call tmp path so
/// `O_EXCL` failure means active attack, not a stale-from-prior-
/// crash leftover.
pub(crate) fn create_atomic_tmp_owner_only(tmp_path: &Path) -> std::io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    options.open(tmp_path)
}

/// Open `path` for reading without hanging on a planted FIFO. On Unix
/// the flags are `O_NONBLOCK` so the open(2) call itself returns
/// immediately for a FIFO with no writer (vs. blocking indefinitely);
/// the held fd is then fstat-validated and the function refuses
/// anything that is not a regular file. Regular files ignore
/// `O_NONBLOCK` (no kernel-side blocking semantics) so the happy-path
/// `read` works normally.
///
/// SYMLINKS ARE FOLLOWED. Use this helper for paths the design
/// explicitly allows operators to route through secret-management
/// tooling (1Password, `pass`, secret volumes). Use
/// [`open_regular_file_no_hang_no_follow`] for paths where symlinks
/// are not part of the contract.
///
/// Returns `Ok(None)` for `NotFound` so callers can branch on missing
/// without an outer error wrap.
pub(crate) fn open_regular_file_no_hang(path: &Path) -> std::io::Result<Option<std::fs::File>> {
    // Pre-check via `metadata` (which follows symlinks) so platforms
    // where `OpenOptions::open` returns a generic permission-denied
    // for a directory at the path (Windows: "Access is denied", AIX,
    // etc.) surface the same "not a regular file" classification as
    // the post-open fstat check on Unix. Symlinks-to-regular-files
    // are intentionally allowed for this helper.
    match std::fs::metadata(path) {
        Ok(meta) => {
            if !meta.is_file() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "not a regular file (symlinks to regular files are allowed)",
                ));
            }
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err),
    }

    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK);
    }
    let file = match options.open(path) {
        Ok(file) => file,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err),
    };
    // Post-open re-check defends against TOCTOU between the pre-check
    // metadata and the open: a same-uid attacker who races a symlink
    // swap or directory-create between the two syscalls hits this
    // branch.
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "not a regular file (symlinks to regular files are allowed)",
        ));
    }
    Ok(Some(file))
}

/// `read_to_end` companion to [`open_regular_file_no_hang_no_follow`]
/// with a hard byte cap.
///
/// Opens with `O_NOFOLLOW | O_NONBLOCK` + fstat-validates regular
/// file, then reads at most `max_bytes + 1` bytes. Returns
/// `Err(InvalidData)` if either:
/// - the metadata size is already over `max_bytes` (fast path), or
/// - the read produced more than `max_bytes` bytes (post-read check
///   defends against metadata-vs-read races on growing files).
///
/// `Ok(None)` on `NotFound`. Use for daemon-startup loads of marker
/// / transaction / journal / index JSON files where the legitimate
/// content is bounded by a small known size; without a cap a same-
/// uid attacker who plants a multi-GB file at one of these paths
/// OOMs the daemon at startup before tokio reactor or audit log
/// come up.
pub(crate) fn read_to_vec_no_hang_no_follow_capped(
    path: &Path,
    max_bytes: u64,
) -> std::io::Result<Option<Vec<u8>>> {
    use std::io::Read;
    let mut file = match open_regular_file_no_hang_no_follow(path)? {
        Some(file) => file,
        None => return Ok(None),
    };
    let metadata = file.metadata()?;
    if metadata.len() > max_bytes {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "file exceeds {} byte cap (metadata reports {} bytes)",
                max_bytes,
                metadata.len()
            ),
        ));
    }
    let mut buf = Vec::new();
    (&mut file).take(max_bytes + 1).read_to_end(&mut buf)?;
    if buf.len() as u64 > max_bytes {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("file exceeds {} byte cap (post-read)", max_bytes),
        ));
    }
    Ok(Some(buf))
}

/// Open `path` for reading with `O_NOFOLLOW` + `O_NONBLOCK` (Unix)
/// and post-open `is_file()` validation. Closes BOTH the
/// symlink-to-FIFO hang class AND the direct-FIFO-at-path hang
/// class. Use this for state-dir files where symlinks are not part
/// of the design contract — daemon-owned binaries, transaction/
/// marker JSON, session history, credential index.
///
/// Returns `Ok(None)` for `NotFound`.
pub(crate) fn open_regular_file_no_hang_no_follow(
    path: &Path,
) -> std::io::Result<Option<std::fs::File>> {
    // Pre-check via `symlink_metadata` so platforms where
    // `OpenOptions::open` returns a generic permission-denied for a
    // directory at the path (Windows: "Access is denied", AIX, etc.)
    // surface the same "not a regular file" / "opened path is a
    // symlink" classification as the post-open fstat check on Unix.
    // Without this, callers and tests cannot reliably depend on the
    // error variant without per-platform branches.
    match std::fs::symlink_metadata(path) {
        Ok(meta) => {
            if meta.file_type().is_symlink() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "opened path is a symlink",
                ));
            }
            if !meta.is_file() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "not a regular file",
                ));
            }
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err),
    }

    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = match options.open(path) {
        Ok(file) => file,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err),
    };
    // Post-open re-check defends against the TOCTOU window between
    // the symlink_metadata above and the open: a same-uid attacker
    // who races a symlink swap or directory-create between the two
    // syscalls hits this branch.
    let metadata = file.metadata()?;
    if metadata.file_type().is_symlink() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "opened path is a symlink",
        ));
    }
    if !metadata.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "not a regular file",
        ));
    }
    Ok(Some(file))
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

    /// Pin every infix string used across the seven atomic-write call
    /// sites: `cfg` (config write), `secret` (matrix credentials),
    /// `iid` (matrix installation id), `cli-secret` (CLI secret writes),
    /// `jsonl` / `archive` / `json` (sessions store). A typo in any of
    /// these would not compile-fail but would silently break operator
    /// journal globs that filter on `*.{infix}.tmp.*` — and the
    /// unique counter pin protects against a regression that loses
    /// monotonicity.
    #[test]
    fn test_atomic_tmp_path_infix_variants_pin_journal_glob_contract() {
        let base = Path::new("/tmp/x/file.bin");
        for infix in &[
            "cfg",
            "secret",
            "iid",
            "cli-secret",
            "jsonl",
            "archive",
            "json",
        ] {
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

    /// Pin the `unwrap_or("carapace")` fallback when `base.file_name()`
    /// returns None (e.g. `Path::new("/")`). A future refactor that
    /// hard-codes a different fallback string would break operator
    /// journals expecting `carapace.{infix}.tmp.*` for orphan-base
    /// cases.
    #[test]
    fn test_atomic_tmp_path_orphan_base_uses_carapace_fallback() {
        let p = atomic_tmp_path(Path::new("/"), "cfg");
        let name = p.file_name().expect("file_name").to_str().expect("utf8");
        assert!(
            name.starts_with("carapace.cfg.tmp."),
            "orphan-base must fall through to `carapace` stem; got: {name}"
        );
    }

    /// Batch 98: `read_to_vec_no_hang_no_follow_capped` must refuse
    /// to read a file larger than the requested cap. Without this
    /// the daemon could OOM at startup on an attacker-planted multi-
    /// GB marker file in `state_dir/updates/`.
    #[test]
    fn test_read_to_vec_no_hang_no_follow_capped_metadata_over_cap() {
        let temp = tempfile::tempdir().expect("tempdir");
        let target = temp.path().join("oversized.json");
        std::fs::write(&target, vec![b'x'; 256]).expect("write");
        let err = read_to_vec_no_hang_no_follow_capped(&target, 128)
            .expect_err("metadata over cap must reject");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert!(
            err.to_string().contains("byte cap"),
            "error must mention cap: {err}"
        );
    }

    /// Happy path — content within the cap is returned verbatim.
    #[test]
    fn test_read_to_vec_no_hang_no_follow_capped_under_cap_succeeds() {
        let temp = tempfile::tempdir().expect("tempdir");
        let target = temp.path().join("small.json");
        let bytes = b"{\"phase\":\"Created\"}".to_vec();
        std::fs::write(&target, &bytes).expect("write");
        let read = read_to_vec_no_hang_no_follow_capped(&target, 64 * 1024)
            .expect("under-cap read")
            .expect("Some(buf)");
        assert_eq!(read, bytes);
    }

    /// `NotFound` returns `Ok(None)` so callers can express the
    /// "missing marker = nothing to recover" contract without a
    /// separate `path.exists()` probe.
    #[test]
    fn test_read_to_vec_no_hang_no_follow_capped_missing_is_none() {
        let temp = tempfile::tempdir().expect("tempdir");
        let target = temp.path().join("never-existed.json");
        let read = read_to_vec_no_hang_no_follow_capped(&target, 1024)
            .expect("NotFound must not be an error");
        assert!(read.is_none(), "missing file must yield Ok(None)");
    }
}
