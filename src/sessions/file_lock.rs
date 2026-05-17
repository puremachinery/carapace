//! Advisory file locking using `flock(2)` on Unix and `LockFileEx` on Windows.
//!
//! Provides an RAII [`FileLock`] that holds an exclusive advisory lock on a
//! `.lock` sentinel file beside the target path. The lock is released
//! automatically when the `FileLock` is dropped.

use std::fs::File;
use std::io;
use std::path::Path;

/// RAII advisory file lock.
///
/// Holds an exclusive `flock(LOCK_EX)` on a `.lock` sentinel file. The lock
/// is released when this struct is dropped.
///
/// **Sentinel-file lifecycle**: the `.lock` file is created on first
/// acquire and intentionally NOT removed on Drop. Removing the
/// sentinel on Drop opens a TOCTOU race: between our unlock and our
/// remove, another process could create+lock a fresh file at the
/// same path; our subsequent remove deletes the path entry while
/// the new lock is held on a still-valid FD/inode, and a third
/// acquirer would create a NEW file at the path → distinct inode →
/// flock would not exclude it from the second holder. The standard
/// POSIX fix is to leave the sentinel in place so all acquirers
/// open the same inode and contend on the same lock. Operators
/// will see one persistent `.lock` file in `state_dir` per lockable
/// resource (e.g. `.matrix-rekey.lock.lock`); document those in the
/// operator-facing docs rather than try to clean up at runtime.
pub struct FileLock {
    _file: File,
}

impl FileLock {
    /// Acquire an exclusive lock on the given path (blocking).
    ///
    /// Opens `<path>.lock` and holds `flock(LOCK_EX)` on it. The
    /// sentinel is created if absent, but never truncated (which
    /// would zero a planted symlink's target) and never followed
    /// through a symlink (O_NOFOLLOW on Unix).
    pub fn acquire(path: &Path) -> Result<Self, io::Error> {
        let lock_path = lock_path_for(path);
        let file = open_lock_sentinel(&lock_path)?;
        flock_exclusive(&file)?;
        Ok(Self { _file: file })
    }

    /// Try to acquire an exclusive lock without blocking.
    ///
    /// Returns `Ok(Some(lock))` on success, `Ok(None)` if the lock is held
    /// by another process, or `Err` on I/O failure.
    pub fn try_acquire(path: &Path) -> Result<Option<Self>, io::Error> {
        let lock_path = lock_path_for(path);
        let file = open_lock_sentinel(&lock_path)?;
        match flock_try_exclusive(&file) {
            Ok(true) => Ok(Some(Self { _file: file })),
            Ok(false) => Ok(None),
            Err(e) => Err(e),
        }
    }
}

/// Open (or create) the `.lock` sentinel for advisory flocking with
/// hardened flags: write-only, create-if-missing, O_NOFOLLOW on Unix,
/// mode 0o600. Critically does NOT use `O_TRUNC` — the prior
/// `File::create` call applied `O_CREAT|O_WRONLY|O_TRUNC`, which
/// allowed a same-uid attacker who planted a symlink at the sentinel
/// path to have the daemon truncate the symlink's target file. The
/// sentinel itself is 0-byte by design (only the held flock matters),
/// so omitting `O_TRUNC` does not change the success semantics.
fn open_lock_sentinel(lock_path: &Path) -> Result<File, io::Error> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // O_NOFOLLOW + O_NONBLOCK: O_NOFOLLOW protects against the
        // symlink-truncate class. O_NONBLOCK additionally prevents
        // `O_WRONLY | O_CREAT` from blocking when the dirent at
        // `lock_path` is a pre-planted FIFO with no reader — a same-
        // uid attacker (state_dir/sessions/ is 0o700 but reachable by
        // a tool-call escape) could otherwise hang the lock-acquire
        // path indefinitely. The subsequent `flock(LOCK_EX)` on the
        // returned fd is the actual mutual-exclusion primitive; the
        // file mode is irrelevant for FIFOs since flock(2) operates
        // on the fd regardless of dirent type, but the post-open
        // check expected by callers is documented to reject non-
        // regular dirents at higher layers.
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    options.open(lock_path)
}

impl Drop for FileLock {
    fn drop(&mut self) {
        flock_unlock(&self._file);
    }
}

/// Compute the `.lock` sentinel path for a given file path.
fn lock_path_for(path: &Path) -> std::path::PathBuf {
    let mut lock = path.as_os_str().to_os_string();
    lock.push(".lock");
    lock.into()
}

// ---------------------------------------------------------------------------
// Unix implementation using libc::flock
// ---------------------------------------------------------------------------

#[cfg(unix)]
fn flock_exclusive(file: &File) -> Result<(), io::Error> {
    use std::os::unix::io::AsRawFd;
    let fd = file.as_raw_fd();
    let rc = unsafe { libc::flock(fd, libc::LOCK_EX) };
    if rc != 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(unix)]
fn flock_try_exclusive(file: &File) -> Result<bool, io::Error> {
    use std::os::unix::io::AsRawFd;
    let fd = file.as_raw_fd();
    let rc = unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) };
    if rc == 0 {
        Ok(true)
    } else {
        let err = io::Error::last_os_error();
        if err.kind() == io::ErrorKind::WouldBlock {
            Ok(false)
        } else {
            Err(err)
        }
    }
}

#[cfg(unix)]
fn flock_unlock(file: &File) {
    use std::os::unix::io::AsRawFd;
    let fd = file.as_raw_fd();
    unsafe {
        libc::flock(fd, libc::LOCK_UN);
    }
}

// ---------------------------------------------------------------------------
// Windows implementation using LockFileEx
// ---------------------------------------------------------------------------

#[cfg(windows)]
const WHOLE_FILE_LOCK_LEN_LOW: u32 = u32::MAX;
#[cfg(windows)]
const WHOLE_FILE_LOCK_LEN_HIGH: u32 = u32::MAX;

#[cfg(windows)]
fn whole_file_overlapped() -> windows_sys::Win32::System::IO::OVERLAPPED {
    use windows_sys::Win32::System::IO::{OVERLAPPED, OVERLAPPED_0, OVERLAPPED_0_0};
    // Lock range starts at offset 0 and spans u64::MAX bytes via LOW/HIGH length args.
    OVERLAPPED {
        Anonymous: OVERLAPPED_0 {
            Anonymous: OVERLAPPED_0_0 {
                Offset: 0,
                OffsetHigh: 0,
            },
        },
        ..Default::default()
    }
}

#[cfg(windows)]
fn flock_exclusive(file: &File) -> Result<(), io::Error> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{LockFileEx, LOCKFILE_EXCLUSIVE_LOCK};

    let handle = file.as_raw_handle() as windows_sys::Win32::Foundation::HANDLE;
    let mut overlapped = whole_file_overlapped();
    let rc = unsafe {
        LockFileEx(
            handle,
            LOCKFILE_EXCLUSIVE_LOCK,
            0,
            WHOLE_FILE_LOCK_LEN_LOW,
            WHOLE_FILE_LOCK_LEN_HIGH,
            &mut overlapped,
        )
    };
    if rc == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(windows)]
fn flock_try_exclusive(file: &File) -> Result<bool, io::Error> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::{ERROR_LOCK_VIOLATION, ERROR_SHARING_VIOLATION};
    use windows_sys::Win32::Storage::FileSystem::{
        LockFileEx, LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY,
    };

    let handle = file.as_raw_handle() as windows_sys::Win32::Foundation::HANDLE;
    let mut overlapped = whole_file_overlapped();
    let rc = unsafe {
        LockFileEx(
            handle,
            LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
            0,
            WHOLE_FILE_LOCK_LEN_LOW,
            WHOLE_FILE_LOCK_LEN_HIGH,
            &mut overlapped,
        )
    };
    if rc != 0 {
        return Ok(true);
    }

    let err = io::Error::last_os_error();
    match err.raw_os_error() {
        Some(code)
            if code == ERROR_LOCK_VIOLATION as i32 || code == ERROR_SHARING_VIOLATION as i32 =>
        {
            Ok(false)
        }
        _ => Err(err),
    }
}

#[cfg(windows)]
fn flock_unlock(file: &File) {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::UnlockFileEx;

    let handle = file.as_raw_handle() as windows_sys::Win32::Foundation::HANDLE;
    // Unlock must match the same region/offset used by LockFileEx.
    let mut overlapped = whole_file_overlapped();
    unsafe {
        let _ = UnlockFileEx(
            handle,
            0,
            WHOLE_FILE_LOCK_LEN_LOW,
            WHOLE_FILE_LOCK_LEN_HIGH,
            &mut overlapped,
        );
    }
}

// ---------------------------------------------------------------------------
// Non-Unix and non-Windows: no-op implementation
// ---------------------------------------------------------------------------

#[cfg(all(not(unix), not(windows)))]
fn flock_exclusive(_file: &File) -> Result<(), io::Error> {
    Ok(())
}

#[cfg(all(not(unix), not(windows)))]
fn flock_try_exclusive(_file: &File) -> Result<bool, io::Error> {
    Ok(true)
}

#[cfg(all(not(unix), not(windows)))]
fn flock_unlock(_file: &File) {}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_acquire_and_release() {
        let dir = TempDir::new().unwrap();
        let target = dir.path().join("data.jsonl");
        std::fs::write(&target, b"").unwrap();

        let lock = FileLock::acquire(&target).unwrap();
        // Lock file should exist
        assert!(lock_path_for(&target).exists());
        drop(lock);

        // After drop, another acquire should succeed
        let lock2 = FileLock::acquire(&target).unwrap();
        drop(lock2);
    }

    #[test]
    fn test_try_acquire_succeeds_when_free() {
        let dir = TempDir::new().unwrap();
        let target = dir.path().join("meta.json");
        std::fs::write(&target, b"").unwrap();

        let maybe = FileLock::try_acquire(&target).unwrap();
        assert!(maybe.is_some());
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn test_try_acquire_returns_none_when_held() {
        let dir = TempDir::new().unwrap();
        let target = dir.path().join("contention.jsonl");
        std::fs::write(&target, b"").unwrap();

        let _held = FileLock::acquire(&target).unwrap();
        let second = FileLock::try_acquire(&target).unwrap();
        assert!(second.is_none(), "should return None when lock is held");
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn test_lock_released_on_drop() {
        let dir = TempDir::new().unwrap();
        let target = dir.path().join("drop_test.jsonl");
        std::fs::write(&target, b"").unwrap();

        {
            let _lock = FileLock::acquire(&target).unwrap();
            // Lock is held here
            let contended = FileLock::try_acquire(&target).unwrap();
            assert!(contended.is_none());
        }
        // Lock dropped — second acquire should succeed
        let reclaimed = FileLock::try_acquire(&target).unwrap();
        assert!(reclaimed.is_some());
    }

    /// Pin Batch 72 HIGH #4: FileLock refuses to truncate-through a
    /// symlink. The prior `File::create` (O_TRUNC) would zero the
    /// symlink's target file. With O_NOFOLLOW + no-truncate the
    /// daemon refuses the open and the planted target is untouched.
    #[cfg(unix)]
    #[test]
    fn test_acquire_refuses_symlinked_lock_sentinel() {
        use std::os::unix::fs as unix_fs;
        let dir = TempDir::new().unwrap();
        let target = dir.path().join("data.jsonl");
        std::fs::write(&target, b"").unwrap();
        // Attacker-planted symlink at the sentinel path → a daemon-
        // writable file we should never truncate.
        let victim = dir.path().join("victim");
        std::fs::write(&victim, b"do-not-touch").unwrap();
        let lock_path = lock_path_for(&target);
        unix_fs::symlink(&victim, &lock_path).unwrap();

        let err = match FileLock::acquire(&target) {
            Ok(_) => panic!("symlinked sentinel must be refused"),
            Err(err) => err,
        };
        // O_NOFOLLOW makes the open itself fail with ELOOP on most
        // platforms ("Too many levels of symbolic links" / os error 62).
        assert!(
            err.raw_os_error().is_some(),
            "expected an OS error from O_NOFOLLOW open, got: {err}"
        );
        // The victim must be untouched (no truncation).
        assert_eq!(std::fs::read(&victim).unwrap(), b"do-not-touch");
    }

    #[cfg(all(not(unix), not(windows)))]
    #[test]
    fn test_noop_lock_always_succeeds() {
        let dir = TempDir::new().unwrap();
        let target = dir.path().join("noop.json");
        std::fs::write(&target, b"").unwrap();

        let lock1 = FileLock::acquire(&target).unwrap();
        let lock2 = FileLock::try_acquire(&target).unwrap();
        assert!(lock2.is_some(), "no-op lock should always succeed");
        drop(lock1);
    }
}
