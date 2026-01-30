//! Deep health checks — diagnostics, `/health/live`, `/health/ready`.
//!
//! Provides system-level diagnostics (disk, memory, file descriptors, LLM
//! reachability) and readiness checks for container orchestrators.

use serde::Serialize;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use parking_lot::Mutex;

/// System-level diagnostics gathered on demand.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SystemDiagnostics {
    /// Whether the state directory is writable.
    pub storage_writable: bool,
    /// Free bytes on the filesystem containing the state directory.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disk_free_bytes: Option<u64>,
    /// Resident set size of this process, in bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_rss_bytes: Option<u64>,
    /// Number of open file descriptors.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub open_fds: Option<u64>,
    /// Whether the LLM provider is reachable.
    /// `None` if no provider is configured.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub llm_reachable: Option<bool>,
}

/// Gathers system diagnostics on demand.
pub struct HealthChecker {
    state_dir: PathBuf,
    llm_reachable_cache: Mutex<Option<(Instant, bool)>>,
}

/// LLM reachability cache TTL (30 seconds).
const LLM_CACHE_TTL_SECS: u64 = 30;

impl HealthChecker {
    /// Create a new health checker.
    pub fn new(state_dir: PathBuf) -> Self {
        Self {
            state_dir,
            llm_reachable_cache: Mutex::new(None),
        }
    }

    /// Gather all diagnostics. This is cheap — only the LLM reachability
    /// check involves a network call, and it is cached for 30s.
    pub fn gather_diagnostics(&self, has_llm: bool) -> SystemDiagnostics {
        let storage_writable = check_storage_writable(&self.state_dir);
        let disk_free_bytes = disk_free_bytes(&self.state_dir);
        let memory_rss_bytes = memory_rss_bytes();
        let open_fds = open_fd_count();

        let llm_reachable = if has_llm {
            // Use cached value if fresh enough
            let cache = self.llm_reachable_cache.lock();
            match cache.as_ref() {
                Some((ts, val)) if ts.elapsed().as_secs() < LLM_CACHE_TTL_SECS => Some(*val),
                _ => None, // will be populated by async caller
            }
        } else {
            None
        };

        SystemDiagnostics {
            storage_writable,
            disk_free_bytes,
            memory_rss_bytes,
            open_fds,
            llm_reachable,
        }
    }

    /// Update the cached LLM reachability result.
    pub fn set_llm_reachable(&self, reachable: bool) {
        let mut cache = self.llm_reachable_cache.lock();
        *cache = Some((Instant::now(), reachable));
    }

    /// Check if the system is ready (for readiness probes).
    ///
    /// Ready means storage is writable. If an LLM provider is configured,
    /// we also check cached reachability (but stale/missing cache is treated
    /// as ready to avoid false negatives).
    pub fn is_ready(&self, has_llm: bool) -> bool {
        let storage_ok = check_storage_writable(&self.state_dir);
        if !storage_ok {
            return false;
        }
        if has_llm {
            let cache = self.llm_reachable_cache.lock();
            if let Some((ts, reachable)) = cache.as_ref() {
                if ts.elapsed().as_secs() < LLM_CACHE_TTL_SECS && !reachable {
                    return false;
                }
            }
        }
        true
    }
}

/// Touch + remove a temp file to verify the state directory is writable.
pub fn check_storage_writable(state_dir: &Path) -> bool {
    let probe = state_dir.join(".health_probe");
    match std::fs::File::create(&probe) {
        Ok(_) => {
            let _ = std::fs::remove_file(&probe);
            true
        }
        Err(_) => false,
    }
}

/// Get free bytes on the filesystem containing `path`.
#[cfg(unix)]
pub fn disk_free_bytes(path: &Path) -> Option<u64> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let c_path = CString::new(path.as_os_str().as_bytes()).ok()?;
    unsafe {
        let mut stat: libc::statvfs = std::mem::zeroed();
        if libc::statvfs(c_path.as_ptr(), &mut stat) == 0 {
            #[allow(clippy::unnecessary_cast)]
            Some(stat.f_bavail as u64 * stat.f_frsize as u64)
        } else {
            None
        }
    }
}

#[cfg(not(unix))]
pub fn disk_free_bytes(_path: &Path) -> Option<u64> {
    None
}

/// Get the RSS (resident set size) of this process in bytes.
#[cfg(target_os = "macos")]
pub fn memory_rss_bytes() -> Option<u64> {
    // Use mach_task_info on macOS
    unsafe {
        #[allow(deprecated)]
        let task = libc::mach_task_self();
        let mut info: libc::mach_task_basic_info_data_t = std::mem::zeroed();
        let mut count = (std::mem::size_of::<libc::mach_task_basic_info_data_t>()
            / std::mem::size_of::<libc::natural_t>())
            as libc::mach_msg_type_number_t;
        let kr = libc::task_info(
            task,
            libc::MACH_TASK_BASIC_INFO,
            &mut info as *mut _ as libc::task_info_t,
            &mut count,
        );
        if kr == libc::KERN_SUCCESS {
            Some(info.resident_size)
        } else {
            None
        }
    }
}

#[cfg(target_os = "linux")]
pub fn memory_rss_bytes() -> Option<u64> {
    // Parse /proc/self/status for VmRSS
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            let kb_str = rest.trim().trim_end_matches(" kB").trim();
            let kb: u64 = kb_str.parse().ok()?;
            return Some(kb * 1024);
        }
    }
    None
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub fn memory_rss_bytes() -> Option<u64> {
    None
}

/// Count open file descriptors for this process.
#[cfg(target_os = "linux")]
pub fn open_fd_count() -> Option<u64> {
    std::fs::read_dir("/proc/self/fd")
        .ok()
        .map(|entries| entries.count() as u64)
}

#[cfg(target_os = "macos")]
pub fn open_fd_count() -> Option<u64> {
    // Use proc_pidinfo on macOS
    unsafe {
        let pid = libc::getpid();
        let buffer_size =
            libc::proc_pidinfo(pid, libc::PROC_PIDLISTFDS, 0, std::ptr::null_mut(), 0);
        if buffer_size <= 0 {
            return None;
        }
        let count = buffer_size as u64 / std::mem::size_of::<libc::proc_fdinfo>() as u64;
        Some(count)
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub fn open_fd_count() -> Option<u64> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_check_storage_writable_valid_dir() {
        let dir = TempDir::new().unwrap();
        assert!(check_storage_writable(dir.path()));
    }

    #[test]
    fn test_check_storage_writable_nonexistent() {
        let path = Path::new("/nonexistent/path/that/should/not/exist");
        assert!(!check_storage_writable(path));
    }

    #[test]
    fn test_disk_free_bytes_returns_some_for_tmp() {
        let dir = TempDir::new().unwrap();
        let result = disk_free_bytes(dir.path());
        // On Unix this should return Some; on Windows it may return None
        #[cfg(unix)]
        assert!(result.is_some());
        let _ = result; // avoid unused warning on non-unix
    }

    #[test]
    fn test_memory_rss_bytes_returns_something() {
        let result = memory_rss_bytes();
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        assert!(result.is_some(), "RSS should be available on this platform");
        let _ = result;
    }

    #[test]
    fn test_open_fd_count_returns_something() {
        let result = open_fd_count();
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        assert!(
            result.is_some(),
            "FD count should be available on this platform"
        );
        let _ = result;
    }

    #[test]
    fn test_health_checker_gather_diagnostics() {
        let dir = TempDir::new().unwrap();
        let checker = HealthChecker::new(dir.path().to_path_buf());
        let diag = checker.gather_diagnostics(false);
        assert!(diag.storage_writable);
        assert!(diag.llm_reachable.is_none());
    }

    #[test]
    fn test_health_checker_is_ready_no_llm() {
        let dir = TempDir::new().unwrap();
        let checker = HealthChecker::new(dir.path().to_path_buf());
        assert!(checker.is_ready(false));
    }

    #[test]
    fn test_health_checker_llm_cache() {
        let dir = TempDir::new().unwrap();
        let checker = HealthChecker::new(dir.path().to_path_buf());
        checker.set_llm_reachable(true);
        let diag = checker.gather_diagnostics(true);
        assert_eq!(diag.llm_reachable, Some(true));
        assert!(checker.is_ready(true));
    }

    #[test]
    fn test_health_checker_llm_unreachable() {
        let dir = TempDir::new().unwrap();
        let checker = HealthChecker::new(dir.path().to_path_buf());
        checker.set_llm_reachable(false);
        assert!(!checker.is_ready(true));
    }

    #[test]
    fn test_diagnostics_serialization() {
        let diag = SystemDiagnostics {
            storage_writable: true,
            disk_free_bytes: Some(1_000_000),
            memory_rss_bytes: Some(50_000_000),
            open_fds: Some(42),
            llm_reachable: None,
        };
        let json = serde_json::to_value(&diag).unwrap();
        assert_eq!(json["storageWritable"], true);
        assert_eq!(json["diskFreeBytes"], 1_000_000);
        // llm_reachable should be skipped when None
        assert!(json.get("llmReachable").is_none());
    }
}
