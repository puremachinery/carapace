//! OS-level sandboxing for tool subprocess execution.
//!
//! Provides resource limits (CPU time, memory, file descriptors) and platform-
//! specific process sandboxing for tool invocations that spawn subprocesses.
//!
//! ## Platform support
//!
//! - **macOS**: Uses `sandbox-exec` via a restrictive Seatbelt profile string
//!   and `setrlimit` for resource limits.
//! - **Linux**: Uses landlock (Linux 5.13+) for filesystem access control and
//!   `setrlimit` / `prctl` for resource limits.
//! - **Windows**: Uses Job Objects for process-level limits (CPU, memory,
//!   process-count) and command allowlisting against configured path roots.
//!   Network deny mode (`network_access=false`) is not yet enforceable and
//!   fails closed in support checks.
//! - **Other**: Unsupported for sandbox-required subprocess paths (fail-closed).
//!
//! ## Configuration
//!
//! Controlled via `agent.sandbox.*` keys in config:
//!
//! ```json5
//! {
//!   agent: {
//!     sandbox: {
//!       enabled: true,
//!       max_cpu_seconds: 30,
//!       max_memory_mb: 512,
//!       max_fds: 256,
//!       allowed_paths: ["/tmp", "/usr/bin"],
//!       network_access: false,
//!     }
//!   }
//! }
//! ```

use serde::{Deserialize, Serialize};
use serde_json::Value;
#[cfg(unix)]
use std::os::unix::process::CommandExt;
#[cfg(windows)]
use std::os::windows::io::AsRawHandle;
#[cfg(not(target_os = "windows"))]
use std::path::PathBuf;
#[cfg(target_os = "windows")]
use std::path::{Path, PathBuf};
#[cfg(windows)]
use std::process::Stdio;
use std::process::{Command, Output};
#[cfg(windows)]
use win32job::Job;
#[cfg(target_os = "windows")]
use windows_sys::Win32::Foundation::HANDLE;
#[cfg(target_os = "windows")]
use windows_sys::Win32::System::JobObjects::{
    JobObjectExtendedLimitInformation, SetInformationJobObject,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_ACTIVE_PROCESS,
    JOB_OBJECT_LIMIT_PROCESS_MEMORY, JOB_OBJECT_LIMIT_PROCESS_TIME, JOB_OBJECT_LIMIT_WORKINGSET,
};

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Sandbox configuration for tool subprocess execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessSandboxConfig {
    /// Master switch -- when `false`, sandboxing is skipped entirely.
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Maximum CPU time in seconds per tool invocation.
    #[serde(default = "default_max_cpu_seconds")]
    pub max_cpu_seconds: u64,

    /// Maximum virtual memory in megabytes per tool invocation.
    #[serde(default = "default_max_memory_mb")]
    pub max_memory_mb: u64,

    /// Maximum number of open file descriptors per tool invocation.
    #[serde(default = "default_max_fds")]
    pub max_fds: u64,

    /// Filesystem paths the sandboxed process is allowed to access.
    /// On macOS these are added to the Seatbelt profile as readable paths.
    /// On Linux these are added to the landlock ruleset.
    #[serde(default = "default_allowed_paths")]
    pub allowed_paths: Vec<String>,

    /// Whether the sandboxed process may access the network.
    #[serde(default)]
    pub network_access: bool,

    /// Environment variable filter: only these variables are passed through
    /// to the child process.  Empty list means pass all (no filtering).
    #[serde(default)]
    pub env_filter: Vec<String>,
}

fn default_true() -> bool {
    true
}
fn default_max_cpu_seconds() -> u64 {
    30
}
fn default_max_memory_mb() -> u64 {
    512
}
fn default_max_fds() -> u64 {
    256
}
fn default_allowed_paths() -> Vec<String> {
    vec![
        "/tmp".to_string(),
        "/usr/bin".to_string(),
        "/usr/local/bin".to_string(),
        "/bin".to_string(),
    ]
}

fn push_unique_path(paths: &mut Vec<String>, path: &str) {
    if !paths.iter().any(|p| p == path) {
        paths.push(path.to_string());
    }
}

#[cfg(target_os = "macos")]
fn default_probe_allowed_paths() -> Vec<String> {
    vec![
        "/tmp".to_string(),
        "/private/tmp".to_string(),
        "/bin".to_string(),
        "/usr/bin".to_string(),
        "/usr/local/bin".to_string(),
        "/sbin".to_string(),
        "/usr/sbin".to_string(),
        "/usr/lib".to_string(),
        "/etc".to_string(),
        "/System".to_string(),
        "/Library".to_string(),
        "/private/var".to_string(),
    ]
}

#[cfg(target_os = "linux")]
fn default_probe_allowed_paths() -> Vec<String> {
    vec![
        "/tmp".to_string(),
        "/bin".to_string(),
        "/usr/bin".to_string(),
        "/usr/local/bin".to_string(),
        "/sbin".to_string(),
        "/usr/sbin".to_string(),
        "/usr/lib".to_string(),
        "/lib".to_string(),
        "/lib64".to_string(),
        "/etc".to_string(),
        "/proc".to_string(),
    ]
}

#[cfg(target_os = "windows")]
fn default_probe_allowed_paths() -> Vec<String> {
    vec![
        r"C:\Windows".to_string(),
        r"C:\Windows\System32".to_string(),
        r"C:\Windows\System32\WindowsPowerShell\v1.0".to_string(),
    ]
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
fn default_probe_allowed_paths() -> Vec<String> {
    default_allowed_paths()
}

fn default_tailscale_allowed_paths() -> Vec<String> {
    let mut paths = default_probe_allowed_paths();

    #[cfg(target_os = "linux")]
    {
        // On many Linux systems, /var/run is a symlink to /run. Keep both
        // to avoid distro-specific path assumptions.
        push_unique_path(&mut paths, "/run");
        push_unique_path(&mut paths, "/var/run");
    }

    #[cfg(target_os = "macos")]
    {
        // Tailscale CLI may need daemon IPC paths on Unix hosts.
        push_unique_path(&mut paths, "/var/run");
    }

    #[cfg(target_os = "windows")]
    {
        push_unique_path(&mut paths, r"C:\Program Files\Tailscale");
        push_unique_path(&mut paths, r"C:\Program Files (x86)\Tailscale");
    }

    // On non-Unix targets, this returns probe defaults unchanged.
    paths
}

fn default_ssh_tunnel_allowed_paths() -> Vec<String> {
    let mut paths = default_tailscale_allowed_paths();

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        push_unique_path(&mut paths, "/dev");

        if let Some(home) = std::env::var("HOME").ok().filter(|home| !home.is_empty()) {
            push_unique_path(&mut paths, &home);
            let ssh_dir = format!("{home}/.ssh");
            push_unique_path(&mut paths, &ssh_dir);
        }
    }

    #[cfg(target_os = "windows")]
    {
        push_unique_path(&mut paths, r"C:\Windows\System32\OpenSSH");
        if let Some(home) = std::env::var("USERPROFILE")
            .ok()
            .filter(|home| !home.is_empty())
        {
            push_unique_path(&mut paths, &home);
            let ssh_dir = format!(r"{home}\.ssh");
            push_unique_path(&mut paths, &ssh_dir);
        }
    }

    paths
}

/// Build a conservative sandbox profile for short-lived runtime probe commands.
///
/// Intended for low-risk helper subprocesses such as `hostname`, `route`,
/// `ifconfig`, and `ip` that only need local filesystem visibility and no
/// outbound networking.
pub fn default_probe_sandbox_config() -> ProcessSandboxConfig {
    ProcessSandboxConfig {
        enabled: true,
        max_cpu_seconds: 5,
        max_memory_mb: 128,
        max_fds: 64,
        allowed_paths: default_probe_allowed_paths(),
        network_access: false,
        env_filter: Vec::new(),
    }
}

/// Build a sandbox profile for Tailscale CLI helper subprocesses.
///
/// This profile is less restrictive than `default_probe_sandbox_config()`
/// because `tailscale` commands may need local daemon IPC paths and localhost
/// networking to communicate with tailscaled.
pub fn default_tailscale_cli_sandbox_config() -> ProcessSandboxConfig {
    ProcessSandboxConfig {
        enabled: true,
        max_cpu_seconds: 10,
        max_memory_mb: 256,
        max_fds: 128,
        allowed_paths: default_tailscale_allowed_paths(),
        network_access: true,
        env_filter: Vec::new(),
    }
}

/// Build a sandbox profile for long-lived SSH tunnel subprocesses.
///
/// This profile permits outbound networking and read access to typical SSH
/// config/key paths while still applying process-level limits.
pub fn default_ssh_tunnel_sandbox_config() -> ProcessSandboxConfig {
    ProcessSandboxConfig {
        enabled: true,
        max_cpu_seconds: 300,
        max_memory_mb: 256,
        max_fds: 256,
        allowed_paths: default_ssh_tunnel_allowed_paths(),
        network_access: true,
        env_filter: Vec::new(),
    }
}

impl Default for ProcessSandboxConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_cpu_seconds: default_max_cpu_seconds(),
            max_memory_mb: default_max_memory_mb(),
            max_fds: default_max_fds(),
            allowed_paths: default_allowed_paths(),
            network_access: false,
            env_filter: Vec::new(),
        }
    }
}

impl ProcessSandboxConfig {
    /// Parse a `ProcessSandboxConfig` from a JSON config value.
    ///
    /// Expects an object shaped like:
    /// ```json
    /// { "enabled": true, "max_cpu_seconds": 30, "max_memory_mb": 512, ... }
    /// ```
    ///
    /// Returns the default config for `None` or non-object values.
    pub fn from_config(value: Option<&Value>) -> Self {
        match value {
            Some(v) => serde_json::from_value(v.clone()).unwrap_or_default(),
            None => Self::default(),
        }
    }

    /// Maximum memory in bytes (derived from `max_memory_mb`).
    pub fn max_memory_bytes(&self) -> u64 {
        self.max_memory_mb.saturating_mul(1024 * 1024)
    }

    /// Return the allowed paths as `PathBuf` values.
    pub fn allowed_path_bufs(&self) -> Vec<PathBuf> {
        self.allowed_paths.iter().map(PathBuf::from).collect()
    }
}

// ---------------------------------------------------------------------------
// Resource limits (cross-platform via libc)
// ---------------------------------------------------------------------------

/// Errors that can occur when applying sandbox constraints.
#[derive(Debug, thiserror::Error)]
pub enum SandboxError {
    #[error("failed to set resource limit {resource}: {detail}")]
    ResourceLimit { resource: String, detail: String },

    #[error("platform sandbox error: {0}")]
    Platform(String),

    #[error("sandbox not supported on this platform")]
    Unsupported,
}

/// Apply resource limits (RLIMIT_CPU, RLIMIT_AS, RLIMIT_NOFILE) to the
/// current process.
///
/// This is intended to be called in a child process before `exec`.
/// On non-Unix platforms this is a no-op.
#[cfg(unix)]
pub fn apply_resource_limits(config: &ProcessSandboxConfig) -> Result<(), SandboxError> {
    // RLIMIT_CPU -- max CPU seconds
    set_rlimit(libc::RLIMIT_CPU, config.max_cpu_seconds)?;

    // RLIMIT_AS -- max virtual memory (bytes).
    // Best-effort: macOS does not support setrlimit for RLIMIT_AS and
    // returns EINVAL regardless of the values passed.
    if let Err(e) = set_rlimit(libc::RLIMIT_AS, config.max_memory_bytes()) {
        tracing::debug!("RLIMIT_AS not supported on this platform: {e}");
    }

    // RLIMIT_NOFILE -- max open file descriptors
    set_rlimit(libc::RLIMIT_NOFILE, config.max_fds)?;

    Ok(())
}

/// Resource type alias — `c_int` on macOS/BSDs, `__rlimit_resource_t` (u32) on Linux glibc.
#[cfg(target_os = "linux")]
type RlimitResource = libc::__rlimit_resource_t;
#[cfg(all(unix, not(target_os = "linux")))]
type RlimitResource = libc::c_int;

#[cfg(unix)]
fn set_rlimit(resource: RlimitResource, limit: u64) -> Result<(), SandboxError> {
    // Get current limits so we can respect the existing hard limit.
    // Unprivileged processes cannot raise the hard limit.
    let mut current = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    let ret = unsafe { libc::getrlimit(resource, &mut current) };
    if ret != 0 {
        let errno = std::io::Error::last_os_error();
        return Err(SandboxError::ResourceLimit {
            resource: rlimit_name(resource).to_string(),
            detail: format!("getrlimit failed: {errno}"),
        });
    }

    let requested = limit as libc::rlim_t;
    let hard = current.rlim_max;

    // Set soft limit to the requested value (capped at hard limit).
    // Leave hard limit unchanged to avoid EINVAL on macOS / non-root.
    let rlim = libc::rlimit {
        rlim_cur: if hard == libc::RLIM_INFINITY || requested < hard {
            requested
        } else {
            hard
        },
        rlim_max: hard,
    };
    let ret = unsafe { libc::setrlimit(resource, &rlim) };
    if ret != 0 {
        let errno = std::io::Error::last_os_error();
        return Err(SandboxError::ResourceLimit {
            resource: rlimit_name(resource).to_string(),
            detail: errno.to_string(),
        });
    }
    Ok(())
}

#[cfg(unix)]
fn rlimit_name(resource: RlimitResource) -> &'static str {
    match resource {
        libc::RLIMIT_CPU => "RLIMIT_CPU",
        libc::RLIMIT_AS => "RLIMIT_AS",
        libc::RLIMIT_NOFILE => "RLIMIT_NOFILE",
        _ => "RLIMIT_UNKNOWN",
    }
}

#[cfg(not(unix))]
pub fn apply_resource_limits(_config: &ProcessSandboxConfig) -> Result<(), SandboxError> {
    tracing::warn!("resource limits are not supported on this platform");
    Ok(())
}

// ---------------------------------------------------------------------------
// macOS: sandbox-exec (Seatbelt) profile
// ---------------------------------------------------------------------------

/// Build a macOS Seatbelt sandbox profile string.
///
/// The profile denies everything by default, then selectively allows:
/// - Reading from `allowed_paths`
/// - Process execution
/// - Writing to `/tmp` and `/dev/null`
/// - Optionally network access
#[cfg(target_os = "macos")]
pub fn build_seatbelt_profile(config: &ProcessSandboxConfig) -> String {
    let mut profile = String::from("(version 1)\n(deny default)\n");

    // Always allow basic process execution
    profile.push_str("(allow process-exec)\n");
    profile.push_str("(allow process-fork)\n");
    profile.push_str("(allow sysctl-read)\n");
    profile.push_str("(allow mach-lookup)\n");

    // Allow reading from allowed paths
    for path in &config.allowed_paths {
        profile.push_str(&format!(
            "(allow file-read* (subpath \"{}\"))\n",
            escape_seatbelt_path(path)
        ));
    }

    // Allow writing to /tmp and /dev/null (common tool requirements)
    profile.push_str("(allow file-write* (subpath \"/tmp\"))\n");
    profile.push_str("(allow file-write* (subpath \"/private/tmp\"))\n");
    profile.push_str("(allow file-write* (literal \"/dev/null\"))\n");
    profile.push_str("(allow file-read* (subpath \"/dev\"))\n");

    // Allow reading standard system paths required for dynamic linking
    profile.push_str("(allow file-read* (subpath \"/usr/lib\"))\n");
    profile.push_str("(allow file-read* (subpath \"/System\"))\n");
    profile.push_str("(allow file-read* (subpath \"/Library\"))\n");
    profile.push_str("(allow file-read* (subpath \"/private/var\"))\n");

    // Network access
    if config.network_access {
        profile.push_str("(allow network*)\n");
    } else {
        // Allow localhost only (for IPC)
        profile.push_str("(allow network* (local ip \"localhost:*\"))\n");
    }

    profile
}

#[cfg(target_os = "macos")]
fn escape_seatbelt_path(path: &str) -> String {
    // Seatbelt profile paths use forward slashes; escape quotes
    path.replace('\\', "/").replace('"', "\\\"")
}

/// Apply macOS sandbox profile via `sandbox-exec -p <profile>` wrapper.
///
/// In production, this wraps the child command with `sandbox-exec -p <profile>`.
/// Returns the command prefix arguments to prepend to the subprocess invocation.
#[cfg(target_os = "macos")]
pub fn macos_sandbox_command_prefix(config: &ProcessSandboxConfig) -> Vec<String> {
    if !config.enabled {
        return Vec::new();
    }
    let profile = build_seatbelt_profile(config);
    vec!["sandbox-exec".to_string(), "-p".to_string(), profile]
}

// ---------------------------------------------------------------------------
// Windows: Job Objects
// ---------------------------------------------------------------------------

#[cfg(target_os = "windows")]
fn windows_working_set_limits(config: &ProcessSandboxConfig) -> (usize, usize) {
    let max = usize::try_from(config.max_memory_bytes()).unwrap_or(usize::MAX);
    let min = (1024 * 1024).min(max);
    (min, max.max(min))
}

#[cfg(target_os = "windows")]
fn windows_cpu_time_limit_100ns(config: &ProcessSandboxConfig) -> i64 {
    let ticks = config.max_cpu_seconds.saturating_mul(10_000_000);
    i64::try_from(ticks).unwrap_or(i64::MAX)
}

#[cfg(target_os = "windows")]
fn windows_active_process_limit(config: &ProcessSandboxConfig) -> u32 {
    // Windows does not expose an RLIMIT_NOFILE equivalent; map this setting
    // to a process-count cap so the sandbox still constrains process fan-out.
    u32::try_from(config.max_fds).unwrap_or(u32::MAX).max(1)
}

#[cfg(target_os = "windows")]
fn configure_windows_job_limits(
    job: &Job,
    config: &ProcessSandboxConfig,
) -> Result<(), SandboxError> {
    let (min_working_set, max_working_set) = windows_working_set_limits(config);
    let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = JOBOBJECT_EXTENDED_LIMIT_INFORMATION {
        BasicLimitInformation: Default::default(),
        IoInfo: Default::default(),
        ProcessMemoryLimit: 0,
        JobMemoryLimit: 0,
        PeakProcessMemoryUsed: 0,
        PeakJobMemoryUsed: 0,
    };

    info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_WORKINGSET
        | JOB_OBJECT_LIMIT_PROCESS_MEMORY
        | JOB_OBJECT_LIMIT_PROCESS_TIME
        | JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
    info.BasicLimitInformation.MinimumWorkingSetSize = min_working_set;
    info.BasicLimitInformation.MaximumWorkingSetSize = max_working_set;
    info.BasicLimitInformation.PerProcessUserTimeLimit = windows_cpu_time_limit_100ns(config);
    info.BasicLimitInformation.ActiveProcessLimit = windows_active_process_limit(config);
    info.ProcessMemoryLimit = usize::try_from(config.max_memory_bytes()).unwrap_or(usize::MAX);

    let ret = unsafe {
        SetInformationJobObject(
            job.handle() as HANDLE,
            JobObjectExtendedLimitInformation,
            &info as *const _ as *const std::ffi::c_void,
            std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        )
    };
    if ret == 0 {
        return Err(SandboxError::Platform(format!(
            "failed to configure Windows job object limits: {}",
            std::io::Error::last_os_error()
        )));
    }

    Ok(())
}

#[cfg(target_os = "windows")]
fn create_windows_job(config: &ProcessSandboxConfig) -> Result<Job, SandboxError> {
    let job = Job::create()
        .map_err(|e| SandboxError::Platform(format!("failed to create Windows job object: {e}")))?;
    configure_windows_job_limits(&job, config)?;
    Ok(job)
}

#[cfg(target_os = "windows")]
fn windows_job_objects_available(config: &ProcessSandboxConfig) -> Result<(), SandboxError> {
    let _ = create_windows_job(config)?;
    Ok(())
}

#[cfg(target_os = "windows")]
fn normalize_windows_path(path: &Path) -> String {
    let mut normalized = path
        .to_string_lossy()
        .replace('/', "\\")
        .to_ascii_lowercase();
    while normalized.ends_with('\\') && normalized.len() > 3 {
        normalized.pop();
    }
    normalized
}

#[cfg(target_os = "windows")]
fn canonicalize_windows_path(path: &Path) -> PathBuf {
    std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

#[cfg(target_os = "windows")]
fn resolve_windows_executable(program: &str) -> Option<PathBuf> {
    let program_path = Path::new(program);
    if program_path.components().count() > 1 || program_path.is_absolute() {
        if program_path.is_file() {
            return Some(canonicalize_windows_path(program_path));
        }
        return None;
    }

    let has_extension = program_path.extension().is_some();
    let default_exts = ".COM;.EXE;.BAT;.CMD".to_string();
    let path_exts = std::env::var("PATHEXT").unwrap_or(default_exts);
    let path_exts: Vec<String> = path_exts
        .split(';')
        .filter(|ext| !ext.is_empty())
        .map(|ext| ext.to_ascii_lowercase())
        .collect();

    let path_var = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_var) {
        if has_extension {
            let candidate = dir.join(program);
            if candidate.is_file() {
                return Some(canonicalize_windows_path(&candidate));
            }
            continue;
        }

        for ext in &path_exts {
            let candidate = dir.join(format!("{program}{ext}"));
            if candidate.is_file() {
                return Some(canonicalize_windows_path(&candidate));
            }
        }
    }

    None
}

#[cfg(target_os = "windows")]
fn validate_windows_allowed_program(
    program: &str,
    config: &ProcessSandboxConfig,
) -> std::io::Result<()> {
    if config.allowed_paths.is_empty() {
        return Ok(());
    }

    let resolved = resolve_windows_executable(program).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("unable to resolve Windows executable path for '{program}'"),
        )
    })?;
    let resolved_norm = normalize_windows_path(&resolved);

    let allowed = config.allowed_paths.iter().any(|root| {
        let root_path = canonicalize_windows_path(Path::new(root));
        let root_norm = normalize_windows_path(&root_path);
        resolved_norm == root_norm || resolved_norm.starts_with(&(root_norm + "\\"))
    });

    if !allowed {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "program '{}' resolved to '{}' outside sandbox allowed_paths",
                program,
                resolved.display()
            ),
        ));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Linux: landlock filesystem access control
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
fn probe_landlock_abi_version() -> Result<u32, SandboxError> {
    // landlock syscall constants.
    const LANDLOCK_CREATE_RULESET: libc::c_long = 444;
    const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1;

    let abi_version_raw = unsafe {
        libc::syscall(
            LANDLOCK_CREATE_RULESET,
            std::ptr::null::<libc::c_void>(),
            0usize,
            LANDLOCK_CREATE_RULESET_VERSION,
        )
    };
    if abi_version_raw < 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::ENOSYS) || err.raw_os_error() == Some(libc::EOPNOTSUPP)
        {
            return Err(SandboxError::Unsupported);
        }
        return Err(SandboxError::Platform(format!(
            "landlock ABI query failed: {err}"
        )));
    }

    Ok(abi_version_raw as u32)
}

#[cfg(target_os = "linux")]
fn validate_landlock_abi_support(
    abi_version: u32,
    config: &ProcessSandboxConfig,
) -> Result<(), SandboxError> {
    if abi_version == 0 {
        return Err(SandboxError::Unsupported);
    }
    if !config.network_access && abi_version < 4 {
        return Err(SandboxError::Platform(format!(
            "landlock ABI v4+ required when network_access=false (detected v{abi_version})"
        )));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
unsafe fn create_landlock_ruleset(attr_ptr: *const libc::c_void, attr_size: usize) -> libc::c_int {
    const LANDLOCK_CREATE_RULESET: libc::c_long = 444;
    libc::syscall(LANDLOCK_CREATE_RULESET, attr_ptr, attr_size, 0u32) as libc::c_int
}

#[cfg(target_os = "macos")]
fn macos_seatbelt_available() -> bool {
    use std::path::Path;

    if Path::new("/usr/bin/sandbox-exec").is_file() {
        return true;
    }

    std::env::var_os("PATH").is_some_and(|paths| {
        std::env::split_paths(&paths).any(|dir| dir.join("sandbox-exec").is_file())
    })
}

/// Apply landlock restrictions on Linux.
///
/// Uses landlock ABI v1+ (Linux 5.13+) for filesystem restrictions and
/// landlock ABI v4+ (Linux 6.2+) to enforce deny-by-default TCP
/// connect/bind when `network_access` is disabled.
///
/// This path is fail-closed: unsupported kernels return `SandboxError::Unsupported`.
#[cfg(target_os = "linux")]
pub fn apply_landlock(config: &ProcessSandboxConfig) -> Result<(), SandboxError> {
    // Landlock syscall constants.
    const LANDLOCK_ADD_RULE: libc::c_long = 445;
    const LANDLOCK_RESTRICT_SELF: libc::c_long = 446;

    const LANDLOCK_RULE_PATH_BENEATH: u32 = 1;

    // Filesystem access rights (ABI v1).
    const LANDLOCK_ACCESS_FS_EXECUTE: u64 = 1 << 0;
    const LANDLOCK_ACCESS_FS_WRITE_FILE: u64 = 1 << 1;
    const LANDLOCK_ACCESS_FS_READ_FILE: u64 = 1 << 2;
    const LANDLOCK_ACCESS_FS_READ_DIR: u64 = 1 << 3;
    const LANDLOCK_ACCESS_FS_REMOVE_DIR: u64 = 1 << 4;
    const LANDLOCK_ACCESS_FS_REMOVE_FILE: u64 = 1 << 5;
    const LANDLOCK_ACCESS_FS_MAKE_CHAR: u64 = 1 << 6;
    const LANDLOCK_ACCESS_FS_MAKE_DIR: u64 = 1 << 7;
    const LANDLOCK_ACCESS_FS_MAKE_REG: u64 = 1 << 8;
    const LANDLOCK_ACCESS_FS_MAKE_SOCK: u64 = 1 << 9;
    const LANDLOCK_ACCESS_FS_MAKE_FIFO: u64 = 1 << 10;
    const LANDLOCK_ACCESS_FS_MAKE_BLOCK: u64 = 1 << 11;
    const LANDLOCK_ACCESS_FS_MAKE_SYM: u64 = 1 << 12;

    const ALL_ACCESS: u64 = LANDLOCK_ACCESS_FS_EXECUTE
        | LANDLOCK_ACCESS_FS_WRITE_FILE
        | LANDLOCK_ACCESS_FS_READ_FILE
        | LANDLOCK_ACCESS_FS_READ_DIR
        | LANDLOCK_ACCESS_FS_REMOVE_DIR
        | LANDLOCK_ACCESS_FS_REMOVE_FILE
        | LANDLOCK_ACCESS_FS_MAKE_CHAR
        | LANDLOCK_ACCESS_FS_MAKE_DIR
        | LANDLOCK_ACCESS_FS_MAKE_REG
        | LANDLOCK_ACCESS_FS_MAKE_SOCK
        | LANDLOCK_ACCESS_FS_MAKE_FIFO
        | LANDLOCK_ACCESS_FS_MAKE_BLOCK
        | LANDLOCK_ACCESS_FS_MAKE_SYM;

    const READ_EXECUTE: u64 =
        LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR;

    // Network access rights (ABI v4).
    const LANDLOCK_ACCESS_NET_BIND_TCP: u64 = 1 << 0;
    const LANDLOCK_ACCESS_NET_CONNECT_TCP: u64 = 1 << 1;
    const HANDLED_NET_ACCESS: u64 = LANDLOCK_ACCESS_NET_BIND_TCP | LANDLOCK_ACCESS_NET_CONNECT_TCP;

    // landlock_ruleset_attr (ABI v1)
    #[repr(C)]
    struct RulesetAttrV1 {
        handled_access_fs: u64,
    }

    // landlock_ruleset_attr (ABI v4+)
    #[repr(C)]
    struct RulesetAttrV4 {
        handled_access_fs: u64,
        handled_access_net: u64,
    }

    // landlock_path_beneath_attr
    #[repr(C)]
    struct PathBeneathAttr {
        allowed_access: u64,
        parent_fd: libc::c_int,
    }

    use std::os::unix::io::RawFd;

    let abi_version = probe_landlock_abi_version()?;

    validate_landlock_abi_support(abi_version, config)?;

    enum RulesetAttr {
        V1(RulesetAttrV1),
        V4(RulesetAttrV4),
    }

    let attr = if config.network_access {
        RulesetAttr::V1(RulesetAttrV1 {
            handled_access_fs: ALL_ACCESS,
        })
    } else {
        RulesetAttr::V4(RulesetAttrV4 {
            handled_access_fs: ALL_ACCESS,
            // With no allow-rules for net ports, this denies TCP bind/connect.
            handled_access_net: HANDLED_NET_ACCESS,
        })
    };

    let (attr_ptr, attr_size) = match &attr {
        RulesetAttr::V1(v1) => (
            v1 as *const _ as *const libc::c_void,
            std::mem::size_of::<RulesetAttrV1>(),
        ),
        RulesetAttr::V4(v4) => (
            v4 as *const _ as *const libc::c_void,
            std::mem::size_of::<RulesetAttrV4>(),
        ),
    };
    let ruleset_fd: RawFd = unsafe { create_landlock_ruleset(attr_ptr, attr_size) } as RawFd;

    if ruleset_fd < 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::ENOSYS) || err.raw_os_error() == Some(libc::EOPNOTSUPP)
        {
            return Err(SandboxError::Unsupported);
        }
        return Err(SandboxError::Platform(format!(
            "landlock_create_ruleset failed: {err}"
        )));
    }

    // Add rules for allowed paths
    for path_str in &config.allowed_paths {
        let c_path = match std::ffi::CString::new(path_str.as_str()) {
            Ok(p) => p,
            Err(_) => continue, // skip paths with null bytes
        };
        let fd = unsafe { libc::open(c_path.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
        if fd < 0 {
            // Path doesn't exist -- skip (not an error)
            tracing::debug!(path = %path_str, "landlock: skipping non-existent path");
            continue;
        }

        let rule = PathBeneathAttr {
            allowed_access: READ_EXECUTE,
            parent_fd: fd,
        };
        let ret = unsafe {
            libc::syscall(
                LANDLOCK_ADD_RULE,
                ruleset_fd,
                LANDLOCK_RULE_PATH_BENEATH,
                &rule as *const PathBeneathAttr,
                0u32,
            )
        };
        unsafe { libc::close(fd) };

        if ret < 0 {
            let err = std::io::Error::last_os_error();
            tracing::warn!(path = %path_str, error = %err, "landlock: failed to add rule");
        }
    }

    // Add /tmp with write access
    {
        let tmp_path = std::ffi::CString::new("/tmp").unwrap();
        let fd = unsafe { libc::open(tmp_path.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
        if fd >= 0 {
            let rule = PathBeneathAttr {
                allowed_access: ALL_ACCESS, // full access to /tmp
                parent_fd: fd,
            };
            unsafe {
                libc::syscall(
                    LANDLOCK_ADD_RULE,
                    ruleset_fd,
                    LANDLOCK_RULE_PATH_BENEATH,
                    &rule as *const PathBeneathAttr,
                    0u32,
                );
                libc::close(fd);
            }
        }
    }

    // Add /dev/null with read/write access for stdio redirection.
    {
        let dev_null_path = std::ffi::CString::new("/dev/null").unwrap();
        let fd = unsafe { libc::open(dev_null_path.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
        if fd >= 0 {
            let rule = PathBeneathAttr {
                allowed_access: LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_WRITE_FILE,
                parent_fd: fd,
            };
            unsafe {
                libc::syscall(
                    LANDLOCK_ADD_RULE,
                    ruleset_fd,
                    LANDLOCK_RULE_PATH_BENEATH,
                    &rule as *const PathBeneathAttr,
                    0u32,
                );
                libc::close(fd);
            }
        }
    }

    // Enforce the ruleset (no_new_privs required)
    let ret = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if ret < 0 {
        unsafe { libc::close(ruleset_fd) };
        let err = std::io::Error::last_os_error();
        return Err(SandboxError::Platform(format!(
            "prctl(PR_SET_NO_NEW_PRIVS) failed: {err}"
        )));
    }

    let ret = unsafe { libc::syscall(LANDLOCK_RESTRICT_SELF, ruleset_fd, 0u32) };
    unsafe { libc::close(ruleset_fd) };

    if ret < 0 {
        let err = std::io::Error::last_os_error();
        return Err(SandboxError::Platform(format!(
            "landlock_restrict_self failed: {err}"
        )));
    }

    tracing::debug!(
        abi = abi_version,
        paths = config.allowed_paths.len(),
        network_access = config.network_access,
        "landlock sandbox applied"
    );
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn apply_landlock(_config: &ProcessSandboxConfig) -> Result<(), SandboxError> {
    // landlock is Linux-only; no-op on other platforms
    Ok(())
}

// ---------------------------------------------------------------------------
// Unified sandbox application
// ---------------------------------------------------------------------------

/// Apply all available sandbox constraints for the current platform.
///
/// This function is intended to be called in a child process (e.g., via
/// `Command::pre_exec`) before the actual command is executed.
///
/// On macOS: resource limits only (Seatbelt is applied via command prefix).
/// On Linux: resource limits + landlock.
pub fn apply_sandbox(config: &ProcessSandboxConfig) -> Result<(), SandboxError> {
    if !config.enabled {
        tracing::debug!("process sandbox is disabled");
        return Ok(());
    }

    tracing::debug!(
        max_cpu_seconds = config.max_cpu_seconds,
        max_memory_mb = config.max_memory_mb,
        max_fds = config.max_fds,
        network_access = config.network_access,
        "applying process sandbox"
    );

    // Apply resource limits on all Unix platforms
    apply_resource_limits(config)?;

    // Apply platform-specific sandbox
    #[cfg(target_os = "linux")]
    apply_landlock(config)?;

    // On macOS, Seatbelt is applied via the command prefix (sandbox-exec),
    // not via in-process calls. Resource limits are sufficient here.

    Ok(())
}

/// Ensure the configured sandbox can be meaningfully enforced on this target.
///
/// Returns `SandboxError::Unsupported` when sandboxing is enabled on targets
/// without implemented OS-level process isolation backends.
pub fn ensure_sandbox_supported(config: Option<&ProcessSandboxConfig>) -> Result<(), SandboxError> {
    let Some(config) = config.filter(|cfg| cfg.enabled) else {
        return Ok(());
    };

    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    let _ = config;

    #[cfg(target_os = "linux")]
    {
        let abi_version = probe_landlock_abi_version()?;
        validate_landlock_abi_support(abi_version, config)
    }

    #[cfg(target_os = "macos")]
    {
        if !macos_seatbelt_available() {
            return Err(SandboxError::Platform(
                "sandbox-exec not found; cannot enforce macOS Seatbelt sandbox".to_string(),
            ));
        }
        Ok(())
    }

    #[cfg(target_os = "windows")]
    {
        if !config.network_access {
            return Err(SandboxError::Platform(
                "Windows sandbox backend does not yet enforce network_access=false".to_string(),
            ));
        }
        windows_job_objects_available(config)
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        Err(SandboxError::Unsupported)
    }
}

/// Build the command wrapper for sandboxed execution.
///
/// Returns `None` if no command prefix is needed (Linux uses in-process
/// sandboxing; other platforms may not have a wrapper).
pub fn sandbox_command_prefix(config: &ProcessSandboxConfig) -> Option<Vec<String>> {
    if !config.enabled {
        return None;
    }

    #[cfg(target_os = "macos")]
    {
        let prefix = macos_sandbox_command_prefix(config);
        if prefix.is_empty() {
            None
        } else {
            Some(prefix)
        }
    }

    #[cfg(not(target_os = "macos"))]
    {
        None
    }
}

/// Build argv for a subprocess with optional sandbox wrapping.
///
/// On macOS with sandboxing enabled this prepends `sandbox-exec -p <profile>`
/// and then appends the target program + args. On other platforms (or when
/// sandboxing is disabled), this returns the original program + args.
pub fn sandbox_command_argv(
    program: &str,
    args: &[&str],
    config: Option<&ProcessSandboxConfig>,
) -> Vec<String> {
    let mut argv = Vec::new();
    if let Some(prefix) = config
        .filter(|cfg| cfg.enabled)
        .and_then(sandbox_command_prefix)
    {
        argv.extend(prefix);
    }
    argv.push(program.to_string());
    argv.extend(args.iter().map(|arg| (*arg).to_string()));
    argv
}

/// Apply common sandbox command configuration to a child command.
///
/// This applies environment filtering (when configured) and, on Unix,
/// installs a `pre_exec` hook to enforce in-child sandbox constraints such as
/// rlimits and Linux landlock.
fn configure_sandboxed_command(cmd: &mut Command, config: Option<&ProcessSandboxConfig>) {
    let Some(cfg) = config.filter(|cfg| cfg.enabled) else {
        return;
    };

    if !cfg.env_filter.is_empty() {
        cmd.env_clear();
        for var in &cfg.env_filter {
            if let Ok(value) = std::env::var(var) {
                cmd.env(var, value);
            }
        }
    }

    #[cfg(unix)]
    {
        let cfg = cfg.clone();
        // SAFETY: `pre_exec` runs in the child process immediately before
        // exec. The closure only applies deterministic sandbox setup and
        // returns an IO error on failure.
        unsafe {
            cmd.pre_exec(move || {
                apply_sandbox(&cfg).map_err(|e| std::io::Error::other(e.to_string()))?;
                Ok(())
            });
        }
    }
}

/// Build a standard-library command with optional sandbox wrapping.
///
/// This helper centralizes subprocess sandbox setup for runtime call sites.
///
/// Platform behavior:
/// - macOS: prepends `sandbox-exec -p <profile>` when sandboxing is enabled
/// - Linux: no prefix (sandbox is applied via in-child `pre_exec`)
/// - Other: no prefix
/// - When configured, applies `env_filter` before spawning
pub fn build_sandboxed_std_command(
    program: &str,
    args: &[&str],
    config: Option<&ProcessSandboxConfig>,
) -> Command {
    let argv = sandbox_command_argv(program, args, config);
    let mut cmd = Command::new(&argv[0]);
    if argv.len() > 1 {
        cmd.args(&argv[1..]);
    }
    configure_sandboxed_command(&mut cmd, config);
    cmd
}

/// Build a Tokio command with optional sandbox wrapping.
///
/// Mirrors `build_sandboxed_std_command` for async subprocess call sites.
pub fn build_sandboxed_tokio_command(
    program: &str,
    args: &[&str],
    config: Option<&ProcessSandboxConfig>,
) -> tokio::process::Command {
    let argv = sandbox_command_argv(program, args, config);
    let mut cmd = tokio::process::Command::new(&argv[0]);
    if argv.len() > 1 {
        cmd.args(&argv[1..]);
    }
    configure_sandboxed_command(cmd.as_std_mut(), config);
    cmd
}

#[cfg(target_os = "windows")]
fn assign_windows_job_to_std_child(
    child: &std::process::Child,
    config: &ProcessSandboxConfig,
) -> std::io::Result<()> {
    let job = create_windows_job(config).map_err(|e| std::io::Error::other(e.to_string()))?;
    job.assign_process(child.as_raw_handle() as isize)
        .map_err(|e| {
            std::io::Error::other(format!(
                "failed to assign process to Windows job object: {e}"
            ))
        })
}

#[cfg(target_os = "windows")]
fn assign_windows_job_to_tokio_child(
    child: &tokio::process::Child,
    config: &ProcessSandboxConfig,
) -> std::io::Result<()> {
    let Some(raw_handle) = child.raw_handle() else {
        return Err(std::io::Error::other("missing child process handle"));
    };
    let job = create_windows_job(config).map_err(|e| std::io::Error::other(e.to_string()))?;
    job.assign_process(raw_handle as isize).map_err(|e| {
        std::io::Error::other(format!(
            "failed to assign process to Windows job object: {e}"
        ))
    })
}

/// Execute a sandboxed std command and capture output.
///
/// On Windows this assigns the spawned child process to a Job Object before
/// waiting for completion.
pub fn run_sandboxed_std_command_output(
    program: &str,
    args: &[&str],
    config: Option<&ProcessSandboxConfig>,
) -> std::io::Result<Output> {
    let mut cmd = build_sandboxed_std_command(program, args, config);

    #[cfg(target_os = "windows")]
    {
        if let Some(cfg) = config.filter(|cfg| cfg.enabled) {
            validate_windows_allowed_program(program, cfg)?;
            cmd.stdin(Stdio::null());
            cmd.stdout(Stdio::piped());
            cmd.stderr(Stdio::piped());
            let mut child = cmd.spawn()?;
            if let Err(err) = assign_windows_job_to_std_child(&child, cfg) {
                let _ = child.kill();
                let _ = child.wait();
                return Err(err);
            }
            return child.wait_with_output();
        }
    }

    cmd.output()
}

/// Execute a sandboxed tokio command and capture output.
///
/// On Windows this assigns the spawned child process to a Job Object before
/// waiting for completion.
pub async fn run_sandboxed_tokio_command_output(
    program: &str,
    args: &[&str],
    config: Option<&ProcessSandboxConfig>,
) -> std::io::Result<Output> {
    let mut cmd = build_sandboxed_tokio_command(program, args, config);

    #[cfg(target_os = "windows")]
    {
        if let Some(cfg) = config.filter(|cfg| cfg.enabled) {
            validate_windows_allowed_program(program, cfg)?;
            cmd.stdin(Stdio::null());
            cmd.stdout(Stdio::piped());
            cmd.stderr(Stdio::piped());
            let mut child = cmd.spawn()?;
            if let Err(err) = assign_windows_job_to_tokio_child(&child, cfg) {
                let _ = child.kill().await;
                let _ = child.wait().await;
                return Err(err);
            }
            return child.wait_with_output().await;
        }
    }

    cmd.output().await
}

/// Spawn a sandboxed tokio child process.
///
/// On Windows this assigns the spawned child process to a Job Object before
/// returning it to the caller.
pub async fn spawn_sandboxed_tokio_command(
    program: &str,
    args: &[&str],
    config: Option<&ProcessSandboxConfig>,
    kill_on_drop: bool,
) -> std::io::Result<tokio::process::Child> {
    let mut cmd = build_sandboxed_tokio_command(program, args, config);
    cmd.kill_on_drop(kill_on_drop);
    let child = cmd.spawn()?;

    #[cfg(target_os = "windows")]
    {
        if let Some(cfg) = config.filter(|cfg| cfg.enabled) {
            validate_windows_allowed_program(program, cfg)?;
            let mut child = child;
            if let Err(err) = assign_windows_job_to_tokio_child(&child, cfg) {
                let _ = child.kill().await;
                let _ = child.wait().await;
                return Err(err);
            }
            return Ok(child);
        }
    }

    Ok(child)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ==================== Config Parsing ====================

    #[test]
    fn test_default_config() {
        let config = ProcessSandboxConfig::default();
        assert!(config.enabled);
        assert_eq!(config.max_cpu_seconds, 30);
        assert_eq!(config.max_memory_mb, 512);
        assert_eq!(config.max_fds, 256);
        assert!(!config.network_access);
        assert!(config.env_filter.is_empty());
        assert!(!config.allowed_paths.is_empty());
    }

    #[test]
    fn test_max_memory_bytes() {
        let config = ProcessSandboxConfig {
            max_memory_mb: 512,
            ..Default::default()
        };
        assert_eq!(config.max_memory_bytes(), 512 * 1024 * 1024);
    }

    #[test]
    fn test_max_memory_bytes_overflow() {
        let config = ProcessSandboxConfig {
            max_memory_mb: u64::MAX,
            ..Default::default()
        };
        // saturating_mul should not panic
        assert_eq!(config.max_memory_bytes(), u64::MAX);
    }

    #[test]
    fn test_allowed_path_bufs() {
        let config = ProcessSandboxConfig {
            allowed_paths: vec!["/tmp".to_string(), "/usr/bin".to_string()],
            ..Default::default()
        };
        let bufs = config.allowed_path_bufs();
        assert_eq!(bufs.len(), 2);
        assert_eq!(bufs[0], PathBuf::from("/tmp"));
        assert_eq!(bufs[1], PathBuf::from("/usr/bin"));
    }

    #[test]
    fn test_from_config_none() {
        let config = ProcessSandboxConfig::from_config(None);
        assert!(config.enabled);
        assert_eq!(config.max_cpu_seconds, 30);
    }

    #[test]
    fn test_from_config_partial_json() {
        let val = json!({
            "enabled": false,
            "max_cpu_seconds": 60
        });
        let config = ProcessSandboxConfig::from_config(Some(&val));
        assert!(!config.enabled);
        assert_eq!(config.max_cpu_seconds, 60);
        // Defaults for unspecified fields
        assert_eq!(config.max_memory_mb, 512);
        assert_eq!(config.max_fds, 256);
    }

    #[test]
    fn test_from_config_full_json() {
        let val = json!({
            "enabled": true,
            "max_cpu_seconds": 10,
            "max_memory_mb": 256,
            "max_fds": 128,
            "allowed_paths": ["/home/user", "/opt/tools"],
            "network_access": true,
            "env_filter": ["PATH", "HOME"]
        });
        let config = ProcessSandboxConfig::from_config(Some(&val));
        assert!(config.enabled);
        assert_eq!(config.max_cpu_seconds, 10);
        assert_eq!(config.max_memory_mb, 256);
        assert_eq!(config.max_fds, 128);
        assert_eq!(config.allowed_paths, vec!["/home/user", "/opt/tools"]);
        assert!(config.network_access);
        assert_eq!(config.env_filter, vec!["PATH", "HOME"]);
    }

    #[test]
    fn test_from_config_invalid_json_falls_back_to_default() {
        let val = json!("not an object");
        let config = ProcessSandboxConfig::from_config(Some(&val));
        // Should fall back to defaults
        assert!(config.enabled);
        assert_eq!(config.max_cpu_seconds, 30);
    }

    #[test]
    fn test_from_config_null_value() {
        let val = json!(null);
        let config = ProcessSandboxConfig::from_config(Some(&val));
        assert!(config.enabled);
    }

    #[test]
    fn test_config_serde_roundtrip() {
        let config = ProcessSandboxConfig {
            enabled: true,
            max_cpu_seconds: 45,
            max_memory_mb: 1024,
            max_fds: 512,
            allowed_paths: vec!["/tmp".to_string(), "/data".to_string()],
            network_access: true,
            env_filter: vec!["PATH".to_string()],
        };
        let json_str = serde_json::to_string(&config).unwrap();
        let parsed: ProcessSandboxConfig = serde_json::from_str(&json_str).unwrap();
        assert_eq!(parsed.enabled, config.enabled);
        assert_eq!(parsed.max_cpu_seconds, config.max_cpu_seconds);
        assert_eq!(parsed.max_memory_mb, config.max_memory_mb);
        assert_eq!(parsed.max_fds, config.max_fds);
        assert_eq!(parsed.allowed_paths, config.allowed_paths);
        assert_eq!(parsed.network_access, config.network_access);
        assert_eq!(parsed.env_filter, config.env_filter);
    }

    #[test]
    fn test_default_allowed_paths_include_standard_dirs() {
        let paths = default_allowed_paths();
        assert!(paths.contains(&"/tmp".to_string()));
        assert!(paths.contains(&"/usr/bin".to_string()));
        assert!(paths.contains(&"/bin".to_string()));
    }

    // ==================== Resource Limits ====================

    #[cfg(unix)]
    #[test]
    fn test_apply_resource_limits_succeeds_with_defaults() {
        // Apply conservative limits -- should succeed in test environment.
        // We use very generous limits to avoid interfering with the test runner.
        let config = ProcessSandboxConfig {
            max_cpu_seconds: 3600, // 1 hour (very generous)
            max_memory_mb: 4096,   // 4 GB
            max_fds: 1024,         // generous
            ..Default::default()
        };
        let result = apply_resource_limits(&config);
        assert!(
            result.is_ok(),
            "apply_resource_limits failed: {:?}",
            result.err()
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_rlimit_name_known_resources() {
        assert_eq!(rlimit_name(libc::RLIMIT_CPU), "RLIMIT_CPU");
        assert_eq!(rlimit_name(libc::RLIMIT_AS), "RLIMIT_AS");
        assert_eq!(rlimit_name(libc::RLIMIT_NOFILE), "RLIMIT_NOFILE");
    }

    #[cfg(unix)]
    #[test]
    fn test_rlimit_name_unknown_resource() {
        assert_eq!(rlimit_name(9999 as RlimitResource), "RLIMIT_UNKNOWN");
    }

    // ==================== macOS Seatbelt ====================

    #[cfg(target_os = "macos")]
    #[test]
    fn test_build_seatbelt_profile_default() {
        let config = ProcessSandboxConfig::default();
        let profile = build_seatbelt_profile(&config);

        assert!(profile.contains("(version 1)"));
        assert!(profile.contains("(deny default)"));
        assert!(profile.contains("(allow process-exec)"));
        assert!(profile.contains("(allow process-fork)"));
        // Should include allowed paths
        assert!(profile.contains("/tmp"));
        assert!(profile.contains("/usr/bin"));
        // Should not allow full network access by default
        assert!(!profile.contains("(allow network*)"));
        // Should allow localhost
        assert!(profile.contains("localhost"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_build_seatbelt_profile_with_network() {
        let config = ProcessSandboxConfig {
            network_access: true,
            ..Default::default()
        };
        let profile = build_seatbelt_profile(&config);
        assert!(profile.contains("(allow network*)"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_build_seatbelt_profile_custom_paths() {
        let config = ProcessSandboxConfig {
            allowed_paths: vec!["/home/user/data".to_string(), "/opt/tools".to_string()],
            ..Default::default()
        };
        let profile = build_seatbelt_profile(&config);
        assert!(profile.contains("/home/user/data"));
        assert!(profile.contains("/opt/tools"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_macos_sandbox_command_prefix_enabled() {
        let config = ProcessSandboxConfig::default();
        let prefix = macos_sandbox_command_prefix(&config);
        assert_eq!(prefix.len(), 3);
        assert_eq!(prefix[0], "sandbox-exec");
        assert_eq!(prefix[1], "-p");
        assert!(prefix[2].contains("(version 1)"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_macos_sandbox_command_prefix_disabled() {
        let config = ProcessSandboxConfig {
            enabled: false,
            ..Default::default()
        };
        let prefix = macos_sandbox_command_prefix(&config);
        assert!(prefix.is_empty());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_escape_seatbelt_path_normal() {
        assert_eq!(escape_seatbelt_path("/usr/bin"), "/usr/bin");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_escape_seatbelt_path_with_quotes() {
        assert_eq!(
            escape_seatbelt_path("/path/with\"quote"),
            "/path/with\\\"quote"
        );
    }

    // ==================== Sandbox Application ====================

    #[test]
    fn test_apply_sandbox_disabled() {
        let config = ProcessSandboxConfig {
            enabled: false,
            ..Default::default()
        };
        let result = apply_sandbox(&config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_sandbox_command_prefix_disabled() {
        let config = ProcessSandboxConfig {
            enabled: false,
            ..Default::default()
        };
        assert!(sandbox_command_prefix(&config).is_none());
    }

    #[test]
    fn test_sandbox_command_argv_disabled() {
        let config = ProcessSandboxConfig {
            enabled: false,
            ..Default::default()
        };
        let argv = sandbox_command_argv("hostname", &["-f"], Some(&config));
        assert_eq!(argv, vec!["hostname".to_string(), "-f".to_string()]);
    }

    #[test]
    fn test_build_sandboxed_std_command_disabled_passthrough() {
        let config = ProcessSandboxConfig {
            enabled: false,
            ..Default::default()
        };
        let command = build_sandboxed_std_command("hostname", &["-f"], Some(&config));
        assert_eq!(command.get_program(), std::ffi::OsStr::new("hostname"));
        let args: Vec<String> = command
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect();
        assert_eq!(args, vec!["-f".to_string()]);
    }

    #[test]
    fn test_build_sandboxed_tokio_command_disabled_passthrough() {
        let config = ProcessSandboxConfig {
            enabled: false,
            ..Default::default()
        };
        let command = build_sandboxed_tokio_command("hostname", &["-f"], Some(&config));
        let std_cmd = command.as_std();
        assert_eq!(std_cmd.get_program(), std::ffi::OsStr::new("hostname"));
        let args: Vec<String> = std_cmd
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect();
        assert_eq!(args, vec!["-f".to_string()]);
    }

    fn env_filter_test_config() -> ProcessSandboxConfig {
        ProcessSandboxConfig {
            enabled: true,
            env_filter: vec![
                "PATH".to_string(),
                "CARAPACE_SANDBOX_TEST_MISSING".to_string(),
            ],
            ..Default::default()
        }
    }

    fn assert_env_filter_applied(command: &std::process::Command) {
        let envs: Vec<(String, Option<String>)> = command
            .get_envs()
            .map(|(key, value)| {
                (
                    key.to_string_lossy().into_owned(),
                    value.map(|v| v.to_string_lossy().into_owned()),
                )
            })
            .collect();

        assert!(
            envs.iter()
                .any(|(key, value)| key == "PATH" && value.is_some()),
            "expected PATH to be preserved by env_filter"
        );
        assert!(
            !envs
                .iter()
                .any(|(key, _)| key == "CARAPACE_SANDBOX_TEST_MISSING"),
            "unexpected missing variable entry in filtered environment"
        );
    }

    #[test]
    fn test_build_sandboxed_std_command_applies_env_filter() {
        let config = env_filter_test_config();
        let command = build_sandboxed_std_command("hostname", &["-f"], Some(&config));
        assert_env_filter_applied(&command);
    }

    #[test]
    fn test_build_sandboxed_tokio_command_applies_env_filter() {
        let config = env_filter_test_config();
        let command = build_sandboxed_tokio_command("hostname", &["-f"], Some(&config));
        assert_env_filter_applied(command.as_std());
    }

    #[test]
    fn test_default_probe_sandbox_config_limits() {
        let config = default_probe_sandbox_config();
        assert!(config.enabled);
        assert_eq!(config.max_cpu_seconds, 5);
        assert_eq!(config.max_memory_mb, 128);
        assert_eq!(config.max_fds, 64);
        assert!(!config.network_access);
        assert!(!config.allowed_paths.is_empty());
    }

    #[test]
    fn test_default_tailscale_cli_sandbox_config_limits() {
        let config = default_tailscale_cli_sandbox_config();
        assert!(config.enabled);
        assert_eq!(config.max_cpu_seconds, 10);
        assert_eq!(config.max_memory_mb, 256);
        assert_eq!(config.max_fds, 128);
        assert!(config.network_access);
        assert!(!config.allowed_paths.is_empty());
    }

    #[test]
    fn test_default_ssh_tunnel_sandbox_config_limits() {
        let config = default_ssh_tunnel_sandbox_config();
        assert!(config.enabled);
        assert_eq!(config.max_cpu_seconds, 300);
        assert_eq!(config.max_memory_mb, 256);
        assert_eq!(config.max_fds, 256);
        assert!(config.network_access);
        assert!(!config.allowed_paths.is_empty());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_default_probe_sandbox_config_paths_macos() {
        let config = default_probe_sandbox_config();
        assert!(config.allowed_paths.iter().any(|p| p == "/private/tmp"));
        assert!(config.allowed_paths.iter().any(|p| p == "/System"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_default_tailscale_cli_sandbox_config_paths_macos() {
        let config = default_tailscale_cli_sandbox_config();
        assert!(config.allowed_paths.iter().any(|p| p == "/private/var"));
        assert!(config.allowed_paths.iter().any(|p| p == "/var/run"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_default_ssh_tunnel_sandbox_config_paths_macos() {
        let config = default_ssh_tunnel_sandbox_config();
        assert!(config.allowed_paths.iter().any(|p| p == "/etc"));
        assert!(config.allowed_paths.iter().any(|p| p == "/dev"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_default_probe_sandbox_config_paths_linux() {
        let config = default_probe_sandbox_config();
        assert!(config.allowed_paths.iter().any(|p| p == "/proc"));
        assert!(config.allowed_paths.iter().any(|p| p == "/lib64"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_default_tailscale_cli_sandbox_config_paths_linux() {
        let config = default_tailscale_cli_sandbox_config();
        assert!(config.allowed_paths.iter().any(|p| p == "/run"));
        assert!(config.allowed_paths.iter().any(|p| p == "/var/run"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_default_ssh_tunnel_sandbox_config_paths_linux() {
        let config = default_ssh_tunnel_sandbox_config();
        assert!(config.allowed_paths.iter().any(|p| p == "/etc"));
        assert!(config.allowed_paths.iter().any(|p| p == "/dev"));
        assert!(config.allowed_paths.iter().any(|p| p == "/run"));
        assert!(config.allowed_paths.iter().any(|p| p == "/var/run"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_validate_landlock_abi_support_allows_network_enabled_on_v1() {
        let config = ProcessSandboxConfig {
            network_access: true,
            ..Default::default()
        };
        assert!(validate_landlock_abi_support(1, &config).is_ok());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_validate_landlock_abi_support_rejects_network_disabled_before_v4() {
        let config = ProcessSandboxConfig {
            network_access: false,
            ..Default::default()
        };
        let err = validate_landlock_abi_support(3, &config).unwrap_err();
        assert!(matches!(err, SandboxError::Platform(_)));
        assert!(err.to_string().contains("ABI v4+"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_validate_landlock_abi_support_allows_network_disabled_on_v4() {
        let config = ProcessSandboxConfig {
            network_access: false,
            ..Default::default()
        };
        assert!(validate_landlock_abi_support(4, &config).is_ok());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_sandbox_command_prefix_macos() {
        let config = ProcessSandboxConfig::default();
        let prefix = sandbox_command_prefix(&config);
        assert!(prefix.is_some());
        let prefix = prefix.unwrap();
        assert_eq!(prefix[0], "sandbox-exec");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_sandbox_command_argv_macos_includes_prefix_and_target() {
        let config = ProcessSandboxConfig::default();
        let argv = sandbox_command_argv("hostname", &["-f"], Some(&config));
        assert!(!argv.is_empty());
        assert_eq!(argv[0], "sandbox-exec");
        assert!(argv.contains(&"hostname".to_string()));
        assert!(argv.contains(&"-f".to_string()));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_sandbox_command_prefix_linux_is_none() {
        // Linux uses in-process sandboxing (landlock), no command prefix
        let config = ProcessSandboxConfig::default();
        let prefix = sandbox_command_prefix(&config);
        assert!(prefix.is_none());
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn test_sandbox_command_argv_non_macos_passthrough() {
        let config = ProcessSandboxConfig::default();
        let argv = sandbox_command_argv("hostname", &["-f"], Some(&config));
        assert_eq!(argv, vec!["hostname".to_string(), "-f".to_string()]);
    }

    // ==================== SandboxError ====================

    #[test]
    fn test_sandbox_error_display() {
        let err = SandboxError::ResourceLimit {
            resource: "RLIMIT_CPU".to_string(),
            detail: "permission denied".to_string(),
        };
        assert_eq!(
            err.to_string(),
            "failed to set resource limit RLIMIT_CPU: permission denied"
        );

        let err = SandboxError::Platform("landlock not available".to_string());
        assert_eq!(
            err.to_string(),
            "platform sandbox error: landlock not available"
        );

        let err = SandboxError::Unsupported;
        assert_eq!(err.to_string(), "sandbox not supported on this platform");
    }

    #[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
    #[test]
    fn test_ensure_sandbox_supported_supported_platform() {
        let config = ProcessSandboxConfig {
            network_access: true,
            ..Default::default()
        };
        assert!(ensure_sandbox_supported(Some(&config)).is_ok());
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_ensure_sandbox_supported_windows_rejects_network_deny() {
        let config = ProcessSandboxConfig {
            network_access: false,
            ..Default::default()
        };
        let err = ensure_sandbox_supported(Some(&config)).unwrap_err();
        assert!(matches!(err, SandboxError::Platform(_)));
        assert!(err.to_string().contains("network_access=false"));
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    #[test]
    fn test_ensure_sandbox_supported_unsupported_platform() {
        let config = ProcessSandboxConfig::default();
        let err = ensure_sandbox_supported(Some(&config)).unwrap_err();
        assert!(matches!(err, SandboxError::Unsupported));
    }

    // ==================== Integration-style ====================

    #[test]
    fn test_config_propagation() {
        // Verify config values are correctly propagated through the pipeline
        let val = json!({
            "enabled": true,
            "max_cpu_seconds": 15,
            "max_memory_mb": 256,
            "max_fds": 64,
            "allowed_paths": ["/opt/sandbox"],
            "network_access": false,
            "env_filter": ["PATH"]
        });
        let config = ProcessSandboxConfig::from_config(Some(&val));

        assert!(config.enabled);
        assert_eq!(config.max_cpu_seconds, 15);
        assert_eq!(config.max_memory_bytes(), 256 * 1024 * 1024);
        assert_eq!(config.max_fds, 64);
        assert_eq!(config.allowed_paths, vec!["/opt/sandbox"]);
        assert!(!config.network_access);
        assert_eq!(config.env_filter, vec!["PATH"]);

        // Verify derived values
        let path_bufs = config.allowed_path_bufs();
        assert_eq!(path_bufs.len(), 1);
        assert_eq!(path_bufs[0], PathBuf::from("/opt/sandbox"));
    }

    #[test]
    fn test_landlock_noop_on_non_linux() {
        // On non-Linux, apply_landlock should be a no-op
        let _config = ProcessSandboxConfig::default();
        #[cfg(not(target_os = "linux"))]
        {
            let result = apply_landlock(&_config);
            assert!(result.is_ok());
        }
    }
}
