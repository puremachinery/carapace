//! WASM plugin system
//!
//! wasmtime-based plugin host with capability enforcement.
//!
//! This module provides:
//! - Plugin loading from .wasm files
//! - Host function implementations for plugins
//! - Capability enforcement (credential isolation, SSRF protection, rate limiting)
//! - Plugin registry for tracking loaded instances
//!
//! # Security Model
//!
//! Plugins run in sandboxed WASM environments with capability-based access:
//!
//! 1. **Credential Isolation**: All credential keys are automatically prefixed with
//!    the plugin ID. A plugin calling `credential_get("token")` reads
//!    `<plugin-id>:token`. Plugins cannot access other plugins' credentials.
//!
//! 2. **SSRF Protection**: Both `media_fetch` and `http_fetch` block requests to:
//!    - IPv4 private ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
//!    - IPv4 link-local (169.254.0.0/16)
//!    - IPv4/IPv6 localhost (127.0.0.0/8, ::1)
//!    - IPv6 private ranges (fc00::/7, fe80::/10)
//!    - Cloud metadata endpoints (169.254.169.254, fd00:ec2::254)
//!    - Only HTTP/HTTPS protocols are allowed
//!
//! 3. **Config Access**: Plugins can only read keys under `plugins.<plugin-id>.*`.
//!    Gateway-level config (tokens, auth) is not accessible.
//!
//! 4. **Resource Limits**:
//!    - Memory: 64MB per plugin instance
//!    - Execution: 30s timeout per function call
//!    - HTTP requests: 100/minute rate limit per plugin
//!    - Logging: 1000 messages/minute rate limit per plugin
//!    - Body size: 10MB max for HTTP request/response bodies

/// Maximum managed plugin artifact size accepted by install/update paths.
pub(crate) const MAX_MANAGED_PLUGIN_ARTIFACT_BYTES: u64 = 50 * 1024 * 1024;

/// Maximum managed plugin manifest size accepted by loader/bootstrap paths.
///
/// A 1 MiB cap blanket-failed every managed plugin on installations
/// with hundreds of entries or verbose per-entry metadata: the
/// loader's `load_plugins_manifest` returned Err on exceed, the
/// bootstrap's `manifest_error` then marked every entry as Failed
/// with the same generic "invalid manifest" message. 16 MiB
/// comfortably holds ~10k entries with rich per-entry metadata
/// while still bounding read work against pathological input. The
/// install/update WS handlers ALSO enforce this cap at write time
/// (`write_plugins_manifest`), so a corrupt over-size manifest
/// cannot be persisted to disk in the first place.
///
/// **Memory footprint follow-up.** A worst-case 16 MiB JSON parsed
/// through `serde_json::Value` materializes to ~4-8× the wire size
/// due to per-node `Value` enum + boxed `String`/`Map`/`Vec`
/// overhead (~64-128 MiB resident). The install/update path holds
/// the parsed tree alongside the manifest backup bytes and the
/// pretty-printed output buffer simultaneously, peaking around
/// ~120 MiB transient per install. Serialization is sequential
/// (single-allocator, `PLUGINS_MANIFEST_RMW_LOCK` serializes
/// installs), so the peak is bounded — but the steady-state daemon
/// memory budget jumped 16× from the old 1 MiB cap. A follow-up
/// refactor should introduce a typed `PluginManifest` DTO and parse
/// directly into it (avoiding the intermediate `Value` tree), or
/// stream the manifest entry-by-entry rather than materializing the
/// full document at once. Tracking as a separate PR because the
/// typed-boundary change has reach beyond the manifest reader.
pub(crate) const MAX_MANAGED_PLUGIN_MANIFEST_BYTES: u64 = 16 * 1024 * 1024;

fn managed_plugin_not_regular_file_error(path: &std::path::Path, label: &str) -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        format!("{label} at '{}' is not a regular file", path.display()),
    )
}

fn managed_plugin_too_large_error(
    path: &std::path::Path,
    label: &str,
    len: u64,
    max_len: u64,
) -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        format!(
            "{label} at '{}' exceeds maximum size ({} bytes > {} bytes)",
            path.display(),
            len,
            max_len
        ),
    )
}

fn managed_plugin_metadata_is_reparse_point(metadata: &std::fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

        metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }
    #[cfg(not(windows))]
    {
        let _ = metadata;
        false
    }
}

fn validate_managed_plugin_regular_file_metadata(
    path: &std::path::Path,
    metadata: &std::fs::Metadata,
    label: &str,
) -> std::io::Result<()> {
    let file_type = metadata.file_type();
    if file_type.is_symlink()
        || managed_plugin_metadata_is_reparse_point(metadata)
        || managed_plugin_metadata_has_unsupported_links(path, metadata)
        || !metadata.is_file()
    {
        return Err(managed_plugin_not_regular_file_error(path, label));
    }
    Ok(())
}

fn managed_plugin_metadata_has_unsupported_links(
    path: &std::path::Path,
    metadata: &std::fs::Metadata,
) -> bool {
    #[cfg(windows)]
    {
        let _ = metadata;
        // `std::os::windows::fs::MetadataExt::number_of_links()` is gated
        // behind the unstable `windows_by_handle` feature (tracking issue
        // rust-lang/rust#63010) on the stable toolchain, so we re-stat the
        // path through `GetFileInformationByHandle` instead. Fail-closed:
        // if we can't determine the link count, treat the file as having
        // unsupported links so the caller surfaces a clear refusal.
        WindowsFileId::from_path(path)
            .map(|id| id.number_of_links > 1)
            .unwrap_or(true)
    }
    #[cfg(unix)]
    {
        let _ = path;
        use std::os::unix::fs::MetadataExt;
        metadata.nlink() > 1
    }
    #[cfg(all(not(windows), not(unix)))]
    {
        let _ = (path, metadata);
        false
    }
}

/// Windows-only by-handle file identity, used as the stable-Rust
/// replacement for `std::os::windows::fs::MetadataExt`'s
/// `number_of_links` / `volume_serial_number` / `file_index` methods,
/// all of which are gated behind the unstable `windows_by_handle`
/// feature on the stable toolchain.
///
/// Wraps `GetFileInformationByHandle` against either an already-open
/// `std::fs::File` (for backup-cleanup identity capture at open time)
/// or against a path that the helper opens internally with
/// `CreateFileW` + `OPEN_EXISTING` (for re-stat at cleanup time).
#[cfg(windows)]
#[derive(Debug, Clone, Copy)]
pub(crate) struct WindowsFileId {
    pub(crate) volume_serial: u32,
    pub(crate) file_index: u64,
    pub(crate) number_of_links: u32,
}

#[cfg(windows)]
impl WindowsFileId {
    pub(crate) fn from_handle(file: &std::fs::File) -> std::io::Result<Self> {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Foundation::HANDLE;
        use windows_sys::Win32::Storage::FileSystem::{
            GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
        };

        // SAFETY: `BY_HANDLE_FILE_INFORMATION` is `repr(C)` POD with no
        // pointer fields, so zero-init is a valid initial state. The
        // `GetFileInformationByHandle` call below either fully populates
        // every field on success or we return early via `last_os_error`
        // before any reader sees the buffer.
        let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
        // SAFETY: `file.as_raw_handle()` returns a valid Win32 handle owned
        // by `file`; the handle stays alive for the duration of the borrow
        // because `file` is not dropped until after this function returns.
        // `GetFileInformationByHandle` does not close the handle.
        let rc = unsafe { GetFileInformationByHandle(file.as_raw_handle() as HANDLE, &mut info) };
        if rc == 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(Self::from_raw(&info))
    }

    pub(crate) fn from_path(path: &std::path::Path) -> std::io::Result<Self> {
        use std::os::windows::ffi::OsStrExt;
        use std::ptr;
        use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
        use windows_sys::Win32::Storage::FileSystem::{
            CreateFileW, GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
            FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE,
            FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
        };

        let wide: Vec<u16> = path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        // SAFETY: `wide` is a null-terminated UTF-16 sequence owned for
        // the duration of this call. `lpSecurityAttributes` and
        // `hTemplateFile` are null pointers (default security descriptor,
        // no template). We pass `dwDesiredAccess = 0` for metadata-only
        // access; `FILE_FLAG_BACKUP_SEMANTICS` is required when the path
        // could be a directory.
        //
        // SECURITY: `FILE_FLAG_OPEN_REPARSE_POINT` is required so the
        // identity check sees the reparse point's OWN volume_serial /
        // file_index — not the target it would otherwise redirect to. The
        // sibling `open_managed_plugin_regular_file_no_follow` uses
        // `symlink_metadata` (the Unix equivalent of refusing to follow);
        // without the same discipline here, a same-uid attacker could
        // swap the path to a reparse point between the
        // `WindowsFileId::from_handle(opened_file)` capture and this
        // `from_path` re-stat, and the identity check would compare the
        // original opened file against the reparse target. Setting this
        // flag makes the by-handle vs by-path comparison symmetric.
        let handle = unsafe {
            CreateFileW(
                wide.as_ptr(),
                0,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                ptr::null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: see `from_handle` — `info` is an owned zero-init POD.
        let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
        let rc = unsafe { GetFileInformationByHandle(handle, &mut info) };
        // SAFETY: `handle` came from a successful `CreateFileW` and we
        // have not closed it elsewhere. The Close result is intentionally
        // dropped — there is no recovery path if Close fails, the kernel
        // reclaims the handle on process exit, and overwriting our return
        // value with the Close error would mask the more useful
        // `GetFileInformationByHandle` failure above.
        unsafe {
            let _ = CloseHandle(handle);
        }
        if rc == 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(Self::from_raw(&info))
    }

    fn from_raw(
        info: &windows_sys::Win32::Storage::FileSystem::BY_HANDLE_FILE_INFORMATION,
    ) -> Self {
        let file_index = ((info.nFileIndexHigh as u64) << 32) | (info.nFileIndexLow as u64);
        Self {
            volume_serial: info.dwVolumeSerialNumber,
            file_index,
            number_of_links: info.nNumberOfLinks,
        }
    }

    pub(crate) fn identity_matches(&self, other: &Self) -> bool {
        self.volume_serial == other.volume_serial && self.file_index == other.file_index
    }
}

#[cfg(windows)]
#[cfg(test)]
mod windows_file_id_tests {
    use super::WindowsFileId;
    use std::fs;
    use std::io::Write;
    use tempfile::TempDir;

    /// Pin the round-7 sharp-edges HIGH-2 fix: `WindowsFileId::from_path`
    /// must open with `FILE_FLAG_OPEN_REPARSE_POINT` so a same-uid
    /// attacker who swaps the dirent for a reparse point cannot trick
    /// `identity_matches` into matching the redirect target's identity
    /// against the originally-opened file's identity.
    #[test]
    fn from_handle_and_from_path_agree_for_same_regular_file() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("same-file");
        let mut file = fs::File::create(&path).unwrap();
        file.write_all(b"abc").unwrap();
        file.sync_all().unwrap();

        let by_handle = WindowsFileId::from_handle(&file).expect("from_handle");
        let by_path = WindowsFileId::from_path(&path).expect("from_path");

        assert!(
            by_handle.identity_matches(&by_path),
            "WindowsFileId::from_handle and from_path must agree on the same regular file \
             ({:?} vs {:?})",
            by_handle,
            by_path
        );
    }

    /// Pin the cleanup-restored-transaction-backup TOCTOU defense: after
    /// the backup is renamed elsewhere and a different file is created
    /// at the same name, the captured by-handle id of the original file
    /// must NOT match the by-path id of the new file at the same name.
    /// If it did, the Windows backup-cleanup path could be tricked into
    /// `remove_file` of a path the attacker just substituted.
    #[test]
    fn identity_differs_after_rename_swap() {
        let dir = TempDir::new().unwrap();
        let a = dir.path().join("a");
        let b = dir.path().join("b");

        let file_a = fs::File::create(&a).unwrap();
        let original_by_handle = WindowsFileId::from_handle(&file_a).expect("from_handle");

        // Move A to B; the file_a handle stays open against the
        // original inode while the dirent at A becomes vacant.
        fs::rename(&a, &b).unwrap();

        // Plant a brand-new file at A with a different inode.
        let _new_a = fs::File::create(&a).unwrap();
        let new_a_by_path = WindowsFileId::from_path(&a).expect("from_path");

        assert!(
            !original_by_handle.identity_matches(&new_a_by_path),
            "after rename-swap, by_handle of the originally-opened file must NOT match \
             by_path of the new file at the same dirent ({:?} vs {:?})",
            original_by_handle,
            new_a_by_path
        );
    }

    /// Pin `managed_plugin_metadata_has_unsupported_links`'s
    /// hardlink-detection invariant on Windows.
    #[test]
    fn number_of_links_detects_hardlink() {
        let dir = TempDir::new().unwrap();
        let target = dir.path().join("target");
        let link = dir.path().join("link");
        fs::write(&target, b"data").unwrap();
        fs::hard_link(&target, &link).expect("hard_link");

        let id = WindowsFileId::from_path(&target).expect("from_path");
        assert!(
            id.number_of_links > 1,
            "a hardlinked file must report number_of_links > 1; got {}",
            id.number_of_links
        );
    }

    /// Pin the SECURITY note on `WindowsFileId::from_path`: when the
    /// dirent is a symlink, the helper must return the symlink's OWN
    /// identity rather than following to the target. If it followed,
    /// the `identity_matches(opened_handle, path_re_stat)` chain that
    /// guards backup cleanup would compare the original opened inode
    /// against the symlink-target's inode and could be tricked into a
    /// false positive.
    #[test]
    fn from_path_does_not_follow_reparse_points() {
        let dir = TempDir::new().unwrap();
        let target = dir.path().join("target");
        let link = dir.path().join("link");
        fs::write(&target, b"data").unwrap();
        // Symbolic-link creation on Windows requires either developer
        // mode or admin privileges. CI runners may not have either,
        // so skip the assertion when the link cannot be created.
        if std::os::windows::fs::symlink_file(&target, &link).is_err() {
            eprintln!(
                "from_path_does_not_follow_reparse_points: symlink creation refused \
                 (developer-mode/admin required); skipping reparse-point assertion"
            );
            return;
        }

        let target_id = WindowsFileId::from_path(&target).expect("from_path target");
        let link_id = WindowsFileId::from_path(&link).expect("from_path link");
        assert!(
            !target_id.identity_matches(&link_id),
            "from_path of a symlink must return the symlink's own identity, not the target's \
             (target {:?} vs link {:?})",
            target_id,
            link_id
        );
    }
}

fn open_managed_plugin_regular_file_no_follow(
    path: &std::path::Path,
    label: &str,
) -> std::io::Result<std::fs::File> {
    let metadata = std::fs::symlink_metadata(path)?;
    validate_managed_plugin_regular_file_metadata(path, &metadata, label)?;

    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // O_NOFOLLOW + O_NONBLOCK: pre-open symlink_metadata refuses
        // symlinks but a TOCTOU window between the pre-check and
        // the open lets a same-uid attacker swap the dirent for a
        // FIFO. Without O_NONBLOCK the open(2) blocks indefinitely;
        // post-open `validate_managed_plugin_regular_file_metadata`
        // would reject the FIFO once open returns.
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;
        // Windows has no exact O_NOFOLLOW equivalent. Open the path with
        // FILE_FLAG_OPEN_REPARSE_POINT and then revalidate opened metadata;
        // the remaining race is bounded to a same-path reparse mutation that
        // must also pass the post-open regular-file check before callers read.
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = options.open(path)?;
    let opened_metadata = file.metadata()?;
    validate_managed_plugin_regular_file_metadata(path, &opened_metadata, label)?;
    Ok(file)
}

/// Validate a managed plugin path under the same no-follow, no-hardlink policy
/// used by readers before a path-level operation such as transaction rollback.
pub(crate) fn validate_managed_plugin_path_no_follow(
    path: &std::path::Path,
    label: &str,
    max_len: u64,
) -> std::io::Result<()> {
    open_managed_plugin_path_no_follow(path, label, max_len).map(|_| ())
}

/// Open a managed plugin path under the same no-follow, no-hardlink, max-size
/// policy used by readers, returning the opened file identity to the caller.
pub(crate) fn open_managed_plugin_path_no_follow(
    path: &std::path::Path,
    label: &str,
    max_len: u64,
) -> std::io::Result<std::fs::File> {
    let file = open_managed_plugin_regular_file_no_follow(path, label)?;
    let len = file.metadata()?.len();
    if len > max_len {
        return Err(managed_plugin_too_large_error(path, label, len, max_len));
    }
    Ok(file)
}

/// Open a managed `.wasm` artifact without following symlinks or reparse points.
pub(crate) fn open_managed_plugin_wasm_no_follow(
    path: &std::path::Path,
) -> std::io::Result<std::fs::File> {
    open_managed_plugin_regular_file_no_follow(path, "managed plugin artifact")
}

/// Read a managed `.wasm` artifact under the same no-follow policy as writes.
pub(crate) fn read_managed_plugin_wasm_no_follow(
    path: &std::path::Path,
) -> std::io::Result<Vec<u8>> {
    let file = open_managed_plugin_wasm_no_follow(path)?;
    let len = file.metadata()?.len();
    if len > MAX_MANAGED_PLUGIN_ARTIFACT_BYTES {
        return Err(managed_plugin_too_large_error(
            path,
            "managed plugin artifact",
            len,
            MAX_MANAGED_PLUGIN_ARTIFACT_BYTES,
        ));
    }
    let mut bytes = Vec::new();
    let mut limited = std::io::Read::take(file, MAX_MANAGED_PLUGIN_ARTIFACT_BYTES + 1);
    std::io::Read::read_to_end(&mut limited, &mut bytes)?;
    if bytes.len() as u64 > MAX_MANAGED_PLUGIN_ARTIFACT_BYTES {
        return Err(managed_plugin_too_large_error(
            path,
            "managed plugin artifact",
            bytes.len() as u64,
            MAX_MANAGED_PLUGIN_ARTIFACT_BYTES,
        ));
    }
    Ok(bytes)
}

/// Read `plugins-manifest.json` without following symlinks or reparse points.
pub(crate) fn read_managed_plugins_manifest_no_follow(
    path: &std::path::Path,
) -> std::io::Result<Option<String>> {
    let file = match open_managed_plugin_regular_file_no_follow(path, "plugins manifest") {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let len = file.metadata()?.len();
    if len > MAX_MANAGED_PLUGIN_MANIFEST_BYTES {
        return Err(managed_plugin_too_large_error(
            path,
            "plugins manifest",
            len,
            MAX_MANAGED_PLUGIN_MANIFEST_BYTES,
        ));
    }
    // Near-cap warning: emit a tracing::warn! when the manifest
    // crosses 75% of the cap. The 16 MiB cap fail-closes at the cap
    // edge with a generic ERROR_INVALID_REQUEST; without an early
    // warning, the first signal an operator gets is the next install
    // returning "plugins manifest exceeds maximum size". 75% (12 MiB)
    // gives ~4 MiB of headroom to trim/restructure before the cliff
    // — typically several thousand additional entries depending on
    // metadata richness.
    //
    // Throttle to at most once per hour per process. `read_managed_
    // plugins_manifest_no_follow` is called from `load_plugins_manifest`
    // (every loader startup pass / hot-reload) AND from the WS
    // `plugins.list` / install / update handlers, so a UI or operator
    // polling `plugins.list` would otherwise produce one warn-line per
    // poll while the manifest sits above the threshold. `tracing` has
    // no built-in rate limiting; the throttle has to live here.
    const MANIFEST_WARN_THRESHOLD: u64 = MAX_MANAGED_PLUGIN_MANIFEST_BYTES * 3 / 4;
    if len >= MANIFEST_WARN_THRESHOLD {
        static LAST_WARN_AT_SECS: std::sync::atomic::AtomicU64 =
            std::sync::atomic::AtomicU64::new(0);
        if crate::logging::throttle::throttled_once_per_hour(&LAST_WARN_AT_SECS) {
            tracing::warn!(
                path = %path.display(),
                manifest_bytes = len,
                cap_bytes = MAX_MANAGED_PLUGIN_MANIFEST_BYTES,
                "plugins manifest size approaching cap; trim unused entries before the next \
                 install/update operation hits the 16 MiB cliff and refuses the write"
            );
        }
    }
    let mut reader = std::io::Read::take(file, MAX_MANAGED_PLUGIN_MANIFEST_BYTES + 1);
    let mut contents = String::new();
    std::io::Read::read_to_string(&mut reader, &mut contents)?;
    if contents.len() as u64 > MAX_MANAGED_PLUGIN_MANIFEST_BYTES {
        return Err(managed_plugin_too_large_error(
            path,
            "plugins manifest",
            contents.len() as u64,
            MAX_MANAGED_PLUGIN_MANIFEST_BYTES,
        ));
    }
    Ok(Some(contents))
}

/// Validate a managed plugin name used for `plugins.install` / `plugins.update`.
pub(crate) fn validate_managed_plugin_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("plugin name must not be empty".to_string());
    }
    if name.len() > 128 {
        return Err("plugin name is too long (max 128 characters)".to_string());
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(
            "plugin name may only contain ASCII alphanumeric characters, hyphens, and underscores"
                .to_string(),
        );
    }
    if crate::plugins::loader::is_reserved_plugin_id(name) {
        return Err(format!(
            "plugin name '{}' is reserved for plugin configuration",
            name
        ));
    }
    Ok(())
}

pub mod bindings;
pub mod capabilities;
pub mod dispatch;
mod engine;
pub mod hook_utils;
pub mod host;
pub mod loader;
pub mod permissions;
pub mod runtime;
pub mod sandbox;
pub mod signature;
pub mod tools;

pub mod caps;

#[cfg(test)]
mod tests;

// Re-export commonly used types
pub use bindings::{
    BindingError, ChannelCapabilities, ChannelInfo, ChannelPluginInstance, ChatType,
    DeliveryResult, HookEvent, HookPluginInstance, HookResult, OutboundContext, PluginError,
    PluginRegistry, ReadReceiptContext, Retryability, ServicePluginInstance, ToolContext,
    ToolDefinition, ToolPluginInstance, ToolResult, TypingContext, WebhookPluginInstance,
    WebhookRequest, WebhookResponse,
};
pub use capabilities::{
    CapabilityError, ConfigEnforcer, CredentialEnforcer, RateLimiterRegistry, SsrfProtection,
    HTTP_RATE_LIMIT_PER_MINUTE, LOG_RATE_LIMIT_PER_MINUTE,
};
pub use dispatch::{
    is_modifiable_hook, DispatchError, HookDispatchResult, HookDispatcher, ToolDispatcher,
    WebhookDispatcher, MODIFIABLE_HOOKS,
};
pub(crate) use engine::PluginEngine;
pub use host::{
    HostError, HttpRequest, HttpResponse, MediaFetchResult, PluginHostContext,
    PluginHostContextBuilder, MAX_HTTP_BODY_SIZE, MAX_LOG_MESSAGE_SIZE, MAX_URL_LENGTH,
};
pub use loader::{LoadedPlugin, LoaderError, PluginKind, PluginLoader, PluginManifest};
pub use permissions::{
    compute_effective_permissions, validate_declared_permissions, DeclaredPermissions,
    EffectivePermissions, PermissionConfig, PermissionEnforcer, PermissionError,
    PermissionOverride,
};
pub use runtime::{
    HostState, PluginInstanceHandle, PluginRuntime, RuntimeError, DEFAULT_EXECUTION_TIMEOUT,
    DEFAULT_FUEL_BUDGET, MAX_PLUGIN_MEMORY_BYTES,
};
pub use tools::{
    create_registry as create_tools_registry, BuiltinTool, ToolInvokeContext, ToolInvokeError,
    ToolInvokeResult, ToolsRegistry,
};
