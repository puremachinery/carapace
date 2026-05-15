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
        || managed_plugin_metadata_has_unsupported_links(metadata)
        || !metadata.is_file()
    {
        return Err(managed_plugin_not_regular_file_error(path, label));
    }
    Ok(())
}

fn managed_plugin_metadata_has_unsupported_links(metadata: &std::fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;

        metadata.number_of_links() > 1
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        metadata.nlink() > 1
    }
    #[cfg(all(not(windows), not(unix)))]
    {
        let _ = metadata;
        false
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
        options.custom_flags(libc::O_NOFOLLOW);
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
    // Near-cap warning: emit a single tracing::warn! when the manifest
    // crosses 75% of the cap. The 16 MiB cap fail-closes at the cap
    // edge with a generic ERROR_INVALID_REQUEST; without an early
    // warning, the first signal an operator gets is the next install
    // returning "plugins manifest exceeds maximum size". 75% (12 MiB)
    // gives ~4 MiB of headroom to trim/restructure before the cliff
    // — typically several thousand additional entries depending on
    // metadata richness. Throttle is per-process via the tracing
    // module's own rate limiting / log dedup; the warn fires on every
    // manifest read above the threshold so an operator who fixes the
    // underlying bloat sees the warning stop on the next install.
    const MANIFEST_WARN_THRESHOLD: u64 = MAX_MANAGED_PLUGIN_MANIFEST_BYTES * 3 / 4;
    if len >= MANIFEST_WARN_THRESHOLD {
        tracing::warn!(
            path = %path.display(),
            manifest_bytes = len,
            cap_bytes = MAX_MANAGED_PLUGIN_MANIFEST_BYTES,
            "plugins manifest size approaching cap; trim unused entries before the next \
             install/update operation hits the 16 MiB cliff and refuses the write"
        );
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
