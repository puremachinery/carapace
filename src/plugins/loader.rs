//! Plugin loader (discover + instantiate WASM modules)
//!
//! Loads WASM plugins from the plugins directory, validates their manifests,
//! and prepares them for instantiation with wasmtime.
//!
//! # Metadata Extraction
//!
//! The loader derives manifest metadata from WASM modules using a layered
//! approach (highest priority first):
//!
//! 1. **Custom section**: A `plugin-manifest` custom section containing JSON
//! 2. **Export inspection**: Determines [`PluginKind`] from which WIT interfaces the
//!    module exports (e.g., `send-text` implies a channel plugin)
//! 3. **File path**: Plugin name derived from the filename, version from modification time

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;
use thiserror::Error;
use wasmtime::{Config, Engine, Module};

/// Plugin loading errors
#[non_exhaustive]
#[derive(Error, Debug)]
pub enum LoaderError {
    #[error("Failed to read plugins directory: {0}")]
    DirectoryReadError(String),

    #[error("Failed to read WASM file {path}: {message}")]
    WasmReadError { path: String, message: String },

    #[error("Failed to compile WASM module {path}: {message}")]
    WasmCompileError { path: String, message: String },

    #[error("Invalid plugin manifest for {plugin_id}: {message}")]
    InvalidManifest { plugin_id: String, message: String },

    #[error("Duplicate plugin ID: {0}")]
    DuplicatePluginId(String),

    #[error("Plugin not found: {0}")]
    PluginNotFound(String),

    #[error("Invalid plugin ID format: {0}")]
    InvalidPluginId(String),

    #[error("Wasmtime engine error: {0}")]
    EngineError(String),

    #[error(
        "Skill hash verification failed for '{skill_name}': expected {expected}, got {actual}"
    )]
    HashVerificationFailed {
        skill_name: String,
        expected: String,
        actual: String,
    },

    #[error("Skill signature verification failed for '{skill_name}': {reason}")]
    SignatureVerificationFailed { skill_name: String, reason: String },
}

/// Plugin kinds supported by the gateway
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PluginKind {
    Channel,
    Tool,
    Webhook,
    Service,
    Provider,
    Hook,
}

impl std::fmt::Display for PluginKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PluginKind::Channel => write!(f, "channel"),
            PluginKind::Tool => write!(f, "tool"),
            PluginKind::Webhook => write!(f, "webhook"),
            PluginKind::Service => write!(f, "service"),
            PluginKind::Provider => write!(f, "provider"),
            PluginKind::Hook => write!(f, "hook"),
        }
    }
}

/// Plugin manifest structure
///
/// Matches the manifest interface in wit/plugin.wit
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginManifest {
    /// Unique plugin identifier (lowercase alphanumeric + hyphens, max 32 chars)
    pub id: String,
    /// Display name (max 64 chars)
    pub name: String,
    /// Description (max 500 chars)
    pub description: String,
    /// Semantic version (e.g., "1.0.0")
    pub version: String,
    /// Plugin kind
    pub kind: PluginKind,
    /// Fine-grained permissions declared by the plugin.
    /// When present, these are validated at load time and enforced at runtime.
    #[serde(default)]
    pub permissions: super::permissions::DeclaredPermissions,
}

impl PluginManifest {
    /// Validate the manifest
    pub fn validate(&self) -> Result<(), LoaderError> {
        // Validate ID format
        if self.id.is_empty() || self.id.len() > 32 {
            return Err(LoaderError::InvalidManifest {
                plugin_id: self.id.clone(),
                message: "ID must be 1-32 characters".to_string(),
            });
        }

        if !self
            .id
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        {
            return Err(LoaderError::InvalidManifest {
                plugin_id: self.id.clone(),
                message: "ID must contain only lowercase alphanumeric and hyphens".to_string(),
            });
        }

        // Validate name
        if self.name.is_empty() || self.name.len() > 64 {
            return Err(LoaderError::InvalidManifest {
                plugin_id: self.id.clone(),
                message: "Name must be 1-64 characters".to_string(),
            });
        }

        // Validate description
        if self.description.len() > 500 {
            return Err(LoaderError::InvalidManifest {
                plugin_id: self.id.clone(),
                message: "Description must be at most 500 characters".to_string(),
            });
        }

        // Validate version (basic semver check)
        if !self.version.contains('.') {
            return Err(LoaderError::InvalidManifest {
                plugin_id: self.id.clone(),
                message: "Version must be in semver format (e.g., 1.0.0)".to_string(),
            });
        }

        Ok(())
    }
}

/// Loaded plugin information
pub struct LoadedPlugin {
    /// Plugin manifest
    pub manifest: PluginManifest,
    /// Path to the WASM file
    pub wasm_path: PathBuf,
    /// Compiled WASM module (can be instantiated multiple times)
    pub module: Module,
    /// Raw WASM bytes (for component instantiation)
    pub wasm_bytes: Vec<u8>,
    /// Discovered WASM capabilities (from import enumeration).
    pub discovered_capabilities: Option<super::sandbox::DiscoveredCapabilities>,
}

impl std::fmt::Debug for LoadedPlugin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoadedPlugin")
            .field("manifest", &self.manifest)
            .field("wasm_path", &self.wasm_path)
            .field("wasm_bytes_len", &self.wasm_bytes.len())
            .field("discovered_capabilities", &self.discovered_capabilities)
            .finish()
    }
}

// ============== WASM Metadata Extraction ==============

/// WASM binary magic bytes (\0asm)
const WASM_MAGIC: [u8; 4] = [0x00, 0x61, 0x73, 0x6D];

/// WASM custom section ID
const WASM_SECTION_CUSTOM: u8 = 0;

/// Expected custom section name for embedded plugin manifests
const PLUGIN_MANIFEST_SECTION: &str = "plugin-manifest";

/// Metadata extracted from a WASM module's binary contents
#[derive(Debug, Default)]
struct WasmModuleMetadata {
    /// Plugin manifest parsed from a `plugin-manifest` custom section (JSON)
    pub manifest_json: Option<PluginManifest>,
    /// Module name from the WASM name section (custom section named "name")
    pub module_name: Option<String>,
}

impl WasmModuleMetadata {
    /// Parse metadata from raw WASM bytes.
    ///
    /// Scans custom sections for:
    /// - `plugin-manifest`: JSON-encoded [`PluginManifest`]
    /// - `name`: The standard WASM name section (extracts the module name)
    fn from_wasm_bytes(bytes: &[u8]) -> Self {
        let mut meta = WasmModuleMetadata::default();

        // Validate magic + version header (8 bytes)
        if bytes.len() < 8 || bytes[..4] != WASM_MAGIC {
            return meta;
        }

        let mut offset = 8; // skip magic (4) + version (4)

        while offset < bytes.len() {
            // Each section: section_id (1 byte) + LEB128 size + payload
            let section_id = bytes[offset];
            offset += 1;

            let (section_size, bytes_read) = match read_leb128_u32(bytes, offset) {
                Some(v) => v,
                None => break,
            };
            offset += bytes_read;

            let section_end = offset + section_size as usize;
            if section_end > bytes.len() {
                break;
            }

            if section_id == WASM_SECTION_CUSTOM {
                // Custom section payload: name_len (LEB128) + name_bytes + data
                let payload = &bytes[offset..section_end];
                if let Some((name, data)) = parse_custom_section_name(payload) {
                    if name == PLUGIN_MANIFEST_SECTION {
                        if let Ok(manifest) = serde_json::from_slice::<PluginManifest>(data) {
                            tracing::debug!(
                                plugin_id = %manifest.id,
                                "Found plugin-manifest custom section"
                            );
                            meta.manifest_json = Some(manifest);
                        } else {
                            tracing::warn!(
                                "Found plugin-manifest custom section but failed to parse as JSON"
                            );
                        }
                    } else if name == "name" {
                        // The WASM name section encodes module name as subsection 0:
                        // subsection_id (1 byte) + LEB128 size + name_len (LEB128) + name_bytes
                        meta.module_name = parse_name_section_module_name(data);
                    }
                }
            }

            offset = section_end;
        }

        meta
    }
}

/// Read a LEB128-encoded u32 from `bytes` starting at `offset`.
/// Returns `(value, bytes_consumed)` or `None` if the data is truncated.
fn read_leb128_u32(bytes: &[u8], offset: usize) -> Option<(u32, usize)> {
    let mut result: u32 = 0;
    let mut shift: u32 = 0;
    let mut pos = offset;

    loop {
        if pos >= bytes.len() {
            return None;
        }
        let byte = bytes[pos];
        pos += 1;

        result |= ((byte & 0x7F) as u32) << shift;
        if byte & 0x80 == 0 {
            return Some((result, pos - offset));
        }
        shift += 7;
        if shift >= 35 {
            // Malformed LEB128
            return None;
        }
    }
}

/// Parse the name and data from a custom section payload.
///
/// Custom section payload layout: `name_len` (LEB128) + `name` (UTF-8) + `data`
fn parse_custom_section_name(payload: &[u8]) -> Option<(&str, &[u8])> {
    let (name_len, bytes_read) = read_leb128_u32(payload, 0)?;
    let name_start = bytes_read;
    let name_end = name_start + name_len as usize;
    if name_end > payload.len() {
        return None;
    }
    let name = std::str::from_utf8(&payload[name_start..name_end]).ok()?;
    let data = &payload[name_end..];
    Some((name, data))
}

/// Parse the module name from a WASM name section.
///
/// The name section contains subsections. Subsection 0 is the module name:
/// `subsection_id(1)` + `subsection_size(LEB128)` + `name_len(LEB128)` + `name_bytes`
fn parse_name_section_module_name(data: &[u8]) -> Option<String> {
    if data.is_empty() {
        return None;
    }

    let mut offset = 0;
    while offset < data.len() {
        let subsection_id = data[offset];
        offset += 1;

        let (subsection_size, bytes_read) = read_leb128_u32(data, offset)?;
        offset += bytes_read;

        let subsection_end = offset + subsection_size as usize;
        if subsection_end > data.len() {
            return None;
        }

        if subsection_id == 0 {
            // Module name subsection: name_len (LEB128) + name_bytes
            let (name_len, name_bytes_read) = read_leb128_u32(data, offset)?;
            let name_start = offset + name_bytes_read;
            let name_end = name_start + name_len as usize;
            if name_end > data.len() {
                return None;
            }
            return std::str::from_utf8(&data[name_start..name_end])
                .ok()
                .map(|s| s.to_string());
        }

        offset = subsection_end;
    }

    None
}

/// Determine [`PluginKind`] by inspecting which WIT interface exports a WASM module provides.
///
/// Export name matching uses the WIT interface export naming conventions from
/// `wit/plugin.wit`. The first match wins, in priority order:
///
/// 1. Channel: exports containing `send-text` or `channel-adapter`
/// 2. Tool: exports containing `invoke` or `get-definitions`
/// 3. Webhook: exports containing `get-paths` (webhook-specific)
/// 4. Service: exports containing `health` or `service`
/// 5. Provider: exports containing `complete` or `list-models`
/// 6. Hook: exports containing `get-hooks`
/// 7. Default: [`PluginKind::Tool`]
fn derive_plugin_kind_from_exports(module: &Module) -> PluginKind {
    let export_names: Vec<&str> = module.exports().map(|e| e.name()).collect();

    let has = |needle: &str| export_names.iter().any(|name| name.contains(needle));

    if has("send-text") || has("channel-adapter") || has("channel-meta") {
        PluginKind::Channel
    } else if has("get-definitions") || has("execute-tool") {
        PluginKind::Tool
    } else if has("get-paths") || has("webhook") {
        PluginKind::Webhook
    } else if has("health") || has("service") {
        PluginKind::Service
    } else if has("complete") || has("list-models") || has("provider") {
        PluginKind::Provider
    } else if has("get-hooks") || has("hooks") {
        PluginKind::Hook
    } else {
        // Default to Tool when exports are unrecognizable (matches prior behavior)
        PluginKind::Tool
    }
}

/// Derive a semver-like version string from a file's modification timestamp.
///
/// Format: `0.0.YYYYMMDDHHMMSS` -- the major and minor components are zero to
/// indicate the version was auto-derived rather than declared by the plugin
/// author. Returns `"0.0.0"` if the timestamp cannot be read.
fn derive_version_from_file(path: &Path) -> String {
    fs::metadata(path)
        .ok()
        .and_then(|m| m.modified().ok())
        .map(|mtime| {
            let duration = mtime
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default();
            let secs = duration.as_secs();
            // Convert to a compact date-time integer: YYYYMMDDHHMMSS
            // We use chrono-free arithmetic (86400s/day, etc.)
            let days = secs / 86400;
            let time_of_day = secs % 86400;
            let hours = time_of_day / 3600;
            let minutes = (time_of_day % 3600) / 60;
            let seconds = time_of_day % 60;

            // Civil date from days since epoch (simplified algorithm)
            let (year, month, day) = civil_from_days(days as i64);

            format!(
                "0.0.{}{:02}{:02}{:02}{:02}{:02}",
                year, month, day, hours, minutes, seconds
            )
        })
        .unwrap_or_else(|| "0.0.0".to_string())
}

/// Convert days since Unix epoch to (year, month, day).
///
/// Uses Howard Hinnant's algorithm for civil date from days.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

/// Convert a kebab-case plugin ID to a human-readable display name.
///
/// Examples:
/// - `"my-plugin"` -> `"My Plugin"`
/// - `"slack"` -> `"Slack"`
/// - `"ms-teams-bot"` -> `"Ms Teams Bot"`
fn derive_display_name(plugin_id: &str) -> String {
    plugin_id
        .split('-')
        .map(|word| {
            let mut chars = word.chars();
            match chars.next() {
                None => String::new(),
                Some(c) => {
                    let mut s = c.to_uppercase().to_string();
                    s.extend(chars);
                    s
                }
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Derive a complete [`PluginManifest`] from a WASM module and its file path.
///
/// The derivation order (highest priority first):
///
/// 1. If the WASM bytes contain a `plugin-manifest` custom section with valid JSON,
///    that manifest is used directly.
/// 2. Otherwise, metadata is assembled from:
///    - **id**: file stem (e.g. `my-plugin.wasm` -> `my-plugin`)
///    - **name**: derived display name from the module's name section, or from the file
///      stem if no name section is present
///    - **version**: derived from the file's modification timestamp
///    - **kind**: determined by inspecting module exports
///    - **description**: states the source file path
fn derive_manifest(
    plugin_id: &str,
    wasm_path: &Path,
    wasm_bytes: &[u8],
    module: &Module,
) -> PluginManifest {
    // Try to extract metadata from WASM binary custom sections
    let wasm_meta = WasmModuleMetadata::from_wasm_bytes(wasm_bytes);

    // If we found a complete manifest in a custom section, use it directly
    if let Some(manifest) = wasm_meta.manifest_json {
        tracing::debug!(
            plugin_id = %manifest.id,
            "Using manifest from plugin-manifest custom section"
        );
        return manifest;
    }

    // Derive individual fields with fallbacks
    let name = wasm_meta
        .module_name
        .unwrap_or_else(|| derive_display_name(plugin_id));

    let version = derive_version_from_file(wasm_path);

    let kind = derive_plugin_kind_from_exports(module);

    let description = format!(
        "{} plugin loaded from {}",
        kind,
        wasm_path
            .file_name()
            .and_then(|f| f.to_str())
            .unwrap_or("unknown"),
    );

    tracing::debug!(
        plugin_id = %plugin_id,
        derived_name = %name,
        derived_version = %version,
        derived_kind = %kind,
        "Derived manifest metadata from WASM module"
    );

    PluginManifest {
        id: plugin_id.to_string(),
        name,
        description,
        version,
        kind,
        permissions: super::permissions::DeclaredPermissions::default(),
    }
}

/// Name of the skills manifest file stored alongside WASM binaries.
const SKILLS_MANIFEST_FILE: &str = "skills-manifest.json";

/// Compute the SHA-256 hash of the given bytes and return it as a lowercase hex string.
fn compute_sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let hash = hasher.finalize();
    hex::encode(hash)
}

/// Verify that a skill's WASM bytes match the expected SHA-256 hash stored in the
/// skills manifest.
///
/// If no manifest entry or no `sha256` field exists for the skill (legacy entry),
/// verification is skipped with a warning log and `Ok(())` is returned.
pub fn verify_skill_hash_on_load(
    skill_name: &str,
    wasm_bytes: &[u8],
    manifest: &serde_json::Value,
) -> Result<(), LoaderError> {
    let expected_hash = manifest
        .get(skill_name)
        .and_then(|entry| entry.get("sha256"))
        .and_then(|v| v.as_str());

    match expected_hash {
        Some(expected) => {
            let actual = compute_sha256_hex(wasm_bytes);
            if actual != expected {
                tracing::error!(
                    skill = %skill_name,
                    expected = %expected,
                    actual = %actual,
                    "skill hash mismatch — possible tampering detected"
                );
                return Err(LoaderError::HashVerificationFailed {
                    skill_name: skill_name.to_string(),
                    expected: expected.to_string(),
                    actual,
                });
            }
            tracing::debug!(
                skill = %skill_name,
                sha256 = %actual,
                "skill hash verification passed"
            );
            Ok(())
        }
        None => {
            tracing::warn!(
                skill = %skill_name,
                "no sha256 hash in manifest for skill, skipping verification (legacy entry)"
            );
            Ok(())
        }
    }
}

/// Load the skills manifest from the given directory.
/// Returns `None` if the manifest file does not exist.
pub fn load_skills_manifest(skills_dir: &Path) -> Option<serde_json::Value> {
    let manifest_path = skills_dir.join(SKILLS_MANIFEST_FILE);
    match fs::read_to_string(&manifest_path) {
        Ok(contents) => Some(serde_json::from_str(&contents).unwrap_or_default()),
        Err(_) => None,
    }
}

/// Plugin loader that manages discovery and loading of WASM plugins
pub struct PluginLoader {
    /// Wasmtime engine (shared across all plugins)
    engine: Engine,
    /// Loaded plugins by ID
    plugins: RwLock<HashMap<String, Arc<LoadedPlugin>>>,
    /// Plugins directory
    plugins_dir: PathBuf,
    /// Signature verification configuration
    signature_config: super::signature::SignatureConfig,
}

impl PluginLoader {
    /// Create a new plugin loader
    pub fn new(plugins_dir: PathBuf) -> Result<Self, LoaderError> {
        Self::with_signature_config(plugins_dir, super::signature::SignatureConfig::default())
    }

    /// Create a new plugin loader with explicit signature config
    pub fn with_signature_config(
        plugins_dir: PathBuf,
        signature_config: super::signature::SignatureConfig,
    ) -> Result<Self, LoaderError> {
        // Configure wasmtime engine
        let mut config = Config::new();
        config.wasm_component_model(true);
        config.async_support(true);

        let engine = Engine::new(&config).map_err(|e| LoaderError::EngineError(e.to_string()))?;

        Ok(Self {
            engine,
            plugins: RwLock::new(HashMap::new()),
            plugins_dir,
            signature_config,
        })
    }

    /// Get the wasmtime engine
    pub fn engine(&self) -> &Engine {
        &self.engine
    }

    /// Get the plugins directory
    pub fn plugins_dir(&self) -> &Path {
        &self.plugins_dir
    }

    /// Discover and load all plugins from the plugins directory
    pub fn load_all(&self) -> Result<Vec<String>, LoaderError> {
        if !self.plugins_dir.exists() {
            tracing::debug!(
                plugins_dir = %self.plugins_dir.display(),
                "Plugins directory does not exist, skipping plugin loading"
            );
            return Ok(Vec::new());
        }

        let entries = fs::read_dir(&self.plugins_dir)
            .map_err(|e| LoaderError::DirectoryReadError(e.to_string()))?;

        let mut loaded_ids = Vec::new();

        for entry in entries {
            let entry = entry.map_err(|e| LoaderError::DirectoryReadError(e.to_string()))?;
            let path = entry.path();

            // Only process .wasm files
            if path.extension().map(|e| e == "wasm").unwrap_or(false) {
                match self.load_plugin(&path) {
                    Ok(plugin_id) => {
                        tracing::info!(
                            plugin_id = %plugin_id,
                            path = %path.display(),
                            "Loaded plugin"
                        );
                        loaded_ids.push(plugin_id);
                    }
                    Err(e) => {
                        tracing::warn!(
                            path = %path.display(),
                            error = %e,
                            "Failed to load plugin"
                        );
                    }
                }
            }
        }

        Ok(loaded_ids)
    }

    /// Core loading logic: reads, verifies, and compiles a WASM plugin
    /// without inserting it into the plugin map.
    fn load_plugin_inner(
        &self,
        wasm_path: &Path,
    ) -> Result<(String, Arc<LoadedPlugin>), LoaderError> {
        // Read the WASM file
        let wasm_bytes = fs::read(wasm_path).map_err(|e| LoaderError::WasmReadError {
            path: wasm_path.display().to_string(),
            message: e.to_string(),
        })?;

        // Read manifest once
        let manifest_json = wasm_path.parent().and_then(load_skills_manifest);

        // Verify SHA-256 hash against the skills manifest (if present)
        if let Some(ref manifest) = manifest_json {
            if let Some(stem) = wasm_path.file_stem().and_then(|s| s.to_str()) {
                verify_skill_hash_on_load(stem, &wasm_bytes, manifest)?;
            }
        }

        // Verify Ed25519 signature against the skills manifest (if present)
        if let Some(ref manifest) = manifest_json {
            if let Some(stem) = wasm_path.file_stem().and_then(|s| s.to_str()) {
                super::signature::verify_skill_signature(
                    stem,
                    &wasm_bytes,
                    manifest,
                    &self.signature_config,
                )?;
            }
        }

        // Compile the module
        let module =
            Module::new(&self.engine, &wasm_bytes).map_err(|e| LoaderError::WasmCompileError {
                path: wasm_path.display().to_string(),
                message: e.to_string(),
            })?;

        let discovered_capabilities = Some(super::sandbox::enumerate_capabilities(&module));

        let plugin_id = wasm_path
            .file_stem()
            .and_then(|s| s.to_str())
            .ok_or_else(|| LoaderError::InvalidPluginId(wasm_path.display().to_string()))?
            .to_string();

        if !Self::is_valid_plugin_id(&plugin_id) {
            return Err(LoaderError::InvalidPluginId(plugin_id));
        }

        let plugin_manifest = derive_manifest(&plugin_id, wasm_path, &wasm_bytes, &module);

        let loaded = Arc::new(LoadedPlugin {
            manifest: plugin_manifest,
            wasm_path: wasm_path.to_path_buf(),
            module,
            wasm_bytes,
            discovered_capabilities,
        });

        Ok((plugin_id, loaded))
    }

    /// Load a single plugin from a WASM file
    pub fn load_plugin(&self, wasm_path: &Path) -> Result<String, LoaderError> {
        let (plugin_id, loaded) = self.load_plugin_inner(wasm_path)?;

        // Check for duplicates
        {
            let plugins = self.plugins.read();
            if plugins.contains_key(&plugin_id) {
                return Err(LoaderError::DuplicatePluginId(plugin_id));
            }
        }

        // Store the plugin
        {
            let mut plugins = self.plugins.write();
            plugins.insert(plugin_id.clone(), loaded);
        }

        Ok(plugin_id)
    }

    /// Load a plugin from bytes with a manifest
    #[cfg(test)]
    pub fn load_plugin_from_bytes(
        &self,
        manifest: PluginManifest,
        wasm_bytes: &[u8],
    ) -> Result<String, LoaderError> {
        // Validate manifest
        manifest.validate()?;

        // Check for duplicates
        {
            let plugins = self.plugins.read();
            if plugins.contains_key(&manifest.id) {
                return Err(LoaderError::DuplicatePluginId(manifest.id.clone()));
            }
        }

        // Compile the module
        let module =
            Module::new(&self.engine, wasm_bytes).map_err(|e| LoaderError::WasmCompileError {
                path: format!("<bytes:{}>", manifest.id),
                message: e.to_string(),
            })?;

        // Enumerate WASM capabilities for sandbox checking
        let discovered_capabilities = Some(super::sandbox::enumerate_capabilities(&module));

        let plugin_id = manifest.id.clone();

        // Create loaded plugin
        let loaded = LoadedPlugin {
            manifest,
            wasm_path: PathBuf::new(), // No file path for byte-loaded plugins
            module,
            wasm_bytes: wasm_bytes.to_vec(),
            discovered_capabilities,
        };

        // Store the plugin
        {
            let mut plugins = self.plugins.write();
            plugins.insert(plugin_id.clone(), Arc::new(loaded));
        }

        Ok(plugin_id)
    }

    /// Get a loaded plugin by ID
    pub fn get_plugin(&self, plugin_id: &str) -> Option<Arc<LoadedPlugin>> {
        let plugins = self.plugins.read();
        plugins.get(plugin_id).cloned()
    }

    /// Get all loaded plugin IDs
    pub fn list_plugins(&self) -> Vec<String> {
        let plugins = self.plugins.read();
        plugins.keys().cloned().collect()
    }

    /// Get all loaded plugins of a specific kind
    pub fn list_plugins_by_kind(&self, kind: PluginKind) -> Vec<Arc<LoadedPlugin>> {
        let plugins = self.plugins.read();
        plugins
            .values()
            .filter(|p| p.manifest.kind == kind)
            .cloned()
            .collect()
    }

    /// Unload a plugin by ID
    pub fn unload_plugin(&self, plugin_id: &str) -> Result<(), LoaderError> {
        let mut plugins = self.plugins.write();
        if plugins.remove(plugin_id).is_none() {
            return Err(LoaderError::PluginNotFound(plugin_id.to_string()));
        }
        Ok(())
    }

    /// Reload a plugin from its WASM file.
    ///
    /// The new module is compiled and verified *before* replacing the old one,
    /// so the plugin stays available if the reload fails.
    pub fn reload_plugin(&self, plugin_id: &str) -> Result<(), LoaderError> {
        let wasm_path = {
            let plugins = self.plugins.read();
            let plugin = plugins
                .get(plugin_id)
                .ok_or_else(|| LoaderError::PluginNotFound(plugin_id.to_string()))?;
            plugin.wasm_path.clone()
        };

        if wasm_path.as_os_str().is_empty() {
            return Err(LoaderError::PluginNotFound(format!(
                "{} (byte-loaded, cannot reload)",
                plugin_id
            )));
        }

        // Load new plugin first, then swap atomically
        let (_, new_plugin) = self.load_plugin_inner(&wasm_path)?;
        let mut plugins = self.plugins.write();
        plugins.insert(plugin_id.to_string(), new_plugin);

        Ok(())
    }

    /// Check if a plugin ID is valid
    fn is_valid_plugin_id(id: &str) -> bool {
        !id.is_empty()
            && id.len() <= 32
            && id
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_plugin_manifest_validation() {
        // Valid manifest
        let manifest = PluginManifest {
            id: "my-plugin".to_string(),
            name: "My Plugin".to_string(),
            description: "A test plugin".to_string(),
            version: "1.0.0".to_string(),
            kind: PluginKind::Tool,
            permissions: Default::default(),
        };
        assert!(manifest.validate().is_ok());

        // Invalid ID (too long)
        let manifest = PluginManifest {
            id: "x".repeat(33),
            name: "Test".to_string(),
            description: "Test".to_string(),
            version: "1.0.0".to_string(),
            kind: PluginKind::Tool,
            permissions: Default::default(),
        };
        assert!(manifest.validate().is_err());

        // Invalid ID (uppercase)
        let manifest = PluginManifest {
            id: "MyPlugin".to_string(),
            name: "Test".to_string(),
            description: "Test".to_string(),
            version: "1.0.0".to_string(),
            kind: PluginKind::Tool,
            permissions: Default::default(),
        };
        assert!(manifest.validate().is_err());

        // Invalid version (no dot)
        let manifest = PluginManifest {
            id: "test".to_string(),
            name: "Test".to_string(),
            description: "Test".to_string(),
            version: "1".to_string(),
            kind: PluginKind::Tool,
            permissions: Default::default(),
        };
        assert!(manifest.validate().is_err());
    }

    #[test]
    fn test_valid_plugin_id() {
        assert!(PluginLoader::is_valid_plugin_id("my-plugin"));
        assert!(PluginLoader::is_valid_plugin_id("plugin123"));
        assert!(PluginLoader::is_valid_plugin_id("a"));
        assert!(PluginLoader::is_valid_plugin_id("a-b-c"));

        assert!(!PluginLoader::is_valid_plugin_id(""));
        assert!(!PluginLoader::is_valid_plugin_id("My-Plugin")); // uppercase
        assert!(!PluginLoader::is_valid_plugin_id("plugin_name")); // underscore
        assert!(!PluginLoader::is_valid_plugin_id(&"x".repeat(33))); // too long
    }

    #[test]
    fn test_plugin_loader_creation() {
        let temp_dir = tempdir().unwrap();
        let loader = PluginLoader::new(temp_dir.path().to_path_buf());
        assert!(loader.is_ok());
    }

    #[test]
    fn test_load_all_empty_dir() {
        let temp_dir = tempdir().unwrap();
        let loader = PluginLoader::new(temp_dir.path().to_path_buf()).unwrap();
        let result = loader.load_all();
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn test_load_all_nonexistent_dir() {
        let loader = PluginLoader::new(PathBuf::from("/nonexistent/plugins/dir")).unwrap();
        let result = loader.load_all();
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn test_plugin_kind_display() {
        assert_eq!(PluginKind::Channel.to_string(), "channel");
        assert_eq!(PluginKind::Tool.to_string(), "tool");
        assert_eq!(PluginKind::Webhook.to_string(), "webhook");
        assert_eq!(PluginKind::Service.to_string(), "service");
        assert_eq!(PluginKind::Provider.to_string(), "provider");
        assert_eq!(PluginKind::Hook.to_string(), "hook");
    }

    #[test]
    fn test_unload_nonexistent_plugin() {
        let temp_dir = tempdir().unwrap();
        let loader = PluginLoader::new(temp_dir.path().to_path_buf()).unwrap();

        let result = loader.unload_plugin("nonexistent");
        assert!(matches!(result, Err(LoaderError::PluginNotFound(_))));
    }

    // ============== WASM Metadata Extraction Tests ==============

    #[test]
    fn test_derive_display_name_single_word() {
        assert_eq!(derive_display_name("slack"), "Slack");
    }

    #[test]
    fn test_derive_display_name_multi_word() {
        assert_eq!(derive_display_name("my-plugin"), "My Plugin");
    }

    #[test]
    fn test_derive_display_name_three_words() {
        assert_eq!(derive_display_name("ms-teams-bot"), "Ms Teams Bot");
    }

    #[test]
    fn test_derive_display_name_empty() {
        assert_eq!(derive_display_name(""), "");
    }

    #[test]
    fn test_derive_display_name_numeric() {
        assert_eq!(derive_display_name("plugin-123"), "Plugin 123");
    }

    #[test]
    fn test_read_leb128_u32_single_byte() {
        // Value 5 -> [0x05]
        let bytes = [0x05];
        let (value, consumed) = read_leb128_u32(&bytes, 0).unwrap();
        assert_eq!(value, 5);
        assert_eq!(consumed, 1);
    }

    #[test]
    fn test_read_leb128_u32_multi_byte() {
        // Value 624485 -> [0xE5, 0x8E, 0x26]
        let bytes = [0xE5, 0x8E, 0x26];
        let (value, consumed) = read_leb128_u32(&bytes, 0).unwrap();
        assert_eq!(value, 624485);
        assert_eq!(consumed, 3);
    }

    #[test]
    fn test_read_leb128_u32_with_offset() {
        let bytes = [0xFF, 0x05]; // padding byte, then value 5
        let (value, consumed) = read_leb128_u32(&bytes, 1).unwrap();
        assert_eq!(value, 5);
        assert_eq!(consumed, 1);
    }

    #[test]
    fn test_read_leb128_u32_empty() {
        let bytes: [u8; 0] = [];
        assert!(read_leb128_u32(&bytes, 0).is_none());
    }

    #[test]
    fn test_read_leb128_u32_truncated() {
        // Continuation bit set but no following byte
        let bytes = [0x80];
        assert!(read_leb128_u32(&bytes, 0).is_none());
    }

    #[test]
    fn test_parse_custom_section_name() {
        // Custom section with name "test" (4 bytes) and data "hello"
        let mut payload = vec![4]; // name length
        payload.extend_from_slice(b"test"); // name
        payload.extend_from_slice(b"hello"); // data

        let (name, data) = parse_custom_section_name(&payload).unwrap();
        assert_eq!(name, "test");
        assert_eq!(data, b"hello");
    }

    #[test]
    fn test_parse_custom_section_name_empty_data() {
        let mut payload = vec![3]; // name length
        payload.extend_from_slice(b"foo"); // name, no data after

        let (name, data) = parse_custom_section_name(&payload).unwrap();
        assert_eq!(name, "foo");
        assert!(data.is_empty());
    }

    #[test]
    fn test_parse_custom_section_name_invalid_utf8() {
        let payload = vec![2, 0xFF, 0xFE]; // name length 2, invalid UTF-8
        assert!(parse_custom_section_name(&payload).is_none());
    }

    /// Helper: build a minimal WASM binary with a custom section
    fn build_wasm_with_custom_section(section_name: &str, section_data: &[u8]) -> Vec<u8> {
        let mut wasm = Vec::new();

        // WASM header: magic + version
        wasm.extend_from_slice(&WASM_MAGIC);
        wasm.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]); // version 1

        // Custom section: id=0, then LEB128 size, then name-len + name + data
        let name_bytes = section_name.as_bytes();
        let mut section_payload = Vec::new();
        // Name length (LEB128)
        write_leb128_u32(&mut section_payload, name_bytes.len() as u32);
        // Name bytes
        section_payload.extend_from_slice(name_bytes);
        // Section data
        section_payload.extend_from_slice(section_data);

        // Section header: id + payload size
        wasm.push(WASM_SECTION_CUSTOM);
        write_leb128_u32(&mut wasm, section_payload.len() as u32);
        wasm.extend_from_slice(&section_payload);

        wasm
    }

    /// Helper: write a u32 as LEB128 to a byte vector
    fn write_leb128_u32(buf: &mut Vec<u8>, mut value: u32) {
        loop {
            let mut byte = (value & 0x7F) as u8;
            value >>= 7;
            if value != 0 {
                byte |= 0x80;
            }
            buf.push(byte);
            if value == 0 {
                break;
            }
        }
    }

    #[test]
    fn test_wasm_metadata_from_empty_bytes() {
        let meta = WasmModuleMetadata::from_wasm_bytes(&[]);
        assert!(meta.manifest_json.is_none());
        assert!(meta.module_name.is_none());
    }

    #[test]
    fn test_wasm_metadata_from_invalid_magic() {
        let meta =
            WasmModuleMetadata::from_wasm_bytes(&[0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00]);
        assert!(meta.manifest_json.is_none());
        assert!(meta.module_name.is_none());
    }

    #[test]
    fn test_wasm_metadata_from_valid_wasm_no_sections() {
        // Minimal valid WASM: just magic + version, no sections
        let wasm = [0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00];
        let meta = WasmModuleMetadata::from_wasm_bytes(&wasm);
        assert!(meta.manifest_json.is_none());
        assert!(meta.module_name.is_none());
    }

    #[test]
    fn test_wasm_metadata_plugin_manifest_section() {
        let manifest_json = serde_json::json!({
            "id": "test-plugin",
            "name": "Test Plugin",
            "description": "A test plugin from custom section",
            "version": "1.2.3",
            "kind": "tool"
        });
        let json_bytes = serde_json::to_vec(&manifest_json).unwrap();

        let wasm = build_wasm_with_custom_section(PLUGIN_MANIFEST_SECTION, &json_bytes);
        let meta = WasmModuleMetadata::from_wasm_bytes(&wasm);

        assert!(meta.manifest_json.is_some());
        let manifest = meta.manifest_json.unwrap();
        assert_eq!(manifest.id, "test-plugin");
        assert_eq!(manifest.name, "Test Plugin");
        assert_eq!(manifest.description, "A test plugin from custom section");
        assert_eq!(manifest.version, "1.2.3");
        assert_eq!(manifest.kind, PluginKind::Tool);
    }

    #[test]
    fn test_wasm_metadata_invalid_manifest_json() {
        // Invalid JSON in plugin-manifest section should be ignored
        let wasm = build_wasm_with_custom_section(PLUGIN_MANIFEST_SECTION, b"not valid json{{{");
        let meta = WasmModuleMetadata::from_wasm_bytes(&wasm);
        assert!(meta.manifest_json.is_none());
    }

    #[test]
    fn test_wasm_metadata_unrelated_custom_section() {
        // A custom section with a different name should be ignored
        let wasm = build_wasm_with_custom_section("producers", b"some data");
        let meta = WasmModuleMetadata::from_wasm_bytes(&wasm);
        assert!(meta.manifest_json.is_none());
        assert!(meta.module_name.is_none());
    }

    #[test]
    fn test_wasm_metadata_name_section() {
        // Build a name section with module name (subsection 0)
        let module_name = "my-cool-module";
        let name_bytes = module_name.as_bytes();

        let mut subsection = Vec::new();
        // Subsection ID 0 = module name
        subsection.push(0);
        // Subsection size (name_len_leb + name_bytes)
        let mut name_content = Vec::new();
        write_leb128_u32(&mut name_content, name_bytes.len() as u32);
        name_content.extend_from_slice(name_bytes);
        write_leb128_u32(&mut subsection, name_content.len() as u32);
        subsection.extend_from_slice(&name_content);

        let wasm = build_wasm_with_custom_section("name", &subsection);
        let meta = WasmModuleMetadata::from_wasm_bytes(&wasm);

        assert!(meta.manifest_json.is_none());
        assert_eq!(meta.module_name.as_deref(), Some("my-cool-module"));
    }

    #[test]
    fn test_derive_version_from_file_returns_timestamp_version() {
        let temp_dir = tempdir().unwrap();
        let file_path = temp_dir.path().join("test.wasm");
        fs::write(&file_path, b"test").unwrap();

        let version = derive_version_from_file(&file_path);
        // Version should start with "0.0." and have a date-time suffix
        assert!(
            version.starts_with("0.0."),
            "Version should start with '0.0.', got: {}",
            version
        );
        // The rest should be digits (YYYYMMDDHHMMSS)
        let date_part = &version[4..];
        assert!(
            date_part.chars().all(|c| c.is_ascii_digit()),
            "Date part should be all digits, got: {}",
            date_part
        );
        // Should be 14 digits (YYYYMMDDHHMMSS)
        assert_eq!(
            date_part.len(),
            14,
            "Date part should be 14 digits, got: {}",
            date_part
        );
    }

    #[test]
    fn test_derive_version_from_nonexistent_file() {
        let version = derive_version_from_file(Path::new("/nonexistent/file.wasm"));
        assert_eq!(version, "0.0.0");
    }

    #[test]
    fn test_civil_from_days_epoch() {
        // Day 0 = January 1, 1970
        let (y, m, d) = civil_from_days(0);
        assert_eq!((y, m, d), (1970, 1, 1));
    }

    #[test]
    fn test_civil_from_days_known_date() {
        // 2024-01-15 is day 19737 from epoch
        // (2024-01-01 is day 19723, +14 = 19737)
        let (y, m, d) = civil_from_days(19737);
        assert_eq!((y, m, d), (2024, 1, 15));
    }

    #[test]
    fn test_civil_from_days_leap_year() {
        // 2024-02-29 is day 19782 (2024 is a leap year)
        let (y, m, d) = civil_from_days(19782);
        assert_eq!((y, m, d), (2024, 2, 29));
    }

    #[test]
    fn test_leb128_roundtrip() {
        let mut buf = Vec::new();
        write_leb128_u32(&mut buf, 42);
        let (value, _) = read_leb128_u32(&buf, 0).unwrap();
        assert_eq!(value, 42);
    }

    #[test]
    fn test_leb128_roundtrip_large() {
        let mut buf = Vec::new();
        write_leb128_u32(&mut buf, 1_000_000);
        let (value, _) = read_leb128_u32(&buf, 0).unwrap();
        assert_eq!(value, 1_000_000);
    }

    #[test]
    fn test_leb128_roundtrip_zero() {
        let mut buf = Vec::new();
        write_leb128_u32(&mut buf, 0);
        let (value, consumed) = read_leb128_u32(&buf, 0).unwrap();
        assert_eq!(value, 0);
        assert_eq!(consumed, 1);
    }

    #[test]
    fn test_wasm_metadata_multiple_custom_sections() {
        // Build a WASM binary with two custom sections: an unrelated one, then plugin-manifest
        let manifest_json = serde_json::json!({
            "id": "multi-section",
            "name": "Multi Section Plugin",
            "description": "Has multiple custom sections",
            "version": "2.0.0",
            "kind": "channel"
        });
        let json_bytes = serde_json::to_vec(&manifest_json).unwrap();

        let mut wasm = Vec::new();
        // WASM header
        wasm.extend_from_slice(&WASM_MAGIC);
        wasm.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]);

        // First custom section: "producers"
        {
            let name = b"producers";
            let data = b"some producer data";
            let mut payload = Vec::new();
            write_leb128_u32(&mut payload, name.len() as u32);
            payload.extend_from_slice(name);
            payload.extend_from_slice(data);

            wasm.push(WASM_SECTION_CUSTOM);
            write_leb128_u32(&mut wasm, payload.len() as u32);
            wasm.extend_from_slice(&payload);
        }

        // Second custom section: "plugin-manifest"
        {
            let name = PLUGIN_MANIFEST_SECTION.as_bytes();
            let mut payload = Vec::new();
            write_leb128_u32(&mut payload, name.len() as u32);
            payload.extend_from_slice(name);
            payload.extend_from_slice(&json_bytes);

            wasm.push(WASM_SECTION_CUSTOM);
            write_leb128_u32(&mut wasm, payload.len() as u32);
            wasm.extend_from_slice(&payload);
        }

        let meta = WasmModuleMetadata::from_wasm_bytes(&wasm);
        assert!(meta.manifest_json.is_some());
        let manifest = meta.manifest_json.unwrap();
        assert_eq!(manifest.id, "multi-section");
        assert_eq!(manifest.kind, PluginKind::Channel);
    }

    #[test]
    fn test_parse_name_section_empty_data() {
        assert!(parse_name_section_module_name(&[]).is_none());
    }

    #[test]
    fn test_parse_name_section_no_module_name_subsection() {
        // Subsection 1 (function names) instead of 0 (module name)
        let mut data = Vec::new();
        data.push(1); // subsection ID = 1 (not module name)
        let inner = b"\x01X"; // 1-byte name "X"
        write_leb128_u32(&mut data, inner.len() as u32);
        data.extend_from_slice(inner);

        assert!(parse_name_section_module_name(&data).is_none());
    }
}
