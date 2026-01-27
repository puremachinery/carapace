//! Plugin loader (discover + instantiate WASM modules)
//!
//! Loads WASM plugins from the plugins directory, validates their manifests,
//! and prepares them for instantiation with wasmtime.

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use thiserror::Error;
use wasmtime::{Config, Engine, Module};

/// Plugin loading errors
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
}

impl std::fmt::Debug for LoadedPlugin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoadedPlugin")
            .field("manifest", &self.manifest)
            .field("wasm_path", &self.wasm_path)
            .field("wasm_bytes_len", &self.wasm_bytes.len())
            .finish()
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
}

impl PluginLoader {
    /// Create a new plugin loader
    pub fn new(plugins_dir: PathBuf) -> Result<Self, LoaderError> {
        // Configure wasmtime engine
        let mut config = Config::new();
        config.wasm_component_model(true);
        config.async_support(true);

        let engine = Engine::new(&config).map_err(|e| LoaderError::EngineError(e.to_string()))?;

        Ok(Self {
            engine,
            plugins: RwLock::new(HashMap::new()),
            plugins_dir,
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

    /// Load a single plugin from a WASM file
    pub fn load_plugin(&self, wasm_path: &Path) -> Result<String, LoaderError> {
        // Read the WASM file
        let wasm_bytes = fs::read(wasm_path).map_err(|e| LoaderError::WasmReadError {
            path: wasm_path.display().to_string(),
            message: e.to_string(),
        })?;

        // Compile the module
        let module =
            Module::new(&self.engine, &wasm_bytes).map_err(|e| LoaderError::WasmCompileError {
                path: wasm_path.display().to_string(),
                message: e.to_string(),
            })?;

        // For now, we extract the plugin ID from the filename
        // In a full implementation, we would instantiate the module and call get_manifest()
        let plugin_id = wasm_path
            .file_stem()
            .and_then(|s| s.to_str())
            .ok_or_else(|| LoaderError::InvalidPluginId(wasm_path.display().to_string()))?
            .to_string();

        // Validate plugin ID format
        if !Self::is_valid_plugin_id(&plugin_id) {
            return Err(LoaderError::InvalidPluginId(plugin_id));
        }

        // Check for duplicates
        {
            let plugins = self.plugins.read();
            if plugins.contains_key(&plugin_id) {
                return Err(LoaderError::DuplicatePluginId(plugin_id));
            }
        }

        // Create a placeholder manifest (in production, this would come from the module)
        let manifest = PluginManifest {
            id: plugin_id.clone(),
            name: plugin_id.clone(),
            description: format!("Plugin loaded from {}", wasm_path.display()),
            version: "0.0.0".to_string(),
            kind: PluginKind::Tool, // Default, would be determined from module
        };

        // Create loaded plugin
        let loaded = LoadedPlugin {
            manifest,
            wasm_path: wasm_path.to_path_buf(),
            module,
            wasm_bytes,
        };

        // Store the plugin
        {
            let mut plugins = self.plugins.write();
            plugins.insert(plugin_id.clone(), Arc::new(loaded));
        }

        Ok(plugin_id)
    }

    /// Load a plugin from bytes with a manifest
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

        let plugin_id = manifest.id.clone();

        // Create loaded plugin
        let loaded = LoadedPlugin {
            manifest,
            wasm_path: PathBuf::new(), // No file path for byte-loaded plugins
            module,
            wasm_bytes: wasm_bytes.to_vec(),
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

    /// Reload a plugin from its WASM file
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

        // Unload and reload
        self.unload_plugin(plugin_id)?;
        self.load_plugin(&wasm_path)?;

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
        };
        assert!(manifest.validate().is_ok());

        // Invalid ID (too long)
        let manifest = PluginManifest {
            id: "x".repeat(33),
            name: "Test".to_string(),
            description: "Test".to_string(),
            version: "1.0.0".to_string(),
            kind: PluginKind::Tool,
        };
        assert!(manifest.validate().is_err());

        // Invalid ID (uppercase)
        let manifest = PluginManifest {
            id: "MyPlugin".to_string(),
            name: "Test".to_string(),
            description: "Test".to_string(),
            version: "1.0.0".to_string(),
            kind: PluginKind::Tool,
        };
        assert!(manifest.validate().is_err());

        // Invalid version (no dot)
        let manifest = PluginManifest {
            id: "test".to_string(),
            name: "Test".to_string(),
            description: "Test".to_string(),
            version: "1".to_string(),
            kind: PluginKind::Tool,
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
}
