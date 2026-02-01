//! Capability sandboxing for WASM plugins.
//!
//! Enumerates WASM module imports to discover required capabilities, then
//! enforces a capability policy that restricts which host functions a
//! plugin may call.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use wasmtime::Module;

/// WASM capabilities that can be discovered from module imports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WasmCapability {
    /// HTTP fetch operations.
    Http,
    /// Credential get/set operations.
    Credentials,
    /// Media fetch operations.
    Media,
    /// Config access (always allowed).
    Config,
    /// Logging operations (always allowed).
    Logging,
}

impl std::fmt::Display for WasmCapability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WasmCapability::Http => write!(f, "http"),
            WasmCapability::Credentials => write!(f, "credentials"),
            WasmCapability::Media => write!(f, "media"),
            WasmCapability::Config => write!(f, "config"),
            WasmCapability::Logging => write!(f, "logging"),
        }
    }
}

/// Per-skill capability policy.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CapabilityPolicy {
    /// Allow HTTP fetch operations.
    #[serde(default)]
    pub allow_http: bool,
    /// Allow credential get/set operations.
    #[serde(default)]
    pub allow_credentials: bool,
    /// Allow media fetch operations.
    #[serde(default)]
    pub allow_media: bool,
}

/// Sandbox configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxConfig {
    /// Master switch — when `false`, capability checks are skipped.
    /// Defaults to `true` so the sandbox is active unless explicitly disabled.
    #[serde(default = "sandbox_enabled_default")]
    pub enabled: bool,
    /// Default policy for skills without explicit overrides.
    #[serde(default)]
    pub defaults: CapabilityPolicy,
    /// Per-skill overrides (keyed by skill name).
    #[serde(default)]
    pub overrides: HashMap<String, CapabilityPolicy>,
}

fn sandbox_enabled_default() -> bool {
    true
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            defaults: CapabilityPolicy::default(),
            overrides: HashMap::new(),
        }
    }
}

/// Capabilities discovered from a WASM module's imports.
#[derive(Debug, Clone, Default)]
pub struct DiscoveredCapabilities {
    /// Set of capabilities the module requires.
    pub capabilities: Vec<WasmCapability>,
}

/// Map a WASM import function name to a capability.
fn import_to_capability(import_name: &str) -> Option<WasmCapability> {
    match import_name {
        "http-fetch" => Some(WasmCapability::Http),
        "credential-get" | "credential-set" => Some(WasmCapability::Credentials),
        "media-fetch" => Some(WasmCapability::Media),
        "config-get" => Some(WasmCapability::Config),
        name if name.starts_with("log-") => Some(WasmCapability::Logging),
        _ => None,
    }
}

/// Enumerate capabilities required by a compiled WASM module.
///
/// Uses `Module::imports()` to inspect host function imports and maps them
/// to capability categories.
pub fn enumerate_capabilities(module: &Module) -> DiscoveredCapabilities {
    let mut seen = std::collections::HashSet::new();
    let mut capabilities = Vec::new();

    for import in module.imports() {
        if let Some(cap) = import_to_capability(import.name()) {
            if seen.insert(cap) {
                capabilities.push(cap);
            }
        }
    }

    DiscoveredCapabilities { capabilities }
}

/// Check whether a skill's discovered capabilities are allowed by the sandbox policy.
///
/// Config and Logging are always allowed.
/// Returns `Ok(())` if all capabilities are permitted, or `Err(denied)` with
/// the list of denied capabilities.
pub fn check_capabilities(
    skill_name: &str,
    discovered: &DiscoveredCapabilities,
    config: &SandboxConfig,
) -> Result<(), Vec<WasmCapability>> {
    if !config.enabled {
        return Ok(());
    }

    let policy = config.overrides.get(skill_name).unwrap_or(&config.defaults);

    let mut denied = Vec::new();

    for cap in &discovered.capabilities {
        let allowed = match cap {
            WasmCapability::Http => policy.allow_http,
            WasmCapability::Credentials => policy.allow_credentials,
            WasmCapability::Media => policy.allow_media,
            WasmCapability::Config => true,  // always allowed
            WasmCapability::Logging => true, // always allowed
        };

        if !allowed {
            denied.push(*cap);
        }
    }

    if denied.is_empty() {
        Ok(())
    } else {
        Err(denied)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== Import Mapping ====================

    #[test]
    fn test_import_to_capability_http() {
        assert_eq!(
            import_to_capability("http-fetch"),
            Some(WasmCapability::Http)
        );
    }

    #[test]
    fn test_import_to_capability_credentials() {
        assert_eq!(
            import_to_capability("credential-get"),
            Some(WasmCapability::Credentials)
        );
        assert_eq!(
            import_to_capability("credential-set"),
            Some(WasmCapability::Credentials)
        );
    }

    #[test]
    fn test_import_to_capability_media() {
        assert_eq!(
            import_to_capability("media-fetch"),
            Some(WasmCapability::Media)
        );
    }

    #[test]
    fn test_import_to_capability_config() {
        assert_eq!(
            import_to_capability("config-get"),
            Some(WasmCapability::Config)
        );
    }

    #[test]
    fn test_import_to_capability_logging() {
        assert_eq!(
            import_to_capability("log-debug"),
            Some(WasmCapability::Logging)
        );
        assert_eq!(
            import_to_capability("log-info"),
            Some(WasmCapability::Logging)
        );
        assert_eq!(
            import_to_capability("log-warn"),
            Some(WasmCapability::Logging)
        );
        assert_eq!(
            import_to_capability("log-error"),
            Some(WasmCapability::Logging)
        );
    }

    #[test]
    fn test_import_to_capability_unknown() {
        assert_eq!(import_to_capability("unknown-func"), None);
        assert_eq!(import_to_capability("send-text"), None);
    }

    // ==================== Policy Checking ====================

    #[test]
    fn test_check_capabilities_all_denied() {
        let discovered = DiscoveredCapabilities {
            capabilities: vec![WasmCapability::Http, WasmCapability::Credentials],
        };
        let config = SandboxConfig::default();

        let result = check_capabilities("test-skill", &discovered, &config);
        assert!(result.is_err());
        let denied = result.unwrap_err();
        assert!(denied.contains(&WasmCapability::Http));
        assert!(denied.contains(&WasmCapability::Credentials));
    }

    #[test]
    fn test_check_capabilities_all_allowed() {
        let discovered = DiscoveredCapabilities {
            capabilities: vec![WasmCapability::Http, WasmCapability::Credentials],
        };
        let config = SandboxConfig {
            enabled: true,
            defaults: CapabilityPolicy {
                allow_http: true,
                allow_credentials: true,
                allow_media: false,
            },
            overrides: HashMap::new(),
        };

        let result = check_capabilities("test-skill", &discovered, &config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_check_capabilities_config_always_allowed() {
        let discovered = DiscoveredCapabilities {
            capabilities: vec![WasmCapability::Config],
        };
        let config = SandboxConfig::default();

        let result = check_capabilities("test-skill", &discovered, &config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_check_capabilities_logging_always_allowed() {
        let discovered = DiscoveredCapabilities {
            capabilities: vec![WasmCapability::Logging],
        };
        let config = SandboxConfig::default();

        let result = check_capabilities("test-skill", &discovered, &config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_check_capabilities_per_skill_override() {
        let discovered = DiscoveredCapabilities {
            capabilities: vec![WasmCapability::Http],
        };
        let mut overrides = HashMap::new();
        overrides.insert(
            "my-skill".to_string(),
            CapabilityPolicy {
                allow_http: true,
                allow_credentials: false,
                allow_media: false,
            },
        );
        let config = SandboxConfig {
            enabled: true,
            defaults: CapabilityPolicy::default(),
            overrides,
        };

        // my-skill has HTTP allowed
        assert!(check_capabilities("my-skill", &discovered, &config).is_ok());
        // other-skill uses defaults (HTTP denied)
        assert!(check_capabilities("other-skill", &discovered, &config).is_err());
    }

    // ==================== Disabled Config ====================

    #[test]
    fn test_disabled_sandbox_allows_all() {
        let discovered = DiscoveredCapabilities {
            capabilities: vec![
                WasmCapability::Http,
                WasmCapability::Credentials,
                WasmCapability::Media,
            ],
        };
        let config = SandboxConfig {
            enabled: false,
            ..Default::default()
        };

        let result = check_capabilities("any-skill", &discovered, &config);
        assert!(result.is_ok());
    }

    // ==================== Config Serialization ====================

    #[test]
    fn test_sandbox_config_default() {
        let config = SandboxConfig::default();
        assert!(config.enabled);
        assert!(!config.defaults.allow_http);
        assert!(!config.defaults.allow_credentials);
        assert!(!config.defaults.allow_media);
        assert!(config.overrides.is_empty());
    }

    #[test]
    fn test_sandbox_config_serde_roundtrip() {
        let mut overrides = HashMap::new();
        overrides.insert(
            "web-skill".to_string(),
            CapabilityPolicy {
                allow_http: true,
                allow_credentials: false,
                allow_media: true,
            },
        );
        let config = SandboxConfig {
            enabled: true,
            defaults: CapabilityPolicy {
                allow_http: false,
                allow_credentials: false,
                allow_media: false,
            },
            overrides,
        };

        let json = serde_json::to_string(&config).unwrap();
        let parsed: SandboxConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.enabled, config.enabled);
        assert!(parsed.overrides.contains_key("web-skill"));
        assert!(parsed.overrides["web-skill"].allow_http);
    }

    #[test]
    fn test_capability_display() {
        assert_eq!(WasmCapability::Http.to_string(), "http");
        assert_eq!(WasmCapability::Credentials.to_string(), "credentials");
        assert_eq!(WasmCapability::Media.to_string(), "media");
        assert_eq!(WasmCapability::Config.to_string(), "config");
        assert_eq!(WasmCapability::Logging.to_string(), "logging");
    }

    // ==================== Empty Capabilities ====================

    #[test]
    fn test_no_capabilities_always_passes() {
        let discovered = DiscoveredCapabilities {
            capabilities: Vec::new(),
        };
        let config = SandboxConfig::default();
        assert!(check_capabilities("any-skill", &discovered, &config).is_ok());
    }

    // ==================== Mixed Allowed/Denied ====================

    #[test]
    fn test_partial_deny() {
        let discovered = DiscoveredCapabilities {
            capabilities: vec![
                WasmCapability::Http,
                WasmCapability::Config,
                WasmCapability::Media,
            ],
        };
        let config = SandboxConfig {
            enabled: true,
            defaults: CapabilityPolicy {
                allow_http: true,
                allow_credentials: false,
                allow_media: false,
            },
            overrides: HashMap::new(),
        };

        let result = check_capabilities("test-skill", &discovered, &config);
        assert!(result.is_err());
        let denied = result.unwrap_err();
        assert_eq!(denied, vec![WasmCapability::Media]);
    }
}
