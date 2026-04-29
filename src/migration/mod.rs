use std::path::PathBuf;

use serde_json::Value;

pub mod aider;
pub mod nemoclaw;
pub mod openclaw;
pub mod opencode;

/// Add a canonical provider prefix to an imported model name for Carapace routing.
///
/// External tools use a mix of bare model names and provider/model identifiers.
/// Convert the known imported forms into Carapace's current provider:model form.
/// Well-known bare model families are delegated to the current model-name helper.
///
/// Unrecognized models pass through unchanged.
pub(crate) fn prefix_imported_model(model: &str) -> String {
    if let Some((provider, rest)) = model.split_once('/') {
        let provider_lower = provider.to_ascii_lowercase();
        match provider_lower.as_str() {
            "anthropic" => return format!("anthropic:{rest}"),
            "openai" => return format!("openai:{rest}"),
            "gemini" | "google" => return format!("gemini:{rest}"),
            "bedrock" => return format!("bedrock:{rest}"),
            "vertex" => return format!("vertex:{rest}"),
            "ollama" => return format!("ollama:{rest}"),
            "codex" => return format!("codex:{rest}"),
            "venice" => return format!("venice:{rest}"),
            "claude-cli" => return format!("claude-cli:{rest}"),
            "models" if rest.to_ascii_lowercase().starts_with("gemini-") => {
                return format!("gemini:{rest}");
            }
            _ => {}
        }
    }

    crate::model_names::prefix_bare_model(model)
}

/// A field that was successfully mapped to Carapace config.
#[derive(Debug, Clone)]
pub struct ImportMapping {
    pub source_path: String,
    pub carapace_key: String,
    pub value: Value,
    pub sensitive: bool,
}

/// A field that was found but could not be mapped.
#[derive(Debug, Clone)]
pub struct SkippedField {
    pub source_path: String,
    pub reason: &'static str,
}

/// Result of scanning and mapping a source config.
#[derive(Debug, Default)]
pub struct ImportPlan {
    pub source_name: &'static str,
    pub config_path: Option<PathBuf>,
    pub mappings: Vec<ImportMapping>,
    pub skipped: Vec<SkippedField>,
    pub warnings: Vec<String>,
}

impl ImportPlan {
    pub fn is_empty(&self) -> bool {
        self.mappings.is_empty()
    }

    /// Build a Carapace config Value from the mapped fields.
    pub fn build_carapace_config(&self) -> Value {
        let mut config = serde_json::json!({});
        for mapping in &self.mappings {
            set_nested(&mut config, &mapping.carapace_key, mapping.value.clone());
        }
        config
    }
}

pub(crate) fn set_nested(config: &mut Value, dotted_key: &str, value: Value) {
    let segments: Vec<&str> = dotted_key.split('.').collect();
    let mut current = config;
    for (i, segment) in segments.iter().enumerate() {
        if i == segments.len() - 1 {
            current[*segment] = value;
            return;
        }
        if !current.get(*segment).is_some_and(|v| v.is_object()) {
            current[*segment] = serde_json::json!({});
        }
        current = current.get_mut(*segment).unwrap();
    }
}

pub(crate) fn push_mapping(
    plan: &mut ImportPlan,
    source_path: String,
    carapace_key: &str,
    value: Value,
    sensitive: bool,
) {
    if plan.mappings.iter().any(|m| m.carapace_key == carapace_key) {
        return;
    }
    plan.mappings.push(ImportMapping {
        source_path,
        carapace_key: carapace_key.to_string(),
        value,
        sensitive,
    });
}
