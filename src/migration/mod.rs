use std::path::PathBuf;

use serde_json::Value;

pub mod aider;
pub mod nemoclaw;
pub mod openclaw;
pub mod opencode;

/// Add a canonical provider prefix to a bare model name for Carapace routing.
///
/// All well-known model families get the appropriate prefix:
/// - `claude-*` → `anthropic:`
/// - `gpt-*`, `o1*`, `o3*`, `o4*`, `chatgpt-*` → `openai:`
/// - `gemini-*`, `models/gemini-*` → `gemini:`
///
/// Unrecognized models pass through unchanged.
pub(crate) fn prefix_bare_model(model: &str) -> String {
    let lower = model.to_ascii_lowercase();
    if lower.starts_with("claude-") {
        format!("anthropic:{model}")
    } else if lower.starts_with("gpt-")
        || lower == "o1"
        || lower.starts_with("o1-")
        || lower == "o3"
        || lower.starts_with("o3-")
        || lower == "o4"
        || lower.starts_with("o4-")
        || lower.starts_with("chatgpt-")
    {
        format!("openai:{model}")
    } else if lower.starts_with("gemini-") {
        format!("gemini:{model}")
    } else if lower.starts_with("models/gemini-") {
        // Google canonical API form: models/gemini-2.0-flash → gemini:gemini-2.0-flash
        format!("gemini:{}", &model[7..])
    } else {
        model.to_string()
    }
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
