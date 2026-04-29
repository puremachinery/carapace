pub(crate) const KNOWN_PROVIDER_PREFIXES: &[&str] = &[
    "anthropic:",
    "openai:",
    "gemini:",
    "vertex:",
    "bedrock:",
    "ollama:",
    "codex:",
    "venice:",
    "claude-cli:",
];

pub(crate) fn known_provider_prefixes_message() -> String {
    KNOWN_PROVIDER_PREFIXES.join(", ")
}

/// Add a canonical provider prefix to a bare model name for Carapace routing.
///
/// Handles well-known model families:
/// - `claude-*` -> `anthropic:`
/// - `gpt-*`, `o1*`, `o3*`, `o4*`, `chatgpt-*` -> `openai:`
/// - `gemini-*` -> `gemini:`
/// - `anthropic.claude-*`, `amazon.titan-*`, `meta.llama*` -> `bedrock:`
///
/// Unrecognized models pass through unchanged.
pub(crate) fn prefix_bare_model(model: &str) -> String {
    let lower = model.to_ascii_lowercase();

    // If it already has a provider:model colon form (no dots in prefix), don't double-prefix.
    // Bedrock native IDs like anthropic.claude-v1:0 have dots before the colon and still
    // need to be prefixed with bedrock:.
    if let Some((prefix, _)) = model.split_once(':') {
        if !prefix.contains('.') {
            return model.to_string();
        }
    }

    if lower == "claude-cli" {
        "claude-cli:default".to_string()
    } else if lower.starts_with("claude-") {
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
    } else if lower.starts_with("anthropic.claude-")
        || lower.starts_with("amazon.titan-")
        || lower.starts_with("meta.llama")
    {
        format!("bedrock:{model}")
    } else {
        model.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::{known_provider_prefixes_message, prefix_bare_model, KNOWN_PROVIDER_PREFIXES};

    #[test]
    fn known_prefix_message_tracks_prefix_list() {
        assert_eq!(
            known_provider_prefixes_message(),
            KNOWN_PROVIDER_PREFIXES.join(", ")
        );
    }

    #[test]
    fn prefixes_well_known_bare_models() {
        assert_eq!(
            prefix_bare_model("claude-sonnet-4"),
            "anthropic:claude-sonnet-4"
        );
        assert_eq!(prefix_bare_model("gpt-4o"), "openai:gpt-4o");
        assert_eq!(
            prefix_bare_model("gemini-2.0-flash"),
            "gemini:gemini-2.0-flash"
        );
        assert_eq!(
            prefix_bare_model("anthropic.claude-3-5-sonnet-20241022-v2:0"),
            "bedrock:anthropic.claude-3-5-sonnet-20241022-v2:0"
        );
    }

    #[test]
    fn slash_model_values_are_not_rewritten() {
        assert_eq!(
            prefix_bare_model("models/gemini-2.0-flash"),
            "models/gemini-2.0-flash"
        );
    }

    #[test]
    fn keeps_current_provider_colon_forms() {
        assert_eq!(
            prefix_bare_model("anthropic:claude-sonnet-4"),
            "anthropic:claude-sonnet-4"
        );
    }
}
