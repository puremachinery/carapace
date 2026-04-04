use serde_json::{json, Value};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VertexModelRoute {
    Default,
    Explicit,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VertexSetupInput {
    pub project_id: String,
    pub location: String,
    pub route: VertexModelRoute,
    pub model: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VertexSetupInputError;

impl std::fmt::Display for VertexSetupInputError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "explicit Vertex routes require a concrete non-default model"
        )
    }
}

impl std::error::Error for VertexSetupInputError {}

impl VertexSetupInput {
    pub fn route_model(&self) -> Result<String, VertexSetupInputError> {
        match self.route {
            VertexModelRoute::Default => Ok("vertex:default".to_string()),
            VertexModelRoute::Explicit => {
                let explicit_model =
                    normalize_vertex_model_id(self.model.as_deref().unwrap_or_default());
                if explicit_model.is_empty() || explicit_model == "default" {
                    Err(VertexSetupInputError)
                } else {
                    Ok(format!("vertex:{explicit_model}"))
                }
            }
        }
    }

    pub fn default_model(&self) -> Option<String> {
        match self.route {
            VertexModelRoute::Default => self
                .model
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned),
            VertexModelRoute::Explicit => None,
        }
    }
}

pub fn normalize_vertex_model_id(model: &str) -> String {
    crate::agent::vertex::strip_vertex_prefix(model.trim())
        .trim()
        .to_string()
}

pub fn write_vertex_config(
    config: &mut Value,
    input: &VertexSetupInput,
) -> Result<(), VertexSetupInputError> {
    if !config.get("vertex").is_some_and(Value::is_object) {
        config["vertex"] = json!({});
    }
    config["vertex"]["projectId"] = json!(input.project_id.trim());
    config["vertex"]["location"] = json!(input.location.trim());
    config["agents"]["defaults"]["model"] = json!(input.route_model()?);

    if let Some(vertex) = config.get_mut("vertex").and_then(Value::as_object_mut) {
        match input.default_model() {
            Some(model) => {
                vertex.insert("model".to_string(), json!(model));
            }
            None => {
                vertex.remove("model");
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_write_vertex_config_default_route_sets_default_model() {
        let mut config = json!({});
        write_vertex_config(
            &mut config,
            &VertexSetupInput {
                project_id: "my-project".to_string(),
                location: "us-central1".to_string(),
                route: VertexModelRoute::Default,
                model: Some("gemini-2.5-flash".to_string()),
            },
        )
        .expect("default Vertex route should serialize");

        assert_eq!(config["vertex"]["projectId"], "my-project");
        assert_eq!(config["vertex"]["location"], "us-central1");
        assert_eq!(config["vertex"]["model"], "gemini-2.5-flash");
        assert_eq!(config["agents"]["defaults"]["model"], "vertex:default");
    }

    #[test]
    fn test_write_vertex_config_explicit_route_clears_default_model() {
        let mut config = json!({
            "vertex": {
                "model": "gemini-2.5-flash"
            }
        });
        write_vertex_config(
            &mut config,
            &VertexSetupInput {
                project_id: "my-project".to_string(),
                location: "us-central1".to_string(),
                route: VertexModelRoute::Explicit,
                model: Some("vertex:google/gemini-1.5-pro".to_string()),
            },
        )
        .expect("explicit Vertex route should serialize");

        assert_eq!(config["vertex"]["projectId"], "my-project");
        assert_eq!(config["vertex"]["location"], "us-central1");
        assert!(
            config["vertex"].get("model").is_none(),
            "explicit routes should not persist `vertex.model`"
        );
        assert_eq!(
            config["agents"]["defaults"]["model"],
            "vertex:google/gemini-1.5-pro"
        );
    }

    #[test]
    fn test_route_model_rejects_missing_explicit_model() {
        let input = VertexSetupInput {
            project_id: "my-project".to_string(),
            location: "us-central1".to_string(),
            route: VertexModelRoute::Explicit,
            model: None,
        };

        assert_eq!(input.route_model(), Err(VertexSetupInputError));
    }

    #[test]
    fn test_route_model_rejects_default_as_explicit_model() {
        let input = VertexSetupInput {
            project_id: "my-project".to_string(),
            location: "us-central1".to_string(),
            route: VertexModelRoute::Explicit,
            model: Some("vertex:default".to_string()),
        };

        assert_eq!(input.route_model(), Err(VertexSetupInputError));
    }

    #[test]
    fn test_normalize_vertex_model_id_strips_provider_prefix() {
        assert_eq!(
            normalize_vertex_model_id("vertex:gemini-2.5-flash"),
            "gemini-2.5-flash"
        );
        assert_eq!(
            normalize_vertex_model_id("vertex:google/gemini-1.5-pro"),
            "google/gemini-1.5-pro"
        );
        assert_eq!(
            normalize_vertex_model_id(" google/gemini-1.5-pro "),
            "google/gemini-1.5-pro"
        );
    }
}
