//! Named-route resolution for agent execution targets.
//!
//! Maps route references to concrete `provider:model` strings via a
//! precedence chain: request → session → agent → defaults.
//! Within each scope, `route` is checked before `model`.

use serde::Deserialize;
use serde_json::Value;
use std::collections::HashMap;

use crate::agent::{AgentConfigurationError, AgentError};

/// A named route — backend target + optional metadata.
#[derive(Debug, Clone, Deserialize)]
pub struct RouteConfig {
    /// Required — provider:model string (e.g. "anthropic:claude-sonnet-4-20250514")
    pub model: String,
    /// Optional human-readable label
    pub label: Option<String>,
}

/// A selector level — each scope carries an optional route reference
/// and an optional direct model string.
#[derive(Debug, Default)]
pub struct SelectorLevel<'a> {
    pub route: Option<&'a str>,
    pub model: Option<&'a str>,
}

/// Structured input to the route resolver, one level per scope.
#[derive(Debug, Default)]
pub struct RouteResolutionInputs<'a> {
    pub request: SelectorLevel<'a>,
    pub session: SelectorLevel<'a>,
    pub agent: SelectorLevel<'a>,
    pub defaults: SelectorLevel<'a>,
}

/// Which precedence level produced the resolved model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteSource {
    RequestRoute,
    RequestModel,
    SessionRoute,
    SessionModel,
    AgentRoute,
    AgentModel,
    DefaultsRoute,
    DefaultsModel,
}

/// The resolved execution target.
#[derive(Debug, Clone)]
pub struct ResolvedRoute {
    pub model: String,
    pub source: RouteSource,
}

/// Resolve the execution target from the precedence chain.
///
/// Checks scopes in order: request → session → agent → defaults.
/// Within each scope, `route` is checked before `model`.
///
/// Fail-closed: a present `route` that doesn't resolve to a key in the
/// routes map is a hard error — no fallback to sibling `model` or lower levels.
pub fn resolve_execution_target(
    routes: &HashMap<String, RouteConfig>,
    inputs: &RouteResolutionInputs<'_>,
) -> Result<ResolvedRoute, AgentError> {
    let levels: [(&SelectorLevel<'_>, RouteSource, RouteSource); 4] = [
        (
            &inputs.request,
            RouteSource::RequestRoute,
            RouteSource::RequestModel,
        ),
        (
            &inputs.session,
            RouteSource::SessionRoute,
            RouteSource::SessionModel,
        ),
        (
            &inputs.agent,
            RouteSource::AgentRoute,
            RouteSource::AgentModel,
        ),
        (
            &inputs.defaults,
            RouteSource::DefaultsRoute,
            RouteSource::DefaultsModel,
        ),
    ];

    for (level, route_source, model_source) in &levels {
        if let Some(route_name) = level.route {
            let route_name = route_name.trim();
            if !route_name.is_empty() {
                let config = routes.get(route_name).ok_or_else(|| {
                    AgentError::Configuration(AgentConfigurationError::unknown_route(route_name))
                })?;
                return Ok(ResolvedRoute {
                    model: config.model.clone(),
                    source: *route_source,
                });
            }
        }
        if let Some(model) = level.model {
            let model = model.trim();
            if !model.is_empty() {
                return Ok(ResolvedRoute {
                    model: model.to_string(),
                    source: *model_source,
                });
            }
        }
    }

    Err(AgentError::Configuration(
        AgentConfigurationError::missing_model(),
    ))
}

/// Parse the top-level `routes` map from config. Returns empty map if not present.
pub fn load_routes(cfg: &Value) -> HashMap<String, RouteConfig> {
    let Some(routes_obj) = cfg.get("routes").and_then(Value::as_object) else {
        return HashMap::new();
    };
    routes_obj
        .iter()
        .filter_map(
            |(key, value)| match serde_json::from_value::<RouteConfig>(value.clone()) {
                Ok(config) => Some((key.clone(), config)),
                Err(e) => {
                    tracing::warn!(
                        route = %key,
                        error = %e,
                        "skipping malformed route entry"
                    );
                    None
                }
            },
        )
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn make_routes() -> HashMap<String, RouteConfig> {
        let mut m = HashMap::new();
        m.insert(
            "fast".to_string(),
            RouteConfig {
                model: "anthropic:claude-sonnet-4-20250514".to_string(),
                label: Some("Fast route".to_string()),
            },
        );
        m.insert(
            "smart".to_string(),
            RouteConfig {
                model: "anthropic:claude-opus-4-20250514".to_string(),
                label: None,
            },
        );
        m
    }

    #[test]
    fn resolve_named_route() {
        let routes = make_routes();
        let inputs = RouteResolutionInputs {
            agent: SelectorLevel {
                route: Some("fast"),
                ..Default::default()
            },
            ..Default::default()
        };
        let resolved = resolve_execution_target(&routes, &inputs).unwrap();
        assert_eq!(resolved.model, "anthropic:claude-sonnet-4-20250514");
        assert_eq!(resolved.source, RouteSource::AgentRoute);
    }

    #[test]
    fn resolve_direct_model_no_routes() {
        let routes = HashMap::new();
        let inputs = RouteResolutionInputs {
            agent: SelectorLevel {
                model: Some("openai:gpt-4o"),
                ..Default::default()
            },
            ..Default::default()
        };
        let resolved = resolve_execution_target(&routes, &inputs).unwrap();
        assert_eq!(resolved.model, "openai:gpt-4o");
        assert_eq!(resolved.source, RouteSource::AgentModel);
    }

    #[test]
    fn request_route_wins_over_agent_model() {
        let routes = make_routes();
        let inputs = RouteResolutionInputs {
            request: SelectorLevel {
                route: Some("smart"),
                ..Default::default()
            },
            agent: SelectorLevel {
                model: Some("openai:gpt-4o"),
                ..Default::default()
            },
            ..Default::default()
        };
        let resolved = resolve_execution_target(&routes, &inputs).unwrap();
        assert_eq!(resolved.model, "anthropic:claude-opus-4-20250514");
        assert_eq!(resolved.source, RouteSource::RequestRoute);
    }

    #[test]
    fn agent_route_wins_over_defaults_model() {
        let routes = make_routes();
        let inputs = RouteResolutionInputs {
            agent: SelectorLevel {
                route: Some("fast"),
                ..Default::default()
            },
            defaults: SelectorLevel {
                model: Some("openai:gpt-4o"),
                ..Default::default()
            },
            ..Default::default()
        };
        let resolved = resolve_execution_target(&routes, &inputs).unwrap();
        assert_eq!(resolved.model, "anthropic:claude-sonnet-4-20250514");
        assert_eq!(resolved.source, RouteSource::AgentRoute);
    }

    #[test]
    fn session_route_wins_over_agent_model() {
        let routes = make_routes();
        let inputs = RouteResolutionInputs {
            session: SelectorLevel {
                route: Some("smart"),
                ..Default::default()
            },
            agent: SelectorLevel {
                model: Some("openai:gpt-4o"),
                ..Default::default()
            },
            ..Default::default()
        };
        let resolved = resolve_execution_target(&routes, &inputs).unwrap();
        assert_eq!(resolved.model, "anthropic:claude-opus-4-20250514");
        assert_eq!(resolved.source, RouteSource::SessionRoute);
    }

    #[test]
    fn session_model_wins_over_agent_route() {
        let routes = make_routes();
        let inputs = RouteResolutionInputs {
            session: SelectorLevel {
                model: Some("openai:gpt-4o"),
                ..Default::default()
            },
            agent: SelectorLevel {
                route: Some("fast"),
                ..Default::default()
            },
            ..Default::default()
        };
        let resolved = resolve_execution_target(&routes, &inputs).unwrap();
        assert_eq!(resolved.model, "openai:gpt-4o");
        assert_eq!(resolved.source, RouteSource::SessionModel);
    }

    #[test]
    fn request_model_wins_over_session_route() {
        let routes = make_routes();
        let inputs = RouteResolutionInputs {
            request: SelectorLevel {
                model: Some("openai:gpt-4o"),
                ..Default::default()
            },
            session: SelectorLevel {
                route: Some("smart"),
                ..Default::default()
            },
            ..Default::default()
        };
        let resolved = resolve_execution_target(&routes, &inputs).unwrap();
        assert_eq!(resolved.model, "openai:gpt-4o");
        assert_eq!(resolved.source, RouteSource::RequestModel);
    }

    #[test]
    fn unknown_route_is_hard_error() {
        let routes = make_routes();
        let inputs = RouteResolutionInputs {
            agent: SelectorLevel {
                route: Some("nonexistent"),
                model: Some("openai:gpt-4o"), // must NOT fall through
            },
            ..Default::default()
        };
        let err = resolve_execution_target(&routes, &inputs).unwrap_err();
        let msg = err.to_string();
        assert_eq!(msg, "requested route is not configured");
        assert!(!msg.contains("nonexistent"), "got: {msg}");
        assert!(!msg.contains("routes"), "got: {msg}");

        let AgentError::Configuration(config_error) = err else {
            panic!("expected configuration error");
        };
        assert_eq!(
            config_error.code().as_str(),
            "unknown_route",
            "got: {:?}",
            config_error.code()
        );
        assert!(config_error.operator_hint().contains("nonexistent"));
        assert!(config_error.operator_hint().contains("`routes`"));
    }

    #[test]
    fn empty_and_whitespace_are_skipped() {
        let routes = make_routes();
        let inputs = RouteResolutionInputs {
            request: SelectorLevel {
                route: Some("  "),
                model: Some(""),
            },
            agent: SelectorLevel {
                model: Some("openai:gpt-4o"),
                ..Default::default()
            },
            ..Default::default()
        };
        let resolved = resolve_execution_target(&routes, &inputs).unwrap();
        assert_eq!(resolved.model, "openai:gpt-4o");
        assert_eq!(resolved.source, RouteSource::AgentModel);
    }

    #[test]
    fn no_model_configured_returns_clear_error() {
        let routes = HashMap::new();
        let inputs = RouteResolutionInputs::default();
        let err = resolve_execution_target(&routes, &inputs).unwrap_err();
        let msg = err.to_string();
        assert_eq!(msg, "agent model is not configured");
        assert!(!msg.contains("agents.defaults"), "got: {msg}");
        assert!(!msg.contains("route"), "got: {msg}");

        let AgentError::Configuration(config_error) = err else {
            panic!("expected configuration error");
        };
        assert_eq!(
            config_error.code().as_str(),
            "missing_model",
            "got: {:?}",
            config_error.code()
        );
        assert!(config_error.operator_hint().contains("agents.defaults"));
    }

    #[test]
    fn resolve_defaults_model_without_routes_map() {
        let routes = HashMap::new();
        let inputs = RouteResolutionInputs {
            defaults: SelectorLevel {
                model: Some("anthropic:claude-sonnet-4-20250514"),
                ..Default::default()
            },
            ..Default::default()
        };
        let resolved = resolve_execution_target(&routes, &inputs).unwrap();
        assert_eq!(resolved.model, "anthropic:claude-sonnet-4-20250514");
        assert_eq!(resolved.source, RouteSource::DefaultsModel);
    }

    #[test]
    fn load_routes_from_config() {
        let cfg = json!({
            "routes": {
                "fast": {
                    "model": "anthropic:claude-sonnet-4-20250514",
                    "label": "Fast"
                },
                "smart": {
                    "model": "anthropic:claude-opus-4-20250514"
                }
            }
        });
        let routes = load_routes(&cfg);
        assert_eq!(routes.len(), 2);
        assert_eq!(routes["fast"].model, "anthropic:claude-sonnet-4-20250514");
        assert_eq!(routes["fast"].label.as_deref(), Some("Fast"));
        assert_eq!(routes["smart"].model, "anthropic:claude-opus-4-20250514");
        assert!(routes["smart"].label.is_none());
    }

    #[test]
    fn load_routes_missing_section() {
        let cfg = json!({"agents": {}});
        let routes = load_routes(&cfg);
        assert!(routes.is_empty());
    }

    #[test]
    fn request_route_overrides_session_model() {
        let mut routes = HashMap::new();
        routes.insert(
            "fast".to_string(),
            RouteConfig {
                model: "gemini:gemini-2.0-flash".to_string(),
                label: None,
            },
        );

        let inputs = RouteResolutionInputs {
            request: SelectorLevel {
                route: Some("fast"),
                model: None,
            },
            session: SelectorLevel {
                route: None,
                model: Some("anthropic:claude-sonnet-4-20250514"),
            },
            ..Default::default()
        };

        let result = resolve_execution_target(&routes, &inputs).unwrap();
        assert_eq!(result.model, "gemini:gemini-2.0-flash");
        assert_eq!(result.source, RouteSource::RequestRoute);
    }
}
