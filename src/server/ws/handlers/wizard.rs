//! Setup wizard handlers.
//!
//! Manages interactive setup wizards for configuring channels, agents,
//! and other system components.

use parking_lot::RwLock;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::LazyLock;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use uuid::Uuid;

use super::super::*;
use super::config::{map_validation_issues, read_config_snapshot, write_config_file};
use crate::config;
use crate::server::bind::DEFAULT_PORT;

/// Available wizard types
pub const WIZARD_TYPES: [&str; 6] = [
    "setup",
    "channel",
    "agent",
    "provider",
    "skill",
    "migration",
];

/// Wizard timeout in seconds (30 minutes)
const WIZARD_TIMEOUT_SECS: u64 = 1800;

/// Global wizard state
static WIZARD_STATE: LazyLock<RwLock<WizardManager>> =
    LazyLock::new(|| RwLock::new(WizardManager::default()));

/// Manages active wizard instances
#[derive(Debug, Default)]
pub struct WizardManager {
    /// Active wizard sessions by ID
    wizards: HashMap<String, WizardSession>,
}

/// A wizard session
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WizardSession {
    /// Unique wizard ID
    pub id: String,
    /// Wizard type
    pub wizard_type: String,
    /// Current step index (0-based)
    pub current_step: usize,
    /// Total number of steps
    pub total_steps: usize,
    /// Step definitions
    pub steps: Vec<WizardStep>,
    /// Collected data from completed steps
    pub data: HashMap<String, Value>,
    /// Whether the wizard is complete
    pub complete: bool,
    /// Whether the wizard was cancelled
    pub cancelled: bool,
    /// Created timestamp (ms since epoch)
    pub created_at: u64,
    /// Last activity timestamp (ms since epoch)
    pub last_activity: u64,
    /// Connection ID that started the wizard
    pub conn_id: Option<String>,
}

/// A single wizard step
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WizardStep {
    /// Step identifier
    pub id: String,
    /// Step title
    pub title: String,
    /// Step description
    pub description: Option<String>,
    /// Input type (text, select, confirm, etc.)
    pub input_type: String,
    /// Available options for select/multiselect
    pub options: Option<Vec<WizardOption>>,
    /// Whether this step is required
    pub required: bool,
    /// Default value
    pub default: Option<Value>,
    /// Validation rules
    pub validation: Option<WizardValidation>,
}

/// A wizard option for select inputs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WizardOption {
    pub value: String,
    pub label: String,
    pub description: Option<String>,
}

/// Validation rules for wizard inputs
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WizardValidation {
    pub min_length: Option<usize>,
    pub max_length: Option<usize>,
    pub pattern: Option<String>,
}

impl WizardManager {
    /// Create a new wizard session
    fn create_wizard(&mut self, wizard_type: &str, conn_id: Option<String>) -> WizardSession {
        // Clean up expired wizards
        self.cleanup_expired();

        let id = Uuid::new_v4().to_string();
        let now = now_ms();
        let steps = create_wizard_steps(wizard_type);
        let total_steps = steps.len();

        let session = WizardSession {
            id: id.clone(),
            wizard_type: wizard_type.to_string(),
            current_step: 0,
            total_steps,
            steps,
            data: HashMap::new(),
            complete: false,
            cancelled: false,
            created_at: now,
            last_activity: now,
            conn_id,
        };

        self.wizards.insert(id, session.clone());
        session
    }

    /// Get an active wizard by ID
    fn get_wizard(&self, id: &str) -> Option<&WizardSession> {
        self.wizards.get(id)
    }

    /// Get a mutable wizard by ID
    fn get_wizard_mut(&mut self, id: &str) -> Option<&mut WizardSession> {
        self.wizards.get_mut(id)
    }

    /// Cancel a wizard
    fn cancel_wizard(&mut self, id: &str) -> Option<WizardSession> {
        if let Some(wizard) = self.wizards.get_mut(id) {
            wizard.cancelled = true;
            wizard.last_activity = now_ms();
            wizard.data.clear();
            Some(wizard.clone())
        } else {
            None
        }
    }

    /// Get the currently active wizard (if any)
    fn active_wizard(&self) -> Option<&WizardSession> {
        self.wizards.values().find(|w| !w.complete && !w.cancelled)
    }

    /// Clean up expired wizard sessions
    fn cleanup_expired(&mut self) {
        let now = now_ms();
        let timeout_ms = WIZARD_TIMEOUT_SECS * 1000;
        self.wizards
            .retain(|_, w| now - w.last_activity < timeout_ms);
    }
}

/// Build the steps for the initial setup wizard.
fn setup_wizard_steps() -> Vec<WizardStep> {
    vec![
        WizardStep {
            id: "welcome".to_string(),
            title: "Welcome to Carapace".to_string(),
            description: Some("Let's get you set up with your AI assistant.".to_string()),
            input_type: "confirm".to_string(),
            options: None,
            required: true,
            default: Some(Value::Bool(true)),
            validation: None,
        },
        WizardStep {
            id: "provider".to_string(),
            title: "Select AI Provider".to_string(),
            description: Some("Choose your preferred AI model provider.".to_string()),
            input_type: "select".to_string(),
            options: Some(vec![
                WizardOption {
                    value: "anthropic".to_string(),
                    label: "Anthropic (Claude)".to_string(),
                    description: Some("Recommended for most users".to_string()),
                },
                WizardOption {
                    value: "openai".to_string(),
                    label: "OpenAI (GPT)".to_string(),
                    description: None,
                },
            ]),
            required: true,
            default: Some(Value::String("anthropic".to_string())),
            validation: None,
        },
        WizardStep {
            id: "api_key".to_string(),
            title: "Enter API Key".to_string(),
            description: Some("Enter your API key for the selected provider.".to_string()),
            input_type: "password".to_string(),
            options: None,
            required: true,
            default: None,
            validation: Some(WizardValidation {
                min_length: Some(10),
                max_length: Some(256),
                pattern: None,
            }),
        },
        WizardStep {
            id: "auth_mode".to_string(),
            title: "Gateway Auth Mode".to_string(),
            description: Some("Choose token or password authentication for gateway access."
                .to_string()),
            input_type: "select".to_string(),
            options: Some(vec![
                WizardOption {
                    value: "token".to_string(),
                    label: "Token (recommended)".to_string(),
                    description: Some("Bearer token auth for CLI/API access.".to_string()),
                },
                WizardOption {
                    value: "password".to_string(),
                    label: "Password".to_string(),
                    description: Some("Password auth for gateway access.".to_string()),
                },
            ]),
            required: true,
            default: Some(Value::String("token".to_string())),
            validation: None,
        },
        WizardStep {
            id: "auth_secret".to_string(),
            title: "Gateway Secret".to_string(),
            description: Some(
                "Optional. Leave blank to auto-generate a strong secret for the selected auth mode."
                    .to_string(),
            ),
            input_type: "password".to_string(),
            options: None,
            required: false,
            default: None,
            validation: Some(WizardValidation {
                min_length: Some(10),
                max_length: Some(256),
                pattern: None,
            }),
        },
        WizardStep {
            id: "bind_mode".to_string(),
            title: "Gateway Bind Mode".to_string(),
            description: Some(
                "Loopback keeps access local. LAN exposes the service on your local network."
                    .to_string(),
            ),
            input_type: "select".to_string(),
            options: Some(vec![
                WizardOption {
                    value: "loopback".to_string(),
                    label: "Loopback (recommended)".to_string(),
                    description: Some("Local access only.".to_string()),
                },
                WizardOption {
                    value: "lan".to_string(),
                    label: "LAN".to_string(),
                    description: Some("Reachable from devices on your local network.".to_string()),
                },
            ]),
            required: true,
            default: Some(Value::String("loopback".to_string())),
            validation: None,
        },
        WizardStep {
            id: "port".to_string(),
            title: "Gateway Port".to_string(),
            description: Some("TCP port for the gateway service.".to_string()),
            input_type: "text".to_string(),
            options: None,
            required: true,
            default: Some(Value::String(DEFAULT_PORT.to_string())),
            validation: Some(WizardValidation {
                min_length: Some(1),
                max_length: Some(5),
                pattern: Some("^[0-9]{1,5}$".to_string()),
            }),
        },
        WizardStep {
            id: "complete".to_string(),
            title: "Setup Complete".to_string(),
            description: Some("You're all set! Start chatting with your assistant.".to_string()),
            input_type: "confirm".to_string(),
            options: None,
            required: true,
            default: Some(Value::Bool(true)),
            validation: None,
        },
    ]
}

/// Build the steps for the channel configuration wizard.
fn channel_wizard_steps() -> Vec<WizardStep> {
    vec![
        WizardStep {
            id: "channel_type".to_string(),
            title: "Select Channel".to_string(),
            description: Some("Choose a messaging channel to configure.".to_string()),
            input_type: "select".to_string(),
            options: Some(vec![
                WizardOption {
                    value: "telegram".to_string(),
                    label: "Telegram".to_string(),
                    description: None,
                },
                WizardOption {
                    value: "discord".to_string(),
                    label: "Discord".to_string(),
                    description: None,
                },
                WizardOption {
                    value: "slack".to_string(),
                    label: "Slack".to_string(),
                    description: None,
                },
            ]),
            required: true,
            default: None,
            validation: None,
        },
        WizardStep {
            id: "channel_token".to_string(),
            title: "Enter Bot Token".to_string(),
            description: Some("Enter the bot token for your channel.".to_string()),
            input_type: "password".to_string(),
            options: None,
            required: true,
            default: None,
            validation: Some(WizardValidation {
                min_length: Some(10),
                max_length: None,
                pattern: None,
            }),
        },
    ]
}

/// Build the steps for the agent configuration wizard.
fn agent_wizard_steps() -> Vec<WizardStep> {
    vec![
        WizardStep {
            id: "agent_name".to_string(),
            title: "Agent Name".to_string(),
            description: Some("Give your agent a name.".to_string()),
            input_type: "text".to_string(),
            options: None,
            required: true,
            default: Some(Value::String("Assistant".to_string())),
            validation: Some(WizardValidation {
                min_length: Some(1),
                max_length: Some(50),
                pattern: None,
            }),
        },
        WizardStep {
            id: "agent_personality".to_string(),
            title: "Agent Personality".to_string(),
            description: Some("Describe how your agent should behave.".to_string()),
            input_type: "textarea".to_string(),
            options: None,
            required: false,
            default: None,
            validation: Some(WizardValidation {
                min_length: None,
                max_length: Some(1000),
                pattern: None,
            }),
        },
    ]
}

/// Create steps for a wizard type
fn create_wizard_steps(wizard_type: &str) -> Vec<WizardStep> {
    match wizard_type {
        "setup" => setup_wizard_steps(),
        "channel" => channel_wizard_steps(),
        "agent" => agent_wizard_steps(),
        _ => vec![WizardStep {
            id: "generic".to_string(),
            title: "Configuration".to_string(),
            description: None,
            input_type: "confirm".to_string(),
            options: None,
            required: true,
            default: Some(Value::Bool(true)),
            validation: None,
        }],
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_millis() as u64
}

fn set_value_at_path(root: &mut Value, path: &str, value: Value) {
    let parts: Vec<&str> = path.split('.').collect();
    let mut current = root;

    for (i, part) in parts.iter().enumerate() {
        if i == parts.len() - 1 {
            if let Value::Object(map) = current {
                map.insert(part.to_string(), value);
            }
            return;
        }

        if !current.get(*part).is_some_and(|v| v.is_object()) {
            if let Value::Object(map) = current {
                map.insert(part.to_string(), Value::Object(serde_json::Map::new()));
            }
        }
        current = current.get_mut(*part).expect("just inserted");
    }
}

fn normalize_string(value: &Value) -> Option<String> {
    value
        .as_str()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
}

fn validate_step_input(step: &WizardStep, input: Option<&Value>) -> Result<(), ErrorShape> {
    if step.required && input.is_none() {
        return Err(error_shape(
            ERROR_INVALID_REQUEST,
            "input is required for this step",
            None,
        ));
    }

    let Some(input) = input else {
        return Ok(());
    };

    match step.input_type.as_str() {
        "confirm" => {
            if !input.is_boolean() {
                return Err(error_shape(
                    ERROR_INVALID_REQUEST,
                    "confirm input must be a boolean",
                    None,
                ));
            }
        }
        "select" => {
            let Some(selection) = input.as_str() else {
                return Err(error_shape(
                    ERROR_INVALID_REQUEST,
                    "select input must be a string",
                    None,
                ));
            };
            if let Some(options) = &step.options {
                if !options.iter().any(|option| option.value == selection) {
                    return Err(error_shape(
                        ERROR_INVALID_REQUEST,
                        "input is not a valid option",
                        None,
                    ));
                }
            }
        }
        _ => {
            let Some(value) = input.as_str() else {
                return Err(error_shape(
                    ERROR_INVALID_REQUEST,
                    "input must be a string",
                    None,
                ));
            };

            if let Some(validation) = &step.validation {
                if let Some(min) = validation.min_length {
                    if value.len() < min {
                        return Err(error_shape(
                            ERROR_INVALID_REQUEST,
                            "input is shorter than the minimum length",
                            None,
                        ));
                    }
                }
                if let Some(max) = validation.max_length {
                    if value.len() > max {
                        return Err(error_shape(
                            ERROR_INVALID_REQUEST,
                            "input exceeds the maximum length",
                            None,
                        ));
                    }
                }
                if let Some(pattern) = &validation.pattern {
                    let regex = Regex::new(pattern).map_err(|err| {
                        error_shape(
                            ERROR_INVALID_REQUEST,
                            &format!("invalid validation pattern: {}", err),
                            None,
                        )
                    })?;
                    if !regex.is_match(value) {
                        return Err(error_shape(
                            ERROR_INVALID_REQUEST,
                            "input does not match the required pattern",
                            None,
                        ));
                    }
                }
            }
        }
    }

    Ok(())
}

fn require_wizard_string(
    data: &HashMap<String, Value>,
    key: &str,
    label: &str,
) -> Result<String, ErrorShape> {
    data.get(key).and_then(normalize_string).ok_or_else(|| {
        error_shape(
            ERROR_INVALID_REQUEST,
            &format!("{} is required", label),
            None,
        )
    })
}

fn parse_wizard_port(
    data: &HashMap<String, Value>,
    key: &str,
    default_port: u16,
) -> Result<u16, ErrorShape> {
    let Some(raw) = data.get(key).and_then(normalize_string) else {
        return Ok(default_port);
    };

    let port = raw.parse::<u16>().map_err(|_| {
        error_shape(
            ERROR_INVALID_REQUEST,
            "port must be a valid integer between 1 and 65535",
            None,
        )
    })?;
    if port == 0 {
        return Err(error_shape(
            ERROR_INVALID_REQUEST,
            "port must be between 1 and 65535",
            None,
        ));
    }
    Ok(port)
}

fn generate_wizard_secret_hex(byte_len: usize) -> Result<String, ErrorShape> {
    crate::crypto::generate_hex_secret(byte_len).map_err(|_| {
        error_shape(
            ERROR_INVALID_REQUEST,
            "failed to generate authentication secret",
            None,
        )
    })
}

fn resolve_wizard_auth_secret(
    auth_secret: Option<&String>,
    generated_byte_len: usize,
) -> Result<String, ErrorShape> {
    match auth_secret {
        Some(secret) => Ok(secret.clone()),
        None => generate_wizard_secret_hex(generated_byte_len),
    }
}

fn apply_agent_wizard(config_value: &mut Value, name: Option<&str>, description: Option<&str>) {
    let Value::Object(root) = config_value else {
        return;
    };

    let agents = root
        .entry("agents")
        .or_insert_with(|| Value::Object(serde_json::Map::new()));
    if !agents.is_object() {
        *agents = Value::Object(serde_json::Map::new());
    }
    let agents_map = agents.as_object_mut().expect("just ensured object");
    let list_value = agents_map
        .entry("list")
        .or_insert_with(|| Value::Array(Vec::new()));
    if !list_value.is_array() {
        *list_value = Value::Array(Vec::new());
    }
    let list = list_value.as_array_mut().expect("just ensured array");

    let mut target_index = list
        .iter()
        .position(|agent| {
            agent
                .get("default")
                .and_then(Value::as_bool)
                .unwrap_or(false)
        })
        .or_else(|| {
            list.iter()
                .position(|agent| agent.get("id").and_then(Value::as_str) == Some("default"))
        });

    if target_index.is_none() {
        if list.is_empty() {
            list.push(json!({
                "id": "default",
                "default": true,
                "identity": {}
            }));
            target_index = Some(0);
        } else {
            target_index = Some(0);
        }
    }

    let Some(index) = target_index else {
        return;
    };

    let agent = &mut list[index];
    if !agent.is_object() {
        *agent = Value::Object(serde_json::Map::new());
    }
    let agent_map = agent.as_object_mut().expect("just ensured object");
    let identity = agent_map
        .entry("identity")
        .or_insert_with(|| Value::Object(serde_json::Map::new()));
    if !identity.is_object() {
        *identity = Value::Object(serde_json::Map::new());
    }
    let identity_map = identity.as_object_mut().expect("just ensured object");
    if let Some(name) = name {
        identity_map.insert("name".to_string(), Value::String(name.to_string()));
    }
    if let Some(description) = description {
        identity_map.insert(
            "description".to_string(),
            Value::String(description.to_string()),
        );
    }
}

fn apply_wizard_config(
    wizard_type: &str,
    data: &HashMap<String, Value>,
    config_value: &mut Value,
) -> Result<bool, ErrorShape> {
    if !config_value.is_object() {
        return Err(error_shape(
            ERROR_INVALID_REQUEST,
            "config root must be an object",
            None,
        ));
    }

    match wizard_type {
        "setup" => {
            let provider = require_wizard_string(data, "provider", "provider")?;
            let api_key = require_wizard_string(data, "api_key", "api_key")?;
            let auth_mode = data
                .get("auth_mode")
                .and_then(normalize_string)
                .unwrap_or_else(|| "token".to_string())
                .to_lowercase();
            let auth_secret = data.get("auth_secret").and_then(normalize_string);
            let bind_mode = data
                .get("bind_mode")
                .and_then(normalize_string)
                .unwrap_or_else(|| "loopback".to_string())
                .to_lowercase();
            let port = parse_wizard_port(data, "port", DEFAULT_PORT)?;

            match provider.as_str() {
                "anthropic" => {
                    set_value_at_path(config_value, "anthropic.apiKey", json!(api_key));
                    set_value_at_path(
                        config_value,
                        "agents.defaults.model",
                        json!("claude-sonnet-4-20250514"),
                    );
                }
                "openai" => {
                    set_value_at_path(config_value, "openai.apiKey", json!(api_key));
                    set_value_at_path(config_value, "agents.defaults.model", json!("gpt-4o"));
                }
                _ => return Err(error_shape(ERROR_INVALID_REQUEST, "unknown provider", None)),
            }

            match auth_mode.as_str() {
                "token" => {
                    let token = resolve_wizard_auth_secret(auth_secret.as_ref(), 32)?;
                    set_value_at_path(
                        config_value,
                        "gateway.auth",
                        json!({
                            "mode": "token",
                            "token": token
                        }),
                    );
                }
                "password" => {
                    let password = resolve_wizard_auth_secret(auth_secret.as_ref(), 24)?;
                    set_value_at_path(
                        config_value,
                        "gateway.auth",
                        json!({
                            "mode": "password",
                            "password": password
                        }),
                    );
                }
                _ => {
                    return Err(error_shape(
                        ERROR_INVALID_REQUEST,
                        "auth_mode must be token or password",
                        None,
                    ));
                }
            }

            match bind_mode.as_str() {
                "loopback" | "lan" => {
                    set_value_at_path(config_value, "gateway.bind", json!(bind_mode));
                }
                _ => {
                    return Err(error_shape(
                        ERROR_INVALID_REQUEST,
                        "bind_mode must be loopback or lan",
                        None,
                    ));
                }
            }
            set_value_at_path(config_value, "gateway.port", json!(port));
            Ok(true)
        }
        "channel" => {
            let channel = require_wizard_string(data, "channel_type", "channel_type")?;
            let token = require_wizard_string(data, "channel_token", "channel_token")?;
            match channel.as_str() {
                "telegram" => {
                    set_value_at_path(config_value, "telegram.botToken", json!(token));
                    set_value_at_path(config_value, "telegram.enabled", json!(true));
                }
                "discord" => {
                    set_value_at_path(config_value, "discord.botToken", json!(token));
                    set_value_at_path(config_value, "discord.enabled", json!(true));
                }
                "slack" => {
                    set_value_at_path(config_value, "slack.botToken", json!(token));
                    set_value_at_path(config_value, "slack.enabled", json!(true));
                }
                _ => {
                    return Err(error_shape(
                        ERROR_INVALID_REQUEST,
                        "unknown channel type",
                        None,
                    ))
                }
            }
            Ok(true)
        }
        "agent" => {
            let name = data.get("agent_name").and_then(normalize_string);
            let description = data.get("agent_personality").and_then(normalize_string);
            apply_agent_wizard(config_value, name.as_deref(), description.as_deref());
            Ok(true)
        }
        _ => Ok(false),
    }
}

fn persist_wizard_config(
    wizard_type: &str,
    data: &HashMap<String, Value>,
) -> Result<Option<String>, ErrorShape> {
    let snapshot = read_config_snapshot();
    let mut config_value = snapshot.config.clone();
    let applied = apply_wizard_config(wizard_type, data, &mut config_value)?;

    if !applied {
        return Ok(None);
    }

    let issues = map_validation_issues(config::validate_config(&config_value));
    if !issues.is_empty() {
        return Err(error_shape(
            ERROR_INVALID_REQUEST,
            "invalid config",
            Some(json!({ "issues": issues })),
        ));
    }

    let path = config::get_config_path();
    write_config_file(&path, &config_value)?;
    Ok(Some(path.display().to_string()))
}

/// Start a new wizard
pub(super) fn handle_wizard_start(params: Option<&Value>) -> Result<Value, ErrorShape> {
    let wizard_type = params
        .and_then(|v| v.get("type"))
        .and_then(|v| v.as_str())
        .unwrap_or("setup");

    if !WIZARD_TYPES.contains(&wizard_type) {
        return Err(error_shape(
            ERROR_INVALID_REQUEST,
            &format!("unknown wizard type: {}", wizard_type),
            Some(json!({ "validTypes": WIZARD_TYPES })),
        ));
    }

    let conn_id = params
        .and_then(|v| v.get("connId"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let mut manager = WIZARD_STATE.write();

    // Check for existing active wizard
    if let Some(active) = manager.active_wizard() {
        return Err(error_shape(
            ERROR_INVALID_REQUEST,
            "a wizard is already active",
            Some(json!({
                "activeWizardId": active.id,
                "type": active.wizard_type
            })),
        ));
    }

    let session = manager.create_wizard(wizard_type, conn_id);
    let current_step = session.steps.first().cloned();

    Ok(json!({
        "ok": true,
        "wizardId": session.id,
        "type": session.wizard_type,
        "step": session.current_step,
        "totalSteps": session.total_steps,
        "currentStep": current_step,
        "complete": false
    }))
}

/// Advance to the next wizard step
pub(super) fn handle_wizard_next(params: Option<&Value>) -> Result<Value, ErrorShape> {
    let wizard_id = params
        .and_then(|v| v.get("wizardId"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "wizardId is required", None))?;

    let input = params.and_then(|v| v.get("input")).cloned();

    let (wizard_type, wizard_data, total_steps, next_step) = {
        let mut manager = WIZARD_STATE.write();
        let wizard = manager
            .get_wizard_mut(wizard_id)
            .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "wizard not found", None))?;

        if wizard.complete {
            return Err(error_shape(
                ERROR_INVALID_REQUEST,
                "wizard is already complete",
                None,
            ));
        }

        if wizard.cancelled {
            return Err(error_shape(
                ERROR_INVALID_REQUEST,
                "wizard was cancelled",
                None,
            ));
        }

        // Validate and store current step input
        if let Some(current_step) = wizard.steps.get(wizard.current_step) {
            validate_step_input(current_step, input.as_ref())?;
            let step_id = current_step.id.clone();
            if let Some(value) = input {
                wizard.data.insert(step_id, value);
            }
        }

        wizard.last_activity = now_ms();
        let next_step = wizard.current_step + 1;

        if next_step < wizard.total_steps {
            wizard.current_step = next_step;
            let current_step = wizard.steps.get(wizard.current_step).cloned();
            return Ok(json!({
                "ok": true,
                "wizardId": wizard.id,
                "step": wizard.current_step,
                "totalSteps": wizard.total_steps,
                "currentStep": current_step,
                "complete": false
            }));
        }

        (
            wizard.wizard_type.clone(),
            wizard.data.clone(),
            wizard.total_steps,
            next_step,
        )
    };

    let applied_path = persist_wizard_config(&wizard_type, &wizard_data)?;

    {
        let mut manager = WIZARD_STATE.write();
        if let Some(wizard) = manager.get_wizard_mut(wizard_id) {
            wizard.complete = true;
            wizard.current_step = next_step;
            wizard.data.clear();
            wizard.last_activity = now_ms();
        }
    }

    Ok(json!({
        "ok": true,
        "wizardId": wizard_id,
        "step": next_step,
        "totalSteps": total_steps,
        "complete": true,
        "applied": applied_path.is_some(),
        "configPath": applied_path
    }))
}

/// Go back to the previous wizard step
pub(super) fn handle_wizard_back(params: Option<&Value>) -> Result<Value, ErrorShape> {
    let wizard_id = params
        .and_then(|v| v.get("wizardId"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "wizardId is required", None))?;

    let mut manager = WIZARD_STATE.write();
    let wizard = manager
        .get_wizard_mut(wizard_id)
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "wizard not found", None))?;

    if wizard.current_step == 0 {
        return Err(error_shape(
            ERROR_INVALID_REQUEST,
            "already at first step",
            None,
        ));
    }

    wizard.current_step -= 1;
    wizard.last_activity = now_ms();

    let current_step = wizard.steps.get(wizard.current_step).cloned();
    let step_id = current_step.as_ref().map(|s| s.id.clone());
    let previous_input = step_id.and_then(|id| wizard.data.get(&id).cloned());

    Ok(json!({
        "ok": true,
        "wizardId": wizard.id,
        "step": wizard.current_step,
        "totalSteps": wizard.total_steps,
        "currentStep": current_step,
        "previousInput": previous_input,
        "complete": false
    }))
}

/// Cancel an active wizard
pub(super) fn handle_wizard_cancel(params: Option<&Value>) -> Result<Value, ErrorShape> {
    let wizard_id = params
        .and_then(|v| v.get("wizardId"))
        .and_then(|v| v.as_str());

    let mut manager = WIZARD_STATE.write();

    // If wizard_id provided, cancel that specific wizard
    // Otherwise, cancel the active wizard
    let id_to_cancel = if let Some(id) = wizard_id {
        Some(id.to_string())
    } else {
        manager.active_wizard().map(|w| w.id.clone())
    };

    if let Some(id) = id_to_cancel {
        if let Some(wizard) = manager.cancel_wizard(&id) {
            return Ok(json!({
                "ok": true,
                "cancelled": true,
                "wizardId": wizard.id,
                "type": wizard.wizard_type
            }));
        }
    }

    Ok(json!({
        "ok": true,
        "cancelled": false,
        "reason": "no active wizard"
    }))
}

/// Get wizard status
pub(super) fn handle_wizard_status(params: Option<&Value>) -> Result<Value, ErrorShape> {
    let wizard_id = params
        .and_then(|v| v.get("wizardId"))
        .and_then(|v| v.as_str());

    let manager = WIZARD_STATE.read();

    // If wizard_id provided, get that specific wizard
    // Otherwise, get the active wizard
    let wizard = if let Some(id) = wizard_id {
        manager.get_wizard(id)
    } else {
        manager.active_wizard()
    };

    match wizard {
        Some(w) => {
            let current_step = w.steps.get(w.current_step).cloned();
            Ok(json!({
                "active": !w.complete && !w.cancelled,
                "wizardId": w.id,
                "type": w.wizard_type,
                "step": w.current_step,
                "totalSteps": w.total_steps,
                "currentStep": current_step,
                "complete": w.complete,
                "cancelled": w.cancelled,
                "createdAt": w.created_at,
                "lastActivity": w.last_activity
            }))
        }
        None => Ok(json!({
            "active": false,
            "wizardId": null
        })),
    }
}

/// List all active wizards
pub(super) fn handle_wizard_list() -> Result<Value, ErrorShape> {
    let manager = WIZARD_STATE.read();

    let wizards: Vec<Value> = manager
        .wizards
        .values()
        .filter(|w| !w.complete && !w.cancelled)
        .map(|w| {
            json!({
                "wizardId": w.id,
                "type": w.wizard_type,
                "step": w.current_step,
                "totalSteps": w.total_steps,
                "createdAt": w.created_at
            })
        })
        .collect();

    Ok(json!({
        "wizards": wizards,
        "count": wizards.len()
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Mutex to serialize tests that modify global state
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    fn reset_state() {
        let mut manager = WIZARD_STATE.write();
        manager.wizards.clear();
    }

    #[test]
    fn test_wizard_start() {
        let _lock = TEST_LOCK.lock().unwrap();
        reset_state();
        let params = json!({ "type": "setup" });
        let result = handle_wizard_start(Some(&params)).unwrap();
        assert_eq!(result["ok"], true);
        assert_eq!(result["type"], "setup");
        assert_eq!(result["step"], 0);
        assert!(result["totalSteps"].as_i64().unwrap() > 0);
        assert_eq!(result["complete"], false);
    }

    #[test]
    fn test_wizard_start_invalid_type() {
        let _lock = TEST_LOCK.lock().unwrap();
        reset_state();
        let params = json!({ "type": "invalid" });
        let result = handle_wizard_start(Some(&params));
        assert!(result.is_err());
    }

    #[test]
    fn test_wizard_next() {
        let _lock = TEST_LOCK.lock().unwrap();
        reset_state();

        // Start wizard
        let start_params = json!({ "type": "setup" });
        let start_result = handle_wizard_start(Some(&start_params)).unwrap();
        let wizard_id = start_result["wizardId"].as_str().unwrap();

        // Advance to next step
        let next_params = json!({
            "wizardId": wizard_id,
            "input": true
        });
        let result = handle_wizard_next(Some(&next_params)).unwrap();
        assert_eq!(result["ok"], true);
        assert_eq!(result["step"], 1);
    }

    #[test]
    fn test_wizard_cancel() {
        let _lock = TEST_LOCK.lock().unwrap();
        reset_state();

        // Start wizard
        let start_params = json!({ "type": "setup" });
        let start_result = handle_wizard_start(Some(&start_params)).unwrap();
        let wizard_id = start_result["wizardId"].as_str().unwrap();

        // Cancel wizard
        let cancel_params = json!({ "wizardId": wizard_id });
        let result = handle_wizard_cancel(Some(&cancel_params)).unwrap();
        assert_eq!(result["ok"], true);
        assert_eq!(result["cancelled"], true);
    }

    #[test]
    fn test_wizard_status() {
        let _lock = TEST_LOCK.lock().unwrap();
        reset_state();
        let result = handle_wizard_status(None).unwrap();
        assert_eq!(result["active"], false);
        assert!(result["wizardId"].is_null());
    }

    #[test]
    fn test_wizard_status_with_active() {
        let _lock = TEST_LOCK.lock().unwrap();
        reset_state();

        // Start wizard
        let start_params = json!({ "type": "setup" });
        handle_wizard_start(Some(&start_params)).unwrap();

        // Check status
        let result = handle_wizard_status(None).unwrap();
        assert_eq!(result["active"], true);
        assert_eq!(result["type"], "setup");
    }

    #[test]
    fn test_wizard_cannot_start_when_active() {
        let _lock = TEST_LOCK.lock().unwrap();
        reset_state();

        // Start first wizard
        let start_params = json!({ "type": "setup" });
        handle_wizard_start(Some(&start_params)).unwrap();

        // Try to start another
        let result = handle_wizard_start(Some(&start_params));
        assert!(result.is_err());
    }

    #[test]
    fn test_wizard_list() {
        let _lock = TEST_LOCK.lock().unwrap();
        reset_state();

        // Start wizard
        let start_params = json!({ "type": "setup" });
        handle_wizard_start(Some(&start_params)).unwrap();

        // List wizards
        let result = handle_wizard_list().unwrap();
        assert_eq!(result["count"], 1);
    }

    #[test]
    fn test_apply_setup_wizard_updates_config() {
        let mut data = HashMap::new();
        data.insert("provider".to_string(), json!("anthropic"));
        data.insert("api_key".to_string(), json!("sk-test"));
        let mut config_value = json!({});

        let applied = apply_wizard_config("setup", &data, &mut config_value).unwrap();
        assert!(applied);
        assert_eq!(
            config_value["anthropic"]["apiKey"],
            Value::String("sk-test".to_string())
        );
        assert_eq!(
            config_value["gateway"]["auth"]["mode"],
            Value::String("token".to_string())
        );
        assert_eq!(
            config_value["agents"]["defaults"]["model"],
            Value::String("claude-sonnet-4-20250514".to_string())
        );
        assert_eq!(
            config_value["gateway"]["bind"],
            Value::String("loopback".to_string())
        );
        assert_eq!(
            config_value["gateway"]["port"],
            Value::Number(DEFAULT_PORT.into())
        );
        assert!(config_value["gateway"]["auth"]["token"]
            .as_str()
            .map(|v| !v.is_empty())
            .unwrap_or(false));
    }

    #[test]
    fn test_apply_setup_wizard_respects_auth_and_bind_overrides() {
        let mut data = HashMap::new();
        data.insert("provider".to_string(), json!("openai"));
        data.insert("api_key".to_string(), json!("sk-openai"));
        data.insert("auth_mode".to_string(), json!("password"));
        data.insert("auth_secret".to_string(), json!("my-password"));
        data.insert("bind_mode".to_string(), json!("lan"));
        data.insert("port".to_string(), json!("19001"));
        let mut config_value = json!({});

        let applied = apply_wizard_config("setup", &data, &mut config_value).unwrap();
        assert!(applied);
        assert_eq!(
            config_value["openai"]["apiKey"],
            Value::String("sk-openai".to_string())
        );
        assert_eq!(
            config_value["gateway"]["auth"]["mode"],
            Value::String("password".to_string())
        );
        assert_eq!(
            config_value["agents"]["defaults"]["model"],
            Value::String("gpt-4o".to_string())
        );
        assert_eq!(
            config_value["gateway"]["auth"]["password"],
            Value::String("my-password".to_string())
        );
        assert_eq!(
            config_value["gateway"]["bind"],
            Value::String("lan".to_string())
        );
        assert_eq!(config_value["gateway"]["port"], Value::Number(19001.into()));
    }

    #[test]
    fn test_apply_channel_wizard_updates_config() {
        let mut data = HashMap::new();
        data.insert("channel_type".to_string(), json!("telegram"));
        data.insert("channel_token".to_string(), json!("bot:token"));
        let mut config_value = json!({});

        let applied = apply_wizard_config("channel", &data, &mut config_value).unwrap();
        assert!(applied);
        assert_eq!(
            config_value["telegram"]["botToken"],
            Value::String("bot:token".to_string())
        );
        assert_eq!(config_value["telegram"]["enabled"], Value::Bool(true));
    }

    #[test]
    fn test_apply_agent_wizard_updates_identity() {
        let mut data = HashMap::new();
        data.insert("agent_name".to_string(), json!("Nova"));
        data.insert("agent_personality".to_string(), json!("Helpful and calm."));
        let mut config_value = json!({
            "agents": {
                "list": [{
                    "id": "default",
                    "default": true,
                    "identity": { "name": "Old" }
                }]
            }
        });

        let applied = apply_wizard_config("agent", &data, &mut config_value).unwrap();
        assert!(applied);
        assert_eq!(
            config_value["agents"]["list"][0]["identity"]["name"],
            Value::String("Nova".to_string())
        );
        assert_eq!(
            config_value["agents"]["list"][0]["identity"]["description"],
            Value::String("Helpful and calm.".to_string())
        );
    }
}
