//! Setup wizard handlers.
//!
//! Manages interactive setup wizards for configuring channels, agents,
//! and other system components.

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::LazyLock;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use uuid::Uuid;

use super::super::*;

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

/// Start a new wizard
pub(super) fn handle_wizard_start(params: Option<&Value>) -> Result<Value, ErrorShape> {
    tracing::debug!("wizard.start: stub response");
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
        "stub": true,
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
    tracing::debug!("wizard.next: stub response");
    let wizard_id = params
        .and_then(|v| v.get("wizardId"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "wizardId is required", None))?;

    let input = params.and_then(|v| v.get("input")).cloned();

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
        let step_id = current_step.id.clone();

        // Check if required input is provided
        if current_step.required && input.is_none() {
            return Err(error_shape(
                ERROR_INVALID_REQUEST,
                "input is required for this step",
                None,
            ));
        }

        // Store the input
        if let Some(value) = input {
            wizard.data.insert(step_id, value);
        }
    }

    wizard.last_activity = now_ms();

    // Advance to next step
    wizard.current_step += 1;

    // Check if wizard is complete
    if wizard.current_step >= wizard.total_steps {
        wizard.complete = true;
        let result = json!({
            "stub": true,
            "ok": true,
            "wizardId": wizard.id,
            "step": wizard.current_step,
            "totalSteps": wizard.total_steps,
            "complete": true,
            "data": wizard.data
        });
        return Ok(result);
    }

    let current_step = wizard.steps.get(wizard.current_step).cloned();

    Ok(json!({
        "stub": true,
        "ok": true,
        "wizardId": wizard.id,
        "step": wizard.current_step,
        "totalSteps": wizard.total_steps,
        "currentStep": current_step,
        "complete": false
    }))
}

/// Go back to the previous wizard step
pub(super) fn handle_wizard_back(params: Option<&Value>) -> Result<Value, ErrorShape> {
    tracing::debug!("wizard.back: stub response");
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
        "stub": true,
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
    tracing::debug!("wizard.cancel: stub response");
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
                "stub": true,
                "ok": true,
                "cancelled": true,
                "wizardId": wizard.id,
                "type": wizard.wizard_type
            }));
        }
    }

    Ok(json!({
        "stub": true,
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
}
