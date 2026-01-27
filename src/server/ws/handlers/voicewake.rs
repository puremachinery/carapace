//! Voicewake state and handlers.
//!
//! Manages voice wake detection settings including keyword configuration
//! and enabled/disabled state.

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::LazyLock;

use super::super::*;

/// Available wake keywords
pub const WAKE_KEYWORDS: [&str; 4] = ["hey claude", "ok claude", "claude", "jarvis"];

/// Global voicewake state
static VOICEWAKE_STATE: LazyLock<RwLock<VoicewakeState>> =
    LazyLock::new(|| RwLock::new(VoicewakeState::default()));

/// Voicewake configuration state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoicewakeState {
    /// Whether voicewake is enabled
    pub enabled: bool,
    /// Active wake keyword (primary, for backward compat)
    pub keyword: Option<String>,
    /// All active triggers (Node parity)
    pub triggers: Vec<String>,
    /// Sensitivity level (0.0 to 1.0)
    pub sensitivity: f64,
    /// Whether to play a confirmation sound
    pub confirmation_sound: bool,
    /// Minimum confidence threshold
    pub threshold: f64,
    /// Per-device settings
    pub device_settings: HashMap<String, DeviceVoicewakeSettings>,
}

impl Default for VoicewakeState {
    fn default() -> Self {
        Self {
            enabled: false,
            keyword: None,
            triggers: Vec::new(),
            sensitivity: 0.5,
            confirmation_sound: true,
            threshold: 0.7,
            device_settings: HashMap::new(),
        }
    }
}

/// Per-device voicewake settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceVoicewakeSettings {
    pub enabled: bool,
    pub keyword: Option<String>,
    pub sensitivity: Option<f64>,
}

/// Get the current voicewake state
/// Per Node semantics: returns {triggers: string[]}
pub(super) fn handle_voicewake_get() -> Result<Value, ErrorShape> {
    let state = VOICEWAKE_STATE.read();
    // Node format: return all stored triggers (empty if disabled)
    let triggers: Vec<String> = if state.enabled {
        state.triggers.clone()
    } else {
        Vec::new()
    };

    Ok(json!({
        "triggers": triggers
    }))
}

/// Enable voicewake
pub(super) fn handle_voicewake_enable(params: Option<&Value>) -> Result<Value, ErrorShape> {
    let mut state = VOICEWAKE_STATE.write();

    // Set keyword if provided (and sync to triggers)
    if let Some(keyword) = params
        .and_then(|v| v.get("keyword"))
        .and_then(|v| v.as_str())
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
    {
        let kw = keyword.to_string();
        state.keyword = Some(kw.clone());
        // Sync triggers: if empty or keyword not in triggers, set it
        if state.triggers.is_empty() || !state.triggers.contains(&kw) {
            state.triggers = vec![kw];
        }
    }

    // Set sensitivity if provided
    if let Some(sensitivity) = params
        .and_then(|v| v.get("sensitivity"))
        .and_then(|v| v.as_f64())
    {
        state.sensitivity = sensitivity.clamp(0.0, 1.0);
    }

    state.enabled = true;

    Ok(json!({
        "ok": true,
        "enabled": true,
        "keyword": state.keyword,
        "sensitivity": state.sensitivity
    }))
}

/// Disable voicewake
pub(super) fn handle_voicewake_disable() -> Result<Value, ErrorShape> {
    let mut state = VOICEWAKE_STATE.write();
    state.enabled = false;

    Ok(json!({
        "ok": true,
        "enabled": false
    }))
}

/// Maximum number of triggers allowed
const MAX_TRIGGERS: usize = 32;
/// Maximum length of each trigger
const MAX_TRIGGER_LEN: usize = 64;
/// Default triggers to use when list is empty after sanitization (Node defaults)
const DEFAULT_TRIGGERS: [&str; 3] = ["clawd", "claude", "computer"];

/// Normalize voice wake triggers per Node's normalizeVoiceWakeTriggers:
/// - Trim whitespace
/// - Truncate each trigger to 64 chars
/// - Clamp to 32 entries max
/// - Filter empty strings
/// - Fall back to default triggers when empty
/// Note: Node does NOT lowercase or dedupe
fn normalize_triggers(raw: Vec<String>) -> Vec<String> {
    let sanitized: Vec<String> = raw
        .into_iter()
        .map(|s| {
            let trimmed = s.trim();
            if trimmed.len() > MAX_TRIGGER_LEN {
                trimmed[..MAX_TRIGGER_LEN].to_string()
            } else {
                trimmed.to_string()
            }
        })
        .filter(|s| !s.is_empty())
        .take(MAX_TRIGGERS)
        .collect();

    // Fall back to defaults when empty (Node behavior)
    if sanitized.is_empty() {
        DEFAULT_TRIGGERS.iter().map(|s| s.to_string()).collect()
    } else {
        sanitized
    }
}

/// Set voicewake settings
/// Per Node semantics: accepts {triggers: string[]} and returns {triggers: string[]}
/// Rejects requests without a valid triggers array (INVALID_REQUEST per Node parity)
/// Normalizes triggers: trim, truncate, clamp count, default fallback (Node keeps case, no dedupe).
/// Broadcasts voicewake.changed event to all connected clients.
pub(super) fn handle_voicewake_set(
    params: Option<&Value>,
    state: Option<&WsServerState>,
) -> Result<Value, ErrorShape> {
    // Per Node parity: triggers must be a string array, reject if missing or not an array
    let triggers_value = params
        .and_then(|v| v.get("triggers"))
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "triggers is required", None))?;

    let triggers_array = triggers_value
        .as_array()
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "triggers must be an array", None))?;

    // Validate all elements are strings
    let raw_triggers: Vec<String> = triggers_array
        .iter()
        .map(|v| {
            v.as_str()
                .map(|s| s.to_string())
                .ok_or_else(|| {
                    error_shape(
                        ERROR_INVALID_REQUEST,
                        "triggers must be an array of strings",
                        None,
                    )
                })
        })
        .collect::<Result<Vec<_>, _>>()?;

    // Normalize: trim, truncate, clamp count, default fallback (Node keeps case, no dedupe)
    let triggers = normalize_triggers(raw_triggers);

    {
        let mut voicewake_state = VOICEWAKE_STATE.write();

        // Store all triggers and use first as primary keyword for backward compat
        voicewake_state.triggers = triggers.clone();
        voicewake_state.keyword = triggers.first().cloned();
        voicewake_state.enabled = !triggers.is_empty();
    }

    // Broadcast voicewake.changed event to all connected clients (Node parity)
    if let Some(ws_state) = state {
        broadcast_event(
            ws_state,
            "voicewake.changed",
            json!({
                "triggers": triggers
            }),
        );
    }

    Ok(json!({
        "triggers": triggers
    }))
}

/// List available wake keywords
pub(super) fn handle_voicewake_keywords() -> Result<Value, ErrorShape> {
    Ok(json!({
        "keywords": WAKE_KEYWORDS
    }))
}

/// Test voicewake detection (for calibration)
pub(super) fn handle_voicewake_test(params: Option<&Value>) -> Result<Value, ErrorShape> {
    let audio_data = params
        .and_then(|v| v.get("audioData"))
        .and_then(|v| v.as_str());

    let state = VOICEWAKE_STATE.read();

    // In a real implementation, this would process audio through wake word detection
    // For now, return a simulated result
    Ok(json!({
        "ok": true,
        "detected": false,
        "confidence": 0.0,
        "keyword": state.keyword,
        "threshold": state.threshold,
        "hasAudioData": audio_data.is_some()
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Mutex to serialize tests that modify global state
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    fn reset_state() {
        let mut state = VOICEWAKE_STATE.write();
        *state = VoicewakeState::default();
    }

    #[test]
    fn test_voicewake_get_default() {
        let _lock = TEST_LOCK.lock().unwrap();
        reset_state();
        let result = handle_voicewake_get().unwrap();
        // Node format: {triggers: []}
        let triggers = result["triggers"].as_array().unwrap();
        assert!(triggers.is_empty());
    }

    #[test]
    fn test_voicewake_enable() {
        let _lock = TEST_LOCK.lock().unwrap();
        reset_state();
        let params = json!({
            "keyword": "hey claude",
            "sensitivity": 0.8
        });
        let result = handle_voicewake_enable(Some(&params)).unwrap();
        assert_eq!(result["ok"], true);
        assert_eq!(result["enabled"], true);
        assert_eq!(result["keyword"], "hey claude");
        assert_eq!(result["sensitivity"], 0.8);
    }

    #[test]
    fn test_voicewake_disable() {
        let _lock = TEST_LOCK.lock().unwrap();
        reset_state();
        // First enable
        handle_voicewake_enable(None).unwrap();

        // Then disable
        let result = handle_voicewake_disable().unwrap();
        assert_eq!(result["ok"], true);
        assert_eq!(result["enabled"], false);
    }

    #[test]
    fn test_voicewake_set() {
        let _lock = TEST_LOCK.lock().unwrap();
        reset_state();
        // Node format: {triggers: string[]}
        let params = json!({
            "triggers": ["claude"]
        });
        let result = handle_voicewake_set(Some(&params), None).unwrap();
        let triggers = result["triggers"].as_array().unwrap();
        assert_eq!(triggers.len(), 1);
        assert_eq!(triggers[0], "claude");
    }

    #[test]
    fn test_voicewake_set_multiple_triggers() {
        let _lock = TEST_LOCK.lock().unwrap();
        reset_state();
        let params = json!({
            "triggers": ["hey claude", "ok claude", "claude"]
        });
        let result = handle_voicewake_set(Some(&params), None).unwrap();
        let triggers = result["triggers"].as_array().unwrap();
        assert_eq!(triggers.len(), 3);
    }

    #[test]
    fn test_voicewake_keywords() {
        let result = handle_voicewake_keywords().unwrap();
        let keywords = result["keywords"].as_array().unwrap();
        assert!(keywords.len() >= 3);
        assert!(keywords.contains(&json!("hey claude")));
    }

    #[test]
    fn test_voicewake_set_triggers_format() {
        let _lock = TEST_LOCK.lock().unwrap();
        reset_state();
        // Node format: {triggers: string[]}
        let params = json!({
            "triggers": ["hey claude", "ok claude"]
        });
        let result = handle_voicewake_set(Some(&params), None).unwrap();
        let triggers = result["triggers"].as_array().unwrap();
        assert_eq!(triggers.len(), 2);
        assert_eq!(triggers[0], "hey claude");
    }

    #[test]
    fn test_voicewake_set_empty_triggers_uses_defaults() {
        let _lock = TEST_LOCK.lock().unwrap();
        reset_state();
        // Empty triggers falls back to defaults (Node behavior)
        let params = json!({
            "triggers": []
        });
        let result = handle_voicewake_set(Some(&params), None).unwrap();
        let triggers = result["triggers"].as_array().unwrap();
        // Should have default triggers: ["clawd", "claude", "computer"]
        assert_eq!(triggers.len(), 3);
        assert_eq!(triggers[0], "clawd");
        assert_eq!(triggers[1], "claude");
        assert_eq!(triggers[2], "computer");
    }

    #[test]
    fn test_voicewake_get_after_set() {
        let _lock = TEST_LOCK.lock().unwrap();
        reset_state();
        // Set triggers
        let params = json!({
            "triggers": ["hey claude"]
        });
        handle_voicewake_set(Some(&params), None).unwrap();

        // Get should return the triggers
        let result = handle_voicewake_get().unwrap();
        let triggers = result["triggers"].as_array().unwrap();
        assert_eq!(triggers.len(), 1);
        assert_eq!(triggers[0], "hey claude");
    }

    #[test]
    fn test_voicewake_set_rejects_missing_triggers() {
        let _lock = TEST_LOCK.lock().unwrap();
        reset_state();
        // Missing triggers should return error
        let params = json!({});
        let result = handle_voicewake_set(Some(&params), None);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.message, "triggers is required");
    }

    #[test]
    fn test_voicewake_set_rejects_non_array_triggers() {
        let _lock = TEST_LOCK.lock().unwrap();
        reset_state();
        // triggers as string should return error
        let params = json!({ "triggers": "hey claude" });
        let result = handle_voicewake_set(Some(&params), None);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.message, "triggers must be an array");
    }

    #[test]
    fn test_voicewake_set_rejects_non_string_elements() {
        let _lock = TEST_LOCK.lock().unwrap();
        reset_state();
        // triggers with non-string elements should return error
        let params = json!({ "triggers": ["hey claude", 123] });
        let result = handle_voicewake_set(Some(&params), None);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.message, "triggers must be an array of strings");
    }

    #[test]
    fn test_voicewake_set_preserves_case() {
        let _lock = TEST_LOCK.lock().unwrap();
        reset_state();
        // Node preserves case (does NOT lowercase)
        let params = json!({ "triggers": ["Hey Claude", "OK CLAUDE"] });
        let result = handle_voicewake_set(Some(&params), None).unwrap();
        let triggers = result["triggers"].as_array().unwrap();
        assert_eq!(triggers[0], "Hey Claude");
        assert_eq!(triggers[1], "OK CLAUDE");
    }

    #[test]
    fn test_voicewake_set_allows_duplicates() {
        let _lock = TEST_LOCK.lock().unwrap();
        reset_state();
        // Node does NOT dedupe triggers
        let params = json!({ "triggers": ["hey claude", "hey claude", "Hey Claude"] });
        let result = handle_voicewake_set(Some(&params), None).unwrap();
        let triggers = result["triggers"].as_array().unwrap();
        assert_eq!(triggers.len(), 3);
    }

    #[test]
    fn test_voicewake_set_trims_whitespace() {
        let _lock = TEST_LOCK.lock().unwrap();
        reset_state();
        // Whitespace should be trimmed
        let params = json!({ "triggers": ["  hey claude  ", "\tok claude\n"] });
        let result = handle_voicewake_set(Some(&params), None).unwrap();
        let triggers = result["triggers"].as_array().unwrap();
        assert_eq!(triggers[0], "hey claude");
        assert_eq!(triggers[1], "ok claude");
    }

    #[test]
    fn test_voicewake_set_defaults_when_empty() {
        let _lock = TEST_LOCK.lock().unwrap();
        reset_state();
        // Empty list should fall back to defaults (Node behavior)
        let params = json!({ "triggers": ["   ", ""] });
        let result = handle_voicewake_set(Some(&params), None).unwrap();
        let triggers = result["triggers"].as_array().unwrap();
        // Node defaults: ["clawd", "claude", "computer"]
        assert_eq!(triggers.len(), 3);
        assert_eq!(triggers[0], "clawd");
    }

    #[test]
    fn test_voicewake_set_clamps_count() {
        let _lock = TEST_LOCK.lock().unwrap();
        reset_state();
        // Should clamp to 32 entries max
        let many_triggers: Vec<String> = (0..50).map(|i| format!("trigger {}", i)).collect();
        let params = json!({ "triggers": many_triggers });
        let result = handle_voicewake_set(Some(&params), None).unwrap();
        let triggers = result["triggers"].as_array().unwrap();
        assert_eq!(triggers.len(), 32);
    }

    #[test]
    fn test_voicewake_set_truncates_long_triggers() {
        let _lock = TEST_LOCK.lock().unwrap();
        reset_state();
        // Each trigger should be truncated to 64 chars
        let long_trigger = "a".repeat(100);
        let params = json!({ "triggers": [long_trigger] });
        let result = handle_voicewake_set(Some(&params), None).unwrap();
        let triggers = result["triggers"].as_array().unwrap();
        assert_eq!(triggers[0].as_str().unwrap().len(), 64);
    }
}
