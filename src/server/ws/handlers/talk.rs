//! Talk mode handlers.
//!
//! Manages conversational talk modes including voice, push-to-talk,
//! and continuous listening settings.

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::LazyLock;

use super::super::*;

/// Available talk modes
pub const TALK_MODES: [&str; 4] = ["off", "push-to-talk", "voice-activated", "continuous"];

/// Global talk state
static TALK_STATE: LazyLock<RwLock<TalkState>> =
    LazyLock::new(|| RwLock::new(TalkState::default()));

/// Talk mode configuration state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TalkState {
    /// Current talk mode
    pub mode: String,
    /// Whether talk mode is active (listening)
    pub active: bool,
    /// Voice activity detection threshold (0.0 to 1.0)
    pub vad_threshold: f64,
    /// Silence timeout in milliseconds
    pub silence_timeout_ms: u64,
    /// Whether to automatically respond
    pub auto_respond: bool,
    /// Input device ID
    pub input_device: Option<String>,
    /// Output device ID
    pub output_device: Option<String>,
}

impl Default for TalkState {
    fn default() -> Self {
        Self {
            mode: "off".to_string(),
            active: false,
            vad_threshold: 0.3,
            silence_timeout_ms: 1500,
            auto_respond: true,
            input_device: None,
            output_device: None,
        }
    }
}

/// Set talk mode
pub(super) fn handle_talk_mode(params: Option<&Value>) -> Result<Value, ErrorShape> {
    let mode = params
        .and_then(|v| v.get("mode"))
        .and_then(|v| v.as_str())
        .unwrap_or("off");

    if !TALK_MODES.contains(&mode) {
        return Err(error_shape(
            ERROR_INVALID_REQUEST,
            &format!("unknown talk mode: {}", mode),
            Some(json!({ "validModes": TALK_MODES })),
        ));
    }

    let mut state = TALK_STATE.write();
    let previous_mode = state.mode.clone();
    state.mode = mode.to_string();

    // Auto-activate non-off modes
    state.active = mode != "off";

    Ok(json!({
        "ok": true,
        "mode": mode,
        "previousMode": previous_mode,
        "active": state.active
    }))
}

/// Get talk mode status
pub(super) fn handle_talk_status() -> Result<Value, ErrorShape> {
    let state = TALK_STATE.read();

    Ok(json!({
        "mode": state.mode,
        "active": state.active,
        "vadThreshold": state.vad_threshold,
        "silenceTimeoutMs": state.silence_timeout_ms,
        "autoRespond": state.auto_respond,
        "inputDevice": state.input_device,
        "outputDevice": state.output_device,
        "availableModes": TALK_MODES
    }))
}

/// Start talk (begin listening)
pub(super) fn handle_talk_start(params: Option<&Value>) -> Result<Value, ErrorShape> {
    let mut state = TALK_STATE.write();

    if state.mode == "off" {
        return Err(error_shape(
            ERROR_INVALID_REQUEST,
            "talk mode is off; set a mode first",
            None,
        ));
    }

    state.active = true;

    // Optional session key for the conversation
    let session_key = params
        .and_then(|v| v.get("sessionKey"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    Ok(json!({
        "ok": true,
        "active": true,
        "mode": state.mode,
        "sessionKey": session_key
    }))
}

/// Stop talk (stop listening)
pub(super) fn handle_talk_stop() -> Result<Value, ErrorShape> {
    let mut state = TALK_STATE.write();
    state.active = false;

    Ok(json!({
        "ok": true,
        "active": false,
        "mode": state.mode
    }))
}

/// Configure talk settings
pub(super) fn handle_talk_configure(params: Option<&Value>) -> Result<Value, ErrorShape> {
    let mut state = TALK_STATE.write();

    if let Some(threshold) = params
        .and_then(|v| v.get("vadThreshold"))
        .and_then(|v| v.as_f64())
    {
        state.vad_threshold = threshold.clamp(0.0, 1.0);
    }

    if let Some(timeout) = params
        .and_then(|v| v.get("silenceTimeoutMs"))
        .and_then(|v| v.as_i64())
    {
        state.silence_timeout_ms = timeout.max(100) as u64;
    }

    if let Some(auto) = params
        .and_then(|v| v.get("autoRespond"))
        .and_then(|v| v.as_bool())
    {
        state.auto_respond = auto;
    }

    if let Some(input) = params
        .and_then(|v| v.get("inputDevice"))
        .and_then(|v| v.as_str())
    {
        state.input_device = Some(input.to_string());
    }

    if let Some(output) = params
        .and_then(|v| v.get("outputDevice"))
        .and_then(|v| v.as_str())
    {
        state.output_device = Some(output.to_string());
    }

    Ok(json!({
        "ok": true,
        "vadThreshold": state.vad_threshold,
        "silenceTimeoutMs": state.silence_timeout_ms,
        "autoRespond": state.auto_respond,
        "inputDevice": state.input_device,
        "outputDevice": state.output_device
    }))
}

/// List available audio devices
pub(super) fn handle_talk_devices() -> Result<Value, ErrorShape> {
    tracing::debug!("talk.devices: stub response");
    // In a real implementation, this would enumerate audio devices
    // For now, return simulated devices
    Ok(json!({
        "stub": true,
        "inputDevices": [
            { "id": "default", "name": "Default Input", "default": true },
            { "id": "built-in-mic", "name": "Built-in Microphone", "default": false }
        ],
        "outputDevices": [
            { "id": "default", "name": "Default Output", "default": true },
            { "id": "built-in-speakers", "name": "Built-in Speakers", "default": false }
        ]
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Mutex to serialize tests that modify global state
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    fn reset_state() {
        let mut state = TALK_STATE.write();
        *state = TalkState::default();
    }

    #[test]
    fn test_talk_mode_default() {
        let _lock = TEST_LOCK.lock().unwrap();
        reset_state();
        let result = handle_talk_status().unwrap();
        assert_eq!(result["mode"], "off");
        assert_eq!(result["active"], false);
    }

    #[test]
    fn test_talk_mode_set() {
        let _lock = TEST_LOCK.lock().unwrap();
        reset_state();
        let params = json!({ "mode": "push-to-talk" });
        let result = handle_talk_mode(Some(&params)).unwrap();
        assert_eq!(result["ok"], true);
        assert_eq!(result["mode"], "push-to-talk");
        assert_eq!(result["active"], true);
    }

    #[test]
    fn test_talk_mode_invalid() {
        let _lock = TEST_LOCK.lock().unwrap();
        reset_state();
        let params = json!({ "mode": "invalid" });
        let result = handle_talk_mode(Some(&params));
        assert!(result.is_err());
    }

    #[test]
    fn test_talk_start_requires_mode() {
        let _lock = TEST_LOCK.lock().unwrap();
        reset_state();
        let result = handle_talk_start(None);
        assert!(result.is_err());
    }

    #[test]
    fn test_talk_start_stop() {
        let _lock = TEST_LOCK.lock().unwrap();
        reset_state();

        // Set mode first
        let mode_params = json!({ "mode": "push-to-talk" });
        handle_talk_mode(Some(&mode_params)).unwrap();

        // Start
        let result = handle_talk_start(None).unwrap();
        assert_eq!(result["active"], true);

        // Stop
        let result = handle_talk_stop().unwrap();
        assert_eq!(result["active"], false);
    }

    #[test]
    fn test_talk_configure() {
        let _lock = TEST_LOCK.lock().unwrap();
        reset_state();
        let params = json!({
            "vadThreshold": 0.5,
            "silenceTimeoutMs": 2000,
            "autoRespond": false
        });
        let result = handle_talk_configure(Some(&params)).unwrap();
        assert_eq!(result["vadThreshold"], 0.5);
        assert_eq!(result["silenceTimeoutMs"], 2000);
        assert_eq!(result["autoRespond"], false);
    }

    #[test]
    fn test_talk_configure_clamped() {
        let _lock = TEST_LOCK.lock().unwrap();
        reset_state();
        let params = json!({
            "vadThreshold": 5.0 // Should clamp to 1.0
        });
        let result = handle_talk_configure(Some(&params)).unwrap();
        assert_eq!(result["vadThreshold"], 1.0);
    }
}
