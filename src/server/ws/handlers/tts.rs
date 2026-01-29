//! Text-to-speech handlers.
//!
//! Manages TTS settings including provider selection, voice configuration,
//! and text-to-speech conversion.

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::LazyLock;

use super::super::*;

/// Available TTS providers
pub const TTS_PROVIDERS: [&str; 4] = ["system", "elevenlabs", "openai", "google"];

/// Available system voices (platform-dependent)
pub const SYSTEM_VOICES: [&str; 6] = ["samantha", "alex", "victoria", "karen", "daniel", "moira"];

/// Global TTS state
static TTS_STATE: LazyLock<RwLock<TtsState>> = LazyLock::new(|| RwLock::new(TtsState::default()));

/// TTS configuration state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TtsState {
    /// Whether TTS is enabled
    pub enabled: bool,
    /// Active TTS provider
    pub provider: Option<String>,
    /// Selected voice for the current provider
    pub voice: Option<String>,
    /// Speaking rate (0.5 to 2.0, 1.0 is normal)
    pub rate: f64,
    /// Pitch adjustment (-1.0 to 1.0, 0.0 is normal)
    pub pitch: f64,
    /// Volume (0.0 to 1.0)
    pub volume: f64,
    /// Provider-specific API keys (stored securely in production)
    pub provider_config: ProviderConfig,
}

impl Default for TtsState {
    fn default() -> Self {
        Self {
            enabled: false,
            provider: None,
            voice: None,
            rate: 1.0,
            pitch: 0.0,
            volume: 1.0,
            provider_config: ProviderConfig::default(),
        }
    }
}

/// Provider-specific configuration
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProviderConfig {
    /// ElevenLabs configuration
    pub elevenlabs: Option<ElevenLabsConfig>,
    /// OpenAI configuration
    pub openai: Option<OpenAiTtsConfig>,
}

/// ElevenLabs TTS configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElevenLabsConfig {
    pub voice_id: Option<String>,
    pub model_id: Option<String>,
    pub stability: f64,
    pub similarity_boost: f64,
}

/// OpenAI TTS configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenAiTtsConfig {
    pub model: String,
    pub voice: String,
}

/// Get TTS status
pub(super) fn handle_tts_status() -> Result<Value, ErrorShape> {
    let state = TTS_STATE.read();
    Ok(json!({
        "enabled": state.enabled,
        "provider": state.provider,
        "voice": state.voice,
        "rate": state.rate,
        "pitch": state.pitch,
        "volume": state.volume
    }))
}

/// List available TTS providers
pub(super) fn handle_tts_providers() -> Result<Value, ErrorShape> {
    let state = TTS_STATE.read();
    let providers: Vec<Value> = TTS_PROVIDERS
        .iter()
        .map(|&p| {
            json!({
                "id": p,
                "name": match p {
                    "system" => "System Voice",
                    "elevenlabs" => "ElevenLabs",
                    "openai" => "OpenAI TTS",
                    "google" => "Google Cloud TTS",
                    _ => p
                },
                "available": p == "system" || p == state.provider.as_deref().unwrap_or("")
            })
        })
        .collect();

    Ok(json!({
        "providers": providers,
        "current": state.provider
    }))
}

/// Enable TTS
pub(super) fn handle_tts_enable() -> Result<Value, ErrorShape> {
    let mut state = TTS_STATE.write();
    state.enabled = true;

    // Default to system provider if none set
    if state.provider.is_none() {
        state.provider = Some("system".to_string());
    }

    Ok(json!({
        "ok": true,
        "enabled": true,
        "provider": state.provider
    }))
}

/// Disable TTS
pub(super) fn handle_tts_disable() -> Result<Value, ErrorShape> {
    let mut state = TTS_STATE.write();
    state.enabled = false;

    Ok(json!({
        "ok": true,
        "enabled": false
    }))
}

/// Resolve the OpenAI API key from config or environment.
fn resolve_openai_api_key() -> Option<String> {
    // Try config first: models.providers.openai.apiKey
    if let Ok(cfg) = config::load_config() {
        if let Some(key) = cfg
            .get("models")
            .and_then(|v| v.get("providers"))
            .and_then(|v| v.get("openai"))
            .and_then(|v| v.get("apiKey"))
            .and_then(|v| v.as_str())
        {
            if !key.is_empty() {
                return Some(key.to_string());
            }
        }
    }

    // Fall back to environment variable
    env::var("OPENAI_API_KEY").ok().filter(|k| !k.is_empty())
}

/// Convert text to speech
pub(super) async fn handle_tts_convert(params: Option<&Value>) -> Result<Value, ErrorShape> {
    let text = params
        .and_then(|v| v.get("text"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "text is required", None))?;

    if text.trim().is_empty() {
        return Err(error_shape(
            ERROR_INVALID_REQUEST,
            "text cannot be empty",
            None,
        ));
    }

    // Read state in a block so the parking_lot guard (which is !Send) is
    // dropped before any await point.
    let (provider, voice, rate, pitch) = {
        let state = TTS_STATE.read();

        if !state.enabled {
            return Err(error_shape(ERROR_UNAVAILABLE, "TTS is not enabled", None));
        }

        let provider = state.provider.as_deref().unwrap_or("system").to_string();
        let voice = state.voice.clone().unwrap_or_else(|| "alloy".to_string());
        let rate = state.rate;
        let pitch = state.pitch;
        (provider, voice, rate, pitch)
    };

    if provider == "openai" {
        if let Some(api_key) = resolve_openai_api_key() {
            let client = reqwest::Client::new();
            let body = json!({
                "model": "tts-1",
                "input": text,
                "voice": voice,
                "response_format": "mp3"
            });

            let response = client
                .post("https://api.openai.com/v1/audio/speech")
                .header("Authorization", format!("Bearer {}", api_key))
                .json(&body)
                .send()
                .await
                .map_err(|e| {
                    error_shape(
                        ERROR_UNAVAILABLE,
                        &format!("OpenAI TTS request failed: {}", e),
                        None,
                    )
                })?;

            if !response.status().is_success() {
                let status = response.status();
                let err_body = response.text().await.unwrap_or_default();
                return Err(error_shape(
                    ERROR_UNAVAILABLE,
                    &format!("OpenAI TTS API error ({}): {}", status, err_body),
                    None,
                ));
            }

            let audio_bytes = response.bytes().await.map_err(|e| {
                error_shape(
                    ERROR_UNAVAILABLE,
                    &format!("failed to read OpenAI TTS response: {}", e),
                    None,
                )
            })?;

            let audio_b64 = base64::engine::general_purpose::STANDARD.encode(&audio_bytes);

            return Ok(json!({
                "ok": true,
                "text": text,
                "provider": provider,
                "voice": voice,
                "rate": rate,
                "pitch": pitch,
                "audio": audio_b64,
                "audioFormat": "mp3",
                "duration": null
            }));
        }
        // No API key available – fall through to null-audio response
    }

    // Non-OpenAI provider or no API key: return null audio
    Ok(json!({
        "ok": true,
        "text": text,
        "provider": provider,
        "voice": voice,
        "rate": rate,
        "pitch": pitch,
        "audio": null,
        "audioFormat": "mp3",
        "duration": null
    }))
}

/// Set TTS provider
pub(super) fn handle_tts_set_provider(params: Option<&Value>) -> Result<Value, ErrorShape> {
    let provider = params
        .and_then(|v| v.get("provider"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "provider is required", None))?;

    if !TTS_PROVIDERS.contains(&provider) {
        return Err(error_shape(
            ERROR_INVALID_REQUEST,
            &format!("unknown provider: {}", provider),
            Some(json!({ "validProviders": TTS_PROVIDERS })),
        ));
    }

    let mut state = TTS_STATE.write();
    state.provider = Some(provider.to_string());

    // Reset voice when changing provider
    state.voice = None;

    Ok(json!({
        "ok": true,
        "provider": provider
    }))
}

/// Set TTS voice
pub(super) fn handle_tts_set_voice(params: Option<&Value>) -> Result<Value, ErrorShape> {
    let voice = params
        .and_then(|v| v.get("voice"))
        .and_then(|v| v.as_str())
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "voice is required", None))?;

    let mut state = TTS_STATE.write();
    state.voice = Some(voice.to_string());

    Ok(json!({
        "ok": true,
        "voice": voice,
        "provider": state.provider
    }))
}

/// List available voices for the current provider
pub(super) fn handle_tts_voices() -> Result<Value, ErrorShape> {
    let state = TTS_STATE.read();
    let provider = state.provider.as_deref().unwrap_or("system");

    let voices: Vec<Value> = match provider {
        "system" => SYSTEM_VOICES
            .iter()
            .map(|&v| {
                json!({
                    "id": v,
                    "name": v.chars().next().map(|c| c.to_uppercase().to_string()).unwrap_or_default() + &v[1..],
                    "gender": match v {
                        "samantha" | "victoria" | "karen" | "moira" => "female",
                        _ => "male"
                    }
                })
            })
            .collect(),
        "openai" => vec!["alloy", "echo", "fable", "onyx", "nova", "shimmer"]
            .into_iter()
            .map(|v| {
                json!({
                    "id": v,
                    "name": v.chars().next().map(|c| c.to_uppercase().to_string()).unwrap_or_default() + &v[1..]
                })
            })
            .collect(),
        _ => vec![],
    };

    Ok(json!({
        "provider": provider,
        "voices": voices,
        "current": state.voice
    }))
}

/// Configure TTS settings (rate, pitch, volume)
pub(super) fn handle_tts_configure(params: Option<&Value>) -> Result<Value, ErrorShape> {
    let mut state = TTS_STATE.write();

    if let Some(rate) = params.and_then(|v| v.get("rate")).and_then(|v| v.as_f64()) {
        state.rate = rate.clamp(0.5, 2.0);
    }

    if let Some(pitch) = params.and_then(|v| v.get("pitch")).and_then(|v| v.as_f64()) {
        state.pitch = pitch.clamp(-1.0, 1.0);
    }

    if let Some(volume) = params
        .and_then(|v| v.get("volume"))
        .and_then(|v| v.as_f64())
    {
        state.volume = volume.clamp(0.0, 1.0);
    }

    Ok(json!({
        "ok": true,
        "rate": state.rate,
        "pitch": state.pitch,
        "volume": state.volume
    }))
}

/// Stop any ongoing TTS playback
pub(super) fn handle_tts_stop() -> Result<Value, ErrorShape> {
    // In a real implementation, this would stop audio playback
    Ok(json!({
        "ok": true,
        "stopped": true
    }))
}

/// Speak text immediately (shorthand for convert + play)
pub(super) fn handle_tts_speak(params: Option<&Value>) -> Result<Value, ErrorShape> {
    let text = params
        .and_then(|v| v.get("text"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "text is required", None))?;

    if text.trim().is_empty() {
        return Err(error_shape(
            ERROR_INVALID_REQUEST,
            "text cannot be empty",
            None,
        ));
    }

    let state = TTS_STATE.read();

    if !state.enabled {
        return Err(error_shape(ERROR_UNAVAILABLE, "TTS is not enabled", None));
    }

    // Generate a unique ID for this speech request
    let speech_id = uuid::Uuid::new_v4().to_string();

    Ok(json!({
        "ok": true,
        "speechId": speech_id,
        "text": text,
        "provider": state.provider,
        "voice": state.voice,
        "status": "queued"
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Mutex to serialize tests that modify global state
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    fn reset_state() {
        let mut state = TTS_STATE.write();
        *state = TtsState::default();
    }

    #[test]
    fn test_tts_status_default() {
        let _lock = TEST_LOCK.lock().unwrap();
        reset_state();
        let result = handle_tts_status().unwrap();
        assert_eq!(result["enabled"], false);
        assert!(result["provider"].is_null());
        assert_eq!(result["rate"], 1.0);
    }

    #[test]
    fn test_tts_enable_disable() {
        let _lock = TEST_LOCK.lock().unwrap();
        reset_state();

        let result = handle_tts_enable().unwrap();
        assert_eq!(result["ok"], true);
        assert_eq!(result["enabled"], true);
        assert_eq!(result["provider"], "system");

        let result = handle_tts_disable().unwrap();
        assert_eq!(result["ok"], true);
        assert_eq!(result["enabled"], false);
    }

    #[test]
    fn test_tts_set_provider() {
        let _lock = TEST_LOCK.lock().unwrap();
        reset_state();

        let params = json!({ "provider": "openai" });
        let result = handle_tts_set_provider(Some(&params)).unwrap();
        assert_eq!(result["ok"], true);
        assert_eq!(result["provider"], "openai");
    }

    #[test]
    fn test_tts_set_invalid_provider() {
        let _lock = TEST_LOCK.lock().unwrap();
        reset_state();

        let params = json!({ "provider": "invalid" });
        let result = handle_tts_set_provider(Some(&params));
        assert!(result.is_err());
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn test_tts_convert_requires_enabled() {
        let _lock = TEST_LOCK.lock().unwrap();
        reset_state();

        let params = json!({ "text": "Hello world" });
        let result = handle_tts_convert(Some(&params)).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code, ERROR_UNAVAILABLE);
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn test_tts_convert_when_enabled() {
        let _lock = TEST_LOCK.lock().unwrap();
        reset_state();
        handle_tts_enable().unwrap();

        let params = json!({ "text": "Hello world" });
        let result = handle_tts_convert(Some(&params)).await.unwrap();
        assert_eq!(result["ok"], true);
        assert_eq!(result["text"], "Hello world");
        assert_eq!(result["provider"], "system");
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn test_tts_convert_openai_no_api_key_returns_null_audio() {
        let _lock = TEST_LOCK.lock().unwrap();
        reset_state();

        // Enable TTS and set provider to openai
        handle_tts_enable().unwrap();
        let params = json!({ "provider": "openai" });
        handle_tts_set_provider(Some(&params)).unwrap();

        // Ensure no OPENAI_API_KEY is set for this test
        env::remove_var("OPENAI_API_KEY");

        let params = json!({ "text": "Hello from OpenAI" });
        let result = handle_tts_convert(Some(&params)).await.unwrap();
        assert_eq!(result["ok"], true);
        assert_eq!(result["text"], "Hello from OpenAI");
        assert_eq!(result["provider"], "openai");
        assert!(result["audio"].is_null());
        assert_eq!(result["audioFormat"], "mp3");
    }

    #[test]
    fn test_tts_providers() {
        let _lock = TEST_LOCK.lock().unwrap();
        reset_state();
        let result = handle_tts_providers().unwrap();
        let providers = result["providers"].as_array().unwrap();
        assert!(providers.len() >= 3);
    }

    #[test]
    fn test_tts_configure() {
        let _lock = TEST_LOCK.lock().unwrap();
        reset_state();

        let params = json!({
            "rate": 1.5,
            "pitch": 0.2,
            "volume": 0.8
        });
        let result = handle_tts_configure(Some(&params)).unwrap();
        assert_eq!(result["rate"], 1.5);
        assert_eq!(result["pitch"], 0.2);
        assert_eq!(result["volume"], 0.8);
    }

    #[test]
    fn test_tts_configure_clamped() {
        let _lock = TEST_LOCK.lock().unwrap();
        reset_state();

        let params = json!({
            "rate": 10.0, // Should clamp to 2.0
            "volume": -1.0 // Should clamp to 0.0
        });
        let result = handle_tts_configure(Some(&params)).unwrap();
        assert_eq!(result["rate"], 2.0);
        assert_eq!(result["volume"], 0.0);
    }

    #[test]
    fn test_tts_voices() {
        let _lock = TEST_LOCK.lock().unwrap();
        reset_state();
        let result = handle_tts_voices().unwrap();
        assert_eq!(result["provider"], "system");
        let voices = result["voices"].as_array().unwrap();
        assert!(!voices.is_empty());
    }
}
