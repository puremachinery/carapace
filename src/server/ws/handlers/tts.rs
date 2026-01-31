//! Text-to-speech handlers.
//!
//! Manages TTS settings including provider selection, voice configuration,
//! and text-to-speech conversion via the OpenAI TTS API.

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::LazyLock;

use super::super::*;

/// Available TTS providers
pub const TTS_PROVIDERS: [&str; 4] = ["system", "elevenlabs", "openai", "google"];

/// Audio formats supported by the OpenAI TTS API.
pub const OPENAI_AUDIO_FORMATS: [&str; 4] = ["mp3", "opus", "aac", "flac"];

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

/// Validate and normalise the requested audio format.
///
/// Returns the format string to use with the OpenAI API. If `raw` is `None`
/// the default format `"mp3"` is returned.
fn validate_audio_format(raw: Option<&str>) -> Result<&'static str, ErrorShape> {
    match raw {
        None => Ok("mp3"),
        Some(f) => {
            let lower = f.trim();
            OPENAI_AUDIO_FORMATS
                .iter()
                .find(|&&fmt| fmt.eq_ignore_ascii_case(lower))
                .copied()
                .ok_or_else(|| {
                    error_shape(
                        ERROR_INVALID_REQUEST,
                        &format!(
                            "unsupported audio format '{}'; supported: mp3, opus, aac, flac",
                            f
                        ),
                        Some(json!({ "supportedFormats": OPENAI_AUDIO_FORMATS })),
                    )
                })
        }
    }
}

/// Call the OpenAI TTS API and return raw audio bytes.
async fn openai_tts_request(
    api_key: &str,
    text: &str,
    voice: &str,
    format: &str,
    speed: f64,
) -> Result<bytes::Bytes, ErrorShape> {
    let client = reqwest::Client::new();
    let body = json!({
        "model": "tts-1",
        "input": text,
        "voice": voice,
        "response_format": format,
        "speed": speed.clamp(0.25, 4.0)
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

    response.bytes().await.map_err(|e| {
        error_shape(
            ERROR_UNAVAILABLE,
            &format!("failed to read OpenAI TTS response: {}", e),
            None,
        )
    })
}

/// Convert text to speech.
///
/// Params:
///   - `text` (required): the text to convert.
///   - `format` (optional): audio format — `mp3` (default), `opus`, `aac`, or `flac`.
///
/// When the provider is `openai` and an API key is available the handler
/// calls the OpenAI TTS API and returns base64-encoded audio.  If no key is
/// configured for the `openai` provider the handler returns a clear error.
/// For other providers (e.g. `system`) the handler returns `audio: null`
/// since those providers do not have a server-side synthesis path.
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

    let requested_format = params
        .and_then(|v| v.get("format"))
        .and_then(|v| v.as_str());
    let audio_format = validate_audio_format(requested_format)?;

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
        let api_key = resolve_openai_api_key().ok_or_else(|| {
            error_shape(
                ERROR_UNAVAILABLE,
                "OpenAI API key not configured; set models.providers.openai.apiKey in config or OPENAI_API_KEY env var",
                None,
            )
        })?;

        let audio_bytes = openai_tts_request(&api_key, text, &voice, audio_format, rate).await?;

        let audio_b64 = base64::engine::general_purpose::STANDARD.encode(&audio_bytes);

        return Ok(json!({
            "ok": true,
            "text": text,
            "provider": provider,
            "voice": voice,
            "rate": rate,
            "pitch": pitch,
            "audio": audio_b64,
            "audioFormat": audio_format,
            "audioSize": audio_bytes.len(),
            "duration": null
        }));
    }

    // Non-OpenAI provider: no server-side synthesis available.
    Ok(json!({
        "ok": true,
        "text": text,
        "provider": provider,
        "voice": voice,
        "rate": rate,
        "pitch": pitch,
        "audio": null,
        "audioFormat": audio_format,
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
    tracing::debug!("tts.stop: stub response");
    // In a real implementation, this would stop audio playback
    Ok(json!({
        "stub": true,
        "ok": true,
        "stopped": true
    }))
}

/// Speak text immediately (shorthand for convert + play).
///
/// Delegates to the conversion pipeline and wraps the result with a unique
/// speech ID so callers can track playback.
pub(super) async fn handle_tts_speak(params: Option<&Value>) -> Result<Value, ErrorShape> {
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

    // Generate a unique ID for this speech request
    let speech_id = uuid::Uuid::new_v4().to_string();

    // Delegate to the convert pipeline for the actual audio synthesis.
    let mut converted = handle_tts_convert(params).await?;

    // Attach the speech ID and mark as playing.
    if let Some(obj) = converted.as_object_mut() {
        obj.insert("speechId".to_string(), json!(speech_id));
        obj.insert("status".to_string(), json!("playing"));
    }

    Ok(converted)
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
    async fn test_tts_convert_openai_no_api_key_returns_error() {
        let _lock = TEST_LOCK.lock().unwrap();
        reset_state();

        // Enable TTS and set provider to openai
        handle_tts_enable().unwrap();
        let params = json!({ "provider": "openai" });
        handle_tts_set_provider(Some(&params)).unwrap();

        // Ensure no OPENAI_API_KEY is set for this test
        env::remove_var("OPENAI_API_KEY");

        let params = json!({ "text": "Hello from OpenAI" });
        let result = handle_tts_convert(Some(&params)).await;
        assert!(
            result.is_err(),
            "should error when no API key is configured"
        );
        let err = result.unwrap_err();
        assert_eq!(err.code, ERROR_UNAVAILABLE);
        assert!(
            err.message.contains("API key"),
            "error message should mention API key: {}",
            err.message
        );
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

    // -----------------------------------------------------------------------
    // Audio format validation tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_validate_audio_format_default() {
        let result = validate_audio_format(None).unwrap();
        assert_eq!(result, "mp3");
    }

    #[test]
    fn test_validate_audio_format_all_supported() {
        for fmt in &OPENAI_AUDIO_FORMATS {
            let result = validate_audio_format(Some(fmt)).unwrap();
            assert_eq!(result, *fmt);
        }
    }

    #[test]
    fn test_validate_audio_format_case_insensitive() {
        assert_eq!(validate_audio_format(Some("MP3")).unwrap(), "mp3");
        assert_eq!(validate_audio_format(Some("Opus")).unwrap(), "opus");
        assert_eq!(validate_audio_format(Some("AAC")).unwrap(), "aac");
        assert_eq!(validate_audio_format(Some("FLAC")).unwrap(), "flac");
    }

    #[test]
    fn test_validate_audio_format_invalid() {
        let result = validate_audio_format(Some("wav"));
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code, ERROR_INVALID_REQUEST);
        assert!(err.message.contains("wav"));
    }

    // -----------------------------------------------------------------------
    // Convert with format parameter tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn test_tts_convert_invalid_format() {
        let _lock = TEST_LOCK.lock().unwrap();
        reset_state();
        handle_tts_enable().unwrap();

        let params = json!({ "text": "Hello", "format": "wav" });
        let result = handle_tts_convert(Some(&params)).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code, ERROR_INVALID_REQUEST);
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn test_tts_convert_system_returns_null_audio() {
        let _lock = TEST_LOCK.lock().unwrap();
        reset_state();
        handle_tts_enable().unwrap();

        let params = json!({ "text": "Hello", "format": "opus" });
        let result = handle_tts_convert(Some(&params)).await.unwrap();
        assert_eq!(result["ok"], true);
        assert_eq!(result["provider"], "system");
        assert!(result["audio"].is_null());
        assert_eq!(result["audioFormat"], "opus");
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn test_tts_convert_empty_text() {
        let _lock = TEST_LOCK.lock().unwrap();
        reset_state();
        handle_tts_enable().unwrap();

        let params = json!({ "text": "   " });
        let result = handle_tts_convert(Some(&params)).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code, ERROR_INVALID_REQUEST);
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn test_tts_convert_missing_text() {
        let _lock = TEST_LOCK.lock().unwrap();
        reset_state();
        handle_tts_enable().unwrap();

        let params = json!({});
        let result = handle_tts_convert(Some(&params)).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code, ERROR_INVALID_REQUEST);
    }

    // -----------------------------------------------------------------------
    // Speak handler tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn test_tts_speak_requires_enabled() {
        let _lock = TEST_LOCK.lock().unwrap();
        reset_state();

        let params = json!({ "text": "Hello" });
        let result = handle_tts_speak(Some(&params)).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code, ERROR_UNAVAILABLE);
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn test_tts_speak_returns_speech_id() {
        let _lock = TEST_LOCK.lock().unwrap();
        reset_state();
        handle_tts_enable().unwrap();

        let params = json!({ "text": "Hello" });
        let result = handle_tts_speak(Some(&params)).await.unwrap();
        assert_eq!(result["ok"], true);
        assert!(result["speechId"].is_string(), "should have speechId");
        assert_eq!(result["status"], "playing");
        assert_eq!(result["text"], "Hello");
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn test_tts_speak_empty_text() {
        let _lock = TEST_LOCK.lock().unwrap();
        reset_state();
        handle_tts_enable().unwrap();

        let params = json!({ "text": "" });
        let result = handle_tts_speak(Some(&params)).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code, ERROR_INVALID_REQUEST);
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn test_tts_speak_openai_no_key_returns_error() {
        let _lock = TEST_LOCK.lock().unwrap();
        reset_state();
        handle_tts_enable().unwrap();
        let p = json!({ "provider": "openai" });
        handle_tts_set_provider(Some(&p)).unwrap();
        env::remove_var("OPENAI_API_KEY");

        let params = json!({ "text": "Test speech" });
        let result = handle_tts_speak(Some(&params)).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code, ERROR_UNAVAILABLE);
    }

    // -----------------------------------------------------------------------
    // Set voice tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_tts_set_voice() {
        let _lock = TEST_LOCK.lock().unwrap();
        reset_state();

        let params = json!({ "voice": "echo" });
        let result = handle_tts_set_voice(Some(&params)).unwrap();
        assert_eq!(result["ok"], true);
        assert_eq!(result["voice"], "echo");
    }

    #[test]
    fn test_tts_set_voice_empty_rejected() {
        let _lock = TEST_LOCK.lock().unwrap();
        reset_state();

        let params = json!({ "voice": "  " });
        let result = handle_tts_set_voice(Some(&params));
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // OpenAI voices listing
    // -----------------------------------------------------------------------

    #[test]
    fn test_tts_voices_openai() {
        let _lock = TEST_LOCK.lock().unwrap();
        reset_state();
        let p = json!({ "provider": "openai" });
        handle_tts_set_provider(Some(&p)).unwrap();

        let result = handle_tts_voices().unwrap();
        assert_eq!(result["provider"], "openai");
        let voices = result["voices"].as_array().unwrap();
        assert_eq!(voices.len(), 6);
        let ids: Vec<&str> = voices.iter().map(|v| v["id"].as_str().unwrap()).collect();
        assert!(ids.contains(&"alloy"));
        assert!(ids.contains(&"shimmer"));
    }
}
