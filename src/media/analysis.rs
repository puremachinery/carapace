//! Media analysis pipeline using LLM provider APIs.
//!
//! Provides a provider-agnostic interface for analyzing media content
//! (images, audio, video) using AI models. Includes implementations for:
//!
//! - **AnthropicMediaAnalyzer**: Claude's vision API for image analysis
//! - **OpenAiMediaAnalyzer**: OpenAI vision for images, Whisper for audio
//!
//! Analysis results can be cached alongside media files as `.analysis.json`.

use std::path::{Path, PathBuf};

use async_trait::async_trait;
use base64::Engine;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Default prompt for image analysis when none is provided.
pub const DEFAULT_IMAGE_PROMPT: &str = "Describe this image concisely.";

/// Default model for Anthropic image analysis.
pub const DEFAULT_ANTHROPIC_MODEL: &str = "claude-sonnet-4-6";

/// Default model for OpenAI image analysis.
pub const DEFAULT_OPENAI_VISION_MODEL: &str = "gpt-5.5";

/// Default max tokens for analysis responses.
pub const DEFAULT_ANALYSIS_MAX_TOKENS: u32 = 1024;

/// Errors that can occur during media analysis.
#[derive(Error, Debug, Clone)]
pub enum AnalysisError {
    #[error("unsupported media type: {0}")]
    UnsupportedMediaType(String),

    #[error("API request failed: {0}")]
    ApiRequest(String),

    #[error("API response error: {status} {body}")]
    ApiResponse { status: u16, body: String },

    #[error("failed to parse API response: {0}")]
    ParseResponse(String),

    #[error("I/O error: {0}")]
    Io(String),

    #[error("media data is empty")]
    EmptyData,

    #[error("provider not configured: {0}")]
    NotConfigured(String),
}

/// Type of media being analyzed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MediaType {
    Image,
    Audio,
    Video,
}

impl MediaType {
    /// Determine media type from a MIME type string.
    pub fn from_mime(mime: &str) -> Option<Self> {
        let lower = mime.to_lowercase();
        if lower.starts_with("image/") {
            Some(MediaType::Image)
        } else if lower.starts_with("audio/") {
            Some(MediaType::Audio)
        } else if lower.starts_with("video/") {
            Some(MediaType::Video)
        } else {
            None
        }
    }
}

/// Result of analyzing a media file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MediaAnalysis {
    /// Human-readable description or transcription of the media.
    pub description: String,

    /// Type of media that was analyzed.
    pub media_type: MediaType,

    /// Name of the provider that performed the analysis (e.g., "anthropic", "openai").
    pub provider: String,

    /// Number of tokens consumed by the analysis, if reported by the API.
    pub tokens_used: Option<u64>,
}

/// Provider-agnostic interface for media analysis.
///
/// Implementations send media data to an LLM or specialized API and return
/// structured analysis results.
#[async_trait]
pub trait MediaAnalyzer: Send + Sync {
    /// Analyze an image and return a description.
    ///
    /// # Arguments
    /// * `image_data` - Raw image bytes (JPEG, PNG, GIF, WebP)
    /// * `mime_type` - MIME type of the image (e.g., "image/png")
    /// * `prompt` - Optional custom prompt; defaults to a concise description request
    async fn analyze_image(
        &self,
        image_data: &[u8],
        mime_type: &str,
        prompt: Option<&str>,
    ) -> Result<MediaAnalysis, AnalysisError>;

    /// Transcribe audio content.
    ///
    /// # Arguments
    /// * `audio_data` - Raw audio bytes
    /// * `mime_type` - MIME type of the audio (e.g., "audio/mp3")
    async fn transcribe_audio(
        &self,
        audio_data: &[u8],
        mime_type: &str,
    ) -> Result<MediaAnalysis, AnalysisError>;

    /// Return the media types this analyzer supports.
    fn supported_types(&self) -> Vec<MediaType>;
}

/// Anthropic Claude vision-based media analyzer.
///
/// Uses the Anthropic Messages API to analyze images by sending them as
/// base64-encoded content blocks in user messages.
pub struct AnthropicMediaAnalyzer {
    client: reqwest::Client,
    api_key: String,
    base_url: String,
    model: String,
    max_tokens: u32,
}

impl AnthropicMediaAnalyzer {
    /// Create a new Anthropic media analyzer.
    ///
    /// # Arguments
    /// * `api_key` - Anthropic API key
    pub fn new(api_key: String) -> Result<Self, AnalysisError> {
        if api_key.trim().is_empty() {
            return Err(AnalysisError::NotConfigured(
                "Anthropic API key must not be empty".to_string(),
            ));
        }
        let client = reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(10))
            .timeout(std::time::Duration::from_secs(120))
            .build()
            .map_err(|e| AnalysisError::ApiRequest(format!("failed to build HTTP client: {e}")))?;

        Ok(Self {
            client,
            api_key,
            base_url: "https://api.anthropic.com".to_string(),
            model: DEFAULT_ANTHROPIC_MODEL.to_string(),
            max_tokens: DEFAULT_ANALYSIS_MAX_TOKENS,
        })
    }

    /// Set a custom base URL (e.g., for proxy or testing).
    pub fn with_base_url(mut self, url: String) -> Self {
        self.base_url = url.trim_end_matches('/').to_string();
        self
    }

    /// Set a custom model.
    pub fn with_model(mut self, model: String) -> Self {
        self.model = model;
        self
    }

    /// Set custom max tokens for analysis responses.
    pub fn with_max_tokens(mut self, max_tokens: u32) -> Self {
        self.max_tokens = max_tokens;
        self
    }
}

#[async_trait]
impl MediaAnalyzer for AnthropicMediaAnalyzer {
    async fn analyze_image(
        &self,
        image_data: &[u8],
        mime_type: &str,
        prompt: Option<&str>,
    ) -> Result<MediaAnalysis, AnalysisError> {
        if image_data.is_empty() {
            return Err(AnalysisError::EmptyData);
        }

        let media_type = validate_image_mime(mime_type)?;
        let prompt_text = prompt.unwrap_or(DEFAULT_IMAGE_PROMPT);

        // Encode image as base64
        let b64 = base64::engine::general_purpose::STANDARD.encode(image_data);

        // Build the Anthropic Messages API request body with an image content block.
        // See: https://docs.anthropic.com/en/docs/build-with-claude/vision
        let body = serde_json::json!({
            "model": self.model,
            "max_tokens": self.max_tokens,
            "messages": [{
                "role": "user",
                "content": [
                    {
                        "type": "image",
                        "source": {
                            "type": "base64",
                            "media_type": media_type,
                            "data": b64,
                        }
                    },
                    {
                        "type": "text",
                        "text": prompt_text,
                    }
                ]
            }]
        });

        let url = format!("{}/v1/messages", self.base_url);

        let response = self
            .client
            .post(&url)
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", "2023-06-01")
            .header("content-type", "application/json")
            .json(&body)
            .send()
            .await
            .map_err(|e| AnalysisError::ApiRequest(format!("HTTP request failed: {e}")))?;

        let status = response.status();
        if !status.is_success() {
            let body_text = response
                .text()
                .await
                .unwrap_or_else(|_| "<unreadable>".to_string());
            return Err(AnalysisError::ApiResponse {
                status: status.as_u16(),
                body: body_text,
            });
        }

        let resp_body: serde_json::Value = response
            .json()
            .await
            .map_err(|e| AnalysisError::ParseResponse(format!("failed to read JSON: {e}")))?;

        // Extract text from the first text content block in the response
        let description = extract_anthropic_text(&resp_body)?;

        // Extract token usage
        let tokens_used = resp_body
            .get("usage")
            .map(|u| {
                let input = u.get("input_tokens").and_then(|v| v.as_u64()).unwrap_or(0);
                let output = u.get("output_tokens").and_then(|v| v.as_u64()).unwrap_or(0);
                input + output
            })
            .filter(|&t| t > 0);

        Ok(MediaAnalysis {
            description,
            media_type: MediaType::Image,
            provider: "anthropic".to_string(),
            tokens_used,
        })
    }

    async fn transcribe_audio(
        &self,
        _audio_data: &[u8],
        _mime_type: &str,
    ) -> Result<MediaAnalysis, AnalysisError> {
        Err(AnalysisError::UnsupportedMediaType(
            "Anthropic does not support audio transcription".to_string(),
        ))
    }

    fn supported_types(&self) -> Vec<MediaType> {
        vec![MediaType::Image]
    }
}

/// OpenAI GPT-4 Vision and Whisper media analyzer.
///
/// Uses GPT-4 Vision for image analysis (base64 data URLs in content array)
/// and the Whisper API for audio transcription.
pub struct OpenAiMediaAnalyzer {
    client: reqwest::Client,
    api_key: String,
    base_url: String,
    vision_model: String,
    max_tokens: u32,
}

impl OpenAiMediaAnalyzer {
    /// Create a new OpenAI media analyzer.
    ///
    /// # Arguments
    /// * `api_key` - OpenAI API key
    pub fn new(api_key: String) -> Result<Self, AnalysisError> {
        if api_key.trim().is_empty() {
            return Err(AnalysisError::NotConfigured(
                "OpenAI API key must not be empty".to_string(),
            ));
        }
        let client = reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(10))
            .timeout(std::time::Duration::from_secs(120))
            .build()
            .map_err(|e| AnalysisError::ApiRequest(format!("failed to build HTTP client: {e}")))?;

        Ok(Self {
            client,
            api_key,
            base_url: "https://api.openai.com".to_string(),
            vision_model: DEFAULT_OPENAI_VISION_MODEL.to_string(),
            max_tokens: DEFAULT_ANALYSIS_MAX_TOKENS,
        })
    }

    /// Set a custom base URL (e.g., for proxy or testing).
    pub fn with_base_url(mut self, url: String) -> Self {
        self.base_url = url.trim_end_matches('/').to_string();
        self
    }

    /// Set a custom vision model.
    pub fn with_vision_model(mut self, model: String) -> Self {
        self.vision_model = model;
        self
    }

    /// Set custom max tokens for analysis responses.
    pub fn with_max_tokens(mut self, max_tokens: u32) -> Self {
        self.max_tokens = max_tokens;
        self
    }
}

#[async_trait]
impl MediaAnalyzer for OpenAiMediaAnalyzer {
    async fn analyze_image(
        &self,
        image_data: &[u8],
        mime_type: &str,
        prompt: Option<&str>,
    ) -> Result<MediaAnalysis, AnalysisError> {
        if image_data.is_empty() {
            return Err(AnalysisError::EmptyData);
        }

        let media_type = validate_image_mime(mime_type)?;
        let prompt_text = prompt.unwrap_or(DEFAULT_IMAGE_PROMPT);

        // Encode image as base64 data URL
        let b64 = base64::engine::general_purpose::STANDARD.encode(image_data);
        let data_url = format!("data:{};base64,{}", media_type, b64);

        // Build the OpenAI Chat Completions API request body with an image_url
        // content block. See: https://platform.openai.com/docs/guides/vision
        let body = serde_json::json!({
            "model": self.vision_model,
            "max_completion_tokens": self.max_tokens,
            "messages": [{
                "role": "user",
                "content": [
                    {
                        "type": "image_url",
                        "image_url": {
                            "url": data_url,
                        }
                    },
                    {
                        "type": "text",
                        "text": prompt_text,
                    }
                ]
            }]
        });

        let url = format!("{}/v1/chat/completions", self.base_url);

        let response = self
            .client
            .post(&url)
            .header("authorization", format!("Bearer {}", self.api_key))
            .header("content-type", "application/json")
            .json(&body)
            .send()
            .await
            .map_err(|e| AnalysisError::ApiRequest(format!("HTTP request failed: {e}")))?;

        let status = response.status();
        if !status.is_success() {
            let body_text = response
                .text()
                .await
                .unwrap_or_else(|_| "<unreadable>".to_string());
            return Err(AnalysisError::ApiResponse {
                status: status.as_u16(),
                body: body_text,
            });
        }

        let resp_body: serde_json::Value = response
            .json()
            .await
            .map_err(|e| AnalysisError::ParseResponse(format!("failed to read JSON: {e}")))?;

        // Extract text from the first choice's message content
        let description = extract_openai_text(&resp_body)?;

        // Extract token usage
        let tokens_used = resp_body
            .get("usage")
            .map(|u| {
                let prompt = u.get("prompt_tokens").and_then(|v| v.as_u64()).unwrap_or(0);
                let completion = u
                    .get("completion_tokens")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                prompt + completion
            })
            .filter(|&t| t > 0);

        Ok(MediaAnalysis {
            description,
            media_type: MediaType::Image,
            provider: "openai".to_string(),
            tokens_used,
        })
    }

    async fn transcribe_audio(
        &self,
        audio_data: &[u8],
        mime_type: &str,
    ) -> Result<MediaAnalysis, AnalysisError> {
        if audio_data.is_empty() {
            return Err(AnalysisError::EmptyData);
        }

        // Validate that this is an audio MIME type
        if !mime_type.to_lowercase().starts_with("audio/") {
            return Err(AnalysisError::UnsupportedMediaType(format!(
                "expected audio/* MIME type, got: {}",
                mime_type
            )));
        }

        let extension = audio_mime_to_extension(mime_type);

        // Build a multipart form for the Whisper API.
        // See: https://platform.openai.com/docs/api-reference/audio/createTranscription
        let file_part = reqwest::multipart::Part::bytes(audio_data.to_vec())
            .file_name(format!("audio{}", extension))
            .mime_str(mime_type)
            .map_err(|e| AnalysisError::ApiRequest(format!("failed to build form part: {e}")))?;

        let form = reqwest::multipart::Form::new()
            .text("model", "whisper-1")
            .text("response_format", "json")
            .part("file", file_part);

        let url = format!("{}/v1/audio/transcriptions", self.base_url);

        let response = self
            .client
            .post(&url)
            .header("authorization", format!("Bearer {}", self.api_key))
            .multipart(form)
            .send()
            .await
            .map_err(|e| AnalysisError::ApiRequest(format!("HTTP request failed: {e}")))?;

        let status = response.status();
        if !status.is_success() {
            let body_text = response
                .text()
                .await
                .unwrap_or_else(|_| "<unreadable>".to_string());
            return Err(AnalysisError::ApiResponse {
                status: status.as_u16(),
                body: body_text,
            });
        }

        let resp_body: serde_json::Value = response
            .json()
            .await
            .map_err(|e| AnalysisError::ParseResponse(format!("failed to read JSON: {e}")))?;

        let text = resp_body
            .get("text")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        if text.is_empty() {
            return Err(AnalysisError::ParseResponse(
                "Whisper API returned empty transcription".to_string(),
            ));
        }

        Ok(MediaAnalysis {
            description: text,
            media_type: MediaType::Audio,
            provider: "openai".to_string(),
            // Whisper API does not report token usage
            tokens_used: None,
        })
    }

    fn supported_types(&self) -> Vec<MediaType> {
        vec![MediaType::Image, MediaType::Audio]
    }
}

// ---------------------------------------------------------------------------
// Integration: analyze stored media files with caching
// ---------------------------------------------------------------------------

/// Analyze a stored media file, using a cached result if available.
///
/// This function:
/// 1. Checks for an existing `.analysis.json` cache file alongside the media file
/// 2. If cached, deserializes and returns the cached result
/// 3. Otherwise, reads the media file, selects the appropriate analysis method,
///    runs the analysis, caches the result, and returns it
///
/// # Arguments
/// * `path` - Path to the stored media file
/// * `mime_type` - MIME type of the media
/// * `analyzer` - The media analyzer to use
/// * `prompt` - Optional custom prompt for image analysis
pub async fn analyze(
    path: &Path,
    mime_type: &str,
    analyzer: &dyn MediaAnalyzer,
    prompt: Option<&str>,
) -> Result<MediaAnalysis, AnalysisError> {
    let cache_path = analysis_cache_path(path);

    // Check for cached result
    if let Ok(cached) = read_cached_analysis(&cache_path).await {
        tracing::debug!(
            path = %path.display(),
            provider = %cached.provider,
            "Using cached media analysis"
        );
        return Ok(cached);
    }

    // Read the media file
    let data = tokio::fs::read(path)
        .await
        .map_err(|e| AnalysisError::Io(format!("failed to read {}: {}", path.display(), e)))?;

    // Determine media type and run analysis
    let media_type = MediaType::from_mime(mime_type).ok_or_else(|| {
        AnalysisError::UnsupportedMediaType(format!(
            "cannot determine media type from: {}",
            mime_type
        ))
    })?;

    let result = match media_type {
        MediaType::Image => analyzer.analyze_image(&data, mime_type, prompt).await?,
        MediaType::Audio => analyzer.transcribe_audio(&data, mime_type).await?,
        MediaType::Video => {
            return Err(AnalysisError::UnsupportedMediaType(
                "video analysis is not yet implemented".to_string(),
            ));
        }
    };

    // Cache the result
    if let Err(e) = write_cached_analysis(&cache_path, &result).await {
        tracing::warn!(
            path = %cache_path.display(),
            error = %e,
            "Failed to cache media analysis result"
        );
    }

    Ok(result)
}

/// Compute the cache file path for a given media file path.
///
/// Appends `.analysis.json` to the original file path.
fn analysis_cache_path(media_path: &Path) -> PathBuf {
    let mut cache_path = media_path.as_os_str().to_owned();
    cache_path.push(".analysis.json");
    PathBuf::from(cache_path)
}

/// Read a cached analysis result from disk.
async fn read_cached_analysis(cache_path: &Path) -> Result<MediaAnalysis, AnalysisError> {
    let data = tokio::fs::read_to_string(cache_path)
        .await
        .map_err(|e| AnalysisError::Io(format!("cache read failed: {e}")))?;
    let analysis: MediaAnalysis = serde_json::from_str(&data)
        .map_err(|e| AnalysisError::ParseResponse(format!("cache parse failed: {e}")))?;
    Ok(analysis)
}

/// Write an analysis result to the cache file.
async fn write_cached_analysis(
    cache_path: &Path,
    analysis: &MediaAnalysis,
) -> Result<(), AnalysisError> {
    let json = serde_json::to_string_pretty(analysis)
        .map_err(|e| AnalysisError::Io(format!("failed to serialize analysis: {e}")))?;
    tokio::fs::write(cache_path, json)
        .await
        .map_err(|e| AnalysisError::Io(format!("failed to write cache: {e}")))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Validate that a MIME type is a supported image type and normalize it.
///
/// Returns the normalized MIME type string suitable for API calls.
fn validate_image_mime(mime_type: &str) -> Result<&str, AnalysisError> {
    let lower = mime_type.to_lowercase();
    // Strip any parameters (e.g., "image/jpeg; charset=utf-8")
    let base = lower.split(';').next().unwrap_or("").trim();
    match base {
        "image/jpeg" | "image/jpg" => Ok("image/jpeg"),
        "image/png" => Ok("image/png"),
        "image/gif" => Ok("image/gif"),
        "image/webp" => Ok("image/webp"),
        _ => Err(AnalysisError::UnsupportedMediaType(format!(
            "unsupported image MIME type: {}",
            mime_type
        ))),
    }
}

/// Extract text from an Anthropic Messages API response.
fn extract_anthropic_text(response: &serde_json::Value) -> Result<String, AnalysisError> {
    let content = response
        .get("content")
        .and_then(|c| c.as_array())
        .ok_or_else(|| {
            AnalysisError::ParseResponse("response missing 'content' array".to_string())
        })?;

    for block in content {
        if block.get("type").and_then(|t| t.as_str()) == Some("text") {
            if let Some(text) = block.get("text").and_then(|t| t.as_str()) {
                return Ok(text.to_string());
            }
        }
    }

    Err(AnalysisError::ParseResponse(
        "no text content block in Anthropic response".to_string(),
    ))
}

/// Extract text from an OpenAI Chat Completions API response.
fn extract_openai_text(response: &serde_json::Value) -> Result<String, AnalysisError> {
    let choices = response
        .get("choices")
        .and_then(|c| c.as_array())
        .ok_or_else(|| {
            AnalysisError::ParseResponse("response missing 'choices' array".to_string())
        })?;

    if choices.is_empty() {
        return Err(AnalysisError::ParseResponse(
            "no choices in OpenAI response".to_string(),
        ));
    }

    let content = choices[0]
        .get("message")
        .and_then(|m| m.get("content"))
        .and_then(|c| c.as_str())
        .ok_or_else(|| {
            AnalysisError::ParseResponse("no message content in OpenAI response choice".to_string())
        })?;

    Ok(content.to_string())
}

/// Map an audio MIME type to a file extension for the Whisper API.
fn audio_mime_to_extension(mime_type: &str) -> &'static str {
    let lower = mime_type.to_lowercase();
    let base = lower.split(';').next().unwrap_or("").trim();
    match base {
        "audio/mpeg" | "audio/mp3" => ".mp3",
        "audio/wav" | "audio/x-wav" | "audio/wave" => ".wav",
        "audio/mp4" | "audio/m4a" | "audio/x-m4a" => ".m4a",
        "audio/webm" => ".webm",
        "audio/ogg" => ".ogg",
        "audio/flac" => ".flac",
        _ => ".bin",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== MediaType tests ====================

    #[test]
    fn test_media_type_from_mime_image() {
        assert_eq!(MediaType::from_mime("image/png"), Some(MediaType::Image));
        assert_eq!(MediaType::from_mime("image/jpeg"), Some(MediaType::Image));
        assert_eq!(MediaType::from_mime("image/gif"), Some(MediaType::Image));
        assert_eq!(MediaType::from_mime("image/webp"), Some(MediaType::Image));
        assert_eq!(MediaType::from_mime("IMAGE/PNG"), Some(MediaType::Image));
    }

    #[test]
    fn test_media_type_from_mime_audio() {
        assert_eq!(MediaType::from_mime("audio/mpeg"), Some(MediaType::Audio));
        assert_eq!(MediaType::from_mime("audio/wav"), Some(MediaType::Audio));
        assert_eq!(MediaType::from_mime("audio/mp3"), Some(MediaType::Audio));
        assert_eq!(MediaType::from_mime("AUDIO/WAV"), Some(MediaType::Audio));
    }

    #[test]
    fn test_media_type_from_mime_video() {
        assert_eq!(MediaType::from_mime("video/mp4"), Some(MediaType::Video));
        assert_eq!(MediaType::from_mime("video/webm"), Some(MediaType::Video));
        assert_eq!(MediaType::from_mime("VIDEO/MP4"), Some(MediaType::Video));
    }

    #[test]
    fn test_media_type_from_mime_unsupported() {
        assert_eq!(MediaType::from_mime("application/json"), None);
        assert_eq!(MediaType::from_mime("text/plain"), None);
        assert_eq!(MediaType::from_mime(""), None);
    }

    // ==================== MediaAnalysis serialization tests ====================

    #[test]
    fn test_media_analysis_serialize_deserialize() {
        let analysis = MediaAnalysis {
            description: "A cat sitting on a windowsill".to_string(),
            media_type: MediaType::Image,
            provider: "anthropic".to_string(),
            tokens_used: Some(256),
        };

        let json = serde_json::to_string(&analysis).unwrap();
        let deserialized: MediaAnalysis = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.description, analysis.description);
        assert_eq!(deserialized.media_type, analysis.media_type);
        assert_eq!(deserialized.provider, analysis.provider);
        assert_eq!(deserialized.tokens_used, analysis.tokens_used);
    }

    #[test]
    fn test_media_analysis_serialize_no_tokens() {
        let analysis = MediaAnalysis {
            description: "Transcribed audio".to_string(),
            media_type: MediaType::Audio,
            provider: "openai".to_string(),
            tokens_used: None,
        };

        let json = serde_json::to_string(&analysis).unwrap();
        let deserialized: MediaAnalysis = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.tokens_used, None);
        assert_eq!(deserialized.media_type, MediaType::Audio);
    }

    // ==================== validate_image_mime tests ====================

    #[test]
    fn test_validate_image_mime_supported() {
        assert_eq!(validate_image_mime("image/jpeg").unwrap(), "image/jpeg");
        assert_eq!(validate_image_mime("image/jpg").unwrap(), "image/jpeg");
        assert_eq!(validate_image_mime("image/png").unwrap(), "image/png");
        assert_eq!(validate_image_mime("image/gif").unwrap(), "image/gif");
        assert_eq!(validate_image_mime("image/webp").unwrap(), "image/webp");
    }

    #[test]
    fn test_validate_image_mime_case_insensitive() {
        assert_eq!(validate_image_mime("IMAGE/JPEG").unwrap(), "image/jpeg");
        assert_eq!(validate_image_mime("Image/Png").unwrap(), "image/png");
    }

    #[test]
    fn test_validate_image_mime_with_parameters() {
        assert_eq!(
            validate_image_mime("image/jpeg; charset=utf-8").unwrap(),
            "image/jpeg"
        );
    }

    #[test]
    fn test_validate_image_mime_unsupported() {
        assert!(validate_image_mime("image/tiff").is_err());
        assert!(validate_image_mime("image/bmp").is_err());
        assert!(validate_image_mime("audio/mpeg").is_err());
        assert!(validate_image_mime("text/plain").is_err());
    }

    // ==================== extract_anthropic_text tests ====================

    #[test]
    fn test_extract_anthropic_text_success() {
        let response = serde_json::json!({
            "id": "msg_1",
            "type": "message",
            "role": "assistant",
            "content": [
                {
                    "type": "text",
                    "text": "This is a photo of a sunset over mountains."
                }
            ],
            "usage": {
                "input_tokens": 1500,
                "output_tokens": 20
            }
        });

        let text = extract_anthropic_text(&response).unwrap();
        assert_eq!(text, "This is a photo of a sunset over mountains.");
    }

    #[test]
    fn test_extract_anthropic_text_no_content() {
        let response = serde_json::json!({
            "id": "msg_1",
            "type": "message",
        });

        let result = extract_anthropic_text(&response);
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_anthropic_text_empty_content() {
        let response = serde_json::json!({
            "content": []
        });

        let result = extract_anthropic_text(&response);
        assert!(result.is_err());
    }

    // ==================== extract_openai_text tests ====================

    #[test]
    fn test_extract_openai_text_success() {
        let response = serde_json::json!({
            "id": "chatcmpl-1",
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": "The image shows a cat sitting on a keyboard."
                },
                "finish_reason": "stop"
            }],
            "usage": {
                "prompt_tokens": 500,
                "completion_tokens": 15,
                "total_tokens": 515
            }
        });

        let text = extract_openai_text(&response).unwrap();
        assert_eq!(text, "The image shows a cat sitting on a keyboard.");
    }

    #[test]
    fn test_extract_openai_text_no_choices() {
        let response = serde_json::json!({
            "id": "chatcmpl-1",
        });

        let result = extract_openai_text(&response);
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_openai_text_empty_choices() {
        let response = serde_json::json!({
            "choices": []
        });

        let result = extract_openai_text(&response);
        assert!(result.is_err());
    }

    // ==================== audio_mime_to_extension tests ====================

    #[test]
    fn test_audio_mime_to_extension() {
        assert_eq!(audio_mime_to_extension("audio/mpeg"), ".mp3");
        assert_eq!(audio_mime_to_extension("audio/mp3"), ".mp3");
        assert_eq!(audio_mime_to_extension("audio/wav"), ".wav");
        assert_eq!(audio_mime_to_extension("audio/x-wav"), ".wav");
        assert_eq!(audio_mime_to_extension("audio/mp4"), ".m4a");
        assert_eq!(audio_mime_to_extension("audio/m4a"), ".m4a");
        assert_eq!(audio_mime_to_extension("audio/webm"), ".webm");
        assert_eq!(audio_mime_to_extension("audio/ogg"), ".ogg");
        assert_eq!(audio_mime_to_extension("audio/flac"), ".flac");
        assert_eq!(audio_mime_to_extension("audio/unknown"), ".bin");
    }

    #[test]
    fn test_audio_mime_to_extension_case_insensitive() {
        assert_eq!(audio_mime_to_extension("AUDIO/MPEG"), ".mp3");
        assert_eq!(audio_mime_to_extension("Audio/Wav"), ".wav");
    }

    // ==================== analysis_cache_path tests ====================

    #[test]
    fn test_analysis_cache_path() {
        let media_path = Path::new("/tmp/carapace-media/abc123.png");
        let cache_path = analysis_cache_path(media_path);
        assert_eq!(
            cache_path,
            PathBuf::from("/tmp/carapace-media/abc123.png.analysis.json")
        );
    }

    #[test]
    fn test_analysis_cache_path_with_extension() {
        let media_path = Path::new("/tmp/media/file.jpg");
        let cache_path = analysis_cache_path(media_path);
        assert_eq!(
            cache_path,
            PathBuf::from("/tmp/media/file.jpg.analysis.json")
        );
    }

    // ==================== Cache read/write integration tests ====================

    #[tokio::test]
    async fn test_write_and_read_cached_analysis() {
        let temp_dir = tempfile::tempdir().unwrap();
        let cache_path = temp_dir.path().join("test.png.analysis.json");

        let analysis = MediaAnalysis {
            description: "A test image description".to_string(),
            media_type: MediaType::Image,
            provider: "anthropic".to_string(),
            tokens_used: Some(100),
        };

        // Write cache
        write_cached_analysis(&cache_path, &analysis).await.unwrap();

        // Read cache
        let cached = read_cached_analysis(&cache_path).await.unwrap();
        assert_eq!(cached.description, "A test image description");
        assert_eq!(cached.media_type, MediaType::Image);
        assert_eq!(cached.provider, "anthropic");
        assert_eq!(cached.tokens_used, Some(100));
    }

    #[tokio::test]
    async fn test_read_cached_analysis_not_found() {
        let result = read_cached_analysis(Path::new("/nonexistent/path.analysis.json")).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_read_cached_analysis_invalid_json() {
        let temp_dir = tempfile::tempdir().unwrap();
        let cache_path = temp_dir.path().join("bad.analysis.json");
        tokio::fs::write(&cache_path, "not valid json")
            .await
            .unwrap();

        let result = read_cached_analysis(&cache_path).await;
        assert!(result.is_err());
    }

    // ==================== analyze integration tests ====================

    /// A mock analyzer for testing the analyze() integration function.
    struct MockAnalyzer {
        image_response: Option<MediaAnalysis>,
        audio_response: Option<MediaAnalysis>,
    }

    #[async_trait]
    impl MediaAnalyzer for MockAnalyzer {
        async fn analyze_image(
            &self,
            _image_data: &[u8],
            _mime_type: &str,
            _prompt: Option<&str>,
        ) -> Result<MediaAnalysis, AnalysisError> {
            self.image_response.clone().ok_or_else(|| {
                AnalysisError::UnsupportedMediaType("mock: no image response".to_string())
            })
        }

        async fn transcribe_audio(
            &self,
            _audio_data: &[u8],
            _mime_type: &str,
        ) -> Result<MediaAnalysis, AnalysisError> {
            self.audio_response.clone().ok_or_else(|| {
                AnalysisError::UnsupportedMediaType("mock: no audio response".to_string())
            })
        }

        fn supported_types(&self) -> Vec<MediaType> {
            let mut types = Vec::new();
            if self.image_response.is_some() {
                types.push(MediaType::Image);
            }
            if self.audio_response.is_some() {
                types.push(MediaType::Audio);
            }
            types
        }
    }

    #[tokio::test]
    async fn test_analyze_image_file() {
        let temp_dir = tempfile::tempdir().unwrap();
        let image_path = temp_dir.path().join("test.png");
        tokio::fs::write(&image_path, b"fake png data")
            .await
            .unwrap();

        let analyzer = MockAnalyzer {
            image_response: Some(MediaAnalysis {
                description: "A test image".to_string(),
                media_type: MediaType::Image,
                provider: "mock".to_string(),
                tokens_used: Some(50),
            }),
            audio_response: None,
        };

        let result = analyze(&image_path, "image/png", &analyzer, None)
            .await
            .unwrap();
        assert_eq!(result.description, "A test image");
        assert_eq!(result.media_type, MediaType::Image);
        assert_eq!(result.provider, "mock");

        // Verify cache was written
        let cache_path = analysis_cache_path(&image_path);
        assert!(cache_path.exists());
    }

    #[tokio::test]
    async fn test_analyze_uses_cache_on_second_call() {
        let temp_dir = tempfile::tempdir().unwrap();
        let image_path = temp_dir.path().join("cached.png");
        tokio::fs::write(&image_path, b"fake png data")
            .await
            .unwrap();

        // Write a cached analysis first
        let cached_analysis = MediaAnalysis {
            description: "Cached description".to_string(),
            media_type: MediaType::Image,
            provider: "cached-provider".to_string(),
            tokens_used: Some(42),
        };
        let cache_path = analysis_cache_path(&image_path);
        write_cached_analysis(&cache_path, &cached_analysis)
            .await
            .unwrap();

        // The analyzer should never be called since cache exists
        let analyzer = MockAnalyzer {
            image_response: Some(MediaAnalysis {
                description: "This should not be returned".to_string(),
                media_type: MediaType::Image,
                provider: "mock".to_string(),
                tokens_used: None,
            }),
            audio_response: None,
        };

        let result = analyze(&image_path, "image/png", &analyzer, None)
            .await
            .unwrap();
        assert_eq!(result.description, "Cached description");
        assert_eq!(result.provider, "cached-provider");
        assert_eq!(result.tokens_used, Some(42));
    }

    #[tokio::test]
    async fn test_analyze_audio_file() {
        let temp_dir = tempfile::tempdir().unwrap();
        let audio_path = temp_dir.path().join("test.mp3");
        tokio::fs::write(&audio_path, b"fake audio data")
            .await
            .unwrap();

        let analyzer = MockAnalyzer {
            image_response: None,
            audio_response: Some(MediaAnalysis {
                description: "Hello, world!".to_string(),
                media_type: MediaType::Audio,
                provider: "mock".to_string(),
                tokens_used: None,
            }),
        };

        let result = analyze(&audio_path, "audio/mpeg", &analyzer, None)
            .await
            .unwrap();
        assert_eq!(result.description, "Hello, world!");
        assert_eq!(result.media_type, MediaType::Audio);
    }

    #[tokio::test]
    async fn test_analyze_video_unsupported() {
        let temp_dir = tempfile::tempdir().unwrap();
        let video_path = temp_dir.path().join("test.mp4");
        tokio::fs::write(&video_path, b"fake video data")
            .await
            .unwrap();

        let analyzer = MockAnalyzer {
            image_response: None,
            audio_response: None,
        };

        let result = analyze(&video_path, "video/mp4", &analyzer, None).await;
        assert!(result.is_err());
        match result {
            Err(AnalysisError::UnsupportedMediaType(msg)) => {
                assert!(msg.contains("video"), "error should mention video: {msg}");
            }
            other => panic!("expected UnsupportedMediaType, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_analyze_unknown_mime() {
        let temp_dir = tempfile::tempdir().unwrap();
        let file_path = temp_dir.path().join("test.bin");
        tokio::fs::write(&file_path, b"some data").await.unwrap();

        let analyzer = MockAnalyzer {
            image_response: None,
            audio_response: None,
        };

        let result = analyze(&file_path, "application/octet-stream", &analyzer, None).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_analyze_missing_file() {
        let analyzer = MockAnalyzer {
            image_response: Some(MediaAnalysis {
                description: "irrelevant".to_string(),
                media_type: MediaType::Image,
                provider: "mock".to_string(),
                tokens_used: None,
            }),
            audio_response: None,
        };

        let result = analyze(
            Path::new("/nonexistent/image.png"),
            "image/png",
            &analyzer,
            None,
        )
        .await;
        assert!(result.is_err());
    }

    // ==================== Provider construction tests ====================

    #[test]
    fn test_anthropic_analyzer_rejects_empty_key() {
        let result = AnthropicMediaAnalyzer::new("".to_string());
        assert!(result.is_err());
    }

    #[test]
    fn test_anthropic_analyzer_rejects_whitespace_key() {
        let result = AnthropicMediaAnalyzer::new("   ".to_string());
        assert!(result.is_err());
    }

    #[test]
    fn test_anthropic_analyzer_accepts_valid_key() {
        let result = AnthropicMediaAnalyzer::new("sk-ant-test-key".to_string());
        assert!(result.is_ok());
    }

    #[test]
    fn test_anthropic_analyzer_builder() {
        let analyzer = AnthropicMediaAnalyzer::new("test-key".to_string())
            .unwrap()
            .with_base_url("https://proxy.example.com/".to_string())
            .with_model("claude-3-haiku".to_string())
            .with_max_tokens(512);

        assert_eq!(analyzer.base_url, "https://proxy.example.com");
        assert_eq!(analyzer.model, "claude-3-haiku");
        assert_eq!(analyzer.max_tokens, 512);
    }

    #[test]
    fn test_anthropic_supported_types() {
        let analyzer = AnthropicMediaAnalyzer::new("test-key".to_string()).unwrap();
        let types = analyzer.supported_types();
        assert_eq!(types, vec![MediaType::Image]);
    }

    #[test]
    fn test_openai_analyzer_rejects_empty_key() {
        let result = OpenAiMediaAnalyzer::new("".to_string());
        assert!(result.is_err());
    }

    #[test]
    fn test_openai_analyzer_rejects_whitespace_key() {
        let result = OpenAiMediaAnalyzer::new("   ".to_string());
        assert!(result.is_err());
    }

    #[test]
    fn test_openai_analyzer_accepts_valid_key() {
        let result = OpenAiMediaAnalyzer::new("sk-test-key-1234567890".to_string());
        assert!(result.is_ok());
    }

    #[test]
    fn test_openai_analyzer_builder() {
        let analyzer = OpenAiMediaAnalyzer::new("test-key".to_string())
            .unwrap()
            .with_base_url("https://proxy.example.com/".to_string())
            .with_vision_model("gpt-4-turbo".to_string())
            .with_max_tokens(2048);

        assert_eq!(analyzer.base_url, "https://proxy.example.com");
        assert_eq!(analyzer.vision_model, "gpt-4-turbo");
        assert_eq!(analyzer.max_tokens, 2048);
    }

    #[test]
    fn test_openai_supported_types() {
        let analyzer = OpenAiMediaAnalyzer::new("test-key".to_string()).unwrap();
        let types = analyzer.supported_types();
        assert_eq!(types, vec![MediaType::Image, MediaType::Audio]);
    }

    // ==================== Empty data tests ====================

    #[tokio::test]
    async fn test_anthropic_analyze_empty_image() {
        let analyzer = AnthropicMediaAnalyzer::new("test-key".to_string()).unwrap();
        let result = analyzer.analyze_image(&[], "image/png", None).await;
        assert!(matches!(result, Err(AnalysisError::EmptyData)));
    }

    #[tokio::test]
    async fn test_openai_analyze_empty_image() {
        let analyzer = OpenAiMediaAnalyzer::new("test-key".to_string()).unwrap();
        let result = analyzer.analyze_image(&[], "image/png", None).await;
        assert!(matches!(result, Err(AnalysisError::EmptyData)));
    }

    #[tokio::test]
    async fn test_openai_transcribe_empty_audio() {
        let analyzer = OpenAiMediaAnalyzer::new("test-key".to_string()).unwrap();
        let result = analyzer.transcribe_audio(&[], "audio/mpeg").await;
        assert!(matches!(result, Err(AnalysisError::EmptyData)));
    }

    // ==================== Anthropic audio unsupported ====================

    #[tokio::test]
    async fn test_anthropic_transcribe_audio_unsupported() {
        let analyzer = AnthropicMediaAnalyzer::new("test-key".to_string()).unwrap();
        let result = analyzer.transcribe_audio(b"audio data", "audio/mpeg").await;
        assert!(matches!(
            result,
            Err(AnalysisError::UnsupportedMediaType(_))
        ));
    }

    // ==================== OpenAI audio MIME validation ====================

    #[tokio::test]
    async fn test_openai_transcribe_wrong_mime() {
        let analyzer = OpenAiMediaAnalyzer::new("test-key".to_string()).unwrap();
        let result = analyzer.transcribe_audio(b"data", "image/png").await;
        assert!(matches!(
            result,
            Err(AnalysisError::UnsupportedMediaType(_))
        ));
    }

    // ==================== MediaType serde tests ====================

    #[test]
    fn test_media_type_serde_roundtrip() {
        let types = vec![MediaType::Image, MediaType::Audio, MediaType::Video];
        for t in &types {
            let json = serde_json::to_string(t).unwrap();
            let deserialized: MediaType = serde_json::from_str(&json).unwrap();
            assert_eq!(*t, deserialized);
        }
    }

    #[test]
    fn test_media_type_serde_values() {
        assert_eq!(
            serde_json::to_string(&MediaType::Image).unwrap(),
            "\"image\""
        );
        assert_eq!(
            serde_json::to_string(&MediaType::Audio).unwrap(),
            "\"audio\""
        );
        assert_eq!(
            serde_json::to_string(&MediaType::Video).unwrap(),
            "\"video\""
        );
    }

    // ==================== AnalysisError display tests ====================

    #[test]
    fn test_analysis_error_display() {
        let err = AnalysisError::EmptyData;
        assert_eq!(err.to_string(), "media data is empty");

        let err = AnalysisError::UnsupportedMediaType("video/avi".to_string());
        assert_eq!(err.to_string(), "unsupported media type: video/avi");

        let err = AnalysisError::ApiResponse {
            status: 429,
            body: "rate limited".to_string(),
        };
        assert_eq!(err.to_string(), "API response error: 429 rate limited");
    }
}
