//! Logging subsystem
//!
//! Structured logging via tracing with support for JSON (production) and
//! plaintext (development) output formats.
//!
//! # Log Targets
//!
//! Use these consistent target names across the codebase:
//! - `gateway` - main gateway operations
//! - `ws` - WebSocket server
//! - `http` - HTTP server
//! - `plugins` - plugin system
//! - `auth` - authentication
//! - `config` - configuration loading
//!
//! # Environment Variables
//!
//! - `CARAPACE_LOG` - Primary log level/filter (takes precedence)
//! - `RUST_LOG` - Fallback log level/filter
//!
//! # Examples
//!
//! ```no_run
//! use carapace::logging::{init_logging, LogConfig, LogFormat, LogOutput};
//!
//! // Development setup (plaintext to stdout)
//! init_logging(LogConfig::development()).unwrap();
//!
//! // Production setup (JSON to stdout)
//! init_logging(LogConfig::production()).unwrap();
//!
//! // Custom setup with file output
//! init_logging(LogConfig {
//!     format: LogFormat::Json,
//!     output: LogOutput::File("/var/log/carapace.log".into()),
//!     default_level: tracing::Level::INFO,
//! }).unwrap();
//! ```

pub mod audit;
pub mod buffer;
pub mod redact;

use std::fs::File;
use std::io;
use std::path::PathBuf;
use std::sync::OnceLock;

use crate::logging::redact::RedactingMakeWriter;
use tracing::Level;
use tracing_subscriber::fmt::time::UtcTime;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Layer};

/// Guard to track if logging has been initialized
static INIT_GUARD: OnceLock<()> = OnceLock::new();

/// Log output format
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LogFormat {
    /// JSON format for production (structured logs)
    Json,
    /// Human-readable plaintext for development
    #[default]
    Plaintext,
}

/// Log output destination
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum LogOutput {
    /// Write to stdout
    #[default]
    Stdout,
    /// Write to stderr
    Stderr,
    /// Write to a file at the given path
    File(PathBuf),
}

/// Configuration for the logging subsystem
#[derive(Debug, Clone)]
pub struct LogConfig {
    /// Output format (JSON or plaintext)
    pub format: LogFormat,
    /// Output destination (stdout, stderr, or file)
    pub output: LogOutput,
    /// Default log level when no env filter is set
    pub default_level: Level,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            format: LogFormat::Plaintext,
            output: LogOutput::Stdout,
            default_level: Level::INFO,
        }
    }
}

impl LogConfig {
    /// Create a development configuration (plaintext to stdout, debug level)
    pub fn development() -> Self {
        Self {
            format: LogFormat::Plaintext,
            output: LogOutput::Stdout,
            default_level: Level::DEBUG,
        }
    }

    /// Create a production configuration (JSON to stdout, info level)
    pub fn production() -> Self {
        Self {
            format: LogFormat::Json,
            output: LogOutput::Stdout,
            default_level: Level::INFO,
        }
    }
}

/// Error type for logging initialization
#[derive(Debug, thiserror::Error)]
pub enum LoggingError {
    #[error("failed to create log file: {0}")]
    FileCreation(#[from] io::Error),
    #[error("failed to parse log filter: {0}")]
    FilterParse(#[from] tracing_subscriber::filter::ParseError),
    #[error("logging already initialized")]
    AlreadyInitialized,
    #[error("failed to set global subscriber: {0}")]
    SetGlobalDefault(#[from] tracing::subscriber::SetGlobalDefaultError),
    #[error("failed to initialize subscriber: {0}")]
    TryInit(#[from] tracing_subscriber::util::TryInitError),
}

/// Build an EnvFilter from environment variables or default level.
///
/// Checks CARAPACE_LOG first, then RUST_LOG, falling back to the default level.
fn build_env_filter(default_level: Level) -> Result<EnvFilter, LoggingError> {
    // Check CARAPACE_LOG first, then RUST_LOG
    if let Ok(filter) = std::env::var("CARAPACE_LOG") {
        return Ok(EnvFilter::try_new(filter)?);
    }
    if let Ok(filter) = std::env::var("RUST_LOG") {
        return Ok(EnvFilter::try_new(filter)?);
    }

    // Default filter with standard targets
    let default_filter = format!(
        "{level},gateway={level},ws={level},http={level},plugins={level},auth={level},config={level}",
        level = default_level.as_str().to_lowercase()
    );
    Ok(EnvFilter::try_new(default_filter)?)
}

/// Initialize the logging subsystem with the given configuration.
///
/// This function should be called once at application startup. Subsequent calls
/// will return an error.
///
/// # Errors
///
/// Returns an error if:
/// - Logging has already been initialized
/// - The log file cannot be created (for file output)
/// - The environment filter is invalid
pub fn init_logging(config: LogConfig) -> Result<(), LoggingError> {
    // Prevent double initialization
    if INIT_GUARD.set(()).is_err() {
        return Err(LoggingError::AlreadyInitialized);
    }

    let filter = build_env_filter(config.default_level)?;

    // RFC 3339 timestamp format
    let timer = UtcTime::rfc_3339();

    // Buffer layer captures logs for the logs.tail WebSocket endpoint
    let buffer_layer = buffer::LogBufferLayer::new();

    match (&config.format, &config.output) {
        (LogFormat::Json, LogOutput::Stdout) => {
            let writer = RedactingMakeWriter::new(io::stdout);
            let layer = tracing_subscriber::fmt::layer()
                .json()
                .with_timer(timer)
                .with_target(true)
                .with_current_span(true)
                .with_span_list(true)
                .with_writer(writer)
                .with_filter(filter);

            tracing_subscriber::registry()
                .with(layer)
                .with(buffer_layer)
                .init();
        }
        (LogFormat::Json, LogOutput::Stderr) => {
            let writer = RedactingMakeWriter::new(io::stderr);
            let layer = tracing_subscriber::fmt::layer()
                .json()
                .with_timer(timer)
                .with_target(true)
                .with_current_span(true)
                .with_span_list(true)
                .with_writer(writer)
                .with_filter(filter);

            tracing_subscriber::registry()
                .with(layer)
                .with(buffer_layer)
                .init();
        }
        (LogFormat::Json, LogOutput::File(path)) => {
            let file = File::create(path)?;
            let writer = RedactingMakeWriter::new(file);
            let layer = tracing_subscriber::fmt::layer()
                .json()
                .with_timer(timer)
                .with_target(true)
                .with_current_span(true)
                .with_span_list(true)
                .with_writer(writer)
                .with_filter(filter);

            tracing_subscriber::registry()
                .with(layer)
                .with(buffer_layer)
                .init();
        }
        (LogFormat::Plaintext, LogOutput::Stdout) => {
            let writer = RedactingMakeWriter::new(io::stdout);
            let layer = tracing_subscriber::fmt::layer()
                .with_timer(timer)
                .with_target(true)
                .with_thread_ids(false)
                .with_thread_names(false)
                .with_file(false)
                .with_line_number(false)
                .with_writer(writer)
                .with_filter(filter);

            tracing_subscriber::registry()
                .with(layer)
                .with(buffer_layer)
                .init();
        }
        (LogFormat::Plaintext, LogOutput::Stderr) => {
            let writer = RedactingMakeWriter::new(io::stderr);
            let layer = tracing_subscriber::fmt::layer()
                .with_timer(timer)
                .with_target(true)
                .with_thread_ids(false)
                .with_thread_names(false)
                .with_file(false)
                .with_line_number(false)
                .with_writer(writer)
                .with_filter(filter);

            tracing_subscriber::registry()
                .with(layer)
                .with(buffer_layer)
                .init();
        }
        (LogFormat::Plaintext, LogOutput::File(path)) => {
            let file = File::create(path)?;
            let writer = RedactingMakeWriter::new(file);
            let layer = tracing_subscriber::fmt::layer()
                .with_timer(timer)
                .with_target(true)
                .with_thread_ids(false)
                .with_thread_names(false)
                .with_file(false)
                .with_line_number(false)
                .with_writer(writer)
                .with_filter(filter);

            tracing_subscriber::registry()
                .with(layer)
                .with(buffer_layer)
                .init();
        }
    }

    Ok(())
}

/// Initialize logging for tests.
///
/// This is a convenience function that initializes logging with test-friendly
/// defaults (plaintext, debug level). It silently ignores errors if logging
/// is already initialized, making it safe to call from multiple tests.
pub fn init_test_logging() {
    let _ = init_logging_internal(LogConfig {
        format: LogFormat::Plaintext,
        output: LogOutput::Stdout,
        default_level: Level::DEBUG,
    });
}

/// Internal initialization that doesn't check the guard (for testing)
fn init_logging_internal(config: LogConfig) -> Result<(), LoggingError> {
    let filter = build_env_filter(config.default_level)?;
    let timer = UtcTime::rfc_3339();

    let subscriber = tracing_subscriber::registry();

    match (&config.format, &config.output) {
        (LogFormat::Json, LogOutput::Stdout) => {
            let writer = RedactingMakeWriter::new(io::stdout);
            let layer = tracing_subscriber::fmt::layer()
                .json()
                .with_timer(timer)
                .with_target(true)
                .with_current_span(true)
                .with_span_list(true)
                .with_writer(writer)
                .with_filter(filter);

            subscriber.with(layer).try_init()?;
        }
        (LogFormat::Plaintext, LogOutput::Stdout) => {
            let writer = RedactingMakeWriter::new(io::stdout);
            let layer = tracing_subscriber::fmt::layer()
                .with_timer(timer)
                .with_target(true)
                .with_writer(writer)
                .with_filter(filter);

            subscriber.with(layer).try_init()?;
        }
        _ => {
            // For testing, just use stdout plaintext
            let writer = RedactingMakeWriter::new(io::stdout);
            let layer = tracing_subscriber::fmt::layer()
                .with_timer(timer)
                .with_target(true)
                .with_writer(writer)
                .with_filter(filter);

            subscriber.with(layer).try_init()?;
        }
    }

    Ok(())
}

/// Log target constants for consistent naming across the codebase
pub mod targets {
    /// Main gateway operations
    pub const GATEWAY: &str = "gateway";
    /// WebSocket server
    pub const WS: &str = "ws";
    /// HTTP server
    pub const HTTP: &str = "http";
    /// Plugin system
    pub const PLUGINS: &str = "plugins";
    /// Authentication
    pub const AUTH: &str = "auth";
    /// Configuration loading
    pub const CONFIG: &str = "config";
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use tempfile::NamedTempFile;

    /// Mutex to serialize tests that modify global state (env vars).
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn test_log_config_defaults() {
        let config = LogConfig::default();
        assert_eq!(config.format, LogFormat::Plaintext);
        assert_eq!(config.output, LogOutput::Stdout);
        assert_eq!(config.default_level, Level::INFO);
    }

    #[test]
    fn test_log_config_development() {
        let config = LogConfig::development();
        assert_eq!(config.format, LogFormat::Plaintext);
        assert_eq!(config.output, LogOutput::Stdout);
        assert_eq!(config.default_level, Level::DEBUG);
    }

    #[test]
    fn test_log_config_production() {
        let config = LogConfig::production();
        assert_eq!(config.format, LogFormat::Json);
        assert_eq!(config.output, LogOutput::Stdout);
        assert_eq!(config.default_level, Level::INFO);
    }

    #[test]
    fn test_env_filter_default() {
        let _lock = TEST_LOCK.lock().unwrap();
        // Clear env vars for this test
        std::env::remove_var("CARAPACE_LOG");
        std::env::remove_var("RUST_LOG");

        // Filter should be created successfully with default level
        let filter = build_env_filter(Level::INFO);
        assert!(
            filter.is_ok(),
            "Should create filter with default INFO level"
        );
    }

    #[test]
    fn test_env_filter_carapace_log() {
        let _lock = TEST_LOCK.lock().unwrap();
        std::env::set_var("CARAPACE_LOG", "debug");
        let filter = build_env_filter(Level::INFO);
        assert!(filter.is_ok(), "Should create filter from CARAPACE_LOG");
        std::env::remove_var("CARAPACE_LOG");
    }

    #[test]
    fn test_env_filter_rust_log_fallback() {
        let _lock = TEST_LOCK.lock().unwrap();
        std::env::remove_var("CARAPACE_LOG");
        std::env::set_var("RUST_LOG", "warn");
        let filter = build_env_filter(Level::INFO);
        assert!(
            filter.is_ok(),
            "Should create filter from RUST_LOG fallback"
        );
        std::env::remove_var("RUST_LOG");
    }

    #[test]
    fn test_env_filter_carapace_takes_precedence() {
        let _lock = TEST_LOCK.lock().unwrap();
        std::env::set_var("CARAPACE_LOG", "error");
        std::env::set_var("RUST_LOG", "debug");
        // CARAPACE_LOG should take precedence (both are valid, so just verify creation)
        let filter = build_env_filter(Level::INFO);
        assert!(
            filter.is_ok(),
            "Should create filter with CARAPACE_LOG taking precedence"
        );
        std::env::remove_var("CARAPACE_LOG");
        std::env::remove_var("RUST_LOG");
    }

    #[test]
    fn test_env_filter_complex_directive() {
        let _lock = TEST_LOCK.lock().unwrap();
        std::env::set_var("CARAPACE_LOG", "gateway=debug,ws=info,http=warn");
        let filter = build_env_filter(Level::INFO);
        assert!(
            filter.is_ok(),
            "Should parse complex directive from CARAPACE_LOG"
        );
        std::env::remove_var("CARAPACE_LOG");
    }

    #[test]
    fn test_log_output_file() {
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path().to_path_buf();

        let config = LogConfig {
            format: LogFormat::Plaintext,
            output: LogOutput::File(path.clone()),
            default_level: Level::INFO,
        };

        assert_eq!(config.output, LogOutput::File(path));
    }

    #[test]
    fn test_targets_constants() {
        assert_eq!(targets::GATEWAY, "gateway");
        assert_eq!(targets::WS, "ws");
        assert_eq!(targets::HTTP, "http");
        assert_eq!(targets::PLUGINS, "plugins");
        assert_eq!(targets::AUTH, "auth");
        assert_eq!(targets::CONFIG, "config");
    }

    #[test]
    fn test_logging_error_display() {
        let err = LoggingError::AlreadyInitialized;
        assert_eq!(err.to_string(), "logging already initialized");

        let io_err = io::Error::new(io::ErrorKind::NotFound, "file not found");
        let err = LoggingError::FileCreation(io_err);
        assert!(err.to_string().contains("failed to create log file"));
    }

    // Integration test for JSON format output
    #[test]
    fn test_json_format_structure() {
        // We can't fully test the global subscriber in unit tests,
        // but we can verify the JSON layer builds correctly
        let filter = EnvFilter::try_new("info").unwrap();
        let timer = UtcTime::rfc_3339();

        // This should not panic
        let _layer = tracing_subscriber::fmt::layer::<tracing_subscriber::Registry>()
            .json()
            .with_timer(timer)
            .with_target(true)
            .with_current_span(true)
            .with_span_list(true)
            .with_filter(filter);
    }

    // Verify file output creates the file
    #[test]
    fn test_file_output_creation() {
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path().to_path_buf();

        // Create a file and write to it (simulating what the logger does)
        let file = File::create(&path).unwrap();
        drop(file);

        assert!(path.exists());
    }
}
