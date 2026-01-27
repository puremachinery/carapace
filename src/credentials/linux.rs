//! Linux Secret Service credential storage
//!
//! Uses the `keyring` crate to interface with Secret Service (D-Bus).
//! Requires a Secret Service provider like GNOME Keyring or KWallet.

use super::{CredentialBackend, CredentialError, CredentialKey, SERVICE_NAME};
use keyring::Entry;
use std::sync::atomic::{AtomicBool, Ordering};

/// Linux Secret Service credential backend
pub struct LinuxCredentialBackend {
    /// Cached availability status
    available: AtomicBool,
    /// Whether availability has been checked
    checked: AtomicBool,
}

impl LinuxCredentialBackend {
    pub fn new() -> Self {
        Self {
            available: AtomicBool::new(false),
            checked: AtomicBool::new(false),
        }
    }

    /// Get or create a keyring entry for the given key
    fn get_entry(&self, key: &CredentialKey) -> Result<Entry, CredentialError> {
        Entry::new(SERVICE_NAME, &key.to_account_key())
            .map_err(|e| CredentialError::Internal(format!("Failed to create keyring entry: {}", e)))
    }

    /// Map keyring errors to our error types
    fn map_error(error: keyring::Error) -> CredentialError {
        match error {
            keyring::Error::NoEntry => CredentialError::NotFound,
            keyring::Error::Ambiguous(_) => {
                CredentialError::Internal("Ambiguous secret service entry".to_string())
            }
            keyring::Error::TooLong(field, _) => {
                CredentialError::Internal(format!("Field too long: {}", field))
            }
            keyring::Error::Invalid(field, _) => {
                CredentialError::Internal(format!("Invalid field: {}", field))
            }
            keyring::Error::NoStorageAccess(platform_err) => {
                let err_str = platform_err.to_string().to_lowercase();
                // Check for D-Bus connection errors
                if err_str.contains("dbus")
                    || err_str.contains("secret service")
                    || err_str.contains("not available")
                    || err_str.contains("connection refused")
                {
                    CredentialError::StoreUnavailable(format!(
                        "Secret Service unavailable. Install GNOME Keyring or KWallet. Error: {}",
                        platform_err
                    ))
                } else if err_str.contains("locked") || err_str.contains("unlock") {
                    CredentialError::StoreLocked
                } else if err_str.contains("denied") || err_str.contains("permission") {
                    CredentialError::AccessDenied
                } else {
                    CredentialError::StoreUnavailable(platform_err.to_string())
                }
            }
            keyring::Error::PlatformFailure(platform_err) => {
                let err_str = platform_err.to_string().to_lowercase();
                if err_str.contains("dbus")
                    || err_str.contains("no secret service")
                    || err_str.contains("not found")
                {
                    CredentialError::StoreUnavailable(format!(
                        "Secret Service unavailable. Install GNOME Keyring or KWallet. Error: {}",
                        platform_err
                    ))
                } else if err_str.contains("locked") {
                    CredentialError::StoreLocked
                } else {
                    CredentialError::Internal(platform_err.to_string())
                }
            }
            _ => CredentialError::Internal(error.to_string()),
        }
    }
}

impl Default for LinuxCredentialBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl CredentialBackend for LinuxCredentialBackend {
    async fn get_raw(&self, key: &CredentialKey) -> Result<Option<String>, CredentialError> {
        let entry = self.get_entry(key)?;

        match entry.get_password() {
            Ok(password) => {
                // Treat empty string as not set
                if password.is_empty() {
                    Ok(None)
                } else {
                    Ok(Some(password))
                }
            }
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(Self::map_error(e)),
        }
    }

    async fn set_raw(&self, key: &CredentialKey, value: &str) -> Result<(), CredentialError> {
        let entry = self.get_entry(key)?;
        entry.set_password(value).map_err(Self::map_error)
    }

    async fn delete_raw(&self, key: &CredentialKey) -> Result<(), CredentialError> {
        let entry = self.get_entry(key)?;

        match entry.delete_password() {
            Ok(()) => Ok(()),
            // Treat "not found" as success for delete (idempotent)
            Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(Self::map_error(e)),
        }
    }

    async fn is_available(&self) -> bool {
        // Return cached result if already checked
        if self.checked.load(Ordering::Acquire) {
            return self.available.load(Ordering::Acquire);
        }

        // Try a test operation to check availability
        let test_key = CredentialKey::new("_health", "_check", "_test");
        let entry = match self.get_entry(&test_key) {
            Ok(e) => e,
            Err(_) => {
                self.available.store(false, Ordering::Release);
                self.checked.store(true, Ordering::Release);
                return false;
            }
        };

        // Try to read (should succeed even if not found)
        let available = match entry.get_password() {
            Ok(_) => true,
            Err(keyring::Error::NoEntry) => true,
            Err(e) => {
                let err = Self::map_error(e);
                // On Linux, if Secret Service is unavailable, log a helpful message
                if matches!(err, CredentialError::StoreUnavailable(_)) {
                    tracing::warn!(
                        "Secret Service is not available. Install GNOME Keyring or KWallet \
                         for secure credential storage. Operating in env-only mode."
                    );
                }
                !matches!(
                    err,
                    CredentialError::StoreLocked | CredentialError::StoreUnavailable(_)
                )
            }
        };

        self.available.store(available, Ordering::Release);
        self.checked.store(true, Ordering::Release);
        available
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_mapping() {
        // Test NoEntry maps to NotFound
        let err = LinuxCredentialBackend::map_error(keyring::Error::NoEntry);
        assert!(matches!(err, CredentialError::NotFound));
    }

    #[test]
    fn test_key_format() {
        let key = CredentialKey::new("auth-profile", "main", "anthropic:default");
        assert_eq!(key.to_account_key(), "auth-profile:main:anthropic:default");
    }

    // Integration tests that actually touch Secret Service are gated behind a feature flag
    // because they require a running Secret Service daemon
    #[cfg(feature = "secret-service-tests")]
    mod integration {
        use super::*;

        #[tokio::test]
        async fn test_secret_service_roundtrip() {
            let backend = LinuxCredentialBackend::new();

            // Skip if Secret Service not available
            if !backend.is_available().await {
                eprintln!("Secret Service not available, skipping integration test");
                return;
            }

            let key = CredentialKey::new("test", "integration", "roundtrip");

            // Clean up any previous test data
            let _ = backend.delete_raw(&key).await;

            // Initially should not exist
            let result = backend.get_raw(&key).await.unwrap();
            assert_eq!(result, None);

            // Set a value
            backend.set_raw(&key, "test-secret").await.unwrap();

            // Get it back
            let result = backend.get_raw(&key).await.unwrap();
            assert_eq!(result, Some("test-secret".to_string()));

            // Update the value
            backend.set_raw(&key, "updated-secret").await.unwrap();

            // Get updated value
            let result = backend.get_raw(&key).await.unwrap();
            assert_eq!(result, Some("updated-secret".to_string()));

            // Delete it
            backend.delete_raw(&key).await.unwrap();

            // Should be gone
            let result = backend.get_raw(&key).await.unwrap();
            assert_eq!(result, None);
        }

        #[tokio::test]
        async fn test_secret_service_availability() {
            let backend = LinuxCredentialBackend::new();
            let available = backend.is_available().await;
            // Just log the result - availability depends on the system
            eprintln!("Secret Service available: {}", available);
        }
    }
}
