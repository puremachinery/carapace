//! macOS Keychain credential storage
//!
//! Uses the `keyring` crate to interface with macOS Keychain.

use super::{CredentialBackend, CredentialError, CredentialKey, SERVICE_NAME};
use keyring::Entry;
use std::sync::atomic::{AtomicBool, Ordering};

/// macOS Keychain credential backend
pub struct MacOsCredentialBackend {
    /// Cached availability status
    available: AtomicBool,
    /// Whether availability has been checked
    checked: AtomicBool,
}

impl MacOsCredentialBackend {
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
                CredentialError::Internal("Ambiguous keychain entry".to_string())
            }
            keyring::Error::TooLong(field, _) => {
                CredentialError::Internal(format!("Field too long: {}", field))
            }
            keyring::Error::Invalid(field, _) => {
                CredentialError::Internal(format!("Invalid field: {}", field))
            }
            keyring::Error::NoStorageAccess(platform_err) => {
                // Check for specific macOS keychain errors
                let err_str = platform_err.to_string().to_lowercase();
                if err_str.contains("user interaction not allowed")
                    || err_str.contains("interaction not allowed")
                {
                    // Keychain is locked and requires unlock
                    CredentialError::StoreLocked
                } else if err_str.contains("denied") || err_str.contains("permission") {
                    CredentialError::AccessDenied
                } else {
                    CredentialError::StoreUnavailable(platform_err.to_string())
                }
            }
            keyring::Error::PlatformFailure(platform_err) => {
                let err_str = platform_err.to_string().to_lowercase();
                if err_str.contains("user interaction not allowed")
                    || err_str.contains("-25308")
                // errSecInteractionNotAllowed
                {
                    CredentialError::StoreLocked
                } else if err_str.contains("-25293") || err_str.contains("authorization") {
                    // errSecAuthFailed
                    CredentialError::AccessDenied
                } else {
                    CredentialError::Internal(platform_err.to_string())
                }
            }
            _ => CredentialError::Internal(error.to_string()),
        }
    }
}

impl Default for MacOsCredentialBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl CredentialBackend for MacOsCredentialBackend {
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
        let err = MacOsCredentialBackend::map_error(keyring::Error::NoEntry);
        assert!(matches!(err, CredentialError::NotFound));
    }

    #[test]
    fn test_key_format() {
        let key = CredentialKey::new("auth-profile", "main", "anthropic:default");
        assert_eq!(key.to_account_key(), "auth-profile:main:anthropic:default");
    }

    // Integration tests that actually touch the keychain are gated behind a feature flag
    // because they require user interaction on macOS (keychain access prompt)
    #[cfg(feature = "keychain-tests")]
    mod integration {
        use super::*;

        #[tokio::test]
        async fn test_keychain_roundtrip() {
            let backend = MacOsCredentialBackend::new();
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
        async fn test_keychain_availability() {
            let backend = MacOsCredentialBackend::new();
            // On a normal macOS system with keychain, this should be true
            let available = backend.is_available().await;
            assert!(available, "Keychain should be available on macOS");
        }
    }
}
