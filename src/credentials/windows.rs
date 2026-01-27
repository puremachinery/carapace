//! Windows Credential Manager storage
//!
//! Uses the `keyring` crate to interface with Windows Credential Manager.
//! Target name format: `clawdbot:<kind>:<agentId>:<id>`

use super::{CredentialBackend, CredentialError, CredentialKey, SERVICE_NAME};
use keyring::Entry;
use std::sync::atomic::{AtomicBool, Ordering};

/// Windows Credential Manager backend
pub struct WindowsCredentialBackend {
    /// Cached availability status
    available: AtomicBool,
    /// Whether availability has been checked
    checked: AtomicBool,
}

impl WindowsCredentialBackend {
    pub fn new() -> Self {
        Self {
            available: AtomicBool::new(false),
            checked: AtomicBool::new(false),
        }
    }

    /// Get or create a keyring entry for the given key
    /// On Windows, the target name will be: `clawdbot:<kind>:<agentId>:<id>`
    fn get_entry(&self, key: &CredentialKey) -> Result<Entry, CredentialError> {
        // Windows Credential Manager uses target name as the unique identifier
        // We use service:account format which keyring translates to target name
        Entry::new(SERVICE_NAME, &key.to_account_key())
            .map_err(|e| CredentialError::Internal(format!("Failed to create keyring entry: {}", e)))
    }

    /// Map keyring errors to our error types
    fn map_error(error: keyring::Error) -> CredentialError {
        match error {
            keyring::Error::NoEntry => CredentialError::NotFound,
            keyring::Error::Ambiguous(_) => {
                CredentialError::Internal("Ambiguous credential entry".to_string())
            }
            keyring::Error::TooLong(field, _) => {
                CredentialError::Internal(format!("Field too long: {}", field))
            }
            keyring::Error::Invalid(field, _) => {
                CredentialError::Internal(format!("Invalid field: {}", field))
            }
            keyring::Error::NoStorageAccess(platform_err) => {
                let err_str = platform_err.to_string().to_lowercase();
                if err_str.contains("access denied") || err_str.contains("access is denied") {
                    CredentialError::AccessDenied
                } else {
                    CredentialError::StoreUnavailable(platform_err.to_string())
                }
            }
            keyring::Error::PlatformFailure(platform_err) => {
                let err_str = platform_err.to_string().to_lowercase();
                // Windows error codes
                if err_str.contains("1168") || err_str.contains("element not found") {
                    // ERROR_NOT_FOUND
                    CredentialError::NotFound
                } else if err_str.contains("5") || err_str.contains("access denied") {
                    // ERROR_ACCESS_DENIED
                    CredentialError::AccessDenied
                } else {
                    CredentialError::Internal(platform_err.to_string())
                }
            }
            _ => CredentialError::Internal(error.to_string()),
        }
    }
}

impl Default for WindowsCredentialBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl CredentialBackend for WindowsCredentialBackend {
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

        // Windows Credential Manager is always available when user is logged in
        // Try a test operation to verify
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
                    CredentialError::StoreUnavailable(_) | CredentialError::AccessDenied
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
        let err = WindowsCredentialBackend::map_error(keyring::Error::NoEntry);
        assert!(matches!(err, CredentialError::NotFound));
    }

    #[test]
    fn test_key_format() {
        let key = CredentialKey::new("auth-profile", "main", "anthropic:default");
        assert_eq!(key.to_account_key(), "auth-profile:main:anthropic:default");
    }

    // Integration tests that actually touch Credential Manager are gated behind a feature flag
    #[cfg(feature = "credential-manager-tests")]
    mod integration {
        use super::*;

        #[tokio::test]
        async fn test_credential_manager_roundtrip() {
            let backend = WindowsCredentialBackend::new();

            // Skip if Credential Manager not available
            if !backend.is_available().await {
                eprintln!("Credential Manager not available, skipping integration test");
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
        async fn test_credential_manager_availability() {
            let backend = WindowsCredentialBackend::new();
            let available = backend.is_available().await;
            // On Windows with a logged-in user, this should be true
            assert!(available, "Credential Manager should be available on Windows");
        }
    }
}
