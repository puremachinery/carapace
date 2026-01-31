//! Skill signature verification using Ed25519.
//!
//! Provides optional cryptographic verification of WASM skill binaries.
//! Publishers sign WASM bytes with Ed25519, and the signature + public key
//! are stored in the skills manifest. On load, the signature is verified
//! before the module is instantiated.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use super::loader::LoaderError;

/// Signature verification configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureConfig {
    /// Master switch — when `false`, signature checks are skipped.
    #[serde(default)]
    pub enabled: bool,
    /// When `true`, unsigned skills are rejected (otherwise just warned).
    #[serde(default)]
    pub require_signature: bool,
    /// Hex-encoded Ed25519 public keys of trusted publishers.
    /// If non-empty, the skill's publisher key must be in this list.
    #[serde(default)]
    pub trusted_publishers: Vec<String>,
}

impl Default for SignatureConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            require_signature: true,
            trusted_publishers: Vec::new(),
        }
    }
}

/// Sign WASM bytes with an Ed25519 signing key.
///
/// Returns the signature as a 64-byte array.
pub fn sign_wasm_bytes(wasm_bytes: &[u8], signing_key: &SigningKey) -> Signature {
    signing_key.sign(wasm_bytes)
}

/// Parse a hex-encoded Ed25519 verifying key.
pub fn parse_verifying_key(hex_key: &str) -> Result<VerifyingKey, LoaderError> {
    let bytes = hex::decode(hex_key).map_err(|e| LoaderError::SignatureVerificationFailed {
        skill_name: String::new(),
        reason: format!("invalid hex public key: {e}"),
    })?;

    if bytes.len() != 32 {
        return Err(LoaderError::SignatureVerificationFailed {
            skill_name: String::new(),
            reason: format!("public key must be 32 bytes, got {}", bytes.len()),
        });
    }

    let key_bytes: [u8; 32] = bytes.try_into().unwrap();
    VerifyingKey::from_bytes(&key_bytes).map_err(|e| LoaderError::SignatureVerificationFailed {
        skill_name: String::new(),
        reason: format!("invalid Ed25519 public key: {e}"),
    })
}

/// Parse a hex-encoded Ed25519 signature.
fn parse_signature(hex_sig: &str) -> Result<Signature, LoaderError> {
    let bytes = hex::decode(hex_sig).map_err(|e| LoaderError::SignatureVerificationFailed {
        skill_name: String::new(),
        reason: format!("invalid hex signature: {e}"),
    })?;

    if bytes.len() != 64 {
        return Err(LoaderError::SignatureVerificationFailed {
            skill_name: String::new(),
            reason: format!("signature must be 64 bytes, got {}", bytes.len()),
        });
    }

    let sig_bytes: [u8; 64] = bytes.try_into().unwrap();
    Ok(Signature::from_bytes(&sig_bytes))
}

/// Verify the Ed25519 signature of a skill's WASM bytes.
///
/// Reads `publisher_key` and `signature` from the skills manifest and verifies
/// them against the raw WASM bytes.
///
/// # Behavior
///
/// - Missing manifest or missing signature fields with `require_signature: false`
///   → logs a warning and returns Ok.
/// - Missing signature with `require_signature: true` → returns error.
/// - Invalid signature → returns error.
/// - If `trusted_publishers` is non-empty, the publisher key must be in the list.
pub fn verify_skill_signature(
    skill_name: &str,
    wasm_bytes: &[u8],
    manifest: &serde_json::Value,
    config: &SignatureConfig,
) -> Result<(), LoaderError> {
    if !config.enabled {
        return Ok(());
    }

    let entry = match manifest.get(skill_name) {
        Some(e) => e,
        None => {
            if config.require_signature {
                return Err(LoaderError::SignatureVerificationFailed {
                    skill_name: skill_name.to_string(),
                    reason: "no manifest entry and signatures are required".to_string(),
                });
            }
            tracing::warn!(
                skill = %skill_name,
                "no manifest entry for skill, skipping signature verification"
            );
            return Ok(());
        }
    };

    let publisher_key_hex = match entry.get("publisher_key").and_then(|v| v.as_str()) {
        Some(k) => k,
        None => {
            if config.require_signature {
                return Err(LoaderError::SignatureVerificationFailed {
                    skill_name: skill_name.to_string(),
                    reason: "no publisher_key in manifest and signatures are required".to_string(),
                });
            }
            tracing::warn!(
                skill = %skill_name,
                "no publisher_key in manifest, skipping signature verification"
            );
            return Ok(());
        }
    };

    let signature_hex = match entry.get("signature").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => {
            if config.require_signature {
                return Err(LoaderError::SignatureVerificationFailed {
                    skill_name: skill_name.to_string(),
                    reason: "no signature in manifest and signatures are required".to_string(),
                });
            }
            tracing::warn!(
                skill = %skill_name,
                "no signature in manifest, skipping signature verification"
            );
            return Ok(());
        }
    };

    // Parse key and signature
    let verifying_key = parse_verifying_key(publisher_key_hex).map_err(|e| {
        LoaderError::SignatureVerificationFailed {
            skill_name: skill_name.to_string(),
            reason: format!("publisher key parse error: {e}"),
        }
    })?;

    let signature =
        parse_signature(signature_hex).map_err(|e| LoaderError::SignatureVerificationFailed {
            skill_name: skill_name.to_string(),
            reason: format!("signature parse error: {e}"),
        })?;

    // Check trusted publishers (case-insensitive hex comparison)
    let publisher_lower = publisher_key_hex.to_ascii_lowercase();
    if !config.trusted_publishers.is_empty()
        && !config
            .trusted_publishers
            .iter()
            .any(|tp| tp.to_ascii_lowercase() == publisher_lower)
    {
        return Err(LoaderError::SignatureVerificationFailed {
            skill_name: skill_name.to_string(),
            reason: format!(
                "publisher key {} is not in the trusted publishers list",
                publisher_key_hex
            ),
        });
    }

    // Verify signature
    verifying_key.verify(wasm_bytes, &signature).map_err(|e| {
        LoaderError::SignatureVerificationFailed {
            skill_name: skill_name.to_string(),
            reason: format!("Ed25519 signature verification failed: {e}"),
        }
    })?;

    tracing::debug!(
        skill = %skill_name,
        publisher = %publisher_key_hex,
        "skill signature verification passed"
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use std::fs;
    use std::path::Path;
    use tempfile::TempDir;

    fn generate_keypair() -> (SigningKey, VerifyingKey) {
        let mut secret = [0u8; 32];
        getrandom::getrandom(&mut secret).expect("failed to generate random bytes");
        let signing_key = SigningKey::from_bytes(&secret);
        let verifying_key = signing_key.verifying_key();
        (signing_key, verifying_key)
    }

    fn write_manifest(dir: &Path, skill_name: &str, pub_key_hex: &str, sig_hex: &str) {
        let manifest = serde_json::json!({
            skill_name: {
                "sha256": "dummy",
                "publisher_key": pub_key_hex,
                "signature": sig_hex
            }
        });
        fs::write(
            dir.join("skills-manifest.json"),
            serde_json::to_string(&manifest).unwrap(),
        )
        .unwrap();
    }

    // ==================== Sign/Verify Roundtrip ====================

    #[test]
    fn test_sign_verify_roundtrip() {
        let (signing_key, verifying_key) = generate_keypair();
        let wasm_bytes = b"fake wasm module bytes";

        let signature = sign_wasm_bytes(wasm_bytes, &signing_key);
        assert!(verifying_key.verify(wasm_bytes, &signature).is_ok());
    }

    #[test]
    fn test_verify_wrong_bytes_fails() {
        let (signing_key, verifying_key) = generate_keypair();
        let wasm_bytes = b"original wasm bytes";
        let tampered_bytes = b"tampered wasm bytes";

        let signature = sign_wasm_bytes(wasm_bytes, &signing_key);
        assert!(verifying_key.verify(tampered_bytes, &signature).is_err());
    }

    #[test]
    fn test_verify_wrong_key_fails() {
        let (signing_key, _) = generate_keypair();
        let (_, wrong_verifying_key) = generate_keypair();
        let wasm_bytes = b"wasm bytes";

        let signature = sign_wasm_bytes(wasm_bytes, &signing_key);
        assert!(wrong_verifying_key.verify(wasm_bytes, &signature).is_err());
    }

    // ==================== Key Parsing ====================

    #[test]
    fn test_parse_verifying_key_valid() {
        let (_, verifying_key) = generate_keypair();
        let hex_key = hex::encode(verifying_key.as_bytes());
        let parsed = parse_verifying_key(&hex_key).unwrap();
        assert_eq!(parsed.as_bytes(), verifying_key.as_bytes());
    }

    #[test]
    fn test_parse_verifying_key_invalid_hex() {
        let result = parse_verifying_key("not-hex-data!");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_verifying_key_wrong_length() {
        let result = parse_verifying_key(&hex::encode([0u8; 16]));
        assert!(result.is_err());
    }

    // ==================== Full Verification Flow ====================

    #[test]
    fn test_verify_skill_signature_success() {
        let dir = TempDir::new().unwrap();
        let (signing_key, verifying_key) = generate_keypair();
        let wasm_bytes = b"test wasm content for signing";

        let signature = sign_wasm_bytes(wasm_bytes, &signing_key);
        let pub_hex = hex::encode(verifying_key.as_bytes());
        let sig_hex = hex::encode(signature.to_bytes());

        write_manifest(dir.path(), "test-skill", &pub_hex, &sig_hex);
        let manifest_content = fs::read_to_string(dir.path().join("skills-manifest.json")).unwrap();
        let manifest: serde_json::Value = serde_json::from_str(&manifest_content).unwrap();

        let config = SignatureConfig {
            enabled: true,
            require_signature: true,
            trusted_publishers: Vec::new(),
        };

        let result = verify_skill_signature("test-skill", wasm_bytes, &manifest, &config);
        assert!(
            result.is_ok(),
            "signature verification failed: {:?}",
            result
        );
    }

    #[test]
    fn test_verify_skill_signature_tampered() {
        let dir = TempDir::new().unwrap();
        let (signing_key, verifying_key) = generate_keypair();
        let wasm_bytes = b"original content";
        let tampered = b"tampered content";

        let signature = sign_wasm_bytes(wasm_bytes, &signing_key);
        let pub_hex = hex::encode(verifying_key.as_bytes());
        let sig_hex = hex::encode(signature.to_bytes());

        write_manifest(dir.path(), "test-skill", &pub_hex, &sig_hex);
        let manifest_content = fs::read_to_string(dir.path().join("skills-manifest.json")).unwrap();
        let manifest: serde_json::Value = serde_json::from_str(&manifest_content).unwrap();

        let config = SignatureConfig {
            enabled: true,
            require_signature: true,
            trusted_publishers: Vec::new(),
        };

        let result = verify_skill_signature("test-skill", tampered, &manifest, &config);
        assert!(result.is_err());
    }

    // ==================== Trusted Publishers ====================

    #[test]
    fn test_trusted_publisher_accepted() {
        let dir = TempDir::new().unwrap();
        let (signing_key, verifying_key) = generate_keypair();
        let wasm_bytes = b"wasm bytes for trusted test";

        let signature = sign_wasm_bytes(wasm_bytes, &signing_key);
        let pub_hex = hex::encode(verifying_key.as_bytes());
        let sig_hex = hex::encode(signature.to_bytes());

        write_manifest(dir.path(), "my-skill", &pub_hex, &sig_hex);
        let manifest_content = fs::read_to_string(dir.path().join("skills-manifest.json")).unwrap();
        let manifest: serde_json::Value = serde_json::from_str(&manifest_content).unwrap();

        let config = SignatureConfig {
            enabled: true,
            require_signature: true,
            trusted_publishers: vec![pub_hex.clone()],
        };

        let result = verify_skill_signature("my-skill", wasm_bytes, &manifest, &config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_untrusted_publisher_rejected() {
        let dir = TempDir::new().unwrap();
        let (signing_key, verifying_key) = generate_keypair();
        let (_, other_key) = generate_keypair();
        let wasm_bytes = b"wasm bytes";

        let signature = sign_wasm_bytes(wasm_bytes, &signing_key);
        let pub_hex = hex::encode(verifying_key.as_bytes());
        let sig_hex = hex::encode(signature.to_bytes());
        let other_hex = hex::encode(other_key.as_bytes());

        write_manifest(dir.path(), "my-skill", &pub_hex, &sig_hex);
        let manifest_content = fs::read_to_string(dir.path().join("skills-manifest.json")).unwrap();
        let manifest: serde_json::Value = serde_json::from_str(&manifest_content).unwrap();

        let config = SignatureConfig {
            enabled: true,
            require_signature: true,
            trusted_publishers: vec![other_hex],
        };

        let result = verify_skill_signature("my-skill", wasm_bytes, &manifest, &config);
        assert!(result.is_err());
    }

    #[test]
    fn test_trusted_publisher_case_insensitive() {
        let dir = TempDir::new().unwrap();
        let (signing_key, verifying_key) = generate_keypair();
        let wasm_bytes = b"wasm bytes for case test";

        let signature = sign_wasm_bytes(wasm_bytes, &signing_key);
        let pub_hex = hex::encode(verifying_key.as_bytes());
        let sig_hex = hex::encode(signature.to_bytes());

        write_manifest(dir.path(), "my-skill", &pub_hex, &sig_hex);
        let manifest_content = fs::read_to_string(dir.path().join("skills-manifest.json")).unwrap();
        let manifest: serde_json::Value = serde_json::from_str(&manifest_content).unwrap();

        // Use UPPERCASE in trusted_publishers, lowercase in manifest
        let config = SignatureConfig {
            enabled: true,
            require_signature: true,
            trusted_publishers: vec![pub_hex.to_ascii_uppercase()],
        };

        let result = verify_skill_signature("my-skill", wasm_bytes, &manifest, &config);
        assert!(
            result.is_ok(),
            "case-insensitive comparison should pass: {:?}",
            result
        );
    }

    // ==================== Missing Signature Handling ====================

    #[test]
    fn test_missing_signature_require_false_ok() {
        // No manifest at all (Null value)
        let config = SignatureConfig {
            enabled: true,
            require_signature: false,
            trusted_publishers: Vec::new(),
        };

        let result =
            verify_skill_signature("some-skill", b"wasm", &serde_json::Value::Null, &config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_missing_signature_require_true_fails() {
        // No manifest at all (Null value)
        let config = SignatureConfig {
            enabled: true,
            require_signature: true,
            trusted_publishers: Vec::new(),
        };

        let result =
            verify_skill_signature("some-skill", b"wasm", &serde_json::Value::Null, &config);
        assert!(result.is_err());
    }

    #[test]
    fn test_missing_entry_require_false_ok() {
        let manifest: serde_json::Value = serde_json::from_str(r#"{"other-skill": {}}"#).unwrap();

        let config = SignatureConfig {
            enabled: true,
            require_signature: false,
            trusted_publishers: Vec::new(),
        };

        let result = verify_skill_signature("missing-skill", b"wasm", &manifest, &config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_missing_publisher_key_require_true_fails() {
        let manifest = serde_json::json!({
            "my-skill": { "sha256": "dummy" }
        });

        let config = SignatureConfig {
            enabled: true,
            require_signature: true,
            trusted_publishers: Vec::new(),
        };

        let result = verify_skill_signature("my-skill", b"wasm", &manifest, &config);
        assert!(result.is_err());
    }

    // ==================== Disabled Config ====================

    #[test]
    fn test_disabled_config_skips_verification() {
        let config = SignatureConfig {
            enabled: false,
            require_signature: true,
            trusted_publishers: Vec::new(),
        };

        // No manifest, but disabled — should pass
        let result =
            verify_skill_signature("any-skill", b"wasm", &serde_json::Value::Null, &config);
        assert!(result.is_ok());
    }

    // ==================== Config Serialization ====================

    #[test]
    fn test_config_default() {
        let config = SignatureConfig::default();
        assert!(config.enabled);
        assert!(config.require_signature);
        assert!(config.trusted_publishers.is_empty());
    }

    #[test]
    fn test_config_serde_roundtrip() {
        let config = SignatureConfig {
            enabled: true,
            require_signature: true,
            trusted_publishers: vec!["abc123".to_string()],
        };
        let json = serde_json::to_string(&config).unwrap();
        let parsed: SignatureConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.enabled, config.enabled);
        assert_eq!(parsed.require_signature, config.require_signature);
        assert_eq!(parsed.trusted_publishers, config.trusted_publishers);
    }

    // ==================== Signature Parsing ====================

    #[test]
    fn test_parse_signature_invalid_hex() {
        let result = parse_signature("not-valid-hex!");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_signature_wrong_length() {
        let result = parse_signature(&hex::encode([0u8; 32]));
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_signature_valid() {
        let (signing_key, _) = generate_keypair();
        let sig = sign_wasm_bytes(b"data", &signing_key);
        let hex_sig = hex::encode(sig.to_bytes());
        let parsed = parse_signature(&hex_sig).unwrap();
        assert_eq!(parsed.to_bytes(), sig.to_bytes());
    }
}
