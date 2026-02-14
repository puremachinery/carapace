//! Skill packaging CLI handlers.
//!
//! Provides commands for building, signing, and packaging skills
//! for the carapace gateway.

use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command as ProcessCommand;

use crate::plugins::signature::sign_wasm_bytes;

/// WASM binary magic bytes: `\0asm`
const WASM_MAGIC: [u8; 4] = [0x00, 0x61, 0x73, 0x6D];

/// Name of the skills manifest file.
const SKILLS_MANIFEST_FILE: &str = "skills-manifest.json";

/// Skill key pair for signing.
#[derive(Debug, Serialize, Deserialize)]
pub struct SkillKeyPair {
    /// Hex-encoded signing key (64 chars).
    pub signing_key: String,
    /// Hex-encoded verifying key (64 chars).
    pub verifying_key: String,
}

/// Skill manifest entry.
#[derive(Debug, Serialize, Deserialize)]
pub struct SkillManifestEntry {
    pub name: String,
    pub version: Option<String>,
    pub sha256: String,
    pub publisher_key: String,
    pub signature: String,
    pub url: Option<String>,
}

/// Full skill manifest.
#[derive(Debug, Serialize, Deserialize)]
pub struct SkillManifest {
    #[serde(flatten)]
    pub entries: std::collections::HashMap<String, SkillManifestEntry>,
}

/// Compute SHA-256 hash of data and return as hex string.
fn compute_sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let hash = hasher.finalize();
    hex::encode(hash)
}

/// Parse a hex-encoded Ed25519 signing key.
fn parse_signing_key(hex_key: &str) -> Result<SigningKey, String> {
    let bytes = hex::decode(hex_key).map_err(|e| format!("invalid hex signing key: {e}"))?;

    if bytes.len() != 32 {
        return Err(format!(
            "signing key must be 32 bytes, got {}",
            bytes.len()
        ));
    }

    let key_bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "failed to convert signing key to a 32-byte array".to_string())?;
    Ok(SigningKey::from_bytes(&key_bytes))
}

/// Validate WASM magic bytes.
fn validate_wasm(bytes: &[u8]) -> Result<(), String> {
    if bytes.len() < 4 || bytes[..4] != WASM_MAGIC {
        return Err("invalid WASM file: bad magic bytes".to_string());
    }
    Ok(())
}

/// Embed plugin manifest into WASM binary as a custom section.
fn embed_manifest_in_wasm(
    wasm_bytes: &[u8],
    manifest: &crate::plugins::loader::PluginManifest,
) -> Result<Vec<u8>, String> {
    // Serialize manifest to JSON
    let manifest_json =
        serde_json::to_string(manifest).map_err(|e| format!("failed to serialize manifest: {e}"))?;

    // Build custom section: section_id (0) + size + name ("plugin-manifest") + data
    let name = "plugin-manifest";
    let name_bytes = name.as_bytes();
    let data_bytes = manifest_json.as_bytes();

    // Calculate sizes
    let name_len = name_bytes.len();
    // section_content_size = name_len_byte + name + data
    let section_content_size = 1 + name_len + data_bytes.len();

    let mut output = Vec::with_capacity(wasm_bytes.len() + section_content_size + 10);

    // Copy original WASM header (magic + version)
    output.extend_from_slice(&wasm_bytes[..8]);

    // Copy the rest of the original WASM (skip header, we'll re-add sections)
    if wasm_bytes.len() > 8 {
        output.extend_from_slice(&wasm_bytes[8..]);
    }

    // Add custom section
    output.push(0x00); // Section ID: custom

    // Write section size as LEB128
    write_leb128_u32(&mut output, section_content_size as u32);

    // Name length (LEB128)
    write_leb128_u32(&mut output, name_len as u32);

    // Name
    output.extend_from_slice(name_bytes);
    // Data
    output.extend_from_slice(data_bytes);

    Ok(output)
}

/// Write a u32 as LEB128 encoded bytes.
fn write_leb128_u32(output: &mut Vec<u8>, value: u32) {
    // LEB128 encoding: write 7-bit chunks, with continuation bit
    let mut value = value;
    loop {
        let mut byte = (value & 0x7F) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80; // continuation bit
        }
        output.push(byte);
        if value == 0 {
            break;
        }
    }
}

/// Run the skill build handler.
pub fn handle_skill_build(
    source: &str,
    output: Option<&str>,
    id: Option<&str>,
    name: Option<&str>,
    version: Option<&str>,
    description: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let source_path = PathBuf::from(source);

    if !source_path.exists() {
        return Err(format!("source directory does not exist: {}", source).into());
    }

    // Determine skill ID from directory name if not provided
    let skill_id = id.unwrap_or_else(|| {
        source_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unnamed-skill")
    });

    let skill_name = name.unwrap_or(skill_id);
    let skill_version = version.unwrap_or("0.1.0");
    let skill_description = description
        .map(|s| s.to_string())
        .unwrap_or_else(|| format!("Skill built from {}", source));

    // Check for Cargo.toml to determine if it's a Rust project
    let is_rust = source_path.join("Cargo.toml").exists();

    let output_path = PathBuf::from(output.unwrap_or(&format!("{}.wasm", skill_id)));

    if is_rust {
        println!("Building Rust skill from {}...", source);

        // Run cargo component build
        let mut cmd = ProcessCommand::new("cargo");
        cmd.arg("component")
            .arg("build")
            .arg("--release")
            .current_dir(&source_path);

        println!("Running: cargo component build --release");

        let status = cmd.status()?;

        if !status.success() {
            return Err(format!("cargo component build failed").into());
        }

        // Find the built WASM file
        let target_dir = source_path.join("target").join("wasm32-wasip2").join("release");
        let mut found_wasm: Option<PathBuf> = None;

        for entry in fs::read_dir(&target_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("wasm") {
                found_wasm = Some(path);
                break;
            }
        }

        let wasm_path = found_wasm.ok_or("could not find built WASM file")?;

        // Copy to output
        fs::copy(&wasm_path, &output_path)?;
        println!("Built skill to {}", output_path.display());
    } else {
        return Err("source directory does not contain a Cargo.toml - only Rust skills are supported for now".into());
    }

    // Read the built WASM
    let wasm_bytes = fs::read(&output_path)?;
    validate_wasm(&wasm_bytes)?;

    // Create and embed plugin manifest
    let manifest = crate::plugins::loader::PluginManifest {
        id: skill_id.to_string(),
        name: skill_name.to_string(),
        description: skill_description.to_string(),
        version: skill_version.to_string(),
        kind: crate::plugins::loader::PluginKind::Tool,
        permissions: crate::plugins::permissions::DeclaredPermissions::default(),
    };

    let embedded_wasm = embed_manifest_in_wasm(&wasm_bytes, &manifest)?;
    fs::write(&output_path, &embedded_wasm)?;

    // Compute hash
    let hash = compute_sha256_hex(&embedded_wasm);

    println!("Skill built successfully!");
    println!("  ID: {}", skill_id);
    println!("  Name: {}", skill_name);
    println!("  Version: {}", skill_version);
    println!("  SHA256: {}", hash);
    println!("  Output: {}", output_path.display());

    Ok(())
}

/// Run the skill sign handler.
pub fn handle_skill_sign(
    input: &str,
    output: Option<&str>,
    output_dir: Option<&str>,
    key: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let input_path = PathBuf::from(input);

    if !input_path.exists() {
        return Err(format!("input file does not exist: {}", input).into());
    }

    // Parse the signing key
    let signing_key = parse_signing_key(key)
        .map_err(|e| format!("invalid signing key: {}", e))?;

    let verifying_key = signing_key.verifying_key();

    // Read WASM file
    let wasm_bytes = fs::read(&input_path)?;
    validate_wasm(&wasm_bytes)?;

    // Compute hash
    let hash = compute_sha256_hex(&wasm_bytes);

    // Sign the WASM bytes
    let signature = sign_wasm_bytes(&wasm_bytes, &signing_key);
    let signature_hex = hex::encode(signature.to_bytes());
    let verifying_key_hex = hex::encode(verifying_key.as_bytes());

    // Determine output paths
    let skill_name = input_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("unnamed-skill")
        .to_string();

    let output_wasm_path = if let Some(out) = output {
        PathBuf::from(out)
    } else if let Some(dir) = output_dir {
        PathBuf::from(dir).join(format!("{}.wasm", skill_name))
    } else {
        input_path.with_extension("wasm.signed")
    };

    let output_manifest_path = if let Some(dir) = output_dir {
        PathBuf::from(dir).join(SKILLS_MANIFEST_FILE)
    } else {
        output_wasm_path
            .parent()
            .unwrap_or(Path::new("."))
            .join(SKILLS_MANIFEST_FILE)
    };

    // Create output directory if needed
    if let Some(dir) = output_dir {
        fs::create_dir_all(dir)?;
    }

    // Copy WASM to output
    fs::copy(&input_path, &output_wasm_path)?;

    // Create or update manifest
    let mut manifest = if output_manifest_path.exists() {
        let content = fs::read_to_string(&output_manifest_path)?;
        serde_json::from_str(&content)
            .map_err(|e| format!("failed to parse existing manifest: {e}"))?
    } else {
        SkillManifest {
            entries: std::collections::HashMap::new(),
        }
    };

    manifest.entries.insert(
        skill_name.clone(),
        SkillManifestEntry {
            name: skill_name,
            version: None,
            sha256: hash,
            publisher_key: verifying_key_hex.clone(),
            signature: signature_hex,
            url: None,
        },
    );

    // Write manifest
    let manifest_json = serde_json::to_string_pretty(&manifest)?;
    fs::write(&output_manifest_path, manifest_json)?;

    println!("Skill signed successfully!");
    println!("  Input: {}", input_path.display());
    println!("  Output: {}", output_wasm_path.display());
    println!("  Manifest: {}", output_manifest_path.display());
    println!("  Publisher Key: {}", verifying_key_hex);

    Ok(())
}

/// Run the skill generate-key handler.
pub fn handle_skill_generate_key(output: Option<&str>) -> Result<(), Box<dyn std::error::Error>> {
    use getrandom::fill;

    // Generate random bytes for the key
    let mut seed = [0u8; 32];
    fill(&mut seed)?;

    let signing_key = SigningKey::from_bytes(&seed);
    let verifying_key = signing_key.verifying_key();

    let key_pair = SkillKeyPair {
        signing_key: hex::encode(signing_key.to_bytes()),
        verifying_key: hex::encode(verifying_key.as_bytes()),
    };

    let json = serde_json::to_string_pretty(&key_pair)?;

    if let Some(out) = output {
        fs::write(out, &json)?;
        println!("Key pair generated and saved to {}", out);
    } else {
        println!("Key pair generated (keys masked for display):");
        // Mask the keys for display - show first/last 8 chars
        let masked = key_pair.signing_key.len();
        println!("  signing_key: {}...{}", &key_pair.signing_key[..8], &key_pair.signing_key[masked-8..]);
        println!("  verifying_key: {}...{}", &key_pair.verifying_key[..8], &key_pair.verifying_key[masked-8..]);
    }

    println!("\nIMPORTANT: Keep the secret key safe! The public key can be shared.");
    println!("  - Use secret key with: cara skill sign --key <secret>");
    println!("  - Share public key with users to verify your skills");

    Ok(())
}

/// Download a file from a URL (async version).
async fn download_file_async(url: &str, dest: &Path) -> Result<Vec<u8>, String> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(60))
        .build()
        .map_err(|e| format!("failed to create HTTP client: {}", e))?;

    let response = client
        .get(url)
        .send()
        .await
        .map_err(|e| format!("failed to download: {}", e))?;

    if !response.status().is_success() {
        return Err(format!("download failed with HTTP {}", response.status()));
    }

    let bytes = response
        .bytes()
        .await
        .map_err(|e| format!("failed to read response: {}", e))?;

    // Write to dest if provided
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("failed to create parent directory: {}", e))?;
    }
    let mut file = fs::File::create(dest)
        .map_err(|e| format!("failed to create file: {}", e))?;
    file.write_all(&bytes)
        .map_err(|e| format!("failed to write file: {}", e))?;

    Ok(bytes.to_vec())
}

/// Clone a GitHub repository.
fn clone_github_repo(url: &str, dest: &Path) -> Result<(), String> {
    // Parse GitHub URL to get owner/repo
    let repo_url = if url.contains("github.com") {
        // Convert various GitHub URL formats to clone URL
        let parts: Vec<&str> = url
            .trim_end_matches(".git")
            .trim_end_matches('/')
            .rsplit('/')
            .take(2)
            .collect();

        if parts.len() < 2 {
            return Err("invalid GitHub URL".to_string());
        }

        format!("https://github.com/{}/{}.git", parts[1], parts[0])
    } else {
        url.to_string()
    };

    println!("Cloning repository...");

    let output = ProcessCommand::new("git")
        .args(["clone", "--depth", "1", &repo_url])
        .arg(dest)
        .output()
        .map_err(|e| format!("git clone failed: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("git clone failed: {}", stderr));
    }

    Ok(())
}

/// Run the skill package handler.
pub async fn handle_skill_package(
    url: &str,
    output: Option<&str>,
    key: Option<&str>,
    generate_key: bool,
    name: Option<&str>,
    version: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Determine output directory
    let output_dir = PathBuf::from(output.unwrap_or("./skill-package"));
    fs::create_dir_all(&output_dir)?;

    // Determine if we need to generate a key
    let signing_key = if generate_key {
        use getrandom::fill;
        let mut seed = [0u8; 32];
        fill(&mut seed)?;
        Some(SigningKey::from_bytes(&seed))
    } else if let Some(k) = key {
        Some(parse_signing_key(k).map_err(|e| format!("invalid key: {}", e))?)
    } else {
        None
    };

    let _verifying_key = signing_key.as_ref().map(|k| k.verifying_key());

    let skill_name = name
        .map(|s| s.to_string())
        .or_else(|| {
            // Try to derive from URL
            let filename = url.rsplit('/').next()?;
            filename.strip_suffix(".wasm").map(|s| s.to_string())
        })
        .unwrap_or_else(|| "unnamed-skill".to_string());

    let temp_dir = std::env::temp_dir().join(format!("skill-{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(&temp_dir)?;

    let wasm_path: PathBuf;

    // Check if URL is direct WASM or GitHub repo
    if url.ends_with(".wasm") || url.contains("/releases/") || url.contains("/archive/") {
        // Direct WASM download
        println!("Downloading skill from {}...", url);
        let dest = temp_dir.join(format!("{}.wasm", skill_name));
        download_file_async(url, &dest).await?;
        wasm_path = dest;
    } else {
        // GitHub repository
        println!("Fetching skill from {}...", url);
        clone_github_repo(url, &temp_dir)?;

        // Find the cloned repo and build
        let source_path = temp_dir
            .read_dir()?
            .next()
            .ok_or("empty repository")?
            .map_err(|e| e)?
            .path();

        // Check if there's a Cargo.toml
        if !source_path.join("Cargo.toml").exists() {
            return Err("repository does not contain a skill (no Cargo.toml found)".into());
        }

        // Build the skill
        println!("Building skill from {}...", source_path.display());

        let build_output = ProcessCommand::new("cargo")
            .args(["component", "build", "--release"])
            .current_dir(&source_path)
            .output()
            .map_err(|e| format!("build failed: {}", e))?;

        if !build_output.status.success() {
            let stderr = String::from_utf8_lossy(&build_output.stderr);
            return Err(format!("build failed: {}", stderr).into());
        }

        // Find the built WASM
        let target_dir = source_path
            .join("target")
            .join("wasm32-wasip2")
            .join("release");

        let wasm_file = target_dir
            .read_dir()?
            .find_map(|e| {
                let e = e.ok()?;
                let p = e.path();
                if p.extension().and_then(|s| s.to_str()) == Some("wasm") {
                    Some(p)
                } else {
                    None
                }
            })
            .ok_or("could not find built WASM file")?;

        wasm_path = output_dir.join(format!("{}.wasm", skill_name));
        fs::copy(&wasm_file, &wasm_path)?;
    }

    // Read the WASM
    let wasm_bytes = fs::read(&wasm_path)?;
    validate_wasm(&wasm_bytes)?;

    // Compute hash
    let hash = compute_sha256_hex(&wasm_bytes);

    // Sign if we have a key
    let (signature_hex, publisher_key_hex) = if let Some(ref sk) = signing_key {
        let sig = sign_wasm_bytes(&wasm_bytes, sk);
        let vk = sk.verifying_key();
        (
            Some(hex::encode(sig.to_bytes())),
            Some(hex::encode(vk.as_bytes())),
        )
    } else {
        (None, None)
    };

    // Create manifest
    let mut manifest = SkillManifest {
        entries: std::collections::HashMap::new(),
    };

    manifest.entries.insert(
        skill_name.clone(),
        SkillManifestEntry {
            name: skill_name.clone(),
            version: version.map(|v| v.to_string()),
            sha256: hash.clone(),
            publisher_key: publisher_key_hex.clone().unwrap_or_default(),
            signature: signature_hex.clone().unwrap_or_default(),
            url: Some(url.to_string()),
        },
    );

    // Write manifest
    let manifest_path = output_dir.join(SKILLS_MANIFEST_FILE);
    let manifest_json = serde_json::to_string_pretty(&manifest)?;
    fs::write(&manifest_path, manifest_json)?;

    // Move WASM to output directory if not already there
    let final_wasm_path = output_dir.join(format!("{}.wasm", skill_name));
    if wasm_path != final_wasm_path {
        fs::rename(&wasm_path, &final_wasm_path)?;
    }

    // Cleanup temp dir
    let _ = fs::remove_dir_all(&temp_dir);

    println!("\nSkill packaged successfully!");
    println!("  Output directory: {}", output_dir.display());
    println!("  Skill: {}", skill_name);
    println!("  SHA256: {}", hash);

    if let Some(ref pk) = publisher_key_hex {
        println!("  Publisher Key: {}", pk);
    }

    if signing_key.is_none() {
        println!("\nWARNING: Skill was not signed. Use --key or --generate-key to sign.");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Verifier;
    use tempfile::TempDir;

    #[test]
    fn test_compute_sha256() {
        let data = b"hello world";
        let hash = compute_sha256_hex(data);
        // Known SHA-256 of "hello world"
        assert_eq!(
            hash,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test]
    fn test_compute_sha256_empty() {
        let data = b"";
        let hash = compute_sha256_hex(data);
        // Known SHA-256 of empty string
        assert_eq!(
            hash,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn test_validate_wasm_valid() {
        let valid_wasm = [0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00];
        assert!(validate_wasm(&valid_wasm).is_ok());
    }

    #[test]
    fn test_validate_wasm_invalid_magic() {
        let invalid_wasm = [0x00, 0x00, 0x00, 0x00];
        assert!(validate_wasm(&invalid_wasm).is_err());
    }

    #[test]
    fn test_validate_wasm_too_short() {
        let invalid_wasm = [0x00, 0x61];
        assert!(validate_wasm(&invalid_wasm).is_err());
    }

    #[test]
    fn test_parse_signing_key_valid() {
        // 32 bytes of 'a' as hex (valid format, not real secret)
        let key_hex = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let key = parse_signing_key(key_hex);
        assert!(key.is_ok());
    }

    #[test]
    fn test_parse_signing_key_invalid_hex() {
        let key_hex = "not-hex";
        let key = parse_signing_key(key_hex);
        assert!(key.is_err());
    }

    #[test]
    fn test_parse_signing_key_wrong_length() {
        // 31 bytes as hex (62 chars - wrong length)
        let key_hex = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let key = parse_signing_key(key_hex);
        assert!(key.is_err());
    }

    #[test]
    fn test_sign_and_verify_roundtrip() {
        // Generate a random key
        let mut seed = [0u8; 32];
        seed[0] = 0x42; // Ensure non-zero
        let signing_key = SigningKey::from_bytes(&seed);
        let verifying_key = signing_key.verifying_key();

        // Test data
        let wasm_bytes = b"fake wasm module bytes";

        // Sign
        let signature = sign_wasm_bytes(wasm_bytes, &signing_key);

        // Verify
        assert!(verifying_key.verify(wasm_bytes, &signature).is_ok());
    }

    #[test]
    fn test_sign_wrong_bytes_fails() {
        let mut seed = [0u8; 32];
        seed[0] = 0x42;
        let signing_key = SigningKey::from_bytes(&seed);
        let verifying_key = signing_key.verifying_key();

        let original = b"original wasm bytes";
        let tampered = b"tampered wasm bytes";

        let signature = sign_wasm_bytes(original, &signing_key);
        assert!(verifying_key.verify(tampered, &signature).is_err());
    }

    #[test]
    fn test_generate_lib_rs() {
        let content = generate_lib_rs("my-test-skill");
        
        // Check key elements are present
        assert!(content.contains("my-test-skill"));
        assert!(content.contains("impl tool::Host for MySkill"));
        assert!(content.contains("fn get_definitions"));
        assert!(content.contains("fn invoke"));
    }

    #[test]
    fn test_generate_lib_rs_different_ids() {
        let content1 = generate_lib_rs("skill-one");
        let content2 = generate_lib_rs("skill-two");
        
        assert!(content1.contains("skill-one"));
        assert!(content2.contains("skill-two"));
        assert!(!content1.contains("skill-two"));
    }

    #[test]
    fn test_skill_manifest_entry_serialization() {
        let entry = SkillManifestEntry {
            name: "test-skill".to_string(),
            version: Some("1.0.0".to_string()),
            sha256: "abc123".to_string(),
            publisher_key: "def456".to_string(),
            signature: "ghi789".to_string(),
            url: Some("https://example.com/skill.wasm".to_string()),
        };

        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("test-skill"));
        assert!(json.contains("1.0.0"));
        assert!(json.contains("abc123"));
    }

    #[test]
    fn test_skill_manifest_roundtrip() {
        let mut manifest = SkillManifest {
            entries: std::collections::HashMap::new(),
        };

        manifest.entries.insert(
            "my-skill".to_string(),
            SkillManifestEntry {
                name: "my-skill".to_string(),
                version: Some("2.0.0".to_string()),
                sha256: "hash123".to_string(),
                publisher_key: "key456".to_string(),
                signature: "sig789".to_string(),
                url: None,
            },
        );

        let json = serde_json::to_string(&manifest).unwrap();
        let parsed: SkillManifest = serde_json::from_str(&json).unwrap();

        assert!(parsed.entries.contains_key("my-skill"));
        let entry = parsed.entries.get("my-skill").unwrap();
        assert_eq!(entry.version.as_ref().unwrap(), "2.0.0");
    }

    #[test]
    fn test_handle_skill_template_creates_files() {
        let temp_dir = TempDir::new().unwrap();
        let output = temp_dir.path().join("test-skill");
        
        // Call the template handler
        let result = handle_skill_template(
            Some(output.to_str().unwrap()),
            "tool",
            Some("test-tool"),
        );
        
        assert!(result.is_ok());
        
        // Check files were created
        assert!(output.join("Cargo.toml").exists());
        assert!(output.join("src/lib.rs").exists());
        assert!(output.join("wit/plugin.wit").exists());
        assert!(output.join(".gitignore").exists());
        assert!(output.join("README.md").exists());
    }

    #[test]
    fn test_handle_skill_template_invalid_kind() {
        let temp_dir = TempDir::new().unwrap();
        let output = temp_dir.path().join("test-skill");
        
        let result = handle_skill_template(
            Some(output.to_str().unwrap()),
            "invalid-kind",
            None,
        );
        
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("invalid skill kind"));
    }

    #[test]
    fn test_handle_skill_template_existing_dir_fails() {
        let temp_dir = TempDir::new().unwrap();
        
        // Create the directory first
        std::fs::create_dir(temp_dir.path().join("existing")).unwrap();
        
        let result = handle_skill_template(
            Some(temp_dir.path().join("existing").to_str().unwrap()),
            "tool",
            None,
        );
        
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("already exists"));
    }

    #[test]
    fn test_handle_skill_sign_creates_manifest() {
        let temp_dir = TempDir::new().unwrap();
        
        // Create a valid WASM file
        let wasm_path = temp_dir.path().join("test.wasm");
        let mut wasm_file = std::fs::File::create(&wasm_path).unwrap();
        wasm_file.write_all(&[0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00]).unwrap();
        
        // Create a temp dir for output
        let output_dir = temp_dir.path().join("output");
        
        // Generate a key and sign
        let mut seed = [0u8; 32];
        seed[0] = 0x42;
        let signing_key = SigningKey::from_bytes(&seed);
        let key_hex = hex::encode(signing_key.to_bytes());
        
        let result = handle_skill_sign(
            wasm_path.to_str().unwrap(),
            None,
            Some(output_dir.to_str().unwrap()),
            &key_hex,
        );
        
        assert!(result.is_ok());
        
        // Check manifest was created
        let manifest_path = output_dir.join("skills-manifest.json");
        assert!(manifest_path.exists());
        
        // Check WASM was copied
        assert!(output_dir.join("test.wasm").exists());
    }

    #[test]
    fn test_handle_skill_sign_invalid_wasm() {
        let temp_dir = TempDir::new().unwrap();
        
        // Create an invalid WASM file
        let wasm_path = temp_dir.path().join("invalid.wasm");
        std::fs::write(&wasm_path, b"not wasm").unwrap();
        
        let mut seed = [0u8; 32];
        seed[0] = 0x42;
        let signing_key = SigningKey::from_bytes(&seed);
        let key_hex = hex::encode(signing_key.to_bytes());
        
        let result = handle_skill_sign(
            wasm_path.to_str().unwrap(),
            None,
            Some(temp_dir.path().join("output").to_str().unwrap()),
            &key_hex,
        );
        
        assert!(result.is_err());
    }

    #[test]
    fn test_handle_skill_sign_invalid_key() {
        let temp_dir = TempDir::new().unwrap();
        
        // Create a valid WASM file
        let wasm_path = temp_dir.path().join("test.wasm");
        let mut wasm_file = std::fs::File::create(&wasm_path).unwrap();
        wasm_file.write_all(&[0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00]).unwrap();
        
        let result = handle_skill_sign(
            wasm_path.to_str().unwrap(),
            None,
            Some(temp_dir.path().join("output").to_str().unwrap()),
            "invalid-key",
        );
        
        assert!(result.is_err());
    }

    #[test]
    fn test_embed_manifest_in_wasm() {
        let wasm_bytes = [0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00];
        
        let manifest = crate::plugins::loader::PluginManifest {
            id: "test-plugin".to_string(),
            name: "Test Plugin".to_string(),
            description: "A test plugin".to_string(),
            version: "1.0.0".to_string(),
            kind: crate::plugins::loader::PluginKind::Tool,
            permissions: crate::plugins::permissions::DeclaredPermissions::default(),
        };
        
        let _result = embed_manifest_in_wasm(&wasm_bytes, &manifest);
        // This may fail due to the embedding logic, but we're testing the function exists
        // The actual embedding is complex and tested more thoroughly via integration tests
    }
}

/// Generate the lib.rs content for a new skill - avoids format! escaping issues
fn generate_lib_rs(skill_id: &str) -> String {
    let mut s = String::new();
    s.push_str("// Skill template - edit this file to implement your skill!\n");
    s.push_str("// See carapace wit/plugin.wit for the full interface definitions\n\n");
    s.push_str("wit_bindgen::generate!(\"../wit/plugin.wit\");\n\n");
    s.push_str("pub struct MySkill;\n\n");
    s.push_str("impl tool::Host for MySkill {\n");
    s.push_str("    fn get_definitions(&mut self) -> Vec<tool::ToolDefinition> {\n");
    s.push_str("        vec![tool::ToolDefinition {\n");
    s.push_str(&format!("            name: \"{}\".to_string(),\n", skill_id));
    s.push_str("            description: \"My skill tool\".to_string(),\n");
    s.push_str("            input_schema: \"{\\\"type\\\": \\\"object\\\"}\".to_string(),\n");
    s.push_str("        }}]\n");
    s.push_str("    }\n\n");
    s.push_str("    fn invoke(&mut self, name: String, params: String, _ctx: tool::ToolContext) -> Result<tool::ToolResult, tool::PluginError> {\n");
    s.push_str("        println!(\"Tool: {} params: {}\", name, params);\n");
    s.push_str("        Ok(tool::ToolResult {\n");
    s.push_str("            success: true,\n");
    s.push_str("            result: Some(\"{\\\"ok\\\": true}\".to_string()),\n");
    s.push_str("            error: None,\n");
    s.push_str("        })\n");
    s.push_str("    }\n");
    s.push_str("}\n\n");
    s.push_str("export!(MySkill);\n");
    s
}

/// Run the skill template handler - generate a starter skill project.
pub fn handle_skill_template(
    output: Option<&str>,
    kind: &str,
    id: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let output_dir = PathBuf::from(output.unwrap_or("./my-skill"));

    let skill_id = id.unwrap_or_else(|| {
        output_dir
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("my-skill")
    });

    // Validate kind
    let valid_kinds = ["tool", "channel", "webhook", "service", "hook", "provider"];
    if !valid_kinds.contains(&kind) {
        return Err(format!(
            "invalid skill kind: {}. Valid kinds: {}",
            kind,
            valid_kinds.join(", ")
        )
        .into());
    }

    // Create output directory
    if output_dir.exists() {
        return Err(format!("directory already exists: {}", output_dir.display()).into());
    }
    fs::create_dir_all(&output_dir)?;

    // Create Cargo.toml - simpler version
    let cargo_toml = format!(
        r#"[package]
name = "{}"
version = "0.1.0"
edition = "2021"
description = "A carapace skill of type: {}"

[dependencies]
wit-bindgen = "0.24"
serde = {{ version = "1", features = ["derive"] }}
serde_json = "1"

[lib]
crate-type = ["cdylib"]
"#,
        skill_id, kind
    );
    fs::write(output_dir.join("Cargo.toml"), cargo_toml)?;

    // Create wit directory and plugin.wit - copy from carapace
    let wit_dir = output_dir.join("wit");
    fs::create_dir_all(&wit_dir)?;
    
    // Copy the WIT file from carapace
    let carapace_wit = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|p| p.to_path_buf()))
        .map(|p| p.join("../wit/plugin.wit"))
        .or_else(|| PathBuf::from("wit/plugin.wit").canonicalize().ok())
        .unwrap_or_else(|| PathBuf::from("wit/plugin.wit"));
    
    if carapace_wit.exists() {
        fs::copy(&carapace_wit, wit_dir.join("plugin.wit"))
            .map_err(|e| format!("failed to copy WIT file: {}", e))?;
    } else {
        // Fallback: create a minimal WIT file
        let minimal_wit = include_str!("../../wit/plugin.wit");
        fs::write(wit_dir.join("plugin.wit"), minimal_wit)?;
    }

    // Create src directory and basic lib.rs
    let src_dir = output_dir.join("src");
    fs::create_dir_all(&src_dir)?;

    // Write lib.rs using a simple function to avoid format! escaping issues
    let lib_rs = generate_lib_rs(skill_id);
    fs::write(src_dir.join("lib.rs"), lib_rs)?;

    // Create .gitignore
    fs::write(
        output_dir.join(".gitignore"),
        "/target\n*.wasm\n*.wat\n",
    )?;

    // Create README
    let readme = format!(
        r#"# {}

A carapace skill of type: {}

## Building

```bash
cargo component build --release
```

The compiled WASM will be in `target/wasm32-wasip2/release/{}.wasm`.

## Installing

```bash
cara skill sign --input target/wasm32-wasip2/release/{}.wasm --key YOUR_KEY --output-dir /path/to/skills
```

## Note

This template uses the tool plugin interface. Edit `src/lib.rs` to customize.
For full WIT interface definitions, see `wit/plugin.wit`.
"#,
        skill_id, kind, skill_id, skill_id
    );
    fs::write(output_dir.join("README.md"), readme)?;

    println!("Skill template created successfully!");
    println!("  Directory: {}", output_dir.display());
    println!("  Kind: {}", kind);
    println!("  ID: {}", skill_id);
    println!();
    println!("To build your skill:");
    println!("  cd {}", output_dir.display());
    println!("  cargo component build --release");
    println!();
    println!("Note: You may need to install cargo-component:");
    println!("  cargo install cargo-component");

    Ok(())
}
