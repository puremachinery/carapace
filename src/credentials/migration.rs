use super::{CredentialBackend, CredentialError, CredentialKey, CredentialStore};
use crate::config::secrets::SecretStore;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const MIGRATION_STATE_VERSION: u32 = 1;
const PROFILE_METADATA_KEYS: &[&str] = &[
    "id",
    "profileId",
    "name",
    "provider",
    "type",
    "order",
    "lastGood",
    "usageStats",
];
const SAFE_TOP_LEVEL_KEYS: &[&str] = &[
    "order",
    "lastGood",
    "usageStats",
    "version",
    "updatedAt",
    "createdAt",
];

type ProfileEntry = (String, Value, Option<String>);

struct ExtractedProfiles {
    entries: Vec<ProfileEntry>,
    sanitized: Value,
    unmigratable: bool,
}

#[derive(Debug, Default)]
pub struct MigrationReport {
    pub migrated: usize,
    pub matched: usize,
    pub conflicts: usize,
    pub cleaned_files: usize,
    pub skipped: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct MigrationState {
    version: u32,
    #[serde(rename = "startedAt")]
    started_at: u64,
    #[serde(default)]
    completed: Vec<String>,
}

impl MigrationState {
    fn new() -> Self {
        Self {
            version: MIGRATION_STATE_VERSION,
            started_at: now_ts(),
            completed: Vec::new(),
        }
    }
}

#[derive(Debug, Default)]
struct FileOutcome {
    touched: bool,
    cleaned: bool,
}

impl FileOutcome {
    fn remaining(&self) -> bool {
        self.touched && !self.cleaned
    }
}

#[derive(Debug)]
struct WhatsappFile {
    path: PathBuf,
    name: String,
}

#[derive(Debug)]
struct WhatsappAccount {
    account_id: String,
    files: Vec<WhatsappFile>,
}

#[derive(Debug, Default)]
struct LegacyScan {
    oauth_path: Option<PathBuf>,
    copilot_path: Option<PathBuf>,
    auth_profiles: Vec<(String, PathBuf)>,
    auth_legacy: Vec<(String, PathBuf)>,
    pairing: Vec<(String, PathBuf)>,
    allow_from: Vec<(String, PathBuf)>,
    whatsapp_accounts: Vec<WhatsappAccount>,
}

impl LegacyScan {
    fn has_any(&self) -> bool {
        self.oauth_path.is_some()
            || self.copilot_path.is_some()
            || !self.auth_profiles.is_empty()
            || !self.auth_legacy.is_empty()
            || !self.pairing.is_empty()
            || !self.allow_from.is_empty()
            || !self.whatsapp_accounts.is_empty()
    }
}

#[derive(Debug, PartialEq, Eq)]
enum EnsureResult {
    Stored,
    Matched,
    Conflict,
}

fn now_ts() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn migration_state_path(state_dir: &Path) -> PathBuf {
    state_dir.join("credentials").join("migration.state")
}

fn resolve_legacy_credentials_dir(state_dir: &Path) -> PathBuf {
    std::env::var("CARAPACE_OAUTH_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| state_dir.join("credentials"))
}

fn resolve_agent_ids(state_dir: &Path) -> Vec<String> {
    let mut ids = Vec::new();
    let agents_dir = state_dir.join("agents");
    if let Ok(entries) = fs::read_dir(&agents_dir) {
        for entry in entries.flatten() {
            if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                if let Some(name) = entry.file_name().to_str() {
                    ids.push(name.to_string());
                }
            }
        }
    }
    if ids.is_empty() {
        ids.push("main".to_string());
    }
    ids.sort();
    ids
}

fn load_migration_state(path: &Path) -> Result<Option<MigrationState>, CredentialError> {
    if !path.exists() {
        return Ok(None);
    }

    let content = fs::read_to_string(path).map_err(|e| CredentialError::IoError(e.to_string()))?;
    match serde_json::from_str::<MigrationState>(&content) {
        Ok(state) => {
            if state.version != MIGRATION_STATE_VERSION {
                tracing::warn!(
                    found = state.version,
                    expected = MIGRATION_STATE_VERSION,
                    "Migration state version mismatch; resetting"
                );
                return Ok(None);
            }
            Ok(Some(state))
        }
        Err(err) => {
            tracing::warn!(error = %err, "Failed to parse migration state; resetting");
            let timestamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_millis())
                .unwrap_or(0);
            let corrupt_path =
                path.with_file_name(format!("migration.state.corrupt.{}", timestamp));
            if let Err(err) = fs::rename(path, &corrupt_path) {
                tracing::warn!(error = %err, "Failed to move corrupt migration state");
            }
            Ok(None)
        }
    }
}

fn write_json_atomic<T: Serialize>(path: &Path, value: &T) -> Result<(), CredentialError> {
    let content = serde_json::to_string_pretty(value)
        .map_err(|e| CredentialError::JsonError(e.to_string()))?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| CredentialError::IoError(e.to_string()))?;
    }
    let temp_path = path.with_extension("tmp");
    let mut file = File::create(&temp_path).map_err(|e| CredentialError::IoError(e.to_string()))?;
    file.write_all(content.as_bytes())
        .map_err(|e| CredentialError::IoError(e.to_string()))?;
    file.sync_all()
        .map_err(|e| CredentialError::IoError(e.to_string()))?;
    fs::rename(&temp_path, path).map_err(|e| CredentialError::IoError(e.to_string()))?;
    Ok(())
}

fn write_string_atomic(path: &Path, value: &str) -> Result<(), CredentialError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| CredentialError::IoError(e.to_string()))?;
    }
    let temp_path = path.with_extension("tmp");
    let mut file = File::create(&temp_path).map_err(|e| CredentialError::IoError(e.to_string()))?;
    file.write_all(value.as_bytes())
        .map_err(|e| CredentialError::IoError(e.to_string()))?;
    file.sync_all()
        .map_err(|e| CredentialError::IoError(e.to_string()))?;
    fs::rename(&temp_path, path).map_err(|e| CredentialError::IoError(e.to_string()))?;
    Ok(())
}

fn write_migration_state(path: &Path, state: &MigrationState) -> Result<(), CredentialError> {
    write_json_atomic(path, state)
}

fn scan_legacy(
    state_dir: &Path,
    legacy_credentials_dir: &Path,
    agent_ids: &[String],
) -> LegacyScan {
    let mut scan = LegacyScan::default();

    let oauth_path = legacy_credentials_dir.join("oauth.json");
    if oauth_path.exists() {
        scan.oauth_path = Some(oauth_path);
    }

    let copilot_path = legacy_credentials_dir.join("github-copilot.token.json");
    if copilot_path.exists() {
        scan.copilot_path = Some(copilot_path);
    }

    for agent_id in agent_ids {
        let agent_dir = state_dir.join("agents").join(agent_id).join("agent");
        let auth_profiles = agent_dir.join("auth-profiles.json");
        if auth_profiles.exists() {
            scan.auth_profiles
                .push((agent_id.to_string(), auth_profiles));
        }
        let auth_legacy = agent_dir.join("auth.json");
        if auth_legacy.exists() {
            scan.auth_legacy.push((agent_id.to_string(), auth_legacy));
        }
    }

    if let Ok(entries) = fs::read_dir(legacy_credentials_dir) {
        for entry in entries.flatten() {
            if entry.file_type().map(|t| t.is_file()).unwrap_or(false) {
                if let Some(name) = entry.file_name().to_str() {
                    if let Some(channel) = name.strip_suffix("-pairing.json") {
                        if !channel.is_empty() {
                            scan.pairing.push((channel.to_string(), entry.path()));
                        }
                    } else if let Some(channel) = name.strip_suffix("-allowFrom.json") {
                        if !channel.is_empty() {
                            scan.allow_from.push((channel.to_string(), entry.path()));
                        }
                    }
                }
            }
        }
    }

    let mut whatsapp_accounts: HashMap<String, Vec<WhatsappFile>> = HashMap::new();
    let whatsapp_root = legacy_credentials_dir.join("whatsapp");
    if whatsapp_root.is_dir() {
        if let Ok(accounts) = fs::read_dir(&whatsapp_root) {
            for account_entry in accounts.flatten() {
                if !account_entry
                    .file_type()
                    .map(|t| t.is_dir())
                    .unwrap_or(false)
                {
                    continue;
                }
                let account_id = match account_entry.file_name().to_str() {
                    Some(name) => name.to_string(),
                    None => continue,
                };
                let account_path = account_entry.path();
                let mut files = Vec::new();
                if let Ok(entries) = fs::read_dir(&account_path) {
                    for entry in entries.flatten() {
                        if !entry.file_type().map(|t| t.is_file()).unwrap_or(false) {
                            continue;
                        }
                        let file_name = match entry.file_name().to_str() {
                            Some(name) => name.to_string(),
                            None => continue,
                        };
                        if file_name == "session.enc" {
                            continue;
                        }
                        files.push(WhatsappFile {
                            path: entry.path(),
                            name: file_name,
                        });
                    }
                }
                if !files.is_empty() {
                    whatsapp_accounts.insert(account_id, files);
                }
            }
        }
    }

    let legacy_root_creds = legacy_credentials_dir.join("creds.json");
    if legacy_root_creds.is_file() {
        whatsapp_accounts
            .entry("default".to_string())
            .or_default()
            .push(WhatsappFile {
                path: legacy_root_creds,
                name: "legacy/creds.json".to_string(),
            });
    }

    let mut whatsapp_accounts_vec = whatsapp_accounts
        .into_iter()
        .map(|(account_id, files)| WhatsappAccount { account_id, files })
        .collect::<Vec<_>>();
    whatsapp_accounts_vec.sort_by(|a, b| a.account_id.cmp(&b.account_id));
    scan.whatsapp_accounts = whatsapp_accounts_vec;

    scan
}

fn values_match(existing: &str, legacy: &str) -> bool {
    match (
        serde_json::from_str::<Value>(existing),
        serde_json::from_str::<Value>(legacy),
    ) {
        (Ok(a), Ok(b)) => values_match_json(&a, &b),
        _ => existing == legacy,
    }
}

fn values_match_json(existing: &Value, legacy: &Value) -> bool {
    if existing == legacy {
        return true;
    }
    let (Some(existing_obj), Some(legacy_obj)) = (existing.as_object(), legacy.as_object()) else {
        return false;
    };

    let existing_provider = existing_obj.get("provider").and_then(|v| v.as_str());
    let legacy_provider = legacy_obj.get("provider").and_then(|v| v.as_str());
    if let (Some(a), Some(b)) = (existing_provider, legacy_provider) {
        if a != b {
            return false;
        }
    }

    let mut existing_sans = existing_obj.clone();
    let mut legacy_sans = legacy_obj.clone();
    existing_sans.remove("provider");
    legacy_sans.remove("provider");
    Value::Object(existing_sans) == Value::Object(legacy_sans)
}

fn sanitize_profile(profile: &Map<String, Value>, fallback_id: Option<&str>) -> Map<String, Value> {
    let mut sanitized = Map::new();
    for key in PROFILE_METADATA_KEYS {
        if let Some(value) = profile.get(*key) {
            sanitized.insert((*key).to_string(), value.clone());
        }
    }
    if sanitized.get("id").is_none() {
        if let Some(fallback) = fallback_id {
            sanitized.insert("id".to_string(), Value::String(fallback.to_string()));
        }
    }
    sanitized
}

fn profile_has_secrets(profile: &Map<String, Value>) -> bool {
    profile
        .keys()
        .any(|key| !PROFILE_METADATA_KEYS.contains(&key.as_str()))
}

fn extract_profile_id(profile: &Map<String, Value>, fallback_id: Option<&str>) -> Option<String> {
    for key in ["id", "profileId", "name"] {
        if let Some(Value::String(value)) = profile.get(key) {
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
    }
    if let Some(fallback) = fallback_id {
        if !fallback.is_empty() {
            return Some(fallback.to_string());
        }
    }
    if let Some(Value::String(provider)) = profile.get("provider") {
        if !provider.is_empty() {
            return Some(format!("{}:default", provider));
        }
    }
    None
}

fn extract_profiles(value: &Value) -> ExtractedProfiles {
    let mut entries = Vec::new();
    let mut unmigratable = false;

    match value {
        Value::Array(items) => {
            let mut sanitized_items = Vec::new();
            for item in items {
                if let Value::Object(profile) = item {
                    let fallback_id = None;
                    if profile_has_secrets(profile) {
                        if let Some(profile_id) = extract_profile_id(profile, fallback_id) {
                            let provider = profile
                                .get("provider")
                                .and_then(|v| v.as_str())
                                .map(|s| s.to_string());
                            entries.push((profile_id, Value::Object(profile.clone()), provider));
                        } else {
                            unmigratable = true;
                        }
                    }
                    sanitized_items.push(Value::Object(sanitize_profile(profile, fallback_id)));
                }
            }
            ExtractedProfiles {
                entries,
                sanitized: Value::Array(sanitized_items),
                unmigratable,
            }
        }
        Value::Object(map) => {
            if let Some(Value::Array(profiles)) = map.get("profiles") {
                let mut sanitized_profiles = Vec::new();
                for profile in profiles {
                    if let Value::Object(profile_map) = profile {
                        let fallback_id = None;
                        if profile_has_secrets(profile_map) {
                            if let Some(profile_id) = extract_profile_id(profile_map, fallback_id) {
                                let provider = profile_map
                                    .get("provider")
                                    .and_then(|v| v.as_str())
                                    .map(|s| s.to_string());
                                entries.push((
                                    profile_id,
                                    Value::Object(profile_map.clone()),
                                    provider,
                                ));
                            } else {
                                unmigratable = true;
                            }
                        }
                        sanitized_profiles
                            .push(Value::Object(sanitize_profile(profile_map, fallback_id)));
                    }
                }
                let mut sanitized_obj = Map::new();
                sanitized_obj.insert("profiles".to_string(), Value::Array(sanitized_profiles));
                for key in SAFE_TOP_LEVEL_KEYS {
                    if let Some(value) = map.get(*key) {
                        sanitized_obj.insert((*key).to_string(), value.clone());
                    }
                }
                ExtractedProfiles {
                    entries,
                    sanitized: Value::Object(sanitized_obj),
                    unmigratable,
                }
            } else {
                let mut sanitized_obj = Map::new();
                for (profile_id, profile_value) in map.iter() {
                    if let Value::Object(profile_map) = profile_value {
                        let fallback_id = Some(profile_id.as_str());
                        if profile_has_secrets(profile_map) {
                            if let Some(profile_id) = extract_profile_id(profile_map, fallback_id) {
                                let provider = profile_map
                                    .get("provider")
                                    .and_then(|v| v.as_str())
                                    .map(|s| s.to_string());
                                entries.push((
                                    profile_id,
                                    Value::Object(profile_map.clone()),
                                    provider,
                                ));
                            } else {
                                unmigratable = true;
                            }
                        }
                        sanitized_obj.insert(
                            profile_id.to_string(),
                            Value::Object(sanitize_profile(profile_map, fallback_id)),
                        );
                    }
                }
                ExtractedProfiles {
                    entries,
                    sanitized: Value::Object(sanitized_obj),
                    unmigratable,
                }
            }
        }
        _ => ExtractedProfiles {
            entries,
            sanitized: Value::Null,
            unmigratable,
        },
    }
}

async fn ensure_credential<B: CredentialBackend>(
    store: &CredentialStore<B>,
    key: &CredentialKey,
    value: &Value,
    provider: Option<String>,
    report: &mut MigrationReport,
) -> Result<EnsureResult, CredentialError> {
    let value_str =
        serde_json::to_string(value).map_err(|e| CredentialError::JsonError(e.to_string()))?;

    let existing = store.get(key).await?;
    if let Some(existing_value) = existing {
        if values_match(&existing_value, &value_str) {
            if let Err(err) = store.record_index_entry(key, provider).await {
                tracing::warn!(
                    key = %key,
                    error = %err,
                    "Failed to update credential index during migration"
                );
            }
            report.matched += 1;
            return Ok(EnsureResult::Matched);
        }
        tracing::warn!(key = %key, "Existing credential does not match legacy value; skipping");
        report.conflicts += 1;
        return Ok(EnsureResult::Conflict);
    }

    match store.set(key, &value_str, provider).await {
        Ok(()) => {
            report.migrated += 1;
            Ok(EnsureResult::Stored)
        }
        Err(CredentialError::KeyTooLong | CredentialError::ValueTooLong) => {
            tracing::warn!(
                key = %key,
                "Legacy credential key/value exceeds limits; skipping migration"
            );
            report.conflicts += 1;
            Ok(EnsureResult::Conflict)
        }
        Err(err) => Err(err),
    }
}

async fn migrate_oauth_file<B: CredentialBackend>(
    store: &CredentialStore<B>,
    path: &Path,
    agent_ids: &[String],
    completed: &mut HashSet<String>,
    report: &mut MigrationReport,
) -> Result<FileOutcome, CredentialError> {
    let mut outcome = FileOutcome {
        touched: false,
        cleaned: false,
    };
    if !path.exists() {
        return Ok(outcome);
    }
    outcome.touched = true;

    let content = fs::read_to_string(path).map_err(|e| CredentialError::IoError(e.to_string()))?;
    let value: Value = match serde_json::from_str(&content) {
        Ok(value) => value,
        Err(err) => {
            tracing::warn!(error = %err, "Failed to parse oauth.json; skipping migration");
            report.conflicts += 1;
            return Ok(outcome);
        }
    };

    let Some(map) = value.as_object() else {
        tracing::warn!("oauth.json is not an object; skipping migration");
        report.conflicts += 1;
        return Ok(outcome);
    };

    let mut conflict = false;
    for (provider_name, provider_value) in map.iter() {
        let mut entry_value = provider_value.clone();
        if let Value::Object(entry_map) = &mut entry_value {
            if !entry_map.contains_key("provider") {
                entry_map.insert(
                    "provider".to_string(),
                    Value::String(provider_name.to_string()),
                );
            }
        }
        for agent_id in agent_ids {
            let key = CredentialKey::new(
                "auth-profile",
                agent_id.to_string(),
                format!("{}:default", provider_name),
            );
            match ensure_credential(
                store,
                &key,
                &entry_value,
                Some(provider_name.to_string()),
                report,
            )
            .await?
            {
                EnsureResult::Stored | EnsureResult::Matched => {
                    completed.insert(key.to_account_key());
                }
                EnsureResult::Conflict => {
                    conflict = true;
                }
            }
        }
    }

    if !conflict {
        match fs::remove_file(path) {
            Ok(()) => {
                outcome.cleaned = true;
                report.cleaned_files += 1;
            }
            Err(err) => {
                tracing::warn!(error = %err, "Failed to remove oauth.json after migration");
                report.conflicts += 1;
            }
        }
    }

    Ok(outcome)
}

async fn migrate_auth_profiles_file<B: CredentialBackend>(
    store: &CredentialStore<B>,
    agent_id: &str,
    path: &Path,
    completed: &mut HashSet<String>,
    report: &mut MigrationReport,
) -> Result<FileOutcome, CredentialError> {
    let mut outcome = FileOutcome {
        touched: false,
        cleaned: false,
    };
    if !path.exists() {
        return Ok(outcome);
    }
    outcome.touched = true;

    let content = fs::read_to_string(path).map_err(|e| CredentialError::IoError(e.to_string()))?;
    let value: Value = match serde_json::from_str(&content) {
        Ok(value) => value,
        Err(err) => {
            tracing::warn!(error = %err, "Failed to parse auth-profiles.json; skipping migration");
            report.conflicts += 1;
            return Ok(outcome);
        }
    };

    let extracted = extract_profiles(&value);
    if extracted.entries.is_empty() && matches!(extracted.sanitized, Value::Null) {
        tracing::warn!("auth-profiles.json has unsupported structure; skipping migration");
        report.conflicts += 1;
        return Ok(outcome);
    }

    let mut conflict = extracted.unmigratable;
    if extracted.unmigratable {
        tracing::warn!(
            "auth-profiles.json contains profiles without stable IDs; leaving file unchanged"
        );
        report.conflicts += 1;
    }
    for (profile_id, profile_value, provider) in extracted.entries {
        let key = CredentialKey::new("auth-profile", agent_id.to_string(), profile_id);
        match ensure_credential(store, &key, &profile_value, provider, report).await? {
            EnsureResult::Stored | EnsureResult::Matched => {
                completed.insert(key.to_account_key());
            }
            EnsureResult::Conflict => {
                conflict = true;
            }
        }
    }

    if !conflict {
        if let Err(err) = write_json_atomic(path, &extracted.sanitized) {
            tracing::warn!(error = %err, "Failed to rewrite auth-profiles.json after migration");
            report.conflicts += 1;
        } else {
            outcome.cleaned = true;
            report.cleaned_files += 1;
        }
    }

    Ok(outcome)
}

async fn migrate_auth_legacy_file<B: CredentialBackend>(
    store: &CredentialStore<B>,
    agent_id: &str,
    path: &Path,
    completed: &mut HashSet<String>,
    report: &mut MigrationReport,
) -> Result<FileOutcome, CredentialError> {
    let mut outcome = FileOutcome {
        touched: false,
        cleaned: false,
    };
    if !path.exists() {
        return Ok(outcome);
    }
    outcome.touched = true;

    let content = fs::read_to_string(path).map_err(|e| CredentialError::IoError(e.to_string()))?;
    let value: Value = match serde_json::from_str(&content) {
        Ok(value) => value,
        Err(err) => {
            tracing::warn!(error = %err, "Failed to parse auth.json; skipping migration");
            report.conflicts += 1;
            return Ok(outcome);
        }
    };

    let extracted = extract_profiles(&value);
    if extracted.entries.is_empty() {
        tracing::warn!("auth.json has unsupported structure or no secrets; skipping migration");
        report.conflicts += 1;
        return Ok(outcome);
    }

    let mut conflict = extracted.unmigratable;
    if extracted.unmigratable {
        tracing::warn!("auth.json contains profiles without stable IDs; leaving file unchanged");
        report.conflicts += 1;
    }
    for (profile_id, profile_value, provider) in extracted.entries {
        let key = CredentialKey::new("auth-profile", agent_id.to_string(), profile_id);
        match ensure_credential(store, &key, &profile_value, provider, report).await? {
            EnsureResult::Stored | EnsureResult::Matched => {
                completed.insert(key.to_account_key());
            }
            EnsureResult::Conflict => {
                conflict = true;
            }
        }
    }

    if !conflict {
        match fs::remove_file(path) {
            Ok(()) => {
                outcome.cleaned = true;
                report.cleaned_files += 1;
            }
            Err(err) => {
                tracing::warn!(error = %err, "Failed to remove auth.json after migration");
                report.conflicts += 1;
            }
        }
    }

    Ok(outcome)
}

async fn migrate_copilot_file<B: CredentialBackend>(
    store: &CredentialStore<B>,
    path: &Path,
    completed: &mut HashSet<String>,
    report: &mut MigrationReport,
) -> Result<FileOutcome, CredentialError> {
    let mut outcome = FileOutcome {
        touched: false,
        cleaned: false,
    };
    if !path.exists() {
        return Ok(outcome);
    }
    outcome.touched = true;

    let content = fs::read_to_string(path).map_err(|e| CredentialError::IoError(e.to_string()))?;
    let value: Value = match serde_json::from_str(&content) {
        Ok(value) => value,
        Err(err) => {
            tracing::warn!(error = %err, "Failed to parse copilot token JSON; skipping migration");
            report.conflicts += 1;
            return Ok(outcome);
        }
    };

    let key = CredentialKey::new("copilot", "token", "default");
    let mut conflict = false;
    match ensure_credential(store, &key, &value, None, report).await? {
        EnsureResult::Stored | EnsureResult::Matched => {
            completed.insert(key.to_account_key());
        }
        EnsureResult::Conflict => {
            conflict = true;
        }
    }

    if !conflict {
        match fs::remove_file(path) {
            Ok(()) => {
                outcome.cleaned = true;
                report.cleaned_files += 1;
            }
            Err(err) => {
                tracing::warn!(error = %err, "Failed to remove copilot token file after migration");
                report.conflicts += 1;
            }
        }
    }

    Ok(outcome)
}

async fn migrate_pairing_file<B: CredentialBackend>(
    store: &CredentialStore<B>,
    path: &Path,
    channel: &str,
    allowlist: bool,
    completed: &mut HashSet<String>,
    report: &mut MigrationReport,
) -> Result<FileOutcome, CredentialError> {
    let mut outcome = FileOutcome {
        touched: false,
        cleaned: false,
    };
    if !path.exists() {
        return Ok(outcome);
    }
    outcome.touched = true;

    let content = fs::read_to_string(path).map_err(|e| CredentialError::IoError(e.to_string()))?;
    let value: Value = match serde_json::from_str(&content) {
        Ok(value) => value,
        Err(err) => {
            tracing::warn!(error = %err, "Failed to parse pairing file; skipping migration");
            report.conflicts += 1;
            return Ok(outcome);
        }
    };

    let payload = json!({"version": 1, "payload": value});
    let key = if allowlist {
        CredentialKey::new("pairing", "allowFrom", channel)
    } else {
        CredentialKey::new("pairing", "store", channel)
    };

    let mut conflict = false;
    match ensure_credential(store, &key, &payload, None, report).await? {
        EnsureResult::Stored | EnsureResult::Matched => {
            completed.insert(key.to_account_key());
        }
        EnsureResult::Conflict => {
            conflict = true;
        }
    }

    if !conflict {
        match fs::remove_file(path) {
            Ok(()) => {
                outcome.cleaned = true;
                report.cleaned_files += 1;
            }
            Err(err) => {
                tracing::warn!(error = %err, "Failed to remove pairing file after migration");
                report.conflicts += 1;
            }
        }
    }

    Ok(outcome)
}

fn parse_whatsapp_key(value: &str) -> Option<Vec<u8>> {
    let parsed: Value = serde_json::from_str(value).ok()?;
    let key_b64 = parsed
        .get("key")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())?;
    BASE64.decode(key_b64.as_bytes()).ok()
}

fn build_whatsapp_bundle(files: &[WhatsappFile]) -> Result<String, CredentialError> {
    let mut file_map = Map::new();
    for file in files {
        let bytes = fs::read(&file.path).map_err(|e| CredentialError::IoError(e.to_string()))?;
        file_map.insert(file.name.clone(), Value::String(BASE64.encode(bytes)));
    }
    let bundle = json!({"version": 1, "files": file_map});
    serde_json::to_string(&bundle).map_err(|e| CredentialError::JsonError(e.to_string()))
}

async fn migrate_whatsapp_account<B: CredentialBackend>(
    store: &CredentialStore<B>,
    legacy_credentials_dir: &Path,
    account: &WhatsappAccount,
    completed: &mut HashSet<String>,
    report: &mut MigrationReport,
) -> Result<FileOutcome, CredentialError> {
    let mut outcome = FileOutcome {
        touched: false,
        cleaned: false,
    };
    if account.files.is_empty() {
        return Ok(outcome);
    }
    outcome.touched = true;

    let bundle_json = match build_whatsapp_bundle(&account.files) {
        Ok(bundle) => bundle,
        Err(err) => {
            tracing::warn!(
                account = %account.account_id,
                error = %err,
                "Failed to bundle WhatsApp legacy files; skipping migration"
            );
            report.conflicts += 1;
            return Ok(outcome);
        }
    };
    let session_key = CredentialKey::new("whatsapp", "session-key", &account.account_id);

    let mut key_bytes: Option<Vec<u8>> = None;
    let existing = store.get(&session_key).await?;
    if let Some(existing_value) = existing {
        match parse_whatsapp_key(&existing_value) {
            Some(bytes) => {
                key_bytes = Some(bytes);
                if let Err(err) = store.record_index_entry(&session_key, None).await {
                    tracing::warn!(
                        key = %session_key,
                        error = %err,
                        "Failed to update WhatsApp session key index during migration"
                    );
                }
                report.matched += 1;
            }
            None => {
                tracing::warn!(
                    key = %session_key,
                    "Stored WhatsApp session key is invalid; skipping migration"
                );
                report.conflicts += 1;
                return Ok(outcome);
            }
        }
    }

    if key_bytes.is_none() {
        let mut raw_key = vec![0u8; 32];
        getrandom::fill(&mut raw_key).map_err(|e| CredentialError::IoError(e.to_string()))?;
        let key_payload = json!({
            "key": BASE64.encode(&raw_key),
            "format": "v1"
        });
        let key_payload_str = serde_json::to_string(&key_payload)
            .map_err(|e| CredentialError::JsonError(e.to_string()))?;
        store.set(&session_key, &key_payload_str, None).await?;
        report.migrated += 1;
        key_bytes = Some(raw_key);
    }

    let key_bytes = key_bytes.unwrap_or_default();
    let secret_store =
        SecretStore::new(&key_bytes).map_err(|e| CredentialError::Internal(e.to_string()))?;
    let encrypted = secret_store
        .encrypt(&bundle_json)
        .map_err(|e| CredentialError::Internal(e.to_string()))?;

    let account_dir = legacy_credentials_dir
        .join("whatsapp")
        .join(&account.account_id);
    fs::create_dir_all(&account_dir).map_err(|e| CredentialError::IoError(e.to_string()))?;
    let session_path = account_dir.join("session.enc");
    if let Err(err) = write_string_atomic(&session_path, &encrypted) {
        tracing::warn!(
            account = %account.account_id,
            error = %err,
            "Failed to write WhatsApp session bundle; leaving legacy files untouched"
        );
        report.conflicts += 1;
        return Ok(outcome);
    }

    let mut delete_failed = false;
    for file in &account.files {
        if let Err(err) = fs::remove_file(&file.path) {
            tracing::warn!(
                error = %err,
                path = ?file.path,
                "Failed to remove WhatsApp legacy file after migration"
            );
            delete_failed = true;
        }
    }

    if !delete_failed {
        outcome.cleaned = true;
        report.cleaned_files += 1;
    } else {
        report.conflicts += 1;
    }

    completed.insert(session_key.to_account_key());

    Ok(outcome)
}

pub async fn migrate_plaintext_credentials(
    state_dir: PathBuf,
) -> Result<MigrationReport, CredentialError> {
    let backend = super::default_backend();
    let store = CredentialStore::new(backend, state_dir.clone()).await?;
    migrate_plaintext_credentials_with_store(&store, &state_dir).await
}

async fn migrate_plaintext_credentials_with_store<B: CredentialBackend>(
    store: &CredentialStore<B>,
    state_dir: &Path,
) -> Result<MigrationReport, CredentialError> {
    let mut report = MigrationReport::default();

    if store.is_env_only_mode() {
        report.skipped = true;
        tracing::warn!("Credential store unavailable; skipping plaintext migration");
        return Ok(report);
    }

    let legacy_credentials_dir = resolve_legacy_credentials_dir(state_dir);
    let agent_ids = resolve_agent_ids(state_dir);
    let scan = scan_legacy(state_dir, &legacy_credentials_dir, &agent_ids);

    let state_path = migration_state_path(state_dir);
    let mut state = load_migration_state(&state_path)?;
    let mut completed: HashSet<String> = state
        .as_ref()
        .map(|s| s.completed.iter().cloned().collect())
        .unwrap_or_default();

    if !scan.has_any() {
        if state.is_some() {
            if let Err(err) = fs::remove_file(&state_path) {
                tracing::warn!(error = %err, "Failed to remove stale migration state");
            }
        }
        return Ok(report);
    }

    if state.is_none() {
        let new_state = MigrationState::new();
        write_migration_state(&state_path, &new_state)?;
        state = Some(new_state);
    }

    let mut remaining_legacy = false;

    if let Some(path) = &scan.oauth_path {
        let outcome =
            migrate_oauth_file(store, path, &agent_ids, &mut completed, &mut report).await?;
        if outcome.remaining() {
            remaining_legacy = true;
        }
    }

    for (agent_id, path) in &scan.auth_profiles {
        let outcome =
            migrate_auth_profiles_file(store, agent_id, path, &mut completed, &mut report).await?;
        if outcome.remaining() {
            remaining_legacy = true;
        }
    }

    for (agent_id, path) in &scan.auth_legacy {
        let outcome =
            migrate_auth_legacy_file(store, agent_id, path, &mut completed, &mut report).await?;
        if outcome.remaining() {
            remaining_legacy = true;
        }
    }

    if let Some(path) = &scan.copilot_path {
        let outcome = migrate_copilot_file(store, path, &mut completed, &mut report).await?;
        if outcome.remaining() {
            remaining_legacy = true;
        }
    }

    for (channel, path) in &scan.pairing {
        let outcome =
            migrate_pairing_file(store, path, channel, false, &mut completed, &mut report).await?;
        if outcome.remaining() {
            remaining_legacy = true;
        }
    }

    for (channel, path) in &scan.allow_from {
        let outcome =
            migrate_pairing_file(store, path, channel, true, &mut completed, &mut report).await?;
        if outcome.remaining() {
            remaining_legacy = true;
        }
    }

    for account in &scan.whatsapp_accounts {
        let outcome = migrate_whatsapp_account(
            store,
            &legacy_credentials_dir,
            account,
            &mut completed,
            &mut report,
        )
        .await?;
        if outcome.remaining() {
            remaining_legacy = true;
        }
    }

    if remaining_legacy {
        if let Some(state) = state.as_mut() {
            let mut completed_vec = completed.into_iter().collect::<Vec<_>>();
            completed_vec.sort();
            state.completed = completed_vec;
            write_migration_state(&state_path, state)?;
        }
    } else if let Err(err) = fs::remove_file(&state_path) {
        if err.kind() != std::io::ErrorKind::NotFound {
            tracing::warn!(error = %err, "Failed to remove migration state after completion");
        }
    }

    if report.migrated > 0 || report.cleaned_files > 0 {
        tracing::info!(
            migrated = report.migrated,
            matched = report.matched,
            cleaned_files = report.cleaned_files,
            "Legacy credential migration completed"
        );
    }

    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credentials::{CredentialStore, MockCredentialBackend};
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_oauth_migration_removes_file() {
        let temp = tempdir().unwrap();
        let state_dir = temp.path().to_path_buf();
        let legacy_dir = state_dir.join("credentials");
        fs::create_dir_all(&legacy_dir).unwrap();
        let oauth_path = legacy_dir.join("oauth.json");
        fs::write(
            &oauth_path,
            r#"{ "anthropic": { "type": "api_key", "key": "secret" } }"#,
        )
        .unwrap();

        let backend = MockCredentialBackend::new(true);
        let store = CredentialStore::new(backend, state_dir.clone())
            .await
            .unwrap();
        let report = migrate_plaintext_credentials_with_store(&store, &state_dir)
            .await
            .unwrap();

        assert!(report.migrated > 0);
        assert!(!oauth_path.exists());

        let key = CredentialKey::new("auth-profile", "main", "anthropic:default");
        let stored = store.get(&key).await.unwrap().unwrap();
        assert!(stored.contains("secret"));

        let keys = store.list_keys().await;
        assert!(keys
            .iter()
            .any(|k| k.to_account_key() == key.to_account_key()));
    }

    #[tokio::test]
    async fn test_oauth_recovery_cleans_when_store_matches() {
        let temp = tempdir().unwrap();
        let state_dir = temp.path().to_path_buf();
        let legacy_dir = state_dir.join("credentials");
        fs::create_dir_all(&legacy_dir).unwrap();
        let oauth_path = legacy_dir.join("oauth.json");
        fs::write(
            &oauth_path,
            r#"{ "anthropic": { "type": "api_key", "key": "secret" } }"#,
        )
        .unwrap();

        let backend = MockCredentialBackend::new(true);
        let store = CredentialStore::new(backend, state_dir.clone())
            .await
            .unwrap();
        let key = CredentialKey::new("auth-profile", "main", "anthropic:default");
        store
            .set(
                &key,
                r#"{"type":"api_key","key":"secret","provider":"anthropic"}"#,
                Some("anthropic".to_string()),
            )
            .await
            .unwrap();

        let report = migrate_plaintext_credentials_with_store(&store, &state_dir)
            .await
            .unwrap();

        assert!(report.matched > 0);
        assert!(!oauth_path.exists());
    }
}
