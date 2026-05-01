//! Credential storage module
//!
//! Platform-specific secure credential storage:
//! - macOS: Keychain
//! - Linux: Secret Service
//! - Windows: Credential Manager
//!
//! Key namespace: Service name `carapace`, account key format `kind:<agentId>:<id>`

#[cfg(target_os = "macos")]
mod macos;

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "windows")]
mod windows;

use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::Write as IoWrite;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tokio::time::timeout;

/// Service name for all credentials
pub const SERVICE_NAME: &str = "carapace";

/// Maximum key length for plugin credentials
pub const MAX_KEY_LENGTH: usize = 64;

/// Maximum value length for credentials (64 KB)
pub const MAX_VALUE_LENGTH: usize = 64 * 1024;

/// Maximum credentials per plugin
pub const MAX_CREDENTIALS_PER_PLUGIN: usize = 100;

/// Rate limit for writes per plugin (per minute)
pub const WRITE_RATE_LIMIT_PER_MINUTE: usize = 10;

/// Suffix used for staged credential rotation.
const PENDING_SUFFIX: &str = ":pending";
const WHATSAPP_LEGACY_PLAINTEXT_FILENAMES: &[&str] =
    &["creds.json", "identity.json", "session.json"];
const WHATSAPP_LEGACY_PLAINTEXT_PREFIXES: &[&str] = &[
    "app-state-sync-key-",
    "app-state-sync-version-",
    "pre-key-",
    "sender-key-",
    "session-",
];
const AGENT_LEGACY_CREDENTIAL_JSON_KEYS: &[&str] = &[
    "access_token",
    "accessToken",
    "api_key",
    "apiKey",
    "client_secret",
    "clientSecret",
    "key",
    "oauth_token",
    "oauthToken",
    "refresh_token",
    "refreshToken",
    "secret",
    "setup_token",
    "setupToken",
    "token",
];
// Matches the config-secret JSON scan bound so startup file-shape probes have
// the same conservative stack-safety limit.
const CREDENTIAL_SHAPE_SCAN_MAX_DEPTH: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PlaintextCredentialScanFailure {
    ReadFailed,
    InvalidJson,
    DepthLimitExceeded,
}

impl std::fmt::Display for PlaintextCredentialScanFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ReadFailed => write!(f, "read failed"),
            Self::InvalidJson => write!(f, "invalid JSON"),
            Self::DepthLimitExceeded => write!(f, "JSON nesting exceeds scan depth limit"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct PlaintextCredentialScanIssue {
    pub path: String,
    pub failure: PlaintextCredentialScanFailure,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CredentialShapeScan {
    Absent,
    Present,
    Indeterminate(PlaintextCredentialScanFailure),
}

struct PresentJsonField;

impl<'de> Deserialize<'de> for PresentJsonField {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let _ = serde::de::IgnoredAny::deserialize(deserializer)?;
        Ok(Self)
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct LegacyWhatsappPrimaryCredentialShape {
    #[serde(default, alias = "noise_key")]
    noise_key: Option<PresentJsonField>,
    #[serde(default, alias = "signed_identity_key")]
    signed_identity_key: Option<PresentJsonField>,
    #[serde(default, alias = "registration_id")]
    registration_id: Option<PresentJsonField>,
    #[serde(default, alias = "adv_secret_key")]
    adv_secret_key: Option<PresentJsonField>,
}

impl LegacyWhatsappPrimaryCredentialShape {
    fn has_credential_shape(&self) -> bool {
        self.noise_key.is_some()
            || self.signed_identity_key.is_some()
            || self.registration_id.is_some()
            || self.adv_secret_key.is_some()
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct LegacyWhatsappSessionShape {
    #[serde(default, rename = "_sessions")]
    sessions: Option<PresentJsonField>,
    #[serde(default, alias = "chain_key")]
    chain_key: Option<PresentJsonField>,
    #[serde(default, alias = "current_ratchet")]
    current_ratchet: Option<PresentJsonField>,
    #[serde(default, alias = "index_info")]
    index_info: Option<PresentJsonField>,
}

impl LegacyWhatsappSessionShape {
    fn has_credential_shape(&self) -> bool {
        self.sessions.is_some()
            || self.chain_key.is_some()
            || self.current_ratchet.is_some()
            || self.index_info.is_some()
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct LegacyWhatsappKeyMaterialShape {
    #[serde(default, alias = "identity_key")]
    identity_key: Option<PresentJsonField>,
    #[serde(default, alias = "signed_pre_key")]
    signed_pre_key: Option<PresentJsonField>,
    #[serde(default, alias = "sender_key_state")]
    sender_key_state: Option<PresentJsonField>,
    #[serde(default, alias = "sender_signing_key")]
    sender_signing_key: Option<PresentJsonField>,
}

impl LegacyWhatsappKeyMaterialShape {
    fn has_credential_shape(&self) -> bool {
        self.identity_key.is_some()
            || self.signed_pre_key.is_some()
            || self.sender_key_state.is_some()
            || self.sender_signing_key.is_some()
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct LegacyWhatsappAccountShape {
    #[serde(default, alias = "signal_identities")]
    signal_identities: Option<PresentJsonField>,
    #[serde(default)]
    account: Option<PresentJsonField>,
    #[serde(default, alias = "account_settings")]
    account_settings: Option<PresentJsonField>,
    #[serde(default)]
    me: Option<PresentJsonField>,
}

impl LegacyWhatsappAccountShape {
    fn has_credential_shape(&self) -> bool {
        self.signal_identities.is_some()
            || self.account.is_some()
            || self.account_settings.is_some()
            || self.me.is_some()
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct LegacyWhatsappAppStateShape {
    #[serde(default, alias = "key_data")]
    key_data: Option<PresentJsonField>,
    #[serde(default)]
    fingerprint: Option<PresentJsonField>,
    #[serde(default, alias = "my_app_state_key_id")]
    my_app_state_key_id: Option<PresentJsonField>,
    #[serde(default, alias = "pending_pre_key")]
    pending_pre_key: Option<PresentJsonField>,
}

impl LegacyWhatsappAppStateShape {
    fn has_credential_shape(&self) -> bool {
        self.key_data.is_some()
            || self.fingerprint.is_some()
            || self.my_app_state_key_id.is_some()
            || self.pending_pre_key.is_some()
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct LegacyWhatsappSyncShape {
    #[serde(default, alias = "processed_history_messages")]
    processed_history_messages: Option<PresentJsonField>,
    #[serde(default, alias = "first_unuploaded_pre_key_id")]
    first_unuploaded_pre_key_id: Option<PresentJsonField>,
    #[serde(default, alias = "last_account_sync_timestamp")]
    last_account_sync_timestamp: Option<PresentJsonField>,
    #[serde(default, alias = "next_pre_key_id")]
    next_pre_key_id: Option<PresentJsonField>,
}

impl LegacyWhatsappSyncShape {
    fn has_credential_shape(&self) -> bool {
        self.processed_history_messages.is_some()
            || self.first_unuploaded_pre_key_id.is_some()
            || self.last_account_sync_timestamp.is_some()
            || self.next_pre_key_id.is_some()
    }
}

#[derive(Deserialize)]
struct LegacyWhatsappCredentialShape {
    // Keep these sub-shapes' field names disjoint: serde `flatten` will route a
    // colliding key to the first matching sub-shape in declaration order.
    #[serde(flatten)]
    primary: LegacyWhatsappPrimaryCredentialShape,
    #[serde(flatten)]
    session: LegacyWhatsappSessionShape,
    #[serde(flatten)]
    key_material: LegacyWhatsappKeyMaterialShape,
    #[serde(flatten)]
    account: LegacyWhatsappAccountShape,
    #[serde(flatten)]
    app_state: LegacyWhatsappAppStateShape,
    #[serde(flatten)]
    sync: LegacyWhatsappSyncShape,
}

impl LegacyWhatsappCredentialShape {
    fn has_credential_shape(&self) -> bool {
        self.primary.has_credential_shape()
            || self.session.has_credential_shape()
            || self.key_material.has_credential_shape()
            || self.account.has_credential_shape()
            || self.app_state.has_credential_shape()
            || self.sync.has_credential_shape()
    }
}

#[derive(Deserialize)]
struct LegacyWhatsappBufferShape {
    #[serde(rename = "type")]
    _kind: LegacyWhatsappBufferKind,
    #[serde(rename = "data")]
    _data: NonEmptyJsonArray,
}

#[derive(Deserialize)]
enum LegacyWhatsappBufferKind {
    #[serde(rename = "Buffer")]
    Buffer,
}

struct NonEmptyString;

impl<'de> Deserialize<'de> for NonEmptyString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        if value.trim().is_empty() {
            Err(<D::Error as serde::de::Error>::custom("empty string"))
        } else {
            Ok(Self)
        }
    }
}

struct NonEmptyJsonArray;

impl<'de> Deserialize<'de> for NonEmptyJsonArray {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_seq(NonEmptyJsonArrayVisitor)
    }
}

struct NonEmptyJsonArrayVisitor;

impl<'de> serde::de::Visitor<'de> for NonEmptyJsonArrayVisitor {
    type Value = NonEmptyJsonArray;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a non-empty JSON array")
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::SeqAccess<'de>,
    {
        if seq.next_element::<serde::de::IgnoredAny>()?.is_none() {
            return Err(<A::Error as serde::de::Error>::custom("empty array"));
        }
        while seq.next_element::<serde::de::IgnoredAny>()?.is_some() {}
        Ok(NonEmptyJsonArray)
    }
}

#[derive(Deserialize)]
struct LegacyPairingEnvelopeShape {
    #[serde(default, rename = "pairingCode", alias = "pairing_code")]
    pairing_code: Option<PresentJsonField>,
    #[serde(default)]
    pairing: Option<PresentJsonField>,
    #[serde(default)]
    credential: Option<PresentJsonField>,
    #[serde(default)]
    credentials: Option<PresentJsonField>,
}

impl LegacyPairingEnvelopeShape {
    fn has_credential_shape(&self) -> bool {
        self.pairing_code.is_some()
            || self.pairing.is_some()
            || self.credential.is_some()
            || self.credentials.is_some()
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct LegacyPairingCredentialRecordShape {
    // Pairing object detection intentionally keeps only envelope keys plus
    // credential-record anchors. The old scan also matched allowFrom,
    // allowedFrom, allowlist, contacts, identity, key, phone, senders, session,
    // and store, but those names are generic enough to appear in incidental
    // operational JSON even in *-pairing.json files.
    #[serde(default)]
    token: Option<PresentJsonField>,
    #[serde(default)]
    secret: Option<PresentJsonField>,
    #[serde(default)]
    jid: Option<PresentJsonField>,
    #[serde(default, alias = "client_id")]
    client_id: Option<PresentJsonField>,
    #[serde(default, alias = "device_id")]
    device_id: Option<PresentJsonField>,
}

impl LegacyPairingCredentialRecordShape {
    fn has_credential_shape(&self) -> bool {
        self.token.is_some()
            || self.secret.is_some()
            || self.jid.is_some()
            || self.client_id.is_some()
            || self.device_id.is_some()
    }
}

#[derive(Deserialize)]
#[serde(untagged)]
enum LegacyPairingShape {
    String(NonEmptyString),
    Array(NonEmptyJsonArray),
}

/// Credential store errors
#[derive(Debug, Clone, PartialEq)]
pub enum CredentialError {
    /// Keychain/secret store is locked and requires user interaction
    StoreLocked,
    /// Secret store service is not available (e.g., no Secret Service on Linux)
    StoreUnavailable(String),
    /// Access denied to the credential
    AccessDenied,
    /// Credential not found
    NotFound,
    /// Operation timed out
    Timeout,
    /// I/O error
    IoError(String),
    /// JSON serialization/deserialization error
    JsonError(String),
    /// Key exceeds maximum length
    KeyTooLong,
    /// Value exceeds maximum length
    ValueTooLong,
    /// Plugin credential quota exceeded
    QuotaExceeded,
    /// Plugin rate limit exceeded
    RateLimitExceeded,
    /// Index file is corrupted
    IndexCorrupted,
    /// Plaintext credential files are no longer accepted.
    PlaintextCredentialFilesDetected(Vec<String>),
    /// Potential plaintext credential files could not be safely inspected.
    PlaintextCredentialFilesUnscannable(Vec<PlaintextCredentialScanIssue>),
    /// Plaintext credentials were found and some candidate files could not be safely inspected.
    PlaintextCredentialFilesBlocked {
        detected: Vec<String>,
        unscannable: Vec<PlaintextCredentialScanIssue>,
    },
    /// File lock acquisition failed
    LockFailed,
    /// Credential verification failed after write
    VerificationFailed,
    /// Internal error
    Internal(String),
}

impl std::fmt::Display for CredentialError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StoreLocked => write!(f, "Credential store is locked"),
            Self::StoreUnavailable(msg) => write!(f, "Credential store unavailable: {}", msg),
            Self::AccessDenied => write!(f, "Access denied to credential"),
            Self::NotFound => write!(f, "Credential not found"),
            Self::Timeout => write!(f, "Operation timed out"),
            Self::IoError(msg) => write!(f, "I/O error: {}", msg),
            Self::JsonError(msg) => write!(f, "JSON error: {}", msg),
            Self::KeyTooLong => {
                write!(
                    f,
                    "Key exceeds maximum length of {} characters",
                    MAX_KEY_LENGTH
                )
            }
            Self::ValueTooLong => {
                write!(
                    f,
                    "Value exceeds maximum length of {} bytes",
                    MAX_VALUE_LENGTH
                )
            }
            Self::QuotaExceeded => write!(
                f,
                "Plugin credential quota exceeded (max {} credentials)",
                MAX_CREDENTIALS_PER_PLUGIN
            ),
            Self::RateLimitExceeded => write!(
                f,
                "Plugin write rate limit exceeded ({} writes/minute)",
                WRITE_RATE_LIMIT_PER_MINUTE
            ),
            Self::IndexCorrupted => write!(f, "Credential index file is corrupted"),
            Self::PlaintextCredentialFilesDetected(paths) if paths.len() == 1 => write!(
                f,
                "plaintext credential file detected at {}; delete it and re-enroll",
                paths[0]
            ),
            Self::PlaintextCredentialFilesDetected(paths) => write!(
                f,
                "plaintext credential files detected ({}): {}; delete them and re-enroll",
                paths.len(),
                paths.join(", ")
            ),
            Self::PlaintextCredentialFilesUnscannable(issues) if issues.len() == 1 => write!(
                f,
                "potential plaintext credential file at {} could not be safely inspected ({}); repair the file or permissions, or remove it before startup",
                issues[0].path,
                issues[0].failure
            ),
            Self::PlaintextCredentialFilesUnscannable(issues) => {
                let paths = issues
                    .iter()
                    .map(|issue| format!("{} ({})", issue.path, issue.failure))
                    .collect::<Vec<_>>();
                write!(
                    f,
                    "potential plaintext credential files could not be safely inspected ({}): {}; repair the files or permissions, or remove them before startup",
                    issues.len(),
                    paths.join(", ")
                )
            }
            Self::PlaintextCredentialFilesBlocked {
                detected,
                unscannable,
            } => {
                let unscannable = unscannable
                    .iter()
                    .map(|issue| format!("{} ({})", issue.path, issue.failure))
                    .collect::<Vec<_>>();
                write!(
                    f,
                    "plaintext credential files detected ({}): {}; delete them and re-enroll; potential plaintext credential files could not be safely inspected ({}): {}; repair the files or permissions, or remove them before startup",
                    detected.len(),
                    detected.join(", "),
                    unscannable.len(),
                    unscannable.join(", ")
                )
            }
            Self::LockFailed => write!(f, "Failed to acquire file lock"),
            Self::VerificationFailed => write!(f, "Failed to verify credential after write"),
            Self::Internal(msg) => write!(f, "Internal error: {}", msg),
        }
    }
}

impl std::error::Error for CredentialError {}

/// Check if an error is retryable
pub fn is_retryable(error: &CredentialError) -> bool {
    matches!(
        error,
        CredentialError::Timeout | CredentialError::IoError(_) | CredentialError::RateLimitExceeded
    )
}

pub(crate) fn reject_plaintext_credential_files(state_dir: &Path) -> Result<(), CredentialError> {
    let mut findings = plaintext_credential_findings(state_dir);
    findings.sort_and_dedup();

    match (
        findings.detected.is_empty(),
        findings.unscannable.is_empty(),
    ) {
        (false, false) => {
            return Err(CredentialError::PlaintextCredentialFilesBlocked {
                detected: findings.detected,
                unscannable: findings.unscannable,
            });
        }
        (true, false) => {
            return Err(CredentialError::PlaintextCredentialFilesUnscannable(
                findings.unscannable,
            ));
        }
        (false, true) => {
            return Err(CredentialError::PlaintextCredentialFilesDetected(
                findings.detected,
            ));
        }
        (true, true) => {}
    }

    Ok(())
}

#[derive(Default)]
struct PlaintextCredentialFindings {
    detected: Vec<String>,
    unscannable: Vec<PlaintextCredentialScanIssue>,
}

impl PlaintextCredentialFindings {
    fn record(&mut self, path: &Path, scan: CredentialShapeScan) {
        match scan {
            CredentialShapeScan::Absent => {}
            CredentialShapeScan::Present => self.detected.push(path.display().to_string()),
            CredentialShapeScan::Indeterminate(failure) => {
                self.unscannable.push(PlaintextCredentialScanIssue {
                    path: path.display().to_string(),
                    failure,
                });
            }
        }
    }

    fn extend(&mut self, other: Self) {
        self.detected.extend(other.detected);
        self.unscannable.extend(other.unscannable);
    }

    fn sort_and_dedup(&mut self) {
        self.detected.sort();
        self.detected.dedup();
        self.unscannable.sort();
        self.unscannable.dedup();
    }
}

fn plaintext_credential_findings(state_dir: &Path) -> PlaintextCredentialFindings {
    let credentials_dir = state_dir.join("credentials");
    let known_credential_paths = [
        credentials_dir.join("oauth.json"),
        credentials_dir.join("github-copilot.token.json"),
        credentials_dir.join("creds.json"),
    ];
    let mut findings = PlaintextCredentialFindings::default();
    for path in known_credential_paths {
        if path.is_file() {
            findings.record(&path, known_plaintext_file_credential_scan(&path));
        }
    }

    findings.extend(agent_plaintext_credential_findings(state_dir));

    if let Ok(entries) = fs::read_dir(&credentials_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
                continue;
            };
            if name.ends_with("-pairing.json") || name.ends_with("-allowFrom.json") {
                findings.record(&path, pairing_plaintext_file_credential_scan(&path));
            }
        }
    }

    let whatsapp_root = credentials_dir.join("whatsapp");
    if let Ok(accounts) = fs::read_dir(&whatsapp_root) {
        for account in accounts.flatten() {
            let account_path = account.path();
            if !account_path.is_dir() {
                continue;
            }
            if let Ok(files) = fs::read_dir(account_path) {
                for file in files.flatten() {
                    let path = file.path();
                    if let Some(scan) = legacy_whatsapp_plaintext_file_scan(&path) {
                        findings.record(&path, scan);
                    }
                }
            }
        }
    }

    findings
}

fn legacy_whatsapp_plaintext_file_scan(path: &Path) -> Option<CredentialShapeScan> {
    let name = path.file_name().and_then(|name| name.to_str())?;
    let matched_name = WHATSAPP_LEGACY_PLAINTEXT_FILENAMES.contains(&name)
        || (name.ends_with(".json")
            && WHATSAPP_LEGACY_PLAINTEXT_PREFIXES
                .iter()
                .any(|prefix| name.starts_with(prefix)));
    matched_name.then(|| whatsapp_plaintext_file_credential_scan(path))
}

// Read the file, parse as JSON, and apply `predicate`. Unreadable,
// unparseable, or too-deep files fail closed, but use a distinct scan-failure
// error so operators do not mistake file-system corruption for confirmed
// plaintext credentials.
fn plaintext_file_credential_scan(
    path: &Path,
    predicate: fn(&Value) -> CredentialShapeScan,
) -> CredentialShapeScan {
    let content = match fs::read_to_string(path) {
        Ok(content) => content,
        Err(err) => {
            tracing::warn!(
                path = %path.display(),
                error = %err,
                "unable to read potential plaintext credential file; rejecting startup"
            );
            return CredentialShapeScan::Indeterminate(PlaintextCredentialScanFailure::ReadFailed);
        }
    };
    let value = match serde_json::from_str::<Value>(&content) {
        Ok(value) => value,
        Err(err) => {
            tracing::warn!(
                path = %path.display(),
                error = %err,
                "unable to parse potential plaintext credential file; rejecting startup"
            );
            return CredentialShapeScan::Indeterminate(PlaintextCredentialScanFailure::InvalidJson);
        }
    };
    predicate(&value)
}

fn known_plaintext_file_credential_scan(path: &Path) -> CredentialShapeScan {
    if fs::metadata(path)
        .map(|metadata| metadata.len() == 0)
        .unwrap_or(false)
    {
        return CredentialShapeScan::Absent;
    }
    plaintext_file_credential_scan(path, known_json_credential_scan)
}

fn known_json_credential_scan(value: &Value) -> CredentialShapeScan {
    match value {
        Value::String(value) if !value.trim().is_empty() => CredentialShapeScan::Present,
        Value::Object(_) => first_present_or_indeterminate([
            agent_json_credential_scan(value),
            simple_bool_credential_scan(whatsapp_json_has_credential_shape(value)),
            simple_bool_credential_scan(pairing_json_has_credential_shape(value)),
        ]),
        _ => CredentialShapeScan::Absent,
    }
}

fn whatsapp_plaintext_file_credential_scan(path: &Path) -> CredentialShapeScan {
    plaintext_file_credential_scan(path, |value| {
        simple_bool_credential_scan(whatsapp_json_has_credential_shape(value))
    })
}

fn whatsapp_json_has_credential_shape(value: &Value) -> bool {
    if LegacyWhatsappBufferShape::deserialize(value).is_ok() {
        return true;
    }
    // The object shape intentionally deserializes any JSON object; field
    // presence in `has_credential_shape` is the content gate.
    LegacyWhatsappCredentialShape::deserialize(value)
        .is_ok_and(|shape| shape.has_credential_shape())
}

fn pairing_plaintext_file_credential_scan(path: &Path) -> CredentialShapeScan {
    plaintext_file_credential_scan(path, |value| {
        simple_bool_credential_scan(pairing_json_has_credential_shape(value))
    })
}

fn pairing_json_has_credential_shape(value: &Value) -> bool {
    match LegacyPairingShape::deserialize(value) {
        Ok(LegacyPairingShape::String(_) | LegacyPairingShape::Array(_)) => true,
        Err(_) => {
            LegacyPairingEnvelopeShape::deserialize(value)
                .is_ok_and(|shape| shape.has_credential_shape())
                || LegacyPairingCredentialRecordShape::deserialize(value)
                    .is_ok_and(|shape| shape.has_credential_shape())
        }
    }
}

fn agent_plaintext_credential_findings(state_dir: &Path) -> PlaintextCredentialFindings {
    let mut findings = PlaintextCredentialFindings::default();
    let agents_dir = state_dir.join("agents");
    if let Ok(entries) = fs::read_dir(agents_dir) {
        for entry in entries.flatten() {
            let agent_root = entry.path();
            if !agent_root.is_dir() {
                continue;
            }
            let agent_dir = agent_root.join("agent");
            let auth_profiles = agent_dir.join("auth-profiles.json");
            findings.record(
                &auth_profiles,
                agent_plaintext_file_credential_scan(&auth_profiles),
            );
            let auth = agent_dir.join("auth.json");
            findings.record(&auth, agent_plaintext_file_credential_scan(&auth));
        }
    }
    findings
}

fn agent_plaintext_file_credential_scan(path: &Path) -> CredentialShapeScan {
    if !path.is_file() {
        return CredentialShapeScan::Absent;
    }
    plaintext_file_credential_scan(path, agent_json_credential_scan)
}

fn simple_bool_credential_scan(has_shape: bool) -> CredentialShapeScan {
    if has_shape {
        CredentialShapeScan::Present
    } else {
        CredentialShapeScan::Absent
    }
}

fn first_present_or_indeterminate(
    scans: impl IntoIterator<Item = CredentialShapeScan>,
) -> CredentialShapeScan {
    let mut indeterminate = None;
    for scan in scans {
        match scan {
            CredentialShapeScan::Present => return CredentialShapeScan::Present,
            CredentialShapeScan::Indeterminate(failure) => indeterminate = Some(failure),
            CredentialShapeScan::Absent => {}
        }
    }
    indeterminate
        .map(CredentialShapeScan::Indeterminate)
        .unwrap_or(CredentialShapeScan::Absent)
}

fn agent_json_credential_scan(value: &Value) -> CredentialShapeScan {
    agent_json_credential_scan_inner(value, 0)
}

fn agent_json_credential_scan_inner(value: &Value, depth: usize) -> CredentialShapeScan {
    if depth > CREDENTIAL_SHAPE_SCAN_MAX_DEPTH {
        return CredentialShapeScan::Indeterminate(
            PlaintextCredentialScanFailure::DepthLimitExceeded,
        );
    }

    match value {
        Value::Object(object) => {
            let mut indeterminate = None;
            for (key, value) in object {
                let scan = if AGENT_LEGACY_CREDENTIAL_JSON_KEYS.contains(&key.as_str()) {
                    credential_value_plaintext_scan_inner(value, depth + 1)
                } else {
                    agent_json_credential_scan_inner(value, depth + 1)
                };
                match scan {
                    CredentialShapeScan::Present => return CredentialShapeScan::Present,
                    CredentialShapeScan::Indeterminate(failure) => indeterminate = Some(failure),
                    CredentialShapeScan::Absent => {}
                }
            }
            indeterminate
                .map(CredentialShapeScan::Indeterminate)
                .unwrap_or(CredentialShapeScan::Absent)
        }
        Value::Array(items) => first_present_or_indeterminate(
            items
                .iter()
                .map(|item| agent_json_credential_scan_inner(item, depth + 1)),
        ),
        _ => CredentialShapeScan::Absent,
    }
}

#[cfg(test)]
fn credential_value_plaintext_scan(value: &Value) -> CredentialShapeScan {
    credential_value_plaintext_scan_inner(value, 0)
}

fn credential_value_plaintext_scan_inner(value: &Value, depth: usize) -> CredentialShapeScan {
    if depth > CREDENTIAL_SHAPE_SCAN_MAX_DEPTH {
        return CredentialShapeScan::Indeterminate(
            PlaintextCredentialScanFailure::DepthLimitExceeded,
        );
    }

    match value {
        Value::String(value) => {
            let value = value.trim();
            if !value.is_empty() && !value.starts_with("enc:v") {
                CredentialShapeScan::Present
            } else {
                CredentialShapeScan::Absent
            }
        }
        Value::Array(items) => first_present_or_indeterminate(
            items
                .iter()
                .map(|item| credential_value_plaintext_scan_inner(item, depth + 1)),
        ),
        Value::Object(object) => first_present_or_indeterminate(
            object
                .values()
                .map(|value| credential_value_plaintext_scan_inner(value, depth + 1)),
        ),
        _ => CredentialShapeScan::Absent,
    }
}

/// Delete a keyring credential entry with idempotent not-found semantics.
pub(crate) async fn delete_keyring_entry(
    account_key: String,
    map_error: fn(keyring::Error) -> CredentialError,
    task_name: &'static str,
) -> Result<(), CredentialError> {
    let outcome = tokio::task::spawn_blocking(move || {
        let entry = keyring::Entry::new(SERVICE_NAME, &account_key).map_err(map_error)?;
        match entry.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(map_error(e)),
        }
    })
    .await;

    outcome.map_err(|e| CredentialError::Internal(format!("{task_name} task failed: {e}")))?
}

/// Retry policy configuration
#[derive(Debug, Clone)]
pub struct RetryPolicy {
    pub max_retries: usize,
    pub timeout: Duration,
    pub backoff: Option<Vec<Duration>>,
}

impl RetryPolicy {
    /// Policy for get operations: 5s timeout, 2 retries, no backoff
    pub fn for_get() -> Self {
        Self {
            max_retries: 2,
            timeout: Duration::from_secs(5),
            backoff: None,
        }
    }

    /// Policy for set operations: 10s timeout, 3 retries, exponential backoff
    pub fn for_set() -> Self {
        Self {
            max_retries: 3,
            timeout: Duration::from_secs(10),
            backoff: Some(vec![
                Duration::from_millis(100),
                Duration::from_millis(500),
                Duration::from_secs(2),
            ]),
        }
    }

    /// Policy for delete operations: 5s timeout, 2 retries, no backoff
    pub fn for_delete() -> Self {
        Self {
            max_retries: 2,
            timeout: Duration::from_secs(5),
            backoff: None,
        }
    }
}

/// Credential key with parsed components
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CredentialKey {
    pub kind: String,
    pub agent_id: String,
    pub id: String,
}

impl CredentialKey {
    /// Create a new credential key
    pub fn new(
        kind: impl Into<String>,
        agent_id: impl Into<String>,
        id: impl Into<String>,
    ) -> Self {
        Self {
            kind: kind.into(),
            agent_id: agent_id.into(),
            id: id.into(),
        }
    }

    /// Parse a key string in format `kind:<agentId>:<id>`
    pub fn parse(key: &str) -> Option<Self> {
        let parts: Vec<&str> = key.splitn(3, ':').collect();
        if parts.len() == 3 {
            Some(Self {
                kind: parts[0].to_string(),
                agent_id: parts[1].to_string(),
                id: parts[2].to_string(),
            })
        } else {
            None
        }
    }

    /// Format as account key string
    pub fn to_account_key(&self) -> String {
        format!("{}:{}:{}", self.kind, self.agent_id, self.id)
    }

    /// Create a plugin-prefixed key
    pub fn with_plugin_prefix(plugin_id: &str, kind: &str, id: &str) -> Self {
        // Sanitize plugin_id to prevent path traversal attacks
        let sanitized_plugin_id = plugin_id.replace("..", "_").replace(['/', '\\'], "_");

        Self {
            kind: format!("plugin:{}", sanitized_plugin_id),
            agent_id: kind.to_string(),
            id: id.to_string(),
        }
    }
}

/// Gateway auth secrets loaded from the credential store
#[derive(Debug, Default, Clone, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct GatewayAuthSecrets {
    pub token: Option<String>,
    pub password: Option<String>,
}

/// Read gateway auth token/password from the credential store (if available).
pub async fn read_gateway_auth(state_dir: PathBuf) -> Result<GatewayAuthSecrets, CredentialError> {
    let backend = default_backend();
    let store = CredentialStore::new(backend, state_dir).await?;

    let token_key = CredentialKey::new("gateway", "token", "default");
    let password_key = CredentialKey::new("gateway", "password", "default");

    let token = store.get(&token_key).await?;
    let password = store.get(&password_key).await?;

    Ok(GatewayAuthSecrets { token, password })
}

/// Read CLI device identity (JSON) from the credential store.
pub async fn read_device_identity(state_dir: PathBuf) -> Result<Option<String>, CredentialError> {
    let backend = default_backend();
    let store = CredentialStore::new(backend, state_dir).await?;
    let key = CredentialKey::new("device", "cli", "identity");
    store.get(&key).await
}

/// Write CLI device identity (JSON) to the credential store.
pub async fn write_device_identity(state_dir: PathBuf, value: &str) -> Result<(), CredentialError> {
    let backend = default_backend();
    let store = CredentialStore::new(backend, state_dir).await?;
    let key = CredentialKey::new("device", "cli", "identity");
    store.set(&key, value, None).await
}

#[cfg(target_os = "macos")]
pub(crate) type DefaultCredentialBackend = macos::MacOsCredentialBackend;

#[cfg(target_os = "linux")]
pub(crate) type DefaultCredentialBackend = linux::LinuxCredentialBackend;

#[cfg(target_os = "windows")]
pub(crate) type DefaultCredentialBackend = windows::WindowsCredentialBackend;

#[cfg(target_os = "macos")]
fn default_backend() -> macos::MacOsCredentialBackend {
    macos::MacOsCredentialBackend::new()
}

#[cfg(target_os = "linux")]
fn default_backend() -> linux::LinuxCredentialBackend {
    linux::LinuxCredentialBackend::new()
}

#[cfg(target_os = "windows")]
fn default_backend() -> windows::WindowsCredentialBackend {
    windows::WindowsCredentialBackend::new()
}

/// Build the default platform credential store for the given state dir.
pub(crate) async fn create_default_store(
    state_dir: PathBuf,
) -> Result<Arc<CredentialStore<DefaultCredentialBackend>>, CredentialError> {
    let backend = default_backend();
    let store = CredentialStore::new(backend, state_dir).await?;
    Ok(Arc::new(store))
}

impl std::fmt::Display for CredentialKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_account_key())
    }
}

/// Index entry for a credential (non-secret metadata)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexEntry {
    pub key: CredentialKey,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    pub last_updated: u64,
}

/// Plugin quota tracking
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PluginQuota {
    pub count: usize,
}

/// Credential index file structure
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CredentialIndex {
    pub version: u32,
    #[serde(default)]
    pub entries: HashMap<String, IndexEntry>,
    #[serde(default)]
    pub plugins: HashMap<String, PluginQuota>,
}

impl CredentialIndex {
    pub const VERSION: u32 = 1;

    pub fn new() -> Self {
        Self {
            version: Self::VERSION,
            entries: HashMap::new(),
            plugins: HashMap::new(),
        }
    }
}

/// In-memory rate limit tracking for plugins
#[derive(Debug, Default)]
pub struct RateLimitTracker {
    /// Map of plugin_id -> list of write timestamps (in seconds since epoch)
    writes: HashMap<String, Vec<u64>>,
}

impl RateLimitTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Check if a write is allowed for the given plugin
    pub fn check_and_record(&mut self, plugin_id: &str) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let one_minute_ago = now.saturating_sub(60);

        let writes = self.writes.entry(plugin_id.to_string()).or_default();

        // Remove old entries
        writes.retain(|&ts| ts > one_minute_ago);

        // Check if under limit
        if writes.len() >= WRITE_RATE_LIMIT_PER_MINUTE {
            return false;
        }

        // Record new write
        writes.push(now);
        true
    }
}

/// Credential store trait
pub trait CredentialBackend: Send + Sync {
    /// Get a credential by key (raw operation, no retry)
    fn get_raw<'a>(
        &'a self,
        key: &'a CredentialKey,
    ) -> impl std::future::Future<Output = Result<Option<String>, CredentialError>> + Send + 'a;

    /// Set a credential (raw operation, no retry)
    fn set_raw<'a>(
        &'a self,
        key: &'a CredentialKey,
        value: &'a str,
    ) -> impl std::future::Future<Output = Result<(), CredentialError>> + Send + 'a;

    /// Delete a credential (raw operation, no retry)
    fn delete_raw<'a>(
        &'a self,
        key: &'a CredentialKey,
    ) -> impl std::future::Future<Output = Result<(), CredentialError>> + Send + 'a;

    /// Check if the credential store is available and unlocked
    fn is_available(&self) -> impl std::future::Future<Output = bool> + Send + '_;
}

/// Main credential store that wraps a backend with retry logic and index management
pub struct CredentialStore<B: CredentialBackend> {
    backend: B,
    index_path: PathBuf,
    index: Arc<RwLock<CredentialIndex>>,
    rate_limiter: Arc<RwLock<RateLimitTracker>>,
    env_only_mode: bool,
}

impl<B: CredentialBackend> CredentialStore<B> {
    /// Create a new credential store with the given backend and state directory
    pub async fn new(backend: B, state_dir: PathBuf) -> Result<Self, CredentialError> {
        let credentials_dir = state_dir.join("credentials");
        fs::create_dir_all(&credentials_dir)
            .map_err(|e| CredentialError::IoError(e.to_string()))?;

        let index_path = credentials_dir.join("index.json");
        let index = Self::load_or_create_index(&index_path)?;

        let env_only_mode = !backend.is_available().await;
        if env_only_mode {
            tracing::warn!(
                "Credential store is unavailable, operating in env-only mode. \
                 Some features requiring stored credentials will be degraded."
            );
        }

        Ok(Self {
            backend,
            index_path,
            index: Arc::new(RwLock::new(index)),
            rate_limiter: Arc::new(RwLock::new(RateLimitTracker::new())),
            env_only_mode,
        })
    }

    /// Check if running in environment-only mode (keychain unavailable)
    pub fn is_env_only_mode(&self) -> bool {
        self.env_only_mode
    }

    fn backup_path(path: &Path) -> PathBuf {
        path.with_extension("json.bak")
    }

    fn corrupt_path(path: &Path) -> PathBuf {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);
        path.with_extension(format!("corrupt.{}", timestamp))
    }

    fn pending_key_for(key: &CredentialKey) -> Result<CredentialKey, CredentialError> {
        if key.id.ends_with(PENDING_SUFFIX) {
            return Err(CredentialError::Internal(
                "pending key cannot be staged again".to_string(),
            ));
        }

        Ok(CredentialKey {
            kind: key.kind.clone(),
            agent_id: key.agent_id.clone(),
            id: format!("{}{}", key.id, PENDING_SUFFIX),
        })
    }

    fn recalculate_plugin_quotas(index: &mut CredentialIndex) {
        let mut quotas: HashMap<String, PluginQuota> = HashMap::new();
        for entry in index.entries.values() {
            let plugin_key = if let Some(provider) = &entry.provider {
                if provider.starts_with("plugin:") {
                    Some(provider.clone())
                } else {
                    None
                }
            } else if entry.key.kind.starts_with("plugin:") {
                Some(entry.key.kind.clone())
            } else {
                None
            };

            if let Some(plugin_key) = plugin_key {
                let quota = quotas.entry(plugin_key).or_default();
                quota.count += 1;
            }
        }
        index.plugins = quotas;
    }

    fn load_index_file(path: &Path) -> Result<CredentialIndex, CredentialError> {
        let content =
            fs::read_to_string(path).map_err(|e| CredentialError::IoError(e.to_string()))?;
        let mut index: CredentialIndex = serde_json::from_str(&content)
            .map_err(|e| CredentialError::JsonError(e.to_string()))?;

        if index.version != CredentialIndex::VERSION {
            tracing::warn!(
                found = index.version,
                expected = CredentialIndex::VERSION,
                "Credential index version mismatch"
            );
            return Err(CredentialError::IndexCorrupted);
        }

        let mut removed = 0usize;
        index.entries.retain(|account_key, entry| {
            let expected = entry.key.to_account_key();
            let valid = account_key == &expected;
            if !valid {
                removed += 1;
            }
            valid
        });

        if removed > 0 {
            tracing::warn!(removed, "Removed invalid credential index entries");
        }

        Self::recalculate_plugin_quotas(&mut index);

        Ok(index)
    }

    /// Load or create the credential index
    fn load_or_create_index(path: &PathBuf) -> Result<CredentialIndex, CredentialError> {
        let backup_path = Self::backup_path(path);

        if path.exists() {
            match Self::load_index_file(path) {
                Ok(index) => return Ok(index),
                Err(err) => {
                    tracing::warn!(
                        error = %err,
                        "Credential index invalid; attempting recovery"
                    );
                }
            }
        }

        if backup_path.exists() {
            match Self::load_index_file(&backup_path) {
                Ok(index) => {
                    tracing::warn!(
                        "Restoring credential index from backup at {:?}",
                        backup_path
                    );

                    if path.exists() {
                        let corrupt_path = Self::corrupt_path(path);
                        if let Err(err) = fs::rename(path, &corrupt_path) {
                            tracing::warn!(
                                error = %err,
                                "Failed to move corrupted index to {:?}",
                                corrupt_path
                            );
                        }
                    }

                    if let Err(err) = fs::copy(&backup_path, path) {
                        tracing::warn!(
                            error = %err,
                            "Failed to restore index backup to {:?}",
                            path
                        );
                    }

                    return Ok(index);
                }
                Err(err) => {
                    tracing::warn!(
                        error = %err,
                        "Credential index backup invalid; starting fresh"
                    );
                }
            }
        }

        if path.exists() {
            let corrupt_path = Self::corrupt_path(path);
            tracing::warn!("Credential index corrupted, moving to {:?}", corrupt_path);
            fs::rename(path, &corrupt_path).map_err(|e| CredentialError::IoError(e.to_string()))?;
        }

        Ok(CredentialIndex::new())
    }

    /// Save the index with file locking
    async fn save_index(&self) -> Result<(), CredentialError> {
        let index = self.index.read().await;
        let content = serde_json::to_string_pretty(&*index)
            .map_err(|e| CredentialError::JsonError(e.to_string()))?;
        drop(index);

        // Use file locking for writes
        let lock_path = self.index_path.with_extension("lock");

        // Try to acquire lock with 5s timeout
        let lock_result = timeout(Duration::from_secs(5), async {
            loop {
                match OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&lock_path)
                {
                    Ok(_) => return Ok(()),
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                        // Check if lock is stale (older than 30s)
                        if let Ok(metadata) = fs::metadata(&lock_path) {
                            if let Ok(modified) = metadata.modified() {
                                if modified
                                    .elapsed()
                                    .map(|d| d.as_secs() > 30)
                                    .unwrap_or(false)
                                {
                                    // Stale lock, remove it
                                    let _ = fs::remove_file(&lock_path);
                                    continue;
                                }
                            }
                        }
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }
                    Err(e) => return Err(CredentialError::IoError(e.to_string())),
                }
            }
        })
        .await;

        match lock_result {
            Ok(Ok(())) => {}
            Ok(Err(e)) => return Err(e),
            Err(_) => return Err(CredentialError::LockFailed),
        }

        // Write the file atomically
        let temp_path = self.index_path.with_extension("tmp");
        let result = (|| {
            let backup_path = Self::backup_path(&self.index_path);
            if self.index_path.exists() {
                if let Err(err) = fs::copy(&self.index_path, &backup_path) {
                    tracing::warn!(
                        error = %err,
                        "Failed to write credential index backup to {:?}",
                        backup_path
                    );
                }
            }

            let mut file =
                File::create(&temp_path).map_err(|e| CredentialError::IoError(e.to_string()))?;
            IoWrite::write_all(&mut file, content.as_bytes())
                .map_err(|e| CredentialError::IoError(e.to_string()))?;
            file.sync_all()
                .map_err(|e| CredentialError::IoError(e.to_string()))?;
            fs::rename(&temp_path, &self.index_path)
                .map_err(|e| CredentialError::IoError(e.to_string()))?;

            if !backup_path.exists() {
                if let Err(err) = fs::copy(&self.index_path, &backup_path) {
                    tracing::warn!(
                        error = %err,
                        "Failed to create initial credential index backup at {:?}",
                        backup_path
                    );
                }
            }
            Ok(())
        })();

        // Always remove the lock
        let _ = fs::remove_file(&lock_path);

        result
    }

    /// Get a credential with retry logic
    pub async fn get(&self, key: &CredentialKey) -> Result<Option<String>, CredentialError> {
        if self.env_only_mode {
            return Ok(None);
        }

        self.with_retry(&RetryPolicy::for_get(), || async {
            self.backend.get_raw(key).await
        })
        .await
    }

    /// Set a credential with retry logic and atomic verification
    pub async fn set(
        &self,
        key: &CredentialKey,
        value: &str,
        provider: Option<String>,
    ) -> Result<(), CredentialError> {
        if self.env_only_mode {
            return Err(CredentialError::StoreUnavailable(
                "Operating in env-only mode".to_string(),
            ));
        }

        // Validate key and value length
        if key.to_account_key().len() > MAX_KEY_LENGTH {
            return Err(CredentialError::KeyTooLong);
        }
        if value.len() > MAX_VALUE_LENGTH {
            return Err(CredentialError::ValueTooLong);
        }

        // Read-write-verify pattern for atomicity
        let prior_value = self
            .with_retry(&RetryPolicy::for_get(), || async {
                self.backend.get_raw(key).await
            })
            .await;
        let (old_value, old_value_known) = match prior_value {
            Ok(value) => (value, true),
            Err(err) => {
                tracing::warn!(
                    key = %key,
                    error = %err,
                    "Failed to read existing credential before write; rollback may be limited"
                );
                (None, false)
            }
        };

        // Write new value with retry
        self.with_retry(&RetryPolicy::for_set(), || async {
            self.backend.set_raw(key, value).await
        })
        .await?;

        // Verify the write succeeded
        let verified = self.backend.get_raw(key).await?;
        if verified.as_deref() != Some(value) {
            tracing::error!(key = %key, "Credential verification failed after write");

            // Attempt to restore old value (best effort).
            if let Some(previous) = old_value {
                if let Err(err) = self
                    .with_retry(&RetryPolicy::for_set(), || async {
                        self.backend.set_raw(key, &previous).await
                    })
                    .await
                {
                    tracing::error!(
                        key = %key,
                        error = %err,
                        "Credential rollback failed; credential may be lost"
                    );
                }
            } else if old_value_known {
                if let Err(err) = self
                    .with_retry(&RetryPolicy::for_delete(), || async {
                        self.backend.delete_raw(key).await
                    })
                    .await
                {
                    tracing::error!(
                        key = %key,
                        error = %err,
                        "Credential rollback delete failed; credential may be lost"
                    );
                }
            } else {
                tracing::warn!(
                    key = %key,
                    "Skipping rollback delete because prior value is unknown"
                );
            }

            return Err(CredentialError::VerificationFailed);
        }

        // Update index
        {
            let mut index = self.index.write().await;
            let entry = IndexEntry {
                key: key.clone(),
                provider,
                last_updated: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0),
            };
            index.entries.insert(key.to_account_key(), entry);
        }

        self.save_index().await?;

        Ok(())
    }

    /// Stage a credential update under a pending key.
    pub async fn set_pending(
        &self,
        key: &CredentialKey,
        value: &str,
        provider: Option<String>,
    ) -> Result<(), CredentialError> {
        let pending_key = Self::pending_key_for(key)?;
        self.set(&pending_key, value, provider).await
    }

    /// Get a staged credential value (if any).
    pub async fn get_pending(
        &self,
        key: &CredentialKey,
    ) -> Result<Option<String>, CredentialError> {
        let pending_key = Self::pending_key_for(key)?;
        self.get(&pending_key).await
    }

    /// Promote a staged credential into the active key.
    pub async fn commit_pending(
        &self,
        key: &CredentialKey,
        provider: Option<String>,
    ) -> Result<(), CredentialError> {
        if self.env_only_mode {
            return Err(CredentialError::StoreUnavailable(
                "Operating in env-only mode".to_string(),
            ));
        }

        let pending_key = Self::pending_key_for(key)?;
        let pending_value = self.get(&pending_key).await?;
        let Some(pending_value) = pending_value else {
            let mut index = self.index.write().await;
            let removed = index
                .entries
                .remove(&pending_key.to_account_key())
                .is_some();
            drop(index);
            if removed {
                if let Err(err) = self.save_index().await {
                    tracing::warn!(
                        key = %pending_key,
                        error = %err,
                        "Failed to prune pending index entry after missing commit"
                    );
                }
            }
            return Err(CredentialError::NotFound);
        };

        let (pending_provider, existing_provider) = {
            let index = self.index.read().await;
            (
                index
                    .entries
                    .get(&pending_key.to_account_key())
                    .and_then(|entry| entry.provider.clone()),
                index
                    .entries
                    .get(&key.to_account_key())
                    .and_then(|entry| entry.provider.clone()),
            )
        };

        let resolved_provider = provider.or(pending_provider).or(existing_provider);

        self.set(key, &pending_value, resolved_provider).await?;

        if let Err(err) = self.delete(&pending_key).await {
            match err {
                CredentialError::NotFound => {
                    let mut index = self.index.write().await;
                    index.entries.remove(&pending_key.to_account_key());
                    drop(index);
                    if let Err(err) = self.save_index().await {
                        tracing::warn!(
                            key = %pending_key,
                            error = %err,
                            "Failed to prune pending index entry after commit"
                        );
                    }
                }
                _ => {
                    tracing::warn!(
                        key = %pending_key,
                        error = %err,
                        "Failed to delete pending credential after commit"
                    );
                }
            }
        }

        Ok(())
    }

    /// Discard a staged credential update if it exists.
    pub async fn discard_pending(&self, key: &CredentialKey) -> Result<(), CredentialError> {
        if self.env_only_mode {
            return Err(CredentialError::StoreUnavailable(
                "Operating in env-only mode".to_string(),
            ));
        }

        let pending_key = Self::pending_key_for(key)?;
        let pending_value = self.get(&pending_key).await?;
        if pending_value.is_none() {
            let mut index = self.index.write().await;
            let removed = index
                .entries
                .remove(&pending_key.to_account_key())
                .is_some();
            drop(index);
            if removed {
                let _ = self.save_index().await;
            }
            return Ok(());
        }

        match self.delete(&pending_key).await {
            Ok(()) => Ok(()),
            Err(CredentialError::NotFound) => {
                let mut index = self.index.write().await;
                index.entries.remove(&pending_key.to_account_key());
                drop(index);
                let _ = self.save_index().await;
                Ok(())
            }
            Err(err) => Err(err),
        }
    }

    /// Delete a credential with retry logic
    pub async fn delete(&self, key: &CredentialKey) -> Result<(), CredentialError> {
        if self.env_only_mode {
            return Err(CredentialError::StoreUnavailable(
                "Operating in env-only mode".to_string(),
            ));
        }

        self.with_retry(&RetryPolicy::for_delete(), || async {
            self.backend.delete_raw(key).await
        })
        .await?;

        // Update index
        {
            let mut index = self.index.write().await;
            index.entries.remove(&key.to_account_key());
        }

        self.save_index().await?;

        Ok(())
    }

    /// Record or refresh a credential entry in the index without touching the store.
    pub async fn record_index_entry(
        &self,
        key: &CredentialKey,
        provider: Option<String>,
    ) -> Result<(), CredentialError> {
        let mut index = self.index.write().await;
        let existing_provider = index
            .entries
            .get(&key.to_account_key())
            .and_then(|entry| entry.provider.clone());
        let entry = IndexEntry {
            key: key.clone(),
            provider: provider.or(existing_provider),
            last_updated: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
        };
        index.entries.insert(key.to_account_key(), entry);
        Self::recalculate_plugin_quotas(&mut index);
        drop(index);
        self.save_index().await
    }

    /// Get a plugin credential with isolation
    pub async fn plugin_get(
        &self,
        plugin_id: &str,
        kind: &str,
        id: &str,
    ) -> Result<Option<String>, CredentialError> {
        let key = CredentialKey::with_plugin_prefix(plugin_id, kind, id);
        self.get(&key).await
    }

    /// Set a plugin credential with isolation and quota enforcement
    ///
    /// Uses a write lock for the entire operation to prevent race conditions
    /// where concurrent calls could both increment the quota for the same new key.
    pub async fn plugin_set(
        &self,
        plugin_id: &str,
        kind: &str,
        id: &str,
        value: &str,
    ) -> Result<(), CredentialError> {
        // Check rate limit
        {
            let mut rate_limiter = self.rate_limiter.write().await;
            if !rate_limiter.check_and_record(plugin_id) {
                return Err(CredentialError::RateLimitExceeded);
            }
        }

        let key = CredentialKey::with_plugin_prefix(plugin_id, kind, id);
        let plugin_key = format!("plugin:{}", plugin_id);
        let account_key = key.to_account_key();

        // Check if this is a new key BEFORE setting (atomically with quota update)
        // We need to determine this before the set() call modifies the index
        let is_new_key = {
            let index = self.index.read().await;
            let quota = index.plugins.get(&plugin_key);
            let current_count = quota.map(|q| q.count).unwrap_or(0);
            let key_exists = index.entries.contains_key(&account_key);

            // Reject if at quota and this would be a new key
            if !key_exists && current_count >= MAX_CREDENTIALS_PER_PLUGIN {
                return Err(CredentialError::QuotaExceeded);
            }

            !key_exists
        };

        // Set the credential (this updates the index.entries via set())
        self.set(&key, value, Some(plugin_key.clone())).await?;

        // Update plugin quota if this was a new key
        // Note: There's a small race window here where another concurrent call
        // could also see is_new_key=true for the same key. However:
        // 1. Both calls succeed in setting the credential (last write wins)
        // 2. The quota might be incremented twice for one key
        // To fully prevent this, we'd need to hold a write lock during set(),
        // but that would block all credential operations.
        //
        // For now, we accept this minor over-counting as it only affects quota
        // (not security) and is self-correcting on delete or recalculation.
        if is_new_key {
            let mut index = self.index.write().await;
            let quota = index.plugins.entry(plugin_key).or_default();
            quota.count += 1;
        }

        self.save_index().await?;

        Ok(())
    }

    /// Delete a plugin credential with isolation
    pub async fn plugin_delete(
        &self,
        plugin_id: &str,
        kind: &str,
        id: &str,
    ) -> Result<(), CredentialError> {
        let key = CredentialKey::with_plugin_prefix(plugin_id, kind, id);
        self.delete(&key).await?;

        // Update plugin quota
        {
            let mut index = self.index.write().await;
            let plugin_key = format!("plugin:{}", plugin_id);
            if let Some(quota) = index.plugins.get_mut(&plugin_key) {
                quota.count = quota.count.saturating_sub(1);
            }
        }

        self.save_index().await?;

        Ok(())
    }

    /// Execute an operation with retry logic
    async fn with_retry<F, Fut, T>(&self, policy: &RetryPolicy, op: F) -> Result<T, CredentialError>
    where
        F: Fn() -> Fut,
        Fut: std::future::Future<Output = Result<T, CredentialError>>,
    {
        let mut last_error = CredentialError::Internal("No attempts made".to_string());

        for attempt in 0..=policy.max_retries {
            // Apply backoff before retry (not on first attempt)
            if attempt > 0 {
                if let Some(ref backoff) = policy.backoff {
                    if let Some(delay) = backoff.get(attempt - 1) {
                        tokio::time::sleep(*delay).await;
                    }
                }
            }

            match timeout(policy.timeout, op()).await {
                Ok(Ok(result)) => return Ok(result),
                Ok(Err(e)) => {
                    last_error = e.clone();
                    if !is_retryable(&e) {
                        return Err(e);
                    }
                    tracing::debug!(
                        attempt = attempt + 1,
                        max_retries = policy.max_retries,
                        error = %e,
                        "Credential operation failed, retrying"
                    );
                }
                Err(_) => {
                    last_error = CredentialError::Timeout;
                    tracing::debug!(
                        attempt = attempt + 1,
                        max_retries = policy.max_retries,
                        "Credential operation timed out, retrying"
                    );
                }
            }
        }

        Err(last_error)
    }

    /// List all credential keys from the index
    pub async fn list_keys(&self) -> Vec<CredentialKey> {
        let index = self.index.read().await;
        index.entries.values().map(|e| e.key.clone()).collect()
    }

    /// Check health of the credential store
    pub async fn check_health(&self) -> CredentialHealthStatus {
        if self.env_only_mode {
            return CredentialHealthStatus {
                available: false,
                locked: false,
                error: Some("Operating in env-only mode".to_string()),
            };
        }

        // Try a test read/write
        let test_key = CredentialKey::new("health", "check", "test");
        let test_value = format!("health-check-{}", uuid::Uuid::new_v4());

        match self.backend.set_raw(&test_key, &test_value).await {
            Ok(()) => {
                // Clean up test credential
                let _ = self.backend.delete_raw(&test_key).await;
                CredentialHealthStatus {
                    available: true,
                    locked: false,
                    error: None,
                }
            }
            Err(CredentialError::StoreLocked) => CredentialHealthStatus {
                available: false,
                locked: true,
                error: Some("Credential store is locked".to_string()),
            },
            Err(e) => CredentialHealthStatus {
                available: false,
                locked: false,
                error: Some(e.to_string()),
            },
        }
    }
}

/// Health status of the credential store
#[derive(Debug, Clone)]
pub struct CredentialHealthStatus {
    pub available: bool,
    pub locked: bool,
    pub error: Option<String>,
}

/// Create a platform-appropriate credential backend
#[cfg(target_os = "macos")]
pub fn create_backend() -> macos::MacOsCredentialBackend {
    macos::MacOsCredentialBackend::new()
}

#[cfg(target_os = "linux")]
pub fn create_backend() -> linux::LinuxCredentialBackend {
    linux::LinuxCredentialBackend::new()
}

#[cfg(target_os = "windows")]
pub fn create_backend() -> windows::WindowsCredentialBackend {
    windows::WindowsCredentialBackend::new()
}

// For testing on unsupported platforms
#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
pub fn create_backend() -> MockCredentialBackend {
    MockCredentialBackend::default()
}

/// Mock credential backend for testing
#[derive(Debug, Default)]
pub struct MockCredentialBackend {
    credentials: Arc<RwLock<HashMap<String, String>>>,
    available: bool,
}

impl MockCredentialBackend {
    pub fn new(available: bool) -> Self {
        Self {
            credentials: Arc::new(RwLock::new(HashMap::new())),
            available,
        }
    }
}

impl CredentialBackend for MockCredentialBackend {
    async fn get_raw(&self, key: &CredentialKey) -> Result<Option<String>, CredentialError> {
        if !self.available {
            return Err(CredentialError::StoreUnavailable(
                "Mock store unavailable".to_string(),
            ));
        }
        let credentials = self.credentials.read().await;
        Ok(credentials.get(&key.to_account_key()).cloned())
    }

    async fn set_raw(&self, key: &CredentialKey, value: &str) -> Result<(), CredentialError> {
        if !self.available {
            return Err(CredentialError::StoreUnavailable(
                "Mock store unavailable".to_string(),
            ));
        }
        let mut credentials = self.credentials.write().await;
        credentials.insert(key.to_account_key(), value.to_string());
        Ok(())
    }

    async fn delete_raw(&self, key: &CredentialKey) -> Result<(), CredentialError> {
        if !self.available {
            return Err(CredentialError::StoreUnavailable(
                "Mock store unavailable".to_string(),
            ));
        }
        let mut credentials = self.credentials.write().await;
        credentials.remove(&key.to_account_key());
        Ok(())
    }

    async fn is_available(&self) -> bool {
        self.available
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn mock_backend() -> MockCredentialBackend {
        MockCredentialBackend::new(true)
    }

    #[test]
    fn test_credential_key_parsing() {
        let key = CredentialKey::parse("auth-profile:main:anthropic:default");
        assert!(key.is_some());
        let key = key.unwrap();
        assert_eq!(key.kind, "auth-profile");
        assert_eq!(key.agent_id, "main");
        assert_eq!(key.id, "anthropic:default");
    }

    #[test]
    fn test_credential_key_to_string() {
        let key = CredentialKey::new("gateway", "token", "default");
        assert_eq!(key.to_account_key(), "gateway:token:default");
    }

    #[test]
    fn test_plugin_key_sanitization() {
        let key = CredentialKey::with_plugin_prefix("../malicious", "token", "test");
        assert!(!key.kind.contains(".."));
        assert!(key.kind.starts_with("plugin:"));
    }

    #[test]
    fn test_rate_limit_tracker() {
        let mut tracker = RateLimitTracker::new();

        // Should allow up to WRITE_RATE_LIMIT_PER_MINUTE writes
        for _ in 0..WRITE_RATE_LIMIT_PER_MINUTE {
            assert!(tracker.check_and_record("test-plugin"));
        }

        // Should reject the next write
        assert!(!tracker.check_and_record("test-plugin"));
    }

    #[test]
    fn test_plaintext_credential_guard_detects_known_whatsapp_files() {
        let temp = tempdir().unwrap();
        let account_dir = temp
            .path()
            .join("credentials")
            .join("whatsapp")
            .join("default");
        std::fs::create_dir_all(&account_dir).unwrap();
        let legacy_path = account_dir.join("session-123.json");
        std::fs::write(
            &legacy_path,
            serde_json::json!({
                "noiseKey": {
                    "private": {"type": "Buffer", "data": [1]},
                    "public": {"type": "Buffer", "data": [2]}
                },
                "signedIdentityKey": {
                    "private": {"type": "Buffer", "data": [3]},
                    "public": {"type": "Buffer", "data": [4]}
                },
                "registrationId": 42,
                "_sessions": {}
            })
            .to_string(),
        )
        .unwrap();

        let err = reject_plaintext_credential_files(temp.path())
            .expect_err("known plaintext WhatsApp file should be rejected");
        assert_eq!(
            err,
            CredentialError::PlaintextCredentialFilesDetected(vec![legacy_path
                .display()
                .to_string()])
        );
    }

    #[test]
    fn test_plaintext_credential_guard_reports_all_detected_files() {
        let temp = tempdir().unwrap();
        let credentials_dir = temp.path().join("credentials");
        std::fs::create_dir_all(&credentials_dir).unwrap();
        let oauth_path = credentials_dir.join("oauth.json");
        let creds_path = credentials_dir.join("creds.json");
        std::fs::write(&oauth_path, r#"{"access_token":"secret"}"#).unwrap();
        std::fs::write(&creds_path, r#"{"noiseKey":{"private":"secret"}}"#).unwrap();

        let err = reject_plaintext_credential_files(temp.path())
            .expect_err("all plaintext credential files should be reported");
        let CredentialError::PlaintextCredentialFilesDetected(paths) = err else {
            panic!("expected plaintext credential rejection");
        };

        assert_eq!(
            paths,
            vec![
                creds_path.display().to_string(),
                oauth_path.display().to_string()
            ]
        );
    }

    #[test]
    fn test_plaintext_credential_guard_ignores_incidental_known_files() {
        let temp = tempdir().unwrap();
        let credentials_dir = temp.path().join("credentials");
        std::fs::create_dir_all(&credentials_dir).unwrap();
        std::fs::write(credentials_dir.join("oauth.json"), "{}").unwrap();
        std::fs::write(credentials_dir.join("github-copilot.token.json"), "\"\"").unwrap();
        std::fs::write(credentials_dir.join("creds.json"), r#"{"note":"debug"}"#).unwrap();

        reject_plaintext_credential_files(temp.path())
            .expect("incidental known-name files should not block startup");
    }

    #[test]
    fn test_plaintext_credential_guard_rejects_malformed_known_file() {
        let temp = tempdir().unwrap();
        let credentials_dir = temp.path().join("credentials");
        std::fs::create_dir_all(&credentials_dir).unwrap();
        let oauth_path = credentials_dir.join("oauth.json");
        std::fs::write(&oauth_path, "{not json").unwrap();

        let err = reject_plaintext_credential_files(temp.path())
            .expect_err("malformed known-name credential file should fail closed");
        assert_eq!(
            err,
            CredentialError::PlaintextCredentialFilesUnscannable(vec![
                PlaintextCredentialScanIssue {
                    path: oauth_path.display().to_string(),
                    failure: PlaintextCredentialScanFailure::InvalidJson,
                }
            ])
        );
        assert!(
            err.to_string().contains("could not be safely inspected")
                && err.to_string().contains("invalid JSON")
                && !err.to_string().contains("re-enroll")
        );
    }

    #[test]
    fn test_plaintext_credential_guard_reports_detected_and_unscannable_files_together() {
        let temp = tempdir().unwrap();
        let credentials_dir = temp.path().join("credentials");
        std::fs::create_dir_all(&credentials_dir).unwrap();
        let creds_path = credentials_dir.join("creds.json");
        let oauth_path = credentials_dir.join("oauth.json");
        std::fs::write(&creds_path, r#"{"access_token":"secret"}"#).unwrap();
        std::fs::write(&oauth_path, "{not json").unwrap();

        let err = reject_plaintext_credential_files(temp.path())
            .expect_err("mixed credential findings should fail startup");

        assert_eq!(
            err,
            CredentialError::PlaintextCredentialFilesBlocked {
                detected: vec![creds_path.display().to_string()],
                unscannable: vec![PlaintextCredentialScanIssue {
                    path: oauth_path.display().to_string(),
                    failure: PlaintextCredentialScanFailure::InvalidJson,
                }],
            }
        );
        let message = err.to_string();
        assert!(message.contains(&creds_path.display().to_string()));
        assert!(message.contains(&oauth_path.display().to_string()));
        assert!(message.contains("delete them and re-enroll"));
        assert!(message.contains("could not be safely inspected"));
    }

    #[test]
    fn test_plaintext_credential_guard_detects_pairing_files_with_credential_shape() {
        let temp = tempdir().unwrap();
        let credentials_dir = temp.path().join("credentials");
        std::fs::create_dir_all(&credentials_dir).unwrap();
        let pairing_path = credentials_dir.join("telegram-pairing.json");
        let token_path = credentials_dir.join("telegram-token-pairing.json");
        let allow_from_path = credentials_dir.join("telegram-allowFrom.json");
        std::fs::write(&pairing_path, r#"{"pairingCode":"123-456"}"#).unwrap();
        std::fs::write(&token_path, r#"{"token":"secret"}"#).unwrap();
        std::fs::write(&allow_from_path, r#"["+15551234567"]"#).unwrap();

        let err = reject_plaintext_credential_files(temp.path())
            .expect_err("credential-shaped pairing files should be rejected");
        let CredentialError::PlaintextCredentialFilesDetected(paths) = err else {
            panic!("expected plaintext credential rejection");
        };

        assert_eq!(
            paths,
            vec![
                allow_from_path.display().to_string(),
                pairing_path.display().to_string(),
                token_path.display().to_string()
            ]
        );
    }

    #[test]
    fn test_plaintext_credential_guard_ignores_incidental_pairing_files() {
        let temp = tempdir().unwrap();
        let credentials_dir = temp.path().join("credentials");
        std::fs::create_dir_all(&credentials_dir).unwrap();
        std::fs::write(
            credentials_dir.join("2026-01-15-pairing.json"),
            r#"{"message":"debug note"}"#,
        )
        .unwrap();
        std::fs::write(
            credentials_dir.join("2026-01-15-allowFrom.json"),
            r#"{"message":"debug note"}"#,
        )
        .unwrap();

        reject_plaintext_credential_files(temp.path())
            .expect("incidental pairing files should not block startup");
    }

    #[test]
    fn test_plaintext_credential_guard_ignores_pairing_files_with_only_generic_keys() {
        let temp = tempdir().unwrap();
        let credentials_dir = temp.path().join("credentials");
        std::fs::create_dir_all(&credentials_dir).unwrap();
        std::fs::write(
            credentials_dir.join("debug-pairing.json"),
            r#"{"allowFrom":["+15551234567"],"session":"operator note","identity":"alice"}"#,
        )
        .unwrap();

        reject_plaintext_credential_files(temp.path())
            .expect("generic pairing-shaped metadata should not block startup");
    }

    #[test]
    fn test_pairing_credential_shape_ignores_generic_keys_without_envelope() {
        let value = serde_json::json!({
            "allowFrom": ["+15551234567"],
            "allowedFrom": ["+15551234567"],
            "allowlist": ["alice"],
            "key": "debug",
            "session": "operator note",
            "senders": ["alice"],
            "store": "fixture",
            "identity": "alice",
            "phone": "+15551234567",
            "contacts": ["alice"]
        });

        assert!(!pairing_json_has_credential_shape(&value));
    }

    #[test]
    fn test_pairing_credential_shape_detects_canonical_object_fields() {
        for value in [
            serde_json::json!({"pairingCode": "123-456"}),
            serde_json::json!({"pairing_code": "123-456"}),
            serde_json::json!({"pairing": {"code": "123-456"}}),
            serde_json::json!({"pairing": {}}),
            serde_json::json!({"credential": "pairing-secret"}),
            serde_json::json!({"credentials": ["pairing-secret"]}),
            serde_json::json!({"token": "pairing-secret"}),
            serde_json::json!({"secret": "pairing-secret"}),
            serde_json::json!({"jid": "debug@example.invalid"}),
            serde_json::json!({"clientId": "debug-client"}),
            serde_json::json!({"client_id": "debug-client"}),
            serde_json::json!({"deviceId": "debug-device"}),
            serde_json::json!({"device_id": "debug-device"}),
        ] {
            assert!(pairing_json_has_credential_shape(&value), "{value}");
        }
    }

    #[test]
    fn test_plaintext_credential_guard_detects_non_default_agent_files() {
        let temp = tempdir().unwrap();
        let agent_dir = temp.path().join("agents").join("primary").join("agent");
        std::fs::create_dir_all(&agent_dir).unwrap();
        let auth_path = agent_dir.join("auth.json");
        std::fs::write(&auth_path, r#"{"anthropic":{"apiKey":"secret"}}"#).unwrap();

        let err = reject_plaintext_credential_files(temp.path())
            .expect_err("non-default agent plaintext credential file should be rejected");
        assert_eq!(
            err,
            CredentialError::PlaintextCredentialFilesDetected(vec![auth_path
                .display()
                .to_string()])
        );
    }

    #[test]
    fn test_plaintext_credential_guard_detects_agent_auth_profile_plaintext_secret() {
        let temp = tempdir().unwrap();
        let agent_dir = temp.path().join("agents").join("primary").join("agent");
        std::fs::create_dir_all(&agent_dir).unwrap();
        let auth_profiles_path = agent_dir.join("auth-profiles.json");
        std::fs::write(
            &auth_profiles_path,
            r#"[{"id":"anthropic:default","provider":"anthropic","token":"secret"}]"#,
        )
        .unwrap();

        let err = reject_plaintext_credential_files(temp.path())
            .expect_err("agent auth profile with plaintext secret should be rejected");
        assert_eq!(
            err,
            CredentialError::PlaintextCredentialFilesDetected(vec![auth_profiles_path
                .display()
                .to_string()])
        );
    }

    #[test]
    fn test_agent_credential_shape_scan_reports_depth_limit() {
        let mut value = serde_json::json!({"note": "not credential"});
        for index in 0..=CREDENTIAL_SHAPE_SCAN_MAX_DEPTH {
            value = serde_json::json!({ format!("level{index}"): value });
        }

        assert_eq!(
            agent_json_credential_scan(&value),
            CredentialShapeScan::Indeterminate(PlaintextCredentialScanFailure::DepthLimitExceeded)
        );
    }

    #[test]
    fn test_agent_credential_plaintext_scan_reports_depth_limit() {
        let mut value = serde_json::json!("enc:v2:aaa:bbb:ccc");
        for _ in 0..=CREDENTIAL_SHAPE_SCAN_MAX_DEPTH {
            value = serde_json::json!([value]);
        }

        assert_eq!(
            credential_value_plaintext_scan(&value),
            CredentialShapeScan::Indeterminate(PlaintextCredentialScanFailure::DepthLimitExceeded)
        );
    }

    #[test]
    fn test_plaintext_credential_guard_reports_depth_limit_as_unscannable() {
        let temp = tempdir().unwrap();
        let agent_dir = temp.path().join("agents").join("primary").join("agent");
        std::fs::create_dir_all(&agent_dir).unwrap();
        let auth_path = agent_dir.join("auth.json");
        let mut value = serde_json::json!({"note": "not credential"});
        for index in 0..=CREDENTIAL_SHAPE_SCAN_MAX_DEPTH {
            value = serde_json::json!({ format!("level{index}"): value });
        }
        std::fs::write(&auth_path, value.to_string()).unwrap();

        let err = reject_plaintext_credential_files(temp.path())
            .expect_err("too-deep credential-shaped file should fail closed");

        assert_eq!(
            err,
            CredentialError::PlaintextCredentialFilesUnscannable(vec![
                PlaintextCredentialScanIssue {
                    path: auth_path.display().to_string(),
                    failure: PlaintextCredentialScanFailure::DepthLimitExceeded,
                }
            ])
        );
        assert!(
            err.to_string().contains("scan depth limit") && !err.to_string().contains("re-enroll")
        );
    }

    #[test]
    fn test_plaintext_credential_guard_ignores_current_agent_auth_profile_envelope() {
        let temp = tempdir().unwrap();
        let agent_dir = temp.path().join("agents").join("primary").join("agent");
        std::fs::create_dir_all(&agent_dir).unwrap();
        std::fs::write(
            agent_dir.join("auth-profiles.json"),
            r#"{"version":2,"profiles":[{"id":"anthropic:default","provider":"anthropic","credential_kind":"token","token":"enc:v2:aaa:bbb:ccc"}]}"#,
        )
        .unwrap();

        reject_plaintext_credential_files(temp.path())
            .expect("current encrypted auth profile envelope should not block startup");
    }

    #[test]
    fn test_whatsapp_credential_shape_detects_canonical_fields() {
        let camel_case = serde_json::json!({
            "noiseKey": {"private": {"type": "Buffer", "data": [1]}},
            "signedIdentityKey": {"public": {"type": "Buffer", "data": [2]}},
            "registrationId": 42,
            "_sessions": {}
        });
        let snake_case = serde_json::json!({
            "noise_key": {"private": {"type": "Buffer", "data": [1]}},
            "signed_identity_key": {"public": {"type": "Buffer", "data": [2]}},
            "registration_id": 42
        });

        assert!(whatsapp_json_has_credential_shape(&camel_case));
        assert!(whatsapp_json_has_credential_shape(&snake_case));
    }

    #[test]
    fn test_whatsapp_credential_shape_detects_each_mapped_field() {
        for value in [
            serde_json::json!({"noiseKey": {"private": {"type": "Buffer", "data": [1]}}}),
            serde_json::json!({"signedIdentityKey": {"public": {"type": "Buffer", "data": [1]}}}),
            serde_json::json!({"registrationId": 42}),
            serde_json::json!({"_sessions": {}}),
            serde_json::json!({"advSecretKey": "secret"}),
            serde_json::json!({"chainKey": {"counter": 1}}),
            serde_json::json!({"currentRatchet": {"ephemeralKeyPair": "secret"}}),
            serde_json::json!({"indexInfo": {"baseKey": "abc"}}),
            serde_json::json!({"identityKey": {"type": "Buffer", "data": [1]}}),
            serde_json::json!({"signedPreKey": {"keyPair": "secret"}}),
            serde_json::json!({"senderKeyState": {"chainKey": "secret"}}),
            serde_json::json!({"senderSigningKey": {"type": "Buffer", "data": [1]}}),
            serde_json::json!({"signalIdentities": [{"identifier": "alice"}]}),
            serde_json::json!({"account": {"details": "secret"}}),
            serde_json::json!({"accountSettings": {"unarchiveChats": false}}),
            serde_json::json!({"me": {"id": "alice"}}),
            serde_json::json!({"keyData": {"type": "Buffer", "data": [1]}}),
            serde_json::json!({"fingerprint": {"rawId": 1}}),
            serde_json::json!({"myAppStateKeyId": "app-state-key"}),
            serde_json::json!({"pendingPreKey": {"keyId": 1}}),
            serde_json::json!({"processedHistoryMessages": []}),
            serde_json::json!({"firstUnuploadedPreKeyId": 1}),
            serde_json::json!({"lastAccountSyncTimestamp": 123}),
            serde_json::json!({"nextPreKeyId": 2}),
            serde_json::json!({"noise_key": {"private": {"type": "Buffer", "data": [1]}}}),
            serde_json::json!({"signed_identity_key": {"public": {"type": "Buffer", "data": [1]}}}),
            serde_json::json!({"registration_id": 42}),
            serde_json::json!({"adv_secret_key": "secret"}),
            serde_json::json!({"chain_key": {"counter": 1}}),
            serde_json::json!({"current_ratchet": {"ephemeralKeyPair": "secret"}}),
            serde_json::json!({"index_info": {"baseKey": "abc"}}),
            serde_json::json!({"identity_key": {"type": "Buffer", "data": [1]}}),
            serde_json::json!({"signed_pre_key": {"keyPair": "secret"}}),
            serde_json::json!({"sender_key_state": {"chainKey": "secret"}}),
            serde_json::json!({"sender_signing_key": {"type": "Buffer", "data": [1]}}),
            serde_json::json!({"signal_identities": [{"identifier": "alice"}]}),
            serde_json::json!({"account_settings": {"unarchiveChats": false}}),
            serde_json::json!({"key_data": {"type": "Buffer", "data": [1]}}),
            serde_json::json!({"my_app_state_key_id": "app-state-key"}),
            serde_json::json!({"pending_pre_key": {"keyId": 1}}),
            serde_json::json!({"processed_history_messages": []}),
            serde_json::json!({"first_unuploaded_pre_key_id": 1}),
            serde_json::json!({"last_account_sync_timestamp": 123}),
            serde_json::json!({"next_pre_key_id": 2}),
        ] {
            assert!(whatsapp_json_has_credential_shape(&value), "{value}");
        }
    }

    #[test]
    fn test_whatsapp_credential_shape_ignores_objects_without_mapped_fields() {
        for value in [
            serde_json::json!({}),
            serde_json::json!({"message": "operator note"}),
            serde_json::json!({"name": "alice", "status": "online"}),
            serde_json::json!({"type": "Buffer", "data": []}),
        ] {
            assert!(!whatsapp_json_has_credential_shape(&value), "{value}");
        }
    }

    #[test]
    fn test_plaintext_credential_guard_ignores_incidental_whatsapp_files() {
        let temp = tempdir().unwrap();
        let account_dir = temp
            .path()
            .join("credentials")
            .join("whatsapp")
            .join("default");
        std::fs::create_dir_all(&account_dir).unwrap();
        std::fs::write(account_dir.join("session.enc"), "encrypted").unwrap();
        std::fs::write(account_dir.join(".DS_Store"), "finder").unwrap();
        std::fs::write(account_dir.join("notes.json"), "{}").unwrap();
        std::fs::write(
            account_dir.join("session-debug.json"),
            r#"{"message":"operator note"}"#,
        )
        .unwrap();

        reject_plaintext_credential_files(temp.path())
            .expect("incidental WhatsApp files should not block startup");
    }

    #[test]
    fn test_plaintext_credential_guard_detects_buffer_shaped_whatsapp_file() {
        let temp = tempdir().unwrap();
        let account_dir = temp
            .path()
            .join("credentials")
            .join("whatsapp")
            .join("default");
        std::fs::create_dir_all(&account_dir).unwrap();
        let legacy_path = account_dir.join("pre-key-1.json");
        std::fs::write(&legacy_path, r#"{"type":"Buffer","data":[1,2,3]}"#).unwrap();

        let err = reject_plaintext_credential_files(temp.path())
            .expect_err("credential-shaped WhatsApp file should be rejected");
        assert_eq!(
            err,
            CredentialError::PlaintextCredentialFilesDetected(vec![legacy_path
                .display()
                .to_string()])
        );
    }

    #[tokio::test]
    async fn test_mock_backend_operations() {
        let backend = mock_backend();
        let key = CredentialKey::new("test", "agent", "id");

        // Initially empty
        assert_eq!(backend.get_raw(&key).await.unwrap(), None);

        // Set a value
        backend.set_raw(&key, "secret-value").await.unwrap();

        // Get it back
        assert_eq!(
            backend.get_raw(&key).await.unwrap(),
            Some("secret-value".to_string())
        );

        // Delete it
        backend.delete_raw(&key).await.unwrap();

        // Should be gone
        assert_eq!(backend.get_raw(&key).await.unwrap(), None);
    }

    #[tokio::test]
    async fn test_credential_store_basic_operations() {
        let temp_dir = tempdir().unwrap();
        let backend = mock_backend();
        let store = CredentialStore::new(backend, temp_dir.path().to_path_buf())
            .await
            .unwrap();

        let key = CredentialKey::new("test", "agent", "id");

        // Set
        store.set(&key, "my-secret", None).await.unwrap();

        // Get
        let value = store.get(&key).await.unwrap();
        assert_eq!(value, Some("my-secret".to_string()));

        // Delete
        store.delete(&key).await.unwrap();

        // Should be gone
        let value = store.get(&key).await.unwrap();
        assert_eq!(value, None);
    }

    #[tokio::test]
    async fn test_credential_index_persistence() {
        let temp_dir = tempdir().unwrap();

        // Create store and add credential
        {
            let backend = mock_backend();
            let store = CredentialStore::new(backend, temp_dir.path().to_path_buf())
                .await
                .unwrap();

            let key = CredentialKey::new("test", "agent", "id");
            store
                .set(&key, "my-secret", Some("provider".to_string()))
                .await
                .unwrap();
        }

        // Verify index file exists
        let index_path = temp_dir.path().join("credentials").join("index.json");
        assert!(index_path.exists());

        // Read and verify index content
        let content = fs::read_to_string(&index_path).unwrap();
        let index: CredentialIndex = serde_json::from_str(&content).unwrap();
        assert!(index.entries.contains_key("test:agent:id"));
    }

    #[tokio::test]
    async fn test_corrupted_index_recovery() {
        let temp_dir = tempdir().unwrap();
        let creds_dir = temp_dir.path().join("credentials");
        fs::create_dir_all(&creds_dir).unwrap();

        let index_path = creds_dir.join("index.json");
        let backup_path = creds_dir.join("index.json.bak");

        // Write corrupted index
        fs::write(&index_path, "{ invalid json }").unwrap();

        // Write a valid backup
        let key = CredentialKey::new("test", "agent", "id");
        let mut index = CredentialIndex::new();
        index.entries.insert(
            key.to_account_key(),
            IndexEntry {
                key: key.clone(),
                provider: None,
                last_updated: 1,
            },
        );
        let content = serde_json::to_string_pretty(&index).unwrap();
        fs::write(&backup_path, content).unwrap();

        // Create store - should recover
        let backend = mock_backend();
        let store = CredentialStore::new(backend, temp_dir.path().to_path_buf())
            .await
            .unwrap();

        let keys = store.list_keys().await;
        assert!(keys.iter().any(|k| k.to_account_key() == "test:agent:id"));

        // Check that corrupt file was renamed
        let entries: Vec<_> = fs::read_dir(&creds_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.file_name()
                    .to_string_lossy()
                    .starts_with("index.corrupt.")
            })
            .collect();
        assert_eq!(entries.len(), 1);
    }

    #[tokio::test]
    async fn test_corrupted_index_without_backup() {
        let temp_dir = tempdir().unwrap();
        let creds_dir = temp_dir.path().join("credentials");
        fs::create_dir_all(&creds_dir).unwrap();

        let index_path = creds_dir.join("index.json");
        fs::write(&index_path, "{ invalid json }").unwrap();

        let backend = mock_backend();
        let store = CredentialStore::new(backend, temp_dir.path().to_path_buf())
            .await
            .unwrap();

        assert!(store.list_keys().await.is_empty());

        let entries: Vec<_> = fs::read_dir(&creds_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.file_name()
                    .to_string_lossy()
                    .starts_with("index.corrupt.")
            })
            .collect();
        assert_eq!(entries.len(), 1);
    }

    #[tokio::test]
    async fn test_plugin_credential_isolation() {
        let temp_dir = tempdir().unwrap();
        let backend = mock_backend();
        let store = CredentialStore::new(backend, temp_dir.path().to_path_buf())
            .await
            .unwrap();

        // Set credentials for two different plugins
        store
            .plugin_set("plugin-a", "token", "api", "secret-a")
            .await
            .unwrap();
        store
            .plugin_set("plugin-b", "token", "api", "secret-b")
            .await
            .unwrap();

        // Each plugin should only see its own credentials
        let value_a = store.plugin_get("plugin-a", "token", "api").await.unwrap();
        let value_b = store.plugin_get("plugin-b", "token", "api").await.unwrap();

        assert_eq!(value_a, Some("secret-a".to_string()));
        assert_eq!(value_b, Some("secret-b".to_string()));
    }

    #[tokio::test]
    async fn test_env_only_mode() {
        let temp_dir = tempdir().unwrap();
        let backend = MockCredentialBackend::new(false); // Unavailable
        let store = CredentialStore::new(backend, temp_dir.path().to_path_buf())
            .await
            .unwrap();

        assert!(store.is_env_only_mode());

        // Get should return None
        let key = CredentialKey::new("test", "agent", "id");
        let value = store.get(&key).await.unwrap();
        assert_eq!(value, None);

        // Set should fail
        let result = store.set(&key, "value", None).await;
        assert!(matches!(result, Err(CredentialError::StoreUnavailable(_))));
    }

    #[test]
    fn test_error_retryable() {
        assert!(is_retryable(&CredentialError::Timeout));
        assert!(is_retryable(&CredentialError::IoError("test".to_string())));
        assert!(is_retryable(&CredentialError::RateLimitExceeded));

        assert!(!is_retryable(&CredentialError::StoreLocked));
        assert!(!is_retryable(&CredentialError::AccessDenied));
        assert!(!is_retryable(&CredentialError::NotFound));
    }

    #[test]
    fn test_retry_policies() {
        let get_policy = RetryPolicy::for_get();
        assert_eq!(get_policy.max_retries, 2);
        assert_eq!(get_policy.timeout, Duration::from_secs(5));
        assert!(get_policy.backoff.is_none());

        let set_policy = RetryPolicy::for_set();
        assert_eq!(set_policy.max_retries, 3);
        assert_eq!(set_policy.timeout, Duration::from_secs(10));
        assert!(set_policy.backoff.is_some());

        let delete_policy = RetryPolicy::for_delete();
        assert_eq!(delete_policy.max_retries, 2);
        assert_eq!(delete_policy.timeout, Duration::from_secs(5));
        assert!(delete_policy.backoff.is_none());
    }

    #[tokio::test]
    async fn test_key_too_long_validation() {
        let temp_dir = tempdir().unwrap();
        let backend = mock_backend();
        let store = CredentialStore::new(backend, temp_dir.path().to_path_buf())
            .await
            .unwrap();

        // Create a key that's too long
        let long_id = "x".repeat(MAX_KEY_LENGTH + 10);
        let key = CredentialKey::new("test", "agent", &long_id);

        let result = store.set(&key, "value", None).await;
        assert!(matches!(result, Err(CredentialError::KeyTooLong)));
    }

    #[tokio::test]
    async fn test_value_too_long_validation() {
        let temp_dir = tempdir().unwrap();
        let backend = mock_backend();
        let store = CredentialStore::new(backend, temp_dir.path().to_path_buf())
            .await
            .unwrap();

        let key = CredentialKey::new("test", "agent", "id");
        let long_value = "x".repeat(MAX_VALUE_LENGTH + 1);

        let result = store.set(&key, &long_value, None).await;
        assert!(matches!(result, Err(CredentialError::ValueTooLong)));
    }

    #[tokio::test]
    async fn test_pending_rotation_commit() {
        let temp_dir = tempdir().unwrap();
        let backend = mock_backend();
        let store = CredentialStore::new(backend, temp_dir.path().to_path_buf())
            .await
            .unwrap();

        let key = CredentialKey::new("gateway", "token", "default");
        store.set(&key, "old", None).await.unwrap();
        store.set_pending(&key, "new", None).await.unwrap();

        let current = store.get(&key).await.unwrap();
        assert_eq!(current, Some("old".to_string()));

        let pending = store.get_pending(&key).await.unwrap();
        assert_eq!(pending, Some("new".to_string()));

        store.commit_pending(&key, None).await.unwrap();

        let current = store.get(&key).await.unwrap();
        assert_eq!(current, Some("new".to_string()));

        let pending = store.get_pending(&key).await.unwrap();
        assert_eq!(pending, None);
    }

    #[tokio::test]
    async fn test_pending_rotation_missing() {
        let temp_dir = tempdir().unwrap();
        let backend = mock_backend();
        let store = CredentialStore::new(backend, temp_dir.path().to_path_buf())
            .await
            .unwrap();

        let key = CredentialKey::new("gateway", "token", "default");
        let result = store.commit_pending(&key, None).await;
        assert!(matches!(result, Err(CredentialError::NotFound)));
    }

    #[tokio::test]
    async fn test_pending_key_rejected() {
        let temp_dir = tempdir().unwrap();
        let backend = mock_backend();
        let store = CredentialStore::new(backend, temp_dir.path().to_path_buf())
            .await
            .unwrap();

        let key = CredentialKey::new("gateway", "token", "default:pending");
        let result = store.set_pending(&key, "value", None).await;
        assert!(matches!(result, Err(CredentialError::Internal(_))));
    }

    #[tokio::test]
    async fn test_commit_pending_preserves_provider() {
        let temp_dir = tempdir().unwrap();
        let backend = mock_backend();
        let store = CredentialStore::new(backend, temp_dir.path().to_path_buf())
            .await
            .unwrap();

        let key = CredentialKey::new("gateway", "token", "default");
        store
            .set(&key, "old", Some("provider-x".to_string()))
            .await
            .unwrap();
        store.set_pending(&key, "new", None).await.unwrap();

        store.commit_pending(&key, None).await.unwrap();

        let index = store.index.read().await;
        let entry = index.entries.get(&key.to_account_key()).unwrap();
        assert_eq!(entry.provider.as_deref(), Some("provider-x"));
    }

    #[tokio::test]
    async fn test_commit_pending_prunes_stale_index() {
        let temp_dir = tempdir().unwrap();
        let backend = mock_backend();
        let store = CredentialStore::new(backend, temp_dir.path().to_path_buf())
            .await
            .unwrap();

        let key = CredentialKey::new("gateway", "token", "default");
        store.set_pending(&key, "new", None).await.unwrap();

        let pending_key = CredentialKey::new(
            key.kind.clone(),
            key.agent_id.clone(),
            format!("{}{}", key.id, PENDING_SUFFIX),
        );
        store.backend.delete_raw(&pending_key).await.unwrap();

        let result = store.commit_pending(&key, None).await;
        assert!(matches!(result, Err(CredentialError::NotFound)));

        let index = store.index.read().await;
        assert!(!index.entries.contains_key(&pending_key.to_account_key()));
    }

    #[tokio::test]
    async fn test_pending_rotation_env_only_mode() {
        let temp_dir = tempdir().unwrap();
        let backend = MockCredentialBackend::new(false);
        let store = CredentialStore::new(backend, temp_dir.path().to_path_buf())
            .await
            .unwrap();

        let key = CredentialKey::new("gateway", "token", "default");
        let commit_result = store.commit_pending(&key, None).await;
        assert!(matches!(
            commit_result,
            Err(CredentialError::StoreUnavailable(_))
        ));

        let discard_result = store.discard_pending(&key).await;
        assert!(matches!(
            discard_result,
            Err(CredentialError::StoreUnavailable(_))
        ));
    }

    #[tokio::test]
    async fn test_plugin_quota_not_incremented_on_update() {
        let temp_dir = tempdir().unwrap();
        let backend = mock_backend();
        let store = CredentialStore::new(backend, temp_dir.path().to_path_buf())
            .await
            .unwrap();

        let plugin_id = "test-plugin";

        // Set a credential for the first time
        store
            .plugin_set(plugin_id, "token", "api-key", "secret-v1")
            .await
            .unwrap();

        // Check quota is 1
        {
            let index = store.index.read().await;
            let plugin_key = format!("plugin:{}", plugin_id);
            let quota = index.plugins.get(&plugin_key);
            assert_eq!(quota.map(|q| q.count).unwrap_or(0), 1);
        }

        // Update the same credential multiple times
        for i in 2..10 {
            store
                .plugin_set(plugin_id, "token", "api-key", &format!("secret-v{}", i))
                .await
                .unwrap();
        }

        // Quota should still be 1 (updates don't increment)
        {
            let index = store.index.read().await;
            let plugin_key = format!("plugin:{}", plugin_id);
            let quota = index.plugins.get(&plugin_key);
            assert_eq!(
                quota.map(|q| q.count).unwrap_or(0),
                1,
                "Quota should not increment on updates"
            );
        }

        // Verify the value was actually updated
        let value = store
            .plugin_get(plugin_id, "token", "api-key")
            .await
            .unwrap();
        assert_eq!(value, Some("secret-v9".to_string()));
    }

    #[tokio::test]
    async fn test_plugin_quota_incremented_on_new_keys() {
        let temp_dir = tempdir().unwrap();
        let backend = mock_backend();
        let store = CredentialStore::new(backend, temp_dir.path().to_path_buf())
            .await
            .unwrap();

        let plugin_id = "test-plugin";

        // Set multiple different credentials
        for i in 1..=5 {
            store
                .plugin_set(
                    plugin_id,
                    "token",
                    &format!("key-{}", i),
                    &format!("secret-{}", i),
                )
                .await
                .unwrap();
        }

        // Quota should be 5 (one for each unique key)
        {
            let index = store.index.read().await;
            let plugin_key = format!("plugin:{}", plugin_id);
            let quota = index.plugins.get(&plugin_key);
            assert_eq!(
                quota.map(|q| q.count).unwrap_or(0),
                5,
                "Quota should increment for each new key"
            );
        }
    }
}
